from __future__ import annotations

import re
import ast
import keyword

import pytest

from d810.mba.bounded_synthesis import ProofReceipt
from d810.mba.rule_proposal import MbaRuleProposal, render_rule_source
from d810.mba.typed_term import TypedBvTerm, term_cost


def _term(op: str | None, width: int = 32, *, value: int | None = None, key: str | None = None, children=()):
    return TypedBvTerm(op, width, value=value, leaf_key=("register", key) if key else None, children=children)


def test_proposal_validates_costs_receipts_and_renders_ascii_rule_source() -> None:
    x, y = _term(None, key="x"), _term(None, key="y")
    pattern = _term("add", children=(_term("add", children=(x, y)), x))
    replacement = _term("or", children=(x, y))
    proofs = tuple(ProofReceipt(width=width, verdict=True, elapsed_ms=0.1, counterexample=None) for width in (8, 16, 32, 64))
    proposal = MbaRuleProposal(
        proposal_fingerprint=None,
        source_fingerprints=("residual-1",),
        occurrence_count=2,
        pattern=pattern,
        replacement=replacement,
        source_cost=term_cost(pattern),
        replacement_cost=term_cost(replacement),
        atomization_bindings=(),
        proof_receipts=proofs,
        class_name="MbaResidualOrRule",
        family="or",
        description="Discover OR from a residual MBA identity",
        provenance=("provider:cobra",),
        fixture={"case_id": "fixture-1"},
    )
    source = render_rule_source(proposal)
    assert source.isascii()
    assert source.count("class MbaResidualOrRule") == 1
    assert "PATTERN =" in source and "REPLACEMENT =" in source
    assert "VerifiableRule" in source
    assert "provider:cobra" not in source
    assert "dynamic" not in source.lower()


def test_proposal_rejects_incomplete_proof_and_non_cheaper_replacement() -> None:
    x = _term(None, key="x")
    pattern = _term("add", children=(x, _term(None, value=1)))
    with pytest.raises(ValueError, match="proof|cheaper"):
        MbaRuleProposal(
            proposal_fingerprint=None,
            source_fingerprints=("r",),
            occurrence_count=1,
            pattern=pattern,
            replacement=pattern,
            source_cost=term_cost(pattern),
            replacement_cost=term_cost(pattern),
            atomization_bindings=(),
            proof_receipts=(),
            class_name="Bad",
            family="add",
            description="bad",
            provenance=(),
            fixture={},
        )


def test_rendered_source_uses_stable_variable_declarations() -> None:
    x, y = _term(None, key="x"), _term(None, key="y")
    pattern = _term("add", children=(_term("add", children=(x, y)), x))
    replacement = _term("xor", children=(x, y))
    proofs = tuple(ProofReceipt(width=width, verdict=True, elapsed_ms=0.1) for width in (8, 16, 32, 64))
    proposal = MbaRuleProposal(
        proposal_fingerprint=None,
        source_fingerprints=("r",), occurrence_count=1,
        pattern=pattern, replacement=replacement,
        source_cost=term_cost(pattern), replacement_cost=term_cost(replacement),
        atomization_bindings=(), proof_receipts=proofs,
        class_name="StableRule", family="xor", description="stable", provenance=(), fixture={},
    )
    source = render_rule_source(proposal)
    assert re.search(r"x_0\s*=\s*Var\(\"x_0\"\)", source)
    assert re.search(r"x_1\s*=\s*Var\(\"x_1\"\)", source)


def test_proposal_freezes_metadata_and_requires_canonical_fingerprint() -> None:
    from d810.mba.rule_proposal import proposal_fingerprint

    x = _term(None, key="x")
    pattern = _term("add", children=(_term("add", children=(x, x)), x))
    replacement = _term("xor", children=(x, x))
    proofs = tuple(ProofReceipt(width=width, verdict=True, elapsed_ms=0.1) for width in (8, 16, 32, 64))
    fixture = {"nested": [{"value": 1}]}
    kwargs = dict(
        source_fingerprints=("z", "a", "a"), occurrence_count=1,
        pattern=pattern, replacement=replacement,
        source_cost=term_cost(pattern), replacement_cost=term_cost(replacement),
        atomization_bindings=(), proof_receipts=proofs,
        class_name="StableRule", family="xor", description="stable", provenance=("z", "a", "a"), fixture=fixture,
    )
    digest = proposal_fingerprint(**kwargs)
    proposal = MbaRuleProposal(proposal_fingerprint=digest, **kwargs)
    fixture["nested"][0]["value"] = 9
    assert proposal.fixture["nested"][0]["value"] == 1
    assert proposal.source_fingerprints == ("a", "z")
    assert proposal.provenance == ("a", "z")
    assert proposal.to_dict()["provenance"] == ["a", "z"]
    with pytest.raises(ValueError, match="fingerprint"):
        MbaRuleProposal(proposal_fingerprint="0" * 64, **kwargs)


def test_fingerprint_ignores_solver_timing_but_tracks_semantics_and_provenance() -> None:
    from d810.mba.rule_proposal import proposal_fingerprint

    x = _term(None, key="x")
    pattern = _term("add", children=(_term("add", children=(x, x)), x))
    replacement = _term("xor", children=(x, x))
    base = dict(
        source_fingerprints=("r",), occurrence_count=1, pattern=pattern, replacement=replacement,
        source_cost=term_cost(pattern), replacement_cost=term_cost(replacement), atomization_bindings=(),
        class_name="Stable", family="xor", description="d", provenance=("p",), fixture={},
    )
    first = tuple(ProofReceipt(width=width, verdict=True, elapsed_ms=0.1) for width in (8, 16, 32, 64))
    second = tuple(ProofReceipt(width=width, verdict=True, elapsed_ms=99.9) for width in (8, 16, 32, 64))
    assert proposal_fingerprint(proof_receipts=first, **base) == proposal_fingerprint(proof_receipts=second, **base)
    assert proposal_fingerprint(proof_receipts=first, **{**base, "provenance": ("changed",)}) != proposal_fingerprint(proof_receipts=first, **base)
    assert proposal_fingerprint(proof_receipts=first, **{**base, "replacement": pattern}) != proposal_fingerprint(proof_receipts=first, **base)


def test_width_metadata_survives_manifest_and_rendering() -> None:
    from d810.mba.rule_proposal import proposal_fingerprint
    from d810.mba.typed_term import fixed_shift_term, term_fingerprint

    x = _term(None, key="x")
    all_ones = _term(None, value=(1 << 32) - 1)
    pattern = _term("add", children=(fixed_shift_term("ror", 32, x, 3), _term(None, value=1)))
    replacement = _term("xor", children=(x, all_ones))
    proofs = tuple(ProofReceipt(width=width, verdict=True, elapsed_ms=0.1) for width in (8, 16, 32, 64))
    kwargs = dict(
        source_fingerprints=("r",), occurrence_count=1, pattern=pattern, replacement=replacement,
        source_cost=term_cost(pattern), replacement_cost=term_cost(replacement), atomization_bindings=(),
        proof_receipts=proofs, class_name="WidthAware", family="fixed", description="d", provenance=("p",), fixture={},
        width_relative_all_ones=(term_fingerprint(all_ones),), fixed_operation_descriptors=(("ror", 3, 32),),
    )
    proposal = MbaRuleProposal(proposal_fingerprint=proposal_fingerprint(**kwargs), **kwargs)
    manifest = proposal.to_dict()
    source = render_rule_source(proposal)
    assert manifest["width_relative_all_ones"] == [term_fingerprint(all_ones)]
    assert "NEGATIVE_ONE" in source
    assert 'FixedRotate("ror"' in source
    assert "shift_29" not in source


def test_proposal_rejects_keywords_unicode_and_non_json_fixture() -> None:
    x = _term(None, key="x")
    pattern = _term("add", children=(_term("add", children=(x, x)), x))
    replacement = _term("xor", children=(x, x))
    proofs = tuple(ProofReceipt(width=width, verdict=True, elapsed_ms=0.1) for width in (8, 16, 32, 64))
    base = dict(source_fingerprints=("r",), occurrence_count=1, pattern=pattern, replacement=replacement,
                source_cost=term_cost(pattern), replacement_cost=term_cost(replacement), atomization_bindings=(),
                proof_receipts=proofs, family="xor", description="d", provenance=("p",), fixture={})
    from d810.mba.rule_proposal import proposal_fingerprint
    digest = proposal_fingerprint(class_name="Good", **base)
    with pytest.raises(ValueError):
        MbaRuleProposal(proposal_fingerprint=digest, class_name=keyword.kwlist[0], **base)
    with pytest.raises(ValueError):
        MbaRuleProposal(proposal_fingerprint=digest, class_name="éRule", **base)
    with pytest.raises((TypeError, ValueError)):
        MbaRuleProposal(proposal_fingerprint=digest, class_name="Good", fixture={"bad": object()}, **{k: v for k, v in base.items() if k != "fixture"})


def test_rendered_source_parses_without_changing_rule_registry() -> None:
    from d810.mba.rules._base import VerifiableRule
    from d810.mba.rule_proposal import proposal_fingerprint

    x = _term(None, key="x")
    pattern = _term("add", children=(_term("add", children=(x, x)), x))
    replacement = _term("xor", children=(x, x))
    proofs = tuple(ProofReceipt(width=width, verdict=True, elapsed_ms=0.1) for width in (8, 16, 32, 64))
    base = dict(source_fingerprints=("r",), occurrence_count=1, pattern=pattern, replacement=replacement,
                source_cost=term_cost(pattern), replacement_cost=term_cost(replacement), atomization_bindings=(),
                proof_receipts=proofs, class_name="NoSideEffect", family="xor", description="d", provenance=("p",), fixture={})
    proposal = MbaRuleProposal(proposal_fingerprint=proposal_fingerprint(**base), **base)
    before = dict(VerifiableRule.registry)
    source = render_rule_source(proposal)
    ast.parse(source)
    assert dict(VerifiableRule.registry) == before
