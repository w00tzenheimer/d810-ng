from __future__ import annotations

import re

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
        proposal_fingerprint="proposal-1",
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
            proposal_fingerprint="p",
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
        proposal_fingerprint="p",
        source_fingerprints=("r",), occurrence_count=1,
        pattern=pattern, replacement=replacement,
        source_cost=term_cost(pattern), replacement_cost=term_cost(replacement),
        atomization_bindings=(), proof_receipts=proofs,
        class_name="StableRule", family="xor", description="stable", provenance=(), fixture={},
    )
    source = render_rule_source(proposal)
    assert re.search(r"x_0\s*=\s*Var\(\"x_0\"\)", source)
    assert re.search(r"x_1\s*=\s*Var\(\"x_1\"\)", source)
