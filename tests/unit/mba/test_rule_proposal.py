from __future__ import annotations

import re
import ast
import keyword

import pytest

from d810.mba.bounded_synthesis import ProofReceipt
from d810.mba.rule_proposal import MbaRuleProposal, render_rule_source
from d810.mba.typed_term import TypedBvTerm, term_cost, term_fingerprint


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


def test_width_metadata_rejects_forged_markers_and_descriptors() -> None:
    from d810.mba.bounded_synthesis import GrammarAllOnesOrigin
    from d810.mba.rule_proposal import proposal_fingerprint

    x = _term(None, key="x")
    pattern = _term("mul", children=(x, _term(None, value=1)))
    replacement = x
    proofs = tuple(ProofReceipt(width=width, verdict=True, elapsed_ms=0.1) for width in (8, 16, 32, 64))
    base = dict(
        source_fingerprints=("r",), occurrence_count=1, pattern=pattern, replacement=replacement,
        source_cost=term_cost(pattern), replacement_cost=term_cost(replacement), atomization_bindings=(),
        proof_receipts=proofs, class_name="Forged", family="mul", description="d", provenance=("p",), fixture={},
    )
    forged_marker = GrammarAllOnesOrigin(
        occurrence_path=(),
        terminal_fingerprint=term_fingerprint(_term(None, value=1)),
        source_width=32,
    )
    with pytest.raises(TypeError, match="unexpected keyword"):
        MbaRuleProposal(
            proposal_fingerprint=proposal_fingerprint(**base),
            width_relative_all_ones=(forged_marker,),
            **base,
        )
    with pytest.raises(ValueError):
        MbaRuleProposal(
            proposal_fingerprint=proposal_fingerprint(fixed_operation_descriptors=(("ror", 3, 32),), **base),
            fixed_operation_descriptors=(("ror", 3, 32),),
            **base,
        )
    with pytest.raises(ValueError):
        MbaRuleProposal(
            proposal_fingerprint=proposal_fingerprint(fixed_operation_descriptors=(("ror", -1, 32),), **base),
            fixed_operation_descriptors=(("ror", -1, 32),),
            **base,
        )


def test_width_metadata_survives_manifest_and_rendering() -> None:
    from d810.mba.bounded_synthesis import synthesize_residual
    from d810.mba.rule_proposal import proposal_fingerprint
    from d810.mba.subterm_atomization import AtomizedMbaTerm

    zero = _term(None, value=0)
    all_ones = _term(None, value=(1 << 32) - 1)
    pattern = _term("bnot", children=(zero,))
    result = synthesize_residual(AtomizedMbaTerm(pattern, pattern, ()))
    assert result.certified and result.replacement == all_ones
    kwargs = dict(
        source_fingerprints=("r",), occurrence_count=1, pattern=pattern, replacement=result.replacement,
        source_cost=term_cost(pattern), replacement_cost=result.replacement_cost, atomization_bindings=(),
        proof_receipts=result.proof_receipts, class_name="WidthAware", family="bnot", description="d", provenance=("p",), fixture={},
        synthesis_result=result,
    )
    proposal = MbaRuleProposal(
        proposal_fingerprint=proposal_fingerprint(
            width_relative_all_ones=result.width_relative_all_ones,
            fixed_operation_descriptors=result.fixed_operation_descriptors,
            **{key: value for key, value in kwargs.items() if key != "synthesis_result"},
        ),
        **kwargs,
    )
    manifest = proposal.to_dict()
    source = render_rule_source(proposal)
    assert manifest["width_relative_all_ones"] == [
        {
            "origin": "grammar_injected_all_ones",
            "occurrence_path": [],
            "source_width": 32,
            "terminal_fingerprint": term_fingerprint(all_ones),
        }
    ]
    assert "NEGATIVE_ONE" in source


def test_fixed_input_all_ones_stays_literal_in_result_manifest_source_and_proof() -> None:
    from d810.mba.bounded_synthesis import synthesize_residual
    from d810.mba.rule_proposal import proposal_fingerprint
    from d810.mba.subterm_atomization import AtomizedMbaTerm
    from d810.mba.verifier import VerificationOptions, verify_transformation

    mask = _term(None, value=0xFFFFFFFF)
    zero = _term(None, value=0)
    pattern = _term("xor", children=(mask, zero))
    result = synthesize_residual(AtomizedMbaTerm(pattern, pattern, ()))
    assert result.certified and result.replacement == mask
    assert result.width_relative_all_ones == ()
    base = dict(
        source_fingerprints=("fixed-mask",),
        occurrence_count=1,
        pattern=pattern,
        replacement=mask,
        source_cost=term_cost(pattern),
        replacement_cost=term_cost(mask),
        atomization_bindings=(),
        proof_receipts=result.proof_receipts,
        class_name="FixedMaskRule",
        family="xor",
        description="fixed input mask remains fixed",
        provenance=("test",),
        fixture={},
        synthesis_result=result,
    )
    proposal = MbaRuleProposal(
        proposal_fingerprint=proposal_fingerprint(
            width_relative_all_ones=(),
            fixed_operation_descriptors=(),
            **{key: value for key, value in base.items() if key != "synthesis_result"},
        ),
        **base,
    )

    assert proposal.to_dict()["width_relative_all_ones"] == []
    source = render_rule_source(proposal)
    assert "NEGATIVE_ONE" not in source
    assert 'Const("const_4294967295", 4294967295)' in source
    namespace: dict[str, object] = {}
    exec(compile(source, "<fixed-mask>", "exec"), namespace)
    rule = namespace["FixedMaskRule"]()
    for width in (8, 16, 32, 64):
        verdict, counterexample = verify_transformation(
            rule.PATTERN,
            rule.REPLACEMENT,
            options=VerificationOptions(bit_width=width, timeout_ms=5000),
        )
        assert verdict is True and counterexample is None
    assert rule.REPLACEMENT.value == 0xFFFFFFFF


def test_rotate_source_executes_and_compiles_in_isolated_process() -> None:
    import os
    import subprocess
    import sys
    from pathlib import Path
    from d810.mba.rule_proposal import proposal_fingerprint
    from d810.mba.typed_term import fixed_shift_term

    x = _term(None, key="x")
    rotate = fixed_shift_term("ror", 32, x, 3)
    pattern = _term("add", children=(rotate, _term(None, value=0)))
    replacement = rotate
    proofs = tuple(ProofReceipt(width=width, verdict=True, elapsed_ms=0.1) for width in (8, 16, 32, 64))
    base = dict(
        source_fingerprints=("r",), occurrence_count=1, pattern=pattern, replacement=replacement,
        source_cost=term_cost(pattern), replacement_cost=term_cost(replacement), atomization_bindings=(),
        proof_receipts=proofs, class_name="ExecutableRotate", family="fixed", description="d", provenance=("p",), fixture={},
        fixed_operation_descriptors=(("ror", 3, 32),),
    )
    proposal = MbaRuleProposal(proposal_fingerprint=proposal_fingerprint(**base), **base)
    source = render_rule_source(proposal)
    script = """
import sys
from d810.mba.canonical_pattern import compile_canonical_pattern
from d810.mba.verifier import verify_transformation, VerificationOptions
namespace = {}
exec(compile(sys.stdin.read(), '<proposal>', 'exec'), namespace)
rule = namespace['ExecutableRotate']()
for width in (8, 16, 32, 64):
    compiled = compile_canonical_pattern(rule, width=width, declaration_index=0)
    assert compiled.pattern_term.operation == 'add'
    assert verify_transformation(rule.PATTERN, rule.REPLACEMENT, options=VerificationOptions(bit_width=width, timeout_ms=5000))[0]
"""
    env = dict(os.environ)
    env["PYTHONPATH"] = "src"
    root = Path(__file__).resolve().parents[3]
    subprocess.run([sys.executable, "-c", script], cwd=root, env=env, input=source, text=True, check=True)


@pytest.mark.parametrize("direction", ("rol", "ror"))
def test_rotate_source_is_admitted_count_safe_materialized_and_proved(
    direction: str,
) -> None:
    import os
    import subprocess
    import sys
    from pathlib import Path

    from d810.mba.rule_proposal import proposal_fingerprint
    from d810.mba.typed_term import fixed_shift_term

    x = _term(None, key="x")
    rotate = fixed_shift_term(direction, 32, x, 3)
    pattern = _term("add", children=(rotate, _term(None, value=0)))
    proofs = tuple(
        ProofReceipt(width=width, verdict=True, elapsed_ms=0.1)
        for width in (8, 16, 32, 64)
    )
    base = dict(
        source_fingerprints=("r",),
        occurrence_count=1,
        pattern=pattern,
        replacement=rotate,
        source_cost=term_cost(pattern),
        replacement_cost=term_cost(rotate),
        atomization_bindings=(),
        proof_receipts=proofs,
        class_name=f"Executable{direction.title()}Rule",
        family="add",
        description="fixed rotate admission regression",
        provenance=("test",),
        fixture={},
        fixed_operation_descriptors=((direction, 3, 32),),
    )
    proposal = MbaRuleProposal(
        proposal_fingerprint=proposal_fingerprint(**base), **base
    )
    source = render_rule_source(proposal)
    script = f"""
import sys

from d810.mba.ac_matching import match_canonical_term_pattern
from d810.backends.mba.compiled_pattern_catalogue import CompiledPatternCatalogue
from d810.mba.canonical_pattern import compile_canonical_pattern
from d810.mba.certified_rule_compiler import RuleCompilationStatus, _compile_rule_families
from d810.mba.typed_term import TypedBvTerm, fixed_shift_term
from d810.mba.verifier import VerificationOptions, verify_transformation
from d810.mba.bounded_synthesis import generalize_terms

namespace = {{}}
exec(compile(sys.stdin.read(), '<proposal>', 'exec'), namespace)
rule_type = namespace[{proposal.class_name!r}]
catalogue = _compile_rule_families({{'add': (rule_type,)}})
receipt = catalogue.receipt_for('add', {proposal.class_name!r})
assert receipt.status is RuleCompilationStatus.COMPILED, receipt.reason
rule = receipt.compiled_rule
assert rule is not None
runtime_catalogue = CompiledPatternCatalogue.from_rules((rule,))
for width in (8, 16, 32, 64):
    compiled = compile_canonical_pattern(rule, width=width, declaration_index=0)
    leaf = TypedBvTerm(None, width, leaf_key=('candidate', 'x'))
    candidate = TypedBvTerm('add', width, children=(
        fixed_shift_term({direction!r}, width, leaf, 3),
        TypedBvTerm(None, width, value=0),
    ))
    matched = match_canonical_term_pattern(compiled, candidate, comparison_budget=32)
    assert matched.matches
    wrong = TypedBvTerm('add', width, children=(
        fixed_shift_term({direction!r}, width, leaf, 7),
        TypedBvTerm(None, width, value=0),
    ))
    assert not match_canonical_term_pattern(compiled, wrong, comparison_budget=32).matches
    materialized = compiled.materialize_replacement(matched.matches[0].bindings)
    assert materialized.shift_count == 3
    applications = runtime_catalogue.canonical_applications(candidate)
    assert len(applications) == 1
    assert applications[0][1].shift_count == 3
    assert runtime_catalogue.canonical_applications(wrong) == ()
    pattern_expr, replacement_expr = generalize_terms(candidate, materialized, width=width)
    verdict, counterexample = verify_transformation(
        pattern_expr,
        replacement_expr,
        options=VerificationOptions(bit_width=width, timeout_ms=5000),
    )
    assert verdict is True and counterexample is None
"""
    env = dict(os.environ)
    env["PYTHONPATH"] = "src"
    root = Path(__file__).resolve().parents[3]
    subprocess.run(
        [sys.executable, "-c", script],
        cwd=root,
        env=env,
        input=source,
        text=True,
        check=True,
    )


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
