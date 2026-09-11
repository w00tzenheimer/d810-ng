from __future__ import annotations

from types import SimpleNamespace

from d810.mba.ac_matching import (
    check_canonical_feasibility,
    match_canonical_term_pattern,
    prepare_canonical_candidate_facts,
    prepare_canonical_template_facts,
)
from d810.mba.canonical_pattern import compile_canonical_pattern
from d810.mba.dsl import Const, Var
from d810.mba.typed_term import TypedBvTerm


def _leaf(name: str, width: int = 32) -> TypedBvTerm:
    return TypedBvTerm(None, width, leaf_key=("test", name))


def _constant(value: int, width: int = 32) -> TypedBvTerm:
    return TypedBvTerm(None, width, value=value)


def _node(
    operation: str,
    left: TypedBvTerm,
    right: TypedBvTerm,
    width: int = 32,
) -> TypedBvTerm:
    return TypedBvTerm(operation, width, children=(left, right))


def _template(pattern, *, width: int = 32):
    rule = SimpleNamespace(
        pattern=pattern,
        replacement=pattern,
        source_name="FeasibilityRule",
        aliases=(),
        family="test",
        proof_widths=(width,),
        guarded=False,
        constraints=(),
    )
    return compile_canonical_pattern(rule, width=width, declaration_index=0)


def _check(template, candidate):
    return check_canonical_feasibility(
        prepare_canonical_template_facts(template),
        prepare_canonical_candidate_facts(candidate),
    )


def test_root_placeholder_and_unknown_facts_survive_without_predicate_work() -> None:
    root = _node("add", _leaf("a"), _leaf("b"))

    placeholder = _check(_template(Var("x")), root)
    assert placeholder.known is True
    assert placeholder.survives is True
    assert placeholder.predicate_comparisons == 0

    unknown = check_canonical_feasibility(None, prepare_canonical_candidate_facts(root))
    assert unknown.known is False
    assert unknown.survives is True
    assert unknown.predicate_comparisons == 0


def test_ac_requirements_are_existential_without_bijection_or_repeat_shortcut() -> None:
    candidate = _node("xor", _leaf("a"), _leaf("b"))
    template = _template(Var("x") ^ Var("x"))

    report = _check(template, candidate)

    assert report.known is True
    assert report.survives is True
    assert report.predicate_comparisons == 3
    assert not match_canonical_term_pattern(
        template, candidate, comparison_budget=16
    ).matches


def test_constant_masking_and_wrong_value_rejection() -> None:
    pattern = Const("wide", 0x1FF) + Var("x")
    template = _template(pattern, width=8)
    accepted_candidate = _node("add", _constant(0xFF, 8), _leaf("x", 8), width=8)
    rejected_candidate = _node("add", _constant(0xFE, 8), _leaf("x", 8), width=8)

    accepted = _check(template, accepted_candidate)
    rejected = _check(template, rejected_candidate)

    assert accepted.survives is True
    assert rejected.survives is False
    assert match_canonical_term_pattern(
        template, accepted_candidate, comparison_budget=16
    ).matches
    assert not match_canonical_term_pattern(
        template, rejected_candidate, comparison_budget=16
    ).matches


def test_constant_requirement_distinguishes_nonconstant_terminal() -> None:
    candidate = _node("add", _leaf("a"), _leaf("b"))

    constant = _check(_template(Const("one", 1) + Var("x")), candidate)
    wildcard = _check(_template(Var("x") + Var("y")), candidate)

    assert constant.survives is False
    assert wildcard.survives is True


def test_candidate_ac_flattening_is_asymmetric_and_mixed_width_is_not_vetoed() -> None:
    a, b, c, d = (Var(name) for name in "abcd")
    template = _template((a + (b * c)) + d)
    product = _node("mul", _leaf("b"), _leaf("c"))
    equal_width = _node("add", _leaf("a"), _node("add", product, _leaf("d")))
    mixed_width_candidate = _node(
        "add",
        _leaf("a", 16),
        _node(
            "add",
            _node("mul", _leaf("b", 16), _leaf("c", 16), width=16),
            _leaf("d", 16),
            width=16,
        ),
        width=16,
    )

    assert _check(template, equal_width).survives is True
    assert _check(template, mixed_width_candidate).survives is True
    assert match_canonical_term_pattern(
        template, equal_width, comparison_budget=64
    ).matches
    assert not match_canonical_term_pattern(
        template, mixed_width_candidate, comparison_budget=64
    ).matches


def test_rigid_root_and_unsupported_candidate_fail_closed_to_survival() -> None:
    template = _template(Var("x") ^ Var("y"))

    rejected = _check(template, _node("add", _leaf("x"), _leaf("y")))
    unknown = check_canonical_feasibility(
        prepare_canonical_template_facts(template),
        prepare_canonical_candidate_facts(object()),
    )

    assert rejected.known is True
    assert rejected.survives is False
    assert unknown.known is False
    assert unknown.survives is True
