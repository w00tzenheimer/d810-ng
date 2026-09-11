import pytest


@pytest.mark.parametrize("width", (8, 16, 32, 64))
def test_cst_rule8_uses_typed_progress_constraint(width: int) -> None:
    from d810.mba.canonical_pattern import compile_canonical_pattern, evaluate_frozen_constraints
    from d810.mba.rules.cst import CstSimplificationRule8
    from d810.mba.typed_term import TypedBvTerm

    compiled = compile_canonical_pattern(
        CstSimplificationRule8(), width=width, declaration_index=0
    )

    assert len(compiled.constraints) == 2
    assert compiled.constraints[1].operation == "ne"

    mask = (1 << width) - 1
    progressing = {
        "x_0": TypedBvTerm(None, width, value=0x55 & mask),
        "c_1": TypedBvTerm(None, width, value=mask),
        "c_2": TypedBvTerm(None, width, value=0x0F & mask),
    }
    assert evaluate_frozen_constraints(compiled.constraints, progressing, width=width)
    assert progressing["c_res"].value == (mask & ~0x0F) & mask

    unchanged = {
        "x_0": TypedBvTerm(None, width, value=0x55 & mask),
        "c_1": TypedBvTerm(None, width, value=(mask & ~0x0F)),
        "c_2": TypedBvTerm(None, width, value=0x0F & mask),
    }
    assert not evaluate_frozen_constraints(compiled.constraints, unchanged, width=width)


@pytest.mark.parametrize(
    "rule_name",
    ("PredFFRule1", "PredFFRule2", "PredFFRule3", "PredFFRule4", "PredOdd1", "PredOdd2"),
)
def test_root_dynamic_const_is_retained_as_explicit_symbolic_operation(rule_name: str) -> None:
    from d810.mba.rules import predicates

    rule = getattr(predicates, rule_name)()

    assert rule.replacement is getattr(type(rule), "REPLACEMENT")
    assert rule.replacement.operation == "dynamic_const"
    assert not rule.replacement.is_leaf()


def test_nested_dynamic_const_is_retained_by_rule_storage() -> None:
    from d810.mba.dsl import DynamicConst, Var
    from d810.mba.rules._base import VerifiableRule

    x = Var("x")

    class NestedDynamicRule(VerifiableRule):
        PATTERN = x
        REPLACEMENT = x + DynamicConst("computed", lambda _ctx: 7, size_from="x")

    rule = NestedDynamicRule()
    assert rule.replacement.right.operation == "dynamic_const"


def test_canonical_lowerer_rejects_dynamic_const_explicitly() -> None:
    from d810.mba.canonical_pattern import CanonicalPatternUnsupported, lower_symbolic_template
    from d810.mba.dsl import DynamicConst

    with pytest.raises(CanonicalPatternUnsupported, match="dynamic_const"):
        lower_symbolic_template(DynamicConst("computed", lambda _ctx: 1), width=32)


def test_dynamic_const_semantic_encoding_includes_callback_and_size_source() -> None:
    from d810.mba.canonical_pattern import _jsonable_semantics
    from d810.mba.dsl import DynamicConst

    first = _jsonable_semantics(DynamicConst("computed", lambda _ctx: 1, "x"))
    changed_callback = _jsonable_semantics(
        DynamicConst("computed", lambda _ctx: 2, "x")
    )
    changed_source = _jsonable_semantics(
        DynamicConst("computed", lambda _ctx: 1, "y")
    )

    assert first != changed_callback
    assert first != changed_source
