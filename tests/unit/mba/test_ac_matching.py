from __future__ import annotations

from d810.mba.ac_matching import AcMatchStopReason, match_ac_pattern
from d810.mba.dsl import Const, Var
from d810.mba.typed_term import TypedBvTerm


def _leaf(name: str) -> TypedBvTerm:
    return TypedBvTerm(None, 32, leaf_key=("test", name))


def _node(operation: str, left: TypedBvTerm, right: TypedBvTerm) -> TypedBvTerm:
    return TypedBvTerm(operation, 32, children=(left, right))


def test_binary_commutation_is_lazy_and_returns_original_candidate_paths() -> None:
    x = Var("x")
    report = match_ac_pattern(
        x + Const("one", 1),
        _node("add", TypedBvTerm(None, 32, value=1), _leaf("x")),
        comparison_budget=8,
    )

    assert report.stop_reason is AcMatchStopReason.MATCHED
    assert report.bindings is not None
    assert dict(report.bindings.candidate_path_by_name) == {"x": (1,), "one": (0,)}
    assert report.commuted_branches == 1


def test_nested_failed_swap_restores_bindings_before_second_branch() -> None:
    x, y = Var("x"), Var("y")
    pattern = (x - y) + x
    candidate = _node("add", _leaf("x"), _node("sub", _leaf("x"), _leaf("y")))

    report = match_ac_pattern(pattern, candidate, comparison_budget=32)

    assert report.stop_reason is AcMatchStopReason.MATCHED
    assert report.bindings is not None
    assert dict(report.bindings.candidate_path_by_name) == {"x": (1, 0), "y": (1, 1)}


def test_non_ac_parent_retries_a_nested_lazy_commutation_after_rhs_rejects() -> None:
    """The Sub_HD2 shape needs the XOR child to roll back to its swap."""

    x, y = Var("x"), Var("y")
    two = Const("two", 2)
    pattern = (x ^ y) - two * ((~x) & y)
    a, b = _leaf("a"), _leaf("b")
    candidate = _node(
        "sub",
        _node("xor", a, b),
        _node(
            "mul",
            TypedBvTerm(None, 32, value=2),
            _node("and", a, TypedBvTerm("bnot", 32, children=(b,))),
        ),
    )

    report = match_ac_pattern(pattern, candidate, comparison_budget=64)

    assert report.stop_reason is AcMatchStopReason.MATCHED
    assert report.bindings is not None
    assert dict(report.bindings.candidate_path_by_name) == {
        "x": (0, 1),
        "y": (0, 0),
        "two": (1, 0),
    }
    assert report.commuted_branches >= 1


def test_same_width_ac_chain_requires_equal_cardinality_and_never_group_binds() -> None:
    a, b, c = Var("a"), Var("b"), Var("c")
    candidate = _node("add", _leaf("c"), _node("add", _leaf("b"), _leaf("a")))

    report = match_ac_pattern((a + b) + c, candidate, comparison_budget=64)
    assert report.stop_reason is AcMatchStopReason.MATCHED
    assert report.bindings is not None
    assert set(report.bindings.candidate_path_by_name) == {"a", "b", "c"}
    assert report.flattened_nodes > 0

    rejected = match_ac_pattern(a + b, candidate, comparison_budget=64)
    assert rejected.stop_reason is AcMatchStopReason.CARDINALITY_MISMATCH
    assert rejected.bindings is None


def test_nested_cardinality_miss_does_not_abort_an_outer_ac_backtrack() -> None:
    a, b, c, d, e, f, g = (Var(name) for name in "abcdefg")
    pattern = ((a + b) * c) + (((d + e) + f) * g)
    valid_product = _node("mul", _node("add", _leaf("a"), _leaf("b")), _leaf("c"))
    three_operand_product = _node(
        "mul",
        _node("add", _node("add", _leaf("a"), _leaf("b")), _leaf("extra")),
        _leaf("c"),
    )
    candidate = _node("add", three_operand_product, valid_product)

    report = match_ac_pattern(pattern, candidate, comparison_budget=128)

    assert report.stop_reason is AcMatchStopReason.MATCHED
    assert report.bindings is not None
    assert set(report.bindings.candidate_path_by_name) == set("abcdefg")


def test_repeated_variables_and_constants_are_rigid() -> None:
    x = Var("x")
    report = match_ac_pattern(
        x ^ x, _node("xor", _leaf("a"), _leaf("a")), comparison_budget=8
    )
    assert report.stop_reason is AcMatchStopReason.MATCHED

    mismatch = match_ac_pattern(
        x ^ x, _node("xor", _leaf("a"), _leaf("b")), comparison_budget=8
    )
    assert mismatch.stop_reason is AcMatchStopReason.MISS

    c = Const("one", 1)
    assert (
        match_ac_pattern(
            c + x,
            _node("add", _leaf("x"), TypedBvTerm(None, 32, value=1)),
            comparison_budget=8,
        ).stop_reason
        is AcMatchStopReason.MATCHED
    )


def test_noncommutative_width_and_budget_fail_closed() -> None:
    x, y = Var("x"), Var("y")
    assert (
        match_ac_pattern(
            x - Const("one", 1),
            _node("sub", TypedBvTerm(None, 32, value=1), _leaf("x")),
            comparison_budget=8,
        ).stop_reason
        is AcMatchStopReason.MISS
    )
    unsupported = TypedBvTerm(None, 7, leaf_key=("test", "x"))
    assert (
        match_ac_pattern(x, unsupported, comparison_budget=8).stop_reason
        is AcMatchStopReason.UNSUPPORTED_WIDTH
    )
    assert (
        match_ac_pattern(
            x + y, _node("add", _leaf("x"), _leaf("y")), comparison_budget=0
        ).stop_reason
        is AcMatchStopReason.COMPARISON_BUDGET
    )
