"""Concrete bit-vector evaluation, independent of symbolic Z3 certification."""

from types import SimpleNamespace

import pytest

from d810.ir.expr.constraints import EqualityConstraint
from d810.ir.expr.dsl import Const


@pytest.mark.parametrize("width", [8, 16, 32, 64])
def test_complement_preserves_all_expression_bits(width):
    value = 0x0051C78825B4E571 & ((1 << width) - 1)
    constraint = EqualityConstraint(Const("result"), ~Const("c"))
    assert constraint.eval_and_define({"c": value, "_width": width}) == (
        "result",
        (~value) & ((1 << width) - 1),
    )


@pytest.mark.parametrize(
    "context", [{}, {"_width": 0}, {"_width": True}, {"_width": 7}, {"_width": 32.0}]
)
def test_missing_or_invalid_width_cannot_define(context):
    constraint = EqualityConstraint(Const("result"), ~Const("c"))
    assert constraint.eval_and_define({"c": 0x0051C78825B4E571, **context}) == (
        None,
        None,
    )


def test_typed_leaf_cannot_be_silently_truncated():
    constraint = EqualityConstraint(Const("result"), ~Const("c"))
    leaf = SimpleNamespace(value=0x0051C78825B4E571, size=8, expected_size=8)
    assert constraint.eval_and_define({"c": leaf, "_width": 32}) == (None, None)


def test_inconsistent_leaf_size_is_rejected():
    constraint = EqualityConstraint(Const("result"), ~Const("c"))
    leaf = SimpleNamespace(value=1, size=8, expected_size=4)
    assert constraint.eval_and_define({"c": leaf, "_width": 64}) == (None, None)


def test_unsized_runtime_leaf_is_rejected():
    constraint = EqualityConstraint(Const("result"), ~Const("c"))
    assert constraint.eval_and_define(
        {"c": SimpleNamespace(value=1), "_width": 64}
    ) == (None, None)


def test_narrow_shift_count_is_not_data_width():
    constraint = EqualityConstraint(Const("result"), Const("c") >> Const("count"))
    context = {
        "c": SimpleNamespace(value=0x8000000000000000, size=8),
        "count": SimpleNamespace(value=32, size=1),
        "_width": 64,
    }
    assert constraint.eval_and_define(context) == ("result", 0x80000000)


def test_mixed_width_arithmetic_without_conversion_is_rejected():
    constraint = EqualityConstraint(Const("result"), Const("c") + Const("d"))
    context = {
        "c": SimpleNamespace(value=0x8000000000000000, size=8),
        "d": SimpleNamespace(value=1, size=1),
        "_width": 64,
    }
    assert constraint.eval_and_define(context) == (None, None)
