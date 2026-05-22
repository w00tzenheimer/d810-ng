"""Z3 lowering coverage for setz/setnz AST comparisons."""

from __future__ import annotations

import pytest

try:
    import z3

    Z3_AVAILABLE = True
except ImportError:
    Z3_AVAILABLE = False

try:
    import ida_hexrays

    IDA_AVAILABLE = True
except ImportError:
    IDA_AVAILABLE = False


def _constant(value: int):
    from d810.hexrays.expr.ast import AstConstant

    constant = AstConstant(str(value), value, 4)
    constant.dest_size = 4
    return constant


def _z3_value(opcode: int, left: int, right: int | None = None) -> int:
    from d810.backends.ast.z3 import AstNodeZ3Visitor
    from d810.hexrays.expr.ast import AstNode

    ast = AstNode(
        opcode,
        _constant(left),
        _constant(right) if right is not None else None,
    )
    return z3.simplify(AstNodeZ3Visitor().visit(ast)).as_long()


@pytest.mark.skipif(not Z3_AVAILABLE, reason="z3 not installed")
@pytest.mark.skipif(not IDA_AVAILABLE, reason="IDA not available")
class TestZ3SetComparisons:
    def test_setz_compares_binary_operands(self):
        assert _z3_value(ida_hexrays.m_setz, 5, 5) == 1
        assert _z3_value(ida_hexrays.m_setz, 5, 7) == 0

    def test_setnz_compares_binary_operands(self):
        assert _z3_value(ida_hexrays.m_setnz, 5, 5) == 0
        assert _z3_value(ida_hexrays.m_setnz, 5, 7) == 1

    def test_unary_zero_test_behavior_is_preserved(self):
        assert _z3_value(ida_hexrays.m_setz, 0) == 1
        assert _z3_value(ida_hexrays.m_setz, 5) == 0
        assert _z3_value(ida_hexrays.m_setnz, 0) == 0
        assert _z3_value(ida_hexrays.m_setnz, 5) == 1
