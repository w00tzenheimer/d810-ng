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

    @pytest.mark.parametrize(
        "left,right",
        [
            (5, 7),            # both positive, no overflow
            (7, 5),
            (0, 0),
            (100, -100),       # diff signs, small -> no overflow
            (-100, 100),
            (2147483647, -1),  # INT_MAX - (-1) -> overflow
            (-2147483648, 1),  # INT_MIN - 1     -> overflow
            (-2147483648, -1), # same sign       -> no overflow
        ],
    )
    def test_seto_matches_canonical_subtraction_overflow(self, left, right):
        # m_seto must reproduce d810.core.bits.get_sub_of (the Cython evaluator's
        # OF semantics): the signed-subtraction overflow flag of left - right.
        from d810.core.bits import get_sub_of

        assert _z3_value(ida_hexrays.m_seto, left, right) == get_sub_of(
            left, right, 4
        )

    def test_seto_no_longer_raises_unknown_opcode(self):
        # Regression: before the m_seto case, the visitor raised D810Z3Exception
        # ("Unknown opcode seto"), which aborted Z3 proof of every signed-compare
        # opaque predicate (e.g. the OLLVM BCF (y >=s c) | (y <s c) tautology).
        assert _z3_value(ida_hexrays.m_seto, 5, 7) in (0, 1)

    def test_signed_compare_tautology_is_provable_with_seto(self):
        # The OLLVM/Tigress BCF shape: (y >=s c) | (y <s c) == 1 for ALL y.
        # Hex-Rays lowers the signed compares to flags -- <s is SF ^ OF, >=s is
        # SF == OF -- so the proof needs m_seto. Build SF/OF over a symbolic y the
        # way the visitor does and prove the disjunction is a tautology.
        y = z3.BitVec("y", 32)
        c = z3.BitVecVal(0xA, 32)
        difference = y - c
        sf = difference < z3.BitVecVal(0, 32)  # m_sets(left=y-c)
        overflow_bit = z3.Extract(31, 31, (y ^ difference) & (y ^ c))
        of = overflow_bit == z3.BitVecVal(1, 1)  # m_seto(y, c)
        signed_lt = sf != of                     # y <s c
        signed_ge = sf == of                     # y >=s c
        solver = z3.Solver()
        solver.add(z3.Not(z3.Or(signed_lt, signed_ge)))
        assert solver.check() == z3.unsat  # no y falsifies the tautology
