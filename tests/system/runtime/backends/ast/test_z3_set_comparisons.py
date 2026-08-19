"""Z3 lowering coverage for setz/setnz AST comparisons."""

from __future__ import annotations

from types import SimpleNamespace

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


def _constant_width(value: int, size: int):
    constant = _constant(value)
    constant.dest_size = size
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


def _z3_value_width(opcode: int, left: int, right: int, size: int) -> int:
    from d810.backends.ast.z3 import AstNodeZ3Visitor
    from d810.hexrays.expr.ast import AstNode

    ast = AstNode(opcode, _constant_width(left, size), _constant_width(right, size))
    ast.dest_size = 1
    return z3.simplify(AstNodeZ3Visitor().visit(ast)).as_long()


def _z3_unary_value_width(opcode: int, left: int, size: int) -> int:
    from d810.backends.ast.z3 import AstNodeZ3Visitor
    from d810.hexrays.expr.ast import AstNode

    ast = AstNode(opcode, _constant_width(left, size), None)
    ast.dest_size = 1
    return z3.simplify(AstNodeZ3Visitor().visit(ast)).as_long()


def _z3_binary_expression_width(
    opcode: int, left: int, right: int, input_size: int, result_size: int
):
    from d810.backends.ast.z3 import AstNodeZ3Visitor
    from d810.hexrays.expr.ast import AstNode

    ast = AstNode(
        opcode,
        _constant_width(left, input_size),
        _constant_width(right, input_size),
    )
    ast.dest_size = result_size
    return z3.simplify(AstNodeZ3Visitor().visit(ast))


def _z3_unary_expression_width(
    opcode: int, value: int, input_size: int, result_size: int
):
    from d810.backends.ast.z3 import AstNodeZ3Visitor
    from d810.hexrays.expr.ast import AstNode

    ast = AstNode(opcode, _constant_width(value, input_size), None)
    ast.dest_size = result_size
    return z3.simplify(AstNodeZ3Visitor().visit(ast))


@pytest.mark.skipif(not Z3_AVAILABLE, reason="z3 not installed")
@pytest.mark.skipif(not IDA_AVAILABLE, reason="IDA not available")
class TestZ3SetComparisons:
    def test_symbolic_constant_leaf_is_resized_to_its_native_width(self):
        from d810.backends.ast.z3 import AstNodeZ3Visitor

        constant = _constant_width(0, 1)
        constant.z3_var = z3.BitVec("symbolic_byte_constant", 32)

        assert AstNodeZ3Visitor().visit(constant).size() == 8

    def test_mixed_width_value_operation_is_rejected(self):
        from d810.backends.ast.z3 import AstNodeZ3Visitor
        from d810.errors import D810Z3Exception
        from d810.hexrays.expr.ast import AstNode

        ast = AstNode(
            ida_hexrays.m_add,
            _constant_width(1, 1),
            _constant_width(2, 4),
        )
        ast.dest_size = 4

        with pytest.raises(D810Z3Exception, match="mixed-width"):
            AstNodeZ3Visitor().visit(ast)

    def test_shift_count_may_be_narrower_than_the_shifted_value(self):
        from d810.backends.ast.z3 import AstNodeZ3Visitor
        from d810.hexrays.expr.ast import AstNode

        ast = AstNode(
            ida_hexrays.m_shl,
            _constant_width(1, 4),
            _constant_width(3, 1),
        )
        ast.dest_size = 4

        result = z3.simplify(AstNodeZ3Visitor().visit(ast))
        assert result.size() == 32
        assert result.as_long() == 8

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
            (5, 7),  # both positive, no overflow
            (7, 5),
            (0, 0),
            (100, -100),  # diff signs, small -> no overflow
            (-100, 100),
            (2147483647, -1),  # INT_MAX - (-1) -> overflow
            (-2147483648, 1),  # INT_MIN - 1     -> overflow
            (-2147483648, -1),  # same sign       -> no overflow
        ],
    )
    def test_seto_matches_canonical_subtraction_overflow(self, left, right):
        # m_seto must reproduce d810.core.bits.get_sub_of (the Cython evaluator's
        # OF semantics): the signed-subtraction overflow flag of left - right.
        from d810.core.bits import get_sub_of

        assert _z3_value(ida_hexrays.m_seto, left, right) == get_sub_of(left, right, 4)

    def test_seto_no_longer_raises_unknown_opcode(self):
        # Regression: before the m_seto case, the visitor raised D810Z3Exception
        # ("Unknown opcode seto"), which aborted Z3 proof of every signed-compare
        # opaque predicate (e.g. the OLLVM BCF (y >=s c) | (y <s c) tautology).
        assert _z3_value(ida_hexrays.m_seto, 5, 7) in (0, 1)

    def test_seto_uses_the_native_byte_operand_width(self):
        # int8(0x7f) - int8(0xff) = 127 - (-1) overflows.
        assert _z3_value_width(ida_hexrays.m_seto, 0x7F, 0xFF, 1) == 1

    def test_unary_setz_and_setnz_use_the_native_byte_width(self):
        assert _z3_unary_value_width(ida_hexrays.m_setz, 0, 1) == 1
        assert _z3_unary_value_width(ida_hexrays.m_setnz, 0, 1) == 0

    def test_setp_uses_the_subtraction_result_not_the_left_operand(self):
        # PF is parity of (left - right): 1 - 1 == 0, which has even parity.
        assert _z3_value(ida_hexrays.m_setp, 1, 1) == 1

    def test_cfadd_and_ofadd_are_lowered(self):
        assert _z3_value(ida_hexrays.m_cfadd, 0xFFFFFFFF, 1) == 1
        assert _z3_value(ida_hexrays.m_ofadd, 0x7FFFFFFF, 1) == 1

    def test_smod_uses_truncation_toward_zero_remainder(self):
        assert _z3_value(ida_hexrays.m_smod, 0xFFFFFFF9, 3) == 0xFFFFFFFF

    @pytest.mark.parametrize(
        ("opcode_name", "left", "right"),
        [
            ("add", 0x7F, 1),
            ("sub", 0, 1),
            ("mul", 0x10, 0x20),
            ("udiv", 0xF9, 3),
            ("sdiv", 0xF9, 3),
            ("umod", 0xF9, 3),
            ("smod", 0xF9, 3),
            ("and", 0xF0, 0xAA),
            ("or", 0xF0, 0x0A),
            ("xor", 0xF0, 0xAA),
            ("shl", 0x41, 1),
            ("shr", 0x81, 1),
            ("sar", 0x81, 1),
            ("cfadd", 0xFF, 1),
            ("ofadd", 0x7F, 1),
            ("seto", 0x7F, 0xFF),
            ("setp", 1, 1),
            ("setz", 7, 7),
            ("setnz", 7, 8),
            ("setae", 7, 6),
            ("setb", 6, 7),
            ("seta", 7, 6),
            ("setbe", 6, 7),
            ("setg", 0xFF, 1),
            ("setge", 0xFF, 1),
            ("setl", 0xFF, 1),
            ("setle", 0xFF, 1),
        ],
    )
    def test_binary_lowering_matches_the_concrete_byte_oracle(
        self, opcode_name, left, right
    ):
        from d810.core.bits import fold_binary_opcode

        result_size = 1
        expected = fold_binary_opcode(
            opcode_name,
            left,
            right,
            left_bytes=1,
            right_bytes=1,
            result_bytes=result_size,
        )
        expression = _z3_binary_expression_width(
            getattr(ida_hexrays, f"m_{opcode_name}"),
            left,
            right,
            1,
            result_size,
        )

        assert expression.size() == 8
        assert expression.as_long() == expected

    @pytest.mark.parametrize(
        ("opcode_name", "value", "input_size", "result_size"),
        [
            ("mov", 0x1234, 2, 1),
            ("neg", 5, 1, 1),
            ("lnot", 0, 1, 1),
            ("bnot", 0xAA, 1, 1),
            ("xdu", 0xFF, 1, 4),
            ("xds", 0xFF, 1, 4),
            ("low", 0x1234, 2, 1),
            ("high", 0x1234, 2, 1),
            ("sets", 0xFF, 1, 1),
        ],
    )
    def test_unary_lowering_matches_the_concrete_width_oracle(
        self, opcode_name, value, input_size, result_size
    ):
        from d810.core.bits import fold_unary_opcode

        expected = fold_unary_opcode(
            opcode_name,
            value,
            input_bytes=input_size,
            result_bytes=result_size,
        )
        expression = _z3_unary_expression_width(
            getattr(ida_hexrays, f"m_{opcode_name}"),
            value,
            input_size,
            result_size,
        )

        assert expression.size() == result_size * 8
        assert expression.as_long() == expected

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
        signed_lt = sf != of  # y <s c
        signed_ge = sf == of  # y >=s c
        solver = z3.Solver()
        solver.add(z3.Not(z3.Or(signed_lt, signed_ge)))
        assert solver.check() == z3.unsat  # no y falsifies the tautology

    def test_bounded_zero_predicate_results_preserve_fail_closed_wrappers(
        self, monkeypatch
    ):
        import d810.backends.ast.z3 as z3mod
        from d810.backends.ast.z3 import Z3MopProver
        from d810.backends.ast.z3_proof_policy import (
            Z3ProofPolicy,
            Z3ProofStatus,
        )

        class _FakeAst:
            def is_leaf(self):
                return True

            def get_leaf_list(self):
                return []

        class _FakeVisitor:
            def visit(self, _ast):
                return z3.BitVecVal(0, 32)

        mop = SimpleNamespace(t=ida_hexrays.mop_r, size=4, name="zero")
        monkeypatch.setattr(
            z3mod,
            "structural_mop_hash",
            lambda _mop, _depth: 1,
        )
        monkeypatch.setattr(z3mod, "AstNodeZ3Visitor", _FakeVisitor)

        def _fake_mop_to_ast(_mop, *, node_budget):
            node_budget.consume()
            return _FakeAst()

        monkeypatch.setattr(z3mod, "mop_to_ast", _fake_mop_to_ast)
        prover = Z3MopProver(
            policy=Z3ProofPolicy(max_expression_nodes=1, proof_timeout_ms=100)
        )

        zero_result = prover.prove_always_zero(mop)
        nonzero_result = prover.prove_always_nonzero(mop)

        assert zero_result.status is Z3ProofStatus.PROVED
        assert nonzero_result.status is Z3ProofStatus.DISPROVED
        assert prover.is_always_zero(mop) is True
        assert prover.is_always_nonzero(mop) is False
