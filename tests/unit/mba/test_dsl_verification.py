"""Unit tests for d810.mba DSL and Z3 verification.

These tests verify that the symbolic expression DSL and Z3 verification
work WITHOUT IDA Pro. This is critical for enabling unit testing of
optimization rules outside of the IDA environment.

Key tests:
1. SymbolicExpression operations (Var, Const, operators)
2. Z3VerificationVisitor conversion
3. prove_equivalence for known mathematical identities

NOTE: Tests for VerifiableRule subclass definition are in PR #21 (mba-rules)
since they require the d810.mba.rules module.
"""

import pytest


class TestDSL:
    """Tests for the symbolic expression DSL."""

    def test_var_creation(self):
        """Test that Var() creates a symbolic variable."""
        from d810.mba.dsl import Var

        x = Var("x")
        assert x.name == "x"
        assert x.value is None
        assert x.is_leaf()
        assert x.is_variable()
        assert not x.is_constant()

    def test_const_creation_symbolic(self):
        """Test that Const() without value creates a pattern-matching constant."""
        from d810.mba.dsl import Const

        c = Const("c_1")
        assert c.name == "c_1"
        assert c.value is None
        assert c.is_leaf()
        # Pattern-matching constants are NOT variables but also NOT concrete constants
        assert not c.is_constant()  # No concrete value
        assert c.is_variable()  # Will bind to a value during matching

    def test_const_creation_concrete(self):
        """Test that Const() with value creates a concrete constant."""
        from d810.mba.dsl import Const

        one = Const("ONE", 1)
        assert one.name == "ONE"
        assert one.value == 1
        assert one.is_leaf()
        assert one.is_constant()
        assert not one.is_variable()

    def test_predefined_constants(self):
        """Test predefined constants ZERO, ONE, TWO, etc."""
        from d810.mba.dsl import NEGATIVE_ONE, NEGATIVE_TWO, ONE, TWO, ZERO

        assert ZERO.value == 0
        assert ONE.value == 1
        assert TWO.value == 2
        assert NEGATIVE_ONE.value == -1
        assert NEGATIVE_TWO.value == -2

    def test_binary_operations(self):
        """Test all binary operations produce correct expression trees."""
        from d810.mba.dsl import Var

        x, y = Var("x"), Var("y")

        # Arithmetic
        add = x + y
        assert add.operation == "add"
        assert add.left is x
        assert add.right is y

        sub = x - y
        assert sub.operation == "sub"

        mul = x * y
        assert mul.operation == "mul"

        # Bitwise
        and_op = x & y
        assert and_op.operation == "and"

        or_op = x | y
        assert or_op.operation == "or"

        xor_op = x ^ y
        assert xor_op.operation == "xor"

        # Shift
        shl = x << y
        assert shl.operation == "shl"

        shr = x >> y
        assert shr.operation == "shr"

    def test_unary_operations(self):
        """Test unary operations."""
        from d810.mba.dsl import Var

        x = Var("x")

        neg = -x
        assert neg.operation == "neg"
        assert neg.left is x
        assert neg.right is None

        bnot = ~x
        assert bnot.operation == "bnot"

        lnot = x.lnot()
        assert lnot.operation == "lnot"

    def test_repr(self):
        """Test string representation of expressions."""
        from d810.mba.dsl import Const, Var

        x, y = Var("x"), Var("y")
        expr = (x | y) - (x & y)

        # Just ensure repr works and produces something sensible
        s = repr(expr)
        assert "x" in s
        assert "y" in s


class TestZ3Verification:
    """Tests for Z3 verification of symbolic expressions."""

    def test_visitor_import(self):
        """Test that Z3VerificationVisitor can be imported without IDA."""
        from d810.mba.backends.z3 import Z3VerificationVisitor

        visitor = Z3VerificationVisitor(bit_width=32)
        assert visitor is not None
        assert visitor.bit_width == 32

    def test_visitor_converts_variable(self):
        """Test Z3VerificationVisitor converts variables to Z3 BitVec."""
        from d810.mba.dsl import Var
        from d810.mba.backends.z3 import Z3VerificationVisitor

        x = Var("x")
        visitor = Z3VerificationVisitor()
        z3_expr = visitor.visit(x)

        # Just verify it's a Z3 expression
        assert str(z3_expr) == "x"

    def test_visitor_converts_constant(self):
        """Test Z3VerificationVisitor converts constants to Z3 BitVecVal."""
        from d810.mba.dsl import Const
        from d810.mba.backends.z3 import Z3VerificationVisitor

        one = Const("ONE", 1)
        visitor = Z3VerificationVisitor()
        z3_expr = visitor.visit(one)

        # Just verify it's a Z3 expression with value 1
        assert "1" in str(z3_expr)

    def test_visitor_converts_expression(self):
        """Test Z3VerificationVisitor converts complex expression."""
        from d810.mba.dsl import Var
        from d810.mba.backends.z3 import Z3VerificationVisitor

        x, y = Var("x"), Var("y")
        expr = (x | y) - (x & y)

        visitor = Z3VerificationVisitor()
        z3_expr = visitor.visit(expr)

        # Verify it's a well-formed Z3 expression
        s = str(z3_expr)
        assert "x" in s
        assert "y" in s


class TestProveEquivalence:
    """Tests for prove_equivalence function."""

    def test_prove_equivalence_import(self):
        """Test prove_equivalence can be imported without IDA."""
        from d810.mba.backends.z3 import prove_equivalence

        assert callable(prove_equivalence)

    def test_xor_identity_1(self):
        """Test XOR identity: (x | y) - (x & y) = x ^ y."""
        from d810.mba.dsl import Var
        from d810.mba.backends.z3 import prove_equivalence

        x, y = Var("x"), Var("y")
        pattern = (x | y) - (x & y)
        replacement = x ^ y

        is_equiv, counter = prove_equivalence(pattern, replacement)
        assert is_equiv is True
        assert counter is None

    def test_xor_identity_2(self):
        """Test XOR identity: x + y - 2*(x & y) = x ^ y."""
        from d810.mba.dsl import Const, Var
        from d810.mba.backends.z3 import prove_equivalence

        x, y = Var("x"), Var("y")
        TWO = Const("2", 2)
        pattern = x + y - TWO * (x & y)
        replacement = x ^ y

        is_equiv, counter = prove_equivalence(pattern, replacement)
        assert is_equiv is True
        assert counter is None

    def test_bnot_identity(self):
        """Test bitwise NOT identity: ~x = -x - 1."""
        from d810.mba.dsl import Const, Var
        from d810.mba.backends.z3 import prove_equivalence

        x = Var("x")
        ONE = Const("1", 1)
        pattern = ~x
        replacement = -x - ONE

        is_equiv, counter = prove_equivalence(pattern, replacement)
        assert is_equiv is True

    def test_add_commutativity(self):
        """Test addition is commutative: x + y = y + x."""
        from d810.mba.dsl import Var
        from d810.mba.backends.z3 import prove_equivalence

        x, y = Var("x"), Var("y")
        is_equiv, _ = prove_equivalence(x + y, y + x)
        assert is_equiv is True

    def test_non_equivalent_detected(self):
        """Test that non-equivalent expressions are detected."""
        from d810.mba.dsl import Var
        from d810.mba.backends.z3 import prove_equivalence

        x, y = Var("x"), Var("y")
        pattern = x + y
        wrong_replacement = x - y

        is_equiv, counter = prove_equivalence(pattern, wrong_replacement)
        assert is_equiv is False
        # Counter should provide values where they differ
        assert counter is not None
