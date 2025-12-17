"""A declarative DSL for defining optimization rules using symbolic expressions.

This module provides a high-level, declarative way to define optimization patterns
using Python's operator overloading. The symbolic expressions are pure tree structures
with no dependencies on IDA Pro or any specific backend.

Example:
    >>> x, y = Var("x"), Var("y")
    >>> pattern = (x | y) - (x & y)  # Pure symbolic expression
    >>> # Can be converted to different representations by visitors:
    >>> # - Z3VerificationVisitor → Z3 for proving
    >>> # - IDAVisitor → AstNode for pattern matching
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from d810.mba.constraints import ConstraintExpr


@runtime_checkable
class SymbolicExpressionProtocol(Protocol):
    """Protocol for structural typing of SymbolicExpression - survives hot reloads."""

    operation: str | None
    left: "SymbolicExpressionProtocol | None"
    right: "SymbolicExpressionProtocol | None"
    name: str | None
    value: int | None

    def is_leaf(self) -> bool: ...


class SymbolicExpression:
    """A pure symbolic expression tree with no backend dependencies.

    This is a self-contained tree structure representing symbolic operations.
    It does NOT depend on IDA Pro or any specific representation - visitors
    convert it to different backends (Z3, IDA AstNode, strings, etc.).

    Attributes:
        operation: The operation type ("add", "sub", "xor", etc.) or None for leaves.
        left: Left child expression (for binary operations).
        right: Right child expression (for binary operations).
        name: Variable/constant name (for leaf nodes).
        value: Concrete value (for constant leaves), None for symbolic constants.
        constraint: Boolean constraint (for bool_to_int operation only).
    """

    def __init__(
        self,
        operation: str | None = None,
        left: SymbolicExpression | None = None,
        right: SymbolicExpression | None = None,
        name: str | None = None,
        value: int | None = None,
        constraint: ConstraintExpr | None = None,
        is_pattern_constant: bool = False,
    ):
        """Initialize a symbolic expression.

        Args:
            operation: Operation type ("add", "sub", etc.) or None for leaves.
            left: Left operand for binary operations.
            right: Right operand for binary operations.
            name: Name for variables/constants.
            value: Concrete value for constants, None for variables/symbolic constants.
            constraint: Boolean constraint (only for "bool_to_int" operation).
            is_pattern_constant: True if this is a pattern-matching constant (created via Const()).
        """
        self.operation = operation
        self.left = left
        self.right = right
        self.name = name
        self.value = value
        self.constraint = constraint
        self.is_pattern_constant = is_pattern_constant

    def is_leaf(self) -> bool:
        """Check if this is a leaf node (variable or constant)."""
        return self.operation is None

    def is_constant(self) -> bool:
        """Check if this is a constant (has a concrete value)."""
        return self.is_leaf() and self.value is not None

    def is_variable(self) -> bool:
        """Check if this is a variable (leaf with no concrete value)."""
        return self.is_leaf() and self.value is None

    # Binary arithmetic operations
    def __add__(self, other: SymbolicExpression) -> SymbolicExpression:
        """Addition: self + other."""
        return SymbolicExpression(operation="add", left=self, right=other)

    def __sub__(self, other: SymbolicExpression) -> SymbolicExpression:
        """Subtraction: self - other."""
        return SymbolicExpression(operation="sub", left=self, right=other)

    def __mul__(self, other: SymbolicExpression) -> SymbolicExpression:
        """Multiplication: self * other."""
        return SymbolicExpression(operation="mul", left=self, right=other)

    # Binary bitwise operations
    def __and__(self, other: SymbolicExpression) -> SymbolicExpression:
        """Bitwise AND: self & other."""
        return SymbolicExpression(operation="and", left=self, right=other)

    def __or__(self, other: SymbolicExpression) -> SymbolicExpression:
        """Bitwise OR: self | other."""
        return SymbolicExpression(operation="or", left=self, right=other)

    def __xor__(self, other: SymbolicExpression) -> SymbolicExpression:
        """Bitwise XOR: self ^ other."""
        return SymbolicExpression(operation="xor", left=self, right=other)

    # Shift operations
    def __lshift__(self, other: SymbolicExpression) -> SymbolicExpression:
        """Left shift: self << other."""
        return SymbolicExpression(operation="shl", left=self, right=other)

    def __rshift__(self, other: SymbolicExpression) -> SymbolicExpression:
        """Logical right shift: self >> other."""
        return SymbolicExpression(operation="shr", left=self, right=other)

    def sar(self, other: SymbolicExpression) -> SymbolicExpression:
        """Arithmetic right shift: self.sar(other)."""
        return SymbolicExpression(operation="sar", left=self, right=other)

    # Unary operations
    def __invert__(self) -> SymbolicExpression:
        """Bitwise NOT: ~self."""
        return SymbolicExpression(operation="bnot", left=self)

    def __neg__(self) -> SymbolicExpression:
        """Arithmetic negation: -self."""
        return SymbolicExpression(operation="neg", left=self)

    # Logical operations (return 0 or 1)
    def lnot(self) -> SymbolicExpression:
        """Logical NOT: returns 1 if self is 0, else 0."""
        return SymbolicExpression(operation="lnot", left=self)

    def __eq__(self, other: SymbolicExpression) -> ConstraintExpr:  # type: ignore
        """Equality constraint: self == other.

        NOTE: This overrides Python's default equality to return a ConstraintExpr
        instead of bool. This allows writing declarative constraints like:
            val_res == c2 - ONE

        For object identity comparison, use `is` instead.

        Args:
            other: The right-hand side of the equality

        Returns:
            An EqualityConstraint that can be used in CONSTRAINTS list
        """
        from d810.mba.constraints import EqualityConstraint

        return EqualityConstraint(self, other)

    def __ne__(self, other: SymbolicExpression) -> ConstraintExpr:  # type: ignore
        """Inequality constraint: self != other.

        Args:
            other: The right-hand side of the inequality

        Returns:
            A ComparisonConstraint that can be used in CONSTRAINTS list
        """
        from d810.mba.constraints import ComparisonConstraint

        return ComparisonConstraint(self, other, "!=", "ne")

    def __lt__(self, other: SymbolicExpression) -> ConstraintExpr:
        """Less-than constraint: self < other.

        Args:
            other: The right-hand side of the comparison

        Returns:
            A ComparisonConstraint that can be used in CONSTRAINTS list
        """
        from d810.mba.constraints import ComparisonConstraint

        return ComparisonConstraint(self, other, "<", "lt")

    def __le__(self, other: SymbolicExpression) -> ConstraintExpr:
        """Less-than-or-equal constraint: self <= other.

        Args:
            other: The right-hand side of the comparison

        Returns:
            A ComparisonConstraint that can be used in CONSTRAINTS list
        """
        from d810.mba.constraints import ComparisonConstraint

        return ComparisonConstraint(self, other, "<=", "le")

    def __gt__(self, other: SymbolicExpression) -> ConstraintExpr:
        """Greater-than constraint: self > other.

        Args:
            other: The right-hand side of the comparison

        Returns:
            A ComparisonConstraint that can be used in CONSTRAINTS list
        """
        from d810.mba.constraints import ComparisonConstraint

        return ComparisonConstraint(self, other, ">", "gt")

    def __ge__(self, other: SymbolicExpression) -> ConstraintExpr:
        """Greater-than-or-equal constraint: self >= other.

        Args:
            other: The right-hand side of the comparison

        Returns:
            A ComparisonConstraint that can be used in CONSTRAINTS list
        """
        from d810.mba.constraints import ComparisonConstraint

        return ComparisonConstraint(self, other, ">=", "ge")

    def __repr__(self) -> str:
        """Return a string representation of this expression."""
        if self.is_leaf():
            if self.is_constant():
                return f"{self.name or self.value}"
            return self.name or "<?>"

        if self.operation in ("neg", "bnot", "lnot"):
            # Unary operations
            op_sym = {"neg": "-", "bnot": "~", "lnot": "!"}[self.operation]
            return f"({op_sym}{self.left})"

        # Binary operations
        op_sym = {
            "add": "+",
            "sub": "-",
            "mul": "*",
            "and": "&",
            "or": "|",
            "xor": "^",
            "shl": "<<",
            "shr": ">>",
            "sar": ">>a",
        }.get(self.operation, f"?{self.operation}?")

        return f"({self.left} {op_sym} {self.right})"

    def __str__(self) -> str:
        """Return a string representation of this expression."""
        return repr(self)


def Var(name: str) -> SymbolicExpression:
    """Create a symbolic variable.

    Variables represent unknown values in patterns. During pattern matching,
    they bind to specific expressions in the code being analyzed.

    Args:
        name: The variable name (e.g., "x_0", "x_1").

    Returns:
        A SymbolicExpression representing a variable.

    Example:
        >>> x = Var("x_0")
        >>> y = Var("x_1")
        >>> pattern = x + y  # Matches any addition
    """
    return SymbolicExpression(name=name, value=None)


def Const(name: str, value: int | None = None) -> SymbolicExpression:
    """Create a symbolic constant.

    Constants can be:
    - Pattern-matching constants (value=None): Match any constant, bind its value
    - Concrete constants (value=int): Match only this specific value

    Args:
        name: The constant name (e.g., "c_1", "ONE").
        value: Concrete value (e.g., 1) or None for pattern-matching.

    Returns:
        A SymbolicExpression representing a constant.

    Examples:
        >>> c1 = Const("c_1")  # Matches any constant, stores value
        >>> one = Const("ONE", 1)  # Matches only value 1
        >>> pattern = x + Const("c_1")  # x plus any constant
    """
    return SymbolicExpression(name=name, value=value, is_pattern_constant=True)


def Zext(expr: SymbolicExpression, target_width: int) -> SymbolicExpression:
    """Zero-extend an expression to a larger bit-width.

    This represents the `xdu` (extend-unsigned-double) operation in IDA microcode.
    Zero-extension pads the high bits with zeros when converting to a larger width.

    Args:
        expr: The expression to zero-extend
        target_width: The target bit-width (e.g., 32 for extending to 32 bits)

    Returns:
        A SymbolicExpression representing the zero-extended value.

    Examples:
        >>> # Extend (x & 1) to 32 bits
        >>> pattern = Zext(x & ONE, 32)

        >>> # Pattern: xdu(x & 1) == 2 is always false
        >>> PATTERN = (Zext(x & ONE, 32) == TWO).to_int()
        >>> REPLACEMENT = ZERO  # Always false
    """
    return SymbolicExpression(operation="zext", left=expr, value=target_width)


# Common symbolic constants for convenience
ZERO = Const("0", 0)
ONE = Const("1", 1)
TWO = Const("2", 2)
NEGATIVE_ONE = Const("-1", -1)
NEGATIVE_TWO = Const("-2", -2)


class DynamicConst:
    """A constant whose value is computed dynamically at match time.

    This allows rules to compute new constant values based on matched
    constants in the pattern. For example, a rule might need to compute
    `c2 - 1` when it matches `c2`.

    Attributes:
        name: The name/identifier for this dynamic constant.
        compute: A function that takes the match context and returns the value.
        size_from: Optional variable name to copy the size from (default: use context size).

    Example:
        >>> # Rule that replaces pattern with c2 - 1
        >>> REPLACEMENT = x + DynamicConst("val_res", lambda ctx: ctx['c2'].value - 1)
    """

    def __init__(self, name: str, compute, size_from: str | None = None):
        """Initialize a dynamic constant.

        Args:
            name: The constant's name/identifier.
            compute: Callable that takes match context dict and returns int value.
            size_from: Optional variable name to determine operand size.
        """
        self.name = name
        self.compute = compute
        self.size_from = size_from

    def __repr__(self) -> str:
        return f"DynamicConst({self.name})"

    def __str__(self) -> str:
        return self.name


class ConstraintPredicate:
    """Helper for defining common constraint predicates.

    This class provides factory methods for creating common constraint
    checks that rules need to perform on matched values.

    Example:
        >>> from d810.mba.dsl import when
        >>> CONSTRAINTS = [
        ...     when.equal_mops("c_1", "c_2"),  # c_1 value == c_2 value
        ...     when.is_bnot("c_1", "c_2"),     # c_1 == ~c_2
        ... ]
    """

    @staticmethod
    def equal_mops(var1: str, var2: str, ignore_size: bool = True):
        """Check that two matched operands have equal values.

        Args:
            var1: Name of first variable in the match context.
            var2: Name of second variable in the match context.
            ignore_size: If True, compare values ignoring operand size.

        Returns:
            A constraint function that checks equality.

        Example:
            >>> # Rule is only valid when c_1 value equals c_2 value
            >>> CONSTRAINTS = [when.equal_mops("c_1", "c_2")]
        """

        def check(ctx):
            from d810.hexrays.hexrays_helpers import equal_mops_ignore_size

            if var1 not in ctx or var2 not in ctx:
                return False
            if ignore_size:
                return equal_mops_ignore_size(ctx[var1].mop, ctx[var2].mop)
            else:
                return ctx[var1].mop == ctx[var2].mop

        return check

    @staticmethod
    def is_bnot(var1: str, var2: str):
        """Check that var1 == ~var2 (bitwise NOT relationship).

        Args:
            var1: Name of first variable.
            var2: Name of second variable (should be bitwise NOT of var1).

        Returns:
            A constraint function that checks the NOT relationship.

        Example:
            >>> # Rule is only valid when c_1 == ~c_2
            >>> CONSTRAINTS = [when.is_bnot("c_1", "c_2")]
        """

        def check(ctx):
            from d810.hexrays.hexrays_helpers import equal_bnot_mop

            if var1 not in ctx or var2 not in ctx:
                return False
            return equal_bnot_mop(ctx[var1].mop, ctx[var2].mop)

        return check

    @staticmethod
    def const_equals(var: str, value: int):
        """Check that a matched constant has a specific value.

        Args:
            var: Name of the constant variable.
            value: The expected value.

        Returns:
            A constraint function that checks the value.

        Example:
            >>> # Rule is only valid when c_1 equals 0xFF
            >>> CONSTRAINTS = [when.const_equals("c_1", 0xFF)]
        """

        def check(ctx):
            if var not in ctx:
                return False
            return ctx[var].value == value

        return check

    @staticmethod
    def const_satisfies(var: str, predicate):
        """Check that a matched constant satisfies a custom predicate.

        Args:
            var: Name of the constant variable.
            predicate: A callable that takes the constant value and returns bool.

        Returns:
            A constraint function that checks the predicate.

        Example:
            >>> # Rule is only valid when c_1 is even
            >>> CONSTRAINTS = [when.const_satisfies("c_1", lambda v: v % 2 == 0)]
        """

        def check(ctx):
            if var not in ctx:
                return False
            return predicate(ctx[var].value)

        return check

    @staticmethod
    def or_inequality(var1: str, var2: str):
        """Check that (var1 | var2) != var2.

        This is useful for predicate simplification where (x | c1) can never equal c2
        if (c1 | c2) != c2.

        Args:
            var1: First variable name
            var2: Second variable name

        Returns:
            Constraint function with Z3 conversion attached

        Example:
            >>> CONSTRAINTS = [when.or_inequality("c_1", "c_2")]
        """

        def check(ctx):
            if var1 not in ctx or var2 not in ctx:
                return False
            return (ctx[var1].value | ctx[var2].value) != ctx[var2].value

        # Attach Z3 conversion
        def to_z3(z3_vars):
            import z3

            if var1 not in z3_vars or var2 not in z3_vars:
                return None
            return (z3_vars[var1] | z3_vars[var2]) != z3_vars[var2]

        check._to_z3 = to_z3
        return check

    @staticmethod
    def and_inequality(var1: str, var2: str):
        """Check that (var1 & var2) != var2.

        Args:
            var1: First variable name
            var2: Second variable name

        Returns:
            Constraint function with Z3 conversion attached

        Example:
            >>> CONSTRAINTS = [when.and_inequality("c_1", "c_2")]
        """

        def check(ctx):
            if var1 not in ctx or var2 not in ctx:
                return False
            return (ctx[var1].value & ctx[var2].value) != ctx[var2].value

        def to_z3(z3_vars):
            import z3

            if var1 not in z3_vars or var2 not in z3_vars:
                return None
            return (z3_vars[var1] & z3_vars[var2]) != z3_vars[var2]

        check._to_z3 = to_z3
        return check

    @staticmethod
    def equals_minus_two(var: str):
        """Check that var equals -2 in two's complement.

        For size-independent verification, this checks: (var + 2) masked to bit width == 0.

        Args:
            var: Variable name to check

        Returns:
            Constraint function with Z3 conversion attached

        Example:
            >>> CONSTRAINTS = [when.equals_minus_two("val_fe")]
        """

        def check(ctx):
            if var not in ctx:
                return False
            from d810.hexrays.hexrays_helpers import AND_TABLE

            # Check (val + 2) & mask == 0, which means val == -2 in two's complement
            return (ctx[var].value + 2) & AND_TABLE[ctx[var].size] == 0

        def to_z3(z3_vars):
            import z3

            if var not in z3_vars:
                return None
            # For 32-bit: val == -2 is equivalent to val == 0xFFFFFFFE
            # Which is (val + 2) & 0xFFFFFFFF == 0
            # In Z3, this is simply: z3_var == -2 (Z3 handles two's complement)
            return z3_vars[var] == z3.BitVecVal(-2, 32)

        check._to_z3 = to_z3
        return check


# Singleton instance for constraint predicates
when = ConstraintPredicate()
