"""Constraint expressions for declarative rule verification.

This module provides constraint expression types that allow rules to specify
constraints declaratively using operator overloading, rather than through lambda parsing.

These classes are BACKEND-AGNOSTIC data structures. They describe *what* a constraint
is, not *how* to verify it. The Z3-specific conversion is in d810.mba.backends.z3.

Example:
    Instead of:
        val_res = DynamicConst("val_res", lambda ctx: ctx['c_2'].value - 1)

    Use:
        val_res = Const("val_res")
        CONSTRAINTS = [val_res == c2 - ONE]

To convert constraints to Z3 for verification:
    from d810.mba.backends.z3 import constraint_to_z3
    z3_bool = constraint_to_z3(constraint, z3_vars)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from .dsl import SymbolicExpression, SymbolicExpressionProtocol


# =============================================================================
# Protocols for hot-reload-safe isinstance() checks
# =============================================================================


@runtime_checkable
class ConstraintExprProtocol(Protocol):
    """Protocol for structural typing of ConstraintExpr - survives hot reloads.

    Used for isinstance() checks that need to work after hot reload when class
    identity changes. Any class implementing check() and eval_and_define() methods
    is compatible with this protocol.
    """

    def check(self, candidate: dict[str, Any]) -> bool:
        """Check if constraint holds for concrete candidate values."""
        ...

    def eval_and_define(
        self, candidate: dict[str, Any]
    ) -> tuple[str | None, int | None]:
        """Try to extract a variable definition from this constraint."""
        ...


@runtime_checkable
class EqualityConstraintProtocol(Protocol):
    """Protocol for structural typing of EqualityConstraint - survives hot reloads.

    Attributes accessed after isinstance() checks:
    - left: Left-hand side expression
    - right: Right-hand side expression
    """

    left: Any
    right: Any


@runtime_checkable
class ComparisonConstraintProtocol(Protocol):
    """Protocol for structural typing of ComparisonConstraint - survives hot reloads.

    Attributes accessed after isinstance() checks:
    - left: Left-hand side expression
    - right: Right-hand side expression
    - op_name: Operation name ("ne", "lt", "gt", "le", "ge")
    """

    left: Any
    right: Any
    op_name: str


@runtime_checkable
class AndConstraintProtocol(Protocol):
    """Protocol for structural typing of AndConstraint - survives hot reloads.

    Attributes accessed after isinstance() checks:
    - left: Left constraint
    - right: Right constraint
    """

    left: "ConstraintExprProtocol"
    right: "ConstraintExprProtocol"


@runtime_checkable
class OrConstraintProtocol(Protocol):
    """Protocol for structural typing of OrConstraint - survives hot reloads.

    Attributes accessed after isinstance() checks:
    - left: Left constraint
    - right: Right constraint
    """

    left: "ConstraintExprProtocol"
    right: "ConstraintExprProtocol"


@runtime_checkable
class NotConstraintProtocol(Protocol):
    """Protocol for structural typing of NotConstraint - survives hot reloads.

    Attributes accessed after isinstance() checks:
    - operand: The constraint to negate
    """

    operand: "ConstraintExprProtocol"


@dataclass
class ConstraintExpr:
    """Base class for constraint expressions.

    Constraint expressions are created by operator overloading on SymbolicExpression.
    They are pure data structures describing constraints. Backend-specific conversion
    (e.g., to Z3) is handled by visitor functions in the respective backend modules.

    For Z3 conversion, use: d810.mba.backends.z3.constraint_to_z3()
    """

    def eval_and_define(
        self, candidate: dict[str, Any]
    ) -> tuple[str | None, int | None]:
        """Try to extract a variable definition from this constraint.

        If this is a defining constraint (e.g., val_res == c2 - 1), returns
        (variable_name, computed_value). Otherwise returns (None, None).

        Args:
            candidate: Dictionary mapping variable names to matched values

        Returns:
            (var_name, value) if this defines a variable, else (None, None)
        """
        raise NotImplementedError

    def check(self, candidate: dict[str, Any]) -> bool:
        """Check if this constraint holds for concrete candidate values.

        Args:
            candidate: Dictionary mapping variable names to matched values

        Returns:
            True if constraint is satisfied, False otherwise
        """
        raise NotImplementedError

    def __call__(self, candidate: dict[str, Any]) -> bool:
        """Make constraints callable for backward compatibility.

        This allows existing code that expects `constraint(match_context)` to work.

        Args:
            candidate: Dictionary mapping variable names to matched values

        Returns:
            True if constraint is satisfied, False otherwise
        """
        return self.check(candidate)

    def __and__(self, other: ConstraintExpr) -> ConstraintExpr:
        """Logical AND: self & other."""
        return AndConstraint(self, other)

    def __or__(self, other: ConstraintExpr) -> ConstraintExpr:
        """Logical OR: self | other."""
        return OrConstraint(self, other)

    def __invert__(self) -> ConstraintExpr:
        """Logical NOT: ~self."""
        return NotConstraint(self)

    def to_int(self) -> "SymbolicExpression":
        """Convert boolean constraint to integer expression (0 or 1).

        This bridges the gap between boolean constraints (formulas) and arithmetic
        expressions (terms). In C-like languages and IDA microcode, comparison
        results are treated as integers (0 for false, 1 for true).

        Equivalent to:
        - C: (int)(x != y)
        - Z3: If(x != y, 1, 0)
        - IDA: SETNZ, SETZ instructions

        Example:
            >>> x = Var("x")
            >>> constraint = x != Const("0", 0)  # Returns ConstraintExpr (boolean)
            >>> int_expr = constraint.to_int()   # Returns SymbolicExpression (0 or 1)
            >>> pattern = int_expr + Const("5", 5)  # Now can use in arithmetic!

        Returns:
            SymbolicExpression representing 0 (false) or 1 (true)
        """
        return SymbolicExpression(operation="bool_to_int", constraint=self)


@dataclass
class EqualityConstraint(ConstraintExpr):
    """Represents an equality constraint: left == right.

    Can be either:
    1. Defining constraint: val_res == c2 - 1 (defines val_res)
    2. Checking constraint: c1 == ~c2 (checks relationship)

    Attributes:
        left: Left-hand side expression
        right: Right-hand side expression
    """

    left: Any  # SymbolicExpression or AstBase
    right: Any  # SymbolicExpression or AstBase

    def eval_and_define(
        self, candidate: dict[str, Any]
    ) -> tuple[str | None, int | None]:
        """If left is a simple constant, define it as right's value."""
        # Check if left is a simple constant (not a compound expression)
        if self._is_simple_constant(self.left):
            const_name = self._get_name(self.left)

            # Check if this constant is already in candidate (matched from pattern)
            # If yes, this is a checking constraint, not a defining one
            if const_name in candidate:
                return (None, None)

            # Evaluate right side with candidate values
            try:
                value = self._eval_expr(self.right, candidate)
                return (const_name, value)
            except (KeyError, ValueError, AttributeError):
                # Can't evaluate yet - might be forward reference
                return (None, None)

        return (None, None)

    def check(self, candidate: dict[str, Any]) -> bool:
        """Check if left == right with concrete values or structural equality.

        For constraints like `bnot_y == ~y`, this performs structural checking
        using IDA's equal_bnot_mop function instead of value-based comparison.
        """

        # Check if this is a structural BNOT constraint: left == ~right
        # This needs special handling because we compare AST structure, not values
        # Use Protocol for hot-reload safety
        if (
            isinstance(self.right, SymbolicExpressionProtocol)
            and self.right.operation == "bnot"
            and self.right.left is not None
        ):
            return self._check_bnot_constraint(candidate)

        # Regular value-based equality check
        try:
            left_val = self._eval_expr(self.left, candidate)
            right_val = self._eval_expr(self.right, candidate)
            return left_val == right_val
        except (KeyError, ValueError, AttributeError):
            # Can't evaluate - constraint FAILS (not skipped!)
            # Previously this returned True which caused incorrect matches
            return False

    def _check_bnot_constraint(self, candidate: dict[str, Any]) -> bool:
        """Check structural BNOT constraint: left == ~right.

        Uses IDA's equal_bnot_mop for proper structural comparison.

        Args:
            candidate: Dictionary mapping variable names to matched AstNodes.

        Returns:
            True if left is structurally ~right, False otherwise.
        """

        # Get the variable names involved
        # left should be a simple variable (e.g., "bnot_y")
        # right should be ~variable (e.g., ~y)
        if not self._is_simple_constant(self.left):
            logger.debug("_check_bnot_constraint: left is not simple constant")
            return False

        left_name = self._get_name(self.left)
        if left_name not in candidate:
            logger.debug(f"_check_bnot_constraint: {left_name} not in candidate keys {list(candidate.keys())}")
            return False

        # Get the operand of the BNOT (e.g., "y" from ~y)
        bnot_operand = self.right.left
        # Use Protocol for hot-reload safety
        if (
            not isinstance(bnot_operand, SymbolicExpressionProtocol)
            or not bnot_operand.is_leaf()
        ):
            logger.debug("_check_bnot_constraint: bnot_operand is not a leaf")
            return False

        operand_name = bnot_operand.name
        if operand_name not in candidate:
            logger.debug(f"_check_bnot_constraint: {operand_name} not in candidate keys {list(candidate.keys())}")
            return False

        # Get the matched AstNodes
        left_node = candidate[left_name]
        right_node = candidate[operand_name]

        # Extract mops from AstNodes (if they have them)
        left_mop = getattr(left_node, "mop", None)
        right_mop = getattr(right_node, "mop", None)

        if left_mop is None or right_mop is None:
            return False

        # Use IDA's structural BNOT comparison
        try:
            from d810.hexrays.hexrays_helpers import equal_bnot_mop

            return equal_bnot_mop(left_mop, right_mop)
        except ImportError:
            # IDA not available - can't check structural constraint
            return False

    def _is_simple_constant(self, expr) -> bool:
        """Check if expression is a simple constant (not compound)."""

        # Use Protocol for hot-reload safety
        if isinstance(expr, SymbolicExpressionProtocol):
            return expr.is_leaf() and expr.name is not None

        return False

    def _get_name(self, expr) -> str:
        """Get the name of a constant."""

        # Use Protocol for hot-reload safety
        if isinstance(expr, SymbolicExpressionProtocol):
            if expr.name:
                return expr.name
            raise ValueError(f"SymbolicExpression has no name: {expr}")

        raise ValueError(f"Cannot get name from {expr}")

    def _eval_expr(self, expr, candidate: dict[str, Any]) -> int:
        """Evaluate expression with concrete candidate values.

        Args:
            expr: SymbolicExpression to evaluate
            candidate: Dictionary with concrete values

        Returns:
            Integer result of evaluation
        """

        # Use Protocol for hot-reload safety
        if isinstance(expr, SymbolicExpressionProtocol):
            return self._eval_symbolic_expr(expr, candidate)

        raise ValueError(
            f"Cannot evaluate {type(expr).__name__}: expected SymbolicExpression"
        )

    def _eval_symbolic_expr(self, expr, candidate: dict[str, Any]) -> int:
        """Evaluate a pure SymbolicExpression with concrete values."""

        # Get width for masking (default 32-bit)
        width = candidate.get("_width", 32)
        mask = (1 << width) - 1

        # Leaf node
        if expr.is_leaf():
            if expr.name in candidate:
                value = candidate[expr.name]
                if hasattr(value, "value"):
                    return value.value
                return value
            if expr.value is not None:
                return expr.value
            raise ValueError(f"Variable/constant {expr.name} not in candidate")

        # Operation node - evaluate recursively
        left_val = self._eval_symbolic_expr(expr.left, candidate) if expr.left else None
        right_val = (
            self._eval_symbolic_expr(expr.right, candidate) if expr.right else None
        )

        match expr.operation:
            case "neg":
                return (-left_val) & mask
            case "bnot":
                return (~left_val) & mask
            case "add":
                return (left_val + right_val) & mask
            case "sub":
                return (left_val - right_val) & mask
            case "mul":
                return (left_val * right_val) & mask
            case "and":
                return left_val & right_val
            case "or":
                return left_val | right_val
            case "xor":
                return left_val ^ right_val
            case "shl":
                return (left_val << right_val) & mask
            case "shr":
                return (left_val >> right_val) & mask
            case "sar":
                # Arithmetic right shift - preserve sign bit
                if left_val & (1 << (width - 1)):
                    # Negative - fill with 1s
                    return (left_val >> right_val) | (~mask >> right_val)
                return left_val >> right_val
            case _:
                raise ValueError(f"Unknown operation: {expr.operation}")


@dataclass
class ComparisonConstraint(ConstraintExpr):
    """Represents a comparison constraint: left op right.

    Supports !=, <, >, <=, >= operations.

    Attributes:
        left: Left-hand side expression
        right: Right-hand side expression
        op_symbol: String representation of operator (for display)
        op_name: Operation name ("ne", "lt", "gt", "le", "ge")
    """

    left: Any  # SymbolicExpression or AstBase
    right: Any  # SymbolicExpression or AstBase
    op_symbol: str  # For display: "!=", "<", ">", "<=", ">="
    op_name: str  # Internal: "ne", "lt", "gt", "le", "ge"

    def eval_and_define(
        self, candidate: dict[str, Any]
    ) -> tuple[str | None, int | None]:
        """Comparisons don't define variables."""
        return (None, None)

    def check(self, candidate: dict[str, Any]) -> bool:
        """Check if comparison holds with concrete values."""
        try:
            eq_constraint = EqualityConstraint(self.left, self.right)
            left_val = eq_constraint._eval_expr(self.left, candidate)
            right_val = eq_constraint._eval_expr(self.right, candidate)

            match self.op_name:
                case "ne":
                    return left_val != right_val
                case "lt":
                    return left_val < right_val
                case "gt":
                    return left_val > right_val
                case "le":
                    return left_val <= right_val
                case "ge":
                    return left_val >= right_val
                case _:
                    raise ValueError(f"Unknown comparison: {self.op_name}")
        except (KeyError, ValueError, AttributeError):
            # Can't evaluate
            return False

    def __repr__(self) -> str:
        return f"({self.left} {self.op_symbol} {self.right})"


@dataclass
class AndConstraint(ConstraintExpr):
    """Logical AND of two constraints.

    Attributes:
        left: Left constraint
        right: Right constraint
    """

    left: ConstraintExpr
    right: ConstraintExpr

    def eval_and_define(
        self, candidate: dict[str, Any]
    ) -> tuple[str | None, int | None]:
        """Try to extract definitions from left first, then right."""
        # Try left constraint
        var_name, value = self.left.eval_and_define(candidate)
        if var_name is not None:
            return (var_name, value)

        # Try right constraint
        return self.right.eval_and_define(candidate)

    def check(self, candidate: dict[str, Any]) -> bool:
        """Both constraints must hold."""
        return self.left.check(candidate) and self.right.check(candidate)

    def __repr__(self) -> str:
        return f"({self.left} && {self.right})"


@dataclass
class OrConstraint(ConstraintExpr):
    """Logical OR of two constraints.

    Attributes:
        left: Left constraint
        right: Right constraint
    """

    left: ConstraintExpr
    right: ConstraintExpr

    def eval_and_define(
        self, candidate: dict[str, Any]
    ) -> tuple[str | None, int | None]:
        """OR doesn't define variables - both branches would need same value."""
        return (None, None)

    def check(self, candidate: dict[str, Any]) -> bool:
        """At least one constraint must hold."""
        return self.left.check(candidate) or self.right.check(candidate)

    def __repr__(self) -> str:
        return f"({self.left} || {self.right})"


@dataclass
class NotConstraint(ConstraintExpr):
    """Logical NOT of a constraint.

    Attributes:
        operand: The constraint to negate
    """

    operand: ConstraintExpr

    def eval_and_define(
        self, candidate: dict[str, Any]
    ) -> tuple[str | None, int | None]:
        """NOT doesn't define variables."""
        return (None, None)

    def check(self, candidate: dict[str, Any]) -> bool:
        """Negate the operand's result."""
        return not self.operand.check(candidate)

    def __repr__(self) -> str:
        return f"!({self.operand})"


def is_constraint_expr(obj: Any) -> bool:
    """Check if an object is a ConstraintExpr instance.

    Uses ConstraintExprProtocol for hot-reload safety - survives class identity
    changes after plugin reload.
    """
    return isinstance(obj, ConstraintExprProtocol)
