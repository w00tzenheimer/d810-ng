"""Z3 backend for pure SymbolicExpression verification.

WARNING: This module must remain IDA-INDEPENDENT. Do not add imports from:
    - ida_hexrays, idaapi, idautils, idc
    - d810.hexrays.expr.ast (AstNode is IDA-coupled)
    - d810.hexrays.*
    - d810.optimizers.*

=============================================================================
ARCHITECTURE: Two Z3 Modules in d810
=============================================================================

There are TWO separate Z3 utility modules in d810, serving different purposes:

1. THIS FILE: d810.backends.mba.z3 (PURE - no IDA)
   ------------------------------------------------
   Purpose: Verify optimization rules using pure symbolic expressions.
   Input:   d810.mba.dsl.SymbolicExpression (platform-independent DSL)
   Use:     Unit tests, CI, TDD rule development, mathematical verification

   Key exports:
   - Z3VerificationVisitor: Converts SymbolicExpression -> Z3 BitVec
   - prove_equivalence(): Prove two SymbolicExpressions are equivalent
   - verify_rule(): Verify a rule's PATTERN equals its REPLACEMENT

   Example:
       from d810.mba.dsl import Var
       from d810.backends.mba.z3 import prove_equivalence

       x, y = Var("x"), Var("y")
       assert prove_equivalence((x | y) - (x & y), x ^ y)  # XOR identity

2. d810.backends.ast.z3 (IDA-SPECIFIC)
   ------------------------------------
   Purpose: Z3 verification of actual IDA microcode during deobfuscation.
   Input:   d810.hexrays.expr.ast.AstNode (wraps IDA mop_t/minsn_t)
   Use:     Runtime verification inside IDA Pro plugin

   Key exports:
   - Z3MopProver: Stateful prover with caching and optional CFG context
   - AstNodeZ3Visitor: Converts AstNode -> Z3 BitVec

=============================================================================
WHY TWO MODULES?
=============================================================================

The separation enables:
1. Unit testing rules WITHOUT IDA Pro license
2. CI/CD pipeline verification (GitHub Actions)
3. TDD workflow: write rule -> verify with Z3 -> integrate with IDA
4. Clear dependency boundaries (mba/ never imports IDA modules)

The d810.mba package is designed to be reusable outside of IDA Pro entirely.
=============================================================================
"""

from __future__ import annotations

import functools
from d810.core import typing
from d810.core.typing import TYPE_CHECKING, Any, Dict

from d810.core import getLogger
from d810.errors import D810Z3Exception
# Top-level, not deferred. The comment this replaces claimed a circular
# import, but SymbolicExpressionProtocol now lives in d810.ir.expr.dsl
# (a leaf module) and imports cleanly at module scope -- verified by
# importing this module standalone.
from d810.mba.dsl import SymbolicExpressionProtocol
from d810.mba.backend_registry import VerificationEngineProvider

logger = getLogger(__name__)

if TYPE_CHECKING:
    from d810.mba.dsl import SymbolicExpression
    from d810.mba.verifier import VerificationOptions

try:
    import z3

    Z3_INSTALLED = True
    # Since version 4.8.2, when Z3 is creating a BitVec, it relies on _str_to_bytes which uses sys.stdout.encoding
    # However, in IDA Pro (7.6sp1) sys.stdout is an object of type IDAPythonStdOut
    # which doesn't have a 'encoding' attribute, thus we set it to something, so that Z3 works
    import sys

    try:
        x = sys.stdout.encoding
    except AttributeError:
        logger.debug("Couldn't find sys.stdout.encoding, setting it to utf-8")
        sys.stdout.encoding = "utf-8"  # type: ignore
except (ImportError, AttributeError, OSError) as e:
    logger.warning("Z3 import failed (%s). Z3 features disabled.", e)
    Z3_INSTALLED = False


@functools.lru_cache(maxsize=1)
def requires_z3_installed(func: typing.Callable[..., typing.Any]):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if not Z3_INSTALLED:
            raise D810Z3Exception("Z3 is not installed")
        return func(*args, **kwargs)

    return wrapper


# =============================================================================
# Z3VerificationEngine - Implements VerificationEngine protocol
# =============================================================================


class Z3VerificationEngine:
    """Z3 implementation of the VerificationEngine protocol.

    This class provides Z3-based verification for MBA rules. It implements
    the VerificationEngine protocol defined in d810.mba.verifier.

    Usage:
        >>> from d810.backends.mba.z3 import Z3VerificationEngine
        >>> from d810.mba.dsl import Var
        >>> engine = Z3VerificationEngine()
        >>> x, y = Var("x"), Var("y")
        >>> is_eq, _ = engine.prove_equivalence((x | y) - (x & y), x ^ y)
        >>> assert is_eq
    """

    def __init__(self):
        """Initialize the Z3 verification engine.

        Raises:
            ImportError: If Z3 is not installed.
        """
        if not Z3_INSTALLED:
            raise ImportError(
                "Z3 is not installed. Install z3-solver to use Z3VerificationEngine."
            )

    def create_variables(
        self, var_names: set[str], options: "VerificationOptions | None" = None
    ) -> Dict[str, z3.BitVecRef]:
        """Create Z3 BitVec variables for the given names.

        Args:
            var_names: Set of variable names to create.
            options: Verification options (uses bit_width).

        Returns:
            Dictionary mapping variable names to Z3 BitVec objects.
        """
        bit_width = options.bit_width if options else 32
        return create_z3_variables(var_names, bit_width)

    def create_z3_variables(
        self, var_names: set[str], bit_width: int = 32
    ) -> dict[str, z3.BitVecRef]:
        """Expose the pure fixed-width variable helper through the registry."""

        return create_z3_variables(var_names, bit_width)

    def constraint_to_z3(
        self,
        constraint: Any,
        z3_vars: dict[str, z3.BitVecRef],
        bit_width: int = 32,
    ) -> z3.BoolRef:
        """Expose declarative constraint lowering through the registry."""

        return constraint_to_z3(constraint, z3_vars, bit_width)

    def verify_rule(self, rule: Any, bit_width: int | None = None) -> bool:
        """Expose rule certification through the registry."""

        return verify_rule(rule, bit_width=bit_width)

    def prove_equivalence(
        self,
        pattern: "SymbolicExpression",
        replacement: "SymbolicExpression",
        variables: Dict[str, Any] | None = None,
        constraints: list[Any] | None = None,
        options: "VerificationOptions | None" = None,
    ) -> tuple[bool, Dict[str, int] | None]:
        """Prove that pattern is semantically equivalent to replacement using Z3.

        Args:
            pattern: The original expression.
            replacement: The simplified expression.
            variables: Optional pre-created Z3 variables (z3_vars).
            constraints: Optional list of constraints.
            options: Verification options (bit_width, timeout, etc.).

        Returns:
            Tuple of (is_equivalent, counterexample).
        """
        bit_width = options.bit_width if options else 32
        timeout_ms = options.timeout_ms if options else 0

        # Delegate to the module-level function
        return prove_equivalence(
            pattern,
            replacement,
            z3_vars=variables,
            constraints=constraints,
            bit_width=bit_width,
            timeout_ms=timeout_ms,
        )


class Z3VerificationProvider(VerificationEngineProvider):
    registrant_name = "z3"

    @classmethod
    def create_engine(cls) -> Z3VerificationEngine:
        return Z3VerificationEngine()


# =============================================================================
# Z3VerificationVisitor - Converts SymbolicExpression to Z3
# =============================================================================


class Z3VerificationVisitor:
    """Visitor that converts SymbolicExpression to Z3 for verification/proving.

    This visitor walks a pure SymbolicExpression tree and builds equivalent
    Z3 symbolic expressions for theorem proving. It has NO dependencies on
    IDA Pro - it works entirely with platform-independent symbolic expressions.

    Example:
        >>> from d810.mba.dsl import Var
        >>> x, y = Var("x"), Var("y")
        >>> pattern = (x | y) - (x & y)  # Pure SymbolicExpression
        >>>
        >>> visitor = Z3VerificationVisitor()
        >>> z3_expr = visitor.visit(pattern)  # Convert to Z3
        >>> # z3_expr is now a z3.BitVecRef representing (x | y) - (x & y)
    """

    def __init__(
        self, bit_width: int = 32, var_map: dict[str, z3.BitVecRef] | None = None
    ):
        """Initialize the Z3 verification visitor.

        Args:
            bit_width: Bit width for Z3 BitVec variables (default 32).
            var_map: Optional pre-created Z3 variables. If provided, the visitor
                    will use these instead of creating new ones. Useful when you
                    need to share variables across multiple expressions.
        """
        if not Z3_INSTALLED:
            raise ImportError(
                "Z3 is not installed. Install z3-solver to use Z3VerificationVisitor."
            )

        self.bit_width = bit_width
        self.var_map: dict[str, z3.BitVecRef] = var_map if var_map is not None else {}

    def visit(self, expr: SymbolicExpression) -> z3.BitVecRef:
        """Visit a SymbolicExpression and return the equivalent Z3 expression.

        Args:
            expr: The SymbolicExpression to visit.

        Returns:
            A Z3 BitVecRef representing the expression.

        Raises:
            ValueError: If the expression is None or invalid.
        """
        if expr is None:
            raise ValueError("Cannot visit None expression")

        if expr.is_leaf():
            return self._visit_leaf(expr)

        return self._visit_operation(expr)

    def _visit_leaf(self, expr: SymbolicExpression) -> z3.BitVecRef:
        """Visit a leaf node (variable or constant).

        Args:
            expr: The leaf SymbolicExpression.

        Returns:
            Z3 BitVec for variables, Z3 BitVecVal for concrete constants.
        """
        if expr.is_constant():
            # Concrete constant like Const("ONE", 1)
            return z3.BitVecVal(expr.value, self.bit_width)

        # Variable or pattern-matching constant like Var("x") or Const("c_1")
        if expr.name not in self.var_map:
            self.var_map[expr.name] = z3.BitVec(expr.name, self.bit_width)

        return self.var_map[expr.name]

    def _visit_operation(self, expr: SymbolicExpression) -> z3.BitVecRef | z3.BoolRef:
        """Visit an operation node (binary/unary operation).

        Args:
            expr: The operation SymbolicExpression.

        Returns:
            Z3 expression representing the operation.

        Raises:
            ValueError: If the operation is unsupported.
        """
        # Handle bool_to_int specially - it has a constraint instead of left/right
        if expr.operation == "bool_to_int":
            return self._visit_bool_to_int(expr)

        # Recursively visit children
        left = self.visit(expr.left) if expr.left else None
        right = self.visit(expr.right) if expr.right else None

        # Map operation strings to Z3 operations
        match expr.operation:
            # Unary operations
            case "neg":
                return -left

            case "lnot":
                # Logical NOT: returns 1 if operand is 0, else 0
                return z3.If(
                    left == z3.BitVecVal(0, self.bit_width),
                    z3.BitVecVal(1, self.bit_width),
                    z3.BitVecVal(0, self.bit_width),
                )

            case "bnot":
                return ~left

            # Binary arithmetic operations
            case "add":
                return left + right

            case "sub":
                return left - right

            case "mul":
                return left * right

            case "udiv":
                return z3.UDiv(left, right)

            case "sdiv":
                return left / right

            case "umod":
                return z3.URem(left, right)

            case "smod":
                return left % right

            # Binary bitwise operations
            case "or":
                return left | right

            case "and":
                return left & right

            case "xor":
                return left ^ right

            # Shift operations
            case "shl":
                return left << right

            case "shr":
                return z3.LShR(left, right)  # Logical shift right

            case "sar":
                return left >> right  # Arithmetic shift right

            # Part extraction operations
            case "low":
                target_width = expr.value or self.bit_width
                high_bit = min(int(target_width) - 1, left.size() - 1)
                extracted = typing.cast(z3.BitVecRef, z3.Extract(high_bit, 0, left))
                if extracted.size() < self.bit_width:
                    return z3.ZeroExt(self.bit_width - extracted.size(), extracted)
                return extracted

            case "high":
                target_width = expr.value or self.bit_width
                source_width = left.size()
                low_bit = max(source_width - int(target_width), 0)
                high_bit = source_width - 1
                extracted = typing.cast(
                    z3.BitVecRef, z3.Extract(high_bit, low_bit, left)
                )
                if extracted.size() < self.bit_width:
                    return z3.ZeroExt(self.bit_width - extracted.size(), extracted)
                return extracted

            # Extension operations
            case "zext":
                # Zero-extend to target width
                # expr.value contains target_width, left contains the expression
                target_width = expr.value
                if target_width > self.bit_width:
                    # Extending beyond current bit_width - add zeros at the top
                    extend_bits = target_width - self.bit_width
                    return z3.ZeroExt(extend_bits, left)
                elif target_width == self.bit_width:
                    # Already at target width, no extension needed
                    return left
                else:
                    # Target width smaller than current - this shouldn't happen in practice
                    # but handle it by extracting the low bits
                    return z3.Extract(target_width - 1, 0, left)

            # Comparison operations (return 0 or 1)
            case "setnz":
                return z3.If(
                    left != z3.BitVecVal(0, self.bit_width),
                    z3.BitVecVal(1, self.bit_width),
                    z3.BitVecVal(0, self.bit_width),
                )

            case "setz":
                return z3.If(
                    left == z3.BitVecVal(0, self.bit_width),
                    z3.BitVecVal(1, self.bit_width),
                    z3.BitVecVal(0, self.bit_width),
                )

            case "setae":
                return z3.If(
                    z3.UGE(left, right),
                    z3.BitVecVal(1, self.bit_width),
                    z3.BitVecVal(0, self.bit_width),
                )

            case "setb":
                return z3.If(
                    z3.ULT(left, right),
                    z3.BitVecVal(1, self.bit_width),
                    z3.BitVecVal(0, self.bit_width),
                )

            case "seta":
                return z3.If(
                    z3.UGT(left, right),
                    z3.BitVecVal(1, self.bit_width),
                    z3.BitVecVal(0, self.bit_width),
                )

            case "setbe":
                return z3.If(
                    z3.ULE(left, right),
                    z3.BitVecVal(1, self.bit_width),
                    z3.BitVecVal(0, self.bit_width),
                )

            case "setg":
                return z3.If(
                    left > right,
                    z3.BitVecVal(1, self.bit_width),
                    z3.BitVecVal(0, self.bit_width),
                )

            case "setge":
                return z3.If(
                    left >= right,
                    z3.BitVecVal(1, self.bit_width),
                    z3.BitVecVal(0, self.bit_width),
                )

            case "setl":
                return z3.If(
                    left < right,
                    z3.BitVecVal(1, self.bit_width),
                    z3.BitVecVal(0, self.bit_width),
                )

            case "setle":
                return z3.If(
                    left <= right,
                    z3.BitVecVal(1, self.bit_width),
                    z3.BitVecVal(0, self.bit_width),
                )

            case _:
                raise ValueError(
                    f"Unsupported operation in Z3VerificationVisitor: {expr.operation}. "
                    f"Add support for this operation in backends/z3.py"
                )

    def _visit_bool_to_int(self, expr: SymbolicExpression) -> z3.BitVecRef:
        """Visit a bool_to_int operation: converts ConstraintExpr to 0 or 1.

        This is the bridge between boolean formulas (ConstraintExpr) and arithmetic
        terms (SymbolicExpression). It implements the C-like behavior where comparison
        results can be used as integers.

        Args:
            expr: SymbolicExpression with operation="bool_to_int" and constraint set.

        Returns:
            Z3 If-expression: If(constraint, 1, 0)

        Example:
            constraint = x != 0  # ConstraintExpr
            expr = constraint.to_int()  # SymbolicExpression(operation="bool_to_int")
            z3_expr = visitor._visit_bool_to_int(expr)  # If(x != 0, 1, 0)
        """
        if expr.constraint is None:
            raise ValueError("bool_to_int operation requires a constraint")

        # Convert the ConstraintExpr to a Z3 boolean
        bool_expr = self._constraint_to_z3(expr.constraint)

        # Wrap in If: returns 1 if true, 0 if false
        return z3.If(
            bool_expr,
            z3.BitVecVal(1, self.bit_width),
            z3.BitVecVal(0, self.bit_width),
        )

    def _constraint_to_z3(self, constraint) -> z3.BoolRef:
        """Convert a ConstraintExpr to a Z3 boolean expression.

        Args:
            constraint: ConstraintExpr (EqualityConstraint, ComparisonConstraint, etc.)

        Returns:
            Z3 BoolRef representing the constraint

        Raises:
            ValueError: If constraint type is unsupported
        """
        # Use Protocols for hot-reload-safe isinstance() checks
        from d810.mba.constraints import (
            AndConstraintProtocol,
            ComparisonConstraintProtocol,
            EqualityConstraintProtocol,
            NotConstraintProtocol,
            OrConstraintProtocol,
        )

        # Check ComparisonConstraintProtocol FIRST - it's more specific
        # (has op_name) than EqualityConstraintProtocol. Due to structural
        # typing, ComparisonConstraint matches both protocols since it has
        # left/right attributes.
        if isinstance(constraint, ComparisonConstraintProtocol):
            left_z3 = self._expr_to_z3_helper(constraint.left)
            right_z3 = self._expr_to_z3_helper(constraint.right)

            match constraint.op_name:
                case "ne":
                    return left_z3 != right_z3
                case "lt":
                    return z3.ULT(left_z3, right_z3)
                case "le":
                    return z3.ULE(left_z3, right_z3)
                case "gt":
                    return z3.UGT(left_z3, right_z3)
                case "ge":
                    return z3.UGE(left_z3, right_z3)
                case _:
                    raise ValueError(
                        f"Unsupported comparison operator: {constraint.op_name}"
                    )

        if isinstance(constraint, EqualityConstraintProtocol):
            left_z3 = self._expr_to_z3_helper(constraint.left)
            right_z3 = self._expr_to_z3_helper(constraint.right)
            return left_z3 == right_z3

        if isinstance(constraint, AndConstraintProtocol):
            left_bool = self._constraint_to_z3(constraint.left)
            right_bool = self._constraint_to_z3(constraint.right)
            return z3.And(left_bool, right_bool)

        if isinstance(constraint, OrConstraintProtocol):
            left_bool = self._constraint_to_z3(constraint.left)
            right_bool = self._constraint_to_z3(constraint.right)
            return z3.Or(left_bool, right_bool)

        if isinstance(constraint, NotConstraintProtocol):
            inner_bool = self._constraint_to_z3(constraint.operand)
            return z3.Not(inner_bool)

        raise ValueError(f"Unsupported constraint type: {type(constraint)}")

    def _expr_to_z3_helper(self, expr):
        """Helper to convert expression (SymbolicExpression or value) to Z3.

        Args:
            expr: Can be SymbolicExpression, int, or other value

        Returns:
            Z3 BitVecRef
        """
    
        # Use Protocol for hot-reload safety
        if isinstance(expr, SymbolicExpressionProtocol):
            return self.visit(expr)

        # Handle raw integer values (from constraint evaluation)
        if isinstance(expr, int):
            return z3.BitVecVal(expr, self.bit_width)

        # Fallback - try to visit as SymbolicExpression
        return self.visit(expr)

    def get_variables(self) -> dict[str, z3.BitVecRef]:
        """Get all Z3 variables created during visitation.

        Returns:
            Dictionary mapping variable names to Z3 BitVecRef objects.
            Useful for adding constraints to the solver.
        """
        return self.var_map.copy()


# =============================================================================
# prove_equivalence - Prove two SymbolicExpressions are equivalent
# =============================================================================


def prove_equivalence(
    pattern: SymbolicExpression,
    replacement: SymbolicExpression,
    z3_vars: dict[str, z3.BitVecRef] | None = None,
    constraints: list[Any] | None = None,
    bit_width: int = 32,
    timeout_ms: int = 0,
) -> tuple[bool, dict[str, int] | None]:
    """Prove that two SymbolicExpressions are semantically equivalent using Z3.

    This function uses the Z3VerificationVisitor to convert both expressions
    to Z3, then attempts to prove they are equivalent for all possible variable
    values (subject to any constraints).

    Args:
        pattern: The first SymbolicExpression (typically the pattern to match).
        replacement: The second SymbolicExpression (typically the replacement).
        z3_vars: Optional pre-created Z3 variables. If provided, these will be
                used for pattern constants and variables. If None, variables
                will be created automatically.
        constraints: Optional list of Z3 constraint expressions (BoolRef objects).
                    These constraints must hold for the equivalence to be valid.
        bit_width: Bit width for Z3 variables (default 32).
        timeout_ms: Per-solver timeout in milliseconds. This must remain
                    solver-local; do not mutate process-global Z3 state inside IDA.

    Returns:
        A tuple of (is_equivalent, counterexample):
        - is_equivalent: True if proven equivalent, False otherwise.
        - counterexample: If not equivalent, a dict mapping variable names to
                         values that demonstrate the difference. None if equivalent.

    Example:
        >>> from d810.mba.dsl import Var
        >>> x, y = Var("x"), Var("y")
        >>> pattern = (x | y) - (x & y)
        >>> replacement = x ^ y
        >>> is_equiv, _ = prove_equivalence(pattern, replacement)
        >>> assert is_equiv  # These are mathematically equivalent
    """
    if not Z3_INSTALLED:
        raise ImportError(
            "Z3 is not installed. Install z3-solver to prove equivalence."
        )

    # Create visitor with optional pre-created variables
    visitor = Z3VerificationVisitor(bit_width=bit_width, var_map=z3_vars)

    try:
        pattern_z3 = visitor.visit(pattern)
        replacement_z3 = visitor.visit(replacement)
    except Exception:
        # Conversion failed - expressions are invalid or contain unsupported operations
        return False, None

    # Create solver and add constraints. Timeout is solver-local because IDA can
    # host multiple Z3-using plugins in one process.
    solver = z3.Solver()
    if timeout_ms > 0:
        try:
            solver.set(timeout=timeout_ms)
        except Exception as e:
            logger.warning("Failed to set Z3 solver timeout: %s", e)

    if constraints:
        for constraint in constraints:
            solver.add(constraint)

    # Prove equivalence by checking if inequality is unsatisfiable
    # If pattern != replacement has no solution, they are equivalent
    solver.add(pattern_z3 != replacement_z3)
    result = solver.check()

    if result == z3.unsat:
        # No counterexample exists - patterns are equivalent!
        return True, None

    if result == z3.sat:
        # Found a counterexample - patterns are NOT equivalent
        model = solver.model()
        counterexample = {}

        for name, z3_var in visitor.get_variables().items():
            value = model.eval(z3_var, model_completion=True)
            if hasattr(value, "as_long"):
                counterexample[name] = value.as_long()
            else:
                counterexample[name] = str(value)

        return False, counterexample

    # Z3 returned unknown - cannot prove either way
    return False, None


# =============================================================================
# verify_rule - Verify a rule's pattern equals its replacement
# =============================================================================


def _symbolic_expression_signature(expression: Any) -> tuple[Any, ...]:
    """Return the exact pure DSL tree shape used by a certificate prover."""

    operation = getattr(expression, "operation", None)
    if operation is None:
        return (
            "leaf",
            getattr(expression, "name", None),
            getattr(expression, "value", None),
            bool(getattr(expression, "is_pattern_constant", False)),
        )
    return (
        "node",
        str(operation),
        _symbolic_expression_signature(getattr(expression, "left", None)),
        (
            _symbolic_expression_signature(getattr(expression, "right", None))
            if getattr(expression, "right", None) is not None
            else None
        ),
    )


def _complement_mask_hodur_expected_rule():
    """Build the one audited complement-mask identity without IDA imports."""

    from d810.mba.dsl import Const, Var

    mask, value, complement_mask = Var("x_0"), Var("x_1"), Var("bnot_x_0")
    two, three, four = Const("2", 2), Const("3", 3), Const("4", 4)
    pattern = (
        (
            four * ~(mask & value)
            + (two * (mask & value) - three * (complement_mask & value))
        )
        - two * ~(complement_mask & value)
        - two * ~(mask | value)
        - three * ~(complement_mask | value)
    )
    return pattern, value - mask, complement_mask == ~mask


def _is_unsat(formula: Any) -> bool:
    """Prove one small, independently-checkable bit-vector obligation."""

    solver = z3.Solver()
    solver.add(formula)
    return solver.check() == z3.unsat


def _verify_complement_mask_hodur_v1(rule: Any, bit_width: int) -> bool:
    """Certify the complement-mask identity through audited small lemmas.

    A monolithic bit-blast of this wide MBA expression is impractical at 32/64
    bits.  This certificate first requires the exact declarative tree and
    complement constraint, then uses Z3 to prove the four Boolean/ring lemmas
    that reduce it to linear modular arithmetic.  The remaining arithmetic
    obligation is also discharged by Z3.  Any altered pattern, replacement or
    constraint therefore fails closed before catalogue admission.
    """

    if type(bit_width) is not int or bit_width <= 0:
        return False
    try:
        expected_pattern, expected_replacement, expected_constraint = (
            _complement_mask_hodur_expected_rule()
        )
        if _symbolic_expression_signature(rule.pattern) != _symbolic_expression_signature(
            expected_pattern
        ):
            return False
        if _symbolic_expression_signature(
            rule.replacement
        ) != _symbolic_expression_signature(expected_replacement):
            return False
        constraints = tuple(getattr(rule, "CONSTRAINTS", ()) or ())
        if len(constraints) != 1:
            return False
        constraint = constraints[0]
        if (
            _symbolic_expression_signature(getattr(constraint, "left", None))
            != _symbolic_expression_signature(getattr(expected_constraint, "left", None))
            or _symbolic_expression_signature(getattr(constraint, "right", None))
            != _symbolic_expression_signature(getattr(expected_constraint, "right", None))
            or getattr(constraint, "op_name", None) != getattr(expected_constraint, "op_name", None)
        ):
            return False

        mask = z3.BitVec("certificate_mask", bit_width)
        value = z3.BitVec("certificate_value", bit_width)
        complement = ~mask
        masked = value & mask
        complement_masked = value & complement
        all_ones = z3.BitVecVal((1 << bit_width) - 1, bit_width)

        # The Boolean identities that expose the original expression's ring
        # structure. Each one is discharged separately, rather than trusting a
        # host-side rewrite.
        if not _is_unsat(masked + complement_masked != value):
            return False
        if not _is_unsat((value | mask) != mask + complement_masked):
            return False
        if not _is_unsat((value | complement) != complement + masked):
            return False
        if not _is_unsat(mask + complement != all_ones):
            return False

        # Substitute the four proved identities and ``~t == -t - 1`` into the
        # declared residual. What remains is linear modular arithmetic.
        reduced = (
            2 * masked
            - 3 * complement_masked
            + 4 * (-masked - 1)
            - 2 * (-complement_masked - 1)
            - 2 * (-(mask + complement_masked) - 1)
            - 3 * (-(complement + masked) - 1)
        )
        return _is_unsat(reduced != value - mask)
    except Exception:
        return False


def _eid_key_schedule_3_expected_rule():
    """Build the audited coefficient-six Eid identity."""

    from d810.mba.dsl import Const, Var

    x, y = Var("x_0"), Var("x_1")
    six = Const("6", 6)
    pattern = (
        six * (~(x | y))
        + six * (y & ~x)
        + (x ^ y)
        + six * (x & y)
        - six * ((~x) | y)
    )
    return pattern, x ^ y


def _verify_eid_key_schedule_3_v1(rule: Any, bit_width: int) -> bool:
    """Certify the coefficient-six identity through small Z3 obligations."""

    if type(bit_width) is not int or bit_width <= 0:
        return False
    try:
        expected_pattern, expected_replacement = (
            _eid_key_schedule_3_expected_rule()
        )
        if _symbolic_expression_signature(rule.pattern) != _symbolic_expression_signature(
            expected_pattern
        ):
            return False
        if _symbolic_expression_signature(
            rule.replacement
        ) != _symbolic_expression_signature(expected_replacement):
            return False
        if tuple(getattr(rule, "CONSTRAINTS", ()) or ()):
            return False

        x = z3.BitVec("certificate_x", bit_width)
        y = z3.BitVec("certificate_y", bit_width)
        not_x = ~x
        neither = ~(x | y)
        only_y = y & not_x
        both = x & y
        union = not_x | y

        # The masks are disjoint partitions, so their modular arithmetic sum
        # is the same as their bitwise union.  Prove the two partitions and the
        # ring distribution independently to avoid one impractical bit-blast.
        if not _is_unsat(neither + only_y != not_x):
            return False
        if not _is_unsat(not_x + both != union):
            return False
        if not _is_unsat(
            6 * neither + 6 * only_y + 6 * both
            != 6 * (neither + only_y + both)
        ):
            return False

        reduced = 6 * union + (x ^ y) - 6 * union
        return _is_unsat(reduced != (x ^ y))
    except Exception:
        return False


def verify_rule(
    rule,
    bit_width: int | None = None,
) -> bool:
    """Verify that a rule's pattern is equivalent to its replacement using Z3.

    This function takes a VerifiableRule (or any object with pattern/replacement
    SymbolicExpression attributes) and proves mathematical equivalence using Z3.

    This is the ONLY entry point for rule verification - rules should NOT contain
    Z3-specific code themselves. All Z3 logic is encapsulated here.

    Args:
        rule: A rule object with:
            - pattern: SymbolicExpression (the pattern to match)
            - replacement: SymbolicExpression (the replacement)
            - CONSTRAINTS: Optional list of constraint predicates
            - SKIP_VERIFICATION: Optional bool to skip verification
            - KNOWN_INCORRECT: Optional bool for known-incorrect rules
            - BIT_WIDTH: Optional int for rule-specific bit width (default 32)
            - name: Optional str for error messages
        bit_width: Bit width for Z3 BitVec variables. If None, uses rule.BIT_WIDTH
                   or defaults to 32.

    Returns:
        True if the rule is proven correct.

    Raises:
        AssertionError: If verification fails with detailed error message.
        ImportError: If Z3 is not installed.

    Example:
        >>> from d810.backends.mba.z3 import verify_rule
        >>> from d810.mba.dsl import Var
        >>> x, y = Var("x"), Var("y")
        >>>
        >>> class MyRule:
        ...     pattern = (x | y) - (x & y)
        ...     replacement = x ^ y
        ...     name = "XorFromOrAnd"
        ...
        >>> assert verify_rule(MyRule())  # Proves equivalence
    """
    if not Z3_INSTALLED:
        raise ImportError(
            f"Cannot verify rule {getattr(rule, 'name', 'unknown')}: Z3 is not installed. "
            "Install z3-solver to enable rule verification."
        )

    # Check if rule should skip verification
    if getattr(rule, "SKIP_VERIFICATION", False):
        logger.debug(
            f"Skipping verification for {getattr(rule, 'name', 'unknown')}: SKIP_VERIFICATION=True"
        )
        return True

    # Resolve bit_width: parameter > rule.BIT_WIDTH > default 32
    if bit_width is None:
        bit_width = getattr(rule, "BIT_WIDTH", 32)

    z3_certificate_prover = getattr(rule, "Z3_CERTIFICATE_PROVER", None)
    if z3_certificate_prover is not None:
        if z3_certificate_prover != "eid-key-schedule-3-v1":
            return False
        return _verify_eid_key_schedule_3_v1(rule, bit_width)

    certificate_prover = getattr(rule, "EGGLOG_CERTIFICATE_PROVER", None)
    if certificate_prover is not None:
        if certificate_prover != "complement-mask-hodur-v1":
            return False
        return _verify_complement_mask_hodur_v1(rule, bit_width)
    logger.debug(
        f"Verifying {getattr(rule, 'name', 'unknown')} with bit_width={bit_width}"
    )


    pattern = rule.pattern
    replacement = rule.replacement
    rule_name = getattr(rule, "name", rule.__class__.__name__)

    # Validate inputs
    if pattern is None:
        logger.debug(f"Skipping verification for {rule_name}: pattern is None")
        return True

    # Use Protocol for hot-reload safety
    if not isinstance(replacement, SymbolicExpressionProtocol):
        logger.debug(
            f"Skipping verification for {rule_name}: replacement is {type(replacement).__name__}, not SymbolicExpression"
        )
        return True

    # Collect all variable/constant names from both expressions
    var_names = set()
    _collect_symbolic_names(pattern, var_names)
    _collect_symbolic_names(replacement, var_names)
    for constraint in getattr(rule, "CONSTRAINTS", ()) or ():
        _collect_constraint_names(constraint, var_names)

    # Create Z3 variables for all symbolic names
    z3_vars = {name: z3.BitVec(name, bit_width) for name in sorted(var_names)}

    # Get rule-specific constraints and convert to Z3
    constraints = _extract_constraints(rule, z3_vars, bit_width=bit_width)

    # Create visitor and convert expressions to Z3
    visitor = Z3VerificationVisitor(bit_width=bit_width, var_map=z3_vars)

    try:
        pattern_z3 = visitor.visit(pattern)
        replacement_z3 = visitor.visit(replacement)
    except Exception as e:
        logger.warning(f"Failed to convert {rule_name} to Z3: {e}")
        return False

    # Create solver and add constraints
    solver = z3.Solver()
    for constraint in constraints:
        solver.add(constraint)

    # Prove equivalence: check if pattern != replacement is unsatisfiable
    solver.add(pattern_z3 != replacement_z3)
    result = solver.check()

    if result == z3.unsat:
        # Patterns are equivalent
        logger.debug(f"Rule {rule_name} verified successfully")
        return True

    # Verification failed - build detailed error message
    counterexample = {}
    if result == z3.sat:
        model = solver.model()
        for name, z3_var in z3_vars.items():
            value = model.eval(z3_var, model_completion=True)
            if hasattr(value, "as_long"):
                counterexample[name] = value.as_long()

    msg = (
        f"\n--- VERIFICATION FAILED ---\n"
        f"Rule:        {rule_name}\n"
        f"Description: {getattr(rule, 'description', 'No description')}\n"
        f"Identity:    {pattern} => {replacement}\n"
    )
    if counterexample:
        msg += f"Counterexample: {counterexample}\n"
    if constraints:
        msg += f"Constraints were: {constraints}\n"
    msg += (
        "This rule does NOT preserve semantics and should not be used.\n"
        "Please fix the pattern, replacement, or constraints."
    )
    raise AssertionError(msg)


# =============================================================================
# Z3 Variable Creation
# =============================================================================


def create_z3_variables(
    var_names: set[str], bit_width: int = 32
) -> dict[str, z3.BitVecRef]:
    """Create Z3 BitVec variables for a set of variable names.

    This helper keeps Z3-specific code in the backend, allowing other modules
    to remain backend-agnostic.

    Args:
        var_names: Set of variable names to create Z3 variables for.
        bit_width: Bit width for Z3 BitVec variables (default 32).

    Returns:
        Dictionary mapping variable names to Z3 BitVec objects.

    Example:
        >>> var_names = {"x", "y", "c1"}
        >>> z3_vars = create_z3_variables(var_names, bit_width=32)
        >>> # z3_vars = {"c1": BitVec("c1", 32), "x": BitVec("x", 32), "y": BitVec("y", 32)}
    """
    return {name: z3.BitVec(name, bit_width) for name in sorted(var_names)}


# =============================================================================
# Constraint to Z3 Conversion
# =============================================================================


def constraint_to_z3(
    constraint,
    z3_vars: dict[str, z3.BitVecRef],
    bit_width: int = 32,
) -> z3.BoolRef:
    """Convert a ConstraintExpr to a Z3 boolean expression.

    This is the Z3-backend-specific visitor for constraint expressions.
    The constraint classes themselves are backend-agnostic data structures.

    Args:
        constraint: A ConstraintExpr instance (EqualityConstraint, ComparisonConstraint, etc.)
        z3_vars: Dictionary mapping variable names to Z3 BitVec objects.

    Returns:
        Z3 boolean expression representing the constraint.

    Example:
        >>> from d810.mba.dsl import Var, Const
        >>> from d810.mba.constraints import EqualityConstraint
        >>> x = Var("x")
        >>> c = Const("c")
        >>> constraint = EqualityConstraint(c, x + Const("1", 1))
        >>> z3_vars = {"x": z3.BitVec("x", 32), "c": z3.BitVec("c", 32)}
        >>> z3_bool = constraint_to_z3(constraint, z3_vars)
    """
    # Use Protocols for hot-reload-safe isinstance() checks
    from d810.mba.constraints import (
        EqualityConstraintProtocol,
        ComparisonConstraintProtocol,
        AndConstraintProtocol,
        OrConstraintProtocol,
        NotConstraintProtocol,
    )

    # Check ComparisonConstraintProtocol FIRST - it's more specific
    # (has op_name) than EqualityConstraintProtocol. Due to structural
    # typing, ComparisonConstraint matches both protocols since it has
    # left/right attributes.
    if isinstance(constraint, ComparisonConstraintProtocol):
        left_z3 = _constraint_expr_to_z3(constraint.left, z3_vars, bit_width)
        right_z3 = _constraint_expr_to_z3(constraint.right, z3_vars, bit_width)

        match constraint.op_name:
            case "ne":
                return left_z3 != right_z3
            case "lt":
                return z3.ULT(left_z3, right_z3)
            case "gt":
                return z3.UGT(left_z3, right_z3)
            case "le":
                return z3.ULE(left_z3, right_z3)
            case "ge":
                return z3.UGE(left_z3, right_z3)
            case _:
                raise ValueError(f"Unknown comparison: {constraint.op_name}")

    elif isinstance(constraint, EqualityConstraintProtocol):
        left_z3 = _constraint_expr_to_z3(constraint.left, z3_vars, bit_width)
        right_z3 = _constraint_expr_to_z3(constraint.right, z3_vars, bit_width)
        return left_z3 == right_z3

    elif isinstance(constraint, AndConstraintProtocol):
        left_z3 = constraint_to_z3(constraint.left, z3_vars, bit_width)
        right_z3 = constraint_to_z3(constraint.right, z3_vars, bit_width)
        return z3.And(left_z3, right_z3)

    elif isinstance(constraint, OrConstraintProtocol):
        left_z3 = constraint_to_z3(constraint.left, z3_vars, bit_width)
        right_z3 = constraint_to_z3(constraint.right, z3_vars, bit_width)
        return z3.Or(left_z3, right_z3)

    elif isinstance(constraint, NotConstraintProtocol):
        operand_z3 = constraint_to_z3(constraint.operand, z3_vars, bit_width)
        return z3.Not(operand_z3)

    else:
        raise TypeError(f"Unknown constraint type: {type(constraint)}")


def _constraint_expr_to_z3(
    expr, z3_vars: dict[str, z3.BitVecRef], bit_width: int
) -> z3.BitVecRef:
    """Convert a SymbolicExpression within a constraint to Z3.

    Args:
        expr: SymbolicExpression to convert
        z3_vars: Dictionary mapping variable names to Z3 BitVec objects

    Returns:
        Z3 BitVecRef representing the expression

    Raises:
        ValueError: If expr is not a SymbolicExpression
    """

    # Use Protocol for hot-reload safety
    if isinstance(expr, SymbolicExpressionProtocol):
        visitor = Z3VerificationVisitor(bit_width=bit_width, var_map=z3_vars)
        return visitor.visit(expr)

    raise ValueError(
        f"Cannot convert {type(expr).__name__} to Z3: expected SymbolicExpression"
    )


def _collect_constraint_names(constraint, names: set) -> None:
    """Recursively collect variable/constant names from a ConstraintExpr.

    Args:
        constraint: A ConstraintExpr to traverse (EqualityConstraint,
                   ComparisonConstraint, AndConstraint, etc.)
        names: Set to add discovered names to.
    """
    from d810.mba.constraints import (
        AndConstraintProtocol,
        ComparisonConstraintProtocol,
        EqualityConstraintProtocol,
        NotConstraintProtocol,
        OrConstraintProtocol,
    )

    if constraint is None:
        return

    # Binary constraints with left/right expressions
    if isinstance(
        constraint, (EqualityConstraintProtocol, ComparisonConstraintProtocol)
    ):
        _collect_symbolic_names(constraint.left, names)
        _collect_symbolic_names(constraint.right, names)

    # Logical AND/OR with left/right constraints
    elif isinstance(constraint, (AndConstraintProtocol, OrConstraintProtocol)):
        _collect_constraint_names(constraint.left, names)
        _collect_constraint_names(constraint.right, names)

    # Logical NOT with single operand
    elif isinstance(constraint, NotConstraintProtocol):
        _collect_constraint_names(constraint.operand, names)


def _collect_symbolic_names(expr, names: set) -> None:
    """Recursively collect variable and constant names from a SymbolicExpression.

    Args:
        expr: A SymbolicExpression to traverse.
        names: Set to add discovered names to.
    """

    # Use Protocol for hot-reload safety
    if expr is None or not isinstance(expr, SymbolicExpressionProtocol):
        return

    if expr.is_leaf():
        if expr.name and expr.value is None:
            # Variable or pattern-matching constant (no concrete value)
            names.add(expr.name)
    else:
        _collect_symbolic_names(expr.left, names)
        _collect_symbolic_names(expr.right, names)

    # Handle bool_to_int expressions that store variables in expr.constraint
    if hasattr(expr, "constraint") and expr.constraint is not None:
        _collect_constraint_names(expr.constraint, names)


def _extract_constraints(rule, z3_vars: dict, bit_width: int = 32) -> list:
    """Extract and convert rule constraints to Z3 expressions.

    Args:
        rule: The rule object with optional CONSTRAINTS attribute or get_constraints method.
        z3_vars: Dictionary mapping variable names to Z3 BitVec objects.

    Returns:
        List of Z3 constraint expressions.
    """
    z3_constraints = []

    # First, check for get_constraints method (explicit Z3 constraint generation)
    if hasattr(rule, "get_constraints") and callable(rule.get_constraints):
        try:
            custom_constraints = rule.get_constraints(z3_vars)
            if custom_constraints:
                if isinstance(custom_constraints, list):
                    z3_constraints.extend(custom_constraints)
                else:
                    z3_constraints.append(custom_constraints)
                logger.debug(
                    f"Got {len(z3_constraints)} constraints from get_constraints() for {getattr(rule, 'name', 'unknown')}"
                )
        except Exception as e:
            logger.warning(
                f"Failed to call get_constraints() for {getattr(rule, 'name', 'unknown')}: {e}"
            )

    # Then, check CONSTRAINTS attribute
    constraints_attr = getattr(rule, "CONSTRAINTS", None)
    if not constraints_attr:
        return z3_constraints

    for constraint in constraints_attr:
        # Check if this is a ConstraintExpr (declarative style)
        try:
            from d810.mba.constraints import is_constraint_expr

            if is_constraint_expr(constraint):
                z3_constraint = constraint_to_z3(
                    constraint, z3_vars, bit_width=bit_width
                )
                z3_constraints.append(z3_constraint)
                continue
        except Exception:
            pass

        # Check if constraint has _to_z3 method (constraint helpers)
        if callable(constraint) and hasattr(constraint, "_to_z3"):
            try:
                z3_constraint = constraint._to_z3(z3_vars)
                if z3_constraint is not None:
                    z3_constraints.append(z3_constraint)
                    continue
            except Exception:
                pass

        # Legacy callable constraints - try to auto-detect pattern
        if (
            callable(constraint)
            and hasattr(constraint, "__closure__")
            and constraint.__closure__
        ):
            closure_vars = []
            for cell in constraint.__closure__:
                content = cell.cell_contents
                if isinstance(content, str):
                    closure_vars.append(content)

            if len(closure_vars) >= 2:
                var1, var2 = closure_vars[0], closure_vars[1]
                if var1 in z3_vars and var2 in z3_vars:
                    # Assume is_bnot pattern (most common)
                    z3_constraints.append(z3_vars[var1] == ~z3_vars[var2])
                    continue

        logger.debug(
            f"Could not convert constraint to Z3 for rule {getattr(rule, 'name', 'unknown')}"
        )

    return z3_constraints


def d810_backend_probe() -> str | None:
    """Backend plugin protocol hook: ``None`` if usable, else why not.

    This module imports cleanly whether or not z3 is installed -- it only
    sets Z3_INSTALLED -- so import success is not evidence the backend works.
    Z3_INSTALLED stays authoritative; this just exposes it uniformly.
    """
    return None if Z3_INSTALLED else ("z3 not installed or failed to import (pip install z3-solver)")
