"""Pure verification framework for MBA simplification rules.

This module provides IDA-independent verification of optimization rules.
It defines:
1. VerificationEngine protocol - interface for verification backends
2. MBARule classes - rule definitions that use engines for verification

The module is BACKEND-AGNOSTIC. Backend implementations (Z3, etc.) are in d810.mba.backends.

This is the extraction of pure verification logic from d810.optimizers.rules,
designed to work without IDA Pro dependencies.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any, Dict, List, Protocol, runtime_checkable

from d810.mba.dsl import SymbolicExpression, SymbolicExpressionProtocol

# =============================================================================
# Verification Options
# =============================================================================


@dataclass
class VerificationOptions:
    """Configuration options for verification engines.

    This dataclass provides a flexible way to pass options to verification
    engines. Each engine may use different subsets of these options.

    Attributes:
        bit_width: Bit width for bitvector variables (default 32).
        timeout_ms: Solver timeout in milliseconds (0 = no timeout).
        verbose: Enable verbose output from the solver.
        extra: Additional engine-specific options.

    Example:
        >>> opts = VerificationOptions(bit_width=64, timeout_ms=5000)
        >>> rule.verify(options=opts)
    """

    bit_width: int = 32
    timeout_ms: int = 0
    verbose: bool = False
    extra: Dict[str, Any] = field(default_factory=dict)


# Default options instance
DEFAULT_OPTIONS = VerificationOptions()


# =============================================================================
# Verification Engine Protocol
# =============================================================================


@runtime_checkable
class VerificationEngine(Protocol):
    """Protocol defining the interface for verification backends.

    Any verification backend (Z3, CVC5, future e-graph, etc.) must implement
    this protocol to be usable with MBARule.verify().

    This enables dependency injection and makes the verification system
    extensible to new backends without modifying the core rule classes.

    Example implementation:
        class Z3VerificationEngine:
            def create_variables(self, var_names, options):
                import z3
                return {name: z3.BitVec(name, options.bit_width)
                        for name in sorted(var_names)}

            def prove_equivalence(self, pattern, replacement, ...):
                # Z3-specific implementation
                ...
    """

    def create_variables(
        self, var_names: set[str], options: VerificationOptions = DEFAULT_OPTIONS
    ) -> Dict[str, Any]:
        """Create solver-specific variables for the given names.

        Args:
            var_names: Set of variable names to create.
            options: Verification options (bit_width, etc.).

        Returns:
            Dictionary mapping variable names to solver-specific variable objects.
        """
        ...

    def prove_equivalence(
        self,
        pattern: SymbolicExpression,
        replacement: SymbolicExpression,
        variables: Dict[str, Any] | None = None,
        constraints: List[Any] | None = None,
        options: VerificationOptions = DEFAULT_OPTIONS,
    ) -> tuple[bool, Dict[str, int] | None]:
        """Prove that pattern is semantically equivalent to replacement.

        Args:
            pattern: The original expression.
            replacement: The simplified expression.
            variables: Optional pre-created solver variables.
            constraints: Optional list of constraints that must hold.
            options: Verification options (bit_width, timeout, etc.).

        Returns:
            Tuple of (is_equivalent, counterexample).
            - is_equivalent: True if proven equivalent.
            - counterexample: If not equivalent, dict mapping var names to
                            values demonstrating the difference.
        """
        ...


def get_default_engine() -> VerificationEngine:
    """Get the default verification engine (Z3).

    Returns:
        A Z3VerificationEngine instance.

    Raises:
        ImportError: If Z3 is not installed.
    """
    from d810.mba.backends.z3 import Z3VerificationEngine

    return Z3VerificationEngine()


# =============================================================================
# MBA Rule Classes
# =============================================================================


class MBARule(abc.ABC):
    """A pure MBA simplification rule that can verify its own correctness.

    This is the IDA-independent base class for optimization rules. It defines
    a pattern-to-replacement transformation and can verify the mathematical
    correctness using a pluggable verification engine.

    Unlike d810.optimizers.rules.VerifiableRule, this class has:
    - NO IDA dependencies (no minsn_t, mop_t, AstNode)
    - Pure symbolic verification only
    - Pluggable verification backends via VerificationEngine protocol

    Subclasses must define:
        name: str - Human-readable rule name
        description: str - What the rule does
        pattern: SymbolicExpression - The pattern to match
        replacement: SymbolicExpression - The replacement expression

    Example:
        >>> from d810.mba import Var
        >>> class XorIdentity(MBARule):
        ...     name = "XOR from OR/AND"
        ...     description = "Simplify (x|y)-(x&y) to x^y"
        ...
        ...     @property
        ...     def pattern(self):
        ...         x, y = Var("x"), Var("y")
        ...         return (x | y) - (x & y)
        ...
        ...     @property
        ...     def replacement(self):
        ...         x, y = Var("x"), Var("y")
        ...         return x ^ y
        ...
        >>> rule = XorIdentity()
        >>> rule.verify()  # Uses default Z3 engine
        True
    """

    name: str = "UnnamedMBARule"
    description: str = "No description"

    @property
    @abc.abstractmethod
    def pattern(self) -> SymbolicExpression:
        """The symbolic pattern to match."""
        ...

    @property
    @abc.abstractmethod
    def replacement(self) -> SymbolicExpression:
        """The symbolic expression to replace the pattern with."""
        ...

    def verify(
        self,
        options: VerificationOptions | None = None,
        engine: VerificationEngine | None = None,
    ) -> bool:
        """Proves that the pattern is equivalent to the replacement.

        Args:
            options: Verification options (bit_width, timeout, etc.).
                    If None, uses default options (32-bit).
            engine: Verification engine to use. If None, uses Z3.

        Returns:
            True if the rule is proven correct.

        Raises:
            AssertionError: If the patterns are not equivalent.
            ImportError: If no engine provided and Z3 is not available.
        """
        if options is None:
            options = DEFAULT_OPTIONS
        if engine is None:
            engine = get_default_engine()

        # Prove equivalence - engine handles variable creation internally
        is_equivalent, counterexample = engine.prove_equivalence(
            self.pattern, self.replacement, options=options
        )

        if not is_equivalent:
            msg = (
                f"\n--- VERIFICATION FAILED ---\n"
                f"Rule:        {self.name}\n"
                f"Description: {self.description}\n"
                f"Identity:    {self.pattern} => {self.replacement}\n"
            )
            if counterexample:
                msg += f"Counterexample: {counterexample}\n"
            msg += (
                "This rule does NOT preserve semantics and should not be used.\n"
                "Please fix the pattern or replacement definition."
            )
            raise AssertionError(msg)

        return True


class ConstrainedMBARule(MBARule):
    """An MBA rule with constraints on when it's valid.

    Some MBA identities only hold under certain conditions. This class
    extends MBARule to support constraints.

    Constraints can be defined in two ways:
    1. CONSTRAINTS class attribute with ConstraintExpr objects (preferred)
    2. get_constraints() method returning solver-specific expressions (legacy)

    Example using CONSTRAINTS (preferred):
        >>> from d810.mba import Var, Const
        >>> class ConditionalRule(ConstrainedMBARule):
        ...     name = "Conditional simplification"
        ...     c1 = Const("c1")
        ...     CONSTRAINTS = [c1 == Const("0", 0)]
        ...
        ...     @property
        ...     def pattern(self):
        ...         return Var("x") + self.c1
        ...
        ...     @property
        ...     def replacement(self):
        ...         return Var("x")
    """

    def get_constraints(self, solver_vars: Dict[str, Any]) -> List[Any]:
        """Define constraints for this rule's validity (legacy method).

        Override this method to specify constraints using solver-specific
        expressions directly. For new code, prefer using the CONSTRAINTS
        class attribute with ConstraintExpr objects.

        Args:
            solver_vars: Dictionary mapping variable names to solver-specific
                        variable objects (e.g., Z3 BitVec).

        Returns:
            List of solver-specific constraint expressions.
        """
        return []

    def verify(
        self,
        options: VerificationOptions | None = None,
        engine: VerificationEngine | None = None,
    ) -> bool:
        """Proves that pattern ≡ replacement under the defined constraints.

        Args:
            options: Verification options (bit_width, timeout, etc.).
            engine: Verification engine to use. If None, uses Z3.

        Returns:
            True if the rule is proven correct under its constraints.

        Raises:
            AssertionError: If verification fails.
            ImportError: If no engine provided and Z3 is not available.
        """
        if options is None:
            options = DEFAULT_OPTIONS
        if engine is None:
            engine = get_default_engine()

        # Skip verification if replacement is not a SymbolicExpression
        # Use Protocol for hot-reload safety
        if not isinstance(self.replacement, SymbolicExpressionProtocol):
            return True

        # Collect all variable names from pattern and replacement
        var_names = set()
        _collect_var_names(self.pattern, var_names)
        _collect_var_names(self.replacement, var_names)

        # Create solver variables via the engine
        solver_vars = engine.create_variables(var_names, options)

        # Get constraints - support both legacy get_constraints() and new CONSTRAINTS
        constraints = self.get_constraints(solver_vars)

        # Prove equivalence
        is_equivalent, counterexample = engine.prove_equivalence(
            self.pattern,
            self.replacement,
            variables=solver_vars,
            constraints=constraints,
            options=options,
        )

        if not is_equivalent:
            msg = (
                f"\n--- VERIFICATION FAILED ---\n"
                f"Rule:        {self.name}\n"
                f"Description: {self.description}\n"
                f"Identity:    {self.pattern} => {self.replacement}\n"
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

        return True


# =============================================================================
# Utility Functions
# =============================================================================


def verify_transformation(
    pattern: SymbolicExpression,
    replacement: SymbolicExpression,
    constraints: List[Any] | None = None,
    options: VerificationOptions | None = None,
    engine: VerificationEngine | None = None,
) -> tuple[bool, dict[str, int] | None]:
    """Verify that a transformation preserves semantics.

    This is a functional interface for one-off verification without
    creating an MBARule class.

    Args:
        pattern: The original expression.
        replacement: The simplified expression.
        constraints: Optional list of constraints.
        options: Verification options (bit_width, timeout, etc.).
        engine: Verification engine to use. If None, uses Z3.

    Returns:
        Tuple of (is_equivalent, counterexample).

    Example:
        >>> from d810.mba import Var, verify_transformation
        >>> x, y = Var("x"), Var("y")
        >>> pattern = (x | y) - (x & y)
        >>> replacement = x ^ y
        >>> is_valid, _ = verify_transformation(pattern, replacement)
        >>> assert is_valid
    """
    if options is None:
        options = DEFAULT_OPTIONS
    if engine is None:
        engine = get_default_engine()

    # Collect all variable names
    var_names = set()
    _collect_var_names(pattern, var_names)
    _collect_var_names(replacement, var_names)

    # Create solver variables via the engine
    solver_vars = engine.create_variables(var_names, options)

    # Prove equivalence
    return engine.prove_equivalence(
        pattern,
        replacement,
        variables=solver_vars,
        constraints=constraints,
        options=options,
    )


def _collect_var_names(expr: SymbolicExpression, var_names: set) -> None:
    """Recursively collect variable and constant names from expression."""
    # Use Protocol for hot-reload safety
    if expr is None or not isinstance(expr, SymbolicExpressionProtocol):
        return
    if expr.is_leaf():
        if expr.name and expr.value is None:
            var_names.add(expr.name)
    else:
        if expr.left:
            _collect_var_names(expr.left, var_names)
        if expr.right:
            _collect_var_names(expr.right, var_names)


__all__ = [
    "VerificationOptions",
    "DEFAULT_OPTIONS",
    "VerificationEngine",
    "get_default_engine",
    "MBARule",
    "ConstrainedMBARule",
    "verify_transformation",
]
