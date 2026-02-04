"""Pure symbolic optimization rules with backend-agnostic definitions.

This module provides base classes for creating optimization rules using pure
symbolic expressions. Rules are defined using the DSL (d810.mba.dsl) and are
completely independent of any backend (Z3, IDA, etc.).

Verification and pattern matching are handled by backends:
- d810.mba.backends.z3.verify_rule() - Z3-based verification
- d810.mba.backends.ida.IDAPatternAdapter - IDA pattern matching

Registry Architecture:
    Rules inherit from Registrant for automatic registration. This avoids
    triggering IDA imports at class definition time, enabling unit testing
    without IDA. Instantiation happens lazily when rules are actually needed.

    Usage:
        # Verification (requires Z3):
        from d810.mba.backends.z3 import verify_rule
        for rule_cls in VerifiableRule.registry.values():
            verify_rule(rule_cls())

        # IDA integration (instantiates rules):
        instances = VerifiableRule.instantiate_all()
"""

from __future__ import annotations

import abc
from typing import TYPE_CHECKING, Any, Dict, List, Self

from d810.core import getLogger
from d810.core.registry import Registrant
from d810.mba.dsl import SymbolicExpression, SymbolicExpressionProtocol

# Import types only for type checking to avoid circular imports and IDA dependencies
if TYPE_CHECKING:
    from d810.optimizers.core import OptimizationContext

logger = getLogger(__name__)


class SymbolicRule(abc.ABC):
    """A rule defined by symbolic, verifiable expressions.

    This abstract base class represents an optimization rule where both the
    pattern to match and the replacement are defined using the symbolic DSL.
    The rule can be verified for correctness using Z3.

    Subclasses must define the pattern and replacement as SymbolicExpression
    objects using Python's operator overloading for readability.
    """

    name: str = "UnnamedSymbolicRule"
    description: str = "No description"

    @property
    @abc.abstractmethod
    def pattern(self) -> SymbolicExpression:
        """The symbolic pattern to match.

        Returns:
            A SymbolicExpression representing the pattern to search for.

        Example:
            >>> from d810.mba.dsl import Var
            >>> x, y = Var("x"), Var("y")
            >>> return (x | y) - (x & y)
        """
        ...

    @property
    @abc.abstractmethod
    def replacement(self) -> SymbolicExpression:
        """The symbolic expression to replace the pattern with.

        Returns:
            A SymbolicExpression representing the replacement.

        Example:
            >>> from d810.mba.dsl import Var
            >>> x, y = Var("x"), Var("y")
            >>> return x ^ y
        """
        ...

    def apply(self, context: OptimizationContext, ins: "minsn_t") -> int:
        """Applies the symbolic rule to a single instruction.

        This method implements the pattern matching and replacement logic.
        It will be fully implemented as part of the pattern matching refactoring.

        Args:
            context: The optimization context.
            ins: The microcode instruction to potentially optimize.

        Returns:
            1 if the instruction was modified, 0 otherwise.
        """
        # This will be implemented as part of the pattern matching refactoring
        raise NotImplementedError(
            "SymbolicRule.apply() will be implemented in the pattern matching refactoring"
        )


class VerifiableRule(SymbolicRule, Registrant):
    """A symbolic rule that can verify its own correctness with constraints.

    This class extends both SymbolicRule (for Z3 verification) and Registrant
    (for automatic registration). All subclasses are automatically registered
    via the Registrant metaclass.

    Class Variables:
        PATTERN: DSL-based pattern (SymbolicExpression from dsl module)
        REPLACEMENT: DSL-based replacement (SymbolicExpression from dsl module)
        CONSTRAINTS: Optional list of runtime constraint functions.
                    Each function takes a match context dict and returns bool.
        DYNAMIC_CONSTS: Optional dict mapping constant names to compute functions.
                       Used for constants whose values depend on matched values.

    Example:
        >>> from d810.mba.dsl import Var, Const
        >>> x, y = Var("x_0"), Var("x_1")
        >>> class Xor_HackersDelight1(VerifiableRule):
        ...     PATTERN = (x | y) - (x & y)
        ...     REPLACEMENT = x ^ y

    Example with constraints:
        >>> from d810.mba.dsl import when
        >>> class MyRule(VerifiableRule):
        ...     PATTERN = (x ^ Const("c_1")) + (x + Const("c_2"))
        ...     REPLACEMENT = x & y
        ...     CONSTRAINTS = [when.equal_mops("c_1", "c_2")]

    Example with dynamic constants:
        >>> class MyRule(VerifiableRule):
        ...     PATTERN = x + Const("c_2")
        ...     REPLACEMENT = x + DynamicConst("val_res", lambda ctx: ctx['c_2'].value - 1)
    """

    BIT_WIDTH = 32  # Default bit-width for Z3 verification

    CONSTRAINTS: List = []  # Runtime constraints (list of callables)
    DYNAMIC_CONSTS: Dict[str, Any] = {}  # Dynamic constant generators
    CONTEXT_VARS: Dict[str, Any] = (
        {}
    )  # Context providers (e.g., {"full_reg": context.dst.parent_register})
    UPDATE_DESTINATION: str | None = (
        None  # Variable name to use as new destination (e.g., "full_reg")
    )
    KNOWN_INCORRECT: bool = (
        False  # Set to True for rules that are mathematically incorrect
    )
    SKIP_VERIFICATION: bool = (
        False  # Set to True to skip Z3 verification (e.g., for size-dependent constraints)
    )

    @classmethod
    def resolve_lazy_rules(cls) -> None:
        """Force load all lazily registered rules into the main registry."""
        for name in list(cls.lazy_registry.keys()):
            try:
                cls.get(name)
                logger.debug(f"Lazily resolved rule: {name}")
            except Exception as e:
                logger.error(f"Failed to resolve lazy rule '{name}': {e}")

    @classmethod
    def instantiate_all(cls) -> List[Self]:
        """Resolve lazy rules and instantiate all registered rules.

        This acts as the replacement for RuleRegistry.instantiate_all().
        It is safe to call even if IDA is not ready, provided the __init__
        of the rules checks for environment availability.

        Note:
            Classes without a valid pattern (e.g., test base classes) are skipped.
            This prevents test classes that inherit from VerifiableRule but don't
            define PATTERN from polluting the rule list.
        """
        cls.resolve_lazy_rules()

        instances: List[Self] = []
        for rule_cls in cls.registry.values():
            # Skip abstract classes
            if isabstract(rule_cls):
                logger.debug(f"Skipping abstract class: {rule_cls.__name__}")
                continue
            # Skip classes without a valid pattern definition
            # These are typically test base classes that inherit VerifiableRule
            # but don't define PATTERN/REPLACEMENT
            # Use Protocol for hot-reload safety
            has_pattern = hasattr(rule_cls, "_dsl_pattern") or (
                "PATTERN" in rule_cls.__dict__
                and isinstance(rule_cls.__dict__["PATTERN"], SymbolicExpressionProtocol)
            )
            if not has_pattern:
                logger.debug(f"Skipping class without pattern: {rule_cls.__name__}")
                continue

            try:
                instance = rule_cls()
                instances.append(instance)
            except Exception as e:
                logger.warning(
                    f"Skipping rule {rule_cls.__name__} due to instantiation error: {e}"
                )

        return instances

    def __init__(self):
        """Initialize a VerifiableRule instance.

        Sets up instance attributes required by the d810 optimizer system.
        This initialization is IDA-independent - pattern conversion happens lazily.
        """
        # Call parent __init__ - this will initialize pattern_candidates etc.
        # when PatternMatchingRule is in our bases
        super().__init__()

        # These attributes are needed for the d810 optimizer system
        # Set them here in case the parent __init__ didn't set them
        if not hasattr(self, "maturities"):
            self.maturities = []
        if not hasattr(self, "config"):
            self.config = {}
        if not hasattr(self, "log_dir"):
            self.log_dir = None
        if not hasattr(self, "dump_intermediate_microcode"):
            self.dump_intermediate_microcode = False
        # Note: pattern_candidates is now a property, not set in __init__

    def configure(self, kwargs: Dict[str, Any]) -> None:
        """Configure this rule with options from a JSON config.

        This method is required by the d810 optimizer system.

        Args:
            kwargs: Configuration dictionary from the JSON project file.
        """
        self.config = kwargs if kwargs is not None else {}
        if "maturities" in self.config:
            try:
                from d810.hexrays.hexrays_formatters import string_to_maturity

                self.maturities = [
                    string_to_maturity(x) for x in self.config["maturities"]
                ]
            except ImportError:
                pass
        if "dump_intermediate_microcode" in self.config:
            self.dump_intermediate_microcode = self.config[
                "dump_intermediate_microcode"
            ]

    def set_log_dir(self, log_dir: str) -> None:
        """Set the log directory for this rule.

        Args:
            log_dir: Path to the log directory.
        """
        self.log_dir = log_dir

    def __init_subclass__(cls, **kwargs):
        """Automatically convert DSL patterns to internal storage.

        This magic method is called whenever a class inherits from VerifiableRule.
        It:
        1. Renames PATTERN/REPLACEMENT to _dsl_pattern/_dsl_replacement (internal storage)
        2. Creates PATTERN/REPLACEMENT_PATTERN properties that return AstNodes

        Note: Registration happens automatically via Registrant.__init_subclass__.
        """
        super().__init_subclass__(**kwargs)

        # Capture and convert DSL patterns to internal storage
        # Subclasses set PATTERN/REPLACEMENT as class vars (SymbolicExpression)
        # We move them to _dsl_pattern/_dsl_replacement so the properties work
        # IMPORTANT: Use isinstance() instead of hasattr(.., 'node') to avoid
        # triggering IDA imports at class definition time. The .node property
        # lazily imports IDA modules, which would break unit testing without IDA.
        # Use Protocol for hot-reload safety
        if "PATTERN" in cls.__dict__ and isinstance(
            cls.__dict__["PATTERN"], SymbolicExpressionProtocol
        ):
            cls._dsl_pattern = cls.__dict__["PATTERN"]
            # Keep PATTERN as an alias for backward compatibility

        # Use Protocol for hot-reload safety
        if "REPLACEMENT" in cls.__dict__ and isinstance(
            cls.__dict__["REPLACEMENT"], SymbolicExpressionProtocol
        ):
            cls._dsl_replacement = cls.__dict__["REPLACEMENT"]
            # Keep REPLACEMENT as an alias for backward compatibility

    # Implement rule name property (required by OptimizationRule)
    @property
    def name(self) -> str:
        """Return the rule name (class name by default).

        This is used by d810's optimizer to track which rules fire.
        """
        return self.__class__.__name__

    @property
    def description(self) -> str:
        """Return the rule description from DESCRIPTION class attribute.

        Falls back to "No description" if not set.
        """
        return getattr(self.__class__, "DESCRIPTION", "No description")

    # Implement SymbolicRule abstract properties
    @property
    def pattern(self) -> SymbolicExpression | None:
        """The symbolic pattern to match (SymbolicRule interface).

        Returns the DSL SymbolicExpression for Z3 verification.
        """
        # Look up the MRO for _dsl_pattern (set by __init_subclass__)
        for cls in type(self).__mro__:
            if hasattr(cls, "_dsl_pattern"):
                return cls._dsl_pattern

    @property
    def replacement(self) -> SymbolicExpression | None:
        """The symbolic replacement expression (SymbolicRule interface).

        Returns the DSL SymbolicExpression for Z3 verification.
        """
        # Look up the MRO for _dsl_replacement (set by __init_subclass__)
        for cls in type(self).__mro__:
            if hasattr(cls, "_dsl_replacement"):
                return cls._dsl_replacement

    # =========================================================================
    # Constraint Checking Interface
    # =========================================================================
    # These methods implement constraint checking for pattern matching.
    # They are called by IDAPatternAdapter when checking if a matched
    # candidate satisfies the rule's constraints.

    def check_candidate(self, candidate) -> bool:
        """Check if a candidate AstNode matches this rule's constraints.

        This implements the GenericPatternRule interface, allowing VerifiableRule
        to work with PatternMatchingRule's matching system.

        The candidate is an AstNode that has already matched the PATTERN structure.
        This method:
        1. Adds the candidate itself to the context (for context providers)
        2. Runs all context providers to bind additional variables
        3. Checks all runtime constraints
        4. Optionally updates the destination operand

        Args:
            candidate: An AstNode that structurally matches PATTERN

        Returns:
            True if all constraints are satisfied, False otherwise
        """
        # Build match context from candidate's matched variables
        # AstNode stores matched leaves in leafs_by_name after pattern matching
        # Also support legacy mop_dict and get_z3_vars interfaces
        match_context = {}
        if hasattr(candidate, "leafs_by_name") and candidate.leafs_by_name:
            match_context = candidate.leafs_by_name
        elif hasattr(candidate, "mop_dict"):
            match_context = candidate.mop_dict
        elif hasattr(candidate, "get_z3_vars"):
            match_context = candidate.get_z3_vars({})

        # If no variable bindings are available, we can't check constraints
        # This happens when the pattern is checked in read_only mode before mops are populated
        if not match_context:
            # If this rule has CONSTRAINTS, we need bindings to check them
            # Return False to force the caller to populate bindings first
            if hasattr(self, "CONSTRAINTS") and self.CONSTRAINTS:
                return False
            # No constraints to check, pattern match is sufficient
            return True

        # CRITICAL: Add the candidate itself so constraints/providers can inspect it
        # This enables context-aware constraints like when.dst.is_high_half
        match_context["_candidate"] = candidate

        # Run context providers to bind additional variables
        # Example: {"full_reg": context.dst.parent_register}
        if hasattr(self, "CONTEXT_VARS") and self.CONTEXT_VARS:
            for var_name, provider in self.CONTEXT_VARS.items():
                try:
                    # Call the provider with the match context
                    value = provider(match_context)
                    if value is None:
                        # Provider failed (e.g., couldn't find parent register)
                        logger.debug(
                            f"Context provider for '{var_name}' returned None in {self.name}"
                        )
                        return False

                    # Add the bound variable to both contexts
                    match_context[var_name] = value
                    if hasattr(candidate, "mop_dict"):
                        candidate.mop_dict[var_name] = value

                except Exception as e:
                    logger.debug(
                        f"Context provider for '{var_name}' failed in {self.name}: {e}"
                    )
                    return False

        # Check all runtime constraints (including context-aware ones)
        if not self.check_runtime_constraints(match_context):
            return False

        # Handle destination update side effect
        # If UPDATE_DESTINATION is set, modify the candidate's destination operand
        if hasattr(self, "UPDATE_DESTINATION") and self.UPDATE_DESTINATION:
            dest_var = self.UPDATE_DESTINATION
            if dest_var in match_context:
                bound_var = match_context[dest_var]
                # Extract the mop from the AstNode
                if hasattr(bound_var, "mop") and bound_var.mop is not None:
                    candidate.dst_mop = bound_var.mop
                    logger.debug(f"Updated destination to '{dest_var}' in {self.name}")
                else:
                    logger.warning(
                        f"UPDATE_DESTINATION '{dest_var}' has no mop in {self.name}"
                    )
                    return False
            else:
                logger.warning(
                    f"UPDATE_DESTINATION '{dest_var}' not found in context for {self.name}"
                )
                return False

        return True

    def check_runtime_constraints(self, match_context: Dict[str, Any]) -> bool:
        """Check if all runtime constraints are satisfied for this match.

        This method evaluates the CONSTRAINTS list against the matched values.
        Constraints can be either:
        1. ConstraintExpr objects (new declarative style)
        2. Callable predicates (legacy style)

        Args:
            match_context: Dictionary mapping variable names to matched AstNodes/values.

        Returns:
            True if all constraints pass, False otherwise.

        Example:
            >>> # New declarative style:
            >>> CONSTRAINTS = [
            ...     c1 == ~c2,          # Checking constraint
            ...     val_res == c2 - ONE  # Defining constraint
            ... ]
            >>> # Legacy style:
            >>> from d810.mba.dsl import when
            >>> CONSTRAINTS = [
            ...     when.equal_mops("c_1", "c_2"),
            ...     when.is_bnot("x_0", "bnot_x_0"),
            ... ]
        """
        if not hasattr(self, "CONSTRAINTS") or not self.CONSTRAINTS:
            return True

        for constraint in self.CONSTRAINTS:
            try:
                # Check if this is a ConstraintExpr (new declarative style)
                from d810.mba.constraints import is_constraint_expr

                if is_constraint_expr(constraint):
                    # Try to extract a variable definition
                    var_name, value = constraint.eval_and_define(match_context)

                    if var_name is not None:
                        # This is a defining constraint - add the computed value
                        from d810.expr.ast import AstConstant

                        match_context[var_name] = AstConstant(var_name, value)
                    else:
                        # This is a checking constraint - verify it holds
                        if not constraint.check(match_context):
                            return False
                else:
                    # Legacy callable constraint
                    if not constraint(match_context):
                        return False
            except (KeyError, AttributeError, TypeError) as e:
                logger.debug(f"Constraint check failed for {self.name}: {e}")
                return False

        return True

    # =========================================================================
    # Z3 Constraint Generation Interface
    # =========================================================================
    # These methods are called by the Z3 backend during rule verification.
    # Subclasses can override get_constraints() to provide custom Z3 constraints.

    def get_constraints(self, z3_vars: Dict[str, Any]) -> List:
        """Get Z3 constraints for rule verification.

        This method is called by the Z3 backend (d810.mba.backends.z3) during
        rule verification. Subclasses can override this to provide custom Z3
        constraints that must hold for the rule to be valid.

        The default implementation returns an empty list, allowing subclasses
        to safely call super().get_constraints(z3_vars).

        Args:
            z3_vars: Dictionary mapping variable names to Z3 BitVec objects.

        Returns:
            List of Z3 constraint expressions.

        Example:
            >>> def get_constraints(self, z3_vars):
            ...     from z3 import ULT
            ...     # Require that c_0 < c_1
            ...     constraints = super().get_constraints(z3_vars)
            ...     constraints.append(ULT(z3_vars['c_0'], z3_vars['c_1']))
            ...     return constraints
        """
        return []


def isabstract(cls) -> bool:
    """Check if a class is abstract (has unimplemented abstract methods).

    Args:
        cls: The class to check.

    Returns:
        True if the class has any unimplemented abstract methods.
    """
    return bool(getattr(cls, "__abstractmethods__", None))
