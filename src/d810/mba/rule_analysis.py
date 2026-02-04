"""Utilities for analyzing MBA rule relationships using e-graphs.

This module provides functions to detect when two MBA rules are:
1. Equivalent (same pattern with different syntax)
2. Inverse (applying one then the other creates a cycle)

These utilities help identify redundant rules and potential optimization loops.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from d810.mba.rules._base import VerifiableRule

logger = logging.getLogger(__name__)


def _check_egglog_available() -> bool:
    """Check if egglog is available for use."""
    try:
        from d810.mba.backends.egglog_backend import check_egglog_available
        return check_egglog_available()
    except ImportError:
        return False


def _symbolic_expr_to_pattern_expr(expr, var_cache: dict | None = None):
    """Convert a SymbolicExpression to a PatternExpr for e-graph analysis.

    Args:
        expr: A SymbolicExpression from the DSL.
        var_cache: Cache mapping variable names to PatternExpr variables.

    Returns:
        PatternExpr representation, or None if conversion fails.
    """
    from d810.mba.backends.egglog_backend import PatternExpr
    from d810.mba.dsl import SymbolicExpressionProtocol

    if var_cache is None:
        var_cache = {}

    if expr is None:
        return None

    # Handle SymbolicExpression
    if not isinstance(expr, SymbolicExpressionProtocol):
        logger.debug(f"Cannot convert non-SymbolicExpression: {type(expr)}")
        return None

    # Leaf node (variable or constant)
    if expr.is_leaf():
        name = expr.name or f"leaf_{id(expr)}"
        if name not in var_cache:
            var_cache[name] = PatternExpr.var(name)
        return var_cache[name]

    # Binary operations
    operation = expr.operation

    if operation in ("add", "sub", "mul", "and", "or", "xor"):
        left = _symbolic_expr_to_pattern_expr(expr.left, var_cache)
        right = _symbolic_expr_to_pattern_expr(expr.right, var_cache)
        if left is None or right is None:
            return None

        op_map = {
            "add": lambda l, r: l + r,
            "sub": lambda l, r: l - r,
            "mul": lambda l, r: l * r,
            "and": lambda l, r: l & r,
            "or": lambda l, r: l | r,
            "xor": lambda l, r: l ^ r,
        }
        return op_map[operation](left, right)

    # Unary operations
    if operation in ("neg", "bnot"):
        operand = _symbolic_expr_to_pattern_expr(expr.left, var_cache)
        if operand is None:
            return None

        if operation == "neg":
            return -operand
        elif operation == "bnot":
            return ~operand

    # Unsupported operation - treat as leaf
    logger.debug(f"Unsupported operation '{operation}', treating as leaf")
    name = f"op_{operation}_{id(expr)}"
    if name not in var_cache:
        var_cache[name] = PatternExpr.var(name)
    return var_cache[name]


def _collect_leaf_names(expr) -> list[str]:
    """Collect all leaf variable names from a SymbolicExpression in order of first occurrence.

    Args:
        expr: A SymbolicExpression from the DSL.

    Returns:
        List of variable names in order of first occurrence.
    """
    from d810.mba.dsl import SymbolicExpressionProtocol

    if expr is None:
        return []

    if not isinstance(expr, SymbolicExpressionProtocol):
        return []

    if expr.is_leaf():
        name = expr.name or f"leaf_{id(expr)}"
        return [name]

    # Collect from children
    names = []
    seen = set()

    if expr.left is not None:
        for name in _collect_leaf_names(expr.left):
            if name not in seen:
                names.append(name)
                seen.add(name)

    if expr.right is not None:
        for name in _collect_leaf_names(expr.right):
            if name not in seen:
                names.append(name)
                seen.add(name)

    return names


def _symbolic_expr_to_pattern_expr_positional(expr):
    """Convert a SymbolicExpression to a PatternExpr with positional variable naming.

    This function renames all variables to positional names (v0, v1, v2, ...)
    based on their first occurrence in the expression tree. This allows
    comparison of expressions with different variable names but the same
    structure.

    Args:
        expr: A SymbolicExpression from the DSL.

    Returns:
        PatternExpr representation with positional variable names, or None if conversion fails.
    """
    from d810.mba.backends.egglog_backend import PatternExpr
    from d810.mba.dsl import SymbolicExpressionProtocol

    if expr is None:
        return None

    # Collect original variable names in order
    original_names = _collect_leaf_names(expr)

    # Create positional mapping: original_name -> v0, v1, v2, ...
    positional_cache = {}
    for i, orig_name in enumerate(original_names):
        positional_name = f"v{i}"
        positional_cache[orig_name] = PatternExpr.var(positional_name)

    # Convert using the positional cache
    return _symbolic_expr_to_pattern_expr(expr, positional_cache)


def _get_rule_pattern(rule: "VerifiableRule"):
    """Extract the PATTERN SymbolicExpression from a rule.

    Args:
        rule: A VerifiableRule instance.

    Returns:
        The PATTERN SymbolicExpression, or None if not found.
    """
    # Try _dsl_pattern first (stored by __init_subclass__)
    for cls in type(rule).__mro__:
        if hasattr(cls, "_dsl_pattern"):
            return cls._dsl_pattern

    # Fallback to PATTERN class attribute
    if hasattr(type(rule), "PATTERN"):
        return type(rule).PATTERN

    return None


def _get_rule_replacement(rule: "VerifiableRule"):
    """Extract the REPLACEMENT SymbolicExpression from a rule.

    Args:
        rule: A VerifiableRule instance.

    Returns:
        The REPLACEMENT SymbolicExpression, or None if not found.
    """
    # Try _dsl_replacement first (stored by __init_subclass__)
    for cls in type(rule).__mro__:
        if hasattr(cls, "_dsl_replacement"):
            return cls._dsl_replacement

    # Fallback to REPLACEMENT class attribute
    if hasattr(type(rule), "REPLACEMENT"):
        return type(rule).REPLACEMENT

    return None


def check_rules_equivalent(rule1: "VerifiableRule", rule2: "VerifiableRule") -> bool:
    """Check if two rules' patterns are equivalent under e-graph rewriting.

    Two patterns are equivalent if they represent the same mathematical
    expression, differing only in commutativity or other rewrite rules.

    Args:
        rule1: First rule to compare.
        rule2: Second rule to compare.

    Returns:
        True if rule1.PATTERN is equivalent to rule2.PATTERN after saturation.
        False if not equivalent or if conversion fails.

    Example:
        >>> # These should be equivalent (commuted XOR):
        >>> # rule1.PATTERN = x ^ y
        >>> # rule2.PATTERN = y ^ x
        >>> check_rules_equivalent(rule1, rule2)  # True
    """
    if not _check_egglog_available():
        logger.warning("egglog not available for rule equivalence checking")
        return False

    from d810.mba.backends.egglog_backend import verify_pattern_equivalence

    # Get patterns
    pattern1 = _get_rule_pattern(rule1)
    pattern2 = _get_rule_pattern(rule2)

    if pattern1 is None or pattern2 is None:
        logger.debug(f"Cannot get pattern from rules: {rule1.name}, {rule2.name}")
        return False

    # Convert to PatternExpr using shared variable cache
    var_cache = {}
    expr1 = _symbolic_expr_to_pattern_expr(pattern1, var_cache)
    expr2 = _symbolic_expr_to_pattern_expr(pattern2, var_cache)

    if expr1 is None or expr2 is None:
        logger.debug(f"Cannot convert patterns to PatternExpr")
        return False

    # Use e-graph to check equivalence
    return verify_pattern_equivalence(expr1, expr2)


def check_inverse_rules(rule1: "VerifiableRule", rule2: "VerifiableRule") -> bool:
    """Check if rule1.PATTERN is equivalent to rule2.REPLACEMENT (making them inverses).

    Two rules are inverses if applying one followed by the other creates a
    no-op cycle. This happens when:
    - rule1 transforms A -> B
    - rule2 transforms B -> A

    This is detected by checking if rule1.PATTERN is equivalent to
    rule2.REPLACEMENT (or vice versa).

    Args:
        rule1: First rule to compare.
        rule2: Second rule to compare.

    Returns:
        True if rule1.PATTERN is equivalent to rule2.REPLACEMENT.
        False if not inverse or if conversion fails.

    Example:
        >>> # BnotXor_FactorRule_1: x ^ ~y => ~(x ^ y)
        >>> # CstSimplificationRule16: ~(x ^ c_1) => x ^ ~c_1
        >>> # These are inverses because:
        >>> #   BnotXor pattern: x ^ ~y
        >>> #   CstSimpl replacement: x ^ ~c_1
        >>> # They're equivalent (y can match c_1)
        >>> check_inverse_rules(bnotxor_rule, cstsimp_rule)  # True
    """
    if not _check_egglog_available():
        logger.warning("egglog not available for inverse rule checking")
        return False

    from d810.mba.backends.egglog_backend import verify_pattern_equivalence

    # Get pattern from rule1 and replacement from rule2
    pattern1 = _get_rule_pattern(rule1)
    replacement2 = _get_rule_replacement(rule2)

    if pattern1 is None or replacement2 is None:
        logger.debug(f"Cannot get pattern/replacement from rules: {rule1.name}, {rule2.name}")
        return False

    # Convert to PatternExpr with POSITIONAL variable naming
    # We rename variables by position (v0, v1, ...) so that structurally
    # equivalent expressions with different variable names are recognized.
    expr1 = _symbolic_expr_to_pattern_expr_positional(pattern1)
    expr2 = _symbolic_expr_to_pattern_expr_positional(replacement2)

    if expr1 is None or expr2 is None:
        logger.debug(f"Cannot convert to PatternExpr")
        return False

    # Use e-graph to check equivalence
    return verify_pattern_equivalence(expr1, expr2)


def find_inverse_rule_pairs(
    rules: list["VerifiableRule"],
) -> list[tuple["VerifiableRule", "VerifiableRule"]]:
    """Find all pairs of rules that are inverses of each other.

    This function examines all pairs of rules and identifies those where
    one rule's pattern matches the other's replacement, indicating they
    could create optimization loops.

    Args:
        rules: List of VerifiableRule instances to analyze.

    Returns:
        List of (rule1, rule2) tuples where rule1.PATTERN is equivalent
        to rule2.REPLACEMENT.

    Note:
        This is O(n^2) in the number of rules, but typically the rule
        set is small enough that this is acceptable.
    """
    if not _check_egglog_available():
        logger.warning("egglog not available for finding inverse pairs")
        return []

    inverse_pairs = []

    for i, rule1 in enumerate(rules):
        for rule2 in rules[i + 1:]:  # Avoid checking (a, b) and (b, a)
            # Check if rule1.PATTERN ~ rule2.REPLACEMENT
            if check_inverse_rules(rule1, rule2):
                inverse_pairs.append((rule1, rule2))

            # Check if rule2.PATTERN ~ rule1.REPLACEMENT
            if check_inverse_rules(rule2, rule1):
                inverse_pairs.append((rule2, rule1))

    return inverse_pairs


def find_equivalent_rule_patterns(
    rules: list["VerifiableRule"],
) -> list[tuple["VerifiableRule", "VerifiableRule"]]:
    """Find all pairs of rules with equivalent patterns (potential duplicates).

    This function identifies rules that match the same expressions,
    which might indicate redundant rules in the ruleset.

    Args:
        rules: List of VerifiableRule instances to analyze.

    Returns:
        List of (rule1, rule2) tuples where rule1.PATTERN is equivalent
        to rule2.PATTERN.
    """
    if not _check_egglog_available():
        logger.warning("egglog not available for finding equivalent patterns")
        return []

    equivalent_pairs = []

    for i, rule1 in enumerate(rules):
        for rule2 in rules[i + 1:]:
            if check_rules_equivalent(rule1, rule2):
                equivalent_pairs.append((rule1, rule2))

    return equivalent_pairs
