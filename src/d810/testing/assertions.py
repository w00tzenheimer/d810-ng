"""Assertion helpers for deobfuscation tests.

This module provides reusable assertion functions that handle common
patterns in deobfuscation testing.
"""

from __future__ import annotations

from d810.core.typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from d810.core.stats import OptimizationStatistics


def assert_contains(
    code: str,
    patterns: list[str],
    context: str = "code",
    all_required: bool = True,
) -> None:
    """Assert that code contains specified patterns.

    Args:
        code: The code string to check.
        patterns: List of patterns that should be present.
        context: Description for error messages (e.g., "obfuscated code").
        all_required: If True, ALL patterns must be present. If False, ANY pattern.

    Raises:
        AssertionError: If the required patterns are not found.
    """
    if not patterns:
        return

    found = [p for p in patterns if p in code]
    missing = [p for p in patterns if p not in code]

    if all_required and missing:
        raise AssertionError(
            f"Missing required patterns in {context}:\n"
            f"  Missing: {missing}\n"
            f"  Found: {found}\n"
            f"  Code:\n{_indent(code)}"
        )

    if not all_required and not found:
        raise AssertionError(
            f"None of the expected patterns found in {context}:\n"
            f"  Expected any of: {patterns}\n"
            f"  Code:\n{_indent(code)}"
        )


def assert_not_contains(
    code: str,
    patterns: list[str],
    context: str = "code",
) -> None:
    """Assert that code does NOT contain specified patterns.

    Args:
        code: The code string to check.
        patterns: List of patterns that should NOT be present.
        context: Description for error messages.

    Raises:
        AssertionError: If any forbidden pattern is found.
    """
    if not patterns:
        return

    found = [p for p in patterns if p in code]

    if found:
        raise AssertionError(
            f"Forbidden patterns found in {context}:\n"
            f"  Found: {found}\n"
            f"  Code:\n{_indent(code)}"
        )


def assert_code_equivalent(
    actual: str,
    expected: str,
    code_comparator: Any,
    acceptable_patterns: Optional[list[str]] = None,
) -> bool:
    """Assert that actual code is semantically equivalent to expected.

    First tries AST-based comparison via code_comparator. If that fails,
    falls back to checking acceptable_patterns.

    Args:
        actual: The actual deobfuscated code.
        expected: The expected code.
        code_comparator: CodeComparator instance for AST comparison.
        acceptable_patterns: Fallback patterns if AST comparison fails.

    Returns:
        True if exact AST match, False if only patterns matched.

    Raises:
        AssertionError: If neither AST match nor patterns found.
    """
    # Try exact AST comparison first
    if code_comparator is not None and expected:
        if code_comparator.are_equivalent(actual, expected):
            return True

    # Fall back to pattern matching
    if acceptable_patterns:
        found = [p for p in acceptable_patterns if p in actual]
        if found:
            return False  # Patterns matched, but not exact

    # Neither exact match nor patterns
    if expected:
        raise AssertionError(
            f"Code does not match expected:\n"
            f"  Expected:\n{_indent(expected)}\n"
            f"  Actual:\n{_indent(actual)}\n"
            f"  Acceptable patterns: {acceptable_patterns or 'none'}"
        )

    return False


def assert_rules_fired(
    stats: "OptimizationStatistics",
    required_rules: list[str],
    expected_rules: Optional[list[str]] = None,
    forbidden_rules: Optional[list[str]] = None,
    function_name: Optional[str] = None,
) -> None:
    """Assert that the correct rules fired during optimization.

    Args:
        stats: The optimization statistics to check.
        required_rules: Rules that MUST have fired (failure if missing).
        expected_rules: Rules that SHOULD have fired (warning if missing).
        forbidden_rules: Rules that MUST NOT have fired (failure if present).
        function_name: Optional function name for filtering stats.

    Raises:
        AssertionError: If required/forbidden rule constraints are violated.
    """
    # Get the set of rules that actually fired
    fired_rules = _get_fired_rules(stats, function_name)

    # Check required rules
    if required_rules:
        missing = [r for r in required_rules if r not in fired_rules]
        if missing:
            raise AssertionError(
                f"Required rules did not fire:\n"
                f"  Missing: {missing}\n"
                f"  Fired: {sorted(fired_rules)}"
            )

    # Check forbidden rules
    if forbidden_rules:
        forbidden_fired = [r for r in forbidden_rules if r in fired_rules]
        if forbidden_fired:
            raise AssertionError(
                f"Forbidden rules fired:\n"
                f"  Forbidden: {forbidden_fired}\n"
                f"  All fired: {sorted(fired_rules)}"
            )

    # Check expected rules (warning only, not failure)
    if expected_rules:
        missing = [r for r in expected_rules if r not in fired_rules]
        if missing:
            import warnings

            warnings.warn(
                f"Expected rules did not fire (non-fatal): {missing}",
                UserWarning,
                stacklevel=2,
            )


def assert_code_changed(before: str, after: str) -> None:
    """Assert that deobfuscation changed the code.

    Args:
        before: Code before deobfuscation.
        after: Code after deobfuscation.

    Raises:
        AssertionError: If the code is identical.
    """
    if before == after:
        raise AssertionError(
            f"Deobfuscation did not change the code:\n{_indent(before)}"
        )


def assert_operator_complexity(
    before: str,
    after: str,
    mode: str,
    operators: Optional[list[str]] = None,
    context: str = "code",
) -> None:
    """Assert operator-count complexity trends between before/after code.

    Theory and purpose:
        This assertion treats operator density as a lightweight proxy for
        expression complexity in decompiled pseudocode. In practice, many
        deobfuscation transforms reduce algebraic noise by collapsing
        multi-operator MBA expressions into simpler canonical forms. When that
        happens, the total count of selected operators should decrease or at
        least not increase.

        This is intentionally weaker than AST semantic equivalence:
        - AST equivalence answers "is it the same meaning?"
        - operator complexity answers "did we simplify the surface shape?"

        The two are complementary. A transform can preserve semantics while
        still making the output harder to read (complexity increase), and this
        helper catches that class of regression when a case opts in.

    Recommended usage:
        - Use for cases where readability/simplification is a product goal.
        - Configure per case (do not enforce globally).
        - Prefer ``mode="non_increase"`` unless strict reduction is a stable
          invariant for that function/profile.
        - Choose an operator set that matches the target family
          (e.g. MBA: ``+ - * ^ & |``).

    Limits:
        - This is lexical counting, not full symbolic complexity.
        - Equivalent rewrites can move complexity across operators.
        - Different decompiler versions can alter formatting/tokenization.
        - Therefore this should be used as a targeted guardrail, not as a sole
          correctness oracle.

    Args:
        before: Code before deobfuscation.
        after: Code after deobfuscation.
        mode: One of:
            - "decrease": after count must be strictly lower.
            - "non_increase": after count must be <= before.
        operators: Operators to count. Defaults to ["+", "-", "*"].
        context: Description for error messages.

    Raises:
        AssertionError: If complexity trend does not match mode.
        ValueError: If mode is unsupported.
    """
    ops = operators or ["+", "-", "*"]
    before_count = sum(before.count(op) for op in ops)
    after_count = sum(after.count(op) for op in ops)

    if mode == "decrease":
        if after_count >= before_count:
            raise AssertionError(
                f"Operator complexity did not decrease in {context}:\n"
                f"  Operators: {ops}\n"
                f"  Before: {before_count}\n"
                f"  After: {after_count}"
            )
        return

    if mode == "non_increase":
        if after_count > before_count:
            raise AssertionError(
                f"Operator complexity increased in {context}:\n"
                f"  Operators: {ops}\n"
                f"  Before: {before_count}\n"
                f"  After: {after_count}"
            )
        return

    raise ValueError(
        f"Unsupported operator complexity mode '{mode}'. "
        "Expected 'decrease' or 'non_increase'."
    )


def _get_fired_rules(
    stats: "OptimizationStatistics",
    function_name: Optional[str] = None,
) -> set[str]:
    """Extract the set of rule names that fired from statistics.

    Args:
        stats: The optimization statistics.
        function_name: Optional function name to filter by.

    Returns:
        Set of rule names that fired.
    """
    fired = set()

    # Get rule executions from stats
    if hasattr(stats, "rule_executions"):
        for execution in stats.rule_executions.values():
            if function_name and hasattr(execution, "function_name"):
                if execution.function_name != function_name:
                    continue
            if hasattr(execution, "rule_name"):
                fired.add(execution.rule_name)

    # Alternative: check summary dict
    if hasattr(stats, "to_dict"):
        summary = stats.to_dict()
        if "rules_fired" in summary:
            fired.update(summary["rules_fired"].keys())
        # CFG rules are tracked in cfg_rule_usages
        if "cfg_rule_usages" in summary:
            fired.update(summary["cfg_rule_usages"].keys())

    return fired


def _indent(text: str, prefix: str = "    ") -> str:
    """Indent each line of text."""
    lines = text.split("\n")
    return "\n".join(prefix + line for line in lines)
