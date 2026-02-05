"""Tests for MBA rule relationship analysis using e-graphs.

This module tests the rule analysis utilities that detect:
1. Equivalent rules (same pattern, different syntax)
2. Inverse rules (applying one then the other creates a cycle)
"""

import pytest

# Check if egglog is available
try:
    from d810.mba.backends.egglog_backend import check_egglog_available, PatternExpr
    EGGLOG_AVAILABLE = check_egglog_available()
except ImportError:
    EGGLOG_AVAILABLE = False

pytestmark = pytest.mark.skipif(not EGGLOG_AVAILABLE, reason="egglog not installed")


class TestSymbolicExprToPatternExpr:
    """Tests for converting SymbolicExpression to PatternExpr."""

    def test_convert_variable(self):
        """Test converting a simple variable."""
        from d810.mba.dsl import Var
        from d810.mba.rule_analysis import _symbolic_expr_to_pattern_expr

        x = Var("x_0")
        result = _symbolic_expr_to_pattern_expr(x)

        assert result is not None
        # PatternExpr should be created

    def test_convert_binary_op(self):
        """Test converting a binary operation."""
        from d810.mba.dsl import Var
        from d810.mba.rule_analysis import _symbolic_expr_to_pattern_expr

        x, y = Var("x_0"), Var("x_1")
        expr = x + y

        result = _symbolic_expr_to_pattern_expr(expr)
        assert result is not None

    def test_convert_xor_bnot(self):
        """Test converting x ^ ~y pattern (BnotXor)."""
        from d810.mba.dsl import Var
        from d810.mba.rule_analysis import _symbolic_expr_to_pattern_expr

        x, y = Var("x_0"), Var("x_1")
        expr = x ^ ~y

        result = _symbolic_expr_to_pattern_expr(expr)
        assert result is not None

    def test_convert_bnot_xor(self):
        """Test converting ~(x ^ y) pattern."""
        from d810.mba.dsl import Var
        from d810.mba.rule_analysis import _symbolic_expr_to_pattern_expr

        x, y = Var("x_0"), Var("x_1")
        expr = ~(x ^ y)

        result = _symbolic_expr_to_pattern_expr(expr)
        assert result is not None

    def test_shared_var_cache(self):
        """Test that variable cache is shared correctly."""
        from d810.mba.dsl import Var
        from d810.mba.rule_analysis import _symbolic_expr_to_pattern_expr

        x = Var("x_0")
        expr = x + x  # Same variable used twice

        var_cache = {}
        result = _symbolic_expr_to_pattern_expr(expr, var_cache)

        assert result is not None
        assert "x_0" in var_cache


class TestCheckRulesEquivalent:
    """Tests for checking if two rules have equivalent patterns."""

    def test_pred0_and_predodd_equivalent(self):
        """Test that Pred0Rule1 and PredOdd1 have equivalent patterns.

        Both rules match: (x * (x - 1)) & 1
        """
        from d810.mba.rules.predicates import Pred0Rule1, PredOdd1
        from d810.mba.rule_analysis import check_rules_equivalent

        rule1 = Pred0Rule1()
        rule2 = PredOdd1()

        # Both have the same pattern: (x * (x - 1)) & 1
        result = check_rules_equivalent(rule1, rule2)
        assert result is True, "Pred0Rule1 and PredOdd1 should have equivalent patterns"

    def test_different_patterns_not_equivalent(self):
        """Test that rules with different patterns are not equivalent."""
        from d810.mba.rules.predicates import Pred0Rule1, Pred0Rule2
        from d810.mba.rule_analysis import check_rules_equivalent

        rule1 = Pred0Rule1()  # (x * (x - 1)) & 1
        rule2 = Pred0Rule2()  # (x * (x + 1)) & 1

        result = check_rules_equivalent(rule1, rule2)
        assert result is False, "Different patterns should not be equivalent"


class TestCheckInverseRules:
    """Tests for detecting inverse rule pairs."""

    def test_bnotxor_and_cstsimp16_inverse(self):
        """Test that BnotXor_FactorRule_1 and CstSimplificationRule16 are inverses.

        BnotXor_FactorRule_1: x ^ ~y => ~(x ^ y)
        CstSimplificationRule16: ~(x ^ c_1) => x ^ ~c_1

        These are inverses in the direction:
        - CstSimpl16.PATTERN ~ BnotXor.REPLACEMENT
        - i.e., ~(x ^ c_1) matches ~(x ^ y) structurally

        Note: The opposite direction (BnotXor.PATTERN ~ CstSimpl16.REPLACEMENT)
        does NOT match because CstSimpl16 uses a variable `bnot_c_1` (not an
        expression `~c_1`) in its replacement, so `x ^ bnot_c_1` is NOT
        structurally equivalent to `x ^ ~y`.

        However, we can still detect they form a cycle via the PATTERN -> REPLACEMENT
        relationship in one direction.
        """
        from d810.mba.rules.bnot import BnotXor_FactorRule_1
        from d810.mba.rules.cst import CstSimplificationRule16
        from d810.mba.rule_analysis import check_inverse_rules

        bnotxor = BnotXor_FactorRule_1()
        cstsimp = CstSimplificationRule16()

        # CstSimpl16.PATTERN ~ BnotXor.REPLACEMENT
        # This is the direction that matches structurally:
        # ~(x ^ c_1) ~ ~(x ^ y) after positional normalization
        result = check_inverse_rules(cstsimp, bnotxor)
        assert result is True, "CstSimpl16 pattern should match BnotXor replacement"

    def test_cstsimp16_pattern_vs_bnotxor_replacement(self):
        """Test that CstSimpl16.PATTERN ~ BnotXor.REPLACEMENT.

        CstSimplificationRule16: ~(x ^ c_1) => x ^ ~c_1
        BnotXor_FactorRule_1: x ^ ~y => ~(x ^ y)

        - CstSimpl16 pattern: ~(x ^ c_1)
        - BnotXor replacement: ~(x ^ y)
        These are structurally equivalent (both are "NOT (var XOR var)")
        """
        from d810.mba.rules.bnot import BnotXor_FactorRule_1
        from d810.mba.rules.cst import CstSimplificationRule16
        from d810.mba.rule_analysis import check_inverse_rules

        bnotxor = BnotXor_FactorRule_1()
        cstsimp = CstSimplificationRule16()

        # CstSimpl16.PATTERN ~ BnotXor.REPLACEMENT
        result = check_inverse_rules(cstsimp, bnotxor)
        assert result is True, "CstSimpl16 pattern should match BnotXor replacement"

    def test_non_inverse_rules(self):
        """Test that unrelated rules are not detected as inverses."""
        from d810.mba.rules.predicates import Pred0Rule1, Pred0Rule3
        from d810.mba.rule_analysis import check_inverse_rules

        rule1 = Pred0Rule1()  # (x * (x - 1)) & 1 => 0
        rule2 = Pred0Rule3()  # x & ~x => 0

        # These are not inverses
        result = check_inverse_rules(rule1, rule2)
        assert result is False, "Unrelated rules should not be inverses"


class TestFindInversePairs:
    """Tests for finding all inverse pairs in a rule set."""

    def test_find_bnotxor_cstsimp_pair(self):
        """Test that find_inverse_rule_pairs detects BnotXor/CstSimpl16."""
        from d810.mba.rules.bnot import BnotXor_FactorRule_1
        from d810.mba.rules.cst import CstSimplificationRule16
        from d810.mba.rule_analysis import find_inverse_rule_pairs

        rules = [BnotXor_FactorRule_1(), CstSimplificationRule16()]
        pairs = find_inverse_rule_pairs(rules)

        # Should find both directions
        assert len(pairs) >= 1, "Should find at least one inverse pair"

        # Check that the pair is found
        names = [(r1.name, r2.name) for r1, r2 in pairs]
        assert any(
            ("BnotXor_FactorRule_1" in n1 and "CstSimplificationRule16" in n2) or
            ("CstSimplificationRule16" in n1 and "BnotXor_FactorRule_1" in n2)
            for n1, n2 in names
        ), f"Should find BnotXor/CstSimpl pair, found: {names}"


class TestFindEquivalentPatterns:
    """Tests for finding rules with equivalent patterns."""

    def test_find_pred0_predodd_equivalent(self):
        """Test that find_equivalent_rule_patterns finds Pred0Rule1/PredOdd1."""
        from d810.mba.rules.predicates import Pred0Rule1, PredOdd1
        from d810.mba.rule_analysis import find_equivalent_rule_patterns

        rules = [Pred0Rule1(), PredOdd1()]
        pairs = find_equivalent_rule_patterns(rules)

        assert len(pairs) == 1, f"Should find exactly one equivalent pair, found {len(pairs)}"

        rule1, rule2 = pairs[0]
        names = {rule1.name, rule2.name}
        assert names == {"Pred0Rule1", "PredOdd1"}, f"Expected Pred0Rule1/PredOdd1, got {names}"


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_rule_without_pattern(self):
        """Test handling of rules without PATTERN defined."""
        from d810.mba.rules._base import VerifiableRule
        from d810.mba.rule_analysis import check_rules_equivalent

        class RuleWithoutPattern(VerifiableRule):
            """A test rule without PATTERN."""
            pass

        class RuleWithoutPattern2(VerifiableRule):
            """Another test rule without PATTERN."""
            pass

        # Should return False gracefully, not crash
        rule1 = RuleWithoutPattern()
        rule2 = RuleWithoutPattern2()

        result = check_rules_equivalent(rule1, rule2)
        assert result is False

    def test_none_expression(self):
        """Test that None expressions are handled gracefully."""
        from d810.mba.rule_analysis import _symbolic_expr_to_pattern_expr

        result = _symbolic_expr_to_pattern_expr(None)
        assert result is None
