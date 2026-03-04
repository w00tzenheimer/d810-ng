"""Tests for flow profile classification and dispatch pattern detection.

This module tests the FlowProfileClassifier service, which classifies
control-flow flattening patterns based on aggregated flow statistics.
"""

from __future__ import annotations

import pytest

from d810.recon.flow.profile_classifier import (
    ClassificationResult,
    DispatchPattern,
    FlowProfile,
    FlowProfileClassifier,
)


class TestFlowProfile:
    """Test FlowProfile dataclass validation."""

    def test_valid_profile(self) -> None:
        """Valid profile should construct without errors."""
        profile = FlowProfile(
            total_blocks=20,
            dispatch_region_size=3,
            case_block_count=17,
            compare_chain_length=10,
            state_alias_count=2,
            dispatch_table_size=10,
            has_default_target=True,
            max_block_successors=2,
        )
        assert profile.total_blocks == 20
        assert profile.dispatch_region_size == 3
        assert profile.case_block_count == 17
        assert profile.compare_chain_length == 10
        assert profile.state_alias_count == 2
        assert profile.dispatch_table_size == 10
        assert profile.has_default_target is True
        assert profile.max_block_successors == 2

    @pytest.mark.parametrize(
        "field_index, field_name",
        [
            (0, "total_blocks"),
            (1, "dispatch_region_size"),
            (2, "case_block_count"),
            (3, "compare_chain_length"),
            (4, "state_alias_count"),
            (5, "dispatch_table_size"),
            (7, "max_block_successors"),
        ],
    )
    def test_negative_field_raises(self, field_index: int, field_name: str) -> None:
        """Negative values should raise ValueError for any numeric field."""
        args = [20, 3, 17, 10, 2, 10, True, 2]
        args[field_index] = -1
        with pytest.raises(ValueError, match=f"{field_name} must be non-negative"):
            FlowProfile(*args)

    def test_zero_values_allowed(self) -> None:
        """Zero values should be allowed for all metrics."""
        profile = FlowProfile(0, 0, 0, 0, 0, 0, False, 0)
        assert profile.total_blocks == 0
        assert profile.dispatch_region_size == 0
        assert profile.compare_chain_length == 0

    def test_flow_profile_is_immutable(self) -> None:
        """FlowProfile should be immutable (frozen dataclass)."""
        profile = FlowProfile(20, 3, 17, 10, 2, 10, True, 2)
        with pytest.raises(AttributeError):
            profile.total_blocks = 99


class TestClassificationResult:
    """Test ClassificationResult dataclass validation."""

    def test_valid_result(self) -> None:
        """Valid result should construct without errors."""
        result = ClassificationResult(
            pattern=DispatchPattern.SIMPLE_COMPARE_CHAIN,
            confidence=0.95,
            recommended_strategy="compare_chain_direct",
            reasoning="Test",
        )
        assert result.pattern == DispatchPattern.SIMPLE_COMPARE_CHAIN
        assert result.confidence == 0.95
        assert result.recommended_strategy == "compare_chain_direct"
        assert result.reasoning == "Test"

    def test_confidence_out_of_range_low_raises(self) -> None:
        """Confidence < 0.0 should raise ValueError."""
        with pytest.raises(ValueError, match="confidence must be in"):
            ClassificationResult(
                pattern=DispatchPattern.UNKNOWN,
                confidence=-0.1,
                recommended_strategy="conservative",
                reasoning="Test",
            )

    def test_confidence_out_of_range_high_raises(self) -> None:
        """Confidence > 1.0 should raise ValueError."""
        with pytest.raises(ValueError, match="confidence must be in"):
            ClassificationResult(
                pattern=DispatchPattern.UNKNOWN,
                confidence=1.1,
                recommended_strategy="conservative",
                reasoning="Test",
            )

    def test_confidence_boundary_zero(self) -> None:
        """Confidence = 0.0 should be allowed."""
        result = ClassificationResult(
            pattern=DispatchPattern.UNKNOWN,
            confidence=0.0,
            recommended_strategy="conservative",
            reasoning="Test",
        )
        assert result.confidence == 0.0

    def test_confidence_boundary_one(self) -> None:
        """Confidence = 1.0 should be allowed."""
        result = ClassificationResult(
            pattern=DispatchPattern.UNKNOWN,
            confidence=1.0,
            recommended_strategy="conservative",
            reasoning="Test",
        )
        assert result.confidence == 1.0


class TestSimpleCompareChainClassification:
    """Test classification of simple compare chains (linear if-else)."""

    def test_simple_compare_chain_high_confidence(self) -> None:
        """High chain/table ratio (1.0) should classify as SIMPLE with high confidence."""
        profile = FlowProfile(
            total_blocks=20,
            dispatch_region_size=3,
            case_block_count=17,
            compare_chain_length=10,
            state_alias_count=2,
            dispatch_table_size=10,
            has_default_target=True,
            max_block_successors=2,
        )
        result = FlowProfileClassifier.classify(profile)

        assert result.pattern == DispatchPattern.SIMPLE_COMPARE_CHAIN
        assert result.confidence >= 0.9
        assert result.recommended_strategy == "compare_chain_direct"
        assert "Linear compare chain" in result.reasoning

    def test_simple_compare_chain_exact_match(self) -> None:
        """Chain length == table size should give highest confidence."""
        profile = FlowProfile(
            total_blocks=25,
            dispatch_region_size=4,
            case_block_count=21,
            compare_chain_length=15,
            state_alias_count=3,
            dispatch_table_size=15,
            has_default_target=True,
            max_block_successors=2,
        )
        result = FlowProfileClassifier.classify(profile)

        assert result.pattern == DispatchPattern.SIMPLE_COMPARE_CHAIN
        assert result.confidence == 1.0
        assert result.recommended_strategy == "compare_chain_direct"

    def test_simple_compare_chain_threshold(self) -> None:
        """Chain/table ratio at 0.8 threshold should classify as SIMPLE."""
        profile = FlowProfile(
            total_blocks=20,
            dispatch_region_size=3,
            case_block_count=17,
            compare_chain_length=8,
            state_alias_count=2,
            dispatch_table_size=10,
            has_default_target=True,
            max_block_successors=2,
        )
        result = FlowProfileClassifier.classify(profile)

        assert result.pattern == DispatchPattern.SIMPLE_COMPARE_CHAIN
        assert result.confidence >= 0.8
        assert result.recommended_strategy == "compare_chain_direct"

    def test_simple_compare_chain_single_entry(self) -> None:
        """Single dispatch entry should classify correctly."""
        profile = FlowProfile(
            total_blocks=5,
            dispatch_region_size=2,
            case_block_count=3,
            compare_chain_length=1,
            state_alias_count=1,
            dispatch_table_size=1,
            has_default_target=True,
            max_block_successors=2,
        )
        result = FlowProfileClassifier.classify(profile)

        assert result.pattern == DispatchPattern.SIMPLE_COMPARE_CHAIN
        assert result.confidence == 1.0


class TestNestedCompareTreeClassification:
    """Test classification of nested compare trees (binary search)."""

    def test_nested_compare_tree(self) -> None:
        """Low chain/table ratio (< 0.5) should classify as NESTED_COMPARE_TREE."""
        profile = FlowProfile(
            total_blocks=20,
            dispatch_region_size=3,
            case_block_count=17,
            compare_chain_length=4,
            state_alias_count=2,
            dispatch_table_size=10,
            has_default_target=True,
            max_block_successors=2,
        )
        result = FlowProfileClassifier.classify(profile)

        assert result.pattern == DispatchPattern.NESTED_COMPARE_TREE
        assert result.confidence >= 0.7
        assert result.recommended_strategy == "symbolic_execution"
        assert "Nested compare tree" in result.reasoning

    def test_nested_compare_tree_very_low_ratio(self) -> None:
        """Very low chain/table ratio should give higher confidence."""
        profile = FlowProfile(
            total_blocks=30,
            dispatch_region_size=5,
            case_block_count=25,
            compare_chain_length=2,
            state_alias_count=3,
            dispatch_table_size=20,
            has_default_target=True,
            max_block_successors=2,
        )
        result = FlowProfileClassifier.classify(profile)

        assert result.pattern == DispatchPattern.NESTED_COMPARE_TREE
        # Ratio = 2/20 = 0.1, confidence = 0.7 + (0.5 - 0.1) * 0.4 = 0.86
        assert result.confidence >= 0.85
        assert result.recommended_strategy == "symbolic_execution"

    def test_nested_compare_tree_threshold(self) -> None:
        """Chain/table ratio just below 0.5 should classify as NESTED."""
        profile = FlowProfile(
            total_blocks=20,
            dispatch_region_size=3,
            case_block_count=17,
            compare_chain_length=4,
            state_alias_count=2,
            dispatch_table_size=9,
            has_default_target=True,
            max_block_successors=2,
        )
        result = FlowProfileClassifier.classify(profile)

        assert result.pattern == DispatchPattern.NESTED_COMPARE_TREE
        assert result.recommended_strategy == "symbolic_execution"


class TestSwitchTableClassification:
    """Test classification of switch tables (computed jumps)."""

    def test_switch_table(self) -> None:
        """High fan-out + small dispatch region should classify as SWITCH_TABLE."""
        profile = FlowProfile(
            total_blocks=20,
            dispatch_region_size=2,
            case_block_count=18,
            compare_chain_length=0,
            state_alias_count=1,
            dispatch_table_size=10,
            has_default_target=True,
            max_block_successors=10,
        )
        result = FlowProfileClassifier.classify(profile)

        assert result.pattern == DispatchPattern.SWITCH_TABLE
        assert result.confidence >= 0.7
        assert result.recommended_strategy == "switch_reconstruction"
        assert "Switch table" in result.reasoning

    def test_switch_table_high_fan_out(self) -> None:
        """Very high fan-out should increase confidence."""
        profile = FlowProfile(
            total_blocks=50,
            dispatch_region_size=3,
            case_block_count=47,
            compare_chain_length=0,
            state_alias_count=1,
            dispatch_table_size=20,
            has_default_target=True,
            max_block_successors=20,
        )
        result = FlowProfileClassifier.classify(profile)

        assert result.pattern == DispatchPattern.SWITCH_TABLE
        assert result.confidence >= 0.9
        assert result.recommended_strategy == "switch_reconstruction"

    def test_switch_table_threshold_region_size(self) -> None:
        """Dispatch region size <= 3 is required for SWITCH_TABLE."""
        profile = FlowProfile(
            total_blocks=20,
            dispatch_region_size=3,
            case_block_count=17,
            compare_chain_length=0,
            state_alias_count=1,
            dispatch_table_size=10,
            has_default_target=True,
            max_block_successors=5,
        )
        result = FlowProfileClassifier.classify(profile)

        assert result.pattern == DispatchPattern.SWITCH_TABLE

    def test_switch_table_region_too_large(self) -> None:
        """Dispatch region size > 3 should NOT classify as SWITCH_TABLE."""
        profile = FlowProfile(
            total_blocks=20,
            dispatch_region_size=4,
            case_block_count=16,
            compare_chain_length=0,
            state_alias_count=1,
            dispatch_table_size=10,
            has_default_target=True,
            max_block_successors=10,
        )
        result = FlowProfileClassifier.classify(profile)

        # Should classify as MIXED_DISPATCH instead
        assert result.pattern == DispatchPattern.MIXED_DISPATCH


class TestMixedDispatchClassification:
    """Test classification of mixed dispatch patterns."""

    def test_mixed_dispatch(self) -> None:
        """High fan-out + large dispatch region should classify as MIXED."""
        profile = FlowProfile(
            total_blocks=30,
            dispatch_region_size=5,
            case_block_count=25,
            compare_chain_length=8,
            state_alias_count=3,
            dispatch_table_size=12,
            has_default_target=True,
            max_block_successors=5,
        )
        result = FlowProfileClassifier.classify(profile)

        assert result.pattern == DispatchPattern.MIXED_DISPATCH
        assert result.confidence == 0.7
        assert result.recommended_strategy == "hybrid"
        assert "Mixed dispatch" in result.reasoning

    def test_mixed_dispatch_high_fan_out_only(self) -> None:
        """High fan-out alone (without small region) triggers MIXED."""
        profile = FlowProfile(
            total_blocks=20,
            dispatch_region_size=10,
            case_block_count=10,
            compare_chain_length=5,
            state_alias_count=2,
            dispatch_table_size=8,
            has_default_target=True,
            max_block_successors=4,
        )
        result = FlowProfileClassifier.classify(profile)

        assert result.pattern == DispatchPattern.MIXED_DISPATCH
        assert result.recommended_strategy == "hybrid"


class TestUnknownPatternClassification:
    """Test classification of unknown/unrecognized patterns."""

    def test_unknown_no_dispatch_table(self) -> None:
        """No dispatch table should classify as UNKNOWN."""
        profile = FlowProfile(
            total_blocks=20,
            dispatch_region_size=3,
            case_block_count=17,
            compare_chain_length=0,
            state_alias_count=2,
            dispatch_table_size=0,
            has_default_target=False,
            max_block_successors=2,
        )
        result = FlowProfileClassifier.classify(profile)

        assert result.pattern == DispatchPattern.UNKNOWN
        assert result.confidence == 1.0
        assert result.recommended_strategy == "conservative"
        assert "No dispatch table" in result.reasoning

    def test_unknown_no_dispatch_region(self) -> None:
        """No dispatch region should classify as UNKNOWN."""
        profile = FlowProfile(
            total_blocks=20,
            dispatch_region_size=0,
            case_block_count=20,
            compare_chain_length=5,
            state_alias_count=2,
            dispatch_table_size=5,
            has_default_target=True,
            max_block_successors=2,
        )
        result = FlowProfileClassifier.classify(profile)

        assert result.pattern == DispatchPattern.UNKNOWN
        assert result.confidence == 1.0
        assert result.recommended_strategy == "conservative"
        assert "No dispatch region" in result.reasoning

    def test_unknown_both_missing(self) -> None:
        """Both missing should classify as UNKNOWN."""
        profile = FlowProfile(
            total_blocks=20,
            dispatch_region_size=0,
            case_block_count=20,
            compare_chain_length=0,
            state_alias_count=0,
            dispatch_table_size=0,
            has_default_target=False,
            max_block_successors=2,
        )
        result = FlowProfileClassifier.classify(profile)

        assert result.pattern == DispatchPattern.UNKNOWN
        assert result.recommended_strategy == "conservative"


class TestAmbiguousClassification:
    """Test classification when pattern is ambiguous (mid-range ratios)."""

    def test_ambiguous_mid_range_ratio(self) -> None:
        """Chain/table ratio in [0.5, 0.8) should have lower confidence."""
        profile = FlowProfile(
            total_blocks=20,
            dispatch_region_size=3,
            case_block_count=17,
            compare_chain_length=6,
            state_alias_count=2,
            dispatch_table_size=10,
            has_default_target=True,
            max_block_successors=2,
        )
        result = FlowProfileClassifier.classify(profile)

        # Ratio = 6/10 = 0.6, falls in ambiguous range
        assert result.pattern == DispatchPattern.SIMPLE_COMPARE_CHAIN
        assert result.confidence == 0.5
        assert result.recommended_strategy == "compare_chain_direct"
        assert "Ambiguous" in result.reasoning

    def test_ambiguous_exactly_at_boundary(self) -> None:
        """Ratio exactly at 0.5 should be ambiguous."""
        profile = FlowProfile(
            total_blocks=20,
            dispatch_region_size=3,
            case_block_count=17,
            compare_chain_length=5,
            state_alias_count=2,
            dispatch_table_size=10,
            has_default_target=True,
            max_block_successors=2,
        )
        result = FlowProfileClassifier.classify(profile)

        # Ratio = 5/10 = 0.5, at boundary
        assert result.confidence == 0.5


class TestStrategyRecommendation:
    """Test strategy recommendation for each pattern."""

    def test_recommend_strategy_simple(self) -> None:
        """SIMPLE_COMPARE_CHAIN should recommend compare_chain_direct."""
        result = ClassificationResult(
            pattern=DispatchPattern.SIMPLE_COMPARE_CHAIN,
            confidence=0.9,
            recommended_strategy="compare_chain_direct",
            reasoning="Test",
        )
        strategy = FlowProfileClassifier.recommend_strategy(result)
        assert strategy == "compare_chain_direct"

    def test_recommend_strategy_nested(self) -> None:
        """NESTED_COMPARE_TREE should recommend symbolic_execution."""
        result = ClassificationResult(
            pattern=DispatchPattern.NESTED_COMPARE_TREE,
            confidence=0.8,
            recommended_strategy="symbolic_execution",
            reasoning="Test",
        )
        strategy = FlowProfileClassifier.recommend_strategy(result)
        assert strategy == "symbolic_execution"

    def test_recommend_strategy_switch(self) -> None:
        """SWITCH_TABLE should recommend switch_reconstruction."""
        result = ClassificationResult(
            pattern=DispatchPattern.SWITCH_TABLE,
            confidence=0.9,
            recommended_strategy="switch_reconstruction",
            reasoning="Test",
        )
        strategy = FlowProfileClassifier.recommend_strategy(result)
        assert strategy == "switch_reconstruction"

    def test_recommend_strategy_mixed(self) -> None:
        """MIXED_DISPATCH should recommend hybrid."""
        result = ClassificationResult(
            pattern=DispatchPattern.MIXED_DISPATCH,
            confidence=0.7,
            recommended_strategy="hybrid",
            reasoning="Test",
        )
        strategy = FlowProfileClassifier.recommend_strategy(result)
        assert strategy == "hybrid"

    def test_recommend_strategy_unknown(self) -> None:
        """UNKNOWN should recommend conservative."""
        result = ClassificationResult(
            pattern=DispatchPattern.UNKNOWN,
            confidence=1.0,
            recommended_strategy="conservative",
            reasoning="Test",
        )
        strategy = FlowProfileClassifier.recommend_strategy(result)
        assert strategy == "conservative"


class TestFromComponents:
    """Test from_components convenience method."""

    def test_from_components_simple_chain(self) -> None:
        """from_components should build profile and classify correctly."""
        adj = {0: (1, 2), 1: (0,), 2: (0,), 3: (4,), 4: ()}
        dispatch_region = frozenset({0, 1, 2})
        case_blocks = frozenset({3, 4})

        result = FlowProfileClassifier.from_components(
            dispatch_region=dispatch_region,
            case_blocks=case_blocks,
            dispatch_table_size=2,
            compare_chain_length=2,
            state_alias_count=1,
            has_default=True,
            adj=adj,
        )

        assert result.pattern == DispatchPattern.SIMPLE_COMPARE_CHAIN
        assert result.recommended_strategy == "compare_chain_direct"

    def test_from_components_switch_table(self) -> None:
        """from_components with high fan-out should detect SWITCH_TABLE."""
        adj = {0: (1, 2, 3, 4, 5), 1: (), 2: (), 3: (), 4: (), 5: ()}
        dispatch_region = frozenset({0})
        case_blocks = frozenset({1, 2, 3, 4, 5})

        result = FlowProfileClassifier.from_components(
            dispatch_region=dispatch_region,
            case_blocks=case_blocks,
            dispatch_table_size=5,
            compare_chain_length=0,
            state_alias_count=1,
            has_default=False,
            adj=adj,
        )

        assert result.pattern == DispatchPattern.SWITCH_TABLE

    def test_from_components_empty_adj(self) -> None:
        """from_components with empty adjacency should handle gracefully."""
        adj = {}
        dispatch_region = frozenset()
        case_blocks = frozenset()

        result = FlowProfileClassifier.from_components(
            dispatch_region=dispatch_region,
            case_blocks=case_blocks,
            dispatch_table_size=0,
            compare_chain_length=0,
            state_alias_count=0,
            has_default=False,
            adj=adj,
        )

        assert result.pattern == DispatchPattern.UNKNOWN

    def test_from_components_computes_max_successors(self) -> None:
        """from_components should compute max_block_successors correctly."""
        adj = {0: (1, 2), 1: (3,), 2: (3,), 3: (4, 5, 6), 4: (), 5: (), 6: ()}
        dispatch_region = frozenset({0, 1, 2})
        case_blocks = frozenset({3, 4, 5, 6})

        result = FlowProfileClassifier.from_components(
            dispatch_region=dispatch_region,
            case_blocks=case_blocks,
            dispatch_table_size=3,
            compare_chain_length=2,
            state_alias_count=1,
            has_default=True,
            adj=adj,
        )

        # max_successors should be 3 (from block 3)
        # region_size=3 (at boundary), so SWITCH_TABLE (since <= 3)
        assert result.pattern == DispatchPattern.SWITCH_TABLE


class TestLargeDispatchTable:
    """Test classification with large dispatch tables (50+ entries)."""

    def test_large_simple_compare_chain(self) -> None:
        """Large simple compare chain (50 entries) should classify correctly."""
        profile = FlowProfile(
            total_blocks=100,
            dispatch_region_size=5,
            case_block_count=95,
            compare_chain_length=50,
            state_alias_count=3,
            dispatch_table_size=50,
            has_default_target=True,
            max_block_successors=2,
        )
        result = FlowProfileClassifier.classify(profile)

        assert result.pattern == DispatchPattern.SIMPLE_COMPARE_CHAIN
        assert result.confidence == 1.0

    def test_large_nested_tree(self) -> None:
        """Large nested tree (100 entries) should classify correctly."""
        profile = FlowProfile(
            total_blocks=200,
            dispatch_region_size=10,
            case_block_count=190,
            compare_chain_length=20,
            state_alias_count=5,
            dispatch_table_size=100,
            has_default_target=True,
            max_block_successors=2,
        )
        result = FlowProfileClassifier.classify(profile)

        assert result.pattern == DispatchPattern.NESTED_COMPARE_TREE
        assert result.recommended_strategy == "symbolic_execution"


class TestZeroCaseBlocks:
    """Test classification when case_block_count is zero."""

    def test_zero_case_blocks(self) -> None:
        """Zero case blocks should still allow classification."""
        profile = FlowProfile(
            total_blocks=5,
            dispatch_region_size=5,
            case_block_count=0,
            compare_chain_length=3,
            state_alias_count=1,
            dispatch_table_size=3,
            has_default_target=True,
            max_block_successors=2,
        )
        result = FlowProfileClassifier.classify(profile)

        # Should still classify based on other metrics
        assert result.pattern == DispatchPattern.SIMPLE_COMPARE_CHAIN
        assert result.confidence == 1.0


class TestBoundaryConditions:
    """Test boundary conditions between patterns."""

    def test_boundary_simple_to_ambiguous(self) -> None:
        """Chain/table ratio just below 0.8 should be ambiguous."""
        profile = FlowProfile(
            total_blocks=20,
            dispatch_region_size=3,
            case_block_count=17,
            compare_chain_length=7,
            state_alias_count=2,
            dispatch_table_size=10,
            has_default_target=True,
            max_block_successors=2,
        )
        result = FlowProfileClassifier.classify(profile)

        # Ratio = 7/10 = 0.7, in ambiguous range [0.5, 0.8)
        assert result.pattern == DispatchPattern.SIMPLE_COMPARE_CHAIN
        assert result.confidence == 0.5

    def test_boundary_nested_to_ambiguous(self) -> None:
        """Chain/table ratio just above 0.5 should be ambiguous."""
        profile = FlowProfile(
            total_blocks=20,
            dispatch_region_size=3,
            case_block_count=17,
            compare_chain_length=6,
            state_alias_count=2,
            dispatch_table_size=10,
            has_default_target=True,
            max_block_successors=2,
        )
        result = FlowProfileClassifier.classify(profile)

        # Ratio = 6/10 = 0.6, in ambiguous range [0.5, 0.8)
        assert result.confidence == 0.5

    def test_boundary_switch_to_mixed_fan_out(self) -> None:
        """Max successors > 2 should affect classification."""
        # With small region, should be SWITCH
        profile_switch = FlowProfile(
            total_blocks=20,
            dispatch_region_size=2,
            case_block_count=18,
            compare_chain_length=0,
            state_alias_count=1,
            dispatch_table_size=10,
            has_default_target=True,
            max_block_successors=3,
        )
        result_switch = FlowProfileClassifier.classify(profile_switch)
        assert result_switch.pattern == DispatchPattern.SWITCH_TABLE

        # With large region, should be MIXED
        profile_mixed = FlowProfile(
            total_blocks=20,
            dispatch_region_size=5,
            case_block_count=15,
            compare_chain_length=0,
            state_alias_count=1,
            dispatch_table_size=10,
            has_default_target=True,
            max_block_successors=3,
        )
        result_mixed = FlowProfileClassifier.classify(profile_mixed)
        assert result_mixed.pattern == DispatchPattern.MIXED_DISPATCH
