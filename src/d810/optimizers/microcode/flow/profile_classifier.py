"""Flow profile classification for dispatch pattern selection.

This module implements classification of control-flow flattening patterns
to select appropriate unflattening strategies. Based on cadecff's strategy
selection logic, it analyzes aggregated flow statistics to identify dispatch
patterns and recommend the optimal resolution approach.

Key insight from cadecff integration plan:
    Flow-level statistics (SCC size, compare chain length, dispatch table
    size, max successors) characterize the dispatch pattern and drive
    strategy selection: simple compare chains use direct resolution, nested
    trees use symbolic execution, switch tables use table reconstruction.

Usage:
    profile = FlowProfile(
        total_blocks=100,
        dispatch_region_size=5,
        case_block_count=95,
        compare_chain_length=10,
        state_alias_count=3,
        dispatch_table_size=12,
        has_default_target=True,
        max_block_successors=2,
    )
    result = FlowProfileClassifier.classify(profile)
    # result.pattern = DispatchPattern.SIMPLE_COMPARE_CHAIN
    # result.recommended_strategy = "compare_chain_direct"

References:
    - CaDeCFF strategy selection: ~/src/idapro/cadecff/src/cadecff/analysis.py
    - CaDeCFF integration plan: docs/plans/CaDeCFF-Integration.md section 3.5
"""

from __future__ import annotations

import enum
from dataclasses import dataclass

__all__ = [
    "DispatchPattern",
    "FlowProfile",
    "ClassificationResult",
    "FlowProfileClassifier",
]


class DispatchPattern(enum.Enum):
    """Recognized dispatch patterns in flattened code.

    These patterns determine which unflattening strategy to use.
    """

    SIMPLE_COMPARE_CHAIN = "simple_compare_chain"  # Linear if-else chain
    NESTED_COMPARE_TREE = "nested_compare_tree"  # Binary search tree
    SWITCH_TABLE = "switch_table"  # Computed jump table
    MIXED_DISPATCH = "mixed_dispatch"  # Combination of patterns
    UNKNOWN = "unknown"  # Cannot classify


@dataclass(frozen=True)
class FlowProfile:
    """Aggregated statistics about a function's control flow.

    These metrics characterize the dispatch pattern and enable classification
    without requiring deep symbolic execution or pattern matching.

    Attributes:
        total_blocks: Total number of blocks in the function
        dispatch_region_size: Number of blocks in SCC dispatch region
        case_block_count: Number of case/payload blocks (outside SCC)
        compare_chain_length: Length of longest compare chain
        state_alias_count: Number of state variable aliases
        dispatch_table_size: Number of entries in dispatch table
        has_default_target: Whether a default/fallthrough exists
        max_block_successors: Maximum outgoing edges from any block

    Examples:
        >>> # Simple linear compare chain
        >>> profile = FlowProfile(
        ...     total_blocks=20,
        ...     dispatch_region_size=3,
        ...     case_block_count=17,
        ...     compare_chain_length=10,
        ...     state_alias_count=2,
        ...     dispatch_table_size=10,
        ...     has_default_target=True,
        ...     max_block_successors=2,
        ... )
        >>> # Characteristics: chain_length ≈ table_size, max_successors=2
        >>> # → SIMPLE_COMPARE_CHAIN pattern
    """

    total_blocks: int
    dispatch_region_size: int
    case_block_count: int
    compare_chain_length: int
    state_alias_count: int
    dispatch_table_size: int
    has_default_target: bool
    max_block_successors: int

    def __post_init__(self) -> None:
        """Validate profile constraints."""
        if self.total_blocks < 0:
            raise ValueError("total_blocks must be non-negative")
        if self.dispatch_region_size < 0:
            raise ValueError("dispatch_region_size must be non-negative")
        if self.case_block_count < 0:
            raise ValueError("case_block_count must be non-negative")
        if self.compare_chain_length < 0:
            raise ValueError("compare_chain_length must be non-negative")
        if self.state_alias_count < 0:
            raise ValueError("state_alias_count must be non-negative")
        if self.dispatch_table_size < 0:
            raise ValueError("dispatch_table_size must be non-negative")
        if self.max_block_successors < 0:
            raise ValueError("max_block_successors must be non-negative")


@dataclass(frozen=True)
class ClassificationResult:
    """Result of classifying a function's dispatch pattern.

    Attributes:
        pattern: The identified dispatch pattern
        confidence: Classification confidence (0.0 to 1.0)
        recommended_strategy: Strategy name for the unflattener
        reasoning: Human-readable explanation of classification

    Examples:
        >>> result = ClassificationResult(
        ...     pattern=DispatchPattern.SIMPLE_COMPARE_CHAIN,
        ...     confidence=0.95,
        ...     recommended_strategy="compare_chain_direct",
        ...     reasoning="Linear compare chain with 10/10 entries",
        ... )
    """

    pattern: DispatchPattern
    confidence: float
    recommended_strategy: str
    reasoning: str

    def __post_init__(self) -> None:
        """Validate result constraints."""
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence must be in [0.0, 1.0], got {self.confidence}")


class FlowProfileClassifier:
    """Classify dispatch patterns from flow profiles.

    This service implements the cadecff strategy selection algorithm,
    using flow-level statistics to identify dispatch patterns and
    recommend unflattening strategies. Pure function, no state.

    Classification heuristics:
    - SIMPLE_COMPARE_CHAIN: Linear if-else chain with high chain/table ratio
    - NESTED_COMPARE_TREE: Binary tree structure with low chain/table ratio
    - SWITCH_TABLE: Computed jump with high fan-out and small dispatch region
    - MIXED_DISPATCH: Combination of patterns (high fan-out + large table)
    - UNKNOWN: Missing dispatch table or dispatch region

    Example:
        >>> profile = FlowProfile(
        ...     total_blocks=20,
        ...     dispatch_region_size=3,
        ...     case_block_count=17,
        ...     compare_chain_length=10,
        ...     state_alias_count=2,
        ...     dispatch_table_size=10,
        ...     has_default_target=True,
        ...     max_block_successors=2,
        ... )
        >>> result = FlowProfileClassifier.classify(profile)
        >>> result.pattern == DispatchPattern.SIMPLE_COMPARE_CHAIN
        True
        >>> result.recommended_strategy
        'compare_chain_direct'
    """

    @staticmethod
    def classify(profile: FlowProfile) -> ClassificationResult:
        """Classify a function's dispatch pattern from its flow profile.

        Classification heuristics:
        - SIMPLE_COMPARE_CHAIN: dispatch_table_size > 0 and
          compare_chain_length >= dispatch_table_size * 0.8 and
          max_block_successors <= 2
        - NESTED_COMPARE_TREE: dispatch_table_size > 0 and
          max_block_successors <= 2 and
          compare_chain_length < dispatch_table_size * 0.5
          (suggests binary tree organization)
        - SWITCH_TABLE: max_block_successors > 2 and
          dispatch_region_size <= 3
          (computed indirect jump)
        - MIXED_DISPATCH: dispatch_table_size > 0 and
          max_block_successors > 2
        - UNKNOWN: dispatch_table_size == 0 or
          dispatch_region_size == 0

        Parameters
        ----------
        profile : aggregated flow statistics

        Returns
        -------
        ClassificationResult with pattern, confidence, strategy, and reasoning

        Examples
        --------
        >>> # Simple compare chain
        >>> profile = FlowProfile(20, 3, 17, 10, 2, 10, True, 2)
        >>> result = FlowProfileClassifier.classify(profile)
        >>> result.pattern == DispatchPattern.SIMPLE_COMPARE_CHAIN
        True
        >>> result.confidence >= 0.9
        True

        >>> # Nested compare tree
        >>> profile = FlowProfile(20, 3, 17, 4, 2, 10, True, 2)
        >>> result = FlowProfileClassifier.classify(profile)
        >>> result.pattern == DispatchPattern.NESTED_COMPARE_TREE
        True

        >>> # Switch table
        >>> profile = FlowProfile(20, 2, 18, 0, 1, 10, True, 10)
        >>> result = FlowProfileClassifier.classify(profile)
        >>> result.pattern == DispatchPattern.SWITCH_TABLE
        True

        >>> # Mixed dispatch
        >>> profile = FlowProfile(20, 5, 15, 8, 3, 12, True, 5)
        >>> result = FlowProfileClassifier.classify(profile)
        >>> result.pattern == DispatchPattern.MIXED_DISPATCH
        True

        >>> # Unknown (no dispatch table)
        >>> profile = FlowProfile(20, 3, 17, 0, 2, 0, False, 2)
        >>> result = FlowProfileClassifier.classify(profile)
        >>> result.pattern == DispatchPattern.UNKNOWN
        True
        """
        # Early exit: cannot classify without dispatch table or dispatch region
        if profile.dispatch_table_size == 0:
            return ClassificationResult(
                pattern=DispatchPattern.UNKNOWN,
                confidence=1.0,
                recommended_strategy="conservative",
                reasoning="No dispatch table entries found",
            )

        if profile.dispatch_region_size == 0:
            return ClassificationResult(
                pattern=DispatchPattern.UNKNOWN,
                confidence=1.0,
                recommended_strategy="conservative",
                reasoning="No dispatch region detected (no SCC)",
            )

        # Compute ratios for classification
        chain_to_table_ratio = (
            profile.compare_chain_length / profile.dispatch_table_size
            if profile.dispatch_table_size > 0
            else 0.0
        )

        # Pattern detection (order matters: check most specific patterns first)

        # 1. SWITCH_TABLE: High fan-out, small dispatch region
        #    Suggests a computed jump table (indirect jump with many targets)
        if profile.max_block_successors > 2 and profile.dispatch_region_size <= 3:
            confidence = min(
                1.0,
                0.7 + (profile.max_block_successors / 10) * 0.2,
            )
            return ClassificationResult(
                pattern=DispatchPattern.SWITCH_TABLE,
                confidence=confidence,
                recommended_strategy="switch_reconstruction",
                reasoning=(
                    f"Switch table: max_successors={profile.max_block_successors}, "
                    f"dispatch_region_size={profile.dispatch_region_size}"
                ),
            )

        # 2. MIXED_DISPATCH: High fan-out with large dispatch table
        #    Suggests combination of compare chains and computed jumps
        if profile.max_block_successors > 2:
            confidence = 0.7
            return ClassificationResult(
                pattern=DispatchPattern.MIXED_DISPATCH,
                confidence=confidence,
                recommended_strategy="hybrid",
                reasoning=(
                    f"Mixed dispatch: max_successors={profile.max_block_successors}, "
                    f"table_size={profile.dispatch_table_size}"
                ),
            )

        # 3. SIMPLE_COMPARE_CHAIN: High chain/table ratio, low fan-out
        #    Suggests linear if-else chain (one comparison per entry)
        if chain_to_table_ratio >= 0.8:
            # High confidence if ratio is very close to 1.0 (exact match)
            confidence = min(1.0, 0.8 + (chain_to_table_ratio - 0.8) * 1.0)
            return ClassificationResult(
                pattern=DispatchPattern.SIMPLE_COMPARE_CHAIN,
                confidence=confidence,
                recommended_strategy="compare_chain_direct",
                reasoning=(
                    f"Linear compare chain: chain_length={profile.compare_chain_length}, "
                    f"table_size={profile.dispatch_table_size} "
                    f"(ratio={chain_to_table_ratio:.2f})"
                ),
            )

        # 4. NESTED_COMPARE_TREE: Low chain/table ratio, low fan-out
        #    Suggests binary search tree organization (fewer comparisons)
        if chain_to_table_ratio < 0.5:
            confidence = 0.7 + (0.5 - chain_to_table_ratio) * 0.4
            return ClassificationResult(
                pattern=DispatchPattern.NESTED_COMPARE_TREE,
                confidence=confidence,
                recommended_strategy="symbolic_execution",
                reasoning=(
                    f"Nested compare tree: chain_length={profile.compare_chain_length}, "
                    f"table_size={profile.dispatch_table_size} "
                    f"(ratio={chain_to_table_ratio:.2f})"
                ),
            )

        # 5. Ambiguous: chain/table ratio in [0.5, 0.8), low fan-out
        #    Could be either pattern, use conservative strategy
        return ClassificationResult(
            pattern=DispatchPattern.SIMPLE_COMPARE_CHAIN,
            confidence=0.5,
            recommended_strategy="compare_chain_direct",
            reasoning=(
                f"Ambiguous compare pattern: chain_length={profile.compare_chain_length}, "
                f"table_size={profile.dispatch_table_size} "
                f"(ratio={chain_to_table_ratio:.2f})"
            ),
        )

    @staticmethod
    def recommend_strategy(result: ClassificationResult) -> str:
        """Return the recommended unflattening strategy name.

        Mapping:
        - SIMPLE_COMPARE_CHAIN → "compare_chain_direct"
        - NESTED_COMPARE_TREE → "symbolic_execution"
        - SWITCH_TABLE → "switch_reconstruction"
        - MIXED_DISPATCH → "hybrid"
        - UNKNOWN → "conservative"

        Parameters
        ----------
        result : classification result

        Returns
        -------
        Strategy name as string

        Examples
        --------
        >>> result = ClassificationResult(
        ...     pattern=DispatchPattern.SIMPLE_COMPARE_CHAIN,
        ...     confidence=0.9,
        ...     recommended_strategy="compare_chain_direct",
        ...     reasoning="test",
        ... )
        >>> FlowProfileClassifier.recommend_strategy(result)
        'compare_chain_direct'
        """
        # The recommended_strategy is already computed during classification,
        # so this is just an accessor. Kept for API compatibility.
        return result.recommended_strategy

    @staticmethod
    def from_components(
        dispatch_region: frozenset[int],
        case_blocks: frozenset[int],
        dispatch_table_size: int,
        compare_chain_length: int,
        state_alias_count: int,
        has_default: bool,
        adj: dict[int, tuple[int, ...]],
    ) -> ClassificationResult:
        """Convenience: build FlowProfile from raw components and classify.

        Constructs the FlowProfile from the outputs of the previous services
        (DispatchRegionDetector, StateVarAliasExpander, CompareChainResolver)
        and runs classification.

        Parameters
        ----------
        dispatch_region : blocks in the dispatch SCC
        case_blocks : blocks outside the dispatch SCC
        dispatch_table_size : number of dispatch table entries
        compare_chain_length : length of longest compare chain
        state_alias_count : number of state variable aliases
        has_default : whether a default/fallthrough target exists
        adj : adjacency dict (block_serial → successor serials)

        Returns
        -------
        ClassificationResult

        Examples
        --------
        >>> # Simple compare chain from components
        >>> adj = {0: (1, 2), 1: (0,), 2: (0,), 3: (4,), 4: ()}
        >>> dispatch_region = frozenset({0, 1, 2})
        >>> case_blocks = frozenset({3, 4})
        >>> result = FlowProfileClassifier.from_components(
        ...     dispatch_region=dispatch_region,
        ...     case_blocks=case_blocks,
        ...     dispatch_table_size=2,
        ...     compare_chain_length=2,
        ...     state_alias_count=1,
        ...     has_default=True,
        ...     adj=adj,
        ... )
        >>> result.pattern == DispatchPattern.SIMPLE_COMPARE_CHAIN
        True
        """
        # Compute total blocks
        all_nodes = set(adj.keys())
        for succs in adj.values():
            all_nodes.update(succs)
        total_blocks = len(all_nodes)

        # Compute max_block_successors
        max_block_successors = max((len(succs) for succs in adj.values()), default=0)

        # Build FlowProfile
        profile = FlowProfile(
            total_blocks=total_blocks,
            dispatch_region_size=len(dispatch_region),
            case_block_count=len(case_blocks),
            compare_chain_length=compare_chain_length,
            state_alias_count=state_alias_count,
            dispatch_table_size=dispatch_table_size,
            has_default_target=has_default,
            max_block_successors=max_block_successors,
        )

        # Classify
        return FlowProfileClassifier.classify(profile)
