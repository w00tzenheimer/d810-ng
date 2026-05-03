"""Concrete unflattening strategies for Hodur CFF.

Each strategy implements the
:class:`~d810.optimizers.microcode.flow.flattening.hodur.strategy.UnflatteningStrategy`
Protocol and proposes :class:`~d810.optimizers.microcode.flow.flattening.hodur.strategy.PlanFragment`
objects describing CFG edits without mutating the microcode directly.

Available strategies (in dependency order):

1. :class:`ValrangeResolutionStrategy` — IDA value-range fallback for
   unresolved exits, family ``fallback``.
2. :class:`EdgeSplitConflictResolutionStrategy` — conflict-driven block
   duplication, family ``direct``.
3. :class:`TerminalLoopCleanupStrategy` — break residual terminal loops,
   family ``cleanup``.
4. :class:`ConditionalForkFallbackStrategy` — conditional-fork resolution,
   family ``fallback``.
5. :class:`InnerMergeDuplicationStrategy` — tail-duplicate small DAG merge
    blocks to eliminate structurer gotos, family ``cleanup``.
6. :class:`StateConstantReturnFixupStrategy` — NOP leaked state constants
    in BLT_STOP predecessor return paths, family ``cleanup``.
7. :class:`DeadStateVariableEliminationStrategy` — NOP remaining reads of
    the dead state variable after linearization, family ``cleanup``.
8. :class:`StateWriteReconstructionStrategy` — experimental horizon-driven
    semantic handoff reconstruction, family ``direct``.
9. :class:`SemanticStructuredRegionStrategy` — region-first lowering from
   trusted structured semantic regions, family ``direct``.
10. :class:`SemanticExactNodeAllPlannableEdgesStrategy` — bulk experimental
   DAG redirect scaffold for straight-line exact handoffs only,
   family ``direct``.
11. :class:`ExactConditionalNodeLoweringStrategy` — predicate-aware hammock
    lowering for exact conditional nodes, family ``direct``.
12. :class:`ExactConditionalAliasNodeLoweringStrategy` — lower duplicate-arm
    conditional nodes whose semantic exits alias to one canonical target,
    family ``direct``.
13. :class:`ExactConditionalForkNodeLoweringStrategy` — own both exits of
    exact two-way semantic fork nodes, family ``direct``.
14. :class:`ExactConditionalBridgeNodeLoweringStrategy` — prototype mixed-shape
    bridge lowering for exact conditional nodes with one semantic bridge arm,
    family ``direct``.
15. :class:`ExactNodeFrontierBypassStrategy` — redirect residual dispatcher
    feeders into dominating exact-node heads so BST cleanup can run,
    family ``direct``.
"""
from __future__ import annotations

import os

from d810.optimizers.microcode.flow.flattening.hodur.strategies.valrange_resolution import (
    ValrangeResolutionStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.edge_split_conflict import (
    EdgeSplitConflictResolutionStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.terminal_loop_cleanup import (
    TerminalLoopCleanupStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.conditional_fork_fallback import (
    ConditionalForkFallbackStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.dead_state_variable_elimination import (
    DeadStateVariableEliminationStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.inner_merge_duplication import (
    InnerMergeDuplicationStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.state_constant_return_fixup import (
    StateConstantReturnFixupStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.linearized_flow_graph import (
    LinearizedFlowGraphStrategy,
    SemanticStructuredRegionStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.reconstruction import (
    StateWriteReconstructionStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.semantic_exact_node import (
    SemanticExactNodeAllPlannableEdgesStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.exact_conditional_node import (
    ExactConditionalNodeLoweringStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.exact_conditional_alias import (
    ExactConditionalAliasNodeLoweringStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.exact_conditional_fork import (
    ExactConditionalForkNodeLoweringStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.prototypes import (
    ExactConditionalBridgeNodeLoweringStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.exact_node_frontier_bypass import (
    ExactNodeFrontierBypassStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.handler_chain_composer import (
    HandlerChainComposerStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.topological_sort import (
    TopologicalSortStrategy,
)
from d810.optimizers.microcode.flow.flattening.strategies.bad_while_loop import (
    BadWhileLoopStrategy,
)
from d810.optimizers.microcode.flow.flattening.strategies.fake_jump import (
    FakeJumpStrategy,
)
from d810.optimizers.microcode.flow.flattening.strategies.single_iteration import (
    SingleIterationStrategy,
)

__all__ = [
    "ValrangeResolutionStrategy",
    "EdgeSplitConflictResolutionStrategy",
    "TerminalLoopCleanupStrategy",
    "ConditionalForkFallbackStrategy",
    "DeadStateVariableEliminationStrategy",
    "InnerMergeDuplicationStrategy",
    "StateConstantReturnFixupStrategy",
    "LinearizedFlowGraphStrategy",
    "SemanticStructuredRegionStrategy",
    "StateWriteReconstructionStrategy",
    "SemanticExactNodeAllPlannableEdgesStrategy",
    "ExactConditionalNodeLoweringStrategy",
    "ExactConditionalAliasNodeLoweringStrategy",
    "ExactConditionalForkNodeLoweringStrategy",
    "ExactConditionalBridgeNodeLoweringStrategy",
    "ExactNodeFrontierBypassStrategy",
    "HandlerChainComposerStrategy",
    "TopologicalSortStrategy",
    "BadWhileLoopStrategy",
    "FakeJumpStrategy",
    "SingleIterationStrategy",
    "ALL_STRATEGIES",
    "EXPERIMENTAL_STRATEGIES",
    "LEGACY_STRATEGIES",
]

def _filter_strategies(strategies: list[type]) -> list[type]:
    """Filter strategies via env vars D810_HODUR_ONLY / D810_HODUR_SKIP.

    D810_HODUR_ONLY=Foo,Bar        — only run Foo and Bar
    D810_HODUR_SKIP=Baz            — skip Baz, run everything else
    Both can be combined; ONLY is applied first, then SKIP.
    """
    only = {n.strip() for n in os.environ.get("D810_HODUR_ONLY", "").split(",") if n.strip()}
    skip = {n.strip() for n in os.environ.get("D810_HODUR_SKIP", "").split(",") if n.strip()}
    out = list(strategies)
    if only:
        out = [s for s in out if s.__name__ in only]
    if skip:
        out = [s for s in out if s.__name__ not in skip]
    return out


# Live pipeline: semantic regions plus HCC-owned reconstruction orchestration.
#
# ``HandlerChainComposerStrategy`` is included for registration but is
# controlled via ``HANDLER_CHAIN_COMPOSER_ENABLED`` on the class itself.
# Standalone ``StateWriteReconstructionStrategy`` remains importable for
# targeted archaeology/regression tests, but HCC owns the live SWR-style
# orchestration and conflict handling.
EXPERIMENTAL_STRATEGIES: list[type] = _filter_strategies([
    SemanticStructuredRegionStrategy,
    HandlerChainComposerStrategy,
])

_STANDALONE_SRW_ENABLED = (
    os.getenv("D810_RECON_ENABLE_STANDALONE_SRW", "").strip() == "1"
    and os.getenv("D810_RECON_SKIP_SRW_STRATEGY", "").strip() != "1"
)

ALL_STRATEGIES: list[type] = _filter_strategies([
    SemanticStructuredRegionStrategy,
    HandlerChainComposerStrategy,
    StateConstantReturnFixupStrategy,
    DeadStateVariableEliminationStrategy,
    *([StateWriteReconstructionStrategy] if _STANDALONE_SRW_ENABLED else []),
])

# Legacy pipeline preserved for reference/fallback.
#
# Dormant strategies retired pre-Phase-1 of the DAG-as-arbiter epic
# (uee-jrgq):
#   * EdgeSplitConflictResolutionStrategy — placeholder, emits no fragment;
#     symbolic duplicate-block split was never re-enabled
#   * ConditionalForkFallbackStrategy — explicitly disabled in unflattener
#     (`disabled_strategy_names`); CONDITIONAL_REDIRECT subsumed by the
#     SRW conditional-arm path
#   * InnerMergeDuplicationStrategy — already-commented; tail-duplication
#     causes IDA structurer goto proliferation
# Imports kept so the classes remain accessible for manual/experimental
# use; LEGACY_STRATEGIES below excludes them so they cannot be picked up
# by automatic legacy-fallback wiring.
LEGACY_STRATEGIES: list[type] = [
    ValrangeResolutionStrategy,
    # EdgeSplitConflictResolutionStrategy,  # dormant — see header above
    TerminalLoopCleanupStrategy,
    # ConditionalForkFallbackStrategy,  # dormant — see header above
    # InnerMergeDuplicationStrategy,  # dormant — see header above
    StateConstantReturnFixupStrategy,
    DeadStateVariableEliminationStrategy,
]
