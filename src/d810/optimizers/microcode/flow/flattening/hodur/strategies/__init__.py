"""Concrete unflattening strategies for Hodur CFF.

Each strategy implements the
:class:`~d810.optimizers.microcode.flow.flattening.hodur.strategy.UnflatteningStrategy`
Protocol and proposes :class:`~d810.optimizers.microcode.flow.flattening.hodur.strategy.PlanFragment`
objects describing CFG edits without mutating the microcode directly.

Available strategies (in dependency order):

1. :class:`ValrangeResolutionStrategy` — IDA value-range fallback for
   unresolved exits, family ``fallback``.
2. :class:`HiddenHandlerClosureStrategy` — retired hidden-handler placeholder,
   family ``direct``.
3. :class:`EdgeSplitConflictResolutionStrategy` — conflict-driven block
   duplication, family ``direct``.
4. :class:`TerminalLoopCleanupStrategy` — break residual terminal loops,
   family ``cleanup``.
5. :class:`PredPatchFallbackStrategy` — MopTracker predecessor patching,
   family ``fallback``.
6. :class:`ConditionalForkFallbackStrategy` — conditional-fork resolution,
   family ``fallback``.
7. :class:`AssignmentMapFallbackStrategy` — dead state-assignment NOPs and
    assignment-map redirects, family ``fallback``.
8. :class:`InnerMergeDuplicationStrategy` — tail-duplicate small DAG merge
    blocks to eliminate structurer gotos, family ``cleanup``.
9. :class:`StateConstantReturnFixupStrategy` — NOP leaked state constants
    in BLT_STOP predecessor return paths, family ``cleanup``.
10. :class:`DeadStateVariableEliminationStrategy` — NOP remaining reads of
    the dead state variable after linearization, family ``cleanup``.
11. :class:`StateWriteReconstructionStrategy` — experimental horizon-driven
    semantic handoff reconstruction, family ``direct``.
"""
from __future__ import annotations

from d810.optimizers.microcode.flow.flattening.hodur.strategies.valrange_resolution import (
    ValrangeResolutionStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.hidden_handler_closure import (
    HiddenHandlerClosureStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.edge_split_conflict import (
    EdgeSplitConflictResolutionStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.terminal_loop_cleanup import (
    TerminalLoopCleanupStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.pred_patch_fallback import (
    PredPatchFallbackStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.conditional_fork_fallback import (
    ConditionalForkFallbackStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.assignment_map_fallback import (
    AssignmentMapFallbackStrategy,
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
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.reconstruction import (
    StateWriteReconstructionStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.topological_sort import (
    TopologicalSortStrategy,
)

__all__ = [
    "ValrangeResolutionStrategy",
    "HiddenHandlerClosureStrategy",
    "EdgeSplitConflictResolutionStrategy",
    "TerminalLoopCleanupStrategy",
    "PredPatchFallbackStrategy",
    "ConditionalForkFallbackStrategy",
    "AssignmentMapFallbackStrategy",
    "DeadStateVariableEliminationStrategy",
    "InnerMergeDuplicationStrategy",
    "StateConstantReturnFixupStrategy",
    "LinearizedFlowGraphStrategy",
    "StateWriteReconstructionStrategy",
    "TopologicalSortStrategy",
    "ALL_STRATEGIES",
    "LEGACY_STRATEGIES",
]

# Experimental pipeline: reconstruction-first with direct cleanup.
# LinearizedFlowGraphStrategy remains importable for targeted tests and manual
# experiments, but it is no longer part of the live Hodur pipeline.
# DEAD CODE NOTE:
# BackwardPredResolutionStrategy is intentionally not registered here anymore.
# It remains in-tree only as reference/debugging code; reconstruction now owns
# the late semantic handoffs that backward_pred used to patch heuristically.
ALL_STRATEGIES: list[type] = [
    StateWriteReconstructionStrategy,
    HiddenHandlerClosureStrategy,
    StateConstantReturnFixupStrategy,
    DeadStateVariableEliminationStrategy,
    # DISCRIMINATOR TEST: topo disabled
    # TopologicalSortStrategy,
]

# Legacy pipeline preserved for reference/fallback.
LEGACY_STRATEGIES: list[type] = [
    ValrangeResolutionStrategy,
    HiddenHandlerClosureStrategy,
    EdgeSplitConflictResolutionStrategy,
    TerminalLoopCleanupStrategy,
    PredPatchFallbackStrategy,
    ConditionalForkFallbackStrategy,
    AssignmentMapFallbackStrategy,
    # InnerMergeDuplicationStrategy disabled: tail-duplication of merge blocks
    # causes IDA structurer regressions (goto proliferation) that outweigh the
    # occasional goto elimination it provides.  Keep the import so the class
    # remains accessible for manual/experimental use.
    # InnerMergeDuplicationStrategy,
    StateConstantReturnFixupStrategy,
    DeadStateVariableEliminationStrategy,
]
