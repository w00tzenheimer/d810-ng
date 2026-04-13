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
"""
from __future__ import annotations

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
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.reconstruction import (
    StateWriteReconstructionStrategy,
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
    "StateWriteReconstructionStrategy",
    "TopologicalSortStrategy",
    "BadWhileLoopStrategy",
    "FakeJumpStrategy",
    "SingleIterationStrategy",
    "ALL_STRATEGIES",
    "LEGACY_STRATEGIES",
]

# Experimental pipeline: reconstruction-first with direct cleanup.
# LinearizedFlowGraphStrategy remains importable for targeted tests and manual
# experiments, but it is no longer part of the live Hodur pipeline.
# Dead legacy shells and dormant reference strategies have been deleted once
# their behavior was either harvested into shared recon/cfg modules or fully
# superseded by reconstruction/LFG.
ALL_STRATEGIES: list[type] = [
    StateWriteReconstructionStrategy,
    FakeJumpStrategy,
    BadWhileLoopStrategy,
    SingleIterationStrategy,
    StateConstantReturnFixupStrategy,
    DeadStateVariableEliminationStrategy,
    # DISCRIMINATOR TEST: topo disabled
    # TopologicalSortStrategy,
]

# Legacy pipeline preserved for reference/fallback.
LEGACY_STRATEGIES: list[type] = [
    ValrangeResolutionStrategy,
    EdgeSplitConflictResolutionStrategy,
    TerminalLoopCleanupStrategy,
    ConditionalForkFallbackStrategy,
    # InnerMergeDuplicationStrategy disabled: tail-duplication of merge blocks
    # causes IDA structurer regressions (goto proliferation) that outweigh the
    # occasional goto elimination it provides.  Keep the import so the class
    # remains accessible for manual/experimental use.
    # InnerMergeDuplicationStrategy,
    StateConstantReturnFixupStrategy,
    DeadStateVariableEliminationStrategy,
]
