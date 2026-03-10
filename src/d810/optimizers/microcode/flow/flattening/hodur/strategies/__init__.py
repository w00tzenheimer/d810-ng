"""Concrete unflattening strategies for Hodur CFF.

Each strategy implements the
:class:`~d810.optimizers.microcode.flow.flattening.hodur.strategy.UnflatteningStrategy`
Protocol and proposes :class:`~d810.optimizers.microcode.flow.flattening.hodur.strategy.PlanFragment`
objects describing CFG edits without mutating the microcode directly.

Available strategies (in dependency order):

1. :class:`DirectHandlerLinearizationStrategy` — BST-based goto-redirect,
   family ``direct``.
2. :class:`ValrangeResolutionStrategy` — IDA value-range fallback for
   unresolved exits, family ``fallback``.
3. :class:`HiddenHandlerClosureStrategy` — second-pass for BST root-walk
   targets, family ``direct``.
4. :class:`EdgeSplitConflictResolutionStrategy` — conflict-driven block
   duplication, family ``direct``.
5. :class:`TerminalLoopCleanupStrategy` — break residual terminal loops,
   family ``cleanup``.
6. :class:`PrivateTerminalSuffixStrategy` — clone shared terminal suffix
   per handler entry for ``suffix_ambiguous`` sites, family ``direct``.
7. :class:`DirectTerminalLoweringStrategy` — per-anchor return value
   materialization for ``needs_direct_lowering`` sites, family ``direct``.
8. :class:`PredPatchFallbackStrategy` — MopTracker predecessor patching,
   family ``fallback``.
9. :class:`ConditionalForkFallbackStrategy` — conditional-fork resolution,
   family ``fallback``.
10. :class:`AssignmentMapFallbackStrategy` — dead state-assignment NOPs and
    assignment-map redirects, family ``fallback``.
11. :class:`InnerMergeDuplicationStrategy` — tail-duplicate small DAG merge
    blocks to eliminate structurer gotos, family ``cleanup``.
12. :class:`StateConstantReturnFixupStrategy` — NOP leaked state constants
    in BLT_STOP predecessor return paths, family ``cleanup``.
13. :class:`DeadStateVariableEliminationStrategy` — NOP remaining reads of
    the dead state variable after linearization, family ``cleanup``.
"""
from __future__ import annotations

from d810.optimizers.microcode.flow.flattening.hodur.strategies.direct_linearization import (
    DirectHandlerLinearizationStrategy,
)
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
from d810.optimizers.microcode.flow.flattening.hodur.strategies.private_terminal_suffix import (
    PrivateTerminalSuffixStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.direct_terminal_lowering import (
    DirectTerminalLoweringStrategy,
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

__all__ = [
    "DirectHandlerLinearizationStrategy",
    "ValrangeResolutionStrategy",
    "HiddenHandlerClosureStrategy",
    "EdgeSplitConflictResolutionStrategy",
    "TerminalLoopCleanupStrategy",
    "PrivateTerminalSuffixStrategy",
    "PredPatchFallbackStrategy",
    "ConditionalForkFallbackStrategy",
    "AssignmentMapFallbackStrategy",
    "DirectTerminalLoweringStrategy",
    "DeadStateVariableEliminationStrategy",
    "InnerMergeDuplicationStrategy",
    "StateConstantReturnFixupStrategy",
    "ALL_STRATEGIES",
]

ALL_STRATEGIES: list[type] = [
    DirectHandlerLinearizationStrategy,
    ValrangeResolutionStrategy,
    HiddenHandlerClosureStrategy,
    EdgeSplitConflictResolutionStrategy,
    TerminalLoopCleanupStrategy,
    PrivateTerminalSuffixStrategy,
    DirectTerminalLoweringStrategy,
    PredPatchFallbackStrategy,
    ConditionalForkFallbackStrategy,
    AssignmentMapFallbackStrategy,
    # DISABLED: causes INTERR 50860 on hodur_func (verify failure in DuplicateBlock)
    # InnerMergeDuplicationStrategy,
    StateConstantReturnFixupStrategy,
    DeadStateVariableEliminationStrategy,
]
