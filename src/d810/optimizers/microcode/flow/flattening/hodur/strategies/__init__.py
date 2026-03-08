"""Concrete unflattening strategies for Hodur CFF.

Each strategy implements the
:class:`~d810.optimizers.microcode.flow.flattening.hodur.strategy.UnflatteningStrategy`
Protocol and proposes :class:`~d810.optimizers.microcode.flow.flattening.hodur.strategy.PlanFragment`
objects describing CFG edits without mutating the microcode directly.

Available strategies (in dependency order):

1. :class:`DirectHandlerLinearizationStrategy` — BST-based goto-redirect,
   family ``direct``.
2. :class:`HiddenHandlerClosureStrategy` — second-pass for BST root-walk
   targets, family ``direct``.
3. :class:`EdgeSplitConflictResolutionStrategy` — conflict-driven block
   duplication, family ``direct``.
4. :class:`TerminalLoopCleanupStrategy` — break residual terminal loops,
   family ``cleanup``.
5. :class:`PrivateTerminalSuffixStrategy` — clone shared terminal suffix
   per handler entry for ``suffix_ambiguous`` sites, family ``direct``.
6. :class:`DirectTerminalLoweringStrategy` — per-anchor return value
   materialization for ``needs_direct_lowering`` sites, family ``direct``.
7. :class:`PredPatchFallbackStrategy` — MopTracker predecessor patching,
   family ``fallback``.
8. :class:`ConditionalForkFallbackStrategy` — conditional-fork resolution,
   family ``fallback``.
9. :class:`AssignmentMapFallbackStrategy` — dead state-assignment NOPs and
   assignment-map redirects, family ``fallback``.
"""
from __future__ import annotations

from d810.optimizers.microcode.flow.flattening.hodur.strategies.direct_linearization import (
    DirectHandlerLinearizationStrategy,
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

__all__ = [
    "DirectHandlerLinearizationStrategy",
    "HiddenHandlerClosureStrategy",
    "EdgeSplitConflictResolutionStrategy",
    "TerminalLoopCleanupStrategy",
    "PrivateTerminalSuffixStrategy",
    "PredPatchFallbackStrategy",
    "ConditionalForkFallbackStrategy",
    "AssignmentMapFallbackStrategy",
    "DirectTerminalLoweringStrategy",
    "ALL_STRATEGIES",
]

ALL_STRATEGIES: list[type] = [
    DirectHandlerLinearizationStrategy,
    HiddenHandlerClosureStrategy,
    EdgeSplitConflictResolutionStrategy,
    TerminalLoopCleanupStrategy,
    PrivateTerminalSuffixStrategy,
    DirectTerminalLoweringStrategy,
    PredPatchFallbackStrategy,
    ConditionalForkFallbackStrategy,
    AssignmentMapFallbackStrategy,
]
