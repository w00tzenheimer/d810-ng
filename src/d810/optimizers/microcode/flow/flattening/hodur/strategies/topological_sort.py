"""TopologicalSortStrategy -- DFS block reordering for linearized handlers.

After :class:`LinearizedFlowGraphStrategy` has redirected handler exits to
handler entries, the handler body blocks are still scattered across the MBA in
their original (obfuscated) positions.  This strategy computes a DFS traversal
of handlers starting from the initial state, collects their body blocks in
DFS order, and emits a :class:`ReorderBlocks` modification that copies them
to the end of the MBA in that order.

The copy-to-end + serial remapping approach leaves the originals as dead code
(no incoming edges) that IDA's deep cleaning removes.
"""
from __future__ import annotations

from d810.core import logging
from d810.core.typing import TYPE_CHECKING
from d810.hexrays.utils.hexrays_formatters import maturity_to_string

from d810.cfg.reorder_blocks_planning import compute_reorder_blocks as plan_reorder_blocks
from d810.optimizers.microcode.flow.flattening.engine.strategy import (
    FAMILY_DIRECT,
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
)
from d810.recon.flow.bst_model import resolve_target_via_bst
if TYPE_CHECKING:
    from d810.cfg.graph_modification import ReorderBlocks
    from d810.optimizers.microcode.flow.flattening.engine.snapshot import (
        AnalysisSnapshot,
    )

logger = logging.getLogger("D810.hodur.strategy.topological_sort")

__all__ = ["TopologicalSortStrategy"]


class TopologicalSortStrategy:
    """Phase 3: Reorder handler body blocks in DFS order from entry state.

    Computes DFS traversal from initial_state through sm.transitions,
    collects handler.handler_blocks in DFS order, emits ReorderBlocks.

    Must run AFTER LinearizedFlowGraphStrategy (prerequisites guard).
    """

    prerequisites: list[str] = ["linearized_flow_graph"]
    _applied: set[tuple[int, int]] = set()  # (func_ea, maturity) already processed

    @property
    def name(self) -> str:
        """Return the strategy identifier."""
        return "topological_sort"

    @property
    def family(self) -> str:
        """Return the strategy family."""
        return FAMILY_DIRECT

    # ------------------------------------------------------------------
    # Applicability
    # ------------------------------------------------------------------

    def is_applicable(self, snapshot: AnalysisSnapshot) -> bool:
        """Return True when the snapshot has a state machine with handlers,
        a BST result with handler_state_map, and a known initial_state.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            True if the transition graph can be traversed for DFS ordering.
        """
        mba = snapshot.mba
        if mba is not None:
            func_ea = mba.entry_ea
            maturity = mba.maturity
            if (func_ea, maturity) in TopologicalSortStrategy._applied:
                logger.debug(
                    "TopologicalSort: already applied for func_ea=0x%x maturity=%s, skipping",
                    func_ea, maturity_to_string(maturity),
                )
                return False

        sm = snapshot.state_machine
        if sm is None or not sm.handlers:
            return False
        if sm.initial_state is None:
            return False

        bst = snapshot.bst_result
        if bst is None:
            return False
        handler_state_map = getattr(bst, "handler_state_map", None) or {}
        if not handler_state_map:
            return False
        return True

    # ------------------------------------------------------------------
    # Core reorder logic (static, reusable from LFG)
    # ------------------------------------------------------------------

    @staticmethod
    def compute_reorder_blocks(
        snapshot: AnalysisSnapshot,
    ) -> ReorderBlocks | None:
        """Compatibility wrapper over :mod:`d810.cfg.reorder_blocks_planning`."""
        bst_result = snapshot.bst_result
        if bst_result is None:
            return None
        return plan_reorder_blocks(
            snapshot,
            resolve_target_entry=lambda state: resolve_target_via_bst(
                bst_result,
                state,
            ),
            handler_entry_state_map=(
                getattr(bst_result, "handler_state_map", {}) or {}
            ),
            dispatcher_blocks=frozenset(
                int(block)
                for block in (getattr(bst_result, "bst_node_blocks", ()) or ())
            ),
        )

    # ------------------------------------------------------------------
    # Plan
    # ------------------------------------------------------------------

    def plan(self, snapshot: AnalysisSnapshot) -> PlanFragment | None:
        """Produce a PlanFragment with a single ReorderBlocks modification.

        DFS traversal from initial_state through sm.transitions to collect
        handler body blocks in linearized order.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            A PlanFragment with a ReorderBlocks modification, or None
            when the strategy has nothing to contribute.
        """
        if not self.is_applicable(snapshot):
            return None

        reorder = self.compute_reorder_blocks(snapshot)
        if reorder is None:
            return None

        mba = snapshot.mba

        # Empty ownership — ReorderBlocks copies blocks to new serials and
        # remaps references; it does not claim exclusive ownership of the
        # originals (LFG already owns the redirect edges on those blocks).
        ownership = OwnershipScope(
            blocks=frozenset(),
            edges=frozenset(),
            transitions=frozenset(),
        )
        benefit = BenefitMetrics(
            handlers_resolved=0,
            transitions_resolved=0,
            blocks_freed=0,
            conflict_density=0.0,
        )
        # NOTE: _applied marking moved to unflattener post-success loop.
        # Strategies must NOT mark themselves applied during planning.

        return PlanFragment(
            strategy_name=self.name,
            family=self.family,
            modifications=[reorder],
            ownership=ownership,
            prerequisites=self.prerequisites,
            expected_benefit=benefit,
            risk_score=0.2,
            metadata={
                "dfs_block_count": len(reorder.dfs_block_order),
                "handler_count": len(
                    snapshot.state_machine.handlers
                ) if snapshot.state_machine else 0,
                # Override safeguard threshold: ReorderBlocks is a single bulk
                # operation, not per-edge redirects.  The safeguard gate counts
                # len(modifications) which is 1 for this strategy.
                "safeguard_min_required": 1,
            },
        )
