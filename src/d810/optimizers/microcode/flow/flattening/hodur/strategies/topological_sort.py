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

from d810.cfg.graph_modification import ReorderBlocks

try:
    import ida_hexrays as _ida_hexrays
    _BLT_2WAY: int | None = _ida_hexrays.BLT_2WAY
except ImportError:
    _BLT_2WAY = None
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    FAMILY_DIRECT,
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
)
from d810.recon.flow.bst_model import resolve_target_via_bst

if TYPE_CHECKING:
    from d810.optimizers.microcode.flow.flattening.hodur.snapshot import (
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
                    "TopologicalSort: already applied for func_ea=0x%x maturity=%d, skipping",
                    func_ea, maturity,
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

        sm = snapshot.state_machine
        assert sm is not None
        bst_result = snapshot.bst_result
        assert bst_result is not None

        handler_state_map: dict[int, int] = getattr(
            bst_result, "handler_state_map", {}
        ) or {}
        range_map: dict[int, tuple[int | None, int | None]] = getattr(
            bst_result, "handler_range_map", {}
        ) or {}

        initial_state = sm.initial_state
        assert initial_state is not None

        # Build reverse map: handler_entry_serial -> state_value
        entry_to_state: dict[int, int] = {
            serial: state for serial, state in handler_state_map.items()
        }

        # DFS from initial state through transitions
        visited_states: set[int] = set()
        dfs_block_order: list[int] = []
        seen_blocks: set[int] = set()  # deduplicate shared handler blocks

        def _resolve_entry(to_state: int) -> int | None:
            """Resolve a state value to handler entry serial."""
            target = resolve_target_via_bst(bst_result, to_state)
            if target is not None:
                return target
            # Fallback: check range_map including catch-all ranges
            for serial, (low, high) in range_map.items():
                lo = low if low is not None else 0
                hi = high if high is not None else 0xFFFFFFFF
                if lo <= to_state <= hi:
                    return serial
            return None

        def _dfs(state: int) -> None:
            if state in visited_states:
                return
            if state not in sm.handlers:
                return
            visited_states.add(state)
            handler = sm.handlers[state]
            for blk_serial in handler.handler_blocks:
                if blk_serial not in seen_blocks:
                    seen_blocks.add(blk_serial)
                    dfs_block_order.append(blk_serial)

            # Collect transitions from this handler, unconditional first
            handler_block_set = set(handler.handler_blocks)
            unconditional: list[int] = []
            conditional: list[int] = []

            for trans in sm.transitions:
                if trans.from_block not in handler_block_set:
                    continue
                target_entry = _resolve_entry(trans.to_state)
                if target_entry is None:
                    continue
                target_state = entry_to_state.get(target_entry)
                if target_state is None:
                    continue
                if trans.is_conditional:
                    conditional.append(target_state)
                else:
                    unconditional.append(target_state)

            # Follow unconditional transitions first (depth-first)
            for target_state in unconditional:
                _dfs(target_state)

            # Then follow conditional transitions
            for target_state in conditional:
                _dfs(target_state)

        _dfs(initial_state)

        # Append any handlers not reached by DFS
        for state in sm.handlers:
            if state not in visited_states:
                _dfs(state)

        if not dfs_block_order:
            return None

        # Pre-compute which blocks are NOT BLT_2WAY and which ARE BLT_2WAY.
        # Non-2WAY blocks are copied directly in Phase A.  2WAY blocks (handler-
        # internal conditionals) get a copy + fallthrough trampoline pair.
        non_2way_serials: tuple[int, ...] = ()
        two_way_serials: tuple[int, ...] = ()
        mba = snapshot.mba
        if mba is not None and _BLT_2WAY is not None:
            _non_2way: list[int] = []
            _two_way: list[int] = []
            for s in dfs_block_order:
                blk = mba.get_mblock(s)
                if blk is None:
                    continue
                if blk.type == _BLT_2WAY:
                    _two_way.append(s)
                else:
                    _non_2way.append(s)
            non_2way_serials = tuple(_non_2way)
            two_way_serials = tuple(_two_way)
        else:
            logger.warning(
                "TopologicalSortStrategy: cannot filter BLT_2WAY blocks "
                "(mba=%s, _BLT_2WAY=%s), non_2way_serials over-estimated",
                mba, _BLT_2WAY,
            )
            non_2way_serials = tuple(dfs_block_order)

        logger.info(
            "TopologicalSort: %d blocks in DFS order (%d non-2WAY, %d 2WAY) for %d handlers",
            len(dfs_block_order),
            len(non_2way_serials),
            len(two_way_serials),
            len(visited_states),
        )

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
        # Mark as applied so subsequent IDA passes at the same maturity skip.
        if mba is not None:
            func_ea = mba.entry_ea
            maturity = mba.maturity
            TopologicalSortStrategy._applied.add((func_ea, maturity))
            logger.info(
                "TopologicalSort: marking func_ea=0x%x maturity=%d as applied",
                func_ea, maturity,
            )

        return PlanFragment(
            strategy_name=self.name,
            family=self.family,
            modifications=[
                ReorderBlocks(
                    dfs_block_order=tuple(dfs_block_order),
                    non_2way_serials=non_2way_serials,
                    two_way_serials=two_way_serials,
                ),
            ],
            ownership=ownership,
            prerequisites=self.prerequisites,
            expected_benefit=benefit,
            risk_score=0.2,
            metadata={
                "dfs_block_count": len(dfs_block_order),
                "handler_count": len(visited_states),
                # Override safeguard threshold: ReorderBlocks is a single bulk
                # operation, not per-edge redirects.  The safeguard gate counts
                # len(modifications) which is 1 for this strategy.
                "safeguard_min_required": 1,
            },
        )
