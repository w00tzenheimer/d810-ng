"""Backward dispatcher-predecessor resolution strategy.

Resolves TAIL_CHASE_FAILED handler exits by using MopTracker to backward-walk
from each dispatcher predecessor and resolve the state variable value, then
looking up the target handler via the IntervalDispatcher.

This runs on the PRE-APPLY MBA where state var writes are still intact
(before NOP'ing). Post-apply, the writes are NOP'd and block structure
changes due to trampolines.
"""
from __future__ import annotations

from d810.core import logging
from d810.core.typing import TYPE_CHECKING
from d810.optimizers.microcode.flow.flattening.hodur._modification_bridge import (
    ModificationBuilder,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    FAMILY_DIRECT,
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
)
from d810.recon.flow.bst_model import resolve_target_via_bst

if TYPE_CHECKING:
    from d810.optimizers.microcode.flow.flattening.hodur.snapshot import AnalysisSnapshot

logger = logging.getLogger("D810.hodur.strategy.backward_pred_resolution")

__all__ = ["BackwardPredResolutionStrategy"]


class BackwardPredResolutionStrategy:
    """Resolve unresolved handler exits via backward dispatcher-pred walk.

    For each non-BST predecessor of the dispatcher block, use MopTracker
    to backward-walk and resolve the state variable value.  If the value
    can be resolved, perform a BST lookup to determine the target handler
    and emit a ``RedirectGoto`` modification.

    Family: ``FAMILY_DIRECT`` -- runs after primary direct strategies.
    Risk: LOW-MEDIUM -- read-only backward walk + BST lookup, no speculation.
    """

    @property
    def name(self) -> str:
        """Return the strategy identifier."""
        return "backward_pred_resolution"

    @property
    def family(self) -> str:
        """Return the strategy family."""
        return FAMILY_DIRECT

    def is_applicable(self, snapshot: "AnalysisSnapshot") -> bool:
        """Return True when a BST result and dispatcher serial are present.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            True if the snapshot has a BST result with a valid dispatcher serial.
        """
        return (
            snapshot.bst_result is not None
            and snapshot.bst_dispatcher_serial >= 0
        )

    def plan(self, snapshot: "AnalysisSnapshot") -> PlanFragment | None:
        """Produce a PlanFragment for backward-pred-based exit resolution.

        For each non-BST predecessor of the dispatcher block, use MopTracker
        to backward-walk and resolve the state variable value, then emit a
        redirect if BST lookup succeeds.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            A PlanFragment with redirect modifications, or None when no
            exits could be resolved.
        """
        import ida_hexrays

        from d810.evaluator.hexrays_microcode.tracker import MopTracker

        mba = snapshot.mba
        bst_result = snapshot.bst_result
        dispatcher_serial = snapshot.bst_dispatcher_serial
        bst_node_blocks = bst_result.bst_node_blocks
        bst_serials = set(bst_node_blocks) | {dispatcher_serial}

        # Get state var mop (must be mop_S)
        state_var = getattr(snapshot.state_machine, "state_var", None)
        if state_var is None or state_var.t != ida_hexrays.mop_S:
            return None

        disp_blk = mba.get_mblock(dispatcher_serial)
        if disp_blk is None:
            return None

        # Build set of blocks already handled by LFG transitions.
        # On the first pass, resolved_transitions is empty, so we also
        # check the state machine's transition list directly -- these are
        # the from_block serials that LFG's direct_handler_linearization
        # will redirect.  Emitting duplicates causes GATE_FAILED.
        lfg_handled: set[int] = set()
        sm = snapshot.state_machine
        if sm is not None:
            for trans in sm.transitions:
                if trans.from_block is not None:
                    lfg_handled.add(trans.from_block)

        # Also include blocks whose transitions were explicitly resolved
        # by earlier strategies (belt-and-suspenders for later passes).
        resolved_trans = snapshot.resolved_transitions
        if resolved_trans and sm is not None:
            for t in sm.transitions:
                key = (t.from_state, t.to_state)
                if key in resolved_trans:
                    lfg_handled.add(t.from_block)

        # LFG also redirects blocks discovered via exit state resolution
        # (BFS from handler entries) and BST default block discovery (DFS
        # forward evaluation).  These redirect sources are NOT in
        # sm.transitions, so the filter above misses them.  Any dispatcher
        # predecessor inside a handler's block set will be reached by
        # LFG's forward evaluation — add all handler-owned blocks to the
        # exclusion set to prevent duplicate redirects that cause
        # CFG_50860_SUCC_MISMATCH.
        if sm is not None:
            for handler in sm.handlers.values():
                lfg_handled.add(handler.check_block)
                for blk_serial in handler.handler_blocks:
                    lfg_handled.add(blk_serial)

        # LFG's _resolve_exit_states performs BFS from handler entries for
        # EXIT states (handlers with no outgoing transition) and redirects
        # any block it discovers that writes a state constant.  These
        # BFS-discovered blocks may NOT appear in handler_blocks (e.g.
        # blk[48] for handler 0x6D207773).  Replicate the EXIT state
        # identification and BFS to exclude those blocks.
        if sm is not None and bst_result is not None:
            handler_state_map = getattr(bst_result, "handler_state_map", None) or {}
            if handler_state_map:
                # Inverted map: state_value -> handler entry serial
                state_to_entry: dict[int, int] = {
                    v: k for k, v in handler_state_map.items()
                }
                states_with_outgoing: set[int] = {
                    t.from_state for t in sm.transitions
                    if t.from_state is not None
                }
                for state_val, handler in sm.handlers.items():
                    if state_val in states_with_outgoing:
                        continue
                    # This is an EXIT state — LFG will BFS from its entry.
                    correct_entry = state_to_entry.get(state_val)
                    if correct_entry is None:
                        _exit_dispatcher = getattr(bst_result, "dispatcher", None)
                        if _exit_dispatcher is not None:
                            correct_entry = _exit_dispatcher.lookup(state_val)
                    if correct_entry is None:
                        continue
                    # BFS from correct_entry (mirrors LFG depth=6)
                    bfs_visited: set[int] = set()
                    bfs_queue: list[tuple[int, int]] = [(correct_entry, 0)]
                    while bfs_queue:
                        blk_serial, depth = bfs_queue.pop(0)
                        if blk_serial in bfs_visited:
                            continue
                        bfs_visited.add(blk_serial)
                        if blk_serial in bst_serials:
                            continue
                        try:
                            blk = mba.get_mblock(blk_serial)
                        except (AttributeError, IndexError):
                            continue
                        if blk is None:
                            continue
                        if depth < 6:
                            try:
                                for si in range(blk.nsucc()):
                                    succ_s = blk.succ(si)
                                    if succ_s not in bfs_visited:
                                        bfs_queue.append((succ_s, depth + 1))
                            except Exception:
                                pass
                    lfg_handled.update(bfs_visited)

        builder = ModificationBuilder.from_snapshot(snapshot)
        modifications = []
        owned_blocks: set[int] = set()

        # Count non-BST dispatcher preds for the log summary
        total_preds = sum(
            1 for pi in range(disp_blk.npred())
            if disp_blk.pred(pi) not in bst_serials
        )
        skipped = sum(
            1 for pi in range(disp_blk.npred())
            if disp_blk.pred(pi) not in bst_serials
            and disp_blk.pred(pi) in lfg_handled
        )
        remaining = total_preds - skipped
        if skipped:
            logger.info(
                "BACKWARD_PRED: skipping %d LFG-handled predecessors, "
                "processing %d remaining",
                skipped, remaining,
            )

        # Iterate dispatcher predecessors
        for pi in range(disp_blk.npred()):
            pred_serial = disp_blk.pred(pi)
            if pred_serial in bst_serials:
                continue

            # Skip predecessors whose transitions are handled by LFG
            # or were already resolved by earlier strategies.
            if pred_serial in lfg_handled:
                continue

            pred_blk = mba.get_mblock(pred_serial)
            if pred_blk is None or pred_blk.nsucc() != 1:
                continue

            # Only redirect blocks still pointing at the dispatcher.
            # If the successor is already something else (redirected by
            # an earlier strategy in the same decompilation pass), emitting
            # a second redirect would create a duplicate-successor
            # violation (CFG_50860_SUCC_MISMATCH).
            if pred_blk.succ(0) != dispatcher_serial:
                continue

            # Use MopTracker to backward-walk and resolve the state var value
            MopTracker.reset()
            tracker = MopTracker([state_var], max_nb_block=10, max_path=50)
            try:
                histories = tracker.search_backward(pred_blk, pred_blk.tail)
            except Exception:
                logger.debug(
                    "BACKWARD_PRED: blk[%d] MopTracker search_backward failed",
                    pred_serial,
                )
                continue

            resolved_value = None
            for history in histories:
                value = history.get_mop_constant_value(state_var)
                if value is not None:
                    resolved_value = value
                    break  # first valid resolution wins

            if resolved_value is None:
                continue

            # BST lookup
            target = resolve_target_via_bst(bst_result, resolved_value)
            if target is None:
                logger.info(
                    "BACKWARD_PRED: blk[%d] state=0x%X no BST target",
                    pred_serial, resolved_value,
                )
                continue

            # Emit redirect
            mod = builder.goto_redirect(
                source_block=pred_serial, target_block=target,
            )
            if mod is not None:
                modifications.append(mod)
                owned_blocks.add(pred_serial)
                logger.info(
                    "BACKWARD_PRED: blk[%d] MopTracker resolved state=0x%X -> handler blk[%d]",
                    pred_serial, resolved_value, target,
                )

        if not modifications:
            return None

        logger.info(
            "BACKWARD_PRED: resolved %d dispatcher predecessors",
            len(modifications),
        )

        return PlanFragment(
            strategy_name=self.name,
            family=self.family,
            modifications=modifications,
            ownership=OwnershipScope(
                blocks=frozenset(),  # Don't claim blocks — avoid conflict with LFG
                edges=frozenset(),
                transitions=frozenset(),
            ),
            prerequisites=["direct_handler_linearization"],
            expected_benefit=BenefitMetrics(
                handlers_resolved=0,
                transitions_resolved=len(modifications),
                blocks_freed=0,
                conflict_density=0.0,
            ),
            risk_score=0.3,
            metadata={"safeguard_min_required": 1},
        )
