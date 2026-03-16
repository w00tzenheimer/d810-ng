"""LinearizedFlowGraphStrategy -- deterministic graph-stitching linearization.

Uses the complete handler transition graph already present in the
:class:`~d810.optimizers.microcode.flow.flattening.hodur.datamodel.HodurStateMachine`
to wire handler exits directly to handler entries.  No forward evaluation is
needed -- the known ``StateTransition`` objects provide the mapping.

Algorithm:

1. Iterate ALL transitions in ``sm.transitions`` (the flat list of every
   ``StateTransition`` ever recorded, including orphaned MBA/proxy-var
   transitions that may not be attached to any per-handler list).
2. Resolve each ``to_state`` via ``resolve_target_via_bst`` (handles both
   exact matches and BST range-map entries).
3. Emit a ``RedirectGoto`` (unconditional) or ``RedirectBranch`` (conditional)
   targeting the resolved handler entry serial.
4. Wire pre-header to the initial handler entry.
"""
from __future__ import annotations

import ida_hexrays

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
from d810.optimizers.microcode.flow.flattening.hodur._helpers import (
    evaluate_handler_paths,
)
from d810.recon.flow.bst_analysis import resolve_via_bst_walk
from d810.recon.flow.bst_model import resolve_target_via_bst
from d810.recon.flow.transition_builder import _get_state_var_stkoff

if TYPE_CHECKING:
    from d810.optimizers.microcode.flow.flattening.hodur.datamodel import (
        HodurStateMachine,
    )
    from d810.optimizers.microcode.flow.flattening.hodur.snapshot import (
        AnalysisSnapshot,
    )

logger = logging.getLogger("D810.hodur.strategy.linearized_flow_graph", logging.DEBUG)

__all__ = ["LinearizedFlowGraphStrategy"]


class LinearizedFlowGraphStrategy:
    """Wire handler exits to handler entries using the known transition graph.

    This strategy is a lightweight alternative to
    :class:`DirectHandlerLinearizationStrategy`.  Instead of running DFS
    forward evaluation on live microcode, it reads the pre-computed
    ``StateTransition`` objects from the state machine and emits redirect
    modifications deterministically.
    """

    @property
    def name(self) -> str:
        """Return the strategy identifier."""
        return "linearized_flow_graph"

    @property
    def family(self) -> str:
        """Return the strategy family."""
        return FAMILY_DIRECT

    # No prerequisites -- this is a standalone first-pass strategy.
    prerequisites: list[str] = []
    _applied: set[tuple[int, int]] = set()  # (func_ea, maturity) already processed

    # ------------------------------------------------------------------
    # Applicability
    # ------------------------------------------------------------------

    def is_applicable(self, snapshot: AnalysisSnapshot) -> bool:
        """Return True when the snapshot has a state machine with handlers,
        a BST result with ``handler_state_map``, and a known ``initial_state``.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            True if the transition graph can be traversed.
        """
        mba = snapshot.mba
        if mba is not None:
            func_ea = mba.entry_ea
            maturity = mba.maturity
            if (func_ea, maturity) in LinearizedFlowGraphStrategy._applied:
                logger.info(
                    "LFG: already applied for func 0x%X at maturity %d",
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
        """Produce a :class:`PlanFragment` by stitching the transition graph.

        Iterates EVERY resolved edge in the state machine transition graph
        and emits a redirect for each one.  Then NOPs all state variable
        writes in handler blocks so the BST dispatcher becomes dead code.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            A :class:`PlanFragment` with redirect modifications, or ``None``
            when the strategy has nothing to contribute.
        """
        if not self.is_applicable(snapshot):
            return None

        sm = snapshot.state_machine
        assert sm is not None  # guaranteed by is_applicable
        bst_result = snapshot.bst_result
        assert bst_result is not None

        handler_state_map: dict[int, int] = dict(
            getattr(bst_result, "handler_state_map", {}) or {}
        )
        # Backfill handler_state_map from IntervalDispatcher so that
        # handlers reachable only via wide BST range intervals are
        # included in all downstream resolution (exit states, BST
        # default discovery, DOT graph, coverage checks).
        # handler_state_map shape: {handler_serial: state_value}
        _dispatcher = getattr(bst_result, "dispatcher", None)
        if _dispatcher is not None:
            _existing_handler_serials = set(handler_state_map.keys())
            # Count how many rows map to each target.  Targets that
            # appear in multiple disjoint intervals are catch-all /
            # default blocks, NOT real handlers -- skip them.
            from collections import Counter as _Counter
            _target_freq: dict[int, int] = _Counter(
                r.target for r in _dispatcher._rows
            )
            for _row in _dispatcher._rows:
                if _row.target in _existing_handler_serials:
                    continue
                if _target_freq[_row.target] > 1:
                    continue  # catch-all / default block
                # Use lo as representative state value for this range.
                handler_state_map[_row.target] = _row.lo
                logger.info(
                    "LFG: INTERVAL_BACKFILL blk[%d] <- state 0x%X "
                    "(range [0x%X, 0x%X))",
                    _row.target, _row.lo, _row.lo, _row.hi,
                )
        pre_header_serial: int | None = getattr(
            bst_result, "pre_header_serial", None
        )
        bst_node_blocks: set[int] = set(
            getattr(bst_result, "bst_node_blocks", set()) or set()
        )

        builder = ModificationBuilder.from_snapshot(snapshot)
        modifications: list = []
        owned_blocks: set[int] = set()
        owned_edges: set[tuple[int, int]] = set()
        owned_transitions: set[tuple[int, int]] = set()

        resolved_count = 0
        skipped_count = 0
        # Track which (from_block, to_serial) pairs have been emitted to
        # avoid duplicate redirects when the same exit block appears in
        # multiple transitions.
        emitted: set[tuple[int, int]] = set()
        # Track which 1-way blocks already have a redirect emitted to
        # detect conflicting redirects on shared tail blocks.
        claimed_1way: dict[int, int] = {}  # from_block -> first target_entry

        initial_state = sm.initial_state
        assert initial_state is not None

        # Collect handler block ownership from all known handlers.
        for handler in sm.handlers.values():
            owned_blocks.add(handler.check_block)
            owned_blocks.update(handler.handler_blocks)

        # Build dispatcher region: BST nodes + blocks outside handler
        # ownership.  Used to identify which successor of a 2-way block
        # leads back to the dispatcher (the leg to replace).
        dispatcher_region: set[int] = set(bst_node_blocks)

        # Pre-compute the handler_range_map for catch-all fallback.
        # resolve_target_via_bst() intentionally skips wide ranges
        # (span >= 0xFFFF0000) to avoid false positives during normal
        # resolution.  However, unresolved states that genuinely belong
        # to the BST default/catch-all handler should still be linked.
        range_map: dict[int, tuple[int | None, int | None]] = getattr(
            bst_result, "handler_range_map", {}
        ) or {}

        # -----------------------------------------------------------------
        # 1. Iterate ALL transitions from the flat sm.transitions list.
        #    This includes orphaned MBA/proxy-var transitions that may not
        #    be attached to any per-handler transition list.
        # -----------------------------------------------------------------
        raw_transition_count = len(sm.transitions)
        range_fallback_count = 0

        for transition in sm.transitions:
            # Skip transitions with unresolved from_state (emitted by UD
            # chain discovery as placeholders for future resolution).
            if transition.from_state is None:
                continue

            to_state = transition.to_state
            from_block = transition.from_block

            # Resolve target via BST (handles exact + range matches).
            target_entry = resolve_target_via_bst(bst_result, to_state)

            # Fallback: check range_map including catch-all ranges that
            # resolve_target_via_bst() intentionally skips.
            if target_entry is None:
                for serial, (low, high) in range_map.items():
                    lo = low if low is not None else 0
                    hi = high if high is not None else 0xFFFFFFFF
                    if lo <= to_state <= hi:
                        target_entry = serial
                        range_fallback_count += 1
                        logger.info(
                            "LFG: range-fallback resolved 0x%X -> blk[%d]",
                            to_state,
                            serial,
                        )
                        break

            if target_entry is None:
                logger.debug(
                    "LFG: to_state 0x%X resolves to None, skipping",
                    to_state,
                )
                skipped_count += 1
                continue

            # Deduplicate: same (from_block, target_entry) should only
            # emit one redirect.
            emit_key = (from_block, target_entry)
            if emit_key in emitted:
                continue
            emitted.add(emit_key)

            # Skip self-loop redirects (MBA fake self-loops).
            if from_block == target_entry:
                logger.info(
                    "LFG: skipping self-loop redirect blk[%d] -> blk[%d] "
                    "(state 0x%X -> 0x%X)",
                    from_block, target_entry,
                    transition.from_state, to_state,
                )
                skipped_count += 1
                continue

            # Emit the appropriate modification.
            #
            # For 2-way (conditional) blocks we MUST identify which
            # successor leg to replace and use edge_redirect so that a
            # RedirectBranch is emitted with the correct old_target.
            # Using goto_redirect on a 2-way block would emit
            # ConvertToGoto, collapsing both arms into a single goto --
            # producing CFG_BLT2WAY_NON_JCC_TAIL / BAD_NSUCC violations.
            from_nsucc = builder.block_nsucc_map.get(from_block, 1)
            if from_nsucc == 2:
                bst_old_target: int | None = None
                from_succs = builder.block_succ_map.get(from_block, ())

                # Strategy: find the successor that leads toward the
                # dispatcher.  Check BST nodes first, then any block
                # outside handler ownership, then any block in the
                # dispatcher_region.
                for succ_serial in from_succs:
                    if succ_serial in bst_node_blocks:
                        bst_old_target = succ_serial
                        break
                if bst_old_target is None:
                    for succ_serial in from_succs:
                        if succ_serial not in owned_blocks:
                            bst_old_target = succ_serial
                            break
                if bst_old_target is None:
                    for succ_serial in from_succs:
                        if succ_serial in dispatcher_region:
                            bst_old_target = succ_serial
                            break

                # Last resort for 2-way blocks where BOTH successors are
                # handler blocks: pick the successor that is NOT the
                # resolved target.  This happens when a conditional
                # handler has already had one arm redirected in a
                # previous transition, leaving both arms as handler
                # entries.
                if bst_old_target is None:
                    for succ_serial in from_succs:
                        if succ_serial != target_entry:
                            bst_old_target = succ_serial
                            break

                if bst_old_target is None:
                    logger.debug(
                        "LFG: skipping 2-way transition blk[%d] -> "
                        "blk[%d] (state 0x%X -> 0x%X, conditional=%s): "
                        "cannot determine old_target among succs %s",
                        from_block,
                        target_entry,
                        transition.from_state,
                        to_state,
                        transition.is_conditional,
                        from_succs,
                    )
                    skipped_count += 1
                    continue

                mod = builder.edge_redirect(
                    source_block=from_block,
                    target_block=target_entry,
                    old_target=bst_old_target,
                )
            else:
                # 1-way block -- check for shared tail conflict.
                if from_block in claimed_1way:
                    first_target = claimed_1way[from_block]
                    if first_target != target_entry:
                        # CONFLICT: this 1-way block already has a redirect
                        # to a different target.  Skip to avoid emitting two
                        # conflicting goto_redirects on the same BLT_1WAY
                        # block (which causes CFG_50856_BAD_NSUCC and
                        # rejects the entire plan fragment).
                        # TODO: back-propagate to predecessor conditional
                        # block once handler-aware predecessor walk is
                        # implemented.
                        logger.info(
                            "LFG: CONFLICT on 1-way blk[%d]: already "
                            "-> blk[%d], skipping -> blk[%d] "
                            "(state 0x%X -> 0x%X)",
                            from_block,
                            first_target,
                            target_entry,
                            transition.from_state,
                            to_state,
                        )
                        skipped_count += 1
                        continue
                    else:
                        # Same target -- already handled by dedup.
                        continue
                else:
                    mod = builder.goto_redirect(
                        source_block=from_block,
                        target_block=target_entry,
                    )
                    claimed_1way[from_block] = target_entry

            modifications.append(mod)
            owned_edges.add((from_block, target_entry))
            owned_transitions.add((transition.from_state, to_state))
            resolved_count += 1

            logger.info(
                "LFG: redirect blk[%d] -> blk[%d]  "
                "(state 0x%X -> 0x%X, conditional=%s)",
                from_block,
                target_entry,
                transition.from_state,
                to_state,
                transition.is_conditional,
            )

        # A1 handler chain block redirect pass DISABLED: chain blocks inside
        # handlers may be mid-handler, not handler exits. Redirecting them to
        # the next handler's entry short-circuits handler bodies, causing DCE.
        # Needs redesign: chain blocks should be redirected within the handler's
        # internal flow, not to the exit target handler.
        chain_redirect_count = 0

        # -----------------------------------------------------------------
        # 1b. Resolve EXIT states via handler_state_map.
        #
        #     Some handlers have no outgoing transition because the walker
        #     entered a BST comparison node instead of the real handler body.
        #     handler_state_map knows the correct entry block for each state.
        #     We BFS from the correct entry to find state variable writes
        #     (m_mov #const, state_var) and resolve the target handler.
        # -----------------------------------------------------------------
        exit_resolved_count = self._resolve_exit_states(
            snapshot=snapshot,
            sm=sm,
            bst_result=bst_result,
            handler_state_map=handler_state_map,
            bst_node_blocks=bst_node_blocks,
            dispatcher_region=dispatcher_region,
            builder=builder,
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            owned_transitions=owned_transitions,
            emitted=emitted,
            claimed_1way=claimed_1way,
        )
        resolved_count += exit_resolved_count

        # Mark as applied BEFORE BST-default discovery so that a crash
        # inside _discover_bst_default_transitions does not cause
        # redundant retries on subsequent IDA callbacks.
        mba = snapshot.mba
        if mba is not None:
            func_ea = mba.entry_ea
            maturity = mba.maturity
            type(self)._applied.add((func_ea, maturity))
            logger.info(
                "LFG: marking func 0x%X maturity=%d as applied",
                func_ea, maturity,
            )

        # -----------------------------------------------------------------
        # 1c. Discover transitions through BST default blocks via DFS
        #     forward evaluation.
        #
        #     Some handlers exit through BST default blocks with
        #     MBA-computed state values (e.g., v7 ^ v8) that the
        #     analysis-phase walker cannot resolve.  evaluate_handler_paths
        #     carries per-handler operand context through BST nodes and
        #     can forward-evaluate these expressions to discover the
        #     concrete exit state, which is then resolved via the BST
        #     to find the target handler entry.
        # -----------------------------------------------------------------
        try:
            bst_default_count = self._discover_bst_default_transitions(
                snapshot=snapshot,
                sm=sm,
                bst_result=bst_result,
                handler_state_map=handler_state_map,
                bst_node_blocks=bst_node_blocks,
                dispatcher_region=dispatcher_region,
                builder=builder,
                modifications=modifications,
                owned_blocks=owned_blocks,
                owned_edges=owned_edges,
                owned_transitions=owned_transitions,
                emitted=emitted,
                claimed_1way=claimed_1way,
            )
        except Exception:
            logger.warning(
                "LFG: BST-default discovery failed, continuing with "
                "%d main redirects", resolved_count, exc_info=True,
            )
            bst_default_count = 0
        resolved_count += bst_default_count

        # -----------------------------------------------------------------
        # 2. Wire pre-header to initial handler entry.
        # -----------------------------------------------------------------
        initial_entry = resolve_target_via_bst(bst_result, initial_state)
        if pre_header_serial is not None and initial_entry is not None:
            # Skip if the transition loop already redirected the pre-header
            # block (avoids duplicate goto_redirect → BAD_NSUCC on 1-way).
            if pre_header_serial not in claimed_1way:
                mod = builder.goto_redirect(
                    source_block=pre_header_serial,
                    target_block=initial_entry,
                )
                modifications.append(mod)
                owned_blocks.add(pre_header_serial)
                owned_edges.add((pre_header_serial, initial_entry))
                claimed_1way[pre_header_serial] = initial_entry
                logger.info(
                    "LFG: pre-header blk[%d] -> initial handler blk[%d] "
                    "(state 0x%X)",
                    pre_header_serial,
                    initial_entry,
                    initial_state,
                )
            else:
                logger.info(
                    "LFG: pre-header blk[%d] already redirected, "
                    "skipping duplicate pre-header wire",
                    pre_header_serial,
                )

        if not modifications:
            logger.info("LFG: no modifications emitted")
            return None

        # 2b. Emit resolved state machine DOT graph for diagnostics.
        self._emit_resolved_graph_dot(
            sm, bst_result, handler_state_map, emitted, skipped_count,
        )

        # -----------------------------------------------------------------
        # 3. NOP state variable writes in ALL mba blocks.
        #    After redirecting exits, state variable assignments are dead
        #    code.  Leaving them alive keeps BST comparison blocks
        #    reachable, creating spurious while-loops in the decompiled
        #    output.  Shared tail blocks between handlers and the BST
        #    dispatcher also write the state variable but aren't in any
        #    handler's block set, so we scan ALL mba blocks (excluding BST
        #    node blocks which READ the state variable).
        # -----------------------------------------------------------------
        redirected_states: set[int] = {
            t.from_state for t in sm.transitions
            if t.from_state is not None
            and (
                (t.from_block, resolve_target_via_bst(bst_result, t.to_state))
                in emitted
                or resolve_target_via_bst(bst_result, t.to_state) is not None
            )
        }
        nop_mods, nop_blocks = self._nop_state_variable_writes(
            snapshot, builder, owned_blocks, redirected_states,
            bst_node_blocks,
        )
        modifications.extend(nop_mods)
        owned_blocks.update(nop_blocks)

        # -----------------------------------------------------------------
        # 3b. NOP m_goto @dispatcher in single-owner handler blocks.
        #     After state variable writes are NOP'd, explicit m_goto
        #     instructions targeting the dispatcher still keep it
        #     reachable.  NOP these gotos (turning the block into a
        #     dead-end) instead of redirecting to avoid shared-block DCE.
        #     Only safe for blocks with npred<=1.
        # -----------------------------------------------------------------
        dispatcher_serial = snapshot.bst_dispatcher_serial
        goto_nop_mods, goto_nop_count, goto_skip_count = (
            self._nop_dispatcher_gotos(
                snapshot, dispatcher_serial, bst_node_blocks, builder,
            )
        )
        modifications.extend(goto_nop_mods)

        # -----------------------------------------------------------------
        # 4. Disconnect 2-way blocks with dispatcher back-edges.
        #    After linearization, some 2-way blocks (BST comparison nodes
        #    or handler conditionals) still have the dispatcher as one
        #    successor.  These back-edges create while loops in the
        #    decompiled output.  Convert such blocks from 2-way to 1-way
        #    via ConvertToGoto, keeping the non-dispatcher successor.
        # -----------------------------------------------------------------
        disconnect_count = self._disconnect_bst_comparison_nodes(
            bst_node_blocks, dispatcher_serial, builder, modifications, emitted,
        )

        logger.info(
            "LFG: emitted %d redirects (%d exit-resolved, %d bst-default) "
            "+ %d chain redirects, %d stvar NOPs across %d blocks, "
            "%d goto NOPs (%d shared-skipped), %d BST disconnects "
            "(%d raw transitions, %d skipped, %d range-fallback)",
            resolved_count,
            exit_resolved_count,
            bst_default_count,
            chain_redirect_count,
            len(nop_mods),
            len(nop_blocks),
            goto_nop_count,
            goto_skip_count,
            disconnect_count,
            raw_transition_count,
            skipped_count,
            range_fallback_count,
        )

        # =============================================================
        # DISPATCHER COVERAGE DIAGNOSTIC
        #
        # Log which dispatcher predecessor blocks are NOT covered by
        # any redirect emission.  These are the edges keeping the BST
        # alive and represent missing transitions in the state machine.
        # =============================================================
        flow_graph = snapshot.flow_graph
        if flow_graph is not None and snapshot.bst_dispatcher_serial >= 0:
            dispatcher_snap = flow_graph.get_block(
                snapshot.bst_dispatcher_serial,
            )
            if dispatcher_snap is not None:
                # Collect all from_block serials that got a redirect.
                redirected_blocks: set[int] = set()
                for m in modifications:
                    for attr in (
                        "from_serial",
                        "block_serial",
                        "source_block",
                        "src_block",
                    ):
                        val = getattr(m, attr, None)
                        if val is not None:
                            redirected_blocks.add(val)
                            break

                uncovered: list[tuple[int, int, int, list[int], bool]] = []
                for pred in dispatcher_snap.preds:
                    if pred in redirected_blocks:
                        continue
                    if pred in bst_node_blocks:
                        continue  # BST internal, expected
                    pred_snap = flow_graph.get_block(pred)
                    nsucc = len(pred_snap.succs) if pred_snap else -1
                    succs = list(pred_snap.succs) if pred_snap else []
                    npred = len(pred_snap.preds) if pred_snap else -1

                    # Check if any transition has this block as from_block.
                    has_transition = any(
                        t.from_block == pred for t in sm.transitions
                    )
                    uncovered.append(
                        (pred, nsucc, npred, succs, has_transition),
                    )

                logger.info(
                    "DIAG_COVERAGE: dispatcher blk[%d] has %d preds, "
                    "%d redirected, %d BST, %d uncovered non-BST",
                    snapshot.bst_dispatcher_serial,
                    len(dispatcher_snap.preds),
                    len(redirected_blocks & set(dispatcher_snap.preds)),
                    sum(
                        1
                        for p in dispatcher_snap.preds
                        if p in bst_node_blocks
                    ),
                    len(uncovered),
                )
                for pred, nsucc, npred, succs, has_trans in uncovered:
                    logger.info(
                        "DIAG_COVERAGE: uncovered blk[%d] nsucc=%d npred=%d "
                        "succs=%s has_transition=%s",
                        pred,
                        nsucc,
                        npred,
                        succs,
                        has_trans,
                    )

        handlers_visited = len(sm.handlers)
        ownership = OwnershipScope(
            blocks=frozenset(owned_blocks),
            edges=frozenset(owned_edges),
            transitions=frozenset(owned_transitions),
        )
        benefit = BenefitMetrics(
            handlers_resolved=handlers_visited,
            transitions_resolved=resolved_count,
            blocks_freed=len(bst_node_blocks),
            conflict_density=0.0,
        )
        return PlanFragment(
            strategy_name=self.name,
            family=self.family,
            modifications=modifications,
            ownership=ownership,
            prerequisites=self.prerequisites,
            expected_benefit=benefit,
            risk_score=0.1,
            metadata={
                "handlers_visited": handlers_visited,
                "resolved_count": resolved_count,
                "chain_redirect_count": chain_redirect_count,
                "exit_resolved_count": exit_resolved_count,
                "bst_default_count": bst_default_count,
                "raw_transitions": raw_transition_count,
                "skipped_count": skipped_count,
                "range_fallback_count": range_fallback_count,
                "disconnect_count": disconnect_count,
                "goto_nop_count": goto_nop_count,
                "goto_skip_count": goto_skip_count,
            },
        )

    # ------------------------------------------------------------------
    # Resolved state machine DOT graph
    # ------------------------------------------------------------------

    @staticmethod
    def _emit_resolved_graph_dot(
        sm: HodurStateMachine,
        bst_result: object,
        handler_state_map: dict[int, int],
        emitted: set[tuple[int, int]],
        skipped_count: int,
    ) -> None:
        """Emit a DOT graph showing the RESOLVED transition graph.

        This shows the forward-evaluated transitions with self-loops resolved
        to real next states, unlike the raw state machine graph which shows
        OLLVM MBA self-loops.

        Args:
            sm: The Hodur state machine with handlers and transitions.
            bst_result: BST analysis result with handler_state_map.
            handler_state_map: Mapping of handler serial -> state value.
            emitted: Set of (from_block, to_block) pairs that were successfully
                redirected.
            skipped_count: Number of transitions that could not be resolved.
        """
        if not logger.info_on:
            return

        # Build reverse map: state_value -> handler serial (entry block)
        state_to_serial: dict[int, int] = {}
        for serial, state_val in handler_state_map.items():
            state_to_serial[state_val] = serial

        # Classify each handler and collect edges
        #
        # Categories:
        #   resolved   - has at least one successfully redirected transition
        #   exit       - terminal handler (no outgoing transitions)
        #   unresolved - has transitions but none were resolved
        #   conditional - has 2+ distinct to_states (branching handler)

        # Group transitions by from_state
        transitions_by_from: dict[int, list] = {}
        for t in sm.transitions:
            if t.from_state is not None:
                transitions_by_from.setdefault(t.from_state, []).append(t)

        # Track per-handler resolution status
        node_states: set[int] = set()  # all handler state values
        resolved_edges: list[tuple[int, int, bool]] = []  # (from_state, to_state, is_conditional)
        exit_states: set[int] = set()
        unresolved_states: set[int] = set()

        # Collect the range_map for fallback resolution (same logic as plan())
        range_map: dict[int, tuple[int | None, int | None]] = getattr(
            bst_result, "handler_range_map", {}
        ) or {}

        for state_val, handler in sm.handlers.items():
            node_states.add(state_val)
            handler_transitions = transitions_by_from.get(state_val, [])

            if not handler_transitions:
                exit_states.add(state_val)
                continue

            has_resolved = False
            for t in handler_transitions:
                # Resolve to_state the same way plan() does
                target_entry = resolve_target_via_bst(bst_result, t.to_state)
                if target_entry is None:
                    for serial, (low, high) in range_map.items():
                        lo = low if low is not None else 0
                        hi = high if high is not None else 0xFFFFFFFF
                        if lo <= t.to_state <= hi:
                            target_entry = serial
                            break

                if target_entry is not None:
                    # Map target serial back to state value
                    target_state = handler_state_map.get(target_entry)
                    if target_state is not None:
                        resolved_edges.append(
                            (state_val, target_state, t.is_conditional)
                        )
                        has_resolved = True
                    else:
                        # Target is a known block but not in handler_state_map
                        # (could be a non-handler block). Still mark as resolved.
                        has_resolved = True

            if not has_resolved:
                unresolved_states.add(state_val)

        # Deduplicate edges (same from/to pair may appear from multiple transitions)
        seen_edges: set[tuple[int, int, bool]] = set()
        unique_edges: list[tuple[int, int, bool]] = []
        for edge in resolved_edges:
            if edge not in seen_edges:
                seen_edges.add(edge)
                unique_edges.append(edge)

        # Count conditional nodes (handlers with 2+ distinct targets)
        targets_per_handler: dict[int, set[int]] = {}
        for from_s, to_s, _ in unique_edges:
            targets_per_handler.setdefault(from_s, set()).add(to_s)
        conditional_states: set[int] = {
            s for s, targets in targets_per_handler.items() if len(targets) >= 2
        }

        # Build DOT lines
        dot: list[str] = []
        dot.append("digraph resolved_state_machine {")
        dot.append("    rankdir=LR;")
        dot.append("    node [shape=record];")

        # START node
        initial_state = sm.initial_state
        if initial_state is not None:
            dot.append("")
            dot.append("    START [shape=point];")
            dot.append('    START -> "0x%08X";' % initial_state)

        # Node declarations
        dot.append("")
        for state_val in sorted(node_states):
            serial = state_to_serial.get(state_val, -1)
            label_parts = ["0x%08X" % state_val, "blk[%d]" % serial]

            if state_val in exit_states:
                label_parts.append("EXIT")
                dot.append(
                    '    "0x%08X" [label="%s" style=filled fillcolor=lightgreen];'
                    % (state_val, "\\n".join(label_parts))
                )
            elif state_val in unresolved_states:
                label_parts.append("UNRESOLVED")
                dot.append(
                    '    "0x%08X" [label="%s" style=filled fillcolor=orange];'
                    % (state_val, "\\n".join(label_parts))
                )
            elif state_val in conditional_states:
                label_parts.append("BRANCH")
                dot.append(
                    '    "0x%08X" [label="%s" style=filled fillcolor=lightskyblue];'
                    % (state_val, "\\n".join(label_parts))
                )
            else:
                dot.append(
                    '    "0x%08X" [label="%s"];'
                    % (state_val, "\\n".join(label_parts))
                )

        # Edges
        dot.append("")
        for from_s, to_s, is_cond in unique_edges:
            if is_cond:
                dot.append(
                    '    "0x%08X" -> "0x%08X" [color=blue];'
                    % (from_s, to_s)
                )
            else:
                dot.append(
                    '    "0x%08X" -> "0x%08X";' % (from_s, to_s)
                )

        # Self-loop for unresolved states
        for state_val in sorted(unresolved_states):
            dot.append(
                '    "0x%08X" -> "0x%08X" [style=dashed color=red];'
                % (state_val, state_val)
            )

        dot.append("}")

        # Summary counts
        n_resolved = len(node_states) - len(exit_states) - len(unresolved_states)
        n_edges = len(unique_edges)

        logger.info(
            "LFG resolved graph: %d nodes, %d edges, %d resolved, "
            "%d unresolved, %d exits, %d conditional",
            len(node_states),
            n_edges,
            n_resolved,
            len(unresolved_states),
            len(exit_states),
            len(conditional_states),
        )

        # Emit DOT graph
        logger.info("LFG_RESOLVED_GRAPH_DOT_START")
        for line in dot:
            logger.info(line)
        logger.info("LFG_RESOLVED_GRAPH_DOT_END")

    # ------------------------------------------------------------------
    # EXIT state resolution via handler_state_map
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_exit_states(
        snapshot: AnalysisSnapshot,
        sm: HodurStateMachine,
        bst_result: object,
        handler_state_map: dict[int, int],
        bst_node_blocks: set[int],
        dispatcher_region: set[int],
        builder: ModificationBuilder,
        modifications: list,
        owned_blocks: set[int],
        owned_edges: set[tuple[int, int]],
        owned_transitions: set[tuple[int, int]],
        emitted: set[tuple[int, int]],
        claimed_1way: dict[int, int],
    ) -> int:
        """Resolve EXIT handlers whose walker entered a BST node instead of
        the real handler body.

        For each handler state that has NO outgoing transition in
        ``sm.transitions``, look up the correct entry block via the inverted
        ``handler_state_map``, BFS from that block to find ``m_mov #const,
        state_var`` instructions, then resolve the constant via the BST to
        wire the handler exit to the correct target.

        Returns:
            Number of redirects emitted by this pass.
        """
        mba = snapshot.mba
        if mba is None:
            return 0

        # Build inverted map: state_value -> correct handler entry serial.
        # handler_state_map shape: {handler_serial: state_value}
        state_to_entry: dict[int, int] = {
            v: k for k, v in handler_state_map.items()
        }
        # Also store the dispatcher reference for fallback lookup on
        # states that are only reachable via wide BST range intervals.
        _exit_dispatcher = getattr(bst_result, "dispatcher", None)

        # Resolve state variable stkoff (same logic as _nop_state_variable_writes).
        stkoff: int | None = None
        detector = snapshot.detector
        if detector is not None:
            try:
                stkoff = _get_state_var_stkoff(detector)
            except Exception:
                pass
        if stkoff is None and sm.state_var is not None:
            try:
                if sm.state_var.t == ida_hexrays.mop_S:
                    stkoff = sm.state_var.s.off
            except Exception:
                pass

        if stkoff is None:
            logger.info(
                "LFG EXIT: cannot resolve state_var stkoff, skipping"
            )
            return 0

        # Identify states with outgoing transitions.
        states_with_outgoing: set[int] = {
            t.from_state for t in sm.transitions
            if t.from_state is not None
        }

        # Also exclude self-loop-skipped states: states where the only
        # transitions have from_block == target_entry (already skipped in
        # main loop).
        self_loop_only: set[int] = set()
        for state_val, handler in sm.handlers.items():
            if state_val not in states_with_outgoing:
                continue
            handler_transitions = [
                t for t in sm.transitions if t.from_state == state_val
            ]
            all_self_loop = True
            for t in handler_transitions:
                target = resolve_target_via_bst(bst_result, t.to_state)
                if target is None or t.from_block != target:
                    all_self_loop = False
                    break
            if all_self_loop and handler_transitions:
                self_loop_only.add(state_val)

        # Find EXIT states: handlers with no outgoing transition (or only
        # self-loops that were skipped).
        exit_states: list[int] = []
        for state_val in sm.handlers:
            if state_val in states_with_outgoing and state_val not in self_loop_only:
                continue
            exit_states.append(state_val)

        if not exit_states:
            logger.info("LFG EXIT: no EXIT states found")
            return 0

        logger.info(
            "LFG EXIT: found %d EXIT states: %s",
            len(exit_states),
            ["0x%X" % s for s in exit_states],
        )

        resolved_count = 0
        max_bfs_depth = 6

        for state_val in exit_states:
            handler = sm.handlers[state_val]
            correct_entry = state_to_entry.get(state_val)
            # Fallback: use IntervalDispatcher for range-matched states.
            if correct_entry is None and _exit_dispatcher is not None:
                correct_entry = _exit_dispatcher.lookup(state_val)
                if correct_entry is not None:
                    logger.info(
                        "LFG EXIT: DISP_LOOKUP state 0x%X -> blk[%d] "
                        "(via IntervalDispatcher)",
                        state_val,
                        correct_entry,
                    )
            if correct_entry is None:
                if state_val in self_loop_only:
                    logger.info(
                        "LFG EXIT: skipping self-loop state 0x%X "
                        "(not in handler_state_map)",
                        state_val,
                    )
                    continue
                # BST boundary state — try direct BST walk to find target block.
                dispatcher_serial = snapshot.bst_dispatcher_serial
                if dispatcher_serial >= 0 and bst_node_blocks:
                    target_serial = resolve_via_bst_walk(
                        mba, dispatcher_serial, state_val, bst_node_blocks,
                    )
                    if target_serial is not None:
                        # Find from_block: look for a transition that writes
                        # this state value so we know the exit block.
                        from_block: int | None = None
                        for t in sm.transitions:
                            if t.to_state == state_val:
                                from_block = t.from_block
                                break
                        if from_block is None:
                            # Fallback: use handler's check/entry block.
                            from_block = (
                                handler.handler_blocks[0]
                                if handler.handler_blocks
                                else handler.check_block
                            )
                        if from_block in bst_node_blocks:
                            logger.info(
                                "LFG EXIT: BST walk skipping state 0x%X "
                                "— from_block blk[%d] is BST node",
                                state_val,
                                from_block,
                            )
                            continue
                        if from_block != target_serial:
                            emit_key = (from_block, target_serial)
                            if emit_key not in emitted:
                                emitted.add(emit_key)
                                from_nsucc = builder.block_nsucc_map.get(
                                    from_block, 1,
                                )
                                if from_nsucc == 2:
                                    bst_old_target: int | None = None
                                    from_succs = builder.block_succ_map.get(
                                        from_block, (),
                                    )
                                    for succ_serial in from_succs:
                                        if succ_serial in bst_node_blocks:
                                            bst_old_target = succ_serial
                                            break
                                    if bst_old_target is None:
                                        for succ_serial in from_succs:
                                            if succ_serial not in owned_blocks:
                                                bst_old_target = succ_serial
                                                break
                                    if bst_old_target is None:
                                        for succ_serial in from_succs:
                                            if succ_serial in dispatcher_region:
                                                bst_old_target = succ_serial
                                                break
                                    if bst_old_target is None:
                                        for succ_serial in from_succs:
                                            if succ_serial != target_serial:
                                                bst_old_target = succ_serial
                                                break
                                    if bst_old_target is not None:
                                        mod = builder.edge_redirect(
                                            source_block=from_block,
                                            target_block=target_serial,
                                            old_target=bst_old_target,
                                        )
                                        modifications.append(mod)
                                        owned_edges.add(
                                            (from_block, target_serial),
                                        )
                                        resolved_count += 1
                                        logger.info(
                                            "LFG EXIT: BST walk resolved "
                                            "state 0x%X: blk[%d] -> blk[%d] "
                                            "(2-way, old_target=blk[%d])",
                                            state_val,
                                            from_block,
                                            target_serial,
                                            bst_old_target,
                                        )
                                        continue
                                else:
                                    if from_block in claimed_1way:
                                        first_target = claimed_1way[from_block]
                                        if first_target != target_serial:
                                            logger.info(
                                                "LFG EXIT: BST walk CONFLICT "
                                                "on 1-way blk[%d]: already "
                                                "-> blk[%d], skipping "
                                                "-> blk[%d]",
                                                from_block,
                                                first_target,
                                                target_serial,
                                            )
                                            continue
                                        else:
                                            continue
                                    mod = builder.goto_redirect(
                                        source_block=from_block,
                                        target_block=target_serial,
                                    )
                                    claimed_1way[from_block] = target_serial
                                    modifications.append(mod)
                                    owned_edges.add(
                                        (from_block, target_serial),
                                    )
                                    resolved_count += 1
                                    logger.info(
                                        "LFG EXIT: BST walk resolved "
                                        "state 0x%X: blk[%d] -> blk[%d] "
                                        "(1-way)",
                                        state_val,
                                        from_block,
                                        target_serial,
                                    )
                                    continue
                logger.info(
                    "LFG EXIT: state 0x%X not in handler_state_map "
                    "and BST walk failed, skipping",
                    state_val,
                )
                continue

            current_entry = handler.handler_blocks[0] if handler.handler_blocks else handler.check_block

            logger.info(
                "LFG EXIT: state 0x%X: handler entry blk[%d], "
                "correct entry blk[%d]%s",
                state_val,
                current_entry,
                correct_entry,
                " (MISMATCH)" if current_entry != correct_entry else "",
            )

            # BFS from the correct entry block to find m_mov #const, state_var.
            visited: set[int] = set()
            queue: list[tuple[int, int]] = [(correct_entry, 0)]  # (serial, depth)
            found_writes: list[tuple[int, int, int]] = []  # (blk_serial, insn_ea, const_value)

            while queue:
                blk_serial, depth = queue.pop(0)
                if blk_serial in visited:
                    continue
                visited.add(blk_serial)

                # Skip BST nodes -- they compare the state var, not write it.
                if blk_serial in bst_node_blocks:
                    continue

                try:
                    blk = mba.get_mblock(blk_serial)  # type: ignore[attr-defined]
                except (AttributeError, IndexError):
                    continue
                if blk is None:
                    continue

                # Walk all instructions in this block looking for
                # m_mov #const, state_var.
                insn = blk.head
                while insn is not None:
                    if insn.opcode == ida_hexrays.m_mov:
                        d = insn.d
                        if (
                            d is not None
                            and d.t == ida_hexrays.mop_S
                            and d.s is not None
                            and d.s.off == stkoff
                            and insn.l is not None
                            and insn.l.t == ida_hexrays.mop_n
                        ):
                            const_val = insn.l.nnn.value
                            found_writes.append(
                                (blk_serial, insn.ea, const_val)
                            )
                            logger.info(
                                "LFG EXIT: state 0x%X: found m_mov #0x%X, "
                                "state_var in blk[%d]",
                                state_val,
                                const_val,
                                blk_serial,
                            )
                    insn = insn.next

                # Continue BFS to successors within depth limit.
                if depth < max_bfs_depth:
                    try:
                        nsucc = blk.nsucc()
                        for i in range(nsucc):
                            succ_serial = blk.succ(i)
                            if succ_serial not in visited:
                                queue.append((succ_serial, depth + 1))
                    except Exception:
                        pass

            if not found_writes:
                logger.info(
                    "LFG EXIT: state 0x%X: no state var writes found via "
                    "BFS from blk[%d] (depth %d, visited %d blocks)",
                    state_val,
                    correct_entry,
                    max_bfs_depth,
                    len(visited),
                )
                continue

            # For each found write, resolve the target handler and emit a
            # redirect from the write block back to the correct handler.
            for write_blk, write_ea, exit_state_value in found_writes:
                target_entry = resolve_target_via_bst(
                    bst_result, exit_state_value
                )
                if target_entry is None:
                    logger.info(
                        "LFG EXIT: state 0x%X: exit value 0x%X from "
                        "blk[%d] resolves to None, skipping",
                        state_val,
                        exit_state_value,
                        write_blk,
                    )
                    continue

                # Skip self-loop redirects.
                if write_blk == target_entry:
                    logger.info(
                        "LFG EXIT: state 0x%X: skipping self-loop "
                        "blk[%d] -> blk[%d]",
                        state_val,
                        write_blk,
                        target_entry,
                    )
                    continue

                emit_key = (write_blk, target_entry)
                if emit_key in emitted:
                    continue
                emitted.add(emit_key)

                # Determine from_block: the block that writes the exit
                # state and needs its successor redirected.  For 1-way
                # blocks this is the write block itself.  For 2-way
                # blocks we find the dispatcher-bound successor leg.
                from_block = write_blk
                from_nsucc = builder.block_nsucc_map.get(from_block, 1)

                if from_nsucc == 2:
                    bst_old_target: int | None = None
                    from_succs = builder.block_succ_map.get(
                        from_block, ()
                    )
                    for succ_serial in from_succs:
                        if succ_serial in bst_node_blocks:
                            bst_old_target = succ_serial
                            break
                    if bst_old_target is None:
                        for succ_serial in from_succs:
                            if succ_serial not in owned_blocks:
                                bst_old_target = succ_serial
                                break
                    if bst_old_target is None:
                        for succ_serial in from_succs:
                            if succ_serial in dispatcher_region:
                                bst_old_target = succ_serial
                                break
                    if bst_old_target is None:
                        for succ_serial in from_succs:
                            if succ_serial != target_entry:
                                bst_old_target = succ_serial
                                break

                    if bst_old_target is None:
                        logger.info(
                            "LFG EXIT: state 0x%X: cannot determine "
                            "old_target for 2-way blk[%d], skipping",
                            state_val,
                            from_block,
                        )
                        continue

                    mod = builder.edge_redirect(
                        source_block=from_block,
                        target_block=target_entry,
                        old_target=bst_old_target,
                    )
                else:
                    # 1-way: check for shared tail conflict.
                    if from_block in claimed_1way:
                        first_target = claimed_1way[from_block]
                        if first_target != target_entry:
                            logger.info(
                                "LFG EXIT: CONFLICT on 1-way blk[%d]: "
                                "already -> blk[%d], skipping -> blk[%d]",
                                from_block,
                                first_target,
                                target_entry,
                            )
                            continue
                        else:
                            continue  # already emitted
                    mod = builder.goto_redirect(
                        source_block=from_block,
                        target_block=target_entry,
                    )
                    claimed_1way[from_block] = target_entry

                modifications.append(mod)
                owned_edges.add((from_block, target_entry))
                owned_transitions.add((state_val, exit_state_value))
                resolved_count += 1

                logger.info(
                    "LFG EXIT: resolved state 0x%X: blk[%d] -> blk[%d] "
                    "(exit value 0x%X)",
                    state_val,
                    from_block,
                    target_entry,
                    exit_state_value,
                )

        logger.info(
            "LFG: resolved %d EXIT states via handler_state_map",
            resolved_count,
        )
        return resolved_count

    # ------------------------------------------------------------------
    # BST default block transition discovery via DFS forward evaluation
    # ------------------------------------------------------------------

    @staticmethod
    def _discover_bst_default_transitions(
        snapshot: AnalysisSnapshot,
        sm: HodurStateMachine,
        bst_result: object,
        handler_state_map: dict[int, int],
        bst_node_blocks: set[int],
        dispatcher_region: set[int],
        builder: ModificationBuilder,
        modifications: list,
        owned_blocks: set[int],
        owned_edges: set[tuple[int, int]],
        owned_transitions: set[tuple[int, int]],
        emitted: set[tuple[int, int]],
        claimed_1way: dict[int, int],
    ) -> int:
        """Discover handler transitions through BST default blocks via DFS.

        Some handlers exit through BST default blocks whose state values
        are computed via MBA expressions (e.g., ``v7 ^ v8``).  The
        analysis-phase walker cannot resolve these because multi-predecessor
        constant folding fails.  :func:`evaluate_handler_paths` carries
        per-handler operand context through BST nodes and can
        forward-evaluate these expressions to discover the concrete exit
        state.

        This method iterates all handlers, runs ``evaluate_handler_paths``
        on each, and for any newly-discovered transition whose target
        handler entry is not yet covered by an emitted redirect, emits a
        redirect modification.

        Returns:
            Number of new redirects emitted.
        """
        mba = snapshot.mba
        if mba is None:
            return 0

        # Resolve state variable stkoff (same pattern as _resolve_exit_states).
        stkoff: int | None = None
        detector = snapshot.detector
        if detector is not None:
            try:
                stkoff = _get_state_var_stkoff(detector)
            except Exception:
                pass
        if stkoff is None and sm.state_var is not None:
            try:
                if sm.state_var.t == ida_hexrays.mop_S:
                    stkoff = sm.state_var.s.off
            except Exception:
                pass

        if stkoff is None:
            logger.info(
                "LFG BST-default: cannot resolve state_var stkoff, skipping"
            )
            return 0

        # Compute the set of handler entry serials already targeted by
        # an emitted redirect.  These are the *targets* (second element)
        # of each emitted (from_block, to_block) pair.
        covered_entries: set[int] = {to_blk for _, to_blk in emitted}

        # All handler entry serials from the handler_state_map.
        all_handler_entries: set[int] = set(handler_state_map.keys())
        uncovered_entries: set[int] = all_handler_entries - covered_entries

        if not uncovered_entries:
            logger.info(
                "LFG BST-default: all %d handler entries already covered",
                len(all_handler_entries),
            )
            return 0

        # Only run BST default discovery when enough handlers are uncovered
        # to justify the risk. Small numbers indicate the main loop + exit resolver
        # already handled the function well.
        uncovered_ratio = len(uncovered_entries) / len(handler_state_map) if handler_state_map else 0
        if len(uncovered_entries) < 3 and uncovered_ratio < 0.15:
            logger.info(
                "LFG BST-default: skipping, %d uncovered (%.0f%%) below both thresholds",
                len(uncovered_entries), uncovered_ratio * 100,
            )
            return 0

        logger.info(
            "LFG BST-default: %d uncovered handler entries out of %d: %s",
            len(uncovered_entries),
            len(all_handler_entries),
            sorted(uncovered_entries),
        )

        # Build the set of handler entry blocks for the DFS boundary guard.
        handler_entry_blocks: set[int] = set(handler_state_map.values())

        resolved_count = 0

        for handler_state, handler_entry in handler_state_map.items():
            # Run DFS forward evaluation from this handler.
            paths = evaluate_handler_paths(
                mba=mba,
                entry_serial=handler_entry,
                incoming_state=handler_state,
                bst_node_blocks=bst_node_blocks,
                state_var_stkoff=stkoff,
                handler_entry_blocks=handler_entry_blocks,
            )

            for path_result in paths:
                if path_result.final_state is None:
                    continue

                final_state = path_result.final_state & 0xFFFFFFFF
                from_block = path_result.exit_block

                # Resolve the final state to a handler entry serial.
                target_entry = resolve_target_via_bst(
                    bst_result, final_state,
                )
                if target_entry is None:
                    continue

                # Only interested in transitions to uncovered entries.
                if target_entry not in uncovered_entries:
                    continue

                # Skip self-loop redirects.
                if from_block == target_entry:
                    continue

                # Deduplicate.
                emit_key = (from_block, target_entry)
                if emit_key in emitted:
                    continue
                emitted.add(emit_key)

                # Don't redirect from a block that's already committed
                # to redirect to a covered handler.
                source_serial = from_block
                if source_serial in owned_blocks:
                    continue

                # Emit the redirect (same pattern as main loop).
                from_nsucc = builder.block_nsucc_map.get(from_block, 1)

                if from_nsucc == 2:
                    bst_old_target: int | None = None
                    from_succs = builder.block_succ_map.get(
                        from_block, (),
                    )
                    for succ_serial in from_succs:
                        if succ_serial in bst_node_blocks:
                            bst_old_target = succ_serial
                            break
                    if bst_old_target is None:
                        for succ_serial in from_succs:
                            if succ_serial not in owned_blocks:
                                bst_old_target = succ_serial
                                break
                    if bst_old_target is None:
                        for succ_serial in from_succs:
                            if succ_serial in dispatcher_region:
                                bst_old_target = succ_serial
                                break
                    if bst_old_target is None:
                        for succ_serial in from_succs:
                            if succ_serial != target_entry:
                                bst_old_target = succ_serial
                                break

                    if bst_old_target is None:
                        logger.info(
                            "LFG BST-default: cannot determine old_target "
                            "for 2-way blk[%d], skipping",
                            from_block,
                        )
                        continue

                    mod = builder.edge_redirect(
                        source_block=from_block,
                        target_block=target_entry,
                        old_target=bst_old_target,
                    )
                else:
                    # 1-way: check for shared tail conflict.
                    if from_block in claimed_1way:
                        first_target = claimed_1way[from_block]
                        if first_target != target_entry:
                            logger.info(
                                "LFG BST-default: CONFLICT on 1-way "
                                "blk[%d]: already -> blk[%d], skipping "
                                "-> blk[%d]",
                                from_block,
                                first_target,
                                target_entry,
                            )
                            continue
                        else:
                            continue  # already emitted
                    mod = builder.goto_redirect(
                        source_block=from_block,
                        target_block=target_entry,
                    )
                    claimed_1way[from_block] = target_entry

                modifications.append(mod)
                owned_edges.add((from_block, target_entry))
                owned_transitions.add((handler_state, final_state))
                resolved_count += 1

                # Mark this entry as covered so subsequent iterations
                # don't re-discover the same target.
                uncovered_entries.discard(target_entry)

                logger.info(
                    "LFG BST-default: discovered transition "
                    "handler 0x%X blk[%d] -> state 0x%X -> "
                    "handler blk[%d] (from_block=blk[%d])",
                    handler_state,
                    handler_entry,
                    final_state,
                    target_entry,
                    from_block,
                )

            # Early exit: all uncovered entries now covered.
            if not uncovered_entries:
                break

        logger.info(
            "LFG BST-default: discovered %d new transitions, "
            "%d entries still uncovered",
            resolved_count,
            len(uncovered_entries),
        )
        return resolved_count

    # ------------------------------------------------------------------
    # State variable write NOPing
    # ------------------------------------------------------------------

    @staticmethod
    def _nop_state_variable_writes(
        snapshot: AnalysisSnapshot,
        builder: ModificationBuilder,
        handler_blocks: set[int],
        redirected_states: set[int],
        bst_node_blocks: set[int],
    ) -> tuple[list, set[int]]:
        """NOP instructions that write to the state variable in ALL mba blocks.

        After handler exits are redirected away from the BST dispatcher, ALL
        state variable writes are dead code -- the state variable is only read
        by BST comparison blocks, which become unreachable once writes stop.

        This scans every block in the mba (not just handler-owned blocks)
        because shared tail blocks between handlers and the BST dispatcher
        also write the state variable but aren't in any handler's block set.

        BST node blocks are excluded because they READ the state variable
        (comparison blocks), not write it.

        Args:
            snapshot: Immutable analysis snapshot for the current function.
            builder: Modification builder for emitting NOP edits.
            handler_blocks: Set of block serials belonging to handlers.
            redirected_states: Set of handler from_state values that had at
                least one successful redirect emitted.
            bst_node_blocks: Set of BST node block serials to exclude from
                NOPing (these READ the state variable).

        Returns:
            A tuple of (list of NOP modifications, set of block serials touched).
        """
        logger.info(
            "LFG NOP: entering _nop_state_variable_writes "
            "(redirected_states=%d, handler_blocks=%d, bst_node_blocks=%d)",
            len(redirected_states), len(handler_blocks), len(bst_node_blocks),
        )
        sm = snapshot.state_machine
        if sm is None:
            logger.info("LFG NOP: sm is None, bailing")
            return [], set()

        # Resolve state variable stack offset.
        stkoff: int | None = None
        detector = snapshot.detector
        if detector is not None:
            try:
                stkoff = _get_state_var_stkoff(detector)
            except Exception:
                pass
        if stkoff is None and sm.state_var is not None:
            try:
                if sm.state_var.t == ida_hexrays.mop_S:
                    stkoff = sm.state_var.s.off
            except Exception:
                pass

        if stkoff is None:
            logger.info("LFG: cannot resolve state_var stkoff, skipping NOP pass")
            return [], set()

        mba = snapshot.mba
        if mba is None:
            logger.info("LFG NOP: snapshot.mba is None, bailing")
            return [], set()
        logger.info(
            "LFG NOP: stkoff=0x%x, mba.qty=%d, bst_node_blocks=%s",
            stkoff, mba.qty, sorted(bst_node_blocks),
        )

        modifications: list = []
        nop_blocks: set[int] = set()
        nop_count = 0
        blocks_scanned = 0
        serial = -1

        try:
            for blk_idx in range(mba.qty):  # type: ignore[attr-defined]
                try:
                    blk = mba.get_mblock(blk_idx)  # type: ignore[attr-defined]
                except (AttributeError, IndexError):
                    continue
                if blk is None:
                    continue

                serial = blk.serial

                # Skip BST node blocks -- they READ the state variable
                # (comparison blocks), not write it.
                if serial in bst_node_blocks:
                    continue

                blocks_scanned += 1
                insn = blk.head
                while insn is not None:
                    # Check if the destination operand writes to the state variable.
                    d = insn.d
                    if (
                        d is not None
                        and d.t == ida_hexrays.mop_S
                        and d.s is not None
                        and d.s.off == stkoff
                    ):
                        modifications.append(
                            builder.nop_instruction(
                                source_block=serial,
                                instruction_ea=insn.ea,
                            )
                        )
                        nop_blocks.add(serial)
                        nop_count += 1
                    insn = insn.next
        except Exception as exc:
            logger.info(
                "LFG NOP: scan loop CRASHED at blk[%d] after scanning %d blocks, "
                "%d NOPs so far: %s",
                serial, blocks_scanned, nop_count, exc,
            )

        logger.info(
            "LFG: NOP'd %d state variable writes across %d blocks "
            "(scanned %d of %d total, excluded %d BST node blocks)",
            nop_count,
            len(nop_blocks),
            blocks_scanned,
            mba.qty,
            len(bst_node_blocks),
        )

        return modifications, nop_blocks

    @staticmethod
    def _nop_dispatcher_gotos(
        snapshot: AnalysisSnapshot,
        dispatcher_serial: int,
        bst_node_blocks: set[int],
        builder: ModificationBuilder,
    ) -> tuple[list, int, int]:
        """Disabled -- dispatcher goto NOPs are no longer emitted.

        Previously NOP'd ``m_goto @dispatcher`` instructions in handler blocks.
        This caused issues with blocks becoming unreachable dead-ends before
        the dispatcher was fully disconnected.  The BST disconnect pass
        (step 4) handles dispatcher back-edge removal more safely.

        Returns:
            An empty tuple of ``([], 0, 0)``.
        """
        return [], 0, 0

    @staticmethod
    def _disconnect_bst_comparison_nodes(
        bst_node_blocks: set[int],
        dispatcher_serial: int,
        builder: ModificationBuilder,
        modifications: list,
        emitted: set[tuple[int, int]],
    ) -> int:
        """Convert 2-way blocks with dispatcher back-edges to 1-way.

        After linearization, handler exits have been redirected to their
        target handler entries and state variable writes have been NOP'd.
        However, some 2-way blocks (BST comparison nodes or handler
        conditionals) may still have the dispatcher as one successor.
        These back-edges create ``while`` loops in the decompiled output.

        Emits :class:`ConvertToGoto` keeping the non-dispatcher successor.

        Args:
            bst_node_blocks: Set of BST comparison block serials.
            dispatcher_serial: Serial of the dispatcher entry block.
            builder: Modification builder for emitting graph edits.
            modifications: List to append new modifications to.
            emitted: Set of ``(from, to)`` pairs for dedup.

        Returns:
            Number of blocks disconnected from the dispatcher.
        """
        if dispatcher_serial < 0:
            return 0

        # Build set of block serials that already have a redirect from
        # the main handler-linearization pass.  These blocks must NOT
        # receive a second conflicting redirect.
        already_redirected: set[int] = {src for src, _ in emitted}

        disconnect_count = 0
        # Scan ALL blocks in the flow graph, not just BST nodes.
        for serial in sorted(builder.block_nsucc_map):
            # Skip the dispatcher itself.
            if serial == dispatcher_serial:
                continue
            # Skip blocks already handled by the main redirect pass.
            if serial in already_redirected:
                continue

            nsucc = builder.block_nsucc_map.get(serial, 0)
            if nsucc != 2:
                continue

            succs = list(builder.block_succ_map.get(serial, ()))
            if len(succs) != 2:
                continue

            succ0, succ1 = succs[0], succs[1]

            # Check if either successor is the dispatcher.
            if succ0 != dispatcher_serial and succ1 != dispatcher_serial:
                continue

            # Keep the non-dispatcher successor.
            keep_serial = succ1 if succ0 == dispatcher_serial else succ0

            emit_key = (serial, keep_serial)
            if emit_key in emitted:
                continue
            emitted.add(emit_key)

            mod = builder.convert_to_goto(serial, keep_serial)
            modifications.append(mod)
            disconnect_count += 1

            is_bst = serial in bst_node_blocks
            logger.info(
                "BST_DISCONNECT: blk[%d] (%s) 2-way -> 1-way goto "
                "blk[%d] (removed dispatcher back-edge to blk[%d])",
                serial,
                "BST" if is_bst else "handler",
                keep_serial,
                dispatcher_serial,
            )

        return disconnect_count

    @staticmethod
    def _disconnect_bst_entries(
        bst_node_blocks: set[int],
        builder: ModificationBuilder,
        owned_edges: set[tuple[int, int]],
        modifications: list,
        emitted: set[tuple[int, int]],
        stop_serial: int = -1,
    ) -> int:
        """Disconnect BST leaf -> handler entry edges.

        After linearization, handler entries are reachable via goto chains.
        BST leaf comparison nodes still have edges pointing to handler entries,
        keeping the BST tree alive in the decompiled output.  This pass
        redirects those BST leaf -> handler edges to BLT_STOP, making
        handler entries ONLY reachable via the linearized goto chain.
        The BST tree becomes dead-ended and IDA DCEs it.

        Args:
            bst_node_blocks: Set of BST node block serials.
            builder: Modification builder for emitting edge redirects.
            owned_edges: Set of (from, to) edges from the linearization pass.
            modifications: List to append new modifications to.
            emitted: Set of (from, to) pairs for dedup.
            stop_serial: Serial of BLT_STOP block (redirect target).

        Returns:
            Number of BST leaf edges disconnected.
        """
        if stop_serial < 0:
            return 0
        linearized_entries: set[int] = {target for _, target in owned_edges}

        disconnect_count = 0
        disconnected_nodes: set[int] = set()
        for bst_serial in sorted(bst_node_blocks):
            nsucc = builder.block_nsucc_map.get(bst_serial, 0)
            if nsucc != 2:
                continue

            succs = list(builder.block_succ_map.get(bst_serial, ()))
            if len(succs) != 2:
                continue

            for idx, succ in enumerate(succs):
                if bst_serial in disconnected_nodes:
                    break  # only one redirect per BST node
                if succ not in linearized_entries:
                    continue
                if succ in bst_node_blocks:
                    continue  # internal BST edge, not a leaf -> handler
                other_succ = succs[1 - idx]
                if other_succ == stop_serial:
                    continue  # other succ is already BLT_STOP, skip

                emit_key = ("bst_disconnect", bst_serial, succ)
                if emit_key in emitted:
                    continue

                mod = builder.edge_redirect(
                    source_block=bst_serial,
                    target_block=stop_serial,
                    old_target=succ,
                )
                modifications.append(mod)
                emitted.add(emit_key)
                disconnected_nodes.add(bst_serial)
                disconnect_count += 1
                logger.info(
                    "LFG BST-DISCONNECT: blk[%d] edge to handler blk[%d] "
                    "-> redirected to BLT_STOP blk[%d]",
                    bst_serial,
                    succ,
                    stop_serial,
                )

        return disconnect_count

