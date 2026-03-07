"""DirectHandlerLinearizationStrategy — core BST-based linearization.

Faithful port of HodurUnflattener._linearize_handlers (first pass only) from
commit 4313af46.  Iterates all detected state machine handlers, runs DFS forward
evaluation to find handler exit paths and their final state values, then proposes
GOTO_REDIRECT / EDGE_REDIRECT / NOP_INSN edits that bypass the dispatcher entirely.
"""
from __future__ import annotations

from collections import deque

import ida_hexrays
from d810.core.typing import TYPE_CHECKING

from d810.core import logging
from d810.cfg.flow.graph_checks import prove_terminal_sink
from d810.recon.flow.bst_analysis import (
    find_bst_default_block_snapshot,
)
from d810.recon.flow.bst_model import resolve_target_via_bst
from d810.optimizers.microcode.flow.flattening.hodur._helpers import (
    collect_state_machine_blocks,
    evaluate_handler_paths,
    find_terminal_exit_target_snapshot,
    resolve_exit_via_bst_default_snapshot,
)
from d810.optimizers.microcode.flow.flattening.hodur._modification_bridge import (
    ModificationBuilder,
)
from d810.optimizers.microcode.flow.flattening.hodur.datamodel import HandlerPathResult
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    FAMILY_DIRECT,
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
)
from d810.recon.flow.transition_builder import (
    _get_state_var_stkoff,
)
from d810.cfg.flow.terminal_return import (
    TerminalCfgSuffixFrontier,
    TerminalSemanticLoweringFrontier,
    TerminalLoweringAction,
    classify_cfg_suffix_action,
    compute_terminal_cfg_suffix_frontier,
)

if TYPE_CHECKING:
    from d810.cfg.flowgraph import FlowGraph
    from d810.optimizers.microcode.flow.flattening.hodur.snapshot import (
        AnalysisSnapshot,
    )

logger = logging.getLogger("D810.hodur.strategy.direct_linearization")

__all__ = ["DirectHandlerLinearizationStrategy"]

# Minimum number of unique normalized anchors (handler body exits redirected
# to the shared epilogue entry) required before Phase 2 suffix privatization
# is emitted.  hodur_func has 3 anchors (benign convergence — IDA structures
# fine), sub_7FFD has 10 (severe fan-in that needs privatization).
_MIN_TERMINAL_ANCHORS_FOR_PRIVATIZATION = 4


def _compute_linear_suffix_chain(
    fg: FlowGraph,
    start_serial: int,
) -> list[int] | None:
    """Walk forward from start_serial following single successors until a 0-succ block.

    Returns the block serial chain [start, ..., return_block] or None if:
    - Any interior block has nsucc != 1
    - The final block has nsucc != 0
    - A cycle is detected
    - Chain length < 2 (degenerate / no shared corridor)
    """
    chain = [start_serial]
    visited = {start_serial}
    current = start_serial
    while True:
        succs = fg.successors(current)
        if len(succs) == 0:
            break  # terminal block found
        if len(succs) != 1:
            return None  # not linear, fail closed
        nxt = succs[0]
        if nxt in visited:
            return None  # cycle
        visited.add(nxt)
        chain.append(nxt)
        current = nxt
    if len(chain) < 2:
        return None  # degenerate, no shared corridor to privatize
    return chain


def _recover_handler_body_exit(
    ordered_path: list[int],
    infrastructure_blocks: frozenset[int],
) -> int | None:
    """Walk backward through DFS ordered_path, skip infrastructure blocks.

    Returns the serial of the last handler-owned block before the path
    enters dispatcher/BST/suffix infrastructure. Returns None if no
    valid body exit is found.
    """
    for serial in reversed(ordered_path):
        if serial not in infrastructure_blocks:
            return serial
    return None


def _mop_matches_stkoff_snapshot(mop_snap: object | None, stkoff: int) -> bool:
    """Snapshot-based equivalent of ``_mop_matches_stkoff`` for ``MopSnapshot``.

    Checks whether a :class:`~d810.cfg.flowgraph.MopSnapshot` represents a
    stack variable operand at the given stack offset.  This avoids touching
    live ``mop_t`` objects.
    """
    if mop_snap is None:
        return False
    return getattr(mop_snap, "stkoff", None) == stkoff


class DirectHandlerLinearizationStrategy:
    """Propose GOTO_REDIRECT / EDGE_REDIRECT / NOP_INSN edits for all resolved handler exits.

    This is a faithful port of HodurUnflattener._linearize_handlers (first pass only)
    from commit 4313af46.  It reads the BST analysis result from the snapshot and,
    for each handler entry, runs DFS forward evaluation, resolves exit states via BST
    lookup, and proposes redirects from handler exit blocks to target handler entries.

    No CFG mutations are performed until execution time; strategies emit
    backend-agnostic graph modifications inside a
    :class:`~d810.optimizers.microcode.flow.flattening.hodur.strategy.PlanFragment`.
    """

    @property
    def name(self) -> str:
        """Return the strategy identifier."""
        return "direct_handler_linearization"

    @property
    def family(self) -> str:
        """Return the strategy family."""
        return FAMILY_DIRECT

    def is_applicable(self, snapshot: AnalysisSnapshot) -> bool:
        """Return True when the snapshot has a BST result with handlers.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            True if bst_result is populated with handler_state_map entries so
            that direct linearization can be attempted.
        """
        bst = snapshot.bst_result
        if bst is None:
            return False
        handler_state_map = getattr(bst, "handler_state_map", None) or {}
        return bool(handler_state_map)

    def plan(self, snapshot: AnalysisSnapshot) -> PlanFragment | None:
        """Produce a PlanFragment with edits for all resolvable handler exits.

        Faithful port of HodurUnflattener._linearize_handlers (first pass, i.e.
        main handler loop + BST back-edge pass + pre-header redirect).  The
        second pass (hidden handler fixpoint closure) is handled by
        HiddenHandlerClosureStrategy.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            A PlanFragment with at least one edit, or None when no work can
            be done.
        """
        if not self.is_applicable(snapshot):
            return None

        # K3: live mba_t still required for DEEP_IDA paths —
        # evaluate_handler_paths calls _forward_eval_insn on live minsn_t.
        # All topology and instruction-chain walks are migrated to flow_graph snapshots.
        mba = snapshot.mba
        bst_result = snapshot.bst_result
        dispatcher_serial: int = snapshot.bst_dispatcher_serial
        state_machine = snapshot.state_machine

        # ---- Resolve state_var_stkoff ----
        # Port of HodurUnflattener._get_effective_state_var_stkoff from 4313af46.
        # First try via detector (which wraps the same logic), then fall back to
        # reading mop_S.s.off directly from the state_machine's state_var mop_t.
        state_var_stkoff: int | None = None
        detector = snapshot.detector
        if detector is not None:
            try:
                state_var_stkoff = _get_state_var_stkoff(detector)
            except Exception:
                pass
        if state_var_stkoff is None and state_machine is not None and state_machine.state_var is not None:
            sv = state_machine.state_var
            try:
                if sv.t == ida_hexrays.mop_S:
                    state_var_stkoff = sv.s.off
            except Exception:
                pass
        if state_var_stkoff is None:
            logger.info("Cannot linearize: state_var_stkoff is None")
            return None

        bst_node_blocks: set[int] = set(getattr(bst_result, "bst_node_blocks", set()) or set())
        bst_node_blocks.add(dispatcher_serial)
        sm_blocks = collect_state_machine_blocks(state_machine)

        # ---- Build all_handlers dict: handler_serial -> incoming_state ----
        all_handlers: dict[int, int] = {}
        handler_state_map: dict = getattr(bst_result, "handler_state_map", {}) or {}
        handler_range_map: dict = getattr(bst_result, "handler_range_map", {}) or {}
        for serial, state in handler_state_map.items():
            all_handlers[serial] = state
        for serial, (low, high) in handler_range_map.items():
            if serial not in all_handlers:
                mid = low if low is not None else (high if high is not None else 0)
                all_handlers[serial] = mid

        builder = ModificationBuilder.from_snapshot(snapshot)
        modifications: list = []
        owned_blocks: set[int] = set()
        owned_edges: set[tuple[int, int]] = set()
        owned_transitions: set[tuple[int, int]] = set()

        resolved_count = 0
        claimed_exits: dict[int, int] = {}
        claimed_edges: dict[tuple[int, int], int] = {}
        bst_rootwalk_targets: set[int] = set()

        # Pass-0 redirect ledger (kept in metadata for G2 / diagnostics)
        pass0_ledger: list[dict] = []
        linearized_blocks: set[int] = set()

        # Accumulate all evaluated handler paths for return site extraction
        all_handler_paths: dict[int, list[HandlerPathResult]] = {}

        # Track terminal exit blocks for semantic gate cycle detection
        terminal_exit_blocks: set[int] = set()

        # Track anchors (exit blocks) that get redirected to the shared terminal target
        terminal_redirect_anchors: set[int] = set()

        # Collect terminal handler paths for Phase 1+2 (body exit normalization + suffix privatization).
        # Deduped by body exit serial — the same handler body exit can appear many
        # times if the handler has multiple conditional DFS paths that all terminate
        # at the return block.  Using a dict keyed by body_exit serial eliminates
        # the O(N^2) explosion (e.g. 368 privatizations for 3 real anchors).
        terminal_body_exit_candidates: dict[int, HandlerPathResult] = {}
        _terminal_paths_total = 0  # diagnostic: total paths before dedup

        handler_entry_set: set[int] = set(all_handlers.keys())
        pre_header_serial: int | None = getattr(bst_result, "pre_header_serial", None)
        forbidden_blocks: set[int] = {dispatcher_serial} | handler_entry_set
        if pre_header_serial is not None:
            forbidden_blocks.add(pre_header_serial)
        # exit_blocks: blocks with 0 successors
        # _preflight_adj: adjacency for prove_terminal_sink validation
        # Use flow_graph snapshot when available to avoid live mba topology walk.
        exit_blocks: set[int] = set()
        _preflight_adj: dict[int, list[int]] = {}
        fg = snapshot.flow_graph
        if fg is not None:
            for serial, blk_snap in fg.blocks.items():
                if blk_snap.nsucc == 0:
                    exit_blocks.add(serial)
                _preflight_adj[serial] = list(blk_snap.succs)
        else:
            raise ValueError("K3: flow_graph is required but not available in snapshot")

        def _queue_redirect(
            path: object,
            target: int,
            reason: str,
        ) -> dict | None:
            """Queue a redirect for one handler exit path.

            Returns a dict with redirect metadata, or None on failure.
            This mirrors _queue_handler_redirect from the original, but instead
            of calling deferred.queue_*, it returns a descriptor that the outer
            function converts to graph modifications.
            """
            # Fast path: exit block not yet claimed by any handler.
            if path.exit_block not in claimed_exits:
                claimed_exits[path.exit_block] = target
                logger.info(
                    "REDIRECT_DECISION: exit_blk=%d target=%d via_pred=None"
                    " decision=plain reason=%s via_pred_npred=None",
                    path.exit_block, target, reason,
                )
                return {
                    "kind": "plain",
                    "source_block": path.exit_block,
                    "via_pred": None,
                    "target": target,
                    "old_target": None,
                }

            # Already claimed for same target — no-op.
            if claimed_exits[path.exit_block] == target:
                return {
                    "kind": "already_claimed",
                    "source_block": path.exit_block,
                    "via_pred": None,
                    "target": target,
                    "old_target": None,
                }

            # Conflict: need edge-level redirect.
            if len(path.ordered_path) >= 2:
                via_pred = path.ordered_path[-2]
            else:
                logger.warning(
                    "EDGE_REDIRECT: no via_pred for exit blk[%d] -> target %d "
                    "(ordered_path too short: %s)",
                    path.exit_block, target, path.ordered_path,
                )
                return None

            old_target = 0
            # K3: TOPOLOGY_ONLY — use flow_graph for succ lookup
            _exit_snap = fg.get_block(path.exit_block)
            if _exit_snap is not None and _exit_snap.nsucc > 0:
                old_target = _exit_snap.succs[0]

            edge_key = (path.exit_block, via_pred)
            if edge_key in claimed_edges:
                if claimed_edges[edge_key] == target:
                    return {
                        "kind": "already_claimed_edge",
                        "source_block": path.exit_block,
                        "via_pred": via_pred,
                        "target": target,
                        "old_target": old_target,
                    }
                # Escalate: walk backward through ordered_path to find an unclaimed edge.
                logger.info(
                    "EDGE_ESCALATION: edge (%d, %d) claimed for %d, searching earlier segment for target %d",
                    path.exit_block, via_pred, claimed_edges[edge_key], target,
                )
                found_src: int | None = None
                found_pred: int | None = None
                for i in range(len(path.ordered_path) - 2, 0, -1):
                    seg_src = path.ordered_path[i]
                    seg_pred = path.ordered_path[i - 1]
                    seg_key = (seg_src, seg_pred)
                    if seg_key not in claimed_edges and seg_src not in bst_node_blocks:
                        # K3: TOPOLOGY_ONLY — use flow_graph for nsucc/succ checks
                        _seg_src_snap = fg.get_block(seg_src)
                        _seg_pred_snap = fg.get_block(seg_pred)
                        if _seg_src_snap is None or _seg_pred_snap is None:
                            continue
                        if _seg_src_snap.nsucc != 1:
                            continue
                        if _seg_pred_snap.nsucc != 1:
                            continue
                        if seg_src not in _seg_pred_snap.succs:
                            continue
                        found_src = seg_src
                        found_pred = seg_pred
                        break
                if found_src is None or found_pred is None:
                    logger.warning(
                        "EDGE_REDIRECT: all path segments claimed for exit blk[%d] -> target %d, "
                        "cannot queue redirect",
                        path.exit_block, target,
                    )
                    return None
                src_block = found_src
                use_pred = found_pred
                # K3: TOPOLOGY_ONLY — use flow_graph for succ lookup
                _src_snap = fg.get_block(src_block)
                old_target = _src_snap.succs[0] if _src_snap is not None and _src_snap.nsucc > 0 else 0
                logger.info(
                    "REDIRECT_DECISION: exit_blk=%d target=%d via_pred=%d"
                    " decision=escalated reason=prior_edge_claimed",
                    path.exit_block, target, use_pred,
                )
            else:
                src_block = path.exit_block
                use_pred = via_pred
                logger.info(
                    "REDIRECT_DECISION: exit_blk=%d target=%d via_pred=%d"
                    " decision=edge_split reason=exit_claimed",
                    path.exit_block, target, use_pred,
                )

            logger.info(
                "EDGE_REDIRECT: exit blk[%d] -> target %d conflicts with claimed=%d; "
                "using edge_redirect(src=%d, old=%d, new=%d, via_pred=%d)",
                path.exit_block, target, claimed_exits[path.exit_block],
                src_block, old_target, target, use_pred,
            )
            claimed_edges[(src_block, use_pred)] = target
            return {
                "kind": "edge",
                "source_block": src_block,
                "via_pred": use_pred,
                "target": target,
                "old_target": old_target,
            }

        def _append_nop(source_block: int, instruction_ea: int) -> None:
            modifications.append(
                builder.nop_instruction(
                    source_block=source_block,
                    instruction_ea=instruction_ea,
                )
            )

        def _emit_redirect(meta: dict, path: object, incoming_state: int, category: str, handler_serial: int) -> bool:
            """Convert redirect metadata into graph modifications."""
            kind = meta["kind"]
            target = meta["target"]
            src_block = meta["source_block"]

            if kind in ("already_claimed", "already_claimed_edge"):
                return True  # Already queued, no new edit needed.

            if kind == "plain":
                modifications.append(
                    builder.goto_redirect(
                        source_block=src_block,
                        target_block=target,
                    )
                )
                owned_blocks.add(src_block)
                owned_edges.add((src_block, target))
                pass0_ledger.append({
                    "category": category,
                    "handler_entry": handler_serial,
                    "incoming_state": incoming_state,
                    "exit_block": path.exit_block,
                    "final_state": path.final_state,
                    "source_block": src_block,
                    "via_pred": None,
                    "target_block": target,
                })
                return True

            if kind == "edge":
                via_pred = meta["via_pred"]
                old_target = meta["old_target"]
                modifications.append(
                    builder.edge_redirect(
                        source_block=src_block,
                        target_block=target,
                        old_target=old_target,
                        via_pred=via_pred,
                        rule_priority=550,
                    )
                )
                owned_blocks.add(src_block)
                owned_edges.add((src_block, target))
                pass0_ledger.append({
                    "category": category,
                    "handler_entry": handler_serial,
                    "incoming_state": incoming_state,
                    "exit_block": path.exit_block,
                    "final_state": path.final_state,
                    "source_block": src_block,
                    "via_pred": via_pred,
                    "target_block": target,
                })
                return True

            return False

        # ---- Main handler loop ----
        for handler_serial, incoming_state in all_handlers.items():
            if handler_serial in bst_node_blocks:
                continue

            # K3: DEEP_IDA — forward eval requires live minsn_t via mba
            paths = evaluate_handler_paths(
                mba=mba,
                entry_serial=handler_serial,
                incoming_state=incoming_state,
                bst_node_blocks=bst_node_blocks,
                state_var_stkoff=state_var_stkoff,
            )

            if not paths:
                logger.debug(
                    "Handler blk[%d] (state 0x%x): no exit paths found, deferring to legacy",
                    handler_serial,
                    incoming_state,
                )
                continue

            all_handler_paths[handler_serial] = list(paths)
            linearized_blocks.add(handler_serial)

            for path in paths:
                if path.final_state is None:
                    # Terminal path — handler exits (e.g. m_ret or 0-succ block).
                    # The exit block may still goto the dispatcher; redirect it to
                    # the function's real exit corridor so it survives DCE.
                    terminal_exit_blocks.add(path.exit_block)
                    # K3: TOPOLOGY_ONLY — use flow_graph for 0-succ check
                    _exit_snap = fg.get_block(path.exit_block)
                    _exit_nsucc = _exit_snap.nsucc if _exit_snap is not None else None
                    if _exit_nsucc is not None and _exit_nsucc == 0:
                        # Block already has no successors (true terminal) — nothing to do.
                        logger.info(
                            "Handler blk[%d] (state=0x%x): true terminal exit via blk[%d] (0 succs)",
                            handler_serial,
                            incoming_state,
                            path.exit_block,
                        )
                        # Early dedup by body exit using partial infrastructure
                        _partial_infra = frozenset(bst_node_blocks | {dispatcher_serial})
                        _body_exit = _recover_handler_body_exit(
                            path.ordered_path, _partial_infra,
                        )
                        _terminal_paths_total += 1
                        if _body_exit is not None and _body_exit not in terminal_body_exit_candidates:
                            terminal_body_exit_candidates[_body_exit] = path
                        resolved_count += 1
                        continue

                    # Exit block still has successors (likely goto dispatcher).
                    # Find the function's terminal exit target (K3.5: snapshot).
                    terminal_target = find_terminal_exit_target_snapshot(
                        fg, dispatcher_serial, sm_blocks
                    )
                    if terminal_target is not None and terminal_target != path.exit_block:
                        # Validate terminal sink before accepting redirect
                        sink_proof = prove_terminal_sink(
                            terminal_target, _preflight_adj, exit_blocks, forbidden_blocks
                        )
                        if not sink_proof.ok:
                            logger.warning(
                                "Handler blk[%d] (state=0x%x): terminal redirect "
                                "blk[%d] -> blk[%d] REJECTED: %s (witness: %s)",
                                handler_serial, incoming_state,
                                path.exit_block, terminal_target,
                                sink_proof.reason, sink_proof.witness_path,
                            )
                            continue

                        _reason = (
                            f"hodur-linear: blk[{handler_serial}] "
                            f"terminal exit blk[{path.exit_block}] -> exit blk[{terminal_target}]"
                        )
                        meta = _queue_redirect(path, terminal_target, _reason)
                        if meta is not None and meta["kind"] not in ("already_claimed", "already_claimed_edge"):
                            ok = _emit_redirect(meta, path, incoming_state, "terminal_exit", handler_serial)
                            if ok:
                                linearized_blocks.add(path.exit_block)
                                # Track redirect target so cycle detector walks from it too
                                terminal_exit_blocks.add(terminal_target)
                                # Track anchor for PrivateTerminalSuffix emission
                                terminal_redirect_anchors.add(path.exit_block)
                                # NOP dead state writes on the terminal path
                                for write_blk, write_ea in path.state_writes:
                                    _append_nop(

                                        source_block=write_blk,

                                        instruction_ea=write_ea,

                                    )
                                logger.info(
                                    "Handler blk[%d] (state=0x%x): terminal exit blk[%d] -> exit blk[%d]",
                                    handler_serial,
                                    incoming_state,
                                    path.exit_block,
                                    terminal_target,
                                )
                        resolved_count += 1
                    else:
                        logger.info(
                            "Handler blk[%d] (state=0x%x): terminal exit via blk[%d] (no redirect target found)",
                            handler_serial,
                            incoming_state,
                            path.exit_block,
                        )
                        resolved_count += 1
                    continue

                target_serial = resolve_target_via_bst(bst_result, path.final_state)

                if target_serial is None:
                    # No handler matches this state value — it's an exit transition.
                    # K3: use flow_graph snapshot for topology-only BST default lookup
                    bst_default = find_bst_default_block_snapshot(
                        fg,
                        dispatcher_serial,
                        bst_result.bst_node_blocks,
                        set(handler_state_map.keys()),
                    )
                    exit_target: int | None = None
                    resolve_label: str = ""
                    if bst_default is not None and path.final_state is not None:
                        # K3: use flow_graph snapshot for BST walk
                        exit_target = resolve_exit_via_bst_default_snapshot(
                            fg, bst_default, path.final_state
                        )
                        if exit_target is not None:
                            resolve_label = f"BST default blk[{bst_default}]"
                    if exit_target is None and path.final_state is not None:
                        # K3: use flow_graph snapshot for BST root-walk
                        exit_target = resolve_exit_via_bst_default_snapshot(
                            fg, dispatcher_serial, path.final_state
                        )
                        if exit_target is not None:
                            resolve_label = "BST root-walk"
                            bst_rootwalk_targets.add(exit_target)
                        if exit_target is not None and exit_target in bst_node_blocks:
                            logger.info(
                                "hodur-linear: handler %d exit state 0x%x resolved to BST internal node blk[%d], skipping",
                                handler_serial,
                                path.final_state,
                                exit_target,
                            )
                            exit_target = None

                    if exit_target is not None:
                        _reason = (
                            f"hodur-linear: blk[{handler_serial}] "
                            f"exit 0x{path.final_state:x} -> {resolve_label} -> blk[{exit_target}]"
                        )
                        meta = _queue_redirect(path, exit_target, _reason)
                        if meta is not None and meta["kind"] not in ("already_claimed", "already_claimed_edge"):
                            ok = _emit_redirect(meta, path, incoming_state, "exit_resolved", handler_serial)
                            if ok:
                                linearized_blocks.add(path.exit_block)
                                # NOP dead state writes in exit path
                                for write_blk, write_ea in path.state_writes:
                                    _append_nop(

                                        source_block=write_blk,

                                        instruction_ea=write_ea,

                                    )
                                # NOP dead state_var writes in the resolved exit target block.
                                # K3: INSN_CHAIN — migrated to snapshot iter_insns
                                _exit_tgt_snap = fg.get_block(exit_target)
                                if _exit_tgt_snap is not None and exit_target not in bst_node_blocks:
                                    for _scan_insn in _exit_tgt_snap.iter_insns():
                                        if (
                                            _scan_insn.opcode == ida_hexrays.m_mov
                                            and _scan_insn.d is not None
                                            and _mop_matches_stkoff_snapshot(
                                                _scan_insn.d,
                                                state_var_stkoff,
                                            )
                                        ):
                                            logger.info(
                                                "  NOP dead state_var write in exit target"
                                                " blk[%d] ea=%#x",
                                                exit_target,
                                                _scan_insn.ea,
                                            )
                                            _append_nop(

                                                source_block=exit_target,

                                                instruction_ea=_scan_insn.ea,

                                            )
                                resolved_count += 1
                                owned_transitions.add((incoming_state, path.final_state))
                        elif meta is not None and meta["kind"] in ("already_claimed", "already_claimed_edge"):
                            pass  # already counted
                        else:
                            pass  # conflict, skip
                        continue

                    # Fallback: redirect to bst_default directly (or terminal exit)
                    if bst_default is None:
                        # K3: use flow_graph snapshot
                        bst_default = find_terminal_exit_target_snapshot(
                            fg, dispatcher_serial, sm_blocks
                        )
                    if bst_default is not None:
                        _reason = (
                            f"hodur-linear: blk[{handler_serial}] "
                            f"exit state 0x{path.final_state:x} -> bst_default blk[{bst_default}]"
                        )
                        meta = _queue_redirect(path, bst_default, _reason)
                        if meta is not None and meta["kind"] not in ("already_claimed", "already_claimed_edge"):
                            ok = _emit_redirect(meta, path, incoming_state, "exit_bst_default", handler_serial)
                            if ok:
                                linearized_blocks.add(path.exit_block)
                                # Keep state variable live for exit paths (no NOP).
                                resolved_count += 1
                                owned_transitions.add((incoming_state, path.final_state))
                    else:
                        logger.debug(
                            "Handler blk[%d]: exit state 0x%x -> no bst_default found, leaving intact",
                            handler_serial,
                            path.final_state,
                        )
                    continue

                # Normal state transition to another handler
                is_self_loop = target_serial == handler_serial
                _reason = (
                    f"hodur-linear: blk[{handler_serial}] "
                    f"0x{incoming_state:x}->0x{path.final_state:x} "
                    f"{'(loop)' if is_self_loop else ''}"
                )
                meta = _queue_redirect(path, target_serial, _reason)
                if meta is not None and meta["kind"] not in ("already_claimed", "already_claimed_edge"):
                    ok = _emit_redirect(meta, path, incoming_state, "state_transition", handler_serial)
                    if ok:
                        linearized_blocks.add(path.exit_block)
                        # NOP dead state writes (skip multi-pred blocks)
                        for write_blk, write_ea in path.state_writes:
                            # K3: TOPOLOGY_ONLY — use flow_graph for npred check
                            _wb_snap = fg.get_block(write_blk)
                            if _wb_snap is not None and _wb_snap.npred > 1:
                                continue
                            _append_nop(

                                source_block=write_blk,

                                instruction_ea=write_ea,

                            )
                        resolved_count += 1
                        owned_transitions.add((incoming_state, path.final_state))

        # ---- BST default back-edge pass ----
        # K3.4: use flow_graph snapshot for topology-only BST default lookup
        bst_default_for_backedge = find_bst_default_block_snapshot(
            fg,
            dispatcher_serial,
            bst_result.bst_node_blocks,
            set(handler_state_map.keys()),
        )
        if bst_default_for_backedge is not None:
            bst_default_region: set[int] = set()
            bde_queue: list[int] = [bst_default_for_backedge]
            handler_serials_set = set(handler_state_map.keys())
            while bde_queue:
                serial = bde_queue.pop()
                if (
                    serial in bst_default_region
                    or serial in bst_node_blocks
                    or serial == dispatcher_serial
                ):
                    continue
                if serial in handler_serials_set:
                    continue
                bst_default_region.add(serial)
                # K3: TOPOLOGY_ONLY — use flow_graph for successor expansion
                _bde_snap = fg.get_block(serial)
                if _bde_snap is not None:
                    for _s in _bde_snap.succs:
                        bde_queue.append(_s)

            for serial in bst_default_region:
                _bde_blk_snap = fg.get_block(serial)
                if _bde_blk_snap is None:
                    continue
                backedge_succs = [
                    s for s in _bde_blk_snap.succs
                    if s in bst_node_blocks
                ]
                if not backedge_succs:
                    continue

                # K3: INSN_CHAIN — migrated to snapshot iter_insns
                written_state = None
                state_write_ea = None
                for insn_snap in _bde_blk_snap.iter_insns():
                    if insn_snap.opcode == ida_hexrays.m_mov and insn_snap.d is not None:
                        if _mop_matches_stkoff_snapshot(insn_snap.d, state_var_stkoff):
                            if (
                                insn_snap.l is not None
                                and insn_snap.l.t == ida_hexrays.mop_n
                                and insn_snap.l.value is not None
                            ):
                                written_state = int(insn_snap.l.value)
                                state_write_ea = insn_snap.ea
                if written_state is None:
                    continue

                # K3.4: use flow_graph snapshot for BST walk
                target = resolve_exit_via_bst_default_snapshot(
                    fg, bst_default_for_backedge, written_state
                )
                if target is None:
                    continue

                logger.info(
                    "  BST default back-edge: blk[%d] state %#x -> resolved blk[%d]",
                    serial,
                    written_state,
                    target,
                )

                _synthetic_path = HandlerPathResult(
                    exit_block=serial,
                    final_state=written_state,
                    state_writes=[],
                    ordered_path=[serial],
                )
                _reason = (
                    f"hodur-linear: BST default blk[{serial}] {written_state:#x}->blk[{target}]"
                )
                meta = _queue_redirect(_synthetic_path, target, _reason)
                if meta is not None and meta["kind"] not in ("already_claimed", "already_claimed_edge"):
                    ok = _emit_redirect(meta, _synthetic_path, written_state, "bst_default_backedge", serial)
                    if ok:
                        if state_write_ea is not None:
                            _append_nop(

                                source_block=serial,

                                instruction_ea=state_write_ea,

                            )
                        # K3: INSN_CHAIN — migrated to snapshot iter_insns
                        _tgt_snap = fg.get_block(target)
                        if _tgt_snap is not None and target not in bst_node_blocks:
                            for _scan_insn in _tgt_snap.iter_insns():
                                if (
                                    _scan_insn.opcode == ida_hexrays.m_mov
                                    and _scan_insn.d is not None
                                    and _mop_matches_stkoff_snapshot(
                                        _scan_insn.d, state_var_stkoff
                                    )
                                ):
                                    _append_nop(

                                        source_block=target,

                                        instruction_ea=_scan_insn.ea,

                                    )
                        resolved_count += 1

        # ---- PASS 2: Hidden handler fixpoint closure ----
        # Iterate bst_rootwalk_targets collected during pass 1.
        # For each hidden handler entry, run DFS forward eval, resolve exits,
        # and emit redirects.  Continue until no new hidden handlers are found
        # (fixpoint convergence).
        hidden_worklist: deque[int] = deque(bst_rootwalk_targets)
        hidden_seen: set[int] = set(bst_rootwalk_targets)
        hidden_processed: set[int] = set()
        hidden_redirects_seen: set[tuple[int, int, int, int]] = set()

        while hidden_worklist:
            rootwalk_blk = hidden_worklist.popleft()
            if rootwalk_blk in hidden_processed:
                continue
            hidden_processed.add(rootwalk_blk)
            if rootwalk_blk in bst_node_blocks:
                continue  # Skip actual BST comparison nodes
            try:
                # K3: DEEP_IDA — forward eval requires live minsn_t via mba
                hidden_paths = evaluate_handler_paths(
                    mba=mba,
                    entry_serial=rootwalk_blk,
                    incoming_state=0,
                    bst_node_blocks=bst_node_blocks,
                    state_var_stkoff=state_var_stkoff,
                )
            except Exception:
                continue

            for path in hidden_paths:
                if path.final_state is None:
                    # Terminal path — redirect to function exit if the block
                    # still has successors (goto dispatcher).
                    terminal_exit_blocks.add(path.exit_block)
                    # K3: TOPOLOGY_ONLY — use flow_graph for 0-succ check
                    _h_exit_snap = fg.get_block(path.exit_block)
                    _h_exit_nsucc = _h_exit_snap.nsucc if _h_exit_snap is not None else None
                    if _h_exit_nsucc is not None and _h_exit_nsucc == 0:
                        # Early dedup by body exit using partial infrastructure
                        _partial_infra_h = frozenset(bst_node_blocks | {dispatcher_serial})
                        _body_exit_h = _recover_handler_body_exit(
                            path.ordered_path, _partial_infra_h,
                        )
                        _terminal_paths_total += 1
                        if _body_exit_h is not None and _body_exit_h not in terminal_body_exit_candidates:
                            terminal_body_exit_candidates[_body_exit_h] = path
                        resolved_count += 1
                        continue  # True terminal, nothing to do.
                    # K3.5: use flow_graph snapshot
                    terminal_target = find_terminal_exit_target_snapshot(
                        fg, dispatcher_serial, sm_blocks
                    )
                    if terminal_target is not None and terminal_target != path.exit_block:
                        # Validate terminal sink before accepting redirect
                        sink_proof = prove_terminal_sink(
                            terminal_target, _preflight_adj, exit_blocks, forbidden_blocks
                        )
                        if not sink_proof.ok:
                            logger.warning(
                                "Hidden blk[%d]: terminal redirect "
                                "blk[%d] -> blk[%d] REJECTED: %s (witness: %s)",
                                rootwalk_blk,
                                path.exit_block, terminal_target,
                                sink_proof.reason, sink_proof.witness_path,
                            )
                            resolved_count += 1
                            continue

                        _reason = (
                            f"hodur-linear: hidden blk[{rootwalk_blk}] "
                            f"terminal exit blk[{path.exit_block}] -> exit blk[{terminal_target}]"
                        )
                        meta = _queue_redirect(path, terminal_target, _reason)
                        if meta is not None and meta["kind"] not in ("already_claimed", "already_claimed_edge"):
                            ok = _emit_redirect(meta, path, 0, "hidden_terminal_exit", rootwalk_blk)
                            if ok:
                                linearized_blocks.add(path.exit_block)
                                # Track redirect target so cycle detector walks from it too
                                terminal_exit_blocks.add(terminal_target)
                                # Track anchor for PrivateTerminalSuffix emission
                                terminal_redirect_anchors.add(path.exit_block)
                                for write_blk, write_ea in path.state_writes:
                                    _append_nop(

                                        source_block=write_blk,

                                        instruction_ea=write_ea,

                                    )
                                logger.info(
                                    "hodur-linear: hidden blk[%d] terminal exit blk[%d] -> exit blk[%d]",
                                    rootwalk_blk,
                                    path.exit_block,
                                    terminal_target,
                                )
                        resolved_count += 1
                    else:
                        resolved_count += 1
                    continue

                # Try exact BST resolution first
                target = resolve_target_via_bst(bst_result, path.final_state)
                if target is None:
                    # Try BST root-walk (K3: use flow_graph snapshot)
                    target = resolve_exit_via_bst_default_snapshot(
                        fg, dispatcher_serial, path.final_state
                    )
                    # Chain detection diagnostic
                    if (
                        target is not None
                        and target not in bst_node_blocks
                        and target not in all_handlers
                    ):
                        logger.info(
                            "Chain candidate: hidden blk[%d] exit -> blk[%d] "
                            "(not a known handler, potential chained hidden handler)",
                            rootwalk_blk,
                            target,
                        )
                if target is None:
                    continue
                if target in bst_node_blocks:
                    continue  # Don't redirect to BST internal nodes
                if target == path.exit_block:
                    logger.info(
                        "hodur-linear: hidden-handler blk[%d] exit_blk=%d resolved to itself, skipping",
                        rootwalk_blk,
                        path.exit_block,
                    )
                    continue

                if target not in all_handlers and target not in hidden_seen:
                    hidden_seen.add(target)
                    hidden_worklist.append(target)
                    logger.info(
                        "Queued chained hidden handler: blk[%d] from hidden blk[%d] state=0x%x",
                        target,
                        rootwalk_blk,
                        path.final_state,
                    )

                hidden_key = (rootwalk_blk, path.exit_block, path.final_state, target)
                if hidden_key in hidden_redirects_seen:
                    logger.info(
                        "hodur-linear: hidden-handler duplicate redirect skipped "
                        "blk[%d] exit_blk=%d state=0x%x target=%d",
                        rootwalk_blk,
                        path.exit_block,
                        path.final_state,
                        target,
                    )
                    continue
                hidden_redirects_seen.add(hidden_key)

                _reason = (
                    f"hodur-linear: hidden-handler blk[{rootwalk_blk}]"
                    f" exit 0x{path.final_state:x} -> blk[{target}]"
                )
                meta = _queue_redirect(path, target, _reason)
                if meta is not None and meta["kind"] not in ("already_claimed", "already_claimed_edge"):
                    ok = _emit_redirect(meta, path, 0, "hidden_handler", rootwalk_blk)
                    if ok:
                        linearized_blocks.add(path.exit_block)
                        logger.info(
                            "hodur-linear: hidden-handler blk[%d] exit_blk=%d -> target blk[%d] (state 0x%x)",
                            rootwalk_blk,
                            path.exit_block,
                            target,
                            path.final_state,
                        )
                        for write_blk, write_ea in path.state_writes:
                            # K3: TOPOLOGY_ONLY — use flow_graph for npred check
                            _hwb_snap = fg.get_block(write_blk)
                            if _hwb_snap is not None and _hwb_snap.npred > 1:
                                continue  # Skip NOP on shared multi-pred blocks
                            _append_nop(

                                source_block=write_blk,

                                instruction_ea=write_ea,

                            )
                        resolved_count += 1

        # ---- Pre-header redirect ----
        initial_state = getattr(bst_result, "initial_state", None)
        pre_header_serial = getattr(bst_result, "pre_header_serial", None)
        if initial_state is not None and pre_header_serial is not None:
            initial_handler = resolve_target_via_bst(bst_result, initial_state)
            if initial_handler is not None:
                _reason = "hodur-linear: pre-header -> initial handler"
                modifications.append(
                    builder.goto_redirect(
                        source_block=pre_header_serial,
                        target_block=initial_handler,
                    )
                )
                owned_blocks.add(pre_header_serial)
                owned_edges.add((pre_header_serial, initial_handler))
                pass0_ledger.append({
                    "category": "preheader",
                    "handler_entry": pre_header_serial,
                    "incoming_state": initial_state,
                    "exit_block": pre_header_serial,
                    "final_state": initial_state,
                    "source_block": pre_header_serial,
                    "via_pred": None,
                    "target_block": initial_handler,
                })
                resolved_count += 1

        logger.info(
            "Hodur direct linearization: %d transitions resolved for %d handlers",
            resolved_count,
            len(all_handlers),
        )

        # --- Phase 1+2: Terminal exit normalization + suffix privatization ---
        # NOTE: Emission is DISABLED (diagnostic-only). The backward walk in
        # _recover_handler_body_exit does not encode ownership — it collapsed
        # 11 terminal paths to 1 body exit for sub_7FFD and caused 31 gotos
        # regression on hodur_func.  Infrastructure is preserved for future
        # forward-ownership approach.
        private_suffix_count = 0
        cfg_frontier: TerminalCfgSuffixFrontier | None = None
        if terminal_body_exit_candidates:
            terminal_target_for_suffix = find_terminal_exit_target_snapshot(
                fg, dispatcher_serial, sm_blocks
            )
            if terminal_target_for_suffix is not None:
                cfg_frontier = compute_terminal_cfg_suffix_frontier(
                    return_block_serial=terminal_target_for_suffix,
                    predecessors_of=fg.predecessors,
                )
                shared_entry = cfg_frontier.shared_entry_serial
                return_block = cfg_frontier.return_block_serial
                suffix_serials = cfg_frontier.suffix_serials

                # Full infrastructure blocks (including suffix) for re-validation
                infrastructure = frozenset(
                    bst_node_blocks | {dispatcher_serial} | set(suffix_serials)
                )

                # Phase 1: Re-validate body exits with full infrastructure (DIAGNOSTIC ONLY — no emission)
                normalized_anchors: set[int] = set()
                for body_exit_candidate, path in terminal_body_exit_candidates.items():
                    # Re-recover with full infrastructure (includes suffix_serials)
                    body_exit = _recover_handler_body_exit(
                        path.ordered_path, infrastructure
                    )
                    if body_exit is None:
                        logger.info(
                            "DIAGNOSTIC: PTS: no body exit for terminal path ending at blk[%d]",
                            path.exit_block,
                        )
                        continue

                    # Validate: body_exit must be a 1-succ block pointing into infrastructure
                    body_exit_snap = fg.get_block(body_exit)
                    if body_exit_snap is None or body_exit_snap.nsucc != 1:
                        logger.info(
                            "DIAGNOSTIC: PTS: body exit blk[%d] has nsucc=%d, skipping",
                            body_exit,
                            body_exit_snap.nsucc if body_exit_snap is not None else -1,
                        )
                        continue

                    current_succ = body_exit_snap.succs[0]
                    if current_succ not in infrastructure:
                        logger.info(
                            "DIAGNOSTIC: PTS: body exit blk[%d] succ blk[%d] not in infrastructure, skipping",
                            body_exit,
                            current_succ,
                        )
                        continue

                    if body_exit in normalized_anchors:
                        continue  # already processed (safety net)

                    # EMISSION DISABLED — would have been:
                    # modifications.append(builder.goto_redirect(source_block=body_exit, target_block=shared_entry))
                    normalized_anchors.add(body_exit)
                    # EMISSION DISABLED — do NOT modify owned_blocks or owned_edges

                    # EMISSION DISABLED — would have NOP'd state writes:
                    # for write_blk, write_ea in path.state_writes:
                    #     _append_nop(source_block=write_blk, instruction_ea=write_ea)

                    logger.info(
                        "DIAGNOSTIC: PTS Phase 1: would normalize blk[%d] -> blk[%d] (shared_entry)",
                        body_exit,
                        shared_entry,
                    )

                # Diagnostic summary before Phase 2 gate
                logger.info(
                    "DIAGNOSTIC: PTS summary: %d terminal paths seen, %d unique body exits, "
                    "%d normalized anchors, suffix=blk[%d]->blk[%d] (%d blocks)",
                    _terminal_paths_total,
                    len(terminal_body_exit_candidates),
                    len(normalized_anchors),
                    shared_entry,
                    return_block,
                    len(suffix_serials),
                )

                # Phase 2: Classify but do NOT emit PTS (DIAGNOSTIC ONLY)
                semantic_frontier = classify_cfg_suffix_action(cfg_frontier)
                if semantic_frontier.action != TerminalLoweringAction.PRIVATE_TERMINAL_SUFFIX:
                    logger.info(
                        "DIAGNOSTIC: PTS: semantic action guard rejected emission: %s",
                        semantic_frontier.summary(),
                    )
                elif len(normalized_anchors) < _MIN_TERMINAL_ANCHORS_FOR_PRIVATIZATION:
                    logger.info(
                        "DIAGNOSTIC: PTS: anchor count guard suppressed emission: "
                        "%d anchors < %d minimum",
                        len(normalized_anchors),
                        _MIN_TERMINAL_ANCHORS_FOR_PRIVATIZATION,
                    )
                elif (
                    len(suffix_serials) >= 2
                    and cfg_frontier.shared_entry_serial != cfg_frontier.return_block_serial
                ):
                    # EMISSION DISABLED — would have emitted:
                    # for anchor in sorted(normalized_anchors):
                    #     modifications.append(builder.private_terminal_suffix(...))
                    # private_suffix_count = len(normalized_anchors)
                    logger.info(
                        "DIAGNOSTIC: PTS Phase 2: would emit %d privatizations for suffix blk[%d]->blk[%d] (semantic: %s)",
                        len(normalized_anchors),
                        shared_entry,
                        return_block,
                        semantic_frontier.summary(),
                    )
                else:
                    logger.info(
                        "DIAGNOSTIC: PTS: guards not met -- %d anchors, %d suffix blocks",
                        len(normalized_anchors),
                        len(suffix_serials),
                    )

        # --- Forward ownership-frontier diagnostic ---
        # Uses forward walk through ordered_path to find the last non-infra block
        # before the first infrastructure block — a more principled body exit
        # candidate than the backward walk in _recover_handler_body_exit.
        if terminal_body_exit_candidates and cfg_frontier is not None:
            suffix_set = set(cfg_frontier.suffix_serials)
            full_infra = frozenset(
                bst_node_blocks | {dispatcher_serial} | suffix_set
            )
            if pre_header_serial is not None:
                full_infra = full_infra | {pre_header_serial}

            # Count candidate frequency across all terminal paths
            candidate_frequency: dict[int, int] = {}
            forward_candidates: list[tuple[int | None, int | None, int | None]] = []

            for _body_exit_key, path in terminal_body_exit_candidates.items():
                handler_entry = path.ordered_path[0] if path.ordered_path else None

                # Forward walk: find first infra block, previous block is candidate
                candidate: int | None = None
                candidate_succ: int | None = None
                prev_block: int | None = None
                for blk_serial in path.ordered_path:
                    if blk_serial in full_infra:
                        candidate = prev_block
                        candidate_succ = blk_serial
                        break
                    prev_block = blk_serial

                forward_candidates.append((handler_entry, candidate, candidate_succ))
                if candidate is not None:
                    candidate_frequency[candidate] = candidate_frequency.get(candidate, 0) + 1

            # Log the diagnostic
            for handler_entry, candidate, candidate_succ in forward_candidates:
                freq = candidate_frequency.get(candidate, 0) if candidate is not None else 0
                cand_snap = fg.get_block(candidate) if candidate is not None else None
                cand_nsucc = cand_snap.nsucc if cand_snap is not None else -1
                cand_succs = list(cand_snap.succs) if cand_snap is not None else []

                is_valid = (
                    candidate is not None
                    and candidate not in full_infra
                    and cand_nsucc == 1
                    and (cand_succs[0] in full_infra if cand_succs else False)
                    and freq == 1  # not shared across handlers
                )

                logger.info(
                    "PTS forward-frontier DIAGNOSTIC: handler=blk[%s] candidate=blk[%s] "
                    "succ=blk[%s] nsucc=%d freq=%d valid=%s",
                    handler_entry, candidate, candidate_succ, cand_nsucc, freq, is_valid,
                )

            # Summary
            valid_count = sum(
                1 for _, c, _ in forward_candidates
                if c is not None and candidate_frequency.get(c, 0) == 1
            )
            logger.info(
                "PTS forward-frontier summary: %d terminal paths, %d unique candidates, "
                "%d valid (freq==1, 1-succ, succ-in-infra), suffix=%s",
                len(forward_candidates),
                len(candidate_frequency),
                valid_count,
                "blk[%d]->blk[%d]" % (cfg_frontier.shared_entry_serial, cfg_frontier.return_block_serial),
            )

        if not modifications:
            return None

        # Claim BST node blocks as influenced.
        owned_blocks.update(bst_node_blocks)

        ownership = OwnershipScope(
            blocks=frozenset(owned_blocks),
            edges=frozenset(owned_edges),
            transitions=frozenset(owned_transitions),
        )
        benefit = BenefitMetrics(
            handlers_resolved=len(all_handlers),
            transitions_resolved=resolved_count,
            blocks_freed=len(bst_node_blocks),
            conflict_density=0.0,
        )
        return PlanFragment(
            strategy_name=self.name,
            family=self.family,
            modifications=modifications,
            ownership=ownership,
            prerequisites=[],
            expected_benefit=benefit,
            risk_score=0.1,
            # Store ledger and bookkeeping for diagnostics.
            # hidden_processed: set of hidden handler serials processed in Pass 2.
            metadata={
                "pass0_redirect_ledger": pass0_ledger,
                "linearized_blocks": linearized_blocks,
                "bst_rootwalk_targets": bst_rootwalk_targets,
                "hidden_processed": hidden_processed,
                "resolved_transitions": set(owned_transitions),
                "handler_paths": all_handler_paths,
                "handler_entry_serials": set(all_handlers.keys()),
                "terminal_exit_blocks": terminal_exit_blocks,
                "dispatcher_serial": dispatcher_serial,
                "forbidden_blocks": forbidden_blocks,
                "exit_blocks": exit_blocks,
                "pre_header_serial": pre_header_serial,
                "private_terminal_suffix_count": private_suffix_count,
            },
        )
