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
    _mop_matches_stkoff,
    find_bst_default_block,
    find_bst_default_block_snapshot,
)
from d810.recon.flow.bst_model import resolve_target_via_bst
from d810.optimizers.microcode.flow.flattening.hodur._helpers import (
    collect_state_machine_blocks,
    evaluate_handler_paths,
    find_terminal_exit_target,
    find_terminal_exit_target_snapshot,
    resolve_exit_via_bst_default,
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

if TYPE_CHECKING:
    from d810.optimizers.microcode.flow.flattening.hodur.snapshot import (
        AnalysisSnapshot,
    )

logger = logging.getLogger("D810.hodur.strategy.direct_linearization")

__all__ = ["DirectHandlerLinearizationStrategy"]


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

        # K3: live mba_t still required — helper functions (evaluate_handler_paths,
        # find_terminal_exit_target, resolve_exit_via_bst_default, find_bst_default_block,
        # _mop_matches_stkoff) and instruction-chain walks (blk.head/tail/insn.next)
        # all operate on live mblock_t objects.  Only topology-only loops (exit_blocks,
        # adjacency) are migrated to flow_graph above.
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
            # K3: mba required — flow_graph not available in this snapshot
            for i in range(mba.qty):
                blk_i = mba.get_mblock(i)
                succs = []
                if blk_i is not None:
                    if blk_i.nsucc() == 0:
                        exit_blocks.add(i)
                    for j in range(blk_i.nsucc()):
                        succs.append(blk_i.succ(j))
                _preflight_adj[i] = succs

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
            exit_blk = mba.get_mblock(path.exit_block)

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
            _exit_snap = fg.get_block(path.exit_block) if fg is not None else None
            if _exit_snap is not None and _exit_snap.nsucc > 0:
                old_target = _exit_snap.succs[0]
            elif exit_blk is not None and exit_blk.nsucc() > 0:
                old_target = exit_blk.succ(0)

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
                        _seg_src_snap = fg.get_block(seg_src) if fg is not None else None
                        _seg_pred_snap = fg.get_block(seg_pred) if fg is not None else None
                        if _seg_src_snap is not None and _seg_pred_snap is not None:
                            if _seg_src_snap.nsucc != 1:
                                continue
                            if _seg_pred_snap.nsucc != 1:
                                continue
                            if seg_src not in _seg_pred_snap.succs:
                                continue
                        else:
                            seg_src_blk = mba.get_mblock(seg_src)
                            seg_pred_blk = mba.get_mblock(seg_pred)
                            if seg_src_blk is None or seg_pred_blk is None:
                                continue
                            if seg_src_blk.nsucc() != 1:
                                continue
                            if seg_pred_blk.nsucc() != 1:
                                continue
                            if not any(
                                seg_pred_blk.succ(j) == seg_src
                                for j in range(seg_pred_blk.nsucc())
                            ):
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
                _src_snap = fg.get_block(src_block) if fg is not None else None
                if _src_snap is not None:
                    old_target = _src_snap.succs[0] if _src_snap.nsucc > 0 else 0
                else:
                    src_blk = mba.get_mblock(src_block)
                    old_target = src_blk.succ(0) if src_blk is not None and src_blk.nsucc() > 0 else 0
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
                    _exit_snap = fg.get_block(path.exit_block) if fg is not None else None
                    _exit_nsucc = _exit_snap.nsucc if _exit_snap is not None else None
                    if _exit_nsucc is None:
                        exit_blk = mba.get_mblock(path.exit_block)
                        _exit_nsucc = exit_blk.nsucc() if exit_blk is not None else None
                    if _exit_nsucc is not None and _exit_nsucc == 0:
                        # Block already has no successors (true terminal) — nothing to do.
                        logger.info(
                            "Handler blk[%d] (state=0x%x): true terminal exit via blk[%d] (0 succs)",
                            handler_serial,
                            incoming_state,
                            path.exit_block,
                        )
                        resolved_count += 1
                        continue

                    # Exit block still has successors (likely goto dispatcher).
                    # Find the function's terminal exit target (K3.5: snapshot).
                    if fg is not None:
                        terminal_target = find_terminal_exit_target_snapshot(
                            fg, dispatcher_serial, sm_blocks
                        )
                    else:
                        terminal_target = find_terminal_exit_target(
                            mba, dispatcher_serial, sm_blocks
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
                    # K3.4: prefer snapshot for topology-only BST default lookup
                    if fg is not None:
                        bst_default = find_bst_default_block_snapshot(
                            fg,
                            dispatcher_serial,
                            bst_result.bst_node_blocks,
                            set(handler_state_map.keys()),
                        )
                    else:
                        bst_default = find_bst_default_block(
                            mba,
                            dispatcher_serial,
                            bst_result.bst_node_blocks,
                            set(handler_state_map.keys()),
                        )
                    exit_target: int | None = None
                    resolve_label: str = ""
                    if bst_default is not None and path.final_state is not None:
                        # K3.4: prefer snapshot for BST walk with InsnSnapshot
                        if fg is not None:
                            exit_target = resolve_exit_via_bst_default_snapshot(
                                fg, bst_default, path.final_state
                            )
                        else:
                            exit_target = resolve_exit_via_bst_default(
                                mba, bst_default, path.final_state
                            )
                        if exit_target is not None:
                            resolve_label = f"BST default blk[{bst_default}]"
                    if exit_target is None and path.final_state is not None:
                        # K3.4: prefer snapshot for BST root-walk
                        if fg is not None:
                            exit_target = resolve_exit_via_bst_default_snapshot(
                                fg, dispatcher_serial, path.final_state
                            )
                        else:
                            exit_target = resolve_exit_via_bst_default(
                                mba, dispatcher_serial, path.final_state
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
                                exit_blk = mba.get_mblock(exit_target)
                                if exit_blk is not None and exit_target not in bst_node_blocks:
                                    scan_insn = exit_blk.head
                                    while scan_insn is not None:
                                        if (
                                            scan_insn.opcode == ida_hexrays.m_mov
                                            and scan_insn.d is not None
                                            and _mop_matches_stkoff(
                                                scan_insn.d,
                                                state_var_stkoff,
                                                mba=mba,
                                            )
                                        ):
                                            logger.info(
                                                "  NOP dead state_var write in exit target"
                                                " blk[%d] ea=%#x",
                                                exit_target,
                                                scan_insn.ea,
                                            )
                                            _append_nop(

                                                source_block=exit_target,

                                                instruction_ea=scan_insn.ea,

                                            )
                                        scan_insn = scan_insn.next
                                resolved_count += 1
                                owned_transitions.add((incoming_state, path.final_state))
                        elif meta is not None and meta["kind"] in ("already_claimed", "already_claimed_edge"):
                            pass  # already counted
                        else:
                            pass  # conflict, skip
                        continue

                    # Fallback: redirect to bst_default directly (or terminal exit)
                    if bst_default is None:
                        if fg is not None:
                            bst_default = find_terminal_exit_target_snapshot(
                                fg, dispatcher_serial, sm_blocks
                            )
                        else:
                            bst_default = find_terminal_exit_target(
                                mba, dispatcher_serial, sm_blocks
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
                            _wb_snap = fg.get_block(write_blk) if fg is not None else None
                            if _wb_snap is not None:
                                if _wb_snap.npred > 1:
                                    continue
                            else:
                                write_blk_obj = mba.get_mblock(write_blk)
                                if write_blk_obj is not None and write_blk_obj.npred() > 1:
                                    continue
                            _append_nop(

                                source_block=write_blk,

                                instruction_ea=write_ea,

                            )
                        resolved_count += 1
                        owned_transitions.add((incoming_state, path.final_state))

        # ---- BST default back-edge pass ----
        # K3.4: prefer snapshot for topology-only BST default lookup
        if fg is not None:
            bst_default_for_backedge = find_bst_default_block_snapshot(
                fg,
                dispatcher_serial,
                bst_result.bst_node_blocks,
                set(handler_state_map.keys()),
            )
        else:
            bst_default_for_backedge = find_bst_default_block(
                mba,
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
                _bde_snap = fg.get_block(serial) if fg is not None else None
                if _bde_snap is not None:
                    for _s in _bde_snap.succs:
                        bde_queue.append(_s)
                else:
                    blk = mba.get_mblock(serial)
                    if blk is None:
                        continue
                    for i in range(blk.nsucc()):
                        bde_queue.append(blk.succ(i))

            for serial in bst_default_region:
                blk = mba.get_mblock(serial)
                if blk is None:
                    continue
                backedge_succs = [
                    blk.succ(i) for i in range(blk.nsucc())
                    if blk.succ(i) in bst_node_blocks
                ]
                if not backedge_succs:
                    continue

                insn = blk.head
                written_state = None
                state_write_ea = None
                while insn is not None:
                    if insn.opcode == ida_hexrays.m_mov and insn.d is not None:
                        if _mop_matches_stkoff(insn.d, state_var_stkoff, mba=mba):
                            if insn.l is not None and insn.l.t == ida_hexrays.mop_n:
                                written_state = int(insn.l.nnn.value)
                                state_write_ea = insn.ea
                    insn = insn.next

                if written_state is None:
                    continue

                # K3.4: prefer snapshot for BST walk with InsnSnapshot
                if fg is not None:
                    target = resolve_exit_via_bst_default_snapshot(
                        fg, bst_default_for_backedge, written_state
                    )
                else:
                    target = resolve_exit_via_bst_default(
                        mba, bst_default_for_backedge, written_state
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
                        target_blk = mba.get_mblock(target)
                        if target_blk is not None and target not in bst_node_blocks:
                            scan_insn = target_blk.head
                            while scan_insn is not None:
                                if (
                                    scan_insn.opcode == ida_hexrays.m_mov
                                    and scan_insn.d is not None
                                    and _mop_matches_stkoff(
                                        scan_insn.d, state_var_stkoff, mba=mba
                                    )
                                ):
                                    _append_nop(

                                        source_block=target,

                                        instruction_ea=scan_insn.ea,

                                    )
                                scan_insn = scan_insn.next
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
                    _h_exit_snap = fg.get_block(path.exit_block) if fg is not None else None
                    _h_exit_nsucc = _h_exit_snap.nsucc if _h_exit_snap is not None else None
                    if _h_exit_nsucc is None:
                        exit_blk = mba.get_mblock(path.exit_block)
                        _h_exit_nsucc = exit_blk.nsucc() if exit_blk is not None else None
                    if _h_exit_nsucc is not None and _h_exit_nsucc == 0:
                        resolved_count += 1
                        continue  # True terminal, nothing to do.
                    # K3.5: prefer snapshot path
                    if fg is not None:
                        terminal_target = find_terminal_exit_target_snapshot(
                            fg, dispatcher_serial, sm_blocks
                        )
                    else:
                        terminal_target = find_terminal_exit_target(
                            mba, dispatcher_serial, sm_blocks
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
                    # Try BST root-walk (K3.4: prefer snapshot)
                    if fg is not None:
                        target = resolve_exit_via_bst_default_snapshot(
                            fg, dispatcher_serial, path.final_state
                        )
                    else:
                        target = resolve_exit_via_bst_default(
                            mba, dispatcher_serial, path.final_state
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
                            _hwb_snap = fg.get_block(write_blk) if fg is not None else None
                            if _hwb_snap is not None:
                                if _hwb_snap.npred > 1:
                                    continue  # Skip NOP on shared multi-pred blocks
                            else:
                                write_blk_obj = mba.get_mblock(write_blk)
                                if write_blk_obj is not None and write_blk_obj.npred() > 1:
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
            },
        )
