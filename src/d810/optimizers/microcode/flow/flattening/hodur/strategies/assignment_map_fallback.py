"""AssignmentMapFallbackStrategy — resolve remaining back-edges via assignment_map.

After all transition patches, some handler exit blocks may still have back-edges
to the dispatcher.  These blocks contain state assignments that identify their
target handler.  This strategy uses ``state_machine.assignment_map`` to find
those assignments and proposes NOP_INSN edits for dead state writes plus
GOTO_REDIRECT edits for the remaining back-edges.

Corresponds to ``HodurUnflattener._resolve_remaining_via_assignment_map`` and
``_queue_state_assignment_removals``.
"""
from __future__ import annotations

import ida_hexrays
from d810.core.typing import TYPE_CHECKING

from d810.core import logging
from d810.cfg.flowgraph import BlockSnapshot, FlowGraph, InsnSnapshot
from d810.optimizers.microcode.flow.flattening.hodur.analysis import (
    HODUR_STATE_CHECK_OPCODES,
    HodurStateMachineDetector,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    FAMILY_FALLBACK,
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
)
from d810.optimizers.microcode.flow.flattening.hodur._modification_bridge import (
    ModificationBuilder,
)

if TYPE_CHECKING:
    from d810.optimizers.microcode.flow.flattening.hodur.snapshot import (
        AnalysisSnapshot,
    )

logger = logging.getLogger("D810.hodur.strategy.assignment_map_fallback")

__all__ = ["AssignmentMapFallbackStrategy"]


class AssignmentMapFallbackStrategy:
    """Propose NOP_INSN and GOTO_REDIRECT edits via assignment_map lookup.

    Part 1 (``_queue_state_assignment_removals``): NOPs dead state variable
    writes in handler blocks.  Iterates all handler body blocks, finds
    ``m_mov`` of a state constant to the state variable, and emits NOP_INSN
    edits.

    Part 2 (``_resolve_remaining_via_assignment_map``): For unresolved handler
    exits that still target dispatcher check blocks, uses ``assignment_map`` to
    determine the target state, resolves to a handler entry, and emits
    GOTO_REDIRECT edits.  2-way exit blocks outside the state machine region
    are handled via BLOCK_DUPLICATE (not yet implemented in the executor -- the
    edit is emitted as a warning placeholder).

    Prerequisites: ``direct_handler_linearization`` must have run first.
    """

    @property
    def name(self) -> str:
        """Return the strategy identifier."""
        return "assignment_map_fallback"

    @property
    def family(self) -> str:
        """Return the strategy family."""
        return FAMILY_FALLBACK

    def is_applicable(self, snapshot: AnalysisSnapshot) -> bool:
        """Return True when the state machine has an assignment_map.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            True if ``state_machine.assignment_map`` is non-empty.
        """
        sm = snapshot.state_machine
        if sm is None:
            return False
        assignment_map = getattr(sm, "assignment_map", None)
        state_var = getattr(sm, "state_var", None)
        return bool(assignment_map) and state_var is not None

    def plan(self, snapshot: AnalysisSnapshot) -> PlanFragment | None:
        """Produce a PlanFragment with NOP_INSN and GOTO_REDIRECT edits.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            A PlanFragment with dead-assignment NOP edits and remaining
            back-edge redirects, or None when no assignment_map data exists.
        """
        if not self.is_applicable(snapshot):
            return None

        from d810.optimizers.microcode.flow.flattening.hodur._helpers import (
            collect_state_machine_blocks,
            find_terminal_exit_target_snapshot,
        )

        # K3: fully migrated to FlowGraph — no mba/get_mblock refs remain.
        fg = snapshot.flow_graph
        sm = snapshot.state_machine
        handlers = getattr(sm, "handlers", {}) or {}
        state_constants: set = getattr(sm, "state_constants", set()) or set()
        assignment_map: dict = getattr(sm, "assignment_map", {}) or {}
        state_var = getattr(sm, "state_var", None)
        detector = snapshot.detector

        if not handlers or state_var is None:
            return None

        builder = ModificationBuilder.from_snapshot(snapshot)
        modifications: list = []
        owned_blocks: set[int] = set()

        state_machine_blocks = collect_state_machine_blocks(sm)

        # --- Part 1: NOP dead state variable assignments ---
        self._queue_state_assignment_removals(
            sm=sm,
            handlers=handlers,
            state_constants=state_constants,
            state_var=state_var,
            ida_hexrays=ida_hexrays,
            edits=modifications,
            owned_blocks=owned_blocks,
            builder=builder,
            flow_graph=fg,
        )

        # --- Part 2: resolve remaining back-edges via assignment_map ---
        self._resolve_remaining_via_assignment_map(
            sm=sm,
            handlers=handlers,
            assignment_map=assignment_map,
            state_var=state_var,
            state_machine_blocks=state_machine_blocks,
            find_terminal_exit_target_snapshot=find_terminal_exit_target_snapshot,
            detector=detector,
            ida_hexrays=ida_hexrays,
            edits=modifications,
            owned_blocks=owned_blocks,
            builder=builder,
            flow_graph=fg,
        )

        if not modifications:
            return None

        ownership = OwnershipScope(
            blocks=frozenset(owned_blocks),
            edges=frozenset(),
            transitions=frozenset(),
        )
        benefit = BenefitMetrics(
            handlers_resolved=0,
            transitions_resolved=len(assignment_map),
            blocks_freed=len(assignment_map),
            conflict_density=0.2,
        )
        return PlanFragment(
            strategy_name=self.name,
            family=self.family,
            modifications=modifications,
            ownership=ownership,
            prerequisites=["direct_handler_linearization"],
            expected_benefit=benefit,
            risk_score=0.25,
        )

    # -------------------------------------------------------------------------
    # Private helpers -- ported from HodurUnflattener
    # -------------------------------------------------------------------------

    def _find_state_write_in_block(
        self,
        blk: object,
        state_var: object,
        state_constants: set,
        ida_hexrays: object,
    ) -> list[tuple[int, int]]:
        """Scan block instructions for m_mov of state constant to state_var.

        Args:
            blk: Live mblock_t.
            state_var: mop_t for the state variable.
            state_constants: Set of known state constant values.
            ida_hexrays: The ida_hexrays module (IDA runtime).

        Returns:
            List of (block_serial, insn_ea) tuples for matching instructions.
        """
        results: list[tuple[int, int]] = []
        insn = blk.head
        while insn:
            if (
                insn.opcode == ida_hexrays.m_mov
                and insn.l is not None
                and insn.l.t == ida_hexrays.mop_n
                and insn.l.nnn.value in state_constants
                and insn.d is not None
                and insn.d.t == state_var.t
                and insn.d.size == state_var.size
            ):
                results.append((blk.serial, insn.ea))
            insn = insn.next
        return results

    @staticmethod
    def _find_state_write_in_snapshot(
        block_snap: BlockSnapshot,
        state_var_t: int,
        state_var_size: int,
        state_constants: set,
        m_mov: int,
        mop_n: int,
    ) -> list[tuple[int, int]]:
        """Scan a BlockSnapshot for m_mov of state constant to state_var (K3.6).

        Snapshot-based equivalent of :meth:`_find_state_write_in_block` that
        operates on :class:`BlockSnapshot` / :class:`InsnSnapshot` instead of
        live IDA objects.

        Args:
            block_snap: BlockSnapshot for the block.
            state_var_t: mop type of the state variable (e.g. mop_S=3).
            state_var_size: Size in bytes of the state variable operand.
            state_constants: Set of known state constant values.
            m_mov: IDA opcode for m_mov.
            mop_n: IDA mop type for mop_n (numeric constant).

        Returns:
            List of (block_serial, insn_ea) tuples for matching instructions.
        """
        results: list[tuple[int, int]] = []
        for insn in block_snap.iter_insns():
            if (
                insn.opcode == m_mov
                and insn.l is not None
                and insn.l.t == mop_n
                and insn.l.value in state_constants
                and insn.d is not None
                and insn.d.t == state_var_t
                and insn.d.size == state_var_size
            ):
                results.append((block_snap.serial, insn.ea))
        return results

    def _extract_assigned_state_from_block(
        self,
        blk_serial: int,
        assignment_map: dict,
        state_var: object,
    ) -> int | None:
        """Extract the constant state assigned in a block via assignment_map.

        ``assignment_map`` is ``dict[int, list[minsn_t]]`` -- values are lists
        of live microcode instructions, not scalar state values.  Iterate the
        list and return the first ``m_mov`` whose left operand is a numeric
        constant.

        Args:
            blk_serial: Block serial number.
            assignment_map: Mapping of block serial -> list of minsn_t.
            state_var: mop_t for the state variable (used for size masking).

        Returns:
            The assigned state constant value, or None if not found.
        """
        insns = assignment_map.get(blk_serial)
        if not insns:
            return None

        size = getattr(state_var, "size", 4)
        if size not in (1, 2, 4, 8):
            size = 4
        mask = (1 << (size * 8)) - 1

        for insn in insns:
            if insn.opcode == ida_hexrays.m_mov and insn.l is not None and insn.l.t == ida_hexrays.mop_n:
                return int(insn.l.nnn.value) & mask

        return None

    def _queue_state_assignment_removals(
        self,
        sm: object,
        handlers: dict,
        state_constants: set,
        state_var: object,
        ida_hexrays: object,
        edits: list,
        owned_blocks: set[int],
        builder: ModificationBuilder | None = None,
        flow_graph: FlowGraph | None = None,
    ) -> None:
        """NOP dead state variable writes in handler blocks.

        Faithful port of HodurUnflattener._queue_state_assignment_removals
        (the NOP-state-assignment inner loop only -- the terminal back-edge fix
        is handled by TerminalLoopCleanupStrategy in the refactored pipeline).

        K3: fully migrated to FlowGraph — uses ``BlockSnapshot.iter_insns()``
        exclusively.
        """
        if sm is None or state_var is None:
            return

        initial_state = getattr(sm, "initial_state", None)
        if initial_state is None:
            return

        state_var_t: int = getattr(state_var, "t", -1)
        state_var_size: int = getattr(state_var, "size", 4)
        m_mov: int = ida_hexrays.m_mov
        mop_n: int = ida_hexrays.mop_n

        # NOP state variable assignments in handler body blocks.
        for handler in handlers.values():
            for blk_serial in handler.handler_blocks:
                block_snap = flow_graph.get_block(blk_serial) if flow_graph is not None else None
                if block_snap is None:
                    continue

                hits = self._find_state_write_in_snapshot(
                    block_snap,
                    state_var_t=state_var_t,
                    state_var_size=state_var_size,
                    state_constants=state_constants,
                    m_mov=m_mov,
                    mop_n=mop_n,
                )
                for hit_serial, hit_ea in hits:
                    logger.info(
                        "NOPed state assignment in block %d (ea=0x%x)",
                        hit_serial,
                        hit_ea,
                    )
                    if builder is not None:
                        edits.append(
                            builder.nop_instruction(
                                source_block=hit_serial,
                                instruction_ea=hit_ea,
                            )
                        )
                    owned_blocks.add(hit_serial)

    def _resolve_remaining_via_assignment_map(
        self,
        sm: object,
        handlers: dict,
        assignment_map: dict,
        state_var: object,
        state_machine_blocks: set[int],
        find_terminal_exit_target_snapshot: object,
        detector: object = None,
        ida_hexrays: object = None,
        edits: list | None = None,
        owned_blocks: set[int] | None = None,
        builder: ModificationBuilder | None = None,
        flow_graph: FlowGraph | None = None,
    ) -> None:
        """Resolve remaining dispatcher back-edges using assignment_map lookup.

        Faithful port of HodurUnflattener._resolve_remaining_via_assignment_map.

        For unresolved handler exits that still target dispatcher check blocks,
        use assignment_map to directly resolve and redirect them, bypassing
        MopTracker backward tracing which fails on modified CFG.

        K3: fully migrated to FlowGraph — all topology and instruction access
        uses BlockSnapshot/InsnSnapshot exclusively.

        Note: 2-way exit blocks outside the state-machine region are lowered to
        direct ``ConvertToGoto`` edits here. True block duplication remains
        disabled until symbolic duplicate materialization exists.
        """
        if not assignment_map:
            return

        check_blocks = {h.check_block for h in handlers.values()}

        # Collect predecessors of ALL check blocks via FlowGraph.
        preds_to_check: set[tuple[int, int]] = set()
        for cb_serial in check_blocks:
            cb_snap = flow_graph.get_block(cb_serial) if flow_graph is not None else None
            if cb_snap is None:
                continue
            for pred_serial in cb_snap.preds:
                if pred_serial not in check_blocks:
                    preds_to_check.add((pred_serial, cb_serial))

        for pred_serial, dispatcher_target in preds_to_check:
            pred_snap = flow_graph.get_block(pred_serial) if flow_graph is not None else None
            if pred_snap is None:
                continue

            # Handle 2-way exit blocks ONLY outside the state machine region.
            if pred_snap.nsucc == 2:
                if pred_serial not in state_machine_blocks:
                    forward_succs = [
                        s for s in pred_snap.succs if s not in check_blocks
                    ]
                    if forward_succs:
                        forward_target = forward_succs[0]
                        edits.append(
                            builder.convert_to_goto(
                                source_block=pred_serial,
                                target_block=forward_target,
                            )
                        )
                        owned_blocks.add(pred_serial)
                        logger.info(
                            "Assignment-map resolver: converted 2-way exit blk[%d] "
                            "to direct goto blk[%d]",
                            pred_serial,
                            forward_target,
                        )
                continue

            # Only handle 1-way blocks (goto blocks).
            if pred_snap.nsucc != 1:
                continue

            # Try to find state assignment in this block via assignment_map.
            target_state = self._extract_assigned_state_from_block(
                pred_serial, assignment_map, state_var
            )

            # If not found directly, walk backward along single-pred chains.
            if target_state is None:
                walk_serial = pred_serial
                for _ in range(5):  # max backward walk depth
                    walk_snap = flow_graph.get_block(walk_serial) if flow_graph is not None else None
                    if walk_snap is None or walk_snap.npred != 1:
                        break
                    walk_serial = walk_snap.preds[0]
                    target_state = self._extract_assigned_state_from_block(
                        walk_serial, assignment_map, state_var
                    )
                    if target_state is not None:
                        break

            # Also try detector-level extraction if available.
            if target_state is None and detector is not None:
                try:
                    target_state = detector._extract_assigned_state_from_block(
                        pred_serial, assignment_map, state_var
                    )
                except Exception:
                    pass

            if target_state is None:
                continue

            # Terminal states (no handler) should exit the state machine.
            if target_state not in sm.handlers:
                first_ck = min(check_blocks) if check_blocks else None
                if first_ck is not None and find_terminal_exit_target_snapshot is not None:
                    exit_tgt = find_terminal_exit_target_snapshot(
                        flow_graph, first_ck, state_machine_blocks
                    )
                else:
                    exit_tgt = None
                if exit_tgt is not None:
                    edits.append(
                        builder.goto_redirect(
                            source_block=pred_serial,
                            target_block=exit_tgt,
                        )
                    )
                    owned_blocks.add(pred_serial)
                    logger.info(
                        "Assignment-map resolver: terminal state 0x%x "
                        "blk[%d] -> exit blk[%d]",
                        target_state,
                        pred_serial,
                        exit_tgt,
                    )
                continue

            # Find the handler entry for the target state.
            handler_entry = self._resolve_handler_entry(
                dispatcher_target, target_state, handlers, flow_graph
            )
            if handler_entry is None:
                continue

            edits.append(
                builder.goto_redirect(
                    source_block=pred_serial,
                    target_block=handler_entry,
                )
            )
            owned_blocks.add(pred_serial)
            logger.info(
                "Assignment-map resolver: block %d (state 0x%x) -> handler block %d"
                " (via check block %d)",
                pred_serial,
                target_state,
                handler_entry,
                dispatcher_target,
            )

    @staticmethod
    def _extract_check_constant_and_opcode_snapshot(
        insn_snap: InsnSnapshot,
    ) -> tuple[int, int, int] | None:
        """Snapshot equivalent of ``HodurStateMachineDetector._extract_check_constant_and_opcode``.

        Extracts the comparison constant and normalized opcode from a check
        instruction snapshot.  Mirrors the live-object version but reads from
        ``InsnSnapshot.l`` / ``InsnSnapshot.r`` (MopSnapshot) instead of live
        ``minsn_t`` operands.

        Returns:
            (normalized_opcode, constant_value, constant_size) or None.
        """
        mop_n: int = ida_hexrays.mop_n

        # Find the numeric operand (l or r), mirroring extract_num_mop logic.
        num_mop = None
        if insn_snap.l is not None and insn_snap.l.t == mop_n:
            num_mop = insn_snap.l
        elif insn_snap.r is not None and insn_snap.r.t == mop_n:
            num_mop = insn_snap.r

        if num_mop is None or num_mop.value is None:
            return None

        normalized_opcode = insn_snap.opcode
        if insn_snap.l is not None and insn_snap.l.t == mop_n:
            normalized_opcode = (
                HodurStateMachineDetector._swap_jump_opcode_for_reversed_operands(
                    insn_snap.opcode
                )
            )

        return (normalized_opcode, int(num_mop.value), num_mop.size)

    @staticmethod
    def _get_jump_and_fallthrough_targets_snapshot(
        block_snap: BlockSnapshot,
    ) -> tuple[int | None, int | None]:
        """Snapshot equivalent of ``HodurStateMachineDetector._get_jump_and_fallthrough_targets``.

        Returns jump-target and fall-through successor for a conditional block,
        reading from ``BlockSnapshot`` topology instead of live ``mblock_t``.

        Returns:
            (jump_target, fallthrough) or (None, None) if not resolvable.
        """
        mop_b: int = ida_hexrays.mop_b

        tail = block_snap.tail
        if tail is None or tail.d is None or tail.d.t != mop_b:
            return None, None

        jump_target = tail.d.block_ref
        if jump_target is None:
            return None, None

        fallthrough = None
        for succ in block_snap.succs:
            if succ != jump_target:
                fallthrough = succ
                break

        if fallthrough is None:
            # Try serial+1 as fallthrough (common convention).
            candidate = block_snap.serial + 1
            # We don't have flow_graph here, but if serial+1 is not in succs
            # and not the jump target, this fallback mirrors the original logic
            # which checked blk.serial + 1 < blk.mba.qty.
            fallthrough = candidate

        return jump_target, fallthrough

    def _resolve_handler_entry(
        self,
        dispatcher_target: int,
        target_state: int,
        handlers: dict,
        flow_graph: FlowGraph,
    ) -> int | None:
        """Find the handler entry block for the given target state.

        Port of HodurUnflattener._resolve_conditional_chain_target: walks the
        BST conditional-check chain starting from ``dispatcher_target``,
        evaluating each comparison against ``target_state``, until it reaches a
        leaf block that is not a state-check node.  That leaf is the handler
        entry block.

        K3: fully migrated to FlowGraph — uses BlockSnapshot/InsnSnapshot
        exclusively via ``_extract_check_constant_and_opcode_snapshot`` and
        ``_get_jump_and_fallthrough_targets_snapshot``.

        Args:
            dispatcher_target: Check block serial that the predecessor currently
                targets (start of BST walk).
            target_state: Concrete state value to resolve.
            handlers: Mapping of state value -> handler object (unused here,
                kept for context).
            flow_graph: FlowGraph snapshot for block lookups.

        Returns:
            Handler entry block serial (leaf after BST traversal), or None if
            the chain cannot be resolved.
        """
        visited: set[int] = set()
        current = dispatcher_target

        for _ in range(flow_graph.block_count):
            if current in visited:
                return None
            visited.add(current)

            blk_snap = flow_graph.get_block(current)
            if blk_snap is None:
                return None
            if blk_snap.tail_opcode is None or blk_snap.tail_opcode not in HODUR_STATE_CHECK_OPCODES:
                return current

            tail_insn = blk_snap.tail
            if tail_insn is None:
                return current

            check_info = self._extract_check_constant_and_opcode_snapshot(tail_insn)
            if check_info is None:
                return current

            check_opcode, check_const, check_size = check_info
            jump_target, fallthrough = (
                self._get_jump_and_fallthrough_targets_snapshot(blk_snap)
            )
            if jump_target is None or fallthrough is None:
                return None

            jump_taken = HodurStateMachineDetector._is_jump_taken_for_state(
                check_opcode,
                int(target_state),
                check_const,
                check_size,
            )
            if jump_taken is None:
                return None

            current = jump_target if jump_taken else fallthrough

        return None
