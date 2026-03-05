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
    are handled via BLOCK_DUPLICATE (not yet implemented in the executor — the
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
            find_terminal_exit_target,
        )

        mba = snapshot.mba
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
            mba=mba,
            sm=sm,
            handlers=handlers,
            state_constants=state_constants,
            state_var=state_var,
            ida_hexrays=ida_hexrays,
            edits=modifications,
            owned_blocks=owned_blocks,
        )

        # --- Part 2: resolve remaining back-edges via assignment_map ---
        self._resolve_remaining_via_assignment_map(
            mba=mba,
            sm=sm,
            handlers=handlers,
            assignment_map=assignment_map,
            state_var=state_var,
            state_machine_blocks=state_machine_blocks,
            find_terminal_exit_target=find_terminal_exit_target,
            detector=detector,
            ida_hexrays=ida_hexrays,
            edits=modifications,
            owned_blocks=owned_blocks,
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
    # Private helpers — ported from HodurUnflattener
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

    def _extract_assigned_state_from_block(
        self,
        blk_serial: int,
        assignment_map: dict,
        state_var: object,
    ) -> int | None:
        """Extract the constant state assigned in a block via assignment_map.

        ``assignment_map`` is ``dict[int, list[minsn_t]]`` — values are lists
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
        mba: object,
        sm: object,
        handlers: dict,
        state_constants: set,
        state_var: object,
        ida_hexrays: object,
        edits: list,
        owned_blocks: set[int],
    ) -> None:
        """NOP dead state variable writes in handler blocks.

        Faithful port of HodurUnflattener._queue_state_assignment_removals
        (the NOP-state-assignment inner loop only — the terminal back-edge fix
        is handled by TerminalLoopCleanupStrategy in the refactored pipeline).
        """
        if sm is None or state_var is None:
            return

        initial_state = getattr(sm, "initial_state", None)
        if initial_state is None:
            return

        # NOP state variable assignments in handler body blocks.
        for handler in handlers.values():
            for blk_serial in handler.handler_blocks:
                if blk_serial >= mba.qty:
                    continue
                blk = mba.get_mblock(blk_serial)
                if blk is None:
                    continue
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
                        logger.info(
                            "NOPed state assignment in block %d (ea=0x%x)",
                            blk_serial,
                            insn.ea,
                        )
                        modifications.append(
                            builder.nop_instruction(
                                source_block=blk_serial,
                                instruction_ea=insn.ea,
                            )
                        )
                        owned_blocks.add(blk_serial)
                    insn = insn.next

    def _resolve_remaining_via_assignment_map(
        self,
        mba: object,
        sm: object,
        handlers: dict,
        assignment_map: dict,
        state_var: object,
        state_machine_blocks: set[int],
        find_terminal_exit_target: object,
        detector: object,
        ida_hexrays: object,
        edits: list,
        owned_blocks: set[int],
    ) -> None:
        """Resolve remaining dispatcher back-edges using assignment_map lookup.

        Faithful port of HodurUnflattener._resolve_remaining_via_assignment_map.

        For unresolved handler exits that still target dispatcher check blocks,
        use assignment_map to directly resolve and redirect them, bypassing
        MopTracker backward tracing which fails on modified CFG.

        Note: BLOCK_DUPLICATE edits for 2-way exit blocks are emitted but are
        not yet fully implemented in the executor — they will be logged as
        warnings.
        """
        if not assignment_map:
            return

        check_blocks = {h.check_block for h in handlers.values()}

        # Collect predecessors of ALL check blocks.
        preds_to_check: set[tuple[int, int]] = set()
        for cb_serial in check_blocks:
            cb_blk = mba.get_mblock(cb_serial)
            if cb_blk is None:
                continue
            for pred_serial in cb_blk.predset:
                if pred_serial not in check_blocks:
                    preds_to_check.add((pred_serial, cb_serial))

        for pred_serial, dispatcher_target in preds_to_check:
            pred_blk = mba.get_mblock(pred_serial)
            if pred_blk is None:
                continue

            # Handle 2-way exit blocks ONLY outside the state machine region.
            if pred_blk.nsucc() == 2:
                if pred_serial not in state_machine_blocks:
                    # Find the non-check-block successor (the forward path).
                    forward_succs = [
                        s for s in pred_blk.succset if s not in check_blocks
                    ]
                    if forward_succs:
                        forward_target = forward_succs[0]
                        modifications.append(
                            builder.duplicate_block(
                                source_block=pred_serial,
                                target_block=forward_target,
                            )
                        )
                        owned_blocks.add(pred_serial)
                        logger.info(
                            "Assignment-map resolver: converted 2-way exit blk[%d] "
                            "to goto blk[%d]",
                            pred_serial,
                            forward_target,
                        )
                continue

            # Only handle 1-way blocks (goto blocks).
            if pred_blk.nsucc() != 1:
                continue

            # Try to find state assignment in this block via assignment_map.
            target_state = self._extract_assigned_state_from_block(
                pred_serial, assignment_map, state_var
            )

            # If not found directly, walk backward along single-pred chains.
            if target_state is None:
                walk_serial = pred_serial
                for _ in range(5):  # max backward walk depth
                    walk_blk = mba.get_mblock(walk_serial)
                    if walk_blk is None or walk_blk.npred() != 1:
                        break
                    walk_serial = list(walk_blk.predset)[0]
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
                exit_tgt = (
                    find_terminal_exit_target(mba, first_ck, state_machine_blocks)
                    if first_ck is not None
                    else None
                )
                if exit_tgt is not None:
                    modifications.append(
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
                dispatcher_target, target_state, handlers, mba
            )
            if handler_entry is None:
                continue

            modifications.append(
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

    def _resolve_handler_entry(
        self,
        dispatcher_target: int,
        target_state: int,
        handlers: dict,
        mba: object,
    ) -> int | None:
        """Find the handler entry block for the given target state.

        Port of HodurUnflattener._resolve_conditional_chain_target: walks the
        BST conditional-check chain starting from ``dispatcher_target``,
        evaluating each comparison against ``target_state``, until it reaches a
        leaf block that is not a state-check node.  That leaf is the handler
        entry block.

        Args:
            dispatcher_target: Check block serial that the predecessor currently
                targets (start of BST walk).
            target_state: Concrete state value to resolve.
            handlers: Mapping of state value -> handler object (unused here,
                kept for context).
            mba: Live mba_t needed to fetch mblock_t objects.

        Returns:
            Handler entry block serial (leaf after BST traversal), or None if
            the chain cannot be resolved.
        """
        visited: set[int] = set()
        current = dispatcher_target

        for _ in range(mba.qty):
            if current in visited:
                return None
            visited.add(current)

            blk = mba.get_mblock(current)
            if blk is None:
                return None
            if blk.tail is None or blk.tail.opcode not in HODUR_STATE_CHECK_OPCODES:
                return current

            check_info = HodurStateMachineDetector._extract_check_constant_and_opcode(
                blk.tail
            )
            if check_info is None:
                return current

            check_opcode, check_const, check_size = check_info
            jump_target, fallthrough = (
                HodurStateMachineDetector._get_jump_and_fallthrough_targets(blk)
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
