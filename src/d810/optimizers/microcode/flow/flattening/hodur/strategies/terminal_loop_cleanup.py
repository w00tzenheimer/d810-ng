"""TerminalLoopCleanupStrategy — fix residual infinite-loop artifacts.

After linearization, some handler exit blocks may still loop back to the
dispatcher via lightweight transition blocks, or form degenerate single-block
self-loops.  This strategy proposes GOTO_REDIRECT edits that cut those loops
and redirect to the nearest function exit or return block.
"""
from __future__ import annotations

import ida_hexrays
from d810.core.typing import TYPE_CHECKING

from d810.core import logging
from d810.optimizers.microcode.flow.flattening.hodur._helpers import (
    can_reach_return,
    collect_state_machine_blocks,
    find_terminal_exit_target,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    FAMILY_CLEANUP,
    BenefitMetrics,
    EditType,
    OwnershipScope,
    PlanFragment,
    ProposedEdit,
)

if TYPE_CHECKING:
    from d810.optimizers.microcode.flow.flattening.hodur.snapshot import (
        AnalysisSnapshot,
    )

logger = logging.getLogger("D810.hodur.strategy.terminal_loop_cleanup")

__all__ = ["TerminalLoopCleanupStrategy"]


class TerminalLoopCleanupStrategy:
    """Propose GOTO_REDIRECT edits to break residual terminal back-edge loops.

    Corresponds to the logic in
    ``HodurUnflattener._find_terminal_loopback_transition``,
    ``_is_lightweight_terminal_transition_block``,
    ``_find_terminal_exit_target``,
    ``_can_reach_return``,
    ``_queue_terminal_backedge_fix``,
    ``_queue_legacy_terminal_backedge_fix``,
    ``_fix_degenerate_terminal_loops``,
    ``_collect_nearby_blocks``, and
    ``_is_degenerate_loop_block``.

    This strategy runs after direct linearization and is therefore in
    FAMILY_CLEANUP.
    """

    @property
    def name(self) -> str:
        """Return the strategy identifier."""
        return "terminal_loop_cleanup"

    @property
    def family(self) -> str:
        """Return the strategy family."""
        return FAMILY_CLEANUP

    def is_applicable(self, snapshot: AnalysisSnapshot) -> bool:
        """Return True when a state machine with transitions is detected.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            True if the snapshot describes a non-empty state machine.
        """
        sm = snapshot.state_machine
        if sm is None:
            return False
        has_handlers = bool(getattr(sm, "handlers", None))
        has_transitions = bool(getattr(sm, "transitions", None))
        return has_handlers or has_transitions

    def plan(self, snapshot: AnalysisSnapshot) -> PlanFragment | None:
        """Produce a PlanFragment with GOTO_REDIRECT edits for terminal loop blocks.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            A PlanFragment with terminal-loop redirect edits, or None when the
            strategy has nothing to contribute.
        """
        if not self.is_applicable(snapshot):
            return None

        mba = snapshot.mba
        sm = snapshot.state_machine
        handlers = getattr(sm, "handlers", {}) or {}

        if not handlers:
            return None

        edits: list[ProposedEdit] = []
        owned_blocks: set[int] = set()

        state_machine_blocks = collect_state_machine_blocks(sm)
        first_check_block = list(handlers.values())[0].check_block

        # --- _queue_terminal_backedge_fix ---
        self._queue_terminal_backedge_fix(
            mba=mba,
            sm=sm,
            handlers=handlers,
            state_machine_blocks=state_machine_blocks,
            first_check_block=first_check_block,
            find_terminal_exit_target=find_terminal_exit_target,
            ida_hexrays=ida_hexrays,
            edits=edits,
            owned_blocks=owned_blocks,
        )

        # --- _queue_legacy_terminal_backedge_fix ---
        self._queue_legacy_terminal_backedge_fix(
            mba=mba,
            sm=sm,
            state_machine_blocks=state_machine_blocks,
            first_check_block=first_check_block,
            find_terminal_exit_target=find_terminal_exit_target,
            ida_hexrays=ida_hexrays,
            edits=edits,
            owned_blocks=owned_blocks,
        )

        # --- _fix_degenerate_terminal_loops ---
        self._fix_degenerate_terminal_loops(
            mba=mba,
            handlers=handlers,
            state_machine_blocks=state_machine_blocks,
            find_terminal_exit_target=find_terminal_exit_target,
            ida_hexrays=ida_hexrays,
            edits=edits,
            owned_blocks=owned_blocks,
        )

        if not edits:
            return None

        ownership = OwnershipScope(
            blocks=frozenset(owned_blocks),
            edges=frozenset(),
            transitions=frozenset(),
        )
        benefit = BenefitMetrics(
            handlers_resolved=0,
            transitions_resolved=len(edits),
            blocks_freed=len(owned_blocks),
            conflict_density=0.0,
        )
        return PlanFragment(
            strategy_name=self.name,
            family=self.family,
            proposed_edits=edits,
            ownership=ownership,
            prerequisites=[],
            expected_benefit=benefit,
            risk_score=0.15,
        )

    # -------------------------------------------------------------------------
    # Private helpers — ported from HodurUnflattener
    # -------------------------------------------------------------------------

    def _find_terminal_loopback_transition(
        self,
        sm: object,
        mba: object,
        ida_hexrays: object,
    ) -> object | None:
        """Find the unique transition that loops back to the initial state.

        Faithful port of HodurUnflattener._find_terminal_loopback_transition.
        """
        if sm is None or sm.initial_state is None:
            return None

        initial_state = int(sm.initial_state)
        loopbacks = [
            transition
            for transition in sm.transitions
            if transition.to_state == initial_state
            and transition.from_state != initial_state
        ]
        if len(loopbacks) != 1:
            return None

        transition = loopbacks[0]
        transition_blk = mba.get_mblock(transition.from_block)
        if transition_blk is None:
            return None

        if not self._is_lightweight_terminal_transition_block(
            transition_blk, sm, ida_hexrays
        ):
            return None

        return transition

    def _is_lightweight_terminal_transition_block(
        self,
        blk: object,
        sm: object,
        ida_hexrays: object,
    ) -> bool:
        """Return True if the block is a trivial transition (mov+goto/nop only).

        Faithful port of HodurUnflattener._is_lightweight_terminal_transition_block.
        """
        if sm is None or sm.state_var is None:
            return False

        # Build HODUR_STATE_CHECK_OPCODES locally (IDA-runtime values).
        state_check_opcodes = {
            ida_hexrays.m_jnz,
            ida_hexrays.m_jz,
            ida_hexrays.m_jae,
            ida_hexrays.m_jb,
            ida_hexrays.m_ja,
            ida_hexrays.m_jbe,
            ida_hexrays.m_jg,
            ida_hexrays.m_jge,
            ida_hexrays.m_jl,
            ida_hexrays.m_jle,
        }

        state_var = sm.state_var
        insn = blk.head
        while insn:
            if insn.opcode == ida_hexrays.m_mov:
                if (
                    insn.d.t == ida_hexrays.mop_z
                    or not self._mops_match_state_var(insn.d, state_var, ida_hexrays)
                    or insn.l.t != ida_hexrays.mop_n
                ):
                    return False
            elif insn.opcode in (ida_hexrays.m_goto, ida_hexrays.m_nop):
                pass
            else:
                # Allow conditional jump tails on 2-way transition blocks.
                if insn != blk.tail or insn.opcode not in state_check_opcodes:
                    return False
            insn = insn.next

        return True

    def _mops_match_state_var(
        self,
        candidate: object,
        state_var: object,
        ida_hexrays: object,
    ) -> bool:
        """Compare a mop_t against the state variable mop_t."""
        if candidate is None:
            return False
        if candidate.t != state_var.t:
            return False
        if candidate.size != state_var.size:
            return False
        if candidate.t == ida_hexrays.mop_S:
            return candidate.s.off == state_var.s.off
        if candidate.t == ida_hexrays.mop_r:
            return candidate.r == state_var.r
        return False

    def _collect_nearby_blocks(
        self,
        mba: object,
        seed_blocks: set[int],
        depth: int = 2,
    ) -> set[int]:
        """BFS expansion around seed_blocks up to given depth.

        Faithful port of HodurUnflattener._collect_nearby_blocks.
        """
        nearby = set(seed_blocks)
        frontier = set(seed_blocks)
        for _ in range(max(depth, 0)):
            next_frontier: set[int] = set()
            for blk_serial in frontier:
                blk = mba.get_mblock(blk_serial)
                if blk is None:
                    continue
                for succ in blk.succset:
                    if succ not in nearby:
                        next_frontier.add(succ)
                for pred in blk.predset:
                    if pred not in nearby:
                        next_frontier.add(pred)
            if not next_frontier:
                break
            nearby.update(next_frontier)
            frontier = next_frontier
        return nearby

    def _is_degenerate_loop_block(
        self,
        blk: object,
        ida_hexrays: object,
    ) -> bool:
        """Return True for trivial synthetic loop blocks (nop/goto-only).

        Faithful port of HodurUnflattener._is_degenerate_loop_block.
        """
        insn = blk.head
        meaningful = 0
        while insn:
            if insn.opcode not in (ida_hexrays.m_nop, ida_hexrays.m_goto):
                meaningful += 1
                if meaningful > 0:
                    return False
            insn = insn.next
        return True

    def _queue_terminal_backedge_fix(
        self,
        mba: object,
        sm: object,
        handlers: dict,
        state_machine_blocks: set[int],
        first_check_block: int,
        find_terminal_exit_target: object,
        ida_hexrays: object,
        edits: list,
        owned_blocks: set[int],
    ) -> None:
        """Find and fix the terminal back-edge that creates the while(1) wrapper.

        Faithful port of HodurUnflattener._queue_terminal_backedge_fix.
        """
        if sm is None or sm.initial_state is None:
            return

        # Preserve the previously-stable behavior for classic jnz-based Hodur/ABC
        # flattening before attempting broader structural heuristics.
        if self._queue_legacy_terminal_backedge_fix(
            mba=mba,
            sm=sm,
            state_machine_blocks=state_machine_blocks,
            first_check_block=first_check_block,
            find_terminal_exit_target=find_terminal_exit_target,
            ida_hexrays=ida_hexrays,
            edits=edits,
            owned_blocks=owned_blocks,
        ):
            return

        success_target = find_terminal_exit_target(
            mba, first_check_block, state_machine_blocks
        )
        if success_target is None:
            return

        initial_state = int(sm.initial_state)
        check_blocks = {handler.check_block for handler in handlers.values()}

        # Primary strategy: rewrite transitions that loop back to INITIAL_STATE.
        loopback_transitions = [
            transition
            for transition in sm.transitions
            if transition.to_state == initial_state
            and transition.from_state != initial_state
        ]
        candidate_blocks = [
            transition.from_block for transition in loopback_transitions
        ]

        # Fallback: no explicit loopback transition found, use structural back-edges
        # to the dispatcher entry among lightweight state-machine blocks.
        if not candidate_blocks:
            for blk_serial in state_machine_blocks:
                blk = mba.get_mblock(blk_serial)
                if blk is None:
                    continue
                if (
                    first_check_block in blk.succset
                    and self._is_lightweight_terminal_transition_block(
                        blk, sm, ida_hexrays
                    )
                ):
                    candidate_blocks.append(blk_serial)

        processed_blocks: set[int] = set()
        for blk_serial in candidate_blocks:
            if blk_serial in processed_blocks:
                continue
            processed_blocks.add(blk_serial)

            blk = mba.get_mblock(blk_serial)
            if blk is None:
                continue
            if not any(succ in check_blocks for succ in blk.succset):
                continue

            logger.info(
                "Redirecting terminal loopback block %d -> exit block %d",
                blk_serial,
                success_target,
            )
            if blk.nsucc() == 1:
                edits.append(ProposedEdit(
                    edit_type=EditType.GOTO_REDIRECT,
                    source_block=blk_serial,
                    target_block=success_target,
                    metadata={
                        "reason": "terminal loopback -> success path",
                        "rule_priority": 50,
                        "strategy": self.name,
                    },
                ))
                owned_blocks.add(blk_serial)
            elif blk.nsucc() == 2:
                edits.append(ProposedEdit(
                    edit_type=EditType.CONVERT_TO_GOTO,
                    source_block=blk_serial,
                    target_block=success_target,
                    metadata={
                        "reason": "terminal loopback cond -> success path",
                        "rule_priority": 50,
                        "strategy": self.name,
                    },
                ))
                owned_blocks.add(blk_serial)

    def _queue_legacy_terminal_backedge_fix(
        self,
        mba: object,
        sm: object,
        state_machine_blocks: set[int],
        first_check_block: int,
        find_terminal_exit_target: object,
        ida_hexrays: object,
        edits: list,
        owned_blocks: set[int],
    ) -> bool:
        """Legacy Hodur cleanup: rewrite direct goto back-edges to first check for jnz wrappers.

        Faithful port of HodurUnflattener._queue_legacy_terminal_backedge_fix.

        Returns:
            True if any redirects were queued, False otherwise.
        """
        if sm is None:
            return False

        first_check_blk = mba.get_mblock(first_check_block)
        if first_check_blk is None or first_check_blk.tail is None:
            return False

        # Default: jnz jump target (next check block in chain)
        jnz_target = None
        if (
            first_check_blk.tail.opcode == ida_hexrays.m_jnz
            and first_check_blk.tail.d.t == ida_hexrays.mop_b
        ):
            jnz_target = first_check_blk.tail.d.b

        # Prefer true exit target when it escapes the state machine region.
        exit_target = find_terminal_exit_target(
            mba, first_check_blk.serial, state_machine_blocks
        )
        if exit_target is not None and exit_target not in state_machine_blocks:
            success_target = exit_target
        else:
            success_target = jnz_target

        if success_target is None:
            return False

        queued_any = False
        for blk_serial in range(mba.qty):
            blk = mba.get_mblock(blk_serial)
            if blk is None:
                continue
            if first_check_block not in blk.succset:
                continue
            if blk_serial <= first_check_block:
                continue
            if blk.tail is None or blk.tail.opcode != ida_hexrays.m_goto:
                continue
            if blk.tail.l.t != ida_hexrays.mop_b or blk.tail.l.b != first_check_block:
                continue

            edits.append(ProposedEdit(
                edit_type=EditType.GOTO_REDIRECT,
                source_block=blk_serial,
                target_block=success_target,
                metadata={
                    "reason": "terminal back-edge -> success path (legacy)",
                    "rule_priority": 50,
                    "strategy": self.name,
                },
            ))
            owned_blocks.add(blk_serial)
            queued_any = True

        return queued_any

    def _fix_degenerate_terminal_loops(
        self,
        mba: object,
        handlers: dict,
        state_machine_blocks: set[int],
        find_terminal_exit_target: object,
        ida_hexrays: object,
        edits: list,
        owned_blocks: set[int],
    ) -> None:
        """Redirect trivial terminal loops that can remain after unflattening.

        Faithful port of HodurUnflattener._fix_degenerate_terminal_loops.
        """
        if not handlers:
            return

        first_check_block = list(handlers.values())[0].check_block
        exit_target = find_terminal_exit_target(
            mba, first_check_block, state_machine_blocks
        )
        if exit_target is None:
            return

        candidate_blocks = self._collect_nearby_blocks(
            mba, state_machine_blocks, depth=4
        )

        for blk_serial in sorted(candidate_blocks):
            blk = mba.get_mblock(blk_serial)
            if blk is None:
                continue
            if blk.nsucc() != 1 or not self._is_degenerate_loop_block(
                blk, ida_hexrays
            ):
                continue

            succ = next(iter(blk.succset))
            if succ == blk.serial and blk.serial != exit_target:
                edits.append(ProposedEdit(
                    edit_type=EditType.GOTO_REDIRECT,
                    source_block=blk.serial,
                    target_block=exit_target,
                    metadata={
                        "reason": "fix_degenerate_terminal_loop",
                        "rule_priority": 50,
                        "strategy": self.name,
                    },
                ))
                owned_blocks.add(blk.serial)
                logger.info(
                    "Queued redirect: terminal self-loop block %d -> %d",
                    blk.serial,
                    exit_target,
                )
                continue

            succ_blk = mba.get_mblock(succ)
            if succ_blk is None or succ_blk.nsucc() != 1:
                continue
            if not self._is_degenerate_loop_block(succ_blk, ida_hexrays):
                continue
            succ2 = next(iter(succ_blk.succset))
            if (
                succ2 == blk.serial
                and blk.serial != exit_target
                and succ != exit_target
            ):
                edits.append(ProposedEdit(
                    edit_type=EditType.GOTO_REDIRECT,
                    source_block=blk.serial,
                    target_block=exit_target,
                    metadata={
                        "reason": "fix_degenerate_terminal_loop",
                        "rule_priority": 50,
                        "strategy": self.name,
                    },
                ))
                owned_blocks.add(blk.serial)
                logger.info(
                    "Queued redirect: terminal 2-block loop %d<->%d via %d",
                    blk.serial,
                    succ,
                    exit_target,
                )
