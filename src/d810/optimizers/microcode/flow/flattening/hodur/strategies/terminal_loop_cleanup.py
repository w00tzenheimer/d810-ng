"""TerminalLoopCleanupStrategy -- fix residual infinite-loop artifacts.

After linearization, some handler exit blocks may still loop back to the
dispatcher via lightweight transition blocks, or form degenerate single-block
self-loops.  This strategy proposes GOTO_REDIRECT edits that cut those loops
and redirect to the nearest function exit or return block.
"""
from __future__ import annotations

import ida_hexrays
from d810.core.typing import TYPE_CHECKING

from d810.core import logging
from d810.cfg.flowgraph import BlockSnapshot
from d810.optimizers.microcode.flow.flattening.hodur._helpers import (
    collect_state_machine_blocks,
    find_terminal_exit_target_snapshot,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    FAMILY_CLEANUP,
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

        # K3: fully migrated to FlowGraph
        flow_graph = snapshot.flow_graph
        sm = snapshot.state_machine
        handlers = getattr(sm, "handlers", {}) or {}

        if not handlers:
            return None

        builder = ModificationBuilder.from_snapshot(snapshot)
        modifications: list = []
        owned_blocks: set[int] = set()

        state_machine_blocks = collect_state_machine_blocks(sm)
        first_check_block = list(handlers.values())[0].check_block

        # --- _queue_terminal_backedge_fix ---
        self._queue_terminal_backedge_fix(
            sm=sm,
            handlers=handlers,
            state_machine_blocks=state_machine_blocks,
            first_check_block=first_check_block,
            ida_hexrays=ida_hexrays,
            edits=modifications,
            owned_blocks=owned_blocks,
            builder=builder,
            flow_graph=flow_graph,
        )

        # --- _queue_legacy_terminal_backedge_fix ---
        self._queue_legacy_terminal_backedge_fix(
            sm=sm,
            state_machine_blocks=state_machine_blocks,
            first_check_block=first_check_block,
            ida_hexrays=ida_hexrays,
            edits=modifications,
            owned_blocks=owned_blocks,
            builder=builder,
            flow_graph=flow_graph,
        )

        # --- _fix_degenerate_terminal_loops ---
        self._fix_degenerate_terminal_loops(
            handlers=handlers,
            state_machine_blocks=state_machine_blocks,
            ida_hexrays=ida_hexrays,
            edits=modifications,
            owned_blocks=owned_blocks,
            builder=builder,
            flow_graph=flow_graph,
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
            transitions_resolved=len(modifications),
            blocks_freed=len(owned_blocks),
            conflict_density=0.0,
        )
        return PlanFragment(
            strategy_name=self.name,
            family=self.family,
            modifications=modifications,
            ownership=ownership,
            prerequisites=[],
            expected_benefit=benefit,
            risk_score=0.15,
        )

    # -------------------------------------------------------------------------
    # Private helpers -- ported from HodurUnflattener
    # -------------------------------------------------------------------------

    def _find_terminal_loopback_transition(
        self,
        sm: object,
        flow_graph: object,
        ida_hexrays: object,
    ) -> object | None:
        """Find the unique transition that loops back to the initial state.

        Faithful port of HodurUnflattener._find_terminal_loopback_transition.
        K3: migrated from mba.get_mblock to flow_graph.get_block + snapshot.
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
        blk_snap = flow_graph.get_block(transition.from_block)
        if blk_snap is None:
            return None

        # Resolve state_var shape for snapshot path.
        _sv = getattr(sm, "state_var", None) if sm is not None else None
        _sv_t: int = getattr(_sv, "t", -1) if _sv is not None else -1
        _sv_size: int = getattr(_sv, "size", 4) if _sv is not None else 4
        _sv_stkoff: int | None = None
        _sv_reg: int | None = None
        if _sv is not None:
            if _sv_t == ida_hexrays.mop_S:
                _s = getattr(_sv, "s", None)
                _sv_stkoff = getattr(_s, "off", None) if _s is not None else None
            elif _sv_t == ida_hexrays.mop_r:
                _sv_reg = getattr(_sv, "r", None)

        _state_check_opcodes: set[int] = {
            ida_hexrays.m_jnz, ida_hexrays.m_jz,
            ida_hexrays.m_jae, ida_hexrays.m_jb,
            ida_hexrays.m_ja, ida_hexrays.m_jbe,
            ida_hexrays.m_jg, ida_hexrays.m_jge,
            ida_hexrays.m_jl, ida_hexrays.m_jle,
        }

        if not self._is_lightweight_terminal_transition_snapshot(
            blk_snap,
            state_var_t=_sv_t,
            state_var_size=_sv_size,
            state_var_stkoff=_sv_stkoff,
            state_var_reg=_sv_reg,
            m_mov=ida_hexrays.m_mov,
            m_goto=ida_hexrays.m_goto,
            m_nop=ida_hexrays.m_nop,
            mop_z=ida_hexrays.mop_z,
            mop_n=ida_hexrays.mop_n,
            mop_S=ida_hexrays.mop_S,
            mop_r=ida_hexrays.mop_r,
            state_check_opcodes=_state_check_opcodes,
        ):
            return None

        return transition

    @staticmethod
    def _is_lightweight_terminal_transition_snapshot(
        block_snap: BlockSnapshot,
        state_var_t: int,
        state_var_size: int,
        state_var_stkoff: int | None,
        state_var_reg: int | None,
        m_mov: int,
        m_goto: int,
        m_nop: int,
        mop_z: int,
        mop_n: int,
        mop_S: int,
        mop_r: int,
        state_check_opcodes: set[int],
    ) -> bool:
        """Snapshot variant of :meth:`_is_lightweight_terminal_transition_block` (K3.6).

        Uses ``BlockSnapshot.iter_insns()`` instead of walking the live
        ``mblock_t`` instruction chain.

        Args:
            block_snap: BlockSnapshot for the block.
            state_var_t: mop type of the state variable.
            state_var_size: Size in bytes of the state variable operand.
            state_var_stkoff: Stack offset for mop_S state variables (or None).
            state_var_reg: Register id for mop_r state variables (or None).
            m_mov: IDA opcode for m_mov.
            m_goto: IDA opcode for m_goto.
            m_nop: IDA opcode for m_nop.
            mop_z: IDA mop type for mop_z.
            mop_n: IDA mop type for mop_n.
            mop_S: IDA mop type for mop_S.
            mop_r: IDA mop type for mop_r.
            state_check_opcodes: Set of conditional jump opcodes.

        Returns:
            True if the block is a trivial transition block.
        """
        insns = block_snap.insn_snapshots
        tail_idx = len(insns) - 1

        for idx, insn in enumerate(insns):
            if insn.opcode == m_mov:
                d = insn.d
                l_op = insn.l
                if d is None or d.t == mop_z:
                    return False
                # Check dest matches state var
                if d.t != state_var_t or d.size != state_var_size:
                    return False
                if d.t == mop_S and (d.stkoff is None or d.stkoff != state_var_stkoff):
                    return False
                if d.t == mop_r and (d.reg is None or d.reg != state_var_reg):
                    return False
                if l_op is None or l_op.t != mop_n:
                    return False
            elif insn.opcode in (m_goto, m_nop):
                pass
            else:
                # Allow conditional jump tails on 2-way transition blocks.
                if idx != tail_idx or insn.opcode not in state_check_opcodes:
                    return False
        return True

    @staticmethod
    def _collect_nearby_blocks(
        flow_graph: object,
        seed_blocks: set[int],
        depth: int = 2,
    ) -> set[int]:
        """BFS expansion around seed_blocks up to given depth.

        Faithful port of HodurUnflattener._collect_nearby_blocks.
        K3: fully migrated to FlowGraph (mba fallback removed).
        """
        nearby = set(seed_blocks)
        frontier = set(seed_blocks)
        for _ in range(max(depth, 0)):
            next_frontier: set[int] = set()
            for blk_serial in frontier:
                blk_snap = flow_graph.get_block(blk_serial)
                if blk_snap is None:
                    continue
                for succ in blk_snap.succs:
                    if succ not in nearby:
                        next_frontier.add(succ)
                for pred in blk_snap.preds:
                    if pred not in nearby:
                        next_frontier.add(pred)
            if not next_frontier:
                break
            nearby.update(next_frontier)
            frontier = next_frontier
        return nearby

    @staticmethod
    def _is_degenerate_loop_block_snapshot(
        block_snap: BlockSnapshot,
        m_nop: int,
        m_goto: int,
    ) -> bool:
        """Snapshot variant of :meth:`_is_degenerate_loop_block` (K3.6).

        Uses ``BlockSnapshot.iter_insns()`` instead of walking the live
        ``mblock_t`` instruction chain.

        Args:
            block_snap: BlockSnapshot for the block.
            m_nop: IDA opcode for m_nop.
            m_goto: IDA opcode for m_goto.

        Returns:
            True if the block contains only nop/goto instructions.
        """
        for insn in block_snap.iter_insns():
            if insn.opcode not in (m_nop, m_goto):
                return False
        return True

    def _queue_terminal_backedge_fix(
        self,
        sm: object,
        handlers: dict,
        state_machine_blocks: set[int],
        first_check_block: int,
        ida_hexrays: object,
        edits: list,
        owned_blocks: set[int],
        builder: ModificationBuilder | None = None,
        flow_graph: object | None = None,
    ) -> None:
        """Find and fix the terminal back-edge that creates the while(1) wrapper.

        Faithful port of HodurUnflattener._queue_terminal_backedge_fix.
        K3: fully migrated to FlowGraph (mba removed).
        """
        if sm is None or sm.initial_state is None:
            return

        # Preserve the previously-stable behavior for classic jnz-based Hodur/ABC
        # flattening before attempting broader structural heuristics.
        if self._queue_legacy_terminal_backedge_fix(
            sm=sm,
            state_machine_blocks=state_machine_blocks,
            first_check_block=first_check_block,
            ida_hexrays=ida_hexrays,
            edits=edits,
            owned_blocks=owned_blocks,
            builder=builder,
            flow_graph=flow_graph,
        ):
            return

        success_target = find_terminal_exit_target_snapshot(
            flow_graph, first_check_block, state_machine_blocks
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
        #
        # K3: resolve state_var shape for snapshot path.
        _sv = getattr(sm, "state_var", None) if sm is not None else None
        _sv_t: int = getattr(_sv, "t", -1) if _sv is not None else -1
        _sv_size: int = getattr(_sv, "size", 4) if _sv is not None else 4
        _sv_stkoff: int | None = None
        _sv_reg: int | None = None
        if _sv is not None:
            if _sv_t == ida_hexrays.mop_S:
                _s = getattr(_sv, "s", None)
                _sv_stkoff = getattr(_s, "off", None) if _s is not None else None
            elif _sv_t == ida_hexrays.mop_r:
                _sv_reg = getattr(_sv, "r", None)

        _state_check_opcodes: set[int] = {
            ida_hexrays.m_jnz, ida_hexrays.m_jz,
            ida_hexrays.m_jae, ida_hexrays.m_jb,
            ida_hexrays.m_ja, ida_hexrays.m_jbe,
            ida_hexrays.m_jg, ida_hexrays.m_jge,
            ida_hexrays.m_jl, ida_hexrays.m_jle,
        }

        if not candidate_blocks:
            for blk_serial in state_machine_blocks:
                blk_snap_cand = flow_graph.get_block(blk_serial)
                if blk_snap_cand is None:
                    continue
                if first_check_block not in blk_snap_cand.succs:
                    continue
                if self._is_lightweight_terminal_transition_snapshot(
                    blk_snap_cand,
                    state_var_t=_sv_t,
                    state_var_size=_sv_size,
                    state_var_stkoff=_sv_stkoff,
                    state_var_reg=_sv_reg,
                    m_mov=ida_hexrays.m_mov,
                    m_goto=ida_hexrays.m_goto,
                    m_nop=ida_hexrays.m_nop,
                    mop_z=ida_hexrays.mop_z,
                    mop_n=ida_hexrays.mop_n,
                    mop_S=ida_hexrays.mop_S,
                    mop_r=ida_hexrays.mop_r,
                    state_check_opcodes=_state_check_opcodes,
                ):
                    candidate_blocks.append(blk_serial)

        processed_blocks: set[int] = set()
        for blk_serial in candidate_blocks:
            if blk_serial in processed_blocks:
                continue
            processed_blocks.add(blk_serial)

            blk_snap = flow_graph.get_block(blk_serial)
            if blk_snap is None:
                continue
            if not any(succ in check_blocks for succ in blk_snap.succs):
                continue

            logger.info(
                "Redirecting terminal loopback block %d -> exit block %d",
                blk_serial,
                success_target,
            )
            if blk_snap.nsucc == 1:
                edits.append(
                    builder.goto_redirect(
                        source_block=blk_serial,
                        target_block=success_target,
                    )
                )
                owned_blocks.add(blk_serial)
            elif blk_snap.nsucc == 2:
                edits.append(
                    builder.convert_to_goto(
                        source_block=blk_serial,
                        target_block=success_target,
                    )
                )
                owned_blocks.add(blk_serial)

    def _queue_legacy_terminal_backedge_fix(
        self,
        sm: object,
        state_machine_blocks: set[int],
        first_check_block: int,
        ida_hexrays: object,
        edits: list,
        owned_blocks: set[int],
        builder: ModificationBuilder | None = None,
        flow_graph: object | None = None,
    ) -> bool:
        """Legacy Hodur cleanup: rewrite direct goto back-edges to first check for jnz wrappers.

        Faithful port of HodurUnflattener._queue_legacy_terminal_backedge_fix.
        K3: fully migrated to FlowGraph (mba removed).

        Returns:
            True if any redirects were queued, False otherwise.
        """
        if sm is None:
            return False

        first_check_snap = flow_graph.get_block(first_check_block)
        if first_check_snap is None or first_check_snap.tail is None:
            return False

        # Default: jnz jump target (next check block in chain)
        jnz_target = None
        tail_insn = first_check_snap.tail
        if (
            tail_insn.opcode == ida_hexrays.m_jnz
            and tail_insn.d is not None
            and tail_insn.d.t == ida_hexrays.mop_b
        ):
            jnz_target = tail_insn.d.block_ref

        # Prefer true exit target when it escapes the state machine region.
        exit_target = find_terminal_exit_target_snapshot(
            flow_graph, first_check_block, state_machine_blocks
        )
        if exit_target is not None and exit_target not in state_machine_blocks:
            success_target = exit_target
        else:
            success_target = jnz_target

        if success_target is None:
            return False

        queued_any = False
        for blk_serial in range(flow_graph.block_count):
            blk_snap = flow_graph.get_block(blk_serial)
            if blk_snap is None:
                continue
            if first_check_block not in blk_snap.succs:
                continue
            if blk_serial <= first_check_block:
                continue
            if blk_snap.tail is None or blk_snap.tail.opcode != ida_hexrays.m_goto:
                continue
            blk_tail_l = blk_snap.tail.l
            if blk_tail_l is None or blk_tail_l.t != ida_hexrays.mop_b or blk_tail_l.block_ref != first_check_block:
                continue

            edits.append(
                builder.goto_redirect(
                    source_block=blk_serial,
                    target_block=success_target,
                )
            )
            owned_blocks.add(blk_serial)
            queued_any = True

        return queued_any

    def _fix_degenerate_terminal_loops(
        self,
        handlers: dict,
        state_machine_blocks: set[int],
        ida_hexrays: object,
        edits: list,
        owned_blocks: set[int],
        builder: ModificationBuilder | None = None,
        flow_graph: object | None = None,
    ) -> None:
        """Redirect trivial terminal loops that can remain after unflattening.

        Faithful port of HodurUnflattener._fix_degenerate_terminal_loops.
        K3: fully migrated to FlowGraph (mba removed).
        """
        if not handlers:
            return

        first_check_block = list(handlers.values())[0].check_block
        exit_target = find_terminal_exit_target_snapshot(
            flow_graph, first_check_block, state_machine_blocks
        )
        if exit_target is None:
            return

        candidate_blocks = self._collect_nearby_blocks(
            flow_graph, state_machine_blocks, depth=4,
        )

        m_nop = ida_hexrays.m_nop
        m_goto = ida_hexrays.m_goto

        for blk_serial in sorted(candidate_blocks):
            blk_snap = flow_graph.get_block(blk_serial)
            if blk_snap is None:
                continue
            if blk_snap.nsucc != 1 or not self._is_degenerate_loop_block_snapshot(
                blk_snap, m_nop, m_goto
            ):
                continue

            succ = blk_snap.succs[0]
            if succ == blk_snap.serial and blk_snap.serial != exit_target:
                edits.append(
                    builder.goto_redirect(
                        source_block=blk_snap.serial,
                        target_block=exit_target,
                    )
                )
                owned_blocks.add(blk_snap.serial)
                logger.info(
                    "Queued redirect: terminal self-loop block %d -> %d",
                    blk_snap.serial,
                    exit_target,
                )
                continue

            succ_snap = flow_graph.get_block(succ)
            if succ_snap is None or succ_snap.nsucc != 1:
                continue
            if not self._is_degenerate_loop_block_snapshot(succ_snap, m_nop, m_goto):
                continue
            succ2 = succ_snap.succs[0]
            if (
                succ2 == blk_snap.serial
                and blk_snap.serial != exit_target
                and succ != exit_target
            ):
                edits.append(
                    builder.goto_redirect(
                        source_block=blk_snap.serial,
                        target_block=exit_target,
                    )
                )
                owned_blocks.add(blk_snap.serial)
                logger.info(
                    "Queued redirect: terminal 2-block loop %d<->%d via %d",
                    blk_snap.serial,
                    succ,
                    exit_target,
                )
