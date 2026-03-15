"""Backward dispatcher-predecessor resolution strategy.

Resolves TAIL_CHASE_FAILED handler exits by backward-walking from each
dispatcher predecessor to find the state variable write, evaluating MBA
expressions (m_sub, m_xor, etc.) recursively, then looking up the target
handler via the IntervalDispatcher.

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

    For each non-BST predecessor of the dispatcher block, backward-walk
    to find the state variable write instruction.  If the written value
    can be resolved (literal, or MBA expression of literals), perform a
    BST lookup to determine the target handler and emit a ``RedirectGoto``
    modification.

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

        For each non-BST predecessor of the dispatcher block, backward-walk
        to find the state variable write, evaluate MBA expressions recursively,
        and emit a redirect if BST lookup succeeds.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            A PlanFragment with redirect modifications, or None when no
            exits could be resolved.
        """
        import ida_hexrays

        mba = snapshot.mba
        bst_result = snapshot.bst_result
        dispatcher_serial = snapshot.bst_dispatcher_serial
        bst_node_blocks = bst_result.bst_node_blocks
        bst_serials = set(bst_node_blocks) | {dispatcher_serial}

        # Get state var stkoff
        state_var = getattr(snapshot.state_machine, "state_var", None)
        if state_var is None or state_var.t != ida_hexrays.mop_S:
            return None
        state_var_stkoff = state_var.s.off

        disp_blk = mba.get_mblock(dispatcher_serial)
        if disp_blk is None:
            return None

        builder = ModificationBuilder.from_snapshot(snapshot)
        modifications = []
        owned_blocks: set[int] = set()

        # Iterate dispatcher predecessors
        for pi in range(disp_blk.npred()):
            pred_serial = disp_blk.pred(pi)
            if pred_serial in bst_serials:
                continue

            pred_blk = mba.get_mblock(pred_serial)
            if pred_blk is None or pred_blk.nsucc() != 1:
                continue

            # Backward walk to find state var write
            resolved_value = self._resolve_exit_state(
                mba, pred_blk, state_var_stkoff, bst_serials,
            )

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
                    "BACKWARD_PRED: blk[%d] state=0x%X -> handler blk[%d]",
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
                blocks=frozenset(owned_blocks),
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
        )

    def _resolve_exit_state(
        self,
        mba: object,
        start_blk: object,
        state_var_stkoff: int,
        bst_serials: set[int],
    ) -> int | None:
        """Walk backward from start_blk to find state var write and resolve value.

        Scans instructions backward in each block looking for a write to
        the state variable (stack slot at ``state_var_stkoff``).  Follows
        single-predecessor chains up to depth 8, skipping BST blocks.

        Args:
            mba: The ``mbl_array_t`` microcode array.
            start_blk: The starting ``mblock_t`` to walk backward from.
            state_var_stkoff: Stack offset of the state variable.
            bst_serials: Set of BST/dispatcher block serials to avoid.

        Returns:
            Resolved integer state value, or None if unresolvable.
        """
        import ida_hexrays

        walk_blk = start_blk
        for _depth in range(8):
            # Scan instructions backward
            insn = walk_blk.tail
            while insn is not None:
                if (insn.d is not None
                        and insn.d.t == ida_hexrays.mop_S
                        and insn.d.s is not None
                        and insn.d.s.off == state_var_stkoff):
                    # Found state var write -- resolve the value
                    return self._resolve_write_value(
                        insn, walk_blk, mba, bst_serials,
                    )
                insn = insn.prev

            # Continue to single predecessor
            if walk_blk.npred() != 1:
                break
            pred_serial = walk_blk.pred(0)
            if pred_serial in bst_serials:
                break
            walk_blk = mba.get_mblock(pred_serial)
            if walk_blk is None:
                break

        return None

    def _resolve_write_value(
        self,
        insn: object,
        blk: object,
        mba: object,
        bst_serials: set[int],
    ) -> int | None:
        """Resolve the value written by a state var write instruction.

        Handles ``m_mov`` (simple copy), binary ops (``m_sub``, ``m_xor``,
        etc.), and recursive MBA expression evaluation.

        Args:
            insn: The ``minsn_t`` that writes the state variable.
            blk: The ``mblock_t`` containing the instruction.
            mba: The ``mbl_array_t`` microcode array.
            bst_serials: Set of BST/dispatcher block serials to avoid.

        Returns:
            Resolved integer value, or None if unresolvable.
        """
        import ida_hexrays

        BINARY_OPS = {
            ida_hexrays.m_xor, ida_hexrays.m_sub, ida_hexrays.m_add,
            ida_hexrays.m_and, ida_hexrays.m_or, ida_hexrays.m_mul,
        }

        if insn.opcode == ida_hexrays.m_mov:
            return self._eval_operand(insn.l, blk, mba, bst_serials, 0)
        elif insn.opcode in BINARY_OPS:
            left = self._eval_operand(insn.l, blk, mba, bst_serials, 0)
            right = self._eval_operand(insn.r, blk, mba, bst_serials, 0)
            if left is not None and right is not None:
                return _apply_binary_op(insn.opcode, left, right)
        return None

    def _eval_operand(
        self,
        mop: object,
        blk: object,
        mba: object,
        bst_serials: set[int],
        depth: int,
    ) -> int | None:
        """Recursively evaluate an operand to a constant value.

        Handles literal numbers (``mop_n``), stack variables (``mop_S``),
        registers (``mop_r``), and sub-expressions (``mop_d``).

        Args:
            mop: The ``mop_t`` operand to evaluate.
            blk: The ``mblock_t`` context for backward search.
            mba: The ``mbl_array_t`` microcode array.
            bst_serials: Set of BST/dispatcher block serials to avoid.
            depth: Current recursion depth (max 8).

        Returns:
            Resolved integer value, or None if unresolvable.
        """
        import ida_hexrays

        if depth > 8 or mop is None:
            return None

        # Literal
        if mop.t == ida_hexrays.mop_n:
            return mop.nnn.value

        # Stack variable -- backward search for literal def
        if mop.t == ida_hexrays.mop_S and mop.s is not None:
            return self._find_stkvar_def(
                mop.s.off, blk, mba, bst_serials, depth,
            )

        # Register -- backward search for literal def
        if mop.t == ida_hexrays.mop_r:
            return self._find_reg_def(
                mop.r, blk, mba, bst_serials, depth,
            )

        # Sub-expression (result of another instruction)
        if mop.t == ida_hexrays.mop_d and mop.d is not None:
            return self._eval_sub_insn(mop.d, blk, mba, bst_serials, depth)

        return None

    def _eval_sub_insn(
        self,
        sub: object,
        blk: object,
        mba: object,
        bst_serials: set[int],
        depth: int,
    ) -> int | None:
        """Evaluate a sub-instruction (mop_d) to a constant value.

        Handles binary ops, extension ops (``m_xdu``, ``m_xds``), and
        ``m_mov`` as a copy.

        Args:
            sub: The ``minsn_t`` sub-instruction.
            blk: The ``mblock_t`` context.
            mba: The ``mbl_array_t`` microcode array.
            bst_serials: Set of BST/dispatcher block serials to avoid.
            depth: Current recursion depth.

        Returns:
            Resolved integer value, or None if unresolvable.
        """
        import ida_hexrays

        BINARY_OPS = {
            ida_hexrays.m_xor, ida_hexrays.m_sub, ida_hexrays.m_add,
            ida_hexrays.m_and, ida_hexrays.m_or, ida_hexrays.m_mul,
        }

        if sub.opcode in BINARY_OPS:
            left = self._eval_operand(sub.l, blk, mba, bst_serials, depth + 1)
            right = self._eval_operand(sub.r, blk, mba, bst_serials, depth + 1)
            if left is not None and right is not None:
                return _apply_binary_op(sub.opcode, left, right)

        # xdu/xds -- treat as copy
        m_xdu = getattr(ida_hexrays, "m_xdu", -1)
        m_xds = getattr(ida_hexrays, "m_xds", -1)
        if sub.opcode in (m_xdu, m_xds):
            return self._eval_operand(sub.l, blk, mba, bst_serials, depth + 1)

        if sub.opcode == ida_hexrays.m_mov:
            return self._eval_operand(sub.l, blk, mba, bst_serials, depth + 1)

        return None

    def _find_stkvar_def(
        self,
        stkoff: int,
        blk: object,
        mba: object,
        bst_serials: set[int],
        depth: int,
    ) -> int | None:
        """Find literal definition of a stack variable by backward walk.

        Args:
            stkoff: Stack offset of the variable to find.
            blk: Starting ``mblock_t`` for the backward walk.
            mba: The ``mbl_array_t`` microcode array.
            bst_serials: Set of BST/dispatcher block serials to avoid.
            depth: Current recursion depth.

        Returns:
            Resolved integer value, or None if not found.
        """
        import ida_hexrays

        search_blk = blk
        for _ in range(8):
            insn = search_blk.tail
            while insn is not None:
                if (insn.d is not None
                        and insn.d.t == ida_hexrays.mop_S
                        and insn.d.s is not None
                        and insn.d.s.off == stkoff):
                    return self._eval_operand(
                        insn.l, search_blk, mba, bst_serials, depth + 1,
                    )
                insn = insn.prev
            if search_blk.npred() != 1:
                break
            ps = search_blk.pred(0)
            if ps in bst_serials:
                break
            search_blk = mba.get_mblock(ps)
            if search_blk is None:
                break
        return None

    def _find_reg_def(
        self,
        reg: int,
        blk: object,
        mba: object,
        bst_serials: set[int],
        depth: int,
    ) -> int | None:
        """Find literal definition of a register by backward walk.

        Args:
            reg: Register number to find the definition for.
            blk: Starting ``mblock_t`` for the backward walk.
            mba: The ``mbl_array_t`` microcode array.
            bst_serials: Set of BST/dispatcher block serials to avoid.
            depth: Current recursion depth.

        Returns:
            Resolved integer value, or None if not found.
        """
        import ida_hexrays

        search_blk = blk
        for _ in range(8):
            insn = search_blk.tail
            while insn is not None:
                if (insn.d is not None
                        and insn.d.t == ida_hexrays.mop_r
                        and insn.d.r == reg):
                    return self._eval_operand(
                        insn.l, search_blk, mba, bst_serials, depth + 1,
                    )
                insn = insn.prev
            if search_blk.npred() != 1:
                break
            ps = search_blk.pred(0)
            if ps in bst_serials:
                break
            search_blk = mba.get_mblock(ps)
            if search_blk is None:
                break
        return None


def _apply_binary_op(opcode: int, left: int, right: int) -> int | None:
    """Apply a binary microcode operation to two resolved integer operands.

    Args:
        opcode: The microcode opcode (m_xor, m_sub, m_add, etc.).
        left: Left operand value.
        right: Right operand value.

    Returns:
        Result masked to 32 bits, or None if the opcode is unrecognized.
    """
    import ida_hexrays

    mask = 0xFFFFFFFF
    if opcode == ida_hexrays.m_xor:
        return (left ^ right) & mask
    if opcode == ida_hexrays.m_sub:
        return (left - right) & mask
    if opcode == ida_hexrays.m_add:
        return (left + right) & mask
    if opcode == ida_hexrays.m_and:
        return (left & right) & mask
    if opcode == ida_hexrays.m_or:
        return (left | right) & mask
    if opcode == ida_hexrays.m_mul:
        return (left * right) & mask
    return None
