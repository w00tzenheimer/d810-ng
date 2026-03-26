"""StateConstantReturnFixupStrategy -- NOP leaked state constants in return paths.

After Hodur linearization, some return-path blocks still contain
``m_mov rax = #<state_const>`` instructions that overwrite the correct return
value with a stale dispatcher constant.  This strategy identifies such
instructions by matching their immediate source operand against the set of
known state constants, and emits ``NopInstruction`` modifications to remove
them.  IDA's own dataflow optimizer then propagates the correct reaching
definition into the return slot.

Family: ``FAMILY_CLEANUP`` -- runs after all other strategies.
Prerequisites: ``["linearized_flow_graph"]`` -- the active DAG-driven
linearizer must already have resolved handler transitions.
"""
from __future__ import annotations

import ida_hexrays

from d810.core import logging
from d810.core.typing import TYPE_CHECKING
from d810.optimizers.microcode.flow.flattening.hodur._modification_bridge import (
    ModificationBuilder,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    FAMILY_CLEANUP,
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
)

if TYPE_CHECKING:
    from d810.optimizers.microcode.flow.flattening.hodur.snapshot import (
        AnalysisSnapshot,
    )

logger = logging.getLogger("D810.hodur.strategy.state_const_return_fixup")

__all__ = ["StateConstantReturnFixupStrategy"]

# IDA block type for the function exit (BLT_STOP = 1).
_BLT_STOP: int = 1


class StateConstantReturnFixupStrategy:
    """NOP ``m_mov rax = #<state_const>`` in BLT_STOP predecessor blocks.

    After linearization, handler bodies correctly compute the return value,
    but residual OLLVM dispatcher glue may overwrite ``rax`` with a stale
    state constant just before the return.  Removing the overwrite lets IDA
    propagate the correct reaching definition.

    Family: ``FAMILY_CLEANUP`` -- last in pipeline.
    Risk: LOW -- only NOPs instructions whose source is a known state constant.
    """

    @property
    def name(self) -> str:
        """Return the strategy identifier."""
        return "state_constant_return_fixup"

    @property
    def family(self) -> str:
        """Return the strategy family."""
        return FAMILY_CLEANUP

    def is_applicable(self, snapshot: AnalysisSnapshot) -> bool:
        """Return True when known state constants exist.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            True if there are known state constants to match against.
        """
        return bool(self._collect_state_constants(snapshot))

    def plan(self, snapshot: AnalysisSnapshot) -> PlanFragment | None:
        """Produce a PlanFragment with NOP edits for leaked state constant writes.

        Scans predecessor blocks of BLT_STOP for ``m_mov`` instructions that
        write a known state constant into ``rax`` or a return stack variable,
        and emits ``NopInstruction`` modifications for each.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            A PlanFragment with NOP modifications, or ``None`` when no leaked
            state constants were found.
        """
        mba = snapshot.mba
        if mba is None:
            return None

        known_consts = self._collect_state_constants(snapshot)
        if not known_consts:
            return None

        # Find the BLT_STOP block (typically the last block in the MBA).
        stop_serial = self._find_stop_block(mba)
        if stop_serial is None:
            logger.info(
                "StateConstReturnFixup: no BLT_STOP block found"
            )
            return None

        stop_blk = mba.get_mblock(stop_serial)  # type: ignore[attr-defined]
        if stop_blk is None:
            return None

        builder = ModificationBuilder.from_snapshot(snapshot)
        modifications: list = []
        owned_blocks: set[int] = set()
        seen_sites: set[tuple[int, int]] = set()
        nop_count = 0
        state_var_stkoff = self._resolve_state_var_stkoff(snapshot)

        # First, inspect any shared return-mux block that feeds BLT_STOP.
        # Many leaked constants are staged one block before the stop block
        # and then funneled through a common `mov return_slot -> rax` mux.
        npred = stop_blk.npred()
        for i in range(npred):
            mux_serial = stop_blk.pred(i)
            mux_blk = mba.get_mblock(mux_serial)  # type: ignore[attr-defined]
            if mux_blk is None:
                continue
            return_slot_stkoff = self._find_return_slot_stkoff(mux_blk)
            if return_slot_stkoff is None:
                continue

            mux_npred = mux_blk.npred()
            for j in range(mux_npred):
                feeder_serial = mux_blk.pred(j)
                feeder_blk = mba.get_mblock(feeder_serial)  # type: ignore[attr-defined]
                if feeder_blk is None:
                    continue
                if feeder_blk.nsucc() != 1:
                    continue
                if feeder_blk.succ(0) != mux_serial:
                    continue

                insn = feeder_blk.tail
                walk_limit = 6
                walked = 0
                while insn is not None and walked < walk_limit:
                    if self._is_synthetic_return_feeder_insn(
                        insn,
                        return_slot_stkoff=return_slot_stkoff,
                        state_var_stkoff=state_var_stkoff,
                    ):
                        site = (feeder_serial, insn.ea)
                        if site not in seen_sites:
                            modifications.append(
                                builder.nop_instruction(
                                    source_block=feeder_serial,
                                    instruction_ea=insn.ea,
                                )
                            )
                            seen_sites.add(site)
                            owned_blocks.add(feeder_serial)
                            nop_count += 1
                            logger.info(
                                "StateConstReturnFixup: NOP synthetic return feeder"
                                " at blk[%d]:0x%x feeding mux blk[%d]",
                                feeder_serial,
                                insn.ea,
                                mux_serial,
                            )
                        break
                    insn = insn.prev
                    walked += 1

        # Also preserve the original narrow scan of BLT_STOP predecessors.
        for i in range(npred):
            pred_serial = stop_blk.pred(i)
            pred_blk = mba.get_mblock(pred_serial)  # type: ignore[attr-defined]
            if pred_blk is None:
                continue

            # Walk backward through instructions in the predecessor block,
            # looking for m_mov with an immediate state constant source.
            insn = pred_blk.tail
            # Limit backward walk to avoid scanning entire large blocks.
            walk_limit = 8
            walked = 0
            while insn is not None and walked < walk_limit:
                if self._is_state_const_mov(insn, known_consts):
                    site = (pred_serial, insn.ea)
                    if site not in seen_sites:
                        modifications.append(
                            builder.nop_instruction(
                                source_block=pred_serial,
                                instruction_ea=insn.ea,
                            )
                        )
                        seen_sites.add(site)
                        owned_blocks.add(pred_serial)
                        nop_count += 1
                        logger.info(
                            "StateConstReturnFixup: NOP m_mov #0x%x at"
                            " blk[%d]:0x%x",
                            insn.l.nnn.value if (
                                insn.l is not None
                                and insn.l.t == ida_hexrays.mop_n
                            ) else 0,
                            pred_serial,
                            insn.ea,
                        )
                    # Only remove the LAST state-const write per block to be
                    # conservative; break after the first match walking backward.
                    break
                insn = insn.prev
                walked += 1

        logger.info(
            "StateConstReturnFixup: %d instructions NOPed across %d"
            " BLT_STOP predecessors",
            nop_count,
            npred,
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
            transitions_resolved=0,
            blocks_freed=0,
            conflict_density=0.0,
        )
        return PlanFragment(
            strategy_name=self.name,
            family=self.family,
            modifications=modifications,
            ownership=ownership,
            prerequisites=["linearized_flow_graph"],
            expected_benefit=benefit,
            risk_score=0.1,
            metadata={
                "safeguard_min_required": 1,
                # This cleanup intentionally stacks on top of the DAG
                # linearizer's block ownership: it NOPs leaked return-slot
                # feeders inside already-linearized handler blocks and does not
                # compete for CFG edges or state transitions.
                "allow_prerequisite_block_overlap": True,
                # NOPing stale state-var → return-slot feeders temporarily
                # creates undefined-use (INTERR 50846) that IDA resolves at
                # later maturities via its own dataflow optimizer.
                "execution_policy": "nop_cleanup_relaxed",
            },
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _collect_state_constants(snapshot: AnalysisSnapshot) -> set[int]:
        """Collect all known state constants from snapshot and BST result.

        Merges ``snapshot.state_constants`` with values from
        ``bst_result.handler_state_map`` and ``bst_result.handler_range_map``.

        Args:
            snapshot: Immutable analysis snapshot.

        Returns:
            Set of integer state constant values.
        """
        consts: set[int] = set(snapshot.state_constants)

        bst = snapshot.bst_result
        if bst is not None:
            handler_state_map: dict = (
                getattr(bst, "handler_state_map", {}) or {}
            )
            handler_range_map: dict = (
                getattr(bst, "handler_range_map", {}) or {}
            )
            for state_val in handler_state_map.values():
                consts.add(int(state_val))
            for low, high in handler_range_map.values():
                if low is not None:
                    consts.add(int(low))
                if high is not None:
                    consts.add(int(high))

        return consts

    @staticmethod
    def _find_stop_block(mba: object) -> int | None:
        """Find the BLT_STOP block serial in the MBA.

        Scans from the last block backward (BLT_STOP is typically the last
        block).

        Args:
            mba: An ``ida_hexrays.mba_t`` instance.

        Returns:
            Block serial of BLT_STOP, or ``None`` if not found.
        """
        qty = mba.qty  # type: ignore[attr-defined]
        # BLT_STOP is almost always the last block; scan backward for safety.
        for i in range(qty - 1, -1, -1):
            blk = mba.get_mblock(i)  # type: ignore[attr-defined]
            if blk is not None and int(blk.type) == _BLT_STOP:
                return i
        return None

    @staticmethod
    def _is_state_const_mov(
        insn: object,
        known_consts: set[int],
    ) -> bool:
        """Check if an instruction is ``m_mov #<state_const>, <dest>``.

        The instruction must be:
        - Opcode: ``m_mov``
        - Left (source) operand: ``mop_n`` (immediate) with value in
          ``known_consts``
        - Destination: ``mop_r`` (register) or ``mop_S`` (stack variable)

        Args:
            insn: An ``ida_hexrays.minsn_t`` instruction.
            known_consts: Set of known dispatcher state constant values.

        Returns:
            True if the instruction writes a known state constant.
        """
        if insn.opcode != ida_hexrays.m_mov:
            return False

        src = insn.l
        if src is None or src.t != ida_hexrays.mop_n:
            return False

        try:
            val = src.nnn.value
        except (AttributeError, TypeError):
            return False

        if val not in known_consts:
            return False

        # Verify destination is a register or stack variable (return slot).
        dst = insn.d
        if dst is None:
            return False
        if dst.t not in (ida_hexrays.mop_r, ida_hexrays.mop_S):
            return False

        return True

    @staticmethod
    def _resolve_state_var_stkoff(snapshot: AnalysisSnapshot) -> int | None:
        """Best-effort state-var stack offset resolution."""
        detector = getattr(snapshot, "detector", None)
        if detector is not None:
            try:
                from d810.recon.flow.transition_builder import _get_state_var_stkoff

                return _get_state_var_stkoff(detector)
            except Exception:
                pass
        sm = getattr(snapshot, "state_machine", None)
        if sm is not None and getattr(sm, "state_var", None) is not None:
            try:
                sv = sm.state_var
                if sv.t == ida_hexrays.mop_S:
                    return sv.s.off
            except Exception:
                pass
        return None

    @staticmethod
    def _find_return_slot_stkoff(mux_blk: object) -> int | None:
        """Extract the stack return-slot copied into rax in a return mux block."""
        insn = getattr(mux_blk, "head", None)
        walk_limit = 4
        walked = 0
        while insn is not None and walked < walk_limit:
            if (
                insn.opcode == ida_hexrays.m_mov
                and insn.l is not None
                and insn.l.t == ida_hexrays.mop_S
                and insn.d is not None
                and insn.d.t == ida_hexrays.mop_r
            ):
                try:
                    return insn.l.s.off
                except Exception:
                    return None
            insn = insn.next
            walked += 1
        return None

    @staticmethod
    def _is_synthetic_return_feeder_insn(
        insn: object,
        *,
        return_slot_stkoff: int,
        state_var_stkoff: int | None,
    ) -> bool:
        """Match feeder writes that leak synthetic constants into the return slot."""
        dst = getattr(insn, "d", None)
        if (
            dst is None
            or dst.t != ida_hexrays.mop_S
            or dst.s is None
            or dst.s.off != return_slot_stkoff
        ):
            return False

        src = getattr(insn, "l", None)
        if insn.opcode == ida_hexrays.m_mov and src is not None and src.t == ida_hexrays.mop_n:
            return True

        if insn.opcode not in (
            ida_hexrays.m_mov,
            ida_hexrays.m_xdu,
            ida_hexrays.m_xds,
        ):
            return False

        if (
            state_var_stkoff is not None
            and src is not None
            and src.t == ida_hexrays.mop_S
            and src.s is not None
            and src.s.off == state_var_stkoff
        ):
            return True

        return False
