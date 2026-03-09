"""DeadStateVariableEliminationStrategy -- NOP reads of the dead state variable.

After Hodur linearization, the OLLVM dispatcher state variable is semantically
dead.  DirectLinearization already NOPs state variable **writes** (``m_mov
#CONST, state_var``).  However, downstream **reads** of the state variable
survive -- for example, ``m_xdu %var_8.8 = %var_7BC.4`` instructions that
widen the dead state variable into a return slot.

This strategy identifies all remaining read sites of the state variable
across the entire MBA and emits ``NopInstruction`` modifications to eliminate
them, preventing stale dispatcher state constants from leaking into the
decompiled pseudocode.

Family: ``FAMILY_CLEANUP`` -- runs after all other strategies.
Prerequisites: ``["direct_handler_linearization"]`` -- state writes must
already be handled by DirectLinearization.
"""
from __future__ import annotations

import ida_hexrays
from d810.core.typing import TYPE_CHECKING

from d810.core import logging
from d810.evaluator.hexrays_microcode.chains import (
    UseSite,
    find_all_uses_of_stkvar,
)
from d810.optimizers.microcode.flow.flattening.hodur._modification_bridge import (
    ModificationBuilder,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    FAMILY_CLEANUP,
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

logger = logging.getLogger("D810.hodur.strategy.dead_state_var_elim")

__all__ = ["DeadStateVariableEliminationStrategy"]


class DeadStateVariableEliminationStrategy:
    """NOP all remaining reads of the dead state variable after linearization.

    After DirectLinearization eliminates the dispatcher and NOPs state variable
    writes, some instructions still read the state variable (e.g., ``m_xdu``
    that widens the state variable into a return register slot).  These reads
    are dispatcher glue with no semantic purpose after unflattening.

    This strategy:

    1. Resolves the state variable stack offset from the snapshot.
    2. Uses DU chains (via :func:`find_all_uses_of_stkvar`) to locate every
       block and instruction that reads the state variable.
    3. Emits a ``NopInstruction`` for each read site to eliminate the dead
       reference.

    Family: ``FAMILY_CLEANUP`` -- last in pipeline.
    Risk: LOW -- only NOPs instructions whose sole source is the dead state var.
    """

    @property
    def name(self) -> str:
        """Return the strategy identifier."""
        return "dead_state_variable_elimination"

    @property
    def family(self) -> str:
        """Return the strategy family."""
        return FAMILY_CLEANUP

    def is_applicable(self, snapshot: AnalysisSnapshot) -> bool:
        """Return True when a state machine with a known state variable exists.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            True if the snapshot describes a state machine whose state variable
            stack offset can be determined.
        """
        sm = snapshot.state_machine
        if sm is None:
            return False
        if not getattr(sm, "handlers", None):
            return False
        # We need the state variable to be identifiable.
        stkoff = self._resolve_stkoff(snapshot)
        return stkoff is not None

    def plan(self, snapshot: AnalysisSnapshot) -> PlanFragment | None:
        """Produce a PlanFragment with NOP edits for dead state variable reads.

        Scans the entire MBA for instructions that read the state variable
        and emits ``NopInstruction`` modifications for each.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            A PlanFragment with NOP modifications, or ``None`` when no read
            sites were found or the strategy is not applicable.
        """
        if not self.is_applicable(snapshot):
            return None

        mba = snapshot.mba
        if mba is None:
            return None

        state_var_stkoff = self._resolve_stkoff(snapshot)
        if state_var_stkoff is None:
            return None

        # Determine width of the state variable (typically 4 bytes for OLLVM).
        state_var_width = self._resolve_width(snapshot, state_var_stkoff)

        # Find all read sites via DU chains.
        use_sites: list[UseSite] = find_all_uses_of_stkvar(
            mba, state_var_stkoff, state_var_width,
        )

        if not use_sites:
            logger.info(
                "DeadStateVarElim: no read sites found for state_var stkoff=0x%x",
                state_var_stkoff,
            )
            return None

        builder = ModificationBuilder.from_snapshot(snapshot)
        modifications: list = []
        owned_blocks: set[int] = set()
        nop_count = 0

        for use in use_sites:
            # Verify this is genuinely a read of the state variable as a
            # source operand (not a write destination -- those are handled by
            # DirectLinearization).
            if self._is_state_var_read(mba, use, state_var_stkoff):
                # Guard: do NOT NOP instructions whose destination is a
                # non-state stack variable (e.g. m_xdu widening the dead
                # state var into the return slot).  NOPing such instructions
                # kills the only definition of the return slot, producing
                # uninitialized return values.
                skip_reason = self._dest_is_non_state_stkvar(
                    mba, use, state_var_stkoff,
                )
                if skip_reason is not None:
                    logger.warning(
                        "DSVE: skipping NOP of %s at blk[%d]:0x%x"
                        " — dest is non-state stkvar at off=0x%x",
                        skip_reason[0],
                        use.block_serial,
                        use.ins_ea,
                        skip_reason[1],
                    )
                    continue

                modifications.append(
                    builder.nop_instruction(
                        source_block=use.block_serial,
                        instruction_ea=use.ins_ea,
                    )
                )
                owned_blocks.add(use.block_serial)
                nop_count += 1
                logger.debug(
                    "DeadStateVarElim: NOP read site blk[%d] ea=0x%x opcode=%d",
                    use.block_serial,
                    use.ins_ea,
                    use.ins_opcode,
                )

        logger.info(
            "DeadStateVarElim: %d/%d use sites NOPed for state_var stkoff=0x%x",
            nop_count,
            len(use_sites),
            state_var_stkoff,
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
            prerequisites=["direct_handler_linearization"],
            expected_benefit=benefit,
            risk_score=0.1,
            metadata={"safeguard_min_required": 1},
        )

    @staticmethod
    def _resolve_stkoff(snapshot: AnalysisSnapshot) -> int | None:
        """Extract the state variable stack offset from the snapshot.

        Mirrors the resolution logic in DirectLinearizationStrategy.plan():
        first tries the detector, then falls back to reading ``mop_S.s.off``
        from the state machine's ``state_var``.

        Args:
            snapshot: Immutable analysis snapshot.

        Returns:
            Stack offset as an integer, or ``None`` if unavailable.
        """
        stkoff: int | None = None
        detector = snapshot.detector
        if detector is not None:
            try:
                stkoff = _get_state_var_stkoff(detector)
            except Exception:
                pass
        if stkoff is None:
            sm = snapshot.state_machine
            if sm is not None and sm.state_var is not None:
                sv = sm.state_var
                try:
                    if sv.t == ida_hexrays.mop_S:
                        stkoff = sv.s.off
                except Exception:
                    pass
        return stkoff

    @staticmethod
    def _resolve_width(
        snapshot: AnalysisSnapshot,
        stkoff: int,
    ) -> int:
        """Determine the operand width of the state variable.

        Reads the ``size`` attribute from the state machine's ``state_var``
        mop if available; defaults to 4 bytes (standard OLLVM pattern).

        Args:
            snapshot: Immutable analysis snapshot.
            stkoff: Stack offset (unused, reserved for future use).

        Returns:
            Operand width in bytes.
        """
        sm = snapshot.state_machine
        if sm is not None and sm.state_var is not None:
            try:
                return sm.state_var.size
            except (AttributeError, TypeError):
                pass
        return 4

    @staticmethod
    def _is_state_var_read(
        mba: object,
        use: UseSite,
        stkoff: int,
    ) -> bool:
        """Verify that the use site reads the state variable as a source operand.

        Returns ``False`` if the instruction only writes to the state variable
        (destination operand) without reading it -- those are write sites
        handled by DirectLinearization.

        Args:
            mba: An ``ida_hexrays.mba_t`` instance.
            use: The use site to check.
            stkoff: Stack offset of the state variable.

        Returns:
            ``True`` if the state variable appears as a source (read) operand.
        """
        try:
            blk = mba.get_mblock(use.block_serial)  # type: ignore[attr-defined]
        except (AttributeError, IndexError):
            return False

        if blk is None:
            return False

        # Walk to the instruction at the given EA.
        cur_ins = blk.head
        while cur_ins is not None:
            if cur_ins.ea == use.ins_ea:
                # Check if the state var appears as a source operand.
                l_is_stkvar = (
                    cur_ins.l is not None
                    and cur_ins.l.t == ida_hexrays.mop_S
                    and cur_ins.l.s is not None
                    and cur_ins.l.s.off == stkoff
                )
                r_is_stkvar = (
                    cur_ins.r is not None
                    and cur_ins.r.t == ida_hexrays.mop_S
                    and cur_ins.r.s is not None
                    and cur_ins.r.s.off == stkoff
                )
                return l_is_stkvar or r_is_stkvar
            cur_ins = cur_ins.next

        return False

    # Opcodes that copy/widen a source into a destination.
    _COPY_OPCODES: frozenset[int] = frozenset({
        ida_hexrays.m_mov,
        ida_hexrays.m_xdu,
        ida_hexrays.m_xds,
    })

    # Opcode names for diagnostic logging.
    _OPCODE_NAMES: dict[int, str] = {
        ida_hexrays.m_mov: "m_mov",
        ida_hexrays.m_xdu: "m_xdu",
        ida_hexrays.m_xds: "m_xds",
    }

    @staticmethod
    def _dest_is_non_state_stkvar(
        mba: object,
        use: UseSite,
        state_var_stkoff: int,
    ) -> tuple[str, int] | None:
        """Check if the instruction writes to a non-state stack variable.

        When a copy/widening instruction (``m_mov``, ``m_xdu``, ``m_xds``)
        reads the dead state variable as SOURCE but writes to a DIFFERENT
        stack variable as DESTINATION, NOPing it would destroy the only
        definition of that destination (e.g., the return slot).

        Args:
            mba: An ``ida_hexrays.mba_t`` instance.
            use: The use site to inspect.
            state_var_stkoff: Stack offset of the dead state variable.

        Returns:
            A ``(opcode_name, dest_stkoff)`` tuple if the guard triggers
            (meaning the NOP should be skipped), or ``None`` if safe to NOP.
        """
        try:
            blk = mba.get_mblock(use.block_serial)  # type: ignore[attr-defined]
        except (AttributeError, IndexError):
            return None

        if blk is None:
            return None

        cur_ins = blk.head
        while cur_ins is not None:
            if cur_ins.ea == use.ins_ea:
                # Only guard copy/widening opcodes.
                if cur_ins.opcode not in DeadStateVariableEliminationStrategy._COPY_OPCODES:
                    return None
                # Check if dest is a stack variable different from state var.
                d = cur_ins.d
                if (
                    d is not None
                    and d.t == ida_hexrays.mop_S
                    and d.s is not None
                    and d.s.off != state_var_stkoff
                ):
                    opname = DeadStateVariableEliminationStrategy._OPCODE_NAMES.get(
                        cur_ins.opcode, "opcode_%d" % cur_ins.opcode,
                    )
                    return (opname, d.s.off)
                return None
            cur_ins = cur_ins.next

        return None
