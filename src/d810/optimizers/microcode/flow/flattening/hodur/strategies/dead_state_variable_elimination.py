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
Prerequisites: ``["state_write_reconstruction"]`` -- the reconstruction pass
must already have rewritten the semantic handoffs before stale state-variable
reads are removed.
"""
from __future__ import annotations

import ida_hexrays
from d810.core.typing import TYPE_CHECKING

from d810.core import logging
from d810.evaluator.hexrays_microcode.chains import (
    DefSite,
    UseSite,
    find_all_uses_of_stkvar,
    find_reaching_defs_for_stkvar,
)
from d810.evaluator.hexrays_microcode.valrange_dataflow import (
    ValrangeKey,
    run_valrange_fixpoint,
)
from d810.evaluator.hexrays_microcode.forward_dataflow import FixpointResult
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

        # Collect known state constants for reaching-def override check.
        state_constants = self._collect_state_constants(snapshot)

        # Run valrange fixpoint once for the entire MBA.  The result is
        # used by _dest_is_non_state_stkvar to reclassify reaching defs
        # whose source is not a literal constant but whose valrange collapses
        # to a known state constant.
        vr_fixpoint: FixpointResult | None = None
        try:
            vr_fixpoint = run_valrange_fixpoint(mba)
            logger.info(
                "DSVE: valrange fixpoint converged in %d iterations",
                vr_fixpoint.iterations,
            )
        except Exception:
            logger.info("DSVE: valrange fixpoint failed; falling back to ad-hoc checks")

        # BST check nodes read the state var as a comparison operand (m_jnz
        # condition).  Nopping the tail of a 2WAY block causes INTERR 50860
        # because the succset no longer matches the tail instruction type.
        _bst = snapshot.bst_result
        _bst_node_blocks: set[int] = set(getattr(_bst, "bst_node_blocks", set()) or set())

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
            # Skip BST check nodes — they are state-machine infrastructure,
            # not handler body reads.  Their tail instructions are conditional
            # branches; nopping them causes INTERR 50860 (succset mismatch).
            if use.block_serial in _bst_node_blocks:
                logger.debug(
                    "DSVE: skipping NOP in BST node blk[%d] ea=0x%x",
                    use.block_serial, use.ins_ea,
                )
                continue

            # Skip use sites in gutted blocks — after Gut-and-Wire, these
            # blocks contain only m_nop/m_goto; their DU chain entries are
            # stale leftovers from pre-gut analysis.
            if self._is_gutted_block(mba, use.block_serial):
                logger.debug(
                    "DSVE: skipping NOP in gutted blk[%d] ea=0x%x",
                    use.block_serial, use.ins_ea,
                )
                continue

            # Safety net: never NOP the tail instruction of a 2WAY block.
            # Regardless of BST membership, a conditional branch tail cannot
            # be replaced with m_nop while the block retains 2 successors —
            # IDA's verify() raises INTERR 50860 (succset mismatch).
            if mba is not None:
                _blk = mba.get_mblock(use.block_serial)
                if (
                    _blk is not None
                    and _blk.nsucc() > 1
                    and _blk.tail is not None
                    and _blk.tail.ea == use.ins_ea
                ):
                    logger.debug(
                        "DSVE: skipping NOP of 2WAY tail in blk[%d] ea=0x%x",
                        use.block_serial, use.ins_ea,
                    )
                    continue

            # Guard: skip NOP when the instruction WRITES to state_var
            # with a non-constant (dynamic) source.  OLLVM reuses state_var
            # as a return-value carrier on early-exit paths (e.g.,
            # ``state_var = v51``).  NOPing such writes destroys the value
            # before it reaches the return slot via ``m_xdu``.
            if self._is_dynamic_state_var_write(
                mba, use, state_var_stkoff, state_constants,
            ):
                logger.debug(
                    "DSVE: skipping NOP of state_var write with non-const"
                    " source in blk[%d] ea=0x%x",
                    use.block_serial, use.ins_ea,
                )
                continue

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
                    state_constants=state_constants,
                    state_var_width=state_var_width,
                    vr_fixpoint=vr_fixpoint,
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
            prerequisites=["state_write_reconstruction"],
            expected_benefit=benefit,
            risk_score=0.1,
            metadata={"safeguard_min_required": 1},
        )

    @staticmethod
    def _is_gutted_block(mba: object, serial: int) -> bool:
        """Check whether a block has been gutted (all instructions NOPed).

        After Gut-and-Wire, unreachable blocks have their instructions
        replaced with ``m_nop`` (possibly followed by a trailing ``m_goto``).
        IDA's DU chains are stale — computed before the gut pass — so they
        still reference defs in these dead blocks.  This predicate lets
        DSVE skip such defs.

        Args:
            mba: An ``ida_hexrays.mba_t`` instance.
            serial: Block serial number to check.

        Returns:
            ``True`` if every instruction in the block is ``m_nop`` or
            ``m_goto`` (i.e., the block has been gutted).
        """
        try:
            blk = mba.get_mblock(serial)  # type: ignore[attr-defined]
        except (AttributeError, IndexError):
            return False
        if blk is None:
            return False
        insn = blk.head
        if insn is None:
            # Empty block — treat as gutted.
            return True
        while insn is not None:
            if (
                insn.opcode != ida_hexrays.m_nop
                and insn.opcode != ida_hexrays.m_goto
            ):
                return False
            insn = insn.next
        return True

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

    @staticmethod
    def _is_dynamic_state_var_write(
        mba: object,
        use: UseSite,
        stkoff: int,
        state_constants: frozenset[int],
    ) -> bool:
        """Check if the instruction writes a non-constant value TO state_var.

        OLLVM reuses the state variable as a return-value carrier on
        early-exit paths.  For example::

            m_mov %var_XX, %state_var     ; state_var = v51

        If we NOP this write, the state variable retains its stale
        dispatcher constant, which then leaks into the return slot via
        a downstream ``m_xdu %return_slot = %state_var``.

        Only state-constant writes (``mop_n`` source whose value is in
        *state_constants*) are safe to NOP — those are pure BST dispatch
        assignments.  All other writes (register, stack variable,
        expression sources, or constants not in state_constants) must
        be preserved.

        Args:
            mba: An ``ida_hexrays.mba_t`` instance.
            use: The use site to inspect.
            stkoff: Stack offset of the state variable.
            state_constants: Known dispatcher state constant values.

        Returns:
            ``True`` if the instruction writes a non-constant (dynamic)
            value to state_var and should NOT be NOPed.
        """
        try:
            blk = mba.get_mblock(use.block_serial)  # type: ignore[attr-defined]
        except (AttributeError, IndexError):
            return False

        if blk is None:
            return False

        cur_ins = blk.head
        while cur_ins is not None:
            if cur_ins.ea == use.ins_ea:
                # Check if state_var is the destination operand.
                d = cur_ins.d
                d_is_state_var = (
                    d is not None
                    and d.t == ida_hexrays.mop_S
                    and d.s is not None
                    and d.s.off == stkoff
                )
                if not d_is_state_var:
                    return False

                # State_var IS the destination.  Inspect source operands.
                # For unary ops (m_mov, m_xdu, m_xds): source is ``l``.
                # For binary ops (m_sub, m_xor, etc.): sources are
                # ``l`` and ``r`` — if either is non-constant, the
                # result flowing into state_var is dynamic.
                source_ops = []
                if cur_ins.l is not None:
                    source_ops.append(cur_ins.l)
                if cur_ins.r is not None:
                    source_ops.append(cur_ins.r)

                if not source_ops:
                    # No source operands at all (unexpected); be
                    # conservative and allow NOP.
                    return False

                for src in source_ops:
                    if src.t == ida_hexrays.mop_n:
                        # Immediate constant — check if it's a known
                        # state constant.
                        try:
                            val = src.nnn.value
                        except (AttributeError, TypeError):
                            # Can't read value; treat as dynamic.
                            return True
                        # Mask to 32 bits for OLLVM state comparison.
                        if (val & 0xFFFFFFFF) not in state_constants:
                            return True
                    else:
                        # Non-immediate source (mop_r, mop_S, mop_d,
                        # etc.) — this is a dynamic value.
                        return True

                # All source operands are state constants — safe to NOP.
                return False
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
    def _resolve_def_via_fixpoint(
        vr_fixpoint: FixpointResult,
        def_block_serial: int,
        state_var_stkoff: int,
        state_var_width: int,
    ) -> int | None:
        """Look up the state variable value from the valrange fixpoint result.

        Queries the fixpoint's ``out_states`` for the def block to find
        whether the state variable has a singleton value after the block's
        transfer function.  This replaces per-def IDA valrange queries with
        a single cached fixpoint computation.

        Args:
            vr_fixpoint: Precomputed fixpoint result from
                :func:`run_valrange_fixpoint`.
            def_block_serial: Block serial of the defining instruction.
            state_var_stkoff: Stack offset of the dead state variable.
            state_var_width: Operand width in bytes (typically 4).

        Returns:
            A single concrete integer if the fixpoint resolves the state
            variable to a singleton value, otherwise ``None``.
        """
        state_var_key = ValrangeKey(
            mop_type=ida_hexrays.mop_S,
            identifier=state_var_stkoff,
            size=state_var_width,
        )
        out_env = vr_fixpoint.out_states.get(def_block_serial, {})
        if state_var_key not in out_env:
            return None

        vr = out_env[state_var_key]
        try:
            ok, val = vr.cvt_to_single_value()
            if ok:
                return int(val)
        except (AttributeError, TypeError):
            # cvt_to_single_value not available; try dstr() parse fallback.
            pass
        return None

    @staticmethod
    def _chase_indirect_stkvar_def(
        def_blk: object,
        def_ins: object,
        source_stkoff: int,
        state_constants: frozenset[int],
    ) -> int | None:
        """Chase one level of indirection through a stack variable copy.

        When the reaching def is ``m_mov %src_stkvar, %state_var``, walk
        backward in the same block to find the most recent write to
        ``%src_stkvar``.  If that write is ``m_mov #const, %src_stkvar``
        and *const* is in *state_constants*, return the constant value.

        Args:
            def_blk: ``ida_hexrays.mblock_t`` containing the def instruction.
            def_ins: The defining ``ida_hexrays.minsn_t`` instruction (the
                ``m_mov %src_stkvar, %state_var`` instruction).
            source_stkoff: Stack offset of the intermediate source variable.
            state_constants: Known dispatcher state constant values.

        Returns:
            The state constant value if the indirect chain resolves,
            otherwise ``None``.
        """
        try:
            # Walk backward from def_ins to find the latest write to
            # source_stkoff in this block.
            prev = def_ins.prev  # type: ignore[union-attr]
            while prev is not None:
                # Look for m_mov #const, %src_stkvar
                if prev.opcode == ida_hexrays.m_mov:
                    d = prev.d
                    if (
                        d is not None
                        and d.t == ida_hexrays.mop_S
                        and d.s is not None
                        and d.s.off == source_stkoff
                    ):
                        # Found a write to the source variable.
                        l = prev.l
                        if (
                            l is not None
                            and l.t == ida_hexrays.mop_n
                        ):
                            try:
                                val = l.nnn.value
                            except (AttributeError, TypeError):
                                return None
                            if (val & 0xFFFFFFFF) in state_constants:
                                return val
                        # Non-constant source — stop chasing.
                        return None
                prev = prev.prev
        except Exception:
            pass
        return None

    @staticmethod
    def _collect_state_constants(snapshot: AnalysisSnapshot) -> frozenset[int]:
        """Collect all known state constants from the snapshot and BST result.

        Merges ``snapshot.state_constants`` with values from
        ``bst_result.handler_state_map`` and ``bst_result.handler_range_map``.

        Args:
            snapshot: Immutable analysis snapshot.

        Returns:
            Frozen set of integer state constant values.
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

        return frozenset(consts)

    @staticmethod
    def _dest_is_non_state_stkvar(
        mba: object,
        use: UseSite,
        state_var_stkoff: int,
        state_constants: frozenset[int] = frozenset(),
        state_var_width: int = 4,
        vr_fixpoint: FixpointResult | None = None,
    ) -> tuple[str, int] | None:
        """Check if the instruction writes to a non-state stack variable.

        When a copy/widening instruction (``m_mov``, ``m_xdu``, ``m_xds``)
        reads the dead state variable as SOURCE but writes to a DIFFERENT
        stack variable as DESTINATION, NOPing it would destroy the only
        definition of that destination (e.g., the return slot).

        However, if ALL reaching definitions of the state variable at this
        block are known state constants (or already NOPed), the instruction
        is pure dispatcher glue and can safely be NOPed -- the return slot
        has no legitimate value coming through this path.

        Args:
            mba: An ``ida_hexrays.mba_t`` instance.
            use: The use site to inspect.
            state_var_stkoff: Stack offset of the dead state variable.
            state_constants: Known dispatcher state constant values for
                reaching-def override check.
            state_var_width: Operand width of the state variable in bytes.
            vr_fixpoint: Precomputed valrange fixpoint result, or ``None``
                to skip fixpoint-based reclassification.

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
                    skip_tuple = (opname, d.s.off)

                    # --- Reaching-def override ---
                    # If all reaching defs of the state var at this block are
                    # known state constants (or already NOPed), the copy is
                    # pure dispatcher glue and safe to NOP.
                    if not state_constants:
                        return skip_tuple

                    try:
                        defs: list[DefSite] = find_reaching_defs_for_stkvar(
                            mba, use.block_serial,
                            state_var_stkoff, state_var_width,
                        )
                    except Exception:
                        logger.info(
                            "DSVE reaching-def check EXCEPTION for blk[%d];"
                            " preserving guard",
                            use.block_serial,
                        )
                        return skip_tuple

                    if not defs:
                        logger.info(
                            "DSVE reaching-def check for blk[%d]: 0 defs found;"
                            " preserving guard",
                            use.block_serial,
                        )
                        return skip_tuple

                    logger.info(
                        "DSVE reaching-def check for blk[%d]: %d defs found",
                        use.block_serial, len(defs),
                    )

                    non_const_count = 0
                    gutted_count = 0
                    for def_site in defs:
                        # Skip defs from gutted (all-NOP/goto) blocks.
                        # After Gut-and-Wire, IDA's DU chains are stale
                        # and still reference defs in dead blocks.
                        if DeadStateVariableEliminationStrategy._is_gutted_block(
                            mba, def_site.block_serial,
                        ):
                            gutted_count += 1
                            logger.info(
                                "DSVE: skipping def at blk[%d] ea=0x%x"
                                " — gutted block (dead def)",
                                def_site.block_serial,
                                def_site.ins_ea,
                            )
                            continue

                        is_state_const = False
                        reclassify_method: str | None = None
                        try:
                            def_blk = mba.get_mblock(  # type: ignore[attr-defined]
                                def_site.block_serial,
                            )
                            if def_blk is not None:
                                def_ins = def_blk.head
                                while def_ins is not None:
                                    if def_ins.ea == def_site.ins_ea:
                                        # Already NOPed -> safe
                                        if def_ins.opcode == ida_hexrays.m_nop:
                                            is_state_const = True
                                        # m_mov with immediate state constant
                                        elif (
                                            def_ins.opcode == ida_hexrays.m_mov
                                            and def_ins.l is not None
                                            and def_ins.l.t == ida_hexrays.mop_n
                                        ):
                                            try:
                                                val = def_ins.l.nnn.value
                                            except (AttributeError, TypeError):
                                                val = None
                                            if val is not None and val in state_constants:
                                                is_state_const = True

                                        # -- Fallback 1: valrange fixpoint --
                                        # If the def instruction writes to the
                                        # state variable but the source is not an
                                        # immediate constant, look up the cached
                                        # valrange fixpoint to see if the state
                                        # variable collapses to a singleton known
                                        # state constant after this block.
                                        if (
                                            not is_state_const
                                            and vr_fixpoint is not None
                                            and def_ins.d is not None
                                            and def_ins.d.t == ida_hexrays.mop_S
                                            and def_ins.d.s is not None
                                            and def_ins.d.s.off == state_var_stkoff
                                        ):
                                            vr_val = DeadStateVariableEliminationStrategy._resolve_def_via_fixpoint(
                                                vr_fixpoint,
                                                def_site.block_serial,
                                                state_var_stkoff,
                                                state_var_width,
                                            )
                                            if (
                                                vr_val is not None
                                                and (vr_val & 0xFFFFFFFF)
                                                in state_constants
                                            ):
                                                is_state_const = True
                                                reclassify_method = "valrange_fixpoint"
                                                logger.info(
                                                    "DSVE: reclassified def at"
                                                    " blk[%d] ea=0x%x as"
                                                    " state_const via valrange"
                                                    " fixpoint (value=0x%x)",
                                                    def_site.block_serial,
                                                    def_site.ins_ea,
                                                    vr_val & 0xFFFFFFFF,
                                                )

                                        # -- Fallback 2: indirect mop_S chase --
                                        # If the def is ``m_mov %src_stkvar,
                                        # %state_var`` (mop_S source), walk
                                        # backward in the same block to find
                                        # the most recent write to that source
                                        # variable.  If it is ``m_mov #const,
                                        # %src_stkvar`` with const in
                                        # state_constants, reclassify.
                                        if (
                                            not is_state_const
                                            and def_ins.opcode
                                            == ida_hexrays.m_mov
                                            and def_ins.l is not None
                                            and def_ins.l.t
                                            == ida_hexrays.mop_S
                                            and def_ins.l.s is not None
                                        ):
                                            ind_val = (
                                                DeadStateVariableEliminationStrategy._chase_indirect_stkvar_def(
                                                    def_blk,
                                                    def_ins,
                                                    def_ins.l.s.off,
                                                    state_constants,
                                                )
                                            )
                                            if ind_val is not None:
                                                is_state_const = True
                                                reclassify_method = "indirect"
                                                logger.info(
                                                    "DSVE: reclassified def at"
                                                    " blk[%d] ea=0x%x as"
                                                    " state_const via indirect"
                                                    " (value=0x%x)",
                                                    def_site.block_serial,
                                                    def_site.ins_ea,
                                                    ind_val & 0xFFFFFFFF,
                                                )

                                        break
                                    def_ins = def_ins.next
                        except Exception:
                            pass

                        logger.info(
                            "  def in blk[%d] ea=0x%x: opcode=%d"
                            " (is_state_const=%s%s)",
                            def_site.block_serial,
                            def_site.ins_ea,
                            def_site.ins_opcode,
                            is_state_const,
                            " via %s" % reclassify_method
                            if reclassify_method
                            else "",
                        )
                        if not is_state_const:
                            non_const_count += 1

                    if gutted_count > 0:
                        logger.info(
                            "DSVE: filtered %d/%d reaching defs from"
                            " gutted blocks for blk[%d]",
                            gutted_count, len(defs), use.block_serial,
                        )

                    if non_const_count == 0:
                        logger.info(
                            "DSVE guard OVERRIDDEN for blk[%d]: all %d"
                            " reaching defs are state constants"
                            " (%d gutted, %d live)",
                            use.block_serial, len(defs),
                            gutted_count, len(defs) - gutted_count,
                        )
                        return None  # Allow NOP

                    logger.info(
                        "DSVE guard PRESERVED for blk[%d]: %d/%d defs"
                        " are non-constant (%d gutted)",
                        use.block_serial, non_const_count, len(defs),
                        gutted_count,
                    )
                    return skip_tuple

                return None
            cur_ins = cur_ins.next

        return None
