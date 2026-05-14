"""Hex-Rays dead state-variable cleanup evidence collection."""
from __future__ import annotations

from dataclasses import dataclass

import ida_hexrays

from d810.cfg.state_variable import StateVariableRef
from d810.core.logging import getLogger
from d810.core.typing import Protocol
from d810.evaluator.hexrays_microcode.chains import (
    DefSite,
    UseSite,
    find_all_uses_of_stkvar,
    find_reaching_defs_for_stkvar,
)
from d810.evaluator.hexrays_microcode.forward_dataflow import FixpointResult
from d810.evaluator.hexrays_microcode.valrange_dataflow import (
    ValrangeKey,
    run_valrange_fixpoint,
)

logger = getLogger(__name__)


@dataclass(frozen=True, slots=True)
class DeadStateReadCleanupSite:
    """A neutral dead state-variable read cleanup site."""

    block_serial: int
    insn_ea: int
    opcode_name: str


@dataclass(frozen=True, slots=True)
class DeadStateReadSkip:
    """Diagnostic-only skip reason for a candidate dead-state read site."""

    block_serial: int
    insn_ea: int
    reason: str
    detail: str = ""


@dataclass(frozen=True, slots=True)
class DeadStateVariableCleanupEvidence:
    """Batch result for dead state-variable cleanup evidence."""

    state_variable: StateVariableRef
    use_site_count: int
    sites: tuple[DeadStateReadCleanupSite, ...]
    skips: tuple[DeadStateReadSkip, ...] = ()
    valrange_iterations: int | None = None


class DeadStateVariableEvidenceBackend(Protocol):
    """Backend boundary for dead state-variable read cleanup evidence."""

    def resolve_state_variable(
        self,
        *,
        detector: object | None,
        state_var: object | None,
    ) -> StateVariableRef | None:
        """Return the dispatcher state-variable identity, if available."""

    def collect_dead_state_read_cleanup_evidence(
        self,
        mba: object,
        *,
        state_variable: StateVariableRef,
        known_state_constants: set[int] | frozenset[int],
        bst_node_blocks: set[int] | frozenset[int] = frozenset(),
    ) -> DeadStateVariableCleanupEvidence:
        """Return neutral cleanup sites for dead state-variable reads."""


class HexRaysDeadStateVariableEvidenceBackend:
    """Use live Hex-Rays microcode to classify dead state-variable reads."""

    def resolve_state_variable(
        self,
        *,
        detector: object | None,
        state_var: object | None,
    ) -> StateVariableRef | None:
        """Resolve the state variable from detector evidence or live mop data."""
        candidates: list[object] = []
        if detector is not None:
            sm = getattr(detector, "state_machine", None)
            detector_state_var = getattr(sm, "state_var", None)
            if detector_state_var is not None:
                candidates.append(detector_state_var)
        if state_var is not None:
            candidates.append(state_var)

        for candidate in candidates:
            try:
                if candidate.t != ida_hexrays.mop_S:
                    continue
                stkoff = int(candidate.s.off)
                width = int(getattr(candidate, "size", 4) or 4)
            except Exception:
                continue
            return StateVariableRef(stkoff=stkoff, width=width)
        return None

    def collect_dead_state_read_cleanup_evidence(
        self,
        mba: object,
        *,
        state_variable: StateVariableRef,
        known_state_constants: set[int] | frozenset[int],
        bst_node_blocks: set[int] | frozenset[int] = frozenset(),
    ) -> DeadStateVariableCleanupEvidence:
        state_constants = frozenset(int(value) for value in known_state_constants)
        bst_blocks = frozenset(int(block) for block in bst_node_blocks)
        vr_fixpoint = _run_valrange_fixpoint(mba)

        use_sites: list[UseSite] = find_all_uses_of_stkvar(
            mba,
            state_variable.stkoff,
            state_variable.width,
        )
        cleanup_sites: list[DeadStateReadCleanupSite] = []
        skips: list[DeadStateReadSkip] = []

        for use in use_sites:
            decision = _classify_dead_state_use(
                mba,
                use,
                state_variable=state_variable,
                state_constants=state_constants,
                bst_node_blocks=bst_blocks,
                vr_fixpoint=vr_fixpoint,
            )
            if isinstance(decision, DeadStateReadCleanupSite):
                cleanup_sites.append(decision)
            else:
                skips.append(decision)

        return DeadStateVariableCleanupEvidence(
            state_variable=state_variable,
            use_site_count=len(use_sites),
            sites=tuple(cleanup_sites),
            skips=tuple(skips),
            valrange_iterations=(
                vr_fixpoint.iterations if vr_fixpoint is not None else None
            ),
        )


def _run_valrange_fixpoint(mba: object) -> FixpointResult | None:
    try:
        result = run_valrange_fixpoint(mba)
        logger.info(
            "DSVE: valrange fixpoint converged in %d iterations",
            result.iterations,
        )
        return result
    except Exception:
        logger.info("DSVE: valrange fixpoint failed; falling back to ad-hoc checks")
        return None


def _classify_dead_state_use(
    mba: object,
    use: UseSite,
    *,
    state_variable: StateVariableRef,
    state_constants: frozenset[int],
    bst_node_blocks: frozenset[int],
    vr_fixpoint: FixpointResult | None,
) -> DeadStateReadCleanupSite | DeadStateReadSkip:
    if use.block_serial in bst_node_blocks:
        logger.debug(
            "DSVE: skipping NOP in BST node blk[%d] ea=0x%x",
            use.block_serial,
            use.ins_ea,
        )
        return _skip(use, "bst_node")

    if _is_gutted_block(mba, use.block_serial):
        logger.debug(
            "DSVE: skipping NOP in gutted blk[%d] ea=0x%x",
            use.block_serial,
            use.ins_ea,
        )
        return _skip(use, "gutted_block")

    if _is_two_way_tail(mba, use):
        logger.debug(
            "DSVE: skipping NOP of 2WAY tail in blk[%d] ea=0x%x",
            use.block_serial,
            use.ins_ea,
        )
        return _skip(use, "two_way_tail")

    if _is_dynamic_state_var_write(
        mba,
        use,
        state_variable.stkoff,
        state_constants,
    ):
        logger.debug(
            "DSVE: skipping NOP of state_var write with non-const"
            " source in blk[%d] ea=0x%x",
            use.block_serial,
            use.ins_ea,
        )
        return _skip(use, "dynamic_state_var_write")

    if not _is_state_var_read(mba, use, state_variable.stkoff):
        return _skip(use, "not_state_var_read")

    skip_reason = _dest_is_non_state_stkvar(
        mba,
        use,
        state_variable.stkoff,
        state_constants=state_constants,
        state_var_width=state_variable.width,
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
        return _skip(
            use,
            "dest_non_state_stkvar",
            detail=f"{skip_reason[0]}:0x{skip_reason[1]:x}",
        )

    return DeadStateReadCleanupSite(
        block_serial=int(use.block_serial),
        insn_ea=int(use.ins_ea),
        opcode_name=_OPCODE_NAMES.get(
            int(use.ins_opcode),
            f"opcode_{int(use.ins_opcode)}",
        ),
    )


def _skip(use: UseSite, reason: str, detail: str = "") -> DeadStateReadSkip:
    return DeadStateReadSkip(
        block_serial=int(use.block_serial),
        insn_ea=int(use.ins_ea),
        reason=reason,
        detail=detail,
    )


def _is_gutted_block(mba: object, serial: int) -> bool:
    try:
        blk = mba.get_mblock(serial)  # type: ignore[attr-defined]
    except (AttributeError, IndexError):
        return False
    if blk is None:
        return False
    insn = blk.head
    if insn is None:
        return True
    while insn is not None:
        if (
            insn.opcode != ida_hexrays.m_nop
            and insn.opcode != ida_hexrays.m_goto
        ):
            return False
        insn = insn.next
    return True


def _is_two_way_tail(mba: object, use: UseSite) -> bool:
    try:
        blk = mba.get_mblock(use.block_serial)  # type: ignore[attr-defined]
    except (AttributeError, IndexError):
        return False
    return (
        blk is not None
        and int(blk.nsucc()) > 1  # type: ignore[attr-defined]
        and blk.tail is not None
        and int(blk.tail.ea) == int(use.ins_ea)
    )


def _is_state_var_read(
    mba: object,
    use: UseSite,
    stkoff: int,
) -> bool:
    try:
        blk = mba.get_mblock(use.block_serial)  # type: ignore[attr-defined]
    except (AttributeError, IndexError):
        return False

    if blk is None:
        return False

    cur_ins = blk.head
    while cur_ins is not None:
        if cur_ins.ea == use.ins_ea:
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


def _is_dynamic_state_var_write(
    mba: object,
    use: UseSite,
    stkoff: int,
    state_constants: frozenset[int],
) -> bool:
    try:
        blk = mba.get_mblock(use.block_serial)  # type: ignore[attr-defined]
    except (AttributeError, IndexError):
        return False

    if blk is None:
        return False

    cur_ins = blk.head
    while cur_ins is not None:
        if cur_ins.ea == use.ins_ea:
            d = cur_ins.d
            d_is_state_var = (
                d is not None
                and d.t == ida_hexrays.mop_S
                and d.s is not None
                and d.s.off == stkoff
            )
            if not d_is_state_var:
                return False

            source_ops = []
            if cur_ins.l is not None:
                source_ops.append(cur_ins.l)
            if cur_ins.r is not None:
                source_ops.append(cur_ins.r)

            if not source_ops:
                return False

            for src in source_ops:
                if src.t == ida_hexrays.mop_n:
                    try:
                        val = src.nnn.value
                    except (AttributeError, TypeError):
                        return True
                    if (val & 0xFFFFFFFF) not in state_constants:
                        return True
                else:
                    return True

            return False
        cur_ins = cur_ins.next

    return False


_COPY_OPCODES: frozenset[int] = frozenset({
    ida_hexrays.m_mov,
    ida_hexrays.m_xdu,
    ida_hexrays.m_xds,
})

_OPCODE_NAMES: dict[int, str] = {
    ida_hexrays.m_mov: "m_mov",
    ida_hexrays.m_xdu: "m_xdu",
    ida_hexrays.m_xds: "m_xds",
}


def _resolve_def_via_fixpoint(
    vr_fixpoint: FixpointResult,
    def_block_serial: int,
    state_var_stkoff: int,
    state_var_width: int,
) -> int | None:
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
        pass
    return None


def _chase_indirect_stkvar_def(
    def_blk: object,
    def_ins: object,
    source_stkoff: int,
    state_constants: frozenset[int],
) -> int | None:
    try:
        prev = def_ins.prev  # type: ignore[union-attr]
        while prev is not None:
            if prev.opcode == ida_hexrays.m_mov:
                d = prev.d
                if (
                    d is not None
                    and d.t == ida_hexrays.mop_S
                    and d.s is not None
                    and d.s.off == source_stkoff
                ):
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
                    return None
            prev = prev.prev
    except Exception:
        pass
    return None


def _dest_is_non_state_stkvar(
    mba: object,
    use: UseSite,
    state_var_stkoff: int,
    state_constants: frozenset[int] = frozenset(),
    state_var_width: int = 4,
    vr_fixpoint: FixpointResult | None = None,
) -> tuple[str, int] | None:
    try:
        blk = mba.get_mblock(use.block_serial)  # type: ignore[attr-defined]
    except (AttributeError, IndexError):
        return None

    if blk is None:
        return None

    cur_ins = blk.head
    while cur_ins is not None:
        if cur_ins.ea == use.ins_ea:
            if cur_ins.opcode not in _COPY_OPCODES:
                return None
            d = cur_ins.d
            if (
                d is not None
                and d.t == ida_hexrays.mop_S
                and d.s is not None
                and d.s.off != state_var_stkoff
            ):
                opname = _OPCODE_NAMES.get(
                    cur_ins.opcode, "opcode_%d" % cur_ins.opcode,
                )
                skip_tuple = (opname, d.s.off)

                if not state_constants:
                    return skip_tuple

                try:
                    defs: list[DefSite] = find_reaching_defs_for_stkvar(
                        mba,
                        use.block_serial,
                        state_var_stkoff,
                        state_var_width,
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
                    if _is_gutted_block(mba, def_site.block_serial):
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
                                    if def_ins.opcode == ida_hexrays.m_nop:
                                        is_state_const = True
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

                                    if (
                                        not is_state_const
                                        and vr_fixpoint is not None
                                        and def_ins.d is not None
                                        and def_ins.d.t == ida_hexrays.mop_S
                                        and def_ins.d.s is not None
                                        and def_ins.d.s.off == state_var_stkoff
                                    ):
                                        vr_val = _resolve_def_via_fixpoint(
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

                                    if (
                                        not is_state_const
                                        and def_ins.opcode == ida_hexrays.m_mov
                                        and def_ins.l is not None
                                        and def_ins.l.t == ida_hexrays.mop_S
                                        and def_ins.l.s is not None
                                    ):
                                        ind_val = _chase_indirect_stkvar_def(
                                            def_blk,
                                            def_ins,
                                            def_ins.l.s.off,
                                            state_constants,
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
                        "DSVE guard KEPT for blk[%d]: all %d reaching"
                        " defs are state constants (%d gutted, %d live)"
                        " but dest is non-state stkvar at off=0x%x",
                        use.block_serial, len(defs),
                        gutted_count, len(defs) - gutted_count,
                        skip_tuple[1],
                    )
                    return skip_tuple

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


__all__ = [
    "DeadStateReadCleanupSite",
    "DeadStateReadSkip",
    "DeadStateVariableCleanupEvidence",
    "DeadStateVariableEvidenceBackend",
    "HexRaysDeadStateVariableEvidenceBackend",
    "StateVariableRef",
]
