"""Live Hex-Rays implementation of the recon ``CarrierResolver`` boundary.

This adapter lives in the optimizer layer (permitted to import
``d810.hexrays`` and the live evaluator), so the pure recon
``terminal_corridor_discovery`` never imports Hex-Rays to answer the one
genuinely-live question it delegates: "what constant did this indirect
state-variable write resolve to?"

The two ``_resolve_*`` helpers were moved here verbatim from
``d810.recon.flow.terminal_corridor_discovery``; their logic is
unchanged.
"""
from __future__ import annotations

from d810.cfg.flowgraph import InsnKind, OperandKind
from d810.evaluator.hexrays_microcode.def_search import find_def_in_block
from d810.evaluator.hexrays_microcode.valranges import (
    ValrangeLocation,
    ValrangeLocationKind,
    collect_instruction_valrange_record_for_location,
)
from d810.hexrays.mutation.ir_translator import (
    classify_live_insn_kind,
    classify_live_operand_kind,
)
from d810.recon.flow.carrier_resolution import CarrierResolver
from d810.recon.flow.state_machine_analysis import (
    CarrierResolutionResult,
    ResolutionMethod,
)
from d810.recon.flow.terminal_corridor_discovery import CarrierSourceKind


def _resolve_indirect_state_write_via_mba(
    mba: object,
    candidate_serial: int,
    state_var_stkoff: int,
) -> CarrierResolutionResult | None:
    try:
        live_blk = mba.get_mblock(candidate_serial)
    except Exception:
        return None
    if live_blk is None:
        return None

    cur_ins = live_blk.tail
    while cur_ins is not None:
        if classify_live_insn_kind(cur_ins) is InsnKind.MOV and cur_ins.d is not None:
            if (
                classify_live_operand_kind(cur_ins.d) is OperandKind.STACK
                and cur_ins.d.s is not None
                and cur_ins.d.s.off == state_var_stkoff
            ):
                source_mop = cur_ins.l
                if source_mop is None:
                    break
                if classify_live_operand_kind(source_mop) is OperandKind.NUMBER:
                    nnn = source_mop.nnn
                    if nnn is not None:
                        return CarrierResolutionResult(
                            kind=CarrierSourceKind.STATE_CONST.value,
                            const_value=int(nnn.value),
                            method=ResolutionMethod.MBA_DEF_SEARCH,
                            def_blk_serial=None,
                            def_insn_ea=None,
                            source_mop_type=int(source_mop.t),
                        )
                    break
                if classify_live_operand_kind(source_mop) not in (OperandKind.REGISTER, OperandKind.STACK):
                    break
                def_ins = find_def_in_block(source_mop, live_blk, cur_ins)
                if def_ins is None:
                    pred_blk = live_blk
                    for _depth in range(3):
                        npred = pred_blk.npred()
                        if npred != 1:
                            break
                        pred_serial = pred_blk.pred(0)
                        try:
                            pred_blk = mba.get_mblock(pred_serial)
                        except Exception:
                            break
                        if pred_blk is None:
                            break
                        scan = pred_blk.tail
                        while scan is not None:
                            if (
                                classify_live_insn_kind(scan) is InsnKind.MOV
                                and scan.d is not None
                                and scan.d.t == source_mop.t
                            ):
                                dest_matches = False
                                if classify_live_operand_kind(source_mop) is OperandKind.STACK:
                                    try:
                                        dest_matches = scan.d.s.off == source_mop.s.off
                                    except Exception:
                                        pass
                                elif classify_live_operand_kind(source_mop) is OperandKind.REGISTER:
                                    try:
                                        dest_matches = scan.d.r == source_mop.r
                                    except Exception:
                                        pass
                                if (
                                    dest_matches
                                    and scan.l is not None
                                    and classify_live_operand_kind(scan.l) is OperandKind.NUMBER
                                ):
                                    def_ins = scan
                                    live_blk = pred_blk
                                    break
                            scan = scan.prev
                        if def_ins is not None:
                            break
                if def_ins is None:
                    break
                if (
                    classify_live_insn_kind(def_ins) is InsnKind.MOV
                    and def_ins.l is not None
                    and classify_live_operand_kind(def_ins.l) is OperandKind.NUMBER
                ):
                    nnn = def_ins.l.nnn
                    if nnn is not None:
                        src_stkoff: int | None = None
                        src_mreg: int | None = None
                        if classify_live_operand_kind(source_mop) is OperandKind.STACK:
                            try:
                                src_stkoff = source_mop.s.off
                            except Exception:
                                pass
                        elif classify_live_operand_kind(source_mop) is OperandKind.REGISTER:
                            try:
                                src_mreg = int(source_mop.r)
                            except Exception:
                                pass
                        return CarrierResolutionResult(
                            kind=CarrierSourceKind.STATE_CONST.value,
                            const_value=int(nnn.value),
                            method=ResolutionMethod.MBA_DEF_SEARCH,
                            def_blk_serial=live_blk.serial,
                            def_insn_ea=def_ins.ea,
                            source_mop_type=int(source_mop.t),
                            source_stkoff=src_stkoff,
                            source_mreg=src_mreg,
                        )
                break
        cur_ins = cur_ins.prev
    return None


def _resolve_state_const_via_valranges(
    mba: object,
    candidate_serial: int,
    state_var_stkoff: int,
) -> CarrierResolutionResult | None:
    try:
        live_blk = mba.get_mblock(candidate_serial)
    except Exception:
        return None
    if live_blk is None:
        return None

    cur_ins = live_blk.tail
    state_write_ins = None
    while cur_ins is not None:
        if classify_live_insn_kind(cur_ins) is InsnKind.MOV and cur_ins.d is not None:
            if (
                classify_live_operand_kind(cur_ins.d) is OperandKind.STACK
                and cur_ins.d.s is not None
                and cur_ins.d.s.off == state_var_stkoff
            ):
                state_write_ins = cur_ins
                break
        cur_ins = cur_ins.prev
    if state_write_ins is None:
        return None

    source_mop = state_write_ins.l
    source_kind = classify_live_operand_kind(source_mop)
    if source_mop is None or source_kind not in (OperandKind.REGISTER, OperandKind.STACK):
        return None

    if source_kind is OperandKind.REGISTER:
        location = ValrangeLocation(
            kind=ValrangeLocationKind.REGISTER,
            identifier=int(source_mop.r),
            width=int(source_mop.size),
        )
    else:
        try:
            stkoff = source_mop.s.off
        except Exception:
            return None
        location = ValrangeLocation(
            kind=ValrangeLocationKind.STACK,
            identifier=int(stkoff),
            width=int(source_mop.size),
        )

    try:
        record = collect_instruction_valrange_record_for_location(
            live_blk,
            state_write_ins,
            location,
        )
    except Exception:
        return None
    if record is None:
        return None

    range_text = record.range_text.strip()
    if range_text.startswith("{") and range_text.endswith("}"):
        inner = range_text[1:-1].strip()
        if "," not in inner and ".." not in inner:
            try:
                val = int(inner, 0)
            except ValueError:
                return None
            return CarrierResolutionResult(
                kind=CarrierSourceKind.STATE_CONST.value,
                const_value=val,
                method=ResolutionMethod.VALRANGES,
                def_blk_serial=None,
                def_insn_ea=None,
                source_mop_type=int(source_mop.t),
            )
    return None


class LiveCarrierResolver(CarrierResolver):
    """Live Hex-Rays ``CarrierResolver`` bound to a single ``mba``.

    Tries the def-search resolver first, then the valrange resolver.
    Returns ``None`` when neither names the constant.
    """

    def __init__(self, mba: object) -> None:
        self._mba = mba

    def resolve_indirect_state_write(
        self,
        candidate_serial: int,
        state_var_stkoff: int,
    ) -> CarrierResolutionResult | None:
        result = _resolve_indirect_state_write_via_mba(
            self._mba, candidate_serial, state_var_stkoff
        )
        if result is not None:
            return result
        return _resolve_state_const_via_valranges(
            self._mba, candidate_serial, state_var_stkoff
        )
