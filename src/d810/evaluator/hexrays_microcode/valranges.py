"""Read-only Hex-Rays value-range helpers.

This module wraps IDA's native ``mblock_t.get_valranges()`` API for use in
live microcode diagnostics. It is intentionally read-only: it collects value
ranges for register and stack-variable operands without mutating the MBA.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

import ida_hexrays

from d810.core import logging
from d810.core.typing import Dict, Iterable, List, Optional
from d810.hexrays.utils.hexrays_helpers import UseDefFlags

logger = logging.getLogger(__name__)


class ValrangeLocationKind(str, Enum):
    """Supported value-range location kinds."""

    REGISTER = "register"
    STACK = "stack"


@dataclass(frozen=True)
class ValrangeLocation:
    """Structured identity for a value-range query location."""

    kind: ValrangeLocationKind
    identifier: int
    width: int

    @property
    def ida_label(self) -> str:
        """Return the historic IDA-like label used in debug dumps."""
        return f"%0x{self.identifier:X}.{self.width}"


@dataclass(frozen=True)
class ValrangeRecord:
    """Structured value-range result for a block or instruction anchor."""

    block_serial: int
    location: ValrangeLocation
    range_text: str
    instruction_ea: Optional[int] = None

    def __str__(self) -> str:
        return f"{self.location.ida_label}:{self.range_text}"


@dataclass(frozen=True)
class _ValrangeOperand:
    """Internal operand descriptor used during collection."""

    vivl: object
    location: ValrangeLocation


def _iter_operand_specs(ins: ida_hexrays.minsn_t) -> Iterable[_ValrangeOperand]:
    """Yield structured operand specs for register/stack operands in *ins*."""
    for mop in (ins.l, ins.r, ins.d):
        if mop is None:
            continue
        try:
            mop_type = mop.t
        except Exception:
            continue
        if mop_type == ida_hexrays.mop_z:
            continue

        try:
            vivl = ida_hexrays.vivl_t()
            if mop_type == ida_hexrays.mop_r:
                assert mop.r is not None
                vivl.set_reg(mop.r, mop.size)
                location = ValrangeLocation(
                    kind=ValrangeLocationKind.REGISTER,
                    identifier=int(mop.r),
                    width=int(mop.size),
                )
            elif mop_type == ida_hexrays.mop_S:
                assert mop.s is not None
                try:
                    stkoff = mop.s.off
                except Exception:
                    stkoff = getattr(mop, "stkoff", None)
                    if stkoff is None:
                        continue
                vivl.set_stkoff(stkoff, mop.size)
                location = ValrangeLocation(
                    kind=ValrangeLocationKind.STACK,
                    identifier=int(stkoff),
                    width=int(mop.size),
                )
            else:
                continue
            yield _ValrangeOperand(vivl=vivl, location=location)
        except Exception:
            continue


def _collect_valrange_records_for_operands(
    blk,
    operands: Iterable[_ValrangeOperand],
    *,
    ins=None,
) -> List[ValrangeRecord]:
    """Collect non-trivial structured ranges for the given operand intervals."""
    seen: set[tuple[str, int, int]] = set()
    results: List[ValrangeRecord] = []

    for operand in operands:
        try:
            key = (
                operand.location.kind.value,
                operand.location.identifier,
                operand.location.width,
            )
            if key in seen:
                continue
            seen.add(key)

            vr = ida_hexrays.valrng_t(operand.location.width)
            if ins is None:
                ok = blk.get_valranges(
                    vr,
                    operand.vivl,
                    ida_hexrays.VR_AT_START
                    | ida_hexrays.VR_AT_END
                    | ida_hexrays.VR_EXACT,
                )
            else:
                ok = blk.get_valranges(
                    vr,
                    operand.vivl,
                    ins,
                    ida_hexrays.VR_AT_START
                    | ida_hexrays.VR_AT_END
                    | ida_hexrays.VR_EXACT,
                )
            if ok and not vr.empty() and not vr.all_values():
                ins_ea = None
                if ins is not None:
                    try:
                        ins_ea = int(ins.ea)
                    except Exception:
                        ins_ea = None
                results.append(
                    ValrangeRecord(
                        block_serial=int(blk.serial),
                        location=operand.location,
                        range_text=vr.dstr(),
                        instruction_ea=ins_ea,
                    )
                )
        except Exception:
            continue

    return results


def collect_block_valrange_record_for_location(
    blk,
    location: ValrangeLocation,
) -> Optional[ValrangeRecord]:
    """Collect a single block-start value-range record for *location* in *blk*.

    Args:
        blk: ``ida_hexrays.mblock_t`` block to query.
        location: Structured register/stack location to query.

    Returns:
        A :class:`ValrangeRecord` if IDA reports a non-trivial range for the
        location at block start, otherwise ``None``.
    """
    vivl = ida_hexrays.vivl_t()
    if location.kind == ValrangeLocationKind.REGISTER:
        vivl.set_reg(location.identifier, location.width)
    elif location.kind == ValrangeLocationKind.STACK:
        vivl.set_stkoff(location.identifier, location.width)
    else:
        return None
    records = _collect_valrange_records_for_operands(
        blk, (_ValrangeOperand(vivl=vivl, location=location),)
    )
    return records[0] if records else None


def collect_instruction_valrange_record_for_location(
    blk,
    ins,
    location: ValrangeLocation,
) -> Optional[ValrangeRecord]:
    """Collect a single instruction-anchored value-range record for *location*.

    Args:
        blk: ``ida_hexrays.mblock_t`` containing *ins*.
        ins: Instruction anchor passed to ``mblock_t.get_valranges(..., ins, ...)``.
        location: Structured register/stack location to query.

    Returns:
        A :class:`ValrangeRecord` if IDA reports a non-trivial range at the
        instruction point, otherwise ``None``.
    """
    vivl = ida_hexrays.vivl_t()
    if location.kind == ValrangeLocationKind.REGISTER:
        vivl.set_reg(location.identifier, location.width)
    elif location.kind == ValrangeLocationKind.STACK:
        vivl.set_stkoff(location.identifier, location.width)
    else:
        return None
    records = _collect_valrange_records_for_operands(
        blk, (_ValrangeOperand(vivl=vivl, location=location),), ins=ins
    )
    return records[0] if records else None


def collect_instruction_valrange_records(blk, ins) -> List[ValrangeRecord]:
    """Collect non-trivial value-range records at a specific instruction in *blk*."""
    return _collect_valrange_records_for_operands(
        blk,
        _iter_operand_specs(ins),
        ins=ins,
    )


def _collect_block_operands(blk) -> List[_ValrangeOperand]:
    """Collect register/stack operand specs from all instructions in *blk*."""
    operands: list[_ValrangeOperand] = []
    ins = blk.head
    while ins is not None:
        operands.extend(_iter_operand_specs(ins))
        ins = ins.next
    return operands


def _collect_valrange_records_from_block_and_predecessors(
    blk: ida_hexrays.mblock_t,
    visited: set[int],
) -> List[ValrangeRecord]:
    """Recursively collect valrange records from *blk* and its predecessors."""
    serial = int(blk.serial)
    if serial in visited:
        return []
    visited.add(serial)

    results = list(
        _collect_valrange_records_for_operands(blk, _collect_block_operands(blk))
    )

    for pred in blk.preds():
        if pred is not None:
            results.extend(
                _collect_valrange_records_from_block_and_predecessors(pred, visited)
            )

    return results


def collect_block_valrange_records(
    blk: ida_hexrays.mblock_t, *, include_predecessors: bool = False
) -> List[ValrangeRecord]:
    """Collect non-trivial value-range records for register/stack operands in *blk*.

    Args:
        blk: Block to collect from.
        include_predecessors: If True, recursively walk predecessors and include
            their valranges. Default False for per-block-only (used by
            collect_mba_valrange_records).
    """
    if include_predecessors:
        return _collect_valrange_records_from_block_and_predecessors(blk, set())
    return _collect_valrange_records_for_operands(blk, _collect_block_operands(blk))


def collect_mba_valrange_records(mba) -> Dict[int, List[ValrangeRecord]]:
    """Collect block-level value-range records for every block in *mba*."""
    result: Dict[int, List[ValrangeRecord]] = {}
    for i in range(mba.qty):
        blk = mba.get_mblock(i)
        if blk is None:
            continue
        ranges = collect_block_valrange_records(blk)
        if ranges:
            result[int(blk.serial)] = ranges
    return result


def collect_instruction_valranges(blk, ins) -> List[str]:
    """Collect non-trivial value ranges at a specific instruction in *blk*."""
    return [str(record) for record in collect_instruction_valrange_records(blk, ins)]


def collect_block_valranges(blk) -> List[str]:
    """Collect non-trivial value ranges for register/stack operands in *blk*."""
    return [str(record) for record in collect_block_valrange_records(blk)]


def collect_mba_valranges(mba) -> Dict[int, List[str]]:
    """Collect block-level value ranges for every block in *mba*."""
    return {
        blk_serial: [str(record) for record in records]
        for blk_serial, records in collect_mba_valrange_records(mba).items()
    }


def resolve_state_via_valranges(blk, stkoff_mop, ins) -> int | None:
    """Resolve a stack-variable operand to a single concrete value via IDA valranges.

    Queries IDA's pre-computed value range analysis for the given stack operand
    at the specified instruction point.  Tries ``VR_EXACT`` first (strictest,
    no over-approximation), then falls back to ``VR_AT_START`` and ``VR_AT_END``.

    Args:
        blk: ``ida_hexrays.mblock_t`` block containing *ins*.
        stkoff_mop: ``ida_hexrays.mop_t`` stack operand (``mop_S``) to query.
        ins: Instruction anchor for the query point.

    Returns:
        A single concrete integer value if the valrange collapses to one value,
        otherwise ``None``.
    """

    try:
        vivl = ida_hexrays.vivl_t()
        try:
            stkoff = stkoff_mop.s.off
        except Exception:
            stkoff = getattr(stkoff_mop, "stkoff", None)
            if stkoff is None:
                return None
        vivl.set_stkoff(stkoff, stkoff_mop.size)
    except Exception:
        return None

    vr = ida_hexrays.valrng_t(stkoff_mop.size)

    # Priority 1: VR_EXACT — only provably-exact values
    for vr_flag in (
        ida_hexrays.VR_EXACT,
        ida_hexrays.VR_AT_START,
        ida_hexrays.VR_AT_END,
    ):

        ok = blk.get_valranges(vr, vivl, ins, vr_flag)
        if ok and not vr.empty() and not vr.all_values():
            ok_single, val = vr.cvt_to_single_value()
            if ok_single:
                return int(val)


def resolve_state_via_valrange_probe(
    blk,
    stkoff: int,
    interval_dispatcher,
    insn=None,
    stkoff_size=4,
) -> int | None:
    """Probe IntervalDispatcher targets against a block's incoming state var valrange.

    For each row in the interval dispatcher, tests whether the row's
    representative value (``row.lo``) falls within the block's incoming
    valrange for the state variable at *stkoff*.  If exactly one target
    matches, returns that target block serial.

    This is a fallback for when MopTracker backward-walk fails to resolve
    a concrete state constant.

    Args:
        blk: ``ida_hexrays.mblock_t`` block to query.
        stkoff: Stack offset of the state variable.
        interval_dispatcher: :class:`IntervalDispatcher` with handler rows.
        insn: Optional instruction anchor (defaults to ``blk.head``).

    Returns:
        Target block serial if exactly one handler interval overlaps
        with the valrange, or ``None``.
    """

    try:
        vivl = ida_hexrays.vivl_t()
        vivl.set_stkoff(stkoff, stkoff_size)
        vr = ida_hexrays.valrng_t(stkoff_size)
        target_insn = insn if insn is not None else blk.head
        got_vr = blk.get_valranges(vr, vivl, target_insn, ida_hexrays.VR_AT_START)
        if not got_vr:
            logger.info(
                "VALRANGE_PROBE: blk[%d] stkoff=0x%X get_valranges returned False",
                blk.serial,
                stkoff,
            )
            return None
        vr_str = vr.dstr() if hasattr(vr, "dstr") else "?"
        if vr.empty():
            logger.info("VALRANGE_PROBE: blk[%d] empty valrange", blk.serial)
            return None
        if vr.all_values():
            logger.info("VALRANGE_PROBE: blk[%d] all_values valrange", blk.serial)
            return None
        # Singleton → direct lookup
        ok, single_val = vr.cvt_to_single_value()
        if ok:
            target = interval_dispatcher.lookup(int(single_val))
            logger.info(
                "VALRANGE_PROBE: blk[%d] singleton 0x%X -> target=%s",
                blk.serial,
                single_val,
                target,
            )
            return target
        # Non-singleton: probe each interval row's lo value
        matching_targets: set[int] = set()
        for row in interval_dispatcher._rows:
            if vr.has(row.lo):
                matching_targets.add(row.target)
        logger.info(
            "VALRANGE_PROBE: blk[%d] vr=%s matched %d targets: %s",
            blk.serial,
            vr_str,
            len(matching_targets),
            matching_targets,
        )
        if len(matching_targets) == 1:
            return matching_targets.pop()
    except Exception as exc:
        logger.info("VALRANGE_PROBE: blk[%d] exception: %s", blk.serial, exc)


__all__ = [
    "ValrangeLocationKind",
    "ValrangeLocation",
    "ValrangeRecord",
    "collect_block_valrange_records",
    "collect_block_valrange_record_for_location",
    "collect_instruction_valrange_records",
    "collect_instruction_valrange_record_for_location",
    "collect_mba_valrange_records",
    "collect_block_valranges",
    "collect_instruction_valranges",
    "collect_mba_valranges",
    "resolve_state_via_valranges",
    "resolve_state_via_valrange_probe",
]
