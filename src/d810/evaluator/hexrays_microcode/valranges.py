"""Read-only Hex-Rays value-range helpers.

This module wraps IDA's native ``mblock_t.get_valranges()`` API for use in
live microcode diagnostics. It is intentionally read-only: it collects value
ranges for register and stack-variable operands without mutating the MBA.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from d810.core.typing import Dict, Iterable, List, Optional


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


def _ida_hexrays():
    """Import ``ida_hexrays`` lazily so the module remains importable in tests."""
    import ida_hexrays

    return ida_hexrays


def _iter_operand_specs(ins) -> Iterable[_ValrangeOperand]:
    """Yield structured operand specs for register/stack operands in *ins*."""
    ida_hexrays = _ida_hexrays()
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
                vivl.set_reg(mop.r, mop.size)
                location = ValrangeLocation(
                    kind=ValrangeLocationKind.REGISTER,
                    identifier=int(mop.r),
                    width=int(mop.size),
                )
            elif mop_type == ida_hexrays.mop_S:
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
    ida_hexrays = _ida_hexrays()
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
                ok = blk.get_valranges(vr, operand.vivl, ida_hexrays.VR_AT_START)
            else:
                ok = blk.get_valranges(vr, operand.vivl, ins, ida_hexrays.VR_AT_START)
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
    ida_hexrays = _ida_hexrays()
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
    ida_hexrays = _ida_hexrays()
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


def collect_block_valrange_records(blk) -> List[ValrangeRecord]:
    """Collect non-trivial value-range records for register/stack operands in *blk*."""
    operands: list[_ValrangeOperand] = []
    ins = blk.head
    while ins is not None:
        operands.extend(_iter_operand_specs(ins))
        ins = ins.next
    return _collect_valrange_records_for_operands(blk, operands)


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
]
