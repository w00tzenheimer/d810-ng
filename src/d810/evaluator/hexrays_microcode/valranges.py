"""Read-only Hex-Rays value-range helpers.

This module wraps IDA's native ``mblock_t.get_valranges()`` API for use in
live microcode diagnostics. It is intentionally read-only: it collects value
ranges for register and stack-variable operands without mutating the MBA.
"""
from __future__ import annotations

from d810.core.typing import Dict, Iterable, List


def _ida_hexrays():
    """Import ``ida_hexrays`` lazily so the module remains importable in tests."""
    import ida_hexrays

    return ida_hexrays


def _iter_operand_triples(ins) -> Iterable[tuple[object, int, str]]:
    """Yield ``(vivl, size, label)`` for register/stack operands in *ins*."""
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
            elif mop_type == ida_hexrays.mop_S:
                try:
                    stkoff = mop.s.off
                except Exception:
                    stkoff = getattr(mop, "stkoff", None)
                    if stkoff is None:
                        continue
                vivl.set_stkoff(stkoff, mop.size)
            else:
                continue
            label = f"%0x{vivl.off:X}.{mop.size}"
            yield vivl, mop.size, label
        except Exception:
            continue


def _collect_valranges_for_operands(
    blk,
    operands: Iterable[tuple[object, int, str]],
    *,
    ins=None,
) -> List[str]:
    """Collect non-trivial ranges for the given operand intervals."""
    ida_hexrays = _ida_hexrays()
    seen: set[tuple[int, int, int]] = set()
    results: List[str] = []

    for vivl, size, label in operands:
        try:
            try:
                vtype = vivl.type()
            except Exception:
                vtype = 0
            key = (vtype, vivl.off, size)
            if key in seen:
                continue
            seen.add(key)

            vr = ida_hexrays.valrng_t(size)
            if ins is None:
                ok = blk.get_valranges(vr, vivl, ida_hexrays.VR_AT_START)
            else:
                ok = blk.get_valranges(vr, vivl, ins, ida_hexrays.VR_AT_START)
            if ok and not vr.empty() and not vr.all_values():
                results.append(f"{label}:{vr.dstr()}")
        except Exception:
            continue

    return results


def collect_instruction_valranges(blk, ins) -> List[str]:
    """Collect non-trivial value ranges at a specific instruction in *blk*."""
    return _collect_valranges_for_operands(
        blk,
        _iter_operand_triples(ins),
        ins=ins,
    )


def collect_block_valranges(blk) -> List[str]:
    """Collect non-trivial value ranges for register/stack operands in *blk*."""
    operands: list[tuple[object, int, str]] = []
    ins = blk.head
    while ins is not None:
        operands.extend(_iter_operand_triples(ins))
        ins = ins.next
    return _collect_valranges_for_operands(blk, operands)


def collect_mba_valranges(mba) -> Dict[int, List[str]]:
    """Collect block-level value ranges for every block in *mba*."""
    result: Dict[int, List[str]] = {}
    for i in range(mba.qty):
        blk = mba.get_mblock(i)
        if blk is None:
            continue
        ranges = collect_block_valranges(blk)
        if ranges:
            result[blk.serial] = ranges
    return result


__all__ = [
    "collect_block_valranges",
    "collect_instruction_valranges",
    "collect_mba_valranges",
]
