"""Value-range collection for microcode blocks.

This module wraps IDA's ``mblock_t.get_valranges()`` API to collect
per-block value ranges for register and stack-variable operands.

It is a read-only analysis pass -- it never modifies the microcode.

Public API:
    collect_block_valranges  -- per-block value-range strings
    collect_mba_valranges    -- per-MBA mapping of serial -> value-range strings
"""
from __future__ import annotations

import ida_hexrays

from d810.core.typing import Dict, List


def collect_block_valranges(blk: ida_hexrays.mblock_t) -> List[str]:
    """Collect non-trivial value ranges for register/stack operands in *blk*.

    Walks all instructions, builds a ``vivl_t`` for each unique register or
    stack-variable operand, then calls ``blk.get_valranges(vr, vivl,
    VR_AT_START)``.  Only non-empty, non-``all_values`` results are returned.

    Args:
        blk: A microcode basic block.

    Returns:
        Formatted range strings, e.g. ``["%0x3C.4:==610BB4D9"]``.
    """
    seen: set[tuple[int, int, int]] = set()
    results: List[str] = []

    ins = blk.head
    while ins is not None:
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

                try:
                    vtype = vivl.type()
                except Exception:
                    vtype = 0
                key = (vtype, vivl.off, mop.size)
                if key in seen:
                    continue
                seen.add(key)

                vr = ida_hexrays.valrng_t(mop.size)
                if blk.get_valranges(vr, vivl, ida_hexrays.VR_AT_START):
                    if not vr.empty() and not vr.all_values():
                        label = f"%0x{vivl.off:X}.{mop.size}"
                        results.append(f"{label}:{vr.dstr()}")
            except Exception:
                continue
        ins = ins.next

    return results


def collect_mba_valranges(
    mba: ida_hexrays.mbl_array_t,
) -> Dict[int, List[str]]:
    """Collect value ranges for every block in *mba*.

    Args:
        mba: The microcode block array.

    Returns:
        Mapping from block serial number to its value-range strings.
        Blocks with no non-trivial ranges are omitted.
    """
    result: Dict[int, List[str]] = {}
    for i in range(mba.qty):
        blk = mba.get_mblock(i)
        if blk is None:
            continue
        ranges = collect_block_valranges(blk)
        if ranges:
            result[blk.serial] = ranges
    return result
