"""Lifecycle helpers for imported scalar return carriers.

Imported terminal bodies temporarily need stronger liveness than ordinary
Hex-Rays microcode.  The physical ABI return register is protected through
global DCE, then released at ``hxe_glbopt``.  At the same boundary, explicit
``m_ret`` instructions are converted to Hex-Rays' canonical edge to the
synthetic ``BLT_STOP`` block before ctree construction.
"""

from __future__ import annotations

from collections.abc import Collection

import ida_hexrays
import ida_ida
import ida_typeinf

_INTEGER_TYPES_BY_WIDTH = {
    1: int(ida_typeinf.BT_INT8),
    2: int(ida_typeinf.BT_INT16),
    4: int(ida_typeinf.BT_INT32),
    8: int(ida_typeinf.BT_INT64),
}


def scalar_return_mreg(width: int) -> int | None:
    """Resolve a single-register integer return through the active ABI."""
    base_type = _INTEGER_TYPES_BY_WIDTH.get(int(width))
    if base_type is None:
        return None
    try:
        details = ida_typeinf.func_type_data_t()
        details.rettype = ida_typeinf.tinfo_t(
            base_type | int(ida_typeinf.BTMT_UNKSIGN)
        )
        details.set_cc(ida_ida.inf_get_callcnv())
        if not ida_typeinf.calc_retloc(details):
            return None
        location = details.retloc
        if not location.is_reg1():
            return None
        return int(ida_hexrays.reg2mreg(int(location.reg1()))) + int(
            location.regoff()
        )
    except Exception:
        return None


def protect_scalar_return_register(mba: object, width: int) -> bool:
    """Protect the active ABI return register from global dead elimination."""
    return_mreg = scalar_return_mreg(width)
    if return_mreg is None:
        return False
    return bool(mba.nodel_memory.add(return_mreg, int(width)))


def release_scalar_return_register(mba: object, width: int) -> bool:
    """Release temporary DCE protection before lvar/ctree construction."""
    return_mreg = scalar_return_mreg(width)
    if return_mreg is None:
        return False
    return bool(mba.nodel_memory.sub(return_mreg, int(width)))


def _single_return_width(return_widths: Collection[int]) -> int | None:
    widths = {int(width) for width in return_widths}
    if len(widths) != 1:
        return None
    width = next(iter(widths))
    return width if scalar_return_mreg(width) is not None else None


def imported_terminal_return_edges(
    mba: object,
    return_widths: Collection[int],
) -> tuple[tuple[object, object], ...]:
    """Select owned explicit returns and their canonical ``BLT_STOP`` target.

    This evidence layer stays mutation-free. The hook passes the returned
    block pairs to the central mutation backend. Width validation ensures that
    the function has a supported scalar ABI return location before any live
    CFG mutation occurs.
    """
    if _single_return_width(return_widths) is None:
        return ()
    quantity = int(getattr(mba, "qty", 0) or 0)
    if quantity < 2:
        return ()
    stop = mba.get_mblock(quantity - 1)
    if stop is None or int(stop.type) != int(ida_hexrays.BLT_STOP):
        return ()

    candidates: list[object] = []
    for serial in range(quantity - 1):
        block = mba.get_mblock(serial)
        tail = None if block is None else block.tail
        if tail is not None and int(tail.opcode) == int(ida_hexrays.m_ret):
            candidates.append(block)
    if not candidates:
        return ()
    return tuple((block, stop) for block in candidates)


__all__ = [
    "imported_terminal_return_edges",
    "protect_scalar_return_register",
    "release_scalar_return_register",
    "scalar_return_mreg",
]
