"""Operand/variable helpers with zero CFG coupling.

This module contains utility functions for working with microcode operands
(mop_t) and variable names. Split from cfg_utils.py as part of the
CFG Pass Pipeline refactor (Phase 1).
"""
from __future__ import annotations

import functools

import ida_hexrays

from d810.core import getLogger

helper_logger = getLogger(__name__)

_VALID_MOP_SIZES = frozenset({1, 2, 4, 8, 16})


def safe_make_number(mop, value, size):
    """Create a number operand with validated size.

    If *size* is not one of the valid IDA operand sizes (1, 2, 4, 8, 16),
    it is replaced with 4 (32-bit) to prevent a zero-size ``mop_n`` from
    crashing Hex-Rays' C++ verify / optimize_local passes.
    """
    if size not in _VALID_MOP_SIZES:
        helper_logger.warning("Invalid mop size %d, defaulting to 4", size)
        size = 4
    mask = (1 << (size * 8)) - 1
    mop.make_number(value & mask, size)


@functools.lru_cache(maxsize=1024)
def _get_mba_frame_size(mba: ida_hexrays.mba_t | None) -> int | None:
    """Return cached frame size for an MBA (fast C-level functools cache)."""
    if mba is None:
        return None
    for att in ("minstkref", "stacksize", "frsize", "fullsize"):
        val = getattr(mba, att, None)
        if val:
            return val
    return None


# Optional second-level cache: one name per SSA *valnum* (fast path)
_VALNUM_NAME_CACHE: dict[int, str] = {}


@functools.lru_cache(maxsize=16384)
def _cached_stack_var_name(
    mop_identity: int,  #  not used in the function but we need this bad boy for caching
    t: int,
    reg_or_off: int,
    size: int,
    valnum: int,
    frame_size: int | None,
) -> str:
    """Compute & cache printable variable names (identity-based)."""
    if t == ida_hexrays.mop_S:
        if frame_size is not None and frame_size >= reg_or_off:
            disp = frame_size - reg_or_off
            base = f"%var_{disp:X}.{size}"
        else:
            base = f"stk_{reg_or_off:X}.{size}"
    else:  # mop_r
        base = ida_hexrays.get_mreg_name(reg_or_off, size)
    return f"{base}{{{valnum}}}"


def get_stack_var_name(mop: ida_hexrays.mop_t) -> str | None:
    """Return a stable human-readable name for *mop*.

    Fast path: lookup by ``mop.valnum`` in `_VALNUM_NAME_CACHE`.  Falls back to
    identity-based LRU cache on a miss.
    """
    cached = _VALNUM_NAME_CACHE.get(mop.valnum)
    if cached is not None:
        return cached

    if mop.t == ida_hexrays.mop_S:
        frame_size = _get_mba_frame_size(getattr(mop.s, "mba", None))
        name = _cached_stack_var_name(
            id(mop), mop.t, mop.s.off, mop.size, mop.valnum, frame_size
        )
    elif mop.t == ida_hexrays.mop_r:
        name = _cached_stack_var_name(id(mop), mop.t, mop.r, mop.size, mop.valnum, None)
    else:
        return None
    return name


def extract_base_and_offset(mop: ida_hexrays.mop_t) -> tuple[ida_hexrays.mop_t | None, int]:
    if (
        mop.t == ida_hexrays.mop_d
        and mop.d is not None
        and mop.d.opcode == ida_hexrays.m_add
    ):
        # (base + const)
        if mop.d.l and mop.d.l.t in {ida_hexrays.mop_S, ida_hexrays.mop_r}:
            off = mop.d.r.nnn.value if mop.d.r and mop.d.r.t == ida_hexrays.mop_n else 0
            return mop.d.l, off
        if mop.d.r and mop.d.r.t in {ida_hexrays.mop_S, ida_hexrays.mop_r}:
            off = mop.d.l.nnn.value if mop.d.l and mop.d.l.t == ida_hexrays.mop_n else 0
            return mop.d.r, off
    return None, 0


__all__ = [
    "safe_make_number",
    "get_stack_var_name",
    "extract_base_and_offset",
    "_VALID_MOP_SIZES",
    "_get_mba_frame_size",
    "_cached_stack_var_name",
    "_VALNUM_NAME_CACHE",
]
