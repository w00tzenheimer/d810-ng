"""Canonical Hex-Rays mutation helpers for constant-memory reads."""

from __future__ import annotations

import ida_hexrays
from d810.hexrays.ir.number_operand import safe_make_number


_SUPPORTED_WIDTHS = frozenset({1, 2, 4, 8})
_LEGAL_DESTINATION_TYPES = frozenset(
    {
        ida_hexrays.mop_r,
        ida_hexrays.mop_l,
        ida_hexrays.mop_S,
        ida_hexrays.mop_v,
    }
)


def _masked_value(value: int, size: int) -> int:
    if size not in _SUPPORTED_WIDTHS:
        raise ValueError(f"unsupported immediate width: {size}")
    return int(value) & ((1 << (int(size) * 8)) - 1)


def replace_operand_with_immediate(operand, value: int, size: int) -> None:
    """Replace one owned ``mop_t`` with an unsigned immediate."""

    safe_make_number(operand, value, int(size))


def make_ldc_replacement(instruction, value: int, size: int):
    """Build an ``m_ldc`` replacement while preserving a legal destination."""

    replacement = ida_hexrays.minsn_t(instruction.ea)
    replacement.opcode = ida_hexrays.m_ldc

    replacement.l = ida_hexrays.mop_t()
    replace_operand_with_immediate(replacement.l, value, size)

    replacement.r = ida_hexrays.mop_t()
    replacement.r.erase()

    replacement.d = ida_hexrays.mop_t()
    destination = instruction.d
    if destination is not None and destination.t in _LEGAL_DESTINATION_TYPES:
        replacement.d.assign(destination)
        replacement.d.size = int(size)
    else:
        replacement.d.erase()
    return replacement


def rewrite_load_as_immediate_move(instruction, value: int, size: int) -> None:
    """Rewrite an existing memory load as ``m_mov #value`` in place."""

    instruction.opcode = ida_hexrays.m_mov
    replace_operand_with_immediate(instruction.l, value, size)
    instruction.r.erase()


__all__ = [
    "make_ldc_replacement",
    "replace_operand_with_immediate",
    "rewrite_load_as_immediate_move",
]
