"""Helpers for validating and rebuilding instruction snapshots."""
from __future__ import annotations

from collections.abc import Sequence

import ida_hexrays

from d810.cfg.flowgraph import InsnSnapshot
from d810.hexrays.ir.mop_snapshot import MopSnapshot
from d810.hexrays.utils.hexrays_formatters import sanitize_ea


def _iter_insn_snapshot_operands(insn_snapshot: InsnSnapshot) -> tuple[tuple[str, object], ...]:
    if insn_snapshot.operand_slots:
        return insn_snapshot.operand_slots
    slot_names = ("l", "r", "d")
    return tuple(
        (slot_names[idx], operand)
        for idx, operand in enumerate(insn_snapshot.operands[: len(slot_names)])
    )


def instruction_snapshot_safe_ea(
    instructions: Sequence[InsnSnapshot],
    *,
    fallback: int,
) -> int:
    return next(
        (sanitize_ea(instruction.ea) for instruction in instructions if instruction.ea > 0),
        sanitize_ea(fallback) or 1,
    )


def _sanitize_mop_tree_eas(mop: "ida_hexrays.mop_t", safe_ea: int) -> None:
    if mop.t == ida_hexrays.mop_d and mop.d is not None:
        mop.d.ea = safe_ea
        _sanitize_mop_tree_eas(mop.d.l, safe_ea)
        _sanitize_mop_tree_eas(mop.d.r, safe_ea)
        _sanitize_mop_tree_eas(mop.d.d, safe_ea)


def _rebuild_mop_from_snapshot_operand(operand: object, safe_ea: int) -> "ida_hexrays.mop_t":
    if isinstance(operand, MopSnapshot):
        mop = operand.to_mop()
    elif hasattr(operand, "to_mop"):
        mop = operand.to_mop()  # type: ignore[assignment]
    elif isinstance(operand, ida_hexrays.mop_t):
        mop = ida_hexrays.mop_t()
        mop.assign(operand)
    else:
        raise TypeError(f"Unsupported InsertBlock operand type: {type(operand).__name__}")

    if not isinstance(mop, ida_hexrays.mop_t):
        raise TypeError(f"Operand did not rebuild to mop_t: {type(mop).__name__}")
    expected_t = getattr(operand, "t", None)
    if isinstance(expected_t, int) and mop.t != expected_t:
        raise TypeError(
            f"Operand rebuilt to wrong mop type: expected {expected_t}, got {mop.t}"
        )
    _sanitize_mop_tree_eas(mop, safe_ea)
    return mop


def validate_insn_snapshots(instructions: Sequence[InsnSnapshot]) -> str | None:
    """Return None when snapshots are structurally rebuildable."""
    safe_ea = instruction_snapshot_safe_ea(instructions, fallback=1)
    try:
        for instruction in instructions:
            for _slot_name, operand in _iter_insn_snapshot_operands(instruction):
                _rebuild_mop_from_snapshot_operand(operand, safe_ea)
    except Exception as exc:
        return str(exc)
    return None


def _build_minsn_from_snapshot(
    insn_snapshot: InsnSnapshot,
    safe_ea: int,
) -> "ida_hexrays.minsn_t":
    new_ins = ida_hexrays.minsn_t(sanitize_ea(safe_ea))
    new_ins.opcode = insn_snapshot.opcode

    new_ins.l = ida_hexrays.mop_t()
    new_ins.l.erase()
    new_ins.r = ida_hexrays.mop_t()
    new_ins.r.erase()
    new_ins.d = ida_hexrays.mop_t()
    new_ins.d.erase()

    for slot_name, operand in _iter_insn_snapshot_operands(insn_snapshot):
        setattr(new_ins, slot_name, _rebuild_mop_from_snapshot_operand(operand, safe_ea))

    return new_ins


def materialize_insn_snapshots(
    instructions: Sequence[InsnSnapshot],
    *,
    safe_ea: int,
) -> list["ida_hexrays.minsn_t"]:
    safe_ea = sanitize_ea(safe_ea) or 1
    return [_build_minsn_from_snapshot(instruction, safe_ea) for instruction in instructions]


__all__ = [
    "instruction_snapshot_safe_ea",
    "materialize_insn_snapshots",
    "validate_insn_snapshots",
]
