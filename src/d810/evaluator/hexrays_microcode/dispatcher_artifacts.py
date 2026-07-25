"""Evaluator-backed plans for dispatcher-state materialization artifacts."""

from __future__ import annotations

import dataclasses

from d810.core import logging
from d810.core.typing import Any


logger = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True, slots=True)
class DispatcherStateReturnCarrierArtifactPlan:
    """Scalar mutation plan proven by the abstract dispatcher-state evaluator."""

    block_serial: int
    join_serial: int
    dispatcher_serial: int
    selector_value: int
    state_value: int
    state_size: int
    replacement_body_index: int = 1
    nop_body_index: int = 2


def _register_id(ida_hexrays: Any, mop: Any) -> int | None:
    if mop is None:
        return None
    try:
        if int(getattr(mop, "t", -1)) != int(ida_hexrays.mop_r):
            return None
        return int(getattr(mop, "r"))
    except Exception:
        return None


def _body_insns(ida_hexrays: Any, block: Any) -> list[Any]:
    insns: list[Any] = []
    cur = block.head
    while cur is not None:
        opcode = int(getattr(cur, "opcode", -1))
        if opcode not in {int(ida_hexrays.m_nop), int(ida_hexrays.m_goto)}:
            insns.append(cur)
        cur = cur.next
    return insns


def _mop_const_value(ida_hexrays: Any, mop: Any) -> int | None:
    if mop is None:
        return None
    try:
        if int(getattr(mop, "t", -1)) != int(ida_hexrays.mop_n):
            return None
    except Exception:
        return None
    nnn = getattr(mop, "nnn", None)
    value = getattr(nnn, "value", None) if nnn is not None else None
    if value is None:
        value = getattr(mop, "value", None)
    if value is None or callable(value):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def plan_dispatcher_state_return_carrier_artifact(
    mba: Any,
    block_serial: int,
) -> DispatcherStateReturnCarrierArtifactPlan | None:
    """Plan a generic split dispatcher-state artifact through the evaluator.

    The live shape is:

    - one block writes a byte selector plus two scratch constants;
    - its single successor XORs the scratch operands into the dispatcher state;
    - the successor goes to the dispatcher.

    This helper validates that shape and asks the existing dynamic state-write
    evaluator to fold the dispatcher-state write. It returns scalar proof data
    only; Hex-Rays graph mutation is owned by the mutation adapter layer.
    """
    import ida_hexrays

    from d810.analyses.data_flow.abstract_value import Const
    from d810.evaluator.hexrays_microcode.dynamic_state_write_backend import (
        resolve_predecessor_seeded_write_value,
    )

    block = mba.get_mblock(int(block_serial))
    if block is None:
        return None
    try:
        if int(block.nsucc()) != 1:
            return None
        join_serial = int(block.succ(0))
    except Exception:
        return None
    join = mba.get_mblock(join_serial)
    if join is None:
        return None
    try:
        if int(join.nsucc()) != 1:
            return None
        dispatcher_serial = int(join.succ(0))
    except Exception:
        return None

    body = _body_insns(ida_hexrays, block)
    if len(body) != 3:
        return None
    selector_write, left_const_write, right_const_write = body
    if any(int(getattr(insn, "opcode", -1)) != int(ida_hexrays.m_mov) for insn in body):
        return None
    selector_value = _mop_const_value(ida_hexrays, getattr(selector_write, "l", None))
    if selector_value is None or not (0 <= int(selector_value) <= 0xFF):
        return None
    if _mop_const_value(ida_hexrays, getattr(left_const_write, "l", None)) is None:
        return None
    if _mop_const_value(ida_hexrays, getattr(right_const_write, "l", None)) is None:
        return None
    left_reg = _register_id(ida_hexrays, getattr(left_const_write, "d", None))
    right_reg = _register_id(ida_hexrays, getattr(right_const_write, "d", None))
    if left_reg is None or right_reg is None or left_reg == right_reg:
        return None

    join_body = _body_insns(ida_hexrays, join)
    if len(join_body) != 1:
        return None
    join_insn = join_body[0]
    if int(getattr(join_insn, "opcode", -1)) != int(ida_hexrays.m_xor):
        return None
    join_left_reg = _register_id(ida_hexrays, getattr(join_insn, "l", None))
    join_right_reg = _register_id(ida_hexrays, getattr(join_insn, "r", None))
    if {join_left_reg, join_right_reg} != {left_reg, right_reg}:
        return None
    dispatcher_dst = getattr(join_insn, "d", None)
    if (
        dispatcher_dst is None
        or getattr(dispatcher_dst, "t", None) == ida_hexrays.mop_z
    ):
        return None

    folded = resolve_predecessor_seeded_write_value(
        mba=mba,
        block_serial=int(join_serial),
        predecessor_serial=int(block_serial),
        dest_mop=dispatcher_dst,
    )
    if not isinstance(folded, Const):
        logger.info(
            "dispatcher_state_return_carrier_artifact: skipped block=%d "
            "join=%d reason=abstract_fold_top",
            int(block_serial),
            int(join_serial),
        )
        return None

    size = int(getattr(dispatcher_dst, "size", 0) or getattr(folded, "size", 4) or 4)
    mask = (1 << (size * 8)) - 1
    value = int(folded.value) & mask
    logger.info(
        "dispatcher_state_return_carrier_artifact: planned block=%d "
        "join=%d dispatcher=%d selector=0x%X abstract_state=0x%X",
        int(block_serial),
        int(join_serial),
        int(dispatcher_serial),
        int(selector_value),
        value,
    )
    return DispatcherStateReturnCarrierArtifactPlan(
        block_serial=int(block_serial),
        join_serial=int(join_serial),
        dispatcher_serial=int(dispatcher_serial),
        selector_value=int(selector_value),
        state_value=value,
        state_size=size,
    )


__all__ = [
    "DispatcherStateReturnCarrierArtifactPlan",
    "plan_dispatcher_state_return_carrier_artifact",
]
