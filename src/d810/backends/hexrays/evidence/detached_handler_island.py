"""Recognize one detached call-bearing state handler from native boundaries."""

from __future__ import annotations

import ida_hexrays
import ida_idp
import ida_ua
import idaapi

from d810.analyses.control_flow.detached_handler_island import (
    DetachedHandlerIslandCandidate,
    DetachedHandlerIslandPlan,
    DetachedSourcePath,
    plan_detached_handler_island,
)


def _decode(ea: int) -> tuple[ida_ua.insn_t, int] | None:
    insn = ida_ua.insn_t()
    size = int(ida_ua.decode_insn(insn, int(ea)))
    return (insn, size) if size > 0 else None


def _mnemonic(ea: int) -> str:
    return str(idaapi.print_insn_mnem(int(ea)) or "").lower()


def _is_esp_displacement(op: object) -> bool:
    if op.type != idaapi.o_displ:
        return False
    name = ida_idp.get_reg_name(int(op.reg), 4)
    return bool(name) and str(name).lower() == "esp"


def _operand_mreg(op: object) -> int | None:
    if op.type != idaapi.o_reg:
        return None
    name = ida_idp.get_reg_name(int(op.reg), 4)
    if not name:
        return None
    register = int(ida_idp.str2reg(str(name)))
    return int(ida_hexrays.reg2mreg(register)) if register >= 0 else None


def recognize_detached_handler_island(
    *,
    source_path: DetachedSourcePath,
    state_register: int,
    state_targets: tuple[tuple[int, int], ...],
) -> DetachedHandlerIslandPlan | None:
    """Parse the bounded ``push; call; cmp; state; jcc`` detached shape."""
    cursor = int(source_path.detached_entry_ea)

    decoded = _decode(cursor)
    if decoded is None:
        return None
    push, size = decoded
    if _mnemonic(cursor) != "push" or not _is_esp_displacement(push.ops[0]):
        return None
    call_argument_ida_stkoff = int(push.ops[0].addr)
    cursor += size

    decoded = _decode(cursor)
    if decoded is None:
        return None
    call, size = decoded
    if _mnemonic(cursor) != "call" or call.ops[0].type not in {
        idaapi.o_near,
        idaapi.o_far,
    }:
        return None
    call_target_ea = int(call.ops[0].addr)
    cursor += size

    decoded = _decode(cursor)
    if decoded is None:
        return None
    cleanup, size = decoded
    if _mnemonic(cursor) == "add":
        cleanup_register = _operand_mreg(cleanup.ops[0])
        esp_register = int(ida_hexrays.reg2mreg(ida_idp.str2reg("esp")))
        if cleanup_register != esp_register or cleanup.ops[1].type != idaapi.o_imm:
            return None
        cursor += size

    decoded = _decode(cursor)
    if decoded is None:
        return None
    compare, size = decoded
    if (
        _mnemonic(cursor) != "cmp"
        or not _is_esp_displacement(compare.ops[0])
        or compare.ops[1].type != idaapi.o_imm
        or int(compare.ops[1].value) != 0
    ):
        return None
    predicate_ida_stkoff = int(compare.ops[0].addr)
    cursor += size

    decoded = _decode(cursor)
    if decoded is None:
        return None
    inherited_write, size = decoded
    if (
        _mnemonic(cursor) != "mov"
        or _operand_mreg(inherited_write.ops[0]) != int(state_register)
        or inherited_write.ops[1].type != idaapi.o_imm
    ):
        return None
    inherited_state = int(inherited_write.ops[1].value)
    cursor += size

    decoded = _decode(cursor)
    if decoded is None:
        return None
    branch, size = decoded
    branch_mnemonic = _mnemonic(cursor)
    if branch_mnemonic not in {"jz", "je", "jnz", "jne"} or branch.ops[0].type not in {
        idaapi.o_near,
        idaapi.o_far,
    }:
        return None
    condition_code = 4 if branch_mnemonic in {"jz", "je"} else 5
    detached_end_ea = cursor + size
    taken_ea = int(branch.ops[0].addr)

    decoded = _decode(taken_ea)
    if decoded is None:
        return None
    taken_write, _taken_size = decoded
    if (
        _mnemonic(taken_ea) != "mov"
        or _operand_mreg(taken_write.ops[0]) != int(state_register)
        or taken_write.ops[1].type != idaapi.o_imm
    ):
        return None
    taken_state = int(taken_write.ops[1].value)

    return plan_detached_handler_island(
        DetachedHandlerIslandCandidate(
            source_path=source_path,
            detached_end_ea=detached_end_ea,
            call_target_ea=call_target_ea,
            call_argument_ida_stkoff=call_argument_ida_stkoff,
            predicate_ida_stkoff=predicate_ida_stkoff,
            state_register=int(state_register),
            condition_code=condition_code,
            inherited_state=inherited_state,
            taken_state=taken_state,
            state_targets=state_targets,
        )
    )


__all__ = ["recognize_detached_handler_island"]
