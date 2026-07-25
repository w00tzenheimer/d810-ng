"""Live Hex-Rays evidence adapters for narrow call ABI proofs."""

from __future__ import annotations

import ida_hexrays
import ida_frame
import ida_funcs
import ida_idp
import ida_typeinf
import ida_ua
import idaapi
from dataclasses import dataclass

from d810.analyses.control_flow.call_abi import (
    StackCallAbiEvidence,
    StackCallAbiProof,
)


def _same_live_instruction(left: object, right: object) -> bool:
    """Compare SWIG instruction proxies by stable live identity."""
    return int(left.ea) == int(right.ea) and int(left.opcode) == int(right.opcode)


@dataclass(frozen=True, slots=True)
class _LiveStackArgument:
    ida_offset: int
    vd_offset: int
    initializer_ea: int
    operand: object


def _outgoing_stack_arguments(
    block: object,
    *,
    word_size: int,
) -> tuple[_LiveStackArgument, ...] | None:
    arguments: list[_LiveStackArgument] = []
    seen: set[int] = set()
    instruction = block.head
    while instruction is not None:
        if _same_live_instruction(instruction, block.tail):
            break
        if int(instruction.opcode) in {
            int(ida_hexrays.m_call),
            int(ida_hexrays.m_icall),
        }:
            arguments.clear()
            seen.clear()
            instruction = instruction.next
            continue
        destination = instruction.d
        if int(destination.t) == int(ida_hexrays.mop_S):
            vd_offset = int(destination.s.off)
            ida_offset = int(block.mba.stkoff_vd2ida(vd_offset))
            if ida_offset < 0:
                if int(destination.size) != int(word_size) or ida_offset in seen:
                    return None
                seen.add(ida_offset)
                arguments.append(
                    _LiveStackArgument(
                        ida_offset=ida_offset,
                        vd_offset=vd_offset,
                        initializer_ea=int(instruction.ea),
                        operand=destination,
                    )
                )
        instruction = instruction.next
    return tuple(sorted(arguments, key=lambda argument: argument.ida_offset))


def outgoing_stack_argument_offsets(
    block: object,
    *,
    word_size: int,
) -> tuple[int, ...] | None:
    """Return exact negative stack identities written before the tail call.

    A previous call starts a new outgoing-argument region.  Duplicate writes or
    non-word-sized writes make the sequence ambiguous and force abstention.
    Positive stack identities are persistent locals, not outgoing arguments.
    """
    arguments = _outgoing_stack_arguments(block, word_size=word_size)
    if arguments is None:
        return None
    return tuple(argument.ida_offset for argument in arguments)


def trace_linear_microcode_reentry(
    call_block: object,
    proven_reentry_eas: frozenset[int],
    *,
    max_blocks: int = 16,
) -> tuple[bool, bool]:
    """Return ``(linear, reached)`` for the post-call microcode corridor."""
    successors = tuple(int(serial) for serial in call_block.succset)
    if len(successors) != 1:
        return False, False
    serial = successors[0]
    visited: set[int] = set()
    for _index in range(int(max_blocks)):
        if serial in visited:
            return False, False
        visited.add(serial)
        block = call_block.mba.get_mblock(serial)
        if block is None:
            return False, False
        instruction = block.head
        while instruction is not None:
            if int(instruction.ea) in proven_reentry_eas:
                return True, True
            if int(instruction.opcode) in {
                int(ida_hexrays.m_call),
                int(ida_hexrays.m_icall),
            }:
                return False, False
            if _same_live_instruction(instruction, block.tail):
                break
            instruction = instruction.next
        successors = tuple(int(value) for value in block.succset)
        if not successors:
            return True, False
        if len(successors) != 1:
            return False, False
        serial = successors[0]
    return False, False


def collect_three_argument_callee_purged_evidence(
    block: object,
    *,
    proven_reentry_eas: frozenset[int],
    has_authoritative_type: bool,
    call_stack_deficit: int | None,
    caller_stack_adjustment: int | None,
    word_size: int,
) -> StackCallAbiEvidence:
    """Collect the live evidence consumed by the portable three-arg rule."""
    offsets = outgoing_stack_argument_offsets(block, word_size=word_size)
    linear, reached = trace_linear_microcode_reentry(
        block,
        proven_reentry_eas,
    )
    return StackCallAbiEvidence(
        word_size=int(word_size),
        outgoing_stack_offsets=offsets if offsets is not None else (),
        call_stack_deficit=call_stack_deficit,
        argument_values_proven=offsets is not None,
        continuation_is_linear=linear,
        continuation_reaches_proven_reentry=reached,
        caller_stack_adjustment=caller_stack_adjustment,
        has_authoritative_type=bool(has_authoritative_type),
    )


def native_call_stack_deficit(block: object, call_ea: int) -> int | None:
    """Return bytes below the function's canonical frame at ``call_ea``."""
    function = ida_funcs.get_func(int(call_ea))
    if function is None:
        return None
    try:
        stack_pointer_delta = int(ida_frame.get_spd(function, int(call_ea)))
    except Exception:
        return None
    canonical_delta = -(int(block.mba.frsize) + int(block.mba.frregs))
    deficit = canonical_delta - stack_pointer_delta
    return deficit if deficit >= 0 else None


def _decode_native_instruction(ea: int) -> tuple[object, int] | None:
    instruction = ida_ua.insn_t()
    size = int(ida_ua.decode_insn(instruction, int(ea)))
    return (instruction, size) if size > 0 else None


def _native_instruction_mnemonic(instruction: object) -> str:
    return str(idaapi.print_insn_mnem(int(instruction.ea)) or "").lower()


def _native_instruction_writes_stack_pointer(instruction: object) -> bool:
    accesses = ida_idp.reg_accesses_t()
    if ida_idp.ph_get_reg_accesses(accesses, instruction, 0) < 0:
        return True
    register_names = ida_idp.ph_get_regnames()
    for access in accesses:
        name = str(register_names[int(access.regnum)]).lower()
        if name in {"sp", "esp", "rsp"} and int(access.access_type) & int(
            ida_idp.WRITE_ACCESS
        ):
            return True
    return False


def native_corridor_has_no_stack_adjustment(
    call_ea: int,
    proven_reentry_eas: frozenset[int],
    *,
    max_instructions: int = 64,
) -> bool | None:
    """Prove a straight native post-call corridor has no SP write.

    The destination re-entry must have been proven independently by the
    computed-transfer resolver.  Any decode failure or earlier control transfer
    is ambiguity and therefore abstains.
    """
    decoded_call = _decode_native_instruction(int(call_ea))
    if decoded_call is None:
        return None
    call_instruction, call_size = decoded_call
    if not _native_instruction_mnemonic(call_instruction).startswith("call"):
        return None
    ea = int(call_ea) + int(call_size)
    for _index in range(int(max_instructions)):
        if ea in proven_reentry_eas:
            return True
        decoded = _decode_native_instruction(ea)
        if decoded is None:
            return None
        instruction, size = decoded
        if _native_instruction_writes_stack_pointer(instruction):
            return False
        mnemonic = _native_instruction_mnemonic(instruction)
        if (
            mnemonic.startswith("j")
            or mnemonic.startswith("call")
            or mnemonic.startswith("ret")
            or mnemonic in {"int", "int3", "syscall", "sysenter"}
        ):
            return None
        ea += int(size)
    return None


def apply_three_argument_stdcall_type(
    call_type: object,
    proof: StackCallAbiProof,
) -> bool:
    """Fill ``call_type`` with the exact function type authorized by ``proof``."""
    if (
        int(proof.argument_count) != 3
        or int(proof.stack_argument_bytes) != 12
        or not proof.callee_purges_stack
    ):
        return False
    details = ida_typeinf.func_type_data_t()
    details.rettype = ida_typeinf.tinfo_t(ida_typeinf.BTF_INT32)
    details.set_cc(ida_typeinf.CM_CC_STDCALL)
    for _index in range(int(proof.argument_count)):
        argument = ida_typeinf.funcarg_t()
        argument.type = ida_typeinf.tinfo_t(ida_typeinf.BTF_INT32)
        details.push_back(argument)
    return bool(call_type.create_func(details))


def build_three_argument_stdcall_callinfo(
    block: object,
    call_type: object,
    proof: StackCallAbiProof,
) -> object | None:
    """Build a complete final ``mcallinfo_t`` from the proven stack cells."""
    if (
        int(proof.argument_count) != 3
        or int(proof.stack_argument_bytes) != 12
        or not proof.callee_purges_stack
    ):
        return None
    arguments = _outgoing_stack_arguments(block, word_size=4)
    if arguments is None or len(arguments) != int(proof.argument_count):
        return None
    if tuple(argument.ida_offset for argument in arguments) != (-12, -8, -4):
        return None

    callinfo = ida_hexrays.mcallinfo_t()
    if not callinfo.set_type(call_type):
        return None
    callinfo.args.clear()
    argument_type = ida_typeinf.tinfo_t(ida_typeinf.BTF_INT32)
    for index, evidence in enumerate(arguments):
        argument = callinfo.args.push_back()
        argument.copy_mop(evidence.operand)
        argument.type = argument_type
        argument.argloc.set_stkoff(index * 4)
        argument.ea = int(evidence.initializer_ea)
    callinfo.cc = ida_typeinf.CM_CC_STDCALL
    callinfo.solid_args = int(proof.argument_count)
    callinfo.call_spd = min(argument.vd_offset for argument in arguments)
    callinfo.stkargs_top = max(argument.vd_offset + 4 for argument in arguments)
    callinfo.flags |= (
        int(ida_hexrays.FCI_FINAL)
        | int(ida_hexrays.FCI_SPLOK)
        | int(ida_hexrays.FCI_EXPLOCS)
    )
    return callinfo


__all__ = [
    "apply_three_argument_stdcall_type",
    "build_three_argument_stdcall_callinfo",
    "collect_three_argument_callee_purged_evidence",
    "native_call_stack_deficit",
    "native_corridor_has_no_stack_adjustment",
    "outgoing_stack_argument_offsets",
    "trace_linear_microcode_reentry",
]
