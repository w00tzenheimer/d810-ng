from types import SimpleNamespace

import ida_hexrays
import ida_typeinf

from d810.analyses.control_flow.call_abi import StackCallAbiProof
from d810.backends.hexrays.evidence import call_abi
from d810.backends.hexrays.evidence.call_abi import (
    apply_three_argument_stdcall_type,
    build_three_argument_stdcall_callinfo,
    collect_three_argument_callee_purged_evidence,
    native_call_stack_deficit,
    native_corridor_has_no_stack_adjustment,
    outgoing_stack_argument_offsets,
    trace_linear_microcode_reentry,
)


def _operand(kind: int, *, offset: int = 0, size: int = 4):
    return SimpleNamespace(
        t=kind,
        s=SimpleNamespace(off=offset),
        size=size,
    )


def _instruction(opcode: int, ea: int, destination, following=None):
    return SimpleNamespace(
        opcode=opcode,
        ea=ea,
        d=destination,
        next=following,
    )


def test_collects_complete_contiguous_outgoing_stack_arguments() -> None:
    tail = _instruction(ida_hexrays.m_icall, 0x1030, _operand(ida_hexrays.mop_z))
    third = _instruction(ida_hexrays.m_ldx, 0x1020, _operand(ida_hexrays.mop_S, offset=0x24), tail)
    second = _instruction(ida_hexrays.m_mov, 0x1010, _operand(ida_hexrays.mop_S, offset=0x28), third)
    first = _instruction(ida_hexrays.m_mov, 0x1000, _operand(ida_hexrays.mop_S, offset=0x2C), second)
    block = SimpleNamespace(
        head=first,
        tail=tail,
        mba=SimpleNamespace(
            stkoff_vd2ida=lambda offset: {0x24: -12, 0x28: -8, 0x2C: -4}[offset]
        ),
    )

    assert outgoing_stack_argument_offsets(block, word_size=4) == (-12, -8, -4)


def test_argument_collection_rejects_duplicate_or_wrong_sized_writes() -> None:
    tail = _instruction(ida_hexrays.m_icall, 0x1030, _operand(ida_hexrays.mop_z))
    duplicate = _instruction(ida_hexrays.m_mov, 0x1020, _operand(ida_hexrays.mop_S, offset=0x28), tail)
    wrong_size = _instruction(
        ida_hexrays.m_mov,
        0x1010,
        _operand(ida_hexrays.mop_S, offset=0x28, size=2),
        duplicate,
    )
    first = _instruction(ida_hexrays.m_mov, 0x1000, _operand(ida_hexrays.mop_S, offset=0x2C), wrong_size)
    block = SimpleNamespace(
        head=first,
        tail=tail,
        mba=SimpleNamespace(stkoff_vd2ida=lambda offset: {0x28: -8, 0x2C: -4}[offset]),
    )

    assert outgoing_stack_argument_offsets(block, word_size=4) is None


def test_argument_collection_stops_at_equal_swig_tail_proxy() -> None:
    class _EqualInstruction(SimpleNamespace):
        def __eq__(self, other) -> bool:
            return (
                int(self.ea) == int(other.ea)
                and int(self.opcode) == int(other.opcode)
            )

    tail_in_chain = _EqualInstruction(
        opcode=ida_hexrays.m_icall,
        ea=0x1030,
        d=_operand(ida_hexrays.mop_z),
        next=None,
    )
    tail_proxy = _EqualInstruction(
        opcode=ida_hexrays.m_icall,
        ea=0x1030,
        d=_operand(ida_hexrays.mop_z),
        next=None,
    )
    first = _instruction(
        ida_hexrays.m_mov,
        0x1000,
        _operand(ida_hexrays.mop_S, offset=0x2C),
        tail_in_chain,
    )
    block = SimpleNamespace(
        head=first,
        tail=tail_proxy,
        mba=SimpleNamespace(stkoff_vd2ida=lambda _offset: -4),
    )

    assert outgoing_stack_argument_offsets(block, word_size=4) == (-4,)


def test_traces_linear_continuation_to_proven_reentry_ea() -> None:
    reentry = _instruction(ida_hexrays.m_ijmp, 0x2020, _operand(ida_hexrays.mop_z))
    continuation = SimpleNamespace(
        head=reentry,
        tail=reentry,
        succset=(),
    )
    call = _instruction(ida_hexrays.m_icall, 0x1030, _operand(ida_hexrays.mop_z))
    mba = SimpleNamespace(get_mblock=lambda serial: {1: continuation}[serial])
    block = SimpleNamespace(tail=call, succset=(1,), mba=mba)

    assert trace_linear_microcode_reentry(block, frozenset({0x2020})) == (
        True,
        True,
    )


def test_reentry_trace_abstains_on_branching_continuation() -> None:
    call = _instruction(ida_hexrays.m_icall, 0x1030, _operand(ida_hexrays.mop_z))
    mba = SimpleNamespace(get_mblock=lambda serial: None)
    block = SimpleNamespace(tail=call, succset=(1, 2), mba=mba)

    assert trace_linear_microcode_reentry(block, frozenset({0x2020})) == (
        False,
        False,
    )


def test_collects_structural_evidence_without_sample_identity(monkeypatch) -> None:
    call = _instruction(ida_hexrays.m_icall, 0x1030, _operand(ida_hexrays.mop_z))
    block = SimpleNamespace(tail=call)
    monkeypatch.setattr(
        "d810.backends.hexrays.evidence.call_abi.outgoing_stack_argument_offsets",
        lambda _block, *, word_size: (-12, -8, -4),
    )
    monkeypatch.setattr(
        "d810.backends.hexrays.evidence.call_abi.trace_linear_microcode_reentry",
        lambda _block, _reentry_eas: (True, True),
    )

    evidence = collect_three_argument_callee_purged_evidence(
        block,
        proven_reentry_eas=frozenset({0x2020}),
        has_authoritative_type=False,
        call_stack_deficit=12,
        caller_stack_adjustment=0,
        word_size=4,
    )

    assert evidence.outgoing_stack_offsets == (-12, -8, -4)
    assert evidence.continuation_reaches_proven_reentry
    assert not evidence.has_authoritative_type


def test_computes_call_stack_deficit_from_canonical_frame(monkeypatch) -> None:
    function = object()
    monkeypatch.setattr(call_abi.ida_funcs, "get_func", lambda _ea: function)
    monkeypatch.setattr(
        call_abi.ida_frame,
        "get_spd",
        lambda owner, _ea: -1180 if owner is function else 0,
    )
    block = SimpleNamespace(mba=SimpleNamespace(frsize=1164, frregs=4))

    assert native_call_stack_deficit(block, 0x1030) == 12


def test_native_corridor_requires_no_stack_write_before_reentry(monkeypatch) -> None:
    instructions = {
        0x1000: (SimpleNamespace(ea=0x1000, mnemonic="call", writes_sp=False), 3),
        0x1003: (SimpleNamespace(ea=0x1003, mnemonic="mov", writes_sp=False), 2),
    }
    monkeypatch.setattr(
        call_abi,
        "_decode_native_instruction",
        lambda ea: instructions.get(ea),
    )
    monkeypatch.setattr(
        call_abi,
        "_native_instruction_writes_stack_pointer",
        lambda instruction: instruction.writes_sp,
    )
    monkeypatch.setattr(
        call_abi,
        "_native_instruction_mnemonic",
        lambda instruction: instruction.mnemonic,
    )

    assert native_corridor_has_no_stack_adjustment(
        0x1000,
        frozenset({0x1005}),
    )

    instructions[0x1003] = (
        SimpleNamespace(ea=0x1003, mnemonic="add", writes_sp=True),
        2,
    )
    assert not native_corridor_has_no_stack_adjustment(
        0x1000,
        frozenset({0x1005}),
    )


def test_native_corridor_abstains_on_early_control_transfer(monkeypatch) -> None:
    instructions = {
        0x1000: (SimpleNamespace(ea=0x1000, mnemonic="call", writes_sp=False), 3),
        0x1003: (SimpleNamespace(ea=0x1003, mnemonic="jmp", writes_sp=False), 2),
    }
    monkeypatch.setattr(
        call_abi,
        "_decode_native_instruction",
        lambda ea: instructions.get(ea),
    )
    monkeypatch.setattr(
        call_abi,
        "_native_instruction_writes_stack_pointer",
        lambda instruction: instruction.writes_sp,
    )
    monkeypatch.setattr(
        call_abi,
        "_native_instruction_mnemonic",
        lambda instruction: instruction.mnemonic,
    )

    assert native_corridor_has_no_stack_adjustment(
        0x1000,
        frozenset({0x1005}),
    ) is None


class TestStdcallTypeMaterialization:
    binary_name = "restructuring_lab.dll"

    def test_builds_stdcall_function_type_with_three_stack_arguments(
        self,
        ida_database,
    ) -> None:
        call_type = ida_typeinf.tinfo_t()
        proof = StackCallAbiProof(argument_count=3, stack_argument_bytes=12)

        assert apply_three_argument_stdcall_type(call_type, proof)
        assert call_type.is_func()
        details = ida_typeinf.func_type_data_t()
        assert call_type.get_func_details(details)
        assert int(details.get_cc()) == int(ida_typeinf.CM_CC_STDCALL)
        assert len(details) == 3
        assert all(argument.type.get_size() == 4 for argument in details)

    def test_builds_complete_final_mop_f_callinfo(
        self,
        ida_database,
        monkeypatch,
    ) -> None:
        class _ArgLoc:
            def __init__(self) -> None:
                self.offset = None

            def set_stkoff(self, offset: int) -> None:
                self.offset = offset

            def stkoff(self) -> int:
                return self.offset

        class _CallArgument:
            def __init__(self) -> None:
                self.argloc = _ArgLoc()
                self.t = ida_hexrays.mop_z
                self.s = SimpleNamespace(off=0)
                self.size = 0
                self.type = None
                self.ea = 0

            def copy_mop(self, operand) -> None:
                self.t = operand.t
                self.s = operand.s
                self.size = operand.size

        class _CallArguments(list):
            def push_back(self):
                argument = _CallArgument()
                self.append(argument)
                return argument

        class _Callinfo:
            def __init__(self) -> None:
                self.args = _CallArguments()
                self.cc = 0
                self.solid_args = 0
                self.call_spd = 0
                self.stkargs_top = 0
                self.flags = 0

            def set_type(self, _call_type) -> bool:
                return True

        monkeypatch.setattr(call_abi.ida_hexrays, "mcallinfo_t", _Callinfo)
        tail = _instruction(
            ida_hexrays.m_icall,
            0x1030,
            _operand(ida_hexrays.mop_z),
        )
        third = _instruction(
            ida_hexrays.m_ldx,
            0x1020,
            _operand(ida_hexrays.mop_S, offset=0x24),
            tail,
        )
        second = _instruction(
            ida_hexrays.m_mov,
            0x1010,
            _operand(ida_hexrays.mop_S, offset=0x28),
            third,
        )
        first = _instruction(
            ida_hexrays.m_mov,
            0x1000,
            _operand(ida_hexrays.mop_S, offset=0x2C),
            second,
        )
        block = SimpleNamespace(
            head=first,
            tail=tail,
            mba=SimpleNamespace(
                stkoff_vd2ida=lambda offset: {
                    0x24: -12,
                    0x28: -8,
                    0x2C: -4,
                }[offset]
            ),
        )
        call_type = ida_typeinf.tinfo_t()
        proof = StackCallAbiProof(argument_count=3, stack_argument_bytes=12)
        assert apply_three_argument_stdcall_type(call_type, proof)

        callinfo = build_three_argument_stdcall_callinfo(
            block,
            call_type,
            proof,
        )

        assert callinfo is not None
        assert int(callinfo.cc) == int(ida_typeinf.CM_CC_STDCALL)
        assert len(callinfo.args) == 3
        assert [int(argument.t) for argument in callinfo.args] == [
            int(ida_hexrays.mop_S),
        ] * 3
        assert [int(argument.s.off) for argument in callinfo.args] == [
            0x24,
            0x28,
            0x2C,
        ]
        assert [int(argument.argloc.stkoff()) for argument in callinfo.args] == [
            0,
            4,
            8,
        ]
        assert int(callinfo.call_spd) == 0x24
        assert int(callinfo.stkargs_top) == 0x30
        assert int(callinfo.flags) & int(ida_hexrays.FCI_FINAL)
        assert int(callinfo.flags) & int(ida_hexrays.FCI_SPLOK)
        assert int(callinfo.flags) & int(ida_hexrays.FCI_EXPLOCS)
