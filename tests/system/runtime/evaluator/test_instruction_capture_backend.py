from __future__ import annotations

from types import SimpleNamespace

import ida_hexrays

from d810.ir.flowgraph import BlockSnapshot, InsnSnapshot, MopSnapshot
from d810.transforms.state_write_cleanup import StateWriteCleanupAction
from d810.evaluator.hexrays_microcode.instruction_capture_backend import (
    HexRaysInstructionCaptureBackend,
)


class _Insn:
    def __init__(
        self,
        opcode: int,
        *,
        ea: int = 0,
        l=None,
        r=None,
        d=None,
        next_insn=None,
    ):
        self.opcode = opcode
        self.ea = ea
        self.l = l
        self.r = r
        self.d = d
        self.next = next_insn


class _Block:
    def __init__(self, head, *, serial: int = 0):
        self.head = head
        self.serial = serial


class _Mba:
    def __init__(self, blocks):
        self._blocks = blocks
        self.qty = max(tuple(blocks) or (-1,)) + 1

    def get_mblock(self, serial):
        return self._blocks.get(int(serial))


def _state_mop(stkoff: int) -> SimpleNamespace:
    return SimpleNamespace(
        t=ida_hexrays.mop_S,
        size=4,
        s=SimpleNamespace(off=stkoff),
    )


def _const_mop(value: int) -> SimpleNamespace:
    return SimpleNamespace(
        t=ida_hexrays.mop_n,
        size=4,
        nnn=SimpleNamespace(value=value),
    )


def _live_like_state_mop(stkoff: int) -> SimpleNamespace:
    return SimpleNamespace(
        t=ida_hexrays.mop_S,
        size=4,
        stkoff=object(),
        s=SimpleNamespace(off=stkoff),
    )


def _live_like_const_mop(value: int) -> SimpleNamespace:
    return SimpleNamespace(
        t=ida_hexrays.mop_n,
        size=4,
        value=object(),
        nnn=SimpleNamespace(value=value),
    )


def test_block_has_non_state_payload_rejects_state_write_goto_glue() -> None:
    goto = _Insn(ida_hexrays.m_goto)
    write = _Insn(
        ida_hexrays.m_mov,
        l=_const_mop(0x55),
        d=_state_mop(0x30),
        next_insn=goto,
    )
    backend = HexRaysInstructionCaptureBackend()

    assert not backend.block_has_non_state_payload(
        _Mba({7: _Block(write)}),
        7,
        state_variable=0x30,
    )


def test_block_has_non_state_payload_accepts_real_instruction() -> None:
    real = _Insn(ida_hexrays.m_add)
    backend = HexRaysInstructionCaptureBackend()

    assert backend.block_has_non_state_payload(
        _Mba({7: _Block(real)}),
        7,
        state_variable=0x30,
    )


def test_classify_trivial_tail_state_write_cleanup_returns_nop_request() -> None:
    state = MopSnapshot(t=ida_hexrays.mop_S, size=4, stkoff=0x30)
    const = MopSnapshot(t=ida_hexrays.mop_n, size=4, value=0x55)
    target = MopSnapshot(t=ida_hexrays.mop_b, size=4, block_ref=9)
    block = BlockSnapshot(
        7,
        0,
        (9,),
        (),
        0,
        0,
        (
            InsnSnapshot(ida_hexrays.m_mov, 0x1004, (), l=const, d=state),
            InsnSnapshot(ida_hexrays.m_goto, 0x1008, (), l=target),
        ),
    )

    request = HexRaysInstructionCaptureBackend().classify_trivial_tail_state_write_cleanup(
        block,
        state_variable=0x30,
        expected_state=0x55,
    )

    assert request is not None
    assert request.action == StateWriteCleanupAction.NOP_INSTRUCTION
    assert request.block_serial == 7
    assert request.insn_ea == 0x1004


def test_classify_matching_state_write_cleanup_returns_zero_request() -> None:
    state = MopSnapshot(t=ida_hexrays.mop_S, size=4, stkoff=0x30)
    const = MopSnapshot(t=ida_hexrays.mop_n, size=4, value=0x55)
    block = BlockSnapshot(
        7,
        0,
        (),
        (),
        0,
        0,
        (InsnSnapshot(ida_hexrays.m_mov, 0x1004, (), l=const, d=state),),
    )

    request = HexRaysInstructionCaptureBackend().classify_matching_state_write_cleanup(
        block,
        state_variable=0x30,
        expected_state=0x55,
    )

    assert request is not None
    assert request.action == StateWriteCleanupAction.ZERO_SOURCE
    assert request.block_serial == 7
    assert request.insn_ea == 0x1004


def test_collect_unresolved_stkvar_reads_uses_snapshot_order() -> None:
    backend = HexRaysInstructionCaptureBackend()
    external = MopSnapshot(t=ida_hexrays.mop_S, size=4, stkoff=0x40)
    local = MopSnapshot(t=ida_hexrays.mop_S, size=4, stkoff=0x50)
    state = MopSnapshot(t=ida_hexrays.mop_S, size=4, stkoff=0x30)

    unresolved = backend.collect_unresolved_stkvar_reads(
        (
            InsnSnapshot(ida_hexrays.m_mov, 0x1000, (), l=external, d=local),
            InsnSnapshot(ida_hexrays.m_add, 0x1004, (), l=local, r=state),
        ),
        state_variable=0x30,
    )

    assert unresolved == {0x40}


def test_find_unique_const_writer_for_stkoff_returns_only_unique_writer() -> None:
    writer = _Insn(
        ida_hexrays.m_mov,
        l=_const_mop(0x44),
        d=_state_mop(0x50),
    )
    other = _Insn(
        ida_hexrays.m_mov,
        l=_const_mop(0x55),
        d=_state_mop(0x60),
    )
    backend = HexRaysInstructionCaptureBackend()

    assert backend.find_unique_const_writer_for_stkoff(
        _Mba({2: _Block(writer), 4: _Block(other)}),
        0x50,
        state_variable=0x30,
    ) == 2


def test_find_unique_const_writer_for_stkoff_uses_live_mop_fallback_fields() -> None:
    writer = _Insn(
        ida_hexrays.m_mov,
        l=_live_like_const_mop(0x44),
        d=_live_like_state_mop(0x50),
    )
    backend = HexRaysInstructionCaptureBackend()

    assert backend.find_unique_const_writer_for_stkoff(
        _Mba({2: _Block(writer)}),
        0x50,
        state_variable=0x30,
    ) == 2


def test_find_unique_const_writer_for_stkoff_rejects_multiple_writers() -> None:
    writer_a = _Insn(
        ida_hexrays.m_mov,
        l=_const_mop(0x44),
        d=_state_mop(0x50),
    )
    writer_b = _Insn(
        ida_hexrays.m_mov,
        l=_const_mop(0x55),
        d=_state_mop(0x50),
    )
    backend = HexRaysInstructionCaptureBackend()

    assert backend.find_unique_const_writer_for_stkoff(
        _Mba({2: _Block(writer_a), 4: _Block(writer_b)}),
        0x50,
        state_variable=0x30,
    ) is None


def test_block_contains_call_detects_call_opcode() -> None:
    call = _Insn(ida_hexrays.m_call)
    backend = HexRaysInstructionCaptureBackend()

    assert backend.block_contains_call(_Mba({3: _Block(call)}), 3)


def test_instruction_snapshot_is_call_detects_call_opcode() -> None:
    backend = HexRaysInstructionCaptureBackend()

    assert backend.instruction_snapshot_is_call(_Insn(ida_hexrays.m_icall))
    assert not backend.instruction_snapshot_is_call(_Insn(ida_hexrays.m_add))


def test_captured_body_contains_call_reads_backend_summary() -> None:
    backend = HexRaysInstructionCaptureBackend()
    captured_body = SimpleNamespace(
        summary=SimpleNamespace(contains_call=True),
    )

    assert backend.captured_body_contains_call(captured_body)


def test_block_contains_call_rejects_non_call_opcode() -> None:
    real = _Insn(ida_hexrays.m_add)
    backend = HexRaysInstructionCaptureBackend()

    assert not backend.block_contains_call(_Mba({3: _Block(real)}), 3)


def test_collect_state_constant_writes_returns_backend_neutral_evidence() -> None:
    write = _Insn(
        ida_hexrays.m_mov,
        ea=0x2200,
        l=_const_mop(0x123456789),
        d=_state_mop(0x30),
    )
    other = _Insn(
        ida_hexrays.m_mov,
        ea=0x2300,
        l=_const_mop(0x44),
        d=_state_mop(0x40),
    )
    backend = HexRaysInstructionCaptureBackend()

    writes = backend.collect_state_constant_writes(
        _Mba({5: _Block(write), 6: _Block(other)}),
        state_variable=0x30,
    )

    assert len(writes) == 1
    assert writes[0].block_serial == 5
    assert writes[0].insn_ea == 0x2200
    assert writes[0].state_value == 0x23456789
