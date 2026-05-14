from __future__ import annotations

from types import SimpleNamespace

import ida_hexrays

from d810.cfg.flowgraph import BlockSnapshot, InsnSnapshot, MopSnapshot
from d810.cfg.state_write_cleanup import StateWriteCleanupAction
from d810.evaluator.hexrays_microcode.instruction_capture_backend import (
    HexRaysInstructionCaptureBackend,
)


class _Insn:
    def __init__(self, opcode: int, *, l=None, d=None, next_insn=None):
        self.opcode = opcode
        self.l = l
        self.d = d
        self.next = next_insn


class _Block:
    def __init__(self, head):
        self.head = head


class _Mba:
    def __init__(self, blocks):
        self._blocks = blocks

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
