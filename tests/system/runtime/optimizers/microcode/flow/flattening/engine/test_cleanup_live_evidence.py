"""Tests for live cleanup evidence collectors."""
from __future__ import annotations

from types import SimpleNamespace

import ida_hexrays

from d810.optimizers.microcode.flow.flattening import (
    cleanup_live_evidence as live_evidence_module,
)
from d810.optimizers.microcode.flow.flattening.cleanup_live_evidence import (
    collect_live_single_iteration_convert_fixes,
    collect_live_single_iteration_block_fixes,
)
from d810.optimizers.microcode.flow.flattening.strategies.single_iteration import (
    SingleIterationConvertFix,
    SingleIterationPredFix,
)


class _FakeMop:
    def __init__(
        self,
        mop_type: int,
        *,
        name: str = "",
        value: int | None = None,
        size: int = 4,
    ) -> None:
        self.t = mop_type
        self.name = name
        self.size = size
        self.nnn = SimpleNamespace(value=value)
        self._value = value

    def signed_value(self) -> int:
        assert self._value is not None
        return int(self._value)

    def equal_mops(self, other: object, _flags: int) -> bool:
        return (
            isinstance(other, _FakeMop)
            and self.t == other.t
            and self.name == other.name
        )


class _FakeInsn:
    def __init__(
        self,
        opcode: int,
        *,
        left: _FakeMop | None = None,
        right: _FakeMop | None = None,
        dest: _FakeMop | object | None = None,
        prev: object | None = None,
    ) -> None:
        self.opcode = opcode
        self.l = left
        self.r = right
        self.d = dest
        self.prev = prev


class _FakeBlock:
    def __init__(
        self,
        serial: int,
        succs: tuple[int, ...],
        preds: tuple[int, ...],
        tail: _FakeInsn,
    ) -> None:
        self.serial = int(serial)
        self._succs = tuple(int(succ) for succ in succs)
        self.succset = set(self._succs)
        self.predset = set(int(pred) for pred in preds)
        self.tail = tail
        self.mba: _FakeMba | None = None

    def nsucc(self) -> int:
        return len(self._succs)

    def succ(self, index: int) -> int:
        return self._succs[index]


class _FakeMba:
    def __init__(self, *blocks: _FakeBlock) -> None:
        self._blocks = {block.serial: block for block in blocks}
        for block in blocks:
            block.mba = self

    def get_mblock(self, serial: int) -> _FakeBlock | None:
        return self._blocks.get(int(serial))


def _reg(name: str) -> _FakeMop:
    return _FakeMop(ida_hexrays.mop_r, name=name)


def _num(value: int) -> _FakeMop:
    return _FakeMop(ida_hexrays.mop_n, value=value)


def test_copied_carrier_jz_self_loop_produces_entry_redirect() -> None:
    state = _reg("r8d")
    compared = _reg("edx")
    update = _reg("eax")

    capture = _FakeInsn(
        ida_hexrays.m_mov,
        left=state,
        dest=compared,
    )
    state_update = _FakeInsn(
        ida_hexrays.m_mov,
        left=update,
        dest=state,
        prev=capture,
    )
    header_tail = _FakeInsn(
        ida_hexrays.m_jz,
        left=compared,
        right=_num(0xE739ACEB),
        dest=SimpleNamespace(b=6),
        prev=state_update,
    )
    header = _FakeBlock(6, (7, 6), (4, 5, 6), header_tail)

    update_init = _FakeInsn(
        ida_hexrays.m_mov,
        left=_num(0xBAD3ACF7),
        dest=update,
    )
    state_init = _FakeInsn(
        ida_hexrays.m_mov,
        left=_num(0xE739ACEB),
        dest=state,
        prev=update_init,
    )
    pred_tail = _FakeInsn(ida_hexrays.m_goto, dest=SimpleNamespace(b=6), prev=state_init)
    entry_pred = _FakeBlock(4, (6,), (2,), pred_tail)

    non_entering_state = _FakeInsn(
        ida_hexrays.m_mov,
        left=_num(0xBAD3ACF7),
        dest=state,
        prev=update_init,
    )
    other_pred_tail = _FakeInsn(
        ida_hexrays.m_goto,
        dest=SimpleNamespace(b=6),
        prev=non_entering_state,
    )
    other_pred = _FakeBlock(5, (6,), (7,), other_pred_tail)

    _FakeMba(header, entry_pred, other_pred)

    assert collect_live_single_iteration_block_fixes(header) == (
        SingleIterationPredFix(loop_header=6, pred_block=4, new_target=7),
    )


def test_copied_carrier_single_iteration_rejects_extra_header_work() -> None:
    state = _reg("r8d")
    compared = _reg("edx")
    update = _reg("eax")
    unrelated = _reg("r15d")

    capture = _FakeInsn(
        ida_hexrays.m_mov,
        left=state,
        dest=compared,
    )
    extra_work = _FakeInsn(
        ida_hexrays.m_mov,
        left=update,
        dest=unrelated,
        prev=capture,
    )
    state_update = _FakeInsn(
        ida_hexrays.m_mov,
        left=update,
        dest=state,
        prev=extra_work,
    )
    header_tail = _FakeInsn(
        ida_hexrays.m_jz,
        left=compared,
        right=_num(0xE739ACEB),
        dest=SimpleNamespace(b=6),
        prev=state_update,
    )
    header = _FakeBlock(6, (7, 6), (4, 6), header_tail)

    update_init = _FakeInsn(
        ida_hexrays.m_mov,
        left=_num(0xBAD3ACF7),
        dest=update,
    )
    state_init = _FakeInsn(
        ida_hexrays.m_mov,
        left=_num(0xE739ACEB),
        dest=state,
        prev=update_init,
    )
    pred_tail = _FakeInsn(ida_hexrays.m_goto, dest=SimpleNamespace(b=6), prev=state_init)
    entry_pred = _FakeBlock(4, (6,), (2,), pred_tail)

    _FakeMba(header, entry_pred)

    assert collect_live_single_iteration_block_fixes(header) == ()


def test_copied_carrier_accepts_multiple_update_values_when_all_exit(
    monkeypatch,
) -> None:
    state = _reg("r8d")
    compared = _reg("edx")
    update = _reg("eax")

    capture = _FakeInsn(
        ida_hexrays.m_mov,
        left=state,
        dest=compared,
    )
    state_update = _FakeInsn(
        ida_hexrays.m_mov,
        left=update,
        dest=state,
        prev=capture,
    )
    header_tail = _FakeInsn(
        ida_hexrays.m_jz,
        left=compared,
        right=_num(0xE739ACEB),
        dest=SimpleNamespace(b=6),
        prev=state_update,
    )
    header = _FakeBlock(6, (7, 6), (4, 6), header_tail)
    pred_tail = _FakeInsn(ida_hexrays.m_goto, dest=SimpleNamespace(b=6))
    entry_pred = _FakeBlock(4, (6,), (2,), pred_tail)
    _FakeMba(header, entry_pred)

    def _resolve_constants(pred_blk, mop, **_kwargs):
        assert pred_blk is entry_pred
        if mop.equal_mops(state, ida_hexrays.EQ_IGNSIZE):
            return frozenset((0xE739ACEB,))
        if mop.equal_mops(update, ida_hexrays.EQ_IGNSIZE):
            return frozenset((0xBAD3ACF7, 0x5C6C1503))
        return None

    monkeypatch.setattr(
        live_evidence_module,
        "_resolve_live_mop_constants",
        _resolve_constants,
    )

    assert collect_live_single_iteration_block_fixes(header) == (
        SingleIterationPredFix(loop_header=6, pred_block=4, new_target=7),
    )


def test_body_preserving_single_iteration_redirects_body_backedge() -> None:
    state = _reg("edx")
    scratch = _reg("rcx")

    header_tail = _FakeInsn(
        ida_hexrays.m_jz,
        left=state,
        right=_num(0x5C6C1503),
        dest=SimpleNamespace(b=5),
    )
    header = _FakeBlock(6, (7, 5), (4, 5), header_tail)

    side_effect = _FakeInsn(
        ida_hexrays.m_mov,
        left=scratch,
        dest=_reg("rbx"),
    )
    state_update = _FakeInsn(
        ida_hexrays.m_mov,
        left=_num(0xBAD3ACF7),
        dest=state,
        prev=side_effect,
    )
    body_tail = _FakeInsn(ida_hexrays.m_goto, dest=SimpleNamespace(b=6), prev=state_update)
    body = _FakeBlock(5, (6,), (6,), body_tail)

    entry_pred = _FakeBlock(
        4,
        (6,),
        (3,),
        _FakeInsn(ida_hexrays.m_goto, dest=SimpleNamespace(b=6)),
    )

    _FakeMba(header, body, entry_pred)

    assert collect_live_single_iteration_block_fixes(header) == (
        SingleIterationPredFix(loop_header=6, pred_block=5, new_target=7),
    )


def test_body_preserving_single_iteration_rejects_header_work() -> None:
    state = _reg("edx")
    header_copy = _FakeInsn(
        ida_hexrays.m_mov,
        left=state,
        dest=_reg("eax"),
    )
    header_tail = _FakeInsn(
        ida_hexrays.m_jz,
        left=state,
        right=_num(0x5C6C1503),
        dest=SimpleNamespace(b=5),
        prev=header_copy,
    )
    header = _FakeBlock(6, (7, 5), (4, 5), header_tail)

    state_update = _FakeInsn(
        ida_hexrays.m_mov,
        left=_num(0xBAD3ACF7),
        dest=state,
    )
    body_tail = _FakeInsn(ida_hexrays.m_goto, dest=SimpleNamespace(b=6), prev=state_update)
    body = _FakeBlock(5, (6,), (6,), body_tail)
    entry_pred = _FakeBlock(
        4,
        (6,),
        (3,),
        _FakeInsn(ida_hexrays.m_goto, dest=SimpleNamespace(b=6)),
    )
    _FakeMba(header, body, entry_pred)

    assert collect_live_single_iteration_block_fixes(header) == ()


def test_copied_comparison_self_loop_converts_when_entries_exit() -> None:
    compared = _reg("edx")
    source = _reg("r8d")

    copy_to_compared = _FakeInsn(
        ida_hexrays.m_xdu,
        left=source,
        dest=compared,
    )
    copy_to_scratch = _FakeInsn(
        ida_hexrays.m_mov,
        left=source,
        dest=_reg("eax"),
        prev=copy_to_compared,
    )
    header_tail = _FakeInsn(
        ida_hexrays.m_jz,
        left=compared,
        right=_num(0xE739ACEB),
        dest=SimpleNamespace(b=6),
        prev=copy_to_scratch,
    )
    header = _FakeBlock(6, (7, 6), (4, 6), header_tail)

    source_init = _FakeInsn(
        ida_hexrays.m_mov,
        left=_num(0xBAD3ACF7),
        dest=source,
    )
    entry_pred = _FakeBlock(
        4,
        (6,),
        (3,),
        _FakeInsn(ida_hexrays.m_goto, dest=SimpleNamespace(b=6), prev=source_init),
    )
    mba = _FakeMba(header, entry_pred)
    mba.qty = 7
    mba.maturity = ida_hexrays.MMAT_GLBOPT1

    assert collect_live_single_iteration_convert_fixes(
        mba,
        allowed_maturities=(ida_hexrays.MMAT_GLBOPT1,),
    ) == (
        SingleIterationConvertFix(loop_header=6, new_target=7),
    )
