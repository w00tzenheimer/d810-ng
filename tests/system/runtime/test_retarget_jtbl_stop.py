"""Jump-table retargeting must preserve the terminal block's ready lists."""

from __future__ import annotations

from types import SimpleNamespace

import ida_hexrays

from d810.hexrays.mutation.cfg_mutations import retarget_jtbl_block_cases


class _SerialSet:
    def __init__(self, values=()):
        self.values = list(values)

    def __iter__(self):
        return iter(self.values)

    def __getitem__(self, index):
        return self.values[index]

    def size(self):
        return len(self.values)

    def _del(self, value):
        self.values.remove(value)

    def push_back(self, value):
        self.values.append(value)

    def clear(self):
        self.values.clear()

    def add_unique(self, value):
        if value not in self.values:
            self.values.append(value)


class _Targets:
    def __init__(self, values):
        self.values = list(values)

    def size(self):
        return len(self.values)

    def __getitem__(self, index):
        return self.values[index]

    def __setitem__(self, index, value):
        self.values[index] = value


class _Block:
    def __init__(self, serial, succs=(), preds=()):
        self.serial = serial
        self.succset = _SerialSet(succs)
        self.predset = _SerialSet(preds)
        self.dirty_calls = 0

    def mark_lists_dirty(self):
        self.dirty_calls += 1


def test_retarget_jtbl_default_does_not_dirty_stop_block() -> None:
    source = _Block(2, succs=(2, 3))
    ordinary = _Block(3, preds=(2,))
    stop = _Block(4)
    source.predset = _SerialSet((2,))
    targets = _Targets((3, 2))
    source.tail = SimpleNamespace(
        opcode=ida_hexrays.m_jtbl,
        r=SimpleNamespace(t=ida_hexrays.mop_c, c=SimpleNamespace(targets=targets)),
    )
    blocks = {2: source, 3: ordinary, 4: stop}
    mba = SimpleNamespace(
        qty=5,
        get_mblock=blocks.get,
        mark_chains_dirty=lambda: None,
    )
    source.mba = mba

    assert retarget_jtbl_block_cases(source, {2: 4}) == 1
    assert targets.values == [3, 4]
    assert source.succset.values == [3, 4]
    assert stop.predset.values == [2]
    assert stop.dirty_calls == 0
