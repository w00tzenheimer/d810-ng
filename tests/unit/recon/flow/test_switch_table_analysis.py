"""Unit tests for switch-table analysis pure-logic helpers."""
from __future__ import annotations

from d810.recon.flow.dispatcher_detection import DispatcherType
from d810.recon.flow.switch_table_analysis import (
    build_state_dispatcher_map_from_cases,
    find_switch_loop_guard_blocks,
)


class _FakeBlock:
    def __init__(self, *, preds=(), succs=(), tail=None):
        self._preds = tuple(preds)
        self._succs = tuple(succs)
        self.tail = tail

    def npred(self):
        return len(self._preds)

    def pred(self, index):
        return self._preds[index]

    def nsucc(self):
        return len(self._succs)

    def succ(self, index):
        return self._succs[index]


class _FakeMba:
    def __init__(self, blocks):
        self._blocks = dict(blocks)

    def get_mblock(self, serial):
        return self._blocks.get(serial)


class _FakeStackRef:
    def __init__(self, off):
        self.off = off


class _FakeConst:
    def __init__(self, value):
        self.value = value


class _FakeMop:
    def __init__(self, *, stkoff=None, value=None):
        if stkoff is not None:
            self.s = _FakeStackRef(stkoff)
        if value is not None:
            self.nnn = _FakeConst(value)


class _FakeTail:
    def __init__(self, left, right, opcode=43):
        self.opcode = opcode
        self.l = left
        self.r = right


def test_find_switch_loop_guard_blocks_finds_while_guard():
    guard_tail = _FakeTail(_FakeMop(stkoff=0x10), _FakeMop(value=0xFF))
    mba = _FakeMba({
        2: _FakeBlock(preds=(0, 6), succs=(3, 9), tail=guard_tail),
        3: _FakeBlock(preds=(2, 6), succs=(4, 5)),
        6: _FakeBlock(succs=(3,)),
        9: _FakeBlock(),
    })

    assert find_switch_loop_guard_blocks(
        mba,
        3,
        state_var_stkoff=0x10,
        case_values=frozenset({0, 1, 2, 3, 4, 5, 6, 7}),
    ) == frozenset({2})


def test_find_switch_loop_guard_blocks_rejects_unrelated_branch():
    branch_tail = _FakeTail(_FakeMop(stkoff=0x20), _FakeMop(value=0xFF))
    mba = _FakeMba({
        2: _FakeBlock(preds=(0, 6), succs=(3, 9), tail=branch_tail),
        3: _FakeBlock(preds=(2, 6), succs=(4, 5)),
        6: _FakeBlock(succs=(3,)),
        9: _FakeBlock(),
    })

    assert find_switch_loop_guard_blocks(
        mba,
        3,
        state_var_stkoff=0x10,
        case_values=frozenset({0, 1, 2, 3, 4, 5, 6, 7}),
    ) == frozenset()


class TestBuildStateDispatcherMapFromCases:
    """Test case-list to exact StateDispatcherMap conversion."""

    def test_simple_4_state(self):
        """abc_or_dispatch shape: 4 linear cases."""
        cases = [(0, 10), (1, 11), (2, 12), (3, 13)]
        m = build_state_dispatcher_map_from_cases(
            cases=cases,
            dispatcher_serial=5,
            dispatcher_blocks=frozenset({5}),
            state_var_stkoff=0x3C,
        )
        assert m.state_to_handler() == {0: 10, 1: 11, 2: 12, 3: 13}
        assert m.handler_state_map() == {10: 0, 11: 1, 12: 2, 13: 3}
        assert m.dispatcher_entry_block == 5
        assert m.dispatcher_blocks == frozenset({5})
        assert m.state_var_stkoff == 0x3C
        assert m.source == DispatcherType.SWITCH_TABLE

    def test_with_initial_state(self):
        cases = [(0, 10), (1, 11)]
        m = build_state_dispatcher_map_from_cases(
            cases=cases,
            dispatcher_serial=5,
            dispatcher_blocks=frozenset({5}),
            state_var_stkoff=0x3C,
            initial_state=0,
        )
        assert m.initial_state == 0

    def test_preserves_aliased_targets(self):
        """Multiple case values mapping to one target stay exact rows."""
        cases = [(0, 10), (1, 10), (2, 11)]
        m = build_state_dispatcher_map_from_cases(
            cases=cases,
            dispatcher_serial=5,
            dispatcher_blocks=frozenset({5}),
            state_var_stkoff=0x3C,
        )
        assert m.state_to_handler() == {0: 10, 1: 10, 2: 11}
        assert m.states_by_target() == {10: (0, 1), 11: (2,)}
        assert [row.row_kind for row in m.rows] == [
            "handler_alias",
            "handler_alias",
            "handler",
        ]
        # The old handler-map view is intentionally lossy; exact aliases live
        # in StateDispatcherMap.rows.
        assert m.to_dispatcher_handler_map().handler_state_map == {10: 0, 11: 2}

    def test_preserves_self_loop_targets(self):
        """Cases targeting the dispatcher itself are exact self-loop rows."""
        cases = [(0, 10), (1, 5), (2, 11)]
        m = build_state_dispatcher_map_from_cases(
            cases=cases,
            dispatcher_serial=5,
            dispatcher_blocks=frozenset({5}),
            state_var_stkoff=0x3C,
        )
        assert m.resolve_target(1) == 5
        assert m.rows[1].is_dispatcher_self_loop
        assert m.handler_state_map() == {10: 0, 11: 2}

    def test_empty_cases(self):
        m = build_state_dispatcher_map_from_cases(
            cases=[],
            dispatcher_serial=5,
            dispatcher_blocks=frozenset({5}),
            state_var_stkoff=0x3C,
        )
        assert m.rows == ()
        assert m.handler_state_map() == {}

    def test_resolve_target_works(self):
        """End-to-end: build map then resolve targets."""
        cases = [(0, 10), (1, 11), (2, 12), (3, 13)]
        m = build_state_dispatcher_map_from_cases(
            cases=cases,
            dispatcher_serial=5,
            dispatcher_blocks=frozenset({5}),
            state_var_stkoff=0x3C,
        )
        assert m.resolve_target(0) == 10
        assert m.resolve_target(2) == 12
        assert m.resolve_target(99) is None

    def test_records_default_target_separately(self):
        cases = [(0, 10), (None, 99)]
        m = build_state_dispatcher_map_from_cases(
            cases=cases,
            dispatcher_serial=5,
            dispatcher_blocks=frozenset({5}),
            state_var_stkoff=0x3C,
        )
        assert m.state_to_handler() == {0: 10}
        assert m.default_target_block == 99
        assert m.default_row_kind == "dispatcher_default"
