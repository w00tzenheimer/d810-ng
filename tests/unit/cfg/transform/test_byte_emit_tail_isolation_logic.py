"""Unit tests for byte_emit_tail_isolation pure helpers.

No IDA imports. The orchestrator is exercised via a fake adapter.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from d810.cfg.transform.byte_emit_tail_isolation import (
    BlockView,
    FactRow,
    FactView,
    MicrocodeAdapter,
    PrecheckResult,
    ShapingReport,
    _check_preconditions,
    _resolve_target_ea,
    isolate_byte_emit_tail,
)


# ----- _resolve_target_ea -----


def _row(byte_index, snap, role="terminal_tail", ea="0x0000000180012df0"):
    return FactRow(
        snapshot_id=snap,
        byte_index=byte_index,
        block_serial=100 + byte_index,
        start_ea_hex=ea,
        corridor_role=role,
    )


def test_resolve_target_ea_returns_none_when_no_fact_for_byte():
    rows = [_row(0, 5), _row(1, 5), _row(3, 5)]
    assert _resolve_target_ea(rows, byte_index=2) is None


def test_resolve_target_ea_picks_terminal_tail_when_present():
    rows = [
        _row(2, 5, role="terminal_tail", ea="0xAA"),
        _row(2, 5, role="post_pipeline", ea="0xBB"),
    ]
    assert _resolve_target_ea(rows, byte_index=2) == "0xAA"


def test_resolve_target_ea_picks_highest_snapshot_when_no_tail_role():
    rows = [
        _row(2, 1, role="post_pipeline", ea="0xAA"),
        _row(2, 5, role="post_pipeline", ea="0xBB"),
    ]
    assert _resolve_target_ea(rows, byte_index=2) == "0xBB"


def test_resolve_target_ea_prefers_tail_role_even_at_lower_snapshot():
    rows = [
        _row(2, 9, role="post_pipeline", ea="0xCC"),
        _row(2, 5, role="terminal_tail", ea="0xAA"),
    ]
    assert _resolve_target_ea(rows, byte_index=2) == "0xAA"


# ----- _check_preconditions -----


def _block(*, nsucc=1, succ_serial=200, succ_npred=2, tail_kind="goto"):
    return BlockView(
        serial=161,
        start_ea=0x180012DF0,
        nsucc=nsucc,
        succ_serial=succ_serial,
        succ_npred=succ_npred,
        tail_kind=tail_kind,
    )


def test_preconditions_ok_for_shared_tail_with_goto():
    res = _check_preconditions(_block(nsucc=1, succ_npred=2, tail_kind="goto"))
    assert res.ok is True
    assert res.block is not None


def test_preconditions_ok_for_shared_tail_with_fallthrough():
    res = _check_preconditions(
        _block(nsucc=1, succ_npred=3, tail_kind="fallthrough")
    )
    assert res.ok is True
    assert res.block is not None


def test_preconditions_fail_when_nsucc_not_one():
    res = _check_preconditions(_block(nsucc=2))
    assert res.ok is False
    assert "multi_succ" in res.reason


def test_preconditions_fail_when_no_successor():
    res = _check_preconditions(_block(nsucc=1, succ_serial=None))
    assert res.ok is False
    assert "no_successor" in res.reason


def test_preconditions_fail_when_successor_unique_pred():
    """successor.npred == 1 means there's no folding pressure → no-op."""
    res = _check_preconditions(_block(succ_npred=1))
    assert res.ok is False
    assert res.reason == "no_shared_tail"


def test_preconditions_fail_when_tail_kind_unsupported():
    res = _check_preconditions(_block(tail_kind="cond_branch"))
    assert res.ok is False
    assert "tail_kind" in res.reason


# ----- isolate_byte_emit_tail orchestrator -----


@dataclass
class _FakeFactView:
    rows: list[FactRow] = field(default_factory=list)

    def terminal_byte_emit_facts(self, byte_index):
        return [r for r in self.rows if r.byte_index == byte_index]


@dataclass
class _FakeAdapter:
    block_at_ea: dict[int, BlockView] = field(default_factory=dict)
    insert_calls: list[tuple[int, int]] = field(default_factory=list)
    next_trampoline_serial: int = 999
    npred_after_insert: int = 1  # what successor_npred returns AFTER insertion

    def find_block_by_ea(self, ea):
        return self.block_at_ea.get(ea)

    def insert_trampoline_after(self, *, predecessor_serial, successor_serial):
        self.insert_calls.append((predecessor_serial, successor_serial))
        return self.next_trampoline_serial

    def successor_npred(self, successor_serial):
        return self.npred_after_insert


def test_isolate_invalid_byte_index_returns_no_op():
    res = isolate_byte_emit_tail(
        byte_index=99,
        fact_view=_FakeFactView(),
        adapter=_FakeAdapter(),
    )
    assert res.applied is False
    assert res.reason == "invalid_byte_index"


def test_isolate_no_fact_returns_no_op():
    res = isolate_byte_emit_tail(
        byte_index=2,
        fact_view=_FakeFactView(rows=[]),
        adapter=_FakeAdapter(),
    )
    assert res.applied is False
    assert res.reason == "no_fact"


def test_isolate_block_not_findable_returns_no_op():
    fv = _FakeFactView(rows=[_row(2, 5, ea="0x0000000180012DF0")])
    adapter = _FakeAdapter(block_at_ea={})  # nothing at that EA
    res = isolate_byte_emit_tail(
        byte_index=2, fact_view=fv, adapter=adapter,
    )
    assert res.applied is False
    assert res.reason == "block_not_resolvable_at_runtime"
    assert res.byte_emit_ea == 0x180012DF0
    assert adapter.insert_calls == []


def test_isolate_no_shared_tail_returns_no_op():
    fv = _FakeFactView(rows=[_row(2, 5, ea="0x0000000180012DF0")])
    adapter = _FakeAdapter(
        block_at_ea={0x180012DF0: _block(succ_npred=1)},
    )
    res = isolate_byte_emit_tail(
        byte_index=2, fact_view=fv, adapter=adapter,
    )
    assert res.applied is False
    assert res.reason == "no_shared_tail"
    assert adapter.insert_calls == []


def test_isolate_happy_path_inserts_trampoline_and_reports_npred_change():
    fv = _FakeFactView(rows=[_row(2, 5, ea="0x0000000180012DF0")])
    adapter = _FakeAdapter(
        block_at_ea={0x180012DF0: _block(nsucc=1, succ_serial=200, succ_npred=3)},
        next_trampoline_serial=999,
        npred_after_insert=3,  # original siblings still wired; pred replaced
    )
    res = isolate_byte_emit_tail(
        byte_index=2, fact_view=fv, adapter=adapter,
    )
    assert res.applied is True
    assert res.reason == "ok"
    assert res.byte_index == 2
    assert res.byte_emit_serial == 161
    assert res.trampoline_serial == 999
    assert res.successor_serial_before == 200
    assert res.successor_npred_before == 3
    assert res.successor_npred_after == 3
    assert adapter.insert_calls == [(161, 200)]


def test_isolate_malformed_ea_returns_no_op():
    fv = _FakeFactView(rows=[_row(2, 5, ea="not-a-hex")])
    res = isolate_byte_emit_tail(
        byte_index=2, fact_view=fv, adapter=_FakeAdapter(),
    )
    assert res.applied is False
    assert res.reason.startswith("malformed_ea:")
