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
    # split bookkeeping
    split_calls: list[int] = field(default_factory=list)
    next_split_serial: int = 888
    block_after_split: dict[int, BlockView] = field(default_factory=dict)
    split_should_raise: bool = False

    def find_block_by_ea(self, ea):
        # If a split has been recorded, prefer the post-split mapping.
        if self.split_calls and ea in self.block_after_split:
            return self.block_after_split[ea]
        return self.block_at_ea.get(ea)

    def insert_trampoline_after(self, *, predecessor_serial, successor_serial):
        self.insert_calls.append((predecessor_serial, successor_serial))
        return self.next_trampoline_serial

    def successor_npred(self, successor_serial):
        return self.npred_after_insert

    def split_block_at_tail_jcnd(self, block_serial):
        self.split_calls.append(block_serial)
        if self.split_should_raise:
            raise RuntimeError("simulated split failure")
        return self.next_split_serial


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


# ----- parse_tail_distinct_byte_env -----


def test_parse_tail_distinct_byte_env_unset_returns_none():
    from d810.cfg.transform.byte_emit_tail_isolation import (
        parse_tail_distinct_byte_env,
    )
    assert parse_tail_distinct_byte_env(None) is None
    assert parse_tail_distinct_byte_env("") is None


def test_parse_tail_distinct_byte_env_non_integer_returns_none():
    from d810.cfg.transform.byte_emit_tail_isolation import (
        parse_tail_distinct_byte_env,
    )
    assert parse_tail_distinct_byte_env("xyz") is None
    assert parse_tail_distinct_byte_env("2x") is None


def test_parse_tail_distinct_byte_env_out_of_range_returns_none():
    from d810.cfg.transform.byte_emit_tail_isolation import (
        parse_tail_distinct_byte_env,
    )
    assert parse_tail_distinct_byte_env("-1") is None
    assert parse_tail_distinct_byte_env("7") is None
    assert parse_tail_distinct_byte_env("99") is None


def test_parse_tail_distinct_byte_env_valid_returns_int():
    from d810.cfg.transform.byte_emit_tail_isolation import (
        parse_tail_distinct_byte_env,
    )
    for k in range(7):
        assert parse_tail_distinct_byte_env(str(k)) == k


def test_parse_tail_distinct_byte_env_strips_whitespace():
    from d810.cfg.transform.byte_emit_tail_isolation import (
        parse_tail_distinct_byte_env,
    )
    assert parse_tail_distinct_byte_env("  2  ") == 2


# ----- duplicate_convergence_for_byte_path orchestrator -----


from d810.cfg.transform.byte_emit_tail_isolation import (
    duplicate_convergence_for_byte_path,
)


@dataclass
class _FakeConvergenceAdapter(_FakeAdapter):
    has_m_stx: dict[int, bool] = field(default_factory=dict)
    forward_walk_result: tuple[int | None, str] = (None, "")
    clone_calls: list[tuple[int, int]] = field(default_factory=list)
    next_clone_serial: int = 777

    def block_has_m_stx(self, block_serial):
        return self.has_m_stx.get(block_serial, False)

    def forward_walk_until_convergence(self, start_serial, *, max_depth=8):
        return self.forward_walk_result

    def clone_convergence_for_byte_path(
        self, *, predecessor_serial, convergence_serial,
    ):
        self.clone_calls.append((predecessor_serial, convergence_serial))
        return self.next_clone_serial


def test_duplicate_convergence_byte6_happy_path_clones_and_reports():
    fv = _FakeFactView(rows=[_row(6, 5, ea="0x000000018001687C")])
    pre_block = BlockView(
        serial=217, start_ea=0x18001687C, nsucc=1,
        succ_serial=218, succ_npred=9, tail_kind="goto",
    )
    adapter = _FakeConvergenceAdapter(
        block_at_ea={0x18001687C: pre_block},
        has_m_stx={217: True},
        forward_walk_result=(218, "ok"),
        next_clone_serial=777,
    )
    res = duplicate_convergence_for_byte_path(
        byte_index=6, fact_view=fv, adapter=adapter,
    )
    assert res.applied is True
    assert res.reason == "ok"
    assert res.byte_index == 6
    assert res.byte_emit_serial == 217
    assert res.convergence_serial == 218
    assert res.clone_serial == 777
    assert adapter.clone_calls == [(217, 218)]


def test_duplicate_convergence_rejects_non_byte6():
    fv = _FakeFactView(rows=[_row(2, 5, ea="0x0000000180012DF0")])
    res = duplicate_convergence_for_byte_path(
        byte_index=2, fact_view=fv, adapter=_FakeConvergenceAdapter(),
    )
    assert res.applied is False
    assert res.reason == "probe_byte6_only"


def test_duplicate_convergence_rejects_no_fact():
    res = duplicate_convergence_for_byte_path(
        byte_index=6, fact_view=_FakeFactView(rows=[]),
        adapter=_FakeConvergenceAdapter(),
    )
    assert res.applied is False
    assert res.reason == "no_fact"


def test_duplicate_convergence_rejects_emit_block_lacks_m_stx():
    fv = _FakeFactView(rows=[_row(6, 5, ea="0x000000018001687C")])
    pre_block = BlockView(
        serial=217, start_ea=0x18001687C, nsucc=1,
        succ_serial=218, succ_npred=9, tail_kind="goto",
    )
    adapter = _FakeConvergenceAdapter(
        block_at_ea={0x18001687C: pre_block},
        has_m_stx={217: False},  # NO m_stx
        forward_walk_result=(218, "ok"),
    )
    res = duplicate_convergence_for_byte_path(
        byte_index=6, fact_view=fv, adapter=adapter,
    )
    assert res.applied is False
    assert res.reason == "no_m_stx_in_emit"
    assert adapter.clone_calls == []


def test_duplicate_convergence_rejects_no_convergence_in_walk():
    fv = _FakeFactView(rows=[_row(6, 5, ea="0x000000018001687C")])
    pre_block = BlockView(
        serial=217, start_ea=0x18001687C, nsucc=1,
        succ_serial=218, succ_npred=1, tail_kind="goto",
    )
    adapter = _FakeConvergenceAdapter(
        block_at_ea={0x18001687C: pre_block},
        has_m_stx={217: True},
        forward_walk_result=(None, "no_npred_gt_1_within_depth"),
    )
    res = duplicate_convergence_for_byte_path(
        byte_index=6, fact_view=fv, adapter=adapter,
    )
    assert res.applied is False
    assert res.reason == "no_npred_gt_1_within_depth"
    assert adapter.clone_calls == []


def test_duplicate_convergence_rejects_no_return_reachable():
    fv = _FakeFactView(rows=[_row(6, 5, ea="0x000000018001687C")])
    pre_block = BlockView(
        serial=217, start_ea=0x18001687C, nsucc=1,
        succ_serial=218, succ_npred=9, tail_kind="goto",
    )
    adapter = _FakeConvergenceAdapter(
        block_at_ea={0x18001687C: pre_block},
        has_m_stx={217: True},
        forward_walk_result=(None, "convergence_does_not_reach_return"),
    )
    res = duplicate_convergence_for_byte_path(
        byte_index=6, fact_view=fv, adapter=adapter,
    )
    assert res.applied is False
    assert res.reason == "convergence_does_not_reach_return"


def test_parse_tail_duplicate_convergence_byte_env_only_accepts_6():
    from d810.cfg.transform.byte_emit_tail_isolation import (
        parse_tail_duplicate_convergence_byte_env,
    )
    assert parse_tail_duplicate_convergence_byte_env("6") == 6
    assert parse_tail_duplicate_convergence_byte_env("0") is None
    assert parse_tail_duplicate_convergence_byte_env("2") is None
    assert parse_tail_duplicate_convergence_byte_env("") is None
    assert parse_tail_duplicate_convergence_byte_env(None) is None
    assert parse_tail_duplicate_convergence_byte_env("xyz") is None
