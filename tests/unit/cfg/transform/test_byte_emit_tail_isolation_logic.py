"""Unit tests for byte_emit_tail_isolation pure helpers.

No IDA imports. The orchestrator is exercised via a fake adapter.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from d810.transforms.byte_emit_tail_isolation import (
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
    from d810.transforms.byte_emit_tail_isolation import (
        parse_tail_distinct_byte_env,
    )
    assert parse_tail_distinct_byte_env(None) is None
    assert parse_tail_distinct_byte_env("") is None


def test_parse_tail_distinct_byte_env_non_integer_returns_none():
    from d810.transforms.byte_emit_tail_isolation import (
        parse_tail_distinct_byte_env,
    )
    assert parse_tail_distinct_byte_env("xyz") is None
    assert parse_tail_distinct_byte_env("2x") is None


def test_parse_tail_distinct_byte_env_out_of_range_returns_none():
    from d810.transforms.byte_emit_tail_isolation import (
        parse_tail_distinct_byte_env,
    )
    assert parse_tail_distinct_byte_env("-1") is None
    assert parse_tail_distinct_byte_env("7") is None
    assert parse_tail_distinct_byte_env("99") is None


def test_parse_tail_distinct_byte_env_valid_returns_int():
    from d810.transforms.byte_emit_tail_isolation import (
        parse_tail_distinct_byte_env,
    )
    for k in range(7):
        assert parse_tail_distinct_byte_env(str(k)) == k


def test_parse_tail_distinct_byte_env_strips_whitespace():
    from d810.transforms.byte_emit_tail_isolation import (
        parse_tail_distinct_byte_env,
    )
    assert parse_tail_distinct_byte_env("  2  ") == 2


# ----- duplicate_convergence_for_byte_path orchestrator -----


from d810.transforms.byte_emit_tail_isolation import (
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
    from d810.transforms.byte_emit_tail_isolation import (
        parse_tail_duplicate_convergence_byte_env,
    )
    assert parse_tail_duplicate_convergence_byte_env("6") == 6
    assert parse_tail_duplicate_convergence_byte_env("0") is None
    assert parse_tail_duplicate_convergence_byte_env("2") is None
    assert parse_tail_duplicate_convergence_byte_env("") is None
    assert parse_tail_duplicate_convergence_byte_env(None) is None
    assert parse_tail_duplicate_convergence_byte_env("xyz") is None


# ----- parse_state_cascade_pair_env -----


from d810.transforms.byte_emit_tail_isolation import (
    StateCascadeReport,
    execute_state_cascade,
    execute_terminal_tail_cascade_egress_lowering,
    parse_state_cascade_pair_env,
)


def test_parse_state_cascade_pair_env_only_accepts_5_6():
    assert parse_state_cascade_pair_env("5:6") == (5, 6)
    assert parse_state_cascade_pair_env("  5:6  ") == (5, 6)
    assert parse_state_cascade_pair_env(None) is None
    assert parse_state_cascade_pair_env("") is None
    assert parse_state_cascade_pair_env("0:1") is None
    assert parse_state_cascade_pair_env("5") is None
    assert parse_state_cascade_pair_env("5:7") is None
    assert parse_state_cascade_pair_env("6:5") is None
    assert parse_state_cascade_pair_env("xyz") is None


# ----- execute_state_cascade -----


@dataclass
class _FakePlanRow:
    """Minimal duck-type for TerminalTailCascadeEgressRow."""

    byte_index: int = 5
    source_block: int | None = 161
    current_continuation_target: int | None = 200
    intended_target: int | None = 217
    early_return_target: int | None = 42
    current_convergence_target: int | None = 200
    state_variable: str | None = "%var_198"
    state_required_value: int | None = 5
    state_write_block: int | None = None
    state_write_path: tuple[int, ...] = ()
    state_write_bypassed: bool = False
    state_update_verdict: str = "SAFE_TARGET_POST_GUARD"
    confidence: float = 0.9
    reason: str = "complete_cascade_egress_candidate"
    preserves_early_return: bool = True


@dataclass
class _FakeStateCascadeAdapter:
    clone_calls: list[tuple[int, int]] = field(default_factory=list)
    redirect_calls: list[tuple[int, int, int]] = field(default_factory=list)
    next_clone_serial: int = 555

    def clone_state_write_block(self, *, template_serial, tail_goto_target):
        self.clone_calls.append((template_serial, tail_goto_target))
        return self.next_clone_serial

    def redirect_advance_edge(
        self, *, source_serial, old_target_serial, new_target_serial,
    ):
        self.redirect_calls.append(
            (source_serial, old_target_serial, new_target_serial)
        )


def test_execute_state_cascade_rejects_non_5_6_pair():
    res = execute_state_cascade(
        pair=(0, 1),
        plan_row=_FakePlanRow(),
        adapter=_FakeStateCascadeAdapter(),
    )
    assert res.applied is False
    assert res.reason == "probe_5_6_only"
    assert res.pair == ""


def test_execute_state_cascade_rejects_when_verdict_not_safe():
    row = _FakePlanRow(state_update_verdict="AMBIGUOUS_STATE_UPDATE")
    adapter = _FakeStateCascadeAdapter()
    res = execute_state_cascade(pair=(5, 6), plan_row=row, adapter=adapter)
    assert res.applied is False
    assert res.reason == "planner_verdict_not_safe:AMBIGUOUS_STATE_UPDATE"
    assert adapter.redirect_calls == []
    assert adapter.clone_calls == []


def test_execute_state_cascade_rejects_when_source_block_none():
    row = _FakePlanRow(source_block=None)
    adapter = _FakeStateCascadeAdapter()
    res = execute_state_cascade(pair=(5, 6), plan_row=row, adapter=adapter)
    assert res.applied is False
    assert res.reason == "planner_row_missing_source_block"
    assert adapter.redirect_calls == []

def test_execute_state_cascade_rejects_when_intended_target_none():
    row = _FakePlanRow(intended_target=None)
    adapter = _FakeStateCascadeAdapter()
    res = execute_state_cascade(pair=(5, 6), plan_row=row, adapter=adapter)
    assert res.applied is False
    assert res.reason == "planner_row_missing_intended_target"
    assert adapter.redirect_calls == []


def test_execute_state_cascade_rejects_when_continuation_none():
    row = _FakePlanRow(current_continuation_target=None)
    adapter = _FakeStateCascadeAdapter()
    res = execute_state_cascade(pair=(5, 6), plan_row=row, adapter=adapter)
    assert res.applied is False
    assert res.reason == "planner_row_missing_current_continuation"
    assert adapter.redirect_calls == []


def test_execute_state_cascade_rejects_when_byte_index_not_5():
    row = _FakePlanRow(byte_index=4)
    adapter = _FakeStateCascadeAdapter()
    res = execute_state_cascade(pair=(5, 6), plan_row=row, adapter=adapter)
    assert res.applied is False
    assert res.reason == "planner_row_not_byte5"


def test_execute_state_cascade_happy_path_no_clone_when_not_bypassed():
    row = _FakePlanRow(
        source_block=161,
        current_continuation_target=200,
        intended_target=217,
        early_return_target=42,
        state_write_bypassed=False,
        state_write_block=180,  # present but not bypassed -> no clone
    )
    adapter = _FakeStateCascadeAdapter()
    res = execute_state_cascade(pair=(5, 6), plan_row=row, adapter=adapter)
    assert res.applied is True
    assert res.reason == "ok"
    assert res.pair == "5:6"
    assert res.proof == "SAFE_TARGET_POST_GUARD"
    assert res.source_byte_block == 161
    assert res.old_advance_target == 200
    assert res.post_guard_target == 217
    assert res.state_write_block_cloned is None
    assert res.preserved_early_return_target == 42
    assert adapter.clone_calls == []
    assert adapter.redirect_calls == [(161, 200, 217)]


def test_execute_state_cascade_happy_path_clones_when_bypassed():
    row = _FakePlanRow(
        source_block=161,
        current_continuation_target=200,
        intended_target=217,
        early_return_target=42,
        state_write_block=180,
        state_write_bypassed=True,
        state_write_path=(200, 201, 217),
    )
    adapter = _FakeStateCascadeAdapter(next_clone_serial=555)
    res = execute_state_cascade(pair=(5, 6), plan_row=row, adapter=adapter)
    assert res.applied is True
    assert res.reason == "ok"
    assert res.state_write_block_cloned == 555
    assert res.skipped_guard_blocks == (200, 201, 217)
    # Clone receives template=180, tail_goto_target=intended_target (217).
    assert adapter.clone_calls == [(180, 217)]
    # Advance edge points at the clone, NOT directly at intended_target.
    assert adapter.redirect_calls == [(161, 200, 555)]


def test_execute_state_cascade_no_clone_when_bypassed_but_no_state_write_block():
    row = _FakePlanRow(
        source_block=161,
        current_continuation_target=200,
        intended_target=217,
        state_write_bypassed=True,
        state_write_block=None,  # no template available -> no clone, fall through
    )
    adapter = _FakeStateCascadeAdapter()
    res = execute_state_cascade(pair=(5, 6), plan_row=row, adapter=adapter)
    assert res.applied is True
    assert res.state_write_block_cloned is None
    assert adapter.clone_calls == []
    assert adapter.redirect_calls == [(161, 200, 217)]


# ----- execute_terminal_tail_cascade_egress_lowering -----


def test_execute_terminal_tail_cascade_egress_lowers_safe_rows():
    row = _FakePlanRow(
        byte_index=2,
        source_block=118,
        current_continuation_target=120,
        intended_target=161,
        early_return_target=119,
        state_update_verdict="SAFE_TARGET_POST_GUARD",
    )
    adapter = _FakeStateCascadeAdapter()

    res = execute_terminal_tail_cascade_egress_lowering(
        plan_rows=(row,),
        adapter=adapter,
        byte_indices=(2,),
        split_byte_indices=(),
    )

    assert res.applied is True
    assert res.applied_rows == (2,)
    assert adapter.redirect_calls == [(118, 120, 161)]
    assert adapter.clone_calls == []


def test_execute_terminal_tail_cascade_egress_rejects_unproven_state_write():
    row = _FakePlanRow(
        byte_index=4,
        source_block=163,
        current_continuation_target=165,
        intended_target=101,
        state_update_verdict="NEEDS_STATE_WRITE",
        state_write_bypassed=True,
        state_write_block=None,
    )
    adapter = _FakeStateCascadeAdapter()

    res = execute_terminal_tail_cascade_egress_lowering(
        plan_rows=(row,),
        adapter=adapter,
        byte_indices=(4,),
        split_byte_indices=(),
    )

    assert res.applied is False
    assert res.skipped_rows == ("byte4:planner_needs_state_write_without_template",)
    assert adapter.redirect_calls == []
    assert adapter.clone_calls == []


def test_execute_terminal_tail_cascade_egress_clones_proven_state_write():
    row = _FakePlanRow(
        byte_index=4,
        source_block=163,
        current_continuation_target=165,
        intended_target=101,
        state_update_verdict="NEEDS_STATE_WRITE",
        state_write_bypassed=True,
        state_write_block=164,
    )
    adapter = _FakeStateCascadeAdapter(next_clone_serial=777)

    res = execute_terminal_tail_cascade_egress_lowering(
        plan_rows=(row,),
        adapter=adapter,
        byte_indices=(4,),
        split_byte_indices=(),
    )

    assert res.applied is True
    assert res.cloned_state_write_blocks == (777,)
    assert adapter.clone_calls == [(164, 101)]
    assert adapter.redirect_calls == [(163, 165, 777)]


def test_execute_terminal_tail_cascade_egress_splits_same_block_row():
    row = _FakePlanRow(
        byte_index=3,
        source_block=163,
        current_continuation_target=165,
        intended_target=163,
    )

    @dataclass
    class _SplitAdapter(_FakeStateCascadeAdapter):
        split_calls: list[int] = field(default_factory=list)

        def split_block_at_tail_jcnd(self, block_serial):
            self.split_calls.append(block_serial)
            return 999

    adapter = _SplitAdapter()

    res = execute_terminal_tail_cascade_egress_lowering(
        plan_rows=(row,),
        adapter=adapter,
        byte_indices=(),
        split_byte_indices=(3,),
    )

    assert res.applied is True
    assert res.applied_rows == (3,)
    assert res.split_blocks == (999,)
    assert adapter.split_calls == [163]
    assert adapter.redirect_calls == []
