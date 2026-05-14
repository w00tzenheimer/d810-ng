"""System tests for Hex-Rays byte-tail materialization adapter helpers."""
from __future__ import annotations

from dataclasses import dataclass, field


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
class _FakeBlockView:
    serial: int


@dataclass
class _FakeBridgeAdapter:
    """Maps snapshot EA to live serial via a dict."""

    ea_to_live: dict[int, int] = field(default_factory=dict)

    def find_block_by_ea(self, ea):
        live = self.ea_to_live.get(int(ea))
        if live is None:
            return None
        return _FakeBlockView(serial=int(live))


@dataclass
class _FakeDiagConn:
    """Canned cursor for the (snapshot_id, serial) -> start_ea_i64 query."""

    rows_by_serial: dict[int, int | None] = field(default_factory=dict)

    def execute(self, sql, params):
        snap_id, serial = params  # noqa: F841 -- snap_id intentionally unused
        return _FakeCursor(self.rows_by_serial.get(int(serial)))


class _FakeCursor:
    def __init__(self, ea_value):
        self._ea = ea_value

    def fetchone(self):
        if self._ea is None:
            return None
        return (int(self._ea),)


class _SilentLogger:
    def info(self, *args, **kwargs):  # noqa: D401 -- swallow
        pass


@dataclass
class _FakeLiveBlock:
    succs: tuple[int, ...] = ()

    def nsucc(self):
        return len(self.succs)

    def succ(self, index):
        return self.succs[int(index)]


@dataclass
class _FakeLiveMba:
    blocks: dict[int, _FakeLiveBlock] = field(default_factory=dict)

    def get_mblock(self, serial):
        return self.blocks.get(int(serial))


@dataclass
class _FakeLiveAdapter:
    _mba: _FakeLiveMba


def test_bridge_plan_row_happy_path_maps_all_fields():
    from d810.hexrays.mutation.byte_emit_tail_isolation_runtime import (
        _bridge_plan_row_to_live_mba,
    )

    row = _FakePlanRow(
        source_block=101,
        current_continuation_target=102,
        intended_target=217,
        state_write_block=180,
        state_write_bypassed=True,
    )
    conn = _FakeDiagConn(rows_by_serial={
        101: 0x1800_1000,
        102: 0x1800_2000,
        217: 0x1800_3000,
        180: 0x1800_4000,
    })
    adapter = _FakeBridgeAdapter(ea_to_live={
        0x1800_1000: 11,
        0x1800_2000: 22,
        0x1800_3000: 33,
        0x1800_4000: 44,
    })

    mapped, reason = _bridge_plan_row_to_live_mba(
        row,
        diag_conn=conn,
        snap17_id=17,
        adapter=adapter,
        logger_=_SilentLogger(),
    )

    assert reason == "ok"
    assert mapped is not None
    assert mapped.source_block == 11
    assert mapped.current_continuation_target == 22
    assert mapped.intended_target == 33
    assert mapped.state_write_block == 44
    assert mapped.byte_index == 5
    assert mapped.early_return_target == 42
    assert mapped.state_update_verdict == "SAFE_TARGET_POST_GUARD"
    assert mapped.state_write_bypassed is True


def test_bridge_plan_row_identity_mode_uses_live_serials():
    from d810.hexrays.mutation.byte_emit_tail_isolation_runtime import (
        _bridge_plan_row_to_live_mba,
    )

    row = _FakePlanRow(
        source_block=101,
        current_continuation_target=102,
        intended_target=217,
        state_write_block=180,
        state_write_bypassed=True,
    )
    adapter = _FakeLiveAdapter(
        _FakeLiveMba(
            blocks={
                101: _FakeLiveBlock(succs=(102,)),
                102: _FakeLiveBlock(),
                180: _FakeLiveBlock(),
                217: _FakeLiveBlock(),
            }
        )
    )

    mapped, reason = _bridge_plan_row_to_live_mba(
        row,
        diag_conn=None,
        snap17_id=None,
        adapter=adapter,
        logger_=_SilentLogger(),
    )

    assert reason == "ok"
    assert mapped is not None
    assert mapped.source_block == 101
    assert mapped.current_continuation_target == 102
    assert mapped.intended_target == 217
    assert mapped.state_write_block == 180


def test_load_planner_sites_from_fact_view_uses_observation_source_block():
    from d810.hexrays.mutation.byte_emit_tail_isolation_runtime import (
        _load_planner_sites_from_fact_view,
    )
    from d810.recon.facts.model import FactObservation, ValidatedFactView

    obs = FactObservation(
        fact_id="terminal-byte-2",
        kind="TerminalByteEmitterFact",
        semantic_key="terminal:2",
        maturity="MMAT_GLBOPT1",
        phase="post_bundle_stabilize",
        confidence=0.9,
        source_block=118,
        source_ea=0x180015005,
        payload={
            "byte_index": 2,
            "corridor_role": "terminal_tail",
            "emitter_role": "memory_store",
            "source_byte_expression": "xdu.8([ds.2:(%var_190.8+#2.8)].1)",
            "destination_buffer_expression": "[ds.2:%var_178]",
        },
    )

    sites = _load_planner_sites_from_fact_view(
        ValidatedFactView(maturity="MMAT_GLBOPT1", observations=(obs,))
    )

    assert len(sites) == 1
    assert sites[0].byte_index == 2
    assert sites[0].block_serial == 118


def test_bridge_plan_row_rejects_when_source_block_missing_from_snap17():
    from d810.hexrays.mutation.byte_emit_tail_isolation_runtime import (
        _bridge_plan_row_to_live_mba,
    )

    row = _FakePlanRow(
        source_block=101,
        current_continuation_target=102,
        intended_target=217,
    )
    conn = _FakeDiagConn(rows_by_serial={
        102: 0x1800_2000,
        217: 0x1800_3000,
    })
    adapter = _FakeBridgeAdapter(ea_to_live={
        0x1800_2000: 22,
        0x1800_3000: 33,
    })

    mapped, reason = _bridge_plan_row_to_live_mba(
        row,
        diag_conn=conn,
        snap17_id=17,
        adapter=adapter,
        logger_=_SilentLogger(),
    )

    assert mapped is None
    assert reason == "live_block_not_resolvable:source_block:101:no_snap17_row"


def test_bridge_plan_row_rejects_when_continuation_ea_not_in_live_mba():
    from d810.hexrays.mutation.byte_emit_tail_isolation_runtime import (
        _bridge_plan_row_to_live_mba,
    )

    row = _FakePlanRow(
        source_block=101,
        current_continuation_target=102,
        intended_target=217,
    )
    conn = _FakeDiagConn(rows_by_serial={
        101: 0x1800_1000,
        102: 0x1800_2000,
        217: 0x1800_3000,
    })
    adapter = _FakeBridgeAdapter(ea_to_live={
        0x1800_1000: 11,
        0x1800_3000: 33,
    })

    mapped, reason = _bridge_plan_row_to_live_mba(
        row,
        diag_conn=conn,
        snap17_id=17,
        adapter=adapter,
        logger_=_SilentLogger(),
    )

    assert mapped is None
    assert reason == (
        "live_block_not_resolvable:current_continuation_target:102:"
        "ea_0x18002000_not_in_live_mba"
    )


def test_bridge_plan_row_rejects_when_intended_target_ea_missing():
    from d810.hexrays.mutation.byte_emit_tail_isolation_runtime import (
        _bridge_plan_row_to_live_mba,
    )

    row = _FakePlanRow(
        source_block=101,
        current_continuation_target=102,
        intended_target=217,
    )
    conn = _FakeDiagConn(rows_by_serial={
        101: 0x1800_1000,
        102: 0x1800_2000,
    })
    adapter = _FakeBridgeAdapter(ea_to_live={
        0x1800_1000: 11,
        0x1800_2000: 22,
    })

    mapped, reason = _bridge_plan_row_to_live_mba(
        row,
        diag_conn=conn,
        snap17_id=17,
        adapter=adapter,
        logger_=_SilentLogger(),
    )

    assert mapped is None
    assert reason == "live_block_not_resolvable:intended_target:217:no_snap17_row"


def test_bridge_plan_row_skips_state_write_when_not_bypassed():
    from d810.hexrays.mutation.byte_emit_tail_isolation_runtime import (
        _bridge_plan_row_to_live_mba,
    )

    row = _FakePlanRow(
        source_block=101,
        current_continuation_target=102,
        intended_target=217,
        state_write_bypassed=False,
        state_write_block=180,
    )
    conn = _FakeDiagConn(rows_by_serial={
        101: 0x1800_1000,
        102: 0x1800_2000,
        217: 0x1800_3000,
    })
    adapter = _FakeBridgeAdapter(ea_to_live={
        0x1800_1000: 11,
        0x1800_2000: 22,
        0x1800_3000: 33,
    })

    mapped, reason = _bridge_plan_row_to_live_mba(
        row,
        diag_conn=conn,
        snap17_id=17,
        adapter=adapter,
        logger_=_SilentLogger(),
    )

    assert reason == "ok"
    assert mapped is not None
    assert mapped.source_block == 11
    assert mapped.current_continuation_target == 22
    assert mapped.intended_target == 33
    assert mapped.state_write_block == 180


def test_bridge_plan_row_requires_state_write_when_bypassed():
    from d810.hexrays.mutation.byte_emit_tail_isolation_runtime import (
        _bridge_plan_row_to_live_mba,
    )

    row = _FakePlanRow(
        source_block=101,
        current_continuation_target=102,
        intended_target=217,
        state_write_bypassed=True,
        state_write_block=None,
    )
    conn = _FakeDiagConn(rows_by_serial={
        101: 0x1800_1000,
        102: 0x1800_2000,
        217: 0x1800_3000,
    })
    adapter = _FakeBridgeAdapter(ea_to_live={
        0x1800_1000: 11,
        0x1800_2000: 22,
        0x1800_3000: 33,
    })

    mapped, reason = _bridge_plan_row_to_live_mba(
        row,
        diag_conn=conn,
        snap17_id=17,
        adapter=adapter,
        logger_=_SilentLogger(),
    )

    assert mapped is None
    assert reason == (
        "live_block_not_resolvable:state_write_block:None:required_when_bypassed"
    )


def test_select_terminal_tail_entry_live_uses_fact_backed_prep_block():
    from d810.cfg.terminal_tail_cascade_egress_planner import (
        TerminalByteEmitSite,
        TerminalTailBlock,
    )
    from d810.hexrays.mutation.byte_emit_tail_isolation_runtime import (
        _select_terminal_tail_entry_live,
    )

    blocks = {
        130: TerminalTailBlock(
            serial=130,
            succs=(143,),
            type_name="BLT_1WAY",
            insn_opcodes=("m_call", "m_goto"),
            insn_text=("call   $0x180000000", "goto   @143"),
        ),
        135: TerminalTailBlock(
            serial=135,
            succs=(136, 143),
            type_name="BLT_2WAY",
            insn_opcodes=("m_jnz",),
            insn_text=("jnz    %var_7BC.4, #0x139F2922.4, @143",),
        ),
        143: TerminalTailBlock(
            serial=143,
            preds=(130, 135),
            succs=(144, 145),
            type_name="BLT_2WAY",
            insn_opcodes=("m_call", "m_add", "m_stx", "m_jnz"),
            insn_text=(
                "call   $0x180000000",
                "add    %var_218.8, #0x80.8, %var_330.8",
                "stx    #0x80.8, ds.2, %var_178.8",
                "jnz    %var_320.8, #1.8, @145",
            ),
        ),
    }
    sites = (
        TerminalByteEmitSite(
            byte_index=1,
            block_serial=143,
            opcode="m_stx",
            emitter_role="memory_store",
            corridor_role="terminal_tail",
            continuation_edge=145,
            return_edge=144,
            confidence=0.8,
        ),
    )
    conn = _FakeDiagConn(rows_by_serial={
        130: 0x1800_51C8,
        143: 0x1800_5FB8,
    })
    adapter = _FakeBridgeAdapter(ea_to_live={
        0x1800_51C8: 80,
        0x1800_5FB8: 43,
    })

    live, reason = _select_terminal_tail_entry_live(
        blocks=blocks,
        sites=sites,
        rows_by_byte={},
        diag_conn=conn,
        target_snap=17,
        adapter=adapter,
    )

    assert reason == "ok"
    assert live == 80


def test_close_terminal_tail_entry_frontier_applies_when_entry_is_reachable(monkeypatch):
    import d810.hexrays.mutation.byte_emit_tail_isolation_runtime as runtime
    from d810.cfg.terminal_tail_cascade_egress_planner import (
        TerminalByteEmitSite,
        TerminalTailBlock,
    )

    blocks = {
        130: TerminalTailBlock(
            serial=130,
            succs=(143,),
            type_name="BLT_1WAY",
            insn_opcodes=("m_call", "m_goto"),
            insn_text=("call   $0x180000000", "goto   @143"),
        ),
        143: TerminalTailBlock(
            serial=143,
            preds=(130,),
            succs=(144, 145),
            type_name="BLT_2WAY",
            insn_opcodes=("m_stx", "m_jnz"),
            insn_text=("stx    #0x80.8, ds.2, %var_178.8", "jnz @145"),
        ),
    }
    sites = (
        TerminalByteEmitSite(
            byte_index=1,
            block_serial=143,
            opcode="m_stx",
            emitter_role="memory_store",
            corridor_role="terminal_tail",
            continuation_edge=145,
            return_edge=144,
            confidence=0.8,
        ),
    )
    dag = runtime._DagSemantics(
        snapshot_id=7,
        state_to_scc={0x2315233C: 8},
        scc_reachable={8: frozenset({8})},
        block_to_sccs={
            139: frozenset({4}),
            141: frozenset({4}),
            130: frozenset({8}),
        },
        scc_successors={8: frozenset()},
        edges=(
            runtime._DagEdge(
                edge_id=58,
                source_state=0x139F2922,
                target_state=0x2315233C,
                edge_kind="CONDITIONAL_TRANSITION",
                source_block=139,
                source_arm=1,
                target_entry=211,
                ordered_path=(136, 137, 139, 141),
            ),
        ),
    )
    conn = _FakeDiagConn(rows_by_serial={
        130: 0x1800_51C8,
        139: 0x1800_5F20,
    })

    @dataclass
    class _Adapter:
        ea_to_live: dict[int, int]
        redirects: list[tuple[int, int, int]] = field(default_factory=list)

        def find_block_by_ea(self, ea):
            live = self.ea_to_live.get(int(ea))
            if live is None:
                return None
            return _FakeBlockView(serial=int(live))

        def redirect_advance_edge(
            self, *, source_serial, old_target_serial, new_target_serial,
        ):
            self.redirects.append(
                (int(source_serial), int(old_target_serial), int(new_target_serial))
            )

    adapter = _Adapter(ea_to_live={0x1800_51C8: 130, 0x1800_5F20: 139})
    monkeypatch.setattr(
        runtime,
        "_live_reachable_from_entry",
        lambda adapter: frozenset({0, 139, 130}),
    )
    monkeypatch.setattr(
        runtime,
        "_live_successor_map",
        lambda adapter: {139: (140, 141), 141: (211,), 130: (143,)},
    )
    monkeypatch.setattr(
        runtime,
        "_map_snap_successor_to_live",
        lambda **kwargs: (141, "ok"),
    )
    monkeypatch.setattr(
        runtime,
        "_frontier_for_terminal_arm",
        lambda **kwargs: (141, 211, "state_frontier"),
    )
    monkeypatch.setattr(
        runtime,
        "_first_cyclic_scc_reachable",
        lambda **kwargs: object(),
    )
    monkeypatch.setattr(
        runtime,
        "_cfg_scc_is_illegal_from_dag_sources",
        lambda **kwargs: True,
    )

    applied, skipped = runtime._close_terminal_tail_entry_frontier(
        rows_by_byte={},
        blocks=blocks,
        sites=sites,
        dag=dag,
        diag_conn=conn,
        target_snap=17,
        adapter=adapter,
    )

    assert skipped == ()
    assert applied == ((141, 211, 130),)
    assert adapter.redirects == [(141, 211, 130)]
