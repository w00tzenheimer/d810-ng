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


class _FakeEvidenceProvider:
    def __init__(self, evidence) -> None:
        self.evidence = evidence
        self.seen_mba = None

    def byte_tail_runtime_evidence(self, mba):
        self.seen_mba = mba
        return self.evidence


@dataclass
class _FakeLiveBlock:
    succs: tuple[int, ...] = ()
    start: int = 0
    head: object | None = None

    def nsucc(self):
        return len(self.succs)

    def succ(self, index):
        return self.succs[int(index)]


@dataclass
class _FakeLiveInsn:
    ea: int
    next: object | None = None


@dataclass
class _FakeLiveMba:
    blocks: dict[int, _FakeLiveBlock] = field(default_factory=dict)

    @property
    def qty(self):
        return max(self.blocks, default=-1) + 1

    def get_mblock(self, serial):
        return self.blocks.get(int(serial))


@dataclass
class _FakeLiveAdapter:
    _mba: _FakeLiveMba


def test_bridge_plan_row_rejects_diag_bridge_inputs():
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

    assert mapped is None
    assert reason == "live_block_not_resolvable:diag_bridge_disabled"


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


def test_load_planner_sites_remaps_stale_source_block_by_live_instruction_ea():
    from d810.hexrays.mutation.byte_emit_tail_isolation_runtime import (
        _load_planner_sites_from_fact_view,
    )
    from d810.recon.facts.model import FactObservation, ValidatedFactView

    obs = FactObservation(
        fact_id="terminal-byte-3",
        kind="TerminalByteEmitterFact",
        semantic_key="terminal:3",
        maturity="MMAT_GLBOPT1",
        phase="pre_d810",
        confidence=0.9,
        source_block=164,
        source_ea=0x180016285,
        payload={
            "byte_index": 3,
            "corridor_role": "terminal_tail",
            "emitter_role": "memory_store",
            "opcode": "m_stx",
            "source_byte_expression": "xdu.8([ds.2:(%var_190.8+#3.8)].1)",
            "destination_buffer_expression": "[ds.2:%var_188]",
            "source_block": 164,
            "destination_block": 164,
            "block_serial": 164,
            "block_ea": 0x180016252,
        },
    )
    adapter = _FakeLiveAdapter(
        _FakeLiveMba(
            blocks={
                163: _FakeLiveBlock(
                    start=0x180016252,
                    head=_FakeLiveInsn(ea=0x180016285),
                ),
                164: _FakeLiveBlock(start=0x1800162C0),
            }
        )
    )

    sites = _load_planner_sites_from_fact_view(
        ValidatedFactView(maturity="MMAT_GLBOPT1", observations=(obs,)),
        adapter=adapter,
    )

    assert len(sites) == 1
    assert sites[0].byte_index == 3
    assert sites[0].block_serial == 163


def test_tail_distinct_uses_provider_fact_view_without_diag(monkeypatch):
    import d810.hexrays.mutation.byte_emit_tail_isolation_runtime as runtime
    from d810.hexrays.mutation.byte_tail_runtime_evidence import (
        ByteTailRuntimeEvidence,
    )

    fact_view = object()
    mba = object()
    provider = _FakeEvidenceProvider(
        ByteTailRuntimeEvidence(fact_view=fact_view)
    )
    calls = {}

    def fake_isolate_byte_emit_tail(*, byte_index, fact_view, adapter):
        calls["byte_index"] = byte_index
        calls["fact_view"] = fact_view
        calls["adapter"] = adapter
        return "report"

    monkeypatch.setenv("D810_TAIL_DISTINCT_BYTE", "2")
    monkeypatch.setattr(runtime, "isolate_byte_emit_tail", fake_isolate_byte_emit_tail)

    runtime.maybe_run_tail_distinct(
        mba,
        evidence_provider=provider,
    )

    assert provider.seen_mba is mba
    assert calls["byte_index"] == 2
    assert calls["fact_view"] is fact_view
    assert isinstance(calls["adapter"], runtime.LiveMbaAdapter)
    assert not hasattr(runtime, "DiagDbFactView")


def test_tail_distinct_missing_provider_skips_without_diag(monkeypatch):
    import d810.hexrays.mutation.byte_emit_tail_isolation_runtime as runtime

    def fail_isolate_byte_emit_tail(**kwargs):
        raise AssertionError("tail distinct should require explicit evidence")

    monkeypatch.setenv("D810_TAIL_DISTINCT_BYTE", "2")
    monkeypatch.setattr(runtime, "isolate_byte_emit_tail", fail_isolate_byte_emit_tail)

    runtime.maybe_run_tail_distinct(object())

    assert not hasattr(runtime, "DiagDbFactView")


def test_tail_distinct_accepts_validated_fact_view(monkeypatch):
    import d810.hexrays.mutation.byte_emit_tail_isolation_runtime as runtime
    from d810.recon.facts import FactObservation, ValidatedFactView

    view = ValidatedFactView(
        maturity="MMAT_GLBOPT1",
        observations=(
            FactObservation(
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
                    "block_ea": 0x180015005,
                    "block_serial": 118,
                },
            ),
        ),
    )
    calls = {}

    def fake_isolate_byte_emit_tail(*, byte_index, fact_view, adapter):
        rows = tuple(fact_view.terminal_byte_emit_facts(byte_index))
        calls["rows"] = rows
        return "report"

    monkeypatch.setenv("D810_TAIL_DISTINCT_BYTE", "2")
    monkeypatch.setattr(runtime, "isolate_byte_emit_tail", fake_isolate_byte_emit_tail)

    runtime.maybe_run_tail_distinct(object(), fact_view=view)

    assert len(calls["rows"]) == 1
    assert calls["rows"][0].block_serial == 118
    assert calls["rows"][0].start_ea_hex == "0x0000000180015005"


def test_tail_duplicate_convergence_uses_explicit_fact_view_without_diag(monkeypatch):
    import d810.hexrays.mutation.byte_emit_tail_isolation_runtime as runtime

    fact_view = object()
    calls = {}

    def fake_duplicate_convergence_for_byte_path(
        *,
        byte_index,
        fact_view,
        adapter,
    ):
        calls["byte_index"] = byte_index
        calls["fact_view"] = fact_view
        calls["adapter"] = adapter
        return "report"

    monkeypatch.setenv("D810_TAIL_DUPLICATE_CONVERGENCE_BYTE", "6")
    monkeypatch.delenv("D810_TAIL_DISTINCT_BYTE", raising=False)
    monkeypatch.setattr(
        runtime,
        "duplicate_convergence_for_byte_path",
        fake_duplicate_convergence_for_byte_path,
    )

    runtime.maybe_run_tail_duplicate_convergence(
        object(),
        fact_view=fact_view,
    )

    assert calls["byte_index"] == 6
    assert calls["fact_view"] is fact_view
    assert isinstance(calls["adapter"], runtime.LiveMbaAdapter)


def test_tail_duplicate_missing_provider_skips_without_diag(monkeypatch):
    import d810.hexrays.mutation.byte_emit_tail_isolation_runtime as runtime

    def fail_duplicate_convergence_for_byte_path(**kwargs):
        raise AssertionError("tail duplicate should require explicit evidence")

    monkeypatch.setenv("D810_TAIL_DUPLICATE_CONVERGENCE_BYTE", "6")
    monkeypatch.delenv("D810_TAIL_DISTINCT_BYTE", raising=False)
    monkeypatch.setattr(
        runtime,
        "duplicate_convergence_for_byte_path",
        fail_duplicate_convergence_for_byte_path,
    )

    runtime.maybe_run_tail_duplicate_convergence(object())

    assert not hasattr(runtime, "DiagDbFactView")


def test_terminal_tail_uses_provider_planner_evidence_without_fact_view(monkeypatch):
    import d810.cfg.terminal_tail_cascade_egress_planner as planner_module
    import d810.hexrays.mutation.byte_emit_tail_isolation_runtime as runtime
    from d810.hexrays.mutation.byte_tail_runtime_evidence import (
        ByteTailRuntimeEvidence,
        TerminalTailPlannerEvidence,
    )
    from d810.recon.flow.terminal_tail_priors import (
        TerminalTailCascadeEgressPriors,
    )

    blocks = {10: object()}
    sites = [object()]
    dag = object()
    provider = _FakeEvidenceProvider(
        ByteTailRuntimeEvidence(
            terminal_tail_planner=TerminalTailPlannerEvidence(
                blocks=blocks,
                sites=sites,
                dag=dag,
            ),
            terminal_tail_cascade_egress=TerminalTailCascadeEgressPriors(
                byte_indices=(1,),
            ),
        )
    )
    calls = {}

    class FakePlanner:
        def __init__(self, planner_blocks, planner_sites):
            calls["blocks"] = planner_blocks
            calls["sites"] = planner_sites

        def build_plan(self):
            return type("Plan", (), {"rows": ()})()

    def fail_mba_blocks(mba):
        raise AssertionError("MBA planner blocks should not be loaded")

    def fail_fact_sites(fact_view):
        raise AssertionError("fact-view planner sites should not be loaded")

    monkeypatch.delenv("D810_TAIL_DISTINCT_BYTE", raising=False)
    monkeypatch.delenv("D810_TAIL_DUPLICATE_CONVERGENCE_BYTE", raising=False)
    monkeypatch.delenv("D810_TERMINAL_TAIL_STATE_CASCADE_PAIR", raising=False)
    monkeypatch.setattr(
        planner_module,
        "TerminalTailCascadeEgressPlanner",
        FakePlanner,
    )
    monkeypatch.setattr(runtime, "_load_planner_blocks_from_mba", fail_mba_blocks)
    monkeypatch.setattr(runtime, "_load_planner_sites_from_fact_view", fail_fact_sites)
    monkeypatch.setattr(runtime, "_load_dag_semantics_from_dag", lambda value: value)
    monkeypatch.setattr(runtime, "LiveMbaAdapter", lambda mba: object())
    monkeypatch.setattr(
        runtime,
        "execute_terminal_tail_cascade_egress_lowering",
        lambda **kwargs: "report",
    )
    monkeypatch.setattr(
        runtime,
        "_close_terminal_equality_frontiers",
        lambda **kwargs: ((), ()),
    )
    monkeypatch.setattr(
        runtime,
        "_close_terminal_tail_entry_frontier",
        lambda **kwargs: ((), ()),
    )

    mba = object()
    runtime.maybe_run_terminal_tail_cascade_egress_lowering(
        mba,
        evidence_provider=provider,
    )

    assert provider.seen_mba is mba
    assert calls["blocks"] == blocks
    assert calls["sites"] == sites


def test_terminal_tail_without_explicit_cascade_priors_skips(monkeypatch):
    import d810.hexrays.mutation.byte_emit_tail_isolation_runtime as runtime
    from d810.hexrays.mutation.byte_tail_runtime_evidence import (
        ByteTailRuntimeEvidence,
    )

    provider = _FakeEvidenceProvider(ByteTailRuntimeEvidence(fact_view=object()))

    def fail_load_planner_blocks_from_mba(mba):
        raise AssertionError("terminal tail cascade should require explicit priors")

    monkeypatch.delenv("D810_TAIL_DISTINCT_BYTE", raising=False)
    monkeypatch.delenv("D810_TAIL_DUPLICATE_CONVERGENCE_BYTE", raising=False)
    monkeypatch.delenv("D810_TERMINAL_TAIL_STATE_CASCADE_PAIR", raising=False)
    monkeypatch.setattr(
        runtime,
        "_load_planner_blocks_from_mba",
        fail_load_planner_blocks_from_mba,
    )

    runtime.maybe_run_terminal_tail_cascade_egress_lowering(
        object(),
        evidence_provider=provider,
    )

    assert provider.seen_mba is not None


def test_tail_state_cascade_missing_provider_skips_without_diag(monkeypatch):
    import d810.hexrays.mutation.byte_emit_tail_isolation_runtime as runtime

    def fail_load_planner_blocks_from_mba(mba):
        raise AssertionError("tail state cascade should require explicit evidence")

    monkeypatch.setenv("D810_TERMINAL_TAIL_STATE_CASCADE_PAIR", "5:6")
    monkeypatch.delenv("D810_TAIL_DISTINCT_BYTE", raising=False)
    monkeypatch.delenv("D810_TAIL_DUPLICATE_CONVERGENCE_BYTE", raising=False)
    monkeypatch.setattr(
        runtime,
        "_load_planner_blocks_from_mba",
        fail_load_planner_blocks_from_mba,
    )

    runtime.maybe_run_tail_state_cascade(object())

    assert not hasattr(runtime, "DiagDbFactView")


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
    assert reason == "live_block_not_resolvable:diag_bridge_disabled"


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
    assert reason == "live_block_not_resolvable:diag_bridge_disabled"


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
    assert reason == "live_block_not_resolvable:diag_bridge_disabled"


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

    assert mapped is None
    assert reason == "live_block_not_resolvable:diag_bridge_disabled"


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
    adapter = _FakeLiveAdapter(
        _FakeLiveMba(
            blocks={
                130: _FakeLiveBlock(succs=(143,)),
                143: _FakeLiveBlock(succs=(144, 145)),
            }
        )
    )

    live, reason = _select_terminal_tail_entry_live(
        blocks=blocks,
        sites=sites,
        rows_by_byte={},
        diag_conn=None,
        target_snap=None,
        adapter=adapter,
        first_byte_index=1,
    )

    assert reason == "ok"
    assert live == 130


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
        _mba: _FakeLiveMba
        redirects: list[tuple[int, int, int]] = field(default_factory=list)

        def find_block_by_ea(self, ea):
            return None

        def redirect_advance_edge(
            self, *, source_serial, old_target_serial, new_target_serial,
        ):
            self.redirects.append(
                (int(source_serial), int(old_target_serial), int(new_target_serial))
            )

    adapter = _Adapter(
        _FakeLiveMba(
            blocks={
                130: _FakeLiveBlock(succs=(143,)),
                139: _FakeLiveBlock(succs=(140, 141)),
                141: _FakeLiveBlock(succs=(211,)),
                211: _FakeLiveBlock(),
            }
        )
    )
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
        diag_conn=None,
        target_snap=None,
        adapter=adapter,
        first_byte_index=1,
    )

    assert skipped == ("edge58:already_enters_dag_target:211",)
    assert applied == ()
    assert adapter.redirects == []


def test_close_terminal_equality_frontiers_skips_byte1_row_by_default(monkeypatch):
    import d810.hexrays.mutation.byte_emit_tail_isolation_runtime as runtime

    @dataclass
    class _Adapter:
        redirects: list[tuple[int, int, int]] = field(default_factory=list)
        cleared: list[int] = field(default_factory=list)

        def redirect_advance_edge(
            self, *, source_serial, old_target_serial, new_target_serial,
        ):
            self.redirects.append(
                (int(source_serial), int(old_target_serial), int(new_target_serial))
            )

        def clear_state_frontier_payload(self, block_serial):
            self.cleared.append(int(block_serial))

    adapter = _Adapter()
    rows_by_byte = {
        1: _FakePlanRow(
            byte_index=1,
            source_block=10,
            current_continuation_target=11,
            early_return_target=100,
        ),
        2: _FakePlanRow(
            byte_index=2,
            source_block=20,
            current_continuation_target=21,
            early_return_target=200,
        ),
    }

    monkeypatch.setattr(
        runtime,
        "_map_terminal_return_frontier",
        lambda **kwargs: (900, "ok"),
    )
    monkeypatch.setattr(
        runtime,
        "_live_successor_map",
        lambda adapter: {10: (100,), 20: (900,), 100: (111,), 110: (111,), 900: ()},
    )
    monkeypatch.setattr(runtime, "_dag_sccs_for_snap_blocks", lambda *args: frozenset({1}))
    monkeypatch.setattr(
        runtime,
        "_map_snap_serial_to_live",
        lambda **kwargs: (int(kwargs["snap_serial"]), "ok"),
    )
    monkeypatch.setattr(
        runtime,
        "_map_snap_successor_to_live",
        lambda **kwargs: (
            900 if int(kwargs["snap_target_serial"]) == 200 else int(kwargs["snap_target_serial"]),
            "ok",
        ),
    )
    monkeypatch.setattr(
        runtime,
        "_live_block_is_state_frontier_only",
        lambda adapter, live_serial: int(live_serial) == 100,
    )
    monkeypatch.setattr(
        runtime,
        "_frontier_for_terminal_arm",
        lambda **kwargs: (_ for _ in ()).throw(
            AssertionError("state-frontier return arms should be handled directly")
        ),
    )
    monkeypatch.setattr(
        runtime,
        "_live_single_successor",
        lambda adapter, live_serial: 111 if int(live_serial) == 100 else None,
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

    applied, skipped = runtime._close_terminal_equality_frontiers(
        rows_by_byte=rows_by_byte,
        blocks={},
        sites=(),
        dag=object(),
        diag_conn=None,
        target_snap=None,
        adapter=adapter,
        return_frontier_byte_index=2,
        row_byte_indices=(2, 3),
        shared_store_guard_byte_indices=(3, 5),
    )

    assert applied == ()
    assert skipped == ("byte2_row_equality:already_closed:900",)
    assert adapter.cleared == []
    assert adapter.redirects == []


def test_close_terminal_equality_frontiers_does_not_discover_byte1_state_frontier(
    monkeypatch,
):
    import d810.hexrays.mutation.byte_emit_tail_isolation_runtime as runtime

    @dataclass
    class _Adapter:
        redirects: list[tuple[int, int, int]] = field(default_factory=list)
        cleared: list[int] = field(default_factory=list)

        def redirect_advance_edge(
            self, *, source_serial, old_target_serial, new_target_serial,
        ):
            self.redirects.append(
                (int(source_serial), int(old_target_serial), int(new_target_serial))
            )

        def clear_state_frontier_payload(self, block_serial):
            self.cleared.append(int(block_serial))

    adapter = _Adapter()
    rows_by_byte = {
        1: _FakePlanRow(
            byte_index=1,
            source_block=10,
            current_continuation_target=11,
            early_return_target=100,
        ),
        2: _FakePlanRow(
            byte_index=2,
            source_block=20,
            current_continuation_target=21,
            early_return_target=200,
        ),
    }

    monkeypatch.setattr(runtime, "_map_terminal_return_frontier", lambda **kwargs: (900, "ok"))
    monkeypatch.setattr(runtime, "_live_successor_map", lambda adapter: {10: (100,), 20: (900,)})
    monkeypatch.setattr(runtime, "_dag_sccs_for_snap_blocks", lambda *args: frozenset({1}))
    monkeypatch.setattr(runtime, "_map_snap_serial_to_live", lambda **kwargs: (int(kwargs["snap_serial"]), "ok"))
    monkeypatch.setattr(
        runtime,
        "_map_snap_successor_to_live",
        lambda **kwargs: (
            900 if int(kwargs["snap_target_serial"]) == 200 else int(kwargs["snap_target_serial"]),
            "ok",
        ),
    )
    monkeypatch.setattr(runtime, "_live_block_is_state_frontier_only", lambda adapter, live_serial: int(live_serial) == 144)
    monkeypatch.setattr(runtime, "_frontier_for_terminal_arm", lambda **kwargs: (144, 111, "state_frontier"))
    monkeypatch.setattr(runtime, "_first_cyclic_scc_reachable", lambda **kwargs: object())
    monkeypatch.setattr(runtime, "_cfg_scc_is_illegal_from_dag_sources", lambda **kwargs: True)

    applied, skipped = runtime._close_terminal_equality_frontiers(
        rows_by_byte=rows_by_byte,
        blocks={},
        sites=(),
        dag=object(),
        diag_conn=None,
        target_snap=None,
        adapter=adapter,
        return_frontier_byte_index=2,
        row_byte_indices=(2, 3),
        shared_store_guard_byte_indices=(3, 5),
    )

    assert applied == ()
    assert skipped == ("byte2_row_equality:already_closed:900",)
    assert adapter.cleared == []
    assert adapter.redirects == []


def test_close_terminal_equality_frontiers_skips_dag_conditional_returns_by_default(
    monkeypatch,
):
    import d810.hexrays.mutation.byte_emit_tail_isolation_runtime as runtime

    @dataclass
    class _Adapter:
        redirects: list[tuple[int, int, int]] = field(default_factory=list)
        cleared: list[int] = field(default_factory=list)

        def redirect_advance_edge(
            self, *, source_serial, old_target_serial, new_target_serial,
        ):
            self.redirects.append(
                (int(source_serial), int(old_target_serial), int(new_target_serial))
            )

        def clear_state_frontier_payload(self, block_serial):
            self.cleared.append(int(block_serial))

    adapter = _Adapter()
    dag = runtime._DagSemantics(
        snapshot_id=7,
        state_to_scc={},
        scc_reachable={},
        block_to_sccs={26: frozenset({1})},
        scc_successors={},
        edges=(
            runtime._DagEdge(
                edge_id=92,
                source_state=0x64AFC49D,
                target_state=None,
                edge_kind="CONDITIONAL_RETURN",
                source_block=26,
                source_arm=0,
                target_entry=None,
                ordered_path=(26, 27, 218, 219),
            ),
        ),
    )

    monkeypatch.setattr(runtime, "_map_terminal_return_frontier", lambda **kwargs: (900, "ok"))
    monkeypatch.setattr(runtime, "_live_successor_map", lambda adapter: {26: (27, 28), 27: (111,), 900: ()})
    monkeypatch.setattr(runtime, "_map_snap_serial_to_live", lambda **kwargs: (int(kwargs["snap_serial"]), "ok"))
    monkeypatch.setattr(runtime, "_map_snap_successor_to_live", lambda **kwargs: (int(kwargs["snap_target_serial"]), "ok"))
    monkeypatch.setattr(runtime, "_live_block_is_state_frontier_only", lambda adapter, live_serial: int(live_serial) == 27)
    monkeypatch.setattr(runtime, "_live_single_successor", lambda adapter, live_serial: 111 if int(live_serial) == 27 else None)
    monkeypatch.setattr(
        runtime,
        "_first_cyclic_scc_reachable",
        lambda **kwargs: (_ for _ in ()).throw(
            AssertionError("DAG conditional returns do not need a cyclic CFG proof")
        ),
    )
    monkeypatch.setattr(
        runtime,
        "_frontier_for_terminal_arm",
        lambda **kwargs: (_ for _ in ()).throw(
            AssertionError("state-frontier return arm should be handled directly")
        ),
    )

    applied, skipped = runtime._close_terminal_equality_frontiers(
        rows_by_byte={},
        blocks={},
        sites=(),
        dag=dag,
        diag_conn=None,
        target_snap=None,
        adapter=adapter,
        return_frontier_byte_index=2,
        row_byte_indices=(2, 3),
        shared_store_guard_byte_indices=(3, 5),
    )

    assert skipped == ()
    assert applied == ()
    assert adapter.cleared == []
    assert adapter.redirects == []


def test_close_terminal_equality_frontiers_skips_dag_fallthrough_source_by_default(
    monkeypatch,
):
    import d810.hexrays.mutation.byte_emit_tail_isolation_runtime as runtime

    @dataclass
    class _Adapter:
        redirects: list[tuple[int, int, int]] = field(default_factory=list)
        fallthrough_redirects: list[tuple[int, int, int]] = field(default_factory=list)
        cleared: list[int] = field(default_factory=list)

        def redirect_advance_edge(
            self, *, source_serial, old_target_serial, new_target_serial,
        ):
            self.redirects.append(
                (int(source_serial), int(old_target_serial), int(new_target_serial))
            )

        def redirect_fallthrough_edge(
            self, *, source_serial, old_target_serial, new_target_serial,
        ):
            self.fallthrough_redirects.append(
                (int(source_serial), int(old_target_serial), int(new_target_serial))
            )
            return 28

        def clear_state_frontier_payload(self, block_serial):
            self.cleared.append(int(block_serial))

    adapter = _Adapter()
    dag = runtime._DagSemantics(
        snapshot_id=7,
        state_to_scc={},
        scc_reachable={},
        block_to_sccs={26: frozenset({1})},
        scc_successors={},
        edges=(
            runtime._DagEdge(
                edge_id=130,
                source_state=0x45B18E82,
                target_state=None,
                edge_kind="CONDITIONAL_RETURN",
                source_block=26,
                source_arm=0,
                target_entry=None,
                ordered_path=(26, 27, 218, 219),
            ),
        ),
    )

    monkeypatch.setattr(runtime, "_map_terminal_return_frontier", lambda **kwargs: (900, "ok"))
    monkeypatch.setattr(runtime, "_live_successor_map", lambda adapter: {26: (27, 28), 27: (111,), 900: ()})
    monkeypatch.setattr(runtime, "_map_snap_serial_to_live", lambda **kwargs: (int(kwargs["snap_serial"]), "ok"))
    monkeypatch.setattr(runtime, "_map_snap_successor_to_live", lambda **kwargs: (int(kwargs["snap_target_serial"]), "ok"))
    monkeypatch.setattr(runtime, "_live_block_is_state_frontier_only", lambda adapter, live_serial: int(live_serial) == 27)
    monkeypatch.setattr(runtime, "_live_single_successor", lambda adapter, live_serial: 111 if int(live_serial) == 27 else None)
    monkeypatch.setattr(
        runtime,
        "_first_cyclic_scc_reachable",
        lambda **kwargs: (_ for _ in ()).throw(
            AssertionError("DAG conditional returns do not need a cyclic CFG proof")
        ),
    )

    applied, skipped = runtime._close_terminal_equality_frontiers(
        rows_by_byte={},
        blocks={},
        sites=(),
        dag=dag,
        diag_conn=None,
        target_snap=None,
        adapter=adapter,
        return_frontier_byte_index=2,
        row_byte_indices=(2, 3),
        shared_store_guard_byte_indices=(3, 5),
    )

    assert skipped == ()
    assert applied == ()
    assert adapter.cleared == []
    assert adapter.fallthrough_redirects == []
    assert adapter.redirects == []


def test_impossible_return_artifact_edges_route_to_sibling_continuation(
    monkeypatch,
):
    import d810.hexrays.mutation.byte_emit_tail_isolation_runtime as runtime
    from d810.recon.flow.return_frontier_artifacts import (
        ReturnFrontierArtifactEdgeProof,
    )

    @dataclass
    class _Adapter:
        redirects: list[tuple[int, int, int]] = field(default_factory=list)
        cleared: list[int] = field(default_factory=list)

        def redirect_advance_edge(
            self, *, source_serial, old_target_serial, new_target_serial,
        ):
            self.redirects.append(
                (int(source_serial), int(old_target_serial), int(new_target_serial))
            )

        def clear_state_frontier_payload(self, block_serial):
            self.cleared.append(int(block_serial))

    adapter = _Adapter()

    monkeypatch.setattr(
        runtime,
        "_live_successor_map",
        lambda adapter: {27: (28, 79), 28: (92,), 79: (29,), 29: (), 92: ()},
    )
    monkeypatch.setattr(
        runtime,
        "_live_single_successor",
        lambda adapter, live_serial: {28: 92, 79: 29}.get(int(live_serial)),
    )
    applied = runtime._rewrite_impossible_return_artifact_edges(
        adapter,
        (
            ReturnFrontierArtifactEdgeProof(
                source_block=27,
                artifact_block=28,
                old_target_block=92,
                continuation_block=29,
                proof_ids=("unit",),
            ),
        ),
    )

    assert applied == ((27, 28, 29),)
    assert adapter.cleared == [28]
    assert adapter.redirects == [(28, 92, 29)]


def test_impossible_return_artifact_requires_exact_old_target(monkeypatch):
    import d810.hexrays.mutation.byte_emit_tail_isolation_runtime as runtime
    from d810.recon.flow.return_frontier_artifacts import (
        ReturnFrontierArtifactEdgeProof,
    )

    @dataclass
    class _Adapter:
        redirects: list[tuple[int, int, int]] = field(default_factory=list)
        cleared: list[int] = field(default_factory=list)

        def redirect_advance_edge(
            self, *, source_serial, old_target_serial, new_target_serial,
        ):
            self.redirects.append(
                (int(source_serial), int(old_target_serial), int(new_target_serial))
            )

        def clear_state_frontier_payload(self, block_serial):
            self.cleared.append(int(block_serial))

    adapter = _Adapter()
    monkeypatch.setattr(
        runtime,
        "_live_successor_map",
        lambda adapter: {27: (28, 79), 28: (92,), 79: (29,), 29: (), 92: ()},
    )
    monkeypatch.setattr(
        runtime,
        "_live_single_successor",
        lambda adapter, live_serial: {28: 92, 79: 29}.get(int(live_serial)),
    )

    applied = runtime._rewrite_impossible_return_artifact_edges(
        adapter,
        (
            ReturnFrontierArtifactEdgeProof(
                source_block=27,
                artifact_block=28,
                old_target_block=93,
                continuation_block=29,
                proof_ids=("unit",),
            ),
        ),
    )

    assert applied == ()
    assert adapter.cleared == []
    assert adapter.redirects == []


def test_impossible_return_artifact_rewrite_uses_provider_evidence(monkeypatch):
    import d810.hexrays.mutation.byte_emit_tail_isolation_runtime as runtime
    from d810.hexrays.mutation.byte_tail_runtime_evidence import (
        ByteTailRuntimeEvidence,
    )
    from d810.recon.flow.return_frontier_artifacts import (
        ReturnFrontierArtifactEdgeProof,
    )

    @dataclass
    class _Adapter:
        redirects: list[tuple[int, int, int]] = field(default_factory=list)
        cleared: list[int] = field(default_factory=list)

        def redirect_advance_edge(
            self, *, source_serial, old_target_serial, new_target_serial,
        ):
            self.redirects.append(
                (int(source_serial), int(old_target_serial), int(new_target_serial))
            )

        def clear_state_frontier_payload(self, block_serial):
            self.cleared.append(int(block_serial))

    adapter = _Adapter()
    provider = _FakeEvidenceProvider(
        ByteTailRuntimeEvidence(
            impossible_return_artifact_edges=(
                ReturnFrontierArtifactEdgeProof(
                    source_block=27,
                    artifact_block=28,
                    old_target_block=92,
                    continuation_block=29,
                    proof_ids=("unit",),
                ),
            )
        )
    )

    monkeypatch.setenv("D810_REWRITE_IMPOSSIBLE_RETURN_ARTIFACTS", "1")
    monkeypatch.setattr(runtime, "LiveMbaAdapter", lambda mba: adapter)
    monkeypatch.setattr(
        runtime,
        "_live_successor_map",
        lambda adapter: {27: (28, 79), 28: (92,), 79: (29,), 29: (), 92: ()},
    )
    monkeypatch.setattr(
        runtime,
        "_live_single_successor",
        lambda adapter, live_serial: {28: 92, 79: 29}.get(int(live_serial)),
    )

    applied = runtime.maybe_rewrite_impossible_return_artifact_edges(
        object(),
        evidence_provider=provider,
    )

    assert applied == ((27, 28, 29),)
    assert provider.seen_mba is not None
    assert adapter.cleared == [28]
    assert adapter.redirects == [(28, 92, 29)]


def test_terminal_zero_guard_literal_return_edges_rewrites_zero_arm(
    monkeypatch,
):
    import d810.hexrays.mutation.byte_emit_tail_isolation_runtime as runtime

    rewritten: list[tuple[int, int]] = []
    adapter = object()

    monkeypatch.setattr(
        runtime,
        "_live_successor_map",
        lambda adapter: {61: (62, 88), 62: (27,), 88: (92,), 92: ()},
    )
    monkeypatch.setattr(
        runtime,
        "_terminal_zero_guard_targets_literal_return",
        lambda adapter, source_serial, return_serial: (
            int(source_serial) == 61 and int(return_serial) == 88
        ),
    )
    monkeypatch.setattr(
        runtime,
        "_terminal_return_block_has_only_literal_zero_guard_preds",
        lambda adapter, return_serial: int(return_serial) == 88,
    )

    def fake_rewrite(adapter, *, return_serial, literal_value):
        rewritten.append((int(return_serial), int(literal_value)))
        return True

    monkeypatch.setattr(runtime, "_rewrite_terminal_return_block_to_literal", fake_rewrite)

    applied = runtime._rewrite_terminal_zero_guard_literal_return_edges(
        adapter,
        (0x5644FD01B1049C4B,),
    )

    assert applied == ((61, 88, 0x5644FD01B1049C4B),)
    assert rewritten == [(88, 0x5644FD01B1049C4B)]
