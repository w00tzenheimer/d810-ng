"""Unit tests for ReconAnalysisRuntime coordinator."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from types import MappingProxyType
from unittest.mock import MagicMock, call, create_autospec, patch

import pytest

from d810.core import ProviderPhaseSnapshot
from d810.core import logging
from d810.core.diag.schema import create_tables
from d810.core.settings import configure_settings, reset_settings
from d810.recon.analysis import AnalysisPhase
from d810.recon.facts import FactConsumerRecord, FactObservation
from d810.recon.models import DeobfuscationHints, ReconResult
from d810.recon.phase import ReconPhase
from d810.recon.runtime import ReconAnalysisRuntime, logger
from d810.recon.store import ReconStore

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_FUNC_EA = 0x401000
_MATURITY = 5
_SENTINEL_TARGET = object()


def _phase(level: int = _MATURITY, friendly: str | None = None) -> ProviderPhaseSnapshot:
    return ProviderPhaseSnapshot(
        provider_name="hexrays_microcode",
        provider_level=level,
        friendly_provider_level=friendly or f"MMAT_{level}",
    )


def _make_recon_result(
    collector_name: str = "CFGShapeCollector",
    func_ea: int = _FUNC_EA,
    maturity: int = _MATURITY,
) -> ReconResult:
    return ReconResult(
        collector_name=collector_name,
        func_ea=func_ea,
        maturity=maturity,
        timestamp=0.0,
        metrics=MappingProxyType({"block_count": 20}),
        candidates=(),
    )


def _make_hints(
    func_ea: int = _FUNC_EA,
    obfuscation_type: str | None = "ollvm_flat",
    confidence: float = 0.85,
) -> DeobfuscationHints:
    return DeobfuscationHints(
        func_ea=func_ea,
        obfuscation_type=obfuscation_type,
        confidence=confidence,
        recommended_inferences=("unflattening",),
        candidates=(),
        suppress_rules=(),
    )


def _make_runtime() -> tuple[ReconAnalysisRuntime, MagicMock, MagicMock, MagicMock]:
    """Build a runtime with mocked dependencies.

    Returns (runtime, mock_phase, mock_analysis, mock_store).
    Patches ``get_recon_writer`` so writes execute synchronously on mock_store.
    """
    mock_phase = create_autospec(ReconPhase, instance=True)
    mock_analysis = create_autospec(AnalysisPhase, instance=True)
    mock_store = create_autospec(ReconStore, instance=True)
    mock_store.db_path = Path("/tmp/test_recon.db")

    writer = _make_sync_writer(mock_store)
    p1 = patch("d810.recon.runtime.get_recon_writer", return_value=writer)
    p2 = patch("d810.recon.phase.get_recon_writer", return_value=writer)
    p1.start()
    p2.start()
    _active_patchers.extend([p1, p2])

    rt = ReconAnalysisRuntime(mock_phase, mock_analysis, mock_store)
    return rt, mock_phase, mock_analysis, mock_store


def _make_sync_writer(mock_store: MagicMock) -> MagicMock:
    """Create a mock writer that executes submit calls synchronously."""
    writer = MagicMock()
    writer.submit.side_effect = lambda fn: fn(mock_store)
    writer.submit_sync.side_effect = lambda fn: fn(mock_store)
    writer.flush.return_value = None
    return writer


_active_patchers: list = []


@pytest.fixture(autouse=True)
def _cleanup_writer_patchers():
    """Stop any writer patches started by ``_make_runtime``."""
    yield
    for p in _active_patchers:
        p.stop()
    _active_patchers.clear()
    reset_settings()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_collect_and_analyze_persists_hints() -> None:
    """collect_and_analyze with persist_hints=True saves hints to store."""
    rt, mock_phase, mock_analysis, mock_store = _make_runtime()

    results = [_make_recon_result()]
    hints = _make_hints()

    mock_phase.run_microcode_collectors.return_value = results
    mock_analysis.interpret.return_value = hints

    returned = rt.collect_and_analyze(
        _FUNC_EA,
        _SENTINEL_TARGET,
        _phase(),
        persist_hints=True,
    )

    assert returned is hints
    mock_phase.run_microcode_collectors.assert_called_once_with(
        _SENTINEL_TARGET,
        func_ea=_FUNC_EA,
        provider_phase=_phase(),
    )
    mock_analysis.interpret.assert_called_once_with(
        func_ea=_FUNC_EA,
        results=results,
        store=mock_store,
    )
    mock_store.save_hints.assert_called_once_with(hints)


def test_collect_and_analyze_no_persist() -> None:
    """collect_and_analyze with persist_hints=False does NOT save hints."""
    rt, mock_phase, mock_analysis, mock_store = _make_runtime()

    results = [_make_recon_result()]
    hints = _make_hints()

    mock_phase.run_microcode_collectors.return_value = results
    mock_analysis.interpret.return_value = hints

    returned = rt.collect_and_analyze(
        _FUNC_EA,
        _SENTINEL_TARGET,
        _phase(),
        persist_hints=False,
    )

    assert returned is hints
    mock_store.save_hints.assert_not_called()


def test_load_hints_delegates_to_store() -> None:
    """load_hints passes through to store and returns the result."""
    rt, _mock_phase, _mock_analysis, mock_store = _make_runtime()

    stored_hints = _make_hints()
    mock_store.load_hints.return_value = stored_hints

    returned = rt.load_hints(_FUNC_EA)

    assert returned is stored_hints
    mock_store.load_hints.assert_called_once_with(func_ea=_FUNC_EA)


def test_load_hints_returns_none_when_absent() -> None:
    """load_hints returns None when the store has no entry."""
    rt, _mock_phase, _mock_analysis, mock_store = _make_runtime()

    mock_store.load_hints.return_value = None

    returned = rt.load_hints(_FUNC_EA)

    assert returned is None
    mock_store.load_hints.assert_called_once_with(func_ea=_FUNC_EA)


def test_fact_lifecycle_capture_can_be_disabled() -> None:
    configure_settings(fact_lifecycle=False)
    rt, _mock_phase, _mock_analysis, _mock_store = _make_runtime()

    summary = rt.capture_maturity_facts(
        object(),
        func_ea=_FUNC_EA,
        provider_phase=_phase(1),
        phase="pre_d810",
    )

    assert summary.enabled is False
    assert summary.invoked is False
    assert summary.reason == "disabled"


def test_fact_lifecycle_capture_invokes_empty_registry_once() -> None:
    configure_settings(fact_lifecycle=True)
    rt, _mock_phase, _mock_analysis, _mock_store = _make_runtime()

    first = rt.capture_maturity_facts(
        object(),
        func_ea=_FUNC_EA,
        provider_phase=_phase(1),
        phase="pre_d810",
    )
    second = rt.capture_maturity_facts(
        object(),
        func_ea=_FUNC_EA,
        provider_phase=_phase(1),
        phase="pre_d810",
    )

    assert first.enabled is True
    assert first.invoked is True
    assert first.collector_count == 0
    assert first.observation_count == 0
    assert second.invoked is False
    assert second.reason == "already-fired"


def test_fact_lifecycle_capture_persists_to_diag_snapshot() -> None:
    class _Collector:
        name = "fake-induction"
        maturities = frozenset({_MATURITY})

        def collect(self, target, *, func_ea: int, maturity: int, phase: str):
            return (
                FactObservation(
                    fact_id="induction:runtime",
                    kind="InductionCarrierFact",
                    semantic_key="loop:runtime",
                    maturity=f"MMAT_{maturity}",
                    phase=phase,
                    confidence=1.0,
                    source_block=42,
                ),
            )

    configure_settings(fact_lifecycle=True)
    rt, _mock_phase, _mock_analysis, _mock_store = _make_runtime()
    rt._fact_lifecycle.register(_Collector())  # targeted substrate test

    conn = sqlite3.connect(":memory:")
    create_tables(conn)
    conn.execute(
        "INSERT INTO snapshots VALUES "
        "(1, 'test', '0x0000000000401000', 0x401000, 'MMAT_GLBOPT1', "
        "'pre_d810', 1, 0.0)"
    )

    # Wire the abstract observability backend to the test conn and bind
    # a SnapshotRef whose key resolves to snap_id=1 in this fixture.
    from d810.core.diag.event_handlers import (
        _bind_snapshot_id, install_diag_event_handlers,
        uninstall_diag_event_handlers,
    )
    from d810.core.observability import SnapshotRef
    install_diag_event_handlers()
    snap_ref = SnapshotRef(
        key="test-key", func_ea=_FUNC_EA, label="test",
        maturity="MMAT_GLBOPT1", phase="pre_d810",
    )
    _bind_snapshot_id(snap_ref, 1)
    try:
        with patch(
            "d810.core.diag.event_handlers.get_diag_db",
            return_value=conn,
        ):
            summary = rt.capture_maturity_facts(
                object(),
                func_ea=_FUNC_EA,
                provider_phase=_phase(),
                phase="pre_d810",
                snapshot=snap_ref,
            )
    finally:
        uninstall_diag_event_handlers()

    assert summary.observation_count == 1
    row = conn.execute(
        "SELECT kind, source_block FROM fact_observations "
        "WHERE fact_id='induction:runtime'"
    ).fetchone()
    assert row == ("InductionCarrierFact", 42)


def test_validated_fact_view_is_exposed_from_runtime() -> None:
    class _Collector:
        name = "fake-induction"
        maturities = frozenset({_MATURITY})

        def collect(self, target, *, func_ea: int, maturity: int, phase: str):
            return (
                FactObservation(
                    fact_id="induction:runtime",
                    kind="InductionCarrierFact",
                    semantic_key="loop:runtime",
                    maturity=f"MMAT_{maturity}",
                    phase=phase,
                    confidence=1.0,
                    source_block=42,
                ),
            )

    configure_settings(fact_lifecycle=True)
    rt, _mock_phase, _mock_analysis, _mock_store = _make_runtime()
    rt.register_fact_collector(_Collector())

    rt.capture_maturity_facts(
        object(),
        func_ea=_FUNC_EA,
        provider_phase=_phase(),
        phase="pre_d810",
    )

    view = rt.validated_fact_view(_FUNC_EA, _MATURITY)

    assert len(view.observations) == 1
    assert len(view.active_observations) == 1
    assert view.observations[0].fact_id == "induction:runtime"


def test_record_fact_consumers_persists_to_latest_diag_snapshot() -> None:
    conn = sqlite3.connect(":memory:")
    create_tables(conn)
    conn.execute(
        "INSERT INTO snapshots "
        "(id, label, func_ea_hex, func_ea_i64, maturity, phase, block_count, timestamp) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (
            7,
            "pre",
            f"0x{_FUNC_EA:016x}",
            _FUNC_EA,
            "MMAT_GLBOPT1",
            "pre_d810",
            3,
            0.0,
        ),
    )
    conn.commit()
    rt, _mock_phase, _mock_analysis, _mock_store = _make_runtime()
    record = FactConsumerRecord(
        consumer="hodur.unflattener",
        strategy="HodurUnflattener",
        fact_id="induction:runtime",
        maturity="MMAT_GLBOPT1",
        decision="stale",
        reason="unit-test",
        payload={"active": 0},
    )

    configure_settings(diag_snapshots=True)
    # The new flow emits FactConsumersForLatestSnapshot; the diag
    # subscriber finds the latest snapshot row and writes deduplicated
    # fact_consumers rows. We install the subscriber and patch the
    # diag conn provider to return our test conn.
    from d810.core.diag.event_handlers import (
        install_diag_event_handlers, uninstall_diag_event_handlers,
    )
    install_diag_event_handlers()
    try:
        with patch(
            "d810.core.diag.event_handlers.get_diag_db", return_value=conn,
        ):
            persisted = rt.record_fact_consumers(_FUNC_EA, (record,))

        assert persisted == 1
        row = conn.execute(
            "SELECT snapshot_id, consumer, strategy, fact_id, decision, payload "
            "FROM fact_consumers"
        ).fetchone()
        assert row[0] == 7
        assert row[1:5] == (
            "hodur.unflattener",
            "HodurUnflattener",
            "induction:runtime",
            "stale",
        )
        assert json.loads(row[5]) == {"active": 0}

        with patch(
            "d810.core.diag.event_handlers.get_diag_db", return_value=conn,
        ):
            # New emit; subscriber sees the row already exists and dedups.
            rt.record_fact_consumers(_FUNC_EA, (record,))

        assert conn.execute("SELECT COUNT(*) FROM fact_consumers").fetchone()[0] == 1
    finally:
        uninstall_diag_event_handlers()


def test_load_or_analyze_cache_hit() -> None:
    """load_or_analyze returns cached hints without running collectors."""
    rt, mock_phase, mock_analysis, mock_store = _make_runtime()

    cached_hints = _make_hints()
    mock_store.load_hints.return_value = cached_hints

    returned = rt.load_or_analyze(
        _FUNC_EA,
        _SENTINEL_TARGET,
        _phase(),
    )

    assert returned is cached_hints
    mock_store.load_hints.assert_called_once_with(func_ea=_FUNC_EA)
    mock_phase.run_microcode_collectors.assert_not_called()
    mock_analysis.interpret.assert_not_called()


def test_load_or_analyze_cache_miss() -> None:
    """load_or_analyze falls back to collect_and_analyze on cache miss."""
    rt, mock_phase, mock_analysis, mock_store = _make_runtime()

    results = [_make_recon_result()]
    fresh_hints = _make_hints(confidence=0.70)

    mock_store.load_hints.return_value = None
    mock_phase.run_microcode_collectors.return_value = results
    mock_analysis.interpret.return_value = fresh_hints

    returned = rt.load_or_analyze(
        _FUNC_EA,
        _SENTINEL_TARGET,
        _phase(),
        persist_hints=True,
    )

    assert returned is fresh_hints
    mock_store.load_hints.assert_called_once_with(func_ea=_FUNC_EA)
    mock_phase.run_microcode_collectors.assert_called_once_with(
        _SENTINEL_TARGET,
        func_ea=_FUNC_EA,
        provider_phase=_phase(),
    )
    mock_analysis.interpret.assert_called_once_with(
        func_ea=_FUNC_EA,
        results=results,
        store=mock_store,
    )
    mock_store.save_hints.assert_called_once_with(fresh_hints)


def test_reset_for_func_clears_fired_and_store() -> None:
    """reset_for_func delegates to phase.reset and store.clear_func."""
    rt, mock_phase, _mock_analysis, mock_store = _make_runtime()

    result = rt.reset_for_func(_FUNC_EA)

    assert result is True
    mock_phase.reset.assert_called_once_with(func_ea=_FUNC_EA)
    mock_store.clear_func.assert_called_once_with(func_ea=_FUNC_EA)


def test_analyze_and_persist_with_results() -> None:
    """analyze_and_persist runs analysis and saves hints when results exist."""
    rt, _mock_phase, mock_analysis, mock_store = _make_runtime()

    results = [_make_recon_result()]
    hints = _make_hints()

    mock_store.load_all_recon_results.return_value = results
    mock_analysis.interpret.return_value = hints

    returned = rt.analyze_and_persist(_FUNC_EA)

    assert returned is hints
    mock_store.load_all_recon_results.assert_called_once_with(func_ea=_FUNC_EA)
    mock_analysis.interpret.assert_called_once_with(
        func_ea=_FUNC_EA,
        results=results,
        store=mock_store,
    )
    mock_store.save_hints.assert_called_once_with(hints)


def test_analyze_and_persist_no_results() -> None:
    """analyze_and_persist returns None when store has no recon results."""
    rt, _mock_phase, mock_analysis, mock_store = _make_runtime()

    mock_store.load_all_recon_results.return_value = []

    returned = rt.analyze_and_persist(_FUNC_EA)

    assert returned is None
    mock_store.load_all_recon_results.assert_called_once_with(func_ea=_FUNC_EA)
    mock_analysis.interpret.assert_not_called()
    mock_store.save_hints.assert_not_called()


def test_analyze_and_persist_overwrites_previous_hints() -> None:
    """analyze_and_persist overwrites hints on re-analysis."""
    rt, _mock_phase, mock_analysis, mock_store = _make_runtime()

    results_v1 = [_make_recon_result()]
    hints_v1 = _make_hints(confidence=0.60)
    results_v2 = [_make_recon_result(), _make_recon_result("DispatchPatternCollector")]
    hints_v2 = _make_hints(confidence=0.95)

    # First call
    mock_store.load_all_recon_results.return_value = results_v1
    mock_analysis.interpret.return_value = hints_v1
    ret1 = rt.analyze_and_persist(_FUNC_EA)

    # Second call with more results
    mock_store.load_all_recon_results.return_value = results_v2
    mock_analysis.interpret.return_value = hints_v2
    ret2 = rt.analyze_and_persist(_FUNC_EA)

    assert ret1 is hints_v1
    assert ret2 is hints_v2
    assert mock_store.save_hints.call_count == 2
    mock_store.save_hints.assert_any_call(hints_v1)
    mock_store.save_hints.assert_any_call(hints_v2)


def test_collect_and_analyze_saves_recon_results() -> None:
    """Verify run_microcode_collectors is invoked (it saves results internally)."""
    rt, mock_phase, mock_analysis, mock_store = _make_runtime()

    r1 = _make_recon_result("CFGShapeCollector")
    r2 = _make_recon_result("DispatchPatternCollector")
    results = [r1, r2]
    hints = _make_hints()

    mock_phase.run_microcode_collectors.return_value = results
    mock_analysis.interpret.return_value = hints

    returned = rt.collect_and_analyze(
        _FUNC_EA,
        _SENTINEL_TARGET,
        _phase(),
    )

    assert returned is hints
    # The runtime delegates to phase which internally saves each ReconResult.
    # Verify the phase was called with the right arguments.
    mock_phase.run_microcode_collectors.assert_called_once_with(
        _SENTINEL_TARGET,
        func_ea=_FUNC_EA,
        provider_phase=_phase(),
    )
    # Both results are forwarded to the analysis phase.
    mock_analysis.interpret.assert_called_once_with(
        func_ea=_FUNC_EA,
        results=results,
        store=mock_store,
    )


# ---------------------------------------------------------------------------
# Dedup: reset fires exactly once per decompilation, across managers
# ---------------------------------------------------------------------------


def test_reset_deduplicates_across_calls() -> None:
    """Calling reset_for_func(X) twice only fires phase.reset/store.clear once.

    This simulates two managers (instruction + block) both calling
    reset_for_func with the same func_ea during a single decompilation.
    The runtime's internal guard deduplicates: only the first call fires.
    """
    rt, mock_phase, _mock_analysis, mock_store = _make_runtime()

    # First call fires
    assert rt.reset_for_func(_FUNC_EA) is True
    assert mock_phase.reset.call_count == 1
    assert mock_store.clear_func.call_count == 1

    # Second call with same func_ea is a no-op
    assert rt.reset_for_func(_FUNC_EA) is False
    assert mock_phase.reset.call_count == 1  # still 1
    assert mock_store.clear_func.call_count == 1  # still 1


def test_mark_decompilation_finished_allows_re_reset() -> None:
    """After mark_decompilation_finished, same func_ea triggers reset again.

    Simulates the lifecycle: decompile func X -> FINISHED event ->
    re-decompile func X. The FINISHED event calls mark_decompilation_finished
    which resets the guard so the next decompilation fires reset.
    """
    rt, mock_phase, _mock_analysis, mock_store = _make_runtime()

    # 1st decompilation
    assert rt.reset_for_func(_FUNC_EA) is True
    assert mock_phase.reset.call_count == 1

    # Decompilation finishes
    rt.mark_decompilation_finished()

    # 2nd decompilation of SAME function: fires again
    assert rt.reset_for_func(_FUNC_EA) is True
    assert mock_phase.reset.call_count == 2
    assert mock_store.clear_func.call_count == 2
    mock_phase.reset.assert_has_calls([call(func_ea=_FUNC_EA), call(func_ea=_FUNC_EA)])


def test_reset_for_func_flushes_previous_outcomes() -> None:
    """Switching to func B flushes persisted outcomes for func A.

    When reset_for_func(B) is called while func A is active, the runtime
    should persist session summary and consumer outcomes for A *before*
    clearing state for B.  This closes the gap where outcomes are lost if
    mark_decompilation_finished is never called (e.g. IDA decompiles A
    then immediately starts B).
    """
    rt, _mock_phase, _mock_analysis, mock_store = _make_runtime()

    func_a = 0x401000
    func_b = 0x402000

    # Activate func A
    rt.reset_for_func(func_a)

    # Set up store responses for func A's persist path
    hints_a = _make_hints(func_ea=func_a)
    mock_store.load_hints.return_value = hints_a
    results_a = [_make_recon_result(func_ea=func_a)]
    mock_store.load_all_recon_results.return_value = results_a

    # Record an outcome for func A
    rt.record_rule_scope_outcome(
        func_ea=func_a,
        hints=hints_a,
        apply_result=None,
        source="analyzed",
    )

    # Now switch to func B -- should flush func A outcomes first
    rt.reset_for_func(func_b)

    # Session summaries are persisted eagerly by analyze_and_persist,
    # not by _persist_outcomes, so no save_session_summary call here.
    mock_store.save_session_summary.assert_not_called()
    # Consumer outcome for func A was persisted
    mock_store.save_consumer_outcome.assert_called_once()
    outcome_call = mock_store.save_consumer_outcome.call_args
    assert outcome_call.kwargs["func_ea"] == func_a
    assert outcome_call.kwargs["consumer_name"] == "rule_scope"


def test_reset_fires_on_different_func_without_mark_finished() -> None:
    """Switching to a different function fires reset without needing mark_finished.

    This covers the case where IDA decompiles func A then func B in sequence
    without an explicit FINISHED event between them.
    """
    rt, mock_phase, _mock_analysis, mock_store = _make_runtime()
    other_ea = 0x402000

    assert rt.reset_for_func(_FUNC_EA) is True
    assert rt.reset_for_func(other_ea) is True
    assert mock_phase.reset.call_count == 2
    mock_phase.reset.assert_has_calls([call(func_ea=_FUNC_EA), call(func_ea=other_ea)])


# ---------------------------------------------------------------------------
# Outcome recording
# ---------------------------------------------------------------------------


def test_runtime_record_outcome() -> None:
    """record_outcome delegates to outcome log."""
    rt, _mock_phase, _mock_analysis, _mock_store = _make_runtime()

    from d810.recon.outcome import RuleScopeOutcomeAdapter
    from d810.recon.runtime import ReconOutcome

    outcome = ReconOutcome(
        func_ea=_FUNC_EA,
        hints=_make_hints(),
        apply_result=None,
        source="analyzed",
    )
    adapter = RuleScopeOutcomeAdapter(outcome)
    rt.record_outcome(adapter)

    reports = rt.outcome_log.get_func_reports(_FUNC_EA)
    assert len(reports) == 1
    assert reports[0].consumer_name == "rule_scope"
    assert reports[0].func_ea == _FUNC_EA


def test_reset_clears_outcome_log() -> None:
    """reset_for_func clears outcome entries for the function."""
    rt, _mock_phase, _mock_analysis, _mock_store = _make_runtime()

    from d810.recon.outcome import RuleScopeOutcomeAdapter
    from d810.recon.runtime import ReconOutcome

    outcome = ReconOutcome(
        func_ea=_FUNC_EA,
        hints=_make_hints(),
        apply_result=None,
        source="cached",
    )
    adapter = RuleScopeOutcomeAdapter(outcome)
    rt.record_outcome(adapter)
    assert len(rt.outcome_log.get_func_reports(_FUNC_EA)) == 1

    # reset_for_func should also clear outcome log
    rt.reset_for_func(_FUNC_EA)
    assert rt.outcome_log.get_func_reports(_FUNC_EA) == []


def test_record_rule_scope_outcome() -> None:
    """record_rule_scope_outcome builds adapter internally and records."""
    rt, _mock_phase, _mock_analysis, _mock_store = _make_runtime()

    hints = _make_hints()
    rt.record_rule_scope_outcome(
        func_ea=_FUNC_EA,
        hints=hints,
        apply_result=None,
        source="analyzed",
    )

    reports = rt.outcome_log.get_func_reports(_FUNC_EA)
    assert len(reports) == 1
    assert reports[0].consumer_name == "rule_scope"
    assert reports[0].source_artifacts_available is True
    assert reports[0].summary_available is True
    assert reports[0].consumer_verdict_applied is False  # apply_result=None


def test_record_planner_outcome() -> None:
    """record_planner_outcome creates PlannerOutcomeAdapter and records."""
    rt, _mock_phase, _mock_analysis, _mock_store = _make_runtime()

    class FakeProvenance:
        input_summary = None
        rows = ()
        accepted_count = 1

    rt.record_planner_outcome(func_ea=0x5000, provenance=FakeProvenance())
    reports = rt.outcome_log.get_func_reports(0x5000)
    assert len(reports) == 1
    assert reports[0].consumer_name == "hodur_planner"


def test_record_flow_gate_outcome() -> None:
    """record_flow_gate_outcome creates FlowGateOutcomeAdapter and records."""
    rt, _mock_phase, _mock_analysis, _mock_store = _make_runtime()

    class FakeDecision:
        allowed = True

    rt.record_flow_gate_outcome(func_ea=0x6000, decision=FakeDecision())
    reports = rt.outcome_log.get_func_reports(0x6000)
    assert len(reports) == 1
    assert reports[0].consumer_name == "flow_gate"


def test_record_flow_gate_outcome_with_gate_name() -> None:
    """record_flow_gate_outcome with custom gate_name uses that name."""
    rt, _mock_phase, _mock_analysis, _mock_store = _make_runtime()

    class FakeDecision:
        allowed = True

    rt.record_flow_gate_outcome(
        func_ea=0x6000,
        decision=FakeDecision(),
        gate_name="unflattening_gate",
    )
    reports = rt.outcome_log.get_func_reports(0x6000)
    assert len(reports) == 1
    assert reports[0].consumer_name == "unflattening_gate"


def test_mark_decompilation_finished_logs_summary() -> None:
    """mark_decompilation_finished logs outcome summary when func was active."""
    rt, _mock_phase, _mock_analysis, _mock_store = _make_runtime()

    # Set active function
    rt.reset_for_func(_FUNC_EA)

    # Record an outcome
    rt.record_rule_scope_outcome(
        func_ea=_FUNC_EA,
        hints=_make_hints(),
        apply_result=None,
        source="analyzed",
    )
    rt.mark_decompilation_finished()
    summary = rt.get_outcome_summary(_FUNC_EA)
    assert len(summary["consumers"]) != 0


def test_mark_decompilation_finished_no_log_when_no_outcomes() -> None:
    """mark_decompilation_finished does not log when no outcomes recorded."""
    rt, _mock_phase, _mock_analysis, _mock_store = _make_runtime()

    rt.reset_for_func(_FUNC_EA)

    rt.mark_decompilation_finished()
    summary = rt.get_outcome_summary(_FUNC_EA)
    assert len(summary["consumers"]) == 0


def test_get_outcome_summary() -> None:
    """get_outcome_summary delegates to outcome log summary."""
    rt, _mock_phase, _mock_analysis, _mock_store = _make_runtime()

    rt.record_rule_scope_outcome(
        func_ea=_FUNC_EA,
        hints=_make_hints(),
        apply_result=None,
        source="analyzed",
    )

    summary = rt.get_outcome_summary(_FUNC_EA)
    assert summary["func_ea"] == _FUNC_EA
    assert len(summary["consumers"]) == 1
    assert summary["consumers"][0]["name"] == "rule_scope"


# ---------------------------------------------------------------------------
# Persistence on decompilation finish
# ---------------------------------------------------------------------------


def test_mark_decompilation_finished_persists_outcomes() -> None:
    """mark_decompilation_finished calls _persist_outcomes which saves to store."""
    rt, _mock_phase, _mock_analysis, mock_store = _make_runtime()

    # Set up active function with hints and an outcome
    rt.reset_for_func(_FUNC_EA)

    hints = _make_hints()
    mock_store.load_hints.return_value = hints

    results = [_make_recon_result()]
    mock_store.load_all_recon_results.return_value = results

    # Record a consumer outcome
    rt.record_rule_scope_outcome(
        func_ea=_FUNC_EA,
        hints=hints,
        apply_result=None,
        source="analyzed",
    )

    rt.mark_decompilation_finished()

    # Session summaries are persisted eagerly by analyze_and_persist,
    # not by _persist_outcomes, so no save_session_summary call here.
    mock_store.save_session_summary.assert_not_called()
    # Consumer outcome was persisted
    mock_store.save_consumer_outcome.assert_called_once()
    outcome_call = mock_store.save_consumer_outcome.call_args
    assert outcome_call.kwargs["func_ea"] == _FUNC_EA
    assert outcome_call.kwargs["consumer_name"] == "rule_scope"
    assert outcome_call.kwargs["artifacts_available"] is True
    assert outcome_call.kwargs["summary_available"] is True
    assert outcome_call.kwargs["verdict_applied"] is False


def test_mark_decompilation_finished_no_hints_still_persists_outcomes() -> None:
    """Even without hints, consumer outcomes are persisted by _persist_outcomes."""
    rt, _mock_phase, _mock_analysis, mock_store = _make_runtime()

    rt.reset_for_func(_FUNC_EA)

    # Record a consumer outcome
    rt.record_rule_scope_outcome(
        func_ea=_FUNC_EA,
        hints=None,
        apply_result=None,
        source="unavailable",
    )

    rt.mark_decompilation_finished()

    # Session summaries are handled eagerly, not here
    mock_store.save_session_summary.assert_not_called()
    # Consumer outcome still persisted
    mock_store.save_consumer_outcome.assert_called_once()
