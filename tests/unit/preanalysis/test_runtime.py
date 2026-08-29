"""Unit tests for the split preanalysis and consumer-analysis runtimes."""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from types import MappingProxyType
from unittest.mock import MagicMock, call, create_autospec, patch

import pytest

from d810.core import ProviderPhaseSnapshot
from d810.core.decompilation_session import DecompilationSessionEvent
from d810.core.diag.models import FactConsumer, Snapshot
from d810.core.settings import configure_settings, reset_settings
from d810.passes.analysis import AnalysisPhase
from d810.analyses.value_flow.facts import FactConsumerRecord, FactObservation
from d810.analyses.control_flow.models import DeobfuscationHints, PreanalysisResult
from d810.passes.phase import PreanalysisPhase
from d810.passes.preanalysis_runtime import PreanalysisRuntime
from d810.passes.runtime import DecompilationAnalysisRuntime
from d810.passes.store import PreanalysisStore
from tests.unit.core.diag._orm_bind import make_bound_diag_db

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_FUNC_EA = 0x401000
_MATURITY = 5
_SENTINEL_TARGET = object()


class _CountingConnection:
    def __init__(self, connection, *, fail_select_once=False):
        self.connection = connection
        self.fail_select_once = fail_select_once
        self.select_count = 0

    def execute(self, sql, params=()):
        if str(sql).startswith("SELECT 1 FROM fact_consumers"):
            self.select_count += 1
            if self.fail_select_once:
                self.fail_select_once = False
                raise sqlite3.OperationalError("select")
        return self.connection.execute(sql, params)

    def __getattr__(self, name):
        return getattr(self.connection, name)


class _AbsentFactConsumerConnection:
    """Thread-safe raw-SQL stand-in for a fact-consumer row miss."""

    class _Result:
        @staticmethod
        def fetchone():
            return None

    def execute(self, _sql, _params=()):
        return self._Result()


def _phase(
    level: int = _MATURITY, friendly: str | None = None
) -> ProviderPhaseSnapshot:
    return ProviderPhaseSnapshot(
        provider_name="hexrays_microcode",
        provider_level=level,
        friendly_provider_level=friendly or f"MMAT_{level}",
    )


def _event(func_ea: int = _FUNC_EA, epoch: int = 1) -> DecompilationSessionEvent:
    return DecompilationSessionEvent(
        function_ea=func_ea,
        database_identity="test.i64",
        top_level_epoch=epoch,
    )


def _make_preanalysis_result(
    collector_name: str = "CFGShapeCollector",
    func_ea: int = _FUNC_EA,
    maturity: int = _MATURITY,
) -> PreanalysisResult:
    return PreanalysisResult(
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
        suppress_stages=(),
    )


def _make_runtime(
    *,
    validated_fact_view_provider=None,
) -> tuple[DecompilationAnalysisRuntime, MagicMock, MagicMock, MagicMock]:
    "Build a runtime with mocked dependencies.\n\n    Returns (runtime, mock_phase, mock_analysis, mock_store).\n    Patches ``get_preanalysis_writer`` so writes execute synchronously on mock_store.\n"
    mock_phase = create_autospec(PreanalysisPhase, instance=True)
    mock_analysis = create_autospec(AnalysisPhase, instance=True)
    mock_store = create_autospec(PreanalysisStore, instance=True)
    mock_store.db_path = Path("/tmp/test_preanalysis.db")

    writer = _make_sync_writer(mock_store)
    p1 = patch("d810.passes.runtime.get_preanalysis_writer", return_value=writer)
    p2 = patch("d810.passes.phase.get_preanalysis_writer", return_value=writer)
    p1.start()
    p2.start()
    _active_patchers.extend([p1, p2])

    rt = DecompilationAnalysisRuntime(
        mock_analysis,
        mock_store,
        validated_fact_view_provider=validated_fact_view_provider,
    )
    return rt, mock_phase, mock_analysis, mock_store


def _make_preanalysis_runtime() -> tuple[PreanalysisRuntime, MagicMock, MagicMock]:
    mock_phase = create_autospec(PreanalysisPhase, instance=True)
    mock_store = create_autospec(PreanalysisStore, instance=True)
    mock_store.db_path = Path("/tmp/test_preanalysis.db")
    writer = _make_sync_writer(mock_store)
    patches = (
        patch(
            "d810.passes.preanalysis_runtime.get_preanalysis_writer",
            return_value=writer,
        ),
        patch("d810.passes.phase.get_preanalysis_writer", return_value=writer),
    )
    for active in patches:
        active.start()
        _active_patchers.append(active)
    return (
        PreanalysisRuntime(phase=mock_phase, store=mock_store),
        mock_phase,
        mock_store,
    )


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


def test_preanalysis_capture_and_consumer_analysis_are_separate() -> None:
    preanalysis, mock_phase, _mock_store = _make_preanalysis_runtime()
    analysis, _unused_phase, mock_analysis, analysis_store = _make_runtime()
    results = [_make_preanalysis_result()]
    hints = _make_hints()
    analysis_store.load_all_preanalysis_results.return_value = results
    mock_analysis.interpret.return_value = hints

    preanalysis.capture_flowgraph(
        _SENTINEL_TARGET,
        func_ea=_FUNC_EA,
        provider_phase=_phase(),
    )
    returned = analysis.analyze(_FUNC_EA)

    mock_phase.run_microcode_collectors.assert_called_once_with(
        _SENTINEL_TARGET,
        func_ea=_FUNC_EA,
        provider_phase=_phase(),
    )
    mock_analysis.interpret.assert_called_once_with(
        func_ea=_FUNC_EA,
        results=results,
        store=analysis_store,
    )
    analysis_store.save_hints.assert_called_once_with(hints)
    assert returned is hints


def test_analysis_runtime_has_no_raw_collection_compatibility_api() -> None:
    runtime, _phase, _analysis, _store = _make_runtime()

    assert not hasattr(runtime, "collect_and_analyze")
    assert not hasattr(runtime, "capture_maturity_facts")
    assert not hasattr(runtime, "register_fact_collector")
    assert hasattr(runtime, "validated_fact_view")
    assert not hasattr(runtime, "load_or_analyze")


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
    rt, _mock_phase, _mock_store = _make_preanalysis_runtime()

    summary = rt.capture_facts(
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
    rt, _mock_phase, _mock_store = _make_preanalysis_runtime()

    first = rt.capture_facts(
        object(),
        func_ea=_FUNC_EA,
        provider_phase=_phase(1),
        phase="pre_d810",
    )
    second = rt.capture_facts(
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
    rt, _mock_phase, _mock_store = _make_preanalysis_runtime()
    rt.register_fact_collector(_Collector())

    db = make_bound_diag_db()
    conn = db.connection()
    Snapshot.insert(
        id=1,
        label="test",
        func_ea_hex="0x0000000000401000",
        func_ea_i64=0x401000,
        maturity="MMAT_GLBOPT1",
        phase="pre_d810",
        block_count=1,
        timestamp=0.0,
    ).execute()

    # Wire the abstract observability backend to the test conn and bind
    # a SnapshotRef whose key resolves to snap_id=1 in this fixture.
    from d810.core.diag.event_handlers import (
        _bind_snapshot_id,
        install_diag_event_handlers,
        uninstall_diag_event_handlers,
    )
    from d810.core.observability import SnapshotRef

    install_diag_event_handlers()
    snap_ref = SnapshotRef(
        key="test-key",
        func_ea=_FUNC_EA,
        label="test",
        maturity="MMAT_GLBOPT1",
        phase="pre_d810",
    )
    _bind_snapshot_id(snap_ref, 1)
    try:
        with patch(
            "d810.core.diag.event_handlers.get_diag_conn",
            return_value=conn,
        ):
            summary = rt.capture_facts(
                object(),
                func_ea=_FUNC_EA,
                provider_phase=_phase(),
                phase="pre_d810",
                snapshot=snap_ref,
            )
    finally:
        uninstall_diag_event_handlers()

    assert summary.observation_count == 1
    from d810.core.diag.models import FactObservation as FactObservationModel

    row = (
        FactObservationModel.select(
            FactObservationModel.kind, FactObservationModel.source_block
        )
        .where(FactObservationModel.fact_id == "induction:runtime")
        .tuples()
        .first()
    )
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
    preanalysis, _mock_phase, _mock_store = _make_preanalysis_runtime()
    preanalysis.register_fact_collector(_Collector())
    analysis, _unused_phase, _unused_analysis, _unused_store = _make_runtime(
        validated_fact_view_provider=preanalysis._validated_fact_view,
    )

    preanalysis.capture_facts(
        object(),
        func_ea=_FUNC_EA,
        provider_phase=_phase(),
        phase="pre_d810",
    )

    view = analysis.validated_fact_view(_FUNC_EA, _MATURITY)

    assert not hasattr(preanalysis, "validated_fact_view")
    assert len(view.observations) == 1
    assert len(view.active_observations) == 1
    assert view.observations[0].fact_id == "induction:runtime"


def test_record_fact_consumers_deduplicates_only_within_latest_diag_snapshot() -> None:
    db = make_bound_diag_db()
    conn = db.connection()
    Snapshot.insert(
        id=7,
        label="pre",
        func_ea_hex=f"0x{_FUNC_EA:016x}",
        func_ea_i64=_FUNC_EA,
        maturity="MMAT_GLBOPT1",
        phase="pre_d810",
        block_count=3,
        timestamp=0.0,
    ).execute()
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
        install_diag_event_handlers,
        uninstall_diag_event_handlers,
    )

    install_diag_event_handlers()
    try:
        with patch(
            "d810.core.diag.event_handlers.get_diag_conn",
            return_value=conn,
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
            "d810.core.diag.event_handlers.get_diag_conn",
            return_value=conn,
        ):
            # New emit; subscriber sees the row already exists and dedups.
            rt.record_fact_consumers(_FUNC_EA, (record,))

        assert FactConsumer.select().count() == 1

        changed_same_snapshot = FactConsumerRecord(
            consumer=record.consumer,
            strategy=record.strategy,
            fact_id=record.fact_id,
            maturity=record.maturity,
            decision=record.decision,
            reason="changed-reason",
            payload={"active": 1, "evidence_generation": 2},
        )
        with patch(
            "d810.core.diag.event_handlers.get_diag_conn",
            return_value=conn,
        ):
            rt.record_fact_consumers(_FUNC_EA, (changed_same_snapshot,))

        assert FactConsumer.select().count() == 2

        Snapshot.insert(
            id=8,
            label="next-pre",
            func_ea_hex=f"0x{_FUNC_EA:016x}",
            func_ea_i64=_FUNC_EA,
            maturity="MMAT_GLBOPT1",
            phase="pre_d810",
            block_count=4,
            timestamp=1.0,
        ).execute()
        next_record = FactConsumerRecord(
            consumer=record.consumer,
            strategy=record.strategy,
            fact_id=record.fact_id,
            maturity=record.maturity,
            decision=record.decision,
            reason="next-generation",
            payload={"active": 1},
        )
        with patch(
            "d810.core.diag.event_handlers.get_diag_conn",
            return_value=conn,
        ):
            rt.record_fact_consumers(_FUNC_EA, (next_record,))

        rows = conn.execute(
            "SELECT snapshot_id, reason, payload FROM fact_consumers "
            "ORDER BY snapshot_id"
        ).fetchall()
        assert [
            (snapshot_id, reason, json.loads(payload))
            for snapshot_id, reason, payload in rows
        ] == [
            (7, "unit-test", {"active": 0}),
            (7, "changed-reason", {"active": 1, "evidence_generation": 2}),
            (8, "next-generation", {"active": 1}),
        ]
    finally:
        uninstall_diag_event_handlers()


def _insert_latest_fact_consumer_snapshot(db, snapshot_id: int) -> None:
    from d810.core.diag import diag_models_on

    with diag_models_on(db):
        Snapshot.insert(
            id=snapshot_id,
            label="pre",
            func_ea_hex=f"0x{_FUNC_EA:016x}",
            func_ea_i64=_FUNC_EA,
            maturity="MMAT_CALLS",
            phase="pre_d810",
            block_count=1,
            timestamp=0.0,
        ).execute()


def _latest_fact_consumer_event(*records):
    from d810.core.observability_events import FactConsumersForLatestSnapshot

    return FactConsumersForLatestSnapshot(_FUNC_EA, tuple(records))


def _recovery_gate_record(**changes) -> FactConsumerRecord:
    values = {
        "consumer": "state_machine_cff_unflattener",
        "strategy": "recovery_gate",
        "fact_id": "resolver_session:indirect_dispatcher_materialized",
        "maturity": "MMAT_CALLS",
        "decision": "declined",
        "reason": "maturity_not_registered",
        "payload": {
            "evidence_generation": 0,
            "normalization_published_postvalidated_generation": None,
            "imported_identity_ready": None,
            "indirect_dispatcher_materialized": False,
            "recovery_epoch_phase": 0,
            "resolver_session_present": False,
            "rounds_before": 0,
        },
    }
    values.update(changes)
    return FactConsumerRecord(**values)


def test_latest_fact_consumer_handler_keeps_full_recovery_identity() -> None:
    from d810.core.diag import event_handlers

    db = make_bound_diag_db()
    conn = db.connection()
    _insert_latest_fact_consumer_snapshot(db, 31)
    record = _recovery_gate_record()
    changed_decision = _recovery_gate_record(decision="accepted")
    changed_maturity = _recovery_gate_record(maturity="MMAT_GLBOPT1")
    event_handlers.uninstall_diag_event_handlers()
    try:
        with patch("d810.core.diag.event_handlers.get_diag_conn", return_value=conn):
            event_handlers._handle_fact_consumers_latest(
                _latest_fact_consumer_event(record, record)
            )
            event_handlers._handle_fact_consumers_latest(
                _latest_fact_consumer_event(changed_decision)
            )
            event_handlers._handle_fact_consumers_latest(
                _latest_fact_consumer_event(changed_maturity)
            )
        assert FactConsumer.select().count() == 3

        _insert_latest_fact_consumer_snapshot(db, 32)
        with patch("d810.core.diag.event_handlers.get_diag_conn", return_value=conn):
            event_handlers._handle_fact_consumers_latest(
                _latest_fact_consumer_event(record)
            )
        assert FactConsumer.select().where(FactConsumer.snapshot == 32).count() == 1
    finally:
        event_handlers.uninstall_diag_event_handlers()


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("evidence_generation", 1),
        ("normalization_published_postvalidated_generation", 1),
        ("imported_identity_ready", True),
        ("indirect_dispatcher_materialized", True),
        ("recovery_epoch_phase", 1),
        ("resolver_session_present", True),
        ("rounds_before", 1),
    ),
)
def test_latest_recovery_payload_field_change_is_distinct(field, value) -> None:
    from d810.core.diag import event_handlers

    db = make_bound_diag_db()
    conn = db.connection()
    _insert_latest_fact_consumer_snapshot(db, 41)
    record = _recovery_gate_record()
    changed = _recovery_gate_record(payload={**record.payload, field: value})
    event_handlers.uninstall_diag_event_handlers()
    try:
        with patch("d810.core.diag.event_handlers.get_diag_conn", return_value=conn):
            event_handlers._handle_fact_consumers_latest(
                _latest_fact_consumer_event(record, changed)
            )
        assert FactConsumer.select().count() == 2
    finally:
        event_handlers.uninstall_diag_event_handlers()


def test_latest_fact_consumer_insert_failure_does_not_warm_cache() -> None:
    from d810.core.diag import event_handlers

    db = make_bound_diag_db()
    conn = db.connection()
    _insert_latest_fact_consumer_snapshot(db, 52)
    event = _latest_fact_consumer_event(
        FactConsumerRecord("other", "non_recovery", "fact", "MMAT_CALLS", "declined", "retry", {"v": 1})
    )
    event_handlers.uninstall_diag_event_handlers()
    try:
        with patch("d810.core.diag.event_handlers.get_diag_conn", return_value=conn), patch.object(
            event_handlers,
            "snapshot_fact_consumers",
            side_effect=sqlite3.OperationalError("insert"),
        ):
            with pytest.raises(sqlite3.OperationalError, match="insert"):
                event_handlers._handle_fact_consumers_latest(event)
        with patch("d810.core.diag.event_handlers.get_diag_conn", return_value=conn), patch.object(
            event_handlers, "snapshot_fact_consumers", wraps=event_handlers.snapshot_fact_consumers
        ) as writer:
            event_handlers._handle_fact_consumers_latest(event)
        assert writer.call_count == 1
        assert FactConsumer.select().count() == 1
    finally:
        event_handlers.uninstall_diag_event_handlers()


def test_latest_fact_consumer_cache_is_cold_after_uninstall_and_reinstall() -> None:
    from d810.core.diag import event_handlers

    db = make_bound_diag_db()
    conn = _CountingConnection(db.connection())
    _insert_latest_fact_consumer_snapshot(db, 61)
    event = _latest_fact_consumer_event(
        FactConsumerRecord("other", "non_recovery", "fact", "MMAT_CALLS", "declined", "same", {"v": 1})
    )
    event_handlers.uninstall_diag_event_handlers()
    try:
        with patch("d810.core.diag.event_handlers.get_diag_conn", return_value=conn):
            event_handlers._handle_fact_consumers_latest(event)
            event_handlers._handle_fact_consumers_latest(event)
            assert conn.select_count == 1
            event_handlers.uninstall_diag_event_handlers()
            event_handlers.install_diag_event_handlers()
            event_handlers._handle_fact_consumers_latest(event)
        assert conn.select_count == 2
        assert FactConsumer.select().count() == 1
    finally:
        event_handlers.uninstall_diag_event_handlers()


def test_latest_fact_consumer_select_retry_and_warm_cache_query_count() -> None:
    from d810.core.diag import event_handlers

    db = make_bound_diag_db()
    conn = _CountingConnection(db.connection(), fail_select_once=True)
    _insert_latest_fact_consumer_snapshot(db, 71)
    event = _latest_fact_consumer_event(
        FactConsumerRecord("other", "non_recovery", "fact", "MMAT_CALLS", "declined", "retry", {"v": 1})
    )
    event_handlers.uninstall_diag_event_handlers()
    try:
        with patch("d810.core.diag.event_handlers.get_diag_conn", return_value=conn):
            with pytest.raises(sqlite3.OperationalError, match="select"):
                event_handlers._handle_fact_consumers_latest(event)
            event_handlers._handle_fact_consumers_latest(event)
            assert conn.select_count == 2
            event_handlers._handle_fact_consumers_latest(event)
        assert conn.select_count == 2
        assert FactConsumer.select().count() == 1
    finally:
        event_handlers.uninstall_diag_event_handlers()


def test_latest_fact_consumer_cache_does_not_cross_bound_databases(tmp_path) -> None:
    from d810.core.diag import create_diag_database, diag_models_on, event_handlers

    event = _latest_fact_consumer_event(
        FactConsumerRecord("other", "non_recovery", "fact", "MMAT_CALLS", "declined", "same", {"v": 1})
    )
    event_handlers.uninstall_diag_event_handlers()
    try:
        for database_path in (tmp_path / "first.sqlite", tmp_path / "second.sqlite"):
            # create_diag_database resets the active writer database.  Each
            # path therefore supplies an independent connection and binding.
            db = create_diag_database(str(database_path))
            try:
                _insert_latest_fact_consumer_snapshot(db, 81)
                conn = db.connection()
                with patch("d810.core.diag.event_handlers.get_diag_conn", return_value=conn):
                    event_handlers._handle_fact_consumers_latest(event)
                with diag_models_on(db):
                    assert FactConsumer.select().count() == 1
            finally:
                db.close()
    finally:
        event_handlers.uninstall_diag_event_handlers()


def test_latest_fact_consumer_concurrent_duplicates_write_one_semantic_row() -> None:
    """A blocked first write keeps an identical concurrent event out of the writer."""
    from d810.core.diag import event_handlers

    db = make_bound_diag_db()
    conn = _AbsentFactConsumerConnection()
    event = _latest_fact_consumer_event(
        FactConsumerRecord("other", "non_recovery", "fact", "MMAT_CALLS", "declined", "same", {"v": 1})
    )
    first_writer = threading.Barrier(2)
    release_first_writer = threading.Event()
    second_writer_entered = threading.Event()
    persisted_rows = []
    writer_lock = threading.Lock()

    def writer(*_args):
        with writer_lock:
            persisted_rows.append(object())
            is_first = len(persisted_rows) == 1
        if is_first:
            first_writer.wait()
            assert release_first_writer.wait(timeout=1)
        else:
            second_writer_entered.set()

    def handle() -> None:
        event_handlers._handle_fact_consumers_latest(event)

    event_handlers.uninstall_diag_event_handlers()
    try:
        with patch("d810.core.diag.event_handlers.get_diag_conn", return_value=conn), patch.object(
            event_handlers, "_latest_snapshot_id_for_func", return_value=91
        ), patch.object(event_handlers, "snapshot_fact_consumers", side_effect=writer):
            first = threading.Thread(target=handle)
            second = threading.Thread(target=handle)
            first.start()
            first_writer.wait()
            second.start()
            try:
                assert not second_writer_entered.wait(timeout=0.1)
            finally:
                release_first_writer.set()
            first.join(timeout=1)
            second.join(timeout=1)
        assert not first.is_alive()
        assert not second.is_alive()
        assert len(persisted_rows) == 1
    finally:
        event_handlers.uninstall_diag_event_handlers()


def test_latest_fact_consumer_uninstall_waits_for_inflight_write_and_leaves_cache_cold() -> None:
    """Uninstall cannot finish before an in-flight handler has finished warming."""
    from d810.core.diag import event_handlers

    db = make_bound_diag_db()
    conn = _AbsentFactConsumerConnection()
    event = _latest_fact_consumer_event(
        FactConsumerRecord("other", "non_recovery", "fact", "MMAT_CALLS", "declined", "same", {"v": 1})
    )
    writer_started = threading.Barrier(2)
    release_writer = threading.Event()
    uninstall_done = threading.Event()
    writer_calls = []

    def writer(*_args):
        writer_calls.append(object())
        if len(writer_calls) == 1:
            writer_started.wait()
            assert release_writer.wait(timeout=1)

    def handle() -> None:
        event_handlers._handle_fact_consumers_latest(event)

    def uninstall() -> None:
        event_handlers.uninstall_diag_event_handlers()
        uninstall_done.set()

    event_handlers.uninstall_diag_event_handlers()
    try:
        with patch("d810.core.diag.event_handlers.get_diag_conn", return_value=conn), patch.object(
            event_handlers, "_latest_snapshot_id_for_func", return_value=92
        ), patch.object(event_handlers, "snapshot_fact_consumers", side_effect=writer):
            handler = threading.Thread(target=handle)
            handler.start()
            writer_started.wait()
            uninstaller = threading.Thread(target=uninstall)
            uninstaller.start()
            try:
                assert not uninstall_done.wait(timeout=0.1)
            finally:
                release_writer.set()
            handler.join(timeout=1)
            uninstaller.join(timeout=1)
            assert not handler.is_alive()
            assert not uninstaller.is_alive()
            assert not event_handlers._LATEST_FACT_CONSUMER_KEYS
            assert not event_handlers._LATEST_FACT_CONSUMER_SNAPSHOTS
            event_handlers.install_diag_event_handlers()
            event_handlers._handle_fact_consumers_latest(event)
            assert len(writer_calls) == 2
    finally:
        event_handlers.uninstall_diag_event_handlers()


def test_latest_fact_consumer_prunes_old_snapshot_cache_keys() -> None:
    from d810.core.diag import event_handlers

    db = make_bound_diag_db()
    conn = _CountingConnection(db.connection())
    _insert_latest_fact_consumer_snapshot(db, 101)
    event = _latest_fact_consumer_event(
        FactConsumerRecord("other", "non_recovery", "fact", "MMAT_CALLS", "declined", "same", {"v": 1})
    )
    event_handlers.uninstall_diag_event_handlers()
    try:
        with patch("d810.core.diag.event_handlers.get_diag_conn", return_value=conn):
            event_handlers._handle_fact_consumers_latest(event)
            _insert_latest_fact_consumer_snapshot(db, 102)
            event_handlers._handle_fact_consumers_latest(event)
        assert {key[2] for key in event_handlers._LATEST_FACT_CONSUMER_KEYS} == {102}
        assert event_handlers._LATEST_FACT_CONSUMER_SNAPSHOTS[(conn, _FUNC_EA)] == 102
    finally:
        event_handlers.uninstall_diag_event_handlers()


def test_begin_session_clears_fired_and_store() -> None:
    """Preanalysis begin resets collector state and stored raw evidence."""
    rt, mock_phase, mock_store = _make_preanalysis_runtime()

    result = rt.begin_session(_event())

    assert result is None
    mock_phase.reset.assert_called_once_with(func_ea=_FUNC_EA)
    mock_store.clear_func.assert_called_once_with(func_ea=_FUNC_EA)


def test_analyze_with_results() -> None:
    """analyze runs analysis and saves hints when results exist."""
    rt, _mock_phase, mock_analysis, mock_store = _make_runtime()

    results = [_make_preanalysis_result()]
    hints = _make_hints()

    mock_store.load_all_preanalysis_results.return_value = results
    mock_analysis.interpret.return_value = hints

    returned = rt.analyze(_FUNC_EA)

    assert returned is hints
    mock_store.load_all_preanalysis_results.assert_called_once_with(func_ea=_FUNC_EA)
    mock_analysis.interpret.assert_called_once_with(
        func_ea=_FUNC_EA,
        results=results,
        store=mock_store,
    )
    mock_store.save_hints.assert_called_once_with(hints)


def test_analyze_no_results() -> None:
    "analyze returns None when store has no preanalysis results."
    rt, _mock_phase, mock_analysis, mock_store = _make_runtime()

    mock_store.load_all_preanalysis_results.return_value = []

    returned = rt.analyze(_FUNC_EA)

    assert returned is None
    mock_store.load_all_preanalysis_results.assert_called_once_with(func_ea=_FUNC_EA)
    mock_analysis.interpret.assert_not_called()
    mock_store.save_hints.assert_not_called()


def test_analyze_overwrites_previous_hints() -> None:
    """analyze overwrites hints on re-analysis."""
    rt, _mock_phase, mock_analysis, mock_store = _make_runtime()

    results_v1 = [_make_preanalysis_result()]
    hints_v1 = _make_hints(confidence=0.60)
    results_v2 = [
        _make_preanalysis_result(),
        _make_preanalysis_result("DispatchPatternCollector"),
    ]
    hints_v2 = _make_hints(confidence=0.95)

    # First call
    mock_store.load_all_preanalysis_results.return_value = results_v1
    mock_analysis.interpret.return_value = hints_v1
    ret1 = rt.analyze(_FUNC_EA)

    # Second call with more results
    mock_store.load_all_preanalysis_results.return_value = results_v2
    mock_analysis.interpret.return_value = hints_v2
    ret2 = rt.analyze(_FUNC_EA)

    assert ret1 is hints_v1
    assert ret2 is hints_v2
    assert mock_store.save_hints.call_count == 2
    mock_store.save_hints.assert_any_call(hints_v1)
    mock_store.save_hints.assert_any_call(hints_v2)


def test_preanalysis_capture_delegates_portable_graph_to_phase() -> None:
    rt, mock_phase, _mock_store = _make_preanalysis_runtime()

    rt.capture_flowgraph(
        _SENTINEL_TARGET,
        func_ea=_FUNC_EA,
        provider_phase=_phase(),
    )

    mock_phase.run_microcode_collectors.assert_called_once_with(
        _SENTINEL_TARGET,
        func_ea=_FUNC_EA,
        provider_phase=_phase(),
    )


# ---------------------------------------------------------------------------
# Dedup: reset fires exactly once per decompilation, across managers
# ---------------------------------------------------------------------------


def test_reset_deduplicates_across_calls() -> None:
    """Analysis outcome reset is idempotent for one active function."""
    rt, _mock_phase, _mock_analysis, _mock_store = _make_runtime()

    assert rt.begin_session(_event()) is True

    assert rt.begin_session(_event()) is False


def test_finish_session_allows_analysis_outcome_reset() -> None:
    rt, _mock_phase, _mock_analysis, _mock_store = _make_runtime()

    assert rt.begin_session(_event()) is True

    rt.finish_session(_event())

    assert rt.begin_session(_event(epoch=2)) is True


def test_flush_active_session_persists_outcomes_when_structural_finish_is_missing() -> None:
    """Manager shutdown must not lose a callback chain lacking hxe_structural."""
    rt, _mock_phase, _mock_analysis, mock_store = _make_runtime()
    rt.begin_session(_event())
    rt.record_execution_scope_outcome(
        func_ea=_FUNC_EA,
        hints=_make_hints(),
        apply_result=None,
        source="analyzed",
    )

    assert rt.flush_active_session() is True
    assert rt.flush_active_session() is False

    mock_store.save_consumer_outcome.assert_called_once()
    outcome_call = mock_store.save_consumer_outcome.call_args
    assert outcome_call.kwargs["func_ea"] == _FUNC_EA
    assert outcome_call.kwargs["consumer_name"] == "execution_scope"


def test_begin_session_flushes_previous_outcomes() -> None:
    """Switching to func B flushes persisted outcomes for func A.

    When begin_session(B) is called while func A is active, the runtime
    should persist session summary and consumer outcomes for A *before*
    clearing state for B.  This closes the gap where outcomes are lost if
    mark_decompilation_finished is never called (e.g. IDA decompiles A
    then immediately starts B).
    """
    rt, _mock_phase, _mock_analysis, mock_store = _make_runtime()

    func_a = 0x401000
    func_b = 0x402000

    # Activate func A
    rt.begin_session(_event(func_a))

    # Set up store responses for func A's persist path
    hints_a = _make_hints(func_ea=func_a)
    mock_store.load_hints.return_value = hints_a
    results_a = [_make_preanalysis_result(func_ea=func_a)]
    mock_store.load_all_preanalysis_results.return_value = results_a

    # Record an outcome for func A
    rt.record_execution_scope_outcome(
        func_ea=func_a,
        hints=hints_a,
        apply_result=None,
        source="analyzed",
    )

    # Now switch to func B -- should flush func A outcomes first
    rt.begin_session(_event(func_b))

    # Session summaries are persisted eagerly by analyze,
    # not by _persist_outcomes, so no save_session_summary call here.
    mock_store.save_session_summary.assert_not_called()
    # Consumer outcome for func A was persisted
    mock_store.save_consumer_outcome.assert_called_once()
    outcome_call = mock_store.save_consumer_outcome.call_args
    assert outcome_call.kwargs["func_ea"] == func_a
    assert outcome_call.kwargs["consumer_name"] == "execution_scope"


def test_nested_session_reset_restores_parent_without_mark_finished() -> None:
    """An inner decompilation preserves the live parent session.

    The coordinator distinguishes this from an abandoned sequential function
    switch and sets ``preserve_active_session`` for the inner start.
    """
    rt, _mock_phase, _mock_analysis, _mock_store = _make_runtime()
    outer_ea = _FUNC_EA
    inner_ea = 0x402000

    assert rt.begin_session(_event(outer_ea)) is True
    assert (
        rt.begin_session(
            _event(inner_ea),
            preserve_active_session=True,
        )
        is True
    )
    rt.finish_session(_event(inner_ea), resume_event=_event(outer_ea))

    assert rt._current_func_ea == outer_ea


# ---------------------------------------------------------------------------
# Outcome recording
# ---------------------------------------------------------------------------


def test_runtime_record_outcome() -> None:
    """record_outcome delegates to outcome log."""
    rt, _mock_phase, _mock_analysis, _mock_store = _make_runtime()

    from d810.passes.outcome import ExecutionScopeOutcomeAdapter
    from d810.passes.runtime import AnalysisOutcome

    outcome = AnalysisOutcome(
        func_ea=_FUNC_EA,
        hints=_make_hints(),
        apply_result=None,
        source="analyzed",
    )
    adapter = ExecutionScopeOutcomeAdapter(outcome)
    rt.record_outcome(adapter)

    reports = rt.outcome_log.get_func_reports(_FUNC_EA)
    assert len(reports) == 1
    assert reports[0].consumer_name == "execution_scope"
    assert reports[0].func_ea == _FUNC_EA


def test_reset_clears_outcome_log() -> None:
    """begin_session clears outcome entries for the function."""
    rt, _mock_phase, _mock_analysis, _mock_store = _make_runtime()

    from d810.passes.outcome import ExecutionScopeOutcomeAdapter
    from d810.passes.runtime import AnalysisOutcome

    outcome = AnalysisOutcome(
        func_ea=_FUNC_EA,
        hints=_make_hints(),
        apply_result=None,
        source="cached",
    )
    adapter = ExecutionScopeOutcomeAdapter(outcome)
    rt.record_outcome(adapter)
    assert len(rt.outcome_log.get_func_reports(_FUNC_EA)) == 1

    # begin_session should also clear outcome log
    rt.begin_session(_event())
    assert rt.outcome_log.get_func_reports(_FUNC_EA) == []


def test_record_execution_scope_outcome() -> None:
    """record_execution_scope_outcome builds adapter internally and records."""
    rt, _mock_phase, _mock_analysis, _mock_store = _make_runtime()

    hints = _make_hints()
    rt.record_execution_scope_outcome(
        func_ea=_FUNC_EA,
        hints=hints,
        apply_result=None,
        source="analyzed",
    )

    reports = rt.outcome_log.get_func_reports(_FUNC_EA)
    assert len(reports) == 1
    assert reports[0].consumer_name == "execution_scope"
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


def test_finish_session_logs_summary() -> None:
    """finish_session logs the outcome summary for the finished owner."""
    rt, _mock_phase, _mock_analysis, _mock_store = _make_runtime()

    # Set active function
    rt.begin_session(_event())

    # Record an outcome
    rt.record_execution_scope_outcome(
        func_ea=_FUNC_EA,
        hints=_make_hints(),
        apply_result=None,
        source="analyzed",
    )
    rt.finish_session(_event())
    summary = rt.get_outcome_summary(_FUNC_EA)
    assert len(summary["consumers"]) != 0


def test_finish_session_no_log_when_no_outcomes() -> None:
    """finish_session does not log when no outcomes were recorded."""
    rt, _mock_phase, _mock_analysis, _mock_store = _make_runtime()

    rt.begin_session(_event())

    rt.finish_session(_event())
    summary = rt.get_outcome_summary(_FUNC_EA)
    assert len(summary["consumers"]) == 0


def test_get_outcome_summary() -> None:
    """get_outcome_summary delegates to outcome log summary."""
    rt, _mock_phase, _mock_analysis, _mock_store = _make_runtime()

    rt.record_execution_scope_outcome(
        func_ea=_FUNC_EA,
        hints=_make_hints(),
        apply_result=None,
        source="analyzed",
    )

    summary = rt.get_outcome_summary(_FUNC_EA)
    assert summary["func_ea"] == _FUNC_EA
    assert len(summary["consumers"]) == 1
    assert summary["consumers"][0]["name"] == "execution_scope"


# ---------------------------------------------------------------------------
# Persistence on decompilation finish
# ---------------------------------------------------------------------------


def test_finish_session_persists_outcomes() -> None:
    """finish_session persists consumer outcomes to the store."""
    rt, _mock_phase, _mock_analysis, mock_store = _make_runtime()

    # Set up active function with hints and an outcome
    rt.begin_session(_event())

    hints = _make_hints()
    mock_store.load_hints.return_value = hints

    results = [_make_preanalysis_result()]
    mock_store.load_all_preanalysis_results.return_value = results

    # Record a consumer outcome
    rt.record_execution_scope_outcome(
        func_ea=_FUNC_EA,
        hints=hints,
        apply_result=None,
        source="analyzed",
    )

    rt.finish_session(_event())

    # Session summaries are persisted eagerly by analyze,
    # not by _persist_outcomes, so no save_session_summary call here.
    mock_store.save_session_summary.assert_not_called()
    # Consumer outcome was persisted
    mock_store.save_consumer_outcome.assert_called_once()
    outcome_call = mock_store.save_consumer_outcome.call_args
    assert outcome_call.kwargs["func_ea"] == _FUNC_EA
    assert outcome_call.kwargs["consumer_name"] == "execution_scope"
    assert outcome_call.kwargs["artifacts_available"] is True
    assert outcome_call.kwargs["summary_available"] is True
    assert outcome_call.kwargs["verdict_applied"] is False


def test_finish_session_no_hints_still_persists_outcomes() -> None:
    """Even without hints, consumer outcomes are persisted by _persist_outcomes."""
    rt, _mock_phase, _mock_analysis, mock_store = _make_runtime()

    rt.begin_session(_event())

    # Record a consumer outcome
    rt.record_execution_scope_outcome(
        func_ea=_FUNC_EA,
        hints=None,
        apply_result=None,
        source="unavailable",
    )

    rt.finish_session(_event())

    # Session summaries are handled eagerly, not here
    mock_store.save_session_summary.assert_not_called()
    # Consumer outcome still persisted
    mock_store.save_consumer_outcome.assert_called_once()
