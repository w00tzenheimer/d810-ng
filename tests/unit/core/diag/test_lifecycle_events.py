from __future__ import annotations

from unittest.mock import patch

import pytest

from d810.core.diag import create_diag_database
from d810.core.diag.event_handlers import (
    install_diag_event_handlers,
    uninstall_diag_event_handlers,
)
from d810.core.observability import SnapshotRef, emit, reset_diagnostic_bus
from d810.core.observability_events import (
    CaptureMbaSnapshotRequested,
    DiagnosticSessionObserved,
    LifecycleEventObserved,
)
from d810.core.observability_models import BlockSnapshot


@pytest.fixture
def diag_conn():
    return create_diag_database(":memory:").connection()


@pytest.fixture(autouse=True)
def lifecycle_sink(diag_conn):
    reset_diagnostic_bus()
    with patch(
        "d810.core.diag.event_handlers.get_diag_conn",
        new=lambda *_args, **_kwargs: diag_conn,
    ):
        install_diag_event_handlers()
        yield
        uninstall_diag_event_handlers()
    reset_diagnostic_bus()


def test_lifecycle_events_are_session_ordered_and_snapshot_correlation_is_explicit(
    diag_conn,
) -> None:
    emit(
        DiagnosticSessionObserved(
            session_id="session-1",
            func_ea=0x40C8B0,
            top_level_epoch=7,
            native_key_json='{"schema_version":1}',
            status="active",
        )
    )
    # Re-observation after the diagnostic sink opens is idempotent. This is
    # the native-preflight-before-prolog ordering exercised by live Hex-Rays.
    emit(
        DiagnosticSessionObserved(
            session_id="session-1",
            func_ea=0x40C8B0,
            top_level_epoch=7,
            native_key_json='{"schema_version":1}',
            status="active",
        )
    )
    emit(
        LifecycleEventObserved(
            session_id="session-1",
            func_ea=0x40C8B0,
            event_kind="evidence_published",
            evidence_generation=3,
            mba_generation_before=8,
            mba_generation_after=8,
            summary="portable route published",
        )
    )
    snapshot = SnapshotRef(
        key="snapshot-1",
        func_ea=0x40C8B0,
        label="calls",
        maturity="MMAT_CALLS",
        phase="post_pipeline",
    )
    emit(
        CaptureMbaSnapshotRequested(
            snapshot=snapshot,
            blocks=(
                BlockSnapshot(
                    serial=0,
                    block_type=1,
                    type_name="BLT_1WAY",
                    start_ea=0x40C8B0,
                ),
            ),
        )
    )
    emit(
        LifecycleEventObserved(
            session_id="session-1",
            func_ea=0x40C8B0,
            event_kind="normalization_published_postvalidated",
            snapshot=snapshot,
            evidence_generation=3,
            mba_generation_before=8,
            mba_generation_after=9,
            summary="PREOPT rebound",
        )
    )
    emit(
        LifecycleEventObserved(
            session_id="session-1",
            func_ea=0x40C8B0,
            event_kind="calls_consumed",
            evidence_generation=4,
            mba_generation_before=9,
            mba_generation_after=9,
            summary="CALLS consumed route",
        )
    )

    rows = diag_conn.execute(
        "SELECT event_seq,event_kind,snapshot_id,evidence_generation,"
        "mba_generation_before,mba_generation_after "
        "FROM lifecycle_events ORDER BY event_seq"
    ).fetchall()
    assert rows == [
        (1, "session_active", None, None, None, None),
        (2, "evidence_published", None, 3, 8, 8),
        (3, "normalization_published_postvalidated", 1, 3, 8, 9),
        (4, "calls_consumed", None, 4, 9, 9),
    ]


def test_session_status_transitions_are_owned_by_one_event(diag_conn) -> None:
    active = DiagnosticSessionObserved(
        "session-1", 0x40C8B0, 7, '{"schema_version":1}', "active", 10.0
    )
    emit(active)
    emit(active)
    emit(
        DiagnosticSessionObserved(
            "session-1", 0x40C8B0, 7, '{"schema_version":1}', "finished", 20.0
        )
    )
    emit(
        DiagnosticSessionObserved(
            "session-1", 0x40C8B0, 7, '{"schema_version":1}', "finished", 30.0
        )
    )

    assert diag_conn.execute(
        "SELECT status,started_at,finished_at FROM diagnostic_sessions"
    ).fetchone() == ("finished", 10.0, 20.0)
    assert diag_conn.execute(
        "SELECT event_seq,event_kind,timestamp FROM lifecycle_events ORDER BY event_seq"
    ).fetchall() == [
        (1, "session_active", 10.0),
        (2, "session_finished", 20.0),
    ]
