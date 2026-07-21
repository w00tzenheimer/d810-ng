from __future__ import annotations

from unittest.mock import patch

import pytest

from d810.core.diag import create_diag_database
from d810.core.diag.event_handlers import install_diag_event_handlers, uninstall_diag_event_handlers
from d810.core.observability import emit, reset_diagnostic_bus
from d810.core.observability_events import (
    DiagnosticSessionObserved,
    EvidenceGenerationObserved,
    IdentityDecisionObserved,
)


@pytest.fixture
def diag_conn():
    return create_diag_database(":memory:").connection()


@pytest.fixture(autouse=True)
def sink(diag_conn):
    reset_diagnostic_bus()
    with patch(
        "d810.core.diag.event_handlers.get_diag_conn",
        new=lambda *_args, **_kwargs: diag_conn,
    ):
        install_diag_event_handlers()
        emit(
            DiagnosticSessionObserved(
                session_id="s1",
                func_ea=0x40C8B0,
                top_level_epoch=1,
                native_key_json='{"schema_version":1}',
                status="active",
            )
        )
        yield
        uninstall_diag_event_handlers()
    reset_diagnostic_bus()


def test_evidence_and_identity_details_share_ordered_envelopes(diag_conn) -> None:
    emit(
        EvidenceGenerationObserved(
            session_id="s1",
            func_ea=0x40C8B0,
            operation="merge",
            previous_generation=2,
            resulting_generation=3,
            evidence_family="bootstrap_route",
            outcome="accepted",
            owner="native_preanalysis",
            reason="new route",
            maturity="MMAT_CALLS",
            phase="calls_done",
        )
    )
    emit(
        IdentityDecisionObserved(
            session_id="s1",
            func_ea=0x40C8B0,
            decision_kind="rebind",
            consumer="preopt_importer",
            identity_role="source",
            native_key_json='{"schema_version":1}',
            exact_eas_json="[4245683]",
            native_ranges_json='[{"start_ea":4245683,"end_ea":4245684}]',
            primary_anchor_ea=0x40C8B3,
            current_serial=17,
            mba_generation=9,
            evidence_generation=3,
            maturity="MMAT_CALLS",
            outcome="bound",
            candidates_json="[]",
            reason="unique exact identity",
        )
    )

    assert diag_conn.execute(
        "SELECT operation,previous_generation,resulting_generation "
        "FROM evidence_generation_events"
    ).fetchone() == ("merge", 2, 3)
    assert diag_conn.execute(
        "SELECT current_serial,primary_anchor_ea_i64,mba_generation,outcome "
        "FROM identity_decisions"
    ).fetchone() == (17, 0x40C8B3, 9, "bound")
    assert diag_conn.execute(
        "SELECT event_seq,event_kind FROM lifecycle_events ORDER BY event_seq"
    ).fetchall() == [
        (1, "session_active"),
        (2, "evidence_generation"),
        (3, "identity_decision"),
    ]


def test_identity_decision_rejects_serial_without_anchor() -> None:
    with pytest.raises(ValueError, match="EA anchor"):
        IdentityDecisionObserved(
            session_id="s1",
            func_ea=0x40C8B0,
            decision_kind="rebind",
            consumer="test",
            identity_role="source",
            native_key_json="{}",
            exact_eas_json="[]",
            native_ranges_json="[]",
            primary_anchor_ea=None,
            current_serial=7,
            mba_generation=1,
            evidence_generation=1,
            maturity="MMAT_CALLS",
            outcome="bound",
            candidates_json="[]",
            reason="invalid",
        )
