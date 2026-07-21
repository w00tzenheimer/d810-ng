from __future__ import annotations

from unittest.mock import patch

import pytest

from d810.core.diag import create_diag_database
from d810.core.diag.event_handlers import install_diag_event_handlers, uninstall_diag_event_handlers
from d810.core.observability import emit, reset_diagnostic_bus
from d810.core.observability_events import (
    DiagnosticSessionObserved,
    MutationPlanItemObserved,
    MutationPlanObserved,
    MutationReceiptObserved,
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
        emit(DiagnosticSessionObserved("s1", 0x40C8B0, 1, "{}", "active"))
        yield
        uninstall_diag_event_handlers()
    reset_diagnostic_bus()


def test_plan_and_receipt_are_correlated_by_gateway_batch(diag_conn) -> None:
    item = MutationPlanItemObserved(
        item_index=0,
        mutation_kind="edge_redirect",
        source_serial=17,
        source_anchor_ea=0x40CA3D,
        source_identity_json='{"native_ranges":[]}',
        target_serial=21,
        target_anchor_ea=0x40CD76,
        target_identity_json='{"native_ranges":[]}',
        disposition="planned",
        reason="resolver route",
    )
    emit(
        MutationPlanObserved(
            session_id="s1",
            func_ea=0x40C8B0,
            mutation_batch_id="batch-1",
            mutation_kind="edge_redirect",
            planned_operation_count=1,
            mba_generation=8,
            evidence_generation=3,
            maturity="MMAT_CALLS",
            description="apply route",
            items=(item,),
        )
    )
    emit(
        MutationReceiptObserved(
            session_id="s1",
            func_ea=0x40C8B0,
            mutation_batch_id="batch-1",
            mutation_kind="edge_redirect",
            pre_generation=8,
            post_generation=9,
            planned_operation_count=1,
            applied_operation_count=1,
            evidence_generation=3,
            maturity="MMAT_CALLS",
            outcome="committed",
            description="apply route",
            reason="",
            affected_identity_json=(item.source_identity_json,),
            affected_anchor_eas=(item.source_anchor_ea,),
        )
    )

    assert diag_conn.execute(
        "SELECT mutation_batch_id,item_index,source_anchor_ea_i64 "
        "FROM mutation_plan_items"
    ).fetchone() == ("batch-1", 0, 0x40CA3D)
    assert diag_conn.execute(
        "SELECT mutation_batch_id,pre_generation,post_generation,outcome "
        "FROM mutation_receipts"
    ).fetchone() == ("batch-1", 8, 9, "committed")
    assert diag_conn.execute(
        "SELECT event_seq,event_kind,correlation_id FROM lifecycle_events "
        "ORDER BY event_seq"
    ).fetchall() == [
        (1, "session_active", None),
        (2, "mutation_plan", "batch-1"),
        (3, "mutation_receipt", "batch-1"),
    ]
