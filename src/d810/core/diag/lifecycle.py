"""Writers for the event-native diagnostic lifecycle timeline."""

from __future__ import annotations

import json
import sqlite3
import time

from d810.core.observability_events import (
    DiagnosticSessionObserved,
    EvidenceGenerationObserved,
    IdentityDecisionObserved,
    LifecycleEventObserved,
    MutationPlanObserved,
    MutationReceiptObserved,
)


def _func_hex(func_ea: int) -> str:
    return f"0x{int(func_ea) & 0xFFFFFFFFFFFFFFFF:016x}"


def persist_diagnostic_session(
    conn: sqlite3.Connection,
    event: DiagnosticSessionObserved,
) -> None:
    timestamp = float(event.timestamp or time.time())
    existing = conn.execute(
        "SELECT started_at,diagnostic_error_count FROM diagnostic_sessions "
        "WHERE session_id=?",
        (str(event.session_id),),
    ).fetchone()
    started_at = timestamp if existing is None else float(existing[0])
    error_count = 0 if existing is None else int(existing[1])
    finished_at = None if event.status == "active" else timestamp
    conn.execute(
        "INSERT OR REPLACE INTO diagnostic_sessions "
        "(session_id,func_ea_hex,func_ea_i64,top_level_epoch,native_key_json,"
        "started_at,finished_at,status,diagnostic_error_count) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (
            str(event.session_id),
            _func_hex(event.func_ea),
            int(event.func_ea),
            int(event.top_level_epoch),
            str(event.native_key_json),
            started_at,
            finished_at,
            str(event.status),
            error_count,
        ),
    )


def persist_lifecycle_event(
    conn: sqlite3.Connection,
    event: LifecycleEventObserved,
    *,
    snapshot_id: int | None,
) -> int:
    row = conn.execute(
        "SELECT COALESCE(MAX(event_seq),0)+1 FROM lifecycle_events "
        "WHERE session_id=?",
        (str(event.session_id),),
    ).fetchone()
    event_seq = int(row[0])
    cursor = conn.execute(
        "INSERT INTO lifecycle_events "
        "(session_id,event_seq,timestamp,event_kind,snapshot_id,func_ea_hex,"
        "func_ea_i64,provider,maturity,phase,evidence_generation,"
        "mba_generation_before,mba_generation_after,correlation_id,summary,"
        "payload_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            str(event.session_id),
            event_seq,
            float(event.timestamp or time.time()),
            str(event.event_kind),
            snapshot_id,
            _func_hex(event.func_ea),
            int(event.func_ea),
            event.provider,
            event.maturity,
            event.phase,
            event.evidence_generation,
            event.mba_generation_before,
            event.mba_generation_after,
            event.correlation_id,
            str(event.summary),
            json.dumps(event.payload, sort_keys=True, separators=(",", ":")),
        ),
    )
    return int(cursor.lastrowid)


__all__ = ["persist_diagnostic_session", "persist_lifecycle_event"]


def persist_evidence_generation(
    conn: sqlite3.Connection,
    event: EvidenceGenerationObserved,
    *,
    snapshot_id: int | None,
) -> int:
    event_id = persist_lifecycle_event(
        conn,
        LifecycleEventObserved(
            session_id=event.session_id,
            func_ea=event.func_ea,
            event_kind="evidence_generation",
            snapshot=event.snapshot,
            provider=event.provider,
            maturity=event.maturity,
            phase=event.phase,
            evidence_generation=event.resulting_generation,
            summary=f"{event.evidence_family}: {event.operation} {event.outcome}",
            timestamp=event.timestamp,
        ),
        snapshot_id=snapshot_id,
    )
    conn.execute(
        "INSERT INTO evidence_generation_events VALUES (?,?,?,?,?,?,?,?)",
        (
            event_id,
            event.operation,
            int(event.previous_generation),
            int(event.resulting_generation),
            event.evidence_family,
            event.outcome,
            event.owner,
            event.reason,
        ),
    )
    return event_id


def persist_identity_decision(
    conn: sqlite3.Connection,
    event: IdentityDecisionObserved,
    *,
    snapshot_id: int | None,
) -> int:
    anchor = int(event.primary_anchor_ea)
    event_id = persist_lifecycle_event(
        conn,
        LifecycleEventObserved(
            session_id=event.session_id,
            func_ea=event.func_ea,
            event_kind="identity_decision",
            snapshot=event.snapshot,
            maturity=event.maturity,
            evidence_generation=event.evidence_generation,
            mba_generation_before=event.mba_generation,
            mba_generation_after=event.mba_generation,
            summary=f"{event.consumer}: {event.decision_kind} {event.outcome}",
            timestamp=event.timestamp,
        ),
        snapshot_id=snapshot_id,
    )
    conn.execute(
        "INSERT INTO identity_decisions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            event_id,
            event.decision_kind,
            event.consumer,
            event.identity_role,
            event.native_key_json,
            event.exact_eas_json,
            event.native_ranges_json,
            f"0x{anchor & 0xFFFFFFFFFFFFFFFF:016x}",
            anchor,
            event.current_serial,
            int(event.mba_generation),
            int(event.evidence_generation),
            event.outcome,
            event.candidates_json,
            event.reason,
        ),
    )
    return event_id


__all__ = [
    "persist_diagnostic_session",
    "persist_evidence_generation",
    "persist_identity_decision",
    "persist_lifecycle_event",
]


def _anchor_hex(anchor: int | None) -> str | None:
    if anchor is None:
        return None
    return f"0x{int(anchor) & 0xFFFFFFFFFFFFFFFF:016x}"


def persist_mutation_plan(
    conn: sqlite3.Connection,
    event: MutationPlanObserved,
) -> int:
    event_id = persist_lifecycle_event(
        conn,
        LifecycleEventObserved(
            session_id=event.session_id,
            func_ea=event.func_ea,
            event_kind="mutation_plan",
            maturity=event.maturity,
            evidence_generation=event.evidence_generation,
            mba_generation_before=event.mba_generation,
            mba_generation_after=event.mba_generation,
            correlation_id=event.mutation_batch_id,
            summary=(
                f"{event.mutation_kind}: {event.planned_operation_count} planned"
            ),
            payload={
                "description": event.description,
                "mutation_kind": event.mutation_kind,
                "planned_operation_count": int(event.planned_operation_count),
            },
            timestamp=event.timestamp,
        ),
        snapshot_id=None,
    )
    for item in event.items:
        conn.execute(
            "INSERT INTO mutation_plan_items VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                event_id,
                event.mutation_batch_id,
                int(item.item_index),
                item.mutation_kind,
                item.source_serial,
                _anchor_hex(item.source_anchor_ea),
                item.source_anchor_ea,
                item.source_identity_json,
                item.target_serial,
                _anchor_hex(item.target_anchor_ea),
                item.target_anchor_ea,
                item.target_identity_json,
                item.disposition,
                item.reason,
            ),
        )
    return event_id


def persist_mutation_receipt(
    conn: sqlite3.Connection,
    event: MutationReceiptObserved,
) -> int | None:
    plan = conn.execute(
        "SELECT 1 FROM lifecycle_events WHERE session_id=? "
        "AND event_kind='mutation_plan' AND correlation_id=?",
        (event.session_id, event.mutation_batch_id),
    ).fetchone()
    if plan is None:
        conn.execute(
            "UPDATE diagnostic_sessions SET status='failed',"
            "diagnostic_error_count=diagnostic_error_count+1 WHERE session_id=?",
            (event.session_id,),
        )
        return None
    event_id = persist_lifecycle_event(
        conn,
        LifecycleEventObserved(
            session_id=event.session_id,
            func_ea=event.func_ea,
            event_kind="mutation_receipt",
            maturity=event.maturity,
            evidence_generation=event.evidence_generation,
            mba_generation_before=event.pre_generation,
            mba_generation_after=event.post_generation,
            correlation_id=event.mutation_batch_id,
            summary=f"{event.mutation_kind}: {event.outcome}",
            timestamp=event.timestamp,
        ),
        snapshot_id=None,
    )
    conn.execute(
        "INSERT INTO mutation_receipts VALUES (?,?,?,?,?,?,?,?,?,?)",
        (
            event_id,
            event.mutation_batch_id,
            event.mutation_kind,
            int(event.pre_generation),
            int(event.post_generation),
            int(event.planned_operation_count),
            int(event.applied_operation_count),
            event.outcome,
            event.description,
            event.reason,
        ),
    )
    for index, (identity_json, anchor) in enumerate(
        zip(event.affected_identity_json, event.affected_anchor_eas)
    ):
        conn.execute(
            "INSERT INTO mutation_receipt_identities VALUES (?,?,?,?,?)",
            (event_id, index, identity_json, _anchor_hex(anchor), int(anchor)),
        )
    return event_id


__all__.extend(["persist_mutation_plan", "persist_mutation_receipt"])
