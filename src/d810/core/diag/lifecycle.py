"""Writers for the event-native diagnostic lifecycle timeline."""

from __future__ import annotations

import json
import sqlite3
import time

from d810.core.observability_events import (
    CfgTransactionAttemptObserved,
    DiagnosticSessionObserved,
    EvidenceGenerationObserved,
    IdentityDecisionObserved,
    LifecycleEventObserved,
    MutationPlanObserved,
    MutationReceiptObserved,
    SemanticFragmentRouteOracleComparedObserved,
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


def persist_diagnostic_session_transition(
    conn: sqlite3.Connection,
    event: DiagnosticSessionObserved,
) -> bool:
    """Persist one status transition and its authoritative timeline event.

    Re-observing the same status is intentionally idempotent. Native preflight
    can create the lifecycle owner before Hex-Rays prolog opens the diagnostic
    sink; prolog republishes the active state so the DB cannot miss its owner.
    """
    existing = conn.execute(
        "SELECT status FROM diagnostic_sessions WHERE session_id=?",
        (str(event.session_id),),
    ).fetchone()
    if existing is not None and str(existing[0]) == str(event.status):
        return False
    persist_diagnostic_session(conn, event)
    persist_lifecycle_event(
        conn,
        LifecycleEventObserved(
            session_id=event.session_id,
            func_ea=event.func_ea,
            event_kind=f"session_{event.status}",
            summary=f"decompilation session {event.status}",
            timestamp=event.timestamp,
        ),
        snapshot_id=None,
    )
    return True


def persist_lifecycle_event(
    conn: sqlite3.Connection,
    event: LifecycleEventObserved,
    *,
    snapshot_id: int | None,
) -> int:
    row = conn.execute(
        "SELECT COALESCE(MAX(event_seq),0)+1 FROM lifecycle_events WHERE session_id=?",
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


def persist_cfg_transaction_attempt(
    conn: sqlite3.Connection,
    event: CfgTransactionAttemptObserved,
) -> int:
    """Persist one ordered attempt phase and upsert its normalized authority."""
    event_id = persist_lifecycle_event(
        conn,
        LifecycleEventObserved(
            session_id=event.session_id,
            func_ea=event.func_ea,
            event_kind="cfg_transaction_phase",
            phase=event.phase,
            evidence_generation=event.evidence_generation,
            mba_generation_before=event.mba_generation,
            mba_generation_after=event.mba_generation,
            correlation_id=f"{event.plan_id}:{event.attempt_id}",
            summary=f"CFG transaction {event.phase}",
            payload={"plan_id": event.plan_id, "attempt_id": event.attempt_id},
            timestamp=event.timestamp,
        ),
        snapshot_id=None,
    )
    existing = conn.execute(
        "SELECT first_failure_obligation,first_failure_phase,"
        "first_failure_reason,interr_code FROM cfg_transaction_attempts "
        "WHERE plan_id=? AND attempt_id=?",
        (event.plan_id, event.attempt_id),
    ).fetchone()
    first_failure = (
        existing
        if existing is not None and existing[2] is not None
        else (
            event.first_failure_obligation,
            event.first_failure_phase,
            event.first_failure_reason,
            event.interr_code,
        )
    )
    conn.execute(
        "INSERT INTO cfg_transaction_attempts "
        "(plan_id,attempt_id,session_id,func_ea_hex,func_ea_i64,current_phase,"
        "mba_generation,evidence_generation,mutation_started,poisoned,"
        "first_failure_obligation,first_failure_phase,first_failure_reason,"
        "interr_code) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(plan_id,attempt_id) DO UPDATE SET "
        "current_phase=excluded.current_phase,"
        "mba_generation=excluded.mba_generation,"
        "evidence_generation=excluded.evidence_generation,"
        "mutation_started=MAX(cfg_transaction_attempts.mutation_started,"
        "excluded.mutation_started),"
        "poisoned=MAX(cfg_transaction_attempts.poisoned,excluded.poisoned),"
        "first_failure_obligation=excluded.first_failure_obligation,"
        "first_failure_phase=excluded.first_failure_phase,"
        "first_failure_reason=excluded.first_failure_reason,"
        "interr_code=excluded.interr_code",
        (
            event.plan_id,
            event.attempt_id,
            event.session_id,
            _func_hex(event.func_ea),
            int(event.func_ea),
            event.phase,
            int(event.mba_generation),
            int(event.evidence_generation),
            int(event.mutation_started),
            int(event.poisoned),
            *first_failure,
        ),
    )
    conn.execute(
        "INSERT INTO cfg_transaction_phase_events "
        "(event_id,plan_id,attempt_id,phase_index,phase,mutation_started,"
        "poisoned,failure_obligation,failure_phase,failure_reason,interr_code) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (
            event_id,
            event.plan_id,
            event.attempt_id,
            int(event.phase_index),
            event.phase,
            int(event.mutation_started),
            int(event.poisoned),
            event.first_failure_obligation,
            event.first_failure_phase,
            event.first_failure_reason,
            event.interr_code,
        ),
    )
    for witness in event.creation_witnesses:
        conn.execute(
            "INSERT INTO cfg_creation_witnesses "
            "(plan_id,attempt_id,local_block_id,provenance,"
            "reserved_handle_token,logical_proxy_token,logical_version,"
            "logical_generation,insertion_quantity_before,"
            "insertion_quantity_after,requested_insertion_serial,"
            "returned_serial,invalidated,state) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(plan_id,attempt_id,local_block_id) DO UPDATE SET "
            "provenance=COALESCE(excluded.provenance,"
            "cfg_creation_witnesses.provenance),"
            "reserved_handle_token=COALESCE(excluded.reserved_handle_token,"
            "cfg_creation_witnesses.reserved_handle_token),"
            "logical_proxy_token=COALESCE(excluded.logical_proxy_token,"
            "cfg_creation_witnesses.logical_proxy_token),"
            "logical_version=COALESCE(excluded.logical_version,"
            "cfg_creation_witnesses.logical_version),"
            "logical_generation=COALESCE(excluded.logical_generation,"
            "cfg_creation_witnesses.logical_generation),"
            "insertion_quantity_before=COALESCE(excluded.insertion_quantity_before,"
            "cfg_creation_witnesses.insertion_quantity_before),"
            "insertion_quantity_after=COALESCE(excluded.insertion_quantity_after,"
            "cfg_creation_witnesses.insertion_quantity_after),"
            "requested_insertion_serial=COALESCE(excluded.requested_insertion_serial,"
            "cfg_creation_witnesses.requested_insertion_serial),"
            "returned_serial=COALESCE(excluded.returned_serial,"
            "cfg_creation_witnesses.returned_serial),"
            "invalidated=MAX(cfg_creation_witnesses.invalidated,excluded.invalidated),"
            "state=excluded.state",
            (
                event.plan_id,
                event.attempt_id,
                witness.local_block_id,
                witness.provenance,
                witness.reserved_handle_token,
                witness.logical_proxy_token,
                witness.logical_version,
                witness.logical_generation,
                witness.insertion_quantity_before,
                witness.insertion_quantity_after,
                witness.requested_insertion_serial,
                witness.returned_serial,
                int(witness.invalidated),
                witness.state,
            ),
        )
    return event_id


__all__ = [
    "persist_cfg_transaction_attempt",
    "persist_diagnostic_session",
    "persist_diagnostic_session_transition",
    "persist_lifecycle_event",
]


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
    "persist_diagnostic_session_transition",
    "persist_evidence_generation",
    "persist_identity_decision",
    "persist_lifecycle_event",
]


def _anchor_hex(anchor: int | None) -> str | None:
    if anchor is None:
        return None
    return f"0x{int(anchor) & 0xFFFFFFFFFFFFFFFF:016x}"


def _compact_json_strings(values: tuple[str, ...]) -> str:
    return json.dumps(list(values), separators=(",", ":"))


def _root_group_descriptor(group) -> tuple[object, ...]:
    return (
        group.group_id,
        group.predecessor_block_id,
        _anchor_hex(group.predecessor_anchor_ea),
        int(group.predecessor_anchor_ea),
        _compact_json_strings(group.edge_ids),
        _compact_json_strings(group.edge_roles),
        _compact_json_strings(group.original_block_ids),
        _compact_json_strings(group.replacement_block_ids),
    )


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
            summary=(f"{event.mutation_kind}: {event.planned_operation_count} planned"),
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
    if event.fragment_plan_id:
        conn.execute(
            "INSERT INTO semantic_fragment_transactions "
            "(mutation_batch_id,plan_event_id,receipt_event_id,plan_id,"
            "atomic_group_id,plan_json,outcome,fragment_staged,"
            "root_publication_attempted,root_publication_succeeded,"
            "rollback_attempted,rollback_succeeded,reason) "
            "VALUES (?,?,NULL,?,?,?,NULL,NULL,NULL,NULL,NULL,NULL,'')",
            (
                event.mutation_batch_id,
                event_id,
                event.fragment_plan_id,
                event.fragment_atomic_group_id,
                event.fragment_plan_json,
            ),
        )
        conn.execute(
            "INSERT INTO semantic_fragment_transaction_events "
            "(event_id,mutation_batch_id,event_index,event_kind,outcome,"
            "detail_json) VALUES (?,?,?,?,?,?)",
            (
                event_id,
                event.mutation_batch_id,
                0,
                "plan_recorded",
                "planned",
                json.dumps(
                    {
                        "plan_id": event.fragment_plan_id,
                        "atomic_group_id": event.fragment_atomic_group_id,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            ),
        )
        for group in event.root_publication_groups:
            conn.execute(
                "INSERT INTO semantic_fragment_root_publication_groups "
                "(plan_event_id,receipt_event_id,mutation_batch_id,group_id,"
                "predecessor_block_id,predecessor_anchor_ea_hex,"
                "predecessor_anchor_ea_i64,edge_ids_json,edge_roles_json,"
                "original_block_ids_json,replacement_block_ids_json,"
                "publication_attempted,publication_succeeded,"
                "rollback_attempted,rollback_succeeded) "
                "VALUES (?,NULL,?,?,?,?,?,?,?,?,?,NULL,NULL,NULL,NULL)",
                (
                    event_id,
                    event.mutation_batch_id,
                    *_root_group_descriptor(group),
                ),
            )
    return event_id


def persist_semantic_fragment_route_oracle(
    conn: sqlite3.Connection,
    event: SemanticFragmentRouteOracleComparedObserved,
) -> int:
    transaction = conn.execute(
        "SELECT plan_id,atomic_group_id FROM semantic_fragment_transactions "
        "WHERE mutation_batch_id=?",
        (event.mutation_batch_id,),
    ).fetchone()
    if transaction != (event.plan_id, event.atomic_group_id):
        raise ValueError("fragment route oracle does not match its persisted plan")
    passed = all(comparison.outcome == "matched" for comparison in event.comparisons)
    event_id = persist_lifecycle_event(
        conn,
        LifecycleEventObserved(
            session_id=event.session_id,
            func_ea=event.func_ea,
            event_kind="semantic_fragment_route_oracle",
            maturity=event.maturity,
            evidence_generation=event.evidence_generation,
            mba_generation_before=event.mba_generation,
            mba_generation_after=event.mba_generation,
            correlation_id=event.mutation_batch_id,
            summary=(
                f"detached route oracle: {'passed' if passed else 'failed'} "
                f"({len(event.comparisons)} routes)"
            ),
            payload={
                "atomic_group_id": event.atomic_group_id,
                "plan_id": event.plan_id,
                "run_id": event.run_id,
            },
            timestamp=event.timestamp,
        ),
        snapshot_id=None,
    )
    ledger_by_route = dict(event.reference_ledger_identities)
    for comparison_index, comparison in enumerate(event.comparisons):
        conn.execute(
            "INSERT INTO semantic_fragment_route_oracle_comparisons "
            "(event_id,mutation_batch_id,comparison_index,run_id,plan_id,"
            "atomic_group_id,route_id,maturity,candidate_variant,outcome,"
            "first_divergence,failed_invariant,owner_ea_hex,owner_ea_i64,"
            "rewrite_anchor_ea_hex,rewrite_anchor_ea_i64,"
            "reference_ledger_identity,oracle_shape_json,candidate_shape_json,"
            "reason) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                event_id,
                event.mutation_batch_id,
                comparison_index,
                event.run_id,
                event.plan_id,
                event.atomic_group_id,
                comparison.route_id,
                comparison.maturity,
                comparison.candidate_variant,
                comparison.outcome,
                int(comparison.first_divergence),
                comparison.failed_invariant,
                _func_hex(comparison.owner_ea),
                int(comparison.owner_ea),
                _func_hex(comparison.rewrite_anchor_ea),
                int(comparison.rewrite_anchor_ea),
                ledger_by_route[comparison.route_id],
                (
                    None
                    if comparison.oracle_shape is None
                    else comparison.oracle_shape.to_json()
                ),
                (
                    None
                    if comparison.candidate_shape is None
                    else comparison.candidate_shape.to_json()
                ),
                comparison.reason,
            ),
        )
    next_index = int(
        conn.execute(
            "SELECT COALESCE(MAX(event_index),0)+1 FROM "
            "semantic_fragment_transaction_events WHERE mutation_batch_id=?",
            (event.mutation_batch_id,),
        ).fetchone()[0]
    )
    conn.execute(
        "INSERT INTO semantic_fragment_transaction_events "
        "(event_id,mutation_batch_id,event_index,event_kind,outcome,detail_json) "
        "VALUES (?,?,?,?,?,?)",
        (
            event_id,
            event.mutation_batch_id,
            next_index,
            "detached_route_oracle",
            "passed" if passed else "failed",
            json.dumps(
                {
                    "comparison_count": len(event.comparisons),
                    "run_id": event.run_id,
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
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
    if event.fragment_plan_id:
        transaction = conn.execute(
            "SELECT plan_id,atomic_group_id FROM semantic_fragment_transactions "
            "WHERE mutation_batch_id=?",
            (event.mutation_batch_id,),
        ).fetchone()
        if transaction != (
            event.fragment_plan_id,
            event.fragment_atomic_group_id,
        ):
            raise ValueError(
                "semantic-fragment receipt does not match its persisted plan"
            )
        persisted_groups = conn.execute(
            "SELECT group_id,predecessor_block_id,"
            "predecessor_anchor_ea_hex,predecessor_anchor_ea_i64,"
            "edge_ids_json,edge_roles_json,original_block_ids_json,"
            "replacement_block_ids_json "
            "FROM semantic_fragment_root_publication_groups "
            "WHERE mutation_batch_id=? ORDER BY group_id",
            (event.mutation_batch_id,),
        ).fetchall()
        expected_groups = sorted(
            (_root_group_descriptor(group) for group in event.root_publication_groups),
            key=lambda row: str(row[0]),
        )
        if persisted_groups != expected_groups:
            raise ValueError(
                "semantic-fragment receipt root groups do not match its plan"
            )
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
    if event.fragment_plan_id:
        conn.execute(
            "UPDATE semantic_fragment_transactions SET "
            "receipt_event_id=?,outcome=?,fragment_staged=?,"
            "root_publication_attempted=?,root_publication_succeeded=?,"
            "rollback_attempted=?,rollback_succeeded=?,reason=? "
            "WHERE mutation_batch_id=?",
            (
                event_id,
                event.outcome,
                int(event.fragment_staged),
                int(event.root_publication_attempted),
                int(event.root_publication_succeeded),
                int(event.rollback_attempted),
                (
                    None
                    if event.rollback_succeeded is None
                    else int(event.rollback_succeeded)
                ),
                event.reason,
                event.mutation_batch_id,
            ),
        )
        for group in event.root_publication_groups:
            updated = conn.execute(
                "UPDATE semantic_fragment_root_publication_groups SET "
                "receipt_event_id=?,publication_attempted=?,"
                "publication_succeeded=?,rollback_attempted=?,"
                "rollback_succeeded=? "
                "WHERE mutation_batch_id=? AND group_id=?",
                (
                    event_id,
                    int(group.publication_attempted),
                    int(group.publication_succeeded),
                    int(group.rollback_attempted),
                    (
                        None
                        if group.rollback_succeeded is None
                        else int(group.rollback_succeeded)
                    ),
                    event.mutation_batch_id,
                    group.group_id,
                ),
            )
            if updated.rowcount != 1:
                raise ValueError(
                    "semantic-fragment receipt lost a root publication group"
                )
        for outcome_index, outcome in enumerate(event.validation_outcomes):
            conn.execute(
                "INSERT INTO semantic_fragment_validation_outcomes "
                "(event_id,mutation_batch_id,outcome_index,phase,"
                "postcondition,subject_id,passed,reason,block_ids_json) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    event_id,
                    event.mutation_batch_id,
                    outcome_index,
                    outcome.phase,
                    outcome.postcondition,
                    outcome.subject_id,
                    int(outcome.passed),
                    outcome.reason,
                    json.dumps(
                        list(outcome.block_ids),
                        separators=(",", ":"),
                    ),
                ),
            )
        for transition_index, transition in enumerate(event.version_transitions):
            conn.execute(
                "INSERT INTO logical_block_version_transitions "
                "(event_id,mutation_batch_id,transition_index,proxy_token,"
                "version,physical_handle_token,generation,provenance,"
                "stable_identity_json,anchor_ea_hex,anchor_ea_i64,"
                "predecessor_version,from_state,to_state) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    event_id,
                    event.mutation_batch_id,
                    transition_index,
                    transition.proxy_token,
                    transition.version,
                    transition.physical_handle_token,
                    transition.generation,
                    transition.provenance,
                    transition.stable_identity_json,
                    (
                        None
                        if transition.anchor_ea is None
                        else _func_hex(transition.anchor_ea)
                    ),
                    transition.anchor_ea,
                    transition.predecessor_version,
                    transition.from_state,
                    transition.to_state,
                ),
            )

        transaction_events: list[tuple[str, str, dict[str, object]]] = [
            (
                f"{failure.failure_kind}_failure",
                "failed",
                {
                    "phase": failure.phase,
                    "error_type": failure.error_type,
                    "error_message": failure.error_message,
                    "interr_code": failure.interr_code,
                    "verification_context": failure.verification_context,
                },
            )
            for failure in event.fragment_failures
        ]
        transaction_events.extend(
            [
                (
                    "fragment_staged",
                    "completed" if event.fragment_staged else "failed",
                    {},
                ),
            ]
        )
        for phase in ("prepublication", "postpublication"):
            outcomes = tuple(
                outcome
                for outcome in event.validation_outcomes
                if outcome.phase == phase
            )
            if outcomes:
                transaction_events.append(
                    (
                        f"{phase}_validation",
                        (
                            "passed"
                            if all(outcome.passed for outcome in outcomes)
                            else "failed"
                        ),
                        {"outcome_count": len(outcomes)},
                    )
                )
            if phase == "prepublication" and event.root_publication_attempted:
                transaction_events.extend(
                    (
                        "root_group_publication",
                        ("published" if group.publication_succeeded else "failed"),
                        {"group_id": group.group_id},
                    )
                    for group in event.root_publication_groups
                    if group.publication_attempted
                )
                transaction_events.append(
                    (
                        "root_publication",
                        ("published" if event.root_publication_succeeded else "failed"),
                        {},
                    )
                )
        if event.rollback_attempted:
            transaction_events.extend(
                (
                    "root_group_rollback",
                    ("succeeded" if group.rollback_succeeded else "failed"),
                    {"group_id": group.group_id},
                )
                for group in event.root_publication_groups
                if group.rollback_attempted
            )
            transaction_events.append(
                (
                    "rollback",
                    "succeeded" if event.rollback_succeeded else "failed",
                    {},
                )
            )
        transaction_events.append(("receipt", event.outcome, {"reason": event.reason}))
        next_event_index = int(
            conn.execute(
                "SELECT COALESCE(MAX(event_index),0)+1 FROM "
                "semantic_fragment_transaction_events WHERE mutation_batch_id=?",
                (event.mutation_batch_id,),
            ).fetchone()[0]
        )
        for event_index, (
            event_kind,
            outcome,
            detail,
        ) in enumerate(transaction_events, start=next_event_index):
            conn.execute(
                "INSERT INTO semantic_fragment_transaction_events "
                "(event_id,mutation_batch_id,event_index,event_kind,outcome,"
                "detail_json) VALUES (?,?,?,?,?,?)",
                (
                    event_id,
                    event.mutation_batch_id,
                    event_index,
                    event_kind,
                    outcome,
                    json.dumps(detail, sort_keys=True, separators=(",", ":")),
                ),
            )
    return event_id


__all__.extend(
    [
        "persist_mutation_plan",
        "persist_mutation_receipt",
        "persist_semantic_fragment_route_oracle",
    ]
)
