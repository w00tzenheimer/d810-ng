from __future__ import annotations

import json

import pytest

from d810.core.diag import create_diag_database
from d810.core.diag.deobfuscation_case import (
    materialize_closed_deobfuscation_case,
    project_closed_case_rows,
)
from d810.core.diag.lifecycle import (
    persist_diagnostic_session_transition,
    persist_frontend_normalization_plan_intent,
    persist_lifecycle_event,
    persist_semantic_output_verified,
)
from d810.core.observability_events import (
    DiagnosticSessionObserved,
    FrontendNormalizationPlanIntentObserved,
    LifecycleEventObserved,
    SemanticOutputVerifiedObserved,
)


FUNC_EA = 0x180001000
NATIVE_KEY = json.dumps(
    {"function_fingerprint": "sha256:fixture", "runtime": "ida9.3"},
    sort_keys=True,
)


@pytest.fixture
def conn():
    return create_diag_database(":memory:").connection()


def _active(conn, session_id: str = "session-1") -> None:
    persist_diagnostic_session_transition(
        conn,
        DiagnosticSessionObserved(
            session_id=session_id,
            func_ea=FUNC_EA,
            top_level_epoch=1,
            native_key_json=NATIVE_KEY,
            status="active",
            timestamp=1.0,
        ),
    )


def _finish(conn, session_id: str = "session-1", status: str = "finished") -> None:
    persist_diagnostic_session_transition(
        conn,
        DiagnosticSessionObserved(
            session_id=session_id,
            func_ea=FUNC_EA,
            top_level_epoch=1,
            native_key_json=NATIVE_KEY,
            status=status,
            timestamp=20.0,
        ),
    )


def _lifecycle(
    conn,
    *,
    session_id: str,
    event_kind: str,
    event_seq_hint: int = 0,
    correlation_id: str | None = None,
    summary: str = "typed source",
) -> int:
    return persist_lifecycle_event(
        conn,
        LifecycleEventObserved(
            session_id=session_id,
            func_ea=FUNC_EA,
            event_kind=event_kind,
            correlation_id=correlation_id,
            summary=summary,
            timestamp=float(event_seq_hint or 2),
        ),
        snapshot_id=None,
    )


def _identity(conn, *, session_id: str = "session-1", outcome: str = "accepted") -> int:
    event_id = _lifecycle(
        conn,
        session_id=session_id,
        event_kind="identity_decision",
        summary=f"identity {outcome}",
    )
    conn.execute(
        "INSERT INTO identity_decisions "
        "(event_id,decision_kind,consumer,identity_role,native_key_json,"
        "exact_eas_json,native_ranges_json,primary_anchor_ea_hex,"
        "primary_anchor_ea_i64,current_serial,mba_generation,evidence_generation,"
        "outcome,candidates_json,reason) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            event_id,
            "fixture",
            "fixture",
            "function",
            NATIVE_KEY,
            "[6442455040]",
            "[]",
            "0x0000000180001000",
            FUNC_EA,
            None,
            1,
            1,
            outcome,
            "[]",
            "fixture",
        ),
    )
    return event_id


def _plan(conn, *, session_id: str = "session-1", batch_id: str = "batch-1") -> int:
    event_id = _lifecycle(
        conn,
        session_id=session_id,
        event_kind="mutation_plan",
        correlation_id=batch_id,
        summary="fragment plan",
    )
    conn.execute(
        "INSERT INTO mutation_plan_items "
        "(event_id,mutation_batch_id,item_index,mutation_kind,source_serial,"
        "source_anchor_ea_hex,source_anchor_ea_i64,source_identity_json,"
        "target_serial,target_anchor_ea_hex,target_anchor_ea_i64,target_identity_json,"
        "disposition,reason) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            event_id,
            batch_id,
            0,
            "redirect",
            7,
            "0x0000000180001000",
            FUNC_EA,
            NATIVE_KEY,
            None,
            None,
            None,
            None,
            "selected",
            "fixture",
        ),
    )
    return event_id


def _receipt(
    conn,
    *,
    session_id: str = "session-1",
    batch_id: str = "batch-1",
    outcome: str = "committed",
) -> int:
    event_id = _lifecycle(
        conn,
        session_id=session_id,
        event_kind="mutation_receipt",
        correlation_id=batch_id,
        summary=f"receipt {outcome}",
    )
    conn.execute(
        "INSERT INTO mutation_receipts "
        "(event_id,mutation_batch_id,mutation_kind,pre_generation,post_generation,"
        "planned_operation_count,applied_operation_count,outcome,description,reason) "
        "VALUES (?,?,?,?,?,?,?,?,?,?)",
        (
            event_id,
            batch_id,
            "fragment_publication",
            1,
            2 if outcome == "committed" else 1,
            1,
            1 if outcome == "committed" else 0,
            outcome,
            "fixture receipt",
            "fixture",
        ),
    )
    conn.execute(
        "INSERT INTO mutation_receipt_identities "
        "(event_id,identity_index,identity_json,primary_anchor_ea_hex,"
        "primary_anchor_ea_i64) VALUES (?,?,?,?,?)",
        (event_id, 0, NATIVE_KEY, "0x0000000180001000", FUNC_EA),
    )
    return event_id


def _frontend_intent(conn, *, session_id: str = "session-1") -> int:
    return persist_frontend_normalization_plan_intent(
        conn,
        FrontendNormalizationPlanIntentObserved(
            session_id=session_id,
            func_ea=FUNC_EA,
            evidence_generation=1,
            work_item_id="work-item-1",
            plan_id="plan-1",
            atomic_group_id="group-1",
            publication_revision=1,
            block_count=1,
            operation_count=1,
            imported_block_count=1,
            native_body_count=1,
            published_operation_ids=("op-1",),
            selected_obligation_ids=("obl-1",),
            remaining_obligation_ids=(),
            unreachable_obligation_ids=(),
            complete_plan_json='{"plan_id":"plan-1"}',
        ),
    )


def _validation(conn, *, session_id: str = "session-1", passed: bool = True) -> int:
    event_id = _lifecycle(
        conn,
        session_id=session_id,
        event_kind="mutation_receipt",
        correlation_id="batch-validation",
        summary="validation source",
    )
    conn.execute(
        "INSERT INTO semantic_fragment_validation_outcomes "
        "(event_id,mutation_batch_id,outcome_index,phase,postcondition,subject_id,"
        "passed,reason,block_ids_json) VALUES (?,?,?,?,?,?,?,?,?)",
        (
            event_id,
            "batch-validation",
            0,
            "prepublication",
            "fragment_is_closed",
            "fragment-1",
            int(passed),
            "fixture",
            "[\"block-1\"]",
        ),
    )
    return event_id


def _semantic_output(conn, *, session_id: str = "session-1") -> int:
    return persist_semantic_output_verified(
        conn,
        SemanticOutputVerifiedObserved(
            session_id=session_id,
            func_ea=FUNC_EA,
            verifier_id="verifier:fixture",
            witness_id="verifier:fixture:1",
            summary="Reference and candidate outputs matched.",
            native_anchor_ea=FUNC_EA,
            evidence_generation=2,
        ),
    )


def _closed_case(conn, session_id: str) -> tuple:
    return conn.execute(
        "SELECT verdict_level, first_blocked_obligation, semantic_witness "
        "FROM deobfuscation_cases WHERE session_id=?",
        (session_id,),
    ).fetchone()


def test_projects_c1_c3_c5_with_deterministic_block(conn) -> None:
    _active(conn)
    _identity(conn)
    _plan(conn)
    _receipt(conn)
    _finish(conn)

    case_id = materialize_closed_deobfuscation_case(conn, "session-1")
    assert _closed_case(conn, "session-1") == (
        "c5_publication",
        "semantic_output_verification",
        None,
    )
    assert conn.execute(
        "SELECT finding_kind, evidence_level, native_anchor_ea_i64 "
        "FROM deobfuscation_case_findings WHERE case_id=? ORDER BY finding_index",
        (case_id,),
    ).fetchall() == [
        ("portable_evidence", "c1_discovery", FUNC_EA),
        ("fragment_plan", "c3_canonical_plan", FUNC_EA),
        ("receipt", "c5_publication", FUNC_EA),
    ]


def test_terminal_session_without_typed_evidence_is_c0(conn) -> None:
    _active(conn)
    _finish(conn)

    case_id = materialize_closed_deobfuscation_case(conn, "session-1")
    assert _closed_case(conn, "session-1") == ("c0_environment", None, None)
    assert conn.execute(
        "SELECT finding_kind, evidence_level, native_anchor_ea_i64, source_event_id "
        "FROM deobfuscation_case_findings WHERE case_id=?",
        (case_id,),
    ).fetchone() == ("observation", "c0_environment", FUNC_EA, 2)


def test_rejected_receipt_is_a_c5_blocker_and_materialization_is_idempotent(conn) -> None:
    _active(conn)
    _plan(conn)
    _receipt(conn, outcome="aborted")
    _finish(conn, status="failed")

    first = materialize_closed_deobfuscation_case(conn, "session-1")
    second = materialize_closed_deobfuscation_case(conn, "session-1")
    assert first == second
    assert _closed_case(conn, "session-1") == (
        "c5_publication",
        "mutation_receipt_not_committed",
        None,
    )
    assert conn.execute(
        "SELECT finding_id, blocked_obligation "
        "FROM deobfuscation_case_findings ORDER BY finding_index"
    ).fetchall() == [
        ("mutation-plan:2", None),
        ("mutation-receipt:3", "mutation_receipt_not_committed"),
    ]
    assert conn.execute("SELECT COUNT(*) FROM deobfuscation_cases").fetchone() == (1,)


@pytest.mark.parametrize(
    ("builder", "finding_kind", "evidence_level"),
    [
        (_frontend_intent, "pass_decision", "c2_normalization"),
        (_validation, "validation", "c4_staged_proof"),
    ],
)
def test_projects_typed_intermediate_evidence(
    conn,
    builder,
    finding_kind: str,
    evidence_level: str,
) -> None:
    _active(conn)
    builder(conn)
    _finish(conn)

    case_id = materialize_closed_deobfuscation_case(conn, "session-1")
    assert conn.execute(
        "SELECT finding_kind, evidence_level FROM deobfuscation_case_findings "
        "WHERE case_id=?",
        (case_id,),
    ).fetchone() == (finding_kind, evidence_level)


def test_c6_requires_a_valid_typed_witness(conn) -> None:
    _active(conn)
    _semantic_output(conn)
    _finish(conn)

    case_id = materialize_closed_deobfuscation_case(conn, "session-1")
    assert _closed_case(conn, "session-1") == (
        "c6_semantic_output",
        None,
        "verifier:fixture:1",
    )
    assert conn.execute(
        "SELECT witness_id, verifier_id, native_anchor_ea_i64 "
        "FROM deobfuscation_case_semantic_witnesses WHERE case_id=?",
        (case_id,),
    ).fetchone() == ("verifier:fixture:1", "verifier:fixture", FUNC_EA)


def test_c6_without_an_exact_witness_is_rejected(conn) -> None:
    _active(conn)
    event_id = _lifecycle(
        conn,
        session_id="session-1",
        event_kind="semantic_output_verified",
        summary="malformed semantic result",
    )
    conn.execute(
        "INSERT INTO semantic_output_verdicts "
        "(event_id,verifier_id,witness_id,summary,native_anchor_ea_i64) "
        "VALUES (?,?,?,?,?)",
        (event_id, "verifier:fixture", "", "malformed", FUNC_EA),
    )
    _finish(conn)

    with pytest.raises(ValueError, match="witness"):
        project_closed_case_rows(conn, "session-1")


def test_receipt_without_correlated_plan_is_a_projection_error(conn) -> None:
    _active(conn)
    _receipt(conn)
    _finish(conn)

    with pytest.raises(ValueError, match="correlated plan"):
        materialize_closed_deobfuscation_case(conn, "session-1")
