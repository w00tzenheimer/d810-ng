"""Project typed diagnostic lifecycle rows into one closed deobfuscation case.

This module is deliberately a pure SQLite projector.  It consumes normalized
diagnostic tables only; it never parses lifecycle payload JSON or log output.
The resulting case is the producer boundary consumed by the Workbench.
"""

from __future__ import annotations

import dataclasses
import json
import sqlite3

from d810.core.deobfuscation_case import (
    CaseEvidenceLevel,
    CaseFinding,
    CaseFindingKind,
    CaseVerdict,
)

__all__ = [
    "ClosedCaseProjection",
    "ProjectedSemanticWitness",
    "materialize_closed_deobfuscation_case",
    "project_closed_case_rows",
]


CASE_SCHEMA_VERSION = 1

_ACCEPTED_OUTCOMES = frozenset(
    {
        "accepted",
        "bound",
        "committed",
        "created",
        "installed",
        "matched",
        "passed",
        "ready",
        "recorded",
        "resolved",
        "restored",
        "selected",
        "success",
        "succeeded",
    }
)

_LEVEL_RANK = {
    CaseEvidenceLevel.C0_ENVIRONMENT: 0,
    CaseEvidenceLevel.C1_DISCOVERY: 1,
    CaseEvidenceLevel.C2_NORMALIZATION: 2,
    CaseEvidenceLevel.C3_CANONICAL_PLAN: 3,
    CaseEvidenceLevel.C4_STAGED_PROOF: 4,
    CaseEvidenceLevel.C5_PUBLICATION: 5,
    CaseEvidenceLevel.C6_SEMANTIC_OUTPUT: 6,
}

_VERDICT_SUMMARIES = {
    CaseEvidenceLevel.C0_ENVIRONMENT: "Diagnostic session closed without typed deobfuscation evidence.",
    CaseEvidenceLevel.C1_DISCOVERY: "Native discovery evidence was recorded.",
    CaseEvidenceLevel.C2_NORMALIZATION: "A typed frontend normalization intent was recorded.",
    CaseEvidenceLevel.C3_CANONICAL_PLAN: "A typed canonical mutation plan was recorded.",
    CaseEvidenceLevel.C4_STAGED_PROOF: "Typed staged proof evidence was recorded.",
    CaseEvidenceLevel.C5_PUBLICATION: "A typed mutation publication receipt was recorded.",
    CaseEvidenceLevel.C6_SEMANTIC_OUTPUT: "A typed semantic output witness was recorded.",
}


@dataclasses.dataclass(frozen=True, slots=True)
class ProjectedSemanticWitness:
    """One typed semantic verifier source retained for case materialization."""

    witness_id: str
    source_event_id: int
    verifier_id: str
    native_anchor_ea: int
    summary: str


@dataclasses.dataclass(frozen=True, slots=True)
class ClosedCaseProjection:
    """All normalized fields needed to write one closed case."""

    case_id: str
    session_id: str
    function_fingerprint: str
    runtime_identity: str
    run_identity: str
    closed_status: str
    closed_at: float
    findings: tuple[CaseFinding, ...]
    verdict: CaseVerdict
    semantic_witnesses: tuple[ProjectedSemanticWitness, ...] = ()
    finding_blocked_obligations: tuple[tuple[str, str], ...] = ()


def _require_text(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be non-empty")
    return value


def _accepted(outcome: object) -> bool:
    return str(outcome).strip().lower() in _ACCEPTED_OUTCOMES


def _event_provenance(event_id: int) -> tuple[str, ...]:
    return (f"lifecycle:{int(event_id)}",)


def _event_rows(
    conn: sqlite3.Connection,
    session_id: str,
) -> tuple[dict[str, object], ...]:
    rows = conn.execute(
        "SELECT event_id,event_seq,timestamp,event_kind,func_ea_i64 "
        "FROM lifecycle_events WHERE session_id=? ORDER BY event_seq,event_id",
        (session_id,),
    ).fetchall()
    return tuple(
        {
            "event_id": int(row[0]),
            "event_seq": int(row[1]),
            "timestamp": float(row[2]),
            "event_kind": str(row[3]),
            "func_ea_i64": int(row[4]),
        }
        for row in rows
    )


def _event_index(rows: tuple[dict[str, object], ...]) -> dict[int, dict[str, object]]:
    return {int(row["event_id"]): row for row in rows}


def _stable_finding(
    *,
    finding_id: str,
    event_id: int,
    kind: CaseFindingKind,
    level: CaseEvidenceLevel,
    summary: str,
    detail: object,
    native_ea: int | None,
    confidence: float | None,
) -> CaseFinding:
    if native_ea is not None and int(native_ea) < 0:
        raise ValueError("native anchor must be non-negative")
    detail_text = (
        ""
        if detail is None
        else (
            json.dumps(detail, sort_keys=True, separators=(",", ":"))
            if isinstance(detail, (dict, list, tuple))
            else str(detail)
        )
    )
    finding = CaseFinding(
        finding_id=_require_text(finding_id, "finding_id"),
        kind=kind,
        summary=_require_text(summary, "finding summary"),
        detail=detail_text,
        native_ea=None if native_ea is None else int(native_ea),
        confidence=confidence,
        provenance=_event_provenance(event_id),
    )
    return finding


def _load_session(
    conn: sqlite3.Connection,
    session_id: str,
) -> tuple[str, int, str, float | None, str] | None:
    row = conn.execute(
        "SELECT session_id,func_ea_i64,native_key_json,finished_at,status "
        "FROM diagnostic_sessions WHERE session_id=?",
        (session_id,),
    ).fetchone()
    if row is None:
        return None
    return (str(row[0]), int(row[1]), str(row[2]), row[3], str(row[4]))


def _runtime_identity(native_key_json: str) -> str:
    try:
        native_key = json.loads(native_key_json)
    except (TypeError, ValueError) as exc:
        raise ValueError("diagnostic session native key JSON is invalid") from exc
    if not isinstance(native_key, dict):
        raise ValueError("diagnostic session native key must be an object")
    _require_text(native_key.get("function_fingerprint"), "function_fingerprint")
    return native_key_json


def _source_event(
    event_index: dict[int, dict[str, object]],
    event_id: int,
    expected_kind: str,
) -> dict[str, object]:
    row = event_index.get(int(event_id))
    if row is None:
        raise ValueError(f"typed source event {event_id} is outside the session")
    if row["event_kind"] != expected_kind:
        raise ValueError(
            f"typed source event {event_id} has unexpected kind "
            f"{row['event_kind']!r}; expected {expected_kind!r}"
        )
    return row


def _first_plan_anchor(rows: list[tuple[object, ...]]) -> int:
    for row in rows:
        source_anchor = row[0]
        target_anchor = row[1]
        anchor = source_anchor if source_anchor is not None else target_anchor
        if anchor is not None:
            return int(anchor)
    raise ValueError("mutation plan has no native EA anchor")


def project_closed_case_rows(
    conn: sqlite3.Connection,
    session_id: str,
) -> ClosedCaseProjection:
    """Project one terminal diagnostic session from typed rows only."""
    session = _load_session(conn, session_id)
    if session is None:
        raise ValueError(f"diagnostic session {session_id!r} does not exist")
    _, function_ea, native_key_json, finished_at, status = session
    if status not in {"finished", "failed"}:
        raise ValueError("deobfuscation case requires a terminal diagnostic session")
    runtime_identity = _runtime_identity(native_key_json)
    native_key = json.loads(native_key_json)
    function_fingerprint = _require_text(
        native_key.get("function_fingerprint"), "function_fingerprint"
    )
    events = _event_rows(conn, session_id)
    event_index = _event_index(events)
    terminal = [
        row
        for row in events
        if row["event_kind"] == f"session_{status}"
    ]
    if not terminal:
        raise ValueError("terminal diagnostic session lacks a terminal lifecycle event")
    terminal_event = terminal[-1]
    closed_at = (
        float(finished_at)
        if finished_at is not None
        else float(terminal_event["timestamp"])
    )

    ordered: list[tuple[int, int, int, CaseFinding]] = []
    blockers: list[tuple[int, int, str]] = []
    finding_blockers: list[tuple[str, str]] = []
    semantic_witnesses: list[ProjectedSemanticWitness] = []

    def add(
        *,
        event_id: int,
        tie: int,
        finding: CaseFinding,
        event_kind: str,
        blocked_obligation: str | None = None,
    ) -> None:
        source = _source_event(event_index, event_id, event_kind)
        ordered.append(
            (int(source["event_seq"]), int(event_id), int(tie), finding)
        )
        if blocked_obligation is not None:
            blockers.append(
                (int(source["event_seq"]), int(event_id), blocked_obligation)
            )
            finding_blockers.append((finding.finding_id, blocked_obligation))

    for row in conn.execute(
        "SELECT e.event_id,e.operation,e.outcome,e.owner,e.reason,"
        "le.func_ea_i64 FROM evidence_generation_events e "
        "JOIN lifecycle_events le ON le.event_id=e.event_id "
        "WHERE le.session_id=? ORDER BY le.event_seq,e.event_id",
        (session_id,),
    ):
        event_id, operation, outcome, owner, reason, source_ea = row
        accepted = _accepted(outcome)
        add(
            event_id=int(event_id),
            tie=0,
            event_kind="evidence_generation",
            blocked_obligation=None if accepted else "evidence_generation_rejected",
            finding=_stable_finding(
                finding_id=f"evidence-generation:{int(event_id)}",
                event_id=int(event_id),
                kind=(
                    CaseFindingKind.OBSERVATION
                    if accepted
                    else CaseFindingKind.REJECTION
                ),
                level=CaseEvidenceLevel.C1_DISCOVERY,
                summary=(
                    "Portable evidence generation was accepted."
                    if accepted
                    else "Portable evidence generation was rejected."
                ),
                detail={
                    "operation": operation,
                    "owner": owner,
                    "outcome": outcome,
                    "reason": reason,
                },
                native_ea=int(source_ea),
                confidence=1.0 if accepted else 0.0,
            ),
        )

    for row in conn.execute(
        "SELECT i.event_id,i.decision_kind,i.consumer,i.identity_role,"
        "i.outcome,i.reason,i.primary_anchor_ea_i64,le.func_ea_i64 "
        "FROM identity_decisions i JOIN lifecycle_events le ON le.event_id=i.event_id "
        "WHERE le.session_id=? ORDER BY le.event_seq,i.event_id",
        (session_id,),
    ):
        (
            event_id,
            decision_kind,
            consumer,
            identity_role,
            outcome,
            reason,
            anchor,
            _source_ea,
        ) = row
        if anchor is None:
            raise ValueError("identity decision has no native EA anchor")
        accepted = _accepted(outcome)
        add(
            event_id=int(event_id),
            tie=0,
            event_kind="identity_decision",
            blocked_obligation=None if accepted else "identity_decision_rejected",
            finding=_stable_finding(
                finding_id=f"identity-decision:{int(event_id)}",
                event_id=int(event_id),
                kind=(
                    CaseFindingKind.PORTABLE_EVIDENCE
                    if accepted
                    else CaseFindingKind.REJECTION
                ),
                level=CaseEvidenceLevel.C1_DISCOVERY,
                summary=(
                    "A native identity decision was accepted."
                    if accepted
                    else "A native identity decision was rejected."
                ),
                detail={
                    "decision_kind": decision_kind,
                    "consumer": consumer,
                    "identity_role": identity_role,
                    "outcome": outcome,
                    "reason": reason,
                },
                native_ea=int(anchor),
                confidence=1.0 if accepted else 0.0,
            ),
        )

    for row in conn.execute(
        "SELECT p.event_id,p.work_item_id,p.plan_id,p.atomic_group_id,"
        "p.evidence_generation,p.complete_plan_json,le.func_ea_i64 "
        "FROM frontend_normalization_plan_intents p "
        "JOIN lifecycle_events le ON le.event_id=p.event_id "
        "WHERE le.session_id=? ORDER BY le.event_seq,p.event_id",
        (session_id,),
    ):
        event_id, work_item_id, plan_id, atomic_group_id, generation, plan_json, source_ea = row
        add(
            event_id=int(event_id),
            tie=0,
            event_kind="frontend_normalization_plan_intent",
            finding=_stable_finding(
                finding_id=f"normalization-intent:{int(event_id)}",
                event_id=int(event_id),
                kind=CaseFindingKind.PASS_DECISION,
                level=CaseEvidenceLevel.C2_NORMALIZATION,
                summary="A receipt-backed frontend normalization plan was recorded.",
                detail={
                    "work_item_id": work_item_id,
                    "plan_id": plan_id,
                    "atomic_group_id": atomic_group_id,
                    "evidence_generation": generation,
                    "complete_plan": plan_json,
                },
                native_ea=int(source_ea),
                confidence=1.0,
            ),
        )

    plans: dict[str, tuple[int, int, list[tuple[object, ...]]]] = {}
    for row in conn.execute(
        "SELECT le.event_id,le.event_seq,le.correlation_id,"
        "mpi.source_anchor_ea_i64,mpi.target_anchor_ea_i64,mpi.item_index "
        "FROM lifecycle_events le LEFT JOIN mutation_plan_items mpi "
        "ON mpi.event_id=le.event_id WHERE le.session_id=? "
        "AND le.event_kind='mutation_plan' "
        "ORDER BY le.event_seq,le.event_id,mpi.item_index",
        (session_id,),
    ):
        event_id, event_seq, batch_id, source_anchor, target_anchor, item_index = row
        if batch_id is None or not str(batch_id).strip():
            raise ValueError("mutation plan lacks its correlation id")
        record = plans.setdefault(
            str(batch_id), (int(event_id), int(event_seq), [])
        )
        record[2].append((source_anchor, target_anchor, item_index))
    for batch_id, (event_id, _event_seq, items) in plans.items():
        if not items:
            continue
        anchor = _first_plan_anchor(items)
        add(
            event_id=event_id,
            tie=0,
            event_kind="mutation_plan",
            finding=_stable_finding(
                finding_id=f"mutation-plan:{event_id}",
                event_id=event_id,
                kind=CaseFindingKind.FRAGMENT_PLAN,
                level=CaseEvidenceLevel.C3_CANONICAL_PLAN,
                summary="A typed canonical mutation plan was recorded.",
                detail={"mutation_batch_id": batch_id, "item_count": len(items)},
                native_ea=anchor,
                confidence=1.0,
            ),
        )

    for row in conn.execute(
        "SELECT v.event_id,v.mutation_batch_id,v.outcome_index,v.phase,"
        "v.postcondition,v.subject_id,v.passed,v.reason,le.func_ea_i64 "
        "FROM semantic_fragment_validation_outcomes v "
        "JOIN lifecycle_events le ON le.event_id=v.event_id "
        "WHERE le.session_id=? ORDER BY le.event_seq,v.event_id,v.outcome_index",
        (session_id,),
    ):
        (
            event_id,
            batch_id,
            outcome_index,
            phase,
            postcondition,
            subject_id,
            passed,
            reason,
            source_ea,
        ) = row
        passed = bool(passed)
        blocked = None
        if not passed:
            blocked = (
                "prepublication_validation_failed"
                if phase == "prepublication"
                else "postpublication_validation_failed"
            )
        add(
            event_id=int(event_id),
            tie=int(outcome_index),
            event_kind="mutation_receipt",
            blocked_obligation=blocked,
            finding=_stable_finding(
                finding_id=f"validation:{int(event_id)}:{int(outcome_index)}",
                event_id=int(event_id),
                kind=(CaseFindingKind.VALIDATION if passed else CaseFindingKind.REJECTION),
                level=CaseEvidenceLevel.C4_STAGED_PROOF,
                summary=(
                    "A semantic fragment validation passed."
                    if passed
                    else "A semantic fragment validation failed."
                ),
                detail={
                    "mutation_batch_id": batch_id,
                    "phase": phase,
                    "postcondition": postcondition,
                    "subject_id": subject_id,
                    "reason": reason,
                },
                native_ea=int(source_ea),
                confidence=1.0 if passed else 0.0,
            ),
        )

    for row in conn.execute(
        "SELECT o.event_id,o.mutation_batch_id,o.comparison_index,o.route_id,"
        "o.outcome,o.rewrite_anchor_ea_i64,o.reason "
        "FROM semantic_fragment_route_oracle_comparisons o "
        "JOIN lifecycle_events le ON le.event_id=o.event_id "
        "WHERE le.session_id=? ORDER BY le.event_seq,o.event_id,o.comparison_index",
        (session_id,),
    ):
        event_id, batch_id, comparison_index, route_id, outcome, anchor, reason = row
        if anchor is None:
            raise ValueError("route oracle comparison has no native EA anchor")
        accepted = _accepted(outcome)
        add(
            event_id=int(event_id),
            tie=int(comparison_index),
            event_kind="semantic_fragment_route_oracle",
            finding=_stable_finding(
                finding_id=f"route-oracle:{int(event_id)}:{int(comparison_index)}",
                event_id=int(event_id),
                kind=(CaseFindingKind.VALIDATION if accepted else CaseFindingKind.REJECTION),
                level=CaseEvidenceLevel.C4_STAGED_PROOF,
                summary=(
                    "A semantic route oracle comparison matched."
                    if accepted
                    else "A semantic route oracle comparison was rejected."
                ),
                detail={
                    "mutation_batch_id": batch_id,
                    "route_id": route_id,
                    "outcome": outcome,
                    "reason": reason,
                },
                native_ea=int(anchor),
                confidence=1.0 if accepted else 0.0,
            ),
        )

    plan_batches = set(plans)
    for row in conn.execute(
        "SELECT r.event_id,r.mutation_batch_id,r.mutation_kind,r.outcome,"
        "r.description,r.reason,le.event_seq "
        "FROM mutation_receipts r JOIN lifecycle_events le ON le.event_id=r.event_id "
        "WHERE le.session_id=? ORDER BY le.event_seq,r.event_id",
        (session_id,),
    ):
        event_id, batch_id, mutation_kind, outcome, description, reason, _event_seq = row
        batch_id = str(batch_id)
        if batch_id not in plan_batches:
            raise ValueError("mutation receipt has no correlated plan")
        identity_rows = conn.execute(
            "SELECT primary_anchor_ea_i64 FROM mutation_receipt_identities "
            "WHERE event_id=? ORDER BY identity_index",
            (int(event_id),),
        ).fetchall()
        if not identity_rows or any(row[0] is None for row in identity_rows):
            raise ValueError("mutation receipt has no anchored identity")
        anchor = int(identity_rows[0][0])
        accepted = _accepted(outcome)
        add(
            event_id=int(event_id),
            tie=0,
            event_kind="mutation_receipt",
            blocked_obligation=(
                None if accepted else "mutation_receipt_not_committed"
            ),
            finding=_stable_finding(
                finding_id=f"mutation-receipt:{int(event_id)}",
                event_id=int(event_id),
                kind=CaseFindingKind.RECEIPT if accepted else CaseFindingKind.REJECTION,
                level=CaseEvidenceLevel.C5_PUBLICATION,
                summary=(
                    "A mutation publication receipt committed."
                    if accepted
                    else "A mutation publication receipt did not commit."
                ),
                detail={
                    "mutation_batch_id": batch_id,
                    "mutation_kind": mutation_kind,
                    "outcome": outcome,
                    "description": description,
                    "reason": reason,
                },
                native_ea=anchor,
                confidence=1.0 if accepted else 0.0,
            ),
        )

    for row in conn.execute(
        "SELECT s.event_id,s.verifier_id,s.witness_id,s.summary,"
        "s.native_anchor_ea_i64,le.event_seq "
        "FROM semantic_output_verdicts s JOIN lifecycle_events le "
        "ON le.event_id=s.event_id WHERE le.session_id=? "
        "AND le.event_kind='semantic_output_verified' "
        "ORDER BY le.event_seq,s.event_id",
        (session_id,),
    ):
        event_id, verifier_id, witness_id, summary, anchor, _event_seq = row
        verifier_id = _require_text(verifier_id, "verifier_id")
        witness_id = _require_text(witness_id, "witness_id")
        summary = _require_text(summary, "semantic witness summary")
        if anchor is None or int(anchor) < 0:
            raise ValueError("semantic witness has no native EA anchor")
        semantic_witnesses.append(
            ProjectedSemanticWitness(
                witness_id=witness_id,
                source_event_id=int(event_id),
                verifier_id=verifier_id,
                native_anchor_ea=int(anchor),
                summary=summary,
            )
        )
        add(
            event_id=int(event_id),
            tie=0,
            event_kind="semantic_output_verified",
            finding=_stable_finding(
                finding_id=f"semantic-result:{int(event_id)}",
                event_id=int(event_id),
                kind=CaseFindingKind.SEMANTIC_RESULT,
                level=CaseEvidenceLevel.C6_SEMANTIC_OUTPUT,
                summary="A semantic output verifier supplied a typed witness.",
                detail={"verifier_id": verifier_id, "witness_id": witness_id},
                native_ea=int(anchor),
                confidence=1.0,
            ),
        )

    ordered.sort(key=lambda item: (item[0], item[1], item[2]))
    findings = tuple(item[3] for item in ordered)
    if not findings:
        findings = (
            _stable_finding(
                finding_id=f"environment:{int(terminal_event['event_id'])}",
                event_id=int(terminal_event["event_id"]),
                kind=CaseFindingKind.OBSERVATION,
                level=CaseEvidenceLevel.C0_ENVIRONMENT,
                summary=_VERDICT_SUMMARIES[CaseEvidenceLevel.C0_ENVIRONMENT],
                detail={"closed_status": status},
                native_ea=function_ea,
                confidence=1.0,
            ),
        )
        strongest = CaseEvidenceLevel.C0_ENVIRONMENT
    else:
        strongest = CaseEvidenceLevel.C0_ENVIRONMENT
        for _event_seq, _event_id, _tie, finding in ordered:
            level = _finding_level(finding)
            if _LEVEL_RANK[level] > _LEVEL_RANK[strongest]:
                strongest = level

    blockers.sort(key=lambda item: (item[0], item[1]))
    first_blocked = blockers[0][2] if blockers else None
    if strongest is CaseEvidenceLevel.C5_PUBLICATION and not semantic_witnesses:
        first_blocked = first_blocked or "semantic_output_verification"
    semantic_witness = semantic_witnesses[-1].witness_id if semantic_witnesses else None
    verdict = CaseVerdict(
        level=CaseEvidenceLevel.C6_SEMANTIC_OUTPUT
        if semantic_witnesses
        else strongest,
        summary=_VERDICT_SUMMARIES[
            CaseEvidenceLevel.C6_SEMANTIC_OUTPUT
            if semantic_witnesses
            else strongest
        ],
        first_blocked_obligation=first_blocked,
        semantic_witness=semantic_witness,
    )
    return ClosedCaseProjection(
        case_id=f"{session_id}:case-v1",
        session_id=session_id,
        function_fingerprint=function_fingerprint,
        runtime_identity=runtime_identity,
        run_identity=session_id,
        closed_status=status,
        closed_at=closed_at,
        findings=findings,
        verdict=verdict,
        semantic_witnesses=tuple(semantic_witnesses),
        finding_blocked_obligations=tuple(finding_blockers),
    )


def materialize_closed_deobfuscation_case(
    conn: sqlite3.Connection,
    session_id: str,
) -> str:
    """Project and atomically replace the deterministic closed case rows."""
    projection = project_closed_case_rows(conn, session_id)
    conn.execute(
        "DELETE FROM deobfuscation_case_semantic_witnesses WHERE case_id=?",
        (projection.case_id,),
    )
    conn.execute(
        "DELETE FROM deobfuscation_case_findings WHERE case_id=?",
        (projection.case_id,),
    )
    conn.execute(
        "DELETE FROM deobfuscation_cases WHERE case_id=?",
        (projection.case_id,),
    )
    conn.execute(
        "INSERT INTO deobfuscation_cases "
        "(case_id,session_id,case_schema_version,function_fingerprint,"
        "runtime_identity,run_identity,closed_status,closed_at,verdict_level,"
        "verdict_summary,first_blocked_obligation,semantic_witness) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            projection.case_id,
            projection.session_id,
            CASE_SCHEMA_VERSION,
            projection.function_fingerprint,
            projection.runtime_identity,
            projection.run_identity,
            projection.closed_status,
            projection.closed_at,
            projection.verdict.level.value,
            projection.verdict.summary,
            projection.verdict.first_blocked_obligation,
            projection.verdict.semantic_witness,
        ),
    )
    blocked_by_finding = dict(projection.finding_blocked_obligations)
    for finding_index, finding in enumerate(projection.findings):
        provenance_json = json.dumps(
            list(finding.provenance), sort_keys=True, separators=(",", ":")
        )
        source_event_id = int(finding.provenance[0].split(":", 1)[1])
        blocked = blocked_by_finding.get(finding.finding_id)
        conn.execute(
            "INSERT INTO deobfuscation_case_findings "
            "(case_id,finding_index,finding_id,source_event_id,finding_kind,"
            "evidence_level,summary,detail,native_anchor_ea_i64,confidence,"
            "provenance_json,blocked_obligation) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                projection.case_id,
                finding_index,
                finding.finding_id,
                source_event_id,
                finding.kind.value,
                _finding_level(finding).value,
                finding.summary,
                finding.detail,
                finding.native_ea,
                finding.confidence,
                provenance_json,
                blocked,
            ),
        )
    for witness in projection.semantic_witnesses:
        conn.execute(
            "INSERT INTO deobfuscation_case_semantic_witnesses "
            "(case_id,witness_id,source_event_id,verifier_id,"
            "native_anchor_ea_i64,summary) VALUES (?,?,?,?,?,?)",
            (
                projection.case_id,
                witness.witness_id,
                witness.source_event_id,
                witness.verifier_id,
                witness.native_anchor_ea,
                witness.summary,
            ),
        )
    return projection.case_id


def _finding_level(finding: CaseFinding) -> CaseEvidenceLevel:
    """Recover the fixed source level from the deterministic finding id."""
    prefix = finding.finding_id.split(":", 1)[0]
    return {
        "environment": CaseEvidenceLevel.C0_ENVIRONMENT,
        "evidence-generation": CaseEvidenceLevel.C1_DISCOVERY,
        "identity-decision": CaseEvidenceLevel.C1_DISCOVERY,
        "normalization-intent": CaseEvidenceLevel.C2_NORMALIZATION,
        "mutation-plan": CaseEvidenceLevel.C3_CANONICAL_PLAN,
        "validation": CaseEvidenceLevel.C4_STAGED_PROOF,
        "route-oracle": CaseEvidenceLevel.C4_STAGED_PROOF,
        "mutation-receipt": CaseEvidenceLevel.C5_PUBLICATION,
        "semantic-result": CaseEvidenceLevel.C6_SEMANTIC_OUTPUT,
    }.get(prefix, CaseEvidenceLevel.C0_ENVIRONMENT)
