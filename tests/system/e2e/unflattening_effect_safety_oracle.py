"""Pure reachability helpers for the exact unflattening safety oracle."""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
import math
import re


AUTHORITY_PHASES = ("inventory_ms", "binding_ms", "evaluation_ms", "views_ms")
AUTHORITY_COUNTERS = (
    "source_inventory_builds",
    "candidate_inventory_builds",
    "index_folds",
    "view_graph_traversals",
)
AUTHORITY_IMAGE = "idapro-9.4-speedups:latest"
_OBLIGATION_STATES = frozenset({"satisfied", "unproven", "violated", "inconsistent"})
_LOSS_KINDS = frozenset(
    {
        "retired_dispatcher_infrastructure",
        "equivalent_semantic_route",
        "exact_infeasible_effect",
        "terminal_cycle_break",
        "local_alias_scalarization",
        "detached_dead_handler_component",
        "unclassified",
        "conflicting",
    }
)
_LOSS_SUMMARY_BUCKETS = (
    "structurally_lost",
    "allowed",
    "forbidden",
    "conflicting",
    "observed_only",
)
_UNACCEPTED_LOSS_KINDS = frozenset({"unclassified", "conflicting"})
_BINDING_STATUSES = frozenset(
    {
        "unique",
        "missing",
        "ambiguous",
        "stale_generation",
    }
)
_UNIQUE_CANDIDATE_LOSS_KINDS = frozenset(
    {
        "retired_dispatcher_infrastructure",
        "exact_infeasible_effect",
        "local_alias_scalarization",
    }
)


@dataclass(frozen=True, slots=True)
class AuthorityCoverageOracleRow:
    subject: str
    subject_id: str
    dimension: str
    state: str


@dataclass(frozen=True, slots=True)
class AuthorityObligationOracleRow:
    subject: str
    subject_id: str
    dimension: str
    state: str
    supporting_justification_ids: tuple[str, ...]
    refuting_justification_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AuthorityExplanationOracleRow:
    justification_id: str
    rule: str
    premise_ids: tuple[str, ...]
    conclusion_subject: str
    conclusion_subject_id: str
    conclusion_dimension: str
    polarity: str
    claim_id: str | None


@dataclass(frozen=True, slots=True)
class AuthorityLossOracleRow:
    subject: str
    subject_id: str
    anchor: str
    classification: str
    binding_status: str
    source_binding_status: str
    structural_dimension: str
    structural_state: str
    evidence_ids: tuple[str, ...]
    supporting_justification_ids: tuple[str, ...]
    refuting_justification_ids: tuple[str, ...]
    claim_ids: tuple[str, ...]
    rules: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AuthorityLossSummary:
    structurally_lost: tuple[str, ...]
    allowed: tuple[str, ...]
    forbidden: tuple[str, ...]
    conflicting: tuple[str, ...]
    observed_only: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AuthorityPhaseOracleRow:
    authority_id: str
    binding_id: str | None
    case_id: str
    phase: str
    accepted: bool
    reason: str
    source_fingerprint: str
    candidate_fingerprint: str
    generation: int
    anchored_loss_labels: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    justification_ids: tuple[str, ...]
    explanations: tuple[AuthorityExplanationOracleRow, ...]
    coverage_rows: tuple[AuthorityCoverageOracleRow, ...]
    loss_rows: tuple[AuthorityLossOracleRow, ...]
    observed_only_loss_rows: tuple[AuthorityLossOracleRow, ...]
    loss_summary: AuthorityLossSummary
    unproven: int
    violated: int
    inconsistent: int
    source_inventory_builds: int
    candidate_inventory_builds: int
    index_folds: int
    view_graph_traversals: int
    inventory_ms: float
    binding_ms: float
    evaluation_ms: float
    views_ms: float
    total_authority_ms: float

    @property
    def coverage_count(self) -> int:
        return len(self.coverage_rows)

    @property
    def loss_count(self) -> int:
        return len(self.loss_rows)


@dataclass(frozen=True, slots=True)
class AuthorityOracleEvidence:
    projected: AuthorityPhaseOracleRow
    observed: AuthorityPhaseOracleRow
    plan_id: str
    attempt_id: str
    session_id: str


def authority_oracle_marker_payload(
    *,
    target: str,
    function: str,
    function_ea: int,
    fixture_sha256: str,
    session_id: str,
    evidence: AuthorityOracleEvidence,
) -> dict[str, object]:
    """Serialize the closed marker consumed by the timing artifact parser."""
    if type(evidence) is not AuthorityOracleEvidence:
        raise TypeError("evidence must be AuthorityOracleEvidence")
    if str(session_id) != evidence.session_id:
        raise ValueError("marker session_id must match authority evidence")

    def timing(row: AuthorityPhaseOracleRow) -> dict[str, object]:
        return {
            "inventory_ms": row.inventory_ms,
            "binding_ms": row.binding_ms,
            "evaluation_ms": row.evaluation_ms,
            "views_ms": row.views_ms,
            "total_authority_ms": row.total_authority_ms,
            "source_inventory_builds": row.source_inventory_builds,
            "candidate_inventory_builds": row.candidate_inventory_builds,
            "index_folds": row.index_folds,
            "view_graph_traversals": row.view_graph_traversals,
        }

    return {
        "schema": "unflatten-authority-oracle.v2",
        "target": target,
        "function": function,
        "function_ea": int(function_ea),
        "fixture_sha256": fixture_sha256,
        "image": AUTHORITY_IMAGE,
        "canonical_pair": {
            "authority_id": evidence.projected.authority_id,
            "projected_case_id": evidence.projected.case_id,
            "observed_case_id": evidence.observed.case_id,
            "source_fingerprint": evidence.projected.source_fingerprint,
            "projected_candidate_fingerprint": evidence.projected.candidate_fingerprint,
            "observed_candidate_fingerprint": evidence.observed.candidate_fingerprint,
            "observed_binding_id": evidence.observed.binding_id,
            "plan_id": evidence.plan_id,
            "attempt_id": evidence.attempt_id,
            "session_id": evidence.session_id,
            "projected_timings": timing(evidence.projected),
            "observed_timings": timing(evidence.observed),
        },
    }


def _authority_finite_nonnegative(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field} must be numeric")
    result = float(value)
    if not math.isfinite(result) or result < 0:
        raise ValueError(f"{field} must be finite and non-negative")
    return result


def _authority_ids(value: object, field: str) -> tuple[str, ...]:
    if (
        not isinstance(value, (list, tuple))
        or any(not isinstance(item, str) or not item for item in value)
        or len(set(value)) != len(value)
    ):
        raise ValueError(f"authority {field} is invalid")
    return tuple(value)


def _authority_subject_id(value: object, field: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
        raise ValueError(f"authority {field} is invalid")
    return value


def _authority_explanations(
    value: object,
    *,
    evidence_ids: tuple[str, ...],
    justification_ids: tuple[str, ...],
) -> tuple[AuthorityExplanationOracleRow, ...]:
    if not isinstance(value, (list, tuple)):
        raise ValueError("authority explanations are missing")
    rows: list[AuthorityExplanationOracleRow] = []
    for item in value:
        if not isinstance(item, Mapping) or set(item) != {
            "justification_id",
            "rule",
            "premise_ids",
            "conclusion",
            "polarity",
            "claim_id",
        }:
            raise ValueError("authority explanation schema is invalid")
        justification_id = item.get("justification_id")
        rule = item.get("rule")
        premise_ids = _authority_ids(item.get("premise_ids"), "explanation premise_ids")
        conclusion = item.get("conclusion")
        polarity = item.get("polarity")
        claim_id = item.get("claim_id")
        if (
            not isinstance(justification_id, str)
            or not justification_id
            or not isinstance(rule, str)
            or not rule
            or not isinstance(conclusion, Mapping)
            or set(conclusion) != {"subject", "subject_id", "dimension"}
            or not isinstance(conclusion.get("subject"), str)
            or not conclusion["subject"]
            or not re.fullmatch(
                r"sha256:[0-9a-f]{64}",
                conclusion.get("subject_id", ""),
            )
            or not isinstance(conclusion.get("dimension"), str)
            or not conclusion["dimension"]
            or polarity not in {"supports", "refutes"}
            or (
                claim_id is not None and (not isinstance(claim_id, str) or not claim_id)
            )
        ):
            raise ValueError("authority explanation is invalid")
        if not set(premise_ids).issubset(evidence_ids):
            raise ValueError("authority explanation premise is outside phase evidence")
        rows.append(
            AuthorityExplanationOracleRow(
                justification_id,
                rule,
            premise_ids,
            conclusion["subject"],
            conclusion["subject_id"],
            conclusion["dimension"],
                polarity,
                claim_id,
            )
        )
    if len({row.justification_id for row in rows}) != len(rows):
        raise ValueError("authority explanations are not unique")
    if tuple(row.justification_id for row in rows) != justification_ids:
        raise ValueError("authority explanations do not match justification_ids")
    return tuple(rows)


def _authority_obligation_rows(
    value: object,
    *,
    justification_ids: tuple[str, ...],
) -> tuple[AuthorityObligationOracleRow, ...]:
    if not isinstance(value, (list, tuple)):
        raise ValueError("authority obligation states are missing")
    rows: list[AuthorityObligationOracleRow] = []
    for item in value:
        if not isinstance(item, Mapping) or set(item) != {
            "subject",
            "subject_id",
            "dimension",
            "state",
            "supports",
            "refutes",
        }:
            raise ValueError("authority obligation state is invalid")
        subject = item.get("subject")
        subject_id = _authority_subject_id(
            item.get("subject_id"), "obligation subject_id"
        )
        dimension = item.get("dimension")
        state = item.get("state")
        supports = _authority_ids(item.get("supports"), "obligation supports")
        refutes = _authority_ids(item.get("refutes"), "obligation refutes")
        if (
            not isinstance(subject, str)
            or not subject
            or not isinstance(dimension, str)
            or not dimension
            or state not in _OBLIGATION_STATES
        ):
            raise ValueError("authority obligation state is invalid")
        if state != "satisfied":
            raise ValueError("authority obligation state is not satisfied")
        if set(supports) & set(refutes):
            raise ValueError(
                "authority obligation supports and refutes are not disjoint"
            )
        if not set((*supports, *refutes)).issubset(justification_ids):
            raise ValueError(
                "authority obligation justification is outside phase inventory"
            )
        rows.append(
            AuthorityObligationOracleRow(
                subject,
                subject_id,
                dimension,
                state,
                supports,
                refutes,
            )
        )
    if len({(row.subject_id, row.dimension) for row in rows}) != len(rows):
        raise ValueError("authority obligation rows are not unique")
    return tuple(rows)


def _authority_loss_rows(
    value: object,
    field: str,
    *,
    evidence_ids: tuple[str, ...],
    justification_ids: tuple[str, ...],
) -> tuple[AuthorityLossOracleRow, ...]:
    if not isinstance(value, (list, tuple)):
        raise ValueError(f"authority {field} is missing")
    rows: list[AuthorityLossOracleRow] = []
    for loss in value:
        if not isinstance(loss, Mapping):
            raise ValueError(f"authority {field} row is invalid")
        subject = loss.get("subject")
        subject_id = _authority_subject_id(loss.get("subject_id"), "loss subject_id")
        binding_status = loss.get("binding_status")
        source_binding_status = loss.get("source_binding_status")
        if not isinstance(subject, str) or not subject:
            raise ValueError("authority loss subject is invalid")
        if binding_status not in _BINDING_STATUSES:
            raise ValueError("authority loss binding status is invalid")
        if source_binding_status != "unique":
            raise ValueError("authority loss source binding status is invalid")
        label = loss.get("anchor")
        if not isinstance(label, str) or not re.fullmatch(
            r"(?:blk[0-9]+|subject:sha256:[0-9a-f]{64})@0x[0-9a-f]+", label
        ):
            raise ValueError("authority loss anchor is invalid")
        classification = loss.get("classification")
        if not isinstance(classification, str) or classification not in _LOSS_KINDS:
            raise ValueError("authority loss classification is invalid")
        if binding_status not in {"missing", "unique"} or (
            binding_status == "unique"
            and classification not in _UNIQUE_CANDIDATE_LOSS_KINDS
        ):
            raise ValueError(
                "authority loss binding status is not valid for classification"
            )
        structural = loss.get("structural")
        if not isinstance(structural, Mapping) or set(structural) != {
            "dimension",
            "state",
        }:
            raise ValueError("authority loss structural state is invalid")
        structural_dimension = structural.get("dimension")
        structural_state = structural.get("state")
        if (
            structural_dimension != "structural_accounting"
            or structural_state not in _OBLIGATION_STATES
        ):
            raise ValueError("authority loss structural state is invalid")
        semantic = loss.get("semantic")
        if not isinstance(semantic, (list, tuple)):
            raise ValueError("authority loss semantic state is invalid")
        for semantic_cell in semantic:
            if not isinstance(semantic_cell, Mapping) or set(semantic_cell) != {
                "dimension",
                "state",
            }:
                raise ValueError("authority loss semantic state is invalid")
            if (
                not isinstance(semantic_cell.get("dimension"), str)
                or semantic_cell.get("state") not in _OBLIGATION_STATES
            ):
                raise ValueError("authority loss semantic state is invalid")

        row_evidence_ids = _authority_ids(loss.get("evidence_ids"), "loss evidence_ids")
        supports = _authority_ids(
            loss.get("supporting_justification_ids"),
            "loss supporting_justification_ids",
        )
        refutes = _authority_ids(
            loss.get("refuting_justification_ids"),
            "loss refuting_justification_ids",
        )
        claim_ids = _authority_ids(loss.get("claim_ids"), "loss claim_ids")
        rules = _authority_ids(loss.get("rules"), "loss rules")
        if not set(row_evidence_ids).issubset(evidence_ids):
            raise ValueError("authority loss evidence is outside phase inventory")
        if set(supports) & set(refutes):
            raise ValueError("authority loss supports and refutes are not disjoint")
        if not set((*supports, *refutes)).issubset(justification_ids):
            raise ValueError("authority loss justification is outside phase inventory")

        rows.append(
            AuthorityLossOracleRow(
                subject,
                subject_id,
                label,
                classification,
                binding_status,
                source_binding_status,
                structural_dimension,
                structural_state,
                row_evidence_ids,
                supports,
                refutes,
                claim_ids,
                rules,
            )
        )
    if len({row.subject_id for row in rows}) != len(rows):
        raise ValueError(f"authority {field} subject_ids are not unique")
    return tuple(rows)


def _authority_loss_summary(
    value: object,
    *,
    loss_rows: tuple[AuthorityLossOracleRow, ...],
    observed_only_loss_rows: tuple[AuthorityLossOracleRow, ...],
) -> AuthorityLossSummary:
    if not isinstance(value, Mapping) or set(value) != set(_LOSS_SUMMARY_BUCKETS):
        raise ValueError("authority loss summary schema is invalid")
    buckets: dict[str, tuple[str, ...]] = {}
    for name in _LOSS_SUMMARY_BUCKETS:
        raw = value.get(name)
        if not isinstance(raw, (list, tuple)) or any(
            not isinstance(item, str) for item in raw
        ):
            raise ValueError(f"authority loss summary {name} is invalid")
        rows = tuple(raw)
        if len(set(rows)) != len(rows):
            raise ValueError(f"authority loss summary {name} is not unique")
        if any(
            not re.fullmatch(
                r"(?:blk[0-9]+|subject:sha256:[0-9a-f]{64})@0x[0-9a-f]+", item
            )
            for item in rows
        ):
            raise ValueError(f"authority loss summary {name} anchor is invalid")
        buckets[name] = rows
    expected = {
        "structurally_lost": tuple(row.anchor for row in loss_rows),
        "allowed": tuple(
            row.anchor
            for row in loss_rows
            if row.classification not in _UNACCEPTED_LOSS_KINDS
        ),
        "forbidden": tuple(
            row.anchor for row in loss_rows if row.classification == "unclassified"
        ),
        "conflicting": tuple(
            row.anchor for row in loss_rows if row.classification == "conflicting"
        ),
        "observed_only": tuple(row.anchor for row in observed_only_loss_rows),
    }
    if buckets != expected:
        raise ValueError("authority loss summary disagrees with ledger")
    if buckets["forbidden"]:
        raise ValueError("authority loss summary contains forbidden loss")
    if buckets["conflicting"]:
        raise ValueError("authority loss summary contains conflicting loss")
    if any(
        row.classification in _UNACCEPTED_LOSS_KINDS for row in observed_only_loss_rows
    ):
        raise ValueError("authority observed-only loss is not canonically classified")
    return AuthorityLossSummary(**buckets)


def _authority_coverage_rows(value: object) -> tuple[AuthorityCoverageOracleRow, ...]:
    if not isinstance(value, (list, tuple)):
        raise ValueError("authority coverage is missing")
    rows: list[AuthorityCoverageOracleRow] = []
    for item in value:
        if not isinstance(item, Mapping) or set(item) != {
            "subject",
            "subject_id",
            "dimension",
            "state",
        }:
            raise ValueError("authority coverage row is invalid")
        subject, subject_id, dimension, state = (
            item.get(name) for name in ("subject", "subject_id", "dimension", "state")
        )
        if not isinstance(subject, str) or not subject:
            raise ValueError("authority coverage subject is invalid")
        if dimension != "corridor_coverage" or state not in _OBLIGATION_STATES:
            raise ValueError("authority coverage row is invalid")
        if state != "satisfied":
            raise ValueError("authority coverage row is not satisfied")
        rows.append(
            AuthorityCoverageOracleRow(
                subject,
                _authority_subject_id(subject_id, "coverage subject_id"),
                dimension,
                state,
            )
        )
    if len({(row.subject_id, row.dimension) for row in rows}) != len(rows):
        raise ValueError("authority coverage rows are not unique")
    return tuple(rows)


def _validate_coverage_obligations(
    coverage_rows: tuple[AuthorityCoverageOracleRow, ...],
    states: tuple[AuthorityObligationOracleRow, ...],
) -> None:
    """Require coverage to be the exact canonical obligation projection."""
    obligations: set[tuple[str, str, str]] = set()
    for item in states:
        if item.dimension == "corridor_coverage":
            obligations.add((item.subject, item.subject_id, item.dimension, item.state))
    coverage = {
        (row.subject, row.subject_id, row.dimension, row.state) for row in coverage_rows
    }
    if coverage != obligations:
        raise ValueError("authority coverage does not match canonical obligations")


def _authority_phase_row(
    payload: Mapping[str, object], phase: str
) -> AuthorityPhaseOracleRow:
    if payload.get("schema") != "unflatten_authority_phase.v2":
        raise ValueError("authority phase schema is invalid")
    if payload.get("schema_version") != 2:
        raise ValueError("authority phase schema_version is invalid")
    if payload.get("rule_set_version") != 1:
        raise ValueError("authority phase rule_set_version is invalid")
    if payload.get("phase") != phase:
        raise ValueError(f"authority phase must be {phase}")
    authority_id = payload.get("authority_id")
    case_id = payload.get("case_id")
    if not isinstance(authority_id, str) or not authority_id:
        raise ValueError("authority_id is invalid")
    if not isinstance(case_id, str) or not case_id:
        raise ValueError("case_id is invalid")
    provenance: dict[str, str] = {}
    for key in ("plan_id", "attempt_id", "session_id"):
        value = payload.get(key)
        if not isinstance(value, str) or not value:
            raise ValueError(f"{key} is invalid")
        provenance[key] = value
    binding_id = payload.get("binding_id")
    if phase == "projected_preflight":
        if binding_id is not None:
            raise ValueError("projected binding_id must be null")
    elif not isinstance(binding_id, str) or not binding_id:
        raise ValueError("observed binding_id is invalid")
    if payload.get("accepted") is not True or payload.get("reason") != "accepted":
        raise ValueError("authority phase is not accepted")
    source_fingerprint = payload.get("source_fingerprint")
    candidate_fingerprint = payload.get("candidate_fingerprint")
    if not isinstance(source_fingerprint, str) or not source_fingerprint:
        raise ValueError("source_fingerprint is invalid")
    if not isinstance(candidate_fingerprint, str) or not candidate_fingerprint:
        raise ValueError("candidate_fingerprint is invalid")
    generation = payload.get("generation")
    if (
        isinstance(generation, bool)
        or not isinstance(generation, int)
        or generation < 0
    ):
        raise ValueError("authority generation is invalid")
    bindings = payload.get("bindings")
    if not isinstance(bindings, (list, tuple)):
        raise ValueError("authority bindings are missing")
    for item in bindings:
        if not isinstance(item, Mapping):
            raise ValueError("authority binding is invalid")
        binding_generation = item.get("generation")
        if (
            isinstance(binding_generation, bool)
            or not isinstance(binding_generation, int)
            or binding_generation < 0
        ):
            raise ValueError("authority binding generation is invalid")
        if generation != binding_generation:
            raise ValueError(
                "authority binding generation differs from phase generation"
            )
    if not bindings:
        raise ValueError("authority bindings are missing")
    evidence_ids = _authority_ids(payload.get("evidence_ids"), "evidence_ids")
    justification_ids = _authority_ids(
        payload.get("justification_ids"),
        "justification_ids",
    )
    explanations = _authority_explanations(
        payload.get("explanations"),
        evidence_ids=evidence_ids,
        justification_ids=justification_ids,
    )
    state_rows = _authority_obligation_rows(
        payload.get("obligation_states"),
        justification_ids=justification_ids,
    )
    obligation_keys = {(row.subject_id, row.dimension) for row in state_rows}
    if any(
        (row.conclusion_subject_id, row.conclusion_dimension) not in obligation_keys
        for row in explanations
    ):
        raise ValueError(
            "authority explanation conclusion is outside obligation states"
        )
    coverage_rows = _authority_coverage_rows(payload.get("coverage"))
    _validate_coverage_obligations(coverage_rows, state_rows)
    loss_rows = _authority_loss_rows(
        payload.get("loss_ledger"),
        "loss ledger",
        evidence_ids=evidence_ids,
        justification_ids=justification_ids,
    )
    observed_only_loss_rows = _authority_loss_rows(
        payload.get("observed_only_loss"),
        "observed-only loss",
        evidence_ids=evidence_ids,
        justification_ids=justification_ids,
    )
    loss_summary = _authority_loss_summary(
        payload.get("loss_summary"),
        loss_rows=loss_rows,
        observed_only_loss_rows=observed_only_loss_rows,
    )
    counts = {state: 0 for state in ("unproven", "violated", "inconsistent")}
    metrics = payload.get("metrics")
    if not isinstance(metrics, Mapping):
        raise ValueError("authority phase metrics are missing")
    counters: dict[str, int] = {}
    for key in AUTHORITY_COUNTERS:
        value = metrics.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"authority counter {key} is invalid")
        counters[key] = value
    if tuple(counters[key] for key in AUTHORITY_COUNTERS) != (1, 1, 1, 0):
        raise ValueError("authority counters are invalid")
    timings = payload.get("timings")
    if not isinstance(timings, Mapping):
        raise ValueError("authority timings are missing")
    timing = {
        key: _authority_finite_nonnegative(timings.get(key), f"timing {key}")
        for key in (*AUTHORITY_PHASES, "total_authority_ms")
    }
    if (
        abs(timing["total_authority_ms"] - sum(timing[key] for key in AUTHORITY_PHASES))
        > 1.0
    ):
        raise ValueError("authority timing total is inconsistent")
    return AuthorityPhaseOracleRow(
        authority_id=authority_id,
        binding_id=binding_id if isinstance(binding_id, str) else None,
        case_id=case_id,
        phase=phase,
        accepted=True,
        reason="accepted",
        source_fingerprint=source_fingerprint,
        candidate_fingerprint=candidate_fingerprint,
        generation=generation,
        anchored_loss_labels=tuple(row.anchor for row in loss_rows),
        evidence_ids=evidence_ids,
        justification_ids=justification_ids,
        explanations=explanations,
        coverage_rows=coverage_rows,
        loss_rows=loss_rows,
        observed_only_loss_rows=observed_only_loss_rows,
        loss_summary=loss_summary,
        unproven=counts["unproven"],
        violated=counts["violated"],
        inconsistent=counts["inconsistent"],
        source_inventory_builds=counters["source_inventory_builds"],
        candidate_inventory_builds=counters["candidate_inventory_builds"],
        index_folds=counters["index_folds"],
        view_graph_traversals=counters["view_graph_traversals"],
        inventory_ms=timing["inventory_ms"],
        binding_ms=timing["binding_ms"],
        evaluation_ms=timing["evaluation_ms"],
        views_ms=timing["views_ms"],
        total_authority_ms=timing["total_authority_ms"],
    )


def parse_authority_phase_payloads(
    payloads: Iterable[Mapping[str, object]],
    *,
    expected_session_id: str | None = None,
) -> AuthorityOracleEvidence:
    """Parse exactly one canonical projected/observed authority-phase pair."""
    selected: dict[str, Mapping[str, object]] = {}
    for payload in payloads:
        if not isinstance(payload, Mapping):
            raise ValueError("authority phase payload is not an object")
        phase = payload.get("phase")
        if phase not in {"projected_preflight", "observed_post_apply"}:
            continue
        if expected_session_id is not None:
            payload_session = payload.get("session_id")
            if (
                isinstance(payload_session, str)
                and payload_session
                and payload_session != expected_session_id
            ):
                continue
        if phase in selected:
            raise ValueError(f"duplicate authority phase payload: {phase}")
        selected[phase] = payload
    if set(selected) != {"projected_preflight", "observed_post_apply"}:
        raise ValueError(
            "authority phase payloads require exactly one projected and observed row"
        )
    projected = _authority_phase_row(
        selected["projected_preflight"], "projected_preflight"
    )
    observed = _authority_phase_row(
        selected["observed_post_apply"], "observed_post_apply"
    )
    if projected.authority_id != observed.authority_id:
        raise ValueError("authority IDs differ between phase rows")
    provenance = {
        key: selected["projected_preflight"][key]
        for key in ("plan_id", "attempt_id", "session_id")
    }
    for key, value in provenance.items():
        if selected["observed_post_apply"][key] != value:
            raise ValueError(f"{key} differs between phase rows")
    if (
        expected_session_id is not None
        and provenance["session_id"] != expected_session_id
    ):
        raise ValueError("session_id does not match selected diagnostic session")
    if projected.case_id == observed.case_id:
        raise ValueError("projected and observed case IDs must be distinct")
    if projected.source_fingerprint != observed.source_fingerprint:
        raise ValueError("source fingerprints differ between phase rows")
    if any(
        row.unproven or row.violated or row.inconsistent
        for row in (projected, observed)
    ):
        raise ValueError("authority obligation states are not accepted")
    if projected.observed_only_loss_rows or projected.loss_summary.observed_only:
        raise ValueError("projected authority phase cannot carry observed-only loss")
    projected_by_subject_id = {row.subject_id: row for row in projected.loss_rows}
    expected_observed_only = tuple(
        row
        for row in observed.loss_rows
        if row.subject_id not in projected_by_subject_id
    )
    if tuple(
        (row.subject_id, row.classification) for row in observed.observed_only_loss_rows
    ) != tuple((row.subject_id, row.classification) for row in expected_observed_only):
        raise ValueError("observed-only loss does not match canonical ledger delta")
    return AuthorityOracleEvidence(
        projected,
        observed,
        provenance["plan_id"],
        provenance["attempt_id"],
        provenance["session_id"],
    )


def require_target_authority_policy(
    evidence: AuthorityOracleEvidence,
    target: str,
) -> None:
    """Apply exact fixture policy to an already-validated canonical pair.

    A makes a deliberately partial redirect and retains its dispatcher; B/C
    are full dispatcher-retirement outcomes.  This only inspects typed rows
    emitted by the authority verdict and never reconstructs CFG coverage.
    """
    if type(evidence) is not AuthorityOracleEvidence:
        raise TypeError("evidence must be AuthorityOracleEvidence")
    if target not in {"A", "B", "C"}:
        raise ValueError("unknown authority target")
    if target == "A":
        for phase in (evidence.projected, evidence.observed):
            if phase.coverage_rows or phase.loss_rows or phase.observed_only_loss_rows:
                raise ValueError(
                    "target A must retain an empty coverage and loss ledger"
                )
            summary = phase.loss_summary
            if any(getattr(summary, name) for name in _LOSS_SUMMARY_BUCKETS):
                raise ValueError("target A must retain an empty loss summary")
        return
    observed = evidence.observed
    if not any(
        row.dimension == "corridor_coverage" and row.state == "satisfied"
        for row in observed.coverage_rows
    ):
        raise ValueError(
            "dispatcher-removal target requires observed corridor coverage"
        )
    explanations_by_id = {row.justification_id: row for row in observed.explanations}

    def sealed_retirement(row: AuthorityLossOracleRow) -> bool:
        if not (
            row.classification == "retired_dispatcher_infrastructure"
            and row.structural_dimension == "structural_accounting"
            and row.structural_state == "satisfied"
            and row.evidence_ids
            and row.supporting_justification_ids
            and row.claim_ids
            and row.rules == ("retired_infrastructure_proven",)
        ):
            return False
        support = tuple(
            explanations_by_id[justification_id]
            for justification_id in row.supporting_justification_ids
        )
        return all(
            explanation.polarity == "supports"
            and explanation.rule == "retired_infrastructure_proven"
            and explanation.claim_id in row.claim_ids
            and explanation.conclusion_subject_id == row.subject_id
            and explanation.conclusion_dimension == "structural_accounting"
            and bool(explanation.premise_ids)
            and set(explanation.premise_ids).issubset(row.evidence_ids)
            for explanation in support
        )

    retired_rows = tuple(row for row in observed.loss_rows if sealed_retirement(row))
    if not retired_rows:
        raise ValueError("dispatcher-removal target requires retired dispatcher loss")


def select_committed_authority_phase_payloads(
    payloads: Iterable[Mapping[str, object]],
    *,
    clean_committed_correlations: set[tuple[str, str, str]],
    expected_session_id: str,
) -> tuple[Mapping[str, object], ...]:
    """Select the one committed authority correlation before strict parsing."""
    grouped: dict[tuple[str, str, str], list[Mapping[str, object]]] = {}
    for payload in payloads:
        if not isinstance(payload, Mapping):
            raise ValueError("authority phase payload is not an object")
        if payload.get("phase") not in {"projected_preflight", "observed_post_apply"}:
            raise ValueError("authority phase payload phase is invalid")
        correlation = tuple(
            payload.get(field) for field in ("plan_id", "attempt_id", "session_id")
        )
        if any(not isinstance(value, str) or not value for value in correlation):
            raise ValueError("authority phase payload correlation is malformed")
        plan_id, attempt_id, session_id = correlation
        if session_id != expected_session_id:
            raise ValueError("authority phase payload is cross-session")
        grouped.setdefault((plan_id, attempt_id, session_id), []).append(payload)
    matching = set(grouped).intersection(clean_committed_correlations)
    if len(matching) != 1:
        raise ValueError("require exactly one committed authority correlation")
    return tuple(grouped[next(iter(matching))])


def session_scoped_rows(
    rows: Iterable[tuple[object, ...]],
    session_id: str,
    *,
    session_index: int = -1,
) -> tuple[tuple[object, ...], ...]:
    """Keep only rows owned by the selected diagnostic session.

    SQLite queries in the exact fixture already constrain their joins by
    ``session_id``.  This small pure postcondition keeps the test oracle
    fail-closed if a query is later broadened or a view starts returning
    cross-session rows, and gives unit tests a direct stale-row regression.
    """
    selected = str(session_id)
    selected_rows: list[tuple[object, ...]] = []
    for row in rows:
        index = session_index if session_index >= 0 else len(row) + session_index
        if 0 <= index < len(row) and str(row[index]) == selected:
            selected_rows.append(row)
    return tuple(selected_rows)


def transaction_bound_dispatcher_removal_proofs(
    proofs: Iterable[Mapping[str, object]],
    *,
    committed_attempts: Iterable[tuple[object, object]],
    committed_batches: Iterable[object],
) -> tuple[Mapping[str, object], ...]:
    """Keep applied removal proofs owned by one committed plan/attempt/batch.

    A diagnostic session may contain stale or superseded observations.  The
    proof is authoritative only when its ``(plan_id, attempt_id)`` pair is a
    clean committed CFG attempt and the same attempt id is the committed
    mutation batch.  The caller supplies rows already constrained to the
    selected diagnostic session.
    """
    committed_identities = {
        (str(plan_id), str(attempt_id))
        for plan_id, attempt_id in committed_attempts
        if plan_id is not None and attempt_id is not None
    }
    committed_batch_ids = {
        str(batch_id) for batch_id in committed_batches if batch_id is not None
    }
    selected: list[Mapping[str, object]] = []
    for payload in proofs:
        if not isinstance(payload, Mapping):
            continue
        if payload.get("application_status") != "applied":
            continue
        plan_id = payload.get("plan_id")
        attempt_id = payload.get("attempt_id")
        if plan_id is None or attempt_id is None:
            continue
        identity = (str(plan_id), str(attempt_id))
        if identity not in committed_identities:
            continue
        if str(attempt_id) not in committed_batch_ids:
            continue
        selected.append(payload)
    return tuple(selected)


def require_distinct_native_eas(
    call_eas: Iterable[int],
    *,
    expected_count: int | None = None,
) -> tuple[int, ...]:
    """Validate source-bound native marker EAs before exact CFG traversal."""
    values = tuple(int(ea) for ea in call_eas)
    if expected_count is not None and len(values) != int(expected_count):
        raise ValueError(
            f"expected {int(expected_count)} native EAs, found {len(values)}"
        )
    if len(set(values)) != len(values):
        raise ValueError("native marker EAs must be distinct")
    return values


def reachable_call_eas(
    block_successors: Mapping[int, Iterable[int]],
    call_eas_by_block: Mapping[int, Iterable[int]],
    *,
    entry_serial: int = 0,
) -> frozenset[int]:
    """Return exact native call EAs in the entry-reachable post-D810 CFG.

    The graph and call map are already persisted snapshot facts.  Unknown
    successor serials are malformed evidence, not an unreachable-call
    fallback, so this helper fails closed with ``ValueError``.
    """
    graph = {
        int(serial): tuple(int(target) for target in successors)
        for serial, successors in block_successors.items()
    }
    entry = int(entry_serial)
    if entry not in graph:
        raise ValueError(f"post-D810 snapshot has no entry block {entry}")
    if any(
        int(target) not in graph
        for successors in graph.values()
        for target in successors
    ):
        raise ValueError("post-D810 snapshot contains an unknown successor")

    reachable: set[int] = set()
    pending = deque((entry,))
    while pending:
        serial = int(pending.popleft())
        if serial in reachable:
            continue
        reachable.add(serial)
        pending.extend(graph[serial])

    return frozenset(
        int(ea)
        for serial, eas in call_eas_by_block.items()
        if int(serial) in reachable
        for ea in eas
    )
