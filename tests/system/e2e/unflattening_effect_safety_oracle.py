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
_PARITY_KEYS = frozenset(
    {"schema", "authority_id", "case_ids", "projected", "observed", "counters", "codec", "legacy_anchored_loss_labels", "parity_ok"}
)
_PARITY_RESULT_KEYS = frozenset({"accepted_equal", "reason_equal", "losses_equal"})
_CODEC_KEYS = frozenset({"captured_keys", "adaptations", "all_adapted"})
_ADAPTATION_KEYS = frozenset({"key", "family", "result_ids", "payload_sha256"})
_OBLIGATION_STATES = frozenset({"satisfied", "unproven", "violated", "inconsistent"})
_LEGACY_KEYS = frozenset({
    "concrete_state_route_provenance",
    "dispatcher_corridor_coverage",
    "dispatcher_removal_preflight_proof",
    "exact_state_branch_effect_exclusions",
    "full_unflattening_claim",
    "native_bound_transition_route_receipts",
    "unflatten_completion_status",
    "use_def_severance_audit",
})


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


@dataclass(frozen=True, slots=True)
class AuthorityOracleEvidence:
    projected: AuthorityPhaseOracleRow
    observed: AuthorityPhaseOracleRow
    parity: dict[str, object]
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
            "plan_id": evidence.plan_id,
            "attempt_id": evidence.attempt_id,
        }

    return {
        "schema": "unflatten-authority-oracle.v1",
        "target": target,
        "function": function,
        "function_ea": int(function_ea),
        "fixture_sha256": fixture_sha256,
        "session_id": str(session_id),
        "projected": timing(evidence.projected),
        "observed": timing(evidence.observed),
        "image": AUTHORITY_IMAGE,
        "parity": evidence.parity,
    }


def _authority_finite_nonnegative(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field} must be numeric")
    result = float(value)
    if not math.isfinite(result) or result < 0:
        raise ValueError(f"{field} must be finite and non-negative")
    return result


def _authority_phase_row(payload: Mapping[str, object], phase: str) -> AuthorityPhaseOracleRow:
    if payload.get("schema") != "unflatten_authority_phase.v1":
        raise ValueError("authority phase schema is invalid")
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
    if isinstance(generation, bool) or not isinstance(generation, int) or generation < 0:
        raise ValueError("authority generation is invalid")
    bindings = payload.get("bindings")
    if not isinstance(bindings, (list, tuple)):
        raise ValueError("authority bindings are missing")
    for item in bindings:
        if not isinstance(item, Mapping):
            raise ValueError("authority binding is invalid")
        binding_generation = item.get("generation")
        if isinstance(binding_generation, bool) or not isinstance(binding_generation, int) or binding_generation < 0:
            raise ValueError("authority binding generation is invalid")
        if generation != binding_generation:
            raise ValueError("authority binding generation differs from phase generation")
    if not bindings:
        raise ValueError("authority bindings are missing")
    loss_ledger = payload.get("loss_ledger")
    if not isinstance(loss_ledger, (list, tuple)):
        raise ValueError("authority loss ledger is missing")
    labels: list[str] = []
    for loss in loss_ledger:
        if not isinstance(loss, Mapping):
            raise ValueError("authority loss row is invalid")
        label = loss.get("anchor")
        if not isinstance(label, str) or not re.fullmatch(
            r"(?:blk[0-9]+|subject:sha256:[0-9a-f]{64})@0x[0-9a-f]+", label
        ):
            raise ValueError("authority loss anchor is invalid")
        labels.append(label)
    states = payload.get("obligation_states")
    if not isinstance(states, (list, tuple)):
        raise ValueError("authority obligation states are missing")
    counts = {state: 0 for state in ("unproven", "violated", "inconsistent")}
    for item in states:
        if not isinstance(item, Mapping) or item.get("state") not in _OBLIGATION_STATES:
            raise ValueError("authority obligation state is invalid")
        if item["state"] in counts:
            counts[item["state"]] += 1
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
    if abs(timing["total_authority_ms"] - sum(timing[key] for key in AUTHORITY_PHASES)) > 1.0:
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
        anchored_loss_labels=tuple(labels),
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


def _authority_codec(value: object, field: str) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != _CODEC_KEYS:
        raise ValueError(f"{field} is incomplete")
    captured = value.get("captured_keys")
    adaptations = value.get("adaptations")
    if not isinstance(captured, (list, tuple)) or not captured or list(captured) != sorted(set(captured)):
        raise ValueError(f"{field} captured keys are invalid")
    if any(key not in _LEGACY_KEYS for key in captured):
        raise ValueError(f"{field} captured keys contain unsupported key")
    if not isinstance(adaptations, (list, tuple)):
        raise ValueError(f"{field} adaptations are invalid")
    adapted_keys: list[str] = []
    for adaptation in adaptations:
        if not isinstance(adaptation, Mapping) or set(adaptation) != _ADAPTATION_KEYS:
            raise ValueError(f"{field} adaptation is incomplete")
        key = adaptation.get("key")
        if not isinstance(key, str) or key not in _LEGACY_KEYS:
            raise ValueError(f"{field} adaptation key is unsupported")
        adapted_keys.append(key)
        if adaptation.get("family") != key:
            raise ValueError(f"{field} family is invalid")
        result_ids = adaptation.get("result_ids")
        if not isinstance(result_ids, (list, tuple)) or any(not isinstance(item, str) or not item for item in result_ids) or list(result_ids) != sorted(set(result_ids)):
            raise ValueError(f"{field} result IDs are invalid")
        digest = adaptation.get("payload_sha256")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError(f"{field} payload digest is invalid")
    if adapted_keys != list(captured) or value.get("all_adapted") is not True:
        raise ValueError(f"{field} adaptation coverage is invalid")
    return dict(value)


def _authority_parity(
    value: Mapping[str, object],
    projected: AuthorityPhaseOracleRow,
    observed: AuthorityPhaseOracleRow,
    expected_codec: Mapping[str, object],
) -> dict[str, object]:
    if value.get("schema") != "unflatten_authority_shadow_parity.v2":
        raise ValueError("parity schema or keys are invalid")
    if "codec" not in value:
        raise ValueError("parity codec is incomplete")
    if set(value) != _PARITY_KEYS:
        raise ValueError("parity schema or keys are invalid")
    if value.get("authority_id") != projected.authority_id or value.get("authority_id") != observed.authority_id:
        raise ValueError("parity authority ID does not match phase rows")
    case_ids = value.get("case_ids")
    if not isinstance(case_ids, Mapping) or set(case_ids) != {"projected", "observed"}:
        raise ValueError("parity case IDs are invalid")
    if case_ids["projected"] != projected.case_id or case_ids["observed"] != observed.case_id:
        raise ValueError("parity case IDs do not match phase rows")
    for phase in ("projected", "observed"):
        row = value.get(phase)
        if not isinstance(row, Mapping) or set(row) != _PARITY_RESULT_KEYS or any(row[key] is not True for key in _PARITY_RESULT_KEYS):
            raise ValueError(f"parity {phase} result is invalid")
    legacy_labels = value.get("legacy_anchored_loss_labels")
    if not isinstance(legacy_labels, Mapping) or set(legacy_labels) != {"projected", "observed"}:
        raise ValueError("parity legacy anchored loss labels are invalid")
    for phase, phase_row in (("projected", projected), ("observed", observed)):
        labels = legacy_labels[phase]
        if (
            not isinstance(labels, (list, tuple))
            or any(
                not isinstance(label, str)
                or not re.fullmatch(r"(?:blk[0-9]+|subject:sha256:[0-9a-f]{64})@0x[0-9a-f]+", label)
                for label in labels
            )
            or len(set(labels)) != len(labels)
        ):
            raise ValueError(f"parity {phase} legacy anchored loss labels are invalid")
        if set(labels) != set(phase_row.anchored_loss_labels):
            raise ValueError(f"parity {phase} exact loss labels differ from canonical loss ledger")
        if value[phase]["losses_equal"] is not (set(labels) == set(phase_row.anchored_loss_labels)):
            raise ValueError(f"parity {phase} losses_equal is not derived from exact loss labels")
    counters = value.get("counters")
    if not isinstance(counters, Mapping) or set(counters) != {"projected", "observed"}:
        raise ValueError("parity counters are invalid")
    expected = {
        "projected": (projected.source_inventory_builds, projected.candidate_inventory_builds, projected.index_folds, projected.view_graph_traversals),
        "observed": (observed.source_inventory_builds, observed.candidate_inventory_builds, observed.index_folds, observed.view_graph_traversals),
    }
    for phase, values in expected.items():
        if not isinstance(counters[phase], (list, tuple)) or tuple(counters[phase]) != values:
            raise ValueError("parity counters do not match phase rows")
    codec = _authority_codec(value.get("codec"), "parity codec")
    if codec != dict(expected_codec):
        raise ValueError("parity codec differs from phase codec")
    if value.get("parity_ok") is not True:
        raise ValueError("parity_ok is false")
    return dict(value)


def parse_authority_phase_payloads(
    payloads: Iterable[Mapping[str, object]],
    *,
    expected_session_id: str | None = None,
) -> AuthorityOracleEvidence:
    """Parse exactly one projected/observed phase and final observed parity."""
    selected: dict[str, Mapping[str, object]] = {}
    for payload in payloads:
        if not isinstance(payload, Mapping):
            raise ValueError("authority phase payload is not an object")
        phase = payload.get("phase")
        if phase not in {"projected_preflight", "observed_post_apply"}:
            continue
        if expected_session_id is not None:
            payload_session = payload.get("session_id")
            if isinstance(payload_session, str) and payload_session and payload_session != expected_session_id:
                continue
        if phase in selected:
            raise ValueError(f"duplicate authority phase payload: {phase}")
        selected[phase] = payload
    if set(selected) != {"projected_preflight", "observed_post_apply"}:
        raise ValueError("authority phase payloads require exactly one projected and observed row")
    projected = _authority_phase_row(selected["projected_preflight"], "projected_preflight")
    observed = _authority_phase_row(selected["observed_post_apply"], "observed_post_apply")
    projected_codec = _authority_codec(selected["projected_preflight"].get("codec"), "projected codec")
    observed_codec = _authority_codec(selected["observed_post_apply"].get("codec"), "observed codec")
    if projected_codec != observed_codec:
        raise ValueError("projected and observed codec receipts differ")
    if "parity" in selected["projected_preflight"]:
        raise ValueError("projected phase parity is forbidden")
    if projected.authority_id != observed.authority_id:
        raise ValueError("authority IDs differ between phase rows")
    provenance = {
        key: selected["projected_preflight"][key]
        for key in ("plan_id", "attempt_id", "session_id")
    }
    for key, value in provenance.items():
        if selected["observed_post_apply"][key] != value:
            raise ValueError(f"{key} differs between phase rows")
    if expected_session_id is not None and provenance["session_id"] != expected_session_id:
        raise ValueError("session_id does not match selected diagnostic session")
    if projected.case_id == observed.case_id:
        raise ValueError("projected and observed case IDs must be distinct")
    if projected.source_fingerprint != observed.source_fingerprint:
        raise ValueError("source fingerprints differ between phase rows")
    if any(row.unproven or row.violated or row.inconsistent for row in (projected, observed)):
        raise ValueError("authority obligation states are not accepted")
    parity = selected["observed_post_apply"].get("parity")
    if not isinstance(parity, Mapping):
        raise ValueError("observed phase parity is required")
    return AuthorityOracleEvidence(
        projected,
        observed,
        _authority_parity(parity, projected, observed, projected_codec),
        provenance["plan_id"],
        provenance["attempt_id"],
        provenance["session_id"],
    )


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
