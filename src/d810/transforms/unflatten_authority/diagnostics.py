"""Typed diagnostic projections for unflatten authority phases."""

from __future__ import annotations

from dataclasses import dataclass
import math
from time import perf_counter_ns
from d810.analyses.value_flow.observation import FactObservation
from d810.transforms.cfg_transaction import TransactionAttemptId

from . import model
from .legacy_codec import LegacyShadowCodecReceipt
from .views import ViewMetrics, compatibility_projection, observed_only_loss, semantic_loss_ledger


@dataclass(frozen=True, slots=True)
class ShadowParityCounters:
    source_inventory_builds: int
    candidate_inventory_builds: int
    index_folds: int
    view_graph_traversals: int

    def __post_init__(self) -> None:
        for name in ("source_inventory_builds", "candidate_inventory_builds", "index_folds", "view_graph_traversals"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise TypeError(f"{name} must be a non-negative exact int")

    @property
    def tuple(self) -> tuple[int, int, int, int]:
        return (self.source_inventory_builds, self.candidate_inventory_builds, self.index_folds, self.view_graph_traversals)

    @classmethod
    def from_case(cls, case: model.SemanticSafetyCase) -> "ShadowParityCounters":
        if type(case) is not model.SemanticSafetyCase:
            raise TypeError("case must be SemanticSafetyCase")
        metrics = case.phase_metrics
        # The source inventory is owned by preparation and reused by the
        # observed phase.  The preparation receipt is the cumulative source
        # build authority; phase-local metrics remain local work counters.
        return cls(
            metrics.preparation_metrics.source_inventory_builds,
            metrics.candidate_inventory_builds,
            metrics.index_folds,
            metrics.view_graph_traversals,
        )


@dataclass(frozen=True, slots=True)
class LegacyPhaseOutcome:
    phase: model.UnflattenAuthorityPhase
    accepted: bool
    reason_scope: model.UnflattenAuthorityReason
    anchored_losses: tuple[tuple[int, int], ...]

    def __post_init__(self) -> None:
        if type(self.phase) is not model.UnflattenAuthorityPhase:
            raise TypeError("phase must be UnflattenAuthorityPhase")
        if type(self.accepted) is not bool:
            raise TypeError("accepted must be an exact bool")
        if type(self.reason_scope) is not model.UnflattenAuthorityReason:
            raise TypeError("reason_scope must be UnflattenAuthorityReason")
        rows = tuple(self.anchored_losses)
        if any(
            type(row) is not tuple or len(row) != 2
            or type(row[0]) is not int or type(row[1]) is not int
            for row in rows
        ):
            raise TypeError("anchored_losses must contain (serial, ea) tuples")
        if any(serial < 0 or ea < 0 for serial, ea in rows):
            raise ValueError("anchored loss coordinates must be non-negative")
        if rows != tuple(sorted(set(rows))):
            raise ValueError("anchored_losses must be unique and canonical")
        object.__setattr__(self, "anchored_losses", rows)

    @property
    def anchored_loss_labels(self) -> tuple[str, ...]:
        return tuple(f"blk{serial}@0x{ea:x}" for serial, ea in self.anchored_losses)


def _canonical_losses(verdict: model.UnflattenAuthorityVerdict) -> tuple[tuple[int, int], ...]:
    case = verdict.safety_case
    if case is None:
        return ()
    return tuple(sorted((row.source_serial, row.source_anchor_ea) for row in semantic_loss_ledger(case).rows))


@dataclass(frozen=True, slots=True)
class LegacyCanonicalParityRow:
    legacy: LegacyPhaseOutcome
    canonical: model.UnflattenAuthorityVerdict
    accepted_equal: bool
    reason_equal: bool
    losses_equal: bool

    def __post_init__(self) -> None:
        if type(self.legacy) is not LegacyPhaseOutcome or type(self.canonical) is not model.UnflattenAuthorityVerdict:
            raise TypeError("parity row requires closed legacy and canonical outcomes")
        if self.legacy.phase is not self.canonical.phase:
            raise ValueError("legacy and canonical phases differ")
        if (self.accepted_equal, self.reason_equal, self.losses_equal) != (
            self.legacy.accepted == self.canonical.accepted,
            self.legacy.reason_scope is self.canonical.reason,
            self.legacy.anchored_losses == _canonical_losses(self.canonical),
        ):
            raise ValueError("parity row equality fields are not derived")


@dataclass(frozen=True, slots=True)
class ShadowParityPayload:
    projected: LegacyCanonicalParityRow
    observed: LegacyCanonicalParityRow
    authority_id: str
    projected_case_id: str | None
    observed_case_id: str | None
    projected_counters: ShadowParityCounters
    observed_counters: ShadowParityCounters
    codec_receipt: LegacyShadowCodecReceipt

    def __post_init__(self) -> None:
        if type(self.projected) is not LegacyCanonicalParityRow or type(self.observed) is not LegacyCanonicalParityRow:
            raise TypeError("parity rows must be closed")
        if type(self.authority_id) is not str or not self.authority_id:
            raise TypeError("authority_id must be non-empty")
        if self.projected.canonical.authority_id != self.authority_id or self.observed.canonical.authority_id != self.authority_id:
            raise ValueError("parity authority IDs differ")
        for row, case_id, label in (
            (self.projected, self.projected_case_id, "projected"),
            (self.observed, self.observed_case_id, "observed"),
        ):
            if row.canonical.accepted:
                if type(case_id) is not str or not case_id:
                    raise ValueError(f"accepted {label} parity requires a non-empty case ID")
            elif case_id is not None and (type(case_id) is not str or not case_id):
                raise ValueError(f"{label} case ID must be a non-empty string or None")
            if row.canonical.case_id != case_id:
                raise ValueError(f"{label} parity case ID is not canonical")
        if (
            self.projected_case_id is not None
            and self.observed_case_id is not None
            and self.projected_case_id == self.observed_case_id
        ):
            raise ValueError("projected and observed case IDs must be distinct")
        if type(self.codec_receipt) is not LegacyShadowCodecReceipt:
            raise TypeError("codec_receipt must be LegacyShadowCodecReceipt")
        for name, counters in (("projected_counters", self.projected_counters), ("observed_counters", self.observed_counters)):
            if type(counters) is not ShadowParityCounters:
                raise TypeError(f"{name} must be ShadowParityCounters")

    @property
    def parity_ok(self) -> bool:
        return (
            self.projected.accepted_equal and self.projected.reason_equal
            and self.projected.losses_equal and self.observed.accepted_equal
            and self.observed.reason_equal and self.observed.losses_equal
            and self.projected_counters.tuple == (1, 1, 1, 0)
            and self.observed_counters.tuple == (1, 1, 1, 0)
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "schema": "unflatten_authority_shadow_parity.v2",
            "authority_id": self.authority_id,
            "case_ids": {"projected": self.projected_case_id, "observed": self.observed_case_id},
            "projected": {"accepted_equal": self.projected.accepted_equal, "reason_equal": self.projected.reason_equal, "losses_equal": self.projected.losses_equal},
            "observed": {"accepted_equal": self.observed.accepted_equal, "reason_equal": self.observed.reason_equal, "losses_equal": self.observed.losses_equal},
            "legacy_anchored_loss_labels": {
                "projected": self.projected.legacy.anchored_loss_labels,
                "observed": self.observed.legacy.anchored_loss_labels,
            },
            "counters": {"projected": self.projected_counters.tuple, "observed": self.observed_counters.tuple},
            "codec": {
                "captured_keys": self.codec_receipt.consumed_keys,
                "adaptations": tuple({
                    "key": item.key,
                    "family": item.family,
                    "result_ids": item.result_ids,
                    "payload_sha256": item.payload_sha256,
                } for item in self.codec_receipt.adaptations),
                "all_adapted": len(self.codec_receipt.adaptations) == len(self.codec_receipt.shadow.entries),
            },
            "parity_ok": self.parity_ok,
        }


def compare_shadow_parity(
    projected_legacy: LegacyPhaseOutcome,
    projected_canonical: model.UnflattenAuthorityVerdict,
    observed_legacy: LegacyPhaseOutcome,
    observed_canonical: model.UnflattenAuthorityVerdict,
    *,
    projected_counters: ShadowParityCounters,
    observed_counters: ShadowParityCounters,
    codec_receipt: LegacyShadowCodecReceipt,
) -> ShadowParityPayload:
    """Compare legacy and canonical facts independently for each phase."""

    projected = LegacyCanonicalParityRow(
        projected_legacy, projected_canonical,
        projected_legacy.accepted == projected_canonical.accepted,
        projected_legacy.reason_scope is projected_canonical.reason,
        projected_legacy.anchored_losses == _canonical_losses(projected_canonical),
    )
    observed = LegacyCanonicalParityRow(
        observed_legacy, observed_canonical,
        observed_legacy.accepted == observed_canonical.accepted,
        observed_legacy.reason_scope is observed_canonical.reason,
        observed_legacy.anchored_losses == _canonical_losses(observed_canonical),
    )
    if projected_canonical.authority_id is None or observed_canonical.authority_id != projected_canonical.authority_id:
        raise ValueError("parity authority IDs differ")
    return ShadowParityPayload(
        projected, observed, projected_canonical.authority_id,
        projected_canonical.case_id, observed_canonical.case_id,
        projected_counters, observed_counters, codec_receipt,
    )


project_shadow_parity = compare_shadow_parity
parity_projection = compare_shadow_parity


def require_shadow_parity(payload: ShadowParityPayload) -> None:
    """Raise for a diagnostic mismatch at an explicit owner/test boundary."""

    if type(payload) is not ShadowParityPayload:
        raise TypeError("payload must be ShadowParityPayload")
    for name, row in (("projected", payload.projected), ("observed", payload.observed)):
        if not (row.accepted_equal and row.reason_equal and row.losses_equal):
            raise ValueError(
                f"{name} legacy/canonical parity mismatch: "
                f"accepted={row.accepted_equal}, reason={row.reason_equal}, "
                f"losses={row.losses_equal}"
            )
    if payload.projected_counters.tuple != (1, 1, 1, 0) or payload.observed_counters.tuple != (1, 1, 1, 0):
        raise ValueError(
            "shadow parity counter mismatch: "
            f"projected={payload.projected_counters.tuple}, "
            f"observed={payload.observed_counters.tuple}"
        )


@dataclass(frozen=True, slots=True)
class PhaseTimings:
    """Closed timing values supplied by the transaction observer."""

    inventory_ms: float | None = None
    binding_ms: float | None = None
    evaluation_ms: float | None = None
    views_ms: float | None = None
    total_authority_ms: float | None = None
    observation_ms: float | None = None

    def __post_init__(self) -> None:
        for name in (
            "inventory_ms", "binding_ms", "evaluation_ms", "views_ms",
            "total_authority_ms", "observation_ms",
        ):
            value = getattr(self, name)
            if value is not None and (
                type(value) is not float or value < 0 or not math.isfinite(value)
            ):
                raise TypeError(f"{name} must be a non-negative float or None")


def _subject_label(subject: model.SemanticSubjectRef) -> str:
    if subject.anchor_ea is None:
        return subject.subject_id
    return f"{subject.subject_id}@0x{subject.anchor_ea:x}"


def _loss_row_payload(row: model.SemanticLossRow) -> dict[str, object]:
    return {
        "subject": _subject_label(row.source_subject),
        "classification": row.kind.value,
        "binding_status": row.candidate_binding.status.value,
        "source_binding_status": row.source_binding.status.value,
        "anchor": row.anchored_location,
        "structural": {
            "dimension": row.structural_obligation.key.dimension.value,
            "state": row.structural_obligation.state.value,
        },
        "semantic": tuple(
            {
                "dimension": cell.key.dimension.value,
                "state": cell.state.value,
            }
            for cell in row.relevant_semantic_obligations
        ),
        "evidence_ids": row.evidence_ids,
        "supporting_justification_ids": row.supporting_justification_ids,
        "refuting_justification_ids": row.refuting_justification_ids,
        "claim_ids": row.claim_ids,
        "rules": tuple(rule.value for rule in row.rules),
    }


def _phase_view_projection(
    verdict: model.UnflattenAuthorityVerdict,
    projected_case: model.SemanticSafetyCase | None,
) -> tuple[object, object, dict[str, str] | None]:
    case = verdict.safety_case
    ledger = None if case is None else semantic_loss_ledger(case)
    observed_delta = None
    observed_delta_rejection = None
    if projected_case is not None and case is not None:
        observed_delta = observed_only_loss(projected_case, case)
    elif projected_case is not None:
        observed_delta_rejection = {
            "code": "observed_case_missing",
            "reason": "observed_case_missing",
        }
    return ledger, observed_delta, observed_delta_rejection


def build_phase_payload(
    verdict: model.UnflattenAuthorityVerdict,
    views: ViewMetrics | None = None,
    timings: PhaseTimings | None = None,
    projected_case: model.SemanticSafetyCase | None = None,
    codec_receipt: LegacyShadowCodecReceipt | None = None,
    parity_payload: ShadowParityPayload | None = None,
    codec_error: str | None = None,
    parity_error: str | None = None,
    correlation: TransactionAttemptId | None = None,
    _view_projection: tuple[object, object, dict[str, str] | None] | None = None,
) -> dict[str, object]:
    """Build one complete, typed payload from a canonical verdict."""

    if type(verdict) is not model.UnflattenAuthorityVerdict:
        raise TypeError("verdict must be UnflattenAuthorityVerdict")
    case = verdict.safety_case
    if projected_case is not None and type(projected_case) is not model.SemanticSafetyCase:
        raise TypeError("projected_case must be SemanticSafetyCase or None")
    if projected_case is not None and verdict.phase is not model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY:
        raise ValueError("projected_case is only valid for observed diagnostics")
    if codec_receipt is not None and type(codec_receipt) is not LegacyShadowCodecReceipt:
        raise TypeError("codec_receipt must be LegacyShadowCodecReceipt or None")
    if codec_error is not None and (type(codec_error) is not str or not codec_error):
        raise TypeError("codec_error must be a non-empty string or None")
    if parity_error is not None and (type(parity_error) is not str or not parity_error):
        raise TypeError("parity_error must be a non-empty string or None")
    if parity_payload is not None and type(parity_payload) is not ShadowParityPayload:
        raise TypeError("parity_payload must be ShadowParityPayload or None")
    if correlation is not None and type(correlation) is not TransactionAttemptId:
        raise TypeError("correlation must be TransactionAttemptId or None")
    if parity_payload is not None and verdict.phase is not model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY:
        raise ValueError("final parity is only valid for observed diagnostics")
    if _view_projection is None:
        _view_projection = _phase_view_projection(verdict, projected_case)
    ledger, observed_delta, observed_delta_rejection = _view_projection
    states = () if case is None else tuple(
        {"subject": _subject_label(cell.key.subject), "dimension": cell.key.dimension.value, "state": cell.state.value}
        for cell in case.obligation_index.cells
    )
    bindings = () if case is None else tuple(
        {"subject": binding.subject.subject_id, "phase": binding.phase.value, "fingerprint": binding.graph_fingerprint, "generation": binding.generation, "status": binding.status.value, "serial": binding.serial, "anchor_ea": binding.anchor_ea}
        for binding in case.bindings
    )
    prep = None if case is None else case.phase_metrics.preparation_metrics
    cumulative_counters = None if case is None else ShadowParityCounters.from_case(case)
    loss_ledger = () if ledger is None else tuple(_loss_row_payload(row) for row in ledger.rows)
    payload: dict[str, object] = {
        "schema": "unflatten_authority_phase.v1",
        "phase": verdict.phase.value, "reason": verdict.reason.value, "accepted": verdict.accepted,
        "authority_id": verdict.authority_id, "binding_id": verdict.binding_id,
        "case_id": verdict.case_id, "candidate_fingerprint": verdict.candidate_fingerprint,
        # The closed verdict intentionally carries only the candidate
        # fingerprint; no diagnostic projection may mislabel the authority ID
        # as a source graph fingerprint.
        "source_fingerprint": (
            case.source_fingerprint if case is not None
            else None if projected_case is None
            else projected_case.source_fingerprint
        ),
        "generation": None if case is None else case.candidate_generation,
        "obligation_states": states,
        "failed_obligations": tuple({"subject": _subject_label(failed.key.subject), "dimension": failed.key.dimension.value, "state": failed.state.value} for failed in verdict.failed_obligations),
        "loss_ledger": loss_ledger,
        "observed_only_loss": () if observed_delta is None else tuple(_loss_row_payload(row) for row in observed_delta.rows),
        "observed_only_loss_rejection": observed_delta_rejection,
        "bindings": bindings,
        "handlers": () if case is None else tuple(subject.subject_id for subject in case.subjects if subject.role is model.SemanticSubjectRole.AUTHORITATIVE_HANDLER),
        "terminals": () if case is None else tuple(subject.subject_id for subject in case.subjects if subject.role is model.SemanticSubjectRole.TERMINAL_SITE),
        "coverage": () if case is None else tuple({"subject": item.key.subject.subject_id, "dimension": item.key.dimension.value, "state": item.state.value} for item in case.obligation_index.cells if item.key.dimension is model.SafetyDimension.CORRIDOR_COVERAGE),
        "evidence_ids": () if case is None else tuple(item.evidence_id for item in case.evidence),
        "justification_ids": () if case is None else tuple(item.justification_id for item in case.justifications),
        "metrics": None if prep is None else {
            "source_inventory_builds": cumulative_counters.source_inventory_builds,
            "candidate_inventory_builds": cumulative_counters.candidate_inventory_builds,
            "inventory_ms": case.phase_metrics.phase_build_metrics.inventory_ms,
            "index_folds": cumulative_counters.index_folds,
            "view_graph_traversals": cumulative_counters.view_graph_traversals,
            "local_phase_build": {
                "source_inventory_builds": case.phase_metrics.phase_build_metrics.source_inventory_builds,
                "candidate_inventory_builds": case.phase_metrics.phase_build_metrics.candidate_inventory_builds,
            },
        },
    }
    if views is not None:
        if type(views) is not ViewMetrics:
            raise TypeError("views must be ViewMetrics")
        payload["views"] = {
            "index_folds": views.index_folds,
            "view_graph_traversals": views.view_graph_traversals,
            "inventory_ms": None if views.phase_build_metrics is None else views.phase_build_metrics.inventory_ms,
        }
    if timings is not None:
        if type(timings) is not PhaseTimings:
            raise TypeError("timings must be PhaseTimings")
        payload["timings"] = {
            "inventory_ms": timings.inventory_ms,
            "binding_ms": timings.binding_ms,
            "evaluation_ms": timings.evaluation_ms,
            "views_ms": timings.views_ms,
            "total_authority_ms": timings.total_authority_ms,
            "observation_ms": timings.observation_ms,
        }
    if codec_receipt is not None:
        payload["codec"] = {
            "captured_keys": codec_receipt.consumed_keys,
            "adaptations": tuple({
                "key": item.key,
                "family": item.family,
                "result_ids": item.result_ids,
                "payload_sha256": item.payload_sha256,
            } for item in codec_receipt.adaptations),
            "all_adapted": len(codec_receipt.adaptations) == len(codec_receipt.shadow.entries),
        }
    elif codec_error is not None:
        payload["codec"] = {"all_adapted": False, "error": codec_error}
    if parity_error is not None:
        payload["parity_error"] = parity_error
    if correlation is not None:
        payload.update({
            "plan_id": correlation.plan_id,
            "attempt_id": correlation.attempt_id,
            "session_id": correlation.session_id,
            "generation": correlation.generation,
        })
    if parity_payload is not None:
        payload["parity"] = parity_payload.to_payload()
    return payload


def phase_observation(
    verdict: model.UnflattenAuthorityVerdict,
    *, maturity: str, source_ea: int,
    timings: PhaseTimings | None = None,
    views: ViewMetrics | None = None,
    projected_case: model.SemanticSafetyCase | None = None,
    codec_receipt: LegacyShadowCodecReceipt | None = None,
    parity_payload: ShadowParityPayload | None = None,
    codec_error: str | None = None,
    parity_error: str | None = None,
    correlation: TransactionAttemptId | None = None,
) -> FactObservation:
    """Build exactly one anchored observation for one authority phase."""

    if parity_payload is not None and timings is None:
        raise ValueError("final parity observation requires timings")
    view_started_ns = perf_counter_ns()
    view_projection = _phase_view_projection(verdict, projected_case)
    views_ms = (perf_counter_ns() - view_started_ns) / 1_000_000.0
    if timings is not None and timings.views_ms is None:
        components = tuple(
            value for value in (
                timings.inventory_ms, timings.binding_ms,
                timings.evaluation_ms, views_ms,
            ) if value is not None
        )
        timings = PhaseTimings(
            inventory_ms=timings.inventory_ms,
            binding_ms=timings.binding_ms,
            evaluation_ms=timings.evaluation_ms,
            views_ms=views_ms,
            total_authority_ms=sum(components),
            observation_ms=timings.observation_ms,
        )
    payload_started_ns = perf_counter_ns()
    payload = build_phase_payload(
        verdict, views, timings, projected_case,
        codec_receipt, parity_payload,
        codec_error,
        parity_error,
        correlation,
        _view_projection=view_projection,
    )
    if timings is not None and timings.observation_ms is None:
        payload_timings = payload.get("timings")
        if isinstance(payload_timings, dict):
            payload_timings["observation_ms"] = (
                perf_counter_ns() - payload_started_ns
            ) / 1_000_000.0
    fact_id = verdict.case_id or f"plan:{verdict.authority_id}:precase-rejection"
    evidence = tuple(payload["evidence_ids"]) + tuple(payload["justification_ids"])
    return FactObservation(
        fact_id=fact_id, kind="unflatten_authority_phase",
        semantic_key=verdict.authority_id or fact_id, maturity=str(maturity),
        phase=verdict.phase.value, confidence=1.0, source_block=None,
        source_ea=int(source_ea), block_fingerprint=verdict.candidate_fingerprint,
        mop_signature=None, payload=payload, evidence=evidence,
    )


def dispatcher_outcome_observations(
    *,
    projected_verdict: model.UnflattenAuthorityVerdict | None,
    observed_verdict: model.UnflattenAuthorityVerdict | None,
    function_ea: int,
    maturity: str,
    application_status: str,
    outcome_reason: str | None,
    plan_id: str,
    attempt_id: str | None,
) -> tuple[FactObservation, ...]:
    """Project canonical phase verdicts into legacy dispatcher fact rows.

    These rows keep existing observability subscribers live, but every field
    is derived from the canonical verdict and pure compatibility view.  No
    plan metadata or CFG is parsed on this path.
    """

    for name, verdict in (
        ("projected_verdict", projected_verdict),
        ("observed_verdict", observed_verdict),
    ):
        if verdict is not None and type(verdict) is not model.UnflattenAuthorityVerdict:
            raise TypeError(f"{name} must be an UnflattenAuthorityVerdict or None")
    primary = observed_verdict or projected_verdict
    if primary is None:
        return ()
    projected_views = {
        kind: None if projected_verdict is None else compatibility_projection(projected_verdict, kind).to_payload()
        for kind in ("coverage", "removal")
    }
    observed_views = {
        kind: None if observed_verdict is None else compatibility_projection(observed_verdict, kind).to_payload()
        for kind in ("coverage", "removal")
    }
    rows: list[FactObservation] = []
    for kind, fact_kind, label in (
        ("coverage", "UnflattenDispatcherCorridorCoverageSummary", "coverage"),
        ("removal", "UnflattenDispatcherRemovalPreflightProof", "removal"),
    ):
        view = compatibility_projection(primary, kind)
        payload = view.to_payload()
        payload.update({
            "function_ea": int(function_ea),
            "application_status": application_status,
            "outcome_reason": outcome_reason,
            "plan_id": plan_id,
            "attempt_id": attempt_id,
            "canonical": True,
        })
        if kind == "coverage":
            payload.update({
                "projected_coverage_validation": projected_views[kind],
                "observed_coverage_validation": observed_views[kind],
            })
        else:
            payload.update({
                "projected_validation": projected_views[kind],
                "observed_validation": observed_views[kind],
            })
        authority = primary.authority_id or f"plan:{plan_id}"
        fact_id = (
            f"unflatten-dispatcher-{label}:{application_status}:"
            f"func=0x{int(function_ea):x}:{authority}"
        )
        evidence = tuple(
            item for item in (
                view.authority_id,
                view.binding_id,
                view.case_id,
                *view.subject_ids,
            ) if item is not None
        )
        rows.append(FactObservation(
            fact_id=fact_id,
            kind=fact_kind,
            semantic_key=f"unflatten_dispatcher_{label}:func=0x{int(function_ea):x}:{authority}",
            maturity=str(maturity),
            phase=primary.phase.value,
            confidence=1.0,
            source_block=None,
            source_ea=int(function_ea),
            block_fingerprint=primary.candidate_fingerprint,
            mop_signature=None,
            payload=payload,
            evidence=evidence,
        ))
    return tuple(rows)


__all__ = [
    "LegacyPhaseOutcome", "LegacyCanonicalParityRow", "PhaseTimings",
    "ShadowParityCounters", "ShadowParityPayload",
    "build_phase_payload", "compare_shadow_parity", "parity_projection",
    "project_shadow_parity", "require_shadow_parity", "phase_observation",
    "dispatcher_outcome_observations",
]
