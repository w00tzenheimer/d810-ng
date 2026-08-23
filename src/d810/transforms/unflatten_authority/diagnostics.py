"""Typed diagnostic projections for unflatten authority phases."""

from __future__ import annotations

from dataclasses import dataclass

from d810.analyses.value_flow.observation import FactObservation

from . import model
from .views import ViewMetrics, observed_only_loss, semantic_loss_ledger


@dataclass(frozen=True, slots=True)
class PhaseTimings:
    """Closed timing values supplied by the transaction observer."""

    inventory_ms: float | None = None
    observation_ms: float | None = None

    def __post_init__(self) -> None:
        for name in ("inventory_ms", "observation_ms"):
            value = getattr(self, name)
            if value is not None and (type(value) is not float or value < 0):
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


def build_phase_payload(
    verdict: model.UnflattenAuthorityVerdict,
    views: ViewMetrics | None = None,
    timings: PhaseTimings | None = None,
    projected_case: model.SemanticSafetyCase | None = None,
) -> dict[str, object]:
    """Build one complete, typed payload from a canonical verdict."""

    if type(verdict) is not model.UnflattenAuthorityVerdict:
        raise TypeError("verdict must be UnflattenAuthorityVerdict")
    case = verdict.safety_case
    if projected_case is not None and type(projected_case) is not model.SemanticSafetyCase:
        raise TypeError("projected_case must be SemanticSafetyCase or None")
    if projected_case is not None and verdict.phase is not model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY:
        raise ValueError("projected_case is only valid for observed diagnostics")
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
    states = () if case is None else tuple(
        {"subject": _subject_label(cell.key.subject), "dimension": cell.key.dimension.value, "state": cell.state.value}
        for cell in case.obligation_index.cells
    )
    bindings = () if case is None else tuple(
        {"subject": binding.subject.subject_id, "phase": binding.phase.value, "fingerprint": binding.graph_fingerprint, "generation": binding.generation, "status": binding.status.value, "serial": binding.serial, "anchor_ea": binding.anchor_ea}
        for binding in case.bindings
    )
    prep = None if case is None else case.phase_metrics.preparation_metrics
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
        "metrics": None if prep is None else {"source_inventory_builds": case.phase_metrics.phase_build_metrics.source_inventory_builds, "candidate_inventory_builds": case.phase_metrics.phase_build_metrics.candidate_inventory_builds, "inventory_ms": case.phase_metrics.phase_build_metrics.inventory_ms, "index_folds": case.phase_metrics.index_folds, "view_graph_traversals": case.phase_metrics.view_graph_traversals},
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
            "observation_ms": timings.observation_ms,
        }
    return payload


def phase_observation(
    verdict: model.UnflattenAuthorityVerdict,
    *, maturity: str, source_ea: int,
    timings: PhaseTimings | None = None,
    views: ViewMetrics | None = None,
    projected_case: model.SemanticSafetyCase | None = None,
) -> FactObservation:
    """Build exactly one anchored observation for one authority phase."""

    payload = build_phase_payload(verdict, views, timings, projected_case)
    fact_id = verdict.case_id or f"plan:{verdict.authority_id}:precase-rejection"
    evidence = tuple(payload["evidence_ids"]) + tuple(payload["justification_ids"])
    return FactObservation(
        fact_id=fact_id, kind="unflatten_authority_phase",
        semantic_key=verdict.authority_id or fact_id, maturity=str(maturity),
        phase=verdict.phase.value, confidence=1.0, source_block=None,
        source_ea=int(source_ea), block_fingerprint=verdict.candidate_fingerprint,
        mop_signature=None, payload=payload, evidence=evidence,
    )


__all__ = ["PhaseTimings", "build_phase_payload", "phase_observation"]
