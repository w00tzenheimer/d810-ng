"""Typed diagnostic projections for unflatten authority phases."""

from __future__ import annotations

from dataclasses import dataclass
import math
from time import perf_counter_ns
from d810.analyses.value_flow.observation import FactObservation
from d810.transforms.cfg_transaction import TransactionAttemptId

from . import model
from .ids import content_id
from .views import (
    ObservedLossReclassification,
    ViewMetrics,
    observed_loss_delta,
)


@dataclass(frozen=True, slots=True)
class CanonicalPhaseCounters:
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
    def from_case(cls, case: model.SemanticSafetyCase) -> "CanonicalPhaseCounters":
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
class PhaseTimings:
    """Closed timing values supplied by the transaction observer."""

    inventory_ms: float | None = None
    binding_ms: float | None = None
    evaluation_ms: float | None = None
    views_ms: float | None = None
    total_authority_ms: float | None = None

    def __post_init__(self) -> None:
        for name in (
            "inventory_ms", "binding_ms", "evaluation_ms", "views_ms",
            "total_authority_ms",
        ):
            value = getattr(self, name)
            if value is not None and (
                type(value) is not float or value < 0 or not math.isfinite(value)
            ):
                raise TypeError(f"{name} must be a non-negative float or None")
        components = (
            self.inventory_ms,
            self.binding_ms,
            self.evaluation_ms,
            self.views_ms,
        )
        if (self.views_ms is None) != (self.total_authority_ms is None):
            raise ValueError(
                "views_ms and total_authority_ms must be supplied together"
            )
        if self.total_authority_ms is not None:
            expected_total = sum(
                value for value in components if value is not None
            )
            if not math.isclose(
                self.total_authority_ms,
                expected_total,
                rel_tol=0.0,
                abs_tol=1e-9,
            ):
                raise ValueError(
                    "total_authority_ms must equal the four phase components"
                )


def _subject_label(subject: model.SemanticSubjectRef) -> str:
    if subject.anchor_ea is None:
        return f"subject:{subject.subject_id}"
    return f"subject:{subject.subject_id}@0x{subject.anchor_ea:x}"


def _binding_label(binding: model.PhaseSubjectBinding) -> str:
    """Render one stable location label without exposing a naked serial."""
    if (
        binding.status is model.SubjectBindingStatus.UNIQUE
        and binding.serial is not None
        and binding.anchor_ea is not None
    ):
        return f"blk{binding.serial}@0x{binding.anchor_ea:x}"
    anchor = (
        binding.anchor_ea
        if binding.anchor_ea is not None
        else binding.subject.anchor_ea
    )
    return (
        f"subject:{binding.subject.subject_id}@0x{anchor:x}"
        if anchor is not None
        else f"subject:{binding.subject.subject_id}"
    )


def _case_subject_label(
    case: model.SemanticSafetyCase, subject: model.SemanticSubjectRef,
) -> str:
    binding = next(
        (item for item in case.bindings if item.subject.subject_id == subject.subject_id),
        None,
    )
    return _binding_label(binding) if binding is not None else _subject_label(subject)


def _obligation_payload(
    case: model.SemanticSafetyCase,
    cell: model.ObligationEvidenceCell,
    bindings_by_subject: dict[str, model.PhaseSubjectBinding],
) -> dict[str, object]:
    subject = cell.key.subject
    binding = bindings_by_subject.get(subject.subject_id)
    return {
        "subject": (
            _binding_label(binding)
            if binding is not None
            else _subject_label(subject)
        ),
        "dimension": cell.key.dimension.value,
        "state": cell.state.value,
        "supports": cell.supporting_justification_ids,
        "refutes": cell.refuting_justification_ids,
    }


def _justification_payload(
    case: model.SemanticSafetyCase,
    item: model.AuthorityJustification,
) -> dict[str, object]:
    return {
        "justification_id": item.justification_id,
        "rule": item.rule.value,
        "premise_ids": item.premise_ids,
        "conclusion": {
            "subject": _case_subject_label(case, item.conclusion.subject),
            "dimension": item.conclusion.dimension.value,
        },
        "polarity": item.polarity.value,
        "claim_id": item.claim_id,
    }


def _loss_row_payload(
    row: model.SemanticLossRow | "SemanticLossProjectionRow",
) -> dict[str, object]:
    return {
        "subject": _binding_label(row.candidate_binding),
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


def _loss_reclassification_payload(
    row: ObservedLossReclassification,
) -> dict[str, object]:
    return {
        "subject": row.subject.subject_id,
        "anchor": row.anchored_location,
        "projected_kind": row.projected_kind.value,
        "observed_kind": row.observed_kind.value,
        "projected_evidence_ids": row.projected_evidence_ids,
        "observed_evidence_ids": row.observed_evidence_ids,
    }


def _phase_view_projection(
    verdict: model.UnflattenAuthorityVerdict,
    projected_case: model.SemanticSafetyCase | None,
    prepared_authority: model.PreparedUnflattenAuthority | None,
) -> tuple[
    object,
    model.ObservedSemanticLossDelta | tuple["SemanticLossProjectionRow", ...] | None,
    dict[str, str] | None,
    tuple[ObservedLossReclassification, ...],
]:
    case = verdict.safety_case
    acceptance = verdict.observed_acceptance
    if prepared_authority is not None:
        if type(prepared_authority) is not model.PreparedUnflattenAuthority:
            raise TypeError("prepared_authority must be PreparedUnflattenAuthority or None")
        prepared_authority.__post_init__()
    ledger = verdict.loss_ledger
    if acceptance is not None:
        if ledger is not acceptance.observed_ledger:
            raise ValueError("observed diagnostics lost the canonical ledger occurrence")
    elif verdict.accepted:
        if verdict.phase is not model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT:
            raise ValueError("accepted observed diagnostics require a closed observed acceptance")
        if prepared_authority is None:
            raise ValueError("accepted projected diagnostics require the prepared authority occurrence")
        if (
            prepared_authority.projected_case is not case
            or prepared_authority.authority_id != verdict.authority_id
        ):
            raise ValueError("prepared authority is foreign to projected diagnostic verdict")
        if ledger is not prepared_authority.projected_loss_ledger:
            raise ValueError("projected diagnostics lost the canonical ledger occurrence")
    observed_delta = None
    observed_delta_rejection = None
    observed_reclassifications: tuple[ObservedLossReclassification, ...] = ()
    if acceptance is not None:
        if projected_case is not None and projected_case is not acceptance.bound_authority.prepared.projected_case:
            raise ValueError("diagnostic projected case is foreign to accepted observed authority")
        observed_delta = acceptance.delta
    elif (
        projected_case is not None
        and case is not None
        and ledger is not None
        and prepared_authority is not None
    ):
        if projected_case is not prepared_authority.projected_case:
            raise ValueError("diagnostic projected case is foreign to prepared authority")
        projection = observed_loss_delta(
            prepared_authority.projected_loss_ledger, ledger,
        )
        observed_delta = projection.rows
        observed_reclassifications = projection.reclassifications
    elif projected_case is not None:
        observed_delta_rejection = {
            "code": "canonical_observed_ledger_missing",
            "reason": "canonical_observed_ledger_missing",
        }
    return ledger, observed_delta, observed_delta_rejection, observed_reclassifications


def build_phase_payload(
    verdict: model.UnflattenAuthorityVerdict,
    views: ViewMetrics | None = None,
    timings: PhaseTimings | None = None,
    projected_case: model.SemanticSafetyCase | None = None,
    prepared_authority: model.PreparedUnflattenAuthority | None = None,
    correlation: TransactionAttemptId | None = None,
    _view_projection: tuple[
        object,
        model.ObservedSemanticLossDelta | tuple["SemanticLossProjectionRow", ...] | None,
        dict[str, str] | None,
        tuple[ObservedLossReclassification, ...],
    ] | None = None,
) -> dict[str, object]:
    """Build one complete, typed payload from a canonical verdict."""

    if type(verdict) is not model.UnflattenAuthorityVerdict:
        raise TypeError("verdict must be UnflattenAuthorityVerdict")
    case = verdict.safety_case
    if projected_case is not None and type(projected_case) is not model.SemanticSafetyCase:
        raise TypeError("projected_case must be SemanticSafetyCase or None")
    if projected_case is not None and verdict.phase is not model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY:
        raise ValueError("projected_case is only valid for observed diagnostics")
    if correlation is not None and type(correlation) is not TransactionAttemptId:
        raise TypeError("correlation must be TransactionAttemptId or None")
    if _view_projection is None:
        _view_projection = _phase_view_projection(
            verdict, projected_case, prepared_authority,
        )
    ledger, observed_delta, observed_delta_rejection, observed_reclassifications = _view_projection
    bindings_by_subject = {} if case is None else {
        binding.subject.subject_id: binding for binding in case.bindings
    }
    cells_by_key = {} if case is None else {
        cell.key: cell for cell in case.obligation_index.cells
    }
    states = () if case is None else tuple(
        _obligation_payload(case, cell, bindings_by_subject)
        for cell in case.obligation_index.cells
    )
    bindings = () if case is None else tuple(
        {"subject": _binding_label(binding), "phase": binding.phase.value, "fingerprint": binding.graph_fingerprint, "generation": binding.generation, "status": binding.status.value}
        for binding in case.bindings
    )
    prep = None if case is None else case.phase_metrics.preparation_metrics
    cumulative_counters = None if case is None else CanonicalPhaseCounters.from_case(case)
    loss_ledger = () if ledger is None else tuple(_loss_row_payload(row) for row in ledger.rows)
    anchored_loss_labels = tuple(
        row["anchor"] for row in loss_ledger if row["anchor"] is not None
    )
    explanations = () if case is None else tuple(
        _justification_payload(case, item) for item in case.justifications
    )
    state_counts = {
        state.value: sum(row["state"] == state.value for row in states)
        for state in model.ObligationState
    }
    plan_id = None if correlation is None else correlation.plan_id
    attempt_id = None if correlation is None else correlation.attempt_id
    log_lines = (
        "UNFLAT_AUTH "
        f"phase={verdict.phase.value} "
        f"verdict={'accepted' if verdict.accepted else 'rejected'} "
        f"reason={verdict.reason.value} "
        f"authority={verdict.authority_id or 'precase'} "
        f"binding={verdict.binding_id or 'none'} "
        f"case={verdict.case_id or 'precase'} "
        f"plan={plan_id or 'unknown'} attempt={attempt_id or 'unknown'} "
        f"sat={state_counts['satisfied']} "
        f"unproven={state_counts['unproven']} "
        f"violated={state_counts['violated']} "
        f"inconsistent={state_counts['inconsistent']}",
        *(
            "UNFLAT_OBLIGATION "
            f"subject={row['subject']} dimension={row['dimension']} "
            f"state={row['state']} "
            f"support={','.join(row['supports']) or 'none'} "
            f"refute={','.join(row['refutes']) or 'none'}"
            for row in states
            if row["state"] != model.ObligationState.SATISFIED.value
        ),
    )
    observed_loss_rows = (
        ()
        if observed_delta is None
        else tuple(
            _loss_row_payload(row)
            for row in (
                observed_delta
                if type(observed_delta) is tuple
                else observed_delta.rows
            )
        )
    )
    loss_summary = {
        "structurally_lost": tuple(row.anchored_location for row in (() if ledger is None else ledger.rows)),
        "allowed": tuple(row.anchored_location for row in (() if ledger is None else ledger.allowed)),
        "forbidden": tuple(row.anchored_location for row in (() if ledger is None else ledger.unclassified)),
        "conflicting": tuple(row.anchored_location for row in (() if ledger is None else ledger.conflicting)),
        "observed_only": tuple(row["anchor"] for row in observed_loss_rows),
    }
    payload: dict[str, object] = {
        "schema": "unflatten_authority_phase.v1",
        "schema_version": 1,
        "rule_set_version": 1,
        "phase": verdict.phase.value, "reason": verdict.reason.value, "accepted": verdict.accepted,
        "verdict": "accepted" if verdict.accepted else "rejected",
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
        "source_graph_fingerprint": (
            case.source_fingerprint if case is not None
            else None if projected_case is None
            else projected_case.source_fingerprint
        ),
        "candidate_graph_fingerprint": verdict.candidate_fingerprint,
        "generation": None if case is None else case.candidate_generation,
        "obligation_states": states,
        "failed_obligations": (
            ()
            if case is None
            else tuple(
                _obligation_payload(
                    case,
                    cells_by_key[failed.key],
                    bindings_by_subject,
                )
                for failed in verdict.failed_obligations
            )
        ),
        "loss_ledger": loss_ledger,
        "loss_summary": loss_summary,
        "anchored_loss_labels": anchored_loss_labels,
        "observed_only_loss": observed_loss_rows,
        "observed_only_loss_rejection": observed_delta_rejection,
        "observed_loss_reclassification": tuple(
            _loss_reclassification_payload(row)
            for row in observed_reclassifications
        ),
        "bindings": bindings,
        "handlers": () if case is None else tuple(_case_subject_label(case, subject) for subject in case.subjects if subject.role is model.SemanticSubjectRole.AUTHORITATIVE_HANDLER),
        "terminals": () if case is None else tuple(_case_subject_label(case, subject) for subject in case.subjects if subject.role is model.SemanticSubjectRole.TERMINAL_SITE),
        "coverage": () if case is None else tuple({"subject": _case_subject_label(case, item.key.subject), "dimension": item.key.dimension.value, "state": item.state.value} for item in case.obligation_index.cells if item.key.dimension is model.SafetyDimension.CORRIDOR_COVERAGE),
        "evidence_ids": () if case is None else tuple(item.evidence_id for item in case.evidence),
        "justification_ids": () if case is None else tuple(item.justification_id for item in case.justifications),
        "explanations": explanations,
        "log_lines": log_lines,
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
        }
    if correlation is not None:
        payload.update({
            "plan_id": correlation.plan_id,
            "attempt_id": correlation.attempt_id,
            "session_id": correlation.session_id,
            "generation": correlation.generation,
        })
    return payload


def phase_observation(
    verdict: model.UnflattenAuthorityVerdict,
    *, maturity: str, source_ea: int,
    timings: PhaseTimings | None = None,
    views: ViewMetrics | None = None,
    projected_case: model.SemanticSafetyCase | None = None,
    prepared_authority: model.PreparedUnflattenAuthority | None = None,
    correlation: TransactionAttemptId | None = None,
) -> FactObservation:
    """Build exactly one anchored observation for one authority phase."""

    view_started_ns = perf_counter_ns()
    view_projection = _phase_view_projection(
        verdict, projected_case, prepared_authority,
    )
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
        )
    payload = build_phase_payload(
        verdict, views, timings, projected_case, prepared_authority,
        correlation,
        _view_projection=view_projection,
    )
    precase_id = content_id(
        "d810.unflatten.precase-rejection.v1",
        (
            verdict.phase,
            verdict.reason,
            verdict.authority_id,
            verdict.candidate_fingerprint,
        ),
    )
    semantic_precase_key = (
        f"plan:{correlation.plan_id}:precase-rejection"
        if correlation is not None
        else precase_id
    )
    fact_id = verdict.case_id or precase_id
    evidence = tuple(sorted(
        (*payload["evidence_ids"], *payload["justification_ids"])
    ))
    return FactObservation(
        fact_id=fact_id, kind="unflatten_authority_phase",
        semantic_key=verdict.authority_id or semantic_precase_key, maturity=str(maturity),
        phase=verdict.phase.value, confidence=1.0, source_block=None,
        source_ea=int(source_ea), block_fingerprint=verdict.candidate_fingerprint,
        mop_signature=None, payload=payload, evidence=evidence,
    )


__all__ = [
    "CanonicalPhaseCounters", "PhaseTimings", "build_phase_payload",
    "phase_observation",
]
