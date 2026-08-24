"""Read-only projections from an evaluator-owned safety case.

This module intentionally accepts no graph, plan, projection, or callback.  A
view is a pure tuple projection over the immutable case and its index.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import model


VIEW_GRAPH_TRAVERSALS = 0


@dataclass(frozen=True, slots=True)
class ViewMetrics:
    index_folds: int
    view_graph_traversals: int
    preparation_metrics: model.PreparationBuildMetrics | None = None
    phase_build_metrics: model.PhaseBuildMetrics | None = None


@dataclass(frozen=True, slots=True)
class ObservedLossReclassification:
    """One anchored loss subject whose semantic kind changed after apply."""

    subject: model.SemanticSubjectRef
    anchored_location: str
    projected_kind: model.SemanticLossKind
    observed_kind: model.SemanticLossKind
    projected_evidence_ids: tuple[str, ...]
    observed_evidence_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.subject) is not model.SemanticSubjectRef:
            raise TypeError("reclassification subject must be SemanticSubjectRef")
        if type(self.anchored_location) is not str or not self.anchored_location:
            raise TypeError("reclassification location must be a non-empty string")
        for name in ("projected_kind", "observed_kind"):
            if type(getattr(self, name)) is not model.SemanticLossKind:
                raise TypeError(f"{name} must be SemanticLossKind")
        for name in ("projected_evidence_ids", "observed_evidence_ids"):
            values = getattr(self, name)
            if type(values) is not tuple or any(type(item) is not str or not item for item in values):
                raise TypeError(f"{name} must contain exact evidence IDs")
            if values != tuple(sorted(set(values))):
                raise ValueError(f"{name} must be canonical and unique")


@dataclass(frozen=True, slots=True)
class ObservedLossDeltaProjection:
    """Observed-only rows plus separate post-apply kind reclassifications."""

    observed_only: model.ObservedSemanticLossDelta
    reclassifications: tuple[ObservedLossReclassification, ...] = ()

    def __post_init__(self) -> None:
        if type(self.observed_only) is not model.ObservedSemanticLossDelta:
            raise TypeError("observed_only must be ObservedSemanticLossDelta")
        if type(self.reclassifications) is not tuple:
            raise TypeError("reclassifications must be an exact tuple")
        if any(type(item) is not ObservedLossReclassification for item in self.reclassifications):
            raise TypeError("reclassifications must contain typed projections")
        subject_ids = tuple(item.subject.subject_id for item in self.reclassifications)
        if subject_ids != tuple(sorted(set(subject_ids))):
            raise ValueError("reclassifications must be canonical and unique")


@dataclass(frozen=True, slots=True)
class ExactEffectLossView:
    """Canonical evidence and sole exact classification for one effect loss."""

    evidence_ids: tuple[str, ...]
    justification_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RetiredInfrastructureView:
    """Exact structural rows supported by one retirement claim."""

    claim_id: str
    retired_member_subject_ids: tuple[str, ...]
    retained_member_subject_ids: tuple[str, ...]
    unaccounted_member_subject_ids: tuple[str, ...]
    drifted_member_subject_ids: tuple[str, ...]
    structural_cell_keys: tuple[model.ObligationKey, ...]
    justification_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CorridorCoverageView:
    """The case-owned aggregate corridor coverage projection."""

    corridor_subject_id: str
    forecast_id: str
    phase_result_id: str
    covered_path_ids: tuple[str, ...]
    residual_path_ids: tuple[str, ...]
    drifted_path_ids: tuple[str, ...]
    enumeration_complete: bool
    matched_semantic_exclusion_ids: tuple[str, ...]
    state: model.ObligationState
    evidence_ids: tuple[str, ...]
    justification_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class TerminalCycleView:
    """The narrow structural/terminal projection of one cycle-break claim."""

    claim_id: str
    cycle_subject_id: str
    cleanup_source_subject_id: str
    terminal_subject_id: str
    route_proof_ids: tuple[str, ...]
    structural_justification_ids: tuple[str, ...]
    terminal_justification_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DetachedComponentView:
    """Exact dead-handler loss rows, classified only by the canonical ledger."""

    claim_id: str
    dead_handler_subject_ids: tuple[str, ...]
    ledger_rows: tuple[model.SemanticLossRow, ...]


@dataclass(frozen=True, slots=True)
class CompatibilityValidationView:
    """One-release immutable projection for legacy diagnostic consumers."""

    kind: str
    passed: bool
    reason: str
    phase: str
    authority_id: str | None
    binding_id: str | None
    case_id: str | None
    candidate_fingerprint: str
    failed_obligation_states: tuple[str, ...] = ()
    retirement_subject_ids: tuple[str, ...] = ()
    corridor_subject_ids: tuple[str, ...] = ()
    subject_ids: tuple[str, ...] = ()

    def to_payload(self) -> dict[str, object]:
        return {
            "validation_status": "accepted" if self.passed else "rejected",
            "reason": self.reason,
            "phase": self.phase,
            "authority_id": self.authority_id,
            "binding_id": self.binding_id,
            "case_id": self.case_id,
            "candidate_fingerprint": self.candidate_fingerprint,
            "failed_obligation_states": self.failed_obligation_states,
            "retirement_subject_ids": self.retirement_subject_ids,
            "corridor_subject_ids": self.corridor_subject_ids,
            "subject_ids": self.subject_ids,
        }


def compatibility_projection(
    verdict: model.UnflattenAuthorityVerdict | None,
    kind: str,
) -> CompatibilityValidationView | None:
    """Project a verdict without parsing metadata or traversing a graph."""

    if verdict is None:
        return None
    if type(verdict) is not model.UnflattenAuthorityVerdict:
        raise TypeError("compatibility projection requires an authority verdict")
    if kind not in ("removal", "coverage"):
        raise ValueError("unknown compatibility projection")
    case = verdict.safety_case
    if case is None:
        return CompatibilityValidationView(
            kind, verdict.accepted, verdict.reason.value, verdict.phase.value,
            verdict.authority_id, verdict.binding_id, verdict.case_id,
            verdict.candidate_fingerprint,
            tuple(sorted({item.state.value for item in verdict.failed_obligations})),
        )
    subject_ids: tuple[str, ...] = ()
    retirement_subject_ids: tuple[str, ...] = ()
    corridor_subject_ids: tuple[str, ...] = ()
    if kind == "removal":
        claims = tuple(
            claim for claim in case.claims
            if type(claim) is model.RetiredDispatcherInfrastructureClaim
        )
        subject_ids = tuple(sorted(
            subject.subject_id
            for claim in claims
            for subject in claim.member_subjects
        ))
        retirement_subject_ids = subject_ids
    else:
        evidence = tuple(
            item for item in case.evidence
            if item.kind is model.AuthorityEvidenceKind.CORRIDOR_COVERAGE
        )
        if evidence:
            payload = evidence[0].payload
            subject_ids = (payload.corridor_subject_id,)
        corridor_subject_ids = subject_ids
    failed_states = tuple(sorted({item.state.value for item in verdict.failed_obligations}))
    return CompatibilityValidationView(
        kind,
        verdict.accepted,
        verdict.reason.value,
        verdict.phase.value,
        verdict.authority_id,
        verdict.binding_id,
        verdict.case_id,
        verdict.candidate_fingerprint,
        failed_states,
        retirement_subject_ids,
        corridor_subject_ids,
        subject_ids,
    )


def corridor_coverage_rows(case: model.SemanticSafetyCase) -> CorridorCoverageView:
    """Project the sole aggregate corridor result without recomputation."""

    _check_case(case)
    evidence = tuple(
        item for item in case.evidence
        if item.kind is model.AuthorityEvidenceKind.CORRIDOR_COVERAGE
    )
    if len(evidence) != 1 or type(evidence[0].payload) is not model.CorridorCoverageEvidencePayload:
        raise ValueError("corridor coverage requires one canonical evidence row")
    payload = evidence[0].payload
    result = case.corridor_coverage_phase_result
    if result is None or payload.phase_result_id != result.result_id:
        raise ValueError("corridor coverage lacks its case-owned phase result")
    key = next(
        (
            cell.key for cell in case.obligation_index.cells
            if cell.key.subject.subject_id == payload.corridor_subject_id
            and cell.key.dimension is model.SafetyDimension.CORRIDOR_COVERAGE
        ),
        None,
    )
    if key is None:
        raise ValueError("corridor coverage evidence lacks its aggregate obligation")
    cell = next(cell for cell in case.obligation_index.cells if cell.key == key)
    return CorridorCoverageView(
        payload.corridor_subject_id,
        payload.forecast_id,
        payload.phase_result_id,
        payload.covered_path_ids,
        payload.residual_path_ids,
        payload.drifted_path_ids,
        payload.enumeration_complete,
        payload.matched_semantic_exclusion_ids,
        cell.state,
        (evidence[0].evidence_id,),
        tuple(sorted(
            (*cell.supporting_justification_ids, *cell.refuting_justification_ids)
        )),
    )


def retired_infrastructure_view(
    case: model.SemanticSafetyCase, claim_id: str,
) -> RetiredInfrastructureView:
    """Project a retirement claim without widening it to corridor authority."""

    _check_case(case)
    if type(claim_id) is not str:
        raise TypeError("claim ID must be an exact string")
    claim = next(
        (
            item for item in case.claims
            if type(item) is model.RetiredDispatcherInfrastructureClaim
            and item.claim_id == claim_id
        ),
        None,
    )
    if claim is None:
        raise ValueError("retirement claim is missing or ambiguous")
    catalog = case.retirement_candidate_catalog
    result = case.retirement_phase_result
    if catalog is None or result is None:
        raise ValueError("case has no sealed retirement candidate/result pair")
    plan_refs = set(catalog.member_refs)
    phase_by_ref = {item.block_ref: item for item in result.members}
    if set(phase_by_ref) != plan_refs or result.claim_id != claim_id:
        raise ValueError("retirement phase result does not cover the exact claim plan")
    member_ids = {
        subject.subject_id: subject
        for subject in case.subjects
        if subject.role is model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE
        and subject.block_ref in plan_refs
    }
    if set(subject.block_ref for subject in member_ids.values()) != plan_refs:
        raise ValueError("retirement view is missing an exact dispatcher member")
    retired = tuple(sorted(
        subject_id for subject_id, subject in member_ids.items()
        if phase_by_ref[subject.block_ref].classification
        is model.RetirementPhaseClassification.RETIRED
    ))
    retained = tuple(sorted(
        subject_id for subject_id, subject in member_ids.items()
        if phase_by_ref[subject.block_ref].classification
        is model.RetirementPhaseClassification.RETAINED
    ))
    unaccounted = tuple(sorted(
        subject_id for subject_id, subject in member_ids.items()
        if phase_by_ref[subject.block_ref].classification
        is model.RetirementPhaseClassification.UNACCOUNTED
    ))
    drifted = tuple(sorted(
        subject_id for subject_id, subject in member_ids.items()
        if phase_by_ref[subject.block_ref].classification
        is model.RetirementPhaseClassification.DRIFTED
    ))
    structural = tuple(sorted(
        (
            cell.key for cell in case.obligation_index.cells
            if cell.key.dimension is model.SafetyDimension.STRUCTURAL_ACCOUNTING
            and cell.key.subject.subject_id in set(retired)
        ),
        key=lambda key: key.subject.subject_id,
    ))
    justifications = tuple(sorted(
        item.justification_id for item in case.justifications
        if item.claim_id == claim_id
        and item.conclusion.dimension is model.SafetyDimension.STRUCTURAL_ACCOUNTING
    ))
    return RetiredInfrastructureView(
        claim_id, retired, retained, unaccounted, drifted, structural,
        justifications,
    )


def terminal_cycle_rows(
    case: model.SemanticSafetyCase, claim_id: str | None = None,
) -> TerminalCycleView:
    """Project exact cycle/terminal claim conclusions without widening scope."""

    _check_case(case)
    claims = tuple(
        item for item in case.claims
        if type(item) is model.TerminalCycleBreakClaim
        and (claim_id is None or item.claim_id == claim_id)
    )
    if len(claims) != 1:
        raise ValueError("terminal-cycle rows require one unambiguous claim")
    claim = claims[0]
    keys = {
        "cycle": model.ObligationKey(
            claim.cycle_subject, model.SafetyDimension.STRUCTURAL_ACCOUNTING,
        ),
        "terminal": model.ObligationKey(
            claim.terminal_subject, model.SafetyDimension.TERMINAL_REACHABILITY,
        ),
    }
    if any(key not in {cell.key for cell in case.obligation_index.cells} for key in keys.values()):
        raise ValueError("terminal-cycle claim lacks exact obligation cells")
    structural = tuple(
        item.justification_id for item in case.justifications
        if item.claim_id == claim.claim_id and item.conclusion == keys["cycle"]
    )
    terminal = tuple(
        item.justification_id for item in case.justifications
        if item.claim_id == claim.claim_id
        and item.rule is model.UnflattenJustificationRule.TERMINAL_CYCLE_BREAK_PROVEN
        and item.conclusion == keys["terminal"]
    )
    foreign_scope = tuple(
        item for item in case.justifications
        if item.claim_id == claim.claim_id
        and item.conclusion not in {keys["cycle"], keys["terminal"]}
    )
    if foreign_scope:
        raise ValueError("terminal-cycle claim widened beyond cycle and terminal conclusions")
    return TerminalCycleView(
        claim.claim_id,
        claim.cycle_subject.subject_id,
        claim.cleanup_source_subject.subject_id,
        claim.terminal_subject.subject_id,
        claim.terminal_route_proof_ids,
        tuple(sorted(structural)),
        tuple(sorted(terminal)),
    )


def retirement_rows(
    case: model.SemanticSafetyCase, claim_id: str | None = None,
) -> RetiredInfrastructureView:
    """Project only exact case-owned retirement rows and satisfied cells."""

    if claim_id is None:
        retirement_ids = tuple(
            item.claim_id for item in case.claims
            if type(item) is model.RetiredDispatcherInfrastructureClaim
        )
        if len(retirement_ids) != 1:
            raise ValueError("retirement rows require one unambiguous retirement claim")
        claim_id = retirement_ids[0]
    view = retired_infrastructure_view(case, claim_id)
    if view.unaccounted_member_subject_ids or view.drifted_member_subject_ids:
        raise ValueError("retirement rows require a satisfied structural cell")
    ledger = semantic_loss_ledger(case)
    cells = {
        cell.key: cell for cell in case.obligation_index.cells
    }
    for subject_id in (*view.retired_member_subject_ids, *view.retained_member_subject_ids):
        subject = next((item for item in case.subjects if item.subject_id == subject_id), None)
        if subject is None:
            raise ValueError("retirement row subject is absent from case")
        cell = cells.get(model.ObligationKey(subject, model.SafetyDimension.STRUCTURAL_ACCOUNTING))
        if cell is None or cell.state is not model.ObligationState.SATISFIED:
            raise ValueError("retirement row lacks a satisfied structural cell")
        if subject_id in view.retired_member_subject_ids:
            rows = tuple(row for row in ledger.rows if row.source_subject.subject_id == subject_id)
            if len(rows) != 1 or rows[0].kind is not model.SemanticLossKind.RETIRED_DISPATCHER_INFRASTRUCTURE:
                raise ValueError("retired row lacks exact retirement ledger authority")
            if {justification.claim_id for justification in rows[0].justifications
                if justification.claim_id is not None} != {claim_id}:
                raise ValueError("retired row lacks exact retirement claim justification")
            if not any(
                justification.rule is model.UnflattenJustificationRule.RETIRED_INFRASTRUCTURE_PROVEN
                and justification.conclusion == model.ObligationKey(subject, model.SafetyDimension.STRUCTURAL_ACCOUNTING)
                and justification.claim_id == claim_id
                for justification in rows[0].justifications
            ):
                raise ValueError("retired row lacks exact retirement proof rule")
    return view


def detached_component_rows(
    case: model.SemanticSafetyCase, claim_id: str,
) -> DetachedComponentView:
    """Project one detached claim from ledger classifications, never raw membership."""

    _check_case(case)
    claim = next(
        (
            item for item in case.claims
            if type(item) is model.DetachedDeadHandlerComponentClaim
            and item.claim_id == claim_id
        ),
        None,
    )
    if claim is None:
        raise ValueError("detached component claim is missing or ambiguous")
    dead_ids = tuple(sorted(subject.subject_id for subject in claim.dead_handler_subjects))
    rows = tuple(
        row for row in semantic_loss_ledger(case).rows
        if row.source_subject.subject_id in set(dead_ids)
    )
    if tuple(row.source_subject.subject_id for row in rows) != dead_ids:
        raise ValueError("detached component lacks exact dead-handler ledger rows")
    if any(
        row.kind is not model.SemanticLossKind.DETACHED_DEAD_HANDLER_COMPONENT
        or tuple(row.claim_ids) != (claim_id,)
        for row in rows
    ):
        raise ValueError("detached component lacks exact ledger classification")
    return DetachedComponentView(claim_id, dead_ids, rows)


def semantic_loss_ledger(case: model.SemanticSafetyCase) -> model.SemanticLossLedger:
    """Project the evaluator-owned case into its one canonical loss ledger."""

    _check_case(case)
    subjects = {subject.subject_id: subject for subject in case.subjects}
    bindings = {binding.subject.subject_id: binding for binding in case.bindings}
    source_bindings = {binding.subject.subject_id: binding for binding in case.source_bindings}
    cells = {cell.key: cell for cell in case.obligation_index.cells}
    justifications = {item.justification_id: item for item in case.justifications}
    evidence = {item.evidence_id: item for item in case.evidence}
    claims = {item.claim_id: item for item in case.claims}
    retirement_result = case.retirement_phase_result
    retired_refs = set(retirement_result.retired_refs) if retirement_result is not None else set()
    rows: list[model.SemanticLossRow] = []
    for subject_id in case.source_subject_ids:
        subject = subjects.get(subject_id)
        binding = bindings.get(subject_id)
        if subject is None or binding is None:
            raise ValueError("source subject partition is not covered by the case")
        source_binding = source_bindings.get(subject_id)
        if source_binding is None:
            raise ValueError("source subject partition is not covered by source bindings")
        if binding.status is not model.SubjectBindingStatus.MISSING and subject.block_ref not in retired_refs:
            continue
        if case.phase is model.UnflattenAuthorityPhase.PRODUCER_FORECAST:
            continue
        structural_key = model.ObligationKey(subject, model.SafetyDimension.STRUCTURAL_ACCOUNTING)
        structural = cells.get(structural_key)
        if structural is None:
            # Aggregate source subjects such as NON_STATE_VALUE_FLOW have no
            # structural-accounting cell and therefore cannot be semantic-loss
            # ledger subjects.
            continue
        semantic = tuple(
            cell for cell in case.obligation_index.cells
            if cell.key.subject.subject_id == subject_id
            and cell.key.dimension is not model.SafetyDimension.STRUCTURAL_ACCOUNTING
        )
        relevant = (structural, *semantic)
        relevant_justifications = tuple(
            justifications[justification_id]
            for cell in relevant
            for justification_id in (
                *cell.supporting_justification_ids,
                *cell.refuting_justification_ids,
            )
        )
        relevant_evidence = tuple(
            evidence[premise]
            for item in relevant_justifications
            for premise in item.premise_ids
        )
        relevant_claims = tuple(
            claims[item.claim_id]
            for item in relevant_justifications
            if item.claim_id is not None
        )
        rows.append(model.SemanticLossRow(
            case=case,
            source_subject=subject,
            source_binding=source_binding,
            candidate_binding=binding,
            structural_obligation=structural,
            relevant_semantic_obligations=semantic,
            justifications=tuple(sorted(set(relevant_justifications), key=lambda item: item.justification_id)),
            evidence=tuple(sorted(set(relevant_evidence), key=lambda item: item.evidence_id)),
            claims=tuple(sorted(set(relevant_claims), key=lambda item: item.claim_id)),
        ))
    ledger = model.SemanticLossLedger(
        case=case,
        authority_id=case.authority_id,
        case_id=case.case_id,
        phase=case.phase,
        source_fingerprint=case.source_fingerprint,
        candidate_fingerprint=case.candidate_fingerprint,
        rows=tuple(sorted(rows, key=lambda row: row.source_subject.subject_id)),
    )
    return ledger


def observed_only_loss(
    projected_case: model.SemanticSafetyCase,
    observed_case: model.SemanticSafetyCase,
) -> model.ObservedSemanticLossDelta:
    """Project only genuinely new loss subjects relative to preflight."""

    projection = observed_loss_delta(projected_case, observed_case)
    if projection.reclassifications:
        raise ValueError("observed semantic loss classification drift")
    return projection.observed_only


def observed_loss_delta(
    projected_case: model.SemanticSafetyCase,
    observed_case: model.SemanticSafetyCase,
) -> ObservedLossDeltaProjection:
    """Project observed-only loss and kind reclassification separately."""

    _check_case(projected_case)
    _check_case(observed_case)
    if projected_case.phase is not model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT:
        raise ValueError("projected case must be PROJECTED_PREFLIGHT")
    if observed_case.phase is not model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY:
        raise ValueError("observed case must be OBSERVED_POST_APPLY")
    if projected_case.authority_id != observed_case.authority_id:
        raise ValueError("projected and observed cases have different authorities")
    if projected_case.source_fingerprint != observed_case.source_fingerprint:
        raise ValueError("projected and observed cases have different source fingerprints")
    if projected_case.source_subject_ids != observed_case.source_subject_ids:
        raise ValueError("projected and observed cases have different source partitions")
    projected_subjects = tuple(
        subject for subject in projected_case.subjects
        if subject.subject_id in set(projected_case.source_subject_ids)
    )
    observed_subjects = tuple(
        subject for subject in observed_case.subjects
        if subject.subject_id in set(observed_case.source_subject_ids)
    )
    if projected_subjects != observed_subjects:
        raise ValueError("projected and observed cases have different source subjects")
    if projected_case.source_bindings != observed_case.source_bindings:
        raise ValueError("projected and observed cases have different source bindings")
    if projected_case.source_inventory != observed_case.source_inventory:
        raise ValueError("projected and observed cases have different source inventories")
    projected = semantic_loss_ledger(projected_case)
    observed = semantic_loss_ledger(observed_case)
    projected_by_subject = {row.source_subject.subject_id: row for row in projected.rows}
    observed_by_subject = {row.source_subject.subject_id: row for row in observed.rows}
    common = set(projected_by_subject) & set(observed_by_subject)
    drift = {
        subject_id for subject_id in common
        if projected_by_subject[subject_id].kind is not observed_by_subject[subject_id].kind
    }
    reclassifications = tuple(
        ObservedLossReclassification(
            subject=observed_by_subject[subject_id].source_subject,
            anchored_location=observed_by_subject[subject_id].anchored_location,
            projected_kind=projected_by_subject[subject_id].kind,
            observed_kind=observed_by_subject[subject_id].kind,
            projected_evidence_ids=projected_by_subject[subject_id].evidence_ids,
            observed_evidence_ids=observed_by_subject[subject_id].evidence_ids,
        )
        for subject_id in sorted(drift)
    )
    rows = tuple(sorted(
        (row for subject_id, row in observed_by_subject.items() if subject_id not in projected_by_subject),
        key=lambda row: row.source_subject.subject_id,
    ))
    return ObservedLossDeltaProjection(
        observed_only=model.ObservedSemanticLossDelta(
            authority_id=observed.authority_id,
            source_fingerprint=observed.source_fingerprint,
            projected_case_id=projected.case_id,
            observed_case_id=observed.case_id,
            rows=rows,
        ),
        reclassifications=reclassifications,
    )


def obligation_states(case: model.SemanticSafetyCase) -> tuple[tuple[model.ObligationKey, model.ObligationState], ...]:
    _check_case(case)
    return tuple((cell.key, cell.state) for cell in case.obligation_index.cells)


def failed_obligations(case: model.SemanticSafetyCase) -> tuple[model.FailedObligation, ...]:
    _check_case(case)
    return tuple(
        model.FailedObligation(cell.key, cell.state)
        for cell in case.obligation_index.cells
        if cell.state is not model.ObligationState.SATISFIED
    )


def evidence_ids(case: model.SemanticSafetyCase) -> tuple[str, ...]:
    _check_case(case)
    return tuple(item.evidence_id for item in case.evidence)


def justification_ids(case: model.SemanticSafetyCase) -> tuple[str, ...]:
    _check_case(case)
    return tuple(item.justification_id for item in case.justifications)


def exact_effect_loss_view(
    case: model.SemanticSafetyCase, discarded_effect_subject_id: str,
) -> ExactEffectLossView:
    _check_case(case)
    if type(discarded_effect_subject_id) is not str:
        raise TypeError("discarded effect subject ID must be an exact string")
    claim_ids = {
        claim.claim_id
        for claim in case.claims
        if type(claim) is model.ExactInfeasibleEffectClaim
        and claim.discarded_effect_subject.subject_id == discarded_effect_subject_id
    }
    if len(claim_ids) != 1:
        raise ValueError("exact discarded effect claim is missing or ambiguous")
    evidence = tuple(
        item.evidence_id
        for item in case.evidence
        if item.subject.subject_id == discarded_effect_subject_id
        and item.kind is model.AuthorityEvidenceKind.EFFECT_SITE
    )
    justifications = tuple(
        item.justification_id
        for item in case.justifications
        if item.conclusion.subject.subject_id == discarded_effect_subject_id
        and item.rule is model.UnflattenJustificationRule.EXACT_INFEASIBLE_EFFECT_PROVEN
    )
    if not evidence or len(justifications) != 2:
        raise ValueError("exact discarded effect view is incomplete")
    return ExactEffectLossView(evidence, justifications)


def view_metrics(case: model.SemanticSafetyCase, preparation_metrics: model.PreparationBuildMetrics | None = None) -> ViewMetrics:
    _check_case(case)
    if preparation_metrics is not None:
        raise TypeError("views cannot accept unrelated preparation metrics")
    return ViewMetrics(
        index_folds=case.phase_metrics.index_folds,
        view_graph_traversals=case.phase_metrics.view_graph_traversals,
        preparation_metrics=case.phase_metrics.preparation_metrics,
        phase_build_metrics=case.phase_metrics.phase_build_metrics,
    )


def _check_case(case: model.SemanticSafetyCase) -> None:
    if type(case) is not model.SemanticSafetyCase:
        raise TypeError("view requires SemanticSafetyCase")


# Stable descriptive aliases used by compatibility consumers.
loss_view = failed_obligations
coverage_view = obligation_states
diagnostic_view = evidence_ids


__all__ = [
    "VIEW_GRAPH_TRAVERSALS", "ViewMetrics", "ExactEffectLossView", "RetiredInfrastructureView", "CorridorCoverageView", "TerminalCycleView", "DetachedComponentView", "corridor_coverage_rows", "terminal_cycle_rows", "detached_component_rows", "obligation_states",
    "failed_obligations", "evidence_ids", "justification_ids", "view_metrics",
    "exact_effect_loss_view", "retired_infrastructure_view", "retirement_rows", "semantic_loss_ledger", "observed_only_loss", "observed_loss_delta",
    "ObservedLossReclassification", "ObservedLossDeltaProjection",
    "loss_view", "coverage_view", "diagnostic_view", "CompatibilityValidationView", "compatibility_projection",
]
