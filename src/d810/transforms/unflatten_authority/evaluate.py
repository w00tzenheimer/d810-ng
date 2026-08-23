"""Pure total evaluator for already-derived unflatten authority inputs."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
import re

from d810.analyses.control_flow import semantic_route_evidence as route_model
from d810.transforms.cfg_transaction import PlanBlockRef

from . import model
from . import gates
from . import producer_api
from .ids import _case_factory, _evidence_factory, _justification_factory, authority_id as _authority_id_digest


@dataclass(frozen=True, slots=True)
class _EffectClassification:
    """Single classification of one source effect site for this phase."""

    preserved: bool
    authorized_loss: bool
    refuted: bool
    claim: model.ExactInfeasibleEffectClaim | model.LocalAliasEffectScalarizationClaim | None
    authorized_transition: bool = False
    structural_preserved: bool = False


# Inventory observations use the compact canonical opcode assigned by the
# backend adapter.  A local-alias scalarization is specifically STORE -> MOV;
# accepting an arbitrary opcode would make the display text the only semantic
# proof of the transition.
LOCAL_ALIAS_MOV_OPCODE = 4

_SUPPORTED_PATCH_STEP_TYPES = frozenset({
    "PatchScalarizeLocalAliasAccess",
    "PatchLowerConditionalStateTransition",
    "PatchRedirectBranch",
    "PatchEdgeSplitTrampoline",
    "PatchEdgeSplitCorridor",
    "PatchConditionalRedirect",
    "PatchInsertBlock",
    "PatchDuplicateBlock",
    "PatchDuplicateReplayAndRedirect",
    "PatchCloneConditionalAsGoto",
    "PatchCloneConditionalAsGotoFromBranchArm",
})


def _patch_owner_subjects(
    payload: model.PatchStepEvidencePayload,
    subjects: tuple[model.SemanticSubjectRef, ...],
) -> tuple[model.SemanticSubjectRef, ...]:
    """Return the exact candidate-role witnesses for one closed patch fact."""

    planned = tuple(
        subject for subject in subjects
        if subject.role is model.SemanticSubjectRole.PLANNED_HELPER
        and subject.block_ref == payload.owner_ref
    )
    if payload.step_type == "PatchScalarizeLocalAliasAccess":
        return planned or tuple(
            subject for subject in subjects
            if subject.role is model.SemanticSubjectRole.EFFECT_SITE
            and subject.kind is model.SemanticSubjectKind.BLOCK
            and subject.block_ref == payload.owner_ref
        )
    if payload.step_type in {
        "PatchLowerConditionalStateTransition",
        "PatchRedirectBranch",
    }:
        return planned or tuple(
            subject for subject in subjects
            if subject.block_ref == payload.owner_ref
            and (
                subject.kind is model.SemanticSubjectKind.BLOCK
                or (
                    payload.step_type == "PatchRedirectBranch"
                    and subject.role is model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE
                )
            )
        )
    if payload.step_type in _SUPPORTED_PATCH_STEP_TYPES - {
        "PatchScalarizeLocalAliasAccess",
    }:
        return planned
    return tuple(
        subject for subject in subjects
        if subject.role is model.SemanticSubjectRole.EFFECT_SITE
        and subject.block_ref == payload.owner_ref
    )


def _has_exact_scalar_base_access(
    display_text: str, base_token: str, expected_width: int,
) -> bool:
    """Match the complete destination/base operand and optional width."""

    match = re.fullmatch(
        rf"\s*mov\s+[^,]+,\s*{re.escape(base_token)}(?:\.(?P<width>\d+))?\s*",
        display_text,
    )
    return match is not None and (
        match.group("width") is None
        or match.group("width") == str(expected_width)
    )


def _classify_effect_site(
    effect: model.InventoryEffectSite,
    subject: model.SemanticSubjectRef,
    source_binding: model.PhaseSubjectBinding,
    candidate_binding: model.PhaseSubjectBinding | None,
    candidate_effect: model.InventoryEffectSite | tuple[model.InventoryEffectSite, ...] | None,
    claim: model.ExactInfeasibleEffectClaim | None,
    route_assessment: route_model.CanonicalRouteAssessment | None,
    generic_gate_facts: gates.GenericCfgGateFacts | None,
    *,
    phase: model.UnflattenAuthorityPhase | None = None,
    local_alias_claim: model.LocalAliasEffectScalarizationClaim | None = None,
    local_alias_owner_binding: model.PhaseSubjectBinding | None = None,
    local_alias_owner_observation: model.InventoryInstructionObservation | None = None,
    local_alias_owner_reachable: bool = False,
) -> _EffectClassification:
    """Classify one effect from closed phase facts exactly once."""

    candidate_rows = (
        () if candidate_effect is None
        else candidate_effect if type(candidate_effect) is tuple
        else (candidate_effect,)
    )
    candidate_row = candidate_rows[0] if len(candidate_rows) == 1 else None
    candidate_site_matches = bool(
        candidate_row is not None
        and candidate_binding is not None
        and candidate_binding.status is model.SubjectBindingStatus.UNIQUE
        and candidate_row.owner_serial == candidate_binding.serial
        and candidate_row.owner_ref == effect.owner_ref
        and candidate_row.owner_anchor_ea == effect.owner_anchor_ea
        and candidate_row.instruction_ea == effect.instruction_ea
        and candidate_row.effect_kind is effect.effect_kind
        and candidate_row.opcode == effect.opcode
        and candidate_row.width == effect.width
    )
    preserved = (
        source_binding.status is model.SubjectBindingStatus.UNIQUE
        and candidate_binding is not None
        and candidate_binding.status is model.SubjectBindingStatus.UNIQUE
        and candidate_site_matches
    )
    if preserved and not (
        local_alias_claim is not None
        and phase is model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY
    ):
        # A present site is preserved; a claim cannot annotate a preserved
        # effect or authorize any loss metadata.
        return _EffectClassification(True, False, False, None)
    preserved_alias_transition_missing = preserved and (
        local_alias_claim is not None
        and phase is model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY
    )
    # A candidate row that exists but mismatches the source is drift, not an
    # authorized absence.  Only the closed MISSING site binding qualifies for
    # an exact-loss claim.
    candidate_site_absent = (
        not candidate_rows
        and candidate_binding is not None
        and candidate_binding.status is model.SubjectBindingStatus.MISSING
    )
    exact = (
        candidate_site_absent
        and
        claim is not None
        and claim.discarded_effect_subject.subject_id == subject.subject_id
        and claim.discarded_effect_ea == effect.instruction_ea
        and claim.width == effect.width
        and claim.discarded_effect_subject.locator.owner_ref == effect.owner_ref
        and claim.discarded_effect_subject.locator.owner_anchor_ea == effect.owner_anchor_ea
        and claim.discarded_effect_subject.locator.effect_kind is effect.effect_kind
    )
    route_ok = bool(
        claim is not None
        and route_assessment is not None
        and route_assessment.accepted
        and tuple(claim.route_proof_ids) == tuple(route_assessment.proof_ids)
    )
    raw_facts = None if generic_gate_facts is None else generic_gate_facts.effectful_raw
    effective_facts = None if generic_gate_facts is None else generic_gate_facts.effectful_effective
    owner = effect.owner_serial
    raw_lost = raw_facts is not None and owner in raw_facts.lost_block_serials
    raw_retained = raw_facts is not None and owner in raw_facts.pre_effectful_block_serials and not raw_lost
    effective_retained = effective_facts is not None and owner in effective_facts.pre_effectful_block_serials and owner not in effective_facts.lost_block_serials
    gate_ok = bool(
        generic_gate_facts is not None
        and effective_retained
        and (raw_lost or raw_retained)
    )
    authorized = bool(exact and route_ok and gate_ok)
    alias_exact = bool(
        not candidate_rows
        and local_alias_claim is not None
        and local_alias_claim.owner_subject.block_ref == effect.owner_ref
        and local_alias_claim.owner_subject.anchor_ea == effect.owner_anchor_ea
        and local_alias_claim.host_ea == effect.instruction_ea
        and local_alias_claim.host_opcode == effect.opcode
        and (
            local_alias_claim.value_size is None
            or local_alias_claim.value_size == effect.width
        )
        and candidate_binding is not None
        and candidate_binding.status is model.SubjectBindingStatus.MISSING
        and local_alias_owner_binding is not None
        and local_alias_owner_binding.status is model.SubjectBindingStatus.UNIQUE
        and local_alias_owner_reachable
        and local_alias_owner_observation is not None
        and local_alias_owner_observation.instruction_ea == effect.instruction_ea
        and local_alias_owner_observation.instruction_kind is model.InsnKind.MOV
        and local_alias_owner_observation.opcode == LOCAL_ALIAS_MOV_OPCODE
        and local_alias_owner_observation.display_text is not None
        and local_alias_owner_observation.width == effect.width
        and _has_exact_scalar_base_access(
            local_alias_owner_observation.display_text,
            local_alias_claim.base_token,
            effect.width,
        )
        and not local_alias_owner_observation.is_call
        and local_alias_owner_observation.call_kind is None
        and local_alias_owner_observation.control_transfer_kind is None
    )
    if alias_exact:
        return _EffectClassification(False, True, False, local_alias_claim, True)
    if preserved_alias_transition_missing:
        return _EffectClassification(
            False, False, True, None, False, True,
        )
    return _EffectClassification(False, authorized, not authorized, claim if authorized else None)


REQUIRED_DIMENSIONS: dict[model.SemanticSubjectRole, tuple[model.SafetyDimension, ...]] = {
    model.SemanticSubjectRole.SOURCE_ENTRY: (
        model.SafetyDimension.IDENTITY_BINDING, model.SafetyDimension.TOPOLOGY_INTEGRITY,
        model.SafetyDimension.STRUCTURAL_ACCOUNTING, model.SafetyDimension.ENTRY_REACHABILITY,
    ),
    model.SemanticSubjectRole.DISPATCHER_ENTRY: (
        model.SafetyDimension.IDENTITY_BINDING, model.SafetyDimension.TOPOLOGY_INTEGRITY,
        model.SafetyDimension.STRUCTURAL_ACCOUNTING, model.SafetyDimension.ENTRY_REACHABILITY,
        model.SafetyDimension.CORRIDOR_COVERAGE,
    ),
    model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE: (
        model.SafetyDimension.IDENTITY_BINDING, model.SafetyDimension.TOPOLOGY_INTEGRITY,
        model.SafetyDimension.STRUCTURAL_ACCOUNTING, model.SafetyDimension.CORRIDOR_COVERAGE,
    ),
    model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE: (
        model.SafetyDimension.IDENTITY_BINDING, model.SafetyDimension.TOPOLOGY_INTEGRITY,
        model.SafetyDimension.STRUCTURAL_ACCOUNTING, model.SafetyDimension.ROUTE_EQUIVALENCE,
    ),
    model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION: (
        model.SafetyDimension.IDENTITY_BINDING, model.SafetyDimension.TOPOLOGY_INTEGRITY,
        model.SafetyDimension.STRUCTURAL_ACCOUNTING, model.SafetyDimension.ROUTE_EQUIVALENCE,
    ),
    model.SemanticSubjectRole.EFFECT_SITE: (
        model.SafetyDimension.IDENTITY_BINDING, model.SafetyDimension.STRUCTURAL_ACCOUNTING,
        model.SafetyDimension.EFFECT_PRESERVATION,
    ),
    model.SemanticSubjectRole.AUTHORITATIVE_HANDLER: (
        model.SafetyDimension.IDENTITY_BINDING, model.SafetyDimension.TOPOLOGY_INTEGRITY,
        model.SafetyDimension.STRUCTURAL_ACCOUNTING, model.SafetyDimension.HANDLER_REACHABILITY,
    ),
    model.SemanticSubjectRole.TERMINAL_SITE: (
        model.SafetyDimension.IDENTITY_BINDING, model.SafetyDimension.STRUCTURAL_ACCOUNTING,
        model.SafetyDimension.TERMINAL_REACHABILITY,
    ),
    model.SemanticSubjectRole.NON_STATE_VALUE_FLOW: (
        model.SafetyDimension.IDENTITY_BINDING, model.SafetyDimension.USE_DEF_INTEGRITY,
    ),
    model.SemanticSubjectRole.DISPATCHER_CORRIDOR: (
        model.SafetyDimension.IDENTITY_BINDING, model.SafetyDimension.STRUCTURAL_ACCOUNTING,
        model.SafetyDimension.CORRIDOR_COVERAGE,
    ),
    model.SemanticSubjectRole.PLANNED_HELPER: (
        model.SafetyDimension.IDENTITY_BINDING, model.SafetyDimension.TOPOLOGY_INTEGRITY,
        model.SafetyDimension.STRUCTURAL_ACCOUNTING,
    ),
}


@dataclass(frozen=True, slots=True)
class _JustificationRuleSpec:
    dimensions: frozenset[model.SafetyDimension]
    polarity: model.EvidencePolarity
    evidence_kinds: frozenset[model.AuthorityEvidenceKind]
    min_premises: int = 1
    max_premises: int | None = 1


def _rule(
    *dimensions: model.SafetyDimension,
    polarity: model.EvidencePolarity,
    evidence: tuple[model.AuthorityEvidenceKind, ...],
    min_premises: int = 1,
    max_premises: int | None = 1,
) -> _JustificationRuleSpec:
    return _JustificationRuleSpec(frozenset(dimensions), polarity, frozenset(evidence), min_premises, max_premises)


_JUSTIFICATION_RULE_SPECS: dict[model.UnflattenJustificationRule, _JustificationRuleSpec] = {
    # A value-flow subject is an aggregate over every redirect owner.  Its
    # identity proof therefore carries one exact phase-binding premise per
    # owner, while ordinary subjects remain single-binding proofs.
    model.UnflattenJustificationRule.UNIQUE_PHASE_BINDING: _rule(model.SafetyDimension.IDENTITY_BINDING, polarity=model.EvidencePolarity.SUPPORTS, evidence=(model.AuthorityEvidenceKind.PHASE_BINDING,), max_premises=None),
    model.UnflattenJustificationRule.NONUNIQUE_PHASE_BINDING: _rule(model.SafetyDimension.IDENTITY_BINDING, polarity=model.EvidencePolarity.REFUTES, evidence=(model.AuthorityEvidenceKind.PHASE_BINDING,), max_premises=None),
    model.UnflattenJustificationRule.TOPOLOGY_PRESERVED: _rule(model.SafetyDimension.TOPOLOGY_INTEGRITY, polarity=model.EvidencePolarity.SUPPORTS, evidence=(model.AuthorityEvidenceKind.TOPOLOGY,)),
    model.UnflattenJustificationRule.TOPOLOGY_DRIFTED: _rule(model.SafetyDimension.TOPOLOGY_INTEGRITY, polarity=model.EvidencePolarity.REFUTES, evidence=(model.AuthorityEvidenceKind.TOPOLOGY,)),
    model.UnflattenJustificationRule.SOURCE_PRESERVED: _rule(model.SafetyDimension.STRUCTURAL_ACCOUNTING, polarity=model.EvidencePolarity.SUPPORTS, evidence=(model.AuthorityEvidenceKind.STRUCTURAL_LINEAGE,)),
    model.UnflattenJustificationRule.SOURCE_SPLIT_WITH_RECIPROCAL_ORIGINS: _rule(model.SafetyDimension.STRUCTURAL_ACCOUNTING, polarity=model.EvidencePolarity.SUPPORTS, evidence=(model.AuthorityEvidenceKind.STRUCTURAL_LINEAGE,)),
    model.UnflattenJustificationRule.SOURCE_FOLDED_WITH_RECIPROCAL_ORIGINS: _rule(model.SafetyDimension.STRUCTURAL_ACCOUNTING, polarity=model.EvidencePolarity.SUPPORTS, evidence=(model.AuthorityEvidenceKind.STRUCTURAL_LINEAGE,)),
    model.UnflattenJustificationRule.SOURCE_LOSS_UNACCOUNTED: _rule(model.SafetyDimension.STRUCTURAL_ACCOUNTING, polarity=model.EvidencePolarity.REFUTES, evidence=(model.AuthorityEvidenceKind.STRUCTURAL_LINEAGE,)),
    model.UnflattenJustificationRule.RETIRED_INFRASTRUCTURE_PROVEN: _rule(model.SafetyDimension.STRUCTURAL_ACCOUNTING, model.SafetyDimension.CORRIDOR_COVERAGE, polarity=model.EvidencePolarity.SUPPORTS, evidence=(model.AuthorityEvidenceKind.STRUCTURAL_LINEAGE, model.AuthorityEvidenceKind.CORRIDOR_COVERAGE), max_premises=None),
    model.UnflattenJustificationRule.EQUIVALENT_ROUTE_PROVEN: _rule(model.SafetyDimension.STRUCTURAL_ACCOUNTING, model.SafetyDimension.ROUTE_EQUIVALENCE, polarity=model.EvidencePolarity.SUPPORTS, evidence=(model.AuthorityEvidenceKind.SEMANTIC_ROUTE,)),
    model.UnflattenJustificationRule.EXACT_INFEASIBLE_EFFECT_PROVEN: _rule(model.SafetyDimension.EFFECT_PRESERVATION, model.SafetyDimension.STRUCTURAL_ACCOUNTING, polarity=model.EvidencePolarity.SUPPORTS, evidence=(model.AuthorityEvidenceKind.EFFECT_SITE, model.AuthorityEvidenceKind.SEMANTIC_ROUTE), min_premises=2, max_premises=2),
    model.UnflattenJustificationRule.LOCAL_ALIAS_SCALARIZATION_PROVEN: _rule(model.SafetyDimension.EFFECT_PRESERVATION, polarity=model.EvidencePolarity.SUPPORTS, evidence=(model.AuthorityEvidenceKind.EFFECT_SITE, model.AuthorityEvidenceKind.PATCH_STEP, model.AuthorityEvidenceKind.PHASE_BINDING, model.AuthorityEvidenceKind.REACHABILITY), min_premises=4, max_premises=4),
    model.UnflattenJustificationRule.TERMINAL_CYCLE_BREAK_PROVEN: _rule(model.SafetyDimension.STRUCTURAL_ACCOUNTING, model.SafetyDimension.TERMINAL_REACHABILITY, polarity=model.EvidencePolarity.SUPPORTS, evidence=(model.AuthorityEvidenceKind.STRUCTURAL_LINEAGE, model.AuthorityEvidenceKind.REACHABILITY), min_premises=2, max_premises=2),
    model.UnflattenJustificationRule.ROUTE_MISSING_OR_DRIFTED: _rule(model.SafetyDimension.ROUTE_EQUIVALENCE, polarity=model.EvidencePolarity.REFUTES, evidence=(model.AuthorityEvidenceKind.SEMANTIC_ROUTE,)),
    model.UnflattenJustificationRule.EFFECT_PRESERVED: _rule(model.SafetyDimension.EFFECT_PRESERVATION, polarity=model.EvidencePolarity.SUPPORTS, evidence=(model.AuthorityEvidenceKind.EFFECT_SITE,)),
    model.UnflattenJustificationRule.EFFECT_LOST_UNACCOUNTED: _rule(model.SafetyDimension.EFFECT_PRESERVATION, polarity=model.EvidencePolarity.REFUTES, evidence=(model.AuthorityEvidenceKind.EFFECT_SITE,)),
    model.UnflattenJustificationRule.SUBJECT_REACHABLE: _rule(model.SafetyDimension.ENTRY_REACHABILITY, model.SafetyDimension.HANDLER_REACHABILITY, model.SafetyDimension.TERMINAL_REACHABILITY, polarity=model.EvidencePolarity.SUPPORTS, evidence=(model.AuthorityEvidenceKind.REACHABILITY,)),
    model.UnflattenJustificationRule.SUBJECT_UNREACHABLE: _rule(model.SafetyDimension.ENTRY_REACHABILITY, model.SafetyDimension.HANDLER_REACHABILITY, model.SafetyDimension.TERMINAL_REACHABILITY, polarity=model.EvidencePolarity.REFUTES, evidence=(model.AuthorityEvidenceKind.REACHABILITY,)),
    model.UnflattenJustificationRule.USE_DEF_AUDIT_CLEAN: _rule(model.SafetyDimension.USE_DEF_INTEGRITY, polarity=model.EvidencePolarity.SUPPORTS, evidence=(model.AuthorityEvidenceKind.USE_DEF_AUDIT,)),
    model.UnflattenJustificationRule.USE_DEF_AUDIT_UNAVAILABLE: _rule(model.SafetyDimension.USE_DEF_INTEGRITY, polarity=model.EvidencePolarity.REFUTES, evidence=(model.AuthorityEvidenceKind.USE_DEF_AUDIT,)),
    model.UnflattenJustificationRule.NON_STATE_USE_DEF_SEVERED: _rule(model.SafetyDimension.USE_DEF_INTEGRITY, polarity=model.EvidencePolarity.REFUTES, evidence=(model.AuthorityEvidenceKind.USE_DEF_AUDIT,)),
    model.UnflattenJustificationRule.CORRIDOR_FULLY_COVERED: _rule(model.SafetyDimension.CORRIDOR_COVERAGE, polarity=model.EvidencePolarity.SUPPORTS, evidence=(model.AuthorityEvidenceKind.CORRIDOR_COVERAGE,)),
    model.UnflattenJustificationRule.CORRIDOR_RESIDUAL_UNACCOUNTED: _rule(model.SafetyDimension.CORRIDOR_COVERAGE, polarity=model.EvidencePolarity.REFUTES, evidence=(model.AuthorityEvidenceKind.CORRIDOR_COVERAGE,)),
    model.UnflattenJustificationRule.HELPER_OWNER_LINEAGE_PROVEN: _rule(model.SafetyDimension.STRUCTURAL_ACCOUNTING, polarity=model.EvidencePolarity.SUPPORTS, evidence=(model.AuthorityEvidenceKind.PATCH_STEP,)),
    model.UnflattenJustificationRule.RESEGMENTATION_LINEAGE_PROVEN: _rule(model.SafetyDimension.STRUCTURAL_ACCOUNTING, polarity=model.EvidencePolarity.SUPPORTS, evidence=(model.AuthorityEvidenceKind.PATCH_STEP,)),
    model.UnflattenJustificationRule.GENERIC_CFG_GATE_PASSED: _rule(model.SafetyDimension.ENTRY_REACHABILITY, model.SafetyDimension.EFFECT_PRESERVATION, model.SafetyDimension.TERMINAL_REACHABILITY, polarity=model.EvidencePolarity.SUPPORTS, evidence=(model.AuthorityEvidenceKind.GENERIC_CFG_GATE,)),
    model.UnflattenJustificationRule.GENERIC_CFG_GATE_FAILED: _rule(model.SafetyDimension.ENTRY_REACHABILITY, model.SafetyDimension.EFFECT_PRESERVATION, model.SafetyDimension.TERMINAL_REACHABILITY, polarity=model.EvidencePolarity.REFUTES, evidence=(model.AuthorityEvidenceKind.GENERIC_CFG_GATE,)),
}


def _subject_key(subject: model.SemanticSubjectRef) -> str:
    return subject.subject_id


def _route_destination_ids(
    route: model.SemanticSubjectRef,
    subjects: tuple[model.SemanticSubjectRef, ...],
) -> tuple[str, ...]:
    """Project destination IDs in the route locator's paired order."""

    if type(route.locator) is not model.RouteSubjectLocator:
        raise ValueError("route subject must carry a RouteSubjectLocator")
    return tuple(
        next(
            subject.subject_id
            for subject in subjects
            if subject.role is model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION
            and subject.block_ref == ref
            and subject.anchor_ea == anchor
        )
        for ref, anchor in zip(
            route.locator.destination_refs,
            route.locator.destination_anchor_eas,
        )
    )


def _claim_subjects(claim: model.UnflattenClaim) -> tuple[model.SemanticSubjectRef, ...]:
    """Return the closed subject inventory owned by one typed claim."""

    if type(claim) is model.RetiredDispatcherInfrastructureClaim:
        return (claim.infrastructure_subject, claim.corridor_subject, *claim.member_subjects)
    if type(claim) is model.EquivalentSemanticRouteClaim:
        return (
            claim.retired_route_subject, claim.replacement_route_subject,
            claim.source_subject, *claim.destination_subjects,
        )
    if type(claim) is model.ExactInfeasibleEffectClaim:
        return (
            claim.effect_subject, claim.source_subject, claim.predicate_subject,
            claim.selected_target_subject, claim.discarded_effect_subject,
        )
    if type(claim) is model.LocalAliasEffectScalarizationClaim:
        return (claim.owner_subject,)
    if type(claim) is model.TerminalCycleBreakClaim:
        return (claim.cycle_subject, claim.cleanup_source_subject, claim.terminal_subject)
    raise TypeError("claims must contain closed UnflattenClaim values")


def _make_justification(
    *, rule: model.UnflattenJustificationRule, key: model.ObligationKey,
    polarity: model.EvidencePolarity, phase: model.UnflattenAuthorityPhase,
    premise_ids: tuple[str, ...] = (),
    claim_id: str | None = None,
) -> model.AuthorityJustification:
    values = {
        "rule": rule, "premise_ids": tuple(sorted(premise_ids)), "conclusion": key,
        "polarity": polarity, "phase": phase,
        "claim_id": claim_id,
    }
    return _justification_factory(model.AuthorityJustification, **values)


def _new_index(cells: tuple[model.ObligationEvidenceCell, ...]) -> model.ObligationEvidenceIndex:
    index = object.__new__(model.ObligationEvidenceIndex)
    object.__setattr__(index, "cells", cells)
    object.__setattr__(index, "_token", model._OBLIGATION_INDEX_TOKEN)
    model.ObligationEvidenceIndex.__post_init__(index)
    return index


def _build_obligation_index(
    required: tuple[model.ObligationKey, ...],
    justifications: tuple[model.AuthorityJustification, ...],
    phase: model.UnflattenAuthorityPhase,
) -> model.ObligationEvidenceIndex:
    support: dict[model.ObligationKey, list[str]] = defaultdict(list)
    refute: dict[model.ObligationKey, list[str]] = defaultdict(list)
    required_set = set(required)
    for justification in justifications:
        if justification.conclusion not in required_set:
            raise ValueError("justification conclusion is outside obligation inventory")
        target = support if justification.polarity is model.EvidencePolarity.SUPPORTS else refute
        target[justification.conclusion].append(justification.justification_id)
    cells = tuple(
        model.ObligationEvidenceCell(
            key=key, phase=phase,
            supporting_justification_ids=tuple(sorted(support.get(key, ()))),
            refuting_justification_ids=tuple(sorted(refute.get(key, ()))),
        )
        for key in required
    )
    return _new_index(cells)


def _dimensions(
    subjects: tuple[model.SemanticSubjectRef, ...],
    claims: tuple[model.UnflattenClaim, ...],
    candidate_bindings: tuple[model.PhaseSubjectBinding, ...],
    *,
    candidate_fingerprint: str | None = None,
    candidate_generation: int | None = None,
    retired_topology_satisfied_ids: frozenset[str] = frozenset(),
    conditional_relations: tuple[model.ConditionalSubjectRelation, ...] = (),
) -> tuple[model.ObligationKey, ...]:
    result: set[model.ObligationKey] = set()
    relation_dimensions = {(item.target_subject_id, item.dimension) for item in conditional_relations}
    for subject in subjects:
        dimensions = list(REQUIRED_DIMENSIONS[subject.role])
        if (
            subject.role is model.SemanticSubjectRole.EFFECT_SITE
            and subject.kind is model.SemanticSubjectKind.BLOCK
        ):
            dimensions = [
                dimension for dimension in dimensions
                if dimension is not model.SafetyDimension.EFFECT_PRESERVATION
            ]
        if (
            subject.role is model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE
            and subject.subject_id in retired_topology_satisfied_ids
        ):
            dimensions = [
                dimension for dimension in dimensions
                if dimension is not model.SafetyDimension.TOPOLOGY_INTEGRITY
            ]
        dimensions.extend(
            dimension for target_id, dimension in relation_dimensions
            if target_id == subject.subject_id and dimension not in dimensions
        )
        result.update(model.ObligationKey(subject, dimension) for dimension in dimensions)
    return tuple(sorted(result, key=lambda key: (key.subject.subject_id, key.dimension.value)))


def _add_justification(
    out: list[model.AuthorityJustification], key: model.ObligationKey,
    rule: model.UnflattenJustificationRule, polarity: model.EvidencePolarity,
    phase: model.UnflattenAuthorityPhase, premises: tuple[str, ...] = (),
    claim_id: str | None = None,
) -> None:
    out.append(_make_justification(rule=rule, key=key, polarity=polarity, phase=phase, premise_ids=premises, claim_id=claim_id))


def _validate_justification_graph(
    justifications: tuple[model.AuthorityJustification, ...],
    required: tuple[model.ObligationKey, ...], evidence: tuple[model.AuthorityEvidence, ...],
    phase: model.UnflattenAuthorityPhase,
    claims: tuple[model.UnflattenClaim, ...] = (),
    conditional_relations: tuple[model.ConditionalSubjectRelation, ...] = (),
    *, candidate_fingerprint: str | None = None,
    candidate_generation: int | None = None,
    bindings: tuple[model.PhaseSubjectBinding, ...] = (),
    subjects: tuple[model.SemanticSubjectRef, ...] = (),
    source_subject_ids: tuple[str, ...] = (),
) -> None:
    required_set = set(required)
    ids = {item.justification_id for item in justifications}
    evidence_ids = {item.evidence_id for item in evidence}
    if len(ids) != len(justifications):
        raise ValueError("duplicate justification IDs")
    graph: dict[str, tuple[str, ...]] = {}
    claim_rules = {
        model.UnflattenJustificationRule.RETIRED_INFRASTRUCTURE_PROVEN,
        model.UnflattenJustificationRule.EQUIVALENT_ROUTE_PROVEN,
        model.UnflattenJustificationRule.EXACT_INFEASIBLE_EFFECT_PROVEN,
        model.UnflattenJustificationRule.LOCAL_ALIAS_SCALARIZATION_PROVEN,
        model.UnflattenJustificationRule.TERMINAL_CYCLE_BREAK_PROVEN,
    }
    claim_ids = {claim.claim_id for claim in claims}
    for item in justifications:
        if item.phase is not phase:
            raise ValueError("justification phase does not match case phase")
        if item.conclusion not in required_set:
            raise ValueError("justification conclusion is outside obligation inventory")
        spec = _JUSTIFICATION_RULE_SPECS.get(item.rule)
        if spec is None:
            raise ValueError("unknown justification rule")
        if item.conclusion.dimension not in spec.dimensions:
            raise ValueError("justification rule dimension mismatch")
        if item.polarity is not spec.polarity:
            raise ValueError("justification rule polarity mismatch")
        if item.rule in claim_rules and item.claim_id is None:
            raise ValueError("claim rule requires claim_id")
        if item.rule not in claim_rules and item.claim_id is not None:
            raise ValueError("non-claim rule cannot carry claim_id")
        if item.claim_id is not None and claims and item.claim_id not in claim_ids:
            raise ValueError("justification claim is outside claim inventory")
        if not spec.min_premises <= len(item.premise_ids) or (
            spec.max_premises is not None and len(item.premise_ids) > spec.max_premises
        ):
            raise ValueError("justification premise cardinality mismatch")
        if item.rule in {
            model.UnflattenJustificationRule.UNIQUE_PHASE_BINDING,
            model.UnflattenJustificationRule.NONUNIQUE_PHASE_BINDING,
        } and item.conclusion.subject.role is not model.SemanticSubjectRole.NON_STATE_VALUE_FLOW and len(item.premise_ids) != 1:
            raise ValueError("ordinary identity binding requires one premise")
        if item.conclusion.subject.role is model.SemanticSubjectRole.NON_STATE_VALUE_FLOW and item.rule in {
            model.UnflattenJustificationRule.UNIQUE_PHASE_BINDING,
            model.UnflattenJustificationRule.NONUNIQUE_PHASE_BINDING,
        } and len(set(item.premise_ids)) != len(item.premise_ids):
            raise ValueError("value-flow identity premises must be unique")
        if any(premise not in evidence_ids for premise in item.premise_ids):
            raise ValueError("foreign justification premise")
        by_evidence_id = {item.evidence_id: item for item in evidence}
        premise_kinds = tuple(by_evidence_id[premise].kind for premise in item.premise_ids)
        if any(kind not in spec.evidence_kinds for kind in premise_kinds):
            raise ValueError("justification evidence kind mismatch")
        if candidate_fingerprint is not None or candidate_generation is not None:
            if candidate_fingerprint is None or candidate_generation is None:
                raise ValueError("contextual binding validation requires fingerprint and generation")
            if item.rule in {
                model.UnflattenJustificationRule.UNIQUE_PHASE_BINDING,
                model.UnflattenJustificationRule.NONUNIQUE_PHASE_BINDING,
            }:
                binding_rows = tuple(
                    by_evidence_id[premise].payload.binding
                    for premise in item.premise_ids
                    if type(by_evidence_id[premise].payload) is model.PhaseBindingEvidencePayload
                )
                if len(binding_rows) != len(item.premise_ids):
                    raise ValueError("identity justification requires phase-binding payloads")
                target = item.conclusion.subject
                if target.role is model.SemanticSubjectRole.NON_STATE_VALUE_FLOW:
                    owner_refs = set(target.locator.redirect_owner_refs)
                    allowed = {
                        subject.subject_id for subject in subjects
                        if subject.role is model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE
                        and subject.block_ref in owner_refs
                    }
                else:
                    allowed = {target.subject_id}
                if any(binding.subject.subject_id not in allowed for binding in binding_rows):
                    raise ValueError("identity premise is outside exact subject owner scope")
                valid_rows = tuple(
                    binding for binding in binding_rows
                    if binding.phase is phase
                    and (
                        binding.status is model.SubjectBindingStatus.UNIQUE
                        or (
                            phase is not model.UnflattenAuthorityPhase.PRODUCER_FORECAST
                            and binding.status is model.SubjectBindingStatus.MISSING
                            and binding.subject.subject_id in set(source_subject_ids)
                        )
                    )
                    and binding.graph_fingerprint == candidate_fingerprint
                    and binding.generation == candidate_generation
                    and (
                        target.role is not model.SemanticSubjectRole.NON_STATE_VALUE_FLOW
                        or (
                            binding.block_ref == binding.subject.block_ref
                            and binding.anchor_ea == binding.subject.anchor_ea
                            and binding.subject.anchor_ea in binding.native_instruction_eas
                        )
                    )
                )
                if item.rule is model.UnflattenJustificationRule.UNIQUE_PHASE_BINDING:
                    if target.role is model.SemanticSubjectRole.NON_STATE_VALUE_FLOW:
                        required_owner_ids = {
                            subject.subject_id for subject in subjects
                            if subject.role is model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE
                            and subject.block_ref in target.locator.redirect_owner_refs
                        }
                        if (
                            len(required_owner_ids) != len(target.locator.redirect_owner_refs)
                            or
                            len(binding_rows) != len(required_owner_ids)
                            or {binding.subject.subject_id for binding in binding_rows}
                            != required_owner_ids
                        ):
                            raise ValueError("unique value-flow identity requires the exact owner premise set")
                    if len(valid_rows) != len(binding_rows):
                        raise ValueError("unique identity support has stale or non-unique binding")
                elif (
                    len(valid_rows) == len(binding_rows)
                    and len(binding_rows) == (
                        len(target.locator.redirect_owner_refs)
                        if target.role is model.SemanticSubjectRole.NON_STATE_VALUE_FLOW
                        else 1
                    )
                    ):
                        raise ValueError("nonunique identity refutation lacks a mismatch condition")
            if item.rule in {
                model.UnflattenJustificationRule.USE_DEF_AUDIT_CLEAN,
                model.UnflattenJustificationRule.USE_DEF_AUDIT_UNAVAILABLE,
                model.UnflattenJustificationRule.NON_STATE_USE_DEF_SEVERED,
            }:
                if len(item.premise_ids) != 1:
                    raise ValueError("use-def justification requires one audit premise")
                audit_item = by_evidence_id[item.premise_ids[0]]
                payload = audit_item.payload
                target = item.conclusion.subject
                if (
                    type(payload) is not model.UseDefAuditEvidencePayload
                    or target.role is not model.SemanticSubjectRole.NON_STATE_VALUE_FLOW
                    or payload.fragment_id != target.locator.fragment_id
                    or payload.state_identity != target.locator.state_identity
                ):
                    raise ValueError("use-def audit premise is outside exact value-flow scope")
                if item.rule is model.UnflattenJustificationRule.USE_DEF_AUDIT_CLEAN:
                    if not (
                        payload.executed
                        and payload.fragment_atomic
                        and payload.actionable_non_state_severance_count == 0
                        and not payload.violation_ids
                    ):
                        raise ValueError("clean use-def support has contradictory audit payload")
                elif item.rule is model.UnflattenJustificationRule.USE_DEF_AUDIT_UNAVAILABLE:
                    if payload.executed and payload.fragment_atomic:
                        raise ValueError("unavailable use-def refutation has an executed atomic audit")
                elif (
                    not payload.executed
                    or not payload.fragment_atomic
                    or payload.actionable_non_state_severance_count <= 0
                    or not payload.violation_ids
                    or len(set(payload.violation_ids)) != len(payload.violation_ids)
                    or payload.actionable_non_state_severance_count != len(payload.violation_ids)
                ):
                    raise ValueError("use-def severance refutation lacks complete actionable violations")
        if item.rule in {
            model.UnflattenJustificationRule.RETIRED_INFRASTRUCTURE_PROVEN,
        } and not {
            model.AuthorityEvidenceKind.STRUCTURAL_LINEAGE,
            model.AuthorityEvidenceKind.CORRIDOR_COVERAGE,
        } <= set(premise_kinds):
            raise ValueError("retirement justification requires lineage and coverage evidence")
        if item.rule is model.UnflattenJustificationRule.EXACT_INFEASIBLE_EFFECT_PROVEN and tuple(sorted(premise_kinds, key=lambda kind: kind.value)) != (
            model.AuthorityEvidenceKind.EFFECT_SITE,
            model.AuthorityEvidenceKind.SEMANTIC_ROUTE,
        ):
            raise ValueError("exact-effect justification requires one effect and one route premise")
        if item.rule is model.UnflattenJustificationRule.TERMINAL_CYCLE_BREAK_PROVEN and tuple(sorted(premise_kinds, key=lambda kind: kind.value)) != (
            model.AuthorityEvidenceKind.REACHABILITY,
            model.AuthorityEvidenceKind.STRUCTURAL_LINEAGE,
        ):
            raise ValueError("terminal claim requires lineage and reachability premises")
        if item.rule is model.UnflattenJustificationRule.LOCAL_ALIAS_SCALARIZATION_PROVEN and Counter(premise_kinds) != Counter({
            model.AuthorityEvidenceKind.EFFECT_SITE: 1,
            model.AuthorityEvidenceKind.PATCH_STEP: 1,
            model.AuthorityEvidenceKind.PHASE_BINDING: 1,
            model.AuthorityEvidenceKind.REACHABILITY: 1,
        }):
            raise ValueError("alias justification requires one exact effect, patch, binding, and reachability premise")
        if item.claim_id is None:
            for premise in item.premise_ids:
                payload = by_evidence_id[premise].payload
                target = item.conclusion.subject.subject_id
                correlated = (
                    type(payload) is model.PhaseBindingEvidencePayload
                    and (
                        payload.binding.subject.subject_id == target
                        or (
                            item.conclusion.subject.role is model.SemanticSubjectRole.NON_STATE_VALUE_FLOW
                            and payload.binding.subject.role is model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE
                            and payload.binding.subject.block_ref in item.conclusion.subject.locator.redirect_owner_refs
                        )
                    )
                ) or (
                    type(payload) is model.TopologyEvidencePayload
                    and payload.subject_id == target
                ) or (
                    type(payload) is model.StructuralLineageEvidencePayload
                    and target in payload.source_subject_ids
                ) or (
                    type(payload) is model.SemanticRouteEvidencePayload
                    and target in (payload.route_subject_id, payload.source_subject_id, *payload.destination_subject_ids)
                ) or (
                    type(payload) is model.EffectSiteEvidencePayload
                    and payload.effect_subject_id == target
                ) or (
                    type(payload) is model.ReachabilityEvidencePayload
                    and payload.target_subject_id == target
                ) or (
                    type(payload) is model.ReachabilityEvidencePayload
                    and any(
                        relation.source_subject_id == payload.target_subject_id
                        and relation.target_subject_id == target
                        and relation.dimension is item.conclusion.dimension
                        for relation in conditional_relations
                    )
                ) or (
                    type(payload) is model.UseDefAuditEvidencePayload
                    and by_evidence_id[premise].subject.subject_id == target
                ) or (
                    type(payload) is model.CorridorCoverageEvidencePayload
                    and (
                        payload.corridor_subject_id == target
                        or target in payload.member_subject_ids
                        or any(
                            subject.subject_id == target
                            and any(
                                member.subject_id in payload.member_subject_ids
                                and member.block_ref == subject.block_ref
                                for member in subjects
                            )
                            for subject in subjects
                        )
                    )
                ) or (
                    type(payload) is model.PatchStepEvidencePayload
                    and by_evidence_id[premise].subject.subject_id == target
                ) or (
                    type(payload) is model.GenericCfgGateEvidencePayload
                    and target in payload.affected_subject_ids
                )
                if not correlated:
                    raise ValueError("justification premise is outside conclusion subject scope")
        if item.claim_id is not None and claims:
            claim = next((claim for claim in claims if claim.claim_id == item.claim_id), None)
            if claim is None:
                raise ValueError("justification claim is outside claim inventory")
            allowed = {
                model.UnflattenJustificationRule.RETIRED_INFRASTRUCTURE_PROVEN: type(claim) is model.RetiredDispatcherInfrastructureClaim,
                model.UnflattenJustificationRule.EQUIVALENT_ROUTE_PROVEN: type(claim) in {
                    model.EquivalentSemanticRouteClaim,
                    model.ExactInfeasibleEffectClaim,
                },
                model.UnflattenJustificationRule.EXACT_INFEASIBLE_EFFECT_PROVEN: type(claim) is model.ExactInfeasibleEffectClaim,
                model.UnflattenJustificationRule.LOCAL_ALIAS_SCALARIZATION_PROVEN: type(claim) is model.LocalAliasEffectScalarizationClaim,
                model.UnflattenJustificationRule.TERMINAL_CYCLE_BREAK_PROVEN: type(claim) is model.TerminalCycleBreakClaim,
            }.get(item.rule, False)
            if not allowed:
                raise ValueError("justification rule does not match its claim")
            claim_targets = {
                subject.subject_id for subject in _claim_subjects(claim)
            }
            if type(claim) is model.LocalAliasEffectScalarizationClaim:
                claim_targets.update(
                    relation.target_subject_id
                    for relation in conditional_relations
                    if relation.source_subject_id == claim.owner_subject.subject_id
                    and relation.dimension is model.SafetyDimension.EFFECT_PRESERVATION
                )
            elif type(claim) is model.ExactInfeasibleEffectClaim:
                for premise in item.premise_ids:
                    payload = by_evidence_id[premise].payload
                    if type(payload) is model.SemanticRouteEvidencePayload:
                        claim_targets.add(payload.route_subject_id)
                        claim_targets.update(payload.destination_subject_ids)
            if item.conclusion.subject.subject_id not in claim_targets:
                raise ValueError("claim justification concludes outside claim scope")
            for premise in item.premise_ids:
                payload = by_evidence_id[premise].payload
                correlated = False
                if type(claim) is model.RetiredDispatcherInfrastructureClaim:
                    correlated = (
                        type(payload) is model.StructuralLineageEvidencePayload
                        and payload.claim_id == claim.claim_id
                    ) or (
                        type(payload) is model.CorridorCoverageEvidencePayload
                        and payload.corridor_subject_id == claim.corridor_subject.subject_id
                    )
                elif type(claim) is model.EquivalentSemanticRouteClaim:
                    correlated = (
                        type(payload) is model.SemanticRouteEvidencePayload
                        and payload.route_subject_id == claim.retired_route_subject.subject_id
                        and payload.source_subject_id == claim.source_subject.subject_id
                        and payload.destination_subject_ids == _route_destination_ids(claim.retired_route_subject, subjects)
                    )
                elif type(claim) is model.ExactInfeasibleEffectClaim:
                    correlated = (
                        type(payload) is model.EffectSiteEvidencePayload
                        and payload.effect_subject_id == claim.discarded_effect_subject.subject_id
                    ) or (
                        type(payload) is model.SemanticRouteEvidencePayload
                        and payload.source_subject_id == claim.predicate_subject.subject_id
                        and payload.proof_ids == tuple(sorted(claim.route_proof_ids))
                    )
                elif type(claim) is model.LocalAliasEffectScalarizationClaim:
                    correlated = (
                        type(payload) is model.EffectSiteEvidencePayload
                        and payload.effect_subject_id in claim_targets
                    ) or (
                        type(payload) is model.PatchStepEvidencePayload
                        and payload.owner_ref == claim.owner_subject.block_ref
                    ) or (
                        type(payload) is model.PhaseBindingEvidencePayload
                        and payload.binding.subject.subject_id == claim.owner_subject.subject_id
                    ) or (
                        type(payload) is model.ReachabilityEvidencePayload
                        and payload.target_subject_id == claim.owner_subject.subject_id
                    )
                elif type(claim) is model.TerminalCycleBreakClaim:
                    correlated = (
                        type(payload) is model.StructuralLineageEvidencePayload
                        and payload.claim_id == claim.claim_id
                    ) or (
                        type(payload) is model.ReachabilityEvidencePayload
                        and payload.target_subject_id == claim.terminal_subject.subject_id
                    )
                if not correlated:
                    raise ValueError("claim premise is outside exact claim evidence scope")
        graph[item.justification_id] = ()
    visiting: set[str] = set()
    visited: set[str] = set()
    def visit(node: str) -> None:
        if node in visiting:
            raise ValueError("justification graph contains a cycle")
        if node in visited:
            return
        visiting.add(node)
        for parent in graph[node]:
            visit(parent)
        visiting.remove(node)
        visited.add(node)
    for node in graph:
        visit(node)


def _identity_support(
    subject: model.SemanticSubjectRef,
    inventory: tuple[model.SemanticSubjectRef, ...],
    bindings: tuple[model.PhaseSubjectBinding, ...],
    phase: model.UnflattenAuthorityPhase,
    fingerprint: str,
    generation: int,
    *,
    allow_source_indexed_missing: bool = False,
) -> bool:
    if not any(candidate == subject for candidate in inventory) and not (
        allow_source_indexed_missing
        and any(
            binding.subject == subject
            and binding.status is model.SubjectBindingStatus.MISSING
            for binding in bindings
        )
    ):
        # source-indexed MISSING rows are a known identity absence
        return False
    valid = tuple(
        binding for binding in bindings
        if binding.phase is phase and (
            binding.status is model.SubjectBindingStatus.UNIQUE
            or (
                allow_source_indexed_missing
                and binding.status is model.SubjectBindingStatus.MISSING
                and binding.subject == subject
            )
        )
        and binding.graph_fingerprint == fingerprint and binding.generation == generation
    )
    if allow_source_indexed_missing and any(
        binding.subject == subject
        and binding.status is model.SubjectBindingStatus.MISSING
        for binding in valid
    ) and type(subject.locator) is not model.ValueFlowSubjectLocator:
        return True
    def owner(ref: object, anchor: int | None = None) -> bool:
        return any(
            binding.subject.kind is model.SemanticSubjectKind.BLOCK
            and binding.subject.block_ref == ref
            and (anchor is None or binding.anchor_ea == anchor)
            for binding in valid
        )
    exact_subject_binding = any(binding.subject == subject for binding in valid)
    locator = subject.locator
    if type(locator) is model.BlockSubjectLocator:
        return any(binding.subject == subject for binding in valid)
    if type(locator) is model.ValueFlowSubjectLocator:
        refs = tuple(locator.redirect_owner_refs)
        if not refs or len(set(refs)) != len(refs):
            return False
        owner_subjects = tuple(
            candidate for candidate in inventory
            if candidate.role is model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE
            and candidate.block_ref in refs
        )
        if (
            len(owner_subjects) != len(refs)
            or {candidate.block_ref for candidate in owner_subjects} != set(refs)
        ):
            return False
        owner_bindings = tuple(
            binding for binding in bindings
            if binding.subject.role is model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE
            and binding.subject.block_ref in refs
        )
        if {
            binding.subject.block_ref for binding in owner_bindings
        } != set(refs) or len(owner_bindings) != len(owner_subjects):
            return False
        return all(
            binding.phase is phase
            and binding.status is model.SubjectBindingStatus.UNIQUE
            and binding.graph_fingerprint == fingerprint
            and binding.generation == generation
            and binding.block_ref == binding.subject.block_ref
            and binding.anchor_ea == binding.subject.anchor_ea
            and binding.subject.anchor_ea in binding.native_instruction_eas
            for binding in owner_bindings
        )
    if type(locator) is model.RouteSubjectLocator:
        return exact_subject_binding and owner(locator.source_ref, locator.source_anchor_ea) and all(
            owner(ref, anchor)
            for ref, anchor in zip(locator.destination_refs, locator.destination_anchor_eas)
        )
    if type(locator) is model.EdgeSubjectLocator:
        return exact_subject_binding and owner(locator.source_ref, locator.source_anchor_ea) and owner(locator.target_ref, locator.target_anchor_ea)
    if type(locator) is model.EffectSubjectLocator:
        return exact_subject_binding and owner(locator.owner_ref, locator.owner_anchor_ea)
    if type(locator) is model.HandlerSubjectLocator or type(locator) is model.TerminalSubjectLocator:
        return exact_subject_binding and owner(locator.block_ref, locator.anchor_ea)
    if type(locator) is model.CorridorSubjectLocator:
        return exact_subject_binding and owner(locator.entry_ref, locator.entry_anchor_ea) and all(
            owner(ref, anchor) for ref, anchor in zip(locator.member_refs, locator.member_anchor_eas)
        )
    return False


def _receipt_digest(value: object) -> str:
    return _authority_id_digest(value)


def _validate_receipt(
    inputs: model.DerivedUnflattenPreparationInputs,
) -> None:
    receipt = inputs.preparation_receipt
    proposal = inputs.proposal
    if receipt.proposal_id != _receipt_digest(proposal):
        raise ValueError("preparation receipt belongs to a different proposal")
    if receipt.plan_id != proposal.plan_id:
        raise ValueError("preparation receipt belongs to a different plan")
    if receipt.source_fingerprint != inputs.source_inventory.graph_fingerprint or receipt.candidate_fingerprint != inputs.candidate_inventory.graph_fingerprint:
        raise ValueError("preparation receipt fingerprint mismatch")
    if receipt.source_generation != inputs.source_inventory.generation or receipt.candidate_generation != inputs.candidate_inventory.generation:
        raise ValueError("preparation receipt generation mismatch")
    if receipt.metrics != inputs.preparation_metrics:
        raise ValueError("preparation receipt metrics mismatch")
    source_subjects = tuple(sorted(inputs.source_inventory.subjects, key=lambda item: item.subject_id))
    candidate_subjects = tuple(sorted(inputs.candidate_inventory.subjects, key=lambda item: item.subject_id))
    source_bindings = tuple(sorted(inputs.source_inventory.bindings, key=lambda item: item.subject.subject_id))
    candidate_bindings = tuple(sorted(inputs.candidate_inventory.bindings, key=lambda item: item.subject.subject_id))
    relations = tuple(sorted(inputs.conditional_relations, key=lambda item: (item.source_subject_id, item.target_subject_id, item.dimension.value, item.provenance_id)))
    patch_payloads = tuple(
        item for item in inputs.patch_step_facts
        if type(item) is model.PatchStepEvidencePayload
    )
    route_subjects = tuple(
        item for item in source_subjects
        if item.role in (model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE, model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION)
    )
    effect_subjects = tuple(item.subject_id for item in source_subjects if item.role is model.SemanticSubjectRole.EFFECT_SITE)
    terminal_subjects = tuple(item.subject_id for item in source_subjects if item.role is model.SemanticSubjectRole.TERMINAL_SITE)
    plan_input_subjects = tuple(
        item.subject_id for item in source_subjects
        if item.role in {
            model.SemanticSubjectRole.SOURCE_ENTRY,
            model.SemanticSubjectRole.DISPATCHER_ENTRY,
            model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE,
            model.SemanticSubjectRole.AUTHORITATIVE_HANDLER,
        }
    )
    dispatcher_members = tuple(
        item.subject_id for item in source_subjects
        if item.role is model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE
    )
    helpers = tuple(
        item.subject_id for item in candidate_subjects
        if item.role is model.SemanticSubjectRole.PLANNED_HELPER
    )
    expected = {
        "source_inventory_digest": inputs.source_inventory.inventory_digest,
        "candidate_inventory_digest": inputs.candidate_inventory.inventory_digest,
        "source_binding_digest": _receipt_digest(source_bindings),
        "candidate_binding_digest": _receipt_digest(candidate_bindings),
        "route_expansion_digest": _receipt_digest(route_subjects),
        "effect_catalog_digest": _receipt_digest(effect_subjects),
        "terminal_catalog_digest": _receipt_digest(terminal_subjects),
        "plan_input_digest": _receipt_digest(plan_input_subjects),
        "dispatcher_member_digest": _receipt_digest(dispatcher_members),
        "planned_helper_digest": _receipt_digest(helpers),
        "patch_step_digest": _receipt_digest(tuple(sorted(patch_payloads, key=lambda item: (item.plan_id, item.step_index)))),
        "conditional_relation_digest": _receipt_digest(relations),
        "generic_gate_facts_digest": (
            _receipt_digest(inputs.generic_gate_facts)
            if inputs.generic_gate_facts is not None else None
        ),
        "route_assessment_digest": (
            _receipt_digest(tuple(
                (
                    item.phase.value, item.graph_fingerprint, item.generation,
                    item.evidence_id, item.proof_ids,
                    item.rejection_reason.value if item.rejection_reason else None,
                    item.bound_content_digest,
                )
                for item in (inputs.source_route_assessment, inputs.candidate_route_assessment)
                if item is not None
            ))
            if inputs.source_route_assessment is not None or inputs.candidate_route_assessment is not None
            else None
        ),
    }
    for name, value in expected.items():
        if getattr(receipt, name) != value:
            raise ValueError(f"preparation receipt {name} mismatch")
    source_pairs = {(subject.block_ref, subject.anchor_ea) for subject in source_subjects if subject.block_ref is not None}
    # The receipt is the closed preparation boundary.  A partial catalogue
    # cannot be repaired by looking at claims or coincident coordinates.
    if source_pairs != set(
        (block.block_ref, block.anchor_ea)
        for block in proposal.source_identity_catalog.blocks
    ):
        raise ValueError("source inventory does not exactly cover the proposal source catalog")
    plan_refs = {
        proposal.plan_inputs.source_entry_ref,
        proposal.plan_inputs.dispatcher_entry_ref,
        *proposal.plan_inputs.dispatcher_member_refs,
        *(handler.block_ref for handler in proposal.plan_inputs.authoritative_handlers),
        *proposal.use_def_witness.redirect_owner_refs,
    }
    if not plan_refs <= {subject.block_ref for subject in source_subjects if subject.block_ref is not None}:
        raise ValueError("source inventory does not cover all plan inputs")
    member_subject_refs = {
        subject.block_ref
        for subject in source_subjects
        if subject.role is model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE
    }
    if not set(proposal.plan_inputs.dispatcher_member_refs) <= member_subject_refs:
        raise ValueError("dispatcher member inventory does not cover the plan input catalog")
    handler_subject_refs = {
        (subject.block_ref, subject.anchor_ea)
        for subject in source_subjects
        if subject.role is model.SemanticSubjectRole.AUTHORITATIVE_HANDLER
    }
    expected_handlers = {
        (handler.block_ref, handler.anchor_ea)
        for handler in proposal.plan_inputs.authoritative_handlers
    }
    if not expected_handlers <= handler_subject_refs:
        raise ValueError("authoritative handler inventory does not cover the plan input catalog")
    route_expansions = {
        (
            subject.locator.proof_id,
            subject.locator.source_ref,
            subject.locator.source_anchor_ea,
            tuple(zip(subject.locator.destination_refs, subject.locator.destination_anchor_eas)),
        )
        for subject in source_subjects
        if type(subject.locator) is model.RouteSubjectLocator
    }
    expected_expansions = {
        (
            proof.proof_id,
            next(
                block.block_ref for block in proposal.source_identity_catalog.blocks
                if block.anchor_ea == proof.source_anchor_ea or proof.source_anchor_ea in block.native_instruction_eas
            ),
            proof.source_anchor_ea,
            tuple(
                (
                    next(
                        block.block_ref for block in proposal.source_identity_catalog.blocks
                        if block.anchor_ea == destination.target_anchor_ea or destination.target_anchor_ea in block.native_instruction_eas
                    ),
                    destination.target_anchor_ea,
                )
                for destination in proof.destinations
            ),
        )
        for proof in proposal.route_evidence.route_proofs
    }
    if expected_expansions != route_expansions:
        raise ValueError("source inventory does not cover canonical route expansion")


def _evaluator_fact_evidence(
    inputs: model.DerivedUnflattenPreparationInputs,
    phase: model.UnflattenAuthorityPhase,
) -> tuple[tuple[model.AuthorityEvidence, ...], tuple[model.AuthorityEvidence, ...], tuple[model.GenericCfgGateResult, ...], dict[str, _EffectClassification]]:
    """Create semantic evidence from closed inventories and transport facts."""

    source = inputs.source_inventory
    candidate = inputs.candidate_inventory
    source_subjects = tuple(sorted(source.subjects, key=lambda item: item.subject_id))
    candidate_subjects = tuple(sorted(candidate.subjects, key=lambda item: item.subject_id))
    source_bindings = {item.subject.subject_id: item for item in source.bindings}
    candidate_bindings = {item.subject.subject_id: item for item in candidate.bindings}
    evidence: list[model.AuthorityEvidence] = []
    classifications: dict[str, _EffectClassification] = {}
    validated_exact_claims: dict[str, model.ExactInfeasibleEffectClaim] = {}

    def structural_lineage(
        subject: model.SemanticSubjectRef,
        source_binding: model.PhaseSubjectBinding,
        candidate_binding: model.PhaseSubjectBinding | None,
    ) -> tuple[model.StructuralDisposition, tuple[str, ...], tuple[int, ...], tuple[str, ...]]:
        """Classify block origins from the already-bound candidate inventory."""

        if source_binding.status is not model.SubjectBindingStatus.UNIQUE:
            return model.StructuralDisposition.UNACCOUNTED_LOSS, (), (), (subject.subject_id,)
        source_origins = set(source_binding.native_instruction_eas)
        if subject.kind is not model.SemanticSubjectKind.BLOCK:
            if (
                candidate_binding is not None
                and candidate_binding.status is model.SubjectBindingStatus.UNIQUE
            ):
                origins = tuple(sorted(source_origins & set(candidate_binding.native_instruction_eas)))
                return model.StructuralDisposition.PRESERVED, (subject.subject_id,), origins, (subject.subject_id,)
            return model.StructuralDisposition.UNACCOUNTED_LOSS, (), (), (subject.subject_id,)
        if not any(
            type(binding.subject.block_ref) is PlanBlockRef
            for binding in candidate_bindings.values()
            if binding.status is model.SubjectBindingStatus.UNIQUE
        ):
            intersecting_ids = {
                binding.subject.subject_id
                for binding in candidate_bindings.values()
                if binding.status is model.SubjectBindingStatus.UNIQUE
                and binding.subject.kind is model.SemanticSubjectKind.BLOCK
                and binding.subject.role in {
                    subject.role,
                    model.SemanticSubjectRole.PLANNED_HELPER,
                }
                and set(binding.native_instruction_eas) & source_origins
            }
            if (
                candidate_binding is None
                or candidate_binding.status is not model.SubjectBindingStatus.UNIQUE
                or set(candidate_binding.native_instruction_eas) != source_origins
                or intersecting_ids != {subject.subject_id}
            ):
                return model.StructuralDisposition.UNACCOUNTED_LOSS, (), (), (subject.subject_id,)
            return (
                model.StructuralDisposition.PRESERVED,
                (subject.subject_id,),
                tuple(sorted(candidate_binding.native_instruction_eas)),
                (subject.subject_id,),
            )
        candidates = tuple(
            binding for binding in candidate_bindings.values()
            if binding.status is model.SubjectBindingStatus.UNIQUE
            and binding.subject.kind is model.SemanticSubjectKind.BLOCK
            and binding.subject.role in {
                subject.role,
                model.SemanticSubjectRole.PLANNED_HELPER,
            }
        )
        closed_targets = {
            relation.target_subject_id
            for relation in inputs.conditional_relations
            if relation.source_subject_id == subject.subject_id
            and relation.dimension is model.SafetyDimension.STRUCTURAL_ACCOUNTING
        }
        intersecting_candidates = tuple(
            binding for binding in candidate_bindings.values()
            if binding.status is model.SubjectBindingStatus.UNIQUE
            and binding.subject.kind is model.SemanticSubjectKind.BLOCK
            and binding.subject.role in {
                subject.role,
                model.SemanticSubjectRole.PLANNED_HELPER,
            }
            and set(binding.native_instruction_eas) & source_origins
        )
        intersecting_candidate_ids = {
            binding.subject.subject_id for binding in intersecting_candidates
        }
        if not closed_targets:
            if (
                candidate_binding is not None
                and candidate_binding.status is model.SubjectBindingStatus.UNIQUE
                and set(candidate_binding.native_instruction_eas) == source_origins
                and intersecting_candidate_ids == {subject.subject_id}
            ):
                return model.StructuralDisposition.PRESERVED, (subject.subject_id,), tuple(sorted(source_origins)), (subject.subject_id,)
            return model.StructuralDisposition.UNACCOUNTED_LOSS, (), (), (subject.subject_id,)
        if intersecting_candidate_ids != closed_targets:
            return model.StructuralDisposition.UNACCOUNTED_LOSS, (), (), (subject.subject_id,)
        candidates = tuple(
            binding for binding in candidates
            if binding.subject.subject_id in closed_targets
        )
        candidates = tuple(sorted(candidates, key=lambda item: item.subject.subject_id))
        candidate_sets = tuple(set(item.native_instruction_eas) for item in candidates)
        reverse_sources = {
            candidate.subject.subject_id: {
                relation.source_subject_id
                for relation in inputs.conditional_relations
                if relation.target_subject_id == candidate.subject.subject_id
                and relation.dimension is model.SafetyDimension.STRUCTURAL_ACCOUNTING
            }
            for candidate in candidates
        }
        if (
            len(candidates) >= 2
            and all(candidate_sets)
            and all(reverse_sources[item.subject.subject_id] == {subject.subject_id} for item in candidates)
            and all(left.isdisjoint(right) for index, left in enumerate(candidate_sets) for right in candidate_sets[index + 1:])
            and set().union(*candidate_sets) == source_origins
        ):
            return (
                model.StructuralDisposition.SPLIT,
                tuple(item.subject.subject_id for item in candidates),
                tuple(sorted(source_origins)),
                (subject.subject_id,),
            )
        if len(candidates) == 1:
            candidate_origins = candidate_sets[0]
            source_group = tuple(sorted(
                item.subject_id
                for item in source_subjects
                if item.kind is model.SemanticSubjectKind.BLOCK
                and item.role is subject.role
                and (
                    binding := source_bindings.get(item.subject_id)
                ) is not None
                and binding.status is model.SubjectBindingStatus.UNIQUE
                and any(
                    relation.source_subject_id == item.subject_id
                    and relation.target_subject_id == candidates[0].subject.subject_id
                    and relation.dimension is model.SafetyDimension.STRUCTURAL_ACCOUNTING
                    for relation in inputs.conditional_relations
                )
            ))
            source_sets = tuple(
                set(source_bindings[item].native_instruction_eas)
                for item in source_group
            )
            intersecting_sources = {
                item.subject_id for item in source_subjects
                if item.kind is model.SemanticSubjectKind.BLOCK
                and item.role is subject.role
                and (binding := source_bindings.get(item.subject_id)) is not None
                and binding.status is model.SubjectBindingStatus.UNIQUE
                and set(binding.native_instruction_eas) & candidate_origins
            }
            if (
                len(source_group) >= 2
                and reverse_sources[candidates[0].subject.subject_id] == set(source_group)
                and intersecting_sources == set(source_group)
                and all(source_sets)
                and all(left.isdisjoint(right) for index, left in enumerate(source_sets) for right in source_sets[index + 1:])
                and set().union(*source_sets) == candidate_origins
            ):
                return (
                    model.StructuralDisposition.FOLDED,
                    (candidates[0].subject.subject_id,),
                    tuple(sorted(candidate_origins)),
                    source_group,
                )
            if (
                candidate_origins == source_origins
                and reverse_sources[candidates[0].subject.subject_id] == {subject.subject_id}
            ):
                return model.StructuralDisposition.PRESERVED, (candidates[0].subject.subject_id,), tuple(sorted(source_origins)), (subject.subject_id,)
        return model.StructuralDisposition.UNACCOUNTED_LOSS, (), (), (subject.subject_id,)
    for exact_claim in inputs.claims:
        if type(exact_claim) is not model.ExactInfeasibleEffectClaim:
            continue
        try:
            correlation = producer_api.validate_exact_effect_claim_semantics(
                proposal=inputs.proposal,
                claim=exact_claim,
                source_serial_by_ref=source.serial_by_ref,
            )
        except (TypeError, ValueError):
            correlation = None
        if correlation is not None:
            validated_exact_claims[exact_claim.discarded_effect_subject.subject_id] = exact_claim
    alias_context_by_effect: dict[
        str,
        tuple[
            model.LocalAliasEffectScalarizationClaim,
            model.PhaseSubjectBinding | None,
            model.InventoryInstructionObservation | None,
            bool,
        ],
    ] = {}
    for alias_claim in (
        claim for claim in inputs.claims
        if type(claim) is model.LocalAliasEffectScalarizationClaim
    ):
        effect_subjects = tuple(
            subject for subject in source_subjects
            if subject.role is model.SemanticSubjectRole.EFFECT_SITE
            and type(subject.locator) is model.EffectSubjectLocator
            and subject.locator.owner_ref == alias_claim.owner_subject.block_ref
            and subject.locator.owner_anchor_ea == alias_claim.owner_subject.anchor_ea
            and subject.locator.instruction_ea == alias_claim.host_ea
            and subject.locator.effect_kind is model.EffectSiteKind.STORE
        )
        if len(effect_subjects) != 1:
            raise ValueError("local-alias relation must target an exact STORE alias effect")
        effect_subject = effect_subjects[0]
        relation_rows = tuple(
            relation for relation in inputs.conditional_relations
            if relation.source_subject_id == alias_claim.owner_subject.subject_id
            and relation.target_subject_id == effect_subject.subject_id
            and relation.dimension is model.SafetyDimension.EFFECT_PRESERVATION
        )
        if len(relation_rows) != 1 or effect_subject.subject_id in alias_context_by_effect:
            raise ValueError("local-alias claim must have one unique effect relation")
        if (
            effect_subject is None
            or effect_subject.role is not model.SemanticSubjectRole.EFFECT_SITE
            or type(effect_subject.locator) is not model.EffectSubjectLocator
            or effect_subject.locator.owner_ref != alias_claim.owner_subject.block_ref
            or effect_subject.locator.owner_anchor_ea != alias_claim.owner_subject.anchor_ea
            or effect_subject.locator.instruction_ea != alias_claim.host_ea
            or effect_subject.locator.effect_kind is not model.EffectSiteKind.STORE
        ):
            raise ValueError("local-alias relation does not target its exact STORE alias effect")
        owner_binding = candidate_bindings.get(alias_claim.owner_subject.subject_id)
        owner_observation = None
        if owner_binding is not None and owner_binding.status is model.SubjectBindingStatus.UNIQUE:
            owner_observations = tuple(
                observation
                for block in candidate.blocks
                if block.serial == owner_binding.serial
                for observation in block.instruction_observations
                if observation.instruction_ea == alias_claim.host_ea
            )
            if len(owner_observations) > 1:
                raise ValueError("local-alias host observation is ambiguous")
            owner_observation = owner_observations[0] if owner_observations else None
        owner_reachable = bool(
            owner_binding is not None
            and owner_binding.status is model.SubjectBindingStatus.UNIQUE
            and owner_binding.serial in candidate.reachable_serials
        )
        alias_context_by_effect[effect_subject.subject_id] = (
            alias_claim, owner_binding, owner_observation, owner_reachable,
        )

    topology_roles = {
        model.SemanticSubjectRole.SOURCE_ENTRY,
        model.SemanticSubjectRole.DISPATCHER_ENTRY,
        model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE,
        model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE,
        model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION,
        model.SemanticSubjectRole.AUTHORITATIVE_HANDLER,
        model.SemanticSubjectRole.PLANNED_HELPER,
    }

    def topology_relations(inventory: model.SemanticGraphInventory) -> tuple[model.TopologyEdgeRelation, ...]:
        by_serial = {item.serial: item for item in inventory.blocks}
        subject_by_serial: dict[int, tuple[model.SemanticSubjectRef, ...]] = defaultdict(tuple)
        for subject in inventory.subjects:
            if (
                subject.role in topology_roles
                and subject.block_ref is not None
                and subject.block_ref in inventory.serial_by_ref
            ):
                serial = inventory.serial_by_ref[subject.block_ref]
                subject_by_serial[serial] = (*subject_by_serial[serial], subject)
        rows: dict[tuple[int, int], dict[model.TopologyIncidenceKind, model.InventoryTopologyIncidence]] = {}
        for item in inventory.topology:
            key = (item.owner_serial, item.peer_serial) if item.kind is model.TopologyIncidenceKind.SUCCESSOR else (item.peer_serial, item.owner_serial)
            rows.setdefault(key, {})[item.kind] = item
        result: list[model.TopologyEdgeRelation] = []
        for (source_serial, target_serial), pair in rows.items():
            successor = pair.get(model.TopologyIncidenceKind.SUCCESSOR)
            predecessor = pair.get(model.TopologyIncidenceKind.PREDECESSOR)
            if successor is None or predecessor is None or successor.source_transfer_ea != predecessor.source_transfer_ea:
                continue
            anchor = successor.source_transfer_ea
            if anchor is None:
                anchor = by_serial[source_serial].anchor_ea
            if anchor is None:
                continue
            for source_subject in subject_by_serial.get(source_serial, ()):
                for target_subject in subject_by_serial.get(target_serial, ()):
                    result.append(model.TopologyEdgeRelation(
                        model.SemanticEdgeRole.DIRECT, source_subject.subject_id,
                        target_subject.subject_id, anchor,
                    ))
                    result.append(model.TopologyEdgeRelation(
                        model.SemanticEdgeRole.DIRECT, target_subject.subject_id,
                        source_subject.subject_id, anchor,
                    ))
        return tuple(sorted(result, key=lambda item: (item.source_subject_id, item.target_subject_id, item.native_edge_anchor_ea)))

    source_topology = topology_relations(source)
    candidate_topology = topology_relations(candidate)

    def has_reciprocal_edges(relations: tuple[model.TopologyEdgeRelation, ...]) -> bool:
        """Report reciprocity of the raw topology rows being assessed."""

        if not relations:
            return True
        relation_set = set(relations)
        return all(
            model.TopologyEdgeRelation(
                relation.role,
                relation.target_subject_id,
                relation.source_subject_id,
                relation.native_edge_anchor_ea,
            ) in relation_set
            for relation in relations
        )

    # Reachability is reconstructed from the closed candidate block rows.  A
    # two-node ``(root, target)`` witness is not evidence: every returned path
    # must follow the candidate successor relation and name each intermediate
    # inventoried block.
    source_entry = next((
        item for item in source_subjects
        if item.role is model.SemanticSubjectRole.SOURCE_ENTRY
    ), None)
    candidate_binding_by_id = {
        item.subject.subject_id: item for item in candidate.bindings
    }
    candidate_subjects_by_serial: dict[int, tuple[model.SemanticSubjectRef, ...]] = {}
    for subject in candidate.subjects:
        binding = candidate_binding_by_id.get(subject.subject_id)
        if binding is None or binding.status is not model.SubjectBindingStatus.UNIQUE:
            continue
        if type(binding.serial) is not int:
            continue
        candidate_subjects_by_serial[binding.serial] = (
            *candidate_subjects_by_serial.get(binding.serial, ()), subject,
        )
    candidate_blocks_by_serial = {item.serial: item for item in candidate.blocks}
    candidate_entry_binding = (
        None if source_entry is None
        else candidate_binding_by_id.get(source_entry.subject_id)
    )
    root_serial = (
        None if candidate_entry_binding is None
        or candidate_entry_binding.status is not model.SubjectBindingStatus.UNIQUE
        else candidate_entry_binding.serial
    )
    paths: dict[int, tuple[int, ...]] = {}
    if type(root_serial) is int and root_serial in candidate_blocks_by_serial:
        queue = [root_serial]
        paths[root_serial] = (root_serial,)
        while queue:
            serial = queue.pop(0)
            block = candidate_blocks_by_serial[serial]
            for successor in block.successor_serials:
                if successor in paths or successor not in candidate_blocks_by_serial:
                    continue
                paths[successor] = (*paths[serial], successor)
                queue.append(successor)
    assessment = inputs.source_route_assessment if phase is model.UnflattenAuthorityPhase.PRODUCER_FORECAST else inputs.candidate_route_assessment
    for subject in source_subjects:
        if subject.role is model.SemanticSubjectRole.EFFECT_SITE and type(subject.locator) is model.EffectSubjectLocator:
            locator = subject.locator
            effect = next((item for item in source.effects
                           if item.owner_ref == locator.owner_ref
                           and item.owner_anchor_ea == locator.owner_anchor_ea
                           and item.instruction_ea == locator.instruction_ea
                           and item.effect_kind is locator.effect_kind), None)
            if effect is not None and effect.owner_serial in source.reachable_serials:
                candidate_effect = tuple(
                    item for item in candidate.effects
                    if item.owner_ref == effect.owner_ref
                    and item.owner_anchor_ea == effect.owner_anchor_ea
                    and item.instruction_ea == effect.instruction_ea
                )
                alias_context = alias_context_by_effect.get(
                    subject.subject_id, (None, None, None, False),
                )
                classifications[subject.subject_id] = _classify_effect_site(
                    effect,
                    subject,
                    source_bindings[subject.subject_id],
                    candidate_bindings.get(subject.subject_id),
                    candidate_effect,
                    validated_exact_claims.get(subject.subject_id),
                    assessment,
                    inputs.generic_gate_facts,
                    local_alias_claim=alias_context[0],
                    local_alias_owner_binding=alias_context[1],
                    local_alias_owner_observation=alias_context[2],
                    local_alias_owner_reachable=alias_context[3],
                    phase=phase,
                )
    for subject in source_subjects:
        if subject.role not in {
            model.SemanticSubjectRole.DISPATCHER_ENTRY,
            model.SemanticSubjectRole.AUTHORITATIVE_HANDLER,
            model.SemanticSubjectRole.TERMINAL_SITE,
            model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION,
        } and not (
            subject.role is model.SemanticSubjectRole.EFFECT_SITE
            and subject.kind is model.SemanticSubjectKind.BLOCK
            and any(
                type(claim) is model.LocalAliasEffectScalarizationClaim
                and claim.owner_subject.subject_id == subject.subject_id
                for claim in inputs.claims
            )
        ) or source_entry is None or subject.block_ref is None:
            continue
        binding = candidate_binding_by_id.get(subject.subject_id)
        candidate_serial = (
            None if binding is None
            or binding.status is not model.SubjectBindingStatus.UNIQUE
            else binding.serial
        )
        serial_path = paths.get(candidate_serial) if type(candidate_serial) is int else None
        if serial_path is None:
            path_subject_ids: tuple[str, ...] = ()
            reachable = False
        else:
            path_subject_ids_list: list[str] = [source_entry.subject_id]
            for serial in serial_path[1:-1]:
                intermediate = candidate_subjects_by_serial.get(serial, ())
                if not intermediate:
                    path_subject_ids_list = []
                    break
                path_subject_ids_list.append(intermediate[0].subject_id)
            if path_subject_ids_list and serial_path[-1] == root_serial:
                path_subject_ids = (
                    tuple(path_subject_ids_list)
                    if subject.subject_id == source_entry.subject_id
                    else (*path_subject_ids_list, subject.subject_id)
                )
            elif path_subject_ids_list:
                path_subject_ids = (*path_subject_ids_list, subject.subject_id)
            else:
                path_subject_ids = ()
            reachable = bool(path_subject_ids)
        evidence.append(_evidence_factory(
            model.AuthorityEvidence,
            model.AuthorityEvidenceKind.REACHABILITY,
            subject,
            phase,
            model.ReachabilityEvidencePayload(
                source_entry.subject_id, subject.subject_id, reachable,
                path_subject_ids,
            ),
        ))

    for subject in source_subjects:
        if subject.block_ref is None:
            continue
        source_binding = source_bindings.get(subject.subject_id)
        candidate_binding = candidate_bindings.get(subject.subject_id)
        if source_binding is None:
            continue
        effect_classification = classifications.get(subject.subject_id)
        if (
            phase is model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT
            and
            effect_classification is not None
            and effect_classification.refuted
            and not effect_classification.authorized_loss
            and subject.kind is not model.SemanticSubjectKind.BLOCK
            and (
                candidate_binding is not None
                and candidate_binding.status is model.SubjectBindingStatus.MISSING
            )
            and any(
                binding.block_ref == subject.block_ref
                and binding.status is model.SubjectBindingStatus.UNIQUE
                for binding in candidate_bindings.values()
            )
            and not any(
                candidate.kind is model.SemanticSubjectKind.EFFECT
                and candidate.block_ref == subject.block_ref
                and candidate.anchor_ea == subject.anchor_ea
                and (
                    candidate_binding_for_subject := candidate_bindings.get(candidate.subject_id)
                ) is not None
                and candidate_binding_for_subject.status is model.SubjectBindingStatus.UNIQUE
                for candidate in candidate_subjects
            )
        ):
            raise ValueError("preserved lineage requires an exact candidate subject")
        preserved = (
            source_binding.status is model.SubjectBindingStatus.UNIQUE
            and candidate_binding is not None
            and candidate_binding.status is model.SubjectBindingStatus.UNIQUE
        )
        if effect_classification is not None:
            if effect_classification.authorized_loss:
                alias_owner_binding = None
                if type(effect_classification.claim) is model.LocalAliasEffectScalarizationClaim:
                    alias_owner_binding = candidate_bindings.get(
                        effect_classification.claim.owner_subject.subject_id
                    )
                if (
                    alias_owner_binding is not None
                    and alias_owner_binding.status is model.SubjectBindingStatus.UNIQUE
                ):
                    # Alias scalarization changes the exact effect, while the
                    # owning block remains structurally preserved.
                    disposition = model.StructuralDisposition.PRESERVED
                else:
                    disposition = None
            elif effect_classification.preserved or effect_classification.structural_preserved:
                disposition = model.StructuralDisposition.PRESERVED
            else:
                disposition = model.StructuralDisposition.UNACCOUNTED_LOSS
        else:
            disposition = model.StructuralDisposition.PRESERVED if preserved else model.StructuralDisposition.UNACCOUNTED_LOSS
        claim = next((claim for claim in inputs.claims
                      if type(claim) is model.RetiredDispatcherInfrastructureClaim
                      and subject.subject_id in {item.subject_id for item in claim.member_subjects}), None)
        if (
            claim is not None
            and disposition is not None
            and candidate_binding is not None
            and candidate_binding.status is model.SubjectBindingStatus.UNIQUE
        ):
            disposition = model.StructuralDisposition.AUTHORIZED_RETIREMENT
        if effect_classification is None and subject.kind is model.SemanticSubjectKind.BLOCK:
            disposition, derived_candidate_ids, derived_origins, source_group = structural_lineage(
                subject, source_binding, candidate_binding,
            )
            if disposition is model.StructuralDisposition.FOLDED and subject.subject_id != source_group[0]:
                continue
        else:
            derived_candidate_ids = ()
            derived_origins = ()
            source_group = (subject.subject_id,)
        lineage_preserved = disposition is model.StructuralDisposition.PRESERVED
        lineage_binding = candidate_binding
        if (
            effect_classification is not None
            and type(effect_classification.claim) is model.LocalAliasEffectScalarizationClaim
        ):
            lineage_binding = candidate_bindings.get(
                effect_classification.claim.owner_subject.subject_id,
            )
        lineage_candidate_ids = (
            (effect_classification.claim.owner_subject.subject_id,)
            if (
                lineage_preserved
                and effect_classification is not None
                and type(effect_classification.claim) is model.LocalAliasEffectScalarizationClaim
            )
            else (derived_candidate_ids if disposition in {
                model.StructuralDisposition.SPLIT,
                model.StructuralDisposition.FOLDED,
            } else (
                derived_candidate_ids
                if lineage_preserved and derived_candidate_ids
                else ((subject.subject_id,) if lineage_preserved else ())
            ))
        )
        if disposition is not None:
            exact_origins = derived_origins
            if not exact_origins and lineage_binding is not None:
                candidate_origins = set(lineage_binding.native_instruction_eas)
                if candidate_origins == set(source_binding.native_instruction_eas):
                    exact_origins = tuple(sorted(candidate_origins))
            lineage = model.StructuralLineageEvidencePayload(
                subject.subject_id, lineage_candidate_ids, disposition,
                exact_origins, claim.claim_id if claim is not None else None, source_group,
            )
            evidence.append(_evidence_factory(model.AuthorityEvidence, model.AuthorityEvidenceKind.STRUCTURAL_LINEAGE, subject, phase, lineage))
        if subject.role not in topology_roles:
            continue
        expected = tuple(item for item in source_topology if subject.subject_id in (item.source_subject_id, item.target_subject_id))
        observed = tuple(item for item in candidate_topology if subject.subject_id in (item.source_subject_id, item.target_subject_id))
        topology = model.TopologyEvidencePayload(
            subject.subject_id,
            tuple(sorted(item.source_subject_id for item in expected if item.target_subject_id == subject.subject_id)),
            tuple(sorted(item.target_subject_id for item in expected if item.source_subject_id == subject.subject_id)),
            has_reciprocal_edges(expected), _authority_id_digest(expected), _authority_id_digest(observed), expected, observed,
        )
        evidence.append(_evidence_factory(model.AuthorityEvidence, model.AuthorityEvidenceKind.TOPOLOGY, subject, phase, topology))

    source_subject_ids = {subject.subject_id for subject in source_subjects}
    for helper in candidate_subjects:
        if (
            helper.role is not model.SemanticSubjectRole.PLANNED_HELPER
            or helper.subject_id in source_subject_ids
        ):
            continue
        observed = tuple(
            item for item in candidate_topology
            if helper.subject_id in (item.source_subject_id, item.target_subject_id)
        )
        evidence.append(_evidence_factory(
            model.AuthorityEvidence,
            model.AuthorityEvidenceKind.TOPOLOGY,
            helper,
            phase,
            model.TopologyEvidencePayload(
                helper.subject_id,
                (),
                (),
                has_reciprocal_edges(observed),
                _authority_id_digest(()),
                _authority_id_digest(observed),
                (), observed,
            ),
        ))

    for subject in source_subjects:
        if subject.role is not model.SemanticSubjectRole.EFFECT_SITE or type(subject.locator) is not model.EffectSubjectLocator:
            continue
        locator = subject.locator
        effect = next((item for item in source.effects
                       if item.owner_ref == locator.owner_ref
                       and item.owner_anchor_ea == locator.owner_anchor_ea
                       and item.instruction_ea == locator.instruction_ea
                       and item.effect_kind is locator.effect_kind), None)
        if effect is None or effect.owner_serial not in source.reachable_serials:
            continue
        classification = classifications.get(subject.subject_id)
        if classification is None:
            continue
        metadata_claim = classification.claim
        exact_metadata_claim = (
            metadata_claim
            if type(metadata_claim) is model.ExactInfeasibleEffectClaim
            else None
        )
        payload = model.EffectSiteEvidencePayload(
            subject.subject_id, effect.effect_kind, effect.instruction_ea, effect.opcode,
            effect.width,
            exact_metadata_claim.state_identity if exact_metadata_claim is not None else None,
            exact_metadata_claim.normalized_state if exact_metadata_claim is not None else None,
            exact_metadata_claim.consensus.mode if exact_metadata_claim is not None else model.ProviderConsensusMode.NOT_APPLICABLE,
            exact_metadata_claim.consensus.provider_ids if exact_metadata_claim is not None else (),
            classification.preserved,
        )
        evidence.append(_evidence_factory(model.AuthorityEvidence, model.AuthorityEvidenceKind.EFFECT_SITE, subject, phase, payload))

    for subject in source_subjects:
        if subject.kind is not model.SemanticSubjectKind.ROUTE:
            continue
        locator = subject.locator
        destinations = tuple(
            next(item.subject_id for item in source_subjects
                 if item.role is model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION
                 and item.block_ref == ref and item.anchor_ea == anchor)
            for ref, anchor in zip(locator.destination_refs, locator.destination_anchor_eas)
        )
        route_payload = model.SemanticRouteEvidencePayload(
            subject.subject_id, (locator.proof_id,), locator.atomic_group_id,
            next((item.subject_id for item in source_subjects
                  if item.role is model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE
                  and item.block_ref == locator.source_ref and item.anchor_ea == locator.source_anchor_ea), subject.subject_id),
            destinations, bool(assessment is not None and assessment.accepted and locator.proof_id in assessment.proof_ids),
        )
        evidence.append(_evidence_factory(model.AuthorityEvidence, model.AuthorityEvidenceKind.SEMANTIC_ROUTE, subject, phase, route_payload))

    corridor = next((item for item in source_subjects if item.role is model.SemanticSubjectRole.DISPATCHER_CORRIDOR), None)
    if corridor is not None:
        members = tuple(item.subject_id for item in source_subjects if item.role is model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE)
        covered = tuple(item for item in members if candidate_bindings.get(item) is not None and candidate_bindings[item].status is model.SubjectBindingStatus.UNIQUE)
        evidence.append(_evidence_factory(model.AuthorityEvidence, model.AuthorityEvidenceKind.CORRIDOR_COVERAGE, corridor, phase, model.CorridorCoverageEvidencePayload(corridor.subject_id, members, covered, tuple(item for item in members if item not in covered))))

    generic_gates: list[model.GenericCfgGateResult] = []
    facts = inputs.generic_gate_facts
    if facts is not None:
        entry = next((item for item in source_subjects if item.role is model.SemanticSubjectRole.SOURCE_ENTRY), None)
        entry_ids = () if entry is None else (entry.subject_id,)
        generic_gates.append(model.GenericCfgGateResult(model.GenericCfgGateKind.ENTRY_REACHABILITY, facts.entry.passed, entry_ids if facts.entry.passed else (), () if facts.entry.passed else entry_ids, facts.entry.reason or "entry_reachability"))
        effect_ids = tuple(item.subject_id for item in source_subjects if item.role is model.SemanticSubjectRole.EFFECT_SITE and type(item.locator) is model.EffectSubjectLocator and item.locator.effect_kind in {model.EffectSiteKind.CALL, model.EffectSiteKind.STORE})
        generic_gates.append(model.GenericCfgGateResult(model.GenericCfgGateKind.EFFECTFUL_REACHABILITY, facts.effectful_effective.passed, effect_ids if facts.effectful_effective.passed else (), () if facts.effectful_effective.passed else effect_ids, facts.effectful_effective.reason or "effectful_reachability"))
        terminal_ids = tuple(item.subject_id for item in source_subjects if item.role is model.SemanticSubjectRole.TERMINAL_SITE and type(item.locator) is model.TerminalSubjectLocator and item.locator.terminal_kind in {model.TerminalKind.RETURN, model.TerminalKind.STOP})
        generic_gates.append(model.GenericCfgGateResult(model.GenericCfgGateKind.TERMINAL_REACHABILITY, facts.terminal.passed, terminal_ids if facts.terminal.passed else (), () if facts.terminal.passed else terminal_ids, facts.terminal.reason or "terminal_reachability"))
    # A missing generic-gate bundle is an absence of evidence.  It must not
    # be converted into synthetic passing rows: inventory-derived reachability
    # and presence evidence remain independently authoritative where defined.
    patch_evidence_rows = []
    for item in inputs.patch_step_facts:
        if item.plan_id != inputs.proposal.plan_id:
            raise ValueError("patch-step evidence belongs to a different plan")
        if item.step_type not in _SUPPORTED_PATCH_STEP_TYPES:
            raise ValueError("patch-step evidence has an unsupported step kind")
        if (
            item.step_type == "PatchRedirectBranch"
            and type(item.owner_ref) is not PlanBlockRef
        ):
            # Legacy redirect branches retain Task 11's receipt semantics;
            # their closed fact is still hashed and replayed, but they do not
            # acquire a new helper-obligation row without a planned owner.
            continue
        patch_subjects = _patch_owner_subjects(item, candidate_subjects)
        if not patch_subjects:
            raise ValueError("patch-step fact owner is not an inventoried planned helper")
        patch_evidence_rows.extend(
            _evidence_factory(
                model.AuthorityEvidence,
                model.AuthorityEvidenceKind.PATCH_STEP,
                patch_subject,
                phase,
                item,
            )
            for patch_subject in patch_subjects
        )
    patch_evidence = tuple(patch_evidence_rows)
    return tuple(sorted(evidence, key=lambda item: item.evidence_id)), patch_evidence, tuple(generic_gates), classifications


def build_semantic_case(
    *, authority_id: str, phase: model.UnflattenAuthorityPhase,
    inputs: model.DerivedUnflattenPreparationInputs,
) -> model.SemanticSafetyCase:
    if type(inputs) is not model.DerivedUnflattenPreparationInputs:
        raise TypeError("inputs must be DerivedUnflattenPreparationInputs")
    model.DerivedUnflattenPreparationInputs.__post_init__(inputs)
    model._id(authority_id, "authority_id")
    if type(phase) is not model.UnflattenAuthorityPhase:
        raise TypeError("phase must be UnflattenAuthorityPhase")
    proposal = inputs.proposal
    source_inventory = inputs.source_inventory
    candidate_inventory = inputs.candidate_inventory
    source_subjects = tuple(sorted(source_inventory.subjects, key=lambda item: item.subject_id))
    candidate_subjects = tuple(sorted(candidate_inventory.subjects, key=lambda item: item.subject_id))
    source_bindings = tuple(sorted(source_inventory.bindings, key=lambda item: item.subject.subject_id))
    candidate_bindings = tuple(sorted(candidate_inventory.bindings, key=lambda item: item.subject.subject_id))
    source_fingerprint = source_inventory.graph_fingerprint
    candidate_fingerprint = candidate_inventory.graph_fingerprint
    source_generation = source_inventory.generation
    candidate_generation = candidate_inventory.generation
    lineage_evidence, patch_step_evidence, generic_gates, classifications = _evaluator_fact_evidence(
        inputs, phase,
    )
    proposal_claim_ids = {claim.claim_id for claim in proposal.claims}
    input_claim_ids = {claim.claim_id for claim in inputs.claims}
    if not proposal_claim_ids <= input_claim_ids or any(
        claim.claim_id not in proposal_claim_ids and type(claim) is not model.LocalAliasEffectScalarizationClaim
        for claim in inputs.claims
    ):
        raise ValueError("derived claims must preserve producer claims and closed transaction-derived claims")
    if source_generation != proposal.source_identity_catalog.generation:
        raise ValueError("source generation does not match proposal")
    if not source_subjects:
        raise ValueError("authority requires a non-empty source inventory")
    _validate_receipt(inputs)
    source_ids = {subject.subject_id for subject in source_subjects}
    candidate_ids = {subject.subject_id for subject in candidate_subjects}
    known_input_subjects = {
        subject.subject_id: subject
        for subject in (*source_subjects, *candidate_subjects)
    }
    alias_owners = {
        claim.owner_subject.subject_id
        for claim in inputs.claims
        if type(claim) is model.LocalAliasEffectScalarizationClaim
    }
    alias_claims = tuple(
        claim for claim in inputs.claims
        if type(claim) is model.LocalAliasEffectScalarizationClaim
    )
    allowed_relation_dimensions = {
        model.SafetyDimension.ROUTE_EQUIVALENCE,
        model.SafetyDimension.TOPOLOGY_INTEGRITY,
        model.SafetyDimension.HANDLER_REACHABILITY,
        model.SafetyDimension.TERMINAL_REACHABILITY,
        model.SafetyDimension.STRUCTURAL_ACCOUNTING,
    }
    for relation in inputs.conditional_relations:
        if relation.source_subject_id not in source_ids:
            raise ValueError("conditional relation source is outside source inventory")
        if relation.target_subject_id not in source_ids | {
            item.subject_id for item in candidate_subjects
            if item.role is model.SemanticSubjectRole.PLANNED_HELPER
        }:
            raise ValueError("conditional relation target is outside case inventory")
        if relation.dimension is model.SafetyDimension.EFFECT_PRESERVATION:
            target = known_input_subjects.get(relation.target_subject_id)
            matching_claims = tuple(
                claim for claim in alias_claims
                if claim.owner_subject.subject_id == relation.source_subject_id
                and claim.host_ea == target.locator.instruction_ea
            ) if target is not None and type(target.locator) is model.EffectSubjectLocator else ()
            if (
                relation.source_subject_id not in alias_owners
                or len(matching_claims) != 1
                or target is None
                or target.role is not model.SemanticSubjectRole.EFFECT_SITE
                or type(target.locator) is not model.EffectSubjectLocator
                or target.locator.effect_kind is not model.EffectSiteKind.STORE
                or target.locator.owner_ref != matching_claims[0].owner_subject.block_ref
                or target.locator.owner_anchor_ea != matching_claims[0].owner_subject.anchor_ea
            ):
                raise ValueError("effect conditional relation must target an exact STORE alias effect")
        elif relation.dimension not in allowed_relation_dimensions:
            raise ValueError("conditional relation has an unsupported dimension")
    if any(binding.subject.subject_id not in source_ids for binding in source_bindings):
        raise ValueError("source binding is outside source inventory")
    if any(binding.subject.subject_id not in source_ids | candidate_ids for binding in candidate_bindings):
        raise ValueError("candidate binding is outside candidate inventory")
    if {binding.subject.subject_id for binding in source_bindings} != source_ids:
        raise ValueError("source binding inventory is incomplete")
    if {binding.subject.subject_id for binding in candidate_bindings} != source_ids | candidate_ids:
        raise ValueError("candidate binding inventory is incomplete; include MISSING rows")
    claim_subject_ids = {
        subject.subject_id for claim in inputs.claims for subject in _claim_subjects(claim)
    }
    if not claim_subject_ids <= source_ids:
        raise ValueError("claim subject is outside the source inventory")
    source_entries = tuple(
        subject for subject in source_subjects
        if subject.role is model.SemanticSubjectRole.SOURCE_ENTRY
    )
    if len(source_entries) != 1:
        raise ValueError("source inventory must contain exactly one SOURCE_ENTRY")
    source_entry = source_entries[0]
    if (
        source_entry.block_ref != proposal.plan_inputs.source_entry_ref
        or source_entry.anchor_ea != next(
            block.anchor_ea
            for block in proposal.source_identity_catalog.blocks
            if block.block_ref == proposal.plan_inputs.source_entry_ref
        )
    ):
        raise ValueError("source entry does not match proposal plan inputs")
    catalog_by_ref = {
        block.block_ref: block for block in proposal.source_identity_catalog.blocks
    }
    def _block_subject(role: model.SemanticSubjectRole, ref: object) -> model.SemanticSubjectRef | None:
        witness = catalog_by_ref.get(ref)
        if witness is None:
            return None
        return next(
            (
                subject for subject in source_subjects
                if subject.role is role
                and subject.block_ref == ref
                and subject.anchor_ea == witness.anchor_ea
            ),
            None,
        )
    if _block_subject(model.SemanticSubjectRole.DISPATCHER_ENTRY, proposal.plan_inputs.dispatcher_entry_ref) is None:
        raise ValueError("source inventory is missing the dispatcher entry")
    if any(
        _block_subject(model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE, ref) is None
        for ref in proposal.plan_inputs.dispatcher_member_refs
    ):
        raise ValueError("source inventory is missing a dispatcher member")
    if any(
        not any(
            subject.role is model.SemanticSubjectRole.AUTHORITATIVE_HANDLER
            and subject.block_ref == handler.block_ref
            and subject.anchor_ea == handler.anchor_ea
            for subject in source_subjects
        )
        for handler in proposal.plan_inputs.authoritative_handlers
    ):
        raise ValueError("source inventory is missing an authoritative handler")
    actual_source_entries = {
        (subject.block_ref, subject.anchor_ea)
        for subject in source_subjects
        if subject.role is model.SemanticSubjectRole.SOURCE_ENTRY
    }
    actual_dispatcher_entries = {
        (subject.block_ref, subject.anchor_ea)
        for subject in source_subjects
        if subject.role is model.SemanticSubjectRole.DISPATCHER_ENTRY
    }
    actual_members = {
        (subject.block_ref, subject.anchor_ea)
        for subject in source_subjects
        if subject.role is model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE
    }
    actual_handlers = {
        (subject.block_ref, subject.anchor_ea)
        for subject in source_subjects
        if subject.role is model.SemanticSubjectRole.AUTHORITATIVE_HANDLER
    }
    expected_source_entries = {
        (proposal.plan_inputs.source_entry_ref,
         catalog_by_ref[proposal.plan_inputs.source_entry_ref].anchor_ea)
    }
    expected_dispatcher_entries = {
        (proposal.plan_inputs.dispatcher_entry_ref,
         catalog_by_ref[proposal.plan_inputs.dispatcher_entry_ref].anchor_ea)
    }
    expected_members = {
        (ref, catalog_by_ref[ref].anchor_ea)
        for ref in proposal.plan_inputs.dispatcher_member_refs
    }
    expected_handlers = {
        (handler.block_ref, handler.anchor_ea)
        for handler in proposal.plan_inputs.authoritative_handlers
    }
    if (
        actual_source_entries != expected_source_entries
        or actual_dispatcher_entries != expected_dispatcher_entries
        or actual_members != expected_members
        or actual_handlers != expected_handlers
    ):
        raise ValueError("source plan-input role inventory is not exact")
    for source in source_subjects:
        if source.block_ref is not None:
            witness = catalog_by_ref.get(source.block_ref)
            if witness is None or witness.anchor_ea != source.anchor_ea:
                raise ValueError("source subject is outside the proposal source catalog")
        elif source.role is model.SemanticSubjectRole.NON_STATE_VALUE_FLOW:
            if any(ref not in catalog_by_ref for ref in source.locator.redirect_owner_refs):
                raise ValueError("value-flow owner is outside the proposal source catalog")
    use_def = proposal.use_def_witness
    value_flows = tuple(
        subject for subject in source_subjects
        if subject.role is model.SemanticSubjectRole.NON_STATE_VALUE_FLOW
    )
    expected_value_flow = model.ValueFlowSubjectLocator(
        use_def.fragment_id, use_def.state_identity, use_def.redirect_owner_refs,
    )
    if tuple(use_def.redirect_owner_refs) != tuple(
        proposal.plan_inputs.dispatcher_member_refs
    ):
        raise ValueError("use-def owners must be exact dispatcher member refs")
    if (
        not expected_value_flow.redirect_owner_refs
        or len(set(expected_value_flow.redirect_owner_refs))
        != len(expected_value_flow.redirect_owner_refs)
    ):
        raise ValueError("use-def value-flow owner refs must be nonempty and unique")
    if (
        len(set(use_def.violation_ids)) != len(use_def.violation_ids)
        or len(use_def.violation_ids) != use_def.actionable_non_state_severance_count
    ):
        raise ValueError("use-def violation IDs must be unique and total")
    if len(value_flows) != 1 or value_flows[0].locator != expected_value_flow:
        raise ValueError("source inventory must contain the exact use-def value-flow subject")
    value_flow = value_flows[0]
    subjects = tuple(sorted({*source_subjects, *(subject for subject in candidate_subjects if subject.role is model.SemanticSubjectRole.PLANNED_HELPER)}, key=_subject_key))
    phase_bindings = (
        source_bindings
        if phase is model.UnflattenAuthorityPhase.PRODUCER_FORECAST
        else candidate_bindings
    )
    required = _dimensions(
        subjects, inputs.claims, phase_bindings,
        candidate_fingerprint=(
            source_fingerprint
            if phase is model.UnflattenAuthorityPhase.PRODUCER_FORECAST
            else candidate_fingerprint
        ),
        candidate_generation=(
            source_generation
            if phase is model.UnflattenAuthorityPhase.PRODUCER_FORECAST
            else candidate_generation
        ),
        retired_topology_satisfied_ids=frozenset(
            member.subject_id
            for claim in inputs.claims
            if type(claim) is model.RetiredDispatcherInfrastructureClaim
            and {
                item.payload.source_subject_id for item in lineage_evidence
                if type(item.payload) is model.StructuralLineageEvidencePayload
                and item.payload.claim_id == claim.claim_id
                and item.payload.disposition is model.StructuralDisposition.AUTHORIZED_RETIREMENT
            } == {member.subject_id for member in claim.member_subjects}
            and any(
                type(item.payload) is model.CorridorCoverageEvidencePayload
                and item.payload.corridor_subject_id == claim.corridor_subject.subject_id
                and set(item.payload.member_subject_ids) == {member.subject_id for member in claim.member_subjects}
                and set(item.payload.covered_subject_ids) == {member.subject_id for member in claim.member_subjects}
                and not item.payload.residual_subject_ids
                for item in lineage_evidence
            )
            for member in claim.member_subjects
        ),
        conditional_relations=inputs.conditional_relations,
    )
    justifications: list[model.AuthorityJustification] = []
    candidate_bindings = {binding.subject.subject_id: binding for binding in candidate_bindings}
    source_bindings = {binding.subject.subject_id: binding for binding in source_bindings}
    candidate_bindings_tuple = tuple(candidate_inventory.bindings)
    bindings = tuple(sorted(
        candidate_bindings_tuple if phase is not model.UnflattenAuthorityPhase.PRODUCER_FORECAST else tuple(source_inventory.bindings),
        key=lambda item: item.subject.subject_id,
    ))
    current_bindings = candidate_bindings if phase is not model.UnflattenAuthorityPhase.PRODUCER_FORECAST else source_bindings
    binding_evidence: dict[str, str] = {}
    evidence_rows: list[model.AuthorityEvidence] = []
    case_subject_ids = {
        subject.subject_id for subject in source_subjects
    } | {
        subject.subject_id for subject in candidate_subjects
        if subject.role is model.SemanticSubjectRole.PLANNED_HELPER
    }
    for binding in (candidate_bindings_tuple if phase is not model.UnflattenAuthorityPhase.PRODUCER_FORECAST else tuple(source_inventory.bindings)):
        if binding.subject.subject_id not in case_subject_ids:
            continue
        payload = model.PhaseBindingEvidencePayload(binding)
        evidence_item = _evidence_factory(model.AuthorityEvidence, model.AuthorityEvidenceKind.PHASE_BINDING, binding.subject, phase, payload)
        evidence_rows.append(evidence_item)
        binding_evidence[binding.subject.subject_id] = evidence_item.evidence_id
    audit_payload = model.UseDefAuditEvidencePayload(
        use_def.fragment_id, use_def.state_identity, use_def.executed,
        use_def.fragment_atomic, use_def.actionable_non_state_severance_count,
        use_def.violation_ids,
    )
    audit_subject = value_flow
    audit_item = _evidence_factory(
        model.AuthorityEvidence, model.AuthorityEvidenceKind.USE_DEF_AUDIT,
        audit_subject, phase, audit_payload,
    )
    evidence_rows.append(audit_item)
    authorized_loss_subject_ids = {
        subject_id for subject_id, classification in classifications.items()
        if classification.authorized_loss
    }
    supplied_lineage_sources = {
        source_id
        for item in (*lineage_evidence, *patch_step_evidence)
        if type(item.payload) is model.StructuralLineageEvidencePayload
        for source_id in item.payload.source_subject_ids
    }
    lineage_rows = tuple(
        item for item in (*lineage_evidence, *patch_step_evidence)
        if type(item.payload) is model.StructuralLineageEvidencePayload
    )
    lineage_covered_sources = tuple(
        source_id for item in lineage_rows for source_id in item.payload.source_subject_ids
    )
    if len(set(lineage_covered_sources)) != len(lineage_covered_sources):
        raise ValueError("each source subject requires exactly one lineage classification")
    for source in source_subjects:
        if source.subject_id in supplied_lineage_sources:
            continue
        if source.subject_id in authorized_loss_subject_ids:
            continue
        missing_lineage = model.StructuralLineageEvidencePayload(
            source.subject_id, (), model.StructuralDisposition.UNACCOUNTED_LOSS, (), None,
        )
        evidence_rows.append(_evidence_factory(
            model.AuthorityEvidence, model.AuthorityEvidenceKind.STRUCTURAL_LINEAGE,
            source, phase, missing_lineage,
        ))
    for gate in generic_gates:
            expected_role = {
            model.GenericCfgGateKind.ENTRY_REACHABILITY: model.SemanticSubjectRole.SOURCE_ENTRY,
            model.GenericCfgGateKind.EFFECTFUL_REACHABILITY: model.SemanticSubjectRole.EFFECT_SITE,
            model.GenericCfgGateKind.TERMINAL_REACHABILITY: model.SemanticSubjectRole.TERMINAL_SITE,
            }[gate.gate]
            scoped_subjects = tuple(
                subject for subject in subjects if subject.role is expected_role
            )
            if gate.gate is model.GenericCfgGateKind.EFFECTFUL_REACHABILITY:
                scoped_subjects = tuple(
                    subject for subject in scoped_subjects
                    if type(subject.locator) is model.EffectSubjectLocator
                    and subject.locator.effect_kind in {
                        model.EffectSiteKind.CALL,
                        model.EffectSiteKind.STORE,
                    }
                )
            elif gate.gate is model.GenericCfgGateKind.TERMINAL_REACHABILITY:
                scoped_subjects = tuple(
                    subject for subject in scoped_subjects
                    if type(subject.locator) is model.TerminalSubjectLocator
                    and subject.locator.terminal_kind in {
                        model.TerminalKind.RETURN,
                        model.TerminalKind.STOP,
                    }
                )
            scoped_ids = {subject.subject_id for subject in scoped_subjects}
            affected_ids = set(gate.supported_subject_ids) | set(gate.refuted_subject_ids)
            if gate.gate is model.GenericCfgGateKind.ENTRY_REACHABILITY and len(scoped_ids) != 1:
                raise ValueError("entry gate requires exactly one SOURCE_ENTRY subject")
            if affected_ids != scoped_ids:
                raise ValueError("generic gate scope is incomplete or contains unrelated subjects")
            gate_targets = tuple((item, True) for item in gate.supported_subject_ids) + tuple(
                (item, False) for item in gate.refuted_subject_ids
            )
            for affected, passed in gate_targets:
                subject = next((item for item in subjects if item.subject_id == affected), None)
                if subject is None:
                    raise ValueError("generic gate targets a foreign subject")
                if subject.role is not expected_role:
                    raise ValueError("generic gate target has an incompatible subject role")
                payload = model.GenericCfgGateEvidencePayload(gate.gate, passed, (affected,), gate.reason_code)
                evidence_item = _evidence_factory(model.AuthorityEvidence, model.AuthorityEvidenceKind.GENERIC_CFG_GATE, subject, phase, payload)
                evidence_rows.append(evidence_item)
    for key in required:
        if key.dimension is not model.SafetyDimension.IDENTITY_BINDING:
            continue
        subject_id_ = key.subject.subject_id
        binding = current_bindings.get(subject_id_)
        expected_fingerprint = source_fingerprint if phase is model.UnflattenAuthorityPhase.PRODUCER_FORECAST else candidate_fingerprint
        expected_generation = source_generation if phase is model.UnflattenAuthorityPhase.PRODUCER_FORECAST else candidate_generation
        supports = _identity_support(
            key.subject,
            source_subjects if phase is model.UnflattenAuthorityPhase.PRODUCER_FORECAST else candidate_subjects,
            bindings, phase, expected_fingerprint, expected_generation,
            allow_source_indexed_missing=(
                phase is not model.UnflattenAuthorityPhase.PRODUCER_FORECAST
                and subject_id_ in {
                    item.subject_id for item in source_subjects
                }
            ),
        )
        if type(key.subject.locator) is model.ValueFlowSubjectLocator:
            # Value-flow identity is the conjunction of the exact owner
            # bindings.  The aggregate has no live block of its own and must
            # never be authorized by its synthetic MISSING binding row.
            premises = tuple(
                binding_evidence[owner.subject_id]
                for owner in (
                    binding.subject
                    for binding in sorted(
                        candidate_bindings_tuple
                        if phase is not model.UnflattenAuthorityPhase.PRODUCER_FORECAST
                        else tuple(source_inventory.bindings),
                        key=lambda item: item.subject.subject_id,
                    )
                    if binding.subject.block_ref in key.subject.locator.redirect_owner_refs
                    and binding.subject.role is model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE
                    and binding.subject.subject_id in binding_evidence
                )
            )
        else:
            premises = (binding_evidence[subject_id_],) if subject_id_ in binding_evidence else ()
        _add_justification(
            justifications, key,
            model.UnflattenJustificationRule.UNIQUE_PHASE_BINDING if supports else model.UnflattenJustificationRule.NONUNIQUE_PHASE_BINDING,
            model.EvidencePolarity.SUPPORTS if supports else model.EvidencePolarity.REFUTES, phase,
            premises,
        )
    evidence = tuple(sorted((*evidence_rows, *lineage_evidence, *patch_step_evidence), key=lambda item: item.evidence_id))
    known_subjects = {subject.subject_id: subject for subject in subjects}
    known_subject_ids = set(known_subjects)
    topology_rows = {
        item.payload.subject_id: item.payload
        for item in evidence
        if type(item.payload) is model.TopologyEvidencePayload
    }
    topology_items = tuple(
        item for item in evidence if type(item.payload) is model.TopologyEvidencePayload
    )
    if len(topology_rows) != len(topology_items):
        raise ValueError("topology evidence must contain one row per subject")
    candidate_drift_ids: set[str] = set()
    # A changed relation set is a shared edge-owner drift: both endpoints
    # lose topology authority, even when the peer row happens to retain its
    # own reverse relation.
    for item in topology_items:
        payload = item.payload
        if set(payload.candidate_edge_relations) != set(payload.expected_edge_relations):
            candidate_drift_ids.update(
                relation.source_subject_id
                for relation in (*payload.expected_edge_relations, *payload.candidate_edge_relations)
            )
            candidate_drift_ids.update(
                relation.target_subject_id
                for relation in (*payload.expected_edge_relations, *payload.candidate_edge_relations)
            )
    for item in topology_items:
        payload = item.payload
        for relation in payload.candidate_edge_relations:
            peer = topology_rows.get(relation.target_subject_id)
            peer_relations = () if peer is None else peer.candidate_edge_relations
            if not any(
                reverse.source_subject_id == relation.target_subject_id
                and reverse.target_subject_id == relation.source_subject_id
                and reverse.role is relation.role
                and reverse.native_edge_anchor_ea == relation.native_edge_anchor_ea
                for reverse in peer_relations
            ):
                candidate_drift_ids.update(
                    (relation.source_subject_id, relation.target_subject_id)
                )
    for item in evidence:
        if item.phase is not phase or item.subject.subject_id not in known_subject_ids:
            raise ValueError("evidence phase or subject is outside the case")
        payload = item.payload
        header_target: str | None = None
        if type(payload) is model.PhaseBindingEvidencePayload:
            header_target = payload.binding.subject.subject_id
            if (
                payload.binding.phase is not item.phase
                or payload.binding.subject.subject_id != item.subject.subject_id
            ):
                raise ValueError("phase-binding evidence header does not match payload")
        elif type(payload) is model.TopologyEvidencePayload:
            header_target = payload.subject_id
            if any(value not in known_subject_ids for value in (*payload.predecessor_subject_ids, *payload.successor_subject_ids)):
                raise ValueError("topology evidence references a foreign subject")
            if (
                payload.expected_shape_digest != _authority_id_digest(payload.expected_edge_relations)
                or payload.candidate_shape_digest != _authority_id_digest(payload.candidate_edge_relations)
            ):
                raise ValueError("topology digest does not match canonical edge relations")
            expected_relations = set(payload.expected_edge_relations)
            candidate_relations = set(payload.candidate_edge_relations)
            if candidate_relations != expected_relations:
                candidate_drift_ids.update(
                    relation.source_subject_id
                    for relation in (*payload.expected_edge_relations, *payload.candidate_edge_relations)
                )
                candidate_drift_ids.update(
                    relation.target_subject_id
                    for relation in (*payload.expected_edge_relations, *payload.candidate_edge_relations)
                )
            expected_predecessors = {
                relation.source_subject_id for relation in payload.expected_edge_relations
                if relation.target_subject_id == payload.subject_id
            }
            expected_successors = {
                relation.target_subject_id for relation in payload.expected_edge_relations
                if relation.source_subject_id == payload.subject_id
            }
            declared_predecessors = set(payload.predecessor_subject_ids)
            declared_successors = set(payload.successor_subject_ids)
            if (
                not expected_relations
                and not candidate_relations
                and (declared_predecessors or declared_successors)
            ):
                raise ValueError("topology peer lists require edge relations")
            if (
                declared_predecessors != expected_predecessors
                or declared_successors != expected_successors
            ):
                raise ValueError("topology edge relation scope does not match its peer lists")
            if any(
                relation.source_subject_id not in known_subject_ids
                or relation.target_subject_id not in known_subject_ids
                or payload.subject_id not in {
                    relation.source_subject_id, relation.target_subject_id,
                }
                for relation in payload.candidate_edge_relations
            ):
                raise ValueError("candidate topology relation references a foreign or non-incident subject")
            for relation in payload.candidate_edge_relations:
                peer = topology_rows.get(relation.target_subject_id)
                peer_relations = () if peer is None else peer.candidate_edge_relations
                if not any(
                    reverse.source_subject_id == relation.target_subject_id
                    and reverse.target_subject_id == relation.source_subject_id
                    and reverse.role is relation.role
                    and reverse.native_edge_anchor_ea == relation.native_edge_anchor_ea
                    for reverse in peer_relations
                ):
                    candidate_drift_ids.update(
                        (relation.source_subject_id, relation.target_subject_id)
                    )
            if expected_relations or candidate_relations:
                if not payload.reciprocal_edges:
                    raise ValueError("directed topology evidence must declare reciprocal edges")
                if expected_relations == candidate_relations:
                    for relation in payload.expected_edge_relations:
                        peer = topology_rows.get(
                            relation.target_subject_id
                            if relation.source_subject_id == payload.subject_id
                            else relation.source_subject_id
                        )
                        peer_relations = () if peer is None else peer.expected_edge_relations
                        if peer is None or not any(
                            reverse.source_subject_id == relation.target_subject_id
                            and reverse.target_subject_id == relation.source_subject_id
                            and reverse.role is relation.role
                            and reverse.native_edge_anchor_ea == relation.native_edge_anchor_ea
                            for reverse in peer_relations
                        ):
                            raise ValueError("topology evidence lacks an exact reciprocal edge relation")
        elif type(payload) is model.StructuralLineageEvidencePayload:
            header_target = payload.source_subject_id
            known = {subject.subject_id for subject in subjects}
            if any(item not in known for item in payload.candidate_subject_ids):
                raise ValueError("lineage evidence targets a foreign candidate")
        elif type(payload) is model.SemanticRouteEvidencePayload:
            header_target = payload.route_subject_id
            proposal_proof_ids = tuple(sorted(proof.proof_id for proof in proposal.route_evidence.route_proofs))
            if payload.proof_ids != proposal_proof_ids or payload.atomic_group_id != proposal.route_evidence.atomic_group_id:
                raise ValueError("route evidence is outside the proposal proof scope")
            route_claim = next(
                (
                    claim for claim in inputs.claims
                    if type(claim) is model.EquivalentSemanticRouteClaim
                    and payload.route_subject_id == claim.retired_route_subject.subject_id
                ),
                None,
            )
            exact_effect_claim = next(
                (
                    claim for claim in inputs.claims
                    if type(claim) is model.ExactInfeasibleEffectClaim
                    and payload.proof_ids == tuple(sorted(claim.route_proof_ids))
                    and payload.source_subject_id == claim.predicate_subject.subject_id
                    and claim.selected_target_subject.subject_id in payload.destination_subject_ids
                ),
                None,
            )
            if route_claim is None and exact_effect_claim is None:
                raise ValueError("route evidence target is outside the claimed route scope")
            if route_claim is not None and (
                payload.proof_ids != route_claim.route_proof_ids
                or payload.atomic_group_id != route_claim.atomic_group_id
                or payload.source_subject_id != route_claim.source_subject.subject_id
                or payload.destination_subject_ids != tuple(
                    _route_destination_ids(route_claim.retired_route_subject, subjects)
                )
            ):
                raise ValueError("route evidence target is outside the claimed route scope")
            if exact_effect_claim is not None:
                route_subject = known_subjects.get(payload.route_subject_id)
                if route_subject is None or type(route_subject.locator) is not model.RouteSubjectLocator:
                    raise ValueError("route evidence target is not a derived route subject")
                canonical_destinations = tuple(
                    next(
                        subject.subject_id
                        for subject in subjects
                        if subject.role is model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION
                        and subject.block_ref == ref
                        and subject.anchor_ea == anchor
                    )
                    for ref, anchor in zip(
                        route_subject.locator.destination_refs,
                        route_subject.locator.destination_anchor_eas,
                    )
                )
                if payload.destination_subject_ids != canonical_destinations:
                    raise ValueError("exact-effect route evidence must cover the canonical destinations exactly")
            if any(target not in known_subject_ids for target in payload.destination_subject_ids):
                raise ValueError("route evidence references a foreign destination")
            route_subject = known_subjects.get(payload.route_subject_id)
            if route_subject is None or type(route_subject.locator) is not model.RouteSubjectLocator:
                raise ValueError("route evidence target is not a derived route subject")
            locator = route_subject.locator
            if (
                locator.proof_id not in payload.proof_ids
                or locator.atomic_group_id != payload.atomic_group_id
                or locator.source_ref != known_subjects[payload.source_subject_id].block_ref
                or tuple(locator.destination_refs) != tuple(
                    known_subjects[target].block_ref
                    for target in payload.destination_subject_ids
                )
                or tuple(locator.destination_anchor_eas) != tuple(
                    known_subjects[target].anchor_ea
                    for target in payload.destination_subject_ids
                )
            ):
                raise ValueError("route evidence locator does not match its payload")
        elif type(payload) is model.EffectSiteEvidencePayload:
            header_target = payload.effect_subject_id
            effect_subject = known_subjects.get(payload.effect_subject_id)
            if (
                effect_subject is None
                or type(effect_subject.locator) is not model.EffectSubjectLocator
                or effect_subject.locator.instruction_ea != payload.instruction_ea
                or effect_subject.locator.effect_kind is not payload.effect_kind
            ):
                raise ValueError("effect evidence locator does not match its payload")
        elif type(payload) is model.ReachabilityEvidencePayload:
            header_target = payload.target_subject_id
            if payload.root_subject_id not in known_subject_ids or any(
                value not in known_subject_ids for value in payload.path_subject_ids
            ):
                raise ValueError("reachability evidence references a foreign subject")
        elif type(payload) is model.UseDefAuditEvidencePayload:
            header_target = item.subject.subject_id
            if (
                item.subject.role is not model.SemanticSubjectRole.NON_STATE_VALUE_FLOW
                or type(item.subject.locator) is not model.ValueFlowSubjectLocator
                or item.subject.locator.fragment_id != payload.fragment_id
                or item.subject.locator.state_identity != payload.state_identity
            ):
                raise ValueError("use-def evidence target does not match its payload")
        elif type(payload) is model.CorridorCoverageEvidencePayload:
            header_target = payload.corridor_subject_id
            corridor_subject = known_subjects.get(payload.corridor_subject_id)
            if corridor_subject is None or type(corridor_subject.locator) is not model.CorridorSubjectLocator:
                raise ValueError("corridor evidence target is not a derived corridor")
            member_pairs = set(zip(
                corridor_subject.locator.member_refs,
                corridor_subject.locator.member_anchor_eas,
            ))
            corridor_members = {
                subject.subject_id for subject in subjects
                if (subject.block_ref, subject.anchor_ea) in member_pairs
                and subject.kind is model.SemanticSubjectKind.BLOCK
                and subject.role is model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE
            }
            if set(payload.member_subject_ids) != corridor_members:
                raise ValueError("corridor evidence member scope does not match its locator")
        elif type(payload) is model.PatchStepEvidencePayload:
            header_target = item.subject.subject_id
            allowed_owner = item.subject.role in {
                model.SemanticSubjectRole.PLANNED_HELPER,
                model.SemanticSubjectRole.EFFECT_SITE,
            } or (
                payload.step_type in {
                    "PatchLowerConditionalStateTransition",
                    "PatchRedirectBranch",
                }
                and (
                    item.subject.kind is model.SemanticSubjectKind.BLOCK
                    or (
                        payload.step_type == "PatchRedirectBranch"
                        and item.subject.role is model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE
                    )
                )
            )
            if not allowed_owner or item.subject.block_ref != payload.owner_ref:
                raise ValueError("patch-step evidence header does not match its owner")
        elif type(payload) is model.GenericCfgGateEvidencePayload:
            if len(payload.affected_subject_ids) != 1:
                raise ValueError("generic gate evidence must be per subject")
            header_target = payload.affected_subject_ids[0]
        if header_target is not None and item.subject.subject_id != header_target:
            raise ValueError("evidence header subject does not match payload target")
        if type(payload) is model.StructuralLineageEvidencePayload:
            if payload.disposition in (model.StructuralDisposition.SPLIT, model.StructuralDisposition.FOLDED) and not payload.reciprocal_native_origin_eas:
                raise ValueError("split/fold lineage requires reciprocal origins")
            source_subject_ids = {subject.subject_id for subject in source_subjects}
            if any(value not in source_subject_ids for value in payload.source_subject_ids):
                raise ValueError("lineage source group is absent from source inventory")
            candidate_subject_ids = {subject.subject_id for subject in candidate_subjects}
            if any(value not in candidate_subject_ids for value in payload.candidate_subject_ids):
                raise ValueError("lineage candidate is absent from candidate inventory")
            if payload.disposition is model.StructuralDisposition.PRESERVED and len(payload.candidate_subject_ids) != 1:
                raise ValueError("preserved lineage requires exactly one candidate")
            if payload.disposition is model.StructuralDisposition.SPLIT and len(payload.candidate_subject_ids) < 2:
                raise ValueError("split lineage requires multiple candidates")
            if payload.disposition is model.StructuralDisposition.FOLDED and not payload.candidate_subject_ids:
                raise ValueError("fold lineage requires a candidate")
            if payload.disposition in (
                model.StructuralDisposition.PRESERVED,
                model.StructuralDisposition.SPLIT,
                model.StructuralDisposition.FOLDED,
            ):
                source_group_bindings = tuple(
                    source_bindings.get(value) for value in payload.source_subject_ids
                )
                candidate_bindings_for_lineage = tuple(
                    candidate_bindings.get(value) for value in payload.candidate_subject_ids
                )
                if any(binding is None for binding in source_group_bindings) or any(binding is None for binding in candidate_bindings_for_lineage):
                    raise ValueError("lineage lacks source/candidate binding witnesses")
                source_ea_sets = tuple(
                    set(binding.native_instruction_eas)
                    for binding in source_group_bindings
                    if binding is not None
                )
                source_eas = set().union(*source_ea_sets)
                candidate_eas = tuple(
                    set(binding.native_instruction_eas)
                    for binding in candidate_bindings_for_lineage
                    if binding is not None
                )
                if any(not eas for eas in candidate_eas) or not source_eas:
                    raise ValueError("lineage bindings lack native instruction witnesses")
                if payload.disposition is model.StructuralDisposition.SPLIT and any(
                    left & right for index, left in enumerate(candidate_eas)
                    for right in candidate_eas[index + 1:]
                ):
                    raise ValueError("split/fold candidate origins must be disjoint")
                if payload.disposition is model.StructuralDisposition.PRESERVED:
                    if len(payload.source_subject_ids) != 1:
                        raise ValueError("preserved lineage requires one source")
                    if candidate_eas[0] != source_eas:
                        raise ValueError("preserved lineage requires equal source and candidate origins")
                    expected_origins = tuple(sorted(source_eas))
                elif payload.disposition is model.StructuralDisposition.SPLIT:
                    if len(payload.source_subject_ids) != 1:
                        raise ValueError("split lineage requires one source")
                    candidate_union = set().union(*candidate_eas)
                    if candidate_union != source_eas:
                        raise ValueError("split lineage must partition the source origins")
                    expected_origins = tuple(sorted(source_eas))
                else:
                    if len(payload.source_subject_ids) < 2 or len(payload.candidate_subject_ids) != 1:
                        raise ValueError("folded lineage must carry multiple sources and one candidate")
                    if any(not eas for eas in source_ea_sets) or any(
                        left & right for index, left in enumerate(source_ea_sets)
                        for right in source_ea_sets[index + 1:]
                    ):
                        raise ValueError("folded source origins must be disjoint and nonempty")
                    if candidate_eas[0] != source_eas:
                        raise ValueError("folded lineage must union source origins exactly")
                    expected_origins = tuple(sorted(source_eas))
                if payload.reciprocal_native_origin_eas != expected_origins:
                    raise ValueError("lineage reciprocal origins do not match binding witnesses")
            if payload.disposition is model.StructuralDisposition.AUTHORIZED_RETIREMENT:
                retirement_claim = next(
                    (
                        claim for claim in inputs.claims
                        if claim.claim_id == payload.claim_id
                        and type(claim) is model.RetiredDispatcherInfrastructureClaim
                        and payload.source_subject_id in {member.subject_id for member in claim.member_subjects}
                    ),
                    None,
            )
                if retirement_claim is None:
                    raise ValueError("retirement lineage requires an in-scope claim")
        targets: tuple[tuple[str, model.SafetyDimension, bool, model.UnflattenJustificationRule], ...] = ()
        if type(payload) is model.TopologyEvidencePayload:
            passed = (
                not payload.expected_edge_relations
                and not payload.candidate_edge_relations
                and not payload.predecessor_subject_ids
                and not payload.successor_subject_ids
                and payload.reciprocal_edges
            ) or (
                bool(payload.expected_edge_relations)
                and payload.reciprocal_edges
                and payload.expected_edge_relations == payload.candidate_edge_relations
            )
            if payload.subject_id in candidate_drift_ids:
                passed = False
            targets = ((payload.subject_id, model.SafetyDimension.TOPOLOGY_INTEGRITY, passed, model.UnflattenJustificationRule.TOPOLOGY_PRESERVED if passed else model.UnflattenJustificationRule.TOPOLOGY_DRIFTED),)
        elif type(payload) is model.StructuralLineageEvidencePayload:
            if payload.disposition is model.StructuralDisposition.AUTHORIZED_RETIREMENT:
                targets = ()
                continue
            passed = payload.disposition in {
                model.StructuralDisposition.PRESERVED,
                model.StructuralDisposition.SPLIT,
                model.StructuralDisposition.FOLDED,
            }
            rule = {
                model.StructuralDisposition.PRESERVED: model.UnflattenJustificationRule.SOURCE_PRESERVED,
                model.StructuralDisposition.SPLIT: model.UnflattenJustificationRule.SOURCE_SPLIT_WITH_RECIPROCAL_ORIGINS,
                model.StructuralDisposition.FOLDED: model.UnflattenJustificationRule.SOURCE_FOLDED_WITH_RECIPROCAL_ORIGINS,
            }.get(payload.disposition, model.UnflattenJustificationRule.SOURCE_LOSS_UNACCOUNTED)
            targets = tuple(
                (source_id, model.SafetyDimension.STRUCTURAL_ACCOUNTING, passed, rule)
                for source_id in payload.source_subject_ids
            )
        elif type(payload) is model.SemanticRouteEvidencePayload:
            # A route payload is negative evidence by itself.  Positive
            # route authority is attached below only through a correlated
            # exact claim and the sealed assessment that produced ``matched``.
            if not payload.matched:
                rule = model.UnflattenJustificationRule.ROUTE_MISSING_OR_DRIFTED
                targets = tuple(
                    (target, model.SafetyDimension.ROUTE_EQUIVALENCE, False, rule)
                    for target in (
                        payload.route_subject_id,
                        payload.source_subject_id,
                        *payload.destination_subject_ids,
                    )
                )
        elif type(payload) is model.EffectSiteEvidencePayload:
            rule = model.UnflattenJustificationRule.EFFECT_PRESERVED if payload.preserved else model.UnflattenJustificationRule.EFFECT_LOST_UNACCOUNTED
            classified_loss = classifications.get(payload.effect_subject_id)
            classified_loss = bool(classified_loss and classified_loss.authorized_loss)
            targets = () if classified_loss else ((payload.effect_subject_id, model.SafetyDimension.EFFECT_PRESERVATION, payload.preserved, rule),)
        elif type(payload) is model.ReachabilityEvidencePayload:
            target = next((subject for subject in subjects if subject.subject_id == payload.target_subject_id), None)
            dimension = {model.SemanticSubjectRole.SOURCE_ENTRY: model.SafetyDimension.ENTRY_REACHABILITY, model.SemanticSubjectRole.DISPATCHER_ENTRY: model.SafetyDimension.ENTRY_REACHABILITY, model.SemanticSubjectRole.AUTHORITATIVE_HANDLER: model.SafetyDimension.HANDLER_REACHABILITY, model.SemanticSubjectRole.TERMINAL_SITE: model.SafetyDimension.TERMINAL_REACHABILITY}.get(target.role) if target is not None else None
            if dimension is not None:
                targets = ((payload.target_subject_id, dimension, payload.reachable, model.UnflattenJustificationRule.SUBJECT_REACHABLE if payload.reachable else model.UnflattenJustificationRule.SUBJECT_UNREACHABLE),)
            elif target is not None and target.role is model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION:
                conditional_targets: list[tuple[str, model.SafetyDimension, bool, model.UnflattenJustificationRule]] = []
                rule = model.UnflattenJustificationRule.SUBJECT_REACHABLE if payload.reachable else model.UnflattenJustificationRule.SUBJECT_UNREACHABLE
                for relation in inputs.conditional_relations:
                    if relation.source_subject_id != payload.target_subject_id:
                        continue
                    if relation.dimension not in {
                        model.SafetyDimension.HANDLER_REACHABILITY,
                        model.SafetyDimension.TERMINAL_REACHABILITY,
                    }:
                        continue
                    conditional_targets.append(
                        (relation.target_subject_id, relation.dimension, payload.reachable, rule)
                    )
                targets = tuple(conditional_targets)
        elif type(payload) is model.UseDefAuditEvidencePayload:
            target = next(
                (
                    subject for subject in subjects
                    if subject.role is model.SemanticSubjectRole.NON_STATE_VALUE_FLOW
                    and type(subject.locator) is model.ValueFlowSubjectLocator
                    and subject.locator.fragment_id == payload.fragment_id
                    and subject.locator.state_identity == payload.state_identity
                ),
                None,
            )
            if target is not None:
                clean = (
                    payload.executed
                    and payload.fragment_atomic
                    and payload.actionable_non_state_severance_count == 0
                    and not payload.violation_ids
                )
                if clean:
                    rule = model.UnflattenJustificationRule.USE_DEF_AUDIT_CLEAN
                elif not payload.executed or not payload.fragment_atomic:
                    rule = model.UnflattenJustificationRule.USE_DEF_AUDIT_UNAVAILABLE
                else:
                    rule = model.UnflattenJustificationRule.NON_STATE_USE_DEF_SEVERED
                targets = ((target.subject_id, model.SafetyDimension.USE_DEF_INTEGRITY, clean, rule),)
        elif type(payload) is model.CorridorCoverageEvidencePayload:
            complete = not payload.residual_subject_ids and set(payload.member_subject_ids) == set(payload.covered_subject_ids)
            target_ids = (payload.corridor_subject_id, *payload.member_subject_ids)
            target_ids += tuple(
                subject.subject_id
                for subject in subjects
                if subject.role is model.SemanticSubjectRole.DISPATCHER_ENTRY
            )
            targets = tuple(
                (target, model.SafetyDimension.CORRIDOR_COVERAGE, complete, model.UnflattenJustificationRule.CORRIDOR_FULLY_COVERED if complete else model.UnflattenJustificationRule.CORRIDOR_RESIDUAL_UNACCOUNTED)
                for target in dict.fromkeys(target_ids)
            )
        elif type(payload) is model.PatchStepEvidencePayload:
            if payload.plan_id != proposal.plan_id:
                raise ValueError("patch-step evidence belongs to a different plan")
            if payload.step_type not in {
                *_SUPPORTED_PATCH_STEP_TYPES,
            }:
                raise ValueError("patch-step evidence has an unsupported step kind")
            owner_subject_ids = {
                subject.subject_id for subject in _patch_owner_subjects(payload, subjects)
            }
            if item.subject.subject_id not in owner_subject_ids:
                raise ValueError("patch-step evidence row is outside its exact owner-role set")
            helper_ids = (item.subject.subject_id,)
            if not helper_ids:
                raise ValueError("patch-step evidence owner is outside helper inventory")
            rule = model.UnflattenJustificationRule.HELPER_OWNER_LINEAGE_PROVEN
            targets = () if payload.step_type == "PatchScalarizeLocalAliasAccess" else tuple(
                (target, model.SafetyDimension.STRUCTURAL_ACCOUNTING, True, rule)
                for target in helper_ids
            )
        elif type(payload) is model.GenericCfgGateEvidencePayload:
            dimension = {model.GenericCfgGateKind.ENTRY_REACHABILITY: model.SafetyDimension.ENTRY_REACHABILITY, model.GenericCfgGateKind.EFFECTFUL_REACHABILITY: model.SafetyDimension.EFFECT_PRESERVATION, model.GenericCfgGateKind.TERMINAL_REACHABILITY: model.SafetyDimension.TERMINAL_REACHABILITY}[payload.gate]
            targets = tuple((target, dimension, payload.passed, model.UnflattenJustificationRule.GENERIC_CFG_GATE_PASSED if payload.passed else model.UnflattenJustificationRule.GENERIC_CFG_GATE_FAILED) for target in payload.affected_subject_ids)
        known_subject_ids = {subject.subject_id for subject in subjects}
        if any(target_id not in known_subject_ids for target_id, _, _, _ in targets):
            raise ValueError("evidence payload targets a foreign subject")
        for target_id, dimension, passed, rule in targets:
            if (
                not passed
                and dimension is model.SafetyDimension.EFFECT_PRESERVATION
                and (
                    target_id in authorized_loss_subject_ids
                    or (
                        classifications.get(target_id) is not None
                        and classifications[target_id].preserved
                    )
                )
            ):
                # A failed generic effect gate remains in the evidence
                # inventory, but exact classified loss is normalized by its
                # receipt-correlated claim and must not become a refutation.
                continue
            subject = next((subject for subject in subjects if subject.subject_id == target_id), None)
            key = model.ObligationKey(subject, dimension) if subject is not None else None
            if key is not None and key in required:
                _add_justification(justifications, key, rule, model.EvidencePolarity.SUPPORTS if passed else model.EvidencePolarity.REFUTES, phase, (item.evidence_id,))
    # Claims have narrow, hard-coded authority and cannot prove unrelated dimensions.
    for claim in inputs.claims:
        targets: tuple[tuple[model.SemanticSubjectRef, model.SafetyDimension], ...] = ()
        rule = model.UnflattenJustificationRule.SOURCE_PRESERVED
        claim_evidence: tuple[str, ...] = ()
        if type(claim) is model.RetiredDispatcherInfrastructureClaim:
            matching_lineage = tuple(
                item for item in evidence
                if type(item.payload) is model.StructuralLineageEvidencePayload
                and item.payload.claim_id == claim.claim_id
                and item.payload.source_subject_id in {member.subject_id for member in claim.member_subjects}
                and item.payload.disposition is model.StructuralDisposition.AUTHORIZED_RETIREMENT
            )
            matching_coverage = tuple(
                item for item in evidence
                if type(item.payload) is model.CorridorCoverageEvidencePayload
                and item.payload.corridor_subject_id == claim.corridor_subject.subject_id
                and set(item.payload.member_subject_ids) == {member.subject_id for member in claim.member_subjects}
            )
            claim_evidence = tuple(item.evidence_id for item in (*matching_lineage, *matching_coverage))
            lineage_members = tuple(item.payload.source_subject_id for item in matching_lineage)
            exact_lineage = (
                len(matching_lineage) == len(claim.member_subjects)
                and set(lineage_members) == {member.subject_id for member in claim.member_subjects}
                and len(set(lineage_members)) == len(lineage_members)
            )
            if exact_lineage and matching_coverage:
                targets = tuple((member, model.SafetyDimension.STRUCTURAL_ACCOUNTING) for member in claim.member_subjects) + ((claim.corridor_subject, model.SafetyDimension.CORRIDOR_COVERAGE),)
            rule = model.UnflattenJustificationRule.RETIRED_INFRASTRUCTURE_PROVEN
        elif type(claim) is model.EquivalentSemanticRouteClaim:
            matching_route = tuple(
                item for item in evidence
                if type(item.payload) is model.SemanticRouteEvidencePayload
                and item.payload.route_subject_id == claim.retired_route_subject.subject_id
                and item.payload.source_subject_id == claim.source_subject.subject_id
                and item.payload.destination_subject_ids == _route_destination_ids(claim.retired_route_subject, source_subjects)
                and item.payload.atomic_group_id == claim.atomic_group_id
                and item.payload.matched
            )
            if matching_route:
                claim_evidence = tuple(item.evidence_id for item in matching_route)
                targets = ((claim.retired_route_subject, model.SafetyDimension.STRUCTURAL_ACCOUNTING), (claim.source_subject, model.SafetyDimension.ROUTE_EQUIVALENCE)) + tuple((item, model.SafetyDimension.ROUTE_EQUIVALENCE) for item in claim.destination_subjects)
            rule = model.UnflattenJustificationRule.EQUIVALENT_ROUTE_PROVEN
        elif type(claim) is model.ExactInfeasibleEffectClaim:
            matching_effect = tuple(
                item for item in evidence
                if type(item.payload) is model.EffectSiteEvidencePayload
                and item.payload.effect_subject_id == claim.discarded_effect_subject.subject_id
                and item.payload.instruction_ea == claim.discarded_effect_ea
                and classifications.get(item.payload.effect_subject_id) is not None
                and classifications[item.payload.effect_subject_id].authorized_loss
            )
            matching_route = tuple(
                item for item in evidence
                if type(item.payload) is model.SemanticRouteEvidencePayload
                and item.payload.proof_ids == tuple(sorted(claim.route_proof_ids))
                and item.payload.atomic_group_id == proposal.route_evidence.atomic_group_id
                and item.payload.source_subject_id == claim.predicate_subject.subject_id
                and claim.selected_target_subject.subject_id in item.payload.destination_subject_ids
                and item.payload.matched
            )
            if matching_route:
                claim_evidence = tuple(item.evidence_id for item in (*matching_effect, *matching_route))
                targets = (
                    (claim.discarded_effect_subject, model.SafetyDimension.EFFECT_PRESERVATION),
                    (claim.discarded_effect_subject, model.SafetyDimension.STRUCTURAL_ACCOUNTING),
                ) if matching_effect else ()
                route_subject = next(
                    subject for subject in subjects
                    if subject.kind is model.SemanticSubjectKind.ROUTE
                    and subject.subject_id == matching_route[0].payload.route_subject_id
                )
                route_targets = (
                    route_subject,
                    claim.source_subject,
                    claim.predicate_subject,
                    claim.selected_target_subject,
                    *tuple(
                        subject for subject in subjects
                        if subject.subject_id in matching_route[0].payload.destination_subject_ids
                    ),
                )
                for route_target in dict.fromkeys(route_targets):
                    route_key = model.ObligationKey(route_target, model.SafetyDimension.ROUTE_EQUIVALENCE)
                    if route_key in required:
                        _add_justification(
                            justifications, route_key,
                            model.UnflattenJustificationRule.EQUIVALENT_ROUTE_PROVEN,
                            model.EvidencePolarity.SUPPORTS, phase,
                            (matching_route[0].evidence_id,), claim.claim_id,
                        )
            rule = model.UnflattenJustificationRule.EXACT_INFEASIBLE_EFFECT_PROVEN
        elif type(claim) is model.LocalAliasEffectScalarizationClaim:
            alias_relations = tuple(
                relation for relation in inputs.conditional_relations
                if relation.source_subject_id == claim.owner_subject.subject_id
                and relation.dimension is model.SafetyDimension.EFFECT_PRESERVATION
                and any(
                    subject.subject_id == relation.target_subject_id
                    and type(subject.locator) is model.EffectSubjectLocator
                    and subject.locator.instruction_ea == claim.host_ea
                    and subject.locator.effect_kind is model.EffectSiteKind.STORE
                    for subject in subjects
                )
            )
            alias_target_ids = {relation.target_subject_id for relation in alias_relations}
            alias_effect = tuple(
                item for item in evidence
                if type(item.payload) is model.EffectSiteEvidencePayload
                and item.payload.effect_subject_id in alias_target_ids
                and item.payload.effect_kind is model.EffectSiteKind.STORE
                and (
                    item.payload.preserved
                    or (
                        classifications.get(item.payload.effect_subject_id) is not None
                        and classifications[item.payload.effect_subject_id].authorized_loss
                        and classifications[item.payload.effect_subject_id].authorized_transition
                        and classifications[item.payload.effect_subject_id].claim is claim
                    )
                )
                and item.payload.instruction_ea == claim.host_ea
                and item.payload.opcode == claim.host_opcode
                and (
                    claim.value_size is None
                    or item.payload.width == claim.value_size
                )
            )
            alias_patch = tuple(
                item for item in evidence
                if type(item.payload) is model.PatchStepEvidencePayload
                and item.payload.step_type == "PatchScalarizeLocalAliasAccess"
                and item.payload.plan_id == proposal.plan_id
                and item.payload.step_index == claim.step_index
                and item.payload.owner_ref == claim.owner_subject.block_ref
                and item.payload.step_digest == claim.step_digest
                and item.payload.host_ea == claim.host_ea
                and item.payload.host_opcode == claim.host_opcode
                and item.payload.value_size == claim.value_size
            )
            alias_binding = tuple(
                item for item in evidence
                if type(item.payload) is model.PhaseBindingEvidencePayload
                and item.payload.binding.subject.subject_id == claim.owner_subject.subject_id
                and item.payload.binding.status is model.SubjectBindingStatus.UNIQUE
            )
            alias_reachability = tuple(
                item for item in evidence
                if type(item.payload) is model.ReachabilityEvidencePayload
                and item.payload.target_subject_id == claim.owner_subject.subject_id
                and item.payload.reachable
                and item.payload.root_subject_id in {
                    subject.subject_id for subject in subjects
                    if subject.role is model.SemanticSubjectRole.SOURCE_ENTRY
                }
                and item.payload.root_subject_id != claim.owner_subject.subject_id
                and item.payload.path_subject_ids
                and item.payload.path_subject_ids[0] == item.payload.root_subject_id
                and item.payload.path_subject_ids[-1] == item.payload.target_subject_id
            )
            alias_evidence = (*alias_effect, *alias_patch, *alias_binding, *alias_reachability)
            if len(alias_relations) == 1 and len(alias_effect) == len(alias_patch) == len(alias_binding) == len(alias_reachability) == 1:
                claim_evidence = tuple(item.evidence_id for item in alias_evidence)
                effect_target = next(subject for subject in subjects if subject.subject_id in alias_target_ids)
                targets = ((effect_target, model.SafetyDimension.EFFECT_PRESERVATION),)
            rule = model.UnflattenJustificationRule.LOCAL_ALIAS_SCALARIZATION_PROVEN
        elif type(claim) is model.TerminalCycleBreakClaim:
            matching_lineage = tuple(
                item for item in evidence
                if type(item.payload) is model.StructuralLineageEvidencePayload
                and item.payload.claim_id == claim.claim_id
                and item.payload.source_subject_id == claim.cycle_subject.subject_id
            )
            matching_reach = tuple(
                item for item in evidence
                if type(item.payload) is model.ReachabilityEvidencePayload
                and item.payload.target_subject_id == claim.terminal_subject.subject_id
                and item.payload.reachable
            )
            if matching_lineage and matching_reach:
                claim_evidence = tuple(item.evidence_id for item in (*matching_lineage, *matching_reach))
                targets = ((claim.cycle_subject, model.SafetyDimension.STRUCTURAL_ACCOUNTING), (claim.terminal_subject, model.SafetyDimension.TERMINAL_REACHABILITY))
            rule = model.UnflattenJustificationRule.TERMINAL_CYCLE_BREAK_PROVEN
        for subject, dimension in targets:
            key = model.ObligationKey(subject, dimension)
            if key in required:
                _add_justification(
                    justifications, key, rule, model.EvidencePolarity.SUPPORTS,
                    phase, claim_evidence, claim.claim_id,
                )
    justifications_tuple = tuple(sorted(justifications, key=lambda item: item.justification_id))
    _validate_justification_graph(
        justifications_tuple, required, evidence, phase, inputs.claims,
        inputs.conditional_relations,
        candidate_fingerprint=(
            source_fingerprint
            if phase is model.UnflattenAuthorityPhase.PRODUCER_FORECAST
            else candidate_fingerprint
        ),
        candidate_generation=(
            source_generation
            if phase is model.UnflattenAuthorityPhase.PRODUCER_FORECAST
            else candidate_generation
        ),
        bindings=bindings,
        subjects=subjects,
        source_subject_ids=tuple(item.subject_id for item in source_subjects),
    )
    index = _build_obligation_index(required, justifications_tuple, phase)
    values = {
        "authority_id": authority_id,
        "preparation_receipt_id": inputs.preparation_receipt.receipt_id,
        "preparation_receipt": inputs.preparation_receipt,
        "phase": phase,
        "candidate_fingerprint": (
            source_fingerprint
            if phase is model.UnflattenAuthorityPhase.PRODUCER_FORECAST
            else candidate_fingerprint
        ),
        "candidate_generation": (
            source_generation
            if phase is model.UnflattenAuthorityPhase.PRODUCER_FORECAST
            else candidate_generation
        ), "source_fingerprint": source_fingerprint,
        "claims": inputs.claims, "subjects": subjects,
        "bindings": bindings, "conditional_relations": inputs.conditional_relations,
        "required_obligations": required, "evidence": evidence,
        "justifications": justifications_tuple, "obligation_index": index,
        "phase_metrics": model.SemanticPhaseMetrics(
            inputs.preparation_metrics,
            inputs.phase_build_metrics.source_inventory_builds,
            inputs.phase_build_metrics.candidate_inventory_builds,
            1,
            0,
            inputs.phase_build_metrics.phase,
            inputs.phase_build_metrics,
        ),
        "source_inventory": source_inventory,
        "source_subject_ids": tuple(item.subject_id for item in source_subjects),
        "source_bindings": tuple(source_inventory.bindings),
    }
    return _case_factory(model.SemanticSafetyCase, **values)


def evaluate_case(case: model.SemanticSafetyCase) -> model.UnflattenAuthorityVerdict:
    if type(case) is not model.SemanticSafetyCase:
        raise TypeError("case must be SemanticSafetyCase")
    failed = tuple(model.FailedObligation(cell.key, cell.state) for cell in case.obligation_index.cells if cell.state is not model.ObligationState.SATISFIED)
    graph_mismatch = any(
        binding.graph_fingerprint != case.candidate_fingerprint
        or binding.generation != case.candidate_generation
        for binding in case.bindings
        if binding.subject.kind is model.SemanticSubjectKind.BLOCK
    )
    phase_binding_failed = any(
        item.key.dimension is model.SafetyDimension.IDENTITY_BINDING
        and item.state is model.ObligationState.VIOLATED
        for item in failed
    )
    if graph_mismatch:
        reason = model.UnflattenAuthorityReason.GRAPH_GENERATION_MISMATCH
    elif phase_binding_failed:
        reason = {
            model.UnflattenAuthorityPhase.PRODUCER_FORECAST: model.UnflattenAuthorityReason.SOURCE_BINDING_FAILED,
            model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT: model.UnflattenAuthorityReason.PROJECTED_BINDING_FAILED,
            model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY: model.UnflattenAuthorityReason.LIVE_BINDING_FAILED,
        }[case.phase]
    elif any(item.state is model.ObligationState.INCONSISTENT for item in failed):
        reason = model.UnflattenAuthorityReason.OBLIGATION_INCONSISTENT
    elif any(item.state is model.ObligationState.VIOLATED for item in failed):
        reason = model.UnflattenAuthorityReason.OBLIGATION_VIOLATED
    elif failed:
        reason = model.UnflattenAuthorityReason.OBLIGATION_UNPROVEN
    else:
        reason = model.UnflattenAuthorityReason.ACCEPTED
    return model.UnflattenAuthorityVerdict(
        accepted=not failed, phase=case.phase, reason=reason, authority_id=case.authority_id,
        binding_id=None, case_id=case.case_id, candidate_fingerprint=case.candidate_fingerprint,
        safety_case=case, failed_obligations=failed,
    )


__all__ = ["REQUIRED_DIMENSIONS", "build_semantic_case", "evaluate_case", "_build_obligation_index"]
