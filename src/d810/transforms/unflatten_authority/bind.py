"""Exact source/projected identity binding for typed unflatten subjects."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, fields as dataclass_fields, is_dataclass, replace
import hashlib
import re
import threading
from types import MappingProxyType, MemberDescriptorType
import weakref

from d810.core.logging import getLogger
from d810.ir.flowgraph import BlockKind, InsnKind
from d810.ir.semantics import ControlTransferKind
from d810.ir.block_identity import StableBlockIdentity
from d810.analyses.control_flow import semantic_route_evidence as route_model
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.transforms.plan import (
    PatchPlan, PatchConditionalRedirect, PatchLowerConditionalStateTransition,
    PatchConvertToGoto, PatchRedirectBranch, PatchRedirectGoto,
    PatchScalarizeLocalAliasAccess,
    PatchEdgeSplitTrampoline, PatchEdgeSplitCorridor,
)
from d810.transforms.cfg_transaction import (
    LogicalBlockRef, NativeBlockRef, PlanBlockRef, TransactionAttemptId, PatchStepKind,
)
from . import ids as authority_ids
from . import model, producer_api
from .gates import GenericEffectfulGateFacts
from .proposal import (
    CanonicalPatchStepDescriptor,
    canonical_patch_step_descriptors,
    _patch_block_spec_preimage,
    _native_route_destination_subject_for_proof_destination,
)
from .ids import (
    _subject_factory,
    canonical_bytes,
    semantic_graph_fingerprint,
    validate_canonical_roundtrip,
    authority_id,
    source_route_authority_id,
    projected_route_realization_id,
    projected_route_realization_row_id,
    route_realization_id,
    cloned_semantic_observation_digest,
    cloned_semantic_instruction_origin_id,
    cloned_semantic_prefix_id,
    raw_effect_gate_phase_fact_id,
    effect_site_coordinate_id,
    terminal_site_coordinate_id,
    exact_effect_binding_result_id,
    local_alias_binding_result_id,
    projected_effect_site_result_id,
    projected_terminal_site_result_id,
    projected_semantic_site_phase_result_id,
    projected_route_site_preservation_id,
    derived_effect_gate_fact_id,
    projected_authority_id,
    authority_id as canonical_authority_id,
    patch_step_fact_id,
    patch_step_fact_id as _canonical_patch_step_fact_id,
)


logger = getLogger(__name__)


@dataclass(frozen=True, slots=True)
class _LocalAliasClaimFactOccurrence:
    claim: model.LocalAliasEffectScalarizationClaim
    patch_step_fact: model.PatchStepEvidencePayload
    source_site: model.InventoryEffectSite
    source_observation: model.InventoryInstructionObservation


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class _DerivedTransactionClaimInventory:
    proposal: model.ProposedUnflattenContract
    plan: PatchPlan
    source_inventory: model.SemanticGraphInventory
    proposal_claims: tuple[model.ProducerUnflattenClaim, ...]
    local_alias_occurrences: tuple[_LocalAliasClaimFactOccurrence, ...]
    claims: tuple[model.UnflattenClaim, ...]
    route_patch_step_facts: tuple[model.PatchStepEvidencePayload, ...]
    local_patch_step_facts: tuple[model.PatchStepEvidencePayload, ...]
    patch_step_facts: tuple[model.PatchStepEvidencePayload, ...]
    legacy_conditional_relations: tuple[model.ConditionalSubjectRelation, ...]


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class _TransactionProjectedClaimInventory:
    derived: _DerivedTransactionClaimInventory
    source_authority: model.SourceBoundRouteAuthority
    attempt_id: TransactionAttemptId
    projected_inventory: model.SemanticGraphInventory


@dataclass(frozen=True, slots=True)
class _ExactSelectedArmDirectCorrelation:
    route_claim: model.EquivalentSemanticRouteClaim
    proof: route_model.SemanticRouteProof
    descriptor: CanonicalPatchStepDescriptor
    facts: tuple[model.PatchStepEvidencePayload, ...]
    feeder: model.AnchoredBlockRef
    predicate_old_target: model.AnchoredBlockRef
    selected_destination: route_model.SemanticRouteDestination
    discarded_destination: route_model.SemanticRouteDestination
    exact_claims: tuple[model.ExactInfeasibleEffectClaim, ...]


_DERIVED_TRANSACTION_CLAIM_INVENTORIES: dict[
    int, tuple[weakref.ReferenceType[_DerivedTransactionClaimInventory], tuple[object, ...]]
] = {}


def _derived_transaction_claim_inventory_token(
    value: _DerivedTransactionClaimInventory,
) -> tuple[object, ...]:
    return (
        id(value.proposal), id(value.plan), id(value.source_inventory),
        tuple(id(item) for item in value.proposal_claims),
        tuple(
            (
                id(item), id(item.claim), id(item.patch_step_fact),
                id(item.source_site), id(item.source_observation),
            )
            for item in value.local_alias_occurrences
        ),
        tuple(id(item) for item in value.claims),
        tuple(id(item) for item in value.route_patch_step_facts),
        tuple(id(item) for item in value.local_patch_step_facts),
        tuple(id(item) for item in value.patch_step_facts),
        tuple(id(item) for item in value.legacy_conditional_relations),
    )


def _validate_derived_transaction_claim_inventory_fields(
    value: _DerivedTransactionClaimInventory,
) -> None:
    if type(value) is not _DerivedTransactionClaimInventory:
        raise TypeError("derived transaction claims require the exact private inventory")
    if type(value.proposal) is not model.ProposedUnflattenContract:
        raise TypeError("derived transaction proposal is not closed")
    if type(value.plan) is not PatchPlan or value.plan.unflatten_proposal is not value.proposal:
        raise ValueError("derived transaction plan is foreign to its proposal")
    if type(value.source_inventory) is not model.SemanticGraphInventory:
        raise TypeError("derived transaction source inventory is not closed")
    model.validate_semantic_graph_inventory(value.source_inventory)
    if value.source_inventory.phase is not model.UnflattenAuthorityPhase.PRODUCER_FORECAST:
        raise ValueError("derived transaction source inventory has the wrong phase")
    if value.source_inventory.generation != value.proposal.source_identity_catalog.generation:
        raise ValueError("derived transaction source generation differs")
    if type(value.proposal_claims) is not tuple or (
        len(value.proposal_claims) != len(value.proposal.claims)
        or any(left is not right for left, right in zip(value.proposal_claims, value.proposal.claims))
    ):
        raise ValueError("derived transaction proposal claims are not exact occurrences")
    tuple_fields = (
        value.local_alias_occurrences, value.claims,
        value.route_patch_step_facts, value.local_patch_step_facts,
        value.patch_step_facts, value.legacy_conditional_relations,
    )
    if any(type(items) is not tuple for items in tuple_fields):
        raise TypeError("derived transaction inventory fields must be exact tuples")
    if any(type(item) is not _LocalAliasClaimFactOccurrence for item in value.local_alias_occurrences):
        raise TypeError("derived transaction local occurrences are not closed")
    local_claims: list[model.LocalAliasEffectScalarizationClaim] = []
    claimed_local_facts: list[model.PatchStepEvidencePayload] = []
    seen_steps: set[tuple[int, object, int, int]] = set()
    source_blocks = {block.serial: block for block in value.source_inventory.blocks}
    source_serials = value.source_inventory.serial_by_ref
    for occurrence in value.local_alias_occurrences:
        claim = occurrence.claim
        fact = occurrence.patch_step_fact
        site = occurrence.source_site
        observation = occurrence.source_observation
        if (
            type(claim) is not model.LocalAliasEffectScalarizationClaim
            or type(fact) is not model.PatchStepEvidencePayload
            or type(site) is not model.InventoryEffectSite
            or type(observation) is not model.InventoryInstructionObservation
        ):
            raise TypeError("derived local occurrence contains an open value")
        if claim.step_index < 0 or claim.step_index >= len(value.plan.steps):
            raise ValueError("derived local claim step is outside the plan")
        step = value.plan.steps[claim.step_index]
        if type(step) is not PatchScalarizeLocalAliasAccess:
            raise ValueError("derived local claim does not select a scalar step")
        serial = source_serials.get(step.block_serial)
        block = source_blocks.get(serial)
        if (
            fact.plan_id != value.plan.plan_id
            or fact.step_index != claim.step_index
            or fact.step_type != "PatchScalarizeLocalAliasAccess"
            or fact.owner_ref != step.block_serial
            or fact.step_digest != claim.step_digest
            or fact.host_ea != claim.host_ea
            or fact.host_opcode != claim.host_opcode
            or fact.value_size != claim.value_size
            or block is None
            or site.owner_ref != step.block_serial
            or site.owner_serial != serial
            or site.owner_anchor_ea != block.anchor_ea
            or site.instruction_ea != claim.host_ea
            or site.instruction_ordinal != observation.ordinal
            or site.opcode != claim.host_opcode
            or site.width != observation.width
            or (
                claim.value_size is not None
                and site.width != claim.value_size
            )
            or site.effect_kind is not model.EffectSiteKind.STORE
            or not any(candidate is site for candidate in value.source_inventory.effects)
            or not any(candidate is observation for candidate in block.instruction_observations)
            or observation.instruction_ea != claim.host_ea
            or observation.opcode != claim.host_opcode
            or (
                claim.value_size is not None
                and observation.width != claim.value_size
            )
            or observation.raw_opcode is None
            or observation.instruction_kind is not InsnKind.STORE
            or observation.is_call
            or observation.call_kind is not None
            or observation.control_transfer_kind is not None
            or block.block_ref != site.owner_ref
        ):
            raise ValueError("derived local claim/fact/site occurrence differs from source")
        key = (claim.step_index, step.block_serial, claim.host_ea, claim.host_opcode)
        if key in seen_steps:
            raise ValueError("derived local occurrence is duplicated")
        seen_steps.add(key)
        local_claims.append(claim)
        claimed_local_facts.append(fact)
    scalar_steps = tuple(
        index for index, step in enumerate(value.plan.steps)
        if type(step) is PatchScalarizeLocalAliasAccess
    )
    if tuple(sorted(
        item.step_index for item in value.local_patch_step_facts
    )) != scalar_steps:
        raise ValueError("derived local patch facts do not exhaust scalar steps")
    occurrence_by_step = {
        item.claim.step_index: item for item in value.local_alias_occurrences
    }
    local_fact_ids = {id(item) for item in value.local_patch_step_facts}
    if any(id(item) not in local_fact_ids for item in claimed_local_facts):
        raise ValueError("derived local claim fact is outside the local fact inventory")
    for fact in value.local_patch_step_facts:
        if type(fact) is not model.PatchStepEvidencePayload:
            raise TypeError("derived local patch fact is not closed")
        if fact.step_index < 0 or fact.step_index >= len(value.plan.steps):
            raise ValueError("derived local patch fact step is outside the plan")
        step = value.plan.steps[fact.step_index]
        if type(step) is not PatchScalarizeLocalAliasAccess:
            raise ValueError("derived local patch fact does not select a scalar step")
        serial = source_serials.get(step.block_serial)
        block = source_blocks.get(serial)
        expected_digest = canonical_authority_id((
            "PatchScalarizeLocalAliasAccess",
            fact.step_index,
            step.block_serial,
            step.host_ea,
            step.host_opcode,
            step.alias_token,
            step.base_token,
            step.host_text_sha1,
            step.value_size,
        ))
        observations = () if block is None else tuple(
            item for item in block.instruction_observations
            if item.instruction_ea == step.host_ea
            and item.opcode == step.host_opcode
        )
        if (
            fact.plan_id != value.plan.plan_id
            or fact.step_type != "PatchScalarizeLocalAliasAccess"
            or fact.owner_ref != step.block_serial
            or fact.step_digest != expected_digest
            or fact.host_ea != step.host_ea
            or fact.host_opcode != step.host_opcode
            or fact.value_size != step.value_size
            or len(observations) != 1
            or observations[0].instruction_kind not in {InsnKind.LOAD, InsnKind.STORE}
        ):
            raise ValueError("derived local patch fact differs from its exact source host")
        occurrence = occurrence_by_step.get(fact.step_index)
        if observations[0].instruction_kind is InsnKind.STORE:
            if occurrence is None or occurrence.patch_step_fact is not fact:
                raise ValueError("derived local STORE fact lacks its exact loss claim")
        elif occurrence is not None:
            raise ValueError("derived local LOAD fact must not mint an effect-loss claim")
    canonical_claims = tuple(sorted(
        (*value.proposal_claims, *local_claims), key=lambda item: item.claim_id,
    ))
    if value.claims != canonical_claims or any(
        left is not right for left, right in zip(value.claims, canonical_claims)
    ) or len({item.claim_id for item in value.claims}) != len(value.claims):
        raise ValueError("derived complete claim inventory is not canonical")
    if any(type(item) is not model.PatchStepEvidencePayload for item in value.route_patch_step_facts):
        raise TypeError("derived route fact subset is not closed")
    route_ids = {id(item) for item in value.route_patch_step_facts}
    local_ids = {id(item) for item in value.local_patch_step_facts}
    if route_ids & local_ids:
        raise ValueError("derived route/local fact subsets overlap")
    expected_facts = tuple(sorted(
        (*value.route_patch_step_facts, *value.local_patch_step_facts),
        key=patch_step_fact_id,
    ))
    if value.patch_step_facts != expected_facts or any(
        left is not right for left, right in zip(value.patch_step_facts, expected_facts)
    ):
        raise ValueError("derived complete fact inventory is not canonical")
    if len({patch_step_fact_id(item) for item in value.patch_step_facts}) != len(value.patch_step_facts):
        raise ValueError("derived patch fact IDs are duplicated")
    if any(type(item) is not model.ConditionalSubjectRelation for item in value.legacy_conditional_relations):
        raise TypeError("derived legacy relations are not closed")


def _mint_derived_transaction_claim_inventory(
    *, proposal: model.ProposedUnflattenContract, plan: PatchPlan,
    source_inventory: model.SemanticGraphInventory,
    proposal_claims: tuple[model.ProducerUnflattenClaim, ...],
    local_alias_occurrences: tuple[_LocalAliasClaimFactOccurrence, ...],
    claims: tuple[model.UnflattenClaim, ...],
    route_patch_step_facts: tuple[model.PatchStepEvidencePayload, ...],
    local_patch_step_facts: tuple[model.PatchStepEvidencePayload, ...],
    patch_step_facts: tuple[model.PatchStepEvidencePayload, ...],
    legacy_conditional_relations: tuple[model.ConditionalSubjectRelation, ...],
) -> _DerivedTransactionClaimInventory:
    value = object.__new__(_DerivedTransactionClaimInventory)
    for name, item in locals().copy().items():
        if name != "value":
            object.__setattr__(value, name, item)
    _validate_derived_transaction_claim_inventory_fields(value)
    key = id(value)
    token = _derived_transaction_claim_inventory_token(value)

    def cleanup(reference: weakref.ReferenceType[_DerivedTransactionClaimInventory]) -> None:
        with _REGISTRY_PUBLICATION_LOCK:
            row = _DERIVED_TRANSACTION_CLAIM_INVENTORIES.get(key)
            if row is not None and row[0] is reference:
                _DERIVED_TRANSACTION_CLAIM_INVENTORIES.pop(key, None)

    with _REGISTRY_PUBLICATION_LOCK:
        _DERIVED_TRANSACTION_CLAIM_INVENTORIES[key] = (weakref.ref(value, cleanup), token)
    return value


def _validate_derived_transaction_claim_inventory(
    value: _DerivedTransactionClaimInventory,
) -> None:
    _validate_derived_transaction_claim_inventory_fields(value)
    with _REGISTRY_PUBLICATION_LOCK:
        row = _DERIVED_TRANSACTION_CLAIM_INVENTORIES.get(id(value))
        if row is None or row[0]() is not value:
            raise ValueError("derived transaction inventory is not binder-owned")
        if row[1] != _derived_transaction_claim_inventory_token(value):
            raise ValueError("derived transaction inventory occurrence content drifted")


@dataclass(frozen=True, slots=True)
class _ExactEffectBindingDraft:
    claim: model.ExactInfeasibleEffectClaim
    proof: object
    source_authority: model.SourceBoundRouteAuthority
    relation_draft: object
    source_row: model.InventoryEffectSite
    raw_effect_gate_fact: model.RawEffectGatePhaseFact
    source_inventory: model.SemanticGraphInventory
    projected_inventory: model.SemanticGraphInventory


@dataclass(frozen=True, slots=True)
class _LocalAliasBindingDraft:
    claim: model.LocalAliasEffectScalarizationClaim
    patch_step_fact: model.PatchStepEvidencePayload
    source_row: model.InventoryEffectSite
    source_observation: model.InventoryInstructionObservation
    projected_block: object
    projected_observation: object
    source_inventory: model.SemanticGraphInventory
    projected_inventory: model.SemanticGraphInventory


@dataclass(frozen=True, slots=True)
class _ProjectedEffectDispositionDraft:
    source_row: model.InventoryEffectSite
    source_subject: object
    owner_mapping: object | None
    projected_row: model.InventoryEffectSite | None
    projected_subject: object | None
    outcome: model.ProjectedEffectSiteOutcome
    lineage: object | None
    relation_draft: object | None
    exact_binding: _ExactEffectBindingDraft | None
    local_binding: _LocalAliasBindingDraft | None
    patch_step_fact: model.PatchStepEvidencePayload | None


@dataclass(frozen=True, slots=True)
class _ProjectedTerminalDispositionDraft:
    source_row: model.InventoryTerminalSite
    source_subject: object
    owner_mapping: object | None
    projected_row: model.InventoryTerminalSite
    projected_subject: object
    outcome: model.ProjectedTerminalSiteOutcome
    lineage: object
    relation_draft: object | None


@dataclass(frozen=True, slots=True)
class _RouteSiteSubsetDraft:
    relation_draft: object
    effect_dispositions: tuple[_ProjectedEffectDispositionDraft, ...]
    terminal_dispositions: tuple[_ProjectedTerminalDispositionDraft, ...]


@dataclass(frozen=True, slots=True)
class _ProjectedSiteClosureDraft:
    exact_binding_drafts: tuple[_ExactEffectBindingDraft, ...]
    local_binding_drafts: tuple[_LocalAliasBindingDraft, ...]
    effect_dispositions: tuple[_ProjectedEffectDispositionDraft, ...]
    terminal_dispositions: tuple[_ProjectedTerminalDispositionDraft, ...]
    route_subsets: tuple[_RouteSiteSubsetDraft, ...]
    raw_retained_source_owners: tuple[object, ...]
    raw_lost_source_owners: tuple[object, ...]


@dataclass(frozen=True, slots=True)
class _RelationOwnerOccurrence:
    relation_id: str
    source_owner: model.AnchoredBlockRef
    projected_owner: model.AnchoredBlockRef
    lineage: model.ProjectedSiteLineageKind


@dataclass(frozen=True, slots=True)
class _ProjectedSiteDraftViolation(ValueError):
    reason_code: str
    scope: object
    relation_draft: object | None = None
    claim: object | None = None
    proof: object | None = None
    patch_step_fact: object | None = None
    source_row: object | None = None
    projected_row: object | None = None
    anchored_refs: tuple[object, ...] = ()
    stage = model.RouteRealizationFailureStage.EFFECT_TERMINAL_PRESERVATION

    def __post_init__(self) -> None:
        ValueError.__init__(self, self.reason_code)


def _projected_relation_diagnostic_anchors(
    relation: object,
) -> tuple[model.AnchoredBlockRef, ...]:
    """Return every closed anchored role carried by one selected relation."""
    if relation is None:
        return ()
    if type(relation) is model.DirectRouteRealization:
        values = (relation.feeder, relation.old_target, relation.new_target)
    elif type(relation) is model.SharedCarrierSourceBypassRouteRealization:
        values = (
            relation.proof_source, relation.shared_feeder,
            relation.comparison_entry, relation.semantic_target,
        )
    elif type(relation) is model.RetainedPrefixRouteRealization:
        values = (
            relation.proof_source, relation.delivery_owner,
            relation.old_target, relation.new_target,
        )
    elif type(relation) is model.LoweredConditionalRouteRealization:
        values = (
            relation.feeder, relation.proof_source, relation.old_target,
            *(arm.target for arm in relation.arms),
        )
    elif type(relation) is model.ClonedConditionalRouteRealization:
        values = (
            relation.feeder, relation.proof_source, relation.old_target,
            relation.replacement_clone, relation.fallthrough_helper,
            *(arm.target for arm in relation.arms),
        )
    elif type(relation) is model.FoldedConditionalRouteRealization:
        values = (
            relation.feeder, relation.selected_target,
            relation.discarded_target,
        )
    elif type(relation) is model.TwoArmDirectBranchRouteRealization:
        values = (
            relation.feeder, relation.source_rewritten_arm,
            relation.projected_replacement_arm, relation.untouched_arm,
        )
    elif type(relation) is model.BranchFallthroughHelperRouteRealization:
        values = (
            relation.feeder, relation.source_fallthrough,
            relation.untouched_conditional_arm, relation.helper,
            relation.semantic_target,
        )
    elif type(relation) is model.ClonedRouteCorridorRealization:
        values = (
            relation.predecessor, relation.proof_source,
            relation.descriptor_old_target, relation.terminal_continuation,
            *relation.source_corridor, *relation.cloned_corridor,
            relation.semantic_target,
            *(prefix.source_owner for prefix in relation.semantic_prefixes),
            *(prefix.clone_owner for prefix in relation.semantic_prefixes),
            *(prefix.projected_successor for prefix in relation.semantic_prefixes),
        )
    elif type(relation) is model.ClonedCarrierRouteCorridorRealization:
        values = (
            relation.proof_source, relation.physical_feeder,
            relation.comparison_entry, *relation.source_corridor,
            *relation.cloned_corridor, relation.semantic_target,
            *(prefix.source_owner for prefix in relation.semantic_prefixes),
            *(prefix.clone_owner for prefix in relation.semantic_prefixes),
            *(prefix.projected_successor for prefix in relation.semantic_prefixes),
        )
    else:
        raise TypeError("projected relation diagnostic type is not admitted")
    return tuple(sorted(set(values), key=canonical_bytes))


def _projected_site_coordinate_drift_reason(
    actual: object, expected: object,
) -> str | None:
    """Classify one exact closed coordinate drift before occurrence identity."""
    if type(actual) is not type(expected):
        return None

    def differs(name: str) -> bool:
        actual_value = getattr(actual, name)
        expected_value = getattr(expected, name)
        return (
            type(actual_value) is not type(expected_value)
            or actual_value != expected_value
        )

    owner_differs = (
        differs("owner_ref") or differs("owner_anchor_ea")
    )
    if type(actual) is model.InventoryEffectSite:
        fields = (
            ("instruction_ea", "projected effect instruction EA differs"),
            (
                "instruction_ordinal",
                "projected effect instruction ordinal differs",
            ),
            ("effect_kind", "projected effect kind differs"),
            ("opcode", "projected effect opcode differs"),
            ("width", "projected effect width differs"),
        )
        owner_reason = "projected effect anchored owner differs"
    elif type(actual) is model.InventoryTerminalSite:
        fields = (
            ("instruction_ea", "projected terminal instruction EA differs"),
            (
                "instruction_ordinal",
                "projected terminal instruction ordinal differs",
            ),
            ("terminal_kind", "projected terminal kind differs"),
        )
        owner_reason = "projected terminal anchored owner differs"
    else:
        return None
    reasons = tuple(
        reason for name, reason in fields if differs(name)
    ) + ((owner_reason,) if owner_differs else ())
    return reasons[0] if len(reasons) == 1 else None


def _translate_projected_site_draft_violation(exc: _ProjectedSiteDraftViolation) -> dict[str, object]:
    def locator_anchors(locator: object) -> tuple[model.AnchoredBlockRef, ...]:
        pairs: list[tuple[object, object]] = []
        for ref_name, anchor_name in (
            ("owner_ref", "owner_anchor_ea"),
            ("block_ref", "anchor_ea"),
            ("source_ref", "source_anchor_ea"),
            ("target_ref", "target_anchor_ea"),
        ):
            ref = getattr(locator, ref_name, None)
            anchor = getattr(locator, anchor_name, None)
            if ref is not None and type(anchor) is int:
                pairs.append((ref, anchor))
        if type(locator) is model.RouteSubjectLocator:
            pairs.extend(
                (item.block_ref, item.anchor_ea)
                for item in locator.native_destination_members()
                if type(item) is model.BlockSubjectLocator
            )
        anchored: list[model.AnchoredBlockRef] = []
        for ref, anchor in pairs:
            try:
                anchored.append(model.AnchoredBlockRef(ref, anchor))
            except (TypeError, ValueError):
                continue
        return tuple(anchored)

    relation = exc.relation_draft
    claim = exc.claim if exc.claim is not None else getattr(relation, "claim", None)
    proof = exc.proof if exc.proof is not None else getattr(relation, "proof", None)
    fact = exc.patch_step_fact
    descriptor = getattr(relation, "descriptor", None)
    if fact is None and relation is not None and getattr(relation, "facts", ()):
        fact = relation.facts[0]
    anchors = list(exc.anchored_refs)
    anchors.extend(_projected_relation_diagnostic_anchors(
        getattr(relation, "relation", None),
    ))
    if claim is not None:
        for subject_name in (
            "effect_subject", "source_subject", "predicate_subject",
            "selected_target_subject", "discarded_effect_subject",
            "owner_subject",
        ):
            subject = getattr(claim, subject_name, None)
            if subject is not None:
                anchors.extend(locator_anchors(getattr(subject, "locator", None)))
    for row in (exc.source_row, exc.projected_row):
        owner_ref = getattr(row, "owner_ref", None)
        owner_anchor = getattr(row, "owner_anchor_ea", None)
        if owner_anchor is None:
            owner_ref = getattr(row, "block_ref", owner_ref)
            owner_anchor = getattr(row, "anchor_ea", owner_anchor)
        if owner_ref is not None and type(owner_anchor) is int:
            try:
                anchors.append(model.AnchoredBlockRef(owner_ref, owner_anchor))
            except (TypeError, ValueError):
                pass
    return {
        "stage": exc.stage,
        "scope_override": exc.scope,
        "claim": claim,
        "proof_override": proof,
        "fact": fact,
        "descriptor": descriptor,
        "extra_anchored_refs": tuple(anchors),
    }


_ROUTE_REGISTRY: dict[int, tuple[weakref.ReferenceType[object], str]] = {}
_SITE_REGISTRY: dict[int, tuple[weakref.ReferenceType[object], str]] = {}
_SITE_BINDING_REGISTRY: dict[int, tuple[weakref.ReferenceType[object], str]] = {}
_OBSERVED_LOGICAL_ENDPOINT_REGISTRY: dict[
    int, tuple[weakref.ReferenceType[object], str]
] = {}
_OBSERVED_ROUTE_TOPOLOGY_REGISTRY: dict[
    int, tuple[weakref.ReferenceType[object], str]
] = {}
_OBSERVED_LOWERED_CONDITIONAL_TOPOLOGY_REGISTRY: dict[
    int, tuple[weakref.ReferenceType[object], str]
] = {}
# Publication occurs only in transaction_api's complete entry-liveness binder.
# This lower layer owns the occurrence store and validates consumers without
# depending upward on the transaction facade.
_ENTRY_ENDPOINT_LIVENESS_RECEIPT_OCCURRENCES: dict[int, tuple[object, str]] = {}
_REGISTRY_PUBLICATION_LOCK = threading.RLock()


def _registry_reference(
    value: object, registry: dict[int, tuple[weakref.ReferenceType[object], str]],
    key: int,
) -> weakref.ReferenceType[object]:
    def cleanup(reference: weakref.ReferenceType[object]) -> None:
        with _REGISTRY_PUBLICATION_LOCK:
            row = registry.get(key)
            if row is not None and row[0] is reference:
                registry.pop(key, None)

    return weakref.ref(value, cleanup)


def _registry_occurrence_is_registered(
    registry: dict[int, tuple[weakref.ReferenceType[object], str]],
    key: int, value: object, seal: str,
) -> bool:
    row = registry.get(key)
    if row is None:
        return False
    if row[0]() is value and row[1] == seal:
        return True
    raise ValueError("registry occurrence conflicts with an existing publication")


def _register_registry_occurrence(
    value: object, seal: str,
    registry: dict[int, tuple[weakref.ReferenceType[object], str]],
) -> object:
    key = id(value)
    reference = _registry_reference(value, registry, key)
    with _REGISTRY_PUBLICATION_LOCK:
        canonical_seal = _canonical_registry_seal(value, registry)
        if seal != canonical_seal:
            raise ValueError("registry publication seal is not canonical")
        if _registry_occurrence_is_registered(
            registry, key, value, canonical_seal,
        ):
            return value
        registry[key] = (reference, canonical_seal)
    return value


class _AtomicPublicationBatch:
    """One call-owned, prechecked all-or-none registry publication batch."""

    __slots__ = ("_entries", "_committed")

    def __init__(self) -> None:
        self._entries: list[
            tuple[dict, int, weakref.ReferenceType[object], str]
        ] = []
        self._committed = False

    def defer(
        self, *, value: object,
        registry: dict[int, tuple[weakref.ReferenceType[object], str]],
        seal: str,
    ) -> object:
        if self._committed:
            raise ValueError("publication batch is already committed")
        key = id(value)

        reference = _registry_reference(value, registry, key)
        self._entries.append((registry, key, reference, seal))
        return value

    def commit(self) -> None:
        """Precheck every exact occurrence before the first registry write."""
        with _REGISTRY_PUBLICATION_LOCK:
            if self._committed:
                raise ValueError("publication batch is already committed")
            seen: dict[tuple[int, int], tuple[object, str]] = {}
            unpublished: list[
                tuple[dict, int, weakref.ReferenceType[object], str]
            ] = []
            for registry, key, reference, seal in self._entries:
                occurrence = (id(registry), key)
                value = reference()
                if value is None:
                    raise ValueError("publication batch occurrence is no longer live")
                canonical_seal = _canonical_registry_seal(value, registry)
                if canonical_seal != seal:
                    raise ValueError("publication batch content seal differs")
                previous = seen.get(occurrence)
                if previous is not None:
                    if previous[0] is not value or previous[1] != seal:
                        raise ValueError(
                            "publication batch contains a conflicting occurrence"
                        )
                    continue
                seen[occurrence] = (value, canonical_seal)
                if not _registry_occurrence_is_registered(
                    registry, key, value, canonical_seal,
                ):
                    unpublished.append((registry, key, reference, canonical_seal))
            for registry, key, reference, seal in unpublished:
                registry[key] = (reference, seal)
            self._committed = True


def _register_site(value: object, identity: str, _registry=_SITE_REGISTRY) -> object:
    return _register_registry_occurrence(value, identity, _registry)


def validate_bound_entry_endpoint_liveness_allowance(
    receipt: model.BoundEntryEndpointLivenessAllowance,
) -> None:
    """Require the exact binder-minted entry-liveness receipt occurrence."""
    if type(receipt) is not model.BoundEntryEndpointLivenessAllowance:
        raise TypeError("entry liveness receipt has unknown type")
    receipt.__post_init__()
    with _REGISTRY_PUBLICATION_LOCK:
        row = _ENTRY_ENDPOINT_LIVENESS_RECEIPT_OCCURRENCES.get(id(receipt))
        if row is None or row[0] is not receipt:
            raise ValueError("entry liveness receipt was not binder-minted")
        if row[1] != receipt.binding_id:
            raise ValueError("entry liveness receipt content drifted")


def _publish_bound_entry_endpoint_liveness_batch(
    receipts: tuple[model.BoundEntryEndpointLivenessAllowance, ...],
) -> tuple[model.BoundEntryEndpointLivenessAllowance, ...]:
    """Atomically publish a fully transaction-validated receipt batch."""
    if type(receipts) is not tuple or any(
        type(item) is not model.BoundEntryEndpointLivenessAllowance
        for item in receipts
    ):
        raise TypeError("entry liveness publication requires exact receipts")
    for receipt in receipts:
        receipt.__post_init__()
    with _REGISTRY_PUBLICATION_LOCK:
        # Precheck the complete batch before the first registry write.
        seen: set[int] = set()
        for receipt in receipts:
            key = id(receipt)
            if key in seen:
                raise ValueError("entry liveness publication batch is duplicated")
            seen.add(key)
            existing = _ENTRY_ENDPOINT_LIVENESS_RECEIPT_OCCURRENCES.get(key)
            if existing is not None and (
                existing[0] is not receipt
                or existing[1] != receipt.binding_id
            ):
                raise ValueError("entry liveness receipt publication conflicts")
        for receipt in receipts:
            _ENTRY_ENDPOINT_LIVENESS_RECEIPT_OCCURRENCES[id(receipt)] = (
                receipt, receipt.binding_id,
            )
    return receipts


def _mint_observed_logical_endpoint_occurrence(
    **values: object,
) -> model.ObservedLogicalEndpointOccurrence:
    occurrence = model.ObservedLogicalEndpointOccurrence(**values)
    return _register_registry_occurrence(
        occurrence,
        occurrence.occurrence_id,
        _OBSERVED_LOGICAL_ENDPOINT_REGISTRY,
    )


def _validate_observed_logical_endpoint_occurrence(
    occurrence: model.ObservedLogicalEndpointOccurrence,
) -> None:
    if type(occurrence) is not model.ObservedLogicalEndpointOccurrence:
        raise TypeError("observed logical endpoint occurrence has unknown type")
    occurrence.__post_init__()
    row = _OBSERVED_LOGICAL_ENDPOINT_REGISTRY.get(id(occurrence))
    if row is None or row[0]() is not occurrence:
        raise ValueError(
            "observed logical endpoint occurrence was not minted by the binder",
        )
    if row[1] != occurrence.occurrence_id:
        raise ValueError("observed logical endpoint occurrence content drifted")


def mint_observed_route_topology_occurrence(
    **values: object,
) -> model.ObservedRouteTopologyOccurrence:
    """Mint the sole transaction-owned receipt for one observed route row."""

    occurrence = model.ObservedRouteTopologyOccurrence(**values)
    return _register_registry_occurrence(
        occurrence,
        occurrence.occurrence_id,
        _OBSERVED_ROUTE_TOPOLOGY_REGISTRY,
    )


def validate_observed_route_topology_occurrence(
    occurrence: model.ObservedRouteTopologyOccurrence,
) -> None:
    if type(occurrence) is not model.ObservedRouteTopologyOccurrence:
        raise TypeError("observed route topology occurrence has unknown type")
    occurrence.__post_init__()
    row = _OBSERVED_ROUTE_TOPOLOGY_REGISTRY.get(id(occurrence))
    if row is None or row[0]() is not occurrence:
        raise ValueError(
            "observed route topology occurrence was not minted by the binder",
        )
    if row[1] != occurrence.occurrence_id:
        raise ValueError("observed route topology occurrence content drifted")


def mint_observed_lowered_conditional_topology_occurrence(
    **values: object,
) -> model.ObservedLoweredConditionalTopologyOccurrence:
    """Mint one transaction-owned lowered-conditional topology receipt."""

    occurrence = model.ObservedLoweredConditionalTopologyOccurrence(**values)
    return _register_registry_occurrence(
        occurrence,
        occurrence.occurrence_id,
        _OBSERVED_LOWERED_CONDITIONAL_TOPOLOGY_REGISTRY,
    )


def validate_observed_lowered_conditional_topology_occurrence(
    occurrence: model.ObservedLoweredConditionalTopologyOccurrence,
) -> None:
    if type(occurrence) is not model.ObservedLoweredConditionalTopologyOccurrence:
        raise TypeError(
            "observed lowered conditional topology occurrence has unknown type",
        )
    occurrence.__post_init__()
    row = _OBSERVED_LOWERED_CONDITIONAL_TOPOLOGY_REGISTRY.get(id(occurrence))
    if row is None or row[0]() is not occurrence:
        raise ValueError(
            "observed lowered conditional topology occurrence was not minted by the binder",
        )
    if row[1] != occurrence.occurrence_id:
        raise ValueError(
            "observed lowered conditional topology occurrence content drifted",
        )


def _site_mint(
    cls: type[object], values: dict[str, object], *,
    identity_name: str | None = None,
    _batch: _AtomicPublicationBatch | None = None,
) -> object:
    value = object.__new__(cls)
    for name, item in values.items():
        object.__setattr__(value, name, item)
    if identity_name is not None:
        object.__setattr__(value, identity_name, "sha256:" + "0" * 64)
    if cls is model.RawEffectGatePhaseFact:
        object.__setattr__(value, "fact_id", raw_effect_gate_phase_fact_id(value))
    value.__post_init__()
    identity = getattr(value, identity_name) if identity_name is not None else (
        effect_site_coordinate_id(value) if cls is model.EffectSiteCoordinate
        else terminal_site_coordinate_id(value) if cls is model.TerminalSiteCoordinate
        else canonical_authority_id((type(value).__qualname__, canonical_bytes(value)))
    )
    if _batch is not None:
        return _batch.defer(
            value=value, registry=_SITE_REGISTRY, seal=identity,
        )
    return _register_site(value, identity)


def _require_registered_site_occurrence(
    value: object, _registry=_SITE_REGISTRY,
) -> None:
    if type(value) not in {
        model.EffectSiteCoordinate, model.TerminalSiteCoordinate,
        model.RawEffectGatePhaseFact, model.ScalarizedInstructionCoordinate,
    }:
        raise TypeError("semantic site value has an unknown closed type")
    row = _registry.get(id(value))
    if row is None or row[0]() is not value:
        raise ValueError("semantic site value was not minted by its binder")


def _validate_registered_site(
    value: object, _registry=_SITE_REGISTRY, *,
    _content_sealed: bool = False,
) -> None:
    _require_registered_site_occurrence(value, _registry)
    if _content_sealed:
        return
    row = _registry[id(value)]
    expected = _canonical_registry_seal(value, _registry)
    if row[1] != expected:
        raise ValueError("semantic site content seal does not match")


def validate_raw_effect_gate_phase_fact(value: model.RawEffectGatePhaseFact) -> None:
    """Validate one binder-minted raw gate fact at an authority boundary."""
    if type(value) is not model.RawEffectGatePhaseFact:
        raise TypeError("raw effect gate fact must be RawEffectGatePhaseFact")
    _validate_registered_site(value)


def _site_binding_identity(value: object) -> str:
    if type(value) is model.ExactEffectBindingResult:
        return exact_effect_binding_result_id(value)
    if type(value) is model.LocalAliasScalarizationBindingResult:
        return local_alias_binding_result_id(value)
    if type(value) is model.ProjectedEffectSiteResult:
        return projected_effect_site_result_id(value)
    if type(value) is model.ProjectedTerminalSiteResult:
        return projected_terminal_site_result_id(value)
    if type(value) is model.ProjectedSemanticSitePhaseResult:
        return projected_semantic_site_phase_result_id(value)
    if type(value) is model.ProjectedRouteSitePreservation:
        return projected_route_site_preservation_id(value)
    raise TypeError("semantic site binding has an unknown closed type")


def _site_binding_mint(
    cls: type[object], values: dict[str, object], identity_name: str,
    *, _batch: _AtomicPublicationBatch | None = None,
) -> object:
    value = object.__new__(cls)
    for name, item in values.items():
        object.__setattr__(value, name, item)
    object.__setattr__(value, identity_name, "sha256:" + "0" * 64)
    object.__setattr__(value, identity_name, _site_binding_identity(value))
    value.__post_init__()
    identity = getattr(value, identity_name)
    if _batch is not None:
        return _batch.defer(
            value=value, registry=_SITE_BINDING_REGISTRY,
            seal=identity,
        )
    return _register_site_binding(value, identity)


def _register_site_binding(
    value: object, identity: str,
    _registry=_SITE_BINDING_REGISTRY,
) -> object:
    return _register_registry_occurrence(value, identity, _registry)


def _require_registered_site_binding_occurrence(value: object) -> None:
    if type(value) not in {
        model.ExactEffectBindingResult, model.LocalAliasScalarizationBindingResult,
        model.ProjectedEffectSiteResult, model.ProjectedTerminalSiteResult,
        model.ProjectedSemanticSitePhaseResult, model.ProjectedRouteSitePreservation,
    }:
        raise TypeError("semantic site binding has an unknown closed type")
    row = _SITE_BINDING_REGISTRY.get(id(value))
    if row is None or row[0]() is not value:
        raise ValueError("semantic site binding was not minted by this binder")


def _validate_site_binding(
    value: object, identity_name: str, *, _content_sealed: bool = False,
) -> None:
    _require_registered_site_binding_occurrence(value)
    if _content_sealed:
        return
    row = _SITE_BINDING_REGISTRY[id(value)]
    expected = _canonical_registry_seal(value, _SITE_BINDING_REGISTRY)
    if row[1] != expected:
        raise ValueError("semantic site binding content seal does not match")


def validate_exact_effect_binding_result(
    value: model.ExactEffectBindingResult, *, _content_sealed: bool = False,
) -> None:
    _validate_site_binding(
        value, "binding_result_id", _content_sealed=_content_sealed,
    )


def validate_local_alias_binding_result(
    value: model.LocalAliasScalarizationBindingResult, *,
    _content_sealed: bool = False,
) -> None:
    _validate_site_binding(
        value, "binding_result_id", _content_sealed=_content_sealed,
    )


def validate_projected_effect_site_result(
    value: model.ProjectedEffectSiteResult, *, _content_sealed: bool = False,
) -> None:
    _validate_site_binding(value, "result_id", _content_sealed=_content_sealed)


def validate_projected_terminal_site_result(
    value: model.ProjectedTerminalSiteResult, *, _content_sealed: bool = False,
) -> None:
    _validate_site_binding(value, "result_id", _content_sealed=_content_sealed)


def validate_projected_site_phase_result(
    value: model.ProjectedSemanticSitePhaseResult, *,
    _content_sealed: bool = False,
) -> None:
    _validate_site_binding(value, "result_id", _content_sealed=_content_sealed)
    for binding in value.exact_effect_bindings:
        validate_exact_effect_binding_result(binding, _content_sealed=True)
    for binding in value.local_alias_bindings:
        validate_local_alias_binding_result(binding, _content_sealed=True)
    for result in value.effect_results:
        validate_projected_effect_site_result(result, _content_sealed=True)
    for result in value.terminal_results:
        validate_projected_terminal_site_result(result, _content_sealed=True)


def validate_projected_route_site_preservation(
    value: model.ProjectedRouteSitePreservation, *,
    _content_sealed: bool = False,
) -> None:
    _validate_site_binding(
        value, "preservation_id", _content_sealed=_content_sealed,
    )


def _inventory_owner_coordinate(
    inventory: model.SemanticGraphInventory,
    serial: int,
    *,
    label: str,
) -> model.AnchoredBlockRef:
    if type(serial) is not int or serial < 0:
        raise TypeError(f"{label} serial must be an exact non-negative int")
    rows = tuple(row for row in inventory.blocks if row.serial == serial)
    if len(rows) != 1:
        raise ValueError(f"{label} serial does not resolve one inventory row")
    row = rows[0]
    if row.block_ref is None or row.anchor_ea is None:
        raise ValueError(f"{label} serial has no stable owner identity")
    return model.AnchoredBlockRef(row.block_ref, row.anchor_ea)


def _validate_source_projected_lineage(
    source_inventory: model.SemanticGraphInventory,
    projected_inventory: model.SemanticGraphInventory,
) -> None:
    """Require the projected inventory to name this exact source domain."""
    if source_inventory.generation != projected_inventory.generation:
        raise ValueError("source/projected inventory generation lineage mismatch")
    if source_inventory.function_ea != projected_inventory.function_ea:
        raise ValueError("source/projected inventory function lineage mismatch")
    if source_inventory.source_subject_ids != projected_inventory.source_subject_ids:
        raise ValueError("source/projected inventory source subject lineage mismatch")


def _bind_effect_site_coordinate(
    inventory: model.SemanticGraphInventory,
    row: model.InventoryEffectSite,
    *, _batch: _AtomicPublicationBatch | None = None,
    _inventory_validated: bool = False,
) -> model.EffectSiteCoordinate:
    if type(row) is not model.InventoryEffectSite:
        raise TypeError("effect row must be InventoryEffectSite")
    if type(_inventory_validated) is not bool:
        raise TypeError("inventory validation state must be an exact bool")
    if not _inventory_validated:
        model.validate_semantic_graph_inventory(inventory)
    if row not in inventory.effects or sum(item is row for item in inventory.effects) != 1:
        raise ValueError("effect row is not the exact inventory-owned occurrence")
    if row.owner_serial not in inventory.reachable_serials:
        raise ValueError("effect row owner is not reachable")
    owner = _inventory_owner_coordinate(inventory, row.owner_serial, label="effect")
    if row.owner_ref != owner.ref or row.owner_anchor_ea != owner.anchor_ea:
        raise ValueError("effect row owner does not match inventory identity")
    return _site_mint(model.EffectSiteCoordinate, {
        "owner": owner,
        "instruction_ordinal": row.instruction_ordinal,
        "instruction_ea": row.instruction_ea,
        "effect_kind": row.effect_kind,
        "opcode": row.opcode,
        "width": row.width,
    }, _batch=_batch)


def _bind_terminal_site_coordinate(
    inventory: model.SemanticGraphInventory,
    row: model.InventoryTerminalSite,
    *, _batch: _AtomicPublicationBatch | None = None,
    _inventory_validated: bool = False,
) -> model.TerminalSiteCoordinate:
    if type(row) is not model.InventoryTerminalSite:
        raise TypeError("terminal row must be InventoryTerminalSite")
    if type(_inventory_validated) is not bool:
        raise TypeError("inventory validation state must be an exact bool")
    if not _inventory_validated:
        model.validate_semantic_graph_inventory(inventory)
    if row not in inventory.terminals or sum(item is row for item in inventory.terminals) != 1:
        raise ValueError("terminal row is not the exact inventory-owned occurrence")
    if row.owner_serial not in inventory.reachable_serials:
        raise ValueError("terminal row owner is not reachable")
    owner = _inventory_owner_coordinate(inventory, row.owner_serial, label="terminal")
    if row.owner_ref != owner.ref or row.owner_anchor_ea != owner.anchor_ea:
        raise ValueError("terminal row owner does not match inventory identity")
    return _site_mint(model.TerminalSiteCoordinate, {
        "owner": owner,
        "instruction_ordinal": row.instruction_ordinal,
        "instruction_ea": row.instruction_ea,
        "terminal_kind": row.terminal_kind,
    }, _batch=_batch)


def bind_raw_effect_gate_phase_fact(
    *,
    source_inventory: model.SemanticGraphInventory,
    projected_inventory: model.SemanticGraphInventory,
    raw_gate_facts: GenericEffectfulGateFacts,
    derived_claim_inventory: _DerivedTransactionClaimInventory | None = None,
) -> model.RawEffectGatePhaseFact:
    """Resolve the legacy raw serial DTO once against typed transaction facts.

    A legacy gate reports block owners, whereas a local STORE-to-MOV
    scalarization is an effect-site loss while its owner block remains
    reachable.  The typed, transaction-derived occurrence is therefore the
    only authority that may explain a raw lost owner which is still present in
    the projected inventory.  Raw serials never create that allowance.
    """
    if type(source_inventory) is not model.SemanticGraphInventory:
        raise TypeError("source_inventory must be SemanticGraphInventory")
    if type(projected_inventory) is not model.SemanticGraphInventory:
        raise TypeError("projected_inventory must be SemanticGraphInventory")
    if source_inventory.phase is not model.UnflattenAuthorityPhase.PRODUCER_FORECAST:
        raise ValueError("raw gate source inventory must be producer forecast")
    if projected_inventory.phase is not model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT:
        raise ValueError("raw gate projected inventory must be projected preflight")
    model.validate_semantic_graph_inventory(source_inventory)
    model.validate_semantic_graph_inventory(projected_inventory)
    _validate_source_projected_lineage(source_inventory, projected_inventory)
    if type(raw_gate_facts) is not GenericEffectfulGateFacts:
        raise TypeError("raw_gate_facts must be GenericEffectfulGateFacts")
    raw_gate_facts.__post_init__()
    if derived_claim_inventory is not None:
        _validate_derived_transaction_claim_inventory(derived_claim_inventory)
        if (
            derived_claim_inventory.source_inventory is not source_inventory
        ):
            raise ValueError("raw gate derived inventory differs from source inventory")

    source_rows = {row.serial: row for row in source_inventory.blocks}
    pre = raw_gate_facts.pre_effectful_block_serials
    retained = raw_gate_facts.post_reachable_effectful_block_serials
    lost = raw_gate_facts.lost_block_serials
    if any(type(serial) is not int for serial in (*pre, *retained, *lost)):
        raise TypeError("raw gate serials must be exact ints")
    if not pre == retained | lost or retained & lost:
        raise ValueError("raw gate serials must form a disjoint complete partition")
    if not pre <= set(source_rows):
        raise ValueError("raw gate serial is foreign to source inventory")
    expected_effect_owners = {
        row.owner_serial
        for row in source_inventory.effects
        if row.owner_serial in source_inventory.reachable_serials
    }
    raw_only = pre - expected_effect_owners
    if raw_only:
        raise ValueError(
            "raw gate contains a non-canonical effect owner "
            f"raw_only={tuple(sorted(raw_only))!r}"
        )
    source_owner_refs = {
        serial: source_rows[serial].block_ref for serial in expected_effect_owners
    }
    if any(ref is None for ref in source_owner_refs.values()):
        raise ValueError("canonical effect owner lacks an exact source reference")
    projected_serial_by_ref = projected_inventory.serial_by_ref
    structurally_retained = frozenset(
        serial
        for serial, ref in source_owner_refs.items()
        if (
            (projected_serial := projected_serial_by_ref.get(ref)) is not None
            and projected_serial in projected_inventory.reachable_serials
        )
    )
    structurally_lost = frozenset(expected_effect_owners) - structurally_retained
    local_scalarized_owners = frozenset(
        occurrence.source_site.owner_serial
        for occurrence in (
            () if derived_claim_inventory is None
            else derived_claim_inventory.local_alias_occurrences
        )
    )
    allowed_lost = structurally_lost | local_scalarized_owners
    if not lost <= allowed_lost:
        raise ValueError(
            "raw gate effect-owner disposition contradicts canonical inventory "
            f"lost_conflicts={tuple(sorted(lost - allowed_lost))!r}"
        )
    # Older gates can report only a subset of source effect owners.  Complete
    # that view from immutable structural reachability, exactly as before; a
    # reported typed scalarization loss is never inferred for an omitted owner.
    omitted = expected_effect_owners - pre
    retained = retained | (omitted & structurally_retained)
    lost = lost | (omitted & structurally_lost)
    pre = frozenset(expected_effect_owners)
    pre_owners = tuple(sorted(
        (_inventory_owner_coordinate(source_inventory, serial, label="raw pre") for serial in pre),
        key=canonical_bytes,
    ))
    retained_owners = tuple(sorted(
        (_inventory_owner_coordinate(source_inventory, serial, label="raw retained") for serial in retained),
        key=canonical_bytes,
    ))
    lost_owners = tuple(sorted(
        (_inventory_owner_coordinate(source_inventory, serial, label="raw lost") for serial in lost),
        key=canonical_bytes,
    ))
    values = {
        "phase": model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        "source_inventory_digest": source_inventory.inventory_digest,
        "projected_inventory_digest": projected_inventory.inventory_digest,
        "source_fingerprint": source_inventory.graph_fingerprint,
        "projected_fingerprint": projected_inventory.graph_fingerprint,
        "source_generation": source_inventory.generation,
        "projected_generation": projected_inventory.generation,
        "pre_effectful_source_owners": pre_owners,
        "raw_retained_source_owners": retained_owners,
        "raw_lost_source_owners": lost_owners,
        "generic_raw_payload_digest": canonical_authority_id((
            "unflatten.raw-effect-gate-payload.v1", raw_gate_facts,
        )),
        "fact_id": "sha256:" + "0" * 64,
    }
    return _site_mint(model.RawEffectGatePhaseFact, values, identity_name="fact_id")


def _claim_source_effect_row(
    claim: model.ExactInfeasibleEffectClaim,
    inventory: model.SemanticGraphInventory,
) -> model.InventoryEffectSite:
    locator = claim.effect_subject.locator
    matches = tuple(
        row for row in inventory.effects
        if row.owner_ref == locator.owner_ref
        and row.instruction_ea == locator.instruction_ea
        and row.effect_kind is locator.effect_kind
    )
    if len(matches) > 1:
        raise ValueError("exact-effect source site is ambiguous")
    return matches[0] if matches else None


def _canonical_semantic_site_owner_mapping(
    *, source_inventory: model.SemanticGraphInventory,
    source_owner: model.AnchoredBlockRef,
    clone_occurrences: tuple[tuple[str, model.AnchoredBlockRef, model.AnchoredBlockRef], ...],
) -> model.AnchoredBlockRef | None:
    """Return a single clone owner, or omit a site-free multi-clone source.

    Route incidence remains exhaustive elsewhere.  This narrower domain is only
    for semantic-site dispositions, which deliberately remain one per source
    row and therefore cannot choose between distinct clone coordinates.
    """
    clone_owners = {
        projected_owner
        for _relation_id, occurrence_source, projected_owner in clone_occurrences
        if occurrence_source == source_owner
    }
    if len(clone_owners) <= 1:
        return next(iter(clone_owners), None)
    has_site = any(
        row.owner_ref == source_owner.ref
        and row.owner_anchor_ea == source_owner.anchor_ea
        and row.owner_serial in source_inventory.reachable_serials
        for row in (*source_inventory.effects, *source_inventory.terminals)
    )
    if has_site:
        raise ValueError("conflicting clone mappings for semantic-site owner")
    return None


def bind_projected_exact_effect(
    *, authority_id: str, attempt_id: TransactionAttemptId,
    source_authority: model.SourceBoundRouteAuthority,
    claim: model.ExactInfeasibleEffectClaim,
    source_inventory: model.SemanticGraphInventory,
    projected_inventory: model.SemanticGraphInventory,
    relation_index: object,
    raw_effect_gate_fact: model.RawEffectGatePhaseFact,
) -> model.ExactEffectBindingResult:
    """Bind one exact-effect claim through the shared ID-free validator."""
    if type(source_authority) is not model.SourceBoundRouteAuthority:
        raise TypeError("source_authority must be SourceBoundRouteAuthority")
    if type(attempt_id) is not TransactionAttemptId:
        raise TypeError("attempt_id must be TransactionAttemptId")
    attempt_id.__post_init__()
    draft = _draft_exact_effect_binding(
        source_authority=source_authority, claim=claim,
        source_inventory=source_inventory, projected_inventory=projected_inventory,
        relation_index=relation_index, raw_effect_gate_fact=raw_effect_gate_fact,
    )
    relation_id = draft.relation_draft.relation.relation_id if hasattr(draft.relation_draft, "relation") else draft.relation_draft
    values = {
        "authority_id": authority_id, "source_authority_id": source_authority.source_authority_id,
        "attempt_id": attempt_id, "phase": model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        "claim": claim, "proof_id": claim.route_proof_ids[0],
        "supporting_route_relation_id": relation_id,
        "source_subject_ids": tuple(sorted({
            claim.effect_subject.subject_id, claim.source_subject.subject_id,
            claim.predicate_subject.subject_id, claim.selected_target_subject.subject_id,
            claim.discarded_effect_subject.subject_id,
        })),
        "source_site": _bind_effect_site_coordinate(source_inventory, draft.source_row),
        "source_inventory_digest": source_inventory.inventory_digest,
        "projected_inventory_digest": projected_inventory.inventory_digest,
        "source_fingerprint": source_inventory.graph_fingerprint,
        "projected_fingerprint": projected_inventory.graph_fingerprint,
        "source_generation": source_inventory.generation, "projected_generation": projected_inventory.generation,
        "raw_effect_gate_fact_id": raw_effect_gate_fact.fact_id,
        "binding_result_id": "sha256:" + "0" * 64,
    }
    return _site_binding_mint(model.ExactEffectBindingResult, values, "binding_result_id")


def bind_local_alias_scalarization(
    *, authority_id: str, attempt_id: TransactionAttemptId,
    claim: model.LocalAliasEffectScalarizationClaim,
    patch_step_fact: model.PatchStepEvidencePayload, patch_step_fact_id: str,
    source_inventory: model.SemanticGraphInventory,
    projected_inventory: model.SemanticGraphInventory,
) -> model.LocalAliasScalarizationBindingResult:
    """Bind one local alias through the shared ID-free validator."""
    if type(claim) is not model.LocalAliasEffectScalarizationClaim:
        raise TypeError("claim must be LocalAliasEffectScalarizationClaim")
    if type(attempt_id) is not TransactionAttemptId:
        raise TypeError("attempt_id must be TransactionAttemptId")
    attempt_id.__post_init__()
    draft = _draft_local_alias_binding(
        claim=claim, patch_step_fact=patch_step_fact,
        source_inventory=source_inventory, projected_inventory=projected_inventory,
    )
    if patch_step_fact_id != _canonical_patch_step_fact_id(patch_step_fact):
        raise ValueError("patch step fact ID does not match payload")
    scalarized = _site_mint(model.ScalarizedInstructionCoordinate, {
        "owner": model.AnchoredBlockRef(draft.projected_block.block_ref, draft.projected_block.anchor_ea),
        "instruction_ordinal": draft.projected_observation.ordinal,
        "instruction_ea": draft.projected_observation.instruction_ea,
        "instruction_kind": InsnKind.MOV, "opcode": draft.projected_observation.opcode,
        "raw_opcode": draft.projected_observation.raw_opcode,
        "width": draft.projected_observation.width,
        "display_text_digest": canonical_authority_id(("scalarized-display-text", draft.projected_observation.display_text)),
    })
    values = {
        "authority_id": authority_id, "attempt_id": attempt_id,
        "phase": model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        "claim": claim, "source_subject_id": claim.owner_subject.subject_id,
        "source_site": _bind_effect_site_coordinate(source_inventory, draft.source_row),
        "scalarized_site": scalarized, "patch_step_fact": patch_step_fact,
        "patch_step_fact_id": _canonical_patch_step_fact_id(patch_step_fact),
        "source_inventory_digest": source_inventory.inventory_digest,
        "projected_inventory_digest": projected_inventory.inventory_digest,
        "source_fingerprint": source_inventory.graph_fingerprint,
        "projected_fingerprint": projected_inventory.graph_fingerprint,
        "source_generation": source_inventory.generation,
        "projected_generation": projected_inventory.generation,
        "binding_result_id": "sha256:" + "0" * 64,
    }
    return _site_binding_mint(model.LocalAliasScalarizationBindingResult, values, "binding_result_id")

def _draft_exact_effect_binding(
    *, source_authority: model.SourceBoundRouteAuthority,
    claim: model.ExactInfeasibleEffectClaim,
    source_inventory: model.SemanticGraphInventory,
    projected_inventory: model.SemanticGraphInventory,
    relation_index: object,
    raw_effect_gate_fact: model.RawEffectGatePhaseFact,
    relation_draft: object | None = None,
) -> _ExactEffectBindingDraft:
    """Validate exact-effect inputs into an ID-free, closure-private draft."""
    if type(source_authority) is not model.SourceBoundRouteAuthority:
        raise TypeError("source_authority must be SourceBoundRouteAuthority")
    if type(claim) is not model.ExactInfeasibleEffectClaim:
        raise TypeError("claim must be ExactInfeasibleEffectClaim")
    for inventory, phase in (
        (source_inventory, model.UnflattenAuthorityPhase.PRODUCER_FORECAST),
        (projected_inventory, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT),
    ):
        if type(inventory) is not model.SemanticGraphInventory or inventory.phase is not phase:
            raise ValueError("exact-effect inventories have wrong phase")
        model.validate_semantic_graph_inventory(inventory)
    validate_raw_effect_gate_phase_fact(raw_effect_gate_fact)
    _validate_source_projected_lineage(source_inventory, projected_inventory)
    if claim not in source_authority.proposal.claims:
        raise ValueError("exact-effect claim is foreign to source authority")
    if claim.source_generation != source_inventory.generation:
        raise ValueError("exact-effect claim generation mismatch")
    proof_id = claim.route_proof_ids[0]
    proof = next((item for item in source_authority.proposal.route_evidence.route_proofs if item.proof_id == proof_id), None)
    if proof is None:
        raise ValueError("exact-effect proof is foreign to source authority")
    source_row = _claim_source_effect_row(claim, source_inventory)
    if source_row is None:
        raise ValueError("exact-effect source site is absent")
    if (
        source_row.instruction_ea != claim.discarded_effect_ea
        or source_row.effect_kind is not claim.effect_subject.locator.effect_kind
        or source_row.width != claim.width
        or claim.effect_subject.locator.owner_anchor_ea != source_row.owner_anchor_ea
    ):
        raise ValueError("exact-effect source site drifts from claim")
    source_locator = claim.source_subject.locator
    predicate_locator = claim.predicate_subject.locator
    if hasattr(proof, "source_owner_anchor_ea") and source_locator.anchor_ea != proof.source_owner_anchor_ea:
        raise ValueError("exact-effect source coordinate drifts from proof")
    if getattr(proof, "predicate", None) is not None:
        predicate = proof.predicate
        if (
            predicate_locator.anchor_ea != proof.source_anchor_ea
            or not _ref_matches_identity(
                predicate_locator.block_ref, proof.source_identity,
            )
            or predicate.consumer.anchor_ea != claim.predicate_branch_ea
        ):
            raise ValueError("exact-effect predicate coordinate drifts from proof")
        if predicate.storage_identity != claim.state_identity or predicate.width != claim.width:
            raise ValueError("exact-effect predicate state proof drifts from claim")
    if getattr(proof, "state_write", None) is not None:
        write = proof.state_write
        if write.state_variable != claim.state_identity or write.width != claim.width:
            raise ValueError("exact-effect state-write proof drifts from claim")
        if write.instruction_ea != claim.source_write_ea:
            raise ValueError("exact-effect source-write EA drifts from claim")
    selected_target = claim.selected_target_subject.block_ref
    relation_id = next(
        (candidate for key, candidate in getattr(relation_index, "relations_by_key", ())
         if key[0] == proof_id and key[1] == selected_target),
        None,
    )
    if relation_id is None:
        raise ValueError("exact-effect relation is missing")
    if source_row.owner_ref not in {owner.ref for owner in raw_effect_gate_fact.pre_effectful_source_owners}:
        raise ValueError("exact-effect owner is absent from raw pre partition")
    if relation_draft is None:
        relation_draft = relation_id
    return _ExactEffectBindingDraft(
        claim=claim, proof=proof, source_authority=source_authority,
        relation_draft=relation_draft, source_row=source_row,
        raw_effect_gate_fact=raw_effect_gate_fact,
        source_inventory=source_inventory, projected_inventory=projected_inventory,
    )


def _draft_local_alias_binding(
    *, claim: model.LocalAliasEffectScalarizationClaim,
    patch_step_fact: model.PatchStepEvidencePayload,
    source_inventory: model.SemanticGraphInventory,
    projected_inventory: model.SemanticGraphInventory,
    _allow_route_owned_retirement: bool = False,
) -> _LocalAliasBindingDraft:
    """Validate local STORE/MOV grammar without minting coordinates or IDs."""
    if type(claim) is not model.LocalAliasEffectScalarizationClaim:
        raise TypeError("claim must be LocalAliasEffectScalarizationClaim")
    if type(patch_step_fact) is not model.PatchStepEvidencePayload:
        raise TypeError("patch_step_fact must be PatchStepEvidencePayload")
    if (
        patch_step_fact.step_index != claim.step_index
        or patch_step_fact.host_ea != claim.host_ea
        or patch_step_fact.host_opcode != claim.host_opcode
        or patch_step_fact.step_digest != claim.step_digest
    ):
        raise ValueError("local-alias patch step does not match claim")
    if type(source_inventory) is not model.SemanticGraphInventory or type(projected_inventory) is not model.SemanticGraphInventory:
        raise TypeError("local-alias inventories must be SemanticGraphInventory")
    if claim.source_generation != source_inventory.generation:
        raise ValueError("local-alias claim generation mismatch")
    model.validate_semantic_graph_inventory(source_inventory)
    model.validate_semantic_graph_inventory(projected_inventory)
    source_row = next(
        (row for row in source_inventory.effects
         if row.owner_ref == claim.owner_subject.block_ref
         and row.owner_anchor_ea == claim.owner_subject.anchor_ea
         and row.instruction_ea == claim.host_ea
         and row.effect_kind is model.EffectSiteKind.STORE),
        None,
    )
    if source_row is None:
        raise ValueError("local-alias source STORE is missing")
    if source_row.opcode != claim.host_opcode:
        raise ValueError("local-alias STORE opcode differs from claim")
    source_blocks = tuple(
        row for row in source_inventory.blocks
        if row.block_ref == claim.owner_subject.block_ref
        and row.serial == source_row.owner_serial
        and row.anchor_ea == source_row.owner_anchor_ea
    )
    if len(source_blocks) != 1:
        raise ValueError("local-alias source STORE owner is ambiguous")
    source_observations = tuple(
        item for item in source_blocks[0].instruction_observations
        if item.ordinal == source_row.instruction_ordinal
        and item.instruction_ea == source_row.instruction_ea
    )
    if len(source_observations) != 1:
        raise ValueError("local-alias source STORE observation is missing")
    source_observation = source_observations[0]
    if (
        source_observation.instruction_kind is not InsnKind.STORE
        or source_observation.opcode != source_row.opcode
        or source_observation.raw_opcode is None
        or source_observation.width != source_row.width
        or (
            claim.value_size is not None
            and source_observation.width != claim.value_size
        )
        or source_observation.is_call
        or source_observation.call_kind is not None
        or source_observation.control_transfer_kind is not None
    ):
        raise ValueError("local-alias source STORE observation differs")
    projected_blocks = tuple(
        row for row in projected_inventory.blocks
        if row.block_ref == claim.owner_subject.block_ref
        and row.serial == source_row.owner_serial
        and row.anchor_ea == source_row.owner_anchor_ea
    )
    block = projected_blocks[0] if len(projected_blocks) == 1 else None
    if block is None:
        raise ValueError("local-alias projected owner is missing")
    if (
        block.serial not in projected_inventory.reachable_serials
        and not _allow_route_owned_retirement
    ):
        raise ValueError("local-alias projected owner is unreachable")
    projected_widths = {
        width for width in (
            claim.value_size,
            source_observation.width,
            (
                claim.owner_subject.block_ref.identity.native_key.bitness // 8
                if type(claim.owner_subject.block_ref) is NativeBlockRef
                else None
            ),
        )
        if type(width) is int and not isinstance(width, bool) and width > 0
    }
    observations = tuple(
        item for item in block.instruction_observations
        if item.instruction_ea == claim.host_ea
        and item.width in projected_widths
        and item.instruction_kind is InsnKind.MOV
    )
    if len(observations) != 1:
        raise ValueError(
            "local-alias requires one exact MOV observation: "
            f"host=0x{claim.host_ea:X} width={claim.value_size!r} "
            f"observed={tuple((item.ordinal, item.instruction_ea, item.width, item.instruction_kind.value, item.display_text) for item in block.instruction_observations)!r}"
        )
    observation = observations[0]
    if (
        observation.opcode != claim.host_opcode
        or observation.opcode != source_observation.opcode
        or observation.raw_opcode != source_observation.raw_opcode
        or observation.width not in projected_widths
        or observation.is_call
        or observation.call_kind is not None
    ):
        raise ValueError("local-alias candidate MOV opcode/control differs from claim")
    if observation.control_transfer_kind is not None:
        raise ValueError("local-alias candidate MOV has a control transfer")
    if type(observation.display_text) is not str:
        raise ValueError("local-alias MOV lacks closed display text")
    grammar = (
        rf"\s*{re.escape(claim.alias_token)}\s*=\s*"
        rf"(?:(?i:byte|word|dword|qword)\s+(?i:ptr)\s+)?"
        rf"{re.escape(claim.base_token)}\s*"
    )
    if re.fullmatch(grammar, observation.display_text) is None:
        raise ValueError("local-alias MOV does not match closed scalar grammar")
    return _LocalAliasBindingDraft(
        claim=claim, patch_step_fact=patch_step_fact, source_row=source_row,
        source_observation=source_observation,
        projected_block=block, projected_observation=observation,
        source_inventory=source_inventory, projected_inventory=projected_inventory,
    )


def _local_alias_has_route_owned_retirement(
    *,
    claim: model.LocalAliasEffectScalarizationClaim,
    projected_inventory: model.SemanticGraphInventory,
    drafts: tuple[object, ...],
    owner_index: object,
) -> bool:
    """Return whether one exact route relation owns an unreachable alias site.

    A scalarization claim proves the STORE-to-MOV semantic normalization.  It
    does not independently authorize structural loss of its owner.  When the
    transformed owner is outside the projected closure, the same owner must
    also occur in exactly one already-validated structural route relation.
    """

    source_owner = model.AnchoredBlockRef(
        claim.owner_subject.block_ref,
        claim.owner_subject.anchor_ea,
    )
    blocks = tuple(
        row for row in projected_inventory.blocks
        if row.block_ref == source_owner.ref
        and row.anchor_ea == source_owner.anchor_ea
    )
    if len(blocks) != 1:
        return False
    if blocks[0].serial in projected_inventory.reachable_serials:
        return False
    relation_ids = {
        occurrence.relation_id
        for occurrence in getattr(owner_index, "relation_owner_occurrences", ())
        if occurrence.source_owner == source_owner
    }
    if len(relation_ids) != 1:
        return False
    relation_id = next(iter(relation_ids))
    return sum(
        getattr(getattr(draft, "relation", None), "relation_id", None)
        == relation_id
        for draft in drafts
    ) == 1


def _site_subject(inventory: model.SemanticGraphInventory, row: object) -> object:
    for binding in inventory.bindings:
        subject = binding.subject
        locator = getattr(subject, "locator", None)
        if isinstance(row, model.InventoryEffectSite):
            if (
                getattr(locator, "owner_ref", None) == row.owner_ref
                and getattr(locator, "instruction_ea", None) == row.instruction_ea
                and getattr(locator, "effect_kind", None) is row.effect_kind
            ):
                return subject
        elif isinstance(row, model.InventoryTerminalSite):
            if (
                getattr(locator, "block_ref", None) == row.owner_ref
                and getattr(locator, "instruction_ea", None) == row.instruction_ea
                and getattr(locator, "terminal_kind", None) is row.terminal_kind
            ):
                return subject
    return canonical_authority_id((
        "projected-effect-site-subject" if isinstance(row, model.InventoryEffectSite)
        else "projected-terminal-site-subject",
        row.owner_ref, row.instruction_ea, getattr(row, "effect_kind", getattr(row, "terminal_kind", None)),
    ))


def _draft_projected_site_closure(
    *, authority_id: str, source_authority: model.SourceBoundRouteAuthority,
    plan: PatchPlan, source_inventory: model.SemanticGraphInventory,
    projected_inventory: model.SemanticGraphInventory,
    claims: tuple[object, ...], patch_step_facts: tuple[model.PatchStepEvidencePayload, ...],
    raw_effect_gate_fact: model.RawEffectGatePhaseFact,
    legacy_effective_gate_facts: object, attempt_id: TransactionAttemptId,
    drafts: tuple[object, ...], owner_index: object,
) -> _ProjectedSiteClosureDraft:
    """Discover the site closure without minting any coordinate or result."""
    del authority_id, plan, attempt_id
    exact_claims = tuple(item for item in claims if type(item) is model.ExactInfeasibleEffectClaim)
    alias_claims = tuple(item for item in claims if type(item) is model.LocalAliasEffectScalarizationClaim)
    exact_by_site = {
        (item.effect_subject.locator.owner_ref, item.effect_subject.locator.instruction_ea, item.effect_subject.locator.effect_kind): item
        for item in exact_claims
    }
    alias_by_site = {(item.owner_subject.block_ref, item.host_ea): item for item in alias_claims}
    relation_by_key = {}
    for item in drafts:
        relation_by_key[(item.proof_id, item.selected_target_ref)] = item
    relation_by_id = {
        item.relation.relation_id: item for item in drafts
    }
    relation_occurrences = tuple(owner_index.relation_owner_occurrences)

    def relation_for_owner(owner: object) -> object | None:
        matches = {
            occurrence.relation_id
            for occurrence in relation_occurrences
            if occurrence.source_owner == owner
        }
        if len(matches) != 1:
            return None
        return relation_by_id.get(next(iter(matches)))
    exact_binding_drafts: list[_ExactEffectBindingDraft] = []
    for claim in exact_claims:
        proof_id = claim.route_proof_ids[0]
        relation_draft = relation_by_key.get((proof_id, claim.selected_target_subject.block_ref))
        try:
            exact_binding_drafts.append(_draft_exact_effect_binding(
                source_authority=source_authority, claim=claim,
                source_inventory=source_inventory, projected_inventory=projected_inventory,
                relation_index=owner_index, raw_effect_gate_fact=raw_effect_gate_fact,
                relation_draft=relation_draft,
            ))
        except (TypeError, ValueError) as exc:
            proof = next(
                (item for item in getattr(getattr(source_authority, "proposal", None), "route_evidence", ()).route_proofs
                 if item.proof_id == proof_id),
                None,
            ) if hasattr(getattr(source_authority, "proposal", None), "route_evidence") else None
            source_row = None
            try:
                source_row = _claim_source_effect_row(claim, source_inventory)
            except (TypeError, ValueError):
                pass
            raise _ProjectedSiteDraftViolation(
                str(exc), scope=model.RouteRealizationFailureScope.STEP,
                relation_draft=relation_draft, claim=claim, proof=proof,
                source_row=source_row,
            ) from exc
    patch_by_index = {fact.step_index: fact for fact in patch_step_facts}
    local_binding_drafts: list[_LocalAliasBindingDraft] = []
    for claim in alias_claims:
        fact = patch_by_index.get(claim.step_index)
        if fact is None:
            raise _ProjectedSiteDraftViolation(
                "local-alias patch step fact is missing",
                scope=model.RouteRealizationFailureScope.STEP, claim=claim,
            )
        try:
            route_owned_retirement = _local_alias_has_route_owned_retirement(
                claim=claim,
                projected_inventory=projected_inventory,
                drafts=drafts,
                owner_index=owner_index,
            )
            local_binding_drafts.append(_draft_local_alias_binding(
                claim=claim, patch_step_fact=fact,
                source_inventory=source_inventory, projected_inventory=projected_inventory,
                _allow_route_owned_retirement=route_owned_retirement,
            ))
        except (TypeError, ValueError) as exc:
            source_row = next(
                (row for row in source_inventory.effects
                 if row.owner_ref == claim.owner_subject.block_ref
                 and row.owner_anchor_ea == claim.owner_subject.anchor_ea
                 and row.instruction_ea == claim.host_ea),
                None,
            )
            source_owner = model.AnchoredBlockRef(
                claim.owner_subject.block_ref,
                claim.owner_subject.anchor_ea,
            )
            owner_rows = tuple(
                item for item in getattr(owner_index, "owner_rows", ())
                if item.source_owner == source_owner
            )
            relation_occurrences = tuple(
                item
                for item in getattr(owner_index, "relation_owner_occurrences", ())
                if item.source_owner == source_owner
            )
            projected_blocks = tuple(
                (
                    row.serial,
                    row.anchor_ea,
                    row.successor_serials,
                    row.serial in projected_inventory.reachable_serials,
                )
                for row in projected_inventory.blocks
                if row.block_ref == claim.owner_subject.block_ref
                or row.anchor_ea == claim.owner_subject.anchor_ea
            )
            logger.warning(
                "local-alias projected binding context: claim=%s step=%d "
                "source=%r owner_rows=%r relation_occurrences=%r projected_blocks=%r",
                claim.claim_id,
                claim.step_index,
                (source_row.owner_serial, source_row.owner_anchor_ea)
                if source_row is not None else None,
                owner_rows,
                relation_occurrences,
                projected_blocks,
            )
            raise _ProjectedSiteDraftViolation(
                str(exc), scope=model.RouteRealizationFailureScope.STEP,
                claim=claim, patch_step_fact=fact, source_row=source_row,
            ) from exc
    exact_by_claim = {item.claim.claim_id: item for item in exact_binding_drafts}
    alias_by_claim = {item.claim.claim_id: item for item in local_binding_drafts}
    effect_dispositions: list[_ProjectedEffectDispositionDraft] = []
    terminal_dispositions: list[_ProjectedTerminalDispositionDraft] = []
    for source_row in source_inventory.effects:
        if source_row.owner_serial not in source_inventory.reachable_serials:
            continue
        source_subject = _site_subject(source_inventory, source_row)
        source_owner = next(
            (item for item in owner_index.owner_rows
             if item.source_owner.ref == source_row.owner_ref
             and item.source_owner.anchor_ea == source_row.owner_anchor_ea),
            None,
        )
        projected_owner = source_owner.projected_owner.ref if source_owner is not None else source_row.owner_ref
        candidates = tuple(
            row for row in projected_inventory.effects
            if row.owner_serial in projected_inventory.reachable_serials
            and row.owner_ref == projected_owner
            and row.instruction_ea == source_row.instruction_ea
            and row.effect_kind is source_row.effect_kind
        )
        exact_candidates = tuple(
            row for row in candidates
            if row.opcode == source_row.opcode and row.width == source_row.width
        )
        if candidates and not exact_candidates:
            raise _ProjectedSiteDraftViolation(
                "projected effect site opcode/width drifted",
                scope=model.RouteRealizationFailureScope.STEP,
                source_row=source_row,
                relation_draft=relation_for_owner(
                    source_owner.source_owner if source_owner is not None else None,
                ),
            )
        if len(exact_candidates) > 1:
            raise _ProjectedSiteDraftViolation(
                "projected effect site is ambiguous",
                scope=model.RouteRealizationFailureScope.STEP, source_row=source_row,
            )
        projected_row = exact_candidates[0] if exact_candidates else None
        exact_claim = exact_by_site.get((source_row.owner_ref, source_row.instruction_ea, source_row.effect_kind))
        alias_claim = alias_by_site.get((source_row.owner_ref, source_row.instruction_ea))
        relation_draft = relation_for_owner(
            source_owner.source_owner if source_owner is not None else None,
        )
        if projected_row is not None:
            lineage = source_owner.lineage if source_owner is not None else model.ProjectedSiteLineageKind.SAME_OWNER
            outcome = (
                model.ProjectedEffectSiteOutcome.RELATION_CLONED
                if lineage is model.ProjectedSiteLineageKind.RELATION_CLONE
                else model.ProjectedEffectSiteOutcome.PRESERVED
            )
            projected_subject = _site_subject(projected_inventory, projected_row)
        elif alias_claim is not None:
            lineage = None
            outcome = model.ProjectedEffectSiteOutcome.LOCAL_ALIAS_SCALARIZED
            projected_subject = None
        elif exact_claim is not None:
            lineage = None
            outcome = model.ProjectedEffectSiteOutcome.EXACT_INFEASIBLE
            projected_subject = None
        else:
            # Do not turn a missing allowance into an independent binder
            # verdict.  Seal the exact missing site and let the transaction
            # case/ledger classify it UNCLASSIFIED; every projected gate then
            # rejects the same canonical result atomically.
            lineage = None
            outcome = model.ProjectedEffectSiteOutcome.UNCLASSIFIED
            projected_subject = None
        effect_dispositions.append(_ProjectedEffectDispositionDraft(
            source_row=source_row, source_subject=source_subject,
            owner_mapping=source_owner, projected_row=projected_row,
            projected_subject=projected_subject, outcome=outcome, lineage=lineage,
            relation_draft=relation_draft,
            exact_binding=exact_by_claim.get(exact_claim.claim_id) if exact_claim is not None else None,
            local_binding=alias_by_claim.get(alias_claim.claim_id) if alias_claim is not None else None,
            patch_step_fact=(alias_by_claim[alias_claim.claim_id].patch_step_fact
                             if alias_claim is not None and alias_claim.claim_id in alias_by_claim
                             else None),
        ))
    for source_row in source_inventory.terminals:
        if source_row.owner_serial not in source_inventory.reachable_serials:
            continue
        source_subject = _site_subject(source_inventory, source_row)
        source_owner = next(
            (item for item in owner_index.owner_rows
             if item.source_owner.ref == source_row.owner_ref
             and item.source_owner.anchor_ea == source_row.owner_anchor_ea),
            None,
        )
        co_located_exact = next(
            (
                binding for binding in exact_binding_drafts
                if binding.source_row.owner_ref == source_row.owner_ref
                and binding.source_row.owner_anchor_ea == source_row.owner_anchor_ea
                and binding.source_row.instruction_ea == source_row.instruction_ea
                and binding.source_row.instruction_ordinal == source_row.instruction_ordinal
            ),
            None,
        )
        diagnostic_relation = (
            relation_for_owner(
                source_owner.source_owner if source_owner is not None else None,
            )
            if source_owner is not None else
            getattr(co_located_exact, "relation_draft", None)
        )
        projected_owner = source_owner.projected_owner.ref if source_owner is not None else source_row.owner_ref
        candidates = tuple(
            row for row in projected_inventory.terminals
            if row.owner_serial in projected_inventory.reachable_serials
            and row.owner_ref == projected_owner
            and row.instruction_ea == source_row.instruction_ea
            and row.terminal_kind is source_row.terminal_kind
            and row.instruction_ordinal == source_row.instruction_ordinal
        )
        if len(candidates) != 1:
            raise _ProjectedSiteDraftViolation(
                "terminal site is missing or ambiguous",
                scope=(model.RouteRealizationFailureScope.STEP if diagnostic_relation is not None
                       else model.RouteRealizationFailureScope.EVIDENCE),
                relation_draft=diagnostic_relation,
                source_row=source_row,
            )
        projected_row = candidates[0]
        lineage = source_owner.lineage if source_owner is not None else model.ProjectedSiteLineageKind.SAME_OWNER
        outcome = (
            model.ProjectedTerminalSiteOutcome.RELATION_CLONED
            if lineage is model.ProjectedSiteLineageKind.RELATION_CLONE
            else model.ProjectedTerminalSiteOutcome.PRESERVED
        )
        terminal_dispositions.append(_ProjectedTerminalDispositionDraft(
            source_row=source_row, source_subject=source_subject,
            owner_mapping=source_owner, projected_row=projected_row,
            projected_subject=_site_subject(projected_inventory, projected_row),
            outcome=outcome, lineage=lineage,
            relation_draft=relation_for_owner(
                source_owner.source_owner if source_owner is not None else None,
            ),
        ))
    subsets: list[_RouteSiteSubsetDraft] = []
    for relation_draft in drafts:
        source_owners = {
            item.source_owner for item in relation_occurrences
            if item.relation_id == relation_draft.relation.relation_id
        }
        subsets.append(_RouteSiteSubsetDraft(
            relation_draft=relation_draft,
            effect_dispositions=tuple(item for item in effect_dispositions if item.owner_mapping in owner_index.owner_rows and item.owner_mapping.source_owner in source_owners),
            terminal_dispositions=tuple(item for item in terminal_dispositions if item.owner_mapping in owner_index.owner_rows and item.owner_mapping.source_owner in source_owners),
        ))
    return _ProjectedSiteClosureDraft(
        exact_binding_drafts=tuple(exact_binding_drafts),
        local_binding_drafts=tuple(local_binding_drafts),
        effect_dispositions=tuple(effect_dispositions),
        terminal_dispositions=tuple(terminal_dispositions),
        route_subsets=tuple(subsets),
        raw_retained_source_owners=raw_effect_gate_fact.raw_retained_source_owners,
        raw_lost_source_owners=raw_effect_gate_fact.raw_lost_source_owners,
    )


def _unclassified_effect_cut_frontier(
    *,
    source_inventory: model.SemanticGraphInventory,
    projected_inventory: model.SemanticGraphInventory,
    plan: PatchPlan,
    patch_step_facts: tuple[model.PatchStepEvidencePayload, ...],
    owner_serial: int,
) -> tuple[tuple[object, ...], tuple[object, ...], tuple[object, ...]]:
    """Attribute a missing effect site to inventory-visible candidate cuts.

    This is diagnostic-only: it reverse-walks source topology through candidate
    unreachable blocks and reports the first reachable-to-unreachable edges.
    It neither assesses a route nor changes the site disposition.
    """
    source_blocks = {row.serial: row for row in source_inventory.blocks}
    projected_serial_by_ref = projected_inventory.serial_by_ref
    projected_reachable = set(projected_inventory.reachable_serials)

    def candidate_reachable(serial: int) -> bool:
        row = source_blocks.get(serial)
        if row is None or row.block_ref is None:
            return False
        projected_serial = projected_serial_by_ref.get(row.block_ref)
        return (
            projected_serial is not None
            and projected_serial in projected_reachable
        )

    predecessors: dict[int, list[model.InventoryTopologyIncidence]] = {}
    for incidence in source_inventory.topology:
        if incidence.kind is model.TopologyIncidenceKind.SUCCESSOR:
            predecessors.setdefault(incidence.peer_serial, []).append(incidence)

    frontier: list[object] = []
    seen: set[int] = set()
    pending = [owner_serial]
    while pending:
        target_serial = pending.pop()
        if target_serial in seen:
            continue
        seen.add(target_serial)
        for incidence in sorted(
            predecessors.get(target_serial, ()),
            key=lambda row: (
                row.owner_serial,
                row.peer_serial,
                -1 if row.source_transfer_ea is None else row.source_transfer_ea,
            ),
        ):
            source_serial = incidence.owner_serial
            source_row = source_blocks.get(source_serial)
            target_row = source_blocks.get(target_serial)
            if candidate_reachable(source_serial):
                frontier.append((
                    source_serial,
                    None if source_row is None else source_row.block_ref,
                    None if source_row is None else source_row.anchor_ea,
                    target_serial,
                    None if target_row is None else target_row.block_ref,
                    None if target_row is None else target_row.anchor_ea,
                    incidence.source_transfer_ea,
                ))
            else:
                pending.append(source_serial)
    frontier_rows = tuple(sorted(frontier, key=canonical_bytes))
    endpoint_refs = {
        ref
        for edge in frontier_rows
        for ref in (edge[1], edge[4])
        if ref is not None
    }
    # This helper only renders failure context.  Reconstructing canonical step
    # descriptors here would introduce a second validation authority beside
    # _index_lineage_fact_groups.  The closed fact payload already carries the
    # relevant operation coordinates for every endpoint-owned cut.
    endpoint_facts = tuple(
        fact
        for fact in patch_step_facts
        if fact.owner_ref in endpoint_refs
    )
    descriptor_rows = tuple(
        (
            fact.step_index,
            fact.step_type,
            fact.owner_ref,
            fact.host_ea,
            fact.host_opcode,
            fact.value_size,
            fact.step_digest,
        )
        for fact in endpoint_facts
    )
    descriptor_indices = {fact.step_index for fact in endpoint_facts}
    fact_rows = tuple(
        (
            fact.step_index,
            fact.step_type,
            fact.owner_ref,
            fact.host_ea,
            fact.host_opcode,
            fact.value_size,
            fact.step_digest,
        )
        for fact in patch_step_facts
        if (
            fact.owner_ref in endpoint_refs
            or fact.step_index in descriptor_indices
        )
    )
    return frontier_rows, descriptor_rows, fact_rows


def _validate_projected_site_closure_draft(
    draft: _ProjectedSiteClosureDraft, *, source_authority: model.SourceBoundRouteAuthority,
    plan: PatchPlan, source_inventory: model.SemanticGraphInventory,
    projected_inventory: model.SemanticGraphInventory,
    claims: tuple[object, ...], patch_step_facts: tuple[model.PatchStepEvidencePayload, ...],
    raw_effect_gate_fact: model.RawEffectGatePhaseFact,
    legacy_effective_gate_facts: object, attempt_id: TransactionAttemptId,
    drafts: tuple[object, ...], owner_index: object,
    route_publications: tuple[tuple[object, str], ...],
) -> None:
    """Reconstruct and validate every draft invariant without minting."""
    if type(draft) is not _ProjectedSiteClosureDraft:
        raise _ProjectedSiteDraftViolation("projected site draft has an unknown type", scope=model.RouteRealizationFailureScope.EVIDENCE)
    if type(source_authority) is not model.SourceBoundRouteAuthority or type(plan) is not PatchPlan:
        raise _ProjectedSiteDraftViolation("canonical route context is foreign", scope=model.RouteRealizationFailureScope.EVIDENCE)
    if plan.unflatten_proposal is not source_authority.proposal or type(attempt_id) is not TransactionAttemptId:
        raise _ProjectedSiteDraftViolation("canonical route context occurrence differs", scope=model.RouteRealizationFailureScope.EVIDENCE)
    attempt_id.__post_init__()
    proposal_claims = source_authority.proposal.claims
    if type(claims) is not tuple or claims != tuple(sorted(
        claims, key=lambda item: item.claim_id,
    )) or len({item.claim_id for item in claims}) != len(claims):
        raise _ProjectedSiteDraftViolation("claim tuple is not authority-owned", scope=model.RouteRealizationFailureScope.EVIDENCE)
    selected_proposal_claims = tuple(
        item for canonical in proposal_claims
        for item in claims if item is canonical
    )
    local_claims_only = tuple(
        item for item in claims
        if type(item) is model.LocalAliasEffectScalarizationClaim
    )
    if (
        len(selected_proposal_claims) != len(proposal_claims)
        or any(
            item is not canonical
            for item, canonical in zip(selected_proposal_claims, proposal_claims)
        )
        or len(claims) != len(proposal_claims) + len(local_claims_only)
    ):
        raise _ProjectedSiteDraftViolation("claim tuple is not authority-owned", scope=model.RouteRealizationFailureScope.EVIDENCE)
    if (
        type(patch_step_facts) is not tuple
        or any(type(fact) is not model.PatchStepEvidencePayload for fact in patch_step_facts)
        or patch_step_facts != tuple(sorted(patch_step_facts, key=patch_step_fact_id))
        or len({patch_step_fact_id(fact) for fact in patch_step_facts})
        != len(patch_step_facts)
    ):
        raise _ProjectedSiteDraftViolation("patch-step facts are not canonical", scope=model.RouteRealizationFailureScope.EVIDENCE)
    if type(drafts) is not tuple:
        raise _ProjectedSiteDraftViolation("structural draft tuple is not canonical", scope=model.RouteRealizationFailureScope.EVIDENCE)
    if drafts and any(type(item) is not type(drafts[0]) for item in drafts):
        raise _ProjectedSiteDraftViolation("structural draft tuple is not canonical", scope=model.RouteRealizationFailureScope.EVIDENCE)
    expected_route_publications: list[object] = []
    for structural in drafts:
        relation = structural.relation
        if type(relation) in {
            model.ClonedRouteCorridorRealization,
            model.ClonedCarrierRouteCorridorRealization,
        }:
            for prefix in relation.semantic_prefixes:
                expected_route_publications.extend(prefix.instruction_origins)
                expected_route_publications.append(prefix)
        expected_route_publications.append(relation)
    if (
        type(route_publications) is not tuple
        or len(route_publications) != len(expected_route_publications)
    ):
        raise _ProjectedSiteDraftViolation(
            "structural route publication batch differs",
            scope=model.RouteRealizationFailureScope.EVIDENCE,
        )
    for publication, expected in zip(route_publications, expected_route_publications):
        if type(publication) is not tuple or len(publication) != 2:
            raise _ProjectedSiteDraftViolation(
                "structural route publication row is not canonical",
                scope=model.RouteRealizationFailureScope.EVIDENCE,
            )
        value, identity = publication
        expected_identity = next((
            getattr(value, name)
            for name in ("origin_id", "prefix_id", "relation_id")
            if hasattr(value, name)
        ), None)
        if value is not expected or identity != expected_identity:
            raise _ProjectedSiteDraftViolation(
                "structural route publication occurrence differs",
                scope=model.RouteRealizationFailureScope.EVIDENCE,
            )
    if (
        not hasattr(owner_index, "owner_rows")
        or not hasattr(owner_index, "relation_owner_occurrences")
        or not hasattr(owner_index, "inverse_only_projected_owners")
    ):
        raise _ProjectedSiteDraftViolation("owner index is not canonical", scope=model.RouteRealizationFailureScope.EVIDENCE)
    if type(raw_effect_gate_fact) is not model.RawEffectGatePhaseFact:
        raise _ProjectedSiteDraftViolation("raw gate fact is foreign", scope=model.RouteRealizationFailureScope.EVIDENCE)
    validate_raw_effect_gate_phase_fact(raw_effect_gate_fact)
    if (
        raw_effect_gate_fact.source_inventory_digest != source_inventory.inventory_digest
        or raw_effect_gate_fact.projected_inventory_digest != projected_inventory.inventory_digest
        or raw_effect_gate_fact.source_fingerprint != source_inventory.graph_fingerprint
        or raw_effect_gate_fact.projected_fingerprint != projected_inventory.graph_fingerprint
        or raw_effect_gate_fact.source_generation != source_inventory.generation
        or raw_effect_gate_fact.projected_generation != projected_inventory.generation
    ):
        raise _ProjectedSiteDraftViolation("raw gate envelope differs", scope=model.RouteRealizationFailureScope.EVIDENCE)
    for structural in drafts:
        if any(not any(fact is canonical for canonical in patch_step_facts) for fact in getattr(structural, "facts", ())):
            raise _ProjectedSiteDraftViolation("structural fact occurrence is foreign", scope=model.RouteRealizationFailureScope.STEP, relation_draft=structural)
    source_effects = tuple(row for row in source_inventory.effects if row.owner_serial in source_inventory.reachable_serials)
    source_terminals = tuple(row for row in source_inventory.terminals if row.owner_serial in source_inventory.reachable_serials)
    draft_effect_rows = tuple(item.source_row for item in draft.effect_dispositions)
    draft_terminal_rows = tuple(item.source_row for item in draft.terminal_dispositions)
    if draft.raw_retained_source_owners != raw_effect_gate_fact.raw_retained_source_owners or draft.raw_lost_source_owners != raw_effect_gate_fact.raw_lost_source_owners:
        raise _ProjectedSiteDraftViolation("raw owner partitions differ", scope=model.RouteRealizationFailureScope.EVIDENCE)
    source_serials = {row.serial for row in source_inventory.blocks}
    pre_serials = {owner.ref for owner in raw_effect_gate_fact.pre_effectful_source_owners}
    # The raw gate is a source-phase partition: it commits every effect owner
    # reachable in the immutable source, including an owner that becomes
    # unreachable in the projected closure.  Inventory rows that were already
    # unreachable in the source are not preservation obligations.
    expected_pre = {row.owner_ref for row in source_effects}
    retained_refs = {owner.ref for owner in raw_effect_gate_fact.raw_retained_source_owners}
    lost_refs = {owner.ref for owner in raw_effect_gate_fact.raw_lost_source_owners}
    if (
        pre_serials != expected_pre
        or retained_refs & lost_refs
        or retained_refs | lost_refs != pre_serials
    ):
        raise _ProjectedSiteDraftViolation("raw owner partition is incomplete", scope=model.RouteRealizationFailureScope.EVIDENCE)
    del source_serials
    canonical_claims = tuple(claims)
    exact_claims = tuple(item for item in canonical_claims if type(item) is model.ExactInfeasibleEffectClaim)
    alias_claims = tuple(item for item in canonical_claims if type(item) is model.LocalAliasEffectScalarizationClaim)
    exact_by_id = {item.claim_id: item for item in exact_claims}
    alias_by_id = {item.claim_id: item for item in alias_claims}
    if len(exact_by_id) != len(exact_claims) or len(alias_by_id) != len(alias_claims):
        raise _ProjectedSiteDraftViolation("binding claims contain duplicates", scope=model.RouteRealizationFailureScope.EVIDENCE)
    if len(draft.exact_binding_drafts) != len(exact_claims) or len(draft.local_binding_drafts) != len(alias_claims):
        raise _ProjectedSiteDraftViolation("binding drafts are not exhaustive", scope=model.RouteRealizationFailureScope.STEP)
    structural_by_key = {
        (structural.proof_id, structural.selected_target_ref): structural
        for structural in drafts
    }
    exact_by_draft_id = {}
    for item in draft.exact_binding_drafts:
        canonical = exact_by_id.get(item.claim.claim_id)
        if canonical is not item.claim:
            raise _ProjectedSiteDraftViolation("exact claim occurrence differs", scope=model.RouteRealizationFailureScope.STEP, claim=canonical or item.claim)
        if item.source_inventory is not source_inventory or item.projected_inventory is not projected_inventory:
            raise _ProjectedSiteDraftViolation("exact inventory occurrence differs", scope=model.RouteRealizationFailureScope.EVIDENCE, claim=item.claim)
        expected_relation = structural_by_key.get((canonical.route_proof_ids[0], canonical.selected_target_subject.block_ref))
        try:
            expected = _draft_exact_effect_binding(source_authority=source_authority, claim=canonical, source_inventory=source_inventory, projected_inventory=projected_inventory, relation_index=owner_index, raw_effect_gate_fact=raw_effect_gate_fact, relation_draft=expected_relation)
        except (TypeError, ValueError) as exc:
            raise _ProjectedSiteDraftViolation(
                str(exc), scope=model.RouteRealizationFailureScope.STEP,
                claim=canonical, relation_draft=expected_relation,
            ) from exc
        if expected.source_row is not item.source_row or expected.proof is not item.proof or expected.relation_draft is not item.relation_draft:
            raise _ProjectedSiteDraftViolation("exact draft correlation differs", scope=model.RouteRealizationFailureScope.STEP, claim=canonical, proof=item.proof, source_row=item.source_row)
        exact_by_draft_id[canonical.claim_id] = item
    alias_by_draft_id = {}
    for item in draft.local_binding_drafts:
        canonical = alias_by_id.get(item.claim.claim_id)
        if canonical is not item.claim:
            raise _ProjectedSiteDraftViolation("local claim occurrence differs", scope=model.RouteRealizationFailureScope.STEP, claim=canonical or item.claim)
        if item.patch_step_fact not in patch_step_facts or not any(item.patch_step_fact is fact for fact in patch_step_facts):
            raise _ProjectedSiteDraftViolation("local patch fact occurrence differs", scope=model.RouteRealizationFailureScope.STEP, claim=canonical, patch_step_fact=item.patch_step_fact)
        try:
            expected = _draft_local_alias_binding(
                claim=canonical,
                patch_step_fact=item.patch_step_fact,
                source_inventory=source_inventory,
                projected_inventory=projected_inventory,
                _allow_route_owned_retirement=(
                    _local_alias_has_route_owned_retirement(
                        claim=canonical,
                        projected_inventory=projected_inventory,
                        drafts=drafts,
                        owner_index=owner_index,
                    )
                ),
            )
        except (TypeError, ValueError) as exc:
            raise _ProjectedSiteDraftViolation(
                str(exc), scope=model.RouteRealizationFailureScope.STEP,
                claim=canonical, patch_step_fact=item.patch_step_fact,
                source_row=item.source_row,
            ) from exc
        if (
            expected.source_row is not item.source_row
            or expected.source_observation is not item.source_observation
            or expected.projected_block is not item.projected_block
            or expected.projected_observation is not item.projected_observation
        ):
            raise _ProjectedSiteDraftViolation("local draft correlation differs", scope=model.RouteRealizationFailureScope.STEP, claim=canonical, patch_step_fact=item.patch_step_fact, source_row=item.source_row)
        alias_by_draft_id[canonical.claim_id] = item
    structural_by_id = {item.relation.relation_id: item for item in drafts}
    owner_rows = tuple(owner_index.owner_rows)
    expected_owner_rows: list[tuple[object, object, object, str | None]] = []
    expected_occurrences: list[tuple[str, object, object, object]] = []
    expected_inverse_only: set[object] = set()
    same = model.ProjectedSiteLineageKind.SAME_OWNER
    clone = model.ProjectedSiteLineageKind.RELATION_CLONE
    for structural in drafts:
        relation = structural.relation
        def add_expected(source: object, projected: object, lineage: object, relation_id: str | None) -> None:
            expected = (source, projected, lineage, relation_id)
            if expected not in expected_owner_rows:
                expected_owner_rows.append(expected)
        def add_occurrence(
            source: object, projected: object, lineage: object,
        ) -> None:
            expected = (
                relation.relation_id, source, projected, lineage,
            )
            if expected not in expected_occurrences:
                expected_occurrences.append(expected)
        if type(relation) is model.DirectRouteRealization:
            add_expected(relation.feeder, relation.feeder, same, None)
            add_expected(relation.new_target, relation.new_target, same, None)
            add_occurrence(relation.feeder, relation.feeder, same)
            add_occurrence(relation.new_target, relation.new_target, same)
        elif type(relation) is model.SharedCarrierSourceBypassRouteRealization:
            for owner in (relation.proof_source, relation.semantic_target):
                add_expected(owner, owner, same, None)
                add_occurrence(owner, owner, same)
        elif type(relation) is model.RetainedPrefixRouteRealization:
            for owner in (
                relation.proof_source,
                relation.delivery_owner,
                relation.new_target,
            ):
                add_expected(owner, owner, same, None)
                add_occurrence(owner, owner, same)
        elif type(relation) is model.LoweredConditionalRouteRealization:
            add_expected(relation.feeder, relation.feeder, same, None)
            add_expected(relation.proof_source, relation.proof_source, same, None)
            add_occurrence(relation.feeder, relation.feeder, same)
            add_occurrence(relation.proof_source, relation.proof_source, same)
            for arm in relation.arms:
                add_expected(arm.target, arm.target, same, None)
                add_occurrence(arm.target, arm.target, same)
        elif type(relation) is model.ClonedConditionalRouteRealization:
            add_expected(relation.feeder, relation.feeder, same, None)
            add_expected(relation.proof_source, relation.replacement_clone, clone, relation.relation_id)
            add_occurrence(relation.feeder, relation.feeder, same)
            add_occurrence(
                relation.proof_source, relation.replacement_clone, clone,
            )
            for arm in relation.arms:
                add_expected(arm.target, arm.target, same, None)
                add_occurrence(arm.target, arm.target, same)
            expected_inverse_only.add(relation.fallthrough_helper)
        elif type(relation) is model.FoldedConditionalRouteRealization:
            for owner in (relation.feeder, relation.selected_target):
                add_expected(owner, owner, same, None)
                add_occurrence(owner, owner, same)
        elif type(relation) is model.TwoArmDirectBranchRouteRealization:
            add_expected(relation.feeder, relation.feeder, same, None)
            add_expected(relation.projected_replacement_arm, relation.projected_replacement_arm, same, None)
            add_expected(relation.untouched_arm, relation.untouched_arm, same, None)
            add_occurrence(relation.feeder, relation.feeder, same)
            add_occurrence(
                relation.projected_replacement_arm,
                relation.projected_replacement_arm,
                same,
            )
            add_occurrence(relation.untouched_arm, relation.untouched_arm, same)
        elif type(relation) is model.BranchFallthroughHelperRouteRealization:
            add_expected(relation.feeder, relation.feeder, same, None)
            add_expected(relation.untouched_conditional_arm, relation.untouched_conditional_arm, same, None)
            add_expected(relation.semantic_target, relation.semantic_target, same, None)
            add_occurrence(relation.feeder, relation.feeder, same)
            add_occurrence(
                relation.untouched_conditional_arm,
                relation.untouched_conditional_arm,
                same,
            )
            add_occurrence(relation.semantic_target, relation.semantic_target, same)
            expected_inverse_only.add(relation.helper)
        elif type(relation) is model.ClonedRouteCorridorRealization:
            add_expected(relation.predecessor, relation.predecessor, same, None)
            add_expected(relation.semantic_target, relation.semantic_target, same, None)
            add_occurrence(relation.predecessor, relation.predecessor, same)
            add_occurrence(relation.semantic_target, relation.semantic_target, same)
            for source_owner, projected_owner in zip(relation.source_corridor, relation.cloned_corridor):
                add_expected(source_owner, projected_owner, clone, relation.relation_id)
                add_occurrence(source_owner, projected_owner, clone)
        elif type(relation) is model.ClonedCarrierRouteCorridorRealization:
            add_expected(relation.proof_source, relation.proof_source, same, None)
            add_expected(relation.semantic_target, relation.semantic_target, same, None)
            add_occurrence(relation.proof_source, relation.proof_source, same)
            add_occurrence(relation.semantic_target, relation.semantic_target, same)
            for source_owner, projected_owner in zip(
                relation.source_corridor, relation.cloned_corridor,
            ):
                add_expected(
                    source_owner, projected_owner, clone, relation.relation_id,
                )
                add_occurrence(source_owner, projected_owner, clone)
    expected_rows_by_source: dict[object, list[tuple[object, object, object, str | None]]] = {}
    for expected in expected_owner_rows:
        expected_rows_by_source.setdefault(expected[0], []).append(expected)
    canonical_expected_owner_rows: dict[object, tuple[object, object, object, str | None]] = {}
    for source, source_expected_rows in expected_rows_by_source.items():
        clone_occurrences = tuple(
            (relation_id, source, projected)
            for _source, projected, lineage, relation_id in source_expected_rows
            if lineage is model.ProjectedSiteLineageKind.RELATION_CLONE
            and relation_id is not None
        )
        clone_owner = _canonical_semantic_site_owner_mapping(
            source_inventory=source_inventory,
            source_owner=source,
            clone_occurrences=clone_occurrences,
        )
        if clone_occurrences and clone_owner is None and not any(
            item[2] is model.ProjectedSiteLineageKind.SAME_OWNER
            for item in source_expected_rows
        ):
            continue
        def is_same_owner(item: tuple[object, object, object, str | None]) -> bool:
            return (
                item[0] == item[1]
                and item[2] is model.ProjectedSiteLineageKind.SAME_OWNER
                and item[3] is None
            )

        for expected in source_expected_rows:
            source, projected, lineage, relation_id = expected
            previous = canonical_expected_owner_rows.get(source)
            if previous is None or previous == expected:
                canonical_expected_owner_rows[source] = expected
            elif is_same_owner(previous):
                continue
            elif is_same_owner(expected):
                canonical_expected_owner_rows[source] = expected
            else:
                raise _ProjectedSiteDraftViolation(
                    "owner-index has conflicting clone mappings",
                    scope=model.RouteRealizationFailureScope.STEP,
                )
    expected_owner_rows = list(canonical_expected_owner_rows.values())
    actual_owner_rows = tuple(
        (row.source_owner, row.projected_owner, row.lineage, row.relation_id)
        for row in owner_rows
    )
    if set(actual_owner_rows) != set(expected_owner_rows) or len(actual_owner_rows) != len(expected_owner_rows):
        raise _ProjectedSiteDraftViolation("owner-index domain differs from structural drafts", scope=model.RouteRealizationFailureScope.STEP)
    relation_occurrences = tuple(owner_index.relation_owner_occurrences)
    if any(type(row) is not _RelationOwnerOccurrence for row in relation_occurrences):
        raise _ProjectedSiteDraftViolation("relation-owner occurrence type differs", scope=model.RouteRealizationFailureScope.STEP)
    actual_occurrences = tuple(
        (row.relation_id, row.source_owner, row.projected_owner, row.lineage)
        for row in relation_occurrences
    )
    if (
        set(actual_occurrences) != set(expected_occurrences)
        or len(actual_occurrences) != len(expected_occurrences)
    ):
        raise _ProjectedSiteDraftViolation("relation-owner incidence differs from structural drafts", scope=model.RouteRealizationFailureScope.STEP)
    if set(owner_index.inverse_only_projected_owners) != expected_inverse_only:
        raise _ProjectedSiteDraftViolation("inverse-only owner domain differs from structural drafts", scope=model.RouteRealizationFailureScope.STEP)
    def relation_ids_for_owner(owner: object) -> set[str]:
        return {
            relation_id
            for relation_id, source_owner, _projected_owner, _lineage
            in expected_occurrences
            if source_owner == owner
        }

    def structural_for_owner(owner: object) -> object | None:
        relation_ids = relation_ids_for_owner(owner)
        if len(relation_ids) != 1:
            return None
        return structural_by_id.get(next(iter(relation_ids)))

    def structural_for_projected_owner(owner: object) -> object | None:
        relation_ids = {
            relation_id
            for relation_id, _source_owner, projected_owner, _lineage
            in expected_occurrences
            if projected_owner == owner
        }
        relation_ids.update(
            structural.relation.relation_id
            for structural in drafts
            if (
                type(structural.relation)
                is model.ClonedConditionalRouteRealization
                and structural.relation.fallthrough_helper == owner
            )
            or (
                type(structural.relation)
                is model.BranchFallthroughHelperRouteRealization
                and structural.relation.helper == owner
            )
        )
        if len(relation_ids) != 1:
            return None
        return structural_by_id.get(next(iter(relation_ids)))

    def structural_for_source_row(row: object) -> object | None:
        source_owner = model.AnchoredBlockRef(
            row.owner_ref, row.owner_anchor_ea,
        )
        mappings = tuple(
            mapping for mapping in owner_rows
            if mapping.source_owner == source_owner
        )
        if len(mappings) != 1:
            return None
        return structural_for_owner(mappings[0].source_owner)

    missing_effects = tuple(
        row for row in source_effects
        if not any(actual is row for actual in draft_effect_rows)
    )
    missing_terminals = tuple(
        row for row in source_terminals
        if not any(actual is row for actual in draft_terminal_rows)
    )
    foreign_effects = tuple(
        row for row in draft_effect_rows
        if not any(row is canonical for canonical in source_effects)
    )
    foreign_terminals = tuple(
        row for row in draft_terminal_rows
        if not any(row is canonical for canonical in source_terminals)
    )

    def reject_one_relation_owned_duplicate(
        dispositions: tuple[object, ...], source_rows: tuple[object, ...],
        *, site_kind: str,
    ) -> None:
        repeated = tuple(
            (source_row, tuple(
                item for item in dispositions
                if item.source_row is source_row
            ))
            for source_row in source_rows
            if sum(item.source_row is source_row for item in dispositions) > 1
        )
        if len(dispositions) != len(source_rows) + 1 or len(repeated) != 1:
            return
        source_row, occurrences = repeated[0]
        if len(occurrences) != 2:
            return
        relation_draft = structural_for_source_row(source_row)
        if relation_draft is None:
            return
        projected_label = (
            "effect" if site_kind == "effect" else "terminal"
        )
        if occurrences[0] is occurrences[1]:
            raise _ProjectedSiteDraftViolation(
                f"projected {projected_label} disposition is consumed more than once",
                scope=model.RouteRealizationFailureScope.STEP,
                relation_draft=relation_draft, source_row=source_row,
                projected_row=occurrences[1].projected_row,
            )
        source_owner = model.AnchoredBlockRef(
            source_row.owner_ref, source_row.owner_anchor_ea,
        )
        expected_mappings = tuple(
            row for row in owner_rows if row.source_owner == source_owner
        )
        if len(expected_mappings) != 1:
            return
        expected_mapping = expected_mappings[0]
        canonical = tuple(
            item for item in occurrences
            if item.owner_mapping is expected_mapping
        )
        conflicting = tuple(
            item for item in occurrences
            if item.owner_mapping is not expected_mapping
            and any(item.owner_mapping is row for row in owner_rows)
        )
        if len(canonical) == len(conflicting) == 1:
            foreign_mapping = conflicting[0].owner_mapping
            raise _ProjectedSiteDraftViolation(
                f"source {projected_label} disposition has conflicting owner mappings",
                scope=model.RouteRealizationFailureScope.STEP,
                relation_draft=relation_draft, source_row=source_row,
                projected_row=conflicting[0].projected_row,
                anchored_refs=(foreign_mapping.projected_owner,),
            )

    reject_one_relation_owned_duplicate(
        draft.effect_dispositions, source_effects, site_kind="effect",
    )
    reject_one_relation_owned_duplicate(
        draft.terminal_dispositions, source_terminals, site_kind="terminal",
    )
    if (
        len({id(item.source_row) for item in draft.effect_dispositions})
        != len(draft.effect_dispositions)
        or len({id(item.source_row) for item in draft.terminal_dispositions})
        != len(draft.terminal_dispositions)
    ):
        raise _ProjectedSiteDraftViolation(
            "source site partition contains duplicates",
            scope=model.RouteRealizationFailureScope.EVIDENCE,
        )
    if (
        len(missing_effects) == 1
        and not foreign_effects
        and not missing_terminals
        and len(draft_effect_rows) + 1 == len(source_effects)
    ):
        missing = missing_effects[0]
        relation_draft = structural_for_source_row(missing)
        if relation_draft is not None:
            raise _ProjectedSiteDraftViolation(
                "source effect disposition is missing",
                scope=model.RouteRealizationFailureScope.STEP,
                relation_draft=relation_draft,
                source_row=missing,
            )
    if (
        len(missing_terminals) == 1
        and not foreign_terminals
        and not missing_effects
        and len(draft_terminal_rows) + 1 == len(source_terminals)
    ):
        missing = missing_terminals[0]
        relation_draft = structural_for_source_row(missing)
        if relation_draft is not None:
            raise _ProjectedSiteDraftViolation(
                "source terminal disposition is missing",
                scope=model.RouteRealizationFailureScope.STEP,
                relation_draft=relation_draft,
                source_row=missing,
            )
    if (
        len(draft_effect_rows) != len(source_effects)
        or any(
            actual is not expected
            for actual, expected in zip(draft_effect_rows, source_effects)
        )
        or len(draft_terminal_rows) != len(source_terminals)
        or any(
            actual is not expected
            for actual, expected in zip(draft_terminal_rows, source_terminals)
        )
    ):
        raise _ProjectedSiteDraftViolation(
            "source site partition is not exhaustive",
            scope=model.RouteRealizationFailureScope.EVIDENCE,
        )
    consumed_effects: dict[int, int] = {}
    consumed_terminals: dict[int, int] = {}
    exact_refs: dict[str, int] = {key: 0 for key in exact_by_id}
    alias_refs: dict[str, int] = {key: 0 for key in alias_by_id}
    def site_observation(inventory: model.SemanticGraphInventory, row: object) -> object:
        blocks = tuple(
            block for block in inventory.blocks
            if block.serial == row.owner_serial and block.block_ref == row.owner_ref
        )
        observations = tuple(
            observation for block in blocks
            for observation in block.instruction_observations
            if observation.ordinal == row.instruction_ordinal
            and observation.instruction_ea == row.instruction_ea
        )
        if len(observations) != 1:
            raise _ProjectedSiteDraftViolation("site observation occurrence is not unique", scope=model.RouteRealizationFailureScope.STEP, source_row=row)
        return observations[0]
    for item in draft.effect_dispositions:
        mapping = next((row for row in owner_rows if row is item.owner_mapping), None)
        if item.owner_mapping is not None and mapping is None:
            foreign_projected_owner = getattr(
                item.owner_mapping, "projected_owner", None,
            )
            raise _ProjectedSiteDraftViolation(
                "owner mapping occurrence differs",
                scope=model.RouteRealizationFailureScope.STEP,
                relation_draft=structural_for_source_row(item.source_row),
                source_row=item.source_row,
                projected_row=item.projected_row,
                anchored_refs=(foreign_projected_owner,)
                if type(foreign_projected_owner) is model.AnchoredBlockRef
                else (),
            )
        projected_owner = mapping.projected_owner.ref if mapping is not None else item.source_row.owner_ref
        candidates = tuple(row for row in projected_inventory.effects if row.owner_serial in projected_inventory.reachable_serials and row.owner_ref == projected_owner and row.instruction_ea == item.source_row.instruction_ea and row.effect_kind is item.source_row.effect_kind)
        exact_candidates = tuple(row for row in candidates if row.opcode == item.source_row.opcode and row.width == item.source_row.width)
        expected_row = exact_candidates[0] if len(exact_candidates) == 1 else None
        exact_claim = next((claim for claim in exact_claims if claim.effect_subject.locator.owner_ref == item.source_row.owner_ref and claim.effect_subject.locator.instruction_ea == item.source_row.instruction_ea and claim.effect_subject.locator.effect_kind is item.source_row.effect_kind), None)
        alias_claim = next((claim for claim in alias_claims if claim.owner_subject.block_ref == item.source_row.owner_ref and claim.host_ea == item.source_row.instruction_ea), None)
        source_observation = site_observation(source_inventory, item.source_row)
        if source_observation.opcode != item.source_row.opcode or source_observation.width != item.source_row.width:
            raise _ProjectedSiteDraftViolation("source effect observation differs", scope=model.RouteRealizationFailureScope.STEP, claim=exact_claim or alias_claim, source_row=item.source_row)
        projected_observation = site_observation(projected_inventory, expected_row) if expected_row is not None else None
        expected_structural = (
            structural_for_owner(mapping.source_owner)
            if mapping is not None else None
        )
        if expected_row is not None and (
            projected_observation.opcode != source_observation.opcode
            or projected_observation.raw_opcode != source_observation.raw_opcode
            or projected_observation.width != source_observation.width
        ):
            raise _ProjectedSiteDraftViolation("projected effect raw observation differs", scope=model.RouteRealizationFailureScope.STEP, relation_draft=expected_structural, source_row=item.source_row, projected_row=expected_row)
        expected_relation_ids = (
            relation_ids_for_owner(mapping.source_owner)
            if mapping is not None else set()
        )
        if item.source_subject is not _site_subject(source_inventory, item.source_row):
            raise _ProjectedSiteDraftViolation("source subject occurrence differs", scope=model.RouteRealizationFailureScope.STEP, claim=exact_claim or alias_claim, relation_draft=expected_structural, source_row=item.source_row)
        if expected_row is not None and expected_row.owner_serial not in projected_inventory.reachable_serials:
            raise _ProjectedSiteDraftViolation("projected effect owner is unreachable", scope=model.RouteRealizationFailureScope.STEP, claim=exact_claim or alias_claim, relation_draft=expected_structural, source_row=item.source_row, projected_row=expected_row)
        if expected_row is not None and item.projected_row is not expected_row:
            coordinate_reason = _projected_site_coordinate_drift_reason(
                item.projected_row, expected_row,
            )
            if coordinate_reason is not None:
                raise _ProjectedSiteDraftViolation(
                    coordinate_reason,
                    scope=(
                        model.RouteRealizationFailureScope.STEP
                        if mapping
                        else model.RouteRealizationFailureScope.EVIDENCE
                    ),
                    claim=(
                        None
                        if expected_structural is not None
                        else exact_claim or alias_claim
                    ),
                    relation_draft=(
                        expected_structural or item.relation_draft
                    ),
                    source_row=item.source_row,
                    projected_row=item.projected_row,
                )
        if item.projected_row is not expected_row and not (expected_row is None and item.projected_row is None):
            raise _ProjectedSiteDraftViolation("projected effect occurrence differs", scope=model.RouteRealizationFailureScope.STEP if mapping else model.RouteRealizationFailureScope.EVIDENCE, claim=None if expected_structural is not None else exact_claim or alias_claim, relation_draft=expected_structural or item.relation_draft, source_row=item.source_row, projected_row=item.projected_row)
        if expected_row is not None and item.projected_subject is not _site_subject(projected_inventory, expected_row):
            raise _ProjectedSiteDraftViolation("projected subject occurrence differs", scope=model.RouteRealizationFailureScope.STEP, claim=exact_claim or alias_claim, relation_draft=expected_structural or item.relation_draft, source_row=item.source_row, projected_row=expected_row)
        expected_lineage = (
            mapping.lineage
            if mapping is not None and expected_row is not None
            else model.ProjectedSiteLineageKind.SAME_OWNER
            if expected_row is not None
            else None
        )
        expected_outcome = model.ProjectedEffectSiteOutcome.RELATION_CLONED if expected_lineage is model.ProjectedSiteLineageKind.RELATION_CLONE else model.ProjectedEffectSiteOutcome.PRESERVED if expected_row is not None else model.ProjectedEffectSiteOutcome.LOCAL_ALIAS_SCALARIZED if alias_claim is not None else model.ProjectedEffectSiteOutcome.EXACT_INFEASIBLE if exact_claim is not None else model.ProjectedEffectSiteOutcome.UNCLASSIFIED
        if item.outcome is not expected_outcome or item.lineage is not expected_lineage:
            raise _ProjectedSiteDraftViolation("effect lineage/outcome differs", scope=model.RouteRealizationFailureScope.STEP if mapping else model.RouteRealizationFailureScope.EVIDENCE, claim=exact_claim or alias_claim, relation_draft=expected_structural or item.relation_draft, source_row=item.source_row, projected_row=item.projected_row)
        if expected_outcome is model.ProjectedEffectSiteOutcome.UNCLASSIFIED:
            source_row = item.source_row
            mapped_owner = (
                mapping.projected_owner.ref
                if mapping is not None
                else source_row.owner_ref
            )
            mapped_blocks = tuple(
                (
                    row.serial,
                    row.block_ref,
                    row.anchor_ea,
                    row.serial in projected_inventory.reachable_serials,
                )
                for row in projected_inventory.blocks
                if row.block_ref == mapped_owner
            )
            mapped_bindings = tuple(
                (
                    row.block_ref,
                    row.serial,
                    row.anchor_ea,
                    row.status.value,
                    row.role.value,
                )
                for row in projected_inventory.bindings
                if row.block_ref == mapped_owner
            )
            mapped_owner_effects = tuple(
                (
                    row.owner_serial,
                    row.owner_anchor_ea,
                    row.instruction_ordinal,
                    row.instruction_ea,
                    row.effect_kind.value,
                    row.opcode,
                    row.width,
                    row.owner_serial in projected_inventory.reachable_serials,
                )
                for row in projected_inventory.effects
                if row.owner_ref == mapped_owner
                and row.instruction_ea == source_row.instruction_ea
            )
            same_ea_effects = tuple(
                (
                    row.owner_serial,
                    row.owner_ref,
                    row.owner_anchor_ea,
                    row.instruction_ordinal,
                    row.effect_kind.value,
                    row.opcode,
                    row.width,
                    row.owner_serial in projected_inventory.reachable_serials,
                )
                for row in projected_inventory.effects
                if row.instruction_ea == source_row.instruction_ea
            )
            cut_frontier, cut_descriptors, cut_facts = (
                _unclassified_effect_cut_frontier(
                    source_inventory=source_inventory,
                    projected_inventory=projected_inventory,
                    plan=plan,
                    patch_step_facts=patch_step_facts,
                    owner_serial=source_row.owner_serial,
                )
            )
            logger.warning(
                "unclassified projected effect-site context: source=%r "
                "owner_mapping=%r mapped_owner=%r mapped_blocks=%r "
                "mapped_bindings=%r mapped_owner_effects=%r same_ea_effects=%r "
                "cut_frontier=%r cut_descriptors=%r cut_facts=%r",
                (
                    source_row.owner_ref,
                    source_row.owner_serial,
                    source_row.owner_anchor_ea,
                    source_row.instruction_ordinal,
                    source_row.instruction_ea,
                    source_row.effect_kind.value,
                    source_row.opcode,
                    source_row.width,
                ),
                mapping,
                mapped_owner,
                mapped_blocks,
                mapped_bindings,
                mapped_owner_effects,
                same_ea_effects,
                cut_frontier,
                cut_descriptors,
                cut_facts,
            )
            raise _ProjectedSiteDraftViolation(
                "projected effect site has no typed disposition",
                scope=model.RouteRealizationFailureScope.EVIDENCE,
                source_row=item.source_row,
                projected_row=item.projected_row,
            )
        if mapping is not None:
            if (
                len(expected_relation_ids) == 1
                and item.relation_draft is not expected_structural
            ) or (
                len(expected_relation_ids) > 1
                and item.relation_draft is not None
            ) or not expected_relation_ids:
                raise _ProjectedSiteDraftViolation("effect relation occurrence differs", scope=model.RouteRealizationFailureScope.STEP, claim=exact_claim or alias_claim, relation_draft=expected_structural or item.relation_draft, source_row=item.source_row, projected_row=item.projected_row)
        elif item.relation_draft is not None:
            raise _ProjectedSiteDraftViolation("unmapped effect carries a relation", scope=model.RouteRealizationFailureScope.EVIDENCE, claim=exact_claim or alias_claim, source_row=item.source_row, projected_row=item.projected_row)
        if exact_claim is not None:
            binding = exact_by_draft_id.get(exact_claim.claim_id)
            if item.exact_binding is not binding: raise _ProjectedSiteDraftViolation("exact binding use differs", scope=model.RouteRealizationFailureScope.STEP, claim=exact_claim, relation_draft=expected_structural, source_row=item.source_row)
            exact_refs[exact_claim.claim_id] += 1
        if alias_claim is not None:
            binding = alias_by_draft_id.get(alias_claim.claim_id)
            if item.local_binding is not binding or item.patch_step_fact is not binding.patch_step_fact: raise _ProjectedSiteDraftViolation("local binding use differs", scope=model.RouteRealizationFailureScope.STEP, claim=alias_claim, relation_draft=expected_structural, patch_step_fact=binding.patch_step_fact if binding is not None else item.patch_step_fact, source_row=item.source_row)
            alias_refs[alias_claim.claim_id] += 1
        if expected_row is not None: consumed_effects[id(expected_row)] = consumed_effects.get(id(expected_row), 0) + 1
    for item in draft.terminal_dispositions:
        mapping = next((row for row in owner_rows if row is item.owner_mapping), None)
        if item.owner_mapping is not None and mapping is None:
            foreign_projected_owner = getattr(
                item.owner_mapping, "projected_owner", None,
            )
            raise _ProjectedSiteDraftViolation(
                "terminal owner occurrence differs",
                scope=model.RouteRealizationFailureScope.STEP,
                relation_draft=structural_for_source_row(item.source_row),
                source_row=item.source_row,
                projected_row=item.projected_row,
                anchored_refs=(foreign_projected_owner,)
                if type(foreign_projected_owner) is model.AnchoredBlockRef
                else (),
            )
        projected_owner = mapping.projected_owner.ref if mapping is not None else item.source_row.owner_ref
        candidates = tuple(row for row in projected_inventory.terminals if row.owner_serial in projected_inventory.reachable_serials and row.owner_ref == projected_owner and row.instruction_ea == item.source_row.instruction_ea and row.terminal_kind is item.source_row.terminal_kind and row.instruction_ordinal == item.source_row.instruction_ordinal)
        expected_row = candidates[0] if len(candidates) == 1 else None
        expected_structural = (
            structural_for_owner(mapping.source_owner)
            if mapping is not None else None
        )
        expected_relation_ids = (
            relation_ids_for_owner(mapping.source_owner)
            if mapping is not None else set()
        )
        if item.source_subject is not _site_subject(source_inventory, item.source_row):
            raise _ProjectedSiteDraftViolation("terminal source subject occurrence differs", scope=model.RouteRealizationFailureScope.STEP, relation_draft=expected_structural, source_row=item.source_row)
        expected_terminal_outcome = model.ProjectedTerminalSiteOutcome.RELATION_CLONED if mapping is not None and mapping.lineage is model.ProjectedSiteLineageKind.RELATION_CLONE else model.ProjectedTerminalSiteOutcome.PRESERVED
        expected_terminal_lineage = mapping.lineage if mapping is not None else model.ProjectedSiteLineageKind.SAME_OWNER
        if expected_row is not None and expected_row.owner_serial not in projected_inventory.reachable_serials:
            raise _ProjectedSiteDraftViolation("projected terminal owner is unreachable", scope=model.RouteRealizationFailureScope.STEP, relation_draft=expected_structural, source_row=item.source_row, projected_row=expected_row)
        if expected_row is not None and item.projected_row is not expected_row:
            coordinate_reason = _projected_site_coordinate_drift_reason(
                item.projected_row, expected_row,
            )
            if coordinate_reason is not None:
                raise _ProjectedSiteDraftViolation(
                    coordinate_reason,
                    scope=(
                        model.RouteRealizationFailureScope.STEP
                        if mapping
                        else model.RouteRealizationFailureScope.EVIDENCE
                    ),
                    relation_draft=(
                        expected_structural or item.relation_draft
                    ),
                    source_row=item.source_row,
                    projected_row=item.projected_row,
                )
        if expected_row is None or item.projected_row is not expected_row or item.outcome is not expected_terminal_outcome or item.lineage is not expected_terminal_lineage:
            raise _ProjectedSiteDraftViolation("terminal strictness differs", scope=model.RouteRealizationFailureScope.STEP if mapping else model.RouteRealizationFailureScope.EVIDENCE, relation_draft=expected_structural or item.relation_draft, source_row=item.source_row, projected_row=item.projected_row)
        if mapping is None and item.relation_draft is not None:
            raise _ProjectedSiteDraftViolation("unmapped terminal carries a relation", scope=model.RouteRealizationFailureScope.EVIDENCE, source_row=item.source_row, projected_row=item.projected_row)
        if mapping is not None and (
            (
                len(expected_relation_ids) == 1
                and item.relation_draft is not expected_structural
            )
            or (
                len(expected_relation_ids) > 1
                and item.relation_draft is not None
            )
            or not expected_relation_ids
        ):
            raise _ProjectedSiteDraftViolation("terminal relation occurrence differs", scope=model.RouteRealizationFailureScope.STEP, relation_draft=expected_structural or item.relation_draft, source_row=item.source_row, projected_row=item.projected_row)
        if item.projected_subject is not _site_subject(projected_inventory, expected_row):
            raise _ProjectedSiteDraftViolation("terminal projected subject occurrence differs", scope=model.RouteRealizationFailureScope.STEP, relation_draft=expected_structural or item.relation_draft, source_row=item.source_row, projected_row=expected_row)
        if expected_row is not None: consumed_terminals[id(expected_row)] = consumed_terminals.get(id(expected_row), 0) + 1
    for row in projected_inventory.effects:
        if row.owner_serial in projected_inventory.reachable_serials and consumed_effects.get(id(row), 0) != 1:
            diagnostic_owner = model.AnchoredBlockRef(
                row.owner_ref, row.owner_anchor_ea,
            )
            raise _ProjectedSiteDraftViolation("projected effect inverse is incomplete", scope=model.RouteRealizationFailureScope.STEP, relation_draft=structural_for_projected_owner(diagnostic_owner), projected_row=row)
    for row in projected_inventory.terminals:
        if row.owner_serial in projected_inventory.reachable_serials and consumed_terminals.get(id(row), 0) != 1:
            diagnostic_owner = model.AnchoredBlockRef(
                row.owner_ref, row.owner_anchor_ea,
            )
            raise _ProjectedSiteDraftViolation("projected terminal inverse is incomplete", scope=model.RouteRealizationFailureScope.STEP, relation_draft=structural_for_projected_owner(diagnostic_owner), projected_row=row)
    if any(count != 1 for count in exact_refs.values()) or any(count != 1 for count in alias_refs.values()):
        raise _ProjectedSiteDraftViolation("binding use counts are not exact", scope=model.RouteRealizationFailureScope.STEP)
    if len(draft.route_subsets) != len(drafts): raise _ProjectedSiteDraftViolation("route subsets are incomplete", scope=model.RouteRealizationFailureScope.EVIDENCE)
    subset_relations: list[object] = []
    for subset in draft.route_subsets:
        if not any(subset.relation_draft is structural for structural in drafts): raise _ProjectedSiteDraftViolation("route subset relation is foreign", scope=model.RouteRealizationFailureScope.STEP)
        if any(subset.relation_draft is previous for previous in subset_relations): raise _ProjectedSiteDraftViolation("route subset relation is duplicated", scope=model.RouteRealizationFailureScope.STEP, relation_draft=subset.relation_draft)
        subset_relations.append(subset.relation_draft)
        expected_sources = {
            source_owner
            for relation_id, source_owner, _projected_owner, _lineage
            in expected_occurrences
            if relation_id == subset.relation_draft.relation.relation_id
        }
        expected_effects = tuple(item for item in draft.effect_dispositions if item.owner_mapping is not None and item.owner_mapping.source_owner in expected_sources)
        expected_terminals = tuple(item for item in draft.terminal_dispositions if item.owner_mapping is not None and item.owner_mapping.source_owner in expected_sources)
        foreign_subset_items = tuple(
            item for item in subset.effect_dispositions
            if not any(item is expected for expected in expected_effects)
        ) + tuple(
            item for item in subset.terminal_dispositions
            if not any(item is expected for expected in expected_terminals)
        )
        if (
            len(subset.effect_dispositions) != len(expected_effects)
            or len(subset.terminal_dispositions) != len(expected_terminals)
            or any(not any(item is expected for expected in expected_effects) for item in subset.effect_dispositions)
            or {id(item) for item in subset.effect_dispositions} != {id(item) for item in expected_effects}
            or any(not any(item is expected for expected in expected_terminals) for item in subset.terminal_dispositions)
            or {id(item) for item in subset.terminal_dispositions} != {id(item) for item in expected_terminals}
        ):
            offending = (
                foreign_subset_items[0]
                if len(foreign_subset_items) == 1 else None
            )
            raise _ProjectedSiteDraftViolation(
                "route subset occurrence differs",
                scope=model.RouteRealizationFailureScope.STEP,
                relation_draft=subset.relation_draft,
                source_row=getattr(offending, "source_row", None),
                projected_row=getattr(offending, "projected_row", None),
            )
    if legacy_effective_gate_facts is not None:
        source_serial_by_ref = {row.block_ref: row.serial for row in source_inventory.blocks if row.block_ref is not None}
        pre = frozenset(source_serial_by_ref[owner.ref] for owner in raw_effect_gate_fact.pre_effectful_source_owners if owner.ref in source_serial_by_ref)
        raw_lost = frozenset(source_serial_by_ref[owner.ref] for owner in raw_effect_gate_fact.raw_lost_source_owners if owner.ref in source_serial_by_ref)
        raw_retained = frozenset(source_serial_by_ref[owner.ref] for owner in raw_effect_gate_fact.raw_retained_source_owners if owner.ref in source_serial_by_ref)
        authorized_raw_lost = frozenset(
            source_serial_by_ref[owner.ref]
            for owner in raw_effect_gate_fact.raw_lost_source_owners
            if owner.ref in source_serial_by_ref
            and (
                owner_effects := tuple(
                    row for row in source_effects
                    if row.owner_ref == owner.ref
                    and row.owner_anchor_ea == owner.anchor_ea
                )
            )
            and all(
                sum(
                    item.source_row is row
                    for item in draft.effect_dispositions
                ) == 1
                for row in owner_effects
            )
        )
        effective_lost = raw_lost - authorized_raw_lost
        effective_post = raw_retained | authorized_raw_lost
        # The legacy gate is only a compatibility observation over the raw
        # structural reachability universe.  The canonical inventory may add
        # typed route roots that the legacy walk cannot see (notably indirect
        # dispatcher targets).  Compare the DTO against the canonical verdict
        # restricted to its own declared universe; never require it to
        # reconstruct the transaction's larger semantic partition.
        legacy_pre = legacy_effective_gate_facts.pre_effectful_block_serials
        if not legacy_pre <= pre:
            raise _ProjectedSiteDraftViolation(
                "legacy effective gate contains a foreign effect owner",
                scope=model.RouteRealizationFailureScope.EVIDENCE,
            )
        legacy_post = effective_post & legacy_pre
        legacy_lost = effective_lost & legacy_pre
        expected = GenericEffectfulGateFacts(
            not legacy_lost,
            legacy_pre,
            legacy_post,
            legacy_lost,
            legacy_effective_gate_facts.reason,
        )
        if legacy_effective_gate_facts != expected:
            raise _ProjectedSiteDraftViolation(
                "legacy effective gate differs from derived view",
                scope=model.RouteRealizationFailureScope.EVIDENCE,
            )


def _route_content_seal(value: object, identity: str) -> str:
    """Seal exact stored route state without executing producer behavior.

    Route values can contain portable instruction attributes represented by a
    ``mappingproxy``.  Hashing their live dataclass payload through the general
    canonical codec can invoke the protocol of a foreign mapping backing that
    proxy.  Publication must first reduce the complete value to the same closed,
    callback-free structural snapshot used by registry validation.
    """
    snapshot = _registry_structural_snapshot(value)
    return hashlib.sha256(canonical_bytes((identity, snapshot))).hexdigest()


authority_ids._ensure_registries()
_REGISTRY_CANONICAL_RECORD_TYPES = frozenset(
    record_type
    for record_type in (
        *authority_ids._RECORD_TYPES,
        *authority_ids._EXTERNAL_TYPES,
        *authority_ids._PINNED_RECORD_TYPES,
    )
    if is_dataclass(record_type)
)
_REGISTRY_CANONICAL_ENUM_TYPES = frozenset(authority_ids._ENUM_TYPES)


def _stored_dataclass_field(value: object, name: str) -> object:
    """Read one exact trusted dataclass storage cell without user lookup."""
    value_type = type(value)
    try:
        storage = object.__getattribute__(value, "__dict__")
    except AttributeError:
        storage = None
    if storage is not None:
        if type(storage) is not dict:
            raise TypeError("registered dataclass storage must be an exact dict")
        try:
            return dict.__getitem__(storage, name)
        except KeyError as exc:
            raise ValueError("registered dataclass field is not initialized") from exc
    for owner in type.__getattribute__(value_type, "__mro__"):
        descriptor = type.__getattribute__(owner, "__dict__").get(name)
        if type(descriptor) is MemberDescriptorType:
            try:
                return object.__getattribute__(value, name)
            except AttributeError as exc:
                raise ValueError("registered dataclass field is not initialized") from exc
    raise TypeError("registered dataclass field has unsupported storage")


def _registry_structural_snapshot(value: object) -> tuple[object, ...]:
    """Capture exact closed state without retaining or calling candidate values."""
    occurrences: dict[int, int] = {}
    active: set[int] = set()

    def compound(item: object, kind: str, build) -> tuple[object, ...]:
        marker = id(item)
        if marker in active:
            raise ValueError("cyclic registered authority state")
        previous = occurrences.get(marker)
        if previous is not None:
            return ("ref", previous)
        occurrence = len(occurrences)
        occurrences[marker] = occurrence
        active.add(marker)
        try:
            content = build()
        finally:
            active.remove(marker)
        return (kind, occurrence, content)

    def visit(item: object) -> tuple[object, ...]:
        item_type = type(item)
        if item is None:
            return ("none",)
        if item_type is bool:
            return ("bool", 1 if item else 0)
        if item_type is int:
            return ("int", item)
        if item_type is str:
            return ("str", item)
        if item_type is bytes:
            return ("bytes", item)
        if item_type is float:
            return ("float", float.hex(item))
        if item_type in _REGISTRY_CANONICAL_ENUM_TYPES:
            enum_name = object.__getattribute__(item, "_name_")
            if type(enum_name) is not str:
                raise ValueError("registered enum member has no exact name")
            return (
                "enum", item_type.__module__, item_type.__qualname__, enum_name,
            )
        if item_type is tuple:
            return compound(item, "tuple", lambda: tuple(
                visit(tuple.__getitem__(item, index))
                for index in range(tuple.__len__(item))
            ))
        if item_type is frozenset:
            def frozen_content() -> tuple[object, ...]:
                members = []
                iterator = frozenset.__iter__(item)
                while True:
                    try:
                        member = next(iterator)
                    except StopIteration:
                        break
                    if type(member) not in {bool, int, str, bytes}:
                        raise TypeError(
                            "registered frozensets require exact primitive members"
                        )
                    members.append(visit(member))
                return tuple(sorted(members))
            return compound(item, "frozenset", frozen_content)
        if item_type is MappingProxyType:
            def mapping_content() -> tuple[object, ...]:
                pairs: list[tuple[str, tuple[object, ...]]] = []
                backing = authority_ids._exact_mappingproxy_backing(item)
                for key, member in dict.items(backing):
                    if type(key) is not str:
                        raise TypeError(
                            "registered mapping proxies require exact string keys"
                        )
                    pairs.append((key, visit(member)))
                return tuple(sorted(pairs, key=lambda pair: pair[0]))
            return compound(item, "mappingproxy", mapping_content)
        if item_type in _REGISTRY_CANONICAL_RECORD_TYPES:
            def record_content() -> tuple[object, ...]:
                return tuple(
                    (field.name, visit(_stored_dataclass_field(item, field.name)))
                    for field in dataclass_fields(item_type)
                )
            return compound(
                item,
                "record:" + item_type.__module__ + "." + item_type.__qualname__,
                record_content,
            )
        if item_type in {list, dict, set}:
            raise TypeError("mutable containers are not registered authority state")
        raise TypeError("registered authority state has an unsupported exact type")

    return visit(value)


def _detached_canonical_copy(value: object, memo: dict[int, object]) -> object:
    """Copy one already-closed graph into exact trusted built-in records."""
    value_type = type(value)
    if value is None or value_type in {bool, int, str, bytes, float}:
        return value
    if value_type in _REGISTRY_CANONICAL_ENUM_TYPES:
        return value
    if value_type is tuple:
        existing = memo.get(id(value))
        if existing is not None:
            return existing
        clone = tuple(
            _detached_canonical_copy(tuple.__getitem__(value, index), memo)
            for index in range(tuple.__len__(value))
        )
        memo[id(value)] = clone
        return clone
    if value_type is frozenset:
        existing = memo.get(id(value))
        if existing is not None:
            return existing
        clone = frozenset(
            _detached_canonical_copy(item, memo)
            for item in frozenset.__iter__(value)
        )
        memo[id(value)] = clone
        return clone
    if value_type is MappingProxyType:
        existing = memo.get(id(value))
        if existing is not None:
            return existing
        # Canonical route evidence seals portable instruction attributes as
        # exact mapping proxies.  Detach their backing mapping as well so the
        # registry snapshot never trusts producer-owned mutable state.
        detached: dict[str, object] = {}
        clone = MappingProxyType(detached)
        memo[id(value)] = clone
        backing = authority_ids._exact_mappingproxy_backing(value)
        detached.update({
            key: _detached_canonical_copy(member, memo)
            for key, member in dict.items(backing)
        })
        return clone
    if value_type in _REGISTRY_CANONICAL_RECORD_TYPES:
        existing = memo.get(id(value))
        if existing is not None:
            return existing
        clone = object.__new__(value_type)
        memo[id(value)] = clone
        for item in dataclass_fields(value_type):
            object.__setattr__(
                clone, item.name,
                _detached_canonical_copy(
                    _stored_dataclass_field(value, item.name), memo,
                ),
            )
        return clone
    raise TypeError("registered authority state cannot be detached")


def _canonical_record_snapshot(value: object) -> object:
    """Normalize a detached copy and require identical candidate live state."""
    candidate_state = _registry_structural_snapshot(value)
    canonical = _detached_canonical_copy(value, {})
    type(canonical).__post_init__(canonical)
    canonical_state = _registry_structural_snapshot(canonical)
    if candidate_state != canonical_state:
        raise ValueError("registry candidate differs from canonical live state")
    if candidate_state != _registry_structural_snapshot(value):
        raise ValueError("registry candidate changed during classification")
    return canonical


def _route_failure_identity(value: model.RouteRealizationFailure) -> str:
    return authority_id((
        "unflatten.route-realization-failure.v1",
        tuple(
            (item.name, getattr(value, item.name))
            for item in dataclass_fields(type(value))
            if not item.name.startswith("_")
        ),
    ))


def _route_result_identity(value: object) -> str:
    return authority_id((
        type(value).__qualname__,
        tuple(
            (item.name, getattr(value, item.name))
            for item in dataclass_fields(type(value))
            if not item.name.startswith("_")
        ),
    ))


def _canonical_registry_seal(
    value: object,
    registry: dict[int, tuple[weakref.ReferenceType[object], str]],
    _site_registry=_SITE_REGISTRY,
    _binding_registry=_SITE_BINDING_REGISTRY,
    _route_registry=_ROUTE_REGISTRY,
    _logical_registry=_OBSERVED_LOGICAL_ENDPOINT_REGISTRY,
    _route_seal=_route_content_seal,
) -> str:
    """Recompute one closed record's canonical live publication seal."""
    if registry is _logical_registry:
        if type(value) is not model.ObservedLogicalEndpointOccurrence:
            raise TypeError("logical endpoint registry has an unknown type")
        value.__post_init__()
        return value.occurrence_id
    if registry is _OBSERVED_ROUTE_TOPOLOGY_REGISTRY:
        if type(value) is not model.ObservedRouteTopologyOccurrence:
            raise TypeError("route topology registry has an unknown type")
        value.__post_init__()
        return value.occurrence_id
    if registry is _OBSERVED_LOWERED_CONDITIONAL_TOPOLOGY_REGISTRY:
        if type(value) is not model.ObservedLoweredConditionalTopologyOccurrence:
            raise TypeError(
                "lowered conditional topology registry has an unknown type",
            )
        value.__post_init__()
        return value.occurrence_id
    if registry is _site_registry:
        if type(value) not in {
            model.RawEffectGatePhaseFact, model.EffectSiteCoordinate,
            model.TerminalSiteCoordinate, model.ScalarizedInstructionCoordinate,
        }:
            raise TypeError("semantic site value has an unknown closed type")
        canonical = _canonical_record_snapshot(value)
        if type(canonical) is model.RawEffectGatePhaseFact:
            return raw_effect_gate_phase_fact_id(canonical)
        if type(canonical) is model.EffectSiteCoordinate:
            return effect_site_coordinate_id(canonical)
        if type(canonical) is model.TerminalSiteCoordinate:
            return terminal_site_coordinate_id(canonical)
        if type(canonical) is model.ScalarizedInstructionCoordinate:
            return canonical_authority_id((
                type(canonical).__qualname__, canonical_bytes(canonical),
            ))

    if registry is _binding_registry:
        if type(value) not in {
            model.ExactEffectBindingResult,
            model.LocalAliasScalarizationBindingResult,
            model.ProjectedEffectSiteResult,
            model.ProjectedTerminalSiteResult,
            model.ProjectedSemanticSitePhaseResult,
            model.ProjectedRouteSitePreservation,
        }:
            raise TypeError("semantic site binding has an unknown closed type")
        canonical = _canonical_record_snapshot(value)
        return _site_binding_identity(canonical)

    if registry is not _route_registry:
        raise TypeError("publication registry is not a canonical authority registry")

    route_identity_names = {
        model.ClonedSemanticInstructionOrigin: "origin_id",
        model.ClonedSemanticPrefix: "prefix_id",
        model.DirectRouteRealization: "relation_id",
        model.SharedCarrierSourceBypassRouteRealization: "relation_id",
        model.RetainedPrefixRouteRealization: "relation_id",
        model.LoweredConditionalRouteRealization: "relation_id",
        model.ClonedConditionalRouteRealization: "relation_id",
        model.FoldedConditionalRouteRealization: "relation_id",
        model.TwoArmDirectBranchRouteRealization: "relation_id",
        model.BranchFallthroughHelperRouteRealization: "relation_id",
        model.ClonedRouteCorridorRealization: "relation_id",
        model.ClonedCarrierRouteCorridorRealization: "relation_id",
        model.SourceBoundRouteAuthority: "source_authority_id",
        model.ProjectedRouteRealizationRow: "row_id",
        model.ProjectedRouteRealization: "realization_id",
    }
    route_result_types = {
        model.SourceBoundRouteAuthorityAccepted,
        model.SourceBoundRouteAuthorityRejected,
        model.ProjectedRouteRealizationAccepted,
        model.ProjectedRouteRealizationRejected,
    }
    if (
        type(value) not in route_identity_names
        and type(value) is not model.RouteRealizationFailure
        and type(value) not in route_result_types
    ):
        raise TypeError("route authority value has an unknown closed type")
    canonical = _canonical_record_snapshot(value)
    identity_name = route_identity_names.get(type(canonical))
    if identity_name is not None:
        if type(canonical) is model.SourceBoundRouteAuthority:
            route_model.validate_bound_canonical_semantic_evidence(
                canonical.bound_evidence, canonical.proposal.route_evidence,
            )
        identity = getattr(canonical, identity_name)
    elif type(canonical) is model.RouteRealizationFailure:
        identity = _route_failure_identity(canonical)
    elif type(canonical) in route_result_types:
        identity = _route_result_identity(canonical)
    else:
        raise TypeError("route authority value has an unknown closed type")
    return _route_seal(canonical, identity)


def _register_route(value: object, identity: str, _registry=_ROUTE_REGISTRY, _seal=_route_content_seal) -> object:
    seal = _seal(value, identity)
    return _register_registry_occurrence(value, seal, _registry)


def _require_registered_route_occurrence(
    value: object, _registry=_ROUTE_REGISTRY,
) -> None:
    if type(value) not in {
        model.DirectRouteRealization,
        model.SharedCarrierSourceBypassRouteRealization,
        model.RetainedPrefixRouteRealization,
        model.LoweredConditionalRouteRealization,
        model.ClonedConditionalRouteRealization,
        model.FoldedConditionalRouteRealization,
        model.ClonedSemanticInstructionOrigin, model.ClonedSemanticPrefix,
        model.TwoArmDirectBranchRouteRealization, model.BranchFallthroughHelperRouteRealization,
        model.ClonedRouteCorridorRealization,
        model.ClonedCarrierRouteCorridorRealization,
        model.SourceBoundRouteAuthority, model.ProjectedRouteRealizationRow,
        model.ProjectedRouteRealization,
        model.SourceBoundRouteAuthorityAccepted, model.SourceBoundRouteAuthorityRejected,
        model.ProjectedRouteRealizationAccepted, model.ProjectedRouteRealizationRejected,
    }:
        raise TypeError("route authority value has an unknown closed type")
    row = _registry.get(id(value))
    if row is None or row[0]() is not value:
        raise ValueError("route authority value was not minted by its kernel")


def _validate_registered_route(
    value: object, identity_name: str, _registry=_ROUTE_REGISTRY,
    _seal=_route_content_seal, *, _content_sealed: bool = False,
) -> None:
    _require_registered_route_occurrence(value, _registry)
    if _content_sealed:
        return
    row = _registry[id(value)]
    expected = _canonical_registry_seal(value, _registry)
    if row[1] != expected:
        raise ValueError("route authority content seal does not match")


def _route_mint(
    cls: type[object], values: dict[str, object], identity_name: str,
    _register=_register_route, *,
    _batch: _AtomicPublicationBatch | None = None,
    _registry=_ROUTE_REGISTRY, _seal=_route_content_seal,
) -> object:
    value = object.__new__(cls)
    for name, item in values.items():
        object.__setattr__(value, name, item)
    value.__post_init__()
    identity = getattr(value, identity_name)
    if _batch is not None:
        stored_seal = _seal(value, identity)
        return _batch.defer(
            value=value, registry=_registry, seal=stored_seal,
        )
    return _register(value, identity)


def _route_failure(*, claim_id: str | None, proof_id: str | None, route_subject_id: str | None,
                   scope: model.RouteRealizationFailureScope,
                   proposal_id: str | None, evidence_id: str | None,
                   stage: model.RouteRealizationFailureStage,
                   step_index: int | None = None, step_digest: str | None = None,
                   anchored_refs: tuple[object, ...] = (), _register=_register_route) -> model.RouteRealizationFailure:
    values = dict(
        claim_id=claim_id, proof_id=proof_id, route_subject_id=route_subject_id,
        scope=scope, proposal_id=proposal_id, evidence_id=evidence_id,
        stage=stage, step_index=step_index, step_digest=step_digest,
        anchored_refs=anchored_refs,
    )
    failure = object.__new__(model.RouteRealizationFailure)
    for name, item in values.items():
        object.__setattr__(failure, name, item)
    model.RouteRealizationFailure.__post_init__(failure)
    return _register(failure, _route_failure_identity(failure))


def _route_result(
    cls: type[object], values: dict[str, object], identity_name: str | None = None,
    _register=_register_route, *,
    _batch: _AtomicPublicationBatch | None = None,
    _registry=_ROUTE_REGISTRY, _seal=_route_content_seal,
) -> object:
    result = object.__new__(cls)
    for name, item in values.items():
        object.__setattr__(result, name, item)
    result.__post_init__()
    identity = (
        getattr(result, identity_name) if identity_name is not None
        else _route_result_identity(result)
    )
    if _batch is not None:
        stored_seal = _seal(result, identity)
        return _batch.defer(
            value=result, registry=_registry,
            seal=stored_seal,
        )
    _register(result, identity)
    return result


def _route_claims(proposal: model.ProposedUnflattenContract) -> tuple[model.EquivalentSemanticRouteClaim, ...]:
    claims = tuple(
        claim for claim in proposal.claims
        if type(claim) is model.EquivalentSemanticRouteClaim
    )
    if len({claim.claim_id for claim in claims}) != len(claims):
        raise ValueError("route claims must have unique IDs")
    return tuple(sorted(claims, key=lambda claim: claim.claim_id))


def _route_failure_coordinates(proposal: object, *, stage: model.RouteRealizationFailureStage,
                                claim: object | None = None,
                                proof_override: object | None = None,
                                fact: object | None = None,
                                descriptor: object | None = None,
                                extra_anchored_refs: tuple[object, ...] = (),
                                scope_override: object | None = None) -> dict[str, object]:
    """Build typed diagnostic coordinates without exposing validation prose."""
    claim_id = proof_id = route_subject_id = None
    proposal_id = evidence_id = None
    scope = model.RouteRealizationFailureScope.PROPOSAL
    try:
        if type(proposal) is model.ProposedUnflattenContract:
            proposal_id = authority_id(proposal)
            evidence_id = proposal.route_evidence.atomic_group_id
            scope = model.RouteRealizationFailureScope.EVIDENCE
    except (TypeError, ValueError):
        pass
    anchored: list[model.AnchoredBlockRef] = []
    if type(claim) is model.EquivalentSemanticRouteClaim:
        claim_id = claim.claim_id
        route_subject_id = claim.retired_route_subject.subject_id
        scope = model.RouteRealizationFailureScope.CLAIM
        locator = claim.retired_route_subject.locator
        refs = ((locator.source_ref, locator.source_anchor_ea),)
        refs += tuple(
            (item.block_ref, item.anchor_ea)
            for item in locator.native_destination_members()
            if type(item) is model.BlockSubjectLocator
        )
        for ref, anchor in refs:
            try:
                anchored.append(model.AnchoredBlockRef(ref, anchor))
            except (TypeError, ValueError):
                continue
        if len(claim.route_proof_ids) == 1:
            proof_id = claim.route_proof_ids[0]
    elif type(claim) is model.ExactInfeasibleEffectClaim:
        claim_id = claim.claim_id
        scope = model.RouteRealizationFailureScope.CLAIM
        for subject in (
            claim.effect_subject, claim.source_subject, claim.predicate_subject,
            claim.selected_target_subject, claim.discarded_effect_subject,
        ):
            locator = subject.locator
            for ref_name, anchor_name in (
                ("owner_ref", "owner_anchor_ea"),
                ("block_ref", "anchor_ea"),
            ):
                owner_ref = getattr(locator, ref_name, None)
                owner_anchor = getattr(locator, anchor_name, None)
                if owner_ref is not None and type(owner_anchor) is int:
                    try:
                        anchored.append(model.AnchoredBlockRef(owner_ref, owner_anchor))
                    except (TypeError, ValueError):
                        pass
        if len(claim.route_proof_ids) == 1:
            proof_id = claim.route_proof_ids[0]
    elif type(claim) is model.LocalAliasEffectScalarizationClaim:
        claim_id = claim.claim_id
        scope = model.RouteRealizationFailureScope.CLAIM
        locator = claim.owner_subject.locator
        owner_ref = getattr(locator, "block_ref", None)
        owner_anchor = getattr(locator, "anchor_ea", None)
        if owner_ref is not None and type(owner_anchor) is int:
            try:
                anchored.append(model.AnchoredBlockRef(owner_ref, owner_anchor))
            except (TypeError, ValueError):
                pass
    if proof_override is not None:
        proof_id = getattr(proof_override, "proof_id", proof_id)
    if stage is model.RouteRealizationFailureStage.ATTEMPT_BINDING:
        # Attempt binding is evidence-wide.  A transient fact must never
        # promote a preselection failure to arbitrary STEP coordinates.
        scope = model.RouteRealizationFailureScope.EVIDENCE
        claim_id = proof_id = route_subject_id = None
        anchored.clear()
        fact = None
    elif (fact is not None or descriptor is not None) and not (
        stage is model.RouteRealizationFailureStage.PLAN_STEP_CORRELATION
        and descriptor is None
    ):
        scope = model.RouteRealizationFailureScope.STEP
    for ref in extra_anchored_refs:
        if type(ref) is model.AnchoredBlockRef:
            anchored.append(ref)
    if scope_override is not None:
        scope = scope_override
    coordinate_source = fact if fact is not None else descriptor
    step_index = getattr(coordinate_source, "step_index", None)
    step_digest = getattr(coordinate_source, "step_digest", None)
    return dict(
        claim_id=claim_id,
        proof_id=proof_id,
        route_subject_id=route_subject_id,
        scope=scope,
        proposal_id=proposal_id,
        evidence_id=evidence_id,
        stage=stage,
        step_index=step_index if type(step_index) is int and not isinstance(step_index, bool) else None,
        step_digest=step_digest if type(step_digest) is str else None,
        anchored_refs=tuple(sorted(set(anchored), key=canonical_bytes)),
    )


def _validate_source_claim_bindings(
    *, claim: model.EquivalentSemanticRouteClaim,
    proposal: model.ProposedUnflattenContract,
    inventory: model.SemanticGraphInventory,
) -> None:
    """Cross-bind route subjects to the exact producer inventory rows."""
    subjects = {item.subject_id: item for item in inventory.subjects}
    bindings = {
        item.subject.subject_id: item
        for item in inventory.bindings
        if item.subject.subject_id in subjects
    }
    expected_subjects = (claim.source_subject, *claim.destination_subjects, *claim.dag_endpoint_subjects)
    catalog = {
        item.block_ref: item
        for item in proposal.source_identity_catalog.blocks
    }
    for subject in expected_subjects:
        canonical = subjects.get(subject.subject_id)
        binding = bindings.get(subject.subject_id)
        locator = subject.locator
        reminted_native_anchor = False
        if canonical != subject or binding is None:
            # A fresh evidence bundle changes the subject ID when it chooses a
            # different instruction anchor in one native block.  The source
            # inventory deliberately remains tied to its own captured anchor,
            # so recover that one row only when every semantic coordinate but
            # the native instruction anchor is identical.  The canonical
            # materialization binder has already replayed the new anchor;
            # this join merely proves it belongs to the same captured source
            # block rather than accepting a different subject or identity.
            if not (
                type(locator) is model.BlockSubjectLocator
                and type(locator.block_ref) is NativeBlockRef
            ):
                raise ValueError("route claim subject is absent from source inventory")
            witness = catalog.get(locator.block_ref)
            if witness is None:
                raise ValueError("route claim block is absent from source identity catalog")
            alternatives = tuple(
                (candidate, candidate_binding)
                for candidate_binding in inventory.bindings
                for candidate in (subjects.get(candidate_binding.subject.subject_id),)
                if candidate is not None
                and candidate_binding.status is model.SubjectBindingStatus.UNIQUE
                and candidate.kind is subject.kind
                and candidate.role is subject.role
                and type(candidate.locator) is model.BlockSubjectLocator
                and candidate_binding.block_ref == locator.block_ref
                and candidate_binding.native_instruction_eas == witness.native_instruction_eas
                and locator.anchor_ea in candidate_binding.native_instruction_eas
            )
            if len(alternatives) != 1:
                raise ValueError("route claim subject is absent from source inventory")
            canonical, binding = alternatives[0]
            reminted_native_anchor = True
        if binding.status is not model.SubjectBindingStatus.UNIQUE:
            raise ValueError("route claim subject is not uniquely source-bound")
        if type(locator) is model.LogicalFunctionExitSubjectLocator:
            if (
                binding.block_ref != locator.block_ref
                or binding.serial != locator.serial
                or binding.anchor_ea is not None
                or binding.native_instruction_eas
            ):
                raise ValueError("logical route claim binding drifted from its locator")
            continue
        if (
            binding.block_ref != locator.block_ref
            or (not reminted_native_anchor and binding.anchor_ea != locator.anchor_ea)
        ):
            raise ValueError("route claim subject binding drifted from its locator")
        witness = catalog.get(locator.block_ref)
        if witness is None:
            raise ValueError("route claim block is absent from source identity catalog")
        if binding.native_instruction_eas != witness.native_instruction_eas:
            raise ValueError("route claim source origins drifted from identity catalog")
        if type(locator.block_ref) is NativeBlockRef:
            if locator.block_ref.identity.native_key != proposal.source_identity_catalog.native_key:
                raise ValueError("route claim block uses a foreign native key")
            if locator.block_ref.identity.exact_instruction_eas != frozenset(witness.native_instruction_eas):
                raise ValueError("route claim block identity drifted from catalog")


def _catalog_stable_identity(
    witness: model.SourceBlockIdentityWitness,
    *, catalog: model.SourceIdentityCatalog,
) -> StableBlockIdentity:
    """Return the stable identity represented by one catalog-owned block."""
    if type(witness.block_ref) is NativeBlockRef:
        return witness.block_ref.identity
    return StableBlockIdentity.from_instruction_eas(
        witness.native_instruction_eas,
        native_key=catalog.native_key,
    )


def _validate_route_claim_proof_members(
    *, claim: model.EquivalentSemanticRouteClaim,
    proof: route_model.SemanticRouteProof,
    catalog: model.SourceIdentityCatalog,
) -> None:
    """Join catalog-owned route members to proof identities, not proof sites."""
    locator = claim.retired_route_subject.locator
    witnesses = {item.block_ref: item for item in catalog.blocks}

    def witness_for(ref: object, anchor_ea: int) -> model.SourceBlockIdentityWitness:
        witness = witnesses.get(ref)
        if witness is None:
            raise ValueError("route claim locator is not bound to source catalog")
        if type(ref) is NativeBlockRef:
            if not ref.identity.native_ranges.contains(anchor_ea):
                raise ValueError("route claim locator is outside source identity")
        elif witness.anchor_ea != anchor_ea:
            raise ValueError("route claim locator is not bound to source catalog")
        return witness

    source_witness = witness_for(locator.source_ref, locator.source_anchor_ea)
    # A claim's locator records the producer inventory coordinate, while a
    # newly minted canonical proof may select another replayed instruction
    # anchor in that same native block.  Canonical route binding has already
    # established that the proof anchor resolves uniquely in the immutable
    # materialization; source authority joins the two representations by their
    # catalog-owned stable identity.  The later physical step correlation
    # remains exact, so this does not permit an old plan to drift its anchors.
    if _catalog_stable_identity(source_witness, catalog=catalog) != proof.source_identity:
        raise ValueError("route claim source identity differs from canonical proof")

    native_locators = tuple(
        item for item in locator.native_destination_members()
        if type(item) is model.BlockSubjectLocator
    )
    logical_locators = tuple(
        item for item in locator.dag_endpoint_members()
        if type(item) is model.LogicalFunctionExitSubjectLocator
    )
    if len(native_locators) != len(proof.destinations):
        raise ValueError("route claim destination cardinality differs from canonical proof")
    destination_by_identity = {
        destination.target_identity: destination
        for destination in proof.destinations
    }
    if len(destination_by_identity) != len(proof.destinations):
        raise ValueError("canonical proof destinations are not identity-unique")
    claimed_identities = tuple(
        _catalog_stable_identity(
            witness_for(item.block_ref, item.anchor_ea), catalog=catalog,
        )
        for item in native_locators
    )
    if len(set(claimed_identities)) != len(claimed_identities):
        raise ValueError("route claim destinations are not identity-unique")
    if set(claimed_identities) != set(destination_by_identity):
        raise ValueError("route claim destination identities differ from canonical proof")
    expected_logical: dict[int, route_model.SemanticLogicalDagEndpoint] = {}
    if proof.state_dag is not None:
        for comparison in proof.state_dag.witness.comparisons:
            for endpoint in (comparison.true_target, comparison.false_target):
                if type(endpoint) is not route_model.SemanticLogicalDagEndpoint:
                    continue
                prior = expected_logical.setdefault(endpoint.serial, endpoint)
                if prior != endpoint:
                    raise ValueError("canonical logical DAG endpoint serial is ambiguous")
    if proof.terminal_delivery is not None:
        endpoint = proof.terminal_delivery.return_transport.logical_exit
        prior = expected_logical.setdefault(endpoint.serial, endpoint)
        if prior != endpoint:
            raise ValueError("canonical logical DAG endpoint serial is ambiguous")
    claimed_logical = {item.serial: item for item in logical_locators}
    if len(claimed_logical) != len(logical_locators):
        raise ValueError("route claim logical endpoints are not serial-unique")
    if set(claimed_logical) != set(expected_logical):
        raise ValueError("route claim logical endpoints differ from canonical proof")
    for serial, endpoint in expected_logical.items():
        ref = claimed_logical[serial].block_ref
        if (
            ref.session_id != endpoint.session_id
            or ref.proxy_token != endpoint.proxy_token
            or ref.version != endpoint.version
        ):
            raise ValueError("route claim logical endpoint identity differs from canonical proof")


def _validate_source_logical_dag_endpoints(
    proposal: model.ProposedUnflattenContract,
    source_inventory: model.SemanticGraphInventory,
) -> None:
    """Close each logical DAG leaf against the captured source reference.

    Native corridor points are closed by the graph-only materialization.  A
    logical function-exit leaf has no native identity, therefore its exact
    LogicalBlockRef must be present in the source inventory and agree with the
    canonical endpoint's session, token, and version.
    """

    expected: dict[int, route_model.SemanticLogicalDagEndpoint] = {}
    selected_proof_ids = {
        proof_id
        for claim in proposal.claims
        if type(claim) is model.EquivalentSemanticRouteClaim
        for proof_id in claim.route_proof_ids
    }
    for proof in proposal.route_evidence.route_proofs:
        if proof.proof_id not in selected_proof_ids:
            continue
        dag = proof.state_dag
        if dag is not None:
            for comparison in dag.witness.comparisons:
                for endpoint in (comparison.true_target, comparison.false_target):
                    if type(endpoint) is not route_model.SemanticLogicalDagEndpoint:
                        continue
                    prior = expected.setdefault(int(endpoint.serial), endpoint)
                    if prior != endpoint:
                        raise ValueError("logical DAG endpoint serial is ambiguous")
        if proof.terminal_delivery is not None:
            endpoint = proof.terminal_delivery.return_transport.logical_exit
            prior = expected.setdefault(int(endpoint.serial), endpoint)
            if prior != endpoint:
                raise ValueError("logical DAG endpoint serial is ambiguous")
    rows = {int(row.serial): row for row in source_inventory.blocks}
    for serial, endpoint in expected.items():
        row = rows.get(serial)
        ref = None if row is None else row.block_ref
        if (
            row is None
            or not model.is_exact_logical_function_exit_inventory_row(row)
            or ref.session_id != endpoint.session_id
            or ref.proxy_token != endpoint.proxy_token
            or ref.version != endpoint.version
        ):
            raise ValueError("logical DAG endpoint differs from source inventory")


def _bind_source_route_authority(*, proposal: model.ProposedUnflattenContract,
                                 source_inventory: model.SemanticGraphInventory,
                                 source_materialization: route_model.CanonicalRouteMaterialization,
                                 _mint=_route_mint, _failure=_route_failure, _result=_route_result) -> model.SourceBoundRouteAuthorityResult:
    """Bind the complete producer route evidence exactly once."""
    active_claim = None
    active_stage = model.RouteRealizationFailureStage.SOURCE_AUTHORITY
    try:
        if type(proposal) is not model.ProposedUnflattenContract:
            raise TypeError("source authority requires a closed proposal")
        proposal.__post_init__()
        validate_canonical_roundtrip(proposal, model.ProposedUnflattenContract)
        if type(source_inventory) is not model.SemanticGraphInventory:
            raise TypeError("source authority requires a closed source inventory")
        model.validate_semantic_graph_inventory(source_inventory)
        if source_inventory.phase is not model.UnflattenAuthorityPhase.PRODUCER_FORECAST:
            raise ValueError("source inventory must be producer forecast")
        if type(source_materialization) is not route_model.CanonicalRouteMaterialization:
            raise TypeError("source authority requires a captured materialization")
        generation = proposal.source_identity_catalog.generation
        if source_inventory.generation != generation or source_materialization.generation != generation:
            raise ValueError("source generation differs from proposal")
        if source_inventory.graph_fingerprint != source_materialization.graph_fingerprint:
            raise ValueError("source inventory fingerprint differs from materialization")
        # Canonical route materialization intentionally owns only immutable CFG
        # snapshots.  A logical DAG leaf additionally carries the live
        # LogicalBlockRef session/token/version, so bind that identity once
        # against the transaction-owned source inventory before graph replay.
        _validate_source_logical_dag_endpoints(proposal, source_inventory)
        claims = _route_claims(proposal)
        result = route_model.bind_canonical_semantic_evidence_result(
            source_materialization, proposal.route_evidence,
        )
        if result.bound_evidence is None:
            # Canonical binding is evidence-wide. Only after it returns may a
            # proof failure be associated with its exact route claim.
            if result.failures:
                failed_proof_id = result.failures[0].proof_id
                matching_claims = tuple(
                    claim for claim in claims
                    if failed_proof_id in claim.route_proof_ids
                )
                if len(matching_claims) == 1:
                    active_claim = matching_claims[0]
            logger.warning(
                "canonical source route binding rejected: failures=%r",
                result.failures,
            )
            raise ValueError(
                "canonical source route binding rejected: "
                f"failures={result.failures!r}"
            )
        proofs = tuple(sorted(proof.proof_id for proof in proposal.route_evidence.route_proofs))
        claim_proofs = tuple(sorted(proof for claim in claims for proof in claim.route_proof_ids))
        active_stage = model.RouteRealizationFailureStage.CLAIM_COVERAGE
        claim_subject_ids = tuple(
            claim.retired_route_subject.subject_id for claim in claims
        )
        if (
            any(len(claim.route_proof_ids) != 1 for claim in claims)
            or claim_proofs != tuple(sorted(set(claim_proofs)))
            or any(proof_id not in proofs for proof_id in claim_proofs)
            or len(claim_subject_ids) != len(set(claim_subject_ids))
        ):
            raise ValueError(
                "route claims must select canonical proofs at most once"
            )
        for claim in claims:
            locator = claim.retired_route_subject.locator
            if locator.proof_id not in proofs or locator.atomic_group_id != proposal.route_evidence.atomic_group_id:
                raise ValueError("route claim locator is foreign to source evidence")
            if claim.source_generation != generation:
                raise ValueError("route claim generation differs from source authority")
            proof = next(
                (item for item in proposal.route_evidence.route_proofs
                 if item.proof_id == locator.proof_id),
                None,
            )
            if proof is None:
                raise ValueError("route claim proof is absent from source evidence")
            active_claim = claim
            _validate_route_claim_proof_members(
                claim=claim,
                proof=proof,
                catalog=proposal.source_identity_catalog,
            )
            _validate_source_claim_bindings(
                claim=claim, proposal=proposal, inventory=source_inventory,
            )
        values = dict(
            phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
            proposal=proposal,
            proposal_id=authority_id(proposal),
            plan_id=proposal.plan_id,
            source_native_key=proposal.source_identity_catalog.native_key,
            source_fingerprint=source_inventory.graph_fingerprint,
            source_inventory_digest=source_inventory.inventory_digest,
            source_generation=generation,
            evidence_id=proposal.route_evidence.atomic_group_id,
            bound_evidence=result.bound_evidence,
            covered_proof_ids=proofs,
            covered_claim_ids=tuple(claim.claim_id for claim in claims),
        )
        # The model computes and checks the canonical ID from the complete
        # authority payload; the lexical kernel supplies no caller ID.
        provisional = _mint(
            model.SourceBoundRouteAuthority,
            {**values, "source_authority_id": source_route_authority_id((
                values["phase"], values["proposal_id"], values["plan_id"],
                values["source_native_key"], values["source_fingerprint"],
                values["source_inventory_digest"], values["source_generation"],
                values["evidence_id"], values["bound_evidence"],
                values["covered_proof_ids"], values["covered_claim_ids"],
            ))},
            "source_authority_id",
        )
        return _result(model.SourceBoundRouteAuthorityAccepted, {"authority": provisional})
    except (TypeError, ValueError):
        failure = _failure(**_route_failure_coordinates(
            proposal, stage=active_stage,
            claim=active_claim,
        ))
        return _result(model.SourceBoundRouteAuthorityRejected, {"failures": (failure,)})


def _inventory_block(inventory: model.SemanticGraphInventory, ref: object) -> object:
    rows = tuple(item for item in inventory.blocks if item.block_ref == ref)
    if len(rows) != 1:
        raise ValueError("route coordinate must resolve to exactly one inventory block")
    return rows[0]


def _normalized_branch_observation(observation: object) -> tuple[object, ...]:
    """Return feeder semantics with only the approved target slot erased."""
    predicate = observation.predicate_observation
    return (
        observation.ordinal, observation.instruction_ea,
        observation.opcode, observation.raw_opcode, observation.width,
        observation.instruction_kind, observation.control_transfer_kind,
        observation.is_call, observation.call_kind, observation.display_text,
        None if predicate is None else (
            predicate.predicate_kind, predicate.storage_identity,
            predicate.width, predicate.compare_constant,
        ),
    )


def _expected_projected_branch_target(
    *,
    source_explicit_target: int,
    old_target: int,
    untouched_target: int,
    projected_untouched_target: int,
    new_target: int,
    has_fallthrough_helper: bool,
) -> int:
    """Replay the source branch arm role after one exact edge replacement."""
    if source_explicit_target == old_target:
        if has_fallthrough_helper:
            raise ValueError(
                "fallthrough helper cannot replace the source explicit arm"
            )
        return new_target
    if source_explicit_target == untouched_target:
        return projected_untouched_target
    raise ValueError("source predicate target is not one source branch arm")


def _require_projected_feeder_semantics(source_row: object, projected_row: object) -> None:
    if tuple(_normalized_branch_observation(item) for item in source_row.instruction_observations) != tuple(
        _normalized_branch_observation(item) for item in projected_row.instruction_observations
    ):
        raise ValueError("projected branch feeder semantics differ from source")
    if (
        source_row.tail_opcode != projected_row.tail_opcode
        or source_row.raw_tail_opcode != projected_row.raw_tail_opcode
        or source_row.tail_kind is not projected_row.tail_kind
        or source_row.block_kind is not projected_row.block_kind
        or source_row.transfer_ea != projected_row.transfer_ea
    ):
        raise ValueError("projected branch feeder tail differs from source")


def _require_synthetic_goto_helper(
    row: object,
    projected_inventory: model.SemanticGraphInventory,
) -> None:
    observations = row.instruction_observations
    if (
        type(projected_inventory) is not model.SemanticGraphInventory
        or sum(item is row for item in projected_inventory.blocks) != 1
    ):
        raise ValueError("branch helper is not an exact projected inventory row")
    if (
        row.block_kind is not BlockKind.ONE_WAY
        or not observations
        or row.tail_opcode != -1
        or row.raw_tail_opcode is not None
        or row.tail_kind is not InsnKind.GOTO
        or row.graph_start_ea != row.anchor_ea
    ):
        raise ValueError("branch helper is not the canonical synthetic GOTO")
    observation = observations[-1]
    if (
        observation.opcode != -1
        or observation.raw_opcode is not None
        or observation.width != 0
        or observation.instruction_kind is not InsnKind.GOTO
        or observation.control_transfer_kind is not ControlTransferKind.GOTO
        or observation.is_call
        or observation.call_kind is not None
        or observation.predicate_observation is not None
        or observation.display_text != ""
        or row.transfer_ea != observation.instruction_ea
    ):
        raise ValueError("branch helper body is not the canonical synthetic GOTO")

    def observation_occurrence(
        *, owner_serial: int, owner_ref: object, owner_anchor_ea: int,
        ordinal: int | None, instruction_ea: int,
        opcode: int | None = None, width: int | None = None,
    ) -> tuple[object, ...] | None:
        if (
            type(ordinal) is not int
            or ordinal < 0
            or ordinal >= len(observations)
        ):
            return None
        observed = observations[ordinal]
        return (
            owner_serial, owner_ref, owner_anchor_ea,
            observed.ordinal, instruction_ea,
            observed.instruction_kind,
            observed.opcode if opcode is None else opcode,
            observed.raw_opcode,
            observed.width if width is None else width,
        )

    semantic_occurrences = tuple(
        occurrence
        for occurrence in (
            *(
                observation_occurrence(
                    owner_serial=site.owner_serial,
                    owner_ref=site.owner_ref,
                    owner_anchor_ea=site.owner_anchor_ea,
                    ordinal=site.instruction_ordinal,
                    instruction_ea=site.instruction_ea,
                    opcode=site.opcode, width=site.width,
                )
                for site in projected_inventory.effects
                if site.owner_serial == row.serial
            ),
            *(
                observation_occurrence(
                    owner_serial=site.owner_serial,
                    owner_ref=site.owner_ref,
                    owner_anchor_ea=site.owner_anchor_ea,
                    ordinal=site.instruction_ordinal,
                    instruction_ea=site.instruction_ea,
                )
                for site in projected_inventory.terminals
                if site.owner_serial == row.serial
            ),
        )
        if occurrence is not None
    )
    for prefix in observations[:-1]:
        prefix_occurrence = (
            row.serial, row.block_ref, row.anchor_ea,
            prefix.ordinal, prefix.instruction_ea,
            prefix.instruction_kind, prefix.opcode,
            prefix.raw_opcode, prefix.width,
        )
        if prefix_occurrence not in semantic_occurrences:
            raise ValueError(
                "branch helper prefix has no exact projected semantic occurrence"
            )


def _require_corridor_source_retention(
    source_inventory: model.SemanticGraphInventory,
    projected_inventory: model.SemanticGraphInventory,
    source_refs: tuple[object, ...],
) -> None:
    for ref in source_refs:
        source_row = _inventory_block(source_inventory, ref)
        projected_row = _inventory_block(projected_inventory, ref)
        if (
            source_row.instruction_observations != projected_row.instruction_observations
            or source_row.tail_opcode != projected_row.tail_opcode
            or source_row.raw_tail_opcode != projected_row.raw_tail_opcode
            or source_row.tail_kind is not projected_row.tail_kind
            or source_row.block_kind is not projected_row.block_kind
            or source_row.transfer_ea != projected_row.transfer_ea
        ):
            raise ValueError("projected corridor source prefix differs from source")


def _ref_and_serial(value: object, serial_by_ref: Mapping[object, int]) -> tuple[object, int]:
    if value in serial_by_ref:
        return value, serial_by_ref[value]
    if type(value) is int and value in set(serial_by_ref.values()):
        ref = next(ref for ref, serial in serial_by_ref.items() if serial == value)
        return ref, value
    raise ValueError("plan step coordinate is foreign to inventory")


def _ref_matches_identity(ref: object, identity: object) -> bool:
    return type(ref) is NativeBlockRef and ref.identity == identity


@dataclass(frozen=True, slots=True)
class _LineageExpectedFact:
    owner_ref: object
    creation_spec_digest: str | None


class _LineageFactViolation(ValueError):
    def __init__(self, message: str, *, stage: model.RouteRealizationFailureStage,
                 descriptor: CanonicalPatchStepDescriptor | None,
                 fact: model.PatchStepEvidencePayload | None) -> None:
        super().__init__(message)
        self.stage = stage
        self.descriptor = descriptor
        self.fact = fact


@dataclass(frozen=True, slots=True)
class _LineageFactGroupEntry:
    descriptor: CanonicalPatchStepDescriptor
    expected_facts: tuple[_LineageExpectedFact, ...]
    facts: tuple[model.PatchStepEvidencePayload, ...]
    violation: _LineageFactViolation | None


@dataclass(frozen=True, slots=True)
class _LineageFactGroupIndex:
    entries: tuple[_LineageFactGroupEntry, ...]


def _index_lineage_fact_groups(
    plan: PatchPlan,
    patch_step_facts: tuple[model.PatchStepEvidencePayload, ...],
) -> _LineageFactGroupIndex:
    """Build the one canonical fact/descriptor view for a binder call."""
    if type(plan) is not PatchPlan:
        raise TypeError("lineage facts require a closed PatchPlan")
    if type(patch_step_facts) is not tuple:
        raise TypeError("patch_step_facts must be an exact tuple")
    facts = tuple(sorted(patch_step_facts, key=canonical_bytes))
    for fact in facts:
        if type(fact) is not model.PatchStepEvidencePayload:
            raise TypeError("patch_step_facts must contain closed evidence payloads")
    descriptors = canonical_patch_step_descriptors(plan)
    by_identity: dict[tuple[int, str], CanonicalPatchStepDescriptor] = {}
    for descriptor in descriptors:
        identity = (descriptor.step_index, descriptor.step_digest)
        if identity in by_identity:
            raise ValueError("canonical plan descriptors have duplicate identity")
        by_identity[identity] = descriptor
    grouped: dict[int, list[model.PatchStepEvidencePayload]] = {
        descriptor.step_index: [] for descriptor in descriptors
    }
    # The envelope is intentionally checked before identity correlation.
    for fact in facts:
        if fact.plan_id != plan.plan_id:
            raise _LineageFactViolation(
                "patch step fact is foreign to attempt plan",
                stage=model.RouteRealizationFailureStage.ATTEMPT_BINDING,
                descriptor=None, fact=None,
            )
        descriptor = by_identity.get((fact.step_index, fact.step_digest))
        if descriptor is None:
            raise _LineageFactViolation(
                "patch step fact has no exact descriptor identity",
                stage=model.RouteRealizationFailureStage.PLAN_STEP_CORRELATION,
                descriptor=None, fact=fact,
            )
        grouped[descriptor.step_index].append(fact)

    entries: list[_LineageFactGroupEntry] = []
    for descriptor in descriptors:
        expected_specs = dict(descriptor.new_block_spec_digests)
        expected = tuple(
            _LineageExpectedFact(owner, expected_specs.get(owner))
            for owner in descriptor.owner_refs
        )
        supplied = tuple(grouped[descriptor.step_index])
        violation: _LineageFactViolation | None = None
        # Validate each non-identity field once, in the fixed precedence.
        for fact in supplied:
            if (
                fact.step_type != descriptor.step_type
                or fact.host_ea != descriptor.host_ea
                or fact.host_opcode != descriptor.host_opcode
                or fact.value_size is not None
            ):
                violation = _LineageFactViolation(
                    "patch step fact differs from descriptor fields",
                    stage=model.RouteRealizationFailureStage.PLAN_STEP_CORRELATION,
                    descriptor=descriptor, fact=fact,
                )
                break
        if violation is None:
            keys = [(fact.plan_id, fact.step_index, fact.owner_ref) for fact in supplied]
            duplicate = len(keys) != len(set(keys))
            if duplicate:
                violation = _LineageFactViolation(
                    "patch step facts contain a duplicate owner",
                    stage=model.RouteRealizationFailureStage.HELPER_LINEAGE,
                    descriptor=descriptor, fact=supplied[0] if supplied else None,
                )
        if violation is None:
            owners = {fact.owner_ref for fact in supplied}
            expected_owners = {item.owner_ref for item in expected}
            if len(supplied) != len(expected) or owners != expected_owners:
                violation = _LineageFactViolation(
                    "patch step fact group does not cover descriptor owners",
                    stage=model.RouteRealizationFailureStage.HELPER_LINEAGE,
                    descriptor=descriptor, fact=supplied[0] if supplied else None,
                )
        if violation is None:
            expected_by_owner = {item.owner_ref: item.creation_spec_digest for item in expected}
            for fact in sorted(supplied, key=lambda item: canonical_bytes(item)):
                if fact.creation_spec_digest != expected_by_owner.get(fact.owner_ref):
                    violation = _LineageFactViolation(
                        "patch step fact creation digest differs from descriptor",
                        stage=model.RouteRealizationFailureStage.HELPER_LINEAGE,
                        descriptor=descriptor, fact=fact,
                    )
                    break
        if violation is None:
            ordered = tuple(
                next(fact for fact in supplied if fact.owner_ref == expected_fact.owner_ref)
                for expected_fact in expected
            )
        else:
            ordered = supplied
        entries.append(_LineageFactGroupEntry(descriptor, expected, ordered, violation))
    return _LineageFactGroupIndex(tuple(entries))


def _descriptor_refs_match(ref: object, target: object) -> bool:
    return ref == target or _ref_matches_identity(ref, target)


def _state_transform_direct_old_target_is_proof_owned(
    proof: route_model.SemanticRouteProof,
    old_target_ref: object,
) -> bool:
    """Return whether a direct transform route owns its bypassed feeder."""
    transform = proof.state_transform
    return bool(
        proof.proof_kind is route_model.SemanticRouteProofKind.STATE_TRANSFORM
        and proof.shape is route_model.SemanticRouteShape.DIRECT
        and transform is not None
        and _ref_matches_identity(old_target_ref, transform.feeder_identity)
    )


def _owner_bound_direct_coordinates_match(
    plan: PatchPlan,
    proof: route_model.SemanticRouteProof,
    descriptor: CanonicalPatchStepDescriptor,
) -> bool:
    """Match owner -> proof source -> direct destination without inference."""
    if (
        descriptor.step_kind not in {
            PatchStepKind.REDIRECT_GOTO,
            PatchStepKind.REDIRECT_BRANCH,
        }
        or descriptor.step_index < 0
        or descriptor.step_index >= len(plan.steps)
        or type(plan.steps[descriptor.step_index]) not in {
            PatchRedirectGoto,
            PatchRedirectBranch,
        }
        or len(descriptor.route_refs) != 3
        or descriptor.helper_refs
        or proof.shape is not route_model.SemanticRouteShape.DIRECT
        or proof.source_owner_identity is None
        or proof.source_owner_anchor_ea is None
        or len(proof.destinations) != 1
        or proof.destinations[0].role is not SemanticEdgeRole.DIRECT
    ):
        return False
    step = plan.steps[descriptor.step_index]
    owner_ref, old_ref, new_ref = descriptor.route_refs
    destination = proof.destinations[0]
    return bool(
        step.from_serial == owner_ref
        and step.old_target == old_ref
        and step.new_target == new_ref
        and _ref_matches_identity(owner_ref, proof.source_owner_identity)
        and _ref_matches_identity(old_ref, proof.source_identity)
        and _ref_matches_identity(new_ref, destination.target_identity)
    )


def _proof_source_direct_coordinates_match(
    plan: PatchPlan,
    proof: route_model.SemanticRouteProof,
    descriptor: CanonicalPatchStepDescriptor,
) -> bool:
    """Match a direct GOTO owned by the proof source itself exactly.

    This is deliberately narrower than the legacy source-neighborhood
    candidate set.  It is the only direct form that can supersede a retained
    prefix: the post-state already proves that the prefix delivery is
    intentionally bypassed by this exact source-to-destination rewrite.
    """
    if (
        descriptor.step_kind is not PatchStepKind.REDIRECT_GOTO
        or descriptor.step_index < 0
        or descriptor.step_index >= len(plan.steps)
        or type(plan.steps[descriptor.step_index]) is not PatchRedirectGoto
        or len(descriptor.route_refs) != 3
        or descriptor.helper_refs
        or proof.shape is not route_model.SemanticRouteShape.DIRECT
        or proof.proof_kind is route_model.SemanticRouteProofKind.STATE_CARRIER
        or len(proof.destinations) != 1
        or proof.destinations[0].role is not SemanticEdgeRole.DIRECT
    ):
        return False
    source_ref, _old_ref, new_ref = descriptor.route_refs
    step = plan.steps[descriptor.step_index]
    destination = proof.destinations[0]
    return bool(
        step.from_serial == source_ref
        and step.new_target == new_ref
        and _ref_matches_identity(source_ref, proof.source_identity)
        and _ref_matches_identity(new_ref, destination.target_identity)
    )


def _state_carrier_feeder_direct_coordinates_match(
    plan: PatchPlan,
    proof: route_model.SemanticRouteProof,
    descriptor: CanonicalPatchStepDescriptor,
) -> bool:
    """Match one carrier proof's typed feeder bypass exactly.

    A CONST32 carrier proves a three-point source -> feeder -> comparison
    corridor.  The semantic source is the producer, while the executable
    rewrite deliberately replaces the feeder's edge to the comparison entry.
    That is not a generic neighbourhood allowance: every coordinate comes
    from the source-bound carrier proof, and cloned feeders retain their
    separate helper realization path.
    """
    carrier = proof.state_carrier
    if (
        descriptor.step_kind is not PatchStepKind.REDIRECT_GOTO
        or descriptor.step_index < 0
        or descriptor.step_index >= len(plan.steps)
        or type(plan.steps[descriptor.step_index]) is not PatchRedirectGoto
        or len(descriptor.route_refs) != 3
        or descriptor.helper_refs
        or proof.proof_kind is not route_model.SemanticRouteProofKind.STATE_CARRIER
        or proof.shape is not route_model.SemanticRouteShape.DIRECT
        or carrier is None
        or carrier.requires_feeder_clone
        or len(proof.destinations) != 1
        or proof.destinations[0].role is not SemanticEdgeRole.DIRECT
    ):
        return False
    feeder_ref, comparison_ref, destination_ref = descriptor.route_refs
    step = plan.steps[descriptor.step_index]
    destination = proof.destinations[0]
    return bool(
        step.from_serial == feeder_ref
        and step.old_target == comparison_ref
        and step.new_target == destination_ref
        and _ref_matches_identity(feeder_ref, carrier.feeder_identity)
        and _ref_matches_identity(comparison_ref, carrier.comparison_entry_identity)
        and _ref_matches_identity(destination_ref, destination.target_identity)
    )


def _shared_state_carrier_source_bypass_coordinates_match(
    plan: PatchPlan,
    proof: route_model.SemanticRouteProof,
    descriptor: CanonicalPatchStepDescriptor,
    source_inventory: model.SemanticGraphInventory,
) -> bool:
    """Match one source-specific bypass of a genuinely shared carrier.

    Unlike the ordinary carrier realization, the patch owner is the semantic
    proof source.  The feeder must remain a source-CFG corridor shared by at
    least one other predecessor; otherwise this shape is the unsupported
    direct-source bypass rather than a distinct relation family.
    """
    carrier = proof.state_carrier
    if (
        descriptor.step_kind is not PatchStepKind.REDIRECT_GOTO
        or descriptor.step_index < 0
        or descriptor.step_index >= len(plan.steps)
        or type(plan.steps[descriptor.step_index]) is not PatchRedirectGoto
        or len(descriptor.route_refs) != 3
        or descriptor.helper_refs
        or proof.proof_kind is not route_model.SemanticRouteProofKind.STATE_CARRIER
        or proof.shape is not route_model.SemanticRouteShape.DIRECT
        or carrier is None
        or carrier.requires_feeder_clone
        or len(proof.destinations) != 1
        or proof.destinations[0].role is not SemanticEdgeRole.DIRECT
    ):
        return False
    source_ref, feeder_ref, destination_ref = descriptor.route_refs
    step = plan.steps[descriptor.step_index]
    destination = proof.destinations[0]
    if not (
        step.from_serial == source_ref
        and step.old_target == feeder_ref
        and step.new_target == destination_ref
        and _ref_matches_identity(source_ref, proof.source_identity)
        and _ref_matches_identity(source_ref, carrier.source_identity)
        and _ref_matches_identity(feeder_ref, carrier.feeder_identity)
        and _ref_matches_identity(destination_ref, destination.target_identity)
    ):
        return False
    comparison_refs = tuple(
        row.block_ref
        for row in source_inventory.blocks
        if _ref_matches_identity(
            row.block_ref, carrier.comparison_entry_identity,
        )
    )
    if len(comparison_refs) != 1:
        return False
    try:
        source_row = _inventory_block(source_inventory, source_ref)
        feeder_row = _inventory_block(source_inventory, feeder_ref)
        comparison_row = _inventory_block(
            source_inventory, comparison_refs[0],
        )
    except (KeyError, TypeError, ValueError):
        return False
    return bool(
        source_row.successor_serials == (feeder_row.serial,)
        and source_row.serial in feeder_row.predecessor_serials
        and len(feeder_row.predecessor_serials) >= 2
        and any(
            predecessor != source_row.serial
            for predecessor in feeder_row.predecessor_serials
        )
        and feeder_row.successor_serials == (comparison_row.serial,)
        and feeder_row.serial in comparison_row.predecessor_serials
    )


def _state_carrier_helper_corridor_coordinates_match(
    plan: PatchPlan,
    proof: route_model.SemanticRouteProof,
    descriptor: CanonicalPatchStepDescriptor,
) -> bool:
    """Match the cloned form of one exact state-carrier corridor.

    The operation splits the proof source's edge into a cloned feeder.  Its
    descriptor therefore records ``feeder, source, comparison, destination``
    rather than pretending the source is itself the cloned block.  All four
    coordinates are already sealed in the carrier evidence.
    """
    carrier = proof.state_carrier
    if (
        descriptor.step_kind is not PatchStepKind.HELPER_CORRIDOR
        or descriptor.step_index < 0
        or descriptor.step_index >= len(plan.steps)
        or type(plan.steps[descriptor.step_index]) is not PatchEdgeSplitCorridor
        or len(descriptor.route_refs) < 5
        or not descriptor.helper_refs
        or proof.proof_kind is not route_model.SemanticRouteProofKind.STATE_CARRIER
        or proof.shape is not route_model.SemanticRouteShape.DIRECT
        or carrier is None
        or not carrier.requires_feeder_clone
        or len(proof.destinations) != 1
        or proof.destinations[0].role is not SemanticEdgeRole.DIRECT
    ):
        return False
    feeder_ref, source_ref, comparison_ref, destination_ref, clone_until_ref = (
        descriptor.route_refs[:5]
    )
    step = plan.steps[descriptor.step_index]
    destination = proof.destinations[0]
    return bool(
        step.source_serial == feeder_ref
        and step.via_pred == source_ref
        and step.old_target == comparison_ref
        and step.new_target == destination_ref
        and step.clone_until == clone_until_ref
        and len(step.corridor_serials) == 1
        and step.corridor_serials[0] == feeder_ref
        and clone_until_ref == feeder_ref
        and _ref_matches_identity(source_ref, carrier.source_identity)
        and _ref_matches_identity(feeder_ref, carrier.feeder_identity)
        and _ref_matches_identity(comparison_ref, carrier.comparison_entry_identity)
        and _ref_matches_identity(destination_ref, destination.target_identity)
    )


def _retained_prefix_direct_coordinates_match(
    plan: PatchPlan,
    proof: route_model.SemanticRouteProof,
    descriptor: CanonicalPatchStepDescriptor,
    source_inventory: model.SemanticGraphInventory,
) -> bool:
    """Match proof-source -> delivery-owner -> rewritten destination exactly."""
    if (
        descriptor.step_kind is not PatchStepKind.REDIRECT_GOTO
        or descriptor.step_index < 0
        or descriptor.step_index >= len(plan.steps)
        or type(plan.steps[descriptor.step_index]) is not PatchRedirectGoto
        or len(descriptor.route_refs) != 3
        or descriptor.helper_refs
        or proof.proof_kind is not route_model.SemanticRouteProofKind.STATE_ASSIGNMENT
        or proof.shape is not route_model.SemanticRouteShape.DIRECT
        or proof.source_owner_identity is not None
        or len(proof.destinations) != 1
        or proof.destinations[0].role is not SemanticEdgeRole.DIRECT
    ):
        return False
    delivery_ref, _old_ref, new_ref = descriptor.route_refs
    source_matches = tuple(
        row for row in source_inventory.blocks
        if _ref_matches_identity(row.block_ref, proof.source_identity)
    )
    if len(source_matches) != 1:
        return False
    source_row = source_matches[0]
    delivery_serial = source_inventory.serial_by_ref.get(delivery_ref)
    if delivery_serial is None or delivery_ref == source_row.block_ref:
        return False
    try:
        delivery_row = _inventory_block(source_inventory, delivery_ref)
    except (KeyError, TypeError, ValueError):
        return False
    step = plan.steps[descriptor.step_index]
    destination = proof.destinations[0]
    return bool(
        step.from_serial == delivery_ref
        and step.old_target == descriptor.route_refs[1]
        and step.new_target == new_ref
        and source_row.successor_serials == (delivery_serial,)
        and source_row.serial in delivery_row.predecessor_serials
        and _ref_matches_identity(new_ref, destination.target_identity)
    )


def _native_route_destination_subject_for_target_ref(
    *,
    claim: model.EquivalentSemanticRouteClaim,
    proof: route_model.SemanticRouteProof,
    target_ref: object,
    catalog: model.SourceIdentityCatalog,
) -> model.SemanticSubjectRef:
    """Resolve one physical target through the proof, never route-member order."""
    destinations = tuple(
        destination for destination in proof.destinations
        if _ref_matches_identity(target_ref, destination.target_identity)
    )
    if len(destinations) != 1:
        raise ValueError("route target does not select one native proof destination")
    subject = _native_route_destination_subject_for_proof_destination(
        claim=claim,
        proof_destination=destinations[0],
        catalog=catalog,
    )
    if subject.block_ref != target_ref:
        raise ValueError("route proof destination differs from typed target locator")
    return subject


def _guarded_conditional_fold_coordinates_match(
    plan: PatchPlan,
    proof: route_model.SemanticRouteProof,
    descriptor: CanonicalPatchStepDescriptor,
) -> bool:
    """Match the sole exact conditional fold admitted by route authority."""
    if (
        descriptor.step_kind is not PatchStepKind.CONVERT_TO_GOTO
        or descriptor.step_index < 0
        or descriptor.step_index >= len(plan.steps)
        or type(plan.steps[descriptor.step_index]) is not PatchConvertToGoto
        or len(descriptor.route_refs) != 2
        or descriptor.helper_refs
        or proof.proof_kind
        is not route_model.SemanticRouteProofKind.STATE_ASSIGNMENT
        or proof.shape is not route_model.SemanticRouteShape.DIRECT
        or proof.state_write is None
        or proof.state_write.guarded_selection is None
        or len(proof.destinations) != 1
        or proof.destinations[0].role is not SemanticEdgeRole.DIRECT
    ):
        return False
    feeder_ref, selected_ref = descriptor.route_refs
    step = plan.steps[descriptor.step_index]
    guarded = proof.state_write.guarded_selection
    destination = proof.destinations[0]
    return bool(
        step.block_serial == feeder_ref
        and step.goto_target == selected_ref
        and _ref_matches_identity(feeder_ref, proof.source_identity)
        and _ref_matches_identity(feeder_ref, guarded.guard.identity)
        and _ref_matches_identity(selected_ref, guarded.selected_target.identity)
        and _ref_matches_identity(selected_ref, destination.target_identity)
    )


def _default_gap_conditional_fold_parts(
    plan: PatchPlan,
    proof: route_model.SemanticRouteProof,
    descriptor: CanonicalPatchStepDescriptor,
) -> tuple[route_model.SemanticRouteDestination, route_model.SemanticRouteDestination] | None:
    """Return the selected/default arms for one typed default-gap fold only.

    This is intentionally topology correlation, not infeasibility validation:
    the default-gap binder still replays the u32 comparison/state closure.
    """
    forecast = plan.unflatten_proposal.corridor_coverage_forecast
    if (
        type(forecast) is not model.DefaultGapInfeasibilityForecast
        or descriptor.step_kind is not PatchStepKind.CONVERT_TO_GOTO
        or descriptor.step_index < 0
        or descriptor.step_index >= len(plan.steps)
        or type(plan.steps[descriptor.step_index]) is not PatchConvertToGoto
        or len(descriptor.route_refs) != 2
        or descriptor.helper_refs
        or proof.proof_kind is not route_model.SemanticRouteProofKind.STATE_CHOICE
        or proof.shape is not route_model.SemanticRouteShape.CONDITIONAL
        or len(proof.destinations) != 2
    ):
        return None
    feeder_ref, selected_ref = descriptor.route_refs
    step = plan.steps[descriptor.step_index]
    if (
        step.block_serial != feeder_ref
        or step.goto_target != selected_ref
        or not _ref_matches_identity(feeder_ref, proof.source_identity)
    ):
        return None
    selected = tuple(
        destination for destination in proof.destinations
        if _ref_matches_identity(selected_ref, destination.target_identity)
    )
    if len(selected) != 1:
        return None
    opposite = tuple(
        destination for destination in proof.destinations
        if destination is not selected[0]
    )
    if len(opposite) != 1:
        return None
    exclusion = tuple(
        item for item in forecast.exclusions
        if item.route_proof_ids == (proof.proof_id,)
        and _descriptor_refs_match(item.default_entry.block_ref, opposite[0].target_identity)
        and _descriptor_refs_match(item.residual.block_ref, opposite[0].target_identity)
    )
    if len(exclusion) != 1:
        return None
    linked = tuple(path for path in forecast.paths if path.exclusion_id == exclusion[0].exclusion_id)
    if (
        len(linked) != 1
        or linked[0].nodes[0] != exclusion[0].residual
        or linked[0].nodes[-1] != exclusion[0].dispatcher
    ):
        return None
    return selected[0], opposite[0]


def _default_gap_conditional_fold_coordinates_match(
    plan: PatchPlan,
    proof: route_model.SemanticRouteProof,
    descriptor: CanonicalPatchStepDescriptor,
) -> bool:
    return _default_gap_conditional_fold_parts(plan, proof, descriptor) is not None


def _exact_selected_arm_claim_bundle(
    *, plan: PatchPlan, route_claim: model.EquivalentSemanticRouteClaim,
    proof: route_model.SemanticRouteProof,
    descriptor: CanonicalPatchStepDescriptor,
) -> tuple[
    route_model.SemanticRouteDestination,
    route_model.SemanticRouteDestination,
    tuple[model.ExactInfeasibleEffectClaim, ...],
]:
    """Reconstruct one exact conditional-proof/direct-physical correlation."""
    if (
        descriptor.step_kind is not PatchStepKind.REDIRECT_GOTO
        or descriptor.step_index < 0
        or descriptor.step_index >= len(plan.steps)
        or type(plan.steps[descriptor.step_index]) is not PatchRedirectGoto
        or len(descriptor.route_refs) != 3
        or descriptor.helper_refs
        or proof.proof_kind is not route_model.SemanticRouteProofKind.STATE_CHOICE
        or proof.shape is not route_model.SemanticRouteShape.CONDITIONAL
        or proof.source_owner_identity is None
        or proof.source_owner_anchor_ea is None
        or proof.state_write is None
        or proof.predicate is None
        or len(proof.destinations) != 2
    ):
        raise ValueError("selected-arm direct correlation has the wrong closed shape")
    step = plan.steps[descriptor.step_index]
    feeder_ref, old_ref, new_ref = descriptor.route_refs
    if (
        step.from_serial != feeder_ref
        or step.old_target != old_ref
        or step.new_target != new_ref
        or not _ref_matches_identity(feeder_ref, proof.source_owner_identity)
        or not _ref_matches_identity(old_ref, proof.source_identity)
    ):
        raise ValueError("selected-arm direct physical roles differ from proof")
    destinations = {destination.role: destination for destination in proof.destinations}
    if set(destinations) != {
        SemanticEdgeRole.CONDITIONAL_TAKEN,
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
    }:
        raise ValueError("selected-arm direct proof roles are not opposite")
    selected = tuple(
        destination for destination in proof.destinations
        if _ref_matches_identity(new_ref, destination.target_identity)
    )
    if len(selected) != 1:
        raise ValueError("selected-arm direct target is not one proof destination")
    selected_destination = selected[0]
    discarded_destination = next(
        destination for destination in proof.destinations
        if destination is not selected_destination
    )
    opposite_role = (
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH
        if selected_destination.role is SemanticEdgeRole.CONDITIONAL_TAKEN
        else SemanticEdgeRole.CONDITIONAL_TAKEN
    )
    if (
        discarded_destination.role is not opposite_role
        or _ref_matches_identity(
            discarded_destination.target_identity,
            selected_destination.target_identity,
        )
    ):
        raise ValueError("selected-arm direct discarded destination is not opposite")
    exact_claims = tuple(
        item for item in plan.unflatten_proposal.claims
        if type(item) is model.ExactInfeasibleEffectClaim
        and item.route_proof_ids == (proof.proof_id,)
    )
    if not exact_claims:
        raise ValueError("selected-arm direct correlation has no exact site claims")
    state_write = proof.state_write
    predicate = proof.predicate
    for exact_claim in exact_claims:
        source_locator = exact_claim.source_subject.locator
        predicate_locator = exact_claim.predicate_subject.locator
        selected_locator = exact_claim.selected_target_subject.locator
        effect_locator = exact_claim.discarded_effect_subject.locator
        if (
            source_locator.block_ref != feeder_ref
            or source_locator.anchor_ea != proof.source_owner_anchor_ea
            or predicate_locator.block_ref != old_ref
            or predicate_locator.anchor_ea != proof.source_anchor_ea
            or selected_locator.block_ref != new_ref
            or selected_locator.anchor_ea != selected_destination.target_anchor_ea
            or exact_claim.selected_edge_role is not selected_destination.role
            or effect_locator.owner_anchor_ea != discarded_destination.target_anchor_ea
            or not _ref_matches_identity(
                effect_locator.owner_ref, discarded_destination.target_identity,
            )
            or exact_claim.effect_subject is not exact_claim.discarded_effect_subject
            or exact_claim.discarded_effect_ea != effect_locator.instruction_ea
            or exact_claim.state_identity != state_write.state_variable
            or exact_claim.state_identity != predicate.storage_identity
            or exact_claim.normalized_state != state_write.state_constant
            or exact_claim.normalized_state != predicate.compare_constant
            or exact_claim.normalized_state != selected_destination.state_constant
            or exact_claim.width != state_write.width
            or exact_claim.width != predicate.width
            or exact_claim.source_write_ea != state_write.instruction_ea
            or exact_claim.predicate_branch_ea != predicate.consumer.anchor_ea
            or exact_claim.source_generation != route_claim.source_generation
        ):
            raise ValueError("selected-arm direct exact claim bundle is inconsistent")
    selected_subject = _native_route_destination_subject_for_proof_destination(
        claim=route_claim,
        proof_destination=selected_destination,
        catalog=plan.unflatten_proposal.source_identity_catalog,
    )
    if selected_subject.block_ref != new_ref:
        raise ValueError("selected-arm direct target is foreign to route claim")
    if len({item.claim_id for item in exact_claims}) != len(exact_claims):
        raise ValueError("selected-arm direct exact claim bundle is duplicated")
    return selected_destination, discarded_destination, exact_claims


def _select_lineage_fact_group(
    index: _LineageFactGroupIndex,
    *, plan: PatchPlan,
    claim: model.EquivalentSemanticRouteClaim,
    proof: route_model.SemanticRouteProof,
    source_inventory: model.SemanticGraphInventory,
    entry_liveness_receipts: tuple[model.BoundEntryEndpointLivenessAllowance, ...] = (),
) -> _LineageFactGroupEntry:
    """Select one descriptor using only closed step and structural coordinates."""
    source_ref = claim.source_subject.locator.block_ref
    is_conditional = (
        proof.proof_kind is route_model.SemanticRouteProofKind.STATE_CHOICE
        and proof.shape is route_model.SemanticRouteShape.CONDITIONAL
    )
    entries = index.entries
    def kind_entries(kind: PatchStepKind):
        return tuple(entry for entry in entries if entry.descriptor.step_kind is kind)

    direct = tuple(
        entry for entry in kind_entries(PatchStepKind.REDIRECT_GOTO)
        if any(
            _descriptor_refs_match(owner_ref, source_ref)
            for owner_ref in entry.descriptor.owner_refs
        )
    ) + tuple(
        entry for entry in kind_entries(PatchStepKind.BYPASS_TRAMPOLINE)
        if any(
            _descriptor_refs_match(owner_ref, source_ref)
            for owner_ref in entry.descriptor.owner_refs
        )
    )
    branch = tuple(
        entry for entry in kind_entries(PatchStepKind.REDIRECT_BRANCH)
        if type(plan.steps[entry.descriptor.step_index]) is PatchRedirectBranch
        and _descriptor_refs_match(plan.steps[entry.descriptor.step_index].from_serial, source_ref)
    )
    split = tuple(
        entry for entry in kind_entries(PatchStepKind.SPLIT)
        if type(plan.steps[entry.descriptor.step_index]) is PatchEdgeSplitTrampoline
        and _descriptor_refs_match(plan.steps[entry.descriptor.step_index].source_serial, source_ref)
    )
    corridor = tuple(
        entry for entry in kind_entries(PatchStepKind.HELPER_CORRIDOR)
        if type(plan.steps[entry.descriptor.step_index]) is PatchEdgeSplitCorridor
        and source_ref in plan.steps[entry.descriptor.step_index].corridor_serials
    )
    lower_exact = tuple(
        entry for entry in kind_entries(PatchStepKind.LOWER_CONDITIONAL)
        if entry.descriptor.route_refs
        and _descriptor_refs_match(entry.descriptor.route_refs[0], proof.source_owner_identity)
    ) if is_conditional else ()
    lower_fallback = tuple(
        entry for entry in kind_entries(PatchStepKind.LOWER_CONDITIONAL)
        if len(entry.descriptor.route_refs) > 1
        and _descriptor_refs_match(entry.descriptor.route_refs[1], proof.source_identity)
    ) if is_conditional else ()
    conditional_exact = tuple(
        entry for entry in kind_entries(PatchStepKind.CONDITIONAL_REDIRECT)
        if entry.descriptor.route_refs
        and _descriptor_refs_match(entry.descriptor.route_refs[0], proof.source_owner_identity)
    ) if is_conditional else ()
    conditional_fallback = tuple(
        entry for entry in kind_entries(PatchStepKind.CONDITIONAL_REDIRECT)
        if len(entry.descriptor.route_refs) > 1
        and _descriptor_refs_match(entry.descriptor.route_refs[1], proof.source_identity)
    ) if is_conditional else ()
    exact_selected_arm_direct = tuple(
        entry for entry in kind_entries(PatchStepKind.REDIRECT_GOTO)
        if type(plan.steps[entry.descriptor.step_index]) is PatchRedirectGoto
        and len(entry.descriptor.route_refs) == 3
        and _descriptor_refs_match(
            entry.descriptor.route_refs[0], proof.source_owner_identity,
        )
        and _descriptor_refs_match(
            entry.descriptor.route_refs[1], proof.source_identity,
        )
        and any(
            _descriptor_refs_match(
                entry.descriptor.route_refs[2], destination.target_identity,
            )
            for destination in proof.destinations
        )
        and any(
            type(exact_claim) is model.ExactInfeasibleEffectClaim
            and exact_claim.route_proof_ids == (proof.proof_id,)
            for exact_claim in plan.unflatten_proposal.claims
        )
    ) if is_conditional else ()
    owner_bound_direct = tuple(
        entry for entry in entries
        if entry.descriptor.step_kind in {
            PatchStepKind.REDIRECT_GOTO,
            PatchStepKind.REDIRECT_BRANCH,
        }
        if _owner_bound_direct_coordinates_match(
            plan, proof, entry.descriptor,
        )
    ) if not is_conditional else ()
    retained_prefix_direct = tuple(
        entry for entry in kind_entries(PatchStepKind.REDIRECT_GOTO)
        if _retained_prefix_direct_coordinates_match(
            plan, proof, entry.descriptor, source_inventory,
        )
    ) if not is_conditional else ()
    proof_source_direct = tuple(
        entry for entry in kind_entries(PatchStepKind.REDIRECT_GOTO)
        if _proof_source_direct_coordinates_match(
            plan, proof, entry.descriptor,
        )
    ) if not is_conditional else ()
    state_carrier_feeder_direct = tuple(
        entry for entry in kind_entries(PatchStepKind.REDIRECT_GOTO)
        if _state_carrier_feeder_direct_coordinates_match(
            plan, proof, entry.descriptor,
        )
    ) if not is_conditional else ()
    shared_state_carrier_source_bypass = tuple(
        entry for entry in kind_entries(PatchStepKind.REDIRECT_GOTO)
        if _shared_state_carrier_source_bypass_coordinates_match(
            plan, proof, entry.descriptor, source_inventory,
        )
    ) if not is_conditional else ()
    state_carrier_helper_corridor = tuple(
        entry for entry in kind_entries(PatchStepKind.HELPER_CORRIDOR)
        if _state_carrier_helper_corridor_coordinates_match(
            plan, proof, entry.descriptor,
        )
    ) if not is_conditional else ()
    entry_liveness = tuple(
        entry for entry in entries
        for receipt in entry_liveness_receipts
        if entry.descriptor.step_kind in {
            PatchStepKind.REDIRECT_BRANCH, PatchStepKind.REDIRECT_GOTO,
        }
        and type(receipt) is model.BoundEntryEndpointLivenessAllowance
        and receipt.route_proof_id == proof.proof_id
        and any(receipt.patch_step_fact is fact for fact in entry.facts)
        and receipt.allowance.patch_step_index == entry.descriptor.step_index
        and receipt.allowance.patch_step_digest == entry.descriptor.step_digest
        and entry.descriptor.owner_refs == receipt.allowance.entry_predecessor_owner_refs
        and entry.descriptor.route_refs[:3] == (
            receipt.allowance.entry_predecessor_owner_refs[0],
            receipt.allowance.dispatcher_old_target_ref,
            receipt.allowance.replacement_endpoint_ref,
        )
    ) if not is_conditional else ()
    guarded_conditional_fold = tuple(
        entry for entry in kind_entries(PatchStepKind.CONVERT_TO_GOTO)
        if _guarded_conditional_fold_coordinates_match(
            plan, proof, entry.descriptor,
        )
    ) if not is_conditional else ()
    default_gap_conditional_fold = tuple(
        entry for entry in kind_entries(PatchStepKind.CONVERT_TO_GOTO)
        if _default_gap_conditional_fold_coordinates_match(
            plan, proof, entry.descriptor,
        )
    ) if is_conditional else ()
    if is_conditional:
        conditional_tier = tuple({
            entry.descriptor.step_index: entry
            for entry in (*conditional_exact, *conditional_fallback)
        }.values())
        tiers = (
            default_gap_conditional_fold, conditional_tier,
            lower_exact, lower_fallback,
            branch + split + corridor,
            exact_selected_arm_direct,
        )
        candidates = next((tier for tier in tiers if tier), ())
    else:
        candidates = (
            guarded_conditional_fold
            if guarded_conditional_fold
            else owner_bound_direct
            if owner_bound_direct
            else proof_source_direct
            if proof_source_direct
            else shared_state_carrier_source_bypass
            if shared_state_carrier_source_bypass
            else state_carrier_feeder_direct
            if state_carrier_feeder_direct
            else state_carrier_helper_corridor
            if state_carrier_helper_corridor
            else entry_liveness
            if entry_liveness
            else retained_prefix_direct
            if retained_prefix_direct
            else direct + branch + split + corridor
        )
    unique = tuple({entry.descriptor.step_index: entry for entry in candidates}.values())
    if not unique:
        def identity_serial(identity: object) -> int | None:
            return next(
                (
                    serial for ref, serial in source_inventory.serial_by_ref.items()
                    if _ref_matches_identity(ref, identity)
                ),
                None,
            )
        carrier = proof.state_carrier
        carrier_coordinates = (
            None if carrier is None else (
                identity_serial(carrier.source_identity),
                identity_serial(carrier.feeder_identity),
                identity_serial(carrier.comparison_entry_identity),
                carrier.requires_feeder_clone,
            )
        )
        proof_identities = {
            proof.source_identity,
            proof.source_owner_identity,
            *(destination.target_identity for destination in proof.destinations),
        }
        nearby = tuple(
            (
                entry.descriptor.step_index,
                entry.descriptor.step_kind.value,
                tuple(source_inventory.serial_by_ref.get(ref) for ref in entry.descriptor.route_refs),
                tuple(source_inventory.serial_by_ref.get(ref) for ref in entry.descriptor.owner_refs),
            )
            for entry in entries
            if any(
                any(_descriptor_refs_match(ref, identity) for identity in proof_identities)
                for ref in (
                    *entry.descriptor.route_refs,
                    *entry.descriptor.owner_refs,
                )
            )
        )
        logger.warning(
            "projected route has no owning step: proof=%s kind=%s shape=%s "
            "source=%r owner=%r destinations=%r carrier=%r nearby=%r",
            proof.proof_id,
            proof.proof_kind.value,
            proof.shape.value,
            proof.source_identity,
            proof.source_owner_identity,
            tuple(destination.target_identity for destination in proof.destinations),
            carrier_coordinates,
            nearby,
        )
        selected_arm_redirects = tuple(
            entry for entry in kind_entries(PatchStepKind.REDIRECT_GOTO)
            if is_conditional
            and any(
                type(exact_claim) is model.ExactInfeasibleEffectClaim
                and exact_claim.route_proof_ids == (proof.proof_id,)
                for exact_claim in plan.unflatten_proposal.claims
            )
        )
        if len(selected_arm_redirects) == 1:
            entry = selected_arm_redirects[0]
            raise _LineageFactViolation(
                "selected-arm redirect coordinates differ from proof",
                stage=model.RouteRealizationFailureStage.PLAN_STEP_CORRELATION,
                descriptor=entry.descriptor,
                fact=entry.facts[0] if entry.facts else None,
            )
        raise _LineageFactViolation(
            "projected route requires one exact owning step group",
            stage=model.RouteRealizationFailureStage.CLAIM_COVERAGE,
            descriptor=None, fact=None,
        )
    if len(unique) != 1:
        raise _LineageFactViolation(
            "projected route has ambiguous owning step groups",
            stage=model.RouteRealizationFailureStage.CLAIM_SELECTION,
            descriptor=None, fact=None,
        )
    return unique[0]


def _selected_entry_liveness_receipt(
    *, entry: _LineageFactGroupEntry,
    proof: route_model.SemanticRouteProof,
    receipts: tuple[model.BoundEntryEndpointLivenessAllowance, ...],
) -> model.BoundEntryEndpointLivenessAllowance | None:
    """Return the one receipt authorizing this exact physical redirect.

    The route proof's state-write remains the semantic source.  This receipt
    alone supplies the different physical predecessor that owns the removed
    dispatcher edge.
    """
    matches = tuple(
        receipt for receipt in receipts
        if receipt.route_proof_id == proof.proof_id
        and any(receipt.patch_step_fact is fact for fact in entry.facts)
        and receipt.allowance.patch_step_index == entry.descriptor.step_index
        and receipt.allowance.patch_step_digest == entry.descriptor.step_digest
        and entry.descriptor.step_kind in {
            PatchStepKind.REDIRECT_GOTO, PatchStepKind.REDIRECT_BRANCH,
        }
        and entry.descriptor.owner_refs
        == receipt.allowance.entry_predecessor_owner_refs
        and entry.descriptor.route_refs[:3] == (
            receipt.allowance.entry_predecessor_owner_refs[0],
            receipt.allowance.dispatcher_old_target_ref,
            receipt.allowance.replacement_endpoint_ref,
        )
    )
    if not matches:
        return None
    if len(matches) != 1:
        raise ValueError("entry liveness redirect has ambiguous receipt authority")
    return matches[0]


def _require_valid_lineage_fact_group(
    entry: _LineageFactGroupEntry,
) -> tuple[model.PatchStepEvidencePayload, ...]:
    if entry.violation is not None:
        raise entry.violation
    return entry.facts


# Compatibility source anchor retained for the approved 3B3 seam test:
# def _realize_projected_routes(
def _legacy_structural_projected_routes(*, source_authority: model.SourceBoundRouteAuthority,
                              plan: PatchPlan,
                              source_inventory: model.SemanticGraphInventory,
                              projected_inventory: model.SemanticGraphInventory,
                              patch_step_facts: tuple[model.PatchStepEvidencePayload, ...],
                              attempt_id: object,
                              entry_liveness_receipts: tuple[model.BoundEntryEndpointLivenessAllowance, ...] = (),
                              _mint=_route_mint, _failure=_route_failure, _result=_route_result,
                              _validate=_validate_registered_route,
                              _draft_factory=None) -> model.ProjectedRouteRealizationResult:
    """Validate and mint the structural relation for each selected route.

    The public kernel supplies ``_draft_factory`` so this legacy validator can
    hand its already-sealed relation to the private draft phase.  It retains a
    result envelope solely as an atomic failure carrier; the public result is
    minted by the legacy finalizer after the owner/site fold.
    """
    active_claim = None
    active_fact = None
    active_descriptor = None
    active_anchored_refs: tuple[model.AnchoredBlockRef, ...] = ()
    active_stage = model.RouteRealizationFailureStage.PLAN_STEP_CORRELATION
    selected_step_indices: set[int] = set()
    try:
        active_stage = model.RouteRealizationFailureStage.SOURCE_AUTHORITY
        _validate(source_authority, "source_authority_id")
        if type(plan) is not PatchPlan:
            raise TypeError("projected realization requires a PatchPlan")
        active_stage = model.RouteRealizationFailureStage.ATTEMPT_BINDING
        if plan.unflatten_proposal is not source_authority.proposal:
            raise ValueError(
                "projected realization plan is not bound to source authority proposal"
            )
        if type(source_inventory) is not model.SemanticGraphInventory or type(projected_inventory) is not model.SemanticGraphInventory:
            raise TypeError("projected realization requires closed inventories")
        model.validate_semantic_graph_inventory(source_inventory)
        model.validate_semantic_graph_inventory(projected_inventory)
        if source_inventory.phase is not model.UnflattenAuthorityPhase.PRODUCER_FORECAST:
            raise ValueError("projected realization source inventory has wrong phase")
        if (
            source_inventory.generation != source_authority.source_generation
            or source_inventory.graph_fingerprint != source_authority.source_fingerprint
            or source_inventory.inventory_digest != source_authority.source_inventory_digest
        ):
            raise ValueError("projected realization source inventory differs from authority")
        if projected_inventory.phase is not model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT:
            raise ValueError("projected realization inventory has wrong phase")
        if type(attempt_id) is not TransactionAttemptId:
            raise TypeError("projected realization requires TransactionAttemptId")
        if attempt_id.plan_id != plan.plan_id or plan.plan_id != source_authority.plan_id:
            raise ValueError("projected realization plan is foreign")
        if attempt_id.generation != projected_inventory.generation:
            raise ValueError("projected realization generation differs from attempt")
        if type(patch_step_facts) is not tuple:
            raise TypeError("patch_step_facts must be an exact tuple")
        if type(entry_liveness_receipts) is not tuple:
            raise TypeError("entry liveness receipts must be an exact tuple")
        receipt_ids = tuple(receipt.binding_id for receipt in entry_liveness_receipts)
        if receipt_ids != tuple(sorted(receipt_ids)) or len(set(receipt_ids)) != len(receipt_ids):
            raise ValueError("entry liveness receipts are not canonical")
        for receipt in entry_liveness_receipts:
            validate_bound_entry_endpoint_liveness_allowance(receipt)
        facts = patch_step_facts
        active_stage = model.RouteRealizationFailureStage.ATTEMPT_BINDING
        source_by_ref = source_inventory.serial_by_ref
        projected_by_ref = projected_inventory.serial_by_ref
        claims = _route_claims(source_authority.proposal)
        try:
            lineage_index = _index_lineage_fact_groups(plan, facts)
        except _LineageFactViolation as violation:
            active_stage = violation.stage
            active_fact = violation.fact
            raise
        descriptors = {
            entry.descriptor.step_index: entry.descriptor
            for entry in lineage_index.entries
        }
        for claim in claims:
            exact_selected_arm_parts = None
            exact_selected_arm_correlation = None
            active_claim = claim
            active_fact = None
            active_stage = model.RouteRealizationFailureStage.CLAIM_COVERAGE
            locator = claim.retired_route_subject.locator
            source_ref = locator.source_ref
            if source_ref not in source_by_ref or source_ref not in projected_by_ref:
                raise ValueError("projected route source is foreign or missing")
            active_stage = model.RouteRealizationFailureStage.PLAN_STEP_CORRELATION
            claim_proof = next(
                (
                    proof for proof in source_authority.proposal.route_evidence.route_proofs
                    if proof.proof_id == claim.route_proof_ids[0]
                ),
                None,
            )
            try:
                entry = _select_lineage_fact_group(
                    lineage_index, plan=plan, claim=claim, proof=claim_proof,
                    source_inventory=source_inventory,
                    entry_liveness_receipts=entry_liveness_receipts,
                )
            except _LineageFactViolation as violation:
                active_stage = violation.stage
                active_descriptor = violation.descriptor
                active_fact = violation.fact
                raise
            descriptor = entry.descriptor
            entry_liveness_receipt = _selected_entry_liveness_receipt(
                entry=entry,
                proof=claim_proof,
                receipts=entry_liveness_receipts,
            )
            active_descriptor = descriptor
            selected_step_indices.add(descriptor.step_index)
            active_fact = entry.facts[0] if entry.facts else entry.violation.fact if entry.violation else None
            # Establish the complete selected route coordinate set before the
            # group validator can report a member/creation failure.
            selected_anchors: list[model.AnchoredBlockRef] = []
            claim_locator = claim.retired_route_subject.locator
            for anchor_ref, anchor_ea in (
                (claim_locator.source_ref, claim_locator.source_anchor_ea),
                *((item.block_ref, item.anchor_ea)
                  for item in claim_locator.native_destination_members()
                  if type(item) is model.BlockSubjectLocator),
            ):
                try:
                    selected_anchors.append(model.AnchoredBlockRef(anchor_ref, anchor_ea))
                except (TypeError, ValueError):
                    continue
            if claim_proof.source_owner_identity is not None:
                for owner_ref in source_by_ref:
                    if _ref_matches_identity(owner_ref, claim_proof.source_owner_identity):
                        try:
                            owner_row = _inventory_block(source_inventory, owner_ref)
                            if owner_row.anchor_ea is not None:
                                selected_anchors.append(
                                    model.AnchoredBlockRef(owner_ref, owner_row.anchor_ea)
                                )
                        except (TypeError, ValueError):
                            pass
                        break
            for owner_ref in descriptor.owner_refs:
                try:
                    owner_row = _inventory_block(projected_inventory, owner_ref)
                    if owner_row.anchor_ea is not None:
                        selected_anchors.append(model.AnchoredBlockRef(owner_ref, owner_row.anchor_ea))
                except (TypeError, ValueError):
                    continue
            active_anchored_refs = tuple(selected_anchors)
            # Establish every physical family role before validating the fact
            # group, so owner/cardinality/spec failures retain complete
            # coordinates as well as the selected claim.
            if descriptor.step_kind in {
                PatchStepKind.REDIRECT_BRANCH,
                PatchStepKind.SPLIT,
                PatchStepKind.HELPER_CORRIDOR,
            }:
                role_refs = [*descriptor.route_refs, *descriptor.owner_refs]
                step_for_roles = plan.steps[descriptor.step_index]
                role_refs.extend(getattr(step_for_roles, "corridor_serials", ()))
                role_refs.extend(getattr(step_for_roles, "clone_block_ids", ()))
                for role_ref in role_refs:
                    for role_map, role_inventory in (
                        (source_by_ref, source_inventory),
                        (projected_by_ref, projected_inventory),
                    ):
                        if role_ref not in role_map:
                            continue
                        try:
                            role_row = _inventory_block(role_inventory, role_ref)
                            if role_row.anchor_ea is not None:
                                selected_anchors.append(
                                    model.AnchoredBlockRef(role_ref, role_row.anchor_ea)
                                )
                        except (TypeError, ValueError):
                            pass
                        break
            active_anchored_refs = tuple(selected_anchors)
            try:
                lineage_facts = _require_valid_lineage_fact_group(entry)
            except _LineageFactViolation as violation:
                active_stage = violation.stage
                active_descriptor = violation.descriptor
                active_fact = violation.fact
                raise
            fact = lineage_facts[0]
            active_fact = fact
            # Physical predecessor-split steps are structurally selectable and
            # lineage-validated, but produce no projected semantic relation.
            # Keep this rejection immediately after the shared lineage seam.
            selected_step = plan.steps[descriptor.step_index]
            if (
                descriptor.step_kind is PatchStepKind.SPLIT
                and type(selected_step) is PatchEdgeSplitTrampoline
            ):
                active_stage = model.RouteRealizationFailureStage.UNSUPPORTED_REALIZATION_KIND
                raise ValueError("physical split has no projected semantic relation")
            active_stage = model.RouteRealizationFailureStage.PLAN_STEP_CORRELATION
            if descriptor.step_kind is PatchStepKind.CONDITIONAL_REDIRECT:
                # Resolve all deterministic route/owner anchors before group
                # validation so missing/duplicate/foreign owner facts retain
                # the full STEP coordinate set.
                known_refs = (
                    (descriptor.route_refs[0], source_by_ref),
                    (descriptor.route_refs[1], source_by_ref),
                    (descriptor.route_refs[2], source_by_ref),
                    (descriptor.route_refs[3], source_by_ref),
                    *( (owner, projected_by_ref) for owner in descriptor.owner_refs ),
                )
                known_anchors: list[model.AnchoredBlockRef] = []
                # The selected claim remains the canonical coordinate source
                # even when a descriptor field is the drift under test.  Keep
                # its proof-owned feeder/destinations alongside descriptor
                # anchors so correlation failures retain F/R/T/L.
                claim_locator = claim.retired_route_subject.locator
                for claim_ref, claim_anchor in (
                    (claim_locator.source_ref, claim_locator.source_anchor_ea),
                    *((item.block_ref, item.anchor_ea)
                      for item in claim_locator.native_destination_members()
                      if type(item) is model.BlockSubjectLocator),
                ):
                    try:
                        known_anchors.append(model.AnchoredBlockRef(claim_ref, claim_anchor))
                    except (TypeError, ValueError):
                        continue
                if claim_proof is not None and claim_proof.source_owner_identity is not None:
                    for owner_ref in source_by_ref:
                        if _ref_matches_identity(owner_ref, claim_proof.source_owner_identity):
                            owner_row = _inventory_block(source_inventory, owner_ref)
                            if owner_row.anchor_ea is not None:
                                known_anchors.append(
                                    model.AnchoredBlockRef(owner_ref, owner_row.anchor_ea)
                                )
                            break
                for known_ref, serials in known_refs:
                    try:
                        resolved_ref, _serial = _ref_and_serial(known_ref, serials)
                        inventory = projected_inventory if serials is projected_by_ref else source_inventory
                        known_row = _inventory_block(inventory, resolved_ref)
                        if known_row.anchor_ea is not None:
                            known_anchors.append(model.AnchoredBlockRef(resolved_ref, known_row.anchor_ea))
                    except (TypeError, ValueError):
                        continue
                active_anchored_refs = tuple(known_anchors)
            if descriptor.step_kind is PatchStepKind.CONDITIONAL_REDIRECT:
                if type(plan.steps[fact.step_index]) is not PatchConditionalRedirect:
                    raise ValueError("conditional redirect descriptor step type drift")
            if descriptor.step_kind in {
                PatchStepKind.REDIRECT_GOTO,
                PatchStepKind.REDIRECT_BRANCH,
                PatchStepKind.BYPASS_TRAMPOLINE,
            }:
                if len(descriptor.route_refs) != 3:
                    raise ValueError("projected redirect descriptor lacks exact edge coordinates")
                _step_source, old_serial, new_serial = descriptor.route_refs
                expected_projected_targets = (new_serial,)
            elif descriptor.step_kind is PatchStepKind.CONVERT_TO_GOTO:
                guarded_fold = _guarded_conditional_fold_coordinates_match(
                    plan, claim_proof, descriptor,
                )
                default_gap_fold = _default_gap_conditional_fold_coordinates_match(
                    plan, claim_proof, descriptor,
                )
                if len(descriptor.route_refs) != 2 or not (guarded_fold or default_gap_fold):
                    raise ValueError(
                        "conditional fold descriptor differs from guarded proof"
                    )
                _step_source, new_serial = descriptor.route_refs
                if guarded_fold:
                    guarded = claim_proof.state_write.guarded_selection
                    other_endpoint = (
                        guarded.false_target
                        if guarded.selected_target == guarded.true_target
                        else guarded.true_target
                    )
                else:
                    parts = _default_gap_conditional_fold_parts(plan, claim_proof, descriptor)
                    assert parts is not None
                    _selected, other_endpoint = parts
                old_serial = next(
                    ref for ref in source_by_ref
                    if _ref_matches_identity(
                        ref,
                        other_endpoint.identity
                        if guarded_fold else other_endpoint.target_identity,
                    )
                )
                expected_projected_targets = (new_serial,)
            elif descriptor.step_kind is PatchStepKind.LOWER_CONDITIONAL:
                if len(descriptor.route_refs) != 4:
                    raise ValueError("lower-conditional descriptor lacks exact arm coordinates")
                _step_source, old_serial, false_serial, true_serial = descriptor.route_refs
                new_serial = true_serial
                expected_projected_targets = (false_serial, true_serial)
            elif descriptor.step_kind is PatchStepKind.CONDITIONAL_REDIRECT:
                if len(descriptor.route_refs) not in {4, 5}:
                    raise ValueError("conditional descriptor lacks exact arm coordinates")
                _step_source, _ref_serial, conditional_serial, fallthrough_serial, *explicit_old = descriptor.route_refs
                old_serial = _ref_serial if not explicit_old else explicit_old[0]
                new_serial = conditional_serial
                expected_projected_targets = (descriptor.owner_refs[0],)
            elif descriptor.step_kind is PatchStepKind.SPLIT:
                if len(descriptor.route_refs) < 5:
                    raise ValueError("split descriptor lacks exact edge coordinates")
                _step_source, _via_serial, old_serial, _apply_old, new_serial = descriptor.route_refs[:5]
                expected_projected_targets = (new_serial,)
            elif descriptor.step_kind is PatchStepKind.HELPER_CORRIDOR:
                if len(descriptor.route_refs) < 4:
                    raise ValueError("helper corridor lacks exact edge coordinates")
                _step_source, _via_serial, old_serial, new_serial = descriptor.route_refs[:4]
                expected_projected_targets = (new_serial,)
            else:
                active_stage = model.RouteRealizationFailureStage.UNSUPPORTED_REALIZATION_KIND
                raise ValueError("unsupported realization kind")
            old_ref, old_serial_number = _ref_and_serial(old_serial, source_by_ref)
            new_ref, new_serial_number = _ref_and_serial(new_serial, projected_by_ref)
            conditional_replacement_ref = None
            conditional_helper_ref = None
            conditional_replacement_serial = None
            conditional_helper_serial = None
            retained_prefix_match = False
            retained_prefix_source_ref = None
            state_carrier_helper_corridor_match = False
            shared_state_carrier_source_bypass_match = False
            route_source_ref = source_ref
            route_source_serial_number = source_by_ref.get(source_ref)
            if entry_liveness_receipt is not None:
                route_source_ref, route_source_serial_number = _ref_and_serial(
                    entry_liveness_receipt.allowance.entry_predecessor_owner_refs[0],
                    source_by_ref,
                )
            if descriptor.step_kind is PatchStepKind.LOWER_CONDITIONAL:
                # The lower-conditional relation has two distinct named
                # source coordinates: the feeder owns the rewritten tail,
                # while the proof source owns the state/predicate evidence.
                # Select the feeder before resolving source rows and checking
                # old-edge reciprocity so those checks are scoped correctly.
                route_source_ref, route_source_serial_number = _ref_and_serial(
                    descriptor.route_refs[0], source_by_ref,
                )
            if descriptor.step_kind is PatchStepKind.CONDITIONAL_REDIRECT:
                route_source_ref, route_source_serial_number = _ref_and_serial(
                    descriptor.route_refs[0], source_by_ref,
                )
            if descriptor.step_kind is PatchStepKind.CONVERT_TO_GOTO:
                route_source_ref, route_source_serial_number = _ref_and_serial(
                    descriptor.route_refs[0], source_by_ref,
                )
            if (
                descriptor.step_kind is PatchStepKind.HELPER_CORRIDOR
                and _state_carrier_helper_corridor_coordinates_match(
                    plan, claim_proof, descriptor,
                )
            ):
                # The source proof owns the predecessor, while the cloned
                # physical edge is the feeder -> comparison entry.  Use the
                # latter only for physical edge replay; the exact carrier
                # matcher below retains the semantic source coordinate.
                state_carrier_helper_corridor_match = True
                route_source_ref, route_source_serial_number = _ref_and_serial(
                    descriptor.route_refs[0], source_by_ref,
                )
            if (
                descriptor.step_kind is PatchStepKind.REDIRECT_BRANCH
                and _owner_bound_direct_coordinates_match(
                    plan, claim_proof, descriptor,
                )
            ):
                route_source_ref, route_source_serial_number = _ref_and_serial(
                    descriptor.route_refs[0], source_by_ref,
                )
            if descriptor.step_kind in {
                PatchStepKind.REDIRECT_GOTO,
                PatchStepKind.BYPASS_TRAMPOLINE,
                PatchStepKind.LOWER_CONDITIONAL,
                PatchStepKind.CONDITIONAL_REDIRECT,
            }:
                plan_inputs = plan.unflatten_proposal.plan_inputs
                dispatcher_refs = {
                    plan_inputs.dispatcher_entry_ref,
                    *plan_inputs.dispatcher_member_refs,
                }
                if old_ref not in dispatcher_refs:
                    if (
                        descriptor.step_kind is PatchStepKind.REDIRECT_GOTO
                        and (
                            _state_transform_direct_old_target_is_proof_owned(
                                claim_proof, old_ref,
                            )
                            or _owner_bound_direct_coordinates_match(
                                plan, claim_proof, descriptor,
                            )
                            or _state_carrier_feeder_direct_coordinates_match(
                                plan, claim_proof, descriptor,
                            )
                            or _shared_state_carrier_source_bypass_coordinates_match(
                                plan, claim_proof, descriptor,
                                source_inventory,
                            )
                        )
                    ):
                        pass
                    elif descriptor.step_kind is PatchStepKind.REDIRECT_GOTO:
                        # A physical selected-arm redirect bypasses the proof's
                        # conditional predicate, which need not itself be
                        # dispatcher infrastructure.  Admit that topology only
                        # through the complete exact-arm correlation; ordinary
                        # GOTOs retain the dispatcher-membership requirement.
                        try:
                            exact_selected_arm_parts = (
                                _exact_selected_arm_claim_bundle(
                                    plan=plan,
                                    route_claim=claim,
                                    proof=claim_proof,
                                    descriptor=descriptor,
                                )
                            )
                        except (TypeError, ValueError):
                            raise ValueError(
                                "goto or bypass old target is outside dispatcher authority"
                            ) from None
                    else:
                        raise ValueError(
                            "goto or bypass old target is outside dispatcher authority"
                        )
            proof = next(
                proof for proof in source_authority.proposal.route_evidence.route_proofs
                if proof.proof_id == claim.route_proof_ids[0]
            )
            destinations_by_role = {
                item.role: item for item in proof.destinations
            }
            if descriptor.step_kind is PatchStepKind.CONVERT_TO_GOTO:
                guarded_fold = _guarded_conditional_fold_coordinates_match(
                    plan, proof, descriptor,
                )
                default_gap_parts = _default_gap_conditional_fold_parts(
                    plan, proof, descriptor,
                )
                if not guarded_fold and default_gap_parts is None:
                    raise ValueError(
                        "conditional fold does not match exact guarded route"
                    )
                selected_destination = (
                    proof.destinations[0]
                    if guarded_fold else default_gap_parts[0]
                )
                selected_subject = (
                    _native_route_destination_subject_for_proof_destination(
                        claim=claim,
                        proof_destination=selected_destination,
                        catalog=(
                            plan.unflatten_proposal.source_identity_catalog
                        ),
                    )
                )
                if selected_subject.block_ref != new_ref:
                    raise ValueError(
                        "conditional fold selected target differs from claim"
                    )
            if descriptor.step_kind is PatchStepKind.REDIRECT_GOTO:
                if proof.proof_kind is route_model.SemanticRouteProofKind.TERMINAL_DELIVERY:
                    delivery = proof.terminal_delivery
                    if (
                        delivery is None
                        or not _ref_matches_identity(
                            descriptor.route_refs[1], delivery.outer_state_dag.entry_identity,
                        )
                        or not _ref_matches_identity(
                            descriptor.route_refs[2], delivery.exit_entry.identity,
                        )
                        or not _ref_matches_identity(
                            descriptor.route_refs[0],
                            (
                                proof.source_owner_identity
                                if proof.source_owner_identity is not None
                                else proof.source_identity
                            ),
                        )
                    ):
                        raise ValueError(
                            "terminal delivery redirect differs from its exact outer route"
                        )
                owner_bound_direct_match = (
                    _owner_bound_direct_coordinates_match(
                        plan, proof, descriptor,
                    )
                )
                state_carrier_feeder_direct_match = (
                    _state_carrier_feeder_direct_coordinates_match(
                        plan, proof, descriptor,
                    )
                )
                shared_state_carrier_source_bypass_match = (
                    _shared_state_carrier_source_bypass_coordinates_match(
                        plan, proof, descriptor, source_inventory,
                    )
                )
                if (
                    proof.proof_kind
                    is route_model.SemanticRouteProofKind.STATE_CARRIER
                    and not state_carrier_feeder_direct_match
                    and not shared_state_carrier_source_bypass_match
                ):
                    active_stage = (
                        model.RouteRealizationFailureStage
                        .UNSUPPORTED_REALIZATION_KIND
                    )
                    raise ValueError(
                        "state-carrier direct route requires its exact feeder"
                    )
                retained_prefix_match = (
                    _retained_prefix_direct_coordinates_match(
                        plan, proof, descriptor, source_inventory,
                    )
                )
                direct_proof_match = (
                    proof.shape.value == "direct"
                    and len(proof.destinations) == 1
                    and proof.destinations[0].role is SemanticEdgeRole.DIRECT
                    and _ref_matches_identity(
                        descriptor.route_refs[0], proof.source_identity,
                    )
                    and _ref_matches_identity(
                        new_serial, proof.destinations[0].target_identity,
                    )
                )
                if owner_bound_direct_match:
                    direct_proof_match = True
                    route_source_ref, route_source_serial_number = _ref_and_serial(
                        descriptor.route_refs[0], source_by_ref,
                    )
                if entry_liveness_receipt is not None:
                    direct_proof_match = True
                    route_source_ref, route_source_serial_number = _ref_and_serial(
                        entry_liveness_receipt.allowance.entry_predecessor_owner_refs[0],
                        source_by_ref,
                    )
                if state_carrier_feeder_direct_match:
                    direct_proof_match = True
                    route_source_ref, route_source_serial_number = _ref_and_serial(
                        descriptor.route_refs[0], source_by_ref,
                    )
                if shared_state_carrier_source_bypass_match:
                    direct_proof_match = True
                    route_source_ref, route_source_serial_number = _ref_and_serial(
                        descriptor.route_refs[0], source_by_ref,
                    )
                if retained_prefix_match:
                    direct_proof_match = True
                    retained_prefix_source_ref = next(
                        row.block_ref for row in source_inventory.blocks
                        if _ref_matches_identity(
                            row.block_ref, proof.source_identity,
                        )
                    )
                    route_source_ref, route_source_serial_number = _ref_and_serial(
                        descriptor.route_refs[0], source_by_ref,
                    )
                if direct_proof_match:
                    exact_selected_arm_match = False
                else:
                    if exact_selected_arm_parts is None:
                        exact_selected_arm_parts = _exact_selected_arm_claim_bundle(
                            plan=plan, route_claim=claim, proof=proof,
                            descriptor=descriptor,
                        )
                    exact_selected_arm_match = True
                    route_source_ref, route_source_serial_number = _ref_and_serial(
                        descriptor.route_refs[0], source_by_ref,
                    )
                if not direct_proof_match and not exact_selected_arm_match:
                    raise ValueError("goto step does not match one direct semantic route")
                selected_destination = (
                    proof.destinations[0]
                    if direct_proof_match
                    else exact_selected_arm_parts[0]
                )
                selected_subject = _native_route_destination_subject_for_proof_destination(
                    claim=claim,
                    proof_destination=selected_destination,
                    catalog=plan.unflatten_proposal.source_identity_catalog,
                )
                if selected_subject.block_ref != new_ref:
                    raise ValueError("goto destination differs from route claim")
            if descriptor.step_kind is PatchStepKind.BYPASS_TRAMPOLINE:
                if (
                    proof.shape.value != "direct"
                    or len(proof.destinations) != 1
                    or proof.destinations[0].role is not SemanticEdgeRole.DIRECT
                    or not _ref_matches_identity(descriptor.route_refs[0], proof.source_identity)
                    or not _ref_matches_identity(new_serial, proof.destinations[0].target_identity)
                ):
                    raise ValueError("bypass step does not match one direct semantic route")
                selected_subject = _native_route_destination_subject_for_proof_destination(
                    claim=claim,
                    proof_destination=proof.destinations[0],
                    catalog=plan.unflatten_proposal.source_identity_catalog,
                )
                if selected_subject.block_ref != new_ref:
                    raise ValueError("bypass destination differs from route claim")
            if descriptor.step_kind is PatchStepKind.LOWER_CONDITIONAL:
                if type(plan.steps[fact.step_index]) is not PatchLowerConditionalStateTransition:
                    raise ValueError("lower-conditional descriptor step type drift")
                feeder_ref, feeder_serial = _ref_and_serial(
                    descriptor.route_refs[0], source_by_ref,
                )
                route_source_ref = feeder_ref
                route_source_serial_number = feeder_serial
                if not _ref_matches_identity(feeder_ref, proof.source_owner_identity):
                    raise ValueError("lower-conditional feeder differs from proof owner")
                if not _ref_matches_identity(descriptor.route_refs[1], proof.source_identity):
                    raise ValueError("lower-conditional proof source differs from claim proof")
                if old_ref != source_ref or old_ref != descriptor.route_refs[1]:
                    raise ValueError("lower-conditional old target differs from proof source")
                false_destination = destinations_by_role.get(SemanticEdgeRole.CONDITIONAL_FALLTHROUGH)
                true_destination = destinations_by_role.get(SemanticEdgeRole.CONDITIONAL_TAKEN)
                if (
                    false_destination is None
                    or true_destination is None
                    or not _ref_matches_identity(false_serial, false_destination.target_identity)
                    or not _ref_matches_identity(true_serial, true_destination.target_identity)
                ):
                    raise ValueError("conditional plan arms differ from semantic proof roles")
            if descriptor.step_kind is PatchStepKind.CONDITIONAL_REDIRECT:
                active_stage = model.RouteRealizationFailureStage.PLAN_STEP_CORRELATION
                step = plan.steps[fact.step_index]
                if type(step) is not PatchConditionalRedirect:
                    raise ValueError("conditional redirect step is not nominal")
                if step.instructions:
                    active_stage = model.RouteRealizationFailureStage.UNSUPPORTED_REALIZATION_KIND
                    raise ValueError("conditional redirect prelude is unsupported")
                if len(descriptor.owner_refs) != 2 or any(type(ref) is not PlanBlockRef for ref in descriptor.owner_refs):
                    raise ValueError("conditional redirect requires clone and helper owners")
                conditional_replacement_ref, conditional_replacement_serial = _ref_and_serial(
                    descriptor.owner_refs[0], projected_by_ref,
                )
                conditional_helper_ref, conditional_helper_serial = _ref_and_serial(
                    descriptor.owner_refs[1], projected_by_ref,
                )
                creation_specs = tuple(
                    (index, spec) for index, spec in enumerate(plan.new_blocks)
                    if spec.block_id in descriptor.owner_refs
                )
                if tuple(spec.block_id for _index, spec in creation_specs) != descriptor.owner_refs:
                    raise ValueError("conditional creation specs are not in plan order")
                expected_spec_digests = tuple(
                    (spec.block_id, authority_id(_patch_block_spec_preimage(index, spec)))
                    for index, spec in creation_specs
                )
                if descriptor.new_block_spec_digests != expected_spec_digests:
                    raise ValueError("conditional creation spec digest drift")
                clone_spec, helper_spec = (spec for _index, spec in creation_specs)
                from d810.transforms.plan import PatchEdgeRef
                if (
                    clone_spec.kind != "conditional_redirect_clone"
                    or clone_spec.template_block != step.ref_block
                    or clone_spec.incoming_edge != PatchEdgeRef(step.source_serial, step.ref_block)
                    or clone_spec.outgoing_edges != (
                        PatchEdgeRef(step.block_id, step.conditional_target),
                        PatchEdgeRef(step.block_id, step.fallthrough_block_id),
                    )
                    or clone_spec.instructions
                    or clone_spec.captured_body is not None
                    or helper_spec.kind != "conditional_redirect_fallthrough"
                    or helper_spec.template_block != step.ref_block
                    or helper_spec.incoming_edge != PatchEdgeRef(step.block_id, step.fallthrough_block_id)
                    or helper_spec.outgoing_edges != (PatchEdgeRef(step.fallthrough_block_id, step.fallthrough_target),)
                    or helper_spec.instructions
                    or helper_spec.captured_body is not None
                ):
                    raise ValueError("conditional creation spec differs from closed shape")
                if (
                    proof.proof_kind is not route_model.SemanticRouteProofKind.STATE_CHOICE
                    or proof.shape is not route_model.SemanticRouteShape.CONDITIONAL
                    or proof.source_owner_identity is None
                    or not _ref_matches_identity(route_source_ref, proof.source_owner_identity)
                    or not _ref_matches_identity(step.ref_block, proof.source_identity)
                    or old_ref != step.ref_block
                ):
                    raise ValueError("conditional redirect proof coordinates differ")
                if step.old_target_serial is not None and step.old_target_serial != step.ref_block:
                    raise ValueError("conditional redirect explicit old target differs from proof source")
                false_destination = destinations_by_role.get(SemanticEdgeRole.CONDITIONAL_FALLTHROUGH)
                true_destination = destinations_by_role.get(SemanticEdgeRole.CONDITIONAL_TAKEN)
                if (
                    false_destination is None or true_destination is None
                    or not _ref_matches_identity(step.fallthrough_target, false_destination.target_identity)
                    or not _ref_matches_identity(step.conditional_target, true_destination.target_identity)
                ):
                    raise ValueError("conditional redirect semantic arms differ from proof")
                claim_false_subject = _native_route_destination_subject_for_proof_destination(
                    claim=claim,
                    proof_destination=false_destination,
                    catalog=plan.unflatten_proposal.source_identity_catalog,
                )
                claim_true_subject = _native_route_destination_subject_for_proof_destination(
                    claim=claim,
                    proof_destination=true_destination,
                    catalog=plan.unflatten_proposal.source_identity_catalog,
                )
                if {
                    claim_false_subject.block_ref,
                    claim_true_subject.block_ref,
                } != {step.fallthrough_target, step.conditional_target}:
                    raise ValueError("conditional redirect semantic arms differ from proof")
            source_row = _inventory_block(source_inventory, route_source_ref)
            old_row = _inventory_block(source_inventory, old_ref)
            projected_source_row = _inventory_block(projected_inventory, route_source_ref)
            projected_edge_source_row = projected_source_row
            projected_new_row = _inventory_block(
                projected_inventory,
                conditional_replacement_ref if descriptor.step_kind is PatchStepKind.CONDITIONAL_REDIRECT else new_ref,
            )
            if retained_prefix_match:
                retained_source_row = _inventory_block(
                    source_inventory, retained_prefix_source_ref,
                )
                retained_projected_row = _inventory_block(
                    projected_inventory, retained_prefix_source_ref,
                )
                if (
                    retained_source_row.successor_serials
                    != (source_row.serial,)
                    or retained_projected_row.successor_serials
                    != (projected_source_row.serial,)
                    or retained_source_row.serial
                    not in source_row.predecessor_serials
                    or retained_projected_row.serial
                    not in projected_source_row.predecessor_serials
                ):
                    raise ValueError(
                        "retained-prefix proof-source edge differs"
                    )
            if descriptor.step_kind is PatchStepKind.CONDITIONAL_REDIRECT:
                conditional_rows = (
                    source_row,
                    old_row,
                    _inventory_block(projected_inventory, new_ref),
                    _inventory_block(projected_inventory, descriptor.route_refs[3]),
                    projected_new_row,
                    _inventory_block(projected_inventory, conditional_helper_ref),
                )
                if all(row.anchor_ea is not None for row in conditional_rows):
                    active_anchored_refs = tuple(
                        model.AnchoredBlockRef(row.block_ref, row.anchor_ea)
                        for row in conditional_rows
                    )
            active_stage = model.RouteRealizationFailureStage.PLAN_STEP_CORRELATION
            if descriptor.step_kind is PatchStepKind.HELPER_CORRIDOR:
                corridor_step = plan.steps[fact.step_index]
                if type(corridor_step) is PatchEdgeSplitCorridor:
                    corridor_refs = tuple(
                        _ref_and_serial(ref, source_by_ref)[0]
                        for ref in corridor_step.corridor_serials
                    )
                    terminal_ref = _ref_and_serial(
                        _inventory_block(
                            source_inventory, corridor_refs[-1],
                        ).successor_serials[0], source_by_ref,
                    )[0]
                    selected_corridor_target = (
                        _native_route_destination_subject_for_proof_destination(
                            claim=claim,
                            proof_destination=proof.destinations[0],
                            catalog=plan.unflatten_proposal.source_identity_catalog,
                        ).block_ref
                        if len(proof.destinations) == 1
                        else None
                    )
                    literal_refs = (
                        corridor_step.via_pred,
                        *corridor_refs,
                        terminal_ref,
                        *corridor_step.clone_block_ids,
                        *((selected_corridor_target,) if selected_corridor_target is not None else ()),
                    )
                    for literal_ref in literal_refs:
                        inventory = (
                            projected_inventory
                            if literal_ref in projected_by_ref
                            else source_inventory
                        )
                        try:
                            row = _inventory_block(inventory, literal_ref)
                            if row.anchor_ea is not None:
                                active_anchored_refs = (*active_anchored_refs,
                                    model.AnchoredBlockRef(literal_ref, row.anchor_ea))
                        except (TypeError, ValueError):
                            continue
                    expected_descriptor_old = (
                        corridor_step.corridor_serials[1]
                        if len(corridor_step.corridor_serials) > 1
                        else _ref_and_serial(
                            _inventory_block(
                                source_inventory, corridor_step.corridor_serials[-1],
                            ).successor_serials[0], source_by_ref,
                        )[0]
                    )
                    if descriptor.route_refs[2] != expected_descriptor_old:
                        raise ValueError("corridor descriptor old target differs")
            active_stage = model.RouteRealizationFailureStage.OLD_EDGE_REMOVAL
            if old_serial_number not in source_row.successor_serials or source_row.serial not in old_row.predecessor_serials:
                raise ValueError("projected route old edge is absent or non-reciprocal in source")
            if (
                descriptor.step_kind
                not in {PatchStepKind.SPLIT, PatchStepKind.HELPER_CORRIDOR}
                and old_serial_number in projected_source_row.successor_serials
            ):
                raise ValueError("projected route retains the old edge")
            lower_relation: model.LoweredConditionalRouteRealization | None = None
            cloned_relation: model.ClonedConditionalRouteRealization | None = None
            folded_relation: model.FoldedConditionalRouteRealization | None = None
            branch_relation: object | None = None
            corridor_relation: object | None = None
            expected_roles: tuple[object, ...] | None = None
            if descriptor.step_kind is PatchStepKind.CONVERT_TO_GOTO:
                active_stage = model.RouteRealizationFailureStage.CONDITIONAL_ROLES
                guarded_fold = _guarded_conditional_fold_coordinates_match(
                    plan, proof, descriptor,
                )
                default_gap_parts = _default_gap_conditional_fold_parts(
                    plan, proof, descriptor,
                )
                if not guarded_fold and default_gap_parts is None:
                    raise ValueError("conditional fold does not match typed route")
                guarded = None if proof.state_write is None else proof.state_write.guarded_selection
                endpoints = (
                    (guarded.true_target, guarded.false_target)
                    if guarded_fold else default_gap_parts
                )
                endpoint_refs = tuple(
                    next(
                        ref for ref in source_by_ref
                        if _ref_matches_identity(
                            ref,
                            endpoint.identity
                            if guarded_fold else endpoint.target_identity,
                        )
                    )
                    for endpoint in endpoints
                )
                endpoint_serials = tuple(source_by_ref[ref] for ref in endpoint_refs)
                if (
                    source_row.block_kind is not BlockKind.TWO_WAY
                    or len(source_row.successor_serials) != 2
                    or set(source_row.successor_serials) != set(endpoint_serials)
                    or new_serial_number not in endpoint_serials
                    or old_serial_number not in endpoint_serials
                    or old_serial_number == new_serial_number
                ):
                    raise ValueError(
                        "conditional fold source arms differ from guarded proof"
                    )
                selected_source_row = _inventory_block(source_inventory, new_ref)
                selected_projected_row = _inventory_block(
                    projected_inventory, new_ref,
                )
                discarded_projected_row = _inventory_block(
                    projected_inventory, old_ref,
                )
                if (
                    source_row.serial not in selected_source_row.predecessor_serials
                    or projected_source_row.successor_serials
                    != (new_serial_number,)
                    or projected_source_row.serial
                    not in selected_projected_row.predecessor_serials
                    or projected_source_row.serial
                    in discarded_projected_row.predecessor_serials
                ):
                    raise ValueError(
                        "conditional fold projected topology differs"
                    )
                rows = (source_row, selected_source_row, old_row)
                if any(row.anchor_ea is None for row in rows):
                    raise ValueError(
                        "conditional fold requires exact native anchors"
                    )
                feeder = model.AnchoredBlockRef(
                    route_source_ref, source_row.anchor_ea,
                )
                selected = model.AnchoredBlockRef(
                    new_ref, selected_source_row.anchor_ea,
                )
                discarded = model.AnchoredBlockRef(
                    old_ref, old_row.anchor_ea,
                )
                expected_roles = (
                    model.FoldedConditionalRouteRealization.__name__,
                    feeder, selected, discarded,
                )
                folded_relation = _mint(
                    model.FoldedConditionalRouteRealization,
                    {
                        "feeder": feeder,
                        "selected_target": selected,
                        "discarded_target": discarded,
                        "relation_id": route_realization_id((
                            "folded_conditional", feeder,
                            selected, discarded,
                        )),
                    },
                    "relation_id",
                )
            if descriptor.step_kind is PatchStepKind.HELPER_CORRIDOR:
                active_stage = model.RouteRealizationFailureStage.UNSUPPORTED_REALIZATION_KIND
                step = plan.steps[fact.step_index]
                if type(step) is not PatchEdgeSplitCorridor or step.source_new_target is not None:
                    raise ValueError("corridor variant is unsupported")
                if proof.shape is not route_model.SemanticRouteShape.DIRECT or len(proof.destinations) != 1 or proof.destinations[0].role is not SemanticEdgeRole.DIRECT:
                    raise ValueError("corridor proof must be one direct destination")
                source_refs = tuple(_ref_and_serial(ref, source_by_ref)[0] for ref in step.corridor_serials)
                active_stage = model.RouteRealizationFailureStage.PLAN_STEP_CORRELATION
                if (
                    not source_refs
                    or (
                        not state_carrier_helper_corridor_match
                        and source_ref != source_refs[0]
                    )
                ):
                    raise ValueError("corridor proof source differs from claim source")
                active_stage = model.RouteRealizationFailureStage.UNSUPPORTED_REALIZATION_KIND
                # Corridor unsupported rows still report the complete family
                # coordinate boundary.  In particular, retain the terminal
                # continuation even when proof-kind rejection happens before
                # topology validation; this is required for deterministic A_corr
                # diagnostics and is not a second validation path.
                terminal_serials = _inventory_block(
                    source_inventory, source_refs[-1],
                ).successor_serials
                if len(terminal_serials) != 1:
                    raise ValueError("corridor source member must have one terminal continuation")
                terminal_ref, _terminal_serial = _ref_and_serial(
                    terminal_serials[0], source_by_ref,
                )
                # Corridor diagnostics are the literal A_corr coordinate:
                # P,Q0..Qk,R,C0..Ck,N.  The sealed claim destination is N;
                # step.new_target is a plan coordinate and may intentionally
                # differ (for example in an unsupported proof fixture), so it
                # must never add a second production anchor.
                claim_target_ref = (
                    _native_route_destination_subject_for_proof_destination(
                        claim=claim,
                        proof_destination=proof.destinations[0],
                        catalog=plan.unflatten_proposal.source_identity_catalog,
                    ).block_ref
                    if len(proof.destinations) == 1
                    else None
                )
                family_refs = (
                    step.via_pred,
                    *source_refs,
                    terminal_ref,
                    *step.clone_block_ids,
                    *((claim_target_ref,) if claim_target_ref is not None else ()),
                )
                family_anchors: list[model.AnchoredBlockRef] = []
                for ref in family_refs:
                    inventory = (
                        projected_inventory
                        if ref in projected_by_ref
                        else source_inventory
                    )
                    try:
                        row = _inventory_block(inventory, ref)
                        if row.anchor_ea is not None:
                            family_anchors.append(model.AnchoredBlockRef(ref, row.anchor_ea))
                    except (TypeError, ValueError):
                        continue
                active_anchored_refs = tuple(family_anchors)
                if state_carrier_helper_corridor_match:
                    admitted_proof_kinds = {
                        route_model.SemanticRouteProofKind.STATE_CARRIER,
                    }
                else:
                    admitted_proof_kinds = {
                        route_model.SemanticRouteProofKind.STATE_ASSIGNMENT,
                        route_model.SemanticRouteProofKind.STATE_PARTITION,
                    }
                if proof.proof_kind not in admitted_proof_kinds:
                    raise ValueError("corridor proof kind is unsupported")
                active_stage = model.RouteRealizationFailureStage.OLD_EDGE_REMOVAL
                for retained_ref in source_refs:
                    retained_source = _inventory_block(source_inventory, retained_ref)
                    retained_projected = _inventory_block(projected_inventory, retained_ref)
                    if retained_source.successor_serials != retained_projected.successor_serials:
                        raise ValueError("projected corridor source successor chain differs")
                _require_corridor_source_retention(
                    source_inventory, projected_inventory, source_refs,
                )
                predecessor_ref = _ref_and_serial(step.via_pred, source_by_ref)[0]
                projected_edge_source_row = _inventory_block(
                    projected_inventory, predecessor_ref,
                )
                if state_carrier_helper_corridor_match:
                    if not _state_carrier_helper_corridor_coordinates_match(
                        plan, proof, descriptor,
                    ):
                        raise ValueError("carrier corridor coordinates differ")
                elif (
                    not _ref_matches_identity(source_refs[0], proof.source_identity)
                    or proof.source_owner_identity is None
                    or predecessor_ref == source_refs[0]
                    or not _ref_matches_identity(predecessor_ref, proof.source_owner_identity)
                ):
                    raise ValueError("corridor proof source differs")
                terminal_ref, terminal_serial = _ref_and_serial(_inventory_block(source_inventory, source_refs[-1]).successor_serials[0], source_by_ref)
                descriptor_old_ref, descriptor_old_serial = _ref_and_serial(descriptor.route_refs[2], source_by_ref)
                active_stage = model.RouteRealizationFailureStage.PLAN_STEP_CORRELATION
                if descriptor_old_serial != (terminal_serial if len(source_refs) == 1 else _ref_and_serial(source_refs[1], source_by_ref)[1]):
                    raise ValueError("corridor descriptor old target differs")
                clone_refs = tuple(_ref_and_serial(ref, projected_by_ref)[0] for ref in descriptor.owner_refs)
                clone_serials = tuple(_ref_and_serial(ref, projected_by_ref)[1] for ref in descriptor.owner_refs)
                if len(clone_refs) != len(source_refs) or tuple(_inventory_block(source_inventory, ref).successor_serials[0] for ref in source_refs[:-1]) != tuple(_ref_and_serial(ref, source_by_ref)[1] for ref in source_refs[1:]):
                    raise ValueError("corridor source chain differs")
                active_stage = model.RouteRealizationFailureStage.NEW_EDGE_REALIZATION
                if projected_edge_source_row.successor_serials != (clone_serials[0],):
                    raise ValueError("corridor predecessor edge differs")
                prefixes = []
                expected_prefixes = []
                for index, (source_corridor_ref, clone_ref, clone_serial) in enumerate(zip(source_refs, clone_refs, clone_serials)):
                    source_row_corridor = _inventory_block(source_inventory, source_corridor_ref)
                    clone_row = _inventory_block(projected_inventory, clone_ref)
                    expected_predecessor_serial = (
                        _ref_and_serial(predecessor_ref, projected_by_ref)[1]
                        if index == 0 else clone_serials[index - 1]
                    )
                    if clone_row.predecessor_serials != (expected_predecessor_serial,):
                        raise ValueError("corridor clone predecessor preimage differs")
                    if clone_row.successor_serials != ((clone_serials[index + 1]) if index + 1 < len(clone_serials) else new_serial_number,):
                        raise ValueError("corridor clone successor differs")
                    active_stage = model.RouteRealizationFailureStage.EFFECT_TERMINAL_PRESERVATION
                    source_obs = source_row_corridor.instruction_observations
                    clone_obs = clone_row.instruction_observations
                    if not source_obs or not clone_obs or len(source_obs) != len(clone_obs):
                        raise ValueError("corridor prefix observations differ")
                    source_tail = source_obs[-1]
                    clone_tail = clone_obs[-1]
                    if (
                        source_tail.instruction_kind is not InsnKind.GOTO
                        or source_tail.control_transfer_kind is not ControlTransferKind.GOTO
                        or clone_tail.opcode != -1
                        or clone_tail.raw_opcode is not None
                        or clone_tail.width != 0
                        or clone_tail.instruction_kind is not InsnKind.GOTO
                        or clone_tail.control_transfer_kind is not ControlTransferKind.GOTO
                        or clone_tail.is_call
                        or clone_tail.call_kind is not None
                        or clone_tail.predicate_observation is not None
                        or clone_tail.display_text != ""
                        or clone_row.tail_opcode != -1
                        or clone_row.raw_tail_opcode is not None
                        or clone_row.tail_kind is not InsnKind.GOTO
                        or clone_row.transfer_ea != clone_tail.instruction_ea
                    ):
                        raise ValueError("corridor source/clone tails must be GOTO")
                    prefixes_origins = []
                    expected_origins = []
                    for ordinal, (source_observation, clone_observation) in enumerate(zip(source_obs[:-1], clone_obs[:-1])):
                        if source_observation != clone_observation:
                            raise ValueError("corridor semantic prefix differs")
                        observation_digest = cloned_semantic_observation_digest(source_observation)
                        origin_source = model.AnchoredBlockRef(source_corridor_ref, source_row_corridor.anchor_ea)
                        origin_clone = model.AnchoredBlockRef(clone_ref, clone_row.anchor_ea)
                        origin_preimage = ("cloned_semantic_instruction_origin", origin_source, origin_clone, ordinal, ordinal, source_observation.instruction_ea, observation_digest)
                        expected_origins.append((
                            model.ClonedSemanticInstructionOrigin.__name__,
                            origin_source, origin_clone, ordinal, ordinal,
                            source_observation.instruction_ea, observation_digest,
                        ))
                        prefixes_origins.append(_mint(model.ClonedSemanticInstructionOrigin, {
                            "source_owner": origin_source, "clone_owner": origin_clone, "source_ordinal": ordinal, "projected_ordinal": ordinal, "instruction_ea": source_observation.instruction_ea, "observation_digest": observation_digest, "origin_id": cloned_semantic_instruction_origin_id(origin_preimage),
                        }, "origin_id"))
                    creation = descriptor.new_block_spec_digests[index]
                    successor_ref = clone_refs[index + 1] if index + 1 < len(clone_refs) else new_ref
                    prefix_owner = model.AnchoredBlockRef(source_corridor_ref, source_row_corridor.anchor_ea)
                    prefix_clone = model.AnchoredBlockRef(clone_ref, clone_row.anchor_ea)
                    prefix_successor = model.AnchoredBlockRef(successor_ref, _inventory_block(projected_inventory, successor_ref).anchor_ea)
                    expected_prefixes.append((
                        model.ClonedSemanticPrefix.__name__, index, prefix_owner,
                        prefix_clone, 0, len(source_obs) - 1,
                        tuple(expected_origins), len(source_obs) - 1,
                        len(clone_obs) - 1, prefix_successor, creation,
                    ))
                    prefix_preimage = ("cloned_semantic_prefix", index, prefix_owner, prefix_clone, 0, len(source_obs) - 1, tuple(prefixes_origins), len(source_obs) - 1, len(clone_obs) - 1, prefix_successor, creation)
                    prefixes.append(_mint(model.ClonedSemanticPrefix, {
                        "ordinal": index, "source_owner": prefix_owner, "clone_owner": prefix_clone, "source_start_ordinal": 0, "source_end_ordinal_exclusive": len(source_obs) - 1, "instruction_origins": tuple(prefixes_origins), "source_trailing_goto_ordinal": len(source_obs) - 1, "projected_synthetic_goto_ordinal": len(clone_obs) - 1, "projected_successor": prefix_successor, "creation_spec_row": creation, "prefix_id": cloned_semantic_prefix_id(prefix_preimage),
                    }, "prefix_id"))
                anchored_predecessor = model.AnchoredBlockRef(
                    predecessor_ref,
                    _inventory_block(source_inventory, predecessor_ref).anchor_ea,
                )
                anchored_source_corridor = tuple(
                    model.AnchoredBlockRef(
                        ref, _inventory_block(source_inventory, ref).anchor_ea,
                    )
                    for ref in source_refs
                )
                anchored_cloned_corridor = tuple(
                    model.AnchoredBlockRef(
                        ref, _inventory_block(projected_inventory, ref).anchor_ea,
                    )
                    for ref in clone_refs
                )
                anchored_semantic_target = model.AnchoredBlockRef(
                    new_ref, projected_new_row.anchor_ea,
                )
                if state_carrier_helper_corridor_match:
                    carrier = proof.state_carrier
                    if carrier is None:
                        raise ValueError("carrier corridor lacks typed carrier evidence")
                    anchored_proof_source = model.AnchoredBlockRef(
                        predecessor_ref,
                        _inventory_block(source_inventory, predecessor_ref).anchor_ea,
                    )
                    anchored_physical_feeder = anchored_source_corridor[0]
                    anchored_comparison_entry = model.AnchoredBlockRef(
                        descriptor_old_ref,
                        _inventory_block(source_inventory, descriptor_old_ref).anchor_ea,
                    )
                    carrier_roles = (
                        anchored_proof_source, anchored_physical_feeder,
                        anchored_comparison_entry, anchored_source_corridor,
                        anchored_cloned_corridor, anchored_semantic_target,
                    )
                    expected_roles = (
                        model.ClonedCarrierRouteCorridorRealization.__name__,
                        *carrier_roles, tuple(expected_prefixes),
                        descriptor.new_block_spec_digests,
                    )
                    corridor_relation = _mint(
                        model.ClonedCarrierRouteCorridorRealization,
                        {
                            "proof_source": carrier_roles[0],
                            "physical_feeder": carrier_roles[1],
                            "comparison_entry": carrier_roles[2],
                            "source_corridor": carrier_roles[3],
                            "cloned_corridor": carrier_roles[4],
                            "semantic_target": carrier_roles[5],
                            "semantic_prefixes": tuple(prefixes),
                            "creation_spec_digests": descriptor.new_block_spec_digests,
                            "relation_id": route_realization_id((
                                "cloned_carrier_route_corridor", *carrier_roles,
                                tuple(prefixes), descriptor.new_block_spec_digests,
                            )),
                        },
                        "relation_id",
                    )
                else:
                    relation_refs = (
                        anchored_predecessor, anchored_source_corridor[0],
                        model.AnchoredBlockRef(
                            descriptor_old_ref,
                            _inventory_block(
                                source_inventory, descriptor_old_ref,
                            ).anchor_ea,
                        ),
                        model.AnchoredBlockRef(
                            terminal_ref,
                            _inventory_block(
                                source_inventory, terminal_ref,
                            ).anchor_ea,
                        ),
                        anchored_source_corridor, anchored_cloned_corridor,
                        anchored_semantic_target,
                    )
                    expected_roles = (
                        model.ClonedRouteCorridorRealization.__name__,
                        relation_refs[0], relation_refs[1], relation_refs[2],
                        relation_refs[3], relation_refs[4], relation_refs[5],
                        relation_refs[6], tuple(expected_prefixes),
                        descriptor.new_block_spec_digests,
                    )
                    corridor_relation = _mint(model.ClonedRouteCorridorRealization, {
                        "predecessor": relation_refs[0], "proof_source": relation_refs[1], "descriptor_old_target": relation_refs[2], "terminal_continuation": relation_refs[3], "source_corridor": relation_refs[4], "cloned_corridor": relation_refs[5], "semantic_target": relation_refs[6], "semantic_prefixes": tuple(prefixes), "creation_spec_digests": descriptor.new_block_spec_digests, "relation_id": route_realization_id(("cloned_route_corridor", *relation_refs[:3], relation_refs[3], relation_refs[4], relation_refs[5], relation_refs[6], tuple(prefixes), descriptor.new_block_spec_digests)),
                    }, "relation_id")
                expected_projected_targets = (descriptor.owner_refs[0],)
            if descriptor.step_kind is PatchStepKind.REDIRECT_BRANCH:
                active_stage = model.RouteRealizationFailureStage.UNSUPPORTED_REALIZATION_KIND
                step = plan.steps[fact.step_index]
                if type(step) is not PatchRedirectBranch:
                    raise ValueError("branch descriptor step is not nominal")
                if (
                    proof.shape is not route_model.SemanticRouteShape.DIRECT
                    or len(proof.destinations) != 1
                    or proof.destinations[0].role is not SemanticEdgeRole.DIRECT
                    or proof.proof_kind not in {
                        route_model.SemanticRouteProofKind.STATE_ASSIGNMENT,
                        route_model.SemanticRouteProofKind.STATE_DAG,
                        route_model.SemanticRouteProofKind.BOOTSTRAP,
                        route_model.SemanticRouteProofKind.STATE_PARTITION,
                    }
                ):
                    raise ValueError("unsupported branch proof kind or shape")
                owner_bound_partition = (
                    proof.proof_kind
                    is route_model.SemanticRouteProofKind.STATE_PARTITION
                )
                if owner_bound_partition and not _owner_bound_direct_coordinates_match(
                    plan, proof, descriptor,
                ):
                    raise ValueError(
                        "partition branch differs from its exact owner-bound route"
                    )
                if not _ref_matches_identity(source_ref, proof.source_identity):
                    raise ValueError("branch source differs from proof source")
                if not _ref_matches_identity(new_ref, proof.destinations[0].target_identity):
                    raise ValueError("branch destination differs from proof target")
                if source_row.block_kind is not BlockKind.TWO_WAY or len(source_row.successor_serials) != 2:
                    raise ValueError("branch source must be a two-way block")
                source_successors = tuple(source_row.successor_serials)
                if old_serial_number not in source_successors:
                    raise ValueError("branch removed arm is absent from source")
                untouched_serial = next(item for item in source_successors if item != old_serial_number)
                untouched_ref = _ref_and_serial(untouched_serial, source_by_ref)[0]
                _untouched_projected_ref, untouched_projected_serial = _ref_and_serial(
                    untouched_ref, projected_by_ref,
                )
                active_stage = model.RouteRealizationFailureStage.CONDITIONAL_ROLES
                _require_projected_feeder_semantics(source_row, projected_source_row)
                if (
                    not source_row.instruction_observations
                    or not projected_source_row.instruction_observations
                ):
                    raise ValueError("projected branch feeder has no tail observation")
                source_predicate = (
                    source_row.instruction_observations[-1].predicate_observation
                )
                projected_predicate = projected_source_row.instruction_observations[-1].predicate_observation
                source_explicit_target = (
                    source_predicate.explicit_target_serial
                    if source_predicate is not None
                    else source_successors[1]
                )
                if owner_bound_partition:
                    partition = proof.state_partition
                    member = (
                        None
                        if partition is None
                        else next(
                            (
                                item
                                for item in partition.members
                                if _ref_matches_identity(
                                    route_source_ref, item.owner_identity,
                                )
                            ),
                            None,
                        )
                    )
                    conditional_edge = (
                        None if member is None else member.conditional_edge
                    )
                    untouched_row = _inventory_block(
                        source_inventory, untouched_ref,
                    )
                    selected_role = (
                        SemanticEdgeRole.CONDITIONAL_TAKEN
                        if source_explicit_target == old_serial_number
                        else SemanticEdgeRole.CONDITIONAL_FALLTHROUGH
                    )
                    source_tail = source_row.instruction_observations[-1]
                    if partition is None or member is None or conditional_edge is None:
                        raise ValueError(
                            "partition branch lacks its sealed conditional edge"
                        )
                    if source_explicit_target not in {
                        old_serial_number, untouched_serial,
                    }:
                        raise ValueError(
                            "partition branch lacks its exact source arm"
                        )
                    if conditional_edge.edge_role is not selected_role:
                        raise ValueError("partition branch selected edge role differs")
                    if not _ref_matches_identity(
                        untouched_ref, conditional_edge.sibling_identity,
                    ):
                        raise ValueError("partition branch sibling identity differs")
                    if untouched_row.anchor_ea != conditional_edge.sibling_anchor_ea:
                        raise ValueError("partition branch sibling anchor differs")
                    if (
                        source_tail.instruction_ea
                        != conditional_edge.transfer_instruction_ea
                    ):
                        raise ValueError("partition branch transfer instruction differs")
                expected_predicate_target = _expected_projected_branch_target(
                    source_explicit_target=source_explicit_target,
                    old_target=old_serial_number,
                    untouched_target=untouched_serial,
                    projected_untouched_target=untouched_projected_serial,
                    new_target=new_serial_number,
                    has_fallthrough_helper=bool(descriptor.helper_refs),
                )
                if (
                    (source_predicate is None) != (projected_predicate is None)
                    or (
                        projected_predicate is not None
                        and projected_predicate.explicit_target_serial
                        != expected_predicate_target
                    )
                ):
                    raise ValueError("projected branch predicate target differs from arm slot")
                if descriptor.helper_refs:
                    active_stage = model.RouteRealizationFailureStage.NEW_EDGE_REALIZATION
                    helper_ref, helper_serial = _ref_and_serial(descriptor.helper_refs[0], projected_by_ref)
                    helper_row = _inventory_block(projected_inventory, helper_ref)
                    if projected_source_row.successor_serials != (helper_serial, untouched_projected_serial):
                        raise ValueError("branch helper does not occupy fallthrough slot")
                    if helper_row.successor_serials != (new_serial_number,) or projected_source_row.serial not in helper_row.predecessor_serials:
                        raise ValueError("branch helper topology differs")
                    active_stage = model.RouteRealizationFailureStage.EFFECT_TERMINAL_PRESERVATION
                    _require_synthetic_goto_helper(
                        helper_row, projected_inventory,
                    )
                    helper_anchor = helper_row.anchor_ea
                    if helper_anchor is None or source_row.anchor_ea is None or _inventory_block(projected_inventory, untouched_ref).anchor_ea is None or projected_new_row.anchor_ea is None:
                        raise ValueError("branch relation requires exact anchors")
                    feeder_ref = model.AnchoredBlockRef(
                        route_source_ref, source_row.anchor_ea,
                    )
                    fallthrough = model.AnchoredBlockRef(untouched_ref, _inventory_block(source_inventory, untouched_ref).anchor_ea)
                    untouched = model.AnchoredBlockRef(untouched_ref, _inventory_block(projected_inventory, untouched_ref).anchor_ea)
                    helper = model.AnchoredBlockRef(helper_ref, helper_anchor)
                    semantic = model.AnchoredBlockRef(new_ref, projected_new_row.anchor_ea)
                    expected_roles = (
                        model.BranchFallthroughHelperRouteRealization.__name__,
                        feeder_ref, fallthrough, untouched, helper, semantic,
                        descriptor.new_block_spec_digests,
                    )
                    branch_relation = _mint(model.BranchFallthroughHelperRouteRealization, {
                        "feeder": feeder_ref, "source_fallthrough": fallthrough,
                        "untouched_conditional_arm": untouched, "helper": helper,
                        "semantic_target": semantic,
                        "creation_spec_digests": descriptor.new_block_spec_digests,
                        "relation_id": route_realization_id(("branch_fallthrough_helper", feeder_ref, fallthrough, untouched, helper, semantic, descriptor.new_block_spec_digests)),
                    }, "relation_id")
                    expected_projected_targets = (helper_serial, untouched_projected_serial)
                else:
                    expected_projected_arm_order = tuple(
                        new_serial_number
                        if serial == old_serial_number
                        else untouched_projected_serial
                        for serial in source_successors
                    )
                    if (
                        projected_source_row.successor_serials
                        != expected_projected_arm_order
                    ):
                        raise ValueError("branch projected arm order differs")
                    expected_projected_targets = (untouched_serial, new_serial_number)
                    if None in (source_row.anchor_ea, _inventory_block(source_inventory, old_ref).anchor_ea, projected_new_row.anchor_ea, _inventory_block(source_inventory, untouched_ref).anchor_ea):
                        raise ValueError("branch relation requires exact anchors")
                    feeder_ref = model.AnchoredBlockRef(
                        route_source_ref, source_row.anchor_ea,
                    )
                    source_arm = model.AnchoredBlockRef(old_ref, _inventory_block(source_inventory, old_ref).anchor_ea)
                    projected_arm = model.AnchoredBlockRef(new_ref, projected_new_row.anchor_ea)
                    untouched = model.AnchoredBlockRef(untouched_ref, _inventory_block(source_inventory, untouched_ref).anchor_ea)
                    expected_roles = (
                        model.TwoArmDirectBranchRouteRealization.__name__,
                        feeder_ref, source_arm, projected_arm, untouched,
                    )
                    branch_relation = _mint(model.TwoArmDirectBranchRouteRealization, {
                        "feeder": feeder_ref, "source_rewritten_arm": source_arm,
                        "projected_replacement_arm": projected_arm, "untouched_arm": untouched,
                        "relation_id": route_realization_id(("two_arm_direct_branch", feeder_ref, source_arm, projected_arm, untouched)),
                    }, "relation_id")
            if descriptor.step_kind is PatchStepKind.LOWER_CONDITIONAL:
                active_stage = model.RouteRealizationFailureStage.PLAN_STEP_CORRELATION
                step = plan.steps[fact.step_index]
                if type(step) is not PatchLowerConditionalStateTransition:
                    raise ValueError("lower-conditional step is not nominal")
                condition = step.condition_operand
                from d810.transforms.graph_modification import SyntheticStackValueEqualsCondition
                if type(condition) is not SyntheticStackValueEqualsCondition:
                    raise ValueError("unsupported lower-conditional condition")
                if (
                    proof.proof_kind is not route_model.SemanticRouteProofKind.STATE_CHOICE
                    or proof.shape is not route_model.SemanticRouteShape.CONDITIONAL
                ):
                    raise ValueError("lower-conditional proof is not canonical STATE_CHOICE")
                if any(getattr(step, name) is not None for name in (
                    "state_register", "state_size", "false_state", "true_state",
                    "false_state_write_ea", "true_state_write_ea",
                )):
                    raise ValueError("register arm-state lowering is unsupported")
                state_write = proof.state_write
                predicate = proof.predicate
                if state_write is None or predicate is None:
                    raise ValueError("conditional proof lacks state/predicate evidence")
                if not _ref_matches_identity(route_source_ref, state_write.identity):
                    raise ValueError("conditional feeder differs from state-write owner")
                if state_write.state_variable != predicate.storage_identity:
                    raise ValueError("conditional state and predicate storage differ")
                if (
                    state_write.width != predicate.width
                    or state_write.state_constant != predicate.compare_constant
                ):
                    raise ValueError("conditional state write and predicate values differ")
                if condition.stack_stkoff != predicate.storage_identity.offset:
                    raise ValueError("conditional stack offset differs from proof")
                if (
                    condition.stack_size != state_write.width
                    or condition.stack_size != predicate.width
                    or condition.value != state_write.state_constant
                    or condition.value != predicate.compare_constant
                ):
                    raise ValueError("conditional predicate differs from proof")
                false_destination = destinations_by_role[SemanticEdgeRole.CONDITIONAL_FALLTHROUGH]
                true_destination = destinations_by_role[SemanticEdgeRole.CONDITIONAL_TAKEN]
                if (
                    true_destination.state_constant != state_write.state_constant
                    or false_destination.state_constant == true_destination.state_constant
                    or set(item.state_constant for item in proof.destinations)
                    != set(proof.carriers[0].state_values)
                ):
                    raise ValueError("conditional destination state labels differ from proof")
                if source_row.transfer_ea != step.rewrite_from_ea:
                    raise ValueError("conditional rewrite EA is not feeder transfer tail")
                if state_write.instruction_ea not in source_row.native_instruction_eas:
                    raise ValueError("conditional state write is outside feeder inventory")
                if step.rewrite_from_ea <= state_write.instruction_ea:
                    raise ValueError("conditional rewrite EA precedes state write")
                if predicate.origin.identity != proof.source_identity or predicate.consumer.identity != proof.source_identity:
                    raise ValueError("conditional predicate origin/consumer differs from proof source")
                if any(point.identity != proof.source_identity for point in predicate.corridor):
                    raise ValueError("conditional predicate corridor differs from proof source")
                active_stage = model.RouteRealizationFailureStage.CONDITIONAL_ROLES
                projected_false_ref, projected_false_serial = _ref_and_serial(false_serial, projected_by_ref)
                projected_true_ref, projected_true_serial = _ref_and_serial(true_serial, projected_by_ref)
                if projected_source_row.block_kind is not BlockKind.TWO_WAY:
                    raise ValueError("conditional projected feeder is not TWO_WAY")
                if projected_source_row.successor_serials != (projected_false_serial, projected_true_serial):
                    raise ValueError("conditional projected arm order differs")
                if projected_false_serial == projected_true_serial:
                    raise ValueError("conditional projected arms are not distinct")
                false_row = _inventory_block(projected_inventory, projected_false_ref)
                true_row = _inventory_block(projected_inventory, projected_true_ref)
                if projected_source_row.serial not in false_row.predecessor_serials or projected_source_row.serial not in true_row.predecessor_serials:
                    raise ValueError("conditional projected arm edge is not reciprocal")
                if not projected_source_row.instruction_observations:
                    raise ValueError("conditional projected feeder has no tail observation")
                observation = projected_source_row.instruction_observations[-1].predicate_observation
                if observation is None:
                    raise ValueError("conditional projected feeder lacks predicate observation")
                if observation.explicit_target_serial != projected_true_serial:
                    raise ValueError("conditional explicit target differs from taken arm")
                if observation.storage_identity != predicate.storage_identity or observation.width != predicate.width or observation.compare_constant != predicate.compare_constant:
                    raise ValueError("conditional projected predicate differs from proof")
                if observation.predicate_kind.value != "eq":
                    raise ValueError("conditional projected predicate is not EQ")
                if not _ref_matches_identity(false_serial, false_destination.target_identity) or not _ref_matches_identity(true_serial, true_destination.target_identity):
                    raise ValueError("conditional projected targets differ from proof")
                feeder_anchor, proof_anchor = source_row.anchor_ea, old_row.anchor_ea
                false_anchor, true_anchor = false_row.anchor_ea, true_row.anchor_ea
                if None in (feeder_anchor, proof_anchor, false_anchor, true_anchor):
                    raise ValueError("conditional relation requires exact anchors")
                feeder_ref = model.AnchoredBlockRef(route_source_ref, feeder_anchor)
                proof_ref = model.AnchoredBlockRef(old_ref, proof_anchor)
                arms = (
                    model.RealizedConditionalArm(SemanticEdgeRole.CONDITIONAL_FALLTHROUGH, model.AnchoredBlockRef(projected_false_ref, false_anchor)),
                    model.RealizedConditionalArm(SemanticEdgeRole.CONDITIONAL_TAKEN, model.AnchoredBlockRef(projected_true_ref, true_anchor)),
                )
                expected_roles = (
                    model.LoweredConditionalRouteRealization.__name__,
                    feeder_ref, proof_ref, proof_ref, arms,
                )
                lower_relation = _mint(
                    model.LoweredConditionalRouteRealization,
                    {"feeder": feeder_ref, "proof_source": proof_ref, "old_target": proof_ref, "arms": arms,
                     "relation_id": route_realization_id(("lowered_conditional", feeder_ref, proof_ref, proof_ref, arms))},
                    "relation_id",
                )
            if descriptor.step_kind is PatchStepKind.CONDITIONAL_REDIRECT:
                active_stage = model.RouteRealizationFailureStage.CONDITIONAL_ROLES
                state_write = proof.state_write
                predicate = proof.predicate
                if state_write is None or predicate is None:
                    raise ValueError("conditional proof lacks state/predicate evidence")
                clone_row = projected_new_row
                helper_row = _inventory_block(projected_inventory, conditional_helper_ref)
                taken_row = _inventory_block(projected_inventory, new_ref)
                fallthrough_ref, fallthrough_serial_number = _ref_and_serial(
                    descriptor.route_refs[3], projected_by_ref,
                )
                fallthrough_row = _inventory_block(projected_inventory, fallthrough_ref)
                active_stage = model.RouteRealizationFailureStage.OLD_EDGE_REMOVAL
                if source_row.block_kind is not BlockKind.ONE_WAY or source_row.successor_serials != (old_serial_number,):
                    raise ValueError("conditional source feeder is not the exact one-way old edge")
                active_stage = model.RouteRealizationFailureStage.CONDITIONAL_ROLES
                if clone_row.block_kind is not BlockKind.TWO_WAY or clone_row.successor_serials != (
                    conditional_helper_serial, new_serial_number,
                ):
                    raise ValueError("conditional clone physical arm topology differs")
                active_stage = model.RouteRealizationFailureStage.HELPER_LINEAGE
                if helper_row.block_kind is not BlockKind.ONE_WAY or helper_row.successor_serials != (fallthrough_serial_number,):
                    raise ValueError("conditional helper topology differs")
                active_stage = model.RouteRealizationFailureStage.NEW_EDGE_REALIZATION
                if clone_row.predecessor_serials != (route_source_serial_number,):
                    raise ValueError("conditional clone has an undeclared predecessor")
                active_stage = model.RouteRealizationFailureStage.HELPER_LINEAGE
                if helper_row.predecessor_serials != (conditional_replacement_serial,):
                    raise ValueError("conditional helper has an undeclared predecessor")
                active_stage = model.RouteRealizationFailureStage.NEW_EDGE_REALIZATION
                if route_source_serial_number not in clone_row.predecessor_serials:
                    raise ValueError("conditional feeder to clone edge is not reciprocal")
                if conditional_replacement_serial not in taken_row.predecessor_serials or conditional_helper_serial not in fallthrough_row.predecessor_serials:
                    raise ValueError("conditional arm edge is not reciprocal")
                active_stage = model.RouteRealizationFailureStage.HELPER_LINEAGE
                if not clone_row.instruction_observations:
                    raise ValueError("conditional clone does not carry a conditional tail")
                _require_synthetic_goto_helper(
                    helper_row, projected_inventory,
                )
                active_stage = model.RouteRealizationFailureStage.CONDITIONAL_ROLES
                clone_tail = clone_row.instruction_observations[-1]
                source_prefix_size = len(old_row.instruction_observations) - 1
                if len(clone_row.instruction_observations) < len(old_row.instruction_observations):
                    raise ValueError("conditional clone instruction body differs from proof source")
                if clone_row.instruction_observations[:source_prefix_size] != old_row.instruction_observations[:-1]:
                    raise ValueError("conditional clone instruction prefix differs from proof source")
                clone_suffix = clone_row.instruction_observations[
                    source_prefix_size:-1
                ]
                for observation in clone_suffix:
                    has_semantic_site = any(
                        row.owner_ref == clone_row.block_ref
                        and row.instruction_ordinal == observation.ordinal
                        and row.instruction_ea == observation.instruction_ea
                        for row in (
                            *projected_inventory.effects,
                            *projected_inventory.terminals,
                        )
                    )
                    if not has_semantic_site:
                        raise ValueError(
                            "conditional clone instruction body differs from proof source"
                        )
                old_tail = old_row.instruction_observations[-1]
                if (
                    old_tail.instruction_kind is not InsnKind.COND_JUMP
                    or old_tail.control_transfer_kind is not ControlTransferKind.CONDITIONAL_BRANCH
                    or old_tail.is_call
                    or old_tail.call_kind is not None
                    or clone_tail.instruction_kind is not InsnKind.COND_JUMP
                    or clone_tail.control_transfer_kind is not ControlTransferKind.CONDITIONAL_BRANCH
                    or clone_tail.is_call
                    or clone_tail.call_kind is not None
                    or clone_tail.instruction_ea != old_tail.instruction_ea
                    or clone_tail.instruction_ea != predicate.consumer.anchor_ea
                    or clone_tail.opcode != old_tail.opcode
                    or clone_tail.raw_opcode != old_tail.raw_opcode
                    or clone_tail.width != old_tail.width
                    or clone_tail.display_text != old_tail.display_text
                    or clone_row.tail_kind is not InsnKind.COND_JUMP
                    or clone_row.tail_opcode != old_row.tail_opcode
                    or clone_row.raw_tail_opcode != old_row.raw_tail_opcode
                    or clone_tail.instruction_kind is not clone_row.tail_kind
                ):
                    raise ValueError("conditional clone does not carry the exact conditional tail")
                clone_observation = clone_row.instruction_observations[-1]
                predicate_observation = clone_observation.predicate_observation
                if (
                    clone_observation.control_transfer_kind is None
                    or predicate_observation is None
                    or predicate_observation.explicit_target_serial != new_serial_number
                ):
                    raise ValueError("conditional clone lacks explicit predicate target")
                if any(item.predicate_observation is not None for item in helper_row.instruction_observations):
                    raise ValueError("conditional helper retained a predicate observation")
                if (
                    predicate_observation.predicate_kind.value != "eq"
                    or predicate_observation.storage_identity != predicate.storage_identity
                    or predicate_observation.width != predicate.width
                    or predicate_observation.compare_constant != predicate.compare_constant
                    or state_write.state_variable != predicate.storage_identity
                    or state_write.width != predicate.width
                    or state_write.state_constant != predicate.compare_constant
                    or not _ref_matches_identity(route_source_ref, state_write.identity)
                    or predicate.origin.identity != proof.source_identity
                    or predicate.consumer.identity != proof.source_identity
                    or any(point.identity != proof.source_identity for point in predicate.corridor)
                ):
                    raise ValueError("conditional clone predicate differs from canonical proof")
                feeder_anchor, proof_anchor = source_row.anchor_ea, old_row.anchor_ea
                clone_anchor, helper_anchor = clone_row.anchor_ea, helper_row.anchor_ea
                taken_anchor, fallthrough_anchor = taken_row.anchor_ea, fallthrough_row.anchor_ea
                if None in (feeder_anchor, proof_anchor, clone_anchor, helper_anchor, taken_anchor, fallthrough_anchor):
                    raise ValueError("conditional realization requires exact anchors")
                feeder_ref = model.AnchoredBlockRef(route_source_ref, feeder_anchor)
                proof_ref = model.AnchoredBlockRef(old_ref, proof_anchor)
                replacement_ref = model.AnchoredBlockRef(conditional_replacement_ref, clone_anchor)
                helper_ref = model.AnchoredBlockRef(conditional_helper_ref, helper_anchor)
                arms = (
                    model.RealizedConditionalArm(
                        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
                        model.AnchoredBlockRef(fallthrough_ref, fallthrough_anchor),
                    ),
                    model.RealizedConditionalArm(
                        SemanticEdgeRole.CONDITIONAL_TAKEN,
                        model.AnchoredBlockRef(new_ref, taken_anchor),
                    ),
                )
                expected_roles = (
                    model.ClonedConditionalRouteRealization.__name__,
                    feeder_ref, proof_ref, proof_ref, replacement_ref,
                    helper_ref, arms, descriptor.new_block_spec_digests,
                )
                cloned_relation = _mint(
                    model.ClonedConditionalRouteRealization,
                    {
                        "feeder": feeder_ref,
                        "proof_source": proof_ref,
                        "old_target": proof_ref,
                        "replacement_clone": replacement_ref,
                        "fallthrough_helper": helper_ref,
                        "arms": arms,
                        "creation_spec_digests": descriptor.new_block_spec_digests,
                        "relation_id": route_realization_id((
                            "cloned_conditional", feeder_ref, proof_ref, proof_ref,
                            replacement_ref, helper_ref, arms,
                            descriptor.new_block_spec_digests,
                        )),
                    },
                    "relation_id",
                )
            if descriptor.step_kind is PatchStepKind.BYPASS_TRAMPOLINE:
                active_stage = model.RouteRealizationFailureStage.HELPER_LINEAGE
                trampoline_row = old_row
                target_row = _inventory_block(source_inventory, new_ref)
                if tuple(trampoline_row.predecessor_serials) != (source_row.serial,):
                    raise ValueError("bypass trampoline has an undeclared predecessor")
                target_serial_number = _ref_and_serial(new_serial, source_by_ref)[1]
                if target_serial_number not in trampoline_row.successor_serials:
                    raise ValueError("bypass trampoline does not lead to semantic target")
                if trampoline_row.serial not in target_row.predecessor_serials:
                    raise ValueError("bypass trampoline successor is not reciprocal")
                projected_trampoline_row = _inventory_block(projected_inventory, old_ref)
                if projected_trampoline_row.predecessor_serials:
                    raise ValueError("bypass trampoline retains an undeclared attachment")
                if tuple(projected_trampoline_row.successor_serials) != (new_serial_number,):
                    raise ValueError("bypass trampoline successor differs from semantic target")
                if projected_trampoline_row.serial not in projected_new_row.predecessor_serials:
                    raise ValueError("bypass projected trampoline successor is not reciprocal")
            active_stage = model.RouteRealizationFailureStage.NEW_EDGE_REALIZATION
            if descriptor.step_kind not in {PatchStepKind.CONDITIONAL_REDIRECT, PatchStepKind.REDIRECT_BRANCH} and projected_new_row.serial != new_serial_number:
                raise ValueError("projected route target differs between indexes")
            expected_targets = tuple(
                _ref_and_serial(item, projected_by_ref)[1]
                for item in expected_projected_targets
            )
            if set(projected_edge_source_row.successor_serials) != set(expected_targets):
                raise ValueError("projected route successors differ from exact descriptor")
            projected_terminal_serial = projected_source_row.serial
            if descriptor.step_kind is PatchStepKind.REDIRECT_BRANCH and descriptor.helper_refs:
                projected_terminal_serial = _ref_and_serial(
                    descriptor.helper_refs[0], projected_by_ref,
                )[1]
            elif descriptor.step_kind is PatchStepKind.HELPER_CORRIDOR:
                projected_terminal_serial = _ref_and_serial(
                    descriptor.owner_refs[-1], projected_by_ref,
                )[1]
            if projected_terminal_serial not in projected_new_row.predecessor_serials:
                raise ValueError("projected route new edge is absent or non-reciprocal")
            active_stage = model.RouteRealizationFailureStage.EFFECT_TERMINAL_PRESERVATION
            source_route_refs = {
                ref for ref in descriptor.route_refs if ref in source_by_ref
            }
            _native_route_destination_subject_for_target_ref(
                claim=claim,
                proof=proof,
                target_ref=new_ref,
                catalog=plan.unflatten_proposal.source_identity_catalog,
            )
            active_stage = model.RouteRealizationFailureStage.CONDITIONAL_ROLES
            roles = tuple(
                model.ConditionalRoleCoordinate(item.role, int(item.target_anchor_ea))
                for item in proof.destinations
                if item.role in {SemanticEdgeRole.CONDITIONAL_TAKEN, SemanticEdgeRole.CONDITIONAL_FALLTHROUGH}
            )
            roles = tuple(sorted(roles, key=lambda item: (item.role.value, item.coordinate)))
            kind = (
                model.RouteRealizationKind.HELPER_CORRIDOR
                if descriptor.step_kind is PatchStepKind.HELPER_CORRIDOR
                else model.RouteRealizationKind.FOLDED
                if descriptor.step_kind is PatchStepKind.CONVERT_TO_GOTO
                else model.RouteRealizationKind.CONDITIONAL_REDIRECT
                if len(proof.destinations) > 1
                else model.RouteRealizationKind.DIRECT_REDIRECT
            )
            if descriptor.helper_refs and descriptor.step_kind not in {
                PatchStepKind.CONDITIONAL_REDIRECT,
                PatchStepKind.REDIRECT_BRANCH,
                PatchStepKind.HELPER_CORRIDOR,
            }:
                active_stage = model.RouteRealizationFailureStage.UNSUPPORTED_REALIZATION_KIND
                raise ValueError("helper-bearing route is unsupported")
            if cloned_relation is not None:
                relation = cloned_relation
            elif lower_relation is not None:
                relation = lower_relation
            elif folded_relation is not None:
                relation = folded_relation
            elif branch_relation is not None:
                relation = branch_relation
            elif corridor_relation is not None:
                relation = corridor_relation
            else:
                feeder_anchor = source_row.anchor_ea
                old_anchor = old_row.anchor_ea
                new_anchor = projected_new_row.anchor_ea
                if feeder_anchor is None or old_anchor is None or new_anchor is None:
                    raise ValueError("route relation requires anchored inventory coordinates")
                feeder_anchor_ref = model.AnchoredBlockRef(route_source_ref, feeder_anchor)
                old_anchor_ref = model.AnchoredBlockRef(old_ref, old_anchor)
                new_anchor_ref = model.AnchoredBlockRef(new_ref, new_anchor)
                if exact_selected_arm_parts is not None:
                    selected_destination, discarded_destination, exact_claims = (
                        exact_selected_arm_parts
                    )
                    exact_selected_arm_correlation = _ExactSelectedArmDirectCorrelation(
                        route_claim=claim,
                        proof=proof,
                        descriptor=descriptor,
                        facts=lineage_facts,
                        feeder=feeder_anchor_ref,
                        predicate_old_target=old_anchor_ref,
                        selected_destination=selected_destination,
                        discarded_destination=discarded_destination,
                        exact_claims=exact_claims,
                    )
                if shared_state_carrier_source_bypass_match:
                    carrier = proof.state_carrier
                    if carrier is None:
                        raise ValueError("shared-carrier relation lacks carrier evidence")
                    comparison_rows = tuple(
                        row for row in source_inventory.blocks
                        if _ref_matches_identity(
                            row.block_ref,
                            carrier.comparison_entry_identity,
                        )
                    )
                    if (
                        len(comparison_rows) != 1
                        or comparison_rows[0].anchor_ea is None
                    ):
                        raise ValueError(
                            "shared-carrier comparison entry lacks one exact anchor"
                        )
                    comparison_anchor_ref = model.AnchoredBlockRef(
                        comparison_rows[0].block_ref,
                        comparison_rows[0].anchor_ea,
                    )
                    expected_roles = (
                        model.SharedCarrierSourceBypassRouteRealization.__name__,
                        feeder_anchor_ref,
                        old_anchor_ref,
                        comparison_anchor_ref,
                        new_anchor_ref,
                    )
                    relation = _mint(
                        model.SharedCarrierSourceBypassRouteRealization,
                        {
                            "proof_source": feeder_anchor_ref,
                            "shared_feeder": old_anchor_ref,
                            "comparison_entry": comparison_anchor_ref,
                            "semantic_target": new_anchor_ref,
                            "relation_id": route_realization_id((
                                "shared_carrier_source_bypass",
                                feeder_anchor_ref,
                                old_anchor_ref,
                                comparison_anchor_ref,
                                new_anchor_ref,
                            )),
                        },
                        "relation_id",
                    )
                elif retained_prefix_match:
                    proof_source_row = _inventory_block(
                        source_inventory, retained_prefix_source_ref,
                    )
                    if proof_source_row.anchor_ea is None:
                        raise ValueError(
                            "retained-prefix proof source requires an anchor"
                        )
                    proof_source_anchor_ref = model.AnchoredBlockRef(
                        retained_prefix_source_ref,
                        proof_source_row.anchor_ea,
                    )
                    expected_roles = (
                        model.RetainedPrefixRouteRealization.__name__,
                        proof_source_anchor_ref,
                        feeder_anchor_ref,
                        old_anchor_ref,
                        new_anchor_ref,
                    )
                    relation = _mint(
                        model.RetainedPrefixRouteRealization,
                        {
                            "proof_source": proof_source_anchor_ref,
                            "delivery_owner": feeder_anchor_ref,
                            "old_target": old_anchor_ref,
                            "new_target": new_anchor_ref,
                            "relation_id": route_realization_id((
                                "retained_prefix",
                                proof_source_anchor_ref,
                                feeder_anchor_ref,
                                old_anchor_ref,
                                new_anchor_ref,
                            )),
                        },
                        "relation_id",
                    )
                else:
                    expected_roles = (
                        model.DirectRouteRealization.__name__,
                        feeder_anchor_ref, old_anchor_ref, new_anchor_ref,
                    )
                    relation = _mint(
                        model.DirectRouteRealization,
                        {
                            "feeder": feeder_anchor_ref,
                            "old_target": old_anchor_ref,
                            "new_target": new_anchor_ref,
                            "relation_id": route_realization_id(
                                ("direct", feeder_anchor_ref, old_anchor_ref, new_anchor_ref)
                            ),
                        },
                        "relation_id",
                    )
            if _draft_factory is not None:
                if expected_roles is None:
                    raise TypeError("projected route family did not select expected roles")
                selected_target_ref = new_ref
                _draft_factory(
                    claim=claim,
                    proof=claim_proof,
                    lineage_entry=entry,
                    proof_id=proof.proof_id,
                    route_subject_id=claim.retired_route_subject.subject_id,
                    descriptor=descriptor,
                    facts=lineage_facts,
                    selected_target_ref=selected_target_ref,
                    relation=relation,
                    expected_roles=expected_roles,
                    exact_selected_arm=exact_selected_arm_correlation,
                    entry_liveness_receipt=entry_liveness_receipt,
                )
        # Corrupt supplied facts for an unrelated descriptor cannot be silently
        # ignored.  Valid unrelated groups remain isolated and are accepted.
        for entry in lineage_index.entries:
            if entry.descriptor.step_index in selected_step_indices:
                continue
            if entry.descriptor.step_kind is PatchStepKind.CONVERT_TO_GOTO:
                active_stage = model.RouteRealizationFailureStage.CLAIM_SELECTION
                active_descriptor = entry.descriptor
                active_fact = entry.facts[0] if entry.facts else None
                active_claim = None
                active_anchored_refs = ()
                raise ValueError(
                    "conditional fold has no exact typed route owner"
                )
            if (
                entry.descriptor.step_kind is PatchStepKind.REDIRECT_GOTO
                and any(
                    _shared_state_carrier_source_bypass_coordinates_match(
                        plan, proof, entry.descriptor, source_inventory,
                    )
                    for proof in source_authority.proposal.route_evidence.route_proofs
                )
            ):
                active_stage = model.RouteRealizationFailureStage.CLAIM_SELECTION
                active_descriptor = entry.descriptor
                active_fact = entry.facts[0] if entry.facts else None
                active_claim = None
                active_anchored_refs = ()
                raise ValueError(
                    "shared-carrier source bypass has no exact typed route owner"
                )
            if entry.facts and entry.violation is not None:
                active_stage = entry.violation.stage
                active_descriptor = entry.violation.descriptor
                active_fact = entry.violation.fact
                # This is an evidence-wide post-selection sweep.  A corrupt
                # unrelated descriptor must retain its own STEP coordinates,
                # but must not inherit the selected claim's semantic IDs or
                # anchors merely because that claim was processed first.
                active_claim = None
                active_anchored_refs = ()
                raise entry.violation
        if _draft_factory is not None:
            return None
        raise RuntimeError("structural projected route kernel requires a draft sink")
    except (TypeError, ValueError, StopIteration) as exc:
        logger.warning(
            "projected route relation rejected: stage=%s claim=%s step=%s "
            "reason=%s:%s",
            active_stage.value,
            None if active_claim is None else active_claim.claim_id,
            None if active_descriptor is None else active_descriptor.step_index,
            type(exc).__name__,
            exc,
        )
        failure = _failure(**_route_failure_coordinates(
            source_authority.proposal if type(source_authority) is model.SourceBoundRouteAuthority else None,
            stage=active_stage,
            claim=active_claim,
            fact=active_fact,
            descriptor=active_descriptor,
            extra_anchored_refs=active_anchored_refs,
        ))
        return _result(model.ProjectedRouteRealizationRejected, {"failures": (failure,)})
def _validate_registered_result(value, expected, _registry=_ROUTE_REGISTRY,
                               _validate=_validate_registered_route,
                               _seal=_route_content_seal):
    if type(value) is not expected:
        raise TypeError(f"route result has unexpected type {type(value).__name__}")
    row = _registry.get(id(value))
    if row is None or row[0]() is not value:
        raise ValueError("route result was not minted by the route kernel")
    if row[1] != _canonical_registry_seal(value, _registry):
        raise ValueError("route result content seal does not match")
    if expected is model.SourceBoundRouteAuthorityAccepted:
        _validate(
            value.authority, "source_authority_id", _content_sealed=True,
        )
    elif expected is model.ProjectedRouteRealizationAccepted:
        _validate(value.realization, "realization_id", _content_sealed=True)
    else:
        for failure in value.failures:
            failure_row = _registry.get(id(failure))
            if failure_row is None or failure_row[0]() is not failure:
                raise ValueError("route failure was not minted by the route kernel")


def _make_route_kernels():
    mint = _route_mint
    failure = _route_failure
    result = _route_result
    base_validate_route = _validate_registered_route
    base_validate_result = _validate_registered_result
    source_impl = _bind_source_route_authority
    projected_impl = _legacy_structural_projected_routes
    register_route = _register_route
    route_registry, route_seal = register_route.__defaults__

    def publish_route_objects(
        route_publications: tuple[tuple[object, str], ...],
        publication_batch: _AtomicPublicationBatch,
    ) -> None:
        for value, identity in route_publications:
            stored_seal = route_seal(value, identity)
            publication_batch.defer(
                value=value, registry=route_registry,
                seal=stored_seal,
            )

    @dataclass(frozen=True, slots=True, weakref_slot=True)
    class _SelectedProjectedRouteRelation:
        claim: model.EquivalentSemanticRouteClaim
        proof: object
        lineage_entry: _LineageFactGroupEntry
        proof_id: str
        route_subject_id: str
        descriptor: CanonicalPatchStepDescriptor
        facts: tuple[model.PatchStepEvidencePayload, ...]
        selected_target_ref: object
        relation: object
        expected_roles: tuple[object, ...]
        exact_selected_arm: _ExactSelectedArmDirectCorrelation | None
        entry_liveness_receipt: model.BoundEntryEndpointLivenessAllowance | None

    @dataclass(frozen=True, slots=True)
    class _OwnerMapping:
        source_owner: model.AnchoredBlockRef
        projected_owner: model.AnchoredBlockRef
        lineage: model.ProjectedSiteLineageKind
        relation_id: str | None

    @dataclass(frozen=True, slots=True)
    class _ProjectedOwnerMappingIndex:
        relations_by_key: tuple[tuple[tuple[str, object], str], ...]
        owner_rows: tuple[_OwnerMapping, ...]
        relation_owner_occurrences: tuple[_RelationOwnerOccurrence, ...]
        inverse_only_projected_owners: tuple[model.AnchoredBlockRef, ...]

    class _ProjectedDraftViolation(ValueError):
        def __init__(self, message: str, *, draft=None, stage=None) -> None:
            super().__init__(message)
            self.draft = draft
            self.stage = stage

    draft_registry: dict[int, tuple[weakref.ReferenceType[object], str]] = {}

    def descriptor_content(descriptor: CanonicalPatchStepDescriptor) -> tuple[object, ...]:
        return (
            descriptor.plan_id, descriptor.step_index, descriptor.step_type,
            descriptor.step_kind, descriptor.owner_refs, descriptor.route_refs,
            descriptor.helper_refs, descriptor.host_ea, descriptor.host_opcode,
            descriptor.step_digest, descriptor.new_block_spec_digests,
        )

    def draft_content_seal(draft: _SelectedProjectedRouteRelation) -> str:
        correlation = draft.exact_selected_arm
        correlation_content = None if correlation is None else (
            correlation.route_claim, correlation.proof,
            descriptor_content(correlation.descriptor), correlation.facts,
            correlation.feeder, correlation.predicate_old_target,
            correlation.selected_destination, correlation.discarded_destination,
            correlation.exact_claims,
        )
        return authority_id((
            "projected-draft", draft.claim, draft.proof,
            descriptor_content(draft.lineage_entry.descriptor),
            draft.lineage_entry.facts, draft.proof_id, draft.route_subject_id,
            descriptor_content(draft.descriptor), draft.facts,
            draft.selected_target_ref, draft.relation, draft.expected_roles,
            correlation_content, draft.entry_liveness_receipt,
        ))

    def relation_role_payload(relation: object) -> tuple[object, ...]:
        """Snapshot every authority-bearing relation role at selection time."""
        def nested(value: object) -> object:
            if type(value) is model.ClonedSemanticInstructionOrigin:
                return (
                    model.ClonedSemanticInstructionOrigin.__name__,
                    value.source_owner, value.clone_owner, value.source_ordinal,
                    value.projected_ordinal, value.instruction_ea,
                    value.observation_digest,
                )
            if type(value) is model.ClonedSemanticPrefix:
                return (
                    model.ClonedSemanticPrefix.__name__, value.ordinal,
                    value.source_owner, value.clone_owner,
                    value.source_start_ordinal,
                    value.source_end_ordinal_exclusive,
                    tuple(nested(item) for item in value.instruction_origins),
                    value.source_trailing_goto_ordinal,
                    value.projected_synthetic_goto_ordinal,
                    value.projected_successor, value.creation_spec_row,
                )
            if type(value) is tuple:
                return tuple(nested(item) for item in value)
            return value

        if type(relation) is model.DirectRouteRealization:
            return (type(relation).__name__, relation.feeder, relation.old_target, relation.new_target)
        if type(relation) is model.SharedCarrierSourceBypassRouteRealization:
            return (
                type(relation).__name__, relation.proof_source,
                relation.shared_feeder, relation.comparison_entry,
                relation.semantic_target,
            )
        if type(relation) is model.RetainedPrefixRouteRealization:
            return (
                type(relation).__name__, relation.proof_source,
                relation.delivery_owner, relation.old_target,
                relation.new_target,
            )
        if type(relation) is model.LoweredConditionalRouteRealization:
            return (
                type(relation).__name__, relation.feeder, relation.proof_source,
                relation.old_target, relation.arms,
            )
        if type(relation) is model.ClonedConditionalRouteRealization:
            return (
                type(relation).__name__, relation.feeder, relation.proof_source,
                relation.old_target, relation.replacement_clone,
                relation.fallthrough_helper, relation.arms,
                relation.creation_spec_digests,
            )
        if type(relation) is model.FoldedConditionalRouteRealization:
            return (
                type(relation).__name__, relation.feeder,
                relation.selected_target, relation.discarded_target,
            )
        if type(relation) is model.TwoArmDirectBranchRouteRealization:
            return (
                type(relation).__name__, relation.feeder, relation.source_rewritten_arm,
                relation.projected_replacement_arm, relation.untouched_arm,
            )
        if type(relation) is model.BranchFallthroughHelperRouteRealization:
            return (
                type(relation).__name__, relation.feeder, relation.source_fallthrough,
                relation.untouched_conditional_arm, relation.helper,
                relation.semantic_target, relation.creation_spec_digests,
            )
        if type(relation) is model.ClonedRouteCorridorRealization:
            return (
                type(relation).__name__, relation.predecessor, relation.proof_source,
                relation.descriptor_old_target, relation.terminal_continuation,
                relation.source_corridor, relation.cloned_corridor,
                relation.semantic_target, nested(relation.semantic_prefixes),
                relation.creation_spec_digests,
            )
        if type(relation) is model.ClonedCarrierRouteCorridorRealization:
            return (
                type(relation).__name__, relation.proof_source,
                relation.physical_feeder, relation.comparison_entry,
                relation.source_corridor, relation.cloned_corridor,
                relation.semantic_target, nested(relation.semantic_prefixes),
                relation.creation_spec_digests,
            )
        raise TypeError(
            f"unknown projected route relation {type(relation).__name__}"
        )

    def register_draft(draft: _SelectedProjectedRouteRelation) -> _SelectedProjectedRouteRelation:
        seal = draft_content_seal(draft)
        key = id(draft)

        def cleanup(reference: weakref.ReferenceType[object]) -> None:
            row = draft_registry.get(key)
            if row is not None and row[0] is reference:
                draft_registry.pop(key, None)

        draft_registry[key] = (weakref.ref(draft, cleanup), seal)
        return draft

    def require_registered_draft(draft: object) -> _SelectedProjectedRouteRelation:
        if type(draft) is not _SelectedProjectedRouteRelation:
            raise TypeError("projected relation draft has an unknown type")
        row = draft_registry.get(id(draft))
        if row is None or row[0]() is not draft:
            raise ValueError("projected relation draft was not registered by the structural kernel")
        seal = draft_content_seal(draft)
        if row[1] != seal:
            raise ValueError("projected relation draft content seal does not match")
        return draft

    def _draft_projected_route_relations(**kwargs):
        route_publications: list[tuple[object, str]] = []

        def deferred_route_mint(
            cls: type[object], values: dict[str, object], identity_name: str,
        ) -> object:
            """Construct one call-local structural value without publishing it."""
            value = object.__new__(cls)
            for name, item in values.items():
                object.__setattr__(value, name, item)
            value.__post_init__()
            route_publications.append((value, getattr(value, identity_name)))
            return value

        drafts: list[_SelectedProjectedRouteRelation] = []
        selected_context: list[tuple[_LineageFactGroupEntry, tuple[model.PatchStepEvidencePayload, ...]]] = []

        def collect(**values):
            expected_roles = values.pop("expected_roles", None)
            relation = values.get("relation")
            if type(expected_roles) is not tuple or not expected_roles:
                raise TypeError("projected route family expected roles are not sealed")
            if type(relation) not in {
                model.DirectRouteRealization,
                model.SharedCarrierSourceBypassRouteRealization,
                model.RetainedPrefixRouteRealization,
                model.LoweredConditionalRouteRealization,
                model.ClonedConditionalRouteRealization,
                model.FoldedConditionalRouteRealization,
                model.TwoArmDirectBranchRouteRealization,
                model.BranchFallthroughHelperRouteRealization,
                model.ClonedRouteCorridorRealization,
                model.ClonedCarrierRouteCorridorRealization,
            }:
                raise TypeError("projected route family relation is not sealed")
            if expected_roles[0] != type(relation).__name__:
                raise ValueError("projected route family expected-role schema differs")
            if relation_role_payload(relation) != expected_roles:
                raise ValueError("projected route family output differs from selected roles")
            draft = register_draft(_SelectedProjectedRouteRelation(
                **values, expected_roles=expected_roles,
            ))
            drafts.append(draft)
            selected_context.append((draft.lineage_entry, draft.facts))

        structural_kwargs = dict(kwargs)
        structural_kwargs["_mint"] = deferred_route_mint
        structural = projected_impl(**structural_kwargs, _draft_factory=collect)
        if type(structural) is model.ProjectedRouteRealizationRejected:
            return structural, (), None, ()
        try:
            index = _build_projected_owner_mapping_index(
                drafts=tuple(drafts),
                source_authority=kwargs["source_authority"],
                source_inventory=kwargs["source_inventory"],
                plan=kwargs["plan"],
                patch_step_facts=kwargs["patch_step_facts"],
                selected_context=tuple(selected_context),
            )
        except (TypeError, ValueError) as exc:
            draft = getattr(exc, "draft", None)
            if draft is None and drafts:
                draft = drafts[0]
            raise _ProjectedDraftViolation(str(exc), draft=draft) from exc
        return structural, tuple(drafts), index, tuple(route_publications)

    merge_validated_drafts_hook = None

    def _build_projected_owner_mapping_index(
        *, drafts: tuple[_SelectedProjectedRouteRelation, ...],
        source_authority: model.SourceBoundRouteAuthority,
        source_inventory: model.SemanticGraphInventory,
        plan: PatchPlan,
        patch_step_facts: tuple[model.PatchStepEvidencePayload, ...],
        selected_context: tuple[tuple[_LineageFactGroupEntry, tuple[model.PatchStepEvidencePayload, ...]], ...],
    ) -> _ProjectedOwnerMappingIndex:
        nonlocal merge_validated_drafts_hook
        if type(drafts) is not tuple:
            raise TypeError("projected relation drafts must be an exact tuple")
        if type(source_authority) is not model.SourceBoundRouteAuthority:
            raise TypeError("projected relation drafts require source authority")
        if type(source_inventory) is not model.SemanticGraphInventory:
            raise TypeError("projected relation drafts require source inventory")
        model.validate_semantic_graph_inventory(source_inventory)
        if type(plan) is not PatchPlan:
            raise TypeError("projected relation drafts require a PatchPlan")
        if plan.unflatten_proposal is not source_authority.proposal:
            raise ValueError("projected relation draft plan is foreign to authority")
        if type(patch_step_facts) is not tuple:
            raise TypeError("projected relation drafts require exact patch facts")
        canonical_claims = {
            claim.claim_id: claim
            for claim in source_authority.proposal.claims
            if type(claim) is model.EquivalentSemanticRouteClaim
        }
        if type(selected_context) is not tuple:
            raise TypeError("projected relation drafts require selected context")
        for fact in patch_step_facts:
            if type(fact) is not model.PatchStepEvidencePayload:
                raise TypeError("projected relation draft facts are not sealed")
        proof_by_id = {
            proof.proof_id: proof
            for proof in source_authority.proposal.route_evidence.route_proofs
        }
        relation_keys: dict[tuple[str, object], str] = {}
        seen_drafts: set[tuple[object, ...]] = set()
        owner_rows: list[_OwnerMapping] = []
        relation_occurrences: list[_RelationOwnerOccurrence] = []
        inverse_only: set[model.AnchoredBlockRef] = set()
        source_rows: dict[model.AnchoredBlockRef, _OwnerMapping] = {}
        clone_occurrences_by_source: dict[
            model.AnchoredBlockRef,
            set[tuple[str, model.AnchoredBlockRef, model.AnchoredBlockRef]],
        ] = {}
        site_free_multi_clone_sources: set[model.AnchoredBlockRef] = set()
        validated_drafts: list[_SelectedProjectedRouteRelation] = []

        def add(source: model.AnchoredBlockRef, projected: model.AnchoredBlockRef,
                lineage: model.ProjectedSiteLineageKind, relation_id: str | None) -> None:
            if type(source) is not model.AnchoredBlockRef or type(projected) is not model.AnchoredBlockRef:
                raise TypeError("owner mappings require anchored owners")
            row = _OwnerMapping(source, projected, lineage, relation_id)
            if lineage is model.ProjectedSiteLineageKind.RELATION_CLONE:
                clone_occurrences = clone_occurrences_by_source.setdefault(
                    source, set(),
                )
                clone_occurrences.add((relation_id or "", source, projected))
                if len({item[2] for item in clone_occurrences}) > 1:
                    _canonical_semantic_site_owner_mapping(
                        source_inventory=source_inventory,
                        source_owner=source,
                        clone_occurrences=tuple(clone_occurrences),
                    )
                    previous = source_rows.get(source)
                    if (
                        previous is not None
                        and previous.lineage
                        is model.ProjectedSiteLineageKind.RELATION_CLONE
                    ):
                        source_rows.pop(source)
                        owner_rows.remove(previous)
                    site_free_multi_clone_sources.add(source)
                    return
            if (
                source in site_free_multi_clone_sources
                and lineage is model.ProjectedSiteLineageKind.RELATION_CLONE
            ):
                return
            previous = source_rows.get(source)
            def is_same_owner(item: _OwnerMapping) -> bool:
                return (
                    item.source_owner == item.projected_owner
                    and item.lineage is model.ProjectedSiteLineageKind.SAME_OWNER
                    and item.relation_id is None
                )
            if previous is not None and previous != row:
                # Site disposition is single-valued, while a source owner can
                # participate in several route relations.  Preserve every
                # relation incidence separately, but prefer the physical
                # same-owner row when a clone relation also names this owner.
                if is_same_owner(previous):
                    return
                if is_same_owner(row):
                    owner_rows[owner_rows.index(previous)] = row
                    source_rows[source] = row
                    return
                raise ValueError(
                    "conflicting source-owner mappings: "
                    f"source={source!r} previous={previous!r} current={row!r}"
                )
            if previous is None:
                source_rows[source] = row
                owner_rows.append(row)

        def add_occurrence(
            relation_id: str, source: model.AnchoredBlockRef,
            projected: model.AnchoredBlockRef,
            lineage: model.ProjectedSiteLineageKind,
        ) -> None:
            row = _RelationOwnerOccurrence(
                relation_id, source, projected, lineage,
            )
            if row not in relation_occurrences:
                relation_occurrences.append(row)

        for draft in drafts:
            try:
                draft = require_registered_draft(draft)
                if type(draft.claim) is not model.EquivalentSemanticRouteClaim:
                    raise TypeError("projected relation draft claim is not sealed")
                canonical_claim = canonical_claims.get(draft.claim.claim_id)
                if canonical_claim is not draft.claim:
                    raise ValueError("projected relation draft claim is foreign to authority")
                if draft.claim.source_generation != source_authority.source_generation:
                    raise ValueError("projected relation draft claim generation mismatch")
                if draft.route_subject_id != draft.claim.retired_route_subject.subject_id:
                    raise ValueError("projected relation draft route subject mismatch")
                if type(draft.descriptor) is not CanonicalPatchStepDescriptor:
                    raise TypeError("projected relation draft descriptor is not sealed")
                selected = next(
                    (
                        (lineage_entry, selected_facts)
                        for lineage_entry, selected_facts in selected_context
                        if lineage_entry is draft.lineage_entry
                    ),
                    None,
                )
                if selected is None or selected[0].descriptor is not draft.descriptor:
                    raise ValueError("projected relation draft descriptor is not canonical")
                if type(draft.facts) is not tuple or not draft.facts:
                    raise TypeError("projected relation draft facts are incomplete")
                if any(type(fact) is not model.PatchStepEvidencePayload for fact in draft.facts):
                    raise TypeError("projected relation draft fact group is not sealed")
                if any(
                    fact.step_index != draft.descriptor.step_index
                    or fact.step_digest != draft.descriptor.step_digest
                    for fact in draft.facts
                ):
                    raise ValueError("projected relation draft fact group mismatches descriptor")
                if len({(fact.owner_ref, fact.step_index, fact.step_digest) for fact in draft.facts}) != len(draft.facts):
                    raise ValueError("projected relation draft fact group contains duplicates")
                if tuple(fact.owner_ref for fact in draft.facts) != draft.descriptor.owner_refs:
                    raise ValueError("projected relation draft fact group is incomplete")
                supplied_context_facts = selected[1] if selected is not None else ()
                if any(
                    expected is not supplied
                    for expected, supplied in zip(supplied_context_facts, draft.facts)
                ) or len(supplied_context_facts) != len(draft.facts):
                    raise ValueError("projected relation draft facts are foreign or incomplete")
                if any(
                    not any(context_fact is fact for context_fact in patch_step_facts)
                    for fact in draft.facts
                ):
                    raise ValueError("projected relation draft facts are foreign or incomplete")
                if draft.proof_id not in draft.claim.route_proof_ids:
                    raise ValueError("proof/claim/descriptor mismatch")
                proof = proof_by_id.get(draft.proof_id)
                if proof is None or proof is not draft.proof or proof.proof_id != draft.proof_id:
                    raise ValueError("projected relation draft proof is foreign to authority")
                selected_target = draft.selected_target_ref
                _native_route_destination_subject_for_target_ref(
                    claim=draft.claim,
                    proof=proof,
                    target_ref=selected_target,
                    catalog=source_authority.proposal.source_identity_catalog,
                )
                if type(draft.relation) not in {
                    model.DirectRouteRealization,
                    model.SharedCarrierSourceBypassRouteRealization,
                    model.RetainedPrefixRouteRealization,
                    model.LoweredConditionalRouteRealization,
                    model.ClonedConditionalRouteRealization,
                    model.FoldedConditionalRouteRealization,
                    model.TwoArmDirectBranchRouteRealization,
                    model.BranchFallthroughHelperRouteRealization,
                    model.ClonedRouteCorridorRealization,
                    model.ClonedCarrierRouteCorridorRealization,
                }:
                    raise TypeError("projected relation draft relation is not sealed")
                if type(draft.expected_roles) is not tuple:
                    raise TypeError("projected relation draft role seal is incomplete")
                if relation_role_payload(draft.relation) != draft.expected_roles:
                    raise ValueError("projected relation draft relation roles differ from selected family")
                # Structural relations are sealed values, but remain
                # unpublished until the independent site validator accepts
                # the complete closure.  Registration is performed by the
                # closure-local mint phase.
                draft.relation.__post_init__()
                expected_relation_type = {
                    PatchStepKind.REDIRECT_GOTO: (
                        model.DirectRouteRealization,
                        model.SharedCarrierSourceBypassRouteRealization,
                        model.RetainedPrefixRouteRealization,
                    ),
                    PatchStepKind.BYPASS_TRAMPOLINE: model.DirectRouteRealization,
                    PatchStepKind.REDIRECT_BRANCH: (
                        model.BranchFallthroughHelperRouteRealization
                        if draft.descriptor.helper_refs
                        else model.TwoArmDirectBranchRouteRealization
                    ),
                    PatchStepKind.LOWER_CONDITIONAL: model.LoweredConditionalRouteRealization,
                    PatchStepKind.CONDITIONAL_REDIRECT: model.ClonedConditionalRouteRealization,
                    PatchStepKind.CONVERT_TO_GOTO: model.FoldedConditionalRouteRealization,
                    PatchStepKind.HELPER_CORRIDOR: (
                        model.ClonedRouteCorridorRealization,
                        model.ClonedCarrierRouteCorridorRealization,
                    ),
                }.get(draft.descriptor.step_kind)
                if (
                    isinstance(expected_relation_type, tuple)
                    and type(draft.relation) not in expected_relation_type
                    or not isinstance(expected_relation_type, tuple)
                    and type(draft.relation) is not expected_relation_type
                ):
                    raise ValueError("projected relation draft relation family mismatch")

                # Relation objects are already sealed and selected by the
                # structural kernel.  Correlate their anchored roles back to
                # that exact proof/catalog occurrence here; registration and
                # a matching selected target alone are insufficient.
                catalog_by_ref = {
                    witness.block_ref: witness
                    for witness in source_authority.proposal.source_identity_catalog.blocks
                }

                def require_catalog_anchor(owner: object, role: str) -> None:
                    if type(owner) is not model.AnchoredBlockRef:
                        raise TypeError(f"{role} is not an anchored relation role")
                    witness = catalog_by_ref.get(owner.ref)
                    if witness is None:
                        if type(owner.ref) is PlanBlockRef and owner.ref in draft.descriptor.owner_refs:
                            return
                        raise ValueError(f"{role} is foreign to the exact source catalog")
                    if owner.anchor_ea != witness.anchor_ea:
                        raise ValueError(f"{role} is foreign to the exact source catalog")

                def identity_owner(
                    identity: object, anchor_ea: int,
                ) -> model.AnchoredBlockRef:
                    proof_ref = next(
                        (
                            witness.block_ref
                            for witness in source_authority.proposal.source_identity_catalog.blocks
                            if type(witness.block_ref) is NativeBlockRef
                            and witness.block_ref.identity == identity
                        ),
                        None,
                    )
                    if proof_ref is None:
                        raise ValueError("proof identity is foreign to the source catalog")
                    # A proof names an instruction site inside a native block;
                    # structural relation roles name the catalog-owned block.
                    # Preserve that distinction while still requiring the
                    # proof coordinate to be inside the exact native identity.
                    if not proof_ref.identity.native_ranges.contains(anchor_ea):
                        raise ValueError("proof instruction site is outside its exact native identity")
                    witness = catalog_by_ref[proof_ref]
                    owner = model.AnchoredBlockRef(proof_ref, witness.anchor_ea)
                    require_catalog_anchor(owner, "proof source")
                    return owner

                expected_proof_owner = identity_owner(
                    proof.source_identity, proof.source_anchor_ea,
                )
                entry_liveness_receipt = draft.entry_liveness_receipt
                entry_liveness_owner = None
                if entry_liveness_receipt is not None:
                    validate_bound_entry_endpoint_liveness_allowance(
                        entry_liveness_receipt,
                    )
                    if _selected_entry_liveness_receipt(
                        entry=draft.lineage_entry,
                        proof=proof,
                        receipts=(entry_liveness_receipt,),
                    ) is not entry_liveness_receipt:
                        raise ValueError(
                            "entry liveness receipt differs from selected redirect",
                        )
                    owner_ref = (
                        entry_liveness_receipt.allowance
                        .entry_predecessor_owner_refs[0]
                    )
                    owner_witness = catalog_by_ref.get(owner_ref)
                    if owner_witness is None:
                        raise ValueError("entry liveness owner is foreign to source catalog")
                    entry_liveness_owner = model.AnchoredBlockRef(
                        owner_ref, owner_witness.anchor_ea,
                    )
                exact_selected_arm = draft.exact_selected_arm
                owner_bound_direct = _owner_bound_direct_coordinates_match(
                    plan, proof, draft.descriptor,
                )
                carrier_feeder_direct = (
                    _state_carrier_feeder_direct_coordinates_match(
                        plan, proof, draft.descriptor,
                    )
                )
                shared_carrier_source_bypass = (
                    _shared_state_carrier_source_bypass_coordinates_match(
                        plan, proof, draft.descriptor, source_inventory,
                    )
                )
                if exact_selected_arm is not None:
                    if type(exact_selected_arm) is not _ExactSelectedArmDirectCorrelation:
                        raise TypeError("selected-arm direct correlation is not closed")
                    selected_destination, discarded_destination, exact_claims = (
                        _exact_selected_arm_claim_bundle(
                            plan=plan, route_claim=draft.claim, proof=proof,
                            descriptor=draft.descriptor,
                        )
                    )
                    expected_feeder = identity_owner(
                        proof.source_owner_identity,
                        proof.source_owner_anchor_ea,
                    )
                    if (
                        exact_selected_arm.route_claim is not draft.claim
                        or exact_selected_arm.proof is not proof
                        or exact_selected_arm.descriptor is not draft.descriptor
                        or len(exact_selected_arm.facts) != len(draft.facts)
                        or any(
                            left is not right
                            for left, right in zip(exact_selected_arm.facts, draft.facts)
                        )
                        or exact_selected_arm.feeder != expected_feeder
                        or exact_selected_arm.predicate_old_target != expected_proof_owner
                        or exact_selected_arm.selected_destination is not selected_destination
                        or exact_selected_arm.discarded_destination is not discarded_destination
                        or len(exact_selected_arm.exact_claims) != len(exact_claims)
                        or any(
                            left is not right
                            for left, right in zip(
                                exact_selected_arm.exact_claims, exact_claims,
                            )
                        )
                    ):
                        raise ValueError("selected-arm direct correlation occurrence drifted")
                relation_source_owner = (
                    draft.relation.proof_source
                    if type(draft.relation) in {
                        model.SharedCarrierSourceBypassRouteRealization,
                        model.RetainedPrefixRouteRealization,
                        model.LoweredConditionalRouteRealization,
                        model.ClonedConditionalRouteRealization,
                        model.ClonedRouteCorridorRealization,
                        model.ClonedCarrierRouteCorridorRealization,
                    }
                    else draft.relation.feeder
                )
                expected_relation_source_owner = (
                    exact_selected_arm.feeder
                    if exact_selected_arm is not None
                    # A retained-prefix relation keeps W as its semantic
                    # proof source and names P separately as delivery_owner.
                    # An entry-liveness receipt authorizes that physical P
                    # edge; it must not rewrite the proof-source role.
                    else expected_proof_owner
                    if type(draft.relation)
                    is model.RetainedPrefixRouteRealization
                    else entry_liveness_owner
                    if entry_liveness_owner is not None
                    else identity_owner(
                        proof.source_identity, proof.source_anchor_ea,
                    )
                    if type(draft.relation)
                    is model.FoldedConditionalRouteRealization
                    else identity_owner(
                        proof.state_carrier.feeder_identity,
                        proof.state_carrier.feeder_anchor_ea,
                    )
                    if carrier_feeder_direct and proof.state_carrier is not None
                    else identity_owner(
                        proof.source_owner_identity,
                        proof.source_owner_anchor_ea,
                    )
                    if owner_bound_direct
                    else expected_proof_owner
                )
                if relation_source_owner != expected_relation_source_owner:
                    raise ValueError("relation source role does not match exact proof")

                native_roles = []
                for role_name in draft.relation.__dataclass_fields__:
                    if role_name in {"relation_id", "creation_spec_digests", "semantic_prefixes"}:
                        continue
                    value = getattr(draft.relation, role_name)
                    if type(value) is model.AnchoredBlockRef:
                        native_roles.append((role_name, value))
                    elif isinstance(value, tuple):
                        native_roles.extend(
                            (f"{role_name}[{index}]", item)
                            for index, item in enumerate(value)
                            if type(item) is model.AnchoredBlockRef
                        )
                for role_name, owner in native_roles:
                    require_catalog_anchor(owner, role_name)

                relation = draft.relation
                if type(relation) is model.DirectRouteRealization:
                    if (
                        proof.proof_kind
                        is route_model.SemanticRouteProofKind.STATE_CARRIER
                        and not carrier_feeder_direct
                    ):
                        raise ValueError(
                            "state-carrier direct relation lacks exact feeder coordinates"
                        )
                    if exact_selected_arm is None:
                        if (
                            proof.shape is not route_model.SemanticRouteShape.DIRECT
                            or len(proof.destinations) != 1
                            or proof.destinations[0].role is not SemanticEdgeRole.DIRECT
                            or relation.old_target.ref != draft.descriptor.route_refs[1]
                            or (
                                owner_bound_direct
                                and relation.old_target != expected_proof_owner
                            )
                        ):
                            raise ValueError("ordinary direct relation proof differs")
                    elif (
                        relation.feeder != exact_selected_arm.feeder
                        or relation.old_target != exact_selected_arm.predicate_old_target
                        or relation.new_target.ref != selected_target
                        or relation.new_target.anchor_ea
                        != exact_selected_arm.selected_destination.target_anchor_ea
                    ):
                        raise ValueError("selected-arm direct relation roles differ")
                    if relation.new_target.ref != selected_target:
                        raise ValueError("direct relation target differs from selected target")
                elif type(relation) is model.SharedCarrierSourceBypassRouteRealization:
                    carrier = proof.state_carrier
                    if (
                        not shared_carrier_source_bypass
                        or proof.proof_kind
                        is not route_model.SemanticRouteProofKind.STATE_CARRIER
                        or carrier is None
                        or carrier.requires_feeder_clone
                    ):
                        raise ValueError(
                            "shared-carrier bypass lacks exact typed carrier coordinates"
                        )
                    expected_feeder = identity_owner(
                        carrier.feeder_identity, carrier.feeder_anchor_ea,
                    )
                    expected_comparison = identity_owner(
                        carrier.comparison_entry_identity,
                        carrier.comparison_entry_anchor_ea,
                    )
                    if (
                        relation.proof_source != expected_proof_owner
                        or relation.shared_feeder != expected_feeder
                        or relation.comparison_entry != expected_comparison
                        or relation.semantic_target.ref != selected_target
                    ):
                        raise ValueError(
                            "shared-carrier bypass roles differ from exact typed evidence"
                        )
                elif type(relation) is model.RetainedPrefixRouteRealization:
                    expected_proof_source = identity_owner(
                        proof.source_identity, proof.source_anchor_ea,
                    )
                    if (
                        relation.proof_source != expected_proof_source
                        or relation.new_target.ref != selected_target
                        or (
                            entry_liveness_owner is not None
                            and relation.delivery_owner != entry_liveness_owner
                        )
                    ):
                        raise ValueError("retained-prefix relation differs from proof")
                elif type(relation) is model.LoweredConditionalRouteRealization:
                    if relation.old_target != relation.proof_source:
                        raise ValueError("lowered conditional old target differs from proof source")
                    destination_by_role = {
                        destination.role: model.AnchoredBlockRef(
                            next(
                                witness.block_ref
                                for witness in source_authority.proposal.source_identity_catalog.blocks
                                if type(witness.block_ref) is NativeBlockRef
                                and witness.block_ref.identity == destination.target_identity
                            ),
                            destination.target_anchor_ea,
                        )
                        for destination in proof.destinations
                    }
                    if any(arm.target != destination_by_role.get(arm.role) for arm in relation.arms):
                        raise ValueError("lowered conditional arms differ from proof destinations")
                elif type(relation) is model.ClonedConditionalRouteRealization:
                    if relation.old_target != relation.proof_source:
                        raise ValueError("cloned conditional old target differs from proof source")
                    destination_by_role = {
                        destination.role: model.AnchoredBlockRef(
                            next(
                                witness.block_ref
                                for witness in source_authority.proposal.source_identity_catalog.blocks
                                if type(witness.block_ref) is NativeBlockRef
                                and witness.block_ref.identity == destination.target_identity
                            ),
                            destination.target_anchor_ea,
                        )
                        for destination in proof.destinations
                    }
                    if any(arm.target != destination_by_role.get(arm.role) for arm in relation.arms):
                        raise ValueError("cloned conditional arms differ from proof destinations")
                elif type(relation) is model.FoldedConditionalRouteRealization:
                    guarded = (
                        None if proof.state_write is None
                        else proof.state_write.guarded_selection
                    )
                    default_gap_parts = _default_gap_conditional_fold_parts(
                        plan, proof, draft.descriptor,
                    )
                    guarded_fold = _guarded_conditional_fold_coordinates_match(
                        plan, proof, draft.descriptor,
                    )
                    selected_identity = (
                        guarded.selected_target.identity
                        if guarded_fold and guarded is not None
                        else default_gap_parts[0].target_identity
                        if default_gap_parts is not None else None
                    )
                    discarded_identity = (
                        tuple(
                            endpoint.identity for endpoint in (
                                guarded.true_target, guarded.false_target,
                            ) if endpoint != guarded.selected_target
                        )
                        if guarded_fold and guarded is not None
                        else (default_gap_parts[1].target_identity,)
                        if default_gap_parts is not None else ()
                    )
                    if (
                        (not guarded_fold and default_gap_parts is None)
                        or not _ref_matches_identity(
                            relation.feeder.ref, proof.source_identity,
                        )
                        or not _ref_matches_identity(
                            relation.selected_target.ref,
                            selected_identity,
                        )
                        or relation.selected_target.ref != selected_target
                        or not any(
                            _ref_matches_identity(
                                relation.discarded_target.ref,
                                identity,
                            )
                            for identity in discarded_identity
                        )
                    ):
                        raise ValueError(
                            "folded relation differs from guarded proof"
                        )
                elif type(relation) is model.TwoArmDirectBranchRouteRealization:
                    if relation.projected_replacement_arm.ref != selected_target:
                        raise ValueError("two-arm projected arm differs from selected target")
                elif type(relation) is model.BranchFallthroughHelperRouteRealization:
                    if relation.semantic_target.ref != selected_target:
                        raise ValueError("branch-helper target differs from selected target")
                    if relation.source_fallthrough != relation.untouched_conditional_arm:
                        raise ValueError("branch-helper source and untouched roles differ")
                elif type(relation) is model.ClonedRouteCorridorRealization:
                    expected_corridor = tuple(
                        model.AnchoredBlockRef(
                            source_owner.ref,
                            catalog_by_ref[source_owner.ref].anchor_ea,
                        )
                        for source_owner in relation.source_corridor
                    )
                    if relation.source_corridor != expected_corridor:
                        raise ValueError("corridor source roles differ from exact lineage")
                elif type(relation) is model.ClonedCarrierRouteCorridorRealization:
                    carrier = proof.state_carrier
                    if (
                        proof.proof_kind
                        is not route_model.SemanticRouteProofKind.STATE_CARRIER
                        or carrier is None
                        or not carrier.requires_feeder_clone
                        or not _state_carrier_helper_corridor_coordinates_match(
                            plan, proof, draft.descriptor,
                        )
                    ):
                        raise ValueError(
                            "carrier relation lacks its exact typed carrier proof"
                        )
                    expected_feeder = identity_owner(
                        carrier.feeder_identity, carrier.feeder_anchor_ea,
                    )
                    expected_comparison = identity_owner(
                        carrier.comparison_entry_identity,
                        carrier.comparison_entry_anchor_ea,
                    )
                    if (
                        relation.proof_source != expected_proof_owner
                        or relation.physical_feeder != expected_feeder
                        or relation.comparison_entry != expected_comparison
                        or relation.source_corridor != (expected_feeder,)
                        or relation.semantic_target.ref != selected_target
                    ):
                        raise ValueError(
                            "carrier relation roles differ from exact typed evidence"
                        )
                semantic_targets = {
                    draft.relation.new_target.ref
                    if type(draft.relation) in {
                        model.DirectRouteRealization,
                        model.RetainedPrefixRouteRealization,
                    }
                    else False,
                }
                if type(draft.relation) is model.SharedCarrierSourceBypassRouteRealization:
                    semantic_targets = {draft.relation.semantic_target.ref}
                if type(draft.relation) in {
                    model.LoweredConditionalRouteRealization,
                    model.ClonedConditionalRouteRealization,
                }:
                    semantic_targets = {arm.target.ref for arm in draft.relation.arms}
                elif type(draft.relation) is model.TwoArmDirectBranchRouteRealization:
                    semantic_targets = {draft.relation.projected_replacement_arm.ref}
                elif type(draft.relation) is model.FoldedConditionalRouteRealization:
                    semantic_targets = {draft.relation.selected_target.ref}
                elif type(draft.relation) is model.BranchFallthroughHelperRouteRealization:
                    semantic_targets = {draft.relation.semantic_target.ref}
                elif type(draft.relation) is model.ClonedRouteCorridorRealization:
                    semantic_targets = {draft.relation.semantic_target.ref}
                elif type(draft.relation) is model.ClonedCarrierRouteCorridorRealization:
                    semantic_targets = {draft.relation.semantic_target.ref}
                if selected_target not in semantic_targets:
                    raise ValueError("projected relation draft selected target mismatch")
                occurrence = (
                    draft.claim.claim_id, draft.proof_id, draft.route_subject_id,
                    draft.descriptor.step_index, draft.descriptor.step_digest,
                    draft.relation.relation_id, draft.facts,
                )
                if occurrence in seen_drafts:
                    raise ValueError("duplicate projected relation draft occurrence")
                seen_drafts.add(occurrence)
            except (TypeError, ValueError) as exc:
                raise _ProjectedDraftViolation(str(exc), draft=draft) from exc
            key = (draft.proof_id, selected_target)
            old_mapping = relation_keys.get(key)
            if old_mapping is not None:
                raise _ProjectedDraftViolation(
                    "duplicate proof/target mapping occurrence", draft=draft,
                )
            else:
                relation_keys[key] = draft.relation.relation_id
            validated_drafts.append(draft)

        def merge_validated_drafts(
            drafts_to_merge: tuple[_SelectedProjectedRouteRelation, ...],
        ) -> None:
            """Fold only registry/role-sealed drafts into the owner domain."""
            owner_rows.clear()
            relation_occurrences.clear()
            source_rows.clear()
            inverse_only.clear()
            same = model.ProjectedSiteLineageKind.SAME_OWNER
            clone = model.ProjectedSiteLineageKind.RELATION_CLONE
            for draft in drafts_to_merge:
                try:
                    draft = require_registered_draft(draft)
                    if relation_role_payload(draft.relation) != draft.expected_roles:
                        raise ValueError("projected relation draft relation roles differ from selected family")
                    relation = draft.relation

                    def add_for_draft(*args):
                        try:
                            add(*args)
                        except (TypeError, ValueError) as exc:
                            raise _ProjectedDraftViolation(
                                str(exc), draft=draft,
                            ) from exc

                    def occur(
                        source: model.AnchoredBlockRef,
                        projected: model.AnchoredBlockRef,
                        lineage: model.ProjectedSiteLineageKind,
                    ) -> None:
                        add_occurrence(
                            relation.relation_id, source, projected, lineage,
                        )

                    if type(relation) is model.DirectRouteRealization:
                        add_for_draft(relation.feeder, relation.feeder, same, None)
                        add_for_draft(relation.new_target, relation.new_target, same, None)
                        occur(relation.feeder, relation.feeder, same)
                        occur(relation.new_target, relation.new_target, same)
                    elif type(relation) is model.SharedCarrierSourceBypassRouteRealization:
                        for owner in (
                            relation.proof_source, relation.semantic_target,
                        ):
                            add_for_draft(owner, owner, same, None)
                            occur(owner, owner, same)
                    elif type(relation) is model.RetainedPrefixRouteRealization:
                        for owner in (
                            relation.proof_source,
                            relation.delivery_owner,
                            relation.new_target,
                        ):
                            add_for_draft(owner, owner, same, None)
                            occur(owner, owner, same)
                    elif type(relation) is model.LoweredConditionalRouteRealization:
                        add_for_draft(relation.feeder, relation.feeder, same, None)
                        add_for_draft(relation.proof_source, relation.proof_source, same, None)
                        occur(relation.feeder, relation.feeder, same)
                        occur(relation.proof_source, relation.proof_source, same)
                        for arm in relation.arms:
                            add_for_draft(arm.target, arm.target, same, None)
                            occur(arm.target, arm.target, same)
                    elif type(relation) is model.ClonedConditionalRouteRealization:
                        add_for_draft(relation.feeder, relation.feeder, same, None)
                        add_for_draft(relation.proof_source, relation.replacement_clone, clone, relation.relation_id)
                        occur(relation.feeder, relation.feeder, same)
                        occur(relation.proof_source, relation.replacement_clone, clone)
                        for arm in relation.arms:
                            add_for_draft(arm.target, arm.target, same, None)
                            occur(arm.target, arm.target, same)
                        inverse_only.add(relation.fallthrough_helper)
                    elif type(relation) is model.FoldedConditionalRouteRealization:
                        for owner in (
                            relation.feeder, relation.selected_target,
                        ):
                            add_for_draft(owner, owner, same, None)
                            occur(owner, owner, same)
                    elif type(relation) is model.TwoArmDirectBranchRouteRealization:
                        add_for_draft(relation.feeder, relation.feeder, same, None)
                        add_for_draft(relation.projected_replacement_arm, relation.projected_replacement_arm, same, None)
                        add_for_draft(relation.untouched_arm, relation.untouched_arm, same, None)
                        occur(relation.feeder, relation.feeder, same)
                        occur(
                            relation.projected_replacement_arm,
                            relation.projected_replacement_arm,
                            same,
                        )
                        occur(relation.untouched_arm, relation.untouched_arm, same)
                    elif type(relation) is model.BranchFallthroughHelperRouteRealization:
                        add_for_draft(relation.feeder, relation.feeder, same, None)
                        add_for_draft(relation.untouched_conditional_arm, relation.untouched_conditional_arm, same, None)
                        add_for_draft(relation.semantic_target, relation.semantic_target, same, None)
                        occur(relation.feeder, relation.feeder, same)
                        occur(relation.untouched_conditional_arm, relation.untouched_conditional_arm, same)
                        occur(relation.semantic_target, relation.semantic_target, same)
                        inverse_only.add(relation.helper)
                    elif type(relation) is model.ClonedRouteCorridorRealization:
                        add_for_draft(relation.predecessor, relation.predecessor, same, None)
                        add_for_draft(relation.semantic_target, relation.semantic_target, same, None)
                        occur(relation.predecessor, relation.predecessor, same)
                        occur(relation.semantic_target, relation.semantic_target, same)
                        for source_owner, projected_owner in zip(
                            relation.source_corridor, relation.cloned_corridor,
                        ):
                            add_for_draft(source_owner, projected_owner, clone, relation.relation_id)
                            occur(source_owner, projected_owner, clone)
                    elif type(relation) is model.ClonedCarrierRouteCorridorRealization:
                        add_for_draft(
                            relation.proof_source, relation.proof_source,
                            same, None,
                        )
                        add_for_draft(
                            relation.semantic_target, relation.semantic_target,
                            same, None,
                        )
                        occur(
                            relation.proof_source, relation.proof_source, same,
                        )
                        occur(
                            relation.semantic_target,
                            relation.semantic_target,
                            same,
                        )
                        for source_owner, projected_owner in zip(
                            relation.source_corridor,
                            relation.cloned_corridor,
                        ):
                            add_for_draft(
                                source_owner, projected_owner, clone,
                                relation.relation_id,
                            )
                            occur(source_owner, projected_owner, clone)
                    else:
                        raise TypeError(
                            "unknown projected route relation "
                            f"{type(relation).__name__}"
                        )
                except _ProjectedDraftViolation:
                    raise
                except (TypeError, ValueError) as exc:
                    raise _ProjectedDraftViolation(str(exc), draft=draft) from exc

        merge_validated_drafts_hook = merge_validated_drafts
        merge_validated_drafts(tuple(validated_drafts))
        return _ProjectedOwnerMappingIndex(
            tuple((key, relation_id) for key, relation_id in sorted(
                relation_keys.items(), key=canonical_bytes,
            )),
            tuple(owner_rows),
            tuple(sorted(
                relation_occurrences,
                key=lambda row: canonical_bytes((
                    row.relation_id, row.source_owner,
                    row.projected_owner, row.lineage,
                )),
            )),
            tuple(sorted(inverse_only, key=canonical_bytes)),
        )

    def validate_route(value, identity_name, *, _content_sealed=False):
        base_validate_route(
            value, identity_name, _content_sealed=_content_sealed,
        )
        if type(value) is model.ProjectedRouteRealization:
            validate_route(
                value.source_authority, "source_authority_id",
                _content_sealed=True,
            )
            validate_projected_site_phase_result(
                value.site_phase_result, _content_sealed=True,
            )
            for row in value.rows:
                validate_route(row, "row_id", _content_sealed=True)
        elif type(value) is model.ProjectedRouteRealizationRow:
            validate_route(
                value.relation, "relation_id", _content_sealed=True,
            )
            validate_projected_route_site_preservation(
                value.site_preservation, _content_sealed=True,
            )
        elif type(value) in {
            model.ClonedRouteCorridorRealization,
            model.ClonedCarrierRouteCorridorRealization,
        }:
            for prefix in value.semantic_prefixes:
                validate_route(prefix, "prefix_id", _content_sealed=True)
        elif type(value) is model.ClonedSemanticPrefix:
            for origin in value.instruction_origins:
                validate_route(origin, "origin_id", _content_sealed=True)
        elif type(value) is model.ProjectedRouteRealizationAccepted:
            validate_route(
                value.realization, "realization_id", _content_sealed=True,
            )
        elif type(value) is model.SourceBoundRouteAuthorityAccepted:
            validate_route(
                value.authority, "source_authority_id", _content_sealed=True,
            )

    def validate_result(value, expected):
        return base_validate_result(value, expected, _validate=validate_route)

    def _mint_projected_site_closure(
        *, draft: _ProjectedSiteClosureDraft, authority_id: str,
        source_authority: model.SourceBoundRouteAuthority, plan: PatchPlan,
        source_inventory: model.SemanticGraphInventory,
        projected_inventory: model.SemanticGraphInventory,
        raw_effect_gate_fact: model.RawEffectGatePhaseFact,
        legacy_effective_gate_facts: object, attempt_id: TransactionAttemptId,
        drafts: tuple[object, ...], owner_index: object,
        route_publications: tuple[tuple[object, str], ...],
    ) -> model.ProjectedRouteRealizationResult:
        """Mint the accepted closure only after independent draft validation."""
        publication_batch = _AtomicPublicationBatch()
        publish_route_objects(route_publications, publication_batch)
        # The inventories are immutable, exact transaction-owned occurrences.
        # Replay each complete canonical inventory once before binding its site
        # rows; replaying it again for every row makes closure quadratic while
        # adding no intervening mutation or authority boundary.
        model.validate_semantic_graph_inventory(source_inventory)
        model.validate_semantic_graph_inventory(projected_inventory)
        source_effect_coordinates = {
            id(row): _bind_effect_site_coordinate(
                source_inventory, row, _batch=publication_batch,
                _inventory_validated=True,
            )
            for row in source_inventory.effects
            if row.owner_serial in source_inventory.reachable_serials
        }
        projected_effect_coordinates = {
            id(row): _bind_effect_site_coordinate(
                projected_inventory, row, _batch=publication_batch,
                _inventory_validated=True,
            )
            for row in projected_inventory.effects
            if row.owner_serial in projected_inventory.reachable_serials
        }
        source_terminal_coordinates = {
            id(row): _bind_terminal_site_coordinate(
                source_inventory, row, _batch=publication_batch,
                _inventory_validated=True,
            )
            for row in source_inventory.terminals
            if row.owner_serial in source_inventory.reachable_serials
        }
        projected_terminal_coordinates = {
            id(row): _bind_terminal_site_coordinate(
                projected_inventory, row, _batch=publication_batch,
                _inventory_validated=True,
            )
            for row in projected_inventory.terminals
            if row.owner_serial in projected_inventory.reachable_serials
        }
        scalarized_coordinates = {
            id(item): _site_mint(model.ScalarizedInstructionCoordinate, {
                "owner": model.AnchoredBlockRef(item.projected_block.block_ref, item.projected_block.anchor_ea),
                "instruction_ordinal": item.projected_observation.ordinal,
                "instruction_ea": item.projected_observation.instruction_ea,
                "instruction_kind": InsnKind.MOV,
                "opcode": item.projected_observation.opcode,
                "raw_opcode": item.projected_observation.raw_opcode,
                "width": item.projected_observation.width,
                "display_text_digest": canonical_authority_id(("scalarized-display-text", item.projected_observation.display_text)),
            }, _batch=publication_batch)
            for item in draft.local_binding_drafts
        }
        exact_bindings = {}
        for item in draft.exact_binding_drafts:
            claim = item.claim
            relation_id = (
                item.relation_draft.relation.relation_id
                if hasattr(item.relation_draft, "relation") else item.relation_draft
            )
            exact_bindings[id(item)] = _site_binding_mint(model.ExactEffectBindingResult, {
                "authority_id": authority_id,
                "source_authority_id": source_authority.source_authority_id,
                "attempt_id": attempt_id,
                "phase": model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
                "claim": claim,
                "proof_id": claim.route_proof_ids[0],
                "supporting_route_relation_id": relation_id,
                "source_subject_ids": tuple(sorted({
                    claim.effect_subject.subject_id, claim.source_subject.subject_id,
                    claim.predicate_subject.subject_id, claim.selected_target_subject.subject_id,
                    claim.discarded_effect_subject.subject_id,
                })),
                "source_site": source_effect_coordinates[id(item.source_row)],
                "source_inventory_digest": source_inventory.inventory_digest,
                "projected_inventory_digest": projected_inventory.inventory_digest,
                "source_fingerprint": source_inventory.graph_fingerprint,
                "projected_fingerprint": projected_inventory.graph_fingerprint,
                "source_generation": source_inventory.generation,
                "projected_generation": projected_inventory.generation,
                "raw_effect_gate_fact_id": raw_effect_gate_fact.fact_id,
                "binding_result_id": "sha256:" + "0" * 64,
            }, "binding_result_id", _batch=publication_batch)
        alias_bindings = {}
        for item in draft.local_binding_drafts:
            claim = item.claim
            alias_bindings[id(item)] = _site_binding_mint(model.LocalAliasScalarizationBindingResult, {
                "authority_id": authority_id, "attempt_id": attempt_id,
                "phase": model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
                "claim": claim, "source_subject_id": claim.owner_subject.subject_id,
                "source_site": source_effect_coordinates[id(item.source_row)],
                "scalarized_site": scalarized_coordinates[id(item)],
                "patch_step_fact": item.patch_step_fact,
                "patch_step_fact_id": patch_step_fact_id(item.patch_step_fact),
                "source_inventory_digest": source_inventory.inventory_digest,
                "projected_inventory_digest": projected_inventory.inventory_digest,
                "source_fingerprint": source_inventory.graph_fingerprint,
                "projected_fingerprint": projected_inventory.graph_fingerprint,
                "source_generation": source_inventory.generation,
                "projected_generation": projected_inventory.generation,
                "binding_result_id": "sha256:" + "0" * 64,
            }, "binding_result_id", _batch=publication_batch)
        effect_results: list[model.ProjectedEffectSiteResult] = []
        result_by_disposition: dict[int, model.ProjectedEffectSiteResult] = {}
        for item in draft.effect_dispositions:
            exact_binding = exact_bindings.get(id(item.exact_binding)) if item.exact_binding is not None else None
            alias_binding = alias_bindings.get(id(item.local_binding)) if item.local_binding is not None else None
            source_site = (
                exact_binding.source_site if exact_binding is not None
                else alias_binding.source_site if alias_binding is not None
                else source_effect_coordinates[id(item.source_row)]
            )
            projected_site = (
                projected_effect_coordinates[id(item.projected_row)]
                if item.projected_row is not None else None
            )
            source_subject_id = (
                item.exact_binding.claim.effect_subject.subject_id
                if item.exact_binding is not None else
                getattr(item.source_subject, "subject_id", item.source_subject)
            )
            projected_subject_id = (
                getattr(item.projected_subject, "subject_id", item.projected_subject)
                if item.projected_subject is not None else None
            )
            support_claim = (
                item.exact_binding.claim.claim_id if item.outcome is model.ProjectedEffectSiteOutcome.EXACT_INFEASIBLE
                else item.local_binding.claim.claim_id if item.local_binding is not None else None
            )
            support_binding = (
                exact_binding.binding_result_id if item.outcome is model.ProjectedEffectSiteOutcome.EXACT_INFEASIBLE
                else alias_binding.binding_result_id if alias_binding is not None else None
            )
            latent = (
                exact_binding.binding_result_id
                if exact_binding is not None and item.outcome in {
                    model.ProjectedEffectSiteOutcome.PRESERVED,
                    model.ProjectedEffectSiteOutcome.RELATION_CLONED,
                } else None
            )
            row = _site_binding_mint(model.ProjectedEffectSiteResult, {
                "authority_id": authority_id, "attempt_id": attempt_id,
                "phase": model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
                "source_subject_id": source_subject_id, "source_site": source_site,
                "outcome": item.outcome, "projected_subject_id": projected_subject_id,
                "projected_site": projected_site,
                "scalarized_site": alias_binding.scalarized_site if alias_binding is not None else None,
                "lineage_kind": item.lineage,
                "relation_id": item.owner_mapping.relation_id if item.owner_mapping is not None and item.lineage is model.ProjectedSiteLineageKind.RELATION_CLONE else None,
                "supporting_claim_id": support_claim,
                "supporting_binding_result_id": support_binding,
                "latent_exact_binding_result_id": latent,
                "patch_step_index": item.local_binding.claim.step_index if item.local_binding is not None else None,
                "patch_step_digest": item.local_binding.claim.step_digest if item.local_binding is not None else None,
                "raw_effect_gate_fact_id": raw_effect_gate_fact.fact_id,
                "result_id": "sha256:" + "0" * 64,
            }, "result_id", _batch=publication_batch)
            effect_results.append(row)
            result_by_disposition[id(item)] = row
        terminal_results: list[model.ProjectedTerminalSiteResult] = []
        terminal_by_disposition: dict[int, model.ProjectedTerminalSiteResult] = {}
        for item in draft.terminal_dispositions:
            row = _site_binding_mint(model.ProjectedTerminalSiteResult, {
                "authority_id": authority_id, "attempt_id": attempt_id,
                "phase": model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
                "source_subject_id": getattr(item.source_subject, "subject_id", item.source_subject),
                "source_site": source_terminal_coordinates[id(item.source_row)],
                "outcome": item.outcome,
                "projected_subject_id": getattr(item.projected_subject, "subject_id", item.projected_subject),
                "projected_site": projected_terminal_coordinates[id(item.projected_row)],
                "lineage_kind": item.lineage,
                "relation_id": item.owner_mapping.relation_id if item.owner_mapping is not None and item.lineage is model.ProjectedSiteLineageKind.RELATION_CLONE else None,
                "result_id": "sha256:" + "0" * 64,
            }, "result_id", _batch=publication_batch)
            terminal_results.append(row)
            terminal_by_disposition[id(item)] = row
        effect_results = sorted(effect_results, key=lambda item: item.result_id)
        terminal_results = sorted(terminal_results, key=lambda item: item.result_id)
        # Several exact patch steps may realize the same canonical relation.
        # The phase result indexes relation authority, not step occurrences;
        # occurrence multiplicity remains in the realization rows below.
        relation_ids = tuple(sorted({
            item.relation.relation_id for item in drafts
        }))
        derived_id = derived_effect_gate_fact_id(raw_effect_gate_fact.fact_id, tuple(item.result_id for item in effect_results))
        site_phase = _site_binding_mint(model.ProjectedSemanticSitePhaseResult, {
            "authority_id": authority_id, "source_authority_id": source_authority.source_authority_id,
            "attempt_id": attempt_id, "phase": model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            "plan_id": plan.plan_id, "source_inventory_digest": source_inventory.inventory_digest,
            "projected_inventory_digest": projected_inventory.inventory_digest,
            "source_fingerprint": source_inventory.graph_fingerprint,
            "projected_fingerprint": projected_inventory.graph_fingerprint,
            "source_generation": source_inventory.generation, "projected_generation": projected_inventory.generation,
            "relation_ids": relation_ids, "raw_effect_gate_fact": raw_effect_gate_fact,
            "exact_effect_bindings": tuple(sorted(exact_bindings.values(), key=lambda item: item.binding_result_id)),
            "local_alias_bindings": tuple(sorted(alias_bindings.values(), key=lambda item: item.binding_result_id)),
            "effect_results": tuple(effect_results), "terminal_results": tuple(terminal_results),
            "derived_effect_gate_fact_id": derived_id, "result_id": "sha256:" + "0" * 64,
        }, "result_id", _batch=publication_batch)
        rows: list[object] = []
        for subset in draft.route_subsets:
            relation = subset.relation_draft.relation
            effect_ids = tuple(sorted(result_by_disposition[id(item)].result_id for item in subset.effect_dispositions))
            terminal_ids = tuple(sorted(terminal_by_disposition[id(item)].result_id for item in subset.terminal_dispositions))
            preservation = _site_binding_mint(model.ProjectedRouteSitePreservation, {
                "authority_id": authority_id, "attempt_id": attempt_id,
                "relation_id": relation.relation_id, "site_phase_result_id": site_phase.result_id,
                "effect_result_ids": effect_ids, "terminal_result_ids": terminal_ids,
                "preservation_id": "sha256:" + "0" * 64,
            }, "preservation_id", _batch=publication_batch)
            fact = subset.relation_draft.facts[0]
            rows.append(mint(model.ProjectedRouteRealizationRow, {
                "claim_id": subset.relation_draft.claim.claim_id,
                "proof_id": subset.relation_draft.proof_id,
                "route_subject_id": subset.relation_draft.route_subject_id,
                "relation": relation, "site_preservation": preservation,
                "plan_step_index": fact.step_index, "plan_step_type": subset.relation_draft.descriptor.step_kind,
                "plan_step_digest": fact.step_digest,
                "source_fingerprint": source_inventory.graph_fingerprint,
                "projected_fingerprint": projected_inventory.graph_fingerprint,
                "source_generation": source_inventory.generation, "projected_generation": projected_inventory.generation,
                "row_id": projected_route_realization_row_id((
                    subset.relation_draft.claim.claim_id, subset.relation_draft.proof_id,
                    subset.relation_draft.route_subject_id, relation, fact.step_index,
                    subset.relation_draft.descriptor.step_kind, fact.step_digest,
                    source_inventory.graph_fingerprint, projected_inventory.graph_fingerprint,
                    source_inventory.generation, projected_inventory.generation, preservation,
                )),
            }, "row_id", _batch=publication_batch))
        rows_tuple = tuple(sorted(rows, key=lambda item: item.row_id))
        realization = mint(model.ProjectedRouteRealization, {
            "source_authority": source_authority, "attempt_id": attempt_id, "plan_id": plan.plan_id,
            "rows": rows_tuple, "site_phase_result": site_phase,
            "projected_inventory_digest": projected_inventory.inventory_digest,
            "projected_fingerprint": projected_inventory.graph_fingerprint,
            "projected_generation": projected_inventory.generation,
            "realization_id": projected_route_realization_id((
                source_authority.source_authority_id, attempt_id, plan.plan_id, rows_tuple,
                projected_inventory.inventory_digest, projected_inventory.graph_fingerprint,
                projected_inventory.generation, site_phase,
            )),
        }, "realization_id", _batch=publication_batch)
        accepted = result(
            model.ProjectedRouteRealizationAccepted,
            {"realization": realization}, _batch=publication_batch,
        )
        publication_batch.commit()
        return accepted

    def _close_projected_route_and_sites(
        *, authority_id: str, source_authority: model.SourceBoundRouteAuthority,
        plan: PatchPlan, source_inventory: model.SemanticGraphInventory,
        projected_inventory: model.SemanticGraphInventory,
        claims: tuple[object, ...], patch_step_facts: tuple[model.PatchStepEvidencePayload, ...],
        raw_effect_gate_fact: model.RawEffectGatePhaseFact,
        legacy_effective_gate_facts: object, attempt_id: TransactionAttemptId,
        drafts: tuple[object, ...], owner_index: object,
        route_publications: tuple[tuple[object, str], ...],
        claim_inventory: _TransactionProjectedClaimInventory | None = None,
    ) -> model.ProjectedRouteRealizationResult:
        """Close structural relations and every projected semantic site atomically."""
        if claim_inventory is not None:
            require_registered_transaction_projected_claim_inventory(
                claim_inventory,
            )
        site_draft = _draft_projected_site_closure(
            authority_id=authority_id, source_authority=source_authority, plan=plan,
            source_inventory=source_inventory, projected_inventory=projected_inventory,
            claims=claims, patch_step_facts=patch_step_facts,
            raw_effect_gate_fact=raw_effect_gate_fact,
            legacy_effective_gate_facts=legacy_effective_gate_facts,
            attempt_id=attempt_id, drafts=drafts, owner_index=owner_index,
        )
        _validate_projected_site_closure_draft(
            site_draft, source_authority=source_authority, plan=plan,
            source_inventory=source_inventory, projected_inventory=projected_inventory,
            claims=claims, patch_step_facts=patch_step_facts,
            raw_effect_gate_fact=raw_effect_gate_fact,
            legacy_effective_gate_facts=legacy_effective_gate_facts,
            attempt_id=attempt_id, drafts=drafts, owner_index=owner_index,
            route_publications=route_publications,
        )
        if claim_inventory is not None:
            require_registered_transaction_projected_claim_inventory(
                claim_inventory,
            )
        return _mint_projected_site_closure(
            draft=site_draft, authority_id=authority_id,
            source_authority=source_authority, plan=plan,
            source_inventory=source_inventory, projected_inventory=projected_inventory,
            raw_effect_gate_fact=raw_effect_gate_fact,
            legacy_effective_gate_facts=legacy_effective_gate_facts,
            attempt_id=attempt_id, drafts=drafts, owner_index=owner_index,
            route_publications=route_publications,
        )
    source_inventory_pairs: dict[int, tuple[weakref.ReferenceType[object], object]] = {}

    def register_source_inventory_pair(
        authority: model.SourceBoundRouteAuthority,
        inventory: model.SemanticGraphInventory,
    ) -> None:
        key = id(authority)

        def cleanup(reference: weakref.ReferenceType[object]) -> None:
            row = source_inventory_pairs.get(key)
            if row is not None and row[0] is reference:
                source_inventory_pairs.pop(key, None)

        source_inventory_pairs[key] = (weakref.ref(authority, cleanup), inventory)

    def require_source_inventory_pair(
        authority: object, inventory: object,
    ) -> None:
        if type(authority) is not model.SourceBoundRouteAuthority:
            raise TypeError("projected route requires a registered source authority")
        row = source_inventory_pairs.get(id(authority))
        if row is None or row[0]() is not authority:
            raise ValueError("source authority is not paired with a source inventory")
        if row[1] is not inventory:
            raise ValueError("source inventory is not the authority-paired occurrence")

    projected_claim_inventories: dict[
        int,
        tuple[
            weakref.ReferenceType[_TransactionProjectedClaimInventory],
            tuple[object, ...],
        ],
    ] = {}

    def projected_claim_inventory_token(
        value: _TransactionProjectedClaimInventory,
    ) -> tuple[object, ...]:
        return (
            id(value.derived), id(value.source_authority),
            id(value.attempt_id), id(value.projected_inventory),
        )

    def validate_transaction_projected_claim_inventory_fields(
        value: _TransactionProjectedClaimInventory,
    ) -> None:
        if type(value) is not _TransactionProjectedClaimInventory:
            raise TypeError("projected transaction claims require the exact private inventory")
        _validate_derived_transaction_claim_inventory(value.derived)
        derived = value.derived
        authority = value.source_authority
        attempt = value.attempt_id
        projected_inventory = value.projected_inventory
        if type(authority) is not model.SourceBoundRouteAuthority:
            raise TypeError("projected transaction inventory requires source authority")
        require_source_inventory_pair(authority, derived.source_inventory)
        validate_route(authority, "source_authority_id")
        if (
            authority.proposal is not derived.proposal
            or authority.plan_id != derived.plan.plan_id
            or authority.source_inventory_digest != derived.source_inventory.inventory_digest
            or authority.source_fingerprint != derived.source_inventory.graph_fingerprint
            or authority.source_generation != derived.source_inventory.generation
        ):
            raise ValueError("projected transaction source authority differs")
        if type(attempt) is not TransactionAttemptId:
            raise TypeError("projected transaction inventory requires exact attempt")
        attempt.__post_init__()
        if (
            attempt.plan_id != derived.plan.plan_id
            or attempt.generation != derived.source_inventory.generation
        ):
            raise ValueError("projected transaction attempt differs")
        if type(projected_inventory) is not model.SemanticGraphInventory:
            raise TypeError("projected transaction inventory is not closed")
        model.validate_semantic_graph_inventory(projected_inventory)
        if (
            projected_inventory.phase
            is not model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT
            or projected_inventory.generation != attempt.generation
            or projected_inventory.function_ea != derived.source_inventory.function_ea
            or projected_inventory.source_subject_ids
            != derived.source_inventory.source_subject_ids
        ):
            raise ValueError("projected transaction inventory coordinates differ")

    def bind_transaction_projected_claim_inventory(
        *, derived: _DerivedTransactionClaimInventory,
        source_authority: model.SourceBoundRouteAuthority,
        attempt_id: TransactionAttemptId,
        projected_inventory: model.SemanticGraphInventory,
    ) -> _TransactionProjectedClaimInventory:
        value = object.__new__(_TransactionProjectedClaimInventory)
        object.__setattr__(value, "derived", derived)
        object.__setattr__(value, "source_authority", source_authority)
        object.__setattr__(value, "attempt_id", attempt_id)
        object.__setattr__(value, "projected_inventory", projected_inventory)
        validate_transaction_projected_claim_inventory_fields(value)
        key = id(value)
        token = projected_claim_inventory_token(value)

        def cleanup(
            reference: weakref.ReferenceType[_TransactionProjectedClaimInventory],
        ) -> None:
            with _REGISTRY_PUBLICATION_LOCK:
                row = projected_claim_inventories.get(key)
                if row is not None and row[0] is reference:
                    projected_claim_inventories.pop(key, None)

        with _REGISTRY_PUBLICATION_LOCK:
            projected_claim_inventories[key] = (weakref.ref(value, cleanup), token)
        return value

    def require_registered_transaction_projected_claim_inventory(
        value: _TransactionProjectedClaimInventory,
    ) -> None:
        if type(value) is not _TransactionProjectedClaimInventory:
            raise TypeError("projected transaction claims require the exact private inventory")
        with _REGISTRY_PUBLICATION_LOCK:
            row = projected_claim_inventories.get(id(value))
            if row is None or row[0]() is not value:
                raise ValueError("projected transaction inventory is not binder-owned")
            if row[1] != projected_claim_inventory_token(value):
                raise ValueError("projected transaction inventory occurrence drifted")

    def validate_transaction_projected_claim_inventory(
        value: _TransactionProjectedClaimInventory,
    ) -> None:
        validate_transaction_projected_claim_inventory_fields(value)
        require_registered_transaction_projected_claim_inventory(value)

    def source(*, proposal, source_inventory, source_materialization):
        bound = source_impl(
            proposal=proposal,
            source_inventory=source_inventory,
            source_materialization=source_materialization,
            _mint=mint,
            _failure=failure,
            _result=result,
        )
        if type(bound) is model.SourceBoundRouteAuthorityAccepted:
            register_source_inventory_pair(bound.authority, source_inventory)
        return bound

    def projected_draft_rejection(exc: BaseException, source_authority: object):
        draft = getattr(exc, "draft", None)
        claim = getattr(draft, "claim", None)
        fact = draft.facts[0] if draft is not None and draft.facts else None
        descriptor = getattr(draft, "descriptor", None)
        logger.warning(
            "projected route draft rejected: claim=%s proof=%s step=%s reason=%s",
            None if claim is None else claim.claim_id,
            getattr(draft, "proof_id", None),
            None if descriptor is None else descriptor.step_index,
            exc,
        )
        rejected = failure(**_route_failure_coordinates(
            source_authority.proposal
            if type(source_authority) is model.SourceBoundRouteAuthority else None,
            stage=model.RouteRealizationFailureStage.CLAIM_SELECTION,
            claim=claim,
            fact=fact,
            descriptor=descriptor,
        ))
        return result(
            model.ProjectedRouteRealizationRejected,
            {"failures": (rejected,)},
        )

    def realize_from_claim_inventory(
        *, authority_id, claim_inventory, raw_effect_gate_fact,
        legacy_effective_gate_facts, entry_liveness_receipts=(),
    ):
        require_registered_transaction_projected_claim_inventory(
            claim_inventory,
        )
        derived = claim_inventory.derived
        source_authority = claim_inventory.source_authority
        plan = derived.plan
        source_inventory = derived.source_inventory
        projected_inventory = claim_inventory.projected_inventory
        claims = derived.claims
        patch_step_facts = derived.patch_step_facts
        attempt_id = claim_inventory.attempt_id

        def reject_input(stage=model.RouteRealizationFailureStage.ATTEMPT_BINDING):
            rejected = failure(**_route_failure_coordinates(
                source_authority.proposal
                if type(source_authority) is model.SourceBoundRouteAuthority else None,
                stage=stage,
            ))
            return result(model.ProjectedRouteRealizationRejected, {"failures": (rejected,)})

        # The closure is transaction-bound: every scalar input must be the
        # canonical occurrence selected by the source authority/attempt, and
        # the supplied authority ID is only an equality check against the
        # recomputed envelope ID.
        if type(source_authority) is not model.SourceBoundRouteAuthority:
            return reject_input(model.RouteRealizationFailureStage.SOURCE_AUTHORITY)
        if type(plan) is not PatchPlan or plan.unflatten_proposal is not source_authority.proposal:
            return reject_input()
        if type(claims) is not tuple:
            return reject_input()
        if type(patch_step_facts) is not tuple:
            return reject_input()
        if type(entry_liveness_receipts) is not tuple:
            return reject_input()
        if type(raw_effect_gate_fact) is not model.RawEffectGatePhaseFact:
            return reject_input(model.RouteRealizationFailureStage.EFFECT_TERMINAL_PRESERVATION)
        try:
            _validate_registered_site(raw_effect_gate_fact)
            if (
                raw_effect_gate_fact.source_inventory_digest != source_inventory.inventory_digest
                or raw_effect_gate_fact.projected_inventory_digest != projected_inventory.inventory_digest
                or raw_effect_gate_fact.source_fingerprint != source_inventory.graph_fingerprint
                or raw_effect_gate_fact.projected_fingerprint != projected_inventory.graph_fingerprint
                or raw_effect_gate_fact.source_generation != source_inventory.generation
                or raw_effect_gate_fact.projected_generation != projected_inventory.generation
            ):
                return reject_input(model.RouteRealizationFailureStage.EFFECT_TERMINAL_PRESERVATION)
            expected_authority_id = projected_authority_id(
                attempt_id=attempt_id,
                proposal_id=source_authority.proposal_id,
                source_authority_id=source_authority.source_authority_id,
                plan_id=plan.plan_id,
                claims=claims,
                patch_step_facts=patch_step_facts,
                source_inventory=source_inventory,
                projected_inventory=projected_inventory,
                raw_effect_gate_fact=raw_effect_gate_fact,
                entry_liveness_receipts=entry_liveness_receipts,
            )
        except (TypeError, ValueError):
            return reject_input()
        if authority_id != expected_authority_id:
            return reject_input()
        if type(legacy_effective_gate_facts) is not GenericEffectfulGateFacts:
            return reject_input(model.RouteRealizationFailureStage.EFFECT_TERMINAL_PRESERVATION)
        try:
            require_source_inventory_pair(source_authority, source_inventory)
        except (TypeError, ValueError):
            stage = (
                model.RouteRealizationFailureStage.SOURCE_AUTHORITY
                if type(source_authority) is not model.SourceBoundRouteAuthority
                or source_inventory_pairs.get(id(source_authority)) is None
                else model.RouteRealizationFailureStage.ATTEMPT_BINDING
            )
            rejected = failure(**_route_failure_coordinates(
                source_authority.proposal
                if type(source_authority) is model.SourceBoundRouteAuthority else None,
                stage=stage,
            ))
            return result(
                model.ProjectedRouteRealizationRejected,
                {"failures": (rejected,)},
            )
        kwargs = dict(
            source_authority=source_authority,
            plan=plan,
            source_inventory=source_inventory,
            projected_inventory=projected_inventory,
            patch_step_facts=derived.route_patch_step_facts,
            attempt_id=attempt_id,
            entry_liveness_receipts=entry_liveness_receipts,
            _mint=mint,
            _failure=failure,
            _result=result,
            _validate=validate_route,
        )
        validate_transaction_projected_claim_inventory(claim_inventory)
        try:
            structural, drafts, _owner_index, route_publications = (
                _draft_projected_route_relations(**kwargs)
            )
        except (TypeError, ValueError) as exc:
            return projected_draft_rejection(exc, source_authority)
        if type(structural) is model.ProjectedRouteRealizationRejected:
            validate_result(structural, model.ProjectedRouteRealizationRejected)
            return structural
        try:
            finalized = _close_projected_route_and_sites(
                authority_id=authority_id, source_authority=source_authority,
                plan=plan, source_inventory=source_inventory,
                projected_inventory=projected_inventory, claims=claims,
                patch_step_facts=patch_step_facts,
                raw_effect_gate_fact=raw_effect_gate_fact,
                legacy_effective_gate_facts=legacy_effective_gate_facts,
                attempt_id=attempt_id, drafts=drafts, owner_index=_owner_index,
                route_publications=route_publications,
                claim_inventory=claim_inventory,
            )
            if type(finalized) is model.ProjectedRouteRealizationAccepted:
                validate_result(finalized, model.ProjectedRouteRealizationAccepted)
            elif type(finalized) is model.ProjectedRouteRealizationRejected:
                validate_result(finalized, model.ProjectedRouteRealizationRejected)
            else:
                raise TypeError("projected route finalizer returned an unexpected result")
            return finalized
        except _ProjectedSiteDraftViolation as exc:
            logger.warning(
                "projected semantic-site closure rejected: reason=%s scope=%s "
                "claim=%s step=%s source=%s projected=%s",
                exc.reason_code,
                getattr(exc.scope, "value", exc.scope),
                None if exc.claim is None else getattr(exc.claim, "claim_id", None),
                None
                if exc.patch_step_fact is None
                else exc.patch_step_fact.step_index,
                None
                if exc.source_row is None
                else (exc.source_row.owner_serial, exc.source_row.owner_anchor_ea),
                None
                if exc.projected_row is None
                else (exc.projected_row.owner_serial, exc.projected_row.owner_anchor_ea),
            )
            coordinates = _translate_projected_site_draft_violation(exc)
            failure_value = failure(**_route_failure_coordinates(
                source_authority.proposal
                if type(source_authority) is model.SourceBoundRouteAuthority else None,
                **coordinates,
            ))
            return result(
                model.ProjectedRouteRealizationRejected,
                {"failures": (failure_value,)},
            )
        except (TypeError, ValueError) as exc:
            logger.warning(
                "projected semantic-site finalization failed: %s: %s",
                type(exc).__name__,
                exc,
            )
            failure_value = failure(**_route_failure_coordinates(
                source_authority.proposal,
                stage=model.RouteRealizationFailureStage.EFFECT_TERMINAL_PRESERVATION,
            ))
            return result(
                model.ProjectedRouteRealizationRejected,
                {"failures": (failure_value,)},
            )

    def projected(*, authority_id, source_authority, plan, source_inventory,
                  projected_inventory, claims, patch_step_facts, raw_effect_gate_fact,
                  legacy_effective_gate_facts, attempt_id):
        def reject_input(stage=model.RouteRealizationFailureStage.ATTEMPT_BINDING):
            rejected = failure(**_route_failure_coordinates(
                source_authority.proposal
                if type(source_authority) is model.SourceBoundRouteAuthority else None,
                stage=stage,
            ))
            return result(
                model.ProjectedRouteRealizationRejected,
                {"failures": (rejected,)},
            )

        if (
            type(source_authority) is not model.SourceBoundRouteAuthority
            or type(plan) is not PatchPlan
            or plan.unflatten_proposal is not source_authority.proposal
            or type(claims) is not tuple
            or claims is not source_authority.proposal.claims
            or type(patch_step_facts) is not tuple
        ):
            return reject_input()
        try:
            derived = _mint_derived_transaction_claim_inventory(
                proposal=source_authority.proposal,
                plan=plan,
                source_inventory=source_inventory,
                proposal_claims=source_authority.proposal.claims,
                local_alias_occurrences=(),
                claims=source_authority.proposal.claims,
                route_patch_step_facts=patch_step_facts,
                local_patch_step_facts=(),
                patch_step_facts=patch_step_facts,
                legacy_conditional_relations=(),
            )
            inventory = bind_transaction_projected_claim_inventory(
                derived=derived,
                source_authority=source_authority,
                attempt_id=attempt_id,
                projected_inventory=projected_inventory,
            )
            return realize_from_claim_inventory(
                authority_id=authority_id,
                claim_inventory=inventory,
                raw_effect_gate_fact=raw_effect_gate_fact,
                legacy_effective_gate_facts=legacy_effective_gate_facts,
            )
        except (TypeError, ValueError):
            return reject_input()

    def validate_source(value):
        validate_route(value, "source_authority_id")

    def validate_projected(value):
        validate_route(value, "realization_id")

    def validate_source_result(value):
        if type(value) is model.SourceBoundRouteAuthorityAccepted:
            validate_result(value, model.SourceBoundRouteAuthorityAccepted)
        elif type(value) is model.SourceBoundRouteAuthorityRejected:
            validate_result(value, model.SourceBoundRouteAuthorityRejected)
        else:
            raise TypeError("source result has an unexpected closed type")

    def validate_projected_result(value):
        if type(value) is model.ProjectedRouteRealizationAccepted:
            validate_result(value, model.ProjectedRouteRealizationAccepted)
        elif type(value) is model.ProjectedRouteRealizationRejected:
            validate_result(value, model.ProjectedRouteRealizationRejected)
        else:
            raise TypeError("projected result has an unexpected closed type")

    return (
        source, projected,
        bind_transaction_projected_claim_inventory,
        validate_transaction_projected_claim_inventory,
        realize_from_claim_inventory,
        validate_source, validate_projected,
        validate_source_result, validate_projected_result,
    )


(
    bind_source_route_authority, realize_projected_routes,
    _bind_transaction_projected_claim_inventory,
    _validate_transaction_projected_claim_inventory,
    _realize_projected_routes_from_claim_inventory,
    validate_source_route_authority, validate_projected_route_realization,
    validate_source_route_authority_result, validate_projected_route_realization_result,
) = _make_route_kernels()
for _kernel_name in (
    "_make_route_kernels", "_bind_source_route_authority",
    "_legacy_structural_projected_routes",
    "_route_mint", "_route_failure",
    "_route_result", "_ROUTE_REGISTRY", "_route_content_seal",
    "_register_route", "_validate_registered_route", "_validate_registered_result",
):
    globals().pop(_kernel_name, None)


from .proposal import retirement_member_catalog, _validated_terminal_route_claim


def _canonical_digest(value: object, label: str) -> None:
    if (
        type(value) is not str
        or len(value) != 71
        or not value.startswith("sha256:")
        or any(char not in "0123456789abcdef" for char in value[7:])
    ):
        raise ValueError(f"{label} must be a canonical sha256 ID")


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class RetiredInfrastructureBindingResult:
    """Bound retirement members, including exact retained-member rows."""

    claim: model.RetiredDispatcherInfrastructureClaim
    proposal: model.ProposedUnflattenContract
    source_inventory: model.SemanticGraphInventory
    projected_inventory: model.SemanticGraphInventory
    source_catalog: model.SourceIdentityCatalog
    member_catalog: tuple[model.RetirementPlanMember, ...]
    source_bindings: tuple[model.PhaseSubjectBinding, ...]
    projected_bindings: tuple[model.PhaseSubjectBinding, ...]
    generation: int
    phase_result: model.RetirementPhaseResult | None = None
    _content_seal: str = field(init=False, repr=False, compare=False)

    def __new__(cls, *args: object, **kwargs: object):
        raise TypeError("RetiredInfrastructureBindingResult can only be minted by bind_retired_dispatcher_infrastructure_claim")

    @property
    def claim_id(self) -> str:
        return self.claim.claim_id

    def _validate_fields(self) -> None:
        if type(self.claim) is not model.RetiredDispatcherInfrastructureClaim:
            raise TypeError("claim must be a closed retirement claim")
        if type(self.proposal) is not model.ProposedUnflattenContract:
            raise TypeError("proposal must be a closed proposal")
        if type(self.source_inventory) is not model.SemanticGraphInventory:
            raise TypeError("source_inventory must be a closed semantic inventory")
        if type(self.projected_inventory) is not model.SemanticGraphInventory:
            raise TypeError("projected_inventory must be a closed semantic inventory")
        if type(self.phase_result) is not model.RetirementPhaseResult:
            raise TypeError("phase_result must be a sealed RetirementPhaseResult")
        self.phase_result.__post_init__()
        if (
            self.phase_result.claim_id != self.claim.claim_id
            or self.phase_result.phase is not self.projected_inventory.phase
            or self.phase_result.catalog_id != getattr(self.proposal.retirement_candidate_catalog, "catalog_id", None)
            or self.phase_result.source_fingerprint != self.source_inventory.graph_fingerprint
            or self.phase_result.candidate_fingerprint != self.projected_inventory.graph_fingerprint
        ):
            raise ValueError("retirement phase result is foreign to binding")
        phase_by_ref = {
            member.block_ref: member for member in self.phase_result.members
        }
        if set(phase_by_ref) != set(
            self.proposal.retirement_candidate_catalog.member_refs
        ):
            raise ValueError("retirement phase result does not cover exact plan membership")
        model.validate_semantic_graph_inventory(self.source_inventory)
        model.validate_semantic_graph_inventory(self.projected_inventory)
        if self.source_inventory.phase is not model.UnflattenAuthorityPhase.PRODUCER_FORECAST:
            raise ValueError("retirement source inventory must be producer forecast")
        if self.projected_inventory.phase is not model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT:
            raise ValueError("retirement projected inventory must be projected preflight")
        if self.source_inventory.generation != self.generation:
            raise ValueError("retirement source inventory generation is stale")
        validate_canonical_roundtrip(self.claim, model.RetiredDispatcherInfrastructureClaim)
        validate_canonical_roundtrip(self.proposal, model.ProposedUnflattenContract)
        validate_canonical_roundtrip(self.source_catalog, model.SourceIdentityCatalog)
        if self.claim not in self.proposal.claims:
            raise ValueError("retirement claim is foreign to the proposal")
        if self.generation != self.source_catalog.generation:
            raise ValueError("retirement binding generation is stale")
        expected = retirement_member_catalog(self.proposal, self.claim)
        if tuple(self.member_catalog) != expected:
            raise ValueError("retirement member catalog drifted after bind")
        rows_by_ref = {row.block_ref: row for row in expected}
        expected_subjects = {
            item.block_ref: item for item in self.claim.member_subjects
        }
        expected_ids = {
            expected_subjects.get(ref, _subject_factory(
                model.SemanticSubjectRef,
                kind=model.SemanticSubjectKind.BLOCK,
                role=model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE,
                block_ref=ref,
                anchor_ea=row.anchor_ea,
                locator=model.BlockSubjectLocator(ref, row.anchor_ea),
            )).subject_id
            for ref, row in rows_by_ref.items()
        }
        source_by_id = {item.subject.subject_id: item for item in self.source_bindings}
        projected_by_id = {item.subject.subject_id: item for item in self.projected_bindings}
        inventory_source_by_id = {
            item.subject.subject_id: item
            for item in self.source_inventory.bindings
            if item.subject.subject_id in expected_ids
        }
        inventory_projected_by_id = {
            item.subject.subject_id: item
            for item in self.projected_inventory.bindings
            if item.subject.subject_id in expected_ids
        }
        if (
            set(source_by_id) != set(inventory_source_by_id)
            or any(
                source_by_id[subject_id] is not inventory_source_by_id[subject_id]
                for subject_id in source_by_id
            )
        ):
            raise ValueError("retirement source bindings are not carried by source inventory")
        if (
            set(projected_by_id) != set(inventory_projected_by_id)
            or any(
                projected_by_id[subject_id]
                is not inventory_projected_by_id[subject_id]
                for subject_id in projected_by_id
            )
        ):
            raise ValueError("retirement projected bindings are not carried by projected inventory")
        if set(source_by_id) != expected_ids or set(projected_by_id) != expected_ids:
            raise ValueError("retirement binding rows do not cover the exact member catalog")
        expected_order = tuple(sorted(expected_ids))
        if (
            tuple(item.subject.subject_id for item in self.source_bindings) != expected_order
            or tuple(item.subject.subject_id for item in self.projected_bindings) != expected_order
        ):
            raise ValueError("retirement binding rows must preserve canonical subject order")
        if any(
            phase_by_ref[ref].source_binding
            is not source_by_id.get(phase_by_ref[ref].source_binding.subject.subject_id)
            or phase_by_ref[ref].candidate_binding
            is not projected_by_id.get(phase_by_ref[ref].candidate_binding.subject.subject_id)
            for ref in phase_by_ref
        ):
            raise ValueError("retirement phase result bindings differ from binder rows")
        native_by_ref = {
            member.block_ref: member.native_instruction_eas
            for member in self.proposal.retirement_candidate_catalog.plan_members
        }
        for ref, row in rows_by_ref.items():
            subject = expected_subjects.get(ref, _subject_factory(
                model.SemanticSubjectRef,
                kind=model.SemanticSubjectKind.BLOCK,
                role=model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE,
                block_ref=ref,
                anchor_ea=row.anchor_ea,
                locator=model.BlockSubjectLocator(ref, row.anchor_ea),
            ))
            source = source_by_id[subject.subject_id]
            projected = projected_by_id[subject.subject_id]
            if (
                source.subject != subject
                or
                source.status is not model.SubjectBindingStatus.UNIQUE
                or source.phase is not model.UnflattenAuthorityPhase.PRODUCER_FORECAST
                or source.block_ref != ref
                or source.anchor_ea != row.anchor_ea
                or tuple(source.native_instruction_eas) != tuple(native_by_ref[ref])
                or source.generation != self.proposal.retirement_candidate_catalog.source_generation
            ):
                raise ValueError("retirement source binding is not catalog-bound")
            if (
                projected.subject != subject
                or projected.phase is not model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT
                or projected.generation != self.projected_inventory.generation
            ):
                raise ValueError("projected retirement binding is not catalog-bound")
            if projected.status is model.SubjectBindingStatus.MISSING:
                if (
                    projected.block_ref is not None
                    or projected.serial is not None
                    or projected.anchor_ea is not None
                    or projected.native_instruction_eas
                ):
                    raise ValueError("missing projected binding carries stale identity")
                continue
            if projected.status in {
                model.SubjectBindingStatus.AMBIGUOUS,
                model.SubjectBindingStatus.STALE_GENERATION,
            }:
                continue
            if projected.status is not model.SubjectBindingStatus.UNIQUE:
                raise ValueError("projected retirement binding has an unsupported status")
            if (
                projected.block_ref != ref
                or projected.anchor_ea != row.anchor_ea
                or tuple(projected.native_instruction_eas) != tuple(native_by_ref[ref])
            ):
                raise ValueError("retained projected binding drifted from catalog")
            if projected.serial is None:
                raise ValueError("projected retirement binding has no serial")
            phase_member = phase_by_ref[ref]
            expected_reachable = projected.serial in self.projected_inventory.reachable_serials
            if phase_member.candidate_reachable is not expected_reachable:
                raise ValueError("retirement phase reachability drifted from projected inventory")


def _build_retirement_phase_result(
    *,
    claim: model.RetiredDispatcherInfrastructureClaim,
    proposal: model.ProposedUnflattenContract,
    source_inventory: model.SemanticGraphInventory,
    projected_inventory: model.SemanticGraphInventory,
    phase: model.UnflattenAuthorityPhase,
) -> model.RetirementPhaseResult:
    """Mint the sole exact retirement partition for one transaction phase."""
    catalog = proposal.retirement_candidate_catalog
    if type(catalog) is not model.RetirementCandidateCatalog:
        raise ValueError("retirement phase requires a candidate catalog")
    candidates = {item.block_ref: item for item in catalog.candidates}
    claim_subjects = {item.block_ref: item for item in claim.member_subjects}
    source_by_id = {item.subject.subject_id: item for item in source_inventory.bindings}
    candidate_by_id = {item.subject.subject_id: item for item in projected_inventory.bindings}
    rows = []
    for member in catalog.plan_members:
        subject = claim_subjects.get(member.block_ref, _subject_factory(
            model.SemanticSubjectRef,
            kind=model.SemanticSubjectKind.BLOCK,
            role=model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE,
            block_ref=member.block_ref,
            anchor_ea=member.anchor_ea,
            locator=model.BlockSubjectLocator(member.block_ref, member.anchor_ea),
        ))
        source = source_by_id.get(subject.subject_id)
        candidate = candidate_by_id.get(subject.subject_id)
        if source is None or candidate is None:
            raise ValueError("retirement inventories lack exact member bindings")
        eligible = candidates.get(member.block_ref)
        candidate_id = None if eligible is None else eligible.candidate_id
        if source is None or source.status is not model.SubjectBindingStatus.UNIQUE:
            classification = model.RetirementPhaseClassification.UNACCOUNTED
            reason = "source_binding_not_unique"
        elif candidate is None or candidate.status in {
            model.SubjectBindingStatus.AMBIGUOUS,
            model.SubjectBindingStatus.STALE_GENERATION,
        }:
            classification = model.RetirementPhaseClassification.DRIFTED
            reason = "candidate_identity_drift"
        elif candidate.status is model.SubjectBindingStatus.MISSING:
            classification = (
                model.RetirementPhaseClassification.RETIRED
                if eligible is not None else model.RetirementPhaseClassification.UNACCOUNTED
            )
            reason = "candidate_missing" if eligible is not None else "unsupported_missing_member"
        elif candidate.status is model.SubjectBindingStatus.UNIQUE and candidate.serial is not None:
            reachable = candidate.serial in projected_inventory.reachable_serials
            classification = (
                model.RetirementPhaseClassification.RETAINED
                if reachable else (
                    model.RetirementPhaseClassification.RETIRED
                    if eligible is not None else model.RetirementPhaseClassification.UNACCOUNTED
                )
            )
            reason = "candidate_reachable" if reachable else (
                "candidate_unreachable" if eligible is not None else "unsupported_unreachable_member"
            )
        else:
            classification = model.RetirementPhaseClassification.DRIFTED
            reason = "candidate_binding_invalid"
        phase_member = object.__new__(model.RetirementPhaseMember)
        for name, value in {
            "block_ref": member.block_ref,
            "anchor_ea": member.anchor_ea,
            "classification": classification,
            "candidate_id": candidate_id,
            "candidate_reachable": (
                candidate.serial in projected_inventory.reachable_serials
                if candidate.status is model.SubjectBindingStatus.UNIQUE
                and candidate.serial is not None
                else None
            ),
            "reason": reason,
            "source_binding": source,
            "candidate_binding": candidate,
        }.items():
            object.__setattr__(phase_member, name, value)
        phase_member.__post_init__()
        rows.append(phase_member)
    result_id = authority_id((
        "unflatten.dispatcher-retirement-phase.v1", catalog.catalog_id,
        claim.claim_id, phase, source_inventory.graph_fingerprint,
        projected_inventory.graph_fingerprint, source_inventory.generation,
        projected_inventory.generation, tuple(sorted(rows, key=canonical_bytes)),
    ))
    phase_result = object.__new__(model.RetirementPhaseResult)
    for name, value in {
        "result_id": result_id,
        "catalog_id": catalog.catalog_id,
        "claim_id": claim.claim_id,
        "phase": phase,
        "source_fingerprint": source_inventory.graph_fingerprint,
        "candidate_fingerprint": projected_inventory.graph_fingerprint,
        "source_generation": source_inventory.generation,
        "candidate_generation": projected_inventory.generation,
        "members": tuple(sorted(rows, key=canonical_bytes)),
    }.items():
        object.__setattr__(phase_result, name, value)
    phase_result.__post_init__()
    return phase_result


def _retirement_binding_seal(result: RetiredInfrastructureBindingResult) -> str:
    catalog_rows = tuple(
        (
            row.block_ref,
            row.anchor_ea,
            row.native_instruction_eas,
        )
        for row in result.member_catalog
    )
    return "sha256:" + hashlib.sha256(canonical_bytes((
        result.claim, result.proposal, result.source_inventory,
        result.projected_inventory, result.source_catalog,
        catalog_rows, result.source_bindings,
        result.projected_bindings, result.projected_inventory.reachable_serials,
        result.generation, result.phase_result,
    ))).hexdigest()


def terminal_cycle_binding_subjects(
    proposal: model.ProposedUnflattenContract,
    claim: model.TerminalCycleBreakClaim,
) -> tuple[model.SemanticSubjectRef, ...]:
    """Return the one closed subject set owned by a terminal-cycle claim."""

    if type(proposal) is not model.ProposedUnflattenContract:
        raise TypeError("terminal-cycle subjects require a closed proposal")
    if type(claim) is not model.TerminalCycleBreakClaim:
        raise TypeError("terminal-cycle subjects require a closed claim")
    if claim not in proposal.claims:
        raise ValueError("terminal-cycle claim is foreign to the proposal")
    cycle_locator = claim.cycle_subject.locator
    if type(cycle_locator) is not model.CorridorSubjectLocator:
        raise ValueError("terminal-cycle corridor binding is not closed")
    residue_refs = tuple(cycle_locator.member_refs)
    residue_anchors = tuple(cycle_locator.member_anchor_eas)
    if (
        not residue_refs
        or len(set(residue_refs)) != len(residue_refs)
        or len(residue_refs) != len(residue_anchors)
        or cycle_locator.entry_ref
        != proposal.plan_inputs.dispatcher_entry_ref
        or not set(residue_refs)
        <= set(proposal.plan_inputs.dispatcher_member_refs)
        or claim.cleanup_source_subject.block_ref not in set(residue_refs)
    ):
        raise ValueError("terminal-cycle residue is not an exact plan subset")
    catalog_by_ref = {
        item.block_ref: item for item in proposal.source_identity_catalog.blocks
    }
    residue_subjects: list[model.SemanticSubjectRef] = []
    for ref, anchor in zip(residue_refs, residue_anchors):
        witness = catalog_by_ref.get(ref)
        if witness is None or witness.anchor_ea != anchor:
            raise ValueError(
                "terminal-cycle residue member is foreign to the source catalog"
            )
        residue_subjects.append(
            claim.cleanup_source_subject
            if ref == claim.cleanup_source_subject.block_ref
            else _subject_factory(
                model.SemanticSubjectRef,
                kind=model.SemanticSubjectKind.BLOCK,
                role=model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE,
                block_ref=ref,
                anchor_ea=anchor,
                locator=model.BlockSubjectLocator(ref, anchor),
            )
        )
    cleanup = catalog_by_ref.get(claim.cleanup_source_subject.block_ref)
    terminal_locator = claim.terminal_subject.locator
    terminal = catalog_by_ref.get(claim.terminal_subject.block_ref)
    native_terminal_valid = (
        type(terminal_locator) is model.TerminalSubjectLocator
        and terminal is not None
        and terminal.anchor_ea == claim.terminal_subject.anchor_ea
        and terminal_locator.instruction_ea in terminal.native_instruction_eas
    )
    logical_terminal_valid = (
        type(terminal_locator) is model.LogicalFunctionExitSubjectLocator
        and type(claim.terminal_subject.block_ref) is LogicalBlockRef
        and terminal_locator.block_ref == claim.terminal_subject.block_ref
        and claim.terminal_subject.anchor_ea is None
    )
    if (
        cleanup is None
        or cleanup.anchor_ea != claim.cleanup_source_subject.anchor_ea
        or not (native_terminal_valid or logical_terminal_valid)
    ):
        raise ValueError("terminal-cycle endpoint is foreign to the source catalog")
    route_claim, route_proof = _validated_terminal_route_claim(
        proposal, proof_id=claim.terminal_route_proof_ids[0],
    )
    route_source_subject = route_claim.source_subject
    terminal_destination = tuple(route_proof.destinations)
    if len(terminal_destination) != 1:
        raise ValueError("terminal route proof must contain one terminal carrier destination")
    carrier_subject = _native_route_destination_subject_for_proof_destination(
        claim=route_claim,
        proof_destination=terminal_destination[0],
        catalog=proposal.source_identity_catalog,
    )
    if route_source_subject.block_ref == claim.cleanup_source_subject.block_ref:
        raise ValueError("terminal route source aliases the cleanup source")
    return tuple(
        sorted(
            {
                item.subject_id: item
                for item in (
                    claim.cycle_subject,
                    claim.cleanup_source_subject,
                    claim.terminal_subject,
                    route_source_subject,
                    carrier_subject,
                    *residue_subjects,
                )
            }.values(),
            key=lambda item: item.subject_id,
        )
    )


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class TerminalCycleBindingResult:
    """Exact source/projected binding for one terminal-cycle allowance."""

    claim: model.TerminalCycleBreakClaim
    proposal: model.ProposedUnflattenContract
    source_bindings: tuple[model.PhaseSubjectBinding, ...]
    projected_bindings: tuple[model.PhaseSubjectBinding, ...]
    residue_refs: tuple[object, ...]
    source_cycle_edges: tuple[tuple[object, object], ...]
    projected_cycle_edges: tuple[tuple[object, object], ...]
    terminal_route_refs: tuple[object, ...]
    generation: int
    projected_generation: int
    phase_result: model.TerminalCyclePhaseResult
    _content_seal: str = field(init=False, repr=False, compare=False)

    def __new__(cls, *args: object, **kwargs: object):
        raise TypeError("TerminalCycleBindingResult can only be minted by bind_terminal_cycle_break_claim")

    @property
    def claim_id(self) -> str:
        return self.claim.claim_id

    def _validate_fields(self) -> None:
        if type(self.claim) is not model.TerminalCycleBreakClaim:
            raise TypeError("claim must be a closed terminal-cycle claim")
        if type(self.proposal) is not model.ProposedUnflattenContract:
            raise TypeError("proposal must be a closed proposal")
        validate_canonical_roundtrip(self.claim, model.TerminalCycleBreakClaim)
        validate_canonical_roundtrip(self.proposal, model.ProposedUnflattenContract)
        if self.claim not in self.proposal.claims:
            raise ValueError("terminal-cycle claim is foreign to the proposal")
        if self.generation != self.proposal.source_identity_catalog.generation:
            raise ValueError("terminal-cycle binding generation is stale")
        if type(self.phase_result) is not model.TerminalCyclePhaseResult:
            raise TypeError("terminal-cycle binding must carry one closed phase result")
        self.phase_result.__post_init__()
        expected_subjects = terminal_cycle_binding_subjects(
            self.proposal, self.claim,
        )
        expected = {
            subject.subject_id: subject for subject in expected_subjects
        }
        cycle_locator = self.claim.cycle_subject.locator
        if tuple(self.residue_refs) != tuple(cycle_locator.member_refs):
            raise ValueError("terminal-cycle residue refs drifted from corridor locator")
        source = {item.subject.subject_id: item for item in self.source_bindings}
        projected = {item.subject.subject_id: item for item in self.projected_bindings}
        if set(source) != set(expected) or set(projected) != set(expected):
            raise ValueError("terminal-cycle bindings do not cover the exact claim subjects")
        expected_order = tuple(sorted(expected))
        if (
            tuple(item.subject.subject_id for item in self.source_bindings)
            != expected_order
            or tuple(item.subject.subject_id for item in self.projected_bindings)
            != expected_order
        ):
            raise ValueError("terminal-cycle bindings must preserve canonical subject order")
        catalog_by_ref = {
            item.block_ref: item
            for item in self.proposal.source_identity_catalog.blocks
        }
        for subject_id, subject in expected.items():
            source_row = source[subject_id]
            logical_exit = type(subject.locator) is model.LogicalFunctionExitSubjectLocator
            witness = catalog_by_ref.get(subject.block_ref)
            if (
                source_row.subject != subject
                or source_row.phase is not model.UnflattenAuthorityPhase.PRODUCER_FORECAST
                or source_row.status is not model.SubjectBindingStatus.UNIQUE
                or source_row.generation != self.generation
                or source_row.block_ref != subject.block_ref
                or source_row.anchor_ea != subject.anchor_ea
                or (
                    logical_exit
                    and (
                        source_row.serial != subject.locator.serial
                        or tuple(source_row.native_instruction_eas) != ()
                    )
                )
                or (
                    not logical_exit
                    and (
                        witness is None
                        or tuple(source_row.native_instruction_eas)
                        != tuple(witness.native_instruction_eas)
                    )
                )
            ):
                raise ValueError("terminal-cycle source binding is not catalog-bound")
            projected_row = projected[subject_id]
            if (
                projected_row.subject != subject
                or projected_row.phase is not model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT
                or projected_row.generation != self.projected_generation
            ):
                raise ValueError("terminal-cycle projected binding is not phase-bound")
            if subject is self.claim.terminal_subject:
                if (
                    projected_row.status is not model.SubjectBindingStatus.UNIQUE
                    or projected_row.block_ref != subject.block_ref
                    or projected_row.anchor_ea != subject.anchor_ea
                    or tuple(projected_row.native_instruction_eas)
                    != (() if logical_exit else tuple(witness.native_instruction_eas))
                ):
                    raise ValueError("terminal subject must remain projected-reachable by identity")
        if not _contains_directed_cycle(
            self.residue_refs, self.source_cycle_edges,
        ):
            raise ValueError("terminal-cycle source residue is not cyclic")
        if _contains_directed_cycle(
            self.residue_refs, self.projected_cycle_edges,
        ):
            raise ValueError("terminal-cycle residual cycle remains projected")
        carrier = next(
            subject for subject in expected_subjects
            if subject.role
            is model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION
        )
        if (
            not self.terminal_route_refs
            or self.terminal_route_refs[0] != carrier.block_ref
            or self.terminal_route_refs[-1]
            != self.claim.terminal_subject.block_ref
        ):
            raise ValueError(
                "terminal-cycle route does not join its carrier to its terminal"
            )
        phase_result = self.phase_result
        if (
            phase_result.claim_id != self.claim.claim_id
            or phase_result.terminal_route_proof_id
            != self.claim.terminal_route_proof_ids[0]
            or phase_result.source_bindings != self.source_bindings
            or phase_result.candidate_bindings != self.projected_bindings
            or phase_result.residue_refs != self.residue_refs
            or phase_result.source_cycle_edges != self.source_cycle_edges
            or phase_result.candidate_cycle_edges != self.projected_cycle_edges
            or phase_result.terminal_route_refs != self.terminal_route_refs
            or phase_result.source_generation != self.generation
            or phase_result.candidate_generation != self.projected_generation
        ):
            raise ValueError("terminal-cycle phase result drifted from binder facts")


def _terminal_cycle_binding_seal(result: TerminalCycleBindingResult) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes((
        result.claim, result.proposal, result.source_bindings,
        result.projected_bindings, result.residue_refs, result.generation,
        result.projected_generation, result.source_cycle_edges,
        result.projected_cycle_edges, result.terminal_route_refs,
        result.phase_result,
    ))).hexdigest()


def _contains_directed_cycle(
    member_refs: Sequence[object],
    edges: Sequence[tuple[object, object]],
) -> bool:
    members = set(member_refs)
    successors = {ref: set() for ref in members}
    for source_ref, target_ref in edges:
        if source_ref in members and target_ref in members:
            successors[source_ref].add(target_ref)
    active: set[object] = set()
    complete: set[object] = set()

    def visit(ref: object) -> bool:
        if ref in active:
            return True
        if ref in complete:
            return False
        active.add(ref)
        if any(visit(target) for target in successors[ref]):
            return True
        active.remove(ref)
        complete.add(ref)
        return False

    return any(visit(ref) for ref in tuple(members))


def _terminal_cycle_edges(
    inventory: model.SemanticGraphInventory,
    *,
    residue_subjects: Mapping[object, model.SemanticSubjectRef],
) -> tuple[tuple[object, object], ...]:
    bindings = {
        binding.subject.subject_id: binding for binding in inventory.bindings
    }
    ref_by_serial: dict[int, object] = {}
    for ref, subject in residue_subjects.items():
        binding = bindings.get(subject.subject_id)
        if (
            binding is not None
            and binding.status is model.SubjectBindingStatus.UNIQUE
        ):
            ref_by_serial[binding.serial] = ref
    edges = {
        (ref_by_serial[row.owner_serial], ref_by_serial[row.peer_serial])
        for row in inventory.topology
        if row.kind is model.TopologyIncidenceKind.SUCCESSOR
        and row.owner_serial in ref_by_serial
        and row.peer_serial in ref_by_serial
    }
    return tuple(
        sorted(
            edges,
            key=lambda edge: (
                model._structural_key(edge[0]),
                model._structural_key(edge[1]),
            ),
        )
    )


def _terminal_route_refs(
    inventory: model.SemanticGraphInventory,
    *,
    carrier_binding: model.PhaseSubjectBinding,
    terminal_binding: model.PhaseSubjectBinding,
) -> tuple[object, ...]:
    """Return one exact reachable one-way carrier-to-terminal corridor."""

    if (
        carrier_binding.status is not model.SubjectBindingStatus.UNIQUE
        or terminal_binding.status is not model.SubjectBindingStatus.UNIQUE
        or carrier_binding.serial is None
        or terminal_binding.serial is None
    ):
        raise ValueError("terminal carrier and terminal must bind uniquely")
    reachable = set(inventory.reachable_serials)
    if (
        carrier_binding.serial not in reachable
        or terminal_binding.serial not in reachable
    ):
        raise ValueError("terminal route endpoints must remain reachable")
    blocks = {block.serial: block for block in inventory.blocks}
    current = carrier_binding.serial
    terminal_serial = terminal_binding.serial
    seen: set[int] = set()
    route: list[object] = []
    while current not in seen:
        seen.add(current)
        block = blocks.get(current)
        if block is None or block.block_ref is None:
            raise ValueError("terminal route contains an unbound helper block")
        route.append(block.block_ref)
        successors = tuple(
            successor for successor in block.successor_serials
            if successor in reachable
        )
        if current == terminal_serial:
            if successors:
                raise ValueError("terminal route endpoint has a live successor")
            return tuple(route)
        if len(successors) != 1:
            raise ValueError("terminal route is not one exact one-way corridor")
        current = successors[0]
    raise ValueError("terminal route corridor is cyclic")


def _classify_terminal_cycle_break_claim(
    *,
    claim: model.TerminalCycleBreakClaim,
    proposal: model.ProposedUnflattenContract,
    source_inventory: model.SemanticGraphInventory,
    candidate_inventory: model.SemanticGraphInventory,
    phase: model.UnflattenAuthorityPhase,
) -> TerminalCycleBindingResult:
    """Bind one exact reachable cycle break from canonical phase inventories."""

    subjects = terminal_cycle_binding_subjects(proposal, claim)
    if type(source_inventory) is not model.SemanticGraphInventory:
        raise TypeError("terminal-cycle source inventory must be closed")
    if type(candidate_inventory) is not model.SemanticGraphInventory:
        raise TypeError("terminal-cycle candidate inventory must be closed")
    model.validate_semantic_graph_inventory(source_inventory)
    model.validate_semantic_graph_inventory(candidate_inventory)
    if (
        claim.source_generation != source_inventory.generation
        or source_inventory.generation
        != proposal.source_identity_catalog.generation
    ):
        raise ValueError("terminal-cycle claim and source catalog generations differ")
    if phase is not model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT:
        raise ValueError("terminal-cycle binding must be projected preflight")
    if (
        source_inventory.phase
        is not model.UnflattenAuthorityPhase.PRODUCER_FORECAST
        or candidate_inventory.phase is not phase
    ):
        raise ValueError("terminal-cycle inventories are bound to the wrong phase")
    cycle_locator = claim.cycle_subject.locator
    subject_ids = {subject.subject_id for subject in subjects}
    source_bindings = tuple(
        binding for binding in source_inventory.bindings
        if binding.subject.subject_id in subject_ids
    )
    projected_bindings = tuple(
        binding for binding in candidate_inventory.bindings
        if binding.subject.subject_id in subject_ids
    )
    residue_subjects = {
        subject.block_ref: subject
        for subject in subjects
        if subject.role is model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE
        and subject.block_ref in set(cycle_locator.member_refs)
    }
    if set(residue_subjects) != set(cycle_locator.member_refs):
        raise ValueError("terminal-cycle residue subjects are incomplete")
    source_cycle_edges = _terminal_cycle_edges(
        source_inventory, residue_subjects=residue_subjects,
    )
    projected_cycle_edges = _terminal_cycle_edges(
        candidate_inventory, residue_subjects=residue_subjects,
    )
    if _contains_directed_cycle(cycle_locator.member_refs, projected_cycle_edges):
        raise ValueError("terminal-cycle residual cycle remains projected")
    source_binding_by_id = {
        binding.subject.subject_id: binding for binding in source_bindings
    }
    source_entry_binding = source_binding_by_id[
        residue_subjects[cycle_locator.entry_ref].subject_id
    ]
    if (
        source_entry_binding.status is not model.SubjectBindingStatus.UNIQUE
        or source_entry_binding.serial
        not in set(source_inventory.reachable_serials)
    ):
        raise ValueError("terminal-cycle source residue is not source-reachable")
    terminal_binding = next(
        (
            binding for binding in projected_bindings
            if binding.subject == claim.terminal_subject
        ),
        None,
    )
    if (
        terminal_binding is None
        or terminal_binding.status is not model.SubjectBindingStatus.UNIQUE
        or terminal_binding.serial not in set(candidate_inventory.reachable_serials)
    ):
        raise ValueError("terminal subject is not candidate-reachable by identity")
    carrier_binding = next(
        (
            binding for binding in projected_bindings
            if binding.subject.role
            is model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION
        ),
        None,
    )
    if carrier_binding is None:
        raise ValueError("terminal route carrier binding is absent")
    route_source_binding = next(
        (
            binding for binding in projected_bindings
            if binding.subject.role
            is model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE
        ),
        None,
    )
    cleanup_binding = next(
        (
            binding for binding in projected_bindings
            if binding.subject == claim.cleanup_source_subject
        ),
        None,
    )
    if (
        route_source_binding is None
        or cleanup_binding is None
        or route_source_binding.status is not model.SubjectBindingStatus.UNIQUE
        or cleanup_binding.status is not model.SubjectBindingStatus.UNIQUE
        or carrier_binding.status is not model.SubjectBindingStatus.UNIQUE
        or route_source_binding.serial
        not in set(candidate_inventory.reachable_serials)
    ):
        raise ValueError(
            "terminal cycle redirects lack exact source, cleanup, or carrier bindings"
        )
    candidate_blocks = {
        block.serial: block for block in candidate_inventory.blocks
    }
    if (
        tuple(candidate_blocks[route_source_binding.serial].successor_serials)
        != (carrier_binding.serial,)
        or tuple(candidate_blocks[cleanup_binding.serial].successor_serials)
        != (carrier_binding.serial,)
    ):
        raise ValueError(
            "terminal source and cleanup do not converge on the exact carrier"
        )
    terminal_route_refs = _terminal_route_refs(
        candidate_inventory,
        carrier_binding=carrier_binding,
        terminal_binding=terminal_binding,
    )
    source_bindings = tuple(sorted(
        source_bindings, key=lambda item: item.subject.subject_id,
    ))
    projected_bindings = tuple(sorted(
        projected_bindings, key=lambda item: item.subject.subject_id,
    ))
    bound_subject_ids = tuple(
        binding.subject.subject_id for binding in source_bindings
    )
    phase_result_values = {
        "claim_id": claim.claim_id,
        "terminal_route_proof_id": claim.terminal_route_proof_ids[0],
        "phase": phase,
        "source_fingerprint": source_inventory.graph_fingerprint,
        "candidate_fingerprint": candidate_inventory.graph_fingerprint,
        "source_generation": source_inventory.generation,
        "candidate_generation": candidate_inventory.generation,
        "bound_subject_ids": bound_subject_ids,
        "source_binding_digest": authority_id(source_bindings),
        "candidate_binding_digest": authority_id(projected_bindings),
        "residue_refs": tuple(cycle_locator.member_refs),
        "source_cycle_edges": source_cycle_edges,
        "candidate_cycle_edges": projected_cycle_edges,
        "source_bindings": source_bindings,
        "candidate_bindings": projected_bindings,
        "terminal_source_ref": route_source_binding.block_ref,
        "cleanup_source_ref": cleanup_binding.block_ref,
        "terminal_carrier_ref": carrier_binding.block_ref,
        "terminal_route_refs": terminal_route_refs,
        "terminal_subject_id": claim.terminal_subject.subject_id,
        "terminal_subject_ref": terminal_binding.block_ref,
    }
    phase_result_id = authority_id((
        "unflatten.terminal-cycle-phase.v1",
        phase_result_values["claim_id"],
        phase_result_values["terminal_route_proof_id"],
        phase_result_values["phase"],
        phase_result_values["source_fingerprint"],
        phase_result_values["candidate_fingerprint"],
        phase_result_values["source_generation"],
        phase_result_values["candidate_generation"],
        phase_result_values["bound_subject_ids"],
        phase_result_values["source_binding_digest"],
        phase_result_values["candidate_binding_digest"],
        phase_result_values["residue_refs"],
        phase_result_values["source_cycle_edges"],
        phase_result_values["candidate_cycle_edges"],
        phase_result_values["terminal_source_ref"],
        phase_result_values["cleanup_source_ref"],
        phase_result_values["terminal_carrier_ref"],
        phase_result_values["terminal_route_refs"],
        phase_result_values["terminal_subject_id"],
        phase_result_values["terminal_subject_ref"],
    ))
    phase_result = model.TerminalCyclePhaseResult(
        result_id=phase_result_id, **phase_result_values,
    )
    result = object.__new__(TerminalCycleBindingResult)
    for name, value in {
        "claim": claim, "proposal": proposal,
        "source_bindings": source_bindings,
        "projected_bindings": projected_bindings,
        "residue_refs": tuple(cycle_locator.member_refs),
        "source_cycle_edges": source_cycle_edges,
        "projected_cycle_edges": projected_cycle_edges,
        "terminal_route_refs": terminal_route_refs,
        "generation": source_inventory.generation,
        "projected_generation": candidate_inventory.generation,
        "phase_result": phase_result,
    }.items():
        object.__setattr__(result, name, value)
    object.__setattr__(result, "_content_seal", _terminal_cycle_binding_seal(result))
    result._validate_fields()
    return result


def _validate_terminal_cycle_binding_result_fields(result: TerminalCycleBindingResult) -> None:
    if type(result) is not TerminalCycleBindingResult:
        raise TypeError("terminal-cycle result must be closed")
    if result._content_seal != _terminal_cycle_binding_seal(result):
        raise ValueError("terminal-cycle binding content seal does not match")
    result._validate_fields()


def _bind_terminal_cycle_break_claim(
    *,
    claim: model.TerminalCycleBreakClaim,
    proposal: model.ProposedUnflattenContract,
    source_inventory: model.SemanticGraphInventory,
    candidate_inventory: model.SemanticGraphInventory,
    phase: model.UnflattenAuthorityPhase,
) -> TerminalCycleBindingResult:
    """Bind one terminal-cycle claim during projected preparation."""
    if phase is not model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT:
        raise ValueError("terminal-cycle binding must be projected preflight")
    return _classify_terminal_cycle_break_claim(
        claim=claim, proposal=proposal, source_inventory=source_inventory,
        candidate_inventory=candidate_inventory, phase=phase,
    )


def _revalidate_observed_terminal_cycle_break(
    *,
    projected_result: model.TerminalCyclePhaseResult,
    claim: model.TerminalCycleBreakClaim,
    proposal: model.ProposedUnflattenContract,
    source_inventory: model.SemanticGraphInventory,
    observed_inventory: model.SemanticGraphInventory,
) -> model.TerminalCyclePhaseResult:
    """Reclassify one sealed terminal-cycle claim against observed topology."""
    if type(projected_result) is not model.TerminalCyclePhaseResult:
        raise TypeError("observed terminal requires the exact projected result")
    projected_result.__post_init__()
    if (
        projected_result.claim_id != claim.claim_id
        or projected_result.terminal_route_proof_id
        not in claim.terminal_route_proof_ids
        or projected_result.source_fingerprint != source_inventory.graph_fingerprint
    ):
        raise ValueError("observed terminal authority is not the prepared occurrence")
    if tuple(projected_result.source_bindings) != tuple(
        binding for binding in source_inventory.bindings
        if binding.subject.subject_id in {
            item.subject.subject_id for item in projected_result.source_bindings
        }
    ):
        raise ValueError("observed terminal source bindings differ from prepared authority")
    if projected_result.phase is not model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT:
        raise ValueError("observed terminal parent must be projected preflight")
    if observed_inventory.phase is not model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY:
        raise ValueError("observed terminal inventory must be observed post apply")
    source_by_id = {item.subject.subject_id: item for item in source_inventory.bindings}
    observed_by_id = {item.subject.subject_id: item for item in observed_inventory.bindings}
    source_bindings = tuple(projected_result.source_bindings)
    if any(source_by_id.get(item.subject.subject_id) is not item for item in source_bindings):
        raise ValueError("observed terminal source binding domain differs from prepared result")
    observed_bindings = tuple(
        observed_by_id.get(item.subject.subject_id) for item in source_bindings
    )
    if any(item is None for item in observed_bindings):
        raise ValueError("observed terminal binding domain differs from prepared result")
    observed_bindings = tuple(observed_bindings)
    subject_by_ref = {item.subject.block_ref: item.subject for item in source_bindings}
    residue_subjects = {ref: subject_by_ref[ref] for ref in projected_result.residue_refs}
    observed_edges = _terminal_cycle_edges(observed_inventory, residue_subjects=residue_subjects)
    if _contains_directed_cycle(projected_result.residue_refs, observed_edges):
        raise ValueError("terminal-cycle residual cycle remains observed")
    by_ref = {item.subject.block_ref: item for item in observed_bindings}
    route_source = by_ref.get(projected_result.terminal_source_ref)
    cleanup = by_ref.get(projected_result.cleanup_source_ref)
    carrier = by_ref.get(projected_result.terminal_carrier_ref)
    terminal = by_ref.get(projected_result.terminal_subject_ref)
    if (
        any(item is None or item.status is not model.SubjectBindingStatus.UNIQUE for item in (route_source, cleanup, carrier, terminal))
        or any(item.serial not in observed_inventory.reachable_serials for item in (route_source, carrier, terminal))
    ):
        raise ValueError("observed terminal route endpoint is not uniquely reachable")
    blocks = {block.serial: block for block in observed_inventory.blocks}
    if (tuple(blocks[route_source.serial].successor_serials) != (carrier.serial,) or tuple(blocks[cleanup.serial].successor_serials) != (carrier.serial,)):
        raise ValueError("observed terminal source and cleanup do not converge on carrier")
    route = _terminal_route_refs(observed_inventory, carrier_binding=carrier, terminal_binding=terminal)
    observed_bindings = tuple(sorted(observed_bindings, key=lambda item: item.subject.subject_id))
    values = {
        "claim_id": projected_result.claim_id,
        "terminal_route_proof_id": projected_result.terminal_route_proof_id,
        "phase": model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        "source_fingerprint": source_inventory.graph_fingerprint,
        "candidate_fingerprint": observed_inventory.graph_fingerprint,
        "source_generation": source_inventory.generation,
        "candidate_generation": observed_inventory.generation,
        "bound_subject_ids": projected_result.bound_subject_ids,
        "source_binding_digest": authority_id(source_bindings),
        "candidate_binding_digest": authority_id(observed_bindings),
        "residue_refs": projected_result.residue_refs,
        "source_cycle_edges": projected_result.source_cycle_edges,
        "candidate_cycle_edges": observed_edges,
        "source_bindings": source_bindings,
        "candidate_bindings": observed_bindings,
        "terminal_source_ref": projected_result.terminal_source_ref,
        "cleanup_source_ref": projected_result.cleanup_source_ref,
        "terminal_carrier_ref": projected_result.terminal_carrier_ref,
        "terminal_route_refs": route,
        "terminal_subject_id": projected_result.terminal_subject_id,
        "terminal_subject_ref": projected_result.terminal_subject_ref,
    }
    result = object.__new__(model.TerminalCyclePhaseResult)
    object.__setattr__(result, "result_id", authority_id((
        "unflatten.terminal-cycle-phase.v1", values["claim_id"], values["terminal_route_proof_id"],
        values["phase"], values["source_fingerprint"], values["candidate_fingerprint"],
        values["source_generation"], values["candidate_generation"], values["bound_subject_ids"],
        values["source_binding_digest"], values["candidate_binding_digest"], values["residue_refs"],
        values["source_cycle_edges"], values["candidate_cycle_edges"], values["terminal_source_ref"],
        values["cleanup_source_ref"], values["terminal_carrier_ref"], values["terminal_route_refs"],
        values["terminal_subject_id"], values["terminal_subject_ref"],
    )))
    for name, value in values.items(): object.__setattr__(result, name, value)
    result.__post_init__()
    return result


def _make_terminal_cycle_binding_entrypoints(
    graph_impl=_bind_terminal_cycle_break_claim,
    observed_impl=_revalidate_observed_terminal_cycle_break,
):
    """Keep terminal-cycle phase occurrence authority private to the binder."""

    phase_registry: dict[
        int,
        tuple[weakref.ReferenceType[model.TerminalCyclePhaseResult], str],
    ] = {}

    def validate_phase(result: model.TerminalCyclePhaseResult) -> None:
        if type(result) is not model.TerminalCyclePhaseResult:
            raise TypeError("terminal-cycle phase result must be closed")
        registered = phase_registry.get(id(result))
        if registered is None or registered[0]() is not result:
            raise ValueError("terminal-cycle phase result was not minted by the transaction binder")
        result.__post_init__()
        if registered[1] != authority_id(("unflatten.terminal-cycle-phase-object-seal.v1", result)):
            raise ValueError("terminal-cycle phase result content changed after minting")

    def register_phase(
        result: model.TerminalCyclePhaseResult,
    ) -> model.TerminalCyclePhaseResult:
        if type(result) is not model.TerminalCyclePhaseResult:
            raise TypeError("terminal-cycle phase result must be closed")
        result.__post_init__()
        identity = id(result)
        registered = phase_registry.get(identity)
        if registered is not None and registered[0]() is result:
            raise ValueError("terminal-cycle phase result occurrence was already minted")
        seal = authority_id(("unflatten.terminal-cycle-phase-object-seal.v1", result))

        def cleanup(reference: weakref.ReferenceType[model.TerminalCyclePhaseResult]) -> None:
            registered = phase_registry.get(identity)
            if registered is not None and registered[0] is reference:
                phase_registry.pop(identity, None)

        phase_registry[identity] = (weakref.ref(result, cleanup), seal)
        validate_phase(result)
        return result

    def validate_binding(result: TerminalCycleBindingResult) -> None:
        _validate_terminal_cycle_binding_result_fields(result)
        validate_phase(result.phase_result)

    def entrypoint(**kwargs: object) -> TerminalCycleBindingResult:
        result = graph_impl(**kwargs)
        register_phase(result.phase_result)
        validate_binding(result)
        return result

    def observed_entrypoint(**kwargs: object) -> model.TerminalCyclePhaseResult:
        projected_result = kwargs.get("projected_result")
        if type(projected_result) is not model.TerminalCyclePhaseResult:
            raise TypeError("observed terminal requires the exact projected result")
        validate_phase(projected_result)
        return register_phase(observed_impl(**kwargs))

    return entrypoint, validate_phase, validate_binding, observed_entrypoint


(
    bind_terminal_cycle_break_claim,
    validate_terminal_cycle_phase_result,
    validate_terminal_cycle_binding_result,
    revalidate_observed_terminal_cycle_break,
) = _make_terminal_cycle_binding_entrypoints()
del _make_terminal_cycle_binding_entrypoints
del _bind_terminal_cycle_break_claim
del _revalidate_observed_terminal_cycle_break


def _classify_corridor_coverage_forecast(
    *,
    proposal: model.ProposedUnflattenContract,
    source_inventory: model.SemanticGraphInventory,
    candidate_inventory: model.SemanticGraphInventory,
    phase: model.UnflattenAuthorityPhase,
    claims: tuple[model.UnflattenClaim, ...] | None = None,
    projected_correlations: tuple[model.CorridorSemanticExclusionCorrelation, ...] | None = None,
    default_gap_paths: tuple[model.DefaultGapInfeasibilityPath, ...] = (),
) -> model.CorridorCoveragePhaseResult | None:
    """Fold one sealed forecast against already-built inventory topology."""

    if type(proposal) is not model.ProposedUnflattenContract:
        raise TypeError("corridor forecast binding requires a closed proposal")
    forecast = proposal.corridor_coverage_forecast
    if forecast is None:
        return None
    if (
        type(default_gap_paths) is not tuple
        or any(type(item) is not model.DefaultGapInfeasibilityPath for item in default_gap_paths)
    ):
        raise TypeError("default-gap classifier context must contain closed typed paths")
    default_gap_coordinates = {
        (item.nodes, item.state_merge) for item in default_gap_paths
    }
    if type(source_inventory) is not model.SemanticGraphInventory or type(candidate_inventory) is not model.SemanticGraphInventory:
        raise TypeError("corridor forecast binding requires closed inventories")
    model.validate_semantic_graph_inventory(source_inventory)
    model.validate_semantic_graph_inventory(candidate_inventory)
    if type(phase) is not model.UnflattenAuthorityPhase or candidate_inventory.phase is not phase:
        raise ValueError("corridor forecast phase differs from candidate inventory")
    if source_inventory.phase is not model.UnflattenAuthorityPhase.PRODUCER_FORECAST:
        raise ValueError("corridor forecast source inventory must be producer forecast")

    source_blocks = {row.block_ref: row for row in source_inventory.blocks if row.block_ref is not None}
    candidate_blocks = {row.block_ref: row for row in candidate_inventory.blocks if row.block_ref is not None}
    candidate_edges = {
        (row.owner_serial, row.peer_serial)
        for row in candidate_inventory.topology
        if row.kind is model.TopologyIncidenceKind.SUCCESSOR
    }
    source_edges = {
        (row.owner_serial, row.peer_serial)
        for row in source_inventory.topology
        if row.kind is model.TopologyIncidenceKind.SUCCESSOR
    }
    source_predecessor_counts: dict[int, int] = {}
    for row in source_inventory.topology:
        if row.kind is model.TopologyIncidenceKind.PREDECESSOR:
            source_predecessor_counts[row.owner_serial] = source_predecessor_counts.get(row.owner_serial, 0) + 1
    source_fp = source_inventory.graph_fingerprint
    candidate_fp = candidate_inventory.graph_fingerprint
    if source_inventory.generation != forecast.source_generation:
        raise ValueError("corridor forecast source generation differs from source inventory")
    if forecast.function_ea != source_inventory.function_ea:
        raise ValueError("corridor forecast function EA differs from source inventory")
    if candidate_inventory.function_ea != source_inventory.function_ea:
        raise ValueError("candidate function EA differs from source inventory")
    dispatcher_bindings = tuple(
        binding for binding in source_inventory.bindings
        if binding.subject.role is model.SemanticSubjectRole.DISPATCHER_ENTRY
        and binding.subject.block_ref == forecast.dispatcher_ref
        and binding.subject.anchor_ea == forecast.dispatcher_anchor_ea
    )
    if len(dispatcher_bindings) != 1:
        raise ValueError("corridor forecast dispatcher binding is missing or ambiguous")
    source_dispatcher = dispatcher_bindings[0]
    if (
        source_dispatcher.status is not model.SubjectBindingStatus.UNIQUE
        or source_dispatcher.serial not in source_inventory.reachable_serials
    ):
        raise ValueError("corridor forecast source dispatcher is not uniquely reachable")
    candidate_dispatcher_bindings = tuple(
        binding for binding in candidate_inventory.bindings
        if binding.subject.role is model.SemanticSubjectRole.DISPATCHER_ENTRY
        and binding.subject.block_ref == forecast.dispatcher_ref
        and binding.subject.anchor_ea == forecast.dispatcher_anchor_ea
    )
    if len(candidate_dispatcher_bindings) != 1:
        raise ValueError("corridor forecast candidate dispatcher binding is missing or ambiguous")
    candidate_dispatcher = candidate_dispatcher_bindings[0]
    if candidate_dispatcher.status not in {
        model.SubjectBindingStatus.MISSING, model.SubjectBindingStatus.UNIQUE,
    }:
        raise ValueError("corridor forecast candidate dispatcher binding drifted")
    source_dispatcher_reachable = True
    candidate_dispatcher_reachable = (
        candidate_dispatcher.status is model.SubjectBindingStatus.UNIQUE
        and candidate_dispatcher.serial in candidate_inventory.reachable_serials
    )
    if source_dispatcher_reachable and not forecast.paths:
        raise ValueError("reachable source dispatcher requires a non-empty corridor forecast")
    forecast_path_ids = {path.path_id for path in forecast.paths}
    if set(forecast.covered_path_ids) | set(forecast.residual_path_ids) != forecast_path_ids:
        raise ValueError("corridor forecast partitions do not cover the path universe")
    if set(forecast.covered_path_ids) & set(forecast.residual_path_ids):
        raise ValueError("corridor forecast partitions overlap")
    covered: list[str] = []
    residual: list[str] = []
    drifted: list[str] = []
    matched_exclusions: list[str] = []
    correlation_specs: list[tuple[object, ...]] = []
    exclusions_by_id = {
        exclusion.exclusion_id: exclusion
        for exclusion in forecast.semantic_exclusions
    }
    route_proofs = {
        proof.proof_id: proof for proof in proposal.route_evidence.route_proofs
    }

    source_catalog_by_ref = {
        witness.block_ref: witness
        for witness in proposal.source_identity_catalog.blocks
    }
    prepared_correlations = {
        (item.exclusion_id, item.path_id): item
        for item in (projected_correlations or ())
    }

    def exact_native_identity(node: model.CorridorCoveragePathNode) -> StableBlockIdentity:
        witness = source_catalog_by_ref.get(node.block_ref)
        if witness is None or witness.anchor_ea != node.anchor_ea:
            raise ValueError("corridor semantic exclusion node is absent from source catalog")
        if type(witness.block_ref) is NativeBlockRef:
            expected = witness.block_ref.identity
        else:
            expected = StableBlockIdentity.from_instruction_eas(
                witness.native_instruction_eas,
                native_key=proposal.source_identity_catalog.native_key,
            )
        if expected.exact_instruction_eas != frozenset(witness.native_instruction_eas):
            raise ValueError("corridor semantic exclusion identity differs from source catalog")
        return expected

    def bind_semantic_exclusion(
        exclusion_id: str,
        path_id: str,
        ordered_prefix: tuple[model.CorridorCoveragePathNode, ...],
    ) -> None:
        exclusion = exclusions_by_id.get(exclusion_id)
        if exclusion is None:
            raise ValueError("corridor semantic exclusion is absent from forecast")
        exact_suffix = tuple(
            node for node in (
                exclusion.source, exclusion.feeder, exclusion.prefix, exclusion.root,
            )
            if node is not None
        )
        if (
            len(exact_suffix) > len(ordered_prefix)
            or ordered_prefix[-len(exact_suffix):] != exact_suffix
            or exclusion.root.block_ref != forecast.dispatcher_ref
            or exclusion.root.anchor_ea != forecast.dispatcher_anchor_ea
        ):
            raise ValueError("corridor semantic exclusion topology differs from forecast path")
        suffix_serials = tuple(source_inventory.serial_by_ref[node.block_ref] for node in exact_suffix)
        if any(edge not in source_edges for edge in zip(suffix_serials, suffix_serials[1:])):
            raise ValueError("corridor semantic exclusion suffix is absent from source topology")
        source_identity = exact_native_identity(exclusion.source)
        candidates = []
        for claim in (proposal.claims if claims is None else claims):
            if type(claim) is not model.EquivalentSemanticRouteClaim:
                continue
            if len(claim.route_proof_ids) != 1:
                continue
            proof = route_proofs.get(claim.route_proof_ids[0])
            if proof is None:
                continue
            source_match = (
                proof.source_anchor_ea == exclusion.source.anchor_ea
                and proof.source_identity == source_identity
            )
            matching_destinations = tuple(
                destination
                for destination in proof.destinations
                if destination.state_constant == exclusion.normalized_state
            )
            state_route_match = (
                proof.state_write is not None
                and proof.state_write.state_variable == exclusion.state_identity
                and proof.state_write.state_constant == exclusion.normalized_state
                and len(matching_destinations) == 1
            )
            if source_match and state_route_match:
                destination = matching_destinations[0]
                try:
                    destination_subject = _native_route_destination_subject_for_proof_destination(
                        claim=claim,
                        proof_destination=destination,
                        catalog=proposal.source_identity_catalog,
                    )
                except (TypeError, ValueError):
                    destination_match = False
                else:
                    destination_match = (
                        destination_subject.anchor_ea == destination.target_anchor_ea
                        and exact_native_identity(
                            model.CorridorCoveragePathNode(
                                destination_subject.block_ref,
                                destination_subject.anchor_ea,
                            )
                        ) == destination.target_identity
                    )
            else:
                destination_match = False
            if source_match and state_route_match and destination_match:
                candidates.append(claim)
        if len(candidates) != 1:
            raise ValueError("corridor semantic exclusion has zero or multiple route links")
        matched_exclusions.append(exclusion_id)
        claim = candidates[0]
        correlation_specs.append((
            exclusion_id, exclusion.digest, path_id, claim.claim_id, claim.route_proof_ids[0],
            ordered_prefix, source_fp, candidate_fp,
            source_inventory.generation, candidate_inventory.generation,
        ))

    for path in forecast.paths:
        source_serials: list[int] = []
        candidate_serials: list[int] = []
        source_ok = True
        candidate_ok = True
        for node in path.nodes:
            source_row = source_blocks.get(node.block_ref)
            if source_row is None or source_row.anchor_ea != node.anchor_ea:
                source_ok = False
                candidate_ok = False
                break
            source_serials.append(source_row.serial)
            candidate_row = candidate_blocks.get(node.block_ref)
            if candidate_row is None or candidate_row.anchor_ea != node.anchor_ea:
                candidate_ok = False
            else:
                candidate_serials.append(candidate_row.serial)
        source_path_exists = source_ok and all(
            (left, right) in source_edges
            for left, right in zip(source_serials, source_serials[1:])
        )
        candidate_path_exists = candidate_ok and len(candidate_serials) == len(path.nodes) and all(
            (left, right) in candidate_edges
            for left, right in zip(candidate_serials, candidate_serials[1:])
        )
        candidate_state_ok = True
        candidate_state_hard_failure = False
        if source_path_exists and path.state_merge is not None:
            if path.state_merge != path.nodes[-3]:
                raise ValueError("corridor state merge is not the exact path[-3] node")
            merge_row = source_blocks.get(path.state_merge.block_ref)
            feeder_row = source_blocks.get(path.nodes[-2].block_ref)
            if (
                merge_row is None or feeder_row is None
                or source_predecessor_counts.get(merge_row.serial, 0) < 2
                or (merge_row.serial, feeder_row.serial) not in source_edges
                or {
                    peer for left, peer in source_edges if left == merge_row.serial
                } != {feeder_row.serial}
            ):
                raise ValueError("corridor state merge semantics drifted from source topology")
            candidate_merge = candidate_blocks.get(path.state_merge.block_ref)
            candidate_feeder = candidate_blocks.get(path.nodes[-2].block_ref)
            if candidate_merge is None or candidate_feeder is None:
                candidate_state_ok = False
                candidate_state_hard_failure = True
            else:
                candidate_merge_predecessors = sum(
                    1 for row in candidate_inventory.topology
                    if row.kind is model.TopologyIncidenceKind.PREDECESSOR
                    and row.owner_serial == candidate_merge.serial
                )
                candidate_state_ok = (
                    candidate_merge_predecessors >= 2
                    and (candidate_merge.serial, candidate_feeder.serial) in candidate_edges
                    and {
                        peer for left, peer in candidate_edges
                        if left == candidate_merge.serial
                    } == {candidate_feeder.serial}
                )
                candidate_state_hard_failure = candidate_merge_predecessors < 2

        if not source_path_exists:
            drifted.append(path.path_id)
        elif path.disposition is model.CorridorPathDisposition.SEMANTICALLY_EXCLUDED:
            if not path.semantic_exclusion_ids:
                raise ValueError("semantic exclusion path has no typed exclusion IDs")
            for exclusion_id in path.semantic_exclusion_ids:
                prepared = prepared_correlations.get((exclusion_id, path.path_id))
                if projected_correlations is None:
                    bind_semantic_exclusion(exclusion_id, path.path_id, tuple(path.nodes))
                elif (
                    prepared is None
                    or prepared.ordered_prefix != tuple(path.nodes)
                    or prepared.source_fingerprint != source_fp
                    or prepared.source_generation != source_inventory.generation
                ):
                    raise ValueError("observed corridor correlation differs from prepared authority")
                else:
                    matched_exclusions.append(exclusion_id)
                    correlation_specs.append((
                        prepared.exclusion_id, prepared.exclusion_digest,
                        prepared.path_id, prepared.claim_id, prepared.proof_id,
                        prepared.ordered_prefix, source_fp, candidate_fp,
                        source_inventory.generation, candidate_inventory.generation,
                    ))
            covered.append(path.path_id)
        elif path.disposition is model.CorridorPathDisposition.RESIDUAL:
            typed_default_gap = (path.nodes, path.state_merge) in default_gap_coordinates
            if (not candidate_path_exists or candidate_state_hard_failure) and not typed_default_gap:
                raise ValueError(
                    "residual corridor path classification lacks required candidate topology"
                )
            (residual if typed_default_gap or candidate_state_ok else drifted).append(path.path_id)
        elif not candidate_dispatcher_reachable:
            # Structural residue in a disconnected dispatcher component is
            # semantically covered.  Requiring the physical path to disappear
            # would make this phase independently reconstruct a stronger loss
            # decision than the transaction's sealed reachability partition.
            covered.append(path.path_id)
        elif candidate_path_exists:
            drifted.append(path.path_id)
        else:
            covered.append(path.path_id)
            if path.semantic_exclusion_ids:
                raise ValueError("structural corridor coverage cannot carry semantic exclusions")
    correlation_content = tuple(
        sorted(correlation_specs, key=lambda item: (item[0], item[2]))
    )
    dispatcher_candidates = tuple(
        binding.subject.subject_id for binding in source_inventory.bindings
        if binding.subject.role is model.SemanticSubjectRole.DISPATCHER_ENTRY
        and binding.subject.block_ref == forecast.dispatcher_ref
        and binding.subject.anchor_ea == forecast.dispatcher_anchor_ea
        and binding.status is model.SubjectBindingStatus.UNIQUE
    )
    if len(dispatcher_candidates) != 1:
        raise ValueError("corridor forecast dispatcher has no exact unique source subject")
    dispatcher_subject_id = dispatcher_candidates[0]
    # The forecast paths describe upstream delivery into the dispatcher.  They
    # are not a declaration that every upstream node is comparison
    # infrastructure: backward enumeration may legitimately retain an
    # unreachable predecessor.  Comparison membership must instead come from
    # a producer-owned typed declaration.  A retirement catalogue contributes
    # its explicit comparison rows below; canonical state-DAG evidence also
    # contributes its exact comparison nodes.  The latter matters for nested
    # dispatchers whose branch nodes carry state writes and therefore are not
    # eligible as effect-free retirement candidates.
    def source_binding_for_block(
        *, block_ref: object, anchor_ea: int, label: str,
    ) -> model.PhaseSubjectBinding:
        matches = tuple(
            binding
            for binding in source_inventory.bindings
            if (
                binding.subject.role
                is model.SemanticSubjectRole.SOURCE_CATALOG_BLOCK
                and binding.subject.block_ref == block_ref
                and binding.subject.anchor_ea == anchor_ea
            )
        )
        if len(matches) != 1:
            raise ValueError(f"{label} has no exact source subject")
        binding = matches[0]
        if (
            binding.status is not model.SubjectBindingStatus.UNIQUE
            or binding.serial not in source_inventory.reachable_serials
        ):
            raise ValueError(f"{label} is not uniquely source-reachable")
        return binding

    dispatcher_binding = next(
        binding
        for binding in source_inventory.bindings
        if binding.subject.subject_id == dispatcher_subject_id
    )
    comparison_bindings = []
    for claim in proposal.claims:
        if type(claim) is not model.DetachedDeadHandlerComponentClaim:
            continue
        if claim.dispatcher_subject.block_ref != dispatcher_binding.block_ref:
            continue
        for subject in claim.comparison_region_subjects:
            matches = tuple(
                binding for binding in source_inventory.bindings
                if binding.subject == subject
            )
            if len(matches) != 1:
                raise ValueError(
                    "detached comparison-region subject has no exact source binding"
                )
            binding = matches[0]
            if (
                binding.status is not model.SubjectBindingStatus.UNIQUE
                or binding.serial not in source_inventory.reachable_serials
            ):
                raise ValueError(
                    "detached comparison-region subject is not uniquely source-reachable"
                )
            comparison_bindings.append(binding)

    retirement_catalog = proposal.retirement_candidate_catalog
    if retirement_catalog is not None:
        for candidate in retirement_catalog.candidates:
            if candidate.role != "comparison_dispatcher":
                continue
            comparison_bindings.append(source_binding_for_block(
                block_ref=candidate.block_ref,
                anchor_ea=candidate.anchor_ea,
                label="retirement comparison candidate",
            ))
    comparison_region_subject_ids = tuple(sorted({
        dispatcher_subject_id,
        *(binding.subject.subject_id for binding in comparison_bindings),
    }))
    result_id = authority_id((
        "unflatten.corridor-coverage-phase.v1", forecast.forecast_id, phase,
        source_fp, candidate_fp, source_inventory.generation,
        candidate_inventory.generation, tuple(sorted(covered)),
        tuple(sorted(residual)), tuple(sorted(drifted)),
        forecast.enumeration_complete, tuple(sorted(set(matched_exclusions))),
        source_dispatcher_reachable, candidate_dispatcher_reachable,
        correlation_content, comparison_region_subject_ids, dispatcher_subject_id,
    ))
    expected_covered = set(forecast.covered_path_ids)
    if (
        (not candidate_dispatcher_reachable and set(covered) != expected_covered)
        or set(covered) & set(residual)
        or set(covered) | set(residual) | set(drifted) != forecast_path_ids
    ):
        logger.warning(
            "corridor phase partition mismatch: phase=%s dispatcher=%s "
            "forecast_covered=%r covered=%r residual=%r drifted=%r universe=%r",
            phase.value,
            candidate_dispatcher_reachable,
            tuple(sorted(expected_covered)),
            tuple(sorted(covered)),
            tuple(sorted(residual)),
            tuple(sorted(drifted)),
            tuple(sorted(forecast_path_ids)),
        )
        raise ValueError("corridor phase classification disagrees with sealed forecast partition")
    correlations = tuple(
        model.CorridorSemanticExclusionCorrelation(*spec, phase_result_id=result_id)
        for spec in correlation_content
    )
    return model.CorridorCoveragePhaseResult(
        result_id, forecast.forecast_id, phase, source_fp, candidate_fp,
        source_inventory.generation, candidate_inventory.generation,
        tuple(sorted(covered)), tuple(sorted(residual)), tuple(sorted(drifted)),
        forecast.enumeration_complete, tuple(sorted(set(matched_exclusions))),
        source_dispatcher_reachable, candidate_dispatcher_reachable,
        correlations, comparison_region_subject_ids, dispatcher_subject_id,
    )


@dataclass(frozen=True, slots=True)
class DetachedDeadHandlerComponentBindingResult:
    """One transaction-minted detached source authority and phase verdict."""

    source_result: model.DetachedDeadHandlerComponentSourceResult
    phase_result: model.DetachedDeadHandlerComponentPhaseResult

    def __post_init__(self) -> None:
        if type(self.source_result) is not model.DetachedDeadHandlerComponentSourceResult:
            raise TypeError("detached binding requires a closed source result")
        if type(self.phase_result) is not model.DetachedDeadHandlerComponentPhaseResult:
            raise TypeError("detached binding requires a closed phase result")
        validate_detached_source_result(self.source_result)
        validate_detached_phase_result(self.phase_result)
        if self.phase_result.source_result_id != self.source_result.result_id:
            raise ValueError("detached phase result is foreign to its source authority")


def _ref_tuple(values: Sequence[object]) -> tuple[object, ...]:
    return tuple(sorted(set(values), key=canonical_bytes))


def _stable_terminal_keys(
    inventory: model.SemanticGraphInventory,
) -> tuple[tuple[object, int, model.TerminalKind], ...]:
    reachable = set(inventory.reachable_serials)
    rows = (
        (
            item.owner_ref
            if item.owner_ref is not None
            else ("generated", item.owner_serial, item.owner_anchor_ea),
            item.instruction_ea,
            item.terminal_kind,
        )
        for item in inventory.terminals
        if item.owner_serial in reachable
    )
    return tuple(sorted(rows, key=canonical_bytes))


def _stable_effect_keys(
    inventory: model.SemanticGraphInventory,
) -> tuple[tuple[object, int, model.EffectSiteKind], ...]:
    reachable = set(inventory.reachable_serials)
    rows = (
        (
            item.owner_ref
            if item.owner_ref is not None
            else ("generated", item.owner_serial, item.owner_anchor_ea),
            item.instruction_ea,
            item.effect_kind,
        )
        for item in inventory.effects
        if item.owner_serial in reachable
    )
    return tuple(sorted(rows, key=canonical_bytes))


def _candidate_reachable_refs(
    inventory: model.SemanticGraphInventory,
) -> frozenset[object]:
    reachable = set(inventory.reachable_serials)
    return frozenset(
        block.block_ref
        for block in inventory.blocks
        if block.serial in reachable and block.block_ref is not None
    )


def _source_block_maps(
    blocks: Sequence[model.InventoryBlockObservation],
) -> tuple[dict[int, model.InventoryBlockObservation], dict[object, model.InventoryBlockObservation]]:
    by_serial = {block.serial: block for block in blocks}
    by_ref = {
        block.block_ref: block for block in blocks if block.block_ref is not None
    }
    if len(by_serial) != len(tuple(blocks)) or len(by_ref) != len(tuple(blocks)):
        raise ValueError("detached source block facts are not exact by serial and ref")
    return by_serial, by_ref


def _derive_detached_component_refs(
    *,
    source_blocks: Sequence[model.InventoryBlockObservation],
    dead_handler_refs: frozenset[object],
    dispatcher_ref: object,
    candidate_reachable_refs: frozenset[object],
) -> frozenset[object]:
    by_serial, by_ref = _source_block_maps(source_blocks)
    source_refs = frozenset(by_ref)
    lost_refs = source_refs - candidate_reachable_refs
    component: set[object] = set()
    pending = list(dead_handler_refs)
    while pending:
        ref = pending.pop()
        if (
            ref in component
            or ref == dispatcher_ref
            or ref in candidate_reachable_refs
            or ref not in lost_refs
        ):
            continue
        block = by_ref.get(ref)
        if block is None:
            raise ValueError("detached handler is absent from sealed source blocks")
        component.add(ref)
        pending.extend(by_serial[target].block_ref for target in block.successor_serials)
    return frozenset(component)


def _validate_candidate_detached_partition(
    *,
    claim: model.DetachedDeadHandlerComponentClaim,
    candidate_inventory: model.SemanticGraphInventory,
    source_blocks: Sequence[model.InventoryBlockObservation],
    dispatcher_ref: object,
    comparison_refs: frozenset[object],
    expected_component_refs: frozenset[object],
    source_terminal_keys: tuple[tuple[object, int, model.TerminalKind], ...],
    source_effect_keys: tuple[tuple[object, int, model.EffectSiteKind], ...],
) -> tuple[frozenset[object], frozenset[object]]:
    bindings = {
        binding.subject.subject_id: binding
        for binding in candidate_inventory.bindings
    }
    reachable_serials = set(candidate_inventory.reachable_serials)
    reachable_refs = _candidate_reachable_refs(candidate_inventory)

    def binding_reachable(subject: model.SemanticSubjectRef) -> bool:
        binding = bindings.get(subject.subject_id)
        if binding is None or binding.status is model.SubjectBindingStatus.AMBIGUOUS:
            raise ValueError("detached candidate subject binding is absent or ambiguous")
        exact_reachable = (
            binding.status is model.SubjectBindingStatus.UNIQUE
            and binding.serial in reachable_serials
        )
        if exact_reachable != (subject.block_ref in reachable_refs):
            raise ValueError("detached candidate binding disagrees with stable-ref reachability")
        return exact_reachable

    if binding_reachable(claim.dispatcher_subject):
        raise ValueError("detached dispatcher remains candidate-reachable")
    if any(binding_reachable(subject) for subject in claim.dead_handler_subjects):
        raise ValueError("detached dead-handler partition remains candidate-reachable")
    if not all(binding_reachable(subject) for subject in claim.retained_handler_subjects):
        raise ValueError("detached retained-handler partition is not candidate-reachable")
    if any(binding_reachable(subject) for subject in claim.component_subjects):
        raise ValueError("detached component member remains candidate-reachable")

    dead_refs = frozenset(subject.block_ref for subject in claim.dead_handler_subjects)
    derived_component = _derive_detached_component_refs(
        source_blocks=source_blocks,
        dead_handler_refs=dead_refs,
        dispatcher_ref=dispatcher_ref,
        candidate_reachable_refs=reachable_refs,
    )
    if derived_component != expected_component_refs:
        raise ValueError("detached component differs from the exact source/candidate walk")
    if not dead_refs <= derived_component:
        raise ValueError("detached component does not cover every dead handler")

    by_serial, by_ref = _source_block_maps(source_blocks)
    source_refs = frozenset(by_ref)
    lost_refs = source_refs - reachable_refs
    for ref in dead_refs:
        block = by_ref[ref]
        reachable_preds = frozenset(
            by_serial[pred].block_ref
            for pred in block.predecessor_serials
            if pred in by_serial
        )
        if not reachable_preds or not reachable_preds <= comparison_refs:
            raise ValueError("detached dead handler has non-comparison ingress")
    for ref in derived_component:
        block = by_ref[ref]
        reachable_preds = frozenset(
            by_serial[pred].block_ref
            for pred in block.predecessor_serials
            if pred in by_serial
        )
        if not reachable_preds <= derived_component | comparison_refs:
            raise ValueError("detached component has external semantic ingress")
        if any(
            observation.is_call
            or observation.instruction_kind in {model.InsnKind.CALL, model.InsnKind.STORE}
            for observation in block.instruction_observations
        ):
            raise ValueError("detached component contains CALL or STORE")

    remainder = lost_refs - derived_component - comparison_refs
    retired_region = remainder | derived_component | comparison_refs
    for ref in remainder:
        block = by_ref[ref]
        if any(
            observation.is_call
            or observation.instruction_kind in {model.InsnKind.CALL, model.InsnKind.STORE}
            for observation in block.instruction_observations
        ):
            raise ValueError("detached remainder contains CALL or STORE")
        if not block.successor_serials:
            raise ValueError("detached remainder contains a terminal block")
        successor_refs = frozenset(by_serial[target].block_ref for target in block.successor_serials)
        if not successor_refs <= retired_region:
            raise ValueError("detached remainder escapes the retired region")

    if _stable_terminal_keys(candidate_inventory) != source_terminal_keys:
        raise ValueError("detached candidate terminal identity drifted")
    if _stable_effect_keys(candidate_inventory) != source_effect_keys:
        raise ValueError("detached candidate effect identity drifted")
    if len(derived_component) * 2 >= max(1, len(source_refs)):
        raise ValueError("detached component is not a strict minority island")
    return derived_component, frozenset(remainder)


def _detached_source_result_values(
    *,
    claim: model.DetachedDeadHandlerComponentClaim,
    source_inventory: model.SemanticGraphInventory,
    candidate_inventory: model.SemanticGraphInventory,
    corridor_result: model.CorridorCoveragePhaseResult,
) -> dict[str, object]:
    model.validate_semantic_graph_inventory(source_inventory)
    source_bindings = {
        binding.subject.subject_id: binding for binding in source_inventory.bindings
    }
    source_reachable = set(source_inventory.reachable_serials)
    required_subjects = (
        claim.dispatcher_subject,
        *claim.dead_handler_subjects,
        *claim.retained_handler_subjects,
        *claim.component_subjects,
        *claim.comparison_region_subjects,
    )
    for subject in required_subjects:
        binding = source_bindings.get(subject.subject_id)
        if (
            binding is None
            or binding.subject != subject
            or binding.status is not model.SubjectBindingStatus.UNIQUE
            or binding.serial not in source_reachable
        ):
            raise ValueError("detached source subject is not uniquely source-reachable")
    if corridor_result.dispatcher_subject_id != claim.dispatcher_subject.subject_id:
        raise ValueError("detached dispatcher differs from sealed corridor authority")
    comparison_bindings = tuple(
        source_bindings.get(subject_id)
        for subject_id in corridor_result.comparison_region_subject_ids
    )
    if any(
        binding is None
        or binding.status is not model.SubjectBindingStatus.UNIQUE
        or binding.serial not in source_reachable
        for binding in comparison_bindings
    ):
        raise ValueError("detached comparison region is not exactly source-bound")

    source_blocks = tuple(
        block for block in source_inventory.blocks if block.serial in source_reachable
    )
    _source_block_maps(source_blocks)
    source_refs = frozenset(block.block_ref for block in source_blocks)
    comparison_refs = frozenset(binding.block_ref for binding in comparison_bindings)
    dead_refs = frozenset(subject.block_ref for subject in claim.dead_handler_subjects)
    retained_refs = frozenset(subject.block_ref for subject in claim.retained_handler_subjects)
    claimed_component_refs = frozenset(
        subject.block_ref for subject in claim.component_subjects
    )
    terminal_keys = _stable_terminal_keys(source_inventory)
    effect_keys = _stable_effect_keys(source_inventory)
    component_refs, remainder_refs = _validate_candidate_detached_partition(
        claim=claim,
        candidate_inventory=candidate_inventory,
        source_blocks=source_blocks,
        dispatcher_ref=claim.dispatcher_subject.block_ref,
        comparison_refs=comparison_refs,
        expected_component_refs=claimed_component_refs,
        source_terminal_keys=terminal_keys,
        source_effect_keys=effect_keys,
    )
    reachable_subject_ids = tuple(sorted(
        subject_id
        for subject_id, binding in source_bindings.items()
        if binding.status is model.SubjectBindingStatus.UNIQUE
        and binding.serial in source_reachable
    ))
    values = (
        claim.claim_id,
        corridor_result.forecast_id,
        corridor_result.result_id,
        source_inventory.graph_fingerprint,
        source_inventory.generation,
        claim.dispatcher_subject.subject_id,
        claim.dispatcher_subject.block_ref,
        tuple(subject.subject_id for subject in claim.dead_handler_subjects),
        tuple(subject.subject_id for subject in claim.retained_handler_subjects),
        tuple(subject.subject_id for subject in claim.component_subjects),
        corridor_result.comparison_region_subject_ids,
        reachable_subject_ids,
        _ref_tuple(dead_refs),
        _ref_tuple(retained_refs),
        _ref_tuple(comparison_refs),
        authority_id(terminal_keys),
        authority_id(effect_keys),
        authority_id(source_blocks),
        _ref_tuple(source_refs),
        _ref_tuple(component_refs),
        _ref_tuple(remainder_refs),
        terminal_keys,
        effect_keys,
        source_blocks,
    )
    return {
        "result_id": authority_id((
            "unflatten.detached-dead-handler-component-source.v2", *values,
        )),
        "claim_id": values[0],
        "corridor_forecast_id": values[1],
        "corridor_coverage_result_id": values[2],
        "source_fingerprint": values[3],
        "source_generation": values[4],
        "dispatcher_subject_id": values[5],
        "dispatcher_block_ref": values[6],
        "dead_handler_subject_ids": values[7],
        "retained_handler_subject_ids": values[8],
        "component_subject_ids": values[9],
        "comparison_region_subject_ids": values[10],
        "source_reachable_subject_ids": values[11],
        "dead_handler_block_refs": values[12],
        "retained_handler_block_refs": values[13],
        "comparison_region_block_refs": values[14],
        "terminal_digest": values[15],
        "effect_digest": values[16],
        "topology_digest": values[17],
        "source_reachable_block_refs": values[18],
        "component_block_refs": values[19],
        "remainder_block_refs": values[20],
        "terminal_site_keys": values[21],
        "effect_site_keys": values[22],
        "source_blocks": values[23],
    }


def _graph_bind_detached_dead_handler_component_claim(
    *, claim: model.DetachedDeadHandlerComponentClaim,
    source_inventory: model.SemanticGraphInventory,
    candidate_inventory: model.SemanticGraphInventory,
    corridor_result: model.CorridorCoveragePhaseResult,
    phase: model.UnflattenAuthorityPhase,
    source_result: model.DetachedDeadHandlerComponentSourceResult | None = None,
    _mint_source_result: object | None = None,
    _mint_phase_result: object | None = None,
    _lifecycle_secret: object | None = None,
    _source_values_impl=_detached_source_result_values,
) -> DetachedDeadHandlerComponentBindingResult:
    """Mint projected authority once, then validate observed candidates against it."""

    if (
        _lifecycle_secret is None
        or not callable(_mint_source_result)
        or not callable(_mint_phase_result)
    ):
        raise TypeError("detached binding lifecycle is closed")
    if type(claim) is not model.DetachedDeadHandlerComponentClaim:
        raise TypeError("detached claim must be closed")
    claim.__post_init__()
    if phase not in {
        model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
    }:
        raise ValueError("detached binding phase must be projected or observed")
    if (
        type(corridor_result) is not model.CorridorCoveragePhaseResult
        or corridor_result.phase is not phase
        or not corridor_result.full
    ):
        raise ValueError("detached bind requires exact full phase corridor authority")
    corridor_result.__post_init__()
    model.validate_semantic_graph_inventory(candidate_inventory)
    if candidate_inventory.phase is not phase:
        raise ValueError("detached candidate inventory is bound to the wrong phase")
    if (
        corridor_result.source_fingerprint != source_inventory.graph_fingerprint
        or corridor_result.candidate_fingerprint != candidate_inventory.graph_fingerprint
        or corridor_result.source_generation != source_inventory.generation
        or corridor_result.candidate_generation != candidate_inventory.generation
    ):
        raise ValueError("detached corridor result has foreign phase coordinates")

    if source_result is None:
        if phase is not model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT:
            raise ValueError("observed detached bind requires projected sealed source authority")
        source_result = _mint_source_result(**_source_values_impl(
            claim=claim,
            source_inventory=source_inventory,
            candidate_inventory=candidate_inventory,
            corridor_result=corridor_result,
        ))
    else:
        if phase is not model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY:
            raise ValueError("projected detached bind must mint its own source authority")
        if type(source_result) is not model.DetachedDeadHandlerComponentSourceResult:
            raise TypeError("detached source result must be closed")
        validate_detached_source_result(source_result)
        if (
            source_result.claim_id != claim.claim_id
            or source_result.corridor_forecast_id != corridor_result.forecast_id
            or source_result.source_fingerprint != source_inventory.graph_fingerprint
            or source_result.source_generation != source_inventory.generation
            or source_result.dispatcher_subject_id != claim.dispatcher_subject.subject_id
            or source_result.dispatcher_block_ref != claim.dispatcher_subject.block_ref
            or source_result.comparison_region_subject_ids
            != corridor_result.comparison_region_subject_ids
            or corridor_result.dispatcher_subject_id
            != source_result.dispatcher_subject_id
        ):
            raise ValueError("observed detached bind has foreign sealed source authority")
        if source_result.dead_handler_subject_ids != tuple(
            subject.subject_id for subject in claim.dead_handler_subjects
        ) or source_result.retained_handler_subject_ids != tuple(
            subject.subject_id for subject in claim.retained_handler_subjects
        ) or source_result.component_subject_ids != tuple(
            subject.subject_id for subject in claim.component_subjects
        ):
            raise ValueError("observed detached claim partition drifted from source authority")
        component_refs, _remainder_refs = _validate_candidate_detached_partition(
            claim=claim,
            candidate_inventory=candidate_inventory,
            source_blocks=source_result.source_blocks,
            dispatcher_ref=source_result.dispatcher_block_ref,
            comparison_refs=frozenset(source_result.comparison_region_block_refs),
            expected_component_refs=frozenset(source_result.component_block_refs),
            source_terminal_keys=source_result.terminal_site_keys,
            source_effect_keys=source_result.effect_site_keys,
        )
        if component_refs != frozenset(source_result.component_block_refs):
            raise ValueError("observed detached component drifted from source authority")

    values = (
        claim.claim_id,
        phase,
        corridor_result.result_id,
        source_inventory.graph_fingerprint,
        candidate_inventory.graph_fingerprint,
        source_inventory.generation,
        candidate_inventory.generation,
        True,
        source_result.result_id,
    )
    phase_result = _mint_phase_result(
        result_id=authority_id(("unflatten.detached-dead-handler-component-phase.v1", *values)),
        claim_id=claim.claim_id,
        phase=phase,
        corridor_coverage_result_id=corridor_result.result_id,
        source_fingerprint=source_inventory.graph_fingerprint,
        candidate_fingerprint=candidate_inventory.graph_fingerprint,
        source_generation=source_inventory.generation,
        candidate_generation=candidate_inventory.generation,
        accepted=True,
        source_result_id=source_result.result_id,
    )
    return DetachedDeadHandlerComponentBindingResult(source_result, phase_result)


def _make_detached_binding_entrypoint(
    graph_impl=_graph_bind_detached_dead_handler_component_claim,
):
    """Keep detached authority minting private to the graph-binding closure."""

    source_registry: dict[
        int,
        tuple[
            weakref.ReferenceType[model.DetachedDeadHandlerComponentSourceResult], str,
        ],
    ] = {}
    phase_registry: dict[
        int,
        tuple[
            weakref.ReferenceType[model.DetachedDeadHandlerComponentPhaseResult], str,
        ],
    ] = {}
    lifecycle_secret = object()

    def validate_source(result: model.DetachedDeadHandlerComponentSourceResult) -> None:
        if type(result) is not model.DetachedDeadHandlerComponentSourceResult:
            raise TypeError("detached source result must be closed")
        registered = source_registry.get(id(result))
        if registered is None or registered[0]() is not result:
            raise ValueError("detached source result was not minted by the transaction binder")
        result.__post_init__()
        if registered[1] != authority_id(("unflatten.detached-source-object-seal.v1", result)):
            raise ValueError("detached source result content changed after minting")

    def validate_phase(result: model.DetachedDeadHandlerComponentPhaseResult) -> None:
        if type(result) is not model.DetachedDeadHandlerComponentPhaseResult:
            raise TypeError("detached phase result must be closed")
        registered = phase_registry.get(id(result))
        if registered is None or registered[0]() is not result:
            raise ValueError("detached phase result was not minted by the transaction binder")
        result.__post_init__()
        if registered[1] != authority_id(("unflatten.detached-phase-object-seal.v1", result)):
            raise ValueError("detached phase result content changed after minting")

    def mint_source(**values: object) -> model.DetachedDeadHandlerComponentSourceResult:
        result = object.__new__(model.DetachedDeadHandlerComponentSourceResult)
        for name, value in values.items():
            object.__setattr__(result, name, value)
        result.__post_init__()
        identity = id(result)
        seal = authority_id(("unflatten.detached-source-object-seal.v1", result))

        def cleanup(
            reference: weakref.ReferenceType[model.DetachedDeadHandlerComponentSourceResult],
        ) -> None:
            registered = source_registry.get(identity)
            if registered is not None and registered[0] is reference:
                source_registry.pop(identity, None)

        source_registry[identity] = (weakref.ref(result, cleanup), seal)
        validate_source(result)
        return result

    def mint_phase(**values: object) -> model.DetachedDeadHandlerComponentPhaseResult:
        result = object.__new__(model.DetachedDeadHandlerComponentPhaseResult)
        for name, value in values.items():
            object.__setattr__(result, name, value)
        result.__post_init__()
        identity = id(result)
        seal = authority_id(("unflatten.detached-phase-object-seal.v1", result))

        def cleanup(
            reference: weakref.ReferenceType[model.DetachedDeadHandlerComponentPhaseResult],
        ) -> None:
            registered = phase_registry.get(identity)
            if registered is not None and registered[0] is reference:
                phase_registry.pop(identity, None)

        phase_registry[identity] = (weakref.ref(result, cleanup), seal)
        validate_phase(result)
        return result

    def entrypoint(**kwargs: object) -> DetachedDeadHandlerComponentBindingResult:
        return graph_impl(
            **kwargs,
            _mint_source_result=mint_source,
            _mint_phase_result=mint_phase,
            _lifecycle_secret=lifecycle_secret,
        )

    return entrypoint, validate_source, validate_phase


(
    bind_detached_dead_handler_component_claim,
    validate_detached_source_result,
    validate_detached_phase_result,
) = _make_detached_binding_entrypoint()
del _make_detached_binding_entrypoint
del _graph_bind_detached_dead_handler_component_claim
del _detached_source_result_values


def bind_corridor_coverage_forecast(
    *,
    proposal: model.ProposedUnflattenContract,
    source_inventory: model.SemanticGraphInventory,
    candidate_inventory: model.SemanticGraphInventory,
    phase: model.UnflattenAuthorityPhase,
) -> model.CorridorCoveragePhaseResult | None:
    """Bind the proposal forecast during projected preparation."""
    return _classify_corridor_coverage_forecast(
        proposal=proposal, source_inventory=source_inventory,
        candidate_inventory=candidate_inventory, phase=phase,
    )


def _default_gap_base_phase_result(
    base_result: model.CorridorCoveragePhaseResult,
    forecast: model.DefaultGapInfeasibilityForecast,
) -> model.CorridorCoveragePhaseResult:
    """Reclassify only the v2-linked legacy residual rows as covered."""

    linked = {
        next(
            base.path_id for base in forecast.base_forecast.paths
            if (base.nodes, base.state_merge) == (path.nodes, path.state_merge)
        )
        for path in forecast.paths
    }
    base_residual_coordinates = {
        (path.nodes, path.state_merge)
        for path in forecast.base_forecast.paths
        if path.disposition is model.CorridorPathDisposition.RESIDUAL
    }
    extension_coordinates = {
        (path.nodes, path.state_merge) for path in forecast.paths
    }
    if extension_coordinates != base_residual_coordinates:
        raise ValueError("default-gap extension must cover every base residual coordinate")
    if not linked <= set(base_result.residual_path_ids):
        raise ValueError("default-gap paths are not exact residual phase rows")
    covered = tuple(sorted(set(base_result.covered_path_ids) | linked))
    residual = tuple(sorted(set(base_result.residual_path_ids) - linked))
    content = (
        "unflatten.corridor-coverage-phase.v1", base_result.forecast_id,
        base_result.phase, base_result.source_fingerprint,
        base_result.candidate_fingerprint, base_result.source_generation,
        base_result.candidate_generation, covered, residual,
        base_result.drifted_path_ids, base_result.enumeration_complete,
        base_result.matched_semantic_exclusion_ids,
        base_result.source_dispatcher_reachable,
        base_result.candidate_dispatcher_reachable,
        tuple(item.content_key for item in base_result.semantic_exclusion_correlations),
    )
    if base_result.comparison_region_subject_ids:
        content = (*content, base_result.comparison_region_subject_ids)
    if base_result.dispatcher_subject_id is not None:
        content = (*content, base_result.dispatcher_subject_id)
    return model.CorridorCoveragePhaseResult(
        authority_id(content), base_result.forecast_id, base_result.phase,
        base_result.source_fingerprint, base_result.candidate_fingerprint,
        base_result.source_generation, base_result.candidate_generation,
        covered, residual, base_result.drifted_path_ids,
        base_result.enumeration_complete,
        base_result.matched_semantic_exclusion_ids,
        base_result.source_dispatcher_reachable,
        base_result.candidate_dispatcher_reachable,
        base_result.semantic_exclusion_correlations,
        base_result.comparison_region_subject_ids,
        base_result.dispatcher_subject_id,
    )


def _validate_default_gap_extension(
    *,
    extension: model.DefaultGapInfeasibilityForecast,
    exclusion: model.DefaultGapInfeasibilityExclusion,
    path: model.DefaultGapInfeasibilityPath,
    proposal: model.ProposedUnflattenContract,
    source_inventory: model.SemanticGraphInventory,
    candidate_inventory: model.SemanticGraphInventory,
    source_authority: model.SourceBoundRouteAuthority,
) -> None:
    """Replay the narrow, effect-free default arm from sealed inventory facts."""

    if exclusion.state_identity != proposal.plan_inputs.state_identity:
        raise ValueError("default-gap state identity differs from plan")
    if exclusion.state_width_bytes != 4:
        raise ValueError("default-gap state width is not exact u32")
    if not (
        exclusion.default_entry == exclusion.residual == path.nodes[0]
        and path.nodes[-1] == exclusion.dispatcher
    ):
        raise ValueError(
            "default-gap default entry, residual, and exact path endpoints differ"
        )
    source_by_ref = {
        row.block_ref: row for row in source_inventory.blocks if row.block_ref is not None
    }
    candidate_by_ref = {
        row.block_ref: row for row in candidate_inventory.blocks if row.block_ref is not None
    }
    serial_by_ref = source_inventory.serial_by_ref
    for node in (exclusion.dispatcher, exclusion.default_entry, exclusion.residual, *path.nodes):
        row = source_by_ref.get(node.block_ref)
        if row is None or row.anchor_ea != node.anchor_ea or serial_by_ref.get(node.block_ref) != row.serial:
            raise ValueError("default-gap source coordinate is absent or drifted")
    if path.exclusion_id != exclusion.exclusion_id or path.nodes[0] != exclusion.residual:
        raise ValueError("default-gap residual path linkage differs from exclusion")
    if path not in extension.paths or exclusion not in extension.exclusions:
        raise ValueError("default-gap exclusion/path is foreign to the extension forecast")
    source_edges = {
        (row.owner_serial, row.peer_serial) for row in source_inventory.topology
        if row.kind is model.TopologyIncidenceKind.SUCCESSOR
    }
    def serial(node: model.CorridorCoveragePathNode) -> int:
        return source_by_ref[node.block_ref].serial
    if any(edge not in source_edges for edge in zip(map(serial, path.nodes), map(serial, path.nodes[1:]))):
        raise ValueError("default-gap residual path is absent from source topology")

    proofs = {proof.proof_id: proof for proof in proposal.route_evidence.route_proofs}
    if set(exclusion.route_proof_ids) - set(source_authority.covered_proof_ids):
        raise ValueError("default-gap route proof is not covered by source authority")
    states: set[int] = set()
    seed_destinations: list[
        tuple[model.DefaultGapInitialStateSeed, route_model.SemanticRouteDestination]
    ] = []
    seed_by_proof = {seed.route_proof_id: seed for seed in exclusion.initial_state_seeds}
    for proof_id in exclusion.route_proof_ids:
        proof = proofs.get(proof_id)
        if proof is None or proof.state_write is None:
            raise ValueError("default-gap route proof lacks canonical state write")
        write = proof.state_write
        if write.state_variable != exclusion.state_identity or write.width != 4:
            raise ValueError("default-gap route proof state write differs from exclusion")
        source_row = next((row for row in source_by_ref.values()
                           if row.anchor_ea == proof.source_anchor_ea
                           and type(row.block_ref) is NativeBlockRef
                           and row.block_ref.identity == proof.source_identity), None)
        write_row = next((row for row in source_by_ref.values()
                          if type(row.block_ref) is NativeBlockRef
                          and row.block_ref.identity == write.identity
                          and write.instruction_ea in row.native_instruction_eas), None)
        if source_row is None or write_row is None:
            raise ValueError("default-gap route proof source identity differs from inventory")
        seed = seed_by_proof[proof_id]
        if seed.normalized_state != (int(write.state_constant) & 0xFFFFFFFF):
            raise ValueError(
                "default-gap seed state differs from canonical state write"
            )
        destinations = {int(item.state_constant) & 0xFFFFFFFF for item in proof.destinations}
        if not destinations or seed.normalized_state not in destinations:
            raise ValueError("default-gap seed state is absent from canonical route proof")
        exact_destinations = tuple(
            item for item in proof.destinations
            if (int(item.state_constant) & 0xFFFFFFFF)
            == seed.normalized_state
        )
        if len(exact_destinations) != 1:
            raise ValueError("default-gap seed has no unique canonical proof destination")
        seed_destinations.append((seed, exact_destinations[0]))
        # The seed is the source-bound entry into this closed route family;
        # other proof destinations may be discarded effect branches and are
        # not automatically reachable dispatcher states.
        states.add(seed.normalized_state)
    if tuple(sorted(states)) != exclusion.normalized_reachable_states:
        raise ValueError("default-gap reachable state closure differs from canonical proofs")

    # The only admitted arm is an acyclic u32 EQ chain.  Successor[1] is the
    # explicit taken edge; successor[0] is the fallthrough/default continuation.
    serial_rows = {row.serial: row for row in source_by_ref.values()}
    for seed, destination in seed_destinations:
        state = seed.normalized_state
        current = exclusion.dispatcher
        visited: set[int] = set()
        selected = False
        while current != exclusion.default_entry:
            current_serial = serial(current)
            if current_serial in visited:
                raise ValueError("default-gap dispatcher comparison chain is cyclic")
            visited.add(current_serial)
            row = source_by_ref[current.block_ref]
            if len(row.successor_serials) != 2 or not row.instruction_observations:
                raise ValueError("default-gap dispatcher chain lacks exact conditional topology")
            predicate = row.instruction_observations[-1].predicate_observation
            if (
                predicate is None or predicate.predicate_kind is not model.PredicateKind.EQ
                or predicate.storage_identity != exclusion.state_identity
                or predicate.width != 4
                or predicate.explicit_target_serial != row.successor_serials[1]
            ):
                raise ValueError("default-gap dispatcher chain is not an exact u32 EQ predicate")
            if (state & 0xFFFFFFFF) == predicate.compare_constant:
                target_row = serial_rows.get(predicate.explicit_target_serial)
                if (
                    target_row is None
                    or type(target_row.block_ref) is not NativeBlockRef
                    or target_row.block_ref.identity != destination.target_identity
                    or target_row.anchor_ea != destination.target_anchor_ea
                    or target_row.block_ref in {
                        exclusion.default_entry.block_ref,
                        exclusion.residual.block_ref,
                    }
                ):
                    raise ValueError(
                        "default-gap EQ target differs from canonical proof destination"
                    )
                selected = True
                break
            next_row = serial_rows.get(row.successor_serials[0])
            if next_row is None or next_row.block_ref is None or next_row.anchor_ea is None:
                raise ValueError("default-gap fallthrough is not a native source coordinate")
            current = model.CorridorCoveragePathNode(next_row.block_ref, next_row.anchor_ea)
        else:
            raise ValueError("default-gap reachable state set reaches the default entry")
        if not selected:
            raise ValueError("default-gap seed did not select a canonical handler")

    # Every comparison that falls through eventually reaches the declared
    # default entry; the default edge belongs to the final comparison, not
    # necessarily to the dispatcher root.
    current = exclusion.dispatcher
    visited: set[int] = set()
    while current != exclusion.default_entry:
        current_serial = serial(current)
        if current_serial in visited:
            raise ValueError("default-gap dispatcher comparison chain is cyclic")
        visited.add(current_serial)
        row = source_by_ref[current.block_ref]
        predicate = (
            row.instruction_observations[-1].predicate_observation
            if row.instruction_observations else None
        )
        if (
            len(row.successor_serials) != 2
            or predicate is None
            or predicate.predicate_kind is not model.PredicateKind.EQ
            or predicate.storage_identity != exclusion.state_identity
            or predicate.width != 4
            or predicate.explicit_target_serial != row.successor_serials[1]
        ):
            raise ValueError("default-gap dispatcher chain lacks exact conditional topology")
        next_row = serial_rows.get(row.successor_serials[0])
        if next_row is None or next_row.block_ref is None or next_row.anchor_ea is None:
            raise ValueError("default-gap fallthrough is not a native source coordinate")
        current = model.CorridorCoveragePathNode(next_row.block_ref, next_row.anchor_ea)
    if not visited:
        raise ValueError("default-gap default entry is not reached by an explicit fallthrough")

    residual_nodes = tuple(node for node in path.nodes if node != exclusion.dispatcher)
    region_serials = {serial(node) for node in residual_nodes}
    for index, node in enumerate(path.nodes[:-1]):
        row = source_by_ref[node.block_ref]
        if tuple(row.successor_serials) != (serial(path.nodes[index + 1]),):
            raise ValueError("default-gap residual corridor has an unsealed successor escape")
    for node in residual_nodes:
        row = source_by_ref[node.block_ref]
        if any(pred not in region_serials and pred != serial(exclusion.dispatcher)
               for pred in row.predecessor_serials):
            raise ValueError("default-gap residual corridor has external ingress")
        for observation in row.instruction_observations:
            if (
                observation.is_call
                or observation.instruction_kind not in {InsnKind.NOP, InsnKind.GOTO}
                or observation.predicate_observation is not None
            ):
                raise ValueError("default-gap residual corridor contains an effect or terminal")
    for node in residual_nodes:
        candidate_residual = candidate_by_ref.get(node.block_ref)
        if candidate_residual is not None and candidate_residual.serial in candidate_inventory.reachable_serials:
            raise ValueError("default-gap residual remains candidate-reachable")


def _bind_default_gap_infeasibility_forecast(
    *,
    proposal: model.ProposedUnflattenContract,
    source_inventory: model.SemanticGraphInventory,
    candidate_inventory: model.SemanticGraphInventory,
    phase: model.UnflattenAuthorityPhase,
    source_authority: model.SourceBoundRouteAuthority,
) -> model.DefaultGapInfeasibilityPhaseResult | None:
    """Bind projected default-gap exclusions to one sealed corridor authority."""

    if type(proposal) is not model.ProposedUnflattenContract:
        raise TypeError("default-gap binding requires a closed proposal")
    forecast = proposal.corridor_coverage_forecast
    if forecast is None:
        return None
    if type(forecast) is not model.DefaultGapInfeasibilityForecast:
        raise TypeError("default-gap binding requires DefaultGapInfeasibilityForecast")
    if type(source_authority) is not model.SourceBoundRouteAuthority:
        raise TypeError("default-gap binding requires SourceBoundRouteAuthority")
    validate_source_route_authority(source_authority)
    if source_authority.proposal is not proposal:
        raise ValueError("default-gap proposal is not the source-authority occurrence")
    if phase is not model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT:
        raise ValueError("default-gap binding is projected-preflight only")
    if source_authority.source_fingerprint != source_inventory.graph_fingerprint:
        raise ValueError("default-gap source inventory differs from source authority")
    if source_authority.source_inventory_digest != source_inventory.inventory_digest:
        raise ValueError("default-gap source inventory digest differs from source authority")
    base_proposal = replace(proposal, corridor_coverage_forecast=forecast.base_forecast)
    base_result = _classify_corridor_coverage_forecast(
        proposal=base_proposal, source_inventory=source_inventory,
        candidate_inventory=candidate_inventory, phase=phase,
        default_gap_paths=forecast.paths,
    )
    if base_result is None:
        raise ValueError("default-gap base forecast did not classify")
    for path in forecast.paths:
        exclusion = next(item for item in forecast.exclusions if item.exclusion_id == path.exclusion_id)
        _validate_default_gap_extension(
            extension=forecast, exclusion=exclusion, path=path, proposal=proposal,
            source_inventory=source_inventory, candidate_inventory=candidate_inventory,
            source_authority=source_authority,
        )
    base_result = _default_gap_base_phase_result(base_result, forecast)
    if base_result.residual_path_ids or base_result.drifted_path_ids:
        raise ValueError("default-gap extension did not close every base residual atomically")
    provisional = tuple(
        (item.exclusion_id, item.digest, path.path_id, item.dispatcher,
         item.default_entry, item.residual, item.initial_state_seeds,
         item.route_proof_ids, item.normalized_reachable_states,
         source_inventory.graph_fingerprint, candidate_inventory.graph_fingerprint,
         source_inventory.generation, candidate_inventory.generation)
        for path in forecast.paths
        for item in forecast.exclusions if item.exclusion_id == path.exclusion_id
    )
    result_id = authority_id((
        "unflatten.default-gap-infeasibility-phase.v1", base_result, forecast, phase,
        source_inventory.graph_fingerprint, candidate_inventory.graph_fingerprint,
        source_inventory.generation, candidate_inventory.generation,
        tuple(sorted(item.exclusion_id for item in forecast.exclusions)), provisional,
    ))
    correlations = tuple(sorted((
        model.DefaultGapInfeasibilityCorrelation(
            exclusion.exclusion_id, exclusion.digest, path.path_id,
            exclusion.dispatcher, exclusion.default_entry, exclusion.residual,
            exclusion.initial_state_seeds, exclusion.route_proof_ids,
            exclusion.normalized_reachable_states,
            source_inventory.graph_fingerprint, candidate_inventory.graph_fingerprint,
            source_inventory.generation, candidate_inventory.generation, result_id,
        )
        for path in forecast.paths
        for exclusion in forecast.exclusions if exclusion.exclusion_id == path.exclusion_id
    ), key=lambda item: (item.exclusion_id, item.path_id)))
    return model.DefaultGapInfeasibilityPhaseResult(
        result_id, base_result, forecast, phase,
        source_inventory.graph_fingerprint, candidate_inventory.graph_fingerprint,
        source_inventory.generation, candidate_inventory.generation,
        tuple(sorted(item.exclusion_id for item in forecast.exclusions)), correlations,
    )


def _revalidate_observed_default_gap_infeasibility(
    *,
    projected_result: model.DefaultGapInfeasibilityPhaseResult,
    proposal: model.ProposedUnflattenContract,
    source_inventory: model.SemanticGraphInventory,
    observed_inventory: model.SemanticGraphInventory,
    source_authority: model.SourceBoundRouteAuthority,
) -> model.DefaultGapInfeasibilityPhaseResult:
    """Reclassify only the observed default corridor from projected authority."""
    if type(projected_result) is not model.DefaultGapInfeasibilityPhaseResult:
        raise TypeError("observed default-gap requires the exact projected result")
    if type(proposal) is not model.ProposedUnflattenContract:
        raise TypeError("observed default-gap requires a closed proposal")
    if type(source_authority) is not model.SourceBoundRouteAuthority:
        raise TypeError("observed default-gap requires SourceBoundRouteAuthority")
    validate_source_route_authority(source_authority)
    if source_authority.proposal is not proposal:
        raise ValueError("observed default-gap proposal is not the source-authority occurrence")
    if source_authority.source_fingerprint != source_inventory.graph_fingerprint:
        raise ValueError("observed default-gap source inventory differs from source authority")
    if source_authority.source_inventory_digest != source_inventory.inventory_digest:
        raise ValueError("observed default-gap source inventory digest differs from source authority")
    forecast = proposal.corridor_coverage_forecast
    if type(forecast) is not model.DefaultGapInfeasibilityForecast:
        raise TypeError("observed default-gap requires DefaultGapInfeasibilityForecast")
    projected_result.__post_init__()
    if (
        projected_result.forecast is not forecast
        or projected_result.phase is not model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT
        or projected_result.source_fingerprint != source_inventory.graph_fingerprint
        or projected_result.source_generation != source_inventory.generation
        or projected_result.base_result.forecast_id != forecast.base_forecast.forecast_id
    ):
        raise ValueError("observed default-gap authority is not the prepared occurrence")
    if observed_inventory.phase is not model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY:
        raise ValueError("observed default-gap inventory must be observed post apply")

    # This deliberately consumes the sealed projected route/state payload.  It
    # only replays the legacy corridor partition against observed topology.
    base_proposal = replace(proposal, corridor_coverage_forecast=forecast.base_forecast)
    base_result = _classify_corridor_coverage_forecast(
        proposal=base_proposal, source_inventory=source_inventory,
        candidate_inventory=observed_inventory,
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        projected_correlations=(
            projected_result.base_result.semantic_exclusion_correlations
        ),
        default_gap_paths=forecast.paths,
    )
    if base_result is None:
        raise ValueError("observed default-gap base forecast did not classify")
    observed_by_ref = {
        row.block_ref: row for row in observed_inventory.blocks if row.block_ref is not None
    }
    observed_by_serial = {row.serial: row for row in observed_inventory.blocks}
    for path in forecast.paths:
        exclusion = next(item for item in forecast.exclusions if item.exclusion_id == path.exclusion_id)
        # The complete residual remains forbidden if it survives reachable;
        # absence is permitted.  Surviving rows must retain the exact sealed
        # default-corridor predecessor/successor closure; otherwise a partial
        # observed rewrite could silently introduce ingress or an escape.
        residual_nodes = tuple(item for item in path.nodes if item != exclusion.dispatcher)
        for index, node in enumerate(residual_nodes):
            observed = observed_by_ref.get(node.block_ref)
            if observed is not None and observed.anchor_ea != node.anchor_ea:
                raise ValueError("observed default-gap residual coordinate drifted")
            if observed is None:
                continue
            predecessor_ref = (
                residual_nodes[index - 1] if index else exclusion.dispatcher
            ).block_ref
            predecessor = observed_by_ref.get(predecessor_ref)
            expected_predecessors = (
                {predecessor_ref}
                if predecessor is not None
                and observed.serial in predecessor.successor_serials
                else set()
            )
            actual_predecessors = {
                observed_by_serial[serial].block_ref
                for serial in observed.predecessor_serials
                if serial in observed_by_serial and observed_by_serial[serial].block_ref is not None
            }
            if actual_predecessors != expected_predecessors:
                raise ValueError("observed default-gap residual has external ingress or partial rewiring")
            expected_successor = (
                residual_nodes[index + 1] if index + 1 < len(residual_nodes)
                else exclusion.dispatcher
            )
            actual_successors = {
                observed_by_serial[serial].block_ref
                for serial in observed.successor_serials
                if serial in observed_by_serial and observed_by_serial[serial].block_ref is not None
            }
            if actual_successors != {expected_successor.block_ref}:
                raise ValueError("observed default-gap residual has successor escape or partial rewiring")
            if observed.serial in observed_inventory.reachable_serials:
                raise ValueError("default-gap residual remains candidate-reachable")
    base_result = _default_gap_base_phase_result(base_result, forecast)
    if base_result.residual_path_ids or base_result.drifted_path_ids:
        raise ValueError("observed default-gap extension did not close every residual atomically")

    provisional = tuple(
        (correlation.exclusion_id, correlation.exclusion_digest, correlation.path_id,
         correlation.dispatcher, correlation.default_entry, correlation.residual,
         correlation.initial_state_seeds, correlation.route_proof_ids,
         correlation.normalized_reachable_states,
         source_inventory.graph_fingerprint, observed_inventory.graph_fingerprint,
         source_inventory.generation, observed_inventory.generation)
        for correlation in projected_result.correlations
    )
    result_id = authority_id((
        "unflatten.default-gap-infeasibility-phase.v1", base_result, forecast,
        model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        source_inventory.graph_fingerprint, observed_inventory.graph_fingerprint,
        source_inventory.generation, observed_inventory.generation,
        projected_result.matched_exclusion_ids, provisional,
    ))
    correlations = tuple(
        model.DefaultGapInfeasibilityCorrelation(
            item.exclusion_id, item.exclusion_digest, item.path_id,
            item.dispatcher, item.default_entry, item.residual,
            item.initial_state_seeds, item.route_proof_ids,
            item.normalized_reachable_states,
            source_inventory.graph_fingerprint, observed_inventory.graph_fingerprint,
            source_inventory.generation, observed_inventory.generation, result_id,
        )
        for item in projected_result.correlations
    )
    return model.DefaultGapInfeasibilityPhaseResult(
        result_id, base_result, forecast,
        model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        source_inventory.graph_fingerprint, observed_inventory.graph_fingerprint,
        source_inventory.generation, observed_inventory.generation,
        projected_result.matched_exclusion_ids, correlations,
    )


def _make_default_gap_binding_entrypoints(
    projected_impl=_bind_default_gap_infeasibility_forecast,
    observed_impl=_revalidate_observed_default_gap_infeasibility,
):
    """Keep default-gap phase results as transaction-binder occurrences."""
    phase_registry: dict[
        int,
        tuple[weakref.ReferenceType[model.DefaultGapInfeasibilityPhaseResult], str],
    ] = {}

    def validate_phase(result: model.DefaultGapInfeasibilityPhaseResult) -> None:
        if type(result) is not model.DefaultGapInfeasibilityPhaseResult:
            raise TypeError("default-gap phase result must be closed")
        registered = phase_registry.get(id(result))
        if registered is None or registered[0]() is not result:
            raise ValueError("default-gap phase result was not minted by the transaction binder")
        result.__post_init__()
        if registered[1] != authority_id(("unflatten.default-gap-phase-object-seal.v1", result)):
            raise ValueError("default-gap phase result content changed after minting")

    def register_phase(
        result: model.DefaultGapInfeasibilityPhaseResult,
    ) -> model.DefaultGapInfeasibilityPhaseResult:
        if type(result) is not model.DefaultGapInfeasibilityPhaseResult:
            raise TypeError("default-gap phase result must be closed")
        result.__post_init__()
        identity = id(result)
        registered = phase_registry.get(identity)
        if registered is not None and registered[0]() is result:
            raise ValueError("default-gap phase result occurrence was already minted")
        seal = authority_id(("unflatten.default-gap-phase-object-seal.v1", result))

        def cleanup(reference: weakref.ReferenceType[model.DefaultGapInfeasibilityPhaseResult]) -> None:
            registered = phase_registry.get(identity)
            if registered is not None and registered[0] is reference:
                phase_registry.pop(identity, None)

        phase_registry[identity] = (weakref.ref(result, cleanup), seal)
        validate_phase(result)
        return result

    def entrypoint(**kwargs: object) -> model.DefaultGapInfeasibilityPhaseResult | None:
        result = projected_impl(**kwargs)
        return None if result is None else register_phase(result)

    def observed_entrypoint(**kwargs: object) -> model.DefaultGapInfeasibilityPhaseResult:
        projected = kwargs.get("projected_result")
        if type(projected) is not model.DefaultGapInfeasibilityPhaseResult:
            raise TypeError("observed default-gap requires the exact projected result")
        validate_phase(projected)
        return register_phase(observed_impl(**kwargs))

    return entrypoint, validate_phase, observed_entrypoint


(
    bind_default_gap_infeasibility_forecast,
    validate_default_gap_infeasibility_phase_result,
    revalidate_observed_default_gap_infeasibility,
) = _make_default_gap_binding_entrypoints()
del _make_default_gap_binding_entrypoints
del _bind_default_gap_infeasibility_forecast


def revalidate_observed_corridor_coverage(
    *,
    projected_result: model.CorridorCoveragePhaseResult | None,
    proposal: model.ProposedUnflattenContract,
    claims: tuple[model.UnflattenClaim, ...],
    source_inventory: model.SemanticGraphInventory,
    observed_inventory: model.SemanticGraphInventory,
) -> model.CorridorCoveragePhaseResult | None:
    """Reclassify observed corridor topology from the sealed forecast occurrence."""
    forecast = proposal.corridor_coverage_forecast
    if forecast is None:
        if projected_result is not None:
            raise ValueError("observed corridor result exists without a prepared forecast")
        return None
    if type(projected_result) is not model.CorridorCoveragePhaseResult:
        raise TypeError("observed corridor requires the exact projected result")
    projected_result.__post_init__()
    if (
        projected_result.forecast_id != forecast.forecast_id
        or projected_result.phase is not model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT
        or projected_result.source_fingerprint != source_inventory.graph_fingerprint
    ):
        raise ValueError("observed corridor authority is not the prepared occurrence")
    if type(claims) is not tuple:
        raise TypeError("observed corridor claims must be the sealed preparation tuple")
    prepared_claim_ids = {claim.claim_id for claim in claims}
    if (
        len(prepared_claim_ids) != len(claims)
        or any(
            correlation.claim_id not in prepared_claim_ids
            for correlation in projected_result.semantic_exclusion_correlations
        )
    ):
        raise ValueError("observed corridor claims differ from prepared authority")
    if observed_inventory.phase is not model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY:
        raise ValueError("observed corridor inventory must be observed post apply")
    return _classify_corridor_coverage_forecast(
        proposal=proposal, source_inventory=source_inventory,
        candidate_inventory=observed_inventory,
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        claims=claims,
        projected_correlations=projected_result.semantic_exclusion_correlations,
    )


def _classify_retired_dispatcher_infrastructure_claim(
    *,
    claim: model.RetiredDispatcherInfrastructureClaim,
    proposal: model.ProposedUnflattenContract,
    source_inventory: model.SemanticGraphInventory,
    projected_inventory: model.SemanticGraphInventory,
    phase: model.UnflattenAuthorityPhase = model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
) -> RetiredInfrastructureBindingResult:
    """Bind every planned member and classify retirement by inventory reachability.

    A retired member may be physically missing or remain uniquely indexed while
    absent from the exact candidate reachable closure. Retained members must be
    unique and reachable. No raw serial is stored in the result's authority
    catalog; serials remain phase-local rows on the returned bindings.
    """

    if type(claim) is not model.RetiredDispatcherInfrastructureClaim:
        raise TypeError("retirement binding requires a closed retirement claim")
    if type(proposal) is not model.ProposedUnflattenContract:
        raise TypeError("retirement binding requires a closed proposal")
    if claim not in proposal.claims:
        raise ValueError("retirement claim is foreign to the proposal")
    if type(phase) is not model.UnflattenAuthorityPhase:
        raise TypeError("retirement binding phase must be an UnflattenAuthorityPhase")
    if phase is not model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT:
        raise ValueError("retirement binding must be projected preflight")
    if type(source_inventory) is not model.SemanticGraphInventory:
        raise TypeError("retirement source_inventory must be a closed semantic inventory")
    if type(projected_inventory) is not model.SemanticGraphInventory:
        raise TypeError("retirement projected_inventory must be a closed semantic inventory")
    model.validate_semantic_graph_inventory(source_inventory)
    model.validate_semantic_graph_inventory(projected_inventory)
    if source_inventory.phase is not model.UnflattenAuthorityPhase.PRODUCER_FORECAST:
        raise ValueError("retirement source inventory must be producer forecast")
    if projected_inventory.phase is not phase:
        raise ValueError("retirement projected inventory phase differs from requested phase")
    generation = source_inventory.generation
    source_graph_fingerprint = source_inventory.graph_fingerprint
    projected_graph_fingerprint = projected_inventory.graph_fingerprint
    catalog_rows = retirement_member_catalog(proposal, claim)
    catalog = proposal.source_identity_catalog
    subjects_by_ref = {member.block_ref: member for member in claim.member_subjects}
    subjects = []
    for row in catalog_rows:
        subject = subjects_by_ref.get(row.block_ref)
        if subject is None:
            subject = _subject_factory(
                model.SemanticSubjectRef,
                kind=model.SemanticSubjectKind.BLOCK,
                role=model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE,
                block_ref=row.block_ref,
                anchor_ea=row.anchor_ea,
                locator=model.BlockSubjectLocator(row.block_ref, row.anchor_ea),
            )
        subjects.append(subject)
    expected_ids = {subject.subject_id for subject in subjects}
    source_bindings = tuple(sorted(
        (binding for binding in source_inventory.bindings if binding.subject.subject_id in expected_ids),
        key=lambda item: item.subject.subject_id,
    ))
    projected_bindings = tuple(sorted(
        (binding for binding in projected_inventory.bindings if binding.subject.subject_id in expected_ids),
        key=lambda item: item.subject.subject_id,
    ))
    if len(source_bindings) != len(expected_ids) or len(projected_bindings) != len(expected_ids):
        raise ValueError("retirement inventories lack the exact member binding rows")
    result = object.__new__(RetiredInfrastructureBindingResult)
    for name, value in {
        "claim": claim, "proposal": proposal,
        "source_inventory": source_inventory,
        "projected_inventory": projected_inventory,
        "source_catalog": catalog,
        "member_catalog": catalog_rows, "source_bindings": source_bindings,
        "projected_bindings": projected_bindings,
        "generation": generation,
    }.items():
        object.__setattr__(result, name, value)
    object.__setattr__(
        result, "phase_result",
        _build_retirement_phase_result(
            claim=claim, proposal=proposal,
            source_inventory=source_inventory,
            projected_inventory=projected_inventory, phase=phase,
        ),
    )
    object.__setattr__(result, "_content_seal", _retirement_binding_seal(result))
    result._validate_fields()
    return result


_graph_bind_retired_dispatcher_infrastructure_claim = (
    _classify_retired_dispatcher_infrastructure_claim
)


def _make_retirement_binding_entrypoint(
    graph_impl=_graph_bind_retired_dispatcher_infrastructure_claim,
):
    """Keep retirement phase authority attached to the transaction binder."""

    phase_registry: dict[
        int,
        tuple[weakref.ReferenceType[model.RetirementPhaseResult], str],
    ] = {}

    def validate_phase(result: model.RetirementPhaseResult) -> None:
        if type(result) is not model.RetirementPhaseResult:
            raise TypeError("retirement phase result must be closed")
        registered = phase_registry.get(id(result))
        if registered is None or registered[0]() is not result:
            raise ValueError("retirement phase result was not minted by the transaction binder")
        result.__post_init__()
        if registered[1] != authority_id(("unflatten.retirement-phase-object-seal.v1", result)):
            raise ValueError("retirement phase result content changed after minting")

    def register_phase(
        result: model.RetirementPhaseResult,
    ) -> model.RetirementPhaseResult:
        if type(result) is not model.RetirementPhaseResult:
            raise TypeError("retirement phase result must be closed")
        result.__post_init__()
        identity = id(result)
        registered = phase_registry.get(identity)
        if registered is not None and registered[0]() is result:
            raise ValueError("retirement phase result occurrence was already minted")
        seal = authority_id(("unflatten.retirement-phase-object-seal.v1", result))

        def cleanup(reference: weakref.ReferenceType[model.RetirementPhaseResult]) -> None:
            registered = phase_registry.get(identity)
            if registered is not None and registered[0] is reference:
                phase_registry.pop(identity, None)

        phase_registry[identity] = (weakref.ref(result, cleanup), seal)
        validate_phase(result)
        return result

    def entrypoint(**kwargs: object) -> RetiredInfrastructureBindingResult:
        result = graph_impl(**kwargs)
        phase_result = result.phase_result
        assert phase_result is not None
        register_phase(phase_result)
        return result

    def observed_entrypoint(**kwargs: object) -> model.RetirementPhaseResult:
        projected_result = kwargs.get("projected_result")
        if type(projected_result) is not model.RetirementPhaseResult:
            raise TypeError("observed retirement requires the exact projected result")
        validate_phase(projected_result)
        return register_phase(_revalidate_observed_retired_dispatcher_infrastructure(**kwargs))

    return entrypoint, validate_phase, observed_entrypoint


(
    bind_retired_dispatcher_infrastructure_claim,
    validate_retirement_phase_result,
    revalidate_observed_retired_dispatcher_infrastructure,
) = _make_retirement_binding_entrypoint()
del _make_retirement_binding_entrypoint
del _graph_bind_retired_dispatcher_infrastructure_claim


def _revalidate_observed_retired_dispatcher_infrastructure(
    *,
    projected_result: model.RetirementPhaseResult,
    claim: model.RetiredDispatcherInfrastructureClaim,
    proposal: model.ProposedUnflattenContract,
    source_inventory: model.SemanticGraphInventory,
    observed_inventory: model.SemanticGraphInventory,
) -> model.RetirementPhaseResult:
    """Classify observed retirement from one exact projected occurrence.

    This is intentionally an observation adapter, not a planner binder: the
    caller supplies the already-bound claim/result occurrence and the only
    live input is the observed inventory.
    """
    if type(projected_result) is not model.RetirementPhaseResult:
        raise TypeError("observed retirement requires the exact projected result")
    projected_result.__post_init__()
    if (
        projected_result.claim_id != claim.claim_id
        or projected_result.catalog_id
        != getattr(proposal.retirement_candidate_catalog, "catalog_id", None)
        or projected_result.source_fingerprint != source_inventory.graph_fingerprint
        or projected_result.phase
        is not model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT
    ):
        raise ValueError("observed retirement authority is not the prepared occurrence")
    if projected_result.phase is not model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT:
        raise ValueError("observed retirement parent must be projected preflight")
    if observed_inventory.phase is not model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY:
        raise ValueError("observed retirement inventory must be observed post apply")
    source_by_id = {item.subject.subject_id: item for item in source_inventory.bindings}
    observed_by_id = {item.subject.subject_id: item for item in observed_inventory.bindings}
    members = []
    for parent in projected_result.members:
        source = source_by_id.get(parent.source_binding.subject.subject_id)
        candidate = observed_by_id.get(parent.candidate_binding.subject.subject_id)
        if source is not parent.source_binding or candidate is None:
            raise ValueError("observed retirement binding domain differs from prepared result")
        eligible = parent.candidate_id is not None
        if candidate.status in {
            model.SubjectBindingStatus.AMBIGUOUS,
            model.SubjectBindingStatus.STALE_GENERATION,
        }:
            classification, reason = model.RetirementPhaseClassification.DRIFTED, "candidate_identity_drift"
        elif candidate.status is model.SubjectBindingStatus.MISSING:
            classification = (model.RetirementPhaseClassification.RETIRED if eligible else model.RetirementPhaseClassification.UNACCOUNTED)
            reason = "candidate_missing" if eligible else "unsupported_missing_member"
        elif candidate.status is model.SubjectBindingStatus.UNIQUE and candidate.serial is not None:
            reachable = candidate.serial in observed_inventory.reachable_serials
            classification = (model.RetirementPhaseClassification.RETAINED if reachable else (model.RetirementPhaseClassification.RETIRED if eligible else model.RetirementPhaseClassification.UNACCOUNTED))
            reason = "candidate_reachable" if reachable else ("candidate_unreachable" if eligible else "unsupported_unreachable_member")
        else:
            classification, reason = model.RetirementPhaseClassification.DRIFTED, "candidate_binding_invalid"
        member = object.__new__(model.RetirementPhaseMember)
        for name, value in {
            "block_ref": parent.block_ref, "anchor_ea": parent.anchor_ea,
            "classification": classification, "candidate_id": parent.candidate_id,
            "candidate_reachable": (candidate.serial in observed_inventory.reachable_serials if candidate.status is model.SubjectBindingStatus.UNIQUE and candidate.serial is not None else None),
            "reason": reason, "source_binding": source, "candidate_binding": candidate,
        }.items():
            object.__setattr__(member, name, value)
        member.__post_init__()
        members.append(member)
    members = tuple(sorted(members, key=canonical_bytes))
    result = object.__new__(model.RetirementPhaseResult)
    values = {
        "catalog_id": projected_result.catalog_id, "claim_id": projected_result.claim_id,
        "phase": model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        "source_fingerprint": source_inventory.graph_fingerprint,
        "candidate_fingerprint": observed_inventory.graph_fingerprint,
        "source_generation": source_inventory.generation,
        "candidate_generation": observed_inventory.generation, "members": members,
    }
    object.__setattr__(result, "result_id", authority_id((
        "unflatten.dispatcher-retirement-phase.v1", values["catalog_id"],
        values["claim_id"], values["phase"], values["source_fingerprint"],
        values["candidate_fingerprint"], values["source_generation"],
        values["candidate_generation"], members,
    )))
    for name, value in values.items(): object.__setattr__(result, name, value)
    result.__post_init__()
    return result


def _locator_refs(subject: model.SemanticSubjectRef) -> tuple[object, ...]:
    locator = subject.locator
    if type(locator) is model.BlockSubjectLocator:
        return (locator.block_ref,)
    if type(locator) is model.LogicalFunctionExitSubjectLocator:
        return (locator.block_ref,)
    if type(locator) is model.EdgeSubjectLocator:
        return (locator.source_ref, locator.target_ref)
    if type(locator) is model.RouteSubjectLocator:
        return (locator.source_ref, *(item.block_ref for item in locator.native_destination_members()), *(item.block_ref for item in locator.dag_endpoint_members()))
    if type(locator) is model.EffectSubjectLocator:
        return (locator.owner_ref,)
    if type(locator) is model.HandlerSubjectLocator:
        return (locator.block_ref,)
    if type(locator) is model.TerminalSubjectLocator:
        return (locator.block_ref,)
    if type(locator) is model.ValueFlowSubjectLocator:
        return tuple(locator.redirect_owner_refs)
    if type(locator) is model.CorridorSubjectLocator:
        return (locator.entry_ref, *locator.member_refs)
    raise TypeError("subject locator is not closed")


def _witness_anchor_matches(
    witness: model.SourceBlockIdentityWitness,
    anchor_ea: int,
    origins: Sequence[int] | None = None,
) -> bool:
    """Match the witness's one canonical anchor under its native scope."""

    supplied = tuple(witness.native_instruction_eas if origins is None else origins)
    ref = witness.block_ref
    return int(anchor_ea) == witness.anchor_ea and (
        int(anchor_ea) in supplied
        or (
            type(ref) is NativeBlockRef
            and ref.identity.native_ranges.contains(int(anchor_ea))
        )
    )


def bind_subjects(
    subjects: Sequence[model.SemanticSubjectRef],
    *,
    catalog: model.SourceIdentityCatalog,
    phase: model.UnflattenAuthorityPhase,
    graph_fingerprint: str,
    generation: int,
    serial_by_ref: Mapping[object, int],
    native_instruction_eas_by_ref: Mapping[object, Sequence[int]] | None = None,
) -> tuple[model.PhaseSubjectBinding, ...]:
    """Bind every subject against one immutable catalog and exact generation.

    The binding operation deliberately accepts no serial fallback and no
    nearest-anchor matching.  A missing, duplicate, foreign, stale, or
    partially matching row is a rejection rather than an ambiguous binding.
    """

    if type(catalog) is not model.SourceIdentityCatalog:
        raise TypeError("catalog must be a SourceIdentityCatalog")
    validate_canonical_roundtrip(catalog, model.SourceIdentityCatalog)
    if type(phase) is not model.UnflattenAuthorityPhase:
        raise TypeError("phase must be an UnflattenAuthorityPhase")
    if type(graph_fingerprint) is not str or not graph_fingerprint.startswith("sha256:"):
        raise ValueError("graph_fingerprint must be a canonical ID")
    if type(generation) is not int or isinstance(generation, bool) or generation != catalog.generation:
        raise ValueError("binding generation does not match source catalog")
    witnesses = {item.block_ref: item for item in catalog.blocks}
    if len(witnesses) != len(catalog.blocks):
        raise ValueError("source catalog contains duplicate block references")
    if not set(witnesses) <= set(serial_by_ref):
        raise ValueError("serial binding must cover the source catalog")
    extra_refs = set(serial_by_ref) - set(witnesses)
    logical_locators = {
        subject.locator.block_ref: subject.locator
        for subject in subjects
        if type(subject) is model.SemanticSubjectRef
        and type(subject.locator) is model.LogicalFunctionExitSubjectLocator
    }
    if any(type(ref) is not LogicalBlockRef for ref in extra_refs):
        raise ValueError("serial binding extras must be logical source references")
    for ref in extra_refs:
        locator = logical_locators.get(ref)
        if locator is None or serial_by_ref[ref] != locator.serial:
            raise ValueError("serial binding logical function-exit coordinate is not exact")
    serials = tuple(serial_by_ref.values())
    if any(type(serial) is not int or serial < 0 for serial in serials):
        raise ValueError("serial bindings must be exact non-negative integers")
    if len(set(serials)) != len(serials):
        raise ValueError("serial bindings must be unique")
    origins = (
        {
            ref: witness.native_instruction_eas for ref, witness in witnesses.items()
        }
        if native_instruction_eas_by_ref is None
        else native_instruction_eas_by_ref
    )
    if set(origins) != set(witnesses):
        raise ValueError("native-origin binding must exactly cover the source catalog")

    result: list[model.PhaseSubjectBinding] = []
    seen_subjects: set[str] = set()
    for subject in subjects:
        if type(subject) is not model.SemanticSubjectRef:
            raise TypeError("subjects must contain SemanticSubjectRef values")
        validate_canonical_roundtrip(subject, model.SemanticSubjectRef)
        if subject.subject_id in seen_subjects:
            raise ValueError("subject bindings contain duplicate subjects")
        seen_subjects.add(subject.subject_id)
        if type(subject.locator) is model.LogicalFunctionExitSubjectLocator:
            locator = subject.locator
            if serial_by_ref.get(locator.block_ref) != locator.serial:
                result.append(model.PhaseSubjectBinding(
                    subject=subject,
                    phase=phase,
                    block_ref=None,
                    graph_fingerprint=graph_fingerprint,
                    generation=generation,
                    status=model.SubjectBindingStatus.MISSING,
                    serial=None,
                    anchor_ea=None,
                    native_instruction_eas=(),
                    role=subject.role,
                ))
                continue
            result.append(model.PhaseSubjectBinding(
                subject=subject,
                phase=phase,
                block_ref=locator.block_ref,
                graph_fingerprint=graph_fingerprint,
                generation=generation,
                status=model.SubjectBindingStatus.UNIQUE,
                serial=locator.serial,
                anchor_ea=None,
                native_instruction_eas=(),
                role=subject.role,
            ))
            continue
        refs = _locator_refs(subject)
        native_refs = tuple(ref for ref in refs if type(ref) is not LogicalBlockRef)
        if any(ref not in witnesses for ref in native_refs):
            raise ValueError("subject contains a foreign or missing source reference")
        for ref in native_refs:
            expected = tuple(witnesses[ref].native_instruction_eas)
            supplied = tuple(origins[ref])
            if supplied != expected:
                raise ValueError(
                    "native identity instruction EAs do not exactly match catalog "
                    f"ref={ref!r} supplied={supplied!r} expected={expected!r}"
                )
        if subject.kind is model.SemanticSubjectKind.VALUE_FLOW:
            result.append(model.PhaseSubjectBinding(
                subject=subject,
                phase=phase,
                block_ref=None,
                graph_fingerprint=graph_fingerprint,
                generation=generation,
                status=model.SubjectBindingStatus.MISSING,
                serial=None,
                anchor_ea=None,
                native_instruction_eas=(),
                role=subject.role,
            ))
            continue
        owner = subject.block_ref
        if owner not in witnesses or subject.anchor_ea is None:
            raise ValueError("subject has no exact owner anchor")
        witness = witnesses[owner]
        is_route_endpoint = subject.role in {
            model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE,
            model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION,
        }
        route_anchor_matches = (
            is_route_endpoint
            and type(owner) is NativeBlockRef
            and owner.identity.native_ranges.contains(subject.anchor_ea)
        )
        if not route_anchor_matches and (
            subject.anchor_ea != witness.anchor_ea
            or not _witness_anchor_matches(witness, subject.anchor_ea)
        ):
            raise ValueError("subject anchor is a near-match for its source witness")
        result.append(model.PhaseSubjectBinding(
            subject=subject,
            phase=phase,
            block_ref=owner,
            graph_fingerprint=graph_fingerprint,
            generation=generation,
            status=model.SubjectBindingStatus.UNIQUE,
            serial=serial_by_ref[owner],
            anchor_ea=subject.anchor_ea,
            native_instruction_eas=witness.native_instruction_eas,
            role=subject.role,
        ))
    return tuple(sorted(result, key=lambda item: item.subject.subject_id))


bind_source_subjects = bind_subjects


def _bounded_native_ea_diagnostic(values: tuple[int, ...], *, limit: int = 8) -> str:
    """Render native origins compactly without exposing a full ref repr."""
    shown = ", ".join(f"0x{ea:X}" for ea in values[:limit])
    if len(values) > limit:
        shown = f"{shown}, ...+{len(values) - limit}"
    return f"({shown})"


def _projected_native_origin_mismatch(
    *,
    serial: int,
    anchor_ea: int,
    supplied: tuple[int, ...],
    expected: tuple[int, ...],
) -> ValueError:
    """Return one bounded, anchored native-origin mismatch diagnostic."""
    site = (
        f"blk{serial}@0x{anchor_ea:X}"
        if type(serial) is int
        and type(anchor_ea) is int
        and 0 <= anchor_ea < 0xFFFFFFFFFFFFFFFF
        else "native@unanchored"
    )
    return ValueError(
        "native identity instruction EAs do not exactly match catalog "
        f"{site} "
        f"supplied={_bounded_native_ea_diagnostic(supplied)} "
        f"expected={_bounded_native_ea_diagnostic(expected)}"
    )


def _validated_source_logical_function_exit_refs(
    source_inventory: model.SemanticGraphInventory | None,
    *,
    catalog: model.SourceIdentityCatalog,
    generation: int,
) -> frozenset[LogicalBlockRef]:
    """Return logical exits proven by one sealed producer inventory.

    A candidate graph cannot nominate a missing logical route endpoint by
    carrying a sibling ``LogicalFunctionExitSubjectLocator`` itself.  Only the
    immutable producer inventory may establish that source ownership, and it
    must contain exactly one matching, uniquely bound locator at its sealed
    ref/serial coordinate.
    """

    if source_inventory is None:
        return frozenset()
    if type(source_inventory) is not model.SemanticGraphInventory:
        raise TypeError("source_inventory must be SemanticGraphInventory or None")
    model.validate_semantic_graph_inventory(source_inventory)
    if source_inventory.phase is not model.UnflattenAuthorityPhase.PRODUCER_FORECAST:
        raise ValueError("logical endpoint source inventory must be producer forecast")
    if source_inventory.generation != generation or generation != catalog.generation:
        raise ValueError("logical endpoint source inventory generation differs from catalog")

    bindings_by_subject_id = {
        binding.subject.subject_id: binding
        for binding in source_inventory.bindings
    }
    endpoint_subjects: dict[LogicalBlockRef, list[model.SemanticSubjectRef]] = {}
    for subject in source_inventory.subjects:
        if (
            subject.role is model.SemanticSubjectRole.SEMANTIC_DAG_ENDPOINT
            and type(subject.locator) is model.LogicalFunctionExitSubjectLocator
        ):
            endpoint_subjects.setdefault(subject.locator.block_ref, []).append(subject)

    proven: set[LogicalBlockRef] = set()
    for ref, subjects in endpoint_subjects.items():
        if len(subjects) != 1:
            raise ValueError("logical endpoint source inventory is nonunique")
        subject = subjects[0]
        locator = subject.locator
        assert type(locator) is model.LogicalFunctionExitSubjectLocator
        binding = bindings_by_subject_id.get(subject.subject_id)
        if (
            binding is None
            or binding.status is not model.SubjectBindingStatus.UNIQUE
            or binding.block_ref != locator.block_ref
            or binding.serial != locator.serial
            or binding.anchor_ea is not None
            or binding.native_instruction_eas != ()
        ):
            raise ValueError("logical endpoint source inventory binding drift")
        proven.add(ref)
    return frozenset(proven)


def bind_projected_subjects(
    subjects: Sequence[model.SemanticSubjectRef],
    *,
    catalog: model.SourceIdentityCatalog,
    phase: model.UnflattenAuthorityPhase,
    graph_fingerprint: str,
    generation: int,
    serial_by_ref: Mapping[object, int],
    native_instruction_eas_by_ref: Mapping[object, Sequence[int]] | None = None,
    source_inventory: model.SemanticGraphInventory | None = None,
    observed_logical_endpoint_occurrences: tuple[
        model.ObservedLogicalEndpointOccurrence, ...
    ] = (),
) -> tuple[model.PhaseSubjectBinding, ...]:
    """Bind source subjects against a possibly lossy projected graph.

    The projected map is intentionally allowed to omit source references.  A
    subject whose exact owner is absent is represented as ``MISSING``; it is
    not rebound by serial, anchor proximity, or a fabricated projected ref.
    """

    if type(catalog) is not model.SourceIdentityCatalog:
        raise TypeError("catalog must be a SourceIdentityCatalog")
    validate_canonical_roundtrip(catalog, model.SourceIdentityCatalog)
    if type(phase) is not model.UnflattenAuthorityPhase:
        raise TypeError("phase must be an UnflattenAuthorityPhase")
    if type(graph_fingerprint) is not str or not graph_fingerprint.startswith("sha256:"):
        raise ValueError("graph_fingerprint must be a canonical ID")
    if type(generation) is not int or isinstance(generation, bool) or generation != catalog.generation:
        raise ValueError("binding generation does not match source catalog")
    witnesses = {item.block_ref: item for item in catalog.blocks}
    if len(witnesses) != len(catalog.blocks):
        raise ValueError("source catalog contains duplicate block references")
    extra_refs = {
        ref for ref in serial_by_ref
        if ref not in witnesses
    }
    logical_locators = {
        subject.locator.block_ref: subject.locator
        for subject in subjects
        if type(subject) is model.SemanticSubjectRef
        and type(subject.locator) is model.LogicalFunctionExitSubjectLocator
    }
    if type(observed_logical_endpoint_occurrences) is not tuple or any(
        type(item) is not model.ObservedLogicalEndpointOccurrence
        for item in observed_logical_endpoint_occurrences
    ):
        raise TypeError(
            "observed logical endpoint occurrences must be an exact tuple",
        )
    for occurrence in observed_logical_endpoint_occurrences:
        _validate_observed_logical_endpoint_occurrence(occurrence)
    if (
        observed_logical_endpoint_occurrences
        and phase is not model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY
    ):
        raise ValueError(
            "observed logical endpoint occurrences require observed phase",
        )
    occurrence_by_ref = {
        item.logical_ref: item
        for item in observed_logical_endpoint_occurrences
    }
    if len(occurrence_by_ref) != len(observed_logical_endpoint_occurrences):
        raise ValueError("observed logical endpoint occurrences are nonunique")
    if len({
        item.observed_serial for item in observed_logical_endpoint_occurrences
    }) != len(observed_logical_endpoint_occurrences):
        raise ValueError("observed logical endpoint serials are nonunique")
    if any(type(ref) not in (PlanBlockRef, LogicalBlockRef) for ref in extra_refs):
        raise ValueError("projected serial binding contains a foreign source reference")
    for ref in extra_refs:
        if type(ref) is not LogicalBlockRef:
            continue
        locator = logical_locators.get(ref)
        occurrence = occurrence_by_ref.get(ref)
        exact_source_coordinate = (
            locator is not None and serial_by_ref[ref] == locator.serial
        )
        exact_observed_occurrence = (
            locator is not None
            and occurrence is not None
            and occurrence.projected_serial == locator.serial
            and occurrence.observed_serial == serial_by_ref[ref]
        )
        if not exact_source_coordinate and not exact_observed_occurrence:
            raise ValueError("projected logical function-exit coordinate is not exact")
    serials = tuple(serial_by_ref.values())
    if any(type(serial) is not int or serial < 0 for serial in serials):
        raise ValueError("serial bindings must be exact non-negative integers")
    if len(set(serials)) != len(serials):
        raise ValueError("serial bindings must be unique")
    origins = (
        {
            ref: witness.native_instruction_eas
            for ref, witness in witnesses.items()
            if ref in serial_by_ref
        }
        if native_instruction_eas_by_ref is None
        else native_instruction_eas_by_ref
    )
    if native_instruction_eas_by_ref is not None and set(origins) != set(serial_by_ref):
        raise ValueError("projected native-origin binding must cover every projected reference")
    if any(ref not in serial_by_ref for ref in origins):
        raise ValueError("projected native-origin binding contains a foreign reference")
    for ref, supplied in origins.items():
        if ref in witnesses:
            expected_origins = tuple(witnesses[ref].native_instruction_eas)
            supplied_origins = tuple(supplied)
            if supplied_origins != expected_origins and not (
                phase in {
                    model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
                    model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
                }
                and model._phase_native_origin_subset_preserves_anchor(
                    ref,
                    witnesses[ref].anchor_ea,
                    supplied_origins,
                    expected_origins,
                )
            ):
                raise _projected_native_origin_mismatch(
                    serial=serial_by_ref[ref],
                    anchor_ea=witnesses[ref].anchor_ea,
                    supplied=supplied_origins,
                    expected=expected_origins,
                )
        if ref in extra_refs:
            if type(ref) is LogicalBlockRef:
                if tuple(supplied) != ():
                    raise ValueError("logical function-exit origin must remain anchorless")
            elif (
                type(supplied) is not tuple
                or not supplied
                or any(type(ea) is not int or ea < 0 for ea in supplied)
                or len(set(supplied)) != len(supplied)
            ):
                raise ValueError("plan helper origins must be exact and nonempty")

    result: list[model.PhaseSubjectBinding] = []
    seen_subjects: set[str] = set()
    # A logical endpoint has no native catalog witness.  Its absence can be
    # interpreted as lossy projection only during observation, and only from
    # the separately sealed producer inventory -- never from candidate input.
    source_owned_logical_refs = (
        _validated_source_logical_function_exit_refs(
            source_inventory,
            catalog=catalog,
            generation=generation,
        )
        if phase is model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY
        else frozenset()
    )
    if any(
        ref not in source_owned_logical_refs
        for ref in occurrence_by_ref
    ):
        raise ValueError(
            "observed logical endpoint occurrence is not source-owned",
        )
    for subject in subjects:
        if type(subject) is not model.SemanticSubjectRef:
            raise TypeError("subjects must contain SemanticSubjectRef values")
        validate_canonical_roundtrip(subject, model.SemanticSubjectRef)
        if subject.subject_id in seen_subjects:
            raise ValueError("subject bindings contain duplicate subjects")
        seen_subjects.add(subject.subject_id)
        if type(subject.locator) is model.LogicalFunctionExitSubjectLocator:
            locator = subject.locator
            present = serial_by_ref.get(locator.block_ref)
            if present is None:
                result.append(model.PhaseSubjectBinding(
                    subject=subject,
                    phase=phase,
                    block_ref=None,
                    graph_fingerprint=graph_fingerprint,
                    generation=generation,
                    status=model.SubjectBindingStatus.MISSING,
                    serial=None,
                    anchor_ea=None,
                    native_instruction_eas=(),
                    role=subject.role,
                ))
                continue
            if present != locator.serial:
                occurrence = occurrence_by_ref.get(locator.block_ref)
                if (
                    occurrence is None
                    or occurrence.projected_serial != locator.serial
                    or occurrence.observed_serial != present
                ):
                    raise ValueError("projected logical function-exit serial drift")
            result.append(model.PhaseSubjectBinding(
                subject=subject,
                phase=phase,
                block_ref=locator.block_ref,
                graph_fingerprint=graph_fingerprint,
                generation=generation,
                status=model.SubjectBindingStatus.UNIQUE,
                serial=present,
                anchor_ea=None,
                native_instruction_eas=(),
                role=subject.role,
                observed_logical_occurrence=(
                    None
                    if present == locator.serial
                    else occurrence_by_ref[locator.block_ref]
                ),
            ))
            continue
        refs = _locator_refs(subject)
        missing_refs = tuple(
            ref for ref in refs
            if ref not in witnesses and ref not in extra_refs
        )
        if any(
            type(ref) is not LogicalBlockRef
            or ref not in source_owned_logical_refs
            for ref in missing_refs
        ):
            raise ValueError("subject contains a foreign or missing source reference")
        owner = subject.block_ref
        if subject.kind is model.SemanticSubjectKind.VALUE_FLOW:
            owner_present = False
        else:
            if owner is None:
                raise ValueError("projected subject has no exact owner")
            owner_present = owner in serial_by_ref
        complete = all(ref in serial_by_ref for ref in refs)
        if not owner_present or not complete:
            result.append(model.PhaseSubjectBinding(
                subject=subject,
                phase=phase,
                block_ref=None,
                graph_fingerprint=graph_fingerprint,
                generation=generation,
                status=model.SubjectBindingStatus.MISSING,
                serial=None,
                anchor_ea=None,
                native_instruction_eas=(),
                role=subject.role,
            ))
            continue
        if owner in witnesses:
            witness = witnesses[owner]
            witness_anchor = witness.anchor_ea
            witness_origins = tuple(origins[owner])
        else:
            witness_anchor = subject.anchor_ea
            witness_origins = tuple(origins.get(owner, ()))
        is_route_endpoint = subject.role in {
            model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE,
            model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION,
        }
        route_anchor_matches = (
            is_route_endpoint
            and type(owner) is NativeBlockRef
            and subject.anchor_ea is not None
            and owner.identity.native_ranges.contains(subject.anchor_ea)
        )
        if (
            subject.anchor_ea is None
            or (not route_anchor_matches and subject.anchor_ea != witness_anchor)
        ):
            raise ValueError("subject anchor is a near-match for its source witness")
        if owner in witnesses:
            valid_anchor = (
                route_anchor_matches
                or _witness_anchor_matches(witness, subject.anchor_ea, witness_origins)
            )
        else:
            # PlanBlockRef helpers have no source witness. Their exact origin
            # rows were validated above; bind only to one of those rows.
            valid_anchor = bool(witness_origins) and int(subject.anchor_ea) in witness_origins
        if not valid_anchor:
            raise ValueError(
                "projected subject origin does not exactly match catalog: "
                f"subject={subject.subject_id} role={subject.role.value} "
                f"kind={subject.kind.value} owner={owner!r} "
                f"serial={serial_by_ref.get(owner)!r} "
                f"anchor=0x{int(subject.anchor_ea):X} "
                f"witness_origins={witness_origins!r}"
            )
        result.append(model.PhaseSubjectBinding(
            subject=subject,
            phase=phase,
            block_ref=owner,
            graph_fingerprint=graph_fingerprint,
            generation=generation,
            status=model.SubjectBindingStatus.UNIQUE,
            serial=serial_by_ref[owner],
            anchor_ea=subject.anchor_ea,
            native_instruction_eas=witness_origins,
            role=subject.role,
        ))
    return tuple(sorted(result, key=lambda item: item.subject.subject_id))


def bind_inventory_subjects(
    subjects: Sequence[model.SemanticSubjectRef],
    *,
    catalog: model.SourceIdentityCatalog,
    phase: model.UnflattenAuthorityPhase,
    graph_fingerprint: str,
    generation: int,
    serial_by_ref: Mapping[object, int],
    effects: Sequence[model.InventoryEffectSite],
    terminals: Sequence[model.InventoryTerminalSite],
    reachable_serials: Sequence[int],
    native_instruction_eas_by_ref: Mapping[object, Sequence[int]] | None = None,
    source_inventory: model.SemanticGraphInventory | None = None,
    observed_logical_endpoint_occurrences: tuple[
        model.ObservedLogicalEndpointOccurrence, ...
    ] = (),
) -> tuple[model.PhaseSubjectBinding, ...]:
    """Bind an inventory using the inventory's exact reachable site rows.

    Block ownership is not sufficient evidence for an effect or terminal
    subject.  This is the canonical site-level binding operation used by the
    projected and observed inventory builders; every downstream gate consumes
    the resulting binding status rather than reconstructing site presence.
    """
    if type(subjects) is not tuple:
        raise TypeError("subjects must be an exact tuple")
    if type(effects) is not tuple:
        raise TypeError("effects must be an exact tuple")
    if type(terminals) is not tuple:
        raise TypeError("terminals must be an exact tuple")
    if any(type(row) is not model.InventoryEffectSite for row in effects):
        raise TypeError("effects must contain exact InventoryEffectSite rows")
    if any(type(row) is not model.InventoryTerminalSite for row in terminals):
        raise TypeError("terminals must contain exact InventoryTerminalSite rows")
    if type(reachable_serials) is not tuple:
        raise TypeError("reachable_serials must be an exact tuple")
    if reachable_serials != tuple(sorted(set(reachable_serials))) or any(
        type(serial) is not int or serial < 0 for serial in reachable_serials
    ):
        raise ValueError("reachable_serials must be sorted exact non-negative integers")
    # Validate all closed row inputs before binding any subject.  The model
    # resolver is the shared owner of site identity and status semantics.
    for row in (*effects, *terminals):
        row.__post_init__()
        if row.owner_serial not in reachable_serials:
            raise ValueError("inventory site row is outside reachable_serials")
    base = bind_projected_subjects(
        subjects,
        catalog=catalog,
        phase=phase,
        graph_fingerprint=graph_fingerprint,
        generation=generation,
        serial_by_ref=serial_by_ref,
        native_instruction_eas_by_ref=native_instruction_eas_by_ref,
        source_inventory=source_inventory,
        observed_logical_endpoint_occurrences=(
            observed_logical_endpoint_occurrences
        ),
    )
    rebound: list[model.PhaseSubjectBinding] = []
    for binding in base:
        if binding.subject.role in (
            model.SemanticSubjectRole.EFFECT_SITE,
            model.SemanticSubjectRole.TERMINAL_SITE,
        ) and type(binding.subject.locator) in (
            model.EffectSubjectLocator,
            model.TerminalSubjectLocator,
        ):
            rebound.append(model.resolve_inventory_site_binding(
                binding.subject,
                binding,
                effects=effects,
                terminals=terminals,
                reachable_serials=reachable_serials,
                serial_by_ref=dict(serial_by_ref),
            ))
        else:
            rebound.append(binding)
    return tuple(sorted(rebound, key=lambda item: item.subject.subject_id))


def validate_retired_infrastructure_binding_result(
    result: RetiredInfrastructureBindingResult,
) -> None:
    """Reject a retirement binding mutated after it was sealed."""

    if type(result) is not RetiredInfrastructureBindingResult:
        raise TypeError("retirement result must be closed")
    if result._content_seal != _retirement_binding_seal(result):
        raise ValueError("retirement binding content seal does not match")
    result._validate_fields()


__all__ = [
    "RetiredInfrastructureBindingResult",
    "TerminalCycleBindingResult",
    "bind_detached_dead_handler_component_claim",
    "bind_retired_dispatcher_infrastructure_claim",
    "bind_terminal_cycle_break_claim",
    "terminal_cycle_binding_subjects",
    "validate_detached_source_result",
    "validate_detached_phase_result",
    "validate_retirement_phase_result",
    "validate_retired_infrastructure_binding_result",
    "validate_terminal_cycle_phase_result",
    "validate_terminal_cycle_binding_result",
    "bind_subjects",
    "bind_source_subjects",
    "bind_projected_subjects",
    "bind_raw_effect_gate_phase_fact",
    "validate_raw_effect_gate_phase_fact",
    "bind_projected_exact_effect",
    "bind_local_alias_scalarization",
    "validate_exact_effect_binding_result",
    "validate_local_alias_binding_result",
    "validate_projected_effect_site_result",
    "validate_projected_terminal_site_result",
    "validate_projected_site_phase_result",
    "validate_projected_route_site_preservation",
]
