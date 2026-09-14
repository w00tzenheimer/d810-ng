"""Pure total evaluator for already-derived unflatten authority inputs."""

from __future__ import annotations
from .transaction_facts import active_facts, captured, construct

from collections import Counter, defaultdict
from dataclasses import dataclass, replace
import re
from d810.core.typing import Iterable

from d810.ir.block_identity import StableBlockIdentity
from d810.transforms.cfg_transaction import LogicalBlockRef, NativeBlockRef, PatchStepKind, PlanBlockRef

from . import model
from . import bind as authority_bind
from . import gates
from . import producer_api
from .ids import _case_factory, _evidence_factory, _justification_factory, authority_id as _authority_id_digest, canonical_bytes, content_id as _content_id_digest, stage_unpublished_field
from .proposal import _redirect_owner_sort_key


@dataclass(frozen=True, slots=True)
class _EffectClassification:
    """Single classification of one source effect site for this phase."""

    preserved: bool
    authorized_loss: bool
    refuted: bool
    claim: model.ExactInfeasibleEffectClaim | model.LocalAliasEffectScalarizationClaim | None
    authorized_transition: bool = False
    structural_preserved: bool = False


@dataclass(frozen=True, slots=True)
class _ObservedBranchHelperElision:
    """One sealed RF-4 helper elision admitted only during observation."""

    relation_id: str
    helper_ref: PlanBlockRef
    helper_patch_fact: model.PatchStepEvidencePayload
    remove_topology: tuple[model.TopologyEdgeRelation, ...]
    add_topology: tuple[model.TopologyEdgeRelation, ...]


@dataclass(frozen=True, slots=True)
class _ObservedRouteTopologyNormalization:
    """One transaction-derived normalization of sealed route edge pairs."""

    relation_ids: tuple[str, ...]
    patch_facts: tuple[model.PatchStepEvidencePayload, ...]
    candidate_topology: tuple[model.TopologyEdgeRelation, ...]


def _topology_relations_for_inventory(
    inventory: model.SemanticGraphInventory,
    *,
    topology_roles: frozenset[model.SemanticSubjectRole],
) -> tuple[model.TopologyEdgeRelation, ...]:
    """Render the closed inventory topology once as subject-level relations."""

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
    rows: dict[
        tuple[int, int],
        dict[model.TopologyIncidenceKind, model.InventoryTopologyIncidence],
    ] = {}
    for item in inventory.topology:
        key = (
            (item.owner_serial, item.peer_serial)
            if item.kind is model.TopologyIncidenceKind.SUCCESSOR
            else (item.peer_serial, item.owner_serial)
        )
        rows.setdefault(key, {})[item.kind] = item
    result: list[model.TopologyEdgeRelation] = []
    for (source_serial, target_serial), pair in rows.items():
        successor = pair.get(model.TopologyIncidenceKind.SUCCESSOR)
        predecessor = pair.get(model.TopologyIncidenceKind.PREDECESSOR)
        if (
            successor is None
            or predecessor is None
            or successor.source_transfer_ea != predecessor.source_transfer_ea
        ):
            continue
        anchor = successor.source_transfer_ea
        if anchor is None:
            anchor = by_serial[source_serial].anchor_ea
        if anchor is None:
            continue
        for source_subject in subject_by_serial.get(source_serial, ()):
            for target_subject in subject_by_serial.get(target_serial, ()):
                result.append(model.TopologyEdgeRelation(
                    model.SemanticEdgeRole.DIRECT,
                    source_subject.subject_id,
                    target_subject.subject_id,
                    anchor,
                ))
                result.append(model.TopologyEdgeRelation(
                    model.SemanticEdgeRole.DIRECT,
                    target_subject.subject_id,
                    source_subject.subject_id,
                    anchor,
                ))
    return tuple(sorted(
        set(result),
        key=lambda item: (
            item.source_subject_id,
            item.target_subject_id,
            item.native_edge_anchor_ea,
        ),
    ))


def _derive_observed_branch_helper_elisions(
    inputs: model.DerivedUnflattenPreparationInputs,
    *,
    projected_topology: tuple[model.TopologyEdgeRelation, ...],
    candidate_topology: tuple[model.TopologyEdgeRelation, ...],
) -> tuple[_ObservedBranchHelperElision, ...]:
    """Admit only the exact observed RF-4 ``F -> H -> N`` to ``F -> N`` fold.

    The helper is not a general allowance.  Its disappearance is valid only
    when the already-sealed branch-helper relation, both exact branch facts,
    the creation digest, and every affected reciprocal inventory edge agree.
    """

    if inputs.candidate_inventory.phase is not model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY:
        return ()
    realization = inputs.projected_route_realization
    if type(realization) is not model.ProjectedRouteRealization:
        return ()
    projected = inputs.projected_topology_reference
    observed = inputs.candidate_inventory
    projected_rows = {row.serial: row for row in projected.blocks}
    observed_rows = {row.serial: row for row in observed.blocks}
    projected_ref_by_serial = {
        serial: ref for ref, serial in projected.serial_by_ref.items()
    }
    observed_ref_by_serial = {
        serial: ref for ref, serial in observed.serial_by_ref.items()
    }

    def subject_ids(inventory, ref):
        return frozenset(
            subject.subject_id
            for subject in inventory.subjects
            if subject.block_ref == ref
            and subject.role in _TOPOLOGY_ROLES
        )

    def reciprocal(rows, source_serial: int, target_serial: int) -> bool:
        source = rows.get(source_serial)
        target = rows.get(target_serial)
        return bool(
            source is not None
            and target is not None
            and target_serial in source.successor_serials
            and source_serial in target.predecessor_serials
        )

    def refs(rows, ref_by_serial, serial: int, attribute: str):
        row = rows.get(serial)
        if row is None:
            return None
        try:
            return tuple(ref_by_serial[item] for item in getattr(row, attribute))
        except KeyError:
            return None

    def directed(left_ids, right_ids, anchors):
        return {
            model.TopologyEdgeRelation(
                model.SemanticEdgeRole.DIRECT, left, right, anchor,
            )
            for left in left_ids for right in right_ids for anchor in anchors
        } | {
            model.TopologyEdgeRelation(
                model.SemanticEdgeRole.DIRECT, right, left, anchor,
            )
            for left in left_ids for right in right_ids for anchor in anchors
        }

    branch_rows = tuple(
        row for row in realization.rows
        if type(row.relation) is model.BranchFallthroughHelperRouteRealization
    )
    if len({row.relation.relation_id for row in branch_rows}) != len(branch_rows):
        return ()
    missing_helper_relation_ids = {
        row.relation.relation_id
        for row in branch_rows
        if row.relation.helper.ref not in observed.serial_by_ref
        or not any(subject.block_ref == row.relation.helper.ref for subject in observed.subjects)
    }
    # A helper cannot be half-present.  A present helper remains ordinary
    # observed topology; only a wholly absent helper can enter this exact fold.
    if any(
        (row.relation.helper.ref in observed.serial_by_ref)
        != any(subject.block_ref == row.relation.helper.ref for subject in observed.subjects)
        for row in branch_rows
    ):
        return ()
    for row in branch_rows:
        relation = row.relation
        if relation.helper.ref not in observed.serial_by_ref:
            continue
        required = (
            relation.feeder.ref,
            relation.helper.ref,
            relation.untouched_conditional_arm.ref,
            relation.semantic_target.ref,
        )
        if any(ref not in observed.serial_by_ref for ref in required):
            return ()
        feeder, helper, untouched, target = (
            observed.serial_by_ref[ref] for ref in required
        )
        if (
            refs(observed_rows, observed_ref_by_serial, feeder, "successor_serials")
            != (relation.helper.ref, relation.untouched_conditional_arm.ref)
            or refs(observed_rows, observed_ref_by_serial, helper, "predecessor_serials")
            != (relation.feeder.ref,)
            or refs(observed_rows, observed_ref_by_serial, helper, "successor_serials")
            != (relation.semantic_target.ref,)
            or not all((
                reciprocal(observed_rows, feeder, helper),
                reciprocal(observed_rows, feeder, untouched),
                reciprocal(observed_rows, helper, target),
            ))
        ):
            return ()

    results: list[_ObservedBranchHelperElision] = []
    for row in branch_rows:
        relation = row.relation
        if type(relation) is not model.BranchFallthroughHelperRouteRealization:
            continue
        creation_digests = dict(relation.creation_spec_digests)
        helper_digest = creation_digests.get(relation.helper.ref)
        if (
            len(creation_digests) != 1
            or helper_digest is None
            or relation.helper.ref in observed.serial_by_ref
            or any(subject.block_ref == relation.helper.ref for subject in observed.subjects)
        ):
            continue
        branch_facts = tuple(
            fact for fact in inputs.patch_step_facts
            if fact.step_type == "PatchRedirectBranch"
            and fact.step_index == row.plan_step_index
            and fact.step_digest == row.plan_step_digest
        )
        feeder_facts = tuple(
            fact for fact in branch_facts
            if type(fact.owner_ref) is NativeBlockRef
            and fact.owner_ref == relation.feeder.ref
            and fact.creation_spec_digest is None
        )
        helper_facts = tuple(
            fact for fact in branch_facts
            if type(fact.owner_ref) is PlanBlockRef
            and fact.owner_ref == relation.helper.ref
            and fact.creation_spec_digest == helper_digest
        )
        if (
            len(branch_facts) != 2
            or len(feeder_facts) != 1
            or len(helper_facts) != 1
            or any(fact.plan_id != inputs.proposal.plan_id for fact in branch_facts)
        ):
            continue
        route_refs = (
            relation.feeder.ref,
            relation.helper.ref,
            relation.untouched_conditional_arm.ref,
            relation.semantic_target.ref,
        )
        if any(ref not in projected.serial_by_ref for ref in route_refs):
            continue
        feeder_serial, helper_serial, untouched_serial, target_serial = (
            projected.serial_by_ref[ref] for ref in route_refs
        )
        if any(ref not in observed.serial_by_ref for ref in (
            relation.feeder.ref,
            relation.untouched_conditional_arm.ref,
            relation.semantic_target.ref,
        )):
            continue
        observed_feeder = observed.serial_by_ref[relation.feeder.ref]
        observed_untouched = observed.serial_by_ref[relation.untouched_conditional_arm.ref]
        observed_target = observed.serial_by_ref[relation.semantic_target.ref]
        if (
            refs(projected_rows, projected_ref_by_serial, feeder_serial, "successor_serials")
            != (relation.helper.ref, relation.untouched_conditional_arm.ref)
            or refs(projected_rows, projected_ref_by_serial, helper_serial, "predecessor_serials")
            != (relation.feeder.ref,)
            or refs(projected_rows, projected_ref_by_serial, helper_serial, "successor_serials")
            != (relation.semantic_target.ref,)
            or not all((
                reciprocal(projected_rows, feeder_serial, helper_serial),
                reciprocal(projected_rows, feeder_serial, untouched_serial),
                reciprocal(projected_rows, helper_serial, target_serial),
            ))
            or refs(observed_rows, observed_ref_by_serial, observed_feeder, "successor_serials")
            != (relation.semantic_target.ref, relation.untouched_conditional_arm.ref)
            # CFG snapshot construction canonically orders predecessor rows,
            # so prove the exact substitution as a set and separately require
            # reciprocal incidence below.  Ordering is not route authority.
            or frozenset(
                refs(
                    observed_rows, observed_ref_by_serial, observed_target,
                    "predecessor_serials",
                ) or ()
            )
            != frozenset(
                relation.feeder.ref if ref == relation.helper.ref else ref
                for ref in refs(
                    projected_rows, projected_ref_by_serial, target_serial,
                    "predecessor_serials",
                ) or ()
            )
            or not all((
                reciprocal(observed_rows, observed_feeder, observed_target),
                reciprocal(observed_rows, observed_feeder, observed_untouched),
            ))
        ):
            continue
        feeder_ids = subject_ids(projected, relation.feeder.ref)
        helper_ids = subject_ids(projected, relation.helper.ref)
        target_ids = subject_ids(projected, relation.semantic_target.ref)
        if not all((feeder_ids, helper_ids, target_ids)):
            continue
        if any(
            subject_ids(projected, ref) != subject_ids(observed, ref)
            for ref in (
                relation.feeder.ref,
                relation.semantic_target.ref,
            )
        ):
            continue
        feeder_helper = {
            relation for relation in projected_topology
            if {relation.source_subject_id, relation.target_subject_id}
            <= feeder_ids | helper_ids
            and (
                relation.source_subject_id in feeder_ids
                or relation.target_subject_id in feeder_ids
            )
        }
        helper_target = {
            relation for relation in projected_topology
            if {relation.source_subject_id, relation.target_subject_id}
            <= helper_ids | target_ids
            and (
                relation.source_subject_id in helper_ids
                or relation.target_subject_id in helper_ids
            )
        }
        expected_helper_incidence = feeder_helper | helper_target
        actual_helper_incidence = {
            relation for relation in projected_topology
            if relation.source_subject_id in helper_ids
            or relation.target_subject_id in helper_ids
        }
        feeder_helper_anchors = {
            relation.native_edge_anchor_ea for relation in feeder_helper
        }
        normalized_direct = directed(
            feeder_ids, target_ids, feeder_helper_anchors,
        )
        normalized_topology = (set(projected_topology) - actual_helper_incidence) | normalized_direct
        # The relation owns only the F/H/N splice.  Other independently
        # normalized topology is checked by the ordinary topology matcher;
        # this admission must neither bless nor reject it.
        affected_projected_ids = feeder_ids | helper_ids | target_ids
        affected_observed_ids = feeder_ids | target_ids
        normalized_affected_topology = {
            item for item in normalized_topology
            if item.source_subject_id in affected_projected_ids
            or item.target_subject_id in affected_projected_ids
        }
        candidate_affected_topology = {
            item for item in candidate_topology
            if item.source_subject_id in affected_observed_ids
            or item.target_subject_id in affected_observed_ids
        }
        if (
            not feeder_helper_anchors
            or feeder_helper != directed(feeder_ids, helper_ids, feeder_helper_anchors)
            or helper_target != directed(
                helper_ids,
                target_ids,
                {relation.native_edge_anchor_ea for relation in helper_target},
            )
            or actual_helper_incidence != expected_helper_incidence
            or normalized_affected_topology != candidate_affected_topology
        ):
            continue
        results.append(_ObservedBranchHelperElision(
            relation.relation_id,
            relation.helper.ref,
            helper_facts[0],
            tuple(sorted(actual_helper_incidence, key=lambda item: (
                item.source_subject_id, item.target_subject_id,
                item.native_edge_anchor_ea,
            ))),
            tuple(sorted(normalized_direct, key=lambda item: (
                item.source_subject_id, item.target_subject_id,
                item.native_edge_anchor_ea,
            ))),
        ))
    if {item.relation_id for item in results} != missing_helper_relation_ids:
        return ()
    if len({item.helper_ref for item in results}) != len(results):
        return ()
    remove_sets = [set(item.remove_topology) for item in results]
    add_sets = [set(item.add_topology) for item in results]
    if any(
        left & right
        for index, left in enumerate((*remove_sets, *add_sets))
        for right in (*remove_sets, *add_sets)[index + 1:]
    ):
        return ()
    return tuple(results)


def _fold_observed_branch_helper_topology(
    projected_topology: tuple[model.TopologyEdgeRelation, ...],
    elisions: tuple[_ObservedBranchHelperElision, ...],
) -> tuple[model.TopologyEdgeRelation, ...]:
    """Apply pairwise-disjoint, sealed RF-4 topology deltas atomically."""

    removals = set().union(*(set(item.remove_topology) for item in elisions))
    additions = set().union(*(set(item.add_topology) for item in elisions))
    return tuple(sorted(
        (set(projected_topology) - removals) | additions,
        key=lambda item: (
            item.source_subject_id,
            item.target_subject_id,
            item.native_edge_anchor_ea,
        ),
    ))


def _normalize_observed_route_topology(
    inputs: model.DerivedUnflattenPreparationInputs,
    *,
    projected_topology: tuple[model.TopologyEdgeRelation, ...],
    candidate_topology: tuple[model.TopologyEdgeRelation, ...],
) -> _ObservedRouteTopologyNormalization | None:
    """Normalize only physically revalidated RF-1/direct semantic edge pairs.

    The projected route realization and exact patch facts already own the
    semantic edge.  Observation verifies that same edge in the backend graph
    (including the one structural fallthrough helper required by Hex-Rays)
    and then renders the pair with its canonical projected subject/anchor
    coordinates.  Unrelated incident edges remain untouched and therefore
    still fail the ordinary topology comparison.
    """

    if (
        inputs.candidate_inventory.phase
        is not model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY
        or type(inputs.projected_route_realization)
        is not model.ProjectedRouteRealization
    ):
        return None
    candidate = inputs.candidate_inventory
    projected = inputs.projected_topology_reference
    route_occurrences = candidate.observed_route_topology_occurrences
    conditional_occurrences = (
        candidate.observed_lowered_conditional_topology_occurrences
    )
    if not route_occurrences and not conditional_occurrences:
        return None
    for occurrence in route_occurrences:
        authority_bind.validate_observed_route_topology_occurrence(occurrence)
    for occurrence in conditional_occurrences:
        authority_bind.validate_observed_lowered_conditional_topology_occurrence(
            occurrence,
        )
    normalized = set(candidate_topology)
    relation_ids: list[str] = []
    facts: list[model.PatchStepEvidencePayload] = []
    for occurrence in (*route_occurrences, *conditional_occurrences):
        # The binder's projected pairs name the complete subject cross-product
        # for this route relation.  Replace precisely that pair domain; no
        # incident or raw observed edge is independently interpreted here.
        owned_subject_pairs = {
            frozenset((item.source_subject_id, item.target_subject_id))
            for item in occurrence.normalized_pairs
        }
        normalized = {
            item for item in normalized
            if frozenset((item.source_subject_id, item.target_subject_id))
            not in owned_subject_pairs
        }
        normalized.update(occurrence.normalized_pairs)
        relation_ids.append(
            occurrence.relation_id
            if type(occurrence) is model.ObservedRouteTopologyOccurrence
            else occurrence.occurrence_id
        )
        facts.append(occurrence.patch_fact)
    return _ObservedRouteTopologyNormalization(
        tuple(sorted(set(relation_ids))),
        tuple(sorted(set(facts), key=lambda fact: (
            fact.step_index, fact.step_digest, fact.step_type,
        ))),
        tuple(sorted(normalized, key=lambda item: (
            item.source_subject_id, item.target_subject_id,
            item.native_edge_anchor_ea,
        ))),
    )



# Inventory observations use the compact canonical opcode assigned by the
# backend adapter.  A local-alias scalarization is specifically STORE -> MOV;
# accepting an arbitrary opcode would make the display text the only semantic
# proof of the transition.
_SUPPORTED_PATCH_STEP_TYPES = frozenset({
    "PatchScalarizeLocalAliasAccess",
    "PatchLowerConditionalStateTransition",
    "PatchConvertToGoto",
    "PatchRedirectGoto",
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

_TOPOLOGY_ROLES = model.TOPOLOGY_SUBJECT_ROLES


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
    if payload.step_type == "PatchConvertToGoto":
        return planned or tuple(
            subject for subject in subjects
            if subject.block_ref == payload.owner_ref
            and subject.kind is model.SemanticSubjectKind.BLOCK
            and subject.role
            is model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE
        )
    if payload.step_type in {
        "PatchLowerConditionalStateTransition",
        "PatchRedirectGoto",
        "PatchRedirectBranch",
    }:
        return planned or tuple(
            subject for subject in subjects
            if subject.block_ref == payload.owner_ref
            and (
                subject.kind is model.SemanticSubjectKind.BLOCK
                or (
                    payload.step_type in {
                        "PatchRedirectGoto",
                        "PatchRedirectBranch",
                    }
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


def _observed_local_alias_scalar_write_matches(
    observation: model.InventoryInstructionObservation,
    *,
    host_ea: int,
    base_token: str,
    width: int,
) -> bool:
    """Recognize the closed observed forms of one sealed alias scalarization.

    The projected form is an exact STORE-to-MOV rewrite.  Hex-Rays may
    immediately coalesce that MOV into the value instruction that writes the
    same scalar destination.  Observation accepts only a pure value form at
    the exact native host coordinate with the claimed base as its complete
    destination operand; memory stores, calls, transfers, and token-prefix
    matches remain forbidden.
    """

    if type(observation) is not model.InventoryInstructionObservation:
        raise TypeError("local-alias observation must be an inventory row")
    if observation.instruction_ea != host_ea or observation.width != width:
        return False
    if observation.instruction_kind not in {
        model.InsnKind.MOV,
        model.InsnKind.LOAD,
        model.InsnKind.XDU,
        model.InsnKind.XDS,
        model.InsnKind.ADD,
        model.InsnKind.SUB,
        model.InsnKind.AND,
        model.InsnKind.MUL,
        model.InsnKind.VALUE,
        model.InsnKind.SET,
    }:
        return False
    if (
        observation.instruction_kind is model.InsnKind.MOV
        and observation.raw_opcode is not None
        and observation.opcode != observation.raw_opcode
    ):
        return False
    if (
        observation.control_transfer_kind is not None
        or observation.is_call
        or observation.call_kind is not None
        or observation.display_text is None
    ):
        return False

    destination = (
        rf"{re.escape(base_token)}"
        rf"(?:\.(?P<width>\d+))?"
        rf"(?:\{{\d+\}})?"
    )
    match = re.fullmatch(
        rf"\s*[a-zA-Z0-9_]+\s+.+,\s*{destination}\s*",
        observation.display_text,
    )
    return bool(match) and (
        match.group("width") is None
        or match.group("width") == str(width)
    )


def _classify_effect_site(
    effect: model.InventoryEffectSite,
    subject: model.SemanticSubjectRef,
    source_binding: model.PhaseSubjectBinding,
    candidate_binding: model.PhaseSubjectBinding | None,
    candidate_effect: model.InventoryEffectSite | tuple[model.InventoryEffectSite, ...] | None,
    claim: model.ExactInfeasibleEffectClaim | None,
    source_authority: model.SourceBoundRouteAuthority,
    projected_realization: model.ProjectedRouteRealization,
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
    if (
        phase is model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT
        and type(projected_realization) is model.ProjectedRouteRealization
    ):
        # The projected realizer already made the semantic disposition.  This
        # layer may verify that the candidate still matches its sealed
        # coordinate, but must not recreate an independent authorization from
        # raw loss sets, claims, or route coverage.
        sealed_rows = tuple(
            row for row in projected_realization.site_phase_result.effect_results
            if row.source_subject_id == subject.subject_id
        )
        if len(sealed_rows) != 1:
            return _EffectClassification(False, False, True, None)
        sealed = sealed_rows[0]
        if sealed.outcome in {
            model.ProjectedEffectSiteOutcome.PRESERVED,
            model.ProjectedEffectSiteOutcome.RELATION_CLONED,
        }:
            projected_site = sealed.projected_site
            sealed_candidate_matches = bool(
                projected_site is not None
                and candidate_row is not None
                and candidate_binding is not None
                and candidate_binding.subject.subject_id
                == sealed.projected_subject_id
                and candidate_binding.status
                is model.SubjectBindingStatus.UNIQUE
                and candidate_row.owner_serial == candidate_binding.serial
                and candidate_row.owner_ref == projected_site.owner.ref
                and candidate_row.owner_anchor_ea
                == projected_site.owner.anchor_ea
                and candidate_row.instruction_ordinal
                == projected_site.instruction_ordinal
                and candidate_row.instruction_ea
                == projected_site.instruction_ea
                and candidate_row.effect_kind is projected_site.effect_kind
                and candidate_row.opcode == projected_site.opcode
                and candidate_row.width == projected_site.width
            )
            return _EffectClassification(
                sealed_candidate_matches,
                False,
                not sealed_candidate_matches,
                None,
            )
        if sealed.outcome is model.ProjectedEffectSiteOutcome.EXACT_INFEASIBLE:
            authorized = bool(
                not candidate_rows
                and candidate_binding is not None
                and candidate_binding.status is model.SubjectBindingStatus.MISSING
                and claim is not None
                and sealed.supporting_claim_id == claim.claim_id
                and sealed.projected_site is None
            )
            return _EffectClassification(False, authorized, not authorized, claim if authorized else None)
        if sealed.outcome is model.ProjectedEffectSiteOutcome.LOCAL_ALIAS_SCALARIZED:
            authorized = bool(
                not candidate_rows
                and local_alias_claim is not None
                and sealed.supporting_claim_id == local_alias_claim.claim_id
                and sealed.scalarized_site is not None
            )
            return _EffectClassification(False, authorized, not authorized,
                                         local_alias_claim if authorized else None, authorized)
        return _EffectClassification(False, False, True, None)
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
    if claim is None and local_alias_claim is None:
        return _EffectClassification(False, False, True, None)
    if (
        type(source_authority) is not model.SourceBoundRouteAuthority
        or type(projected_realization) is not model.ProjectedRouteRealization
    ):
        return _EffectClassification(False, False, True, None)
    site_phase = projected_realization.site_phase_result
    latent_exact_binding = next((
        binding for binding in site_phase.exact_effect_bindings
        if binding.claim is claim
        and binding.source_site.instruction_ea == effect.instruction_ea
        and binding.source_site.effect_kind is effect.effect_kind
        and binding.source_site.owner.ref == effect.owner_ref
        and binding.source_site.owner.anchor_ea == effect.owner_anchor_ea
    ), None)
    route_ok = bool(
        claim is not None
        and len(claim.route_proof_ids) == 1
        and claim.route_proof_ids[0] in source_authority.covered_proof_ids
        and (
            any(
                row.source_subject_id == subject.subject_id
                and row.outcome is model.ProjectedEffectSiteOutcome.EXACT_INFEASIBLE
                and row.supporting_claim_id == claim.claim_id
                for row in site_phase.effect_results
            )
            or (
                phase is model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY
                and latent_exact_binding is not None
            )
        )
    )
    raw_facts = None if generic_gate_facts is None else generic_gate_facts.effectful_raw
    owner = effect.owner_serial
    raw_lost = raw_facts is not None and owner in raw_facts.lost_block_serials
    raw_retained = raw_facts is not None and owner in raw_facts.pre_effectful_block_serials and not raw_lost
    gate_ok = bool(
        generic_gate_facts is not None
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
        and _observed_local_alias_scalar_write_matches(
            local_alias_owner_observation,
            host_ea=effect.instruction_ea,
            base_token=local_alias_claim.base_token,
            width=effect.width,
        )
    )
    if alias_exact:
        return _EffectClassification(False, True, False, local_alias_claim, True)
    if preserved_alias_transition_missing:
        return _EffectClassification(
            False, False, True, None, False, True,
        )
    return _EffectClassification(False, authorized, not authorized, claim if authorized else None)


REQUIRED_DIMENSIONS: dict[tuple[model.SemanticSubjectKind, model.SemanticSubjectRole], tuple[model.SafetyDimension, ...]] = {
    (model.SemanticSubjectKind.BLOCK, model.SemanticSubjectRole.SOURCE_CATALOG_BLOCK): (
        model.SafetyDimension.IDENTITY_BINDING,
        model.SafetyDimension.STRUCTURAL_ACCOUNTING,
    ),
    (model.SemanticSubjectKind.BLOCK, model.SemanticSubjectRole.SOURCE_LOGICAL_EXIT): (
        model.SafetyDimension.IDENTITY_BINDING,
    ),
    (model.SemanticSubjectKind.BLOCK, model.SemanticSubjectRole.SOURCE_ENTRY): (
        model.SafetyDimension.IDENTITY_BINDING, model.SafetyDimension.TOPOLOGY_INTEGRITY,
        model.SafetyDimension.ENTRY_REACHABILITY,
    ),
    (model.SemanticSubjectKind.BLOCK, model.SemanticSubjectRole.DISPATCHER_ENTRY): (
        model.SafetyDimension.IDENTITY_BINDING, model.SafetyDimension.TOPOLOGY_INTEGRITY,
    ),
    (model.SemanticSubjectKind.BLOCK, model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE): (
        model.SafetyDimension.IDENTITY_BINDING, model.SafetyDimension.TOPOLOGY_INTEGRITY,
    ),
    (model.SemanticSubjectKind.BLOCK, model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE): (
        model.SafetyDimension.IDENTITY_BINDING, model.SafetyDimension.TOPOLOGY_INTEGRITY,
        model.SafetyDimension.ROUTE_EQUIVALENCE,
    ),
    (model.SemanticSubjectKind.EDGE, model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE): (
        model.SafetyDimension.IDENTITY_BINDING, model.SafetyDimension.ROUTE_EQUIVALENCE,
    ),
    (model.SemanticSubjectKind.ROUTE, model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE): (
        model.SafetyDimension.IDENTITY_BINDING, model.SafetyDimension.ROUTE_EQUIVALENCE,
    ),
    (model.SemanticSubjectKind.BLOCK, model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION): (
        model.SafetyDimension.IDENTITY_BINDING, model.SafetyDimension.TOPOLOGY_INTEGRITY,
        model.SafetyDimension.ROUTE_EQUIVALENCE,
    ),
    (model.SemanticSubjectKind.BLOCK, model.SemanticSubjectRole.SEMANTIC_DAG_ENDPOINT): (
        model.SafetyDimension.IDENTITY_BINDING, model.SafetyDimension.ROUTE_EQUIVALENCE,
    ),
    (model.SemanticSubjectKind.BLOCK, model.SemanticSubjectRole.EXACT_EFFECT_SOURCE): (
        model.SafetyDimension.IDENTITY_BINDING, model.SafetyDimension.TOPOLOGY_INTEGRITY,
    ),
    (model.SemanticSubjectKind.BLOCK, model.SemanticSubjectRole.EXACT_EFFECT_PREDICATE): (
        model.SafetyDimension.IDENTITY_BINDING, model.SafetyDimension.TOPOLOGY_INTEGRITY,
    ),
    (model.SemanticSubjectKind.BLOCK, model.SemanticSubjectRole.EXACT_EFFECT_SELECTED_TARGET): (
        model.SafetyDimension.IDENTITY_BINDING, model.SafetyDimension.TOPOLOGY_INTEGRITY,
    ),
    (model.SemanticSubjectKind.BLOCK, model.SemanticSubjectRole.EXACT_EFFECT_DISCARDED_OWNER): (
        model.SafetyDimension.IDENTITY_BINDING, model.SafetyDimension.TOPOLOGY_INTEGRITY,
    ),
    # Marker-only subject: default-gap admissibility is decided by its one
    # typed corridor binder, not by a second per-block evaluator obligation.
    (model.SemanticSubjectKind.BLOCK, model.SemanticSubjectRole.DEFAULT_GAP_INFEASIBLE_RESIDUAL): (),
    (model.SemanticSubjectKind.BLOCK, model.SemanticSubjectRole.EFFECT_SITE): (
        model.SafetyDimension.IDENTITY_BINDING,
        model.SafetyDimension.EFFECT_PRESERVATION,
    ),
    (model.SemanticSubjectKind.EFFECT, model.SemanticSubjectRole.EFFECT_SITE): (
        model.SafetyDimension.IDENTITY_BINDING,
        model.SafetyDimension.EFFECT_PRESERVATION,
    ),
    (model.SemanticSubjectKind.HANDLER, model.SemanticSubjectRole.AUTHORITATIVE_HANDLER): (
        model.SafetyDimension.IDENTITY_BINDING, model.SafetyDimension.TOPOLOGY_INTEGRITY,
        model.SafetyDimension.HANDLER_REACHABILITY,
    ),
    (model.SemanticSubjectKind.TERMINAL, model.SemanticSubjectRole.TERMINAL_SITE): (
        model.SafetyDimension.IDENTITY_BINDING,
        model.SafetyDimension.TERMINAL_REACHABILITY,
    ),
    (model.SemanticSubjectKind.VALUE_FLOW, model.SemanticSubjectRole.NON_STATE_VALUE_FLOW): (
        model.SafetyDimension.IDENTITY_BINDING, model.SafetyDimension.USE_DEF_INTEGRITY,
    ),
    (model.SemanticSubjectKind.CORRIDOR, model.SemanticSubjectRole.DISPATCHER_CORRIDOR): (
        model.SafetyDimension.IDENTITY_BINDING,
        model.SafetyDimension.CORRIDOR_COVERAGE,
    ),
    (model.SemanticSubjectKind.BLOCK, model.SemanticSubjectRole.PLANNED_HELPER): (
        model.SafetyDimension.IDENTITY_BINDING, model.SafetyDimension.TOPOLOGY_INTEGRITY,
        model.SafetyDimension.STRUCTURAL_ACCOUNTING,
    ),
    (model.SemanticSubjectKind.BLOCK, model.SemanticSubjectRole.DETACHED_DEAD_HANDLER_COMPONENT): (
        model.SafetyDimension.IDENTITY_BINDING,
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
    model.UnflattenJustificationRule.RETIRED_INFRASTRUCTURE_PROVEN: _rule(model.SafetyDimension.STRUCTURAL_ACCOUNTING, polarity=model.EvidencePolarity.SUPPORTS, evidence=(model.AuthorityEvidenceKind.STRUCTURAL_LINEAGE,), max_premises=None),
    model.UnflattenJustificationRule.EQUIVALENT_ROUTE_PROVEN: _rule(model.SafetyDimension.STRUCTURAL_ACCOUNTING, model.SafetyDimension.ROUTE_EQUIVALENCE, polarity=model.EvidencePolarity.SUPPORTS, evidence=(model.AuthorityEvidenceKind.SEMANTIC_ROUTE,)),
    # The exact-effect claim's route_proof_ids are a correlation checked while
    # classifying its effect site; they do not own a second route subject.
    # Route subjects are emitted only by EquivalentSemanticRouteClaim.
    model.UnflattenJustificationRule.EXACT_INFEASIBLE_EFFECT_PROVEN: _rule(model.SafetyDimension.EFFECT_PRESERVATION, model.SafetyDimension.STRUCTURAL_ACCOUNTING, polarity=model.EvidencePolarity.SUPPORTS, evidence=(model.AuthorityEvidenceKind.EFFECT_SITE,), min_premises=1, max_premises=1),
    model.UnflattenJustificationRule.LOCAL_ALIAS_SCALARIZATION_PROVEN: _rule(model.SafetyDimension.EFFECT_PRESERVATION, polarity=model.EvidencePolarity.SUPPORTS, evidence=(model.AuthorityEvidenceKind.EFFECT_SITE, model.AuthorityEvidenceKind.PATCH_STEP, model.AuthorityEvidenceKind.PHASE_BINDING, model.AuthorityEvidenceKind.REACHABILITY), min_premises=4, max_premises=4),
    model.UnflattenJustificationRule.TERMINAL_CYCLE_BREAK_PROVEN: _rule(model.SafetyDimension.STRUCTURAL_ACCOUNTING, model.SafetyDimension.TERMINAL_REACHABILITY, polarity=model.EvidencePolarity.SUPPORTS, evidence=(model.AuthorityEvidenceKind.TERMINAL_CYCLE,)),
    model.UnflattenJustificationRule.DETACHED_COMPONENT_PROVEN: _rule(model.SafetyDimension.STRUCTURAL_ACCOUNTING, polarity=model.EvidencePolarity.SUPPORTS, evidence=(model.AuthorityEvidenceKind.DETACHED_COMPONENT,)),
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
    """Project typed destination IDs in the route locator's closed order."""

    if type(route.locator) is not model.RouteSubjectLocator:
        raise ValueError("route subject must carry a RouteSubjectLocator")
    return tuple(
        next(
            subject.subject_id
            for subject in subjects
            if subject.role is model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION
            and subject.locator == destination
        )
        for destination in route.locator.native_destination_members()
    )


def _route_dag_endpoint_ids(
    route: model.SemanticSubjectRef,
    subjects: tuple[model.SemanticSubjectRef, ...],
) -> tuple[str, ...]:
    """Project logical DAG endpoints separately from physical redirect targets."""
    if type(route.locator) is not model.RouteSubjectLocator:
        raise ValueError("route subject must carry a RouteSubjectLocator")
    return tuple(
        next(
            subject.subject_id
            for subject in subjects
            if subject.role is model.SemanticSubjectRole.SEMANTIC_DAG_ENDPOINT
            and subject.locator == endpoint
        )
        for endpoint in route.locator.dag_endpoint_members()
    )


def _claim_subjects(claim: model.UnflattenClaim) -> tuple[model.SemanticSubjectRef, ...]:
    """Return the closed subject inventory owned by one typed claim."""

    if type(claim) is model.RetiredDispatcherInfrastructureClaim:
        return (claim.infrastructure_subject, claim.corridor_subject, *claim.member_subjects)
    if type(claim) is model.DetachedDeadHandlerComponentClaim:
        return (
            claim.dispatcher_subject,
            *claim.dead_handler_subjects,
            *claim.retained_handler_subjects,
            *claim.component_subjects,
        )
    if type(claim) is model.EquivalentSemanticRouteClaim:
        return (
            claim.retired_route_subject, claim.replacement_route_subject,
            claim.source_subject, *claim.destination_subjects, *claim.dag_endpoint_subjects,
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


def _validate_terminal_cycle_claim_scope(
    claim: model.TerminalCycleBreakClaim,
    proposal: model.ProposedUnflattenContract,
) -> None:
    """Bind a terminal-cycle claim to one canonical terminal route.

    The cycle cleanup is a narrow structural allowance.  It is not an
    effect/handler receipt and cannot be minted from a bare serial or an
    unqualified legacy reason string.
    """

    authority_bind.terminal_cycle_binding_subjects(proposal, claim)


def _projected_retirement_cycle_refs(
    *,
    candidate_refs: tuple[NativeBlockRef | LogicalBlockRef, ...],
    inventory: model.SemanticGraphInventory,
) -> tuple[frozenset[object], ...]:
    """Find cyclic SCCs in the projected graph's exact retirement identities.

    Retirement membership is canonicalized by stable block reference, while
    phase bindings are only a witness of that identity in a phase.  In
    particular, a missing or drifted phase binding must not hide an edge
    between two stable identities that are both present in the projected CFG.
    Resolve the catalog refs directly through the sealed projected inventory,
    then inspect the induced successor graph.
    """

    serial_by_ref = inventory.serial_by_ref
    ref_by_serial = {
        serial_by_ref[ref]: ref
        for ref in candidate_refs
        if ref in serial_by_ref
    }
    successors = {
        serial: {
            target
            for target in next(
                block for block in inventory.blocks if block.serial == serial
            ).successor_serials
            if target in ref_by_serial
        }
        for serial in ref_by_serial
    }
    index = 0
    indexes: dict[int, int] = {}
    lowlinks: dict[int, int] = {}
    active: list[int] = []
    active_set: set[int] = set()
    components: list[frozenset[object]] = []

    def visit(serial: int) -> None:
        nonlocal index
        indexes[serial] = index
        lowlinks[serial] = index
        index += 1
        active.append(serial)
        active_set.add(serial)
        for target in successors[serial]:
            if target not in indexes:
                visit(target)
                lowlinks[serial] = min(lowlinks[serial], lowlinks[target])
            elif target in active_set:
                lowlinks[serial] = min(lowlinks[serial], indexes[target])
        if lowlinks[serial] != indexes[serial]:
            return
        component: set[int] = set()
        while True:
            member = active.pop()
            active_set.remove(member)
            component.add(member)
            if member == serial:
                break
        if len(component) > 1 or serial in successors[serial]:
            components.append(frozenset(ref_by_serial[item] for item in component))

    for serial in sorted(successors):
        if serial not in indexes:
            visit(serial)
    return tuple(sorted(components, key=lambda refs: tuple(sorted(map(repr, refs)))))


def _projected_cycle_authority_refs(
    inputs: model.DerivedUnflattenPreparationInputs,
) -> tuple[NativeBlockRef | LogicalBlockRef, ...]:
    """Return typed projected-cycle identities, including detached residue.

    The dispatcher member set also contains retained route-delivery blocks,
    so it cannot be treated as wholesale retirement authority.  Its members
    that are physically unreachable from the projected entry are different:
    they are exact detached dispatcher residue.  Include that residue only
    to reject an unclaimed cycle before native mutation.  This does not mint
    an allowance; the terminal/retirement binders below remain the only way
    an otherwise-cyclic projected component can be accepted.
    """

    refs: set[NativeBlockRef | LogicalBlockRef] = set()
    catalog = inputs.proposal.retirement_candidate_catalog
    if catalog is not None:
        refs.update(catalog.candidate_refs)
    candidate_inventory = inputs.candidate_inventory
    physically_reachable = set(candidate_inventory.physical_entry_reachable_serials)
    serial_by_ref = candidate_inventory.serial_by_ref
    refs.update(
        ref
        for ref in inputs.proposal.plan_inputs.dispatcher_member_refs
        if (
            (serial := serial_by_ref.get(ref)) is not None
            and serial not in physically_reachable
        )
    )
    for result in inputs.terminal_cycle_phase_results:
        if result.phase is model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT:
            refs.update(result.residue_refs)
    return tuple(sorted(refs, key=repr))


def _terminal_cycle_allowance_covers(
    cycle_refs: frozenset[object],
    *,
    claims: tuple[model.UnflattenClaim, ...],
    phase_results: tuple[model.TerminalCyclePhaseResult, ...],
    phase: model.UnflattenAuthorityPhase,
    candidate: model.SemanticGraphInventory,
) -> bool:
    """Accept only an already-sealed allowance for this exact cycle scope."""

    claims_by_id = {
        claim.claim_id: claim
        for claim in claims
        if type(claim) is model.TerminalCycleBreakClaim
    }
    return any(
        result.phase is phase
        and result.candidate_fingerprint == candidate.graph_fingerprint
        and result.candidate_generation == candidate.generation
        and claims_by_id.get(result.claim_id) is not None
        and frozenset(result.residue_refs) == cycle_refs
        for result in phase_results
    )


def _retirement_cycle_allowance_covers(
    cycle_refs: frozenset[object],
    *,
    inputs: model.DerivedUnflattenPreparationInputs,
    phase: model.UnflattenAuthorityPhase,
    candidate: model.SemanticGraphInventory,
) -> bool:
    """Accept an SCC only when the prepared retirement authority owns it.

    This deliberately consumes the binder-minted phase result rather than
    reconstructing retirement from graph reachability or plan metadata.  The
    result has already closed the claim/catalog occurrence and every member's
    source/candidate bindings; this consumer only verifies that those exact
    coordinates still describe the projected SCC under review.
    """

    result = inputs.retirement_phase_result
    if (
        not cycle_refs
        or type(result) is not model.RetirementPhaseResult
        or phase is not model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT
    ):
        return False
    try:
        authority_bind.validate_retirement_phase_result(result)
    except (TypeError, ValueError):
        return False
    catalog = inputs.proposal.retirement_candidate_catalog
    retirement_claims = tuple(
        claim
        for claim in inputs.claims
        if type(claim) is model.RetiredDispatcherInfrastructureClaim
    )
    if (
        catalog is None
        or len(retirement_claims) != 1
        or retirement_claims[0].candidate_catalog != catalog
        or result.catalog_id != catalog.catalog_id
        or result.claim_id != retirement_claims[0].claim_id
        or result.phase is not phase
        or result.source_fingerprint != inputs.source_inventory.graph_fingerprint
        or result.source_generation != inputs.source_inventory.generation
        or result.candidate_fingerprint != candidate.graph_fingerprint
        or result.candidate_generation != candidate.generation
        or {member.block_ref for member in result.members}
        != set(catalog.member_refs)
        # One sealed retirement can contain acyclic members and multiple SCCs.
        # Every member of this SCC must be retired by that exact certificate;
        # the SCC need not exhaust the certificate's complete retired set.
        or not cycle_refs <= frozenset(result.retired_refs)
    ):
        return False
    return all(
        member.classification is model.RetirementPhaseClassification.RETIRED
        and (
            member.candidate_binding.status is model.SubjectBindingStatus.MISSING
            or member.candidate_reachable is False
        )
        for member in result.members
        if member.block_ref in cycle_refs
    )


def _validated_route_realization_rows(
    inputs: model.DerivedUnflattenPreparationInputs,
    phase: model.UnflattenAuthorityPhase,

) -> dict[tuple[str, str, str], model.ProjectedRouteRealizationRow]:
    """Validate one transaction-owned route pair and index its sealed rows."""
    source = inputs.source_route_authority
    realization = inputs.projected_route_realization
    authority_bind.validate_source_route_authority(source)
    authority_bind.validate_projected_route_realization(realization)
    if realization.source_authority is not source:
        raise ValueError("projected realization does not retain exact source authority")
    projected_inventory_matches = (
        realization.projected_inventory_digest
        == inputs.candidate_inventory.inventory_digest
    )
    realization_fingerprint = inputs.candidate_inventory.graph_fingerprint
    realization_generation = inputs.candidate_inventory.generation
    if phase is model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY:
        reference = inputs.projected_topology_reference
        # The sealed realization belongs to preflight.  Observation is
        # correlated separately, so never require its changed inventory to be
        # the preflight graph again.
        projected_inventory_matches = (
            realization.projected_inventory_digest == reference.inventory_digest
        )
        realization_fingerprint = reference.graph_fingerprint
        realization_generation = reference.generation
    if (
        source.proposal is not inputs.proposal
        or source.plan_id != inputs.proposal.plan_id
        or source.source_fingerprint != inputs.source_inventory.graph_fingerprint
        or source.source_generation != inputs.source_inventory.generation
        or not projected_inventory_matches
        or realization.projected_fingerprint != realization_fingerprint
        or realization.projected_generation != realization_generation
    ):
        raise ValueError("route authority realization coordinates differ from inputs")
    rows: dict[tuple[str, str, str], model.ProjectedRouteRealizationRow] = {}
    for row in realization.rows:
        key = (row.claim_id, row.proof_id, row.route_subject_id)
        if key in rows:
            raise ValueError("projected realization has duplicate route coordinates")
        rows[key] = row
    return rows


def _validate_route_authority_realization(
    inputs: model.DerivedUnflattenPreparationInputs,
    phase: model.UnflattenAuthorityPhase,
    claim: model.EquivalentSemanticRouteClaim,
    *,
    _validated_rows: dict[
        tuple[str, str, str], model.ProjectedRouteRealizationRow
    ] | None = None,
) -> model.ProjectedRouteRealizationRow:
    """Return the one sealed realization row after coordinate validation.

    This is an identity/coordinate check, not a route assessment.  In the
    projected phase the binder-owned row is the authority for equivalence.
    """
    source = inputs.source_route_authority
    if type(source) is not model.SourceBoundRouteAuthority:
        raise TypeError("route claim requires one bound source authority")
    rows_by_coordinate = (
        _validated_route_realization_rows(inputs, phase)
        if _validated_rows is None else _validated_rows
    )
    if len(claim.route_proof_ids) != 1:
        raise ValueError("equivalent route claim must select exactly one proof")
    proof_id = claim.route_proof_ids[0]
    if proof_id not in source.covered_proof_ids:
        raise ValueError("equivalent route proof is outside source authority")
    row = rows_by_coordinate.get((
        claim.claim_id, proof_id, claim.retired_route_subject.subject_id,
    ))
    if row is None:
        raise ValueError("equivalent route requires one exact realization row")
    return row


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
    cells = captured(cells)
    index = object.__new__(model.ObligationEvidenceIndex)
    stage_unpublished_field(index, "cells", cells)
    stage_unpublished_field(index, "_token", model._OBLIGATION_INDEX_TOKEN)
    model.ObligationEvidenceIndex.__post_init__(index)
    owner = active_facts()
    if owner is not None:
        owner.metrics["validations"] += 1
        return owner._remember(index, index)
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
    retirement_phase_result: model.RetirementPhaseResult | None = None,
    conditional_relations: tuple[model.ConditionalSubjectRelation, ...] = (),
    proposal: model.ProposedUnflattenContract | None = None,
    detached_dead_handler_ids: frozenset[str] = frozenset(),
) -> tuple[model.ObligationKey, ...]:
    result: set[model.ObligationKey] = set()
    relation_dimensions = {(item.target_subject_id, item.dimension) for item in conditional_relations}
    terminal_cycle_carrier_ids = {
        claim.cycle_subject.subject_id
        for claim in claims
        if type(claim) is model.TerminalCycleBreakClaim
    }
    for subject in subjects:
        dimensions = list(REQUIRED_DIMENSIONS[(subject.kind, subject.role)])
        if subject.subject_id in terminal_cycle_carrier_ids:
            # A terminal-cycle claim uses a corridor-shaped carrier to seal
            # its exact residue coordinates.  Coverage is owned by the one
            # canonical dispatcher-corridor subject minted from the producer
            # forecast; making the claim-local carrier a second coverage
            # obligation would require a second, incompatible classifier.
            dimensions = [
                dimension for dimension in dimensions
                if dimension is not model.SafetyDimension.CORRIDOR_COVERAGE
            ]
        if (
            subject.role is model.SemanticSubjectRole.EFFECT_SITE
            and subject.kind is model.SemanticSubjectKind.BLOCK
        ):
            dimensions = [
                dimension for dimension in dimensions
                if dimension is not model.SafetyDimension.EFFECT_PRESERVATION
            ]
        if subject.subject_id in detached_dead_handler_ids:
            dimensions = [
                dimension for dimension in dimensions
                if dimension not in {
                    model.SafetyDimension.TOPOLOGY_INTEGRITY,
                    model.SafetyDimension.HANDLER_REACHABILITY,
                }
            ]
        dimensions.extend(
            dimension for target_id, dimension in relation_dimensions
            if target_id == subject.subject_id
            and dimension not in dimensions
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
        model.UnflattenJustificationRule.DETACHED_COMPONENT_PROVEN,
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
                    allowed = {
                        subject.subject_id
                        for subject in _value_flow_owner_subjects(
                            subjects, target.locator.redirect_owner_refs,
                        )
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
                        )
                    )
                )
                if item.rule is model.UnflattenJustificationRule.UNIQUE_PHASE_BINDING:
                    if target.role is model.SemanticSubjectRole.NON_STATE_VALUE_FLOW:
                        required_owner_ids = {
                            subject.subject_id
                            for subject in _value_flow_owner_subjects(
                                subjects, target.locator.redirect_owner_refs,
                            )
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
                    # A route/effect/corridor subject can retain its own
                    # binding while an owner premise is absent or nonunique.
                    # In that case NONUNIQUE_PHASE_BINDING is a valid
                    # refutation, not malformed evidence.
                    and _identity_support(
                        target,
                        subjects,
                        bindings,
                        phase,
                        candidate_fingerprint,
                        candidate_generation,
                        allow_source_indexed_missing=(
                            phase is not model.UnflattenAuthorityPhase.PRODUCER_FORECAST
                            and target.subject_id in set(source_subject_ids)
                        ),
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
        } and model.AuthorityEvidenceKind.STRUCTURAL_LINEAGE not in premise_kinds:
            raise ValueError("retirement justification requires structural lineage evidence")
        if item.rule is model.UnflattenJustificationRule.EXACT_INFEASIBLE_EFFECT_PROVEN and premise_kinds != (
            model.AuthorityEvidenceKind.EFFECT_SITE,
        ):
            raise ValueError("exact-effect justification requires one effect premise")
        if (
            item.rule
            is model.UnflattenJustificationRule.TERMINAL_CYCLE_BREAK_PROVEN
            and premise_kinds != (model.AuthorityEvidenceKind.TERMINAL_CYCLE,)
        ):
            raise ValueError(
                "terminal claim requires one sealed terminal-cycle phase result"
            )
        if (
            item.rule is model.UnflattenJustificationRule.DETACHED_COMPONENT_PROVEN
            and premise_kinds != (model.AuthorityEvidenceKind.DETACHED_COMPONENT,)
        ):
            raise ValueError("detached claim requires one sealed detached-component phase result")
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
                            and payload.binding.subject in _value_flow_owner_subjects(
                                subjects,
                                item.conclusion.subject.locator.redirect_owner_refs,
                            )
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
                    and target in (payload.route_subject_id, payload.source_subject_id, *payload.destination_subject_ids, *payload.dag_endpoint_subject_ids)
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
                    and payload.corridor_subject_id == target
                ) or (
                    type(payload) is model.TerminalCycleEvidencePayload
                    and target in payload.bound_subject_ids
                ) or (
                    type(payload) is model.DetachedComponentEvidencePayload
                    and target in payload.authorized_subject_ids
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
                model.UnflattenJustificationRule.DETACHED_COMPONENT_PROVEN: type(claim) is model.DetachedDeadHandlerComponentClaim,
            }.get(item.rule, False)
            if not allowed:
                raise ValueError("justification rule does not match its claim")
            if (
                type(claim) is model.RetiredDispatcherInfrastructureClaim
                and item.conclusion.dimension is not model.SafetyDimension.STRUCTURAL_ACCOUNTING
            ):
                raise ValueError("retirement claim supports structural accounting only")
            if (
                type(claim) is model.DetachedDeadHandlerComponentClaim
                and item.conclusion.dimension is not model.SafetyDimension.STRUCTURAL_ACCOUNTING
            ):
                raise ValueError("detached component claim supports structural accounting only")
            claim_targets = {
                subject.subject_id for subject in _claim_subjects(claim)
            }
            if type(claim) is model.RetiredDispatcherInfrastructureClaim:
                claim_member_refs = {
                    member.block_ref for member in claim.member_subjects
                }
                claim_targets.update(
                    subject.subject_id
                    for subject in subjects
                    if subject.role is model.SemanticSubjectRole.DISPATCHER_ENTRY
                    and subject.block_ref in claim_member_refs
                )
            # Structural authority is indexed by the canonical physical
            # source subject, not by any one semantic claim view.  Expand
            # scope only by the exact claim-owned BlockRef.
            structural_refs = set()
            if type(claim) is model.RetiredDispatcherInfrastructureClaim:
                structural_refs.update(member.block_ref for member in claim.member_subjects)
            elif type(claim) is model.EquivalentSemanticRouteClaim:
                structural_refs.add(claim.source_subject.block_ref)
            elif type(claim) is model.ExactInfeasibleEffectClaim:
                structural_refs.add(claim.discarded_effect_subject.block_ref)
            elif type(claim) is model.TerminalCycleBreakClaim:
                structural_refs.add(claim.cycle_subject.block_ref)
            if structural_refs:
                claim_targets.update(
                    subject.subject_id
                    for subject in subjects
                    if subject.role is model.SemanticSubjectRole.SOURCE_CATALOG_BLOCK
                    and subject.block_ref in structural_refs
                )
            if type(claim) is model.LocalAliasEffectScalarizationClaim:
                claim_targets.update(
                    relation.target_subject_id
                    for relation in conditional_relations
                    if relation.source_subject_id == claim.owner_subject.subject_id
                    and relation.dimension is model.SafetyDimension.EFFECT_PRESERVATION
                )
            if item.conclusion.subject.subject_id not in claim_targets:
                raise ValueError("claim justification concludes outside claim scope")
            for premise in item.premise_ids:
                payload = by_evidence_id[premise].payload
                correlated = False
                if type(claim) is model.RetiredDispatcherInfrastructureClaim:
                    correlated = (
                        type(payload) is model.StructuralLineageEvidencePayload
                        and payload.claim_id == claim.claim_id
                    )
                elif type(claim) is model.EquivalentSemanticRouteClaim:
                    correlated = (
                        type(payload) is model.SemanticRouteEvidencePayload
                        and payload.route_subject_id == claim.retired_route_subject.subject_id
                        and payload.source_subject_id == claim.source_subject.subject_id
                        and payload.destination_subject_ids == _route_destination_ids(claim.retired_route_subject, subjects)
                        and payload.dag_endpoint_subject_ids == _route_dag_endpoint_ids(claim.retired_route_subject, subjects)
                    )
                elif type(claim) is model.ExactInfeasibleEffectClaim:
                    correlated = (
                        type(payload) is model.EffectSiteEvidencePayload
                        and payload.effect_subject_id == claim.discarded_effect_subject.subject_id
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
                        type(payload) is model.TerminalCycleEvidencePayload
                        and payload.claim_id == claim.claim_id
                        and payload.terminal_route_proof_id
                        in claim.terminal_route_proof_ids
                        and payload.terminal_subject_id
                        == claim.terminal_subject.subject_id
                    )
                elif type(claim) is model.DetachedDeadHandlerComponentClaim:
                    correlated = (
                        type(payload) is model.DetachedComponentEvidencePayload
                        and payload.claim_id == claim.claim_id
                        and payload.accepted
                        and payload.authorized_subject_ids == tuple(sorted({
                            *(subject.subject_id for subject in claim.dead_handler_subjects),
                            *(subject.subject_id for subject in claim.component_subjects),
                        }))
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


def _value_flow_owner_subjects(
    subjects: Iterable[model.SemanticSubjectRef],
    refs: tuple[object, ...],
) -> tuple[model.SemanticSubjectRef, ...]:
    """Resolve each sealed redirect owner to its canonical source subject.

    Redirect ownership is route-mutation authority, whereas dispatcher
    infrastructure is retirement authority.  The former may be represented by
    an authoritative handler (or a route endpoint) that is not itself retired.
    Prefer an infrastructure subject when a source block has both roles, then
    retain the exact non-dispatcher semantic owner otherwise.
    """

    precedence = (
        (model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE,
         model.SemanticSubjectKind.BLOCK),
        (model.SemanticSubjectRole.AUTHORITATIVE_HANDLER,
         model.SemanticSubjectKind.HANDLER),
        (model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE,
         model.SemanticSubjectKind.BLOCK),
        (model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION,
         model.SemanticSubjectKind.BLOCK),
        (model.SemanticSubjectRole.SEMANTIC_DAG_ENDPOINT,
         model.SemanticSubjectKind.BLOCK),
        (model.SemanticSubjectRole.SOURCE_ENTRY,
         model.SemanticSubjectKind.BLOCK),
        (model.SemanticSubjectRole.DISPATCHER_ENTRY,
         model.SemanticSubjectKind.BLOCK),
        # Every native source block has exactly one catalogue subject.  It is
        # the typed fallback for a physical redirect owner that legitimately
        # has no narrower retirement, handler, route, or entry role.
        (model.SemanticSubjectRole.SOURCE_CATALOG_BLOCK,
         model.SemanticSubjectKind.BLOCK),
    )
    resolved: list[model.SemanticSubjectRef] = []
    for ref in refs:
        selected = ()
        for role, kind in precedence:
            selected = tuple(
                subject for subject in subjects
                if subject.role is role
                and subject.kind is kind
                and subject.block_ref == ref
            )
            if selected:
                break
        if len(selected) != 1:
            raise ValueError(
                "value-flow owner subject is missing or ambiguous: "
                f"ref={ref!r} "
                f"role={selected[0].role.value if selected else None} "
                f"count={len(selected)}"
            )
        resolved.append(selected[0])
    return tuple(resolved)


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
    if type(locator) is model.LogicalFunctionExitSubjectLocator:
        exact_projected_binding = any(
            binding.subject == subject
            and binding.block_ref == locator.block_ref
            and binding.serial == locator.serial
            and binding.anchor_ea is None
            and not binding.native_instruction_eas
            for binding in valid
        )
        if exact_projected_binding:
            return True
        # Hex-Rays may fold the projected logical function-exit and allocate
        # the exact same sink at another observed serial.  The transaction
        # binder owns that exceptional correspondence: accept it only after a
        # registry-sealed occurrence proves this locator's projected serial,
        # this binding's observed serial, and the exact logical reference.
        # The inventory constructor has already checked the occurrence's
        # owner/predecessor realization against the observed graph.
        if phase is not model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY:
            return False
        for binding in valid:
            occurrence = binding.observed_logical_occurrence
            if (
                binding.subject != subject
                or binding.block_ref != locator.block_ref
                or binding.anchor_ea is not None
                or binding.native_instruction_eas
                or binding.serial is None
                or type(occurrence) is not model.ObservedLogicalEndpointOccurrence
                or occurrence.logical_ref != locator.block_ref
                or occurrence.projected_serial != locator.serial
                or occurrence.observed_serial != binding.serial
            ):
                continue
            try:
                authority_bind._validate_observed_logical_endpoint_occurrence(
                    occurrence,
                )
            except (TypeError, ValueError):
                continue
            return True
        return False
    if type(locator) is model.ValueFlowSubjectLocator:
        refs = tuple(locator.redirect_owner_refs)
        if not refs or len(set(refs)) != len(refs):
            return False
        owner_subjects = _value_flow_owner_subjects(inventory, refs)
        if len(owner_subjects) != len(refs):
            return False
        owner_bindings = tuple(
            binding for binding in bindings
            if binding.subject in owner_subjects
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
            for binding in owner_bindings
        )
    if type(locator) is model.RouteSubjectLocator:
        # The binder mints a UNIQUE route row only after its complete typed
        # locator (source plus every native/logical endpoint) resolves against
        # this exact inventory.  Replaying endpoint ownership here creates a
        # second identity authority that can disagree after backend
        # normalization.  Endpoint semantics remain closed independently by
        # route-equivalence evidence and their own subject obligations.
        return exact_subject_binding
    if type(locator) is model.EdgeSubjectLocator:
        return exact_subject_binding and owner(locator.source_ref, locator.source_anchor_ea) and owner(locator.target_ref, locator.target_anchor_ea)
    if type(locator) is model.EffectSubjectLocator:
        # Effect-site bindings already seal the owner anchor and instruction
        # coordinate.  An unrelated preserved effect need not manufacture a
        # separate BLOCK obligation merely to establish that same identity.
        return exact_subject_binding and any(
            binding.subject == subject
            and binding.block_ref == locator.owner_ref
            and binding.anchor_ea == locator.owner_anchor_ea
            and locator.instruction_ea in binding.native_instruction_eas
            for binding in valid
        )
    if type(locator) is model.TerminalSubjectLocator:
        # SemanticGraphInventory already resolves terminal-site bindings
        # against the exact block/instruction rows. Requiring a second BLOCK
        # role for the same owner would reconstruct that authority here.
        return exact_subject_binding and any(
            binding.subject == subject
            and binding.block_ref == locator.block_ref
            and binding.anchor_ea == locator.anchor_ea
            and locator.instruction_ea in binding.native_instruction_eas
            for binding in valid
        )
    if type(locator) is model.HandlerSubjectLocator:
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
        if item.kind is model.SemanticSubjectKind.ROUTE
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
        "source_route_authority_id": (
            None
            if inputs.source_route_authority is None
            else inputs.source_route_authority.source_authority_id
        ),
        "projected_route_realization_id": (
            None
            if inputs.projected_route_realization is None
            else inputs.projected_route_realization.realization_id
        ),
    }
    for name, value in expected.items():
        if getattr(receipt, name) != value:
            raise ValueError(f"preparation receipt {name} mismatch")
    # The native source catalogue is closed by its dedicated catalogue-block
    # subjects.  Anchorless logical DAG endpoints are separately closed by
    # route endpoint identity/equivalence and must not be reinterpreted as
    # native catalogue rows here.
    source_pairs = {
        (subject.block_ref, subject.anchor_ea)
        for subject in source_subjects
        if subject.role is model.SemanticSubjectRole.SOURCE_CATALOG_BLOCK
    }
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
            subject.locator.native_destination_members(),
        )
        for subject in source_subjects
        if type(subject.locator) is model.RouteSubjectLocator
    }
    # Route subjects are claim-owned inventory facts.  Do not reconstruct
    # route expansions from the complete canonical evidence catalogue: that
    # would promote unselected proofs to inventory obligations and would also
    # impose instruction-origin lookup on physical-entry anchors.
    expected_expansions = {
        (
            claim.replacement_route_subject.locator.proof_id,
            claim.replacement_route_subject.locator.source_ref,
            claim.replacement_route_subject.locator.source_anchor_ea,
            claim.replacement_route_subject.locator.native_destination_members(),
        )
        for claim in proposal.claims
        if type(claim) is model.EquivalentSemanticRouteClaim
    }
    if expected_expansions != route_expansions:
        raise ValueError("source inventory does not cover canonical route expansion")


def derive_corridor_coverage_evidence(
    inputs: model.DerivedUnflattenPreparationInputs,
    phase: model.UnflattenAuthorityPhase,
) -> model.CorridorCoverageEvidencePayload | None:
    """Project the transaction-owned corridor phase result for compatibility."""

    if type(inputs) is not model.DerivedUnflattenPreparationInputs:
        raise TypeError("inputs must be DerivedUnflattenPreparationInputs")
    if type(phase) is not model.UnflattenAuthorityPhase:
        raise TypeError("phase must be UnflattenAuthorityPhase")
    model.DerivedUnflattenPreparationInputs.__post_init__(inputs)
    authority_result = inputs.corridor_coverage_phase_result
    phase_inventory = (
        inputs.source_inventory
        if phase is model.UnflattenAuthorityPhase.PRODUCER_FORECAST
        else inputs.candidate_inventory
    )
    corridor = _canonical_dispatcher_corridor_subject(
        phase_inventory.subjects, inputs.proposal,
    )
    if authority_result is None or corridor is None:
        return None
    forecast_authority = inputs.proposal.corridor_coverage_forecast
    if forecast_authority is None:
        raise ValueError("corridor phase result lacks its authority forecast")
    # Inputs revalidate the enclosing union; compatibility evidence only sees
    # its legacy-shaped partition.
    forecast = model.corridor_base_forecast(forecast_authority)
    result = model.corridor_base_phase_result(authority_result)
    expected_pairs = {
            (exclusion_id, path_id)
            for exclusion_id, path_ids in forecast.semantic_exclusion_path_ids
            for path_id in path_ids
    }
    actual_pairs = {
            (item.exclusion_id, item.path_id)
            for item in result.semantic_exclusion_correlations
    }
    if actual_pairs != expected_pairs:
        raise ValueError(
            "semantic exclusion correlations do not cover the exact forecast universe"
        )
    if result.semantic_exclusion_correlations:
        assert forecast is not None
        exclusions = {item.exclusion_id: item for item in forecast.semantic_exclusions}
        claims = {
            claim.claim_id: claim
            for claim in inputs.proposal.claims
            if type(claim) is model.EquivalentSemanticRouteClaim
        }
        proofs = {
            proof.proof_id: proof
            for proof in inputs.proposal.route_evidence.route_proofs
        }
        source_catalog = {
            witness.block_ref: witness
            for witness in inputs.proposal.source_identity_catalog.blocks
        }
        validated_route_rows = _validated_route_realization_rows(inputs, phase)
        for correlation in result.semantic_exclusion_correlations:
            exclusion = exclusions.get(correlation.exclusion_id)
            claim = claims.get(correlation.claim_id)
            proof = proofs.get(correlation.proof_id)
            if exclusion is None or claim is None or proof is None:
                raise ValueError("semantic exclusion correlation has foreign authority")
            if correlation.exclusion_digest != exclusion.digest or correlation.path_id not in result.covered_path_ids:
                raise ValueError("semantic exclusion correlation digest/path drifted")
            if claim.route_proof_ids != (correlation.proof_id,):
                raise ValueError("semantic exclusion correlation proof scope drifted")
            _validate_route_authority_realization(
                inputs, phase, claim,
                _validated_rows=validated_route_rows,
            )
            source_authority = inputs.source_route_authority
            realization = inputs.projected_route_realization
            if (
                correlation.source_fingerprint != source_authority.source_fingerprint
                or correlation.candidate_fingerprint != realization.projected_fingerprint
                or correlation.source_generation != source_authority.source_generation
                or correlation.candidate_generation != realization.projected_generation
            ):
                raise ValueError("semantic exclusion correlation inventory coordinates drifted")
            path = next((item for item in forecast.paths if item.path_id == correlation.path_id), None)
            if path is None or tuple(correlation.ordered_prefix) != path.nodes:
                raise ValueError("semantic exclusion correlation prefix drifted")
            linked_path_ids = next(
                (
                    path_ids for exclusion_id, path_ids
                    in forecast.semantic_exclusion_path_ids
                    if exclusion_id == correlation.exclusion_id
                ),
                (),
            )
            if correlation.path_id not in linked_path_ids:
                raise ValueError("semantic exclusion correlation path is not forecast-linked")
            source_witness = source_catalog.get(exclusion.source.block_ref)
            if (
                source_witness is None
                or source_witness.anchor_ea != exclusion.source.anchor_ea
            ):
                raise ValueError("semantic exclusion correlation source is foreign")
            expected_source_identity = (
                source_witness.block_ref.identity
                if type(source_witness.block_ref) is NativeBlockRef
                else StableBlockIdentity.from_instruction_eas(
                    source_witness.native_instruction_eas,
                    native_key=inputs.proposal.source_identity_catalog.native_key,
                )
            )
            matching_destinations = tuple(
                destination
                for destination in proof.destinations
                if destination.state_constant == exclusion.normalized_state
            )
            claim_destination_pairs = {
                (subject.block_ref, subject.anchor_ea)
                for subject in claim.destination_subjects
            }
            destination_matches = []
            if len(matching_destinations) == 1:
                destination = matching_destinations[0]
                for block_ref, anchor_ea in claim_destination_pairs:
                    witness = source_catalog.get(block_ref)
                    if witness is None or witness.anchor_ea != anchor_ea:
                        continue
                    expected_identity = (
                        witness.block_ref.identity
                        if type(witness.block_ref) is NativeBlockRef
                        else StableBlockIdentity.from_instruction_eas(
                            witness.native_instruction_eas,
                            native_key=inputs.proposal.source_identity_catalog.native_key,
                        )
                    )
                    if (
                        anchor_ea == destination.target_anchor_ea
                        and expected_identity == destination.target_identity
                    ):
                        destination_matches.append((block_ref, anchor_ea))
            if (
                proof.source_identity
                != expected_source_identity
                or proof.source_anchor_ea != exclusion.source.anchor_ea
                or proof.state_write is None
                or proof.state_write.state_variable != exclusion.state_identity
                or proof.state_write.state_constant != exclusion.normalized_state
                or len(destination_matches) != 1
            ):
                raise ValueError("semantic exclusion correlation route semantics drifted")
    if result.phase is not phase:
        raise ValueError("corridor phase result differs from requested phase")
    return model.CorridorCoverageEvidencePayload(
        corridor.subject_id, result.forecast_id, result.result_id,
        result.covered_path_ids, result.residual_path_ids,
        result.drifted_path_ids, result.enumeration_complete,
        result.matched_semantic_exclusion_ids,
        result.source_dispatcher_reachable, result.candidate_dispatcher_reachable,
    )


def _canonical_dispatcher_corridor_subject(
    subjects: tuple[model.SemanticSubjectRef, ...],
    proposal: model.ProposedUnflattenContract,
) -> model.SemanticSubjectRef | None:
    """Select the plan-owned coverage corridor, never a claim-local corridor."""

    inputs = proposal.plan_inputs
    catalog = {
        witness.block_ref: witness
        for witness in proposal.source_identity_catalog.blocks
    }
    try:
        entry_anchor_ea = catalog[inputs.dispatcher_entry_ref].anchor_ea
        member_anchor_eas = tuple(
            catalog[ref].anchor_ea for ref in inputs.dispatcher_member_refs
        )
    except KeyError as exc:
        raise ValueError(
            "dispatcher coverage corridor is absent from the source catalog"
        ) from exc
    member_refs = tuple(sorted(inputs.dispatcher_member_refs, key=canonical_bytes))
    member_anchor_eas = tuple(catalog[ref].anchor_ea for ref in member_refs)
    corridor_id = _content_id_digest("unflatten.corridor.v1", inputs.dispatcher_member_refs)
    matches = tuple(
        subject
        for subject in subjects
        if (
            subject.role is model.SemanticSubjectRole.DISPATCHER_CORRIDOR
            and type(subject.locator) is model.CorridorSubjectLocator
            and subject.block_ref == inputs.dispatcher_entry_ref
            and subject.anchor_ea == entry_anchor_ea
            and subject.locator.corridor_id == corridor_id
            and subject.locator.entry_ref == inputs.dispatcher_entry_ref
            and subject.locator.entry_anchor_ea == entry_anchor_ea
            and subject.locator.member_refs == member_refs
            and subject.locator.member_anchor_eas == member_anchor_eas
        )
    )
    if not matches:
        return None
    if len(matches) != 1:
        raise ValueError("dispatcher coverage corridor is ambiguous")
    return matches[0]


def _select_route_source_subject(
    route_claim: model.UnflattenClaim | None,
    locator: model.RouteSubjectLocator,
    source_subjects: tuple[model.SemanticSubjectRef, ...],
) -> model.SemanticSubjectRef | None:
    """Resolve route payload ownership from the exact claim, never first-match."""

    if type(route_claim) is not model.EquivalentSemanticRouteClaim:
        raise ValueError("route subject is not owned by an equivalent route claim")
    selected = route_claim.source_subject
    if (
        selected.role is not model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE
        or selected.block_ref != locator.source_ref
        or selected.anchor_ea != locator.source_anchor_ea
    ):
        raise ValueError("route claim source is foreign to its route locator")
    if selected.subject_id not in {item.subject_id for item in source_subjects}:
        raise ValueError("route claim source is absent from source inventory")
    return selected


def _observed_folded_transfer_tail_covered(
    *,
    block_ref: object,
    anchor_ea: int | None,
    source_origins: set[int],
    candidate_origins: set[int],
    transfer_ea: int | None,
    effect_and_terminal_eas: frozenset[int],
) -> bool:
    """Account exactly one folded control-transfer tail as block presence.

    A committed transformation can prove a block's conditional tail static and
    remove it, leaving the physical block in place as a fall-through -- with no
    surviving microinstruction at all when that tail was its only one.  The
    block still denotes its own catalog identity, because identity is the
    reference binding plus the native range rather than the instruction count,
    and a control transfer is neither an effect site nor a terminal site, so
    this admits no silent effect or terminal loss.  What the fold changed is
    the block's outgoing edge, which remains owned by the topology and route
    obligations of the same canonical case.

    Everything else stays a loss: a missing origin that is not the tail, a
    foreign origin, an anchor outside every native range, or a reference with
    no native range to anchor the claim.
    """

    if type(block_ref) is not NativeBlockRef or anchor_ea is None:
        return False
    if not block_ref.identity.native_ranges.contains(int(anchor_ea)):
        return False
    if transfer_ea is None or not candidate_origins <= source_origins:
        return False
    missing = source_origins - candidate_origins
    if missing != {int(transfer_ea)}:
        return False
    return not (missing & effect_and_terminal_eas)


def _observed_identity_backed_origin_loss(
    *,
    phase: model.UnflattenAuthorityPhase,
    block_ref: object,
    anchor_ea: int | None,
    source_origins: set[int],
    candidate_origins: set[int],
) -> bool:
    """Recognize strict observed origin loss inside one preserved identity.

    Lineage witnesses back a preserved block with its bindings, not with its
    instruction count.  When a committed transformation folds instructions out
    of a block that stays uniquely bound at the same reference and anchor, the
    remaining -- possibly empty -- origin set is still that block's, provided
    the anchor is one of the surviving origins or a physical entry inside the
    reference's native range.  Whether the fold itself is accountable is
    decided by the classifier, not by this witness check.
    """

    if phase is not model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY:
        return False
    if anchor_ea is None or not candidate_origins < source_origins:
        return False
    return model._anchor_matches_native_scope(
        block_ref, int(anchor_ea), tuple(sorted(candidate_origins)),
    )


def _evaluator_fact_evidence(
    inputs: model.DerivedUnflattenPreparationInputs,
    phase: model.UnflattenAuthorityPhase,
) -> tuple[
    tuple[model.AuthorityEvidence, ...],
    tuple[model.AuthorityEvidence, ...],
    tuple[model.GenericCfgGateResult, ...],
    dict[str, _EffectClassification],
    tuple[_ObservedBranchHelperElision, ...],
]:
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
    route_claims = tuple(
        claim for claim in inputs.claims
        if type(claim) is model.EquivalentSemanticRouteClaim
    )
    validated_route_rows = (
        _validated_route_realization_rows(inputs, phase)
        if route_claims and any(
            subject.kind is model.SemanticSubjectKind.ROUTE
            for subject in source_subjects
        )
        and type(inputs.source_route_authority)
        is model.SourceBoundRouteAuthority
        and type(inputs.projected_route_realization)
        is model.ProjectedRouteRealization
        else {}
    )

    def structural_lineage(
        subject: model.SemanticSubjectRef,
        source_binding: model.PhaseSubjectBinding,
        candidate_binding: model.PhaseSubjectBinding | None,
    ) -> tuple[model.StructuralDisposition, tuple[str, ...], tuple[int, ...], tuple[str, ...]]:
        """Classify block origins from the already-bound candidate inventory."""

        def observed_exact_subset_covered() -> bool:
            if (
                phase is not model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY
                or candidate_binding is None
                or candidate_binding.status is not model.SubjectBindingStatus.UNIQUE
            ):
                return False
            source_origins = set(source_binding.native_instruction_eas)
            candidate_origins = set(candidate_binding.native_instruction_eas)
            if not candidate_origins < source_origins or candidate_binding.anchor_ea not in candidate_origins:
                return False
            missing = source_origins - candidate_origins
            bindings = inputs.projected_route_realization.site_phase_result.exact_effect_bindings
            for ea in missing:
                effect_subjects = tuple(
                    item for item in source_subjects
                    if item.role is model.SemanticSubjectRole.EFFECT_SITE
                    and type(item.locator) is model.EffectSubjectLocator
                    and item.locator.owner_ref == subject.block_ref
                    and item.locator.owner_anchor_ea == subject.anchor_ea
                    and item.locator.instruction_ea == ea
                )
                if len(effect_subjects) != 1:
                    return False
                classification = classifications.get(effect_subjects[0].subject_id)
                if classification is None or not classification.authorized_loss:
                    return False
                if not any(
                    binding.claim is classification.claim
                    and binding.source_site.instruction_ea == ea
                    and binding.source_site.owner.ref == subject.block_ref
                    and binding.source_site.owner.anchor_ea == subject.anchor_ea
                    for binding in bindings
                ):
                    return False
            return True

        def observed_exact_patch_owner_subset_covered() -> bool:
            """Classify only non-semantic normalization of one patched owner.

            A live backend may fold route-plumbing instructions inside a block
            that remains uniquely bound at the same anchor.  That is block
            preservation only when the transaction already owns one exact
            redirect fact for that same physical owner.  Topology, route,
            use-def, effect, and terminal obligations remain independently
            mandatory in the same canonical case.
            """

            if (
                phase is not model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY
                or subject.role is not model.SemanticSubjectRole.SOURCE_CATALOG_BLOCK
                or candidate_binding is None
                or candidate_binding.status is not model.SubjectBindingStatus.UNIQUE
                or candidate_binding.block_ref != subject.block_ref
            ):
                return False
            source_origins = set(source_binding.native_instruction_eas)
            candidate_origins = set(candidate_binding.native_instruction_eas)
            if (
                not candidate_origins < source_origins
                or candidate_binding.anchor_ea not in candidate_origins
            ):
                return False
            missing = source_origins - candidate_origins
            if any(
                row.owner_ref == subject.block_ref
                and row.instruction_ea in missing
                for row in (*source.effects, *source.terminals)
            ):
                return False
            redirect_facts = tuple(
                fact for fact in inputs.patch_step_facts
                if fact.step_type == "PatchRedirectGoto"
                and fact.owner_ref == subject.block_ref
            )
            return len(redirect_facts) == 1

        def observed_folded_transfer_tail() -> bool:
            """Bind the folded-tail term to this subject's own source row."""

            if (
                phase is not model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY
                or candidate_binding is None
                or candidate_binding.status is not model.SubjectBindingStatus.UNIQUE
                or candidate_binding.block_ref != subject.block_ref
            ):
                return False
            source_row = next(
                (
                    row for row in source.blocks
                    if row.block_ref == subject.block_ref
                ),
                None,
            )
            if source_row is None:
                return False
            return _observed_folded_transfer_tail_covered(
                block_ref=subject.block_ref,
                anchor_ea=candidate_binding.anchor_ea,
                source_origins=set(source_binding.native_instruction_eas),
                candidate_origins=set(candidate_binding.native_instruction_eas),
                transfer_ea=source_row.transfer_ea,
                effect_and_terminal_eas=frozenset(
                    row.instruction_ea
                    for row in (*source.effects, *source.terminals)
                    if row.owner_ref == subject.block_ref
                ),
            )

        if source_binding.status is not model.SubjectBindingStatus.UNIQUE:
            return model.StructuralDisposition.UNACCOUNTED_LOSS, (), (), (subject.subject_id,)
        source_origins = set(source_binding.native_instruction_eas)
        # A folded tail leaves no origin to intersect, so the block's own
        # unique binding at the same reference is still its own candidate.
        folded_transfer_tail = observed_folded_transfer_tail()

        def intersects_source_origins(binding: model.PhaseSubjectBinding) -> bool:
            return bool(set(binding.native_instruction_eas) & source_origins) or (
                folded_transfer_tail
                and binding.subject.subject_id == subject.subject_id
            )

        if subject.kind is not model.SemanticSubjectKind.BLOCK:
            if (
                candidate_binding is not None
                and candidate_binding.status is model.SubjectBindingStatus.UNIQUE
            ):
                origins = tuple(sorted(source_origins & set(candidate_binding.native_instruction_eas)))
                return model.StructuralDisposition.PRESERVED, (subject.subject_id,), origins, (subject.subject_id,)
            return model.StructuralDisposition.UNACCOUNTED_LOSS, (), (), (subject.subject_id,)
        # A surviving canonical physical owner with the same exact origin set
        # is preserved.  Helper clones may carry their own lineage, but must
        # not turn this source identity into a synthetic split/loss merely
        # because they exist elsewhere in the candidate inventory.
        if (
            subject.role is model.SemanticSubjectRole.SOURCE_CATALOG_BLOCK
            and candidate_binding is not None
            and candidate_binding.status is model.SubjectBindingStatus.UNIQUE
            and (
                set(candidate_binding.native_instruction_eas) == source_origins
                or observed_exact_patch_owner_subset_covered()
            )
        ):
            return (
                model.StructuralDisposition.PRESERVED,
                (subject.subject_id,),
                tuple(sorted(source_origins)),
                (subject.subject_id,),
            )
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
                and intersects_source_origins(binding)
            }
            if (
                candidate_binding is None
                or candidate_binding.status is not model.SubjectBindingStatus.UNIQUE
                or (
                    set(candidate_binding.native_instruction_eas) != source_origins
                    and not observed_exact_subset_covered()
                    and not folded_transfer_tail
                )
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
            and intersects_source_origins(binding)
        )
        intersecting_candidate_ids = {
            binding.subject.subject_id for binding in intersecting_candidates
        }
        if not closed_targets:
            if (
                candidate_binding is not None
                and candidate_binding.status is model.SubjectBindingStatus.UNIQUE
                and (
                    set(candidate_binding.native_instruction_eas) == source_origins
                    or observed_exact_subset_covered()
                    or folded_transfer_tail
                )
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
                (
                    candidate_origins == source_origins
                    or observed_exact_subset_covered()
                )
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

    topology_roles = _TOPOLOGY_ROLES
    retirement_result = inputs.retirement_phase_result
    projected_topology_reference = _topology_relations_for_inventory(
        inputs.projected_topology_reference,
        topology_roles=topology_roles,
    )
    candidate_topology = _topology_relations_for_inventory(
        candidate,
        topology_roles=topology_roles,
    )
    observed_helper_elisions = _derive_observed_branch_helper_elisions(
        inputs,
        projected_topology=projected_topology_reference,
        candidate_topology=candidate_topology,
    )
    if observed_helper_elisions:
        projected_topology_reference = _fold_observed_branch_helper_topology(
            projected_topology_reference,
            observed_helper_elisions,
        )
    observed_route_topology = _normalize_observed_route_topology(
        inputs,
        projected_topology=projected_topology_reference,
        candidate_topology=candidate_topology,
    )
    if observed_route_topology is not None:
        candidate_topology = observed_route_topology.candidate_topology

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

    # Inventory construction closed reachability before the source binder and
    # projected realizer ran.  The evaluator is deliberately not a second CFG
    # interpreter: it validates the bound subject coordinate against that
    # sealed inventory and records the corresponding closed fact.  Replaying a
    # BFS here used a subtly different evidence model from the realizer.
    source_entry = next((
        item for item in source_subjects
        if item.role is model.SemanticSubjectRole.SOURCE_ENTRY
    ), None)
    candidate_physical_entry_reachable = frozenset(
        candidate.physical_entry_reachable_serials
    )
    candidate_binding_by_id = {
        item.subject.subject_id: item for item in candidate.bindings
    }
    realization = inputs.projected_route_realization
    sealed_unclassified_effect_ids = (
        {
            row.source_subject_id
            for row in realization.site_phase_result.effect_results
            if row.outcome is model.ProjectedEffectSiteOutcome.UNCLASSIFIED
        }
        if type(realization) is model.ProjectedRouteRealization
        else set()
    )
    for subject in source_subjects:
        if subject.role is model.SemanticSubjectRole.EFFECT_SITE and type(subject.locator) is model.EffectSubjectLocator:
            locator = subject.locator
            effect = next((item for item in source.effects
                           if item.owner_ref == locator.owner_ref
                           and item.owner_anchor_ea == locator.owner_anchor_ea
                           and item.instruction_ea == locator.instruction_ea
                           and item.effect_kind is locator.effect_kind), None)
            if effect is not None and effect.owner_serial in source.reachable_serials:
                candidate_binding = candidate_bindings.get(subject.subject_id)
                sealed_rows = (
                    tuple(
                        row
                        for row in inputs.projected_route_realization.site_phase_result.effect_results
                        if row.source_subject_id == subject.subject_id
                    )
                    if (
                        phase is model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT
                        and type(inputs.projected_route_realization)
                        is model.ProjectedRouteRealization
                    )
                    else ()
                )
                sealed_projected = (
                    sealed_rows[0]
                    if len(sealed_rows) == 1
                    and sealed_rows[0].projected_site is not None
                    else None
                )
                projected_site = (
                    sealed_projected.projected_site
                    if sealed_projected is not None else None
                )
                if sealed_projected is not None:
                    candidate_binding = candidate_bindings.get(
                        sealed_projected.projected_subject_id
                    )
                candidate_effect = tuple(
                    item for item in candidate.effects
                    if item.owner_ref == (
                        projected_site.owner.ref
                        if projected_site is not None else effect.owner_ref
                    )
                    and item.owner_anchor_ea == (
                        projected_site.owner.anchor_ea
                        if projected_site is not None else effect.owner_anchor_ea
                    )
                    and item.instruction_ea == (
                        projected_site.instruction_ea
                        if projected_site is not None else effect.instruction_ea
                    )
                    and (
                        projected_site is None
                        or item.instruction_ordinal
                        == projected_site.instruction_ordinal
                    )
                    and item.effect_kind is (
                        projected_site.effect_kind
                        if projected_site is not None else effect.effect_kind
                    )
                    # Inventory preserves source coordinates for diagnostics,
                    # including now-unreachable blocks.  A projected effect
                    # site is present only when its owner is reachable; the
                    # sealed realizer has already classified the other case.
                    and item.owner_serial in candidate.reachable_serials
                )
                alias_context = alias_context_by_effect.get(
                    subject.subject_id, (None, None, None, False),
                )
                classifications[subject.subject_id] = _classify_effect_site(
                    effect,
                    subject,
                    source_bindings[subject.subject_id],
                    candidate_binding,
                    candidate_effect,
                    validated_exact_claims.get(subject.subject_id),
                    inputs.source_route_authority,
                    inputs.projected_route_realization,
                    inputs.generic_gate_facts,
                    local_alias_claim=alias_context[0],
                    local_alias_owner_binding=alias_context[1],
                    local_alias_owner_observation=alias_context[2],
                    local_alias_owner_reachable=alias_context[3],
                    phase=phase,
                )
    for subject in source_subjects:
        if subject.role not in {
            model.SemanticSubjectRole.SOURCE_ENTRY,
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
        # ``reachable_serials`` is the semantic-site discovery closure: it
        # deliberately roots handler and route evidence behind an indirect
        # dispatcher.  These delivery obligations instead prove a physical
        # path from the source entry, so semantic discovery cannot satisfy
        # one by construction.
        reachable = bool(
            type(candidate_serial) is int
            and candidate_serial in candidate_physical_entry_reachable
        )
        path_subject_ids = (
            (source_entry.subject_id,)
            if reachable and subject.subject_id == source_entry.subject_id
            else (source_entry.subject_id, subject.subject_id)
            if reachable else ()
        )
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

    # Semantic-role topology remains a view-level invariant.  The structural
    # loop below deliberately visits only canonical physical subjects, so
    # emit these view facts here rather than accidentally making topology a
    # side effect of loss classification.
    for subject in source_subjects:
        if subject.role not in topology_roles:
            continue
        expected = tuple(
            item for item in projected_topology_reference
            if subject.subject_id in (item.source_subject_id, item.target_subject_id)
        )
        observed = tuple(
            item for item in candidate_topology
            if subject.subject_id in (item.source_subject_id, item.target_subject_id)
        )
        topology = model.TopologyEvidencePayload(
            subject.subject_id,
            tuple(sorted({item.source_subject_id for item in expected if item.target_subject_id == subject.subject_id})),
            tuple(sorted({item.target_subject_id for item in expected if item.source_subject_id == subject.subject_id})),
            has_reciprocal_edges(expected), _authority_id_digest(expected), _authority_id_digest(observed), expected, observed,
        )
        evidence.append(_evidence_factory(
            model.AuthorityEvidence, model.AuthorityEvidenceKind.TOPOLOGY,
            subject, phase, topology,
        ))

    for subject in source_subjects:
        if subject.block_ref is None:
            continue
        if subject.role is not model.SemanticSubjectRole.SOURCE_CATALOG_BLOCK:
            continue
        source_binding = source_bindings.get(subject.subject_id)
        candidate_binding = candidate_bindings.get(subject.subject_id)
        if source_binding is None:
            continue
        effect_classification = None
        if (
            phase is model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT
            and
            effect_classification is not None
            and effect_classification.refuted
            and not effect_classification.authorized_loss
            and subject.subject_id not in sealed_unclassified_effect_ids
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
                      and subject.block_ref in {
                          item.block_ref for item in claim.member_subjects
                      }), None)
        route_claim = next((claim for claim in inputs.claims
                            if type(claim) is model.EquivalentSemanticRouteClaim
                            and claim.source_subject.block_ref == subject.block_ref), None)
        exact_claim = next((claim for claim in inputs.claims
                            if type(claim) is model.ExactInfeasibleEffectClaim
                            and claim.discarded_effect_subject.block_ref == subject.block_ref), None)
        terminal_claim = next((claim for claim in inputs.claims
                               if type(claim) is model.TerminalCycleBreakClaim
                               and subject.block_ref == claim.cycle_subject.block_ref), None)
        retirement_authorized = (
            claim is not None
            and phase is not model.UnflattenAuthorityPhase.PRODUCER_FORECAST
            and retirement_result is not None
            and subject.block_ref in retirement_result.retired_refs
        )
        if (
            retirement_authorized
        ):
            disposition = model.StructuralDisposition.AUTHORIZED_RETIREMENT
        if (
            not retirement_authorized
            and effect_classification is None
            and subject.kind is model.SemanticSubjectKind.BLOCK
        ):
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
                exact_origins,
                (claim.claim_id if claim is not None else
                 route_claim.claim_id if route_claim is not None else
                 exact_claim.claim_id if exact_claim is not None else
                 terminal_claim.claim_id if terminal_claim is not None else None),
                source_group,
            )
            evidence.append(_evidence_factory(model.AuthorityEvidence, model.AuthorityEvidenceKind.STRUCTURAL_LINEAGE, subject, phase, lineage))
        if subject.role not in topology_roles:
            continue
        expected = tuple(item for item in projected_topology_reference if subject.subject_id in (item.source_subject_id, item.target_subject_id))
        observed = tuple(item for item in candidate_topology if subject.subject_id in (item.source_subject_id, item.target_subject_id))
        topology = model.TopologyEvidencePayload(
            subject.subject_id,
            tuple(sorted({
                item.source_subject_id for item in expected
                if item.target_subject_id == subject.subject_id
            })),
            tuple(sorted({
                item.target_subject_id for item in expected
                if item.source_subject_id == subject.subject_id
            })),
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
        expected = tuple(
            item for item in projected_topology_reference
            if helper.subject_id in (item.source_subject_id, item.target_subject_id)
        )
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
                tuple(sorted({
                    item.source_subject_id for item in expected
                    if item.target_subject_id == helper.subject_id
                })),
                tuple(sorted({
                    item.target_subject_id for item in expected
                    if item.source_subject_id == helper.subject_id
                })),
                has_reciprocal_edges(expected),
                _authority_id_digest(expected),
                _authority_id_digest(observed),
                expected, observed,
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
            effect.width or None,
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
                 and item.locator == destination)
            for destination in locator.native_destination_members()
        )
        route_claim = next(
            (
                claim for claim in inputs.claims
                if type(claim) is model.EquivalentSemanticRouteClaim
                and claim.retired_route_subject.subject_id == subject.subject_id
            ),
            None,
        )
        route_pair_valid = False
        # The semantic-route payload always names the claim's declared source
        # coordinate.  Whether that coordinate is authorized is represented by
        # ``matched`` below; falling back to the ROUTE subject when a synthetic
        # preparation lacks a bound route authority manufactures an invalid
        # source coordinate and makes the case unbuildable before the route
        # evidence validator can report the failed match.
        selected_source_subject = (
            route_claim.source_subject
            if type(route_claim) is model.EquivalentSemanticRouteClaim
            else None
        )
        if type(route_claim) is model.EquivalentSemanticRouteClaim:
            try:
                # PROJECTED_PREFLIGHT consumes the sealed row.  Do not
                # select/replay a route from topology, bindings, or claims.
                # The only local work is checking that this source subject is
                # the row's closed claim coordinate.
                row = _validate_route_authority_realization(
                    inputs, phase, route_claim,
                    _validated_rows=validated_route_rows,
                )
                if phase is model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT:
                    route_pair_valid = (
                        row.route_subject_id == subject.subject_id
                        and row.proof_id == locator.proof_id
                        and row.claim_id == route_claim.claim_id
                    )
                    selected_source_subject = route_claim.source_subject
                else:
                    route_pair_valid = True
                    selected_source_subject = _select_route_source_subject(
                        route_claim, locator, source_subjects,
                    )
            except (TypeError, ValueError):
                route_pair_valid = False
        route_payload = model.SemanticRouteEvidencePayload(
            subject.subject_id, (locator.proof_id,), locator.atomic_group_id,
            selected_source_subject.subject_id
            if selected_source_subject is not None else subject.subject_id,
            destinations,
            bool(
                route_pair_valid
                and locator.proof_id in inputs.source_route_authority.covered_proof_ids
            ),
            _route_dag_endpoint_ids(subject, source_subjects),
        )
        evidence.append(_evidence_factory(model.AuthorityEvidence, model.AuthorityEvidenceKind.SEMANTIC_ROUTE, subject, phase, route_payload))

    corridor_subjects = (
        source_subjects
        if phase is model.UnflattenAuthorityPhase.PRODUCER_FORECAST
        else candidate_subjects
    )
    corridor = _canonical_dispatcher_corridor_subject(
        corridor_subjects, inputs.proposal,
    )
    authority_result = inputs.corridor_coverage_phase_result
    if corridor is not None and authority_result is not None:
        forecast_authority = inputs.proposal.corridor_coverage_forecast
        if forecast_authority is None:
            raise ValueError("corridor phase result lacks its authority forecast")
        _forecast = model.corridor_base_forecast(forecast_authority)
        phase_result = model.corridor_base_phase_result(authority_result)
        evidence.append(_evidence_factory(
            model.AuthorityEvidence,
            model.AuthorityEvidenceKind.CORRIDOR_COVERAGE,
            corridor,
            phase,
            model.CorridorCoverageEvidencePayload(
                corridor.subject_id,
                phase_result.forecast_id,
                phase_result.result_id,
                phase_result.covered_path_ids,
                phase_result.residual_path_ids,
                phase_result.drifted_path_ids,
                phase_result.enumeration_complete,
                phase_result.matched_semantic_exclusion_ids,
                phase_result.source_dispatcher_reachable,
                phase_result.candidate_dispatcher_reachable,
            ),
        ))

    generic_gates: list[model.GenericCfgGateResult] = []
    facts = inputs.generic_gate_facts
    if facts is not None:
        entry = next((item for item in source_subjects if item.role is model.SemanticSubjectRole.SOURCE_ENTRY), None)
        entry_ids = () if entry is None else (entry.subject_id,)
        if not facts.entry.passed and not facts.entry.reason:
            raise ValueError("failed entry gate requires a nonblank reason")
        entry_reason = facts.entry.reason or "entry_reachability"
        generic_gates.append(model.GenericCfgGateResult(model.GenericCfgGateKind.ENTRY_REACHABILITY, facts.entry.passed, entry_ids if facts.entry.passed else (), () if facts.entry.passed else entry_ids, entry_reason))
        effect_ids = tuple(item.subject_id for item in source_subjects if item.role is model.SemanticSubjectRole.EFFECT_SITE and type(item.locator) is model.EffectSubjectLocator and item.locator.effect_kind in {model.EffectSiteKind.CALL, model.EffectSiteKind.STORE})
        # For an applicable projected authority, generic raw/effective graph
        # facts are diagnostic inputs.  The sealed site realization and its
        # resulting canonical classifications decide whether each effect loss
        # is permitted; an allowance serial set must never be threaded back
        # into this gate.
        effect_passed = facts.effectful_effective.passed
        if phase is model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT:
            # The individual effect obligations below carry the sealed
            # classification.  This aggregate raw CFG row must not refute all
            # effects merely because one of them is an exact permitted loss.
            effect_passed = True
        generic_gates.append(model.GenericCfgGateResult(model.GenericCfgGateKind.EFFECTFUL_REACHABILITY, effect_passed, effect_ids if effect_passed else (), () if effect_passed else effect_ids, facts.effectful_effective.reason or "effectful_reachability"))
        terminal_ids = tuple(item.subject_id for item in source_subjects if item.role is model.SemanticSubjectRole.TERMINAL_SITE and type(item.locator) is model.TerminalSubjectLocator and item.locator.terminal_kind in {model.TerminalKind.RETURN, model.TerminalKind.STOP})
        # A graph-wide terminal verdict has no canonical target when the source
        # inventory contains no native RETURN/STOP subject.  In particular, a
        # logical decision-DAG FUNCTION_EXIT is route-closure evidence, not a
        # terminal-site subject.  Its exact preservation is decided by the
        # route identity/equivalence obligations above; fabricating an empty
        # failed terminal row would create a second, targetless authority.
        if terminal_ids:
            generic_gates.append(model.GenericCfgGateResult(model.GenericCfgGateKind.TERMINAL_REACHABILITY, facts.terminal.passed, terminal_ids if facts.terminal.passed else (), () if facts.terminal.passed else terminal_ids, facts.terminal.reason or "terminal_reachability"))
    # A missing generic-gate bundle is an absence of evidence.  It must not
    # be converted into synthetic passing rows: inventory-derived reachability
    # and presence evidence remain independently authoritative where defined.
    elided_helper_fact_ids = {
        id(elision.helper_patch_fact)
        for elision in observed_helper_elisions
    }
    patch_evidence_rows = []
    for item in inputs.patch_step_facts:
        if item.plan_id != inputs.proposal.plan_id:
            raise ValueError("patch-step evidence belongs to a different plan")
        if item.step_type not in _SUPPORTED_PATCH_STEP_TYPES:
            raise ValueError("patch-step evidence has an unsupported step kind")
        if id(item) in elided_helper_fact_ids:
            # This is not a generic missing-helper exception.  The exact
            # fact was consumed by `_derive_observed_branch_helper_elisions`,
            # which verified its paired native branch fact, creation digest,
            # sealed relation, and complete reciprocal topology splice.
            continue
        if (
            item.step_type in {"PatchRedirectGoto", "PatchRedirectBranch"}
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
    return (
        tuple(sorted(evidence, key=lambda item: item.evidence_id)),
        patch_evidence,
        tuple(generic_gates),
        classifications,
        observed_helper_elisions,
    )


def _accepted_detached_component_results(
    inputs: model.DerivedUnflattenPreparationInputs,
    phase: model.UnflattenAuthorityPhase,
) -> tuple[tuple[model.DetachedDeadHandlerComponentClaim, model.DetachedDeadHandlerComponentPhaseResult], ...]:
    """Return only sealed detached allowances at these exact case coordinates."""

    corridor_authority = inputs.corridor_coverage_phase_result
    if corridor_authority is None:
        return ()
    if type(corridor_authority) is not model.DefaultGapInfeasibilityPhaseResult:
        # This helper also serves a narrow unit-level detached-component
        # projection.  Production inputs have already validated the enclosing
        # authority pair in DerivedUnflattenPreparationInputs.
        corridor = corridor_authority
    else:
        forecast_authority = inputs.proposal.corridor_coverage_forecast
        if forecast_authority is None:
            raise ValueError("detached component corridor result lacks forecast")
        _forecast = model.corridor_base_forecast(forecast_authority)
        corridor = model.corridor_base_phase_result(corridor_authority)
    claims = {
        claim.claim_id: claim
        for claim in inputs.claims
        if type(claim) is model.DetachedDeadHandlerComponentClaim
    }
    accepted: list[tuple[model.DetachedDeadHandlerComponentClaim, model.DetachedDeadHandlerComponentPhaseResult]] = []
    for result in inputs.detached_dead_handler_component_phase_results:
        claim = claims.get(result.claim_id)
        if claim is None or not result.accepted:
            continue
        if (
            result.phase is not phase
            or result.corridor_coverage_result_id != corridor.result_id
            or result.source_fingerprint != inputs.source_inventory.graph_fingerprint
            or result.candidate_fingerprint != inputs.candidate_inventory.graph_fingerprint
            or result.source_generation != inputs.source_inventory.generation
            or result.candidate_generation != inputs.candidate_inventory.generation
            or claim.source_generation != result.source_generation
        ):
            continue
        accepted.append((claim, result))
    if len({claim.claim_id for claim, _result in accepted}) != len(accepted):
        raise ValueError("detached component claim has ambiguous accepted phase results")
    return tuple(sorted(accepted, key=lambda item: item[0].claim_id))


def _source_subject_matches_catalog(
    subject: model.SemanticSubjectRef,
    witness: model.SourceBlockIdentityWitness | None,
) -> bool:
    """Accept canonical proof sites only for native route-correlated subjects."""
    if witness is None:
        return False
    if witness.anchor_ea == subject.anchor_ea:
        return True
    if subject.role in {
        model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE,
        model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION,
    }:
        return (
            type(subject.block_ref) is NativeBlockRef
            and subject.block_ref == witness.block_ref
            and type(subject.anchor_ea) is int
            and subject.block_ref.identity.native_ranges.contains(subject.anchor_ea)
        )
    return False


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
    for source_result in inputs.detached_dead_handler_component_source_results:
        authority_bind.validate_detached_source_result(source_result)
    for phase_result in inputs.detached_dead_handler_component_phase_results:
        authority_bind.validate_detached_phase_result(phase_result)
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
    (
        lineage_evidence,
        patch_step_evidence,
        generic_gates,
        classifications,
        observed_helper_elisions,
    ) = _evaluator_fact_evidence(inputs, phase)
    elided_helper_subject_ids = frozenset(
        subject.subject_id
        for elision in observed_helper_elisions
        for subject in inputs.projected_topology_reference.subjects
        if subject.block_ref == elision.helper_ref
        and subject.role is model.SemanticSubjectRole.PLANNED_HELPER
    )
    # The helper's only conditional relations are projected-only obligations.
    # The exact sealed elision above discharges them; no other absent planned
    # helper is admitted to this filtered view.
    conditional_relations = tuple(
        relation for relation in inputs.conditional_relations
        if relation.target_subject_id not in elided_helper_subject_ids
    )
    proposal_claim_ids = {claim.claim_id for claim in proposal.claims}
    input_claim_ids = {claim.claim_id for claim in inputs.claims}
    if not proposal_claim_ids <= input_claim_ids or any(
        claim.claim_id not in proposal_claim_ids and type(claim) is not model.LocalAliasEffectScalarizationClaim
        for claim in inputs.claims
    ):
        raise ValueError("derived claims must preserve producer claims and closed transaction-derived claims")
    for claim in inputs.claims:
        if type(claim) is model.TerminalCycleBreakClaim:
            _validate_terminal_cycle_claim_scope(claim, proposal)
    if source_generation != proposal.source_identity_catalog.generation:
        raise ValueError("source generation does not match proposal")
    if not source_subjects:
        raise ValueError("authority requires a non-empty source inventory")
    _validate_receipt(inputs)
    accepted_detached_results = _accepted_detached_component_results(inputs, phase)
    detached_dead_handler_ids = frozenset(
        subject.subject_id
        for claim, _result in accepted_detached_results
        for subject in claim.dead_handler_subjects
    )
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
    for relation in conditional_relations:
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
        if (
            source.role in {
                model.SemanticSubjectRole.SEMANTIC_DAG_ENDPOINT,
                model.SemanticSubjectRole.SOURCE_LOGICAL_EXIT,
            }
            or (
                source.role is model.SemanticSubjectRole.TERMINAL_SITE
                and type(source.locator) is model.LogicalFunctionExitSubjectLocator
            )
        ):
            # Exact anchorless endpoint coordinates are validated by their
            # dedicated identity/equivalence obligations, not by the native
            # source-catalogue membership check below.
            continue
        if source.block_ref is not None:
            witness = catalog_by_ref.get(source.block_ref)
            if not _source_subject_matches_catalog(source, witness):
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
    route_mutation_facts = tuple(
        fact for fact in inputs.patch_step_facts
        if fact.step_type in {
            "PatchConvertToGoto",
            "PatchRedirectGoto",
            "PatchRedirectBranch",
            "PatchLowerConditionalStateTransition",
        }
        and type(fact.owner_ref) is not PlanBlockRef
    )
    redirect_owner_refs = tuple(
        sorted(
            {fact.owner_ref for fact in route_mutation_facts},
            key=_redirect_owner_sort_key,
        )
    )
    if use_def.redirect_owner_refs and not route_mutation_facts:
        raise ValueError("use-def owners require exact route-mutation patch facts")
    if tuple(use_def.redirect_owner_refs) != redirect_owner_refs:
        raise ValueError("use-def owners must match exact route-mutation patch facts")
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
        retirement_phase_result=inputs.retirement_phase_result,
        candidate_generation=(
            source_generation
            if phase is model.UnflattenAuthorityPhase.PRODUCER_FORECAST
            else candidate_generation
        ),
        conditional_relations=conditional_relations,
        proposal=inputs.proposal,
        detached_dead_handler_ids=detached_dead_handler_ids,
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
    canonical_source_by_ref = {
        subject.block_ref: subject
        for subject in source_subjects
        if subject.role is model.SemanticSubjectRole.SOURCE_CATALOG_BLOCK
    }
    authorized_generic_gate_keys = {
        (claim.terminal_subject.subject_id, model.SafetyDimension.TERMINAL_REACHABILITY)
        for claim in inputs.claims
        if type(claim) is model.TerminalCycleBreakClaim
        and any(
            result.claim_id == claim.claim_id
            and result.phase is phase
            and result.terminal_subject_id == claim.terminal_subject.subject_id
            for result in inputs.terminal_cycle_phase_results
        )
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
        if source.role is not model.SemanticSubjectRole.SOURCE_CATALOG_BLOCK:
            continue
        if source.subject_id in supplied_lineage_sources:
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
                for owner in _value_flow_owner_subjects(
                    source_subjects
                    if phase is model.UnflattenAuthorityPhase.PRODUCER_FORECAST
                    else candidate_subjects,
                    key.subject.locator.redirect_owner_refs,
                )
                if owner.subject_id in binding_evidence
            )
        else:
            premises = (binding_evidence[subject_id_],) if subject_id_ in binding_evidence else ()
        _add_justification(
            justifications, key,
            model.UnflattenJustificationRule.UNIQUE_PHASE_BINDING if supports else model.UnflattenJustificationRule.NONUNIQUE_PHASE_BINDING,
            model.EvidencePolarity.SUPPORTS if supports else model.EvidencePolarity.REFUTES, phase,
            premises,
        )
    terminal_cycle_evidence = tuple(
        _evidence_factory(
            model.AuthorityEvidence,
            model.AuthorityEvidenceKind.TERMINAL_CYCLE,
            next(
                claim.cycle_subject for claim in inputs.claims
                if type(claim) is model.TerminalCycleBreakClaim
                and claim.claim_id == result.claim_id
            ),
            phase,
            model.TerminalCycleEvidencePayload(
                result.result_id, result.claim_id,
                result.terminal_route_proof_id, result.phase,
                result.source_fingerprint, result.candidate_fingerprint,
                result.source_generation, result.candidate_generation,
                result.bound_subject_ids, result.source_binding_digest,
                result.candidate_binding_digest, result.residue_refs,
                result.source_cycle_edges, result.candidate_cycle_edges,
                result.source_bindings, result.candidate_bindings,
                result.terminal_source_ref, result.cleanup_source_ref,
                result.terminal_carrier_ref, result.terminal_route_refs,
                result.terminal_subject_id, result.terminal_subject_ref,
            ),
        )
        for result in inputs.terminal_cycle_phase_results
    )
    detached_component_evidence = tuple(
        _evidence_factory(
            model.AuthorityEvidence,
            model.AuthorityEvidenceKind.DETACHED_COMPONENT,
            claim.dispatcher_subject,
            phase,
            model.DetachedComponentEvidencePayload(
                result.result_id,
                result.claim_id,
                result.corridor_coverage_result_id,
                result.phase,
                result.source_fingerprint,
                result.candidate_fingerprint,
                result.source_generation,
                result.candidate_generation,
                result.accepted,
                tuple(sorted({
                    *(subject.subject_id for subject in claim.dead_handler_subjects),
                    *(subject.subject_id for subject in claim.component_subjects),
                })),
            ),
        )
        for claim, result in accepted_detached_results
    )
    evidence = tuple(sorted((
        *evidence_rows, *lineage_evidence, *patch_step_evidence,
        *terminal_cycle_evidence, *detached_component_evidence,
    ), key=lambda item: item.evidence_id))
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

    redirect_owner_refs = {
        fact.owner_ref
        for fact in inputs.patch_step_facts
        if fact.step_type == "PatchRedirectGoto"
    }
    redirect_owner_subject_ids = {
        subject.subject_id
        for subject in source_subjects
        if subject.block_ref in redirect_owner_refs
    }

    native_route_patch_types = {
        "PatchConvertToGoto",
        "PatchRedirectGoto",
        "PatchRedirectBranch",
        "PatchLowerConditionalStateTransition",
    }
    bound_native_route_patch_subject_ids = {
        item.subject.subject_id
        for item in evidence
        if type(item.payload) is model.PatchStepEvidencePayload
        and item.payload.step_type in native_route_patch_types
        and type(item.payload.owner_ref) is not PlanBlockRef
        and any(item.payload is fact for fact in inputs.patch_step_facts)
    }
    topology_subject_ids = {
        subject_id
        for item in topology_items
        for relation in (
            *item.payload.expected_edge_relations,
            *item.payload.candidate_edge_relations,
        )
        for subject_id in (
            relation.source_subject_id,
            relation.target_subject_id,
        )
    }
    folded_conditional_anchor_edges: set[tuple[object, str, str]] = set()
    if type(inputs.projected_route_realization) is model.ProjectedRouteRealization:
        for row in inputs.projected_route_realization.rows:
            if type(row.relation) is not model.FoldedConditionalRouteRealization:
                continue
            if row.plan_step_type is not PatchStepKind.CONVERT_TO_GOTO:
                raise ValueError(
                    "folded conditional relation requires ConvertToGoto ownership"
                )
            matching_facts = tuple(
                fact
                for fact in inputs.patch_step_facts
                if fact.step_index == row.plan_step_index
                and fact.step_type == "PatchConvertToGoto"
                and fact.step_digest == row.plan_step_digest
                and fact.owner_ref == row.relation.feeder.ref
            )
            if len(matching_facts) != 1:
                raise ValueError(
                    "folded conditional relation lacks one exact patch fact"
                )
            feeder_ids = {
                subject.subject_id
                for subject in source_subjects
                if subject.subject_id in topology_subject_ids
                and subject.block_ref == row.relation.feeder.ref
            }
            selected_target_ids = {
                subject.subject_id
                for subject in source_subjects
                if subject.subject_id in topology_subject_ids
                and subject.block_ref == row.relation.selected_target.ref
            }
            if not feeder_ids or not selected_target_ids:
                raise ValueError(
                    "folded conditional relation is absent from topology subjects"
                )
            for feeder_id in feeder_ids:
                for target_id in selected_target_ids:
                    folded_conditional_anchor_edges.add(
                        (model.SemanticEdgeRole.DIRECT, feeder_id, target_id)
                    )
                    folded_conditional_anchor_edges.add(
                        (model.SemanticEdgeRole.DIRECT, target_id, feeder_id)
                    )
    def topology_relations_match(
        expected_relations: Iterable[model.TopologyEdgeRelation],
        candidate_relations: Iterable[model.TopologyEdgeRelation],
    ) -> bool:
        """Compare one observed topology through exact redirect ownership.

        Hex-Rays may replace a planned GOTO's native transfer instruction with
        a generated GOTO anchored at the retained owner block.  The observed
        inventory deliberately preserves that raw anchor.  It is the same
        canonical topology only when every subject-level edge coordinate is
        unchanged and every anchor-only difference is incident to a sealed
        ``PatchRedirectGoto`` owner.  Any adjacency or unowned-anchor drift
        remains a transaction rejection.
        """

        expected = tuple(expected_relations)
        candidate = tuple(candidate_relations)
        if set(expected) == set(candidate):
            return True
        if (
            phase is not model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY
            or not (
                redirect_owner_subject_ids
                or folded_conditional_anchor_edges
            )
        ):
            return False

        def anchors_by_edge(relations):
            result: dict[tuple[object, str, str], set[int]] = defaultdict(set)
            for relation in relations:
                result[(
                    relation.role,
                    relation.source_subject_id,
                    relation.target_subject_id,
                )].add(relation.native_edge_anchor_ea)
            return result

        expected_by_edge = anchors_by_edge(expected)
        candidate_by_edge = anchors_by_edge(candidate)
        expected_edges = set(expected_by_edge)
        candidate_edges = set(candidate_by_edge)
        removed_edges = expected_edges - candidate_edges
        added_edges = candidate_edges - expected_edges
        if added_edges:
            return False
        if removed_edges:
            return False
        changed_edges = {
            edge
            for edge in expected_edges & candidate_edges
            if expected_by_edge[edge] != candidate_by_edge[edge]
        }
        if changed_edges and not all(
            edge in folded_conditional_anchor_edges
            or source_id in redirect_owner_subject_ids
            or target_id in redirect_owner_subject_ids
            for edge in changed_edges
            for _role, source_id, target_id in (edge,)
        ):
            return False
        return bool(removed_edges or changed_edges)

    candidate_drift_ids: set[str] = set()
    if phase is model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT:
        for cycle_refs in _projected_retirement_cycle_refs(
            candidate_refs=_projected_cycle_authority_refs(inputs),
            inventory=candidate_inventory,
        ):
            if _terminal_cycle_allowance_covers(
                cycle_refs,
                claims=inputs.claims,
                phase_results=inputs.terminal_cycle_phase_results,
                phase=phase,
                candidate=candidate_inventory,
            ):
                continue
            if _retirement_cycle_allowance_covers(
                cycle_refs,
                inputs=inputs,
                phase=phase,
                candidate=candidate_inventory,
            ):
                continue
            # The SCC is a projected transaction fact, not a phase-binding
            # inference.  Mark every canonical subject at its stable identity
            # so the ordinary topology obligation rejects before lower().
            candidate_drift_ids.update(
                subject.subject_id
                for subject in source_subjects
                if subject.block_ref in cycle_refs
            )
    for item in topology_items:
        payload = item.payload
        if not topology_relations_match(
            payload.expected_edge_relations,
            payload.candidate_edge_relations,
        ):
            candidate_drift_ids.update(
                relation.source_subject_id
                for relation in (
                    *payload.expected_edge_relations,
                    *payload.candidate_edge_relations,
                )
            )
            candidate_drift_ids.update(
                relation.target_subject_id
                for relation in (
                    *payload.expected_edge_relations,
                    *payload.candidate_edge_relations,
                )
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
            if not topology_relations_match(
                expected_relations, candidate_relations,
            ):
                candidate_drift_ids.update(
                    relation.source_subject_id
                    for relation in (
                        *payload.expected_edge_relations,
                        *payload.candidate_edge_relations,
                    )
                )
                candidate_drift_ids.update(
                    relation.target_subject_id
                    for relation in (
                        *payload.expected_edge_relations,
                        *payload.candidate_edge_relations,
                    )
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
                if topology_relations_match(
                    expected_relations, candidate_relations,
                ):
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
            proposal_proof_ids = {
                proof.proof_id for proof in proposal.route_evidence.route_proofs
            }
            if (
                not payload.proof_ids
                or not set(payload.proof_ids).issubset(proposal_proof_ids)
                or payload.atomic_group_id != proposal.route_evidence.atomic_group_id
            ):
                raise ValueError("route evidence is outside the proposal proof scope")
            route_claim = next(
                (
                    claim for claim in inputs.claims
                    if type(claim) is model.EquivalentSemanticRouteClaim
                    and payload.route_subject_id == claim.retired_route_subject.subject_id
                ),
                None,
            )
            if route_claim is None:
                raise ValueError("route evidence target is outside the claimed route scope")
            if route_claim is not None and (
                payload.proof_ids != route_claim.route_proof_ids
                or payload.atomic_group_id != route_claim.atomic_group_id
                or payload.source_subject_id != route_claim.source_subject.subject_id
                or payload.destination_subject_ids != tuple(
                    _route_destination_ids(route_claim.retired_route_subject, subjects)
                )
                or payload.dag_endpoint_subject_ids != _route_dag_endpoint_ids(
                    route_claim.retired_route_subject, subjects,
                )
            ):
                raise ValueError("route evidence target is outside the claimed route scope")
            if any(target not in known_subject_ids for target in (*payload.destination_subject_ids, *payload.dag_endpoint_subject_ids)):
                raise ValueError("route evidence references a foreign destination")
            route_subject = known_subjects.get(payload.route_subject_id)
            if route_subject is None or type(route_subject.locator) is not model.RouteSubjectLocator:
                raise ValueError("route evidence target is not a derived route subject")
            locator = route_subject.locator
            if (
                locator.proof_id not in payload.proof_ids
                or locator.atomic_group_id != payload.atomic_group_id
                or locator.source_ref != known_subjects[payload.source_subject_id].block_ref
                or locator.native_destination_members() != tuple(
                    known_subjects[target].locator
                    for target in payload.destination_subject_ids
                )
                or locator.dag_endpoint_members() != tuple(
                    known_subjects[target].locator
                    for target in payload.dag_endpoint_subject_ids
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
            forecast_authority = inputs.proposal.corridor_coverage_forecast
            authority_result = inputs.corridor_coverage_phase_result
            if forecast_authority is None or authority_result is None:
                raise ValueError("corridor evidence lacks its transaction-owned result")
            forecast = model.corridor_base_forecast(forecast_authority)
            result = model.corridor_base_phase_result(authority_result)
            if (
                payload.forecast_id != forecast.forecast_id
                or payload.phase_result_id != result.result_id
                or payload.covered_path_ids != result.covered_path_ids
                or payload.residual_path_ids != result.residual_path_ids
                or payload.drifted_path_ids != result.drifted_path_ids
                or payload.enumeration_complete != result.enumeration_complete
                or payload.matched_semantic_exclusion_ids != result.matched_semantic_exclusion_ids
                or payload.source_dispatcher_reachable != result.source_dispatcher_reachable
                or payload.candidate_dispatcher_reachable != result.candidate_dispatcher_reachable
                or item.phase is not result.phase
                or result.source_fingerprint != inputs.source_inventory.graph_fingerprint
                or result.candidate_fingerprint != inputs.candidate_inventory.graph_fingerprint
                or result.source_generation != inputs.source_inventory.generation
                or result.candidate_generation != inputs.candidate_inventory.generation
                or result.source_fingerprint != inputs.preparation_receipt.source_fingerprint
                or result.candidate_fingerprint != inputs.preparation_receipt.candidate_fingerprint
                or result.source_generation != inputs.preparation_receipt.source_generation
                or result.candidate_generation != inputs.preparation_receipt.candidate_generation
            ):
                raise ValueError("corridor evidence drifted from the bound phase result")
            forecast_ids = {path.path_id for path in forecast.paths}
            if set(payload.covered_path_ids) | set(payload.residual_path_ids) | set(payload.drifted_path_ids) != forecast_ids:
                raise ValueError("corridor evidence path partition is not exhaustive")
        elif type(payload) is model.DetachedComponentEvidencePayload:
            header_target = item.subject.subject_id
            matching = tuple(
                (claim, result)
                for claim, result in accepted_detached_results
                if result.result_id == payload.phase_result_id
            )
            if len(matching) != 1:
                raise ValueError("detached evidence lacks one accepted sealed phase result")
            claim, result = matching[0]
            authorized = tuple(sorted({
                *(subject.subject_id for subject in claim.dead_handler_subjects),
                *(subject.subject_id for subject in claim.component_subjects),
            }))
            if (
                item.subject != claim.dispatcher_subject
                or payload.claim_id != claim.claim_id
                or payload.corridor_coverage_result_id != result.corridor_coverage_result_id
                or payload.phase is not result.phase
                or payload.source_fingerprint != result.source_fingerprint
                or payload.candidate_fingerprint != result.candidate_fingerprint
                or payload.source_generation != result.source_generation
                or payload.candidate_generation != result.candidate_generation
                or not payload.accepted
                or payload.authorized_subject_ids != authorized
            ):
                raise ValueError("detached evidence drifted from its sealed phase result")
        elif type(payload) is model.PatchStepEvidencePayload:
            header_target = item.subject.subject_id
            allowed_owner = item.subject.role in {
                model.SemanticSubjectRole.PLANNED_HELPER,
                model.SemanticSubjectRole.EFFECT_SITE,
            } or (
                payload.step_type == "PatchConvertToGoto"
                and item.subject.kind is model.SemanticSubjectKind.BLOCK
                and item.subject.role
                is model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE
            ) or (
                payload.step_type in {
                    "PatchLowerConditionalStateTransition",
                    "PatchRedirectGoto",
                    "PatchRedirectBranch",
                }
                and (
                    item.subject.kind is model.SemanticSubjectKind.BLOCK
                    or (
                        payload.step_type in {
                            "PatchRedirectGoto",
                            "PatchRedirectBranch",
                        }
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
                range_backed_preserved = False
                if payload.disposition is model.StructuralDisposition.PRESERVED:
                    source_binding = source_group_bindings[0]
                    candidate_binding = candidate_bindings_for_lineage[0]
                    same_bound_identity = bool(
                        source_binding is not None
                        and candidate_binding is not None
                        and source_binding.status is model.SubjectBindingStatus.UNIQUE
                        and candidate_binding.status is model.SubjectBindingStatus.UNIQUE
                        # Source/candidate inventories are independently
                        # materialized immutable occurrences.  Their object
                        # identity is deliberately not cross-phase authority;
                        # the sealed nominal subject value is.
                        and source_binding.subject == candidate_binding.subject
                        and source_binding.subject.subject_id
                        == candidate_binding.subject.subject_id
                        and source_binding.block_ref == candidate_binding.block_ref
                        and source_binding.anchor_ea == candidate_binding.anchor_ea
                    )
                    range_backed_preserved = bool(
                        same_bound_identity
                        and (
                            (not source_eas and not candidate_eas[0])
                            # A committed fold can leave this same bound
                            # identity carrying fewer -- or no -- origins.
                            or _observed_identity_backed_origin_loss(
                                phase=phase,
                                block_ref=candidate_binding.block_ref,
                                anchor_ea=candidate_binding.anchor_ea,
                                source_origins=source_eas,
                                candidate_origins=candidate_eas[0],
                            )
                        )
                    )
                if (
                    (any(not eas for eas in candidate_eas) or not source_eas)
                    and not range_backed_preserved
                ):
                    raise ValueError("lineage bindings lack native instruction witnesses")
                if payload.disposition is model.StructuralDisposition.SPLIT and any(
                    left & right for index, left in enumerate(candidate_eas)
                    for right in candidate_eas[index + 1:]
                ):
                    raise ValueError("split/fold candidate origins must be disjoint")
                if payload.disposition is model.StructuralDisposition.PRESERVED:
                    if len(payload.source_subject_ids) != 1:
                        raise ValueError("preserved lineage requires one source")
                    observed_anchor_preserving_loss = (
                        candidate_bindings_for_lineage[0] is not None
                        and _observed_identity_backed_origin_loss(
                            phase=phase,
                            block_ref=candidate_bindings_for_lineage[0].block_ref,
                            anchor_ea=candidate_bindings_for_lineage[0].anchor_ea,
                            source_origins=source_eas,
                            candidate_origins=candidate_eas[0],
                        )
                    )
                    if (
                        candidate_eas[0] != source_eas
                        and not observed_anchor_preserving_loss
                    ):
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
                    if (
                        payload.reciprocal_native_origin_eas != expected_origins
                        and not (
                            payload.disposition
                            is model.StructuralDisposition.PRESERVED
                            and observed_anchor_preserving_loss
                            and not payload.reciprocal_native_origin_eas
                        )
                    ):
                        raise ValueError("lineage reciprocal origins do not match binding witnesses")
            if payload.disposition is model.StructuralDisposition.AUTHORIZED_RETIREMENT:
                retirement_claim = next(
                    (
                        claim for claim in inputs.claims
                        if claim.claim_id == payload.claim_id
                        and type(claim) is model.RetiredDispatcherInfrastructureClaim
                        and (
                            payload.source_subject_id in {
                                member.subject_id for member in claim.member_subjects
                            }
                            or any(
                                subject.subject_id == payload.source_subject_id
                                and subject.role is model.SemanticSubjectRole.SOURCE_CATALOG_BLOCK
                                and subject.block_ref in {
                                    member.block_ref for member in claim.member_subjects
                                }
                                for subject in subjects
                            )
                            or any(
                                subject.subject_id == payload.source_subject_id
                                and subject.role is model.SemanticSubjectRole.DISPATCHER_ENTRY
                                and subject.block_ref in {
                                    member.block_ref for member in claim.member_subjects
                                }
                                for subject in subjects
                            )
                        )
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
                and topology_relations_match(
                    payload.expected_edge_relations,
                    payload.candidate_edge_relations,
                )
            )
            if payload.subject_id in candidate_drift_ids:
                passed = False
            targets = ((payload.subject_id, model.SafetyDimension.TOPOLOGY_INTEGRITY, passed, model.UnflattenJustificationRule.TOPOLOGY_PRESERVED if passed else model.UnflattenJustificationRule.TOPOLOGY_DRIFTED),)
        elif type(payload) is model.StructuralLineageEvidencePayload:
            if payload.disposition is model.StructuralDisposition.AUTHORIZED_RETIREMENT:
                targets = ()
                continue
            source_subject = next(
                (subject for subject in subjects if subject.subject_id == payload.source_subject_id),
                None,
            )
            normalized_loss_claim = next(
                (
                    claim
                    for claim in inputs.claims
                    if payload.claim_id == claim.claim_id
                    and source_subject is not None
                    and (
                        type(claim) is model.EquivalentSemanticRouteClaim
                        and claim.source_subject.block_ref == source_subject.block_ref
                        or type(claim) is model.ExactInfeasibleEffectClaim
                        and claim.discarded_effect_subject.block_ref == source_subject.block_ref
                        or type(claim) is model.TerminalCycleBreakClaim
                        and claim.cycle_subject.block_ref == source_subject.block_ref
                    )
                    and payload.disposition
                    is model.StructuralDisposition.UNACCOUNTED_LOSS
                    and not payload.candidate_subject_ids
                ),
                None,
            )
            if normalized_loss_claim is not None:
                # The raw missing observation is retained as evidence, but a
                # bound typed allowance supplies the one structural verdict.
                # Do not put both SOURCE_LOSS_UNACCOUNTED and claim support
                # on the canonical physical cell.
                targets = ()
                continue
            if (
                payload.source_subject_id
                in bound_native_route_patch_subject_ids
                and payload.disposition
                is model.StructuralDisposition.UNACCOUNTED_LOSS
                and not payload.candidate_subject_ids
            ):
                # The raw binding row records that the original native owner
                # no longer exists as an equal physical block.  Its exact
                # transaction-bound route row is the sole structural verdict;
                # emitting an independent raw-loss refutation would make the
                # same validated patch both supported and rejected.
                targets = ()
                continue
            if (
                payload.source_subject_id in detached_dead_handler_ids
                and payload.disposition is model.StructuralDisposition.UNACCOUNTED_LOSS
                and not payload.candidate_subject_ids
            ):
                # Retain the raw missing-lineage observation, but a sealed
                # detached result is its sole structural classification.
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
                        *payload.dag_endpoint_subject_ids,
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
                for relation in conditional_relations:
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
            complete = (
                payload.enumeration_complete
                and payload.source_dispatcher_reachable
                and not payload.candidate_dispatcher_reachable
                and not payload.residual_path_ids
                and not payload.drifted_path_ids
                and bool(model.corridor_base_forecast(
                    inputs.proposal.corridor_coverage_forecast
                ).paths)
            )
            targets = ((
                payload.corridor_subject_id,
                model.SafetyDimension.CORRIDOR_COVERAGE,
                complete,
                model.UnflattenJustificationRule.CORRIDOR_FULLY_COVERED
                if complete
                else model.UnflattenJustificationRule.CORRIDOR_RESIDUAL_UNACCOUNTED,
            ),)
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
            targets = () if (
                payload.step_type == "PatchScalarizeLocalAliasAccess"
            ) else tuple(
                (target, model.SafetyDimension.STRUCTURAL_ACCOUNTING, True, rule)
                for target in helper_ids
            )
        elif type(payload) is model.GenericCfgGateEvidencePayload:
            dimension = {model.GenericCfgGateKind.ENTRY_REACHABILITY: model.SafetyDimension.ENTRY_REACHABILITY, model.GenericCfgGateKind.EFFECTFUL_REACHABILITY: model.SafetyDimension.EFFECT_PRESERVATION, model.GenericCfgGateKind.TERMINAL_REACHABILITY: model.SafetyDimension.TERMINAL_REACHABILITY}[payload.gate]
            targets = () if payload.gate is model.GenericCfgGateKind.ENTRY_REACHABILITY else tuple((target, dimension, payload.passed, model.UnflattenJustificationRule.GENERIC_CFG_GATE_PASSED if payload.passed else model.UnflattenJustificationRule.GENERIC_CFG_GATE_FAILED) for target in payload.affected_subject_ids)
        elif type(payload) is model.DetachedComponentEvidencePayload:
            targets = ()
        known_subject_ids = {subject.subject_id for subject in subjects}
        if any(target_id not in known_subject_ids for target_id, _, _, _ in targets):
            raise ValueError("evidence payload targets a foreign subject")
        for target_id, dimension, passed, rule in targets:
            if (
                not passed
                and (
                    (target_id, dimension) in authorized_generic_gate_keys
                    or (
                        dimension is model.SafetyDimension.EFFECT_PRESERVATION
                        and (
                            target_id in authorized_loss_subject_ids
                            or (
                                classifications.get(target_id) is not None
                                and classifications[target_id].preserved
                            )
                        )
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
            retirement_result = inputs.retirement_phase_result
            if retirement_result is None:
                raise ValueError("retirement claim lacks a sealed phase result")
            phase_members = {item.block_ref: item for item in retirement_result.members}
            if set(phase_members) != set(
                inputs.proposal.retirement_candidate_catalog.member_refs
            ):
                raise ValueError("retirement phase result differs from exact plan membership")
            retired_member_subjects = tuple(
                member for member in claim.member_subjects
                if phase_members[member.block_ref].classification
                is model.RetirementPhaseClassification.RETIRED
            )
            retired_member_refs = {member.block_ref for member in retired_member_subjects}
            retired_claim_subjects = tuple(
                canonical_source_by_ref[ref]
                for ref in sorted(retired_member_refs, key=repr)
            )
            matching_lineage = tuple(
                item for item in evidence
                if type(item.payload) is model.StructuralLineageEvidencePayload
                and item.payload.claim_id == claim.claim_id
                and item.payload.source_subject_id in {
                    member.subject_id for member in retired_claim_subjects
                }
                and item.payload.disposition is model.StructuralDisposition.AUTHORIZED_RETIREMENT
            )
            claim_evidence = tuple(item.evidence_id for item in matching_lineage)
            lineage_members = tuple(item.payload.source_subject_id for item in matching_lineage)
            # A retirement claim owns the candidate scope, but the phase
            # result decides which members actually retired.  Retained,
            # reachable candidates must not be required to carry a retirement
            # justification (nor be placed in its retired complement).
            exact_lineage = (
                len(matching_lineage) == len(retired_claim_subjects)
                and set(lineage_members) == {
                    member.subject_id for member in retired_claim_subjects
                }
                and len(set(lineage_members)) == len(lineage_members)
            )
            if exact_lineage and retired_member_subjects:
                targets = tuple(
                    (member, model.SafetyDimension.STRUCTURAL_ACCOUNTING)
                    for member in retired_claim_subjects
                )
            rule = model.UnflattenJustificationRule.RETIRED_INFRASTRUCTURE_PROVEN
        elif type(claim) is model.EquivalentSemanticRouteClaim:
            # The projected route payload was emitted directly from the
            # sealed realization row above.  Revalidating it here would make
            # this justification path a second route authority.
            matching_route = tuple(
                item for item in evidence
                if type(item.payload) is model.SemanticRouteEvidencePayload
                and item.payload.route_subject_id == claim.retired_route_subject.subject_id
                and item.payload.source_subject_id == claim.source_subject.subject_id
                and item.payload.destination_subject_ids == _route_destination_ids(claim.retired_route_subject, source_subjects)
                and item.payload.dag_endpoint_subject_ids == _route_dag_endpoint_ids(claim.retired_route_subject, source_subjects)
                and item.payload.atomic_group_id == claim.atomic_group_id
                and item.payload.matched
            )
            if matching_route:
                claim_evidence = tuple(item.evidence_id for item in matching_route)
                canonical_source = canonical_source_by_ref.get(
                    claim.source_subject.block_ref,
                )
                targets = (
                    ((canonical_source, model.SafetyDimension.STRUCTURAL_ACCOUNTING),)
                    if canonical_source is not None else ()
                ) + (
                    (
                        claim.retired_route_subject,
                        model.SafetyDimension.ROUTE_EQUIVALENCE,
                    ),
                    (
                        claim.source_subject,
                        model.SafetyDimension.ROUTE_EQUIVALENCE,
                    ),
                    *tuple(
                        (item, model.SafetyDimension.ROUTE_EQUIVALENCE)
                        for item in claim.destination_subjects
                    ),
                    *tuple(
                        (item, model.SafetyDimension.ROUTE_EQUIVALENCE)
                        for item in claim.dag_endpoint_subjects
                    ),
                )
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
            if matching_effect:
                claim_evidence = tuple(item.evidence_id for item in matching_effect)
                canonical_owner = canonical_source_by_ref.get(
                    claim.discarded_effect_subject.block_ref,
                )
                targets = (
                    (claim.discarded_effect_subject, model.SafetyDimension.EFFECT_PRESERVATION),
                ) + (
                    ((canonical_owner, model.SafetyDimension.STRUCTURAL_ACCOUNTING),)
                    if canonical_owner is not None else ()
                )
            rule = model.UnflattenJustificationRule.EXACT_INFEASIBLE_EFFECT_PROVEN
        elif type(claim) is model.LocalAliasEffectScalarizationClaim:
            alias_relations = tuple(
                relation for relation in conditional_relations
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
            matching_phase_result = tuple(
                item for item in evidence
                if type(item.payload) is model.TerminalCycleEvidencePayload
                and item.payload.claim_id == claim.claim_id
                and item.payload.phase is phase
                and item.payload.terminal_route_proof_id
                in claim.terminal_route_proof_ids
                and item.payload.terminal_subject_id
                == claim.terminal_subject.subject_id
            )
            if len(matching_phase_result) == 1:
                claim_evidence = (matching_phase_result[0].evidence_id,)
                canonical_cycle = canonical_source_by_ref.get(claim.cycle_subject.block_ref)
                targets = (
                    ((canonical_cycle, model.SafetyDimension.STRUCTURAL_ACCOUNTING),)
                    if canonical_cycle is not None else ()
                ) + (
                    (claim.terminal_subject, model.SafetyDimension.TERMINAL_REACHABILITY),
                )
            rule = model.UnflattenJustificationRule.TERMINAL_CYCLE_BREAK_PROVEN
        elif type(claim) is model.DetachedDeadHandlerComponentClaim:
            matching_detached = tuple(
                item for item in evidence
                if type(item.payload) is model.DetachedComponentEvidencePayload
                and item.payload.claim_id == claim.claim_id
                and item.payload.phase is phase
                and item.payload.accepted
                and item.payload.authorized_subject_ids == tuple(sorted({
                    *(subject.subject_id for subject in claim.dead_handler_subjects),
                    *(subject.subject_id for subject in claim.component_subjects),
                }))
            )
            if len(matching_detached) == 1:
                claim_evidence = (matching_detached[0].evidence_id,)
                targets = tuple(
                    (subject, model.SafetyDimension.STRUCTURAL_ACCOUNTING)
                    for subject in (*claim.dead_handler_subjects, *claim.component_subjects)
                )
            rule = model.UnflattenJustificationRule.DETACHED_COMPONENT_PROVEN
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
        conditional_relations,
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
        "bindings": bindings, "conditional_relations": conditional_relations,
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
        "candidate_inventory": candidate_inventory,
        "source_subject_ids": tuple(item.subject_id for item in source_subjects),
        "source_bindings": tuple(source_inventory.bindings),
        "retirement_candidate_catalog": inputs.proposal.retirement_candidate_catalog,
        "retirement_phase_result": inputs.retirement_phase_result,
        "corridor_coverage_phase_result": inputs.corridor_coverage_phase_result,
        "detached_dead_handler_component_source_results": inputs.detached_dead_handler_component_source_results,
        "detached_dead_handler_component_phase_results": inputs.detached_dead_handler_component_phase_results,
        "terminal_cycle_phase_results": inputs.terminal_cycle_phase_results,
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


def _semantic_loss_rows(case: model.SemanticSafetyCase) -> tuple[model.SemanticLossRow, ...]:
    """Evaluator-private row derivation used by authority and diagnostics."""
    if type(case) is not model.SemanticSafetyCase:
        raise TypeError("semantic loss ledger requires SemanticSafetyCase")
    # The caller mints rows only for the exact case it just evaluated.  Do not
    # replay the complete immutable parent here: the transaction gate is the
    # one boundary that validates a completed phase, while rows retain the
    # exact case occurrence and ledger construction validates their closure.
    subjects = {subject.subject_id: subject for subject in case.subjects}
    bindings = {binding.subject.subject_id: binding for binding in case.bindings}
    source_bindings = {binding.subject.subject_id: binding for binding in case.source_bindings}
    cells = {cell.key: cell for cell in case.obligation_index.cells}
    justifications = {item.justification_id: item for item in case.justifications}
    evidence = {item.evidence_id: item for item in case.evidence}
    claims = {item.claim_id: item for item in case.claims}
    rows: list[model.SemanticLossRow] = []
    for subject_id in model._semantic_loss_source_subject_ids(case):
        subject, binding, source_binding = (
            subjects.get(subject_id), bindings.get(subject_id), source_bindings.get(subject_id),
        )
        if subject is None or binding is None or source_binding is None:
            raise ValueError("source subject partition is not covered by the case")
        if case.phase is model.UnflattenAuthorityPhase.PRODUCER_FORECAST:
            continue
        structural = cells.get(model.ObligationKey(subject, model.SafetyDimension.STRUCTURAL_ACCOUNTING))
        if structural is None:
            continue
        owned_effect_subject_ids = set(
            model._semantic_loss_effect_subject_ids(case, subject),
        )
        semantic = tuple(sorted(
            (
                cell for cell in case.obligation_index.cells
                if (
                    cell.key.dimension is not model.SafetyDimension.STRUCTURAL_ACCOUNTING
                    and (
                        cell.key.subject.subject_id == subject_id
                        or cell.key.subject.subject_id in owned_effect_subject_ids
                    )
                )
            ),
            key=lambda cell: (cell.key.subject.subject_id, cell.key.dimension.value),
        ))
        relevant_justifications = tuple(
            justifications[item]
            for cell in (structural, *semantic)
            for item in (*cell.supporting_justification_ids, *cell.refuting_justification_ids)
        )
        rows.append(model.SemanticLossRow(
            case=case, source_subject=subject, source_binding=source_binding,
            candidate_binding=binding, structural_obligation=structural,
            relevant_semantic_obligations=semantic,
            justifications=tuple(sorted(set(relevant_justifications), key=lambda item: item.justification_id)),
            evidence=tuple(sorted({evidence[premise] for item in relevant_justifications for premise in item.premise_ids}, key=lambda item: item.evidence_id)),
            claims=tuple(sorted({claims[item.claim_id] for item in relevant_justifications if item.claim_id is not None}, key=lambda item: item.claim_id)),
        ))
    return tuple(sorted(rows, key=lambda row: row.source_subject.subject_id))


def build_semantic_loss_ledger(
    case: model.SemanticSafetyCase,
    verdict: model.UnflattenAuthorityVerdict,
) -> model.SemanticLossLedger:
    """Mint the sole loss authority for one evaluated canonical case."""
    if type(case) is not model.SemanticSafetyCase:
        raise TypeError("semantic ledger requires SemanticSafetyCase")
    if case.phase not in (
        model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
    ):
        raise ValueError("semantic ledger requires projected or observed case")
    if type(verdict) is not model.UnflattenAuthorityVerdict:
        raise TypeError("semantic ledger requires canonical verdict")
    if verdict.safety_case is not case:
        raise ValueError("semantic ledger verdict must retain exact safety case")
    rows = _semantic_loss_rows(case)
    return construct(model.SemanticLossLedger,
        case=case, authority_id=case.authority_id, case_id=case.case_id,
        phase=case.phase, source_fingerprint=case.source_fingerprint,
        candidate_fingerprint=case.candidate_fingerprint,
        rows=rows,
        ledger_id=_authority_id_digest((
            "unflatten.semantic-loss-ledger.v1", case.case_id,
            tuple((
                row.source_subject.subject_id,
                tuple(kind.value for kind in row.classification_kinds),
                tuple(item.justification_id for item in row.justifications),
                tuple(item.evidence_id for item in row.evidence),
                tuple(item.claim_id for item in row.claims),
            ) for row in rows),
        )),
    )


def build_projected_semantic_loss_ledger(
    case: model.SemanticSafetyCase,
    verdict: model.UnflattenAuthorityVerdict,
) -> model.SemanticLossLedger:
    """Compatibility name for the projected-only ledger factory."""
    if case.phase is not model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT:
        raise ValueError("projected ledger requires PROJECTED_PREFLIGHT case")
    return build_semantic_loss_ledger(case, verdict)


__all__ = [
    "REQUIRED_DIMENSIONS", "derive_corridor_coverage_evidence",
    "build_semantic_case", "build_semantic_loss_ledger", "build_projected_semantic_loss_ledger",
    "evaluate_case", "_build_obligation_index",
]
