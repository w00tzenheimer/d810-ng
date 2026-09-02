"""Validation helpers for the typed unflatten proposal channel.

This module validates the producer-owned value without evaluating it. Route
selection belongs to :mod:`transaction_api`; historical envelopes are decoded
only by the persistence codec and are never producer transport here.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, fields, replace
from d810.core.typing import Literal, TypeAlias
from d810.transforms.cfg_transaction import (
    LogicalBlockRef, NativeBlockRef, PlanBlockRef, PatchStepKind,
)
from d810.ir.graph_fingerprint import _instruction_projection
from d810.transforms.plan import (
    PatchPlan,
    PatchBlockSpec,
    PatchRedirectGoto,
    PatchRedirectBranch,
    PatchConvertToGoto,
    PatchLowerConditionalStateTransition,
    PatchBypassDispatcherTrampoline,
    PatchConditionalRedirect,
    PatchEdgeSplitTrampoline,
    PatchEdgeSplitCorridor,
    PatchInsertBlock,
    PatchDuplicateBlock,
    PatchDuplicateReplayAndRedirect,
    PatchCloneConditionalAsGoto,
    PatchCloneConditionalAsGotoFromBranchArm,
    normalized_metadata_items,
)
from d810.transforms.dispatcher_corridor_coverage import (
    DispatcherCorridor,
    DispatcherCorridorCoverage,
)
from d810.analyses.control_flow.minimal_state_recovery import (
    CandidatePrefixAlternateCorridorProof,
)
from d810.analyses.control_flow.route_comparison import current_u32_route_comparison
from d810.analyses.control_flow.condition_chain_model import ConditionChainRouteEvidence
from d810.analyses.control_flow.semantic_route_evidence import (
    SemanticCorridorPoint,
    SemanticRouteProof,
    SemanticRouteProofKind,
)
from d810.ir.block_identity import (
    StableBlockIdentity,
    stable_block_identity_semantic_anchor,
)
from d810.ir.flowgraph import InsnKind

from .model import (
    CorridorCoverageForecast,
    CorridorCoveragePath,
    CorridorCoveragePathNode,
    DefaultGapInfeasibilityExclusion,
    DefaultGapInfeasibilityForecast,
    DefaultGapInfeasibilityPath,
    DefaultGapInitialStateSeed,
    CorridorPathDisposition,
    CorridorSemanticExclusion,
    CorridorSubjectLocator,
    BlockSubjectLocator,
    HandlerSubjectLocator,
    LogicalFunctionExitSubjectLocator,
    ProposedUnflattenContract,
    EntryEndpointLivenessForecast,
    EntryEndpointLivenessAllowance,
    EntryEndpointLivenessReason,
    SourceBlockIdentityWitness,
    RetirementCandidateCatalog,
    RetirementPlanMember,
    DispatcherRetirementCandidate,
    RetiredDispatcherInfrastructureClaim,
    DetachedDeadHandlerComponentClaim,
    SemanticSubjectKind,
    SemanticSubjectRef,
    SemanticSubjectRole,
    EquivalentSemanticRouteClaim,
    TerminalCycleBreakClaim,
    TerminalKind,
    TerminalSubjectLocator,
    UnflattenClaimKind,
    UnflattenPlanShape,
    UnflattenAuthorityNotApplicable,
    UnflattenAuthorityReason,
    ProposalValidationStage,
    UnflattenPlanRoute,
)
from .producer_api import build_unflatten_plan_input_catalog
from . import producer_api
from .ids import (
    _claim_factory,
    _subject_factory,
    authority_id,
    canonical_bytes,
    content_id,
    validate_canonical_roundtrip,
)
from .legacy_keys import LEGACY_UNFLATTEN_KEYS


def _native_route_destination_subject_for_proof_destination(
    *,
    claim: EquivalentSemanticRouteClaim,
    proof_destination: object,
    catalog: object,
) -> SemanticSubjectRef:
    """Select the one native claim member sealed by a proof destination.

    A route claim may also retain an anchorless logical FUNCTION_EXIT leaf as
    decision-DAG closure evidence.  That leaf is never a physical redirect or
    carrier target: only the proof's native stable identity selects one block
    subject from the source identity catalog.
    """
    target_identity = getattr(proof_destination, "target_identity", None)
    target_anchor_ea = getattr(proof_destination, "target_anchor_ea", None)
    if not isinstance(target_identity, StableBlockIdentity) or type(target_anchor_ea) is not int:
        raise TypeError("route destination selection requires a native proof target")
    blocks = getattr(catalog, "blocks", None)
    if type(blocks) is not tuple:
        raise TypeError("route destination selection requires a source identity catalog")
    witnesses = {item.block_ref: item for item in blocks}
    selected = []
    for subject in claim.destination_subjects:
        locator = subject.locator
        if (
            type(locator) is not BlockSubjectLocator
            or locator.anchor_ea != target_anchor_ea
        ):
            continue
        witness = witnesses.get(locator.block_ref)
        if (
            witness is None
            or type(locator.block_ref) is not NativeBlockRef
            or not locator.block_ref.identity.native_ranges.contains(locator.anchor_ea)
        ):
            continue
        subject_identity = locator.block_ref.identity
        if subject_identity != target_identity:
            continue
        selected.append(subject)
    if len(selected) != 1:
        raise ValueError("route proof native destination is absent or ambiguous in route claim")
    return selected[0]


@dataclass(frozen=True, slots=True)
class RedirectStepManifest:
    """Canonical, typed redirect steps owned by one finalized PatchPlan."""

    steps: tuple[dict[str, object], ...]
    owner_refs: tuple[NativeBlockRef | LogicalBlockRef, ...]
    digest: str


@dataclass(frozen=True, slots=True)
class CanonicalPatchStepDescriptor:
    """One canonical, typed identity for a planned patch step."""

    plan_id: str
    step_index: int
    step_type: str
    step_kind: PatchStepKind | None
    owner_refs: tuple[NativeBlockRef | LogicalBlockRef | PlanBlockRef, ...]
    route_refs: tuple[NativeBlockRef | LogicalBlockRef | PlanBlockRef, ...]
    helper_refs: tuple[PlanBlockRef, ...]
    host_ea: int | None
    host_opcode: int | None
    step_digest: str
    new_block_spec_digests: tuple[tuple[PlanBlockRef, str], ...]

    @property
    def new_block_spec_digest(self) -> str | None:
        """Compatibility view for the historical one-creation descriptor."""
        return self.new_block_spec_digests[0][1] if len(self.new_block_spec_digests) == 1 else None


def _patch_step_preimage(step_index: int, step: object) -> tuple[object, ...]:
    diagnostic_fields = (
        {"proof_id"}
        if type(step) is PatchLowerConditionalStateTransition
        else set()
    )
    values = tuple(
        (
            item.name,
            tuple(_instruction_projection(instruction) for instruction in getattr(step, item.name))
            if item.name == "instructions" and type(step) is PatchConditionalRedirect
            else getattr(step, item.name),
        )
        for item in fields(step)
        if not item.name.startswith("_") and item.name not in diagnostic_fields
    )
    return (type(step).__name__, step_index, values)


def _patch_block_spec_preimage(spec_index: int, spec: PatchBlockSpec) -> tuple[object, ...]:
    values = tuple(
        (item.name, getattr(spec, item.name))
        for item in fields(spec) if not item.name.startswith("_")
    )
    return ("PatchBlockSpec", spec_index, values)


def _nominal_patch_lineage_parts(step: object):
    """Return owner/ref/host coordinates for the closed planner vocabulary."""
    step_type = type(step)
    if step_type is PatchRedirectBranch:
        helper = step.fallthrough_helper_block_id
        return ((step.from_serial, helper) if helper is not None else (step.from_serial,), (step.from_serial, step.old_target, step.new_target), None, None)
    if step_type is PatchRedirectGoto:
        return ((step.from_serial,), (step.from_serial, step.old_target, step.new_target), None, None)
    if step_type is PatchConvertToGoto:
        return ((step.block_serial,), (step.block_serial, step.goto_target), None, None)
    if step_type is PatchLowerConditionalStateTransition:
        return ((step.source_serial,), (step.source_serial, step.old_dispatcher_serial, step.false_target_serial, step.true_target_serial), step.rewrite_from_ea, None)
    if step_type is PatchBypassDispatcherTrampoline:
        return ((step.source_serial,), (step.source_serial, step.trampoline_serial, step.target_serial), None, None)
    if step_type is PatchEdgeSplitTrampoline:
        return ((step.block_id,), (step.source_serial, step.via_pred, step.old_target, step.apply_old_target, step.new_target, step.template_block), None, None)
    if step_type is PatchEdgeSplitCorridor:
        return (tuple(step.clone_block_ids), (step.source_serial, step.via_pred, step.old_target, step.new_target, step.clone_until, *step.corridor_serials, step.source_new_target), None, None)
    if step_type is PatchConditionalRedirect:
        return ((step.block_id, step.fallthrough_block_id), (step.source_serial, step.ref_block, step.conditional_target, step.fallthrough_target, step.old_target_serial), None, None)
    if step_type is PatchInsertBlock:
        return ((step.block_id,), (step.pred_serial, step.succ_serial, step.old_target_serial), None, None)
    if step_type is PatchDuplicateBlock:
        return (
            tuple(ref for ref in (step.block_id, step.fallthrough_block_id) if ref is not None),
            (step.source_serial, step.pred_serial, *step.source_successors,
             step.target_serial, step.conditional_target, step.fallthrough_target),
            None, None,
        )
    if step_type is PatchDuplicateReplayAndRedirect:
        owners = tuple(
            ref for entry in step.per_pred_replays
            for ref in (entry.replay_block_id, entry.clone_block_id)
            if ref is not None
        )
        refs = (
            step.source_serial, step.dispatcher_entry,
            *(ref for entry in step.per_pred_replays for ref in (
                entry.pred_serial, entry.target_serial,
            )),
        )
        return owners, refs, None, None
    if step_type is PatchCloneConditionalAsGoto:
        return (
            (step.block_id,),
            (step.source_serial, step.pred_serial, step.goto_target,
             *step.source_successors, step.conditional_target,
             step.fallthrough_target),
            None, None,
        )
    if step_type is PatchCloneConditionalAsGotoFromBranchArm:
        return (
            (step.block_id,),
            (step.source_serial, step.pred_serial, step.goto_target,
             *step.source_successors, *step.pred_successors,
             step.pred_branch_target_serial,
             step.pred_fallthrough_target_serial,
             step.conditional_target, step.fallthrough_target),
            None, None,
        )
    return None


def _patch_step_kind(step: object) -> PatchStepKind | None:
    return {
        PatchRedirectGoto: PatchStepKind.REDIRECT_GOTO,
        PatchRedirectBranch: PatchStepKind.REDIRECT_BRANCH,
        PatchConvertToGoto: PatchStepKind.CONVERT_TO_GOTO,
        PatchLowerConditionalStateTransition: PatchStepKind.LOWER_CONDITIONAL,
        PatchBypassDispatcherTrampoline: PatchStepKind.BYPASS_TRAMPOLINE,
        PatchConditionalRedirect: PatchStepKind.CONDITIONAL_REDIRECT,
        PatchEdgeSplitTrampoline: PatchStepKind.SPLIT,
        PatchEdgeSplitCorridor: PatchStepKind.HELPER_CORRIDOR,
    }.get(type(step))


def canonical_patch_step_descriptors(plan: PatchPlan) -> tuple[CanonicalPatchStepDescriptor, ...]:
    if type(plan) is not PatchPlan:
        raise TypeError("patch-step descriptors require a closed PatchPlan")
    helper_specs = {spec.block_id: (index, spec) for index, spec in enumerate(plan.new_blocks)}
    result = []
    for index, step in enumerate(plan.steps):
        parts = _nominal_patch_lineage_parts(step)
        if parts is None:
            continue
        owners, refs, host_ea, host_opcode = parts
        helper_refs = tuple(ref for ref in owners if type(ref) is PlanBlockRef)
        helper = helper_specs.get(helper_refs[0]) if len(helper_refs) == 1 else None
        creation_specs = tuple(
            (spec_index, spec)
            for spec_index, spec in enumerate(plan.new_blocks)
            if spec.block_id in owners and isinstance(spec.block_id, PlanBlockRef)
        )
        if len(owners) > 1:
            preimage = (
                *_patch_step_preimage(index, step),
                ("owners", tuple(owners)),
                *( _patch_block_spec_preimage(spec_index, spec) for spec_index, spec in creation_specs),
            )
        else:
            preimage = _patch_step_preimage(index, step) + (("owner", owners[0]),)
            if helper is not None:
                preimage += (_patch_block_spec_preimage(*helper),)
        spec_digests = tuple(
            (spec.block_id, authority_id(_patch_block_spec_preimage(spec_index, spec)))
            for spec_index, spec in creation_specs
        )
        result.append(CanonicalPatchStepDescriptor(
            plan.plan_id, index, type(step).__name__, _patch_step_kind(step),
            tuple(owners), tuple(ref for ref in refs if ref is not None), helper_refs,
            host_ea, host_opcode, authority_id(preimage), spec_digests,
        ))
    return tuple(result)


def canonical_patch_step_descriptor(plan: PatchPlan, step_index: int) -> CanonicalPatchStepDescriptor:
    if type(step_index) is not int or isinstance(step_index, bool) or step_index < 0:
        raise TypeError("step index must be a non-negative integer")
    for descriptor in canonical_patch_step_descriptors(plan):
        if descriptor.step_index == step_index:
            return descriptor
    raise ValueError("plan step is outside the canonical descriptor vocabulary")


def corridor_coverage_forecast_from_analysis(
    coverage: DispatcherCorridorCoverage,
    *,
    proposal: ProposedUnflattenContract,
    block_refs_by_serial: dict[int, NativeBlockRef | LogicalBlockRef],
    default_gap_infeasibility_exclusions: tuple[DefaultGapInfeasibilityExclusion, ...] = (),
) -> CorridorCoverageForecast | DefaultGapInfeasibilityForecast:
    """Seal producer coverage directly into the typed proposal vocabulary.

    The emitter already owns the immutable corridor analysis.  This adapter
    only changes its identity representation; it deliberately does not emit
    a legacy payload and parse that payload back into authority objects.
    """

    if type(proposal) is not ProposedUnflattenContract:
        raise TypeError("coverage forecast requires a closed proposal")
    if type(coverage) is not DispatcherCorridorCoverage:
        raise TypeError("coverage analysis must be DispatcherCorridorCoverage")
    catalog = {
        item.block_ref: item for item in proposal.source_identity_catalog.blocks
    }
    refs_by_serial = dict(block_refs_by_serial)

    def node_coords(serial: int, ea: int, label: str) -> CorridorCoveragePathNode:
        serial = int(serial)
        ea = int(ea)
        ref = refs_by_serial.get(serial)
        if ref is None or ref not in catalog or catalog[ref].anchor_ea != ea:
            raise ValueError(f"coverage {label} is foreign to source catalog")
        return CorridorCoveragePathNode(ref, ea)

    dispatcher_anchor = coverage.dispatcher
    if dispatcher_anchor is None:
        raise ValueError("coverage forecast requires a dispatcher anchor")
    dispatcher_node = node_coords(
        dispatcher_anchor.serial, dispatcher_anchor.ea, "dispatcher"
    )
    dispatcher_ref = dispatcher_node.block_ref
    if dispatcher_ref != proposal.plan_inputs.dispatcher_entry_ref:
        raise ValueError("coverage dispatcher differs from proposal entry")

    exclusions: list[CorridorSemanticExclusion] = []
    exclusion_suffixes: dict[str, tuple[tuple[int, int], ...]] = {}
    for raw in coverage.semantic_exclusions:
        if type(raw) is not CandidatePrefixAlternateCorridorProof:
            raise TypeError("coverage semantic exclusions must be canonical proofs")
        source = node_coords(
            raw.source_serial, raw.source_ea,
            "semantic exclusion source",
        )
        feeder = None
        if raw.feeder_serial is not None:
            feeder = node_coords(
                raw.feeder_serial, raw.feeder_ea,
                "semantic exclusion feeder",
            )
        prefix = node_coords(
            raw.prefix_serial, raw.prefix_ea,
            "semantic exclusion prefix",
        )
        root = node_coords(
            raw.root_serial, raw.root_ea,
            "semantic exclusion root",
        )
        typed = (
            "unflatten.corridor-semantic-exclusion.v1",
            int(raw.normalized_state) & 0xFFFFFFFF,
            raw.state_identity,
            source,
            feeder,
            prefix,
            root,
        )
        exclusion_id = authority_id(typed)
        exclusion = CorridorSemanticExclusion(
            exclusion_id,
            authority_id(("unflatten.corridor-semantic-exclusion-digest.v1", typed)),
            int(raw.normalized_state) & 0xFFFFFFFF,
            raw.state_identity,
            source,
            feeder,
            prefix,
            root,
        )
        exclusions.append(exclusion)
        suffix = [(int(raw.source_serial), int(raw.source_ea))]
        if feeder is not None:
            suffix.append((int(raw.feeder_serial), int(raw.feeder_ea)))
        suffix.extend(
            (
                (int(raw.prefix_serial), int(raw.prefix_ea)),
                (int(raw.root_serial), int(raw.root_ea)),
            )
        )
        exclusion_suffixes[exclusion_id] = tuple(suffix)

    def path_row(corridor: DispatcherCorridor, disposition: CorridorPathDisposition) -> CorridorCoveragePath:
        if type(corridor) is not DispatcherCorridor:
            raise TypeError("coverage paths must be canonical corridors")
        anchors = tuple(
            node_coords(anchor.serial, anchor.ea, "corridor path")
            for anchor in corridor.path
        )
        state_merge = (
            None
            if corridor.state_merge is None
            else node_coords(
                corridor.state_merge.serial,
                corridor.state_merge.ea,
                "corridor state merge",
            )
        )
        path_exclusions = tuple(
            exclusion_id
            for exclusion_id, suffix in exclusion_suffixes.items()
            if len(corridor.path) >= len(suffix)
            and tuple(
                (int(anchor.serial), int(anchor.ea))
                for anchor in corridor.path[-len(suffix):]
            ) == suffix
        )
        actual_disposition = (
            CorridorPathDisposition.SEMANTICALLY_EXCLUDED
            if path_exclusions
            else disposition
        )
        path_id = authority_id((
            "unflatten.corridor-coverage-path.v1", anchors, state_merge,
            actual_disposition, path_exclusions,
        ))
        return CorridorCoveragePath(
            path_id, anchors, state_merge, actual_disposition, path_exclusions,
        )

    covered = tuple(
        path_row(corridor, CorridorPathDisposition.STRUCTURALLY_COVERED)
        for corridor in coverage.covered_corridors
    )
    residual = tuple(
        path_row(corridor, CorridorPathDisposition.RESIDUAL)
        for corridor in coverage.residual_corridors
    )
    paths = tuple(sorted((*covered, *residual), key=lambda path: path.path_id))
    covered_ids = tuple(path.path_id for path in paths if path.disposition is not CorridorPathDisposition.RESIDUAL)
    residual_ids = tuple(path.path_id for path in paths if path.disposition is CorridorPathDisposition.RESIDUAL)
    exclusion_rows = tuple(sorted(exclusions, key=lambda item: item.exclusion_id))
    digest_rows = tuple((item.exclusion_id, item.digest) for item in exclusion_rows)
    linked_paths = tuple(
        (item.exclusion_id, tuple(path.path_id for path in paths if item.exclusion_id in path.semantic_exclusion_ids))
        for item in exclusion_rows
    )
    forecast_id = authority_id((
        "unflatten.corridor-coverage-forecast.v1", proposal.plan_id,
        int(coverage.function_ea), proposal.source_identity_catalog.native_key,
        proposal.source_identity_catalog.generation, dispatcher_ref,
        dispatcher_node.anchor_ea, paths, covered_ids, residual_ids,
        bool(coverage.enumeration_complete), digest_rows, exclusion_rows, linked_paths,
    ))
    base_forecast = CorridorCoverageForecast(
        forecast_id, proposal.plan_id, int(coverage.function_ea),
        proposal.source_identity_catalog.native_key,
        proposal.source_identity_catalog.generation, dispatcher_ref,
        dispatcher_node.anchor_ea, paths, covered_ids, residual_ids,
        bool(coverage.enumeration_complete), digest_rows, exclusion_rows, linked_paths,
    )
    default_gaps = tuple(default_gap_infeasibility_exclusions)
    if not default_gaps:
        return base_forecast
    if not coverage.enumeration_complete:
        raise ValueError("default-gap exclusions require complete corridor enumeration")
    if any(type(item) is not DefaultGapInfeasibilityExclusion for item in default_gaps):
        raise TypeError("default-gap exclusions must be prebuilt closed rows")
    if default_gaps != tuple(sorted(default_gaps, key=lambda item: item.exclusion_id)):
        raise ValueError("default-gap exclusions must be canonically ordered")
    source_blocks = {item.block_ref: item for item in proposal.source_identity_catalog.blocks}
    residual_paths = tuple(
        path for path in base_forecast.paths
        if path.disposition is CorridorPathDisposition.RESIDUAL
    )
    covered_coordinates = {
        (path.nodes, path.state_merge)
        for path in base_forecast.paths
        if path.disposition is not CorridorPathDisposition.RESIDUAL
    }
    residual_coordinates = {(path.nodes, path.state_merge) for path in residual_paths}
    if len(residual_coordinates) != len(residual_paths) or covered_coordinates & residual_coordinates:
        raise ValueError("corridor residual coordinates must be unique and disjoint from covered paths")
    proofs_by_id = {
        proof.proof_id: proof
        for proof in proposal.route_evidence.route_proofs
    }
    extension_paths: list[DefaultGapInfeasibilityPath] = []
    for exclusion in default_gaps:
        if exclusion.state_identity != proposal.plan_inputs.state_identity:
            raise ValueError("default-gap exclusion state identity differs from plan")
        for node in (exclusion.dispatcher, exclusion.default_entry, exclusion.residual):
            witness = source_blocks.get(node.block_ref)
            if witness is None or witness.anchor_ea != node.anchor_ea:
                raise ValueError("default-gap exclusion coordinate is foreign to source catalog")
        if exclusion.dispatcher != dispatcher_node:
            raise ValueError("default-gap exclusion dispatcher differs from coverage dispatcher")
        for seed in exclusion.initial_state_seeds:
            proof = proofs_by_id.get(seed.route_proof_id)
            if proof is None or seed.route_proof_id not in exclusion.route_proof_ids:
                raise ValueError("default-gap seed route proof is absent from canonical route evidence")
            if seed.normalized_state not in {
                int(destination.state_constant) & 0xFFFFFFFF
                for destination in proof.destinations
            }:
                raise ValueError("default-gap seed state is absent from canonical route proof")
            if not any(
                witness.block_ref.identity == proof.source_identity
                and witness.anchor_ea == proof.source_anchor_ea
                for witness in proposal.source_identity_catalog.blocks
                if type(witness.block_ref) is NativeBlockRef
            ):
                raise ValueError("default-gap seed route proof source is foreign to source catalog")
        matching_paths = tuple(path for path in residual_paths if path.nodes[0] == exclusion.residual)
        if len(matching_paths) != 1:
            raise ValueError("default-gap exclusion is not linked to an exact residual path")
        base_path = matching_paths[0]
        extension_paths.append(DefaultGapInfeasibilityPath(
            authority_id((
                "unflatten.default-gap-infeasibility-path.v1", base_path.nodes,
                base_path.state_merge, exclusion.exclusion_id,
            )),
            base_path.nodes, base_path.state_merge, exclusion.exclusion_id,
        ))
    if len({path.path_id for path in extension_paths}) != len(extension_paths):
        raise ValueError("default-gap exclusions must not link one residual path multiple times")
    if {(path.nodes, path.state_merge) for path in extension_paths} != residual_coordinates:
        raise ValueError("default-gap exclusions must cover every exact residual path")
    extension_paths = sorted(extension_paths, key=lambda item: item.path_id)
    digest_rows = tuple((item.exclusion_id, item.digest) for item in default_gaps)
    return DefaultGapInfeasibilityForecast(
        authority_id((
            "unflatten.default-gap-infeasibility-forecast.v1", base_forecast,
            tuple(extension_paths), digest_rows, default_gaps,
        )),
        base_forecast, tuple(extension_paths), digest_rows, default_gaps,
    )


def retirement_member_catalog(
    proposal: ProposedUnflattenContract,
    claim: RetiredDispatcherInfrastructureClaim,
) -> tuple[RetirementPlanMember, ...]:
    """Validate and return the exact candidate-catalog plan membership."""

    if type(proposal) is not ProposedUnflattenContract:
        raise TypeError("retirement catalog requires a closed proposal")
    if type(claim) is not RetiredDispatcherInfrastructureClaim:
        raise TypeError("retirement catalog requires a closed retirement claim")
    source_catalog = {
        item.block_ref: item for item in proposal.source_identity_catalog.blocks
    }
    plan_refs = tuple(proposal.plan_inputs.dispatcher_member_refs)
    if not plan_refs:
        raise ValueError("retirement plan has no dispatcher members")
    if claim.source_generation != proposal.source_identity_catalog.generation:
        raise ValueError("retirement claim generation differs from source catalog")
    candidate_catalog = proposal.retirement_candidate_catalog
    if candidate_catalog is None or claim.candidate_catalog != candidate_catalog:
        raise ValueError("retirement claim is not bound to proposal candidate catalog")
    catalog_rows = {item.block_ref: item for item in candidate_catalog.plan_members}
    if claim.infrastructure_subject.block_ref != proposal.plan_inputs.dispatcher_entry_ref:
        raise ValueError("retirement infrastructure subject is not the dispatcher entry")
    corridor = claim.corridor_subject.locator
    if type(corridor) is not CorridorSubjectLocator:
        raise ValueError("retirement claim corridor locator is not closed")
    entry = source_catalog.get(proposal.plan_inputs.dispatcher_entry_ref)
    if entry is None:
        raise ValueError("dispatcher entry is absent from source catalog")
    catalog_order = tuple(item.block_ref for item in candidate_catalog.plan_members)
    if (
        corridor.entry_ref != proposal.plan_inputs.dispatcher_entry_ref
        or corridor.entry_anchor_ea != entry.anchor_ea
        or tuple(corridor.member_refs) != catalog_order
        or tuple(corridor.member_anchor_eas)
        != tuple(source_catalog[ref].anchor_ea for ref in catalog_order)
    ):
        raise ValueError("retirement corridor is not the exact plan member catalog")
    candidates_by_ref = {member.block_ref: member for member in claim.member_subjects}
    if len(candidates_by_ref) != len(claim.member_subjects) or any(
        ref not in plan_refs for ref in candidates_by_ref
    ):
        raise ValueError("retirement candidates must be an exact plan-member subset")
    rows: list[RetirementPlanMember] = []
    for ref in plan_refs:
        witness = source_catalog.get(ref)
        if witness is None:
            raise ValueError("dispatcher member is absent from source catalog")
        member = candidates_by_ref.get(ref)
        exact_row = catalog_rows.get(ref)
        if exact_row is None:
            raise ValueError("retirement member is absent from candidate catalog")
        if member is not None:
            if (
                member.role is not SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE
                or type(member.locator) is not BlockSubjectLocator
                or member.anchor_ea != witness.anchor_ea
            ):
                raise ValueError("retirement member identity drifted from source catalog")
        if exact_row.anchor_ea != witness.anchor_ea or exact_row.native_instruction_eas != witness.native_instruction_eas:
            raise ValueError("retirement candidate catalog native identity drifted")
        rows.append(exact_row)
    return tuple(rows)


def _redirect_owner_sort_key(
    ref: NativeBlockRef | LogicalBlockRef,
) -> tuple[object, ...]:
    if type(ref) is LogicalBlockRef:
        return ("logical", ref.session_id, ref.proxy_token, ref.version)
    identity = ref.identity
    return (
        "native",
        identity.native_key.to_json(),
        tuple(sorted(identity.exact_instruction_eas)),
        tuple((item.start_ea, item.end_ea) for item in identity.native_ranges.intervals),
    )


def _validate_redirect_ref(
    plan: PatchPlan, value: object, field_name: str, *, source_owner: bool = False,
) -> None:
    allowed = (NativeBlockRef, LogicalBlockRef, PlanBlockRef)
    if type(value) not in allowed:
        raise TypeError(f"redirect {field_name} must be an exact typed block reference")
    if source_owner and type(value) is PlanBlockRef:
        raise ValueError("redirect source owner must be a source block reference")
    if type(value) is PlanBlockRef and value.plan_id != plan.plan_id:
        raise ValueError("redirect plan-owned reference belongs to a foreign plan")


def _validate_redirect_step(plan: PatchPlan, step: object) -> None:
    if type(step) is PatchConvertToGoto:
        _validate_redirect_ref(
            plan, step.block_serial, "convert source owner", source_owner=True,
        )
        _validate_redirect_ref(plan, step.goto_target, "convert selected target")
        return
    if type(step) is PatchLowerConditionalStateTransition:
        _validate_redirect_ref(plan, step.source_serial, "lower source owner", source_owner=True)
        _validate_redirect_ref(plan, step.old_dispatcher_serial, "lower old dispatcher")
        _validate_redirect_ref(plan, step.false_target_serial, "lower false target")
        _validate_redirect_ref(plan, step.true_target_serial, "lower true target")
        return
    if type(step) not in (PatchRedirectGoto, PatchRedirectBranch):
        if isinstance(step, PatchRedirectGoto):
            raise TypeError("redirect step subclasses are unsupported")
        return
    _validate_redirect_ref(plan, step.from_serial, "source owner", source_owner=True)
    _validate_redirect_ref(plan, step.old_target, "old target")
    _validate_redirect_ref(plan, step.new_target, "new target")
    if type(step) is PatchRedirectBranch:
        helper = step.fallthrough_helper_block_id
        if helper is not None and type(helper) is not PlanBlockRef:
            raise TypeError("branch fallthrough helper must be an exact PlanBlockRef")
        if helper is not None and helper.plan_id != plan.plan_id:
            raise ValueError("branch fallthrough helper belongs to a foreign plan")


def canonical_redirect_manifest(plan: PatchPlan) -> RedirectStepManifest:
    """Return the canonical route-mutation manifest used by proposal validation.

    The manifest includes redirect and lower-conditional route steps in plan
    order. Source owners are exact source references, never backend serials or
    plan-local helper references.
    """

    if type(plan) is not PatchPlan:
        raise TypeError("redirect manifest requires a PatchPlan")
    rows: list[dict[str, object]] = []
    owners: list[NativeBlockRef | LogicalBlockRef] = []
    for index, step in enumerate(plan.steps):
        _validate_redirect_step(plan, step)
        if type(step) not in (
            PatchRedirectGoto,
            PatchRedirectBranch,
            PatchConvertToGoto,
            PatchLowerConditionalStateTransition,
        ):
            continue
        if type(step) is PatchRedirectBranch:
            row = {
                "index": index,
                "step_type": "PatchRedirectBranch",
                "from_ref": step.from_serial,
                "old_target": step.old_target,
                "new_target": step.new_target,
                "fallthrough_helper_block_id": step.fallthrough_helper_block_id,
            }
        elif type(step) is PatchRedirectGoto:
            row = {
                "index": index,
                "step_type": "PatchRedirectGoto",
                "from_ref": step.from_serial,
                "old_target": step.old_target,
                "new_target": step.new_target,
            }
        elif type(step) is PatchConvertToGoto:
            descriptor = canonical_patch_step_descriptor(plan, index)
            row = {
                "index": index,
                "step_type": "PatchConvertToGoto",
                "feeder_ref": step.block_serial,
                "selected_target_ref": step.goto_target,
                "step_digest": descriptor.step_digest,
            }
        elif type(step) is PatchLowerConditionalStateTransition:
            descriptor = canonical_patch_step_descriptor(plan, index)
            row = {
                "index": index,
                "step_type": "PatchLowerConditionalStateTransition",
                "source_ref": step.source_serial,
                "old_dispatcher_ref": step.old_dispatcher_serial,
                "false_target_ref": step.false_target_serial,
                "true_target_ref": step.true_target_serial,
                "step_digest": descriptor.step_digest,
            }
        else:
            continue
        rows.append(row)
        owners.append(
            step.source_serial
            if type(step) is PatchLowerConditionalStateTransition
            else step.block_serial
            if type(step) is PatchConvertToGoto
            else step.from_serial
        )
    if not rows:
        raise ValueError("typed proposal requires a non-empty redirect manifest")
    owner_refs = tuple(sorted(set(owners), key=_redirect_owner_sort_key))
    manifest_rows = tuple(rows)
    return RedirectStepManifest(
        steps=manifest_rows,
        owner_refs=owner_refs,
        digest=content_id(
            "unflatten.use-def.redirect-manifest.v1", manifest_rows
        ),
    )


# Public for the codec/router seam and tests.  It is assembled from the
# current owners above, so this backstop cannot drift by omission.


class MetadataKeyTypeError(ValueError):
    """A metadata key is not a closed, exact ``str`` routing input."""


def reserved_metadata_keys(plan: PatchPlan) -> tuple[str, ...]:
    """Return reserved top-level metadata keys in stable metadata order."""

    keys: list[str] = []
    try:
        raw_items = normalized_metadata_items(plan.metadata)
        # Validate the key domain before invoking dict/set hash or equality
        # semantics.  In particular, a str subclass or arbitrary alias must
        # not get an opportunity to impersonate a reserved key.
        for key, _value in raw_items:
            if type(key) is not str:
                raise MetadataKeyTypeError("metadata keys must be exact str")
        dict(raw_items)
        for key, _value in raw_items:
            if key in LEGACY_UNFLATTEN_KEYS:
                keys.append(key)
    except MetadataKeyTypeError:
        raise
    except Exception as exc:
        raise ValueError("metadata key inspection failed") from exc
    return tuple(keys)


@dataclass(frozen=True, slots=True)
class ProposalAccepted:
    """A validated typed proposal bound to one exact plan."""

    proposal: ProposedUnflattenContract

    def __post_init__(self) -> None:
        if type(self.proposal) is not ProposedUnflattenContract:
            raise TypeError("proposal must be a ProposedUnflattenContract")


@dataclass(frozen=True, slots=True)
class ProposalRejected:
    """A typed proposal rejection with an exhaustive authority reason."""

    reason: UnflattenAuthorityReason
    detail_code: str
    key: str | None = None
    stage: ProposalValidationStage | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.reason, UnflattenAuthorityReason):
            raise TypeError("reason must be an UnflattenAuthorityReason")
        if self.reason in (
            UnflattenAuthorityReason.ACCEPTED,
            UnflattenAuthorityReason.NOT_APPLICABLE,
        ):
            raise ValueError("rejection reason must describe rejection")
        if not isinstance(self.detail_code, str) or not self.detail_code.strip():
            raise ValueError("detail_code must not be blank")
        if self.key is not None and self.key not in LEGACY_UNFLATTEN_KEYS:
            raise ValueError("key must be a reserved unflatten metadata key")
        if self.stage is not None and not isinstance(self.stage, ProposalValidationStage):
            raise TypeError("stage must be ProposalValidationStage or None")


ProposalValidationResult: TypeAlias = ProposalAccepted | ProposalRejected


def validate_proposal(
    plan: PatchPlan,
    proposal: object,
) -> ProposalValidationResult:
    """Validate exact proposal type and plan correlation without evaluation."""

    if type(proposal) is not ProposedUnflattenContract:
        return ProposalRejected(
            UnflattenAuthorityReason.MALFORMED_PROPOSAL,
            "proposal_type_is_not_closed",
        )
    if proposal.plan_id != plan.plan_id:
        return ProposalRejected(
            UnflattenAuthorityReason.MALFORMED_PROPOSAL,
            "proposal_plan_id_mismatch",
        )
    try:
        try:
            validate_canonical_roundtrip(proposal, ProposedUnflattenContract)
        except Exception:
            return ProposalRejected(
                UnflattenAuthorityReason.MALFORMED_PROPOSAL,
                "proposal_invariants_invalid",
                stage=ProposalValidationStage.ROUNDTRIP,
            )
        try:
            ProposedUnflattenContract.__post_init__(proposal)
        except Exception:
            return ProposalRejected(
                UnflattenAuthorityReason.MALFORMED_PROPOSAL,
                "proposal_invariants_invalid",
                stage=ProposalValidationStage.PROPOSAL_POST_INIT,
            )
        try:
            _validate_use_def_locator(plan, proposal)
        except Exception:
            return ProposalRejected(
                UnflattenAuthorityReason.MALFORMED_PROPOSAL,
                "proposal_invariants_invalid",
                stage=ProposalValidationStage.USE_DEF,
            )
        for claim in proposal.claims:
            if type(claim) is RetiredDispatcherInfrastructureClaim:
                try:
                    retirement_member_catalog(proposal, claim)
                except Exception:
                    return ProposalRejected(
                        UnflattenAuthorityReason.MALFORMED_PROPOSAL,
                        "proposal_invariants_invalid",
                        stage=ProposalValidationStage.RETIREMENT_CATALOG,
                    )
        source_blocks = proposal.source_identity_catalog.blocks
        if source_blocks and all(
            type(block.block_ref) is NativeBlockRef for block in source_blocks
        ):
            source_serial_by_ref = {
                block.block_ref: serial
                for serial, block in enumerate(source_blocks)
            }
            for claim in proposal.claims:
                if type(claim) is not producer_api.ExactInfeasibleEffectClaim:
                    continue
                try:
                    valid = producer_api.validate_exact_effect_claim_semantics(
                        proposal=proposal,
                        claim=claim,
                        source_serial_by_ref=source_serial_by_ref,
                    )
                except Exception:
                    valid = None
                if valid is None:
                    return ProposalRejected(
                        UnflattenAuthorityReason.MALFORMED_PROPOSAL,
                        "proposal_invariants_invalid",
                        stage=ProposalValidationStage.EXACT_EFFECT_CORRELATION,
                    )
    except Exception:
        return ProposalRejected(
            UnflattenAuthorityReason.MALFORMED_PROPOSAL,
            "proposal_invariants_invalid",
            stage=ProposalValidationStage.PROPOSAL_POST_INIT,
        )
    return ProposalAccepted(proposal)


def _validate_use_def_locator(
    plan: PatchPlan, proposal: ProposedUnflattenContract
) -> None:
    """Validate the fragment-wide locator against the source catalog.

    The value-flow subject is an aggregate, so it has no block serial or
    primary owner.  Its owner references must nevertheless be an exact,
    non-empty set of source-catalog references; otherwise a producer could
    omit or substitute redirect owners while retaining a superficially valid
    typed proposal.
    """

    if type(plan.source_generation) is not int:
        raise TypeError("typed proposal requires an exact integer source generation")
    catalog = proposal.source_identity_catalog
    if type(catalog.generation) is not int or plan.source_generation != catalog.generation:
        raise ValueError("proposal source generation does not match PatchPlan")
    manifest = canonical_redirect_manifest(plan)
    witness = proposal.use_def_witness
    if tuple(witness.redirect_owner_refs) != manifest.owner_refs:
        raise ValueError("use-def redirect owners do not match the redirect manifest")
    if witness.redirect_digest != manifest.digest:
        raise ValueError("use-def redirect digest does not match the redirect manifest")
    catalog_refs = {item.block_ref for item in catalog.blocks}
    if not set(manifest.owner_refs) <= catalog_refs:
        raise ValueError("use-def redirect owner is outside the source catalog")


def _validated_terminal_route_claim(
    proposal: ProposedUnflattenContract,
    *,
    proof_id: str | None = None,
    source_ref: NativeBlockRef | LogicalBlockRef | None = None,
    target_ref: NativeBlockRef | LogicalBlockRef | None = None,
) -> tuple[EquivalentSemanticRouteClaim, object]:
    """Select one closed route claim, then validate its canonical proof.

    Route proof coordinates are physical evidence coordinates and may point at
    a block entry that is not an exact instruction origin.  The route claim's
    normalized subjects are therefore the authority for endpoint ownership;
    the proof is checked against those subjects without reconstructing them
    from a raw catalog anchor scan.
    """

    if type(proposal) is not ProposedUnflattenContract:
        raise TypeError("terminal route selection requires a closed proposal")
    if proof_id is not None:
        selected = tuple(
            claim
            for claim in proposal.claims
            if type(claim) is EquivalentSemanticRouteClaim
            and proof_id in claim.route_proof_ids
        )
    else:
        if source_ref is None or target_ref is None:
            raise ValueError("terminal route selection requires proof or endpoint coordinates")
        selected = tuple(
            claim
            for claim in proposal.claims
            if type(claim) is EquivalentSemanticRouteClaim
            and claim.source_subject.block_ref == source_ref
            and sum(
                subject.block_ref == target_ref
                for subject in claim.destination_subjects
            ) == 1
        )
    if len(selected) != 1:
        raise ValueError("terminal route claim is absent or ambiguous")
    claim = selected[0]
    validate_canonical_roundtrip(claim, EquivalentSemanticRouteClaim)
    selected_proof_id = claim.route_proof_ids[0]
    proofs = tuple(
        proof
        for proof in proposal.route_evidence.route_proofs
        if proof.proof_id == selected_proof_id
    )
    if len(proofs) != 1:
        raise ValueError("terminal route proof is absent or ambiguous")
    proof = proofs[0]
    if proof.atomic_group_id != claim.atomic_group_id:
        raise ValueError("terminal route proof atomic group differs from route claim")
    destinations = tuple(proof.destinations)
    catalog = {
        item.block_ref: item for item in proposal.source_identity_catalog.blocks
    }

    def identity_for(subject: SemanticSubjectRef, label: str) -> StableBlockIdentity:
        witness = catalog.get(subject.block_ref)
        if witness is None:
            raise ValueError(f"terminal route {label} subject is foreign to source catalog")
        if type(subject.block_ref) is NativeBlockRef:
            if (
                subject.anchor_ea is None
                or not subject.block_ref.identity.native_ranges.contains(
                    int(subject.anchor_ea)
                )
            ):
                raise ValueError(
                    f"terminal route {label} subject is foreign to source catalog"
                )
            return subject.block_ref.identity
        if witness.anchor_ea != subject.anchor_ea:
            raise ValueError(f"terminal route {label} subject is foreign to source catalog")
        if not witness.native_instruction_eas:
            raise ValueError(f"terminal route {label} subject has no native identity")
        return StableBlockIdentity.from_instruction_eas(
            witness.native_instruction_eas,
            native_key=proposal.source_identity_catalog.native_key,
        )

    source_subject = claim.source_subject
    source_identity = identity_for(source_subject, "source")
    bound_destinations = tuple(
        (
            destination,
            _native_route_destination_subject_for_proof_destination(
                claim=claim,
                proof_destination=destination,
                catalog=proposal.source_identity_catalog,
            ),
        )
        for destination in destinations
    )
    if target_ref is None:
        selected_destinations = bound_destinations
    else:
        selected_destinations = tuple(
            item for item in bound_destinations if item[1].block_ref == target_ref
        )
    if len(selected_destinations) != 1:
        raise ValueError(
            "terminal route proof must bind exactly one terminal carrier destination"
        )
    destination, destination_subject = selected_destinations[0]
    if target_ref is not None and destination_subject.block_ref != target_ref:
        raise ValueError("terminal route destination differs from selected endpoint")
    destination_identity = destination.target_identity
    if (
        proof.source_identity != source_identity
        or not source_identity.native_ranges.contains(proof.source_anchor_ea)
        or not destination_identity.native_ranges.contains(destination.target_anchor_ea)
    ):
        raise ValueError("terminal route proof endpoints differ from selected route claim")
    return claim, proof


def claims_from_dispatcher_removal_forecast(
    coverage: DispatcherCorridorCoverage,
    *,
    proposal: ProposedUnflattenContract,
    block_refs_by_serial: dict[int, NativeBlockRef | LogicalBlockRef],
) -> tuple[RetiredDispatcherInfrastructureClaim | DetachedDeadHandlerComponentClaim | TerminalCycleBreakClaim, ...]:
    """Convert producer retirement forecasts into canonical typed claims.

    A missing or incomplete forecast yields no retirement claim.  This helper
    never manufactures a pass/fail result; transaction binding replays the
    candidate against source and candidate inventories.
    """

    if type(coverage) is not DispatcherCorridorCoverage:
        raise TypeError("dispatcher removal forecast must be corridor coverage")
    if not coverage.enumeration_complete:
        return ()
    if coverage.residual_corridors:
        forecast = proposal.corridor_coverage_forecast
        if type(forecast) is not DefaultGapInfeasibilityForecast:
            return ()
        base = forecast.base_forecast
        base_residual_coordinates = {
            (path.nodes, path.state_merge)
            for path in base.paths
            if path.path_id in base.residual_path_ids
        }
        extension_coordinates = {
            (path.nodes, path.state_merge) for path in forecast.paths
        }
        if base_residual_coordinates != extension_coordinates or len(base_residual_coordinates) != len(forecast.paths):
            return ()
    terminal = coverage.cycle_break
    retired_forecast = tuple(coverage.retirement_candidates)
    detached = getattr(coverage, "detached_dead_handler_component", None)
    if not retired_forecast and terminal is None and detached is None:
        return ()
    catalog = {item.block_ref: item for item in proposal.source_identity_catalog.blocks}
    refs_by_serial = dict(block_refs_by_serial)
    plan_refs = tuple(sorted(proposal.plan_inputs.dispatcher_member_refs, key=canonical_bytes))
    entry_ref = proposal.plan_inputs.dispatcher_entry_ref
    entry = catalog.get(entry_ref)
    if entry is None:
        raise ValueError("dispatcher entry is absent from source catalog")
    handler_inputs = {
        item.block_ref: item for item in proposal.plan_inputs.authoritative_handlers
    }
    candidate_catalog = retirement_candidate_catalog_from_forecast(
        coverage,
        proposal=proposal,
        block_refs_by_serial=block_refs_by_serial,
    )

    def resolve(anchor: object, label: str):
        serial, ea = int(anchor.serial), int(anchor.ea)
        ref = refs_by_serial.get(serial)
        witness = catalog.get(ref)
        # An anchorless logical terminal remains an exact source coordinate by
        # its sealed ref/serial pairing; it must not be fabricated as native.
        if (
            label == "terminal stop"
            and type(ref) is LogicalBlockRef
            and witness is None
        ):
            return ref, serial
        if ref is None or witness is None or witness.anchor_ea != ea:
            raise ValueError(f"dispatcher removal {label} is foreign to source catalog")
        return ref, ea

    if terminal is not None:
        dispatcher_ref, dispatcher_ea = resolve(terminal.dispatcher, "terminal dispatcher")
        if dispatcher_ref != entry_ref:
            raise ValueError("terminal switch dispatcher differs from plan entry")
        source_ref, source_ea = resolve(terminal.terminal_source, "terminal source")
        merge_ref, merge_ea = resolve(terminal.shared_merge, "shared merge")
        target_ref, target_ea = resolve(terminal.terminal_target, "terminal target")
        stop_ref, stop_ea = resolve(terminal.terminal_stop, "terminal stop")
        residue_rows = tuple(
            resolve(anchor, "retired residue") for anchor in terminal.retired_residue
        )
        residue_refs = tuple(ref for ref, _ea in residue_rows)
        residue_anchors = tuple(ea for _ref, ea in residue_rows)
        if (
            not residue_refs
            or len(set(residue_refs)) != len(residue_refs)
            or entry_ref not in residue_refs
            or merge_ref not in residue_refs
            or not set(residue_refs) <= set(plan_refs)
        ):
            raise ValueError("terminal switch residue is not an exact plan subset")
        for retired in coverage.retirement_candidates:
            resolve(retired.anchor, "retired infrastructure")

        _route_claim, route_proof = _validated_terminal_route_claim(
            proposal, source_ref=source_ref, target_ref=target_ref,
        )

        cycle = _subject_factory(
            SemanticSubjectRef,
            kind=SemanticSubjectKind.CORRIDOR,
            role=SemanticSubjectRole.DISPATCHER_CORRIDOR,
            block_ref=dispatcher_ref,
            anchor_ea=dispatcher_ea,
            locator=CorridorSubjectLocator(
                authority_id(("unflatten.terminal-cycle.v1", proposal.plan_id, residue_refs)),
                dispatcher_ref,
                dispatcher_ea,
                residue_refs,
                residue_anchors,
            ),
        )
        cleanup = _subject_factory(
            SemanticSubjectRef,
            kind=SemanticSubjectKind.BLOCK,
            role=SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE,
            block_ref=merge_ref,
            anchor_ea=merge_ea,
            locator=BlockSubjectLocator(merge_ref, merge_ea),
        )
        terminal_locator = (
            LogicalFunctionExitSubjectLocator(stop_ref, stop_ea)
            if type(stop_ref) is LogicalBlockRef
            else TerminalSubjectLocator(stop_ref, stop_ea, TerminalKind.STOP, stop_ea)
        )
        terminal_subject = _subject_factory(
            SemanticSubjectRef,
            kind=SemanticSubjectKind.TERMINAL,
            role=SemanticSubjectRole.TERMINAL_SITE,
            block_ref=stop_ref,
            anchor_ea=None if type(stop_ref) is LogicalBlockRef else stop_ea,
            locator=terminal_locator,
        )
        return (_claim_factory(
            TerminalCycleBreakClaim,
            kind=UnflattenClaimKind.TERMINAL_CYCLE_BREAK,
            cycle_subject=cycle,
            cleanup_source_subject=cleanup,
            terminal_subject=terminal_subject,
            terminal_route_proof_ids=(route_proof.proof_id,),
            source_generation=proposal.source_identity_catalog.generation,
        ),)

    detached_claim = None
    if detached is not None:
        dispatcher_ref, dispatcher_ea = resolve(detached.dispatcher, "detached dispatcher")
        if dispatcher_ref != entry_ref:
            raise ValueError("detached dispatcher differs from plan entry")

        def handler_subject(anchor, label):
            ref, ea = resolve(anchor, label)
            handler_input = handler_inputs.get(ref)
            if handler_input is None or int(handler_input.anchor_ea) != ea:
                known = tuple(
                    f"blk{int(serial)}@0x{int(item.anchor_ea):x}"
                    for serial, candidate_ref in sorted(refs_by_serial.items())
                    for item in (handler_inputs.get(candidate_ref),)
                    if item is not None
                )
                raise ValueError(
                    f"detached {label} is not an authoritative source handler "
                    f"(candidate=blk{int(anchor.serial)}@0x{int(anchor.ea):x}, "
                    f"known={known})"
                )
            return _subject_factory(
                SemanticSubjectRef, kind=SemanticSubjectKind.HANDLER,
                role=SemanticSubjectRole.AUTHORITATIVE_HANDLER,
                block_ref=ref, anchor_ea=ea,
                locator=HandlerSubjectLocator(ref, ea, handler_input.normalized_states),
            )

        def component_subject(anchor):
            ref, ea = resolve(anchor, "detached component")
            return _subject_factory(
                SemanticSubjectRef, kind=SemanticSubjectKind.BLOCK,
                role=SemanticSubjectRole.DETACHED_DEAD_HANDLER_COMPONENT,
                block_ref=ref, anchor_ea=ea, locator=BlockSubjectLocator(ref, ea),
            )

        def comparison_subject(anchor):
            ref, ea = resolve(anchor, "detached comparison region")
            if ref not in plan_refs:
                raise ValueError(
                    "detached comparison region is outside dispatcher membership"
                )
            return _subject_factory(
                SemanticSubjectRef, kind=SemanticSubjectKind.BLOCK,
                role=SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE,
                block_ref=ref, anchor_ea=ea,
                locator=BlockSubjectLocator(ref, ea),
            )

        dead = tuple(handler_subject(anchor, "dead handler") for anchor in detached.dead_handlers)
        retained = tuple(handler_subject(anchor, "retained handler") for anchor in detached.retained_handlers)
        component = tuple(component_subject(anchor) for anchor in detached.component)
        comparison = tuple(
            comparison_subject(anchor) for anchor in detached.comparison_region
        )
        if not dead or not retained or not component or not comparison:
            raise ValueError("detached component content is incomplete")
        if len({item.block_ref for item in dead}) != len(dead) or len({item.block_ref for item in retained}) != len(retained) or len({item.block_ref for item in component}) != len(component):
            raise ValueError("detached component anchors are duplicate")
        if {item.block_ref for item in dead} & {item.block_ref for item in retained}:
            raise ValueError("detached handler partitions overlap")
        if not {item.block_ref for item in dead} <= {item.block_ref for item in component}:
            raise ValueError("detached component omits a dead handler")
        dispatcher = _subject_factory(
            SemanticSubjectRef, kind=SemanticSubjectKind.BLOCK,
            role=SemanticSubjectRole.DISPATCHER_ENTRY,
            block_ref=dispatcher_ref, anchor_ea=dispatcher_ea,
            locator=BlockSubjectLocator(dispatcher_ref, dispatcher_ea),
        )
        detached_claim = _claim_factory(
            DetachedDeadHandlerComponentClaim,
            kind=UnflattenClaimKind.DETACHED_DEAD_HANDLER_COMPONENT,
            dispatcher_subject=dispatcher, dead_handler_subjects=dead,
            retained_handler_subjects=retained, component_subjects=component,
            comparison_region_subjects=comparison,
            source_generation=proposal.source_identity_catalog.generation,
        )

    if not retired_forecast:
        return () if detached_claim is None else (detached_claim,)

    retired_rows = retired_forecast
    # Forecast observations are deliberately advisory.  Keep only exact
    # dispatcher-member candidates; a nonmember router observation must never
    # widen the proposal's authority scope.  Handler rows are likewise
    # excluded even if a producer's structural walk happened to encounter
    # them.
    handler_refs = {
        handler.block_ref for handler in proposal.plan_inputs.authoritative_handlers
    }
    retired_by_ref = {
        ref: role
        for row in retired_rows
        for ref, role in ((resolve(row.anchor, "retirement candidate")[0], str(row.role)),)
        if ref in plan_refs and ref not in handler_refs
    }
    claims: list[RetiredDispatcherInfrastructureClaim | DetachedDeadHandlerComponentClaim | TerminalCycleBreakClaim] = []
    if detached_claim is not None:
        claims.append(detached_claim)
    if retired_by_ref:
        if candidate_catalog is None:
            raise ValueError("retirement candidates require a candidate catalog")
        candidate_by_ref = {
            candidate.block_ref: candidate
            for candidate in candidate_catalog.candidates
        }
        member_subjects = tuple(
            _subject_factory(
                SemanticSubjectRef,
                kind=SemanticSubjectKind.BLOCK,
                role=SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE,
                block_ref=ref, anchor_ea=int(catalog[ref].anchor_ea),
                locator=BlockSubjectLocator(ref, int(catalog[ref].anchor_ea)),
            ) for ref in plan_refs if ref in candidate_by_ref
        )
        corridor = _subject_factory(
            SemanticSubjectRef,
            kind=SemanticSubjectKind.CORRIDOR,
            role=SemanticSubjectRole.DISPATCHER_CORRIDOR,
            block_ref=entry_ref, anchor_ea=int(entry.anchor_ea),
            locator=CorridorSubjectLocator(
                content_id("unflatten.corridor.v1", plan_refs), entry_ref,
                int(entry.anchor_ea), plan_refs,
                tuple(int(catalog[ref].anchor_ea) for ref in plan_refs),
            ),
        )
        infrastructure = next(
            (item for item in member_subjects if item.block_ref == entry_ref),
            _subject_factory(
                SemanticSubjectRef,
                kind=SemanticSubjectKind.BLOCK,
                role=SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE,
                block_ref=entry_ref, anchor_ea=int(entry.anchor_ea),
                locator=BlockSubjectLocator(entry_ref, int(entry.anchor_ea)),
            ),
        )
        claims.append(_claim_factory(
            RetiredDispatcherInfrastructureClaim,
            kind=UnflattenClaimKind.RETIRED_DISPATCHER_INFRASTRUCTURE,
            infrastructure_subject=infrastructure, corridor_subject=corridor,
            member_subjects=member_subjects,
            candidate_evidence_ids=tuple(sorted({
                evidence_id
                for candidate in candidate_catalog.candidates
                for evidence_id in candidate.evidence_ids
            })),
            source_generation=proposal.source_identity_catalog.generation,
            candidate_catalog=candidate_catalog,
        ))
    return tuple(claims)


def retirement_candidate_catalog_from_forecast(
    coverage: DispatcherCorridorCoverage,
    *,
    proposal: ProposedUnflattenContract,
    block_refs_by_serial: dict[int, NativeBlockRef | LogicalBlockRef],
) -> RetirementCandidateCatalog | None:
    """Build producer eligibility evidence without minting a partition."""
    if type(coverage) is not DispatcherCorridorCoverage:
        raise TypeError("retirement forecast must be corridor coverage")
    if not coverage.retirement_candidates:
        return None
    source_by_ref = {item.block_ref: item for item in proposal.source_identity_catalog.blocks}
    plan_refs = tuple(sorted(proposal.plan_inputs.dispatcher_member_refs, key=canonical_bytes))
    members = tuple(
        RetirementPlanMember(ref, source_by_ref[ref].anchor_ea, source_by_ref[ref].native_instruction_eas)
        for ref in plan_refs
    )
    handler_refs = {handler.block_ref for handler in proposal.plan_inputs.authoritative_handlers}
    candidates = []
    for row in coverage.retirement_candidates:
        ref = block_refs_by_serial.get(int(row.anchor.serial))
        witness = source_by_ref.get(ref)
        if ref is None or witness is None or ref not in plan_refs or ref in handler_refs:
            continue
        if witness.anchor_ea != int(row.anchor.ea):
            continue
        role = str(row.role)
        evidence_ids = (authority_id(("unflatten.dispatcher-retirement-evidence.v1", ref, witness.anchor_ea, role)),)
        candidate_id = authority_id((
            "unflatten.dispatcher-retirement-candidate.v1", ref,
            witness.anchor_ea, role, evidence_ids,
            proposal.source_identity_catalog.generation,
        ))
        candidates.append(DispatcherRetirementCandidate(
            ref, witness.anchor_ea, role, evidence_ids,
            proposal.source_identity_catalog.generation, candidate_id,
        ))
    if not candidates:
        return None
    candidates = tuple(sorted(candidates, key=canonical_bytes))
    catalog_id = authority_id((
        "unflatten.dispatcher-retirement-candidate-catalog.v1",
        proposal.source_identity_catalog.generation, members, candidates,
    ))
    return RetirementCandidateCatalog(catalog_id, proposal.source_identity_catalog.generation, members, candidates)


@dataclass(frozen=True, slots=True)
class TypedProposalRoute:
    """The sole accepted semantic route in this task."""

    route: Literal[UnflattenPlanRoute.TYPED_PROPOSAL]
    proposal: ProposedUnflattenContract

    def __post_init__(self) -> None:
        if self.route is not UnflattenPlanRoute.TYPED_PROPOSAL:
            raise ValueError("typed route must be TYPED_PROPOSAL")
        if type(self.proposal) is not ProposedUnflattenContract:
            raise TypeError("typed route proposal must be closed")


@dataclass(frozen=True, slots=True)
class RejectedPlanRoute:
    """A total route-selection rejection."""

    reason: UnflattenAuthorityReason
    detail_code: str
    key: str | None = None
    stage: ProposalValidationStage | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.reason, UnflattenAuthorityReason):
            raise TypeError("reason must be an UnflattenAuthorityReason")
        if self.reason in (
            UnflattenAuthorityReason.ACCEPTED,
            UnflattenAuthorityReason.NOT_APPLICABLE,
        ):
            raise ValueError("rejection reason must describe rejection")
        if not isinstance(self.detail_code, str) or not self.detail_code.strip():
            raise ValueError("detail_code must not be blank")
        if self.key is not None and self.key not in LEGACY_UNFLATTEN_KEYS:
            raise ValueError("key must be a reserved unflatten metadata key")
        if self.stage is not None and not isinstance(self.stage, ProposalValidationStage):
            raise TypeError("stage must be ProposalValidationStage or None")


PlanRouteResult: TypeAlias = (
    UnflattenAuthorityNotApplicable | TypedProposalRoute | RejectedPlanRoute
)


def _derive_default_gap_infeasibility_exclusions(
    *,
    source,
    proposal: ProposedUnflattenContract,
    block_refs_by_serial,
    selected_route_proof_ids,
    corridor_coverage,
    condition_chain_route_evidence,
) -> tuple[DefaultGapInfeasibilityExclusion, ...]:
    """Propose exact default-loop exclusions from closed producer evidence.

    This intentionally returns no rows for every non-exact shape.  It is a
    proposal adapter only: transaction binding replays the same facts before a
    loss is ever allowed.
    """
    if (
        type(proposal) is not ProposedUnflattenContract
        or type(corridor_coverage) is not DispatcherCorridorCoverage
        or not corridor_coverage.enumeration_complete
        or corridor_coverage.dispatcher is None
        or type(condition_chain_route_evidence) is not ConditionChainRouteEvidence
        or condition_chain_route_evidence.state_identity != proposal.plan_inputs.state_identity
    ):
        return ()
    condition_chain_dag = condition_chain_route_evidence.decision_dag
    default_entry_serial = condition_chain_route_evidence.default_target_serial
    if (
        int(condition_chain_dag.width) != 32
        or not condition_chain_dag.nodes
        or type(default_entry_serial) is not int
    ):
        return ()
    # The route forest is deliberately limited to exact equality/inequality
    # comparisons.  A broader predicate language belongs in a later feature.
    if any(str(node.op).lower() not in {"jz"}
           for node in condition_chain_dag.nodes.values()):
        return ()
    refs = dict(block_refs_by_serial)
    dispatcher_serial = int(corridor_coverage.dispatcher.serial)
    if refs.get(dispatcher_serial) != proposal.plan_inputs.dispatcher_entry_ref:
        return ()
    if int(condition_chain_dag.root) != dispatcher_serial or condition_chain_dag.aliases:
        return ()
    catalog_by_ref = {item.block_ref: item for item in proposal.source_identity_catalog.blocks}

    def source_coordinate_exists(serial: int) -> bool:
        ref = refs.get(int(serial))
        block = source.get_block(int(serial))
        witness = None if ref is None else catalog_by_ref.get(ref)
        return bool(
            ref is not None and block is not None and witness is not None
            and witness.anchor_ea == int(block.start_ea)
        )

    # A closed dispatcher chain has no disconnected comparison authority: walk
    # its fallthroughs from the exact entry and account for every node.  The
    # source CFG owns arm order, so the portable DAG cannot reverse it.
    chain: set[int] = set()
    current_serial = dispatcher_serial
    while current_serial in condition_chain_dag.nodes:
        if current_serial in chain or not source_coordinate_exists(current_serial):
            return ()
        chain.add(current_serial)
        comparison = condition_chain_dag.nodes[current_serial]
        if int(comparison.serial) != current_serial:
            return ()
        if not source_coordinate_exists(int(comparison.true_target)) or not source_coordinate_exists(int(comparison.false_target)):
            return ()
        block = source.get_block(current_serial)
        if block is None or tuple(block.succs) != (int(comparison.false_target), int(comparison.true_target)):
            return ()
        rebuilt = current_u32_route_comparison(
            source,
            current_serial,
            expected_identities=frozenset({proposal.plan_inputs.state_identity}),
        )
        if rebuilt is None or rebuilt[0] != comparison:
            return ()
        if int(comparison.true_target) == default_entry_serial:
            return ()
        current_serial = int(comparison.false_target)
    if current_serial != default_entry_serial or chain != set(condition_chain_dag.nodes):
        return ()
    default_block = source.get_block(default_entry_serial)
    dispatcher_block = source.get_block(dispatcher_serial)
    if default_block is None or dispatcher_block is None:
        return ()
    if default_entry_serial in condition_chain_dag.nodes:
        return ()
    try:
        default_leaf_exists = any(
            int(path.target) == default_entry_serial and not path.domain.is_empty()
            for path in condition_chain_dag.resolve_paths()
        )
    except (TypeError, ValueError):
        return ()
    if not default_leaf_exists:
        return ()
    if (
        tuple(default_block.succs) != (dispatcher_serial,)
        or default_entry_serial not in dispatcher_block.preds
    ):
        return ()
    # Only NOP/GOTO blocks are eligible default-loop residue.  In particular,
    # never hide a CALL, STORE, RET, or a state load/write behind this adapter.
    if any(snapshot.kind not in {InsnKind.NOP, InsnKind.GOTO}
           for snapshot in default_block.insn_snapshots):
        return ()
    if not default_block.insn_snapshots or default_block.insn_snapshots[-1].kind is not InsnKind.GOTO:
        return ()
    selected_ids = tuple(selected_route_proof_ids or ())
    if not selected_ids or len(set(selected_ids)) != len(selected_ids):
        return ()
    proofs = {item.proof_id: item for item in proposal.route_evidence.route_proofs}
    selected = tuple(proofs.get(item) for item in selected_ids)
    if any(item is None for item in selected):
        return ()
    serial_by_identity = {
        (ref.identity, catalog_by_ref[ref].anchor_ea): serial
        for serial, ref in refs.items()
        if ref in catalog_by_ref and type(ref) is NativeBlockRef
    }
    seeds: list[DefaultGapInitialStateSeed] = []
    for proof in selected:
        state_write = proof.state_write
        if (
            state_write is None
            or state_write.state_variable != proposal.plan_inputs.state_identity
            or int(state_write.width) != 4
        ):
            return ()
        state = int(state_write.state_constant) & 0xFFFFFFFF
        destinations = [
            destination for destination in proof.destinations
            if int(destination.state_constant) & 0xFFFFFFFF == state
        ]
        if len(destinations) != 1:
            return ()
        destination = destinations[0]
        target_serial = serial_by_identity.get((destination.target_identity, destination.target_anchor_ea))
        try:
            routed_serial = int(condition_chain_dag.route(state))
        except (TypeError, ValueError):
            return ()
        if target_serial is None or routed_serial != int(target_serial):
            return ()
        if routed_serial == default_entry_serial:
            return ()
        seeds.append(DefaultGapInitialStateSeed(state, proof.proof_id))
    if len({seed.normalized_state for seed in seeds}) != len(seeds):
        return ()
    seeds = sorted(seeds, key=canonical_bytes)
    selected_ids = tuple(sorted(seed.route_proof_id for seed in seeds))
    reachable_states = tuple(sorted(seed.normalized_state for seed in seeds))
    dispatcher_ref = refs.get(dispatcher_serial)
    default_ref = refs.get(default_entry_serial)
    if dispatcher_ref is None or default_ref is None:
        return ()

    def node(serial: int) -> CorridorCoveragePathNode | None:
        ref = refs.get(serial)
        block = source.get_block(serial)
        witness = None if ref is None else catalog_by_ref.get(ref)
        if ref is None or block is None or witness is None or witness.anchor_ea != int(block.start_ea):
            return None
        return CorridorCoveragePathNode(ref, int(block.start_ea))

    dispatcher_node = node(dispatcher_serial)
    default_node = node(default_entry_serial)
    if dispatcher_node is None or default_node is None:
        return ()
    rows: list[DefaultGapInfeasibilityExclusion] = []
    for corridor in corridor_coverage.residual_corridors:
        if (
            len(corridor.path) != 2
            or int(corridor.path[0].serial) != default_entry_serial
            or int(corridor.path[-1].serial) != dispatcher_serial
        ):
            return ()
        residual = node(default_entry_serial)
        if residual is None:
            return ()
        content = (
            "unflatten.default-gap-infeasibility-exclusion.v2", 4,
            proposal.plan_inputs.state_identity, dispatcher_node, default_node,
            residual, tuple(seeds), tuple(selected_ids), reachable_states,
        )
        rows.append(DefaultGapInfeasibilityExclusion(
            authority_id(content),
            authority_id(("unflatten.default-gap-infeasibility-exclusion-digest.v1", content)),
            4, proposal.plan_inputs.state_identity, dispatcher_node, default_node,
            residual, tuple(seeds), tuple(selected_ids), reachable_states,
        ))
    if not rows or len({item.exclusion_id for item in rows}) != len(rows):
        return ()
    return tuple(sorted(rows, key=lambda item: item.exclusion_id))


def _source_witness_covers_semantic_point(
    witness: SourceBlockIdentityWitness,
    point_ea: int,
    *,
    allow_native_range_fallback: bool = False,
) -> bool:
    """Prove that a semantic endpoint belongs to one immutable source block.

    ``SourceBlockIdentityWitness.anchor_ea`` is the catalogue's stable block
    anchor, whereas route and carrier proofs bind instruction-level semantic
    points.  Treating the former as the latter creates a second coordinate
    namespace and rejects a valid proof whenever the route starts after the
    block's first instruction.  The immutable instruction inventory is the
    exact proof when it is available.  A caller may request native-range
    fallback only for a proof field whose canonical model explicitly allows a
    block anchor rather than an instruction origin (the carrier corridor does).
    """

    if type(witness) is not SourceBlockIdentityWitness or type(point_ea) is not int:
        return False
    if type(witness.block_ref) is not NativeBlockRef:
        return False
    if witness.native_instruction_eas:
        if int(point_ea) in witness.native_instruction_eas:
            return True
        return bool(
            allow_native_range_fallback
            and witness.block_ref.identity.native_ranges.contains(int(point_ea))
        )
    return bool(
        allow_native_range_fallback
        and witness.block_ref.identity.native_ranges.contains(int(point_ea))
    )


def _entry_liveness_route_proof_rejection_detail(
    *,
    source_witnesses: Mapping[object, SourceBlockIdentityWitness],
    replacement_ref,
    redirect_owner_ref,
    dispatcher_old_target_ref,
    state_production_source_ref,
    state_production_instruction_ea: int,
    route_proof_id: str,
    selected_ids: set[str],
    proof: SemanticRouteProof | None,
    state_identity,
    normalized_state: int,
) -> str | None:
    """Return the first fail-closed reason for exact entry-route authority.

    Assignment and carrier proofs deliberately meet at this boundary.  A
    carrier is not an assignment with a missing write: it must bind the whole
    source -> feeder -> comparison corridor to the redirect it authorizes.
    """

    def source_witness(ref: object) -> SourceBlockIdentityWitness | None:
        witness = source_witnesses.get(ref)
        if (
            type(ref) is not NativeBlockRef
            or type(witness) is not SourceBlockIdentityWitness
            or witness.block_ref != ref
        ):
            return None
        return witness

    replacement_witness = source_witness(replacement_ref)
    if replacement_witness is None:
        return "replacement_source_witness"
    if type(replacement_ref) is not NativeBlockRef:
        return "replacement_not_native"
    if route_proof_id not in selected_ids:
        return "proof_not_selected"
    if proof is None:
        return "proof_missing"
    state_write = proof.state_write
    state_carrier = proof.state_carrier
    if state_write is None and not (
        proof.proof_kind is SemanticRouteProofKind.STATE_CARRIER
        and state_carrier is not None
    ):
        return "state_write_missing"
    if state_write is not None:
        write_witness = source_witness(state_production_source_ref)
        if write_witness is None:
            return "state_write_source_witness"
        if (
            redirect_owner_ref != state_production_source_ref
            and (
                type(redirect_owner_ref) is not NativeBlockRef
                or proof.source_owner_identity not in {
                    None, redirect_owner_ref.identity,
                }
            )
        ):
            return "redirect_owner_identity"
        production_identity = state_write.identity
        production_instruction_ea = state_write.instruction_ea
        production_state_identity = state_write.state_variable
        production_state_constant = state_write.state_constant
        identity_reason = "state_write_identity"
        instruction_reason = "state_write_instruction"
    else:
        assert state_carrier is not None
        source_witness_row = source_witness(state_production_source_ref)
        owner_witness = source_witness(redirect_owner_ref)
        feeder_witness = source_witness(dispatcher_old_target_ref)
        comparison_ref = NativeBlockRef(state_carrier.comparison_entry_identity)
        comparison_witness = source_witness(comparison_ref)
        if source_witness_row is None:
            return "state_carrier_source_witness"
        if owner_witness is None:
            return "state_carrier_owner_witness"
        if feeder_witness is None:
            return "state_carrier_feeder_witness"
        if comparison_witness is None:
            return "state_carrier_comparison_witness"
        if (
            type(redirect_owner_ref) is not NativeBlockRef
            or redirect_owner_ref != state_production_source_ref
            or redirect_owner_ref.identity != state_carrier.source_identity
            or state_carrier.owner_identity != redirect_owner_ref.identity
            or not _source_witness_covers_semantic_point(
                owner_witness, state_carrier.owner_anchor_ea,
                allow_native_range_fallback=True,
            )
        ):
            return "state_carrier_redirect_owner"
        # A carrier's nested owner and its enclosing route owner are the same
        # authority subject.  Most source-owned carriers omit the redundant
        # route-level field; when canonical evidence names it explicitly, it
        # must bind the exact same owner point, never merely another block
        # with the same native key.
        if proof.source_owner_identity is not None and (
            proof.source_owner_identity != state_carrier.owner_identity
            or proof.source_owner_identity != redirect_owner_ref.identity
            or proof.source_owner_anchor_ea != state_carrier.owner_anchor_ea
            or not _source_witness_covers_semantic_point(
                owner_witness, int(proof.source_owner_anchor_ea),
                allow_native_range_fallback=True,
            )
        ):
            return "state_carrier_route_owner"
        if (
            not _source_witness_covers_semantic_point(
                source_witness_row, state_carrier.source_anchor_ea,
            )
            or int(state_production_instruction_ea)
            != int(state_carrier.source_anchor_ea)
        ):
            return "state_carrier_source_anchor"
        if (
            type(dispatcher_old_target_ref) is not NativeBlockRef
            or dispatcher_old_target_ref.identity != state_carrier.feeder_identity
            or not _source_witness_covers_semantic_point(
                feeder_witness, state_carrier.feeder_anchor_ea,
                allow_native_range_fallback=True,
            )
        ):
            return "state_carrier_feeder"
        if (
            not _source_witness_covers_semantic_point(
                comparison_witness,
                state_carrier.comparison_entry_anchor_ea,
                allow_native_range_fallback=True,
            )
            or comparison_ref == dispatcher_old_target_ref
            or state_carrier.corridor
            != (
                SemanticCorridorPoint(
                    state_carrier.source_identity,
                    state_carrier.source_anchor_ea,
                ),
                SemanticCorridorPoint(
                    state_carrier.feeder_identity,
                    state_carrier.feeder_anchor_ea,
                ),
                SemanticCorridorPoint(
                    state_carrier.comparison_entry_identity,
                    state_carrier.comparison_entry_anchor_ea,
                ),
            )
        ):
            return "state_carrier_comparison_corridor"
        production_identity = state_carrier.source_identity
        production_instruction_ea = state_carrier.source_anchor_ea
        production_state_identity = state_carrier.state_identity
        production_state_constant = state_carrier.state_constant
        identity_reason = "state_carrier_identity"
        instruction_reason = "state_carrier_instruction"
    if production_identity != state_production_source_ref.identity:
        return identity_reason
    if int(production_instruction_ea) != int(state_production_instruction_ea):
        return instruction_reason
    if state_write is not None and not _source_witness_covers_semantic_point(
        write_witness, production_instruction_ea,
    ):
        return "state_write_instruction_witness"
    if production_state_identity != state_identity:
        return "state_identity"
    if (int(production_state_constant) & 0xFFFFFFFF) != normalized_state:
        return "state_constant"
    if sum(
        1
        for destination in proof.destinations
        if (
            (int(destination.state_constant) & 0xFFFFFFFF) == normalized_state
            and destination.target_identity == replacement_ref.identity
            and destination.target_anchor_ea
            == stable_block_identity_semantic_anchor(replacement_ref.identity)
            and _source_witness_covers_semantic_point(
                replacement_witness, destination.target_anchor_ea,
                allow_native_range_fallback=True,
            )
        )
    ) != 1:
        return "destination"
    return None


def _authoritative_handler_serials_with_retirement_forecast(
    authoritative_handler_serials,
    dispatcher_removal_forecast,
) -> tuple[int, ...]:
    """Normalize route and retirement handler evidence into one catalogue.

    Route selection proves live delivery targets.  A detached dead-handler
    claim necessarily names source handlers that no selected route reaches;
    its exact typed forecast is therefore the authority that contributes those
    additional source obligations.  The transaction still rebinds every
    forecast anchor against the immutable source and candidate inventories.
    """

    serials = {int(serial) for serial in authoritative_handler_serials}
    if dispatcher_removal_forecast is None:
        return tuple(sorted(serials))
    if type(dispatcher_removal_forecast) is not DispatcherCorridorCoverage:
        raise TypeError("dispatcher removal forecast must be corridor coverage")
    detached = dispatcher_removal_forecast.detached_dead_handler_component
    if detached is not None:
        serials.update(
            int(anchor.serial)
            for anchor in (*detached.dead_handlers, *detached.retained_handlers)
        )
    return tuple(sorted(serials))


def attach_typed_proposal(
    plan: PatchPlan,
    *,
    source,
    block_refs_by_serial,
    canonical_route_evidence,
    selected_route_proof_ids=None,
    exact_state_effect_exclusions,
    dispatcher_entry_serial,
    dispatcher_member_serials,
    authoritative_handler_serials,
    state_identity,
    use_def_witness,
    corridor_coverage=None,
    dispatcher_removal_forecast=None,
    condition_chain_route_evidence: ConditionChainRouteEvidence | None = None,
    entry_endpoint_liveness_forecasts: tuple[EntryEndpointLivenessForecast, ...] = (),
) -> PatchPlan:
    """Attach one typed proposal from producer-owned typed evidence."""

    if type(plan) is not PatchPlan:
        raise TypeError("typed proposal attachment requires a PatchPlan")
    if plan.unflatten_proposal is not None:
        raise ValueError("typed proposal attachment may run only once")
    # The selected proof collection is used by proposal construction, entry
    # liveness binding, and optional coverage derivation.  Freeze a one-shot
    # producer iterable before its first consumer so every phase sees the same
    # canonical occurrence sequence.
    selected_route_proof_ids = tuple(selected_route_proof_ids or ())
    source_refs_by_serial = dict(block_refs_by_serial)
    authoritative_handler_serials = (
        _authoritative_handler_serials_with_retirement_forecast(
            authoritative_handler_serials,
            dispatcher_removal_forecast,
        )
    )
    proposal = producer_api.build_proposal(
        plan_id=plan.plan_id,
        source=source,
        block_refs_by_serial=source_refs_by_serial,
        source_generation=plan.source_generation,
        canonical_route_evidence=canonical_route_evidence,
        selected_route_proof_ids=selected_route_proof_ids,
        exact_state_effect_exclusions=exact_state_effect_exclusions,
        dispatcher_entry_serial=dispatcher_entry_serial,
        dispatcher_member_serials=dispatcher_member_serials,
        authoritative_handler_serials=authoritative_handler_serials,
        state_identity=state_identity,
        use_def_witness=use_def_witness,
    )
    if entry_endpoint_liveness_forecasts:
        if type(entry_endpoint_liveness_forecasts) is not tuple or any(
            type(item) is not EntryEndpointLivenessForecast
            for item in entry_endpoint_liveness_forecasts
        ):
            raise TypeError("entry liveness forecasts must be closed records")
        coordinates = {serial: ref for ref, serial in plan.source_coordinates}
        # A patch plan names only mutation coordinates.  The upstream state
        # write and its delivery/exit corridor are immutable source evidence,
        # and deliberately need not be patch targets themselves.
        patch_refs = set(coordinates.values())
        source_witnesses = {
            witness.block_ref: witness
            for witness in proposal.source_identity_catalog.blocks
        }
        allowances: list[EntryEndpointLivenessAllowance] = []
        selected_ids = set(selected_route_proof_ids or ())
        for forecast in entry_endpoint_liveness_forecasts:
            forecast.__post_init__()
            owner = forecast.redirect_owner_ref
            old = forecast.dispatcher_ref
            new = forecast.replacement_ref
            exits = forecast.exit_path_refs
            if (
                owner != forecast.state_write_source_ref
                and not forecast.delivery_path_refs
            ):
                raise ValueError(
                    "entry liveness distinct owner requires a delivery corridor"
                )
            if (
                forecast.delivery_path_refs
                and forecast.delivery_path_refs[-2] != owner
            ):
                raise ValueError(
                    "entry liveness forecast corridor must end at redirect owner"
                )
            if (
                owner not in patch_refs
                or old not in patch_refs
                or new not in patch_refs
            ):
                raise ValueError("entry liveness forecast patch coordinates are foreign")
            if (
                forecast.state_write_source_ref not in source_witnesses
                or any(ref not in source_witnesses for ref in exits)
                or any(ref not in source_witnesses for ref in forecast.delivery_path_refs)
            ):
                raise ValueError("entry liveness forecast immutable source evidence is foreign")
            descriptors = tuple(
                descriptor for descriptor in canonical_patch_step_descriptors(plan)
                if descriptor.owner_refs == (owner,)
                and descriptor.step_type in {"PatchRedirectGoto", "PatchRedirectBranch"}
                and descriptor.route_refs[:3] == (owner, old, new)
            )
            if len(descriptors) != 1:
                raise ValueError("entry liveness carrier has no exact redirect descriptor")
            descriptor = descriptors[0]
            proof_by_id = {
                proof.proof_id: proof for proof in proposal.route_evidence.route_proofs
            }
            proof = proof_by_id.get(forecast.route_proof_id)
            state = int(forecast.normalized_state) & 0xFFFFFFFF
            rejection_detail = _entry_liveness_route_proof_rejection_detail(
                source_witnesses=source_witnesses,
                replacement_ref=new,
                redirect_owner_ref=forecast.redirect_owner_ref,
                dispatcher_old_target_ref=forecast.dispatcher_ref,
                state_production_source_ref=forecast.state_write_source_ref,
                state_production_instruction_ea=(
                    forecast.state_write_instruction_ea
                ),
                route_proof_id=forecast.route_proof_id,
                selected_ids=selected_ids,
                proof=proof,
                state_identity=proposal.plan_inputs.state_identity,
                normalized_state=state,
            )
            if rejection_detail is not None:
                raise ValueError(
                    "entry liveness forecast does not name its selected canonical "
                    f"route proof: {rejection_detail}"
                )
            route_proof_id = forecast.route_proof_id
            allowance_id = authority_id((
                "unflatten.entry-endpoint-liveness-allowance.v1",
                EntryEndpointLivenessReason.NO_PROVIDER_EXIT_PATH_LIVE_SAFE_ENDPOINT,
                state, route_proof_id, (owner,), old, new, tuple(exits),
                descriptor.step_index, descriptor.step_digest,
                forecast.state_write_source_ref, forecast.state_write_instruction_ea,
                forecast.delivery_path_refs, forecast.delivery_path_edges,
                bool(forecast.cut_exit_path_uses),
            ))
            allowances.append(EntryEndpointLivenessAllowance(
                allowance_id, EntryEndpointLivenessReason.NO_PROVIDER_EXIT_PATH_LIVE_SAFE_ENDPOINT,
                state, route_proof_id, (owner,), old, new, tuple(exits),
                descriptor.step_index, descriptor.step_digest,
                forecast.state_write_source_ref, forecast.state_write_instruction_ea,
                forecast.delivery_path_refs, forecast.delivery_path_edges,
                bool(forecast.cut_exit_path_uses),
            ))
        proposal = replace(
            proposal,
            entry_endpoint_liveness_allowances=tuple(allowances),
        )
    producer_api._catalog_ref_by_serial(
        source, proposal.source_identity_catalog, source_refs_by_serial,
    )
    source_coordinates = tuple(
        (source_refs_by_serial[serial], serial)
        for serial in sorted(source.blocks)
    )
    sealed_coordinates = dict(source_coordinates)
    if any(
        sealed_coordinates.get(ref) != serial
        for ref, serial in plan.source_coordinates
    ):
        raise ValueError("plan source coordinates differ from source mapping")
    metadata_items = tuple(normalized_metadata_items(plan.metadata))
    if any(key in LEGACY_UNFLATTEN_KEYS for key, _value in metadata_items):
        raise ValueError("typed producer plans cannot carry reserved legacy metadata")
    full_dispatcher_retirement = False
    if dispatcher_removal_forecast is not None:
        if corridor_coverage is None:
            raise ValueError("coverage-dependent proposal requires coverage metadata")
        default_gaps = _derive_default_gap_infeasibility_exclusions(
            source=source,
            proposal=proposal,
            block_refs_by_serial=source_refs_by_serial,
            selected_route_proof_ids=selected_route_proof_ids,
            corridor_coverage=dispatcher_removal_forecast,
            condition_chain_route_evidence=condition_chain_route_evidence,
        )
        coverage_forecast = corridor_coverage_forecast_from_analysis(
            dispatcher_removal_forecast,
            proposal=proposal,
            block_refs_by_serial=source_refs_by_serial,
            default_gap_infeasibility_exclusions=default_gaps,
        )
        proposal = replace(proposal, corridor_coverage_forecast=coverage_forecast)
        candidate_catalog = retirement_candidate_catalog_from_forecast(
            dispatcher_removal_forecast,
            proposal=proposal,
            block_refs_by_serial=source_refs_by_serial,
        )
        claims = claims_from_dispatcher_removal_forecast(
            dispatcher_removal_forecast,
            proposal=proposal,
            block_refs_by_serial=source_refs_by_serial,
        )
        if claims:
            candidate_refs = {
                member.block_ref
                for claim in claims
                if type(claim) is RetiredDispatcherInfrastructureClaim
                for member in claim.member_subjects
            }
            dispatcher_refs = set(proposal.plan_inputs.dispatcher_member_refs)
            retirement_claim = any(
                type(claim) is RetiredDispatcherInfrastructureClaim
                for claim in claims
            )
            full_dispatcher_retirement = (
                retirement_claim and candidate_refs == dispatcher_refs
            )
            attached_claims = (
                claims if full_dispatcher_retirement else tuple(
                    claim for claim in claims
                    if type(claim) is not RetiredDispatcherInfrastructureClaim
                )
            )
            proposal = replace(
                proposal,
                claims=tuple(sorted(
                    (*proposal.claims, *attached_claims), key=lambda item: item.claim_id,
                )),
                retirement_candidate_catalog=(
                    candidate_catalog if full_dispatcher_retirement else None
                ),
                plan_inputs=replace(
                    proposal.plan_inputs,
                    shape=UnflattenPlanShape.FULL_DISPATCHER_RETIREMENT
                    if full_dispatcher_retirement
                    else UnflattenPlanShape.PARTIAL_REWRITE,
                ),
                corridor_coverage_forecast=coverage_forecast,
            )
        else:
            proposal = replace(
                proposal,
                corridor_coverage_forecast=coverage_forecast,
            )
    if (
        proposal.retirement_candidate_catalog is not None
        or any(type(claim) is RetiredDispatcherInfrastructureClaim for claim in proposal.claims)
    ) and proposal.corridor_coverage_forecast is None:
        raise ValueError("corridor rewrite or retirement proposal requires coverage metadata")
    return replace(
        plan,
        metadata=metadata_items,
        source_coordinates=source_coordinates,
        unflatten_proposal=proposal,
    )


__all__ = [
    "build_unflatten_plan_input_catalog",
    "RedirectStepManifest",
    "canonical_redirect_manifest",
    "LEGACY_UNFLATTEN_KEYS",
    "PlanRouteResult",
    "ProposalAccepted",
    "ProposalRejected",
    "ProposalValidationStage",
    "ProposalValidationResult",
    "RejectedPlanRoute",
    "TypedProposalRoute",
    "reserved_metadata_keys",
    "retirement_member_catalog",
    "validate_proposal",
    "attach_typed_proposal",
    "claims_from_dispatcher_removal_forecast",
]
