"""Patch-transaction-facing route selection for unflatten authority."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, fields, replace
from time import perf_counter
from time import perf_counter_ns
import hashlib
import re

from d810.transforms.plan import (
    PatchBlockSpec,
    PatchCloneConditionalAsGoto,
    PatchCloneConditionalAsGotoFromBranchArm,
    PatchConditionalRedirect,
    PatchDuplicateBlock,
    PatchDuplicateReplayAndRedirect,
    PatchEdgeSplitCorridor,
    PatchEdgeSplitTrampoline,
    PatchInsertBlock,
    PatchLowerConditionalStateTransition,
    PatchPlan,
    PatchRedirectBranch,
    PatchRedirectGoto,
    PatchScalarizeLocalAliasAccess,
)
from d810.analyses.control_flow import semantic_route_evidence as route_model
from d810.analyses.control_flow.semantic_route_evidence import (
    assess_canonical_route,
    CanonicalRouteMaterialization,
)
from d810.ir.flowgraph import FlowGraph
from d810.transforms.cfg_transaction import CfgProjection, TransactionAttemptId
from d810.transforms.cfg_transaction import (
    LogicalBlockRef,
    NativeBlockRef,
    PlanBlockRef,
)
from d810.transforms.patch_binding import (
    BoundPatchPlan,
    iter_refs,
    validate_bound_patch_plan,
)
from d810.transforms.unflatten_authority import bind as authority_bind
from d810.transforms.unflatten_authority import model
from d810.transforms.unflatten_authority import producer_api
from d810.transforms.unflatten_authority.evaluate import build_semantic_case, evaluate_case
from d810.transforms.unflatten_authority import gates
from d810.transforms.unflatten_authority.gates import (
    GenericCfgGateBundle,
    validate_generic_cfg_gate_bundle,
)
from d810.transforms.unflatten_authority.legacy_codec import LegacyShadowCodecReceipt
from d810.transforms.unflatten_authority.diagnostics import (
    LegacyPhaseOutcome,
    PhaseTimings,
    ShadowParityCounters,
    ShadowParityPayload,
)


from d810.transforms.unflatten_authority.ids import (
    _claim_factory,
    _subject_factory,
    authority_id,
    bound_unflatten_binding_id,
    content_id,
    semantic_graph_inventory_digest,
)

from .model import (
    UnflattenAuthorityNotApplicable,
    UnflattenAuthorityReason,
    UnflattenPlanRoute,
)
from .proposal import (
    MetadataKeyTypeError,
    PlanRouteResult,
    ProposalAccepted,
    ProposalRejected,
    RejectedPlanRoute,
    ShadowValidationAccepted,
    TypedProposalRoute,
    reserved_metadata_keys,
    validate_proposal,
    validate_shadow_for_plan,
)


@dataclass(frozen=True, slots=True)
class TimedUnflattenAuthorityResult:
    """Compatibility envelope for owner integrations needing phase timings."""

    result: (
        model.UnflattenAuthorityNotApplicable
        | model.UnflattenAuthorityPreparationAccepted
        | model.UnflattenAuthorityPreparationRejected
        | model.UnflattenAuthorityVerdict
    )
    timings: PhaseTimings

    def __post_init__(self) -> None:
        if type(self.result) not in (
            model.UnflattenAuthorityNotApplicable,
            model.UnflattenAuthorityPreparationAccepted,
            model.UnflattenAuthorityPreparationRejected,
            model.UnflattenAuthorityVerdict,
        ):
            raise TypeError("timed result is not a closed authority result")
        if type(self.timings) is not PhaseTimings:
            raise TypeError("timings must be PhaseTimings")


@dataclass(slots=True)
class _AuthorityTimingRecorder:
    inventory_ms: float | None = None
    binding_ms: float | None = None
    evaluation_ms: float | None = None


def _elapsed_ms(start_ns: int, end_ns: int) -> float:
    return (end_ns - start_ns) / 1_000_000.0


def _subject(kind, role, locator):
    owner = getattr(locator, "block_ref", None)
    if owner is None:
        owner = getattr(locator, "owner_ref", None)
    if owner is None:
        owner = getattr(locator, "source_ref", None)
    if owner is None:
        owner = getattr(locator, "entry_ref", None)
    anchor = getattr(locator, "anchor_ea", None)
    if anchor is None:
        anchor = getattr(locator, "owner_anchor_ea", None)
    if anchor is None:
        anchor = getattr(locator, "source_anchor_ea", None)
    if anchor is None:
        anchor = getattr(locator, "entry_anchor_ea", None)
    return _subject_factory(
        model.SemanticSubjectRef,
        kind=kind,
        role=role,
        block_ref=owner,
        anchor_ea=anchor,
        locator=locator,
    )


def _unavailable_candidate_fingerprint(plan_id: str) -> str:
    return authority_id(("candidate-fingerprint-unavailable", plan_id))


def _live_binding_failed_verdict() -> model.UnflattenAuthorityVerdict:
    """Return a total rejection without dereferencing an untrusted carrier."""
    return model.UnflattenAuthorityVerdict(
        False,
        model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        model.UnflattenAuthorityReason.LIVE_BINDING_FAILED,
        None,
        None,
        None,
        _unavailable_candidate_fingerprint("observed-live-binding"),
        None,
        (),
    )


def _claim_subjects(claim):
    if type(claim) is model.RetiredDispatcherInfrastructureClaim:
        return (claim.infrastructure_subject, claim.corridor_subject, *claim.member_subjects)
    if type(claim) is model.EquivalentSemanticRouteClaim:
        return (claim.retired_route_subject, claim.replacement_route_subject, claim.source_subject, *claim.destination_subjects)
    if type(claim) is model.ExactInfeasibleEffectClaim:
        return (claim.effect_subject, claim.source_subject, claim.predicate_subject, claim.selected_target_subject, claim.discarded_effect_subject)
    if type(claim) is model.LocalAliasEffectScalarizationClaim:
        return (claim.owner_subject,)
    if type(claim) is model.TerminalCycleBreakClaim:
        return (claim.cycle_subject, claim.cleanup_source_subject, claim.terminal_subject)
    raise TypeError("unsupported closed claim")


def _catalog_serials(source: FlowGraph, proposal, plan: PatchPlan, *, blocks=None) -> dict[object, int]:
    block_map = source.blocks if blocks is None else blocks
    rows = tuple(plan.source_coordinates)
    if len(rows) != len(proposal.source_identity_catalog.blocks):
        raise ValueError("plan source coordinates do not cover the source catalog")
    by_ref = {ref: int(serial) for ref, serial in rows}
    expected = {item.block_ref for item in proposal.source_identity_catalog.blocks}
    if set(by_ref) != expected or set(by_ref.values()) != set(block_map):
        raise ValueError("plan source coordinates differ from the source catalog")
    if any(serial not in block_map for serial in by_ref.values()):
        raise ValueError("plan source coordinate points outside the source graph")
    return by_ref


def _projected_plan_serials(plan: PatchPlan) -> dict[PlanBlockRef, int]:
    """Resolve planned block references in the immutable projection coordinate space."""

    if not plan.new_blocks:
        return {}
    source_coordinates = dict(plan.source_coordinates)
    source_stop = plan.relocation_map.source_stop
    stop_before = source_coordinates.get(source_stop) if source_stop is not None else None
    if stop_before is None and source_coordinates:
        stop_before = max(source_coordinates.values())
    if stop_before is None:
        return {}
    return {
        spec.block_id: int(stop_before) + offset
        for offset, spec in enumerate(plan.new_blocks)
    }


def _projected_serials(
    graph: FlowGraph, proposal, *, blocks=None, plan: PatchPlan | None = None,
    planned_serials: Mapping[PlanBlockRef, int] | None = None,
) -> dict[object, int]:
    result: dict[object, int] = {}
    block_values = graph.blocks if blocks is None else blocks
    if planned_serials is None:
        planned_serials = _projected_plan_serials(plan) if plan is not None else {}
    else:
        planned_serials = dict(planned_serials)
        if any(type(ref) is not PlanBlockRef or type(serial) is not int or serial < 0
               for ref, serial in planned_serials.items()):
            raise ValueError("observed helper coordinates must be exact PlanBlockRef rows")
    planned_serial_set = set(planned_serials.values())
    for witness in proposal.source_identity_catalog.blocks:
        def _anchor(block):
            native = getattr(block, "native_start_ea", None)
            start = getattr(block, "start_ea", None)
            return native if native is not None else start
        matches = tuple(
            block.serial
            for block in block_values.values()
            if block.serial not in planned_serial_set
            if _anchor(block) == witness.anchor_ea
        )
        if len(matches) == 1:
            result[witness.block_ref] = int(matches[0])
    if len(set(result.values())) != len(result):
        raise ValueError("projected inventory has duplicate source identities")
    for ref, serial in planned_serials.items():
        if serial in block_values:
            if serial in result.values():
                raise ValueError("planned block coordinate overlaps a source identity")
            result[ref] = serial
    return result


def _block_subjects(proposal, serials, *, include_corridor=True):
    catalog = {item.block_ref: item for item in proposal.source_identity_catalog.blocks}
    subjects = []
    def add(role, ref):
        witness = catalog[ref]
        subjects.append(_subject(model.SemanticSubjectKind.BLOCK, role, model.BlockSubjectLocator(ref, witness.anchor_ea)))
    inputs = proposal.plan_inputs
    add(model.SemanticSubjectRole.SOURCE_ENTRY, inputs.source_entry_ref)
    add(model.SemanticSubjectRole.DISPATCHER_ENTRY, inputs.dispatcher_entry_ref)
    for ref in inputs.dispatcher_member_refs:
        add(model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE, ref)
    for handler in inputs.authoritative_handlers:
        subjects.append(_subject(model.SemanticSubjectKind.HANDLER, model.SemanticSubjectRole.AUTHORITATIVE_HANDLER, model.HandlerSubjectLocator(handler.block_ref, handler.anchor_ea, handler.normalized_states)))
    if include_corridor:
        refs = inputs.dispatcher_member_refs
        subjects.append(_subject(model.SemanticSubjectKind.CORRIDOR, model.SemanticSubjectRole.DISPATCHER_CORRIDOR, model.CorridorSubjectLocator(
            content_id("unflatten.corridor.v1", refs), inputs.dispatcher_entry_ref,
            catalog[inputs.dispatcher_entry_ref].anchor_ea, refs,
            tuple(catalog[ref].anchor_ea for ref in refs),
        )))
    return subjects


def _inventory_subjects(
    proposal, source_serials, effects=(), terminals=(), plan=None,
    planned_helpers: Mapping[PlanBlockRef, int] | None = None,
):
    subjects = _block_subjects(
        proposal, source_serials,
        include_corridor=proposal.corridor_coverage_forecast is not None,
    )
    by_id = {subject.subject_id: subject for subject in subjects}
    # The fragment-wide value-flow subject is always present, even for an
    # exact-effect-only proposal.
    witness = proposal.use_def_witness
    value_flow = _subject(model.SemanticSubjectKind.VALUE_FLOW, model.SemanticSubjectRole.NON_STATE_VALUE_FLOW, model.ValueFlowSubjectLocator(
        witness.fragment_id, witness.state_identity, witness.redirect_owner_refs,
    ))
    by_id[value_flow.subject_id] = value_flow
    for claim in proposal.claims:
        for subject in _claim_subjects(claim):
            by_id[subject.subject_id] = subject
    route_evidence = proposal.route_evidence
    for proof in route_evidence.route_proofs:
        catalog = {item.block_ref: item for item in proposal.source_identity_catalog.blocks}
        source_ref = next(ref for ref, witness_item in catalog.items() if proof.source_anchor_ea in witness_item.native_instruction_eas)
        source_anchor = proof.source_anchor_ea
        destination_pairs = tuple(
            (
                next(
                    ref for ref, witness_item in catalog.items()
                    if destination.target_anchor_ea in witness_item.native_instruction_eas
                ),
                next(
                    witness_item.anchor_ea for ref, witness_item in catalog.items()
                    if destination.target_anchor_ea in witness_item.native_instruction_eas
                ),
            )
            for destination in proof.destinations
        )
        # RouteSubjectLocator canonicalizes these paired ref/EA rows. Never
        # sort the projected subject IDs independently: their order must be
        # the exact order of the locator pairs.
        destination_pairs = tuple(
            sorted(destination_pairs, key=lambda item: model._structural_key(item[0]))
        )
        destinations = tuple(item[0] for item in destination_pairs)
        route = _subject(model.SemanticSubjectKind.ROUTE, model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE, model.RouteSubjectLocator(
            proof.proof_id, proof.atomic_group_id, source_ref, source_anchor,
            destinations, tuple(item[1] for item in destination_pairs),
        ))
        by_id[route.subject_id] = route
        by_id.setdefault(_subject(model.SemanticSubjectKind.BLOCK, model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE, model.BlockSubjectLocator(source_ref, catalog[source_ref].anchor_ea)).subject_id,
                         _subject(model.SemanticSubjectKind.BLOCK, model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE, model.BlockSubjectLocator(source_ref, catalog[source_ref].anchor_ea)))
        for ref, _anchor in destination_pairs:
            item = _subject(
                model.SemanticSubjectKind.BLOCK,
                model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION,
                model.BlockSubjectLocator(ref, catalog[ref].anchor_ea),
            )
            by_id[item.subject_id] = item
    for item in effects:
        if item.owner_ref is None:
            continue
        locator = model.EffectSubjectLocator(
            item.owner_ref, item.owner_anchor_ea, item.instruction_ea, item.effect_kind,
        )
        subject = _subject(model.SemanticSubjectKind.EFFECT, model.SemanticSubjectRole.EFFECT_SITE, locator)
        by_id[subject.subject_id] = subject
    for item in terminals:
        if item.owner_ref is None:
            continue
        locator = model.TerminalSubjectLocator(
            item.owner_ref, item.owner_anchor_ea, item.terminal_kind, item.instruction_ea,
        )
        subject = _subject(model.SemanticSubjectKind.TERMINAL, model.SemanticSubjectRole.TERMINAL_SITE, locator)
        by_id[subject.subject_id] = subject
    if plan is not None:
        catalog = {item.block_ref: item for item in proposal.source_identity_catalog.blocks}
        for step in plan.steps:
            if type(step) is not PatchScalarizeLocalAliasAccess:
                continue
            witness = catalog.get(step.block_serial)
            if witness is None:
                raise ValueError("local-alias step owner is absent from source catalog")
            owner = _subject(
                model.SemanticSubjectKind.BLOCK,
                model.SemanticSubjectRole.EFFECT_SITE,
                model.BlockSubjectLocator(step.block_serial, witness.anchor_ea),
            )
            by_id[owner.subject_id] = owner
    for ref, anchor in (planned_helpers or {}).items():
        helper = _subject(
            model.SemanticSubjectKind.BLOCK,
            model.SemanticSubjectRole.PLANNED_HELPER,
            model.BlockSubjectLocator(ref, anchor),
        )
        by_id[helper.subject_id] = helper
    represented = {subject.block_ref for subject in by_id.values() if subject.block_ref is not None}
    for ref, witness in ((item.block_ref, item) for item in proposal.source_identity_catalog.blocks):
        if ref not in represented:
            subject = _subject(
                model.SemanticSubjectKind.BLOCK,
                model.SemanticSubjectRole.PLANNED_HELPER,
                model.BlockSubjectLocator(ref, witness.anchor_ea),
            )
            by_id[subject.subject_id] = subject
    return tuple(sorted(by_id.values(), key=lambda item: item.subject_id))


def _reachable_serials_from_blocks(blocks, entry_serial: int) -> frozenset[int]:
    if type(entry_serial) is not int or entry_serial < 0:
        raise ValueError("entry_serial must be an exact non-negative integer")
    if not blocks:
        if entry_serial != 0:
            raise ValueError("an empty graph must use entry_serial 0")
        return frozenset()
    if entry_serial not in blocks:
        raise ValueError("entry_serial is absent from graph blocks")
    seen: set[int] = set()
    pending = [entry_serial]
    while pending:
        serial = pending.pop()
        if serial in seen:
            continue
        block = blocks.get(serial)
        if block is None:
            raise ValueError("reachable graph successor is absent")
        seen.add(serial)
        pending.extend(sorted(block.succs, reverse=True))
    return frozenset(seen)


def _build_semantic_graph_inventory(
    graph: FlowGraph,
    proposal: model.ProposedUnflattenContract,
    plan: PatchPlan,
    *,
    source: bool,
    phase: model.UnflattenAuthorityPhase,
    source_subjects: tuple[model.SemanticSubjectRef, ...] = (),
    materialization: CanonicalRouteMaterialization | None = None,
    planned_serials: Mapping[PlanBlockRef, int] | None = None,
) -> model.SemanticGraphInventory:
    """Build one complete source or candidate inventory.

    This is the sole owner of serial projection, reachability, effect/terminal
    discovery, subject construction, and topology materialization.
    """

    if materialization is None:
        materialization = CanonicalRouteMaterialization.capture(
            graph,
            generation=proposal.source_identity_catalog.generation,
            phase=(
                route_model.CanonicalRouteAssessmentPhase.SOURCE
                if source else route_model.CanonicalRouteAssessmentPhase.PROJECTED
            ),
        )
    if materialization.blocks and materialization.entry_serial != graph.entry_serial:
        raise ValueError("route materialization entry differs from graph")
    if materialization.generation != proposal.source_identity_catalog.generation:
        raise ValueError("route materialization generation differs from inventory")
    blocks_by_serial = materialization.blocks
    reachable = _reachable_serials_from_blocks(blocks_by_serial, graph.entry_serial)
    serial_by_ref = (
        _catalog_serials(graph, proposal, plan, blocks=blocks_by_serial)
        if source else _projected_serials(
            graph, proposal, blocks=blocks_by_serial, plan=plan,
            planned_serials=planned_serials,
        )
    )
    fingerprint = materialization.graph_fingerprint
    block_rows = []
    effects = []
    terminals = []
    # Inventory every cached block once.  Reachability remains an explicit
    # closure field used by gates/evidence; it is not the row set itself.
    for serial in sorted(blocks_by_serial):
        block = blocks_by_serial[serial]
        owner_ref = next((ref for ref, value in serial_by_ref.items() if value == serial), None)
        owner_anchor = None
        if owner_ref is not None:
            owner_anchor = next(
                (
                    item.anchor_ea
                    for item in proposal.source_identity_catalog.blocks
                    if item.block_ref == owner_ref
                ),
                None,
            )
            if owner_anchor is None:
                owner_anchor = getattr(block, "native_start_ea", None)
            if owner_anchor is None:
                owner_anchor = getattr(block, "start_ea", None)
            if owner_anchor is None:
                raise ValueError("planned block has no exact native anchor")
        observed = producer_api.observe_inventory_block(
            block, owner_ref=owner_ref, owner_anchor_ea=owner_anchor,
        )
        block_rows.append(observed)
        block_effects, block_terminals = model.resolve_inventory_block_sites(
            serial=observed.serial, owner_ref=observed.block_ref,
            owner_anchor_ea=observed.anchor_ea if observed.anchor_ea is not None else 0,
            block_kind=observed.block_kind,
            successor_serials=observed.successor_serials,
            instruction_observations=observed.instruction_observations,
        )
        effects.extend(block_effects)
        terminals.extend(block_terminals)
    effects = tuple(sorted(effects, key=lambda item: (
        item.owner_serial, item.instruction_ordinal, item.instruction_ea,
        item.effect_kind.value,
    )))
    terminals = tuple(sorted(terminals, key=lambda item: (
        item.owner_serial, item.instruction_ordinal is None,
        item.instruction_ordinal if item.instruction_ordinal is not None else -1,
        item.instruction_ea, item.terminal_kind.value,
    )))
    planned_helpers = {
        ref: next(
            block.anchor_ea if block.anchor_ea is not None
            else min(block.native_instruction_eas)
            for block in block_rows
            if block.serial == serial
        )
        for ref, serial in serial_by_ref.items()
        if not source and type(ref) is PlanBlockRef
    }
    discovered_subjects = _inventory_subjects(
        proposal,
        serial_by_ref,
        tuple(item for item in effects if item.owner_serial in reachable),
        tuple(item for item in terminals if item.owner_serial in reachable),
        plan,
        planned_helpers=planned_helpers,
    )
    if source:
        subjects = discovered_subjects
        source_subject_ids = tuple(item.subject_id for item in subjects)
    else:
        if type(source_subjects) is not tuple or any(type(item) is not model.SemanticSubjectRef for item in source_subjects):
            raise TypeError("source_subjects must be exact semantic subjects")
        subjects = tuple(sorted({item.subject_id: item for item in (*source_subjects, *discovered_subjects)}.values(), key=lambda item: item.subject_id))
        source_subject_ids = tuple(sorted(item.subject_id for item in source_subjects))
    bindings = (
        authority_bind.bind_subjects(
            subjects, catalog=proposal.source_identity_catalog,
            phase=phase, graph_fingerprint=fingerprint,
            generation=proposal.source_identity_catalog.generation,
            serial_by_ref=serial_by_ref,
        ) if source else authority_bind.bind_inventory_subjects(
            subjects, catalog=proposal.source_identity_catalog,
            phase=phase, graph_fingerprint=fingerprint,
            generation=proposal.source_identity_catalog.generation,
            serial_by_ref=serial_by_ref,
            effects=tuple(item for item in effects if item.owner_serial in reachable),
            terminals=tuple(item for item in terminals if item.owner_serial in reachable),
            reachable_serials=tuple(sorted(reachable)),
            native_instruction_eas_by_ref=(
                {
                    row.block_ref: row.native_instruction_eas
                    for row in block_rows
                    if row.block_ref is not None
                }
                if any(
                    isinstance(step, (PatchRedirectBranch, PatchLowerConditionalStateTransition))
                    for step in plan.steps
                ) else None
            ),
        )
    )
    topology = []
    for row in block_rows:
        for peer in row.successor_serials:
            topology.append(model.InventoryTopologyIncidence(
                model.TopologyIncidenceKind.SUCCESSOR, row.serial, peer,
                row.transfer_ea,
            ))
        for peer in row.predecessor_serials:
            peer_row = next((item for item in block_rows if item.serial == peer), None)
            topology.append(model.InventoryTopologyIncidence(
                model.TopologyIncidenceKind.PREDECESSOR, row.serial, peer,
                None if peer_row is None else peer_row.transfer_ea,
            ))
    topology = tuple(sorted(topology, key=lambda item: (
        item.kind.value, item.owner_serial, item.peer_serial,
        item.source_transfer_ea if item.source_transfer_ea is not None else -1,
    )))
    reachable_tuple = tuple(sorted(reachable))
    digest = semantic_graph_inventory_digest(
        phase, fingerprint, proposal.source_identity_catalog.generation,
        tuple(block_rows), subjects, bindings, effects, terminals, topology,
        reachable_tuple, graph.entry_serial, source_subject_ids, graph.func_ea,
    )
    return model.SemanticGraphInventory(
        phase, fingerprint, proposal.source_identity_catalog.generation,
        tuple(block_rows), subjects, bindings, effects, terminals, topology, digest,
        reachable_tuple,
        materialization.entry_serial,
        source_subject_ids,
        function_ea=graph.func_ea,
    )


def _receipt(
    proposal, metrics, *, source_inventory, candidate_inventory,
    generic_gate_facts=None, route_assessments=(), conditional_relations=(),
    patch_step_facts=(),
):
    if type(source_inventory) is not model.SemanticGraphInventory:
        raise TypeError("source_inventory must be SemanticGraphInventory")
    if type(candidate_inventory) is not model.SemanticGraphInventory:
        raise TypeError("candidate_inventory must be SemanticGraphInventory")
    model.validate_semantic_graph_inventory(source_inventory)
    model.validate_semantic_graph_inventory(candidate_inventory)
    model.validate_preparation_build_metrics(metrics)
    if type(proposal) is not model.ProposedUnflattenContract:
        raise TypeError("proposal must be ProposedUnflattenContract")
    if generic_gate_facts is not None and type(generic_gate_facts) is not gates.GenericCfgGateFacts:
        raise TypeError("generic_gate_facts must be GenericCfgGateFacts or None")
    for assessment in route_assessments:
        route_model.validate_canonical_route_assessment(assessment)
    ordered_source_subjects = tuple(sorted(
        source_inventory.subjects, key=lambda item: item.subject_id,
    ))
    ordered_candidate_subjects = tuple(sorted(
        candidate_inventory.subjects, key=lambda item: item.subject_id,
    ))
    ordered_source_bindings = tuple(sorted(
        source_inventory.bindings, key=lambda item: item.subject.subject_id,
    ))
    ordered_candidate_bindings = tuple(sorted(
        candidate_inventory.bindings, key=lambda item: item.subject.subject_id,
    ))
    values = {
        "proposal_id": authority_id(proposal), "plan_id": proposal.plan_id,
        "source_fingerprint": source_inventory.graph_fingerprint,
        "candidate_fingerprint": candidate_inventory.graph_fingerprint,
        "source_generation": source_inventory.generation,
        "candidate_generation": candidate_inventory.generation,
        "source_inventory_digest": source_inventory.inventory_digest,
        "candidate_inventory_digest": candidate_inventory.inventory_digest,
        "source_binding_digest": authority_id(ordered_source_bindings),
        "candidate_binding_digest": authority_id(ordered_candidate_bindings),
        "route_expansion_digest": authority_id(tuple(
            item for item in ordered_source_subjects
            if item.role in (
                model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE,
                model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION,
            )
        )),
        "effect_catalog_digest": authority_id(tuple(
            item.subject_id for item in ordered_source_subjects
            if item.role is model.SemanticSubjectRole.EFFECT_SITE
        )),
        "terminal_catalog_digest": authority_id(tuple(
            item.subject_id for item in ordered_source_subjects
            if item.role is model.SemanticSubjectRole.TERMINAL_SITE
        )),
        "plan_input_digest": authority_id(tuple(
            item.subject_id for item in ordered_source_subjects
            if item.role in {
                model.SemanticSubjectRole.SOURCE_ENTRY,
                model.SemanticSubjectRole.DISPATCHER_ENTRY,
                model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE,
                model.SemanticSubjectRole.AUTHORITATIVE_HANDLER,
            }
        )),
        "dispatcher_member_digest": authority_id(tuple(
            item.subject_id for item in ordered_source_subjects
            if item.role is model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE
        )),
        "planned_helper_digest": authority_id(tuple(
            item.subject_id for item in ordered_candidate_subjects
            if item.role is model.SemanticSubjectRole.PLANNED_HELPER
        )),
        "patch_step_digest": authority_id(tuple(patch_step_facts)),
        "conditional_relation_digest": authority_id(tuple(conditional_relations)),
        "metrics": metrics,
        "generic_gate_facts_digest": authority_id(generic_gate_facts) if generic_gate_facts is not None else None,
        "route_assessment_digest": (
            authority_id(tuple(
                (item.phase.value, item.graph_fingerprint, item.generation,
                 item.evidence_id, item.proof_ids,
                 item.rejection_reason.value if item.rejection_reason else None,
                 item.bound_content_digest)
                for item in route_assessments
            ))
            if route_assessments else None
        ),
        "retirement_catalog": proposal.retirement_catalog,
        "corridor_coverage_forecast": proposal.corridor_coverage_forecast,
    }
    return model.PreparationAuthorityReceipt.mint(**values)


def _derive_local_alias_transaction_facts(
    source_inventory: model.SemanticGraphInventory,
    plan: PatchPlan,
) -> tuple[
    tuple[model.LocalAliasEffectScalarizationClaim, ...],
    tuple[model.PatchStepEvidencePayload, ...],
    tuple[model.ConditionalSubjectRelation, ...],
]:
    """Derive alias authority from the exact typed plan and source inventory."""

    if plan.source_generation is not None and plan.source_generation != source_inventory.generation:
        raise ValueError("local-alias plan generation differs from source inventory")

    claims: list[model.LocalAliasEffectScalarizationClaim] = []
    patch_facts: list[model.PatchStepEvidencePayload] = []
    relations: list[model.ConditionalSubjectRelation] = []
    source_coordinates = dict(plan.source_coordinates)
    blocks_by_serial = {block.serial: block for block in source_inventory.blocks}
    bindings_by_ref = {
        binding.block_ref: binding
        for binding in source_inventory.bindings
        if binding.block_ref is not None
        and binding.status is model.SubjectBindingStatus.UNIQUE
    }
    owner_subjects = {
        subject.block_ref: subject
        for subject in source_inventory.subjects
        if subject.kind is model.SemanticSubjectKind.BLOCK
        and subject.role is model.SemanticSubjectRole.EFFECT_SITE
    }
    seen_hosts: set[tuple[object, int, int]] = set()
    for step_index, step in enumerate(plan.steps):
        if type(step) is not PatchScalarizeLocalAliasAccess:
            continue
        _validate_local_alias_step(step)
        serial = source_coordinates.get(step.block_serial)
        if type(serial) is not int:
            raise ValueError("local-alias step owner lacks an exact source coordinate")
        binding = bindings_by_ref.get(step.block_serial)
        owner_subject = owner_subjects.get(step.block_serial)
        block = blocks_by_serial.get(serial)
        if binding is None or owner_subject is None or block is None:
            raise ValueError("local-alias step owner is not uniquely bound")
        if serial not in source_inventory.reachable_serials:
            raise ValueError("local-alias step owner is unreachable")
        host_key = (step.block_serial, step.host_ea, step.host_opcode)
        if host_key in seen_hosts:
            raise ValueError("local-alias step owner is ambiguous")
        seen_hosts.add(host_key)
        if (
            binding.serial != serial
            or step.host_ea not in binding.native_instruction_eas
            or owner_subject.anchor_ea != binding.anchor_ea
        ):
            raise ValueError("local-alias step owner binding is stale")
        observations = tuple(
            item for item in block.instruction_observations
            if item.instruction_ea == step.host_ea
            and item.opcode == step.host_opcode
        )
        effects = tuple(
            item for item in source_inventory.effects
            if item.owner_serial == serial
            and item.instruction_ea == step.host_ea
            and item.opcode == step.host_opcode
            and item.effect_kind is model.EffectSiteKind.STORE
        )
        if len(observations) != 1 or len(effects) != 1:
            raise ValueError("local-alias step must identify one exact STORE observation")
        observation = observations[0]
        if observation.instruction_kind is not model.InsnKind.STORE:
            raise ValueError("local-alias step host is not a STORE")
        display_text = observation.display_text
        if display_text is None:
            raise ValueError("local-alias step host lacks exact text provenance")
        if re.search(
            rf"(?<![A-Za-z0-9_]){re.escape(step.alias_token)}(?![A-Za-z0-9_])",
            display_text,
        ) is None:
            raise ValueError("local-alias tokens do not match exact host text")
        if step.host_text_sha1 is not None and hashlib.sha1(
            display_text.encode("utf-8", errors="replace")
        ).hexdigest()[:16] != step.host_text_sha1:
            raise ValueError("local-alias host text digest is stale")
        if step.value_size is not None and step.value_size != effects[0].width:
            raise ValueError("local-alias step value size disagrees with STORE")
        step_digest = authority_id(_local_alias_step_preimage(step_index, step))
        claim = _claim_factory(
            model.LocalAliasEffectScalarizationClaim,
            kind=model.UnflattenClaimKind.LOCAL_ALIAS_EFFECT_SCALARIZATION,
            owner_subject=owner_subject,
            step_index=step_index,
            host_ea=step.host_ea,
            host_opcode=step.host_opcode,
            alias_token=step.alias_token,
            base_token=step.base_token,
            host_text_sha1=step.host_text_sha1,
            value_size=step.value_size,
            step_digest=step_digest,
            source_generation=source_inventory.generation,
        )
        patch_facts.append(model.PatchStepEvidencePayload(
            plan.plan_id, step_index, "PatchScalarizeLocalAliasAccess",
            step.block_serial, step_digest, step.host_ea, step.host_opcode,
            step.value_size,
        ))
        effect_subject = next(
            subject for subject in source_inventory.subjects
            if subject.kind is model.SemanticSubjectKind.EFFECT
            and subject.role is model.SemanticSubjectRole.EFFECT_SITE
            and subject.block_ref == step.block_serial
            and subject.anchor_ea == owner_subject.anchor_ea
            and getattr(subject.locator, "instruction_ea", None) == step.host_ea
            and getattr(subject.locator, "effect_kind", None) is model.EffectSiteKind.STORE
        )
        relations.append(model.ConditionalSubjectRelation(
            owner_subject.subject_id,
            effect_subject.subject_id,
            model.SafetyDimension.EFFECT_PRESERVATION,
            authority_id(("local-alias-effect", step_digest, effect_subject.subject_id)),
        ))
        claims.append(claim)
    return (
        tuple(sorted(claims, key=lambda item: item.claim_id)),
        tuple(sorted(patch_facts, key=lambda item: (item.plan_id, item.step_index))),
        tuple(sorted(relations, key=lambda item: (
            item.source_subject_id, item.target_subject_id,
            item.dimension.value, item.provenance_id,
        ))),
    )


def _patch_step_preimage(step_index: int, step: object) -> tuple[object, ...]:
    """Return the closed semantic fields of one helper/resegmentation step."""

    step_type = type(step).__name__
    values = tuple(
        (field.name, getattr(step, field.name))
        for field in fields(step)
        if not field.name.startswith("_")
    )
    return (step_type, step_index, values)


def _patch_block_spec_preimage(spec_index: int, spec: PatchBlockSpec) -> tuple[object, ...]:
    """Return every public field of one created-helper specification."""

    values = tuple(
        (field.name, getattr(spec, field.name))
        for field in fields(spec)
        if not field.name.startswith("_")
    )
    return ("PatchBlockSpec", spec_index, values)


def _nominal_patch_lineage_parts(
    step: object,
) -> tuple[tuple[object, ...], tuple[object, ...], int | None, int | None] | None:
    """Return exact owner/ref fields for supported nominal planner steps."""

    step_type = type(step)
    if step_type is PatchRedirectBranch:
        helper = step.fallthrough_helper_block_id
        owners = (step.from_serial, helper) if helper is not None else (step.from_serial,)
        return (
            owners,
            (step.from_serial, step.old_target, step.new_target),
            None,
            None,
        )
    if step_type is PatchRedirectGoto:
        return (
            (step.from_serial,),
            (step.from_serial, step.old_target, step.new_target),
            None,
            None,
        )
    if step_type is PatchLowerConditionalStateTransition:
        return (
            (step.source_serial,),
            (
                step.source_serial, step.old_dispatcher_serial,
                step.false_target_serial, step.true_target_serial,
            ),
            step.rewrite_from_ea,
            None,
        )
    if step_type is PatchEdgeSplitTrampoline:
        return (
            (step.block_id,),
            (
                step.source_serial, step.via_pred, step.old_target,
                step.apply_old_target, step.new_target, step.template_block,
            ),
            None,
            None,
        )
    if step_type is PatchEdgeSplitCorridor:
        return (
            tuple(step.clone_block_ids),
            (
                step.source_serial, step.via_pred, step.old_target,
                step.new_target, step.clone_until, *step.corridor_serials,
                step.source_new_target,
            ),
            None,
            None,
        )
    if step_type is PatchConditionalRedirect:
        return (
            (step.block_id, step.fallthrough_block_id),
            (
                step.source_serial, step.ref_block, step.conditional_target,
                step.fallthrough_target, step.old_target_serial,
            ),
            None,
            None,
        )
    if step_type is PatchInsertBlock:
        return (
            (step.block_id,),
            (step.pred_serial, step.succ_serial, step.old_target_serial),
            None,
            None,
        )
    if step_type is PatchDuplicateBlock:
        return (
            tuple(ref for ref in (step.block_id, step.fallthrough_block_id) if ref is not None),
            (
                step.source_serial, step.pred_serial, *step.source_successors,
                step.target_serial, step.conditional_target,
                step.fallthrough_target,
            ),
            None,
            None,
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
            (
                step.source_serial, step.pred_serial, step.goto_target,
                *step.source_successors, step.conditional_target,
                step.fallthrough_target,
            ),
            None,
            None,
        )
    if step_type is PatchCloneConditionalAsGotoFromBranchArm:
        return (
            (step.block_id,),
            (
                step.source_serial, step.pred_serial, step.goto_target,
                *step.source_successors, *step.pred_successors,
                step.pred_branch_target_serial,
                step.pred_fallthrough_target_serial,
                step.conditional_target, step.fallthrough_target,
            ),
            None,
            None,
        )
    return None


def _derive_patch_lineage_facts(
    source_inventory: model.SemanticGraphInventory,
    plan: PatchPlan,
) -> tuple[model.PatchStepEvidencePayload, ...]:
    """Derive helper/resegmentation step evidence once at the transaction edge."""

    source_refs = set(source_inventory.serial_by_ref)
    route_refs = {
        subject.block_ref
        for claim in plan.unflatten_proposal.claims
        for subject in _claim_subjects(claim)
        if subject.block_ref is not None
    } if plan.unflatten_proposal is not None else set()
    rows: list[model.PatchStepEvidencePayload] = []
    helper_specs = {
        spec.block_id: (spec_index, spec)
        for spec_index, spec in enumerate(plan.new_blocks)
    }
    if len(helper_specs) != len(plan.new_blocks):
        raise ValueError("plan helper specifications must have unique block IDs")
    for step_index, step in enumerate(plan.steps):
        step_type = type(step).__name__
        parts = _nominal_patch_lineage_parts(step)
        if parts is None:
            continue
        owners, refs, host_ea, host_opcode = parts
        for owner in owners:
            if type(owner) is not PlanBlockRef and owner not in source_refs:
                raise ValueError("patch-step owner is foreign to the source or plan")
            if type(owner) is PlanBlockRef and owner.plan_id != plan.plan_id:
                raise ValueError("patch-step owner belongs to a foreign plan")
            helper_spec = helper_specs.get(owner) if type(owner) is PlanBlockRef else None
            if type(owner) is PlanBlockRef and helper_spec is None:
                raise ValueError("patch-step helper owner lacks exactly one creation spec")
            owner_preimage = ("owner", owner)
            for ref in refs:
                if ref is None:
                    continue
                if type(ref) is PlanBlockRef:
                    if ref.plan_id != plan.plan_id:
                        raise ValueError("patch-step reference belongs to a foreign plan")
                elif ref not in source_refs:
                    raise ValueError("patch-step reference is foreign to the source plan")
            allowed_corridor_refs = {
                proposal_ref
                for proposal_ref in (
                    plan.unflatten_proposal.plan_inputs.source_entry_ref,
                    plan.unflatten_proposal.plan_inputs.dispatcher_entry_ref,
                    *plan.unflatten_proposal.plan_inputs.dispatcher_member_refs,
                )
                if proposal_ref is not None
            } if plan.unflatten_proposal is not None else set()
            if plan.unflatten_proposal is not None:
                forecast = plan.unflatten_proposal.corridor_coverage_forecast
                if forecast is not None:
                    allowed_corridor_refs.update(
                        node.block_ref
                        for path in forecast.paths
                        for node in path.nodes
                    )
                    dispatcher_serial = source_inventory.serial_by_ref.get(
                        forecast.dispatcher_ref
                    )
                    if dispatcher_serial is not None:
                        successor_serials = {
                            successor
                            for block in source_inventory.blocks
                            if block.serial == dispatcher_serial
                            for successor in block.successor_serials
                        }
                        allowed_corridor_refs.update(
                            block.block_ref
                            for block in source_inventory.blocks
                            if block.serial in successor_serials
                            and block.block_ref is not None
                        )
            if step_type in {"PatchLowerConditionalStateTransition", "PatchRedirectGoto", "PatchRedirectBranch"} and route_refs and not {
                ref for ref in refs if ref is not None
            } <= route_refs | allowed_corridor_refs:
                raise ValueError("patch-step source and destination refs are outside proposal route subjects")
            step_preimage: tuple[object, ...] = _patch_step_preimage(step_index, step)
            step_preimage += (owner_preimage,)
            if helper_spec is not None:
                step_preimage += (_patch_block_spec_preimage(*helper_spec),)
            step_digest = authority_id(step_preimage)
            rows.append(model.PatchStepEvidencePayload(
                plan.plan_id, step_index, step_type, owner, step_digest,
                host_ea, host_opcode, None,
            ))
    owned_helpers = {
        fact.owner_ref for fact in rows if type(fact.owner_ref) is PlanBlockRef
    }
    helper_owner_counts = {
        helper_ref: sum(1 for fact in rows if fact.owner_ref == helper_ref)
        for helper_ref in helper_specs
    }
    if owned_helpers != set(helper_specs) or any(
        count != 1 for count in helper_owner_counts.values()
    ):
        raise ValueError("every plan helper specification must have one exact patch-step owner")
    return tuple(rows)


def _derive_transaction_facts(
    source_inventory: model.SemanticGraphInventory,
    plan: PatchPlan,
) -> tuple[
    tuple[model.LocalAliasEffectScalarizationClaim, ...],
    tuple[model.PatchStepEvidencePayload, ...],
    tuple[model.ConditionalSubjectRelation, ...],
]:
    """Derive the complete transaction fact set at one authority boundary.

    Revalidation must replay this exact function.  Keeping alias and
    patch-lineage derivation behind one entry point prevents a later caller
    from silently comparing a Task 12 plan against the Task 11-only replay.
    """

    alias_claims, alias_patch_facts, alias_relations = (
        _derive_local_alias_transaction_facts(source_inventory, plan)
    )
    patch_step_facts = tuple(sorted(
        (*alias_patch_facts, *_derive_patch_lineage_facts(source_inventory, plan)),
        key=lambda item: (item.plan_id, item.step_index, item.step_type),
    ))
    return alias_claims, patch_step_facts, alias_relations


def _derive_patch_lineage_relations(
    source_inventory: model.SemanticGraphInventory,
    candidate_inventory: model.SemanticGraphInventory,
    plan: PatchPlan,
    patch_step_facts: tuple[model.PatchStepEvidencePayload, ...],
) -> tuple[model.ConditionalSubjectRelation, ...]:
    """Bind each patch step to exact source/candidate block witnesses."""

    source_subjects = tuple(
        subject for subject in source_inventory.subjects
        if subject.kind is model.SemanticSubjectKind.BLOCK
        and subject.block_ref is not None
    )
    candidate_subjects = tuple(
        subject for subject in candidate_inventory.subjects
        if subject.kind is model.SemanticSubjectKind.BLOCK
        and subject.block_ref is not None
    )
    candidate_bindings = {
        item.subject.subject_id: item for item in candidate_inventory.bindings
    }
    relations: list[model.ConditionalSubjectRelation] = []
    for fact in patch_step_facts:
        step = plan.steps[fact.step_index]
        if (
            type(step) is PatchRedirectBranch
            and step.fallthrough_helper_block_id is not None
            and type(fact.owner_ref) is not PlanBlockRef
        ):
            # The native source owner is carried as exact patch evidence for
            # evaluator use-def projection, but helper lineage relations are
            # established only by the helper-owned fact.
            continue
        parts = _nominal_patch_lineage_parts(step)
        if parts is None:
            continue
        _owners, refs, _host_ea, _host_opcode = parts
        source_ref = next((ref for ref in refs if type(ref) is not PlanBlockRef), None)
        owner = fact.owner_ref
        helper_spec = next(
            (spec for spec in plan.new_blocks if spec.block_id == owner), None
        ) if type(owner) is PlanBlockRef else None
        if helper_spec is not None and helper_spec.template_block is not None:
            source_ref = helper_spec.template_block
        if source_ref is None:
            raise ValueError("patch-step lineage lacks an exact source reference")
        sources = tuple(item for item in source_subjects if item.block_ref == source_ref)
        candidates = tuple(item for item in candidate_subjects if item.block_ref == owner)
        if not sources or not candidates:
            raise ValueError("patch-step lineage lacks exact source/candidate witnesses")
        if type(owner) is PlanBlockRef:
            preferred = tuple(
                source for source in sources
                if source.role is model.SemanticSubjectRole.SOURCE_ENTRY
            )
            if len(preferred) == 1:
                sources = preferred
            elif len(sources) != 1:
                raise ValueError("helper lineage source role is ambiguous")
        else:
            by_role = {}
            for source in sources:
                by_role.setdefault(source.role, []).append(source)
            candidate_by_role = {}
            for candidate in candidates:
                candidate_by_role.setdefault(candidate.role, []).append(candidate)
            paired = []
            for role in sorted(set(by_role) & set(candidate_by_role), key=lambda value: value.value):
                left, right = by_role[role], candidate_by_role[role]
                if len(left) != 1 or len(right) != 1:
                    raise ValueError("patch-step lineage role witness is ambiguous")
                paired.append((left[0], right[0]))
            if not paired:
                if len(sources) != 1 or len(candidates) != 1:
                    raise ValueError("patch-step lineage block witness is ambiguous")
                paired.append((sources[0], candidates[0]))
        if type(owner) is PlanBlockRef:
            if len(candidates) != 1:
                raise ValueError("helper lineage candidate role is ambiguous")
            paired = ((sources[0], candidates[0]),)
        for source, candidate in paired:
            binding = candidate_bindings.get(candidate.subject_id)
            if binding is None or binding.status is not model.SubjectBindingStatus.UNIQUE:
                raise ValueError("patch-step lineage candidate witness is not unique")
            relations.append(model.ConditionalSubjectRelation(
                source.subject_id,
                candidate.subject_id,
                model.SafetyDimension.STRUCTURAL_ACCOUNTING,
                authority_id(("patch-lineage", fact.step_digest,
                              source.subject_id, candidate.subject_id,
                              binding.native_instruction_eas)),
            ))
    return tuple(sorted(relations, key=lambda item: (
        item.source_subject_id, item.target_subject_id,
        item.dimension.value, item.provenance_id,
    )))


def _local_alias_step_preimage(
    step_index: int, step: PatchScalarizeLocalAliasAccess,
) -> tuple[object, ...]:
    """Return the canonical, closed representation of an alias step.

    ``PatchScalarizeLocalAliasAccess`` is a planner record and deliberately is
    not part of the semantic-authority codec.  The transaction boundary still
    needs a stable digest of every field that becomes semantic authority, so
    digest the exact typed fields rather than passing the planner object to the
    canonical encoder.
    """

    return (
        "PatchScalarizeLocalAliasAccess",
        step_index,
        step.block_serial,
        step.host_ea,
        step.host_opcode,
        step.alias_token,
        step.base_token,
        step.host_text_sha1,
        step.value_size,
    )


def _validate_local_alias_step(step: PatchScalarizeLocalAliasAccess) -> None:
    """Revalidate the planner record at the semantic authority boundary."""

    if type(step) is not PatchScalarizeLocalAliasAccess:
        raise TypeError("local-alias step must be nominal")
    owner = step.block_serial
    if type(owner) not in (NativeBlockRef, LogicalBlockRef):
        raise TypeError("local-alias owner must be NativeBlockRef or LogicalBlockRef")
    try:
        owner.__post_init__()
    except (TypeError, ValueError) as error:
        raise ValueError("local-alias owner reference is malformed") from error
    if (
        type(step.host_ea) is not int
        or not 0 <= step.host_ea < 0xFFFFFFFFFFFFFFFF
    ):
        raise TypeError("local-alias host_ea must be an exact native EA")
    if type(step.host_opcode) is not int or step.host_opcode < 0:
        raise TypeError("local-alias host_opcode must be an exact nonnegative int")
    for value, label in (
        (step.alias_token, "alias_token"),
        (step.base_token, "base_token"),
    ):
        if type(value) is not str or not value.strip():
            raise TypeError(f"local-alias {label} must be a nonblank exact string")
    if step.host_text_sha1 is not None and (
        type(step.host_text_sha1) is not str
        or re.fullmatch(r"[0-9a-f]{16}", step.host_text_sha1) is None
    ):
        raise ValueError("local-alias host_text_sha1 must be lowercase 16-hex")
    if step.value_size is not None and (
        type(step.value_size) is not int or step.value_size <= 0
    ):
        raise TypeError("local-alias value_size must be an exact positive int")


def _derive_inputs(
    source_inventory, candidate_inventory, plan, proposal, generic_gates, *,
    phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
    candidate_generation=None,
    phase_build_metrics,
    preparation_metrics,
    source_route_assessment=None,
    candidate_route_assessment=None,
):
    """Assemble immutable facts; semantic evidence belongs to the evaluator."""

    if type(source_inventory) is not model.SemanticGraphInventory:
        raise TypeError("source_inventory must be SemanticGraphInventory")
    if type(candidate_inventory) is not model.SemanticGraphInventory:
        raise TypeError("candidate_inventory must be SemanticGraphInventory")
    model.validate_semantic_graph_inventory(source_inventory)
    model.validate_semantic_graph_inventory(candidate_inventory)
    terminal_cycle_phase_results = []
    if phase in {
        model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
    }:
        for claim in proposal.claims:
            if type(claim) is model.RetiredDispatcherInfrastructureClaim:
                catalog_rows = claim.retirement_catalog.members
                subjects_by_ref = {
                    subject.block_ref: subject for subject in claim.member_subjects
                }
                exact_subjects = tuple(
                    subjects_by_ref.get(row.block_ref, _subject_factory(
                        model.SemanticSubjectRef,
                        kind=model.SemanticSubjectKind.BLOCK,
                        role=model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE,
                        block_ref=row.block_ref,
                        anchor_ea=row.anchor_ea,
                        locator=model.BlockSubjectLocator(row.block_ref, row.anchor_ea),
                    ))
                    for row in catalog_rows
                )
                exact_subject_ids = {subject.subject_id for subject in exact_subjects}
                source_retirement_bindings = tuple(
                    binding for binding in source_inventory.bindings
                    if binding.subject.subject_id in exact_subject_ids
                )
                projected_retirement_bindings = tuple(
                    binding for binding in candidate_inventory.bindings
                    if binding.subject.subject_id in exact_subject_ids
                )
                binding_result = authority_bind.bind_retired_dispatcher_infrastructure_claim(
                    claim=claim, proposal=proposal,
                    source_graph_fingerprint=source_inventory.graph_fingerprint,
                    projected_graph_fingerprint=candidate_inventory.graph_fingerprint,
                    generation=source_inventory.generation,
                    phase=phase,
                    projected_generation=candidate_generation
                    if candidate_generation is not None else candidate_inventory.generation,
                    source_subject_bindings=source_retirement_bindings,
                    projected_subject_bindings=projected_retirement_bindings,
                )
                expected_source = {
                    item.subject.subject_id: item
                    for item in binding_result.source_bindings
                }
                actual_source = {
                    item.subject.subject_id: item
                    for item in source_inventory.bindings
                    if item.subject.subject_id in expected_source
                }
                expected_projected = {
                    item.subject.subject_id: item
                    for item in binding_result.projected_bindings
                }
                actual_projected = {
                    item.subject.subject_id: item
                    for item in candidate_inventory.bindings
                    if item.subject.subject_id in expected_projected
                }
                if actual_source != expected_source:
                    raise ValueError("retirement binder result is not carried by source facts")
                if actual_projected != expected_projected:
                    raise ValueError("candidate retirement facts drifted from binder result")
            elif type(claim) is model.TerminalCycleBreakClaim:
                terminal_binding = authority_bind.bind_terminal_cycle_break_claim(
                    claim=claim,
                    proposal=proposal,
                    source_inventory=source_inventory,
                    candidate_inventory=candidate_inventory,
                    phase=phase,
                )
                terminal_cycle_phase_results.append(
                    terminal_binding.phase_result,
                )
    if type(phase_build_metrics) is not model.PhaseBuildMetrics:
        raise TypeError("phase_build_metrics must be PhaseBuildMetrics")
    model.validate_phase_build_metrics(phase_build_metrics)
    if type(preparation_metrics) is not model.PreparationBuildMetrics:
        raise TypeError("preparation_metrics must be PreparationBuildMetrics")
    model.validate_preparation_build_metrics(preparation_metrics)
    generic_gate_facts = None
    if type(generic_gates) is GenericCfgGateBundle:
        validate_generic_cfg_gate_bundle(generic_gates)
        generic_gate_facts = generic_gates.facts
    elif generic_gates is not None:
        raise TypeError("generic_gates must be GenericCfgGateBundle or None")
    alias_claims, patch_step_facts, alias_relations = _derive_transaction_facts(
        source_inventory, plan,
    )
    conditional_relations = tuple(sorted(
        (*alias_relations, *_derive_patch_lineage_relations(
            source_inventory, candidate_inventory, plan, patch_step_facts,
        )),
        key=lambda item: (item.source_subject_id, item.target_subject_id,
                          item.dimension.value, item.provenance_id),
    ))
    corridor_coverage_phase_result = authority_bind.bind_corridor_coverage_forecast(
        proposal=proposal,
        source_inventory=source_inventory,
        candidate_inventory=candidate_inventory,
        phase=phase,
    )
    claims = tuple(sorted((*proposal.claims, *alias_claims), key=lambda item: item.claim_id))
    route_assessments = tuple(
        item for item in (source_route_assessment, candidate_route_assessment)
        if item is not None
    )
    receipt = _receipt(
        proposal,
        preparation_metrics,
        source_inventory=source_inventory,
        candidate_inventory=candidate_inventory,
        generic_gate_facts=generic_gate_facts,
        route_assessments=route_assessments,
        conditional_relations=conditional_relations,
        patch_step_facts=patch_step_facts,
    )
    return model.DerivedUnflattenPreparationInputs(
        proposal=proposal,
        claims=claims,
        preparation_receipt=receipt,
        source_inventory=source_inventory,
        candidate_inventory=candidate_inventory,
        source_route_assessment=source_route_assessment,
        candidate_route_assessment=candidate_route_assessment,
        generic_gate_facts=generic_gate_facts,
        conditional_relations=conditional_relations,
        patch_step_facts=patch_step_facts,
        preparation_metrics=preparation_metrics,
        phase_build_metrics=phase_build_metrics,
        corridor_coverage_phase_result=corridor_coverage_phase_result,
        terminal_cycle_phase_results=tuple(sorted(
            terminal_cycle_phase_results, key=lambda item: item.result_id,
        )),
    )


def derive_unflatten_preparation_inputs(
    source, projection, plan, proposal, generic_results
):
    """Build the closed source/candidate inventory consumed by T4."""
    if type(projection) is not CfgProjection:
        raise TypeError("projection must be CfgProjection")
    build_started = perf_counter()
    source_materialization = CanonicalRouteMaterialization.capture(
        source,
        generation=proposal.source_identity_catalog.generation,
        phase=route_model.CanonicalRouteAssessmentPhase.SOURCE,
    )
    projected_materialization = CanonicalRouteMaterialization.capture(
        projection.graph,
        generation=proposal.source_identity_catalog.generation,
        phase=route_model.CanonicalRouteAssessmentPhase.PROJECTED,
    )
    source_inventory = _build_semantic_graph_inventory(
        source, proposal, plan, source=True,
        phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
        materialization=source_materialization,
    )
    candidate_inventory = _build_semantic_graph_inventory(
        projection.graph, proposal, plan, source=False,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        source_subjects=source_inventory.subjects,
        materialization=projected_materialization,
    )
    phase_build_metrics = model.PhaseBuildMetrics(
        model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, 1, 1,
        max(0.0, perf_counter() - build_started) * 1000.0,
    )
    preparation_metrics = model.PreparationBuildMetrics(
        1, 1, phase_build_metrics.inventory_ms,
    )
    source_route_assessment = assess_canonical_route(
        source_materialization, proposal.route_evidence,
    )
    projected_route_assessment = assess_canonical_route(
        projected_materialization, proposal.route_evidence,
    )
    return _derive_inputs(
        source_inventory,
        candidate_inventory,
        plan,
        proposal,
        generic_results,
        candidate_generation=proposal.source_identity_catalog.generation,
        phase_build_metrics=phase_build_metrics,
        preparation_metrics=preparation_metrics,
        source_route_assessment=source_route_assessment,
        candidate_route_assessment=projected_route_assessment,
    )


def _prepare_unflatten_authority(*, source, projection, plan, attempt_id, generic_gates, _timings=None):
    """Prepare one immutable projected authority case before mutation."""
    from .model import (
        UnflattenAuthorityPreparationAccepted,
        UnflattenAuthorityPreparationRejected,
    )
    if type(source) is not FlowGraph or type(projection) is not CfgProjection:
        raise TypeError("unflatten preparation requires a FlowGraph and CfgProjection")
    if not isinstance(plan, PatchPlan):
        raise TypeError("unflatten preparation requires PatchPlan")
    if projection.plan_id != plan.plan_id or projection.snapshot_id != plan.snapshot_id:
        raise ValueError("projection authority differs from PatchPlan")
    if type(attempt_id) is not TransactionAttemptId:
        raise TypeError("unflatten preparation requires TransactionAttemptId")
    if attempt_id.plan_id != plan.plan_id:
        raise ValueError("preparation attempt belongs to a foreign plan")
    if plan.source_generation is not None and attempt_id.generation != plan.source_generation:
        raise ValueError("preparation attempt generation differs from source plan")
    route = select_plan_route(plan)
    if isinstance(route, UnflattenAuthorityNotApplicable):
        return route
    if not isinstance(route, TypedProposalRoute):
        verdict = model.UnflattenAuthorityVerdict(
            False, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
                route.reason, None, None, None,
                _unavailable_candidate_fingerprint(plan.plan_id), None, (),
        )
        return UnflattenAuthorityPreparationRejected(verdict)
    proposal = route.proposal
    candidate_fingerprint = None
    try:
        inventory_started_ns = perf_counter_ns()
        source_materialization = CanonicalRouteMaterialization.capture(
            source,
            generation=proposal.source_identity_catalog.generation,
            phase=route_model.CanonicalRouteAssessmentPhase.SOURCE,
        )
        projected_materialization = CanonicalRouteMaterialization.capture(
            projection.graph,
            generation=proposal.source_identity_catalog.generation,
            phase=route_model.CanonicalRouteAssessmentPhase.PROJECTED,
        )
        source_inventory = _build_semantic_graph_inventory(
            source, proposal, plan, source=True,
            phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
            materialization=source_materialization,
        )
        candidate_inventory = _build_semantic_graph_inventory(
            projection.graph, proposal, plan, source=False,
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            source_subjects=source_inventory.subjects,
            materialization=projected_materialization,
        )
        inventory_ms = _elapsed_ms(inventory_started_ns, perf_counter_ns())
        if _timings is not None:
            _timings.inventory_ms = inventory_ms
        candidate_fingerprint = candidate_inventory.graph_fingerprint
        phase_build_metrics = model.PhaseBuildMetrics(
            model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, 1, 1,
            inventory_ms,
        )
        preparation_metrics = model.PreparationBuildMetrics(
            1, 1, phase_build_metrics.inventory_ms,
        )
        binding_started_ns = perf_counter_ns()
        source_route_assessment = assess_canonical_route(
            source_materialization,
            proposal.route_evidence,
        )
        projected_route_assessment = assess_canonical_route(
            projected_materialization,
            proposal.route_evidence,
        )
        inputs = _derive_inputs(
            source_inventory, candidate_inventory,
            plan, proposal, generic_gates,
            candidate_generation=attempt_id.generation,
            phase_build_metrics=phase_build_metrics,
            preparation_metrics=preparation_metrics,
            source_route_assessment=source_route_assessment,
            candidate_route_assessment=projected_route_assessment,
        )
        bound_routes = source_route_assessment.bound_evidence
        prepared_authority_id = authority_id((
            proposal,
            inputs.claims,
            inputs.patch_step_facts,
            inputs.conditional_relations,
            inputs.source_inventory.graph_fingerprint,
            inputs.candidate_inventory.graph_fingerprint,
            inputs.source_inventory.generation,
            inputs.candidate_inventory.generation,
            inputs.source_inventory.bindings,
            inputs.candidate_inventory.bindings,
        ))
        if _timings is not None:
            _timings.binding_ms = _elapsed_ms(binding_started_ns, perf_counter_ns())
        evaluation_started_ns = perf_counter_ns()
        case = build_semantic_case(
            authority_id=prepared_authority_id,
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            inputs=inputs,
        )
        verdict = evaluate_case(case)
        if _timings is not None:
            _timings.evaluation_ms = _elapsed_ms(evaluation_started_ns, perf_counter_ns())
        if verdict.accepted:
            prepared = model.PreparedUnflattenAuthority(
                authority_id=prepared_authority_id, route=route.route,
                owning_plan=plan, proposal=proposal, claims=inputs.claims,
                bound_routes=bound_routes, snapshot_id=plan.snapshot_id,
                source_maturity=plan.source_maturity,
                source_coordinate_digest=authority_id(
                    tuple(sorted(plan.source_coordinates, key=lambda item: repr(item)))
                ),
                source_fingerprint=inputs.source_inventory.graph_fingerprint,
                projected_fingerprint=inputs.candidate_inventory.graph_fingerprint,
                source_generation=inputs.source_inventory.generation,
                projected_generation=inputs.candidate_inventory.generation,
                source_bindings=inputs.source_inventory.bindings,
                projected_bindings=inputs.candidate_inventory.bindings,
                projected_case=case,
                source_inputs=inputs,
                source_inventory=source_inventory,
                preparation_attempt_id=attempt_id,
                legacy_unflatten_shadow=plan.legacy_unflatten_shadow,
                source_route_assessment=source_route_assessment,
                projected_route_assessment=projected_route_assessment,
            )
            return UnflattenAuthorityPreparationAccepted(prepared, verdict)
        return UnflattenAuthorityPreparationRejected(verdict)
    except (TypeError, ValueError):
        verdict = model.UnflattenAuthorityVerdict(
            False, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            model.UnflattenAuthorityReason.PROJECTED_BINDING_FAILED,
            authority_id(proposal), None, None,
            candidate_fingerprint or _unavailable_candidate_fingerprint(plan.plan_id), None, (),
        )
        return UnflattenAuthorityPreparationRejected(verdict)


def prepare_unflatten_authority(*, source, projection, plan, attempt_id, generic_gates):
    return _prepare_unflatten_authority(
        source=source, projection=projection, plan=plan,
        attempt_id=attempt_id, generic_gates=generic_gates,
    )


def prepare_unflatten_authority_timed(
    *, source, projection, plan, attempt_id, generic_gates,
) -> TimedUnflattenAuthorityResult:
    recorder = _AuthorityTimingRecorder()
    result = _prepare_unflatten_authority(
        source=source, projection=projection, plan=plan,
        attempt_id=attempt_id, generic_gates=generic_gates,
        _timings=recorder,
    )
    return TimedUnflattenAuthorityResult(
        result,
        PhaseTimings(
            inventory_ms=recorder.inventory_ms,
            binding_ms=recorder.binding_ms,
            evaluation_ms=recorder.evaluation_ms,
            total_authority_ms=None,
        ),
    )


def revalidate_bound_patch_plan_against_prepared(
    prepared, bound_plan,
) -> BoundPatchPlan:
    """Recheck live plan authority before bind and observed consumption."""
    if type(prepared) is not model.PreparedUnflattenAuthority:
        raise TypeError("prepared must be PreparedUnflattenAuthority")
    if type(bound_plan) is not BoundPatchPlan:
        raise TypeError("bound_plan must be BoundPatchPlan")
    validate_bound_patch_plan(bound_plan)
    model.validate_semantic_graph_inventory(prepared.source_inventory)
    if prepared.source_inputs is None:
        raise ValueError("prepared authority lacks source inputs")
    model.DerivedUnflattenPreparationInputs.__post_init__(prepared.source_inputs)
    if bound_plan.plan is not prepared.owning_plan:
        raise ValueError("bound patch plan belongs to a foreign plan")
    alias_claims, patch_step_facts, conditional_relations = _derive_transaction_facts(
        prepared.source_inventory, bound_plan.plan,
    )
    conditional_relations = tuple(sorted(
        (*conditional_relations, *_derive_patch_lineage_relations(
            prepared.source_inventory,
            prepared.source_inputs.candidate_inventory,
            bound_plan.plan,
            patch_step_facts,
        )),
        key=lambda item: (item.source_subject_id, item.target_subject_id,
                          item.dimension.value, item.provenance_id),
    ))
    expected_claims = tuple(sorted(
        (*prepared.proposal.claims, *alias_claims),
        key=lambda item: item.claim_id,
    ))
    if (
        prepared.source_inputs.claims != expected_claims
        or prepared.source_inputs.patch_step_facts != patch_step_facts
        or prepared.source_inputs.conditional_relations != conditional_relations
    ):
        raise ValueError("bound patch plan local-alias authority changed")
    if bound_plan.plan.legacy_unflatten_shadow is not prepared.legacy_unflatten_shadow:
        raise ValueError("bound patch plan shadow differs from prepared authority")
    proposal_validation = validate_proposal(
        bound_plan.plan, bound_plan.plan.unflatten_proposal
    )
    if not isinstance(proposal_validation, ProposalAccepted):
        raise ValueError("bound patch plan proposal authority is no longer valid")
    if proposal_validation.proposal is not prepared.proposal:
        raise ValueError("bound patch plan proposal is not the prepared authority object")
    if bound_plan.plan.legacy_unflatten_shadow is not None:
        shadow_validation = validate_shadow_for_plan(
            bound_plan.plan, bound_plan.plan.legacy_unflatten_shadow
        )
        if not isinstance(shadow_validation, ShadowValidationAccepted):
            raise ValueError("bound patch plan shadow authority is no longer valid")
    if prepared.preparation_attempt_id is None:
        raise ValueError("prepared authority has no exact preparation attempt")
    if bound_plan.attempt_id != prepared.preparation_attempt_id:
        raise ValueError("bound patch plan is from a different preparation attempt")
    if bound_plan.attempt_id.plan_id != prepared.proposal.plan_id:
        raise ValueError("bound patch plan attempt belongs to a foreign plan")
    if (
        bound_plan.session_id != bound_plan.attempt_id.session_id
        or bound_plan.generation != bound_plan.attempt_id.generation
    ):
        raise ValueError("bound patch plan session/generation differs from attempt")
    if (
        prepared.source_maturity is not None
        and prepared.source_maturity.provider_id is not None
        and bound_plan.maturity.provider_id != prepared.source_maturity.provider_id
    ):
        raise ValueError("bound patch plan maturity differs from source maturity")
    source_coordinates = dict(prepared.owning_plan.source_coordinates)
    discovered_refs = tuple(dict.fromkeys(iter_refs(
        (bound_plan.plan.steps, bound_plan.plan.new_blocks, bound_plan.plan.relocation_map),
    )))
    executable_refs = {
        ref for ref in discovered_refs
        if type(ref) in (NativeBlockRef, LogicalBlockRef)
    }
    helper_refs = {
        spec.block_id for spec in bound_plan.plan.new_blocks
    }
    supplied_refs = {ref for ref, _serial in bound_plan.bindings}
    if supplied_refs != executable_refs | helper_refs:
        raise ValueError("bound patch plan does not exactly cover executable references")
    expected_order = (
        tuple(ref for ref in discovered_refs if type(ref) in (NativeBlockRef, LogicalBlockRef))
        + tuple(spec.block_id for spec in bound_plan.plan.new_blocks)
    )
    if tuple(ref for ref, _serial in bound_plan.bindings) != expected_order:
        raise ValueError("bound patch plan reference order differs from live binder")
    if any(
        sum(1 for ref, _serial in bound_plan.bindings if ref == helper_ref) != 1
        for helper_ref in helper_refs
    ):
        raise ValueError("each PlanBlockRef helper requires exactly one bound row")
    for ref, serial in bound_plan.bindings:
        if type(ref) is PlanBlockRef:
            if ref not in helper_refs:
                raise ValueError("bound patch plan contains a foreign helper reference")
            continue
        if ref not in source_coordinates:
            raise ValueError("bound patch plan contains a foreign source reference")
        if int(source_coordinates[ref]) != int(serial):
            raise ValueError("bound patch plan source tuple differs from source coordinates")
    return bound_plan


def _validated_observed_helper_serials(
    prepared: model.PreparedUnflattenAuthority,
    bound_plan: BoundPatchPlan,
    observed: FlowGraph,
) -> dict[PlanBlockRef, int]:
    """Use the revalidated binder rows as the live helper-coordinate authority."""
    helper_refs = tuple(spec.block_id for spec in bound_plan.plan.new_blocks)
    rows = tuple(
        (ref, serial) for ref, serial in bound_plan.bindings
        if type(ref) is PlanBlockRef
    )
    if tuple(ref for ref, _serial in rows) != helper_refs:
        raise ValueError("observed helper bindings do not exactly cover plan helpers")
    if len({serial for _ref, serial in rows}) != len(rows):
        raise ValueError("observed helper bindings duplicate live serials")
    source_serials = {
        serial for ref, serial in bound_plan.bindings
        if type(ref) in (NativeBlockRef, LogicalBlockRef)
    }
    source_serials.update(
        int(serial)
        for _ref, serial in prepared.owning_plan.source_coordinates
    )
    source_serials.update(
        int(binding.serial)
        for binding in prepared.source_inventory.bindings
        if binding.serial is not None
    )
    if any(serial in source_serials for _ref, serial in rows):
        raise ValueError("observed helper binding collides with a source serial")
    if any(serial not in observed.blocks for _ref, serial in rows):
        raise ValueError("observed helper binding is absent from the live graph")
    if prepared.owning_plan.plan_id != bound_plan.plan.plan_id:
        raise ValueError("observed helper binding belongs to a foreign plan")
    if prepared.projected_generation != bound_plan.generation:
        raise ValueError("observed helper binding generation differs from authority")
    return dict(rows)


def bind_prepared_unflatten_authority(*, prepared, patch_binding):
    """Bind prepared authority to the exact result of ``bind_patch_plan``."""
    from .model import UnflattenAuthorityBindingAccepted, UnflattenAuthorityBindingRejected
    if type(prepared) is not model.PreparedUnflattenAuthority:
        raise TypeError("prepared must be PreparedUnflattenAuthority")
    try:
        if type(patch_binding) is not BoundPatchPlan:
            raise TypeError("patch_binding must be BoundPatchPlan")
        revalidate_bound_patch_plan_against_prepared(prepared, patch_binding)
        ident = bound_unflatten_binding_id(prepared, patch_binding)
        authority = model.BoundUnflattenAuthority(
            binding_id=ident, prepared=prepared, attempt_id=patch_binding.attempt_id,
            session_id=patch_binding.session_id, generation=patch_binding.generation,
            live_maturity=patch_binding.maturity, live_bindings=patch_binding.bindings,
            patch_binding=patch_binding,
        )
        return UnflattenAuthorityBindingAccepted(authority)
    except (TypeError, ValueError):
        verdict = model.UnflattenAuthorityVerdict(
            False, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            model.UnflattenAuthorityReason.PROJECTED_BINDING_FAILED,
            prepared.authority_id, None, None, prepared.projected_fingerprint, None, (),
        )
        return UnflattenAuthorityBindingRejected(verdict)


def _revalidate_observed_unflatten_authority(
    *, authority, observed, observed_generation, generic_gates, _timings=None,
):
    """Revalidate a bound authority against the observed graph identity."""
    if type(authority) is not model.BoundUnflattenAuthority:
        return _live_binding_failed_verdict()
    if type(observed) is not FlowGraph:
        raise TypeError("observed must be FlowGraph")
    if type(observed_generation) is not int or observed_generation < 0:
        return model.UnflattenAuthorityVerdict(
            False,
            model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
            model.UnflattenAuthorityReason.GRAPH_GENERATION_MISMATCH,
            None,
            None,
            None,
            _unavailable_candidate_fingerprint("observed-generation"),
            None,
            (),
        )
    binding_started_ns = perf_counter_ns()
    try:
        model.BoundUnflattenAuthority.__post_init__(authority)
        model.PreparedUnflattenAuthority.__post_init__(authority.prepared)
        revalidate_bound_patch_plan_against_prepared(
            authority.prepared, authority.patch_binding
        )
        observed_helper_serials = _validated_observed_helper_serials(
            authority.prepared, authority.patch_binding, observed,
        )
    except (TypeError, ValueError, AttributeError):
        return _live_binding_failed_verdict()
    pre_inventory_binding_ms = _elapsed_ms(binding_started_ns, perf_counter_ns())
    validated_prepared = authority.prepared
    validated_generation = authority.generation
    if observed_generation != validated_generation:
        return model.UnflattenAuthorityVerdict(
            False,
            model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
            model.UnflattenAuthorityReason.GRAPH_GENERATION_MISMATCH,
            validated_prepared.authority_id,
            authority.binding_id,
            None,
            _unavailable_candidate_fingerprint("observed-generation-mismatch"),
            None,
            (),
        )
    inventory_started_ns = perf_counter_ns()
    try:
        observed_materialization = CanonicalRouteMaterialization.capture(
            observed,
            generation=observed_generation,
            phase=route_model.CanonicalRouteAssessmentPhase.OBSERVED,
        )
        candidate_inventory = _build_semantic_graph_inventory(
            observed, validated_prepared.proposal, validated_prepared.owning_plan,
            source=False, phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
            source_subjects=validated_prepared.source_inventory.subjects,
            materialization=observed_materialization,
            planned_serials=observed_helper_serials,
        )
    except (TypeError, ValueError):
        return model.UnflattenAuthorityVerdict(
            False,
            model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
            model.UnflattenAuthorityReason.LIVE_BINDING_FAILED,
            validated_prepared.authority_id,
            authority.binding_id,
            None,
            _unavailable_candidate_fingerprint("observed-inventory"),
            None,
            (),
        )
    inventory_ms = _elapsed_ms(inventory_started_ns, perf_counter_ns())
    phase_build_metrics = model.PhaseBuildMetrics(
        model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY, 0, 1,
        inventory_ms,
    )
    if _timings is not None:
        _timings.inventory_ms = inventory_ms
    post_inventory_binding_started_ns = perf_counter_ns()
    observed_fingerprint = candidate_inventory.graph_fingerprint
    prepared_inputs = validated_prepared.source_inputs
    if prepared_inputs is None:
        raise ValueError("prepared authority lacks its closed source inventory")
    if validated_prepared.source_inventory is not prepared_inputs.source_inventory:
        raise ValueError("prepared source inventory identity changed")
    source_route_assessment = validated_prepared.source_route_assessment
    if source_route_assessment is None:
        source_route_assessment = prepared_inputs.source_route_assessment
    if source_route_assessment is None:
        raise ValueError("prepared authority lacks source route assessment")
    observed_route_assessment = assess_canonical_route(
        observed_materialization, validated_prepared.proposal.route_evidence,
    )
    try:
        inputs = _derive_inputs(
            prepared_inputs.source_inventory, candidate_inventory,
            validated_prepared.owning_plan, validated_prepared.proposal, generic_gates,
            phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
            candidate_generation=observed_generation,
            phase_build_metrics=phase_build_metrics,
            preparation_metrics=prepared_inputs.preparation_metrics,
            source_route_assessment=source_route_assessment,
            candidate_route_assessment=observed_route_assessment,
        )
        if _timings is not None:
            _timings.binding_ms = (
                pre_inventory_binding_ms
                + _elapsed_ms(post_inventory_binding_started_ns, perf_counter_ns())
            )
    except (TypeError, ValueError):
        return model.UnflattenAuthorityVerdict(
            False,
            model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
            model.UnflattenAuthorityReason.LIVE_BINDING_FAILED,
            validated_prepared.authority_id,
            authority.binding_id,
            None,
            observed_fingerprint,
            None,
            (),
        )
    evaluation_started_ns = perf_counter_ns()
    observed_case = build_semantic_case(
        authority_id=validated_prepared.authority_id,
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        inputs=inputs,
    )
    verdict = evaluate_case(observed_case)
    if _timings is not None:
        _timings.evaluation_ms = _elapsed_ms(evaluation_started_ns, perf_counter_ns())
    return replace(verdict, binding_id=authority.binding_id)


def revalidate_observed_unflatten_authority(
    *, authority, observed, observed_generation, generic_gates,
):
    return _revalidate_observed_unflatten_authority(
        authority=authority, observed=observed,
        observed_generation=observed_generation, generic_gates=generic_gates,
    )


def revalidate_observed_unflatten_authority_timed(
    *, authority, observed, observed_generation, generic_gates,
) -> TimedUnflattenAuthorityResult:
    recorder = _AuthorityTimingRecorder()
    result = _revalidate_observed_unflatten_authority(
        authority=authority, observed=observed,
        observed_generation=observed_generation, generic_gates=generic_gates,
        _timings=recorder,
    )
    return TimedUnflattenAuthorityResult(
        result,
        PhaseTimings(
            inventory_ms=recorder.inventory_ms,
            binding_ms=recorder.binding_ms,
            evaluation_ms=recorder.evaluation_ms,
            total_authority_ms=None,
        ),
    )


def select_plan_route(plan: PatchPlan) -> PlanRouteResult:
    """Select the only valid authority route for ``plan``.

    Ordinary plans get a dedicated not-applicable result.  Every other route
    is explicit: a closed typed proposal is accepted, while legacy metadata
    requires an adapter and is never guessed as ordinary authority.
    """

    if type(plan) is not PatchPlan:
        raise TypeError("plan must be a PatchPlan")

    try:
        reserved_keys = reserved_metadata_keys(plan)
    except MetadataKeyTypeError:
        return RejectedPlanRoute(
            UnflattenAuthorityReason.MALFORMED_PROPOSAL,
            "metadata_key_type_invalid",
        )
    except ValueError:
        return RejectedPlanRoute(
            UnflattenAuthorityReason.MALFORMED_PROPOSAL,
            "metadata_shape_invalid",
        )
    proposal = plan.unflatten_proposal
    if proposal is not None:
        if reserved_keys:
            return RejectedPlanRoute(
                UnflattenAuthorityReason.DUAL_AUTHORITY_CHANNEL,
                "typed_proposal_has_top_level_legacy_metadata",
                reserved_keys[0],
            )
        validation = validate_proposal(plan, proposal)
        if isinstance(validation, ProposalRejected):
            return RejectedPlanRoute(
                validation.reason,
                validation.detail_code,
                validation.key,
            )
        if plan.legacy_unflatten_shadow is not None:
            rejection = validate_shadow_for_plan(
                plan, plan.legacy_unflatten_shadow
            )
            if not isinstance(rejection, ShadowValidationAccepted):
                return rejection
        if not isinstance(validation, ProposalAccepted):
            raise TypeError("proposal validation returned an unknown result")
        return TypedProposalRoute(
            UnflattenPlanRoute.TYPED_PROPOSAL,
            validation.proposal,
        )

    if plan.legacy_unflatten_shadow is not None:
        return RejectedPlanRoute(
            UnflattenAuthorityReason.MALFORMED_PROPOSAL,
            "shadow_without_typed_proposal",
        )
    if reserved_keys:
        return RejectedPlanRoute(
            UnflattenAuthorityReason.MALFORMED_PROPOSAL,
            "legacy_metadata_requires_explicit_codec_adaptation",
            reserved_keys[0],
        )
    return UnflattenAuthorityNotApplicable(UnflattenPlanRoute.ORDINARY)


def project_shadow_parity(
    projected_legacy: LegacyPhaseOutcome,
    projected_canonical: model.UnflattenAuthorityVerdict,
    observed_legacy: LegacyPhaseOutcome,
    observed_canonical: model.UnflattenAuthorityVerdict,
    *,
    projected_counters: ShadowParityCounters,
    observed_counters: ShadowParityCounters,
    codec_receipt: LegacyShadowCodecReceipt,
) -> ShadowParityPayload:
    """Project parity facts without changing the transaction decision.

    Legacy remains decisive for the shadow release.  This facade only routes
    already validated facts to the pure diagnostic comparator.
    """

    from .diagnostics import compare_shadow_parity
    if type(codec_receipt) is not LegacyShadowCodecReceipt:
        raise TypeError("codec_receipt must be LegacyShadowCodecReceipt")
    return compare_shadow_parity(
        projected_legacy,
        projected_canonical,
        observed_legacy,
        observed_canonical,
        projected_counters=projected_counters,
        observed_counters=observed_counters,
        codec_receipt=codec_receipt,
    )


compare_shadow_parity = project_shadow_parity


def adapt_plan_legacy_shadow(*, source, prepared):
    """Mint one codec receipt from the exact prepared plan shadow."""

    from .legacy_codec import (
        LegacyUnflattenDecodeContext,
        adapt_legacy_unflatten_shadow,
    )
    if type(source) is not FlowGraph or type(prepared) is not model.PreparedUnflattenAuthority:
        raise TypeError("shadow adaptation requires exact source and prepared authority")
    plan = prepared.owning_plan
    proposal = prepared.proposal
    if plan.unflatten_proposal is not proposal:
        raise ValueError("prepared proposal is not the owning plan proposal")
    if plan.source_generation != prepared.source_generation:
        raise ValueError("prepared source generation is not the owning plan generation")
    refs = dict((serial, ref) for ref, serial in plan.source_coordinates)
    context = LegacyUnflattenDecodeContext(
        proposal.plan_id, source, plan.source_generation,
        tuple(sorted(refs.items())), proposal.route_evidence,
        proposal.plan_inputs, proposal.use_def_witness, proposal,
    )
    return adapt_legacy_unflatten_shadow(plan, context=context)


__all__ = [
    "select_plan_route", "derive_unflatten_preparation_inputs",
    "prepare_unflatten_authority",
    "bind_prepared_unflatten_authority", "revalidate_observed_unflatten_authority",
    "project_shadow_parity", "compare_shadow_parity",
    "TimedUnflattenAuthorityResult", "prepare_unflatten_authority_timed",
    "revalidate_observed_unflatten_authority_timed", "adapt_plan_legacy_shadow",
]
