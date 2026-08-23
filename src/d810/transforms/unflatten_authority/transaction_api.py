"""Patch-transaction-facing route selection for unflatten authority."""

from __future__ import annotations

from dataclasses import replace
from time import perf_counter

from d810.transforms.plan import PatchPlan
from d810.analyses.control_flow import semantic_route_evidence as route_model
from d810.analyses.control_flow.semantic_route_evidence import (
    assess_canonical_route,
    CanonicalRouteMaterialization,
)
from d810.ir.flowgraph import FlowGraph
from d810.transforms.cfg_transaction import CfgProjection, TransactionAttemptId
from d810.transforms.patch_binding import (
    BoundPatchPlan,
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
from d810.transforms.unflatten_authority.ids import (
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


def _projected_serials(graph: FlowGraph, proposal, *, blocks=None) -> dict[object, int]:
    result: dict[object, int] = {}
    for witness in proposal.source_identity_catalog.blocks:
        def _anchor(block):
            native = getattr(block, "native_start_ea", None)
            start = getattr(block, "start_ea", None)
            return native if native is not None else start
        matches = tuple(
            block.serial
            for block in (graph.blocks if blocks is None else blocks).values()
            if _anchor(block) == witness.anchor_ea
        )
        if len(matches) == 1:
            result[witness.block_ref] = int(matches[0])
    if len(set(result.values())) != len(result):
        raise ValueError("projected inventory has duplicate source identities")
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


def _inventory_subjects(proposal, source_serials, effects=(), terminals=()):
    subjects = _block_subjects(proposal, source_serials)
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
        if source else _projected_serials(graph, proposal, blocks=blocks_by_serial)
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
                item.anchor_ea for item in proposal.source_identity_catalog.blocks
                if item.block_ref == owner_ref
            )
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
    discovered_subjects = _inventory_subjects(
        proposal,
        serial_by_ref,
        tuple(item for item in effects if item.owner_serial in reachable),
        tuple(item for item in terminals if item.owner_serial in reachable),
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
        reachable_tuple, graph.entry_serial, source_subject_ids,
    )
    return model.SemanticGraphInventory(
        phase, fingerprint, proposal.source_identity_catalog.generation,
        tuple(block_rows), subjects, bindings, effects, terminals, topology, digest,
        reachable_tuple,
        materialization.entry_serial,
        source_subject_ids,
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
    }
    return model.PreparationAuthorityReceipt.mint(**values)


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

    del plan, candidate_generation
    if type(source_inventory) is not model.SemanticGraphInventory:
        raise TypeError("source_inventory must be SemanticGraphInventory")
    if type(candidate_inventory) is not model.SemanticGraphInventory:
        raise TypeError("candidate_inventory must be SemanticGraphInventory")
    model.validate_semantic_graph_inventory(source_inventory)
    model.validate_semantic_graph_inventory(candidate_inventory)
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
    )
    return model.DerivedUnflattenPreparationInputs(
        proposal=proposal,
        claims=proposal.claims,
        preparation_receipt=receipt,
        source_inventory=source_inventory,
        candidate_inventory=candidate_inventory,
        source_route_assessment=source_route_assessment,
        candidate_route_assessment=candidate_route_assessment,
        generic_gate_facts=generic_gate_facts,
        conditional_relations=(),
        patch_step_facts=(),
        preparation_metrics=preparation_metrics,
        phase_build_metrics=phase_build_metrics,
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


def prepare_unflatten_authority(*, source, projection, plan, attempt_id, generic_gates):
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
        candidate_fingerprint = candidate_inventory.graph_fingerprint
        phase_build_metrics = model.PhaseBuildMetrics(
            model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, 1, 1,
            max(0.0, perf_counter() - build_started) * 1000.0,
        )
        preparation_metrics = model.PreparationBuildMetrics(
            1, 1, phase_build_metrics.inventory_ms,
        )
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
            inputs.source_inventory.graph_fingerprint,
            inputs.candidate_inventory.graph_fingerprint,
            inputs.source_inventory.generation,
            inputs.candidate_inventory.generation,
            inputs.source_inventory.bindings,
            inputs.candidate_inventory.bindings,
        ))
        case = build_semantic_case(
            authority_id=prepared_authority_id,
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            inputs=inputs,
        )
        verdict = evaluate_case(case)
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
    expected = dict(prepared.owning_plan.source_coordinates)
    supplied_refs = {ref for ref, _serial in bound_plan.bindings}
    required_refs = {
        item.block_ref
        for item in prepared.projected_bindings
        if item.status is model.SubjectBindingStatus.UNIQUE
        and item.block_ref is not None
    }
    if supplied_refs != required_refs:
        raise ValueError("bound patch plan does not exactly cover required source references")
    expected_order = tuple(
        ref for ref, _serial in prepared.owning_plan.source_coordinates
        if ref in required_refs
    )
    if tuple(ref for ref, _serial in bound_plan.bindings) != expected_order:
        raise ValueError("bound patch plan source tuple order differs from plan")
    for ref, serial in bound_plan.bindings:
        if ref not in expected:
            raise ValueError("bound patch plan contains a foreign source reference")
        if int(expected[ref]) != int(serial):
            raise ValueError("bound patch plan source tuple differs from plan")
    return bound_plan


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


def revalidate_observed_unflatten_authority(
    *, authority, observed, observed_generation, generic_gates,
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
    try:
        model.BoundUnflattenAuthority.__post_init__(authority)
        model.PreparedUnflattenAuthority.__post_init__(authority.prepared)
        revalidate_bound_patch_plan_against_prepared(
            authority.prepared, authority.patch_binding
        )
    except (TypeError, ValueError, AttributeError):
        return _live_binding_failed_verdict()
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
    build_started = perf_counter()
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
    phase_build_metrics = model.PhaseBuildMetrics(
        model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY, 0, 1,
        max(0.0, perf_counter() - build_started) * 1000.0,
    )
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
    observed_case = build_semantic_case(
        authority_id=validated_prepared.authority_id,
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        inputs=inputs,
    )
    verdict = evaluate_case(observed_case)
    return replace(verdict, binding_id=authority.binding_id)


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


__all__ = [
    "select_plan_route", "derive_unflatten_preparation_inputs",
    "prepare_unflatten_authority",
    "bind_prepared_unflatten_authority", "revalidate_observed_unflatten_authority",
]
