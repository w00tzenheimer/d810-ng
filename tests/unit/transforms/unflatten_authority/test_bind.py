"""Exact source/projected binding contracts for Task 9."""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest

from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
from d810.transforms.unflatten_authority import bind
from d810.transforms.unflatten_authority import model
from d810.transforms.cfg_transaction import LogicalBlockRef
from d810.transforms.unflatten_authority.ids import authority_id, semantic_graph_inventory_digest, _claim_factory, _subject_factory
from .helpers import block_ref, exact_fixture, state_identity
from .test_model import _minimal_corridor_forecast, _valid_proposal


def _fixture():
    proposal = model.ProposedUnflattenContract(**_valid_proposal(model))
    catalog = proposal.source_identity_catalog
    return proposal, catalog


def _terminal_cycle_fixture():
    from .test_evaluate import _role_subject

    values = _valid_proposal(model)
    native_key = values["source_identity_catalog"].native_key
    route_source_ref = block_ref("b3")
    terminal_ref = block_ref("b4")
    route_proof = values["route_evidence"].route_proofs[0]
    route_source_identity = StableBlockIdentity.from_instruction_eas(
        (0x1400,), native_key=native_key,
    )
    values["route_evidence"] = replace(
        values["route_evidence"],
        route_proofs=(replace(
            route_proof,
            source_identity=route_source_identity,
            source_anchor_ea=0x1400,
            delivery_region=NativeEaInterval(0x1400, 0x1401),
            destinations=tuple(
                replace(destination, terminal=True)
                for destination in route_proof.destinations
            ),
        ),),
    )
    values["source_identity_catalog"] = model.SourceIdentityCatalog(
        native_key,
        3,
        (
            *values["source_identity_catalog"].blocks,
            model.SourceBlockIdentityWitness(
                route_source_ref, 0x1400, (0x1400,),
            ),
            model.SourceBlockIdentityWitness(
                terminal_ref, 0x1500, (0x1500,),
            ),
        ),
    )
    values["plan_inputs"] = replace(
        values["plan_inputs"], source_entry_ref=route_source_ref,
    )
    cycle = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.CORRIDOR,
        role=model.SemanticSubjectRole.DISPATCHER_CORRIDOR,
        block_ref=block_ref("b0"),
        anchor_ea=0x1000,
        locator=model.CorridorSubjectLocator(
            authority_id("terminal-cycle"),
            block_ref("b0"),
            0x1000,
            (block_ref("b0"), block_ref("b1")),
            (0x1000, 0x1300),
        ),
    )
    cleanup = _role_subject(
        model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE, "1"
    )
    terminal = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.TERMINAL,
        role=model.SemanticSubjectRole.TERMINAL_SITE,
        block_ref=terminal_ref,
        anchor_ea=0x1500,
        locator=model.TerminalSubjectLocator(
            terminal_ref, 0x1500, model.TerminalKind.STOP, 0x1500,
        ),
    )
    claim = _claim_factory(
        model.TerminalCycleBreakClaim,
        model.UnflattenClaimKind.TERMINAL_CYCLE_BREAK,
        cycle,
        cleanup,
        terminal,
        (values["route_evidence"].route_proofs[0].proof_id,),
        3,
    )
    canonical_proof = values["route_evidence"].route_proofs[0]
    atomic_group_id = values["claims"][0].atomic_group_id
    route_subject = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.ROUTE,
        role=model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE,
        block_ref=route_source_ref,
        anchor_ea=0x1400,
        locator=model.RouteSubjectLocator(
            canonical_proof.proof_id,
            atomic_group_id,
            route_source_ref,
            0x1400,
            (block_ref("b2"),),
            (0x1100,),
        ),
    )
    route_source_subject = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.BLOCK,
        role=model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE,
        block_ref=route_source_ref,
        anchor_ea=0x1400,
        locator=model.BlockSubjectLocator(route_source_ref, 0x1400),
    )
    route_destination_subject = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.BLOCK,
        role=model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION,
        block_ref=block_ref("b2"),
        anchor_ea=0x1100,
        locator=model.BlockSubjectLocator(block_ref("b2"), 0x1100),
    )
    equivalent_route = _claim_factory(
        model.EquivalentSemanticRouteClaim,
        model.UnflattenClaimKind.EQUIVALENT_SEMANTIC_ROUTE,
        route_subject,
        route_subject,
        route_source_subject,
        (route_destination_subject,),
        (canonical_proof.proof_id,),
        atomic_group_id,
        3,
    )
    values["claims"] = (equivalent_route, claim)
    return model.ProposedUnflattenContract(**values), claim


def _rewire_inventory(inventory, successors, *, generation=3, entry_serial=None):
    entry_serial = inventory.entry_serial if entry_serial is None else entry_serial
    predecessor_by_serial = {serial: [] for serial in successors}
    for owner, peers in successors.items():
        for peer in peers:
            predecessor_by_serial[peer].append(owner)
    blocks = tuple(
        replace(
            block,
            predecessor_serials=tuple(sorted(predecessor_by_serial[block.serial])),
            successor_serials=tuple(successors[block.serial]),
        )
        for block in inventory.blocks
    )
    topology = tuple(sorted(
        (
            model.InventoryTopologyIncidence(
                kind,
                owner if kind is model.TopologyIncidenceKind.SUCCESSOR else peer,
                peer if kind is model.TopologyIncidenceKind.SUCCESSOR else owner,
                None,
            )
            for owner, peers in successors.items()
            for peer in peers
            for kind in (
                model.TopologyIncidenceKind.SUCCESSOR,
                model.TopologyIncidenceKind.PREDECESSOR,
            )
        ),
        key=lambda item: (item.kind.value, item.owner_serial, item.peer_serial),
    ))
    bindings = tuple(
        replace(binding, generation=generation)
        for binding in inventory.bindings
    )
    reachable = set()
    pending = [entry_serial]
    while pending:
        serial = pending.pop()
        if serial in reachable:
            continue
        reachable.add(serial)
        pending.extend(successors[serial])
    reachable_serials = tuple(sorted(reachable))
    digest = semantic_graph_inventory_digest(
        inventory.phase,
        inventory.graph_fingerprint,
        generation,
        blocks,
        inventory.subjects,
        bindings,
        inventory.effects,
        inventory.terminals,
        topology,
        reachable_serials,
        entry_serial,
        inventory.source_subject_ids,
        inventory.function_ea,
    )
    return replace(
        inventory,
        generation=generation,
        blocks=blocks,
        bindings=bindings,
        topology=topology,
        reachable_serials=reachable_serials,
        entry_serial=entry_serial,
        inventory_digest=digest,
    )


def _terminal_cycle_inventory_fixture():
    from .test_evaluate import _complete_inputs, _role_subject

    proposal, claim = _terminal_cycle_fixture()
    route_source = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.BLOCK,
        role=model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE,
        block_ref=block_ref("b3"),
        anchor_ea=0x1400,
        locator=model.BlockSubjectLocator(block_ref("b3"), 0x1400),
    )
    terminal_route_destination = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.BLOCK,
        role=model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION,
        block_ref=block_ref("b2"),
        anchor_ea=0x1100,
        locator=model.BlockSubjectLocator(block_ref("b2"), 0x1100),
    )
    carrier_effect = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.EFFECT,
        role=model.SemanticSubjectRole.EFFECT_SITE,
        block_ref=block_ref("b2"),
        anchor_ea=0x1100,
        locator=model.EffectSubjectLocator(
            block_ref("b2"), 0x1100, 0x1100,
            model.EffectSiteKind.CALL,
        ),
    )
    source_entry = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.BLOCK,
        role=model.SemanticSubjectRole.SOURCE_ENTRY,
        block_ref=block_ref("b3"),
        anchor_ea=0x1400,
        locator=model.BlockSubjectLocator(block_ref("b3"), 0x1400),
    )
    cycle_entry = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.BLOCK,
        role=model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE,
        block_ref=block_ref("b0"),
        anchor_ea=0x1000,
        locator=model.BlockSubjectLocator(block_ref("b0"), 0x1000),
    )
    inputs = _complete_inputs(
        source_subjects=(
            source_entry,
            route_source,
            terminal_route_destination,
            claim.cycle_subject,
            claim.cleanup_source_subject,
            claim.terminal_subject,
            carrier_effect,
        ),
        candidate_subjects=(
            source_entry,
            route_source,
            _role_subject(model.SemanticSubjectRole.DISPATCHER_ENTRY, "0"),
            cycle_entry,
            claim.cycle_subject,
            claim.cleanup_source_subject,
            claim.terminal_subject,
            terminal_route_destination,
            carrier_effect,
        ),
        # Build the closed graph inventories first. The transaction-owned
        # terminal-cycle phase result is minted from these inventories and is
        # only then admitted into DerivedUnflattenPreparationInputs.
        claims=tuple(
            item for item in proposal.claims
            if type(item) is not model.TerminalCycleBreakClaim
        ),
        proposal=proposal,
    )
    source = _rewire_inventory(
        inputs.source_inventory,
        {0: (1,), 1: (0, 2), 2: (4,), 3: (0,), 4: ()},
        entry_serial=3,
    )
    candidate = _rewire_inventory(
        inputs.candidate_inventory,
        {0: (1,), 1: (2,), 2: (4,), 3: (2,), 4: ()},
        generation=4,
        entry_serial=3,
    )
    residual = _rewire_inventory(
        inputs.candidate_inventory,
        {0: (1,), 1: (0, 2), 2: (4,), 3: (2,), 4: ()},
        generation=4,
        entry_serial=3,
    )
    return proposal, claim, inputs, source, candidate, residual


def _terminal_cycle_derived_inputs():
    """Run the transaction boundary over the realistic terminal fixture."""

    from d810.transforms.plan import PatchPlan, PatchRedirectBranch
    from d810.transforms.unflatten_authority import transaction_api

    proposal, claim, fixture, source, candidate, residual = (
        _terminal_cycle_inventory_fixture()
    )
    plan = PatchPlan(
        plan_id=proposal.plan_id,
        snapshot_id=authority_id("terminal-cycle-snapshot"),
        source_generation=source.generation,
        steps=tuple(
            PatchRedirectBranch(
                owner,
                block_ref("b1")
                if owner == block_ref("b0") else block_ref("b0"),
                block_ref("b2"),
            )
            for owner in proposal.use_def_witness.redirect_owner_refs
        ),
        source_coordinates=tuple(
            (block.block_ref, block.serial)
            for block in source.blocks if block.block_ref is not None
        ),
        unflatten_proposal=proposal,
    )
    inputs = transaction_api._derive_inputs(
        source, candidate, plan, proposal, None,
        phase_build_metrics=fixture.phase_build_metrics,
        preparation_metrics=fixture.preparation_metrics,
        candidate_generation=candidate.generation,
    )
    return proposal, claim, inputs, source, candidate, residual


def _retirement_inventories(
    *, physically_present_retired=False,
    phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
):
    """Build retirement inventories through the transaction-owned inventory builder."""

    from .test_transaction_api import _full_corridor_fixture
    from d810.transforms.unflatten_authority import transaction_api

    source, plan, projected, _gates = _full_corridor_fixture()
    proposal = plan.unflatten_proposal
    source_inventory = transaction_api._build_semantic_graph_inventory(
        source, proposal, plan, source=True,
        phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
    )
    candidate_graph = projected
    if physically_present_retired:
        retired_ref = proposal.retirement_catalog.members[1].block_ref
        retired_serial = next(
            serial for ref, serial in plan.source_coordinates
            if ref == retired_ref
        )
        blocks = {
            serial: replace(
                block,
                preds=tuple(peer for peer in block.preds if peer != retired_serial),
                succs=tuple(peer for peer in block.succs if peer != retired_serial),
            )
            for serial, block in source.blocks.items()
        }
        blocks[retired_serial] = replace(blocks[retired_serial], preds=(), succs=())
        candidate_graph = type(source)(blocks, source.entry_serial, source.func_ea)
    projected_inventory = transaction_api._build_semantic_graph_inventory(
        candidate_graph, proposal, plan, source=False,
        phase=phase,
        source_subjects=source_inventory.subjects,
    )
    claim = next(
        claim for claim in proposal.claims
        if type(claim) is model.RetiredDispatcherInfrastructureClaim
    )
    return proposal, claim, source_inventory, projected_inventory


def test_terminal_cycle_binding_requires_exact_reachable_cycle_break() -> None:
    proposal, claim, _inputs, source, candidate, residual = (
        _terminal_cycle_inventory_fixture()
    )
    result = bind.bind_terminal_cycle_break_claim(
        claim=claim,
        proposal=proposal,
        source_inventory=source,
        candidate_inventory=candidate,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
    )
    bind.validate_terminal_cycle_binding_result(result)
    assert result.source_cycle_edges
    assert not bind._contains_directed_cycle(
        result.residue_refs, result.projected_cycle_edges,
    )
    assert result.generation == 3
    assert result.projected_generation == 4
    with pytest.raises(ValueError, match="residual cycle"):
        bind.bind_terminal_cycle_break_claim(
            claim=claim,
            proposal=proposal,
            source_inventory=source,
            candidate_inventory=residual,
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        )


# Existing binding tests use the original private spelling as a compatibility
# alias; the implementation lives in the shared public helpers module.
_exact_fixture = exact_fixture


def _corridor_inventories(*, candidate_full=False, disposition=None, enumeration_complete=True, candidate_subject_tokens=None):
    """Build source/candidate inventories through the closed test builder."""

    from .test_evaluate import _complete_inputs, _role_subject

    refs = {0: block_ref("b0"), 1: block_ref("b1"), 2: block_ref("b2")}
    proposal_values = _valid_proposal(model)
    nodes = tuple(
        model.CorridorCoveragePathNode(refs[index], anchor)
        for index, anchor in ((1, 0x1300), (2, 0x1100), (0, 0x1000))
    )
    disposition = disposition or model.CorridorPathDisposition.STRUCTURALLY_COVERED
    path_id = authority_id((
        "unflatten.corridor-coverage-path.v1", nodes, None,
        disposition, (),
    ))
    path = model.CorridorCoveragePath(
        path_id, nodes, None, disposition, (),
    )
    covered = (path_id,) if disposition is not model.CorridorPathDisposition.RESIDUAL else ()
    residual = (path_id,) if disposition is model.CorridorPathDisposition.RESIDUAL else ()
    forecast_id = authority_id((
        "unflatten.corridor-coverage-forecast.v1", proposal_values["plan_id"],
        0x1000, proposal_values["source_identity_catalog"].native_key, 3,
        refs[0], 0x1000, (path,), covered, residual, enumeration_complete, (), (), (),
    ))
    proposal_values["corridor_coverage_forecast"] = model.CorridorCoverageForecast(
        forecast_id, proposal_values["plan_id"], 0x1000,
        proposal_values["source_identity_catalog"].native_key, 3, refs[0],
        0x1000, (path,), covered, residual, enumeration_complete, (), (), (),
    )
    proposal = model.ProposedUnflattenContract(**proposal_values)
    source_subjects = tuple(
        _role_subject(role, token)
        for role, token in (
            (model.SemanticSubjectRole.DISPATCHER_ENTRY, "0"),
            (model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE, "1"),
            (model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE, "2"),
        )
    )
    if candidate_full:
        candidate_subjects = source_subjects
    elif candidate_subject_tokens is None:
        candidate_subjects = source_subjects[1:]
    else:
        candidate_subjects = tuple(
            _role_subject(model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE, token)
            for token in candidate_subject_tokens
        )
    inputs = _complete_inputs(
        source_subjects=source_subjects,
        candidate_subjects=candidate_subjects,
        proposal=proposal,
    )
    source = inputs.source_inventory
    candidate = inputs.candidate_inventory
    if candidate_full:
        candidate = _inventory_rephase(
            source, phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            fingerprint=authority_id("candidate-full"), generation=4,
        )
    return proposal, source, candidate


def _inventory_rephase(inventory, *, phase, fingerprint, generation):
    from dataclasses import replace

    bindings = tuple(
        replace(binding, phase=phase, graph_fingerprint=fingerprint, generation=generation)
        for binding in inventory.bindings
    )
    digest = semantic_graph_inventory_digest(
        phase, fingerprint, generation, inventory.blocks, inventory.subjects,
        bindings, inventory.effects, inventory.terminals, inventory.topology,
        inventory.reachable_serials, inventory.entry_serial,
        inventory.source_subject_ids, inventory.function_ea,
    )
    return replace(
        inventory, phase=phase, graph_fingerprint=fingerprint,
        generation=generation, bindings=bindings, inventory_digest=digest,
    )


def _inventory_with_edges(inventory, successors, predecessors):
    """Rebuild a closed inventory after an explicit topology mutation."""

    from dataclasses import replace

    blocks = tuple(
        replace(
            block,
            successor_serials=tuple(sorted(successors.get(block.serial, block.successor_serials))),
            predecessor_serials=tuple(sorted(predecessors.get(block.serial, block.predecessor_serials))),
        )
        for block in inventory.blocks
    )
    by_serial = {block.serial: block for block in blocks}
    topology = tuple(
        incidence
        for block in blocks
        for incidence in (
            tuple(
                model.InventoryTopologyIncidence(
                    model.TopologyIncidenceKind.SUCCESSOR,
                    block.serial, peer, block.transfer_ea,
                )
                for peer in block.successor_serials
            )
            + tuple(
                model.InventoryTopologyIncidence(
                    model.TopologyIncidenceKind.PREDECESSOR,
                    block.serial, peer, by_serial[peer].transfer_ea,
                )
                for peer in block.predecessor_serials
            )
        )
    )
    topology = tuple(sorted(
        topology,
        key=lambda item: (
            item.kind.value, item.owner_serial, item.peer_serial,
            item.source_transfer_ea if item.source_transfer_ea is not None else -1,
        ),
    ))
    closure = set()
    pending = [inventory.entry_serial]
    by_serial = {block.serial: block for block in blocks}
    while pending:
        serial = pending.pop()
        if serial in closure:
            continue
        closure.add(serial)
        pending.extend(by_serial[serial].successor_serials)
    reachable_serials = tuple(sorted(closure))
    digest = semantic_graph_inventory_digest(
        inventory.phase, inventory.graph_fingerprint, inventory.generation,
        blocks, inventory.subjects, inventory.bindings, inventory.effects,
        inventory.terminals, topology, reachable_serials,
        inventory.entry_serial, inventory.source_subject_ids,
        inventory.function_ea,
    )
    return replace(
        inventory, blocks=blocks, topology=topology,
        reachable_serials=reachable_serials, inventory_digest=digest,
    )


def _corridor_forecast_variant(proposal, *, state_merge=None, disposition=None, enumeration_complete=None):
    from dataclasses import replace

    forecast = proposal.corridor_coverage_forecast
    base = forecast.paths[0]
    disposition = disposition or base.disposition
    enumeration_complete = forecast.enumeration_complete if enumeration_complete is None else enumeration_complete
    path_id = authority_id((
        "unflatten.corridor-coverage-path.v1", base.nodes, state_merge,
        disposition, (),
    ))
    path = model.CorridorCoveragePath(path_id, base.nodes, state_merge, disposition, ())
    covered = (path_id,) if disposition is not model.CorridorPathDisposition.RESIDUAL else ()
    residual = (path_id,) if disposition is model.CorridorPathDisposition.RESIDUAL else ()
    forecast_id = authority_id((
        "unflatten.corridor-coverage-forecast.v1", forecast.plan_id,
        forecast.function_ea, forecast.source_native_key, forecast.source_generation,
        forecast.dispatcher_ref, forecast.dispatcher_anchor_ea, (path,), covered,
        residual, enumeration_complete, (), (), (),
    ))
    changed = model.CorridorCoverageForecast(
        forecast_id, forecast.plan_id, forecast.function_ea,
        forecast.source_native_key, forecast.source_generation,
        forecast.dispatcher_ref, forecast.dispatcher_anchor_ea, (path,), covered,
        residual, enumeration_complete, (), (), (),
    )
    return replace(proposal, corridor_coverage_forecast=changed)


def _branch_corridor_inventories():
    proposal, source, candidate = _corridor_inventories()
    source = _inventory_with_edges(
        source,
        {0: (1,), 1: (2,), 2: (0, 1)},
        {0: (2,), 1: (0, 2), 2: (1,)},
    )
    # Candidate dispatcher b0 is intentionally absent.  The surviving merge
    # still has two predecessors (itself and feeder b2), so the positive
    # state-merge check exercises the complete source/candidate topology.
    candidate = _inventory_with_edges(
        candidate,
        {1: (1, 2), 2: (1,)},
        {1: (1, 2), 2: (1,)},
    )
    return _corridor_forecast_variant(
        proposal,
        state_merge=proposal.corridor_coverage_forecast.paths[0].nodes[-3],
    ), source, candidate


def _detached_subject(
    role: model.SemanticSubjectRole,
    serial: int,
) -> model.SemanticSubjectRef:
    ref = block_ref(f"detached-{serial}")
    anchor = 0x2000 + serial * 0x10
    if role is model.SemanticSubjectRole.AUTHORITATIVE_HANDLER:
        kind = model.SemanticSubjectKind.HANDLER
        locator = model.HandlerSubjectLocator(ref, anchor, (serial + 1,))
    else:
        kind = model.SemanticSubjectKind.BLOCK
        locator = model.BlockSubjectLocator(ref, anchor)
    return _subject_factory(
        model.SemanticSubjectRef,
        kind=kind,
        role=role,
        block_ref=ref,
        anchor_ea=anchor,
        locator=locator,
    )


def _detached_inventory(
    *,
    phase: model.UnflattenAuthorityPhase,
    fingerprint: str,
    generation: int,
    subjects: tuple[model.SemanticSubjectRef, ...],
    successors: dict[int, tuple[int, ...]],
    ambiguous_subject_ids: frozenset[str] = frozenset(),
    missing_subject_ids: frozenset[str] = frozenset(),
    instruction_kinds: dict[int, model.InsnKind] | None = None,
    stop_serial: int = 6,
) -> model.SemanticGraphInventory:
    instruction_kinds = {} if instruction_kinds is None else instruction_kinds
    predecessors = {serial: [] for serial in successors}
    for owner, targets in successors.items():
        for target in targets:
            predecessors[target].append(owner)
    bindings = []
    for subject in subjects:
        serial = int(subject.block_ref.proxy_token.rsplit("-", 1)[-1])
        if subject.subject_id in ambiguous_subject_ids:
            bindings.append(model.PhaseSubjectBinding(
                subject, phase, None, fingerprint, generation,
                model.SubjectBindingStatus.AMBIGUOUS, None, None, (), subject.role,
            ))
        elif subject.subject_id in missing_subject_ids:
            bindings.append(model.PhaseSubjectBinding(
                subject, phase, None, fingerprint, generation,
                model.SubjectBindingStatus.MISSING, None, None, (), subject.role,
            ))
        else:
            bindings.append(model.PhaseSubjectBinding(
                subject, phase, subject.block_ref, fingerprint, generation,
                model.SubjectBindingStatus.UNIQUE, serial, subject.anchor_ea,
                (subject.anchor_ea,), subject.role,
            ))
    bindings = tuple(sorted(bindings, key=lambda item: item.subject.subject_id))
    subject_by_serial = {}
    for subject in subjects:
        serial = int(subject.block_ref.proxy_token.rsplit("-", 1)[-1])
        subject_by_serial.setdefault(serial, subject)
    blocks = []
    for serial in sorted(successors):
        subject = subject_by_serial.get(serial)
        ref = subject.block_ref if subject is not None else block_ref(f"detached-{serial}")
        anchor = subject.anchor_ea if subject is not None else 0x2000 + serial * 0x10
        kind = instruction_kinds.get(serial, model.InsnKind.NOP)
        observation = model.InventoryInstructionObservation(
            0, anchor, 0, 1 if kind in {model.InsnKind.CALL, model.InsnKind.STORE} else 0,
            kind, None, kind is model.InsnKind.CALL, None,
        )
        blocks.append(model.InventoryBlockObservation(
            serial, ref, anchor, (anchor,), tuple(sorted(predecessors[serial])),
            tuple(sorted(successors[serial])), None, (observation,),
            model.BlockKind.STOP if serial == stop_serial else model.BlockKind.UNKNOWN,
            anchor,
        ))
    blocks = tuple(blocks)
    effects = tuple(sorted(
        (
            effect
            for block in blocks
            for effect in model.resolve_inventory_block_sites(
                serial=block.serial,
                owner_ref=block.block_ref,
                owner_anchor_ea=block.anchor_ea,
                block_kind=block.block_kind,
                successor_serials=block.successor_serials,
                instruction_observations=block.instruction_observations,
            )[0]
        ),
        key=lambda item: (
            item.owner_serial, item.instruction_ordinal,
            item.instruction_ea, item.effect_kind.value,
        ),
    ))
    terminals = tuple(sorted(
        (
            terminal
            for block in blocks
            for terminal in model.resolve_inventory_block_sites(
                serial=block.serial,
                owner_ref=block.block_ref,
                owner_anchor_ea=block.anchor_ea,
                block_kind=block.block_kind,
                successor_serials=block.successor_serials,
                instruction_observations=block.instruction_observations,
            )[1]
        ),
        key=lambda item: (
            item.owner_serial, item.instruction_ordinal is None,
            item.instruction_ordinal if item.instruction_ordinal is not None else -1,
            item.instruction_ea, item.terminal_kind.value,
        ),
    ))
    topology = tuple(sorted(
        (
            incidence
            for owner, targets in successors.items()
            for target in targets
            for incidence in (
                model.InventoryTopologyIncidence(
                    model.TopologyIncidenceKind.SUCCESSOR, owner, target, None,
                ),
                model.InventoryTopologyIncidence(
                    model.TopologyIncidenceKind.PREDECESSOR, target, owner, None,
                ),
            )
        ),
        key=lambda item: (item.kind.value, item.owner_serial, item.peer_serial),
    ))
    reachable = set()
    pending = [0]
    while pending:
        serial = pending.pop()
        if serial in reachable:
            continue
        reachable.add(serial)
        pending.extend(successors[serial])
    reachable_serials = tuple(sorted(reachable))
    canonical_subjects = tuple(sorted(subjects, key=lambda item: item.subject_id))
    digest = semantic_graph_inventory_digest(
        phase, fingerprint, generation, blocks, canonical_subjects, bindings,
        effects, terminals, topology, reachable_serials, 0,
        tuple(item.subject_id for item in canonical_subjects), 0x2000,
    )
    return model.SemanticGraphInventory(
        phase, fingerprint, generation, blocks, canonical_subjects, bindings,
        effects, terminals, topology, digest, reachable_serials, 0,
        tuple(item.subject_id for item in canonical_subjects), 0x2000,
    )


def _detached_binding_fixture(
    *,
    source_successors: dict[int, tuple[int, ...]] | None = None,
    candidate_successors: dict[int, tuple[int, ...]] | None = None,
    candidate_phase: model.UnflattenAuthorityPhase = model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
    candidate_fingerprint: str | None = None,
    candidate_generation: int = 4,
    ambiguous_subject_ids: frozenset[str] = frozenset(),
    source_instruction_kinds: dict[int, model.InsnKind] | None = None,
    candidate_stop_serial: int = 6,
    component_serials: tuple[int, ...] = (2, 3),
):
    dispatcher = _detached_subject(model.SemanticSubjectRole.DISPATCHER_ENTRY, 1)
    dead = _detached_subject(model.SemanticSubjectRole.AUTHORITATIVE_HANDLER, 2)
    retained = _detached_subject(model.SemanticSubjectRole.AUTHORITATIVE_HANDLER, 4)
    components = tuple(
        _detached_subject(
            model.SemanticSubjectRole.DETACHED_DEAD_HANDLER_COMPONENT, serial,
        )
        for serial in component_serials
    )
    terminal_ref = block_ref("detached-6")
    terminal_anchor = 0x2060
    terminal = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.TERMINAL,
        role=model.SemanticSubjectRole.TERMINAL_SITE,
        block_ref=terminal_ref,
        anchor_ea=terminal_anchor,
        locator=model.TerminalSubjectLocator(
            terminal_ref, terminal_anchor, model.TerminalKind.STOP,
            terminal_anchor,
        ),
    )
    source_instruction_kinds = (
        {} if source_instruction_kinds is None else source_instruction_kinds
    )
    effect_subjects = []
    for serial, kind in source_instruction_kinds.items():
        if kind not in {model.InsnKind.CALL, model.InsnKind.STORE}:
            continue
        ref = block_ref(f"detached-{serial}")
        anchor = 0x2000 + serial * 0x10
        effect_subjects.append(_subject_factory(
            model.SemanticSubjectRef,
            kind=model.SemanticSubjectKind.EFFECT,
            role=model.SemanticSubjectRole.EFFECT_SITE,
            block_ref=ref,
            anchor_ea=anchor,
            locator=model.EffectSubjectLocator(
                ref, anchor, anchor,
                model.EffectSiteKind.CALL
                if kind is model.InsnKind.CALL
                else model.EffectSiteKind.STORE,
            ),
        ))
    claim = _claim_factory(
        model.DetachedDeadHandlerComponentClaim,
        kind=model.UnflattenClaimKind.DETACHED_DEAD_HANDLER_COMPONENT,
        dispatcher_subject=dispatcher,
        dead_handler_subjects=(dead,),
        retained_handler_subjects=(retained,),
        component_subjects=components,
        source_generation=3,
    )
    subjects = tuple(sorted(
        {
            item.subject_id: item
            for item in (
                dispatcher, dead, retained, *components, terminal,
                *effect_subjects,
            )
        }.values(),
        key=lambda item: item.subject_id,
    ))
    source_successors = source_successors or {
        0: (1,), 1: (2, 4, 7), 2: (3,), 3: (1,),
        4: (5,), 5: (6,), 6: (), 7: (1,),
    }
    candidate_successors = candidate_successors or {
        0: (4,), 1: (2, 4, 7), 2: (3,), 3: (1,),
        4: (5,), 5: (6,), 6: (), 7: (1,),
    }
    source = _detached_inventory(
        phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
        fingerprint=authority_id("detached-source"), generation=3,
        subjects=subjects, successors=source_successors,
        instruction_kinds=source_instruction_kinds,
    )
    candidate = _detached_inventory(
        phase=candidate_phase,
        fingerprint=candidate_fingerprint or authority_id(
            f"detached-{candidate_phase.value}"
        ),
        generation=candidate_generation, subjects=subjects,
        successors=candidate_successors,
        ambiguous_subject_ids=ambiguous_subject_ids,
        missing_subject_ids=frozenset({
            *(subject.subject_id for subject in effect_subjects),
            *(() if candidate_stop_serial == 6 else (terminal.subject_id,)),
        }),
        stop_serial=candidate_stop_serial,
    )
    path_id = authority_id("detached-corridor-path")
    forecast_id = authority_id("detached-corridor-forecast")
    comparison_ids = (dispatcher.subject_id,)
    content = (
        "unflatten.corridor-coverage-phase.v1", forecast_id, candidate_phase,
        source.graph_fingerprint, candidate.graph_fingerprint,
        source.generation, candidate.generation, (path_id,), (), (), True, (),
        True, False, (), comparison_ids, dispatcher.subject_id,
    )
    corridor = model.CorridorCoveragePhaseResult(
        authority_id(content), forecast_id, candidate_phase,
        source.graph_fingerprint, candidate.graph_fingerprint,
        source.generation, candidate.generation, (path_id,), (), (), True, (),
        True, False, (), comparison_ids, dispatcher.subject_id,
    )
    return claim, source, candidate, corridor


def test_detached_binding_mints_projected_source_once_and_reuses_it_observed() -> None:
    """Only the public binder owns detached source/phase mint capability."""

    assert not hasattr(bind, "_mint_detached_source_result")
    assert not hasattr(bind, "_mint_detached_phase_result")
    assert "bind_detached_dead_handler_component_claim" in bind.__all__
    claim, source, projected, projected_corridor = _detached_binding_fixture()
    projected_binding = bind.bind_detached_dead_handler_component_claim(
        claim=claim,
        source_inventory=source,
        candidate_inventory=projected,
        corridor_result=projected_corridor,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
    )
    assert projected_binding.phase_result.accepted
    assert projected_binding.phase_result.source_result_id == projected_binding.source_result.result_id
    assert set(projected_binding.source_result.component_block_refs) == {
        subject.block_ref for subject in claim.component_subjects
    }

    _, _, observed, observed_corridor = _detached_binding_fixture(
        candidate_phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        candidate_fingerprint=authority_id("detached-observed"),
        candidate_generation=5,
    )
    observed_binding = bind.bind_detached_dead_handler_component_claim(
        claim=claim,
        source_inventory=source,
        candidate_inventory=observed,
        corridor_result=observed_corridor,
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        source_result=projected_binding.source_result,
    )
    assert observed_binding.source_result is projected_binding.source_result
    assert observed_binding.phase_result.accepted


def test_detached_binding_rejects_ambiguous_loss_and_foreign_dispatcher() -> None:
    claim, source, _candidate, _corridor = _detached_binding_fixture()
    ambiguous_id = claim.dead_handler_subjects[0].subject_id
    _, _, ambiguous, ambiguous_corridor = _detached_binding_fixture(
        ambiguous_subject_ids=frozenset({ambiguous_id}),
    )
    with pytest.raises(ValueError, match="ambiguous"):
        bind.bind_detached_dead_handler_component_claim(
            claim=claim, source_inventory=source,
            candidate_inventory=ambiguous, corridor_result=ambiguous_corridor,
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        )

    wrong_dispatcher = claim.retained_handler_subjects[0].subject_id
    content = (
        "unflatten.corridor-coverage-phase.v1",
        ambiguous_corridor.forecast_id, ambiguous_corridor.phase,
        ambiguous_corridor.source_fingerprint,
        ambiguous_corridor.candidate_fingerprint,
        ambiguous_corridor.source_generation,
        ambiguous_corridor.candidate_generation,
        ambiguous_corridor.covered_path_ids, (), (), True, (), True, False, (),
        tuple(sorted((claim.dispatcher_subject.subject_id, wrong_dispatcher))),
        wrong_dispatcher,
    )
    foreign = model.CorridorCoveragePhaseResult(
        authority_id(content), ambiguous_corridor.forecast_id,
        ambiguous_corridor.phase, ambiguous_corridor.source_fingerprint,
        ambiguous_corridor.candidate_fingerprint,
        ambiguous_corridor.source_generation,
        ambiguous_corridor.candidate_generation,
        ambiguous_corridor.covered_path_ids, (), (), True, (), True, False, (),
        tuple(sorted((claim.dispatcher_subject.subject_id, wrong_dispatcher))),
        wrong_dispatcher,
    )
    with pytest.raises(ValueError, match="dispatcher"):
        bind.bind_detached_dead_handler_component_claim(
            claim=claim, source_inventory=source,
            candidate_inventory=ambiguous, corridor_result=foreign,
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        )


@pytest.mark.parametrize(
    ("source_successors", "component_serials", "reason"),
    (
        (
            {0: (1, 3), 1: (2, 4, 7), 2: (3,), 3: (1,),
             4: (5,), 5: (6,), 6: (), 7: (1,)},
            (2, 3),
            "external semantic ingress",
        ),
        (
            {0: (1,), 1: (2, 4, 7), 2: (3,), 3: (1,),
             4: (5,), 5: (6,), 6: (), 7: (1,)},
            (2,),
            "exact source/candidate walk",
        ),
        (
            {0: (1,), 1: (2, 4), 2: (3,), 3: (7,), 4: (6,),
             6: (), 7: (8,), 8: (9,), 9: (1,)},
            (2, 3, 7, 8, 9),
            "strict minority",
        ),
    ),
)
def test_detached_binding_rejects_topology_component_and_minority_drift(
    source_successors,
    component_serials,
    reason,
) -> None:
    candidate_successors = {
        serial: ((4,) if serial == 0 else targets)
        for serial, targets in source_successors.items()
    }
    claim, source, candidate, corridor = _detached_binding_fixture(
        source_successors=source_successors,
        candidate_successors=candidate_successors,
        component_serials=component_serials,
    )
    with pytest.raises(ValueError, match=reason):
        bind.bind_detached_dead_handler_component_claim(
            claim=claim, source_inventory=source,
            candidate_inventory=candidate, corridor_result=corridor,
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        )


@pytest.mark.parametrize(
    ("source_successors", "source_instruction_kinds", "candidate_stop", "reason"),
    (
        (None, {2: model.InsnKind.CALL}, 6, "CALL or STORE"),
        (None, {7: model.InsnKind.STORE}, 6, "remainder contains CALL or STORE"),
        (
            {0: (1,), 1: (2, 4, 7), 2: (3,), 3: (1,),
             4: (5,), 5: (6,), 6: (), 7: ()},
            None, 6, "remainder contains a terminal block",
        ),
        (
            {0: (1,), 1: (2, 4, 7), 2: (3,), 3: (1,),
             4: (5,), 5: (6,), 6: (), 7: (0,)},
            None, 6, "remainder escapes",
        ),
        (None, None, 99, "terminal identity drifted"),
    ),
)
def test_detached_binding_rejects_effect_terminal_and_remainder_drift(
    source_successors,
    source_instruction_kinds,
    candidate_stop,
    reason,
) -> None:
    claim, source, candidate, corridor = _detached_binding_fixture(
        source_successors=source_successors,
        source_instruction_kinds=source_instruction_kinds,
        candidate_stop_serial=candidate_stop,
    )
    with pytest.raises(ValueError, match=reason):
        bind.bind_detached_dead_handler_component_claim(
            claim=claim, source_inventory=source,
            candidate_inventory=candidate, corridor_result=corridor,
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        )


def test_detached_observed_binding_rejects_handler_and_component_drift() -> None:
    claim, source, projected, projected_corridor = _detached_binding_fixture()
    projected_binding = bind.bind_detached_dead_handler_component_claim(
        claim=claim, source_inventory=source,
        candidate_inventory=projected, corridor_result=projected_corridor,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
    )
    observed_successors = {
        0: (2, 4), 1: (2, 4, 7), 2: (3,), 3: (4,),
        4: (5,), 5: (6,), 6: (), 7: (1,),
    }
    _, _, observed, observed_corridor = _detached_binding_fixture(
        candidate_phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        candidate_fingerprint=authority_id("detached-observed-drift"),
        candidate_generation=5,
        candidate_successors=observed_successors,
    )
    with pytest.raises(
        ValueError,
        match="detached dead-handler partition remains candidate-reachable",
    ):
        bind.bind_detached_dead_handler_component_claim(
            claim=claim, source_inventory=source,
            candidate_inventory=observed, corridor_result=observed_corridor,
            phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
            source_result=projected_binding.source_result,
        )


def test_detached_observed_binding_rejects_reissued_source_authority() -> None:
    claim, source, projected, projected_corridor = _detached_binding_fixture()
    projected_binding = bind.bind_detached_dead_handler_component_claim(
        claim=claim, source_inventory=source,
        candidate_inventory=projected, corridor_result=projected_corridor,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
    )
    sealed = projected_binding.source_result
    values = (
        sealed.claim_id, sealed.corridor_forecast_id,
        sealed.corridor_coverage_result_id, sealed.source_fingerprint,
        sealed.source_generation, sealed.dispatcher_subject_id,
        sealed.dispatcher_block_ref, sealed.dead_handler_subject_ids,
        sealed.retained_handler_subject_ids, sealed.component_subject_ids,
        sealed.comparison_region_subject_ids,
        sealed.source_reachable_subject_ids, sealed.dead_handler_block_refs,
        sealed.retained_handler_block_refs, sealed.comparison_region_block_refs,
        sealed.terminal_digest, sealed.effect_digest, sealed.topology_digest,
        sealed.source_reachable_block_refs, sealed.component_block_refs,
        sealed.remainder_block_refs, (), sealed.effect_site_keys,
        sealed.source_blocks,
    )
    reissued = model.DetachedDeadHandlerComponentSourceResult(
        authority_id((
            "unflatten.detached-dead-handler-component-source.v2", *values,
        )),
        *values,
    )
    _, _, observed, observed_corridor = _detached_binding_fixture(
        candidate_phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        candidate_fingerprint=authority_id("detached-reissued-observed"),
        candidate_generation=5,
    )
    with pytest.raises(ValueError, match="not minted by the transaction binder"):
        bind.bind_detached_dead_handler_component_claim(
            claim=claim, source_inventory=source,
            candidate_inventory=observed, corridor_result=observed_corridor,
            phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
            source_result=reissued,
        )


def test_detached_binding_rejects_reissued_phase_result_at_observed_coordinates() -> None:
    """A forged observed acceptance cannot override the binder's rejected partition."""

    claim, source, projected, projected_corridor = _detached_binding_fixture()
    projected_binding = bind.bind_detached_dead_handler_component_claim(
        claim=claim,
        source_inventory=source,
        candidate_inventory=projected,
        corridor_result=projected_corridor,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
    )
    observed_successors = {
        0: (2, 4), 1: (2, 4, 7), 2: (3,), 3: (4,),
        4: (5,), 5: (6,), 6: (), 7: (1,),
    }
    _, _, observed, observed_corridor = _detached_binding_fixture(
        candidate_phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        candidate_fingerprint=authority_id("detached-reissued-phase-observed"),
        candidate_generation=5,
        candidate_successors=observed_successors,
    )
    values = (
        claim.claim_id,
        model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        observed_corridor.result_id,
        source.graph_fingerprint,
        observed.graph_fingerprint,
        source.generation,
        observed.generation,
        True,
        projected_binding.source_result.result_id,
    )
    reissued = model.DetachedDeadHandlerComponentPhaseResult(
        authority_id((
            "unflatten.detached-dead-handler-component-phase.v1", *values,
        )),
        *values,
    )

    with pytest.raises(
        ValueError,
        match="detached dead-handler partition remains candidate-reachable",
    ):
        bind.bind_detached_dead_handler_component_claim(
            claim=claim,
            source_inventory=source,
            candidate_inventory=observed,
            corridor_result=observed_corridor,
            phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
            source_result=projected_binding.source_result,
        )

    with pytest.raises(ValueError, match="not minted by the transaction binder"):
        bind.DetachedDeadHandlerComponentBindingResult(
            projected_binding.source_result,
            reissued,
        )


def test_detached_stable_site_keys_do_not_drop_generated_reachable_owners() -> None:
    """Defense in depth; nominal candidate inventories reject these sites below."""
    effect = model.InventoryEffectSite(
        8, None, 0x2080, 0, 0x2080, model.EffectSiteKind.CALL, 0, 1,
    )
    terminal = model.InventoryTerminalSite(
        9, None, 0x2090, None, 0x2090, model.TerminalKind.STOP,
    )
    inventory = SimpleNamespace(
        reachable_serials=(8, 9), effects=(effect,), terminals=(terminal,),
    )
    assert bind._stable_effect_keys(inventory) == (
        (("generated", 8, 0x2080), 0x2080, model.EffectSiteKind.CALL),
    )
    assert bind._stable_terminal_keys(inventory) == (
        (("generated", 9, 0x2090), 0x2090, model.TerminalKind.STOP),
    )


def test_candidate_inventory_rejects_unmapped_generated_reachable_call_site() -> None:
    """The inventory boundary forbids the nominal generated-CALL case.

    Candidate semantic sites must have typed subjects, and those subjects require
    stable CFG references.  Therefore an unmapped reachable CALL cannot reach
    detached binding; the generated-key helper remains defense in depth.
    """

    _claim, _source, candidate, _corridor = _detached_binding_fixture()
    target = next(block for block in candidate.blocks if block.serial == 5)
    call = model.InventoryInstructionObservation(
        0, target.anchor_ea, 0, 1, model.InsnKind.CALL, None, True, None,
    )
    blocks = tuple(
        replace(
            block,
            block_ref=None,
            instruction_observations=(call,),
        ) if block.serial == target.serial else block
        for block in candidate.blocks
    )
    effects = tuple(sorted(
        (
            effect
            for block in blocks
            for effect in model.resolve_inventory_block_sites(
                serial=block.serial,
                owner_ref=block.block_ref,
                owner_anchor_ea=block.anchor_ea or 0,
                block_kind=block.block_kind,
                successor_serials=block.successor_serials,
                instruction_observations=block.instruction_observations,
            )[0]
        ),
        key=lambda item: (
            item.owner_serial, item.instruction_ordinal,
            item.instruction_ea, item.effect_kind.value,
        ),
    ))
    terminals = tuple(sorted(
        (
            terminal
            for block in blocks
            for terminal in model.resolve_inventory_block_sites(
                serial=block.serial,
                owner_ref=block.block_ref,
                owner_anchor_ea=block.anchor_ea or 0,
                block_kind=block.block_kind,
                successor_serials=block.successor_serials,
                instruction_observations=block.instruction_observations,
            )[1]
        ),
        key=lambda item: (
            item.owner_serial, item.instruction_ordinal is None,
            item.instruction_ordinal if item.instruction_ordinal is not None else -1,
            item.instruction_ea, item.terminal_kind.value,
        ),
    ))
    digest = semantic_graph_inventory_digest(
        candidate.phase, candidate.graph_fingerprint, candidate.generation,
        blocks, candidate.subjects, candidate.bindings, effects, terminals,
        candidate.topology, candidate.reachable_serials, candidate.entry_serial,
        candidate.source_subject_ids, candidate.function_ea,
    )
    with pytest.raises(ValueError, match="candidate reachable effects are missing subjects"):
        model.SemanticGraphInventory(
            candidate.phase, candidate.graph_fingerprint, candidate.generation,
            blocks, candidate.subjects, candidate.bindings, effects, terminals,
            candidate.topology, digest, candidate.reachable_serials,
            candidate.entry_serial, candidate.source_subject_ids,
            candidate.function_ea,
        )


def test_bind_subjects_requires_exact_catalog_identity_and_generation() -> None:
    proposal, catalog = _fixture()
    subjects = (
        proposal.plan_inputs.authoritative_handlers[0],
    )
    subject = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.HANDLER,
        role=model.SemanticSubjectRole.AUTHORITATIVE_HANDLER,
        block_ref=subjects[0].block_ref,
        anchor_ea=subjects[0].anchor_ea,
        locator=model.HandlerSubjectLocator(
            subjects[0].block_ref, subjects[0].anchor_ea, subjects[0].normalized_states,
        ),
    )
    serials = {item.block_ref: index for index, item in enumerate(catalog.blocks)}
    bound = bind.bind_subjects(
        (subject,), catalog=catalog,
        phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
        graph_fingerprint=authority_id("source"), generation=catalog.generation,
        serial_by_ref=serials,
    )
    assert bound[0].status is model.SubjectBindingStatus.UNIQUE
    assert bound[0].serial == serials[subject.block_ref]

    with pytest.raises(ValueError, match="generation"):
        bind.bind_subjects(
            (subject,), catalog=catalog,
            phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
            graph_fingerprint=authority_id("source"), generation=catalog.generation + 1,
            serial_by_ref=serials,
        )


def test_bind_subjects_rejects_near_match_anchor_and_foreign_serial_rows() -> None:
    proposal, catalog = _fixture()
    handler = proposal.plan_inputs.authoritative_handlers[0]
    locator = model.HandlerSubjectLocator(
        handler.block_ref, handler.anchor_ea, handler.normalized_states,
    )
    subject = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.HANDLER,
        role=model.SemanticSubjectRole.AUTHORITATIVE_HANDLER,
        block_ref=handler.block_ref,
        anchor_ea=handler.anchor_ea,
        locator=locator,
    )
    serials = {item.block_ref: index for index, item in enumerate(catalog.blocks)}
    with pytest.raises(ValueError, match="serial binding"):
        bind.bind_subjects(
            (subject,), catalog=catalog,
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            graph_fingerprint=authority_id("candidate"), generation=catalog.generation,
            serial_by_ref={**serials, block_ref("foreign"): 99},
        )
    near_locator = model.HandlerSubjectLocator(
        handler.block_ref, handler.anchor_ea + 1, handler.normalized_states,
    )
    subject = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.HANDLER,
        role=model.SemanticSubjectRole.AUTHORITATIVE_HANDLER,
        block_ref=handler.block_ref,
        anchor_ea=handler.anchor_ea + 1,
        locator=near_locator,
    )
    with pytest.raises(ValueError, match="near-match"):
        bind.bind_subjects(
            (subject,), catalog=catalog,
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            graph_fingerprint=authority_id("candidate"), generation=catalog.generation,
            serial_by_ref=serials,
        )


def test_source_effect_is_unique_but_projected_effect_is_exactly_missing() -> None:
    _proposal, catalog = _fixture()
    b1 = next(item.block_ref for item in catalog.blocks if item.anchor_ea == 0x1300)
    effect = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.EFFECT,
        role=model.SemanticSubjectRole.EFFECT_SITE,
        block_ref=b1,
        anchor_ea=0x1300,
        locator=model.EffectSubjectLocator(
            b1, 0x1300, 0x1300, model.EffectSiteKind.STORE,
        ),
    )
    serials = {item.block_ref: index for index, item in enumerate(catalog.blocks)}
    source = bind.bind_source_subjects(
        (effect,), catalog=catalog,
        phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
        graph_fingerprint=authority_id("source"), generation=catalog.generation,
        serial_by_ref=serials,
    )
    projected = bind.bind_projected_subjects(
        (effect,), catalog=catalog,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        graph_fingerprint=authority_id("candidate"), generation=catalog.generation,
        serial_by_ref={ref: serial for ref, serial in serials.items() if ref != b1},
    )
    assert source[0].status is model.SubjectBindingStatus.UNIQUE
    assert source[0].serial == serials[b1]
    assert projected[0].status is model.SubjectBindingStatus.MISSING
    assert projected[0].serial is None

    with pytest.raises(ValueError, match="native-origin binding"):
        bind.bind_subjects(
            (effect,), catalog=catalog,
            phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
            graph_fingerprint=authority_id("source"), generation=catalog.generation,
            serial_by_ref=serials,
            native_instruction_eas_by_ref={},
        )
    with pytest.raises(ValueError, match="every projected reference"):
        bind.bind_projected_subjects(
            (effect,), catalog=catalog,
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            graph_fingerprint=authority_id("candidate"), generation=catalog.generation,
            serial_by_ref={ref: serial for ref, serial in serials.items() if ref != b1},
            native_instruction_eas_by_ref={},
        )


def test_inventory_binding_requires_exact_reachable_site_not_surviving_owner() -> None:
    _proposal, catalog = _fixture()
    owner = next(item for item in catalog.blocks if item.anchor_ea == 0x1300)
    effect = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.EFFECT,
        role=model.SemanticSubjectRole.EFFECT_SITE,
        block_ref=owner.block_ref,
        anchor_ea=owner.anchor_ea,
        locator=model.EffectSubjectLocator(
            owner.block_ref, owner.anchor_ea, 0x1300, model.EffectSiteKind.STORE,
        ),
    )
    terminal = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.TERMINAL,
        role=model.SemanticSubjectRole.TERMINAL_SITE,
        block_ref=owner.block_ref,
        anchor_ea=owner.anchor_ea,
        locator=model.TerminalSubjectLocator(
            owner.block_ref, owner.anchor_ea, model.TerminalKind.RETURN, 0x1300,
        ),
    )
    serials = {item.block_ref: index for index, item in enumerate(catalog.blocks)}
    effect_row = model.InventoryEffectSite(
        1, owner.block_ref, owner.anchor_ea, 0, 0x1300,
        model.EffectSiteKind.STORE, 0x90, 4,
    )
    terminal_row = model.InventoryTerminalSite(
        1, owner.block_ref, owner.anchor_ea, 0, 0x1300,
        model.TerminalKind.RETURN,
    )
    absent = bind.bind_inventory_subjects(
        (effect, terminal), catalog=catalog,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        graph_fingerprint=authority_id("candidate-sites-missing"),
        generation=catalog.generation, serial_by_ref=serials,
        effects=(), terminals=(), reachable_serials=(1,),
    )
    assert {item.status for item in absent} == {model.SubjectBindingStatus.MISSING}
    present = bind.bind_inventory_subjects(
        (effect, terminal), catalog=catalog,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        graph_fingerprint=authority_id("candidate-sites-present"),
        generation=catalog.generation, serial_by_ref=serials,
        effects=(effect_row,), terminals=(terminal_row,), reachable_serials=(1,),
    )
    assert all(item.status is model.SubjectBindingStatus.UNIQUE for item in present)


def test_inventory_site_family_swaps_are_typed_rejections() -> None:
    _proposal, catalog = _fixture()
    owner = next(item for item in catalog.blocks if item.anchor_ea == 0x1300)
    serials = {item.block_ref: index for index, item in enumerate(catalog.blocks)}
    subject = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.EFFECT,
        role=model.SemanticSubjectRole.EFFECT_SITE,
        block_ref=owner.block_ref, anchor_ea=owner.anchor_ea,
        locator=model.EffectSubjectLocator(
            owner.block_ref, owner.anchor_ea, 0x1300, model.EffectSiteKind.STORE,
        ),
    )
    effect = model.InventoryEffectSite(
        serials[owner.block_ref], owner.block_ref, owner.anchor_ea,
        0, 0x1300, model.EffectSiteKind.STORE, 0x90, 4,
    )
    terminal = model.InventoryTerminalSite(
        serials[owner.block_ref], owner.block_ref, owner.anchor_ea,
        0, 0x1300, model.TerminalKind.RETURN,
    )
    base = bind.bind_projected_subjects(
        (subject,), catalog=catalog,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        graph_fingerprint=authority_id("family-swap"), generation=catalog.generation,
        serial_by_ref=serials,
    )[0]
    with pytest.raises(TypeError, match="effects"):
        model.resolve_inventory_site_binding(
            subject, base, effects=(terminal,), terminals=(effect,),
            reachable_serials=(serials[owner.block_ref],), serial_by_ref=serials,
        )
    with pytest.raises(TypeError, match="effects"):
        bind.bind_inventory_subjects(
            (subject,), catalog=catalog,
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            graph_fingerprint=authority_id("family-swap-binder"),
            generation=catalog.generation, serial_by_ref=serials,
            effects=(terminal,), terminals=(effect,),
            reachable_serials=(serials[owner.block_ref],),
        )


def test_retirement_binding_requires_retained_members_and_seals_post_bind_mutation() -> None:
    from d810.transforms.unflatten_authority import transaction_api
    from d810.transforms.unflatten_authority.bind import validate_retired_infrastructure_binding_result

    proposal, claim, source_inventory, projected_inventory = _retirement_inventories()
    result = bind.bind_retired_dispatcher_infrastructure_claim(
        claim=claim, proposal=proposal,
        source_inventory=source_inventory,
        projected_inventory=projected_inventory,
    )
    retained = next(
        item for item in result.projected_bindings
        if item.subject.block_ref == claim.retirement_catalog.members[0].block_ref
    )
    assert retained.status is model.SubjectBindingStatus.UNIQUE
    assert not hasattr(result, "candidate_reachable_serials")
    object.__setattr__(result, "generation", source_inventory.generation + 1)
    with pytest.raises(ValueError, match="content seal|generation"):
        validate_retired_infrastructure_binding_result(result)


def test_retirement_binding_accepts_physically_present_but_unreachable_retired_member() -> None:
    """Retirement is a reachability fact, even when the block remains indexed."""

    proposal, claim, source_inventory, projected_inventory = _retirement_inventories(
        physically_present_retired=True,
    )
    retired_ref = claim.retirement_catalog.members[1].block_ref
    retained_ref = claim.retirement_catalog.members[0].block_ref
    result = bind.bind_retired_dispatcher_infrastructure_claim(
        claim=claim, proposal=proposal,
        source_inventory=source_inventory,
        projected_inventory=projected_inventory,
    )

    retired = next(item for item in result.projected_bindings if item.subject.block_ref == retired_ref)
    retained = next(item for item in result.projected_bindings if item.subject.block_ref == retained_ref)
    assert retired.status is model.SubjectBindingStatus.UNIQUE
    assert retired.serial == 6
    assert retained.status is model.SubjectBindingStatus.UNIQUE
    assert retained.serial == 5
    assert projected_inventory.reachable_serials == (0, 1, 2, 3, 4, 5)


def test_retirement_binding_rejects_naked_caller_reachability_authority() -> None:
    """Reachability must come from a closed projected inventory, not a tuple."""

    base = model.ProposedUnflattenContract(**_valid_proposal(model))
    refs = {index: item.block_ref for index, item in enumerate(base.source_identity_catalog.blocks)}
    from d810.transforms.unflatten_authority.legacy_codec import retirement_claim_from_legacy_proof

    claim = retirement_claim_from_legacy_proof(
        {"retired_infrastructure": (
            {"role": "comparison_dispatcher", "anchor": {"serial": 0, "ea": 0x1000}, "retired": True},
            {"role": "comparison_dispatcher", "anchor": {"serial": 1, "ea": 0x1300}, "retired": False},
        )},
        proposal=base, block_refs_by_serial=refs,
    )
    proposal = replace(
        base,
        claims=(claim,),
        plan_inputs=replace(base.plan_inputs, shape=model.UnflattenPlanShape.PARTIAL_REWRITE),
        retirement_catalog=claim.retirement_catalog,
        corridor_coverage_forecast=_minimal_corridor_forecast(model, base),
    )
    with pytest.raises(TypeError):
        bind.bind_retired_dispatcher_infrastructure_claim(
            claim=claim,
            proposal=proposal,
            source_serial_by_ref={item.block_ref: index for index, item in enumerate(base.source_identity_catalog.blocks)},
            projected_serial_by_ref={claim.retirement_catalog.members[1].block_ref: 0},
            candidate_reachable_serials=(0,),
            source_graph_fingerprint=authority_id("naked-reachability-source"),
            projected_graph_fingerprint=authority_id("naked-reachability-projector"),
            generation=base.source_identity_catalog.generation,
        )


def test_retirement_binding_observed_phase_validates_exact_source_and_candidate_rows() -> None:
    """Observed rebinding accepts only the exact catalog-correlated rows."""

    proposal, claim, source_inventory, observed_inventory = _retirement_inventories(
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
    )
    result = bind.bind_retired_dispatcher_infrastructure_claim(
        claim=claim,
        proposal=proposal,
        source_inventory=source_inventory,
        projected_inventory=observed_inventory,
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
    )
    assert result.projected_inventory is observed_inventory
    assert all(
        row.phase is model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY
        for row in result.projected_bindings
    )
    object.__setattr__(observed_inventory, "reachable_serials", ())
    with pytest.raises(ValueError):
        bind.validate_retired_infrastructure_binding_result(result)
    return

@pytest.mark.parametrize("site_kind", (model.EffectSiteKind.STORE, model.TerminalKind.RETURN))
def test_inventory_binding_rejects_site_rows_outside_owned_native_origins(site_kind: object) -> None:
    _proposal, catalog = _fixture()
    owner = next(item for item in catalog.blocks if item.anchor_ea == 0x1300)
    serials = {item.block_ref: index for index, item in enumerate(catalog.blocks)}
    site_ea = 0x1304 if site_kind is model.EffectSiteKind.STORE else 0x1308
    if site_kind is model.EffectSiteKind.STORE:
        subject = _subject_factory(
            model.SemanticSubjectRef,
            kind=model.SemanticSubjectKind.EFFECT,
            role=model.SemanticSubjectRole.EFFECT_SITE,
            block_ref=owner.block_ref, anchor_ea=owner.anchor_ea,
            locator=model.EffectSubjectLocator(
                owner.block_ref, owner.anchor_ea, site_ea, site_kind,
            ),
        )
        effects = (model.InventoryEffectSite(
            serials[owner.block_ref], owner.block_ref, owner.anchor_ea,
            1, site_ea, site_kind, 0x90, 4,
        ),)
        terminals = ()
    else:
        subject = _subject_factory(
            model.SemanticSubjectRef,
            kind=model.SemanticSubjectKind.TERMINAL,
            role=model.SemanticSubjectRole.TERMINAL_SITE,
            block_ref=owner.block_ref, anchor_ea=owner.anchor_ea,
            locator=model.TerminalSubjectLocator(
                owner.block_ref, owner.anchor_ea, site_kind, site_ea,
            ),
        )
        effects = ()
        terminals = (model.InventoryTerminalSite(
            serials[owner.block_ref], owner.block_ref, owner.anchor_ea,
            1, site_ea, site_kind,
        ),)
    with pytest.raises(ValueError, match="site binding owner"):
        bind.bind_inventory_subjects(
            (subject,), catalog=catalog,
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            graph_fingerprint=authority_id("candidate-site-origin-gap"),
            generation=catalog.generation, serial_by_ref=serials,
            effects=effects, terminals=terminals,
            reachable_serials=(serials[owner.block_ref],),
        )


def test_inventory_binding_rejects_noncanonical_rows_and_owner_corruption() -> None:
    from dataclasses import replace
    from types import SimpleNamespace

    _proposal, catalog = _fixture()
    owner = next(item for item in catalog.blocks if item.anchor_ea == 0x1300)
    effect = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.EFFECT,
        role=model.SemanticSubjectRole.EFFECT_SITE,
        block_ref=owner.block_ref, anchor_ea=owner.anchor_ea,
        locator=model.EffectSubjectLocator(
            owner.block_ref, owner.anchor_ea, 0x1304, model.EffectSiteKind.STORE,
        ),
    )
    serials = {item.block_ref: index for index, item in enumerate(catalog.blocks)}
    row = model.InventoryEffectSite(
        serials[owner.block_ref], owner.block_ref, owner.anchor_ea, 1, 0x1304,
        model.EffectSiteKind.STORE, 0x90, 4,
    )
    kwargs = dict(
        catalog=catalog,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        graph_fingerprint=authority_id("invalid-site-input"),
        generation=catalog.generation, serial_by_ref=serials,
        terminals=(), reachable_serials=(serials[owner.block_ref],),
    )
    with pytest.raises(TypeError):
        bind.bind_inventory_subjects(
            (effect,),
            effects=(SimpleNamespace(
                owner_serial=row.owner_serial, owner_ref=row.owner_ref,
                owner_anchor_ea=row.owner_anchor_ea,
                instruction_ordinal=row.instruction_ordinal,
                instruction_ea=row.instruction_ea,
                effect_kind=row.effect_kind, opcode=row.opcode, width=row.width,
            ),),
            **kwargs,
        )
    class EffectSubclass(model.InventoryEffectSite):
        pass
    with pytest.raises(TypeError):
        bind.bind_inventory_subjects(
            (effect,), effects=(EffectSubclass(
                row.owner_serial, row.owner_ref, row.owner_anchor_ea,
                row.instruction_ordinal, row.instruction_ea, row.effect_kind,
                row.opcode, row.width,
            ),), **kwargs,
        )
    with pytest.raises(ValueError, match="owner serial"):
        bind.bind_inventory_subjects(
            (effect,),
            effects=(replace(row, owner_serial=serials[owner.block_ref] + 1),),
            **{**kwargs, "reachable_serials": (serials[owner.block_ref], serials[owner.block_ref] + 1)},
        )
    with pytest.raises(ValueError, match="foreign"):
        bind.bind_inventory_subjects(
            (effect,), effects=(replace(row, owner_ref=block_ref("foreign")),), **kwargs,
        )
    with pytest.raises(ValueError, match="reachable"):
        bind.bind_inventory_subjects(
            (effect,), effects=(row,), terminals=(), reachable_serials=(99,),
            catalog=catalog,
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            graph_fingerprint=authority_id("unreachable-site"),
            generation=catalog.generation, serial_by_ref=serials,
        )


def test_exact_effect_facade_replays_source_and_projected_receipt() -> None:
    source, proposal, exclusion, refs = _exact_fixture()
    claim = proposal.claims[0]
    serial_by_ref = {ref: serial for serial, ref in refs.items()}
    result = bind.bind_exact_effect_claim(
        source=source, projected=source,
        source_block_refs_by_serial=refs,
        projected_serial_by_ref=serial_by_ref,
        exclusion=exclusion, claim=claim, proposal=proposal,
        generation=1,
    )
    assert all(item.status is model.SubjectBindingStatus.UNIQUE for item in result.source_bindings)
    assert all(item.status is model.SubjectBindingStatus.UNIQUE for item in result.projected_bindings)
    assert result.claim_id == claim.claim_id
    from d810.transforms.unflatten_authority.ids import semantic_graph_fingerprint
    assert result.source_graph_fingerprint == semantic_graph_fingerprint(source)
    assert result.projected_graph_fingerprint == semantic_graph_fingerprint(source)
    assert result.generation == proposal.source_identity_catalog.generation


def test_exact_effect_facade_accepts_optional_absent_route_owner() -> None:
    source, proposal, exclusion, refs = _exact_fixture(optional_owner=True)
    claim = proposal.claims[0]
    serial_by_ref = {ref: serial for serial, ref in refs.items()}
    result = bind.bind_exact_effect_claim(
        source=source, projected=source, source_block_refs_by_serial=refs,
        projected_serial_by_ref=serial_by_ref, exclusion=exclusion,
        claim=claim, proposal=proposal, generation=1,
    )
    assert result.claim == claim


def test_canonical_route_binding_requires_live_conditional_instruction() -> None:
    """A matching anchor is insufficient when the branch was normalized away."""
    from d810.analyses.control_flow.semantic_route_evidence import (
        bind_canonical_semantic_evidence,
    )
    from d810.ir.flowgraph import InsnKind, InsnSnapshot

    source, proposal, _exclusion, _refs = _exact_fixture()
    branch_block = source.blocks[1]
    nop_branch = InsnSnapshot(0, 0x2001, (), kind=InsnKind.NOP)
    mutated = source.__class__(
        {
            **source.blocks,
            1: branch_block.__class__(
                serial=branch_block.serial,
                block_type=branch_block.block_type,
                succs=branch_block.succs,
                preds=branch_block.preds,
                flags=branch_block.flags,
                start_ea=branch_block.start_ea,
                insn_snapshots=(branch_block.insn_snapshots[0], nop_branch),
                kind=branch_block.kind,
            ),
        },
        source.entry_serial,
        source.func_ea,
    )

    assert bind_canonical_semantic_evidence(mutated, proposal.route_evidence) is None


def test_canonical_route_binding_rejects_unpermitted_carrier_interference() -> None:
    """A carrier corridor cannot acquire an additional live writer."""
    from d810.analyses.control_flow.semantic_route_evidence import (
        bind_canonical_semantic_evidence,
    )
    from d810.ir.flowgraph import InsnKind, InsnSnapshot, MopSnapshot, OperandKind
    from d810.ir.expressions import ValueOpKind

    source, proposal, _exclusion, _refs = _exact_fixture()
    branch_block = source.blocks[1]
    foreign_writer = InsnSnapshot(
        0,
        0x2000,
        (),
        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=8),
        d=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=4, stack_refs=(4,)),
        kind=InsnKind.MOV,
        value_op_kind=ValueOpKind.MOVE,
    )
    mutated = source.__class__(
        {
            **source.blocks,
            1: branch_block.__class__(
                serial=branch_block.serial,
                block_type=branch_block.block_type,
                succs=branch_block.succs,
                preds=branch_block.preds,
                flags=branch_block.flags,
                start_ea=branch_block.start_ea,
                insn_snapshots=(foreign_writer, branch_block.insn_snapshots[1]),
                kind=branch_block.kind,
            ),
        },
        source.entry_serial,
        source.func_ea,
    )

    assert bind_canonical_semantic_evidence(mutated, proposal.route_evidence) is None


def test_canonical_route_binding_rejects_independent_predicate_interference() -> None:
    """Predicate storage writers are replayed independently of carriers."""
    from dataclasses import replace

    from d810.analyses.control_flow.semantic_route_evidence import (
        SemanticPredicateProof,
        bind_canonical_semantic_evidence,
    )
    from d810.ir.flowgraph import InsnKind, InsnSnapshot, MopSnapshot, OperandKind
    from d810.ir.expressions import ValueOpKind
    from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind

    source, proposal, _exclusion, _refs = _exact_fixture()
    route = proposal.route_evidence.route_proofs[0]
    predicate_storage = StorageIdentity(StorageIdentityKind.STACK, 8)
    predicate = SemanticPredicateProof(
        kind=route.predicate.kind,
        origin=route.predicate.origin,
        consumer=route.predicate.consumer,
        corridor=route.predicate.corridor,
        storage_identity=predicate_storage,
        width=4,
        compare_constant=7,
    )
    branch_block = source.blocks[1]
    predicate_writer = InsnSnapshot(
        0,
        0x2000,
        (),
        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=99),
        d=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=8, stack_refs=(8,)),
        kind=InsnKind.MOV,
        value_op_kind=ValueOpKind.MOVE,
    )
    branch = replace(
        branch_block.insn_snapshots[1],
        l=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=8, stack_refs=(8,)),
    )
    mutated = source.__class__(
        {
            **source.blocks,
            1: replace(branch_block, insn_snapshots=(predicate_writer, branch)),
        },
        source.entry_serial,
        source.func_ea,
    )
    evidence = replace(proposal.route_evidence, route_proofs=(replace(route, predicate=predicate),))

    assert bind_canonical_semantic_evidence(mutated, evidence) is None


@pytest.mark.parametrize("consumer_shape", ("nop", "storage", "width"))
def test_canonical_route_binding_requires_live_carrier_consumer(consumer_shape: str) -> None:
    from dataclasses import replace

    from d810.analyses.control_flow.semantic_route_evidence import bind_canonical_semantic_evidence
    from d810.ir.flowgraph import InsnKind, InsnSnapshot, MopSnapshot, OperandKind
    from d810.ir.expressions import ValueOpKind

    source, proposal, _exclusion, _refs = _exact_fixture()
    block = source.blocks[1]
    if consumer_shape == "nop":
        consumer = InsnSnapshot(0, 0x2001, (), kind=InsnKind.NOP)
    else:
        width = 8 if consumer_shape == "width" else 4
        storage = 8 if consumer_shape == "storage" else 4
        consumer = InsnSnapshot(
            0,
            0x2001,
            (),
            r=MopSnapshot(kind=OperandKind.STACK, size=width, stkoff=storage, stack_refs=(storage,)),
            d=MopSnapshot(kind=OperandKind.REGISTER, size=width, reg=0),
            kind=InsnKind.LOAD,
            value_op_kind=ValueOpKind.LOAD,
        )
    mutated = source.__class__(
        {**source.blocks, 1: replace(block, insn_snapshots=(block.insn_snapshots[0], consumer))},
        source.entry_serial,
        source.func_ea,
    )

    assert bind_canonical_semantic_evidence(mutated, proposal.route_evidence) is None


def test_canonical_route_binding_accepts_extra_target_predecessor() -> None:
    """A valid reciprocal edge need not be the target's only predecessor."""
    from dataclasses import replace

    from d810.analyses.control_flow.semantic_route_evidence import (
        BoundCanonicalSemanticEvidence,
        bind_canonical_semantic_evidence,
    )

    source, proposal, _exclusion, _refs = _exact_fixture()
    target = source.blocks[2]
    mutated = source.__class__(
        {**source.blocks, 2: replace(target, preds=(1, 4))},
        source.entry_serial,
        source.func_ea,
    )

    assert isinstance(
        bind_canonical_semantic_evidence(mutated, proposal.route_evidence),
        BoundCanonicalSemanticEvidence,
    )


def test_canonical_route_binding_rejects_duplicate_carrier_writer_ea() -> None:
    """Ambiguous duplicate EAs cannot be skipped during write replay."""
    from dataclasses import replace

    from d810.analyses.control_flow.semantic_route_evidence import bind_canonical_semantic_evidence
    from d810.ir.flowgraph import InsnKind, InsnSnapshot, MopSnapshot, OperandKind
    from d810.ir.expressions import ValueOpKind

    source, proposal, _exclusion, _refs = _exact_fixture()
    branch_block = source.blocks[1]
    duplicate = InsnSnapshot(
        0,
        0x2000,
        (),
        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=99),
        d=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=4, stack_refs=(4,)),
        kind=InsnKind.MOV,
        value_op_kind=ValueOpKind.MOVE,
    )
    mutated = source.__class__(
        {
            **source.blocks,
            1: replace(
                branch_block,
                insn_snapshots=(branch_block.insn_snapshots[0], duplicate, branch_block.insn_snapshots[1]),
            ),
        },
        source.entry_serial,
        source.func_ea,
    )

    assert bind_canonical_semantic_evidence(mutated, proposal.route_evidence) is None


def test_canonical_route_binding_rejects_frankenstein_origin_branch() -> None:
    """An origin branch cannot be spliced onto a source with no live branch."""
    from dataclasses import replace

    from d810.analyses.control_flow.semantic_route_evidence import (
        SemanticCorridorPoint,
        bind_canonical_semantic_evidence,
    )
    from d810.ir.flowgraph import InsnKind, InsnSnapshot, MopSnapshot, OperandKind
    from d810.ir.semantics import PredicateKind

    source, proposal, _exclusion, refs = _exact_fixture()
    route = proposal.route_evidence.route_proofs[0]
    origin = SemanticCorridorPoint(refs[0].identity, 0x1001)
    predicate = replace(
        route.predicate,
        origin=origin,
        corridor=(origin, route.predicate.consumer),
    )
    origin_branch = InsnSnapshot(
        0,
        0x1001,
        (),
        l=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=4, stack_refs=(4,)),
        r=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=7),
        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=2),
        kind=InsnKind.COND_JUMP,
        branch_predicate=PredicateKind.EQ,
        is_conditional_jump=True,
    )
    mutated = source.__class__(
        {
            **source.blocks,
            0: replace(source.blocks[0], insn_snapshots=(source.blocks[0].insn_snapshots[0], origin_branch)),
            1: replace(source.blocks[1], insn_snapshots=(source.blocks[1].insn_snapshots[0], InsnSnapshot(0, 0x2001, (), kind=InsnKind.NOP))),
        },
        source.entry_serial,
        source.func_ea,
    )
    evidence = replace(proposal.route_evidence, route_proofs=(replace(route, predicate=predicate),))

    assert bind_canonical_semantic_evidence(mutated, evidence) is None


def test_canonical_route_binding_accepts_exact_and_ownerless_routes() -> None:
    from d810.analyses.control_flow.semantic_route_evidence import (
        BoundCanonicalSemanticEvidence,
        bind_canonical_semantic_evidence,
    )

    for optional_owner in (False, True):
        source, proposal, _exclusion, _refs = _exact_fixture(
            optional_owner=optional_owner,
        )
        bound = bind_canonical_semantic_evidence(source, proposal.route_evidence)
        assert isinstance(bound, BoundCanonicalSemanticEvidence)
        assert len(bound.routes) == 1
        assert bound.routes[0].predicate is not None


def test_canonical_route_binding_accepts_normalized_ne_polarity() -> None:
    from dataclasses import replace

    from d810.analyses.control_flow.semantic_route_evidence import (
        BoundCanonicalSemanticEvidence,
        bind_canonical_semantic_evidence,
    )
    from d810.ir.flowgraph import MopSnapshot, OperandKind, PredicateKind

    source, proposal, _exclusion, _refs = _exact_fixture()
    branch_block = source.blocks[1]
    branch = replace(
        branch_block.insn_snapshots[1],
        branch_predicate=PredicateKind.NE,
        predicate_kind=PredicateKind.NE,
        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=3),
    )
    source = source.__class__(
        {
            **source.blocks,
            1: replace(
                branch_block,
                insn_snapshots=(branch_block.insn_snapshots[0], branch),
            ),
        },
        source.entry_serial,
        source.func_ea,
    )
    bound = bind_canonical_semantic_evidence(source, proposal.route_evidence)
    assert isinstance(bound, BoundCanonicalSemanticEvidence)


def test_canonical_route_binding_accepts_independent_compare_and_state_values() -> None:
    """The branch literal is not required to equal a destination state."""
    from dataclasses import replace

    from d810.analyses.control_flow.semantic_route_evidence import (
        BoundCanonicalSemanticEvidence,
        bind_canonical_semantic_evidence,
    )
    from d810.ir.flowgraph import MopSnapshot, OperandKind

    source, proposal, _exclusion, _refs = _exact_fixture()
    route = proposal.route_evidence.route_proofs[0]
    branch_block = source.blocks[1]
    branch = replace(
        branch_block.insn_snapshots[1],
        r=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=0),
    )
    source = source.__class__(
        {
            **source.blocks,
            1: replace(branch_block, insn_snapshots=(branch_block.insn_snapshots[0], branch)),
        },
        source.entry_serial,
        source.func_ea,
    )
    evidence = replace(
        proposal.route_evidence,
        route_proofs=(replace(route, predicate=replace(route.predicate, compare_constant=0)),),
    )

    bound = bind_canonical_semantic_evidence(source, evidence)
    assert isinstance(bound, BoundCanonicalSemanticEvidence)


@pytest.mark.parametrize(
    "mutation",
    (
        "predicate",
        "storage",
        "width",
        "constant",
        "target",
        "role",
        "topology",
        "predicate_ea",
        "state_write_ea",
    ),
)
def test_canonical_route_binding_rejects_adversarial_live_semantics(mutation) -> None:
    from dataclasses import replace

    from d810.analyses.control_flow.semantic_route_evidence import (
        bind_canonical_semantic_evidence,
    )
    from d810.ir.flowgraph import MopSnapshot, OperandKind, PredicateKind

    source, proposal, _exclusion, _refs = _exact_fixture()
    route = proposal.route_evidence.route_proofs[0]
    branch = source.blocks[1].insn_snapshots[1]
    if mutation == "predicate":
        branch = replace(
            branch,
            branch_predicate=PredicateKind.NE,
            predicate_kind=PredicateKind.NE,
        )
    elif mutation == "storage":
        branch = replace(
            branch,
            l=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=8, stack_refs=(8,)),
        )
    elif mutation == "width":
        branch = replace(
            branch,
            l=MopSnapshot(kind=OperandKind.STACK, size=8, stkoff=4, stack_refs=(4,)),
            r=MopSnapshot(kind=OperandKind.NUMBER, size=8, value=7),
        )
    elif mutation == "constant":
        branch = replace(
            branch,
            r=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=8),
        )
    elif mutation == "target":
        branch = replace(
            branch,
            d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=3),
        )
    elif mutation == "role":
        route = replace(
            route,
            destinations=(
                replace(
                    route.destinations[0],
                    role=route.destinations[1].role,
                ),
                replace(
                    route.destinations[1],
                    role=route.destinations[0].role,
                ),
            ),
        )
    elif mutation == "topology":
        block = source.blocks[0]
        source = source.__class__(
            {
                **source.blocks,
                0: replace(block, succs=()),
            },
            source.entry_serial,
            source.func_ea,
        )
    elif mutation == "predicate_ea":
        branch = replace(
            branch,
            ea=0x2002,
        )
    elif mutation == "state_write_ea":
        route = replace(
            route,
            state_write=replace(
                route.state_write,
                instruction_ea=0x1001,
                corridor_instruction_eas=(0x1001, 0x2000),
            ),
        )
    if mutation in {"predicate", "storage", "width", "constant", "target", "predicate_ea"}:
        block = source.blocks[1]
        source = source.__class__(
            {
                **source.blocks,
                1: replace(block, insn_snapshots=(block.insn_snapshots[0], branch)),
            },
            source.entry_serial,
            source.func_ea,
        )
    evidence = replace(proposal.route_evidence, route_proofs=(route,))

    assert bind_canonical_semantic_evidence(source, evidence) is None


def test_exact_effect_facade_allows_unrelated_projected_catalog_omission() -> None:
    source, proposal, exclusion, refs = _exact_fixture()
    claim = proposal.claims[0]
    projected = source.__class__(
        {serial: block for serial, block in source.blocks.items() if serial != 4},
        source.entry_serial,
        source.func_ea,
    )
    serial_by_ref = {ref: serial for serial, ref in refs.items() if serial != 4}
    result = bind.bind_exact_effect_claim(
        source=source,
        projected=projected,
        source_block_refs_by_serial=refs,
        projected_serial_by_ref=serial_by_ref,
        exclusion=exclusion,
        claim=claim,
        proposal=proposal,
        generation=1,
    )
    claim_refs = {
        subject.block_ref
        for subject in (
            claim.source_subject,
            claim.predicate_subject,
            claim.selected_target_subject,
            claim.discarded_effect_subject,
        )
    }
    assert {ref for ref, _serial in result.source_serial_rows} == claim_refs
    assert {ref for ref, _serial in result.projected_serial_rows} == claim_refs
    assert all(item.status is model.SubjectBindingStatus.UNIQUE for item in result.projected_bindings)


def test_exact_effect_facade_rejects_topology_ingress_and_claim_near_matches() -> None:
    source, proposal, exclusion, refs = _exact_fixture()
    claim = proposal.claims[0]
    serial_by_ref = {ref: serial for serial, ref in refs.items()}
    kwargs = dict(source=source, projected=source, source_block_refs_by_serial=refs,
                  projected_serial_by_ref=serial_by_ref, exclusion=exclusion,
                  claim=claim, proposal=proposal, generation=1)
    from dataclasses import replace
    with pytest.raises(ValueError, match="canonical producer|claim"):
        bind.bind_exact_effect_claim(**{**kwargs, "claim": replace(claim, width=8)})
    with pytest.raises(ValueError, match="projected block identity"):
        bind.bind_exact_effect_claim(**{**kwargs, "projected_serial_by_ref": {
            **serial_by_ref, next(iter(serial_by_ref)): 99,
        }})
    with pytest.raises(ValueError, match="topology"):
        bind.bind_exact_effect_claim(**{**kwargs, "exclusion": replace(
            exclusion, selected_target_serial=exclusion.discarded_effect_serial,
        )})
    with pytest.raises(TypeError):
        bind.bind_exact_effect_claim(**kwargs, source_graph_fingerprint="sha256:" + "0" * 64)


def test_exact_effect_facade_rejects_graph_mutation_and_noncanonical_ref_rows() -> None:
    source, proposal, exclusion, refs = _exact_fixture()
    claim = proposal.claims[0]
    serial_by_ref = {ref: serial for serial, ref in refs.items()}
    kwargs = dict(source=source, projected=source, source_block_refs_by_serial=refs,
                  projected_serial_by_ref=serial_by_ref, exclusion=exclusion,
                  claim=claim, proposal=proposal, generation=1)
    from dataclasses import replace
    mutated = replace(
        source,
        blocks={
            **source.blocks,
            exclusion.discarded_effect_serial: replace(
                source.blocks[exclusion.discarded_effect_serial],
                native_start_ea=0x4001,
            ),
        },
    )
    with pytest.raises(ValueError):
        bind.bind_exact_effect_claim(**{**kwargs, "projected": mutated})
    with pytest.raises(ValueError, match="non-canonical row"):
        bind.bind_exact_effect_claim(**{**kwargs, "source_block_refs_by_serial": {
            **refs, 0.9: refs[0],
        }})
    with pytest.raises(ValueError, match="non-canonical row"):
        bind.bind_exact_effect_claim(**{**kwargs, "projected_serial_by_ref": {
            ref: (0.0 if serial == 0 else serial)
            for ref, serial in serial_by_ref.items()
        }})


def test_exact_effect_binding_result_constructor_rejects_half_bound_records() -> None:
    with pytest.raises(TypeError, match="minted by bind_exact_effect_claim"):
        bind.ExactEffectBindingResult()
    with pytest.raises(TypeError, match="minted by bind_exact_effect_claim"):
        bind.ExactEffectBindingResult(
            model.ExactInfeasibleEffectClaim, None, None, None, (), (), (), (),
            authority_id("source"), authority_id("projected"), 1,
        )


def test_exact_effect_binding_registry_does_not_retain_results() -> None:
    import gc
    import weakref

    source, proposal, exclusion, refs = _exact_fixture()
    claim = proposal.claims[0]
    serial_by_ref = {ref: serial for serial, ref in refs.items()}
    registry = next(
        cell.cell_contents
        for cell in bind.validate_exact_effect_binding_result.__closure__ or ()
        if type(cell.cell_contents) is dict
    )
    before = len(registry)
    result = bind.bind_exact_effect_claim(
        source=source, projected=source, source_block_refs_by_serial=refs,
        projected_serial_by_ref=serial_by_ref, exclusion=exclusion,
        claim=claim, proposal=proposal, generation=1,
    )
    assert len(registry) == before + 1
    reference = weakref.ref(result)
    del result
    gc.collect()
    assert reference() is None
    assert len(registry) == before


def test_exact_effect_binding_result_revalidates_mutated_bindings_and_digests() -> None:
    source, proposal, exclusion, refs = _exact_fixture()
    claim = proposal.claims[0]
    serial_by_ref = {ref: serial for serial, ref in refs.items()}
    result = bind.bind_exact_effect_claim(
        source=source, projected=source, source_block_refs_by_serial=refs,
        projected_serial_by_ref=serial_by_ref, exclusion=exclusion,
        claim=claim, proposal=proposal, generation=1,
    )
    original_fingerprint = result.source_graph_fingerprint
    object.__setattr__(result, "source_graph_fingerprint", "sha256:x")
    with pytest.raises(ValueError, match="content seal"):
        bind.validate_exact_effect_binding_result(result)
    object.__setattr__(result, "source_graph_fingerprint", original_fingerprint)
    bind.validate_exact_effect_binding_result(result)
    original_seal = result._content_seal
    object.__setattr__(result, "_content_seal", "sha256:" + "0" * 64)
    with pytest.raises(ValueError, match="content seal"):
        bind.validate_exact_effect_binding_result(result)
    object.__setattr__(result, "_content_seal", original_seal)
    bind.validate_exact_effect_binding_result(result)
    with pytest.raises(TypeError, match="minted by bind_exact_effect_claim"):
        bind.ExactEffectBindingResult(
            result.claim, result.proposal, result.exclusion, result.source_catalog,
            result.source_serial_rows, result.projected_serial_rows,
            result.source_bindings, result.projected_bindings,
            "sha256:x", result.projected_graph_fingerprint, result.generation,
        )
    mutated = result.source_bindings[0]
    object.__setattr__(mutated, "serial", True)
    with pytest.raises((TypeError, ValueError)):
        bind.validate_exact_effect_binding_result(result)
    with pytest.raises(TypeError, match="minted by bind_exact_effect_claim"):
        bind.ExactEffectBindingResult(
            result.claim, result.proposal, result.exclusion, result.source_catalog,
            result.source_serial_rows, result.projected_serial_rows,
            result.source_bindings, result.projected_bindings,
            result.source_graph_fingerprint, result.projected_graph_fingerprint,
            result.generation,
        )
    object.__setattr__(mutated, "serial", next(
        serial for ref, serial in result.source_serial_rows
        if ref == mutated.block_ref
    ))

    rows = list(result.source_serial_rows)
    rows[0] = (rows[0][0], rows[0][1] + 99)
    with pytest.raises(TypeError, match="minted by bind_exact_effect_claim"):
        bind.ExactEffectBindingResult(
            result.claim, result.proposal, result.exclusion, result.source_catalog,
            tuple(rows), result.projected_serial_rows, result.source_bindings,
            result.projected_bindings,
            result.source_graph_fingerprint, result.projected_graph_fingerprint,
            result.generation,
        )

    reissued_claim = _claim_factory(
        model.ExactInfeasibleEffectClaim,
        **{
            field: getattr(result.claim, field)
            for field in (
                "kind", "effect_subject", "source_subject", "predicate_subject",
                "selected_target_subject", "discarded_effect_subject", "normalized_state",
                "state_identity", "width", "source_write_ea", "predicate_branch_ea",
                "discarded_effect_ea", "selected_edge_role", "route_proof_ids",
                "consensus",
            )
        },
        source_generation=99,
    )
    with pytest.raises(TypeError, match="minted by bind_exact_effect_claim"):
        bind.ExactEffectBindingResult(
            reissued_claim, result.proposal, result.exclusion, result.source_catalog,
            result.source_serial_rows, result.projected_serial_rows,
            result.source_bindings, result.projected_bindings,
            result.source_graph_fingerprint, result.projected_graph_fingerprint,
            result.generation,
        )


def test_exact_effect_binding_result_rejects_noncanonical_row_and_binding_order() -> None:
    source, proposal, exclusion, refs = _exact_fixture()
    claim = proposal.claims[0]
    serial_by_ref = {ref: serial for serial, ref in refs.items()}
    result = bind.bind_exact_effect_claim(
        source=source, projected=source, source_block_refs_by_serial=refs,
        projected_serial_by_ref=serial_by_ref, exclusion=exclusion,
        claim=claim, proposal=proposal, generation=1,
    )
    with pytest.raises(TypeError, match="minted by bind_exact_effect_claim"):
        bind.ExactEffectBindingResult(
            result.claim, result.proposal, result.exclusion, result.source_catalog,
            tuple(reversed(result.source_serial_rows)), result.projected_serial_rows,
            result.source_bindings, result.projected_bindings,
            result.source_graph_fingerprint, result.projected_graph_fingerprint,
            result.generation,
        )


def test_exact_effect_binding_result_rejects_canonical_reissued_claim_relationships() -> None:
    from dataclasses import replace

    source, proposal, exclusion, refs = _exact_fixture()
    claim = proposal.claims[0]
    serial_by_ref = {ref: serial for serial, ref in refs.items()}
    result = bind.bind_exact_effect_claim(
        source=source, projected=source, source_block_refs_by_serial=refs,
        projected_serial_by_ref=serial_by_ref, exclusion=exclusion,
        claim=claim, proposal=proposal, generation=1,
    )
    fields = (
        "kind", "effect_subject", "source_subject", "predicate_subject",
        "selected_target_subject", "discarded_effect_subject", "normalized_state",
        "state_identity", "width", "source_write_ea", "predicate_branch_ea",
        "discarded_effect_ea", "selected_edge_role", "route_proof_ids", "consensus",
    )
    base = {field: getattr(claim, field) for field in fields}
    for name, value in (
        ("normalized_state", claim.normalized_state + 1),
        ("source_write_ea", claim.source_write_ea + 1),
        (
            "selected_edge_role",
            next(
                destination.role
                for destination in proposal.route_evidence.route_proofs[0].destinations
                if destination.role is not claim.selected_edge_role
            ),
        ),
    ):
        forged = _claim_factory(
            model.ExactInfeasibleEffectClaim,
            **{**base, name: value, "source_generation": claim.source_generation},
        )
        with pytest.raises(TypeError, match="minted by bind_exact_effect_claim"):
            bind.ExactEffectBindingResult(
                forged, result.proposal, result.exclusion, result.source_catalog,
                result.source_serial_rows, result.projected_serial_rows,
                result.source_bindings, result.projected_bindings,
                result.source_graph_fingerprint, result.projected_graph_fingerprint,
                result.generation,
            )
        forged_proposal = replace(result.proposal, claims=(forged,))
        with pytest.raises(TypeError, match="minted by bind_exact_effect_claim"):
            bind.ExactEffectBindingResult(
                forged, forged_proposal, result.exclusion, result.source_catalog,
                result.source_serial_rows, result.projected_serial_rows,
                result.source_bindings, result.projected_bindings,
                result.source_graph_fingerprint, result.projected_graph_fingerprint,
                result.generation,
            )
        with pytest.raises(TypeError, match="minted by bind_exact_effect_claim"):
            bind.ExactEffectBindingResult(
                result.claim, result.proposal, result.exclusion, result.source_catalog,
                result.source_serial_rows, result.projected_serial_rows,
                tuple(reversed(result.source_bindings)), result.projected_bindings,
                result.source_graph_fingerprint, result.projected_graph_fingerprint,
                result.generation,
            )


def test_exact_effect_binding_rejects_canonical_rebuilt_wrong_anchor_and_origins() -> None:
    from dataclasses import replace

    source, proposal, exclusion, refs = _exact_fixture()
    claim = proposal.claims[0]
    serial_by_ref = {ref: serial for serial, ref in refs.items()}
    result = bind.bind_exact_effect_claim(
        source=source, projected=source, source_block_refs_by_serial=refs,
        projected_serial_by_ref=serial_by_ref, exclusion=exclusion,
        claim=claim, proposal=proposal, generation=1,
    )
    binding = result.source_bindings[0]
    with pytest.raises(ValueError, match="anchor"):
        replace(binding, serial=999, anchor_ea=0xDEAD, native_instruction_eas=(0xDEAD,))
    object.__setattr__(binding, "anchor_ea", 0xBEEF)
    with pytest.raises(TypeError, match="minted by bind_exact_effect_claim"):
        bind.ExactEffectBindingResult(
            result.claim, result.proposal, result.exclusion, result.source_catalog,
            result.source_serial_rows, result.projected_serial_rows,
            result.source_bindings,
            result.projected_bindings, result.source_graph_fingerprint,
            result.projected_graph_fingerprint, result.generation,
        )


def test_exact_semantic_correlation_is_not_public_authority() -> None:
    from d810.transforms.unflatten_authority import producer_api

    assert "_ExactEffectSemanticCorrelation" not in producer_api.__all__
    assert "_resolve_exact_effect_semantics" not in producer_api.__all__
    assert "validate_exact_effect_correlation" not in producer_api.__all__
    assert not hasattr(producer_api, "ExactEffectSemanticCorrelation")
    assert not hasattr(producer_api, "resolve_exact_effect_semantics")
    assert not hasattr(producer_api, "validate_exact_effect_correlation")
    assert not hasattr(bind, "_BindingConstructionToken")
    assert not hasattr(bind, "_mint_exact_effect_binding_result")


def test_exact_effect_public_binding_rejects_coordinated_kind_and_ea_forgery() -> None:
    from dataclasses import replace
    from d810.analyses.control_flow.effect_branch_exclusion import build_exact_state_branch_effect_exclusion
    from d810.ir.flowgraph import InsnKind
    from d810.transforms.unflatten_authority import producer_api

    source, proposal, exclusion, refs = _exact_fixture()
    claim = proposal.claims[0]
    serial_by_ref = {ref: serial for serial, ref in refs.items()}
    kwargs = dict(
        source=source,
        projected=source,
        source_block_refs_by_serial=refs,
        projected_serial_by_ref=serial_by_ref,
        exclusion=exclusion,
        claim=claim,
        proposal=proposal,
        generation=1,
    )
    result = bind.bind_exact_effect_claim(**kwargs)
    call_block = source.blocks[exclusion.discarded_effect_serial]
    store = replace(call_block.insn_snapshots[0], kind=InsnKind.STORE, is_call=False)
    kind_forged = replace(
        source,
        blocks={
            **source.blocks,
            call_block.serial: replace(call_block, insn_snapshots=(store,)),
        },
    )
    with pytest.raises(ValueError):
        bind.bind_exact_effect_claim(**{**kwargs, "source": kind_forged, "projected": kind_forged})

    forged_exclusion = build_exact_state_branch_effect_exclusion(
        kind_forged, kind_forged, normalized_state=7, source_serial=0,
        predicate_serial=1, selected_target_serial=2,
        discarded_effect_serial=3, state_identity=proposal.plan_inputs.state_identity,
    )
    assert forged_exclusion is not None
    forged_proposal = producer_api.build_proposal(
        plan_id=proposal.plan_id, source=kind_forged, block_refs_by_serial=refs,
        source_generation=1, canonical_route_evidence=proposal.route_evidence,
        exact_state_effect_exclusions=(forged_exclusion,), dispatcher_entry_serial=1,
        dispatcher_member_serials=(0, 1), authoritative_handler_serials=(2,),
        state_identity=proposal.plan_inputs.state_identity,
        use_def_witness=proposal.use_def_witness,
    )
    with pytest.raises(TypeError, match="minted by bind_exact_effect_claim"):
        bind.ExactEffectBindingResult(
            forged_proposal.claims[0], forged_proposal, forged_exclusion,
            forged_proposal.source_identity_catalog,
            result.source_serial_rows, result.projected_serial_rows,
            result.source_bindings, result.projected_bindings,
            result.source_graph_fingerprint, result.projected_graph_fingerprint,
            result.generation,
        )

    shifted = replace(call_block.insn_snapshots[0], native_ea=0x4001, ea=0x4001)
    ea_forged = replace(
        source,
        blocks={
            **source.blocks,
            call_block.serial: replace(call_block, native_start_ea=0x4001, insn_snapshots=(shifted,)),
        },
    )
    with pytest.raises(ValueError):
        bind.bind_exact_effect_claim(**{**kwargs, "source": ea_forged, "projected": ea_forged})


def test_exact_effect_binding_uses_shared_call_predicate_resolver() -> None:
    from dataclasses import replace
    from d810.ir.flowgraph import InsnKind
    from d810.ir.semantics import CallKind
    from d810.transforms.unflatten_authority import producer_api

    source, proposal, exclusion, refs = _exact_fixture()
    discarded_block = source.blocks[exclusion.discarded_effect_serial]
    call_by_predicate = replace(
        discarded_block.insn_snapshots[0],
        kind=InsnKind.NOP,
        is_call=False,
        call_kind=CallKind.DIRECT,
    )
    source_with_predicate_call = replace(
        source,
        blocks={
            **source.blocks,
            discarded_block.serial: replace(
                discarded_block, insn_snapshots=(call_by_predicate,)
            ),
        },
    )
    result = producer_api._exact_effect_claim(
        exclusion=exclusion, source=source_with_predicate_call,
        source_catalog=proposal.source_identity_catalog,
        block_refs_by_serial=refs,
        canonical_route_evidence=proposal.route_evidence,
        state_identity=proposal.plan_inputs.state_identity,
    )
    assert result.discarded_effect_ea == exclusion.discarded_effect_ea


def test_bind_corridor_coverage_forecast_direct_inventory_matrix() -> None:
    proposal, source, candidate_missing = _corridor_inventories()
    result = bind.bind_corridor_coverage_forecast(
        proposal=proposal, source_inventory=source,
        candidate_inventory=candidate_missing,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
    )
    assert result is not None
    assert result.source_dispatcher_reachable is True
    assert result.candidate_dispatcher_reachable is False
    assert result.covered_path_ids == proposal.corridor_coverage_forecast.covered_path_ids
    assert result.residual_path_ids == proposal.corridor_coverage_forecast.residual_path_ids
    assert result.drifted_path_ids == ()
    assert result.source_fingerprint == source.graph_fingerprint
    assert result.candidate_fingerprint == candidate_missing.graph_fingerprint
    assert result.source_generation == source.generation
    assert result.candidate_generation == candidate_missing.generation

    _proposal, _source, candidate_full = _corridor_inventories(candidate_full=True)
    full = bind.bind_corridor_coverage_forecast(
        proposal=proposal, source_inventory=source,
        candidate_inventory=candidate_full,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
    )
    assert full.candidate_dispatcher_reachable is True
    assert full.covered_path_ids == ()
    assert full.drifted_path_ids == proposal.corridor_coverage_forecast.covered_path_ids


def test_bind_corridor_forecast_requires_reachable_source_and_nonempty_path_domain() -> None:
    from dataclasses import replace

    proposal, source, candidate = _corridor_inventories()
    forecast = proposal.corridor_coverage_forecast
    empty_id = authority_id((
        "unflatten.corridor-coverage-forecast.v1", forecast.plan_id,
        forecast.function_ea, forecast.source_native_key, forecast.source_generation,
        forecast.dispatcher_ref, forecast.dispatcher_anchor_ea, (), (), (),
        forecast.enumeration_complete, (), (), (),
    ))
    empty = model.CorridorCoverageForecast(
        empty_id, forecast.plan_id, forecast.function_ea, forecast.source_native_key,
        forecast.source_generation, forecast.dispatcher_ref,
        forecast.dispatcher_anchor_ea, (), (), (), True, (), (), (),
    )
    with pytest.raises(ValueError, match="path|empty"):
        bind.bind_corridor_coverage_forecast(
            proposal=replace(proposal, corridor_coverage_forecast=empty),
            source_inventory=source, candidate_inventory=candidate,
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        )

    stale_source = _inventory_rephase(
        source, phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
        fingerprint=source.graph_fingerprint, generation=source.generation + 1,
    )
    with pytest.raises(ValueError, match="generation"):
        bind.bind_corridor_coverage_forecast(
            proposal=proposal, source_inventory=stale_source,
            candidate_inventory=candidate,
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        )


def test_bind_corridor_candidate_reachable_topology_loss_remains_nonfull_coverage() -> None:
    from dataclasses import replace

    proposal, source, candidate = _corridor_inventories(candidate_full=True)
    blocks = tuple(
        replace(
            block,
            successor_serials=() if block.serial == 1 else block.successor_serials,
            predecessor_serials=() if block.serial == 2 else block.predecessor_serials,
        )
        for block in candidate.blocks
    )
    topology = tuple(
        row for row in candidate.topology
        if not (
            row.kind is model.TopologyIncidenceKind.SUCCESSOR
            and row.owner_serial == 1 and row.peer_serial == 2
        ) and not (
            row.kind is model.TopologyIncidenceKind.PREDECESSOR
            and row.owner_serial == 2 and row.peer_serial == 1
        )
    )
    drifted = replace(
        candidate,
        blocks=blocks, topology=topology,
        inventory_digest=semantic_graph_inventory_digest(
            candidate.phase, candidate.graph_fingerprint, candidate.generation,
            blocks, candidate.subjects, candidate.bindings, candidate.effects,
            candidate.terminals, topology, candidate.reachable_serials,
            candidate.entry_serial, candidate.source_subject_ids,
            candidate.function_ea,
        ),
    )
    assert (1, 2) not in {
        (row.owner_serial, row.peer_serial)
        for row in drifted.topology
        if row.kind is model.TopologyIncidenceKind.SUCCESSOR
    }
    result = bind.bind_corridor_coverage_forecast(
        proposal=proposal, source_inventory=source,
        candidate_inventory=drifted,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
    )
    # ``drifted_path_ids`` is reserved for source-path drift and residual
    # paths.  A reachable candidate that loses a covered path is a sealed,
    # non-full structural result, not proof that the source forecast drifted.
    assert result.candidate_dispatcher_reachable is True
    assert result.covered_path_ids == proposal.corridor_coverage_forecast.covered_path_ids
    assert result.drifted_path_ids == ()


@pytest.mark.parametrize("mutation", ["ref", "ea", "order"])
def test_bind_corridor_source_path_node_ref_ea_and_order_mutations_reject(mutation) -> None:
    from dataclasses import replace

    proposal, source, candidate = _corridor_inventories()
    forecast = proposal.corridor_coverage_forecast
    base = forecast.paths[0]
    if mutation == "ref":
        nodes = (
            base.nodes[0],
            model.CorridorCoveragePathNode(LogicalBlockRef("foreign", "corridor", 1), base.nodes[1].anchor_ea),
            base.nodes[2],
        )
    elif mutation == "ea":
        nodes = (
            base.nodes[0],
            model.CorridorCoveragePathNode(base.nodes[1].block_ref, base.nodes[1].anchor_ea + 1),
            base.nodes[2],
        )
    else:
        nodes = (base.nodes[1], base.nodes[0], base.nodes[2])
    path_id = authority_id((
        "unflatten.corridor-coverage-path.v1", nodes, None,
        base.disposition, (),
    ))
    path = model.CorridorCoveragePath(path_id, nodes, None, base.disposition, ())
    forecast_id = authority_id((
        "unflatten.corridor-coverage-forecast.v1", forecast.plan_id,
        forecast.function_ea, forecast.source_native_key, forecast.source_generation,
        forecast.dispatcher_ref, forecast.dispatcher_anchor_ea, (path,), (path_id,),
        (), True, (), (), (),
    ))
    changed = model.CorridorCoverageForecast(
        forecast_id, forecast.plan_id, forecast.function_ea,
        forecast.source_native_key, forecast.source_generation,
        forecast.dispatcher_ref, forecast.dispatcher_anchor_ea,
        (path,), (path_id,), (), True, (), (), (),
    )
    with pytest.raises(ValueError, match="classification|partition|corridor"):
        bind.bind_corridor_coverage_forecast(
            proposal=replace(proposal, corridor_coverage_forecast=changed),
            source_inventory=source, candidate_inventory=candidate,
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        )


@pytest.mark.parametrize("merge_index", [1, 2])
def test_bind_corridor_state_merge_is_exact_path_minus_three_and_requires_branch_topology(merge_index) -> None:
    from dataclasses import replace

    proposal, source, candidate = _corridor_inventories()
    forecast = proposal.corridor_coverage_forecast
    base = forecast.paths[0]
    merge = base.nodes[merge_index]
    path_id = authority_id((
        "unflatten.corridor-coverage-path.v1", base.nodes, merge,
        base.disposition, (),
    ))
    path = model.CorridorCoveragePath(path_id, base.nodes, merge, base.disposition, ())
    forecast_id = authority_id((
        "unflatten.corridor-coverage-forecast.v1", forecast.plan_id,
        forecast.function_ea, forecast.source_native_key, forecast.source_generation,
        forecast.dispatcher_ref, forecast.dispatcher_anchor_ea, (path,), (path_id,),
        (), True, (), (), (),
    ))
    changed = model.CorridorCoverageForecast(
        forecast_id, forecast.plan_id, forecast.function_ea,
        forecast.source_native_key, forecast.source_generation,
        forecast.dispatcher_ref, forecast.dispatcher_anchor_ea,
        (path,), (path_id,), (), True, (), (), (),
    )
    message = r"path\[-3\]"
    with pytest.raises(ValueError, match=message):
        bind.bind_corridor_coverage_forecast(
            proposal=replace(proposal, corridor_coverage_forecast=changed),
            source_inventory=source, candidate_inventory=candidate,
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        )


def test_bind_corridor_state_merge_positive_requires_exact_branch_topology() -> None:
    proposal, source, candidate = _branch_corridor_inventories()
    result = bind.bind_corridor_coverage_forecast(
        proposal=proposal, source_inventory=source,
        candidate_inventory=candidate,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
    )
    path = proposal.corridor_coverage_forecast.paths[0]
    merge_serial = source.serial_by_ref[path.state_merge.block_ref]
    feeder_serial = source.serial_by_ref[path.nodes[-2].block_ref]
    assert path.state_merge == path.nodes[-3]
    assert sum(
        row.kind is model.TopologyIncidenceKind.PREDECESSOR
        and row.owner_serial == merge_serial
        for row in source.topology
    ) == 2
    assert {
        row.peer_serial for row in source.topology
        if row.kind is model.TopologyIncidenceKind.SUCCESSOR
        and row.owner_serial == merge_serial
    } == {feeder_serial}
    assert result.covered_path_ids == proposal.corridor_coverage_forecast.covered_path_ids
    assert result.drifted_path_ids == ()
    assert result.candidate_dispatcher_reachable is False


@pytest.mark.parametrize("candidate_subject_tokens", [("2",), ("1",)])
def test_bind_corridor_covered_state_merge_missing_candidate_node_is_still_covered(candidate_subject_tokens) -> None:
    proposal, source, _candidate = _branch_corridor_inventories()
    _plain_proposal, _plain_source, candidate = _corridor_inventories(
        candidate_subject_tokens=candidate_subject_tokens,
    )
    result = bind.bind_corridor_coverage_forecast(
        proposal=proposal, source_inventory=source,
        candidate_inventory=candidate,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
    )
    assert result.source_dispatcher_reachable is True
    assert result.candidate_dispatcher_reachable is False
    assert result.covered_path_ids == proposal.corridor_coverage_forecast.covered_path_ids
    assert result.drifted_path_ids == ()


@pytest.mark.parametrize(
    "successors,predecessors",
    [
        ({0: (), 1: (2,), 2: (0, 1)}, {0: (2,), 1: (2,), 2: (1,)}),
        ({0: (1, 2), 1: (0, 2), 2: (0, 1)}, {0: (1, 2), 1: (0, 2), 2: (0, 1)}),
    ],
)
def test_bind_corridor_residual_state_merge_candidate_topology_is_required(successors, predecessors) -> None:
    proposal, source, _candidate = _branch_corridor_inventories()
    residual_proposal = _corridor_forecast_variant(
        proposal,
        state_merge=proposal.corridor_coverage_forecast.paths[0].nodes[-3],
        disposition=model.CorridorPathDisposition.RESIDUAL,
    )
    candidate = _inventory_rephase(
        source, phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        fingerprint=authority_id("residual-candidate"), generation=4,
    )
    mutated_candidate = _inventory_with_edges(candidate, successors, predecessors)
    if successors[1] == (0, 2):
        result = bind.bind_corridor_coverage_forecast(
            proposal=residual_proposal, source_inventory=source,
            candidate_inventory=mutated_candidate,
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        )
        assert result.drifted_path_ids == residual_proposal.corridor_coverage_forecast.residual_path_ids
    else:
        with pytest.raises(ValueError, match="classification|partition"):
            bind.bind_corridor_coverage_forecast(
                proposal=residual_proposal, source_inventory=source,
                candidate_inventory=mutated_candidate,
                phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            )


def test_bind_corridor_residual_state_merge_missing_candidate_merge_refutes_partition() -> None:
    proposal, source, _candidate = _branch_corridor_inventories()
    residual_proposal = _corridor_forecast_variant(
        proposal,
        state_merge=proposal.corridor_coverage_forecast.paths[0].nodes[-3],
        disposition=model.CorridorPathDisposition.RESIDUAL,
    )
    _plain_proposal, _plain_source, candidate = _corridor_inventories(
        candidate_subject_tokens=("2",),
    )
    with pytest.raises(ValueError, match="classification|partition"):
        bind.bind_corridor_coverage_forecast(
            proposal=residual_proposal, source_inventory=source,
            candidate_inventory=candidate,
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        )


@pytest.mark.parametrize(
    "successors,predecessors",
    [
        ({0: (), 1: (2,), 2: (0, 1)}, {0: (2,), 1: (2,), 2: (1,)}),
        ({0: (1, 2), 1: (0, 2), 2: (0, 1)}, {0: (1, 2), 1: (0, 2), 2: (0, 1)}),
    ],
)
def test_bind_corridor_state_merge_rejects_predecessor_or_successor_set_drift(successors, predecessors) -> None:
    proposal, source, candidate = _branch_corridor_inventories()
    mutated_source = _inventory_with_edges(source, successors, predecessors)
    with pytest.raises(ValueError, match="state merge semantics"):
        bind.bind_corridor_coverage_forecast(
            proposal=proposal, source_inventory=mutated_source,
            candidate_inventory=candidate,
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        )


def test_bind_corridor_inventory_authority_correlation_is_explicit_and_phase_bound() -> None:
    proposal, source, candidate = _corridor_inventories()
    drifted_source = _inventory_rephase(
        source, phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
        fingerprint=authority_id("drifted-source"), generation=source.generation,
    )
    result = bind.bind_corridor_coverage_forecast(
        proposal=proposal, source_inventory=drifted_source,
        candidate_inventory=candidate,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
    )
    assert result.source_fingerprint == drifted_source.graph_fingerprint

    drifted_candidate = _inventory_rephase(
        candidate, phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        fingerprint=authority_id("drifted-candidate"), generation=candidate.generation + 1,
    )
    result = bind.bind_corridor_coverage_forecast(
        proposal=proposal, source_inventory=source,
        candidate_inventory=drifted_candidate,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
    )
    assert result.candidate_fingerprint == drifted_candidate.graph_fingerprint
    assert result.candidate_generation == drifted_candidate.generation
    with pytest.raises(ValueError, match="phase"):
        bind.bind_corridor_coverage_forecast(
            proposal=proposal, source_inventory=source,
            candidate_inventory=drifted_candidate,
            phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
        )


def test_bind_corridor_residual_and_incomplete_results_remain_nonfull() -> None:
    # The test builder's candidate dispatcher is intentionally absent while
    # constructing a forecast; use the honest full candidate inventory for a
    # residual result, then assert the result remains residual rather than a
    # full-coverage authorization.
    residual_proposal, residual_source, residual_candidate = _corridor_inventories(candidate_full=True)
    residual_proposal = _corridor_forecast_variant(
        residual_proposal,
        disposition=model.CorridorPathDisposition.RESIDUAL,
    )
    residual = bind.bind_corridor_coverage_forecast(
        proposal=residual_proposal, source_inventory=residual_source,
        candidate_inventory=residual_candidate,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
    )
    assert residual.covered_path_ids == ()
    assert residual.residual_path_ids == residual_proposal.corridor_coverage_forecast.residual_path_ids
    assert residual.drifted_path_ids == ()

    incomplete_proposal, incomplete_source, incomplete_candidate = _corridor_inventories()
    incomplete_proposal = _corridor_forecast_variant(
        incomplete_proposal, enumeration_complete=False,
    )
    incomplete = bind.bind_corridor_coverage_forecast(
        proposal=incomplete_proposal, source_inventory=incomplete_source,
        candidate_inventory=incomplete_candidate,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
    )
    assert incomplete.enumeration_complete is False
    assert incomplete.covered_path_ids == incomplete_proposal.corridor_coverage_forecast.covered_path_ids


def test_bind_corridor_semantic_exclusion_requires_one_canonical_route_link() -> None:
    from dataclasses import replace

    proposal, _source, _candidate = _corridor_inventories()
    forecast = proposal.corridor_coverage_forecast
    base = forecast.paths[0]
    exclusion_state = state_identity()
    typed = (
        "unflatten.corridor-semantic-exclusion.v1", 7, exclusion_state,
        base.nodes[0], None, base.nodes[1], base.nodes[2],
    )
    exclusion_id = authority_id(typed)
    exclusion_digest = authority_id((
        "unflatten.corridor-semantic-exclusion-digest.v1", typed,
    ))
    exclusion = model.CorridorSemanticExclusion(
        exclusion_id, exclusion_digest, 7, exclusion_state,
        base.nodes[0], None, base.nodes[1], base.nodes[2],
    )
    path_id = authority_id((
        "unflatten.corridor-coverage-path.v1", base.nodes, None,
        model.CorridorPathDisposition.SEMANTICALLY_EXCLUDED, (exclusion_id,),
    ))
    path = model.CorridorCoveragePath(
        path_id, base.nodes, None,
        model.CorridorPathDisposition.SEMANTICALLY_EXCLUDED, (exclusion_id,),
    )
    forecast_id = authority_id((
        "unflatten.corridor-coverage-forecast.v1", forecast.plan_id,
        forecast.function_ea, forecast.source_native_key, forecast.source_generation,
        forecast.dispatcher_ref, forecast.dispatcher_anchor_ea, (path,), (path_id,), (),
        True, ((exclusion_id, exclusion_digest),), (exclusion,),
        ((exclusion_id, (path_id,)),),
    ))
    excluded_forecast = model.CorridorCoverageForecast(
        forecast_id, forecast.plan_id, forecast.function_ea,
        forecast.source_native_key, forecast.source_generation,
        forecast.dispatcher_ref, forecast.dispatcher_anchor_ea, (path,), (path_id,), (),
        True, ((exclusion_id, exclusion_digest),), (exclusion,),
        ((exclusion_id, (path_id,)),),
    )
    excluded_proposal = replace(
        proposal, corridor_coverage_forecast=excluded_forecast,
    )
    with pytest.raises(ValueError, match="zero or multiple route links"):
        bind.bind_corridor_coverage_forecast(
            proposal=excluded_proposal,
            source_inventory=_source,
            candidate_inventory=_candidate,
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        )


def test_bind_corridor_semantic_exclusion_emits_exact_route_correlation() -> None:
    """A linked semantic path is covered by one transaction-owned correlation."""

    from dataclasses import replace
    from d810.analyses.control_flow.semantic_route_evidence import (
        SemanticRouteDestination, SemanticRouteProof, SemanticStateWriteDeliveryKind,
        SemanticStateWriteProof,
    )
    from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity

    proposal, source, candidate = _corridor_inventories()
    forecast = proposal.corridor_coverage_forecast
    base = forecast.paths[0]
    proof = proposal.route_evidence.route_proofs[0]
    source_identity = StableBlockIdentity.from_instruction_eas(
        (0x1300,), native_key=proposal.route_evidence.native_key,
    )
    target_identity = StableBlockIdentity.from_instruction_eas(
        (0x1100,), native_key=proposal.route_evidence.native_key,
    )
    write = SemanticStateWriteProof(
        source_identity, 0x1300, state_identity(), 4, 1,
        (0x1300,), None, (),
        SemanticStateWriteDeliveryKind.DIRECT,
    )
    proof = SemanticRouteProof(
        proof.proof_id, proof.atomic_group_id, proof.proof_kind, proof.shape,
        source_identity, 0x1300,
        (SemanticRouteDestination(
            proof.destinations[0].role, 1, target_identity, 0x1100,
        ),),
        NativeEaInterval(0x1300, 0x1301), state_write=write,
    )
    route_evidence = replace(
        proposal.route_evidence,
        route_proofs=(proof,),
    )
    source_subject = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.BLOCK,
        role=model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE,
        block_ref=base.nodes[0].block_ref, anchor_ea=base.nodes[0].anchor_ea,
        locator=model.BlockSubjectLocator(
            base.nodes[0].block_ref, base.nodes[0].anchor_ea,
        ),
    )
    destination_subject = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.BLOCK,
        role=model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION,
        block_ref=base.nodes[1].block_ref, anchor_ea=base.nodes[1].anchor_ea,
        locator=model.BlockSubjectLocator(
            base.nodes[1].block_ref, base.nodes[1].anchor_ea,
        ),
    )
    route_locator = model.RouteSubjectLocator(
        proof.proof_id, proof.atomic_group_id,
        base.nodes[0].block_ref, base.nodes[0].anchor_ea,
        (base.nodes[1].block_ref,), (base.nodes[1].anchor_ea,),
    )
    route_subject = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.ROUTE,
        role=model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE,
        block_ref=base.nodes[0].block_ref, anchor_ea=base.nodes[0].anchor_ea,
        locator=route_locator,
    )
    claim = _claim_factory(
        model.EquivalentSemanticRouteClaim,
        kind=model.UnflattenClaimKind.EQUIVALENT_SEMANTIC_ROUTE,
        retired_route_subject=route_subject,
        replacement_route_subject=route_subject,
        source_subject=source_subject,
        destination_subjects=(destination_subject,),
        route_proof_ids=(proof.proof_id,),
        atomic_group_id=proof.atomic_group_id,
        source_generation=proposal.source_identity_catalog.generation,
    )
    proposal = replace(
        proposal, route_evidence=route_evidence, claims=(claim,),
    )
    exclusion_source = base.nodes[0]
    typed = (
        "unflatten.corridor-semantic-exclusion.v1", 1, state_identity(),
        exclusion_source, None, base.nodes[1], base.nodes[2],
    )
    exclusion_id = authority_id(typed)
    exclusion_digest = authority_id((
        "unflatten.corridor-semantic-exclusion-digest.v1", typed,
    ))
    exclusion = model.CorridorSemanticExclusion(
        exclusion_id, exclusion_digest, 1, state_identity(),
        exclusion_source, None, base.nodes[1], base.nodes[2],
    )
    path_id = authority_id((
        "unflatten.corridor-coverage-path.v1", base.nodes, None,
        model.CorridorPathDisposition.SEMANTICALLY_EXCLUDED, (exclusion_id,),
    ))
    path = model.CorridorCoveragePath(
        path_id, base.nodes, None,
        model.CorridorPathDisposition.SEMANTICALLY_EXCLUDED, (exclusion_id,),
    )
    forecast_id = authority_id((
        "unflatten.corridor-coverage-forecast.v1", forecast.plan_id,
        forecast.function_ea, forecast.source_native_key,
        forecast.source_generation, forecast.dispatcher_ref,
        forecast.dispatcher_anchor_ea, (path,), (path_id,), (), True,
        ((exclusion_id, exclusion_digest),), (exclusion,),
        ((exclusion_id, (path_id,)),),
    ))
    proposal = replace(
        proposal,
        corridor_coverage_forecast=model.CorridorCoverageForecast(
            forecast_id, forecast.plan_id, forecast.function_ea,
            forecast.source_native_key, forecast.source_generation,
            forecast.dispatcher_ref, forecast.dispatcher_anchor_ea, (path,),
            (path_id,), (), True, ((exclusion_id, exclusion_digest),),
            (exclusion,), ((exclusion_id, (path_id,)),),
        ),
    )

    result = bind.bind_corridor_coverage_forecast(
        proposal=proposal, source_inventory=source,
        candidate_inventory=candidate,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
    )

    assert result is not None
    assert result.covered_path_ids == (path_id,)
    assert result.matched_semantic_exclusion_ids == (exclusion_id,)
    assert len(result.semantic_exclusion_correlations) == 1
    correlation = result.semantic_exclusion_correlations[0]
    assert (correlation.exclusion_id, correlation.path_id) == (
        exclusion_id, path_id,
    )
    assert correlation.claim_id == proposal.claims[0].claim_id
    assert correlation.proof_id == proof.proof_id
    assert correlation.ordered_prefix == path.nodes
