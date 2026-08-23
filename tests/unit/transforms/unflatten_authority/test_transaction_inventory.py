from __future__ import annotations

import inspect

import pytest

from d810.ir.flowgraph import BlockKind, BlockSnapshot
from d810.transforms.cfg_transaction import PlanBlockRef
from d810.transforms.unflatten_authority import producer_api
from d810.transforms.unflatten_authority import transaction_api
from d810.transforms.unflatten_authority import model
from d810.transforms.unflatten_authority.ids import authority_id, semantic_graph_inventory_digest, _subject_factory


_BADADDR = 0xFFFFFFFFFFFFFFFF


def test_transaction_derivation_does_not_construct_semantic_authority_payloads() -> None:
    source = inspect.getsource(transaction_api._derive_inputs)
    for forbidden in (
        "StructuralLineageEvidencePayload", "TopologyEvidencePayload",
        "SemanticRouteEvidencePayload", "EffectSiteEvidencePayload",
        "ReachabilityEvidencePayload", "CorridorCoverageEvidencePayload",
        "GenericCfgGateResult",
    ):
        assert forbidden not in source
    assert not hasattr(transaction_api, "_topology_relations_from_inventory")


def test_observe_inventory_block_preserves_raw_graph_start_ea() -> None:
    block = BlockSnapshot(
        serial=3,
        block_type=0,
        succs=(),
        preds=(),
        flags=0,
        start_ea=_BADADDR,
        insn_snapshots=(),
        kind=BlockKind.ZERO_WAY,
    )

    observed = producer_api.observe_inventory_block(
        block, owner_ref=None, owner_anchor_ea=None,
    )

    assert type(observed) is model.InventoryBlockObservation
    assert observed.graph_start_ea == _BADADDR


def test_transaction_uses_only_the_closed_inventory_model() -> None:
    assert not hasattr(transaction_api, "GraphSemanticInventory")
    assert not hasattr(transaction_api, "_reused_source_inventory")
    assert not hasattr(transaction_api, "_build_graph_inventory")
    assert "discover_reachable_effects_and_terminals" not in transaction_api.__dict__
    assert "reachable_terminal_blocks" not in transaction_api.__dict__


def test_reachable_closure_empty_graph_has_explicit_zero_entry_policy() -> None:
    assert transaction_api._reachable_serials_from_blocks({}, 0) == frozenset()
    with pytest.raises((TypeError, ValueError)):
        transaction_api._reachable_serials_from_blocks({}, 1)
    with pytest.raises((TypeError, ValueError)):
        transaction_api._reachable_serials_from_blocks({}, True)

    class EntryInt(int):
        pass

    with pytest.raises((TypeError, ValueError)):
        transaction_api._reachable_serials_from_blocks({}, EntryInt(0))


def test_full_candidate_builder_preserves_generated_goto_without_native_ea() -> None:
    from dataclasses import replace

    from d810.ir.flowgraph import BlockKind, BlockSnapshot, FlowGraph, InsnKind, InsnSnapshot
    from d810.ir.semantics import ControlTransferKind
    from d810.transforms.plan import PatchPlan, PatchRedirectGoto
    from d810.transforms.unflatten_authority.proposal import canonical_redirect_manifest

    source, proposal, _exclusion, refs = __import__(
        "tests.unit.transforms.unflatten_authority.test_bind",
        fromlist=["_exact_fixture"],
    )._exact_fixture()
    plan = PatchPlan(
        plan_id=proposal.plan_id,
        snapshot_id=authority_id("generated-goto-snapshot"),
        source_generation=1,
        steps=(
            PatchRedirectGoto(refs[0], refs[1], refs[2]),
            PatchRedirectGoto(refs[1], refs[2], refs[0]),
        ),
        source_coordinates=tuple((ref, serial) for serial, ref in refs.items()),
        unflatten_proposal=proposal,
    )
    manifest = canonical_redirect_manifest(plan)
    proposal = replace(
        proposal,
        use_def_witness=replace(
            proposal.use_def_witness,
            redirect_owner_refs=manifest.owner_refs,
            redirect_digest=manifest.digest,
        ),
    )
    plan = replace(plan, unflatten_proposal=proposal)
    source_inventory = transaction_api._build_semantic_graph_inventory(
        source, proposal, plan, source=True,
        phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
    )
    generated = BlockSnapshot(
        4, 0, (), (), 0, 0xFFFFFFFFFFFFFFFF,
        (InsnSnapshot(
            0x42, 0xFFFFFFFFFFFFFFFF, (), kind=InsnKind.GOTO,
            control_transfer_kind=ControlTransferKind.GOTO,
        ),),
        kind=BlockKind.UNKNOWN,
    )
    candidate_blocks = dict(source.blocks)
    candidate_blocks[4] = generated
    candidate = FlowGraph(candidate_blocks, source.entry_serial, source.func_ea)
    inventory = transaction_api._build_semantic_graph_inventory(
        candidate, proposal, plan, source=False,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        source_subjects=source_inventory.subjects,
    )
    row = next(item for item in inventory.blocks if item.serial == 4)
    assert row.transfer_ea is None
    assert row.instruction_observations[0].instruction_ea is None
    assert row.instruction_observations[0].control_transfer_kind is ControlTransferKind.GOTO
    assert all(
        item.source_transfer_ea is not None
        for item in inventory.topology
        if item.owner_serial != 4 and item.kind is model.TopologyIncidenceKind.SUCCESSOR
    )


def _topology_inventory(*, topology: tuple[model.InventoryTopologyIncidence, ...]) -> model.SemanticGraphInventory:
    ref1 = PlanBlockRef("topology", "one")
    ref2 = PlanBlockRef("topology", "two")
    block1 = model.InventoryBlockObservation(
        1, ref1, 0x1000, (0x1000, 0x1004), (), (2,), None,
        (
            model.InventoryInstructionObservation(0, 0x1000, 1, 0, model.InsnKind.NOP, None, False, None),
            model.InventoryInstructionObservation(1, 0x1004, 2, 0, model.InsnKind.NOP, None, False, None),
        ),
    )
    block2 = model.InventoryBlockObservation(
        2, ref2, 0x2000, (0x2000,), (1,), (), None,
        (model.InventoryInstructionObservation(0, 0x2000, 3, 0, model.InsnKind.NOP, None, False, None),),
    )
    subjects = tuple(sorted((
        _subject_factory(
            model.SemanticSubjectRef,
            kind=model.SemanticSubjectKind.BLOCK,
            role=model.SemanticSubjectRole.SOURCE_ENTRY,
            block_ref=ref1, anchor_ea=0x1000,
            locator=model.BlockSubjectLocator(ref1, 0x1000),
        ),
        _subject_factory(
            model.SemanticSubjectRef,
            kind=model.SemanticSubjectKind.BLOCK,
            role=model.SemanticSubjectRole.DISPATCHER_ENTRY,
            block_ref=ref2, anchor_ea=0x2000,
            locator=model.BlockSubjectLocator(ref2, 0x2000),
        ),
    ), key=lambda item: item.subject_id))
    phase = model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT
    fingerprint = authority_id("topology-graph")
    blocks = (block1, block2)
    closure = (1, 2)
    bindings = tuple(
        model.PhaseSubjectBinding(
            subject, phase, None, fingerprint, 3,
            model.SubjectBindingStatus.MISSING, None, None, (), subject.role,
        )
        for subject in subjects
    )
    digest = semantic_graph_inventory_digest(
        phase, fingerprint, 3, blocks, subjects, bindings, (), (), topology, closure,
        1, tuple(item.subject_id for item in subjects),
    )
    return model.SemanticGraphInventory(
        phase, fingerprint, 3, blocks, subjects, bindings, (), (), topology, digest,
        closure,
        1,
        tuple(item.subject_id for item in subjects),
    )


def test_raw_topology_incidence_requires_both_reciprocal_rows_and_anchor() -> None:
    successor = model.InventoryTopologyIncidence(
        model.TopologyIncidenceKind.SUCCESSOR, 1, 2, None,
    )
    predecessor = model.InventoryTopologyIncidence(
        model.TopologyIncidenceKind.PREDECESSOR, 2, 1, None,
    )
    inventory = _topology_inventory(topology=(predecessor, successor))
    assert {(row.kind, row.owner_serial, row.peer_serial) for row in inventory.topology} == {
        (model.TopologyIncidenceKind.SUCCESSOR, 1, 2),
        (model.TopologyIncidenceKind.PREDECESSOR, 2, 1),
    }
    with pytest.raises(ValueError, match="topology incidence"):
        _topology_inventory(topology=(successor,))
    with pytest.raises(ValueError, match="topology incidence"):
        _topology_inventory(topology=(predecessor,))
    with pytest.raises(ValueError, match="transfer"):
        _topology_inventory(topology=(
            predecessor,
            model.InventoryTopologyIncidence(
                model.TopologyIncidenceKind.SUCCESSOR, 1, 2, 0xDEAD,
            ),
        ))
