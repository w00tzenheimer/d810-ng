"""Canonical state-machine lowering publishes one portable semantic fragment."""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest

from d810.analyses.control_flow.frontend_normalization import (
    FrontendNormalizationEvidence,
    NativeIndirectTransferProof,
    NativeTransferEndpoint,
    NativeTransferShape,
)
from d810.analyses.control_flow.semantic_route_evidence import (
    CanonicalSemanticEvidence,
    SemanticCarrierProof,
    SemanticCorridorPoint,
    SemanticPredicateKind,
    SemanticPredicateProof,
    SemanticRouteDestination,
    SemanticRouteProof,
    SemanticRouteProofKind,
    SemanticRouteShape,
    SemanticStateWriteProof,
    bind_canonical_semantic_evidence,
)
from d810.capabilities.frontend_normalization import (
    FrontendNormalizationEvidenceCapability,
    FrontendNormalizationPlanCapability,
)
from d810.capabilities.resolver import CapabilitySet
from d810.capabilities.semantic_routes import (
    CanonicalSemanticCandidateEvidenceCapability,
    SemanticRouteReferenceOracleCapability,
)
from d810.core.fragment_authority import NormalizationWorkItemAuthority
from d810.core.semantic_route_oracle import (
    ReferenceRouteOracleSelection,
    ReferenceRouteRewrite,
    RouteOracleRun,
    SemanticTransferKind,
)
from d810.ir.block_identity import (
    NativeEaInterval,
    RebindStatus,
    StableBlockIdentity,
)
from d810.ir.flowgraph import BlockSnapshot, FlowGraph, InsnSnapshot
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
from d810.passes.analysis_manager import AnalysisManager
from d810.passes.pass_pipeline import (
    BackendRoute,
    FunctionPipelineContext,
)
from d810.passes.state_machine_spine import (
    semantic_evidence_state_machine_passes,
)
from d810.passes.unflatten.state_machine import (
    BOUND_CANONICAL_SEMANTIC_EVIDENCE,
    LowerCanonicalSemanticFragment,
)
from d810.passes.unflatten import state_machine as state_machine_module
from d810.transforms.canonical_semantic_fragment import (
    CanonicalSemanticFragmentRejected,
    build_canonical_semantic_fragment_plan,
)
from d810.transforms.fragment_plan import (
    FragmentPublicationPurpose,
    FragmentWorkItemScope,
)
from d810.transforms.detached_route_oracle import bind_fragment_reference_oracle
from d810.transforms.plan import PatchPlan
from tests.native_preanalysis import make_native_key


NATIVE_KEY = make_native_key(
    input_identity="sha256:" + "a" * 64,
    function_rva=0x1000,
)


def _identity(ea: int) -> StableBlockIdentity:
    return StableBlockIdentity.from_intervals(
        (NativeEaInterval(ea, ea + 1),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(ea,),
    )


def _cross_maturity_identity_index(
    identity_by_graph_serial: dict[int, StableBlockIdentity],
):
    def rebind_identity(identity: StableBlockIdentity):
        matches = tuple(
            int(serial)
            for serial, candidate in identity_by_graph_serial.items()
            if candidate == identity
        )
        if not matches:
            return SimpleNamespace(status=RebindStatus.MISSING, block=None)
        if len(matches) != 1:
            return SimpleNamespace(status=RebindStatus.AMBIGUOUS, block=None)
        return SimpleNamespace(
            status=RebindStatus.BOUND,
            block=SimpleNamespace(
                serial=matches[0] + 700,
                handle=SimpleNamespace(stable_identity=identity),
            ),
        )

    return SimpleNamespace(
        native_key=NATIVE_KEY,
        rebind_identity=rebind_identity,
    )


def _block(
    serial: int,
    ea: int,
    *,
    succs: tuple[int, ...],
    preds: tuple[int, ...],
) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=len(succs),
        succs=succs,
        preds=preds,
        flags=0,
        start_ea=ea,
        insn_snapshots=(InsnSnapshot(opcode=0, ea=ea, operands=()),),
    )


def _graph_and_bound_evidence():
    graph = FlowGraph(
        blocks={
            10: _block(10, 0x1000, succs=(20,), preds=()),
            20: _block(20, 0x1100, succs=(30,), preds=(10,)),
            30: _block(30, 0x1400, succs=(20,), preds=(20,)),
            40: _block(40, 0x1200, succs=(), preds=()),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    source_identity = _identity(0x1100)
    evidence = CanonicalSemanticEvidence(
        native_key=NATIVE_KEY,
        generation=7,
        atomic_group_id="canonical-semantic:g7",
        route_proofs=(
            SemanticRouteProof(
                proof_id="state-assignment@0x1100",
                atomic_group_id="canonical-semantic:g7",
                proof_kind=SemanticRouteProofKind.STATE_ASSIGNMENT,
                shape=SemanticRouteShape.DIRECT,
                source_identity=source_identity,
                source_anchor_ea=0x1100,
                delivery_region=NativeEaInterval(0x1100, 0x1101),
                destinations=(
                    SemanticRouteDestination(
                        role=SemanticEdgeRole.DIRECT,
                        state_constant=0x11,
                        target_identity=_identity(0x1200),
                        target_anchor_ea=0x1200,
                    ),
                ),
                state_write=SemanticStateWriteProof(
                    identity=source_identity,
                    instruction_ea=0x1100,
                    state_variable=StorageIdentity(
                        StorageIdentityKind.REGISTER,
                        20,
                    ),
                    width=4,
                    state_constant=0x11,
                    corridor_instruction_eas=(0x1100,),
                    authority_transfer_ea=None,
                    preserved_call_instruction_eas=(),
                ),
            ),
        ),
    )
    bound = bind_canonical_semantic_evidence(graph, evidence)
    assert bound is not None
    return graph, bound


def test_current_graph_identity_authority_rebinds_snapshot_derived_identities(
    monkeypatch,
) -> None:
    graph, _bound = _graph_and_bound_evidence()
    rebound_identities: list[StableBlockIdentity] = []

    class _CrossMaturityIdentityIndex:
        def identity_for_serial(self, _serial: int):
            pytest.fail("current graph authority must not reuse index-local serials")

        def rebind_identity(self, identity: StableBlockIdentity):
            rebound_identities.append(identity)
            anchor_ea = min(identity.exact_instruction_eas)
            if anchor_ea == 0x1400:
                return SimpleNamespace(status=RebindStatus.MISSING, block=None)
            return SimpleNamespace(
                status=RebindStatus.BOUND,
                block=SimpleNamespace(
                    serial=int(anchor_ea) + 700,
                    handle=SimpleNamespace(stable_identity=identity),
                ),
            )

    authority = state_machine_module._current_graph_identity_authority(
        graph,
        native_key=NATIVE_KEY,
        current_identity_index=_CrossMaturityIdentityIndex(),
    )

    assert authority == {
        10: _identity(0x1000),
        20: _identity(0x1100),
        40: _identity(0x1200),
    }
    assert rebound_identities == [
        _identity(0x1000),
        _identity(0x1100),
        _identity(0x1400),
        _identity(0x1200),
    ]


def test_current_graph_identity_authority_discards_shared_live_start_coordinate() -> (
    None
):
    graph = FlowGraph(
        blocks={
            10: _block(10, 0x1000, succs=(), preds=()),
            20: BlockSnapshot(
                serial=20,
                block_type=0,
                succs=(),
                preds=(),
                flags=0,
                start_ea=0x1000,
                insn_snapshots=(InsnSnapshot(opcode=0, ea=0x1100, operands=()),),
            ),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    entry_identity = _identity(0x1000)
    imported_identity = _identity(0x1100)
    imported_identity_with_shared_start = StableBlockIdentity.from_intervals(
        (
            NativeEaInterval(0x1000, 0x1001),
            NativeEaInterval(0x1100, 0x1101),
        ),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x1100,),
    )

    class _SharedStartIdentityIndex:
        def rebind_identity(self, identity: StableBlockIdentity):
            rebound_identity = (
                imported_identity_with_shared_start
                if 0x1100 in identity.exact_instruction_eas
                else entry_identity
            )
            return SimpleNamespace(
                status=RebindStatus.BOUND,
                block=SimpleNamespace(
                    serial=900,
                    handle=SimpleNamespace(stable_identity=rebound_identity),
                ),
            )

    authority = state_machine_module._current_graph_identity_authority(
        graph,
        native_key=NATIVE_KEY,
        current_identity_index=_SharedStartIdentityIndex(),
    )

    assert authority == {
        10: entry_identity,
        20: imported_identity,
    }
    assert not authority[20].native_ranges.contains(0x1000)


def test_canonical_semantic_lowering_returns_only_a_fragment_plan() -> None:
    graph, bound = _graph_and_bound_evidence()
    analyses = AnalysisManager(graph)
    analyses.put_analysis(BOUND_CANONICAL_SEMANTIC_EVIDENCE, bound)
    analyses.put_analysis(
        "recover_dispatcher",
        SimpleNamespace(
            dispatcher_block_serial=30,
            dispatch_map=SimpleNamespace(dispatcher_blocks=frozenset({30})),
        ),
    )
    analyses.put_analysis(
        "materialized_dispatcher_router_serials",
        frozenset({30}),
    )
    context = FunctionPipelineContext(
        source=None,
        graph=graph,
        maturity=None,
        project_config=None,
        facts=analyses.view(),
        capabilities=CapabilitySet(),
    )

    result = LowerCanonicalSemanticFragment().run(context)

    assert result.rewrite_plan == PatchPlan()
    assert result.fragment_plan is not None
    assert (
        result.fragment_plan.publication_purpose
        is FragmentPublicationPurpose.CANONICAL_SEMANTIC_LOWERING
    )
    assert tuple(
        result.fragment_plan.block(block_id).semantic_anchor_ea
        for block_id in result.fragment_plan.prohibited_dispatcher_blocks
    ) == (0x1400,)
    metadata = result.analysis_outputs["lower_state_machine_plan_metadata"]
    assert metadata["evidence_generation"] == 7
    assert "serial" not in repr(metadata)


def test_canonical_lowering_composes_candidate_with_unpublished_normalization(
    monkeypatch,
) -> None:
    graph, bound = _graph_and_bound_evidence()
    candidate = bound.evidence
    (direct_proof,) = candidate.route_proofs
    consumer_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x1200, 0x1210),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x1200,),
    )
    predicate_storage = StorageIdentity(StorageIdentityKind.STACK, 0x40)
    carrier_storage = StorageIdentity(StorageIdentityKind.STACK, 0x44)
    state_choice = SemanticRouteProof(
        proof_id="state-choice@0x1200",
        atomic_group_id=candidate.atomic_group_id,
        proof_kind=SemanticRouteProofKind.STATE_CHOICE,
        shape=SemanticRouteShape.CONDITIONAL,
        source_identity=consumer_identity,
        source_anchor_ea=0x1200,
        source_owner_identity=consumer_identity,
        source_owner_anchor_ea=0x1200,
        destinations=(
            SemanticRouteDestination(
                role=SemanticEdgeRole.CONDITIONAL_TAKEN,
                state_constant=0x22,
                target_identity=_identity(0x1250),
                target_anchor_ea=0x1250,
            ),
            SemanticRouteDestination(
                role=SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
                state_constant=0x33,
                target_identity=_identity(0x1260),
                target_anchor_ea=0x1260,
            ),
        ),
        predicate=SemanticPredicateProof(
            kind=SemanticPredicateKind.STORAGE_EQUALS,
            origin=SemanticCorridorPoint(direct_proof.source_identity, 0x1100),
            consumer=SemanticCorridorPoint(consumer_identity, 0x1200),
            corridor=(
                SemanticCorridorPoint(direct_proof.source_identity, 0x1100),
                SemanticCorridorPoint(consumer_identity, 0x1200),
            ),
            storage_identity=predicate_storage,
            width=4,
            compare_constant=0,
        ),
        carriers=(
            SemanticCarrierProof(
                carrier_id="entry-state",
                definition=SemanticCorridorPoint(
                    direct_proof.source_identity,
                    0x1100,
                ),
                consumers=(SemanticCorridorPoint(consumer_identity, 0x1200),),
                corridor=(
                    SemanticCorridorPoint(
                        direct_proof.source_identity,
                        0x1100,
                    ),
                    SemanticCorridorPoint(consumer_identity, 0x1200),
                ),
                storage_identity=carrier_storage,
                width=4,
                state_values=(0x22, 0x33),
                permitted_write_eas=frozenset({0x1100}),
            ),
        ),
    )
    candidate = replace(
        candidate,
        route_proofs=(direct_proof, state_choice),
    )
    frontend_evidence = FrontendNormalizationEvidence(
        native_key=NATIVE_KEY,
        generation=candidate.generation,
        atomic_group_id="frontend-normalization:g7",
        transfer_proofs=(
            NativeIndirectTransferProof(
                proof_id="native-transfer@0x1100",
                atomic_group_id="frontend-normalization:g7",
                shape=NativeTransferShape.DIRECT,
                source_identity=_identity(0x1100),
                source_anchor_ea=0x1100,
                source_transfer_ea=0x1100,
                endpoints=(
                    NativeTransferEndpoint(
                        role=SemanticEdgeRole.DIRECT,
                        identity=_identity(0x1200),
                        anchor_ea=0x1200,
                    ),
                ),
            ),
        ),
    )
    expected_plan = build_canonical_semantic_fragment_plan(
        graph,
        bound,
        prohibited_dispatcher_serials=(30,),
    )
    normalization_plan = replace(
        expected_plan,
        plan_id="frontend-normalization:0x1000:g7",
        atomic_group_id="frontend-normalization:g7",
        publication_purpose=FragmentPublicationPurpose.FRONTEND_NORMALIZATION,
        work_item_scope=FragmentWorkItemScope(
            work_item_id="frontend-normalization:0x1000:g7:complete",
            selected_obligation_ids=("native-transfer@0x1100",),
            remaining_obligation_ids=(),
            unreachable_obligation_ids=(),
        ),
        operations=tuple(
            replace(operation, direct_transfer_rewrite=None)
            for operation in expected_plan.operations
        ),
    )
    normalization_scope = normalization_plan.work_item_scope
    assert normalization_scope is not None
    normalization_authority = NormalizationWorkItemAuthority(
        evidence_generation=candidate.generation,
        publication_revision=1,
        source_plan_id=normalization_plan.plan_id,
        source_atomic_group_id=normalization_plan.atomic_group_id,
        work_item_id=normalization_scope.work_item_id,
        published_operation_ids=tuple(
            dict.fromkeys(
                (
                    *normalization_scope.selected_obligation_ids,
                    *(
                        operation.operation_id
                        for operation in normalization_plan.operations
                    ),
                )
            )
        ),
        selected_obligation_ids=normalization_scope.selected_obligation_ids,
        remaining_obligation_ids=normalization_scope.remaining_obligation_ids,
        unreachable_obligation_ids=normalization_scope.unreachable_obligation_ids,
    )
    calls = []
    monkeypatch.setattr(
        state_machine_module,
        "compose_canonical_semantic_fragment_plan",
        lambda current_graph, normalization_plan, evidence, **kwargs: (
            calls.append(
                (
                    "composition",
                    current_graph,
                    normalization_plan,
                    evidence,
                    kwargs,
                )
            )
            or expected_plan
        ),
    )

    class _CandidateProvider:
        def candidate_evidence_for(self, function_ea: int):
            return candidate if int(function_ea) == graph.func_ea else None

    class _FrontendProvider:
        def evidence_for(self, function_ea: int):
            return frontend_evidence if int(function_ea) == graph.func_ea else None

    class _PlanProvider:
        def plan_for(self, function_ea: int, evidence_generation: int):
            calls.append(("plan", function_ea, evidence_generation))
            return (
                (normalization_plan, normalization_authority)
                if (
                    int(function_ea) == graph.func_ea
                    and int(evidence_generation) == candidate.generation
                )
                else None
            )

    analyses = AnalysisManager(graph)
    analyses.put_analysis(
        "recover_dispatcher",
        SimpleNamespace(
            dispatcher_block_serial=30,
            dispatch_map=SimpleNamespace(dispatcher_blocks=frozenset({30})),
        ),
    )
    current_identity_by_serial = {
        int(serial): _identity(int(block.start_ea))
        for serial, block in graph.blocks.items()
    }
    analyses.put_analysis(
        "current_block_identity_index",
        _cross_maturity_identity_index(current_identity_by_serial),
    )
    capabilities = (
        CapabilitySet()
        .with_capability(
            CanonicalSemanticCandidateEvidenceCapability,
            _CandidateProvider(),
        )
        .with_capability(
            FrontendNormalizationEvidenceCapability,
            _FrontendProvider(),
        )
        .with_capability(
            FrontendNormalizationPlanCapability,
            _PlanProvider(),
        )
    )
    context = FunctionPipelineContext(
        source=None,
        graph=graph,
        maturity=None,
        project_config=None,
        facts=analyses.view(),
        capabilities=capabilities,
    )

    result = LowerCanonicalSemanticFragment().run(context)

    assert result.fragment_plan == expected_plan
    composition_calls = [call for call in calls if call[0] == "composition"]
    assert len(composition_calls) == 1
    assert calls[0] == ("plan", graph.func_ea, candidate.generation)
    assert calls[1][0:4] == (
        "composition",
        graph,
        normalization_plan,
        candidate,
    )
    assert calls[1][4] == {
        "available_evidence": candidate,
        "current_identity_by_serial": current_identity_by_serial,
        "normalization_authority": normalization_authority,
        "prohibited_dispatcher_serials": (30,),
    }
    assert (
        result.analysis_outputs["lower_state_machine_plan_metadata"][
            "evidence_generation"
        ]
        == candidate.generation
    )


def test_candidate_normalization_rejects_missing_receipted_plan_intent() -> None:
    graph, bound = _graph_and_bound_evidence()
    candidate = bound.evidence

    class _PlanProvider:
        def plan_for(self, function_ea: int, evidence_generation: int):
            return None

    with pytest.raises(
        CanonicalSemanticFragmentRejected,
    ) as exc_info:
        state_machine_module._plan_candidate_normalization(
            SimpleNamespace(graph=graph),
            candidate,
            _PlanProvider(),
        )

    rejection = exc_info.value
    assert rejection.reason_code == "frontend_normalization_plan_intent_missing"
    assert rejection.anchor_ea == 0x1100
    assert rejection.payload == {
        "evidence_generation": 7,
        "route_proof_id": "state-assignment@0x1100",
    }


def test_semantic_predecessor_uses_proved_state_write_block_entry() -> None:
    _graph, bound = _graph_and_bound_evidence()
    candidate = bound.evidence
    (proof,) = candidate.route_proofs
    delivery_ea = 0x1110
    proof = replace(
        proof,
        proof_id=f"state-assignment@0x{delivery_ea:X}",
        source_identity=_identity(delivery_ea),
        source_anchor_ea=delivery_ea,
        delivery_region=NativeEaInterval(delivery_ea, delivery_ea + 1),
        state_write=replace(
            proof.state_write,
            identity=_identity(0x1100),
            instruction_ea=0x1100,
            corridor_instruction_eas=(0x1100, delivery_ea),
        ),
    )
    candidate = replace(candidate, route_proofs=(proof,))
    rejection = CanonicalSemanticFragmentRejected(
        "published imported boundary retains unresolved semantic topology",
        reason_code="published_imported_boundary_topology_unresolved",
        anchor_ea=0x1200,
        payload={
            "incoming_operation_id": f"route:{proof.proof_id}",
            "incoming_source_anchor_ea": "0x1100",
        },
    )

    assert (
        state_machine_module._semantic_predecessor_boundary_anchor(
            rejection,
            candidate,
        )
        == 0x1100
    )


def test_temporary_boundary_port_requires_unpublished_semantic_predecessor() -> None:
    rejection = CanonicalSemanticFragmentRejected(
        "published canonical boundary requires one current owner",
        reason_code="published_boundary_current_owner_count_mismatch",
        anchor_ea=0x1100,
        payload={
            "owner_labels": (),
            "current_identity_inventory": (),
            "normalization_incoming_operations": (
                {
                    "source_owner_labels": (),
                    "source_current_identity_inventory": (),
                },
            ),
        },
    )

    assert state_machine_module._temporary_boundary_port_retirement_obligation(
        boundary_anchor_ea=0x1200,
        source_anchor_ea=0x1100,
        upstream_rejection=rejection,
    ) == (
        "retire-temporary-dispatcher-entry@0x1200:publish-semantic-predecessor@0x1100"
    )

    rejection.payload["owner_labels"] = ("blk20@0x1100",)
    assert (
        state_machine_module._temporary_boundary_port_retirement_obligation(
            boundary_anchor_ea=0x1200,
            source_anchor_ea=0x1100,
            upstream_rejection=rejection,
        )
        is None
    )


def test_candidate_composition_reroots_to_semantic_predecessor_and_requires_oracle(
    monkeypatch,
) -> None:
    graph, bound = _graph_and_bound_evidence()
    candidate = bound.evidence
    expected_plan = build_canonical_semantic_fragment_plan(
        graph,
        bound,
        prohibited_dispatcher_serials=(30,),
    )
    normalization_plan = replace(
        expected_plan,
        plan_id="frontend-normalization:0x1000:g7",
        atomic_group_id="frontend-normalization:g7",
        publication_purpose=FragmentPublicationPurpose.FRONTEND_NORMALIZATION,
        work_item_scope=FragmentWorkItemScope(
            work_item_id="frontend-normalization:0x1000:g7:complete",
            selected_obligation_ids=("native-transfer@0x1100",),
            remaining_obligation_ids=(),
            unreachable_obligation_ids=(),
        ),
        operations=tuple(
            replace(operation, direct_transfer_rewrite=None)
            for operation in expected_plan.operations
        ),
    )
    normalization_scope = normalization_plan.work_item_scope
    assert normalization_scope is not None
    normalization_authority = NormalizationWorkItemAuthority(
        evidence_generation=candidate.generation,
        publication_revision=1,
        source_plan_id=normalization_plan.plan_id,
        source_atomic_group_id=normalization_plan.atomic_group_id,
        work_item_id=normalization_scope.work_item_id,
        published_operation_ids=tuple(
            dict.fromkeys(
                (
                    *normalization_scope.selected_obligation_ids,
                    *(
                        operation.operation_id
                        for operation in normalization_plan.operations
                    ),
                )
            )
        ),
        selected_obligation_ids=normalization_scope.selected_obligation_ids,
        remaining_obligation_ids=normalization_scope.remaining_obligation_ids,
        unreachable_obligation_ids=normalization_scope.unreachable_obligation_ids,
    )
    frontend_evidence = FrontendNormalizationEvidence(
        native_key=NATIVE_KEY,
        generation=candidate.generation,
        atomic_group_id=normalization_plan.atomic_group_id,
        transfer_proofs=(
            NativeIndirectTransferProof(
                proof_id="native-transfer@0x1100",
                atomic_group_id=normalization_plan.atomic_group_id,
                shape=NativeTransferShape.DIRECT,
                source_identity=_identity(0x1100),
                source_anchor_ea=0x1100,
                source_transfer_ea=0x1100,
                endpoints=(
                    NativeTransferEndpoint(
                        role=SemanticEdgeRole.DIRECT,
                        identity=_identity(0x1200),
                        anchor_ea=0x1200,
                    ),
                ),
            ),
        ),
    )
    boundary_calls = []

    def reject_root_composition(*_args, **_kwargs):
        raise CanonicalSemanticFragmentRejected(
            "published imported boundary retains unresolved semantic topology",
            reason_code="published_imported_boundary_topology_unresolved",
            anchor_ea=0x1200,
            payload={
                "boundary_block_id": "native[0x1200-0x1201]",
                "incoming_operation_id": "route:state-assignment@0x1100",
                "incoming_source_anchor_ea": "0x1100",
                "incoming_source_block_id": "native[0x1100-0x1101]",
            },
        )

    def compose_boundary(*args, **kwargs):
        boundary_calls.append((args, kwargs))
        if kwargs["boundary_anchor_ea"] == 0x1200:
            raise CanonicalSemanticFragmentRejected(
                "published canonical boundary has no entry-connectable predecessor",
                reason_code="published_boundary_predecessor_missing",
                anchor_ea=0x1200,
                payload={
                    "incoming_predecessors": (
                        {
                            "block": "blk30@0x1400",
                            "prohibited": True,
                        },
                    ),
                },
            )
        assert kwargs["boundary_anchor_ea"] == 0x1100
        return expected_plan

    monkeypatch.setattr(
        state_machine_module,
        "compose_canonical_semantic_fragment_plan",
        reject_root_composition,
    )
    monkeypatch.setattr(
        state_machine_module,
        "compose_canonical_semantic_boundary_fragment_plan",
        compose_boundary,
        raising=False,
    )

    class _CandidateProvider:
        def candidate_evidence_for(self, function_ea: int):
            return candidate if int(function_ea) == graph.func_ea else None

    class _FrontendProvider:
        def evidence_for(self, function_ea: int):
            return frontend_evidence if int(function_ea) == graph.func_ea else None

    class _PlanProvider:
        def plan_for(self, function_ea: int, evidence_generation: int):
            if (
                int(function_ea) == graph.func_ea
                and int(evidence_generation) == candidate.generation
            ):
                return normalization_plan, normalization_authority
            return None

    current_identity_by_serial = {
        int(serial): _identity(int(block.start_ea))
        for serial, block in graph.blocks.items()
    }
    analyses = AnalysisManager(graph)
    analyses.put_analysis(
        "current_block_identity_index",
        _cross_maturity_identity_index(current_identity_by_serial),
    )
    capabilities = (
        CapabilitySet()
        .with_capability(
            CanonicalSemanticCandidateEvidenceCapability,
            _CandidateProvider(),
        )
        .with_capability(
            FrontendNormalizationEvidenceCapability,
            _FrontendProvider(),
        )
        .with_capability(
            FrontendNormalizationPlanCapability,
            _PlanProvider(),
        )
    )
    context = FunctionPipelineContext(
        source=None,
        graph=graph,
        maturity=None,
        project_config=None,
        facts=analyses.view(),
        capabilities=capabilities,
    )

    with pytest.raises(CanonicalSemanticFragmentRejected) as exc_info:
        state_machine_module._compose_candidate_semantic_fragment(
            context,
            prohibited_dispatcher_serials=(30,),
        )

    rejection = exc_info.value
    assert rejection.reason_code == "canonical_boundary_detached_oracle_required"
    assert rejection.anchor_ea == 0x1100
    assert rejection.payload == {
        "atomic_group_id": expected_plan.atomic_group_id,
        "block_count": len(expected_plan.blocks),
        "boundary_anchor_ea": "0x1100",
        "boundary_ports": (),
        "native_body_count": len(expected_plan.native_bodies),
        "operation_count": len(expected_plan.operations),
        "operation_ids": tuple(
            operation.operation_id for operation in expected_plan.operations
        ),
        "plan_id": expected_plan.plan_id,
        "route_proof_ids": ("state-assignment@0x1100",),
        "composition_attempts": (
            {
                "kind": "route",
                "outcome": "rejected",
                "route_proof_ids": ("state-assignment@0x1100",),
                "route_source_anchor_eas": ("0x1100",),
                "reason_code": "published_imported_boundary_topology_unresolved",
                "rejection_anchor_ea": "0x1200",
                "detail": (
                    "published imported boundary retains unresolved semantic topology"
                ),
                "rejection_payload": {
                    "boundary_block_id": "native[0x1200-0x1201]",
                    "incoming_operation_id": "route:state-assignment@0x1100",
                    "incoming_source_anchor_ea": "0x1100",
                    "incoming_source_block_id": "native[0x1100-0x1101]",
                },
            },
            {
                "boundary_anchor_ea": "0x1200",
                "kind": "boundary",
                "outcome": "rejected",
                "reason_code": "published_boundary_predecessor_missing",
                "rejection_anchor_ea": "0x1200",
                "detail": (
                    "published canonical boundary has no entry-connectable predecessor"
                ),
                "rejection_payload": {
                    "incoming_predecessors": (
                        {
                            "block": "blk30@0x1400",
                            "prohibited": True,
                        },
                    ),
                },
            },
            {
                "atomic_group_id": expected_plan.atomic_group_id,
                "block_count": len(expected_plan.blocks),
                "boundary_anchor_ea": "0x1100",
                "kind": "semantic_predecessor_boundary",
                "native_body_count": len(expected_plan.native_bodies),
                "operation_count": len(expected_plan.operations),
                "outcome": "accepted",
                "plan_id": expected_plan.plan_id,
                "root_block_ids": expected_plan.roots,
            },
        ),
    }
    assert len(boundary_calls) == 2
    assert boundary_calls[0][0] == (graph, normalization_plan)
    assert boundary_calls[0][1] == {
        "available_evidence": candidate,
        "boundary_anchor_ea": 0x1200,
        "current_identity_by_serial": current_identity_by_serial,
        "normalization_authority": normalization_authority,
        "prohibited_dispatcher_serials": (30,),
    }
    assert boundary_calls[1][0] == (graph, normalization_plan)
    assert boundary_calls[1][1] == {
        "available_evidence": candidate,
        "boundary_anchor_ea": 0x1100,
        "current_identity_by_serial": current_identity_by_serial,
        "normalization_authority": normalization_authority,
        "prohibited_dispatcher_serials": (30,),
    }


def test_bounded_candidate_plan_binds_exact_reference_oracle_capability() -> None:
    graph, bound = _graph_and_bound_evidence()
    plan = build_canonical_semantic_fragment_plan(
        graph,
        bound,
        prohibited_dispatcher_serials=(30,),
    )
    run = RouteOracleRun(
        run_id="test-exact-bounded-route",
        function_ea=graph.func_ea,
        fixture_sha256="a" * 64,
        reference_binary_sha256="b" * 64,
        candidate_binary_sha256="a" * 64,
        reference_commit="deadbeef",
        runtime_image="test-image",
        runtime_image_id="sha256:" + "c" * 64,
        cache_disabled=True,
    )
    selection = ReferenceRouteOracleSelection(
        run=run,
        publication_root_ea=0x1100,
        routes=(
            ReferenceRouteRewrite(
                route_id="test:0x1000:flow_route:0x1100",
                function_ea=graph.func_ea,
                owner_ea=0x1100,
                rewrite_anchor_ea=0x1100,
                corridor=((0x1100, 0x1101),),
                reference_phase="flow_route",
                original_transfer_kind=SemanticTransferKind.CONDITIONAL,
                final_transfer_kind=SemanticTransferKind.DIRECT,
                direct_target_ea=0x1200,
                reference_ledger_identity="flow_route:0x1100",
            ),
        ),
    )
    calls: list[tuple[int, object, tuple[int, ...]]] = []

    class _ReferenceOracleProvider:
        def reference_oracle_scope_for(
            self,
            function_ea: int,
            native_key,
        ):
            return selection

        def reference_oracle_for(
            self,
            function_ea: int,
            native_key,
            rewrite_anchor_eas: tuple[int, ...],
        ):
            calls.append((function_ea, native_key, rewrite_anchor_eas))
            return selection

    context = SimpleNamespace(
        capabilities=CapabilitySet().with_capability(
            SemanticRouteReferenceOracleCapability,
            _ReferenceOracleProvider(),
        )
    )

    result = state_machine_module._bind_boundary_reference_oracle(
        context,
        function_ea=graph.func_ea,
        boundary_anchor_ea=0x1100,
        boundary_plan=plan,
    )

    assert calls == [(graph.func_ea, NATIVE_KEY, (0x1100,))]
    assert result == bind_fragment_reference_oracle(plan, selection)


def test_configured_reference_root_selects_exact_direct_delivery_corridor() -> None:
    graph, bound = _graph_and_bound_evidence()
    (direct_proof,) = bound.evidence.route_proofs
    direct_proof = replace(
        direct_proof,
        state_write=replace(
            direct_proof.state_write,
            identity=_identity(0x1000),
            instruction_ea=0x1000,
            corridor_instruction_eas=(0x1000, 0x1100),
        ),
    )
    candidate = replace(bound.evidence, route_proofs=(direct_proof,))
    selection = ReferenceRouteOracleSelection(
        run=RouteOracleRun(
            run_id="test-distinct-owner-direct-route",
            function_ea=graph.func_ea,
            fixture_sha256="a" * 64,
            reference_binary_sha256="b" * 64,
            candidate_binary_sha256="a" * 64,
            reference_commit="deadbeef",
            runtime_image="test-image",
            runtime_image_id="sha256:" + "c" * 64,
            cache_disabled=True,
        ),
        publication_root_ea=0x1080,
        routes=(
            ReferenceRouteRewrite(
                route_id="test:0x1000:flow_route:0x1100",
                function_ea=graph.func_ea,
                owner_ea=0x1080,
                rewrite_anchor_ea=0x1100,
                corridor=((0x1000, 0x1101),),
                reference_phase="flow_route",
                original_transfer_kind=SemanticTransferKind.CONDITIONAL,
                final_transfer_kind=SemanticTransferKind.DIRECT,
                direct_target_ea=0x1200,
                reference_ledger_identity="flow_route:0x1100",
            ),
        ),
    )

    result = state_machine_module._configured_reference_root_candidate(
        selection,
        candidate,
    )

    assert result is candidate


def test_configured_reference_root_rejects_direct_delivery_corridor_drift() -> None:
    graph, bound = _graph_and_bound_evidence()
    (direct_proof,) = bound.evidence.route_proofs
    direct_proof = replace(
        direct_proof,
        state_write=replace(
            direct_proof.state_write,
            identity=_identity(0x1000),
            instruction_ea=0x1000,
            corridor_instruction_eas=(0x1000, 0x1100),
        ),
    )
    candidate = replace(bound.evidence, route_proofs=(direct_proof,))
    selection = ReferenceRouteOracleSelection(
        run=RouteOracleRun(
            run_id="test-drifted-owner-direct-route",
            function_ea=graph.func_ea,
            fixture_sha256="a" * 64,
            reference_binary_sha256="b" * 64,
            candidate_binary_sha256="a" * 64,
            reference_commit="deadbeef",
            runtime_image="test-image",
            runtime_image_id="sha256:" + "c" * 64,
            cache_disabled=True,
        ),
        publication_root_ea=0x1080,
        routes=(
            ReferenceRouteRewrite(
                route_id="test:0x1000:flow_route:0x1100",
                function_ea=graph.func_ea,
                owner_ea=0x1080,
                rewrite_anchor_ea=0x1100,
                corridor=((0x1001, 0x1101),),
                reference_phase="flow_route",
                original_transfer_kind=SemanticTransferKind.CONDITIONAL,
                final_transfer_kind=SemanticTransferKind.DIRECT,
                direct_target_ea=0x1200,
                reference_ledger_identity="flow_route:0x1100",
            ),
        ),
    )

    with pytest.raises(
        CanonicalSemanticFragmentRejected,
        match="lacks one exact candidate route",
    ) as exc_info:
        state_machine_module._configured_reference_root_candidate(
            selection,
            candidate,
        )

    assert (
        exc_info.value.reason_code
        == "canonical_configured_reference_root_candidate_mismatch"
    )


def test_configured_reference_scope_drives_live_route_composition_before_boundary(
    monkeypatch,
) -> None:
    graph, bound = _graph_and_bound_evidence()
    candidate = bound.evidence
    plan = build_canonical_semantic_fragment_plan(
        graph,
        bound,
        prohibited_dispatcher_serials=(30,),
    )
    run = RouteOracleRun(
        run_id="test-configured-bounded-route",
        function_ea=graph.func_ea,
        fixture_sha256="a" * 64,
        reference_binary_sha256="b" * 64,
        candidate_binary_sha256="a" * 64,
        reference_commit="deadbeef",
        runtime_image="test-image",
        runtime_image_id="sha256:" + "c" * 64,
        cache_disabled=True,
    )
    selection = ReferenceRouteOracleSelection(
        run=run,
        publication_root_ea=0x1100,
        routes=(
            ReferenceRouteRewrite(
                route_id="test:0x1000:flow_route:0x1100",
                function_ea=graph.func_ea,
                owner_ea=0x1100,
                rewrite_anchor_ea=0x1100,
                corridor=((0x1100, 0x1101),),
                reference_phase="flow_route",
                original_transfer_kind=SemanticTransferKind.CONDITIONAL,
                final_transfer_kind=SemanticTransferKind.DIRECT,
                direct_target_ea=0x1200,
                reference_ledger_identity="flow_route:0x1100",
            ),
        ),
    )
    frontend_evidence = FrontendNormalizationEvidence(
        native_key=NATIVE_KEY,
        generation=candidate.generation,
        atomic_group_id="frontend-normalization:g7",
        transfer_proofs=(
            NativeIndirectTransferProof(
                proof_id="native-transfer@0x1100",
                atomic_group_id="frontend-normalization:g7",
                shape=NativeTransferShape.DIRECT,
                source_identity=_identity(0x1100),
                source_anchor_ea=0x1100,
                source_transfer_ea=0x1100,
                endpoints=(
                    NativeTransferEndpoint(
                        role=SemanticEdgeRole.DIRECT,
                        identity=_identity(0x1200),
                        anchor_ea=0x1200,
                    ),
                ),
            ),
        ),
    )

    class _CandidateProvider:
        def candidate_evidence_for(self, function_ea: int):
            return candidate if int(function_ea) == graph.func_ea else None

    class _FrontendProvider:
        def evidence_for(self, function_ea: int):
            return frontend_evidence if int(function_ea) == graph.func_ea else None

    class _PlanProvider:
        def plan_for(self, function_ea: int, evidence_generation: int):
            return None

    class _ReferenceOracleProvider:
        def reference_oracle_scope_for(self, function_ea: int, native_key):
            if int(function_ea) == graph.func_ea and native_key == NATIVE_KEY:
                return selection
            return None

        def reference_oracle_for(
            self,
            function_ea: int,
            native_key,
            rewrite_anchor_eas: tuple[int, ...],
        ):
            if rewrite_anchor_eas == (0x1100,):
                return selection
            return None

    current_identity_by_serial = {
        int(serial): _identity(int(block.start_ea))
        for serial, block in graph.blocks.items()
    }
    analyses = AnalysisManager(graph)
    analyses.put_analysis(
        "current_block_identity_index",
        _cross_maturity_identity_index(current_identity_by_serial),
    )
    context = FunctionPipelineContext(
        source=None,
        graph=graph,
        maturity=None,
        project_config=None,
        facts=analyses.view(),
        capabilities=(
            CapabilitySet()
            .with_capability(
                CanonicalSemanticCandidateEvidenceCapability,
                _CandidateProvider(),
            )
            .with_capability(
                FrontendNormalizationEvidenceCapability,
                _FrontendProvider(),
            )
            .with_capability(
                FrontendNormalizationPlanCapability,
                _PlanProvider(),
            )
            .with_capability(
                SemanticRouteReferenceOracleCapability,
                _ReferenceOracleProvider(),
            )
        ),
    )
    normalization_authority = object()
    monkeypatch.setattr(
        state_machine_module,
        "_plan_candidate_normalization",
        lambda *_args, **_kwargs: (plan, normalization_authority),
    )
    route_calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def compose_route(*args, **kwargs):
        route_calls.append((args, kwargs))
        return plan

    monkeypatch.setattr(
        state_machine_module,
        "compose_canonical_semantic_fragment_plan",
        compose_route,
    )
    monkeypatch.setattr(
        state_machine_module,
        "compose_canonical_semantic_boundary_fragment_plan",
        lambda *_args, **_kwargs: pytest.fail(
            "a configured live route root must compose before a boundary"
        ),
    )

    result, generation = state_machine_module._compose_candidate_semantic_fragment(
        context,
        prohibited_dispatcher_serials=(30,),
    )

    assert generation == candidate.generation
    assert result == bind_fragment_reference_oracle(plan, selection)
    assert route_calls == [
        (
            (graph, plan, candidate),
            {
                "available_evidence": candidate,
                "current_identity_by_serial": current_identity_by_serial,
                "normalization_authority": normalization_authority,
                "prohibited_dispatcher_serials": (30,),
            },
        )
    ]


def test_configured_reference_scope_preserves_typed_anchor_mismatch(
    monkeypatch,
) -> None:
    graph, bound = _graph_and_bound_evidence()
    candidate = bound.evidence
    plan = build_canonical_semantic_fragment_plan(
        graph,
        bound,
        prohibited_dispatcher_serials=(30,),
    )
    root_route = ReferenceRouteRewrite(
        route_id="test:0x1000:flow_route:0x1100",
        function_ea=graph.func_ea,
        owner_ea=0x1100,
        rewrite_anchor_ea=0x1100,
        corridor=((0x1100, 0x1101),),
        reference_phase="flow_route",
        original_transfer_kind=SemanticTransferKind.CONDITIONAL,
        final_transfer_kind=SemanticTransferKind.DIRECT,
        direct_target_ea=0x1200,
        reference_ledger_identity="flow_route:0x1100",
    )
    selection = ReferenceRouteOracleSelection(
        run=RouteOracleRun(
            run_id="test-configured-anchor-mismatch",
            function_ea=graph.func_ea,
            fixture_sha256="a" * 64,
            reference_binary_sha256="b" * 64,
            candidate_binary_sha256="a" * 64,
            reference_commit="deadbeef",
            runtime_image="test-image",
            runtime_image_id="sha256:" + "c" * 64,
            cache_disabled=True,
        ),
        publication_root_ea=0x1100,
        routes=(
            root_route,
            replace(
                root_route,
                route_id="test:0x1000:flow_route:0x1300",
                owner_ea=0x1300,
                rewrite_anchor_ea=0x1300,
                corridor=((0x1300, 0x1301),),
                reference_ledger_identity="flow_route:0x1300",
            ),
        ),
    )
    monkeypatch.setattr(
        state_machine_module,
        "compose_canonical_semantic_fragment_plan",
        lambda *_args, **_kwargs: plan,
    )

    with pytest.raises(CanonicalSemanticFragmentRejected) as exc_info:
        state_machine_module._compose_configured_reference_scope_plan(
            graph=graph,
            normalization_plan=plan,
            configured_scope=selection,
            available_evidence=candidate,
            current_identity_by_serial={
                serial: _identity(block.start_ea)
                for serial, block in graph.blocks.items()
            },
            normalization_authority=object(),
            prohibited_dispatcher_serials=(30,),
            composition_attempts=[],
        )

    rejection = exc_info.value
    assert rejection.reason_code == "canonical_configured_reference_scope_invalid"
    assert rejection.payload["cause_reason_code"] == (
        "fragment_reference_rewrite_anchor_set_mismatch"
    )
    assert rejection.payload["cause_payload"] == {
        "coordinate_rebindings": (),
        "missing_rewrite_anchors": ("0x1300",),
        "planned_rewrite_anchors": ("0x1100",),
        "selected_rewrite_anchors": ("0x1100", "0x1300"),
        "unexpected_rewrite_anchors": (),
    }


def test_configured_reference_direct_route_returns_one_complete_vertical_plan(
    monkeypatch,
) -> None:
    graph, bound = _graph_and_bound_evidence()
    candidate = bound.evidence
    plan = build_canonical_semantic_fragment_plan(
        graph,
        bound,
        prohibited_dispatcher_serials=(30,),
    )
    reference_route = ReferenceRouteRewrite(
        route_id="test:0x1000:flow_route:0x1100",
        function_ea=graph.func_ea,
        owner_ea=0x1100,
        rewrite_anchor_ea=0x1100,
        corridor=((0x1100, 0x1101),),
        reference_phase="flow_route",
        original_transfer_kind=SemanticTransferKind.CONDITIONAL,
        final_transfer_kind=SemanticTransferKind.DIRECT,
        direct_target_ea=0x1200,
        reference_ledger_identity="flow_route:0x1100",
    )
    selection = ReferenceRouteOracleSelection(
        run=RouteOracleRun(
            run_id="test-configured-detached-direct-route",
            function_ea=graph.func_ea,
            fixture_sha256="a" * 64,
            reference_binary_sha256="b" * 64,
            candidate_binary_sha256="a" * 64,
            reference_commit="deadbeef",
            runtime_image="test-image",
            runtime_image_id="sha256:" + "c" * 64,
            cache_disabled=True,
        ),
        publication_root_ea=0x1100,
        routes=(reference_route,),
    )
    expected_payload = {
        "plan_id": "detached-direct:test",
        "route_proof_id": candidate.route_proofs[0].proof_id,
        "owner_anchor_ea": "0x1100",
        "rewrite_anchor_ea": "0x1100",
        "direct_target_ea": "0x1200",
    }
    detached_plan = SimpleNamespace(
        evidence_generation=candidate.generation,
        source_block=SimpleNamespace(
            block_id="prepared-source",
            native_body_id="prepared-body",
            semantic_anchor_ea=0x1100,
        ),
        diagnostic_payload=lambda: dict(expected_payload),
    )
    planner_calls = []

    def plan_detached(*args, **kwargs):
        planner_calls.append((args, kwargs))
        return detached_plan

    monkeypatch.setattr(
        state_machine_module,
        "plan_detached_reference_direct_route",
        plan_detached,
    )
    vertical_plan = replace(plan, plan_id="canonical-vertical:test")
    boundary_calls = []

    def compose_vertical_boundary(*args, **kwargs):
        boundary_calls.append((args, kwargs))
        return vertical_plan

    monkeypatch.setattr(
        state_machine_module,
        "compose_canonical_semantic_boundary_fragment_plan",
        compose_vertical_boundary,
    )
    monkeypatch.setattr(
        state_machine_module,
        "compose_canonical_semantic_fragment_plan",
        lambda *_args, **_kwargs: pytest.fail(
            "an operation-owned detached route must compose from its boundary"
        ),
    )
    bound_plan = object()
    bind_calls = []

    def bind_vertical(*args):
        bind_calls.append(args)
        return bound_plan

    monkeypatch.setattr(
        state_machine_module,
        "bind_fragment_reference_oracle",
        bind_vertical,
    )
    attempts: list[dict[str, object]] = []
    normalization_authority = object()

    result = state_machine_module._compose_configured_reference_scope_plan(
        graph=graph,
        normalization_plan=plan,
        configured_scope=selection,
        available_evidence=candidate,
        current_identity_by_serial={
            serial: _identity(block.start_ea) for serial, block in graph.blocks.items()
        },
        normalization_authority=normalization_authority,
        prohibited_dispatcher_serials=(30,),
        composition_attempts=attempts,
    )

    assert result is bound_plan
    assert attempts[0] == {
        "kind": "configured_reference_detached_direct_route",
        "outcome": "accepted",
        "route_proof_ids": (candidate.route_proofs[0].proof_id,),
        "route_source_anchor_eas": ("0x1100",),
        **expected_payload,
    }
    assert attempts[1]["kind"] == "configured_reference_detached_direct_fragment"
    assert attempts[1]["outcome"] == "accepted"
    assert attempts[1]["plan_id"] == vertical_plan.plan_id
    assert planner_calls == [
        (
            (plan, candidate, reference_route),
            {"normalization_authority": normalization_authority},
        )
    ]
    assert boundary_calls == [
        (
            (graph, plan),
            {
                "boundary_anchor_ea": 0x1100,
                "available_evidence": candidate,
                "current_identity_by_serial": {
                    serial: _identity(block.start_ea)
                    for serial, block in graph.blocks.items()
                },
                "normalization_authority": normalization_authority,
                "prohibited_dispatcher_serials": (30,),
            },
        )
    ]
    assert bind_calls == [(vertical_plan, selection)]


def test_configured_detached_route_uses_only_a_closed_carrier_ingress_component(
    monkeypatch,
) -> None:
    graph, bound = _graph_and_bound_evidence()
    candidate = bound.evidence
    plan = build_canonical_semantic_fragment_plan(
        graph,
        bound,
        prohibited_dispatcher_serials=(30,),
    )
    reference_route = ReferenceRouteRewrite(
        route_id="test:0x1000:flow_route:0x1100",
        function_ea=graph.func_ea,
        owner_ea=0x1100,
        rewrite_anchor_ea=0x1100,
        corridor=((0x1100, 0x1101),),
        reference_phase="flow_route",
        original_transfer_kind=SemanticTransferKind.CONDITIONAL,
        final_transfer_kind=SemanticTransferKind.DIRECT,
        direct_target_ea=0x1200,
        reference_ledger_identity="flow_route:0x1100",
    )
    selection = ReferenceRouteOracleSelection(
        run=RouteOracleRun(
            run_id="test-configured-carrier-ingress",
            function_ea=graph.func_ea,
            fixture_sha256="a" * 64,
            reference_binary_sha256="b" * 64,
            candidate_binary_sha256="a" * 64,
            reference_commit="deadbeef",
            runtime_image="test-image",
            runtime_image_id="sha256:" + "c" * 64,
            cache_disabled=True,
        ),
        publication_root_ea=0x1100,
        routes=(reference_route,),
    )
    detached_plan = SimpleNamespace(
        evidence_generation=candidate.generation,
        source_block=SimpleNamespace(
            block_id="prepared-source",
            native_body_id="prepared-body",
            semantic_anchor_ea=0x1100,
        ),
        diagnostic_payload=lambda: {
            "plan_id": "detached-direct:test",
            "route_proof_id": candidate.route_proofs[0].proof_id,
            "owner_anchor_ea": "0x1100",
            "rewrite_anchor_ea": "0x1100",
            "direct_target_ea": "0x1200",
        },
    )
    monkeypatch.setattr(
        state_machine_module,
        "plan_detached_reference_direct_route",
        lambda *_args, **_kwargs: detached_plan,
    )

    def reject_detached_boundary(*_args, **_kwargs):
        raise CanonicalSemanticFragmentRejected(
            "detached source has no current owner",
            reason_code="published_boundary_current_owner_count_mismatch",
            anchor_ea=0x1100,
        )

    monkeypatch.setattr(
        state_machine_module,
        "compose_canonical_semantic_boundary_fragment_plan",
        reject_detached_boundary,
    )
    carrier_plan = replace(plan, plan_id="canonical-carrier-ingress:test")
    carrier_calls = []

    def compose_carrier(*args, **kwargs):
        carrier_calls.append((args, kwargs))
        return carrier_plan

    monkeypatch.setattr(
        state_machine_module,
        "compose_canonical_carrier_ingress_fragment_plan",
        compose_carrier,
        raising=False,
    )
    bound_plan = object()
    bind_calls = []

    def bind_carrier(plan_arg, selection_arg):
        bind_calls.append((plan_arg, selection_arg))
        return bound_plan

    monkeypatch.setattr(
        state_machine_module,
        "bind_fragment_reference_oracle",
        bind_carrier,
    )
    current_identity_by_serial = {
        serial: _identity(block.start_ea) for serial, block in graph.blocks.items()
    }
    normalization_authority = object()
    attempts: list[dict[str, object]] = []

    result = state_machine_module._compose_configured_reference_scope_plan(
        graph=graph,
        normalization_plan=plan,
        configured_scope=selection,
        available_evidence=candidate,
        current_identity_by_serial=current_identity_by_serial,
        normalization_authority=normalization_authority,
        prohibited_dispatcher_serials=(30,),
        composition_attempts=attempts,
    )

    assert result is bound_plan
    assert [attempt["kind"] for attempt in attempts] == [
        "configured_reference_detached_direct_route",
        "configured_reference_detached_direct_fragment",
        "configured_reference_carrier_ingress",
    ]
    assert [attempt["outcome"] for attempt in attempts] == [
        "accepted",
        "rejected",
        "accepted",
    ]
    assert carrier_calls == [
        (
            (graph, plan),
            {
                "available_evidence": candidate,
                "detached_route": detached_plan,
                "current_identity_by_serial": current_identity_by_serial,
                "normalization_authority": normalization_authority,
                "prohibited_dispatcher_serials": (30,),
            },
        )
    ]
    assert bind_calls == [(carrier_plan, selection)]

    def reject_open_carrier_component(*_args, **_kwargs):
        raise CanonicalSemanticFragmentRejected(
            "published imported boundary retains unresolved semantic topology",
            reason_code="published_imported_boundary_topology_unresolved",
            anchor_ea=0x1300,
            payload={
                "boundary_block_id": "native@0x1300",
                "operation_id": "native-body-edge@0x1300",
            },
        )

    monkeypatch.setattr(
        state_machine_module,
        "compose_canonical_carrier_ingress_fragment_plan",
        reject_open_carrier_component,
    )
    rejected_attempts: list[dict[str, object]] = []

    with pytest.raises(CanonicalSemanticFragmentRejected) as exc_info:
        state_machine_module._compose_configured_reference_scope_plan(
            graph=graph,
            normalization_plan=plan,
            configured_scope=selection,
            available_evidence=candidate,
            current_identity_by_serial=current_identity_by_serial,
            normalization_authority=normalization_authority,
            prohibited_dispatcher_serials=(30,),
            composition_attempts=rejected_attempts,
        )

    rejection = exc_info.value
    assert rejection.reason_code == "carrier_ingress_target_component_not_closed"
    assert rejection.anchor_ea == 0x1300
    assert rejection.payload["unresolved_reason_code"] == (
        "published_imported_boundary_topology_unresolved"
    )
    assert rejection.payload["contextual_restart_permitted"] is False
    assert [attempt["outcome"] for attempt in rejected_attempts] == [
        "accepted",
        "rejected",
        "rejected",
    ]


def test_configured_reference_scope_reuses_proved_temporary_entry_port(
    monkeypatch,
) -> None:
    graph, bound = _graph_and_bound_evidence()
    candidate = bound.evidence
    plan = build_canonical_semantic_fragment_plan(
        graph,
        bound,
        prohibited_dispatcher_serials=(30,),
    )
    run = RouteOracleRun(
        run_id="test-configured-temporary-port",
        function_ea=graph.func_ea,
        fixture_sha256="a" * 64,
        reference_binary_sha256="b" * 64,
        candidate_binary_sha256="a" * 64,
        reference_commit="deadbeef",
        runtime_image="test-image",
        runtime_image_id="sha256:" + "c" * 64,
        cache_disabled=True,
    )
    selection = ReferenceRouteOracleSelection(
        run=run,
        publication_root_ea=0x1200,
        routes=(
            ReferenceRouteRewrite(
                route_id="test:0x1000:flow_route:0x1100",
                function_ea=graph.func_ea,
                owner_ea=0x1100,
                rewrite_anchor_ea=0x1100,
                corridor=((0x1100, 0x1101),),
                reference_phase="flow_route",
                original_transfer_kind=SemanticTransferKind.CONDITIONAL,
                final_transfer_kind=SemanticTransferKind.DIRECT,
                direct_target_ea=0x1200,
                reference_ledger_identity="flow_route:0x1100",
            ),
        ),
    )
    normalization_authority = object()
    current_identity_by_serial = {
        int(serial): _identity(int(block.start_ea))
        for serial, block in graph.blocks.items()
    }
    boundary_calls: list[dict[str, object]] = []

    def compose_boundary(*_args, **kwargs):
        boundary_calls.append(kwargs)
        anchor_ea = kwargs["boundary_anchor_ea"]
        retirement = kwargs.get("temporary_dispatcher_entry_port_obligation_id")
        if anchor_ea == 0x1200 and retirement is None:
            raise CanonicalSemanticFragmentRejected(
                "published canonical boundary has no entry-connectable predecessor",
                reason_code="published_boundary_predecessor_missing",
                anchor_ea=0x1200,
                payload={"incoming_predecessors": ({"prohibited": True},)},
            )
        if anchor_ea == 0x1100:
            raise CanonicalSemanticFragmentRejected(
                "published canonical boundary requires one current owner",
                reason_code="published_boundary_current_owner_count_mismatch",
                anchor_ea=0x1100,
                payload={
                    "owner_labels": (),
                    "current_identity_inventory": (),
                    "normalization_incoming_operations": (
                        {
                            "source_owner_labels": (),
                            "source_current_identity_inventory": (),
                        },
                    ),
                },
            )
        assert anchor_ea == 0x1200
        assert retirement == (
            "retire-temporary-dispatcher-entry@0x1200:"
            "publish-semantic-predecessor@0x1100"
        )
        return plan

    bind_calls: list[tuple[object, object]] = []

    def bind_reference(candidate_plan, authority):
        bind_calls.append((candidate_plan, authority))
        return candidate_plan

    monkeypatch.setattr(
        state_machine_module,
        "compose_canonical_semantic_boundary_fragment_plan",
        compose_boundary,
    )
    monkeypatch.setattr(
        state_machine_module,
        "bind_fragment_reference_oracle",
        bind_reference,
    )
    composition_attempts: list[dict[str, object]] = []

    result = state_machine_module._compose_configured_reference_scope_plan(
        graph=graph,
        normalization_plan=plan,
        configured_scope=selection,
        available_evidence=candidate,
        current_identity_by_serial=current_identity_by_serial,
        normalization_authority=normalization_authority,
        prohibited_dispatcher_serials=(30,),
        composition_attempts=composition_attempts,
    )

    assert result is plan
    assert bind_calls == [(plan, selection)]
    assert [attempt["kind"] for attempt in composition_attempts] == [
        "configured_reference_scope",
        "configured_reference_semantic_predecessor",
        "configured_reference_temporary_port",
    ]
    assert [attempt["outcome"] for attempt in composition_attempts] == [
        "rejected",
        "rejected",
        "accepted",
    ]
    assert tuple(call["boundary_anchor_ea"] for call in boundary_calls) == (
        0x1200,
        0x1100,
        0x1200,
    )


def test_semantic_evidence_spine_declares_fragment_publication_authority() -> None:
    specs = semantic_evidence_state_machine_passes()

    assert tuple(spec.name for spec in specs) == (
        "recover_dispatcher",
        "recover_state_transitions",
        "plan_semantic_regions",
        "lower_state_machine",
    )
    assert specs[-1].pass_factory is LowerCanonicalSemanticFragment
    assert specs[-1].backend_route is BackendRoute.FRAGMENT_PUBLICATION
    assert BOUND_CANONICAL_SEMANTIC_EVIDENCE not in specs[-1].analyses.required
