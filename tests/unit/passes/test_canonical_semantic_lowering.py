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
)
from d810.core.fragment_authority import NormalizationWorkItemAuthority
from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
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
from d810.transforms.plan import PatchPlan
from tests.native_preanalysis import make_native_key


NATIVE_KEY = make_native_key(function_rva=0x1000)


def _identity(ea: int) -> StableBlockIdentity:
    return StableBlockIdentity.from_intervals(
        (NativeEaInterval(ea, ea + 1),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(ea,),
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
                ),
            ),
        ),
    )
    bound = bind_canonical_semantic_evidence(graph, evidence)
    assert bound is not None
    return graph, bound


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
            return (
                frontend_evidence
                if int(function_ea) == graph.func_ea
                else None
            )

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
        SimpleNamespace(
            identity_for_serial=current_identity_by_serial.get,
        ),
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
    composition_calls = [
        call for call in calls if call[0] == "composition"
    ]
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
    assert (
        BOUND_CANONICAL_SEMANTIC_EVIDENCE
        not in specs[-1].analyses.required
    )
