"""Canonical state-machine lowering publishes one portable semantic fragment."""

from __future__ import annotations

from types import SimpleNamespace

from d810.analyses.control_flow.semantic_route_evidence import (
    CanonicalSemanticEvidence,
    SemanticRouteDestination,
    SemanticRouteProof,
    SemanticRouteProofKind,
    SemanticRouteShape,
    SemanticStateWriteProof,
    bind_canonical_semantic_evidence,
)
from d810.capabilities.resolver import CapabilitySet
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
from d810.transforms.fragment_plan import FragmentPublicationPurpose
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
