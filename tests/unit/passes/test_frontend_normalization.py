"""Portable early frontend-normalization pass contracts."""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest

from d810.analyses.control_flow.frontend_normalization import (
    DetachedSemanticClosureImportRequest,
    FrontendNormalizationEvidence,
    NativeIndirectTransferProof,
    NativeTransferEndpoint,
    NativeTransferShape,
    plan_detached_semantic_closure_import,
)
from d810.analyses.control_flow.native_semantic_closure import (
    NativeBlock,
    NativeCfg,
    NativeEdge,
    NativeEdgeKind,
    NativeRange,
    NativeSemanticClosure,
    NativeTerminalKind,
    ProvenInternalEdge,
)
from d810.capabilities.frontend_normalization import (
    FrontendNormalizationEvidenceCapability,
)
from d810.capabilities.resolver import CapabilitySet
from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
from d810.ir.flowgraph import (
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)
from d810.ir.maturity import IRMaturity
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.passes.analysis_manager import AnalysisManager
from d810.passes.frontend_normalization import (
    DETACHED_SEMANTIC_CLOSURE_IMPORT,
    FRONTEND_NORMALIZATION_EVIDENCE,
    NATIVE_INDIRECT_TRANSFER_EVIDENCE,
    ImportDetachedSemanticClosure,
    NormalizeComputedBranch,
    ResolveNativeIndirectTransfers,
    standard_frontend_normalization_passes,
)
from d810.passes.pass_pipeline import (
    BackendRoute,
    FunctionPipelineContext,
)
from d810.transforms.fragment_plan import (
    FragmentBlockMaterialization,
    FragmentBlockRole,
    FragmentEdge,
    FragmentPublicationPurpose,
)
from d810.transforms.frontend_normalization import (
    plan_frontend_computed_branch_normalization,
)
from tests.native_preanalysis import make_native_key


NATIVE_KEY = make_native_key(function_rva=0x1000)


def _identity(start_ea: int, end_ea: int | None = None) -> StableBlockIdentity:
    end_ea = start_ea + 0x10 if end_ea is None else end_ea
    return StableBlockIdentity.from_intervals(
        (NativeEaInterval(start_ea, end_ea),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(start_ea,),
    )


def _insn(
    ea: int,
    kind: InsnKind,
    *,
    target: int | None = None,
) -> InsnSnapshot:
    destination = (
        None
        if target is None
        else MopSnapshot(
            kind=OperandKind.BLOCK,
            block_ref=int(target),
            size=8,
        )
    )
    return InsnSnapshot(
        opcode=max(1, int(ea) & 0xFF),
        ea=int(ea),
        operands=() if destination is None else (destination,),
        d=destination,
        kind=kind,
        is_conditional_jump=kind is InsnKind.COND_JUMP,
        is_unconditional_jump=kind is InsnKind.GOTO,
    )


def _block(
    serial: int,
    start_ea: int,
    succs: tuple[int, ...],
    preds: tuple[int, ...],
    insns: tuple[InsnSnapshot, ...],
) -> BlockSnapshot:
    return BlockSnapshot(
        serial=int(serial),
        block_type=len(succs),
        succs=succs,
        preds=preds,
        flags=0,
        start_ea=int(start_ea),
        insn_snapshots=insns,
    )


def _graph(*, faithful: bool, include_false_target: bool = True) -> FlowGraph:
    source_succs = (3, 2) if faithful else (2,)
    blocks = {
        0: _block(0, 0x1000, (1,), (), (_insn(0x1000, InsnKind.GOTO),)),
        1: _block(
            1,
            0x1100,
            source_succs,
            (0,),
            (
                _insn(0x1100, InsnKind.SUB),
                _insn(0x1101, InsnKind.COND_JUMP, target=2),
            ),
        ),
        2: _block(
            2,
            0x1200,
            (),
            (1,),
            (_insn(0x1200, InsnKind.RET),),
        ),
    }
    if include_false_target:
        blocks[3] = _block(
            3,
            0x1300,
            (),
            (1,) if faithful else (),
            (_insn(0x1300, InsnKind.RET),),
        )
    return FlowGraph(blocks=blocks, entry_serial=0, func_ea=0x1000)


def _conditional_proof(
    *,
    provenance: tuple[tuple[str, str], ...] = (),
) -> NativeIndirectTransferProof:
    source = _identity(0x1100)
    return NativeIndirectTransferProof(
        proof_id="conditional@0x1101",
        atomic_group_id="frontend-normalization:g7",
        shape=NativeTransferShape.CONDITIONAL,
        source_identity=source,
        source_anchor_ea=0x1101,
        endpoints=(
            NativeTransferEndpoint(
                role=SemanticEdgeRole.CONDITIONAL_TAKEN,
                identity=_identity(0x1200),
                anchor_ea=0x1200,
            ),
            NativeTransferEndpoint(
                role=SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
                identity=_identity(0x1300),
                anchor_ea=0x1300,
            ),
        ),
        predicate_anchor_ea=0x1101,
        condition_producer_ea=0x1100,
        flag_corridor=(source,),
        permitted_flag_write_eas=frozenset({0x1100}),
        diagnostic_provenance=provenance,
    )


def _evidence(
    *,
    closure: NativeSemanticClosure | None = None,
    native_cfg: NativeCfg | None = None,
    provenance: tuple[tuple[str, str], ...] = (),
) -> FrontendNormalizationEvidence:
    return FrontendNormalizationEvidence(
        native_key=NATIVE_KEY,
        generation=7,
        atomic_group_id="frontend-normalization:g7",
        transfer_proofs=(_conditional_proof(provenance=provenance),),
        semantic_closure=closure,
        native_cfg=native_cfg,
    )


def _closure() -> NativeSemanticClosure:
    return NativeSemanticClosure(
        included_block_eas=(0x1300,),
        native_ranges=(NativeRange(0x1300, 0x1310),),
        proven_internal_edges=(),
        abstentions=(),
        seed_provenance=(),
    )


def _native_cfg() -> NativeCfg:
    return NativeCfg(
        {
            0x1300: NativeBlock(
                start_ea=0x1300,
                end_ea=0x1310,
                terminal=NativeTerminalKind.RETURN,
            ),
        }
    )


def _context(
    graph: FlowGraph,
    *,
    capabilities: CapabilitySet | None = None,
    facts: AnalysisManager | None = None,
) -> FunctionPipelineContext:
    return FunctionPipelineContext(
        source=SimpleNamespace(
            flow_graph=graph,
            func_ea=graph.func_ea,
            live_source=object(),
        ),
        graph=graph,
        maturity=IRMaturity.CANONICAL,
        project_config=None,
        facts=facts if facts is not None else AnalysisManager(graph),
        capabilities=capabilities if capabilities is not None else CapabilitySet(),
    )


def test_conditional_native_transfer_proof_requires_both_arms_and_flag_corridor() -> None:
    proof = _conditional_proof()

    assert proof.shape is NativeTransferShape.CONDITIONAL
    assert {endpoint.role for endpoint in proof.endpoints} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN,
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
    }
    assert proof.condition_producer_ea == 0x1100
    assert proof.predicate_anchor_ea == 0x1101

    with pytest.raises(ValueError, match="both conditional roles"):
        replace(proof, endpoints=proof.endpoints[:1])
    with pytest.raises(ValueError, match="flag corridor"):
        replace(proof, flag_corridor=())


def test_provider_provenance_is_diagnostic_and_does_not_change_plan() -> None:
    first = plan_frontend_computed_branch_normalization(
        _graph(faithful=False),
        _evidence(provenance=(("provider", "native-static"),)),
    )
    second = plan_frontend_computed_branch_normalization(
        _graph(faithful=False),
        _evidence(provenance=(("provider", "differential-oracle"),)),
    )

    assert first == second


def test_import_request_names_only_missing_proven_closure_entries() -> None:
    request = plan_detached_semantic_closure_import(
        _graph(faithful=False, include_false_target=False),
        _evidence(closure=_closure(), native_cfg=_native_cfg()),
    )

    assert request == DetachedSemanticClosureImportRequest(
        native_key=NATIVE_KEY,
        generation=7,
        atomic_group_id="frontend-normalization:g7",
        required_entry_eas=(0x1300,),
        native_ranges=(NativeRange(0x1300, 0x1310),),
        proof_ids=("conditional@0x1101",),
        semantic_closure=_closure(),
        native_cfg=_native_cfg(),
    )
    assert (
        plan_detached_semantic_closure_import(
            _graph(faithful=True),
            _evidence(closure=_closure(), native_cfg=_native_cfg()),
        )
        is None
    )


def test_missing_target_is_staged_inside_the_same_normalization_fragment() -> None:
    plan = plan_frontend_computed_branch_normalization(
        _graph(faithful=False, include_false_target=False),
        _evidence(closure=_closure(), native_cfg=_native_cfg()),
    )

    assert plan is not None
    imported = tuple(
        block for block in plan.blocks if block.role is FragmentBlockRole.IMPORTED
    )
    assert len(imported) == 1
    assert (
        imported[0].materialization
        is FragmentBlockMaterialization.IMPORT_NATIVE
    )
    assert imported[0].semantic_anchor_ea == 0x1300
    assert len(plan.native_bodies) == 1
    assert plan.native_bodies[0].entry_block_ids == (imported[0].block_id,)
    operation = plan.operations[0]
    fallthrough = next(
        edge
        for edge in operation.edges
        if edge.role is SemanticEdgeRole.CONDITIONAL_FALLTHROUGH
    )
    assert fallthrough.target_block_id == imported[0].block_id


def test_imported_call_continuation_keeps_its_portable_fallthrough_role() -> None:
    call_ea = 0x1308
    continuation_ea = 0x1310
    closure = NativeSemanticClosure(
        included_block_eas=(0x1300, continuation_ea),
        native_ranges=(NativeRange(0x1300, 0x1320),),
        proven_internal_edges=(
            ProvenInternalEdge(
                source_ea=0x1300,
                target_ea=continuation_ea,
                kind=NativeEdgeKind.CALL_FALLTHROUGH,
            ),
        ),
        abstentions=(),
        seed_provenance=(),
    )
    native_cfg = NativeCfg(
        {
            0x1300: NativeBlock(
                start_ea=0x1300,
                end_ea=continuation_ea,
                outgoing_edges=(
                    NativeEdge(
                        kind=NativeEdgeKind.CALL_FALLTHROUGH,
                        target_ea=continuation_ea,
                        source_instruction_ea=call_ea,
                    ),
                ),
            ),
            continuation_ea: NativeBlock(
                start_ea=continuation_ea,
                end_ea=0x1320,
                terminal=NativeTerminalKind.RETURN,
            ),
        }
    )

    plan = plan_frontend_computed_branch_normalization(
        _graph(faithful=False, include_false_target=False),
        _evidence(closure=closure, native_cfg=native_cfg),
    )

    assert plan is not None
    call_source = next(
        block
        for block in plan.blocks
        if block.semantic_anchor_ea == 0x1300
        and block.role is FragmentBlockRole.IMPORTED
    )
    continuation = next(
        block
        for block in plan.blocks
        if block.semantic_anchor_ea == continuation_ea
        and block.role is FragmentBlockRole.IMPORTED
    )
    operation = next(
        operation
        for operation in plan.operations
        if operation.source_block_id == call_source.block_id
    )
    assert operation.edges == (
        FragmentEdge(
            role=SemanticEdgeRole.CALL_FALLTHROUGH,
            target_block_id=continuation.block_id,
        ),
    )


def test_normalization_plan_replaces_lost_branch_with_one_atomic_two_arm_operation() -> None:
    plan = plan_frontend_computed_branch_normalization(
        _graph(faithful=False),
        _evidence(),
    )

    assert plan is not None
    assert (
        plan.publication_purpose
        is FragmentPublicationPurpose.FRONTEND_NORMALIZATION
    )
    assert plan.atomic_group_id == "frontend-normalization:g7"
    assert len(plan.roots) == 1
    assert len(plan.owned_originals) == 1
    operation = plan.operations[0]
    assert operation.predicate_anchor_ea == 0x1101
    assert {edge.role for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN,
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
    }
    assert len(plan.flag_corridors) == 1
    assert plan.flag_corridors[0].producer.instruction_ea == 0x1100
    assert plan.flag_corridors[0].consumer.instruction_ea == 0x1101


def test_normalization_abstains_when_live_graph_already_preserves_both_arms() -> None:
    assert (
        plan_frontend_computed_branch_normalization(
            _graph(faithful=True),
            _evidence(),
        )
        is None
    )


def test_frontend_normalization_capability_is_structural() -> None:
    evidence = _evidence()

    class _Provider:
        def evidence_for(self, function_ea: int):
            return evidence if function_ea == 0x1000 else None

    assert isinstance(_Provider(), FrontendNormalizationEvidenceCapability)


def test_early_passes_are_ordered_and_separate_analysis_from_publication() -> None:
    specs = standard_frontend_normalization_passes()

    assert tuple(spec.pass_id for spec in specs) == (
        "resolve_native_indirect_transfers",
        "import_detached_semantic_closure",
        "normalize_computed_branch",
    )
    assert tuple(spec.backend_route for spec in specs) == (
        BackendRoute.ANALYSIS_ONLY,
        BackendRoute.ANALYSIS_ONLY,
        BackendRoute.FRAGMENT_PUBLICATION,
    )
    assert all(spec.enabled_at(IRMaturity.CANONICAL) for spec in specs)
    assert not any(spec.enabled_at(IRMaturity.LOCAL_OPTIMIZED) for spec in specs)


def test_resolve_pass_publishes_typed_portable_evidence_only() -> None:
    evidence = _evidence()

    class _Provider:
        def evidence_for(self, function_ea: int):
            return evidence

    ctx = _context(
        _graph(faithful=False),
        capabilities=CapabilitySet().with_capability(
            FrontendNormalizationEvidenceCapability,
            _Provider(),
        ),
    )

    result = ResolveNativeIndirectTransfers().run(ctx)

    assert result.fragment_plan is None
    assert not result.rewrite_plan.steps
    assert result.analysis_outputs == {
        FRONTEND_NORMALIZATION_EVIDENCE: evidence,
    }
    assert result.evidence_outputs == {
        NATIVE_INDIRECT_TRANSFER_EVIDENCE: evidence,
    }


def test_import_and_normalize_passes_consume_the_resolved_analysis() -> None:
    graph = _graph(faithful=False, include_false_target=False)
    facts = AnalysisManager(graph)
    evidence = _evidence(closure=_closure(), native_cfg=_native_cfg())
    facts.put_analysis(FRONTEND_NORMALIZATION_EVIDENCE, evidence)
    import_result = ImportDetachedSemanticClosure().run(
        _context(graph, facts=facts)
    )

    assert import_result.analysis_outputs == {
        DETACHED_SEMANTIC_CLOSURE_IMPORT: plan_detached_semantic_closure_import(
            graph,
            evidence,
        )
    }

    complete_graph = _graph(faithful=False)
    complete_facts = AnalysisManager(complete_graph)
    complete_facts.put_analysis(FRONTEND_NORMALIZATION_EVIDENCE, evidence)
    normalize_result = NormalizeComputedBranch().run(
        _context(complete_graph, facts=complete_facts)
    )

    assert normalize_result.fragment_plan is not None
    assert (
        normalize_result.fragment_plan.publication_purpose
        is FragmentPublicationPurpose.FRONTEND_NORMALIZATION
    )
