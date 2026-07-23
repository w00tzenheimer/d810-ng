"""Portable early frontend-normalization pass contracts."""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest

from d810.analyses.control_flow.frontend_normalization import (
    DetachedSemanticClosureImportRequest,
    FrontendNormalizationEvidence,
    FrontendNormalizationEvidenceRejected,
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
    plan_next_frontend_normalization_work_item,
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


def _direct_proof(
    *,
    proof_id: str,
    source_ea: int,
    target_ea: int,
) -> NativeIndirectTransferProof:
    return NativeIndirectTransferProof(
        proof_id=proof_id,
        atomic_group_id="frontend-normalization:g7",
        shape=NativeTransferShape.DIRECT,
        source_identity=_identity(source_ea),
        source_anchor_ea=source_ea,
        endpoints=(
            NativeTransferEndpoint(
                role=SemanticEdgeRole.DIRECT,
                identity=_identity(target_ea),
                anchor_ea=target_ea,
            ),
        ),
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


def test_conditional_native_transfer_proof_requires_both_arms_and_flag_corridor() -> (
    None
):
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


def test_import_request_names_missing_source_and_destination_roots() -> None:
    graph = FlowGraph(
        blocks={
            0: _block(
                0,
                0x1000,
                (2,),
                (),
                (_insn(0x1000, InsnKind.GOTO, target=2),),
            ),
            2: _block(
                2,
                0x1200,
                (),
                (0,),
                (_insn(0x1200, InsnKind.RET),),
            ),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    closure = NativeSemanticClosure(
        included_block_eas=(0x1100, 0x1300),
        native_ranges=(
            NativeRange(0x1100, 0x1110),
            NativeRange(0x1300, 0x1310),
        ),
        proven_internal_edges=(
            ProvenInternalEdge(
                source_ea=0x1100,
                target_ea=0x1300,
                kind=NativeEdgeKind.CONDITIONAL_FALSE,
            ),
        ),
        abstentions=(),
        seed_provenance=(),
    )
    native_cfg = NativeCfg(
        {
            0x1100: NativeBlock(
                start_ea=0x1100,
                end_ea=0x1110,
                outgoing_edges=(
                    NativeEdge(
                        kind=NativeEdgeKind.CONDITIONAL_TRUE,
                        target_ea=0x1200,
                    ),
                    NativeEdge(
                        kind=NativeEdgeKind.CONDITIONAL_FALSE,
                        target_ea=0x1300,
                    ),
                ),
            ),
            0x1300: NativeBlock(
                start_ea=0x1300,
                end_ea=0x1310,
                terminal=NativeTerminalKind.RETURN,
            ),
        }
    )

    request = plan_detached_semantic_closure_import(
        graph,
        _evidence(closure=closure, native_cfg=native_cfg),
    )

    assert request is not None
    assert request.required_entry_eas == (0x1100, 0x1300)
    assert request.proof_ids == ("conditional@0x1101",)


def test_next_work_item_selects_one_connected_missing_body_component() -> None:
    graph = FlowGraph(
        blocks={
            0: _block(
                0,
                0x1000,
                (1, 4),
                (),
                (_insn(0x1000, InsnKind.COND_JUMP, target=4),),
            ),
            1: _block(
                1,
                0x1100,
                (2,),
                (0,),
                (_insn(0x1100, InsnKind.INDIRECT_JUMP),),
            ),
            2: _block(
                2,
                0x1200,
                (),
                (1,),
                (_insn(0x1200, InsnKind.RET),),
            ),
            4: _block(
                4,
                0x1400,
                (5,),
                (0,),
                (_insn(0x1400, InsnKind.INDIRECT_JUMP),),
            ),
            5: _block(
                5,
                0x1500,
                (),
                (4,),
                (_insn(0x1500, InsnKind.RET),),
            ),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    closure = NativeSemanticClosure(
        included_block_eas=(0x1300, 0x1600),
        native_ranges=(
            NativeRange(0x1300, 0x1310),
            NativeRange(0x1600, 0x1610),
        ),
        proven_internal_edges=(),
        abstentions=(),
        seed_provenance=(),
    )
    native_cfg = NativeCfg(
        {
            0x1300: NativeBlock(
                start_ea=0x1300,
                end_ea=0x1310,
                terminal=NativeTerminalKind.RETURN,
            ),
            0x1600: NativeBlock(
                start_ea=0x1600,
                end_ea=0x1610,
                terminal=NativeTerminalKind.RETURN,
            ),
        }
    )
    evidence = FrontendNormalizationEvidence(
        native_key=NATIVE_KEY,
        generation=7,
        atomic_group_id="frontend-normalization:g7",
        transfer_proofs=(
            _direct_proof(
                proof_id="direct@0x1100",
                source_ea=0x1100,
                target_ea=0x1300,
            ),
            _direct_proof(
                proof_id="direct@0x1400",
                source_ea=0x1400,
                target_ea=0x1600,
            ),
        ),
        semantic_closure=closure,
        native_cfg=native_cfg,
    )

    plan = plan_next_frontend_normalization_work_item(graph, evidence)

    assert plan is not None
    assert len(plan.roots) == 1
    assert plan.block(plan.roots[0]).semantic_anchor_ea == 0x1100
    assert tuple(operation.operation_id for operation in plan.operations) == (
        "direct@0x1100",
    )
    assert plan.work_item_scope is not None
    assert plan.work_item_scope.selected_obligation_ids == ("direct@0x1100",)
    assert plan.work_item_scope.remaining_obligation_ids == ("direct@0x1400",)
    assert len(plan.native_bodies) == 1
    native_body = plan.native_bodies[0]
    assert native_body.proof_ids == ("direct@0x1100",)
    assert tuple(
        plan.block(block_id).semantic_anchor_ea
        for block_id in native_body.block_ids
    ) == (0x1300,)
    assert native_body.native_ranges == (NativeEaInterval(0x1300, 0x1310),)


def test_next_work_item_selects_smallest_complete_root_component() -> None:
    graph = FlowGraph(
        blocks={
            0: _block(
                0,
                0x1000,
                (1, 4),
                (),
                (_insn(0x1000, InsnKind.COND_JUMP, target=4),),
            ),
            1: _block(
                1,
                0x1100,
                (2,),
                (0,),
                (_insn(0x1100, InsnKind.INDIRECT_JUMP),),
            ),
            2: _block(
                2,
                0x1200,
                (),
                (1,),
                (_insn(0x1200, InsnKind.RET),),
            ),
            4: _block(
                4,
                0x1400,
                (5,),
                (0,),
                (_insn(0x1400, InsnKind.INDIRECT_JUMP),),
            ),
            5: _block(
                5,
                0x1500,
                (),
                (4,),
                (_insn(0x1500, InsnKind.RET),),
            ),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    closure = NativeSemanticClosure(
        included_block_eas=(0x1300, 0x1310, 0x1600),
        native_ranges=(
            NativeRange(0x1300, 0x1310),
            NativeRange(0x1310, 0x1320),
            NativeRange(0x1600, 0x1610),
        ),
        proven_internal_edges=(
            ProvenInternalEdge(
                source_ea=0x1300,
                target_ea=0x1310,
                kind=NativeEdgeKind.DIRECT_JUMP,
            ),
        ),
        abstentions=(),
        seed_provenance=(),
    )
    native_cfg = NativeCfg(
        {
            0x1300: NativeBlock(
                start_ea=0x1300,
                end_ea=0x1310,
                outgoing_edges=(
                    NativeEdge(
                        kind=NativeEdgeKind.DIRECT_JUMP,
                        target_ea=0x1310,
                    ),
                ),
            ),
            0x1310: NativeBlock(
                start_ea=0x1310,
                end_ea=0x1320,
                terminal=NativeTerminalKind.RETURN,
            ),
            0x1600: NativeBlock(
                start_ea=0x1600,
                end_ea=0x1610,
                terminal=NativeTerminalKind.RETURN,
            ),
        }
    )
    evidence = FrontendNormalizationEvidence(
        native_key=NATIVE_KEY,
        generation=7,
        atomic_group_id="frontend-normalization:g7",
        transfer_proofs=(
            _direct_proof(
                proof_id="direct@0x1100",
                source_ea=0x1100,
                target_ea=0x1300,
            ),
            _direct_proof(
                proof_id="direct@0x1400",
                source_ea=0x1400,
                target_ea=0x1600,
            ),
        ),
        semantic_closure=closure,
        native_cfg=native_cfg,
    )

    plan = plan_next_frontend_normalization_work_item(graph, evidence)

    assert plan is not None
    assert len(plan.roots) == 1
    assert plan.block(plan.roots[0]).semantic_anchor_ea == 0x1400
    assert tuple(operation.operation_id for operation in plan.operations) == (
        "direct@0x1400",
    )
    assert plan.work_item_scope is not None
    assert plan.work_item_scope.selected_obligation_ids == ("direct@0x1400",)
    assert plan.work_item_scope.remaining_obligation_ids == ("direct@0x1100",)
    assert len(plan.native_bodies) == 1
    native_body = plan.native_bodies[0]
    assert tuple(
        plan.block(block_id).semantic_anchor_ea
        for block_id in native_body.block_ids
    ) == (0x1600,)


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
    assert imported[0].materialization is FragmentBlockMaterialization.IMPORT_NATIVE
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


def test_detached_publication_excludes_an_unreachable_closure_seed_prefix() -> None:
    closure = NativeSemanticClosure(
        included_block_eas=(0x1050, 0x1300),
        native_ranges=(
            NativeRange(0x1050, 0x1060),
            NativeRange(0x1300, 0x1310),
        ),
        proven_internal_edges=(),
        abstentions=(),
        seed_provenance=(),
    )
    native_cfg = NativeCfg(
        {
            0x1050: NativeBlock(
                start_ea=0x1050,
                end_ea=0x1060,
                outgoing_edges=(
                    NativeEdge(
                        kind=NativeEdgeKind.DIRECT_JUMP,
                        target_ea=0x1100,
                    ),
                ),
            ),
            0x1300: NativeBlock(
                start_ea=0x1300,
                end_ea=0x1310,
                terminal=NativeTerminalKind.RETURN,
            ),
        }
    )

    plan = plan_frontend_computed_branch_normalization(
        _graph(faithful=False, include_false_target=False),
        _evidence(closure=closure, native_cfg=native_cfg),
    )

    assert plan is not None
    assert tuple(
        block.semantic_anchor_ea
        for block in plan.blocks
        if block.role is FragmentBlockRole.IMPORTED
    ) == (0x1300,)
    assert plan.native_bodies[0].block_ids == (
        next(
            block.block_id
            for block in plan.blocks
            if block.role is FragmentBlockRole.IMPORTED
        ),
    )


def test_missing_downstream_transfer_source_is_normalized_inside_the_same_fragment() -> (
    None
):
    imported_source_ea = 0x1400
    imported_predicate_ea = 0x1401
    imported_taken_ea = 0x1500
    imported_fallthrough_ea = 0x1600
    live_proof = replace(
        _conditional_proof(),
        endpoints=(
            _conditional_proof().endpoints[0],
            NativeTransferEndpoint(
                role=SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
                identity=_identity(imported_source_ea, 0x1420),
                anchor_ea=imported_source_ea,
            ),
        ),
    )
    imported_source_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(imported_predicate_ea, 0x1420),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(imported_predicate_ea,),
    )
    imported_condition_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(imported_source_ea, imported_predicate_ea),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(imported_source_ea,),
    )
    imported_proof = NativeIndirectTransferProof(
        proof_id="conditional@0x1401",
        atomic_group_id="frontend-normalization:g7",
        shape=NativeTransferShape.CONDITIONAL,
        source_identity=imported_source_identity,
        source_anchor_ea=imported_predicate_ea,
        endpoints=(
            NativeTransferEndpoint(
                role=SemanticEdgeRole.CONDITIONAL_TAKEN,
                identity=_identity(imported_taken_ea),
                anchor_ea=imported_taken_ea,
            ),
            NativeTransferEndpoint(
                role=SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
                identity=_identity(imported_fallthrough_ea),
                anchor_ea=imported_fallthrough_ea,
            ),
        ),
        predicate_anchor_ea=imported_predicate_ea,
        condition_producer_ea=imported_source_ea,
        flag_corridor=(
            imported_condition_identity,
            imported_source_identity,
        ),
        permitted_flag_write_eas=frozenset({imported_source_ea}),
    )
    closure = NativeSemanticClosure(
        included_block_eas=(
            imported_source_ea,
            imported_taken_ea,
            imported_fallthrough_ea,
        ),
        native_ranges=(NativeRange(imported_source_ea, 0x1610),),
        proven_internal_edges=(),
        abstentions=(),
        seed_provenance=(),
    )
    native_cfg = NativeCfg(
        {
            imported_source_ea: NativeBlock(
                start_ea=imported_source_ea,
                end_ea=0x1420,
                outgoing_edges=(
                    NativeEdge(
                        kind=NativeEdgeKind.INDIRECT,
                        target_ea=imported_taken_ea,
                        resolver_proven=True,
                        source_instruction_ea=0x141F,
                    ),
                    NativeEdge(
                        kind=NativeEdgeKind.INDIRECT,
                        target_ea=imported_fallthrough_ea,
                        resolver_proven=True,
                        source_instruction_ea=0x141F,
                    ),
                ),
            ),
            imported_taken_ea: NativeBlock(
                start_ea=imported_taken_ea,
                end_ea=0x1510,
                terminal=NativeTerminalKind.RETURN,
            ),
            imported_fallthrough_ea: NativeBlock(
                start_ea=imported_fallthrough_ea,
                end_ea=0x1610,
                terminal=NativeTerminalKind.RETURN,
            ),
        }
    )
    evidence = replace(
        _evidence(closure=closure, native_cfg=native_cfg),
        transfer_proofs=(live_proof, imported_proof),
    )

    plan = plan_frontend_computed_branch_normalization(
        _graph(faithful=False, include_false_target=False),
        evidence,
    )

    assert plan is not None
    imported_source = next(
        block
        for block in plan.blocks
        if block.role is FragmentBlockRole.IMPORTED
        and block.semantic_anchor_ea == imported_source_ea
    )
    assert imported_source.stable_identity is not None
    assert imported_source.stable_identity.native_ranges.intervals == (
        NativeEaInterval(imported_source_ea, 0x1420),
    )
    assert imported_source.stable_identity.exact_instruction_eas == frozenset(
        {imported_source_ea, imported_predicate_ea}
    )
    imported_operation = tuple(
        operation
        for operation in plan.operations
        if operation.source_block_id == imported_source.block_id
    )
    assert len(imported_operation) == 1
    assert imported_operation[0].predicate_anchor_ea == imported_predicate_ea
    assert {edge.role for edge in imported_operation[0].edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN,
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
    }
    imported_corridor = next(
        corridor
        for corridor in plan.flag_corridors
        if corridor.consumer.instruction_ea == imported_predicate_ea
    )
    assert imported_corridor.block_path == (imported_source.block_id,)


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


def test_unavailable_detached_target_rejection_names_both_native_anchors() -> None:
    closure = NativeSemanticClosure(
        included_block_eas=(0x1300, 0x1400),
        native_ranges=(
            NativeRange(0x1300, 0x1310),
            NativeRange(0x1400, 0x1410),
        ),
        proven_internal_edges=(
            ProvenInternalEdge(
                source_ea=0x1300,
                target_ea=0x1400,
                kind=NativeEdgeKind.DIRECT_JUMP,
            ),
        ),
        abstentions=(),
        seed_provenance=(),
    )
    native_cfg = NativeCfg(
        {
            0x1300: NativeBlock(
                start_ea=0x1300,
                end_ea=0x1310,
                outgoing_edges=(
                    NativeEdge(
                        kind=NativeEdgeKind.DIRECT_JUMP,
                        target_ea=0x1400,
                    ),
                ),
            ),
            0x1400: NativeBlock(
                start_ea=0x1400,
                end_ea=0x1410,
                outgoing_edges=(
                    NativeEdge(
                        kind=NativeEdgeKind.DIRECT_JUMP,
                        target_ea=0x1500,
                    ),
                ),
            ),
        }
    )

    with pytest.raises(
        FrontendNormalizationEvidenceRejected,
        match=(
            r"detached block 0x1400 direct_jump target "
            r"0x1500 is unavailable"
        ),
    ):
        plan_frontend_computed_branch_normalization(
            _graph(faithful=False, include_false_target=False),
            _evidence(closure=closure, native_cfg=native_cfg),
        )


def test_normalization_plan_replaces_lost_branch_with_one_atomic_two_arm_operation() -> (
    None
):
    plan = plan_frontend_computed_branch_normalization(
        _graph(faithful=False),
        _evidence(),
    )

    assert plan is not None
    assert plan.publication_purpose is FragmentPublicationPurpose.FRONTEND_NORMALIZATION
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


def test_normalization_coalesces_adjacent_corridor_segments_in_one_live_block() -> None:
    producer_identity = _identity(0x1100, 0x1101)
    predicate_identity = _identity(0x1101, 0x1110)
    proof = replace(
        _conditional_proof(),
        source_identity=predicate_identity,
        flag_corridor=(producer_identity, predicate_identity),
    )
    evidence = replace(_evidence(), transfer_proofs=(proof,))

    plan = plan_frontend_computed_branch_normalization(
        _graph(faithful=False),
        evidence,
    )

    assert plan is not None
    (corridor,) = plan.flag_corridors
    assert len(corridor.block_path) == 1
    assert corridor.producer.block_id == corridor.consumer.block_id


def test_normalization_ignores_unreferenced_synthetic_blocks() -> None:
    graph = _graph(faithful=False)
    blocks = dict(graph.blocks)
    blocks[4] = _block(
        4,
        0xFFFFFFFFFFFFFFFF,
        (),
        (),
        (),
    )

    plan = plan_frontend_computed_branch_normalization(
        FlowGraph(
            blocks=blocks,
            entry_serial=graph.entry_serial,
            func_ea=graph.func_ea,
        ),
        _evidence(),
    )

    assert plan is not None
    assert all(block.semantic_anchor_ea != 0xFFFFFFFFFFFFFFFF for block in plan.blocks)


def test_normalization_prefers_conditional_owner_over_same_ea_trampoline() -> None:
    graph = FlowGraph(
        blocks={
            0: _block(
                0,
                0x1000,
                (1,),
                (),
                (_insn(0x1000, InsnKind.GOTO, target=1),),
            ),
            1: _block(
                1,
                0x1100,
                (4, 3),
                (0,),
                (
                    _insn(0x1100, InsnKind.SUB),
                    _insn(0x1101, InsnKind.COND_JUMP, target=4),
                ),
            ),
            2: _block(
                2,
                0x1200,
                (),
                (4,),
                (_insn(0x1200, InsnKind.RET),),
            ),
            3: _block(
                3,
                0x1300,
                (),
                (1,),
                (_insn(0x1300, InsnKind.RET),),
            ),
            4: _block(
                4,
                0x1101,
                (2,),
                (1,),
                (
                    _insn(0x1101, InsnKind.MOV),
                    _insn(0x1101, InsnKind.GOTO, target=2),
                ),
            ),
        },
        entry_serial=0,
        func_ea=0x1000,
    )

    plan = plan_frontend_computed_branch_normalization(
        graph,
        _evidence(),
    )

    assert plan is not None
    operation = plan.operations[0]
    assert plan.block(operation.source_block_id).semantic_anchor_ea == 0x1100


def test_normalization_publishes_only_owned_boundary_roots() -> None:
    graph = FlowGraph(
        blocks={
            0: _block(
                0,
                0x1000,
                (6,),
                (),
                (_insn(0x1000, InsnKind.GOTO, target=6),),
            ),
            1: _block(
                1,
                0x1100,
                (2,),
                (5,),
                (_insn(0x1100, InsnKind.GOTO, target=2),),
            ),
            2: _block(
                2,
                0x1200,
                (4,),
                (1,),
                (_insn(0x1200, InsnKind.GOTO, target=4),),
            ),
            3: _block(
                3,
                0x1300,
                (8,),
                (),
                (_insn(0x1300, InsnKind.GOTO, target=8),),
            ),
            4: _block(
                4,
                0x1400,
                (7,),
                (2,),
                (_insn(0x1400, InsnKind.GOTO, target=7),),
            ),
            5: _block(
                5,
                0x1050,
                (1,),
                (6,),
                (_insn(0x1050, InsnKind.GOTO, target=1),),
            ),
            6: _block(
                6,
                0x1020,
                (5,),
                (0,),
                (_insn(0x1020, InsnKind.GOTO, target=5),),
            ),
            7: _block(
                7,
                0x1450,
                (),
                (4,),
                (_insn(0x1450, InsnKind.RET),),
            ),
            8: _block(
                8,
                0x1500,
                (9,),
                (3,),
                (_insn(0x1500, InsnKind.GOTO, target=9),),
            ),
            9: _block(
                9,
                0x1550,
                (),
                (8,),
                (_insn(0x1550, InsnKind.RET),),
            ),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    evidence = replace(
        _evidence(),
        transfer_proofs=(
            _direct_proof(
                proof_id="direct@0x1100",
                source_ea=0x1100,
                target_ea=0x1200,
            ),
            _direct_proof(
                proof_id="direct@0x1200",
                source_ea=0x1200,
                target_ea=0x1300,
            ),
        ),
    )

    plan = plan_frontend_computed_branch_normalization(graph, evidence)

    assert plan is not None
    assert len(plan.owned_originals) == 2
    assert {plan.block(block_id).semantic_anchor_ea for block_id in plan.roots} == {
        0x1100
    }
    external_anchors = {
        block.semantic_anchor_ea
        for block in plan.blocks
        if block.role is FragmentBlockRole.EXTERNAL
    }
    assert {
        0x1000,
        0x1020,
        0x1050,
        0x1400,
        0x1450,
        0x1500,
        0x1550,
    } <= external_anchors


def test_normalization_rejects_when_original_route_corridor_is_not_closed() -> None:
    graph = FlowGraph(
        blocks={
            0: _block(
                0,
                0x1000,
                (1,),
                (),
                (_insn(0x1000, InsnKind.GOTO, target=1),),
            ),
            1: _block(
                1,
                0x1100,
                (2,),
                (0,),
                (_insn(0x1100, InsnKind.GOTO, target=2),),
            ),
            2: _block(
                2,
                0x1200,
                (),
                (1, 4),
                (_insn(0x1200, InsnKind.RET),),
            ),
            3: _block(
                3,
                0x1300,
                (),
                (),
                (_insn(0x1300, InsnKind.RET),),
            ),
            4: _block(
                4,
                0x1400,
                (2,),
                (),
                (_insn(0x1400, InsnKind.GOTO, target=2),),
            ),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    evidence = replace(
        _evidence(),
        transfer_proofs=(
            _direct_proof(
                proof_id="direct@0x1100",
                source_ea=0x1100,
                target_ea=0x1300,
            ),
        ),
    )

    with pytest.raises(
        FrontendNormalizationEvidenceRejected,
        match="original route corridor is not closed",
    ):
        plan_frontend_computed_branch_normalization(graph, evidence)


def test_normalization_ids_distinguish_same_range_topology_and_instruction_blocks() -> (
    None
):
    graph = _graph(faithful=False)
    blocks = dict(graph.blocks)
    blocks[2] = _block(
        2,
        0x1200,
        (4, 5),
        (1,),
        (_insn(0x1200, InsnKind.COND_JUMP, target=4),),
    )
    blocks[4] = _block(4, 0x1400, (), (2,), ())
    blocks[5] = _block(
        5,
        0x1400,
        (),
        (2,),
        (_insn(0x1400, InsnKind.RET),),
    )
    graph = FlowGraph(blocks=blocks, entry_serial=0, func_ea=0x1000)

    plan = plan_frontend_computed_branch_normalization(graph, _evidence())

    assert plan is not None
    same_anchor_blocks = tuple(
        block for block in plan.blocks if block.semantic_anchor_ea == 0x1400
    )
    assert len(same_anchor_blocks) == 2
    assert len({block.block_id for block in same_anchor_blocks}) == 2
    assert len(
        {
            block.stable_identity.exact_instruction_eas
            for block in same_anchor_blocks
            if block.stable_identity is not None
        }
    ) == 2


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
    import_result = ImportDetachedSemanticClosure().run(_context(graph, facts=facts))

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
