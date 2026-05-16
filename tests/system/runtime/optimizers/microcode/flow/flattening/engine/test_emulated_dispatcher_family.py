from __future__ import annotations

from dataclasses import asdict, replace
from types import SimpleNamespace

import idaapi
import ida_hexrays
import pytest

import d810.recon.flow.switch_case_transition_analysis as switch_case_transition_analysis
from d810.cfg.flowgraph import BlockSnapshot, FlowGraph, InsnSnapshot
from d810.cfg.graph_modification import (
    CreateConditionalRedirect,
    InsertBlock,
    PhaseCycleLowering,
    ReorderBlocks,
    RedirectGoto,
    ZeroStateWrite,
)
from d810.hexrays.mutation.deferred_modifier import DeferredGraphModifier
from d810.hexrays.mutation.ir_translator import lift as lift_mba
from d810.optimizers.microcode.flow.flattening import (
    emulated_dispatcher_family as emulated_family_module,
)
from d810.optimizers.microcode.flow.flattening.engine.provenance import (
    DecisionPhase,
    DecisionReasonCode,
    PipelineProvenance,
)
from d810.optimizers.microcode.flow.flattening.engine.runtime import (
    ExecutedPipeline,
    PlannedPipeline,
)
from d810.optimizers.microcode.flow.flattening.engine.strategy import StageResult
from d810.optimizers.microcode.flow.flattening.engine.snapshot import (
    AnalysisSnapshot,
    StateModelSummary,
)
from d810.optimizers.microcode.flow.flattening.emulated_dispatcher_family import (
    EmulatedDispatcherDetection,
    EmulatedDispatcherStrategyFamily,
    GenericDispatcherEngineProfile,
    ollvm_state_dispatcher_map_profile,
    tigress_switch_dispatcher_profile,
)
from d810.optimizers.microcode.flow.flattening.strategies.emulated_dispatcher_strategy import (
    EMULATED_DISPATCHER_CANDIDATE_RECORDS_KEY,
    EMULATED_DISPATCHER_METADATA_KEY,
    EMULATED_DISPATCHER_MODIFICATIONS_KEY,
    EMULATED_DISPATCHER_PHASE_CONTEXT_KEY,
    EmulatedDispatcherCandidateRecord,
    EmulatedDispatcherMetadata,
    EmulatedDispatcherPhaseArtifact,
    EmulatedDispatcherPhaseContext,
    EmulatedDispatcherStrategy,
    extract_emulated_dispatcher_candidate_records,
    extract_emulated_dispatcher_fallback_modifications,
    extract_emulated_dispatcher_metadata,
    extract_emulated_dispatcher_modifications,
    extract_emulated_dispatcher_phase_artifact,
)
from d810.optimizers.microcode.flow.flattening.unflattener_emulated_dispatcher_engine import (
    EmulatedDispatcherUnflattener,
)
from d810.recon.flow.dispatcher_detection import DispatcherType
from d810.recon.flow.branch_ownership import (
    BranchOwnershipProof,
    BranchOwnershipProofKind,
)
from d810.recon.flow.dispatcher_map import StateDispatcherMap, StateDispatcherRow
from d810.recon.flow.reconstruction_candidate_builder import ReconstructionCandidate
from d810.recon.flow.linearized_state_dag import SemanticEdgeKind
from d810.testing.runner import _resolve_test_project_index, get_func_ea
from tests.system.e2e.test_approov_engine_wrapper_baselines import (
    _apply_engine_wrapper_profile,
    _decompile_with_project,
    _decompile_without_d810,
    _force_rule_scope_to_current_profile,
    _get_default_binary,
    _restore_forced_rule_scope,
)


def _verify_error(mba) -> str | None:
    try:
        mba.verify(True)
    except RuntimeError as exc:
        return str(exc)
    return None


def _find_state_write_ea(
    mba,
    *,
    block_serial: int,
    expected_state: int,
    state_var_stkoff: int = 12,
) -> int:
    blk = mba.get_mblock(block_serial)
    assert blk is not None
    insn = blk.head
    while insn is not None:
        if (
            int(insn.opcode) == int(ida_hexrays.m_mov)
            and int(getattr(getattr(insn, "d", None), "t", ida_hexrays.mop_z))
            == int(ida_hexrays.mop_S)
            and int(getattr(getattr(insn, "d", None), "s", SimpleNamespace(off=-1)).off)
            == state_var_stkoff
            and int(getattr(getattr(insn, "l", None), "t", ida_hexrays.mop_z))
            == int(ida_hexrays.mop_n)
            and int(
                getattr(getattr(getattr(insn, "l", None), "nnn", None), "value", -1)
            )
            == expected_state
        ):
            return int(insn.ea)
        insn = insn.next
    raise AssertionError(
        f"missing state write block={block_serial} state={hex(expected_state)}"
    )


def _filter_emulated_dispatcher_snapshot(
    snapshot: AnalysisSnapshot,
    selected_indexes: tuple[int, ...],
) -> AnalysisSnapshot:
    selected_set = set(selected_indexes)
    metadata = extract_emulated_dispatcher_metadata(snapshot.flow_graph)
    assert metadata is not None
    modifications = extract_emulated_dispatcher_modifications(snapshot.flow_graph)
    candidate_records = extract_emulated_dispatcher_candidate_records(snapshot.flow_graph)
    selected_modifications = tuple(
        mod for idx, mod in enumerate(modifications) if idx in selected_set
    )
    selected_records = tuple(
        record
        for record in candidate_records
        if any(idx in selected_set for idx in record.selected_modification_indexes)
    )
    filtered_metadata = replace(
        metadata,
        planning_ready=bool(selected_modifications),
        planning_blocker=None if selected_modifications else metadata.planning_blocker,
        candidate_count=len(selected_modifications),
        candidate_kinds=tuple(type(mod).__name__ for mod in selected_modifications),
        candidate_records=selected_records,
    )
    flow_graph = FlowGraph(
        blocks=snapshot.flow_graph.blocks,
        entry_serial=snapshot.flow_graph.entry_serial,
        func_ea=snapshot.flow_graph.func_ea,
        metadata={
            **dict(snapshot.flow_graph.metadata),
            EMULATED_DISPATCHER_METADATA_KEY: filtered_metadata,
            EMULATED_DISPATCHER_MODIFICATIONS_KEY: selected_modifications,
            EMULATED_DISPATCHER_CANDIDATE_RECORDS_KEY: selected_records,
        },
    )
    return replace(snapshot, flow_graph=flow_graph)


def _fake_mba():
    blk = SimpleNamespace(nsucc=lambda: 0)
    return SimpleNamespace(
        qty=1,
        maturity=ida_hexrays.MMAT_GLBOPT1,
        entry_ea=0x401000,
        get_mblock=lambda _serial: blk,
        for_all_topinsns=lambda collector: None,
    )


def _flow_graph() -> FlowGraph:
    return FlowGraph(
        blocks={
            0: BlockSnapshot(
                serial=0,
                block_type=ida_hexrays.BLT_1WAY,
                succs=(),
                preds=(),
                flags=0,
                start_ea=0x401000,
                insn_snapshots=(),
            )
        },
        entry_serial=0,
        func_ea=0x401000,
    )


def _flow_graph_with_edge() -> FlowGraph:
    return FlowGraph(
        blocks={
            0: BlockSnapshot(
                serial=0,
                block_type=ida_hexrays.BLT_1WAY,
                succs=(1,),
                preds=(),
                flags=0,
                start_ea=0x401000,
                insn_snapshots=(),
            ),
            1: BlockSnapshot(
                serial=1,
                block_type=ida_hexrays.BLT_0WAY,
                succs=(),
                preds=(0,),
                flags=0,
                start_ea=0x401010,
                insn_snapshots=(),
            ),
        },
        entry_serial=0,
        func_ea=0x401000,
    )


def _flow_graph_with_conditional_shape() -> FlowGraph:
    return FlowGraph(
        blocks={
            0: BlockSnapshot(
                serial=0,
                block_type=ida_hexrays.BLT_1WAY,
                succs=(1,),
                preds=(),
                flags=0,
                start_ea=0x401000,
                insn_snapshots=(),
            ),
            1: BlockSnapshot(
                serial=1,
                block_type=ida_hexrays.BLT_2WAY,
                succs=(2, 3),
                preds=(0,),
                flags=0,
                start_ea=0x401010,
                insn_snapshots=(),
            ),
            2: BlockSnapshot(
                serial=2,
                block_type=ida_hexrays.BLT_0WAY,
                succs=(),
                preds=(1,),
                flags=0,
                start_ea=0x401020,
                insn_snapshots=(),
            ),
            3: BlockSnapshot(
                serial=3,
                block_type=ida_hexrays.BLT_0WAY,
                succs=(),
                preds=(1,),
                flags=0,
                start_ea=0x401030,
                insn_snapshots=(),
            ),
        },
        entry_serial=0,
        func_ea=0x401000,
    )


def _state_dispatcher_map(
    *,
    dispatcher_entry: int = 2,
) -> StateDispatcherMap:
    return StateDispatcherMap(
        rows=(
            StateDispatcherRow(
                state_const=0x10,
                target_block=5,
                dispatcher_block=dispatcher_entry,
                compare_block=dispatcher_entry,
                branch_kind="switch_case",
                source=DispatcherType.SWITCH_TABLE,
            ),
            StateDispatcherRow(
                state_const=0x20,
                target_block=7,
                dispatcher_block=dispatcher_entry,
                compare_block=dispatcher_entry,
                branch_kind="switch_case",
                source=DispatcherType.SWITCH_TABLE,
            ),
        ),
        dispatcher_entry_block=dispatcher_entry,
        dispatcher_blocks=frozenset({dispatcher_entry}),
        state_var_stkoff=0x3C,
        state_var_lvar_idx=None,
        source=DispatcherType.SWITCH_TABLE,
        initial_state=0x10,
    )


def test_phase_node_entry_by_state_prefers_exact_dispatcher_map_rows() -> None:
    def _node(state: int, entry: int):
        return SimpleNamespace(
            key=SimpleNamespace(state_const=state),
            entry_anchor=entry,
        )

    def _snapshot(serial: int) -> BlockSnapshot:
        return BlockSnapshot(
            serial=serial,
            block_type=ida_hexrays.BLT_0WAY,
            succs=(),
            preds=(),
            flags=0,
            start_ea=0x401000 + serial,
            insn_snapshots=(),
        )

    dispatch_map = _state_dispatcher_map(dispatcher_entry=2)
    context = EmulatedDispatcherPhaseContext(
        bst_result=object(),
        transition_result=object(),
        transition_report=object(),
        dag=object(),
        semantic_reference_program=object(),
        state_dispatcher_map=dispatch_map,
    )
    dag = SimpleNamespace(
        nodes=(
            _node(0x10, 9),
            _node(0x10, 5),
            _node(0x30, 11),
            _node(0x30, 12),
        ),
    )
    flow_graph = FlowGraph(
        blocks={serial: _snapshot(serial) for serial in (2, 5, 7, 9, 11, 12)},
        entry_serial=9,
        func_ea=0x401000,
    )

    entries = emulated_family_module._phase_node_entry_by_state(
        dag=dag,
        phase_context=context,
        flow_graph=flow_graph,
    )

    assert entries[0x10] == 5
    assert entries[0x20] == 7
    assert entries[0x30] == 11


def test_ollvm_terminal_payload_backedge_retargets_to_selector_return_frontier() -> None:
    def _key(state: int):
        return SimpleNamespace(state_const=state)

    def _edge(
        source: int,
        target: int | None,
        kind: SemanticEdgeKind,
        *,
        target_entry: int,
        branch_ownership_proof: BranchOwnershipProof | None = None,
    ):
        return SimpleNamespace(
            source_key=_key(source),
            target_key=(_key(target) if target is not None else None),
            kind=kind,
            target_entry_anchor=target_entry,
            ordered_path=(target_entry,),
            branch_ownership_proof=branch_ownership_proof,
        )

    payload_state = 0x2AC056AD
    selector_state = 0x049FD3A3
    return_state = 0xBFF7ACB5
    payload_edge = _edge(
        payload_state,
        selector_state,
        SemanticEdgeKind.TRANSITION,
        target_entry=96,
    )
    selector_to_payload = _edge(
        selector_state,
        payload_state,
        SemanticEdgeKind.CONDITIONAL_TRANSITION,
        target_entry=136,
        branch_ownership_proof=BranchOwnershipProof(
            proof_id="proof-selector-to-payload",
            proof_kind=BranchOwnershipProofKind.OBFUSCATION_RESIDUE_ARM,
            trusted=True,
            reason="trusted_opaque_branch_provenance:ollvm_bcf_opaque_predicate",
            source_state=selector_state,
            target_state=payload_state,
            target_entry=136,
            oracle_kind="fixture",
        ),
    )
    selector_to_return = _edge(
        selector_state,
        return_state,
        SemanticEdgeKind.CONDITIONAL_TRANSITION,
        target_entry=204,
    )
    return_edge = _edge(
        return_state,
        None,
        SemanticEdgeKind.CONDITIONAL_RETURN,
        target_entry=204,
    )
    dag = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                key=_key(payload_state),
                entry_anchor=136,
                owned_blocks=(),
                exclusive_blocks=(),
            ),
            SimpleNamespace(
                key=_key(selector_state),
                entry_anchor=96,
                owned_blocks=(),
                exclusive_blocks=(),
            ),
            SimpleNamespace(
                key=_key(return_state),
                entry_anchor=204,
                owned_blocks=(),
                exclusive_blocks=(),
            ),
        ),
        edges=(payload_edge, selector_to_payload, selector_to_return, return_edge),
    )
    flow_graph = FlowGraph(
        blocks={
            96: BlockSnapshot(
                serial=96,
                block_type=ida_hexrays.BLT_2WAY,
                succs=(98, 100),
                preds=(136,),
                flags=0,
                start_ea=0x401096,
                insn_snapshots=(),
            ),
            136: BlockSnapshot(
                serial=136,
                block_type=ida_hexrays.BLT_1WAY,
                succs=(96,),
                preds=(98,),
                flags=0,
                start_ea=0x401136,
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=ida_hexrays.m_stx,
                        ea=0x401136,
                        operands=(),
                    ),
                ),
            ),
            204: BlockSnapshot(
                serial=204,
                block_type=ida_hexrays.BLT_0WAY,
                succs=(),
                preds=(99,),
                flags=0,
                start_ea=0x401204,
                insn_snapshots=(),
            ),
        },
        entry_serial=96,
        func_ea=0x401000,
    )
    candidate = ReconstructionCandidate(
        edge=payload_edge,
        horizon_block=136,
        site=None,
        target_entry=96,
        first_shared_block=None,
        via_pred=None,
        emission_mode="direct",
    )
    logger = SimpleNamespace(info=lambda *args, **kwargs: None)

    rewritten = emulated_family_module._retarget_ollvm_terminal_payload_backedges(
        dag=dag,
        flow_graph=flow_graph,
        raw_candidates=[candidate],
        logger=logger,
    )

    assert len(rewritten) == 1
    assert rewritten[0].target_entry == 204
    assert candidate.target_entry == 96


class _FakeInsn:
    def __init__(self, *, opcode: int, l: object, d: object, ea: int) -> None:
        self.opcode = opcode
        self.l = l
        self.d = d
        self.ea = ea
        self.next = None


class _FakeBlock:
    def __init__(self, head: object | None = None) -> None:
        self.head = head


class _FakeMba:
    def __init__(self, blocks: dict[int, _FakeBlock]) -> None:
        self._blocks = blocks
        self.qty = max(blocks) + 1

    def get_mblock(self, serial: int) -> _FakeBlock:
        return self._blocks[int(serial)]


def _stk_mop(stkoff: int, size: int = 8) -> SimpleNamespace:
    return SimpleNamespace(
        t=ida_hexrays.mop_S,
        size=size,
        s=SimpleNamespace(off=stkoff),
    )


def _reg_mop(reg: int, size: int = 8) -> SimpleNamespace:
    return SimpleNamespace(t=ida_hexrays.mop_r, size=size, r=reg)


def _num_mop(value: int, size: int = 8) -> SimpleNamespace:
    return SimpleNamespace(
        t=ida_hexrays.mop_n,
        size=size,
        value=value,
        nnn=SimpleNamespace(value=value),
    )


def _flow_graph_for_return_carrier_bypass() -> FlowGraph:
    def _block(serial: int, succs: tuple[int, ...], preds: tuple[int, ...]) -> BlockSnapshot:
        return BlockSnapshot(
            serial=serial,
            block_type=ida_hexrays.BLT_1WAY if succs else ida_hexrays.BLT_0WAY,
            succs=succs,
            preds=preds,
            flags=0,
            start_ea=0x401000 + serial,
            insn_snapshots=(),
        )

    return FlowGraph(
        blocks={
            0: _block(0, (1,), ()),
            1: _block(1, (2,), (0,)),
            2: _block(2, (3,), (1,)),
            3: _block(3, (), (2,)),
        },
        entry_serial=0,
        func_ea=0x401000,
    )


def test_dispatcher_loop_recovery_rejects_return_slot_writer_bypass(
    monkeypatch,
) -> None:
    return_read = _FakeInsn(
        opcode=ida_hexrays.m_mov,
        l=_stk_mop(0x8),
        d=_reg_mop(0),
        ea=0x401030,
    )
    mba = _FakeMba(
        {
            0: _FakeBlock(),
            1: _FakeBlock(),
            2: _FakeBlock(),
            3: _FakeBlock(return_read),
        }
    )
    flow_graph = _flow_graph_for_return_carrier_bypass()

    monkeypatch.setattr(
        emulated_family_module,
        "find_reaching_defs_for_stkvar",
        lambda _mba, _blk, _stkoff, _size: (
            SimpleNamespace(block_serial=0, ins_ea=0x401000),
            SimpleNamespace(block_serial=2, ins_ea=0x401020),
        ),
    )

    bypasses = emulated_family_module._return_carrier_preservation_bypasses(
        mba=mba,
        flow_graph=flow_graph,
        modifications=(
            RedirectGoto(from_serial=1, old_target=2, new_target=3),
        ),
    )

    assert len(bypasses) == 1
    assert bypasses[0].writer_block == 2
    assert bypasses[0].return_block == 3
    assert emulated_family_module._return_carrier_preservation_blockers(
        mba=mba,
        flow_graph=flow_graph,
        modifications=(
            RedirectGoto(from_serial=1, old_target=2, new_target=3),
        ),
    ) == ("dispatcher_loop_recovery_return_carrier_bypass",)


def test_dispatcher_loop_recovery_rejects_semantic_return_writer_bypass() -> None:
    def _block(serial: int, succs: tuple[int, ...], preds: tuple[int, ...]) -> BlockSnapshot:
        return BlockSnapshot(
            serial=serial,
            block_type=ida_hexrays.BLT_1WAY if succs else ida_hexrays.BLT_0WAY,
            succs=succs,
            preds=preds,
            flags=0,
            start_ea=0x401000 + serial,
            insn_snapshots=(),
        )

    writer = _FakeInsn(
        opcode=ida_hexrays.m_mov,
        l=_stk_mop(0x10),
        d=_stk_mop(0x8),
        ea=0x401050,
    )
    mba = _FakeMba({10: _FakeBlock(writer)})
    flow_graph = FlowGraph(
        blocks={
            0: _block(0, (8, 9), ()),
            3: _block(3, (11,), (5, 8, 9, 10)),
            5: _block(5, (3,), (10,)),
            8: _block(8, (3,), (0,)),
            9: _block(9, (3,), (0,)),
            10: _block(10, (3,), (8,)),
            11: _block(11, (), (3, 9)),
        },
        entry_serial=0,
        func_ea=0x401000,
    )
    phase_context = SimpleNamespace(
        semantic_reference_program=SimpleNamespace(
            nodes=(
                SimpleNamespace(
                    node_index=0,
                    handler_serial=11,
                    entry_anchor=11,
                ),
            ),
            lines=(
                SimpleNamespace(
                    node_index=0,
                    line_kind="return",
                    text="    return result;",
                ),
            ),
        )
    )

    assert emulated_family_module._return_carrier_preservation_blockers(
        mba=mba,
        flow_graph=flow_graph,
        modifications=(
            RedirectGoto(from_serial=9, old_target=3, new_target=11),
            RedirectGoto(from_serial=10, old_target=3, new_target=5),
            RedirectGoto(from_serial=8, old_target=3, new_target=10),
        ),
        phase_context=phase_context,
    ) == ("dispatcher_loop_recovery_return_carrier_bypass",)


def test_dispatcher_loop_recovery_rejects_semantic_const_zero_return() -> None:
    def _block(serial: int, succs: tuple[int, ...], preds: tuple[int, ...]) -> BlockSnapshot:
        return BlockSnapshot(
            serial=serial,
            block_type=ida_hexrays.BLT_1WAY if succs else ida_hexrays.BLT_0WAY,
            succs=succs,
            preds=preds,
            flags=0,
            start_ea=0x401000 + serial,
            insn_snapshots=(),
        )

    const_zero_return = _FakeInsn(
        opcode=ida_hexrays.m_mov,
        l=_num_mop(0),
        d=_reg_mop(0),
        ea=0x401060,
    )
    mba = _FakeMba({11: _FakeBlock(const_zero_return)})
    flow_graph = FlowGraph(
        blocks={
            0: _block(0, (9,), ()),
            3: _block(3, (11,), (9,)),
            9: _block(9, (3,), (0,)),
            11: _block(11, (), (3, 9)),
        },
        entry_serial=0,
        func_ea=0x401000,
    )
    phase_context = SimpleNamespace(
        semantic_reference_program=SimpleNamespace(
            nodes=(
                SimpleNamespace(
                    node_index=0,
                    handler_serial=11,
                    entry_anchor=11,
                ),
            ),
            lines=(
                SimpleNamespace(
                    node_index=0,
                    line_kind="return",
                    text="    return result;",
                ),
            ),
        )
    )

    assert emulated_family_module._return_carrier_preservation_blockers(
        mba=mba,
        flow_graph=flow_graph,
        modifications=(
            RedirectGoto(from_serial=9, old_target=3, new_target=11),
        ),
        phase_context=phase_context,
    ) == ("dispatcher_loop_recovery_return_carrier_bypass",)


def test_ollvm_terminal_payload_backedge_requires_branch_ownership_proof() -> None:
    def _key(state: int):
        return SimpleNamespace(state_const=state)

    def _edge(
        source: int,
        target: int | None,
        kind: SemanticEdgeKind,
        *,
        target_entry: int,
    ):
        return SimpleNamespace(
            source_key=_key(source),
            target_key=(_key(target) if target is not None else None),
            kind=kind,
            target_entry_anchor=target_entry,
            ordered_path=(target_entry,),
        )

    payload_state = 0x2AC056AD
    selector_state = 0x049FD3A3
    return_state = 0xBFF7ACB5
    payload_edge = _edge(
        payload_state,
        selector_state,
        SemanticEdgeKind.TRANSITION,
        target_entry=96,
    )
    dag = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                key=_key(payload_state),
                entry_anchor=136,
                owned_blocks=(),
                exclusive_blocks=(),
            ),
            SimpleNamespace(
                key=_key(selector_state),
                entry_anchor=96,
                owned_blocks=(),
                exclusive_blocks=(),
            ),
            SimpleNamespace(
                key=_key(return_state),
                entry_anchor=204,
                owned_blocks=(),
                exclusive_blocks=(),
            ),
        ),
        edges=(
            payload_edge,
            _edge(
                selector_state,
                payload_state,
                SemanticEdgeKind.CONDITIONAL_TRANSITION,
                target_entry=136,
            ),
            _edge(
                selector_state,
                return_state,
                SemanticEdgeKind.CONDITIONAL_TRANSITION,
                target_entry=204,
            ),
            _edge(
                return_state,
                None,
                SemanticEdgeKind.CONDITIONAL_RETURN,
                target_entry=204,
            ),
        ),
    )
    flow_graph = FlowGraph(
        blocks={
            96: BlockSnapshot(
                serial=96,
                block_type=ida_hexrays.BLT_2WAY,
                succs=(98, 100),
                preds=(136,),
                flags=0,
                start_ea=0x401096,
                insn_snapshots=(),
            ),
            136: BlockSnapshot(
                serial=136,
                block_type=ida_hexrays.BLT_1WAY,
                succs=(96,),
                preds=(98,),
                flags=0,
                start_ea=0x401136,
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=ida_hexrays.m_stx,
                        ea=0x401136,
                        operands=(),
                    ),
                ),
            ),
            204: BlockSnapshot(
                serial=204,
                block_type=ida_hexrays.BLT_0WAY,
                succs=(),
                preds=(99,),
                flags=0,
                start_ea=0x401204,
                insn_snapshots=(),
            ),
        },
        entry_serial=96,
        func_ea=0x401000,
    )
    candidate = ReconstructionCandidate(
        edge=payload_edge,
        horizon_block=136,
        site=None,
        target_entry=96,
        first_shared_block=None,
        via_pred=None,
        emission_mode="direct",
    )
    logger = SimpleNamespace(info=lambda *args, **kwargs: None)

    rewritten = emulated_family_module._retarget_ollvm_terminal_payload_backedges(
        dag=dag,
        flow_graph=flow_graph,
        raw_candidates=[candidate],
        logger=logger,
    )

    assert rewritten == [candidate]
    assert rewritten[0].target_entry == 96


def test_ollvm_terminal_payload_backedge_consumes_phase_branch_ownership_proofs() -> None:
    def _key(state: int):
        return SimpleNamespace(state_const=state)

    def _edge(
        source: int,
        target: int | None,
        kind: SemanticEdgeKind,
        *,
        target_entry: int,
        branch_arm: int | None = None,
    ):
        return SimpleNamespace(
            source_key=_key(source),
            target_key=(_key(target) if target is not None else None),
            kind=kind,
            source_anchor=SimpleNamespace(
                block_serial=96,
                branch_arm=branch_arm,
            ),
            target_entry_anchor=target_entry,
            ordered_path=(target_entry,),
        )

    payload_state = 0x2AC056AD
    selector_state = 0x049FD3A3
    return_state = 0xBFF7ACB5
    payload_edge = _edge(
        payload_state,
        selector_state,
        SemanticEdgeKind.TRANSITION,
        target_entry=96,
    )
    selector_to_payload = _edge(
        selector_state,
        payload_state,
        SemanticEdgeKind.CONDITIONAL_TRANSITION,
        target_entry=136,
        branch_arm=1,
    )
    selector_to_return = _edge(
        selector_state,
        return_state,
        SemanticEdgeKind.CONDITIONAL_TRANSITION,
        target_entry=204,
        branch_arm=0,
    )
    return_edge = _edge(
        return_state,
        None,
        SemanticEdgeKind.CONDITIONAL_RETURN,
        target_entry=204,
    )
    dag = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                key=_key(payload_state),
                entry_anchor=136,
                owned_blocks=(),
                exclusive_blocks=(),
            ),
            SimpleNamespace(
                key=_key(selector_state),
                entry_anchor=96,
                owned_blocks=(),
                exclusive_blocks=(),
            ),
            SimpleNamespace(
                key=_key(return_state),
                entry_anchor=204,
                owned_blocks=(),
                exclusive_blocks=(),
            ),
        ),
        edges=(payload_edge, selector_to_payload, selector_to_return, return_edge),
    )
    flow_graph = FlowGraph(
        blocks={
            96: BlockSnapshot(
                serial=96,
                block_type=ida_hexrays.BLT_2WAY,
                succs=(98, 100),
                preds=(136,),
                flags=0,
                start_ea=0x401096,
                insn_snapshots=(),
            ),
            136: BlockSnapshot(
                serial=136,
                block_type=ida_hexrays.BLT_1WAY,
                succs=(96,),
                preds=(98,),
                flags=0,
                start_ea=0x401136,
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=ida_hexrays.m_stx,
                        ea=0x401136,
                        operands=(),
                    ),
                ),
            ),
            204: BlockSnapshot(
                serial=204,
                block_type=ida_hexrays.BLT_0WAY,
                succs=(),
                preds=(99,),
                flags=0,
                start_ea=0x401204,
                insn_snapshots=(),
            ),
        },
        entry_serial=96,
        func_ea=0x401000,
    )
    candidate = ReconstructionCandidate(
        edge=payload_edge,
        horizon_block=136,
        site=None,
        target_entry=96,
        first_shared_block=None,
        via_pred=None,
        emission_mode="direct",
    )
    proof = BranchOwnershipProof(
        proof_id="proof-selector-to-payload",
        proof_kind=BranchOwnershipProofKind.OBFUSCATION_RESIDUE_ARM,
        trusted=True,
        reason="moptracker_path_constant_non_taken_arm",
        source_block=96,
        branch_arm=1,
        source_state=selector_state,
        target_state=payload_state,
        target_entry=136,
        oracle_kind="moptracker_branch_ownership",
    )
    logger = SimpleNamespace(info=lambda *args, **kwargs: None)

    rewritten = emulated_family_module._retarget_ollvm_terminal_payload_backedges(
        dag=dag,
        flow_graph=flow_graph,
        raw_candidates=[candidate],
        branch_ownership_proofs=(proof,),
        logger=logger,
    )

    assert len(rewritten) == 1
    assert rewritten[0].target_entry == 204
    assert candidate.target_entry == 96


def test_ollvm_terminal_payload_backedge_rejects_sibling_branch_proof() -> None:
    def _key(state: int):
        return SimpleNamespace(state_const=state)

    def _edge(
        source: int,
        target: int | None,
        kind: SemanticEdgeKind,
        *,
        target_entry: int,
        branch_arm: int | None = None,
        metadata: dict | None = None,
    ):
        return SimpleNamespace(
            source_key=_key(source),
            target_key=(_key(target) if target is not None else None),
            kind=kind,
            source_anchor=SimpleNamespace(
                block_serial=96,
                branch_arm=branch_arm,
            ),
            target_entry_anchor=target_entry,
            ordered_path=(target_entry,),
            metadata=metadata,
        )

    payload_state = 0x2AC056AD
    selector_state = 0x049FD3A3
    return_state = 0xBFF7ACB5
    payload_edge = _edge(
        payload_state,
        selector_state,
        SemanticEdgeKind.TRANSITION,
        target_entry=96,
    )
    sibling_proof = BranchOwnershipProof(
        proof_id="proof-selector-to-return",
        proof_kind=BranchOwnershipProofKind.OBFUSCATION_RESIDUE_ARM,
        trusted=True,
        reason="fixture sibling proof",
        source_block=96,
        branch_arm=0,
        source_state=selector_state,
        target_state=return_state,
        target_entry=204,
        oracle_kind="fixture",
    )
    shared_metadata = {"branch_ownership_proofs": (sibling_proof,)}
    selector_to_payload = _edge(
        selector_state,
        payload_state,
        SemanticEdgeKind.CONDITIONAL_TRANSITION,
        target_entry=136,
        branch_arm=1,
        metadata=shared_metadata,
    )
    selector_to_return = _edge(
        selector_state,
        return_state,
        SemanticEdgeKind.CONDITIONAL_TRANSITION,
        target_entry=204,
        branch_arm=0,
        metadata=shared_metadata,
    )
    return_edge = _edge(
        return_state,
        None,
        SemanticEdgeKind.CONDITIONAL_RETURN,
        target_entry=204,
    )
    dag = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                key=_key(payload_state),
                entry_anchor=136,
                owned_blocks=(),
                exclusive_blocks=(),
            ),
            SimpleNamespace(
                key=_key(selector_state),
                entry_anchor=96,
                owned_blocks=(),
                exclusive_blocks=(),
            ),
            SimpleNamespace(
                key=_key(return_state),
                entry_anchor=204,
                owned_blocks=(),
                exclusive_blocks=(),
            ),
        ),
        edges=(payload_edge, selector_to_payload, selector_to_return, return_edge),
    )
    flow_graph = FlowGraph(
        blocks={
            96: BlockSnapshot(
                serial=96,
                block_type=ida_hexrays.BLT_2WAY,
                succs=(98, 100),
                preds=(136,),
                flags=0,
                start_ea=0x401096,
                insn_snapshots=(),
            ),
            136: BlockSnapshot(
                serial=136,
                block_type=ida_hexrays.BLT_1WAY,
                succs=(96,),
                preds=(98,),
                flags=0,
                start_ea=0x401136,
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=ida_hexrays.m_stx,
                        ea=0x401136,
                        operands=(),
                    ),
                ),
            ),
            204: BlockSnapshot(
                serial=204,
                block_type=ida_hexrays.BLT_0WAY,
                succs=(),
                preds=(99,),
                flags=0,
                start_ea=0x401204,
                insn_snapshots=(),
            ),
        },
        entry_serial=96,
        func_ea=0x401000,
    )
    candidate = ReconstructionCandidate(
        edge=payload_edge,
        horizon_block=136,
        site=None,
        target_entry=96,
        first_shared_block=None,
        via_pred=None,
        emission_mode="direct",
    )
    logger = SimpleNamespace(info=lambda *args, **kwargs: None)

    rewritten = emulated_family_module._retarget_ollvm_terminal_payload_backedges(
        dag=dag,
        flow_graph=flow_graph,
        raw_candidates=[candidate],
        logger=logger,
    )

    assert rewritten == [candidate]
    assert rewritten[0].target_entry == 96


def test_branch_ownership_consumer_requires_minimum_rewrite_identity() -> None:
    edge = SimpleNamespace(
        source_key=SimpleNamespace(state_const=0x10),
        target_key=SimpleNamespace(state_const=0x20),
        target_entry_anchor=30,
        source_anchor=SimpleNamespace(block_serial=5, branch_arm=1),
        branch_ownership_proof=BranchOwnershipProof(
            proof_id="partial-proof",
            proof_kind=BranchOwnershipProofKind.OBFUSCATION_RESIDUE_ARM,
            trusted=True,
            reason="fixture",
            source_state=0x10,
            target_state=0x20,
            oracle_kind="fixture",
        ),
    )

    assert (
        emulated_family_module._edge_has_trusted_nonsemantic_branch_proof(edge)
        is False
    )


def test_branch_ownership_consumer_accepts_branch_arm_identity() -> None:
    edge = SimpleNamespace(
        source_key=SimpleNamespace(state_const=0x10),
        target_key=SimpleNamespace(state_const=0x20),
        target_entry_anchor=30,
        source_anchor=SimpleNamespace(block_serial=5, branch_arm=1),
        branch_ownership_proof=BranchOwnershipProof(
            proof_id="arm-proof",
            proof_kind=BranchOwnershipProofKind.OBFUSCATION_RESIDUE_ARM,
            trusted=True,
            reason="fixture",
            source_block=5,
            branch_arm=1,
            source_state=0x10,
            target_state=0x20,
            oracle_kind="fixture",
        ),
    )

    assert (
        emulated_family_module._edge_has_trusted_nonsemantic_branch_proof(edge)
        is True
    )


def test_branch_ownership_retarget_requires_owned_source_or_split_plan() -> None:
    flow_graph = FlowGraph(
        blocks={
            1: BlockSnapshot(
                serial=1,
                block_type=ida_hexrays.BLT_1WAY,
                succs=(10,),
                preds=(),
                flags=0,
                start_ea=0x401001,
                insn_snapshots=(),
            ),
            10: BlockSnapshot(
                serial=10,
                block_type=ida_hexrays.BLT_1WAY,
                succs=(30,),
                preds=(1, 2),
                flags=0,
                start_ea=0x401010,
                insn_snapshots=(),
            ),
            20: BlockSnapshot(
                serial=20,
                block_type=ida_hexrays.BLT_1WAY,
                succs=(30,),
                preds=(1,),
                flags=0,
                start_ea=0x401020,
                insn_snapshots=(),
            ),
        },
        entry_serial=1,
        func_ea=0x401000,
    )

    shared_direct = SimpleNamespace(
        emission_mode="direct",
        horizon_block=10,
        first_shared_block=None,
        via_pred=None,
    )
    owned_direct = SimpleNamespace(
        emission_mode="direct",
        horizon_block=20,
        first_shared_block=None,
        via_pred=None,
    )
    split_plan = SimpleNamespace(
        emission_mode="pred_split",
        horizon_block=20,
        first_shared_block=10,
        via_pred=1,
    )

    assert (
        emulated_family_module._candidate_has_owned_or_split_lowering(
            shared_direct,
            flow_graph,
        )
        is False
    )
    assert (
        emulated_family_module._candidate_has_owned_or_split_lowering(
            owned_direct,
            flow_graph,
        )
        is True
    )
    assert (
        emulated_family_module._candidate_has_owned_or_split_lowering(
            split_plan,
            flow_graph,
        )
        is True
    )


def _snapshot_operand_signature(mop) -> str:
    if mop is None:
        return "z"
    return (
        f"t={getattr(mop, 't', None)},size={getattr(mop, 'size', None)},"
        f"value={getattr(mop, 'value', None)},stkoff={getattr(mop, 'stkoff', None)},"
        f"reg={getattr(mop, 'reg', None)},block_ref={getattr(mop, 'block_ref', None)}"
    )


def _payload_signature_from_instructions(instructions) -> tuple[str, ...]:
    return tuple(
        "|".join(
            (
                f"op={getattr(insn, 'opcode', None)}",
                f"l={_snapshot_operand_signature(getattr(insn, 'l', None))}",
                f"r={_snapshot_operand_signature(getattr(insn, 'r', None))}",
                f"d={_snapshot_operand_signature(getattr(insn, 'd', None))}",
            )
        )
        for insn in instructions
    )


def _compute_nontrivial_sccs(flow_graph: FlowGraph) -> tuple[tuple[int, ...], ...]:
    index = 0
    stack: list[int] = []
    on_stack: set[int] = set()
    indexes: dict[int, int] = {}
    lowlinks: dict[int, int] = {}
    components: list[tuple[int, ...]] = []

    def _strongconnect(serial: int) -> None:
        nonlocal index
        indexes[serial] = index
        lowlinks[serial] = index
        index += 1
        stack.append(serial)
        on_stack.add(serial)

        for succ in flow_graph.successors(serial):
            if succ not in indexes:
                _strongconnect(succ)
                lowlinks[serial] = min(lowlinks[serial], lowlinks[succ])
            elif succ in on_stack:
                lowlinks[serial] = min(lowlinks[serial], indexes[succ])

        if lowlinks[serial] != indexes[serial]:
            return

        component: list[int] = []
        while stack:
            member = stack.pop()
            on_stack.remove(member)
            component.append(member)
            if member == serial:
                break
        normalized = tuple(sorted(component))
        if len(normalized) > 1:
            components.append(normalized)

    for serial in sorted(flow_graph.blocks):
        if serial not in indexes:
            _strongconnect(serial)

    return tuple(sorted(components))


def _compute_backedges(flow_graph: FlowGraph) -> tuple[tuple[int, int], ...]:
    visited: set[int] = set()
    active: set[int] = set()
    backedges: set[tuple[int, int]] = set()

    def _walk(serial: int) -> None:
        visited.add(serial)
        active.add(serial)
        for succ in flow_graph.successors(serial):
            if succ not in flow_graph.blocks:
                continue
            if succ in active:
                backedges.add((serial, succ))
                continue
            if succ not in visited:
                _walk(succ)
        active.remove(serial)

    if flow_graph.entry_serial in flow_graph.blocks:
        _walk(flow_graph.entry_serial)
    return tuple(sorted(backedges))


def test_phase_reconstruction_reorder_blocks_walks_dag_semantic_order() -> None:
    def _snapshot(serial: int, block_type: int = ida_hexrays.BLT_1WAY) -> BlockSnapshot:
        return BlockSnapshot(
            serial=serial,
            block_type=block_type,
            succs=(),
            preds=(),
            flags=0,
            start_ea=0x401000 + serial,
            insn_snapshots=(),
        )

    def _node(state: int, entry: int, owned: tuple[int, ...]) -> SimpleNamespace:
        return SimpleNamespace(
            key=SimpleNamespace(state_const=state),
            entry_anchor=entry,
            owned_blocks=owned,
            exclusive_blocks=(),
        )

    def _edge(
        source_state: int,
        target_state: int | None,
        path: tuple[int, ...],
        *,
        arm: int | None = None,
        kind: SemanticEdgeKind = SemanticEdgeKind.TRANSITION,
        target_entry: int | None = None,
    ) -> SimpleNamespace:
        return SimpleNamespace(
            kind=kind,
            source_key=SimpleNamespace(state_const=source_state),
            target_key=(
                SimpleNamespace(state_const=target_state)
                if target_state is not None
                else None
            ),
            target_entry_anchor=target_entry,
            source_anchor=SimpleNamespace(branch_arm=arm),
            ordered_path=path,
        )

    flow_graph = FlowGraph(
        blocks={
            2: _snapshot(2),
            3: _snapshot(3),
            10: _snapshot(10),
            11: _snapshot(11),
            12: _snapshot(12),
            13: _snapshot(13, ida_hexrays.BLT_2WAY),
            20: _snapshot(20),
            21: _snapshot(21),
            22: _snapshot(22),
            30: _snapshot(30),
            99: _snapshot(99, ida_hexrays.BLT_0WAY),
            100: _snapshot(100, ida_hexrays.BLT_STOP),
        },
        entry_serial=10,
        func_ea=0x401000,
    )
    dag = SimpleNamespace(
        nodes=(
            _node(0x10, 10, (10, 11)),
            _node(0x20, 20, (20,)),
            _node(0x30, 30, (30,)),
        ),
        edges=(
            _edge(0x10, 0x20, (10, 11, 12, 20), arm=0, target_entry=20),
            _edge(0x10, 0x30, (10, 13, 30), arm=1, target_entry=30),
            _edge(0x20, 0x10, (20, 21, 10), target_entry=10),
            _edge(
                0x20,
                None,
                (20, 22, 99, 100),
                kind=SemanticEdgeKind.CONDITIONAL_RETURN,
                target_entry=100,
            ),
        ),
    )

    reorder = emulated_family_module._phase_reconstruction_reorder_blocks_from_dag(
        dag=dag,
        flow_graph=flow_graph,
        initial_state=0x10,
        excluded_blocks={2, 3},
    )

    assert reorder == ReorderBlocks(
        dfs_block_order=(10, 11, 12, 20, 21, 22, 99, 13, 30),
        non_2way_serials=(10, 11, 12, 20, 21, 22, 99, 30),
        two_way_serials=(13,),
    )


def _summarize_cfg_shape(
    flow_graph: FlowGraph,
    *,
    payload_signatures: tuple[tuple[str, ...], ...] = (),
) -> dict[str, object]:
    payload_blocks: dict[tuple[str, ...], tuple[int, ...]] = {}
    for payload in payload_signatures:
        matched: list[int] = []
        for serial, block in flow_graph.blocks.items():
            block_signature = _payload_signature_from_instructions(block.insn_snapshots)
            if payload and payload == block_signature:
                matched.append(int(serial))
        payload_blocks[payload] = tuple(sorted(matched))

    return {
        "block_count": len(flow_graph.blocks),
        "edge_count": sum(len(block.succs) for block in flow_graph.blocks.values()),
        "nontrivial_sccs": _compute_nontrivial_sccs(flow_graph),
        "backedges": _compute_backedges(flow_graph),
        "payload_blocks": payload_blocks,
    }


_APPROOV_MULTISTATE_PHASE_STATES = {
    "phase1_header": 0xF6A1F,
    "phase1_update": 0xF6A1E,
    "phase2_multiply": 0xF6A20,
    "phase_exit": 0xF6A25,
}


def _record_attr(record, name: str):
    if isinstance(record, dict):
        return record[name]
    return getattr(record, name)


def _approov_multistate_phase_role(record) -> str:
    state_signature = tuple(int(value) for value in _record_attr(record, "state_signature"))
    if state_signature == (_APPROOV_MULTISTATE_PHASE_STATES["phase1_header"],):
        return "phase1_header"
    if state_signature == (_APPROOV_MULTISTATE_PHASE_STATES["phase1_update"],):
        return "phase1_update"
    if state_signature == (_APPROOV_MULTISTATE_PHASE_STATES["phase2_multiply"],):
        return "phase2_multiply"
    if state_signature == (_APPROOV_MULTISTATE_PHASE_STATES["phase_exit"],):
        return "phase_exit"
    return f"unknown:{state_signature!r}"


def _summarize_approov_multistate_phase_roles(records) -> dict[str, tuple[tuple[int, int, tuple[str, ...]], ...]]:
    grouped: dict[str, list[tuple[int, int, tuple[str, ...]]]] = {}
    for record in records:
        role = _approov_multistate_phase_role(record)
        grouped.setdefault(role, []).append(
            (
                int(_record_attr(record, "father_serial")),
                int(_record_attr(record, "target_serial")),
                tuple(str(kind) for kind in _record_attr(record, "selected_modification_kinds")),
            )
        )
    return {
        role: tuple(sorted(entries))
        for role, entries in sorted(grouped.items())
    }


def _build_approov_multistate_phase_cycle(role_map: dict[str, tuple[tuple[int, int, tuple[str, ...]], ...]]) -> PhaseCycleLowering:
    header_entries = tuple(entry[0] for entry in role_map["phase1_header"])
    body_entries = tuple(entry[0] for entry in role_map["phase1_update"])
    next_phase_entries = tuple(entry[0] for entry in role_map["phase2_multiply"])
    terminal_entries = tuple(entry[0] for entry in role_map["phase_exit"])
    return PhaseCycleLowering(
        header_entries=header_entries,
        header_target=role_map["phase1_header"][0][1],
        body_entries=body_entries,
        body_target=role_map["phase1_update"][0][1],
        next_phase_entries=next_phase_entries,
        next_phase_target=role_map["phase2_multiply"][0][1],
        terminal_entries=terminal_entries,
        terminal_target=role_map["phase_exit"][0][1] if terminal_entries else None,
        state_roles=(
            ("phase1_header", _APPROOV_MULTISTATE_PHASE_STATES["phase1_header"]),
            ("phase1_update", _APPROOV_MULTISTATE_PHASE_STATES["phase1_update"]),
            ("phase2_multiply", _APPROOV_MULTISTATE_PHASE_STATES["phase2_multiply"]),
            ("phase_exit", _APPROOV_MULTISTATE_PHASE_STATES["phase_exit"]),
        ),
    )


def test_emulated_dispatcher_family_detect_reports_dispatcher_cache_collector_gap(
    monkeypatch,
) -> None:
    mba = _fake_mba()
    analysis = SimpleNamespace(
        dispatchers=[7, 9],
        state_constants={0xF6A1E, 0xF6A1F},
        dispatcher_type=SimpleNamespace(name="UNKNOWN"),
    )
    cache = SimpleNamespace(analyze=lambda: analysis)

    class _Collector:
        def __init__(self):
            self._items = ()

        def get_dispatcher_list(self):
            return list(self._items)

    monkeypatch.setattr(
        "d810.optimizers.microcode.flow.flattening.emulated_dispatcher_family.DispatcherCache",
        SimpleNamespace(get_or_create=lambda _mba: cache),
    )
    monkeypatch.setattr(
        "d810.optimizers.microcode.flow.flattening.emulated_dispatcher_family.OllvmDispatcherCollector",
        _Collector,
    )

    family = EmulatedDispatcherStrategyFamily(
        cfg_translator=SimpleNamespace(
            lift=lambda _mba: _flow_graph_with_conditional_shape()
        )
    )
    detection = family.detect(mba)

    assert detection.detected is True
    assert detection.analysis_dispatchers == (7, 9)
    assert detection.collector_dispatcher_entries == ()
    assert detection.dispatcher_shape == "unknown"
    assert detection.state_transport == "father_history_emulation"
    assert detection.lowering_mode == "generic_graph_modifications"
    assert detection.provenance_hints == ()
    assert detection.planning_blocker == "dispatcher_cache_detected_but_collector_found_none"


def test_emulated_dispatcher_family_detect_uses_injected_dispatcher_profile(
    monkeypatch,
) -> None:
    visits = []
    mba = SimpleNamespace(
        qty=1,
        maturity=ida_hexrays.MMAT_GLBOPT1,
        entry_ea=0x401000,
        get_mblock=lambda _serial: SimpleNamespace(nsucc=lambda: 0),
        for_all_topinsns=lambda collector: collector.mark_visited(),
    )
    analysis = SimpleNamespace(
        dispatchers=[],
        state_constants={0x1234},
        dispatcher_type=SimpleNamespace(name="PROFILE_KIND"),
    )
    cache = SimpleNamespace(analyze=lambda: analysis)

    class _Collector:
        def mark_visited(self):
            visits.append("visited")

        def get_dispatcher_list(self):
            return [SimpleNamespace(entry_block=SimpleNamespace(serial=11))]

    class _Resolver:
        def get_dispatcher_father_histories(self, *_args):
            return ()

        def check_if_histories_are_resolved(self, _histories):
            return False

        def _filter_dependency_safe_copies(self, _father, insns):
            return list(insns)

        def ensure_all_dispatcher_fathers_are_direct(self):
            return 0

    monkeypatch.setattr(
        "d810.optimizers.microcode.flow.flattening.emulated_dispatcher_family.DispatcherCache",
        SimpleNamespace(get_or_create=lambda _mba: cache),
    )

    family = EmulatedDispatcherStrategyFamily(
        cfg_translator=SimpleNamespace(
            lift=lambda _mba: _flow_graph_with_conditional_shape()
        ),
        profile=GenericDispatcherEngineProfile(
            name="fixture",
            collector_factory=_Collector,
            resolver_factory=_Resolver,
            state_transport="fixture_transport",
            lowering_mode="fixture_lowering",
            provenance_hints=("fixture_profile",),
        ),
    )
    detection = family.detect(mba)

    assert visits == ["visited"]
    assert family.name == "emulated_dispatcher"
    assert detection.detected is True
    assert detection.collector_dispatcher_entries == (11,)
    assert detection.dispatcher_shape == "profile_kind"
    assert detection.state_transport == "fixture_transport"
    assert detection.lowering_mode == "fixture_lowering"
    assert detection.provenance_hints == ("fixture_profile",)


def test_emulated_dispatcher_family_detect_uses_profile_state_dispatcher_map(
    monkeypatch,
) -> None:
    dispatch_map = _state_dispatcher_map(dispatcher_entry=13)
    mba = SimpleNamespace(
        qty=1,
        maturity=ida_hexrays.MMAT_GLBOPT1,
        entry_ea=0x401000,
        get_mblock=lambda _serial: SimpleNamespace(nsucc=lambda: 0),
        for_all_topinsns=lambda _collector: None,
    )
    analysis = SimpleNamespace(
        dispatchers=[],
        state_constants=set(),
        dispatcher_type=SimpleNamespace(name="NONE"),
    )
    cache = SimpleNamespace(analyze=lambda: analysis)

    class _Collector:
        def get_dispatcher_list(self):
            return []

    class _Resolver:
        pass

    monkeypatch.setattr(
        "d810.optimizers.microcode.flow.flattening.emulated_dispatcher_family.DispatcherCache",
        SimpleNamespace(get_or_create=lambda _mba: cache),
    )

    family = EmulatedDispatcherStrategyFamily(
        profile=GenericDispatcherEngineProfile(
            name="switch_fixture",
            collector_factory=_Collector,
            resolver_factory=_Resolver,
            state_transport="state_dispatcher_map",
            lowering_mode="generic_graph_modifications",
            provenance_hints=("switch_table",),
            state_dispatcher_map_factory=lambda *_args: (dispatch_map,),
        )
    )
    detection = family.detect(mba)

    assert detection.detected is True
    assert detection.collector_dispatcher_entries == ()
    assert detection.analysis_dispatchers == ()
    assert detection.state_dispatcher_entries == (13,)
    assert detection.state_dispatcher_maps == (dispatch_map,)
    assert detection.dispatcher_shape == "switch_table"
    assert detection.state_constants == (0x10, 0x20)
    assert detection.state_transport == "state_dispatcher_map"


def test_map_backed_profiles_do_not_instantiate_legacy_resolver() -> None:
    for profile in (
        ollvm_state_dispatcher_map_profile(),
        tigress_switch_dispatcher_profile(),
    ):
        resolver = profile.resolver_factory()
        assert type(resolver).__name__ == "_NoopDispatcherResolver"
        assert resolver.ensure_all_dispatcher_fathers_are_direct() == 0
        assert resolver.check_if_histories_are_resolved(None) is False


def test_tigress_switch_profile_collects_live_transition_facts(monkeypatch) -> None:
    dispatch_map = _state_dispatcher_map(dispatcher_entry=13)
    mba = SimpleNamespace(qty=1, maturity=ida_hexrays.MMAT_GLBOPT1)
    calls = []

    def _collect(*, mba, dispatch_map, profile_name):
        calls.append((mba, dispatch_map, profile_name))
        return ("fact",)

    monkeypatch.setattr(
        switch_case_transition_analysis,
        "collect_switch_case_transition_facts_from_mba",
        _collect,
    )

    profile = tigress_switch_dispatcher_profile()
    facts = profile.collect_switch_case_transition_facts(
        mba,
        state_dispatcher_map=dispatch_map,
    )

    assert facts == ("fact",)
    assert calls == [(mba, dispatch_map, "tigress_switch")]


def test_emulated_dispatcher_unflattener_accepts_tigress_switch_profile() -> None:
    rule = EmulatedDispatcherUnflattener()
    rule.configure({"profile": "tigress_switch", "diagnostics_only": True})

    assert rule._family._profile.name == "tigress_switch"
    assert rule._family._profile.state_transport == "state_dispatcher_map"
    assert rule.diagnostics_only is True


def test_emulated_dispatcher_family_primary_entry_uses_profile() -> None:
    dispatcher_info = object()

    class _Collector:
        def get_dispatcher_list(self):
            return [dispatcher_info]

    class _Resolver:
        pass

    class _Profile(GenericDispatcherEngineProfile):
        def dispatcher_entry_serial(self, seen_dispatcher_info):
            assert seen_dispatcher_info is dispatcher_info
            return 17

    family = EmulatedDispatcherStrategyFamily(
        profile=_Profile(
            name="fixture",
            collector_factory=_Collector,
            resolver_factory=_Resolver,
            state_transport="fixture_transport",
            lowering_mode="fixture_lowering",
        )
    )
    detection = EmulatedDispatcherDetection(
        collector_dispatchers=(dispatcher_info,),
        analysis_dispatchers=(99,),
    )

    assert family._primary_dispatcher_entry_serial(detection) == 17


def test_emulated_dispatcher_family_primary_entry_prefers_state_dispatcher_map() -> None:
    dispatcher_info = object()

    class _Collector:
        def get_dispatcher_list(self):
            return [dispatcher_info]

    class _Resolver:
        pass

    class _Profile(GenericDispatcherEngineProfile):
        def dispatcher_entry_serial(self, seen_dispatcher_info):
            assert seen_dispatcher_info is dispatcher_info
            return 17

    family = EmulatedDispatcherStrategyFamily(
        profile=_Profile(
            name="fixture",
            collector_factory=_Collector,
            resolver_factory=_Resolver,
            state_transport="fixture_transport",
            lowering_mode="fixture_lowering",
        )
    )
    detection = EmulatedDispatcherDetection(
        state_dispatcher_entries=(23,),
        collector_dispatchers=(dispatcher_info,),
        analysis_dispatchers=(99,),
    )

    assert family._primary_dispatcher_entry_serial(detection) == 23


def test_emulated_dispatcher_family_builds_phase_artifact_from_dispatcher_map(
    monkeypatch,
) -> None:
    dispatch_map = _state_dispatcher_map(dispatcher_entry=2)
    switch_fact = SimpleNamespace(fact_id="tigress_switch:case=16:direct")
    switch_fact_calls = []

    class _Collector:
        def get_dispatcher_list(self):
            return []

    class _Resolver:
        pass

    def _switch_fact_factory(mba, seen_dispatch_map, profile_name):
        switch_fact_calls.append((mba, seen_dispatch_map, profile_name))
        return (switch_fact,)

    family = EmulatedDispatcherStrategyFamily(
        profile=GenericDispatcherEngineProfile(
            name="tigress_switch",
            collector_factory=_Collector,
            resolver_factory=_Resolver,
            state_transport="state_dispatcher_map",
            lowering_mode="generic_graph_modifications",
            state_dispatcher_map_factory=lambda *_args: (),
            switch_case_transition_fact_factory=_switch_fact_factory,
        )
    )
    mba = SimpleNamespace(
        qty=3,
        maturity=ida_hexrays.MMAT_GLBOPT1,
        entry_ea=0x401000,
    )
    flow_graph = _flow_graph_with_conditional_shape()

    monkeypatch.setattr(
        emulated_family_module,
        "analyze_bst_dispatcher",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("BST analysis should not run for map-backed profile")
        ),
    )
    monkeypatch.setattr(
        emulated_family_module,
        "_detect_state_var_stkoff",
        lambda *_args, **_kwargs: (0x3C, None),
    )
    monkeypatch.setattr(
        emulated_family_module,
        "recover_dynamic_state_write_transitions",
        lambda **kwargs: kwargs["transition_result"],
    )
    monkeypatch.setattr(
        emulated_family_module,
        "build_dispatcher_transition_report_from_graph",
        lambda *_args, **_kwargs: SimpleNamespace(rows=()),
    )
    monkeypatch.setattr(
        emulated_family_module,
        "build_live_linearized_state_dag_from_graph",
        lambda *_args, **_kwargs: SimpleNamespace(nodes=(), edges=()),
    )
    monkeypatch.setattr(
        emulated_family_module,
        "build_linearized_state_program",
        lambda *_args, **_kwargs: SimpleNamespace(
            variant_name="semantic_reference_like",
            lines=(),
            nodes=(),
        ),
    )
    monkeypatch.setattr(
        emulated_family_module,
        "render_linearized_state_program",
        lambda _program: "",
    )

    artifact, context = family._build_phase_artifact(
        mba,
        EmulatedDispatcherDetection(
            state_dispatcher_maps=(dispatch_map,),
            state_dispatcher_entries=(2,),
            dispatcher_shape="switch_table",
            state_transport="state_dispatcher_map",
            state_constants=(0x10, 0x20),
        ),
        flow_graph=flow_graph,
    )

    assert artifact is not None
    assert context is not None
    assert artifact.dispatcher_entry_serial == 2
    assert artifact.state_var_stkoff == 0x3C
    assert artifact.initial_state == 0x10
    assert artifact.handler_state_map == ((5, 0x10), (7, 0x20))
    assert context.state_dispatcher_map is dispatch_map
    assert context.switch_case_transition_facts == (switch_fact,)
    assert switch_fact_calls == [(mba, dispatch_map, "tigress_switch")]


def test_emulated_dispatcher_phase_diagnostics_emit_profile_switch_facts(
    monkeypatch,
) -> None:
    switch_fact = SimpleNamespace(fact_id="tigress_switch:case=16:direct")
    context = EmulatedDispatcherPhaseContext(
        bst_result=object(),
        transition_result=object(),
        transition_report=object(),
        dag=SimpleNamespace(nodes=(), edges=()),
        semantic_reference_program=object(),
        switch_case_transition_facts=(switch_fact,),
    )
    flow_graph = FlowGraph(
        blocks={
            0: BlockSnapshot(
                serial=0,
                block_type=ida_hexrays.BLT_0WAY,
                succs=(),
                preds=(),
                flags=0,
                start_ea=0x401000,
                insn_snapshots=(),
            )
        },
        entry_serial=0,
        func_ea=0x401000,
        metadata={EMULATED_DISPATCHER_PHASE_CONTEXT_KEY: context},
    )
    snapshot = AnalysisSnapshot(
        mba=SimpleNamespace(maturity=ida_hexrays.MMAT_GLBOPT1, entry_ea=0x401000),
        maturity=ida_hexrays.MMAT_GLBOPT1,
        flow_graph=flow_graph,
        state_summary=StateModelSummary(
            state_constants=frozenset(),
            handler_count=0,
            transition_count=0,
        ),
    )
    observed = []

    monkeypatch.setattr(
        "d810.hexrays.observability.request_capture_mba_snapshot",
        lambda **_kwargs: "snap",
    )
    monkeypatch.setattr(
        "d810.recon.observability.observe_dag",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "d810.recon.observability.observe_dag_local_facts",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "d810.recon.observability.observe_rendered_program",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "d810.recon.observability.observe_state_transition_dispatch_resolutions",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "d810.recon.observability.observe_switch_case_transition_facts",
        lambda snap, facts: observed.append((snap, tuple(facts))),
    )

    EmulatedDispatcherStrategyFamily(
        profile=tigress_switch_dispatcher_profile(),
    ).observe_phase_diagnostics(
        snapshot.mba,
        snapshot,
    )

    assert observed == [("snap", (switch_fact,))]


def test_emulated_dispatcher_phase_diagnostics_reuse_materialized_dag_edges(
    monkeypatch,
) -> None:
    class SinglePassDag:
        def __init__(self, edges):
            self.nodes = ()
            self._edges = tuple(edges)
            self._consumed = False

        @property
        def edges(self):
            if self._consumed:
                return iter(())
            self._consumed = True
            return iter(self._edges)

    edge = SimpleNamespace(
        kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
        source_key=SimpleNamespace(state_const=0x10),
        target_key=SimpleNamespace(state_const=0x20),
        source_anchor=SimpleNamespace(block_serial=5, branch_arm=0),
        target_entry_anchor=9,
        ordered_path=(5, 9),
    )
    context = EmulatedDispatcherPhaseContext(
        bst_result=object(),
        transition_result=object(),
        transition_report=object(),
        dag=SinglePassDag((edge,)),
        semantic_reference_program=object(),
    )
    flow_graph = FlowGraph(
        blocks={
            0: BlockSnapshot(
                serial=0,
                block_type=ida_hexrays.BLT_0WAY,
                succs=(),
                preds=(),
                flags=0,
                start_ea=0x401000,
                insn_snapshots=(),
            )
        },
        entry_serial=0,
        func_ea=0x401000,
        metadata={EMULATED_DISPATCHER_PHASE_CONTEXT_KEY: context},
    )
    snapshot = AnalysisSnapshot(
        mba=SimpleNamespace(maturity=ida_hexrays.MMAT_GLBOPT1, entry_ea=0x401000),
        maturity=ida_hexrays.MMAT_GLBOPT1,
        flow_graph=flow_graph,
        state_summary=StateModelSummary(
            state_constants=frozenset(),
            handler_count=0,
            transition_count=0,
        ),
    )
    observed = []

    monkeypatch.setattr(
        "d810.hexrays.observability.request_capture_mba_snapshot",
        lambda **_kwargs: "snap",
    )
    monkeypatch.setattr(
        "d810.recon.observability.observe_dag",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "d810.recon.observability.observe_dag_local_facts",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "d810.recon.observability.observe_rendered_program",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "d810.recon.observability.observe_state_transition_dispatch_resolutions",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "d810.recon.observability.observe_branch_ownership_proofs",
        lambda snap, proofs: observed.append((snap, tuple(proofs))),
    )

    EmulatedDispatcherStrategyFamily(
        profile=ollvm_state_dispatcher_map_profile(),
    ).observe_phase_diagnostics(
        snapshot.mba,
        snapshot,
    )

    assert observed
    snap, proofs = observed[0]
    assert snap == "snap"
    assert proofs[0]["proof_kind"] == BranchOwnershipProofKind.UNRESOLVED.value
    assert proofs[0]["source_block"] == 5
    assert proofs[0]["branch_arm"] == 0


def test_emulated_dispatcher_family_blocks_residual_terminal_phase_reconstruction() -> None:
    def _snapshot(serial, succs, preds):
        return BlockSnapshot(
            serial=serial,
            block_type=ida_hexrays.BLT_1WAY if succs else ida_hexrays.BLT_0WAY,
            succs=tuple(succs),
            preds=tuple(preds),
            flags=0,
            start_ea=0x401000 + serial,
            insn_snapshots=(),
        )

    flow_graph = FlowGraph(
        blocks={
            0: _snapshot(0, (1,), ()),
            1: _snapshot(1, (), (0,)),
            2: _snapshot(2, (), (5,)),
            5: _snapshot(5, (2,), (8,)),
            7: _snapshot(7, (), (2,)),
            8: _snapshot(8, (5,), (7,)),
        },
        entry_serial=0,
        func_ea=0x401000,
    )
    family = EmulatedDispatcherStrategyFamily()
    artifact = EmulatedDispatcherPhaseArtifact(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=5,
        initial_state=0x10,
        bst_node_blocks=(2,),
        handler_state_map=((5, 0x10), (7, 0x20)),
        semantic_reference_variant="semantic_reference_like",
    )
    context = EmulatedDispatcherPhaseContext(
        bst_result=object(),
        transition_result=object(),
        transition_report=object(),
        dag=SimpleNamespace(
            edges=(
                SimpleNamespace(kind=SemanticEdgeKind.CONDITIONAL_RETURN),
            ),
        ),
        semantic_reference_program=object(),
    )
    detection = EmulatedDispatcherDetection(
        dispatcher_shape="conditional_chain",
        state_transport="state_dispatcher_map",
        lowering_mode="generic_graph_modifications",
        state_constants=(0x10, 0x20),
    )

    modifications, blockers = family._collect_phase_reconstruction_modifications(
        mba=_fake_mba(),
        flow_graph=flow_graph,
        detection=detection,
        phase_artifact=artifact,
        phase_context=context,
    )

    assert modifications == ()
    assert blockers == (
        "phase_reconstruction_residual_terminal_frontier_not_loop_aware",
    )


def test_emulated_dispatcher_family_uses_injected_resolver_for_lowering() -> None:
    profile_calls = []
    histories = (object(),)
    father = SimpleNamespace(serial=5, nsucc=lambda: 1, succ=lambda _idx: 2)
    target = SimpleNamespace(serial=9, nsucc=lambda: 0, tail=None, nextb=None)
    dispatcher_info = object()

    class _Collector:
        def get_dispatcher_list(self):
            return [dispatcher_info]

    class _Resolver:
        pass

    class _Profile(GenericDispatcherEngineProfile):
        def configure_resolver(self, resolver, *, mba, detection):
            profile_calls.append(("configure", mba.maturity))
            resolver.mba = mba
            resolver.cur_maturity = mba.maturity
            resolver.cur_maturity_pass = 0
            resolver.dispatcher_list = list(detection.collector_dispatchers)
            return resolver

        def dispatcher_entry_serial(self, seen_dispatcher_info):
            assert seen_dispatcher_info is dispatcher_info
            profile_calls.append(("entry_serial",))
            return 2

        def dispatcher_predecessor_serials(self, seen_dispatcher_info):
            assert seen_dispatcher_info is dispatcher_info
            profile_calls.append(("predecessors",))
            return (5,)

        def collect_dispatcher_father_histories(
            self,
            resolver,
            dispatcher_father,
            seen_dispatcher_info,
        ):
            assert seen_dispatcher_info is dispatcher_info
            profile_calls.append(("histories", dispatcher_father.serial))
            return histories

        def histories_resolved(self, resolver, seen_histories):
            profile_calls.append(("resolved", seen_histories is histories))
            return True

        def resolve_state_values(self, seen_histories, seen_dispatcher_info):
            assert seen_histories is histories
            assert seen_dispatcher_info is dispatcher_info
            profile_calls.append(("values",))
            return [[0x1234]]

        def state_values_complete(self, values):
            profile_calls.append(("complete", values == [[0x1234]]))
            return True

        def emulate_dispatcher_target(self, seen_dispatcher_info, history):
            assert seen_dispatcher_info is dispatcher_info
            assert history is histories[0]
            profile_calls.append(("emulate",))
            return target, ()

        def filter_dependency_safe_copies(
            self,
            resolver,
            dispatcher_father,
            raw_ins_to_copy,
        ):
            profile_calls.append(("copies", dispatcher_father.serial, len(raw_ins_to_copy)))
            return list(raw_ins_to_copy)

    mba = SimpleNamespace(
        maturity=ida_hexrays.MMAT_GLBOPT2,
        entry_ea=0x401000,
        get_mblock=lambda serial: father if serial == 5 else None,
    )

    def _snapshot(serial, succs, preds):
        return BlockSnapshot(
            serial=serial,
            block_type=ida_hexrays.BLT_1WAY if succs else ida_hexrays.BLT_0WAY,
            succs=tuple(succs),
            preds=tuple(preds),
            flags=0,
            start_ea=0x401000 + serial,
            insn_snapshots=(),
        )

    flow_graph = FlowGraph(
        blocks={
            2: _snapshot(2, (), (5,)),
            5: _snapshot(5, (2,), ()),
            9: _snapshot(9, (), ()),
        },
        entry_serial=5,
        func_ea=0x401000,
    )
    family = EmulatedDispatcherStrategyFamily(
        profile=_Profile(
            name="fixture",
            collector_factory=_Collector,
            resolver_factory=_Resolver,
            state_transport="fixture_transport",
            lowering_mode="fixture_lowering",
            provenance_hints=("fixture_profile",),
        )
    )
    detection = EmulatedDispatcherDetection(
        collector_dispatchers=(dispatcher_info,),
        collector_dispatcher_entries=(2,),
        analysis_dispatchers=(2,),
        dispatcher_shape="profile_kind",
        state_transport="fixture_transport",
        lowering_mode="fixture_lowering",
        provenance_hints=("fixture_profile",),
        state_constants=(0x1234,),
    )

    modifications, blockers, records = family._collect_lowering_candidates(
        mba,
        detection,
        flow_graph=flow_graph,
    )

    assert modifications == (
        RedirectGoto(from_serial=5, old_target=2, new_target=9),
    )
    assert blockers == ()
    assert records[0].selection_reason == "direct_redirect"
    assert ("configure", ida_hexrays.MMAT_GLBOPT2) in profile_calls
    assert ("predecessors",) in profile_calls
    assert ("histories", 5) in profile_calls
    assert ("resolved", True) in profile_calls
    assert ("values",) in profile_calls
    assert ("complete", True) in profile_calls
    assert ("emulate",) in profile_calls
    assert ("copies", 5, 0) in profile_calls


def test_emulated_dispatcher_family_dynamic_transition_uses_profile_selector(
    monkeypatch,
) -> None:
    dispatcher_info = object()
    selected_transition = SimpleNamespace(
        from_block=5,
        to_state=0x1234,
        provenance_kind="profile_specific_state_write",
    )
    source_handler = SimpleNamespace(check_block=5, transitions=(selected_transition,))
    target_handler = SimpleNamespace(check_block=9, transitions=())
    transition_result = SimpleNamespace(
        handlers={
            0x1111: source_handler,
            0x1234: target_handler,
        }
    )
    profile_calls = []

    class _Collector:
        def get_dispatcher_list(self):
            return [dispatcher_info]

    class _Resolver:
        pass

    class _Profile(GenericDispatcherEngineProfile):
        def dispatcher_entry_serial(self, seen_dispatcher_info):
            assert seen_dispatcher_info is dispatcher_info
            return 2

        def select_dynamic_transition(self, seen_transition_result, *, father_serial):
            assert seen_transition_result is transition_result
            profile_calls.append(("select", father_serial))
            return selected_transition, source_handler

        def dynamic_guard_fallthrough(
            self,
            seen_transition_result,
            *,
            target_state,
            target_serial,
            father_serial,
        ):
            assert seen_transition_result is transition_result
            profile_calls.append(("fallthrough", target_state, target_serial, father_serial))
            return 11

    family = EmulatedDispatcherStrategyFamily(
        profile=_Profile(
            name="fixture",
            collector_factory=_Collector,
            resolver_factory=_Resolver,
            state_transport="fixture_transport",
            lowering_mode="fixture_lowering",
        )
    )
    monkeypatch.setattr(
        family,
        "_find_dispatcher_ref_block_for_state",
        lambda *_args, **_kwargs: 7,
    )
    father = SimpleNamespace(serial=5, nsucc=lambda: 1, succ=lambda _idx: 2)
    phase_artifact = EmulatedDispatcherPhaseArtifact(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x20,
    )
    phase_context = EmulatedDispatcherPhaseContext(
        bst_result=object(),
        transition_result=transition_result,
        transition_report=object(),
        dag=object(),
        semantic_reference_program=object(),
    )

    result = family._build_dynamic_transition_candidate(
        mba=object(),
        dispatcher_father=father,
        dispatcher_info=dispatcher_info,
        phase_artifact=phase_artifact,
        phase_context=phase_context,
        scc_memberships={},
    )

    assert result is not None
    modifications, record = result
    assert modifications == (
        CreateConditionalRedirect(
            source_block=5,
            ref_block=7,
            conditional_target=9,
            fallthrough_target=11,
        ),
    )
    assert record.selection_reason == "dynamic_state_write_conditional_redirect"
    assert profile_calls == [
        ("select", 5),
        ("fallthrough", 0x1234, 9, 5),
    ]


def test_emulated_dispatcher_family_build_snapshot_attaches_observation_metadata(
    monkeypatch,
) -> None:
    mba = _fake_mba()
    cache = object()
    monkeypatch.setattr(
        "d810.optimizers.microcode.flow.flattening.emulated_dispatcher_family.DispatcherCache",
        SimpleNamespace(get_or_create=lambda _mba: cache),
    )

    family = EmulatedDispatcherStrategyFamily(
        cfg_translator=SimpleNamespace(lift=lambda _mba: _flow_graph_with_edge())
    )
    detection = EmulatedDispatcherDetection(
        analysis_dispatchers=(3, 5),
        dispatcher_shape="unknown",
        state_transport="father_history_emulation",
        lowering_mode="generic_graph_modifications",
        provenance_hints=(),
        state_constants=(0xF6A1E, 0xF6A1F),
        collector_dispatcher_entries=(),
        planning_blocker="dispatcher_cache_detected_but_collector_found_none",
    )

    snapshot = family.build_snapshot(mba, detection)
    observation = extract_emulated_dispatcher_metadata(snapshot.flow_graph)

    assert snapshot.dispatcher_cache is cache
    assert snapshot.state_summary == StateModelSummary(
        state_constants=frozenset({0xF6A1E, 0xF6A1F}),
        handler_count=2,
        transition_count=0,
    )
    assert observation == EmulatedDispatcherMetadata(
        dispatcher_shape="unknown",
        state_transport="father_history_emulation",
        lowering_mode="generic_graph_modifications",
        provenance_hints=(),
        analysis_dispatchers=(3, 5),
        state_constants=(0xF6A1E, 0xF6A1F),
        collector_dispatchers=(),
        planning_ready=False,
            planning_blocker="phase_linear_chain_not_supported_dispatcher",
        candidate_count=0,
        rejected_fathers=1,
        candidate_kinds=(),
            rejection_reasons=("phase_linear_chain_not_supported_dispatcher",),
        selected_lowering_mode="generic_graph_modifications",
    )


def test_emulated_dispatcher_family_build_snapshot_attaches_lowering_candidates(
    monkeypatch,
) -> None:
    mba = _fake_mba()
    cache = object()
    monkeypatch.setattr(
        "d810.optimizers.microcode.flow.flattening.emulated_dispatcher_family.DispatcherCache",
        SimpleNamespace(get_or_create=lambda _mba: cache),
    )

    family = EmulatedDispatcherStrategyFamily(
        cfg_translator=SimpleNamespace(lift=lambda _mba: _flow_graph_with_edge())
    )
    monkeypatch.setattr(
        family,
        "_collect_lowering_candidates",
        lambda _mba, _det, *, flow_graph, **_kwargs: (
            (RedirectGoto(from_serial=0, old_target=1, new_target=1),),
            ("dispatcher_source_shape_not_lowered",),
            (),
        ),
    )
    detection = EmulatedDispatcherDetection(
        analysis_dispatchers=(3,),
        dispatcher_shape="unknown",
        state_transport="father_history_emulation",
        lowering_mode="generic_graph_modifications",
        provenance_hints=(),
        state_constants=(0xF6A1E,),
        collector_dispatcher_entries=(2,),
    )

    snapshot = family.build_snapshot(mba, detection)
    observation = extract_emulated_dispatcher_metadata(snapshot.flow_graph)
    modifications = extract_emulated_dispatcher_modifications(snapshot.flow_graph)
    assert observation == EmulatedDispatcherMetadata(
        dispatcher_shape="unknown",
        state_transport="father_history_emulation",
        lowering_mode="generic_graph_modifications",
        provenance_hints=(),
        analysis_dispatchers=(3,),
        state_constants=(0xF6A1E,),
        collector_dispatchers=(2,),
        planning_ready=False,
        planning_blocker="dispatcher_source_shape_not_lowered",
        candidate_count=1,
        rejected_fathers=1,
        candidate_kinds=("RedirectGoto",),
        rejection_reasons=("dispatcher_source_shape_not_lowered",),
        selected_lowering_mode="generic_graph_modifications",
        selected_modification_count=1,
    )
    assert modifications == (
        RedirectGoto(from_serial=0, old_target=1, new_target=1),
    )
    assert snapshot.flow_graph.metadata[EMULATED_DISPATCHER_MODIFICATIONS_KEY] == modifications


def test_emulated_dispatcher_family_build_snapshot_keeps_safe_conditional_target_candidate(
    monkeypatch,
) -> None:
    mba = _fake_mba()
    cache = object()
    monkeypatch.setattr(
        "d810.optimizers.microcode.flow.flattening.emulated_dispatcher_family.DispatcherCache",
        SimpleNamespace(get_or_create=lambda _mba: cache),
    )

    family = EmulatedDispatcherStrategyFamily(
        cfg_translator=SimpleNamespace(
            lift=lambda _mba: _flow_graph_with_conditional_shape()
        )
    )
    monkeypatch.setattr(
        family,
        "_collect_lowering_candidates",
        lambda _mba, _det, *, flow_graph, **_kwargs: (
            (
                CreateConditionalRedirect(
                    source_block=0,
                    ref_block=1,
                    conditional_target=2,
                    fallthrough_target=3,
                ),
            ),
            (),
            (),
        ),
    )
    detection = EmulatedDispatcherDetection(
        analysis_dispatchers=(3,),
        dispatcher_shape="unknown",
        state_transport="father_history_emulation",
        lowering_mode="generic_graph_modifications",
        provenance_hints=(),
        state_constants=(0xF6A1E,),
        collector_dispatcher_entries=(2,),
    )

    snapshot = family.build_snapshot(mba, detection)
    observation = extract_emulated_dispatcher_metadata(snapshot.flow_graph)
    modifications = extract_emulated_dispatcher_modifications(snapshot.flow_graph)

    assert observation == EmulatedDispatcherMetadata(
        dispatcher_shape="unknown",
        state_transport="father_history_emulation",
        lowering_mode="generic_graph_modifications",
        provenance_hints=(),
        analysis_dispatchers=(3,),
        state_constants=(0xF6A1E,),
        collector_dispatchers=(2,),
        planning_ready=True,
        planning_blocker=None,
        candidate_count=1,
        rejected_fathers=0,
        candidate_kinds=("CreateConditionalRedirect",),
        rejection_reasons=(),
        selected_lowering_mode="generic_graph_modifications",
        selected_modification_count=1,
    )
    assert modifications == (
        CreateConditionalRedirect(
            source_block=0,
            ref_block=1,
            conditional_target=2,
            fallthrough_target=3,
        ),
    )


def test_emulated_dispatcher_family_inserts_safe_copies_before_conditional_target(
    monkeypatch,
) -> None:
    family = EmulatedDispatcherStrategyFamily()
    safe_insn = SimpleNamespace(opcode=ida_hexrays.m_mov, name="safe")
    histories = (object(),)
    resolver = SimpleNamespace(
        mba=SimpleNamespace(entry_ea=0x401000, maturity=ida_hexrays.MMAT_GLBOPT2),
        get_dispatcher_father_histories=lambda *_args: histories,
        check_if_histories_are_resolved=lambda _histories: True,
        _filter_dependency_safe_copies=lambda _father, insns: list(insns),
    )
    dispatcher_father = SimpleNamespace(
        serial=9,
        nsucc=lambda: 1,
        succ=lambda _idx: 4,
    )
    target_blk = SimpleNamespace(
        serial=1,
        nsucc=lambda: 2,
        tail=SimpleNamespace(opcode=ida_hexrays.m_jnz, d=SimpleNamespace(b=2)),
        nextb=SimpleNamespace(serial=3),
    )
    dispatcher_info = SimpleNamespace(
        entry_block=SimpleNamespace(serial=7, use_before_def_list=()),
        emulate_dispatcher_with_father_history=lambda _history, resolve_conditional_exits=True: (
            target_blk,
            [safe_insn],
        ),
    )
    monkeypatch.setattr(
        "d810.optimizers.microcode.flow.flattening.emulated_dispatcher_family.get_all_possibles_values",
        lambda _histories, _use_before_def_list, verbose=False: [[0xF6A20]],
    )
    monkeypatch.setattr(
        "d810.optimizers.microcode.flow.flattening.emulated_dispatcher_family.check_if_all_values_are_found",
        lambda _values: True,
    )
    monkeypatch.setattr(
        "d810.optimizers.microcode.flow.flattening.emulated_dispatcher_family.capture_insn_snapshot",
        lambda insn: f"snap:{insn.name}",
    )

    candidate, reason, _record = family._build_lowering_candidate(
        resolver,
        dispatcher_father,
        dispatcher_info,
        scc_memberships={},
    )

    assert reason is None
    assert candidate == (
        InsertBlock(
            pred_serial=9,
            succ_serial=1,
            instructions=("snap:safe",),
            old_target_serial=4,
        ),
    )


def test_emulated_dispatcher_family_reuses_deferred_side_effects_after_calls(
    monkeypatch,
) -> None:
    family = EmulatedDispatcherStrategyFamily()
    safe_insn = SimpleNamespace(opcode=ida_hexrays.m_mov, name="safe")
    histories = (object(),)
    dispatcher_info = SimpleNamespace(
        entry_block=SimpleNamespace(serial=7, use_before_def_list=()),
    )
    dispatcher_father = SimpleNamespace(
        serial=9,
        nsucc=lambda: 1,
        succ=lambda _idx: 4,
    )
    target_blk = SimpleNamespace(
        serial=1,
        nsucc=lambda: 1,
        tail=None,
        nextb=None,
    )
    monkeypatch.setattr(
        "d810.optimizers.microcode.flow.flattening.emulated_dispatcher_family.get_all_possibles_values",
        lambda _histories, _use_before_def_list, verbose=False: [[0xF6A20]],
    )
    monkeypatch.setattr(
        "d810.optimizers.microcode.flow.flattening.emulated_dispatcher_family.check_if_all_values_are_found",
        lambda _values: True,
    )
    monkeypatch.setattr(
        "d810.optimizers.microcode.flow.flattening.emulated_dispatcher_family.capture_insn_snapshot",
        lambda insn: f"snap:{insn.name}",
    )

    resolver_calls = SimpleNamespace(
        mba=SimpleNamespace(entry_ea=0x401000, maturity=ida_hexrays.MMAT_CALLS),
        get_dispatcher_father_histories=lambda *_args: histories,
        check_if_histories_are_resolved=lambda _histories: True,
        _filter_dependency_safe_copies=lambda _father, insns: list(insns),
    )
    dispatcher_info.emulate_dispatcher_with_father_history = (
        lambda _history, resolve_conditional_exits=True: (target_blk, [safe_insn])
    )

    candidate, reason, _record = family._build_lowering_candidate(
        resolver_calls,
        dispatcher_father,
        dispatcher_info,
        scc_memberships={},
    )

    assert candidate is None
    assert reason == "dispatcher_side_effects_deferred_to_later_maturity"

    resolver_glbopt = SimpleNamespace(
        mba=SimpleNamespace(entry_ea=0x401000, maturity=ida_hexrays.MMAT_GLBOPT2),
        get_dispatcher_father_histories=lambda *_args: histories,
        check_if_histories_are_resolved=lambda _histories: True,
        _filter_dependency_safe_copies=lambda _father, insns: list(insns),
    )
    dispatcher_info.emulate_dispatcher_with_father_history = (
        lambda _history, resolve_conditional_exits=True: (target_blk, [])
    )

    candidate, reason, _record = family._build_lowering_candidate(
        resolver_glbopt,
        dispatcher_father,
        dispatcher_info,
        scc_memberships={},
    )

    assert reason is None
    assert candidate == (
        InsertBlock(
            pred_serial=9,
            succ_serial=1,
            instructions=("snap:safe",),
            old_target_serial=4,
        ),
    )


def test_emulated_dispatcher_unflattener_records_no_plan_provenance(
    monkeypatch,
) -> None:
    rule = EmulatedDispatcherUnflattener()
    mba = SimpleNamespace(
        maturity=ida_hexrays.MMAT_GLBOPT1,
        entry_ea=0x401000,
    )
    blk = SimpleNamespace(serial=0, mba=mba)
    outcomes: list[object] = []
    rule.set_flow_context(
        SimpleNamespace(report_outcome=lambda provenance, source: outcomes.append((provenance, source)))
    )

    detection = EmulatedDispatcherDetection(
        analysis_dispatchers=(7,),
        dispatcher_shape="unknown",
        state_transport="father_history_emulation",
        lowering_mode="generic_graph_modifications",
        provenance_hints=(),
        planning_blocker="dispatcher_cache_detected_but_collector_found_none",
    )
    snapshot = AnalysisSnapshot(
        mba=mba,
        maturity=ida_hexrays.MMAT_GLBOPT1,
        flow_graph=FlowGraph(
            blocks=_flow_graph().blocks,
            entry_serial=0,
            func_ea=0x401000,
            metadata={
                "emulated_dispatcher": EmulatedDispatcherMetadata(
                    dispatcher_shape="unknown",
                    state_transport="father_history_emulation",
                    lowering_mode="generic_graph_modifications",
                    provenance_hints=(),
                    analysis_dispatchers=(7,),
                    collector_dispatchers=(),
                    planning_ready=False,
                    planning_blocker="dispatcher_cache_detected_but_collector_found_none",
                    candidate_count=0,
                    rejected_fathers=0,
                    candidate_kinds=(),
                    rejection_reasons=(),
                )
            },
        ),
        state_summary=StateModelSummary(
            state_constants=frozenset(),
            handler_count=1,
            transition_count=0,
        ),
    )

    monkeypatch.setattr(rule._family, "detect", lambda _mba: detection)
    monkeypatch.setattr(rule._family, "build_snapshot", lambda _mba, _det: snapshot)

    assert rule.optimize(blk) == 0
    assert rule._last_provenance is not None
    assert {row.strategy_name for row in rule._last_provenance.rows} == {
        "dispatcher_loop_recovery",
        "emulated_dispatcher",
    }
    row = next(
        row
        for row in rule._last_provenance.rows
        if row.strategy_name == "emulated_dispatcher"
    )
    assert row.strategy_name == "emulated_dispatcher"
    assert row.phase == DecisionPhase.INAPPLICABLE
    assert row.reason_code == DecisionReasonCode.REJECTED_INAPPLICABLE
    assert outcomes == [(rule._last_provenance, "planner")]
    assert rule.get_last_observation()["snapshot"] == {
        "dispatcher_shape": "unknown",
        "state_transport": "father_history_emulation",
        "lowering_mode": "generic_graph_modifications",
        "provenance_hints": (),
            "analysis_dispatchers": (7,),
            "state_dispatcher_entries": (),
            "state_constants": (),
        "collector_dispatchers": (),
        "planning_ready": False,
        "planning_blocker": "dispatcher_cache_detected_but_collector_found_none",
        "candidate_count": 0,
        "rejected_fathers": 0,
        "candidate_kinds": (),
        "rejection_reasons": (),
        "candidate_records": (),
        "phase_artifact": None,
        "selected_lowering_mode": None,
        "selected_modification_count": 0,
        "loop_recovery_modification_count": 0,
    }


def test_emulated_dispatcher_strategy_plans_validated_snapshot_modifications() -> None:
    strategy = EmulatedDispatcherStrategy()
    snapshot = AnalysisSnapshot(
        mba=SimpleNamespace(maturity=ida_hexrays.MMAT_GLBOPT1, entry_ea=0x401000),
        maturity=ida_hexrays.MMAT_GLBOPT1,
        flow_graph=FlowGraph(
            blocks=_flow_graph_with_edge().blocks,
            entry_serial=0,
            func_ea=0x401000,
            metadata={
                "emulated_dispatcher": EmulatedDispatcherMetadata(
                    dispatcher_shape="unknown",
                    state_transport="father_history_emulation",
                    lowering_mode="generic_graph_modifications",
                    provenance_hints=(),
                    analysis_dispatchers=(7,),
                    collector_dispatchers=(2,),
                    planning_ready=True,
                    planning_blocker=None,
                    candidate_count=1,
                    rejected_fathers=0,
                    candidate_kinds=("RedirectGoto",),
                    rejection_reasons=(),
                ),
                EMULATED_DISPATCHER_MODIFICATIONS_KEY: (
                    RedirectGoto(from_serial=0, old_target=1, new_target=1),
                ),
            },
        ),
        state_summary=StateModelSummary(
            state_constants=frozenset(),
            handler_count=1,
            transition_count=0,
        ),
    )

    fragment = strategy.plan(snapshot)

    assert fragment is not None
    assert fragment.strategy_name == "emulated_dispatcher"
    assert fragment.metadata["safeguard_min_required"] == 1
    assert fragment.modifications == [
        RedirectGoto(from_serial=0, old_target=1, new_target=1),
    ]


def test_emulated_dispatcher_strategy_rejects_partial_lowering_when_blockers_exist() -> None:
    graph = FlowGraph(
        blocks=_flow_graph_with_edge().blocks,
        entry_serial=0,
        func_ea=0x401000,
        metadata={
            EMULATED_DISPATCHER_METADATA_KEY: EmulatedDispatcherMetadata(
                dispatcher_shape="unknown",
                state_transport="father_history_emulation",
                lowering_mode="generic_graph_modifications",
                provenance_hints=(),
                analysis_dispatchers=(7,),
                collector_dispatchers=(2,),
                planning_ready=False,
                planning_blocker="dispatcher_history_missing_values",
                candidate_count=1,
                rejected_fathers=1,
                candidate_kinds=("RedirectGoto",),
                rejection_reasons=("dispatcher_history_missing_values",),
            ),
            EMULATED_DISPATCHER_MODIFICATIONS_KEY: (
                RedirectGoto(from_serial=0, old_target=1, new_target=1),
            ),
        },
    )
    snapshot = AnalysisSnapshot(
        mba=SimpleNamespace(maturity=ida_hexrays.MMAT_GLBOPT1),
        maturity=ida_hexrays.MMAT_GLBOPT1,
        flow_graph=graph,
        state_summary=StateModelSummary(
            state_constants=frozenset(),
            handler_count=1,
            transition_count=0,
        ),
    )

    strategy = EmulatedDispatcherStrategy()
    assert strategy.is_applicable(snapshot) is False
    assert strategy.plan(snapshot) is None


def test_emulated_dispatcher_unflattener_counts_family_post_execute_cleanup(
    monkeypatch,
) -> None:
    rule = EmulatedDispatcherUnflattener()
    mba = SimpleNamespace(
        maturity=ida_hexrays.MMAT_GLBOPT1,
        entry_ea=0x401000,
    )
    blk = SimpleNamespace(serial=0, mba=mba)
    snapshot = AnalysisSnapshot(
        mba=mba,
        maturity=ida_hexrays.MMAT_GLBOPT1,
        flow_graph=FlowGraph(
            blocks=_flow_graph_with_edge().blocks,
            entry_serial=0,
            func_ea=0x401000,
            metadata={
                "emulated_dispatcher": EmulatedDispatcherMetadata(
                    dispatcher_shape="unknown",
                    state_transport="father_history_emulation",
                    lowering_mode="generic_graph_modifications",
                    provenance_hints=(),
                    analysis_dispatchers=(7,),
                    collector_dispatchers=(2,),
                    planning_ready=True,
                    planning_blocker=None,
                    candidate_count=1,
                    rejected_fathers=0,
                    candidate_kinds=("RedirectGoto",),
                    rejection_reasons=(),
                )
            },
        ),
        state_summary=StateModelSummary(
            state_constants=frozenset(),
            handler_count=1,
            transition_count=0,
        ),
    )

    monkeypatch.setattr(
        rule._family,
        "detect",
        lambda _mba: EmulatedDispatcherDetection(
            analysis_dispatchers=(7,),
            dispatcher_shape="unknown",
            state_transport="father_history_emulation",
            lowering_mode="generic_graph_modifications",
            provenance_hints=(),
        ),
    )
    monkeypatch.setattr(rule._family, "build_snapshot", lambda _mba, _det: snapshot)
    monkeypatch.setattr(
        "d810.optimizers.microcode.flow.flattening.unflattener_emulated_dispatcher_engine.plan_family_pipeline",
        lambda *args, **kwargs: PlannedPipeline(
            pipeline=[object()],
            provenance=PipelineProvenance(),
        ),
    )
    monkeypatch.setattr(
        "d810.optimizers.microcode.flow.flattening.unflattener_emulated_dispatcher_engine.execute_family_pipeline",
        lambda *args, **kwargs: ExecutedPipeline(
            pipeline=[object()],
            results=[],
            provenance=PipelineProvenance(),
            total_changes=2,
            executor=None,
        ),
    )
    monkeypatch.setattr(
        rule._family,
        "post_execute_cleanup",
        lambda _mba, *, snapshot, total_changes: 3,
    )

    assert rule.optimize(blk) == 5


def test_emulated_dispatcher_family_skips_deep_cleaning_for_insert_block(
    monkeypatch,
) -> None:
    family = EmulatedDispatcherStrategyFamily()
    calls: list[tuple[str, object]] = []
    mba = SimpleNamespace(
        mark_chains_dirty=lambda: calls.append(("mark", None)),
        optimize_local=lambda _arg: calls.append(("optimize_local", _arg)),
    )
    snapshot = AnalysisSnapshot(
        mba=mba,
        maturity=ida_hexrays.MMAT_GLBOPT1,
        flow_graph=FlowGraph(
            blocks=_flow_graph_with_edge().blocks,
            entry_serial=0,
            func_ea=0x401000,
            metadata={
                EMULATED_DISPATCHER_METADATA_KEY: EmulatedDispatcherMetadata(
                    dispatcher_shape="unknown",
                    state_transport="father_history_emulation",
                    lowering_mode="generic_graph_modifications",
                    provenance_hints=(),
                    analysis_dispatchers=(7,),
                    collector_dispatchers=(2,),
                    planning_ready=True,
                    planning_blocker=None,
                    candidate_count=1,
                    rejected_fathers=0,
                    candidate_kinds=("InsertBlock",),
                    rejection_reasons=(),
                ),
                EMULATED_DISPATCHER_MODIFICATIONS_KEY: (
                    InsertBlock(
                        pred_serial=0,
                        succ_serial=2,
                        old_target_serial=1,
                        instructions=("snap:safe",),
                    ),
                ),
            },
        ),
        state_summary=StateModelSummary(
            state_constants=frozenset(),
            handler_count=1,
            transition_count=0,
        ),
    )

    monkeypatch.setattr(
        "d810.optimizers.microcode.flow.flattening.emulated_dispatcher_family.mba_deep_cleaning",
        lambda _mba, _final: calls.append(("deep_clean", None)) or 0,
    )
    monkeypatch.setattr(
        "d810.optimizers.microcode.flow.flattening.emulated_dispatcher_family.safe_verify",
        lambda _mba, context, logger_func=None: calls.append(("verify", context)),
    )

    assert family.post_execute_cleanup(mba, snapshot=snapshot, total_changes=1) == 0
    assert calls == [
        ("mark", None),
        (
            "verify",
            "verifying EmulatedDispatcherUnflattener.optimize after deferred edge-split apply",
        ),
    ]


def test_emulated_dispatcher_family_skips_deep_cleaning_for_conditional_redirect(
    monkeypatch,
) -> None:
    family = EmulatedDispatcherStrategyFamily()
    calls: list[tuple[str, object]] = []
    mba = SimpleNamespace(
        mark_chains_dirty=lambda: calls.append(("mark", None)),
        optimize_local=lambda _arg: calls.append(("optimize_local", _arg)),
    )
    snapshot = AnalysisSnapshot(
        mba=mba,
        maturity=ida_hexrays.MMAT_GLBOPT1,
        flow_graph=FlowGraph(
            blocks=_flow_graph_with_conditional_shape().blocks,
            entry_serial=0,
            func_ea=0x401000,
            metadata={
                EMULATED_DISPATCHER_METADATA_KEY: EmulatedDispatcherMetadata(
                    dispatcher_shape="unknown",
                    state_transport="father_history_emulation",
                    lowering_mode="generic_graph_modifications",
                    provenance_hints=(),
                    analysis_dispatchers=(7,),
                    collector_dispatchers=(2,),
                    planning_ready=True,
                    planning_blocker=None,
                    candidate_count=1,
                    rejected_fathers=0,
                    candidate_kinds=("CreateConditionalRedirect",),
                    rejection_reasons=(),
                ),
                EMULATED_DISPATCHER_MODIFICATIONS_KEY: (
                    CreateConditionalRedirect(
                        source_block=0,
                        ref_block=1,
                        conditional_target=2,
                        fallthrough_target=3,
                        instructions=("snap:safe",),
                    ),
                ),
            },
        ),
        state_summary=StateModelSummary(
            state_constants=frozenset(),
            handler_count=1,
            transition_count=0,
        ),
    )

    monkeypatch.setattr(
        "d810.optimizers.microcode.flow.flattening.emulated_dispatcher_family.mba_deep_cleaning",
        lambda _mba, _final: calls.append(("deep_clean", None)) or 0,
    )
    monkeypatch.setattr(
        "d810.optimizers.microcode.flow.flattening.emulated_dispatcher_family.safe_verify",
        lambda _mba, context, logger_func=None: calls.append(("verify", context)),
    )

    assert family.post_execute_cleanup(mba, snapshot=snapshot, total_changes=1) == 0
    assert calls == [
        ("mark", None),
        (
            "verify",
            "verifying EmulatedDispatcherUnflattener.optimize after deferred edge-split apply",
        ),
    ]


def test_emulated_dispatcher_unflattener_builds_snapshot_from_detection(
    monkeypatch,
) -> None:
    rule = EmulatedDispatcherUnflattener()
    mba = SimpleNamespace(
        maturity=ida_hexrays.MMAT_GLBOPT1,
        entry_ea=0x401000,
    )
    blk = SimpleNamespace(serial=0, mba=mba)
    initial_detection = EmulatedDispatcherDetection(
        analysis_dispatchers=(2,),
        dispatcher_shape="unknown",
        state_transport="father_history_emulation",
        lowering_mode="generic_graph_modifications",
        provenance_hints=(),
        collector_dispatcher_entries=(2,),
    )
    snapshot = AnalysisSnapshot(
        mba=mba,
        maturity=ida_hexrays.MMAT_GLBOPT1,
        flow_graph=FlowGraph(
            blocks=_flow_graph().blocks,
            entry_serial=0,
            func_ea=0x401000,
            metadata={
                "emulated_dispatcher": EmulatedDispatcherMetadata(
                    dispatcher_shape="unknown",
                    state_transport="father_history_emulation",
                    lowering_mode="generic_graph_modifications",
                    provenance_hints=(),
                    analysis_dispatchers=(2, 3),
                    collector_dispatchers=(2,),
                    planning_ready=False,
                    planning_blocker="dispatcher_cache_detected_but_collector_found_none",
                    candidate_count=0,
                    rejected_fathers=0,
                    candidate_kinds=(),
                    rejection_reasons=(),
                )
            },
        ),
        state_summary=StateModelSummary(
            state_constants=frozenset(),
            handler_count=2,
            transition_count=0,
        ),
    )
    build_inputs = []

    monkeypatch.setattr(rule._family, "detect", lambda _mba: initial_detection)
    monkeypatch.setattr(
        rule._family,
        "build_snapshot",
        lambda _mba, detection: build_inputs.append(detection) or snapshot,
    )

    assert rule.optimize(blk) == 0
    assert build_inputs == [initial_detection]


@pytest.fixture(scope="class")
def libobfuscated_setup(ida_database, configure_hexrays, setup_libobfuscated_funcs):
    if not idaapi.init_hexrays_plugin():
        pytest.skip("Hex-Rays decompiler plugin not available")
    return ida_database


class TestEmulatedDispatcherManagedContext:
    binary_name = _get_default_binary()

    def test_approov_real_pattern_post_apply_dump_preserves_verify_in_managed_context(
        self,
        libobfuscated_setup,
        d810_state,
        monkeypatch,
    ) -> None:
        import d810.cfg.contracts.transaction_engine as tx_engine_mod
        import d810.optimizers.microcode.flow.flattening.engine.executor as executor_mod
        import d810.optimizers.microcode.flow.flattening.unflattener_emulated_dispatcher_engine as engine_mod
        import d810.hexrays.mutation.ir_translator as ir_translator_mod

        func_ea = get_func_ea("approov_real_pattern")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'approov_real_pattern' not found")

        observed: dict[str, object] = {}
        checkpoints: list[tuple[str, str | None]] = []
        original_tx_apply = tx_engine_mod.CfgTransactionEngine.apply
        original_dump = executor_mod.mba_to_human_readable
        original_execute = engine_mod.execute_family_pipeline
        original_cleanup = EmulatedDispatcherStrategyFamily.post_execute_cleanup
        original_lift = ir_translator_mod.IDAIRTranslator.lift
        original_terminal_audit = executor_mod.TransactionalExecutor._run_terminal_return_audit

        def _wrapped_tx_apply(self, *args, **kwargs):
            result = original_tx_apply(self, *args, **kwargs)
            mba = kwargs["mba"]
            observed["transaction_success"] = result.success
            observed["verify_error_after_transaction_apply"] = _verify_error(mba)
            return result

        def _wrapped_dump(mba):
            rendered = original_dump(mba)
            checkpoints.append(("after_post_apply_dump", _verify_error(mba)))
            return rendered

        def _wrapped_lift(self, mba):
            lifted = original_lift(self, mba)
            checkpoints.append(("after_translator_lift", _verify_error(mba)))
            return lifted

        def _wrapped_terminal_audit(self, fragment, pre_cfg, result):
            out = original_terminal_audit(self, fragment, pre_cfg, result)
            checkpoints.append(("after_terminal_return_audit", _verify_error(self.mba)))
            return out

        def _wrapped_execute(*args, **kwargs):
            executed = original_execute(*args, **kwargs)
            snapshot = args[0]
            observed["verify_error_after_execute"] = _verify_error(snapshot.mba)
            observed["total_changes_after_execute"] = executed.total_changes
            return executed

        def _wrapped_cleanup(self, mba, *, snapshot, total_changes):
            observed["verify_error_before_cleanup"] = _verify_error(mba)
            observed["cleanup_total_changes"] = total_changes
            return original_cleanup(self, mba, snapshot=snapshot, total_changes=total_changes)

        monkeypatch.setattr(tx_engine_mod.CfgTransactionEngine, "apply", _wrapped_tx_apply)
        monkeypatch.setattr(executor_mod, "mba_to_human_readable", _wrapped_dump)
        monkeypatch.setattr(engine_mod, "execute_family_pipeline", _wrapped_execute)
        monkeypatch.setattr(ir_translator_mod.IDAIRTranslator, "lift", _wrapped_lift)
        monkeypatch.setattr(
            executor_mod.TransactionalExecutor,
            "_run_terminal_return_audit",
            _wrapped_terminal_audit,
        )
        monkeypatch.setattr(
            EmulatedDispatcherStrategyFamily,
            "post_execute_cleanup",
            _wrapped_cleanup,
        )

        with d810_state() as state:
            state.stop_d810()
            project_name = "example_libobfuscated.json"
            project_index = _resolve_test_project_index(state, project_name)
            state.load_project(project_index)
            with state.for_project(project_name) as ctx:
                _apply_engine_wrapper_profile(ctx)
                state.stats.reset()
                state.start_d810()
                previous_override = _force_rule_scope_to_current_profile(state, ctx, func_ea)
                try:
                    cfunc = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
                    assert cfunc is not None
                finally:
                    _restore_forced_rule_scope(state, func_ea, previous_override)
            state.stop_d810()

        assert observed["transaction_success"] is True
        assert observed["verify_error_after_transaction_apply"] is None
        assert observed["total_changes_after_execute"] == 3
        assert observed["cleanup_total_changes"] == 3
        assert observed["verify_error_after_execute"] is None
        assert observed["verify_error_before_cleanup"] is None
        assert checkpoints
        first_bad = next((entry for entry in checkpoints if entry[1] is not None), None)
        assert first_bad is None

    def test_approov_real_pattern_stays_verify_clean_before_cleanup_when_post_apply_dump_is_disabled(
        self,
        libobfuscated_setup,
        d810_state,
        monkeypatch,
    ) -> None:
        import d810.cfg.contracts.transaction_engine as tx_engine_mod
        import d810.optimizers.microcode.flow.flattening.engine.executor as executor_mod
        import d810.optimizers.microcode.flow.flattening.unflattener_emulated_dispatcher_engine as engine_mod

        func_ea = get_func_ea("approov_real_pattern")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'approov_real_pattern' not found")

        observed: dict[str, object] = {}
        original_tx_apply = tx_engine_mod.CfgTransactionEngine.apply
        original_execute = engine_mod.execute_family_pipeline
        original_cleanup = EmulatedDispatcherStrategyFamily.post_execute_cleanup

        def _wrapped_tx_apply(self, *args, **kwargs):
            result = original_tx_apply(self, *args, **kwargs)
            observed["verify_error_after_transaction_apply"] = _verify_error(kwargs["mba"])
            return result

        def _wrapped_execute(*args, **kwargs):
            executed = original_execute(*args, **kwargs)
            observed["verify_error_after_execute"] = _verify_error(args[0].mba)
            observed["total_changes_after_execute"] = executed.total_changes
            return executed

        def _wrapped_cleanup(self, mba, *, snapshot, total_changes):
            observed["verify_error_before_cleanup"] = _verify_error(mba)
            observed["cleanup_total_changes"] = total_changes
            return original_cleanup(self, mba, snapshot=snapshot, total_changes=total_changes)

        monkeypatch.setattr(tx_engine_mod.CfgTransactionEngine, "apply", _wrapped_tx_apply)
        monkeypatch.setattr(executor_mod, "mba_to_human_readable", lambda _mba: [])
        monkeypatch.setattr(engine_mod, "execute_family_pipeline", _wrapped_execute)
        monkeypatch.setattr(
            EmulatedDispatcherStrategyFamily,
            "post_execute_cleanup",
            _wrapped_cleanup,
        )

        with d810_state() as state:
            state.stop_d810()
            project_name = "example_libobfuscated.json"
            project_index = _resolve_test_project_index(state, project_name)
            state.load_project(project_index)
            with state.for_project(project_name) as ctx:
                _apply_engine_wrapper_profile(ctx)
                state.stats.reset()
                state.start_d810()
                previous_override = _force_rule_scope_to_current_profile(state, ctx, func_ea)
                try:
                    cfunc = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
                    assert cfunc is not None
                finally:
                    _restore_forced_rule_scope(state, func_ea, previous_override)
            state.stop_d810()

        assert observed["verify_error_after_transaction_apply"] is None
        assert observed["total_changes_after_execute"] == 3
        assert observed["verify_error_after_execute"] is None
        assert observed["verify_error_before_cleanup"] is None

    def test_approov_multistate_managed_context_captures_failure_checkpoint(
        self,
        libobfuscated_setup,
        d810_state,
        monkeypatch,
    ) -> None:
        import d810.cfg.contracts.transaction_engine as tx_engine_mod
        import d810.optimizers.microcode.flow.flattening.engine.executor as executor_mod
        import d810.optimizers.microcode.flow.flattening.unflattener_emulated_dispatcher_engine as engine_mod
        import d810.hexrays.mutation.ir_translator as ir_translator_mod

        func_ea = get_func_ea("approov_multistate")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'approov_multistate' not found")

        observed: dict[str, object] = {}
        checkpoints: list[tuple[str, str | None]] = []
        original_tx_apply = tx_engine_mod.CfgTransactionEngine.apply
        original_dump = executor_mod.mba_to_human_readable
        original_execute = engine_mod.execute_family_pipeline
        original_cleanup = EmulatedDispatcherStrategyFamily.post_execute_cleanup
        original_lift = ir_translator_mod.IDAIRTranslator.lift
        original_terminal_audit = executor_mod.TransactionalExecutor._run_terminal_return_audit

        def _wrapped_tx_apply(self, *args, **kwargs):
            result = original_tx_apply(self, *args, **kwargs)
            mba = kwargs["mba"]
            observed["transaction_success"] = result.success
            observed["transaction_failure_phase"] = result.failure_phase
            observed["transaction_failure_detail"] = result.failure_detail
            observed["transaction_error"] = str(result.error) if result.error else None
            observed["verify_error_after_transaction_apply"] = _verify_error(mba)
            return result

        def _wrapped_dump(mba):
            rendered = original_dump(mba)
            checkpoints.append(("after_post_apply_dump", _verify_error(mba)))
            return rendered

        def _wrapped_lift(self, mba):
            lifted = original_lift(self, mba)
            checkpoints.append(("after_translator_lift", _verify_error(mba)))
            return lifted

        def _wrapped_terminal_audit(self, fragment, pre_cfg, result):
            out = original_terminal_audit(self, fragment, pre_cfg, result)
            checkpoints.append(("after_terminal_return_audit", _verify_error(self.mba)))
            return out

        def _wrapped_execute(*args, **kwargs):
            executed = original_execute(*args, **kwargs)
            snapshot = args[0]
            observed["verify_error_after_execute"] = _verify_error(snapshot.mba)
            observed["total_changes_after_execute"] = executed.total_changes
            return executed

        def _wrapped_cleanup(self, mba, *, snapshot, total_changes):
            observed["verify_error_before_cleanup"] = _verify_error(mba)
            observed["cleanup_total_changes"] = total_changes
            return original_cleanup(self, mba, snapshot=snapshot, total_changes=total_changes)

        monkeypatch.setattr(tx_engine_mod.CfgTransactionEngine, "apply", _wrapped_tx_apply)
        monkeypatch.setattr(executor_mod, "mba_to_human_readable", _wrapped_dump)
        monkeypatch.setattr(engine_mod, "execute_family_pipeline", _wrapped_execute)
        monkeypatch.setattr(ir_translator_mod.IDAIRTranslator, "lift", _wrapped_lift)
        monkeypatch.setattr(
            executor_mod.TransactionalExecutor,
            "_run_terminal_return_audit",
            _wrapped_terminal_audit,
        )
        monkeypatch.setattr(
            EmulatedDispatcherStrategyFamily,
            "post_execute_cleanup",
            _wrapped_cleanup,
        )

        with d810_state() as state:
            state.stop_d810()
            project_name = "example_libobfuscated.json"
            project_index = _resolve_test_project_index(state, project_name)
            state.load_project(project_index)
            with state.for_project(project_name) as ctx:
                _apply_engine_wrapper_profile(ctx)
                state.stats.reset()
                state.start_d810()
                previous_override = _force_rule_scope_to_current_profile(state, ctx, func_ea)
                try:
                    cfunc = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
                    assert cfunc is not None
                finally:
                    _restore_forced_rule_scope(state, func_ea, previous_override)
            state.stop_d810()

        print("APPROOV_MULTISTATE_MANAGED observed=", observed)
        print("APPROOV_MULTISTATE_MANAGED checkpoints=", checkpoints)

        assert "transaction_success" in observed

    def test_approov_multistate_records_candidate_batch_for_triage(
        self,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        monkeypatch,
    ) -> None:
        func_ea = get_func_ea("approov_multistate")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'approov_multistate' not found")

        captured: dict[str, object] = {}
        original_build_snapshot = EmulatedDispatcherStrategyFamily.build_snapshot

        def _wrapped_build_snapshot(self, mba, detection):
            snapshot = original_build_snapshot(self, mba, detection)
            metadata = extract_emulated_dispatcher_metadata(snapshot.flow_graph)
            records = extract_emulated_dispatcher_candidate_records(snapshot.flow_graph)
            if metadata is not None and metadata.candidate_count > int(
                captured.get("candidate_count", -1)
            ):
                captured["candidate_count"] = metadata.candidate_count
                captured["snapshot"] = asdict(metadata)
                captured["candidate_records"] = tuple(asdict(record) for record in records)
            return snapshot

        monkeypatch.setattr(
            EmulatedDispatcherStrategyFamily,
            "build_snapshot",
            _wrapped_build_snapshot,
        )

        with d810_state() as state:
            state.stop_d810()
            project_name = "example_libobfuscated.json"
            project_index = _resolve_test_project_index(state, project_name)
            state.load_project(project_index)
            with state.for_project(project_name) as ctx:
                _apply_engine_wrapper_profile(ctx)
                dispatcher_rule = next(
                    (
                        rule
                        for rule in ctx.active_blk_rules
                        if type(rule).__name__ == "EmulatedDispatcherUnflattener"
                    ),
                    None,
                )
                assert dispatcher_rule is not None
                state.stats.reset()
                state.start_d810()
                previous_override = _force_rule_scope_to_current_profile(
                    state, ctx, func_ea
                )
                try:
                    cfunc = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
                    assert cfunc is not None
                    _ = pseudocode_to_string(cfunc.get_pseudocode())
                finally:
                    _restore_forced_rule_scope(state, func_ea, previous_override)
            state.stop_d810()

        snapshot = captured["snapshot"]
        candidate_records = captured["candidate_records"]
        selected_indexes = tuple(
            sorted(
                {
                    idx
                    for record in candidate_records
                    for idx in record["selected_modification_indexes"]
                }
            )
        )
        print("APPROOV_MULTISTATE_CANDIDATE_RECORDS", candidate_records)
        assert snapshot["candidate_count"] == len(candidate_records) == 6
        assert snapshot["selected_modification_count"] >= len(selected_indexes) == 6
        assert snapshot["rejected_fathers"] == 0
        assert snapshot["selected_lowering_mode"] in {
            "generic_graph_modifications",
            "dispatcher_loop_recovery",
        }
        assert selected_indexes == tuple(range(snapshot["candidate_count"]))
        if snapshot["selected_lowering_mode"] == "dispatcher_loop_recovery":
            assert snapshot["selected_modification_count"] == 9
            assert set(snapshot["candidate_kinds"]) == {
                "ZeroStateWrite",
                "RedirectGoto",
                "RedirectBranch",
            }

    def test_approov_multistate_captures_phase_artifact(
        self,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        monkeypatch,
    ) -> None:
        func_ea = get_func_ea("approov_multistate")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'approov_multistate' not found")

        captured: dict[str, object] = {}
        original_build_snapshot = EmulatedDispatcherStrategyFamily.build_snapshot

        def _wrapped_build_snapshot(self, mba, detection):
            snapshot = original_build_snapshot(self, mba, detection)
            metadata = extract_emulated_dispatcher_metadata(snapshot.flow_graph)
            artifact = extract_emulated_dispatcher_phase_artifact(snapshot.flow_graph)
            if (
                metadata is not None
                and artifact is not None
                and metadata.candidate_count > int(captured.get("candidate_count", -1))
            ):
                captured["candidate_count"] = metadata.candidate_count
                captured["phase_artifact"] = asdict(artifact)
            return snapshot

        monkeypatch.setattr(
            EmulatedDispatcherStrategyFamily,
            "build_snapshot",
            _wrapped_build_snapshot,
        )

        with d810_state() as state:
            state.stop_d810()
            project_name = "example_libobfuscated.json"
            project_index = _resolve_test_project_index(state, project_name)
            state.load_project(project_index)
            with state.for_project(project_name) as ctx:
                _apply_engine_wrapper_profile(ctx)
                state.stats.reset()
                state.start_d810()
                previous_override = _force_rule_scope_to_current_profile(
                    state, ctx, func_ea
                )
                try:
                    cfunc = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
                    assert cfunc is not None
                    _ = pseudocode_to_string(cfunc.get_pseudocode())
                finally:
                    _restore_forced_rule_scope(state, func_ea, previous_override)
            state.stop_d810()

        artifact = captured["phase_artifact"]
        print("APPROOV_MULTISTATE_PHASE_ARTIFACT", artifact)

        assert artifact["dispatcher_entry_serial"] == 3
        assert artifact["pre_header_serial"] == 6
        assert artifact["initial_state"] == 0xF6A1F
        handler_state_map = dict(artifact["handler_state_map"])
        assert set(handler_state_map.values()) == {0xF6A1E, 0xF6A1F, 0xF6A25}
        assert handler_state_map[5] == 0xF6A1E
        assert handler_state_map[9] == 0xF6A1F
        assert artifact["dag_node_count"] == 6
        assert artifact["dag_edge_count"] == 12
        assert artifact["semantic_reference_variant"] == "semantic_reference_like"
        assert artifact["semantic_reference_line_count"] >= 30
        assert artifact["semantic_reference_node_count"] == 6
        assert "STATE_000F6A1F__" in artifact["semantic_reference_program"]
        assert "STATE_000F6A1E:" in artifact["semantic_reference_program"]
        # The rendered reference program may canonicalize range/anonymous
        # entries to STATE_00000000, but the structured labels retain the
        # recovered state identity. Assert the stable structured contract here.
        assert "0x000F6A26" in artifact["semantic_state_labels"]
        assert "s000F6A20" in artifact["semantic_reference_program"]
        assert "goto STATE_000F6A1E;" in artifact["semantic_reference_program"]
        assert "goto STATE_000F6A1F__" in artifact["semantic_reference_program"]

    def test_approov_vm_dispatcher_lowers_dynamic_state_write_with_guard(
        self,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        monkeypatch,
    ) -> None:
        func_ea = get_func_ea("approov_vm_dispatcher")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'approov_vm_dispatcher' not found")

        captured: dict[str, object] = {}
        original_build_snapshot = EmulatedDispatcherStrategyFamily.build_snapshot

        def _wrapped_build_snapshot(self, mba, detection):
            snapshot = original_build_snapshot(self, mba, detection)
            metadata = extract_emulated_dispatcher_metadata(snapshot.flow_graph)
            artifact = extract_emulated_dispatcher_phase_artifact(snapshot.flow_graph)
            if (
                metadata is not None
                and metadata.candidate_count >= int(captured.get("candidate_count", -1))
            ):
                captured["candidate_count"] = metadata.candidate_count
                captured["snapshot"] = asdict(metadata)
                if artifact is not None:
                    captured["phase_artifact"] = asdict(artifact)
            return snapshot

        monkeypatch.setattr(
            EmulatedDispatcherStrategyFamily,
            "build_snapshot",
            _wrapped_build_snapshot,
        )

        with d810_state() as state:
            state.stop_d810()
            project_name = "default_unflattening_approov.json"
            project_index = _resolve_test_project_index(state, project_name)
            state.load_project(project_index)
            with state.for_project(project_name) as ctx:
                _apply_engine_wrapper_profile(ctx)
                state.stats.reset()
                state.start_d810()
                previous_override = _force_rule_scope_to_current_profile(
                    state, ctx, func_ea
                )
                try:
                    cfunc = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
                    assert cfunc is not None
                    _ = pseudocode_to_string(cfunc.get_pseudocode())
                finally:
                    _restore_forced_rule_scope(state, func_ea, previous_override)
            state.stop_d810()

        snapshot = captured["snapshot"]
        assert snapshot["candidate_count"] == 3
        assert snapshot["selected_lowering_mode"] == "generic_graph_modifications"
        assert snapshot["loop_recovery_modification_count"] == 0
        assert snapshot["planning_ready"] is True
        assert snapshot["selected_modification_count"] == 3
        assert snapshot["candidate_kinds"] == (
            "InsertBlock",
            "CreateConditionalRedirect",
            "InsertBlock",
        )
        dynamic_record = next(
            record
            for record in snapshot["candidate_records"]
            if record["selection_reason"]
            == "dynamic_state_write_conditional_redirect"
        )
        assert dynamic_record["father_serial"] == 7
        assert dynamic_record["target_serial"] == 8
        assert dynamic_record["state_signature"] == (0xF6A20,)
        assert dynamic_record["selected_modification_summaries"] == (
            "CreateConditionalRedirect(src=7,ref=4,jcc=8,ft=6,insns=0)",
        )
        artifact = captured["phase_artifact"]
        program = artifact["semantic_reference_program"]
        f6a1f_block = program.split("STATE_000F6A1F:", 1)[1].split("\n\n", 1)[0]
        assert "goto STATE_000F6A20;" in f6a1f_block
        assert "goto STATE_000F6A1F;" not in f6a1f_block

    def test_dispatcher_loop_recovery_guard_rejects_returning_fallback_artifact(
        self,
    ) -> None:
        family = EmulatedDispatcherStrategyFamily()
        artifact = EmulatedDispatcherPhaseArtifact(
            dispatcher_entry_serial=3,
            state_var_stkoff=4,
            pre_header_serial=11,
            initial_state=0xF6A20,
            bst_node_blocks=(3, 4, 6),
            handler_state_map=((5, 0xF6A20), (7, 0xF6A1F), (12, 0xF6A25)),
            handler_range_map=((5, 0, 0xFFFFFFFF), (7, 0, 0xFFFFFFFF), (11, 0xF6A26, 0xFFFFFFFF)),
            transition_rows=3,
            dag_node_count=6,
            dag_edge_count=11,
            semantic_state_labels=(
                "0x00000000",
                "0x000F6A1F",
                "0x000F6A20",
                "0x000F6A21",
                "0x000F6A25",
                "0x000F6A25_fallback",
            ),
            semantic_reference_variant="semantic_reference_like",
            semantic_reference_line_count=32,
            semantic_reference_node_count=9,
            semantic_reference_program=(
                "STATE_000F6A1F:\\n"
                "    return result;\\n"
                "STATE_000F6A25_fallback:\\n"
                "    goto STATE_000F6A20;\\n"
            ),
        )

        blockers = family._dispatcher_loop_recovery_artifact_blockers(artifact)
        assert blockers == ("dispatcher_loop_recovery_fallback_phase",)

    def test_approov_multistate_marks_cluster_candidates_with_strict_key(
        self,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        monkeypatch,
    ) -> None:
        import d810.optimizers.microcode.flow.flattening.unflattener_emulated_dispatcher_engine as engine_mod

        func_ea = get_func_ea("approov_multistate")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'approov_multistate' not found")

        captured: dict[str, object] = {}
        original_execute = engine_mod.execute_family_pipeline

        def _wrapped_execute(snapshot, planned, **kwargs):
            metadata = extract_emulated_dispatcher_metadata(snapshot.flow_graph)
            records = extract_emulated_dispatcher_candidate_records(snapshot.flow_graph)
            modifications = extract_emulated_dispatcher_modifications(snapshot.flow_graph)
            if metadata is not None and len(modifications) > int(
                captured.get("candidate_count", -1)
            ):
                captured["candidate_count"] = len(modifications)
                captured["candidate_records"] = tuple(asdict(record) for record in records)
            return original_execute(snapshot, planned, **kwargs)

        monkeypatch.setattr(engine_mod, "execute_family_pipeline", _wrapped_execute)

        with d810_state() as state:
            state.stop_d810()
            project_name = "example_libobfuscated.json"
            project_index = _resolve_test_project_index(state, project_name)
            state.load_project(project_index)
            with state.for_project(project_name) as ctx:
                _apply_engine_wrapper_profile(ctx)
                state.stats.reset()
                state.start_d810()
                previous_override = _force_rule_scope_to_current_profile(
                    state, ctx, func_ea
                )
                try:
                    cfunc = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
                    assert cfunc is not None
                    _ = pseudocode_to_string(cfunc.get_pseudocode())
                finally:
                    _restore_forced_rule_scope(state, func_ea, previous_override)
            state.stop_d810()

        candidate_records = captured["candidate_records"]
        cluster_records = [
            record for record in candidate_records if record["cluster_candidate"]
        ]
        cluster_groups: dict[tuple[str, ...], list[int]] = {}
        for record in cluster_records:
            cluster_groups.setdefault(record["cluster_key"], []).append(
                record["father_serial"]
            )

        print(
            "APPROOV_MULTISTATE_CLUSTER_CANDIDATES",
            {
                "cluster_groups": {
                    key: tuple(sorted(value)) for key, value in cluster_groups.items()
                },
                "records": cluster_records,
            },
        )

        assert all(record["semantically_valid"] is True for record in candidate_records)
        assert all(
            record["structurally_legacy_equivalent"] is None
            for record in candidate_records
        )
        assert sorted(
            tuple(sorted(fathers)) for fathers in cluster_groups.values()
        ) == [(2, 6), (7, 11)]

    def test_approov_multistate_role_map_identifies_first_phase_unit(
        self,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        monkeypatch,
    ) -> None:
        import d810.optimizers.microcode.flow.flattening.unflattener_emulated_dispatcher_engine as engine_mod

        func_ea = get_func_ea("approov_multistate")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'approov_multistate' not found")

        captured: dict[str, object] = {}
        original_execute = engine_mod.execute_family_pipeline

        def _wrapped_execute(snapshot, planned, **kwargs):
            metadata = extract_emulated_dispatcher_metadata(snapshot.flow_graph)
            records = extract_emulated_dispatcher_candidate_records(snapshot.flow_graph)
            modifications = extract_emulated_dispatcher_modifications(snapshot.flow_graph)
            if metadata is not None and len(modifications) > int(
                captured.get("candidate_count", -1)
            ):
                captured["candidate_count"] = len(modifications)
                captured["candidate_records"] = tuple(asdict(record) for record in records)
            return original_execute(snapshot, planned, **kwargs)

        monkeypatch.setattr(engine_mod, "execute_family_pipeline", _wrapped_execute)

        with d810_state() as state:
            state.stop_d810()
            project_name = "example_libobfuscated.json"
            project_index = _resolve_test_project_index(state, project_name)
            state.load_project(project_index)
            with state.for_project(project_name) as ctx:
                _apply_engine_wrapper_profile(ctx)
                state.stats.reset()
                state.start_d810()
                previous_override = _force_rule_scope_to_current_profile(
                    state, ctx, func_ea
                )
                try:
                    cfunc = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
                    assert cfunc is not None
                    _ = pseudocode_to_string(cfunc.get_pseudocode())
                finally:
                    _restore_forced_rule_scope(state, func_ea, previous_override)
            state.stop_d810()

        role_map = _summarize_approov_multistate_phase_roles(
            captured["candidate_records"]
        )

        print("APPROOV_MULTISTATE_PHASE_ROLE_MAP", role_map)

        assert role_map["phase1_header"] == (
            (2, 9, ("InsertBlock",)),
            (6, 9, ("InsertBlock",)),
        )
        assert role_map["phase1_update"] == (
            (10, 5, ("InsertBlock",)),
        )
        assert role_map["phase2_multiply"] == (
            (7, 12, ("InsertBlock",)),
            (11, 12, ("InsertBlock",)),
        )
        assert role_map["phase_exit"] == (
            (14, 15, ("RedirectGoto",)),
        )

    def test_approov_multistate_phase_cycle_contract(
        self,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        monkeypatch,
    ) -> None:
        import d810.optimizers.microcode.flow.flattening.unflattener_emulated_dispatcher_engine as engine_mod

        func_ea = get_func_ea("approov_multistate")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'approov_multistate' not found")

        captured: dict[str, object] = {}
        original_execute = engine_mod.execute_family_pipeline

        def _wrapped_execute(snapshot, planned, **kwargs):
            metadata = extract_emulated_dispatcher_metadata(snapshot.flow_graph)
            records = extract_emulated_dispatcher_candidate_records(snapshot.flow_graph)
            modifications = extract_emulated_dispatcher_modifications(snapshot.flow_graph)
            if metadata is not None and len(modifications) > int(
                captured.get("candidate_count", -1)
            ):
                captured["candidate_count"] = len(modifications)
                captured["candidate_records"] = tuple(asdict(record) for record in records)
            return original_execute(snapshot, planned, **kwargs)

        monkeypatch.setattr(engine_mod, "execute_family_pipeline", _wrapped_execute)

        with d810_state() as state:
            state.stop_d810()
            project_name = "example_libobfuscated.json"
            project_index = _resolve_test_project_index(state, project_name)
            state.load_project(project_index)
            with state.for_project(project_name) as ctx:
                _apply_engine_wrapper_profile(ctx)
                state.stats.reset()
                state.start_d810()
                previous_override = _force_rule_scope_to_current_profile(
                    state, ctx, func_ea
                )
                try:
                    cfunc = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
                    assert cfunc is not None
                    _ = pseudocode_to_string(cfunc.get_pseudocode())
                finally:
                    _restore_forced_rule_scope(state, func_ea, previous_override)
            state.stop_d810()

        role_map = _summarize_approov_multistate_phase_roles(
            captured["candidate_records"]
        )
        contract = _build_approov_multistate_phase_cycle(role_map)

        print("APPROOV_MULTISTATE_PHASE_CYCLE_CONTRACT", asdict(contract))

        assert contract == PhaseCycleLowering(
            header_entries=(2, 6),
            header_target=9,
            body_entries=(10,),
            body_target=5,
            next_phase_entries=(7, 11),
            next_phase_target=12,
            terminal_entries=(14,),
            terminal_target=15,
            state_roles=(
                ("phase1_header", 0xF6A1F),
                ("phase1_update", 0xF6A1E),
                ("phase2_multiply", 0xF6A20),
                ("phase_exit", 0xF6A25),
            ),
        )

    def test_approov_multistate_cluster_grouping_experiment(
        self,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
        monkeypatch,
    ) -> None:
        assert code_comparator is not None, (
            "libclang required for cluster grouping experiment"
        )
        func_ea = get_func_ea("approov_multistate")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'approov_multistate' not found")

        def _run_legacy() -> tuple[str, dict[str, object]]:
            import d810.optimizers.microcode.flow.flattening.unflattener as legacy_mod

            captured: dict[str, object] = {}
            original_optimize = legacy_mod.Unflattener.optimize

            def _wrapped_optimize(rule, blk):
                result = original_optimize(rule, blk)
                if getattr(blk.mba, "entry_ea", None) == func_ea:
                    captured["final_flow_graph"] = lift_mba(blk.mba)
                    captured["final_maturity"] = int(blk.mba.maturity)
                return result

            with monkeypatch.context() as patch_ctx:
                patch_ctx.setattr(
                    legacy_mod.Unflattener,
                    "optimize",
                    _wrapped_optimize,
                )
                with d810_state() as state:
                    rendered = _decompile_with_project(
                        state,
                        func_ea,
                        "example_libobfuscated.json",
                        pseudocode_to_string,
                        engine_wrappers_only=False,
                    )
            assert "final_flow_graph" in captured
            return rendered, captured

        def _run_engine(*, clustered: bool) -> tuple[str, dict[str, object]]:
            import d810.optimizers.microcode.flow.flattening.unflattener_emulated_dispatcher_engine as engine_mod

            captured: dict[str, object] = {}
            original_execute = engine_mod.execute_family_pipeline
            original_cleanup = EmulatedDispatcherStrategyFamily.post_execute_cleanup

            def _wrap_cleanup(self, mba, *, snapshot, total_changes):
                cleaned = original_cleanup(
                    self,
                    mba,
                    snapshot=snapshot,
                    total_changes=total_changes,
                )
                captured["final_flow_graph"] = lift_mba(mba)
                return cleaned

            def _clustered_execute(snapshot, planned, **kwargs):
                modifications = extract_emulated_dispatcher_fallback_modifications(
                    snapshot.flow_graph
                )
                records = extract_emulated_dispatcher_candidate_records(
                    snapshot.flow_graph
                )
                captured["candidate_records"] = tuple(asdict(record) for record in records)

                grouped: dict[tuple[str, ...], list[EmulatedDispatcherCandidateRecord]] = {}
                for record in records:
                    if record.cluster_candidate:
                        grouped.setdefault(record.cluster_key, []).append(record)

                modifier = DeferredGraphModifier(snapshot.mba)
                # create_standalone_block() inserts at the current stop-block
                # serial and shifts the stop block to the new tail.
                next_serial = int(snapshot.mba.qty) - 1
                consumed_indexes: set[int] = set()
                cluster_payloads: list[tuple[str, ...]] = []

                for cluster_key in sorted(grouped):
                    cluster = sorted(grouped[cluster_key], key=lambda item: item.father_serial)
                    anchor = cluster[0]
                    followers = cluster[1:]
                    anchor_mods = tuple(
                        modifications[index]
                        for index in anchor.selected_modification_indexes
                    )
                    anchor_mod = next(
                        (
                            mod
                            for mod in anchor_mods
                            if isinstance(mod, (InsertBlock, RedirectGoto))
                        ),
                        None,
                    )
                    instructions = ()
                    if isinstance(anchor_mod, InsertBlock):
                        instructions = anchor_mod.instructions
                    elif isinstance(anchor_mod, RedirectGoto):
                        instructions = ()
                    else:
                        raise AssertionError(
                            f"Unexpected clustered modification in experiment: {anchor_mods}"
                        )
                    for mod in anchor_mods:
                        if isinstance(mod, ZeroStateWrite):
                            modifier.queue_zero_state_write(
                                int(mod.block_serial),
                                int(mod.insn_ea),
                                description=(
                                    f"cluster anchor zero state write "
                                    f"{mod.block_serial}@{mod.insn_ea:#x}"
                                ),
                            )
                        elif mod is not anchor_mod:
                            raise AssertionError(
                                f"Unexpected paired clustered modification in experiment: {mod}"
                            )
                    cluster_payloads.append(anchor.payload_signature)
                    modifier.queue_create_and_redirect(
                        source_block_serial=int(anchor.father_serial),
                        final_target_serial=int(anchor.target_serial),
                        instructions_to_copy=list(instructions),
                        expected_serial=next_serial,
                        description=f"cluster anchor {anchor.father_serial}->{anchor.target_serial}",
                    )
                    consumed_indexes.update(anchor.selected_modification_indexes)
                    for follower in followers:
                        modifier.queue_goto_change(
                            block_serial=int(follower.father_serial),
                            new_target=next_serial,
                            description=f"cluster follower {follower.father_serial}->{next_serial}",
                        )
                        consumed_indexes.update(follower.selected_modification_indexes)
                    next_serial += 1

                for record in records:
                    if any(idx in consumed_indexes for idx in record.selected_modification_indexes):
                        continue
                    idx = record.selected_modification_indexes[0]
                    mod = modifications[idx]
                    if isinstance(mod, InsertBlock):
                        modifier.queue_create_and_redirect(
                            source_block_serial=int(mod.pred_serial),
                            final_target_serial=int(mod.succ_serial),
                            instructions_to_copy=list(mod.instructions),
                            expected_serial=next_serial,
                            description=f"standalone insert {mod.pred_serial}->{mod.succ_serial}",
                        )
                        next_serial += 1
                    elif isinstance(mod, RedirectGoto):
                        modifier.queue_goto_change(
                            block_serial=int(mod.from_serial),
                            new_target=int(mod.new_target),
                            description=f"standalone redirect {mod.from_serial}->{mod.new_target}",
                        )
                    elif isinstance(mod, ZeroStateWrite):
                        modifier.queue_zero_state_write(
                            int(mod.block_serial),
                            int(mod.insn_ea),
                            description=(
                                f"standalone zero state write "
                                f"{mod.block_serial}@{mod.insn_ea:#x}"
                            ),
                        )
                    else:
                        raise AssertionError(f"Unexpected modification in experiment: {mod}")

                changes = modifier.apply(
                    run_optimize_local=True,
                    run_deep_cleaning=False,
                )
                captured["cluster_payloads"] = tuple(cluster_payloads)
                captured["post_execute_flow_graph"] = lift_mba(snapshot.mba)
                strategy_name = (
                    planned.pipeline[0].strategy_name
                    if planned.pipeline
                    else "emulated_dispatcher"
                )
                return ExecutedPipeline(
                    pipeline=planned.pipeline,
                    results=[
                        StageResult(
                            strategy_name=strategy_name,
                            edits_applied=changes,
                            success=True,
                        )
                    ],
                    provenance=planned.provenance,
                    total_changes=changes,
                    executor=None,
                )

            def _wrapped_execute(snapshot, planned, **kwargs):
                if not clustered:
                    executed = original_execute(snapshot, planned, **kwargs)
                    captured["candidate_records"] = tuple(
                        asdict(record)
                        for record in extract_emulated_dispatcher_candidate_records(
                            snapshot.flow_graph
                        )
                    )
                    captured["post_execute_flow_graph"] = lift_mba(snapshot.mba)
                    return executed
                return _clustered_execute(snapshot, planned, **kwargs)

            with monkeypatch.context() as patch_ctx:
                patch_ctx.setattr(engine_mod, "execute_family_pipeline", _wrapped_execute)
                patch_ctx.setattr(
                    EmulatedDispatcherStrategyFamily,
                    "post_execute_cleanup",
                    _wrap_cleanup,
                )
                with d810_state() as state:
                    rendered = _decompile_with_project(
                        state,
                        func_ea,
                        "example_libobfuscated.json",
                        pseudocode_to_string,
                        engine_wrappers_only=True,
                    )
            assert "final_flow_graph" in captured
            return rendered, captured

        legacy_code, legacy_capture = _run_legacy()
        current_code, current_capture = _run_engine(clustered=False)
        experimental_code, experimental_capture = _run_engine(clustered=True)

        current_payloads = tuple(
            tuple(record["payload_signature"])
            for record in current_capture["candidate_records"]
            if record["cluster_candidate"]
        )
        experimental_payloads = tuple(experimental_capture.get("cluster_payloads", ()))

        legacy_shape = _summarize_cfg_shape(legacy_capture["final_flow_graph"])
        current_shape = _summarize_cfg_shape(
            current_capture["final_flow_graph"],
            payload_signatures=current_payloads,
        )
        experimental_shape = _summarize_cfg_shape(
            experimental_capture["final_flow_graph"],
            payload_signatures=experimental_payloads,
        )

        summary = {
            "legacy_ast": code_comparator.count_ast_statements(legacy_code),
            "current_ast": code_comparator.count_ast_statements(current_code),
            "experimental_ast": code_comparator.count_ast_statements(experimental_code),
            "legacy_shape": legacy_shape,
            "current_shape": current_shape,
            "experimental_shape": experimental_shape,
            "legacy_code": legacy_code,
            "current_code": current_code,
            "experimental_code": experimental_code,
        }
        print("APPROOV_MULTISTATE_CLUSTER_GROUPING_EXPERIMENT", summary)

        assert current_capture["candidate_records"]
        assert experimental_capture["candidate_records"]
        assert current_shape["payload_blocks"]
        assert experimental_shape["payload_blocks"]

    def test_approov_multistate_handler_subgraph_experiment(
        self,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
        monkeypatch,
    ) -> None:
        assert code_comparator is not None, (
            "libclang required for handler-subgraph experiment"
        )
        func_ea = get_func_ea("approov_multistate")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'approov_multistate' not found")

        def _run_legacy() -> tuple[str, dict[str, object]]:
            import d810.optimizers.microcode.flow.flattening.unflattener as legacy_mod

            captured: dict[str, object] = {}
            original_optimize = legacy_mod.Unflattener.optimize

            def _wrapped_optimize(rule, blk):
                result = original_optimize(rule, blk)
                if getattr(blk.mba, "entry_ea", None) == func_ea:
                    captured["final_flow_graph"] = lift_mba(blk.mba)
                return result

            with monkeypatch.context() as patch_ctx:
                patch_ctx.setattr(
                    legacy_mod.Unflattener,
                    "optimize",
                    _wrapped_optimize,
                )
                with d810_state() as state:
                    rendered = _decompile_with_project(
                        state,
                        func_ea,
                        "example_libobfuscated.json",
                        pseudocode_to_string,
                        engine_wrappers_only=False,
                    )
            assert "final_flow_graph" in captured
            return rendered, captured

        def _run_engine(*, experiment: bool) -> tuple[str, dict[str, object]]:
            import d810.optimizers.microcode.flow.flattening.unflattener_emulated_dispatcher_engine as engine_mod

            captured: dict[str, object] = {}
            original_execute = engine_mod.execute_family_pipeline
            original_cleanup = EmulatedDispatcherStrategyFamily.post_execute_cleanup

            def _wrap_cleanup(self, mba, *, snapshot, total_changes):
                cleaned = original_cleanup(
                    self,
                    mba,
                    snapshot=snapshot,
                    total_changes=total_changes,
                )
                captured["final_flow_graph"] = lift_mba(mba)
                return cleaned

            def _handler_execute(snapshot, planned, **kwargs):
                records = extract_emulated_dispatcher_candidate_records(
                    snapshot.flow_graph
                )
                captured["candidate_records"] = tuple(asdict(record) for record in records)
                captured["phase_role_map"] = _summarize_approov_multistate_phase_roles(
                    records
                )

                modifier = DeferredGraphModifier(snapshot.mba)

                modifier.queue_zero_state_write(
                    2,
                    _find_state_write_ea(
                        snapshot.mba,
                        block_serial=2,
                        expected_state=_APPROOV_MULTISTATE_PHASE_STATES["phase1_header"],
                    ),
                    description="phase loop entry 2 -> 9",
                )
                modifier.queue_goto_change(
                    2,
                    9,
                    description="phase loop entry 2 -> 9",
                )
                modifier.queue_zero_state_write(
                    6,
                    _find_state_write_ea(
                        snapshot.mba,
                        block_serial=6,
                        expected_state=_APPROOV_MULTISTATE_PHASE_STATES["phase1_header"],
                    ),
                    description="phase loop latch 6 -> 9",
                )
                modifier.queue_goto_change(
                    6,
                    9,
                    description="phase loop latch 6 -> 9",
                )
                modifier.queue_zero_state_write(
                    10,
                    _find_state_write_ea(
                        snapshot.mba,
                        block_serial=10,
                        expected_state=_APPROOV_MULTISTATE_PHASE_STATES["phase1_update"],
                    ),
                    description="phase loop body 10 -> 5",
                )
                modifier.queue_goto_change(
                    10,
                    5,
                    description="phase loop body 10 -> 5",
                )
                modifier.queue_conditional_target_change(
                    9,
                    12,
                    description="phase1 header taken -> phase2",
                )
                modifier.queue_conditional_target_change(
                    5,
                    12,
                    description="phase1 update taken -> phase2",
                )
                modifier.queue_conditional_target_change(
                    12,
                    12,
                    description="phase2 taken -> phase2 self loop",
                )

                changes = modifier.apply(
                    run_optimize_local=True,
                    run_deep_cleaning=False,
                )
                captured["post_execute_flow_graph"] = lift_mba(snapshot.mba)
                strategy_name = (
                    planned.pipeline[0].strategy_name
                    if planned.pipeline
                    else "emulated_dispatcher"
                )
                return ExecutedPipeline(
                    pipeline=planned.pipeline,
                    results=[
                        StageResult(
                            strategy_name=strategy_name,
                            edits_applied=changes,
                            success=True,
                        )
                    ],
                    provenance=planned.provenance,
                    total_changes=changes,
                    executor=None,
                )

            def _wrapped_execute(snapshot, planned, **kwargs):
                if not experiment:
                    executed = original_execute(snapshot, planned, **kwargs)
                    captured["candidate_records"] = tuple(
                        asdict(record)
                        for record in extract_emulated_dispatcher_candidate_records(
                            snapshot.flow_graph
                        )
                    )
                    return executed
                return _handler_execute(snapshot, planned, **kwargs)

            with monkeypatch.context() as patch_ctx:
                patch_ctx.setattr(engine_mod, "execute_family_pipeline", _wrapped_execute)
                patch_ctx.setattr(
                    EmulatedDispatcherStrategyFamily,
                    "post_execute_cleanup",
                    _wrap_cleanup,
                )
                with d810_state() as state:
                    rendered = _decompile_with_project(
                        state,
                        func_ea,
                        "example_libobfuscated.json",
                        pseudocode_to_string,
                        engine_wrappers_only=True,
                    )
            assert "final_flow_graph" in captured
            return rendered, captured

        legacy_code, legacy_capture = _run_legacy()
        current_code, current_capture = _run_engine(experiment=False)
        experimental_code, experimental_capture = _run_engine(experiment=True)

        legacy_shape = _summarize_cfg_shape(legacy_capture["final_flow_graph"])
        current_shape = _summarize_cfg_shape(current_capture["final_flow_graph"])
        experimental_shape = _summarize_cfg_shape(
            experimental_capture["final_flow_graph"]
        )

        summary = {
            "phase_role_map": experimental_capture["phase_role_map"],
            "legacy_ast": code_comparator.count_ast_statements(legacy_code),
            "current_ast": code_comparator.count_ast_statements(current_code),
            "experimental_ast": code_comparator.count_ast_statements(experimental_code),
            "legacy_shape": legacy_shape,
            "current_shape": current_shape,
            "experimental_shape": experimental_shape,
            "legacy_code": legacy_code,
            "current_code": current_code,
            "experimental_code": experimental_code,
        }
        print("APPROOV_MULTISTATE_HANDLER_SUBGRAPH_EXPERIMENT", summary)

        assert summary["phase_role_map"]["phase1_header"] == (
            (2, 9, ("InsertBlock",)),
            (6, 9, ("InsertBlock",)),
        )
        assert summary["phase_role_map"]["phase1_update"] == (
            (10, 5, ("InsertBlock",)),
        )

    def test_approov_multistate_single_record_subset_characterization(
        self,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
        monkeypatch,
    ) -> None:
        assert code_comparator is not None, (
            "libclang required for candidate subset characterization"
        )
        func_ea = get_func_ea("approov_multistate")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'approov_multistate' not found")

        def _run_engine_subset(
            selected_indexes: tuple[int, ...] | None = None,
        ) -> tuple[str, dict[str, object] | None]:
            with monkeypatch.context() as patch_ctx:
                import d810.optimizers.microcode.flow.flattening.unflattener_emulated_dispatcher_engine as engine_mod

                captured: dict[str, object] = {}
                original_execute = engine_mod.execute_family_pipeline

                def _wrapped_execute(snapshot, planned, **kwargs):
                    metadata = extract_emulated_dispatcher_metadata(snapshot.flow_graph)
                    records = extract_emulated_dispatcher_candidate_records(
                        snapshot.flow_graph
                    )
                    modifications = extract_emulated_dispatcher_modifications(
                        snapshot.flow_graph
                    )
                    if metadata is not None and len(modifications) > int(
                        captured.get("candidate_count", -1)
                    ):
                        captured["candidate_count"] = len(modifications)
                        captured["snapshot"] = asdict(metadata)
                        captured["candidate_records"] = tuple(
                            asdict(record) for record in records
                        )
                    return original_execute(snapshot, planned, **kwargs)

                patch_ctx.setattr(engine_mod, "execute_family_pipeline", _wrapped_execute)

                if selected_indexes is not None:
                    original_build_snapshot = EmulatedDispatcherStrategyFamily.build_snapshot

                    def _subset_build_snapshot(self, mba, detection):
                        snapshot = original_build_snapshot(self, mba, detection)
                        metadata = extract_emulated_dispatcher_metadata(
                            snapshot.flow_graph
                        )
                        if metadata is None or metadata.candidate_count == 0:
                            return snapshot
                        return _filter_emulated_dispatcher_snapshot(
                            snapshot,
                            selected_indexes,
                        )

                    patch_ctx.setattr(
                        EmulatedDispatcherStrategyFamily,
                        "build_snapshot",
                        _subset_build_snapshot,
                    )

                with d810_state() as state:
                    state.stop_d810()
                    project_name = "example_libobfuscated.json"
                    project_index = _resolve_test_project_index(state, project_name)
                    state.load_project(project_index)
                    with state.for_project(project_name) as ctx:
                        _apply_engine_wrapper_profile(ctx)
                        dispatcher_rule = next(
                            (
                                rule
                                for rule in ctx.active_blk_rules
                                if type(rule).__name__ == "EmulatedDispatcherUnflattener"
                            ),
                            None,
                        )
                        assert dispatcher_rule is not None
                        state.stats.reset()
                        state.start_d810()
                        previous_override = _force_rule_scope_to_current_profile(
                            state, ctx, func_ea
                        )
                        try:
                            cfunc = idaapi.decompile(
                                func_ea, flags=idaapi.DECOMP_NO_CACHE
                            )
                            assert cfunc is not None
                            rendered = pseudocode_to_string(cfunc.get_pseudocode())
                            observation = dispatcher_rule.get_last_observation()
                        finally:
                            _restore_forced_rule_scope(state, func_ea, previous_override)
                    state.stop_d810()
            return rendered, (
                captured.get("snapshot")
                if "snapshot" in captured
                else observation["snapshot"]
            )

        with d810_state() as state:
            legacy_code = _decompile_with_project(
                state,
                func_ea,
                "example_libobfuscated.json",
                pseudocode_to_string,
                engine_wrappers_only=False,
            )

        full_engine_code, full_snapshot = _run_engine_subset()
        assert full_snapshot is not None
        candidate_records = full_snapshot["candidate_records"]
        selected_records = tuple(
            record
            for record in candidate_records
            if record["selected_modification_indexes"]
        )
        assert selected_records

        subset_results: list[tuple[tuple[int, ...], bool, dict[str, int], tuple[str, ...]]] = []
        for record in selected_records:
            subset_indexes = tuple(record["selected_modification_indexes"])
            subset_code, subset_snapshot = _run_engine_subset(subset_indexes)
            subset_results.append(
                (
                    subset_indexes,
                    code_comparator.are_equivalent(subset_code, legacy_code),
                    code_comparator.count_ast_statements(subset_code),
                    tuple(record["selected_modification_kinds"]),
                )
            )
            assert subset_snapshot is not None
            assert subset_snapshot["candidate_count"] == len(subset_indexes)

        print(
            "APPROOV_MULTISTATE_SINGLE_RECORD_SUBSETS",
            {
                "full_engine_ast": code_comparator.count_ast_statements(full_engine_code),
                "legacy_ast": code_comparator.count_ast_statements(legacy_code),
                "subsets": subset_results,
            },
        )

        assert len(subset_results) == len(selected_records)

    def test_approov_multistate_grouped_subset_characterization(
        self,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
        monkeypatch,
    ) -> None:
        assert code_comparator is not None, (
            "libclang required for candidate subset characterization"
        )
        func_ea = get_func_ea("approov_multistate")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'approov_multistate' not found")

        def _run_engine_subset(
            selected_indexes: tuple[int, ...] | None = None,
        ) -> tuple[str, dict[str, object] | None]:
            with monkeypatch.context() as patch_ctx:
                import d810.optimizers.microcode.flow.flattening.unflattener_emulated_dispatcher_engine as engine_mod

                captured: dict[str, object] = {}
                original_execute = engine_mod.execute_family_pipeline

                def _wrapped_execute(snapshot, planned, **kwargs):
                    metadata = extract_emulated_dispatcher_metadata(snapshot.flow_graph)
                    records = extract_emulated_dispatcher_candidate_records(
                        snapshot.flow_graph
                    )
                    modifications = extract_emulated_dispatcher_modifications(
                        snapshot.flow_graph
                    )
                    if metadata is not None and len(modifications) > int(
                        captured.get("candidate_count", -1)
                    ):
                        captured["candidate_count"] = len(modifications)
                        captured["snapshot"] = asdict(metadata)
                        captured["candidate_records"] = tuple(
                            asdict(record) for record in records
                        )
                    return original_execute(snapshot, planned, **kwargs)

                patch_ctx.setattr(engine_mod, "execute_family_pipeline", _wrapped_execute)

                if selected_indexes is not None:
                    original_build_snapshot = EmulatedDispatcherStrategyFamily.build_snapshot

                    def _subset_build_snapshot(self, mba, detection):
                        snapshot = original_build_snapshot(self, mba, detection)
                        metadata = extract_emulated_dispatcher_metadata(
                            snapshot.flow_graph
                        )
                        if metadata is None or metadata.candidate_count == 0:
                            return snapshot
                        return _filter_emulated_dispatcher_snapshot(
                            snapshot,
                            selected_indexes,
                        )

                    patch_ctx.setattr(
                        EmulatedDispatcherStrategyFamily,
                        "build_snapshot",
                        _subset_build_snapshot,
                    )

                with d810_state() as state:
                    state.stop_d810()
                    project_name = "example_libobfuscated.json"
                    project_index = _resolve_test_project_index(state, project_name)
                    state.load_project(project_index)
                    with state.for_project(project_name) as ctx:
                        _apply_engine_wrapper_profile(ctx)
                        dispatcher_rule = next(
                            (
                                rule
                                for rule in ctx.active_blk_rules
                                if type(rule).__name__ == "EmulatedDispatcherUnflattener"
                            ),
                            None,
                        )
                        assert dispatcher_rule is not None
                        state.stats.reset()
                        state.start_d810()
                        previous_override = _force_rule_scope_to_current_profile(
                            state, ctx, func_ea
                        )
                        try:
                            cfunc = idaapi.decompile(
                                func_ea, flags=idaapi.DECOMP_NO_CACHE
                            )
                            assert cfunc is not None
                            rendered = pseudocode_to_string(cfunc.get_pseudocode())
                            observation = dispatcher_rule.get_last_observation()
                        finally:
                            _restore_forced_rule_scope(state, func_ea, previous_override)
                    state.stop_d810()
            return rendered, (
                captured.get("snapshot")
                if "snapshot" in captured
                else observation["snapshot"]
            )

        with d810_state() as state:
            legacy_code = _decompile_with_project(
                state,
                func_ea,
                "example_libobfuscated.json",
                pseudocode_to_string,
                engine_wrappers_only=False,
            )

        full_engine_code, full_snapshot = _run_engine_subset()
        assert full_snapshot is not None
        candidate_records = full_snapshot["candidate_records"]
        selected_records = tuple(
            record
            for record in candidate_records
            if record["selected_modification_indexes"]
        )
        assert len(selected_records) == 6

        groups = (
            ("first_half", (0, 1, 2)),
            ("second_half", (3, 4, 5)),
            ("insert_only", (0, 1, 2, 3, 4)),
            ("redirect_only", (5,)),
        )
        group_results: list[
            tuple[str, tuple[int, ...], bool, dict[str, int], tuple[str, ...]]
        ] = []
        for label, indexes in groups:
            subset_code, subset_snapshot = _run_engine_subset(indexes)
            group_results.append(
                (
                    label,
                    indexes,
                    code_comparator.are_equivalent(subset_code, legacy_code),
                    code_comparator.count_ast_statements(subset_code),
                    tuple(
                        candidate_records[idx]["selected_modification_kinds"][0]
                        for idx in indexes
                    ),
                )
            )
            assert subset_snapshot is not None

        print(
            "APPROOV_MULTISTATE_GROUPED_SUBSETS",
            {
                "full_engine_ast": code_comparator.count_ast_statements(full_engine_code),
                "legacy_ast": code_comparator.count_ast_statements(legacy_code),
                "groups": group_results,
            },
        )

        assert len(group_results) == len(groups)

    def test_approov_multistate_characterization_without_fake_jump_skip(
        self,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
        monkeypatch,
    ) -> None:
        assert code_comparator is not None, (
            "libclang required for candidate subset characterization"
        )
        func_ea = get_func_ea("approov_multistate")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'approov_multistate' not found")

        from d810.cfg.flowgraph import FlowGraph
        from d810.optimizers.microcode.flow.flattening.hodur.family import (
            HodurStrategyFamily,
        )
        from d810.optimizers.microcode.flow.flattening.strategies.fake_jump import (
            FAKE_JUMP_FIXES_METADATA_KEY,
            collect_live_fake_jump_fixes,
            serialize_fake_jump_fixes,
        )
        from d810.recon.flow.dispatcher_detection import DispatcherCache

        original_attach_fake_jump = HodurStrategyFamily.attach_fake_jump_fixes_to_flow_graph

        def _attach_fake_jump_without_cleanup_skip(self, mba, flow_graph):
            updated = original_attach_fake_jump(self, mba, flow_graph)
            if FAKE_JUMP_FIXES_METADATA_KEY in dict(updated.metadata):
                return updated
            try:
                fixes = collect_live_fake_jump_fixes(
                    mba,
                    logger=self._logger,
                    max_nb_block=100,
                    max_path=100,
                    allowed_maturities=(ida_hexrays.MMAT_GLBOPT1,),
                )
            except Exception:
                return updated
            if not fixes:
                return updated
            try:
                dispatcher_cache = DispatcherCache.get_or_create(mba)
                dispatcher_analysis = dispatcher_cache.analyze()
            except Exception:
                dispatcher_cache = None
                dispatcher_analysis = None
            if (
                dispatcher_cache is not None
                and dispatcher_analysis is not None
                and dispatcher_analysis.is_conditional_chain
            ):
                fixes = tuple(
                    fix
                    for fix in fixes
                    if not dispatcher_cache.is_dispatcher(fix.fake_block)
                )
            if not fixes:
                return updated
            metadata = dict(updated.metadata)
            metadata[FAKE_JUMP_FIXES_METADATA_KEY] = serialize_fake_jump_fixes(fixes)
            return FlowGraph(
                blocks=updated.blocks,
                entry_serial=updated.entry_serial,
                func_ea=updated.func_ea,
                metadata=metadata,
            )

        monkeypatch.setattr(
            HodurStrategyFamily,
            "attach_fake_jump_fixes_to_flow_graph",
            _attach_fake_jump_without_cleanup_skip,
        )

        with d810_state() as state:
            legacy_code = _decompile_with_project(
                state,
                func_ea,
                "example_libobfuscated.json",
                pseudocode_to_string,
                engine_wrappers_only=False,
            )

        with d810_state() as state:
            engine_code = _decompile_with_project(
                state,
                func_ea,
                "example_libobfuscated.json",
                pseudocode_to_string,
                engine_wrappers_only=True,
            )

        print(
            "APPROOV_MULTISTATE_WITHOUT_FAKEJUMP_SKIP",
            {
                "legacy_ast": code_comparator.count_ast_statements(legacy_code),
                "engine_ast": code_comparator.count_ast_statements(engine_code),
                "equivalent": code_comparator.are_equivalent(engine_code, legacy_code),
            },
        )

    def test_approov_multistate_characterization_with_fixpred_restored(
        self,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
    ) -> None:
        assert code_comparator is not None, (
            "libclang required for candidate subset characterization"
        )
        func_ea = get_func_ea("approov_multistate")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'approov_multistate' not found")

        with d810_state() as state:
            legacy_code = _decompile_with_project(
                state,
                func_ea,
                "example_libobfuscated.json",
                pseudocode_to_string,
                engine_wrappers_only=False,
            )

        with d810_state() as state:
            state.stop_d810()
            project_name = "example_libobfuscated.json"
            project_index = _resolve_test_project_index(state, project_name)
            state.load_project(project_index)
            with state.for_project(project_name) as ctx:
                _apply_engine_wrapper_profile(ctx)
                ctx.add_rule("FixPredecessorOfConditionalJumpBlock")
                state.stats.reset()
                state.start_d810()
                previous_override = _force_rule_scope_to_current_profile(
                    state, ctx, func_ea
                )
                try:
                    cfunc = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
                    assert cfunc is not None
                    engine_code = pseudocode_to_string(cfunc.get_pseudocode())
                finally:
                    _restore_forced_rule_scope(state, func_ea, previous_override)
            state.stop_d810()

        print(
            "APPROOV_MULTISTATE_WITH_FIXPRED_RESTORED",
            {
                "legacy_ast": code_comparator.count_ast_statements(legacy_code),
                "engine_ast": code_comparator.count_ast_statements(engine_code),
                "equivalent": code_comparator.are_equivalent(engine_code, legacy_code),
            },
        )
