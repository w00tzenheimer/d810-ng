from __future__ import annotations

from dataclasses import asdict, replace
import os
import platform
from types import SimpleNamespace

import idaapi
import ida_hexrays
import pytest

import d810.hexrays.observability as hexrays_observability
import d810.optimizers.microcode.flow.dispatcher.switch_case_transitions as switch_case_transition_adapter
import d810.recon.flow.switch_case_transition_analysis as switch_case_transition_analysis
from d810.cfg.flowgraph import BlockSnapshot, FlowGraph, InsnSnapshot, MopSnapshot
from d810.cfg.graph_modification import (
    CreateConditionalRedirect,
    EdgeRedirectViaPredSplit,
    InsertBlock,
    PhaseCycleLowering,
    PromoteOperandToScalar,
    ReorderBlocks,
    RedirectBranch,
    RedirectGoto,
    ZeroStateWrite,
)
from d810.cfg.plan import PatchEdgeSplitTrampoline, PatchInsertBlock, compile_patch_plan
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
    select_loop_recovery_edges,
    tigress_indirect_dispatcher_profile,
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
from d810.recon.flow.dispatcher_kind import DispatcherType
from d810.recon.flow.dispatcher_discovery_facts import (
    DISPATCHER_INITIAL_STATE_FACT_TYPE,
    STATE_DISPATCHER_TOPOLOGY_FACT_TYPE,
    STATE_VARIABLE_IDENTITY_FACT_TYPE,
)
from d810.recon.flow.branch_ownership import (
    BranchOwnershipProof,
    BranchOwnershipProofKind,
)
from d810.recon.flow.dispatcher_map import StateDispatcherMap, StateDispatcherRow
from d810.recon.flow.reconstruction_candidate_builder import ReconstructionCandidate
from d810.recon.flow.linearized_state_dag import SemanticEdgeKind
from d810.recon.flow.predecessor_dispatcher_target import (
    PredecessorDispatcherTargetFact,
)
from d810.recon.flow.state_dag_index import StateDagIndex
from d810.testing.runner import _resolve_test_project_index, get_func_ea


TEMP_ENGINE_WRAPPER_NOTES = "temporary engine-wrapper test profile"


def _get_default_binary() -> str:
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    return (
        "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"
    )


def _apply_engine_wrapper_profile(ctx) -> None:
    ctx.add_rule("HodurUnflattener")
    ctx.add_rule("EmulatedDispatcherUnflattener")


def _force_rule_scope_to_current_profile(state, ctx, func_ea: int):
    manager = state.manager
    previous = manager.get_function_rule_override(func_ea)
    if (
        previous is not None
        and getattr(previous, "notes", "") == TEMP_ENGINE_WRAPPER_NOTES
        and not getattr(previous, "tags", set())
    ):
        manager.clear_function_rule_override(func_ea)
        previous = None
    enabled_rules = {
        str(rule.name)
        for rule in list(ctx.active_ins_rules) + list(ctx.active_blk_rules)
    }
    manager.set_function_rule_override(
        function_addr=func_ea,
        enabled_rules=enabled_rules,
        disabled_rules=set(),
        notes=TEMP_ENGINE_WRAPPER_NOTES,
    )
    return previous


def _restore_forced_rule_scope(state, func_ea: int, previous) -> None:
    manager = state.manager
    if previous is None:
        manager.clear_function_rule_override(func_ea)
        return
    if (
        getattr(previous, "notes", "") == TEMP_ENGINE_WRAPPER_NOTES
        and not getattr(previous, "tags", set())
    ):
        manager.clear_function_rule_override(func_ea)
        return
    if (
        not previous.enabled_rules
        and not previous.disabled_rules
        and not getattr(previous, "tags", set())
        and not getattr(previous, "notes", "")
    ):
        manager.clear_function_rule_override(func_ea)
        return
    manager.set_function_rule_override(
        function_addr=func_ea,
        enabled_rules=set(previous.enabled_rules),
        disabled_rules=set(previous.disabled_rules),
        notes=getattr(previous, "notes", ""),
    )


def _decompile_without_d810(state, func_ea: int, pseudocode_to_string) -> str:
    state.stop_d810()
    cfunc = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
    assert cfunc is not None, f"Decompilation failed for function at 0x{func_ea:x}"
    return pseudocode_to_string(cfunc.get_pseudocode())


def _decompile_with_project(
    state,
    func_ea: int,
    project_name: str,
    pseudocode_to_string,
    *,
    engine_wrappers_only: bool,
) -> str:
    state.stop_d810()
    project_index = _resolve_test_project_index(state, project_name)
    state.load_project(project_index)
    with state.for_project(project_name) as ctx:
        if engine_wrappers_only:
            _apply_engine_wrapper_profile(ctx)
        state.stats.reset()
        state.start_d810()
        previous_override = _force_rule_scope_to_current_profile(state, ctx, func_ea)
        try:
            cfunc = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert cfunc is not None, (
                f"Decompilation with d810 failed for function at 0x{func_ea:x}"
            )
            rendered = pseudocode_to_string(cfunc.get_pseudocode())
        finally:
            _restore_forced_rule_scope(state, func_ea, previous_override)
    state.stop_d810()
    return rendered


class _Collector:
    def __init__(self):
        self._items = ()

    def visit_minsn(self):
        return 0

    def get_dispatcher_list(self):
        return list(self._items)


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


def _conditional_chain_state_dispatcher_map(
    *,
    dispatcher_entry: int,
    state: int,
    target: int,
) -> StateDispatcherMap:
    return StateDispatcherMap(
        rows=(
            StateDispatcherRow(
                state_const=state,
                target_block=target,
                dispatcher_block=dispatcher_entry,
                compare_block=dispatcher_entry,
                branch_kind="jnz_fallthrough",
                source=DispatcherType.CONDITIONAL_CHAIN,
            ),
        ),
        dispatcher_entry_block=dispatcher_entry,
        dispatcher_blocks=frozenset({dispatcher_entry}),
        state_var_stkoff=0x3C,
        state_var_lvar_idx=None,
        source=DispatcherType.CONDITIONAL_CHAIN,
    )


def _switch_return_fact(source_state: int, exit_block: int):
    return switch_case_transition_analysis.SwitchCaseTransitionFact(
        fact_id=f"tigress_switch:case={source_state}:return",
        transition_kind=switch_case_transition_analysis.SwitchCaseTransitionKind.RETURN_FRONTIER,
        source_state=source_state,
        case_entry_block=exit_block,
        return_value=0,
        proof=BranchOwnershipProof(
            proof_id=f"tigress_switch:case={source_state}:return",
            proof_kind=BranchOwnershipProofKind.TERMINAL_RETURN_FRONTIER,
            trusted=True,
            reason="case_body_returns",
            source_state=source_state,
            source_block=exit_block,
            predicate_block=exit_block,
            dispatcher_entry_block=2,
            oracle_kind="switch_case_return_frontier",
        ),
        reason="case_body_returns",
        exit_block=exit_block,
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
        source_block: int | None = None,
        branch_arm: int | None = None,
        branch_ownership_proof: BranchOwnershipProof | None = None,
    ):
        return SimpleNamespace(
            source_key=_key(source),
            target_key=(_key(target) if target is not None else None),
            kind=kind,
            target_entry_anchor=target_entry,
            source_anchor=(
                SimpleNamespace(block_serial=source_block, branch_arm=branch_arm)
                if source_block is not None
                else None
            ),
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


def test_ollvm_terminal_payload_backedge_uses_pred_split_for_shared_payload() -> None:
    def _key(state: int):
        return SimpleNamespace(state_const=state)

    def _edge(
        source: int,
        target: int | None,
        kind: SemanticEdgeKind,
        *,
        target_entry: int,
        source_block: int | None = None,
        branch_arm: int | None = None,
        branch_ownership_proof: BranchOwnershipProof | None = None,
    ):
        return SimpleNamespace(
            source_key=_key(source),
            target_key=(_key(target) if target is not None else None),
            kind=kind,
            target_entry_anchor=target_entry,
            source_anchor=(
                SimpleNamespace(block_serial=source_block, branch_arm=branch_arm)
                if source_block is not None
                else None
            ),
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
        source_block=98,
        branch_arm=1,
        branch_ownership_proof=BranchOwnershipProof(
            proof_id="proof-selector-to-payload-split",
            proof_kind=BranchOwnershipProofKind.OBFUSCATION_RESIDUE_ARM,
            trusted=True,
            reason="opaque_selected_terminal_selector_backedge_residue",
            source_block=98,
            branch_arm=1,
            source_state=selector_state,
            target_state=payload_state,
            target_entry=136,
            oracle_kind="fixture",
            evidence={"requires_cfg_split": True},
        ),
    )
    selector_to_return = _edge(
        selector_state,
        return_state,
        SemanticEdgeKind.CONDITIONAL_TRANSITION,
        target_entry=204,
        source_block=98,
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
            98: BlockSnapshot(
                serial=98,
                block_type=ida_hexrays.BLT_2WAY,
                succs=(99, 136),
                preds=(96,),
                flags=0,
                start_ea=0x401098,
                insn_snapshots=(),
            ),
            136: BlockSnapshot(
                serial=136,
                block_type=ida_hexrays.BLT_1WAY,
                succs=(96,),
                preds=(98, 146),
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
            146: BlockSnapshot(
                serial=146,
                block_type=ida_hexrays.BLT_2WAY,
                succs=(147, 136),
                preds=(145,),
                flags=0,
                start_ea=0x401146,
                insn_snapshots=(),
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
    assert rewritten[0].target_entry == 204

    replacement = emulated_family_module._terminal_payload_edge_split_replacement(
        candidate=rewritten[0],
        modification=RedirectGoto(from_serial=136, old_target=96, new_target=204),
        dag=dag,
        flow_graph=flow_graph,
        branch_ownership_proofs=(),
    )
    assert replacement == (
        EdgeRedirectViaPredSplit(
            src_block=136,
            old_target=96,
            new_target=204,
            via_pred=98,
        ),
    )


def test_ollvm_terminal_payload_materialization_candidate_preserves_store() -> None:
    def _key(state: int):
        return SimpleNamespace(state_const=state)

    def _edge(
        source: int,
        target: int | None,
        kind: SemanticEdgeKind,
        *,
        target_entry: int,
        source_block: int | None = None,
        branch_arm: int | None = None,
    ):
        return SimpleNamespace(
            source_key=_key(source),
            target_key=(_key(target) if target is not None else None),
            kind=kind,
            target_entry_anchor=target_entry,
            source_anchor=(
                SimpleNamespace(block_serial=source_block, branch_arm=branch_arm)
                if source_block is not None
                else None
            ),
            ordered_path=(target_entry,),
        )

    payload_state = 0x2AC056AD
    selector_state = 0x049FD3A3
    external_state = 0x3CFC5AAB
    return_state = 0xBFF7ACB5
    store = InsnSnapshot(opcode=ida_hexrays.m_stx, ea=0x401136, operands=())
    state_write = InsnSnapshot(opcode=ida_hexrays.m_mov, ea=0x40113A, operands=())
    dag = SimpleNamespace(
        nodes=(),
        edges=(
            _edge(
                payload_state,
                selector_state,
                SemanticEdgeKind.TRANSITION,
                target_entry=96,
            ),
            _edge(
                selector_state,
                payload_state,
                SemanticEdgeKind.CONDITIONAL_TRANSITION,
                target_entry=136,
                source_block=98,
                branch_arm=1,
            ),
            _edge(
                selector_state,
                return_state,
                SemanticEdgeKind.CONDITIONAL_TRANSITION,
                target_entry=204,
                source_block=98,
                branch_arm=0,
            ),
            _edge(
                external_state,
                payload_state,
                SemanticEdgeKind.CONDITIONAL_TRANSITION,
                target_entry=136,
                source_block=146,
                branch_arm=1,
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
            98: BlockSnapshot(
                serial=98,
                block_type=ida_hexrays.BLT_2WAY,
                succs=(204, 100),
                preds=(96,),
                flags=0,
                start_ea=0x401098,
                insn_snapshots=(),
            ),
            100: BlockSnapshot(
                serial=100,
                block_type=ida_hexrays.BLT_1WAY,
                succs=(136,),
                preds=(98,),
                flags=0,
                start_ea=0x401100,
                insn_snapshots=(),
            ),
            136: BlockSnapshot(
                serial=136,
                block_type=ida_hexrays.BLT_1WAY,
                succs=(96,),
                preds=(100, 148),
                flags=0,
                start_ea=0x401136,
                insn_snapshots=(store, state_write),
            ),
            146: BlockSnapshot(
                serial=146,
                block_type=ida_hexrays.BLT_2WAY,
                succs=(147, 148),
                preds=(145,),
                flags=0,
                start_ea=0x401146,
                insn_snapshots=(),
            ),
            148: BlockSnapshot(
                serial=148,
                block_type=ida_hexrays.BLT_1WAY,
                succs=(136,),
                preds=(146,),
                flags=0,
                start_ea=0x401148,
                insn_snapshots=(),
            ),
            204: BlockSnapshot(
                serial=204,
                block_type=ida_hexrays.BLT_0WAY,
                succs=(),
                preds=(98,),
                flags=0,
                start_ea=0x401204,
                insn_snapshots=(),
            ),
        },
        entry_serial=96,
        func_ea=0x401000,
    )
    blocked = BranchOwnershipProof(
        proof_id="selector-gap-proof",
        proof_kind=BranchOwnershipProofKind.UNRESOLVED,
        trusted=False,
        reason="terminal_selector_backedge_requires_side_effect_materialization",
        source_block=98,
        branch_arm=1,
        source_state=selector_state,
        target_state=payload_state,
        target_entry=136,
        oracle_kind="branch_ownership_terminal_selector_backedge",
        evidence={
            "requires_side_effect_materialization": True,
            "opaque_selected_proof_id": "selector-residue-proof",
            "external_incoming_materialization_veto_proof_ids": (
                "external-veto-proof",
            ),
            "external_incoming_side_effect_guard_reasons": (
                "discarded_arm_contains_payload_store",
            ),
        },
    )
    veto = BranchOwnershipProof(
        proof_id="external-veto-proof",
        proof_kind=BranchOwnershipProofKind.UNRESOLVED,
        trusted=False,
        reason="z3_jumpfixer_discarded_arm_side_effect_guard",
        source_block=146,
        branch_arm=1,
        source_state=external_state,
        target_state=payload_state,
        target_entry=136,
        oracle_kind="z3_branch_ownership",
        evidence={
            "side_effect_guard_reason": "discarded_arm_contains_payload_store",
        },
    )

    candidates = (
        emulated_family_module
        ._collect_terminal_selector_payload_materialization_candidates(
            dag=dag,
            flow_graph=flow_graph,
            branch_ownership_proofs=(blocked, veto),
        )
    )

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.selector_source_block == 98
    assert candidate.selector_branch_arm == 1
    assert candidate.selector_old_target == 100
    assert candidate.selector_state == selector_state
    assert candidate.payload_state == payload_state
    assert candidate.payload_block == 136
    assert candidate.payload_backedge_target == 96
    assert candidate.semantic_continuation == 204
    assert candidate.side_effect_corridor_blocks == (136,)
    assert candidate.side_effect_instructions == (store,)
    assert candidate.side_effect_instructions[0].ea == 0x401136
    assert candidate.external_incoming_edges[0].old_target == 148
    assert candidate.materialization_veto_proof_ids == ("external-veto-proof",)
    assert candidate.side_effect_guard_reasons == (
        "discarded_arm_contains_payload_store",
    )
    assert candidate.owned_redirect_edges == ((98, 100), (146, 148))

    modifications = (
        emulated_family_module
        ._terminal_selector_payload_materialization_modifications(candidate)
    )
    compiled_modifications, blocker = (
        emulated_family_module
        ._compile_terminal_selector_payload_materialization_modifications(
            candidate,
            flow_graph,
        )
    )
    assert blocker is None
    assert compiled_modifications == modifications
    assert modifications == (
        InsertBlock(
            pred_serial=98,
            succ_serial=204,
            instructions=(store,),
            old_target_serial=100,
        ),
        InsertBlock(
            pred_serial=146,
            succ_serial=204,
            instructions=(store,),
            old_target_serial=148,
        ),
    )
    patch_plan = compile_patch_plan(modifications, flow_graph)
    rewritten_continuation = patch_plan.relocation_map.rewrite_serial(204)
    assert isinstance(patch_plan.steps[0], PatchInsertBlock)
    assert patch_plan.steps[0].pred_serial == 98
    assert patch_plan.steps[0].succ_serial == rewritten_continuation
    assert patch_plan.steps[0].old_target_serial == 100
    assert patch_plan.steps[0].instructions == (store,)
    assert isinstance(patch_plan.steps[1], PatchInsertBlock)
    assert patch_plan.steps[1].pred_serial == 146
    assert patch_plan.steps[1].succ_serial == rewritten_continuation
    assert patch_plan.steps[1].old_target_serial == 148
    assert patch_plan.steps[1].instructions == (store,)


def test_ollvm_terminal_payload_materialization_rejects_fallthrough_selector_arm() -> None:
    store = InsnSnapshot(opcode=ida_hexrays.m_stx, ea=0x401136, operands=())
    candidate = emulated_family_module.TerminalSelectorPayloadMaterializationCandidate(
        selector_source_block=98,
        selector_branch_arm=0,
        selector_old_target=204,
        selector_state=0x049FD3A3,
        payload_state=0x2AC056AD,
        payload_block=136,
        payload_backedge_target=96,
        semantic_continuation=204,
        side_effect_corridor_blocks=(136,),
        side_effect_instructions=(store,),
        selector_blocked_proof_id="selector-gap-proof",
        selector_residue_proof_id="selector-residue-proof",
        external_incoming_edges=(
            emulated_family_module.TerminalSelectorPayloadIncomingEdge(
                source_block=146,
                branch_arm=1,
                old_target=148,
                source_state=0x3CFC5AAB,
                target_state=0x2AC056AD,
                target_entry=136,
                veto_proof_id="external-veto-proof",
                side_effect_guard_reason="discarded_arm_contains_payload_store",
            ),
        ),
    )
    flow_graph = FlowGraph(
        blocks={
            98: BlockSnapshot(
                serial=98,
                block_type=ida_hexrays.BLT_2WAY,
                succs=(204, 136),
                preds=(96,),
                flags=0,
                start_ea=0x401098,
                insn_snapshots=(),
            ),
            136: BlockSnapshot(
                serial=136,
                block_type=ida_hexrays.BLT_1WAY,
                succs=(96,),
                preds=(98, 146),
                flags=0,
                start_ea=0x401136,
                insn_snapshots=(store,),
            ),
            146: BlockSnapshot(
                serial=146,
                block_type=ida_hexrays.BLT_2WAY,
                succs=(147, 136),
                preds=(145,),
                flags=0,
                start_ea=0x401146,
                insn_snapshots=(),
            ),
            204: BlockSnapshot(
                serial=204,
                block_type=ida_hexrays.BLT_0WAY,
                succs=(),
                preds=(98,),
                flags=0,
                start_ea=0x401204,
                insn_snapshots=(),
            ),
        },
        entry_serial=98,
        func_ea=0x401000,
    )

    modifications, blocker = (
        emulated_family_module
        ._compile_terminal_selector_payload_materialization_modifications(
            candidate,
            flow_graph,
        )
    )

    assert modifications == ()
    assert blocker == "terminal_payload_materialization_selector_arm_not_supported"


def test_ollvm_terminal_payload_materialization_rejects_missing_payload_snapshot() -> None:
    payload_state = 0x2AC056AD
    selector_state = 0x049FD3A3
    external_state = 0x3CFC5AAB
    return_state = 0xBFF7ACB5

    def _key(state: int):
        return SimpleNamespace(state_const=state)

    def _edge(
        source: int,
        target: int | None,
        *,
        target_entry: int,
        source_block: int | None = None,
        branch_arm: int | None = None,
        kind: SemanticEdgeKind = SemanticEdgeKind.CONDITIONAL_TRANSITION,
    ):
        return SimpleNamespace(
            source_key=_key(source),
            target_key=(_key(target) if target is not None else None),
            kind=kind,
            target_entry_anchor=target_entry,
            source_anchor=(
                SimpleNamespace(block_serial=source_block, branch_arm=branch_arm)
                if source_block is not None
                else None
            ),
            ordered_path=(target_entry,),
        )

    dag = SimpleNamespace(
        edges=(
            _edge(
                payload_state,
                selector_state,
                target_entry=96,
                kind=SemanticEdgeKind.TRANSITION,
            ),
            _edge(
                selector_state,
                payload_state,
                target_entry=136,
                source_block=98,
                branch_arm=1,
            ),
            _edge(
                selector_state,
                return_state,
                target_entry=204,
                source_block=98,
                branch_arm=0,
            ),
            _edge(
                external_state,
                payload_state,
                target_entry=136,
                source_block=146,
                branch_arm=1,
            ),
            _edge(
                return_state,
                None,
                target_entry=204,
                kind=SemanticEdgeKind.CONDITIONAL_RETURN,
            ),
        ),
    )
    flow_graph = FlowGraph(
        blocks={
            136: BlockSnapshot(
                serial=136,
                block_type=ida_hexrays.BLT_1WAY,
                succs=(96,),
                preds=(98, 146),
                flags=0,
                start_ea=0x401136,
                insn_snapshots=(
                    InsnSnapshot(opcode=ida_hexrays.m_mov, ea=0x40113A, operands=()),
                ),
            )
        },
        entry_serial=136,
        func_ea=0x401000,
    )
    blocked = BranchOwnershipProof(
        proof_id="selector-gap-proof",
        proof_kind=BranchOwnershipProofKind.UNRESOLVED,
        trusted=False,
        reason="terminal_selector_backedge_requires_side_effect_materialization",
        source_block=98,
        branch_arm=1,
        source_state=selector_state,
        target_state=payload_state,
        target_entry=136,
        evidence={"requires_side_effect_materialization": True},
    )
    veto = BranchOwnershipProof(
        proof_id="external-veto-proof",
        proof_kind=BranchOwnershipProofKind.UNRESOLVED,
        trusted=False,
        reason="z3_jumpfixer_discarded_arm_side_effect_guard",
        source_block=146,
        branch_arm=1,
        source_state=external_state,
        target_state=payload_state,
        target_entry=136,
        evidence={
            "side_effect_guard_reason": "discarded_arm_contains_payload_store",
        },
    )

    candidates = (
        emulated_family_module
        ._collect_terminal_selector_payload_materialization_candidates(
            dag=dag,
            flow_graph=flow_graph,
            branch_ownership_proofs=(blocked, veto),
        )
    )

    assert candidates == ()


def test_ollvm_terminal_payload_materialization_compile_failure_blocks(
    monkeypatch,
) -> None:
    candidate = (
        emulated_family_module.TerminalSelectorPayloadMaterializationCandidate(
            selector_source_block=98,
            selector_branch_arm=1,
            selector_old_target=100,
            selector_state=0x049FD3A3,
            payload_state=0x2AC056AD,
            payload_block=136,
            payload_backedge_target=96,
            semantic_continuation=204,
            side_effect_corridor_blocks=(136,),
            side_effect_instructions=(
                InsnSnapshot(opcode=ida_hexrays.m_stx, ea=0x401136, operands=()),
            ),
            selector_blocked_proof_id="selector-gap-proof",
            selector_residue_proof_id="selector-residue-proof",
            external_incoming_edges=(
                emulated_family_module.TerminalSelectorPayloadIncomingEdge(
                    source_block=146,
                    branch_arm=1,
                    old_target=148,
                    source_state=0x3CFC5AAB,
                    target_state=0x2AC056AD,
                    target_entry=136,
                    veto_proof_id="external-veto-proof",
                    side_effect_guard_reason="discarded_arm_contains_payload_store",
                ),
            ),
        )
    )
    flow_graph = FlowGraph(blocks={}, entry_serial=0, func_ea=0x401000)

    def _raise_compile_failure(*_args, **_kwargs):
        raise ValueError("compile failure")

    monkeypatch.setattr(
        emulated_family_module,
        "compile_patch_plan",
        _raise_compile_failure,
    )

    modifications, blocker = (
        emulated_family_module
        ._compile_terminal_selector_payload_materialization_modifications(
            candidate,
            flow_graph,
        )
    )

    assert modifications == ()
    assert blocker == "terminal_payload_materialization_patch_plan_failed"


def test_ollvm_terminal_payload_materialization_rejects_semantic_external_edge() -> None:
    payload_state = 0x2AC056AD
    selector_state = 0x049FD3A3
    external_state = 0x3CFC5AAB
    return_state = 0xBFF7ACB5

    def _key(state: int):
        return SimpleNamespace(state_const=state)

    def _edge(
        source: int,
        target: int | None,
        *,
        target_entry: int,
        source_block: int | None = None,
        branch_arm: int | None = None,
        kind: SemanticEdgeKind = SemanticEdgeKind.CONDITIONAL_TRANSITION,
    ):
        return SimpleNamespace(
            source_key=_key(source),
            target_key=(_key(target) if target is not None else None),
            kind=kind,
            target_entry_anchor=target_entry,
            source_anchor=(
                SimpleNamespace(block_serial=source_block, branch_arm=branch_arm)
                if source_block is not None
                else None
            ),
            ordered_path=(target_entry,),
        )

    dag = SimpleNamespace(
        edges=(
            _edge(
                payload_state,
                selector_state,
                target_entry=96,
                kind=SemanticEdgeKind.TRANSITION,
            ),
            _edge(
                selector_state,
                payload_state,
                target_entry=136,
                source_block=98,
                branch_arm=1,
            ),
            _edge(
                selector_state,
                return_state,
                target_entry=204,
                source_block=98,
                branch_arm=0,
            ),
            _edge(
                external_state,
                payload_state,
                target_entry=136,
                source_block=146,
                branch_arm=1,
            ),
            _edge(
                return_state,
                None,
                target_entry=204,
                kind=SemanticEdgeKind.CONDITIONAL_RETURN,
            ),
        ),
    )
    flow_graph = FlowGraph(
        blocks={
            136: BlockSnapshot(
                serial=136,
                block_type=ida_hexrays.BLT_1WAY,
                succs=(96,),
                preds=(98, 146),
                flags=0,
                start_ea=0x401136,
                insn_snapshots=(
                    InsnSnapshot(opcode=ida_hexrays.m_stx, ea=0x401136, operands=()),
                ),
            )
        },
        entry_serial=136,
        func_ea=0x401000,
    )
    blocked = BranchOwnershipProof(
        proof_id="selector-gap-proof",
        proof_kind=BranchOwnershipProofKind.UNRESOLVED,
        trusted=False,
        reason="terminal_selector_backedge_requires_side_effect_materialization",
        source_block=98,
        branch_arm=1,
        source_state=selector_state,
        target_state=payload_state,
        target_entry=136,
        evidence={"requires_side_effect_materialization": True},
    )
    semantic = BranchOwnershipProof(
        proof_id="external-semantic-proof",
        proof_kind=BranchOwnershipProofKind.REAL_DATA_DEPENDENT,
        trusted=True,
        reason="source_data_controls_payload",
        source_block=146,
        branch_arm=1,
        source_state=external_state,
        target_state=payload_state,
        target_entry=136,
    )
    veto = replace(
        semantic,
        proof_id="external-veto-proof",
        proof_kind=BranchOwnershipProofKind.UNRESOLVED,
        trusted=False,
        reason="z3_jumpfixer_discarded_arm_side_effect_guard",
        evidence={
            "side_effect_guard_reason": "discarded_arm_contains_payload_store",
        },
    )

    candidates = (
        emulated_family_module
        ._collect_terminal_selector_payload_materialization_candidates(
            dag=dag,
            flow_graph=flow_graph,
            branch_ownership_proofs=(blocked, veto, semantic),
        )
    )

    assert candidates == ()


def test_ollvm_terminal_payload_materialization_rejects_unproven_external_edge() -> None:
    payload_state = 0x2AC056AD
    selector_state = 0x049FD3A3
    external_state = 0x3CFC5AAB
    return_state = 0xBFF7ACB5

    def _key(state: int):
        return SimpleNamespace(state_const=state)

    def _edge(
        source: int,
        target: int | None,
        *,
        target_entry: int,
        source_block: int | None = None,
        branch_arm: int | None = None,
        kind: SemanticEdgeKind = SemanticEdgeKind.CONDITIONAL_TRANSITION,
    ):
        return SimpleNamespace(
            source_key=_key(source),
            target_key=(_key(target) if target is not None else None),
            kind=kind,
            target_entry_anchor=target_entry,
            source_anchor=(
                SimpleNamespace(block_serial=source_block, branch_arm=branch_arm)
                if source_block is not None
                else None
            ),
            ordered_path=(target_entry,),
        )

    dag = SimpleNamespace(
        edges=(
            _edge(
                payload_state,
                selector_state,
                target_entry=96,
                kind=SemanticEdgeKind.TRANSITION,
            ),
            _edge(
                selector_state,
                payload_state,
                target_entry=136,
                source_block=98,
                branch_arm=1,
            ),
            _edge(
                selector_state,
                return_state,
                target_entry=204,
                source_block=98,
                branch_arm=0,
            ),
            _edge(
                external_state,
                payload_state,
                target_entry=136,
                source_block=146,
                branch_arm=1,
            ),
            _edge(
                return_state,
                None,
                target_entry=204,
                kind=SemanticEdgeKind.CONDITIONAL_RETURN,
            ),
        ),
    )
    flow_graph = FlowGraph(
        blocks={
            136: BlockSnapshot(
                serial=136,
                block_type=ida_hexrays.BLT_1WAY,
                succs=(96,),
                preds=(98, 146),
                flags=0,
                start_ea=0x401136,
                insn_snapshots=(
                    InsnSnapshot(opcode=ida_hexrays.m_stx, ea=0x401136, operands=()),
                ),
            )
        },
        entry_serial=136,
        func_ea=0x401000,
    )
    blocked = BranchOwnershipProof(
        proof_id="selector-gap-proof",
        proof_kind=BranchOwnershipProofKind.UNRESOLVED,
        trusted=False,
        reason="terminal_selector_backedge_requires_side_effect_materialization",
        source_block=98,
        branch_arm=1,
        source_state=selector_state,
        target_state=payload_state,
        target_entry=136,
        evidence={"requires_side_effect_materialization": True},
    )

    candidates = (
        emulated_family_module
        ._collect_terminal_selector_payload_materialization_candidates(
            dag=dag,
            flow_graph=flow_graph,
            branch_ownership_proofs=(blocked,),
        )
    )

    assert candidates == ()


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


def test_branch_ownership_consumer_real_branch_proof_vetoes_rewrite() -> None:
    nonsemantic_proof = BranchOwnershipProof(
        proof_id="nonsemantic-arm-proof",
        proof_kind=BranchOwnershipProofKind.OBFUSCATION_RESIDUE_ARM,
        trusted=True,
        reason="fixture nonsemantic",
        source_block=5,
        branch_arm=1,
        source_state=0x10,
        target_state=0x20,
        oracle_kind="fixture",
    )
    real_branch_proof = BranchOwnershipProof(
        proof_id="real-branch-proof",
        proof_kind=BranchOwnershipProofKind.REAL_DATA_DEPENDENT,
        trusted=True,
        reason="fixture input-derived",
        source_block=5,
        branch_arm=1,
        source_state=0x10,
        target_state=0x20,
        oracle_kind="fixture",
    )
    edge = SimpleNamespace(
        source_key=SimpleNamespace(state_const=0x10),
        target_key=SimpleNamespace(state_const=0x20),
        target_entry_anchor=30,
        source_anchor=SimpleNamespace(block_serial=5, branch_arm=1),
        branch_ownership_proofs=(nonsemantic_proof, real_branch_proof),
    )

    assert (
        emulated_family_module._edge_has_trusted_nonsemantic_branch_proof(edge)
        is False
    )


def test_branch_ownership_consumer_sibling_real_branch_does_not_veto_rewrite() -> None:
    nonsemantic_proof = BranchOwnershipProof(
        proof_id="nonsemantic-arm-proof",
        proof_kind=BranchOwnershipProofKind.OBFUSCATION_RESIDUE_ARM,
        trusted=True,
        reason="fixture nonsemantic",
        source_block=5,
        branch_arm=1,
        source_state=0x10,
        target_state=0x20,
        oracle_kind="fixture",
    )
    sibling_real_branch_proof = BranchOwnershipProof(
        proof_id="real-sibling-proof",
        proof_kind=BranchOwnershipProofKind.REAL_DATA_DEPENDENT,
        trusted=True,
        reason="fixture input-derived sibling",
        source_block=5,
        branch_arm=0,
        source_state=0x10,
        target_state=0x30,
        oracle_kind="fixture",
    )
    edge = SimpleNamespace(
        source_key=SimpleNamespace(state_const=0x10),
        target_key=SimpleNamespace(state_const=0x20),
        target_entry_anchor=30,
        source_anchor=SimpleNamespace(block_serial=5, branch_arm=1),
        branch_ownership_proofs=(nonsemantic_proof, sibling_real_branch_proof),
    )

    assert (
        emulated_family_module._edge_has_trusted_nonsemantic_branch_proof(edge)
        is True
    )


def test_branch_ownership_refiner_side_effect_veto_is_sticky() -> None:
    original = BranchOwnershipProof(
        proof_id="candidate",
        proof_kind=BranchOwnershipProofKind.UNRESOLVED,
        trusted=False,
        reason="fixture original",
        source_block=5,
        branch_arm=0,
        source_state=0x10,
        target_state=0x20,
        target_entry=8,
        oracle_kind="fixture",
    )
    z3_veto = replace(
        original,
        reason="z3_jumpfixer_discarded_arm_side_effect_guard",
        evidence={"side_effect_guard_reason": "discarded_arm_contains_payload_store"},
    )

    def _z3_refiner(
        _proof: BranchOwnershipProof,
        _edge: object,
    ) -> BranchOwnershipProof:
        return z3_veto

    def _moptracker_refiner(
        proof: BranchOwnershipProof,
        _edge: object,
    ) -> BranchOwnershipProof:
        return replace(
            proof,
            proof_kind=BranchOwnershipProofKind.OBFUSCATION_RESIDUE_ARM,
            trusted=True,
            reason="moptracker_fallback_residue",
        )

    refiner = emulated_family_module._compose_branch_ownership_refiners(
        (_z3_refiner, _moptracker_refiner)
    )

    refined = refiner(original, SimpleNamespace())

    assert refined == z3_veto
    assert refined.vetoes_fallback_refinement is True
    assert refined.authorizes_nonsemantic_branch_rewrite is False


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


def test_implicit_profile_uses_state_map_evidence(
    monkeypatch,
) -> None:
    dispatch_map = _state_dispatcher_map(dispatcher_entry=13)
    dispatch_map = replace(
        dispatch_map,
        source=DispatcherType.CONDITIONAL_CHAIN,
        rows=tuple(
            replace(row, source=DispatcherType.CONDITIONAL_CHAIN)
            for row in dispatch_map.rows
        ),
    )
    calls = []
    mba = _fake_mba()
    analysis = SimpleNamespace(
        dispatchers=[99],
        state_constants=set(),
        dispatcher_type=SimpleNamespace(name="UNKNOWN"),
    )
    cache = SimpleNamespace(analyze=lambda: analysis)


    def _extract_state_dispatcher_map(_mba, *, dispatcher_entry_block=None, **_kwargs):
        calls.append(dispatcher_entry_block)
        if dispatcher_entry_block is not None:
            return None
        return dispatch_map

    monkeypatch.setattr(
        "d810.optimizers.microcode.flow.flattening.emulated_dispatcher_family.DispatcherCache",
        SimpleNamespace(get_or_create=lambda _mba: cache),
    )
    monkeypatch.setattr(
        emulated_family_module,
        "extract_state_dispatcher_map_from_mba",
        _extract_state_dispatcher_map,
    )

    family = EmulatedDispatcherStrategyFamily()
    detection = family.detect(mba)

    assert calls == [99, None]
    assert detection.detected is True
    assert detection.collector_dispatcher_entries == ()
    assert detection.analysis_dispatchers == (99,)
    assert detection.state_dispatcher_entries == (13,)
    assert detection.dispatcher_shape == "conditional_chain"
    assert detection.state_transport == "state_dispatcher_map"
    assert detection.provenance_hints == ("equality_chain",)
    assert detection.planning_blocker is None


def test_implicit_profile_prefers_switch_map_evidence(
    monkeypatch,
) -> None:
    dispatch_map = _state_dispatcher_map(dispatcher_entry=21)
    mba = _fake_mba()
    analysis = SimpleNamespace(
        dispatchers=[],
        state_constants=set(),
        dispatcher_type=SimpleNamespace(name="UNKNOWN"),
    )
    cache = SimpleNamespace(analyze=lambda: analysis)


    def _unexpected_equality_map(*_args, **_kwargs):
        raise AssertionError("switch-table map should be preferred")

    monkeypatch.setattr(
        "d810.optimizers.microcode.flow.flattening.emulated_dispatcher_family.DispatcherCache",
        SimpleNamespace(get_or_create=lambda _mba: cache),
    )
    monkeypatch.setattr(
        emulated_family_module,
        "_tigress_switch_state_dispatcher_maps",
        lambda *_args: (dispatch_map,),
    )
    monkeypatch.setattr(
        emulated_family_module,
        "_ollvm_state_dispatcher_maps",
        _unexpected_equality_map,
    )

    family = EmulatedDispatcherStrategyFamily()
    detection = family.detect(mba)

    assert detection.detected is True
    assert detection.state_dispatcher_entries == (21,)
    assert detection.dispatcher_shape == "switch_table"
    assert detection.state_transport == "state_dispatcher_map"
    assert detection.provenance_hints == ()
    assert detection.planning_blocker is None


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

    monkeypatch.setattr(
        "d810.optimizers.microcode.flow.flattening.emulated_dispatcher_family.DispatcherCache",
        SimpleNamespace(get_or_create=lambda _mba: cache),
    )

    family = EmulatedDispatcherStrategyFamily(
        profile=GenericDispatcherEngineProfile(
            name="switch_fixture",
            collector_factory=_Collector,
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


def test_implicit_family_profile_uses_state_dispatcher_map() -> None:
    family = EmulatedDispatcherStrategyFamily()

    assert family._profile.name == "ollvm_state_map"
    assert family._profile.state_transport == "state_dispatcher_map"


def test_tigress_indirect_profile_collects_configured_table(monkeypatch) -> None:
    dispatch_map = replace(
        _state_dispatcher_map(dispatcher_entry=3),
        source=DispatcherType.INDIRECT_JUMP,
        initial_state=34,
    )
    mba = SimpleNamespace(qty=1, maturity=ida_hexrays.MMAT_CALLS)
    calls = []

    def _analyze(mba_arg, goto_table_info):
        calls.append((mba_arg, goto_table_info))
        return SimpleNamespace(state_dispatcher_map=dispatch_map)

    from d810.optimizers.microcode.flow.dispatcher import (
        indirect_jump_table_analysis as indirect_analysis,
    )

    monkeypatch.setattr(
        indirect_analysis,
        "analyze_tigress_indirect_dispatcher_from_config",
        _analyze,
    )

    config = {"0x401000": {"table_address": "0x402000"}}
    profile = tigress_indirect_dispatcher_profile(goto_table_info=config)
    maps = profile.collect_state_dispatcher_maps(
        mba,
        analysis=object(),
        collector_dispatchers=(),
    )

    assert maps == (dispatch_map,)
    assert calls == [(mba, config)]


def test_tigress_switch_profile_collects_live_transition_facts(monkeypatch) -> None:
    dispatch_map = _state_dispatcher_map(dispatcher_entry=13)
    mba = SimpleNamespace(qty=1, maturity=ida_hexrays.MMAT_GLBOPT1)
    calls = []

    def _collect(*, mba, dispatch_map, profile_name):
        calls.append((mba, dispatch_map, profile_name))
        return ("fact",)

    monkeypatch.setattr(
        switch_case_transition_adapter,
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


def test_ollvm_profile_supplies_carrier_facts_via_profile(monkeypatch) -> None:
    mba = SimpleNamespace(qty=1, maturity=ida_hexrays.MMAT_CALLS)
    calls = []

    def _collect(seen_mba):
        calls.append(seen_mba)
        return ("carrier_fact",)

    monkeypatch.setattr(
        emulated_family_module,
        "collect_ollvm_post_execute_carrier_facts",
        _collect,
    )

    profile = ollvm_state_dispatcher_map_profile()
    assert profile.collect_post_execute_carrier_facts(mba) == ("carrier_fact",)
    assert calls == [mba]


def test_state_dispatcher_map_config_does_not_enable_predecessor_target_lowering() -> None:
    rule = EmulatedDispatcherUnflattener()
    rule.configure({
        "profile": "state_dispatcher_map",
        "enable_predecessor_dispatcher_target_lowering": True,
    })

    assert rule._family._profile.name == "ollvm_state_map"
    assert rule._family._profile.enable_predecessor_dispatcher_target_lowering is False


def test_post_execute_cleanup_uses_profile_carrier_facts_without_ollvm_name_gate(
    monkeypatch,
) -> None:
    facts = (SimpleNamespace(fact_id="carrier:1"),)
    seen: list[tuple[str, tuple[object, ...]]] = []

    family = EmulatedDispatcherStrategyFamily(
        profile=GenericDispatcherEngineProfile(
            name="carrier_fixture",
            collector_factory=_Collector,
            state_transport="fixture_transport",
            lowering_mode="fixture_lowering",
            post_execute_carrier_fact_factory=lambda _mba: facts,
        )
    )
    mba = SimpleNamespace(
        maturity=ida_hexrays.MMAT_CALLS,
        mark_chains_dirty=lambda: seen.append(("mark", ())),
        optimize_local=lambda _arg: seen.append(("optimize", ())),
    )
    snapshot = AnalysisSnapshot(
        mba=mba,
        maturity=ida_hexrays.MMAT_CALLS,
        flow_graph=FlowGraph(
            blocks=_flow_graph_with_edge().blocks,
            entry_serial=0,
            func_ea=0x401000,
            metadata={EMULATED_DISPATCHER_MODIFICATIONS_KEY: ()},
        ),
        state_summary=StateModelSummary(
            state_constants=frozenset(),
            handler_count=1,
            transition_count=0,
        ),
    )

    monkeypatch.setattr(
        emulated_family_module,
        "_apply_carrier_output_alias_repair",
        lambda _mba, _logger, carrier_facts: (
            seen.append(("output", tuple(carrier_facts))) or 1
        ),
    )
    monkeypatch.setattr(
        emulated_family_module,
        "_apply_local_alias_mem2reg",
        lambda _mba, _logger, carrier_facts: (
            seen.append(("alias", tuple(carrier_facts))) or 0
        ),
    )
    monkeypatch.setattr(
        emulated_family_module,
        "_apply_same_carrier_alias_repairs",
        lambda _mba, _logger, carrier_facts: (
            seen.append(("same", tuple(carrier_facts))) or 0
        ),
    )
    monkeypatch.setattr(
        emulated_family_module.DeferredGraphModifier,
        "run_deep_cleaning",
        lambda _self, **_kwargs: seen.append(("deep_clean", ())) or 0,
    )
    monkeypatch.setattr(
        emulated_family_module,
        "safe_verify",
        lambda _mba, _context, logger_func=None: seen.append(("verify", ())),
    )

    assert family.post_execute_cleanup(mba, snapshot=snapshot, total_changes=1) == 1
    assert ("output", facts) in seen
    assert ("alias", facts) in seen
    assert ("same", facts) in seen


def test_emulated_dispatcher_unflattener_accepts_tigress_switch_profile() -> None:
    rule = EmulatedDispatcherUnflattener()
    rule.configure({"profile": "tigress_switch", "diagnostics_only": True})

    assert rule._family._profile.name == "tigress_switch"
    assert rule._family._profile.state_transport == "state_dispatcher_map"
    assert rule.diagnostics_only is True


def test_emulated_dispatcher_unflattener_accepts_tigress_indirect_profile() -> None:
    rule = EmulatedDispatcherUnflattener()
    rule.configure({
        "profile": "tigress_indirect",
        "diagnostics_only": True,
        "goto_table_info": {"0x401000": {"table_address": "0x402000"}},
    })

    assert rule._family._profile.name == "tigress_indirect"
    assert rule._family._profile.state_transport == "state_dispatcher_map"
    assert rule._family._profile.lowering_mode == "indirect_jump_table_diagnostics"
    assert rule.diagnostics_only is True


def test_tigress_indirect_profile_can_materialize_targets(monkeypatch) -> None:
    calls = []

    def _materialize(config):
        calls.append(config)
        return ()

    import d810.hexrays.preanalysis.indirect_jump_labels as indirect_labels

    monkeypatch.setattr(
        indirect_labels,
        "materialize_indirect_label_targets_from_config",
        _materialize,
    )

    config = {
        "0x401000": {
            "table_address": "0x402000",
            "table_nb_elt": 2,
            "label_end": "0x401100",
        }
    }
    rule = EmulatedDispatcherUnflattener()
    rule.configure({
        "profile": "tigress_indirect",
        "diagnostics_only": True,
        "materialize_indirect_targets": True,
        "goto_table_info": config,
    })

    assert calls == [config]
    assert rule._family._profile.name == "tigress_indirect"


def test_emulated_dispatcher_unflattener_defaults_to_state_dispatcher_map() -> None:
    rule = EmulatedDispatcherUnflattener()
    rule.configure({})

    assert rule._family._profile.name == "ollvm_state_map"
    assert rule._family._profile.state_transport == "state_dispatcher_map"


@pytest.mark.parametrize(
    "profile_name",
    [
        "ollvm_father_history",
        "legacy_father_history",
        "ollvm_legacy_father_history",
        "father_history",
        "ollvm",
        "ollvm_father_history_compat",
    ],
)
def test_emulated_dispatcher_unflattener_rejects_old_father_history_aliases(
    profile_name,
) -> None:
    rule = EmulatedDispatcherUnflattener()

    with pytest.raises(ValueError, match="Unknown EmulatedDispatcherUnflattener profile"):
        rule.configure({"profile": profile_name})


def test_emulated_dispatcher_unflattener_rejects_unknown_profile() -> None:
    rule = EmulatedDispatcherUnflattener()

    with pytest.raises(ValueError, match="Unknown EmulatedDispatcherUnflattener profile"):
        rule.configure({"profile": "typo_state_map"})


def test_emulated_dispatcher_unflattener_accepts_ollvm_materialization_guard() -> None:
    rule = EmulatedDispatcherUnflattener()
    rule.configure({
        "profile": "ollvm_state_map",
        "enable_terminal_payload_materialization": True,
    })

    assert rule._family._profile.name == "ollvm_state_map"
    assert rule._family._profile.enable_terminal_payload_materialization is True


def test_emulated_dispatcher_family_primary_entry_uses_profile() -> None:
    dispatcher_info = object()

    class _Collector:
        def get_dispatcher_list(self):
            return [dispatcher_info]

    class _Profile(GenericDispatcherEngineProfile):
        def dispatcher_entry_serial(self, seen_dispatcher_info):
            assert seen_dispatcher_info is dispatcher_info
            return 17

    family = EmulatedDispatcherStrategyFamily(
        profile=_Profile(
            name="fixture",
            collector_factory=_Collector,
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
    class _Profile(GenericDispatcherEngineProfile):
        def dispatcher_entry_serial(self, seen_dispatcher_info):
            assert seen_dispatcher_info is dispatcher_info
            return 17

    family = EmulatedDispatcherStrategyFamily(
        profile=_Profile(
            name="fixture",
            collector_factory=_Collector,
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


def test_emulated_dispatcher_family_primary_entry_uses_analysis_root_for_conditional_chain() -> None:
    family = EmulatedDispatcherStrategyFamily()
    detection = EmulatedDispatcherDetection(
        dispatcher_shape="conditional_chain",
        state_dispatcher_entries=(3, 7, 10),
        analysis_dispatchers=(2, 3, 6, 7, 10),
    )

    assert family._primary_dispatcher_entry_serial(detection) == 2


def test_emulated_dispatcher_family_builds_phase_artifact_from_dispatcher_map(
    monkeypatch,
) -> None:
    dispatch_map = _state_dispatcher_map(dispatcher_entry=2)
    switch_fact = SimpleNamespace(fact_id="tigress_switch:case=16:direct")
    switch_fact_calls = []

    def _switch_fact_factory(mba, seen_dispatch_map, profile_name):
        switch_fact_calls.append((mba, seen_dispatch_map, profile_name))
        return (switch_fact,)

    family = EmulatedDispatcherStrategyFamily(
        profile=GenericDispatcherEngineProfile(
            name="tigress_switch",
            collector_factory=_Collector,
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
        "_find_pre_header_state",
        lambda *_args, **_kwargs: (1, 0x20),
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
    assert artifact.pre_header_serial == 1
    assert artifact.state_var_stkoff == 0x3C
    assert artifact.initial_state == 0x10
    assert artifact.handler_state_map == ((5, 0x10), (7, 0x20))
    assert context.state_dispatcher_map is dispatch_map
    assert context.switch_case_transition_facts == (switch_fact,)
    assert switch_fact_calls == [(mba, dispatch_map, "tigress_switch")]


def test_emulated_dispatcher_family_anchors_conditional_chain_suffix_maps_to_analysis_root(
    monkeypatch,
) -> None:
    suffix_a = _conditional_chain_state_dispatcher_map(
        dispatcher_entry=3,
        state=0x10,
        target=4,
    )
    suffix_b = _conditional_chain_state_dispatcher_map(
        dispatcher_entry=7,
        state=0x20,
        target=8,
    )

    family = EmulatedDispatcherStrategyFamily(
        profile=GenericDispatcherEngineProfile(
            name="ollvm_state_map",
            collector_factory=_Collector,
            state_transport="state_dispatcher_map",
            lowering_mode="generic_graph_modifications",
            state_dispatcher_map_factory=lambda *_args: (),
        )
    )
    mba = SimpleNamespace(
        qty=9,
        maturity=ida_hexrays.MMAT_GLBOPT1,
        entry_ea=0x401000,
    )
    flow_graph = _flow_graph_with_conditional_shape()
    seen_preheader_entries = []

    monkeypatch.setattr(
        emulated_family_module,
        "analyze_bst_dispatcher",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("map-backed conditional chain should use exact rows")
        ),
    )
    monkeypatch.setattr(
        emulated_family_module,
        "_detect_state_var_stkoff",
        lambda *_args, **_kwargs: (0x3C, None),
    )

    def _fake_find_pre_header_state(_mba, dispatcher_entry, state_var_stkoff):
        seen_preheader_entries.append((dispatcher_entry, state_var_stkoff))
        return 1, 0x10

    monkeypatch.setattr(
        emulated_family_module,
        "_find_pre_header_state",
        _fake_find_pre_header_state,
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
            state_dispatcher_maps=(suffix_a, suffix_b),
            state_dispatcher_entries=(3, 7),
            analysis_dispatchers=(2, 3, 6, 7),
            dispatcher_shape="conditional_chain",
            state_transport="state_dispatcher_map",
            state_constants=(0x10, 0x20),
        ),
        flow_graph=flow_graph,
    )

    assert artifact is not None
    assert context is not None
    assert seen_preheader_entries == [(2, 0x3C)]
    assert artifact.dispatcher_entry_serial == 2
    assert artifact.pre_header_serial == 1
    assert artifact.initial_state == 0x10
    assert artifact.bst_node_blocks == (2, 3, 7)
    assert artifact.handler_state_map == ((4, 0x10), (8, 0x20))
    assert context.state_dispatcher_map is not None
    assert context.state_dispatcher_map.dispatcher_entry_block == 2
    assert context.state_dispatcher_map.dispatcher_blocks == frozenset({2, 3, 7})
    discovery_by_kind = {
        observation.kind: observation
        for observation in context.dispatcher_discovery_fact_observations
    }
    assert discovery_by_kind[STATE_DISPATCHER_TOPOLOGY_FACT_TYPE].payload[
        "dispatcher_blocks"
    ] == [2, 3, 7]
    assert discovery_by_kind[STATE_VARIABLE_IDENTITY_FACT_TYPE].payload[
        "state_var_stkoff"
    ] == 0x3C
    assert discovery_by_kind[DISPATCHER_INITIAL_STATE_FACT_TYPE].payload[
        "initial_state"
    ] == 0x10


def test_tigress_switch_transition_facts_lower_direct_case_redirect() -> None:
    dispatch_map = replace(
        _state_dispatcher_map(dispatcher_entry=2),
        initial_state=None,
    )
    fact = switch_case_transition_analysis.SwitchCaseTransitionFact(
        fact_id="tigress_switch:case=16:direct",
        transition_kind=switch_case_transition_analysis.SwitchCaseTransitionKind.DIRECT,
        source_state=0x10,
        case_entry_block=5,
        next_states=(0x20,),
        exit_block=5,
        reason="direct_case_transition",
    )
    flow_graph = FlowGraph(
        blocks={
            1: BlockSnapshot(
                serial=1,
                block_type=ida_hexrays.BLT_1WAY,
                succs=(2,),
                preds=(),
                flags=0,
                start_ea=0x401001,
                insn_snapshots=(),
            ),
            2: BlockSnapshot(
                serial=2,
                block_type=ida_hexrays.BLT_2WAY,
                succs=(5, 7),
                preds=(1, 5),
                flags=0,
                start_ea=0x401002,
                insn_snapshots=(),
            ),
            5: BlockSnapshot(
                serial=5,
                block_type=ida_hexrays.BLT_1WAY,
                succs=(2,),
                preds=(0,),
                flags=0,
                start_ea=0x401005,
                insn_snapshots=(),
            ),
            7: BlockSnapshot(
                serial=7,
                block_type=ida_hexrays.BLT_0WAY,
                succs=(),
                preds=(2,),
                flags=0,
                start_ea=0x401007,
                insn_snapshots=(),
            ),
        },
        entry_serial=5,
        func_ea=0x401000,
    )
    family = EmulatedDispatcherStrategyFamily(profile=tigress_switch_dispatcher_profile())
    modifications, blockers = family._collect_tigress_switch_transition_modifications(
        flow_graph=flow_graph,
        phase_artifact=EmulatedDispatcherPhaseArtifact(
            dispatcher_entry_serial=2,
            pre_header_serial=1,
            initial_state=0x10,
        ),
        phase_context=EmulatedDispatcherPhaseContext(
            bst_result=object(),
            transition_result=object(),
            transition_report=object(),
            dag=object(),
            semantic_reference_program=object(),
            state_dispatcher_map=dispatch_map,
            switch_case_transition_facts=(fact, _switch_return_fact(0x20, 7)),
        ),
    )

    assert blockers == ()
    assert modifications == (
        RedirectGoto(from_serial=1, old_target=2, new_target=5),
        RedirectGoto(from_serial=5, old_target=2, new_target=7),
    )


def test_switch_transition_facts_lower_guard_reentry_redirect() -> None:
    dispatch_map = replace(
        _state_dispatcher_map(dispatcher_entry=3),
        initial_state=None,
        dispatcher_blocks=frozenset({2, 3}),
    )
    fact = switch_case_transition_analysis.SwitchCaseTransitionFact(
        fact_id="ollvm:case=16:direct",
        transition_kind=switch_case_transition_analysis.SwitchCaseTransitionKind.DIRECT,
        source_state=0x10,
        case_entry_block=5,
        next_states=(0x20,),
        exit_block=6,
        reason="direct_case_transition",
    )
    flow_graph = FlowGraph(
        blocks={
            2: BlockSnapshot(2, ida_hexrays.BLT_2WAY, (3, 9), (1, 6), 0, 0x401002, ()),
            3: BlockSnapshot(3, ida_hexrays.BLT_2WAY, (5, 7), (2,), 0, 0x401003, ()),
            5: BlockSnapshot(5, ida_hexrays.BLT_1WAY, (6,), (3,), 0, 0x401005, ()),
            6: BlockSnapshot(6, ida_hexrays.BLT_1WAY, (2,), (5,), 0, 0x401006, ()),
            7: BlockSnapshot(7, ida_hexrays.BLT_0WAY, (), (3,), 0, 0x401007, ()),
            9: BlockSnapshot(9, ida_hexrays.BLT_0WAY, (), (2,), 0, 0x401009, ()),
        },
        entry_serial=2,
        func_ea=0x401000,
    )
    family = EmulatedDispatcherStrategyFamily()
    modifications, blockers = family._collect_tigress_switch_transition_modifications(
        flow_graph=flow_graph,
        phase_artifact=EmulatedDispatcherPhaseArtifact(
            dispatcher_entry_serial=3,
            pre_header_serial=None,
        ),
        phase_context=EmulatedDispatcherPhaseContext(
            bst_result=object(),
            transition_result=object(),
            transition_report=object(),
            dag=object(),
            semantic_reference_program=object(),
            state_dispatcher_map=dispatch_map,
            switch_case_transition_facts=(fact, _switch_return_fact(0x20, 7)),
        ),
    )

    assert modifications == (
        RedirectGoto(from_serial=6, old_target=2, new_target=7),
    )
    assert blockers == ("tigress_switch_transition_initial_redirect_unproven",)


def test_switch_transition_partial_lowering_keeps_safety_blockers_hard() -> None:
    terminal_unresolved = switch_case_transition_analysis.SwitchCaseTransitionFact(
        fact_id="ollvm:case=7:unresolved:direct_target_not_in_switch_rows",
        transition_kind=switch_case_transition_analysis.SwitchCaseTransitionKind.UNRESOLVED,
        source_state=7,
        case_entry_block=13,
        next_states=(0xFF,),
        reason="direct_target_not_in_switch_rows",
    )
    conditional_unresolved = switch_case_transition_analysis.SwitchCaseTransitionFact(
        fact_id="ollvm:case=1:unresolved:conditional_case_transition_unresolved",
        transition_kind=switch_case_transition_analysis.SwitchCaseTransitionKind.UNRESOLVED,
        source_state=1,
        case_entry_block=5,
        next_states=(2, 3),
        reason="conditional_case_transition_unresolved",
    )
    assert emulated_family_module._switch_transition_blockers_allow_partial_lowering((
        "tigress_switch_transition_initial_redirect_unproven",
        "tigress_switch_transition_visible_state_not_lowered",
    ))
    assert emulated_family_module._switch_transition_blockers_allow_partial_lowering(
        (
            "tigress_switch_transition_fact_unresolved",
            "tigress_switch_transition_initial_redirect_unproven",
        ),
        facts=(terminal_unresolved,),
    )
    assert not emulated_family_module._switch_transition_blockers_allow_partial_lowering(
        (
            "tigress_switch_transition_fact_unresolved",
        ),
        facts=(conditional_unresolved,),
    )
    assert not emulated_family_module._switch_transition_blockers_allow_partial_lowering((
        "tigress_switch_transition_initial_redirect_unproven",
        "tigress_switch_transition_source_not_owned",
    ))
    assert not emulated_family_module._switch_transition_blockers_allow_partial_lowering((
        "tigress_switch_transition_conditional_untrusted",
    ))


def test_switch_transition_partial_lowering_records_partial_rewrite_reasons(monkeypatch) -> None:
    dispatch_map = replace(
        _state_dispatcher_map(dispatcher_entry=3),
        initial_state=None,
        dispatcher_blocks=frozenset({2, 3}),
    )
    fact = switch_case_transition_analysis.SwitchCaseTransitionFact(
        fact_id="ollvm:case=16:direct",
        transition_kind=switch_case_transition_analysis.SwitchCaseTransitionKind.DIRECT,
        source_state=0x10,
        case_entry_block=5,
        next_states=(0x20,),
        exit_block=6,
        reason="direct_case_transition",
    )
    flow_graph = FlowGraph(
        blocks={
            2: BlockSnapshot(2, ida_hexrays.BLT_2WAY, (3, 9), (1, 6), 0, 0x401002, ()),
            3: BlockSnapshot(3, ida_hexrays.BLT_2WAY, (5, 7), (2,), 0, 0x401003, ()),
            5: BlockSnapshot(5, ida_hexrays.BLT_1WAY, (6,), (3,), 0, 0x401005, ()),
            6: BlockSnapshot(6, ida_hexrays.BLT_1WAY, (2,), (5,), 0, 0x401006, ()),
            7: BlockSnapshot(7, ida_hexrays.BLT_0WAY, (), (3,), 0, 0x401007, ()),
            9: BlockSnapshot(9, ida_hexrays.BLT_0WAY, (), (2,), 0, 0x401009, ()),
        },
        entry_serial=2,
        func_ea=0x401000,
    )
    family = EmulatedDispatcherStrategyFamily(
        cfg_translator=SimpleNamespace(lift=lambda _mba: flow_graph),
        profile=tigress_switch_dispatcher_profile(
            allow_incomplete_switch_transition_facts=True,
        ),
    )
    phase_context = EmulatedDispatcherPhaseContext(
        bst_result=object(),
        transition_result=object(),
        transition_report=object(),
        dag=object(),
        semantic_reference_program=object(),
        state_dispatcher_map=dispatch_map,
        switch_case_transition_facts=(fact, _switch_return_fact(0x20, 7)),
    )
    monkeypatch.setattr(
        family,
        "_build_phase_artifact",
        lambda *_args, **_kwargs: (
            EmulatedDispatcherPhaseArtifact(
                dispatcher_entry_serial=3,
                pre_header_serial=None,
            ),
            phase_context,
        ),
    )
    monkeypatch.setattr(
        family,
        "_collect_lowering_candidates",
        lambda *_args, **_kwargs: ((), (), ()),
    )
    monkeypatch.setattr(
        family,
        "_collect_phase_state_dag_modifications",
        lambda *_args, **_kwargs: ((), ()),
    )

    snapshot = family.build_snapshot(
        _fake_mba(),
        EmulatedDispatcherDetection(
            analysis_dispatchers=(3,),
            dispatcher_shape="switch_table",
            state_transport="state_dispatcher_map",
            lowering_mode="generic_graph_modifications",
            provenance_hints=("switch_table",),
            state_constants=(0x10, 0x20),
            state_dispatcher_entries=(3,),
        ),
    )
    metadata = extract_emulated_dispatcher_metadata(snapshot.flow_graph)

    assert metadata is not None
    assert metadata.planning_ready is True
    assert metadata.selected_lowering_mode == "tigress_switch_transition_facts"
    assert metadata.rejection_reasons == ()
    assert metadata.partial_rewrite_reasons == (
        "tigress_switch_transition_initial_redirect_unproven",
    )
    assert metadata.is_partial is True
    modifications = extract_emulated_dispatcher_modifications(snapshot.flow_graph)
    assert modifications == (
        RedirectGoto(from_serial=6, old_target=2, new_target=7),
    )
    assert all(getattr(mod, "from_serial", None) not in {2, 3} for mod in modifications)


def test_loop_recovery_override_clears_switch_partial_rewrite_reasons(monkeypatch) -> None:
    dispatch_map = replace(
        _state_dispatcher_map(dispatcher_entry=3),
        initial_state=None,
        dispatcher_blocks=frozenset({2, 3}),
    )
    fact = switch_case_transition_analysis.SwitchCaseTransitionFact(
        fact_id="ollvm:case=16:direct",
        transition_kind=switch_case_transition_analysis.SwitchCaseTransitionKind.DIRECT,
        source_state=0x10,
        case_entry_block=5,
        next_states=(0x20,),
        exit_block=6,
        reason="direct_case_transition",
    )
    flow_graph = FlowGraph(
        blocks={
            2: BlockSnapshot(2, ida_hexrays.BLT_2WAY, (3, 9), (1, 6), 0, 0x401002, ()),
            3: BlockSnapshot(3, ida_hexrays.BLT_2WAY, (5, 7), (2,), 0, 0x401003, ()),
            5: BlockSnapshot(5, ida_hexrays.BLT_1WAY, (6,), (3,), 0, 0x401005, ()),
            6: BlockSnapshot(6, ida_hexrays.BLT_1WAY, (2,), (5,), 0, 0x401006, ()),
            7: BlockSnapshot(7, ida_hexrays.BLT_0WAY, (), (3,), 0, 0x401007, ()),
            9: BlockSnapshot(9, ida_hexrays.BLT_0WAY, (), (2,), 0, 0x401009, ()),
        },
        entry_serial=2,
        func_ea=0x401000,
    )
    loop_recovery_modifications = (
        RedirectGoto(from_serial=5, old_target=6, new_target=7),
    )
    family = EmulatedDispatcherStrategyFamily(
        cfg_translator=SimpleNamespace(lift=lambda _mba: flow_graph),
        profile=tigress_switch_dispatcher_profile(
            allow_incomplete_switch_transition_facts=True,
        ),
    )
    phase_context = EmulatedDispatcherPhaseContext(
        bst_result=object(),
        transition_result=object(),
        transition_report=object(),
        dag=object(),
        semantic_reference_program=object(),
        state_dispatcher_map=dispatch_map,
        switch_case_transition_facts=(fact, _switch_return_fact(0x20, 7)),
    )
    monkeypatch.setattr(
        family,
        "_build_phase_artifact",
        lambda *_args, **_kwargs: (
            EmulatedDispatcherPhaseArtifact(
                dispatcher_entry_serial=3,
                pre_header_serial=None,
            ),
            phase_context,
        ),
    )
    monkeypatch.setattr(
        family,
        "_collect_lowering_candidates",
        lambda *_args, **_kwargs: ((), (), ()),
    )
    monkeypatch.setattr(
        family,
        "_collect_phase_state_dag_modifications",
        lambda *_args, **_kwargs: ((), ()),
    )
    monkeypatch.setattr(
        family,
        "_collect_loop_recovery_modifications",
        lambda *_args, **_kwargs: (loop_recovery_modifications, (), ()),
    )

    snapshot = family.build_snapshot(
        _fake_mba(),
        EmulatedDispatcherDetection(
            analysis_dispatchers=(3,),
            dispatcher_shape="switch_table",
            state_transport="state_dispatcher_map",
            lowering_mode="generic_graph_modifications",
            provenance_hints=("switch_table",),
            state_constants=(0x10, 0x20),
            collector_dispatchers=(object(),),
            collector_dispatcher_entries=(3,),
            state_dispatcher_entries=(3,),
        ),
    )
    metadata = extract_emulated_dispatcher_metadata(snapshot.flow_graph)

    assert metadata is not None
    assert metadata.planning_ready is True
    assert metadata.selected_lowering_mode == "dispatcher_loop_recovery"
    assert metadata.rejection_reasons == ()
    assert metadata.partial_rewrite_reasons == ()
    assert metadata.is_partial is False
    assert extract_emulated_dispatcher_modifications(snapshot.flow_graph) == (
        loop_recovery_modifications
    )


def test_predecessor_target_lowering_is_recon_only_until_safe_materialization(
    monkeypatch,
) -> None:
    family = EmulatedDispatcherStrategyFamily(
        profile=GenericDispatcherEngineProfile(
            name="fixture",
            collector_factory=_Collector,
            state_transport="state_dispatcher_map",
            lowering_mode="generic_graph_modifications",
            enable_predecessor_dispatcher_target_lowering=True,
        )
    )
    calls = []
    monkeypatch.setattr(
        family,
        "_collect_predecessor_dispatcher_target_candidates",
        lambda **_kwargs: calls.append("called") or (("mod",), (), ()),
    )
    mba = SimpleNamespace(maturity=ida_hexrays.MMAT_GLBOPT1)

    result = family._collect_lowering_candidates(
        mba,
        EmulatedDispatcherDetection(
            state_dispatcher_entries=(4,),
            state_transport="state_dispatcher_map",
            lowering_mode="generic_graph_modifications",
        ),
        flow_graph=_flow_graph_with_edge(),
    )

    assert result == ((), (), ())
    assert calls == []


def test_tigress_switch_transition_facts_lower_conditional_arm_exits() -> None:
    dispatch_map = StateDispatcherMap(
        rows=(
            StateDispatcherRow(0x10, 5, 2, 2, "switch_case", DispatcherType.SWITCH_TABLE),
            StateDispatcherRow(0x20, 7, 2, 2, "switch_case", DispatcherType.SWITCH_TABLE),
            StateDispatcherRow(0x30, 9, 2, 2, "switch_case", DispatcherType.SWITCH_TABLE),
        ),
        dispatcher_entry_block=2,
        dispatcher_blocks=frozenset({2}),
        state_var_stkoff=0x3C,
        state_var_lvar_idx=None,
        source=DispatcherType.SWITCH_TABLE,
        initial_state=0x10,
    )
    fact = switch_case_transition_analysis.SwitchCaseTransitionFact(
        fact_id="tigress_switch:case=16:conditional",
        transition_kind=switch_case_transition_analysis.SwitchCaseTransitionKind.CONDITIONAL,
        source_state=0x10,
        case_entry_block=5,
        next_states=(0x20, 0x30),
        exit_block=6,
        ordered_path=(5, 6),
        proof=BranchOwnershipProof(
            proof_id="tigress_switch:case=16:conditional",
            proof_kind=BranchOwnershipProofKind.REAL_DATA_DEPENDENT,
            trusted=True,
            reason="conditional_case_transition_source_predicate",
            source_state=0x10,
            source_block=5,
            predicate_block=5,
            dispatcher_entry_block=2,
            oracle_kind="switch_case_branch_ownership",
        ),
        payload={
            "arm_exit_blocks": (6, 8),
            "arm_ordered_paths": ((5, 6), (5, 8)),
        },
    )
    flow_graph = FlowGraph(
        blocks={
            1: BlockSnapshot(1, ida_hexrays.BLT_1WAY, (2,), (), 0, 0x401001, ()),
            2: BlockSnapshot(2, ida_hexrays.BLT_2WAY, (5, 7, 9), (1, 6, 8), 0, 0x401002, ()),
            5: BlockSnapshot(5, ida_hexrays.BLT_2WAY, (6, 8), (2,), 0, 0x401005, ()),
            6: BlockSnapshot(6, ida_hexrays.BLT_1WAY, (2,), (5,), 0, 0x401006, ()),
            8: BlockSnapshot(8, ida_hexrays.BLT_1WAY, (2,), (5,), 0, 0x401008, ()),
            7: BlockSnapshot(7, ida_hexrays.BLT_0WAY, (), (2,), 0, 0x401007, ()),
            9: BlockSnapshot(9, ida_hexrays.BLT_0WAY, (), (2,), 0, 0x401009, ()),
        },
        entry_serial=1,
        func_ea=0x401000,
    )
    family = EmulatedDispatcherStrategyFamily(profile=tigress_switch_dispatcher_profile())
    modifications, blockers = family._collect_tigress_switch_transition_modifications(
        flow_graph=flow_graph,
        phase_artifact=EmulatedDispatcherPhaseArtifact(
            dispatcher_entry_serial=2,
            pre_header_serial=1,
        ),
        phase_context=EmulatedDispatcherPhaseContext(
            bst_result=object(),
            transition_result=object(),
            transition_report=object(),
            dag=object(),
            semantic_reference_program=object(),
            state_dispatcher_map=dispatch_map,
            switch_case_transition_facts=(
                fact,
                _switch_return_fact(0x20, 7),
                _switch_return_fact(0x30, 9),
            ),
        ),
    )

    assert blockers == ()
    assert modifications == (
        RedirectGoto(from_serial=1, old_target=2, new_target=5),
        RedirectGoto(from_serial=6, old_target=2, new_target=7),
        RedirectGoto(from_serial=8, old_target=2, new_target=9),
    )


def test_tigress_switch_transition_facts_reject_shared_source() -> None:
    dispatch_map = _state_dispatcher_map(dispatcher_entry=2)
    fact = switch_case_transition_analysis.SwitchCaseTransitionFact(
        fact_id="tigress_switch:case=16:direct",
        transition_kind=switch_case_transition_analysis.SwitchCaseTransitionKind.DIRECT,
        source_state=0x10,
        case_entry_block=5,
        next_states=(0x20,),
        exit_block=5,
        reason="direct_case_transition",
    )
    flow_graph = FlowGraph(
        blocks={
            1: BlockSnapshot(
                serial=1,
                block_type=ida_hexrays.BLT_1WAY,
                succs=(2,),
                preds=(),
                flags=0,
                start_ea=0x401001,
                insn_snapshots=(),
            ),
            2: BlockSnapshot(
                serial=2,
                block_type=ida_hexrays.BLT_2WAY,
                succs=(5, 7),
                preds=(1, 5),
                flags=0,
                start_ea=0x401002,
                insn_snapshots=(),
            ),
            5: BlockSnapshot(
                serial=5,
                block_type=ida_hexrays.BLT_1WAY,
                succs=(2,),
                preds=(0, 1),
                flags=0,
                start_ea=0x401005,
                insn_snapshots=(),
            ),
            7: BlockSnapshot(
                serial=7,
                block_type=ida_hexrays.BLT_0WAY,
                succs=(),
                preds=(2,),
                flags=0,
                start_ea=0x401007,
                insn_snapshots=(),
            ),
        },
        entry_serial=5,
        func_ea=0x401000,
    )
    family = EmulatedDispatcherStrategyFamily(profile=tigress_switch_dispatcher_profile())
    modifications, blockers = family._collect_tigress_switch_transition_modifications(
        flow_graph=flow_graph,
        phase_artifact=EmulatedDispatcherPhaseArtifact(
            dispatcher_entry_serial=2,
            pre_header_serial=1,
        ),
        phase_context=EmulatedDispatcherPhaseContext(
            bst_result=object(),
            transition_result=object(),
            transition_report=object(),
            dag=object(),
            semantic_reference_program=object(),
            state_dispatcher_map=dispatch_map,
            switch_case_transition_facts=(fact, _switch_return_fact(0x20, 7)),
        ),
    )

    assert modifications == ()
    assert "tigress_switch_transition_source_not_owned" in blockers
    assert "tigress_switch_transition_visible_state_not_lowered" in blockers


def test_emulated_dispatcher_phase_diagnostics_emit_profile_switch_facts(
    monkeypatch,
) -> None:
    switch_fact = SimpleNamespace(fact_id="tigress_switch:case=16:direct")
    dispatcher_observation = SimpleNamespace(kind=STATE_DISPATCHER_TOPOLOGY_FACT_TYPE)
    context = EmulatedDispatcherPhaseContext(
        bst_result=object(),
        transition_result=object(),
        transition_report=object(),
        dag=SimpleNamespace(nodes=(), edges=()),
        semantic_reference_program=object(),
        switch_case_transition_facts=(switch_fact,),
        dispatcher_discovery_fact_observations=(dispatcher_observation,),
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
    observed_fact_rows = []

    monkeypatch.setattr(
        hexrays_observability,
        "request_capture_mba_snapshot",
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
    monkeypatch.setattr(
        "d810.recon.observability.observe_fact_observation",
        lambda snap, func_ea, observations: observed_fact_rows.append(
            (snap, func_ea, tuple(observations))
        ),
    )

    EmulatedDispatcherStrategyFamily(
        profile=tigress_switch_dispatcher_profile(),
    ).observe_phase_diagnostics(
        snapshot.mba,
        snapshot,
    )

    assert observed == [("snap", (switch_fact,))]
    assert observed_fact_rows == [
        ("snap", 0x401000, (dispatcher_observation,))
    ]


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
        hexrays_observability,
        "request_capture_mba_snapshot",
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


def test_guarded_entry_setup_pre_header_region_allows_guard_returns() -> None:
    def _snapshot(serial, succs, preds):
        return BlockSnapshot(
            serial=serial,
            block_type=ida_hexrays.BLT_2WAY if len(succs) == 2 else (
                ida_hexrays.BLT_1WAY if succs else ida_hexrays.BLT_0WAY
            ),
            succs=tuple(succs),
            preds=tuple(preds),
            flags=0,
            start_ea=0x401000 + serial,
            insn_snapshots=(),
        )

    flow_graph = FlowGraph(
        blocks={
            0: _snapshot(0, (1,), ()),
            1: _snapshot(1, (2, 3), (0,)),
            2: _snapshot(2, (), (1,)),
            3: _snapshot(3, (4, 5), (1,)),
            4: _snapshot(4, (), (3,)),
            5: _snapshot(5, (6,), (3,)),
            6: _snapshot(6, (7,), (5, 7)),
            7: _snapshot(7, (6,), (6,)),
        },
        entry_serial=0,
        func_ea=0x401000,
    )

    region = emulated_family_module._guarded_entry_setup_pre_header_region(
        flow_graph,
        pre_header_serial=5,
        dispatcher_entry_serial=6,
        forbidden_serials={6, 7},
    )

    assert region == (0, 1, 2, 3, 4, 5)


def test_guarded_entry_setup_pre_header_region_rejects_handler_entry_leak() -> None:
    def _snapshot(serial, succs, preds):
        return BlockSnapshot(
            serial=serial,
            block_type=ida_hexrays.BLT_2WAY if len(succs) == 2 else (
                ida_hexrays.BLT_1WAY if succs else ida_hexrays.BLT_0WAY
            ),
            succs=tuple(succs),
            preds=tuple(preds),
            flags=0,
            start_ea=0x401000 + serial,
            insn_snapshots=(),
        )

    flow_graph = FlowGraph(
        blocks={
            0: _snapshot(0, (1,), ()),
            1: _snapshot(1, (5, 7), (0,)),
            5: _snapshot(5, (6,), (1,)),
            6: _snapshot(6, (7,), (5, 7)),
            7: _snapshot(7, (6,), (1, 6)),
        },
        entry_serial=0,
        func_ea=0x401000,
    )

    region = emulated_family_module._guarded_entry_setup_pre_header_region(
        flow_graph,
        pre_header_serial=5,
        dispatcher_entry_serial=6,
        forbidden_serials={6, 7},
    )

    assert region == ()


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


def test_emulated_dispatcher_family_vetoes_residual_terminal_non_state_use_def(
    monkeypatch,
) -> None:
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
            5: _snapshot(5, (2,), (8,)),
            7: _snapshot(7, (), (2,)),
            8: _snapshot(8, (5,), (7,)),
            9: _snapshot(9, (2,), (8,)),
        },
        entry_serial=5,
        func_ea=0x401000,
    )
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
        dag=SimpleNamespace(edges=()),
        semantic_reference_program=object(),
    )
    detection = EmulatedDispatcherDetection(
        dispatcher_shape="conditional_chain",
        state_transport="state_dispatcher_map",
        lowering_mode="generic_graph_modifications",
        state_constants=(0x10, 0x20),
    )

    def _fake_postprocess(**kwargs):
        kwargs["modifications"].append(
            RedirectGoto(from_serial=9, old_target=2, new_target=7)
        )
        return SimpleNamespace(
            initial_residual_dispatcher_preds=(5,),
            residual_dispatcher_preds=(5,),
        )

    def _fake_use_def_check(_modification, _mba, _flow_graph):
        return (
            SimpleNamespace(
                var_stkoff=0x0,
                var_size=4,
                use_block=7,
                use_ea=0x401007,
            ),
        )

    monkeypatch.setattr(
        emulated_family_module,
        "execute_reconstruction_postprocess",
        _fake_postprocess,
    )
    monkeypatch.setattr(
        emulated_family_module,
        "check_redirect_severs_use_def",
        _fake_use_def_check,
    )

    family = EmulatedDispatcherStrategyFamily()
    modifications, blockers = (
        family._collect_residual_terminal_postprocess_modifications(
            mba=_fake_mba(),
            flow_graph=flow_graph,
            detection=detection,
            phase_artifact=artifact,
            phase_context=context,
            constant_result=object(),
            indexes=SimpleNamespace(dispatcher_region=(2,), node_by_key={}),
            pre_header=5,
            dispatcher_entry=2,
        )
    )

    assert modifications == ()
    assert blockers == ("phase_reconstruction_residual_terminal_use_def_veto",)


def test_emulated_dispatcher_family_state_map_loop_recovery_uses_recon_facts(
    monkeypatch,
) -> None:
    def _snapshot(serial, succs, preds):
        return BlockSnapshot(
            serial=serial,
            block_type=ida_hexrays.BLT_2WAY
            if len(succs) == 2
            else ida_hexrays.BLT_1WAY
            if succs
            else ida_hexrays.BLT_0WAY,
            succs=tuple(succs),
            preds=tuple(preds),
            flags=0,
            start_ea=0x401000 + serial,
            insn_snapshots=(),
        )

    flow_graph = FlowGraph(
        blocks={
            2: _snapshot(2, (3,), (1, 5)),
            3: _snapshot(3, (4, 12), (2, 10, 11)),
            5: _snapshot(5, (2,), (4, 10)),
            7: _snapshot(7, (8, 9), (6, 2)),
            8: _snapshot(8, (10,), (7,)),
            9: _snapshot(9, (10,), (7,)),
            10: _snapshot(10, (3,), (8, 9)),
            11: _snapshot(11, (3,), (6,)),
            12: _snapshot(12, (), (3, 9)),
        },
        entry_serial=2,
        func_ea=0x401000,
    )
    artifact = EmulatedDispatcherPhaseArtifact(
        dispatcher_entry_serial=3,
        state_var_stkoff=4,
        pre_header_serial=8,
        initial_state=0xF6A1E,
        bst_node_blocks=(3, 4, 6),
        handler_state_map=((5, 0xF6A20), (7, 0xF6A1F), (12, 0xF6A25)),
        semantic_reference_variant="semantic_reference_like",
        semantic_state_labels=("0x000F6A1E", "0x000F6A1F", "0x000F6A20", "0x000F6A25"),
    )

    def _edge(source_block, branch_arm, source_state, target_state, target_entry, path):
        return SimpleNamespace(
            kind=SimpleNamespace(
                name=(
                    "CONDITIONAL_TRANSITION"
                    if branch_arm is not None
                    else "TRANSITION"
                )
            ),
            source_key=SimpleNamespace(
                state_const=source_state,
                handler_serial=source_block,
            ),
            target_key=SimpleNamespace(
                state_const=target_state,
                handler_serial=target_entry,
            ),
            target_state=target_state,
            target_entry_anchor=target_entry,
            source_anchor=SimpleNamespace(
                block_serial=source_block,
                branch_arm=branch_arm,
            ),
            ordered_path=tuple(path),
            proof_source="state_dispatcher_map",
            last_write_site=(10, 0x40100A) if source_block == 7 else None,
        )

    context = EmulatedDispatcherPhaseContext(
        bst_result=object(),
        transition_result=object(),
        transition_report=object(),
        dag=SimpleNamespace(
            edges=(
                _edge(2, None, 0xF6A1E, 0xF6A1F, 7, (2,)),
                _edge(7, 1, 0xF6A1F, 0xF6A25, 12, (7, 9)),
                _edge(11, None, 0xF6A1E, 0xF6A20, 5, (11,)),
            ),
        ),
        semantic_reference_program=object(),
        predecessor_dispatcher_target_facts=(),
    )
    monkeypatch.setattr(
        emulated_family_module,
        "_extract_state_from_block",
        lambda *_args, **_kwargs: pytest.fail("last_write_site should avoid path rescans"),
    )
    monkeypatch.setattr(
        emulated_family_module,
        "_return_carrier_preservation_blockers",
        lambda **_kwargs: (),
    )
    mba = SimpleNamespace(
        get_mblock=lambda serial: SimpleNamespace(serial=int(serial)),
    )

    family = EmulatedDispatcherStrategyFamily(
        profile=ollvm_state_dispatcher_map_profile(),
    )
    monkeypatch.setattr(
        family,
        "_build_live_state_write_recovery",
        lambda **kwargs: (
            RedirectGoto(
                from_serial=int(kwargs["father_serial"]),
                old_target=int(kwargs["dispatcher_entry_serial"]),
                new_target=int(kwargs["target_serial"]),
            ),
        ),
    )
    modifications, blockers, records = (
        family._collect_state_map_loop_recovery_modifications(
            mba=mba,
            snapshot_flow_graph=flow_graph,
            phase_artifact=artifact,
            phase_context=context,
        )
    )

    assert blockers == ()
    assert tuple(family._summarize_modification(mod) for mod in modifications) == (
        "RedirectGoto(2:3->7)",
        "RedirectGoto(10:3->12)",
        "RedirectGoto(11:3->5)",
    )
    assert tuple(record.selection_reason for record in records) == (
        "state_map_dag_edge_source_redirect",
        "state_map_dag_edge_last_write_recovery",
        "state_map_dag_edge_source_redirect",
    )
    assert {record.proof_source for record in records} == {"state_dispatcher_map"}


def test_emulated_dispatcher_family_state_map_loop_recovery_uses_dag_branch_edges(
    monkeypatch,
) -> None:
    def _snapshot(serial, succs, preds):
        return BlockSnapshot(
            serial=serial,
            block_type=ida_hexrays.BLT_2WAY
            if len(succs) == 2
            else ida_hexrays.BLT_1WAY
            if succs
            else ida_hexrays.BLT_0WAY,
            succs=tuple(succs),
            preds=tuple(preds),
            flags=0,
            start_ea=0x402000 + serial,
            insn_snapshots=(),
        )

    flow_graph = FlowGraph(
        blocks={
            3: _snapshot(3, (4,), (5, 6)),
            4: _snapshot(4, (5,), (3,)),
            5: _snapshot(5, (6, 3), (4,)),
            6: _snapshot(6, (3,), (5,)),
            9: _snapshot(9, (), (6,)),
            12: _snapshot(12, (), (5,)),
        },
        entry_serial=3,
        func_ea=0x402000,
    )
    artifact = EmulatedDispatcherPhaseArtifact(
        dispatcher_entry_serial=3,
        state_var_stkoff=4,
        pre_header_serial=4,
        initial_state=0x100,
        bst_node_blocks=(3,),
        handler_state_map=((9, 0x200), (12, 0x300)),
        semantic_reference_variant="semantic_reference_like",
        semantic_state_labels=("0x00000100", "0x00000200", "0x00000300"),
    )

    def _fact(pred, state, target, source_state=0x100):
        return PredecessorDispatcherTargetFact(
            fact_id=f"fact:{pred}:{state}:{target}",
            predecessor_block_serial=pred,
            dispatcher_entry_serial=3,
            state_const=state,
            target_block_serial=target,
            resolver_kind="state_dispatcher_map_exact_row",
            row_kind="handler",
            source_state_const=source_state,
            transition_provenance_kind="state_dag_conditional_transition",
            state_var_stkoff=4,
        )

    def _edge(source_block, branch_arm, source_state, target_state, target_entry):
        return SimpleNamespace(
            kind=SimpleNamespace(name="CONDITIONAL_TRANSITION"),
            source_key=SimpleNamespace(state_const=source_state, handler_serial=5),
            target_key=SimpleNamespace(state_const=target_state, handler_serial=target_entry),
            target_state=target_state,
            target_entry_anchor=target_entry,
            source_anchor=SimpleNamespace(
                block_serial=source_block,
                branch_arm=branch_arm,
            ),
            ordered_path=(source_block, 6 if branch_arm == 0 else target_entry),
        )

    context = EmulatedDispatcherPhaseContext(
        bst_result=object(),
        transition_result=object(),
        transition_report=object(),
        dag=SimpleNamespace(
            edges=(
                _edge(5, 0, 0x100, 0x200, 9),
                _edge(5, 1, 0x100, 0x300, 12),
            ),
        ),
        semantic_reference_program=object(),
        predecessor_dispatcher_target_facts=(
            _fact(5, 0x200, 9),
        ),
    )
    monkeypatch.setattr(
        emulated_family_module,
        "_extract_state_from_block",
        lambda blk, *_args, **_kwargs: 0x200
        if int(getattr(blk, "serial", -1)) == 6
        else None,
    )
    monkeypatch.setattr(
        emulated_family_module,
        "_return_carrier_preservation_blockers",
        lambda **_kwargs: (),
    )
    mba = SimpleNamespace(
        get_mblock=lambda serial: SimpleNamespace(
            serial=int(serial),
            nsucc=lambda: 2 if int(serial) == 5 else 1,
        ),
    )

    family = EmulatedDispatcherStrategyFamily(
        profile=ollvm_state_dispatcher_map_profile(),
    )
    monkeypatch.setattr(
        family,
        "_build_live_state_write_recovery",
        lambda **kwargs: (
            RedirectGoto(
                from_serial=int(kwargs["father_serial"]),
                old_target=int(kwargs["dispatcher_entry_serial"]),
                new_target=int(kwargs["target_serial"]),
            ),
        ),
    )
    modifications, blockers, records = (
        family._collect_state_map_loop_recovery_modifications(
            mba=mba,
            snapshot_flow_graph=flow_graph,
            phase_artifact=artifact,
            phase_context=context,
        )
    )

    assert blockers == ()
    assert "RedirectGoto(6:3->9)" in {
        family._summarize_modification(mod) for mod in modifications
    }
    branch_redirects = tuple(
        mod for mod in modifications if isinstance(mod, RedirectBranch)
    )
    assert len(branch_redirects) == 1
    assert branch_redirects[0].from_serial == 5
    assert branch_redirects[0].old_target == 3
    assert branch_redirects[0].new_target == 12
    assert {
        record.selection_reason for record in records
    } == {
        "state_map_dag_edge_state_write_recovery",
        "state_map_dag_edge_dispatcher_arm_redirect",
    }


def test_loop_recovery_edge_selection_abstains_on_ambiguous_anchor() -> None:
    def _edge(target_state, target_entry):
        return SimpleNamespace(
            kind=SimpleNamespace(name="TRANSITION"),
            source_key=SimpleNamespace(state_const=0x100, handler_serial=5),
            target_key=SimpleNamespace(
                state_const=target_state,
                handler_serial=target_entry,
            ),
            target_state=target_state,
            target_entry_anchor=target_entry,
            source_anchor=SimpleNamespace(block_serial=5, branch_arm=None),
            ordered_path=(5,),
            proof_source="state_dispatcher_map",
        )

    selected, blockers = select_loop_recovery_edges(
        StateDagIndex.from_dag(
            SimpleNamespace(edges=(_edge(0x200, 9), _edge(0x300, 12)))
        )
    )

    assert selected == ()
    assert blockers == ("dispatcher_loop_recovery_ambiguous_dag_edges",)


def test_loop_recovery_edge_selection_reports_mixed_ambiguity() -> None:
    def _edge(source, target_state, target_entry):
        return SimpleNamespace(
            kind=SimpleNamespace(name="TRANSITION"),
            source_key=SimpleNamespace(state_const=0x100, handler_serial=source),
            target_key=SimpleNamespace(
                state_const=target_state,
                handler_serial=target_entry,
            ),
            target_state=target_state,
            target_entry_anchor=target_entry,
            source_anchor=SimpleNamespace(block_serial=source, branch_arm=None),
            ordered_path=(source,),
            proof_source="state_dispatcher_map",
        )

    selected, blockers = select_loop_recovery_edges(
        StateDagIndex.from_dag(
            SimpleNamespace(
                edges=(
                    _edge(5, 0x200, 9),
                    _edge(5, 0x300, 12),
                    _edge(6, 0x400, 14),
                )
            )
        )
    )

    assert tuple(plan.source_block for plan in selected) == (6,)
    assert blockers == ("dispatcher_loop_recovery_ambiguous_dag_edges",)


def test_state_map_loop_recovery_requires_dispatcher_edge_for_write_site() -> None:
    def _snapshot(serial, succs, preds):
        return BlockSnapshot(
            serial=serial,
            block_type=ida_hexrays.BLT_1WAY if succs else ida_hexrays.BLT_0WAY,
            succs=tuple(succs),
            preds=tuple(preds),
            flags=0,
            start_ea=0x403000 + serial,
            insn_snapshots=(),
        )

    flow_graph = FlowGraph(
        blocks={
            3: _snapshot(3, (9,), ()),
            6: _snapshot(6, (10,), ()),
            9: _snapshot(9, (), (3,)),
            10: _snapshot(10, (), (6,)),
        },
        entry_serial=3,
        func_ea=0x403000,
    )
    artifact = EmulatedDispatcherPhaseArtifact(
        dispatcher_entry_serial=3,
        state_var_stkoff=4,
        handler_state_map=((9, 0x200),),
        semantic_reference_variant="semantic_reference_like",
        semantic_state_labels=("0x100", "0x200"),
    )
    edge = SimpleNamespace(
        kind=SimpleNamespace(name="TRANSITION"),
        source_key=SimpleNamespace(state_const=0x100, handler_serial=6),
        target_key=SimpleNamespace(state_const=0x200, handler_serial=9),
        target_state=0x200,
        target_entry_anchor=9,
        source_anchor=SimpleNamespace(block_serial=6, branch_arm=None),
        ordered_path=(6,),
        last_write_site=(6, 0x403006),
    )
    context = EmulatedDispatcherPhaseContext(
        bst_result=object(),
        transition_result=object(),
        transition_report=object(),
        dag=SimpleNamespace(edges=(edge,)),
        semantic_reference_program=object(),
    )

    family = EmulatedDispatcherStrategyFamily(
        profile=ollvm_state_dispatcher_map_profile(),
    )
    modifications, blockers, records = (
        family._collect_state_map_loop_recovery_modifications(
            mba=SimpleNamespace(),
            snapshot_flow_graph=flow_graph,
            phase_artifact=artifact,
            phase_context=context,
        )
    )

    assert modifications == ()
    assert blockers == ("dispatcher_loop_recovery_predecessor_not_dispatcher_edge",)
    assert records == ()


def test_state_map_loop_recovery_records_mixed_ambiguous_edges_as_partial(
    monkeypatch,
) -> None:
    def _snapshot(serial, succs, preds):
        return BlockSnapshot(
            serial=serial,
            block_type=ida_hexrays.BLT_1WAY if succs else ida_hexrays.BLT_0WAY,
            succs=tuple(succs),
            preds=tuple(preds),
            flags=0,
            start_ea=0x404000 + serial,
            insn_snapshots=(),
        )

    flow_graph = FlowGraph(
        blocks={
            3: _snapshot(3, (14,), (6,)),
            5: _snapshot(5, (3,), ()),
            6: _snapshot(6, (3,), ()),
            9: _snapshot(9, (), ()),
            12: _snapshot(12, (), ()),
            14: _snapshot(14, (), (3,)),
        },
        entry_serial=3,
        func_ea=0x404000,
    )
    artifact = EmulatedDispatcherPhaseArtifact(
        dispatcher_entry_serial=3,
        state_var_stkoff=4,
        handler_state_map=((9, 0x200),),
        semantic_reference_variant="semantic_reference_like",
        semantic_state_labels=("0x100", "0x200"),
    )

    def _edge(source, target_state, target_entry):
        return SimpleNamespace(
            kind=SimpleNamespace(name="TRANSITION"),
            source_key=SimpleNamespace(state_const=0x100, handler_serial=source),
            target_key=SimpleNamespace(
                state_const=target_state,
                handler_serial=target_entry,
            ),
            target_state=target_state,
            target_entry_anchor=target_entry,
            source_anchor=SimpleNamespace(block_serial=source, branch_arm=None),
            ordered_path=(source,),
            proof_source="state_dispatcher_map",
        )

    context = EmulatedDispatcherPhaseContext(
        bst_result=object(),
        transition_result=object(),
        transition_report=object(),
        dag=SimpleNamespace(
            edges=(
                _edge(5, 0x200, 9),
                _edge(5, 0x300, 12),
                _edge(6, 0x400, 14),
            )
        ),
        semantic_reference_program=object(),
    )
    family = EmulatedDispatcherStrategyFamily(
        cfg_translator=SimpleNamespace(lift=lambda _mba: flow_graph),
        profile=ollvm_state_dispatcher_map_profile(),
    )
    monkeypatch.setattr(
        emulated_family_module,
        "_return_carrier_preservation_blockers",
        lambda **_kwargs: (),
    )
    monkeypatch.setattr(
        family,
        "_build_phase_artifact",
        lambda *_args, **_kwargs: (artifact, context),
    )
    monkeypatch.setattr(
        family,
        "_collect_lowering_candidates",
        lambda *_args, **_kwargs: ((), (), ()),
    )
    monkeypatch.setattr(
        family,
        "_collect_phase_reconstruction_modifications",
        lambda *_args, **_kwargs: ((), ()),
    )
    snapshot = family.build_snapshot(
        SimpleNamespace(
            qty=1,
            maturity=ida_hexrays.MMAT_GLBOPT1,
            entry_ea=0x404000,
            get_mblock=lambda _serial: SimpleNamespace(nsucc=lambda: 0),
            for_all_topinsns=lambda collector: None,
        ),
        EmulatedDispatcherDetection(
            analysis_dispatchers=(3,),
            dispatcher_shape="conditional_chain",
            state_transport="state_dispatcher_map",
            lowering_mode="generic_graph_modifications",
            provenance_hints=("equality_chain",),
            state_constants=(0x100, 0x200, 0x300, 0x400),
            collector_dispatcher_entries=(),
        ),
    )

    metadata = extract_emulated_dispatcher_metadata(snapshot.flow_graph)
    assert metadata is not None
    assert metadata.planning_ready is True
    assert metadata.selected_lowering_mode == "dispatcher_loop_recovery"
    assert metadata.rejection_reasons == ()
    assert metadata.partial_rewrite_reasons == (
        "dispatcher_loop_recovery_ambiguous_dag_edges",
    )
    assert metadata.is_partial is True
    assert extract_emulated_dispatcher_modifications(snapshot.flow_graph) == (
        RedirectGoto(from_serial=6, old_target=3, new_target=14),
    )


def test_state_map_loop_recovery_defers_locopt_from_dag_edges(monkeypatch) -> None:
    flow_graph = _flow_graph_with_edge()
    artifact = EmulatedDispatcherPhaseArtifact(
        dispatcher_entry_serial=3,
        state_var_stkoff=4,
        handler_state_map=((9, 0x200),),
        semantic_reference_variant="semantic_reference_like",
        semantic_state_labels=("0x100", "0x200"),
    )
    edge = SimpleNamespace(
        kind=SimpleNamespace(name="TRANSITION"),
        source_key=SimpleNamespace(state_const=0x100, handler_serial=6),
        target_key=SimpleNamespace(state_const=0x200, handler_serial=9),
        target_state=0x200,
        target_entry_anchor=9,
        source_anchor=SimpleNamespace(block_serial=6, branch_arm=None),
        ordered_path=(6,),
        proof_source="state_dispatcher_map",
    )
    context = EmulatedDispatcherPhaseContext(
        bst_result=object(),
        transition_result=object(),
        transition_report=object(),
        dag=SimpleNamespace(edges=(edge,)),
        semantic_reference_program=object(),
        predecessor_dispatcher_target_facts=(),
    )
    family = EmulatedDispatcherStrategyFamily(
        cfg_translator=SimpleNamespace(lift=lambda _mba: flow_graph),
        profile=ollvm_state_dispatcher_map_profile(),
    )
    monkeypatch.setattr(
        family,
        "_build_phase_artifact",
        lambda *_args, **_kwargs: (artifact, context),
    )
    monkeypatch.setattr(
        family,
        "_collect_lowering_candidates",
        lambda *_args, **_kwargs: ((), (), ()),
    )
    monkeypatch.setattr(
        family,
        "_collect_phase_reconstruction_modifications",
        lambda *_args, **_kwargs: (
            (RedirectGoto(from_serial=0, old_target=1, new_target=2),),
            (),
        ),
    )

    snapshot = family.build_snapshot(
        SimpleNamespace(
            qty=1,
            maturity=ida_hexrays.MMAT_LOCOPT,
            entry_ea=0x401000,
            get_mblock=lambda _serial: SimpleNamespace(nsucc=lambda: 0),
            for_all_topinsns=lambda collector: None,
        ),
        EmulatedDispatcherDetection(
            analysis_dispatchers=(3,),
            dispatcher_shape="conditional_chain",
            state_transport="state_dispatcher_map",
            lowering_mode="generic_graph_modifications",
            provenance_hints=("equality_chain",),
            state_constants=(0x100, 0x200),
            collector_dispatcher_entries=(),
        ),
    )

    metadata = extract_emulated_dispatcher_metadata(snapshot.flow_graph)
    assert metadata is not None
    assert metadata.planning_ready is False
    assert metadata.planning_blocker == "state_map_loop_recovery_deferred_to_glbopt1"
    assert metadata.selected_lowering_mode == "generic_graph_modifications"
    assert extract_emulated_dispatcher_modifications(snapshot.flow_graph) == ()


def test_tigress_indirect_phase_reconstruction_allowed_at_locopt() -> None:
    family = EmulatedDispatcherStrategyFamily(
        profile=tigress_indirect_dispatcher_profile(),
    )
    detection = EmulatedDispatcherDetection(
        dispatcher_shape="indirect_jump",
        state_transport="state_dispatcher_map",
        lowering_mode="indirect_jump_table_diagnostics",
        state_dispatcher_entries=(16,),
    )

    assert family._phase_reconstruction_allowed(
        SimpleNamespace(maturity=ida_hexrays.MMAT_LOCOPT),
        detection,
    )


def test_state_map_switch_reconstruction_waits_until_glbopt() -> None:
    family = EmulatedDispatcherStrategyFamily(
        profile=ollvm_state_dispatcher_map_profile(),
    )
    detection = EmulatedDispatcherDetection(
        dispatcher_shape="switch_table",
        state_transport="state_dispatcher_map",
        lowering_mode="generic_graph_modifications",
        state_dispatcher_entries=(2,),
    )

    assert not family._phase_reconstruction_allowed(
        SimpleNamespace(maturity=ida_hexrays.MMAT_CALLS),
        detection,
    )
    assert family._phase_reconstruction_allowed(
        SimpleNamespace(maturity=ida_hexrays.MMAT_GLBOPT1),
        detection,
    )


def test_tigress_indirect_blocks_coalesced_dispatcher_handler_row() -> None:
    family = EmulatedDispatcherStrategyFamily(
        profile=tigress_indirect_dispatcher_profile(),
    )
    dispatch_map = StateDispatcherMap(
        rows=(
            StateDispatcherRow(
                state_const=0x23,
                target_block=11,
                dispatcher_block=11,
                compare_block=None,
                branch_kind="indirect_jump_table",
                source=DispatcherType.INDIRECT_JUMP,
            ),
        ),
        dispatcher_entry_block=11,
        dispatcher_blocks=frozenset({11}),
        state_var_stkoff=0x30,
        state_var_lvar_idx=None,
        source=DispatcherType.INDIRECT_JUMP,
        initial_state=0x22,
    )
    artifact = EmulatedDispatcherPhaseArtifact(
        dispatcher_entry_serial=11,
        state_var_stkoff=0x30,
        pre_header_serial=0,
        initial_state=0x22,
        handler_state_map=((11, 0x23),),
        semantic_reference_variant="semantic_reference_like",
    )
    context = EmulatedDispatcherPhaseContext(
        bst_result=object(),
        transition_result=object(),
        transition_report=object(),
        dag=SimpleNamespace(edges=()),
        semantic_reference_program=object(),
        state_dispatcher_map=dispatch_map,
    )

    modifications, blockers = family._collect_phase_reconstruction_modifications(
        mba=_fake_mba(),
        flow_graph=_flow_graph(),
        detection=EmulatedDispatcherDetection(
            dispatcher_shape="indirect_jump",
            state_transport="state_dispatcher_map",
            lowering_mode="indirect_jump_table_diagnostics",
        ),
        phase_artifact=artifact,
        phase_context=context,
    )

    assert modifications == ()
    assert blockers == (
        "phase_reconstruction_indirect_handler_coalesced_with_dispatcher",
    )


@pytest.mark.parametrize(
    ("edge_kind", "edge_target_state"),
    (
        (SemanticEdgeKind.CONDITIONAL_RETURN, None),
        (SemanticEdgeKind.TRANSITION, 0x1B),
    ),
)
def test_tigress_indirect_repairs_terminal_state_write_stub(
    edge_kind,
    edge_target_state,
) -> None:
    state_write = InsnSnapshot(
        opcode=ida_hexrays.m_mov,
        ea=0x180017719,
        operands=(),
        l=MopSnapshot(
            t=ida_hexrays.mop_n,
            size=4,
            value=0x1B,
        ),
        d=MopSnapshot(
            t=ida_hexrays.mop_S,
            size=4,
            stkoff=0x30,
        ),
    )
    flow_graph = FlowGraph(
        blocks={
            9: BlockSnapshot(
                serial=9,
                block_type=ida_hexrays.BLT_1WAY,
                succs=(10,),
                preds=(18,),
                flags=0,
                start_ea=0x180017711,
                insn_snapshots=(state_write,),
            ),
            10: BlockSnapshot(
                serial=10,
                block_type=ida_hexrays.BLT_0WAY,
                succs=(),
                preds=(9,),
                flags=0,
                start_ea=0x18001772F,
                insn_snapshots=(),
            ),
            27: BlockSnapshot(
                serial=27,
                block_type=ida_hexrays.BLT_1WAY,
                succs=(16,),
                preds=(),
                flags=0,
                start_ea=0x18001790B,
                insn_snapshots=(),
            ),
        },
        entry_serial=9,
        func_ea=0x1800175C0,
    )
    dispatch_map = StateDispatcherMap(
        rows=(
            StateDispatcherRow(
                state_const=0x1B,
                target_block=27,
                dispatcher_block=16,
                compare_block=None,
                branch_kind="indirect_jump_table",
                source=DispatcherType.INDIRECT_JUMP,
            ),
        ),
        dispatcher_entry_block=16,
        dispatcher_blocks=frozenset({16}),
        state_var_stkoff=0x30,
        state_var_lvar_idx=None,
        source=DispatcherType.INDIRECT_JUMP,
        initial_state=0x22,
    )
    edge = SimpleNamespace(
        kind=edge_kind,
        target_state=edge_target_state,
        ordered_path=(9, 10),
    )

    modifications = (
        emulated_family_module
        ._collect_tigress_indirect_terminal_stub_modifications(
            dag=SimpleNamespace(edges=(edge,)),
            flow_graph=flow_graph,
            dispatch_map=dispatch_map,
            state_var_stkoff=0x30,
            constant_result=SimpleNamespace(in_stk_maps={}, in_reg_maps={}),
        )
    )

    assert modifications == (
        RedirectGoto(
            from_serial=9,
            old_target=10,
            new_target=27,
        ),
    )


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
        state_transport="state_dispatcher_map",
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
        state_transport="state_dispatcher_map",
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
        state_transport="state_dispatcher_map",
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
        state_transport="state_dispatcher_map",
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
        state_transport="state_dispatcher_map",
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
        state_transport="state_dispatcher_map",
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
        state_transport="state_dispatcher_map",
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
                    state_transport="state_dispatcher_map",
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
        "state_transport": "state_dispatcher_map",
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
        "partial_rewrite_reasons": (),
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
                    state_transport="state_dispatcher_map",
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


def test_emulated_dispatcher_strategy_plans_scalar_promotions() -> None:
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
                    dispatcher_shape="conditional_chain",
                    state_transport="state_dispatcher_map",
                    lowering_mode="semantic_carrier_hoist",
                    provenance_hints=("equality_chain",),
                    analysis_dispatchers=(7,),
                    collector_dispatchers=(),
                    planning_ready=True,
                    planning_blocker=None,
                    candidate_count=1,
                    rejected_fathers=0,
                    candidate_kinds=("PromoteOperandToScalar",),
                    rejection_reasons=(),
                    selected_lowering_mode="semantic_carrier_hoist",
                    selected_modification_count=1,
                ),
                EMULATED_DISPATCHER_MODIFICATIONS_KEY: (
                    PromoteOperandToScalar(
                        block_serial=0,
                        host_ea=0x401000,
                        host_opcode=ida_hexrays.m_stx,
                        operand_side="l",
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

    fragment = strategy.plan(snapshot)

    assert fragment is not None
    assert fragment.strategy_name == "emulated_dispatcher"
    assert fragment.modifications == [
        PromoteOperandToScalar(
            block_serial=0,
            host_ea=0x401000,
            host_opcode=ida_hexrays.m_stx,
            operand_side="l",
        ),
    ]


def test_emulated_dispatcher_strategy_rejects_partial_lowering_when_blockers_exist() -> None:
    graph = FlowGraph(
        blocks=_flow_graph_with_edge().blocks,
        entry_serial=0,
        func_ea=0x401000,
        metadata={
            EMULATED_DISPATCHER_METADATA_KEY: EmulatedDispatcherMetadata(
                dispatcher_shape="unknown",
                state_transport="state_dispatcher_map",
                lowering_mode="generic_graph_modifications",
                provenance_hints=(),
                analysis_dispatchers=(7,),
                collector_dispatchers=(2,),
                planning_ready=False,
                planning_blocker="dispatcher_state_values_missing",
                candidate_count=1,
                rejected_fathers=1,
                candidate_kinds=("RedirectGoto",),
                rejection_reasons=("dispatcher_state_values_missing",),
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
                    state_transport="state_dispatcher_map",
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
            state_transport="state_dispatcher_map",
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
                    state_transport="state_dispatcher_map",
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
        "d810.optimizers.microcode.flow.flattening.emulated_dispatcher_family.DeferredGraphModifier.run_deep_cleaning",
        lambda _self, **_kwargs: calls.append(("deep_clean", None)) or 0,
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


def test_emulated_dispatcher_family_records_dispatcher_loop_recovery_root() -> None:
    family = EmulatedDispatcherStrategyFamily()
    mba = SimpleNamespace(entry_ea=0x401000, maturity=ida_hexrays.MMAT_GLBOPT1)
    phase_artifact = EmulatedDispatcherPhaseArtifact(
        dispatcher_entry_serial=3,
        state_var_stkoff=0x20,
        pre_header_serial=8,
        initial_state=0xF6A1E,
        semantic_reference_variant="semantic_reference_like",
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
                    dispatcher_shape="conditional_chain",
                    state_transport="state_dispatcher_map",
                    lowering_mode="dispatcher_loop_recovery",
                    provenance_hints=("equality_chain",),
                    analysis_dispatchers=(3,),
                    collector_dispatchers=(),
                    planning_ready=True,
                    planning_blocker=None,
                    candidate_count=1,
                    rejected_fathers=0,
                    candidate_kinds=("InsertBlock",),
                    rejection_reasons=(),
                    phase_artifact=phase_artifact,
                    selected_lowering_mode="dispatcher_loop_recovery",
                ),
            },
        ),
        state_summary=StateModelSummary(
            state_constants=frozenset(),
            handler_count=1,
            transition_count=0,
        ),
    )

    family.record_executed_phase_reconstruction(
        mba=mba,
        snapshot=snapshot,
        total_changes=1,
    )

    assert family._phase_reconstruction_root_key(  # noqa: SLF001
        mba=mba,
        phase_artifact=phase_artifact,
    ) in family._executed_phase_reconstruction_roots  # noqa: SLF001


def test_state_map_loop_recovery_abstains_for_consumed_root() -> None:
    family = EmulatedDispatcherStrategyFamily(
        profile=ollvm_state_dispatcher_map_profile(),
    )
    mba = SimpleNamespace(entry_ea=0x401000, maturity=ida_hexrays.MMAT_GLBOPT1)
    phase_artifact = EmulatedDispatcherPhaseArtifact(
        dispatcher_entry_serial=3,
        state_var_stkoff=0x20,
        pre_header_serial=8,
        initial_state=0xF6A1E,
        semantic_reference_variant="semantic_reference_like",
    )
    family._executed_phase_reconstruction_roots.add(  # noqa: SLF001
        family._phase_reconstruction_root_key(  # noqa: SLF001
            mba=mba,
            phase_artifact=phase_artifact,
        )
    )

    modifications, blockers, records = (
        family._collect_state_map_loop_recovery_modifications(  # noqa: SLF001
            mba=mba,
            snapshot_flow_graph=_flow_graph_with_edge(),
            phase_artifact=phase_artifact,
            phase_context=SimpleNamespace(),
        )
    )

    assert modifications == ()
    assert blockers == ("dispatcher_loop_recovery_root_already_consumed",)
    assert records == ()


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
                    state_transport="state_dispatcher_map",
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
        "d810.optimizers.microcode.flow.flattening.emulated_dispatcher_family.DeferredGraphModifier.run_deep_cleaning",
        lambda _self, **_kwargs: calls.append(("deep_clean", None)) or 0,
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
        state_transport="state_dispatcher_map",
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
                    state_transport="state_dispatcher_map",
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

    def test_tigress_minmaxarray_transition_fact_validation_selects_mode(
        self,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        monkeypatch,
    ) -> None:
        func_ea = get_func_ea("tigress_minmaxarray")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'tigress_minmaxarray' not found")

        captured: dict[str, object] = {}
        original_build_snapshot = EmulatedDispatcherStrategyFamily.build_snapshot

        def _wrapped_build_snapshot(self, mba, detection):
            snapshot = original_build_snapshot(self, mba, detection)
            metadata = extract_emulated_dispatcher_metadata(snapshot.flow_graph)
            if metadata is not None and (
                metadata.selected_lowering_mode == "tigress_switch_transition_facts"
                or metadata.selected_modification_count
                > int(captured.get("selected_modification_count", -1))
            ):
                captured["selected_modification_count"] = (
                    metadata.selected_modification_count
                )
                captured["snapshot"] = asdict(metadata)
            return snapshot

        monkeypatch.setattr(
            EmulatedDispatcherStrategyFamily,
            "build_snapshot",
            _wrapped_build_snapshot,
        )

        project_name = "default_unflattening_tigress_engine_transition_facts.json"
        with d810_state() as state:
            state.stop_d810()
            project_index = _resolve_test_project_index(state, project_name)
            state.load_project(project_index)
            with state.for_project(project_name) as ctx:
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
                    state,
                    ctx,
                    func_ea,
                )
                try:
                    cfunc = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
                    assert cfunc is not None
                    rendered = pseudocode_to_string(cfunc.get_pseudocode())
                finally:
                    _restore_forced_rule_scope(state, func_ea, previous_override)
            state.stop_d810()

        snapshot = captured.get("snapshot")
        assert snapshot is not None
        assert snapshot["selected_lowering_mode"] == "tigress_switch_transition_facts"
        assert snapshot["planning_ready"] is True
        assert snapshot["selected_modification_count"] >= 18
        assert "for (" in rendered

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
        assert observed["total_changes_after_execute"] > 0
        assert observed["cleanup_total_changes"] == observed["total_changes_after_execute"]
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
        assert observed["total_changes_after_execute"] > 0
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
            if metadata is not None and metadata.selected_modification_count > int(
                captured.get("selected_modification_count", -1)
            ):
                captured["candidate_count"] = metadata.candidate_count
                captured["selected_modification_count"] = (
                    metadata.selected_modification_count
                )
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
        print("APPROOV_MULTISTATE_METADATA", snapshot)
        print("APPROOV_MULTISTATE_CANDIDATE_RECORDS", candidate_records)
        assert snapshot["candidate_count"] == len(candidate_records)
        assert snapshot["selected_modification_count"] > 0
        assert snapshot["rejected_fathers"] == 0
        assert snapshot["selected_lowering_mode"] in {
            "generic_graph_modifications",
            "dispatcher_loop_recovery",
            "state_region_reconstruction",
        }
        assert selected_indexes == tuple(range(snapshot["candidate_count"]))
        if snapshot["selected_lowering_mode"] == "dispatcher_loop_recovery":
            assert snapshot["selected_modification_count"] == len(candidate_records) == 6
            assert set(snapshot["candidate_kinds"]) == {"InsertBlock"}

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
        assert artifact["dag_node_count"] == 4
        assert artifact["dag_edge_count"] == 7
        assert artifact["semantic_reference_variant"] == "semantic_reference_like"
        assert artifact["semantic_reference_line_count"] >= 20
        assert artifact["semantic_reference_node_count"] == 4
        assert "STATE_000F6A1F:" in artifact["semantic_reference_program"]
        assert "STATE_000F6A1E:" in artifact["semantic_reference_program"]
        assert "0x000F6A20" in artifact["semantic_state_labels"]
        assert "STATE_000F6A20:" in artifact["semantic_reference_program"]
        assert "goto STATE_000F6A1E;" in artifact["semantic_reference_program"]
        assert "goto STATE_000F6A1F;" in artifact["semantic_reference_program"]

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
                and metadata.selected_modification_count
                >= int(captured.get("selected_modification_count", -1))
            ):
                captured["candidate_count"] = metadata.candidate_count
                captured["selected_modification_count"] = (
                    metadata.selected_modification_count
                )
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
        assert snapshot["state_transport"] == "state_dispatcher_map"
        assert snapshot["selected_lowering_mode"] in {
            "generic_graph_modifications",
            "state_region_reconstruction",
        }
        assert snapshot["loop_recovery_modification_count"] == 0
        assert snapshot["planning_ready"] is True
        assert snapshot["selected_modification_count"] > 0
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
            (14, 15, ("InsertBlock",)),
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

    def test_approov_multistate_cluster_grouping_engine_contract(
        self,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
        monkeypatch,
    ) -> None:
        assert code_comparator is not None, (
            "libclang required for cluster grouping engine contract"
        )
        func_ea = get_func_ea("approov_multistate")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'approov_multistate' not found")

        def _run_engine() -> tuple[str, dict[str, object]]:
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

            def _wrapped_execute(snapshot, planned, **kwargs):
                executed = original_execute(snapshot, planned, **kwargs)
                captured["candidate_records"] = tuple(
                    asdict(record)
                    for record in extract_emulated_dispatcher_candidate_records(
                        snapshot.flow_graph
                    )
                )
                captured["post_execute_flow_graph"] = lift_mba(snapshot.mba)
                return executed

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

        current_code, current_capture = _run_engine()

        current_payloads = tuple(
            tuple(record["payload_signature"])
            for record in current_capture["candidate_records"]
            if record["cluster_candidate"]
        )
        current_shape = _summarize_cfg_shape(
            current_capture["final_flow_graph"],
            payload_signatures=current_payloads,
        )
        cluster_groups: dict[tuple[str, ...], list[int]] = {}
        for record in current_capture["candidate_records"]:
            if record["cluster_candidate"]:
                cluster_groups.setdefault(record["cluster_key"], []).append(
                    record["father_serial"]
                )

        summary = {
            "ast": code_comparator.count_ast_statements(current_code),
            "shape": current_shape,
            "cluster_groups": {
                key: tuple(sorted(value)) for key, value in cluster_groups.items()
            },
            "code": current_code,
        }
        print("APPROOV_MULTISTATE_CLUSTER_GROUPING_ENGINE_CONTRACT", summary)

        assert current_capture["candidate_records"]
        assert current_shape["payload_blocks"]
        assert sorted(
            tuple(sorted(fathers)) for fathers in cluster_groups.values()
        ) == [(2, 6), (7, 11)]

    def test_approov_multistate_handler_subgraph_engine_contract(
        self,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
        monkeypatch,
    ) -> None:
        assert code_comparator is not None, (
            "libclang required for handler-subgraph engine contract"
        )
        func_ea = get_func_ea("approov_multistate")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'approov_multistate' not found")

        def _run_engine() -> tuple[str, dict[str, object]]:
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

            def _wrapped_execute(snapshot, planned, **kwargs):
                records = extract_emulated_dispatcher_candidate_records(
                    snapshot.flow_graph
                )
                captured["candidate_records"] = tuple(asdict(record) for record in records)
                captured["phase_role_map"] = _summarize_approov_multistate_phase_roles(
                    records
                )
                return original_execute(snapshot, planned, **kwargs)

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

        current_code, current_capture = _run_engine()

        current_shape = _summarize_cfg_shape(current_capture["final_flow_graph"])

        summary = {
            "phase_role_map": current_capture["phase_role_map"],
            "ast": code_comparator.count_ast_statements(current_code),
            "shape": current_shape,
            "code": current_code,
        }
        print("APPROOV_MULTISTATE_HANDLER_SUBGRAPH_ENGINE_CONTRACT", summary)

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
        from d810.optimizers.microcode.flow.flattening.cleanup_live_evidence import (
            collect_live_fake_jump_fixes,
        )
        from d810.optimizers.microcode.flow.flattening.strategies.fake_jump import (
            FAKE_JUMP_FIXES_METADATA_KEY,
            serialize_fake_jump_fixes,
        )
        from d810.optimizers.microcode.flow.dispatcher.dispatcher_cache import DispatcherCache

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
