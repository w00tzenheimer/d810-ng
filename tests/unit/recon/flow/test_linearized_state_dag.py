from __future__ import annotations

import inspect
import re

import pytest

import d810.analyses.control_flow.linearized_state_dag as linearized_state_dag
from d810.ir.flowgraph import (
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)
from d810.analyses.control_flow.interval_map import IntervalDispatcher, IntervalRow
from d810.analyses.control_flow.linearized_state_dag import (
    BoundaryInlineMode,
    LabelRenderMode,
    LinearizedStateDag,
    LocalSegmentKind,
    LocalEdgeKind,
    ProgramCommentMode,
    ProgramRenderStrategy,
    RenderOrderStrategy,
    RedirectSourceKind,
    SemanticEdgeKind,
    StateDagEdge,
    StateDagNode,
    StateDagNodeKey,
    StateLocalEdge,
    StateLocalSegment,
    StateNodeKind,
    StateRedirectAnchor,
    _compute_alias_label_override,
    _build_state_resolver,
    _normalize_alias_nodes,
    _normalize_nonhandler_exact_nodes,
    _normalize_entry_anchors_to_unique_path_starts,
    _resolve_embedded_exact_owner_override,
    _resolve_exact_cover_anchor,
    _resolve_owner_family_fallback,
    _is_range_backed_only_handoff_anchor,
    _resolve_nonraw_owner_semantic_alias,
    _resolve_nonraw_dispatcher_cover_alias,
    _resolve_semantic_entry_anchor,
    _resolve_prior_supplemental_selected_alias,
    _resolve_selected_supplemental_semantic_alias,
    _select_raw_alias_candidate_anchor,
    _resolve_supplemental_source_family_alias,
    _resolve_sub7ffd_corridor_dispatcher_anchor_override,
    _is_supported_explicit_conditional_transition,
    _state_label_for_transition_row,
    _should_prefer_family_fallback_over_raw_exact,
    build_live_linearized_state_dag_from_graph,
    build_linearized_state_program,
    build_linearized_state_dag_from_graph,
    render_linearized_state_program as _render_linearized_state_program,
    render_linearized_state_dag,
    render_linearized_state_dag_dot,
)
from d810.analyses.control_flow.state_machine_analysis import (
    ConditionalTransition,
    HandlerPathResult,
)
from d810.analyses.control_flow.transition_builder import (
    StateHandler,
    StateTransition,
    TransitionResult,
)
from d810.analyses.control_flow.transition_trust import (
    classify_transition_trust_for_explicit_conditional_bridge,
)
from d810.analyses.control_flow.transition_report import (
    DispatcherTransitionReport,
    TransitionKind,
    TransitionPath,
    TransitionRow,
    TransitionSummary,
    build_dispatcher_transition_report_from_graph,
)


def test_linearized_state_dag_does_not_import_live_hexrays() -> None:
    assert "import ida_hexrays" not in inspect.getsource(linearized_state_dag)


def test_side_effect_detection_uses_portable_instruction_kind() -> None:
    block = BlockSnapshot(
        serial=1,
        block_type=0,
        succs=(),
        preds=(),
        flags=0,
        start_ea=0,
        insn_snapshots=(
            InsnSnapshot(opcode=0, ea=0x401000, operands=(), kind=InsnKind.STORE),
        ),
    )

    assert linearized_state_dag._block_has_side_effect_opcode(block)


def render_linearized_state_program(
    dag: LinearizedStateDag,
    **kwargs,
) -> str:
    program = build_linearized_state_program(dag, **kwargs)
    return _render_linearized_state_program(program)


def test_explicit_conditional_bridge_requires_dynamic_provenance() -> None:
    untagged = StateTransition(
        from_state=0x10,
        to_state=0x20,
        from_block=1,
        condition_block=1,
        is_conditional=True,
        provenance_chain=[(1, 2)],
    )
    dynamic = StateTransition(
        from_state=0x10,
        to_state=0x20,
        from_block=1,
        condition_block=1,
        is_conditional=True,
        provenance_chain=[(1, 2)],
        provenance_kind="global_or_state_write",
    )
    derived_xor = StateTransition(
        from_state=0x10,
        to_state=0x20,
        from_block=1,
        condition_block=1,
        is_conditional=True,
        provenance_chain=[(1, 2)],
        provenance_kind="derived_xor_dispatch_key",
    )

    assert not _is_supported_explicit_conditional_transition(untagged)
    assert _is_supported_explicit_conditional_transition(dynamic)
    assert _is_supported_explicit_conditional_transition(derived_xor)
    untagged_support = (
        classify_transition_trust_for_explicit_conditional_bridge(untagged)
    )
    dynamic_support = (
        classify_transition_trust_for_explicit_conditional_bridge(dynamic)
    )
    derived_support = (
        classify_transition_trust_for_explicit_conditional_bridge(derived_xor)
    )

    assert not untagged_support.authorizes_explicit_conditional_bridge
    assert untagged_support.reason == "unsupported_provenance"
    assert dynamic_support.authorizes_explicit_conditional_bridge
    assert dynamic_support.reason == "dynamic_state_write"
    assert derived_support.authorizes_explicit_conditional_bridge
    assert derived_support.reason == "derived_dispatch_key"


def _make_branch_flow_graph() -> FlowGraph:
    blocks = {
        0: BlockSnapshot(0, 0, (1, 2, 3, 7), (), 0, 0, ()),
        1: BlockSnapshot(1, 0, (0,), (0,), 0, 0, ()),
        2: BlockSnapshot(2, 0, (3, 7), (0,), 0, 0, ()),
        3: BlockSnapshot(3, 0, (4,), (0, 2), 0, 0, ()),
        4: BlockSnapshot(4, 0, (), (3,), 0, 0, ()),
        7: BlockSnapshot(7, 0, (), (0, 2), 0, 0, ()),
    }
    return FlowGraph(blocks=blocks, entry_serial=0, func_ea=0x401000)


def test_resolves_synthetic_alias_to_owner_family_fallback() -> None:
    flow_graph = FlowGraph(
        blocks={
            25: BlockSnapshot(25, 0, (26, 34), (), 0, 0, ()),
            26: BlockSnapshot(26, 0, (), (25,), 0, 0, ()),
            33: BlockSnapshot(33, 0, (), (), 0, 0, ()),
            34: BlockSnapshot(34, 0, (), (25,), 0, 0, ()),
        },
        entry_serial=25,
        func_ea=0x401000,
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=0x64AFC49D,
        condition_chain_blocks=(),
        nodes=(
            StateDagNode(
                key=StateDagNodeKey(handler_serial=26, state_const=0x64AFC49D),
                kind=StateNodeKind.EXACT,
                state_label="0x64AFC49D",
                handler_serial=26,
                entry_anchor=26,
                owned_blocks=(26, 28, 29, 30, 31, 32, 33),
                exclusive_blocks=(26, 28, 29, 30, 31, 33),
                shared_suffix_blocks=(32,),
                local_segments=(
                    StateLocalSegment("blk[26]", LocalSegmentKind.BRANCH, (26,)),
                    StateLocalSegment("blk[33]", LocalSegmentKind.GOTO_LABEL, (33,)),
                ),
                local_edges=(),
            ),
            StateDagNode(
                key=StateDagNodeKey(handler_serial=12, state_const=0x64AFC49D),
                kind=StateNodeKind.EXACT,
                state_label="0x64AFC49D_fallback",
                handler_serial=12,
                entry_anchor=12,
                owned_blocks=(12,),
                exclusive_blocks=(12,),
                shared_suffix_blocks=(),
                local_segments=(),
                local_edges=(),
            ),
            StateDagNode(
                key=StateDagNodeKey(handler_serial=34, state_const=0x64AFC49D),
                kind=StateNodeKind.EXACT,
                state_label="0x64AFC49D_fallback",
                handler_serial=34,
                entry_anchor=34,
                owned_blocks=(34, 35),
                exclusive_blocks=(34, 35),
                shared_suffix_blocks=(),
                local_segments=(),
                local_edges=(),
            ),
        ),
        edges=(),
        diagnostics=(),
    )

    assert _resolve_owner_family_fallback({33}, dag, flow_graph) == (
        34,
        "0x64AFC49D_fallback",
    )


def test_resolves_supplemental_source_family_alias_to_fallback_edge() -> None:
    dag = LinearizedStateDag(
        dispatcher_entry_serial=0,
        state_var_stkoff=None,
        pre_header_serial=None,
        initial_state=0x6107F8EC,
        condition_chain_blocks=(),
        nodes=(
            StateDagNode(
                key=StateDagNodeKey(handler_serial=14, state_const=0x474EEEBB),
                kind=StateNodeKind.EXACT,
                state_label="0x474EEEBB_fallback",
                handler_serial=14,
                entry_anchor=14,
                owned_blocks=(14, 16),
                exclusive_blocks=(14, 16),
                shared_suffix_blocks=(),
                local_segments=(),
                local_edges=(),
            ),
            StateDagNode(
                key=StateDagNodeKey(handler_serial=72, state_const=0x4C77464F),
                kind=StateNodeKind.EXACT,
                state_label="0x4C77464F",
                handler_serial=72,
                entry_anchor=72,
                owned_blocks=(72,),
                exclusive_blocks=(72,),
                shared_suffix_blocks=(),
                local_segments=(),
                local_edges=(),
            ),
        ),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
                source_key=StateDagNodeKey(handler_serial=15, state_const=0x6107F8EC),
                target_key=StateDagNodeKey(handler_serial=14, state_const=0x474EEEBB),
                target_state=0x4C77464F,
                target_entry_anchor=14,
                target_label="0x474EEEBB_fallback",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                    block_serial=15,
                    branch_arm=0,
                ),
                ordered_path=(15, 16),
            ),
            StateDagEdge(
                kind=SemanticEdgeKind.TRANSITION,
                source_key=StateDagNodeKey(handler_serial=71, state_const=0x10743C4C),
                target_key=StateDagNodeKey(handler_serial=72, state_const=0x4C77464F),
                target_state=0x4C77464F,
                target_entry_anchor=72,
                target_label="0x4C77464F",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.UNCONDITIONAL,
                    block_serial=71,
                ),
                ordered_path=(71, 72),
            ),
        ),
        transient_entry_blocks=(),
        supplemental_selected_entries=(),
        diagnostics=(),
    )

    assert _resolve_supplemental_source_family_alias(
        0x4C77464F,
        source_contexts={(15, 16)},
        dag=dag,
        condition_chain_blocks=set(),
    ) == (14, "0x474EEEBB_fallback")


def test_selected_supplemental_semantic_alias_uses_matching_selected_anchor() -> None:
    assert _resolve_selected_supplemental_semantic_alias(
        state_value=0x4C77464F,
        selected_anchor=63,
        source_family_alias=(63, "STATE_474EEEBB"),
    ) == (63, "STATE_474EEEBB")


def test_selected_supplemental_semantic_alias_rejects_raw_label() -> None:
    assert (
        _resolve_selected_supplemental_semantic_alias(
            state_value=0x4C77464F,
            selected_anchor=63,
            source_family_alias=(63, "0x4C77464F"),
        )
        is None
    )


def test_state_label_for_transition_row_preserves_nonraw_semantic_alias() -> None:
    row = TransitionRow(
        state_const=0x4C77464F,
        state_range_lo=None,
        state_range_hi=None,
        handler_serial=63,
        kind=TransitionKind.CONDITIONAL,
        next_state=None,
        conditional_states=(0x296F2452, 0x474EEEBB),
        state_label="STATE_474EEEBB",
        transition_label="conditional fallback",
        chain_preview=(15, 16),
        path=TransitionPath(
            handler_serial=63,
            chain=(15, 16),
            next_state=None,
            conditional_states=(0x296F2452, 0x474EEEBB),
            back_edge=False,
            reaches_exit_block=False,
            classified_exit=False,
            unresolved=False,
        ),
    )

    assert _state_label_for_transition_row(
        row,
        node_kind=StateNodeKind.EXACT,
    ) == "STATE_474EEEBB"


def test_state_label_for_range_transition_row_preserves_nonraw_semantic_alias() -> None:
    row = TransitionRow(
        state_const=0x2A5E29F6,
        state_range_lo=0x2A000000,
        state_range_hi=0x2AFFFFFF,
        handler_serial=173,
        kind=TransitionKind.CONDITIONAL,
        next_state=None,
        conditional_states=(0x5FE86821, 0x2E6C61F2),
        state_label="0x2E6C61F2",
        transition_label="conditional fallback",
        chain_preview=(52, 81),
        path=TransitionPath(
            handler_serial=173,
            chain=(52, 81),
            next_state=None,
            conditional_states=(0x5FE86821, 0x2E6C61F2),
            back_edge=False,
            reaches_exit_block=False,
            classified_exit=False,
            unresolved=False,
        ),
    )

    assert _state_label_for_transition_row(
        row,
        node_kind=StateNodeKind.RANGE_BACKED,
    ) == "0x2E6C61F2"


def test_resolves_supplemental_source_family_alias_to_same_state_exact_entry() -> None:
    exact_key = StateDagNodeKey(handler_serial=66, state_const=0x4C77464F)
    dag = LinearizedStateDag(
        dispatcher_entry_serial=0,
        state_var_stkoff=None,
        pre_header_serial=None,
        initial_state=0x6107F8EC,
        condition_chain_blocks=(),
        nodes=(
            StateDagNode(
                key=exact_key,
                kind=StateNodeKind.EXACT,
                state_label="0x4C77464F",
                handler_serial=66,
                entry_anchor=66,
                owned_blocks=(66, 67, 68, 69),
                exclusive_blocks=(66, 67, 68, 69),
                shared_suffix_blocks=(),
                local_segments=(),
                local_edges=(),
            ),
        ),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
                source_key=StateDagNodeKey(handler_serial=15, state_const=0x6107F8EC),
                target_key=exact_key,
                target_state=0x4C77464F,
                target_entry_anchor=66,
                target_label="0x4C77464F",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                    block_serial=15,
                    branch_arm=1,
                ),
                ordered_path=(15, 16),
            ),
        ),
        transient_entry_blocks=(),
        supplemental_selected_entries=(),
        diagnostics=(),
    )

    assert _resolve_supplemental_source_family_alias(
        0x4C77464F,
        source_contexts={(15, 16)},
        dag=dag,
        condition_chain_blocks=set(),
    ) == (66, "0x4C77464F")


def test_resolves_supplemental_source_family_alias_prefers_semantic_alias_over_raw_exact() -> None:
    raw_exact_key = StateDagNodeKey(handler_serial=66, state_const=0x4C77464F)
    dag = LinearizedStateDag(
        dispatcher_entry_serial=0,
        state_var_stkoff=None,
        pre_header_serial=None,
        initial_state=0x6107F8EC,
        condition_chain_blocks=(),
        nodes=(
            StateDagNode(
                key=StateDagNodeKey(handler_serial=14, state_const=0x474EEEBB),
                kind=StateNodeKind.EXACT,
                state_label="0x474EEEBB_fallback",
                handler_serial=14,
                entry_anchor=14,
                owned_blocks=(14,),
                exclusive_blocks=(14,),
                shared_suffix_blocks=(),
                local_segments=(),
                local_edges=(),
            ),
            StateDagNode(
                key=raw_exact_key,
                kind=StateNodeKind.EXACT,
                state_label="0x4C77464F",
                handler_serial=66,
                entry_anchor=66,
                owned_blocks=(66, 67, 68, 69),
                exclusive_blocks=(66, 67, 68, 69),
                shared_suffix_blocks=(),
                local_segments=(),
                local_edges=(),
            ),
        ),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
                source_key=StateDagNodeKey(handler_serial=15, state_const=0x6107F8EC),
                target_key=StateDagNodeKey(handler_serial=14, state_const=0x474EEEBB),
                target_state=0x4C77464F,
                target_entry_anchor=14,
                target_label="0x474EEEBB_fallback",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                    block_serial=15,
                    branch_arm=0,
                ),
                ordered_path=(15, 16),
            ),
            StateDagEdge(
                kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
                source_key=StateDagNodeKey(handler_serial=15, state_const=0x6107F8EC),
                target_key=raw_exact_key,
                target_state=0x4C77464F,
                target_entry_anchor=66,
                target_label="0x4C77464F",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                    block_serial=15,
                    branch_arm=0,
                ),
                ordered_path=(15, 16, 66),
            ),
        ),
        transient_entry_blocks=(),
        supplemental_selected_entries=(),
        diagnostics=(),
    )

    assert _resolve_supplemental_source_family_alias(
        0x4C77464F,
        source_contexts={(15, 16)},
        dag=dag,
        condition_chain_blocks=set(),
    ) == (14, "0x474EEEBB_fallback")


def test_resolves_nonraw_owner_semantic_alias_for_raw_exact_cover_anchor() -> None:
    raw_exact_key = StateDagNodeKey(handler_serial=66, state_const=0x4C77464F)
    dag = LinearizedStateDag(
        dispatcher_entry_serial=0,
        state_var_stkoff=None,
        pre_header_serial=None,
        initial_state=0x6107F8EC,
        condition_chain_blocks=(),
        nodes=(
            StateDagNode(
                key=StateDagNodeKey(handler_serial=63, state_const=0x474EEEBB),
                kind=StateNodeKind.EXACT,
                state_label="0x474EEEBB",
                handler_serial=63,
                entry_anchor=63,
                owned_blocks=(63, 64, 65, 66),
                exclusive_blocks=(63, 64, 65),
                shared_suffix_blocks=(66,),
                local_segments=(),
                local_edges=(),
            ),
            StateDagNode(
                key=raw_exact_key,
                kind=StateNodeKind.EXACT,
                state_label="0x4C77464F",
                handler_serial=66,
                entry_anchor=66,
                owned_blocks=(66, 67, 68, 69),
                exclusive_blocks=(66, 67, 68, 69),
                shared_suffix_blocks=(),
                local_segments=(),
                local_edges=(),
            ),
        ),
        edges=(),
        transient_entry_blocks=(),
        supplemental_selected_entries=(),
        diagnostics=(),
    )

    assert _resolve_nonraw_owner_semantic_alias(
        0x4C77464F,
        anchor_candidates={66, 71},
        dag=dag,
        condition_chain_blocks=set(),
    ) == (63, "0x474EEEBB")


def test_resolves_nonraw_owner_semantic_alias_to_owner_exclusive_head_when_entry_is_seed() -> None:
    dag = LinearizedStateDag(
        dispatcher_entry_serial=0,
        state_var_stkoff=None,
        pre_header_serial=None,
        initial_state=0x6107F8EC,
        condition_chain_blocks=(),
        nodes=(
            StateDagNode(
                key=StateDagNodeKey(handler_serial=66, state_const=0x474EEEBB),
                kind=StateNodeKind.EXACT,
                state_label="0x474EEEBB",
                handler_serial=66,
                entry_anchor=66,
                owned_blocks=(63, 64, 65, 66),
                exclusive_blocks=(63, 64, 65),
                shared_suffix_blocks=(66,),
                local_segments=(),
                local_edges=(),
            ),
        ),
        edges=(),
        transient_entry_blocks=(),
        supplemental_selected_entries=(),
        diagnostics=(),
    )

    assert _resolve_nonraw_owner_semantic_alias(
        0x4C77464F,
        anchor_candidates={66, 71},
        dag=dag,
        condition_chain_blocks=set(),
    ) == (63, "0x474EEEBB")


def test_resolves_nonraw_owner_semantic_alias_returns_none_without_nonraw_owner() -> None:
    dag = LinearizedStateDag(
        dispatcher_entry_serial=0,
        state_var_stkoff=None,
        pre_header_serial=None,
        initial_state=0x6107F8EC,
        condition_chain_blocks=(),
        nodes=(
            StateDagNode(
                key=StateDagNodeKey(handler_serial=66, state_const=0x4C77464F),
                kind=StateNodeKind.EXACT,
                state_label="0x4C77464F",
                handler_serial=66,
                entry_anchor=66,
                owned_blocks=(66, 67, 68, 69),
                exclusive_blocks=(66, 67, 68, 69),
                shared_suffix_blocks=(),
                local_segments=(),
                local_edges=(),
            ),
        ),
        edges=(),
        transient_entry_blocks=(),
        supplemental_selected_entries=(),
        diagnostics=(),
    )

    assert (
        _resolve_nonraw_owner_semantic_alias(
            0x4C77464F,
            anchor_candidates={66},
            dag=dag,
            condition_chain_blocks=set(),
        )
        is None
    )


def test_resolves_nonraw_owner_semantic_alias_from_branchy_raw_path_blocks() -> None:
    dag = LinearizedStateDag(
        dispatcher_entry_serial=0,
        state_var_stkoff=None,
        pre_header_serial=None,
        initial_state=0x6107F8EC,
        condition_chain_blocks=(),
        nodes=(
            StateDagNode(
                key=StateDagNodeKey(handler_serial=66, state_const=0x4C77464F),
                kind=StateNodeKind.EXACT,
                state_label="0x4C77464F",
                handler_serial=66,
                entry_anchor=66,
                owned_blocks=(66, 67, 68, 69),
                exclusive_blocks=(66, 67),
                shared_suffix_blocks=(),
                local_segments=(),
                local_edges=(),
            ),
            StateDagNode(
                key=StateDagNodeKey(handler_serial=68, state_const=0x474EEEBB),
                kind=StateNodeKind.EXACT,
                state_label="0x474EEEBB",
                handler_serial=68,
                entry_anchor=68,
                owned_blocks=(66, 68, 69),
                exclusive_blocks=(68, 69),
                shared_suffix_blocks=(),
                local_segments=(),
                local_edges=(),
            ),
        ),
        edges=(),
        transient_entry_blocks=(),
        supplemental_selected_entries=(),
        diagnostics=(),
    )

    assert _resolve_nonraw_owner_semantic_alias(
        0x4C77464F,
        anchor_candidates={66, 67, 68, 69},
        dag=dag,
        condition_chain_blocks=set(),
    ) == (68, "0x474EEEBB")


def test_resolves_prior_supplemental_selected_alias_to_semantic_owner() -> None:
    dag = LinearizedStateDag(
        dispatcher_entry_serial=0,
        state_var_stkoff=None,
        pre_header_serial=None,
        initial_state=0x6107F8EC,
        condition_chain_blocks=(),
        nodes=(
            StateDagNode(
                key=StateDagNodeKey(handler_serial=66, state_const=0x4C77464F),
                kind=StateNodeKind.EXACT,
                state_label="0x4C77464F",
                handler_serial=66,
                entry_anchor=66,
                owned_blocks=(66, 67, 68, 69),
                exclusive_blocks=(66, 67),
                shared_suffix_blocks=(),
                local_segments=(),
                local_edges=(),
            ),
            StateDagNode(
                key=StateDagNodeKey(handler_serial=66, state_const=0x474EEEBB),
                kind=StateNodeKind.EXACT,
                state_label="0x474EEEBB",
                handler_serial=66,
                entry_anchor=66,
                owned_blocks=(66, 67, 68, 69),
                exclusive_blocks=(68, 69),
                shared_suffix_blocks=(),
                local_segments=(),
                local_edges=(),
            ),
        ),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
                source_key=StateDagNodeKey(handler_serial=15, state_const=0x6107F8EC),
                target_key=StateDagNodeKey(handler_serial=66, state_const=0x474EEEBB),
                target_state=0x4C77464F,
                target_entry_anchor=68,
                target_label="0x474EEEBB",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                    block_serial=15,
                    branch_arm=0,
                ),
                ordered_path=(15, 16),
            ),
        ),
        transient_entry_blocks=(),
        supplemental_selected_entries=((0x4C77464F, 68),),
        diagnostics=(),
    )

    assert _resolve_prior_supplemental_selected_alias(
        0x4C77464F,
        dag=dag,
        condition_chain_blocks=set(),
    ) == (68, "0x474EEEBB")


def test_resolves_nonraw_dispatcher_cover_alias_skips_raw_exact_range_row() -> None:
    dispatcher = IntervalDispatcher(
        [
            IntervalRow(lo=0x432DC78A, hi=0x474EEEBB, target=63),
            IntervalRow(lo=0x474EEEBB, hi=0x474EEEBC, target=66),
            IntervalRow(lo=0x474EEEBC, hi=0x4E69F350, target=71),
            IntervalRow(lo=0x4E69F350, hi=0x4E69F351, target=72),
        ]
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=0,
        state_var_stkoff=None,
        pre_header_serial=None,
        initial_state=0x6107F8EC,
        condition_chain_blocks=(),
        nodes=(
            StateDagNode(
                key=StateDagNodeKey(handler_serial=63, state_const=0x474EEEBB),
                kind=StateNodeKind.EXACT,
                state_label="0x474EEEBB",
                handler_serial=63,
                entry_anchor=63,
                owned_blocks=(63, 64, 65, 66),
                exclusive_blocks=(63, 64, 65),
                shared_suffix_blocks=(66,),
                local_segments=(),
                local_edges=(),
            ),
            StateDagNode(
                key=StateDagNodeKey(handler_serial=66, state_const=0x4C77464F),
                kind=StateNodeKind.EXACT,
                state_label="0x4C77464F",
                handler_serial=66,
                entry_anchor=66,
                owned_blocks=(66, 67, 68, 69),
                exclusive_blocks=(66, 67, 68, 69),
                shared_suffix_blocks=(),
                local_segments=(),
                local_edges=(),
            ),
            StateDagNode(
                key=StateDagNodeKey(handler_serial=71, state_const=0x57BE6FD0),
                kind=StateNodeKind.EXACT,
                state_label="0x57BE6FD0",
                handler_serial=71,
                entry_anchor=71,
                owned_blocks=(71, 72),
                exclusive_blocks=(71, 72),
                shared_suffix_blocks=(),
                local_segments=(),
                local_edges=(),
            ),
        ),
        edges=(),
        transient_entry_blocks=(),
        supplemental_selected_entries=(),
        diagnostics=(),
    )

    assert _resolve_nonraw_dispatcher_cover_alias(
        0x4C77464F,
        dag=dag,
        dispatcher=dispatcher,
        condition_chain_blocks=set(),
    ) == (63, "0x474EEEBB")


def test_resolves_nonraw_dispatcher_cover_alias_skips_known_cover_anchor_without_dag_node() -> None:
    dispatcher = IntervalDispatcher(
        [
            IntervalRow(lo=0x432DC78A, hi=0x474EEEBB, target=63),
            IntervalRow(lo=0x474EEEBB, hi=0x474EEEBC, target=66),
            IntervalRow(lo=0x474EEEBC, hi=0x4E69F350, target=71),
            IntervalRow(lo=0x4E69F350, hi=0x4E69F351, target=72),
        ]
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=0,
        state_var_stkoff=None,
        pre_header_serial=None,
        initial_state=0x6107F8EC,
        condition_chain_blocks=(),
        nodes=(
            StateDagNode(
                key=StateDagNodeKey(handler_serial=63, state_const=0x474EEEBB),
                kind=StateNodeKind.EXACT,
                state_label="0x474EEEBB",
                handler_serial=63,
                entry_anchor=63,
                owned_blocks=(63, 64, 65, 66),
                exclusive_blocks=(63, 64, 65),
                shared_suffix_blocks=(66,),
                local_segments=(),
                local_edges=(),
            ),
        ),
        edges=(),
        transient_entry_blocks=(),
        supplemental_selected_entries=(),
        diagnostics=(),
    )

    assert _resolve_nonraw_dispatcher_cover_alias(
        0x4C77464F,
        dag=dag,
        dispatcher=dispatcher,
        condition_chain_blocks=set(),
        raw_exact_cover_anchor=66,
    ) == (63, "0x474EEEBB")


def test_selects_branchy_cover_exact_as_raw_alias_candidate_when_source_family_is_dispatcher() -> None:
    dag = LinearizedStateDag(
        dispatcher_entry_serial=0,
        state_var_stkoff=None,
        pre_header_serial=None,
        initial_state=0x6107F8EC,
        condition_chain_blocks=(),
        nodes=(),
        edges=(),
        transient_entry_blocks=(),
        supplemental_selected_entries=(),
        diagnostics=(),
    )

    assert _select_raw_alias_candidate_anchor(
        state_value=0x4C77464F,
        dag=dag,
        source_family_alias_anchor=71,
        source_family_alias_is_raw=False,
        cover_exact_anchor=66,
        dispatcher_anchor=71,
        candidate_results_by_anchor={
            66: (
                (
                    HandlerPathResult(
                        exit_block=69,
                        final_state=0x12ACFB20,
                        state_writes=[(69, 0x12ACFB20)],
                        ordered_path=[66, 68, 69],
                    ),
                    HandlerPathResult(
                        exit_block=67,
                        final_state=0x32FCD904,
                        state_writes=[(67, 0x32FCD904)],
                        ordered_path=[66, 67],
                    ),
                ),
                (
                    ConditionalTransition(
                        handler_entry=66,
                        branch_block=66,
                        target_state=0x12ACFB20,
                        target_handler=69,
                        state_write_block=69,
                        state_write_ea=0x401000,
                        branch_arm=0,
                    ),
                ),
            ),
        },
    ) == 66


def test_selects_branchy_source_family_as_raw_alias_candidate_when_exact_entry_is_shared() -> None:
    dag = LinearizedStateDag(
        dispatcher_entry_serial=0,
        state_var_stkoff=None,
        pre_header_serial=None,
        initial_state=0x6107F8EC,
        condition_chain_blocks=(),
        nodes=(
            StateDagNode(
                key=StateDagNodeKey(handler_serial=66, state_const=0x4C77464F),
                kind=StateNodeKind.EXACT,
                state_label="STATE_4C77464F",
                handler_serial=66,
                entry_anchor=66,
                owned_blocks=(66, 67, 68, 69),
                exclusive_blocks=(66, 67, 68, 69),
                shared_suffix_blocks=(),
                local_segments=(),
                local_edges=(),
            ),
            StateDagNode(
                key=StateDagNodeKey(handler_serial=66, state_const=0x474EEEBB),
                kind=StateNodeKind.EXACT,
                state_label="0x474EEEBB",
                handler_serial=66,
                entry_anchor=66,
                owned_blocks=(66, 67, 68, 69),
                exclusive_blocks=(66, 67, 68, 69),
                shared_suffix_blocks=(),
                local_segments=(),
                local_edges=(),
            ),
        ),
        edges=(),
        transient_entry_blocks=(),
        supplemental_selected_entries=(),
        diagnostics=(),
    )

    assert _select_raw_alias_candidate_anchor(
        state_value=0x4C77464F,
        dag=dag,
        source_family_alias_anchor=66,
        source_family_alias_is_raw=False,
        cover_exact_anchor=66,
        dispatcher_anchor=None,
        candidate_results_by_anchor={
            66: (
                (
                    HandlerPathResult(
                        exit_block=69,
                        final_state=0x12ACFB20,
                        state_writes=[(69, 0x12ACFB20)],
                        ordered_path=[66, 68, 69],
                    ),
                    HandlerPathResult(
                        exit_block=67,
                        final_state=0x32FCD904,
                        state_writes=[(67, 0x32FCD904)],
                        ordered_path=[66, 67],
                    ),
                ),
                (
                    ConditionalTransition(
                        handler_entry=66,
                        branch_block=66,
                        target_state=0x12ACFB20,
                        target_handler=69,
                        state_write_block=69,
                        state_write_ea=0x401000,
                        branch_arm=0,
                    ),
                ),
            ),
        },
    ) == 66


def test_build_linearized_state_program_normalizes_rendered_raw_alias_labels() -> None:
    source_key = StateDagNodeKey(handler_serial=15, state_const=0x6107F8EC)
    alias_key = StateDagNodeKey(handler_serial=66, state_const=0x4C77464F)
    semantic_key = StateDagNodeKey(handler_serial=66, state_const=0x474EEEBB)
    dag = LinearizedStateDag(
        dispatcher_entry_serial=0,
        state_var_stkoff=None,
        pre_header_serial=None,
        initial_state=0x6107F8EC,
        condition_chain_blocks=(),
        nodes=(
            StateDagNode(
                key=source_key,
                kind=StateNodeKind.EXACT,
                state_label="STATE_6107F8EC",
                handler_serial=15,
                entry_anchor=15,
                owned_blocks=(15, 16),
                exclusive_blocks=(15, 16),
                shared_suffix_blocks=(),
                local_segments=(),
                local_edges=(),
            ),
            StateDagNode(
                key=alias_key,
                kind=StateNodeKind.EXACT,
                state_label="STATE_4C77464F",
                handler_serial=66,
                entry_anchor=66,
                owned_blocks=(66, 67, 68, 69),
                exclusive_blocks=(66, 67, 68, 69),
                shared_suffix_blocks=(),
                local_segments=(),
                local_edges=(),
            ),
            StateDagNode(
                key=semantic_key,
                kind=StateNodeKind.EXACT,
                state_label="STATE_474EEEBB",
                handler_serial=66,
                entry_anchor=66,
                owned_blocks=(66, 67, 68, 69),
                exclusive_blocks=(66, 67, 68, 69),
                shared_suffix_blocks=(),
                local_segments=(),
                local_edges=(),
            ),
            StateDagNode(
                key=StateDagNodeKey(handler_serial=189, state_const=0x32FCD904),
                kind=StateNodeKind.EXACT,
                state_label="STATE_32FCD904",
                handler_serial=189,
                entry_anchor=189,
                owned_blocks=(189,),
                exclusive_blocks=(189,),
                shared_suffix_blocks=(),
                local_segments=(),
                local_edges=(),
            ),
        ),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
                source_key=source_key,
                target_key=alias_key,
                target_state=0x4C77464F,
                target_entry_anchor=68,
                target_label="STATE_4C77464F",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                    block_serial=15,
                    branch_arm=0,
                ),
                ordered_path=(15, 16),
            ),
            StateDagEdge(
                kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
                source_key=semantic_key,
                target_key=StateDagNodeKey(handler_serial=189, state_const=0x32FCD904),
                target_state=0x32FCD904,
                target_entry_anchor=189,
                target_label="STATE_32FCD904",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                    block_serial=66,
                    branch_arm=1,
                ),
                ordered_path=(66, 67),
            ),
        ),
        supplemental_selected_entries=((0x4C77464F, 68),),
        diagnostics=(),
    )

    program = build_linearized_state_program(
        dag,
        order_strategy=RenderOrderStrategy.SEMANTIC,
        program_strategy=ProgramRenderStrategy.LOCAL_SEGMENT_COLLAPSING,
        label_render_mode=LabelRenderMode.STATE_FAMILY,
        boundary_inline_mode=BoundaryInlineMode.LABELS_ONLY,
        comment_mode=ProgramCommentMode.MINIMAL,
    )

    rendered = "\n".join(line.text for line in program.lines)
    assert "STATE_4C77464F" not in rendered
    assert "STATE_474EEEBB" in rendered


def test_semantic_entry_anchor_keeps_non_condition_chain_handler_over_unique_path_root() -> None:
    paths = (
        HandlerPathResult(
            exit_block=68,
            final_state=0x474EEEBB,
            state_writes=[],
            ordered_path=[66, 67, 68],
        ),
    )

    assert (
        _resolve_semantic_entry_anchor(
            63,
            local_blocks=(63, 66, 67, 68),
            paths=paths,
            condition_chain_blocks=(0, 1, 2, 15, 16),
        )
        == 63
    )


def test_prefers_family_fallback_over_branchy_raw_exact_supplemental_anchor() -> None:
    raw_exact_key = StateDagNodeKey(handler_serial=66, state_const=0x4C77464F)
    dag = LinearizedStateDag(
        dispatcher_entry_serial=0,
        state_var_stkoff=None,
        pre_header_serial=None,
        initial_state=0x6107F8EC,
        condition_chain_blocks=(),
        nodes=(
            StateDagNode(
                key=raw_exact_key,
                kind=StateNodeKind.EXACT,
                state_label="0x4C77464F",
                handler_serial=66,
                entry_anchor=66,
                owned_blocks=(66, 67, 68, 69),
                exclusive_blocks=(66, 67, 68, 69),
                shared_suffix_blocks=(),
                local_segments=(),
                local_edges=(),
            ),
        ),
        edges=(),
        transient_entry_blocks=(),
        supplemental_selected_entries=(),
        diagnostics=(),
    )

    assert _should_prefer_family_fallback_over_raw_exact(
        66,
        family_fallback_anchor=14,
        state_value=0x4C77464F,
        dag=dag,
        candidate_results_by_anchor={
            66: (
                (
                    HandlerPathResult(
                        exit_block=69,
                        final_state=0x12ACFB20,
                        state_writes=[(69, 0x12ACFB20)],
                        ordered_path=[66, 68, 69],
                    ),
                    HandlerPathResult(
                        exit_block=67,
                        final_state=0x32FCD904,
                        state_writes=[(67, 0x32FCD904)],
                        ordered_path=[66, 67],
                    ),
                ),
                (
                    ConditionalTransition(
                        handler_entry=66,
                        branch_block=66,
                        target_state=0x12ACFB20,
                        target_handler=69,
                        state_write_block=69,
                        state_write_ea=0x401000,
                        branch_arm=0,
                    ),
                ),
            ),
        },
    )


def test_does_not_prefer_family_fallback_over_straight_raw_exact_anchor() -> None:
    raw_exact_key = StateDagNodeKey(handler_serial=66, state_const=0x4C77464F)
    dag = LinearizedStateDag(
        dispatcher_entry_serial=0,
        state_var_stkoff=None,
        pre_header_serial=None,
        initial_state=0x6107F8EC,
        condition_chain_blocks=(),
        nodes=(
            StateDagNode(
                key=raw_exact_key,
                kind=StateNodeKind.EXACT,
                state_label="0x4C77464F",
                handler_serial=66,
                entry_anchor=66,
                owned_blocks=(66,),
                exclusive_blocks=(66,),
                shared_suffix_blocks=(),
                local_segments=(),
                local_edges=(),
            ),
        ),
        edges=(),
        transient_entry_blocks=(),
        supplemental_selected_entries=(),
        diagnostics=(),
    )

    assert not _should_prefer_family_fallback_over_raw_exact(
        66,
        family_fallback_anchor=14,
        state_value=0x4C77464F,
        dag=dag,
        candidate_results_by_anchor={
            66: (
                (
                    HandlerPathResult(
                        exit_block=66,
                        final_state=0x139F2922,
                        state_writes=[(66, 0x139F2922)],
                        ordered_path=[66],
                    ),
                ),
                (),
            ),
        },
    )


def test_does_not_prefer_family_fallback_when_source_family_alias_is_raw_exact() -> None:
    raw_exact_key = StateDagNodeKey(handler_serial=66, state_const=0x4C77464F)
    dag = LinearizedStateDag(
        dispatcher_entry_serial=0,
        state_var_stkoff=None,
        pre_header_serial=None,
        initial_state=0x6107F8EC,
        condition_chain_blocks=(),
        nodes=(
            StateDagNode(
                key=raw_exact_key,
                kind=StateNodeKind.EXACT,
                state_label="0x4C77464F",
                handler_serial=66,
                entry_anchor=66,
                owned_blocks=(66, 67, 68, 69),
                exclusive_blocks=(66, 67, 68, 69),
                shared_suffix_blocks=(),
                local_segments=(),
                local_edges=(),
            ),
        ),
        edges=(),
        transient_entry_blocks=(),
        supplemental_selected_entries=(),
        diagnostics=(),
    )

    assert not _should_prefer_family_fallback_over_raw_exact(
        66,
        family_fallback_anchor=14,
        source_family_alias_anchor=66,
        source_family_alias_is_raw=True,
        state_value=0x4C77464F,
        dag=dag,
        candidate_results_by_anchor={
            66: (
                (
                    HandlerPathResult(
                        exit_block=69,
                        final_state=0x12ACFB20,
                        state_writes=[(69, 0x12ACFB20)],
                        ordered_path=[66, 68, 69],
                    ),
                    HandlerPathResult(
                        exit_block=67,
                        final_state=0x32FCD904,
                        state_writes=[(67, 0x32FCD904)],
                        ordered_path=[66, 67],
                    ),
                ),
                (
                    ConditionalTransition(
                        handler_entry=66,
                        branch_block=66,
                        target_state=0x12ACFB20,
                        target_handler=69,
                        state_write_block=69,
                        state_write_ea=0x401000,
                        branch_arm=0,
                    ),
                ),
            ),
        },
    )


def test_prefers_family_fallback_when_source_family_alias_is_raw_exact_with_distinct_cover() -> None:
    raw_exact_key = StateDagNodeKey(handler_serial=66, state_const=0x4C77464F)
    dag = LinearizedStateDag(
        dispatcher_entry_serial=0,
        state_var_stkoff=None,
        pre_header_serial=None,
        initial_state=0x6107F8EC,
        condition_chain_blocks=(),
        nodes=(
            StateDagNode(
                key=raw_exact_key,
                kind=StateNodeKind.EXACT,
                state_label="0x4C77464F",
                handler_serial=66,
                entry_anchor=66,
                owned_blocks=(66, 67, 68, 69),
                exclusive_blocks=(66, 67, 68, 69),
                shared_suffix_blocks=(),
                local_segments=(),
                local_edges=(),
            ),
        ),
        edges=(),
        transient_entry_blocks=(),
        supplemental_selected_entries=(),
        diagnostics=(),
    )

    assert _should_prefer_family_fallback_over_raw_exact(
        66,
        family_fallback_anchor=14,
        cover_anchor=70,
        source_family_alias_anchor=66,
        source_family_alias_is_raw=True,
        state_value=0x4C77464F,
        dag=dag,
        candidate_results_by_anchor={
            66: (
                (
                    HandlerPathResult(
                        exit_block=69,
                        final_state=0x12ACFB20,
                        state_writes=[(69, 0x12ACFB20)],
                        ordered_path=[66, 68, 69],
                    ),
                    HandlerPathResult(
                        exit_block=67,
                        final_state=0x32FCD904,
                        state_writes=[(67, 0x32FCD904)],
                        ordered_path=[66, 67],
                    ),
                ),
                (
                    ConditionalTransition(
                        handler_entry=66,
                        branch_block=66,
                        target_state=0x12ACFB20,
                        target_handler=69,
                        state_write_block=69,
                        state_write_ea=0x401000,
                        branch_arm=0,
                    ),
                ),
            ),
        },
    )


def test_prefers_family_fallback_over_branchy_duplicate_cover_exact_anchor() -> None:
    raw_exact_key = StateDagNodeKey(handler_serial=66, state_const=0x4C77464F)
    semantic_exact_key = StateDagNodeKey(handler_serial=66, state_const=0x474EEEBB)
    dag = LinearizedStateDag(
        dispatcher_entry_serial=0,
        state_var_stkoff=None,
        pre_header_serial=None,
        initial_state=0x6107F8EC,
        condition_chain_blocks=(),
        nodes=(
            StateDagNode(
                key=raw_exact_key,
                kind=StateNodeKind.EXACT,
                state_label="0x4C77464F",
                handler_serial=66,
                entry_anchor=66,
                owned_blocks=(66, 67, 68, 69),
                exclusive_blocks=(66, 67, 68, 69),
                shared_suffix_blocks=(),
                local_segments=(),
                local_edges=(),
            ),
            StateDagNode(
                key=semantic_exact_key,
                kind=StateNodeKind.EXACT,
                state_label="0x474EEEBB",
                handler_serial=66,
                entry_anchor=66,
                owned_blocks=(66, 67, 68, 69),
                exclusive_blocks=(66, 67, 68, 69),
                shared_suffix_blocks=(),
                local_segments=(),
                local_edges=(),
            ),
        ),
        edges=(),
        transient_entry_blocks=(),
        supplemental_selected_entries=(),
        diagnostics=(),
    )

    assert _should_prefer_family_fallback_over_raw_exact(
        66,
        family_fallback_anchor=61,
        cover_exact_anchor=66,
        state_value=0x4C77464F,
        dag=dag,
        candidate_results_by_anchor={
            66: (
                (
                    HandlerPathResult(
                        exit_block=69,
                        final_state=0x12ACFB20,
                        state_writes=[(69, 0x12ACFB20)],
                        ordered_path=[66, 68, 69],
                    ),
                    HandlerPathResult(
                        exit_block=67,
                        final_state=0x32FCD904,
                        state_writes=[(67, 0x32FCD904)],
                        ordered_path=[66, 67],
                    ),
                ),
                (
                    ConditionalTransition(
                        handler_entry=66,
                        branch_block=66,
                        target_state=0x12ACFB20,
                        target_handler=69,
                        state_write_block=69,
                        state_write_ea=0x401000,
                        branch_arm=0,
                    ),
                ),
            ),
        },
    )


def test_does_not_prefer_family_fallback_over_branchy_nonraw_cover_exact_anchor() -> None:
    dag = LinearizedStateDag(
        dispatcher_entry_serial=0,
        state_var_stkoff=None,
        pre_header_serial=None,
        initial_state=0x6107F8EC,
        condition_chain_blocks=(),
        nodes=(
            StateDagNode(
                key=StateDagNodeKey(handler_serial=66, state_const=0x474EEEBB),
                kind=StateNodeKind.EXACT,
                state_label="0x474EEEBB",
                handler_serial=66,
                entry_anchor=66,
                owned_blocks=(66, 67, 68, 69),
                exclusive_blocks=(66, 67, 68, 69),
                shared_suffix_blocks=(),
                local_segments=(),
                local_edges=(),
            ),
        ),
        edges=(),
        transient_entry_blocks=(),
        supplemental_selected_entries=(),
        diagnostics=(),
    )

    assert not _should_prefer_family_fallback_over_raw_exact(
        66,
        family_fallback_anchor=14,
        cover_exact_anchor=66,
        source_family_alias_anchor=66,
        source_family_alias_is_raw=False,
        state_value=0x4C77464F,
        dag=dag,
        candidate_results_by_anchor={
            66: (
                (
                    HandlerPathResult(
                        exit_block=69,
                        final_state=0x12ACFB20,
                        state_writes=[(69, 0x12ACFB20)],
                        ordered_path=[66, 68, 69],
                    ),
                    HandlerPathResult(
                        exit_block=67,
                        final_state=0x32FCD904,
                        state_writes=[(67, 0x32FCD904)],
                        ordered_path=[66, 67],
                    ),
                ),
                (
                    ConditionalTransition(
                        handler_entry=66,
                        branch_block=66,
                        target_state=0x12ACFB20,
                        target_handler=69,
                        state_write_block=69,
                        state_write_ea=0x401000,
                        branch_arm=0,
                    ),
                ),
            ),
        },
    )


def test_resolves_exact_cover_anchor_to_preceding_exact_row() -> None:
    report = DispatcherTransitionReport(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        state_var_lvar_idx=None,
        pre_header_serial=None,
        initial_state=0x6107F8EC,
        handler_state_map={66: 0x474EEEBB},
        handler_range_map={71: (0x474EEEBC, 0x4E69F350)},
        condition_chain_blocks=(),
        rows=(
            TransitionRow(
                state_const=0x474EEEBB,
                state_range_lo=None,
                state_range_hi=None,
                handler_serial=66,
                kind=TransitionKind.CONDITIONAL,
                next_state=None,
                conditional_states=(0x296F2452, 0x4C77464F),
                state_label="0x474EEEBB",
                chain_preview=(66,),
                transition_label="474eeebb",
                path=TransitionPath(
                    handler_serial=66,
                    chain=(66,),
                    next_state=None,
                    conditional_states=(0x296F2452, 0x4C77464F),
                    back_edge=True,
                    reaches_exit_block=False,
                    classified_exit=False,
                    unresolved=False,
                ),
            ),
            TransitionRow(
                state_const=None,
                state_range_lo=0x474EEEBC,
                state_range_hi=0x4E69F350,
                handler_serial=71,
                kind=TransitionKind.UNKNOWN,
                next_state=None,
                conditional_states=(),
                state_label="range alias",
                chain_preview=(71,),
                transition_label="range alias",
                path=TransitionPath(
                    handler_serial=71,
                    chain=(71,),
                    next_state=None,
                    conditional_states=(),
                    back_edge=False,
                    reaches_exit_block=False,
                    classified_exit=False,
                    unresolved=True,
                ),
            ),
        ),
        summary=TransitionSummary(
            handlers_total=2,
            known_count=0,
            conditional_count=1,
            exit_count=0,
            unknown_count=1,
        ),
        diagnostics=(),
    )

    assert _resolve_exact_cover_anchor(
        0x4C77464F,
        report,
        condition_chain_blocks=set(),
    ) == 66


def test_resolves_exact_cover_anchor_from_dispatcher_singleton_row() -> None:
    report = DispatcherTransitionReport(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        state_var_lvar_idx=None,
        pre_header_serial=None,
        initial_state=0x6107F8EC,
        handler_state_map={},
        handler_range_map={71: (0x474EEEBC, 0x4E69F350)},
        condition_chain_blocks=(),
        rows=(
            TransitionRow(
                state_const=None,
                state_range_lo=0x474EEEBC,
                state_range_hi=0x4E69F350,
                handler_serial=71,
                kind=TransitionKind.UNKNOWN,
                next_state=None,
                conditional_states=(),
                state_label="range alias",
                transition_label="range alias",
                chain_preview=(71,),
                path=TransitionPath(
                    handler_serial=71,
                    chain=(71,),
                    next_state=None,
                    conditional_states=(),
                    back_edge=False,
                    reaches_exit_block=False,
                    classified_exit=False,
                    unresolved=True,
                ),
            ),
        ),
        summary=TransitionSummary(
            handlers_total=1,
            known_count=0,
            conditional_count=0,
            exit_count=0,
            unknown_count=1,
        ),
        diagnostics=(),
    )
    dispatcher = IntervalDispatcher(
        [
            IntervalRow(lo=0x474EEEBB, hi=0x474EEEBC, target=66),
            IntervalRow(lo=0x474EEEBC, hi=0x4E69F350, target=71),
            IntervalRow(lo=0x4E69F350, hi=0x4E69F351, target=72),
        ]
    )

    assert _resolve_exact_cover_anchor(
        0x4C77464F,
        report,
        dispatcher=dispatcher,
        condition_chain_blocks=set(),
    ) == 66


def test_build_state_resolver_preserves_raw_exact_row_over_dispatcher_corridor() -> None:
    report = DispatcherTransitionReport(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        state_var_lvar_idx=None,
        pre_header_serial=None,
        initial_state=0x6107F8EC,
        handler_state_map={66: 0x4C77464F},
        handler_range_map={71: (0x474EEEBC, 0x4E69F350)},
        condition_chain_blocks=(),
        rows=(
            TransitionRow(
                state_const=0x4C77464F,
                state_range_lo=None,
                state_range_hi=None,
                handler_serial=66,
                kind=TransitionKind.CONDITIONAL,
                next_state=None,
                conditional_states=(0x296F2452, 0x474EEEBB),
                state_label="State 0x4c77464f",
                transition_label="conditional transition -> {0x296f2452, 0x474eeebb}",
                chain_preview=(66,),
                path=TransitionPath(
                    handler_serial=66,
                    chain=(66, 67),
                    next_state=None,
                    conditional_states=(0x296F2452, 0x474EEEBB),
                    back_edge=False,
                    reaches_exit_block=False,
                    classified_exit=False,
                    unresolved=False,
                ),
            ),
        ),
        summary=TransitionSummary(
            handlers_total=1,
            known_count=0,
            conditional_count=1,
            exit_count=0,
            unknown_count=0,
        ),
        diagnostics=(),
    )
    dispatcher = IntervalDispatcher(
        [
            IntervalRow(lo=0x474EEEBC, hi=0x4E69F350, target=71),
        ]
    )
    flow_graph = FlowGraph(
        blocks={
            66: BlockSnapshot(66, 0, (68,), (), 0, 0, ()),
            68: BlockSnapshot(68, 0, (), (66,), 0, 0, ()),
            71: BlockSnapshot(71, 0, (), (), 0, 0, ()),
        },
        entry_serial=66,
        func_ea=0x401000,
    )

    _, resolve_handler = _build_state_resolver(
        report,
        TransitionResult(),
        dispatcher,
        flow_graph=flow_graph,
    )

    assert resolve_handler(0x4C77464F) == 66


def test_build_state_resolver_overrides_transient_raw_exact_row_to_dispatcher() -> None:
    report = DispatcherTransitionReport(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        state_var_lvar_idx=None,
        pre_header_serial=None,
        initial_state=0x6107F8EC,
        handler_state_map={66: 0x4C77464F},
        handler_range_map={71: (0x474EEEBC, 0x4E69F350)},
        condition_chain_blocks=(),
        rows=(
            TransitionRow(
                state_const=0x4C77464F,
                state_range_lo=None,
                state_range_hi=None,
                handler_serial=66,
                kind=TransitionKind.CONDITIONAL,
                next_state=None,
                conditional_states=(0x296F2452, 0x474EEEBB),
                state_label="State 0x4c77464f",
                transition_label="conditional transition -> {0x296f2452, 0x474eeebb}",
                chain_preview=(66,),
                path=TransitionPath(
                    handler_serial=66,
                    chain=(66, 67),
                    next_state=None,
                    conditional_states=(0x296F2452, 0x474EEEBB),
                    back_edge=False,
                    reaches_exit_block=False,
                    classified_exit=False,
                    unresolved=False,
                ),
            ),
        ),
        summary=TransitionSummary(
            handlers_total=1,
            known_count=0,
            conditional_count=1,
            exit_count=0,
            unknown_count=0,
        ),
        diagnostics=(),
    )
    dispatcher = IntervalDispatcher(
        [
            IntervalRow(lo=0x474EEEBC, hi=0x4E69F350, target=71),
        ]
    )
    flow_graph = FlowGraph(
        blocks={
            66: BlockSnapshot(66, 0, (68,), (), 0, 0, ()),
            68: BlockSnapshot(68, 0, (), (66,), 0, 0, ()),
            71: BlockSnapshot(71, 0, (), (), 0, 0, ()),
        },
        entry_serial=66,
        func_ea=0x401000,
    )

    _, resolve_handler = _build_state_resolver(
        report,
        TransitionResult(),
        dispatcher,
        flow_graph=flow_graph,
        transient_state_values={0x4C77464F},
    )

    assert resolve_handler(0x4C77464F) == 71


def test_build_state_resolver_still_overrides_nonraw_exact_row_to_dispatcher() -> None:
    report = DispatcherTransitionReport(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        state_var_lvar_idx=None,
        pre_header_serial=None,
        initial_state=0x6107F8EC,
        handler_state_map={66: 0x474EEEBB},
        handler_range_map={71: (0x474EEEBC, 0x4E69F350)},
        condition_chain_blocks=(),
        rows=(
            TransitionRow(
                state_const=0x474EEEBB,
                state_range_lo=None,
                state_range_hi=None,
                handler_serial=66,
                kind=TransitionKind.TRANSITION,
                next_state=0x6107F8EC,
                conditional_states=(),
                state_label="State 0x474eeebb",
                transition_label="next=0x6107f8ec",
                chain_preview=(66,),
                path=TransitionPath(
                    handler_serial=66,
                    chain=(66, 68),
                    next_state=0x6107F8EC,
                    conditional_states=(),
                    back_edge=False,
                    reaches_exit_block=False,
                    classified_exit=False,
                    unresolved=False,
                ),
            ),
        ),
        summary=TransitionSummary(
            handlers_total=1,
            known_count=1,
            conditional_count=0,
            exit_count=0,
            unknown_count=0,
        ),
        diagnostics=(),
    )
    dispatcher = IntervalDispatcher(
        [
            IntervalRow(lo=0x474EEEBB, hi=0x4E69F350, target=71),
        ]
    )
    flow_graph = FlowGraph(
        blocks={
            66: BlockSnapshot(66, 0, (68,), (), 0, 0, ()),
            68: BlockSnapshot(68, 0, (), (66,), 0, 0, ()),
            71: BlockSnapshot(71, 0, (), (), 0, 0, ()),
        },
        entry_serial=66,
        func_ea=0x401000,
    )

    _, resolve_handler = _build_state_resolver(
        report,
        TransitionResult(),
        dispatcher,
        flow_graph=flow_graph,
    )

    assert resolve_handler(0x474EEEBB) == 71


def test_build_state_resolver_prefers_dispatcher_over_protected_non_carrier_return_writer() -> None:
    report = DispatcherTransitionReport(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        state_var_lvar_idx=None,
        pre_header_serial=None,
        initial_state=0x6107F8EC,
        handler_state_map={66: 0x474EEEBB},
        handler_range_map={71: (0x474EEEBC, 0x4E69F350)},
        condition_chain_blocks=(),
        rows=(
            TransitionRow(
                state_const=0x474EEEBB,
                state_range_lo=None,
                state_range_hi=None,
                handler_serial=66,
                kind=TransitionKind.TRANSITION,
                next_state=0x6107F8EC,
                conditional_states=(),
                state_label="State 0x474eeebb",
                transition_label="next=0x6107f8ec",
                chain_preview=(66,),
                path=TransitionPath(
                    handler_serial=66,
                    chain=(66, 68),
                    next_state=0x6107F8EC,
                    conditional_states=(),
                    back_edge=False,
                    reaches_exit_block=False,
                    classified_exit=False,
                    unresolved=False,
                ),
            ),
        ),
        summary=TransitionSummary(
            handlers_total=1,
            known_count=1,
            conditional_count=0,
            exit_count=0,
            unknown_count=0,
        ),
        diagnostics=(),
    )
    dispatcher = IntervalDispatcher(
        [
            IntervalRow(lo=0x474EEEBB, hi=0x4E69F350, target=71),
        ]
    )
    artifact_writer = InsnSnapshot(
        opcode=-1,
        ea=0x7100,
        operands=(),
        l=MopSnapshot(kind=OperandKind.STACK, stkoff=0x3C),
        d=MopSnapshot(kind=OperandKind.STACK, stkoff=0x80),
        kind=InsnKind.XDU,
    )
    flow_graph = FlowGraph(
        blocks={
            66: BlockSnapshot(66, 0, (68,), (), 0, 0, ()),
            68: BlockSnapshot(68, 0, (), (66,), 0, 0, ()),
            71: BlockSnapshot(71, 0, (), (), 0, 0, (artifact_writer,)),
        },
        entry_serial=66,
        func_ea=0x401000,
    )

    _, resolve_handler = _build_state_resolver(
        report,
        TransitionResult(),
        dispatcher,
        flow_graph=flow_graph,
        state_var_stkoff=0x3C,
    )

    assert resolve_handler(0x474EEEBB) == 71


def test_build_state_resolver_preserves_nonraw_semantic_alias_row_over_dispatcher() -> None:
    report = DispatcherTransitionReport(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        state_var_lvar_idx=None,
        pre_header_serial=None,
        initial_state=0x6107F8EC,
        handler_state_map={68: 0x4C77464F},
        handler_range_map={71: (0x474EEEBC, 0x4E69F350)},
        condition_chain_blocks=(),
        rows=(
            TransitionRow(
                state_const=0x4C77464F,
                state_range_lo=None,
                state_range_hi=None,
                handler_serial=68,
                kind=TransitionKind.CONDITIONAL,
                next_state=None,
                conditional_states=(0x296F2452, 0x474EEEBB),
                state_label="0x474EEEBB",
                transition_label="conditional fallback",
                chain_preview=(15, 16),
                path=TransitionPath(
                    handler_serial=68,
                    chain=(15, 16),
                    next_state=None,
                    conditional_states=(0x296F2452, 0x474EEEBB),
                    back_edge=False,
                    reaches_exit_block=False,
                    classified_exit=False,
                    unresolved=False,
                ),
            ),
        ),
        summary=TransitionSummary(
            handlers_total=1,
            known_count=0,
            conditional_count=1,
            exit_count=0,
            unknown_count=0,
        ),
        diagnostics=(),
    )
    dispatcher = IntervalDispatcher(
        [
            IntervalRow(lo=0x474EEEBC, hi=0x4E69F350, target=71),
        ]
    )
    flow_graph = FlowGraph(
        blocks={
            68: BlockSnapshot(68, 0, (69,), (), 0, 0, ()),
            69: BlockSnapshot(69, 0, (), (68,), 0, 0, ()),
            71: BlockSnapshot(71, 0, (), (), 0, 0, ()),
        },
        entry_serial=68,
        func_ea=0x401000,
    )

    _, resolve_handler = _build_state_resolver(
        report,
        TransitionResult(),
        dispatcher,
        flow_graph=flow_graph,
    )

    assert resolve_handler(0x4C77464F) == 68


def test_embedded_exact_owner_override_preserves_distinct_local_corridor() -> None:
    node = StateDagNode(
        key=StateDagNodeKey(handler_serial=122, state_const=0x00C0C59F),
        kind=StateNodeKind.RANGE_BACKED,
        state_label="State 0x00C0C59F",
        handler_serial=122,
        entry_anchor=122,
        owned_blocks=(122, 45),
        exclusive_blocks=(122, 45),
        shared_suffix_blocks=(),
        local_segments=(
            StateLocalSegment("blk[122]", LocalSegmentKind.STRAIGHT_LINE, (122, 45)),
        ),
        local_edges=(),
    )
    owner = StateDagNode(
        key=StateDagNodeKey(handler_serial=136, state_const=0x139F2922),
        kind=StateNodeKind.EXACT,
        state_label="State 0x139F2922",
        handler_serial=136,
        entry_anchor=136,
        owned_blocks=(136, 142, 151, 88, 122, 45),
        exclusive_blocks=(136, 142, 151, 88),
        shared_suffix_blocks=(122, 45),
        local_segments=(
            StateLocalSegment(
                "blk[136]",
                LocalSegmentKind.STRAIGHT_LINE,
                (136, 142, 151, 88, 122, 45),
            ),
        ),
        local_edges=(),
    )
    terminal = StateDagNode(
        key=StateDagNodeKey(handler_serial=180, state_const=0x2FBA4611),
        kind=StateNodeKind.EXACT,
        state_label="State 0x2FBA4611",
        handler_serial=180,
        entry_anchor=180,
        owned_blocks=(180,),
        exclusive_blocks=(180,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    node_edge = StateDagEdge(
        kind=SemanticEdgeKind.TRANSITION,
        source_key=node.key,
        target_key=terminal.key,
        target_state=0x2FBA4611,
        target_entry_anchor=180,
        target_label=terminal.state_label,
        source_anchor=StateRedirectAnchor(
            kind=RedirectSourceKind.UNCONDITIONAL,
            block_serial=45,
        ),
        ordered_path=(122, 45),
        last_write_site=(45, 0x180013000),
    )
    owner_edge = StateDagEdge(
        kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
        source_key=owner.key,
        target_key=terminal.key,
        target_state=0x2FBA4611,
        target_entry_anchor=180,
        target_label=terminal.state_label,
        source_anchor=StateRedirectAnchor(
            kind=RedirectSourceKind.CONDITIONAL_BRANCH,
            block_serial=136,
            branch_arm=1,
        ),
        ordered_path=(136, 142, 151, 88, 122, 45),
        last_write_site=(45, 0x180013004),
    )

    assert (
        _resolve_embedded_exact_owner_override(
            node,
            [node, owner, terminal],
            (node_edge,),
            {
                node.key: (node_edge,),
                owner.key: (owner_edge,),
                terminal.key: (),
            },
            canonical_handler_states={0x139F2922, 0x2FBA4611},
        )
        is None
    )


def test_sub7ffd_corridor_dispatcher_anchor_override_prefers_dispatcher_body() -> None:
    assert _resolve_sub7ffd_corridor_dispatcher_anchor_override(
        0x0B2FECE0,
        selected_anchor=132,
        dispatcher_anchor=130,
        dispatcher_exact_anchor=None,
        cover_anchor=132,
        family_fallback_anchor=155,
        bridge_anchor=116,
    ) == 130

    assert (
        _resolve_sub7ffd_corridor_dispatcher_anchor_override(
            0x0B2FECE0,
            selected_anchor=130,
            dispatcher_anchor=130,
            dispatcher_exact_anchor=None,
            cover_anchor=132,
            family_fallback_anchor=155,
            bridge_anchor=116,
        )
        is None
    )


def test_sub7ffd_corridor_dispatcher_exact_override_keeps_semantic_child_anchor() -> None:
    assert (
        _resolve_sub7ffd_corridor_dispatcher_anchor_override(
            0x4E69F350,
            selected_anchor=161,
            dispatcher_anchor=71,
            dispatcher_exact_anchor=72,
            cover_anchor=70,
            family_fallback_anchor=14,
            bridge_anchor=159,
        )
        is None
    )


def test_sub7ffd_corridor_dispatcher_exact_override_does_not_force_4e69_dispatcher_row() -> None:
    assert (
        _resolve_sub7ffd_corridor_dispatcher_anchor_override(
            0x4E69F350,
            selected_anchor=71,
            dispatcher_anchor=71,
            dispatcher_exact_anchor=72,
            cover_anchor=71,
            family_fallback_anchor=None,
            bridge_anchor=159,
        )
        is None
    )


def test_alias_label_override_preserves_node_local_prefix_over_prelude_collapse() -> None:
    flow_graph = FlowGraph(
        blocks={
            122: BlockSnapshot(122, 0, (45,), (), 0, 0, ()),
            45: BlockSnapshot(45, 0, (), (122,), 0, 0, ()),
        },
        entry_serial=122,
        func_ea=0x401000,
    )
    node = StateDagNode(
        key=StateDagNodeKey(handler_serial=122, state_const=0x00C0C59F),
        kind=StateNodeKind.RANGE_BACKED,
        state_label="State 0x00C0C59F",
        handler_serial=122,
        entry_anchor=122,
        owned_blocks=(122, 45),
        exclusive_blocks=(122, 45),
        shared_suffix_blocks=(),
        local_segments=(
            StateLocalSegment("blk[122]", LocalSegmentKind.STRAIGHT_LINE, (122, 45)),
        ),
        local_edges=(),
    )
    terminal = StateDagNode(
        key=StateDagNodeKey(handler_serial=180, state_const=0x2FBA4611),
        kind=StateNodeKind.EXACT,
        state_label="State 0x2FBA4611",
        handler_serial=180,
        entry_anchor=180,
        owned_blocks=(180,),
        exclusive_blocks=(180,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    incoming_edge = StateDagEdge(
        kind=SemanticEdgeKind.TRANSITION,
        source_key=StateDagNodeKey(handler_serial=69, state_const=0x63D54755),
        target_key=node.key,
        target_state=0x00C0C59F,
        target_entry_anchor=122,
        target_label=node.state_label,
        source_anchor=StateRedirectAnchor(
            kind=RedirectSourceKind.UNCONDITIONAL,
            block_serial=122,
        ),
        ordered_path=(),
        last_write_site=None,
    )
    outgoing_edge = StateDagEdge(
        kind=SemanticEdgeKind.TRANSITION,
        source_key=node.key,
        target_key=terminal.key,
        target_state=0x2FBA4611,
        target_entry_anchor=180,
        target_label=terminal.state_label,
        source_anchor=StateRedirectAnchor(
            kind=RedirectSourceKind.UNCONDITIONAL,
            block_serial=45,
        ),
        ordered_path=(122, 45),
        last_write_site=(45, 0x180013000),
    )
    prelude_edge = StateDagEdge(
        kind=SemanticEdgeKind.TRANSITION,
        source_key=StateDagNodeKey(handler_serial=45, state_const=0x139F2922),
        target_key=terminal.key,
        target_state=0x2FBA4611,
        target_entry_anchor=180,
        target_label=terminal.state_label,
        source_anchor=StateRedirectAnchor(
            kind=RedirectSourceKind.UNCONDITIONAL,
            block_serial=45,
        ),
        ordered_path=(45,),
        last_write_site=(45, 0x180013004),
    )

    report = DispatcherTransitionReport(
        dispatcher_entry_serial=0,
        state_var_stkoff=0,
        state_var_lvar_idx=None,
        pre_header_serial=None,
        initial_state=None,
        handler_state_map={
            45: 0x139F2922,
            122: 0x00C0C59F,
            180: 0x2FBA4611,
        },
        handler_range_map={},
        condition_chain_blocks=(),
        rows=(),
        summary=TransitionSummary(
            handlers_total=0,
            known_count=0,
            conditional_count=0,
            exit_count=0,
            unknown_count=0,
        ),
        diagnostics=(),
    )

    assert (
        _compute_alias_label_override(
            node,
            (incoming_edge,),
            (outgoing_edge,),
            report,
            flow_graph,
            {45: (prelude_edge,)},
            {
                0x00C0C59F: (outgoing_edge,),
                0x139F2922: (prelude_edge,),
            },
            {0x139F2922, 0x2FBA4611},
            prefer_local_corridors=False,
        )
        is None
    )


def test_alias_label_override_rejects_sibling_prelude_from_branch_source() -> None:
    flow_graph = FlowGraph(
        blocks={
            81: BlockSnapshot(81, 0, (82, 83), (), 0, 0, ()),
            82: BlockSnapshot(82, 0, (), (81,), 0, 0, ()),
            83: BlockSnapshot(83, 0, (), (81,), 0, 0, ()),
        },
        entry_serial=81,
        func_ea=0x401100,
    )
    node = StateDagNode(
        key=StateDagNodeKey(handler_serial=83, state_const=0x45B18E82),
        kind=StateNodeKind.EXACT,
        state_label="0x45B18E82",
        handler_serial=83,
        entry_anchor=83,
        owned_blocks=(83,),
        exclusive_blocks=(83,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    incoming_edge = StateDagEdge(
        kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
        source_key=StateDagNodeKey(handler_serial=81, state_const=0x5FE86821),
        target_key=node.key,
        target_state=0x45B18E82,
        target_entry_anchor=83,
        target_label=node.state_label,
        source_anchor=StateRedirectAnchor(
            kind=RedirectSourceKind.CONDITIONAL_BRANCH,
            block_serial=81,
            branch_arm=0,
        ),
        ordered_path=(81, 82),
        last_write_site=None,
    )
    outgoing_edge = StateDagEdge(
        kind=SemanticEdgeKind.UNKNOWN,
        source_key=node.key,
        target_key=None,
        target_state=None,
        target_entry_anchor=None,
        target_label="unknown",
        source_anchor=StateRedirectAnchor(
            kind=RedirectSourceKind.UNCONDITIONAL,
            block_serial=83,
        ),
        ordered_path=(83,),
        last_write_site=None,
    )
    sibling_edge = StateDagEdge(
        kind=SemanticEdgeKind.TRANSITION,
        source_key=StateDagNodeKey(handler_serial=83, state_const=0x606DC166),
        target_key=None,
        target_state=0x02760C0D,
        target_entry_anchor=117,
        target_label="0x02760C0D",
        source_anchor=StateRedirectAnchor(
            kind=RedirectSourceKind.UNCONDITIONAL,
            block_serial=83,
        ),
        ordered_path=(83,),
        last_write_site=None,
    )
    report = DispatcherTransitionReport(
        dispatcher_entry_serial=0,
        state_var_stkoff=0,
        state_var_lvar_idx=None,
        pre_header_serial=None,
        initial_state=None,
        handler_state_map={117: 0x02760C0D},
        handler_range_map={},
        condition_chain_blocks=(),
        rows=(),
        summary=TransitionSummary(
            handlers_total=0,
            known_count=0,
            conditional_count=0,
            exit_count=0,
            unknown_count=0,
        ),
        diagnostics=(),
    )

    assert (
        _compute_alias_label_override(
            node,
            (incoming_edge,),
            (outgoing_edge,),
            report,
            flow_graph,
            {83: (sibling_edge,)},
            {0x45B18E82: (outgoing_edge,), 0x606DC166: (sibling_edge,)},
            {0x02760C0D},
            prefer_local_corridors=False,
        )
        is None
    )


def test_alias_label_override_preserves_dispatcher_body_anchor_for_upper_gap_collapse() -> None:
    flow_graph = FlowGraph(
        blocks={
            78: BlockSnapshot(78, 0, (14,), (), 0, 0, ()),
            80: BlockSnapshot(80, 0, (118,), (), 0, 0, ()),
            81: BlockSnapshot(81, 0, (82, 83), (), 0, 0, ()),
            104: BlockSnapshot(104, 0, (118,), (), 0, 0, ()),
            111: BlockSnapshot(111, 0, (81,), (), 0, 0, ()),
            118: BlockSnapshot(118, 0, (), (), 0, 0, ()),
        },
        entry_serial=78,
        func_ea=0x401000,
    )
    node = StateDagNode(
        key=StateDagNodeKey(handler_serial=80, state_const=0x604AAEA6),
        kind=StateNodeKind.RANGE_BACKED,
        state_label="0x604AAEA6",
        handler_serial=80,
        entry_anchor=81,
        owned_blocks=(81,),
        exclusive_blocks=(81,),
        shared_suffix_blocks=(),
        local_segments=(
            StateLocalSegment("blk[81]", LocalSegmentKind.BRANCH, (81,)),
        ),
        local_edges=(),
    )
    incoming_edge = StateDagEdge(
        kind=SemanticEdgeKind.TRANSITION,
        source_key=StateDagNodeKey(handler_serial=111, state_const=0x3FFC21D1),
        target_key=node.key,
        target_state=0x604AAEA6,
        target_entry_anchor=81,
        target_label=node.state_label,
        source_anchor=StateRedirectAnchor(
            kind=RedirectSourceKind.UNCONDITIONAL,
            block_serial=111,
        ),
        ordered_path=(111,),
        last_write_site=None,
    )
    outgoing_edge = StateDagEdge(
        kind=SemanticEdgeKind.TRANSITION,
        source_key=node.key,
        target_key=None,
        target_state=0x606DC166,
        target_entry_anchor=14,
        target_label="0x606DC166",
        source_anchor=StateRedirectAnchor(
            kind=RedirectSourceKind.UNCONDITIONAL,
            block_serial=104,
        ),
        ordered_path=(80, 104),
        last_write_site=(104, 0x180010400),
    )
    bridge_edge = StateDagEdge(
        kind=SemanticEdgeKind.TRANSITION,
        source_key=StateDagNodeKey(handler_serial=78, state_const=0x5D0AEBD3),
        target_key=None,
        target_state=0x606DC166,
        target_entry_anchor=14,
        target_label="0x606DC166",
        source_anchor=StateRedirectAnchor(
            kind=RedirectSourceKind.UNCONDITIONAL,
            block_serial=78,
        ),
        ordered_path=(78, 80, 104),
        last_write_site=(78, 0x180010078),
    )
    report = DispatcherTransitionReport(
        dispatcher_entry_serial=79,
        state_var_stkoff=0,
        state_var_lvar_idx=None,
        pre_header_serial=None,
        initial_state=0x5D0AEBD3,
        handler_state_map={
            78: 0x5D0AEBD3,
            81: 0x5FE86821,
            14: 0x606DC166,
        },
        handler_range_map={80: (0x5FE86822, 0x606DC165)},
        condition_chain_blocks=(79,),
        rows=(
            TransitionRow(
                state_const=0x5D0AEBD3,
                state_range_lo=None,
                state_range_hi=None,
                handler_serial=78,
                kind=TransitionKind.TRANSITION,
                next_state=0x606DC166,
                conditional_states=(),
                state_label="0x5D0AEBD3",
                transition_label="transition",
                chain_preview=(78, 80),
                path=TransitionPath(
                    handler_serial=78,
                    chain=(78, 80),
                    next_state=0x606DC166,
                    conditional_states=(),
                    back_edge=True,
                    reaches_exit_block=False,
                    classified_exit=False,
                    unresolved=False,
                ),
            ),
            TransitionRow(
                state_const=0x5FE86821,
                state_range_lo=None,
                state_range_hi=None,
                handler_serial=81,
                kind=TransitionKind.CONDITIONAL,
                next_state=None,
                conditional_states=(0x02760C0D, 0x45B18E82),
                state_label="0x5FE86821",
                transition_label="conditional",
                chain_preview=(81,),
                path=TransitionPath(
                    handler_serial=81,
                    chain=(81,),
                    next_state=None,
                    conditional_states=(0x02760C0D, 0x45B18E82),
                    back_edge=True,
                    reaches_exit_block=False,
                    classified_exit=False,
                    unresolved=False,
                ),
            ),
            TransitionRow(
                state_const=0x606DC166,
                state_range_lo=None,
                state_range_hi=None,
                handler_serial=14,
                kind=TransitionKind.TRANSITION,
                next_state=0x610BB4D9,
                conditional_states=(),
                state_label="0x606DC166",
                transition_label="transition",
                chain_preview=(14,),
                path=TransitionPath(
                    handler_serial=14,
                    chain=(14,),
                    next_state=0x610BB4D9,
                    conditional_states=(),
                    back_edge=True,
                    reaches_exit_block=False,
                    classified_exit=False,
                    unresolved=False,
                ),
            ),
        ),
        summary=TransitionSummary(
            handlers_total=3,
            known_count=3,
            conditional_count=1,
            exit_count=0,
            unknown_count=0,
        ),
        diagnostics=(),
    )

    assert _compute_alias_label_override(
        node,
        (incoming_edge,),
        (outgoing_edge,),
        report,
        flow_graph,
        {},
        {
            0x5D0AEBD3: (bridge_edge,),
            0x604AAEA6: (outgoing_edge,),
        },
        {0x5D0AEBD3, 0x5FE86821, 0x606DC166},
        prefer_local_corridors=True,
    ) == ("0x606DC166_fallback", 80, True)


def test_alias_label_override_preserves_dispatcher_body_anchor_for_cover_collapse() -> None:
    flow_graph = FlowGraph(
        blocks={
            78: BlockSnapshot(78, 0, (14,), (), 0, 0, ()),
            80: BlockSnapshot(80, 0, (118,), (), 0, 0, ()),
            118: BlockSnapshot(118, 0, (), (), 0, 0, ()),
        },
        entry_serial=78,
        func_ea=0x401000,
    )
    node = StateDagNode(
        key=StateDagNodeKey(handler_serial=80, state_const=0x604AAEA6),
        kind=StateNodeKind.EXACT,
        state_label="0x606DC166_fallback",
        handler_serial=80,
        entry_anchor=78,
        owned_blocks=(78,),
        exclusive_blocks=(78,),
        shared_suffix_blocks=(),
        local_segments=(
            StateLocalSegment("blk[78]", LocalSegmentKind.STRAIGHT_LINE, (78,)),
        ),
        local_edges=(),
    )
    outgoing_edge = StateDagEdge(
        kind=SemanticEdgeKind.TRANSITION,
        source_key=node.key,
        target_key=None,
        target_state=0x029EEE50,
        target_entry_anchor=118,
        target_label="0x029EEE50",
        source_anchor=StateRedirectAnchor(
            kind=RedirectSourceKind.UNCONDITIONAL,
            block_serial=104,
        ),
        ordered_path=(80, 104),
        last_write_site=(104, 0x180010400),
    )
    report = DispatcherTransitionReport(
        dispatcher_entry_serial=79,
        state_var_stkoff=0,
        state_var_lvar_idx=None,
        pre_header_serial=None,
        initial_state=0x5D0AEBD3,
        handler_state_map={
            81: 0x5FE86821,
            80: 0x606DC165,
        },
        handler_range_map={80: (0x5FE86822, 0x606DC165)},
        condition_chain_blocks=(79,),
        rows=(
            TransitionRow(
                state_const=0x5FE86821,
                state_range_lo=None,
                state_range_hi=None,
                handler_serial=81,
                kind=TransitionKind.CONDITIONAL,
                next_state=None,
                conditional_states=(0x02760C0D, 0x45B18E82),
                state_label="0x5FE86821",
                transition_label="conditional",
                chain_preview=(81,),
                path=TransitionPath(
                    handler_serial=81,
                    chain=(81,),
                    next_state=None,
                    conditional_states=(0x02760C0D, 0x45B18E82),
                    back_edge=True,
                    reaches_exit_block=False,
                    classified_exit=False,
                    unresolved=False,
                ),
            ),
        ),
        summary=TransitionSummary(
            handlers_total=1,
            known_count=1,
            conditional_count=1,
            exit_count=0,
            unknown_count=0,
        ),
        diagnostics=(),
    )

    assert _compute_alias_label_override(
        node,
        (),
        (outgoing_edge,),
        report,
        flow_graph,
        {},
        {},
        {0x5FE86821},
        prefer_local_corridors=True,
    ) == ("0x5FE86821_fallback", 80, True)


def _make_branch_transition_result() -> TransitionResult:
    trans_10 = StateTransition(
        from_state=0x10,
        to_state=0x20,
        from_block=1,
        is_conditional=False,
    )
    trans_20_a = StateTransition(
        from_state=0x20,
        to_state=0x30,
        from_block=2,
        condition_block=2,
        is_conditional=True,
    )
    trans_20_b = StateTransition(
        from_state=0x20,
        to_state=0x40,
        from_block=2,
        condition_block=2,
        is_conditional=True,
    )
    return TransitionResult(
        transitions=[trans_10, trans_20_a, trans_20_b],
        handlers={
            0x10: StateHandler(
                state_value=0x10,
                check_block=1,
                handler_blocks=[1],
                transitions=[trans_10],
            ),
            0x20: StateHandler(
                state_value=0x20,
                check_block=2,
                handler_blocks=[2],
                transitions=[trans_20_a, trans_20_b],
            ),
            0x30: StateHandler(
                state_value=0x30,
                check_block=3,
                handler_blocks=[3, 4],
                transitions=[],
            ),
            0x40: StateHandler(
                state_value=0x40,
                check_block=7,
                handler_blocks=[7],
                transitions=[],
            ),
        },
        initial_state=0x10,
        pre_header_serial=9,
        strategy_name="fixture",
        resolved_count=3,
    )


def test_branch_anchors_and_local_cfg_are_preserved() -> None:
    flow_graph = _make_branch_flow_graph()
    transition_result = _make_branch_transition_result()
    report = build_dispatcher_transition_report_from_graph(
        flow_graph=flow_graph,
        transition_result=transition_result,
        dispatcher_entry_serial=5,
    )

    dag = build_linearized_state_dag_from_graph(
        flow_graph,
        report,
        transition_result,
        handler_paths_by_handler={
            2: (
                HandlerPathResult(
                    exit_block=3,
                    final_state=0x30,
                    state_writes=[(2, 0x1000)],
                    ordered_path=[2, 3],
                ),
                HandlerPathResult(
                    exit_block=7,
                    final_state=0x40,
                    state_writes=[(2, 0x1004)],
                    ordered_path=[2, 7],
                ),
            ),
        },
        conditional_transitions_by_handler={
            2: (
                ConditionalTransition(
                    handler_entry=2,
                    branch_block=2,
                    target_state=0x30,
                    target_handler=3,
                    state_write_block=2,
                    state_write_ea=0x1000,
                    branch_arm=0,
                ),
                ConditionalTransition(
                    handler_entry=2,
                    branch_block=2,
                    target_state=0x40,
                    target_handler=7,
                    state_write_block=2,
                    state_write_ea=0x1004,
                    branch_arm=1,
                ),
            ),
        },
    )

    handler_20 = next(node for node in dag.nodes if node.handler_serial == 2)
    assert handler_20.kind == StateNodeKind.EXACT
    assert {edge.kind for edge in handler_20.local_edges} == {
        LocalEdgeKind.FALLTHROUGH,
        LocalEdgeKind.TAKEN,
    }

    outgoing = [
        edge
        for edge in dag.edges
        if edge.source_key.handler_serial == 2
        and edge.kind == SemanticEdgeKind.CONDITIONAL_TRANSITION
    ]
    assert {(edge.source_anchor.block_serial, edge.source_anchor.branch_arm) for edge in outgoing} == {
        (2, 0),
        (2, 1),
    }
    assert {(edge.target_state, edge.target_entry_anchor) for edge in outgoing} == {
        (0x30, 3),
        (0x40, 7),
    }

    rendered = render_linearized_state_dag(dag)
    assert "src=blk[2].fallthrough -> 0x00000030 entry=blk[3]" in rendered
    assert "src=blk[2].taken -> 0x00000040 entry=blk[7]" in rendered


def test_render_linearized_state_program_uses_state_labels_and_branch_pairs() -> None:
    flow_graph = _make_branch_flow_graph()
    transition_result = _make_branch_transition_result()
    report = build_dispatcher_transition_report_from_graph(
        flow_graph=flow_graph,
        transition_result=transition_result,
        dispatcher_entry_serial=5,
    )
    dag = build_linearized_state_dag_from_graph(
        flow_graph,
        report,
        transition_result,
        dispatcher=_AlwaysDispatcher(7),
        handler_paths_by_handler={
            2: (
                HandlerPathResult(
                    exit_block=3,
                    final_state=0x30,
                    state_writes=[(2, 0x1000)],
                    ordered_path=[2, 3],
                ),
                HandlerPathResult(
                    exit_block=7,
                    final_state=0x40,
                    state_writes=[(2, 0x1004)],
                    ordered_path=[2, 7],
                ),
            ),
        },
        conditional_transitions_by_handler={
            2: (
                ConditionalTransition(
                    handler_entry=2,
                    branch_block=2,
                    target_state=0x30,
                    target_handler=3,
                    state_write_block=2,
                    state_write_ea=0x1000,
                    branch_arm=0,
                ),
                ConditionalTransition(
                    handler_entry=2,
                    branch_block=2,
                    target_state=0x40,
                    target_handler=7,
                    state_write_block=2,
                    state_write_ea=0x1004,
                    branch_arm=1,
                ),
            ),
        },
    )

    rendered = render_linearized_state_program(dag)
    assert "STATE_00000020:" in rendered
    assert "STATE_00000030:" in rendered
    assert "STATE_00000040:" in rendered
    assert "if (/* blk[2].taken */)" in rendered
    assert "goto STATE_00000040;" in rendered
    assert "goto STATE_00000030;  // blk[2].fallthrough" in rendered


def test_render_linearized_state_program_can_use_ida_block_serial_labels() -> None:
    flow_graph = _make_branch_flow_graph()
    transition_result = _make_branch_transition_result()
    report = build_dispatcher_transition_report_from_graph(
        flow_graph=flow_graph,
        transition_result=transition_result,
        dispatcher_entry_serial=5,
    )
    dag = build_linearized_state_dag_from_graph(
        flow_graph,
        report,
        transition_result,
        dispatcher=_AlwaysDispatcher(7),
        handler_paths_by_handler={
            2: (
                HandlerPathResult(
                    exit_block=3,
                    final_state=0x30,
                    state_writes=[(2, 0x1000)],
                    ordered_path=[2, 3],
                ),
                HandlerPathResult(
                    exit_block=7,
                    final_state=0x40,
                    state_writes=[(2, 0x1004)],
                    ordered_path=[2, 7],
                ),
            ),
        },
        conditional_transitions_by_handler={
            2: (
                ConditionalTransition(
                    handler_entry=2,
                    branch_block=2,
                    target_state=0x30,
                    target_handler=3,
                    state_write_block=2,
                    state_write_ea=0x1000,
                    branch_arm=0,
                ),
                ConditionalTransition(
                    handler_entry=2,
                    branch_block=2,
                    target_state=0x40,
                    target_handler=7,
                    state_write_block=2,
                    state_write_ea=0x1004,
                    branch_arm=1,
                ),
            ),
        },
    )

    rendered = render_linearized_state_program(
        dag,
        label_render_mode=LabelRenderMode.IDA_BLOCK_SERIAL,
    )

    assert "LABEL_2:" in rendered
    assert "LABEL_3:" in rendered
    assert "LABEL_7:" in rendered
    assert "// state-family: STATE_00000020" in rendered
    assert "// state-family: STATE_00000030" in rendered
    assert "// state-family: STATE_00000040" in rendered
    assert "goto LABEL_7;  /* STATE_00000040 */" in rendered
    assert (
        "goto LABEL_3;  /* STATE_00000030 */  // blk[2].fallthrough" in rendered
    )
    assert "STATE_00000020:" not in rendered


def test_render_linearized_state_program_renders_fallback_and_exit_routine() -> None:
    fallback_key = StateDagNodeKey(handler_serial=34, state_const=0x27EEEA11)
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=0x27EEEA11,
        condition_chain_blocks=(),
        nodes=(
            StateDagNode(
                key=fallback_key,
                kind=StateNodeKind.RANGE_BACKED,
                state_label="0x27EEEA11_fallback",
                handler_serial=34,
                entry_anchor=34,
                owned_blocks=(34, 35),
                exclusive_blocks=(34,),
                shared_suffix_blocks=(35,),
                local_segments=(
                    StateLocalSegment(
                        segment_id="seg0",
                        kind=LocalSegmentKind.STRAIGHT_LINE,
                        blocks=(34, 35),
                    ),
                ),
                local_edges=(),
            ),
        ),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.EXIT_ROUTINE,
                source_key=fallback_key,
                target_key=None,
                target_state=None,
                target_entry_anchor=None,
                target_label="EXIT_ROUTINE",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.UNCONDITIONAL,
                    block_serial=35,
                ),
                ordered_path=(34, 35),
            ),
        ),
    )

    rendered = render_linearized_state_program(dag)
    assert "STATE_27EEEA11_fallback:" in rendered
    assert "goto EXIT_ROUTINE;" in rendered
    assert "EXIT_ROUTINE:" in rendered
    assert "return result;" in rendered


def test_render_linearized_state_program_disambiguates_colliding_labels() -> None:
    source_key = StateDagNodeKey(handler_serial=10, state_const=0x11111111)
    fallback_a_key = StateDagNodeKey(handler_serial=12, state_const=0x64AFC49D)
    fallback_b_key = StateDagNodeKey(handler_serial=34, state_const=0x64AFC49D)
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=0x11111111,
        condition_chain_blocks=(),
        nodes=(
            StateDagNode(
                key=source_key,
                kind=StateNodeKind.EXACT,
                state_label="0x11111111",
                handler_serial=10,
                entry_anchor=10,
                owned_blocks=(10,),
                exclusive_blocks=(10,),
                shared_suffix_blocks=(),
                local_segments=(),
                local_edges=(),
            ),
            StateDagNode(
                key=fallback_a_key,
                kind=StateNodeKind.EXACT,
                state_label="0x64AFC49D_fallback",
                handler_serial=12,
                entry_anchor=12,
                owned_blocks=(12,),
                exclusive_blocks=(12,),
                shared_suffix_blocks=(),
                local_segments=(),
                local_edges=(),
            ),
            StateDagNode(
                key=fallback_b_key,
                kind=StateNodeKind.EXACT,
                state_label="0x64AFC49D_fallback",
                handler_serial=34,
                entry_anchor=34,
                owned_blocks=(34, 35),
                exclusive_blocks=(34, 35),
                shared_suffix_blocks=(),
                local_segments=(),
                local_edges=(),
            ),
        ),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
                source_key=source_key,
                target_key=fallback_a_key,
                target_state=0x64AFC49D,
                target_entry_anchor=12,
                target_label="0x64AFC49D_fallback",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                    block_serial=10,
                    branch_arm=0,
                ),
                ordered_path=(10, 12),
            ),
            StateDagEdge(
                kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
                source_key=source_key,
                target_key=fallback_b_key,
                target_state=0x64AFC49D,
                target_entry_anchor=34,
                target_label="0x64AFC49D_fallback",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                    block_serial=10,
                    branch_arm=1,
                ),
                ordered_path=(10, 34),
            ),
        ),
    )

    rendered = render_linearized_state_program(dag)
    label_a = "STATE_64AFC49D_fallback__blk12_h12_s64AFC49D"
    label_b = "STATE_64AFC49D_fallback__blk34_h34_s64AFC49D"

    assert rendered.count(f"{label_a}:") == 1
    assert rendered.count(f"{label_b}:") == 1
    assert f"goto {label_b};" in rendered
    assert f"goto {label_a};  // blk[10].fallthrough" in rendered


def test_render_linearized_state_program_explicitly_emits_local_segments() -> None:
    node_key = StateDagNodeKey(handler_serial=20, state_const=0x20)
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=0x20,
        condition_chain_blocks=(),
        nodes=(
            StateDagNode(
                key=node_key,
                kind=StateNodeKind.EXACT,
                state_label="0x00000020",
                handler_serial=20,
                entry_anchor=20,
                owned_blocks=(20, 21, 22),
                exclusive_blocks=(20, 21, 22),
                shared_suffix_blocks=(),
                local_segments=(
                    StateLocalSegment(
                        segment_id="blk[20]",
                        kind=LocalSegmentKind.BRANCH,
                        blocks=(20,),
                    ),
                    StateLocalSegment(
                        segment_id="blk[21]",
                        kind=LocalSegmentKind.STRAIGHT_LINE,
                        blocks=(21,),
                    ),
                    StateLocalSegment(
                        segment_id="blk[22]",
                        kind=LocalSegmentKind.GOTO_LABEL,
                        blocks=(22,),
                    ),
                ),
                local_edges=(
                    StateLocalEdge(
                        source_segment_id="blk[20]",
                        target_segment_id="blk[21]",
                        kind=LocalEdgeKind.FALLTHROUGH,
                        branch_arm=0,
                    ),
                    StateLocalEdge(
                        source_segment_id="blk[21]",
                        target_segment_id="blk[22]",
                        kind=LocalEdgeKind.GOTO,
                    ),
                ),
            ),
            StateDagNode(
                key=StateDagNodeKey(handler_serial=30, state_const=0x30),
                kind=StateNodeKind.EXACT,
                state_label="0x00000030",
                handler_serial=30,
                entry_anchor=30,
                owned_blocks=(30,),
                exclusive_blocks=(30,),
                shared_suffix_blocks=(),
                local_segments=(),
                local_edges=(),
            ),
        ),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
                source_key=node_key,
                target_key=StateDagNodeKey(handler_serial=30, state_const=0x30),
                target_state=0x30,
                target_entry_anchor=30,
                target_label="0x00000030",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                    block_serial=20,
                    branch_arm=1,
                ),
                ordered_path=(20, 30),
            ),
        ),
    )

    rendered = render_linearized_state_program(
        dag,
        program_strategy=ProgramRenderStrategy.LOCAL_SEGMENT_EXPLICIT,
    )

    assert "STATE_00000020:" in rendered
    assert "goto STATE_00000020__blk_20;" in rendered
    assert "STATE_00000020__blk_20:" in rendered
    assert "STATE_00000020__blk_21:" in rendered
    assert "STATE_00000020__blk_22:" in rendered
    assert "goto STATE_00000030;" in rendered
    assert "goto STATE_00000020__blk_21;  // blk[20].fallthrough" in rendered


def test_render_linearized_state_program_selectively_collapses_local_corridors() -> None:
    source_key = StateDagNodeKey(handler_serial=20, state_const=0x20)
    target_key = StateDagNodeKey(handler_serial=30, state_const=0x30)
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=0x20,
        condition_chain_blocks=(),
        nodes=(
            StateDagNode(
                key=source_key,
                kind=StateNodeKind.EXACT,
                state_label="0x00000020",
                handler_serial=20,
                entry_anchor=20,
                owned_blocks=(20, 21, 22, 23),
                exclusive_blocks=(20, 21, 22, 23),
                shared_suffix_blocks=(23,),
                local_segments=(
                    StateLocalSegment(
                        segment_id="blk[20]",
                        kind=LocalSegmentKind.BRANCH,
                        blocks=(20,),
                    ),
                    StateLocalSegment(
                        segment_id="blk[21]",
                        kind=LocalSegmentKind.BRANCH,
                        blocks=(21,),
                    ),
                    StateLocalSegment(
                        segment_id="blk[22]",
                        kind=LocalSegmentKind.STRAIGHT_LINE,
                        blocks=(22,),
                    ),
                    StateLocalSegment(
                        segment_id="blk[23]",
                        kind=LocalSegmentKind.SHARED_SUFFIX,
                        blocks=(23,),
                    ),
                ),
                local_edges=(
                    StateLocalEdge(
                        source_segment_id="blk[20]",
                        target_segment_id="blk[21]",
                        kind=LocalEdgeKind.FALLTHROUGH,
                        branch_arm=0,
                    ),
                    StateLocalEdge(
                        source_segment_id="blk[21]",
                        target_segment_id="blk[22]",
                        kind=LocalEdgeKind.FALLTHROUGH,
                        branch_arm=0,
                    ),
                    StateLocalEdge(
                        source_segment_id="blk[21]",
                        target_segment_id="blk[23]",
                        kind=LocalEdgeKind.TAKEN,
                        branch_arm=1,
                    ),
                    StateLocalEdge(
                        source_segment_id="blk[22]",
                        target_segment_id="blk[23]",
                        kind=LocalEdgeKind.GOTO,
                    ),
                ),
            ),
            StateDagNode(
                key=target_key,
                kind=StateNodeKind.EXACT,
                state_label="0x00000030",
                handler_serial=30,
                entry_anchor=30,
                owned_blocks=(30,),
                exclusive_blocks=(30,),
                shared_suffix_blocks=(),
                local_segments=(),
                local_edges=(),
            ),
        ),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
                source_key=source_key,
                target_key=target_key,
                target_state=0x30,
                target_entry_anchor=30,
                target_label="0x00000030",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                    block_serial=20,
                    branch_arm=1,
                ),
                ordered_path=(20, 30),
            ),
            StateDagEdge(
                kind=SemanticEdgeKind.TRANSITION,
                source_key=source_key,
                target_key=target_key,
                target_state=0x30,
                target_entry_anchor=30,
                target_label="0x00000030",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.UNCONDITIONAL,
                    block_serial=23,
                ),
                ordered_path=(23, 30),
            ),
        ),
    )

    rendered = render_linearized_state_program(
        dag,
        program_strategy=ProgramRenderStrategy.LOCAL_BOUNDARY_SELECTIVE,
    )

    assert "STATE_00000020:" in rendered
    assert "if (/* blk[20].taken */)" in rendered
    assert "goto STATE_00000020__blk_23;" in rendered
    assert "STATE_00000020__blk_23:" in rendered
    assert "STATE_00000020__blk_21:" not in rendered
    assert "STATE_00000020__blk_22:" not in rendered


def test_render_linearized_state_program_inlines_one_boundary_level() -> None:
    source_key = StateDagNodeKey(handler_serial=20, state_const=0x20)
    target_a_key = StateDagNodeKey(handler_serial=30, state_const=0x30)
    target_b_key = StateDagNodeKey(handler_serial=40, state_const=0x40)
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=0x20,
        condition_chain_blocks=(),
        nodes=(
            StateDagNode(
                key=source_key,
                kind=StateNodeKind.EXACT,
                state_label="0x00000020",
                handler_serial=20,
                entry_anchor=20,
                owned_blocks=(20, 21),
                exclusive_blocks=(20, 21),
                shared_suffix_blocks=(),
                local_segments=(
                    StateLocalSegment(
                        segment_id="blk[20]",
                        kind=LocalSegmentKind.BRANCH,
                        blocks=(20,),
                    ),
                    StateLocalSegment(
                        segment_id="blk[21]",
                        kind=LocalSegmentKind.BRANCH,
                        blocks=(21,),
                    ),
                ),
                local_edges=(
                    StateLocalEdge(
                        source_segment_id="blk[20]",
                        target_segment_id="blk[21]",
                        kind=LocalEdgeKind.FALLTHROUGH,
                        branch_arm=0,
                    ),
                ),
            ),
            StateDagNode(
                key=target_a_key,
                kind=StateNodeKind.EXACT,
                state_label="0x00000030",
                handler_serial=30,
                entry_anchor=30,
                owned_blocks=(30,),
                exclusive_blocks=(30,),
                shared_suffix_blocks=(),
                local_segments=(),
                local_edges=(),
            ),
            StateDagNode(
                key=target_b_key,
                kind=StateNodeKind.EXACT,
                state_label="0x00000040",
                handler_serial=40,
                entry_anchor=40,
                owned_blocks=(40,),
                exclusive_blocks=(40,),
                shared_suffix_blocks=(),
                local_segments=(),
                local_edges=(),
            ),
        ),
        edges=(
                StateDagEdge(
                    kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
                    source_key=source_key,
                    target_key=target_b_key,
                    target_state=0x40,
                    target_entry_anchor=40,
                    target_label="0x00000040",
                    source_anchor=StateRedirectAnchor(
                        kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                        block_serial=21,
                        branch_arm=1,
                    ),
                    ordered_path=(21, 40),
                ),
                StateDagEdge(
                    kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
                    source_key=source_key,
                    target_key=target_a_key,
                    target_state=0x30,
                    target_entry_anchor=30,
                    target_label="0x00000030",
                    source_anchor=StateRedirectAnchor(
                        kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                        block_serial=21,
                        branch_arm=0,
                    ),
                    ordered_path=(21, 30),
                ),
            ),
        )

    rendered = render_linearized_state_program(
        dag,
        program_strategy=ProgramRenderStrategy.LOCAL_BOUNDARY_SELECTIVE,
        boundary_inline_mode=BoundaryInlineMode.INLINE_SINGLE_LEVEL,
    )

    assert "STATE_00000020__blk_21:" not in rendered
    assert "if (/* blk[21].taken */)" in rendered
    assert "goto STATE_00000040;" in rendered
    assert "goto STATE_00000030;  // blk[21].fallthrough" in rendered


def test_render_linearized_state_program_renders_block_payload_without_terminal_control() -> None:
    source_key = StateDagNodeKey(handler_serial=20, state_const=0x20)
    target_key = StateDagNodeKey(handler_serial=30, state_const=0x30)
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=0x20,
        condition_chain_blocks=(),
        nodes=(
            StateDagNode(
                key=source_key,
                kind=StateNodeKind.EXACT,
                state_label="0x00000020",
                handler_serial=20,
                entry_anchor=20,
                owned_blocks=(20,),
                exclusive_blocks=(20,),
                shared_suffix_blocks=(),
                local_segments=(
                    StateLocalSegment(
                        segment_id="blk[20]",
                        kind=LocalSegmentKind.BRANCH,
                        blocks=(20,),
                    ),
                ),
                local_edges=(),
            ),
            StateDagNode(
                key=target_key,
                kind=StateNodeKind.EXACT,
                state_label="0x00000030",
                handler_serial=30,
                entry_anchor=30,
                owned_blocks=(30,),
                exclusive_blocks=(30,),
                shared_suffix_blocks=(),
                local_segments=(),
                local_edges=(),
            ),
        ),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
                source_key=source_key,
                target_key=target_key,
                target_state=0x30,
                target_entry_anchor=30,
                target_label="0x00000030",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                    block_serial=20,
                    branch_arm=1,
                ),
                ordered_path=(20, 30),
            ),
            StateDagEdge(
                kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
                source_key=source_key,
                target_key=target_key,
                target_state=0x30,
                target_entry_anchor=30,
                target_label="0x00000030",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                    block_serial=20,
                    branch_arm=0,
                ),
                ordered_path=(20, 30),
            ),
        ),
    )

    rendered = render_linearized_state_program(
        dag,
        order_strategy=RenderOrderStrategy.SEMANTIC,
        program_strategy=ProgramRenderStrategy.LOCAL_BOUNDARY_SELECTIVE,
        block_payload_by_serial={
            20: (
                "var_10 = var_20 + 1",
                "if (var_10 == 0) goto LABEL_30",
            ),
        },
    )

    assert "var_10 = var_20 + 1" in rendered
    assert "if (var_10 == 0) goto LABEL_30" not in rendered
    assert "if (var_10 == 0)" in rendered
    assert "goto STATE_00000030;  // blk[20].fallthrough" in rendered


def test_render_linearized_state_program_structures_simple_collapsed_sidechain() -> None:
    source_key = StateDagNodeKey(handler_serial=20, state_const=0x20)
    target_a_key = StateDagNodeKey(handler_serial=30, state_const=0x30)
    target_b_key = StateDagNodeKey(handler_serial=40, state_const=0x40)
    target_c_key = StateDagNodeKey(handler_serial=50, state_const=0x50)
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=0x20,
        condition_chain_blocks=(),
        nodes=(
            StateDagNode(
                key=source_key,
                kind=StateNodeKind.EXACT,
                state_label="0x00000020",
                handler_serial=20,
                entry_anchor=20,
                owned_blocks=(20, 21, 22),
                exclusive_blocks=(20, 21, 22),
                shared_suffix_blocks=(),
                    local_segments=(
                        StateLocalSegment(
                            segment_id="blk[20]",
                            kind=LocalSegmentKind.BRANCH,
                            blocks=(20,),
                        ),
                        StateLocalSegment(
                            segment_id="blk[21]",
                            kind=LocalSegmentKind.BRANCH,
                            blocks=(21,),
                        ),
                        StateLocalSegment(
                            segment_id="blk[22]",
                            kind=LocalSegmentKind.BRANCH,
                            blocks=(22,),
                        ),
                        StateLocalSegment(
                            segment_id="blk[23]",
                            kind=LocalSegmentKind.STRAIGHT_LINE,
                            blocks=(23,),
                        ),
                    ),
                    local_edges=(
                        StateLocalEdge(
                            source_segment_id="blk[20]",
                            target_segment_id="blk[21]",
                            kind=LocalEdgeKind.FALLTHROUGH,
                            branch_arm=0,
                        ),
                        StateLocalEdge(
                            source_segment_id="blk[21]",
                            target_segment_id="blk[22]",
                            kind=LocalEdgeKind.TAKEN,
                            branch_arm=1,
                        ),
                        StateLocalEdge(
                            source_segment_id="blk[21]",
                            target_segment_id="blk[23]",
                            kind=LocalEdgeKind.FALLTHROUGH,
                            branch_arm=0,
                        ),
                        StateLocalEdge(
                            source_segment_id="blk[23]",
                            target_segment_id="blk[22]",
                            kind=LocalEdgeKind.GOTO,
                        ),
                ),
            ),
            StateDagNode(
                key=target_a_key,
                kind=StateNodeKind.EXACT,
                state_label="0x00000030",
                handler_serial=30,
                entry_anchor=30,
                owned_blocks=(30,),
                exclusive_blocks=(30,),
                shared_suffix_blocks=(),
                local_segments=(),
                local_edges=(),
            ),
            StateDagNode(
                key=target_b_key,
                kind=StateNodeKind.EXACT,
                state_label="0x00000040",
                handler_serial=40,
                entry_anchor=40,
                owned_blocks=(40,),
                exclusive_blocks=(40,),
                shared_suffix_blocks=(),
                local_segments=(),
                local_edges=(),
            ),
            StateDagNode(
                key=target_c_key,
                kind=StateNodeKind.EXACT,
                state_label="0x00000050",
                handler_serial=50,
                entry_anchor=50,
                owned_blocks=(50,),
                exclusive_blocks=(50,),
                shared_suffix_blocks=(),
                local_segments=(),
                local_edges=(),
            ),
        ),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
                source_key=source_key,
                target_key=target_b_key,
                target_state=0x40,
                target_entry_anchor=40,
                target_label="0x00000040",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                    block_serial=20,
                    branch_arm=1,
                ),
                ordered_path=(20, 40),
            ),
            StateDagEdge(
                kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
                source_key=source_key,
                target_key=target_a_key,
                target_state=0x30,
                target_entry_anchor=30,
                target_label="0x00000030",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                    block_serial=22,
                    branch_arm=0,
                ),
                ordered_path=(22, 30),
            ),
            StateDagEdge(
                kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
                source_key=source_key,
                target_key=target_c_key,
                target_state=0x50,
                target_entry_anchor=50,
                target_label="0x00000050",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                    block_serial=22,
                    branch_arm=1,
                ),
                ordered_path=(22, 50),
            ),
        ),
    )

    rendered = render_linearized_state_program(
        dag,
        program_strategy=ProgramRenderStrategy.LOCAL_BOUNDARY_SELECTIVE,
        boundary_inline_mode=BoundaryInlineMode.INLINE_SINGLE_LEVEL,
        block_payload_by_serial={
            20: (
                "v0 = entry()",
                "if (v0 == 0) goto LABEL_40",
            ),
            21: (
                "v20 = call()",
                "if (v20 >=u 0x20) goto LABEL_22",
            ),
            23: ("v20 = 0x20",),
        },
    )

    assert "if (v20 <u 0x20)" in rendered
    assert "v20 = 0x20" in rendered
    assert "if (v20 >=u 0x20) goto LABEL_22" not in rendered


def test_render_linearized_state_program_preserves_entry_corridor_payload_before_resolved_target() -> None:
    source_key = StateDagNodeKey(handler_serial=20, state_const=0x20)
    target_key = StateDagNodeKey(handler_serial=30, state_const=0x30)
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=0x20,
        condition_chain_blocks=(),
        nodes=(
            StateDagNode(
                key=source_key,
                kind=StateNodeKind.EXACT,
                state_label="0x00000020",
                handler_serial=20,
                entry_anchor=20,
                owned_blocks=(20, 21),
                exclusive_blocks=(20, 21),
                shared_suffix_blocks=(21,),
                local_segments=(
                    StateLocalSegment(
                        segment_id="blk[20]",
                        kind=LocalSegmentKind.STRAIGHT_LINE,
                        blocks=(20,),
                    ),
                    StateLocalSegment(
                        segment_id="blk[21]",
                        kind=LocalSegmentKind.SHARED_SUFFIX,
                        blocks=(21,),
                    ),
                ),
                local_edges=(
                    StateLocalEdge(
                        source_segment_id="blk[20]",
                        target_segment_id="blk[21]",
                        kind=LocalEdgeKind.SHARED_SUFFIX,
                    ),
                ),
            ),
            StateDagNode(
                key=target_key,
                kind=StateNodeKind.EXACT,
                state_label="0x00000030",
                handler_serial=30,
                entry_anchor=30,
                owned_blocks=(30,),
                exclusive_blocks=(30,),
                shared_suffix_blocks=(),
                local_segments=(),
                local_edges=(),
            ),
        ),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.TRANSITION,
                source_key=source_key,
                target_key=target_key,
                target_state=0x30,
                target_entry_anchor=30,
                target_label="0x00000030",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.UNCONDITIONAL,
                    block_serial=21,
                ),
                ordered_path=(20, 21, 30),
            ),
        ),
    )

    rendered = render_linearized_state_program(
        dag,
        order_strategy=RenderOrderStrategy.SEMANTIC,
        program_strategy=ProgramRenderStrategy.LOCAL_BOUNDARY_SELECTIVE,
        boundary_inline_mode=BoundaryInlineMode.INLINE_SINGLE_LEVEL,
        block_payload_by_serial={
            20: (
                "v120 = setup(v193)",
                "goto LABEL_21",
            ),
            21: (
                "v119 = finish(v120)",
                "goto LABEL_30",
            ),
        },
    )

    assert "v120 = setup(v193)" in rendered
    assert "v119 = finish(v120)" in rendered
    assert "goto STATE_00000030;" in rendered


def test_render_linearized_state_program_emits_semantic_edge_tail_payload() -> None:
    source_key = StateDagNodeKey(handler_serial=20, state_const=0x20)
    target_a_key = StateDagNodeKey(handler_serial=30, state_const=0x30)
    target_b_key = StateDagNodeKey(handler_serial=40, state_const=0x40)
    target_c_key = StateDagNodeKey(handler_serial=50, state_const=0x50)
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=0x20,
        condition_chain_blocks=(),
        nodes=(
            StateDagNode(
                key=source_key,
                kind=StateNodeKind.EXACT,
                state_label="0x00000020",
                handler_serial=20,
                entry_anchor=20,
                owned_blocks=(20, 21, 22, 23),
                exclusive_blocks=(20, 21, 22, 23),
                shared_suffix_blocks=(),
                local_segments=(
                    StateLocalSegment(
                        segment_id="blk[20]",
                        kind=LocalSegmentKind.BRANCH,
                        blocks=(20,),
                    ),
                    StateLocalSegment(
                        segment_id="blk[21]",
                        kind=LocalSegmentKind.BRANCH,
                        blocks=(21,),
                    ),
                    StateLocalSegment(
                        segment_id="blk[22]",
                        kind=LocalSegmentKind.STRAIGHT_LINE,
                        blocks=(22,),
                    ),
                    StateLocalSegment(
                        segment_id="blk[23]",
                        kind=LocalSegmentKind.STRAIGHT_LINE,
                        blocks=(23,),
                    ),
                ),
                local_edges=(
                    StateLocalEdge(
                        source_segment_id="blk[20]",
                        target_segment_id="blk[21]",
                        kind=LocalEdgeKind.FALLTHROUGH,
                        branch_arm=0,
                    ),
                    StateLocalEdge(
                        source_segment_id="blk[21]",
                        target_segment_id="blk[22]",
                        kind=LocalEdgeKind.FALLTHROUGH,
                        branch_arm=0,
                    ),
                    StateLocalEdge(
                        source_segment_id="blk[21]",
                        target_segment_id="blk[23]",
                        kind=LocalEdgeKind.TAKEN,
                        branch_arm=1,
                    ),
                ),
            ),
            StateDagNode(
                key=target_a_key,
                kind=StateNodeKind.EXACT,
                state_label="0x00000030",
                handler_serial=30,
                entry_anchor=30,
                owned_blocks=(30,),
                exclusive_blocks=(30,),
                shared_suffix_blocks=(),
                local_segments=(),
                local_edges=(),
            ),
            StateDagNode(
                key=target_b_key,
                kind=StateNodeKind.EXACT,
                state_label="0x00000040",
                handler_serial=40,
                entry_anchor=40,
                owned_blocks=(40,),
                exclusive_blocks=(40,),
                shared_suffix_blocks=(),
                local_segments=(),
                local_edges=(),
            ),
            StateDagNode(
                key=target_c_key,
                kind=StateNodeKind.EXACT,
                state_label="0x00000050",
                handler_serial=50,
                entry_anchor=50,
                owned_blocks=(50,),
                exclusive_blocks=(50,),
                shared_suffix_blocks=(),
                local_segments=(),
                local_edges=(),
            ),
        ),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
                source_key=source_key,
                target_key=target_b_key,
                target_state=0x40,
                target_entry_anchor=40,
                target_label="0x00000040",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                    block_serial=20,
                    branch_arm=1,
                ),
                ordered_path=(20, 23),
            ),
            StateDagEdge(
                kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
                source_key=source_key,
                target_key=target_a_key,
                target_state=0x30,
                target_entry_anchor=30,
                target_label="0x00000030",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                    block_serial=21,
                    branch_arm=1,
                ),
                ordered_path=(20, 21, 23),
            ),
            StateDagEdge(
                kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
                source_key=source_key,
                target_key=target_c_key,
                target_state=0x50,
                target_entry_anchor=50,
                target_label="0x00000050",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                    block_serial=21,
                    branch_arm=0,
                ),
                ordered_path=(20, 21, 22),
            ),
        ),
    )

    rendered = render_linearized_state_program(
        dag,
        order_strategy=RenderOrderStrategy.SEMANTIC,
        program_strategy=ProgramRenderStrategy.LOCAL_BOUNDARY_SELECTIVE,
        boundary_inline_mode=BoundaryInlineMode.INLINE_SINGLE_LEVEL,
        comment_mode=ProgramCommentMode.MINIMAL,
        block_payload_by_serial={
            20: (
                "v0 = seed()",
                "if (v0 == 0) goto LABEL_40",
            ),
            21: (
                "v1 = compute()",
                "if (v1 == 0) goto LABEL_50",
            ),
            22: ("v_tail = on_fallthrough()", "goto LABEL_50"),
            23: ("v_tail = on_taken()", "goto LABEL_30"),
        },
    )

    assert "v_tail = on_taken()" in rendered
    assert "v_tail = on_fallthrough()" in rendered
    assert "goto STATE_00000030;" in rendered
    assert "goto STATE_00000050;" in rendered


def test_render_linearized_state_program_emits_two_way_merge_once_with_transition() -> None:
    """A 2-way branch whose arms converge on one merge block that writes the next
    state must render the merge body ONCE (at its own label), with both arms routing
    to that label and a single exit goto -- not duplicated per arm.

    Mirrors sub_7FFD handler block 122 (STATE_37B42A40): blk[20] BRANCH, blk[24]
    merge (GOTO_LABEL), blk[23] straight side. An unconditional TRANSITION (path
    20->24) AND a redundant CONDITIONAL_TRANSITION arm0 (path 20->23->24) both target
    the same next state 0x30 -- the live recovery shape. Regression for llr-zfyi
    (block 124 was emitted 3x: taken-arm inline + 2 semantic-edge tails).
    """
    source_key = StateDagNodeKey(handler_serial=20, state_const=0x20)
    target_key = StateDagNodeKey(handler_serial=30, state_const=0x30)
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=0x20,
        condition_chain_blocks=(),
        nodes=(
            StateDagNode(
                key=source_key,
                kind=StateNodeKind.EXACT,
                state_label="0x00000020",
                handler_serial=20,
                entry_anchor=20,
                owned_blocks=(20, 24, 23),
                exclusive_blocks=(20, 24, 23),
                shared_suffix_blocks=(),
                local_segments=(
                    StateLocalSegment(
                        segment_id="blk[20]",
                        kind=LocalSegmentKind.BRANCH,
                        blocks=(20,),
                    ),
                    StateLocalSegment(
                        segment_id="blk[24]",
                        kind=LocalSegmentKind.GOTO_LABEL,
                        blocks=(24,),
                    ),
                    StateLocalSegment(
                        segment_id="blk[23]",
                        kind=LocalSegmentKind.STRAIGHT_LINE,
                        blocks=(23,),
                    ),
                ),
                local_edges=(
                    StateLocalEdge(
                        source_segment_id="blk[20]",
                        target_segment_id="blk[24]",
                        kind=LocalEdgeKind.TAKEN,
                        branch_arm=1,
                    ),
                    StateLocalEdge(
                        source_segment_id="blk[20]",
                        target_segment_id="blk[23]",
                        kind=LocalEdgeKind.FALLTHROUGH,
                        branch_arm=0,
                    ),
                    StateLocalEdge(
                        source_segment_id="blk[23]",
                        target_segment_id="blk[24]",
                        kind=LocalEdgeKind.JOIN,
                    ),
                ),
            ),
            StateDagNode(
                key=target_key,
                kind=StateNodeKind.EXACT,
                state_label="0x00000030",
                handler_serial=30,
                entry_anchor=30,
                owned_blocks=(30,),
                exclusive_blocks=(30,),
                shared_suffix_blocks=(),
                local_segments=(),
                local_edges=(),
            ),
        ),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.TRANSITION,
                source_key=source_key,
                target_key=target_key,
                target_state=0x30,
                target_entry_anchor=30,
                target_label="0x00000030",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.UNCONDITIONAL,
                    block_serial=20,
                ),
                ordered_path=(20, 24),
            ),
            StateDagEdge(
                kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
                source_key=source_key,
                target_key=target_key,
                target_state=0x30,
                target_entry_anchor=30,
                target_label="0x00000030",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                    block_serial=20,
                    branch_arm=0,
                ),
                ordered_path=(20, 23, 24),
            ),
        ),
    )

    rendered = render_linearized_state_program(
        dag,
        order_strategy=RenderOrderStrategy.SEMANTIC,
        program_strategy=ProgramRenderStrategy.LOCAL_BOUNDARY_SELECTIVE,
        boundary_inline_mode=BoundaryInlineMode.INLINE_SINGLE_LEVEL,
        comment_mode=ProgramCommentMode.MINIMAL,
        block_payload_by_serial={
            20: (
                "v0 = cond()",
                "if (v0 >=u 0x10) goto LABEL_24",
            ),
            23: ("v_side = adjust()",),
            24: (
                "v_merge = finalize()",
                "state = 0x30",
            ),
        },
    )

    lines = rendered.splitlines()
    merge_label = "STATE_00000020__blk_24"
    # The merge body is emitted exactly once.
    assert sum(1 for ln in lines if ln.strip() == "v_merge = finalize()") == 1
    # The merge carries its own label.
    assert any(ln.rstrip() == f"{merge_label}:" for ln in lines)
    # Both arms route to the merge label (2 gotos to it), not inline copies.
    assert sum(1 for ln in lines if f"goto {merge_label};" in ln) == 2
    # Exactly one exit transition out of the merge.
    assert sum(1 for ln in lines if ln.strip() == "goto STATE_00000030;") == 1
    # No dangling gotos: every goto target is defined as a label somewhere.
    defined = {
        m.group(1)
        for ln in lines
        if (m := re.match(r"^\s*([A-Za-z_]\w*)\s*:\s*$", ln))
    }
    goto_targets = {
        g for ln in lines for g in re.findall(r"\bgoto\s+([A-Za-z_]\w*)\s*;", ln)
    }
    assert goto_targets <= defined, f"dangling gotos: {sorted(goto_targets - defined)}"


def test_render_linearized_state_program_minimal_comment_mode_hides_metadata_scaffolding() -> None:
    source_key = StateDagNodeKey(handler_serial=20, state_const=0x20)
    target_key = StateDagNodeKey(handler_serial=30, state_const=0x30)
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=0x20,
        condition_chain_blocks=(),
        nodes=(
            StateDagNode(
                key=source_key,
                kind=StateNodeKind.EXACT,
                state_label="0x00000020",
                handler_serial=20,
                entry_anchor=20,
                owned_blocks=(20,),
                exclusive_blocks=(20,),
                shared_suffix_blocks=(),
                local_segments=(),
                local_edges=(),
            ),
            StateDagNode(
                key=target_key,
                kind=StateNodeKind.EXACT,
                state_label="0x00000030",
                handler_serial=30,
                entry_anchor=30,
                owned_blocks=(30,),
                exclusive_blocks=(30,),
                shared_suffix_blocks=(),
                local_segments=(),
                local_edges=(),
            ),
        ),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.TRANSITION,
                source_key=source_key,
                target_key=target_key,
                target_state=0x30,
                target_entry_anchor=30,
                target_label="0x00000030",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.UNCONDITIONAL,
                    block_serial=20,
                ),
                ordered_path=(20, 30),
            ),
        ),
    )

    rendered = render_linearized_state_program(
        dag,
        order_strategy=RenderOrderStrategy.SEMANTIC,
        program_strategy=ProgramRenderStrategy.LOCAL_BOUNDARY_SELECTIVE,
        boundary_inline_mode=BoundaryInlineMode.INLINE_SINGLE_LEVEL,
        comment_mode=ProgramCommentMode.MINIMAL,
        block_payload_by_serial={
            20: (
                "v120 = setup(v193)",
                "goto LABEL_30",
            ),
        },
    )

    assert "v120 = setup(v193)" in rendered
    assert "goto STATE_00000030;" in rendered
    assert "// entry blk" not in rendered
    assert "// blocks:" not in rendered
    assert "// straight_line segment:" not in rendered


def test_render_strategies_distinguish_catalog_from_semantic_order() -> None:
    node_10 = StateDagNode(
        key=StateDagNodeKey(handler_serial=10, state_const=0x10),
        kind=StateNodeKind.EXACT,
        state_label="0x00000010",
        handler_serial=10,
        entry_anchor=10,
        owned_blocks=(10,),
        exclusive_blocks=(10,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    node_05 = StateDagNode(
        key=StateDagNodeKey(handler_serial=5, state_const=0x05),
        kind=StateNodeKind.EXACT,
        state_label="0x00000005",
        handler_serial=5,
        entry_anchor=5,
        owned_blocks=(5,),
        exclusive_blocks=(5,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    node_30 = StateDagNode(
        key=StateDagNodeKey(handler_serial=30, state_const=0x30),
        kind=StateNodeKind.EXACT,
        state_label="0x00000030",
        handler_serial=30,
        entry_anchor=30,
        owned_blocks=(30,),
        exclusive_blocks=(30,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=0x10,
        condition_chain_blocks=(),
        nodes=(node_10, node_05, node_30),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.TRANSITION,
                source_key=node_10.key,
                target_key=node_30.key,
                target_state=0x30,
                target_entry_anchor=30,
                target_label="0x00000030",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.UNCONDITIONAL,
                    block_serial=10,
                ),
                ordered_path=(10, 30),
            ),
        ),
    )

    catalog = render_linearized_state_program(
        dag,
        order_strategy=RenderOrderStrategy.CATALOG,
    )
    semantic = render_linearized_state_program(
        dag,
        order_strategy=RenderOrderStrategy.SEMANTIC,
    )

    assert catalog.index("STATE_00000005:") < catalog.index("STATE_00000030:")
    assert semantic.index("STATE_00000030:") < semantic.index("STATE_00000005:")


def test_suppresses_dispatcher_root_alias_edge_when_concrete_prefix_exists() -> None:
    from d810.analyses.control_flow import linearized_state_dag as dag_mod

    source_key = StateDagNodeKey(handler_serial=118, state_const=0x029EEE50)
    concrete_target = StateDagNodeKey(handler_serial=56, state_const=0x7D9C16EC)

    concrete_edge = StateDagEdge(
        kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
        source_key=source_key,
        target_key=concrete_target,
        target_state=0x7D9C16EC,
        target_entry_anchor=56,
        target_label="0x7D9C16EC",
        source_anchor=StateRedirectAnchor(
            kind=RedirectSourceKind.CONDITIONAL_BRANCH,
            block_serial=118,
            branch_arm=1,
        ),
        ordered_path=(118, 120),
    )
    alias_edge = StateDagEdge(
        kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
        source_key=source_key,
        target_key=None,
        target_state=0x27EEEA11,
        target_entry_anchor=2,
        target_label="0x27EEEA11",
        source_anchor=StateRedirectAnchor(
            kind=RedirectSourceKind.CONDITIONAL_BRANCH,
            block_serial=118,
            branch_arm=1,
        ),
        ordered_path=(118, 120, 2),
    )

    filtered = dag_mod._suppress_condition_chain_extension_alias_edges(
        [alias_edge, concrete_edge],
        condition_chain_blocks={2},
    )

    assert concrete_edge in filtered
    assert alias_edge not in filtered


class _AlwaysDispatcher:
    def __init__(self, target: int) -> None:
        self._target = target

    def lookup(self, state: int) -> int:
        return self._target


def test_exact_state_resolution_beats_dispatcher_fallback() -> None:
    flow_graph = _make_branch_flow_graph()
    transition_result = _make_branch_transition_result()
    report = build_dispatcher_transition_report_from_graph(
        flow_graph=flow_graph,
        transition_result=transition_result,
        dispatcher_entry_serial=5,
    )

    dag = build_linearized_state_dag_from_graph(
        flow_graph,
        report,
        transition_result,
        dispatcher=_AlwaysDispatcher(7),
    )

    transition_edge = next(
        edge
        for edge in dag.edges
        if edge.source_key.handler_serial == 1
        and edge.kind == SemanticEdgeKind.TRANSITION
    )
    assert transition_edge.target_state == 0x20
    assert transition_edge.target_entry_anchor == 2


def _make_terminal_sibling_flow_graph() -> FlowGraph:
    blocks = {
        0: BlockSnapshot(0, 0, (1, 2), (), 0, 0, ()),
        1: BlockSnapshot(1, 0, (2,), (0,), 0, 0, ()),
        2: BlockSnapshot(2, 0, (3, 4), (0, 1), 0, 0, ()),
        3: BlockSnapshot(3, 0, (), (2,), 0, 0, ()),
        4: BlockSnapshot(4, 0, (), (2,), 0, 0, ()),
    }
    return FlowGraph(blocks=blocks, entry_serial=0, func_ea=0x403000)


def _make_terminal_sibling_transition_result() -> TransitionResult:
    trans_20 = StateTransition(
        from_state=0x20,
        to_state=0x30,
        from_block=2,
        condition_block=2,
        is_conditional=True,
    )
    return TransitionResult(
        transitions=[trans_20],
        handlers={
            0x10: StateHandler(
                state_value=0x10,
                check_block=1,
                handler_blocks=[1],
                transitions=[],
            ),
            0x20: StateHandler(
                state_value=0x20,
                check_block=2,
                handler_blocks=[2],
                transitions=[trans_20],
            ),
            0x30: StateHandler(
                state_value=0x30,
                check_block=4,
                handler_blocks=[4],
                transitions=[],
            ),
        },
        initial_state=0x20,
        pre_header_serial=0,
        strategy_name="fixture",
        resolved_count=1,
    )


def test_terminal_sibling_paths_use_branch_anchors() -> None:
    flow_graph = _make_terminal_sibling_flow_graph()
    transition_result = _make_terminal_sibling_transition_result()
    report = build_dispatcher_transition_report_from_graph(
        flow_graph=flow_graph,
        transition_result=transition_result,
        dispatcher_entry_serial=6,
    )

    dag = build_linearized_state_dag_from_graph(
        flow_graph,
        report,
        transition_result,
        handler_paths_by_handler={
            2: (
                HandlerPathResult(
                    exit_block=3,
                    final_state=None,
                    state_writes=[],
                    ordered_path=[2, 3],
                ),
                HandlerPathResult(
                    exit_block=4,
                    final_state=0x30,
                    state_writes=[(2, 0x2000)],
                    ordered_path=[2, 4],
                ),
            ),
        },
        conditional_transitions_by_handler={
            2: (
                ConditionalTransition(
                    handler_entry=2,
                    branch_block=2,
                    target_state=0x30,
                    target_handler=4,
                    state_write_block=2,
                    state_write_ea=0x2000,
                    branch_arm=1,
                ),
            ),
        },
    )

    terminal_edge = next(
        edge
        for edge in dag.edges
        if edge.source_key.handler_serial == 2
        and edge.kind == SemanticEdgeKind.CONDITIONAL_RETURN
    )
    assert terminal_edge.source_anchor.kind == RedirectSourceKind.CONDITIONAL_BRANCH
    assert terminal_edge.source_anchor.block_serial == 2
    assert terminal_edge.source_anchor.branch_arm == 0
    assert terminal_edge.target_label == "RETURN"

    rendered = render_linearized_state_dag(dag)
    assert "edge conditional_return src=blk[2].fallthrough -> RETURN path=[2, 3]" in rendered


def test_branch_anchored_inherited_state_paths_do_not_render_self_edges() -> None:
    flow_graph = FlowGraph(
        blocks={
            1: BlockSnapshot(1, 0, (2,), (), 0, 0, ()),
            2: BlockSnapshot(2, 0, (3, 4), (1,), 0, 0, ()),
            3: BlockSnapshot(3, 0, (), (2,), 0, 0, ()),
            4: BlockSnapshot(4, 0, (), (2,), 0, 0, ()),
            6: BlockSnapshot(6, 0, (), (), 0, 0, ()),
        },
        entry_serial=1,
        func_ea=0x404000,
    )
    transition_result = TransitionResult(
        transitions=[
            StateTransition(
                from_state=0x20,
                to_state=0x30,
                from_block=1,
                is_conditional=False,
            )
        ],
        handlers={
            0x20: StateHandler(
                state_value=0x20,
                check_block=1,
                handler_blocks=[1, 2],
                transitions=[],
            ),
            0x30: StateHandler(
                state_value=0x30,
                check_block=6,
                handler_blocks=[6],
                transitions=[],
            ),
        },
        initial_state=0x20,
        pre_header_serial=7,
        strategy_name="fixture",
        resolved_count=1,
    )
    transition_result.handlers[0x20].transitions = transition_result.transitions
    report = build_dispatcher_transition_report_from_graph(
        flow_graph=flow_graph,
        transition_result=transition_result,
        dispatcher_entry_serial=6,
    )

    dag = build_linearized_state_dag_from_graph(
        flow_graph,
        report,
        transition_result,
        handler_paths_by_handler={
            1: (
                HandlerPathResult(
                    exit_block=3,
                    final_state=0x20,
                    state_writes=[(1, 0x2000)],
                    ordered_path=[1, 2, 3],
                ),
                HandlerPathResult(
                    exit_block=4,
                    final_state=None,
                    state_writes=[],
                    ordered_path=[1, 2, 4],
                ),
            ),
        },
    )

    outgoing = [
        edge
        for edge in dag.edges
        if edge.source_key.handler_serial == 1
    ]
    assert any(
        edge.kind == SemanticEdgeKind.TRANSITION and edge.target_state == 0x30
        for edge in outgoing
    )
    assert not any(
        edge.kind == SemanticEdgeKind.CONDITIONAL_TRANSITION
        and edge.target_state == 0x20
        for edge in outgoing
    )

    rendered = render_linearized_state_dag(dag)
    assert "src=blk[2].fallthrough -> 0x00000020" not in rendered


def _make_shared_suffix_flow_graph() -> FlowGraph:
    blocks = {
        1: BlockSnapshot(1, 0, (5,), (), 0, 0, ()),
        2: BlockSnapshot(2, 0, (), (6,), 0, 0, ()),
        5: BlockSnapshot(5, 0, (6,), (1, 9), 0, 0, ()),
        6: BlockSnapshot(6, 0, (), (5,), 0, 0, ()),
        9: BlockSnapshot(9, 0, (5,), (), 0, 0, ()),
    }
    return FlowGraph(blocks=blocks, entry_serial=1, func_ea=0x402000)


def _make_shared_suffix_transition_result() -> TransitionResult:
    trans_10 = StateTransition(
        from_state=0x10,
        to_state=0x20,
        from_block=1,
        is_conditional=False,
    )
    return TransitionResult(
        transitions=[trans_10],
        handlers={
            0x10: StateHandler(
                state_value=0x10,
                check_block=1,
                handler_blocks=[1, 5, 6],
                transitions=[trans_10],
            ),
            0x20: StateHandler(
                state_value=0x20,
                check_block=2,
                handler_blocks=[2],
                transitions=[],
            ),
            0x100: StateHandler(
                state_value=0x100,
                check_block=9,
                handler_blocks=[9, 5, 6],
                transitions=[],
            ),
        },
        initial_state=0x10,
        pre_header_serial=0,
        strategy_name="fixture",
        resolved_count=1,
    )


def _make_shared_suffix_report() -> DispatcherTransitionReport:
    rows = (
        TransitionRow(
            state_const=0x10,
            state_range_lo=None,
            state_range_hi=None,
            handler_serial=1,
            kind=TransitionKind.TRANSITION,
            next_state=0x20,
            conditional_states=(),
            state_label="State 0x00000010",
            transition_label="next=0x00000020",
            chain_preview=(1, 5, 6),
            path=TransitionPath(
                handler_serial=1,
                chain=(1, 5, 6),
                next_state=0x20,
                conditional_states=(),
                back_edge=True,
                reaches_exit_block=False,
                classified_exit=False,
                unresolved=False,
            ),
        ),
        TransitionRow(
            state_const=0x20,
            state_range_lo=None,
            state_range_hi=None,
            handler_serial=2,
            kind=TransitionKind.EXIT,
            next_state=None,
            conditional_states=(),
            state_label="State 0x00000020",
            transition_label="RETURN (exit)",
            chain_preview=(2,),
            path=TransitionPath(
                handler_serial=2,
                chain=(2,),
                next_state=None,
                conditional_states=(),
                back_edge=False,
                reaches_exit_block=True,
                classified_exit=True,
                unresolved=False,
            ),
        ),
        TransitionRow(
            state_const=0x100,
            state_range_lo=0x100,
            state_range_hi=0x1FF,
            handler_serial=9,
            kind=TransitionKind.UNKNOWN,
            next_state=None,
            conditional_states=(),
            state_label="State range [0x100..0x1ff]",
            transition_label="unknown",
            chain_preview=(9, 5, 6),
            path=TransitionPath(
                handler_serial=9,
                chain=(9, 5, 6),
                next_state=None,
                conditional_states=(),
                back_edge=False,
                reaches_exit_block=False,
                classified_exit=False,
                unresolved=True,
            ),
        ),
    )
    return DispatcherTransitionReport(
        dispatcher_entry_serial=11,
        state_var_stkoff=0x20,
        state_var_lvar_idx=None,
        pre_header_serial=0,
        initial_state=0x10,
        handler_state_map={1: 0x10, 2: 0x20},
        handler_range_map={9: (0x100, 0x1FF)},
        condition_chain_blocks=(11,),
        rows=rows,
        summary=TransitionSummary(
            handlers_total=3,
            known_count=1,
            conditional_count=0,
            exit_count=1,
            unknown_count=1,
        ),
        diagnostics=(),
    )


def test_range_backed_nodes_keep_shared_suffixes_out_of_entry_targets() -> None:
    flow_graph = _make_shared_suffix_flow_graph()
    transition_result = _make_shared_suffix_transition_result()
    report = _make_shared_suffix_report()

    dag = build_linearized_state_dag_from_graph(
        flow_graph,
        report,
        transition_result,
        handler_paths_by_handler={
            1: (
                HandlerPathResult(
                    exit_block=6,
                    final_state=0x20,
                    state_writes=[(1, 0x2000)],
                    ordered_path=[1, 5, 6],
                ),
            ),
            9: (
                HandlerPathResult(
                    exit_block=6,
                    final_state=None,
                    state_writes=[],
                    ordered_path=[9, 5, 6],
                ),
            ),
        },
    )

    range_node = next(node for node in dag.nodes if node.handler_serial == 9)
    assert range_node.kind == StateNodeKind.RANGE_BACKED
    assert range_node.entry_anchor == 9
    assert range_node.shared_suffix_blocks == (5, 6)

    transition_edge = next(
        edge
        for edge in dag.edges
        if edge.source_key.handler_serial == 1
        and edge.kind == SemanticEdgeKind.TRANSITION
        and edge.target_state == 0x20
    )
    assert transition_edge.source_anchor.block_serial == 1
    assert transition_edge.target_entry_anchor == 2
    assert transition_edge.target_entry_anchor != 6

    rendered = render_linearized_state_dag(dag)
    assert "[0x00000100..0x000001FF] (repr 0x00000100)" in rendered
    assert "shared-suffix: blk[5], blk[6]" in rendered


def test_terminal_branch_handoff_preserves_local_goto_chain() -> None:
    flow_graph = FlowGraph(
        blocks={
            23: BlockSnapshot(23, 0, (), (200,), 0, 0, ()),
            131: BlockSnapshot(131, 0, (174,), (), 0, 0, ()),
            174: BlockSnapshot(174, 0, (175, 176), (131,), 0, 0, ()),
            175: BlockSnapshot(175, 0, (217,), (174,), 0, 0, ()),
            176: BlockSnapshot(176, 0, (200,), (174,), 0, 0, ()),
            198: BlockSnapshot(198, 0, (199,), (), 0, 0, ()),
            199: BlockSnapshot(199, 0, (200,), (198,), 0, 0, ()),
            200: BlockSnapshot(200, 0, (23,), (176, 199), 0, 0, ()),
            217: BlockSnapshot(217, 0, (218,), (175,), 0, 0, ()),
            218: BlockSnapshot(218, 0, (), (217,), 0, 0, ()),
        },
        entry_serial=131,
        func_ea=0x407000,
    )
    transition_from_acd = StateTransition(
        from_state=0x0ACD0BD5,
        to_state=0x6465D165,
        from_block=131,
        is_conditional=False,
    )
    transition_from_258 = StateTransition(
        from_state=0x258ED455,
        to_state=0x6465D165,
        from_block=199,
        is_conditional=False,
    )
    transition_result = TransitionResult(
        transitions=[transition_from_acd, transition_from_258],
        handlers={
            0x0ACD0BD5: StateHandler(
                state_value=0x0ACD0BD5,
                check_block=131,
                handler_blocks=[131, 174, 175, 176],
                transitions=[transition_from_acd],
            ),
            0x258ED455: StateHandler(
                state_value=0x258ED455,
                check_block=199,
                handler_blocks=[199],
                transitions=[transition_from_258],
            ),
            0x6465D165: StateHandler(
                state_value=0x6465D165,
                check_block=23,
                handler_blocks=[23],
                transitions=[],
            ),
        },
        initial_state=0x0ACD0BD5,
        pre_header_serial=0,
        strategy_name="fixture",
        resolved_count=2,
    )
    report = DispatcherTransitionReport(
        dispatcher_entry_serial=0,
        state_var_stkoff=None,
        state_var_lvar_idx=None,
        pre_header_serial=None,
        initial_state=0x0ACD0BD5,
        handler_state_map={131: 0x0ACD0BD5, 199: 0x258ED455, 23: 0x6465D165},
        handler_range_map={},
        condition_chain_blocks=(),
        rows=(
            TransitionRow(
                state_const=0x0ACD0BD5,
                state_range_lo=None,
                state_range_hi=None,
                handler_serial=131,
                kind=TransitionKind.EXIT,
                next_state=None,
                conditional_states=(),
                state_label="State 0x0ACD0BD5",
                transition_label="RETURN (exit)",
                chain_preview=(131, 174, 175, 217),
                path=TransitionPath(
                    handler_serial=131,
                    chain=(131, 174, 175, 217),
                    next_state=None,
                    conditional_states=(),
                    back_edge=False,
                    reaches_exit_block=True,
                    classified_exit=True,
                    unresolved=False,
                ),
            ),
            TransitionRow(
                state_const=0x258ED455,
                state_range_lo=None,
                state_range_hi=None,
                handler_serial=199,
                kind=TransitionKind.TRANSITION,
                next_state=0x6465D165,
                conditional_states=(),
                state_label="State 0x258ED455",
                transition_label="next=0x6465D165",
                chain_preview=(199,),
                path=TransitionPath(
                    handler_serial=199,
                    chain=(199,),
                    next_state=0x6465D165,
                    conditional_states=(),
                    back_edge=True,
                    reaches_exit_block=False,
                    classified_exit=False,
                    unresolved=False,
                ),
            ),
            TransitionRow(
                state_const=0x6465D165,
                state_range_lo=None,
                state_range_hi=None,
                handler_serial=23,
                kind=TransitionKind.UNKNOWN,
                next_state=None,
                conditional_states=(),
                state_label="State 0x6465D165",
                transition_label="unknown",
                chain_preview=(23,),
                path=TransitionPath(
                    handler_serial=23,
                    chain=(23,),
                    next_state=None,
                    conditional_states=(),
                    back_edge=False,
                    reaches_exit_block=False,
                    classified_exit=False,
                    unresolved=True,
                ),
            ),
        ),
        summary=TransitionSummary(
            handlers_total=3,
            known_count=1,
            conditional_count=0,
            exit_count=1,
            unknown_count=1,
        ),
        diagnostics=(),
    )

    dag = build_linearized_state_dag_from_graph(
        flow_graph,
        report,
        transition_result,
        handler_paths_by_handler={
            131: (
                HandlerPathResult(
                    exit_block=218,
                    final_state=None,
                    state_writes=[],
                    ordered_path=[131, 174, 175, 217, 218],
                ),
            ),
            199: (
                HandlerPathResult(
                    exit_block=199,
                    final_state=0x6465D165,
                    state_writes=[(199, 0x3000)],
                    ordered_path=[199],
                ),
            ),
        },
    )

    acd_node = next(node for node in dag.nodes if node.handler_serial == 131)
    assert any(
        edge.source_segment_id == "blk[176]"
        and edge.target_segment_id == "blk[200]"
        and edge.kind == LocalEdgeKind.JOIN
        for edge in acd_node.local_edges
    )

    acd_edges = [edge for edge in dag.edges if edge.source_key.handler_serial == 131]
    assert any(
        edge.kind == SemanticEdgeKind.CONDITIONAL_TRANSITION
        and edge.source_anchor.block_serial == 174
        and edge.source_anchor.branch_arm == 1
        and edge.target_state == 0x258ED455
        and edge.target_entry_anchor == 199
        for edge in acd_edges
    )
    assert not any(
        edge.kind == SemanticEdgeKind.TRANSITION
        and edge.target_state == 0x6465D165
        for edge in acd_edges
    )

    rendered = render_linearized_state_dag(dag)
    assert "blk[176] -join-> blk[200]" in rendered
    assert "edge conditional_transition src=blk[174].taken" in rendered
    assert "0x258ED455" in rendered
    assert "entry=blk[199]" in rendered


def test_alias_states_can_share_handler_anchor_and_inherit_edges() -> None:
    flow_graph = FlowGraph(
        blocks={
            1: BlockSnapshot(1, 0, (2,), (), 0, 0, ()),
            2: BlockSnapshot(2, 0, (3,), (1,), 0, 0, ()),
            3: BlockSnapshot(3, 0, (), (2,), 0, 0, ()),
        },
        entry_serial=1,
        func_ea=0x406000,
    )
    handler_10_transition = StateTransition(
        from_state=0x10,
        to_state=0x25,
        from_block=1,
        is_conditional=False,
    )
    handler_20_transition = StateTransition(
        from_state=0x20,
        to_state=0x30,
        from_block=2,
        is_conditional=False,
    )
    transition_result = TransitionResult(
        transitions=[
            handler_10_transition,
            handler_20_transition,
        ],
        handlers={
            0x10: StateHandler(
                state_value=0x10,
                check_block=1,
                handler_blocks=[1],
                transitions=[handler_10_transition],
            ),
            0x20: StateHandler(
                state_value=0x20,
                check_block=2,
                handler_blocks=[2],
                transitions=[handler_20_transition],
            ),
            0x30: StateHandler(
                state_value=0x30,
                check_block=3,
                handler_blocks=[3],
                transitions=[],
            ),
        },
        initial_state=0x10,
        pre_header_serial=0,
        strategy_name="fixture",
        resolved_count=2,
    )
    report = DispatcherTransitionReport(
        dispatcher_entry_serial=0,
        state_var_stkoff=None,
        state_var_lvar_idx=None,
        pre_header_serial=None,
        initial_state=0x10,
        handler_state_map={1: 0x10, 2: 0x20, 3: 0x30},
        handler_range_map={},
        condition_chain_blocks=(),
        rows=(
            TransitionRow(
                state_const=0x10,
                state_range_lo=None,
                state_range_hi=None,
                handler_serial=1,
                kind=TransitionKind.TRANSITION,
                next_state=0x25,
                conditional_states=(),
                state_label="State 0x00000010",
                transition_label="next=0x00000025",
                chain_preview=(1,),
                path=TransitionPath(
                    handler_serial=1,
                    chain=(1,),
                    next_state=0x25,
                    conditional_states=(),
                    back_edge=True,
                    reaches_exit_block=False,
                    classified_exit=False,
                    unresolved=False,
                ),
            ),
            TransitionRow(
                state_const=0x20,
                state_range_lo=None,
                state_range_hi=None,
                handler_serial=2,
                kind=TransitionKind.TRANSITION,
                next_state=0x30,
                conditional_states=(),
                state_label="State 0x00000020",
                transition_label="next=0x00000030",
                chain_preview=(2,),
                path=TransitionPath(
                    handler_serial=2,
                    chain=(2,),
                    next_state=0x30,
                    conditional_states=(),
                    back_edge=True,
                    reaches_exit_block=False,
                    classified_exit=False,
                    unresolved=False,
                ),
            ),
            TransitionRow(
                state_const=0x25,
                state_range_lo=None,
                state_range_hi=None,
                handler_serial=2,
                kind=TransitionKind.TRANSITION,
                next_state=0x30,
                conditional_states=(),
                state_label="State 0x00000025",
                transition_label="range alias of State 0x00000020",
                chain_preview=(2,),
                path=TransitionPath(
                    handler_serial=2,
                    chain=(2,),
                    next_state=0x30,
                    conditional_states=(),
                    back_edge=True,
                    reaches_exit_block=False,
                    classified_exit=False,
                    unresolved=False,
                ),
            ),
            TransitionRow(
                state_const=0x30,
                state_range_lo=None,
                state_range_hi=None,
                handler_serial=3,
                kind=TransitionKind.UNKNOWN,
                next_state=None,
                conditional_states=(),
                state_label="State 0x00000030",
                transition_label="unknown",
                chain_preview=(3,),
                path=TransitionPath(
                    handler_serial=3,
                    chain=(3,),
                    next_state=None,
                    conditional_states=(),
                    back_edge=False,
                    reaches_exit_block=False,
                    classified_exit=False,
                    unresolved=True,
                ),
            ),
        ),
        summary=TransitionSummary(
            handlers_total=4,
            known_count=3,
            conditional_count=0,
            exit_count=0,
            unknown_count=1,
        ),
        diagnostics=(),
    )

    dag = build_linearized_state_dag_from_graph(
        flow_graph,
        report,
        transition_result,
    )

    alias_node = next(node for node in dag.nodes if node.key.state_const == 0x25)
    assert alias_node.entry_anchor == 2

    incoming_edge = next(
        edge
        for edge in dag.edges
        if edge.source_key.state_const == 0x10 and edge.target_state == 0x25
    )
    assert incoming_edge.target_key == alias_node.key

    alias_outgoing = next(
        edge
        for edge in dag.edges
        if edge.source_key.state_const == 0x25 and edge.target_state == 0x30
    )
    assert alias_outgoing.target_entry_anchor == 3


def test_live_builder_iterates_supplemental_fallback_aliases(
    monkeypatch,
) -> None:
    from d810.analyses.control_flow import linearized_state_dag as dag_mod

    flow_graph = FlowGraph(
        blocks={
            93: BlockSnapshot(93, 0, (94, 95), (), 0, 0, ()),
            94: BlockSnapshot(94, 0, (), (93,), 0, 0, ()),
            95: BlockSnapshot(95, 0, (211,), (93,), 0, 0, ()),
            122: BlockSnapshot(122, 0, (180,), (), 0, 0, ()),
            180: BlockSnapshot(180, 0, (), (122,), 0, 0, ()),
            210: BlockSnapshot(210, 0, (211,), (), 0, 0, ()),
            211: BlockSnapshot(211, 0, (106,), (95,), 0, 0, ()),
            108: BlockSnapshot(108, 0, (111,), (), 0, 0, ()),
            106: BlockSnapshot(106, 0, (78,), (211,), 0, 0, ()),
            111: BlockSnapshot(111, 0, (78,), (108,), 0, 0, ()),
            78: BlockSnapshot(78, 0, (14,), (106,), 0, 0, ()),
            14: BlockSnapshot(14, 0, (), (78,), 0, 0, ()),
        },
        entry_serial=93,
        func_ea=0x409000,
    )
    transition_from_422 = StateTransition(
        from_state=0x42267E66,
        to_state=0x24E2E77A,
        from_block=93,
        is_conditional=False,
    )
    transition_bridge = StateTransition(
        from_state=0x00C0C59F,
        to_state=0x2FBA4611,
        from_block=122,
        is_conditional=False,
    )
    transition_result = TransitionResult(
        transitions=[transition_from_422, transition_bridge],
        handlers={
            0x00C0C59F: StateHandler(
                state_value=0x00C0C59F,
                check_block=122,
                handler_blocks=[122],
                transitions=[transition_bridge],
            ),
            0x42267E66: StateHandler(
                state_value=0x42267E66,
                check_block=93,
                handler_blocks=[93, 95],
                transitions=[transition_from_422],
            ),
            0x2FBA4611: StateHandler(
                state_value=0x2FBA4611,
                check_block=180,
                handler_blocks=[180],
                transitions=[],
            ),
            0x606DC166: StateHandler(
                state_value=0x606DC166,
                check_block=14,
                handler_blocks=[14],
                transitions=[],
            ),
        },
        initial_state=0x42267E66,
        pre_header_serial=0,
        strategy_name="fixture",
        resolved_count=1,
    )
    initial_report = DispatcherTransitionReport(
        dispatcher_entry_serial=0,
        state_var_stkoff=0x3C,
        state_var_lvar_idx=None,
        pre_header_serial=None,
        initial_state=0x42267E66,
        handler_state_map={
            122: 0x00C0C59F,
            93: 0x42267E66,
            180: 0x2FBA4611,
            210: 0x2315233C,
            108: 0x393685BA,
            14: 0x606DC166,
        },
        handler_range_map={},
        condition_chain_blocks=(),
        rows=(
            TransitionRow(
                state_const=0x00C0C59F,
                state_range_lo=None,
                state_range_hi=None,
                handler_serial=122,
                kind=TransitionKind.TRANSITION,
                next_state=0x2FBA4611,
                conditional_states=(),
                state_label="State 0x00C0C59F",
                transition_label="next=0x2FBA4611",
                chain_preview=(122,),
                path=TransitionPath(
                    handler_serial=122,
                    chain=(122,),
                    next_state=0x2FBA4611,
                    conditional_states=(),
                    back_edge=True,
                    reaches_exit_block=False,
                    classified_exit=False,
                    unresolved=False,
                ),
            ),
            TransitionRow(
                state_const=0x42267E66,
                state_range_lo=None,
                state_range_hi=None,
                handler_serial=93,
                kind=TransitionKind.TRANSITION,
                next_state=0x24E2E77A,
                conditional_states=(),
                state_label="State 0x42267E66",
                transition_label="next=0x24E2E77A",
                chain_preview=(93, 95),
                path=TransitionPath(
                    handler_serial=93,
                    chain=(93, 95),
                    next_state=0x24E2E77A,
                    conditional_states=(),
                    back_edge=True,
                    reaches_exit_block=False,
                    classified_exit=False,
                    unresolved=False,
                ),
            ),
            TransitionRow(
                state_const=0x2FBA4611,
                state_range_lo=None,
                state_range_hi=None,
                handler_serial=180,
                kind=TransitionKind.UNKNOWN,
                next_state=None,
                conditional_states=(),
                state_label="State 0x2FBA4611",
                transition_label="unknown",
                chain_preview=(180,),
                path=TransitionPath(
                    handler_serial=180,
                    chain=(180,),
                    next_state=None,
                    conditional_states=(),
                    back_edge=False,
                    reaches_exit_block=False,
                    classified_exit=False,
                    unresolved=True,
                ),
            ),
            TransitionRow(
                state_const=0x2315233C,
                state_range_lo=None,
                state_range_hi=None,
                handler_serial=210,
                kind=TransitionKind.TRANSITION,
                next_state=0x7FDCE054,
                conditional_states=(),
                state_label="State 0x2315233C",
                transition_label="next=0x7FDCE054",
                chain_preview=(210,),
                path=TransitionPath(
                    handler_serial=210,
                    chain=(210,),
                    next_state=0x7FDCE054,
                    conditional_states=(),
                    back_edge=True,
                    reaches_exit_block=False,
                    classified_exit=False,
                    unresolved=False,
                ),
            ),
            TransitionRow(
                state_const=0x393685BA,
                state_range_lo=None,
                state_range_hi=None,
                handler_serial=108,
                kind=TransitionKind.TRANSITION,
                next_state=0x34D0F5D6,
                conditional_states=(),
                state_label="State 0x393685BA",
                transition_label="next=0x34D0F5D6",
                chain_preview=(108,),
                path=TransitionPath(
                    handler_serial=108,
                    chain=(108,),
                    next_state=0x34D0F5D6,
                    conditional_states=(),
                    back_edge=True,
                    reaches_exit_block=False,
                    classified_exit=False,
                    unresolved=False,
                ),
            ),
            TransitionRow(
                state_const=0x606DC166,
                state_range_lo=None,
                state_range_hi=None,
                handler_serial=14,
                kind=TransitionKind.UNKNOWN,
                next_state=None,
                conditional_states=(),
                state_label="State 0x606DC166",
                transition_label="unknown",
                chain_preview=(14,),
                path=TransitionPath(
                    handler_serial=14,
                    chain=(14,),
                    next_state=None,
                    conditional_states=(),
                    back_edge=False,
                    reaches_exit_block=False,
                    classified_exit=False,
                    unresolved=True,
                ),
            ),
        ),
        summary=TransitionSummary(
            handlers_total=6,
            known_count=4,
            conditional_count=0,
            exit_count=0,
            unknown_count=2,
        ),
        diagnostics=(),
    )

    def fake_build_report(**kwargs) -> DispatcherTransitionReport:
        return initial_report

    fake_paths: dict[tuple[int, int], tuple[HandlerPathResult, ...]] = {
        (93, 0x42267E66): (
            HandlerPathResult(
                exit_block=95,
                final_state=0x24E2E77A,
                state_writes=[(95, 0x1000)],
                ordered_path=[93, 95],
            ),
        ),
        (122, 0x00C0C59F): (
            HandlerPathResult(
                exit_block=122,
                final_state=0x2FBA4611,
                state_writes=[(122, 0x0FFC)],
                ordered_path=[122],
            ),
        ),
        (211, 0x24E2E77A): (
            HandlerPathResult(
                exit_block=211,
                final_state=0x3E7EA8B8,
                state_writes=[(211, 0x1004)],
                ordered_path=[211],
            ),
        ),
        (106, 0x3E7EA8B8): (
            HandlerPathResult(
                exit_block=106,
                final_state=0x604AAEA6,
                state_writes=[(106, 0x1008)],
                ordered_path=[106],
            ),
        ),
        (78, 0x604AAEA6): (
            HandlerPathResult(
                exit_block=78,
                final_state=0x606DC166,
                state_writes=[(78, 0x100C)],
                ordered_path=[78],
            ),
        ),
        (14, 0x606DC166): (
            HandlerPathResult(
                exit_block=14,
                final_state=None,
                state_writes=[],
                ordered_path=[14],
            ),
        ),
    }

    def fake_evaluate_handler_paths(
        mba,
        handler_serial,
        incoming_state,
        condition_chain_blocks,
        state_var_stkoff,
        handler_entry_blocks,
        **_kwargs,
    ) -> tuple[HandlerPathResult, ...]:
        return fake_paths.get((handler_serial, incoming_state), ())

    monkeypatch.setattr(
        dag_mod,
        "build_dispatcher_transition_report_from_graph",
        fake_build_report,
    )
    monkeypatch.setattr(
        dag_mod,
        "evaluate_handler_paths",
        fake_evaluate_handler_paths,
    )
    monkeypatch.setattr(
        dag_mod,
        "detect_conditional_transitions",
        lambda *args, **kwargs: (),
    )

    dag = build_live_linearized_state_dag_from_graph(
        flow_graph,
        transition_result,
        dispatcher_entry_serial=0,
        state_var_stkoff=0x3C,
        mba=object(),
        prefer_local_corridors=True,
    )

    present_states = {node.key.state_const for node in dag.nodes}
    assert 0x24E2E77A in present_states
    assert 0x3E7EA8B8 in present_states
    assert 0x604AAEA6 in present_states

    nodes_by_state = {
        node.key.state_const: node for node in dag.nodes if node.key.state_const is not None
    }
    assert nodes_by_state[0x24E2E77A].state_label == "0x2315233C_fallback"
    assert nodes_by_state[0x24E2E77A].entry_anchor == 211
    assert nodes_by_state[0x3E7EA8B8].state_label == "0x393685BA_fallback"
    assert nodes_by_state[0x3E7EA8B8].entry_anchor == 106
    assert nodes_by_state[0x604AAEA6].state_label == "0x606DC166_fallback"
    assert nodes_by_state[0x604AAEA6].entry_anchor == 78

    first_hop = next(
        edge
        for edge in dag.edges
        if edge.source_key.state_const == 0x42267E66
        and edge.target_state == 0x24E2E77A
    )
    assert first_hop.target_entry_anchor == 211
    assert first_hop.target_label == "0x2315233C_fallback"

    second_hop = next(
        edge
        for edge in dag.edges
        if edge.source_key.state_const == 0x24E2E77A
        and edge.target_state == 0x3E7EA8B8
    )
    assert second_hop.target_entry_anchor == 106
    assert second_hop.target_label == "0x393685BA_fallback"

    third_hop = next(
        edge
        for edge in dag.edges
        if edge.source_key.state_const == 0x3E7EA8B8
        and edge.target_state == 0x604AAEA6
    )
    assert third_hop.target_entry_anchor == 78
    assert third_hop.target_label == "0x606DC166_fallback"

    assert any(
        edge.source_key.state_const == 0x604AAEA6
        and edge.target_state == 0x606DC166
        and edge.target_entry_anchor == 14
        for edge in dag.edges
    )


def test_live_builder_prefers_exact_cover_fallback_anchor_over_bridge_row(
    monkeypatch,
) -> None:
    from d810.analyses.control_flow import linearized_state_dag as dag_mod

    flow_graph = FlowGraph(
        blocks={
            2: BlockSnapshot(2, 0, (), (95, 212), 0, 0, ()),
            93: BlockSnapshot(93, 0, (95,), (), 0, 0, ()),
            95: BlockSnapshot(95, 0, (2,), (93,), 0, 0, ()),
            122: BlockSnapshot(122, 0, (180,), (), 0, 0, ()),
            180: BlockSnapshot(180, 0, (), (122,), 0, 0, ()),
            210: BlockSnapshot(210, 0, (211, 212), (), 0, 0, ()),
            211: BlockSnapshot(211, 0, (35,), (210,), 0, 0, ()),
            212: BlockSnapshot(212, 0, (2,), (210,), 0, 0, ()),
            35: BlockSnapshot(35, 0, (), (211,), 0, 0, ()),
        },
        entry_serial=93,
        func_ea=0x40C000,
    )
    transition_from_422 = StateTransition(
        from_state=0x42267E66,
        to_state=0x24E2E77A,
        from_block=93,
        is_conditional=False,
    )
    transition_bridge = StateTransition(
        from_state=0x00C0C59F,
        to_state=0x2FBA4611,
        from_block=122,
        is_conditional=False,
    )
    transition_result = TransitionResult(
        transitions=[transition_from_422, transition_bridge],
        handlers={
            0x00C0C59F: StateHandler(
                state_value=0x00C0C59F,
                check_block=122,
                handler_blocks=[122],
                transitions=[transition_bridge],
            ),
            0x42267E66: StateHandler(
                state_value=0x42267E66,
                check_block=93,
                handler_blocks=[93, 95],
                transitions=[transition_from_422],
            ),
            0x2FBA4611: StateHandler(
                state_value=0x2FBA4611,
                check_block=180,
                handler_blocks=[180],
                transitions=[],
            ),
            0x2315233C: StateHandler(
                state_value=0x2315233C,
                check_block=211,
                handler_blocks=[211],
                transitions=[],
            ),
            0x3E7EA8B8: StateHandler(
                state_value=0x3E7EA8B8,
                check_block=212,
                handler_blocks=[212],
                transitions=[],
            ),
        },
        initial_state=0x42267E66,
        pre_header_serial=0,
        strategy_name="fixture",
        resolved_count=2,
    )
    initial_report = DispatcherTransitionReport(
        dispatcher_entry_serial=0,
        state_var_stkoff=0x3C,
        state_var_lvar_idx=None,
        pre_header_serial=None,
        initial_state=0x42267E66,
        handler_state_map={
            122: 0x00C0C59F,
            93: 0x42267E66,
            180: 0x2FBA4611,
            211: 0x2315233C,
            212: 0x3E7EA8B8,
        },
        handler_range_map={},
        condition_chain_blocks=(210,),
        rows=(
            TransitionRow(
                state_const=0x00C0C59F,
                state_range_lo=None,
                state_range_hi=None,
                handler_serial=122,
                kind=TransitionKind.TRANSITION,
                next_state=0x2FBA4611,
                conditional_states=(),
                state_label="State 0x00C0C59F",
                transition_label="next=0x2FBA4611",
                chain_preview=(122,),
                path=TransitionPath(
                    handler_serial=122,
                    chain=(122,),
                    next_state=0x2FBA4611,
                    conditional_states=(),
                    back_edge=True,
                    reaches_exit_block=False,
                    classified_exit=False,
                    unresolved=False,
                ),
            ),
            TransitionRow(
                state_const=0x42267E66,
                state_range_lo=None,
                state_range_hi=None,
                handler_serial=93,
                kind=TransitionKind.TRANSITION,
                next_state=0x24E2E77A,
                conditional_states=(),
                state_label="State 0x42267E66",
                transition_label="next=0x24E2E77A",
                chain_preview=(93, 95),
                path=TransitionPath(
                    handler_serial=93,
                    chain=(93, 95),
                    next_state=0x24E2E77A,
                    conditional_states=(),
                    back_edge=True,
                    reaches_exit_block=False,
                    classified_exit=False,
                    unresolved=False,
                ),
            ),
            TransitionRow(
                state_const=0x2FBA4611,
                state_range_lo=None,
                state_range_hi=None,
                handler_serial=180,
                kind=TransitionKind.UNKNOWN,
                next_state=None,
                conditional_states=(),
                state_label="State 0x2FBA4611",
                transition_label="unknown",
                chain_preview=(180,),
                path=TransitionPath(
                    handler_serial=180,
                    chain=(180,),
                    next_state=None,
                    conditional_states=(),
                    back_edge=False,
                    reaches_exit_block=False,
                    classified_exit=False,
                    unresolved=True,
                ),
            ),
            TransitionRow(
                state_const=0x2315233C,
                state_range_lo=None,
                state_range_hi=None,
                handler_serial=211,
                kind=TransitionKind.TRANSITION,
                next_state=0x7FDCE054,
                conditional_states=(),
                state_label="State 0x2315233C",
                transition_label="next=0x7FDCE054",
                chain_preview=(211,),
                path=TransitionPath(
                    handler_serial=211,
                    chain=(211,),
                    next_state=0x7FDCE054,
                    conditional_states=(),
                    back_edge=True,
                    reaches_exit_block=False,
                    classified_exit=False,
                    unresolved=False,
                ),
            ),
            TransitionRow(
                state_const=0x3E7EA8B8,
                state_range_lo=None,
                state_range_hi=None,
                handler_serial=212,
                kind=TransitionKind.UNKNOWN,
                next_state=None,
                conditional_states=(),
                state_label="State 0x3E7EA8B8",
                transition_label="unknown",
                chain_preview=(212,),
                path=TransitionPath(
                    handler_serial=212,
                    chain=(212,),
                    next_state=None,
                    conditional_states=(),
                    back_edge=False,
                    reaches_exit_block=False,
                    classified_exit=False,
                    unresolved=True,
                ),
            ),
        ),
        summary=TransitionSummary(
            handlers_total=5,
            known_count=3,
            conditional_count=0,
            exit_count=0,
            unknown_count=2,
        ),
        diagnostics=(),
    )

    def fake_build_report(**kwargs) -> DispatcherTransitionReport:
        return initial_report

    fake_paths: dict[tuple[int, int], tuple[HandlerPathResult, ...]] = {
        (93, 0x42267E66): (
            HandlerPathResult(
                exit_block=95,
                final_state=0x24E2E77A,
                state_writes=[(95, 0x24E2E77A)],
                ordered_path=[93, 95],
            ),
        ),
        (122, 0x00C0C59F): (
            HandlerPathResult(
                exit_block=122,
                final_state=0x2FBA4611,
                state_writes=[(122, 0x2FBA4611)],
                ordered_path=[122],
            ),
        ),
        (212, 0x24E2E77A): (
            HandlerPathResult(
                exit_block=212,
                final_state=0x3E7EA8B8,
                state_writes=[(212, 0x3E7EA8B8)],
                ordered_path=[212],
            ),
        ),
    }

    def fake_evaluate_handler_paths(
        mba,
        handler_serial,
        incoming_state,
        condition_chain_blocks,
        state_var_stkoff,
        handler_entry_blocks,
        **_kwargs,
    ) -> tuple[HandlerPathResult, ...]:
        return fake_paths.get((handler_serial, incoming_state), ())

    monkeypatch.setattr(
        dag_mod,
        "build_dispatcher_transition_report_from_graph",
        fake_build_report,
    )
    monkeypatch.setattr(
        dag_mod,
        "evaluate_handler_paths",
        fake_evaluate_handler_paths,
    )
    monkeypatch.setattr(
        dag_mod,
        "detect_conditional_transitions",
        lambda *args, **kwargs: (),
    )

    dag = build_live_linearized_state_dag_from_graph(
        flow_graph,
        transition_result,
        dispatcher_entry_serial=0,
        state_var_stkoff=0x3C,
        mba=object(),
        prefer_local_corridors=True,
    )

    nodes_by_state = {
        node.key.state_const: node for node in dag.nodes if node.key.state_const is not None
    }
    assert nodes_by_state[0x24E2E77A].entry_anchor == 212
    assert nodes_by_state[0x24E2E77A].entry_anchor != 122

    edge = next(
        edge
        for edge in dag.edges
        if edge.source_key.state_const == 0x42267E66
        and edge.target_state == 0x24E2E77A
    )
    assert edge.target_entry_anchor == 212


def test_live_builder_prefers_body_anchor_over_condition_chain_range_root(
    monkeypatch,
) -> None:
    from d810.analyses.control_flow import linearized_state_dag as dag_mod

    class FakeDispatcherRow:
        def __init__(self, target: int) -> None:
            self.target = target

    class FakeDispatcher:
        def lookup_row(self, state_value: int) -> FakeDispatcherRow | None:
            if state_value == 0x27EEEA11:
                return FakeDispatcherRow(24)
            return None

        def lookup(self, state_value: int) -> int | None:
            if state_value == 0x27EEEA11:
                return 24
            return None

    flow_graph = FlowGraph(
        blocks={
            2: BlockSnapshot(2, 0, (3, 112), (95,), 0, 0, ()),
            3: BlockSnapshot(3, 0, (), (2,), 0, 0, ()),
            24: BlockSnapshot(24, 0, (32,), (), 0, 0, ()),
            32: BlockSnapshot(32, 0, (), (24,), 0, 0, ()),
            23: BlockSnapshot(23, 0, (), (24,), 0, 0, ()),
            93: BlockSnapshot(93, 0, (95,), (), 0, 0, ()),
            95: BlockSnapshot(95, 0, (2,), (93,), 0, 0, ()),
            112: BlockSnapshot(112, 0, (), (2,), 0, 0, ()),
        },
        entry_serial=93,
        func_ea=0x40D000,
    )
    transition_to_alias = StateTransition(
        from_state=0x42267E66,
        to_state=0x27EEEA11,
        from_block=93,
        is_conditional=False,
    )
    transition_result = TransitionResult(
        transitions=[transition_to_alias],
        handlers={
            0x42267E66: StateHandler(
                state_value=0x42267E66,
                check_block=93,
                handler_blocks=[93, 95],
                transitions=[transition_to_alias],
            ),
            0x6465D165: StateHandler(
                state_value=0x6465D165,
                check_block=23,
                handler_blocks=[23],
                transitions=[],
            ),
        },
        initial_state=0x42267E66,
        pre_header_serial=0,
        strategy_name="fixture",
        resolved_count=1,
    )
    initial_report = DispatcherTransitionReport(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        state_var_lvar_idx=None,
        pre_header_serial=None,
        initial_state=0x42267E66,
        handler_state_map={
            93: 0x42267E66,
            23: 0x6465D165,
        },
        handler_range_map={
            2: (0x258ED456, 0x296F2451),
        },
        condition_chain_blocks=(2,),
        rows=(
            TransitionRow(
                state_const=0x42267E66,
                state_range_lo=None,
                state_range_hi=None,
                handler_serial=93,
                kind=TransitionKind.TRANSITION,
                next_state=0x27EEEA11,
                conditional_states=(),
                state_label="State 0x42267E66",
                transition_label="next=0x27EEEA11",
                chain_preview=(93, 95),
                path=TransitionPath(
                    handler_serial=93,
                    chain=(93, 95),
                    next_state=0x27EEEA11,
                    conditional_states=(),
                    back_edge=True,
                    reaches_exit_block=False,
                    classified_exit=False,
                    unresolved=False,
                ),
            ),
            TransitionRow(
                state_const=0x6465D165,
                state_range_lo=None,
                state_range_hi=None,
                handler_serial=23,
                kind=TransitionKind.UNKNOWN,
                next_state=None,
                conditional_states=(),
                state_label="State 0x6465D165",
                transition_label="unknown",
                chain_preview=(23,),
                path=TransitionPath(
                    handler_serial=23,
                    chain=(23,),
                    next_state=None,
                    conditional_states=(),
                    back_edge=False,
                    reaches_exit_block=False,
                    classified_exit=False,
                    unresolved=True,
                ),
            ),
        ),
        summary=TransitionSummary(
            handlers_total=2,
            known_count=1,
            conditional_count=0,
            exit_count=0,
            unknown_count=1,
        ),
        diagnostics=(),
    )

    def fake_build_report(**kwargs) -> DispatcherTransitionReport:
        return initial_report

    fake_paths: dict[tuple[int, int], tuple[HandlerPathResult, ...]] = {
        (93, 0x42267E66): (
            HandlerPathResult(
                exit_block=95,
                final_state=0x27EEEA11,
                state_writes=[(95, 0x27EEEA11)],
                ordered_path=[93, 95],
            ),
        ),
        (24, 0x27EEEA11): (
            HandlerPathResult(
                exit_block=24,
                final_state=0x6465D165,
                state_writes=[(24, 0x6465D165)],
                ordered_path=[24],
            ),
        ),
    }

    def fake_evaluate_handler_paths(
        mba,
        handler_serial,
        incoming_state,
        condition_chain_blocks,
        state_var_stkoff,
        handler_entry_blocks,
        **_kwargs,
    ) -> tuple[HandlerPathResult, ...]:
        return fake_paths.get((handler_serial, incoming_state), ())

    monkeypatch.setattr(
        dag_mod,
        "build_dispatcher_transition_report_from_graph",
        fake_build_report,
    )
    monkeypatch.setattr(
        dag_mod,
        "evaluate_handler_paths",
        fake_evaluate_handler_paths,
    )
    monkeypatch.setattr(
        dag_mod,
        "detect_conditional_transitions",
        lambda *args, **kwargs: (),
    )

    dag = build_live_linearized_state_dag_from_graph(
        flow_graph,
        transition_result,
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        dispatcher=FakeDispatcher(),
        mba=object(),
        prefer_local_corridors=True,
    )

    alias_node = next(
        node for node in dag.nodes if node.key.state_const == 0x27EEEA11
    )
    assert alias_node.entry_anchor == 24

    alias_edge = next(
        edge for edge in dag.edges if edge.source_key.state_const == 0x27EEEA11
    )
    assert alias_edge.target_state == 0x6465D165
    assert alias_edge.target_entry_anchor == 23


def test_live_builder_skips_terminal_condition_chain_supplemental_alias(
    monkeypatch,
) -> None:
    from d810.analyses.control_flow import linearized_state_dag as dag_mod

    class FakeDispatcherRow:
        def __init__(self, target: int) -> None:
            self.target = target

    class FakeDispatcher:
        def lookup_row(self, state_value: int) -> FakeDispatcherRow | None:
            if state_value == 0x27EEEA11:
                return FakeDispatcherRow(24)
            return None

        def lookup(self, state_value: int) -> int | None:
            if state_value == 0x27EEEA11:
                return 24
            return None

    flow_graph = FlowGraph(
        blocks={
            2: BlockSnapshot(2, 0, (3, 112), (95,), 0, 0, ()),
            3: BlockSnapshot(3, 0, (), (2,), 0, 0, ()),
            24: BlockSnapshot(24, 0, (), (), 0, 0, ()),
            23: BlockSnapshot(23, 0, (95,), (), 0, 0, ()),
            93: BlockSnapshot(93, 0, (95,), (), 0, 0, ()),
            95: BlockSnapshot(95, 0, (2,), (23, 93), 0, 0, ()),
            112: BlockSnapshot(112, 0, (), (2,), 0, 0, ()),
        },
        entry_serial=93,
        func_ea=0x40D080,
    )
    transition_to_alias = StateTransition(
        from_state=0x42267E66,
        to_state=0x27EEEA11,
        from_block=93,
        is_conditional=False,
    )
    transition_result = TransitionResult(
        transitions=[transition_to_alias],
        handlers={
            0x42267E66: StateHandler(
                state_value=0x42267E66,
                check_block=93,
                handler_blocks=[93, 95],
                transitions=[transition_to_alias],
            ),
            0x6465D165: StateHandler(
                state_value=0x6465D165,
                check_block=23,
                handler_blocks=[23, 95],
                transitions=[],
            ),
        },
        initial_state=0x42267E66,
        pre_header_serial=0,
        strategy_name="fixture",
        resolved_count=1,
    )
    initial_report = DispatcherTransitionReport(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        state_var_lvar_idx=None,
        pre_header_serial=None,
        initial_state=0x42267E66,
        handler_state_map={
            23: 0x6465D165,
            93: 0x42267E66,
        },
        handler_range_map={
            2: (0x258ED456, 0x296F2451),
        },
        condition_chain_blocks=(2,),
        rows=(
            TransitionRow(
                state_const=0x42267E66,
                state_range_lo=None,
                state_range_hi=None,
                handler_serial=93,
                kind=TransitionKind.TRANSITION,
                next_state=0x27EEEA11,
                conditional_states=(),
                state_label="State 0x42267E66",
                transition_label="next=0x27EEEA11",
                chain_preview=(93, 95),
                path=TransitionPath(
                    handler_serial=93,
                    chain=(93, 95),
                    next_state=0x27EEEA11,
                    conditional_states=(),
                    back_edge=True,
                    reaches_exit_block=False,
                    classified_exit=False,
                    unresolved=False,
                ),
            ),
            TransitionRow(
                state_const=0x6465D165,
                state_range_lo=None,
                state_range_hi=None,
                handler_serial=23,
                kind=TransitionKind.EXIT,
                next_state=None,
                conditional_states=(),
                state_label="State 0x6465D165",
                transition_label="return",
                chain_preview=(23, 95),
                path=TransitionPath(
                    handler_serial=23,
                    chain=(23, 95),
                    next_state=None,
                    conditional_states=(),
                    back_edge=False,
                    reaches_exit_block=True,
                    classified_exit=True,
                    unresolved=False,
                ),
            ),
        ),
        summary=TransitionSummary(
            handlers_total=2,
            known_count=1,
            conditional_count=0,
            exit_count=1,
            unknown_count=0,
        ),
        diagnostics=(),
    )

    fake_paths: dict[tuple[int, int], tuple[HandlerPathResult, ...]] = {
        (23, 0x6465D165): (
            HandlerPathResult(
                exit_block=95,
                final_state=None,
                state_writes=[],
                ordered_path=[23, 95],
            ),
        ),
        (93, 0x42267E66): (
            HandlerPathResult(
                exit_block=95,
                final_state=0x27EEEA11,
                state_writes=[(95, 0x27EEEA11)],
                ordered_path=[93, 95],
            ),
        ),
    }

    def fake_build_report(**kwargs) -> DispatcherTransitionReport:
        return initial_report

    def fake_evaluate_handler_paths(
        mba,
        handler_serial,
        incoming_state,
        condition_chain_blocks,
        state_var_stkoff,
        handler_entry_blocks,
        **_kwargs,
    ) -> tuple[HandlerPathResult, ...]:
        return fake_paths.get((handler_serial, incoming_state), ())

    monkeypatch.setattr(
        dag_mod,
        "build_dispatcher_transition_report_from_graph",
        fake_build_report,
    )
    monkeypatch.setattr(
        dag_mod,
        "evaluate_handler_paths",
        fake_evaluate_handler_paths,
    )
    monkeypatch.setattr(
        dag_mod,
        "detect_conditional_transitions",
        lambda *args, **kwargs: (),
    )
    monkeypatch.setattr(
        dag_mod,
        "resolve_exit_via_condition_chain_default_snapshot",
        lambda flow_graph, dispatcher_root_serial, state_value: 24
        if state_value == 0x27EEEA11
        else None,
    )
    monkeypatch.setattr(
        dag_mod,
        "can_reach_return_snapshot",
        lambda flow_graph, serial: serial == 24,
    )

    dag = build_live_linearized_state_dag_from_graph(
        flow_graph,
        transition_result,
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        dispatcher=FakeDispatcher(),
        mba=object(),
        prefer_local_corridors=True,
    )

    assert not any(node.key.state_const == 0x27EEEA11 for node in dag.nodes)
    edge = next(edge for edge in dag.edges if edge.source_key.state_const == 0x42267E66)
    assert edge.target_state == 0x27EEEA11
    assert edge.target_entry_anchor == 24
    assert edge.target_key is None


def test_terminal_condition_chain_alias_requires_existing_terminal_edge_exit(
    monkeypatch,
) -> None:
    from d810.analyses.control_flow import linearized_state_dag as dag_mod

    flow_graph = FlowGraph(
        blocks={
            0: BlockSnapshot(0, 0, (), (), 0, 0, ()),
            10: BlockSnapshot(10, 0, (20,), (), 0, 0, ()),
            20: BlockSnapshot(20, 0, (), (10,), 0, 0, ()),
            30: BlockSnapshot(30, 0, (), (), 0, 0, ()),
            99: BlockSnapshot(99, 0, (), (), 0, 0, ()),
        },
        entry_serial=10,
        func_ea=0x40D090,
    )
    report = DispatcherTransitionReport(
        dispatcher_entry_serial=0,
        state_var_stkoff=0x3C,
        state_var_lvar_idx=None,
        pre_header_serial=None,
        initial_state=0x1000,
        handler_state_map={10: 0x1000},
        handler_range_map={},
        condition_chain_blocks=(0,),
        rows=(
            TransitionRow(
                state_const=0x1000,
                state_range_lo=None,
                state_range_hi=None,
                handler_serial=10,
                kind=TransitionKind.UNKNOWN,
                next_state=None,
                conditional_states=(),
                state_label="State 0x1000",
                transition_label="unknown",
                chain_preview=(10, 20),
                path=TransitionPath(
                    handler_serial=10,
                    chain=(10, 20),
                    next_state=None,
                    conditional_states=(),
                    back_edge=False,
                    reaches_exit_block=False,
                    classified_exit=False,
                    unresolved=True,
                ),
            ),
        ),
        summary=TransitionSummary(
            handlers_total=1,
            known_count=0,
            conditional_count=0,
            exit_count=0,
            unknown_count=1,
        ),
        diagnostics=(),
    )
    transition_result = TransitionResult(
        transitions=[],
        handlers={
            0x1000: StateHandler(
                state_value=0x1000,
                check_block=10,
                handler_blocks=[10, 20],
                transitions=[],
            ),
        },
        initial_state=0x1000,
        pre_header_serial=0,
        strategy_name="fixture",
        resolved_count=0,
    )
    paths_by_handler = {
        10: (
            HandlerPathResult(
                exit_block=20,
                final_state=0x2000,
                state_writes=[(20, 0x2000)],
                ordered_path=[10, 20],
            ),
        ),
    }
    dag = LinearizedStateDag(
        dispatcher_entry_serial=0,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=0x1000,
        condition_chain_blocks=(0,),
        nodes=(),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.EXIT_ROUTINE,
                source_key=StateDagNodeKey(99, 0xDEAD),
                target_key=None,
                target_state=None,
                target_entry_anchor=None,
                target_label="return",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.EXIT_BLOCK,
                    block_serial=99,
                ),
                ordered_path=(99,),
            ),
        ),
    )

    monkeypatch.setattr(
        dag_mod,
        "resolve_exit_via_condition_chain_default_snapshot",
        lambda flow_graph, dispatcher_root_serial, state_value: 30
        if state_value == 0x2000
        else None,
    )
    monkeypatch.setattr(
        dag_mod,
        "can_reach_return_snapshot",
        lambda flow_graph, serial: serial == 30,
    )

    (
        supplemental_states,
        _,
        source_contexts,
        _transient_states,
        terminal_alias_states,
    ) = dag_mod._discover_supplemental_states(
        report,
        transition_result,
        paths_by_handler,
        {},
        dag,
        flow_graph,
    )

    assert supplemental_states == {0x2000}
    assert source_contexts == {0x2000: {(10, 20)}}
    assert terminal_alias_states == set()


def test_state_resolver_prefers_dispatcher_lookup_over_range_map() -> None:
    class FakeDispatcherRow:
        def __init__(self, target: int) -> None:
            self.target = target

    class FakeDispatcher:
        def lookup_row(self, state_value: int) -> FakeDispatcherRow | None:
            if state_value == 0x27EEEA11:
                return FakeDispatcherRow(24)
            return None

        def lookup(self, state_value: int) -> int | None:
            if state_value == 0x27EEEA11:
                return 24
            return None

    flow_graph = FlowGraph(
        blocks={
            2: BlockSnapshot(2, 0, (3, 112), (), 0, 0, ()),
            3: BlockSnapshot(3, 0, (), (2,), 0, 0, ()),
            24: BlockSnapshot(24, 0, (), (), 0, 0, ()),
            93: BlockSnapshot(93, 0, (), (), 0, 0, ()),
        },
        entry_serial=93,
        func_ea=0x40D100,
    )
    transition_to_alias = StateTransition(
        from_state=0x42267E66,
        to_state=0x27EEEA11,
        from_block=93,
        is_conditional=False,
    )
    transition_result = TransitionResult(
        transitions=[transition_to_alias],
        handlers={
            0x42267E66: StateHandler(
                state_value=0x42267E66,
                check_block=93,
                handler_blocks=[93],
                transitions=[transition_to_alias],
            ),
        },
        initial_state=0x42267E66,
        pre_header_serial=None,
        strategy_name="fixture",
        resolved_count=1,
    )
    report = DispatcherTransitionReport(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        state_var_lvar_idx=None,
        pre_header_serial=None,
        initial_state=0x42267E66,
        handler_state_map={93: 0x42267E66},
        handler_range_map={2: (0x258ED456, 0x296F2451)},
        condition_chain_blocks=(2,),
        rows=(
            TransitionRow(
                state_const=0x42267E66,
                state_range_lo=None,
                state_range_hi=None,
                handler_serial=93,
                kind=TransitionKind.TRANSITION,
                next_state=0x27EEEA11,
                conditional_states=(),
                state_label="State 0x42267E66",
                transition_label="next=0x27EEEA11",
                chain_preview=(93,),
                path=TransitionPath(
                    handler_serial=93,
                    chain=(93,),
                    next_state=0x27EEEA11,
                    conditional_states=(),
                    back_edge=True,
                    reaches_exit_block=False,
                    classified_exit=False,
                    unresolved=False,
                ),
            ),
        ),
        summary=TransitionSummary(
            handlers_total=1,
            known_count=1,
            conditional_count=0,
            exit_count=0,
            unknown_count=0,
        ),
        diagnostics=(),
    )

    dag = build_linearized_state_dag_from_graph(
        flow_graph,
        report,
        transition_result,
        dispatcher=FakeDispatcher(),
    )

    edge = next(edge for edge in dag.edges if edge.source_key.state_const == 0x42267E66)
    assert edge.target_state == 0x27EEEA11
    assert edge.target_entry_anchor == 24
    assert edge.target_key is None


def test_stable_handoff_anchor_rejects_range_backed_only_interval_body() -> None:
    state = 0x7FDCE054
    shared_range_handler = 57
    report = DispatcherTransitionReport(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        state_var_lvar_idx=None,
        pre_header_serial=None,
        initial_state=0x1000,
        handler_state_map={10: 0x1000},
        handler_range_map={shared_range_handler: (0x7D9C16ED, 0xFFFFFFFF)},
        condition_chain_blocks=(2,),
        rows=(),
        summary=TransitionSummary(
            handlers_total=0,
            known_count=0,
            conditional_count=0,
            exit_count=0,
            unknown_count=0,
        ),
        diagnostics=(),
    )
    dispatcher = IntervalDispatcher(
        [
            IntervalRow(
                lo=0x7D9C16ED,
                hi=0x100000000,
                target=shared_range_handler,
            ),
        ],
    )

    assert _is_range_backed_only_handoff_anchor(
        state,
        shared_range_handler,
        report,
        dispatcher,
    )


def test_stable_handoff_anchor_allows_exact_dispatcher_binding() -> None:
    state = 0x7FDCE054
    exact_handler = 57
    report = DispatcherTransitionReport(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        state_var_lvar_idx=None,
        pre_header_serial=None,
        initial_state=0x1000,
        handler_state_map={10: 0x1000},
        handler_range_map={exact_handler: (0x7D9C16ED, 0xFFFFFFFF)},
        condition_chain_blocks=(2,),
        rows=(),
        summary=TransitionSummary(
            handlers_total=0,
            known_count=0,
            conditional_count=0,
            exit_count=0,
            unknown_count=0,
        ),
        diagnostics=(),
    )
    dispatcher = IntervalDispatcher(
        [
            IntervalRow(lo=state, hi=state + 1, target=exact_handler),
        ],
    )

    assert not _is_range_backed_only_handoff_anchor(
        state,
        exact_handler,
        report,
        dispatcher,
    )


def test_live_builder_rejects_self_handoff_candidate_anchor(
    monkeypatch,
) -> None:
    from d810.analyses.control_flow import linearized_state_dag as dag_mod

    flow_graph = FlowGraph(
        blocks={
            20: BlockSnapshot(20, 0, (21, 22), (), 0, 0, ()),
            21: BlockSnapshot(21, 0, (), (20,), 0, 0, ()),
            22: BlockSnapshot(22, 0, (), (20,), 0, 0, ()),
            23: BlockSnapshot(23, 0, (), (), 0, 0, ()),
            136: BlockSnapshot(136, 0, (140,), (), 0, 0, ()),
            140: BlockSnapshot(140, 0, (), (136,), 0, 0, ()),
        },
        entry_serial=136,
        func_ea=0x40C800,
    )
    transition_from_139f = StateTransition(
        from_state=0x139F2922,
        to_state=0x63F502FA,
        from_block=136,
        is_conditional=False,
    )
    transition_cover = StateTransition(
        from_state=0x63D54755,
        to_state=0x00C0C59F,
        from_block=22,
        is_conditional=False,
    )
    transition_result = TransitionResult(
        transitions=[transition_from_139f, transition_cover],
        handlers={
            0x139F2922: StateHandler(
                state_value=0x139F2922,
                check_block=136,
                handler_blocks=[136, 140],
                transitions=[transition_from_139f],
            ),
            0x63D54755: StateHandler(
                state_value=0x63D54755,
                check_block=21,
                handler_blocks=[21],
                transitions=[],
            ),
            0x00C0C59F: StateHandler(
                state_value=0x00C0C59F,
                check_block=23,
                handler_blocks=[23],
                transitions=[],
            ),
        },
        initial_state=0x139F2922,
        pre_header_serial=0,
        strategy_name="fixture",
        resolved_count=2,
    )
    initial_report = DispatcherTransitionReport(
        dispatcher_entry_serial=20,
        state_var_stkoff=0x3C,
        state_var_lvar_idx=None,
        pre_header_serial=None,
        initial_state=0x139F2922,
        handler_state_map={
            136: 0x139F2922,
            21: 0x63D54755,
            23: 0x00C0C59F,
        },
        handler_range_map={},
        condition_chain_blocks=(20,),
        rows=(
            TransitionRow(
                state_const=0x139F2922,
                state_range_lo=None,
                state_range_hi=None,
                handler_serial=136,
                kind=TransitionKind.TRANSITION,
                next_state=0x63F502FA,
                conditional_states=(),
                state_label="State 0x139F2922",
                transition_label="next=0x63F502FA",
                chain_preview=(136, 140),
                path=TransitionPath(
                    handler_serial=136,
                    chain=(136, 140),
                    next_state=0x63F502FA,
                    conditional_states=(),
                    back_edge=True,
                    reaches_exit_block=False,
                    classified_exit=False,
                    unresolved=False,
                ),
            ),
            TransitionRow(
                state_const=0x63D54755,
                state_range_lo=None,
                state_range_hi=None,
                handler_serial=21,
                kind=TransitionKind.TRANSITION,
                next_state=0x00C0C59F,
                conditional_states=(),
                state_label="State 0x63D54755",
                transition_label="next=0x00C0C59F",
                chain_preview=(21,),
                path=TransitionPath(
                    handler_serial=21,
                    chain=(21,),
                    next_state=0x00C0C59F,
                    conditional_states=(),
                    back_edge=True,
                    reaches_exit_block=False,
                    classified_exit=False,
                    unresolved=False,
                ),
            ),
            TransitionRow(
                state_const=0x00C0C59F,
                state_range_lo=None,
                state_range_hi=None,
                handler_serial=23,
                kind=TransitionKind.UNKNOWN,
                next_state=None,
                conditional_states=(),
                state_label="State 0x00C0C59F",
                transition_label="unknown",
                chain_preview=(23,),
                path=TransitionPath(
                    handler_serial=23,
                    chain=(23,),
                    next_state=None,
                    conditional_states=(),
                    back_edge=False,
                    reaches_exit_block=False,
                    classified_exit=False,
                    unresolved=True,
                ),
            ),
        ),
        summary=TransitionSummary(
            handlers_total=3,
            known_count=2,
            conditional_count=0,
            exit_count=0,
            unknown_count=1,
        ),
        diagnostics=(),
    )

    def fake_build_report(**kwargs) -> DispatcherTransitionReport:
        return initial_report

    fake_paths: dict[tuple[int, int], tuple[HandlerPathResult, ...]] = {
        (136, 0x139F2922): (
            HandlerPathResult(
                exit_block=140,
                final_state=0x63F502FA,
                state_writes=[(140, 0x63F502FA)],
                ordered_path=[136, 140],
            ),
        ),
        (140, 0x63F502FA): (
            HandlerPathResult(
                exit_block=140,
                final_state=0x63F502FA,
                state_writes=[(140, 0x63F502FA)],
                ordered_path=[140],
            ),
        ),
        (22, 0x63F502FA): (
            HandlerPathResult(
                exit_block=22,
                final_state=0x00C0C59F,
                state_writes=[(22, 0x00C0C59F)],
                ordered_path=[22],
            ),
        ),
    }

    def fake_evaluate_handler_paths(
        mba,
        handler_serial,
        incoming_state,
        condition_chain_blocks,
        state_var_stkoff,
        handler_entry_blocks,
        **_kwargs,
    ) -> tuple[HandlerPathResult, ...]:
        return fake_paths.get((handler_serial, incoming_state), ())

    monkeypatch.setattr(
        dag_mod,
        "build_dispatcher_transition_report_from_graph",
        fake_build_report,
    )
    monkeypatch.setattr(
        dag_mod,
        "evaluate_handler_paths",
        fake_evaluate_handler_paths,
    )
    monkeypatch.setattr(
        dag_mod,
        "detect_conditional_transitions",
        lambda *args, **kwargs: (),
    )

    dag = build_live_linearized_state_dag_from_graph(
        flow_graph,
        transition_result,
        dispatcher_entry_serial=20,
        state_var_stkoff=0x3C,
        mba=object(),
        prefer_local_corridors=True,
    )

    handoff_node = next(
        node for node in dag.nodes if node.key.state_const == 0x63F502FA
    )
    assert handoff_node.entry_anchor == 22

    outgoing = next(
        edge
        for edge in dag.edges
        if edge.source_key.state_const == 0x63F502FA
    )
    assert outgoing.target_state == 0x00C0C59F

def test_alias_node_normalizes_to_direct_exact_prelude() -> None:
    flow_graph = FlowGraph(
        blocks={
            77: BlockSnapshot(77, 0, (78,), (), 0, 0, ()),
            78: BlockSnapshot(78, 0, (14,), (77, 111), 0, 0, ()),
            80: BlockSnapshot(80, 0, (104,), (), 0, 0, ()),
            2: BlockSnapshot(2, 0, (), (111,), 0, 0, ()),
            104: BlockSnapshot(104, 0, (118,), (80,), 0, 0, ()),
            111: BlockSnapshot(111, 0, (2,), (), 0, 0, ()),
            14: BlockSnapshot(14, 0, (), (78,), 0, 0, ()),
            118: BlockSnapshot(118, 0, (), (104,), 0, 0, ()),
        },
        entry_serial=111,
        func_ea=0x40A000,
    )

    transition_from_alias = StateTransition(
        from_state=0x3E7EA8B8,
        to_state=0x604AAEA6,
        from_block=111,
        is_conditional=False,
    )
    transition_from_prelude = StateTransition(
        from_state=0x5D0AEBD3,
        to_state=0x606DC166,
        from_block=78,
        is_conditional=False,
    )
    transition_result = TransitionResult(
        transitions=[transition_from_alias, transition_from_prelude],
        handlers={
            0x3E7EA8B8: StateHandler(
                state_value=0x3E7EA8B8,
                check_block=111,
                handler_blocks=[111],
                transitions=[transition_from_alias],
            ),
            0x5D0AEBD3: StateHandler(
                state_value=0x5D0AEBD3,
                check_block=77,
                handler_blocks=[77, 78],
                transitions=[transition_from_prelude],
            ),
            0x5FE86821: StateHandler(
                state_value=0x5FE86821,
                check_block=81,
                handler_blocks=[81],
                transitions=[],
            ),
            0x606DC166: StateHandler(
                state_value=0x606DC166,
                check_block=14,
                handler_blocks=[14],
                transitions=[],
            ),
            0x029EEE50: StateHandler(
                state_value=0x029EEE50,
                check_block=118,
                handler_blocks=[118],
                transitions=[],
            ),
        },
        initial_state=0x3E7EA8B8,
        pre_header_serial=0,
        strategy_name="fixture",
        resolved_count=2,
    )
    report = DispatcherTransitionReport(
        dispatcher_entry_serial=0,
        state_var_stkoff=0x3C,
        state_var_lvar_idx=None,
        pre_header_serial=None,
        initial_state=0x3E7EA8B8,
        handler_state_map={
            111: 0x3E7EA8B8,
            77: 0x5D0AEBD3,
            81: 0x5FE86821,
            14: 0x606DC166,
            118: 0x029EEE50,
        },
        handler_range_map={},
        condition_chain_blocks=(),
        rows=(
            TransitionRow(
                state_const=0x3E7EA8B8,
                state_range_lo=None,
                state_range_hi=None,
                handler_serial=111,
                kind=TransitionKind.TRANSITION,
                next_state=0x604AAEA6,
                conditional_states=(),
                state_label="State 0x3E7EA8B8",
                transition_label="next=0x604AAEA6",
                chain_preview=(111,),
                path=TransitionPath(
                    handler_serial=111,
                    chain=(111,),
                    next_state=0x604AAEA6,
                    conditional_states=(),
                    back_edge=True,
                    reaches_exit_block=False,
                    classified_exit=False,
                    unresolved=False,
                ),
            ),
            TransitionRow(
                state_const=0x5D0AEBD3,
                state_range_lo=None,
                state_range_hi=None,
                handler_serial=77,
                kind=TransitionKind.TRANSITION,
                next_state=0x606DC166,
                conditional_states=(),
                state_label="State 0x5D0AEBD3",
                transition_label="next=0x606DC166",
                chain_preview=(77, 78),
                path=TransitionPath(
                    handler_serial=77,
                    chain=(77, 78),
                    next_state=0x606DC166,
                    conditional_states=(),
                    back_edge=True,
                    reaches_exit_block=False,
                    classified_exit=False,
                    unresolved=False,
                ),
            ),
            TransitionRow(
                state_const=0x5FE86821,
                state_range_lo=None,
                state_range_hi=None,
                handler_serial=81,
                kind=TransitionKind.UNKNOWN,
                next_state=None,
                conditional_states=(),
                state_label="State 0x5FE86821",
                transition_label="unknown",
                chain_preview=(81,),
                path=TransitionPath(
                    handler_serial=81,
                    chain=(81,),
                    next_state=None,
                    conditional_states=(),
                    back_edge=False,
                    reaches_exit_block=False,
                    classified_exit=False,
                    unresolved=True,
                ),
            ),
            TransitionRow(
                state_const=0x604AAEA6,
                state_range_lo=None,
                state_range_hi=None,
                handler_serial=80,
                kind=TransitionKind.TRANSITION,
                next_state=0x029EEE50,
                conditional_states=(),
                state_label="State 0x604AAEA6",
                transition_label="next=0x029EEE50",
                chain_preview=(80, 104),
                path=TransitionPath(
                    handler_serial=80,
                    chain=(80, 104),
                    next_state=0x029EEE50,
                    conditional_states=(),
                    back_edge=True,
                    reaches_exit_block=False,
                    classified_exit=False,
                    unresolved=False,
                ),
            ),
            TransitionRow(
                state_const=0x606DC166,
                state_range_lo=None,
                state_range_hi=None,
                handler_serial=14,
                kind=TransitionKind.UNKNOWN,
                next_state=None,
                conditional_states=(),
                state_label="State 0x606DC166",
                transition_label="unknown",
                chain_preview=(14,),
                path=TransitionPath(
                    handler_serial=14,
                    chain=(14,),
                    next_state=None,
                    conditional_states=(),
                    back_edge=False,
                    reaches_exit_block=False,
                    classified_exit=False,
                    unresolved=True,
                ),
            ),
            TransitionRow(
                state_const=0x029EEE50,
                state_range_lo=None,
                state_range_hi=None,
                handler_serial=118,
                kind=TransitionKind.UNKNOWN,
                next_state=None,
                conditional_states=(),
                state_label="State 0x029EEE50",
                transition_label="unknown",
                chain_preview=(118,),
                path=TransitionPath(
                    handler_serial=118,
                    chain=(118,),
                    next_state=None,
                    conditional_states=(),
                    back_edge=False,
                    reaches_exit_block=False,
                    classified_exit=False,
                    unresolved=True,
                ),
            ),
        ),
        summary=TransitionSummary(
            handlers_total=6,
            known_count=3,
            conditional_count=0,
            exit_count=0,
            unknown_count=3,
        ),
        diagnostics=(),
    )

    dag = build_linearized_state_dag_from_graph(
        flow_graph,
        report,
        transition_result,
        handler_paths_by_handler={
            80: (
                HandlerPathResult(
                    exit_block=104,
                    final_state=0x029EEE50,
                    state_writes=[(104, 0x029EEE50)],
                    ordered_path=[80, 104],
                ),
            ),
            77: (
                HandlerPathResult(
                    exit_block=78,
                    final_state=0x606DC166,
                    state_writes=[(78, 0x606DC166)],
                    ordered_path=[77, 78],
                ),
            ),
        },
    )

    node = next(node for node in dag.nodes if node.key.state_const == 0x604AAEA6)
    assert node.state_label == "0x606DC166_fallback"
    assert node.entry_anchor == 78

    incoming = next(
        edge
        for edge in dag.edges
        if edge.source_key.state_const == 0x3E7EA8B8 and edge.target_state == 0x604AAEA6
    )
    assert incoming.target_label == "0x606DC166_fallback"
    assert incoming.target_entry_anchor == 78


def test_exact_node_entry_anchor_skips_condition_chain_prefix() -> None:
    flow_graph = FlowGraph(
        blocks={
            77: BlockSnapshot(77, 0, (78, 79), (), 0, 0, ()),
            78: BlockSnapshot(78, 0, (14,), (77,), 0, 0, ()),
            79: BlockSnapshot(79, 0, (), (77,), 0, 0, ()),
            14: BlockSnapshot(14, 0, (), (78,), 0, 0, ()),
        },
        entry_serial=77,
        func_ea=0x40B000,
    )

    transition = StateTransition(
        from_state=0x5D0AEBD3,
        to_state=0x606DC166,
        from_block=78,
        is_conditional=False,
    )
    transition_result = TransitionResult(
        transitions=[transition],
        handlers={
            0x5D0AEBD3: StateHandler(
                state_value=0x5D0AEBD3,
                check_block=77,
                handler_blocks=[77, 78],
                transitions=[transition],
            ),
            0x606DC166: StateHandler(
                state_value=0x606DC166,
                check_block=14,
                handler_blocks=[14],
                transitions=[],
            ),
        },
        initial_state=0x5D0AEBD3,
        pre_header_serial=1,
        strategy_name="fixture",
        resolved_count=1,
    )
    report = DispatcherTransitionReport(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        state_var_lvar_idx=None,
        pre_header_serial=1,
        initial_state=0x5D0AEBD3,
        handler_state_map={
            77: 0x5D0AEBD3,
            14: 0x606DC166,
        },
        handler_range_map={},
        condition_chain_blocks=(77,),
        rows=(
            TransitionRow(
                state_const=0x5D0AEBD3,
                state_range_lo=None,
                state_range_hi=None,
                handler_serial=77,
                kind=TransitionKind.TRANSITION,
                next_state=0x606DC166,
                conditional_states=(),
                state_label="State 0x5D0AEBD3",
                transition_label="next=0x606DC166",
                chain_preview=(77, 78),
                path=TransitionPath(
                    handler_serial=77,
                    chain=(77, 78),
                    next_state=0x606DC166,
                    conditional_states=(),
                    back_edge=True,
                    reaches_exit_block=False,
                    classified_exit=False,
                    unresolved=False,
                ),
            ),
            TransitionRow(
                state_const=0x606DC166,
                state_range_lo=None,
                state_range_hi=None,
                handler_serial=14,
                kind=TransitionKind.UNKNOWN,
                next_state=None,
                conditional_states=(),
                state_label="State 0x606DC166",
                transition_label="unknown",
                chain_preview=(14,),
                path=TransitionPath(
                    handler_serial=14,
                    chain=(14,),
                    next_state=None,
                    conditional_states=(),
                    back_edge=False,
                    reaches_exit_block=False,
                    classified_exit=False,
                    unresolved=True,
                ),
            ),
        ),
        summary=TransitionSummary(
            handlers_total=2,
            known_count=1,
            conditional_count=0,
            exit_count=0,
            unknown_count=1,
        ),
        diagnostics=(),
    )

    dag = build_linearized_state_dag_from_graph(
        flow_graph,
        report,
        transition_result,
        handler_paths_by_handler={
            77: (
                HandlerPathResult(
                    exit_block=78,
                    final_state=0x606DC166,
                    state_writes=[(78, 0x606DC166)],
                    ordered_path=[77, 78],
                ),
            ),
        },
    )

    node = next(node for node in dag.nodes if node.key.state_const == 0x5D0AEBD3)
    assert node.entry_anchor == 78

    outgoing = next(
        edge for edge in dag.edges if edge.source_key.state_const == 0x5D0AEBD3
    )
    assert outgoing.source_anchor.block_serial == 78


def test_render_prefers_raw_target_state_over_canonical_handler_label() -> None:
    source_key = StateDagNodeKey(handler_serial=1, state_const=0x10)
    target_key = StateDagNodeKey(handler_serial=3, state_const=0x30)
    dag = LinearizedStateDag(
        dispatcher_entry_serial=0,
        state_var_stkoff=None,
        pre_header_serial=None,
        initial_state=0x10,
        condition_chain_blocks=(),
        nodes=(
            StateDagNode(
                key=source_key,
                kind=StateNodeKind.EXACT,
                state_label="0x00000010",
                handler_serial=1,
                entry_anchor=1,
                owned_blocks=(1,),
                exclusive_blocks=(1,),
                shared_suffix_blocks=(),
                local_segments=(
                    StateLocalSegment(
                        segment_id="blk[1]",
                        kind=LocalSegmentKind.STRAIGHT_LINE,
                        blocks=(1,),
                    ),
                ),
                local_edges=(),
            ),
            StateDagNode(
                key=target_key,
                kind=StateNodeKind.EXACT,
                state_label="0x00000030",
                handler_serial=3,
                entry_anchor=3,
                owned_blocks=(3,),
                exclusive_blocks=(3,),
                shared_suffix_blocks=(),
                local_segments=(
                    StateLocalSegment(
                        segment_id="blk[3]",
                        kind=LocalSegmentKind.STRAIGHT_LINE,
                        blocks=(3,),
                    ),
                ),
                local_edges=(),
            ),
        ),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
                source_key=source_key,
                target_key=target_key,
                target_state=0x31,
                target_entry_anchor=3,
                target_label="0x00000030",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                    block_serial=1,
                    branch_arm=0,
                ),
                ordered_path=(1, 2),
            ),
        ),
        diagnostics=(),
    )

    rendered = render_linearized_state_dag(dag)
    assert (
        "edge conditional_transition src=blk[1].fallthrough -> "
        "0x00000031 via 0x00000030 entry=blk[3] path=[1, 2]"
    ) in rendered


def test_unique_outgoing_path_start_reanchors_fallback_node() -> None:
    fallback_key = StateDagNodeKey(handler_serial=195, state_const=0x41FB8FBB)
    target_key = StateDagNodeKey(handler_serial=161, state_const=0x11CD1DA3)
    nodes, edges = _normalize_entry_anchors_to_unique_path_starts(
        [
            StateDagNode(
                key=fallback_key,
                kind=StateNodeKind.EXACT,
                state_label="0x41FB8FBB_fallback",
                handler_serial=195,
                entry_anchor=195,
                owned_blocks=(195,),
                exclusive_blocks=(195,),
                shared_suffix_blocks=(),
                local_segments=(),
                local_edges=(),
            ),
            StateDagNode(
                key=target_key,
                kind=StateNodeKind.EXACT,
                state_label="0x11CD1DA3",
                handler_serial=161,
                entry_anchor=161,
                owned_blocks=(161,),
                exclusive_blocks=(161,),
                shared_suffix_blocks=(),
                local_segments=(),
                local_edges=(),
            ),
        ],
        [
            StateDagEdge(
                kind=SemanticEdgeKind.TRANSITION,
                source_key=fallback_key,
                target_key=target_key,
                target_state=0x11CD1DA3,
                target_entry_anchor=161,
                target_label="0x11CD1DA3",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.UNCONDITIONAL,
                    block_serial=39,
                ),
                ordered_path=(39,),
            ),
        ],
        condition_chain_blocks=(2,),
    )

    fallback_node = next(node for node in nodes if node.key == fallback_key)
    assert fallback_node.entry_anchor == 39
    assert 39 in fallback_node.owned_blocks
    assert any(39 in segment.blocks for segment in fallback_node.local_segments)
    assert edges[0].target_entry_anchor == 161


def test_exact_point_dispatcher_node_is_not_rewritten_into_fallback_family() -> None:
    protected_key = StateDagNodeKey(handler_serial=39, state_const=0x71E22BF3)
    target_key = StateDagNodeKey(handler_serial=161, state_const=0x11CD1DA3)
    nodes = [
        StateDagNode(
            key=protected_key,
            kind=StateNodeKind.EXACT,
            state_label="0x71E22BF3",
            handler_serial=39,
            entry_anchor=39,
            owned_blocks=(39,),
            exclusive_blocks=(39,),
            shared_suffix_blocks=(),
            local_segments=(),
            local_edges=(),
        ),
        StateDagNode(
            key=target_key,
            kind=StateNodeKind.EXACT,
            state_label="0x11CD1DA3",
            handler_serial=161,
            entry_anchor=161,
            owned_blocks=(161,),
            exclusive_blocks=(161,),
            shared_suffix_blocks=(),
            local_segments=(),
            local_edges=(),
        ),
    ]
    edges = [
        StateDagEdge(
            kind=SemanticEdgeKind.TRANSITION,
            source_key=protected_key,
            target_key=target_key,
            target_state=0x11CD1DA3,
            target_entry_anchor=161,
            target_label="0x11CD1DA3",
            source_anchor=StateRedirectAnchor(
                kind=RedirectSourceKind.UNCONDITIONAL,
                block_serial=39,
            ),
            ordered_path=(39,),
        ),
    ]
    report = DispatcherTransitionReport(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        state_var_lvar_idx=None,
        pre_header_serial=None,
        initial_state=None,
        handler_state_map={},
        handler_range_map={},
        condition_chain_blocks=(2,),
        rows=(
            TransitionRow(
                state_const=0x71E22BF3,
                state_range_lo=None,
                state_range_hi=None,
                handler_serial=39,
                kind=TransitionKind.TRANSITION,
                next_state=0x11CD1DA3,
                conditional_states=(),
                state_label="0x71E22BF3",
                transition_label="transition",
                chain_preview=(39,),
                path=TransitionPath(
                    handler_serial=39,
                    chain=(39,),
                    next_state=0x11CD1DA3,
                    conditional_states=(),
                    back_edge=True,
                    reaches_exit_block=False,
                    classified_exit=False,
                    unresolved=False,
                ),
            ),
        ),
        summary=TransitionSummary(
            handlers_total=1,
            known_count=1,
            conditional_count=0,
            exit_count=0,
            unknown_count=0,
        ),
        diagnostics=(),
    )
    transition_result = TransitionResult(
        transitions=[],
        handlers={},
        assignment_map={},
        initial_state=None,
        pre_header_serial=None,
        strategy_name="",
        resolved_count=0,
    )
    flow_graph = FlowGraph(
        blocks={
            39: BlockSnapshot(39, 0, (161,), (), 0, 0, ()),
            161: BlockSnapshot(161, 0, (), (39,), 0, 0, ()),
        },
        entry_serial=39,
        func_ea=0x401000,
    )

    alias_nodes, alias_edges = _normalize_alias_nodes(
        nodes,
        edges,
        report,
        transition_result,
        flow_graph,
        prefer_local_corridors=True,
    )
    final_nodes, final_edges = _normalize_nonhandler_exact_nodes(
        alias_nodes,
        alias_edges,
        report,
        transition_result,
        flow_graph,
        prefer_local_corridors=True,
    )

    protected_node = next(node for node in final_nodes if node.key == protected_key)
    assert protected_node.state_label == "0x71E22BF3"
    assert protected_node.entry_anchor == 39
    assert final_edges[0].target_label == "0x11CD1DA3"


def test_render_linearized_state_dag_dot_state_level() -> None:
    flow_graph = _make_branch_flow_graph()
    transition_result = _make_branch_transition_result()
    report = build_dispatcher_transition_report_from_graph(
        flow_graph=flow_graph,
        transition_result=transition_result,
        dispatcher_entry_serial=5,
    )

    dag = build_linearized_state_dag_from_graph(
        flow_graph,
        report,
        transition_result,
        handler_paths_by_handler={
            2: (
                HandlerPathResult(
                    exit_block=3,
                    final_state=0x30,
                    state_writes=[(2, 0x1000)],
                    ordered_path=[2, 3],
                ),
                HandlerPathResult(
                    exit_block=7,
                    final_state=0x40,
                    state_writes=[(2, 0x1004)],
                    ordered_path=[2, 7],
                ),
            ),
        },
        conditional_transitions_by_handler={
            2: (
                ConditionalTransition(
                    handler_entry=2,
                    branch_block=2,
                    target_state=0x30,
                    target_handler=3,
                    state_write_block=2,
                    state_write_ea=0x1000,
                    branch_arm=0,
                ),
                ConditionalTransition(
                    handler_entry=2,
                    branch_block=2,
                    target_state=0x40,
                    target_handler=7,
                    state_write_block=2,
                    state_write_ea=0x1004,
                    branch_arm=1,
                ),
            ),
        },
    )

    dot = render_linearized_state_dag_dot(dag)
    assert "digraph linearized_state_dag {" in dot
    assert "START [shape=point];" in dot
    assert "state_00000020_2" in dot
    assert 'label="conditional_transition\\nsrc=blk[2].fallthrough\\npath=[2, 3]"' in dot
    assert "state_00000020_2 -> state_00000030_3" in dot


def test_render_linearized_state_dag_dot_expanded() -> None:
    flow_graph = _make_branch_flow_graph()
    transition_result = _make_branch_transition_result()
    report = build_dispatcher_transition_report_from_graph(
        flow_graph=flow_graph,
        transition_result=transition_result,
        dispatcher_entry_serial=5,
    )

    dag = build_linearized_state_dag_from_graph(
        flow_graph,
        report,
        transition_result,
        handler_paths_by_handler={
            2: (
                HandlerPathResult(
                    exit_block=3,
                    final_state=0x30,
                    state_writes=[(2, 0x1000)],
                    ordered_path=[2, 3],
                ),
                HandlerPathResult(
                    exit_block=7,
                    final_state=0x40,
                    state_writes=[(2, 0x1004)],
                    ordered_path=[2, 7],
                ),
            ),
        },
        conditional_transitions_by_handler={
            2: (
                ConditionalTransition(
                    handler_entry=2,
                    branch_block=2,
                    target_state=0x30,
                    target_handler=3,
                    state_write_block=2,
                    state_write_ea=0x1000,
                    branch_arm=0,
                ),
                ConditionalTransition(
                    handler_entry=2,
                    branch_block=2,
                    target_state=0x40,
                    target_handler=7,
                    state_write_block=2,
                    state_write_ea=0x1004,
                    branch_arm=1,
                ),
            ),
        },
    )

    dot = render_linearized_state_dag_dot(dag, expanded=True)
    assert "subgraph cluster_state_00000020_2 {" in dot
    assert "state_00000020_2_blk_2" in dot
    assert 'state_00000020_2 -> state_00000020_2_blk_2 [style=dotted, arrowhead=none];' in dot
    assert 'state_00000020_2_blk_2 -> state_00000030_3 [label="conditional_transition\\nsrc=blk[2].fallthrough\\npath=[2, 3]"' in dot


def test_live_builder_prefers_exact_dispatcher_boundary_anchor_for_supplemental_state(
    monkeypatch,
) -> None:
    from d810.analyses.control_flow import linearized_state_dag as dag_mod

    flow_graph = FlowGraph(
        blocks={
            150: BlockSnapshot(150, 0, (151, 152), (), 0, 0, ()),
            151: BlockSnapshot(151, 0, (), (150,), 0, 0, ()),
            152: BlockSnapshot(152, 0, (), (150,), 0, 0, ()),
            201: BlockSnapshot(201, 0, (202,), (), 0, 0, ()),
            202: BlockSnapshot(202, 0, (), (201,), 0, 0, ()),
            217: BlockSnapshot(217, 0, (218,), (), 0, 0, ()),
            218: BlockSnapshot(218, 0, (), (217,), 0, 0, ()),
        },
        entry_serial=201,
        func_ea=0x40B400,
    )
    transition = StateTransition(
        from_state=0x296F2452,
        to_state=0x1A9A9DD9,
        from_block=201,
        is_conditional=False,
    )
    transition_result = TransitionResult(
        transitions=[transition],
        handlers={
            0x16F7FF74: StateHandler(
                state_value=0x16F7FF74,
                check_block=151,
                handler_blocks=[151],
                transitions=[],
            ),
            0x296F2452: StateHandler(
                state_value=0x296F2452,
                check_block=202,
                handler_blocks=[202],
                transitions=[transition],
            ),
        },
        initial_state=0x296F2452,
        pre_header_serial=0,
        strategy_name="fixture",
        resolved_count=1,
    )
    initial_report = DispatcherTransitionReport(
        dispatcher_entry_serial=0,
        state_var_stkoff=0x3C,
        state_var_lvar_idx=None,
        pre_header_serial=None,
        initial_state=0x296F2452,
        handler_state_map={
            151: 0x16F7FF74,
            202: 0x296F2452,
        },
        handler_range_map={},
        condition_chain_blocks=(150,),
        rows=(
            TransitionRow(
                state_const=0x16F7FF74,
                state_range_lo=None,
                state_range_hi=None,
                handler_serial=151,
                kind=TransitionKind.UNKNOWN,
                next_state=None,
                conditional_states=(),
                state_label="State 0x16F7FF74",
                transition_label="unknown",
                chain_preview=(151,),
                path=TransitionPath(
                    handler_serial=151,
                    chain=(151,),
                    next_state=None,
                    conditional_states=(),
                    back_edge=False,
                    reaches_exit_block=False,
                    classified_exit=False,
                    unresolved=True,
                ),
            ),
            TransitionRow(
                state_const=0x296F2452,
                state_range_lo=None,
                state_range_hi=None,
                handler_serial=202,
                kind=TransitionKind.TRANSITION,
                next_state=0x1A9A9DD9,
                conditional_states=(),
                state_label="State 0x296F2452",
                transition_label="next=0x1A9A9DD9",
                chain_preview=(201, 202),
                path=TransitionPath(
                    handler_serial=202,
                    chain=(201, 202),
                    next_state=0x1A9A9DD9,
                    conditional_states=(),
                    back_edge=True,
                    reaches_exit_block=False,
                    classified_exit=False,
                    unresolved=False,
                ),
            ),
        ),
        summary=TransitionSummary(
            handlers_total=2,
            known_count=1,
            conditional_count=0,
            exit_count=0,
            unknown_count=1,
        ),
        diagnostics=(),
    )
    dispatcher = IntervalDispatcher(
        [
            IntervalRow(lo=0x16F7FF75, hi=0x1A9A9DD9, target=152),
            IntervalRow(lo=0x1A9A9DD9, hi=0x1AB9946F, target=217),
        ]
    )

    def fake_build_report(**kwargs):
        return initial_report

    def fake_evaluate_handler_paths(
        mba,
        handler_serial,
        incoming_state,
        condition_chain_blocks,
        state_var_stkoff,
        handler_entry_blocks,
        **_kwargs,
    ) -> tuple[HandlerPathResult, ...]:
        if handler_serial == 217 and incoming_state == 0x1A9A9DD9:
            return (
                HandlerPathResult(
                    exit_block=218,
                    final_state=None,
                    state_writes=[],
                    ordered_path=[217, 218],
                ),
            )
        return ()

    monkeypatch.setattr(
        dag_mod,
        "build_dispatcher_transition_report_from_graph",
        fake_build_report,
    )
    monkeypatch.setattr(
        dag_mod,
        "evaluate_handler_paths",
        fake_evaluate_handler_paths,
    )
    monkeypatch.setattr(
        dag_mod,
        "detect_conditional_transitions",
        lambda *args, **kwargs: (),
    )

    dag = build_live_linearized_state_dag_from_graph(
        flow_graph,
        transition_result,
        dispatcher_entry_serial=0,
        state_var_stkoff=0x3C,
        mba=object(),
        dispatcher=dispatcher,
        prefer_local_corridors=True,
    )

    node = next(node for node in dag.nodes if node.key.state_const == 0x1A9A9DD9)
    assert node.entry_anchor == 217

    incoming = next(
        edge
        for edge in dag.edges
        if edge.source_key.state_const == 0x296F2452
        and edge.target_state == 0x1A9A9DD9
    )
    assert incoming.target_entry_anchor == 217


def test_terminal_alias_node_collapses_to_source_terminal_sibling() -> None:
    flow_graph = FlowGraph(
        blocks={
            47: BlockSnapshot(47, 0, (217,), (), 0, 0, ()),
            69: BlockSnapshot(69, 0, (), (164,), 0, 0, ()),
            161: BlockSnapshot(161, 0, (162, 163), (), 0, 0, ()),
            162: BlockSnapshot(162, 0, (218,), (161,), 0, 0, ()),
            163: BlockSnapshot(163, 0, (164, 165), (161,), 0, 0, ()),
            164: BlockSnapshot(164, 0, (69,), (163,), 0, 0, ()),
            165: BlockSnapshot(165, 0, (), (163,), 0, 0, ()),
            217: BlockSnapshot(217, 0, (218,), (47,), 0, 0, ()),
            218: BlockSnapshot(218, 0, (), (162, 217), 0, 0, ()),
        },
        entry_serial=161,
        func_ea=0x40B800,
    )
    transition_result = TransitionResult(
        transitions=[],
        handlers={
            0x11CD1DA3: StateHandler(
                state_value=0x11CD1DA3,
                check_block=161,
                handler_blocks=[161, 162, 163, 164, 165],
                transitions=[],
            ),
        },
        initial_state=0x11CD1DA3,
        pre_header_serial=0,
        strategy_name="fixture",
        resolved_count=1,
    )
    report = DispatcherTransitionReport(
        dispatcher_entry_serial=0,
        state_var_stkoff=0x3C,
        state_var_lvar_idx=None,
        pre_header_serial=None,
        initial_state=0x11CD1DA3,
        handler_state_map={
            161: 0x11CD1DA3,
            47: 0x6E958F9A,
        },
        handler_range_map={},
        condition_chain_blocks=(),
        rows=(
            TransitionRow(
                state_const=0x11CD1DA3,
                state_range_lo=None,
                state_range_hi=None,
                handler_serial=161,
                kind=TransitionKind.UNKNOWN,
                next_state=None,
                conditional_states=(),
                state_label="State 0x11CD1DA3",
                transition_label="unknown",
                chain_preview=(161,),
                path=TransitionPath(
                    handler_serial=161,
                    chain=(161,),
                    next_state=None,
                    conditional_states=(),
                    back_edge=False,
                    reaches_exit_block=False,
                    classified_exit=False,
                    unresolved=True,
                ),
            ),
            TransitionRow(
                state_const=0x6E958F9A,
                state_range_lo=None,
                state_range_hi=None,
                handler_serial=47,
                kind=TransitionKind.UNKNOWN,
                next_state=None,
                conditional_states=(),
                state_label="State 0x6E958F9A",
                transition_label="unknown",
                chain_preview=(47,),
                path=TransitionPath(
                    handler_serial=47,
                    chain=(47,),
                    next_state=None,
                    conditional_states=(),
                    back_edge=False,
                    reaches_exit_block=False,
                    classified_exit=False,
                    unresolved=True,
                ),
            ),
        ),
        summary=TransitionSummary(
            handlers_total=2,
            known_count=0,
            conditional_count=0,
            exit_count=0,
            unknown_count=2,
        ),
        diagnostics=(),
    )

    dag = build_linearized_state_dag_from_graph(
        flow_graph,
        report,
        transition_result,
        handler_paths_by_handler={
            161: (
                HandlerPathResult(
                    exit_block=218,
                    final_state=None,
                    state_writes=[],
                    ordered_path=[161, 162, 218],
                ),
            ),
            47: (
                HandlerPathResult(
                    exit_block=218,
                    final_state=None,
                    state_writes=[],
                    ordered_path=[47, 217, 218],
                ),
            ),
        },
        conditional_transitions_by_handler={
            161: (
                ConditionalTransition(
                    handler_entry=161,
                    branch_block=163,
                    target_state=0x6E958F9A,
                    target_handler=47,
                    state_write_block=69,
                    state_write_ea=0x401234,
                    branch_arm=0,
                ),
            ),
        },
    )

    alias_node = next(node for node in dag.nodes if node.key.state_const == 0x6E958F9A)
    assert alias_node.entry_anchor == 162

    incoming = next(
        edge
        for edge in dag.edges
        if edge.source_key.state_const == 0x11CD1DA3
        and edge.target_state == 0x6E958F9A
    )
    assert incoming.target_entry_anchor == 162


def test_resolve_target_node_reconnects_mid_interval_next_state() -> None:
    """S4: a mid-interval ``to_state`` resolves to its RANGE_BACKED node.

    Reproduces the sub_7FFD 28-orphan symptom in miniature: handler blk[10]
    (exact state ``0x10000000``) writes next-state ``0x79F598F7``, which is NOT
    an exact key but lies inside the interval ``[0x737189D6, 0x7C2C0220]`` owned
    by the RANGE_BACKED handler blk[52].  Before S4 the exact-only
    ``node_by_state.get`` missed and the edge ``10 -> 52`` was dropped, orphaning
    blk[52].  The interval-containment fallback (``route_via_interval_sets``)
    reconnects it.
    """
    flow_graph = FlowGraph(
        blocks={
            10: BlockSnapshot(10, 0, (52,), (), 0, 0, ()),
            52: BlockSnapshot(52, 0, (), (10,), 0, 0, ()),
        },
        entry_serial=10,
        func_ea=0x401000,
    )
    report = DispatcherTransitionReport(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        state_var_lvar_idx=None,
        pre_header_serial=None,
        initial_state=0x10000000,
        handler_state_map={10: 0x10000000},
        handler_range_map={52: (0x737189D6, 0x7C2C0220)},
        condition_chain_blocks=(),
        rows=(
            TransitionRow(
                state_const=0x10000000,
                state_range_lo=None,
                state_range_hi=None,
                handler_serial=10,
                kind=TransitionKind.TRANSITION,
                next_state=0x79F598F7,
                conditional_states=(),
                state_label="0x10000000",
                transition_label="0x10000000",
                chain_preview=(10,),
                path=TransitionPath(
                    handler_serial=10,
                    chain=(10,),
                    next_state=0x79F598F7,
                    conditional_states=(),
                    back_edge=False,
                    reaches_exit_block=False,
                    classified_exit=False,
                    unresolved=False,
                ),
            ),
            TransitionRow(
                state_const=None,
                state_range_lo=0x737189D6,
                state_range_hi=0x7C2C0220,
                handler_serial=52,
                kind=TransitionKind.UNKNOWN,
                next_state=None,
                conditional_states=(),
                state_label="range alias",
                transition_label="range alias",
                chain_preview=(52,),
                path=TransitionPath(
                    handler_serial=52,
                    chain=(52,),
                    next_state=None,
                    conditional_states=(),
                    back_edge=False,
                    reaches_exit_block=False,
                    classified_exit=False,
                    unresolved=True,
                ),
            ),
        ),
        summary=TransitionSummary(
            handlers_total=2,
            known_count=1,
            conditional_count=0,
            exit_count=0,
            unknown_count=1,
        ),
        diagnostics=(),
    )
    transition_result = TransitionResult(
        transitions=[
            StateTransition(
                from_state=0x10000000,
                to_state=0x79F598F7,
                from_block=10,
                is_conditional=False,
            ),
        ],
        handlers={
            0x10000000: StateHandler(
                state_value=0x10000000,
                check_block=10,
                handler_blocks=[10],
                transitions=[
                    StateTransition(
                        from_state=0x10000000,
                        to_state=0x79F598F7,
                        from_block=10,
                        is_conditional=False,
                    ),
                ],
            ),
        },
        initial_state=0x10000000,
        strategy_name="test",
        resolved_count=1,
    )

    dag = build_linearized_state_dag_from_graph(
        flow_graph,
        report,
        transition_result,
    )

    # The RANGE_BACKED node for blk[52] exists.
    range_node = next(
        node
        for node in dag.nodes
        if node.handler_serial == 52
        and node.kind == StateNodeKind.RANGE_BACKED
    )

    # The mid-interval edge 10 -> 52 is reconnected (target_key resolves to the
    # RANGE_BACKED node, NOT dropped to None).
    reconnect = next(
        edge
        for edge in dag.edges
        if edge.target_state == 0x79F598F7
    )
    assert reconnect.target_key is not None
    assert reconnect.target_key == range_node.key
    assert reconnect.target_key.handler_serial == 52


def test_interval_set_router_matches_mid_interval_handler() -> None:
    """Contract: the single IntervalSet router routes the mid-interval value to 52."""
    from d810.analyses.control_flow.comparison_dispatcher_model import (
        build_partition,
        intervals_from_range_map,
        route_via_interval_sets,
    )

    partition = build_partition(
        {0x10000000: 10}, intervals_from_range_map({52: (0x737189D6, 0x7C2C0220)})
    )
    assert route_via_interval_sets(0x79F598F7, target_intervals=partition) == 52
    # Exact keys still win and out-of-range values still miss.
    assert route_via_interval_sets(0x10000000, target_intervals=partition) == 10
    assert route_via_interval_sets(0x00000001, target_intervals=partition) is None
