from __future__ import annotations

from d810.cfg.flowgraph import BlockSnapshot, FlowGraph
from d810.recon.flow.interval_map import IntervalDispatcher, IntervalRow
from d810.recon.flow.linearized_state_dag import (
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
    _normalize_alias_nodes,
    _normalize_nonhandler_exact_nodes,
    _normalize_entry_anchors_to_unique_path_starts,
    _resolve_owner_family_fallback,
    build_live_linearized_state_dag_from_graph,
    build_linearized_state_dag_from_graph,
    render_linearized_state_program,
    render_linearized_state_dag,
    render_linearized_state_dag_dot,
)
from d810.recon.flow.state_machine_analysis import (
    ConditionalTransition,
    HandlerPathResult,
)
from d810.recon.flow.transition_builder import (
    StateHandler,
    StateTransition,
    TransitionResult,
)
from d810.recon.flow.transition_report import (
    DispatcherTransitionReport,
    TransitionKind,
    TransitionPath,
    TransitionRow,
    TransitionSummary,
    build_dispatcher_transition_report_from_graph,
)


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
        bst_node_blocks=(),
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
        bst_node_blocks=(),
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
        bst_node_blocks=(),
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
        bst_node_blocks=(),
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
        bst_node_blocks=(),
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
        bst_node_blocks=(),
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
        bst_node_blocks=(),
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
        bst_node_blocks=(),
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
        bst_node_blocks=(),
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
        bst_node_blocks=(),
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


def test_render_linearized_state_program_minimal_comment_mode_hides_metadata_scaffolding() -> None:
    source_key = StateDagNodeKey(handler_serial=20, state_const=0x20)
    target_key = StateDagNodeKey(handler_serial=30, state_const=0x30)
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=0x20,
        bst_node_blocks=(),
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
        bst_node_blocks=(),
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
    from d810.recon.flow import linearized_state_dag as dag_mod

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

    filtered = dag_mod._suppress_bst_extension_alias_edges(
        [alias_edge, concrete_edge],
        bst_node_blocks={2},
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
        bst_node_blocks=(11,),
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
        bst_node_blocks=(),
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
        bst_node_blocks=(),
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
    from d810.recon.flow import linearized_state_dag as dag_mod

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
        bst_node_blocks=(),
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
        bst_node_blocks,
        state_var_stkoff,
        handler_entry_blocks,
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
    from d810.recon.flow import linearized_state_dag as dag_mod

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
        bst_node_blocks=(210,),
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
        bst_node_blocks,
        state_var_stkoff,
        handler_entry_blocks,
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


def test_live_builder_prefers_dispatcher_body_anchor_over_bst_range_root(
    monkeypatch,
) -> None:
    from d810.recon.flow import linearized_state_dag as dag_mod

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
        bst_node_blocks=(2,),
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
        bst_node_blocks,
        state_var_stkoff,
        handler_entry_blocks,
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
        bst_node_blocks=(2,),
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


def test_live_builder_rejects_self_handoff_candidate_anchor(
    monkeypatch,
) -> None:
    from d810.recon.flow import linearized_state_dag as dag_mod

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
        bst_node_blocks=(20,),
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
        bst_node_blocks,
        state_var_stkoff,
        handler_entry_blocks,
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
        bst_node_blocks=(),
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


def test_exact_node_entry_anchor_skips_bst_prefix() -> None:
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
        bst_node_blocks=(77,),
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
        bst_node_blocks=(),
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
        bst_node_blocks=(2,),
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
        bst_node_blocks=(2,),
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
    from d810.recon.flow import linearized_state_dag as dag_mod

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
        bst_node_blocks=(150,),
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
        bst_node_blocks,
        state_var_stkoff,
        handler_entry_blocks,
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
        bst_node_blocks=(),
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
