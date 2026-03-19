from __future__ import annotations

from d810.cfg.flowgraph import BlockSnapshot, FlowGraph
from d810.recon.flow.linearized_state_dag import (
    LinearizedStateDag,
    LocalSegmentKind,
    LocalEdgeKind,
    RedirectSourceKind,
    SemanticEdgeKind,
    StateDagEdge,
    StateDagNode,
    StateDagNodeKey,
    StateLocalSegment,
    StateNodeKind,
    StateRedirectAnchor,
    build_live_linearized_state_dag_from_graph,
    build_linearized_state_dag_from_graph,
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
        and edge.ordered_path == (131, 174, 176, 200)
        for edge in acd_edges
    )
    assert not any(
        edge.kind == SemanticEdgeKind.TRANSITION
        and edge.target_state == 0x6465D165
        for edge in acd_edges
    )

    rendered = render_linearized_state_dag(dag)
    assert "blk[176] -join-> blk[200]" in rendered
    assert (
        "edge conditional_transition src=blk[174].taken -> "
        "0x258ED455 entry=blk[199] path=[131, 174, 176, 200]"
    ) in rendered


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
            211: BlockSnapshot(211, 0, (106,), (95,), 0, 0, ()),
            106: BlockSnapshot(106, 0, (78,), (211,), 0, 0, ()),
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
    transition_result = TransitionResult(
        transitions=[transition_from_422],
        handlers={
            0x42267E66: StateHandler(
                state_value=0x42267E66,
                check_block=93,
                handler_blocks=[93, 95],
                transitions=[transition_from_422],
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
        handler_state_map={93: 0x42267E66, 14: 0x606DC166},
        handler_range_map={},
        bst_node_blocks=(),
        rows=(
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
    )

    present_states = {node.key.state_const for node in dag.nodes}
    assert 0x24E2E77A in present_states
    assert 0x3E7EA8B8 in present_states
    assert 0x604AAEA6 in present_states

    assert any(
        edge.source_key.state_const == 0x42267E66
        and edge.target_state == 0x24E2E77A
        and edge.target_entry_anchor == 211
        for edge in dag.edges
    )
    assert any(
        edge.source_key.state_const == 0x24E2E77A
        and edge.target_state == 0x3E7EA8B8
        and edge.target_entry_anchor == 106
        for edge in dag.edges
    )
    assert any(
        edge.source_key.state_const == 0x3E7EA8B8
        and edge.target_state == 0x604AAEA6
        and edge.target_entry_anchor == 78
        for edge in dag.edges
    )
    assert any(
        edge.source_key.state_const == 0x604AAEA6
        and edge.target_state == 0x606DC166
        and edge.target_entry_anchor == 14
        for edge in dag.edges
    )


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
