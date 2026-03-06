from __future__ import annotations

from d810.cfg.flowgraph import BlockSnapshot, FlowGraph
from d810.recon.flow.transition_analysis import build_transition_analysis_from_graph
from d810.recon.flow.transition_builder import (
    StateHandler,
    StateTransition,
    TransitionResult,
)
from d810.recon.flow.transition_report import (
    TransitionKind,
    build_dispatcher_transition_report,
    build_dispatcher_transition_report_from_graph,
    transition_report_from_dict,
    transition_report_to_dict,
)


class _DummyMBA:
    pass


def _make_flow_graph() -> FlowGraph:
    blocks = {
        0: BlockSnapshot(0, 0, (1, 2, 3, 7), (), 0, 0, ()),
        1: BlockSnapshot(1, 0, (0,), (0,), 0, 0, ()),
        2: BlockSnapshot(2, 0, (0,), (0,), 0, 0, ()),
        3: BlockSnapshot(3, 0, (4,), (0,), 0, 0, ()),
        4: BlockSnapshot(4, 0, (), (3,), 0, 0, ()),
        7: BlockSnapshot(7, 0, (7,), (0, 7), 0, 0, ()),
    }
    return FlowGraph(blocks=blocks, entry_serial=0, func_ea=0x401000)


def _make_transition_result() -> TransitionResult:
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
                handler_blocks=[3],
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


def test_build_dispatcher_transition_report_from_graph_classifies_rows():
    report = build_dispatcher_transition_report_from_graph(
        flow_graph=_make_flow_graph(),
        transition_result=_make_transition_result(),
        dispatcher_entry_serial=5,
    )

    assert report.pre_header_serial == 9
    assert report.initial_state == 0x10
    assert report.summary.handlers_total == 4
    assert report.summary.known_count == 1
    assert report.summary.conditional_count == 1
    assert report.summary.exit_count == 1
    assert report.summary.unknown_count == 1

    by_handler = {row.handler_serial: row for row in report.rows}
    assert by_handler[1].kind == TransitionKind.TRANSITION
    assert by_handler[1].transition_label == "next=0x00000020 (back-edge)"
    assert by_handler[2].kind == TransitionKind.CONDITIONAL
    assert by_handler[3].kind == TransitionKind.EXIT
    assert by_handler[3].transition_label == "RETURN (exit)"
    assert by_handler[7].kind == TransitionKind.UNKNOWN
    assert by_handler[7].transition_label == "unknown"


def test_bst_backed_and_graph_backed_reports_render_the_same_rows(monkeypatch):
    flow_graph = _make_flow_graph()
    transition_result = _make_transition_result()
    expected = build_dispatcher_transition_report_from_graph(
        flow_graph=flow_graph,
        transition_result=transition_result,
        dispatcher_entry_serial=5,
        state_var_stkoff=0x20,
        state_var_lvar_idx=3,
        bst_node_blocks=(8, 9),
        diagnostics=("portable",),
    )

    def fake_analyze(*_args, **_kwargs):
        return build_transition_analysis_from_graph(
            flow_graph,
            transition_result,
            dispatcher_entry_serial=5,
            state_var_stkoff=0x20,
            state_var_lvar_idx=3,
            bst_node_blocks=(8, 9),
            diagnostics=("portable",),
        )

    monkeypatch.setattr(
        "d810.recon.flow.transition_report.analyze_bst_dispatcher",
        fake_analyze,
    )

    actual = build_dispatcher_transition_report(
        mba=_DummyMBA(),
        dispatcher_entry_serial=5,
        state_var_stkoff=0x20,
        state_var_lvar_idx=3,
    )

    assert transition_report_to_dict(actual) == transition_report_to_dict(expected)


def test_transition_report_round_trip():
    report = build_dispatcher_transition_report_from_graph(
        flow_graph=_make_flow_graph(),
        transition_result=_make_transition_result(),
        dispatcher_entry_serial=5,
        diagnostics=("round-trip",),
    )

    payload = transition_report_to_dict(report)
    restored = transition_report_from_dict(payload)

    assert transition_report_to_dict(restored) == payload
