from __future__ import annotations

from types import SimpleNamespace

from d810.cfg.flowgraph import BlockSnapshot, FlowGraph
from d810.recon.collectors.handler_transitions import HandlerTransitionsCollector
from d810.recon.flow.transition_builder import (
    StateHandler,
    StateTransition,
    TransitionResult,
)
from d810.recon.flow.transition_report import (
    TransitionKind,
    build_dispatcher_transition_report_from_graph,
    transition_report_to_dict,
)
from d810.recon.phase import ALL_MATURITIES


def _make_flow_graph() -> FlowGraph:
    return FlowGraph(
        blocks={
            0: BlockSnapshot(0, 0, (1, 2), (), 0, 0, ()),
            1: BlockSnapshot(1, 0, (3,), (0,), 0, 0, ()),
            2: BlockSnapshot(2, 0, (2,), (0, 2), 0, 0, ()),
            3: BlockSnapshot(3, 0, (), (1,), 0, 0, ()),
        },
        entry_serial=0,
        func_ea=0x401000,
    )


def _make_transition_result() -> TransitionResult:
    return TransitionResult(
        transitions=[
            StateTransition(0x10, 0x20, from_block=1),
        ],
        handlers={
            0x10: StateHandler(
                state_value=0x10,
                check_block=1,
                handler_blocks=[1],
                transitions=[StateTransition(0x10, 0x20, from_block=1)],
            ),
            0x20: StateHandler(
                state_value=0x20,
                check_block=2,
                handler_blocks=[2],
                transitions=[],
            ),
        },
        initial_state=0x10,
        pre_header_serial=9,
        strategy_name="fixture",
        resolved_count=1,
    )


def test_collector_accepts_serialized_report_without_dispatcher_metadata():
    collector = HandlerTransitionsCollector()
    report = build_dispatcher_transition_report_from_graph(
        flow_graph=_make_flow_graph(),
        transition_result=_make_transition_result(),
        dispatcher_entry_serial=5,
    )
    target = SimpleNamespace(
        metadata={"transition_report": transition_report_to_dict(report)}
    )

    result = collector.collect(target=target, func_ea=0x401000, maturity=7)

    assert collector.maturities is ALL_MATURITIES
    assert result.metrics["handlers_total"] == 2
    assert result.metrics["transition_report"]["dispatcher_entry_serial"] == 5


def test_collector_builds_graph_portable_report_from_metadata():
    collector = HandlerTransitionsCollector()
    target = SimpleNamespace(
        metadata={
            "flow_graph": _make_flow_graph(),
            "transition_result": _make_transition_result(),
            "dispatcher_entry_serial": 5,
        }
    )

    result = collector.collect(target=target, func_ea=0x401000, maturity=7)

    assert result.metrics["handlers_total"] == 2
    assert result.metrics["handlers_known"] == 1
    assert result.metrics["handlers_unknown"] == 1
    rows = result.metrics["transition_report"]["rows"]
    assert {row["kind"] for row in rows} == {TransitionKind.TRANSITION.name, TransitionKind.UNKNOWN.name}
