from __future__ import annotations

from types import SimpleNamespace

from d810.recon.flow import linearized_dag_round_discovery as discovery
from d810.recon.flow.linearized_state_dag import SemanticEdgeKind


class _FakeKey:
    def __init__(self, handler_serial: int):
        self.handler_serial = int(handler_serial)


class _FakeAnchor:
    def __init__(self, block_serial: int):
        self.block_serial = int(block_serial)


class _FakeEdge:
    def __init__(
        self,
        *,
        kind,
        handler_serial: int,
        ordered_path: tuple[int, ...],
        target_entry_anchor: int | None = None,
    ):
        self.kind = kind
        self.source_key = _FakeKey(handler_serial)
        self.source_anchor = _FakeAnchor(ordered_path[0])
        self.ordered_path = ordered_path
        self.target_entry_anchor = target_entry_anchor


class _FakeHandler:
    def __init__(self, check_block: int, handler_blocks: tuple[int, ...]):
        self.check_block = int(check_block)
        self.handler_blocks = tuple(int(block) for block in handler_blocks)


def test_build_linearized_dag_round_summary_collects_exit_and_terminal_facts(monkeypatch):
    transition_edge = _FakeEdge(
        kind=SemanticEdgeKind.TRANSITION,
        handler_serial=10,
        ordered_path=(100, 101),
        target_entry_anchor=200,
    )
    return_edge = _FakeEdge(
        kind=SemanticEdgeKind.CONDITIONAL_RETURN,
        handler_serial=20,
        ordered_path=(300, 301),
    )
    unknown_edge = _FakeEdge(
        kind=SemanticEdgeKind.UNKNOWN,
        handler_serial=30,
        ordered_path=(400,),
    )
    dag = SimpleNamespace(
        edges=(transition_edge, return_edge, unknown_edge),
        nodes=(
            SimpleNamespace(handler_serial=20, owned_blocks=(20, 21)),
            SimpleNamespace(handler_serial=30, owned_blocks=(30,)),
        ),
    )

    monkeypatch.setattr(
        discovery,
        "build_live_linearized_state_dag_from_graph",
        lambda *args, **kwargs: dag,
    )
    monkeypatch.setattr(
        discovery,
        "build_dispatcher_transition_report_from_graph",
        lambda *args, **kwargs: SimpleNamespace(
            rows=(
                SimpleNamespace(handler_serial=10, kind=discovery.TransitionKind.EXIT),
                SimpleNamespace(handler_serial=40, kind=discovery.TransitionKind.EXIT),
            )
        ),
    )
    monkeypatch.setattr(
        discovery,
        "select_plannable_dag_edges",
        lambda dag_obj: (transition_edge,),
    )

    result = discovery.build_linearized_dag_round_summary(
        current_flow_graph=object(),
        transition_result=object(),
        dispatcher_serial=2,
        state_var_stkoff=None,
        pre_header_serial=1,
        initial_state=0x10,
        handler_range_map={},
        bst_node_blocks=(2,),
        diagnostics=(),
        dispatcher=None,
        mba=None,
        handlers={
            10: _FakeHandler(10, (11,)),
            40: _FakeHandler(40, (41, 42)),
        },
    )

    assert result.dag is dag
    assert result.report_exit_handlers == frozenset({40})
    assert result.report_exit_owned_blocks == frozenset({40, 41, 42})
    assert result.terminal_source_handlers == frozenset({20, 30})
    assert result.terminal_source_owned_blocks == frozenset({20, 21, 30})
    assert result.terminal_protected_blocks == frozenset({300, 301, 400})
    assert result.terminal_skipped == 1
    assert result.unknown_skipped == 1
    assert len(result.plannable_edges) == 1
    assert result.plannable_edges[0].source_anchor_block == 100
    assert result.plannable_edges[0].ordered_path == (100, 101)
    assert result.plannable_edges[0].target_entry_anchor == 200
    assert result.plannable_edges[0].requires_safe_target_resolution
