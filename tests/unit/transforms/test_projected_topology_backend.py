from __future__ import annotations

from d810.ir.flowgraph import BlockSnapshot, FlowGraph
from d810.transforms import projected_topology_backend as backend_mod
from d810.transforms.graph_modification import RedirectGoto
from d810.transforms.projected_topology_backend import HodurProjectedTopologyBackend


def _block(serial: int, succs: tuple[int, ...], preds: tuple[int, ...]) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=1 if succs else 0,
        succs=succs,
        preds=preds,
        flags=0,
        start_ea=0x1000 + serial,
        insn_snapshots=(),
    )


def _flow_graph() -> FlowGraph:
    return FlowGraph(
        blocks={
            1: _block(1, (2,), ()),
            2: _block(2, (3,), (1,)),
            3: _block(3, (), (2,)),
        },
        entry_serial=1,
        func_ea=0x1000,
    )


def test_materialize_state_dag_builds_mba_and_corrected_dag(monkeypatch) -> None:
    flow_graph = _flow_graph()
    transition_result = object()
    calls: dict[str, object] = {}

    def _build_mba(arg):
        calls["mba_flow_graph"] = arg
        return {"mba_for": arg.entry_serial}

    def _build_dag(arg, tr, **kwargs):
        calls["dag_flow_graph"] = arg
        calls["transition_result"] = tr
        calls["kwargs"] = kwargs
        corrected_dag_out = kwargs.get("corrected_dag_out")
        if corrected_dag_out is not None:
            corrected_dag_out.append("corrected")
        return "dag"

    monkeypatch.setattr(backend_mod, "build_mba_view_from_flow_graph", _build_mba)
    monkeypatch.setattr(
        backend_mod, "build_live_linearized_state_dag_from_graph", _build_dag
    )

    result = HodurProjectedTopologyBackend().materialize_state_dag(
        flow_graph,
        transition_result,
        dispatcher_entry_serial=99,
        state_var_stkoff=0xA0,
        pre_header_serial=7,
        initial_state=0x1111,
        handler_range_map={10: (0x1000, 0x2000)},
        bst_node_blocks=(5, 6),
        diagnostics=("diag",),
        dispatcher="dispatcher",
        collect_corrected_dag=True,
    )

    assert result.flow_graph is flow_graph
    assert result.mba == {"mba_for": 1}
    assert result.dag == "dag"
    assert result.corrected_dag == "corrected"
    assert calls["mba_flow_graph"] is flow_graph
    assert calls["dag_flow_graph"] is flow_graph
    assert calls["transition_result"] is transition_result
    kwargs = calls["kwargs"]
    assert kwargs["dispatcher_entry_serial"] == 99
    assert kwargs["state_var_stkoff"] == 0xA0
    assert kwargs["prefer_local_corridors"] is True


def test_project_state_dag_projects_modifications_before_materializing(
    monkeypatch,
) -> None:
    flow_graph = _flow_graph()
    transition_result = object()
    calls: dict[str, object] = {}

    monkeypatch.setattr(
        backend_mod,
        "build_mba_view_from_flow_graph",
        lambda arg: {"succs": arg.as_adjacency_dict()},
    )

    def _build_dag(arg, tr, **kwargs):
        calls["projected_flow_graph"] = arg
        calls["transition_result"] = tr
        return "projected-dag"

    monkeypatch.setattr(
        backend_mod, "build_live_linearized_state_dag_from_graph", _build_dag
    )

    result = HodurProjectedTopologyBackend().project_state_dag(
        flow_graph,
        [RedirectGoto(from_serial=1, old_target=2, new_target=3)],
        transition_result,
        dispatcher_entry_serial=99,
        state_var_stkoff=None,
        pre_header_serial=None,
        initial_state=None,
        handler_range_map=None,
        bst_node_blocks=(),
        diagnostics=(),
        dispatcher=None,
    )

    assert result.flow_graph.successors(1) == (3,)
    assert result.flow_graph.metadata["projected_from_patch_plan"] is True
    assert result.dag == "projected-dag"
    assert calls["projected_flow_graph"] is result.flow_graph
    assert calls["transition_result"] is transition_result
