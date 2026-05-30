from __future__ import annotations

from types import SimpleNamespace

from d810.ir.flowgraph import BlockSnapshot, FlowGraph
from d810.transforms.graph_modification import EdgeRedirectViaPredSplit, RedirectGoto
from d810.transforms.modification_builder import ModificationBuilder
from d810.optimizers.microcode.flow.flattening.hodur.strategies import (
    semantic_exact_node as semantic_module,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.semantic_exact_node import (
    _append_deferred_terminal_side_exit_redirects,
    _append_residual_exact_row_redirects,
    _append_known_residual_corridor_redirects,
    _append_residual_shared_group_redirects,
    _append_unique_pred_split_source_redirects,
)


def test_semantic_exact_round_summary_uses_projected_topology_backend(
    monkeypatch,
):
    class _FakeProjectedTopologyBackend:
        def __init__(self) -> None:
            self.live_dag_calls: list[tuple[object, object, dict]] = []

        def build_projected_mba(self, flow_graph: object) -> object:
            raise AssertionError("semantic exact should not project an MBA")

        def build_live_dag(
            self,
            current_flow_graph: object,
            transition_result: object,
            **kwargs,
        ) -> object:
            self.live_dag_calls.append(
                (current_flow_graph, transition_result, kwargs)
            )
            return SimpleNamespace(source="backend-dag")

    backend = _FakeProjectedTopologyBackend()
    setup = SimpleNamespace(
        transition_result=SimpleNamespace(name="transition-result"),
        state_var_stkoff=0x7BC,
        pre_header_serial=9,
        bst_node_blocks=frozenset({2, 9}),
    )
    flow_graph = SimpleNamespace(name="flow-graph")
    mba = SimpleNamespace(name="mba")
    snapshot = SimpleNamespace(
        mba=mba,
        state_machine=SimpleNamespace(initial_state=0x6107F8EC),
        bst_result=SimpleNamespace(),
        flow_graph=flow_graph,
        bst_dispatcher_serial=2,
    )

    monkeypatch.setattr(
        semantic_module,
        "_PROJECTED_TOPOLOGY_BACKEND",
        backend,
    )
    monkeypatch.setattr(
        semantic_module,
        "_prepare_linearized_flow_graph_plan_setup",
        lambda **kwargs: setup,
    )

    def fake_adapt_round_summary(**kwargs):
        dag = kwargs["build_live_dag"](
            kwargs["current_flow_graph"],
            kwargs["transition_result"],
            dispatcher_entry_serial=kwargs["dispatcher_serial"],
            state_var_stkoff=kwargs["state_var_stkoff"],
            pre_header_serial=kwargs["pre_header_serial"],
            initial_state=kwargs["state_machine"].initial_state,
            handler_range_map={},
            bst_node_blocks=kwargs["bst_node_blocks"],
            diagnostics=(),
            dispatcher=None,
            mba=kwargs["dag_round_mba"],
            prefer_local_corridors=True,
        )
        return SimpleNamespace(dag=dag)

    monkeypatch.setattr(
        semantic_module,
        "adapt_linearized_dag_round_summary",
        fake_adapt_round_summary,
    )

    returned_setup, round_summary = (
        semantic_module.build_semantic_exact_round_summary(snapshot)
    )

    assert returned_setup is setup
    assert round_summary.dag.source == "backend-dag"
    assert len(backend.live_dag_calls) == 1
    live_flow_graph, transition_result, kwargs = backend.live_dag_calls[0]
    assert live_flow_graph is flow_graph
    assert transition_result is setup.transition_result
    assert kwargs["dispatcher_entry_serial"] == 2
    assert kwargs["state_var_stkoff"] == 0x7BC
    assert kwargs["pre_header_serial"] == 9
    assert kwargs["initial_state"] == 0x6107F8EC
    assert kwargs["bst_node_blocks"] == frozenset({2, 9})
    assert kwargs["mba"] is mba


def test_append_unique_pred_split_source_redirects_adds_source_redirect_for_unique_target():
    flow_graph = FlowGraph(
        blocks={
            2: BlockSnapshot(2, 0, (), (69,), 0, 0, ()),
            20: BlockSnapshot(20, 0, (69,), (), 0, 0, ()),
            69: BlockSnapshot(69, 0, (2,), (20,), 0, 0, ()),
            122: BlockSnapshot(122, 0, (), (), 0, 0, ()),
        },
        entry_serial=20,
        func_ea=0x180012B60,
    )
    modifications: list[object] = [
        EdgeRedirectViaPredSplit(
            src_block=69,
            old_target=2,
            new_target=122,
            via_pred=20,
        )
    ]
    owned_blocks: set[int] = set()
    owned_edges: set[tuple[int, int]] = set()

    accepted = _append_unique_pred_split_source_redirects(
        modifications=modifications,
        owned_blocks=owned_blocks,
        owned_edges=owned_edges,
        builder=ModificationBuilder.from_snapshot(type("S", (), {"flow_graph": flow_graph})()),
        flow_graph=flow_graph,
        dispatcher_serial=2,
    )

    assert accepted == [(69, 122)]
    assert any(
        isinstance(mod, RedirectGoto) and mod.from_serial == 69 and mod.new_target == 122
        for mod in modifications
    )


def test_append_unique_pred_split_source_redirects_skips_multi_target_sources():
    flow_graph = FlowGraph(
        blocks={
            2: BlockSnapshot(2, 0, (), (45,), 0, 0, ()),
            44: BlockSnapshot(44, 0, (45,), (), 0, 0, ()),
            122: BlockSnapshot(122, 0, (45,), (), 0, 0, ()),
            45: BlockSnapshot(45, 0, (2,), (44, 122), 0, 0, ()),
            126: BlockSnapshot(126, 0, (), (), 0, 0, ()),
            180: BlockSnapshot(180, 0, (), (), 0, 0, ()),
        },
        entry_serial=44,
        func_ea=0x180012B60,
    )
    modifications: list[object] = [
        EdgeRedirectViaPredSplit(
            src_block=45,
            old_target=2,
            new_target=126,
            via_pred=44,
        ),
        EdgeRedirectViaPredSplit(
            src_block=45,
            old_target=2,
            new_target=180,
            via_pred=122,
        ),
    ]

    accepted = _append_unique_pred_split_source_redirects(
        modifications=modifications,
        owned_blocks=set(),
        owned_edges=set(),
        builder=ModificationBuilder.from_snapshot(type("S", (), {"flow_graph": flow_graph})()),
        flow_graph=flow_graph,
        dispatcher_serial=2,
    )

    assert accepted == []
    assert not any(isinstance(mod, RedirectGoto) for mod in modifications)


def test_append_residual_shared_group_redirects_upgrades_per_pred_sources():
    flow_graph = FlowGraph(
        blocks={
            2: BlockSnapshot(2, 0, (), (195,), 0, 0, ()),
            39: BlockSnapshot(39, 0, (), (), 0, 0, ()),
            51: BlockSnapshot(51, 0, (195,), (), 0, 0, ()),
            90: BlockSnapshot(90, 0, (), (), 0, 0, ()),
            194: BlockSnapshot(194, 0, (195,), (), 0, 0, ()),
            195: BlockSnapshot(195, 0, (2,), (), 0, 0, ()),
        },
        entry_serial=51,
        func_ea=0x180012B60,
    )
    modifications: list[object] = [
        EdgeRedirectViaPredSplit(
            src_block=195,
            old_target=2,
            new_target=39,
            via_pred=51,
        ),
        EdgeRedirectViaPredSplit(
            src_block=195,
            old_target=2,
            new_target=90,
            via_pred=194,
        ),
    ]
    owned_blocks: set[int] = set()
    owned_edges: set[tuple[int, int]] = set()

    accepted, deferred = _append_residual_shared_group_redirects(
        modifications=modifications,
        owned_blocks=owned_blocks,
        owned_edges=owned_edges,
        flow_graph=flow_graph,
        dispatcher_serial=2,
    )

    assert accepted == [(195, "per_pred_redirect", ((51, 39), (194, 90)))]
    assert deferred == ()
    redirects = [
        (mod.from_serial, mod.old_target, mod.new_target)
        for mod in modifications
        if isinstance(mod, RedirectGoto)
    ]
    assert (51, 195, 39) in redirects
    assert (194, 195, 90) in redirects
    assert (195, 2, 39) in redirects
    assert not any(isinstance(mod, EdgeRedirectViaPredSplit) for mod in modifications)


def test_append_residual_shared_group_redirects_skips_deferred_poll_suffix_clone():
    flow_graph = FlowGraph(
        blocks={
            2: BlockSnapshot(2, 0, (), (45,), 0, 0, ()),
            44: BlockSnapshot(44, 0, (45,), (), 0, 0, ()),
            122: BlockSnapshot(122, 0, (45,), (), 0, 0, ()),
            45: BlockSnapshot(45, 0, (2,), (), 0, 0, ()),
            126: BlockSnapshot(126, 0, (), (), 0, 0, ()),
            180: BlockSnapshot(180, 0, (), (), 0, 0, ()),
        },
        entry_serial=44,
        func_ea=0x180012B60,
    )
    modifications: list[object] = [
        EdgeRedirectViaPredSplit(
            src_block=45,
            old_target=2,
            new_target=126,
            via_pred=44,
        ),
        EdgeRedirectViaPredSplit(
            src_block=45,
            old_target=2,
            new_target=180,
            via_pred=122,
        ),
    ]

    accepted, deferred = _append_residual_shared_group_redirects(
        modifications=modifications,
        owned_blocks=set(),
        owned_edges=set(),
        flow_graph=flow_graph,
        dispatcher_serial=2,
    )

    assert accepted == []
    assert deferred == (45,)
    assert sum(isinstance(mod, EdgeRedirectViaPredSplit) for mod in modifications) == 2


def test_append_deferred_terminal_side_exit_redirects_rewrites_deferred_shared_group_source():
    flow_graph = FlowGraph(
        blocks={
            2: BlockSnapshot(2, 0, (), (45,), 0, 0, ()),
            45: BlockSnapshot(45, 0, (2,), (), 0, 0, ()),
            127: BlockSnapshot(127, 0, (), (), 0, 0, ()),
        },
        entry_serial=45,
        func_ea=0x180012B60,
    )
    modifications: list[object] = []
    owned_blocks: set[int] = set()
    owned_edges: set[tuple[int, int]] = set()

    accepted = _append_deferred_terminal_side_exit_redirects(
        deferred_sources=(45,),
        modifications=modifications,
        owned_blocks=owned_blocks,
        owned_edges=owned_edges,
        builder=ModificationBuilder.from_snapshot(type("S", (), {"flow_graph": flow_graph})()),
        flow_graph=flow_graph,
        mba=object(),
        dag=object(),
        dispatcher_serial=2,
        bst_node_blocks=set(),
        state_var_stkoff=0x7BC,
        dispatcher=object(),
        terminal_protected_blocks={45},
        resolve_singleton_state_write=lambda *_args, **_kwargs: 0x07A8B3FB,
        resolve_exact_dispatch_target=lambda *_args, **_kwargs: 127,
        reaches_return=lambda *_args, **_kwargs: True,
    )

    assert accepted == [(45, 127, "deferred_terminal_side_exit")]
    redirects = [
        (mod.from_serial, mod.old_target, mod.new_target)
        for mod in modifications
        if isinstance(mod, RedirectGoto)
    ]
    assert redirects == [(45, 2, 127)]


def test_append_residual_exact_row_redirects_accepts_transient_corridor_entry():
    flow_graph = FlowGraph(
        blocks={
            2: BlockSnapshot(2, 0, (), (14,), 0, 0, ()),
            14: BlockSnapshot(14, 0, (2,), (), 0, 0, ()),
            44: BlockSnapshot(44, 0, (), (), 0, 0, ()),
        },
        entry_serial=14,
        func_ea=0x180012B60,
    )
    modifications: list[object] = []
    owned_blocks: set[int] = set()
    owned_edges: set[tuple[int, int]] = set()

    accepted = _append_residual_exact_row_redirects(
        modifications=modifications,
        owned_blocks=owned_blocks,
        owned_edges=owned_edges,
        builder=ModificationBuilder.from_snapshot(type("S", (), {"flow_graph": flow_graph})()),
        flow_graph=flow_graph,
        mba=object(),
        dag=object(),
        dispatcher_serial=2,
        bst_node_blocks=set(),
        state_var_stkoff=0x7BC,
        dispatcher=object(),
        resolve_singleton_state_write=lambda *_args, **_kwargs: 0x139F2922,
        resolve_exact_dispatch_target=lambda *_args, **_kwargs: 44,
        resolve_direct_dag_entry=lambda *_args, **_kwargs: 14,
        has_semantic_support=lambda *_args, **_kwargs: True,
        resolve_supplemental_selected_entry=lambda *_args, **_kwargs: None,
        is_transient_entry=lambda *_args, **_kwargs: True,
        reaches_return=lambda *_args, **_kwargs: False,
    )

    assert accepted == [(14, 44, "transient_corridor_exact_row")]
    assert any(
        isinstance(mod, RedirectGoto) and mod.from_serial == 14 and mod.new_target == 44
        for mod in modifications
    )


def test_append_residual_exact_row_redirects_uses_supplemental_selected_entry():
    flow_graph = FlowGraph(
        blocks={
            2: BlockSnapshot(2, 0, (), (33,), 0, 0, ()),
            33: BlockSnapshot(33, 0, (2,), (), 0, 0, ()),
            34: BlockSnapshot(34, 0, (), (), 0, 0, ()),
        },
        entry_serial=33,
        func_ea=0x180012B60,
    )
    modifications: list[object] = []
    owned_blocks: set[int] = set()
    owned_edges: set[tuple[int, int]] = set()

    accepted = _append_residual_exact_row_redirects(
        modifications=modifications,
        owned_blocks=owned_blocks,
        owned_edges=owned_edges,
        builder=ModificationBuilder.from_snapshot(type("S", (), {"flow_graph": flow_graph})()),
        flow_graph=flow_graph,
        mba=object(),
        dag=object(),
        dispatcher_serial=2,
        bst_node_blocks=set(),
        state_var_stkoff=0x7BC,
        dispatcher=object(),
        resolve_singleton_state_write=lambda *_args, **_kwargs: 0x27EEEA11,
        resolve_exact_dispatch_target=lambda *_args, **_kwargs: 24,
        resolve_direct_dag_entry=lambda *_args, **_kwargs: None,
        has_semantic_support=lambda *_args, **_kwargs: False,
        resolve_supplemental_selected_entry=lambda *_args, **_kwargs: 34,
        is_transient_entry=lambda *_args, **_kwargs: False,
        reaches_return=lambda *_args, **_kwargs: False,
    )

    assert accepted == [(33, 34, "supplemental_exact_row")]
    assert any(
        isinstance(mod, RedirectGoto) and mod.from_serial == 33 and mod.new_target == 34
        for mod in modifications
    )


def test_append_known_residual_corridor_redirects_uses_sample_known_entries():
    flow_graph = FlowGraph(
        blocks={
            2: BlockSnapshot(2, 0, (), (10,), 0, 0, ()),
            25: BlockSnapshot(25, 0, (), (), 0, 0, ()),
            26: BlockSnapshot(26, 0, (), (12,), 0, 0, ()),
            10: BlockSnapshot(10, 0, (2,), (), 0, 0, ()),
            12: BlockSnapshot(12, 0, (26,), (), 0, 0, ()),
            127: BlockSnapshot(127, 0, (), (), 0, 0, ()),
            136: BlockSnapshot(136, 0, (), (), 0, 0, ()),
        },
        entry_serial=10,
        func_ea=0x180012B60,
    )
    modifications: list[object] = []
    owned_blocks: set[int] = set()
    owned_edges: set[tuple[int, int]] = set()

    accepted = _append_known_residual_corridor_redirects(
        modifications=modifications,
        owned_blocks=owned_blocks,
        owned_edges=owned_edges,
        builder=ModificationBuilder.from_snapshot(type("S", (), {"flow_graph": flow_graph})()),
        flow_graph=flow_graph,
        dispatcher_serial=2,
        bst_node_blocks={26},
    )

    assert accepted == [(10, 136), (12, 25)]
    redirects = {
        (mod.from_serial, mod.old_target, mod.new_target)
        for mod in modifications
        if isinstance(mod, RedirectGoto)
    }
    assert redirects == {(10, 2, 136), (12, 26, 25)}


def test_append_residual_exact_row_redirects_adds_terminal_side_exit_and_replaces_pred_split():
    flow_graph = FlowGraph(
        blocks={
            2: BlockSnapshot(2, 0, (45,), (), 0, 0, ()),
            44: BlockSnapshot(44, 0, (45,), (), 0, 0, ()),
            45: BlockSnapshot(45, 0, (2,), (44, 122), 0, 0, ()),
            122: BlockSnapshot(122, 0, (45,), (), 0, 0, ()),
            127: BlockSnapshot(127, 0, (), (), 0, 0, ()),
        },
        entry_serial=44,
        func_ea=0x180012B60,
    )
    modifications: list[object] = [
        EdgeRedirectViaPredSplit(
            src_block=45,
            old_target=2,
            new_target=126,
            via_pred=44,
        ),
        EdgeRedirectViaPredSplit(
            src_block=45,
            old_target=2,
            new_target=180,
            via_pred=122,
        ),
    ]

    accepted = _append_residual_exact_row_redirects(
        modifications=modifications,
        owned_blocks=set(),
        owned_edges=set(),
        builder=ModificationBuilder.from_snapshot(type("S", (), {"flow_graph": flow_graph})()),
        flow_graph=flow_graph,
        mba=object(),
        dag=object(),
        dispatcher_serial=2,
        bst_node_blocks=set(),
        state_var_stkoff=0x7BC,
        dispatcher=object(),
        resolve_singleton_state_write=lambda *_args, **_kwargs: 0x07A8B3FB,
        resolve_exact_dispatch_target=lambda *_args, **_kwargs: 127,
        resolve_direct_dag_entry=lambda *_args, **_kwargs: None,
        has_semantic_support=lambda *_args, **_kwargs: False,
        reaches_return=lambda *_args, **_kwargs: True,
    )

    assert accepted == [(45, 127, "terminal_exact_row")]
    redirects = [
        (mod.from_serial, mod.old_target, mod.new_target)
        for mod in modifications
        if isinstance(mod, RedirectGoto)
    ]
    assert redirects == [(45, 2, 127)]
    assert not any(isinstance(mod, EdgeRedirectViaPredSplit) for mod in modifications)


def test_append_residual_exact_row_redirects_adds_deeper_corridor_bypass():
    flow_graph = FlowGraph(
        blocks={
            2: BlockSnapshot(2, 0, (), (14,), 0, 0, ()),
            14: BlockSnapshot(14, 0, (2,), (), 0, 0, ()),
            136: BlockSnapshot(136, 0, (), (), 0, 0, ()),
        },
        entry_serial=14,
        func_ea=0x180012B60,
    )
    modifications: list[object] = []

    accepted = _append_residual_exact_row_redirects(
        modifications=modifications,
        owned_blocks=set(),
        owned_edges=set(),
        builder=ModificationBuilder.from_snapshot(type("S", (), {"flow_graph": flow_graph})()),
        flow_graph=flow_graph,
        mba=object(),
        dag=object(),
        dispatcher_serial=2,
        bst_node_blocks=set(),
        state_var_stkoff=0x7BC,
        dispatcher=object(),
        resolve_singleton_state_write=lambda *_args, **_kwargs: 0x139F2922,
        resolve_exact_dispatch_target=lambda *_args, **_kwargs: 136,
        resolve_direct_dag_entry=lambda *_args, **_kwargs: 14,
        has_semantic_support=lambda *_args, **_kwargs: True,
        reaches_return=lambda *_args, **_kwargs: False,
    )

    assert accepted == [(14, 136, "corridor_exact_row")]
    redirects = [
        (mod.from_serial, mod.old_target, mod.new_target)
        for mod in modifications
        if isinstance(mod, RedirectGoto)
    ]
    assert redirects == [(14, 2, 136)]


def test_append_residual_exact_row_redirects_skips_semantic_terminal_owned_like_site():
    flow_graph = FlowGraph(
        blocks={
            2: BlockSnapshot(2, 0, (), (208,), 0, 0, ()),
            208: BlockSnapshot(208, 0, (2,), (), 0, 0, ()),
            132: BlockSnapshot(132, 0, (), (), 0, 0, ()),
        },
        entry_serial=208,
        func_ea=0x180012B60,
    )
    modifications: list[object] = []

    accepted = _append_residual_exact_row_redirects(
        modifications=modifications,
        owned_blocks=set(),
        owned_edges=set(),
        builder=ModificationBuilder.from_snapshot(type("S", (), {"flow_graph": flow_graph})()),
        flow_graph=flow_graph,
        mba=object(),
        dag=object(),
        dispatcher_serial=2,
        bst_node_blocks=set(),
        state_var_stkoff=0x7BC,
        dispatcher=object(),
        resolve_singleton_state_write=lambda *_args, **_kwargs: 0x09EB3382,
        resolve_exact_dispatch_target=lambda *_args, **_kwargs: 132,
        resolve_direct_dag_entry=lambda *_args, **_kwargs: 132,
        has_semantic_support=lambda *_args, **_kwargs: True,
        reaches_return=lambda *_args, **_kwargs: False,
    )

    assert accepted == []
    assert modifications == []
