from __future__ import annotations

from types import SimpleNamespace

import pytest

from d810.cfg.flowgraph import BlockSnapshot, FlowGraph
from d810.transforms.graph_modification import ConvertToGoto, RedirectBranch, RedirectGoto, ZeroStateWrite
from d810.ir.redirect import RedirectGotoIntent
from d810.optimizers.microcode.flow.flattening.hodur.strategies import (
    linearized_flow_graph as lfg_module,
)
from d810.optimizers.microcode.flow.flattening.hodur import (
    constant_fixpoint_backend as constant_backend_module,
)
from d810.optimizers.microcode.flow.flattening.hodur import (
    lfg_handoff_resolution_backend as handoff_backend_module,
)
from d810.optimizers.microcode.flow.flattening.hodur import (
    projected_topology_backend as topology_backend_module,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.linearized_flow_graph import (
    _build_narrow_branch_local_region_fallback_candidates,
    _collect_consumed_structured_region_state_edges,
    _collect_structured_region_zero_state_write_modifications,
    _collect_trivial_redirect_tail_zero_state_write_modifications,
    _collect_unmatched_region_sites,
    _sanitize_progressive_topology_modifications,
    _match_accepted_region_sites,
    _filter_unsafe_preferred_region_lowering,
    _filter_lfg_use_def_vetoes,
    _should_defer_transient_internal_region_site,
)


class _FakeProjectedTopologyBackend:
    def __init__(self) -> None:
        self.projected_mba_calls: list[object] = []
        self.project_flow_graph_calls: list[tuple[object, object]] = []
        self.live_dag_calls: list[tuple[object, object, dict]] = []

    def build_projected_mba(self, flow_graph: object) -> object:
        self.projected_mba_calls.append(flow_graph)
        return SimpleNamespace(projected_from=flow_graph)

    def project_flow_graph(
        self,
        base_flow_graph: object,
        modifications: object,
    ) -> object:
        self.project_flow_graph_calls.append((base_flow_graph, modifications))
        return SimpleNamespace(
            projected_base=base_flow_graph,
            projected_modifications=modifications,
        )

    def build_live_dag(
        self,
        current_flow_graph: object,
        transition_result: object,
        **kwargs,
    ) -> object:
        self.live_dag_calls.append((current_flow_graph, transition_result, kwargs))
        return SimpleNamespace(nodes=(), edges=())


def _empty_resolved_round_summary(dag: object) -> SimpleNamespace:
    return SimpleNamespace(
        dag=dag,
        semantic_reference_program=None,
        structured_regions=(),
        plannable_edges=(),
        report_exit_handlers=frozenset(),
        report_exit_owned_blocks=frozenset(),
        terminal_source_keys=frozenset(),
        terminal_source_handlers=frozenset(),
        terminal_source_owned_blocks=frozenset(),
        terminal_protected_blocks=frozenset(),
        terminal_skipped=0,
        unknown_skipped=0,
    )


def test_constant_fixpoint_backend_delegates_to_recon_helper(monkeypatch):
    backend = constant_backend_module.HodurConstantFixpointBackend()
    flow_graph = object()
    seen = {}

    def fake_constant_fixpoint(received_flow_graph, received_stkoff):
        seen["flow_graph"] = received_flow_graph
        seen["stkoff"] = received_stkoff
        return "constant-result"

    monkeypatch.setattr(
        constant_backend_module,
        "run_snapshot_constant_fixpoint",
        fake_constant_fixpoint,
    )

    assert backend.compute(flow_graph, 0x7BC) == "constant-result"
    assert seen == {"flow_graph": flow_graph, "stkoff": 0x7BC}


def test_lfg_structured_region_uses_constant_fixpoint_backend(monkeypatch):
    class _StopAfterConstantFixpoint(Exception):
        pass

    class _FakeConstantFixpointBackend:
        def compute(self, flow_graph: object, state_var_stkoff: int) -> object:
            assert flow_graph is expected_flow_graph
            assert state_var_stkoff == 0x7BC
            raise _StopAfterConstantFixpoint

    expected_flow_graph = object()
    monkeypatch.setattr(
        lfg_module.LinearizedFlowGraphStrategy,
        "_constant_fixpoint_backend",
        _FakeConstantFixpointBackend(),
    )

    with pytest.raises(_StopAfterConstantFixpoint):
        lfg_module.LinearizedFlowGraphStrategy._emit_structured_region_reconstruction(
            region=SimpleNamespace(internal_state_edges=()),
            dag=SimpleNamespace(bst_node_blocks=(), nodes=(), edges=()),
            semantic_reference_program=None,
            structured_regions=(),
            flow_graph=expected_flow_graph,
            state=SimpleNamespace(),
            state_var_stkoff=0x7BC,
            dispatcher_serial=2,
            dispatcher=None,
            snapshot=SimpleNamespace(
                discovery=SimpleNamespace(constant_fixpoint=None)
            ),
        )


def test_lfg_handoff_resolution_backend_delegates_to_recon_helpers(monkeypatch):
    backend = handoff_backend_module.HodurLinearizedFlowGraphHandoffResolutionBackend()
    seen = {}

    def fake_effective_target(
        dag,
        edge,
        *,
        bst_node_blocks,
        state_var_stkoff,
        dispatcher_lookup,
        dispatcher,
        mba,
    ):
        seen["effective"] = (
            dag,
            edge,
            bst_node_blocks,
            state_var_stkoff,
            dispatcher_lookup,
            dispatcher,
            mba,
        )
        return 205

    def fake_tail_target(
        dag,
        *,
        source_block,
        bst_node_blocks,
        dispatcher,
        predecessor_hints,
        require_predecessor_match,
    ):
        seen["tail"] = (
            dag,
            source_block,
            bst_node_blocks,
            dispatcher,
            predecessor_hints,
            require_predecessor_match,
        )
        return (None, 20)

    monkeypatch.setattr(
        handoff_backend_module,
        "resolve_effective_target_entry",
        fake_effective_target,
    )
    monkeypatch.setattr(
        handoff_backend_module,
        "resolve_projected_path_tail_target",
        fake_tail_target,
    )

    effective_response = backend.resolve_effective_target_entry(
        handoff_backend_module.EffectiveTargetEntryRequest(
            dag="dag",
            edge="edge",
            bst_node_blocks=frozenset({2}),
            state_var_stkoff=0x7BC,
            dispatcher_lookup="lookup",
            dispatcher="dispatcher",
            mba="mba",
        )
    )
    tail_response = backend.resolve_projected_path_tail_target(
        handoff_backend_module.ProjectedPathTailTargetRequest(
            dag="dag",
            source_block=10,
            bst_node_blocks=frozenset({2}),
            dispatcher="dispatcher",
            predecessor_hints=(9,),
            require_predecessor_match=True,
        )
    )

    assert effective_response == handoff_backend_module.EffectiveTargetEntryResponse(
        target_entry=205
    )
    assert tail_response == handoff_backend_module.ProjectedPathTailTargetResponse(
        target=(None, 20)
    )
    assert seen == {
        "effective": ("dag", "edge", {2}, 0x7BC, "lookup", "dispatcher", "mba"),
        "tail": ("dag", 10, {2}, "dispatcher", (9,), True),
    }


def test_lfg_target_resolution_hooks_use_handoff_backend(monkeypatch):
    seen = {}

    class _FakeHandoffResolutionBackend:
        def resolve_effective_target_entry(self, request):
            seen["effective"] = request
            return handoff_backend_module.EffectiveTargetEntryResponse(
                target_entry=205
            )

        def resolve_projected_path_tail_target(self, request):
            seen["tail"] = request
            return handoff_backend_module.ProjectedPathTailTargetResponse(
                target=(None, 20)
            )

        def resolve_immediate_handoff_target(self, request):
            seen["immediate"] = request
            return handoff_backend_module.HandoffTargetResponse(target=(17, 20))

        def resolve_projected_snapshot_handoff_target(self, request):
            seen["snapshot"] = request
            return handoff_backend_module.HandoffTargetResponse(target=(18, 20))

        def resolve_assignment_map_handoff_target(self, request):
            seen["assignment"] = request
            return handoff_backend_module.HandoffTargetResponse(target=(19, 20))

        def resolve_synthesized_handoff_target(self, request):
            seen["synthesized"] = request
            return handoff_backend_module.HandoffTargetResponse(target=(21, 20))

    monkeypatch.setattr(
        lfg_module.LinearizedFlowGraphStrategy,
        "_handoff_resolution_backend",
        _FakeHandoffResolutionBackend(),
    )

    assert (
        lfg_module.LinearizedFlowGraphStrategy._resolve_effective_target_entry(
            "dag",
            "edge",
            bst_node_blocks=frozenset({2}),
            state_var_stkoff=0x7BC,
            dispatcher_lookup="lookup",
            dispatcher="dispatcher",
            mba="mba",
        )
        == 205
    )
    assert (
        lfg_module.LinearizedFlowGraphStrategy._resolve_projected_path_tail_target(
            "dag",
            source_block=10,
            bst_node_blocks=frozenset({2}),
            dispatcher="dispatcher",
            predecessor_hints=(9,),
            require_predecessor_match=True,
        )
        == (None, 20)
    )
    assert (
        lfg_module.LinearizedFlowGraphStrategy._resolve_immediate_handoff_target(
            "dag",
            "mba",
            11,
            state_var_stkoff=0x7BC,
            bst_node_blocks=frozenset({2}),
            dispatcher_lookup="lookup",
            dispatcher="dispatcher",
        )
        == (17, 20)
    )
    assert (
        lfg_module.LinearizedFlowGraphStrategy._resolve_projected_snapshot_handoff_target(
            "dag",
            "flow-graph",
            12,
            state_var_stkoff=0x7BC,
            bst_node_blocks=frozenset({2}),
            dispatcher="dispatcher",
        )
        == (18, 20)
    )
    assert (
        lfg_module.LinearizedFlowGraphStrategy._resolve_assignment_map_handoff_target(
            "dag",
            "state-machine",
            13,
            bst_node_blocks=frozenset({2}),
            dispatcher="dispatcher",
        )
        == (19, 20)
    )
    assert (
        lfg_module.LinearizedFlowGraphStrategy._resolve_synthesized_handoff_target(
            "dag",
            "mba",
            14,
            state_var_stkoff=0x7BC,
            bst_node_blocks=frozenset({2}),
            dispatcher="dispatcher",
            via_pred=8,
        )
        == (21, 20)
    )

    assert seen == {
        "effective": handoff_backend_module.EffectiveTargetEntryRequest(
            dag="dag",
            edge="edge",
            bst_node_blocks=frozenset({2}),
            state_var_stkoff=0x7BC,
            dispatcher_lookup="lookup",
            dispatcher="dispatcher",
            mba="mba",
        ),
        "tail": handoff_backend_module.ProjectedPathTailTargetRequest(
            dag="dag",
            source_block=10,
            bst_node_blocks=frozenset({2}),
            dispatcher="dispatcher",
            predecessor_hints=(9,),
            require_predecessor_match=True,
        ),
        "immediate": handoff_backend_module.ImmediateHandoffTargetRequest(
            dag="dag",
            mba="mba",
            block_serial=11,
            state_var_stkoff=0x7BC,
            bst_node_blocks=frozenset({2}),
            dispatcher_lookup="lookup",
            dispatcher="dispatcher",
        ),
        "snapshot": handoff_backend_module.ProjectedSnapshotHandoffTargetRequest(
            dag="dag",
            flow_graph="flow-graph",
            block_serial=12,
            state_var_stkoff=0x7BC,
            bst_node_blocks=frozenset({2}),
            dispatcher="dispatcher",
        ),
        "assignment": handoff_backend_module.AssignmentMapHandoffTargetRequest(
            dag="dag",
            state_machine="state-machine",
            block_serial=13,
            bst_node_blocks=frozenset({2}),
            dispatcher="dispatcher",
        ),
        "synthesized": handoff_backend_module.SynthesizedHandoffTargetRequest(
            dag="dag",
            mba="mba",
            block_serial=14,
            state_var_stkoff=0x7BC,
            bst_node_blocks=frozenset({2}),
            dispatcher="dispatcher",
            via_pred=8,
        ),
    }


def test_projected_topology_backend_delegates_to_recon_helpers(monkeypatch):
    backend = topology_backend_module.HodurProjectedTopologyBackend()
    flow_graph = object()
    transition_result = object()
    seen_live_dag_kwargs = {}
    seen_projection = {}
    compiled_plan = object()
    projected_flow_graph = object()

    monkeypatch.setattr(
        topology_backend_module,
        "build_mba_view_from_flow_graph",
        lambda projected_flow_graph: ("projected-mba", projected_flow_graph),
    )
    def fake_compile_patch_plan(modifications, base_flow_graph):
        seen_projection["compile"] = (modifications, base_flow_graph)
        return compiled_plan

    def fake_project_post_state(base_flow_graph, patch_plan):
        seen_projection["project"] = (base_flow_graph, patch_plan)
        return projected_flow_graph

    monkeypatch.setattr(
        topology_backend_module,
        "compile_patch_plan",
        fake_compile_patch_plan,
    )
    monkeypatch.setattr(
        topology_backend_module,
        "project_post_state",
        fake_project_post_state,
    )

    def fake_build_live_dag(current_flow_graph, received_transition_result, **kwargs):
        seen_live_dag_kwargs.update(kwargs)
        return (current_flow_graph, received_transition_result, kwargs)

    monkeypatch.setattr(
        topology_backend_module,
        "build_live_linearized_state_dag_from_graph",
        fake_build_live_dag,
    )

    assert backend.build_projected_mba(flow_graph) == ("projected-mba", flow_graph)
    assert backend.project_flow_graph(flow_graph, ("mod",)) is projected_flow_graph
    assert seen_projection == {
        "compile": (("mod",), flow_graph),
        "project": (flow_graph, compiled_plan),
    }

    dag = backend.build_live_dag(
        flow_graph,
        transition_result,
        dispatcher_entry_serial=2,
        state_var_stkoff=0x7BC,
        pre_header_serial=None,
        initial_state=0x6107F8EC,
        handler_range_map=None,
        bst_node_blocks=(9, 2),
        diagnostics=(),
        dispatcher=None,
        mba="mba-view",
    )

    assert dag[0] is flow_graph
    assert dag[1] is transition_result
    assert seen_live_dag_kwargs["handler_range_map"] == {}
    assert seen_live_dag_kwargs["bst_node_blocks"] == (2, 9)
    assert seen_live_dag_kwargs["mba"] == "mba-view"


def test_lfg_planning_callbacks_use_projected_topology_backend(monkeypatch):
    backend = _FakeProjectedTopologyBackend()
    monkeypatch.setattr(
        lfg_module.LinearizedFlowGraphStrategy,
        "_projected_topology_backend",
        backend,
    )

    def fake_round_summary(**kwargs):
        dag = kwargs["build_live_dag"](
            kwargs["current_flow_graph"],
            kwargs["transition_result"],
            dispatcher_entry_serial=kwargs["dispatcher_serial"],
            state_var_stkoff=kwargs["state_var_stkoff"],
            pre_header_serial=kwargs["pre_header_serial"],
            initial_state=kwargs["initial_state"],
            handler_range_map=kwargs["handler_range_map"],
            bst_node_blocks=kwargs["bst_node_blocks"],
            diagnostics=kwargs["diagnostics"],
            dispatcher=kwargs["dispatcher"],
            mba=kwargs["mba"],
            prefer_local_corridors=True,
        )
        return _empty_resolved_round_summary(dag)

    monkeypatch.setattr(
        lfg_module,
        "build_linearized_dag_round_summary",
        fake_round_summary,
    )

    strategy = lfg_module.LinearizedFlowGraphStrategy()
    snapshot = SimpleNamespace(bst_dispatcher_serial=2, discovery=None)
    state_machine = SimpleNamespace(initial_state=0x6107F8EC, handlers={})
    transition_result = SimpleNamespace()
    flow_graph = SimpleNamespace(blocks={})
    setup = lfg_module.LinearizedFlowGraphPlanSetup(
        builder=object(),
        state_var_stkoff=0x7BC,
        dispatcher=None,
        blocked_sources=frozenset(),
        dispatcher_region=frozenset({2}),
        bst_node_blocks=frozenset({2}),
        original_blocks=frozenset(),
        transition_result=transition_result,
        pre_header_serial=None,
        projectable=True,
        round_limit=3,
    )
    callbacks = strategy._build_planning_callbacks(
        snapshot=snapshot,
        state_machine=state_machine,
        bst_result=SimpleNamespace(
            handler_range_map={},
            diagnostics=(),
            dispatcher=None,
        ),
        mba=object(),
        dag_setup=setup,
    )

    projected_mba = callbacks.build_projected_mba(flow_graph)
    projected_flow_graph = callbacks.project_flow_graph(flow_graph, ("mod",))
    round_summary = callbacks.build_round_summary(flow_graph, projected_mba)

    assert projected_mba.projected_from is flow_graph
    assert projected_flow_graph.projected_base is flow_graph
    assert projected_flow_graph.projected_modifications == ("mod",)
    assert round_summary.dag.nodes == ()
    assert backend.projected_mba_calls == [flow_graph]
    assert backend.project_flow_graph_calls == [(flow_graph, ("mod",))]
    assert len(backend.live_dag_calls) == 1
    live_flow_graph, live_transition_result, live_kwargs = backend.live_dag_calls[0]
    assert live_flow_graph is flow_graph
    assert live_transition_result is transition_result
    assert live_kwargs["dispatcher_entry_serial"] == 2
    assert live_kwargs["state_var_stkoff"] == 0x7BC
    assert live_kwargs["mba"] is projected_mba


def test_collect_structured_region_zero_state_write_modifications_emits_path_tail_cleanup(monkeypatch):
    candidate = SimpleNamespace(
        edge=SimpleNamespace(
            ordered_path=(15, 16),
            target_state=0x4C77464F,
        )
    )

    def fake_find_last_state_write_site_on_path_snapshot(
        flow_graph,
        ordered_path,
        state_var_stkoff,
        *,
        in_stk_maps=None,
        in_reg_maps=None,
    ):
        assert ordered_path == (15, 16)
        assert state_var_stkoff == 0x7BC
        assert in_stk_maps == {15: {}}
        assert in_reg_maps == {15: {}}
        return (
            16,
            SimpleNamespace(
                state_value=0x4C77464F,
                insn_ea=0x180012EE2,
            ),
        )

    monkeypatch.setattr(
        lfg_module,
        "find_last_state_write_site_on_path_snapshot",
        fake_find_last_state_write_site_on_path_snapshot,
    )

    mods = _collect_structured_region_zero_state_write_modifications(
        accepted_candidates=(candidate,),
        flow_graph=object(),
        state_var_stkoff=0x7BC,
        constant_result=SimpleNamespace(
            in_stk_maps={15: {}},
            in_reg_maps={15: {}},
        ),
        existing_modifications=(),
    )

    assert mods == (ZeroStateWrite(block_serial=16, insn_ea=0x180012EE2),)


def test_collect_structured_region_zero_state_write_modifications_dedupes_existing_cleanup(monkeypatch):
    candidate = SimpleNamespace(
        edge=SimpleNamespace(
            ordered_path=(15, 17),
            target_state=0x296F2452,
        )
    )

    monkeypatch.setattr(
        lfg_module,
        "find_last_state_write_site_on_path_snapshot",
        lambda *args, **kwargs: (
            17,
            SimpleNamespace(
                state_value=0x296F2452,
                insn_ea=0x180012EEC,
            ),
        ),
    )

    mods = _collect_structured_region_zero_state_write_modifications(
        accepted_candidates=(candidate,),
        flow_graph=object(),
        state_var_stkoff=0x7BC,
        constant_result=SimpleNamespace(
            in_stk_maps={},
            in_reg_maps={},
        ),
        existing_modifications=(
            ZeroStateWrite(block_serial=17, insn_ea=0x180012EEC),
        ),
    )

    assert mods == ()


def test_collect_structured_region_zero_state_write_modifications_accepts_observed_alias_target_state(
    monkeypatch,
):
    candidate = SimpleNamespace(
        edge=SimpleNamespace(
            ordered_path=(15, 16),
            target_state=0x474EEEBB,
            observed_target_state=0x4C77464F,
        )
    )

    monkeypatch.setattr(
        lfg_module,
        "find_last_state_write_site_on_path_snapshot",
        lambda *args, **kwargs: (
            16,
            SimpleNamespace(
                state_value=0x4C77464F,
                insn_ea=0x180012EF2,
            ),
        ),
    )

    mods = _collect_structured_region_zero_state_write_modifications(
        accepted_candidates=(candidate,),
        flow_graph=object(),
        state_var_stkoff=0x7BC,
        constant_result=SimpleNamespace(
            in_stk_maps={},
            in_reg_maps={},
        ),
        existing_modifications=(),
    )

    assert mods == (ZeroStateWrite(block_serial=16, insn_ea=0x180012EF2),)


def test_collect_consumed_structured_region_state_edges_includes_observed_alias_targets():
    site = SimpleNamespace(
        source_state=0x6107F8EC,
        target_state=0x474EEEBB,
        successor_state_value=0x474EEEBB,
        edge=SimpleNamespace(
            source_key=SimpleNamespace(state_const=0x6107F8EC),
            target_state=0x474EEEBB,
            observed_target_state=0x4C77464F,
        ),
    )
    candidate = SimpleNamespace(
        edge=SimpleNamespace(
            source_key=SimpleNamespace(state_const=0x6107F8EC),
            target_state=0x474EEEBB,
            observed_target_state=0x4C77464F,
        ),
    )

    consumed = _collect_consumed_structured_region_state_edges(
        accepted_sites=(site,),
        accepted_candidates=(candidate,),
    )

    assert consumed == frozenset(
        {
            (0x6107F8EC, 0x474EEEBB),
            (0x6107F8EC, 0x4C77464F),
        }
    )


def test_collect_unmatched_region_sites_filters_out_already_materialized_site():
    matched_site = SimpleNamespace(source_state=0x6107F8EC, target_state=0x296F2452)
    unmatched_site = SimpleNamespace(source_state=0x6107F8EC, target_state=0x474EEEBB)

    unmatched = _collect_unmatched_region_sites(
        lowering_sites=(matched_site, unmatched_site),
        accepted_sites=(matched_site,),
    )

    assert unmatched == (unmatched_site,)


def test_build_narrow_branch_local_region_fallback_candidates_preserves_branch_local_alias_context():
    flow_graph = FlowGraph(
        blocks={
            15: BlockSnapshot(15, 0, (16, 17), (), 0, 0, ()),
            16: BlockSnapshot(16, 0, (2,), (15,), 0, 0, ()),
            17: BlockSnapshot(17, 0, (2,), (15,), 0, 0, ()),
            2: BlockSnapshot(2, 0, (), (16, 17), 0, 0, ()),
        },
        entry_serial=15,
        func_ea=0x180012B60,
    )
    edge = SimpleNamespace(
        source_key=SimpleNamespace(state_const=0x6107F8EC),
        source_anchor=SimpleNamespace(block_serial=15, branch_arm=0),
        ordered_path=(15, 16),
        target_state=0x474EEEBB,
        observed_target_state=0x4C77464F,
        site=SimpleNamespace(
            block_serial=16,
            state_value=0x4C77464F,
            insn_ea=0x180012EE2,
        ),
    )
    site = SimpleNamespace(
        site_kind="exit",
        source_state=0x6107F8EC,
        target_state=0x474EEEBB,
        source_entry_anchor=136,
        source_anchor_block=15,
        target_entry_anchor=63,
        ordered_path=(15, 16),
        edge=edge,
        semantic_target_label="STATE_474EEEBB",
        successor_state_value=0x474EEEBB,
    )

    candidates = _build_narrow_branch_local_region_fallback_candidates(
        unresolved_sites=(site,),
        flow_graph=flow_graph,
    )

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.emission_mode == "conditional_arm"
    assert candidate.conditional_group_policy == "rewrite_horizon"
    assert candidate.horizon_block == 15
    assert candidate.target_entry == 63
    assert candidate.edge is edge
    assert candidate.site.block_serial == 16
    assert candidate.site.state_value == 0x4C77464F


def test_build_narrow_branch_local_region_fallback_candidates_skips_non_branch_local_sites():
    flow_graph = FlowGraph(
        blocks={
            136: BlockSnapshot(136, 0, (137,), (), 0, 0, ()),
            137: BlockSnapshot(137, 0, (2,), (136,), 0, 0, ()),
            2: BlockSnapshot(2, 0, (), (137,), 0, 0, ()),
        },
        entry_serial=136,
        func_ea=0x180012B60,
    )
    site = SimpleNamespace(
        site_kind="exit",
        source_state=0x139F2922,
        target_state=0x2315233C,
        source_entry_anchor=136,
        source_anchor_block=136,
        target_entry_anchor=211,
        ordered_path=(136,),
        edge=SimpleNamespace(
            source_key=SimpleNamespace(state_const=0x139F2922),
            source_anchor=SimpleNamespace(block_serial=136, branch_arm=None),
            ordered_path=(136,),
            target_state=0x2315233C,
        ),
        semantic_target_label="STATE_2315233C",
        successor_state_value=0x2315233C,
    )

    candidates = _build_narrow_branch_local_region_fallback_candidates(
        unresolved_sites=(site,),
        flow_graph=flow_graph,
    )

    assert candidates == ()


def test_collect_trivial_redirect_tail_zero_state_write_modifications_emits_cleanup_for_redirected_dispatcher_feeder(
    monkeypatch,
):
    flow_graph = FlowGraph(
        blocks={
            2: BlockSnapshot(2, 0, (), (), 0, 0, ()),
            16: BlockSnapshot(16, 0, (2,), (), 0, 0, ()),
        },
        entry_serial=16,
        func_ea=0x180012B60,
    )

    monkeypatch.setattr(
        lfg_module,
        "find_last_state_write_site_snapshot",
        lambda *args, **kwargs: SimpleNamespace(
            state_value=0x4C77464F,
            insn_ea=0x180012EE2,
            unsafe_trailing_insn_eas=(),
            trailing_insn_eas=(0x180012EEA,),
        ),
    )

    mods = _collect_trivial_redirect_tail_zero_state_write_modifications(
        modifications=(
            RedirectGoto(from_serial=16, old_target=2, new_target=66),
        ),
        flow_graph=flow_graph,
        dispatcher_serial=2,
        state_var_stkoff=0x7BC,
    )

    assert mods == (ZeroStateWrite(block_serial=16, insn_ea=0x180012EE2),)


def test_collect_trivial_redirect_tail_zero_state_write_modifications_skips_nontrivial_tail(
    monkeypatch,
):
    flow_graph = FlowGraph(
        blocks={
            2: BlockSnapshot(2, 0, (), (), 0, 0, ()),
            17: BlockSnapshot(17, 0, (2,), (), 0, 0, ()),
        },
        entry_serial=17,
        func_ea=0x180012B60,
    )

    monkeypatch.setattr(
        lfg_module,
        "find_last_state_write_site_snapshot",
        lambda *args, **kwargs: SimpleNamespace(
            state_value=0x296F2452,
            insn_ea=0x180012EEC,
            unsafe_trailing_insn_eas=(0x180012EF0,),
            trailing_insn_eas=(0x180012EF0, 0x180012EF8),
        ),
    )

    mods = _collect_trivial_redirect_tail_zero_state_write_modifications(
        modifications=(
            RedirectGoto(from_serial=17, old_target=2, new_target=202),
        ),
        flow_graph=flow_graph,
        dispatcher_serial=2,
        state_var_stkoff=0x7BC,
    )

    assert mods == ()


def test_filter_lfg_use_def_vetoes_uses_backend_and_drops_real_violations():
    # `_filter_lfg_use_def_vetoes` converts each CFG-layer `RedirectGoto`
    # into a portable `RedirectGotoIntent` at the capability boundary
    # (slice 10), so the fake backend matches by field equality, not by
    # identity, and the expected-calls record carries the IR intent the
    # capability actually received.  The original `RedirectGoto`
    # instances still flow through the filtered result unchanged.
    first = RedirectGoto(from_serial=16, old_target=2, new_target=66)
    second = RedirectGoto(from_serial=17, old_target=2, new_target=202)
    cleanup = ZeroStateWrite(block_serial=17, insn_ea=0x180012EEC)
    first_intent = RedirectGotoIntent(from_serial=16, old_target=2, new_target=66)
    second_intent = RedirectGotoIntent(from_serial=17, old_target=2, new_target=202)

    class FakeUseDefBackend:
        def __init__(self):
            self.calls = []

        def redirect_use_def_violations(self, modification, live_function, pre_cfg):
            self.calls.append((modification, live_function, pre_cfg))
            if modification == first_intent:
                return (SimpleNamespace(var_stkoff=0x40, use_block=81),)
            if modification == second_intent:
                return (SimpleNamespace(var_stkoff=0x7BC, use_block=82),)
            return ()

    backend = FakeUseDefBackend()
    mba = object()
    flow_graph = object()

    filtered = _filter_lfg_use_def_vetoes(
        (first, second, cleanup),
        enabled=True,
        mba=mba,
        flow_graph=flow_graph,
        state_var_stkoff=0x7BC,
        backend=backend,
    )

    assert filtered == (second, cleanup)
    assert backend.calls == [
        (first_intent, mba, flow_graph),
        (second_intent, mba, flow_graph),
    ]


def test_filter_lfg_use_def_vetoes_skips_backend_when_disabled():
    redirect = RedirectGoto(from_serial=16, old_target=2, new_target=66)

    class FailingBackend:
        def redirect_use_def_violations(self, modification, live_function, pre_cfg):
            raise AssertionError("backend should not be called")

    assert _filter_lfg_use_def_vetoes(
        (redirect,),
        enabled=False,
        mba=object(),
        flow_graph=object(),
        state_var_stkoff=0x7BC,
        backend=FailingBackend(),
    ) == (redirect,)
    assert _filter_lfg_use_def_vetoes(
        (redirect,),
        enabled=True,
        mba=None,
        flow_graph=object(),
        state_var_stkoff=0x7BC,
        backend=FailingBackend(),
    ) == (redirect,)


def test_filter_unsafe_preferred_region_lowering_rejects_conditional_arm_when_write_horizon_is_later(
    monkeypatch,
):
    preferred = SimpleNamespace(
        emission_mode="conditional_arm",
        horizon_block=163,
        target_entry_anchor=72,
    )
    site = SimpleNamespace(
        ordered_path=(161, 163, 165),
        source_anchor_block=163,
    )

    monkeypatch.setattr(
        lfg_module,
        "find_last_state_write_site_on_path_snapshot",
        lambda *args, **kwargs: (
            165,
            SimpleNamespace(
                unsafe_trailing_insn_eas=(),
            ),
        ),
    )

    filtered = _filter_unsafe_preferred_region_lowering(
        preferred=preferred,
        site=site,
        flow_graph=object(),
        state_var_stkoff=0x7BC,
        constant_result=SimpleNamespace(in_stk_maps={}, in_reg_maps={}),
    )

    assert filtered is None


def test_filter_unsafe_preferred_region_lowering_keeps_conditional_arm_when_write_horizon_matches_source(
    monkeypatch,
):
    preferred = SimpleNamespace(
        emission_mode="conditional_arm",
        horizon_block=139,
        target_entry_anchor=211,
    )
    site = SimpleNamespace(
        ordered_path=(136, 137, 139),
        source_anchor_block=139,
    )

    monkeypatch.setattr(
        lfg_module,
        "find_last_state_write_site_on_path_snapshot",
        lambda *args, **kwargs: (
            139,
            SimpleNamespace(
                unsafe_trailing_insn_eas=(),
            ),
        ),
    )

    filtered = _filter_unsafe_preferred_region_lowering(
        preferred=preferred,
        site=site,
        flow_graph=object(),
        state_var_stkoff=0x7BC,
        constant_result=SimpleNamespace(in_stk_maps={}, in_reg_maps={}),
    )

    assert filtered is preferred


def test_match_accepted_region_sites_prefers_semantic_signature_over_edge_identity():
    edge_a = SimpleNamespace(
        source_key=SimpleNamespace(state_const=0x139F2922, handler_serial=136),
        target_state=0x2315233C,
        ordered_path=(136, 137, 139, 141),
    )
    edge_b = SimpleNamespace(
        source_key=SimpleNamespace(state_const=0x139F2922, handler_serial=136),
        target_state=0x2315233C,
        ordered_path=(136, 137, 139, 141),
    )
    site = SimpleNamespace(
        source_state=0x139F2922,
        target_state=0x2315233C,
        source_entry_anchor=136,
        target_entry_anchor=211,
        ordered_path=(136, 137, 139, 141),
        edge=edge_a,
    )
    candidate = SimpleNamespace(
        edge=edge_b,
        target_entry=211,
    )

    matched = _match_accepted_region_sites(
        lowering_sites=(site,),
        accepted_candidates=(candidate,),
    )

    assert matched == (site,)


def test_match_accepted_region_sites_falls_back_to_edge_identity_when_signature_is_incomplete():
    edge = SimpleNamespace(
        source_key=SimpleNamespace(state_const=0x5D0AEBD3),
        target_state=0x606DC166,
        ordered_path=(78,),
    )
    site = SimpleNamespace(
        source_state=0x5D0AEBD3,
        target_state=0x606DC166,
        source_entry_anchor=78,
        target_entry_anchor=14,
        ordered_path=(78,),
        edge=edge,
    )
    candidate = SimpleNamespace(
        edge=edge,
        target_entry=14,
    )

    matched = _match_accepted_region_sites(
        lowering_sites=(site,),
        accepted_candidates=(candidate,),
    )

    assert matched == (site,)


def test_filter_unsafe_preferred_region_lowering_keeps_conditional_arm_for_private_branch_feeder(
    monkeypatch,
):
    preferred = SimpleNamespace(
        emission_mode="conditional_arm",
        horizon_block=15,
        target_entry_anchor=68,
    )
    site = SimpleNamespace(
        ordered_path=(15, 16),
        source_anchor_block=15,
    )
    flow_graph = FlowGraph(
        blocks={
            15: BlockSnapshot(15, 0, (16, 17), (), 0, 0, ()),
            16: BlockSnapshot(16, 0, (2,), (15,), 0, 0, ()),
            17: BlockSnapshot(17, 0, (2,), (15,), 0, 0, ()),
            2: BlockSnapshot(2, 0, (), (16, 17), 0, 0, ()),
        },
        entry_serial=15,
        func_ea=0x180012B60,
    )

    monkeypatch.setattr(
        lfg_module,
        "find_last_state_write_site_on_path_snapshot",
        lambda *args, **kwargs: (
            16,
            SimpleNamespace(
                unsafe_trailing_insn_eas=(),
            ),
        ),
    )

    filtered = _filter_unsafe_preferred_region_lowering(
        preferred=preferred,
        site=site,
        flow_graph=flow_graph,
        state_var_stkoff=0x7BC,
        constant_result=SimpleNamespace(in_stk_maps={}, in_reg_maps={}),
    )

    assert filtered is preferred


def test_filter_unsafe_preferred_region_lowering_keeps_conditional_arm_for_singleton_branch_head(
    monkeypatch,
):
    preferred = SimpleNamespace(
        emission_mode="conditional_arm",
        horizon_block=136,
        target_entry_anchor=66,
    )
    site = SimpleNamespace(
        ordered_path=(136,),
        source_anchor_block=136,
    )
    flow_graph = FlowGraph(
        blocks={
            136: BlockSnapshot(136, 0, (137, 142), (), 0, 0, ()),
            137: BlockSnapshot(137, 0, (), (136,), 0, 0, ()),
            142: BlockSnapshot(142, 0, (), (136,), 0, 0, ()),
        },
        entry_serial=136,
        func_ea=0x180012B60,
    )

    monkeypatch.setattr(
        lfg_module,
        "find_last_state_write_site_on_path_snapshot",
        lambda *args, **kwargs: (
            158,
            SimpleNamespace(
                unsafe_trailing_insn_eas=(0x1234, 0x1235),
            ),
        ),
    )

    filtered = _filter_unsafe_preferred_region_lowering(
        preferred=preferred,
        site=site,
        flow_graph=flow_graph,
        state_var_stkoff=0x7BC,
        constant_result=SimpleNamespace(in_stk_maps={}, in_reg_maps={}),
    )

    assert filtered is preferred


def test_should_defer_transient_internal_region_site_for_transient_to_transient_direct_handoff():
    site = SimpleNamespace(
        site_kind="internal",
        source_state=0x1AB9946F,
        target_state=0x7C2C0220,
        edge=SimpleNamespace(
            source_anchor=SimpleNamespace(branch_arm=None),
        ),
    )
    dag = SimpleNamespace(
        transient_state_values=(0x1AB9946F, 0x7C2C0220, 0x2A5ADB57),
    )

    assert _should_defer_transient_internal_region_site(site=site, dag=dag) is True


def test_should_not_defer_transient_internal_region_site_for_nontransient_boundary():
    site = SimpleNamespace(
        site_kind="internal",
        source_state=0x7C2C0220,
        target_state=0x37B42A40,
        edge=SimpleNamespace(
            source_anchor=SimpleNamespace(branch_arm=None),
        ),
    )
    dag = SimpleNamespace(
        transient_state_values=(0x1AB9946F, 0x7C2C0220, 0x2A5ADB57),
    )

    assert _should_defer_transient_internal_region_site(site=site, dag=dag) is False


def test_sanitize_progressive_topology_modifications_drops_stale_redirect_after_prior_rewrite():
    flow_graph = FlowGraph(
        blocks={
            34: BlockSnapshot(34, 0, (35,), (), 0, 0, ()),
            35: BlockSnapshot(35, 0, (), (34,), 0, 0, ()),
            211: BlockSnapshot(211, 0, (), (), 0, 0, ()),
            212: BlockSnapshot(212, 0, (), (), 0, 0, ()),
        },
        entry_serial=34,
        func_ea=0x180012B60,
    )

    sanitized, normalized, dropped = _sanitize_progressive_topology_modifications(
        (
            RedirectGoto(from_serial=34, old_target=35, new_target=211),
            RedirectGoto(from_serial=34, old_target=35, new_target=212),
        ),
        flow_graph=flow_graph,
    )

    assert sanitized == (
        RedirectGoto(from_serial=34, old_target=35, new_target=211),
    )
    assert normalized == 0
    assert dropped == 1


def test_sanitize_progressive_topology_modifications_normalizes_duplicate_target_branch_to_goto():
    flow_graph = FlowGraph(
        blocks={
            15: BlockSnapshot(15, 0, (16, 17), (), 0, 0, ()),
            16: BlockSnapshot(16, 0, (), (15,), 0, 0, ()),
            17: BlockSnapshot(17, 0, (), (15,), 0, 0, ()),
        },
        entry_serial=15,
        func_ea=0x180012B60,
    )

    sanitized, normalized, dropped = _sanitize_progressive_topology_modifications(
        (
            RedirectBranch(from_serial=15, old_target=16, new_target=17),
        ),
        flow_graph=flow_graph,
    )

    assert sanitized == (
        ConvertToGoto(block_serial=15, goto_target=17),
    )
    assert normalized == 1
    assert dropped == 0
