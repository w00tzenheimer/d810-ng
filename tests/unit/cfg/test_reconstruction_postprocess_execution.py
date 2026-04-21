from __future__ import annotations

from types import SimpleNamespace

import d810.cfg.reconstruction_postprocess_execution as postprocess_exec
from d810.cfg.reconstruction_postprocess_execution import (
    _emit_residual_raw_alias_reconstruction_overrides,
    execute_reconstruction_postprocess,
)
from d810.recon.flow.linearized_state_dag import (
    RedirectSourceKind,
    SemanticEdgeKind,
    StateDagEdge,
    StateDagNodeKey,
    StateRedirectAnchor,
)


def _rescue_run(*, emitted_count: int, projected_flow_graph: object):
    return SimpleNamespace(
        emitted_count=emitted_count,
        projected_flow_graph=projected_flow_graph,
    )


class TestExecuteReconstructionPostprocess:
    def test_returns_defaults_when_dispatcher_is_unknown(self, monkeypatch) -> None:
        monkeypatch.setattr(
            postprocess_exec,
            "plan_reconstruction_postprocess_modifications",
            lambda **kwargs: (_ for _ in ()).throw(AssertionError("unexpected")),
        )

        result = execute_reconstruction_postprocess(
            dag=SimpleNamespace(bst_node_blocks={2}),
            corrected_dag=object(),
            flow_graph=SimpleNamespace(blocks={1: object(), 2: object()}),
            modifications=[],
            builder=object(),
            dispatcher_region={2},
            dispatcher_serial=-1,
            bst_result=SimpleNamespace(dispatcher=None),
            state_machine=SimpleNamespace(state_constants={0x10}),
            state_var_stkoff=0x30,
            constant_result=object(),
            node_by_key={},
            rejected_metadata=[],
            owned_blocks=set(),
            owned_edges=set(),
            collect_entry_island_rescue_seeds=lambda *args, **kwargs: (),
            collect_late_entry_island_diagnostics=lambda *args, **kwargs: (),
            collect_late_entry_island_rescue_seeds=lambda *args, **kwargs: (),
            collect_residual_dispatcher_predecessors=lambda *args, **kwargs: (),
            compute_reachable_blocks=lambda *args, **kwargs: set(),
            classify_artifact_return_blocks=lambda *args, **kwargs: set(),
            collect_common_return_corridor=lambda *args, **kwargs: set(),
            collect_terminal_family_report=lambda *args, **kwargs: (),
        )

        assert result.projected_flow_graph.blocks.keys() == {1, 2}
        assert result.residual_dispatcher_preds == ()
        assert result.initial_residual_dispatcher_preds == ()
        assert result.allow_post_apply_bst_cleanup is True
        assert result.postprocess_plan is None

    def test_executes_generic_postprocess_pipeline(self, monkeypatch) -> None:
        projected_states = iter(
            (
                "projected-initial",
                "projected-after-entry",
                "projected-after-extra",
                "projected-after-terminal",
            )
        )
        monkeypatch.setattr(
            postprocess_exec,
            "_project_flow_graph",
            lambda flow_graph, modifications: next(projected_states),
        )

        entry_runs = iter(
            (
                _rescue_run(emitted_count=1, projected_flow_graph="entry"),
                _rescue_run(emitted_count=0, projected_flow_graph="late-entry"),
            )
        )
        monkeypatch.setattr(
            postprocess_exec,
            "execute_reconstruction_entry_island_rescues",
            lambda **kwargs: next(entry_runs),
        )
        monkeypatch.setattr(
            postprocess_exec,
            "execute_reconstruction_late_island_rescues",
            lambda **kwargs: SimpleNamespace(
                run=_rescue_run(emitted_count=0, projected_flow_graph="late"),
                diagnostics=("diag",),
            ),
        )
        residual_preds = iter(((41,), ()))
        preheader_bridge = SimpleNamespace(modification=("pre", 11), resolved_target=77)
        bridge_plan = SimpleNamespace(modifications=[("bridge", 20)], log_entries=())
        feeder_plan = SimpleNamespace(modifications=[("feeder", 30)], log_entries=())
        fixpoint_feeder_plan = SimpleNamespace(modifications=[("fix", 31)], log_entries=())
        return_plan = SimpleNamespace(modifications=[("return", 40)], log_entries=(), skipped_entries=())
        postprocess_plan = SimpleNamespace(
            preheader_bridge=preheader_bridge,
            bridge_plan=bridge_plan,
            feeder_plan=feeder_plan,
            fixpoint_feeder_plan=fixpoint_feeder_plan,
            return_plan=return_plan,
        )
        monkeypatch.setattr(
            postprocess_exec,
            "plan_reconstruction_postprocess_modifications",
            lambda **kwargs: postprocess_plan,
        )
        monkeypatch.setattr(
            postprocess_exec,
            "plan_terminal_family_splits",
            lambda **kwargs: SimpleNamespace(emitted_count=1, iterations=()),
        )

        modifications: list[object] = []
        result = execute_reconstruction_postprocess(
            dag=SimpleNamespace(bst_node_blocks={2}),
            corrected_dag=object(),
            flow_graph=SimpleNamespace(blocks={1: object(), 2: object()}, entry_serial=1),
            modifications=modifications,
            builder=object(),
            dispatcher_region={2, 6},
            dispatcher_serial=6,
            bst_result=SimpleNamespace(dispatcher=SimpleNamespace()),
            state_machine=SimpleNamespace(state_constants={0x10, 0x20}),
            state_var_stkoff=0x30,
            constant_result=object(),
            node_by_key={},
            rejected_metadata=[],
            owned_blocks={15},
            owned_edges={(15, 20)},
            collect_entry_island_rescue_seeds=lambda *args, **kwargs: (),
            collect_late_entry_island_diagnostics=lambda *args, **kwargs: ("diag",),
            collect_late_entry_island_rescue_seeds=lambda *args, **kwargs: (),
            collect_residual_dispatcher_predecessors=lambda *args, **kwargs: next(residual_preds),
            compute_reachable_blocks=lambda *args, **kwargs: {1, 2, 3},
            classify_artifact_return_blocks=lambda *args, **kwargs: {94},
            collect_common_return_corridor=lambda *args, **kwargs: {30, 40},
            collect_terminal_family_report=lambda *args, **kwargs: (),
        )

        assert modifications == [
            ("pre", 11),
            ("bridge", 20),
            ("feeder", 30),
            ("fix", 31),
            ("return", 40),
        ]
        assert result.initial_residual_dispatcher_preds == (41,)
        assert result.residual_dispatcher_preds == ()
        assert result.allow_post_apply_bst_cleanup is False
        assert result.post_apply_bst_cleanup_reason == "residual_dispatcher_redirects"
        assert result.artifact_return_blocks == frozenset({94})
        assert result.common_return_corridor == frozenset({30, 40})
        assert result.postprocess_plan is postprocess_plan
        assert result.projected_flow_graph == "projected-after-terminal"

    def test_runs_residual_alias_overrides_without_bridge_or_feeder_mods(self, monkeypatch) -> None:
        monkeypatch.setattr(
            postprocess_exec,
            "_project_flow_graph",
            lambda flow_graph, modifications: "projected",
        )
        monkeypatch.setattr(
            postprocess_exec,
            "execute_reconstruction_entry_island_rescues",
            lambda **kwargs: _rescue_run(emitted_count=0, projected_flow_graph="entry"),
        )
        monkeypatch.setattr(
            postprocess_exec,
            "execute_reconstruction_late_island_rescues",
            lambda **kwargs: SimpleNamespace(
                run=_rescue_run(emitted_count=0, projected_flow_graph="late"),
                diagnostics=(),
            ),
        )
        monkeypatch.setattr(
            postprocess_exec,
            "plan_reconstruction_postprocess_modifications",
            lambda **kwargs: SimpleNamespace(
                preheader_bridge=SimpleNamespace(modification=None),
                bridge_plan=SimpleNamespace(modifications=[], log_entries=()),
                feeder_plan=SimpleNamespace(modifications=[], log_entries=()),
                fixpoint_feeder_plan=SimpleNamespace(modifications=[], log_entries=()),
                return_plan=SimpleNamespace(modifications=[], log_entries=(), skipped_entries=()),
            ),
        )
        monkeypatch.setattr(
            postprocess_exec,
            "plan_terminal_family_splits",
            lambda **kwargs: SimpleNamespace(emitted_count=0, iterations=()),
        )
        monkeypatch.setattr(
            postprocess_exec,
            "_emit_residual_raw_alias_reconstruction_overrides",
            lambda **kwargs: kwargs["modifications"].append(("late-raw-alias", 63)) or 1,
        )

        residual_preds = iter(((16,), (16,), ()))
        modifications: list[object] = []
        result = execute_reconstruction_postprocess(
            dag=SimpleNamespace(bst_node_blocks={2}),
            corrected_dag=SimpleNamespace(edges=(), nodes=(), bst_node_blocks={2}),
            flow_graph=SimpleNamespace(blocks={1: object(), 2: object()}, entry_serial=1),
            modifications=modifications,
            builder=object(),
            dispatcher_region={2, 6},
            dispatcher_serial=6,
            bst_result=SimpleNamespace(dispatcher=SimpleNamespace(lookup=None)),
            state_machine=SimpleNamespace(state_constants={0x10}),
            state_var_stkoff=0x30,
            constant_result=object(),
            node_by_key={},
            rejected_metadata=[],
            owned_blocks=set(),
            owned_edges=set(),
            collect_entry_island_rescue_seeds=lambda *args, **kwargs: (),
            collect_late_entry_island_diagnostics=lambda *args, **kwargs: (),
            collect_late_entry_island_rescue_seeds=lambda *args, **kwargs: (),
            collect_residual_dispatcher_predecessors=lambda *args, **kwargs: next(residual_preds),
            compute_reachable_blocks=lambda *args, **kwargs: {1, 2, 3},
            classify_artifact_return_blocks=lambda *args, **kwargs: set(),
            collect_common_return_corridor=lambda *args, **kwargs: set(),
            collect_terminal_family_report=lambda *args, **kwargs: (),
            resolve_effective_target_entry=lambda *args, **kwargs: SimpleNamespace(target_entry=63),
            build_projected_mba=lambda *args, **kwargs: object(),
        )

        assert modifications == [("late-raw-alias", 63)]
        assert result.residual_dispatcher_preds == ()
        assert result.allow_post_apply_bst_cleanup is False
        assert result.post_apply_bst_cleanup_reason == "residual_dispatcher_redirects"

    def test_runs_early_residual_alias_overrides_before_broader_postprocess(self, monkeypatch) -> None:
        events: list[str] = []

        monkeypatch.setattr(
            postprocess_exec,
            "_project_flow_graph",
            lambda flow_graph, modifications: "projected",
        )
        monkeypatch.setattr(
            postprocess_exec,
            "execute_reconstruction_entry_island_rescues",
            lambda **kwargs: _rescue_run(emitted_count=0, projected_flow_graph="entry"),
        )
        monkeypatch.setattr(
            postprocess_exec,
            "execute_reconstruction_late_island_rescues",
            lambda **kwargs: SimpleNamespace(
                run=_rescue_run(emitted_count=0, projected_flow_graph="late"),
                diagnostics=(),
            ),
        )

        def _fake_emit(**kwargs):
            events.append("emit")
            kwargs["modifications"].append(("late-raw-alias", 63))
            return 1

        monkeypatch.setattr(
            postprocess_exec,
            "_emit_residual_raw_alias_reconstruction_overrides",
            _fake_emit,
        )

        def _fake_plan(**kwargs):
            events.append("plan")
            return SimpleNamespace(
                preheader_bridge=SimpleNamespace(modification=None),
                bridge_plan=SimpleNamespace(modifications=[], log_entries=()),
                feeder_plan=SimpleNamespace(modifications=[], log_entries=()),
                fixpoint_feeder_plan=SimpleNamespace(modifications=[], log_entries=()),
                return_plan=SimpleNamespace(modifications=[], log_entries=(), skipped_entries=()),
            )

        monkeypatch.setattr(
            postprocess_exec,
            "plan_reconstruction_postprocess_modifications",
            _fake_plan,
        )
        monkeypatch.setattr(
            postprocess_exec,
            "plan_terminal_family_splits",
            lambda **kwargs: SimpleNamespace(emitted_count=0, iterations=()),
        )

        residual_preds = iter(((), (), ()))
        modifications: list[object] = []
        result = execute_reconstruction_postprocess(
            dag=SimpleNamespace(bst_node_blocks={2}),
            corrected_dag=SimpleNamespace(edges=(), nodes=(), bst_node_blocks={2}),
            flow_graph=SimpleNamespace(blocks={1: object(), 2: object()}, entry_serial=1),
            modifications=modifications,
            builder=object(),
            dispatcher_region={2, 6},
            dispatcher_serial=6,
            bst_result=SimpleNamespace(dispatcher=SimpleNamespace(lookup=None)),
            state_machine=SimpleNamespace(state_constants={0x10}),
            state_var_stkoff=0x30,
            constant_result=object(),
            node_by_key={},
            rejected_metadata=[],
            owned_blocks=set(),
            owned_edges=set(),
            collect_entry_island_rescue_seeds=lambda *args, **kwargs: (),
            collect_late_entry_island_diagnostics=lambda *args, **kwargs: (),
            collect_late_entry_island_rescue_seeds=lambda *args, **kwargs: (),
            collect_residual_dispatcher_predecessors=lambda *args, **kwargs: next(residual_preds),
            compute_reachable_blocks=lambda *args, **kwargs: {1, 2, 3},
            classify_artifact_return_blocks=lambda *args, **kwargs: set(),
            collect_common_return_corridor=lambda *args, **kwargs: set(),
            collect_terminal_family_report=lambda *args, **kwargs: (),
            resolve_effective_target_entry=lambda *args, **kwargs: SimpleNamespace(target_entry=63),
            build_projected_mba=lambda *args, **kwargs: object(),
        )

        assert events[:2] == ["emit", "plan"]
        assert modifications == [("late-raw-alias", 63)]
        assert result.allow_post_apply_bst_cleanup is False
        assert result.post_apply_bst_cleanup_reason == "residual_dispatcher_redirects"


def test_emit_residual_raw_alias_reconstruction_overrides_normalizes_to_semantic_target(monkeypatch):
    edge = StateDagEdge(
        kind=SemanticEdgeKind.TRANSITION,
        source_key=StateDagNodeKey(handler_serial=15, state_const=0x10743C4C),
        target_key=None,
        target_state=0x4C77464F,
        target_entry_anchor=72,
        target_label="0x4C77464F",
        source_anchor=StateRedirectAnchor(
            kind=RedirectSourceKind.UNCONDITIONAL,
            block_serial=15,
            branch_arm=None,
        ),
        ordered_path=(15, 16),
    )
    dag = SimpleNamespace(
        edges=(edge,),
        nodes=(SimpleNamespace(entry_anchor=63, state_label="STATE_474EEEBB"),),
        bst_node_blocks={71},
    )
    captured: dict[str, object] = {}
    monkeypatch.setattr(
        postprocess_exec,
        "collect_shared_suffix_blocks",
        lambda dag: set(),
    )

    def _fake_build_candidate(edge, **kwargs):
        captured["normalized_edge"] = edge
        return (
            SimpleNamespace(
                edge=edge,
                horizon_block=16,
                target_entry=int(edge.target_entry_anchor),
                first_shared_block=None,
                via_pred=None,
                emission_mode="direct",
            ),
            None,
        )

    monkeypatch.setattr(postprocess_exec, "build_reconstruction_candidate", _fake_build_candidate)

    def _fake_execute(**kwargs):
        captured["raw_candidates"] = kwargs["raw_candidates"]
        kwargs["modifications"].append(("redirect", kwargs["raw_candidates"][0].target_entry))
        kwargs["owned_blocks"].add(16)
        kwargs["owned_edges"].add((16, kwargs["raw_candidates"][0].target_entry))

    monkeypatch.setattr(
        postprocess_exec,
        "execute_primary_reconstruction_modifications",
        _fake_execute,
    )

    modifications: list[object] = []
    owned_blocks: set[int] = set()
    owned_edges: set[tuple[int, int]] = set()
    redirected = _emit_residual_raw_alias_reconstruction_overrides(
        dag=dag,
        flow_graph=SimpleNamespace(),
        dispatcher_region={71, 72},
        dispatcher_serial=71,
        state_var_stkoff=0x30,
        constant_result=object(),
        resolve_effective_target_entry=lambda *args, **kwargs: SimpleNamespace(target_entry=63),
        analysis_mba=object(),
        dispatcher_lookup=None,
        dispatcher=None,
        residual_dispatcher_preds=(16,),
        modifications=modifications,
        owned_blocks=owned_blocks,
        owned_edges=owned_edges,
    )

    assert redirected == 1
    assert modifications == [("redirect", 63)]
    assert owned_blocks == {16}
    assert owned_edges == {(16, 63)}
    normalized_edge = captured["normalized_edge"]
    assert normalized_edge.target_entry_anchor == 63
    assert normalized_edge.target_label == "STATE_474EEEBB"


def test_emit_residual_raw_alias_reconstruction_overrides_uses_post_source_exit_tail_when_no_residual_preds(
    monkeypatch,
):
    edge = StateDagEdge(
        kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
        source_key=StateDagNodeKey(handler_serial=15, state_const=0x6107F8EC),
        target_key=None,
        target_state=0x4C77464F,
        target_entry_anchor=72,
        target_label="0x4C77464F",
        source_anchor=StateRedirectAnchor(
            kind=RedirectSourceKind.CONDITIONAL_BRANCH,
            block_serial=15,
            branch_arm=1,
        ),
        ordered_path=(15, 16),
    )
    dag = SimpleNamespace(
        edges=(edge,),
        nodes=(SimpleNamespace(entry_anchor=63, state_label="STATE_474EEEBB"),),
        bst_node_blocks={71},
    )
    captured: dict[str, object] = {}
    monkeypatch.setattr(
        postprocess_exec,
        "collect_shared_suffix_blocks",
        lambda dag: set(),
    )

    def _fake_build_candidate(edge, **kwargs):
        captured["normalized_edge"] = edge
        return (
            SimpleNamespace(
                edge=edge,
                horizon_block=16,
                target_entry=int(edge.target_entry_anchor),
                first_shared_block=None,
                via_pred=None,
                emission_mode="direct",
            ),
            None,
        )

    monkeypatch.setattr(postprocess_exec, "build_reconstruction_candidate", _fake_build_candidate)

    def _fake_execute(**kwargs):
        captured["raw_candidates"] = kwargs["raw_candidates"]
        kwargs["modifications"].append(("redirect", kwargs["raw_candidates"][0].target_entry))
        kwargs["owned_blocks"].add(16)
        kwargs["owned_edges"].add((16, kwargs["raw_candidates"][0].target_entry))

    monkeypatch.setattr(
        postprocess_exec,
        "execute_primary_reconstruction_modifications",
        _fake_execute,
    )

    modifications: list[object] = []
    owned_blocks: set[int] = set()
    owned_edges: set[tuple[int, int]] = set()
    redirected = _emit_residual_raw_alias_reconstruction_overrides(
        dag=dag,
        flow_graph=SimpleNamespace(),
        dispatcher_region={71, 72},
        dispatcher_serial=71,
        state_var_stkoff=0x30,
        constant_result=object(),
        resolve_effective_target_entry=lambda *args, **kwargs: SimpleNamespace(target_entry=63),
        analysis_mba=object(),
        dispatcher_lookup=None,
        dispatcher=None,
        residual_dispatcher_preds=(),
        modifications=modifications,
        owned_blocks=owned_blocks,
        owned_edges=owned_edges,
    )

    assert redirected == 1
    assert modifications == [("redirect", 63)]
    assert owned_blocks == {16}
    assert owned_edges == {(16, 63)}
    normalized_edge = captured["normalized_edge"]
    assert normalized_edge.target_entry_anchor == 63
    assert normalized_edge.target_label == "STATE_474EEEBB"


def test_emit_residual_raw_alias_reconstruction_overrides_keeps_prenormalized_raw_alias_live(
    monkeypatch,
):
    edge = StateDagEdge(
        kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
        source_key=StateDagNodeKey(handler_serial=15, state_const=0x6107F8EC),
        target_key=None,
        target_state=0x4C77464F,
        target_entry_anchor=63,
        target_label="0x4C77464F",
        source_anchor=StateRedirectAnchor(
            kind=RedirectSourceKind.CONDITIONAL_BRANCH,
            block_serial=15,
            branch_arm=1,
        ),
        ordered_path=(15, 16),
    )
    dag = SimpleNamespace(
        edges=(edge,),
        nodes=(SimpleNamespace(entry_anchor=63, state_label="STATE_474EEEBB"),),
        bst_node_blocks={71},
    )
    captured: dict[str, object] = {}
    monkeypatch.setattr(
        postprocess_exec,
        "collect_shared_suffix_blocks",
        lambda dag: set(),
    )

    def _fake_build_candidate(edge, **kwargs):
        captured["normalized_edge"] = edge
        return (
            SimpleNamespace(
                edge=edge,
                horizon_block=16,
                target_entry=int(edge.target_entry_anchor),
                first_shared_block=None,
                via_pred=None,
                emission_mode="direct",
            ),
            None,
        )

    monkeypatch.setattr(postprocess_exec, "build_reconstruction_candidate", _fake_build_candidate)

    def _fake_execute(**kwargs):
        captured["raw_candidates"] = kwargs["raw_candidates"]
        kwargs["modifications"].append(("redirect", kwargs["raw_candidates"][0].target_entry))
        kwargs["owned_blocks"].add(16)
        kwargs["owned_edges"].add((16, kwargs["raw_candidates"][0].target_entry))

    monkeypatch.setattr(
        postprocess_exec,
        "execute_primary_reconstruction_modifications",
        _fake_execute,
    )

    modifications: list[object] = []
    owned_blocks: set[int] = set()
    owned_edges: set[tuple[int, int]] = set()
    redirected = _emit_residual_raw_alias_reconstruction_overrides(
        dag=dag,
        flow_graph=SimpleNamespace(),
        dispatcher_region={71, 72},
        dispatcher_serial=71,
        state_var_stkoff=0x30,
        constant_result=object(),
        resolve_effective_target_entry=lambda *args, **kwargs: SimpleNamespace(target_entry=63),
        analysis_mba=object(),
        dispatcher_lookup=None,
        dispatcher=None,
        residual_dispatcher_preds=(),
        modifications=modifications,
        owned_blocks=owned_blocks,
        owned_edges=owned_edges,
    )

    assert redirected == 1
    assert modifications == [("redirect", 63)]
    assert owned_blocks == {16}
    assert owned_edges == {(16, 63)}


def test_emit_residual_raw_alias_reconstruction_overrides_uses_existing_target_entry_when_resolver_unavailable(
    monkeypatch,
):
    edge = StateDagEdge(
        kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
        source_key=StateDagNodeKey(handler_serial=15, state_const=0x6107F8EC),
        target_key=None,
        target_state=0x4C77464F,
        target_entry_anchor=63,
        target_label="0x4C77464F",
        source_anchor=StateRedirectAnchor(
            kind=RedirectSourceKind.CONDITIONAL_BRANCH,
            block_serial=15,
            branch_arm=1,
        ),
        ordered_path=(15, 16),
    )
    dag = SimpleNamespace(
        edges=(edge,),
        nodes=(SimpleNamespace(entry_anchor=63, state_label="STATE_474EEEBB"),),
        bst_node_blocks={71},
    )
    monkeypatch.setattr(
        postprocess_exec,
        "collect_shared_suffix_blocks",
        lambda dag: set(),
    )
    monkeypatch.setattr(
        postprocess_exec,
        "build_reconstruction_candidate",
        lambda edge, **kwargs: (
            SimpleNamespace(
                edge=edge,
                horizon_block=16,
                target_entry=int(edge.target_entry_anchor),
                first_shared_block=None,
                via_pred=None,
                emission_mode="direct",
            ),
            None,
        ),
    )

    def _fake_execute(**kwargs):
        kwargs["modifications"].append(("redirect", kwargs["raw_candidates"][0].target_entry))
        kwargs["owned_blocks"].add(16)
        kwargs["owned_edges"].add((16, kwargs["raw_candidates"][0].target_entry))

    monkeypatch.setattr(
        postprocess_exec,
        "execute_primary_reconstruction_modifications",
        _fake_execute,
    )

    modifications: list[object] = []
    owned_blocks: set[int] = set()
    owned_edges: set[tuple[int, int]] = set()
    redirected = _emit_residual_raw_alias_reconstruction_overrides(
        dag=dag,
        flow_graph=SimpleNamespace(),
        dispatcher_region={71, 72},
        dispatcher_serial=71,
        state_var_stkoff=0x30,
        constant_result=object(),
        resolve_effective_target_entry=None,
        analysis_mba=None,
        dispatcher_lookup=None,
        dispatcher=None,
        residual_dispatcher_preds=(),
        modifications=modifications,
        owned_blocks=owned_blocks,
        owned_edges=owned_edges,
    )

    assert redirected == 1
    assert modifications == [("redirect", 63)]
    assert owned_blocks == {16}
    assert owned_edges == {(16, 63)}
