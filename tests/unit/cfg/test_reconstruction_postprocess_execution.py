from __future__ import annotations

from types import SimpleNamespace

import d810.cfg.reconstruction_postprocess_execution as postprocess_exec
from d810.cfg.reconstruction_postprocess_execution import (
    execute_reconstruction_postprocess,
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
        assert result.allow_post_apply_bst_cleanup is True
        assert result.post_apply_bst_cleanup_reason is None
        assert result.artifact_return_blocks == frozenset({94})
        assert result.common_return_corridor == frozenset({30, 40})
        assert result.postprocess_plan is postprocess_plan
        assert result.projected_flow_graph == "projected-after-terminal"
