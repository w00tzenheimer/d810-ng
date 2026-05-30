from __future__ import annotations

from types import SimpleNamespace

import d810.transforms.reconstruction_rescue_emission as rescue_exec
from d810.transforms.entry_island_rescue_planning import EntryIslandRescueRun
from d810.transforms.reconstruction_rescue_emission import (
    execute_reconstruction_entry_island_rescues,
    execute_reconstruction_late_island_rescues,
)


def _run(*, emitted_count: int, projected_flow_graph: object) -> EntryIslandRescueRun:
    return EntryIslandRescueRun(
        emitted_count=emitted_count,
        iterations=(),
        projected_flow_graph=projected_flow_graph,
    )


class TestReconstructionRescueExecution:
    def test_entry_island_execution_forwards_plan_call(self, monkeypatch) -> None:
        captured: dict[str, object] = {}
        sentinel = _run(emitted_count=1, projected_flow_graph="projected")

        def _plan(**kwargs):
            captured.update(kwargs)
            return sentinel

        monkeypatch.setattr(rescue_exec, "plan_entry_island_rescues", _plan)

        result = execute_reconstruction_entry_island_rescues(
            dag="dag",
            base_flow_graph="base",
            projected_flow_graph="projected",
            builder="builder",
            modifications=[],
            dispatcher_region={6},
            collect_seeds=lambda **kwargs: (),
            compute_reachable_blocks=lambda fg: {1, 2},
        )

        assert result is sentinel
        assert captured["dag"] == "dag"
        assert captured["dispatcher_region"] == {6}

    def test_late_rescue_collects_diagnostics_only_when_no_emission(self, monkeypatch) -> None:
        monkeypatch.setattr(
            rescue_exec,
            "plan_entry_island_rescues",
            lambda **kwargs: _run(emitted_count=0, projected_flow_graph="projected"),
        )

        result = execute_reconstruction_late_island_rescues(
            dag="dag",
            base_flow_graph="base",
            projected_flow_graph="projected",
            builder="builder",
            modifications=[],
            dispatcher_region={6},
            collect_seeds=lambda **kwargs: (),
            collect_diagnostics=lambda fg, **kwargs: ("diag-a", "diag-b"),
            compute_reachable_blocks=lambda fg: {1, 2, 3},
            dispatcher=SimpleNamespace(),
        )

        assert result.run.emitted_count == 0
        assert result.diagnostics == ("diag-a", "diag-b")

    def test_late_rescue_skips_diagnostics_after_emission(self, monkeypatch) -> None:
        monkeypatch.setattr(
            rescue_exec,
            "plan_entry_island_rescues",
            lambda **kwargs: _run(emitted_count=2, projected_flow_graph="projected"),
        )

        result = execute_reconstruction_late_island_rescues(
            dag="dag",
            base_flow_graph="base",
            projected_flow_graph="projected",
            builder="builder",
            modifications=[],
            dispatcher_region={6},
            collect_seeds=lambda **kwargs: (),
            collect_diagnostics=lambda fg, **kwargs: ("should-not-run",),
            compute_reachable_blocks=lambda fg: {1, 2, 3},
            dispatcher=SimpleNamespace(),
        )

        assert result.run.emitted_count == 2
        assert result.diagnostics == ()
