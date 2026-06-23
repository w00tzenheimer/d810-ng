from __future__ import annotations

from pathlib import Path


DISPATCHER_ARTIFACTS = (
    Path(__file__).resolve().parents[4]
    / "src"
    / "d810"
    / "evaluator"
    / "hexrays_microcode"
    / "dispatcher_artifacts.py"
)


def test_dispatcher_artifact_planner_does_not_import_mutation_layer() -> None:
    source = DISPATCHER_ARTIFACTS.read_text(encoding="utf-8")

    assert "def plan_dispatcher_state_return_carrier_artifact(" in source
    assert "DeferredGraphModifier" not in source
    assert "d810.hexrays.mutation" not in source
    assert "lower_dispatcher_state_return_carrier_artifact" not in source
