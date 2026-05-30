"""LS12 C1: structural tests for the explicit lowering-mode vocabulary."""
from __future__ import annotations

from d810.transforms import LoweringMode as LoweringModeFacade
from d810.transforms.lowering import LoweringMode, LoweringStrategy


def test_lowering_mode_is_str_enum_with_four_targets() -> None:
    assert {m.value for m in LoweringMode} == {
        "direct_graph",
        "structured_region",
        "region_composition",
        "dag_linearization",
    }
    assert LoweringMode.DIRECT_GRAPH.value == "direct_graph"
    assert isinstance(LoweringMode.DIRECT_GRAPH, str)


def test_facade_reexports_same_object() -> None:
    assert LoweringModeFacade is LoweringMode


def test_lowering_strategy_is_runtime_checkable() -> None:
    class _FakeLowering:
        lowering_mode = LoweringMode.DAG_LINEARIZATION

        def lower(self, automaton):  # noqa: ANN001
            return automaton

    assert isinstance(_FakeLowering(), LoweringStrategy)

    class _NotLowering:
        pass

    assert not isinstance(_NotLowering(), LoweringStrategy)
