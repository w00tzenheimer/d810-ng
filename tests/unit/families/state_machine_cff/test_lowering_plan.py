"""LS12 C2: structural tests for FlowAutomaton + LoweringGraph."""
from __future__ import annotations

from d810.families.state_machine_cff import FlowAutomaton as FlowAutomatonFacade
from d810.families.state_machine_cff.lowering_plan import FlowAutomaton, LoweringGraph
from d810.transforms.lowering import LoweringMode


def test_flow_automaton_pairs_recognition_and_lowering() -> None:
    fa = FlowAutomaton(recognition_graph=("cyclic-graph",), lowering_plan=None)
    assert fa.recognition_graph == ("cyclic-graph",)
    assert fa.lowering_plan is None


def test_facade_reexports_same_object() -> None:
    assert FlowAutomatonFacade is FlowAutomaton


def test_lowering_graph_is_runtime_checkable_on_lowering_mode() -> None:
    class _FakePlan:
        lowering_mode = LoweringMode.REGION_COMPOSITION

    assert isinstance(_FakePlan(), LoweringGraph)

    class _NoMode:
        pass

    assert not isinstance(_NoMode(), LoweringGraph)
