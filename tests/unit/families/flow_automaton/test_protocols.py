"""LS13 C1: structural tests for the flow-automaton family Protocols."""
from __future__ import annotations

from d810.families.flow_automaton import (
    FlowAutomatonComposition as CompositionFacade,
    FlowAutomatonRecognizer as RecognizerFacade,
)
from d810.families.flow_automaton.protocols import (
    FlowAutomatonComposition,
    FlowAutomatonRecognizer,
)


def test_facade_reexports_same_objects() -> None:
    assert RecognizerFacade is FlowAutomatonRecognizer
    assert CompositionFacade is FlowAutomatonComposition


def test_recognizer_is_runtime_checkable() -> None:
    class _FakeRecognizer:
        name = "fake_jump"

        def recognize(self, graph):  # noqa: ANN001
            return None

    assert isinstance(_FakeRecognizer(), FlowAutomatonRecognizer)

    class _NotRecognizer:
        name = "x"

    assert not isinstance(_NotRecognizer(), FlowAutomatonRecognizer)


def test_composition_is_runtime_checkable() -> None:
    class _FakeComposition:
        def compose(self, recognition):  # noqa: ANN001
            return ()

    assert isinstance(_FakeComposition(), FlowAutomatonComposition)
