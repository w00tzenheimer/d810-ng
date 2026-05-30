"""Family contracts for flow-automaton recognizers (LS13 C1).

Per ``docs/plans/recon-and-cfg-restructuring.md`` ("Flow Automaton And
State-Machine CFF"), the flow-automaton family recognizes small semantic
automata -- ``FakeJump``, ``SingleIteration``, ``BadWhileLoop`` -- as motifs
over a function graph, assigns roles to matched nodes, and composes a chosen
lowering.  These are the backend-neutral contracts for that work; concrete
recognizers (deferred C4) satisfy them structurally.

Graph / recognition / result types are ``Any`` so this family-layer module
stays free of cfg / ir / vendor types (``families`` is ast-grep-globbed as of
LS14, on top of import-linter + the portable-core audit grep).
"""
from __future__ import annotations

from d810.core.typing import Any, Protocol, runtime_checkable

__all__ = ["FlowAutomatonComposition", "FlowAutomatonRecognizer"]


@runtime_checkable
class FlowAutomatonRecognizer(Protocol):
    """Recognizes one flow-automaton motif over a function graph.

    ``recognize`` returns a recognition result (matched roles + evidence) or a
    falsy value when the motif is absent.  The motif is small and local; this is
    a recognizer, not a full state-machine detector.
    """

    name: str

    def recognize(self, graph: Any) -> Any:
        """Return a recognition result for this motif, or a falsy value."""
        ...


@runtime_checkable
class FlowAutomatonComposition(Protocol):
    """Composes a recognized automaton into rewrite intents / a lowering plan.

    Which lowering shape to emit (direct-graph repair vs DAG linearization) is
    the recognizer family's policy choice, recorded via ``d810.transforms``
    ``LoweringMode`` on the produced plan.
    """

    def compose(self, recognition: Any) -> Any:
        """Return rewrite intents / a lowering plan for ``recognition``."""
        ...
