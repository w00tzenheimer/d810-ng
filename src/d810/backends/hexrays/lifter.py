"""Hex-Rays lifter — the §1a ``lift_function`` boundary.

Snapshots a live ``mba_t`` into a portable ``FlowGraph`` and carries the live object opaquely as
``live_source`` for the mutation backend. This is the one place §1a touches a live ``mba`` on the
read side; portable passes only ever see ``flow_graph``.

Structurally satisfies the ``FunctionSource`` protocol (``passes.pass_pipeline``) without importing
it (that would be an upward layer edge); duck-typing is enough.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.ir.flowgraph import FlowGraph
from d810.hexrays.mutation.ir_translator import IDAIRTranslator


@dataclass(frozen=True)
class HexRaysFunctionSource:
    """Portable handle to the function + its live backend object (the §1a FunctionSource)."""

    _mba: object
    _flow_graph: FlowGraph

    @property
    def flow_graph(self) -> FlowGraph:
        return self._flow_graph

    @property
    def func_ea(self) -> int:
        return int(getattr(self._mba, "entry_ea", 0))

    @property
    def live_source(self) -> object:
        return self._mba


def lift_function(mba: object, maturity: object | None = None) -> HexRaysFunctionSource:
    """Lift a live ``mba_t`` into a §1a ``FunctionSource`` (portable FlowGraph + opaque live mba)."""
    translator = IDAIRTranslator()
    return HexRaysFunctionSource(_mba=mba, _flow_graph=translator.lift(mba))
