"""LS11 C8: cyclic semantic automaton + acyclic DAG projection (ticket d81-mt50).

The recognition graph ("what did we prove") may be cyclic; ``StateDagView`` is the
optional acyclic projection used for linearization.  Distinct from the lowering
graph (LS12).  Net-new + unwired in LS11.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from d810.core.typing import Any

__all__ = ["SemanticGraph", "StateDagView"]


@dataclass(frozen=True)
class SemanticGraph:
    """Possibly-cyclic direct semantic CFG over recovered states."""

    states: tuple[Any, ...] = ()          # state ids / refs
    edges: tuple[tuple[Any, Any], ...] = ()  # (src_state, dst_state)
    has_cycles: bool = False


@dataclass(frozen=True)
class StateDagView:
    """Acyclic projection of a SemanticGraph for safe linearization."""

    ordered_states: tuple[Any, ...] = ()
    edges: tuple[tuple[Any, Any], ...] = ()
