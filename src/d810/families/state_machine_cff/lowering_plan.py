"""LS12 C2: FlowAutomaton container + LoweringGraph contract.

Per ``docs/plans/recon-and-cfg-restructuring.md`` ("Recognition Graph Versus
Lowering Graph"), a recovered automaton pairs two distinct views:

  * a *recognition graph* -- "what did we prove?" -- which may legitimately be
    cyclic (real semantic loops Hex-Rays must see to recover loops), and
  * a *lowering plan* -- "what CFG shape do we want Hex-Rays to structure?".

``FlowAutomaton`` binds them; ``LoweringGraph`` is the structural contract for
the lowering-plan half.  Both are net-new and unwired in LS12.

Fields are ``Any``-typed so this family-layer module stays free of cfg / ir /
vendor types; families is not ast-grep-globbed, so import-linter + the
portable-core audit grep are the purity gates.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.core.typing import Any, Protocol, runtime_checkable

__all__ = ["FlowAutomaton", "LoweringGraph"]


@runtime_checkable
class LoweringGraph(Protocol):
    """The chosen target CFG shape (the lowering-plan half of a FlowAutomaton).

    Carries the ``lowering_mode`` it targets (a ``LoweringMode``, typed ``Any``
    here to avoid coupling the family layer to ``d810.transforms``).
    """

    lowering_mode: Any


@dataclass(frozen=True)
class FlowAutomaton:
    """Pairs a (possibly cyclic) recognition graph with a chosen lowering plan.

    ``recognition_graph`` is the proof/extraction view; ``lowering_plan`` is the
    target CFG shape handed to the backend.  State-machine unflattening means
    "recover the semantic automaton, then choose the lowering that gives
    Hex-Rays the best structurability" -- not "always produce a DAG".
    """

    recognition_graph: Any
    lowering_plan: Any
