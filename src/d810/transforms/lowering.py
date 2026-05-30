"""Explicit lowering modes for state-machine / flow-automaton recovery (LS12).

Per the ``docs/plans/recon-and-cfg-restructuring.md`` "Lowering Strategies"
section, lowering is a *choice of target CFG shape* over the same recovered
recognition result, deliberately separate from the recognition graph and from
the obfuscation *family*.  A strategy's family answers "which obfuscation does
this address?"; its lowering mode answers "what CFG shape do we hand Hex-Rays?".
The two are orthogonal: ``TopologicalSort`` and ``HandlerChainComposer`` are
both ``family=direct`` yet lower as ``DAG_LINEARIZATION`` vs
``REGION_COMPOSITION``.

Net-new and backend-neutral: this package must stay IDA-free at import time.
The mode is recorded as provenance on plan fragments (LS12 C4); it does NOT
drive planner scoring or arbitration, which key on ``fragment.family``.
"""
from __future__ import annotations

import enum

from d810.core.typing import Any, Protocol, runtime_checkable

__all__ = ["LoweringMode", "LoweringStrategy"]


class LoweringMode(str, enum.Enum):
    """Target CFG shape a lowering strategy emits for the recovered automaton."""

    #: Rebuild the semantic CFG edges directly. Preferred when Hex-Rays can
    #: structure the recovered graph.
    DIRECT_GRAPH = "direct_graph"
    #: Lower recognized if/else/loop regions deliberately (presentation parity,
    #: goto reduction).
    STRUCTURED_REGION = "structured_region"
    #: Collapse safe linear handler chains into one materialized payload
    #: (use-def dominance / Hex-Rays DCE hazards).
    REGION_COMPOSITION = "region_composition"
    #: Emit explicit gotos from an acyclic projection (fallback / hard cases).
    DAG_LINEARIZATION = "dag_linearization"


@runtime_checkable
class LoweringStrategy(Protocol):
    """A strategy that lowers a recovered recognition result to a target shape.

    Implementations expose their target shape as ``lowering_mode`` and produce
    rewrite intents / plan fragments from a recognition result (typed ``Any``
    here so this portable contract stays free of vendor and cfg types).
    """

    lowering_mode: LoweringMode

    def lower(self, automaton: Any) -> Any:
        """Lower ``automaton`` to this strategy's target CFG shape."""
        ...
