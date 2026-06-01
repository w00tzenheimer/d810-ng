"""Plan semantic regions over a portable FlowGraph (§1a pass #3 transform).

WORK-LIST / seam source: ``optimizers/.../hodur/reconstruction_fragment_builder.py``. The
portable region planning (handler grouping, region boundaries) is lifted here; the live
``mba`` reads it still performs move behind ``MicrocodeEvidenceProvider``. Behavior-neutral
skeleton until that seam lands — NOT wired into the live runtime.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from d810.ir.flowgraph import FlowGraph
from d810.analyses.value_flow.model import ValidatedFactView


@dataclass(frozen=True, slots=True)
class SemanticRegionPlan:
    """Portable plan of semantic regions discovered over the FlowGraph."""

    region_entry_serials: tuple[int, ...] = field(default=())


def plan_semantic_regions(
    graph: FlowGraph, facts: ValidatedFactView
) -> SemanticRegionPlan:
    """Group handler blocks into semantic regions over a portable ``FlowGraph``.

    Skeleton (seam pending): returns an empty plan. Seam-extract from
    ``hodur/reconstruction_fragment_builder``.
    """
    return SemanticRegionPlan()
