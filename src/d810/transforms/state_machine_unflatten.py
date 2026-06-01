"""Lower a recovered state machine to a direct CFG — produce a PatchPlan (§1a pass #4 transform).

WORK-LIST / seam source: ``optimizers/.../hodur/strategies/reconstruction.py`` +
``hodur/strategies/linearized_flow_graph.py``. The transform consumes portable facts
(dispatcher recovery, transitions, regions) and emits a portable ``PatchPlan``; the live
``mba`` mutation it currently performs moves to ``backends/hexrays/mutation`` via
``MutationBackend.apply``. Behavior-neutral skeleton (empty plan) until the seam lands —
NOT wired into the live runtime.
"""
from __future__ import annotations

from d810.ir.flowgraph import FlowGraph
from d810.analyses.value_flow.model import ValidatedFactView
from d810.transforms.plan import PatchPlan


def lower_to_direct_graph(graph: FlowGraph, facts: ValidatedFactView) -> PatchPlan:
    """Build a ``PatchPlan`` that rewrites the dispatcher loop into direct edges.

    Skeleton (seam pending): returns an empty ``PatchPlan`` (a no-op the backend applies as
    nothing). Seam-extract the plan construction from ``hodur/strategies/reconstruction`` +
    ``linearized_flow_graph``, keeping the live edit on the backend side of ``apply``.
    """
    return PatchPlan()
