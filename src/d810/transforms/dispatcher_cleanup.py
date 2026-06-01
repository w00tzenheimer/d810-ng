"""Clean up the residual dispatcher after lowering — produce a PatchPlan (§1a pass #5 transform).

WORK-LIST / seam source: ``optimizers/.../cleanup_backend.py`` + ``cleanup_live_evidence.py``.
These are the cleanup optimizer (separate from the live HodurUnflattener path on the flagship
configs); the portable cleanup planning lives here, the live mutation stays on the backend.
Behavior-neutral skeleton (empty plan) until the seam lands — NOT wired into the live runtime.
"""
from __future__ import annotations

from d810.ir.flowgraph import FlowGraph
from d810.analyses.value_flow.model import ValidatedFactView
from d810.transforms.plan import PatchPlan


def cleanup_residual_dispatcher(
    graph: FlowGraph, facts: ValidatedFactView
) -> PatchPlan:
    """Build a ``PatchPlan`` removing dead dispatcher blocks left after lowering.

    Skeleton (seam pending): returns an empty ``PatchPlan``. Seam-extract from
    ``cleanup_backend`` + ``cleanup_live_evidence``.
    """
    return PatchPlan()
