"""Clean up the residual dispatcher after lowering — produce a PatchPlan (§1a pass #5 transform).

After ``lower_to_direct_graph`` (#4) redirects handlers onto their real successors, the dispatcher
loop and any self-loop/unresolved remnants are dead. This pass lowers each neutral cleanup candidate
to a ``GraphModification`` via the already-portable ``build_dispatcher_cleanup_modification`` and
packs them into a ``PatchPlan`` (the ``planner_modifications`` channel the backend applies).

``candidates`` is the §1a analysis dependency (residual-dispatcher detection); while empty (driver
wiring pending) the plan is empty. Portable composition — no extraction from the live cleanup
backend needed; the candidate -> modification lowering already lives in ``transforms.cleanup_evidence``.
"""
from __future__ import annotations

from d810.core.typing import Sequence
from d810.ir.flowgraph import FlowGraph
from d810.analyses.value_flow.model import ValidatedFactView
from d810.transforms.plan import PatchPlan
from d810.transforms.cleanup_evidence import build_dispatcher_cleanup_modification


def cleanup_residual_dispatcher(
    graph: FlowGraph | None,
    facts: ValidatedFactView | None,
    *,
    candidates: Sequence[object] = (),
) -> PatchPlan:
    """Build a ``PatchPlan`` removing the dead dispatcher remnants left after lowering.

    Lowers each residual-dispatcher cleanup candidate to a ``GraphModification`` (portable) and
    returns them as a plan. Empty ``candidates`` -> empty plan (no-op).
    """
    if graph is None or not candidates:
        return PatchPlan()
    modifications = tuple(
        build_dispatcher_cleanup_modification(candidate) for candidate in candidates
    )
    return PatchPlan(planner_modifications=modifications)
