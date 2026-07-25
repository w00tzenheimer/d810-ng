"""Clean up the residual dispatcher after lowering — produce a PatchPlan (unflatten pass #5 transform).

After ``lower_to_direct_graph`` (#4) redirects handlers onto their real successors, the dispatcher
loop and any self-loop/unresolved remnants are dead. This pass lowers each neutral cleanup candidate
to a ``GraphModification`` via the already-portable ``build_dispatcher_cleanup_modification`` and
compiles them into a typed ``PatchPlan`` while the source graph is available.

``candidates`` is the unflatten analysis dependency (residual-dispatcher detection); while empty (driver
wiring pending) the plan is empty. Portable composition — no extraction from the live cleanup
backend needed; the candidate -> modification lowering already lives in ``transforms.cleanup_evidence``.
"""
from __future__ import annotations

from d810.core.typing import Mapping, Sequence
from d810.ir.flowgraph import FlowGraph
from d810.analyses.value_flow.model import ValidatedFactView
from d810.transforms.plan import PatchPlan, compile_patch_plan
from d810.transforms.cleanup_evidence import build_dispatcher_cleanup_modification
from d810.transforms.cfg_transaction import LogicalBlockRef, NativeBlockRef


def cleanup_residual_dispatcher(
    graph: FlowGraph | None,
    facts: ValidatedFactView | None,
    *,
    candidates: Sequence[object] = (),
    block_refs_by_serial: Mapping[int, NativeBlockRef | LogicalBlockRef] | None = None,
) -> PatchPlan:
    """Build a ``PatchPlan`` removing the dead dispatcher remnants left after lowering.

    Lowers each residual-dispatcher cleanup candidate to a ``GraphModification`` (portable) and
    returns them as a plan. Empty ``candidates`` -> empty plan (no-op).
    """
    if graph is None or not candidates:
        return PatchPlan()
    modifications = [
        build_dispatcher_cleanup_modification(candidate) for candidate in candidates
    ]
    return compile_patch_plan(
        modifications,
        graph,
        block_refs_by_serial=block_refs_by_serial,
    )
