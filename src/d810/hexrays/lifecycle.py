from __future__ import annotations

from d810.core import getLogger
from d810.core.decompilation_session import DecompilationEvent as _DecompilationEvent
from d810.hexrays.mutation.ir_translator import lift as lift_mba_to_flowgraph
from d810.hexrays.utils.hexrays_formatters import maturity_to_string

optimizer_logger = getLogger("D810.optimizer")

HEXRAYS_MICROCODE_PROVIDER = "hexrays_microcode"


def _emit_flowgraph_ready_event(
    event_emitter,
    mba,
    *,
    snapshot=None,
) -> None:
    """Lift ``mba`` and emit ``FLOWGRAPH_READY`` (no-op when emitter is None).

    Shared helper invoked at every maturity-transition gate --
    ``InstructionOptimizerManager.log_info_on_input`` and
    ``BlockOptimizerManager.log_info_on_input``.  Both producers
    route through one helper so the cross-layer event fires at
    every preanalysis-collection lifecycle point.

    The manager-owned lifecycle coordinator is the sole invoker of
    ``PreanalysisRuntime.capture_flowgraph`` for the microcode path. The legacy
    live-mba direct calls that used to live in the hook module are gone.

    Lift failures log via ``optimizer_logger.exception`` and return
    cleanly -- the subscriber never runs for the failed transition,
    so preanalysis misses one maturity but decompilation is never gated
    by a lift bug.

    Payload: ``flow_graph`` + ``func_ea`` + the provider-neutral stage
    fields (``producer`` / ``producer_stage_id`` / ``producer_stage_name``
    / ``snapshot_stage``, E2d) + the retained ``maturity`` /
    ``maturity_name`` aliases (E2b).  Every field is sourced directly
    from ``flow_graph.metadata`` so the event mirrors the lifter's
    metadata contract -- the lifter is the single source of truth, the
    event is NOT an alternate convention.  No ``mba_t`` crosses the
    boundary.

    The block-manager producer may also include the pre-D810
    diagnostic ``snapshot`` so the subscriber can capture facts on
    the same portable payload.  The instruction-manager producer has
    no such snapshot, and therefore emits only the canonical stage
    payload keys.
    """
    if event_emitter is None:
        return
    try:
        flow_graph = lift_mba_to_flowgraph(mba)
    except Exception:
        optimizer_logger.exception(
            "FlowGraph lift failed at maturity %s (func=0x%x); "
            "FLOWGRAPH_READY suppressed for this transition",
            maturity_to_string(int(getattr(mba, "maturity", 0) or 0)),
            int(getattr(mba, "entry_ea", 0) or 0),
        )
        return
    metadata = flow_graph.metadata
    payload = {
        "flow_graph": flow_graph,
        "func_ea": int(mba.entry_ea),
        # Provider-neutral stage fields (E2d), sourced from the lifter's
        # metadata so the event mirrors the single source of truth.
        "producer": metadata["producer"],
        "producer_stage_id": metadata["producer_stage_id"],
        "producer_stage_name": metadata["producer_stage_name"],
        "snapshot_stage": metadata["snapshot_stage"],
        # E2b transition aliases (retained for legacy subscribers).
        "maturity": metadata["maturity"],
        "maturity_name": metadata["maturity_name"],
    }
    if snapshot is not None:
        payload["snapshot"] = snapshot
    event_emitter.emit(_DecompilationEvent.FLOWGRAPH_READY, **payload)
