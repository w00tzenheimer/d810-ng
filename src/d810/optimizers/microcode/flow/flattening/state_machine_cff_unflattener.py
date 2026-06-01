"""§1a live entry point — the state-machine-CFF unflattener driven by the north-star call graph.

This is the runtime realization of the §1a pseudocode: at the maturity hook it lifts the live
``mba`` to a portable ``FunctionSource``, builds an ``AnalysisManager`` (facts), selects the
``HodurFamily``, and runs ``run_pipeline`` (family -> passes -> transforms -> backend.apply). The
ONLY live-mba touch points are the lifter + ``HexRaysMutationBackend`` (backends/hexrays).

GATED OFF by default behind ``D810_USE_S1A_PIPELINE`` — the legacy ``HodurUnflattener`` remains the
default path so the golden is unaffected. Turning the flag on routes the hodur family through the
§1a call graph; until the detection + reconstruction passes are fully ported it is intentionally
incomplete (``HodurFamily.detect`` is still inert), so this is the harness to iterate to
equivalence-or-better, not yet a replacement.
"""
from __future__ import annotations

import os

import ida_hexrays

from d810.core import logging
from d810.hexrays.utils.hexrays_formatters import maturity_to_string
from d810.optimizers.microcode.flow.flattening.unflattening_rule_lifecycle import (
    ComposedUnflatteningRule,
)
from d810.backends.hexrays.lifter import lift_function
from d810.backends.hexrays.mutation.backend import HexRaysMutationBackend
from d810.passes.analysis_manager import AnalysisManager
from d810.passes.driver import run_pipeline
from d810.families.state_machine_cff.hodur_pipeline import HodurFamily

logger = logging.getLogger("D810.unflat.s1a", logging.DEBUG)


def _s1a_enabled() -> bool:
    return os.environ.get("D810_USE_S1A_PIPELINE", "0").strip() == "1"


class StateMachineCffUnflattener(ComposedUnflatteningRule):
    """Run the §1a pipeline for the state-machine-CFF (Hodur) family. Flag-gated, opt-in."""

    DESCRIPTION = "State-machine CFF unflattener via the §1a pipeline (families -> passes -> backend)"
    DEFAULT_UNFLATTENING_MATURITIES = [ida_hexrays.MMAT_GLBOPT1]
    # The §1a pipeline does its own dispatcher detection (HodurFamily.detect); bypass the
    # legacy flow-context unflattening gate (like the other ComposedUnflatteningRule subclasses).
    HAS_OWN_DISPATCHER_COLLECTOR = True

    def __init__(self) -> None:
        super().__init__()
        self._s1a_done_for_ea: int = -1

    def optimize(self, blk: "ida_hexrays.mblock_t") -> int:
        # Bind the live mba FIRST (mirrors HodurUnflattener.optimize): the base
        # ComposedUnflatteningRule only *annotates* ``self.mba`` and the cfg
        # dispatch loop never assigns it, so reading ``self.mba`` before this
        # binding raises AttributeError — which escapes ``func``'s narrow
        # except set into IDA's optblock callback, suppressing this very log
        # line and leaving AFTER == BEFORE (ticket llr-1330).
        self.mba = blk.mba
        logger.info(
            "s1a optimize: enabled=%s maturity=%s blk=%s",
            _s1a_enabled(),
            maturity_to_string(getattr(self.mba, "maturity", 0)),
            getattr(blk, "serial", "?"),
        )
        if not _s1a_enabled():
            return 0
        mba = self.mba
        func_ea = int(getattr(mba, "entry_ea", 0))
        if func_ea == self._s1a_done_for_ea:
            return 0  # one pipeline run per function/maturity
        self._s1a_done_for_ea = func_ea

        source = lift_function(mba, maturity=getattr(mba, "maturity", None))
        # Supply the live validated fact view (state observations) so resolve_state_transitions
        # has the transition evidence; without it the chain produces an empty plan.
        fact_view = None
        flow_ctx = getattr(self, "flow_context", None)
        if flow_ctx is not None:
            try:
                fact_view = flow_ctx.validated_fact_view(getattr(mba, "maturity", 0))
            except Exception:  # noqa: BLE001 — fact view is best-effort input
                logger.debug("s1a: validated_fact_view unavailable", exc_info=True)
        facts = AnalysisManager(source.flow_graph, input_facts=fact_view)
        backend = HexRaysMutationBackend()
        run_pipeline(
            source=source,
            family=HodurFamily(),
            backend=backend,
            facts=facts,
            project_config=None,
            maturity=getattr(mba, "maturity", None),
        )
        # Iteration diagnostics: where does the §1a chain stand for this function?
        rec = facts.get_analysis("recover_dispatcher")
        tr = facts.get_analysis("transition_result")
        regions = facts.get_analysis("plan_semantic_regions")
        logger.info(
            "s1a func=0x%x: input_facts=%s map_rows=%d transitions=%d regions=%d",
            func_ea,
            fact_view is not None,
            len(rec.dispatch_map.rows) if rec and rec.dispatch_map else 0,
            len(tr.transitions) if tr else 0,
            len(regions.linear_regions) if regions else 0,
        )
        # Change accounting is the backend's concern (it lowered the plan); the §1a driver does not
        # yet surface an applied-count, so report 0 until the reconstruction passes land real plans.
        return 0
