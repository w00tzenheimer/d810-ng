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
from d810.optimizers.microcode.flow.flattening.unflattening_rule_lifecycle import (
    ComposedUnflatteningRule,
)
from d810.backends.hexrays.lifter import lift_function
from d810.backends.hexrays.mutation.backend import HexRaysMutationBackend
from d810.passes.analysis_manager import AnalysisManager
from d810.passes.driver import run_pipeline
from d810.families.state_machine_cff.hodur_pipeline import HodurFamily

logger = logging.getLogger("D810.unflat.s1a")


def _s1a_enabled() -> bool:
    return os.environ.get("D810_USE_S1A_PIPELINE", "0").strip() == "1"


class StateMachineCffUnflattener(ComposedUnflatteningRule):
    """Run the §1a pipeline for the state-machine-CFF (Hodur) family. Flag-gated, opt-in."""

    DESCRIPTION = "State-machine CFF unflattener via the §1a pipeline (families -> passes -> backend)"
    DEFAULT_UNFLATTENING_MATURITIES = [ida_hexrays.MMAT_GLBOPT1]

    def __init__(self) -> None:
        super().__init__()
        self._s1a_done_for_ea: int = -1

    def optimize(self, blk: "ida_hexrays.mblock_t") -> int:
        if not _s1a_enabled():
            return 0
        mba = self.mba
        func_ea = int(getattr(mba, "entry_ea", 0))
        if func_ea == self._s1a_done_for_ea:
            return 0  # one pipeline run per function/maturity
        self._s1a_done_for_ea = func_ea

        source = lift_function(mba, maturity=getattr(mba, "maturity", None))
        facts = AnalysisManager(source.flow_graph)
        backend = HexRaysMutationBackend()
        run_pipeline(
            source=source,
            family=HodurFamily(),
            backend=backend,
            facts=facts,
            project_config=None,
            maturity=getattr(mba, "maturity", None),
        )
        # Change accounting is the backend's concern (it lowered the plan); the §1a driver does not
        # yet surface an applied-count, so report 0 until the reconstruction passes land real plans.
        return 0
