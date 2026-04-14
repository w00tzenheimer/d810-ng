"""Thin engine-rule shell for the extracted emulated-dispatcher family."""
from __future__ import annotations

from dataclasses import asdict

import ida_hexrays

from d810.core import getLogger
from d810.optimizers.microcode.flow.flattening.emulated_dispatcher_family import (
    EmulatedDispatcherDetection,
    EmulatedDispatcherStrategyFamily,
)
from d810.optimizers.microcode.flow.flattening.engine.executor import (
    TransactionalExecutor,
)
from d810.optimizers.microcode.flow.flattening.engine.planner import (
    UnflatteningPlanner,
)
from d810.optimizers.microcode.flow.flattening.engine.provenance import (
    PipelineProvenance,
    PlannerInputs,
)
from d810.optimizers.microcode.flow.flattening.engine.runtime import (
    execute_family_pipeline,
    plan_family_pipeline,
)
from d810.optimizers.microcode.flow.flattening.generic import (
    GenericUnflatteningRule,
)
from d810.optimizers.microcode.flow.flattening.strategies.emulated_dispatcher_strategy import (
    EmulatedDispatcherMetadata,
    extract_emulated_dispatcher_metadata,
)

unflat_logger = getLogger("D810.unflat.emulated_dispatcher.engine")

__all__ = ["EmulatedDispatcherUnflattener"]


class EmulatedDispatcherUnflattener(GenericUnflatteningRule):
    """Planner-visible shell for the extracted emulated-dispatcher family."""

    DESCRIPTION = "Extracted engine adapter for generic emulated-dispatcher lowering"
    HAS_OWN_DISPATCHER_COLLECTOR = True
    DEFAULT_MAX_PASSES = 3
    HARD_MAX_PASSES = 10
    DEFAULT_UNFLATTENING_MATURITIES = [
        ida_hexrays.MMAT_CALLS,
        ida_hexrays.MMAT_GLBOPT1,
        ida_hexrays.MMAT_GLBOPT2,
    ]

    def __init__(self) -> None:
        super().__init__()
        self._family = EmulatedDispatcherStrategyFamily()
        self._planner = UnflatteningPlanner()
        self._actual_pass_count = 0
        self._current_tracked_maturity = -1
        self._last_function_ea = -1
        self.max_passes = self.DEFAULT_MAX_PASSES
        self._last_detection: EmulatedDispatcherDetection | None = None
        self._last_snapshot = None
        self._last_provenance: PipelineProvenance | None = None

    def check_if_rule_should_be_used(self, blk: ida_hexrays.mblock_t) -> bool:
        if not super().check_if_rule_should_be_used(blk):
            return False
        function_ea = int(getattr(self.mba, "entry_ea", 0) or 0)
        if (
            self.mba.maturity != self._current_tracked_maturity
            or function_ea != self._last_function_ea
        ):
            self._current_tracked_maturity = self.mba.maturity
            self._last_function_ea = function_ea
            self._actual_pass_count = 0
            self.max_passes = self.DEFAULT_MAX_PASSES
        return self._actual_pass_count < self.max_passes

    def get_last_observation(self) -> dict[str, object]:
        detection = self._last_detection
        snapshot = self._last_snapshot
        observation: EmulatedDispatcherMetadata | None = None
        if snapshot is not None:
            observation = extract_emulated_dispatcher_metadata(snapshot.flow_graph)
        return {
            "detection": {
                "detected": detection.detected if detection is not None else False,
                "description": detection.description if detection is not None else "none",
                "analysis_dispatchers": (
                    detection.analysis_dispatchers if detection is not None else ()
                ),
                "dispatcher_shape": (
                    detection.dispatcher_shape if detection is not None else "none"
                ),
                "state_transport": (
                    detection.state_transport if detection is not None else "none"
                ),
                "lowering_mode": (
                    detection.lowering_mode if detection is not None else "none"
                ),
                "provenance_hints": (
                    detection.provenance_hints if detection is not None else ()
                ),
                "collector_dispatchers": (
                    detection.collector_dispatcher_entries if detection is not None else ()
                ),
                "planning_blocker": (
                    detection.planning_blocker if detection is not None else None
                ),
            },
            "snapshot": asdict(observation) if observation is not None else None,
            "planner": (
                self._last_provenance.summary()
                if self._last_provenance is not None
                else None
            ),
        }

    def optimize(self, blk: ida_hexrays.mblock_t) -> int:
        self.mba = blk.mba
        if not self.check_if_rule_should_be_used(blk):
            return 0

        self._last_detection = self._family.detect(self.mba)
        self._last_snapshot = self._family.build_snapshot(self.mba, self._last_detection)

        planned = plan_family_pipeline(
            self._last_snapshot,
            self._family.strategies_for_maturity(self.cur_maturity),
            planner=self._planner,
            inputs=PlannerInputs(total_handlers=self._last_snapshot.handler_count),
        )
        self._last_provenance = planned.provenance

        unflat_logger.info(
            "Emulated-dispatcher engine detect=%s snapshot=%s planner=%s",
            self._last_detection.description,
            extract_emulated_dispatcher_metadata(self._last_snapshot.flow_graph),
            self._last_provenance.summary(),
        )

        if not planned.pipeline:
            if self.flow_context is not None:
                self.flow_context.report_outcome(planned.provenance, "planner")
            self._actual_pass_count += 1
            return 0

        executed = execute_family_pipeline(
            self._last_snapshot,
            planned,
            executor_factory=lambda mba: TransactionalExecutor(
                mba,
                safeguard_profile="engine",
            ),
            flow_context=self.flow_context,
        )
        self._last_provenance = executed.provenance
        cleanup_changes = self._family.post_execute_cleanup(
            self.mba,
            snapshot=self._last_snapshot,
            total_changes=executed.total_changes,
        )
        total_changes = executed.total_changes + cleanup_changes
        if total_changes > 0 and self.max_passes < self.HARD_MAX_PASSES:
            self.max_passes += 1
        self._actual_pass_count += 1
        return total_changes
