"""Thin engine-rule shell for the simple non-Hodur cleanup family."""
from __future__ import annotations

from dataclasses import asdict

import ida_hexrays

from d810.core import getLogger
from d810.optimizers.microcode.flow.flattening.cleanup_family import (
    CLEANUP_FAMILY_METADATA_KEY,
    SimpleFlatteningCleanupDetection,
    SimpleFlatteningCleanupFamily,
    SimpleFlatteningCleanupMetadata,
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
from d810.optimizers.microcode.flow.flattening.rule_shell import (
    ComposedUnflatteningRule,
)

unflat_logger = getLogger("D810.unflat.cleanup_family.engine")

__all__ = ["SimpleFlatteningCleanupUnflattener"]


class SimpleFlatteningCleanupUnflattener(ComposedUnflatteningRule):
    """Planner-visible shell for generic cleanup PlanFragment strategies."""

    DESCRIPTION = (
        "Shared engine adapter for non-Hodur simple flattening cleanup"
    )
    HAS_OWN_DISPATCHER_COLLECTOR = True
    DEFAULT_UNFLATTENING_MATURITIES = [ida_hexrays.MMAT_GLBOPT1]
    DEFAULT_MAX_PASSES = 3
    HARD_MAX_PASSES = 10

    def __init__(self) -> None:
        super().__init__()
        self._family = SimpleFlatteningCleanupFamily()
        self._planner = UnflatteningPlanner()
        self._actual_pass_count = 0
        self._current_tracked_maturity = -1
        self._last_function_ea = -1
        self.max_passes = self.DEFAULT_MAX_PASSES
        self._last_detection: SimpleFlatteningCleanupDetection | None = None
        self._last_snapshot = None
        self._last_provenance: PipelineProvenance | None = None
        self._last_total_changes = 0

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
        metadata: SimpleFlatteningCleanupMetadata | None = None
        if self._last_snapshot is not None and self._last_snapshot.flow_graph is not None:
            candidate = self._last_snapshot.flow_graph.metadata.get(
                CLEANUP_FAMILY_METADATA_KEY
            )
            if isinstance(candidate, SimpleFlatteningCleanupMetadata):
                metadata = candidate
        return {
            "detection": {
                "detected": detection.detected if detection is not None else False,
                "description": detection.description if detection is not None else "none",
                "fake_jump_fixes": (
                    len(detection.fake_jump_fixes) if detection is not None else 0
                ),
                "single_iteration_fixes": (
                    len(detection.single_iteration_fixes)
                    if detection is not None else 0
                ),
                "bad_while_loop_edits": (
                    len(detection.bad_while_loop_edits)
                    if detection is not None else 0
                ),
                "bad_while_loop_deferred_edits": (
                    len(detection.bad_while_loop_deferred_edits)
                    if detection is not None else 0
                ),
                "bad_while_loop_follow_up": (
                    len(detection.bad_while_loop_follow_up)
                    if detection is not None else 0
                ),
                "bad_while_loop_dependency_diagnostics": (
                    len(detection.bad_while_loop_dependency_diagnostics)
                    if detection is not None else 0
                ),
                "tail_goto_merges": (
                    len(detection.tail_goto_merges) if detection is not None else 0
                ),
                "collection_errors": (
                    detection.collection_errors if detection is not None else ()
                ),
            },
            "snapshot": asdict(metadata) if metadata is not None else None,
            "planner": (
                self._last_provenance.summary()
                if self._last_provenance is not None
                else None
            ),
            "total_changes": self._last_total_changes,
        }

    def optimize(self, blk: ida_hexrays.mblock_t) -> int:
        self.mba = blk.mba
        if not self.check_if_rule_should_be_used(blk):
            return 0

        self._last_detection = self._family.detect(self.mba)
        self._last_snapshot = self._family.build_snapshot(
            self.mba,
            self._last_detection,
        )
        planned = plan_family_pipeline(
            self._last_snapshot,
            self._family.strategies_for_maturity(self.cur_maturity),
            planner=self._planner,
            inputs=PlannerInputs(total_handlers=self._last_snapshot.handler_count),
        )
        self._last_provenance = planned.provenance

        metadata = None
        if self._last_snapshot.flow_graph is not None:
            metadata = self._last_snapshot.flow_graph.metadata.get(
                CLEANUP_FAMILY_METADATA_KEY
            )
        unflat_logger.info(
            "Simple cleanup engine detect=%s snapshot=%s planner=%s",
            self._last_detection.description,
            metadata,
            self._last_provenance.summary(),
        )

        if not planned.pipeline:
            if self.flow_context is not None:
                self.flow_context.report_outcome(planned.provenance, "planner")
            self._actual_pass_count += 1
            self._last_total_changes = 0
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
        self._last_total_changes = total_changes
        return total_changes
