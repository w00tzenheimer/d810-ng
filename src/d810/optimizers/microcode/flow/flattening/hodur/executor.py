"""Transactional executor for Hodur unflattening pipeline."""
from __future__ import annotations

from d810.core import logging

from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    EditType,
    PlanFragment,
    ProposedEdit,
    StageResult,
    VerificationGate,
)

from d810.hexrays.deferred_modifier import DeferredGraphModifier
from d810.optimizers.microcode.flow.flattening.safeguards import (
    should_apply_cfg_modifications,
)

executor_logger = logging.getLogger("D810.unflat.hodur.executor")


class TransactionalExecutor:
    """Applies plan fragments via DeferredGraphModifier with verification gates."""

    def __init__(self, mba: object, gate: VerificationGate | None = None):
        self.mba = mba
        self.gate = gate or VerificationGate()
        self._total_changes = 0

    def execute_pipeline(
        self, pipeline: list[PlanFragment], total_handlers: int
    ) -> list[StageResult]:
        """Execute ordered pipeline of plan fragments."""
        results: list[StageResult] = []
        for fragment in pipeline:
            result = self.execute_stage(fragment, total_handlers)
            results.append(result)
            if result.rollback_needed:
                executor_logger.warning(
                    "Stage %s failed gate check — skipping remaining pipeline",
                    fragment.strategy_name,
                )
                break
        return results

    def execute_stage(self, fragment: PlanFragment, total_handlers: int) -> StageResult:
        """Execute one plan fragment through DeferredGraphModifier."""
        if fragment.is_empty():
            return StageResult(strategy_name=fragment.strategy_name)

        deferred = DeferredGraphModifier(self.mba)

        for edit in fragment.proposed_edits:
            self._apply_edit(deferred, edit)

        if not deferred.has_modifications():
            return StageResult(strategy_name=fragment.strategy_name)

        num_redirected = len(deferred.modifications)
        if not should_apply_cfg_modifications(num_redirected, total_handlers, "hodur"):
            deferred.reset()
            return StageResult(
                strategy_name=fragment.strategy_name,
                success=False,
                error="safeguard rejected modifications",
            )

        changes = deferred.apply(run_optimize_local=True, run_deep_cleaning=False)
        self._total_changes += changes

        result = StageResult(
            strategy_name=fragment.strategy_name,
            edits_applied=changes,
            reachability_after=self._compute_reachability(),
        )

        if not self.gate.check(result):
            result.rollback_needed = True
            result.success = False
            result.error = "verification gate failed"
            executor_logger.warning(
                "Stage %s failed verification gate: reachability=%.2f",
                fragment.strategy_name,
                result.reachability_after,
            )

        return result

    @property
    def total_changes(self) -> int:
        return self._total_changes

    def _apply_edit(self, deferred: object, edit: ProposedEdit) -> None:
        """Convert a ProposedEdit to a deferred modifier operation."""
        if edit.edit_type == EditType.GOTO_REDIRECT:
            blk = self.mba.get_mblock(edit.source_block)
            if blk is None:
                return
            if blk.nsucc() == 1:
                deferred.queue_goto_change(edit.source_block, edit.target_block)
            elif blk.nsucc() == 2:
                deferred.queue_convert_to_goto(edit.source_block, edit.target_block)
        elif edit.edit_type == EditType.CONVERT_TO_GOTO:
            deferred.queue_convert_to_goto(edit.source_block, edit.target_block)
        elif edit.edit_type == EditType.NOP_INSN:
            if edit.instruction_ea is not None:
                deferred.queue_insn_nop(edit.source_block, edit.instruction_ea)
        elif edit.edit_type == EditType.CONDITIONAL_REDIRECT:
            deferred.queue_conditional_target_change(edit.source_block, edit.target_block)
        elif edit.edit_type == EditType.EDGE_REDIRECT:
            old_target = edit.metadata.get("old_target", 0)
            via_pred = edit.metadata.get("via_pred")
            if via_pred is not None and edit.target_block is not None:
                deferred.queue_edge_redirect(
                    src_block=edit.source_block,
                    old_target=old_target,
                    new_target=edit.target_block,
                    via_pred=via_pred,
                    rule_priority=edit.metadata.get("rule_priority", 550),
                    description=edit.metadata.get("description", ""),
                )
        elif edit.edit_type == EditType.BLOCK_DUPLICATE:
            executor_logger.warning(
                "BLOCK_DUPLICATE not yet implemented for block %d",
                edit.source_block,
            )

    def _compute_reachability(self) -> float:
        """Compute fraction of blocks reachable from entry."""
        if self.mba is None:
            return 0.0
        qty = self.mba.qty
        if qty == 0:
            return 0.0
        visited: set[int] = set()
        queue = [0]
        while queue:
            serial = queue.pop()
            if serial in visited or serial < 0 or serial >= qty:
                continue
            visited.add(serial)
            blk = self.mba.get_mblock(serial)
            if blk is not None:
                for i in range(blk.nsucc()):
                    queue.append(blk.succ(i))
        return len(visited) / qty
