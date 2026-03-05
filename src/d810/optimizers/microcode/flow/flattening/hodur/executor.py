"""Transactional executor for Hodur unflattening pipeline."""
from __future__ import annotations

from collections import Counter

from d810.core import logging

from d810.cfg.flow.edit_simulator import simulate_edits
from d810.cfg.flow.graph_checks import SemanticGate, detect_terminal_cycles, prove_terminal_sink
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    EditType,
    PlanFragment,
    ProposedEdit,
    StageResult,
    VerificationGate,
)

from d810.hexrays.mutation.deferred_modifier import DeferredGraphModifier
from d810.optimizers.microcode.flow.flattening.safeguards import (
    should_apply_cfg_modifications,
)

executor_logger = logging.getLogger("D810.unflat.hodur.executor")


class TransactionalExecutor:
    """Applies plan fragments via DeferredGraphModifier with verification gates."""

    def __init__(
        self,
        mba: object,
        gate: VerificationGate | SemanticGate | None = None,
    ):
        self.mba = mba
        self.gate = gate or SemanticGate()
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

        # ---- Pre-apply semantic preflight ----
        terminal_edits = fragment.metadata.get("terminal_redirect_edits", [])
        # Prefer all_redirect_edits (full edit set); fall back to terminal-only
        all_edits = fragment.metadata.get("all_redirect_edits", []) or terminal_edits
        preflight_forbidden = fragment.metadata.get("forbidden_blocks", set())
        preflight_exits = fragment.metadata.get("exit_blocks", set())

        stage_name = fragment.strategy_name
        if all_edits:
            pre_adj = self._build_adjacency_list(self.mba)
            sim_result = simulate_edits(pre_adj, all_edits)
            sim_adj = sim_result.adj

            # Diagnostic: log edit breakdown by kind
            kind_counts = Counter(e.kind for e in all_edits)
            kind_summary = ", ".join(
                "%s=%d" % (k, v) for k, v in sorted(kind_counts.items())
            )
            executor_logger.info(
                "Preflight: %d edits (%s), terminal_exits=%s, forbidden=%d blocks",
                len(all_edits), kind_summary,
                preflight_exits, len(preflight_forbidden),
            )

            # Prove each terminal redirect target is a valid sink
            for edit in terminal_edits:
                sink_result = prove_terminal_sink(
                    edit.new_target, sim_adj, preflight_exits, preflight_forbidden
                )
                if not sink_result.ok:
                    executor_logger.warning(
                        "Preflight REJECT: redirect %d->%d failed: %s (witness: %s)",
                        edit.source, edit.new_target,
                        sink_result.reason, sink_result.witness_path,
                    )
                    return StageResult(
                        strategy_name=fragment.strategy_name,
                        success=False,
                        rollback_needed=False,
                        error="semantic preflight: %s" % sink_result.reason,
                    )

            # Also run detect_terminal_cycles on simulated graph
            preflight_terminal_exits = set(fragment.metadata.get("terminal_exit_blocks", set()))
            # Include redirect targets so cycle detector walks from them too
            for te in terminal_edits:
                preflight_terminal_exits.add(te.new_target)
            # Include clone nodes created by edge-split simulation
            preflight_terminal_exits = preflight_terminal_exits | sim_result.created_clones
            preflight_handler_entries = fragment.metadata.get("handler_entry_serials", set())
            preflight_dispatcher = fragment.metadata.get("dispatcher_serial", -1)
            cycle_result_pre = detect_terminal_cycles(
                sim_adj, preflight_terminal_exits,
                preflight_handler_entries, preflight_dispatcher,
            )
            if not cycle_result_pre.passed:
                executor_logger.warning(
                    "Preflight REJECT: terminal cycles detected in simulated graph"
                )
                return StageResult(
                    strategy_name=stage_name,
                    success=False,
                    rollback_needed=False,
                    error="semantic preflight: terminal cycles detected",
                )


        changes = deferred.apply(
            run_optimize_local=True,
            run_deep_cleaning=False,
            verify_each_mod=True,
            rollback_on_verify_failure=True,
            continue_on_verify_failure=True,
            enable_snapshot_rollback=True,
        )
        self._total_changes += changes

        # 1. Compute diagnostic metrics (logged, not gated)
        reachable_blocks = self._compute_reachable_blocks()
        qty = self.mba.qty if self.mba is not None else 0
        block_reachability = len(reachable_blocks) / qty if qty > 0 else 0.0

        handler_entry_serials: set[int] = fragment.metadata.get(
            "handler_entry_serials", set()
        )
        if handler_entry_serials:
            reachable_handlers = handler_entry_serials & reachable_blocks
            handler_reachability = len(reachable_handlers) / len(handler_entry_serials)
        else:
            handler_reachability = block_reachability

        executor_logger.info(
            "Stage %s diagnostics: block_reachability=%.2f, handler_reachability=%.2f",
            fragment.strategy_name,
            block_reachability,
            handler_reachability,
        )

        # 2. Semantic check: terminal cycles
        adj = self._build_adjacency_list(self.mba)
        terminal_exits: set[int] = fragment.metadata.get("terminal_exit_blocks", set())
        dispatcher_serial: int = fragment.metadata.get("dispatcher_serial", -1)
        cycle_result = detect_terminal_cycles(
            adj, terminal_exits, handler_entry_serials, dispatcher_serial
        )
        if not cycle_result.passed:
            for cyc in cycle_result.cycles:
                executor_logger.warning(
                    "Terminal cycle: blk[%d] re-enters blk[%d] via %s",
                    cyc.terminal_block, cyc.reentry_target, cyc.path,
                )

        # 3. Build StageResult with semantic data
        result = StageResult(
            strategy_name=fragment.strategy_name,
            edits_applied=changes,
            reachability_after=block_reachability,
            handler_reachability=handler_reachability,
            terminal_cycles=cycle_result.cycles,
        )

        # 4. Gate check
        if not self.gate.check(result):
            result.rollback_needed = True
            result.success = False
            result.error = "semantic gate failed"
            executor_logger.warning(
                "Stage %s failed semantic gate: "
                "terminal_cycles=%d, conflict_count=%d",
                fragment.strategy_name,
                len(result.terminal_cycles),
                result.conflict_count_after,
            )
            # Restore MBA to pre-apply snapshot if available
            if deferred._pre_snapshot is not None:
                if deferred._restore_from_snapshot(deferred._pre_snapshot):
                    executor_logger.info(
                        "Stage %s: gate failed, MBA restored from snapshot",
                        fragment.strategy_name,
                    )
                else:
                    executor_logger.error(
                        "Stage %s: gate failed, snapshot rollback failed",
                        fragment.strategy_name,
                    )
                    result.error = "fatal: MBA corrupted, aborting pipeline"
            else:
                executor_logger.warning(
                    "Stage %s: gate failed, no snapshot available for rollback",
                    fragment.strategy_name,
                )
                result.error = "fatal: MBA corrupted, aborting pipeline"

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

    def _build_adjacency_list(self, mba: object) -> dict[int, list[int]]:
        """Build adjacency list from live MBA block graph."""
        adj: dict[int, list[int]] = {}
        if mba is None:
            return adj
        for i in range(mba.qty):
            blk = mba.get_mblock(i)
            succs = []
            if blk is not None:
                for j in range(blk.nsucc()):
                    succs.append(blk.succ(j))
            adj[i] = succs
        return adj

    def _compute_reachable_blocks(self) -> set[int]:
        """Return the set of block serials reachable from entry via DFS."""
        if self.mba is None:
            return set()
        qty = self.mba.qty
        if qty == 0:
            return set()
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
        return visited
