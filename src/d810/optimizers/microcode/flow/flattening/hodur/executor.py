"""Transactional executor for Hodur unflattening pipeline.

# EXECUTOR_BOUNDARY: The executor only enforces gates and updates lifecycle.
# It does NOT perform strategy selection, conflict resolution, pipeline
# reordering, or fragment insertion.  All such decisions are made upstream
# by the UnflatteningPlanner.
#
# The executor may SKIP a fragment only via:
#   - Safeguard gate failure (insufficient modifications for handler count)
#   - Backend precondition filter (individual edge-split failures)
#   - Preflight rejection (structural legality, terminal cycles)
#   - Transaction engine failure (lowering/apply errors)
#   - Semantic gate failure (reachability, handler reachability, conflicts)
#
# None of these constitute re-arbitration: they are runtime safety checks
# that the planner cannot predict at planning time (they depend on live
# MBA state and IDA backend preconditions).
"""
from __future__ import annotations

from collections import Counter

from d810.core import logging

from d810.cfg.flow.edit_simulator import (
    SimulatedEdit,
    graph_modifications_to_simulated_edits,
    patch_plan_to_simulated_edits,
    simulate_edits,
)
from d810.cfg.flow.graph_checks import (
    SemanticGate,
    check_edge_split_structural_legality,
    detect_terminal_cycles,
    prove_terminal_sink,
)
from d810.cfg.flowgraph import FlowGraph
from d810.cfg.contracts import IDACfgContract
from d810.cfg.contracts.transaction_engine import CfgTransactionEngine
from d810.cfg.graph_modification import (
    ConvertToGoto,
    CreateConditionalRedirect,
    EdgeRedirectViaPredSplit,
    GraphModification,
    RedirectBranch,
    RedirectGoto,
)
from d810.cfg.plan import PatchEdgeSplitTrampoline, PatchPlan, compile_patch_plan
from d810.hexrays.mutation.ir_translator import IDAIRTranslator
from d810.optimizers.microcode.flow.flattening.hodur.provenance import (
    GateAccounting,
    GateDecision,
    GateVerdict,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    PlanFragment,
    StageResult,
    VerificationGate,
)
from d810.optimizers.microcode.flow.flattening.safeguards import (
    should_apply_bulk_cfg_modifications,
)
from d810.recon.flow.terminal_return_audit import build_terminal_return_audit
from d810.evaluator.hexrays_microcode.terminal_return_proof import prove_terminal_returns

executor_logger = logging.getLogger("D810.unflat.hodur.executor")


def _preflight_priority(mod: GraphModification) -> int:
    """Mirror DeferredGraphModifier apply priority for topology simulation."""
    from d810.cfg.graph_modification import (
        ConvertToGoto,
        CreateConditionalRedirect,
        EdgeRedirectViaPredSplit,
        InsertBlock,
        RedirectBranch,
        RedirectGoto,
    )

    match mod:
        case InsertBlock() | CreateConditionalRedirect():
            return 5
        case EdgeRedirectViaPredSplit():
            return 8
        case RedirectGoto() | RedirectBranch():
            return 10
        case ConvertToGoto():
            return 20
        case _:
            return 1000


def _preflight_simulated_priority(edit: SimulatedEdit) -> int:
    match edit.kind:
        case "create_conditional_redirect" | "duplicate_block":
            return 5
        case "edge_split_redirect":
            return 8
        case "goto_redirect" | "conditional_redirect":
            return 10
        case "convert_to_goto":
            return 20
        case _:
            return 1000


class TransactionalExecutor:
    """Applies plan fragments through GraphModification lowering with gates."""

    def __init__(
        self,
        mba: object,
        gate: VerificationGate | SemanticGate | None = None,
        translator: IDAIRTranslator | None = None,
        allow_legacy_block_creation: bool = True,
        cfg_contract: IDACfgContract | None = None,
    ):
        self.mba = mba
        self.gate = gate or SemanticGate()
        self.allow_legacy_block_creation = allow_legacy_block_creation
        self.cfg_contract = cfg_contract
        self.translator = translator or IDAIRTranslator(
            allow_legacy_block_creation=allow_legacy_block_creation,
            contract=self.cfg_contract,
        )
        self._total_changes = 0

    def execute_pipeline(
        self, pipeline: list[PlanFragment], total_handlers: int
    ) -> list[StageResult]:
        """Execute ordered pipeline of plan fragments.

        The safeguard gate is checked here, before calling execute_stage(),
        so that the executor never sees rejected stages.
        """
        results: list[StageResult] = []
        for fragment in pipeline:
            # Pre-execution safeguard gate: check before execute_stage()
            modifications = list(fragment.modifications)
            num_modifications = len(modifications)
            safeguard_ok = should_apply_bulk_cfg_modifications(
                num_modifications, total_handlers, "hodur"
            )
            if not safeguard_ok:
                gate_accounting = GateAccounting().add(GateDecision(
                    gate_name="safeguard",
                    verdict=GateVerdict.FAILED,
                    reason=(
                        f"insufficient modifications ({num_modifications}) "
                        f"for {total_handlers} handlers"
                    ),
                ))
                result = StageResult(
                    strategy_name=fragment.strategy_name,
                    success=False,
                    error="safeguard rejected modifications",
                    failure_phase="safeguard",
                )
                result.metadata["gate_accounting"] = gate_accounting
                executor_logger.info(
                    "Safeguard gate rejected stage %s: %s",
                    fragment.strategy_name,
                    gate_accounting.summary(),
                )
                results.append(result)
                continue

            result = self.execute_stage(fragment, total_handlers)
            results.append(result)
            if result.rollback_needed or result.quarantine:
                executor_logger.warning(
                    "Stage %s failed gate check - skipping remaining pipeline",
                    fragment.strategy_name,
                )
                break
        return results

    def execute_stage(self, fragment: PlanFragment, total_handlers: int) -> StageResult:
        """Execute one plan fragment through IDAIRTranslator lowering."""
        if fragment.is_empty():
            return StageResult(strategy_name=fragment.strategy_name)

        modifications = list(fragment.modifications)
        if not modifications:
            return StageResult(strategy_name=fragment.strategy_name)

        gate_accounting = GateAccounting()

        pre_cfg = self.translator.lift(self.mba)

        patch_plan_preview = compile_patch_plan(modifications, pre_cfg)
        modifications, patch_plan_preview, backend_removed = self._filter_backend_unsupported_modifications(
            pre_cfg,
            modifications,
            patch_plan_preview,
        )
        if backend_removed:
            gate_accounting = gate_accounting.with_backend_filter(backend_removed)
        if not modifications:
            gate_accounting = gate_accounting.with_backend_filter(backend_removed)
            result = StageResult(
                strategy_name=fragment.strategy_name,
                success=False,
                error="all modifications removed by execution filters",
                failure_phase="execution_filter",
            )
            result.metadata["backend_filter"] = backend_removed
            result.metadata["gate_accounting"] = gate_accounting
            return result

        if patch_plan_preview.legacy_block_operations and not self.allow_legacy_block_creation:
            return StageResult(
                strategy_name=fragment.strategy_name,
                success=False,
                error="block-creating edits disabled by policy",
                failure_phase="preflight",
            )

        modifications, patch_plan, preflight_error, cycle_removed = self._run_preflight(
            fragment,
            pre_cfg,
            modifications,
            patch_plan_preview,
        )
        if cycle_removed:
            gate_accounting = gate_accounting.with_cycle_filter(cycle_removed)
        if preflight_error is not None:
            preflight_error.metadata.setdefault("cycle_filter", cycle_removed)
            preflight_error.metadata.setdefault("backend_filter", backend_removed)
            preflight_error.metadata["gate_accounting"] = gate_accounting
            return preflight_error
        if not modifications:
            # All modifications removed by cycle + backend filtering
            total_filtered = backend_removed + cycle_removed
            if total_filtered > 0:
                result = StageResult(
                    strategy_name=fragment.strategy_name,
                    success=False,
                    error="all modifications removed by execution filters",
                    failure_phase="execution_filter",
                )
                result.metadata["cycle_filter"] = cycle_removed
                result.metadata["backend_filter"] = backend_removed
                result.metadata["gate_accounting"] = gate_accounting
                return result
            return StageResult(strategy_name=fragment.strategy_name)

        executor_logger.info(
            "Stage %s compiled PatchPlan: concrete=%d symbolic_blocks=%d legacy_block_steps=%d",
            fragment.strategy_name,
            len(patch_plan.concrete_operations),
            len(patch_plan.new_blocks),
            len(patch_plan.legacy_block_operations),
        )

        # Wire CfgTransactionEngine for projected -> pre -> lower/apply sequence
        contract = self._get_cfg_contract()
        self.translator.contract = contract  # ensure translator has it for post-apply hook
        engine = CfgTransactionEngine(translator=self.translator, contract=contract)

        tx_result = engine.apply(patch_plan, pre_cfg=pre_cfg, mba=self.mba)

        gate_accounting = gate_accounting.add(GateDecision(
            gate_name="transaction_engine",
            verdict=GateVerdict.PASSED if tx_result.success else GateVerdict.FAILED,
            reason=(
                f"applied={tx_result.applied_count}"
                if tx_result.success
                else f"rejected at {tx_result.failure_phase}: {tx_result.error}"
            ),
        ))
        if not tx_result.success:
            classification = tx_result.classification
            executor_logger.warning(
                "CfgTransactionEngine rejected stage %s at phase %s: %s",
                fragment.strategy_name,
                tx_result.failure_phase,
                tx_result.error,
            )
            result = StageResult(
                strategy_name=fragment.strategy_name,
                success=False,
                rollback_needed=classification.rollback_needed if classification else False,
                quarantine=classification.quarantine if classification else False,
                error=str(tx_result.error) if tx_result.error else tx_result.failure_phase,
                failure_phase=tx_result.failure_phase or "lowering",
            )
            result.metadata["gate_accounting"] = gate_accounting
            executor_logger.info("Gate accounting: %s", gate_accounting.summary())
            return result

        changes = tx_result.applied_count
        self._total_changes += changes

        post_cfg = self.translator.lift(self.mba)
        reachable_blocks = self._compute_reachability_from_cfg(post_cfg)
        qty = len(post_cfg.blocks)
        block_reachability = len(reachable_blocks) / qty if qty > 0 else 0.0

        handler_entry_serials: set[int] = set(fragment.metadata.get("handler_entry_serials", set()))
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

        adj = post_cfg.as_adjacency_dict()
        terminal_exits: set[int] = set(fragment.metadata.get("terminal_exit_blocks", set()))
        terminal_exits |= self._derive_terminal_targets(
            patch_plan_to_simulated_edits(patch_plan),
            terminal_exits,
        )
        dispatcher_serial: int = int(fragment.metadata.get("dispatcher_serial", -1))
        cycle_result = detect_terminal_cycles(
            adj, terminal_exits, handler_entry_serials, dispatcher_serial
        )
        if not cycle_result.passed:
            for cyc in cycle_result.cycles:
                executor_logger.warning(
                    "Terminal cycle: blk[%d] re-enters blk[%d] via %s",
                    cyc.terminal_block,
                    cyc.reentry_target,
                    cyc.path,
                )

        result = StageResult(
            strategy_name=fragment.strategy_name,
            edits_applied=changes,
            reachability_after=block_reachability,
            handler_reachability=handler_reachability,
            terminal_cycles=cycle_result.cycles,
        )
        if cycle_removed:
            result.metadata["cycle_filter"] = cycle_removed
        if backend_removed:
            result.metadata["backend_filter"] = backend_removed

        # --- Terminal return audit (diagnostic, never gates success) ---
        self._run_terminal_return_audit(fragment, pre_cfg, result)

        gate_ok = self.gate.check(result)
        gate_accounting = gate_accounting.add(GateDecision(
            gate_name="semantic_gate",
            verdict=GateVerdict.PASSED if gate_ok else GateVerdict.FAILED,
            reason=(
                f"reachability={result.reachability_after:.2f}, "
                f"handler_reachability={result.handler_reachability:.2f}, "
                f"conflicts={result.conflict_count_after}"
            ),
        ))

        if isinstance(self.gate, VerificationGate):
            flow_ok = self.gate.check_flow_graph(
                post_cfg,
                handler_entry_serials=handler_entry_serials,
                conflict_count_after=result.conflict_count_after,
            )
            gate_accounting = gate_accounting.add(GateDecision(
                gate_name="verification_flow_graph",
                verdict=GateVerdict.PASSED if flow_ok else GateVerdict.FAILED,
                reason=(
                    f"flow_graph reachability check "
                    f"({'passed' if flow_ok else 'failed'})"
                ),
            ))
            # Combine both results: both must pass (fixes overwrite bug)
            gate_ok = gate_ok and flow_ok

        result.metadata["gate_accounting"] = gate_accounting
        executor_logger.info("Gate accounting: %s", gate_accounting.summary())

        if not gate_ok:
            result.rollback_needed = True
            result.success = False
            result.error = "semantic gate failed"
            result.failure_phase = "semantic_gate"
            executor_logger.warning(
                "Stage %s failed semantic gate: terminal_cycles=%d, conflict_count=%d",
                fragment.strategy_name,
                len(result.terminal_cycles),
                result.conflict_count_after,
            )

        return result

    def _supports_live_mba(self) -> bool:
        return hasattr(self.mba, "get_mblock") and hasattr(self.mba, "qty")

    def _get_cfg_contract(self) -> IDACfgContract | None:
        if self.cfg_contract is not None:
            return self.cfg_contract
        if self._supports_live_mba():
            self.cfg_contract = IDACfgContract()
            return self.cfg_contract
        return None

    def _filter_backend_unsupported_modifications(
        self,
        pre_cfg: FlowGraph,
        modifications: list[GraphModification],
        patch_plan: PatchPlan,
        gate_accounting: GateAccounting | None = None,
    ) -> tuple[list[GraphModification], PatchPlan, int]:
        """Filter edge-split modifications that fail backend preconditions.

        Returns:
            Tuple of (filtered_modifications, recompiled_patch_plan, removed_count).
        """
        if not self._supports_live_mba():
            return modifications, patch_plan, 0
        trampoline_steps = tuple(
            step
            for step in patch_plan.concrete_operations
            if isinstance(step, PatchEdgeSplitTrampoline)
        )
        if not patch_plan.planner_modifications or not trampoline_steps:
            return modifications, patch_plan, 0

        from d810.hexrays.mutation import deferred_modifier

        modifier = deferred_modifier.DeferredGraphModifier(self.mba)
        rejected_edges: set[tuple[int, int, int, int]] = set()
        for step in trampoline_steps:
            if modifier._check_edge_split_trampoline_preconditions(
                source_block_serial=step.source_serial,
                via_pred=step.via_pred,
                old_target=step.old_target,
                new_target=step.new_target,
            ):
                continue
            rejected_edges.add(
                (step.source_serial, step.old_target, step.via_pred, step.new_target)
            )

        if not rejected_edges:
            return modifications, patch_plan, 0

        filtered_modifications: list[GraphModification] = []
        for mod in patch_plan.planner_modifications:
            if isinstance(mod, EdgeRedirectViaPredSplit) and (
                mod.src_block,
                mod.old_target,
                mod.via_pred,
                mod.new_target,
            ) in rejected_edges:
                continue
            filtered_modifications.append(mod)

        removed_count = len(rejected_edges)
        remaining_count = len(filtered_modifications)
        executor_logger.info(
            "executor filter: backend_removed=%d, remaining=%d",
            removed_count,
            remaining_count,
        )
        return filtered_modifications, compile_patch_plan(filtered_modifications, pre_cfg), removed_count

    @property
    def total_changes(self) -> int:
        return self._total_changes

    def _run_preflight(
        self,
        fragment: PlanFragment,
        pre_cfg: FlowGraph,
        modifications: list[GraphModification],
        patch_plan: PatchPlan,
    ) -> tuple[list[GraphModification], PatchPlan, StageResult | None, int]:
        """Run preflight checks and cycle filtering.

        Returns:
            4-tuple of (modifications, patch_plan, error_result_or_None,
            cycle_filter_removed_count).
        """
        simulated_edits = sorted(
            patch_plan_to_simulated_edits(patch_plan),
            key=_preflight_simulated_priority,
        )
        if not simulated_edits:
            return modifications, patch_plan, None, 0

        pre_adj = pre_cfg.as_adjacency_dict()
        structural = check_edge_split_structural_legality(pre_adj, simulated_edits)
        if not structural.passed:
            executor_logger.warning(
                "Preflight REJECT: structural legality failed: %s (%s)",
                structural.reason,
                structural.diagnostics,
            )
            return modifications, patch_plan, StageResult(
                strategy_name=fragment.strategy_name,
                success=False,
                error=f"structural preflight: {structural.reason}",
                failure_phase="preflight",
            ), 0

        sim_result = simulate_edits(pre_adj, simulated_edits)
        sim_adj = sim_result.adj

        kind_counts = Counter(e.kind for e in simulated_edits)
        kind_summary = ", ".join("%s=%d" % (k, v) for k, v in sorted(kind_counts.items()))
        executor_logger.info(
            "Preflight: %d edits (%s)",
            len(simulated_edits),
            kind_summary,
        )

        terminal_exits = set(fragment.metadata.get("terminal_exit_blocks", set()))
        handler_entries = set(fragment.metadata.get("handler_entry_serials", set()))
        dispatcher = int(fragment.metadata.get("dispatcher_serial", -1))

        forbidden_blocks = set(fragment.metadata.get("forbidden_blocks", set()))
        exit_blocks = set(fragment.metadata.get("exit_blocks", set()))

        terminal_targets = self._derive_terminal_targets(simulated_edits, terminal_exits)
        for target in sorted(terminal_targets):
            sink_result = prove_terminal_sink(target, sim_adj, exit_blocks, forbidden_blocks)
            if not sink_result.ok:
                executor_logger.warning(
                    "Preflight REJECT: terminal target %d failed sink proof: %s (witness=%s)",
                    target,
                    sink_result.reason,
                    sink_result.witness_path,
                )
                return modifications, patch_plan, StageResult(
                    strategy_name=fragment.strategy_name,
                    success=False,
                    error=f"semantic preflight: {sink_result.reason}",
                    failure_phase="preflight",
                ), 0

        filtered_modifications, cycle_removed = self._filter_cycle_modifications(
            fragment,
            pre_adj,
            terminal_exits,
            handler_entries,
            dispatcher,
            modifications,
        )
        if filtered_modifications is None:
            executor_logger.warning(
                "Preflight REJECT: terminal cycles persist after filtering"
            )
            return modifications, patch_plan, StageResult(
                strategy_name=fragment.strategy_name,
                success=False,
                error="semantic preflight: terminal cycles detected",
                failure_phase="preflight",
            ), cycle_removed
        if filtered_modifications != modifications:
            modifications = filtered_modifications
            patch_plan = compile_patch_plan(modifications, pre_cfg)
            simulated_edits = sorted(
                patch_plan_to_simulated_edits(patch_plan),
                key=_preflight_simulated_priority,
            )
            sim_result = simulate_edits(pre_adj, simulated_edits)
            sim_adj = sim_result.adj
            terminal_targets = self._derive_terminal_targets(simulated_edits, terminal_exits)

        preflight_cycle_seeds = set(terminal_exits)
        preflight_cycle_seeds |= terminal_targets
        preflight_cycle_seeds |= self._derive_terminal_clone_seeds(
            sim_result.clone_origins,
            terminal_exits,
        )
        cycle_result = detect_terminal_cycles(
            sim_adj,
            preflight_cycle_seeds,
            handler_entries,
            dispatcher,
        )
        if not cycle_result.passed:
            executor_logger.warning(
                "Preflight REJECT: terminal cycles detected (%d cycles)",
                len(cycle_result.cycles),
            )
            return modifications, patch_plan, StageResult(
                strategy_name=fragment.strategy_name,
                success=False,
                error="semantic preflight: terminal cycles detected",
                failure_phase="preflight",
            ), cycle_removed

        return modifications, patch_plan, None, cycle_removed

    def _filter_cycle_modifications(
        self,
        fragment: PlanFragment,
        pre_adj: dict[int, list[int]],
        terminal_exits: set[int],
        handler_entries: set[int],
        dispatcher: int,
        original_modifications: list[GraphModification],
        max_rounds: int = 3,
    ) -> tuple[list[GraphModification] | None, int]:
        """Port baseline cycle filtering using redirect-only modifications.

        Returns:
            Tuple of (filtered_modifications_or_None, removed_count).
            None means cycles persist after filtering and the stage should fail.
        """
        pre_header_serial = fragment.metadata.get("pre_header_serial")
        redirect_modifications: list[GraphModification] = []
        for mod in original_modifications:
            match mod:
                case RedirectGoto(from_serial=src) | RedirectBranch(from_serial=src):
                    if src == pre_header_serial:
                        continue
                    redirect_modifications.append(mod)
                case ConvertToGoto(block_serial=src):
                    if src == pre_header_serial:
                        continue
                    redirect_modifications.append(mod)
                case CreateConditionalRedirect(source_block=src):
                    if src == pre_header_serial:
                        continue
                    redirect_modifications.append(mod)
                case EdgeRedirectViaPredSplit(src_block=src):
                    if src == pre_header_serial:
                        continue
                    redirect_modifications.append(mod)

        if not redirect_modifications:
            return original_modifications, 0

        sorted_redirect_modifications = sorted(
            redirect_modifications,
            key=_preflight_priority,
        )
        redirect_simulated = graph_modifications_to_simulated_edits(
            sorted_redirect_modifications
        )
        if not redirect_simulated:
            return original_modifications, 0

        current_pairs = list(zip(sorted_redirect_modifications, redirect_simulated))
        terminal_redirects = [
            simulated
            for _, simulated in current_pairs
            if simulated.source in terminal_exits or simulated.via_pred in terminal_exits
        ]
        total_removed = 0

        for round_idx in range(max_rounds):
            current_edits = [simulated for _, simulated in current_pairs]
            sim_result = simulate_edits(pre_adj, current_edits)
            cycle_seeds = set(terminal_exits)
            for terminal_edit in terminal_redirects:
                if terminal_edit in current_edits:
                    cycle_seeds.add(terminal_edit.new_target)
            cycle_seeds |= sim_result.created_clones

            cycle_result = detect_terminal_cycles(
                sim_result.adj,
                cycle_seeds,
                handler_entries,
                dispatcher,
            )
            if cycle_result.passed:
                if total_removed == 0:
                    return original_modifications, 0

                kept_counts = Counter(mod for mod, _ in current_pairs)
                kept_redirect_modifications: list[GraphModification] = []
                for mod in redirect_modifications:
                    if kept_counts[mod] == 0:
                        continue
                    kept_redirect_modifications.append(mod)
                    kept_counts[mod] -= 1

                remaining_count = len(kept_redirect_modifications)
                executor_logger.info(
                    "executor filter: cycle_removed=%d, remaining=%d",
                    total_removed,
                    remaining_count,
                )
                final_kept_counts = Counter(kept_redirect_modifications)
                filtered_modifications: list[GraphModification] = []
                for mod in original_modifications:
                    if mod not in redirect_modifications:
                        filtered_modifications.append(mod)
                        continue
                    if final_kept_counts[mod] == 0:
                        continue
                    filtered_modifications.append(mod)
                    final_kept_counts[mod] -= 1

                return filtered_modifications, total_removed

            cycle_nodes: set[int] = set()
            for cyc in cycle_result.cycles:
                cycle_nodes.add(cyc.terminal_block)
                cycle_nodes.add(cyc.reentry_target)
                cycle_nodes.update(cyc.path)

            edits_to_remove: set[int] = set()
            for idx, (_, edit) in enumerate(current_pairs):
                if edit.kind != "edge_split_redirect":
                    continue
                if edit.new_target in cycle_nodes or edit.source in cycle_nodes:
                    edits_to_remove.add(idx)

            if not edits_to_remove:
                return None, total_removed

            total_removed += len(edits_to_remove)
            current_pairs = [
                pair for idx, pair in enumerate(current_pairs) if idx not in edits_to_remove
            ]
            executor_logger.info(
                "Preflight filter round %d: removed %d edits, %d remaining",
                round_idx + 1,
                len(edits_to_remove),
                len(current_pairs),
            )

        return None, total_removed

    def _derive_terminal_clone_seeds(
        self,
        clone_origins: dict[int, SimulatedEdit],
        terminal_exits: set[int],
    ) -> set[int]:
        seeds: set[int] = set()
        for clone_serial, edit in clone_origins.items():
            if edit.kind == "edge_split_redirect":
                if edit.source in terminal_exits or edit.via_pred in terminal_exits:
                    seeds.add(clone_serial)
            elif edit.kind == "create_conditional_redirect":
                if edit.source in terminal_exits:
                    seeds.add(clone_serial)
            elif edit.kind == "duplicate_block":
                if edit.source in terminal_exits or edit.via_pred in terminal_exits:
                    seeds.add(clone_serial)
        return seeds

    def _derive_terminal_targets(
        self,
        edits: list[SimulatedEdit],
        terminal_exits: set[int],
    ) -> set[int]:
        targets: set[int] = set()
        for edit in edits:
            if edit.kind in {"goto_redirect", "conditional_redirect", "convert_to_goto"}:
                if edit.source in terminal_exits:
                    targets.add(edit.new_target)
            elif edit.kind == "edge_split_redirect":
                if edit.source in terminal_exits or edit.via_pred in terminal_exits:
                    targets.add(edit.new_target)
            elif edit.kind == "create_conditional_redirect":
                if edit.source in terminal_exits:
                    targets.add(edit.new_target)
                    if edit.fallthrough_target is not None:
                        targets.add(edit.fallthrough_target)
            elif edit.kind == "duplicate_block":
                if edit.source in terminal_exits or edit.via_pred in terminal_exits:
                    if edit.duplicate_target is not None:
                        targets.add(edit.duplicate_target)
                    elif edit.source_successors:
                        targets.update(edit.source_successors)
                    if edit.fallthrough_target is not None:
                        targets.add(edit.fallthrough_target)
        return targets

    def _compute_reachability_from_cfg(self, cfg: FlowGraph) -> set[int]:
        """Return block serials reachable from entry in a FlowGraph snapshot."""
        if not cfg.blocks:
            return set()

        visited: set[int] = set()
        queue: list[int] = [cfg.entry_serial]

        while queue:
            serial = queue.pop()
            if serial in visited or serial not in cfg.blocks:
                continue
            visited.add(serial)
            queue.extend(cfg.successors(serial))
        return visited

    def _run_terminal_return_audit(
        self,
        fragment: PlanFragment,
        pre_cfg: FlowGraph,
        result: StageResult,
    ) -> None:
        """Run terminal return audit and optional proof as diagnostic metadata.

        This is purely diagnostic -- it never gates stage success. Errors are
        caught and logged at DEBUG level.

        Args:
            fragment: The plan fragment whose metadata contains handler_paths.
            pre_cfg: The pre-linearization FlowGraph snapshot.
            result: The StageResult to attach metadata to.
        """
        handler_paths = fragment.metadata.get("handler_paths", {})
        if not handler_paths:
            return

        terminal_handler_serials: set[int] = set()
        exit_map: dict[int, list[int | None]] = {}
        for handler_serial, paths in handler_paths.items():
            for path in paths:
                if path.final_state is None:
                    terminal_handler_serials.add(handler_serial)
                    exit_map.setdefault(handler_serial, []).append(
                        getattr(path, "exit_block", None)
                    )

        if not terminal_handler_serials:
            return

        try:
            audit = build_terminal_return_audit(
                cfg=pre_cfg,
                terminal_handler_serials=terminal_handler_serials,
                exit_map=exit_map,
                total_handlers=len(handler_paths),
            )
            result.metadata["terminal_return_audit"] = audit
            executor_logger.info("Terminal return audit: %s", audit.summary())
        except Exception:
            executor_logger.debug(
                "Terminal return audit failed", exc_info=True
            )
            return

        if not audit.sites:
            return

        try:
            proof = prove_terminal_returns(self.mba, audit)
            result.metadata["terminal_return_proof"] = proof
            executor_logger.info("Terminal return proof: %s", proof.summary())
        except Exception:
            executor_logger.debug(
                "Terminal return proof skipped (IDA not available or error)",
                exc_info=True,
            )
