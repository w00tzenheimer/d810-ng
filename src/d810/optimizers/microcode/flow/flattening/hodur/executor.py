"""Transactional executor for Hodur unflattening pipeline."""
from __future__ import annotations

from collections import Counter

from d810.core import logging

from d810.cfg.flow.edit_simulator import (
    SimulatedEdit,
    graph_modifications_to_simulated_edits,
    simulate_edits,
)
from d810.cfg.flow.graph_checks import (
    SemanticGate,
    check_edge_split_structural_legality,
    detect_terminal_cycles,
    prove_terminal_sink,
)
from d810.cfg.flowgraph import FlowGraph
from d810.cfg.graph_modification import (
    ConvertToGoto,
    CreateConditionalRedirect,
    EdgeRedirectViaPredSplit,
    GraphModification,
    RedirectBranch,
    RedirectGoto,
)
from d810.hexrays.mutation.ir_translator import IDAIRTranslator
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    PlanFragment,
    StageResult,
    VerificationGate,
)
from d810.optimizers.microcode.flow.flattening.safeguards import (
    should_apply_cfg_modifications,
)

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


class TransactionalExecutor:
    """Applies plan fragments through GraphModification lowering with gates."""

    def __init__(
        self,
        mba: object,
        gate: VerificationGate | SemanticGate | None = None,
        translator: IDAIRTranslator | None = None,
    ):
        self.mba = mba
        self.gate = gate or SemanticGate()
        self.translator = translator or IDAIRTranslator()
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

        pre_cfg = self.translator.lift(self.mba)
        num_modifications = len(modifications)
        if not should_apply_cfg_modifications(num_modifications, total_handlers, "hodur"):
            return StageResult(
                strategy_name=fragment.strategy_name,
                success=False,
                error="safeguard rejected modifications",
            )

        modifications, preflight_error = self._run_preflight(fragment, pre_cfg, modifications)
        if preflight_error is not None:
            return preflight_error
        if not modifications:
            return StageResult(strategy_name=fragment.strategy_name)

        changes = self.translator.lower(modifications, self.mba)
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
            graph_modifications_to_simulated_edits(modifications),
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

        gate_ok = self.gate.check(result)
        if isinstance(self.gate, VerificationGate):
            gate_ok = self.gate.check_flow_graph(
                post_cfg,
                handler_entry_serials=handler_entry_serials,
                conflict_count_after=result.conflict_count_after,
            )

        if not gate_ok:
            result.rollback_needed = True
            result.success = False
            result.error = "semantic gate failed"
            executor_logger.warning(
                "Stage %s failed semantic gate: terminal_cycles=%d, conflict_count=%d",
                fragment.strategy_name,
                len(result.terminal_cycles),
                result.conflict_count_after,
            )

        return result

    @property
    def total_changes(self) -> int:
        return self._total_changes

    def _run_preflight(
        self,
        fragment: PlanFragment,
        pre_cfg: FlowGraph,
        modifications: list[GraphModification],
    ) -> tuple[list[GraphModification], StageResult | None]:
        ordered_modifications = sorted(modifications, key=_preflight_priority)
        simulated_edits = graph_modifications_to_simulated_edits(ordered_modifications)
        if not simulated_edits:
            return modifications, None

        pre_adj = pre_cfg.as_adjacency_dict()
        structural = check_edge_split_structural_legality(pre_adj, simulated_edits)
        if not structural.passed:
            executor_logger.warning(
                "Preflight REJECT: structural legality failed: %s (%s)",
                structural.reason,
                structural.diagnostics,
            )
            return modifications, StageResult(
                strategy_name=fragment.strategy_name,
                success=False,
                error=f"structural preflight: {structural.reason}",
            )

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
                return modifications, StageResult(
                    strategy_name=fragment.strategy_name,
                    success=False,
                    error=f"semantic preflight: {sink_result.reason}",
                )

        filtered_modifications = self._filter_cycle_modifications(
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
            return modifications, StageResult(
                strategy_name=fragment.strategy_name,
                success=False,
                error="semantic preflight: terminal cycles detected",
            )
        if filtered_modifications != modifications:
            modifications = filtered_modifications
            ordered_modifications = sorted(modifications, key=_preflight_priority)
            simulated_edits = graph_modifications_to_simulated_edits(ordered_modifications)
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
            return modifications, StageResult(
                strategy_name=fragment.strategy_name,
                success=False,
                error="semantic preflight: terminal cycles detected",
            )

        return modifications, None

    def _filter_cycle_modifications(
        self,
        fragment: PlanFragment,
        pre_adj: dict[int, list[int]],
        terminal_exits: set[int],
        handler_entries: set[int],
        dispatcher: int,
        original_modifications: list[GraphModification],
        max_rounds: int = 3,
    ) -> list[GraphModification] | None:
        """Port baseline cycle filtering using redirect-only modifications."""
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
            return original_modifications

        sorted_redirect_modifications = sorted(
            redirect_modifications,
            key=_preflight_priority,
        )
        redirect_simulated = graph_modifications_to_simulated_edits(
            sorted_redirect_modifications
        )
        if not redirect_simulated:
            return original_modifications

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
                    return original_modifications

                kept_counts = Counter(mod for mod, _ in current_pairs)
                kept_redirect_modifications: list[GraphModification] = []
                for mod in redirect_modifications:
                    if kept_counts[mod] == 0:
                        continue
                    kept_redirect_modifications.append(mod)
                    kept_counts[mod] -= 1

                executor_logger.warning(
                    "Preflight: filtered %d/%d redirect modifications (removed %d cycle-causing edge-splits in %d rounds)",
                    len(kept_redirect_modifications),
                    len(redirect_modifications),
                    total_removed,
                    round_idx + 1,
                )
                return kept_redirect_modifications

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
                return None

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

        return None

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
