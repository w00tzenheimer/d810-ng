"""Transactional executor for the shared unflattening engine.

# EXECUTOR_BOUNDARY: The executor only enforces gates and updates lifecycle.
# It does NOT perform strategy selection, conflict resolution, pipeline
# reordering, or fragment insertion.  All such decisions are made upstream
# by the UnflatteningPlanner.
#
# The executor may SKIP a fragment only via:
#   - Safeguard gate failure (insufficient modifications for handler count)
#   - Backend precondition filter (individual edge-split failures)
#   - Preflight rejection (structural legality, terminal cycles, entry collapse)
#   - Transaction engine failure (lowering/apply errors)
#   - Semantic gate failure (reachability, handler reachability, conflicts)
#
# None of these constitute re-arbitration: they are runtime safety checks
# that the planner cannot predict at planning time (they depend on live
# MBA state and IDA backend preconditions).
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable

import ida_hexrays

from d810.backends.hexrays.mutation.backend import HexRaysMutationBackend
from d810.hexrays.contracts import IDACfgContract
from d810.passes.transaction_policy import classify_failure
from d810.ir.block_identity import (
    block_fingerprint,
    block_label,
    flow_graph_context_label,
)
from d810.transforms.edit_simulator import (
    SimulatedEdit,
    graph_modifications_to_simulated_edits,
    patch_plan_to_simulated_edits,
    simulate_edits,
)
from d810.analyses.control_flow.graph_checks import (
    SemanticGate,
    check_entry_reachability_counts_not_collapsed,
    check_entry_reachability_not_collapsed,
    check_terminal_reachability_preserved,
    check_edge_split_structural_legality,
    detect_terminal_cycles,
    prove_terminal_sink,
    reachable_from_adjacency,
)
from d810.ir.flowgraph import FlowGraph
from d810.ir.maturity import MaturityEnvelope
from d810.transforms.loop_bound_writer_guard import (
    detect_loop_counter_writeback_tail,
)
from d810.transforms.graph_modification import (
    CloneConditionalAsGoto,
    CloneConditionalAsGotoFromBranchArm,
    ConvertToGoto,
    CreateConditionalRedirect,
    DuplicateBlock,
    EdgeRedirectViaPredSplit,
    GraphModification,
    InsertBlock,
    RedirectBranch,
    RedirectGoto,
)
from d810.transforms.plan import (
    ExecutionPolicy,
    PatchPlan,
    compile_patch_plan,
)
from d810.core import logging
from d810.evaluator.hexrays_microcode.terminal_return_proof import (
    prove_terminal_returns,
)
from d810.hexrays.mutation.ir_translator import (
    IDAIRTranslator,
    classify_live_insn_kind,
    classify_live_operand_kind,
)
from d810.hexrays.mutation.semantic_ownership import (
    find_patch_plan_semantic_ownership_overlap,
    format_patch_plan_semantic_ownership_overlap,
)
from d810.analyses.control_flow.provenance import (
    GateAccounting,
    GateDecision,
    GateVerdict,
)
from d810.transforms.return_carrier_fact_guard import (
    filter_return_carrier_fact_redirects,
)
from d810.backends.hexrays.evidence.terminal_byte_emit_fact_guard import (
    filter_terminal_byte_emit_fact_redirects,
)
from d810.transforms.plan_fragment import (
    PlanFragment,
    StageResult,
    VerificationGate,
)
from d810.evaluator.hexrays_microcode.use_def_dominance import (
    check_redirect_severs_use_def,
)
from d810.analyses.control_flow.safeguards import (
    should_apply_bulk_cfg_modifications,
)
from d810.analyses.control_flow.terminal_return_audit import build_terminal_return_audit

executor_logger = logging.getLogger("d810.unflat.hodur.executor")

# ---------- MBA-to-BlockSnapshot helper (shared, IDA-dependent) ----------
# Phase 5 of the observability-boundary plan will move the serializer
# into `d810.hexrays.mba_serializer`. The facade (`mba_to_block_snapshots`
# from `d810.hexrays.observability`) keeps the call sites stable across
# that move.
from d810.hexrays.observability import mba_to_block_snapshots as _mba_to_block_snapshots


def _optional_int(value: object) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _max_optional_int(*values: int | None) -> int | None:
    present = [int(value) for value in values if value is not None]
    if not present:
        return None
    return max(present)


def _committed_semantic_ownership_gate(
    *,
    strategy_name: str,
    patch_plan: PatchPlan,
    mutation_gateway: object,
    gate_accounting: GateAccounting,
) -> tuple[StageResult | None, GateAccounting]:
    """Reject displaced cleanup before it opens a live CFG transaction."""
    authority = getattr(mutation_gateway, "lifecycle_authority", None)
    if authority is None:
        return None, gate_accounting
    publications = authority.committed_semantic_ownership()
    if not publications:
        return None, gate_accounting
    overlap = find_patch_plan_semantic_ownership_overlap(
        patch_plan,
        mutation_gateway.identity_index,
        publications,
    )
    if overlap is None:
        return (
            None,
            gate_accounting.add(
                GateDecision(
                    gate_name="committed_semantic_ownership",
                    verdict=GateVerdict.PASSED,
                    reason="ordinary PatchPlan is disjoint from committed ownership",
                )
            ),
        )
    reason = format_patch_plan_semantic_ownership_overlap(overlap)
    rejected = gate_accounting.add(
        GateDecision(
            gate_name="committed_semantic_ownership",
            verdict=GateVerdict.FAILED,
            reason=reason,
        )
    )
    result = StageResult(
        strategy_name=strategy_name,
        success=False,
        error=reason,
        failure_phase="semantic_preflight",
    )
    result.metadata["committed_semantic_ownership_overlap"] = {
        "plan_id": overlap.publication.plan_id,
        "atomic_group_id": overlap.publication.atomic_group_id,
        "operation_id": overlap.owner.operation_id,
        "source_block_id": overlap.owner.source_block_id,
        "anchor_ea": overlap.anchor_ea,
    }
    result.metadata["gate_accounting"] = rejected
    return result, rejected


def _reachable_count_from_block_snapshots(
    blocks: object,
    entry_serial: int,
) -> int:
    adj: dict[int, list[int]] = {}
    for block in blocks or ():
        try:
            serial = int(getattr(block, "serial"))
        except (TypeError, ValueError):
            continue
        succs = getattr(block, "succs", ()) or ()
        adj[serial] = [int(succ) for succ in succs]
    return len(reachable_from_adjacency(adj, int(entry_serial)))


def _preflight_priority(mod: GraphModification) -> int:
    """Mirror DeferredGraphModifier apply priority for topology simulation."""
    from d810.transforms.graph_modification import (
        CloneConditionalAsGoto,
        CloneConditionalAsGotoFromBranchArm,
        ConvertToGoto,
        CreateConditionalRedirect,
        EdgeRedirectViaPredSplit,
        InsertBlock,
        RedirectBranch,
        RedirectGoto,
    )

    match mod:
        case (
            InsertBlock()
            | CreateConditionalRedirect()
            | DuplicateBlock()
            | CloneConditionalAsGoto()
            | CloneConditionalAsGotoFromBranchArm()
        ):
            return 5
        case EdgeRedirectViaPredSplit(clone_until=clone_until):
            return 12 if clone_until is not None else 8
        case RedirectGoto() | RedirectBranch():
            return 10
        case ConvertToGoto():
            return 20
        case _:
            return 1000


def _preflight_simulated_priority(edit: SimulatedEdit) -> int:
    match edit.kind:
        case (
            "create_conditional_redirect"
            | "duplicate_block"
            | "clone_conditional_as_goto"
        ):
            return 5
        case "edge_split_redirect":
            return 12 if edit.clone_until is not None else 8
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
        mba: ida_hexrays.mba_t,
        gate: VerificationGate | SemanticGate | None = None,
        translator: IDAIRTranslator | None = None,
        cfg_contract: IDACfgContract | None = None,
        safeguard_profile: str = "engine",
    ):
        self.mba = mba
        self.gate = gate or SemanticGate()
        self.cfg_contract = cfg_contract
        self.safeguard_profile = str(safeguard_profile).strip() or "engine"
        self.translator = translator or IDAIRTranslator(
            contract=self.cfg_contract,
        )
        self._total_changes = 0
        self._mutation_gateway_factory: Callable[[], object | None] | None = None
        self.validated_fact_view: object | None = None
        self.dispatcher_serial: int = -1

    def set_analysis_snapshot(self, snapshot: object) -> None:
        """Attach per-round analysis context for fact-backed executor guards."""
        self.validated_fact_view = getattr(snapshot, "diagnostic_fact_view", None)
        try:
            self.dispatcher_serial = int(
                getattr(snapshot, "dispatcher_root_serial", -1)
            )
        except (TypeError, ValueError):
            self.dispatcher_serial = -1

    def set_mutation_gateway_factory(
        self,
        factory: Callable[[], object | None] | None,
    ) -> None:
        """Attach the coordinator-owned current-MBA gateway factory."""
        self._mutation_gateway_factory = factory

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
            safeguard_override = fragment.metadata.get("safeguard_min_required")
            if safeguard_override is not None:
                executor_logger.info(
                    "[safeguard] using stage override: min_required=%d (stage=%s)",
                    safeguard_override,
                    fragment.strategy_name,
                )
            safeguard_profile = fragment.metadata.get("safeguard_profile")
            if safeguard_profile is None:
                safeguard_profile = fragment.metadata.get("safeguard_context")
            safeguard_context = (
                str(safeguard_profile).strip()
                if safeguard_profile
                else self.safeguard_profile
            )
            safeguard_ok = should_apply_bulk_cfg_modifications(
                num_modifications,
                total_handlers,
                safeguard_context,
                min_required_override=safeguard_override,
            )
            if not safeguard_ok:
                gate_accounting = GateAccounting().add(
                    GateDecision(
                        gate_name="safeguard",
                        verdict=GateVerdict.FAILED,
                        reason=(
                            f"insufficient modifications ({num_modifications}) "
                            f"for {total_handlers} handlers"
                        ),
                    )
                )
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

    def execute_stage(
        self,
        fragment: PlanFragment,
        total_handlers: int,
    ) -> StageResult:
        """Execute one plan fragment through the shared mutation backend."""
        if fragment.is_empty():
            return StageResult(strategy_name=fragment.strategy_name)

        modifications = list(fragment.modifications)
        if not modifications:
            return StageResult(strategy_name=fragment.strategy_name)

        gate_accounting = GateAccounting()

        # Derive execution policy from fragment metadata — travels with the plan.
        raw_policy = fragment.metadata.get("execution_policy")
        if raw_policy == "nop_merge_blocks_relaxed":
            execution_policy = ExecutionPolicy.NOP_MERGE_BLOCKS_RELAXED
        elif raw_policy == "nop_cleanup_relaxed":
            execution_policy = ExecutionPolicy.NOP_CLEANUP_RELAXED
        else:
            execution_policy = ExecutionPolicy.STRICT

        pre_cfg = self.translator.lift(self.mba)
        live_mba_pre_reachable_count: int | None = None
        if fragment.strategy_name == "fake_jump":
            try:
                live_mba_pre_reachable_count = _reachable_count_from_block_snapshots(
                    _mba_to_block_snapshots(self.mba),
                    pre_cfg.entry_serial,
                )
            except Exception:
                executor_logger.debug(
                    "Failed to compute live MBA pre-reachability for fake_jump",
                    exc_info=True,
                )

        # Loop-counter writeback-tail guard.  Any RedirectGoto whose
        # ``old_target`` is the writeback-tail block of a loop-carried
        # counter must be rejected: the redirect would route the
        # predecessor away from the unique counter writeback site, IDA's
        # MMAT_GLBOPT1 DCE would drop the writeback (no live preds), and
        # the inner loop's induction never updates -- producing a
        # non-progressing do-while.  Detector is read-only and narrow
        # (four conjunctive conditions on the candidate tail block, see
        # ``loop_bound_writer_guard.detect_loop_counter_writeback_tail``).
        writeback_tail_blocks: set[int] = set()
        try:
            qty = int(getattr(self.mba, "qty", 0))
        except (AttributeError, TypeError, ValueError):
            qty = 0
        for _i in range(qty):
            _diag = detect_loop_counter_writeback_tail(
                pre_cfg,
                _i,
                insn_kind_classifier=classify_live_insn_kind,
                operand_kind_classifier=classify_live_operand_kind,
            )
            if _diag is not None:
                writeback_tail_blocks.add(int(_diag.tail_block_serial))
        if writeback_tail_blocks:
            _filtered_mods: list = []
            for _mod in modifications:
                if not isinstance(_mod, RedirectGoto):
                    _filtered_mods.append(_mod)
                    continue
                # Reject orphan-the-writeback shape: a predecessor's
                # edge into the tail is being routed elsewhere.  The
                # cumulative effect when all preds get this treatment
                # is an orphaned tail whose writeback IDA's DCE drops.
                if int(_mod.old_target) in writeback_tail_blocks:
                    executor_logger.info(
                        "REDIRECT_REJECTED_LOOP_COUNTER_WRITEBACK_TAIL "
                        "blk[%d] -> blk[%d] (was blk[%d]); "
                        "blk[%d] is a loop-counter writeback tail "
                        "(orphans the writeback)",
                        int(_mod.from_serial),
                        int(_mod.new_target),
                        int(_mod.old_target),
                        int(_mod.old_target),
                    )
                    continue
                # Reject back-edge-sever shape: the writeback tail's
                # own successor is being changed.  Empirically the
                # loop-carrier path runs body -> ... -> writeback_tail
                # -> dispatcher_root -> body; if the tail's exit is
                # rerouted to a non-cycle target, the structurer can
                # no longer construct the loop body around the tail
                # and folds the bound expression into the test,
                # producing a non-progressing inner do-while
                # (sub_7FFD postfix6: ``while ((v61 & 0x3E) != 2)``).
                if int(_mod.from_serial) in writeback_tail_blocks:
                    executor_logger.info(
                        "REDIRECT_REJECTED_LOOP_COUNTER_WRITEBACK_TAIL "
                        "blk[%d] -> blk[%d] (was blk[%d]); "
                        "blk[%d] is a loop-counter writeback tail "
                        "(severs back-edge after writeback)",
                        int(_mod.from_serial),
                        int(_mod.new_target),
                        int(_mod.old_target),
                        int(_mod.from_serial),
                    )
                    continue
                _filtered_mods.append(_mod)
            modifications = _filtered_mods
            if not modifications:
                return StageResult(
                    strategy_name=fragment.strategy_name,
                    success=False,
                    error="all modifications rejected by loop-writeback guard",
                    failure_phase="execution_filter",
                )

        stale_hazard_override_keys = frozenset(
            tuple(int(part) for part in key)
            for key in (
                fragment.metadata.get("return_carrier_stale_hazard_overrides", ()) or ()
            )
            if isinstance(key, (tuple, list)) and len(key) == 3
        )
        terminal_byte_emit_dag_frontier_overrides = frozenset(
            tuple(int(part) for part in key)
            for key in (
                fragment.metadata.get("terminal_byte_emit_dag_frontier_overrides", ())
                or ()
            )
            if isinstance(key, (tuple, list)) and len(key) == 3
        )

        modifications, return_carrier_rejections = filter_return_carrier_fact_redirects(
            modifications,
            mba=self.mba,
            fact_view=self.validated_fact_view,
            dispatcher_serial=self.dispatcher_serial,
            flow_graph=pre_cfg,
            stale_hazard_override_keys=stale_hazard_override_keys,
            reject_carrier_writer_bypass=(
                fragment.strategy_name == "dispatcher_loop_recovery"
            ),
            insn_kind_classifier=classify_live_insn_kind,
            operand_kind_classifier=classify_live_operand_kind,
        )
        if return_carrier_rejections:
            bypass_rejections = sum(
                1
                for rejection in return_carrier_rejections
                if getattr(rejection, "reason", "") == "carrier_writer_bypass"
            )
            gate_accounting = gate_accounting.add(
                GateDecision(
                    gate_name="return_carrier_fact_guard",
                    verdict=GateVerdict.PASSED,
                    reason=(
                        f"rejected {len(return_carrier_rejections)} redirect(s) "
                        f"({bypass_rejections} carrier-bypass) "
                        "that would violate return-carrier facts"
                    ),
                )
            )
        modifications, terminal_byte_emit_rejections = (
            filter_terminal_byte_emit_fact_redirects(
                modifications,
                mba=self.mba,
                fact_view=self.validated_fact_view,
                dispatcher_serial=self.dispatcher_serial,
                flow_graph=pre_cfg,
                dag_frontier_override_keys=(terminal_byte_emit_dag_frontier_overrides),
                insn_kind_classifier=classify_live_insn_kind,
                operand_kind_classifier=classify_live_operand_kind,
            )
        )
        if terminal_byte_emit_rejections:
            gate_accounting = gate_accounting.add(
                GateDecision(
                    gate_name="terminal_byte_emit_fact_guard",
                    verdict=GateVerdict.PASSED,
                    reason=(
                        f"rejected {len(terminal_byte_emit_rejections)} redirect(s) "
                        "that would inject state-flow predecessors into "
                        "terminal_tail byte-emit blocks"
                    ),
                )
            )
        if not modifications:
            result = StageResult(
                strategy_name=fragment.strategy_name,
                success=False,
                error="all modifications rejected by return-carrier fact guard",
                failure_phase="execution_filter",
            )
            result.metadata["return_carrier_fact_rejections"] = (
                return_carrier_rejections
            )
            result.metadata["terminal_byte_emit_fact_rejections"] = (
                terminal_byte_emit_rejections
            )
            result.metadata["gate_accounting"] = gate_accounting
            return result

        modifications, backend_removed = self._filter_backend_unsupported_modifications(
            modifications
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

        mutation_gateway = (
            None
            if self._mutation_gateway_factory is None
            else self._mutation_gateway_factory()
        )
        if mutation_gateway is None:
            result = StageResult(
                strategy_name=fragment.strategy_name,
                success=False,
                error="coordinator-owned mutation gateway unavailable",
                failure_phase="mutation_gateway",
            )
            result.metadata["gate_accounting"] = gate_accounting
            return result
        source_index = mutation_gateway.identity_index
        source_maturity = MaturityEnvelope(
            ir=None,
            provider="hexrays",
            provider_id=int(source_index.maturity),
        )

        modifications, patch_plan, preflight_error, cycle_removed = self._run_preflight(
            fragment,
            pre_cfg,
            modifications,
            execution_policy,
            snapshot_id=source_index.snapshot_id,
            source_maturity=source_maturity,
            source_generation=source_index.generation,
            block_refs_by_serial=source_index.plan_refs_by_serial(),
            live_mba_pre_reachable_count=live_mba_pre_reachable_count,
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

        if not isinstance(patch_plan, PatchPlan):
            raise TypeError("preflight must return one immutable PatchPlan")
        ownership_rejection, gate_accounting = _committed_semantic_ownership_gate(
            strategy_name=fragment.strategy_name,
            patch_plan=patch_plan,
            mutation_gateway=mutation_gateway,
            gate_accounting=gate_accounting,
        )
        if ownership_rejection is not None:
            executor_logger.info(
                "Stage %s rejected before transaction construction: %s",
                fragment.strategy_name,
                ownership_rejection.error,
            )
            return ownership_rejection

        executor_logger.info(
            "Stage %s compiled PatchPlan once: operations=%d symbolic_blocks=%d",
            fragment.strategy_name,
            len(patch_plan.concrete_operations),
            len(patch_plan.new_blocks),
        )

        # uee-b7ze Phase 1 observer-only: log use-def dominance severance
        # for every RedirectGoto that would orphan a stkvar use.  Logging
        # only — we do NOT drop or refuse modifications here.
        for _mod in modifications:
            if not isinstance(_mod, RedirectGoto):
                continue
            try:
                _violations = check_redirect_severs_use_def(_mod, self.mba, pre_cfg)
            except Exception:
                executor_logger.debug(
                    "USE_DEF_SEVERANCE: detector crashed for redirect blk[%d]->blk[%d]",
                    _mod.from_serial,
                    _mod.new_target,
                    exc_info=True,
                )
                continue
            if not _violations:
                continue
            _details = "; ".join(
                f"var_stk[{v.var_stkoff:#x}]@blk[{v.use_block}]" for v in _violations
            )
            executor_logger.warning(
                "USE_DEF_SEVERANCE: redirect blk[%d] -> blk[%d] would orphan %d use(s): %s",
                _mod.from_serial,
                _mod.new_target,
                len(_violations),
                _details,
            )

        # Route the finalized plan through the sole live transaction backend.
        contract = self._get_cfg_contract()
        self.translator.contract = (
            contract  # ensure translator has it for post-apply hook
        )
        backend = HexRaysMutationBackend(
            mutation_gateway=mutation_gateway,
            translator=self.translator,
        )
        tx_error: Exception | None = None
        try:
            post_cfg = backend.apply(patch_plan, self.mba)
        except Exception as error:
            tx_error = error
            post_cfg = pre_cfg
        execution = backend.last_patch_execution
        tx_success = execution is not None and tx_error is None
        tx_failure_phase = (
            None
            if tx_success
            else (
                getattr(self.translator, "last_lowering_phase", None)
                or (
                    "semantic_preflight"
                    if backend.last_patch_failure is not None
                    else "backend_apply"
                )
            )
        )
        tx_failure_detail = (
            None
            if tx_success
            else getattr(self.translator, "last_lowering_subphase", None)
        )
        tx_error = tx_error or backend.last_patch_failure
        tx_applied_count = 0 if execution is None else execution.applied_count

        gate_accounting = gate_accounting.add(
            GateDecision(
                gate_name="transaction_coordinator",
                verdict=GateVerdict.PASSED if tx_success else GateVerdict.FAILED,
                reason=(
                    f"applied={tx_applied_count}"
                    if tx_success
                    else (
                        f"rejected at {tx_failure_phase}"
                        + (f"/{tx_failure_detail}" if tx_failure_detail else "")
                        + f": {tx_error}"
                    )
                ),
            )
        )
        if not tx_success:
            classification = classify_failure(
                tx_failure_phase or "backend_apply",
                "" if tx_error is None else str(tx_error),
            )
            executor_logger.warning(
                "Transaction coordinator rejected stage %s at phase %s detail %s: %s",
                fragment.strategy_name,
                tx_failure_phase,
                tx_failure_detail,
                tx_error,
            )
            result = StageResult(
                strategy_name=fragment.strategy_name,
                success=False,
                rollback_needed=classification.rollback_needed,
                quarantine=classification.quarantine,
                error=str(tx_error) if tx_error else tx_failure_phase,
                failure_phase=tx_failure_phase or "lowering",
            )
            result.metadata["failure_detail"] = tx_failure_detail
            result.metadata["gate_accounting"] = gate_accounting
            executor_logger.info("Gate accounting: %s", gate_accounting.summary())
            return result

        changes = tx_applied_count
        self._total_changes += changes
        creation_receipts = execution.creation_receipts
        realized_serials = {
            receipt.plan_ref: int(receipt.returned_serial)
            for receipt in creation_receipts
        }
        self._log_new_block_origins(
            patch_plan, pre_cfg, post_cfg, realized_serials=realized_serials
        )

        # --- Diagnostic snapshot (gated behind D810_DIAG_SNAPSHOT=1) ---
        try:
            from d810.hexrays.observability import request_capture_mba_snapshot

            request_capture_mba_snapshot(
                blocks=_mba_to_block_snapshots(self.mba),
                label=f"{fragment.strategy_name}_post_apply",
                func_ea=self.mba.entry_ea,
                maturity="MMAT_GLBOPT1",
                phase="post_apply",
            )
        except Exception:
            executor_logger.debug(
                "Diagnostic snapshot failed (non-critical)",
                exc_info=True,
            )

        reachable_blocks = self._compute_reachability_from_cfg(post_cfg)
        qty = len(post_cfg.blocks)
        block_reachability = len(reachable_blocks) / qty if qty > 0 else 0.0

        handler_entry_serials: set[int] = set(
            fragment.metadata.get("handler_entry_serials", set())
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

        terminal_reachability = check_terminal_reachability_preserved(
            pre_cfg,
            post_cfg=post_cfg,
        )
        entry_reachability = None
        if fragment.strategy_name == "fake_jump":
            entry_reachability = check_entry_reachability_not_collapsed(
                pre_cfg,
                post_cfg=post_cfg,
            )
            planner_entry_count = _optional_int(
                fragment.metadata.get("planner_entry_reachable_count")
            )
            baseline_entry_count = _max_optional_int(
                planner_entry_count,
                live_mba_pre_reachable_count,
            )
            if baseline_entry_count is not None:
                entry_reachability = check_entry_reachability_counts_not_collapsed(
                    pre_reachable_count=baseline_entry_count,
                    post_reachable_count=entry_reachability.post_reachable_count,
                    min_retained_ratio=entry_reachability.min_retained_ratio,
                )
        if not terminal_reachability.passed:
            executor_logger.warning(
                "Stage %s orphaned terminal route(s): pre_terminals=%s "
                "post_terminals=%s pre_reachable=%d post_reachable=%d",
                fragment.strategy_name,
                sorted(terminal_reachability.pre_reachable_terminals),
                sorted(terminal_reachability.post_reachable_terminals),
                terminal_reachability.pre_reachable_count,
                terminal_reachability.post_reachable_count,
            )
        if entry_reachability is not None and not entry_reachability.passed:
            executor_logger.warning(
                "Stage fake_jump collapsed entry reachability: "
                "pre_reachable=%d post_reachable=%d retained=%.2f min=%.2f",
                entry_reachability.pre_reachable_count,
                entry_reachability.post_reachable_count,
                entry_reachability.retained_ratio,
                entry_reachability.min_retained_ratio,
            )

        adj = post_cfg.as_adjacency_dict()
        terminal_exits: set[int] = set(
            fragment.metadata.get("terminal_exit_blocks", set())
        )
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
        result.metadata["terminal_reachability"] = terminal_reachability
        result.metadata["_post_cfg"] = post_cfg
        if entry_reachability is not None:
            result.metadata["entry_reachability"] = entry_reachability

        # --- Terminal return audit (diagnostic, never gates success) ---
        self._run_terminal_return_audit(fragment, pre_cfg, result)

        gate_ok = self.gate.check(result)
        gate_accounting = gate_accounting.add(
            GateDecision(
                gate_name="semantic_gate",
                verdict=GateVerdict.PASSED if gate_ok else GateVerdict.FAILED,
                reason=(
                    f"reachability={result.reachability_after:.2f}, "
                    f"handler_reachability={result.handler_reachability:.2f}, "
                    f"conflicts={result.conflict_count_after}"
                ),
            )
        )
        gate_accounting = gate_accounting.add(
            GateDecision(
                gate_name="terminal_reachability",
                verdict=(
                    GateVerdict.PASSED
                    if terminal_reachability.passed
                    else GateVerdict.FAILED
                ),
                reason=(
                    "pre_terminals=%s post_terminals=%s"
                    % (
                        sorted(terminal_reachability.pre_reachable_terminals),
                        sorted(terminal_reachability.post_reachable_terminals),
                    )
                ),
            )
        )
        gate_ok = gate_ok and terminal_reachability.passed
        if entry_reachability is not None:
            gate_accounting = gate_accounting.add(
                GateDecision(
                    gate_name="fake_jump_entry_reachability",
                    verdict=(
                        GateVerdict.PASSED
                        if entry_reachability.passed
                        else GateVerdict.FAILED
                    ),
                    reason=(
                        "pre_reachable=%d post_reachable=%d retained=%.2f"
                        % (
                            entry_reachability.pre_reachable_count,
                            entry_reachability.post_reachable_count,
                            entry_reachability.retained_ratio,
                        )
                    ),
                )
            )
            gate_ok = gate_ok and entry_reachability.passed

        if isinstance(self.gate, VerificationGate):
            flow_ok = self.gate.check_flow_graph(
                post_cfg,
                handler_entry_serials=handler_entry_serials,
                conflict_count_after=result.conflict_count_after,
            )
            gate_accounting = gate_accounting.add(
                GateDecision(
                    gate_name="verification_flow_graph",
                    verdict=GateVerdict.PASSED if flow_ok else GateVerdict.FAILED,
                    reason=(
                        f"flow_graph reachability check "
                        f"({'passed' if flow_ok else 'failed'})"
                    ),
                )
            )
            # Combine both results: both must pass (fixes overwrite bug)
            gate_ok = gate_ok and flow_ok

        result.metadata["gate_accounting"] = gate_accounting
        executor_logger.info("Gate accounting: %s", gate_accounting.summary())

        if not gate_ok:
            result.rollback_needed = True
            result.success = False
            result.error = (
                "terminal reachability gate failed"
                if not terminal_reachability.passed
                else "fake_jump entry reachability gate failed"
                if entry_reachability is not None and not entry_reachability.passed
                else "semantic gate failed"
            )
            result.failure_phase = "semantic_gate"
            executor_logger.warning(
                "Stage %s failed semantic gate: terminal_cycles=%d, conflict_count=%d",
                fragment.strategy_name,
                len(result.terminal_cycles),
                result.conflict_count_after,
            )

        return result

    def _log_new_block_origins(
        self,
        patch_plan: PatchPlan,
        pre_cfg: FlowGraph,
        post_cfg: FlowGraph,
        *,
        realized_serials: dict[object, int],
    ) -> None:
        """Log concrete origin identity for all planner-created blocks."""
        if not patch_plan.new_blocks:
            return
        try:
            from d810.transforms.block_lineage import buffer_patch_plan_block_lineage

            buffer_patch_plan_block_lineage(
                patch_plan,
                pre_cfg,
                post_cfg,
                realized_serials=realized_serials,
            )
        except Exception:
            executor_logger.debug(
                "BLOCK_ORIGIN lineage buffering failed (non-critical)",
                exc_info=True,
            )
        try:
            from d810.core.observability_cfg import (
                observe_cfg_provenance as log_cfg_provenance,
            )
        except Exception:
            log_cfg_provenance = None

        for spec in patch_plan.new_blocks:
            assigned_serial = realized_serials.get(spec.block_id)
            if assigned_serial is None:
                continue
            origin_serial = spec.template_block
            if origin_serial is None and spec.incoming_edge is not None:
                incoming_source = spec.incoming_edge.source
                if isinstance(incoming_source, int):
                    origin_serial = incoming_source
            outgoing_targets = [
                edge.target
                for edge in spec.outgoing_edges
                if isinstance(edge.target, int)
            ]
            origin_label = (
                block_label(pre_cfg, origin_serial)
                if origin_serial is not None
                else "synthetic"
            )
            assigned_label = block_label(post_cfg, assigned_serial)
            extra = {
                "block_id": str(spec.block_id),
                "kind": str(spec.kind),
                "assigned_label": assigned_label,
                "origin_label": origin_label,
                "origin_fingerprint": (
                    block_fingerprint(pre_cfg, origin_serial)
                    if origin_serial is not None
                    else "fp=[]"
                ),
                "assigned_fingerprint": block_fingerprint(post_cfg, assigned_serial),
                "outgoing_targets": [
                    block_label(post_cfg, int(target)) for target in outgoing_targets
                ],
                "context": flow_graph_context_label(post_cfg),
            }
            executor_logger.info(
                "BLOCK_ORIGIN assigned=%s origin=%s clone_reason=%s %s "
                "assigned_%s origin_%s",
                assigned_label,
                origin_label,
                spec.kind,
                flow_graph_context_label(post_cfg),
                block_fingerprint(post_cfg, assigned_serial),
                (
                    block_fingerprint(pre_cfg, origin_serial)
                    if origin_serial is not None
                    else "fp=[]"
                ),
            )
            if log_cfg_provenance is None:
                continue
            try:
                log_cfg_provenance(
                    pass_name="transaction_executor",
                    action="CREATE",
                    block_serial=int(assigned_serial),
                    target_serial=(
                        int(origin_serial) if origin_serial is not None else None
                    ),
                    reason=f"patch_plan:{spec.kind}",
                    extra=extra,
                    mba=self.mba,
                )
            except Exception:
                executor_logger.debug(
                    "BLOCK_ORIGIN provenance logging failed for %s",
                    assigned_label,
                    exc_info=True,
                )

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
        modifications: list[GraphModification],
    ) -> tuple[list[GraphModification], int]:
        """Filter serial-local planner edits before their one-shot compilation."""
        if not self._supports_live_mba():
            return modifications, 0

        from d810.hexrays.mutation import deferred_modifier

        modifier = deferred_modifier.DeferredGraphModifier(self.mba)
        rejected_edges: set[tuple[int, int, int, int]] = set()
        for modification in modifications:
            if not isinstance(modification, EdgeRedirectViaPredSplit):
                continue
            if modification.clone_until is not None:
                continue
            try:
                preconditions_ok = modifier._check_edge_split_trampoline_preconditions(
                    source_block_serial=modification.src_block,
                    via_pred=modification.via_pred,
                    old_target=modification.old_target,
                    new_target=modification.new_target,
                    validate_new_target=False,
                )
            except RuntimeError as exc:
                executor_logger.warning(
                    "executor filter: edge-split live precondition probe failed "
                    "src=%s pred=%s old=%s new=%s: %s",
                    modification.src_block,
                    modification.via_pred,
                    modification.old_target,
                    modification.new_target,
                    exc,
                )
                preconditions_ok = False
            if preconditions_ok:
                continue
            rejected_edges.add(
                (
                    int(modification.src_block),
                    int(modification.old_target),
                    int(modification.via_pred),
                    int(modification.new_target),
                )
            )

        if not rejected_edges:
            return modifications, 0

        def _depends_on_rejected_edge_split(mod: GraphModification) -> bool:
            if isinstance(mod, EdgeRedirectViaPredSplit):
                return any(
                    int(mod.src_block) == source_serial
                    and int(mod.old_target) == old_target
                    and int(mod.via_pred) == via_pred
                    and int(mod.new_target) == new_target
                    for (
                        source_serial,
                        old_target,
                        via_pred,
                        new_target,
                    ) in rejected_edges
                )
            if isinstance(mod, InsertBlock) and mod.old_target_serial is not None:
                return any(
                    int(mod.old_target_serial) == source_serial
                    and int(mod.succ_serial) == new_target
                    for (
                        source_serial,
                        _old_target,
                        _via_pred,
                        new_target,
                    ) in rejected_edges
                )
            return False

        filtered_modifications: list[GraphModification] = []
        for mod in modifications:
            if _depends_on_rejected_edge_split(mod):
                continue
            filtered_modifications.append(mod)

        edge_split_removed_count = len(modifications) - len(filtered_modifications)
        remaining_count = len(filtered_modifications)
        executor_logger.info(
            "executor filter: backend_removed=%d, remaining=%d",
            edge_split_removed_count,
            remaining_count,
        )
        return filtered_modifications, edge_split_removed_count

    @property
    def total_changes(self) -> int:
        return self._total_changes

    def _run_preflight(
        self,
        fragment: PlanFragment,
        pre_cfg: FlowGraph,
        modifications: list[GraphModification],
        execution_policy: ExecutionPolicy,
        *,
        snapshot_id: str,
        source_maturity: MaturityEnvelope,
        source_generation: int,
        block_refs_by_serial,
        live_mba_pre_reachable_count: int | None = None,
    ) -> tuple[list[GraphModification], PatchPlan | None, StageResult | None, int]:
        """Run preflight checks and cycle filtering.

        Returns:
            4-tuple of (modifications, patch_plan, error_result_or_None,
            cycle_filter_removed_count).
        """
        simulated_edits = sorted(
            graph_modifications_to_simulated_edits(modifications),
            key=_preflight_simulated_priority,
        )
        if not simulated_edits:
            return (
                modifications,
                compile_patch_plan(
                    modifications,
                    pre_cfg,
                    execution_policy,
                    snapshot_id=snapshot_id,
                    source_maturity=source_maturity,
                    source_generation=source_generation,
                    block_refs_by_serial=block_refs_by_serial,
                ),
                None,
                0,
            )

        pre_adj = pre_cfg.as_adjacency_dict()
        structural = check_edge_split_structural_legality(pre_adj, simulated_edits)
        if not structural.passed:
            executor_logger.warning(
                "Preflight REJECT: structural legality failed: %s (%s)",
                structural.reason,
                structural.diagnostics,
            )
            return (
                modifications,
                None,
                StageResult(
                    strategy_name=fragment.strategy_name,
                    success=False,
                    error=f"structural preflight: {structural.reason}",
                    failure_phase="preflight",
                ),
                0,
            )

        sim_result = simulate_edits(pre_adj, simulated_edits)
        sim_adj = sim_result.adj

        kind_counts = Counter(e.kind for e in simulated_edits)
        kind_summary = ", ".join(
            "%s=%d" % (k, v) for k, v in sorted(kind_counts.items())
        )
        executor_logger.info(
            "Preflight: %d edits (%s)",
            len(simulated_edits),
            kind_summary,
        )
        terminal_reachability = check_terminal_reachability_preserved(
            pre_cfg,
            post_adj=sim_adj,
        )
        if not terminal_reachability.passed:
            executor_logger.warning(
                "Preflight REJECT: terminal route reachability regressed: "
                "pre_terminals=%s post_terminals=%s pre_reachable=%d "
                "post_reachable=%d",
                sorted(terminal_reachability.pre_reachable_terminals),
                sorted(terminal_reachability.post_reachable_terminals),
                terminal_reachability.pre_reachable_count,
                terminal_reachability.post_reachable_count,
            )
            result = StageResult(
                strategy_name=fragment.strategy_name,
                success=False,
                error=f"semantic preflight: {terminal_reachability.reason}",
                failure_phase="preflight",
            )
            result.metadata["terminal_reachability"] = terminal_reachability
            return modifications, None, result, 0

        if fragment.strategy_name == "fake_jump":
            entry_reachability = check_entry_reachability_not_collapsed(
                pre_cfg,
                post_adj=sim_adj,
            )
            planner_entry_count = _optional_int(
                fragment.metadata.get("planner_entry_reachable_count")
            )
            baseline_entry_count = _max_optional_int(
                planner_entry_count,
                live_mba_pre_reachable_count,
            )
            if baseline_entry_count is not None:
                planner_entry_serial = _optional_int(
                    fragment.metadata.get("planner_entry_serial")
                )
                if planner_entry_serial is None:
                    planner_entry_serial = pre_cfg.entry_serial
                post_reachable_count = len(
                    reachable_from_adjacency(sim_adj, planner_entry_serial)
                )
                entry_reachability = check_entry_reachability_counts_not_collapsed(
                    pre_reachable_count=baseline_entry_count,
                    post_reachable_count=post_reachable_count,
                    min_retained_ratio=entry_reachability.min_retained_ratio,
                )
            executor_logger.info(
                "Preflight fake_jump entry reachability: planner_pre=%s "
                "live_mba_pre=%s post=%d retained=%.2f",
                planner_entry_count,
                live_mba_pre_reachable_count,
                entry_reachability.post_reachable_count,
                entry_reachability.retained_ratio,
            )
            if not entry_reachability.passed:
                executor_logger.warning(
                    "Preflight REJECT: fake_jump would collapse entry reachability: "
                    "pre_reachable=%d post_reachable=%d retained=%.2f min=%.2f",
                    entry_reachability.pre_reachable_count,
                    entry_reachability.post_reachable_count,
                    entry_reachability.retained_ratio,
                    entry_reachability.min_retained_ratio,
                )
                result = StageResult(
                    strategy_name=fragment.strategy_name,
                    success=False,
                    error="semantic preflight: fake_jump entry reachability collapse",
                    failure_phase="preflight",
                )
                result.metadata["entry_reachability"] = entry_reachability
                return modifications, None, result, 0

        terminal_exits = set(fragment.metadata.get("terminal_exit_blocks", set()))
        handler_entries = set(fragment.metadata.get("handler_entry_serials", set()))
        dispatcher = int(fragment.metadata.get("dispatcher_serial", -1))

        forbidden_blocks = set(fragment.metadata.get("forbidden_blocks", set()))
        exit_blocks = set(fragment.metadata.get("exit_blocks", set()))

        terminal_targets = self._derive_terminal_targets(
            simulated_edits, terminal_exits
        )
        for target in sorted(terminal_targets):
            sink_result = prove_terminal_sink(
                target, sim_adj, exit_blocks, forbidden_blocks
            )
            if not sink_result.ok:
                executor_logger.warning(
                    "Preflight REJECT: terminal target %d failed sink proof: %s (witness=%s)",
                    target,
                    sink_result.reason,
                    sink_result.witness_path,
                )
                return (
                    modifications,
                    None,
                    StageResult(
                        strategy_name=fragment.strategy_name,
                        success=False,
                        error=f"semantic preflight: {sink_result.reason}",
                        failure_phase="preflight",
                    ),
                    0,
                )

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
            return (
                modifications,
                None,
                StageResult(
                    strategy_name=fragment.strategy_name,
                    success=False,
                    error="semantic preflight: terminal cycles detected",
                    failure_phase="preflight",
                ),
                cycle_removed,
            )
        modifications = filtered_modifications
        patch_plan = compile_patch_plan(
            modifications,
            pre_cfg,
            execution_policy,
            snapshot_id=snapshot_id,
            source_maturity=source_maturity,
            source_generation=source_generation,
            block_refs_by_serial=block_refs_by_serial,
        )
        # The converter returns the exact stable priority/source order used by
        # DeferredGraphModifier, including source-descending conditional
        # lowerings whose helper insertions shift later live serials.
        simulated_edits = patch_plan_to_simulated_edits(patch_plan)
        sim_result = simulate_edits(pre_adj, simulated_edits)
        sim_adj = sim_result.adj
        terminal_targets = self._derive_terminal_targets(
            simulated_edits, terminal_exits
        )

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
            return (
                modifications,
                patch_plan,
                StageResult(
                    strategy_name=fragment.strategy_name,
                    success=False,
                    error="semantic preflight: terminal cycles detected",
                    failure_phase="preflight",
                ),
                cycle_removed,
            )

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
                case (
                    CloneConditionalAsGoto(source_block=src)
                    | CloneConditionalAsGotoFromBranchArm(source_block=src)
                ):
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
            if simulated.source in terminal_exits
            or simulated.via_pred in terminal_exits
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
                if edit.kind not in {
                    "edge_split_redirect",
                    "clone_conditional_as_goto",
                }:
                    continue
                if edit.new_target in cycle_nodes or edit.source in cycle_nodes:
                    edits_to_remove.add(idx)

            if not edits_to_remove:
                return None, total_removed

            total_removed += len(edits_to_remove)
            current_pairs = [
                pair
                for idx, pair in enumerate(current_pairs)
                if idx not in edits_to_remove
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
            if edit.kind in {"edge_split_redirect", "clone_conditional_as_goto"}:
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
            if edit.kind in {
                "goto_redirect",
                "conditional_redirect",
                "convert_to_goto",
            }:
                if edit.source in terminal_exits:
                    targets.add(edit.new_target)
            elif edit.kind in {"edge_split_redirect", "clone_conditional_as_goto"}:
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
            executor_logger.debug("Terminal return audit failed", exc_info=True)
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
