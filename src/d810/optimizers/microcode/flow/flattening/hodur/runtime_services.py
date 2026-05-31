"""Hodur services for the generic state-machine family runtime."""
from __future__ import annotations

from d810.capabilities.providers import get_microcode_evidence
from d810.core import logging
from d810.hexrays.utils.hexrays_formatters import maturity_to_string
from d810.optimizers.microcode.flow.flattening.engine.provenance import (
    PlannerInputs,
)
from d810.optimizers.microcode.flow.flattening.engine.runtime import (
    ExecutorPolicy,
    ExecutedPipeline,
    FamilyAnalysis,
    FamilyContext,
    FamilyPassResult,
    FamilyRuntimePolicy,
    PlannedPipeline,
    execute_family_pipeline,
    make_transactional_executor_factory,
    plan_family_pipeline,
    run_ordered_family_hooks,
)
from d810.optimizers.microcode.flow.flattening.hodur.audit_runtime import (
    persist_terminal_return_audit,
    prepare_return_frontier_audit,
    record_return_frontier_stage,
)
from d810.optimizers.microcode.flow.flattening.hodur.post_apply_runtime import (
    collect_live_residual_dispatcher_preds,
)
from d810.optimizers.microcode.flow.flattening.hodur.post_pipeline_hooks import (
    HodurPostPipelineHooks,
)
from d810.optimizers.microcode.flow.flattening.hodur.recon_artifacts import (
    load_return_frontier_audit_from_store,
    load_terminal_return_audit_from_store,
    load_transition_report_from_store,
)
from d810.analyses.value_flow.model import FactConsumerRecord, FactStatus

unflat_logger = logging.getLogger("D810.unflat.hodur", logging.DEBUG)


class HodurRuntimeServices:
    """Profile runtime policy and lifecycle callbacks for Hodur."""

    def __init__(self, owner) -> None:
        self.owner = owner

    def runtime_policy(self, profile: object) -> FamilyRuntimePolicy:
        owner = self.owner
        return FamilyRuntimePolicy(
            planner=owner._planner,
            executor_policy=ExecutorPolicy(
                safeguard_profile=profile.executor_safeguard_profile,
                gate=owner._gate,
                allow_legacy_block_creation=owner.allow_legacy_block_creation,
            ),
            build_planner_inputs=self.build_planner_inputs,
            select_strategies=self.select_strategies,
            plan_pipeline=plan_family_pipeline,
            execute_pipeline=execute_family_pipeline,
            executor_factory_builder=make_transactional_executor_factory,
            on_analysis=self.on_analysis,
            on_planned=self.on_planned,
            on_executed=self.on_executed,
        )

    def run_post_pipeline(
        self,
        _profile: object,
        family_result: FamilyPassResult,
    ) -> int:
        return HodurPostPipelineHooks(
            self.owner,
            hook_runner=run_ordered_family_hooks,
        ).run(family_result)

    def clear_cached_dispatcher_context(self) -> None:
        """Drop stale dispatcher/BST context when the current pass has none."""
        owner = self.owner
        owner._last_bst_serials = None
        owner._last_dispatcher_serial = -1
        owner._last_func_ea = 0
        owner._last_bst_block_eas = set()
        owner._last_dispatcher_ea = 0

    def return_frontier_audit_enabled(self, hook_name: str) -> bool:
        """Return whether a named return-frontier audit hook is active."""
        owner = self.owner
        return (
            owner.RETURN_FRONTIER_AUDIT_ENABLED
            and owner._profile.enables_audit_hook(hook_name)
        )

    def terminal_return_persistence_enabled(self) -> bool:
        """Return whether terminal-return executor audit persistence is active."""
        return self.owner._profile.enables_audit_hook("terminal_return_persistence")

    def on_analysis(
        self,
        _context: FamilyContext,
        analysis: FamilyAnalysis,
    ) -> None:
        """Handle Hodur-specific analysis observation after snapshot build."""
        owner = self.owner
        snapshot = analysis.snapshot
        if snapshot.state_machine is None:
            unflat_logger.info(
                "No Hodur state machine detected; evaluating cleanup-only strategies"
            )
            self.clear_cached_dispatcher_context()
            owner._audit_return_sites = ()
        else:
            owner._log_state_machine()
        self.observe_induction_fact_view(snapshot)

    def build_planner_inputs(
        self,
        context: FamilyContext,
        analysis: FamilyAnalysis,
    ) -> PlannerInputs:
        """Load Hodur recon artifacts consumed by the shared planner."""
        snapshot = analysis.snapshot
        if snapshot.state_machine is None:
            transition_report = None
            return_frontier_audit = None
            terminal_return_audit = None
        else:
            transition_report = load_transition_report_from_store(
                func_ea=get_microcode_evidence().get_function_entry_ea(context.mba),
                maturity=context.maturity,
                log_dir=context.log_dir,
            )
            return_frontier_audit = load_return_frontier_audit_from_store(
                func_ea=get_microcode_evidence().get_function_entry_ea(context.mba),
                maturity=context.maturity,
                log_dir=context.log_dir,
            )
            terminal_return_audit = load_terminal_return_audit_from_store(
                func_ea=get_microcode_evidence().get_function_entry_ea(context.mba),
                maturity=context.maturity,
                log_dir=context.log_dir,
            )
        return PlannerInputs(
            total_handlers=snapshot.handler_count,
            handler_transitions=transition_report,
            return_frontier=return_frontier_audit,
            terminal_return_audit=terminal_return_audit,
        )

    def select_strategies(
        self,
        context: FamilyContext,
        _analysis: FamilyAnalysis,
    ) -> list:
        """Select the active Hodur strategy set for this runtime pass."""
        return self.owner._family.strategies_for_maturity(context.maturity)

    def on_planned(
        self,
        context: FamilyContext,
        analysis: FamilyAnalysis,
        planned: PlannedPipeline,
    ) -> None:
        """Run Hodur pre/post-plan audit hooks around generic planning."""
        owner = self.owner
        snapshot = analysis.snapshot
        owner._last_provenance = planned.provenance

        if (
            self.return_frontier_audit_enabled("return_frontier_pre_plan")
            and snapshot.state_machine is not None
        ):
            handler_paths = owner._extract_handler_paths_from_fragments(
                planned.pipeline
            )
            try:
                owner._audit_return_sites = prepare_return_frontier_audit(
                    snapshot,
                    current_return_sites=tuple(owner._audit_return_sites),
                    return_site_provider=owner._return_site_provider,
                    func_ea=get_microcode_evidence().get_function_entry_ea(context.mba),
                    maturity=context.maturity,
                    log_dir=context.log_dir,
                    successors=owner._build_successor_map(),
                    exits=owner._find_exit_blocks(),
                    handler_paths=handler_paths,
                    state_var_stkoff=owner._family.get_effective_state_var_stkoff(
                        snapshot.state_machine
                    ),
                    logger=unflat_logger,
                )
            except Exception:
                unflat_logger.debug("_audit_pre_plan failed (non-critical), continuing")

        if not planned.pipeline:
            unflat_logger.info(
                "No strategy produced a plan fragment; continuing in recon-only diagnostic mode"
            )
            return

        unflat_logger.info("Planner provenance: %s", planned.provenance.summary())

        if (
            self.return_frontier_audit_enabled("return_frontier_post_plan")
            and snapshot.state_machine is not None
            and owner._audit_return_sites
        ):
            try:
                record_return_frontier_stage(
                    return_sites=tuple(owner._audit_return_sites),
                    stage_name="post_plan",
                    func_ea=get_microcode_evidence().get_function_entry_ea(context.mba),
                    maturity=context.maturity,
                    log_dir=context.log_dir,
                    successors=owner._build_successor_map(),
                    exits=owner._find_exit_blocks(),
                    logger=unflat_logger,
                )
            except Exception:
                unflat_logger.debug(
                    "_record_audit_stage(post_plan) failed (non-critical)"
                )

    def on_executed(
        self,
        context: FamilyContext,
        analysis: FamilyAnalysis,
        _planned: PlannedPipeline,
        executed: ExecutedPipeline,
    ) -> None:
        """Record Hodur execution outcomes after the generic runtime executes."""
        owner = self.owner
        snapshot = analysis.snapshot
        pipeline = executed.pipeline
        results = executed.results
        nb_changes = executed.total_changes
        owner._last_provenance = executed.provenance

        live_residual_dispatcher_preds_by_strategy: dict[str, tuple[int, ...]] = {}
        successful_fragments = [
            fragment
            for fragment, result in zip(pipeline, results)
            if result.success and result.edits_applied > 0
        ]
        for fragment in successful_fragments:
            strategy_name = fragment.strategy_name
            group_name = fragment.metadata.get("post_apply_bst_cleanup_group")
            if (
                strategy_name
                not in {"linearized_flow_graph", "exact_node_frontier_bypass"}
                and not isinstance(group_name, str)
            ):
                continue
            residual_preds = collect_live_residual_dispatcher_preds(
                context.mba,
                snapshot,
                strategies=owner._family.strategies,
                strategy_name=strategy_name,
                cfg_translator=owner._family.cfg_translator,
                logger=unflat_logger,
            )
            live_residual_dispatcher_preds_by_strategy[strategy_name] = residual_preds
            if isinstance(group_name, str):
                live_residual_dispatcher_preds_by_strategy[f"group:{group_name}"] = (
                    residual_preds
                )
        owner._last_live_residual_dispatcher_preds_by_strategy = (
            live_residual_dispatcher_preds_by_strategy
        )

        owner._family.record_execution_outcome(
            pipeline,
            results,
            func_ea=get_microcode_evidence().get_function_entry_ea(context.mba),
            maturity=context.maturity,
            nb_changes=nb_changes,
            residual_dispatcher_preds_by_strategy=(
                live_residual_dispatcher_preds_by_strategy
            ),
        )

        if self.terminal_return_persistence_enabled():
            persist_terminal_return_audit(
                results,
                func_ea=get_microcode_evidence().get_function_entry_ea(context.mba),
                maturity=context.maturity,
                log_dir=context.log_dir,
            )

        if (
            self.return_frontier_audit_enabled("return_frontier_post_apply")
            and snapshot.state_machine is not None
            and owner._audit_return_sites
        ):
            try:
                record_return_frontier_stage(
                    return_sites=tuple(owner._audit_return_sites),
                    stage_name="post_apply",
                    func_ea=get_microcode_evidence().get_function_entry_ea(context.mba),
                    maturity=context.maturity,
                    log_dir=context.log_dir,
                    successors=owner._build_successor_map(),
                    exits=owner._find_exit_blocks(),
                    logger=unflat_logger,
                )
            except Exception:
                unflat_logger.debug(
                    "_record_audit_stage(post_apply) failed (non-critical)"
                )

    def observe_induction_fact_view(self, snapshot) -> None:
        """Record Hodur's read-only view of induction-carrier facts."""
        owner = self.owner
        if owner.flow_context is None:
            return
        func_ea = int(getattr(owner.mba, "entry_ea", 0) or 0)
        maturity = int(owner.cur_maturity)
        key = (func_ea, maturity, id(owner.mba))
        if key in owner._fact_view_observed_keys:
            return
        owner._fact_view_observed_keys.add(key)

        try:
            view = owner.flow_context.validated_fact_view(maturity)
        except Exception:
            unflat_logger.exception(
                "HODUR_FACT_VIEW_FAILED func=0x%x maturity=%s reason=view-error",
                func_ea,
                maturity_to_string(maturity),
            )
            return
        if view is None:
            return

        induction_observations = tuple(
            observation
            for observation in view.observations
            if observation.kind == "InductionCarrierFact"
        )
        if not induction_observations:
            unflat_logger.info(
                "HODUR_FACT_VIEW func=0x%x maturity=%s induction_total=0 "
                "active=0 stale=0 lost=0 persisted=0",
                func_ea,
                view.maturity,
            )
            return

        active_ids = {
            observation.fact_id
            for observation in view.active_observations
            if observation.kind == "InductionCarrierFact"
        }
        stale_statuses = {
            FactStatus.STALE,
            FactStatus.CONTRADICTED,
            FactStatus.SUPERSEDED,
            FactStatus.IDENTITY_LOST,
        }
        status_by_fact: dict[str, list[str]] = {}
        for mapping in view.mappings:
            if mapping.source_fact_id not in {obs.fact_id for obs in induction_observations}:
                continue
            status_by_fact.setdefault(mapping.source_fact_id, []).append(
                mapping.status.value
            )

        records: list[FactConsumerRecord] = []
        lost_count = 0
        stale_count = 0
        for observation in induction_observations:
            statuses = tuple(status_by_fact.get(observation.fact_id, ()))
            is_active = observation.fact_id in active_ids
            if not is_active:
                stale_count += 1
            if FactStatus.IDENTITY_LOST.value in statuses:
                lost_count += 1
            decision = "active" if is_active else "stale"
            reason = (
                "active induction fact visible to Hodur"
                if is_active
                else "induction fact inactive in Hodur view"
            )
            records.append(
                FactConsumerRecord(
                    consumer="hodur.unflattener",
                    strategy="HodurUnflattener",
                    fact_id=observation.fact_id,
                    maturity=view.maturity,
                    decision=decision,
                    reason=reason,
                    payload={
                        "semantic_key": observation.semantic_key,
                        "source_block": observation.source_block,
                        "source_ea": observation.source_ea,
                        "mop_signature": observation.mop_signature,
                        "confidence": observation.confidence,
                        "statuses": list(statuses),
                        "has_stale_mapping": any(
                            FactStatus(status) in stale_statuses for status in statuses
                        ),
                        "handler_count": snapshot.handler_count,
                        "pass_index": owner._actual_pass_count,
                        "generation": int(getattr(owner, "current_generation", 0)),
                    },
                )
            )

        persisted = 0
        try:
            persisted = owner.flow_context.report_fact_consumers(tuple(records))
        except Exception:
            unflat_logger.exception(
                "HODUR_FACT_VIEW_FAILED func=0x%x maturity=%s reason=persist-error",
                func_ea,
                view.maturity,
            )
        unflat_logger.info(
            "HODUR_FACT_VIEW func=0x%x maturity=%s induction_total=%d "
            "active=%d stale=%d lost=%d persisted=%d fact_ids=%s",
            func_ea,
            view.maturity,
            len(induction_observations),
            len(active_ids),
            stale_count,
            lost_count,
            persisted,
            [observation.fact_id for observation in induction_observations],
        )
