"""Hodur family adapter over the shared unflattening engine surface."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import ida_hexrays

from d810.cfg.flow.return_frontier import ReturnSite
from d810.cfg.flowgraph import FlowGraph
from d810.core import logging
from d810.hexrays.mutation.ir_translator import IDAIRTranslator
from d810.optimizers.microcode.flow.flattening.engine.family import (
    CFFStrategyFamily,
)
from d810.optimizers.microcode.flow.flattening.hodur.recon_artifacts import (
    load_return_frontier_audit_from_store,
    load_transition_report_from_store,
    record_return_frontier_stage,
    save_terminal_return_audit_to_store,
    save_transition_report_to_store,
    write_return_frontier_artifact_from_store,
)
from d810.optimizers.microcode.flow.flattening.hodur.analysis import (
    MAX_STATE_CONSTANTS_HODUR,
    MIN_STATE_CONSTANT,
    MIN_STATE_CONSTANTS,
    HodurStateMachineDetector,
)
from d810.optimizers.microcode.flow.flattening.hodur.datamodel import (
    DispatcherStateMachine,
)
from d810.optimizers.microcode.flow.flattening.engine.snapshot import (
    AnalysisSnapshot,
    ReachabilityInfo,
)
from d810.optimizers.microcode.flow.flattening.engine.strategy import (
    PlanFragment,
    StageResult,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies import (
    ALL_STRATEGIES,
)
from d810.optimizers.microcode.flow.flattening.strategies.bad_while_loop import (
    BAD_WHILE_LOOP_EDITS_METADATA_KEY,
    BAD_WHILE_LOOP_FOLLOW_UP_METADATA_KEY,
    collect_live_bad_while_loop_analysis,
    serialize_bad_while_loop_edits,
    serialize_bad_while_loop_follow_up,
)
from d810.optimizers.microcode.flow.flattening.strategies.fake_jump import (
    FAKE_JUMP_FIXES_METADATA_KEY,
    collect_live_fake_jump_fixes,
    serialize_fake_jump_fixes,
)
from d810.optimizers.microcode.flow.flattening.strategies.single_iteration import (
    SINGLE_ITERATION_FIXES_METADATA_KEY,
    collect_live_single_iteration_fixes,
    serialize_single_iteration_fixes,
)
from d810.recon.flow.dispatcher_detection import DispatcherCache
from d810.recon.flow.graph_reachability import (
    collect_residual_dispatcher_predecessors,
)
from d810.recon.flow.round_discovery_context import (
    build_round_discovery_context,
)
from d810.recon.flow.state_machine_analysis import run_snapshot_constant_fixpoint
from d810.recon.flow.transition_builder import (
    build_transition_result_from_state_machine,
)

family_logger = logging.getLogger("D810.unflat.hodur.family", logging.DEBUG)

__all__ = ["HodurDetection", "HodurStrategyFamily"]


@dataclass(frozen=True)
class HodurDetection:
    """Concrete detection result for the Hodur family."""

    state_machine: DispatcherStateMachine | None = None
    detector: HodurStateMachineDetector | None = None
    detection_source: str = "none"

    @property
    def detected(self) -> bool:
        return self.state_machine is not None

    @property
    def description(self) -> str:
        if not self.detected:
            return "no hodur state machine detected"
        return f"hodur state machine detected via {self.detection_source}"


class HodurStrategyFamily(CFFStrategyFamily):
    """Concrete CFF family adapter for Hodur-style state machines.

    The family owns:
    - detection
    - immutable snapshot construction
    - strategy registration
    - executor construction policy
    - successful-strategy bookkeeping
    - FlowGraph metadata enrichment
    - return-frontier artifact persistence helpers
    - family-local post-execution helpers

    The live ``HodurUnflattener`` remains responsible for pass lifecycle,
    compatibility accessors and concrete CFG cleanup.
    """

    def __init__(
        self,
        *,
        cfg_translator: IDAIRTranslator | None = None,
        disabled_strategy_names: set[str] | frozenset[str] | None = None,
        strategy_classes: list[type] | tuple[type, ...] | None = None,
        recon_only: bool = False,
        min_state_constant: int = MIN_STATE_CONSTANT,
        min_state_constants: int = MIN_STATE_CONSTANTS,
        max_state_constants: int = MAX_STATE_CONSTANTS_HODUR,
        fact_runtime: object | None = None,
        logger=None,
    ) -> None:
        """Initialize the Hodur family adapter.

        ``fact_runtime`` is the optional recon fact lifecycle runtime
        (concretely a ``d810.recon.facts.runtime.FactLifecycleRuntime`` or any
        object exposing ``validated_fact_view(func_ea, maturity)``).  When
        provided, ``build_snapshot`` will populate
        ``AnalysisSnapshot.diagnostic_fact_view`` so fact-rooted strategy
        gates can consult validated facts.  Typed loosely to avoid an import
        cycle into ``d810.recon.facts``.
        """
        self._cfg_translator = cfg_translator or IDAIRTranslator()
        self._disabled_strategy_names = frozenset(disabled_strategy_names or ())
        self._recon_only = bool(recon_only)
        self._logger = logger or family_logger
        self.min_state_constant = int(min_state_constant)
        self.min_state_constants = int(min_state_constants)
        self.max_state_constants = int(max_state_constants)
        self._fact_runtime: object | None = fact_runtime
        selected_strategy_classes = (
            list(strategy_classes) if strategy_classes is not None else ALL_STRATEGIES
        )
        self._strategies = [
            cls()
            for cls in selected_strategy_classes
            if cls.__name__ not in self._disabled_strategy_names
        ]
        self.reset_runtime_state()

    def set_fact_runtime(self, fact_runtime: object | None) -> None:
        """Late-binding setter for the recon fact lifecycle runtime.

        ``HodurUnflattener`` constructs the family at __init__ time but the
        recon runtime is wired in later via ``set_flow_context``.  Use this
        setter to attach (or detach) the runtime once it becomes known.
        """
        self._fact_runtime = fact_runtime

    @property
    def name(self) -> str:
        return "hodur"

    @property
    def strategies(self) -> list:
        if self._recon_only:
            return []
        return self._strategies

    def strategies_for_maturity(self, maturity: int | None = None) -> list:
        if self._recon_only:
            return []
        return list(self._strategies)

    @property
    def state_machine(self) -> DispatcherStateMachine | None:
        return self._state_machine

    @property
    def detector(self) -> HodurStateMachineDetector | None:
        return self._detector

    @property
    def switch_table_map(self) -> object | None:
        return self._switch_table_map

    @property
    def resolved_transitions(self) -> frozenset[tuple[int | None, int]]:
        return frozenset(self._resolved_transitions)

    @property
    def initial_transitions(self) -> tuple:
        return tuple(self._initial_transitions or ())

    def configure_detection(
        self,
        *,
        min_state_constant: int,
        min_state_constants: int,
        max_state_constants: int,
    ) -> None:
        self.min_state_constant = int(min_state_constant)
        self.min_state_constants = int(min_state_constants)
        self.max_state_constants = int(max_state_constants)

    def reset_runtime_state(self) -> None:
        self._state_machine: DispatcherStateMachine | None = None
        self._detector: HodurStateMachineDetector | None = None
        self._switch_table_map: object | None = None
        self._resolved_transitions: set[tuple[int | None, int]] = set()
        self._initial_transitions: list | None = None
        self._pass_number: int = 0

    def begin_pass(self, pass_number: int) -> None:
        self._pass_number = int(pass_number)
        self._switch_table_map = None

    def detect(self, mba: object) -> HodurDetection:
        detector = HodurStateMachineDetector(
            mba,
            min_state_constant=self.min_state_constant,
            min_state_constants=self.min_state_constants,
            max_state_constants=self.max_state_constants,
        )
        state_machine = detector.detect()
        detection_source = "detector"
        self._detector = detector

        if state_machine is None:
            cache = DispatcherCache.get_or_create(mba)
            analysis = cache.analyze()
            if analysis.is_conditional_chain:
                state_machine = self.build_state_machine_from_cache(analysis)
                detection_source = "dispatcher_cache"

        if state_machine is None:
            state_machine = self.try_switch_table_detection(mba)
            if state_machine is not None:
                detection_source = "switch_table"

        self._state_machine = state_machine
        if state_machine is not None and self._pass_number == 0:
            self._initial_transitions = list(state_machine.transitions)

        return HodurDetection(
            state_machine=state_machine,
            detector=detector,
            detection_source=detection_source if state_machine is not None else "none",
        )

    def build_snapshot(
        self,
        mba: object,
        detection: HodurDetection,
    ) -> AnalysisSnapshot:
        state_machine = detection.state_machine
        flow_graph = self._cfg_translator.lift(mba)
        flow_graph = self.attach_fake_jump_fixes_to_flow_graph(mba, flow_graph)
        flow_graph = self.attach_bad_while_loop_edits_to_flow_graph(mba, flow_graph)
        flow_graph = self.attach_single_iteration_fixes_to_flow_graph(mba, flow_graph)
        dispatcher_cache = DispatcherCache.get_or_create(mba)
        reachability = self.compute_reachability_info(mba)

        # Attach the recon fact view for this (func_ea, maturity), if a
        # runtime is available.  Strategies may consult this for fact-rooted
        # safety gates.  Never falls back to heuristics when absent.
        fact_view = self._resolve_fact_view(mba)

        if state_machine is None:
            return AnalysisSnapshot(
                mba=mba,
                detector=detection.detector,
                dispatcher_cache=dispatcher_cache,
                reachability=reachability,
                maturity=mba.maturity,
                pass_number=self._pass_number,
                flow_graph=flow_graph,
                diagnostic_fact_view=fact_view,
            )

        bst_result = None
        bst_dispatcher_serial = -1
        if state_machine.handlers and self._switch_table_map is None:
            entry_serial = list(state_machine.handlers.values())[0].check_block
            bst_stkoff = self.get_effective_state_var_stkoff(state_machine)
            try:
                from d810.recon.flow.bst_analysis import analyze_bst_dispatcher

                raw_bst = analyze_bst_dispatcher(
                    mba,
                    dispatcher_entry_serial=entry_serial,
                    state_var_stkoff=bst_stkoff,
                )
                if raw_bst is not None and len(raw_bst.handler_state_map) > 0:
                    bst_result = raw_bst
                    bst_dispatcher_serial = entry_serial
            except Exception:
                bst_result = None

        if bst_result is None and self._switch_table_map is not None:
            bst_result = self._switch_table_map.to_bst_result()
            bst_dispatcher_serial = self._switch_table_map.dispatcher_serial
            self._logger.debug(
                "Using synthetic BST from switch-table analysis: %d handlers, dispatcher=blk[%d]",
                len(bst_result.handler_state_map),
                bst_dispatcher_serial,
            )

        if self._pass_number > 0 and self._initial_transitions is not None:
            detected_keys = {
                (t.from_state, t.to_state) for t in state_machine.transitions
            }
            supplemented = 0
            for transition in self._initial_transitions:
                key = (transition.from_state, transition.to_state)
                if (
                    key not in self._resolved_transitions
                    and key not in detected_keys
                ):
                    state_machine.transitions.append(transition)
                    supplemented += 1
            if supplemented:
                self._logger.debug(
                    "HodurStrategyFamily: supplemented %d transitions from initial detection "
                    "(resolved=%d, re-detected=%d)",
                    supplemented,
                    len(self._resolved_transitions),
                    len(detected_keys),
                )

        self._state_machine = state_machine

        # Phase A scaffolding: build the canonical per-round discovery context
        # once, as the family adapter — strategies are NOT yet switched over,
        # they still use their local setup recipes. Tolerate partial inputs
        # gracefully (no half-built contexts — skip to None).
        discovery: object | None = None
        state_var_stkoff = self.get_effective_state_var_stkoff(state_machine)
        if (
            bst_result is not None
            and bst_dispatcher_serial >= 0
            and state_var_stkoff is not None
            and flow_graph is not None
        ):
            try:
                transition_result = build_transition_result_from_state_machine(
                    state_machine,
                    pre_header_serial=getattr(
                        bst_result, "pre_header_serial", None
                    ),
                    strategy_name="hodur_round_discovery_context",
                )
                constant_fixpoint = run_snapshot_constant_fixpoint(
                    flow_graph,
                    state_var_stkoff,
                )
                discovery = build_round_discovery_context(
                    func_ea=int(getattr(mba, "entry_ea", 0) or 0),
                    maturity=int(mba.maturity),
                    pass_number=int(self._pass_number),
                    flow_graph=flow_graph,
                    transition_result=transition_result,
                    dispatcher_entry_serial=bst_dispatcher_serial,
                    state_var_stkoff=state_var_stkoff,
                    structured_regions=(),
                    constant_fixpoint=constant_fixpoint,
                    bst_result=bst_result,
                    initial_state=state_machine.initial_state,
                    pre_header_serial=getattr(
                        bst_result, "pre_header_serial", None
                    ),
                    handler_range_map=(
                        getattr(bst_result, "handler_range_map", {}) or {}
                    ),
                    bst_node_blocks=tuple(
                        sorted(
                            getattr(bst_result, "bst_node_blocks", set())
                            or set()
                        )
                    ),
                    diagnostics=tuple(
                        getattr(bst_result, "diagnostics", ()) or ()
                    ),
                    dispatcher=getattr(bst_result, "dispatcher", None),
                    mba=mba,
                    prefer_local_corridors=True,
                )
            except Exception as exc:
                family_logger.debug(
                    "ReconRoundDiscoveryContext build failed (phase A): %s",
                    exc,
                )
                discovery = None

        return AnalysisSnapshot(
            mba=mba,
            state_machine=state_machine,
            detector=detection.detector,
            dispatcher_cache=dispatcher_cache,
            bst_result=bst_result,
            bst_dispatcher_serial=bst_dispatcher_serial,
            reachability=reachability,
            maturity=mba.maturity,
            pass_number=self._pass_number,
            resolved_transitions=frozenset(self._resolved_transitions),
            initial_transitions=tuple(self._initial_transitions or ()),
            flow_graph=flow_graph,
            discovery=discovery,
            diagnostic_fact_view=fact_view,
        )

    def record_progress(self, *, nb_changes: int) -> None:
        if nb_changes <= 0 or self._state_machine is None:
            return
        for transition in self._state_machine.transitions:
            self._resolved_transitions.add(
                (transition.from_state, transition.to_state)
            )

    def make_executor_factory(
        self,
        *,
        gate: object,
        allow_legacy_block_creation: bool,
    ):
        """Return the live executor factory for the Hodur family."""
        from d810.optimizers.microcode.flow.flattening.engine.executor import (
            TransactionalExecutor,
        )

        def _factory(mba: ida_hexrays.mba_t):
            return TransactionalExecutor(
                mba,
                gate=gate,
                allow_legacy_block_creation=allow_legacy_block_creation,
                safeguard_profile="hodur",
            )

        return _factory

    def record_execution_outcome(
        self,
        pipeline: list[PlanFragment],
        results: list[StageResult],
        *,
        func_ea: int,
        maturity: int,
        nb_changes: int,
        residual_dispatcher_preds_by_strategy: dict[str, tuple[int, ...]] | None = None,
    ) -> None:
        """Persist family-owned execution side effects after one pass."""
        if nb_changes > 0:
            self.record_progress(nb_changes=nb_changes)

        if not pipeline or not results:
            return

        residual_dispatcher_preds_by_strategy = (
            residual_dispatcher_preds_by_strategy or {}
        )
        strategies_by_name = {
            getattr(strategy, "name", None): strategy for strategy in self._strategies
        }

        for fragment, result in zip(pipeline, results):
            if not (result.success and result.edits_applied > 0):
                continue

            strategy = strategies_by_name.get(fragment.strategy_name)
            if strategy is None:
                continue

            applied = getattr(strategy, "_applied", None)
            if applied is not None:
                applied.add((func_ea, maturity))
                self._logger.info(
                    "Marking strategy %s as applied for func 0x%X maturity=%d",
                    fragment.strategy_name,
                    func_ea,
                    maturity,
                )

            residual_counts = getattr(
                strategy,
                "_last_successful_residual_dispatcher_pred_counts",
                None,
            )
            if residual_counts is None:
                continue

            residual_preds = tuple(
                int(serial)
                for serial in residual_dispatcher_preds_by_strategy.get(
                    fragment.strategy_name,
                    tuple(fragment.metadata.get("residual_dispatcher_preds", ())),
                )
            )
            residual_counts[(func_ea, maturity)] = len(residual_preds)
            self._logger.info(
                "Recorded %s residual dispatcher pred count for func 0x%X maturity=%d: %d",
                fragment.strategy_name,
                func_ea,
                maturity,
                len(residual_preds),
            )

    def persist_terminal_return_audit(
        self,
        results: list[StageResult],
        *,
        func_ea: int,
        maturity: int,
        log_dir: Path | str | None,
    ) -> None:
        """Persist the first terminal-return audit emitted by the executor."""
        for result in results:
            audit = result.metadata.get("terminal_return_audit")
            if audit is None:
                continue
            save_terminal_return_audit_to_store(
                func_ea=func_ea,
                maturity=maturity,
                audit=audit,
                log_dir=log_dir,
            )
            return

    def prepare_return_frontier_audit(
        self,
        snapshot: AnalysisSnapshot,
        *,
        current_return_sites: tuple,
        return_site_provider: object,
        func_ea: int,
        maturity: int,
        log_dir: Path | str | None,
        successors: dict[int, list[int]],
        exits: frozenset[int],
        handler_paths: dict[int, list] | None = None,
    ) -> tuple:
        """Build return-frontier sites if needed and record the pre-plan stage."""
        return_sites = tuple(current_return_sites)
        if not return_sites:
            from d810.recon.flow.transition_report import (
                build_dispatcher_transition_report,
            )

            report = load_transition_report_from_store(
                func_ea=func_ea,
                maturity=maturity,
                log_dir=log_dir,
            )
            used_report = False
            if report is not None and report.rows:
                return_sites = return_site_provider.collect_return_sites(report)
                used_report = True
                self._logger.info(
                    "RETURN_FRONTIER_AUDIT: using recon-store transition report "
                    "(%d rows -> %d sites)",
                    len(report.rows),
                    len(return_sites),
                )
            elif snapshot.bst_dispatcher_serial >= 0:
                try:
                    stkoff = self.get_effective_state_var_stkoff(snapshot.state_machine)
                    report = build_dispatcher_transition_report(
                        snapshot.mba,
                        snapshot.bst_dispatcher_serial,
                        state_var_stkoff=stkoff,
                    )
                    save_transition_report_to_store(
                        func_ea=func_ea,
                        maturity=maturity,
                        report=report,
                        log_dir=log_dir,
                    )
                except Exception as exc:
                    report = None
                    self._logger.info(
                        "RETURN_FRONTIER_AUDIT: transition report failed (diagnostic only): %s",
                        exc,
                    )

            if report is not None and report.rows and not used_report:
                return_sites = return_site_provider.collect_return_sites(report)
                self._logger.info(
                    "RETURN_FRONTIER_AUDIT: using transition report (%d rows -> %d sites)",
                    len(report.rows),
                    len(return_sites),
                )
            if not return_sites and handler_paths:
                return_sites = return_site_provider.collect_return_sites_legacy(
                    snapshot, handler_paths
                )
                self._logger.info(
                    "RETURN_FRONTIER_AUDIT: fallback to handler_paths (%d handlers -> %d sites)",
                    len(handler_paths),
                    len(return_sites),
                )
            if not return_sites:
                sites: list[ReturnSite] = []
                for blk_serial in sorted(exits):
                    sites.append(
                        ReturnSite(
                            site_id=f"hodur_exit_{blk_serial}",
                            origin_block=blk_serial,
                            guard_hash=f"{blk_serial:016x}",
                            expected_terminal_kind="return",
                            provenance="pre_plan_exit_block_scan",
                        )
                    )
                return_sites = tuple(sites)
                self._logger.info(
                    "RETURN_FRONTIER_AUDIT: fallback to exit block scan (%d sites)",
                    len(return_sites),
                )

        self.record_return_frontier_stage(
            return_sites,
            "pre_plan",
            func_ea=func_ea,
            maturity=maturity,
            log_dir=log_dir,
            successors=successors,
            exits=exits,
        )
        return return_sites

    def record_return_frontier_stage(
        self,
        return_sites: tuple,
        stage_name: str,
        *,
        func_ea: int,
        maturity: int,
        log_dir: Path | str | None,
        successors: dict[int, list[int]],
        exits: frozenset[int],
    ) -> None:
        """Record one return-frontier audit stage."""
        result = record_return_frontier_stage(
            func_ea=func_ea,
            maturity=maturity,
            log_dir=log_dir,
            return_sites=return_sites,
            successors=successors,
            entry=0,
            exits=exits,
            stage_name=stage_name,
        )
        self._logger.info(
            "RETURN_FRONTIER_AUDIT[%s]: sites=%d broken=%d (diagnostic only, not gated)",
            stage_name,
            result.metrics.get("total_sites", 0),
            result.metrics.get("broken_count", 0),
        )

    def finalize_return_frontier_audit(
        self,
        return_sites: tuple,
        *,
        func_ea: int,
        maturity: int,
        log_dir: Path | str | None,
        artifact_dir: Path,
        successors: dict[int, list[int]],
        exits: frozenset[int],
    ) -> None:
        """Record the final audit stage and write the persisted artifact."""
        self.record_return_frontier_stage(
            return_sites,
            "post_pipeline",
            func_ea=func_ea,
            maturity=maturity,
            log_dir=log_dir,
            successors=successors,
            exits=exits,
        )
        write_return_frontier_artifact_from_store(
            func_ea=func_ea,
            maturity=maturity,
            log_dir=log_dir,
            artifact_dir=artifact_dir,
        )
        audit = load_return_frontier_audit_from_store(
            func_ea=func_ea,
            maturity=maturity,
            log_dir=log_dir,
        )
        if audit is not None:
            audit.summary_log()

    def collect_live_residual_dispatcher_preds(
        self,
        mba: ida_hexrays.mba_t,
        snapshot: AnalysisSnapshot,
        *,
        strategy_name: str,
    ) -> tuple[int, ...]:
        """Collect live residual non-BST predecessors to the dispatcher."""
        bst_result = snapshot.bst_result
        if bst_result is None or snapshot.bst_dispatcher_serial < 0:
            return ()
        strategy = next(
            (
                candidate
                for candidate in self._strategies
                if getattr(candidate, "name", None) == strategy_name
            ),
            None,
        )
        collector = getattr(strategy, "_collect_residual_dispatcher_predecessors", None)
        if collector is None:
            collector = collect_residual_dispatcher_predecessors
        try:
            flow_graph = self._cfg_translator.lift(mba)
            raw_collector = getattr(strategy, "_collect_dispatcher_predecessors", None)
            active_collector = raw_collector or collector
            return active_collector(
                flow_graph,
                snapshot.bst_dispatcher_serial,
                bst_node_blocks=set(bst_result.bst_node_blocks),
            )
        except Exception:
            self._logger.debug(
                "Failed to collect live residual dispatcher preds for %s",
                strategy_name,
                exc_info=True,
            )
            return ()

    def collect_live_lfg_residual_dispatcher_preds(
        self,
        mba: ida_hexrays.mba_t,
        snapshot: AnalysisSnapshot,
    ) -> tuple[int, ...]:
        return self.collect_live_residual_dispatcher_preds(
            mba,
            snapshot,
            strategy_name="linearized_flow_graph",
        )

    @staticmethod
    def collect_post_apply_bst_cleanup_blockers(
        pipeline: list[PlanFragment],
        results: list[StageResult],
        *,
        live_residual_dispatcher_preds_by_strategy: dict[str, tuple[int, ...]] | None = None,
    ) -> dict[str, tuple[int, ...]]:
        blockers: dict[str, tuple[int, ...]] = {}
        live_residual_dispatcher_preds_by_strategy = (
            live_residual_dispatcher_preds_by_strategy or {}
        )
        for fragment, result in zip(pipeline, results):
            if not (result.success and result.edits_applied > 0):
                continue
            if fragment.metadata.get("allow_post_apply_bst_cleanup", True):
                continue
            cleanup_reason = fragment.metadata.get("post_apply_bst_cleanup_reason")
            group_name = fragment.metadata.get("post_apply_bst_cleanup_group")
            if isinstance(group_name, str):
                residual_source = live_residual_dispatcher_preds_by_strategy.get(
                    f"group:{group_name}"
                )
                if residual_source is not None:
                    residual_preds = tuple(int(serial) for serial in residual_source)
                    if not residual_preds:
                        continue
                    blockers[fragment.strategy_name] = residual_preds
                    continue
            residual_preds = tuple(
                int(serial)
                for serial in live_residual_dispatcher_preds_by_strategy.get(
                    fragment.strategy_name,
                    tuple(fragment.metadata.get("residual_dispatcher_preds", ())),
                )
            )
            if residual_preds:
                blockers[fragment.strategy_name] = residual_preds
                continue
            if isinstance(cleanup_reason, str) and cleanup_reason:
                blockers[fragment.strategy_name] = ()
        return blockers

    def attach_fake_jump_fixes_to_flow_graph(
        self,
        mba: ida_hexrays.mba_t,
        flow_graph: FlowGraph,
    ) -> FlowGraph:
        """Attach live FakeJump analysis results to FlowGraph metadata."""
        if mba.maturity not in (ida_hexrays.MMAT_GLBOPT1,):
            return flow_graph

        try:
            fixes = collect_live_fake_jump_fixes(
                mba,
                logger=self._logger,
                max_nb_block=100,
                max_path=100,
                allowed_maturities=(ida_hexrays.MMAT_GLBOPT1,),
            )
        except Exception:
            self._logger.debug(
                "Failed to collect FakeJump fixes for FlowGraph metadata",
                exc_info=True,
            )
            return flow_graph

        if not fixes:
            return flow_graph

        try:
            dispatcher_cache = DispatcherCache.get_or_create(mba)
            dispatcher_analysis = dispatcher_cache.analyze()
        except Exception:
            dispatcher_cache = None
            dispatcher_analysis = None

        if (
            dispatcher_cache is not None
            and dispatcher_analysis is not None
            and dispatcher_analysis.is_conditional_chain
        ):
            original_count = len(fixes)
            fixes = tuple(
                fix
                for fix in fixes
                if not dispatcher_cache.is_dispatcher(fix.fake_block)
            )
            dropped = original_count - len(fixes)
            if dropped > 0:
                self._logger.info(
                    "Dropped %d FakeJump fixes targeting conditional-chain dispatcher blocks",
                    dropped,
                )
            if not fixes:
                return flow_graph

        if (
            self._state_machine is None
            and dispatcher_analysis is not None
            and tuple(getattr(dispatcher_analysis, "dispatchers", ()))
        ):
            self._logger.info(
                "Skipping FakeJump fixes during cleanup-only pass with live "
                "emulated-dispatcher candidates"
            )
            return flow_graph

        metadata = dict(flow_graph.metadata)
        metadata[FAKE_JUMP_FIXES_METADATA_KEY] = serialize_fake_jump_fixes(fixes)
        self._logger.info(
            "Attached %d FakeJump predecessor redirects to FlowGraph metadata",
            len(fixes),
        )
        return FlowGraph(
            blocks=flow_graph.blocks,
            entry_serial=flow_graph.entry_serial,
            func_ea=flow_graph.func_ea,
            metadata=metadata,
        )

    def attach_bad_while_loop_edits_to_flow_graph(
        self,
        mba: ida_hexrays.mba_t,
        flow_graph: FlowGraph,
    ) -> FlowGraph:
        """Attach safe BadWhileLoop edits plus classified follow-up metadata."""
        if mba.maturity not in (ida_hexrays.MMAT_GLBOPT1,):
            return flow_graph

        try:
            analysis = collect_live_bad_while_loop_analysis(
                mba,
                logger=self._logger,
                allowed_maturities=(ida_hexrays.MMAT_GLBOPT1,),
            )
        except Exception:
            self._logger.debug(
                "Failed to collect BadWhileLoop edits for FlowGraph metadata",
                exc_info=True,
            )
            return flow_graph

        if not analysis.edits and not analysis.follow_up:
            return flow_graph

        metadata = dict(flow_graph.metadata)
        if analysis.edits:
            metadata[BAD_WHILE_LOOP_EDITS_METADATA_KEY] = serialize_bad_while_loop_edits(
                analysis.edits
            )
        if analysis.follow_up:
            metadata[BAD_WHILE_LOOP_FOLLOW_UP_METADATA_KEY] = (
                serialize_bad_while_loop_follow_up(analysis.follow_up)
            )
        self._logger.info(
            "Attached %d safe BadWhileLoop edits and %d follow-up gaps to FlowGraph metadata",
            len(analysis.edits),
            len(analysis.follow_up),
        )
        return FlowGraph(
            blocks=flow_graph.blocks,
            entry_serial=flow_graph.entry_serial,
            func_ea=flow_graph.func_ea,
            metadata=metadata,
        )

    def attach_single_iteration_fixes_to_flow_graph(
        self,
        mba: ida_hexrays.mba_t,
        flow_graph: FlowGraph,
    ) -> FlowGraph:
        """Attach live single-iteration redirects to FlowGraph metadata."""
        if mba.maturity not in (ida_hexrays.MMAT_GLBOPT1,):
            return flow_graph

        try:
            fixes = collect_live_single_iteration_fixes(
                mba,
                logger=self._logger,
                allowed_maturities=(ida_hexrays.MMAT_GLBOPT1,),
            )
        except Exception:
            self._logger.debug(
                "Failed to collect single-iteration fixes for FlowGraph metadata",
                exc_info=True,
            )
            return flow_graph

        if not fixes:
            return flow_graph

        metadata = dict(flow_graph.metadata)
        metadata[SINGLE_ITERATION_FIXES_METADATA_KEY] = serialize_single_iteration_fixes(
            fixes
        )
        self._logger.info(
            "Attached %d single-iteration predecessor redirects to FlowGraph metadata",
            len(fixes),
        )
        return FlowGraph(
            blocks=flow_graph.blocks,
            entry_serial=flow_graph.entry_serial,
            func_ea=flow_graph.func_ea,
            metadata=metadata,
        )

    def get_effective_state_var_stkoff(
        self, state_machine: DispatcherStateMachine | None = None
    ) -> int | None:
        if self._detector is not None:
            try:
                from d810.recon.flow.transition_builder import (
                    _get_state_var_stkoff,
                )

                stkoff = _get_state_var_stkoff(self._detector)
                if stkoff is not None:
                    return stkoff
            except Exception:
                pass

        sm = state_machine if state_machine is not None else self._state_machine
        if sm is None or sm.state_var is None:
            return None
        if sm.state_var.t == ida_hexrays.mop_S:
            return sm.state_var.s.off
        return None

    def _resolve_fact_view(self, mba: object) -> object | None:
        """Return the validated fact view for ``(func_ea, mba.maturity)``.

        Returns ``None`` when no fact runtime is attached or when the
        runtime fails to produce a view.  Strategy consumers must tolerate
        ``None`` (no heuristic fallback).
        """
        runtime = self._fact_runtime
        if runtime is None:
            return None
        try:
            func_ea = int(getattr(mba, "entry_ea", 0) or 0)
            maturity = getattr(mba, "maturity", 0)
            return runtime.validated_fact_view(func_ea, maturity)
        except Exception:
            return None

    def compute_reachability_info(self, mba: ida_hexrays.mba_t) -> ReachabilityInfo:
        qty = mba.qty
        visited: set[int] = set()
        queue = [0]
        while queue:
            serial = queue.pop()
            if serial in visited or serial < 0 or serial >= qty:
                continue
            visited.add(serial)
            blk = mba.get_mblock(serial)
            if blk is not None:
                for i in range(blk.nsucc()):
                    queue.append(blk.succ(i))
        return ReachabilityInfo(
            entry_serial=0,
            reachable_blocks=frozenset(visited),
            total_blocks=qty,
        )

    def build_state_machine_from_cache(
        self, analysis: object
    ) -> DispatcherStateMachine | None:
        self._logger.debug(
            "build_state_machine_from_cache: cache-based fallback not implemented "
            "in strategy-pipeline mode; returning None"
        )
        return None

    def try_switch_table_detection(
        self, mba: ida_hexrays.mba_t,
    ) -> DispatcherStateMachine | None:
        from d810.recon.flow.switch_table_analysis import (
            analyze_switch_table_dispatcher,
        )
        from d810.recon.flow.transition_builder import (
            StateHandler,
            StateTransition,
        )
        from d810.recon.flow.state_machine_analysis import evaluate_handler_paths

        result = analyze_switch_table_dispatcher(mba)
        if result is None:
            return None

        handler_map = result.handler_map
        state_var_mop = result.state_var_mop

        self._logger.info(
            "Switch-table dispatcher detected: %d handlers at blk[%d]",
            len(handler_map.handler_state_map),
            handler_map.dispatcher_serial,
        )

        state_machine = DispatcherStateMachine(mba=mba, state_var=state_var_mop)
        state_machine.state_constants = set(handler_map.handler_state_map.values())

        handler_entry_blocks = set(handler_map.handler_state_map.keys())
        dispatcher_blocks_set = set(handler_map.dispatcher_blocks)

        for handler_serial, state_const in handler_map.handler_state_map.items():
            handler = StateHandler(
                state_value=state_const,
                check_block=handler_serial,
                handler_blocks=[handler_serial],
            )
            state_machine.add_handler(handler)

        for handler_serial, state_const in handler_map.handler_state_map.items():
            try:
                paths = evaluate_handler_paths(
                    mba,
                    entry_serial=handler_serial,
                    incoming_state=state_const,
                    bst_node_blocks=dispatcher_blocks_set,
                    state_var_stkoff=handler_map.state_var_stkoff,
                    handler_entry_blocks=handler_entry_blocks,
                )
            except Exception:
                self._logger.debug(
                    "Forward eval failed for switch handler blk[%d] (state=%d)",
                    handler_serial,
                    state_const,
                )
                continue

            for path_result in paths:
                if path_result.final_state is None:
                    continue
                target = handler_map.resolve_target(path_result.final_state)
                if target is None:
                    continue
                transition = StateTransition(
                    from_state=state_const,
                    to_state=path_result.final_state,
                    from_block=path_result.exit_block,
                )
                state_machine.add_transition(transition)

        self._logger.info(
            "Switch-table state machine: %d handlers, %d transitions",
            len(state_machine.handlers),
            len(state_machine.transitions),
        )

        self._switch_table_map = handler_map
        self._state_machine = state_machine
        return state_machine
