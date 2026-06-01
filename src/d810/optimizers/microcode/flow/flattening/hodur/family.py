"""Hodur family adapter over the shared unflattening engine surface."""
from __future__ import annotations

from dataclasses import dataclass

import ida_hexrays

from d810.ir.flowgraph import FlowGraph
from d810.core import logging
from d810.hexrays.mutation.ir_translator import IDAIRTranslator
from d810.hexrays.utils.hexrays_formatters import maturity_to_string
from d810.families.state_machine_cff.family import (
    CFFStrategyFamily,
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
from d810.capabilities.constant_fixpoint import ConstantFixpointBackend
from d810.optimizers.microcode.flow.flattening.hodur.constant_fixpoint_backend import (
    DEFAULT_HODUR_CONSTANT_FIXPOINT_BACKEND,
)
from d810.optimizers.microcode.flow.flattening.engine.snapshot import (
    AnalysisSnapshot,
    ReachabilityInfo,
)
from d810.optimizers.microcode.flow.flattening.engine.runtime import FamilyRunState
from d810.optimizers.microcode.flow.flattening.engine.state_machine_snapshot_builder import (
    StateMachineSnapshotBuilder,
)
from d810.transforms.plan_fragment import (
    PlanFragment,
    StageResult,
)
from d810.optimizers.microcode.flow.flattening.hodur.profile import (
    default_hodur_profile,
)
from d810.optimizers.microcode.flow.flattening.hodur.snapshot_builder import (
    HodurSnapshotPolicy,
)
from d810.optimizers.microcode.flow.flattening.hodur.state_machine_adapters import (
    detect_switch_table_state_machine,
)
from d810.optimizers.microcode.flow.flattening.cleanup_live_evidence import (
    collect_live_fake_jump_fixes,
    collect_live_single_iteration_fixes,
)
from d810.backends.hexrays.evidence.dispatcher.dispatcher_history import (
    DispatcherAnalysis,
    analyze_dispatcher_live,
)
from d810.analyses.control_flow.round_discovery_context import (
    build_round_discovery_context,
)
from d810.passes.function_priors import FunctionAnalysisPriors
from d810.analyses.control_flow.transition_builder import (
    build_transition_result_from_state_machine,
)

family_logger = logging.getLogger("D810.unflat.hodur.family", logging.DEBUG)
_CONSTANT_FIXPOINT_BACKEND: ConstantFixpointBackend = (
    DEFAULT_HODUR_CONSTANT_FIXPOINT_BACKEND
)

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
    - successful-strategy bookkeeping
    - FlowGraph metadata enrichment

    The live ``HodurUnflattener`` remains responsible for pass lifecycle,
    compatibility accessors and concrete CFG cleanup.  Shared runtime helpers
    own executor construction, pass bookkeeping, audit persistence, and
    post-apply cleanup gating.
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
        (concretely a ``d810.passes.fact_runtime.FactLifecycleRuntime`` or any
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
        self._constant_fixpoint_backend: ConstantFixpointBackend = (
            _CONSTANT_FIXPOINT_BACKEND
        )
        self._snapshot_policy = HodurSnapshotPolicy(
            constant_fixpoint_backend=self._constant_fixpoint_backend,
            logger=self._logger,
        )
        self._snapshot_builder = StateMachineSnapshotBuilder(
            cfg_translator=self._cfg_translator,
            logger=self._logger,
        )
        selected_strategy_classes = (
            list(strategy_classes)
            if strategy_classes is not None
            else list(default_hodur_profile().strategy_classes)
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
    def cfg_translator(self) -> IDAIRTranslator:
        return self._cfg_translator

    @property
    def resolved_transitions(self) -> frozenset[tuple[int | None, int]]:
        return self._run_state.resolved_transitions

    @property
    def initial_transitions(self) -> tuple:
        return self._run_state.initial_transitions

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

    def _function_analysis_priors_for_mba(
        self,
        mba: object,
    ) -> FunctionAnalysisPriors:
        return self._snapshot_policy.function_analysis_priors_for_mba(
            mba,
            self._fact_runtime,
        )

    def reset_runtime_state(self) -> None:
        self._state_machine: DispatcherStateMachine | None = None
        self._detector: HodurStateMachineDetector | None = None
        self._switch_table_map: object | None = None
        self._run_state = FamilyRunState()

    def begin_pass(self, pass_number: int) -> None:
        self._run_state = self._run_state.begin_pass(pass_number)
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
            analysis = analyze_dispatcher_live(mba)
            if analysis.is_conditional_chain:
                state_machine = self.build_state_machine_from_cache(analysis)
                detection_source = "dispatcher_analysis"

        if state_machine is None:
            state_machine = self.try_switch_table_detection(mba)
            if state_machine is not None:
                detection_source = "switch_table"

        self._state_machine = state_machine
        if state_machine is not None:
            self._run_state = self._run_state.remember_initial_transitions(
                state_machine.transitions
            )

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
        self._snapshot_policy.constant_fixpoint_backend = (
            self._constant_fixpoint_backend
        )
        snapshot = self._snapshot_builder.build_snapshot(
            mba,
            detection,
            run_state=self._run_state,
            flow_graph_adapter=self._adapt_snapshot_flow_graph,
            dispatcher_analysis_factory=analyze_dispatcher_live,
            reachability_builder=self.compute_reachability_info,
            fact_view_resolver=self._resolve_fact_view,
            function_priors_resolver=self._function_analysis_priors_for_mba,
            bst_evidence_resolver=self._resolve_snapshot_bst_evidence,
            transition_supplementer=self._supplement_initial_transitions,
            discovery_builder=self._build_snapshot_discovery_context,
        )
        self._state_machine = detection.state_machine
        return snapshot

    def _adapt_snapshot_flow_graph(
        self,
        mba: object,
        flow_graph: FlowGraph,
        state_machine: DispatcherStateMachine | None,
    ) -> FlowGraph:
        """Enrich the immutable CFG snapshot for this family pass."""
        return self._snapshot_policy.adapt_flow_graph(
            mba,
            flow_graph,
            state_machine,
            attach_fake_jump_fixes=self.attach_fake_jump_fixes_to_flow_graph,
            attach_single_iteration_fixes=(
                self.attach_single_iteration_fixes_to_flow_graph
            ),
        )

    def _build_snapshot_flow_graph(self, mba: object) -> FlowGraph:
        """Compatibility helper for tests that inspect Hodur flow enrichment."""
        return self._adapt_snapshot_flow_graph(
            mba,
            self._cfg_translator.lift(mba),
            self._state_machine,
        )

    def _build_cleanup_snapshot(
        self,
        mba: object,
        *,
        detection: HodurDetection,
        flow_graph: FlowGraph,
        dispatcher_analysis: DispatcherAnalysis,
        reachability: ReachabilityInfo,
        fact_view: object | None,
    ) -> AnalysisSnapshot:
        """Build a cleanup-only snapshot when no Hodur state machine exists."""
        return self._snapshot_builder.build_cleanup_snapshot(
            mba,
            detection=detection,
            flow_graph=flow_graph,
            dispatcher_analysis=dispatcher_analysis,
            reachability=reachability,
            fact_view=fact_view,
            run_state=self._run_state,
        )

    def _resolve_snapshot_bst_evidence(
        self,
        mba: object,
        state_machine: DispatcherStateMachine,
    ) -> tuple[object | None, int]:
        """Resolve concrete or synthetic BST evidence for a state-machine snapshot."""
        return self._snapshot_policy.resolve_snapshot_bst_evidence(
            mba,
            state_machine,
            switch_table_map=self._switch_table_map,
            state_var_stkoff_resolver=self.get_effective_state_var_stkoff,
        )

    def _supplement_initial_transitions(
        self,
        state_machine: DispatcherStateMachine,
        *,
        run_state: FamilyRunState | None = None,
    ) -> None:
        """Carry unresolved pass-0 transitions into later state-machine snapshots."""
        self._snapshot_policy.supplement_initial_transitions(
            state_machine,
            run_state=run_state or self._run_state,
        )

    def _build_snapshot_discovery_context(
        self,
        mba: object,
        *,
        state_machine: DispatcherStateMachine,
        flow_graph: FlowGraph,
        bst_result: object | None,
        bst_dispatcher_serial: int,
        function_priors: FunctionAnalysisPriors | None,
        run_state: FamilyRunState | None = None,
    ) -> object | None:
        """Build the canonical per-round discovery context for strategies."""
        self._snapshot_policy.constant_fixpoint_backend = (
            self._constant_fixpoint_backend
        )
        return self._snapshot_policy.build_snapshot_discovery_context(
            mba,
            state_machine=state_machine,
            flow_graph=flow_graph,
            bst_result=bst_result,
            bst_dispatcher_serial=bst_dispatcher_serial,
            function_priors=function_priors or FunctionAnalysisPriors(),
            run_state=run_state or self._run_state,
            state_var_stkoff_resolver=self.get_effective_state_var_stkoff,
            transition_builder=build_transition_result_from_state_machine,
            discovery_builder=build_round_discovery_context,
        )

    def record_progress(self, *, nb_changes: int) -> None:
        if nb_changes <= 0 or self._state_machine is None:
            return
        self._run_state = self._run_state.record_resolved_transitions(
            self._state_machine.transitions
        )

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
        maturity_name = maturity_to_string(maturity)

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
                    "Marking strategy %s as applied for func 0x%X maturity=%s",
                    fragment.strategy_name,
                    func_ea,
                    maturity_name,
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
                "Recorded %s residual dispatcher pred count for func 0x%X maturity=%s: %d",
                fragment.strategy_name,
                func_ea,
                maturity_name,
                len(residual_preds),
            )

    def attach_fake_jump_fixes_to_flow_graph(
        self,
        mba: ida_hexrays.mba_t,
        flow_graph: FlowGraph,
    ) -> FlowGraph:
        """Attach live FakeJump analysis results to FlowGraph metadata."""
        return self._snapshot_policy.attach_fake_jump_fixes_to_flow_graph(
            mba,
            flow_graph,
            state_machine=self._state_machine,
            dispatcher_analysis_factory=analyze_dispatcher_live,
            collector=collect_live_fake_jump_fixes,
        )

    def attach_single_iteration_fixes_to_flow_graph(
        self,
        mba: ida_hexrays.mba_t,
        flow_graph: FlowGraph,
    ) -> FlowGraph:
        """Attach live single-iteration redirects to FlowGraph metadata."""
        return self._snapshot_policy.attach_single_iteration_fixes_to_flow_graph(
            mba,
            flow_graph,
            collector=collect_live_single_iteration_fixes,
        )

    def get_effective_state_var_stkoff(
        self, state_machine: DispatcherStateMachine | None = None
    ) -> int | None:
        if self._detector is not None:
            try:
                from d810.analyses.control_flow.transition_builder import (
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
        return self._snapshot_policy.resolve_fact_view(mba, self._fact_runtime)

    def compute_reachability_info(self, mba: ida_hexrays.mba_t) -> ReachabilityInfo:
        return self._snapshot_policy.compute_reachability_info(mba)

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
        adapter_result = detect_switch_table_state_machine(
            mba,
            logger=self._logger,
        )
        if adapter_result is None:
            return None

        state_machine = adapter_result.state_machine
        self._switch_table_map = adapter_result.state_dispatcher_map
        self._state_machine = state_machine
        return state_machine
