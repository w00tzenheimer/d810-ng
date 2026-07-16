from __future__ import annotations

import contextlib
import dataclasses
import importlib
import pathlib

from d810.core import (
    MOP_CONSTANT_CACHE,
    MOP_TO_AST_CACHE,
    typing,
)
from d810.core.logging import getLogger
from d810.core.observability import get_active_diag_path
from d810.core.project import (
    emit_recon_fact_collector_registration,
)
from d810.core.registry import EventEmitter
from d810.core.rule_scope import (
    FunctionRuleOverlay,
    RuleInferenceOverlay,
    RuleScopeEvent,
    RuleScopeInvalidation,
    RuleScopeService,
)
from d810.core.stats import OptimizationStatistics
from d810.backends.ast.z3 import Z3MopProver
from d810.backends.hexrays.registration import (
    ensure_hexrays_fact_lifter_registered,
)
from d810.diagnostics.post_d810_handoff import detect_post_d810_handoff_violations
from d810.diagnostics.workbench_cleanup import DiagnosticCleanupService
from d810.diagnostics.workbench_inventory import DiagnosticInventoryService
from d810.diagnostics.workbench_models import (
    DiagnosticCleanupPlan,
    DiagnosticCleanupResult,
    DiagnosticDatabaseSummary,
    DiagnosticRecord,
    DiagnosticSnapshotSummary,
    DiagnosticViewKind,
)
from d810.evaluator.hexrays_microcode.dispatcher_artifacts import (
    plan_dispatcher_state_return_carrier_artifact,
)
from d810.hexrays.hooks.ctree_hooks import CtreeOptimizerManager
from d810.hexrays.hooks.hexrays_hooks import HexraysDecompilationHook
from d810.hexrays.hooks.optblock_adapter import BlockOptimizerManager
from d810.hexrays.hooks.optinsn_adapter import InstructionOptimizerManager
from d810.hexrays.lifecycle import DecompilationEvent, HEXRAYS_MICROCODE_PROVIDER
from d810.optimizers import load_optimizer_registries
from d810.optimizers.microcode.flow.context import FlowMaturityContext
from d810.optimizers.microcode.instructions.handler import (
    InstructionOptimizer,
)
from d810.passes.function_prior_config import (
    function_prior_keys,
    load_function_analysis_priors_from_config,
)
from d810.passes.function_priors import FunctionAnalysisPriors
from d810.passes.inferences import unflattening_inference
from d810.passes.pass_pipeline_factory import (
    PassPipelineSpec,
    build_pass_pipeline_spec,
    pass_pipeline_spec_from_config,
)
from d810.passes.recon_runtime_factory import (
    build_recon_phase,
    build_recon_runtime_bundle,
)
from d810.passes.scheduler import PassScheduler
from d810.passes.store import shutdown_all_writers
from d810.manager.flowgraph_ready import FlowGraphReadySubscriber
from d810.manager.config_v2_edit_models import (
    ConfigV2FieldSerializer,
    ConfigV2ProjectDraft,
    ConfigV2ProjectValidation,
)
from d810.manager.config_v2_editing import ConfigV2EditingService
from d810.manager.function_recipe_runtime import (
    FunctionRecipeRuntime,
)
from d810.manager.hexrays_pass_pipeline import build_hexrays_flowgraph_pipeline
from d810.manager.post_d810_runtime import HexRaysPostD810Runtime
from d810.manager.profiling import ProfilingController
from d810.manager.project_runtime import ProjectRuntimeSnapshot
from d810.manager.rule_scope_runtime import RuleScopeRuntime
from d810.manager.workbench_comparison import (
    ComparisonIdentity,
    WorkbenchComparisonService,
)
from d810.manager.workbench_models import (
    BaselineRef,
    D810OutputRef,
    DeobfuscationWorkbenchSnapshot,
    WorkbenchComparisonSnapshot,
)
from d810.manager.workbench_service import WorkbenchService
from d810.manager.workbench_recipe_models import (
    FunctionPipelineOverride,
    PassCatalogEntry,
    PipelineRecipeDraft,
    RecipeValidation,
    RecipeCommandRequest,
    RecipeCommandResult,
)
from d810.manager.workbench_recipe_commands import WorkbenchRecipeCommandService
from d810.manager.workbench_recipe_service import RecipeService
from d810.passes.operational_config_v2 import operational_config_v2_pass_registry
from d810.passes.pipeline_config_parser import pipeline_configs_from_project_config


D810_LOG_DIR_NAME = "d810_logs"

logger = getLogger("D810")


def _active_diagnostic_paths() -> tuple[str, ...]:
    path = get_active_diag_path()
    return (path,) if path is not None else ()


def maybe_run_tail_distinct(mba: typing.Any) -> None:
    """Env-gated hook: ``D810_TAIL_DISTINCT_BYTE`` topology-only experiment.

    Thin manager-level re-export of the implementation in
    :mod:`d810.hexrays.mutation.byte_emit_tail_isolation_runtime`.  The real
    helper lives outside ``d810.manager`` so optimizer call sites can
    import it without crossing the layered-architecture import contract
    (optimizers must not depend on ``d810.ui``, and manager transitively
    imports UI).
    """
    from d810.hexrays.mutation.byte_emit_tail_isolation_runtime import (
        maybe_run_tail_distinct as _impl,
    )
    _impl(mba)


def _maturity_name(maturity: int) -> str:
    """Map IDA maturity integer to a human-readable name for file labels."""
    try:
        import ida_hexrays

        _names = {
            ida_hexrays.MMAT_ZERO: "MMAT_ZERO",
            ida_hexrays.MMAT_GENERATED: "MMAT_GENERATED",
            ida_hexrays.MMAT_PREOPTIMIZED: "MMAT_PREOPTIMIZED",
            ida_hexrays.MMAT_LOCOPT: "MMAT_LOCOPT",
            ida_hexrays.MMAT_CALLS: "MMAT_CALLS",
            ida_hexrays.MMAT_GLBOPT1: "MMAT_GLBOPT1",
            ida_hexrays.MMAT_GLBOPT2: "MMAT_GLBOPT2",
            ida_hexrays.MMAT_GLBOPT3: "MMAT_GLBOPT3",
            ida_hexrays.MMAT_LVARS: "MMAT_LVARS",
        }
        return _names.get(maturity, f"MMAT_{maturity}")
    except ImportError:
        return f"MMAT_{maturity}"


@dataclasses.dataclass
class D810Manager:
    log_dir: pathlib.Path
    diagnostic_active_paths_provider: typing.Callable[[], typing.Any] = (
        dataclasses.field(default=_active_diagnostic_paths, repr=False)
    )
    stats: OptimizationStatistics = dataclasses.field(
        default_factory=OptimizationStatistics
    )
    instruction_optimizer_rules: list = dataclasses.field(default_factory=list)
    instruction_optimizer_config: dict = dataclasses.field(default_factory=dict)
    block_optimizer_rules: list = dataclasses.field(default_factory=list)
    block_optimizer_config: dict = dataclasses.field(default_factory=dict)
    ctree_optimizer_rules: list = dataclasses.field(default_factory=list)
    ctree_optimizer_config: dict = dataclasses.field(default_factory=dict)
    config: dict = dataclasses.field(default_factory=dict)
    event_emitter: EventEmitter = dataclasses.field(default_factory=EventEmitter)
    rule_scope_service: RuleScopeService = dataclasses.field(
        default_factory=RuleScopeService
    )
    block_pass_scheduler: PassScheduler = dataclasses.field(default_factory=PassScheduler)
    instruction_pass_scheduler: PassScheduler = dataclasses.field(
        default_factory=PassScheduler
    )
    profiling: ProfilingController = dataclasses.field(init=False)
    rule_scope_runtime: RuleScopeRuntime = dataclasses.field(init=False)
    comparison_service: WorkbenchComparisonService = dataclasses.field(init=False)
    recipe_service: RecipeService = dataclasses.field(init=False)
    function_recipe_runtime: FunctionRecipeRuntime = dataclasses.field(init=False)
    recipe_command_service: WorkbenchRecipeCommandService = dataclasses.field(init=False)
    workbench_service: WorkbenchService = dataclasses.field(init=False)
    diagnostic_inventory_service: DiagnosticInventoryService = dataclasses.field(
        init=False
    )
    diagnostic_cleanup_service: DiagnosticCleanupService = dataclasses.field(init=False)
    config_v2_editing_service: ConfigV2EditingService = dataclasses.field(init=False)
    instruction_optimizer: InstructionOptimizerManager = dataclasses.field(init=False)
    block_optimizer: BlockOptimizerManager = dataclasses.field(init=False)
    ctree_optimizer: CtreeOptimizerManager = dataclasses.field(init=False)
    hx_decompiler_hook: HexraysDecompilationHook = dataclasses.field(init=False)
    _started: bool = dataclasses.field(default=False, init=False)
    _recon_phase: typing.Any = dataclasses.field(default=None, init=False)
    _recon_runtime: typing.Any = dataclasses.field(default=None, init=False)
    _recon_bundle: typing.Any = dataclasses.field(default=None, init=False)
    _flowgraph_ready_subscriber: typing.Any = dataclasses.field(default=None, init=False)
    _post_d810_runtime: typing.Any = dataclasses.field(default=None, init=False)
    _function_analysis_priors: dict[str, FunctionAnalysisPriors] = (
        dataclasses.field(default_factory=dict, init=False)
    )

    def __post_init__(self) -> None:
        self.profiling = ProfilingController(self.log_dir)
        self.rule_scope_runtime = RuleScopeRuntime(
            storage_factory=self._create_rule_scope_storage,
            rule_scope_service=self.rule_scope_service,
            event_emitter=self.event_emitter,
            log_dir=self.log_dir,
            project_name_provider=lambda: str(self.config.get("project_name", "")),
            config_provider=lambda: self.config,
        )
        self.comparison_service = WorkbenchComparisonService()
        workbench_registry = operational_config_v2_pass_registry()
        self.recipe_service = RecipeService(workbench_registry)
        self.function_recipe_runtime = FunctionRecipeRuntime(
            storage_provider=lambda: self.rule_scope_runtime.storage,
            event_emitter=self.event_emitter,
            project_name_provider=lambda: str(self.config.get("project_name", "")),
        )
        self.workbench_service = WorkbenchService(self, registry=workbench_registry)
        self.recipe_command_service = WorkbenchRecipeCommandService(
            identity_is_current=self.workbench_service.recipe_request_is_current,
        )
        self.diagnostic_inventory_service = DiagnosticInventoryService(
            roots=(self.log_dir,),
            active_paths_provider=self.diagnostic_active_paths_provider,
        )
        self.diagnostic_cleanup_service = DiagnosticCleanupService(
            active_paths_provider=self.diagnostic_active_paths_provider,
            quarantine_directory=self.log_dir / "diagnostic_quarantine",
        )
        self.config_v2_editing_service = ConfigV2EditingService(workbench_registry)

    @property
    def started(self):
        return self._started

    @property
    def profiler(self):
        return self.profiling.profiler

    @property
    def cprofiler(self):
        return self.profiling.cprofiler

    @property
    def storage(self):
        return self.rule_scope_runtime.storage

    @storage.setter
    def storage(self, value):
        self.rule_scope_runtime.storage = value

    @property
    def recon_db(self) -> pathlib.Path | None:
        """Path to the recon SQLite database, or None if recon is disabled."""
        rt = getattr(self, "_recon_runtime", None)
        if rt is None:
            return None
        return rt._store.db_path

    def load_recon_hints(self, function_ea: int) -> typing.Any | None:
        """Return persisted hints without triggering collection or mutation."""
        runtime = self._recon_runtime
        if runtime is None:
            return None
        return runtime.load_hints(int(function_ea))

    def get_recon_outcome_reports(self, function_ea: int) -> tuple[typing.Any, ...]:
        """Return a detached tuple of current cross-consumer reports."""
        runtime = self._recon_runtime
        if runtime is None:
            return ()
        return tuple(runtime.outcome_log.get_func_reports(int(function_ea)))

    def get_diagnostic_databases(self) -> tuple[DiagnosticDatabaseSummary, ...]:
        return self.diagnostic_inventory_service.databases()

    def get_diagnostic_snapshots(
        self, path: pathlib.Path | str
    ) -> tuple[DiagnosticSnapshotSummary, ...]:
        return self.diagnostic_inventory_service.snapshots(path)

    def get_diagnostic_records(
        self,
        path: pathlib.Path | str,
        snapshot_id: int,
        kind: DiagnosticViewKind,
    ) -> tuple[DiagnosticRecord, ...]:
        return self.diagnostic_inventory_service.records(path, snapshot_id, kind)

    def plan_diagnostic_selected_snapshots(
        self, path: pathlib.Path | str, snapshot_ids: typing.Sequence[int]
    ) -> DiagnosticCleanupPlan:
        return self.diagnostic_cleanup_service.plan_selected_snapshots(
            path, snapshot_ids
        )

    def plan_diagnostic_all_snapshots(
        self, path: pathlib.Path | str
    ) -> DiagnosticCleanupPlan:
        return self.diagnostic_cleanup_service.plan_all_snapshots(path)

    def plan_diagnostic_keep_latest(
        self, path: pathlib.Path | str, keep: int
    ) -> DiagnosticCleanupPlan:
        return self.diagnostic_cleanup_service.plan_keep_latest(path, keep)

    def plan_diagnostic_older_than(
        self, path: pathlib.Path | str, recorded_before: float
    ) -> DiagnosticCleanupPlan:
        return self.diagnostic_cleanup_service.plan_older_than(path, recorded_before)

    def plan_diagnostic_selected_databases(
        self, paths: typing.Iterable[pathlib.Path | str]
    ) -> DiagnosticCleanupPlan:
        return self.diagnostic_cleanup_service.plan_selected_databases(paths)

    def plan_diagnostic_all_closed_databases(
        self, paths: typing.Iterable[pathlib.Path | str]
    ) -> DiagnosticCleanupPlan:
        return self.diagnostic_cleanup_service.plan_all_closed_databases(paths)

    def plan_diagnostic_vacuum(
        self, paths: typing.Iterable[pathlib.Path | str]
    ) -> DiagnosticCleanupPlan:
        return self.diagnostic_cleanup_service.plan_vacuum(paths)

    def execute_diagnostic_cleanup(
        self,
        plan: DiagnosticCleanupPlan,
        *,
        checkpoint_wal: bool = True,
        vacuum_after: bool = False,
    ) -> DiagnosticCleanupResult:
        return self.diagnostic_cleanup_service.execute(
            plan,
            checkpoint_wal=checkpoint_wal,
            vacuum_after=vacuum_after,
        )

    def get_config_v2_serializer_manifest(self) -> tuple[ConfigV2FieldSerializer, ...]:
        return self.config_v2_editing_service.serializer_manifest()

    def create_config_v2_project_draft(
        self,
        runtime_project: object,
        *,
        destination: pathlib.Path,
    ) -> ConfigV2ProjectDraft:
        return self.config_v2_editing_service.create_draft(
            runtime_project,
            destination=destination,
        )

    def validate_config_v2_project_draft(
        self, draft: ConfigV2ProjectDraft
    ) -> ConfigV2ProjectValidation:
        return self.config_v2_editing_service.validate(draft)

    def set_config_v2_description(
        self, draft: ConfigV2ProjectDraft, description: str
    ) -> ConfigV2ProjectDraft:
        return self.config_v2_editing_service.set_description(draft, description)

    def add_config_v2_pass(
        self,
        draft: ConfigV2ProjectDraft,
        pass_id: str,
        *,
        index: int | None = None,
    ) -> ConfigV2ProjectDraft:
        return self.config_v2_editing_service.add_pass(draft, pass_id, index=index)

    def remove_config_v2_pass(
        self, draft: ConfigV2ProjectDraft, pass_index: int
    ) -> ConfigV2ProjectDraft:
        return self.config_v2_editing_service.remove_pass(draft, pass_index)

    def reorder_config_v2_pass(
        self,
        draft: ConfigV2ProjectDraft,
        pass_index: int,
        new_index: int,
    ) -> ConfigV2ProjectDraft:
        return self.config_v2_editing_service.reorder_pass(
            draft, pass_index, new_index
        )

    def set_config_v2_pass_rules(
        self,
        draft: ConfigV2ProjectDraft,
        *,
        pass_index: int,
        include: typing.Sequence[str],
        exclude: typing.Sequence[str],
        options: typing.Mapping[str, object],
    ) -> ConfigV2ProjectDraft:
        return self.config_v2_editing_service.set_pass_rules(
            draft,
            pass_index=pass_index,
            include=include,
            exclude=exclude,
            options=options,
        )

    def set_config_v2_routing_override(
        self,
        draft: ConfigV2ProjectDraft,
        *,
        prefer: typing.Mapping[str, float],
        require: str | None,
        deny: typing.Sequence[str],
    ) -> ConfigV2ProjectDraft:
        return self.config_v2_editing_service.set_routing_override(
            draft,
            prefer=prefer,
            require=require,
            deny=deny,
        )

    def materialize_recipe_as_config_v2(
        self,
        draft: ConfigV2ProjectDraft,
        recipe: PipelineRecipeDraft,
    ) -> ConfigV2ProjectDraft:
        return self.config_v2_editing_service.materialize_recipe(draft, recipe)

    def save_config_v2_project(
        self,
        draft: ConfigV2ProjectDraft,
        validation: ConfigV2ProjectValidation,
    ) -> object:
        return self.config_v2_editing_service.save(draft, validation)

    def capture_workbench_baseline(
        self,
        identity: ComparisonIdentity,
        pseudocode: str,
    ) -> BaselineRef:
        """Store one native Hex-Rays baseline as immutable evidence."""
        return self.comparison_service.capture_baseline(identity, pseudocode)

    def capture_workbench_d810_output(
        self,
        identity: ComparisonIdentity,
        pseudocode: str,
    ) -> D810OutputRef:
        """Store one normal D810 output as immutable evidence."""
        return self.comparison_service.capture_d810_output(identity, pseudocode)

    def get_workbench_comparison(
        self,
        identity: ComparisonIdentity,
    ) -> WorkbenchComparisonSnapshot:
        """Compare captured evidence only when its full identity is current."""
        return self.comparison_service.compare(identity)

    def get_workbench_recipe_catalog(self) -> tuple[PassCatalogEntry, ...]:
        return self.recipe_service.catalog()

    def create_workbench_recipe_draft(
        self,
        snapshot: DeobfuscationWorkbenchSnapshot,
        runtime_project: object,
    ) -> PipelineRecipeDraft:
        return self.recipe_service.create_draft(
            function_ea=snapshot.function.ea,
            function_fingerprint=snapshot.function.fingerprint,
            workbench_generation=snapshot.generation,
            source_path=snapshot.runtime.source_path,
            runtime_path=snapshot.runtime.runtime_path,
            configs=pipeline_configs_from_project_config(runtime_project),
        )

    def validate_workbench_recipe(
        self,
        draft: PipelineRecipeDraft,
        *,
        facts: object | None = None,
    ) -> RecipeValidation:
        return self.recipe_service.validate(draft, facts=facts)

    def add_workbench_recipe_pass(
        self,
        draft: PipelineRecipeDraft,
        pass_id: str,
    ) -> PipelineRecipeDraft:
        return self.recipe_service.add_pass(draft, pass_id)

    def remove_workbench_recipe_pass(
        self,
        draft: PipelineRecipeDraft,
        item_id: str,
    ) -> PipelineRecipeDraft:
        return self.recipe_service.remove_pass(draft, item_id)

    def set_workbench_recipe_pass_enabled(
        self,
        draft: PipelineRecipeDraft,
        item_id: str,
        enabled: bool,
    ) -> PipelineRecipeDraft:
        return self.recipe_service.set_enabled(draft, item_id, enabled)

    def reorder_workbench_recipe_pass(
        self,
        draft: PipelineRecipeDraft,
        item_id: str,
        new_index: int,
    ) -> PipelineRecipeDraft:
        return self.recipe_service.reorder_pass(draft, item_id, new_index)

    def replace_workbench_recipe_pass_options(
        self,
        draft: PipelineRecipeDraft,
        item_id: str,
        options: typing.Mapping[str, object],
    ) -> PipelineRecipeDraft:
        return self.recipe_service.replace_options(draft, item_id, options)

    def get_workbench_function_recipe(
        self,
        function_ea: int,
    ) -> FunctionPipelineOverride | None:
        return self.function_recipe_runtime.get(function_ea)

    def save_workbench_function_recipe(
        self,
        draft: PipelineRecipeDraft,
        validation: RecipeValidation,
    ) -> FunctionPipelineOverride:
        pass_configs_json = self.recipe_service.serialize_enabled_configs(draft)
        return self.function_recipe_runtime.save(
            draft,
            validation,
            pass_configs_json=pass_configs_json,
        )

    def clear_workbench_function_recipe(self, function_ea: int) -> bool:
        return self.function_recipe_runtime.clear(function_ea)

    def execute_workbench_apply_recipe_once(
        self,
        request: RecipeCommandRequest,
        draft: PipelineRecipeDraft,
        validation: RecipeValidation,
        *,
        lifecycle: typing.Callable[[PipelineRecipeDraft], bool],
    ) -> RecipeCommandResult:
        return self.recipe_command_service.execute_apply_once(
            request,
            draft,
            validation,
            lifecycle=lifecycle,
        )

    def execute_workbench_save_function_recipe(
        self,
        request: RecipeCommandRequest,
        draft: PipelineRecipeDraft,
        validation: RecipeValidation,
    ) -> RecipeCommandResult:
        return self.recipe_command_service.execute_save(
            request,
            draft,
            validation,
            persistence=self.save_workbench_function_recipe,
        )

    def get_workbench_snapshot(
        self,
        *,
        function_ea: int,
        function_name: str,
        function_fingerprint: str | None,
        project_snapshot: ProjectRuntimeSnapshot,
        runtime_project: typing.Any,
        facts: typing.Any | None = None,
        baseline: BaselineRef | None = None,
        latest_output: D810OutputRef | None = None,
    ) -> DeobfuscationWorkbenchSnapshot:
        """Collect one immutable read-only workbench snapshot."""
        return self.workbench_service.collect(
            function_ea=function_ea,
            function_name=function_name,
            function_fingerprint=function_fingerprint,
            project_snapshot=project_snapshot,
            runtime_project=runtime_project,
            facts=facts,
            baseline=baseline,
            latest_output=latest_output,
        )

    def analyze_workbench_function(
        self,
        *,
        function_ea: int,
        target: object,
        provider_phase: object,
    ) -> object:
        """Collect and classify recon evidence without applying any rewrite."""
        if self._recon_runtime is None:
            raise RuntimeError("Recon runtime is not available")
        return self._recon_runtime.collect_and_analyze(
            int(function_ea),
            target,
            provider_phase,
            persist_hints=True,
        )

    def configure(self, **kwargs):
        self.config = kwargs
        self.rule_scope_runtime.configure(kwargs)
        self._load_function_analysis_priors_from_config(
            kwargs.get("function_analysis_priors", {})
        )

    @staticmethod
    def _create_rule_scope_storage(target, *, backend: str = "sqlite"):
        from d810.core.persistence import create_optimization_storage

        return create_optimization_storage(target, backend=backend)

    @staticmethod
    def _coerce_module_names(value: typing.Any) -> tuple[str, ...]:
        if value is None:
            return ()
        if isinstance(value, str):
            items = (value,)
        else:
            try:
                items = tuple(value)
            except TypeError:
                items = (value,)
        return tuple(
            dict.fromkeys(
                str(item).strip()
                for item in items
                if str(item).strip()
            )
        )

    def _load_recon_fact_profile_modules(self) -> None:
        for module_name in self._coerce_module_names(
            self.config.get("recon_fact_profile_modules")
        ):
            try:
                importlib.import_module(module_name)
            except Exception:
                logger.exception(
                    "Recon fact profile module load failed: %s",
                    module_name,
                )

    def _load_function_analysis_priors_from_config(self, raw: typing.Any) -> None:
        self._function_analysis_priors = load_function_analysis_priors_from_config(raw)

    def snapshot_function_analysis_priors(self) -> dict[str, FunctionAnalysisPriors]:
        return dict(self._function_analysis_priors)

    def restore_function_analysis_priors(
        self,
        snapshot: dict[str, FunctionAnalysisPriors] | None,
    ) -> None:
        self._function_analysis_priors = dict(snapshot or {})

    def add_function_analysis_priors(
        self,
        function: str | int,
        priors: FunctionAnalysisPriors,
    ) -> None:
        existing = self.function_analysis_priors(function)
        merged = existing.merge(priors)
        for key in function_prior_keys(function):
            self._function_analysis_priors[key] = merged

    def function_analysis_priors(self, function: str | int) -> FunctionAnalysisPriors:
        for key in function_prior_keys(function):
            priors = self._function_analysis_priors.get(key)
            if priors is not None:
                return priors
        return FunctionAnalysisPriors()

    def function_analysis_priors_for_ea(self, func_ea: int) -> FunctionAnalysisPriors:
        identifiers: list[str | int] = [int(func_ea)]
        try:
            import ida_name

            name = ida_name.get_name(int(func_ea))
        except Exception:
            name = ""
        if name:
            identifiers.append(str(name))

        priors = FunctionAnalysisPriors()
        for identifier in identifiers:
            priors = priors.merge(self.function_analysis_priors(identifier))
        return priors

    def emit_rule_scope_invalidation(
        self,
        reason: RuleScopeEvent,
        *,
        project_name: str | None = None,
        func_eas: frozenset[int] | None = None,
        changed_rules: frozenset[str] | None = None,
    ) -> None:
        self.event_emitter.emit(
            reason,
            RuleScopeInvalidation(
                reason=reason,
                project_name=project_name,
                func_eas=func_eas,
                changed_rules=changed_rules,
            ),
        )

    @property
    def is_profiling(self) -> bool:
        return self.profiling.is_running

    def start_profiling(self):
        self.profiling.start()

    def stop_profiling(self) -> pathlib.Path | None:
        return self.profiling.stop()

    def enable_profiling(self):
        self.profiling.enable()

    def disable_profiling(self):
        self.profiling.disable()

    def dump_profiling_segment(self, new_maturity: int) -> None:
        self.profiling.dump_segment(_maturity_name(new_maturity))

    def _ensure_post_d810_runtime(self) -> HexRaysPostD810Runtime:
        if self._post_d810_runtime is None:
            self._post_d810_runtime = HexRaysPostD810Runtime(
                recon_runtime=self._recon_runtime,
                block_optimizer=self.block_optimizer,
                maturity_name_provider=_maturity_name,
                handoff_detector=detect_post_d810_handoff_violations,
            )
        return self._post_d810_runtime

    def capture_post_d810_mba(
        self,
        mba: typing.Any,
        maturity: int,
        snapshot: typing.Any = None,
    ) -> None:
        self._ensure_post_d810_runtime().capture_mba(mba, maturity, snapshot)

    def capture_post_d810_facts(
        self,
        mba: typing.Any,
        maturity: int,
        snapshot: typing.Any = None,
    ) -> None:
        self._ensure_post_d810_runtime().capture_facts(mba, maturity, snapshot)

    def _resolve_post_d810_linearization_context(
        self,
        mba: typing.Any,
        target_maturity: int,
    ) -> tuple[int | None, int | None]:
        return self._ensure_post_d810_runtime().resolve_linearization_context(
            mba,
            target_maturity,
        )

    def attach_post_d810_rendered_program(
        self,
        mba: typing.Any,
        maturity: int,
        snapshot: typing.Any = None,
    ) -> None:
        self._ensure_post_d810_runtime().attach_rendered_program(
            mba,
            maturity,
            snapshot,
        )

    def probe_post_d810_glbopt_dce(
        self,
        mba: typing.Any,
        maturity: int,
        snapshot: typing.Any = None,
    ) -> None:
        self._ensure_post_d810_runtime().probe_glbopt_dce(mba, maturity, snapshot)

    def validate_post_d810_handoff(
        self,
        mba: typing.Any,
        maturity: int,
        snapshot: typing.Any = None,
    ) -> None:
        self._ensure_post_d810_runtime().validate_handoff(mba, maturity, snapshot)

    def start(self):
        if self._started:
            self.stop()
        logger.debug("Starting manager...")
        load_optimizer_registries()
        # Ensure side-effect registrants are loaded before manager construction.
        from d810.optimizers.microcode.instructions.pattern_matching import (  # noqa: F401
            experimental,
        )

        try:
            from d810.mba.backend_registry import get_egglog_provider

            if bool(get_egglog_provider("egglog").is_available()):
                from d810.optimizers.microcode.flow.egraph import (  # noqa: F401
                    block_optimizer,
                )
                from d810.optimizers.microcode.instructions.egraph import (  # noqa: F401
                    egglog_handler,
                )
        except ImportError:
            pass

        self.rule_scope_service.attach(self.event_emitter)
        self._init_storage()
        self.rule_scope_service.set_overlay_provider(self._get_rule_overlay)
        self.rule_scope_service.set_active_inference(
            self.rule_scope_runtime.active_rule_inference
        )
        self.rule_scope_service.register_inference("unflattening", unflattening_inference)

        # Instantiate core manager classes from registry
        self.instruction_optimizer = InstructionOptimizerManager(
            self.stats, self.log_dir, optimizer_cls=InstructionOptimizer
        )
        project_name = str(self.config.get("project_name", ""))
        idb_key = str(self.config.get("idb_key", project_name))
        self.instruction_optimizer.configure(
            **self.instruction_optimizer_config,
            rule_scope_service=self.rule_scope_service,
            rule_scope_project_name=project_name,
            rule_scope_idb_key=idb_key,
            pass_scheduler=self.instruction_pass_scheduler,
        )
        self.block_optimizer = BlockOptimizerManager(
            self.stats, self.log_dir, ctx_cls=FlowMaturityContext
        )
        self.block_optimizer.configure(
            **self.block_optimizer_config,
            rule_scope_service=self.rule_scope_service,
            rule_scope_project_name=project_name,
            rule_scope_idb_key=idb_key,
            pass_scheduler=self.block_pass_scheduler,
            function_priors_provider=self.function_analysis_priors_for_ea,
            dispatcher_artifact_planner=plan_dispatcher_state_return_carrier_artifact,
        )
        for rule in self.instruction_optimizer_rules:
            rule.log_dir = self.log_dir
            self.instruction_optimizer.add_rule(rule)

        for cfg_rule in self.block_optimizer_rules:
            cfg_rule.log_dir = self.log_dir
            self.block_optimizer.add_rule(cfg_rule)

        # Build PassPipeline when feature flag is enabled (default OFF), or when
        # the explicit loop-carrier experiment is requested. Zero overhead when
        # both are disabled - no imports of pass modules occur.
        _pass_pipeline = None
        _pass_pipeline_spec = pass_pipeline_spec_from_config(self.config)
        if _pass_pipeline_spec is not None:
            _pass_pipeline = self._build_pass_pipeline(spec=_pass_pipeline_spec)

        # Build ReconPhase when feature flag is enabled (default ON).
        # Passive collection with minimal overhead; disable with
        # "enable_recon_pipeline": false in project config.
        self._recon_bundle = None
        self._recon_phase = None
        self._recon_runtime = None
        if self.config.get("enable_recon_pipeline", True):
            self._recon_bundle = build_recon_runtime_bundle(
                log_dir=self.log_dir,
                config=dict(self.config),
            )
            if self._recon_bundle is not None:
                self._recon_phase = self._recon_bundle.recon_phase
                self._recon_runtime = self._recon_bundle.recon_runtime

        # Wire recon phase + runtime into microcode optimizers.
        # The runtime provides reset_for_func() at decompilation start;
        # the phase dispatches collectors at each maturity.
        if self._recon_runtime is not None:
            # LS10: register the Hex-Rays live SourceLifter (import-time side
            # effect) before the induction collector runs, so a raw mba handed
            # directly to a collector can be lifted to a portable fact target.
            # Lazy import -- backends.facts.ida pulls ida_hexrays via
            # d810.hexrays.fact_target, so a module-top import would break
            # unit-test collectability of d810.manager. Dormant for the portable
            # targets the live pipeline passes today (FlowGraph / fact target).
            try:
                # Explicit idempotent ensure() through the backend registration
                # helper: a sys.modules-cached module would make re-import a
                # no-op and leave the registry empty after a
                # reset_live_lifters_for_tests().
                ensure_hexrays_fact_lifter_registered()
            except Exception:
                logger.exception("Hex-Rays live SourceLifter registration failed")
            self._load_recon_fact_profile_modules()
            emit_recon_fact_collector_registration(
                runtime=self._recon_runtime,
                project_config=dict(self.config),
            )
            self.instruction_optimizer.configure(
                recon_phase=self._recon_phase,
                recon_runtime=self._recon_runtime,
            )
            self.block_optimizer.configure(
                recon_phase=self._recon_phase,
                recon_runtime=self._recon_runtime,
            )

        # Wire PassPipeline into BlockOptimizerManager so it fires at
        # MMAT_GLBOPT2, after the unflattener has run at MMAT_GLBOPT1.
        if _pass_pipeline is not None:
            self.block_optimizer.configure(pass_pipeline=_pass_pipeline)

        # Build ctree optimizer with recon phase and runtime from the start.
        self.ctree_optimizer = CtreeOptimizerManager(
            self.stats,
            recon_phase=self._recon_phase,
            recon_runtime=self._recon_runtime,
        )

        for ctree_rule in self.ctree_optimizer_rules:
            ctree_rule.log_dir = self.log_dir
            self.ctree_optimizer.add_rule(ctree_rule)

        self.hx_decompiler_hook = HexraysDecompilationHook(
            self.event_emitter.emit,
            ctree_optimizer_manager=self.ctree_optimizer,
            block_optimizer=self.block_optimizer,
        )
        self._post_d810_runtime = None
        self._compile_rule_scope()
        self._install_hooks()
        self._started = True

    def _init_storage(self) -> None:
        self.rule_scope_runtime.initialize_storage()

    def _load_active_inference_from_storage(self) -> None:
        self.rule_scope_runtime.load_active_inference_from_storage()

    def _get_rule_overlay(self, function_ea: int) -> FunctionRuleOverlay | None:
        return self.rule_scope_runtime.get_rule_overlay(function_ea)

    def get_function_rule_override(self, function_addr: int):
        return self.rule_scope_runtime.get_function_rule_override(function_addr)

    def set_function_rule_override(
        self,
        *,
        function_addr: int,
        enabled_rules: typing.Optional[typing.Set[str]] = None,
        disabled_rules: typing.Optional[typing.Set[str]] = None,
        notes: str = "",
    ) -> None:
        self.rule_scope_runtime.set_function_rule_override(
            function_addr=function_addr,
            enabled_rules=enabled_rules,
            disabled_rules=disabled_rules,
            notes=notes,
        )

    def clear_function_rule_override(self, function_addr: int) -> None:
        self.rule_scope_runtime.clear_function_rule_override(function_addr)

    def get_function_tags(self, function_addr: int) -> set[str]:
        return self.rule_scope_runtime.get_function_tags(function_addr)

    def set_function_tags(
        self,
        *,
        function_addr: int,
        tags: typing.Optional[typing.Set[str]] = None,
    ) -> None:
        self.rule_scope_runtime.set_function_tags(
            function_addr=function_addr,
            tags=tags,
        )

    def set_active_rule_inference(
        self,
        *,
        inference_name: str,
        enabled_rules: typing.Optional[typing.Set[str]] = None,
        disabled_rules: typing.Optional[typing.Set[str]] = None,
        target_func_eas: typing.Optional[typing.Set[int]] = None,
        target_tags_any: typing.Optional[typing.Set[str]] = None,
        target_tags_all: typing.Optional[typing.Set[str]] = None,
        notes: str = "",
    ) -> None:
        self.rule_scope_runtime.set_active_rule_inference(
            inference_name=inference_name,
            enabled_rules=enabled_rules,
            disabled_rules=disabled_rules,
            target_func_eas=target_func_eas,
            target_tags_any=target_tags_any,
            target_tags_all=target_tags_all,
            notes=notes,
        )

    def clear_active_rule_inference(self) -> None:
        self.rule_scope_runtime.clear_active_rule_inference()

    def get_active_rule_inference(self) -> RuleInferenceOverlay | None:
        return self.rule_scope_runtime.get_active_rule_inference()

    def _compile_rule_scope(self) -> None:
        self.rule_scope_service.compile_base_rules(
            project_name=str(self.config.get("project_name", "")),
            instruction_rules=self.instruction_optimizer_rules,
            flow_rules=self.block_optimizer_rules,
            ctree_rules=self.ctree_optimizer_rules,
        )

    def _start_timer(self):
        self.profiling.start_timer()

    def _stop_timer(self, report: bool = True):
        self.profiling.stop_timer(report=report)

    def _install_hooks(self):
        # must become before listeners are installed
        for _subscriber in (
            self.start_profiling,
            self.stats.reset,
            MOP_CONSTANT_CACHE.clear,
            MOP_TO_AST_CACHE.clear,
            Z3MopProver().clear_caches,
            self.instruction_optimizer.reset_cycle_detection,
            self.instruction_optimizer.reset_run_later_state,
            self.block_optimizer.reset_pass_counter,
            self.block_optimizer.reset_pipeline_tracker,
            self.block_optimizer.reset_perf_counters,
            self._start_timer,
        ):
            self.event_emitter.on(DecompilationEvent.STARTED, _subscriber)

        for _subscriber in (
            self.stop_profiling,
            self.stats.report,
            lambda: logger.info(
                "MOP_CONSTANT_CACHE stats: %s", MOP_CONSTANT_CACHE.stats
            ),
            lambda: logger.info("MOP_TO_AST_CACHE stats: %s", MOP_TO_AST_CACHE.stats),
            self.block_optimizer.report_perf_counters,
            self._stop_timer,
        ):
            self.event_emitter.on(DecompilationEvent.FINISHED, _subscriber)

        if self._recon_runtime is not None:
            self.event_emitter.on(
                DecompilationEvent.FINISHED,
                self._recon_runtime.mark_decompilation_finished,
            )

        # E4a/E4b: single shared FLOWGRAPH_READY subscriber for the
        # portable microcode analysis path.  Both manager maturity
        # gates emit this event for the same ``(func_ea, maturity)``;
        # ``ReconPhase.run_microcode_collectors`` dedupes by
        # ``(func_ea, maturity)`` internally, while pre-D810 fact
        # capture runs through the same portable FlowGraph payload
        # whether or not a diagnostic snapshot is attached.
        if self._recon_phase is not None or self._recon_runtime is not None:
            self._flowgraph_ready_subscriber = FlowGraphReadySubscriber(
                recon_phase=self._recon_phase,
                recon_runtime=self._recon_runtime,
                provider_name=HEXRAYS_MICROCODE_PROVIDER,
            )
            self.event_emitter.on(
                DecompilationEvent.FLOWGRAPH_READY,
                self._flowgraph_ready_subscriber,
            )

        from d810.hexrays.preanalysis.flowchart_preanalysis import (
            run_flowchart_preanalysis_handlers,
        )

        self.event_emitter.on(
            DecompilationEvent.HEXRAYS_FLOWCHART_READY,
            run_flowchart_preanalysis_handlers,
        )

        from d810.hexrays.preanalysis.preopt_preanalysis import (
            run_preopt_preanalysis_handlers,
        )

        self.event_emitter.on(
            DecompilationEvent.HEXRAYS_PREOPT_READY,
            run_preopt_preanalysis_handlers,
        )

        from d810.hexrays.preanalysis.locopt_preanalysis import (
            run_locopt_preanalysis_handlers,
        )

        self.event_emitter.on(
            DecompilationEvent.HEXRAYS_LOCOPT_READY,
            run_locopt_preanalysis_handlers,
        )

        from d810.hexrays.preanalysis.callinfo_preanalysis import (
            run_callinfo_preanalysis_handlers,
        )

        self.event_emitter.on(
            DecompilationEvent.HEXRAYS_BUILD_CALLINFO,
            run_callinfo_preanalysis_handlers,
        )

        from d810.hexrays.preanalysis.calls_done_preanalysis import (
            run_calls_done_preanalysis_handlers,
        )

        self.event_emitter.on(
            DecompilationEvent.HEXRAYS_CALLS_DONE,
            run_calls_done_preanalysis_handlers,
        )

        self.event_emitter.on(
            DecompilationEvent.MATURITY_CHANGED, self.dump_profiling_segment
        )
        self.event_emitter.on(
            DecompilationEvent.POST_D810_CAPTURE,
            self._ensure_post_d810_runtime().capture_mba,
        )
        self.event_emitter.on(
            DecompilationEvent.POST_D810_CAPTURE,
            self._ensure_post_d810_runtime().attach_rendered_program,
        )
        self.event_emitter.on(
            DecompilationEvent.POST_D810_CAPTURE,
            self._ensure_post_d810_runtime().validate_handoff,
        )
        self.event_emitter.on(
            DecompilationEvent.POST_D810_CAPTURE,
            self._ensure_post_d810_runtime().probe_glbopt_dce,
        )

        self.instruction_optimizer.event_emitter = self.event_emitter
        self.block_optimizer.event_emitter = self.event_emitter
        self.instruction_optimizer.install()
        self.block_optimizer.install()
        self.hx_decompiler_hook.hook()

    def _build_pass_pipeline(
        self,
        *,
        spec: PassPipelineSpec | None = None,
        include_default_cleanup: bool = True,
        enable_loop_carrier_backedge_refresh: bool = False,
    ):
        """Compatibility delegate for constructing the Hex-Rays pass pipeline."""
        if spec is None:
            spec = build_pass_pipeline_spec(
                include_default_cleanup=include_default_cleanup,
                enable_loop_carrier_backedge_refresh=enable_loop_carrier_backedge_refresh,
            )

        def _fact_view_provider(func_ea: int, maturity: int | str):
            if self._recon_runtime is None:
                return None
            if isinstance(maturity, int):
                maturity = _maturity_name(maturity)
            return self._recon_runtime.validated_fact_view(func_ea, maturity)

        pipeline = build_hexrays_flowgraph_pipeline(
            spec,
            fact_view_provider=_fact_view_provider,
        )
        logger.info(
            "PassPipeline enabled: %s",
            repr(pipeline),
        )
        return pipeline

    def _build_recon_phase(self):
        """Compatibility delegate for callers that still build only a phase."""
        return build_recon_phase(self.log_dir)

    def configure_instruction_optimizer(self, rules, **kwargs):
        self.instruction_optimizer_rules = list(rules)
        self.instruction_optimizer_config = kwargs

    def configure_block_optimizer(self, rules, **kwargs):
        self.block_optimizer_rules = list(rules)
        self.block_optimizer_config = kwargs

    def configure_ctree_optimizer(self, rules, **kwargs):
        self.ctree_optimizer_rules = list(rules)
        self.ctree_optimizer_config = kwargs

    def stop(self):
        if not self._started:
            return
        self._started = False

        self.instruction_optimizer.remove()
        self.block_optimizer.remove()
        self.hx_decompiler_hook.unhook()
        shutdown_all_writers()
        self.event_emitter.clear()
        self.stop_profiling()
        self.rule_scope_runtime.close()
        if self._recon_bundle is not None:
            self._recon_bundle.close()
            self._recon_bundle = None
        elif self._recon_phase is not None:
            try:
                self._recon_phase._store.close()
            except Exception:
                pass
        self._recon_phase = None
        self._recon_runtime = None


@contextlib.contextmanager
def d810_hooks_suppressed(manager: D810Manager):
    """Temporarily suppress d810ng optimization hooks for clean decompilation.

    Used to get pre-deobfuscation microcode snapshots by decompiling
    with d810ng hooks temporarily removed.

    Args:
        manager: The D810Manager instance whose hooks should be temporarily removed.

    Yields:
        None

    Example:
        >>> with d810_hooks_suppressed(state.manager):
        ...     # Decompile with hooks disabled to get pre-deobfuscation state
        ...     mba = gen_microcode(func_ea, maturity)
    """
    if not manager.started:
        # If manager not started, hooks aren't installed anyway
        yield
        return

    # Remove optimizer hooks
    manager.instruction_optimizer.remove()
    manager.block_optimizer.remove()
    try:
        yield
    finally:
        # Restore optimizer hooks
        manager.instruction_optimizer.install()
        manager.block_optimizer.install()


from d810.manager.state import D810State  # noqa: E402
