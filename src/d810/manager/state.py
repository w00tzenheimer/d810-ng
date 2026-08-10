"""Runtime project state for the D810 plugin."""

from __future__ import annotations

import contextlib
import inspect
import importlib
import pathlib

from d810.backends.hexrays.registration import register_hexrays_backend_providers
from d810.hexrays.utils.ida_utils import ensure_hexrays_available
from d810.backends.mba.ida import adapt_rules
from d810.core import typing
from d810.core.config import (
    D810Configuration,
    ProjectConfiguration,
)
from d810.core.config_v2_defaults import (
    ConfigV2DefaultSelection,
    format_config_v2_default_selection_status,
    select_config_v2_default_project,
)
from d810.core.deobfuscation_case import DeobfuscationCaseEvidence
from d810.core.diagnostics_capture_preferences import (
    diagnostics_capture_enabled,
    enable_diagnostics_capture,
)
from d810.core.logging import clear_logs, configure_loggers, getLogger
from d810.core.platform import resolve_arch_config
from d810.core.project import (
    ProjectContext,
    ProjectManager,
    emit_project_reloading,
)
from d810.core.registry import SingletonMeta
from d810.core.execution_scope import ExecutionScopeEvent
from d810.core.stats import OptimizationStatistics
from d810.core.settings import configure_settings, get_settings
from d810.core.typing import TYPE_CHECKING
from d810.diagnostics.workbench_models import (
    DiagnosticCleanupPlan,
    DiagnosticCleanupResult,
    DiagnosticDatabaseSummary,
    DiagnosticRecord,
    DiagnosticSnapshotSummary,
    DiagnosticViewKind,
)
from d810.mba.rules import VerifiableRule
from d810.manager.project_runtime import (
    ProjectRuntimeSnapshot,
    build_project_runtime_snapshot,
    clone_runtime_project as clone_runtime_project_command,
)
from d810.core.function_storage_config import (
    FunctionStorageConfigurationError,
    parse_function_recipe_storage,
)
from d810.manager.config_v2_edit_models import (
    ConfigV2FieldSerializer,
    ConfigV2ProjectDraft,
    ConfigV2ProjectValidation,
)
from d810.passes.function_recipe_runtime import (
    activate_function_recipe_runtime,
    build_recipe_runtime_project,
)
from d810.manager.workbench_models import (
    BaselineRef,
    D810OutputRef,
    DeobfuscationWorkbenchSnapshot,
    WorkbenchCommandRequest,
    WorkbenchCommandResult,
    WorkbenchComparisonSnapshot,
)
from d810.manager.workbench_recipe_models import (
    FunctionPipelineOverride,
    PassCatalogEntry,
    PipelineRecipeDraft,
    RecipeValidation,
    RecipeCommandRequest,
    RecipeCommandResult,
)
from d810.optimizers.microcode.flow.handler import FlowOptimizationRule
from d810.optimizers.microcode.instructions.handler import InstructionOptimizationRule
from d810.passes.pipeline_v2_hook_bridge import pipeline_v2_hook_activation
from d810.passes.state_machine_options import StateMachineCffOptions

if TYPE_CHECKING:
    from d810.manager import D810Manager
    from d810.manager.workbench_comparison import ComparisonIdentity
    from d810.ui.ida_ui import D810GUI

logger = getLogger("d810")
D810_LOG_DIR_NAME = "d810_logs"


class D810State(metaclass=SingletonMeta):
    """
    State class representing the runtime state of the D810 plugin.

    This class is responsible for managing the configuration, the project
    manager, the current project, the current instruction and block rules,
    the known instruction and block rules, and the D810 manager.

    It also provides a GUI for the plugin.
    """

    # placeholders for runtime state
    log_dir: pathlib.Path
    manager: D810Manager
    gui: D810GUI
    current_project: ProjectConfiguration
    current_runtime_project: ProjectConfiguration | None

    def __init__(self):
        self.gui = None  # Set by load(gui=True)
        self.reset()

    def is_loaded(self):
        return self._is_loaded

    @property
    def stats(self) -> OptimizationStatistics:
        """Forward stats access to the manager."""
        if hasattr(self, "manager") and self.manager is not None:
            return self.manager.stats
        return OptimizationStatistics()

    def reset(self, d810_config: D810Configuration | None = None) -> None:
        self._initialized: bool = False
        self.d810_config: D810Configuration = d810_config or D810Configuration()
        self._apply_diagnostics_capture_preference()
        self.project_manager = ProjectManager(self.d810_config)
        self.current_project_index: int = 0
        self.current_ins_rules: typing.List = []
        self.current_blk_rules: typing.List = []
        self.known_ins_rules: typing.List = []
        self.known_blk_rules: typing.List = []
        self.last_pipeline_v2_hook_pass_ids: tuple[str, ...] = ()
        self.last_pipeline_v2_hook_mode: str | None = None
        self.last_config_v2_default_selection: ConfigV2DefaultSelection | None = None
        #: ``project file name -> one-line reason`` for every project whose
        #: activation raised.  A malformed project is SKIPPED, never fatal, so one
        #: bad file in the config directory cannot leave the plugin with no
        #: project at all (ticket lpccp-8c87).
        self.invalid_projects: dict[str, str] = {}
        self.current_runtime_project: ProjectConfiguration | None = None
        self.current_project_runtime_snapshot: ProjectRuntimeSnapshot | None = None
        self._is_loaded: bool = False
        self.gui = None
        self.log_dir = self.d810_config.log_dir / D810_LOG_DIR_NAME
        if self.d810_config.get("erase_logs_on_reload"):
            clear_logs(self.log_dir)
        configure_loggers(self.log_dir)
        manager_module = importlib.import_module("d810.manager")
        self.manager = manager_module.D810Manager(self.log_dir)
        self.function_storage_configuration_error: str | None = None
        try:
            storage_config = parse_function_recipe_storage(
                self.d810_config.get("function_recipe_storage"),
                log_dir=self.log_dir,
            )
        except FunctionStorageConfigurationError as exc:
            self.function_storage_configuration_error = str(exc)
            logger.error("Function recipe storage is disabled: %s", exc)
            self.manager.reconfigure_function_storage(None)
        else:
            self.manager.reconfigure_function_storage(storage_config)
        self._initialized = True

    def _apply_diagnostics_capture_preference(self) -> None:
        """Reapply the persisted global capture preference after reload."""
        configure_settings(
            diag_snapshots=diagnostics_capture_enabled(
                self.d810_config,
                runtime_default=get_settings().diag_snapshots,
            )
        )

    def diagnostics_capture_enabled(self) -> bool:
        return bool(get_settings().diag_snapshots)

    def enable_diagnostics_capture(self) -> bool:
        enabled = enable_diagnostics_capture(self.d810_config)
        configure_settings(diag_snapshots=enabled)
        refresh = getattr(
            getattr(getattr(self, "gui", None), "d810_config_form", None),
            "_update_diagnostics_capture_indicator",
            None,
        )
        if callable(refresh):
            refresh()
        return enabled

    def add_project(self, config: ProjectConfiguration):
        self.project_manager.add(config)

    def update_project(
        self, old_config: ProjectConfiguration, new_config: ProjectConfiguration
    ):
        self.project_manager.update(old_config.path.name, new_config)

    def del_project(self, config: ProjectConfiguration):
        self.project_manager.delete(config)

    def load_project(self, project_index: int) -> ProjectConfiguration | None:
        """Activate one project, or return ``None`` when it is malformed.

        A project whose routing/pipeline payload cannot be resolved is recorded in
        :attr:`invalid_projects` and SKIPPED.  It must never abort the caller:
        ``load()`` enumerates every file in the config directory, so one bad
        project used to leave the plugin with no project at all (lpccp-8c87).
        """
        next_project = self.project_manager.get(project_index)
        try:
            default_selection = select_config_v2_default_project(next_project)
            runtime_project = (
                default_selection.runtime_project
                if default_selection is not None
                else next_project
            )
            activated = self._activate_runtime_project(
                project_index=project_index,
                source_project=next_project,
                runtime_project=runtime_project,
                default_selection=default_selection,
            )
        except Exception as exc:  # noqa: BLE001 - any malformed project is skippable
            self._record_invalid_project(next_project, exc)
            return None
        self.invalid_projects.pop(next_project.path.name, None)
        return activated

    def _load_first_valid_project(
        self, preferred_index: int
    ) -> ProjectConfiguration | None:
        """Activate *preferred_index*, else the first project that activates.

        The persisted ``last_project_index`` can point at a file that has since
        become malformed.  Falling back keeps the plugin usable instead of idle,
        and every skipped project is reported in :attr:`invalid_projects`.
        """
        total = len(self.project_manager)
        if total <= 0:
            return None
        order = [preferred_index] + [i for i in range(total) if i != preferred_index]
        for index in order:
            project = self.load_project(index)
            if project is not None:
                if index != preferred_index:
                    logger.warning(
                        "Project index %d is unusable; fell back to %d (%s)",
                        preferred_index,
                        index,
                        project.path.name,
                    )
                return project
        return None

    def _record_invalid_project(
        self, project: ProjectConfiguration, exc: BaseException
    ) -> None:
        """Mark *project* unusable and say why, without taking the plugin down."""
        name = project.path.name
        reason = f"{type(exc).__name__}: {exc}"
        self.invalid_projects[name] = reason
        logger.warning(
            "Skipping malformed project configuration %s: %s", project.path, reason
        )
        logger.debug("project activation traceback for %s", project.path, exc_info=True)

    def _activate_runtime_project(
        self,
        *,
        project_index: int,
        source_project: ProjectConfiguration,
        runtime_project: ProjectConfiguration,
        default_selection: ConfigV2DefaultSelection | None,
    ) -> ProjectConfiguration:
        """Configure one explicit source/runtime pair without rediscovering it."""
        # Resolve the hook activation BEFORE touching any state: it is the step
        # that validates the pipeline payload and therefore the step that can
        # raise.  Doing it first keeps a malformed project from leaving the
        # previous project half-replaced (lpccp-8c87).
        hook_activation = pipeline_v2_hook_activation(runtime_project)

        old_project_name = (
            self.current_project.path.name
            if getattr(self, "current_project", None) is not None
            else None
        )
        next_project = source_project
        emit_project_reloading(
            old_project_name=old_project_name,
            new_project_name=next_project.path.name,
        )
        self.current_project_index = project_index
        self.current_project = next_project
        self.current_runtime_project = runtime_project
        self.current_ins_rules = []
        self.current_blk_rules = []
        self.last_pipeline_v2_hook_pass_ids = ()
        self.last_pipeline_v2_hook_mode = None
        self.last_config_v2_default_selection = default_selection

        if default_selection is not None:
            logger.info(
                "%s",
                format_config_v2_default_selection_status(
                    selection=default_selection,
                ),
            )

        if hook_activation.enabled:
            self.last_pipeline_v2_hook_mode = "config-v2"
            self.last_pipeline_v2_hook_pass_ids = hook_activation.configured_pass_ids
            project_ins_rules = hook_activation.instruction_rules
            project_blk_rules = hook_activation.block_rules
        else:
            project_ins_rules = tuple(runtime_project.ins_rules)
            project_blk_rules = tuple(runtime_project.blk_rules)

        self.current_project_runtime_snapshot = build_project_runtime_snapshot(
            source_project=self.current_project,
            runtime_project=runtime_project,
            default_selection=default_selection,
            hook_activation=hook_activation,
            hook_mode=self.last_pipeline_v2_hook_mode,
        )

        for rule in self.known_ins_rules:
            for rule_conf in project_ins_rules:
                if not rule_conf.is_activated:
                    continue
                if rule.name == rule_conf.name:
                    effective_config = resolve_arch_config(rule_conf.config)
                    effective_config["dump_intermediate_microcode"] = (
                        self.d810_config.get("dump_intermediate_microcode")
                    )
                    rule.configure(effective_config)
                    rule.set_log_dir(self.log_dir)
                    self.current_ins_rules.append(rule)
        logger.debug("Instruction rules configured")
        for blk_rule in self.known_blk_rules:
            for rule_conf in project_blk_rules:
                if not rule_conf.is_activated:
                    continue
                if blk_rule.name == rule_conf.name:
                    effective_config = resolve_arch_config(rule_conf.config)
                    effective_config["dump_intermediate_microcode"] = (
                        self.d810_config.get("dump_intermediate_microcode")
                    )
                    blk_rule.configure(effective_config)
                    blk_rule.set_log_dir(self.log_dir)
                    self.current_blk_rules.append(blk_rule)
        logger.debug("Block rules configured")
        cfg = dict(runtime_project.additional_configuration)
        cfg.setdefault("project_name", self.current_project.path.name)
        cfg.setdefault("runtime_project_name", runtime_project.path.name)
        self.manager.configure(**cfg)
        self.manager.emit_execution_scope_invalidation(
            ExecutionScopeEvent.PROJECT_PIPELINE_RELOADED,
            project_name=self.current_project.path.name,
        )
        if self.manager.started:
            self.manager.instruction_optimizer.configure(
                **self.manager.instruction_optimizer_config,
                execution_scope_service=self.manager.execution_scope_service,
                execution_scope_project_name=self.current_project.path.name,
                execution_scope_idb_key=str(
                    cfg.get("idb_key", self.current_project.path.name)
                ),
                pass_scheduler=self.manager.instruction_pass_scheduler,
            )
            self.manager.block_optimizer.configure(
                **cfg,
                execution_scope_service=self.manager.execution_scope_service,
                execution_scope_project_name=self.current_project.path.name,
                execution_scope_idb_key=str(
                    cfg.get("idb_key", self.current_project.path.name)
                ),
                pass_scheduler=self.manager.block_pass_scheduler,
                function_priors_provider=(self.manager.function_analysis_priors_for_ea),
            )
            self.manager._compile_execution_scope()
        if getattr(self, "gui", None) is not None:
            logger.info(
                "d810-ng: Rules reconfigured for project %s",
                self.current_project.path.name,
            )
        logger.debug(
            "Loaded project %s (%s) from %s",
            self.current_project.path.name,
            self.current_project.description,
            self.current_project.path,
        )
        if runtime_project.path != self.current_project.path:
            logger.debug(
                "Runtime project %s selected from %s",
                runtime_project.path.name,
                runtime_project.path,
            )
        return self.current_project

    def get_project_runtime_snapshot(self) -> ProjectRuntimeSnapshot:
        snapshot = self.current_project_runtime_snapshot
        if snapshot is None:
            raise RuntimeError("No project runtime snapshot is available")
        return snapshot

    def get_workbench_snapshot(
        self,
        function_ea: int,
        function_name: str = "",
        function_fingerprint: str | None = None,
        *,
        facts: typing.Any | None = None,
    ) -> DeobfuscationWorkbenchSnapshot:
        """Collect workbench truth for the current source/runtime project pair."""
        project_snapshot = self.current_project_runtime_snapshot
        runtime_project = self.current_runtime_project
        if project_snapshot is None or runtime_project is None:
            raise RuntimeError("No runtime project is available for the workbench")
        return self.manager.get_workbench_snapshot(
            function_ea=function_ea,
            function_name=function_name,
            function_fingerprint=function_fingerprint,
            project_snapshot=project_snapshot,
            runtime_project=runtime_project,
            facts=facts,
        )

    def capture_workbench_baseline(
        self,
        identity: ComparisonIdentity,
        pseudocode: str,
    ) -> BaselineRef:
        return self.manager.capture_workbench_baseline(identity, pseudocode)

    def capture_workbench_d810_output(
        self,
        identity: ComparisonIdentity,
        pseudocode: str,
    ) -> D810OutputRef:
        return self.manager.capture_workbench_d810_output(identity, pseudocode)

    def get_workbench_comparison(
        self,
        identity: ComparisonIdentity,
    ) -> WorkbenchComparisonSnapshot:
        return self.manager.get_workbench_comparison(identity)

    def get_diagnostic_databases(self) -> tuple[DiagnosticDatabaseSummary, ...]:
        return self.manager.get_diagnostic_databases()

    def get_diagnostic_snapshots(
        self, path: pathlib.Path | str
    ) -> tuple[DiagnosticSnapshotSummary, ...]:
        return self.manager.get_diagnostic_snapshots(path)

    def get_diagnostic_records(
        self,
        path: pathlib.Path | str,
        snapshot_id: int,
        kind: DiagnosticViewKind,
    ) -> tuple[DiagnosticRecord, ...]:
        return self.manager.get_diagnostic_records(path, snapshot_id, kind)

    def get_diagnostic_case_evidence(
        self,
        path: pathlib.Path | str,
        function_ea: int,
    ) -> DeobfuscationCaseEvidence | None:
        return self.manager.get_diagnostic_case_evidence(path, function_ea)

    def plan_diagnostic_selected_snapshots(
        self, path: pathlib.Path | str, snapshot_ids: typing.Sequence[int]
    ) -> DiagnosticCleanupPlan:
        return self.manager.plan_diagnostic_selected_snapshots(path, snapshot_ids)

    def plan_diagnostic_all_snapshots(
        self, path: pathlib.Path | str
    ) -> DiagnosticCleanupPlan:
        return self.manager.plan_diagnostic_all_snapshots(path)

    def plan_diagnostic_keep_latest(
        self, path: pathlib.Path | str, keep: int
    ) -> DiagnosticCleanupPlan:
        return self.manager.plan_diagnostic_keep_latest(path, keep)

    def plan_diagnostic_selected_databases(
        self, paths: typing.Iterable[pathlib.Path | str]
    ) -> DiagnosticCleanupPlan:
        return self.manager.plan_diagnostic_selected_databases(paths)

    def plan_diagnostic_all_closed_databases(
        self, paths: typing.Iterable[pathlib.Path | str]
    ) -> DiagnosticCleanupPlan:
        return self.manager.plan_diagnostic_all_closed_databases(paths)

    def plan_diagnostic_vacuum(
        self, paths: typing.Iterable[pathlib.Path | str]
    ) -> DiagnosticCleanupPlan:
        return self.manager.plan_diagnostic_vacuum(paths)

    def execute_diagnostic_cleanup(
        self,
        plan: DiagnosticCleanupPlan,
        *,
        checkpoint_wal: bool = True,
        vacuum_after: bool = False,
    ) -> DiagnosticCleanupResult:
        return self.manager.execute_diagnostic_cleanup(
            plan,
            checkpoint_wal=checkpoint_wal,
            vacuum_after=vacuum_after,
        )

    def get_config_v2_serializer_manifest(self) -> tuple[ConfigV2FieldSerializer, ...]:
        return self.manager.get_config_v2_serializer_manifest()

    def create_config_v2_project_draft(
        self, destination: pathlib.Path
    ) -> ConfigV2ProjectDraft:
        runtime_project = self.current_runtime_project
        if runtime_project is None:
            raise RuntimeError("No runtime project is available for config-v2 editing")
        return self.manager.create_config_v2_project_draft(
            runtime_project,
            destination=destination,
        )

    def validate_config_v2_project_draft(
        self, draft: ConfigV2ProjectDraft
    ) -> ConfigV2ProjectValidation:
        return self.manager.validate_config_v2_project_draft(draft)

    def set_config_v2_description(
        self, draft: ConfigV2ProjectDraft, description: str
    ) -> ConfigV2ProjectDraft:
        return self.manager.set_config_v2_description(draft, description)

    def add_config_v2_pass(
        self,
        draft: ConfigV2ProjectDraft,
        pass_id: str,
        *,
        index: int | None = None,
    ) -> ConfigV2ProjectDraft:
        return self.manager.add_config_v2_pass(draft, pass_id, index=index)

    def remove_config_v2_pass(
        self, draft: ConfigV2ProjectDraft, pass_index: int
    ) -> ConfigV2ProjectDraft:
        return self.manager.remove_config_v2_pass(draft, pass_index)

    def reorder_config_v2_pass(
        self, draft: ConfigV2ProjectDraft, pass_index: int, new_index: int
    ) -> ConfigV2ProjectDraft:
        return self.manager.reorder_config_v2_pass(draft, pass_index, new_index)

    def set_config_v2_pass_options(
        self,
        draft: ConfigV2ProjectDraft,
        *,
        pass_index: int,
        options: typing.Mapping[str, object],
    ) -> ConfigV2ProjectDraft:
        return self.manager.set_config_v2_pass_options(
            draft,
            pass_index=pass_index,
            options=options,
        )

    def set_config_v2_pass_transforms(
        self,
        draft: ConfigV2ProjectDraft,
        *,
        pass_index: int,
        transform_ids: typing.Sequence[str],
    ) -> ConfigV2ProjectDraft:
        return self.manager.set_config_v2_pass_transforms(
            draft,
            pass_index=pass_index,
            transform_ids=transform_ids,
        )

    def set_config_v2_routing_override(
        self,
        draft: ConfigV2ProjectDraft,
        *,
        prefer: typing.Mapping[str, float],
        require: str | None,
        deny: typing.Sequence[str],
    ) -> ConfigV2ProjectDraft:
        return self.manager.set_config_v2_routing_override(
            draft,
            prefer=prefer,
            require=require,
            deny=deny,
        )

    def clear_config_v2_routing_override(
        self, draft: ConfigV2ProjectDraft
    ) -> ConfigV2ProjectDraft:
        return self.manager.clear_config_v2_routing_override(draft)

    def replace_config_v2_document(
        self,
        draft: ConfigV2ProjectDraft,
        document: typing.Mapping[str, object],
    ) -> ConfigV2ProjectDraft:
        return self.manager.replace_config_v2_document(draft, document)

    def materialize_recipe_as_config_v2(
        self,
        draft: ConfigV2ProjectDraft,
        recipe: PipelineRecipeDraft,
    ) -> ConfigV2ProjectDraft:
        return self.manager.materialize_recipe_as_config_v2(draft, recipe)

    def save_and_reload_config_v2_project(
        self,
        draft: ConfigV2ProjectDraft,
        validation: ConfigV2ProjectValidation,
    ) -> ProjectConfiguration:
        saved = self.manager.save_config_v2_project(draft, validation)
        name = saved.path.name
        if name in self.project_manager.project_names():
            previous = self.project_manager.get(name)
            self.update_project(previous, saved)
        else:
            self.add_project(saved)
        return self.load_project(self.project_manager.index(name))

    def get_workbench_recipe_catalog(self) -> tuple[PassCatalogEntry, ...]:
        return self.manager.get_workbench_recipe_catalog()

    def create_workbench_recipe_draft(
        self,
        snapshot: DeobfuscationWorkbenchSnapshot,
    ) -> PipelineRecipeDraft:
        runtime_project = self.current_runtime_project
        if runtime_project is None:
            raise RuntimeError("No runtime project is available for the recipe")
        return self.manager.create_workbench_recipe_draft(snapshot, runtime_project)

    def create_active_workbench_recipe_draft(
        self,
        function_ea: int,
    ) -> PipelineRecipeDraft:
        """Create a temporary function recipe from the active config-v2 runtime."""
        runtime_project = self.current_runtime_project
        snapshot = self.current_project_runtime_snapshot
        if runtime_project is None or snapshot is None:
            raise RuntimeError("No runtime project is available for the recipe")
        return self.manager.create_active_workbench_recipe_draft(
            function_ea=function_ea,
            source_path=str(snapshot.source.path),
            runtime_path=str(snapshot.runtime.path),
            runtime_project=runtime_project,
        )

    def create_saved_workbench_recipe_draft(
        self,
        *,
        function_ea: int,
        function_fingerprint: str | None,
        workbench_generation: int = 0,
    ) -> PipelineRecipeDraft | None:
        snapshot = self.current_project_runtime_snapshot
        if snapshot is None:
            raise RuntimeError("No runtime project is available for the recipe")
        return self.manager.create_saved_workbench_recipe_draft(
            function_ea=function_ea,
            function_fingerprint=function_fingerprint,
            workbench_generation=workbench_generation,
            source_path=str(snapshot.source.path),
            runtime_path=str(snapshot.runtime.path),
        )

    def validate_workbench_recipe(
        self,
        draft: PipelineRecipeDraft,
        *,
        facts: object | None = None,
    ) -> RecipeValidation:
        return self.manager.validate_workbench_recipe(draft, facts=facts)

    def add_workbench_recipe_pass(
        self,
        draft: PipelineRecipeDraft,
        pass_id: str,
    ) -> PipelineRecipeDraft:
        return self.manager.add_workbench_recipe_pass(draft, pass_id)

    def remove_workbench_recipe_pass(
        self,
        draft: PipelineRecipeDraft,
        item_id: str,
    ) -> PipelineRecipeDraft:
        return self.manager.remove_workbench_recipe_pass(draft, item_id)

    def set_workbench_recipe_pass_enabled(
        self,
        draft: PipelineRecipeDraft,
        item_id: str,
        enabled: bool,
    ) -> PipelineRecipeDraft:
        return self.manager.set_workbench_recipe_pass_enabled(
            draft,
            item_id,
            enabled,
        )

    def reorder_workbench_recipe_pass(
        self,
        draft: PipelineRecipeDraft,
        item_id: str,
        new_index: int,
    ) -> PipelineRecipeDraft:
        return self.manager.reorder_workbench_recipe_pass(
            draft,
            item_id,
            new_index,
        )

    def replace_workbench_recipe_pass_options(
        self,
        draft: PipelineRecipeDraft,
        item_id: str,
        options: typing.Mapping[str, object],
    ) -> PipelineRecipeDraft:
        return self.manager.replace_workbench_recipe_pass_options(
            draft,
            item_id,
            options,
        )

    def replace_workbench_recipe_state_cff_options(
        self,
        draft: PipelineRecipeDraft,
        options: StateMachineCffOptions,
    ) -> PipelineRecipeDraft:
        return self.manager.replace_workbench_recipe_state_cff_options(
            draft,
            options,
        )

    def get_workbench_recipe_state_cff_options(
        self,
        draft: PipelineRecipeDraft,
    ) -> StateMachineCffOptions:
        return self.manager.get_workbench_recipe_state_cff_options(draft)

    def save_workbench_function_recipe(
        self,
        draft: PipelineRecipeDraft,
        validation: RecipeValidation,
    ) -> FunctionPipelineOverride:
        return self.manager.save_workbench_function_recipe(draft, validation)

    def get_workbench_function_recipe(
        self,
        function_ea: int,
    ) -> FunctionPipelineOverride | None:
        return self.manager.get_workbench_function_recipe(function_ea)

    def clear_workbench_function_recipe(self, function_ea: int) -> bool:
        return self.manager.clear_workbench_function_recipe(function_ea)

    @contextlib.contextmanager
    def activate_workbench_recipe(
        self,
        draft: PipelineRecipeDraft,
    ):
        """Run one synchronous decompile under an in-memory function recipe."""
        if not self.manager.started:
            raise RuntimeError("D810 must be started before activating a recipe")
        source_project = self.current_project
        runtime_project = self.current_runtime_project
        if runtime_project is None:
            raise RuntimeError("No runtime project is available for recipe activation")
        project_index = self.current_project_index
        default_selection = self.last_config_v2_default_selection
        pass_configs_json = self.manager.recipe_service.serialize_enabled_configs(draft)
        recipe_project = build_recipe_runtime_project(
            runtime_project,
            self.manager.recipe_service.deserialize_configs(pass_configs_json),
            function_ea=draft.function_ea,
        )

        def activate_recipe() -> None:
            self._activate_runtime_project(
                project_index=project_index,
                source_project=source_project,
                runtime_project=recipe_project,
                default_selection=None,
            )

        def restore_project() -> None:
            self._activate_runtime_project(
                project_index=project_index,
                source_project=source_project,
                runtime_project=runtime_project,
                default_selection=default_selection,
            )

        with activate_function_recipe_runtime(
            recipe_project,
            stop_runtime=self.stop_d810,
            start_runtime=self.start_d810,
            runtime_started=lambda: bool(self.manager.started),
            activate_recipe=activate_recipe,
            restore_project=restore_project,
        ):
            yield recipe_project

    def execute_workbench_apply_recipe_once(
        self,
        request: RecipeCommandRequest,
        draft: PipelineRecipeDraft,
        validation: RecipeValidation,
        *,
        lifecycle: typing.Callable[[PipelineRecipeDraft], bool],
    ) -> RecipeCommandResult:
        return self.manager.execute_workbench_apply_recipe_once(
            request,
            draft,
            validation,
            lifecycle=lifecycle,
        )

    def workbench_recipe_request_is_current(
        self,
        request: RecipeCommandRequest,
    ) -> bool:
        return self.manager.workbench_service.recipe_request_is_current(request)

    def execute_workbench_save_function_recipe(
        self,
        request: RecipeCommandRequest,
        draft: PipelineRecipeDraft,
        validation: RecipeValidation,
    ) -> RecipeCommandResult:
        return self.manager.execute_workbench_save_function_recipe(
            request,
            draft,
            validation,
        )

    def analyze_workbench_recipe(
        self,
        *,
        function_ea: int,
        target: object,
        provider_phase: object,
    ) -> object:
        return self.manager.analyze_workbench_recipe(
            function_ea=function_ea,
            target=target,
            provider_phase=provider_phase,
        )

    def execute_workbench_analyze(
        self,
        request: WorkbenchCommandRequest,
        *,
        target: object,
        provider_phase: object,
    ) -> WorkbenchCommandResult:
        return self.manager.workbench_service.execute_analyze(
            request,
            target=target,
            provider_phase=provider_phase,
        )

    def execute_workbench_deobfuscate(
        self,
        request: WorkbenchCommandRequest,
        *,
        lifecycle: typing.Callable[[], bool],
    ) -> WorkbenchCommandResult:
        return self.manager.workbench_service.execute_deobfuscate(
            request,
            lifecycle=lifecycle,
        )

    def execute_workbench_build_deobfuscator(
        self,
        request: WorkbenchCommandRequest,
        *,
        target: object,
        provider_phase: object,
    ) -> WorkbenchCommandResult:
        return self.manager.workbench_service.execute_build_deobfuscator(
            request,
            target=target,
            provider_phase=provider_phase,
        )

    def clone_current_runtime_project(
        self,
        destination: pathlib.Path,
        description: str,
    ) -> ProjectConfiguration:
        return clone_runtime_project_command(
            runtime_project=self.current_runtime_project,
            destination=destination,
            description=description,
        )

    def _register_backend_analysis_providers(self) -> None:
        """Register backend-supplied analysis seams before runtime starts."""
        register_hexrays_backend_providers()

    def start_d810(self):
        # Deferred decompiler load: ensure Hex-Rays is loaded + initialized
        # before installing microcode hooks (moved off plugin init / IDB open).
        if not ensure_hexrays_available(force_load=True):
            logger.error("Cannot start D-810: Hex-Rays decompiler is not available")
            return
        self._register_backend_analysis_providers()
        runtime_project = self.current_runtime_project or self.current_project
        self.manager.configure_instruction_optimizer(
            [rule for rule in self.current_ins_rules],
            generate_z3_code=self.d810_config.get("generate_z3_code"),
            dump_intermediate_microcode=self.d810_config.get(
                "dump_intermediate_microcode"
            ),
            **runtime_project.additional_configuration,
        )
        self.manager.configure_block_optimizer(
            [rule for rule in self.current_blk_rules],
            **runtime_project.additional_configuration,
        )
        self.manager.start()
        logger.info("D-810 ready to deobfuscate...")
        self.d810_config.set("last_project_index", self.current_project_index)
        self.d810_config.save()

    def stop_d810(self):
        logger.info("Stopping D-810...")
        self.manager.stop()

    @staticmethod
    def _ensure_extension_rules_registered() -> None:
        """Import extension-contributed rules before the catalogue is read.

        d810 registers its own rules by scanning ``d810.optimizers.__path__``,
        which by construction cannot reach a rule shipped inside an installed
        extension; ``load_extension_rules()`` closes that gap.  It used to run
        only from ``manager.start()`` -- 88 ms *after* :meth:`load` had already
        snapshotted the registry and matched configured rule names against it.
        An extension's rule therefore never entered the catalogue, never
        matched, and never had ``configure()`` called, leaving its pass
        configured, routed and silently inert (ticket d81-ix9c).

        Calling ``load_extension_rules()`` rather than the whole
        ``load_optimizer_registries()`` is deliberate: the latter re-runs the
        module scanner, and running that twice can leave two copies of one rule
        class in a single process.  Module imports are cached, so the later
        call from ``manager.start()`` stays correct and costs nothing.
        """
        from d810.backends import load_extension_rules

        load_extension_rules()

    def _build_known_instruction_rules(self) -> list:
        """Every instruction rule available to be matched against a config."""
        self._ensure_extension_rules_registered()
        rules = [
            rule_cls()
            for rule_cls in InstructionOptimizationRule.registry.values()
            if not inspect.isabstract(rule_cls)
        ]
        rules.extend(adapt_rules(VerifiableRule.instantiate_all()))
        return rules

    def _build_known_block_rules(self) -> list:
        """Every block rule available to be matched against a config."""
        self._ensure_extension_rules_registered()
        return [
            rule_cls()
            for rule_cls in FlowOptimizationRule.registry.values()
            if not inspect.isabstract(rule_cls)
        ]

    def load(
        self,
        gui: bool = True,
        d810_config: D810Configuration | None = None,
    ):
        self.reset(d810_config=d810_config)
        raw_index = self.d810_config.get("last_project_index", 0)
        try:
            self.current_project_index = int(raw_index)
        except (TypeError, ValueError):
            logger.warning(
                "Invalid last_project_index %r in configuration; defaulting to 0",
                raw_index,
            )
            self.current_project_index = 0

        self.current_ins_rules = []
        self.current_blk_rules = []

        self.known_ins_rules = self._build_known_instruction_rules()
        self.known_blk_rules = self._build_known_block_rules()

        if projects := len(self.project_manager):
            preferred = max(0, min(self.current_project_index, projects - 1))
            self._is_loaded = self._load_first_valid_project(preferred) is not None
            if not self._is_loaded:
                logger.warning(
                    "No loadable project configuration among %d file(s); "
                    "plugin is idle. Invalid: %s",
                    projects,
                    ", ".join(sorted(self.invalid_projects)) or "<none>",
                )
                self.current_project = None  # type: ignore[assignment]
        else:
            logger.warning("No project configurations available; plugin is idle.")
            self.current_project = None  # type: ignore[assignment]
            self._is_loaded = False

        if gui and self._is_loaded:
            D810GUI = importlib.import_module("d810.ui.ida_ui").D810GUI
            self.gui = D810GUI(self)
            self.gui.show_windows()

    def unload(self, gui: bool = True):
        self.manager.stop()
        if gui and self._is_loaded:
            self.gui.term()
            del self.gui
        self._is_loaded = False

    @contextlib.contextmanager
    def for_project(self, name: str) -> typing.Generator[ProjectContext, None, None]:
        _old_project_index = self.current_project_index
        project_index = self.project_manager.index(name)
        if project_index != _old_project_index:
            logger.info("switching to project %s", name)
        self.load_project(project_index)

        ctx = ProjectContext(state=self, project_index=project_index)
        try:
            yield ctx
        finally:
            ctx.restore()
            if project_index != _old_project_index:
                logger.info("switching back to project %s", _old_project_index)
                self.load_project(_old_project_index)
