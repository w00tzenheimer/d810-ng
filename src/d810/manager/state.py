"""Runtime project state for the D810 plugin."""

from __future__ import annotations

import contextlib
import inspect
import importlib
import os
import pathlib
import shlex

from d810.backends.hexrays.registration import register_hexrays_backend_providers
from d810.hexrays.utils.ida_utils import ensure_hexrays_available
from d810.backends.mba.ida import (
    IDAPatternAdapter,
    adapt_rules,
    attach_selected_certified_catalogue_snapshot,
)
from d810.core import typing
from d810.core.config import (
    D810Configuration,
    ProjectConfiguration,
)
from d810.core.deobfuscation_case import DeobfuscationCaseEvidence
from d810.core.diagnostics_capture_preferences import (
    diagnostics_capture_enabled,
    set_diagnostics_capture_enabled as persist_diagnostics_capture_enabled,
)
from d810.core.logging import clear_logs, configure_loggers, getLogger
from d810.core.plugins import ImplementationOwnership
from d810.core.platform import resolve_arch_config
from d810.core.project import (
    ProjectContext,
    ProjectManager,
    emit_project_reloading,
    prepare_project_activation_cleanups,
)
from d810.core.registry import SingletonMeta
from d810.core.execution_scope import ExecutionScopeEvent
from d810.core.stats import OptimizationStatistics
from d810.core.settings import (
    apply_saved_runtime_settings,
    configure_settings,
    get_settings,
)
from d810.core.speedup_session import apply_session_cython_disabled
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
from d810.mba.certified_catalogue import StructuralMatcherParityExpectation
from d810.manager.project_runtime import (
    ProjectRuntimeSnapshot,
    build_project_runtime_snapshot,
    clone_project as clone_project_command,
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
from d810.optimizers.microcode.handler import configure_rule_with_maturity_contract
from d810.hexrays.utils.hexrays_formatters import string_to_maturity
from d810.passes.constant_simplification import (
    CONSTANT_SIMPLIFICATION_PASS_ID,
    constant_simplification_provider_maturities,
)
from d810.passes.config_v2_hook_runtime import (
    ConfigV2HookSchedule,
    compile_config_v2_hook_schedule,
    requires_native_preanalysis_handlers,
)
from d810.passes.pass_pipeline import PipelineConfigError
from d810.passes.state_machine_options import StateMachineCffOptions

if TYPE_CHECKING:
    from d810.manager import D810Manager
    from d810.manager.workbench_comparison import ComparisonIdentity
    from d810.ui.ida_ui import D810GUI

logger = getLogger("d810")
D810_LOG_DIR_NAME = "d810_logs"


class RuntimeActivationRollbackError(RuntimeError):
    """The previous live runtime could not be re-established after failure."""


def _external_binding_for_name(
    binding_name: str,
    external_bindings: dict[tuple[str, str], ImplementationOwnership],
) -> ImplementationOwnership | None:
    """Resolve one schedule name to its exact activated external ownership."""
    matches = tuple(
        ownership
        for ownership in external_bindings.values()
        if ownership.candidate.rule_name == binding_name
    )
    if len(matches) > 1:
        candidates = tuple(
            (
                ownership.candidate.pass_id,
                ownership.candidate.backend_name,
                ownership.candidate.backend_origin,
            )
            for ownership in matches
        )
        raise PipelineConfigError(
            f"external implementation binding {binding_name!r} is ambiguous: "
            f"{candidates!r}"
        )
    return matches[0] if matches else None


def _require_registered_schedule_bindings(
    schedule: ConfigV2HookSchedule,
    known_ins_rules: list,
    known_blk_rules: list,
    external_bindings: dict[tuple[str, str], ImplementationOwnership] | None = None,
) -> None:
    """Reject a v2 schedule whose concrete Hex-Rays hooks are unavailable."""
    external_bindings = external_bindings or {}
    known_ins_names = frozenset(
        str(getattr(rule, "name", "")) for rule in known_ins_rules
    )
    known_blk_names = frozenset(
        str(getattr(rule, "name", "")) for rule in known_blk_rules
    )
    missing_ins = tuple(
        dict.fromkeys(
            binding.name
            for binding in schedule.instruction_bindings
            if binding.is_activated
            and binding.name not in known_ins_names
            and _external_binding_for_name(binding.name, external_bindings) is None
        )
    )
    missing_blk = tuple(
        dict.fromkeys(
            binding.name
            for binding in schedule.block_bindings
            if binding.is_activated
            and binding.name not in known_blk_names
            and _external_binding_for_name(binding.name, external_bindings) is None
        )
    )
    if not (missing_ins or missing_blk):
        return

    details: list[str] = []
    if missing_ins:
        details.append(f"instruction={list(missing_ins)!r}")
    if missing_blk:
        details.append(f"block={list(missing_blk)!r}")
    raise PipelineConfigError(
        "config-v2 schedule contains unregistered concrete rule binding(s): "
        + ", ".join(details)
    )


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
        self._diagnostics_capture_observers: set[typing.Callable[[bool], None]] = set()
        self.d810_config: D810Configuration = d810_config or D810Configuration()
        self._apply_diagnostics_capture_preference()
        self._apply_execution_callback_detail_preference()
        self._apply_runtime_settings_preferences()
        self.project_manager = ProjectManager(self.d810_config)
        self.current_project_index: int = 0
        self.current_ins_rules: typing.List = []
        self.current_blk_rules: typing.List = []
        self.known_ins_rules: typing.List = []
        self.known_blk_rules: typing.List = []
        self.last_config_v2_pass_ids: tuple[str, ...] = ()
        #: ``project file name -> one-line reason`` for every project whose
        #: activation raised.  A malformed project is SKIPPED, never fatal, so one
        #: bad file in the config directory cannot leave the plugin with no
        #: project at all (ticket lpccp-8c87).
        self.invalid_projects: dict[str, str] = {}
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

    def _apply_execution_callback_detail_preference(self) -> None:
        """Reapply the saved callback detail unless an environment override wins."""
        if "D810_EXECUTION_CALLBACK_DETAIL" in os.environ:
            return
        configure_settings(
            execution_callback_detail=self.d810_config.get(
                "execution_callback_detail",
                get_settings().execution_callback_detail,
            )
        )

    def _apply_runtime_settings_preferences(self) -> None:
        """Reapply every other saved runtime setting with env taking precedence."""
        apply_saved_runtime_settings(self.d810_config)

    def set_session_cython_disabled(self, disabled: bool) -> bool:
        """Apply the current-session Cython policy and report reload need."""
        return apply_session_cython_disabled(disabled)

    def diagnostics_capture_enabled(self) -> bool:
        return bool(get_settings().diag_snapshots)

    def enable_diagnostics_capture(self) -> bool:
        return self.set_diagnostics_capture_enabled(True)

    def set_diagnostics_capture_enabled(self, enabled: bool) -> bool:
        """Persist, apply, and publish the one global capture choice."""
        enabled = persist_diagnostics_capture_enabled(self.d810_config, enabled)
        configure_settings(diag_snapshots=enabled)
        self._notify_diagnostics_capture_changed(enabled)
        return enabled

    def subscribe_diagnostics_capture(
        self,
        observer: typing.Callable[[bool], None],
    ) -> typing.Callable[[], None]:
        """Observe capture state changes without coupling state to any dock."""
        self._diagnostics_capture_observers.add(observer)

        def unsubscribe() -> None:
            self._diagnostics_capture_observers.discard(observer)

        return unsubscribe

    def _notify_diagnostics_capture_changed(self, enabled: bool) -> None:
        for observer in tuple(self._diagnostics_capture_observers):
            try:
                observer(enabled)
            except Exception:  # noqa: BLE001 - one dock must not break capture
                logger.exception("Diagnostics capture observer failed")

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

        A project whose pipeline payload cannot be resolved is recorded in
        :attr:`invalid_projects` and SKIPPED.  It must never abort the caller:
        ``load()`` enumerates every file in the config directory, so one bad
        project used to leave the plugin with no project at all (lpccp-8c87).
        """
        project = self.project_manager.get(project_index)
        try:
            activated = self._activate_project(
                project_index=project_index,
                project=project,
            )
        except Exception as exc:  # noqa: BLE001 - any malformed project is skippable
            self._record_invalid_project(project, exc)
            return None
        self.invalid_projects.pop(project.path.name, None)
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
        migration_command = shlex.join(
            (
                "python",
                "tools/migrations/migrate_project_config_v2.py",
                str(project.path),
                "--in-place",
            )
        )
        reason = f"{type(exc).__name__}: {exc}; migrate with: {migration_command}"
        self.invalid_projects[name] = reason
        logger.warning(
            "Skipping malformed project configuration %s: %s", project.path, reason
        )
        logger.debug("project activation traceback for %s", project.path, exc_info=True)

    def _capture_project_activation_state(self) -> dict[str, object]:
        """Capture state-owned identities plus the manager-owned runtime lanes."""

        missing = object()
        state_attributes = (
            "current_project_index",
            "current_project",
            "current_ins_rules",
            "current_blk_rules",
            "known_ins_rules",
            "known_blk_rules",
            "last_config_v2_pass_ids",
            "current_project_runtime_snapshot",
            "current_certified_catalogue_snapshot",
            "current_shadow_matcher_parity_ledger",
        )
        return {
            "missing": missing,
            "state": {name: getattr(self, name, missing) for name in state_attributes},
            "manager": self.manager.snapshot_project_activation_state(),
        }

    def _restore_project_activation_state(
        self,
        captured: dict[str, object],
        activation_error: BaseException,
    ) -> None:
        """Restore state and manager lanes or fail closed exactly once."""

        from d810.manager.manager import ManagerActivationStateRestoreError

        restore_failures: list[tuple[str, BaseException]] = []
        missing = captured["missing"]
        for name, value in captured["state"].items():  # type: ignore[union-attr]
            try:
                if value is missing:
                    if hasattr(self, name):
                        delattr(self, name)
                else:
                    setattr(self, name, value)
            except BaseException as exc:
                restore_failures.append((f"state.{name}", exc))

        manager_restore_incomplete = False
        try:
            self.manager.restore_project_activation_state(
                captured["manager"]  # type: ignore[arg-type]
            )
        except ManagerActivationStateRestoreError as exc:
            manager_restore_incomplete = True
            restore_failures.append(("manager", exc))

        if not restore_failures:
            return

        cleanup_failures: list[tuple[str, BaseException]] = []
        if manager_restore_incomplete or restore_failures:
            try:
                cleanup_failures.extend(
                    ("runtime invalidation", error)
                    for error in (
                        self.manager.invalidate_runtime_after_activation_rollback()
                    )
                )
            except BaseException as exc:
                cleanup_failures.append(("runtime invalidation", exc))

        all_failures = (*restore_failures, *cleanup_failures)
        detail = "; ".join(
            f"{label}: {type(error).__name__}: {error}" for label, error in all_failures
        )
        raise RuntimeActivationRollbackError(
            f"runtime activation rollback failed: {detail}"
        ) from activation_error

    def _activate_project(
        self,
        *,
        project_index: int,
        project: ProjectConfiguration,
    ) -> ProjectConfiguration:
        """Compile and activate one canonical project transactionally."""
        # Every fallible operation is staged before the identity-bearing state
        # fields or lifecycle events are published.  In particular, rules are
        # rebuilt for every candidate project: configuring a candidate can
        # never poison the rule objects used by the active project.
        # Capture manager-owned objects and profile-global registries before
        # constructing/configuring any candidate rule.  Tigress-indirect
        # configuration registers reload/materialization handlers as a side
        # effect, so those globals are part of the same rollback boundary.
        activation_snapshot = self._capture_project_activation_state()
        previous_runtime_snapshot = self.current_project_runtime_snapshot
        previous_activations = (
            previous_runtime_snapshot.activated_plugins
            if previous_runtime_snapshot is not None
            else ()
        )
        previous_implementations = (
            previous_runtime_snapshot.activated_implementations
            if previous_runtime_snapshot is not None
            else ()
        )
        backend_registry = self.manager.backend_registry
        staged_implementations: list[ImplementationOwnership] = []
        rolled_back = False

        def _rollback_activation(activation_error: BaseException) -> None:
            nonlocal rolled_back
            if rolled_back:
                return
            rolled_back = True
            try:
                backend_registry.discard_implementation_instances(
                    tuple(staged_implementations)
                )
                self._restore_project_activation_state(
                    activation_snapshot,
                    activation_error,
                )
            finally:
                backend_registry.close_activations_except(previous_activations)

        def _stage_call(callable_, *args, **kwargs):
            try:
                return callable_(*args, **kwargs)
            except BaseException as activation_error:
                _rollback_activation(activation_error)
                raise

        def _raise(error: BaseException):
            raise error

        schedule = _stage_call(compile_config_v2_hook_schedule, project)
        candidate_known_ins_rules = _stage_call(self._build_known_instruction_rules)
        candidate_known_blk_rules = _stage_call(self._build_known_block_rules)

        instruction_names = {
            str(binding.name)
            for binding in schedule.instruction_bindings
            if binding.is_activated
        }
        block_names = {
            str(binding.name)
            for binding in schedule.block_bindings
            if binding.is_activated
        }
        external_rules: dict[tuple[str, str], ImplementationOwnership] = {}
        staged_activations: list[object] = []
        all_binding_names = instruction_names | block_names
        for pass_id in schedule.configured_pass_ids:
            declarations = _stage_call(
                backend_registry.implementation_declarations_for,
                pass_id,
            )
            for candidate, _manifest in declarations:
                if candidate.rule_name not in all_binding_names:
                    continue
                external_key = (candidate.pass_id, candidate.rule_name)
                if external_key in external_rules:
                    _stage_call(
                        _raise,
                        PipelineConfigError(
                            f"pass implementation {candidate.rule_name!r} is ambiguous"
                        ),
                    )
                implementation = _stage_call(
                    backend_registry.activate_implementation,
                    candidate,
                )
                staged_ownership = ImplementationOwnership(candidate, implementation)
                staged_implementations.append(staged_ownership)
                if not isinstance(implementation, InstructionOptimizationRule):
                    _stage_call(
                        _raise,
                        TypeError(
                            f"plugin implementation {candidate.rule_name!r} must be "
                            "an InstructionOptimizationRule"
                        ),
                    )
                services = _stage_call(
                    backend_registry.plugin_rule_services,
                    candidate,
                )
                _stage_call(implementation.bind_plugin_services, services)
                external_rules[external_key] = staged_ownership
                activation = _stage_call(
                    backend_registry.activation_for_candidate, candidate
                )
                if not any(existing is activation for existing in staged_activations):
                    staged_activations.append(activation)
                if candidate.rule_name in instruction_names:
                    candidate_known_ins_rules.append(implementation)
                if candidate.rule_name in block_names:
                    candidate_known_blk_rules.append(implementation)

        snapshot = _stage_call(
            build_project_runtime_snapshot,
            project=project,
            schedule=schedule,
            activated_plugins=tuple(staged_activations),
            activated_implementations=tuple(staged_implementations),
        )
        _stage_call(
            _require_registered_schedule_bindings,
            schedule,
            candidate_known_ins_rules,
            candidate_known_blk_rules,
            external_rules,
        )
        # The registration preflight above is still part of the fallible
        # validation phase.  Existing-profile cleanup belongs before candidate
        # configuration, but must not run until every declared concrete binding
        # has a candidate; otherwise a failed activation would retire the
        # active profile's cleanup hooks.
        _stage_call(prepare_project_activation_cleanups)
        candidate_ins_rules: list = []
        candidate_blk_rules: list = []
        constant_schedule = schedule.constant_simplification_schedule
        constant_stages_by_rule = {
            stage.implementation_name: stage
            for stage in (constant_schedule.stages if constant_schedule else ())
            if stage.enabled and stage.implementation_name
        }

        def configure_rule(rule, effective_config) -> None:
            stage = constant_stages_by_rule.get(rule.name)
            if stage is None:
                rule.configure(effective_config)
                return
            supported_names = constant_simplification_provider_maturities(
                stage.supported_maturities
            )
            effective_names = constant_simplification_provider_maturities(
                stage.effective_maturities
            )
            supported = tuple(string_to_maturity(name) for name in supported_names)
            effective = tuple(string_to_maturity(name) for name in effective_names)
            if any(value is None for value in (*supported, *effective)):
                raise PipelineConfigError(
                    f"{CONSTANT_SIMPLIFICATION_PASS_ID} stage {stage.stage_id} "
                    f"implementation {stage.implementation_name} has an unknown "
                    "provider maturity spelling"
                )
            configure_rule_with_maturity_contract(
                rule,
                effective_config,
                pass_id=CONSTANT_SIMPLIFICATION_PASS_ID,
                stage_id=stage.stage_id,
                expected_supported=tuple(
                    value for value in supported if value is not None
                ),
                expected_effective=tuple(
                    value for value in effective if value is not None
                ),
            )

        # The compiled schedule is authoritative.  Binding order is the
        # declared pipeline order, never registry discovery order.
        for rule_conf in schedule.instruction_bindings:
            if not rule_conf.is_activated:
                continue
            external_binding = _external_binding_for_name(
                rule_conf.name, external_rules
            )
            rules = (
                (external_binding.instance,)
                if external_binding is not None
                else tuple(
                    rule
                    for rule in candidate_known_ins_rules
                    if rule.name == rule_conf.name
                )
            )
            for rule in rules:
                effective_config = _stage_call(resolve_arch_config, rule_conf.config)
                effective_config["dump_intermediate_microcode"] = self.d810_config.get(
                    "dump_intermediate_microcode"
                )
                _stage_call(configure_rule, rule, effective_config)
                _stage_call(rule.set_log_dir, self.log_dir)
                candidate_ins_rules.append(rule)
        logger.debug("Instruction rules configured")

        selected_catalogue_adapters = tuple(
            rule for rule in candidate_ins_rules if isinstance(rule, IDAPatternAdapter)
        )
        # Snapshot construction fingerprints every selected rule and allocates
        # the parity ledger.  Neither belongs to ordinary schedule execution:
        # the rollout stays registry-authoritative unless an operator explicitly
        # requests shadow observation or certificate-gated structural matching.
        shadow_observation_requested = (
            os.environ.get("D810_SHADOW_DSL_MATCHING", "0") == "1"
        )
        structural_matching_requested = (
            os.environ.get("D810_STRUCTURAL_DSL_MATCHING", "0") == "1"
        )
        candidate_certified_catalogue_snapshot = None
        candidate_shadow_matcher_parity_ledger = None
        if selected_catalogue_adapters and (
            shadow_observation_requested or structural_matching_requested
        ):
            certificate_path = None
            parity_expectation = None
            certificate_setting = project.additional_configuration.get(
                "structural_matcher_parity_certificate"
            )
            if type(certificate_setting) is str and certificate_setting:
                configured_path = pathlib.Path(certificate_setting)
                certificate_path = (
                    configured_path
                    if configured_path.is_absolute()
                    else project.path.parent / configured_path
                )
            elif certificate_setting is not None:
                logger.warning(
                    "Ignoring non-string structural matcher parity certificate setting"
                )
            expectation_setting = project.additional_configuration.get(
                "structural_matcher_parity_expectation"
            )
            if isinstance(expectation_setting, dict):
                try:
                    parity_expectation = StructuralMatcherParityExpectation(
                        corpus_digest=expectation_setting["corpus_digest"],
                        toolchain_digest=expectation_setting["toolchain_digest"],
                        runtime_semantics_digest=expectation_setting[
                            "runtime_semantics_digest"
                        ],
                        legacy_observation_count=expectation_setting[
                            "legacy_observation_count"
                        ],
                        observation_count=expectation_setting["observation_count"],
                    )
                except (KeyError, TypeError, ValueError) as exc:
                    logger.warning(
                        "Ignoring invalid structural matcher parity expectation: %s",
                        exc,
                    )
            elif expectation_setting is not None:
                logger.warning(
                    "Ignoring non-object structural matcher parity expectation setting"
                )
            runtime_mode = None
            try:
                from d810.optimizers.microcode.instructions.pattern_matching import (
                    engine as pattern_matching_engine,
                )

                candidate_mode = pattern_matching_engine.get_engine_info().get(
                    "backend"
                )
                if candidate_mode in {"python", "cython"}:
                    runtime_mode = candidate_mode
            except Exception:  # noqa: BLE001 - experimental selection fails closed
                runtime_mode = None
            (
                candidate_certified_catalogue_snapshot,
                candidate_shadow_matcher_parity_ledger,
            ) = _stage_call(
                attach_selected_certified_catalogue_snapshot,
                selected_catalogue_adapters,
                parity_certificate_path=certificate_path,
                parity_expectation=parity_expectation,
                runtime_mode=runtime_mode,
            )
        for rule_conf in schedule.block_bindings:
            if not rule_conf.is_activated:
                continue
            external_binding = _external_binding_for_name(
                rule_conf.name, external_rules
            )
            rules = (
                (external_binding.instance,)
                if external_binding is not None
                else tuple(
                    rule
                    for rule in candidate_known_blk_rules
                    if rule.name == rule_conf.name
                )
            )
            for blk_rule in rules:
                effective_config = _stage_call(resolve_arch_config, rule_conf.config)
                effective_config["dump_intermediate_microcode"] = self.d810_config.get(
                    "dump_intermediate_microcode"
                )
                _stage_call(configure_rule, blk_rule, effective_config)
                _stage_call(blk_rule.set_log_dir, self.log_dir)
                candidate_blk_rules.append(blk_rule)
        logger.debug("Block rules configured")

        cfg = _stage_call(dict, project.additional_configuration)
        cfg["config_v2_native_state_machine_active"] = _stage_call(
            requires_native_preanalysis_handlers, schedule
        )
        cfg.setdefault("project_name", project.path.name)

        try:
            # Stage the candidate rule lists into manager-owned scope inputs.
            # The old lists and optimizer objects are restored if any manager
            # or started-optimizer operation fails.
            self.manager.configure_constant_simplification_schedule(constant_schedule)
            self.manager.configure_instruction_optimizer(
                list(candidate_ins_rules),
                **self.manager.instruction_optimizer_config,
            )
            self.manager.configure_block_optimizer(
                list(candidate_blk_rules),
                **self.manager.block_optimizer_config,
            )

            self.manager.configure(**cfg)
            if self.manager.started:
                self.manager.instruction_optimizer.configure(
                    **self.manager.instruction_optimizer_config,
                    execution_scope_service=self.manager.execution_scope_service,
                    execution_scope_project_name=project.path.name,
                    execution_scope_idb_key=str(cfg.get("idb_key", project.path.name)),
                    pass_scheduler=self.manager.instruction_pass_scheduler,
                )
                self.manager.block_optimizer.configure(
                    **cfg,
                    execution_scope_service=self.manager.execution_scope_service,
                    execution_scope_project_name=project.path.name,
                    execution_scope_idb_key=str(cfg.get("idb_key", project.path.name)),
                    pass_scheduler=self.manager.block_pass_scheduler,
                    function_priors_provider=(
                        self.manager.function_analysis_priors_for_ea
                    ),
                )
                self.manager._compile_execution_scope()
        except BaseException as activation_error:
            _rollback_activation(activation_error)
            raise

        # This is the non-fallible publication point.  No identity/list field
        # is changed until candidate rule configuration, parity attachment,
        # manager configuration, and execution-scope compilation all succeed.
        old_project_name = (
            self.current_project.path.name
            if getattr(self, "current_project", None) is not None
            else None
        )
        self.current_project_index = project_index
        self.current_project = project
        self.known_ins_rules = candidate_known_ins_rules
        self.known_blk_rules = candidate_known_blk_rules
        self.current_ins_rules = candidate_ins_rules
        self.current_blk_rules = candidate_blk_rules
        self.last_config_v2_pass_ids = schedule.configured_pass_ids
        self.current_project_runtime_snapshot = snapshot
        self.current_certified_catalogue_snapshot = (
            candidate_certified_catalogue_snapshot
        )
        self.current_shadow_matcher_parity_ledger = (
            candidate_shadow_matcher_parity_ledger
        )

        # Publication is complete before retiring the prior plugin ownership.
        backend_registry.close_activations_except(snapshot.activated_plugins)
        backend_registry.discard_implementation_instances(previous_implementations)

        emit_project_reloading(
            old_project_name=old_project_name,
            new_project_name=project.path.name,
            isolated=True,
            run_cleanups=False,
        )
        self.manager.emit_execution_scope_invalidation(
            ExecutionScopeEvent.PROJECT_PIPELINE_RELOADED,
            project_name=project.path.name,
            isolated=True,
        )
        if getattr(self, "gui", None) is not None:
            logger.info(
                "d810-ng: Rules reconfigured for project %s",
                project.path.name,
            )
        logger.debug(
            "Loaded project %s (%s) from %s",
            project.path.name,
            project.description,
            project.path,
        )
        return project

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
        """Collect workbench truth for the current canonical project."""
        project_snapshot = self.current_project_runtime_snapshot
        if project_snapshot is None:
            raise RuntimeError("No project is available for the workbench")
        return self.manager.get_workbench_snapshot(
            function_ea=function_ea,
            function_name=function_name,
            function_fingerprint=function_fingerprint,
            project_snapshot=project_snapshot,
            project=self.current_project,
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
        project = self.current_project
        return self.manager.create_config_v2_project_draft(
            project,
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

    def add_config_v2_passes(
        self,
        draft: ConfigV2ProjectDraft,
        pass_ids: tuple[str, ...],
        *,
        index: int | None = None,
    ) -> ConfigV2ProjectDraft:
        return self.manager.add_config_v2_passes(draft, pass_ids, index=index)

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

    def get_workbench_recipe_inspection_catalog(
        self, pass_ids: tuple[str, ...]
    ) -> tuple[PassCatalogEntry, ...]:
        return self.manager.get_workbench_recipe_inspection_catalog(pass_ids)

    def create_workbench_recipe_draft(
        self,
        snapshot: DeobfuscationWorkbenchSnapshot,
    ) -> PipelineRecipeDraft:
        return self.manager.create_workbench_recipe_draft(
            snapshot, self.current_project
        )

    def create_active_workbench_recipe_draft(
        self,
        function_ea: int,
    ) -> PipelineRecipeDraft:
        """Create a temporary function recipe from the active project."""
        project = self.current_project
        snapshot = self.current_project_runtime_snapshot
        if snapshot is None:
            raise RuntimeError("No project is available for the recipe")
        return self.manager.create_active_workbench_recipe_draft(
            function_ea=function_ea,
            project_path=str(snapshot.project.path),
            project=project,
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
            raise RuntimeError("No project is available for the recipe")
        return self.manager.create_saved_workbench_recipe_draft(
            function_ea=function_ea,
            function_fingerprint=function_fingerprint,
            workbench_generation=workbench_generation,
            project_path=str(snapshot.project.path),
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
        project = self.current_project
        project_index = self.current_project_index
        pass_configs_json = self.manager.recipe_service.serialize_enabled_configs(draft)
        recipe_project = build_recipe_runtime_project(
            project,
            self.manager.recipe_service.deserialize_configs(pass_configs_json),
            function_ea=draft.function_ea,
        )

        def activate_recipe() -> None:
            self._activate_project(
                project_index=project_index,
                project=recipe_project,
            )

        def restore_project() -> None:
            self._activate_project(
                project_index=project_index,
                project=project,
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

    def execute_workbench_preview_preparation(
        self,
        request: WorkbenchCommandRequest,
    ) -> WorkbenchCommandResult:
        return self.manager.workbench_service.execute_preview_preparation(request)

    def execute_workbench_prepare_only(
        self,
        request: WorkbenchCommandRequest,
    ) -> WorkbenchCommandResult:
        return self.manager.workbench_service.execute_prepare_only(request)

    def execute_workbench_prepare_and_decompile(
        self,
        request: WorkbenchCommandRequest,
        *,
        lifecycle: typing.Callable[[], object],
    ) -> WorkbenchCommandResult:
        return self.manager.workbench_service.execute_prepare_and_decompile(
            request,
            lifecycle=lifecycle,
        )

    def execute_workbench_restore_preparation(
        self,
        request: WorkbenchCommandRequest,
    ) -> WorkbenchCommandResult:
        return self.manager.workbench_service.execute_restore_preparation(request)

    def clone_current_project(
        self,
        destination: pathlib.Path,
        description: str,
    ) -> ProjectConfiguration:
        return clone_project_command(
            project=self.current_project,
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
        self.manager.configure_instruction_optimizer(
            [rule for rule in self.current_ins_rules],
            generate_z3_code=self.d810_config.get("generate_z3_code"),
            dump_intermediate_microcode=self.d810_config.get(
                "dump_intermediate_microcode"
            ),
            **self.current_project.additional_configuration,
        )
        self.manager.configure_block_optimizer(
            [rule for rule in self.current_blk_rules],
            **self.current_project.additional_configuration,
        )
        project_snapshot = self.get_project_runtime_snapshot()
        constant_schedule = self.manager._constant_simplification_schedule
        self.manager.configure_preparation_scripts(
            project_snapshot.preparation_scripts,
            global_const_persistence_enabled=(
                project_snapshot.global_const_persistence_enabled
            ),
            constant_preparation_options=(
                constant_schedule.preparation if constant_schedule is not None else None
            ),
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
        """Retain the builtin catalogue boundary; plugins use factories."""
        return None

    def _build_known_instruction_rules(self) -> list:
        """Every instruction rule available to be matched against a config."""
        # Analysis rules share the instruction-rule registry but are not
        # imported by the peephole package.  Project activation snapshots this
        # catalogue before D810Manager.start() performs its broad optimizer
        # scan, so import the built-in analysis module explicitly here.
        from d810.optimizers.microcode.instructions.analysis import (  # noqa: F401
            pattern_guess,
        )

        rules = [
            rule_cls()
            for rule_cls in InstructionOptimizationRule.registry.values()
            if not inspect.isabstract(rule_cls)
        ]
        rules.extend(adapt_rules(VerifiableRule.instantiate_all()))
        return rules

    def _build_known_block_rules(self) -> list:
        """Every block rule available to be matched against a config."""
        from d810.optimizers.microcode.instructions.peephole import (  # noqa: F401
            modular_product_nonzero_native,
            predicate_root_recovery_native,
            rotate_idiom_recovery_native,
        )

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
