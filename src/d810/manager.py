from __future__ import annotations

import contextlib
import dataclasses
import inspect
import pathlib
import pstats

try:
    import cProfile
except ImportError:
    cProfile = None  # type: ignore[assignment]
import time
import typing
from typing import TYPE_CHECKING

from d810.core.config import D810Configuration, ProjectConfiguration
from d810.core.logging import clear_logs, configure_loggers, getLogger
from d810.core import MOP_CONSTANT_CACHE, MOP_TO_AST_CACHE
from d810.core.persistence import ActiveRuleRecipeConfig, create_optimization_storage
from d810.core.platform import resolve_arch_config
from d810.core.project import ProjectContext, ProjectManager
from d810.core.registry import EventEmitter
from d810.core.rule_scope import (
    FunctionRuleOverlay,
    RuleRecipeOverlay,
    RuleScopeEvent,
    RuleScopeInvalidation,
    RuleScopeService,
)
from d810.core.singleton import SingletonMeta
from d810.core.stats import OptimizationStatistics
from d810.hexrays.ctree_hooks import CtreeOptimizerManager, CtreeOptimizationRule
from d810.hexrays.hexrays_hooks import (
    BlockOptimizerManager,
    DecompilationEvent,
    HexraysDecompilationHook,
    InstructionOptimizerManager,
)
from d810.mba.backends.ida import adapt_rules
from d810.mba.rules import VerifiableRule
from d810.optimizers.microcode.flow.handler import FlowOptimizationRule
from d810.optimizers.microcode.instructions.handler import InstructionOptimizationRule

if TYPE_CHECKING:
    from d810.ui.ida_ui import D810GUI

try:
    import pyinstrument  # type: ignore
except ImportError:
    pyinstrument = None

D810_LOG_DIR_NAME = "d810_logs"

logger = getLogger("D810")


class CProfileWrapper:
    """
    A simple wrapper around cProfile.Profile that exposes an `.is_running` property.
    """

    def __init__(self):
        self._profiler = cProfile.Profile()
        self._is_running = False

    @property
    def is_running(self):
        return self._is_running

    def enable(self, *args, **kwargs):
        self._profiler.enable(*args, **kwargs)
        self._is_running = True

    def disable(self):
        self._profiler.disable()
        self._is_running = False

    @property
    def profiler(self):
        return self._profiler


@dataclasses.dataclass
class D810Manager:
    log_dir: pathlib.Path
    stats: OptimizationStatistics = dataclasses.field(default_factory=OptimizationStatistics)
    instruction_optimizer_rules: list = dataclasses.field(default_factory=list)
    instruction_optimizer_config: dict = dataclasses.field(default_factory=dict)
    block_optimizer_rules: list = dataclasses.field(default_factory=list)
    block_optimizer_config: dict = dataclasses.field(default_factory=dict)
    ctree_optimizer_rules: list = dataclasses.field(default_factory=list)
    ctree_optimizer_config: dict = dataclasses.field(default_factory=dict)
    config: dict = dataclasses.field(default_factory=dict)
    event_emitter: EventEmitter = dataclasses.field(default_factory=EventEmitter)
    rule_scope_service: RuleScopeService = dataclasses.field(default_factory=RuleScopeService)
    storage: typing.Any = None
    _active_rule_recipe: RuleRecipeOverlay | None = dataclasses.field(default=None, init=False)
    profiler: typing.Any = dataclasses.field(
        default_factory=lambda: pyinstrument.Profiler() if pyinstrument else None
    )
    cprofiler: CProfileWrapper | None = dataclasses.field(
        default_factory=lambda: CProfileWrapper() if cProfile else None
    )
    instruction_optimizer: InstructionOptimizerManager = dataclasses.field(init=False)
    block_optimizer: BlockOptimizerManager = dataclasses.field(init=False)
    ctree_optimizer: CtreeOptimizerManager = dataclasses.field(init=False)
    hx_decompiler_hook: HexraysDecompilationHook = dataclasses.field(init=False)
    _started: bool = dataclasses.field(default=False, init=False)
    _profiling_enabled: bool = dataclasses.field(default=False, init=False)
    _start_ts: float = dataclasses.field(default=0.0, init=False)

    @property
    def started(self):
        return self._started

    def configure(self, **kwargs):
        self.config = kwargs

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
        """Return True if either cProfile or pyinstrument profiler is currently running."""
        if self.cprofiler and self.cprofiler.is_running:
            return True
        if self.profiler and getattr(self.profiler, "is_running", False):
            return True
        return False

    def start_profiling(self):
        if not self._profiling_enabled:
            return

        if self.cprofiler and not self.cprofiler.is_running:
            self.cprofiler.enable()
        if self.profiler and not self.profiler.is_running:
            self.profiler.start()

    def stop_profiling(self) -> pathlib.Path | None:
        if self.cprofiler and self.cprofiler.is_running:
            self.cprofiler.disable()
            output_path = self.log_dir / "d810_cprofile.prof"
            self.cprofiler.profiler.dump_stats(str(output_path))
            pstats.Stats(str(output_path)).strip_dirs().sort_stats("time").print_stats()
            return output_path
        if self.profiler and self.profiler.is_running:
            self.profiler.stop()
            self.profiler.print()
            # save the report as an HTML file in the log directory for easy access.
            output_path = self.log_dir / "d810_profile.html"
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(self.profiler.output_html())
            return output_path

    def enable_profiling(self):
        self._profiling_enabled = True
        self.start_profiling()

    def disable_profiling(self):
        self._profiling_enabled = False
        self.stop_profiling()

    def start(self):
        if self._started:
            self.stop()
        logger.debug("Starting manager...")
        self.rule_scope_service.attach(self.event_emitter)
        self._init_storage()
        self.rule_scope_service.set_overlay_provider(self._get_rule_overlay)
        self.rule_scope_service.set_active_recipe(self._active_rule_recipe)

        # Instantiate core manager classes from registry
        self.instruction_optimizer = InstructionOptimizerManager(self.stats, self.log_dir)
        project_name = str(self.config.get("project_name", ""))
        idb_key = str(self.config.get("idb_key", project_name))
        self.instruction_optimizer.configure(
            **self.instruction_optimizer_config,
            rule_scope_service=self.rule_scope_service,
            rule_scope_project_name=project_name,
            rule_scope_idb_key=idb_key,
        )
        self.block_optimizer = BlockOptimizerManager(self.stats, self.log_dir)
        self.block_optimizer.configure(
            **self.block_optimizer_config,
            rule_scope_service=self.rule_scope_service,
            rule_scope_project_name=project_name,
            rule_scope_idb_key=idb_key,
        )
        self.ctree_optimizer = CtreeOptimizerManager(self.stats)

        for rule in self.instruction_optimizer_rules:
            rule.log_dir = self.log_dir
            self.instruction_optimizer.add_rule(rule)

        for cfg_rule in self.block_optimizer_rules:
            cfg_rule.log_dir = self.log_dir
            self.block_optimizer.add_rule(cfg_rule)

        for ctree_rule in self.ctree_optimizer_rules:
            ctree_rule.log_dir = self.log_dir
            self.ctree_optimizer.add_rule(ctree_rule)

        self.hx_decompiler_hook = HexraysDecompilationHook(
            self.event_emitter.emit,
            ctree_optimizer_manager=self.ctree_optimizer,
        )
        self._compile_rule_scope()
        self._install_hooks()
        self._started = True

    def _init_storage(self) -> None:
        old_storage = self.storage
        backend = str(self.config.get("function_rules_backend", "sqlite")).strip().lower()
        target = self.config.get("function_rules_storage")
        if target is None:
            if backend == "sqlite":
                target = self.log_dir / "d810_function_rules.db"
            else:
                target = "$ d810.optimization_storage"
        try:
            if old_storage is not None:
                try:
                    old_storage.close()
                except Exception:
                    pass
            self.storage = create_optimization_storage(target, backend=backend)
            logger.info(
                "Function-rules storage configured: backend=%s target=%s",
                backend,
                target,
            )
            self._load_active_recipe_from_storage()
            self.emit_rule_scope_invalidation(
                RuleScopeEvent.IDB_OVERLAY_RELOADED,
                project_name=str(self.config.get("project_name", "")),
            )
        except Exception as exc:
            self.storage = None
            logger.warning("Failed to initialize function-rules storage: %s", exc)
            self.emit_rule_scope_invalidation(
                RuleScopeEvent.IDB_OVERLAY_RELOADED,
                project_name=str(self.config.get("project_name", "")),
            )

    def _load_active_recipe_from_storage(self) -> None:
        storage = self.storage
        if storage is None or not hasattr(storage, "get_active_rule_recipe"):
            self._active_rule_recipe = None
            self.rule_scope_service.set_active_recipe(None)
            return
        persisted = storage.get_active_rule_recipe()
        if persisted is None:
            self._active_rule_recipe = None
            self.rule_scope_service.set_active_recipe(None)
            return
        recipe = RuleRecipeOverlay(
            name=str(persisted.name).strip() or "unnamed_recipe",
            enabled_rules=frozenset(str(rule) for rule in persisted.enabled_rules),
            disabled_rules=frozenset(str(rule) for rule in persisted.disabled_rules),
            target_func_eas=frozenset(int(ea) for ea in persisted.target_func_eas),
            target_tags_any=frozenset(
                str(tag).strip() for tag in persisted.target_tags_any if str(tag).strip()
            ),
            target_tags_all=frozenset(
                str(tag).strip() for tag in persisted.target_tags_all if str(tag).strip()
            ),
            notes=str(persisted.notes),
        )
        self._active_rule_recipe = recipe
        self.rule_scope_service.set_active_recipe(recipe)
        self.emit_rule_scope_invalidation(
            RuleScopeEvent.RECIPE_APPLIED,
            project_name=str(self.config.get("project_name", "")),
            changed_rules=frozenset(recipe.enabled_rules | recipe.disabled_rules),
        )

    def _get_rule_overlay(self, function_ea: int) -> FunctionRuleOverlay | None:
        storage = self.storage
        if storage is None:
            return None
        config = storage.get_function_rules(function_ea)
        if config is None:
            return None
        return FunctionRuleOverlay(
            enabled_rules=frozenset(config.enabled_rules),
            disabled_rules=frozenset(config.disabled_rules),
            function_tags=frozenset(config.tags),
        )

    def get_function_rule_override(self, function_addr: int):
        if self.storage is None:
            self._init_storage()
        if self.storage is None:
            return None
        return self.storage.get_function_rules(function_addr)

    def set_function_rule_override(
        self,
        *,
        function_addr: int,
        enabled_rules: typing.Optional[typing.Set[str]] = None,
        disabled_rules: typing.Optional[typing.Set[str]] = None,
        notes: str = "",
    ) -> None:
        if self.storage is None:
            self._init_storage()
        if self.storage is None:
            logger.warning("Function-rules storage unavailable; override not persisted")
            return
        self.storage.set_function_rules(
            function_addr=function_addr,
            enabled_rules=enabled_rules,
            disabled_rules=disabled_rules,
            notes=notes,
        )
        self.emit_rule_scope_invalidation(
            RuleScopeEvent.FUNCTION_OVERRIDE_UPDATED,
            project_name=str(self.config.get("project_name", "")),
            func_eas=frozenset({int(function_addr)}),
            changed_rules=frozenset((enabled_rules or set()) | (disabled_rules or set())),
        )

    def get_function_tags(self, function_addr: int) -> set[str]:
        if self.storage is None:
            self._init_storage()
        if self.storage is None:
            return set()
        if not hasattr(self.storage, "get_function_tags"):
            return set()
        return set(self.storage.get_function_tags(function_addr))

    def set_function_tags(
        self,
        *,
        function_addr: int,
        tags: typing.Optional[typing.Set[str]] = None,
    ) -> None:
        if self.storage is None:
            self._init_storage()
        if self.storage is None:
            logger.warning("Function-rules storage unavailable; tags not persisted")
            return
        if not hasattr(self.storage, "set_function_tags"):
            logger.warning("Function-rules storage does not support function tags")
            return
        normalized_tags = {str(tag).strip() for tag in (tags or set()) if str(tag).strip()}
        self.storage.set_function_tags(function_addr, normalized_tags)
        self.emit_rule_scope_invalidation(
            RuleScopeEvent.FUNCTION_TAGS_UPDATED,
            project_name=str(self.config.get("project_name", "")),
            func_eas=frozenset({int(function_addr)}),
        )

    def set_active_rule_recipe(
        self,
        *,
        recipe_name: str,
        enabled_rules: typing.Optional[typing.Set[str]] = None,
        disabled_rules: typing.Optional[typing.Set[str]] = None,
        target_func_eas: typing.Optional[typing.Set[int]] = None,
        target_tags_any: typing.Optional[typing.Set[str]] = None,
        target_tags_all: typing.Optional[typing.Set[str]] = None,
        notes: str = "",
    ) -> None:
        if self.storage is None:
            self._init_storage()
        recipe = RuleRecipeOverlay(
            name=str(recipe_name).strip() or "unnamed_recipe",
            enabled_rules=frozenset(enabled_rules or set()),
            disabled_rules=frozenset(disabled_rules or set()),
            target_func_eas=frozenset(int(ea) for ea in (target_func_eas or set())),
            target_tags_any=frozenset(
                str(tag).strip() for tag in (target_tags_any or set()) if str(tag).strip()
            ),
            target_tags_all=frozenset(
                str(tag).strip() for tag in (target_tags_all or set()) if str(tag).strip()
            ),
            notes=notes,
        )
        self._active_rule_recipe = recipe
        self.rule_scope_service.set_active_recipe(recipe)
        if self.storage is not None and hasattr(self.storage, "set_active_rule_recipe"):
            self.storage.set_active_rule_recipe(
                ActiveRuleRecipeConfig(
                    name=recipe.name,
                    enabled_rules=set(recipe.enabled_rules),
                    disabled_rules=set(recipe.disabled_rules),
                    target_func_eas=set(recipe.target_func_eas),
                    target_tags_any=set(recipe.target_tags_any),
                    target_tags_all=set(recipe.target_tags_all),
                    notes=recipe.notes,
                )
            )
        self.emit_rule_scope_invalidation(
            RuleScopeEvent.RECIPE_APPLIED,
            project_name=str(self.config.get("project_name", "")),
            changed_rules=frozenset((enabled_rules or set()) | (disabled_rules or set())),
        )

    def clear_active_rule_recipe(self) -> None:
        if self.storage is None:
            self._init_storage()
        self._active_rule_recipe = None
        self.rule_scope_service.set_active_recipe(None)
        if self.storage is not None and hasattr(self.storage, "clear_active_rule_recipe"):
            self.storage.clear_active_rule_recipe()
        self.emit_rule_scope_invalidation(
            RuleScopeEvent.RECIPE_CLEARED,
            project_name=str(self.config.get("project_name", "")),
        )

    def get_active_rule_recipe(self) -> RuleRecipeOverlay | None:
        return self._active_rule_recipe

    def _compile_rule_scope(self) -> None:
        self.rule_scope_service.compile_base_rules(
            project_name=str(self.config.get("project_name", "")),
            instruction_rules=self.instruction_optimizer_rules,
            flow_rules=self.block_optimizer_rules,
            ctree_rules=self.ctree_optimizer_rules,
        )

    def _start_timer(self):
        self._start_ts = time.perf_counter()

    def _stop_timer(self, report: bool = True):
        if report:
            m, s = divmod(time.perf_counter() - self._start_ts, 60)
            logger.info(
                "Decompilation finished in %dm %ds",
                int(m),
                int(s),
            )
        self._start_ts = 0.0

    def _install_hooks(self):
        # must become before listeners are installed
        for _subscriber in (
            self.start_profiling,
            self.stats.reset,
            MOP_CONSTANT_CACHE.clear,
            MOP_TO_AST_CACHE.clear,
            self.instruction_optimizer.reset_cycle_detection,
            self.block_optimizer.reset_pass_counter,
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

        self.instruction_optimizer.install()
        self.block_optimizer.install()
        self.hx_decompiler_hook.hook()

    def configure_instruction_optimizer(self, rules, **kwargs):
        self.instruction_optimizer_rules = [rule for rule in rules]
        self.instruction_optimizer_config = kwargs

    def configure_block_optimizer(self, rules, **kwargs):
        self.block_optimizer_rules = [rule for rule in rules]
        self.block_optimizer_config = kwargs

    def configure_ctree_optimizer(self, rules, **kwargs):
        self.ctree_optimizer_rules = [rule for rule in rules]
        self.ctree_optimizer_config = kwargs

    def stop(self):
        if not self._started:
            return
        self._started = False

        self.instruction_optimizer.remove()
        self.block_optimizer.remove()
        self.hx_decompiler_hook.unhook()
        self.event_emitter.clear()
        if self.profiler or self.cprofiler:
            self.stop_profiling()
        if self.storage is not None:
            try:
                self.storage.close()
            except Exception:
                pass
            self.storage = None


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
        if hasattr(self, 'manager') and self.manager is not None:
            return self.manager.stats
        # Return a fresh stats object if manager not yet initialized
        return OptimizationStatistics()

    def reset(self) -> None:
        self._initialized: bool = False
        self.d810_config: D810Configuration = D810Configuration()
        # manage projects via ProjectManager
        self.project_manager = ProjectManager(self.d810_config)
        self.current_project_index: int = 0
        self.current_ins_rules: typing.List = []
        self.current_blk_rules: typing.List = []
        self.known_ins_rules: typing.List = []
        self.known_blk_rules: typing.List = []
        self._is_loaded: bool = False
        self.gui = None  # Reset gui reference
        # Perform logger setup based on current config
        self.log_dir = self.d810_config.log_dir / D810_LOG_DIR_NAME
        if self.d810_config.get("erase_logs_on_reload"):
            clear_logs(self.log_dir)
        configure_loggers(self.log_dir)
        # Always rely on the D810Configuration.log_dir property which falls back
        # to a sensible default when the option is missing, instead of reading
        # the raw option that may be None and break pathlib.Path construction.
        self.manager = D810Manager(self.log_dir)
        self._initialized = True

    def add_project(self, config: ProjectConfiguration):
        self.project_manager.add(config)

    def update_project(
        self, old_config: ProjectConfiguration, new_config: ProjectConfiguration
    ):
        self.project_manager.update(old_config.path.name, new_config)

    def del_project(self, config: ProjectConfiguration):
        self.project_manager.delete(config)

    def load_project(self, project_index: int) -> ProjectConfiguration:
        self.current_project_index = project_index
        self.current_project = self.project_manager.get(project_index)
        self.current_ins_rules = []
        self.current_blk_rules = []

        for rule in self.known_ins_rules:
            for rule_conf in self.current_project.ins_rules:
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
            for rule_conf in self.current_project.blk_rules:
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
        cfg = dict(self.current_project.additional_configuration)
        cfg.setdefault("project_name", self.current_project.path.name)
        self.manager.configure(**cfg)
        self.manager.emit_rule_scope_invalidation(
            RuleScopeEvent.PROJECT_RULES_RELOADED,
            project_name=self.current_project.path.name,
        )
        if self.manager.started:
            self.manager.instruction_optimizer.configure(
                **self.manager.instruction_optimizer_config,
                rule_scope_service=self.manager.rule_scope_service,
                rule_scope_project_name=self.current_project.path.name,
                rule_scope_idb_key=str(cfg.get("idb_key", self.current_project.path.name)),
            )
            self.manager.block_optimizer.configure(
                rule_scope_service=self.manager.rule_scope_service,
                rule_scope_project_name=self.current_project.path.name,
                rule_scope_idb_key=str(cfg.get("idb_key", self.current_project.path.name)),
            )
            self.manager._compile_rule_scope()
        logger.debug(
            "Loaded project %s (%s) from %s",
            self.current_project.path.name,
            self.current_project.description,
            self.current_project.path,
        )
        return self.current_project

    def start_d810(self):
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
        self.manager.start()
        print("D-810 ready to deobfuscate...")
        self.d810_config.set("last_project_index", self.current_project_index)
        self.d810_config.save()

    def stop_d810(self):
        print("Stopping D-810...")
        self.manager.stop()

    def load(self, gui: bool = True):
        self.reset()
        # Determine which project to auto-load. Fall back to first entry (0)
        # when the configuration value is missing or invalid, and clamp the
        # index to the available range to avoid IndexError when projects were
        # renamed or removed.
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

        # Build lists of available rules, skipping abstract / hidden ones
        self.known_ins_rules = [
            rule_cls()
            for rule_cls in InstructionOptimizationRule.registry.values()
            if not inspect.isabstract(rule_cls)
        ]

        # Add VerifiableRules (DSL-based MBA rules) wrapped with IDA adapter
        # These rules use the new DSL system for pattern matching and verification
        verifiable_instances = VerifiableRule.instantiate_all()
        self.known_ins_rules.extend(adapt_rules(verifiable_instances))

        self.known_blk_rules = [
            rule_cls()
            for rule_cls in FlowOptimizationRule.registry.values()
            if not inspect.isabstract(rule_cls)
        ]

        # Clamp to available projects, if any
        if projects := len(self.project_manager):
            self.current_project_index = max(
                0, min(self.current_project_index, projects - 1)
            )
            self._is_loaded = self.load_project(self.current_project_index) is not None
        else:
            logger.warning("No project configurations available; plugin is idle.")
            self.current_project = None  # type: ignore[assignment]
            self._is_loaded = False

        if gui and self._is_loaded:
            # Lazy import to avoid Qt dependency in headless mode
            from d810.ui.ida_ui import D810GUI
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
