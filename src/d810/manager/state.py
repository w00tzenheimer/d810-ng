"""Runtime project state for the D810 plugin."""
from __future__ import annotations

import contextlib
import inspect
import importlib
import pathlib

from d810.backends.hexrays.registration import register_hexrays_backend_providers
from d810.backends.mba.ida import adapt_rules
from d810.core import typing
from d810.core.config import D810Configuration, ProjectConfiguration
from d810.core.logging import clear_logs, configure_loggers, getLogger
from d810.core.platform import resolve_arch_config
from d810.core.project import (
    ProjectContext,
    ProjectManager,
    emit_project_reloading,
)
from d810.core.registry import SingletonMeta
from d810.core.rule_scope import RuleScopeEvent
from d810.core.stats import OptimizationStatistics
from d810.core.typing import TYPE_CHECKING
from d810.mba.rules import VerifiableRule
from d810.optimizers.microcode.flow.handler import FlowOptimizationRule
from d810.optimizers.microcode.instructions.handler import InstructionOptimizationRule

if TYPE_CHECKING:
    from d810.manager import D810Manager
    from d810.ui.ida_ui import D810GUI

logger = getLogger("D810")
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
        self.project_manager = ProjectManager(self.d810_config)
        self.current_project_index: int = 0
        self.current_ins_rules: typing.List = []
        self.current_blk_rules: typing.List = []
        self.known_ins_rules: typing.List = []
        self.known_blk_rules: typing.List = []
        self._is_loaded: bool = False
        self.gui = None
        self.log_dir = self.d810_config.log_dir / D810_LOG_DIR_NAME
        if self.d810_config.get("erase_logs_on_reload"):
            clear_logs(self.log_dir)
        configure_loggers(self.log_dir)
        manager_module = importlib.import_module("d810.manager")
        self.manager = manager_module.D810Manager(self.log_dir)
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
        old_project_name = (
            self.current_project.path.name
            if getattr(self, "current_project", None) is not None
            else None
        )
        next_project = self.project_manager.get(project_index)
        emit_project_reloading(
            old_project_name=old_project_name,
            new_project_name=next_project.path.name,
        )
        self.current_project_index = project_index
        self.current_project = next_project
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
                rule_scope_idb_key=str(
                    cfg.get("idb_key", self.current_project.path.name)
                ),
                pass_scheduler=self.manager.instruction_pass_scheduler,
            )
            self.manager.block_optimizer.configure(
                rule_scope_service=self.manager.rule_scope_service,
                rule_scope_project_name=self.current_project.path.name,
                rule_scope_idb_key=str(
                    cfg.get("idb_key", self.current_project.path.name)
                ),
                pass_scheduler=self.manager.block_pass_scheduler,
                function_priors_provider=(
                    self.manager.function_analysis_priors_for_ea
                ),
            )
            self.manager._compile_rule_scope()
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
        return self.current_project

    def _register_backend_analysis_providers(self) -> None:
        """Register backend-supplied analysis seams before runtime starts."""
        register_hexrays_backend_providers()

    def start_d810(self):
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
        self.manager.start()
        logger.info("D-810 ready to deobfuscate...")
        self.d810_config.set("last_project_index", self.current_project_index)
        self.d810_config.save()

    def stop_d810(self):
        logger.info("Stopping D-810...")
        self.manager.stop()

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

        self.known_ins_rules = [
            rule_cls()
            for rule_cls in InstructionOptimizationRule.registry.values()
            if not inspect.isabstract(rule_cls)
        ]

        verifiable_instances = VerifiableRule.instantiate_all()
        self.known_ins_rules.extend(adapt_rules(verifiable_instances))

        self.known_blk_rules = [
            rule_cls()
            for rule_cls in FlowOptimizationRule.registry.values()
            if not inspect.isabstract(rule_cls)
        ]

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
