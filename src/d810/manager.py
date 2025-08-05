from __future__ import annotations

import contextlib
import dataclasses
import inspect
import pathlib
import typing

from d810.conf import D810Configuration, ProjectConfiguration
from d810.conf.loggers import clear_logs, configure_loggers, getLogger
from d810.expr.utils import MOP_CONSTANT_CACHE, MOP_TO_AST_CACHE
from d810.hexrays.hexrays_hooks import (
    BlockOptimizerManager,
    DecompilationEvent,
    HexraysDecompilationHook,
    InstructionOptimizerManager,
)
from d810.optimizers.microcode.flow.handler import FlowOptimizationRule
from d810.optimizers.microcode.instructions.handler import InstructionOptimizationRule
from d810.project_manager import ProjectManager
from d810.registry import EventEmitter
from d810.singleton import SingletonMeta
from d810.ui.ida_ui import D810GUI

try:
    import pyinstrument  # type: ignore
except ImportError:
    pyinstrument = None

D810_LOG_DIR_NAME = "d810_logs"

logger = getLogger("D810")


@dataclasses.dataclass
class D810Manager:
    log_dir: pathlib.Path
    instruction_optimizer_rules: list = dataclasses.field(default_factory=list)
    instruction_optimizer_config: dict = dataclasses.field(default_factory=dict)
    block_optimizer_rules: list = dataclasses.field(default_factory=list)
    block_optimizer_config: dict = dataclasses.field(default_factory=dict)
    config: dict = dataclasses.field(default_factory=dict)
    event_emitter: EventEmitter = dataclasses.field(default_factory=EventEmitter)
    profiler: typing.Any = dataclasses.field(
        default_factory=lambda: pyinstrument.Profiler() if pyinstrument else None
    )
    instruction_optimizer: InstructionOptimizerManager = dataclasses.field(init=False)
    block_optimizer: BlockOptimizerManager = dataclasses.field(init=False)
    hx_decompiler_hook: HexraysDecompilationHook = dataclasses.field(init=False)
    _started: bool = dataclasses.field(default=False, init=False)

    @property
    def started(self):
        return self._started

    def configure(self, **kwargs):
        self.config = kwargs

    def start_profiling(self):
        if self.profiler and not self.profiler.is_running:
            self.profiler.start()

    def stop_profiling(self) -> pathlib.Path | None:
        if self.profiler and self.profiler.is_running:
            self.profiler.stop()
            self.profiler.print()
            # save the report as an HTML file in the log directory for easy access.
            output_path = self.log_dir / "d810_profile.html"
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(self.profiler.output_html())
            return output_path

    def start(self):
        if self._started:
            self.stop()
        logger.debug("Starting manager...")

        # Instantiate core manager classes from registry
        self.instruction_optimizer = InstructionOptimizerManager(self.log_dir)
        self.instruction_optimizer.configure(**self.instruction_optimizer_config)
        self.block_optimizer = BlockOptimizerManager(self.log_dir)
        self.block_optimizer.configure(**self.block_optimizer_config)

        for rule in self.instruction_optimizer_rules:
            rule.log_dir = self.log_dir
            self.instruction_optimizer.add_rule(rule)

        for cfg_rule in self.block_optimizer_rules:
            cfg_rule.log_dir = self.log_dir
            self.block_optimizer.add_rule(cfg_rule)

        self.hx_decompiler_hook = HexraysDecompilationHook(self.event_emitter.emit)
        self._install_hooks()
        self._started = True

    def _install_hooks(self):
        # must become before listeners are installed
        for _subscriber in (
            self.start_profiling,
            self.instruction_optimizer.reset_rule_usage_statistic,
            self.block_optimizer.reset_rule_usage_statistic,
            MOP_CONSTANT_CACHE.clear,
            MOP_TO_AST_CACHE.clear,
        ):
            self.event_emitter.on(DecompilationEvent.STARTED, _subscriber)

        for _subscriber in (
            self.stop_profiling,
            self.instruction_optimizer.show_rule_usage_statistic,
            self.block_optimizer.show_rule_usage_statistic,
            lambda: logger.info(
                "MOP_CONSTANT_CACHE stats: %s", MOP_CONSTANT_CACHE.stats
            ),
            lambda: logger.info("MOP_TO_AST_CACHE stats: %s", MOP_TO_AST_CACHE.stats),
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

    def stop(self):
        if not self._started:
            return
        self._started = False

        self.instruction_optimizer.remove()
        self.block_optimizer.remove()
        self.hx_decompiler_hook.unhook()
        self.event_emitter.clear()
        if self.profiler:
            self.stop_profiling()


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
        self.reset()

    def is_loaded(self):
        return self._is_loaded

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
                    rule_conf.config["dump_intermediate_microcode"] = (
                        self.d810_config.get("dump_intermediate_microcode")
                    )
                    rule.configure(rule_conf.config)
                    rule.set_log_dir(self.log_dir)
                    self.current_ins_rules.append(rule)
        logger.debug("Instruction rules configured")
        for blk_rule in self.known_blk_rules:
            for rule_conf in self.current_project.blk_rules:
                if not rule_conf.is_activated:
                    continue
                if blk_rule.name == rule_conf.name:
                    rule_conf.config["dump_intermediate_microcode"] = (
                        self.d810_config.get("dump_intermediate_microcode")
                    )
                    blk_rule.configure(rule_conf.config)
                    blk_rule.set_log_dir(self.log_dir)
                    self.current_blk_rules.append(blk_rule)
        logger.debug("Block rules configured")
        self.manager.configure(**self.current_project.additional_configuration)
        logger.debug(
            "Loaded project %s (%s) from %s",
            self.current_project.path.name,
            self.current_project.description,
            self.current_project.path,
        )
        return self.current_project

    def start_d810(self):
        print("D-810 ready to deobfuscate...")
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
        self.current_project = self.project_manager.get(self.current_project_index)

        self.current_ins_rules = []
        self.current_blk_rules = []

        # Build lists of available rules, skipping abstract / hidden ones
        self.known_ins_rules = [
            rule_cls()
            for rule_cls in InstructionOptimizationRule.registry.values()
            if not inspect.isabstract(rule_cls)
        ]

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
            self._is_loaded = False

        if gui and self._is_loaded:
            self.gui = D810GUI(self)
            self.gui.show_windows()

    def unload(self, gui: bool = True):
        self.manager.stop()
        if gui and self._is_loaded:
            self.gui.term()
            del self.gui
        self._is_loaded = False

    @contextlib.contextmanager
    def for_project(self, name: str) -> typing.Generator[int, None, None]:
        _old_project_index = self.current_project_index
        project_index = self.project_manager.index(name)
        if project_index != _old_project_index:
            logger.info("switching to project %s", name)
        self.load_project(project_index)
        yield project_index
        if project_index != _old_project_index:
            logger.info("switching back to project %s", _old_project_index)
            self.load_project(_old_project_index)
