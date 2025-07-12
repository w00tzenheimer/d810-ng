from __future__ import annotations

import dataclasses
import logging
import os
import pathlib
import threading
import typing

import pyinstrument
from d810.conf import D810Configuration, ProjectConfiguration
from d810.conf.loggers import clear_logs, configure_loggers
from d810.hexrays.hexrays_hooks import (
    BlockOptimizerManager,
    HexraysDecompilationHook,
    InstructionOptimizerManager,
)
from d810.optimizers.flow.handler import FlowOptimizationRule
from d810.optimizers.instructions.handler import InstructionOptimizationRule
from d810.ui.ida_ui import D810GUI

D810_LOG_DIR_NAME = "d810_logs"

logger = logging.getLogger("D810")


class D810Manager(object):
    def __init__(self, log_dir: pathlib.Path):
        self.instruction_optimizer_rules = []
        self.instruction_optimizer_config = {}
        self.block_optimizer_rules = []
        self.block_optimizer_config = {}
        self.instruction_optimizer = None
        self.block_optimizer = None
        self.hx_decompiler_hook = None
        self.log_dir = log_dir
        self.config = {}
        self.profiler = pyinstrument.Profiler()

    def configure(self, **kwargs):
        self.config = kwargs

    def start_profiling(self):
        if not self.profiler.is_running:
            self.profiler.start()

    def stop_profiling(self):
        if self.profiler.is_running:
            self.profiler.stop()
            self.profiler.print()

    def reload(self):
        self.stop()
        logger.debug("Reloading manager...")

        # Instantiate core manager classes from registry
        self.instruction_optimizer = InstructionOptimizerManager(self)
        self.instruction_optimizer.configure(**self.instruction_optimizer_config)
        self.block_optimizer = BlockOptimizerManager(self)
        self.block_optimizer.configure(**self.block_optimizer_config)

        for rule in self.instruction_optimizer_rules:
            rule.log_dir = self.log_dir
            self.instruction_optimizer.add_rule(rule)

        for cfg_rule in self.block_optimizer_rules:
            cfg_rule.log_dir = self.log_dir
            self.block_optimizer.add_rule(cfg_rule)

        self.instruction_optimizer.install()
        self.block_optimizer.install()

        self.hx_decompiler_hook = HexraysDecompilationHook(self)
        self.hx_decompiler_hook.hook()

    def configure_instruction_optimizer(self, rules, **kwargs):
        self.instruction_optimizer_rules = [rule for rule in rules]
        self.instruction_optimizer_config = kwargs

    def configure_block_optimizer(self, rules, **kwargs):
        self.block_optimizer_rules = [rule for rule in rules]
        self.block_optimizer_config = kwargs

    def stop(self):
        if self.instruction_optimizer is not None:
            logger.debug("Removing InstructionOptimizer...")
            self.instruction_optimizer.remove()
            self.instruction_optimizer = None
        if self.block_optimizer is not None:
            logger.debug("Removing ControlFlowFixer...")
            self.block_optimizer.remove()
            self.block_optimizer = None
        if self.hx_decompiler_hook is not None:
            logger.debug("Removing HexraysDecompilationHook...")
            self.hx_decompiler_hook.unhook()
            self.hx_decompiler_hook = None


@dataclasses.dataclass
class D810State:
    """
    Thread-safe singleton dataclass with optional lazy-loading of configuration.

    If `lazy_load_config` is False (default), configuration and loggers
    are initialized immediately. If True, config instantiation and
    logger setup are deferred until first access of `d810_config`.
    """

    # Toggle for lazy configuration loading
    lazy_load_config: bool = False

    # Singleton internals
    _instance: typing.ClassVar[typing.Optional["D810State"]] = None
    _lock: typing.ClassVar[threading.Lock] = threading.Lock()
    _initialized: typing.ClassVar[bool] = False
    _config: typing.ClassVar[typing.Optional[D810Configuration]] = None

    def __new__(cls, *args, **kwargs) -> "D810State":
        # Double-checked locking for thread-safe singleton creation
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __post_init__(self) -> None:
        # Eager initialization if lazy_load_config is disabled
        cls = type(self)
        if not self.lazy_load_config and not cls._initialized:
            with cls._lock:
                if not cls._initialized:
                    self.load(init_only=True)

    @classmethod
    def get(cls, lazy_load_config: bool = False) -> "D810State":
        """
        Retrieve the singleton instance, optionally setting lazy behavior
        on first creation.
        """
        return cls(lazy_load_config=lazy_load_config)

    @property
    def d810_config(self) -> D810Configuration:
        """
        Access the configuration, loading and initializing if needed.
        """
        cls = type(self)
        with cls._lock:
            if cls._config is None:
                # Instantiate config when first accessed
                self._load_config()
            if self.lazy_load_config and not cls._initialized:
                # Perform deferred initialization
                self._initialize()
        return cls._config  # type: ignore

    def _initialize(self) -> None:
        # Perform logger setup based on current config
        config = self.d810_config
        real_log_dir = os.path.join(
            config.get("log_dir"),
            D810_LOG_DIR_NAME,
        )
        if config.get("erase_logs_on_reload"):
            clear_logs(real_log_dir)
        configure_loggers(real_log_dir)
        type(self)._initialized = True

    def _load_config(self) -> None:
        # Helper to eager-load the configuration
        type(self)._config = D810Configuration()

    def is_loaded(self):
        return self._is_loaded

    def _resolve_config_path(self, cfg_name: str) -> pathlib.Path:
        """Return the full path to the configuration file.

        Precedence order:
        1. *Writable* user directory  <IDA_USER>/cfg/d810/<cfg_name>
        2. Built-in read-only templates shipped with the plugin
            (located next to this file in d810/conf/).
        """
        user_path = self.d810_config.config_dir / cfg_name
        if user_path.exists():
            return user_path

        # Fallback to read-only template bundled with the plugin
        return pathlib.Path(__file__).resolve().parent / "conf" / cfg_name

    def register_default_projects(self):
        self.projects = []
        for cfg_name in self.d810_config.get("configurations"):
            cfg_path = self._resolve_config_path(cfg_name)
            try:
                project_configuration = ProjectConfiguration.from_file(cfg_path)
            except Exception as e:
                logger.error("Failed to load project config %s: %s", cfg_path, e)
                continue
            self.projects.append(project_configuration)

        logger.debug("Rule configurations loaded: %s", self.projects)

    def add_project(self, config: ProjectConfiguration):
        self.projects.append(config)
        self.d810_config.get("configurations").append(config.path)
        self.d810_config.save()

    def update_project(
        self, old_config: ProjectConfiguration, new_config: ProjectConfiguration
    ):
        old_config_index = self.projects.index(old_config)
        self.projects[old_config_index] = new_config

    def del_project(self, config: ProjectConfiguration):
        self.projects.remove(config)
        self.d810_config.get("configurations").remove(
            config.path.name
        )  # store only the name
        self.d810_config.save()

        # Only allow deletion when the file lives in the user cfg directory
        try:
            user_cfg_root = self.d810_config.config_dir.resolve()
            cfg_path = config.path.resolve()
            if user_cfg_root in cfg_path.parents:
                cfg_path.unlink(missing_ok=True)
            else:
                logger.warning("Refusing to delete read-only template: %s", cfg_path)
        except Exception as e:
            logger.error("Failed to delete project file %s: %s", config.path, e)

    def load_project(self, project_index: int):
        self.current_project_index = project_index
        self.current_project = self.projects[project_index]
        self.current_ins_rules = []
        self.current_blk_rules = []

        for rule in self.known_ins_rules:
            for rule_conf in self.current_project.ins_rules:
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
                if blk_rule.name == rule_conf.name:
                    rule_conf.config["dump_intermediate_microcode"] = (
                        self.d810_config.get("dump_intermediate_microcode")
                    )
                    blk_rule.configure(rule_conf.config)
                    blk_rule.set_log_dir(self.log_dir)
                    self.current_blk_rules.append(blk_rule)
        logger.debug("Block rules configured")
        self.manager.configure(**self.current_project.additional_configuration)
        logger.debug("Project loaded.")
        return True

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
        self.manager.reload()
        self.d810_config.set("last_project_index", self.current_project_index)
        self.d810_config.save()

    def stop_d810(self):
        print("Stopping D-810...")
        if getattr(self, "manager", None):
            self.manager.stop()

    def load(self, init_only: bool = False):
        self._load_config()
        self._initialize()
        if init_only:
            return

        self.log_dir = pathlib.Path(self.d810_config.get("log_dir")) / D810_LOG_DIR_NAME
        self.manager = D810Manager(self.log_dir)

        self.gui = None
        self.current_project = None
        self.projects: list[ProjectConfiguration] = []
        self.current_project_index = int(self.d810_config.get("last_project_index"))
        self.current_ins_rules = []
        self.current_blk_rules = []

        self.known_ins_rules = [
            rule()
            for rule in InstructionOptimizationRule.registry.values()
            if rule.__name__ != "jumpoptimizationrule"
        ]
        self.known_blk_rules = [
            rule() for rule in FlowOptimizationRule.registry.values()
        ]

        self.register_default_projects()
        self._is_loaded = self.load_project(self.current_project_index)
        self.gui = D810GUI(self)
        self.gui.show_windows()

    def unload(self):
        if getattr(self, "manager", None):
            self.manager.stop()

        if getattr(self, "gui", None):
            self.gui.term()
            self.gui = None
        self._is_loaded = False


"""
JUMP_OPTIMIZATION_RULES = [x() for x in get_all_subclasses(JumpOptimizationRule)]
jump_fixer = JumpFixer()
for jump_optimization_rule in JUMP_OPTIMIZATION_RULES:
    jump_fixer.register_rule(jump_optimization_rule)
JUMP_OPTIMIZATION_BLOCK_RULES = [jump_fixer]
"""
