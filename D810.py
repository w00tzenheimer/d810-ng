import abc
import contextlib
import dataclasses
import os
import sys
import types
import typing

from d810.conf import D810Configuration
from d810.log import clear_logs, configure_loggers
from d810.manager import D810_LOG_DIR_NAME, D810State

import ida_hexrays
import ida_idp
import ida_kernwin
import ida_loader
import idaapi

D810_VERSION = "0.1"


def init_hexrays() -> bool:
    ALL_DECOMPILERS = {
        idaapi.PLFM_386: "hexx64",
        idaapi.PLFM_ARM: "hexarm",
        idaapi.PLFM_PPC: "hexppc",
        idaapi.PLFM_MIPS: "hexmips",
        idaapi.PLFM_RISCV: "hexrv",
    }
    cpu = idaapi.ph.id
    decompiler = ALL_DECOMPILERS.get(cpu, None)
    if not decompiler:
        print("No known decompilers for architecture with ID: %d" % idaapi.ph.id)
        return False
    if idaapi.load_plugin(decompiler) and idaapi.init_hexrays_plugin():
        return True
    else:
        print(f"Couldn't load or initialize decompiler: {decompiler}")
        return False


class Plugin(abc.ABC, idaapi.plugin_t):

    @abc.abstractmethod
    def init(self): ...

    @typing.override
    @abc.abstractmethod
    def run(self, args): ...

    @typing.override
    @abc.abstractmethod
    def term(self): ...


class _UIHooks(idaapi.UI_Hooks):

    def ready_to_run(self):
        pass


class LateInitPlugin(Plugin):

    def __init__(self):
        super().__init__()
        self._ui_hooks: _UIHooks = _UIHooks()

    @typing.override
    def init(self):
        self._ui_hooks.ready_to_run = self.ready_to_run
        if not self._ui_hooks.hook():
            print("LateInitPlugin.__init__ hooking failed!", file=sys.stderr)
            return idaapi.PLUGIN_SKIP
        return idaapi.PLUGIN_OK

    def ready_to_run(self):
        super(_UIHooks, self._ui_hooks).ready_to_run()
        self.late_init()
        self._ui_hooks.unhook()

    @abc.abstractmethod
    def late_init(self): ...


class ReloadablePlugin(LateInitPlugin, idaapi.action_handler_t):
    def __init__(
        self,
        *,
        global_name: str,
        base_package_name: str,
        plugin_class: type,
    ):
        super().__init__()
        self.global_name = global_name
        self.base_package_name = base_package_name
        self.plugin_class = plugin_class

    @typing.override
    def update(self, ctx: ida_kernwin.action_ctx_base_t) -> int:
        return idaapi.AST_ENABLE_ALWAYS

    @typing.override
    def activate(self, ctx: ida_kernwin.action_ctx_base_t):
        self.reload()
        return 1

    @typing.override
    def late_init(self):
        self.add_plugin_to_console()
        self.register_reload_action()

    @typing.override
    def term(self):
        self.unregister_reload_action()
        if self.plugin_class is not None and hasattr(self.plugin_class, "unload"):
            self.plugin_class.unload()

    def register_reload_action(self):
        idaapi.register_action(
            idaapi.action_desc_t(
                f"{self.global_name}:reload_plugin",
                f"Reload plugin: {self.global_name}",
                self,
            )
        )

    def unregister_reload_action(self):
        idaapi.unregister_action(f"{self.global_name}:reload_plugin")

    def add_plugin_to_console(self):
        # add plugin to the IDA python console scope, for test/dev/cli access
        setattr(sys.modules["__main__"], self.global_name, self)

    def reload(self):
        """Hot-reload the plugin core."""
        print(f"[{getattr(self, 'wanted_name', 'plugin')}] Reloading...")

        # # Unload the core and all its components
        # was_mounted = self.plugin.mounted if self.plugin else True
        # if self.plugin is not None:
        #     self.plugin.unload()

        # # Reload all modules in the base package
        # modules_to_reload = [
        #     module_name
        #     for module_name in sys.modules
        #     if module_name.startswith(self.base_package_name)
        # ]
        # for module_name in modules_to_reload:
        #     with contextlib.suppress(ModuleNotFoundError):
        #         idaapi.require(module_name)

        # # Load the plugin core
        # self.plugin = self.plugin_class()

        # self.term()

        # self.d810_config = D810Configuration()

        # # TO-DO: if [...].get raises an exception because log_dir is not found, handle exception
        # real_log_dir = os.path.join(self.d810_config.get("log_dir"), D810_LOG_DIR_NAME)

        # # TO-DO: if [...].get raises an exception because erase_logs_on_reload is not found, handle exception
        # if self.d810_config.get("erase_logs_on_reload"):
        #     clear_logs(real_log_dir)

        # configure_loggers(real_log_dir)
        # self.state = D810State(self.d810_config)
        # print("D-810 reloading...")
        # self.state.start_plugin()


class D810Plugin(ReloadablePlugin):
    #
    # Plugin flags:
    # - PLUGIN_MOD: plugin may modify the database
    # - PLUGIN_PROC: Load/unload plugin when an IDB opens / closes
    # - PLUGIN_HIDE: Hide plugin from the IDA plugin menu  (if this is set, wanted_hotkey is ignored!)
    # - PLUGIN_FIX: Keep plugin alive after IDB is closed
    #
    #

    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_MOD
    wanted_name = "D810"
    wanted_hotkey = "Ctrl-Shift-D"
    comment = "Interface to the D810 plugin"
    help = ""

    def __init__(self):
        super().__init__(
            global_name="D810",
            base_package_name="d810",
            plugin_class=D810State,
        )

    @typing.override
    def init(self):
        if not init_hexrays():
            print(f"{self.wanted_name} need Hex-Rays decompiler. Skipping")
            return idaapi.PLUGIN_SKIP

        kv = ida_kernwin.get_kernel_version().split(".")
        if (int(kv[0]) < 7) or ((int(kv[0]) == 7) and (int(kv[1]) < 5)):
            print(f"{self.wanted_name} need IDA version >= 7.5. Skipping")
            return idaapi.PLUGIN_SKIP
        return super().init()

    @typing.override
    def late_init(self):
        super().late_init()
        if not ida_hexrays.init_hexrays_plugin():
            print(f"{self.wanted_name} need Hex-Rays decompiler. Unloading...")
            self.term()
        print(f"{self.wanted_name} initialized (version {D810_VERSION})")

    @typing.override
    def run(self, args):
        self.reload()

    @typing.override
    def term(self):
        super().term()
        print(f"Terminating {self.wanted_name}...")


def PLUGIN_ENTRY():
    return D810Plugin()
