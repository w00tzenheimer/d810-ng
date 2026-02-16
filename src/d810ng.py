import ida_hexrays
import ida_kernwin
import idaapi

import d810
import d810._vendor
import d810._vendor.ida_reloader as reloadable
from d810.core.typing import override

D810_VERSION = d810.__version__


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


class _UIHooks(idaapi.UI_Hooks):

    def ready_to_run(self):
        pass


class D810Plugin(
    reloadable.ReloadablePluginBase,
    idaapi.action_handler_t,
    idaapi.plugin_t,
):
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
            plugin_class="d810.manager.D810State",
            hook_cls=_UIHooks,
            skip_code=idaapi.PLUGIN_SKIP,
            ok_code=idaapi.PLUGIN_OK,
        )
        self.suppress_reload_errors = False

    @override
    def init(self):
        if not init_hexrays():
            print(f"{self.wanted_name} need Hex-Rays decompiler. Skipping")
            return idaapi.PLUGIN_SKIP

        kv = ida_kernwin.get_kernel_version().split(".")
        if (int(kv[0]) < 7) or ((int(kv[0]) == 7) and (int(kv[1]) < 5)):
            print(f"{self.wanted_name} need IDA version >= 7.5. Skipping")
            return idaapi.PLUGIN_SKIP
        return super().init()

    @override
    def late_init(self):
        super().late_init()
        if not ida_hexrays.init_hexrays_plugin():
            print(f"{self.wanted_name} need Hex-Rays decompiler. Unloading...")
            self.term()
        print(f"{self.wanted_name} initialized (version {D810_VERSION})")

    @override
    def run(self, args):
        self.reload()

    @override
    def term(self):
        super().term()
        print(f"Terminating {self.wanted_name}...")

    def register_reload_action(self):
        """Register the reload action in IDA."""
        idaapi.register_action(
            idaapi.action_desc_t(
                f"{self.global_name}:reload_plugin",
                f"Reload plugin: {self.global_name}",
                self,
            )
        )

    def unregister_reload_action(self):
        """Unregister the reload action from IDA."""
        idaapi.unregister_action(f"{self.global_name}:reload_plugin")

    @override
    def update(self, ctx: ida_kernwin.action_ctx_base_t) -> int:
        """Action handler update - always enabled."""
        return idaapi.AST_ENABLE_ALWAYS

    @override
    def activate(self, ctx: ida_kernwin.action_ctx_base_t):
        """Action handler activate - triggers reload."""
        with self.plugin_setup_reload():
            self.reload()
        return 1

    @override
    def reload(self):
        """Hot-reload the *entire* package.

        The method delegates to ``reloadable.reload_package``, which:

        1. Builds a static import graph for every Python source living under
           the plugin directory.
        2. Detects strongly-connected components (true import cycles).
        3. Produces a deterministic topological order of those components.
        4. Reloads modules in that order, guaranteeing that **all in-package
           dependencies are reloaded before the code that relies on them**.

        Modules whose names match prefixes in ``d810.registry`` are skipped.
        The helper prints a concise warning listing only the *core* cycles it
        found; modules merely *blocked* by a cycle are ordered automatically.
        """

        with self.plugin_setup_reload():
            reloadable.reload_package(
                d810,
                skip=[
                    f"{self.base_package_name}.core.registry",
                    f"{self.base_package_name}._vendor",
                ],
                suppress_errors=self.suppress_reload_errors,
            )


def PLUGIN_ENTRY():
    return D810Plugin()
