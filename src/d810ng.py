import ida_hexrays
import ida_kernwin
import idaapi

import d810
from d810._vendor.ida_reloader import ReloadablePluginBase, reload_package
from d810.core.typing import override

D810_VERSION = d810.__version__


# Processor id -> Hex-Rays decompiler plugin name. Copied verbatim from
# d810.hexrays.utils.ida_utils so this plugin entry module imports nothing from
# d810 proper for the decompiler load/init path (only from d810._vendor). Keep
# in sync with ida_utils if either helper changes.
ALL_DECOMPILERS = {
    idaapi.PLFM_386: "hexx64",
    idaapi.PLFM_ARM: "hexarm",
    idaapi.PLFM_PPC: "hexppc",
    idaapi.PLFM_MIPS: "hexmips",
    idaapi.PLFM_RISCV: "hexrv",
}


def decompiler_for_current_arch() -> "str | None":
    """Return the Hex-Rays decompiler plugin name for the current processor,
    or ``None`` if this architecture has no known decompiler."""
    return ALL_DECOMPILERS.get(idaapi.ph.id, None)


def ensure_hexrays_available(force_load: bool = False) -> bool:
    """Ensure the Hex-Rays decompiler is initialized.

    With ``force_load=False`` an already-available decompiler is initialized but
    the decompiler plugin is never eagerly ``load_plugin``-ed, so callers on the
    plugin-init / IDB-open path do not force hexx64 to load. Callers that
    genuinely need the decompiler (e.g. ``start_d810``) pass ``force_load=True``
    to load it on demand.
    """
    decompiler = decompiler_for_current_arch()
    if not decompiler:
        return False
    if ida_hexrays.init_hexrays_plugin():
        return True
    if (
        force_load
        and idaapi.load_plugin(decompiler)
        and ida_hexrays.init_hexrays_plugin()
    ):
        return True
    return False


# NOTE: the decompiler load is DEFERRED off plugin init(): late_init() starts
# D810 after IDA has completed the plugin-init path, and start_d810() loads the
# matching decompiler on demand immediately before installing microcode hooks.


class _UIHooks(idaapi.UI_Hooks):
    def ready_to_run(self):
        pass


class D810Plugin(
    ReloadablePluginBase,
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
        # Only verify the architecture has a known decompiler; do NOT load it
        # here. init() runs as PLUGIN_PROC (during IDB open), and d810's
        # microcode hooks do not install until start_d810() -- so the decompiler
        # load is deferred there. This avoids force-loading hexx64 on every IDB
        # open, which is unnecessary work on the first-decompile path.
        # Announce the running build before anything can fail: a bug report is
        # only actionable if it names a version (ticket d81-zijs).
        version = getattr(d810, "__version__", "unknown")
        print(f"d810-ng {version}")
        _register_ida_addon(version)

        if decompiler_for_current_arch() is None:
            print(
                f"{self.wanted_name}: no known Hex-Rays decompiler for this "
                "architecture. Skipping"
            )
            return idaapi.PLUGIN_SKIP

        kv = ida_kernwin.get_kernel_version().split(".")
        if (int(kv[0]) < 7) or ((int(kv[0]) == 7) and (int(kv[1]) < 5)):
            print(f"{self.wanted_name} need IDA version >= 7.5. Skipping")
            return idaapi.PLUGIN_SKIP
        return super().init()

    @override
    def late_init(self):
        super().late_init()
        loaded = self.plugin.is_loaded()
        if not loaded:
            self.plugin.load()
            loaded = self.plugin.is_loaded()
        manager = getattr(self.plugin, "manager", None)
        if loaded and manager is not None and not manager.started:
            self.plugin.start_d810()
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

        was_started = bool(
            getattr(getattr(self.plugin, "manager", None), "started", False)
        )
        with self.plugin_setup_reload():
            reload_package(
                d810,
                skip=[
                    f"{self.base_package_name}.core.registry",
                    f"{self.base_package_name}._vendor",
                ],
                suppress_errors=self.suppress_reload_errors,
            )
        manager = getattr(self.plugin, "manager", None)
        if (
            was_started
            and self.plugin.is_loaded()
            and manager is not None
            and not manager.started
        ):
            self.plugin.start_d810()


# noinspection PyPep8Naming
def _register_ida_addon(version: str) -> None:
    """List d810-ng in IDA's own About -> Addons box (ticket d81-zijs).

    ``register_addon`` is documented in the SDK as "Register an add-on. Show
    its info in the About box", which is exactly where users look to confirm
    what is loaded. Best-effort: failing to appear in a list is never worth
    blocking plugin init.
    """
    try:
        info = ida_kernwin.addon_info_t()
        info.id = "com.w00tzenheimer.d810ng"
        info.name = "d810-ng"
        info.producer = "w00tzenheimer, mahmoudimus"
        info.version = version
        info.url = "https://github.com/w00tzenheimer/d810-ng"
        ida_kernwin.register_addon(info)
    except Exception:  # noqa: BLE001 - cosmetic registration, never fatal
        pass


def PLUGIN_ENTRY():
    return D810Plugin()
