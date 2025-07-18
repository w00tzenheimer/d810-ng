import abc
import contextlib
import importlib
import importlib.machinery
import importlib.util
import inspect
import pathlib
import pkgutil
import sys
import types
import typing

import ida_hexrays
import ida_kernwin
import idaapi

import d810

# from d810.manager import D810State


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


# reload one module (depth-first). sort_key controls sibling reload order.
def reload_module(
    module,
    to_reload: set,
    disallow_reload: set[str],
    *,
    sort_key: typing.Callable[[typing.Any], typing.Any] | None = None,
):
    """Depth-first reload of *module* and its (already imported) sub-modules.

    Parameters
    ----------
    module
        The root module from which the traversal starts.
    to_reload
        Set of all modules to reload; mutated to avoid repeats.
    disallow_reload
        Names of modules to skip.
    sort_key
        Optional key to sort dependencies before reload.
    """

    # Skip modules not scheduled or explicitly disallowed
    if module not in to_reload or module.__name__ in disallow_reload:
        return

    # Mark as processed to prevent cycles
    to_reload.remove(module)

    # Reload dependencies first (depth-first)
    children = [
        dep
        for _, dep in inspect.getmembers(module, lambda k: inspect.ismodule(k))
        if dep in to_reload and dep.__name__ not in disallow_reload
    ]
    if sort_key is not None:
        children.sort(key=sort_key)
    for child in children:
        reload_module(child, to_reload, disallow_reload, sort_key=sort_key)

    # Finally reload this module
    print(f"Reloading {module.__name__} ..")
    importlib.reload(module)


# reload all code
def reload_plugin(
    pkgname: str,
    *,
    disallow_reload: set[str] | None = None,
    sort_key: typing.Callable[[typing.Any], typing.Any] | None = None,
):

    to_reload = set()
    disallow_reload = disallow_reload or set()
    for k, mod in sys.modules.items():
        if k.startswith(pkgname) and k not in disallow_reload:
            to_reload.add(mod)

    # Copy the set because *to_reload* will be mutated during traversal.
    for mod in list(to_reload):
        reload_module(mod, to_reload, disallow_reload, sort_key=sort_key)


class _Scanner:

    @classmethod
    def _load_module(
        cls, spec: importlib.machinery.ModuleSpec, callback: typing.Callable | None
    ):
        if spec.loader is None:
            return

        module = importlib.util.module_from_spec(spec)
        # print(f"Loading module {module.__name__}")
        # module is already loaded
        if module.__name__ in sys.modules:
            module = sys.modules[module.__name__]

        # load the module
        else:
            sys.modules[module.__name__] = module
            try:
                spec.loader.exec_module(module)
            except BaseException as e:  # //NOSONAR
                sys.modules.pop(module.__name__)
                print(
                    f"Error while loading extension {spec.name}: {e}",
                    file=sys.stderr,
                )
                return

        if callback is not None:
            callback(module)

    @classmethod
    def scan(
        cls,
        package_path: pathlib.Path | typing.Iterable[str] | str,
        prefix: str,
        callback=None,
    ):
        if isinstance(package_path, pathlib.Path):
            package_path = str(package_path)
        print(f"Scanning package {package_path} with prefix {prefix}")
        for mod_info in pkgutil.walk_packages(package_path, prefix=prefix):
            print(f"Scanning module {mod_info.name}, ispkg? {mod_info.ispkg}")
            if mod_info.ispkg:
                continue

            spec = mod_info.module_finder.find_spec(mod_info.name, None)
            if spec is None:
                continue

            cls._load_module(spec, callback)


class _UIHooks(idaapi.UI_Hooks):

    def ready_to_run(self):
        pass


class Plugin(abc.ABC, idaapi.plugin_t):

    @abc.abstractmethod
    def init(self): ...

    @typing.override
    @abc.abstractmethod
    def run(self, args): ...

    @typing.override
    @abc.abstractmethod
    def term(self): ...


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
        plugin_class: str,
    ):
        super().__init__()
        self.global_name = global_name
        self.base_package_name = base_package_name
        self.plugin_class = plugin_class
        self.plugin = self._import_plugin_cls()

    def _import_plugin_cls(self):
        self.plugin_module, self.plugin_class_name = self.plugin_class.rsplit(".", 1)
        mod = importlib.import_module(self.plugin_module)
        return getattr(mod, self.plugin_class_name)()

    @typing.override
    def update(self, ctx: ida_kernwin.action_ctx_base_t) -> int:
        return idaapi.AST_ENABLE_ALWAYS

    @typing.override
    def activate(self, ctx: ida_kernwin.action_ctx_base_t):
        with self.plugin_setup_reload():
            self.reload()
        return 1

    @typing.override
    def late_init(self):
        self.add_plugin_to_console()
        self.register_reload_action()

    @typing.override
    def term(self):
        self.unregister_reload_action()
        if self.plugin is not None and hasattr(self.plugin, "unload"):
            self.plugin.unload()

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

    @contextlib.contextmanager
    def plugin_setup_reload(self):
        """Hot-reload the plugin core."""
        # Collect all modules via scanner callback

        # Unload existing plugin if loaded
        if self.plugin.is_loaded():
            self.unregister_reload_action()
            self.term()
            self.plugin = self._import_plugin_cls()

        yield

        # Re-register action and load plugin
        self.register_reload_action()
        print(f"{self.global_name} reloading...")
        self.add_plugin_to_console()
        self.plugin.load()

    @abc.abstractmethod
    def reload(self): ...


def module_sort_key(module) -> tuple[bool, str]:
    """
    Sort modules alphabetically by their qualified name, except
    if the module's last path segment is 'optimizers', which
    will always sort after all others.
    """
    full_name = module.__name__
    print(">>>>>>>>>>", "module_sort_key: ", full_name)
    _, _, submodule = full_name.partition(".")
    # (is_optimizers, name) → False sorts before True, then by name
    return submodule.startswith("optimizers."), full_name


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
            plugin_class="d810.manager.D810State",
        )
        self.suppress_reload_errors = False

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
        with self.plugin_setup_reload():
            self.reload()

    @typing.override
    def term(self):
        super().term()
        print(f"Terminating {self.wanted_name}...")

    @typing.override
    def reload(self):
        modules: list[types.ModuleType] = []
        _Scanner.scan(
            d810.__path__,
            self.base_package_name + ".",
            callback=modules.append,
        )

        # Treat these entries as *prefixes* - any module whose fully-qualified
        # name starts with one of these strings will be filtered out. This gives
        # us simple glob-like behaviour without bringing in fnmatch.
        disallowed_prefixes: tuple[str, ...] = (
            f"{self.base_package_name}.registry",
            f"{self.base_package_name}.tests",
        )

        filtered = [
            m
            for m in modules
            if m.__name__.startswith(self.base_package_name)
            and not any(m.__name__.startswith(prefix) for prefix in disallowed_prefixes)
        ]
        # Sort so that 'optimizers' packages come last, then alphabetically
        filtered.sort(
            key=lambda m: (
                m.__name__.startswith(f"{self.base_package_name}.optimizers"),
                m.__name__,
            )
        )
        # Reload each module in sorted order
        for m in filtered:
            print(f"Reloading {m.__name__} ..")
            if self.suppress_reload_errors:
                with contextlib.suppress(ModuleNotFoundError):
                    # idaapi.require(m)
                    importlib.reload(m)
            else:
                # idaapi.require(m)
                importlib.reload(m)


def PLUGIN_ENTRY():
    return D810Plugin()
