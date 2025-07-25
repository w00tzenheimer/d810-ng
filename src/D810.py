import abc
import ast
import bisect
import contextlib
import importlib
import importlib.machinery
import importlib.util
import inspect
import pathlib
import pkgutil
import sys
import time
import typing

import ida_hexrays
import ida_kernwin
import idaapi

import d810
import d810._compat as _compat

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


class DependencyGraph:
    """Smart dependency tracking for modules with memory optimization."""

    def __init__(self, pkg_prefix: str) -> None:
        self._pkg_prefix = pkg_prefix
        self._module_dependencies: dict[str, set[str]] = {}
        self._reverse_dependencies: dict[str, set[str]] = {}
        self._last_scan_time: dict[str, float] = {}
        self._last_cleanup: float = time.time()

        # Cached cycle / topo information (invalidated on every update)
        self._dirty: bool = True
        self._cycles: list[set[str]] = []
        self._topo_order: list[str] = []

    def scan_dependencies(self, file_path: pathlib.Path) -> set[str]:
        """Scan a Python file for import dependencies."""
        if not file_path.exists() or file_path.suffix != ".py":
            return set()

        try:
            with file_path.open(encoding="utf-8") as f:
                content = f.read()

            tree = ast.parse(content, filename=str(file_path))
            dependencies: set[str] = set()

            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    self._process_import_node(node, dependencies)
                elif isinstance(node, ast.ImportFrom):
                    self._process_import_from_node(node, dependencies, file_path)

        except Exception as e:
            print(f"Error scanning dependencies in {file_path}: {e}")
            return set()
        else:
            return dependencies

    def _process_import_node(self, node: ast.Import, dependencies: set[str]) -> None:
        """Process a regular import node."""
        for alias in node.names:
            if alias.name and alias.name.startswith(self._pkg_prefix):
                dependencies.add(alias.name)

    def _process_import_from_node(
        self, node: ast.ImportFrom, dependencies: set[str], file_path: pathlib.Path
    ) -> None:
        """Process an import-from node."""
        if node.module and node.module.startswith(self._pkg_prefix):
            dependencies.add(node.module)
        elif node.level > 0:
            self._process_relative_import(node, dependencies, file_path)

    def _process_relative_import(
        self, node: ast.ImportFrom, dependencies: set[str], file_path: pathlib.Path
    ) -> None:
        """Process relative imports."""
        if node.module:
            # Standard relative import: from .module import something
            if (
                abs_module := self._resolve_relative_import(
                    file_path, node.module, node.level
                )
            ) and abs_module.startswith(self._pkg_prefix):
                dependencies.add(abs_module)
        else:
            # Pure relative import: from . import something
            for alias in node.names:
                if (
                    alias.name
                    and (
                        abs_module := self._resolve_relative_import(
                            file_path, None, node.level, alias.name
                        )
                    )
                    and abs_module.startswith(self._pkg_prefix)
                ):
                    dependencies.add(abs_module)

    def _resolve_relative_import(
        self,
        file_path: pathlib.Path,
        module: str | None,
        level: int,
        imported_name: str | None = None,
    ) -> str | None:
        """Resolve relative imports to absolute module names.

        If `module` is None (pure relative import), treat as importing from the current package.
        """
        try:
            # Get the module path relative to tux package
            base_dir = pathlib.Path(__file__).parent.parent
            relative_path = file_path.relative_to(base_dir)

            # Calculate the parent directory based on level
            path_parts = list(relative_path.parts[:-1])  # Remove filename

            # Go up 'level' directories
            for _ in range(level - 1):
                if path_parts:
                    path_parts.pop()

            if module is None and imported_name is not None:
                # Pure relative import: from . import foo
                # Remove the last component (the module itself) to get the package
                package_parts = path_parts.copy()
                if package_parts:
                    return (
                        f"{self._pkg_prefix}.{'.'.join(package_parts)}.{imported_name}"
                    )
                return f"{self._pkg_prefix}.{imported_name}"

            # Add the relative module if provided
            if module:
                path_parts.extend(module.split("."))

            if path_parts:
                return f"{self._pkg_prefix}.{'.'.join(path_parts)}"
        except (ValueError, IndexError) as e:
            print(f"Failed to resolve relative import: {e}")

        return None

    def update_dependencies(
        self, file_path: pathlib.Path | str, module_name: str
    ) -> None:
        """Update dependency tracking for a module."""
        if isinstance(file_path, str):
            file_path = pathlib.Path(file_path)

        dependencies = self.scan_dependencies(file_path)

        # Clean up old reverse dependencies
        if module_name in self._module_dependencies:
            for old_dep in self._module_dependencies[module_name]:
                if old_dep in self._reverse_dependencies:
                    self._reverse_dependencies[old_dep].discard(module_name)
                    if not self._reverse_dependencies[old_dep]:
                        del self._reverse_dependencies[old_dep]

        # Update forward dependencies
        self._module_dependencies[module_name] = dependencies

        # Update reverse dependencies
        for dep in dependencies:
            if dep not in self._reverse_dependencies:
                self._reverse_dependencies[dep] = set()
            self._reverse_dependencies[dep].add(module_name)

        # Update scan time
        self._last_scan_time[module_name] = time.time()

        # Periodic cleanup
        self._cleanup_if_needed()

        # Mark cached analytics stale
        self._dirty = True

    def get_dependents(self, module_name: str) -> set[str]:
        """Get direct dependents of a module."""
        return self._reverse_dependencies.get(module_name, set()).copy()

    def get_transitive_dependents(
        self, module_name: str, max_depth: int = 100
    ) -> set[str]:
        """Get all transitive dependents of a module with cycle detection."""
        visited: set[str] = set()
        result: set[str] = set()

        def _visit(current_module: str, depth: int) -> None:
            if depth >= max_depth or current_module in visited:
                return

            visited.add(current_module)
            direct_dependents = self.get_dependents(current_module)

            for dependent in direct_dependents:
                if dependent not in result:
                    result.add(dependent)
                    _visit(dependent, depth + 1)

        _visit(module_name, 0)
        return result

    def get_all_tracked_modules(self) -> list[str]:
        """Get all tracked modules."""
        return list(self._module_dependencies.keys())

    def get_module_dependencies(self, module_name: str) -> set[str]:
        """Get direct dependencies of a module."""
        return self._module_dependencies.get(module_name, set()).copy()

    def get_stats(self) -> dict[str, int]:
        """Get statistics about the dependency graph."""
        return {
            "total_modules": len(self._module_dependencies),
            "total_reverse_deps": len(self._reverse_dependencies),
        }

    def get_cycles(self) -> list[set[str]]:
        self._recompute_graph_info()
        return self._cycles.copy()

    def topo_order(self, *, skip: set[str] | None = None) -> list[str]:
        """Return dependency-respecting reload order."""
        self._recompute_graph_info()
        skip = skip or set()
        return [m for m in self._topo_order if m not in skip]

    def _build_adjacency(self) -> dict[str, set[str]]:
        """Return adjacency list with implicit parent-package edges."""
        adj: dict[str, set[str]] = {}
        for mod, deps in self._module_dependencies.items():
            dset = set(deps)
            # Add implicit parent packages (pkg.sub → pkg)
            parts = mod.split(".")
            for i in range(1, len(parts)):
                parent = ".".join(parts[:i])
                if parent.startswith(self._pkg_prefix):
                    dset.add(parent)
            adj[mod] = dset
        return adj

    def _recompute_graph_info(self):
        if not self._dirty:
            return

        adj = self._build_adjacency()

        # Kosaraju algorithm
        order: list[str] = []
        visited: set[str] = set()

        def dfs(v: str):
            visited.add(v)
            for n in adj.get(v, ()):  # forward edges
                if n not in visited:
                    dfs(n)
            order.append(v)

        for v in adj:
            if v not in visited:
                dfs(v)

        # Build reverse adjacency
        radj: dict[str, list[str]] = {}
        for u, ds in adj.items():
            for v in ds:
                radj.setdefault(v, []).append(u)

        visited.clear()
        scc_index: dict[str, int] = {}
        sccs: list[set[str]] = []

        def dfs_rev(v: str, comp: set[str]):
            visited.add(v)
            comp.add(v)
            for n in radj.get(v, ()):  # reverse edge
                if n not in visited:
                    dfs_rev(n, comp)

        for v in reversed(order):
            if v not in visited:
                comp: set[str] = set()
                dfs_rev(v, comp)
                sccs.append(comp)
                for node in comp:
                    scc_index[node] = len(sccs) - 1

        self._cycles = [c for c in sccs if len(c) > 1]

        # Topological sort of condensed graph
        indeg: list[int] = [0] * len(sccs)
        children: list[set[int]] = [set() for _ in sccs]
        for u, deps in adj.items():
            for v in deps:
                cu, cv = scc_index[u], scc_index[v]
                if cu != cv and cu not in children[cv]:
                    # Edge from dependency (v) -> dependent (u)
                    children[cv].add(cu)
                    indeg[cu] += 1

        # queue of SCC indices with zero indeg, alphabetical by *repr* name
        zero = sorted(i for i, d in enumerate(indeg) if d == 0)
        order_modules: list[str] = []
        while zero:
            i = zero.pop(0)
            # append members alphabetically for deterministic order
            order_modules.extend(sorted(sccs[i]))
            for j in children[i]:
                indeg[j] -= 1
                if indeg[j] == 0:
                    bisect.insort(zero, j)

        # Any remaining modules are in cycles that couldn't be resolved (shouldn't happen)
        unresolved = [m for m in adj if m not in order_modules]
        order_modules.extend(sorted(unresolved))

        self._topo_order = order_modules
        self._dirty = False

    def _cleanup_if_needed(self) -> None:
        """Perform cleanup if threshold is exceeded or enough time has passed."""
        current_time = time.time()

        should_cleanup = current_time - self._last_cleanup > 3600  # 1 hour

        if should_cleanup:
            self._cleanup_stale_entries()
            self._last_cleanup = current_time

    def _cleanup_stale_entries(self) -> None:
        """Clean up stale entries from caches."""
        current_time = time.time()
        stale_threshold = 3600  # 1 hour

        # Clean up old scan times and associated data
        stale_modules = [
            module
            for module, scan_time in self._last_scan_time.items()
            if current_time - scan_time > stale_threshold
        ]

        for module in stale_modules:
            self._remove_module_tracking(module)

        if stale_modules:
            print(f"Cleaned up {len(stale_modules)} stale dependency entries")

    def _remove_module_tracking(self, module_name: str) -> None:
        """Remove all tracking data for a module."""
        # Remove from scan times
        self._last_scan_time.pop(module_name, None)

        # Clean up dependencies
        if module_name in self._module_dependencies:
            for dep in self._module_dependencies[module_name]:
                if dep in self._reverse_dependencies:
                    self._reverse_dependencies[dep].discard(module_name)
                    if not self._reverse_dependencies[dep]:
                        del self._reverse_dependencies[dep]
            del self._module_dependencies[module_name]

        # Remove reverse dependencies
        if module_name in self._reverse_dependencies:
            del self._reverse_dependencies[module_name]


def _reload_package_with_graph(
    *,
    pkg_path: typing.Iterable[str],
    base_package: str,
    skip_prefixes: tuple[str, ...] = (),
    suppress_errors: bool = False,
) -> None:
    """Reload *base_package* and all its sub-modules in dependency order.

    Parameters
    ----------
    pkg_path
        The ``__path__`` attribute of the package (e.g. ``d810.__path__``).
    base_package
        Fully-qualified name of the package to reload (e.g. ``'d810'``).
    skip_prefixes
        Tuple of module-name prefixes that must **not** be reloaded.
    suppress_errors
        If *True*, swallow ``ModuleNotFoundError`` raised while reloading.
    """

    disallow_reload: set[str] = {
        name for name in sys.modules if any(name.startswith(p) for p in skip_prefixes)
    }

    dg = DependencyGraph(base_package + ".")

    _Scanner.scan(
        pkg_path,
        base_package + ".",
        callback=lambda m: (
            dg.update_dependencies(m.__file__, m.__name__)
            if (hasattr(m, "__file__") and m.__file__)
            else None
        ),
        skip_packages=False,
    )

    cycles = dg.get_cycles()
    ordered_names = dg.topo_order(skip=disallow_reload)

    if cycles:
        core_cycles = [", ".join(sorted(c)) for c in cycles]
        print(
            f"[{base_package}][reloader] WARNING: cyclic import groups detected:\n  "
            + "\n  ".join(core_cycles)
        )

    for name in ordered_names:
        if name not in sys.modules:
            continue
        try:
            print(f"Reloading {name} ..")
            importlib.reload(sys.modules[name])
        except ModuleNotFoundError as e:
            if suppress_errors:
                print(f"[{base_package}][reloader] Suppressed reload error: {e}")
            else:
                raise


# reload one module (depth-first)* sort_key controls sibling reload order.
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
        skip_packages: bool = False,
    ):
        if isinstance(package_path, pathlib.Path):
            package_path = str(package_path)
        # print(f"Scanning package {package_path} with prefix {prefix}")
        for mod_info in pkgutil.walk_packages(package_path, prefix=prefix):
            if skip_packages and mod_info.ispkg:
                # print(f"Skipping package {mod_info.name}")
                continue

            # Always attempt to load the module, *including* packages, so that
            # every discovered module becomes visible in ``sys.modules``*  This
            # guarantees that later dependency-aware reloading sees brand-new
            # additions on disk even if they have never been imported before.

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

    @_compat.override
    @abc.abstractmethod
    def run(self, args): ...

    @_compat.override
    @abc.abstractmethod
    def term(self): ...


class LateInitPlugin(Plugin):

    def __init__(self):
        super().__init__()
        self._ui_hooks: _UIHooks = _UIHooks()

    @_compat.override
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

    @_compat.override
    def update(self, ctx: ida_kernwin.action_ctx_base_t) -> int:
        return idaapi.AST_ENABLE_ALWAYS

    @_compat.override
    def activate(self, ctx: ida_kernwin.action_ctx_base_t):
        with self.plugin_setup_reload():
            self.reload()
        return 1

    @_compat.override
    def late_init(self):
        self.add_plugin_to_console()
        self.register_reload_action()

    @_compat.override
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

    @_compat.override
    def init(self):
        if not init_hexrays():
            print(f"{self.wanted_name} need Hex-Rays decompiler* Skipping")
            return idaapi.PLUGIN_SKIP

        kv = ida_kernwin.get_kernel_version().split(".")
        if (int(kv[0]) < 7) or ((int(kv[0]) == 7) and (int(kv[1]) < 5)):
            print(f"{self.wanted_name} need IDA version >= 7.5* Skipping")
            return idaapi.PLUGIN_SKIP
        return super().init()

    @_compat.override
    def late_init(self):
        super().late_init()
        if not ida_hexrays.init_hexrays_plugin():
            print(f"{self.wanted_name} need Hex-Rays decompiler* Unloading...")
            self.term()
        print(f"{self.wanted_name} initialized (version {D810_VERSION})")

    @_compat.override
    def run(self, args):
        with self.plugin_setup_reload():
            self.reload()

    @_compat.override
    def term(self):
        super().term()
        print(f"Terminating {self.wanted_name}...")

    @_compat.override
    def reload(self):
        """Hot-reload the *entire* package.

        The method delegates to a standalone helper, ``_reload_package_with_graph``, that:

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

        _reload_package_with_graph(
            pkg_path=d810.__path__,
            base_package=self.base_package_name,
            skip_prefixes=(f"{self.base_package_name}.registry",),
            suppress_errors=self.suppress_reload_errors,
        )


def PLUGIN_ENTRY():
    return D810Plugin()
