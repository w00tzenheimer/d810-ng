"""
Hot-reload infrastructure for an IDA Plugin.

This module provides a `Reloader` class that can reload an entire package
in dependency order, with support for priority modules and cycle detection.

The reloader itself is designed to be reloadable - when the parent code
reloads this module, it should create a new Reloader instance to pick up
the newly loaded class definition.
"""

__version__ = "0.1.0"

import abc
import ast
import bisect
import contextlib
import importlib
import importlib.machinery
import importlib.util
import os
import pathlib
import pkgutil
import platform
import sys
import time
import traceback
import types
import typing
from collections.abc import Iterable, Sequence

# Handle override decorator for Python 3.10/3.11 compatibility
if hasattr(typing, "override"):
    override = typing.override
else:
    F = typing.TypeVar("F", bound=typing.Callable[..., typing.Any])

    def override(fn: F, /) -> F:
        return fn


def overrides(parent_class):
    """Simple decorator that checks that a method with the same name exists in the parent class"""
    # I tried typing.override (Python 3.12+), but support for it does not seem to be ideal (yet)
    # and portability also is an issue. https://github.com/google/pytype/issues/1915 Maybe in 3 years.

    def overrider(method):
        if platform.python_implementation() == "PyPy":
            return method

        assert method.__name__ in dir(parent_class)
        parent_method = getattr(parent_class, method.__name__)
        assert callable(parent_method)

        if os.getenv("CHECK_OVERRIDES", "").lower() not in (
            "1",
            "yes",
            "on",
            "enable",
            "enabled",
        ):
            return method

        # Example return of get_type_hints:
        # {'path': <class 'str'>,
        #  'return': typing.Union[typing.Iterable[str], typing.Dict[str, bytes, NoneType]}
        parent_types = typing.get_type_hints(parent_method)
        # If the parent is not typed, then do not show errors for the typed derived class.
        for argument, argument_type in typing.get_type_hints(method).items():
            if argument in parent_types:
                parent_type = parent_types[argument]
                assert (
                    argument_type == parent_type
                ), f"{method.__name__}: {argument}: {argument_type} != {parent_type}"

        return method

    return overrider


class DependencyGraph:
    """Smart dependency tracking for modules with memory optimization."""

    class _TypeCheckingVisitor(ast.NodeVisitor):
        """Visitor to ignore imports inside TYPE_CHECKING guards."""

        def __init__(
            self,
            graph: "DependencyGraph",
            file_path: pathlib.Path,
        ):
            self.graph = graph
            self.file_path = file_path
            self.dependencies: set[str] = set()

        def is_type_checking_if(self, node: ast.If) -> bool:
            # Detect `if TYPE_CHECKING:` or `if typing.TYPE_CHECKING:`
            # if TYPE_CHECKING:
            assert isinstance(node, ast.If)
            test = node.test
            # Case 1: TYPE_CHECKING
            if isinstance(test, ast.Name) and test.id == "TYPE_CHECKING":
                return True
            # Case 2: typing.TYPE_CHECKING
            elif (
                isinstance(test, ast.Attribute)
                and isinstance(test.value, ast.Name)
                and test.value.id == "typing"
                and test.attr == "TYPE_CHECKING"
            ):
                return True
            return False

        def visit_If(self, node: ast.If) -> None:
            if self.is_type_checking_if(node):
                # Skip the entire block under this guard
                return
            # Otherwise recurse normally
            self.generic_visit(node)

        def visit_Import(self, node: ast.Import) -> None:
            self.graph._process_import_node(node, self.dependencies)

        def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
            self.graph._process_import_from_node(
                node, self.dependencies, self.file_path
            )

    def __init__(self, pkg_prefix: str, pkg_paths: Iterable[str] = ()) -> None:
        self._pkg_prefix = pkg_prefix
        self._pkg_paths = [pathlib.Path(p) for p in pkg_paths]
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
            visitor = self._TypeCheckingVisitor(self, file_path)
            visitor.visit(tree)
        except Exception as e:
            print(f"Error scanning dependencies in {file_path}: {e}")
            return set()
        else:
            return visitor.dependencies

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
            # Get the module path relative to plugin package
            # Find the plugin package root by going up from this file
            base_dir = pathlib.Path(__file__).parent.parent
            relative_path = None

            # Try provided package paths first
            for path in self._pkg_paths:
                try:
                    relative_path = file_path.relative_to(path)
                    break
                except ValueError:
                    continue

            # Fallback to location-based deduction if no path matched
            if relative_path is None:
                # Find the plugin package root by going up from this file
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


class Scanner:
    """Module scanner that loads and discovers all modules in a package."""

    @classmethod
    def _load_module(
        cls, spec: importlib.machinery.ModuleSpec, callback: typing.Callable | None
    ):
        if spec.loader is None:
            return

        module = importlib.util.module_from_spec(spec)
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
                    f"Error while loading extension {spec.name} - {e}\n{traceback.format_exc()}",
                    file=sys.stderr,
                )
                return

        if callback is not None:
            callback(module)

    @classmethod
    def scan(
        cls,
        package_path: pathlib.Path | Iterable[str] | str,
        prefix: str,
        callback=None,
        skip_packages: bool = False,
    ):
        if isinstance(package_path, pathlib.Path):
            package_path = str(package_path)
        # print(f"Scanning package {package_path} with prefix {prefix}")
        for mod_info in pkgutil.walk_packages(package_path, prefix=prefix):
            if skip_packages and mod_info.ispkg:
                continue

            # Always attempt to load the module, *including* packages, so that
            # every discovered module becomes visible in ``sys.modules``. This
            # guarantees that later dependency-aware reloading sees brand-new
            # additions on disk even if they have never been imported before.

            spec = mod_info.module_finder.find_spec(mod_info.name, None)
            if spec is None:
                continue

            cls._load_module(spec, callback)


def _reload_package_with_graph(
    pkg_path: Iterable[str],
    base_package: str,
    skip_prefixes: tuple[str, ...] = (),
    suppress_errors: bool = False,
) -> None:
    """
    Hot-reload an entire package using dependency graph analysis.

    This internal function:
    1. Scans all modules in the package and builds a dependency graph
    2. Detects strongly-connected components (import cycles)
    3. Produces a topological order respecting dependencies
    4. Reloads modules in that order

    Parameters
    ----------
    pkg_path : Iterable[str]
        Package search paths (e.g., mypackage.__path__)
    base_package : str
        Base package name (e.g., "mypackage")
    skip_prefixes : tuple[str, ...]
        Module name prefixes to skip during reload
    suppress_errors : bool
        Whether to suppress ModuleNotFoundError during reload

    Notes
    -----
    This ensures all in-package dependencies are reloaded before the code
    that relies on them. Modules whose names match skip_prefixes are excluded
    from reloading.
    """
    # Build dependency graph
    dg = DependencyGraph(base_package + ".", pkg_paths=pkg_path)

    # Scan and discover all modules in the package
    def update_deps(module):
        if file_path := getattr(module, "__file__", None):
            dg.update_dependencies(file_path, module.__name__)

    Scanner.scan(
        pkg_path,
        base_package + ".",
        callback=update_deps,
        skip_packages=False,
    )

    # Get topological order, skipping specified prefixes
    skip_set = set(
        name
        for name in sys.modules
        if any(name.startswith(prefix) for prefix in skip_prefixes)
    )
    order = dg.topo_order(skip=skip_set)

    # Detect and report cycles
    cycles = dg.get_cycles()
    if cycles:
        core_cycles = [", ".join(sorted(c)) for c in cycles]
        print(
            f"[{base_package}][reload] WARNING: cyclic import groups detected:\n  "
            + "\n  ".join(core_cycles)
        )

    # Reload all modules in dependency order
    for name in order:
        if name not in sys.modules:
            continue
        try:
            print(f"Reloading {name} ...")
            importlib.reload(sys.modules[name])
        except ModuleNotFoundError as e:
            if suppress_errors:
                print(f"[{base_package}][reload] suppressed {e}")
            else:
                raise


def reload_package(
    target: str | types.ModuleType,
    *,
    skip: Sequence[str] = (),
    suppress_errors: bool = False,
) -> None:
    """
    Recursively reload a package and its submodules in dependency order.

    This function provides a convenient interface for hot-reloading packages.
    It automatically handles dependency tracking and ensures modules are
    reloaded in the correct order to avoid stale references.

    Parameters
    ----------
    target : str | types.ModuleType
        The package name (str) or the module object to reload.
        Examples:
            - reload_package("mypackage")
            - import mypackage; reload_package(mypackage)
    skip : Sequence[str]
        A list of submodule prefixes to exclude from reloading.
        Example: skip=['mypackage.vendor', 'mypackage.legacy']
    suppress_errors : bool
        If True, ignore ModuleNotFoundError during reload.

    Raises
    ------
    ImportError
        If the target package is not loaded and cannot be imported.

    Examples
    --------
    >>> import mypackage
    >>> reload_package(mypackage)
    >>> # Or by name:
    >>> reload_package("mypackage", skip=["mypackage.vendor"])

    Notes
    -----
    - If the target is a single module (not a package), performs a simple reload.
    - For packages, uses dependency graph analysis to ensure correct reload order.
    - Detects and reports circular import dependencies.
    """
    # Resolve target to a module object
    if isinstance(target, str):
        if target not in sys.modules:
            # If it's not in sys.modules, try to import it first
            try:
                target_module = importlib.import_module(target)
            except ImportError:
                print(f"Error: Package '{target}' is not loaded. Cannot reload.")
                return
        else:
            target_module = sys.modules[target]
    else:
        target_module = target

    # Validate that it is a package (has __path__)
    if not hasattr(target_module, "__path__"):
        # If it's just a single file module, standard reload is sufficient
        print(
            f"'{target_module.__name__}' is a single module, not a package. "
            f"Performing simple reload."
        )
        importlib.reload(target_module)
        return

    # Extract arguments required by the internal graph reloader
    pkg_path = target_module.__path__
    base_package_name = target_module.__name__

    # Delegate to the graph reloader
    _reload_package_with_graph(
        pkg_path=pkg_path,
        base_package=base_package_name,
        skip_prefixes=tuple(skip),
        suppress_errors=suppress_errors,
    )


class Reloader:
    """
    Hot-reload manager for a package, with priority-based reload ordering.

    This class scans a package for dependencies and reloads modules in
    topological order. Modules matching `priority_prefixes` are reloaded
    first (in the order given), followed by all other modules.

    The reloader itself is designed to be reloadable. When the plugin
    reloads this module, it should create a new Reloader instance to
    pick up the newly loaded class definition.
    """

    def __init__(
        self,
        base_package: str,
        pkg_path: Iterable[str],
        *,
        skip_prefixes: Sequence[str] = (),
        priority_prefixes: Sequence[str] = (),
        suppress_errors: bool = False,
    ):
        self.base_pkg = base_package
        self.pkg_path = pkg_path
        self.skip = tuple(skip_prefixes)
        self.priority = tuple(priority_prefixes)
        self.suppress = suppress_errors
        self._dg = DependencyGraph(base_package + ".", pkg_paths=pkg_path)
        self._scanner = Scanner

    def scan(self):
        """Scan all modules in the package and update dependency graph."""
        self._scanner.scan(
            self.pkg_path,
            self.base_pkg + ".",
            callback=lambda m: (
                self._dg.update_dependencies(m.__file__, m.__name__)
                if getattr(m, "__file__", None)
                else None
            ),
            skip_packages=False,
        )

    def reload_all(self):
        """
        Reload all modules in dependency order, with priority prefixes first.

        This method:
        1. Scans the package for dependencies
        2. Gets topological order (respecting dependencies)
        3. Partitions modules by priority prefixes (stable sort)
        4. Reloads priority modules first, then the rest
        """
        self.scan()
        order = self._dg.topo_order(
            skip=set(
                name
                for name in sys.modules
                if any(name.startswith(p) for p in self.skip)
            )
        )

        # Detect and report cycles
        cycles = self._dg.get_cycles()
        if cycles:
            core_cycles = [", ".join(sorted(c)) for c in cycles]
            print(
                f"[{self.base_pkg}][reloader] WARNING: cyclic import groups detected:\n  "
                + "\n  ".join(core_cycles)
            )

        # Stable-partition by priority_prefixes:
        # Priority modules are reloaded first, in the order specified
        prioritized = []
        for pref in self.priority:
            for mod in order:
                if mod.startswith(pref) and mod not in prioritized:
                    prioritized.append(mod)
        rest = [mod for mod in order if mod not in prioritized]
        final_order = prioritized + rest

        # Reload in final order
        for name in final_order:
            if name not in sys.modules:
                continue
            try:
                print(f"Reloading {name} ...")
                importlib.reload(sys.modules[name])
            except ModuleNotFoundError as e:
                if self.suppress:
                    print(f"[{self.base_pkg}][reload] suppressed {e}")
                else:
                    raise

    @contextlib.contextmanager
    def plugin_context(self, plugin):
        """
        Context manager for reloading a plugin.

        This ensures the plugin is properly unloaded before reload
        and loaded again after reload completes.
        """
        if plugin.is_loaded():
            plugin.unload()
        yield
        self.reload_all()
        plugin.load()


class Plugin(abc.ABC):

    @abc.abstractmethod
    def init(self): ...

    @override
    @abc.abstractmethod
    def run(self, args): ...

    @override
    @abc.abstractmethod
    def term(self): ...


class LateInitPlugin(Plugin):

    def __init__(self, hook_cls: "idaapi.UI_Hooks", skip_code: int, ok_code: int):
        super().__init__()
        self._skip_code = skip_code
        self._ok_code = ok_code
        self._ui_hooks: "idaapi.UI_Hooks" = hook_cls()

    @override
    def init(self):
        self._ui_hooks.ready_to_run = self.ready_to_run
        if not self._ui_hooks.hook():
            print("LateInitPlugin.__init__ hooking failed!", file=sys.stderr)
            return self._skip_code
        return self._ok_code

    def ready_to_run(self):
        self.late_init()
        self._ui_hooks.unhook()

    @abc.abstractmethod
    def late_init(self): ...


class ReloadablePluginBase(LateInitPlugin):
    def __init__(
        self,
        *,
        global_name: str,
        base_package_name: str,
        plugin_class: str,
        hook_cls: "idaapi.UI_Hooks",
        skip_code: int,
        ok_code: int,
    ):
        super().__init__(hook_cls, skip_code, ok_code)
        self.global_name = global_name
        self.base_package_name = base_package_name
        self.plugin_class = plugin_class
        self.plugin = self._import_plugin_cls()

    def _import_plugin_cls(self):
        self.plugin_module, self.plugin_class_name = self.plugin_class.rsplit(".", 1)
        mod = importlib.import_module(self.plugin_module)
        return getattr(mod, self.plugin_class_name)()

    @override
    def late_init(self):
        self.add_plugin_to_console()
        self.register_reload_action()

    @override
    def term(self):
        self.unregister_reload_action()
        if self.plugin is not None and hasattr(self.plugin, "unload"):
            self.plugin.unload()

    def add_plugin_to_console(self):
        # add plugin to the IDA python console scope, for test/dev/cli access
        setattr(sys.modules["__main__"], self.global_name, self)

    @contextlib.contextmanager
    def plugin_setup_reload(self):
        """Hot-reload the plugin core."""
        # Unload existing plugin if loaded
        if self.plugin.is_loaded():
            self.unregister_reload_action()
            self.term()
            self.plugin = self._import_plugin_cls()
            self.plugin.reset()

        yield

        # Re-register action and load plugin
        self.register_reload_action()
        print(f"{self.global_name} reloading...")
        self.add_plugin_to_console()
        self.plugin.load()

    @abc.abstractmethod
    def reload(self): ...

    @abc.abstractmethod
    def register_reload_action(self): ...

    @abc.abstractmethod
    def unregister_reload_action(self): ...
