from __future__ import annotations

import importlib
import py_compile
import sys
from pathlib import Path

import d810._vendor.ida_reloader as ida_reloader
import pytest
from d810._vendor.ida_reloader import DependencyGraph, reload_package


def _write_module(path: Path, source: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")


def _dependency_graph(package_root: Path, package_name: str) -> DependencyGraph:
    graph = DependencyGraph(f"{package_name}.", pkg_paths=[str(package_root)])
    source_root = package_root.parent
    for path in sorted(package_root.rglob("*.py")):
        relative = path.relative_to(source_root).with_suffix("")
        module_name = ".".join(relative.parts)
        if module_name.endswith(".__init__"):
            module_name = module_name[: -len(".__init__")]
        graph.update_dependencies(path, module_name)
    return graph


def test_dependency_graph_resolves_imported_child_module(
    tmp_path: Path,
) -> None:
    """A child-module import must not become a dependency on its re-exporter."""
    package_name = "d810_dependency_child_probe"
    package_root = tmp_path / package_name
    _write_module(package_root / "__init__.py", "")
    _write_module(package_root / "core" / "__init__.py", "")
    _write_module(package_root / "core" / "typing.py", "VALUE = 1\n")
    _write_module(
        package_root / "consumer.py",
        f"from {package_name}.core import typing\n",
    )

    graph = _dependency_graph(package_root, package_name)

    assert graph.get_module_dependencies(f"{package_name}.consumer") == {
        f"{package_name}.core.typing"
    }


def test_dependency_graph_ignores_function_local_imports(tmp_path: Path) -> None:
    """A deferred import must not constrain module reload order."""
    package_name = "d810_dependency_lazy_probe"
    package_root = tmp_path / package_name
    _write_module(package_root / "__init__.py", "")
    _write_module(package_root / "dependency.py", "VALUE = 1\n")
    _write_module(
        package_root / "consumer.py",
        f"def load():\n    from {package_name}.dependency import VALUE\n    return VALUE\n",
    )

    graph = _dependency_graph(package_root, package_name)

    assert graph.get_module_dependencies(f"{package_name}.consumer") == set()


def test_dependency_graph_does_not_invent_parent_package_cycles(
    tmp_path: Path,
) -> None:
    """Package containment alone must not turn an acyclic import graph cyclic."""
    package_name = "d810_dependency_parent_probe"
    package_root = tmp_path / package_name
    _write_module(package_root / "__init__.py", "")
    _write_module(
        package_root / "feature" / "__init__.py",
        "from .public import VALUE\n",
    )
    _write_module(
        package_root / "feature" / "public.py",
        "from .helper import VALUE\n",
    )
    _write_module(package_root / "feature" / "helper.py", "VALUE = 1\n")

    graph = _dependency_graph(package_root, package_name)

    assert graph.get_cycles() == []
    order = graph.topo_order()
    assert order.index(f"{package_name}.feature.helper") < order.index(
        f"{package_name}.feature.public"
    )
    assert order.index(f"{package_name}.feature.public") < order.index(
        f"{package_name}.feature"
    )


def test_dependency_graph_still_detects_eager_import_cycles(tmp_path: Path) -> None:
    """Mutually eager module imports must remain a reported cycle."""
    package_name = "d810_dependency_cycle_probe"
    package_root = tmp_path / package_name
    _write_module(package_root / "__init__.py", "")
    _write_module(package_root / "left.py", "from .right import VALUE\n")
    _write_module(package_root / "right.py", "from .left import VALUE\n")

    graph = _dependency_graph(package_root, package_name)

    assert graph.get_cycles() == [{f"{package_name}.left", f"{package_name}.right"}]


def test_reload_package_replaces_submodules_loaded_from_a_previous_root(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """A checkout switch must not leave child packages on the old tree."""
    package_name = "d810_reload_probe"
    old_root = tmp_path / "old"
    new_root = tmp_path / "new"

    _write_module(old_root / package_name / "__init__.py", "")
    _write_module(
        old_root / package_name / "core" / "__init__.py",
        "from .persistence import Existing\n",
    )
    _write_module(
        old_root / package_name / "core" / "persistence.py",
        "Existing = 1\n",
    )

    _write_module(new_root / package_name / "__init__.py", "")
    _write_module(
        new_root / package_name / "core" / "__init__.py",
        "from .persistence import Existing, FunctionStorageLocator\n",
    )
    _write_module(
        new_root / package_name / "core" / "persistence.py",
        "Existing = 2\nFunctionStorageLocator = object()\n",
    )
    _write_module(
        new_root / package_name / "core" / "function_storage_config.py",
        "VALUE = 42\n",
    )
    _write_module(
        new_root / package_name / "consumer.py",
        f"from {package_name}.core.function_storage_config import VALUE\n"
        "RESULT = VALUE\n",
    )

    monkeypatch.syspath_prepend(str(old_root))
    package = importlib.import_module(package_name)
    old_core = importlib.import_module(f"{package_name}.core")
    old_persistence = importlib.import_module(f"{package_name}.core.persistence")
    assert old_core.Existing == 1
    assert old_persistence.Existing == 1

    monkeypatch.syspath_prepend(str(new_root))
    current_package_path = str(new_root / package_name)
    package.__path__[:] = [current_package_path]
    package.__spec__.submodule_search_locations[:] = [current_package_path]

    try:
        reload_package(package)

        consumer = importlib.import_module(f"{package_name}.consumer")
        core = importlib.import_module(f"{package_name}.core")
        persistence = importlib.import_module(f"{package_name}.core.persistence")
        storage_config = importlib.import_module(
            f"{package_name}.core.function_storage_config"
        )

        assert consumer.RESULT == 42
        assert core.Existing == 2
        assert persistence.Existing == 2
        assert persistence.FunctionStorageLocator is not None
        assert storage_config.VALUE == 42
        for module in (core, persistence, storage_config, consumer):
            assert Path(module.__file__).is_relative_to(new_root)
    finally:
        for module_name in tuple(sys.modules):
            if module_name == package_name or module_name.startswith(
                f"{package_name}."
            ):
                sys.modules.pop(module_name, None)


def test_reload_package_reloads_relative_dependency_before_its_reexporter(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """A changed leaf module must reload before the package re-exporting it."""
    package_name = "d810_reload_order_probe"
    source_root = tmp_path / "source"
    package_root = source_root / package_name

    _write_module(package_root / "__init__.py", "")
    _write_module(
        package_root / "core" / "__init__.py",
        "from .persistence import Existing\n",
    )
    _write_module(
        package_root / "core" / "persistence.py",
        "Existing = 1\n",
    )

    monkeypatch.syspath_prepend(str(source_root))
    package = importlib.import_module(package_name)
    core = importlib.import_module(f"{package_name}.core")
    persistence = importlib.import_module(f"{package_name}.core.persistence")
    assert core.Existing == 1
    assert persistence.Existing == 1

    _write_module(
        package_root / "core" / "__init__.py",
        "from .persistence import Existing, FunctionStorageLocator\n",
    )
    _write_module(
        package_root / "core" / "persistence.py",
        "Existing = 2\nFunctionStorageLocator = object()\n",
    )
    importlib.invalidate_caches()

    try:
        reload_package(package)

        core = importlib.import_module(f"{package_name}.core")
        persistence = importlib.import_module(f"{package_name}.core.persistence")
        assert core.Existing == 2
        assert persistence.Existing == 2
        assert persistence.FunctionStorageLocator is not None
    finally:
        for module_name in tuple(sys.modules):
            if module_name == package_name or module_name.startswith(
                f"{package_name}."
            ):
                sys.modules.pop(module_name, None)


def test_reload_package_defers_new_consumers_until_dependencies_are_reloaded(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    """A newly discovered consumer must not execute against a stale dependency."""
    package_name = "d810_reload_new_consumer_probe"
    source_root = tmp_path / "source"
    package_root = source_root / package_name

    _write_module(package_root / "__init__.py", "")
    _write_module(package_root / "dependency.py", "EXISTING = 1\n")

    monkeypatch.syspath_prepend(str(source_root))
    package = importlib.import_module(package_name)
    dependency = importlib.import_module(f"{package_name}.dependency")
    assert dependency.EXISTING == 1

    _write_module(
        package_root / "dependency.py",
        "EXISTING = 2\nPassContractEvidencePublished = 42\n",
    )
    _write_module(
        package_root / "consumer.py",
        f"from {package_name}.dependency import PassContractEvidencePublished\n"
        "RESULT = PassContractEvidencePublished\n",
    )
    importlib.invalidate_caches()

    try:
        reload_package(package)

        consumer = importlib.import_module(f"{package_name}.consumer")
        dependency = importlib.import_module(f"{package_name}.dependency")
        assert consumer.RESULT == 42
        assert dependency.EXISTING == 2
        assert "Error while loading extension" not in capsys.readouterr().err
    finally:
        for module_name in tuple(sys.modules):
            if module_name == package_name or module_name.startswith(
                f"{package_name}."
            ):
                sys.modules.pop(module_name, None)


def test_reload_package_rejects_unchecked_bytecode_stale_against_source(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    """Hot reload must not execute unchecked bytecode for older source."""
    package_name = "d810_reload_stale_pyc_probe"
    source_root = tmp_path / "source"
    package_root = source_root / package_name
    dependency_path = package_root / "dependency.py"

    _write_module(package_root / "__init__.py", "")
    _write_module(dependency_path, "EXISTING = 1\n")
    py_compile.compile(
        str(dependency_path),
        doraise=True,
        invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
    )
    _write_module(
        dependency_path,
        "EXISTING = 2\nPassContractEvidencePublished = 42\n",
    )
    _write_module(
        package_root / "consumer.py",
        f"from {package_name}.dependency import PassContractEvidencePublished\n"
        "RESULT = PassContractEvidencePublished\n",
    )

    monkeypatch.syspath_prepend(str(source_root))
    package = importlib.import_module(package_name)
    dependency = importlib.import_module(f"{package_name}.dependency")
    assert dependency.EXISTING == 1
    assert not hasattr(dependency, "PassContractEvidencePublished")

    try:
        reload_package(package)

        consumer = importlib.import_module(f"{package_name}.consumer")
        dependency = importlib.import_module(f"{package_name}.dependency")
        assert consumer.RESULT == 42
        assert dependency.EXISTING == 2
        assert "Error while loading extension" not in capsys.readouterr().err
    finally:
        for module_name in tuple(sys.modules):
            if module_name == package_name or module_name.startswith(
                f"{package_name}."
            ):
                sys.modules.pop(module_name, None)


def test_evict_module_prefixes_preserves_shared_namespace_siblings(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Cold eviction must not remove a shared parent or sibling package."""
    source_root = tmp_path / "source"
    namespace = source_root / "acme_shared_namespace"
    extension = namespace / "d810"
    sibling = namespace / "other_plugin"
    _write_module(namespace / "__init__.py", "")
    _write_module(extension / "__init__.py", "TOKEN = object()\n")
    _write_module(sibling / "__init__.py", "TOKEN = object()\n")
    monkeypatch.syspath_prepend(str(source_root))

    parent = importlib.import_module("acme_shared_namespace")
    old_extension = importlib.import_module("acme_shared_namespace.d810")
    sibling_module = importlib.import_module(
        "acme_shared_namespace.other_plugin"
    )

    try:
        evicted = ida_reloader.evict_module_prefixes(
            ["acme_shared_namespace.d810"]
        )

        assert evicted == ("acme_shared_namespace.d810",)
        assert "acme_shared_namespace" in sys.modules
        assert "acme_shared_namespace.other_plugin" in sys.modules
        assert not hasattr(parent, "d810")

        imported: dict[str, object] = {}
        exec("from acme_shared_namespace import d810", imported)
        assert imported["d810"] is not old_extension
        assert parent.other_plugin is sibling_module
    finally:
        for module_name in tuple(sys.modules):
            if module_name == "acme_shared_namespace" or module_name.startswith(
                "acme_shared_namespace."
            ):
                sys.modules.pop(module_name, None)


def test_evict_module_prefixes_removes_the_complete_owned_tree(
    tmp_path: Path,
    monkeypatch,
) -> None:
    source_root = tmp_path / "source"
    package_name = "d810_extension_tree_probe"
    package = source_root / package_name
    _write_module(package / "__init__.py", "")
    _write_module(package / "runtime.py", "TOKEN = object()\n")
    _write_module(package / "rules" / "__init__.py", "")
    _write_module(
        package / "rules" / "solver.py",
        f"from {package_name}.runtime import TOKEN\n",
    )
    monkeypatch.syspath_prepend(str(source_root))
    for module_name in (
        package_name,
        f"{package_name}.runtime",
        f"{package_name}.rules",
        f"{package_name}.rules.solver",
    ):
        importlib.import_module(module_name)

    evicted = ida_reloader.evict_module_prefixes([package_name])

    assert evicted == (
        f"{package_name}.rules.solver",
        f"{package_name}.runtime",
        f"{package_name}.rules",
        package_name,
    )
    assert not any(
        module_name == package_name
        or module_name.startswith(package_name + ".")
        for module_name in sys.modules
    )


class _ReloadLifecycleProbe(ida_reloader.ReloadablePluginBase):
    def __init__(self, events: list[str]) -> None:
        self.events = events
        super().__init__(
            global_name="D810_TEST",
            base_package_name="probe",
            plugin_class="probe.State",
            hook_cls=lambda: object(),
            skip_code=0,
            ok_code=1,
        )

    def _import_plugin_cls(self):
        events = self.events

        class State:
            def is_loaded(self) -> bool:
                return True

            def unload(self) -> None:
                events.append("unload")

            def reset(self) -> None:
                events.append("reset")

            def load(self) -> None:
                events.append("load")

        events.append("construct")
        return State()

    def register_reload_action(self) -> None:
        self.events.append("register")

    def unregister_reload_action(self) -> None:
        self.events.append("unregister")

    def add_plugin_to_console(self) -> None:
        self.events.append("publish")

    def reload(self) -> None:
        raise NotImplementedError

    def run(self, args) -> None:
        raise NotImplementedError


def test_reloadable_plugin_constructs_replacement_after_reload_body() -> None:
    events: list[str] = []
    plugin = _ReloadLifecycleProbe(events)
    events.clear()

    with plugin.plugin_setup_reload():
        events.append("reload-core")

    assert events == [
        "unregister",
        "unload",
        "reload-core",
        "construct",
        "reset",
        "register",
        "publish",
        "load",
    ]


def test_reloadable_plugin_does_not_construct_after_reload_failure() -> None:
    events: list[str] = []
    plugin = _ReloadLifecycleProbe(events)
    original_plugin = plugin.plugin
    events.clear()

    with pytest.raises(RuntimeError, match="reload failed"):
        with plugin.plugin_setup_reload():
            events.append("reload-core")
            raise RuntimeError("reload failed")

    assert plugin.plugin is original_plugin
    assert events == [
        "unregister",
        "unload",
        "reload-core",
    ]
