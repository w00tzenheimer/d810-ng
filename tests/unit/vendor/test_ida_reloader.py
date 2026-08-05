from __future__ import annotations

import importlib
import sys
from pathlib import Path

from d810._vendor.ida_reloader import reload_package


def _write_module(path: Path, source: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")


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
