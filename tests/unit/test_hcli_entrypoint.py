"""Behavioral tests for the wheel-backed HCLI plugin entrypoint."""

from __future__ import annotations

import importlib.util
import shutil
import sys
import types
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
BOOTSTRAP = ROOT / "d810ng.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


@pytest.fixture(autouse=True)
def _clean_bootstrap_modules():
    yield
    for name in (
        "_d810_hcli_entrypoint_impl",
        "_test_d810_hcli_bootstrap",
        "_test_d810_hcli_missing",
        "_test_d810_hcli_missing_export",
    ):
        sys.modules.pop(name, None)


def test_bootstrap_uses_preinstalled_distribution_not_extracted_src(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plugin = tmp_path / "plugin"
    (plugin / "src" / "d810").mkdir(parents=True)
    shutil.copy2(BOOTSTRAP, plugin / "d810ng.py")
    (plugin / "src" / "d810" / "__init__.py").write_text(
        'RUNTIME_MARKER = "source-shadow"\n', encoding="utf-8"
    )
    (plugin / "src" / "d810ng.py").write_text(
        "import d810\n"
        "class D810Plugin:\n"
        "    RUNTIME_MARKER = d810.RUNTIME_MARKER\n"
        "def PLUGIN_ENTRY():\n"
        "    return D810Plugin()\n",
        encoding="utf-8",
    )

    wheel_package = types.ModuleType("d810")
    wheel_package.RUNTIME_MARKER = "wheel"
    monkeypatch.setitem(sys.modules, "d810", wheel_package)

    loaded = _load(plugin / "d810ng.py", "_test_d810_hcli_bootstrap")

    assert loaded.D810Plugin.RUNTIME_MARKER == "wheel"
    assert isinstance(loaded.PLUGIN_ENTRY(), loaded.D810Plugin)
    assert sys.modules["d810"] is wheel_package


def test_bootstrap_reports_missing_implementation_and_cleans_private_module(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plugin = tmp_path / "plugin"
    plugin.mkdir()
    shutil.copy2(BOOTSTRAP, plugin / "d810ng.py")

    wheel_package = types.ModuleType("d810")
    monkeypatch.setitem(sys.modules, "d810", wheel_package)

    with pytest.raises(ImportError, match=r"src/d810ng\.py"):
        _load(plugin / "d810ng.py", "_test_d810_hcli_missing")

    assert "_d810_hcli_entrypoint_impl" not in sys.modules


def test_bootstrap_reports_missing_export_and_cleans_private_module(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plugin = tmp_path / "plugin"
    (plugin / "src").mkdir(parents=True)
    shutil.copy2(BOOTSTRAP, plugin / "d810ng.py")
    (plugin / "src" / "d810ng.py").write_text(
        "class D810Plugin:\n"
        "    pass\n",
        encoding="utf-8",
    )

    wheel_package = types.ModuleType("d810")
    monkeypatch.setitem(sys.modules, "d810", wheel_package)

    with pytest.raises(BaseException) as caught:
        _load(plugin / "d810ng.py", "_test_d810_hcli_missing_export")

    assert isinstance(caught.value, ImportError), repr(caught.value)
    assert "PLUGIN_ENTRY" in str(caught.value)
    assert str(plugin / "src" / "d810ng.py") in str(caught.value)
    assert "_d810_hcli_entrypoint_impl" not in sys.modules
