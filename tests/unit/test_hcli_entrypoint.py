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


def _install_fake_runtime(
    monkeypatch: pytest.MonkeyPatch,
    *,
    marker: str = "wheel",
    native_ok: bool = True,
    native_detail: str = "native extensions loaded",
) -> types.ModuleType:
    """Install a complete wheel-shaped runtime fixture for the bootstrap."""
    wheel_package = types.ModuleType("d810")
    wheel_package.__path__ = []
    wheel_package.RUNTIME_MARKER = marker

    speedups_package = types.ModuleType("d810.speedups")
    speedups_package.__path__ = []
    installer = types.ModuleType("d810.speedups.install")
    installer.inspect_native_extensions = lambda: types.SimpleNamespace(
        ok=native_ok,
        detail=native_detail,
    )

    for name, module in (
        ("d810", wheel_package),
        ("d810.speedups", speedups_package),
        ("d810.speedups.install", installer),
    ):
        monkeypatch.setitem(sys.modules, name, module)
    return wheel_package


@pytest.fixture(autouse=True)
def _clean_bootstrap_modules():
    yield
    for name in (
        "_d810_hcli_entrypoint_impl",
        "_test_d810_hcli_bootstrap",
        "_test_d810_hcli_missing",
        "_test_d810_hcli_missing_export",
        "_test_d810_hcli_native_failure",
    ):
        sys.modules.pop(name, None)


def test_bootstrap_uses_preinstalled_distribution_not_extracted_src(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_sys_path = list(sys.path)
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

    wheel_package = _install_fake_runtime(monkeypatch)

    loaded = _load(plugin / "d810ng.py", "_test_d810_hcli_bootstrap")

    assert loaded.D810Plugin.RUNTIME_MARKER == "wheel"
    assert isinstance(loaded.PLUGIN_ENTRY(), loaded.D810Plugin)
    assert sys.modules["d810"] is wheel_package
    assert sys.path == original_sys_path


def test_bootstrap_rejects_failed_native_probe_before_loading_and_cleans_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plugin = tmp_path / "plugin"
    (plugin / "src").mkdir(parents=True)
    shutil.copy2(BOOTSTRAP, plugin / "d810ng.py")
    loaded_marker = tmp_path / "implementation-loaded"
    (plugin / "src" / "d810ng.py").write_text(
        f"from pathlib import Path\n"
        f"Path({str(loaded_marker)!r}).write_text('loaded')\n"
        "class D810Plugin:\n"
        "    pass\n"
        "def PLUGIN_ENTRY():\n"
        "    return D810Plugin()\n",
        encoding="utf-8",
    )
    _install_fake_runtime(
        monkeypatch,
        native_ok=False,
        native_detail="d810.speedups.c_simd: wrong ABI",
    )

    with pytest.raises(ImportError, match=r"d810\.speedups\.c_simd: wrong ABI"):
        _load(plugin / "d810ng.py", "_test_d810_hcli_native_failure")

    assert not loaded_marker.exists()
    assert "_d810_hcli_entrypoint_impl" not in sys.modules


def test_bootstrap_reports_missing_implementation_and_cleans_private_module(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plugin = tmp_path / "plugin"
    plugin.mkdir()
    shutil.copy2(BOOTSTRAP, plugin / "d810ng.py")

    _install_fake_runtime(monkeypatch)

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

    _install_fake_runtime(monkeypatch)

    with pytest.raises(BaseException) as caught:
        _load(plugin / "d810ng.py", "_test_d810_hcli_missing_export")

    assert isinstance(caught.value, ImportError), repr(caught.value)
    assert "PLUGIN_ENTRY" in str(caught.value)
    assert str(plugin / "src" / "d810ng.py") in str(caught.value)
    assert "_d810_hcli_entrypoint_impl" not in sys.modules
