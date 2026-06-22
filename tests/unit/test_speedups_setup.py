from __future__ import annotations

import runpy
from pathlib import Path

import setuptools


ROOT = Path(__file__).resolve().parents[2]


def _load_setup_helpers(monkeypatch):
    monkeypatch.delenv("D810_BUILD_SPEEDUPS", raising=False)
    monkeypatch.setattr(setuptools, "setup", lambda **kwargs: None)
    return runpy.run_path(str(ROOT / "setup.py"))


def test_linux_sdk_lib_subdir_uses_current_ida_sdk_layout(monkeypatch):
    helpers = _load_setup_helpers(monkeypatch)
    lib_subdir = helpers["_linux_sdk_lib_subdir"]

    assert lib_subdir("amd64", True) == "x64_linux_64"
    assert lib_subdir("arm64", True) == "arm64_linux_64"
    assert lib_subdir("aarch64", True) == "arm64_linux_64"
    assert lib_subdir("intel32", False) == "x86_linux_32"


def test_linux_sdk_lib_dir_falls_back_to_legacy_layout(monkeypatch, tmp_path):
    helpers = _load_setup_helpers(monkeypatch)
    select_lib_dir = helpers["_select_linux_sdk_lib_dir"]
    sdk_lib_dir = helpers["_sdk_lib_dir"]
    linux_lib_subdir = helpers["_linux_sdk_lib_subdir"]

    current_sdk = tmp_path / "current"
    current_lib = sdk_lib_dir(current_sdk, linux_lib_subdir())
    current_lib.mkdir(parents=True)
    assert select_lib_dir(current_sdk) == current_lib

    legacy_sdk = tmp_path / "legacy"
    legacy_lib = legacy_sdk / "src" / "lib" / "x64_linux_gcc_64"
    legacy_lib.mkdir(parents=True)
    assert select_lib_dir(legacy_sdk) == legacy_lib


def test_ida_runtime_lib_dir_uses_container_runtime(monkeypatch, tmp_path):
    helpers = _load_setup_helpers(monkeypatch)
    runtime_lib_dir = helpers["_ida_runtime_lib_dir"]

    monkeypatch.setenv("IDA_INSTALL_DIR", str(tmp_path))
    assert runtime_lib_dir() is None

    (tmp_path / "libida.so").touch()
    assert runtime_lib_dir() == tmp_path
