"""HCLI bootstrap for the wheel-backed D810 runtime."""

from __future__ import annotations

import importlib
import importlib.util
import sys
from pathlib import Path
from types import ModuleType

_IMPLEMENTATION_NAME = "_d810_hcli_entrypoint_impl"
_IMPLEMENTATION_PATH = Path(__file__).resolve().parent / "src" / "d810ng.py"

# Resolve the manifest-pinned distribution before loading the implementation.
# The extracted plugin root is importable, but its ``src`` directory is not.
_RUNTIME_PACKAGE = importlib.import_module("d810")


def _load_implementation() -> ModuleType:
    if not _IMPLEMENTATION_PATH.is_file():
        raise ImportError(
            f"D810 HCLI entrypoint implementation is missing: {_IMPLEMENTATION_PATH}"
        )

    spec = importlib.util.spec_from_file_location(
        _IMPLEMENTATION_NAME, _IMPLEMENTATION_PATH
    )
    if spec is None or spec.loader is None:
        raise ImportError(
            f"cannot create a loader for D810 entrypoint: {_IMPLEMENTATION_PATH}"
        )

    module = importlib.util.module_from_spec(spec)
    sys.modules[_IMPLEMENTATION_NAME] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(_IMPLEMENTATION_NAME, None)
        raise
    return module


_IMPLEMENTATION = _load_implementation()
D810Plugin = _IMPLEMENTATION.D810Plugin
PLUGIN_ENTRY = _IMPLEMENTATION.PLUGIN_ENTRY

__all__ = ["D810Plugin", "PLUGIN_ENTRY"]
