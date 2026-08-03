from __future__ import annotations

import json
import ast
from pathlib import Path

import pytest

from d810.core.config import D810Configuration
from d810.core.diagnostics_capture_preferences import (
    diagnostics_capture_enabled,
    enable_diagnostics_capture,
)


def _options(tmp_path, options: dict[str, object]) -> D810Configuration:
    path = tmp_path / "options.json"
    path.write_text(json.dumps(options), encoding="utf-8")
    return D810Configuration(path)


def test_enable_diagnostics_capture_updates_runtime_and_options_file(tmp_path) -> None:
    config = _options(tmp_path, {"diag_snapshots": False})

    assert enable_diagnostics_capture(config) is True
    assert json.loads((tmp_path / "options.json").read_text(encoding="utf-8")) == {
        "diag_snapshots": True
    }


def test_persisted_capture_preference_overrides_runtime_default(tmp_path) -> None:
    config = _options(tmp_path, {"diag_snapshots": True})

    assert diagnostics_capture_enabled(config, runtime_default=False) is True


def test_state_reset_reapplies_the_saved_capture_preference() -> None:
    path = Path(__file__).resolve().parents[3] / "src" / "d810" / "manager" / "state.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    state = next(
        node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "D810State"
    )
    methods = {
        node.name: ast.unparse(node)
        for node in state.body
        if isinstance(node, ast.FunctionDef)
    }

    assert "self._apply_diagnostics_capture_preference()" in methods["reset"]
    assert "configure_settings" in methods["_apply_diagnostics_capture_preference"]
    assert "enable_diagnostics_capture(self.d810_config)" in methods[
        "enable_diagnostics_capture"
    ]
    assert "_update_diagnostics_capture_indicator" in methods[
        "enable_diagnostics_capture"
    ]
