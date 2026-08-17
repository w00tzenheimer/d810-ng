from __future__ import annotations

import json
import ast
from pathlib import Path

from d810.core.config import D810Configuration
from d810.core.diagnostics_capture_preferences import (
    diagnostics_capture_enabled,
    enable_diagnostics_capture,
    set_diagnostics_capture_enabled,
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


def test_set_diagnostics_capture_enabled_persists_both_states(tmp_path) -> None:
    config = _options(tmp_path, {"diag_snapshots": True})

    assert set_diagnostics_capture_enabled(config, False) is False
    assert json.loads((tmp_path / "options.json").read_text(encoding="utf-8")) == {
        "diag_snapshots": False
    }
    assert set_diagnostics_capture_enabled(config, True) is True


def test_persisted_capture_preference_overrides_runtime_default(tmp_path) -> None:
    config = _options(tmp_path, {"diag_snapshots": True})

    assert diagnostics_capture_enabled(config, runtime_default=False) is True


def test_state_reset_reapplies_the_saved_capture_preference() -> None:
    path = Path(__file__).resolve().parents[3] / "src" / "d810" / "manager" / "state.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    state = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "D810State"
    )
    methods = {
        node.name: ast.unparse(node)
        for node in state.body
        if isinstance(node, ast.FunctionDef)
    }

    assert "self._apply_diagnostics_capture_preference()" in methods["reset"]
    assert "configure_settings" in methods["_apply_diagnostics_capture_preference"]
    assert "set_diagnostics_capture_enabled" in methods
    assert "persist_diagnostics_capture_enabled(self.d810_config, enabled)" in methods[
        "set_diagnostics_capture_enabled"
    ]
    assert "self._notify_diagnostics_capture_changed" in methods[
        "set_diagnostics_capture_enabled"
    ]


def test_state_reset_reapplies_persisted_callback_detail_unless_env_overrides() -> None:
    path = Path(__file__).resolve().parents[3] / "src" / "d810" / "manager" / "state.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    state = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "D810State"
    )
    methods = {
        node.name: ast.unparse(node)
        for node in state.body
        if isinstance(node, ast.FunctionDef)
    }

    assert "self._apply_execution_callback_detail_preference()" in methods["reset"]
    apply_source = methods["_apply_execution_callback_detail_preference"]
    assert "D810_EXECUTION_CALLBACK_DETAIL" in apply_source
    assert "execution_callback_detail" in apply_source
    assert "configure_settings" in apply_source
