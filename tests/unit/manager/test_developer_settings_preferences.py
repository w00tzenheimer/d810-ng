"""Tests for persisted developer runtime setting precedence."""

from __future__ import annotations

import ast
from pathlib import Path


def _state_methods() -> dict[str, str]:
    state_path = (
        Path(__file__).resolve().parents[3] / "src" / "d810" / "manager" / "state.py"
    )
    tree = ast.parse(state_path.read_text(encoding="utf-8"), filename=str(state_path))
    state = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "D810State"
    )
    return {
        node.name: ast.unparse(node)
        for node in state.body
        if isinstance(node, ast.FunctionDef)
    }


def test_state_reset_reapplies_saved_developer_preferences() -> None:
    methods = _state_methods()

    assert "self._apply_runtime_settings_preferences()" in methods["reset"]
    apply_source = methods["_apply_runtime_settings_preferences"]
    assert "'native_perf': 'D810_NATIVE_PERF'" in apply_source
    assert "'nomut_matching': 'D810_NOMUT_MATCHING'" in apply_source
    assert "configure_settings" in apply_source


def test_saved_developer_preferences_are_skipped_when_environment_is_explicit() -> None:
    apply_source = _state_methods()["_apply_runtime_settings_preferences"]

    assert "if environment_name in os.environ" in apply_source
    assert "continue" in apply_source
    assert "'native_perf'" in apply_source
    assert "'nomut_matching'" in apply_source
