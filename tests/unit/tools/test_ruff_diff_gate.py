"""Contracts for the MBA rollout's baseline-relative Ruff gate."""

from __future__ import annotations

import importlib.util
from pathlib import Path


_ROOT = Path(__file__).resolve().parents[3]
_TOOL = _ROOT / "tools" / "scripts" / "ruff_diff_gate.py"


def _tool():
    spec = importlib.util.spec_from_file_location("ruff_diff_gate", _TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_gate_filters_to_changed_python_paths_inside_declared_scopes(monkeypatch) -> None:
    tool = _tool()
    monkeypatch.setattr(
        tool,
        "_git_changed_paths",
        lambda _base: (
            "src/d810/mba/new_report.py",
            "src/d810/backends/mba/changed.py",
            "docs/nope.md",
            "src/d810/other.py",
            "tests/unit/mba/test_new.py",
        ),
    )

    assert tool.changed_python_paths("cfg-recon-mainline") == (
        "src/d810/backends/mba/changed.py",
        "src/d810/mba/new_report.py",
        "tests/unit/mba/test_new.py",
    )


def test_gate_does_not_invoke_ruff_when_the_baseline_relative_diff_is_empty(
    monkeypatch,
) -> None:
    tool = _tool()
    monkeypatch.setattr(tool, "changed_python_paths", lambda _base: ())
    called = []
    monkeypatch.setattr(tool.subprocess, "run", lambda *args, **kwargs: called.append(args))

    assert tool.main(["--base", "cfg-recon-mainline"]) == 0
    assert called == []
