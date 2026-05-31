from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[3] / "tools" / "scripts" / "thinning_gate.py"
_spec = importlib.util.spec_from_file_location("thinning_gate", SCRIPT)
tg = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = tg  # @dataclass needs the module registered (py3.13)
_spec.loader.exec_module(tg)


def test_static_gate_runs_all_four_checks(monkeypatch):
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="13 kept, 0 broken", stderr="")

    monkeypatch.setattr(tg.subprocess, "run", fake_run)
    result = tg.run_gate("static", worktree="wt")
    assert result.passed is True
    assert len(calls) == 4  # lint-imports, sg, unit, check-cycles


def test_static_gate_fails_when_lint_breaks(monkeypatch):
    def fake_run(cmd, **kw):
        is_lint = "lint-imports" in cmd
        return subprocess.CompletedProcess(
            cmd, 0, stdout="1 broken" if is_lint else "ok", stderr=""
        )

    monkeypatch.setattr(tg.subprocess, "run", fake_run)
    result = tg.run_gate("static", worktree="wt")
    assert result.passed is False
    assert result.failed_check == "lint-imports"


def test_static_gate_fails_on_nonzero_exit(monkeypatch):
    def fake_run(cmd, **kw):
        is_sg = "sg" in cmd
        return subprocess.CompletedProcess(cmd, 1 if is_sg else 0, stdout="x", stderr="")

    monkeypatch.setattr(tg.subprocess, "run", fake_run)
    result = tg.run_gate("static", worktree="wt")
    assert result.passed is False
    assert result.failed_check == "sg"


def test_golden_gate_passes_on_e2e_success(monkeypatch):
    def fake_run(cmd, **kw):
        return subprocess.CompletedProcess(cmd, 0, stdout="1 passed", stderr="")

    monkeypatch.setattr(tg.subprocess, "run", fake_run)
    result = tg.run_gate("golden", worktree="wt", e2e_selection=["tests/system/e2e/x.py"])
    assert result.passed is True


def test_golden_gate_fails_on_e2e_failure(monkeypatch):
    def fake_run(cmd, **kw):
        return subprocess.CompletedProcess(cmd, 1, stdout="1 failed", stderr="")

    monkeypatch.setattr(tg.subprocess, "run", fake_run)
    result = tg.run_gate("golden", worktree="wt")
    assert result.passed is False
    assert result.failed_check == "golden-e2e"


def test_unknown_gate_class_raises():
    import pytest

    with pytest.raises(ValueError):
        tg.run_gate("bogus", worktree="wt")
