#!/usr/bin/env python3
"""Run a thinning slice's gate-class and return a structured pass/fail.

static : lint-imports(13/0) + sg(clean) + pytest unit(no regress) + check-cycles
golden : the per-family e2e expectation tests (compare rule-firing JSON + .c goldens).
         Golden runs in PLAIN mode under the Docker IDA runtime; the e2e tests own the
         byte-comparison, so the gate only checks their exit code.
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field

STATIC_CHECKS = (
    ("lint-imports", ["lint-imports", "--config", ".importlinter"]),
    ("sg", ["sg", "scan", "--config", "sgconfig.yml", "--report-style", "short"]),
    ("unit", ["pyenv", "exec", "python", "-m", "pytest", "tests/unit/", "-q"]),
    ("check-cycles", ["pyenv", "exec", "python", "tools/scripts/check-cycles.py"]),
)

_ENV = {"PYTHONPATH": "src:tests"}


@dataclass
class GateResult:
    passed: bool
    failed_check: str = ""
    detail: str = ""
    captured: dict = field(default_factory=dict)


def run_gate(gate_class: str, *, worktree: str, e2e_selection: list[str] | None = None) -> GateResult:
    if gate_class == "static":
        return _run_static(worktree)
    if gate_class == "golden":
        return _run_golden(worktree, e2e_selection or ["tests/system/e2e/"])
    raise ValueError(f"unknown gate_class {gate_class!r}")


def _run_static(worktree: str) -> GateResult:
    captured: dict = {}
    for name, cmd in STATIC_CHECKS:
        cp = subprocess.run(cmd, capture_output=True, text=True, cwd=worktree, env=_ENV)
        captured[name] = (cp.stdout + cp.stderr)[-4000:]
        # lint-imports prints "N broken"; treat nonzero "<n> broken" (n>0) or bad exit as fail.
        broken = bool(re.search(r"[1-9]\d* broken", cp.stdout)) if name == "lint-imports" else False
        if cp.returncode != 0 or broken:
            return GateResult(False, failed_check=name, detail=captured[name], captured=captured)
    return GateResult(True, captured=captured)


def _run_e2e(worktree: str, selection: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["pyenv", "exec", "python", "-m", "pytest", *selection, "-q"],
        capture_output=True, text=True, cwd=worktree, env={"PYTHONPATH": "src"},
    )


def _run_golden(worktree: str, selection: list[str]) -> GateResult:
    cp = _run_e2e(worktree, selection)
    captured = {"e2e": (cp.stdout + cp.stderr)[-4000:]}
    if cp.returncode != 0:
        return GateResult(False, failed_check="golden-e2e", detail=captured["e2e"], captured=captured)
    return GateResult(True, captured=captured)
