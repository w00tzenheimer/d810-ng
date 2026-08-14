#!/usr/bin/env python3
"""Fail only on Ruff findings introduced relative to a selected Git base."""

from __future__ import annotations

import argparse
import subprocess
import sys
from collections.abc import Sequence


_SCOPES = (
    "src/d810/mba/",
    "src/d810/backends/mba/",
    "src/d810/optimizers/microcode/instructions/pattern_matching/",
    "tests/unit/mba/",
    "tests/system/runtime/backends/test_hexrays_mba_island.py",
    "tests/system/runtime/backends/test_ida_ac_matching.py",
)


def _git_changed_paths(base: str) -> tuple[str, ...]:
    """Return committed, staged, and unstaged paths relative to ``base``."""

    commands = (
        ("git", "diff", "--name-only", "--diff-filter=ACMR", f"{base}...HEAD"),
        ("git", "diff", "--name-only", "--diff-filter=ACMR"),
        ("git", "diff", "--name-only", "--diff-filter=ACMR", "--cached"),
    )
    paths: set[str] = set()
    for command in commands:
        completed = subprocess.run(command, check=True, text=True, capture_output=True)
        paths.update(path for path in completed.stdout.splitlines() if path)
    return tuple(sorted(paths))


def changed_python_paths(base: str) -> tuple[str, ...]:
    """Select only changed Python files inside the rollout's declared Ruff scope."""

    return tuple(
        sorted(
            path
            for path in _git_changed_paths(base)
            if path.endswith(".py") and any(path.startswith(scope) for scope in _SCOPES)
        )
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="cfg-recon-mainline")
    args = parser.parse_args(argv)
    try:
        paths = changed_python_paths(args.base)
    except subprocess.CalledProcessError as exc:
        print(f"ruff_diff_gate: cannot resolve base {args.base!r}: {exc}", file=sys.stderr)
        return 2
    if not paths:
        print("ruff_diff_gate: PASS (no changed Python files in rollout scope)")
        return 0
    completed = subprocess.run(("ruff", "check", *paths), check=False)
    return int(completed.returncode)


if __name__ == "__main__":
    raise SystemExit(main())
