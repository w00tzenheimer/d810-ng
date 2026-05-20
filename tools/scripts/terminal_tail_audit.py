#!/usr/bin/env python3
"""Compatibility deprecation stub.

Migrated to ``d810.diagnostics`` -- see ``docs/debug-tooling-migration.md``.
This file forwards to ``python -m d810.diagnostics terminal-tail-audit``
with the same argument shape. To use the new command directly:

    ./tools/d810cli.py byte-audit
    PYTHONPATH=src python -m d810.diagnostics terminal-tail-audit --db DB [--show-edges] [--localize]

The full implementation now lives in ``src/d810/diagnostics/terminal_tail_audit.py``
with unit tests under ``tests/unit/diagnostics/test_terminal_tail_audit.py``.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_src = str(REPO_ROOT / "src")
_env = os.environ.copy()
_existing = _env.get("PYTHONPATH", "")
_env["PYTHONPATH"] = f"{_src}:{_existing}" if _existing else _src

print(
    "[deprecated] tools/scripts/terminal_tail_audit.py migrated to"
    " d810.diagnostics; forwarding to:"
    " python -m d810.diagnostics terminal-tail-audit",
    file=sys.stderr,
)
os.execvpe(
    sys.executable,
    [sys.executable, "-m", "d810.diagnostics", "terminal-tail-audit", *sys.argv[1:]],
    _env,
)
