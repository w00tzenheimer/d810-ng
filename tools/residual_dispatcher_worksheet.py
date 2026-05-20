#!/usr/bin/env python3
"""Compatibility deprecation stub.

Migrated to ``d810.diagnostics`` -- see ``docs/debug-tooling-migration.md``.
This file forwards to ``python -m d810.diagnostics residual-worksheet``
with the same argument shape (``--diag-db``, ``--recon-db``, ``--log``,
``--func-ea``, ``--snapshot-id``, ``--format``, ``--output``,
``--list-snapshots``, etc.). To use the new command directly:

    ./tools/d810cli.py residual-worksheet [--diag-db DB] [--log LOG] [--format FMT] [--output PATH]
    PYTHONPATH=src python -m d810.diagnostics residual-worksheet --diag-db DB ...

The full correlation logic (block + rendered-program + DAG +
modifications + recon planner + LFG DAG log parsing) now lives in
``src/d810/diagnostics/residual_worksheet.py`` with unit tests under
``tests/unit/diagnostics/test_residual_worksheet.py``.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
_src = str(REPO_ROOT / "src")
_env = os.environ.copy()
_existing = _env.get("PYTHONPATH", "")
_env["PYTHONPATH"] = f"{_src}:{_existing}" if _existing else _src

print(
    "[deprecated] tools/residual_dispatcher_worksheet.py migrated to"
    " d810.diagnostics; forwarding to:"
    " python -m d810.diagnostics residual-worksheet",
    file=sys.stderr,
)
os.execvpe(
    sys.executable,
    [sys.executable, "-m", "d810.diagnostics", "residual-worksheet", *sys.argv[1:]],
    _env,
)
