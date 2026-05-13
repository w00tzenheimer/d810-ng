#!/usr/bin/env python3
"""Compatibility deprecation stub.

Migrated to ``d810.diagnostics`` -- see ``docs/debug-tooling-migration.md``.
This file forwards to ``python -m d810.diagnostics inspect-state-node``
with the same argument shape (``--db DB --state STATE [--dump DUMP]
[--context N]``). To use the new command directly:

    ./tools/cff_debug.py state STATE [--db DB] [--dump DUMP] [--context N]
    PYTHONPATH=src python -m d810.diagnostics inspect-state-node --db DB --state STATE [--dump DUMP] [--context N]

The SQL + AFTER pseudocode correlation logic now lives in
``src/d810/diagnostics/inspect_state_node.py`` with unit tests under
``tests/unit/diagnostics/test_inspect_state_node.py``.
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
    "[deprecated] tools/scripts/inspect_linearized_state_node.py migrated to"
    " d810.diagnostics; forwarding to:"
    " python -m d810.diagnostics inspect-state-node",
    file=sys.stderr,
)
os.execvpe(
    sys.executable,
    [sys.executable, "-m", "d810.diagnostics", "inspect-state-node", *sys.argv[1:]],
    _env,
)
