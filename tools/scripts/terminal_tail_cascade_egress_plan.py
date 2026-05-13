#!/usr/bin/env python3
"""Compatibility deprecation stub.

Migrated to ``d810.diagnostics`` -- see ``docs/debug-tooling-migration.md``.
This file forwards to ``python -m d810.diagnostics cascade-egress-plan``
with the same argument shape. To use the new command directly:

    ./tools/cff_debug.py egress-plan
    PYTHONPATH=src python -m d810.diagnostics cascade-egress-plan \\
        --db DB [--fact-snapshot-id N] [--target-snapshot-id N]

The full implementation now lives in
``src/d810/diagnostics/cascade_egress_plan.py`` with unit tests under
``tests/unit/diagnostics/test_cascade_egress_plan.py``. The cfg-layer
planner in ``d810.cfg.terminal_tail_cascade_egress_planner`` is unchanged.
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
    "[deprecated] tools/scripts/terminal_tail_cascade_egress_plan.py"
    " migrated to d810.diagnostics; forwarding to:"
    " python -m d810.diagnostics cascade-egress-plan",
    file=sys.stderr,
)
os.execvpe(
    sys.executable,
    [sys.executable, "-m", "d810.diagnostics", "cascade-egress-plan", *sys.argv[1:]],
    _env,
)
