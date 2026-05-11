#!/usr/bin/env python3
"""Compatibility deprecation stub.

Migrated to ``d810.diagnostics`` -- see ``docs/debug-tooling-migration.md``.
This file forwards to ``python -m d810.diagnostics redirect-reconcile``
with the same argument shape. To use the new command directly:

    ./tools/cff_debug.py reconcile
    PYTHONPATH=src python -m d810.diagnostics redirect-reconcile \\
        --db DB --log LOG --snap-id N \\
        [--state-var-stkoff HEX] [--min-dispatcher-preds N] [--show-edges]

The full implementation now lives in
``src/d810/diagnostics/redirect_reconcile.py`` with unit tests under
``tests/unit/diagnostics/test_redirect_reconcile.py``. The cfg-layer
classification logic in ``d810.cfg.redirect_reconciliation`` is unchanged.
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
    "[deprecated] tools/scripts/reconcile_dispatcher_redirects.py migrated"
    " to d810.diagnostics; forwarding to: python -m d810.diagnostics"
    " redirect-reconcile",
    file=sys.stderr,
)
os.execvpe(
    sys.executable,
    [sys.executable, "-m", "d810.diagnostics", "redirect-reconcile", *sys.argv[1:]],
    _env,
)
