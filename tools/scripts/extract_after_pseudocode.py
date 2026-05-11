#!/usr/bin/env python3
"""Compatibility deprecation stub.

Migrated to ``d810.diagnostics`` -- see ``docs/debug-tooling-migration.md``.
This file forwards to ``python -m d810.diagnostics dump-after`` with the
same argument shape (positional dump file, ``-n/--line-numbers`` flag).
To use the new command directly:

    ./tools/cff_debug.py after [--dump DUMP] [-n]
    PYTHONPATH=src python -m d810.diagnostics dump-after DUMP [-n]

The pure marker parser now lives in ``src/d810/diagnostics/dump_after.py``
with unit tests under ``tests/unit/diagnostics/test_dump_after.py``.
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
    "[deprecated] tools/scripts/extract_after_pseudocode.py migrated to"
    " d810.diagnostics; forwarding to:"
    " python -m d810.diagnostics dump-after",
    file=sys.stderr,
)
os.execvpe(
    sys.executable,
    [sys.executable, "-m", "d810.diagnostics", "dump-after", *sys.argv[1:]],
    _env,
)
