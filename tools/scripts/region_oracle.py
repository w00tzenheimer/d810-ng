#!/usr/bin/env python3
"""Compatibility deprecation stub.

Migrated to ``d810.diagnostics`` -- see ``docs/debug-tooling-migration.md``.
This file forwards to ``python -m d810.diagnostics region-diff`` with the
same argument shape. To use the new command directly:

    ./tools/d810cli.py oracle
    PYTHONPATH=src python -m d810.diagnostics region-diff --db DB [--snap17 N --snap18 M] [--persist] [--microblocks] [--output PATH]

The REF comparison + DCE diagnosis logic now lives in
``src/d810/diagnostics/region_oracle_cli.py`` and is registered as the
``region-diff`` subcommand of ``d810.diagnostics``.
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
    "[deprecated] tools/scripts/region_oracle.py migrated to"
    " d810.diagnostics; forwarding to:"
    " python -m d810.diagnostics region-diff",
    file=sys.stderr,
)
os.execvpe(
    sys.executable,
    [sys.executable, "-m", "d810.diagnostics", "region-diff", *sys.argv[1:]],
    _env,
)
