#!/usr/bin/env python3
"""Compatibility deprecation stub for indirect dispatcher transfer maps."""
from __future__ import annotations

import os
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
_env = os.environ.copy()
_existing = _env.get("PYTHONPATH", "")
_env["PYTHONPATH"] = f"{SRC}:{_existing}" if _existing else str(SRC)

print(
    "[deprecated] tools/scripts/tigress_indirect_state_transfer_map.py migrated"
    " to d810.diagnostics; forwarding to:"
    " python -m d810.diagnostics indirect-transfer-map",
    file=sys.stderr,
)
os.execvpe(
    sys.executable,
    [sys.executable, "-m", "d810.diagnostics", "indirect-transfer-map", *sys.argv[1:]],
    _env,
)
