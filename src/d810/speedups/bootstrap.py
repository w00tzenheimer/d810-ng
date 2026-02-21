"""Path bootstrap for isolated optional speedups dependencies."""

from __future__ import annotations

import os
import sys
from pathlib import Path

DEFAULT_SPEEDUPS_DIR = Path.home() / ".d810-speedups"


def get_speedups_dir() -> Path:
    """Return the configured directory where isolated speedups dependencies live."""

    override = os.environ.get("D810_SPEEDUPS_DIR")
    if override:
        return Path(override).expanduser().resolve()
    return DEFAULT_SPEEDUPS_DIR


def ensure_speedups_on_path() -> bool:
    """Prepend the speedups directory to ``sys.path`` if it exists."""

    speedups_dir = get_speedups_dir()
    if not speedups_dir.is_dir():
        return False
    path_str = str(speedups_dir)
    if path_str in sys.path:
        return True
    sys.path.insert(0, path_str)
    import builtins
    speedups_z3_lib = speedups_dir / "z3" / "lib"
    if speedups_z3_lib.is_dir():
        # Force z3core.py to search our isolated lib dir first,
        # before falling back to cwd (which is IDA's install dir) or PATH.
        # z3core.py checks builtins.Z3_LIB_DIRS and uses it to override
        # the default search order when loading libz3.{dll,dylib,so}.
        builtins.Z3_LIB_DIRS = [str(speedups_z3_lib)]
    return True

