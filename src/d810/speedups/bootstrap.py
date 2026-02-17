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
    return True

