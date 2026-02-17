"""Utilities for the repo-local optional speedups install."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

__all__ = [
    "get_speedups_dir",
    "ensure_speedups_on_path",
    "install_speedups",
]

PACKAGE_ROOT = Path(__file__).resolve().parent
DEFAULT_SPEEDUPS_DIR = PACKAGE_ROOT / ".d810-speedups"
SPEEDUPS_PACKAGES = ["z3-solver>=4.13,<4.15.5"]


def get_speedups_dir() -> Path:
    """Return the configured directory where speedups dependencies live."""

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


def install_speedups(packages: list[str] | None = None) -> None:
    """Install optional dependencies into the private speedups directory."""

    speedups_dir = get_speedups_dir()
    speedups_dir.mkdir(parents=True, exist_ok=True)
    pkg_list = packages or SPEEDUPS_PACKAGES
    cmd = [
        sys.executable,
        "-m",
        "pip",
        "install",
        "--target",
        str(speedups_dir),
        *pkg_list,
    ]
    subprocess.run(cmd, check=True)


def main() -> None:
    install_speedups()


if __name__ == "__main__":
    main()
