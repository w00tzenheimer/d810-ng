"""Installer for isolated optional speedups dependencies."""

from __future__ import annotations

import subprocess
import sys

from d810.speedups import bootstrap

__all__ = [
    "get_speedups_dir",
    "ensure_speedups_on_path",
    "install_speedups",
]

SPEEDUPS_PACKAGES = ["z3-solver>=4.13,<4.15.5"]

get_speedups_dir = bootstrap.get_speedups_dir
ensure_speedups_on_path = bootstrap.ensure_speedups_on_path


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
