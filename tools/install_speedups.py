"""CLI helper that installs optional speedups prerequisites into the repo."""

from __future__ import annotations

from d810.speedups.install import install_speedups


def main() -> None:
    install_speedups()


if __name__ == "__main__":
    main()
