"""CLI report output helpers for diagnostics commands."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path


class OutputTarget:
    def __init__(self, path: Path | None) -> None:
        self.path = path
        self._has_written = False

    def write(self, text: str) -> None:
        if self.path is None:
            sys.stdout.write(text)
            return

        mode = "a" if self._has_written else "w"
        with self.path.open(mode, encoding="utf-8") as output:
            output.write(text)
        self._has_written = True

    def flush(self) -> None:
        if self.path is None:
            sys.stdout.flush()


def add_output_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="Write report output to this file (default: stdout).",
    )


def get_output(args) -> OutputTarget:
    target = getattr(args, "_d810_output_target", None)
    if target is None:
        target = OutputTarget(getattr(args, "output", None))
        setattr(args, "_d810_output_target", target)
    return target


def write_output(output: OutputTarget, text: str = "", *, end: str = "\n") -> None:
    output.write(text + end)
    output.flush()
