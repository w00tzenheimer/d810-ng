#!/usr/bin/env python3
"""Compatibility wrapper for the renamed D810 operator CLI."""
from __future__ import annotations

import os
import sys
from pathlib import Path


def main() -> int:
    target = Path(__file__).with_name("d810cli.py")
    print(
        "[deprecated] tools/cff_debug.py moved to tools/d810cli.py; forwarding.",
        file=sys.stderr,
    )
    os.execvpe(
        sys.executable,
        [sys.executable, str(target), *sys.argv[1:]],
        os.environ.copy(),
    )
    return 127


if __name__ == "__main__":
    raise SystemExit(main())
