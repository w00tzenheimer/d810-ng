#!/usr/bin/env python3
"""Inventory live-backend object-access (duck-typing) in portable-core layers.

This is the grounding inventory for ticket ``llr-zeyu`` (data-model
portability) and the basis for the future live-object-access ast-grep gate.

Portable-core layers are portable by *import shape* (no ``ida_*`` imports,
``lint-imports`` 13/0) but several modules still duck-type a *live* Hex-Rays
``mba``/``mblock``/``minsn`` object instead of consuming a portable
``FlowGraph``/snapshot.  This script enumerates those access sites so they can
be migrated behind provider/capability protocols.

Run from anywhere (uses absolute paths to dodge the cwd-reset hook):

    python3 tools/scripts/inventory_live_object_access.py [--root <repo-or-worktree>]

It is read-only.  Exit code is always 0; the count is informational until the
gate flips it to a hard failure (F-plan F2/F7).
"""
from __future__ import annotations

import argparse
import pathlib
import re
import sys

# Portable-core layers: these MUST NOT touch a live backend object directly.
PORTABLE_CORE = ("ir", "analyses", "transforms", "capabilities", "support", "core")

# Attribute names that only exist on a *live* Hex-Rays mba/mblock/minsn.
# (Snapshot/portable equivalents use different shapes: BlockSnapshot.serial,
#  .succs, .insn_snapshots, FlowGraph.nodes, etc.)
LIVE_ATTRS = (
    "maturity", "qty", "succset", "predset", "head", "tail",
    "npred", "nsucc",
)

# Site patterns -> kind label.  Each is matched per physical line.
PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("get_mblock", re.compile(r"\.get_mblock\s*\(")),
    ("getattr_live", re.compile(
        r'getattr\(\s*[^,]+,\s*"(' + "|".join(LIVE_ATTRS) + r')"')),
    ("attr_succset", re.compile(r"\.succset\b")),
    ("attr_predset", re.compile(r"\.predset\b")),
    ("call_npred", re.compile(r"\.npred\s*\(")),
    ("call_nsucc", re.compile(r"\.nsucc\s*\(")),
    ("build_use_list", re.compile(r"\bbuild_use_list\s*\(")),
    ("get_du", re.compile(r"\.get_du\s*\(")),
    ("snapshot_mba", re.compile(r"\bsnapshot\.mba\b")),
]

# Lines that look like a hit but are NOT live access (kwargs, snapshot paths,
# comments/docstrings describing the duck-typing we are removing).
FALSE_POSITIVE = re.compile(
    r"maturity\s*=\s*int\s*\(|insn_snapshots|^\s*#|\"\"\"|duck-typed"
)


def iter_py(root: pathlib.Path):
    for pkg in PORTABLE_CORE:
        base = root / "src" / "d810" / pkg
        if base.is_dir():
            yield from base.rglob("*.py")


def scan(root: pathlib.Path) -> dict[str, list[tuple[str, int, str, str]]]:
    by_file: dict[str, list[tuple[str, int, str, str]]] = {}
    for path in iter_py(root):
        rel = path.relative_to(root / "src" / "d810").as_posix()
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        for n, line in enumerate(lines, 1):
            if FALSE_POSITIVE.search(line):
                continue
            for kind, rx in PATTERNS:
                if rx.search(line):
                    by_file.setdefault(rel, []).append(
                        (kind, n, line.strip()[:88], rel))
    return by_file


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--root",
        default="/Users/mahmoud/src/idapro/d810/.worktrees/llvm-lisa-restructure",
        help="repo or worktree root (default: llvm-lisa-restructure worktree)",
    )
    args = ap.parse_args()
    root = pathlib.Path(args.root)
    by_file = scan(root)
    total = sum(len(v) for v in by_file.values())
    print(f"# live-object-access inventory (llr-zeyu)  root={root}")
    print(f"# files={len(by_file)}  sites={total}\n")
    for rel in sorted(by_file):
        print(f"## {rel}")
        for kind, n, text, _ in by_file[rel]:
            print(f"  L{n:<4} [{kind:13}] {text}")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
