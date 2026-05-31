#!/usr/bin/env python3
"""Triage llr-zeyu live-object-access sites by migration shape.

Read-only.  For every portable-core file that the gate flags, classify HOW the
live access can be removed, so the burn-down can be ordered safest-first:

  DUAL_PATH   - has an ``if hasattr(target,"blocks")`` (or ``_from_flowgraph``
                / ``_from_mba``) fork: the live branch is dead in production
                (collectors get a FlowGraph via FLOWGRAPH_READY).  Safe delete.
  COLLECTOR   - defines ``def collect(self, target, ...)`` and is registered as
                a ReconCollector: receives a FlowGraph at runtime, so live
                calls are convertible to BlockSnapshot fields.
  HELPER      - a free function / method taking ``mba`` from a HIGH caller;
                needs caller-contract analysis before converting.

Run from anywhere (absolute paths dodge the cwd-reset hook):
    python3 tools/scripts/triage_live_object_sites.py [--root <worktree>]
"""
from __future__ import annotations

import argparse
import pathlib
import re

ROOT_DEFAULT = "/Users/mahmoud/src/idapro/d810/.worktrees/llvm-lisa-restructure"

# Live-object access patterns (mirror the gate; method-call / live-attr only).
LIVE = [
    re.compile(r"\.get_mblock\s*\("),
    re.compile(r"\.nsucc\s*\(\)"),
    re.compile(r"\.npred\s*\(\)"),
    re.compile(r"\.succ\s*\([^)]"),   # .succ(i) call, not .succs
    re.compile(r"\.pred\s*\([^)]"),   # .pred(i) call, not .preds
    re.compile(r"\.succset\b"),
    re.compile(r"\.predset\b"),
]

DUAL = re.compile(r'hasattr\([^,]+,\s*"blocks"\)|_extract_from_flowgraph|'
                  r'_from_flowgraph|_extract_from_mba|_from_mba|'
                  r'isinstance\([^,]+,\s*FlowGraph\)')
COLLECTOR = re.compile(r"def collect\(self, target")

PORTABLE_CORE = ("ir", "analyses", "transforms", "capabilities", "support",
                 "core", "passes", "families")


def iter_py(root: pathlib.Path):
    for pkg in PORTABLE_CORE:
        base = root / "src" / "d810" / pkg
        if base.is_dir():
            yield from base.rglob("*.py")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=ROOT_DEFAULT)
    args = ap.parse_args()
    root = pathlib.Path(args.root)

    rows = []
    for path in iter_py(root):
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        hits = 0
        for line in text.splitlines():
            if any(rx.search(line) for rx in LIVE):
                hits += 1
        if not hits:
            continue
        rel = path.relative_to(root / "src" / "d810").as_posix()
        is_dual = bool(DUAL.search(text))
        is_coll = bool(COLLECTOR.search(text))
        shape = "DUAL_PATH" if is_dual else ("COLLECTOR" if is_coll else "HELPER")
        rows.append((shape, hits, rel))

    rows.sort(key=lambda r: ({"DUAL_PATH": 0, "COLLECTOR": 1, "HELPER": 2}[r[0]],
                             -r[1], r[2]))
    total = sum(r[1] for r in rows)
    print(f"# triage: {len(rows)} files / {total} live-access hits "
          f"(gate counts method-call+attr forms only)\n")
    cur = None
    for shape, hits, rel in rows:
        if shape != cur:
            print(f"## {shape}")
            cur = shape
        print(f"  {hits:3d}  {rel}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
