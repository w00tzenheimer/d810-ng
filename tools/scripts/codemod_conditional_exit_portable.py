#!/usr/bin/env python3
"""Codemod: convert conditional_exit.py helpers from the live ``mblock_t`` API
to the portable ``d810.ir.BlockSnapshot`` field API (ticket llr-zeyu).

``classify_exit_block`` / ``get_loopback_successor`` / ``get_exit_successor``
have ZERO production callers (only the system test exercises them, via live-API
mocks).  Their block parameter can therefore be re-contracted as a portable
``BlockSnapshot``:

    live mblock_t        portable BlockSnapshot
    exit_blk.nsucc()  -> exit_blk.nsucc      (int @property)
    exit_blk.succ(0)  -> exit_blk.succs[0]   (tuple[int])
    exit_blk.succ(1)  -> exit_blk.succs[1]

This is a TARGETED swap, valid only because the block here is caller-supplied
and has no live-mba production source.  It is NOT a general rule: HELPER files
whose block comes from ``mba.get_mblock(...)`` need the upstream FlowGraph lift
instead, not a token swap.

The test's ``_make_blk`` mock is switched from live-API lambdas
(``.nsucc = lambda: n`` / ``.succ = lambda i: ...``) to portable fields
(``.nsucc = n`` int, ``.succs = tuple`` ) so it mirrors BlockSnapshot.

Read-only by default; pass ``--apply`` to write.
"""
from __future__ import annotations

import argparse
import difflib
import pathlib
import re

ROOT = pathlib.Path(
    "/Users/mahmoud/src/idapro/d810/.worktrees/llvm-lisa-restructure"
)

SRC = "src/d810/analyses/control_flow/conditional_exit.py"
TEST = "tests/system/runtime/optimizers/flow/test_conditional_exit.py"

# Source: live method API -> portable field API.
SRC_SUBS = [
    (r"\bexit_blk\.nsucc\(\)", "exit_blk.nsucc"),
    (r"\bexit_blk\.succ\(0\)", "exit_blk.succs[0]"),
    (r"\bexit_blk\.succ\(1\)", "exit_blk.succs[1]"),
]

# Source docstring: state the portable contract.
SRC_DOCSUB = (
    '"""Conditional exit block classification helpers for flattening analysis."""',
    '"""Conditional exit block classification helpers (flattening analysis).\n'
    "\n"
    "Operate on a portable :class:`d810.ir.BlockSnapshot` -- they read\n"
    "``blk.nsucc`` (int) and ``blk.succs`` (tuple) only, never the live\n"
    "Hex-Rays ``mblock_t`` method API (ticket llr-zeyu).\n"
    '"""',
)

# Test: swap the live-API mock for portable fields.
TEST_OLD = (
    "def _make_blk(nsucc: int, succs: list[int]):\n"
    "    blk = types.SimpleNamespace()\n"
    "    blk.nsucc = lambda: nsucc\n"
    "    blk.succ = lambda i: succs[i]\n"
    "    return blk"
)
TEST_NEW = (
    "def _make_blk(nsucc: int, succs: list[int]):\n"
    "    # Mirror the portable d810.ir BlockSnapshot field API the helpers now\n"
    "    # consume: ``.nsucc`` is an int (not a method) and ``.succs`` a tuple.\n"
    "    blk = types.SimpleNamespace()\n"
    "    blk.nsucc = nsucc\n"
    "    blk.succs = tuple(succs)\n"
    "    return blk"
)


def _apply(rel: str, subs, docsub, raw_old_new, apply: bool) -> bool:
    path = ROOT / rel
    src = path.read_text(encoding="utf-8")
    out = src
    for pat, repl in subs:
        out, n = re.subn(pat, repl, out)
        if n == 0:
            print(f"  WARN [{rel}] 0x match: {pat}")
    if docsub is not None:
        old, new = docsub
        if old in out:
            out = out.replace(old, new, 1)
        else:
            print(f"  WARN [{rel}] docstring not found")
    if raw_old_new is not None:
        old, new = raw_old_new
        if old in out:
            out = out.replace(old, new, 1)
        else:
            print(f"  WARN [{rel}] raw block not found")
    changed = out != src
    print(f"{rel}: changed={changed}")
    if changed and not apply:
        print("".join(difflib.unified_diff(
            src.splitlines(keepends=True), out.splitlines(keepends=True),
            fromfile=rel, tofile=rel + " (new)")))
    if changed and apply:
        path.write_text(out, encoding="utf-8")
    return changed


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()
    c1 = _apply(SRC, SRC_SUBS, SRC_DOCSUB, None, args.apply)
    c2 = _apply(TEST, [], None, (TEST_OLD, TEST_NEW), args.apply)
    if not args.apply:
        print("\n(dry-run; pass --apply to write)")
    return 0 if (c1 or c2) else 1


if __name__ == "__main__":
    raise SystemExit(main())
