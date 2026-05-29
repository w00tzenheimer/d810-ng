#!/usr/bin/env python3
"""LS6 S8/S9 codemod: repoint bst-cluster importers from the recon shims to
the canonical homes after the bst-cluster split (ticket d81-1w16).

Deterministic dotted-module-path rewrite:

    d810.recon.flow.bst_analysis  -> d810.backends.hexrays.evidence.bst_analysis
    d810.recon.flow.bst_model     -> d810.analyses.control_flow.bst_model
    d810.recon.flow.interval_map  -> d810.analyses.control_flow.interval_map
    d810.recon.flow.bst_snapshot  -> d810.analyses.control_flow.bst_snapshot

Covers ``from X import ...``, ``import X``, lazy in-function imports, and
string references (codemod scripts / related_paths).  The four recon shim
modules themselves are SKIPPED (their content is intentional and they are
deleted in S9).

Default is dry-run.  Use --apply to write.  Pass one or more root paths
(default: src).  Run from the worktree root with ``pyenv exec``.
"""
from __future__ import annotations

import argparse
import difflib
from pathlib import Path

REPLACEMENTS: tuple[tuple[str, str], ...] = (
    ("d810.recon.flow.bst_analysis", "d810.backends.hexrays.evidence.bst_analysis"),
    ("d810.recon.flow.bst_model", "d810.analyses.control_flow.bst_model"),
    ("d810.recon.flow.interval_map", "d810.analyses.control_flow.interval_map"),
    ("d810.recon.flow.bst_snapshot", "d810.analyses.control_flow.bst_snapshot"),
)

# The migration shims at the old recon paths intentionally reference the new
# homes / old names; never rewrite them (S9 deletes them).
SKIP_SUFFIXES: tuple[str, ...] = (
    "src/d810/recon/flow/bst_analysis.py",
    "src/d810/recon/flow/bst_model.py",
    "src/d810/recon/flow/interval_map.py",
    "src/d810/recon/flow/bst_snapshot.py",
)


def _skip(path: Path) -> bool:
    p = path.as_posix()
    return any(p.endswith(suffix) for suffix in SKIP_SUFFIXES)


def rewrite_text(text: str) -> str:
    out = text
    for old, new in REPLACEMENTS:
        out = out.replace(old, new)
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("roots", nargs="*", default=["src"], help="root paths to scan")
    parser.add_argument("--apply", action="store_true", help="write changes")
    args = parser.parse_args()
    roots = args.roots or ["src"]

    changed = 0
    for root in roots:
        for path in sorted(Path(root).rglob("*.py")):
            if _skip(path):
                continue
            src = path.read_text(encoding="utf-8")
            out = rewrite_text(src)
            if out == src:
                continue
            changed += 1
            if args.apply:
                path.write_text(out, encoding="utf-8")
                print(f"rewrote {path}")
            else:
                print(f"would rewrite {path}")
                for line in difflib.unified_diff(
                    src.splitlines(), out.splitlines(),
                    fromfile=str(path), tofile=str(path), lineterm="",
                ):
                    print(line)

    mode = "applied" if args.apply else "dry-run"
    print(f"\n{mode}: {changed} file(s)" if changed else "no files needed rewriting")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
