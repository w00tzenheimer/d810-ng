#!/usr/bin/env python3
"""Phase 4 codemod: route BST semantic imports through recon.flow.

Default mode is dry-run. Use --apply to write changes.
Run with `pyenv exec` to use the project interpreter.
"""

from __future__ import annotations

import argparse
import difflib
from pathlib import Path


REPLACEMENTS: tuple[tuple[str, str], ...] = (
    (
        "from d810.hexrays.utils.bst_analysis import BSTAnalysisResult, analyze_bst_dispatcher",
        "from d810.recon.flow.bst_analysis import BSTAnalysisResult, analyze_bst_dispatcher",
    ),
    (
        "from d810.hexrays.utils.bst_analysis import BSTAnalysisResult, resolve_target_via_bst",
        "from d810.recon.flow.bst_analysis import BSTAnalysisResult, resolve_target_via_bst",
    ),
    (
        "from d810.hexrays.utils.bst_analysis import BSTAnalysisResult",
        "from d810.recon.flow.bst_analysis import BSTAnalysisResult",
    ),
    (
        "from d810.hexrays.utils.bst_analysis import analyze_bst_dispatcher",
        "from d810.recon.flow.bst_analysis import analyze_bst_dispatcher",
    ),
    (
        "from d810.hexrays.utils.bst_analysis import (\n"
        "    _forward_eval_insn,\n"
        "    _mop_matches_stkoff,\n"
        "    find_bst_default_block,\n"
        "    resolve_target_via_bst,\n"
        ")\n",
        "from d810.hexrays.utils.bst_analysis import (\n"
        "    _forward_eval_insn,\n"
        "    _mop_matches_stkoff,\n"
        "    find_bst_default_block,\n"
        ")\n"
        "from d810.recon.flow.bst_analysis import resolve_target_via_bst\n",
    ),
    (
        "from d810.hexrays.utils.bst_analysis import (\n"
        "    _mop_matches_stkoff,\n"
        "    find_bst_default_block,\n"
        "    resolve_target_via_bst,\n"
        ")\n",
        "from d810.hexrays.utils.bst_analysis import (\n"
        "    _mop_matches_stkoff,\n"
        "    find_bst_default_block,\n"
        ")\n"
        "from d810.recon.flow.bst_analysis import resolve_target_via_bst\n",
    ),
)


TARGET_FILES: tuple[str, ...] = (
    "src/d810/optimizers/microcode/flow/flattening/hodur/_helpers.py",
    "src/d810/optimizers/microcode/flow/flattening/hodur/strategies/direct_linearization.py",
    "src/d810/optimizers/microcode/flow/flattening/hodur/unflattener.py",
    "src/d810/optimizers/microcode/flow/flattening/transition_builder.py",
    "tests/system/runtime/hexrays/test_bst_lookup.py",
    "tests/system/runtime/optimizers/flow/flattening/test_transition_builder.py",
)


def iter_target_files(root: Path) -> list[Path]:
    paths: list[Path] = []
    for rel in TARGET_FILES:
        path = (root / rel).resolve()
        if path.exists():
            paths.append(path)
    return paths


def rewrite_text(text: str) -> str:
    out = text
    for old, new in REPLACEMENTS:
        out = out.replace(old, new)
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".", help="Repo root to scan")
    parser.add_argument("--apply", action="store_true", help="Write changes")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    changed = 0
    for path in iter_target_files(root):
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
            diff = difflib.unified_diff(
                src.splitlines(),
                out.splitlines(),
                fromfile=str(path),
                tofile=str(path),
                lineterm="",
            )
            for line in diff:
                print(line)

    if changed == 0:
        print("no files needed rewriting")
    else:
        mode = "applied" if args.apply else "dry-run"
        print(f"{mode}: {changed} file(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
