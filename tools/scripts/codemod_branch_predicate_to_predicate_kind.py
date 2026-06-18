#!/usr/bin/env python3
"""Codemod: retire ``BranchPredicate`` (ir.flowgraph) in favour of the LLVM-named
``PredicateKind`` (ir.semantics) -- the dedup half of the condition-chain condition
convergence (ticket llr-lxas).

The two enums are semantically identical (same 11 members; BranchPredicate's
string values "eq"/"ne"/... are kept on PredicateKind which is migrated to a
``(str, Enum)`` so ``PredicateKind(str(raw))`` reconstruction still works).  The
two backend lift mappers (``_branch_predicate_from_hexrays`` /
``_branch_predicate_only_from_hexrays``) are the SAME m_jX mapping, so the
``InsnSnapshot.branch_predicate`` value is byte-identical after the swap.

This script does the bulk textual rename across src + tests:
  * ``BranchPredicate.<LONG>`` -> ``PredicateKind.<SHORT>`` (member map)
  * bare ``BranchPredicate``    -> ``PredicateKind``        (imports / annotations)

``ir/flowgraph.py`` (BranchPredicate def + re-export) and ``ir/semantics.py``
(PredicateKind str-enum) and ``hexrays/mutation/ir_translator.py`` (lift swap +
import dedup) are edited by hand, NOT here.  ``flowgraph`` re-exports
``PredicateKind`` so ``from d810.ir.flowgraph import PredicateKind`` keeps
resolving with no import-source surgery.

Read-only by default; pass ``--apply`` to write.
"""
from __future__ import annotations

import argparse
import difflib
import pathlib
import re

ROOT = pathlib.Path("/Users/mahmoud/src/idapro/d810/.worktrees/llvm-lisa-restructure")

# Hand-edited; the codemod must skip these.
SKIP = {
    "src/d810/ir/flowgraph.py",
    "src/d810/ir/semantics.py",
    "src/d810/hexrays/mutation/ir_translator.py",
}

MEMBER_MAP = {
    "EQUAL": "EQ",
    "NOT_EQUAL": "NE",
    "UNSIGNED_GE": "UGE",
    "UNSIGNED_GT": "UGT",
    "UNSIGNED_LE": "ULE",
    "UNSIGNED_LT": "ULT",
    "SIGNED_GE": "SGE",
    "SIGNED_GT": "SGT",
    "SIGNED_LE": "SLE",
    "SIGNED_LT": "SLT",
    "TRUTHY": "TRUTHY",
}


def _rewrite(text: str) -> str:
    # 1) member access: BranchPredicate.<LONG> -> PredicateKind.<SHORT>
    def member_sub(m: re.Match) -> str:
        long = m.group(1)
        short = MEMBER_MAP.get(long)
        return f"PredicateKind.{short}" if short else m.group(0)

    text = re.sub(r"\bBranchPredicate\.([A-Z_]+)\b", member_sub, text)
    # 2) any remaining bare BranchPredicate (imports, annotations, isinstance)
    text = re.sub(r"\bBranchPredicate\b", "PredicateKind", text)
    return text


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()

    targets = []
    for base in ("src", "tests"):
        for path in (ROOT / base).rglob("*.py"):
            rel = str(path.relative_to(ROOT))
            if rel in SKIP:
                continue
            text = path.read_text(encoding="utf-8")
            if "BranchPredicate" not in text:
                continue
            targets.append((rel, path, text))

    changed = 0
    for rel, path, text in targets:
        out = _rewrite(text)
        if out == text:
            continue
        changed += 1
        n = text.count("BranchPredicate")
        print(f"{rel}: {n} BranchPredicate refs rewritten")
        if not args.apply:
            print("".join(difflib.unified_diff(
                text.splitlines(keepends=True)[:0],
                out.splitlines(keepends=True)[:0])))
        if args.apply:
            path.write_text(out, encoding="utf-8")

    # Safety: no surviving BranchPredicate outside the skip set.
    if args.apply:
        survivors = [
            rel for rel, path, _ in targets
            if "BranchPredicate" in path.read_text(encoding="utf-8")
        ]
        if survivors:
            print(f"WARN survivors: {survivors}")
    print(f"\n{changed} files {'rewritten' if args.apply else 'would change'} "
          f"(skipped hand-edited: {sorted(SKIP)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
