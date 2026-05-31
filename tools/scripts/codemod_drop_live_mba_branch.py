#!/usr/bin/env python3
"""Codemod: drop the dead live-``mba_t`` branch from dual-path portable-core
collectors/helpers (ticket llr-zeyu, data-model portability).

Since E4a the HIGH layer lifts the live ``mba`` to a portable ``d810.ir``
FlowGraph once at the FLOWGRAPH_READY boundary and hands portable code the
snapshot.  The ``if hasattr(target, "blocks") and hasattr(target,
"entry_serial"): <FlowGraph> else: <live mba>`` fork is therefore dead on its
``else`` arm in production.  This codemod:

  1. unwraps every ``If`` whose test is the dual-path guard (contains
     ``hasattr(..., "blocks")`` and ``"entry_serial"``) down to just its
     FlowGraph body, dropping the ``else``;
  2. deletes named now-dead helper functions (the ``_*_from_mba`` walkers);
  3. regex-fixes the stale "or live mba_t" docstring prose.

libcst handles (1)+(2); regex handles (3) -- the libcst/regex hybrid the
project standardised on.  Read-only by default; pass ``--apply`` to write.

    python3 tools/scripts/codemod_drop_live_mba_branch.py            # dry-run
    python3 tools/scripts/codemod_drop_live_mba_branch.py --apply
"""
from __future__ import annotations

import argparse
import difflib
import pathlib
import re

import libcst as cst

ROOT = pathlib.Path(
    "/Users/mahmoud/src/idapro/d810/.worktrees/llvm-lisa-restructure"
)

# Per-file plan: dead helper functions to delete + docstring regex subs.
PLAN: dict[str, dict] = {
    "src/d810/analyses/control_flow/dispatch_pattern.py": {
        # Docstring carries no mba prose; only the inline dual-path fork
        # needs unwrapping.
        "dead_funcs": [],
        "doc_subs": [],
    },
    "src/d810/analyses/control_flow/profile_classifier_collector.py": {
        # The else-arm called _live_components; after unwrap it is dead.
        "dead_funcs": ["_live_components"],
        "doc_subs": [
            (
                r"the target \(portable\s+``FlowGraph`` or live ``mba_t``\)",
                "the target (a portable ``d810.ir`` ``FlowGraph``)",
            ),
            (
                r":param target: ``FlowGraph`` snapshot or live ``mba_t``\.",
                ":param target: a portable ``d810.ir`` ``FlowGraph``.",
            ),
        ],
    },
    "src/d810/analyses/control_flow/cfg_shape.py": {
        "dead_funcs": ["_collect_from_mba"],
        "doc_subs": [
            (
                r"Operates on either a live ``mba_t`` \(at IDA runtime\) or a "
                r"``FlowGraph``\nsnapshot \(for unit tests\)\. Distinguishes the "
                r"two by duck-typing: if the\ntarget has a ``blocks`` attribute "
                r"that maps serials to ``BlockSnapshot``,\nit is treated as a "
                r"``FlowGraph``; otherwise it is treated as an ``mba_t``\.",
                "Consumes a portable ``d810.ir`` FlowGraph -- the HIGH layer "
                "lifts\nthe live ``mba`` once at the FLOWGRAPH_READY boundary "
                "(E4a); the\ncollector never touches a live ``mba_t``/``mblock_t`` "
                "(ticket llr-zeyu).",
            ),
            (
                r'"""Extract nodes/succs/preds from a FlowGraph snapshot\."""',
                '"""Extract nodes/succs/preds from a portable FlowGraph."""',
            ),
            (
                r":param target: ``FlowGraph`` or live ``mba_t``\.",
                ":param target: portable ``d810.ir`` ``FlowGraph``.",
            ),
            (
                r"\n\n    Accepts both ``FlowGraph`` \(unit tests\) and live "
                r"``mba_t`` \(IDA runtime\)\.",
                "",
            ),
        ],
    },
}


def _is_dual_path_guard(test: cst.BaseExpression) -> bool:
    """True iff ``test`` is the FlowGraph dual-path guard."""
    code = cst.Module(body=[]).code_for_node(test)
    return 'hasattr' in code and '"blocks"' in code and '"entry_serial"' in code


class DropLiveMbaBranch(cst.CSTTransformer):
    def __init__(self, dead_funcs: list[str]) -> None:
        self.dead_funcs = set(dead_funcs)
        self.unwrapped = 0
        self.deleted: list[str] = []

    def leave_If(
        self, original: cst.If, updated: cst.If
    ) -> cst.BaseStatement | cst.FlattenSentinel:
        if isinstance(original.test, cst.BaseExpression) and _is_dual_path_guard(
            original.test
        ):
            self.unwrapped += 1
            # Replace the whole If with its (FlowGraph) body statements.
            return cst.FlattenSentinel(updated.body.body)
        return updated

    def leave_FunctionDef(
        self, original: cst.FunctionDef, updated: cst.FunctionDef
    ):
        if original.name.value in self.dead_funcs:
            self.deleted.append(original.name.value)
            return cst.RemoveFromParent()
        return updated


def process(rel: str, plan: dict, apply: bool) -> bool:
    path = ROOT / rel
    src = path.read_text(encoding="utf-8")
    module = cst.parse_module(src)
    xform = DropLiveMbaBranch(plan["dead_funcs"])
    new_module = module.visit(xform)
    out = new_module.code
    for pat, repl in plan["doc_subs"]:
        out, n = re.subn(pat, repl, out, flags=re.S)
        if n == 0:
            print(f"  WARN [{rel}] doc_sub matched 0x: {pat[:48]}...")
    changed = out != src
    print(
        f"{rel}: unwrapped={xform.unwrapped} "
        f"deleted={xform.deleted or '-'} changed={changed}"
    )
    if changed and not apply:
        diff = difflib.unified_diff(
            src.splitlines(keepends=True),
            out.splitlines(keepends=True),
            fromfile=rel, tofile=rel + " (new)",
        )
        print("".join(diff))
    if changed and apply:
        path.write_text(out, encoding="utf-8")
    return changed


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--only", help="process only this rel path")
    args = ap.parse_args()
    any_changed = False
    for rel, plan in PLAN.items():
        if args.only and args.only != rel:
            continue
        any_changed |= process(rel, plan, args.apply)
    if not args.apply:
        print("\n(dry-run; pass --apply to write)")
    return 0 if any_changed else 1


if __name__ == "__main__":
    raise SystemExit(main())
