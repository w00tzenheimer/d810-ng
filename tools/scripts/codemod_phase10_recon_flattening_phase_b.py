#!/usr/bin/env python3
"""Phase B codemod: rewrite conditional_exit imports to recon.flow.

Default mode is dry-run. Use ``--apply`` to write changes.
"""

from __future__ import annotations

import argparse
import difflib
from pathlib import Path

import libcst as cst


PHASE_B_RENAMES = {
    "d810.optimizers.microcode.flow.flattening.conditional_exit": (
        "d810.recon.flow.conditional_exit"
    ),
}


class ModuleRenameTransformer(cst.CSTTransformer):
    def leave_ImportFrom(
        self, original_node: cst.ImportFrom, updated_node: cst.ImportFrom
    ) -> cst.ImportFrom:
        module = updated_node.module
        if module is None:
            return updated_node
        module_code = cst.Module([]).code_for_node(module)
        if module_code in PHASE_B_RENAMES:
            return updated_node.with_changes(
                module=cst.parse_expression(PHASE_B_RENAMES[module_code])
            )
        return updated_node

    def leave_ImportAlias(
        self, original_node: cst.ImportAlias, updated_node: cst.ImportAlias
    ) -> cst.ImportAlias:
        name_code = cst.Module([]).code_for_node(updated_node.name)
        if name_code in PHASE_B_RENAMES:
            return updated_node.with_changes(
                name=cst.parse_expression(PHASE_B_RENAMES[name_code])
            )
        return updated_node


def _rewrite_text(text: str) -> str:
    module = cst.parse_module(text)
    out = module.visit(ModuleRenameTransformer()).code
    for old, new in PHASE_B_RENAMES.items():
        out = out.replace(old, new)
    return out


def _iter_python_files(root: Path) -> list[Path]:
    self_path = Path(__file__).resolve()
    include_dirs = [root / "src", root / "tests", root / "tools"]
    files: list[Path] = []
    for base in include_dirs:
        if base.exists():
            files.extend(base.rglob("*.py"))
    return sorted(
        p
        for p in files
        if p.resolve() != self_path
        if "__pycache__/" not in str(p)
        and "/.claude/worktrees/" not in str(p)
        and "/.worktrees/" not in str(p)
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    changed = 0
    for path in _iter_python_files(root):
        src = path.read_text(encoding="utf-8")
        if not any(old in src for old in PHASE_B_RENAMES):
            continue
        out = _rewrite_text(src)
        if out == src:
            continue
        changed += 1
        if args.apply:
            path.write_text(out, encoding="utf-8")
            print(f"rewrote {path.relative_to(root)}")
        else:
            print(f"would rewrite {path.relative_to(root)}")
            for line in difflib.unified_diff(
                src.splitlines(),
                out.splitlines(),
                fromfile=str(path.relative_to(root)),
                tofile=str(path.relative_to(root)),
                lineterm="",
            ):
                print(line)
    mode = "applied" if args.apply else "dry-run"
    print(f"{mode}: rewritten={changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
