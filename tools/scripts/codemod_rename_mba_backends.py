#!/usr/bin/env python3
"""Rewrite `d810.mba_backends` imports/usages to `d810.backends`.

Default mode is dry-run. Use `--apply` to write changes.
Run with `pyenv exec` so LibCST is available in the selected environment.
"""

from __future__ import annotations

import argparse
import difflib
from pathlib import Path

import libcst as cst


class RenameMbaBackendsTransformer(cst.CSTTransformer):
    def leave_ImportFrom(
        self, original_node: cst.ImportFrom, updated_node: cst.ImportFrom
    ) -> cst.ImportFrom:
        module = updated_node.module
        if module is None:
            return updated_node
        module_code = cst.Module([]).code_for_node(module)
        if module_code.startswith("d810.mba_backends"):
            new_module_code = module_code.replace("d810.mba_backends", "d810.backends", 1)
            return updated_node.with_changes(module=cst.parse_expression(new_module_code))
        return updated_node

    def leave_ImportAlias(
        self, original_node: cst.ImportAlias, updated_node: cst.ImportAlias
    ) -> cst.ImportAlias:
        name_code = cst.Module([]).code_for_node(updated_node.name)
        if name_code.startswith("d810.mba_backends"):
            new_name = cst.parse_expression(
                name_code.replace("d810.mba_backends", "d810.backends", 1)
            )
            return updated_node.with_changes(name=new_name)
        return updated_node


def rewrite_text(text: str) -> str:
    module = cst.parse_module(text)
    transformed = module.visit(RenameMbaBackendsTransformer())
    out = transformed.code
    # Catch string/docs comments that encode old module path.
    return out.replace("d810.mba_backends", "d810.backends")


def iter_python_files(root: Path) -> list[Path]:
    self_path = Path(__file__).resolve()
    return sorted(
        p
        for p in root.rglob("*.py")
        if p.resolve() != self_path
        if ".git/" not in str(p)
        and ".venv/" not in str(p)
        and "__pycache__/" not in str(p)
        and "/build/" not in str(p)
        and "/dist/" not in str(p)
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".", help="Repo root to scan")
    parser.add_argument("--apply", action="store_true", help="Write changes")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    changed = 0
    files = iter_python_files(root)
    for path in files:
        src = path.read_text(encoding="utf-8")
        if "mba_backends" not in src:
            continue
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
