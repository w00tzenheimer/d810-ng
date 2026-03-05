#!/usr/bin/env python3
"""Phase A codemod: move flattening analysis modules from optimizers -> recon.

Default mode is dry-run. Use ``--apply`` to write file moves and rewrites.
Run with ``pyenv exec`` so LibCST is available.
"""

from __future__ import annotations

import argparse
import difflib
from pathlib import Path

import libcst as cst


PHASE_A_RENAMES = {
    "d810.optimizers.microcode.flow.flattening.dispatcher_detection": (
        "d810.recon.flow.dispatcher_detection"
    ),
    "d810.optimizers.microcode.flow.flattening.heuristics": (
        "d810.recon.flow.heuristics"
    ),
    "d810.optimizers.microcode.flow.flattening.loop_prover": (
        "d810.recon.flow.loop_prover"
    ),
}

PHASE_A_MOVES = {
    "src/d810/optimizers/microcode/flow/flattening/dispatcher_detection.py": (
        "src/d810/recon/flow/dispatcher_detection.py"
    ),
    "src/d810/optimizers/microcode/flow/flattening/heuristics.py": (
        "src/d810/recon/flow/heuristics.py"
    ),
    "src/d810/optimizers/microcode/flow/flattening/loop_prover.py": (
        "src/d810/recon/flow/loop_prover.py"
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
        if module_code in PHASE_A_RENAMES:
            return updated_node.with_changes(
                module=cst.parse_expression(PHASE_A_RENAMES[module_code])
            )
        return updated_node

    def leave_ImportAlias(
        self, original_node: cst.ImportAlias, updated_node: cst.ImportAlias
    ) -> cst.ImportAlias:
        name_code = cst.Module([]).code_for_node(updated_node.name)
        if name_code in PHASE_A_RENAMES:
            return updated_node.with_changes(
                name=cst.parse_expression(PHASE_A_RENAMES[name_code])
            )
        return updated_node


def _rewrite_text(text: str) -> str:
    module = cst.parse_module(text)
    out = module.visit(ModuleRenameTransformer()).code
    for old, new in PHASE_A_RENAMES.items():
        out = out.replace(old, new)
    return out


def _iter_python_files(root: Path) -> list[Path]:
    self_path = Path(__file__).resolve()
    include_dirs = [root / "src", root / "tests", root / "tools"]
    files: list[Path] = []
    for base in include_dirs:
        if not base.exists():
            continue
        files.extend(base.rglob("*.py"))
    return sorted(
        p
        for p in files
        if p.resolve() != self_path
        if ".git/" not in str(p)
        and ".venv/" not in str(p)
        and "__pycache__/" not in str(p)
        and "/build/" not in str(p)
        and "/dist/" not in str(p)
        and "/.claude/worktrees/" not in str(p)
        and "/.worktrees/" not in str(p)
    )


def _do_moves(root: Path, apply: bool) -> int:
    moved = 0
    for src_rel, dst_rel in PHASE_A_MOVES.items():
        src = root / src_rel
        dst = root / dst_rel
        if not src.exists():
            continue
        moved += 1
        if apply:
            dst.parent.mkdir(parents=True, exist_ok=True)
            src.rename(dst)
            print(f"moved {src_rel} -> {dst_rel}")
        else:
            print(f"would move {src_rel} -> {dst_rel}")
    return moved


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".", help="Repo root to scan")
    parser.add_argument("--apply", action="store_true", help="Write changes")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    moved = _do_moves(root, args.apply)

    rewritten = 0
    for path in _iter_python_files(root):
        src = path.read_text(encoding="utf-8")
        if not any(old in src for old in PHASE_A_RENAMES):
            continue
        out = _rewrite_text(src)
        if out == src:
            continue
        rewritten += 1
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
    print(f"{mode}: moved={moved}, rewritten={rewritten}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
