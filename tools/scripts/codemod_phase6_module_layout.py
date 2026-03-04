#!/usr/bin/env python3
"""Phase 6 codemod: module layout renames for backends/cfg surface.

Default mode is dry-run. Use --apply to write and move files.
Run with: pyenv exec python tools/scripts/codemod_phase6_module_layout.py --dry-run
"""

from __future__ import annotations

import argparse
import difflib
import shutil
from pathlib import Path

import libcst as cst


MODULE_RENAMES: dict[str, str] = {
    "d810.backends.z3": "d810.backends.mba.z3",
    "d810.backends.ida": "d810.backends.mba.ida",
    "d810.backends.egglog_backend": "d810.backends.mba.egglog_backend",
    "d810.backends.egraph": "d810.backends.mba.egraph",
    "d810.cfg.portable_cfg": "d810.cfg.flowgraph",
    "d810.cfg.cfg_backend": "d810.cfg.protocol",
    "d810.cfg.cfg_pass": "d810.cfg.passes._base",
    "d810.cfg.pass_pipeline": "d810.cfg.pipeline",
}

FILE_RENAMES: dict[str, str] = {
    "src/d810/backends/z3.py": "src/d810/backends/mba/z3.py",
    "src/d810/backends/ida.py": "src/d810/backends/mba/ida.py",
    "src/d810/backends/egglog_backend.py": "src/d810/backends/mba/egglog_backend.py",
    "src/d810/backends/egraph.py": "src/d810/backends/mba/egraph.py",
    "src/d810/cfg/portable_cfg.py": "src/d810/cfg/flowgraph.py",
    "src/d810/cfg/cfg_backend.py": "src/d810/cfg/protocol.py",
    "src/d810/cfg/cfg_pass.py": "src/d810/cfg/passes/_base.py",
    "src/d810/cfg/pass_pipeline.py": "src/d810/cfg/pipeline.py",
}

PACKAGE_INITS: dict[str, str] = {
    "src/d810/backends/mba/__init__.py": '"""MBA-specific backends."""\n',
}


def _ordered_module_renames() -> list[tuple[str, str]]:
    return sorted(MODULE_RENAMES.items(), key=lambda kv: len(kv[0]), reverse=True)


def rewrite_dotted_name(name: str) -> str:
    for old, new in _ordered_module_renames():
        if name == old or name.startswith(old + "."):
            return new + name[len(old) :]
    return name


class RenameTransformer(cst.CSTTransformer):
    def leave_ImportAlias(
        self, original_node: cst.ImportAlias, updated_node: cst.ImportAlias
    ) -> cst.ImportAlias:
        name_code = cst.Module([]).code_for_node(updated_node.name)
        new_name = rewrite_dotted_name(name_code)
        if new_name != name_code:
            return updated_node.with_changes(name=cst.parse_expression(new_name))
        return updated_node

    def leave_ImportFrom(
        self, original_node: cst.ImportFrom, updated_node: cst.ImportFrom
    ) -> cst.ImportFrom:
        module = updated_node.module
        if module is None:
            return updated_node
        module_code = cst.Module([]).code_for_node(module)
        new_module_code = rewrite_dotted_name(module_code)
        if new_module_code != module_code:
            return updated_node.with_changes(module=cst.parse_expression(new_module_code))
        return updated_node


def rewrite_text(text: str) -> str:
    module = cst.parse_module(text)
    transformed = module.visit(RenameTransformer())
    out = transformed.code
    for old, new in _ordered_module_renames():
        out = out.replace(old, new)
    return out


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


def ensure_package_files(root: Path, apply: bool) -> None:
    for rel, content in PACKAGE_INITS.items():
        path = root / rel
        if path.exists():
            continue
        if apply:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
            print(f"created {path}")
        else:
            print(f"would create {path}")


def rewrite_files(root: Path, apply: bool) -> int:
    changed = 0
    for path in iter_python_files(root):
        src = path.read_text(encoding="utf-8")
        if "d810.backends" not in src and "d810.cfg." not in src:
            continue
        out = rewrite_text(src)
        if out == src:
            continue
        changed += 1
        if apply:
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
    return changed


def move_files(root: Path, apply: bool) -> int:
    moved = 0
    for old_rel, new_rel in FILE_RENAMES.items():
        old = root / old_rel
        new = root / new_rel
        if not old.exists() or new.exists():
            continue
        moved += 1
        if apply:
            new.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(old), str(new))
            print(f"moved {old} -> {new}")
        else:
            print(f"would move {old} -> {new}")
    return moved


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."), help="Repository root")
    parser.add_argument("--apply", action="store_true", help="Apply changes")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = args.root.resolve()
    apply = args.apply

    ensure_package_files(root, apply)
    changed = rewrite_files(root, apply)
    moved = move_files(root, apply)

    mode = "applied" if apply else "dry-run"
    print(f"{mode}: rewrote {changed} file(s), moved {moved} file(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
