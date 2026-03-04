#!/usr/bin/env python3
"""Phase 2 codemod: move pure CFG framework modules from hexrays to d810.cfg.

Default mode is dry-run. Use --apply to write changes and move files.
Run with `pyenv exec` so LibCST is available.
"""

from __future__ import annotations

import argparse
import difflib
import shutil
from pathlib import Path

import libcst as cst


MODULE_RENAMES: dict[str, str] = {
    # Current paths after phase 1
    "d810.hexrays.mutation.cfg_pass": "d810.cfg.passes._base",
    "d810.hexrays.mutation.cfg_backend": "d810.cfg.protocol",
    "d810.hexrays.mutation.pass_pipeline": "d810.cfg.pipeline",
    "d810.hexrays.mutation.graph_modification": "d810.cfg.graph_modification",
    "d810.hexrays.mutation.passes": "d810.cfg.passes",
    "d810.hexrays.utils.microcode_constants": "d810.cfg.microcode_constants",
    # Legacy pre-phase-1 paths (safety)
    "d810.hexrays.cfg_pass": "d810.cfg.passes._base",
    "d810.hexrays.cfg_backend": "d810.cfg.protocol",
    "d810.hexrays.pass_pipeline": "d810.cfg.pipeline",
    "d810.hexrays.graph_modification": "d810.cfg.graph_modification",
    "d810.hexrays.passes": "d810.cfg.passes",
    "d810.hexrays.microcode_constants": "d810.cfg.microcode_constants",
}

SYMBOL_RENAMES: dict[str, str] = {
    key.rsplit(".", 1)[-1]: value for key, value in MODULE_RENAMES.items()
}

FILE_RENAMES: dict[str, str] = {
    "src/d810/hexrays/mutation/cfg_pass.py": "src/d810/cfg/cfg_pass.py",
    "src/d810/hexrays/mutation/cfg_backend.py": "src/d810/cfg/cfg_backend.py",
    "src/d810/hexrays/mutation/pass_pipeline.py": "src/d810/cfg/pass_pipeline.py",
    "src/d810/hexrays/mutation/graph_modification.py": "src/d810/cfg/graph_modification.py",
    "src/d810/hexrays/utils/microcode_constants.py": "src/d810/cfg/microcode_constants.py",
    "src/d810/hexrays/mutation/passes/__init__.py": "src/d810/cfg/passes/__init__.py",
    "src/d810/hexrays/mutation/passes/block_merge.py": "src/d810/cfg/passes/block_merge.py",
    "src/d810/hexrays/mutation/passes/dead_block_elimination.py": "src/d810/cfg/passes/dead_block_elimination.py",
    "src/d810/hexrays/mutation/passes/fake_jump_fixer.py": "src/d810/cfg/passes/fake_jump_fixer.py",
    "src/d810/hexrays/mutation/passes/goto_chain_removal.py": "src/d810/cfg/passes/goto_chain_removal.py",
    "src/d810/hexrays/mutation/passes/opaque_jump_fixer.py": "src/d810/cfg/passes/opaque_jump_fixer.py",
    "src/d810/hexrays/mutation/passes/simplify_identical_branch.py": "src/d810/cfg/passes/simplify_identical_branch.py",
}

NEW_PACKAGE_INITS = [
    "src/d810/cfg/passes/__init__.py",
]


def _ordered_module_renames() -> list[tuple[str, str]]:
    return sorted(MODULE_RENAMES.items(), key=lambda kv: len(kv[0]), reverse=True)


def rewrite_dotted_name(name: str) -> str:
    for old, new in _ordered_module_renames():
        if name == old or name.startswith(old + "."):
            return new + name[len(old) :]
    return name


class Phase2Transformer(cst.CSTTransformer):
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
    ) -> cst.BaseSmallStatement | cst.FlattenSentinel[cst.BaseSmallStatement]:
        module = updated_node.module
        if module is None:
            return updated_node

        module_code = cst.Module([]).code_for_node(module)

        if (
            module_code in {"d810.hexrays", "d810.hexrays.mutation", "d810.hexrays.utils"}
            and not isinstance(updated_node.names, cst.ImportStar)
        ):
            aliases = list(updated_node.names)
            grouped: dict[str, list[cst.ImportAlias]] = {}
            for alias in aliases:
                alias_name = cst.Module([]).code_for_node(alias.name)
                target_module = SYMBOL_RENAMES.get(alias_name)
                if target_module is None:
                    parent_module = module_code
                else:
                    parent_module, symbol = target_module.rsplit(".", 1)
                    alias = alias.with_changes(name=cst.Name(symbol))
                grouped.setdefault(parent_module, []).append(alias)

            if len(grouped) == 1 and module_code in grouped:
                return updated_node

            new_nodes: list[cst.ImportFrom] = []
            for parent_module, group_aliases in grouped.items():
                new_nodes.append(
                    updated_node.with_changes(
                        module=cst.parse_expression(parent_module),
                        names=tuple(group_aliases),
                    )
                )
            if len(new_nodes) == 1:
                return new_nodes[0]
            return cst.FlattenSentinel(new_nodes)

        new_module_code = rewrite_dotted_name(module_code)
        if new_module_code != module_code:
            return updated_node.with_changes(module=cst.parse_expression(new_module_code))

        return updated_node


def rewrite_text(text: str) -> str:
    module = cst.parse_module(text)
    transformed = module.visit(Phase2Transformer())
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
        if not str(p).endswith(".py")
        or "/tools/scripts/codemod_" not in str(p).replace("\\", "/")
        if ".git/" not in str(p)
        and ".venv/" not in str(p)
        and "__pycache__/" not in str(p)
        and "/build/" not in str(p)
        and "/dist/" not in str(p)
    )


def ensure_package_files(root: Path, apply: bool) -> None:
    for rel in NEW_PACKAGE_INITS:
        path = root / rel
        if path.exists():
            continue
        if apply:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('"""CFG pass namespace."""\n', encoding="utf-8")
            print(f"created {path}")
        else:
            print(f"would create {path}")


def move_files(root: Path, apply: bool) -> int:
    moved = 0
    for old_rel, new_rel in FILE_RENAMES.items():
        old = root / old_rel
        new = root / new_rel
        if not old.exists():
            continue
        moved += 1
        if apply:
            new.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(old), str(new))
            print(f"moved {old} -> {new}")
        else:
            print(f"would move {old} -> {new}")
    return moved


def rewrite_files(root: Path, apply: bool) -> int:
    changed = 0
    for path in iter_python_files(root):
        src = path.read_text(encoding="utf-8")
        if "d810.hexrays" not in src and "d810.cfg" not in src:
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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path("."),
        help="Repository root",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply changes (default is dry-run)",
    )
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
