#!/usr/bin/env python3
"""Phase 1 codemod: regroup d810.hexrays into hooks/ir/mutation/utils.

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
    # hooks
    "d810.hexrays.hexrays_hooks": "d810.hexrays.hooks.hexrays_hooks",
    "d810.hexrays.ctree_hooks": "d810.hexrays.hooks.ctree_hooks",
    # ir
    "d810.hexrays.portable_cfg": "d810.hexrays.ir.portable_cfg",
    "d810.hexrays.cfg_queries": "d810.hexrays.ir.cfg_queries",
    "d810.hexrays.cfg_utils": "d810.hexrays.ir.cfg_utils",
    "d810.hexrays.block_helpers": "d810.hexrays.ir.block_helpers",
    "d810.hexrays.mop_snapshot": "d810.hexrays.ir.mop_snapshot",
    "d810.hexrays.mop_utils": "d810.hexrays.ir.mop_utils",
    # mutation
    "d810.hexrays.cfg_mutations": "d810.hexrays.mutation.cfg_mutations",
    "d810.hexrays.cfg_verify": "d810.hexrays.mutation.cfg_verify",
    "d810.hexrays.deferred_events": "d810.hexrays.mutation.deferred_events",
    "d810.hexrays.deferred_modifier": "d810.hexrays.mutation.deferred_modifier",
    "d810.hexrays.cfg_pass": "d810.hexrays.mutation.cfg_pass",
    "d810.hexrays.cfg_backend": "d810.hexrays.mutation.cfg_backend",
    "d810.hexrays.pass_pipeline": "d810.hexrays.mutation.pass_pipeline",
    "d810.hexrays.graph_modification": "d810.hexrays.mutation.graph_modification",
    "d810.hexrays.passes": "d810.hexrays.mutation.passes",
    "d810.hexrays.backends.ida_backend": "d810.hexrays.mutation.ida_backend",
    # utils
    "d810.hexrays.hexrays_helpers": "d810.hexrays.utils.hexrays_helpers",
    "d810.hexrays.hexrays_formatters": "d810.hexrays.utils.hexrays_formatters",
    "d810.hexrays.microcode_constants": "d810.hexrays.utils.microcode_constants",
    "d810.hexrays.microcode_dump": "d810.hexrays.utils.microcode_dump",
    "d810.hexrays.ida_utils": "d810.hexrays.utils.ida_utils",
    "d810.hexrays.table_utils": "d810.hexrays.utils.table_utils",
    "d810.hexrays.tracker": "d810.hexrays.utils.tracker",
    "d810.hexrays.arch_utils": "d810.hexrays.utils.arch_utils",
    "d810.hexrays.bst_analysis": "d810.hexrays.utils.bst_analysis",
    "d810.hexrays.emulator": "d810.hexrays.utils.emulator",
}

SYMBOL_RENAMES_FROM_HEXRAYS: dict[str, str] = {
    key.rsplit(".", 1)[-1]: value
    for key, value in MODULE_RENAMES.items()
    if key.startswith("d810.hexrays.") and key.count(".") >= 2
}

FILE_RENAMES: dict[str, str] = {
    # hooks
    "src/d810/hexrays/hexrays_hooks.py": "src/d810/hexrays/hooks/hexrays_hooks.py",
    "src/d810/hexrays/ctree_hooks.py": "src/d810/hexrays/hooks/ctree_hooks.py",
    # ir
    "src/d810/hexrays/portable_cfg.py": "src/d810/hexrays/ir/portable_cfg.py",
    "src/d810/hexrays/cfg_queries.py": "src/d810/hexrays/ir/cfg_queries.py",
    "src/d810/hexrays/cfg_utils.py": "src/d810/hexrays/ir/cfg_utils.py",
    "src/d810/hexrays/block_helpers.py": "src/d810/hexrays/ir/block_helpers.py",
    "src/d810/hexrays/mop_snapshot.py": "src/d810/hexrays/ir/mop_snapshot.py",
    "src/d810/hexrays/mop_utils.py": "src/d810/hexrays/ir/mop_utils.py",
    # mutation
    "src/d810/hexrays/cfg_mutations.py": "src/d810/hexrays/mutation/cfg_mutations.py",
    "src/d810/hexrays/cfg_verify.py": "src/d810/hexrays/mutation/cfg_verify.py",
    "src/d810/hexrays/deferred_events.py": "src/d810/hexrays/mutation/deferred_events.py",
    "src/d810/hexrays/deferred_modifier.py": "src/d810/hexrays/mutation/deferred_modifier.py",
    "src/d810/hexrays/cfg_pass.py": "src/d810/hexrays/mutation/cfg_pass.py",
    "src/d810/hexrays/cfg_backend.py": "src/d810/hexrays/mutation/cfg_backend.py",
    "src/d810/hexrays/pass_pipeline.py": "src/d810/hexrays/mutation/pass_pipeline.py",
    "src/d810/hexrays/graph_modification.py": "src/d810/hexrays/mutation/graph_modification.py",
    "src/d810/hexrays/backends/ida_backend.py": "src/d810/hexrays/mutation/ida_backend.py",
    "src/d810/hexrays/passes/__init__.py": "src/d810/hexrays/mutation/passes/__init__.py",
    "src/d810/hexrays/passes/block_merge.py": "src/d810/hexrays/mutation/passes/block_merge.py",
    "src/d810/hexrays/passes/dead_block_elimination.py": "src/d810/hexrays/mutation/passes/dead_block_elimination.py",
    "src/d810/hexrays/passes/fake_jump_fixer.py": "src/d810/hexrays/mutation/passes/fake_jump_fixer.py",
    "src/d810/hexrays/passes/goto_chain_removal.py": "src/d810/hexrays/mutation/passes/goto_chain_removal.py",
    "src/d810/hexrays/passes/opaque_jump_fixer.py": "src/d810/hexrays/mutation/passes/opaque_jump_fixer.py",
    "src/d810/hexrays/passes/simplify_identical_branch.py": "src/d810/hexrays/mutation/passes/simplify_identical_branch.py",
    # utils
    "src/d810/hexrays/hexrays_helpers.py": "src/d810/hexrays/utils/hexrays_helpers.py",
    "src/d810/hexrays/hexrays_formatters.py": "src/d810/hexrays/utils/hexrays_formatters.py",
    "src/d810/hexrays/microcode_constants.py": "src/d810/hexrays/utils/microcode_constants.py",
    "src/d810/hexrays/microcode_dump.py": "src/d810/hexrays/utils/microcode_dump.py",
    "src/d810/hexrays/ida_utils.py": "src/d810/hexrays/utils/ida_utils.py",
    "src/d810/hexrays/table_utils.py": "src/d810/hexrays/utils/table_utils.py",
    "src/d810/hexrays/tracker.py": "src/d810/hexrays/utils/tracker.py",
    "src/d810/hexrays/arch_utils.py": "src/d810/hexrays/utils/arch_utils.py",
    "src/d810/hexrays/bst_analysis.py": "src/d810/hexrays/utils/bst_analysis.py",
    "src/d810/hexrays/emulator.py": "src/d810/hexrays/utils/emulator.py",
}

NEW_PACKAGE_INITS = [
    "src/d810/hexrays/hooks/__init__.py",
    "src/d810/hexrays/ir/__init__.py",
    "src/d810/hexrays/mutation/__init__.py",
    "src/d810/hexrays/mutation/passes/__init__.py",
    "src/d810/hexrays/utils/__init__.py",
]


def _ordered_module_renames() -> list[tuple[str, str]]:
    return sorted(MODULE_RENAMES.items(), key=lambda kv: len(kv[0]), reverse=True)


def rewrite_dotted_name(name: str) -> str:
    for old, new in _ordered_module_renames():
        if name == old or name.startswith(old + "."):
            return new + name[len(old) :]
    return name


class HexraysPhase1Transformer(cst.CSTTransformer):
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

        # Special case: from d810.hexrays import <symbol>
        if module_code == "d810.hexrays" and not isinstance(updated_node.names, cst.ImportStar):
            aliases = list(updated_node.names)
            grouped: dict[str, list[cst.ImportAlias]] = {}
            for alias in aliases:
                alias_name = cst.Module([]).code_for_node(alias.name)
                target_module = SYMBOL_RENAMES_FROM_HEXRAYS.get(alias_name)
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

        # Regular rewrite for from d810.hexrays.* import ...
        new_module_code = rewrite_dotted_name(module_code)
        if new_module_code != module_code:
            return updated_node.with_changes(
                module=cst.parse_expression(new_module_code)
            )

        return updated_node


def rewrite_text(text: str) -> str:
    module = cst.parse_module(text)
    transformed = module.visit(HexraysPhase1Transformer())
    out = transformed.code

    # Keep docs/comments/strings coherent with module moves.
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
    for rel in NEW_PACKAGE_INITS:
        path = root / rel
        if path.exists():
            continue
        if apply:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('"""Hex-Rays package namespace."""\n', encoding="utf-8")
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
        if "d810.hexrays" not in src:
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".", help="Repo root to scan")
    parser.add_argument("--apply", action="store_true", help="Write changes")
    args = parser.parse_args()

    root = Path(args.root).resolve()

    ensure_package_files(root, args.apply)
    rewrites = rewrite_files(root, args.apply)
    moves = move_files(root, args.apply)

    mode = "applied" if args.apply else "dry-run"
    print(f"{mode}: rewrote {rewrites} file(s), moved {moves} file(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
