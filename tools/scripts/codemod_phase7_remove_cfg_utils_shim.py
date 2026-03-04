#!/usr/bin/env python3
"""Phase 7 codemod: replace cfg_utils imports with concrete modules.

Default mode is dry-run. Use --apply to write changes.
Optional: --delete-shim to remove src/d810/hexrays/ir/cfg_utils.py after rewrite.
Run with: pyenv exec python tools/scripts/codemod_phase7_remove_cfg_utils_shim.py --dry-run
"""

from __future__ import annotations

import argparse
import difflib
from pathlib import Path

import libcst as cst

CFG_UTILS_MODULE = "d810.hexrays.ir.cfg_utils"

SYMBOL_TO_MODULE: dict[str, str] = {
    # cfg_queries
    "is_conditional_jump": "d810.hexrays.ir.cfg_queries",
    "is_indirect_jump": "d810.hexrays.ir.cfg_queries",
    "get_block_serials_by_address": "d810.hexrays.ir.cfg_queries",
    "get_block_serials_by_address_range": "d810.hexrays.ir.cfg_queries",
    "_serial_in_predset": "d810.hexrays.ir.cfg_queries",
    # mop_utils
    "safe_make_number": "d810.hexrays.ir.mop_utils",
    "get_stack_var_name": "d810.hexrays.ir.mop_utils",
    "extract_base_and_offset": "d810.hexrays.ir.mop_utils",
    "_VALID_MOP_SIZES": "d810.hexrays.ir.mop_utils",
    "_get_mba_frame_size": "d810.hexrays.ir.mop_utils",
    "_cached_stack_var_name": "d810.hexrays.ir.mop_utils",
    "_VALNUM_NAME_CACHE": "d810.hexrays.ir.mop_utils",
    # cfg_verify
    "_InterrCatcher": "d810.hexrays.mutation.cfg_verify",
    "safe_verify": "d810.hexrays.mutation.cfg_verify",
    "capture_failure_artifact": "d810.hexrays.mutation.cfg_verify",
    "snapshot_block_for_capture": "d810.hexrays.mutation.cfg_verify",
    "log_block_info": "d810.hexrays.mutation.cfg_verify",
    "_snapshot_insn": "d810.hexrays.mutation.cfg_verify",
    "_collect_related_blocks": "d810.hexrays.mutation.cfg_verify",
    "_json_safe": "d810.hexrays.mutation.cfg_verify",
    # cfg_mutations
    "_rewire_edge": "d810.hexrays.mutation.cfg_mutations",
    "insert_goto_instruction": "d810.hexrays.mutation.cfg_mutations",
    "change_1way_call_block_successor": "d810.hexrays.mutation.cfg_mutations",
    "change_1way_block_successor": "d810.hexrays.mutation.cfg_mutations",
    "change_0way_block_successor": "d810.hexrays.mutation.cfg_mutations",
    "change_2way_block_conditional_successor": "d810.hexrays.mutation.cfg_mutations",
    "update_blk_successor": "d810.hexrays.mutation.cfg_mutations",
    "make_2way_block_goto": "d810.hexrays.mutation.cfg_mutations",
    "create_block": "d810.hexrays.mutation.cfg_mutations",
    "create_standalone_block": "d810.hexrays.mutation.cfg_mutations",
    "update_block_successors": "d810.hexrays.mutation.cfg_mutations",
    "_update_jtbl_case_targets": "d810.hexrays.mutation.cfg_mutations",
    "coalesce_jtbl_cases": "d810.hexrays.mutation.cfg_mutations",
    "retarget_jtbl_block_cases": "d810.hexrays.mutation.cfg_mutations",
    "convert_jtbl_to_goto": "d810.hexrays.mutation.cfg_mutations",
    "_get_fallthrough_successor_serial": "d810.hexrays.mutation.cfg_mutations",
    "insert_nop_blk": "d810.hexrays.mutation.cfg_mutations",
    "ensure_last_block_is_goto": "d810.hexrays.mutation.cfg_mutations",
    "duplicate_block": "d810.hexrays.mutation.cfg_mutations",
    "change_block_address": "d810.hexrays.mutation.cfg_mutations",
    "mba_remove_simple_goto_blocks": "d810.hexrays.mutation.cfg_mutations",
    "mba_deep_cleaning": "d810.hexrays.mutation.cfg_mutations",
    "ensure_child_has_an_unconditional_father": "d810.hexrays.mutation.cfg_mutations",
    "downgrade_nway_null_tail_to_1way": "d810.hexrays.mutation.cfg_mutations",
}


class CfgUtilsImportSplitter(cst.CSTTransformer):
    def leave_SimpleStatementLine(
        self, original_node: cst.SimpleStatementLine, updated_node: cst.SimpleStatementLine
    ) -> cst.BaseStatement | cst.FlattenSentinel[cst.BaseStatement]:
        if len(updated_node.body) != 1:
            return updated_node
        stmt = updated_node.body[0]
        if not isinstance(stmt, cst.ImportFrom):
            return updated_node

        module = stmt.module
        if module is None:
            return updated_node
        module_code = cst.Module([]).code_for_node(module)
        if module_code != CFG_UTILS_MODULE:
            return updated_node
        if isinstance(stmt.names, cst.ImportStar):
            return updated_node

        # Emit one import-per-line to avoid semicolon joins and dangling commas.
        out_lines: list[cst.SimpleStatementLine] = []
        changed = False
        for alias in stmt.names:
            symbol = cst.Module([]).code_for_node(alias.name)
            target_module = SYMBOL_TO_MODULE.get(symbol, CFG_UTILS_MODULE)
            if target_module != CFG_UTILS_MODULE:
                changed = True
            out_stmt = stmt.with_changes(
                module=cst.parse_expression(target_module),
                names=(alias.with_changes(comma=cst.MaybeSentinel.DEFAULT),),
            )
            out_lines.append(cst.SimpleStatementLine(body=(out_stmt,)))

        if not changed:
            return updated_node
        return cst.FlattenSentinel(out_lines)


def rewrite_text(text: str) -> str:
    module = cst.parse_module(text)
    return module.visit(CfgUtilsImportSplitter()).code


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


def rewrite_files(root: Path, apply: bool) -> int:
    changed = 0
    for path in iter_python_files(root):
        src = path.read_text(encoding="utf-8")
        if CFG_UTILS_MODULE not in src:
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


def maybe_delete_shim(root: Path, apply: bool, delete_shim: bool) -> None:
    if not delete_shim:
        return
    shim = root / "src/d810/hexrays/ir/cfg_utils.py"
    if not shim.exists():
        return
    if apply:
        shim.unlink()
        print(f"deleted {shim}")
    else:
        print(f"would delete {shim}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."), help="Repository root")
    parser.add_argument("--apply", action="store_true", help="Apply changes")
    parser.add_argument(
        "--delete-shim",
        action="store_true",
        help="Delete src/d810/hexrays/ir/cfg_utils.py after rewrite",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = args.root.resolve()
    apply = args.apply
    changed = rewrite_files(root, apply)
    maybe_delete_shim(root, apply, args.delete_shim)
    mode = "applied" if apply else "dry-run"
    print(f"{mode}: rewrote {changed} file(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
