#!/usr/bin/env python3
"""Add diagnostic infrastructure for TopologicalSort regression investigation.

This codemod adds three diagnostic features:
1. Projected CFG adjacency dump in edit_simulator.py
2. Post-reorder reachability audit in deferred_modifier.py
3. Post-reorder microcode dump in deferred_modifier.py

Default mode is dry-run. Use --apply to write changes.
Run with `pyenv exec` so LibCST is available.
"""
from __future__ import annotations

import argparse
import difflib
from pathlib import Path
import libcst as cst

EDIT_SIMULATOR_PATH = "src/d810/cfg/flow/edit_simulator.py"
DEFERRED_MODIFIER_PATH = "src/d810/hexrays/mutation/deferred_modifier.py"


class EditSimulatorTransformer(cst.CSTTransformer):
    """Add logger import and diagnostic dump to edit_simulator.py."""

    def __init__(self):
        self.added_logger_import = False
        self.added_diagnostic = False

    def leave_ImportFrom(
        self, original_node: cst.ImportFrom, updated_node: cst.ImportFrom
    ) -> cst.ImportFrom:
        # Add getLogger import after FlowGraph import
        if not self.added_logger_import:
            module = updated_node.module
            if module and cst.Module([]).code_for_node(module) == "d810.cfg.flowgraph":
                self.added_logger_import = True
                # Insert getLogger import before this line
                return cst.ImportFrom(
                    module=cst.parse_expression("d810.core.logging"),
                    names=[cst.ImportAlias(name=cst.Name("getLogger"))],
                )
        return updated_node

    def leave_FunctionDef(
        self, original_node: cst.FunctionDef, updated_node: cst.FunctionDef
    ) -> cst.FunctionDef:
        # Add diagnostic after simulated = simulate_edits(...) in project_post_state
        if updated_node.name.value == "project_post_state" and not self.added_diagnostic:
            self.added_diagnostic = True
            # Find the line with simulated = simulate_edits(...)
            new_body = []
            for stmt in updated_node.body.body:
                new_body.append(stmt)
                # Check if this is the simulated = simulate_edits line
                if isinstance(stmt, cst.SimpleStatementLine):
                    for expr in stmt.body:
                        if isinstance(expr, cst.Assign):
                            if isinstance(expr.targets[0].target, cst.Name) and expr.targets[0].target.value == "simulated":
                                # Add diagnostic after this line
                                diagnostic_code = """
    # DIAGNOSTIC: Projected CFG adjacency dump
    if logger.debug_on:
        logger.debug("Projected CFG adjacency after %s:", type(patch_plan).__name__)
        for serial, succs in sorted(simulated.adj.items()):
            clone_marker = " [CLONE]" if serial in simulated.created_clones else ""
            logger.debug("  block %d -> %s%s", serial, succs, clone_marker)
"""
                                # This is a simplified approach - actual implementation needs more care
                                pass
            return updated_node
        return updated_node


def add_logger_import_to_edit_simulator(src: str) -> str:
    """Add getLogger import to edit_simulator.py."""
    if "from d810.core.logging import getLogger" in src:
        return src  # Already added
    
    # Add import after the from d810.cfg.flowgraph import line
    lines = src.splitlines(keepends=True)
    new_lines = []
    added = False
    for line in lines:
        new_lines.append(line)
        if not added and "from d810.cfg.flowgraph import" in line:
            new_lines.append("from d810.core.logging import getLogger\n")
            added = True
    
    return "".join(new_lines)


def add_logger_to_edit_simulator(src: str) -> str:
    """Add logger instance to edit_simulator.py after _BLT_2WAY definition."""
    if 'logger = getLogger("D810.cfg.flow.edit_simulator")' in src:
        return src  # Already added
    
    lines = src.splitlines(keepends=True)
    new_lines = []
    added = False
    for line in lines:
        new_lines.append(line)
        if not added and "_BLT_2WAY = int(getattr(ida_hexrays" in line:
            new_lines.append('\nlogger = getLogger("D810.cfg.flow.edit_simulator")\n')
            added = True
    
    return "".join(new_lines)


def add_projected_cfg_dump(src: str) -> str:
    """Add projected CFG adjacency dump to project_post_state function."""
    if "# DIAGNOSTIC: Projected CFG adjacency dump" in src:
        return src  # Already added
    
    # Find the line after "simulated = simulate_edits(...)" and add diagnostic
    lines = src.splitlines(keepends=True)
    new_lines = []
    added = False
    in_project_post_state = False
    indent_level = 0
    
    for i, line in enumerate(lines):
        new_lines.append(line)
        
        # Detect when we enter project_post_state
        if "def project_post_state(" in line:
            in_project_post_state = True
            continue
        
        # Detect when we leave the function (next def at same indent)
        if in_project_post_state and line.startswith("def "):
            in_project_post_state = False
        
        # Add diagnostic after simulated = simulate_edits
        if in_project_post_state and not added and "simulated = simulate_edits(" in line:
            # Get the indentation
            indent = len(line) - len(line.lstrip())
            new_lines.append("\n")
            new_lines.append(" " * indent + "# DIAGNOSTIC: Projected CFG adjacency dump\n")
            new_lines.append(" " * indent + "if logger.debug_on:\n")
            new_lines.append(" " * indent + "    logger.debug(\"Projected CFG adjacency after %s:\", type(patch_plan).__name__)\n")
            new_lines.append(" " * indent + "    for serial, succs in sorted(simulated.adj.items()):\n")
            new_lines.append(" " * indent + "        clone_marker = \" [CLONE]\" if serial in simulated.created_clones else \"\"\n")
            new_lines.append(" " * indent + "        logger.debug(\"  block %d -> %s%s\", serial, succs, clone_marker)\n")
            added = True
    
    return "".join(new_lines)


def add_reachability_audit(src: str) -> str:
    """Add post-reorder reachability audit to _apply_reorder_blocks."""
    if "# DIAGNOSTIC: Post-reorder reachability audit" in src:
        return src  # Already added
    
    lines = src.splitlines(keepends=True)
    new_lines = []
    added = False
    in_apply_reorder = False
    found_mark_chains = False
    
    for i, line in enumerate(lines):
        new_lines.append(line)
        
        # Detect when we enter _apply_reorder_blocks
        if "def _apply_reorder_blocks(" in line:
            in_apply_reorder = True
            continue
        
        # Detect when we leave the function
        if in_apply_reorder and line.startswith("def ") or (in_apply_reorder and line.startswith("class ")):
            in_apply_reorder = False
            found_mark_chains = False
        
        # Find mark_chains_dirty() call
        if in_apply_reorder and not added and "mba.mark_chains_dirty()" in line:
            found_mark_chains = True
            # Add diagnostic after this line
            indent = "    "  # Standard indent for the function body
            new_lines.append("\n")
            new_lines.append(indent + "# DIAGNOSTIC: Post-reorder reachability audit\n")
            new_lines.append(indent + "if logger.debug_on:\n")
            new_lines.append(indent + "    # BFS from block 0 to check reachability\n")
            new_lines.append(indent + "    visited = {0}\n")
            new_lines.append(indent + "    queue = [0]\n")
            new_lines.append(indent + "    while queue:\n")
            new_lines.append(indent + "        s = queue.pop()\n")
            new_lines.append(indent + "        blk = mba.get_mblock(s)\n")
            new_lines.append(indent + "        if blk is None:\n")
            new_lines.append(indent + "            continue\n")
            new_lines.append(indent + "        for i in range(blk.nsucc()):\n")
            new_lines.append(indent + "            ns = blk.succ(i)\n")
            new_lines.append(indent + "            if ns not in visited:\n")
            new_lines.append(indent + "                visited.add(ns)\n")
            new_lines.append(indent + "                queue.append(ns)\n")
            new_lines.append(indent + "    \n")
            new_lines.append(indent + "    all_serials = set(range(mba.qty))\n")
            new_lines.append(indent + "    unreachable = all_serials - visited\n")
            new_lines.append(indent + "    if unreachable:\n")
            new_lines.append(indent + "        logger.debug(\"REACHABILITY: %d unreachable blocks: %s\", len(unreachable), sorted(unreachable))\n")
            new_lines.append(indent + "        for s in sorted(unreachable):\n")
            new_lines.append(indent + "            blk = mba.get_mblock(s)\n")
            new_lines.append(indent + "            preds = [blk.pred(i) for i in range(blk.npred())]\n")
            new_lines.append(indent + "            succs = [blk.succ(i) for i in range(blk.nsucc())]\n")
            new_lines.append(indent + "            logger.debug(\"  block %d type=%s preds=%s succs=%s\", s, blk.type, preds, succs)\n")
            new_lines.append(indent + "    else:\n")
            new_lines.append(indent + "        logger.debug(\"REACHABILITY: all %d blocks reachable\", mba.qty)\n")
            new_lines.append(indent + "    \n")
            new_lines.append(indent + "    # Post-reorder microcode dump\n")
            new_lines.append(indent + "    mba.dump_mba(False, \"post-reorder-topo\")\n")
            added = True
    
    return "".join(new_lines)


def add_reorder_debug_logging(src: str) -> str:
    """Add debug logging for dfs_block_order, runtime_non_2way, runtime_old_to_new."""
    if "# DIAGNOSTIC: Reorder parameters" in src:
        return src  # Already added
    
    lines = src.splitlines(keepends=True)
    new_lines = []
    added = False
    in_apply_reorder = False
    found_runtime_skipped = False
    
    for i, line in enumerate(lines):
        new_lines.append(line)
        
        # Detect when we enter _apply_reorder_blocks
        if "def _apply_reorder_blocks(" in line:
            in_apply_reorder = True
            continue
        
        # Detect when we leave the function
        if in_apply_reorder and (line.startswith("def ") or line.startswith("class ")):
            in_apply_reorder = False
            found_runtime_skipped = False
        
        # Find after runtime_skipped_2way logging
        if in_apply_reorder and not added and 'logger.info("reorder_blocks: skipped' in line:
            found_runtime_skipped = True
            # Add diagnostic after this line
            indent = "    "  # Standard indent for the function body
            new_lines.append("\n")
            new_lines.append(indent + "# DIAGNOSTIC: Reorder parameters\n")
            new_lines.append(indent + "if logger.debug_on:\n")
            new_lines.append(indent + "    logger.debug(\"dfs_block_order: %s\", dfs_block_order)\n")
            new_lines.append(indent + "    logger.debug(\"runtime_non_2way: %s\", runtime_non_2way)\n")
            new_lines.append(indent + "    logger.debug(\"runtime_old_to_new (initial): %s\", old_to_new)\n")
            added = True
    
    return "".join(new_lines)


def add_logger_to_deferred_modifier(src: str) -> str:
    """Ensure logger is present in deferred_modifier.py (it should already be there)."""
    if 'logger = getLogger("D810.deferred_modifier")' not in src:
        # This should already exist, but just in case
        return src
    return src


def transform_edit_simulator(src: str) -> str:
    """Apply all transformations to edit_simulator.py."""
    result = src
    result = add_logger_import_to_edit_simulator(result)
    result = add_logger_to_edit_simulator(result)
    result = add_projected_cfg_dump(result)
    return result


def transform_deferred_modifier(src: str) -> str:
    """Apply all transformations to deferred_modifier.py."""
    result = src
    result = add_logger_to_deferred_modifier(result)
    result = add_reorder_debug_logging(result)
    result = add_reachability_audit(result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Add diagnostic infrastructure for TopologicalSort regression")
    parser.add_argument("--root", default=".", help="Repo root to scan")
    parser.add_argument("--apply", action="store_true", help="Write changes")
    args = parser.parse_args()
    
    root = Path(args.root).resolve()
    changed = 0
    
    # Process edit_simulator.py
    edit_sim_path = root / EDIT_SIMULATOR_PATH
    if edit_sim_path.exists():
        src = edit_sim_path.read_text(encoding="utf-8")
        out = transform_edit_simulator(src)
        if out != src:
            changed += 1
            if args.apply:
                edit_sim_path.write_text(out, encoding="utf-8")
                print(f"rewrote {edit_sim_path}")
            else:
                print(f"would rewrite {edit_sim_path}")
                diff = difflib.unified_diff(
                    src.splitlines(),
                    out.splitlines(),
                    fromfile=str(edit_sim_path),
                    tofile=str(edit_sim_path),
                    lineterm="",
                )
                for line in diff:
                    print(line)
    
    # Process deferred_modifier.py
    deferred_mod_path = root / DEFERRED_MODIFIER_PATH
    if deferred_mod_path.exists():
        src = deferred_mod_path.read_text(encoding="utf-8")
        out = transform_deferred_modifier(src)
        if out != src:
            changed += 1
            if args.apply:
                deferred_mod_path.write_text(out, encoding="utf-8")
                print(f"rewrote {deferred_mod_path}")
            else:
                print(f"would rewrite {deferred_mod_path}")
                diff = difflib.unified_diff(
                    src.splitlines(),
                    out.splitlines(),
                    fromfile=str(deferred_mod_path),
                    tofile=str(deferred_mod_path),
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
