#!/usr/bin/env python3
"""
d810_debug: consolidated diagnostic CLI for D810 deobfuscation.

Subcommands:
  - capture        : capture before/after pseudocode into a shared SQLite DB
  - compare        : single-function baseline vs D810 unified diff (no DB)
  - bisect         : identify a failing rule for a function
  - dump           : dump before/after pseudocode and rule stats
  - list           : list captured functions from the capture DB
  - show           : show captured before/after pseudocode from the capture DB
  - diff           : show unified/side-by-side diffs from the capture DB
  - summary        : high-level summary of captured functions
  - run-pytest     : run DSL system tests with --capture-to-db
  - pytest-results : show results from the runtime test_results DB

All IDA-using commands run in-process via idapro.open_database/close_database.

Examples (from repo root):

  # Compare a single function without touching the capture DB
  python3 tools/d810_debug.py compare --func test_xor --binary samples/bins/libobfuscated.dylib

  # Capture a couple of functions into the shared DB (uses D810_CAPTURE_DB or .d810_capture.db)
  python3 tools/d810_debug.py capture --functions test_xor --functions test_or

  # Show diffs for all captured functions in unified format
  python3 tools/d810_debug.py diff

  # Run the DSL system tests with --capture-to-db and then inspect their results
  python3 tools/d810_debug.py run-pytest
  python3 tools/d810_debug.py pytest-results

Environment variables:
  D810_TEST_BINARY  : default binary name/path if --binary is not given
  D810_CAPTURE_DB   : default capture DB path if --db is not given
  D810_NO_CYTHON    : set to 1 (or use --no-cython) to disable Cython speedups
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from d810.core.typing import Any, Iterable, Optional, List, Tuple
from d810.testing.capture_db import (
    FUNCTION_TO_DSL_TESTS,
    OVERLAPPING_FUNCTIONS,
    capture_one_function,
    get_default_binary_name,
    get_func_ea,
    init_capture_db,
    resolve_capture_db_path,
    side_by_side_diff,
    strip_colors,
    unified_diff,
)


def _apply_no_cython_flag(no_cython: bool) -> None:
    """
    Ensure D810_NO_CYTHON is set before importing d810 modules.
    """
    if no_cython:
        os.environ.setdefault("D810_NO_CYTHON", "1")


def _resolve_binary_path(binary_arg: Optional[str]) -> Path:
    """
    Resolve the binary path using:
    1. Explicit --binary
    2. D810_TEST_BINARY
    3. Platform default name (libobfuscated.*)
       searched under samples/bins, tests/_resources/bin, tests/system/bins
    """
    if binary_arg:
        return Path(binary_arg)

    binary_name = get_default_binary_name()

    tests_dir = PROJECT_ROOT / "tests" / "system"
    possible_paths = [
        PROJECT_ROOT / "samples" / "bins" / binary_name,
        PROJECT_ROOT / "tests" / "_resources" / "bin" / binary_name,
        tests_dir / "bins" / binary_name,
    ]
    for p in possible_paths:
        if p.exists():
            return p

    # Fallback to bare name; let idapro.open_database complain if invalid.
    return Path(binary_name)


@contextmanager
def _open_ida_database(binary_path: Path):
    """
    Open an IDA database via idapro and ensure it is closed afterwards.
    """
    try:
        import idapro
        import idaapi
    except ImportError as e:  # pragma: no cover - requires IDA
        print(
            f"ERROR: idapro/idaapi modules not available ({e}). "
            "Run this tool inside IDA or with idalib."
        )
        raise SystemExit(1)

    result = idapro.open_database(str(binary_path), run_auto_analysis=True)
    if result != 0:
        print(f"ERROR: Failed to open database for {binary_path} (result={result})")
        raise SystemExit(1)

    idaapi.auto_wait()
    try:
        yield
    finally:  # pragma: no cover - requires IDA
        try:
            idapro.close_database()
        except Exception:
            pass


def _ensure_hexrays() -> None:
    import idaapi

    if not idaapi.init_hexrays_plugin():  # pragma: no cover - requires Hex-Rays
        print("ERROR: Hex-Rays decompiler not available")
        raise SystemExit(1)


def _load_d810_state() -> Any:
    """
    Load D810State singleton with GUI disabled.
    """
    from d810.manager import D810State

    state = D810State()
    if not state.is_loaded():
        state.load(gui=False)
    return state


def _try_decompile(func_ea):
    """
    Decompile a function and return (pseudocode_str_or_None, status_string).
    """
    import idaapi

    try:
        res = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
        if res is None:
            return None, "FAILED (None)"
        return str(res), "OK"
    except Exception as e:  # pragma: no cover - defensive
        return None, f"CRASH ({e})"


def cmd_compare(args: argparse.Namespace) -> None:
    """
    Compare baseline vs D810 pseudocode for a single function and print a diff.
    """
    binary_path = _resolve_binary_path(args.binary)
    _apply_no_cython_flag(args.no_cython)

    with _open_ida_database(binary_path):
        import idaapi

        _ensure_hexrays()
        state = _load_d810_state()

        func_ea = get_func_ea(args.func)
        if func_ea == idaapi.BADADDR:
            print(f"ERROR: Function '{args.func}' not found")
            return

        print(f"[*] Analyzing {hex(func_ea)} in {binary_path}")

        # Baseline
        state.stop_d810()
        base_code, status = _try_decompile(func_ea)
        print(f"[*] Baseline status: {status}")

        # D810
        if args.config:
            try:
                p_idx = state.project_manager.index(args.config)
                state.load_project(p_idx)
            except Exception as e:
                print(f"WARNING: Could not load config {args.config}: {e}")

        state.start_d810()
        d810_code, status = _try_decompile(func_ea)
        print(f"[*] D810 status: {status}")

        if not base_code or not d810_code:
            return

        if base_code == d810_code:
            print("[=] No changes detected.")
            return

        print("[+] Changes detected. Unified diff:")
        diff = unified_diff(base_code, d810_code, args.func)
        if diff:
            print(diff)


def _bisect_rules(func_ea, state, rule_type, rule_list):
    """
    Linear search for a single rule that reproduces a failure.
    """

    def check(subset: List[Any]) -> bool:
        if rule_type == "instruction":
            state.manager.instruction_optimizer_rules = subset
        else:
            state.manager.block_optimizer.cfg_rules = subset
        _, status = _try_decompile(func_ea)
        return status != "OK"

    for i, rule in enumerate(rule_list):
        print(f"    Testing rule {i + 1}/{len(rule_list)}: {rule.name}...", end="\r")
        if check([rule]):
            print(f"\n    [!] Rule {rule.name} fails in isolation.")
            return rule
    return None


def cmd_bisect(args: argparse.Namespace) -> None:
    """
    IDA-in-process rule bisector for a single function.
    """
    binary_path = _resolve_binary_path(args.binary)
    _apply_no_cython_flag(args.no_cython)

    with _open_ida_database(binary_path):
        import idaapi

        _ensure_hexrays()
        state = _load_d810_state()

        func_ea = get_func_ea(args.func)
        if func_ea == idaapi.BADADDR:
            print(f"ERROR: Function '{args.func}' not found")
            return

        if args.config:
            try:
                p_idx = state.project_manager.index(args.config)
                state.load_project(p_idx)
            except Exception as e:
                print(f"WARNING: Could not load config {args.config}: {e}")

        state.start_d810()

        _, status = _try_decompile(func_ea)
        if status == "OK":
            print(
                "[!] Function decompiles successfully with current config; "
                "nothing to bisect."
            )
            return

        print(f"[*] Starting bisect for failure: {status}")
        original_ins = list(state.manager.instruction_optimizer_rules)
        original_blk = list(state.manager.block_optimizer.cfg_rules)
        print(
            f"[*] Active rules: {len(original_ins)} instruction, "
            f"{len(original_blk)} block"
        )

        # First, drop all block rules.
        state.manager.block_optimizer.cfg_rules = []
        _, status = _try_decompile(func_ea)
        if status != "OK":
            print(
                "[*] Failure persists with NO block rules. "
                "Bisecting instruction rules..."
            )
            culprit = _bisect_rules(func_ea, state, "instruction", original_ins)
        else:
            print("[*] Works without block rules. Bisecting block rules...")
            state.manager.block_optimizer.cfg_rules = original_blk
            culprit = _bisect_rules(func_ea, state, "block", original_blk)

        if culprit:
            print(f"\n[!] CULPRIT FOUND: {culprit.name}")
        else:
            print(
                "\n[?] Could not isolate a single culprit. "
                "Failure may require rule interactions."
            )


def cmd_capture(args: argparse.Namespace) -> None:
    """
    Capture before/after pseudocode into the shared capture DB.
    """
    binary_path = _resolve_binary_path(args.binary)
    db_path = resolve_capture_db_path(args.db)
    _apply_no_cython_flag(args.no_cython)

    funcs: List[Tuple[str, Optional[str]]]
    if args.functions:
        funcs = []
        for raw in args.functions:
            for name in raw.split(","):
                name = name.strip()
                if name:
                    funcs.append((name, args.config))
    else:
        funcs = OVERLAPPING_FUNCTIONS

    with _open_ida_database(binary_path):
        import idaapi

        _ensure_hexrays()
        state = _load_d810_state()
        conn = init_capture_db(db_path)
        binary_name = Path(binary_path).name

        print(f"[*] Capturing {len(funcs)} function(s) into {db_path}")

        for func_name, project_cfg in funcs:
            func_ea = get_func_ea(func_name)
            if func_ea == idaapi.BADADDR:
                print(f"  SKIP: Function '{func_name}' not found")
                continue

            if args.config and not project_cfg:
                project_cfg = args.config

            if project_cfg:
                try:
                    idx = state.project_manager.index(project_cfg)
                    state.load_project(idx)
                except Exception as e:
                    print(f"  WARN: could not load project {project_cfg}: {e}")

            print(f"  Capturing {func_name} @ {hex(func_ea)}")
            try:
                summary = capture_one_function(
                    state=state,
                    func_name=func_name,
                    func_ea=func_ea,
                    project_config=project_cfg,
                    conn=conn,
                    binary_name=binary_name,
                )
            except Exception as e:
                print(f"  ERROR: capture failed for {func_name}: {e}")
                continue

            changed = summary["code_changed"]
            rules = summary["rules_fired"]
            print(
                f"    changed={changed} rules={len(rules)} "
                f"{', '.join(rules[:5])}{'...' if len(rules) > 5 else ''}"
            )


def cmd_dump(args: argparse.Namespace) -> None:
    """
    Dump before/after pseudocode and D810 rule stats for one or more functions.
    """
    from d810.core.stats import _maturity_name  # type: ignore[attr-defined]

    binary_path = _resolve_binary_path(args.binary)
    _apply_no_cython_flag(args.no_cython)

    raw = args.functions or ""
    names = [n.strip() for n in raw.split(",") if n.strip()]
    if not names:
        print("ERROR: --functions must specify at least one function name")
        raise SystemExit(1)

    with _open_ida_database(binary_path):
        import idaapi

        _ensure_hexrays()
        state = _load_d810_state()

        if args.project:
            try:
                idx = state.project_manager.index(args.project)
                state.load_project(idx)
            except Exception as e:
                print(f"WARNING: could not load project {args.project}: {e}")

        binary_name = Path(binary_path).name

        for func_name in names:
            func_ea = get_func_ea(func_name)
            if func_ea == idaapi.BADADDR:
                print(f"ERROR: Function '{func_name}' not found")
                continue

            state.stop_d810()
            before = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            if before is None:
                print(f"ERROR: Failed to decompile '{func_name}' without D810")
                continue
            code_before = before.get_pseudocode()

            state.stats.reset()
            state.start_d810()
            after = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            if after is None:
                print(f"ERROR: Failed to decompile '{func_name}' with D810")
                continue
            code_after = after.get_pseudocode()

            from d810.testing.capture_db import pseudocode_to_string

            before_s = pseudocode_to_string(code_before)
            after_s = pseudocode_to_string(code_after)

            rules_fired = state.stats.get_fired_rule_names()
            block_rules_fired = sorted(
                name
                for name, counts in state.stats.cfg_rule_usages.items()
                if any(c > 0 for c in counts)
            )

            def _insn_note(rule_name: str) -> str:
                mat = state.stats.maturity_rule_usages.get(rule_name)
                if not mat:
                    return ""
                parts = [f"@{_maturity_name(m)}:{c}" for m, c in sorted(mat.items())]
                return " [" + ", ".join(parts) + "]"

            def _cfg_note(rule_name: str) -> str:
                mat = state.stats.maturity_cfg_rule_usages.get(rule_name)
                if not mat:
                    return ""
                parts = [
                    f"@{_maturity_name(m)}:{sum(p)}p" for m, p in sorted(mat.items())
                ]
                return " [" + ", ".join(parts) + "]"

            print("\n" + "=" * 88)
            print(f"FUNCTION: {func_name} @ {hex(func_ea)}")
            print(f"BINARY: {binary_name}")
            print(f"PROJECT: {args.project or '<none>'}")
            print(f"CODE_CHANGED: {before_s != after_s}")

            if rules_fired:
                print("RULES_FIRED (instruction):")
                for r in rules_fired:
                    print(f"  {r}{_insn_note(r)}")
            else:
                print("RULES_FIRED (instruction): <none>")

            if block_rules_fired:
                print("RULES_FIRED (block):")
                for r in block_rules_fired:
                    print(f"  {r}{_cfg_note(r)}")
            else:
                print("RULES_FIRED (block): <none>")

            print("\n--- BEFORE ---")
            print(before_s)
            print("\n--- AFTER ---")
            print(after_s)
            print("=" * 88)


def _open_capture_db(db_arg: Optional[str]):
    import sqlite3

    db_path = resolve_capture_db_path(db_arg)
    conn = init_capture_db(db_path)
    conn.row_factory = sqlite3.Row
    return conn, db_path


def cmd_list(args: argparse.Namespace) -> None:
    import sqlite3

    conn, db_path = _open_capture_db(args.db)
    try:
        cur = conn.execute(
            """
            SELECT function_name, code_changed, function_address, rules_fired
            FROM pseudocode_capture
            ORDER BY function_name
            """
        )
        rows = cur.fetchall()
        if not rows:
            print(f"No capture rows in {db_path}")
            return

        print(
            f"{'Function':<40} {'Changed':<10} {'Address':<18} "
            f"{'Rules (sample)'}"
        )
        print("-" * 100)
        for row in rows:
            rules = json.loads(row["rules_fired"]) if row["rules_fired"] else []
            rules_str = ", ".join(rules[:3]) + ("..." if len(rules) > 3 else "")
            print(
                f"{row['function_name']:<40} "
                f"{bool(row['code_changed']):<10} "
                f"{row['function_address']:<18} "
                f"{rules_str}"
            )
    finally:
        conn.close()


def cmd_show(args: argparse.Namespace) -> None:
    import sqlite3

    conn, db_path = _open_capture_db(args.db)
    try:
        if args.function:
            cur = conn.execute(
                """
                SELECT * FROM pseudocode_capture
                WHERE function_name = ?
                """,
                (args.function,),
            )
        else:
            cur = conn.execute(
                """
                SELECT * FROM pseudocode_capture
                ORDER BY function_name
                """
            )
        rows = cur.fetchall()
        if not rows:
            print(f"No capture rows in {db_path}")
            return

        for row in rows:
            print("\n" + "=" * 80)
            print(f"FUNCTION: {row['function_name']} @ {row['function_address']}")
            print(f"Binary: {row['binary_name']}")
            print(f"Project Config: {row['project_config'] or 'None'}")
            print(f"Code Changed: {bool(row['code_changed'])}")

            rules = json.loads(row["rules_fired"]) if row["rules_fired"] else []
            if rules:
                print(f"\nRules Fired ({len(rules)}):")
                for r in rules:
                    print(f"  - {r}")

            print("\n--- BEFORE DEOBFUSCATION ---")
            print(strip_colors(row["code_before"]) if row["code_before"] else "N/A")
            print("\n--- AFTER DEOBFUSCATION ---")
            print(strip_colors(row["code_after"]) if row["code_after"] else "N/A")
    finally:
        conn.close()


def cmd_diff(args: argparse.Namespace) -> None:
    import sqlite3

    conn, db_path = _open_capture_db(args.db)
    try:
        if args.function:
            cur = conn.execute(
                """
                SELECT * FROM pseudocode_capture
                WHERE function_name = ?
                """,
                (args.function,),
            )
            rows = cur.fetchall()
        else:
            cur = conn.execute(
                """
                SELECT * FROM pseudocode_capture
                ORDER BY function_name
                """
            )
            rows = cur.fetchall()

        if not rows:
            print(f"No capture rows in {db_path}")
            return

        for row in rows:
            func = row["function_name"]
            print("\n" + "=" * 100)
            print(f"FUNCTION: {func} @ {row['function_address']}")
            print("=" * 100)

            if args.summary:
                rules = json.loads(row["rules_fired"]) if row["rules_fired"] else []
                before_len = len(strip_colors(row["code_before"]).splitlines()) if row["code_before"] else 0
                after_len = len(strip_colors(row["code_after"]).splitlines()) if row["code_after"] else 0
                print(f"Changed: {bool(row['code_changed'])}")
                print(f"Lines: {before_len} -> {after_len}")
                print(f"Rules fired: {len(rules)}")
                continue

            if args.compact:
                before_len = len(strip_colors(row["code_before"]).splitlines()) if row["code_before"] else 0
                after_len = len(strip_colors(row["code_after"]).splitlines()) if row["code_after"] else 0
                print(f"Code size: {before_len} lines -> {after_len} lines")
                continue

            before = row["code_before"] or ""
            after = row["code_after"] or ""

            if args.mode == "unified":
                diff = unified_diff(before, after, func)
                if diff:
                    print(diff)
                else:
                    print("(no changes)")
            else:
                print(side_by_side_diff(before, after, width=args.width))
    finally:
        conn.close()


def cmd_summary(args: argparse.Namespace) -> None:
    import sqlite3

    conn, db_path = _open_capture_db(args.db)
    try:
        cur = conn.execute(
            """
            SELECT function_name,
                   code_changed,
                   LENGTH(code_before) AS before_len,
                   LENGTH(code_after) AS after_len,
                   rules_fired
            FROM pseudocode_capture
            ORDER BY function_name
            """
        )
        rows = cur.fetchall()
        if not rows:
            print(f"No capture rows in {db_path}")
            return

        print("\n" + "=" * 120)
        print("DEOBFUSCATION SUMMARY")
        print("=" * 120)
        print(
            f"\n{'Function':<35} {'Changed':<8} "
            f"{'Before':<10} {'After':<10} {'Rules':<6} {'DSL Test Classes'}"
        )
        print("-" * 120)

        total_changed = 0
        total_funcs = 0

        for row in rows:
            func = row["function_name"]
            changed = bool(row["code_changed"])
            before_len = row["before_len"] or 0
            after_len = row["after_len"] or 0
            rules = json.loads(row["rules_fired"]) if row["rules_fired"] else []

            total_funcs += 1
            if changed:
                total_changed += 1

            dsl_classes = ", ".join(FUNCTION_TO_DSL_TESTS.get(func, ["N/A"]))
            print(
                f"{func:<35} "
                f"{str(changed):<8} "
                f"{before_len:<10} "
                f"{after_len:<10} "
                f"{len(rules):<6} "
                f"{dsl_classes}"
            )

        print("-" * 120)
        pct = (total_changed / total_funcs * 100.0) if total_funcs else 0.0
        print(
            f"\nTotal: {total_funcs} functions, "
            f"{total_changed} changed ({pct:.0f}%)"
        )
    finally:
        conn.close()


def cmd_run_pytest(args: argparse.Namespace) -> None:
    """
    Run the DSL system tests with --capture-to-db enabled.
    """
    # Keep the filter list consistent with tests/system/run_comparison.py.
    test_functions = [
        "test_chained_add",
        "test_cst_simplification",
        "test_opaque_predicate",
        "test_xor",
        "test_or",
        "test_and",
        "test_neg",
        "tigress_minmaxarray",
        "unwrap_loops",
        "unwrap_loops_2",
        "unwrap_loops_3",
        "while_switch_flattened",
        "test_function_ollvm_fla_bcf_sub",
    ]
    func_filter = " or ".join(test_functions)

    cmd = [
        sys.executable,
        "-m",
        "pytest",
        "tests/system/e2e/test_libdeobfuscated_dsl.py",
        "--capture-to-db",
        "-v",
        "--tb=short",
        "-k",
        func_filter,
    ]

    print("Running pytest with capture-to-db:")
    print("  " + " ".join(cmd))
    result = subprocess.run(cmd, cwd=str(PROJECT_ROOT))
    raise SystemExit(result.returncode)


def cmd_pytest_results(args: argparse.Namespace) -> None:
    """
    Show DSL test results from the runtime test_results database.
    """
    from tests.system.runtime.test_capture import DB_PATH, TestResultQuery

    if not DB_PATH.exists():
        print("ERROR: No test_results DB found. Run run-pytest first.")
        raise SystemExit(1)

    with TestResultQuery(DB_PATH) as query:
        functions = query.list_functions()
        print(
            f"{'Function':<40} {'Suites':<3} {'Runs':<5} "
            f"{'Passed':<6} {'Test Suites'}"
        )
        print("=" * 100)
        for func in functions:
            print(
                f"{func['function_name']:<40} "
                f"{func['suite_count']:<3} "
                f"{func['total_runs']:<5} "
                f"{func['passed_runs']:<6} "
                f"{func['test_suites']}"
            )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="D810 consolidated debug CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Common IDA-using options (added per-command).
    def add_ida_common(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "--binary",
            help=(
                "Binary path/name. Defaults to D810_TEST_BINARY or "
                "libobfuscated.dylib/libobfuscated.dll resolved via system paths."
            ),
        )
        p.add_argument(
            "--no-cython",
            action="store_true",
            help="Set D810_NO_CYTHON=1 before importing d810 to disable Cython.",
        )

    # capture
    p_capture = subparsers.add_parser(
        "capture",
        help="Capture before/after pseudocode into the shared SQLite DB.",
    )
    add_ida_common(p_capture)
    p_capture.add_argument(
        "--db",
        help="Capture DB path (default: D810_CAPTURE_DB or project root /.d810_capture.db).",
    )
    p_capture.add_argument(
        "--functions",
        action="append",
        help=(
            "Function name(s) to capture. Can be specified multiple times or as a "
            "comma-separated list. Defaults to the shared OVERLAPPING_FUNCTIONS set."
        ),
    )
    p_capture.add_argument(
        "--config",
        help="Optional D810 project config name/path applied to functions without an explicit mapping.",
    )

    # compare
    p_compare = subparsers.add_parser(
        "compare", help="Compare baseline vs D810 pseudocode for a single function."
    )
    add_ida_common(p_compare)
    p_compare.add_argument(
        "--func",
        required=True,
        help="Function name or 0x... address.",
    )
    p_compare.add_argument(
        "--config",
        help="Optional D810 project configuration name/path.",
    )

    # bisect
    p_bisect = subparsers.add_parser(
        "bisect",
        help="Bisect rules to find a culprit for a failing decompilation.",
    )
    add_ida_common(p_bisect)
    p_bisect.add_argument(
        "--func",
        required=True,
        help="Function name or 0x... address.",
    )
    p_bisect.add_argument(
        "--config",
        help="Optional D810 project configuration name/path.",
    )

    # dump
    p_dump = subparsers.add_parser(
        "dump",
        help="Dump before/after pseudocode and rule stats for one or more functions.",
    )
    add_ida_common(p_dump)
    p_dump.add_argument(
        "--functions",
        required=True,
        help="Comma-separated list of function names.",
    )
    p_dump.add_argument(
        "--project",
        help="Optional D810 project configuration name/path.",
    )

    # list
    p_list = subparsers.add_parser(
        "list",
        help="List captured functions from the capture DB.",
    )
    p_list.add_argument(
        "--db",
        help="Capture DB path (default: D810_CAPTURE_DB or project root /.d810_capture.db).",
    )

    # show
    p_show = subparsers.add_parser(
        "show",
        help="Show captured before/after pseudocode from the capture DB.",
    )
    p_show.add_argument(
        "--db",
        help="Capture DB path (default: D810_CAPTURE_DB or project root /.d810_capture.db).",
    )
    p_show.add_argument(
        "--function",
        help="Specific function name. If omitted, all functions are shown.",
    )

    # diff
    p_diff = subparsers.add_parser(
        "diff",
        help="Show diffs for captured pseudocode from the capture DB.",
    )
    p_diff.add_argument(
        "--db",
        help="Capture DB path (default: D810_CAPTURE_DB or project root /.d810_capture.db).",
    )
    p_diff.add_argument(
        "--function",
        help="Specific function name. If omitted, all functions are shown.",
    )
    p_diff.add_argument(
        "--mode",
        choices=("unified", "side-by-side"),
        default="unified",
        help="Diff display mode (default: unified).",
    )
    p_diff.add_argument(
        "--compact",
        action="store_true",
        help="Compact view: show only size summary for each function.",
    )
    p_diff.add_argument(
        "--summary",
        action="store_true",
        help="Summary view: per-function change/line/rule counts.",
    )
    p_diff.add_argument(
        "--width",
        type=int,
        default=60,
        help="Column width for side-by-side diff (default: 60).",
    )

    # summary
    p_summary = subparsers.add_parser(
        "summary",
        help="High-level summary of captured functions and DSL test mappings.",
    )
    p_summary.add_argument(
        "--db",
        help="Capture DB path (default: D810_CAPTURE_DB or project root /.d810_capture.db).",
    )

    # run-pytest
    subparsers.add_parser(
        "run-pytest",
        help="Run DSL system tests with --capture-to-db enabled.",
    )

    # pytest-results
    subparsers.add_parser(
        "pytest-results",
        help="Show DSL system test results from the runtime test_results DB.",
    )

    return parser


def main(argv: Optional[List[str]] = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    cmd = args.command
    if cmd == "capture":
        cmd_capture(args)
    elif cmd == "compare":
        cmd_compare(args)
    elif cmd == "bisect":
        cmd_bisect(args)
    elif cmd == "dump":
        cmd_dump(args)
    elif cmd == "list":
        cmd_list(args)
    elif cmd == "show":
        cmd_show(args)
    elif cmd == "diff":
        cmd_diff(args)
    elif cmd == "summary":
        cmd_summary(args)
    elif cmd == "run-pytest":
        cmd_run_pytest(args)
    elif cmd == "pytest-results":
        cmd_pytest_results(args)
    else:  # pragma: no cover - argparse should prevent this
        parser.print_help()


if __name__ == "__main__":
    main()
