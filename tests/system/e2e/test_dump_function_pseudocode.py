"""Manual utility test to dump before/after pseudocode for specific functions.

Usage:
    pytest -s tests/system/e2e/test_dump_function_pseudocode.py \
      --dump-function-pseudocode mixed_dispatcher_pattern \
      --dump-project example_libobfuscated.json

Multiple functions:
    pytest -s tests/system/e2e/test_dump_function_pseudocode.py \
      --dump-function-pseudocode "func_a,func_b,func_c"

Use default platform binary, or override with:
    D810_TEST_BINARY=libobfuscated.dll
"""

from __future__ import annotations

import json
import os
import platform
import re
import tempfile
from pathlib import Path

import pytest

import ida_hexrays
import idaapi
import idc

from d810.recon.microcode_dump import (
    dump_dispatcher_tree,
    dump_function_microcode,
    print_mba_human_readable,
)
from d810.optimizers.microcode.flow.flattening.hodur.diagnostics import (
    build_terminal_return_valrange_report_from_store,
)
from d810.testing.runner import _resolve_test_project_index
from d810.testing.skip_controls import unskip_cases_enabled


def _extract_pseudocode_stats(text: str) -> dict:
    """Extract simple metrics from a pseudocode string.

    Counts are approximate — based on pattern matching, not AST parsing.

    Args:
        text: Pseudocode string (BEFORE or AFTER decompilation output).

    Returns:
        Dict with keys: lines, returns, whiles, gotos, calls, ifs.

    Examples:
        >>> s = 'int x;\\nif (a) return 1;\\nwhile (b) { sub_foo(); }\\nreturn 0;'
        >>> stats = _extract_pseudocode_stats(s)
        >>> stats['lines']
        4
        >>> stats['returns']
        2
        >>> stats['whiles']
        1
        >>> stats['ifs']
        1
        >>> stats['calls'] >= 1
        True
    """
    lines = [ln for ln in text.splitlines() if ln.strip()]
    returns = len(re.findall(r'\breturn\b', text))
    whiles = len(re.findall(r'\bwhile\s*\(', text))
    gotos = len(re.findall(r'\bgoto\b', text))
    ifs = len(re.findall(r'\bif\s*\(', text))
    # Count sub_XXXX style calls explicitly, plus identifier(...) patterns
    sub_calls = len(re.findall(r'\bsub_[0-9A-Fa-f]+\s*\(', text))
    # identifier( where identifier is a word not a keyword and not alone on a
    # continuation line — approximate function-call detection
    kw = {'if', 'while', 'for', 'switch', 'return', 'sizeof', 'typeof', 'goto'}
    ident_calls = len([
        m for m in re.finditer(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\(', text)
        if m.group(1) not in kw
    ])
    calls = max(sub_calls, ident_calls)
    return {
        'lines': len(lines),
        'returns': returns,
        'whiles': whiles,
        'gotos': gotos,
        'calls': calls,
        'ifs': ifs,
    }


def _format_stats_block(function_name: str, before: dict, after: dict) -> str:
    """Format a BEFORE/AFTER/DELTA stats block for a function."""
    keys = ('lines', 'returns', 'whiles', 'gotos', 'calls', 'ifs')

    def _fmt(d: dict) -> str:
        return ' '.join(f'{k}={d[k]}' for k in keys)

    def _delta(b: dict, a: dict) -> str:
        parts = []
        for k in keys:
            diff = a[k] - b[k]
            parts.append(f'{k}={diff:+d}')
        return ' '.join(parts)

    lines = [
        f'=== STATS: {function_name} ===',
        f'BEFORE: {_fmt(before)}',
        f'AFTER:  {_fmt(after)}',
        f'DELTA:  {_delta(before, after)}',
    ]
    return '\n'.join(lines)


def _print_terminal_return_valranges(mba, func_ea: int) -> None:
    """Print grouped terminal-return valrange diagnostics if recon artifacts exist."""
    print("\n--- TERMINAL RETURN VALRANGES ---")
    report = build_terminal_return_valrange_report_from_store(
        mba=mba,
        func_ea=func_ea,
        log_dir=None,
        maturity=None,
    )
    if report is None:
        print("[no terminal return audit available in recon store]")
        return
    print(report.format())


def _get_default_binary() -> str:
    """Get default binary name based on platform, with env var override."""
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    return (
        "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"
    )


def _get_func_ea(name: str) -> int:
    """Get function address by name or hex address string.

    Handles:
    - Named symbols (e.g. ``_hodur_func``)
    - macOS underscore-prefixed names (e.g. ``hodur_func`` -> ``_hodur_func``)
    - Hex address strings (e.g. ``0x180012B60``) for functions without a
      named export (auto-named ``sub_*`` functions not present in the IDB)
    """
    ea = idc.get_name_ea_simple(name)
    if ea == idaapi.BADADDR:
        ea = idc.get_name_ea_simple("_" + name)
    if ea == idaapi.BADADDR and name.startswith("0x"):
        try:
            ea = int(name, 16)
            if not idaapi.get_func(ea):
                ea = idaapi.BADADDR
        except ValueError:
            pass
    return ea


@pytest.mark.pseudocode_dump
class TestDumpFunctionPseudocode:
    """Ad-hoc pseudocode dump harness for local debugging."""

    binary_name = _get_default_binary()

    @pytest.fixture(scope="class")
    def _dump_target(self, request) -> str:
        raw = request.config.getoption("--dump-function-pseudocode")
        if not raw:
            raw = os.environ.get("D810_DUMP_FUNCTION_PSEUDOCODE")
        if not raw and unskip_cases_enabled():
            # Research default: run against a stable baseline function.
            raw = "test_xor"
        if not raw:
            pytest.skip("No --dump-function-pseudocode value provided")
        return raw

    @pytest.fixture(scope="class")
    def libobfuscated_setup(
        self,
        _dump_target,
        ida_database,
        configure_hexrays,
        setup_libobfuscated_funcs,
    ):
        if not idaapi.init_hexrays_plugin():
            pytest.skip("Hex-Rays decompiler plugin not available")
        # Dump utility prefers fully expanded locals for copy/paste-compilable output.
        idaapi.change_hexrays_config("COLLAPSE_LVARS = NO")
        return ida_database

    def test_dump_function_pseudocode(
        self,
        request,
        _dump_target,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
    ):
        raw = _dump_target
        function_names = [name.strip() for name in raw.split(",") if name.strip()]
        if not function_names:
            raise AssertionError(
                "No valid function names provided to --dump-function-pseudocode"
            )

        use_project = not request.config.getoption("--dump-no-project")
        project_name = request.config.getoption("--dump-project")

        with d810_state() as state:
            if use_project:
                project_index = _resolve_test_project_index(state, project_name)
                state.load_project(project_index)

            for function_name in function_names:
                func_ea = _get_func_ea(function_name)
                if func_ea == idaapi.BADADDR:
                    raise AssertionError(f"Function '{function_name}' not found")

                force_rettype = request.config.getoption("--dump-force-rettype", default=None)
                if force_rettype:
                    import ida_typeinf
                    tif = ida_typeinf.tinfo_t()
                    decl_str = f"{force_rettype} __fastcall {function_name}(void);"
                    if ida_typeinf.parse_decl(tif, None, decl_str, ida_typeinf.PT_SIL):
                        ida_typeinf.apply_tinfo(func_ea, tif, ida_typeinf.TINFO_DEFINITE)
                        print(f"[FORCE-RETTYPE] Applied: {decl_str}")
                    else:
                        print(f"[FORCE-RETTYPE] FAILED to parse: {decl_str}")

                state.stop_d810()
                before = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
                if before is None:
                    raise AssertionError(
                        f"Failed to decompile '{function_name}' without d810"
                    )
                code_before = pseudocode_to_string(before.get_pseudocode())

                state.stats.reset()
                state.start_d810()
                after = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
                if after is None:
                    raise AssertionError(
                        f"Failed to decompile '{function_name}' with d810"
                    )
                code_after = pseudocode_to_string(after.get_pseudocode())
                rules_fired = state.stats.get_fired_rule_names()
                # Block/CFG rules are tracked in cfg_rule_usages: name -> [patch_counts].
                # A rule "fired" if it produced at least one positive patch count.
                block_rules_fired = sorted(
                    name
                    for name, counts in state.stats.cfg_rule_usages.items()
                    if any(c > 0 for c in counts)
                )

                # Build per-maturity annotation helpers
                from d810.core.stats import _maturity_name

                def _insn_rule_maturity_note(rule_name: str) -> str:
                    mat = state.stats.maturity_rule_usages.get(rule_name)
                    if not mat:
                        return ""
                    parts = [
                        f"@{_maturity_name(m)}:{c}" for m, c in sorted(mat.items())
                    ]
                    return " [" + ", ".join(parts) + "]"

                def _cfg_rule_maturity_note(rule_name: str) -> str:
                    mat = state.stats.maturity_cfg_rule_usages.get(rule_name)
                    if not mat:
                        return ""
                    parts = [
                        f"@{_maturity_name(m)}:{sum(p)}p"
                        for m, p in sorted(mat.items())
                    ]
                    return " [" + ", ".join(parts) + "]"

                print("\n" + "=" * 88)
                print(f"FUNCTION: {function_name} @ {hex(func_ea)}")
                print(f"BINARY: {self.binary_name}")
                print(f"PROJECT: {project_name if use_project else '<none>'}")
                print(f"CODE_CHANGED: {code_before != code_after}")
                if rules_fired:
                    print("RULES_FIRED (instruction):")
                    for r in rules_fired:
                        print(f"  {r}{_insn_rule_maturity_note(r)}")
                else:
                    print("RULES_FIRED (instruction): <none>")
                if block_rules_fired:
                    print("RULES_FIRED (block):")
                    for r in block_rules_fired:
                        print(f"  {r}{_cfg_rule_maturity_note(r)}")
                else:
                    print("RULES_FIRED (block): <none>")
                print("\n--- BEFORE ---")
                print(code_before)
                print("\n--- AFTER ---")
                print(code_after)
                print("=" * 88)

                # Stats summary — extracted from pseudocode text directly
                stats_before = _extract_pseudocode_stats(code_before)
                stats_after = _extract_pseudocode_stats(code_after)
                print(_format_stats_block(function_name, stats_before, stats_after))

                # Dump dispatcher tree if available
                try:

                    _bst_maturity_name = request.config.getoption(
                        "--dump-bst-maturity", default=None
                    )
                    _bst_maturity_map = {
                        "GENERATED": ida_hexrays.MMAT_GENERATED,
                        "PREOPTIMIZED": ida_hexrays.MMAT_PREOPTIMIZED,
                        "LOCOPT": ida_hexrays.MMAT_LOCOPT,
                        "CALLS": ida_hexrays.MMAT_CALLS,
                        "GLBOPT1": ida_hexrays.MMAT_GLBOPT1,
                        "GLBOPT2": ida_hexrays.MMAT_GLBOPT2,
                        "GLBOPT3": ida_hexrays.MMAT_GLBOPT3,
                        "LVARS": ida_hexrays.MMAT_LVARS,
                    }
                    # Get the MBA from a fresh decompile without d810
                    state.stop_d810()
                    if _bst_maturity_name:
                        target_mat = _bst_maturity_map.get(
                            _bst_maturity_name.upper(), ida_hexrays.MMAT_GLBOPT1
                        )
                        func = idaapi.get_func(func_ea)
                        mbr = idaapi.mba_ranges_t()
                        mbr.ranges.push_back(idaapi.range_t(func.start_ea, func.end_ea))
                        hf = idaapi.hexrays_failure_t()
                        mba = idaapi.gen_microcode(
                            mbr, hf, None, idaapi.DECOMP_NO_WAIT, target_mat
                        )
                        mba_source = f"gen_microcode({_bst_maturity_name.upper()})"
                    else:
                        cfunc_raw = idaapi.decompile(
                            func_ea, flags=idaapi.DECOMP_NO_CACHE
                        )
                        mba = cfunc_raw.mba if cfunc_raw else None
                        mba_source = "decompile(LVARS)"
                    if mba:
                        # Find dispatcher entry (block with most predecessors, typically blk[2])
                        max_preds = 0
                        dispatcher_serial = -1
                        for i in range(mba.qty):
                            blk = mba.get_mblock(i)
                            if blk.npred() > max_preds:
                                max_preds = blk.npred()
                                dispatcher_serial = i
                        if dispatcher_serial >= 0:
                            # Collect Hodur detector context if available
                            hodur_stkoff = None
                            hodur_state_constants = None
                            hodur_transitions = None
                            try:
                                from d810.optimizers.microcode.flow.flattening.unflattener_hodur import (
                                    HodurUnflattener,
                                )

                                # Re-enable d810 briefly to get Hodur context
                                # (best-effort: may not be available at this maturity)
                                detector = getattr(state, "_hodur_detector", None)
                                if detector is not None:
                                    hodur_stkoff = getattr(
                                        detector, "state_var_stkoff", None
                                    )
                                    hodur_state_constants = getattr(
                                        detector, "state_constants", None
                                    )
                                    hodur_transitions = getattr(
                                        detector, "transitions", None
                                    )
                            except Exception:
                                pass
                            tree_str = dump_dispatcher_tree(
                                mba,
                                dispatcher_serial,
                                state_var_stkoff=hodur_stkoff,
                                state_constants=hodur_state_constants,
                                transitions=hodur_transitions,
                            )
                            print(f"\n--- DISPATCHER TREE ({mba_source}) ---")
                            print(
                                f"Entry: blk[{dispatcher_serial}] ({max_preds} predecessors)"
                            )
                            print(tree_str)
                            print("=" * 88)
                except Exception as e:
                    print(f"\n[dispatcher tree dump failed: {e}]")

    def test_dump_microcode(
        self,
        request,
        _dump_target,
        libobfuscated_setup,
        d810_state,
    ):
        _maturity_raw = request.config.getoption("--dump-microcode-maturity") or []
        # Flatten list and split comma-separated values: ["CALLS,GLBOPT1"] -> ["CALLS", "GLBOPT1"]
        maturity_names = [
            m.strip() for entry in _maturity_raw for m in entry.split(",") if m.strip()
        ]
        dump_d810 = request.config.getoption("--dump-microcode-d810")
        dump_human = request.config.getoption("--dump-microcode-human-readable")
        dump_terminal_valranges = request.config.getoption(
            "--dump-terminal-return-valranges"
        )
        dump_d810_maturity = request.config.getoption(
            "--dump-microcode-d810-maturity", default=None
        )
        if not maturity_names and not dump_d810 and not dump_d810_maturity:
            pytest.skip(
                "No --dump-microcode-maturity, --dump-microcode-d810, or --dump-microcode-d810-maturity provided"
            )

        _valid_maturities = {
            "GENERATED",
            "PREOPTIMIZED",
            "LOCOPT",
            "CALLS",
            "GLBOPT1",
            "GLBOPT2",
            "GLBOPT3",
            "LVARS",
        }
        for m in maturity_names:
            if m not in _valid_maturities:
                raise ValueError(
                    f"Invalid maturity '{m}'. Valid: {sorted(_valid_maturities)}"
                )

        raw = _dump_target
        function_names = [name.strip() for name in raw.split(",") if name.strip()]

        if dump_d810:
            # d810-active mode: decompile with d810 running, dump cfunc.mba
            from d810.recon.microcode_dump import mba_to_dict

            use_project = not request.config.getoption("--dump-no-project")
            project_name = request.config.getoption("--dump-project")

            with d810_state() as state:
                if use_project:
                    project_index = _resolve_test_project_index(state, project_name)
                    state.load_project(project_index)

                state.start_d810()

                for function_name in function_names:
                    func_ea = _get_func_ea(function_name)
                    if func_ea == idaapi.BADADDR:
                        raise AssertionError(f"Function '{function_name}' not found")

                    cfunc = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
                    if cfunc is None:
                        raise AssertionError(
                            f"Failed to decompile '{function_name}' with d810"
                        )

                    mba = cfunc.mba
                    data = mba_to_dict(mba, func_name=function_name)

                    print("\n" + "=" * 88)
                    print(
                        f"MICROCODE DUMP (with d810): {function_name} @ {hex(func_ea)}"
                    )
                    print(f"MATURITY: {data['maturity']}")
                    print(f"BLOCKS: {data['num_blocks']}")
                    print("=" * 88)

                    for blk in data["blocks"]:
                        preds = blk["predecessors"]
                        succs = blk["successors"]
                        btype = blk.get("type_name", "")
                        print(
                            f"\n--- blk[{blk['serial']}] type={btype} preds={preds} succs={succs} ---"
                        )
                        for insn in blk["instructions"]:
                            parts = [f"  {insn['opcode']}"]
                            if insn.get("d"):
                                parts.append(f"{insn['d']} =")
                            if insn.get("l"):
                                parts.append(f"{insn['l']}")
                            if insn["opcode"] not in ("mov", "ret", "jmp", "call"):
                                if insn.get("r"):
                                    parts.append(f"{insn['r']}")
                            print(" ".join(parts))
                    if dump_human:
                        print("\n--- HUMAN MICROCODE (with d810) ---")
                        print_mba_human_readable(mba, func_name=function_name)
                    if dump_terminal_valranges:
                        _print_terminal_return_valranges(mba, func_ea)
                    print("=" * 88)
        if dump_d810_maturity:
            # Post-D810 mid-pipeline capture: run decompile with D810 active,
            # but capture the MBA state *after* D810 finishes at the requested
            # maturity via the D810_CAPTURE_POST_MATURITY env-var policy handled
            # by D810Manager's post-maturity capture subscriber.

            _d810_mat_map = {
                "GENERATED": 1,
                "PREOPTIMIZED": 2,
                "LOCOPT": 3,
                "CALLS": 4,
                "GLBOPT1": 5,
                "GLBOPT2": 6,
                "GLBOPT3": 7,
                "LVARS": 8,
            }
            d810_mat_name = dump_d810_maturity.upper()
            if d810_mat_name not in _d810_mat_map:
                raise ValueError(
                    f"Invalid --dump-microcode-d810-maturity '{dump_d810_maturity}'. "
                    f"Valid: {sorted(_d810_mat_map)}"
                )
            target_mat_int = _d810_mat_map[d810_mat_name]
            capture_path = str(Path(tempfile.gettempdir()) / "d810_mid_capture.json")

            use_project = not request.config.getoption("--dump-no-project")
            project_name = request.config.getoption("--dump-project")

            with d810_state() as state:
                if use_project:
                    project_index = _resolve_test_project_index(state, project_name)
                    state.load_project(project_index)

                state.start_d810()

                for function_name in function_names:
                    func_ea = _get_func_ea(function_name)
                    if func_ea == idaapi.BADADDR:
                        raise AssertionError(f"Function '{function_name}' not found")

                    # Remove stale capture file before decompile
                    if os.path.exists(capture_path):
                        os.unlink(capture_path)

                    os.environ["D810_CAPTURE_POST_MATURITY"] = str(target_mat_int)
                    os.environ["D810_CAPTURE_POST_FILE"] = capture_path
                    try:
                        cfunc = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
                    finally:
                        os.environ.pop("D810_CAPTURE_POST_MATURITY", None)
                        os.environ.pop("D810_CAPTURE_POST_FILE", None)

                    if cfunc is None:
                        raise AssertionError(
                            f"Failed to decompile '{function_name}' with d810"
                        )

                    if not os.path.exists(capture_path):
                        print(
                            f"\n[post-D810 capture at {d810_mat_name}: no snapshot written "
                            f"-- D810 may not have advanced past this maturity for this function]"
                        )
                        continue

                    with open(capture_path) as fh:
                        data = json.load(fh)
                    os.unlink(capture_path)

                    print("\n" + "=" * 88)
                    print(
                        f"POST-D810 MICROCODE @ MMAT_{d810_mat_name}: "
                        f"{function_name} @ {hex(func_ea)}"
                    )
                    print(f"MATURITY: {data['maturity']}")
                    print(f"BLOCKS: {data['num_blocks']}")
                    print(f"PROJECT: {project_name if use_project else '<none>'}")
                    print("=" * 88)

                    for blk in data["blocks"]:
                        preds = blk["predecessors"]
                        succs = blk["successors"]
                        btype = blk.get("type_name", "")
                        print(
                            f"\n--- blk[{blk['serial']}] type={btype} preds={preds} succs={succs} ---"
                        )
                        for insn in blk["instructions"]:
                            parts = [f"  {insn['opcode']}"]
                            if insn.get("d"):
                                parts.append(f"{insn['d']} =")
                            if insn.get("l"):
                                parts.append(f"{insn['l']}")
                            if insn["opcode"] not in ("mov", "ret", "jmp", "call"):
                                if insn.get("r"):
                                    parts.append(f"{insn['r']}")
                            print(" ".join(parts))
                    print("=" * 88)
        if maturity_names:
            # Raw (pre-d810) microcode mode using gen_microcode()

            maturity_map = {
                "GENERATED": ida_hexrays.MMAT_GENERATED,
                "PREOPTIMIZED": ida_hexrays.MMAT_PREOPTIMIZED,
                "LOCOPT": ida_hexrays.MMAT_LOCOPT,
                "CALLS": ida_hexrays.MMAT_CALLS,
                "GLBOPT1": ida_hexrays.MMAT_GLBOPT1,
                "GLBOPT2": ida_hexrays.MMAT_GLBOPT2,
                "GLBOPT3": ida_hexrays.MMAT_GLBOPT3,
                "LVARS": ida_hexrays.MMAT_LVARS,
            }

            for maturity_name in maturity_names:
                maturity = maturity_map[maturity_name]
                for function_name in function_names:
                    func_ea = _get_func_ea(function_name)
                    if func_ea == idaapi.BADADDR:
                        raise AssertionError(f"Function '{function_name}' not found")

                    data = dump_function_microcode(func_ea, maturity)
                    if data is None:
                        raise AssertionError(
                            f"Failed to get microcode for '{function_name}' at {maturity_name}"
                        )

                    print("\n" + "=" * 88)
                    print(f"MICROCODE DUMP: {function_name} @ {hex(func_ea)}")
                    print(f"MATURITY: {maturity_name}")
                    print(f"BLOCKS: {data['num_blocks']}")
                    print("=" * 88)

                    for blk in data["blocks"]:
                        preds = blk["predecessors"]
                        succs = blk["successors"]
                        btype = blk.get("type_name", "")
                        print(
                            f"\n--- blk[{blk['serial']}] type={btype} preds={preds} succs={succs} ---"
                        )
                        for insn in blk["instructions"]:
                            parts = [f"  {insn['opcode']}"]
                            if insn.get("d"):
                                parts.append(f"{insn['d']} =")
                            if insn.get("l"):
                                parts.append(f"{insn['l']}")
                            if insn["opcode"] not in ("mov", "ret", "jmp", "call"):
                                if insn.get("r"):
                                    parts.append(f"{insn['r']}")
                            print(" ".join(parts))
                    if dump_human:
                        func = idaapi.get_func(func_ea)
                        mbr = idaapi.mba_ranges_t()
                        mbr.ranges.push_back(idaapi.range_t(func.start_ea, func.end_ea))
                        hf = idaapi.hexrays_failure_t()
                        mba = idaapi.gen_microcode(
                            mbr, hf, None, idaapi.DECOMP_NO_WAIT, maturity
                        )
                        if mba is not None:
                            print(
                                f"\n--- HUMAN MICROCODE ({maturity_name}) ---"
                            )
                            print_mba_human_readable(mba, func_name=function_name)
                            if dump_terminal_valranges:
                                _print_terminal_return_valranges(mba, func_ea)
                    print("=" * 88)
