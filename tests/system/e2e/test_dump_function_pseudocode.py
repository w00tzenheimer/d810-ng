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

import os
import platform

import idaapi
import idc
import pytest

from d810.testing.skip_controls import unskip_cases_enabled
from d810.testing.runner import _resolve_test_project_index


def _get_default_binary() -> str:
    """Get default binary name based on platform, with env var override."""
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    return "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"


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
            raise AssertionError("No valid function names provided to --dump-function-pseudocode")

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
                    parts = [f"@{_maturity_name(m)}:{c}" for m, c in sorted(mat.items())]
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

                # Dump dispatcher tree if available
                try:
                    from d810.hexrays.microcode_dump import dump_dispatcher_tree
                    # Get the MBA from a fresh decompile without d810
                    state.stop_d810()
                    cfunc_raw = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
                    if cfunc_raw and cfunc_raw.mba:
                        # Find dispatcher entry (block with most predecessors, typically blk[2])
                        max_preds = 0
                        dispatcher_serial = -1
                        for i in range(cfunc_raw.mba.qty):
                            blk = cfunc_raw.mba.get_mblock(i)
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
                                    hodur_stkoff = getattr(detector, "state_var_stkoff", None)
                                    hodur_state_constants = getattr(detector, "state_constants", None)
                                    hodur_transitions = getattr(detector, "transitions", None)
                            except Exception:
                                pass
                            tree_str = dump_dispatcher_tree(
                                cfunc_raw.mba,
                                dispatcher_serial,
                                state_var_stkoff=hodur_stkoff,
                                state_constants=hodur_state_constants,
                                transitions=hodur_transitions,
                            )
                            print("\n--- DISPATCHER TREE ---")
                            print(f"Entry: blk[{dispatcher_serial}] ({max_preds} predecessors)")
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
            m.strip()
            for entry in _maturity_raw
            for m in entry.split(",")
            if m.strip()
        ]
        dump_d810 = request.config.getoption("--dump-microcode-d810")
        if not maturity_names and not dump_d810:
            pytest.skip("No --dump-microcode-maturity or --dump-microcode-d810 provided")

        _valid_maturities = {"GENERATED", "PREOPTIMIZED", "LOCOPT", "CALLS", "GLBOPT1", "GLBOPT2", "GLBOPT3", "LVARS"}
        for m in maturity_names:
            if m not in _valid_maturities:
                raise ValueError(f"Invalid maturity '{m}'. Valid: {sorted(_valid_maturities)}")

        raw = _dump_target
        function_names = [name.strip() for name in raw.split(",") if name.strip()]

        if dump_d810:
            # d810-active mode: decompile with d810 running, dump cfunc.mba
            from d810.hexrays.microcode_dump import mba_to_dict

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
                    print(f"MICROCODE DUMP (with d810): {function_name} @ {hex(func_ea)}")
                    print(f"MATURITY: {data['maturity']}")
                    print(f"BLOCKS: {data['num_blocks']}")
                    print("=" * 88)

                    for blk in data["blocks"]:
                        preds = blk["predecessors"]
                        succs = blk["successors"]
                        btype = blk.get("type_name", "")
                        print(f"\n--- blk[{blk['serial']}] type={btype} preds={preds} succs={succs} ---")
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
            import ida_hexrays
            from d810.hexrays.microcode_dump import dump_function_microcode

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
                        print(f"\n--- blk[{blk['serial']}] type={btype} preds={preds} succs={succs} ---")
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
