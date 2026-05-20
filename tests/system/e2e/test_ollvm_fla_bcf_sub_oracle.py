"""Semantic oracle gate for ``test_function_ollvm_fla_bcf_sub``."""
from __future__ import annotations

import os
import platform
from pathlib import Path

import pytest

import idaapi
import idc


def _get_default_binary() -> str:
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    return (
        "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"
    )


def _get_func_ea(name: str) -> int:
    ea = idc.get_name_ea_simple(name)
    if ea == idaapi.BADADDR:
        ea = idc.get_name_ea_simple("_" + name)
    return ea


@pytest.fixture(scope="class")
def libobfuscated_setup(ida_database, configure_hexrays, setup_libobfuscated_funcs):
    if not idaapi.init_hexrays_plugin():
        pytest.skip("Hex-Rays decompiler plugin not available")
    return ida_database


class TestOllvmFlaBcfSubOracle:
    """Lock this fixture's semantic/MBA facts without exact pseudocode shape."""

    binary_name = _get_default_binary()

    def test_fla_bcf_sub_oracle(
        self,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        request,
    ):
        func_name = "test_function_ollvm_fla_bcf_sub"
        func_ea = _get_func_ea(func_name)
        if func_ea == idaapi.BADADDR:
            pytest.skip(f"{func_name} not found")

        from d810.core.settings import configure_settings, reset_settings

        configure_settings(
            diag_snapshots=True,
            capture_post_maturity=idaapi.MMAT_GLBOPT1,
        )
        request.addfinalizer(reset_settings)

        with d810_state() as state:
            with state.for_project("default_unflattening_ollvm.json"):
                state.stats.reset()
                state.start_d810()
                cfunc = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
                assert cfunc is not None, (
                    f"Decompilation of {func_name} with d810 failed"
                )
                code_after = pseudocode_to_string(cfunc.get_pseudocode())

        from d810.core.diag import get_diag_db
        from tests.system.e2e.ollvm.ollvm_fla_bcf_sub_oracle import (
            evaluate_ollvm_fla_bcf_sub_oracle,
            render_ollvm_fla_bcf_sub_oracle_report,
        )

        diag_conn = get_diag_db(func_ea)
        assert diag_conn is not None, (
            "test_function_ollvm_fla_bcf_sub oracle requires a diag DB"
        )

        func_ea_hex = f"0x{func_ea:016x}"
        result = evaluate_ollvm_fla_bcf_sub_oracle(
            code_after,
            conn=diag_conn,
            func_ea_hex=func_ea_hex,
        )
        report = render_ollvm_fla_bcf_sub_oracle_report(
            result,
            func_ea_hex=func_ea_hex,
        )
        artifact_dir = Path(os.environ.get("D810_DUMP_DIR", ".tmp"))
        artifact_dir.mkdir(parents=True, exist_ok=True)
        pseudocode_path = artifact_dir / "ollvm_fla_bcf_sub_after.c"
        pseudocode_path.write_text(code_after, encoding="utf-8")
        report_path = artifact_dir / "ollvm_fla_bcf_sub_oracle.md"
        report_path.write_text(report, encoding="utf-8")

        print(f"\n=== test_function_ollvm_fla_bcf_sub ORACLE: {report_path} ===")
        print(f"=== test_function_ollvm_fla_bcf_sub AFTER: {pseudocode_path} ===")
        print(report)

        assert result.passed, report
