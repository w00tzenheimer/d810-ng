"""Live semantic oracle gate for ``tigress_flatten_indirect``."""
from __future__ import annotations

import json
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


def _diag_db_path(diag_conn, *, func_ea: int) -> Path:
    diag_conn.commit()
    for row in diag_conn.execute("PRAGMA database_list"):
        if row[1] == "main" and row[2]:
            return Path(row[2])

    from d810.core.diag import find_latest_diag_db_path

    latest = find_latest_diag_db_path(func_ea)
    assert latest is not None, (
        "tigress_flatten_indirect oracle requires a diag DB path"
    )
    return latest


@pytest.fixture(scope="class")
def libobfuscated_setup(ida_database, configure_hexrays, setup_libobfuscated_funcs):
    if not idaapi.init_hexrays_plugin():
        pytest.skip("Hex-Rays decompiler plugin not available")
    return ida_database


class TestTigressIndirectSemanticOracle:
    """Exercise the default behavior-affecting indirect engine config live."""

    binary_name = _get_default_binary()

    def test_tigress_indirect_engine_oracle(
        self,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        request,
    ):
        func_name = "tigress_flatten_indirect"
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
            with state.for_project("default_unflattening_tigress_indirect_engine.json"):
                state.stats.reset()
                state.start_d810()
                cfunc = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
                assert cfunc is not None, (
                    f"Decompilation of {func_name} with d810 failed"
                )
                code_after = pseudocode_to_string(cfunc.get_pseudocode())
                block_rules_fired = {
                    name
                    for name, counts in state.stats.cfg_rule_usages.items()
                    if any(count > 0 for count in counts)
                }

        assert "EmulatedDispatcherUnflattener" in block_rules_fired
        assert "UnflattenerTigressIndirect" not in block_rules_fired

        from d810.core.diag import get_diag_db
        from d810.diagnostics.indirect_state_transfer_map import extract_transfer_map
        from tests.system.e2e.tigress.tigress_indirect_semantic_oracle import (
            evaluate_tigress_indirect_semantic_oracle,
            inputs_from_transfer_report,
            render_tigress_indirect_semantic_oracle_report,
        )

        diag_conn = get_diag_db(func_ea)
        assert diag_conn is not None, (
            "tigress_flatten_indirect oracle requires a diag DB"
        )
        db_path = _diag_db_path(diag_conn, func_ea=func_ea)
        report = extract_transfer_map(db_path)
        inputs = inputs_from_transfer_report(
            report,
            initial_state=0x22,
            repaired_handoffs={
                0x11: 0x24,
                0x16: 0x1B,
            },
            pseudocode=code_after,
            func_name=func_name,
        )
        result = evaluate_tigress_indirect_semantic_oracle(inputs)
        oracle_report = render_tigress_indirect_semantic_oracle_report(
            result,
            func_name=func_name,
        )

        artifact_dir = Path(os.environ.get("D810_DUMP_DIR", ".tmp"))
        artifact_dir.mkdir(parents=True, exist_ok=True)
        pseudocode_path = artifact_dir / "tigress_indirect_after.c"
        pseudocode_path.write_text(code_after, encoding="utf-8")
        transfer_map_path = artifact_dir / "tigress_indirect_transfer_map.json"
        transfer_map_path.write_text(
            json.dumps(report, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        report_path = artifact_dir / "tigress_indirect_oracle.md"
        report_path.write_text(oracle_report, encoding="utf-8")

        print(f"\n=== tigress_flatten_indirect ORACLE: {report_path} ===")
        print(f"=== tigress_flatten_indirect AFTER: {pseudocode_path} ===")
        print(f"=== tigress_flatten_indirect TRANSFER MAP: {transfer_map_path} ===")
        print(oracle_report)

        assert result.passed, oracle_report
