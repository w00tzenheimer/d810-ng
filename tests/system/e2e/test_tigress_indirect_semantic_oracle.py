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


def _applied_redirect_edges(diag_conn) -> set[tuple[int, int, int]]:
    rows = diag_conn.execute(
        """
        SELECT block_serial, target_serial, extra_json
        FROM cfg_provenance
        WHERE action = 'REDIRECT_EDGE'
        """
    ).fetchall()
    edges: set[tuple[int, int, int]] = set()
    for source_block, target_block, raw_extra in rows:
        try:
            extra = json.loads(raw_extra or "{}")
        except json.JSONDecodeError:
            continue
        old_target = extra.get("old_target")
        if old_target is None:
            continue
        edges.add((int(source_block), int(target_block), int(old_target)))
    return edges


def _derive_live_repaired_handoffs(report: dict, diag_conn) -> dict[int, int]:
    target_block_by_state = {
        int(transfer["state"]): int(transfer["target_block"])
        for transfer in report.get("transfers", ())
        if int(transfer.get("target_block", -1)) >= 0
    }
    applied_edges = _applied_redirect_edges(diag_conn)
    handoffs: dict[int, int] = {}
    for transfer in report.get("transfers", ()):
        state = int(transfer["state"])
        for terminal_path in transfer.get("terminal_paths", ()):
            next_state = terminal_path.get("last_state")
            if next_state is None:
                continue
            next_state = int(next_state)
            target_block = target_block_by_state.get(next_state)
            if target_block is None:
                continue
            path = tuple(int(block) for block in terminal_path.get("path", ()))
            writes = tuple(terminal_path.get("writes", ()))
            if len(path) < 2 or not writes:
                continue
            old_target = int(path[-1])
            write_block = int(writes[-1]["block"])
            if (write_block, target_block, old_target) in applied_edges:
                handoffs[state] = next_state
    return handoffs


@pytest.fixture(scope="class")
def libobfuscated_setup(ida_database, configure_hexrays, setup_libobfuscated_funcs):
    if not idaapi.init_hexrays_plugin():
        pytest.skip("Hex-Rays decompiler plugin not available")
    return ida_database


class TestTigressIndirectSemanticOracle:
    """Exercise the default behavior-affecting indirect engine config live."""

    binary_name = _get_default_binary()

    @pytest.mark.xfail(
        strict=True,
        reason=(
            "EMULATED-ENGINE path (default_unflattening_tigress_indirect_engine.json, "
            "EmulatedDispatcherUnflattener) is NOT yet semantically equivalent to the "
            "reference test_function_original. The bar is SEMANTIC EQUIVALENCE, not "
            "feature-witness presence. Ground truth from the live oracle (2026-06-10): "
            "exactly TWO checks fail, 13 pass -- "
            "(1) conditional_states: REF (0x05,0x1C,0x1D,0x21,0x24) vs D810 "
            "(0x05,0x1D,0x21,0x24) -- conditional state 0x1C lost its branch (emitted "
            "unconditional); (2) failure_zero_write_present: REF True vs D810 False -- "
            "the failure-path zero-write (`*output = 0`) is absent from emitted pseudocode. "
            "all_states_present / final_output_xor / terminal_states / 0x11+0x16 handoff "
            "targets / table bounds+invariant proofs all PASS, so the earlier prose "
            "('missing else/parity loop at orphaned 0x20', 'collapsed -66 switch arm', "
            "'ref_input_value folded out') was STALE -- no such check fails today. Fix the "
            "0x1C branch recovery + emit the failure zero-write in the emulated engine, "
            "then drop this marker. NOTE: this gates the EMULATED engine ONLY; the "
            "S1a StateMachineCffUnflattener path is gated separately by "
            "test_tigress_indirect_s1a_engine_oracle. (llr-307s, llr-yyti)"
        ),
    )
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

        from d810.core.diag import get_diag_conn
        from d810.diagnostics.indirect_state_transfer_map import extract_transfer_map
        from tests.system.e2e.tigress.tigress_indirect_semantic_oracle import (
            evaluate_tigress_indirect_semantic_oracle,
            inputs_from_transfer_report,
            render_tigress_indirect_semantic_oracle_report,
        )

        diag_conn = get_diag_conn(func_ea)
        assert diag_conn is not None, (
            "tigress_flatten_indirect oracle requires a diag DB"
        )
        db_path = _diag_db_path(diag_conn, func_ea=func_ea)
        report = extract_transfer_map(db_path)
        repaired_handoffs = _derive_live_repaired_handoffs(report, diag_conn)
        assert repaired_handoffs, (
            "tigress_flatten_indirect oracle expected live terminal-stub "
            "handoff repair evidence in cfg_provenance"
        )
        inputs = inputs_from_transfer_report(
            report,
            initial_state=0x22,
            repaired_handoffs=repaired_handoffs,
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

    @pytest.mark.xfail(
        strict=True,
        reason=(
            "S1a StateMachineCffUnflattener path (default_unflattening_tigress_indirect.json) "
            "is NOT YET fully semantically equivalent to the reference test_function_original. "
            "Ground truth from the live oracle (2026-06-10): 14/15 checks PASS, exactly ONE "
            "fails -- conditional_states: REF (0x05,0x1C,0x1D,0x21,0x24) vs D810 "
            "(0x05,0x1D,0x21,0x24): conditional state 0x1C lost its branch (emitted as an "
            "unconditional goto rather than a 2-way). Everything else matches -- "
            "all_states_present, final_output_xor, terminal_states, 0x11+0x16 handoff targets, "
            "failure_zero_write_present (which the EMULATED engine FAILS, so S1a is strictly "
            "better: 1 gap vs 2), table bounds+invariant proofs, no_raw_indirect_jump. The 0x1C "
            "gap is RECOVERABLE (same folded-conditional-arm class the campaign already recovers "
            "for other arms), NOT inherent -- recover the 0x1C conditional so it lowers as a "
            "2-way, then drop this marker. (llr-yyti)"
        ),
    )
    def test_tigress_indirect_s1a_engine_oracle(
        self,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        request,
    ):
        """Ground-truth gate for the §1a StateMachineCffUnflattener path.

        Sibling of ``test_tigress_indirect_engine_oracle`` but exercises the §1a
        config (``default_unflattening_tigress_indirect.json``) instead of the
        emulated engine. §1a runs unconditionally (no enable flag). Reuses the
        same semantic oracle so both paths are measured against identical REF
        witnesses (llr-yyti).
        """
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
            with state.for_project("default_unflattening_tigress_indirect.json"):
                state.stats.reset()
                state.start_d810()
                cfunc = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
                assert cfunc is not None, (
                    f"Decompilation of {func_name} with d810 (§1a) failed"
                )
                code_after = pseudocode_to_string(cfunc.get_pseudocode())
                block_rules_fired = {
                    name
                    for name, counts in state.stats.cfg_rule_usages.items()
                    if any(count > 0 for count in counts)
                }

        from d810.core.diag import get_diag_conn
        from d810.diagnostics.indirect_state_transfer_map import extract_transfer_map
        from tests.system.e2e.tigress.tigress_indirect_semantic_oracle import (
            evaluate_tigress_indirect_semantic_oracle,
            inputs_from_transfer_report,
            render_tigress_indirect_semantic_oracle_report,
        )

        diag_conn = get_diag_conn(func_ea)
        assert diag_conn is not None, (
            "tigress_flatten_indirect §1a oracle requires a diag DB"
        )
        # §1a applies its CFG rewrite through the DEFERRED modifier, so
        # ``optimize()`` returns 0 and ``cfg_rule_usages`` never records
        # ``StateMachineCffUnflattener`` even though the pipeline ran (unlike the
        # synchronous emulated engine). The deferred-safe "did §1a unflatten"
        # signal is the REDIRECT_EDGE provenance it writes to the diag DB.
        assert _applied_redirect_edges(diag_conn), (
            "§1a applied no REDIRECT_EDGE provenance (pipeline did not unflatten); "
            f"cfg_rule_usages fired={sorted(block_rules_fired)}"
        )
        db_path = _diag_db_path(diag_conn, func_ea=func_ea)
        report = extract_transfer_map(db_path)
        # §1a may resolve handoffs without REDIRECT_EDGE old_target provenance;
        # feed whatever provenance exists (do NOT hard-require it) so the oracle
        # reports the true semantic verdict rather than erroring on plumbing.
        repaired_handoffs = _derive_live_repaired_handoffs(report, diag_conn)
        inputs = inputs_from_transfer_report(
            report,
            initial_state=0x22,
            repaired_handoffs=repaired_handoffs,
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
        (artifact_dir / "tigress_indirect_s1a_after.c").write_text(
            code_after, encoding="utf-8"
        )
        (artifact_dir / "tigress_indirect_s1a_transfer_map.json").write_text(
            json.dumps(report, indent=2, sort_keys=True), encoding="utf-8"
        )
        (artifact_dir / "tigress_indirect_s1a_oracle.md").write_text(
            oracle_report, encoding="utf-8"
        )

        print(f"\n=== tigress §1a ORACLE ===\n{oracle_report}")
        print(f"=== tigress §1a repaired_handoffs: {repaired_handoffs} ===")

        assert result.passed, oracle_report
