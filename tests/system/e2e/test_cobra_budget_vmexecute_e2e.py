"""Real IDA fixture regression for budgeted CoBRA and durable proof replay."""

from __future__ import annotations

import hashlib
import sqlite3
import time
from pathlib import Path

import ida_funcs
import idaapi
import idc
import pytest

from d810.testing.runner import _resolve_test_project_index
pytest.importorskip("d810_cobra")
from d810_cobra.rules.cobra_solve import CobraSolveRule

_DLL_SHA256 = "1b002438e8078cb6d11bb061d69ab032363c11c5a6c8a2bdc1fbf02a676a9160"
_START = 0x18001A860
_END = 0x180028552
_PROJECT = "cobra_budgeted_vmexecute_e2e.json"


@pytest.mark.pseudocode_dump
class TestCobraBudgetedVmExecutePacket:
    binary_name = "libobfuscated.dll"

    @pytest.fixture(scope="class")
    def prepared_ea(self, ida_database, configure_hexrays, setup_libobfuscated_funcs):
        assert idaapi.init_hexrays_plugin()
        actual_hash = hashlib.sha256(
            Path(ida_database["binary_path"]).read_bytes()
        ).hexdigest()
        assert actual_hash == _DLL_SHA256
        ea = idc.get_name_ea_simple("VM_ExecutePacket")
        assert ea == _START
        func = ida_funcs.get_func(ea)
        if func is None:
            assert ida_funcs.add_func(ea, _END)
        elif func.end_ea != _END:
            assert ida_funcs.set_func_end(ea, _END)
        assert ida_funcs.get_func(ea).end_ea == _END
        idaapi.change_hexrays_config("MAX_FUNCSIZE = 65536")
        return ea

    def test_budgeted_solve_replays_verified_cache(self, prepared_ea, d810_state):
        with d810_state() as state:
            state.load_project(_resolve_test_project_index(state, _PROJECT))
            state.stop_d810()
            state.start_d810()
            rule = next(
                (
                    rule
                    for rule in state.manager.instruction_optimizer_rules
                    if isinstance(rule, CobraSolveRule)
                ),
                None,
            )
            assert rule is not None, "budgeted CoBRA rule was not activated"
            assert rule.solve_timeout_ms == 25
            assert rule.function_solve_budget_ms == 1500
            assert rule.require_proof

            started = time.perf_counter()
            first = idaapi.decompile(prepared_ea, flags=idaapi.DECOMP_NO_CACHE)
            first_seconds = time.perf_counter() - started
            assert first is not None
            assert "CobraSolveRule" in state.stats.get_fired_rule_names()
            hits_before_replay = rule.table.stats.hits

            state.stats.reset()
            started = time.perf_counter()
            replay = idaapi.decompile(prepared_ea, flags=idaapi.DECOMP_NO_CACHE)
            replay_seconds = time.perf_counter() - started
            assert replay is not None
            assert rule.table.stats.hits > hits_before_replay
            assert "CobraSolveRule" in state.stats.get_fired_rule_names()

            cache_path = Path("/root/.idapro/logs/d810_logs/d810_mba_proofs.db")
            assert cache_path.is_file()
            with sqlite3.connect(cache_path) as conn:
                verified = conn.execute(
                    "SELECT COUNT(*) FROM cobra_proofs_v2 "
                    "WHERE outcome = 'proved' AND proof_verified = 1"
                ).fetchone()[0]
                unverified = conn.execute(
                    "SELECT COUNT(*) FROM cobra_proofs_v2 "
                    "WHERE outcome = 'proved' AND proof_verified != 1"
                ).fetchone()[0]
            assert verified > 0
            assert unverified == 0
            print(
                "COBRA_BUDGET_NATIVE",
                f"first_seconds={first_seconds:.3f}",
                f"replay_seconds={replay_seconds:.3f}",
                f"cache_hits={rule.table.stats.hits - hits_before_replay}",
                f"durable_verified={verified}",
            )
