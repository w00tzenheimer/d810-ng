"""End-to-end receipt for the bounded Egglog XOR reduction spike."""

from __future__ import annotations

import os
import platform

import pytest
import ida_hexrays

from d810.testing.cases import DeobfuscationCase
from d810.testing.runner import run_deobfuscation_test


def _get_default_binary() -> str:
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    return (
        "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"
    )


_XOR_CASE = DeobfuscationCase(
    function="test_xor",
    description="Egglog extracts the Hacker's Delight XOR identity without patterns",
    project="egglog_xor_spike.json",
    obfuscated_contains=["&", "-", "2 *"],
    deobfuscated_contains=["^"],
    must_change=True,
    operator_complexity_mode="decrease",
    operator_complexity_ops=["+", "-", "*", "&", "|", "^"],
    required_rules=["EgglogOptimizer"],
    forbidden_rules=["Xor_HackersDelightRule_3"],
)


class TestEgglogXorSpike:
    binary_name = _get_default_binary()

    def test_config_v2_routes_egglog_rule(self, ida_database, d810_state) -> None:
        with d810_state() as state:
            state.load_project(state.project_manager.index("egglog_xor_spike.json"))
            assert [rule.name for rule in state.current_ins_rules] == [
                "EgglogOptimizer"
            ]
            assert state.current_ins_rules[0].maturities == [ida_hexrays.MMAT_GLBOPT1]

    @pytest.mark.usefixtures("configure_hexrays", "setup_libobfuscated_funcs")
    def test_extracts_xor_without_pattern_rule(
        self,
        ida_database,
        d810_state,
        pseudocode_to_string,
        code_comparator,
        capture_stats,
        load_expected_stats,
    ) -> None:
        run_deobfuscation_test(
            case=_XOR_CASE,
            d810_state=d810_state,
            pseudocode_to_string=pseudocode_to_string,
            code_comparator=code_comparator,
            capture_stats=capture_stats,
            load_expected_stats=load_expected_stats,
        )
