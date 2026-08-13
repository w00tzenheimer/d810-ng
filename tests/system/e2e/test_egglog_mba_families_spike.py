"""Native receipt for certified Egglog ADD, XOR, and SUB reductions."""

from __future__ import annotations

import os
import platform
import time

import ida_hexrays
import pytest

from d810.testing.cases import DeobfuscationCase
from d810.testing.runner import run_deobfuscation_test


def _get_default_binary() -> str:
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    return (
        "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"
    )


_LEGACY_MBA_RULES = [
    "Add_HackersDelightRule_1",
    "Add_HackersDelightRule_2",
    "Add_HackersDelightRule_3",
    "Add_HackersDelightRule_4",
    "Add_HackersDelightRule_5",
    "Add_OllvmRule_1",
    "Add_OllvmRule_2",
    "Add_OllvmRule_3",
    "Add_OllvmRule_4",
    "Add_OllvmRule_DynamicConst",
    "Add_SpecialConstantRule_1",
    "Add_SpecialConstantRule_2",
    "Add_SpecialConstantRule_3",
    "AddXor_Rule_1",
    "AddXor_Rule_2",
    "Xor_HackersDelightRule_1",
    "Xor_HackersDelightRule_2",
    "Xor_HackersDelightRule_3",
    "Xor_HackersDelightRule_4",
    "Xor_HackersDelightRule_5",
    "Xor_MbaRule_1",
    "Xor_MbaRule_2",
    "Xor_MbaRule_3",
    "Xor_FactorRule_1",
    "Xor_FactorRule_2",
    "Xor_FactorRule_3",
    "Xor_Rule_1",
    "Xor_Rule_2",
    "Xor_Rule_3",
    "Xor_Rule_4",
    "Xor_Rule_4_WithXdu",
    "Xor_SpecialConstantRule_1",
    "Xor_SpecialConstantRule_2",
    "Xor1_MbaRule_1",
    "XorAlmost_Rule_1",
    "Xor_NestedStuff",
    "Sub_HackersDelightRule_1",
    "Sub_HackersDelightRule_2",
    "Sub_HackersDelightRule_3",
    "Sub_HackersDelightRule_4",
    "Sub1_FactorRule_1",
    "Sub1_FactorRule_2",
    "Sub1Add_HackersDelightRule_1",
    "Sub1And_HackersDelightRule_1",
    "Sub1Or_MbaRule_1",
    "Sub1And1_MbaRule_1",
]

_MBA_FAMILIES_CASE = DeobfuscationCase(
    function="test_egglog_mba_families",
    description="Egglog extracts certified ADD, XOR, and SUB identities",
    project="egglog_mba_families_spike.json",
    obfuscated_contains=["^", "&", "~"],
    deobfuscated_contains=[
        "*a3 = a2 + a1",
        "a3[1] = a2 ^ a1",
        "a3[2] = a2 - a1",
    ],
    must_change=True,
    operator_complexity_mode="decrease",
    operator_complexity_ops=["+", "-", "*", "&", "|", "^", "~"],
    required_rules=["EgglogOptimizer"],
    forbidden_rules=_LEGACY_MBA_RULES,
)


class TestEgglogMbaFamiliesSpike:
    binary_name = _get_default_binary()

    def test_config_v2_routes_only_selected_egglog_families(
        self, ida_database, d810_state
    ) -> None:
        with d810_state() as state:
            state.load_project(
                state.project_manager.index("egglog_mba_families_spike.json")
            )
            assert [rule.name for rule in state.current_ins_rules] == [
                "EgglogOptimizer"
            ]
            assert state.current_blk_rules == []
            assert state.last_pipeline_v2_hook_pass_ids == ("mba-egglog",)
            optimizer = state.current_ins_rules[0]
            assert optimizer.maturities == [ida_hexrays.MMAT_GLBOPT1]
            assert optimizer.families == ("add", "xor", "sub")

    @pytest.mark.usefixtures("configure_hexrays", "setup_libobfuscated_funcs")
    def test_extracts_add_xor_and_sub_with_exact_certified_provenance(
        self,
        ida_database,
        d810_state,
        pseudocode_to_string,
        code_comparator,
        capture_stats,
        load_expected_stats,
    ) -> None:
        def capture_and_assert_provenance(stats):
            captured = capture_stats(stats)
            provenance = tuple(
                (
                    execution.metadata.get("family"),
                    execution.metadata.get("source_name"),
                    tuple(execution.metadata.get("aliases", ())),
                )
                for execution in stats.rule_execution_log
                if execution.rule_name == "EgglogOptimizer"
            )
            assert provenance == (
                ("add", "Add_HackersDelightRule_2", ("Add_OllvmRule_3",)),
                ("xor", "Xor_HackersDelightRule_3", ()),
                ("sub", "Sub_HackersDelightRule_2", ()),
            )
            return captured

        fixture_started = time.perf_counter()
        run_deobfuscation_test(
            case=_MBA_FAMILIES_CASE,
            d810_state=d810_state,
            pseudocode_to_string=pseudocode_to_string,
            code_comparator=code_comparator,
            capture_stats=capture_and_assert_provenance,
            load_expected_stats=load_expected_stats,
        )
        fixture_seconds = time.perf_counter() - fixture_started
        print(f"\nEGGLOG_MBA_NATIVE_FIXTURE_SECONDS={fixture_seconds:.6f}")
