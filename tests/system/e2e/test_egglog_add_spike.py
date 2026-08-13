"""End-to-end receipt for certified Egglog ADD reductions."""

from __future__ import annotations

import os
import platform

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


_LEGACY_ADD_RULES = [
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
]

_ADD_CASE = DeobfuscationCase(
    function="test_egglog_add_rules",
    description="Egglog extracts direct and guarded certified ADD identities",
    project="egglog_add_spike.json",
    obfuscated_contains=["^", "&", "|"],
    deobfuscated_contains=[
        "*a4 = a2 + a1",
        "a4[1] = a2 + a1",
        "a4[2] = a2 + a1 - 1",
        "a4[3] = a1 + 0x55555555",
        "a4[4] = a1",
    ],
    must_change=True,
    operator_complexity_mode="decrease",
    operator_complexity_ops=["+", "-", "*", "&", "|", "^"],
    required_rules=["EgglogOptimizer"],
    forbidden_rules=_LEGACY_ADD_RULES,
)


class TestEgglogAddSpike:
    binary_name = _get_default_binary()

    def test_config_v2_routes_only_egglog_rule(self, ida_database, d810_state) -> None:
        with d810_state() as state:
            state.load_project(state.project_manager.index("egglog_add_spike.json"))
            assert [rule.name for rule in state.current_ins_rules] == [
                "EgglogOptimizer"
            ]
            assert state.current_ins_rules[0].maturities == [ida_hexrays.MMAT_GLBOPT1]

    @pytest.mark.usefixtures("configure_hexrays", "setup_libobfuscated_funcs")
    def test_extracts_direct_and_guarded_add_rules_with_certified_provenance(
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
                tuple(execution.metadata.get("source_names", ()))
                for execution in stats.rule_execution_log
                if execution.rule_name == "EgglogOptimizer"
            )
            assert provenance == (
                ("Add_HackersDelightRule_2", "Add_OllvmRule_3"),
                ("Add_HackersDelightRule_3",),
                ("Add_OllvmRule_1", "Add_OllvmRule_DynamicConst"),
                ("Add_HackersDelightRule_2", "Add_OllvmRule_3"),
                ("Add_SpecialConstantRule_3",),
            )
            return captured

        run_deobfuscation_test(
            case=_ADD_CASE,
            d810_state=d810_state,
            pseudocode_to_string=pseudocode_to_string,
            code_comparator=code_comparator,
            capture_stats=capture_and_assert_provenance,
            load_expected_stats=load_expected_stats,
        )
