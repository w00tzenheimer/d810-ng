"""End-to-end receipt for certified Egglog ADD reductions."""

from __future__ import annotations

import json
import os
import platform

import ida_hexrays
import pytest

from d810.testing.cases import DeobfuscationCase
from d810.testing.runner import run_deobfuscation_test
from tests.system.e2e.egglog_native_corpus import (
    NativeEgglogCorpusEntry,
    build_native_egglog_attempt_receipt,
)
from tests.system.e2e.egglog_native_profile import (
    build_native_egglog_profile,
    profile_native_egglog_cprofile,
)


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
        "a4[4] = a1",
    ],
    deobfuscated_regexes=[
        r"(?m)^[ \t]*a4\[3\][ \t]*=[ \t]*a1[ \t]*\+[ \t]*"
        r"(?:0x55555555|1431655765)[ \t]*;?[ \t]*$",
    ],
    must_change=True,
    operator_complexity_mode="decrease",
    operator_complexity_ops=["+", "-", "*", "&", "|", "^"],
    required_rules=["EgglogOptimizer"],
    forbidden_rules=_LEGACY_ADD_RULES,
)

_ADD_CORPUS_ENTRY = NativeEgglogCorpusEntry(
    corpus="egglog-add-spike",
    function="test_egglog_add_rules",
    project="egglog_add_spike.json",
    expected_sources=(
        ("Add_HackersDelightRule_2", "Add_OllvmRule_3"),
        ("Add_HackersDelightRule_3",),
        ("Add_OllvmRule_1", "Add_OllvmRule_DynamicConst"),
        ("Add_HackersDelightRule_2", "Add_OllvmRule_3"),
        ("Add_SpecialConstantRule_3",),
    ),
    expected_outcomes=("applied",) * 5,
)


def _assert_degree_one_success_receipt(metadata: dict[str, object]) -> None:
    assert metadata["degree"] == 1
    assert metadata["skip_reason"] is None
    assert metadata["input_cost"] is not None
    assert metadata["extracted_cost"] is not None
    assert 0 < metadata["eclass_count"] <= 64
    assert 0 < metadata["enode_count"] <= 128
    assert 0 < metadata["rule_firings"] <= 32
    assert metadata["elapsed_ms"] >= 0.0
    stage_timings = metadata["stage_timings_ms"]
    assert tuple(stage_timings) == (
        "root_eligibility",
        "native_preflight",
        "egglog_extraction",
        # Phase 1 reads minsn_t/mop_t first. AST allocation begins only
        # after bounded extraction selects a concrete strict reduction.
        "ast_construction",
        "native_z3",
        "reconstruction",
    )
    assert all(
        type(value) is float and value >= 0.0 for value in stage_timings.values()
    )


def _force_fresh_saturation(optimizer, monkeypatch) -> None:
    """Keep this spike focused on Egglog rather than the portfolio fast paths."""

    monkeypatch.setattr(optimizer, "_direct_native_application", lambda **_: None)
    monkeypatch.setattr(optimizer, "learned_replay_enabled", False)


class TestEgglogAddSpike:
    binary_name = _get_default_binary()

    def test_config_v2_routes_only_egglog_rule(self, ida_database, d810_state) -> None:
        with d810_state() as state:
            state.load_project(state.project_manager.index("egglog_add_spike.json"))
            assert [rule.name for rule in state.current_ins_rules] == [
                "EgglogOptimizer"
            ]
            assert state.current_blk_rules == []
            assert state.last_pipeline_v2_hook_pass_ids == ("mba-egraph",)
            optimizer = state.current_ins_rules[0]
            assert optimizer.maturities == [ida_hexrays.MMAT_GLBOPT1]
            assert optimizer.collect_stage_timings is True
            assert (
                optimizer.max_leaves,
                optimizer.max_operator_nodes,
                optimizer.max_degree,
                optimizer.saturation_rounds,
                optimizer.max_eclasses,
                optimizer.max_enodes,
                optimizer.max_rule_firings,
                optimizer.time_budget_ms,
                optimizer.require_proof,
            ) == (2, 10, 1, 2, 64, 128, 32, 1000, True)

    @pytest.mark.usefixtures("configure_hexrays", "setup_libobfuscated_funcs")
    def test_extracts_direct_and_guarded_add_rules_with_certified_provenance(
        self,
        ida_database,
        d810_state,
        monkeypatch,
        pseudocode_to_string,
        code_comparator,
        capture_stats,
        load_expected_stats,
    ) -> None:
        captured_attempts = ()
        captured_optimizer = None
        provider_cursor = 0

        def prepare_runtime_state(state) -> None:
            nonlocal captured_optimizer, provider_cursor
            captured_optimizer = next(
                rule
                for rule in state.current_ins_rules
                if rule.name == "EgglogOptimizer"
            )
            _force_fresh_saturation(captured_optimizer, monkeypatch)
            provider_cursor = captured_optimizer.provider_outcome_cursor()

        def capture_runtime_state(state) -> None:
            nonlocal captured_attempts
            optimizer = next(
                rule
                for rule in state.current_ins_rules
                if rule.name == "EgglogOptimizer"
            )
            assert optimizer is captured_optimizer
            captured_attempts = optimizer.provider_outcomes_since(provider_cursor)

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
            executions = tuple(
                execution
                for execution in stats.rule_execution_log
                if execution.rule_name == "EgglogOptimizer"
            )
            assert len(executions) == len(provenance)
            for execution in executions:
                _assert_degree_one_success_receipt(execution.metadata)
            print(
                "\nEGGLOG_MBA_NATIVE_RECEIPT="
                + json.dumps(
                    build_native_egglog_profile(stats, corpus="egglog-add-spike"),
                    sort_keys=True,
                )
            )
            print(
                "\nEGGLOG_MBA_REAL_CORPUS_RECEIPT="
                + json.dumps(
                    build_native_egglog_attempt_receipt(
                        captured_attempts,
                        entry=_ADD_CORPUS_ENTRY,
                    ),
                    sort_keys=True,
                )
            )
            return captured

        profile_native_egglog_cprofile(
            _ADD_CORPUS_ENTRY.corpus,
            lambda: run_deobfuscation_test(
                case=_ADD_CASE,
                d810_state=d810_state,
                pseudocode_to_string=pseudocode_to_string,
                code_comparator=code_comparator,
                capture_stats=capture_and_assert_provenance,
                prepare_runtime_state=prepare_runtime_state,
                capture_runtime_state=capture_runtime_state,
                load_expected_stats=load_expected_stats,
            ),
        )
