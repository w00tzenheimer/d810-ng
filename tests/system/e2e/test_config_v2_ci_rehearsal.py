"""Normal-runner coverage for supported config-v2 runtime routing."""
from __future__ import annotations

import os
import platform

import pytest

import idaapi

from d810.core.config_v2_defaults import CONFIG_V2_SUPPORTED_DEFAULTS_ENV
from d810.testing import DeobfuscationCase
from d810.testing.config_v2_rehearsal import CONFIG_V2_CI_REHEARSAL_ENV
from d810.testing.runner import run_deobfuscation_test


def _get_default_binary() -> str:
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    return (
        "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"
    )


_REHEARSAL_CASES = (
    pytest.param(
        DeobfuscationCase(
            function="test_chained_add",
            project="default_instruction_only.json",
            obfuscated_contains=["0xFFFFFFEF"],
            acceptable_patterns=["2 * a1[1]", "a1[1] + a1[1]", "0x33", "0x34"],
            check_stats=False,
        ),
        id="default_instruction_only",
    ),
    pytest.param(
        DeobfuscationCase(
            function="tigress_minmaxarray",
            project="default_unflattening_tigress_engine.json",
            obfuscated_contains=["switch", "case"],
            deobfuscated_contains=["Largest element:", "Smallest element:"],
            check_stats=False,
        ),
        id="tigress_engine",
    ),
    pytest.param(
        DeobfuscationCase(
            function="hodur_func",
            project="hodur_flag2.json",
            obfuscated_contains=["while"],
            acceptable_patterns=["Hodur/1.0", "printf", "resolve_api", "sub_180008C"],
            check_stats=False,
        ),
        id="hodur_flag2",
    ),
    pytest.param(
        DeobfuscationCase(
            function="approov_vm_dispatcher",
            project="default_unflattening_approov.json",
            deobfuscated_not_contains=["switch"],
            must_change=True,
        ),
        id="default_unflattening_approov",
    ),
    pytest.param(
        # §1a StateMachineCffUnflattener/ApproovFamily route. The paired parity
        # rows (approov_s1a_mixed_spine_flow / _config_v2_canary_...) prove
        # legacy==canary equivalence outcome-agnostically; this rehearsal case
        # only verifies that the source config routes through the config-v2
        # canary and fires the expected pass ids, so it does not assert a
        # specific unflattening outcome (the §1a threshold may be a no-op).
        DeobfuscationCase(
            function="approov_vm_dispatcher",
            project="default_unflattening_approov_s1a.json",
            must_change=False,
            check_stats=False,
        ),
        id="default_unflattening_approov_s1a",
    ),
    pytest.param(
        DeobfuscationCase(
            function="identity_call_trampoline_chain",
            project="identity_call.json",
            must_change=True,
            check_stats=True,
            required_rules=["IdentityCallResolver"],
            deobfuscated_not_contains=["identity_func("],
            acceptable_patterns=["trampoline_wrapper(", "sub_"],
        ),
        id="identity_call",
    ),
    pytest.param(
        DeobfuscationCase(
            function="hodur_func",
            project="hodur_glbopt2_only.json",
            obfuscated_contains=["while"],
            deobfuscated_not_contains=["while ( 1 )"],
            acceptable_patterns=["Hodur/1.0", "printf", "resolve_api"],
            check_stats=False,
        ),
        id="hodur_glbopt2_only",
    ),
    pytest.param(
        DeobfuscationCase(
            function="hodur_func",
            project="hodur_flag2_s1a.json",
            obfuscated_contains=["while"],
            deobfuscated_not_contains=["while ( 1 )"],
            acceptable_patterns=["Hodur/1.0", "printf", "resolve_api"],
            check_stats=False,
        ),
        id="hodur_flag2_s1a",
    ),
    pytest.param(
        DeobfuscationCase(
            function="hodur_func",
            project="hodur_flag2_with_fcp.json",
            obfuscated_contains=["while"],
            deobfuscated_not_contains=["while ( 1 )"],
            acceptable_patterns=["Hodur/1.0", "printf", "resolve_api"],
            check_stats=False,
        ),
        id="hodur_flag2_with_fcp",
    ),
    pytest.param(
        DeobfuscationCase(
            function="test_mba_guessing",
            project="eidolon.json",
            obfuscated_contains=["*"],
            acceptable_patterns=["a4 | a1", "~(a1 ^ a4)", "return"],
            must_change=True,
            check_stats=False,
        ),
        id="eidolon",
    ),
    # Batch-routed shadow-only configs (d81-xkw8). These rehearsal cases verify
    # the source config routes through its config-v2 canary and fires the
    # expected pass ids (asserted in TestConfigV2SupportedDefaultRouting); the
    # paired parity rows prove legacy==canary equivalence, so they do not assert
    # a specific unflattening outcome (must_change/check_stats left off).
    pytest.param(
        DeobfuscationCase(
            function="tigress_minmaxarray",
            project="default_unflattening_tigress_engine_transition_facts.json",
            must_change=False,
            check_stats=False,
        ),
        id="default_unflattening_tigress_engine_transition_facts",
    ),
    pytest.param(
        DeobfuscationCase(
            function="abc_or_dispatch",
            project="example_libobfuscated_abc.json",
            must_change=False,
            check_stats=False,
        ),
        id="example_libobfuscated_abc",
    ),
    pytest.param(
        DeobfuscationCase(
            function="mixed_dispatcher_pattern",
            project="flatfold.json",
            must_change=False,
            check_stats=False,
        ),
        id="flatfold",
    ),
    pytest.param(
        # Nested two-level Hodur dispatcher, restored by the multi-entry
        # state-write recovery (d81-m0qo). Unlike the other batch cases this
        # one asserts must_change=True: the fix collapses it to a returning
        # arithmetic expression, so the routed config-v2 path must change it.
        DeobfuscationCase(
            function="nested_while_hodur_pattern",
            project="example_hodur.json",
            must_change=True,
            check_stats=False,
        ),
        id="example_hodur",
    ),
)

_EXPECTED_DEFAULT_RUNTIME_CONFIGS = {
    "default_instruction_only.json": (
        "default_instruction_only_config_v2_canary.json",
        (
            "mba-simplify",
            "global-constant-inliner",
            "jump-fixer",
        ),
    ),
    "default_unflattening_tigress_engine.json": (
        "default_unflattening_tigress_engine_config_v2_canary.json",
        (
            "recover_dispatcher",
            "recover_state_transitions",
            "plan_semantic_regions",
            "lower_state_machine",
            "cleanup_residual_dispatcher",
        ),
    ),
    "hodur_flag2.json": (
        "hodur_flag2_config_v2_canary.json",
        (
            "recover_dispatcher",
            "recover_state_transitions",
            "plan_semantic_regions",
            "lower_state_machine",
            "cleanup_residual_dispatcher",
            "jump-fixer",
        ),
    ),
    "hodur_glbopt2_only.json": (
        "hodur_glbopt2_only_config_v2_canary.json",
        (
            "recover_dispatcher",
            "recover_state_transitions",
            "plan_semantic_regions",
            "lower_state_machine",
            "cleanup_residual_dispatcher",
        ),
    ),
    "eidolon.json": (
        "eidolon_config_v2_canary.json",
        ("mba-simplify",),
    ),
    "default_unflattening_approov.json": (
        "default_unflattening_approov_config_v2_canary.json",
        (
            "mba-simplify",
            "mba-state-preconditioner",
            "recover_dispatcher",
            "recover_state_transitions",
            "plan_semantic_regions",
            "lower_state_machine",
            "cleanup_residual_dispatcher",
            "jump-fixer",
        ),
    ),
    "hodur_flag2_s1a.json": (
        "hodur_flag2_s1a_config_v2_canary.json",
        (
            "recover_dispatcher",
            "recover_state_transitions",
            "plan_semantic_regions",
            "lower_state_machine",
            "cleanup_residual_dispatcher",
            "jump-fixer",
        ),
    ),
    "default_unflattening_approov_s1a.json": (
        "default_unflattening_approov_s1a_config_v2_canary.json",
        (
            "mba-simplify",
            "mba-state-preconditioner",
            "recover_dispatcher",
            "recover_state_transitions",
            "plan_semantic_regions",
            "lower_state_machine",
            "cleanup_residual_dispatcher",
            "jump-fixer",
        ),
    ),
    "hodur_flag2_with_fcp.json": (
        "hodur_flag2_with_fcp_config_v2_canary.json",
        (
            "mba-simplify",
            "recover_dispatcher",
            "recover_state_transitions",
            "plan_semantic_regions",
            "lower_state_machine",
            "cleanup_residual_dispatcher",
            "jump-fixer",
            "forward-constant-propagation",
        ),
    ),
    "identity_call.json": (
        "identity_call_config_v2_canary.json",
        ("identity-call-resolver",),
    ),
    "default_unflattening_tigress_engine_transition_facts.json": (
        "default_unflattening_tigress_engine_transition_facts_config_v2_canary.json",
        (
            "mba-simplify",
            "forward-constant-propagation",
            "recover_dispatcher",
            "recover_state_transitions",
            "plan_semantic_regions",
            "lower_state_machine",
            "cleanup_residual_dispatcher",
        ),
    ),
    "example_libobfuscated_abc.json": (
        "example_libobfuscated_abc_config_v2_canary.json",
        (
            "mba-simplify",
            "forward-constant-propagation",
            "recover_dispatcher",
            "recover_state_transitions",
            "plan_semantic_regions",
            "lower_state_machine",
            "cleanup_residual_dispatcher",
            "jump-fixer",
        ),
    ),
    "flatfold.json": (
        "flatfold_config_v2_canary.json",
        (
            "mba-simplify",
            "mba-state-preconditioner",
            "global-constant-inliner",
            "jump-fixer",
            "recover_dispatcher",
            "recover_state_transitions",
            "plan_semantic_regions",
            "lower_state_machine",
            "cleanup_residual_dispatcher",
        ),
    ),
    "example_hodur.json": (
        "example_hodur_config_v2_canary.json",
        (
            "mba-simplify",
            "forward-constant-propagation",
            "recover_dispatcher",
            "recover_state_transitions",
            "plan_semantic_regions",
            "lower_state_machine",
            "cleanup_residual_dispatcher",
            "jump-fixer",
        ),
    ),
}


@pytest.fixture(scope="class")
def libobfuscated_setup(ida_database, configure_hexrays, setup_libobfuscated_funcs):
    if not idaapi.init_hexrays_plugin():
        pytest.skip("Hex-Rays decompiler plugin not available")
    return ida_database


class TestConfigV2CIRehearsalCoverage:
    """The CI rehearsal switch must cover every supported runner mapping."""

    binary_name = _get_default_binary()

    @pytest.mark.parametrize("case", _REHEARSAL_CASES)
    def test_supported_rehearsal_mapping_runs_through_config_v2_canary(
        self,
        case,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
        capture_stats,
        load_expected_stats,
    ):
        run_deobfuscation_test(
            case=case,
            d810_state=d810_state,
            pseudocode_to_string=pseudocode_to_string,
            code_comparator=code_comparator,
            capture_stats=capture_stats,
            load_expected_stats=load_expected_stats,
        )


class TestConfigV2SupportedDefaultRouting:
    """Supported bundled source configs route to config-v2 canaries by default."""

    binary_name = _get_default_binary()

    @pytest.mark.parametrize("case", _REHEARSAL_CASES)
    def test_supported_source_runs_through_config_v2_default(
        self,
        case,
        monkeypatch,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
        capture_stats,
        load_expected_stats,
    ):
        monkeypatch.delenv(CONFIG_V2_CI_REHEARSAL_ENV, raising=False)
        monkeypatch.delenv(CONFIG_V2_SUPPORTED_DEFAULTS_ENV, raising=False)

        run_deobfuscation_test(
            case=case,
            d810_state=d810_state,
            pseudocode_to_string=pseudocode_to_string,
            code_comparator=code_comparator,
            capture_stats=capture_stats,
            load_expected_stats=load_expected_stats,
        )

        from d810.manager import D810State

        state = D810State()
        expected_runtime_config, expected_pass_ids = _EXPECTED_DEFAULT_RUNTIME_CONFIGS[
            case.project
        ]
        assert state.current_project.path.name == case.project
        assert state.current_runtime_project.path.name == expected_runtime_config
        assert state.last_config_v2_default_selection is not None
        assert state.last_config_v2_default_selection.routed is True
        assert state.last_pipeline_v2_hook_mode == "config-v2"
        assert state.last_pipeline_v2_hook_pass_ids == expected_pass_ids
