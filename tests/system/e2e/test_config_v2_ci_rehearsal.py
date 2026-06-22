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
