"""Normal-runner coverage for the explicit config-v2 CI rehearsal switch."""
from __future__ import annotations

import os
import platform

import pytest

import idaapi

from d810.testing import DeobfuscationCase
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
