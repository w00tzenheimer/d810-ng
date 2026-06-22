"""Runtime parity evidence for supported config-v2 generated shadows."""
from __future__ import annotations

import os
import platform

import pytest

import idaapi

from d810.passes.pipeline_v2_hook_bridge import STATE_MACHINE_NATIVE_PASS_IDS
from tests.system.e2e.config_v2_parity_gate import (
    FINAL_POST_D810_SNAPSHOT_LABEL,
    ConfigV2ParityRow,
    assert_config_v2_runtime_parity,
)


_PARITY_ROWS = (
    pytest.param(
        ConfigV2ParityRow(
            row_id="default_instruction_only_mba",
            legacy_config="default_instruction_only.json",
            shadow_config="default_instruction_only.pipeline_v2.json",
            function_name="test_chained_add",
            expected_pass_ids=(
                "mba-simplify",
                "global-constant-inliner",
                "jump-fixer",
            ),
            expects_state_machine=False,
            required_snapshot_label=None,
        ),
        id="default_instruction_only_mba",
    ),
    pytest.param(
        ConfigV2ParityRow(
            row_id="default_instruction_only_config_v2_canary_mba",
            legacy_config="default_instruction_only.json",
            shadow_config="default_instruction_only.pipeline_v2.json",
            runtime_config="default_instruction_only_config_v2_canary.json",
            function_name="test_chained_add",
            expected_pass_ids=(
                "mba-simplify",
                "global-constant-inliner",
                "jump-fixer",
            ),
            expects_state_machine=False,
            required_snapshot_label=None,
        ),
        id="default_instruction_only_config_v2_canary_mba",
    ),
    pytest.param(
        ConfigV2ParityRow(
            row_id="eidolon_mba_instruction_heavy",
            legacy_config="eidolon.json",
            shadow_config="eidolon.pipeline_v2.json",
            function_name="test_mba_guessing",
            expected_pass_ids=("mba-simplify",),
            expects_state_machine=False,
            required_snapshot_label=None,
        ),
        id="eidolon_mba_instruction_heavy",
    ),
    pytest.param(
        ConfigV2ParityRow(
            row_id="tigress_engine_spine",
            legacy_config="default_unflattening_tigress_engine.json",
            shadow_config="default_unflattening_tigress_engine.pipeline_v2.json",
            function_name="tigress_minmaxarray",
            expected_pass_ids=STATE_MACHINE_NATIVE_PASS_IDS,
            expects_state_machine=True,
            required_snapshot_label=None,
        ),
        id="tigress_engine_spine",
    ),
    pytest.param(
        ConfigV2ParityRow(
            row_id="tigress_engine_config_v2_canary_spine",
            legacy_config="default_unflattening_tigress_engine.json",
            shadow_config="default_unflattening_tigress_engine.pipeline_v2.json",
            runtime_config="default_unflattening_tigress_engine_config_v2_canary.json",
            function_name="tigress_minmaxarray",
            expected_pass_ids=STATE_MACHINE_NATIVE_PASS_IDS,
            expects_state_machine=True,
            required_snapshot_label=None,
        ),
        id="tigress_engine_config_v2_canary_spine",
    ),
    pytest.param(
        ConfigV2ParityRow(
            row_id="approov_mixed_spine_flow",
            legacy_config="default_unflattening_approov.json",
            shadow_config="default_unflattening_approov.pipeline_v2.json",
            function_name="approov_vm_dispatcher",
            expected_pass_ids=(
                "mba-simplify",
                "mba-state-preconditioner",
                *STATE_MACHINE_NATIVE_PASS_IDS,
                "jump-fixer",
            ),
            expects_state_machine=True,
            required_snapshot_label=None,
        ),
        id="approov_mixed_spine_flow",
    ),
    pytest.param(
        ConfigV2ParityRow(
            row_id="hodur_glbopt2_only_spine",
            legacy_config="hodur_glbopt2_only.json",
            shadow_config="hodur_glbopt2_only.pipeline_v2.json",
            function_name="hodur_func",
            expected_pass_ids=STATE_MACHINE_NATIVE_PASS_IDS,
            expects_state_machine=True,
            required_snapshot_label=FINAL_POST_D810_SNAPSHOT_LABEL,
        ),
        id="hodur_glbopt2_only_spine",
    ),
    pytest.param(
        ConfigV2ParityRow(
            row_id="hodur_flag2_mixed",
            legacy_config="hodur_flag2.json",
            shadow_config="hodur_flag2.pipeline_v2.json",
            function_name="hodur_func",
            expected_pass_ids=(
                *STATE_MACHINE_NATIVE_PASS_IDS,
                "jump-fixer",
            ),
            expects_state_machine=True,
            required_snapshot_label=FINAL_POST_D810_SNAPSHOT_LABEL,
        ),
        id="hodur_flag2_mixed",
    ),
    pytest.param(
        ConfigV2ParityRow(
            row_id="hodur_flag2_s1a_mixed",
            legacy_config="hodur_flag2_s1a.json",
            shadow_config="hodur_flag2_s1a.pipeline_v2.json",
            function_name="hodur_func",
            expected_pass_ids=(
                *STATE_MACHINE_NATIVE_PASS_IDS,
                "jump-fixer",
            ),
            expects_state_machine=True,
            required_snapshot_label=FINAL_POST_D810_SNAPSHOT_LABEL,
        ),
        id="hodur_flag2_s1a_mixed",
    ),
    pytest.param(
        ConfigV2ParityRow(
            row_id="hodur_flag2_with_fcp_mixed",
            legacy_config="hodur_flag2_with_fcp.json",
            shadow_config="hodur_flag2_with_fcp.pipeline_v2.json",
            function_name="hodur_func",
            expected_pass_ids=(
                "mba-simplify",
                *STATE_MACHINE_NATIVE_PASS_IDS,
                "jump-fixer",
                "forward-constant-propagation",
            ),
            expects_state_machine=True,
            required_snapshot_label=FINAL_POST_D810_SNAPSHOT_LABEL,
        ),
        id="hodur_flag2_with_fcp_mixed",
    ),
    pytest.param(
        ConfigV2ParityRow(
            row_id="hodur_flag2_config_v2_canary_mixed",
            legacy_config="hodur_flag2.json",
            shadow_config="hodur_flag2.pipeline_v2.json",
            runtime_config="hodur_flag2_config_v2_canary.json",
            function_name="hodur_func",
            expected_pass_ids=(
                *STATE_MACHINE_NATIVE_PASS_IDS,
                "jump-fixer",
            ),
            expects_state_machine=True,
            required_snapshot_label=FINAL_POST_D810_SNAPSHOT_LABEL,
        ),
        id="hodur_flag2_config_v2_canary_mixed",
    ),
    pytest.param(
        ConfigV2ParityRow(
            row_id="identity_call_explicit_adapter",
            legacy_config="identity_call.json",
            shadow_config="identity_call.pipeline_v2.json",
            function_name="identity_call_trampoline_chain",
            expected_pass_ids=("identity-call-resolver",),
            expects_state_machine=False,
            required_snapshot_label=None,
        ),
        id="identity_call_explicit_adapter",
    ),
    pytest.param(
        ConfigV2ParityRow(
            row_id="example_libobfuscated_no_fixprecedessor_cleanup",
            legacy_config="example_libobfuscated_no_fixprecedessor.json",
            shadow_config="example_libobfuscated_no_fixprecedessor.pipeline_v2.json",
            function_name="abc_f6_sub_dispatch",
            expected_pass_ids=(
                "mba-simplify",
                "forward-constant-propagation",
                "simple-flattening-cleanup-unflattener",
                "jump-fixer",
            ),
            expects_state_machine=False,
            required_snapshot_label=None,
        ),
        id="example_libobfuscated_no_fixprecedessor_cleanup",
    ),
    pytest.param(
        ConfigV2ParityRow(
            row_id="default_indirect_resolution_branch_call_branch",
            legacy_config="default_indirect_resolution.json",
            shadow_config="default_indirect_resolution.pipeline_v2.json",
            function_name="indirect_jump_table_xor",
            expected_pass_ids=(
                "indirect-branch-resolver",
                "indirect-call-resolver",
            ),
            expects_state_machine=False,
            required_snapshot_label=None,
        ),
        id="default_indirect_resolution_branch_call_branch",
    ),
    pytest.param(
        ConfigV2ParityRow(
            row_id="default_indirect_resolution_branch_call_call",
            legacy_config="default_indirect_resolution.json",
            shadow_config="default_indirect_resolution.pipeline_v2.json",
            function_name="indirect_call_hikari_mov_sub",
            expected_pass_ids=(
                "indirect-branch-resolver",
                "indirect-call-resolver",
            ),
            expects_state_machine=False,
            required_snapshot_label=None,
        ),
        id="default_indirect_resolution_branch_call_call",
    ),
)


def _get_default_binary() -> str:
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    return (
        "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"
    )


@pytest.fixture(scope="class")
def libobfuscated_setup(ida_database, configure_hexrays, setup_libobfuscated_funcs):
    if not idaapi.init_hexrays_plugin():
        pytest.skip("Hex-Rays decompiler plugin not available")
    return ida_database


class TestConfigV2RuntimeParity:
    """Config-v2 opt-in execution must match the legacy runtime source."""

    binary_name = _get_default_binary()

    @pytest.mark.parametrize("row", _PARITY_ROWS)
    def test_config_v2_runtime_matches_legacy(
        self,
        row: ConfigV2ParityRow,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
        request,
    ):
        from d810.core.settings import configure_settings, reset_settings

        configure_settings(
            diag_snapshots=True,
            capture_post_maturity=idaapi.MMAT_GLBOPT1,
        )
        request.addfinalizer(reset_settings)

        assert_config_v2_runtime_parity(
            row=row,
            d810_state=d810_state,
            pseudocode_to_string=pseudocode_to_string,
            code_comparator=code_comparator,
        )
