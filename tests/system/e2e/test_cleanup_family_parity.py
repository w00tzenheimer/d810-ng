"""Focused parity checks for the non-Hodur cleanup family."""

from __future__ import annotations

import os
import platform

import pytest

import idaapi

from d810.testing.runner import _resolve_test_project_index, get_func_ea
from tests.system.e2e.test_approov_engine_wrapper_baselines import (
    _force_rule_scope_to_current_profile,
    _restore_forced_rule_scope,
)


pytestmark = [
    pytest.mark.e2e,
    pytest.mark.skip(
        reason=(
            "legacy cleanup parity is obsolete in the legacy-unflatteners-off "
            "ablation; use primary cleanup-family engine gates"
        )
    ),
]


CLEANUP_FAMILY_RULE = "SimpleFlatteningCleanupUnflattener"
LEGACY_CLEANUP_RULES = ("UnflattenerFakeJump", "SingleIterationLoopUnflattener")


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


def _decompile_without_d810(state, func_ea: int, pseudocode_to_string) -> str:
    state.stop_d810()
    cfunc = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
    assert cfunc is not None, f"Decompilation failed for function at 0x{func_ea:x}"
    return pseudocode_to_string(cfunc.get_pseudocode())


class _RuleScope:
    def __init__(self, state) -> None:
        self.active_ins_rules = list(state.current_ins_rules)
        self.active_blk_rules = list(state.current_blk_rules)


def _cfg_patch_counts(state, *rule_names: str) -> dict[str, tuple[int, ...]]:
    return {
        rule_name: tuple(state.stats.get_cfg_rule_patch_counts(rule_name))
        for rule_name in rule_names
    }


def _decompile_with_profile(
    state,
    func_ea: int,
    project_name: str,
    pseudocode_to_string,
    configure_profile,
) -> tuple[str, tuple[str, ...], dict[str, tuple[int, ...]]]:
    state.stop_d810()
    project_index = _resolve_test_project_index(state, project_name)
    state.load_project(project_index)
    with state.for_project(project_name) as ctx:
        configure_profile(ctx)
        state.stats.reset()
        state.start_d810()
        previous_override = _force_rule_scope_to_current_profile(
            state,
            _RuleScope(state),
            func_ea,
        )
        try:
            cfunc = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert cfunc is not None, (
                f"Decompilation with d810 failed for function at 0x{func_ea:x}"
            )
            rendered = pseudocode_to_string(cfunc.get_pseudocode())
            fired_rules = tuple(state.stats.get_fired_rule_names())
            patch_counts = _cfg_patch_counts(
                state,
                CLEANUP_FAMILY_RULE,
                *LEGACY_CLEANUP_RULES,
            )
        finally:
            _restore_forced_rule_scope(state, func_ea, previous_override)
    state.stop_d810()
    return rendered, fired_rules, patch_counts


def _use_legacy_cleanup_rule(legacy_rule: str):
    def configure(ctx) -> None:
        ctx.remove_rule(CLEANUP_FAMILY_RULE)
        if legacy_rule == "SingleIterationLoopUnflattener":
            ctx.add_rule("SingleIterationLoopUnflattener")

    return configure


def _use_cleanup_family(ctx) -> None:
    for rule_name in LEGACY_CLEANUP_RULES:
        ctx.remove_rule(rule_name)
    ctx.add_rule(CLEANUP_FAMILY_RULE)


class TestCleanupFamilyParity:
    """Compare engine cleanup against the legacy cleanup-only rules."""

    binary_name = _get_default_binary()

    @pytest.mark.parametrize(
        ("function_name", "project_name", "legacy_rule", "legacy_effect_rule"),
        (
            (
                "abc_f6_sub_dispatch",
                "example_libobfuscated_no_fixprecedessor.json",
                "UnflattenerFakeJump",
                "UnflattenerFakeJump",
            ),
            (
                "single_iteration_simple",
                "example_libobfuscated.json",
                "SingleIterationLoopUnflattener",
                "UnflattenerFakeJump",
            ),
        ),
        ids=("fake_jump", "single_iteration"),
    )
    def test_cleanup_family_matches_legacy_rule_on_real_fixture(
        self,
        function_name: str,
        project_name: str,
        legacy_rule: str,
        legacy_effect_rule: str,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
    ) -> None:
        assert code_comparator is not None, (
            "libclang required for cleanup-family semantic parity"
        )
        func_ea = get_func_ea(function_name)
        if func_ea == idaapi.BADADDR:
            pytest.skip(f"Function '{function_name}' not found")

        with d810_state() as state:
            code_before = _decompile_without_d810(state, func_ea, pseudocode_to_string)
            legacy_code, legacy_fired, legacy_patches = _decompile_with_profile(
                state,
                func_ea,
                project_name,
                pseudocode_to_string,
                _use_legacy_cleanup_rule(legacy_rule),
            )
            cleanup_code, cleanup_fired, cleanup_patches = _decompile_with_profile(
                state,
                func_ea,
                project_name,
                pseudocode_to_string,
                _use_cleanup_family,
            )

        assert any(legacy_patches[legacy_effect_rule]), (
            f"Selected legacy fixture did not exercise {legacy_effect_rule}; "
            f"fired_rules={legacy_fired}; patch_counts={legacy_patches}"
        )
        if legacy_effect_rule != legacy_rule:
            assert legacy_patches[legacy_rule] == (), (
                "The live SingleIteration fixture is currently simplified by "
                "FakeJump before SingleIterationLoopUnflattener records patches; "
                f"patch_counts={legacy_patches}"
            )
        assert any(cleanup_patches[CLEANUP_FAMILY_RULE]), (
            "Cleanup family did not run through the engine rule path; "
            f"fired_rules={cleanup_fired}; patch_counts={cleanup_patches}"
        )
        assert cleanup_patches["UnflattenerFakeJump"] == ()
        assert cleanup_patches["SingleIterationLoopUnflattener"] == ()
        assert cleanup_code != code_before, (
            "Cleanup family produced no visible fixture change despite CFG patches; "
            f"function={function_name}; patch_counts={cleanup_patches}"
        )
        assert code_comparator.are_equivalent(cleanup_code, legacy_code), (
            "Cleanup family output diverged from the cleanup-only legacy rule; "
            f"function={function_name}; "
            f"legacy_fired={legacy_fired}; cleanup_fired={cleanup_fired}; "
            f"legacy_patches={legacy_patches}; cleanup_patches={cleanup_patches}; "
            f"changed_before={{'legacy': {legacy_code != code_before}, "
            f"'cleanup': {cleanup_code != code_before}}}"
        )
