"""Regression baseline for Approov cases under the extracted engine path.

This test runs each Approov case twice:

1. The current bundled legacy project for the case.
2. A rule-filtered profile that removes the legacy CFG unflattening rules and
   enables ``HodurUnflattener`` so the extracted engine wrappers are the active
   CFF path.

The locked expectations capture the current semantic-match and AST-metric
baseline for the isolated engine-wrapper profile. They are intentionally a
characterization of the present gap, not a parity claim.
"""

from __future__ import annotations

import os
import platform

import pytest

import idaapi

from d810.testing.runner import (
    _resolve_test_project_index,
    get_binary_suffix,
    get_func_ea,
)
from d810.testing.skip_controls import should_skip_reason
from tests.system.cases.libobfuscated_comprehensive import APPROOV_CASES


ENGINE_WRAPPER_REMOVED_RULES = (
    "FixPredecessorOfConditionalJumpBlock",
    "Unflattener",
    "UnflattenerSwitchCase",
    "SingleIterationLoopUnflattener",
    "UnflattenerFakeJump",
    "BadWhileLoop",
)
TEMP_ENGINE_WRAPPER_NOTES = "temporary engine-wrapper test profile"

APPROOV_ENGINE_BASELINES = {
    "approov_real_pattern": {
        "legacy_project": "example_libobfuscated.json",
        "engine_matches_legacy": False,
        "engine_changed": True,
        "legacy_ast": {
            "statements": 3,
            "returns": 0,
            "whiles": 0,
            "gotos": 0,
            "ifs": 1,
            "calls": 0,
        },
        "engine_ast": {
            "statements": 6,
            "returns": 0,
            "whiles": 1,
            "gotos": 0,
            "ifs": 2,
            "calls": 0,
        },
    },
    "approov_simplified": {
        "legacy_project": "example_libobfuscated.json",
        "engine_matches_legacy": False,
        "engine_changed": True,
        "legacy_ast": {
            "statements": 2,
            "returns": 1,
            "whiles": 1,
            "gotos": 0,
            "ifs": 0,
            "calls": 0,
        },
        "engine_ast": {
            "statements": 5,
            "returns": 1,
            "whiles": 1,
            "gotos": 0,
            "ifs": 1,
            "calls": 0,
        },
    },
    "approov_multistate": {
        "legacy_project": "example_libobfuscated.json",
        "engine_matches_legacy": False,
        "engine_changed": True,
        "legacy_ast": {
            "statements": 5,
            "returns": 0,
            "whiles": 1,
            "gotos": 0,
            "ifs": 1,
            "calls": 0,
        },
        "engine_ast": {
            "statements": 6,
            "returns": 0,
            "whiles": 1,
            "gotos": 0,
            "ifs": 2,
            "calls": 0,
        },
    },
    "approov_vm_dispatcher": {
        "legacy_project": "default_unflattening_approov.json",
        "engine_matches_legacy": True,
        "engine_changed": False,
        "legacy_ast": {
            "statements": 4,
            "returns": 0,
            "whiles": 1,
            "gotos": 0,
            "ifs": 2,
            "calls": 0,
        },
        "engine_ast": {
            "statements": 4,
            "returns": 0,
            "whiles": 1,
            "gotos": 0,
            "ifs": 2,
            "calls": 0,
        },
    },
    "approov_simple_loop": {
        "legacy_project": "example_libobfuscated.json",
        "engine_matches_legacy": True,
        "engine_changed": True,
        "legacy_ast": {
            "statements": 1,
            "returns": 1,
            "whiles": 0,
            "gotos": 0,
            "ifs": 0,
            "calls": 0,
        },
        "engine_ast": {
            "statements": 1,
            "returns": 1,
            "whiles": 0,
            "gotos": 0,
            "ifs": 0,
            "calls": 0,
        },
    },
}


def _get_default_binary() -> str:
    """Get default binary name based on platform, with env var override."""
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    return (
        "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"
    )


def _apply_engine_wrapper_profile(ctx) -> None:
    """Replace legacy CFG unflattening rules with the extracted engine paths."""
    for rule_name in ENGINE_WRAPPER_REMOVED_RULES:
        ctx.remove_rule(rule_name)
    ctx.add_rule("HodurUnflattener")
    ctx.add_rule("EmulatedDispatcherUnflattener")


def _decompile_without_d810(state, func_ea: int, pseudocode_to_string) -> str:
    state.stop_d810()
    cfunc = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
    assert cfunc is not None, f"Decompilation failed for function at 0x{func_ea:x}"
    return pseudocode_to_string(cfunc.get_pseudocode())


def _force_rule_scope_to_current_profile(state, ctx, func_ea: int):
    manager = state.manager
    previous = manager.get_function_rule_override(func_ea)
    if (
        previous is not None
        and getattr(previous, "notes", "") == TEMP_ENGINE_WRAPPER_NOTES
        and not getattr(previous, "tags", set())
    ):
        manager.clear_function_rule_override(func_ea)
        previous = None
    enabled_rules = {
        str(rule.name)
        for rule in list(ctx.active_ins_rules) + list(ctx.active_blk_rules)
    }
    manager.set_function_rule_override(
        function_addr=func_ea,
        enabled_rules=enabled_rules,
        disabled_rules=set(),
        notes=TEMP_ENGINE_WRAPPER_NOTES,
    )
    return previous


def _restore_forced_rule_scope(state, func_ea: int, previous) -> None:
    manager = state.manager
    if previous is None:
        manager.clear_function_rule_override(func_ea)
        return
    if (
        getattr(previous, "notes", "") == TEMP_ENGINE_WRAPPER_NOTES
        and not getattr(previous, "tags", set())
    ):
        manager.clear_function_rule_override(func_ea)
        return
    if (
        not previous.enabled_rules
        and not previous.disabled_rules
        and not getattr(previous, "tags", set())
        and not getattr(previous, "notes", "")
    ):
        manager.clear_function_rule_override(func_ea)
        return
    manager.set_function_rule_override(
        function_addr=func_ea,
        enabled_rules=set(previous.enabled_rules),
        disabled_rules=set(previous.disabled_rules),
        notes=getattr(previous, "notes", ""),
    )


def _decompile_with_project(
    state,
    func_ea: int,
    project_name: str,
    pseudocode_to_string,
    *,
    engine_wrappers_only: bool,
) -> str:
    state.stop_d810()
    project_index = _resolve_test_project_index(state, project_name)
    state.load_project(project_index)
    with state.for_project(project_name) as ctx:
        if engine_wrappers_only:
            _apply_engine_wrapper_profile(ctx)
        state.stats.reset()
        state.start_d810()
        previous_override = _force_rule_scope_to_current_profile(state, ctx, func_ea)
        try:
            cfunc = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert cfunc is not None, (
                f"Decompilation with d810 failed for function at 0x{func_ea:x}"
            )
            rendered = pseudocode_to_string(cfunc.get_pseudocode())
        finally:
            _restore_forced_rule_scope(state, func_ea, previous_override)
    state.stop_d810()
    return rendered


@pytest.fixture(scope="class")
def libobfuscated_setup(ida_database, configure_hexrays, setup_libobfuscated_funcs):
    """Mirror the standard libobfuscated e2e setup fixture."""
    if not idaapi.init_hexrays_plugin():
        pytest.skip("Hex-Rays decompiler plugin not available")
    return ida_database


class TestApproovEngineWrapperBaselines:
    """Characterize Approov behavior under the extracted engine-wrapper path."""

    binary_name = _get_default_binary()

    @pytest.mark.parametrize("case", APPROOV_CASES, ids=lambda c: c.test_id)
    def test_approov_engine_wrapper_characterization(
        self,
        case,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
    ):
        assert code_comparator is not None, (
            "libclang required for engine-wrapper semantic baseline"
        )

        effective_case = case.get_effective_config(get_binary_suffix())
        if (
            effective_case.function != "approov_vm_dispatcher"
            and effective_case.skip
            and should_skip_reason(effective_case.skip)
        ):
            pytest.skip(effective_case.skip)

        func_ea = get_func_ea(effective_case.function)
        if func_ea == idaapi.BADADDR:
            pytest.skip(f"Function '{effective_case.function}' not found")

        with d810_state() as state:
            code_before = _decompile_without_d810(state, func_ea, pseudocode_to_string)
            legacy_code = _decompile_with_project(
                state,
                func_ea,
                effective_case.project,
                pseudocode_to_string,
                engine_wrappers_only=False,
            )
            engine_code = _decompile_with_project(
                state,
                func_ea,
                effective_case.project,
                pseudocode_to_string,
                engine_wrappers_only=True,
            )

        engine_matches_legacy = code_comparator.are_equivalent(engine_code, legacy_code)
        engine_changed = engine_code != code_before
        legacy_ast = code_comparator.count_ast_statements(legacy_code)
        engine_ast = code_comparator.count_ast_statements(engine_code)
        expected = APPROOV_ENGINE_BASELINES[effective_case.function]

        print(
            "APPROOV_ENGINE_BASELINE "
            f"function={effective_case.function} "
            f"legacy_project={effective_case.project} "
            f"engine_matches_legacy={engine_matches_legacy} "
            f"engine_changed={engine_changed} "
            f"legacy_ast={legacy_ast} "
            f"engine_ast={engine_ast}"
        )

        assert effective_case.project == expected["legacy_project"]
        assert engine_matches_legacy is expected["engine_matches_legacy"]
        assert engine_changed is expected["engine_changed"]
        assert legacy_ast == expected["legacy_ast"]
        assert engine_ast == expected["engine_ast"]
