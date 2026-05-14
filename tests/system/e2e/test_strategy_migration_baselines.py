"""Characterization baselines for extracted strategy migrations.

These tests compare the legacy rule path against the extracted engine-wrapper
path on real libobfuscated fixtures. The expectations intentionally lock the
current behavior rather than claiming full parity.
"""

from __future__ import annotations

import os
import platform

import pytest

import idaapi

from d810.testing.runner import (
    _resolve_test_project_index,
    get_func_ea,
)


ENGINE_WRAPPER_REMOVED_RULES = (
    "FixPredecessorOfConditionalJumpBlock",
    "Unflattener",
    "UnflattenerSwitchCase",
    "SingleIterationLoopUnflattener",
    "UnflattenerFakeJump",
    "BadWhileLoop",
)

FAKE_JUMP_CASES = (
    ("abc_f6_sub_dispatch", "example_libobfuscated_no_fixprecedessor.json"),
    ("abc_f6_or_dispatch", "example_libobfuscated.json"),
    ("_hodur_func", "example_libobfuscated.json"),
)

SINGLE_ITERATION_CASES = (
    ("single_iteration_simple", "example_libobfuscated.json"),
    ("single_iteration_residual", "example_libobfuscated.json"),
    ("single_iteration_state_machine", "example_libobfuscated.json"),
)

# The live Hodur engine-wrapper profile no longer registers the migrated
# FakeJump/SingleIteration cleanup strategies. These baselines lock that
# current behavior against the legacy rule output; they are not parity claims.
FAKE_JUMP_BASELINES = {
    "abc_f6_sub_dispatch": {
        "legacy_project": "example_libobfuscated_no_fixprecedessor.json",
        "legacy_changed": True,
        "engine_changed": False,
        "engine_matches_legacy": False,
        "legacy_ast": {
            "statements": 4,
            "returns": 2,
            "whiles": 0,
            "gotos": 0,
            "ifs": 1,
            "calls": 0,
        },
        "engine_ast": {
            "statements": 10,
            "returns": 2,
            "whiles": 1,
            "gotos": 0,
            "ifs": 5,
            "calls": 0,
        },
    },
    "abc_f6_or_dispatch": {
        "legacy_project": "example_libobfuscated.json",
        "legacy_changed": True,
        "engine_changed": False,
        "engine_matches_legacy": False,
        "legacy_ast": {
            "statements": 1,
            "returns": 1,
            "whiles": 0,
            "gotos": 0,
            "ifs": 0,
            "calls": 0,
        },
        "engine_ast": {
            "statements": 6,
            "returns": 1,
            "whiles": 1,
            "gotos": 0,
            "ifs": 1,
            "calls": 0,
        },
    },
    "_hodur_func": {
        "legacy_project": "example_libobfuscated.json",
        "legacy_changed": True,
        "engine_changed": True,
        "engine_matches_legacy": False,
        "legacy_ast": {
            "statements": 38,
            "returns": 3,
            "whiles": 0,
            "gotos": 1,
            "ifs": 7,
            "calls": 3,
        },
        "engine_ast": {
            "statements": 42,
            "returns": 3,
            "whiles": 1,
            "gotos": 1,
            "ifs": 10,
            "calls": 2,
        },
    },
}

SINGLE_ITERATION_BASELINES = {
    "single_iteration_simple": {
        "legacy_project": "example_libobfuscated.json",
        "legacy_changed": True,
        "engine_changed": False,
        "engine_matches_legacy": False,
        "legacy_ast": {
            "statements": 1,
            "returns": 1,
            "whiles": 0,
            "gotos": 0,
            "ifs": 0,
            "calls": 0,
        },
        "engine_ast": {
            "statements": 3,
            "returns": 1,
            "whiles": 0,
            "gotos": 0,
            "ifs": 0,
            "calls": 0,
        },
    },
    "single_iteration_residual": {
        "legacy_project": "example_libobfuscated.json",
        "legacy_changed": True,
        "engine_changed": False,
        "engine_matches_legacy": False,
        "legacy_ast": {
            "statements": 1,
            "returns": 1,
            "whiles": 0,
            "gotos": 0,
            "ifs": 0,
            "calls": 0,
        },
        "engine_ast": {
            "statements": 4,
            "returns": 1,
            "whiles": 0,
            "gotos": 0,
            "ifs": 0,
            "calls": 0,
        },
    },
    "single_iteration_state_machine": {
        "legacy_project": "example_libobfuscated.json",
        "legacy_changed": True,
        "engine_changed": True,
        "engine_matches_legacy": False,
        "legacy_ast": {
            "statements": 1,
            "returns": 1,
            "whiles": 0,
            "gotos": 0,
            "ifs": 0,
            "calls": 0,
        },
        "engine_ast": {
            "statements": 4,
            "returns": 1,
            "whiles": 1,
            "gotos": 0,
            "ifs": 1,
            "calls": 0,
        },
    },
}


def _get_default_binary() -> str:
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    return (
        "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"
    )


def _apply_engine_wrapper_profile(ctx) -> None:
    for rule_name in ENGINE_WRAPPER_REMOVED_RULES:
        ctx.remove_rule(rule_name)
    ctx.add_rule("HodurUnflattener")


def _decompile_without_d810(state, func_ea: int, pseudocode_to_string) -> str:
    state.stop_d810()
    cfunc = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
    assert cfunc is not None, f"Decompilation failed for function at 0x{func_ea:x}"
    return pseudocode_to_string(cfunc.get_pseudocode())


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
        cfunc = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
        assert cfunc is not None, (
            f"Decompilation with d810 failed for function at 0x{func_ea:x}"
        )
        rendered = pseudocode_to_string(cfunc.get_pseudocode())
    state.stop_d810()
    return rendered


@pytest.fixture(scope="class")
def libobfuscated_setup(ida_database, configure_hexrays, setup_libobfuscated_funcs):
    if not idaapi.init_hexrays_plugin():
        pytest.skip("Hex-Rays decompiler plugin not available")
    return ida_database


class TestStrategyMigrationBaselines:
    """Lock current legacy-vs-engine-wrapper migration behavior."""

    binary_name = _get_default_binary()

    @pytest.mark.parametrize(
        ("function_name", "project_name"),
        FAKE_JUMP_CASES,
        ids=[case[0] for case in FAKE_JUMP_CASES],
    )
    def test_fake_jump_migration_baseline(
        self,
        function_name: str,
        project_name: str,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
    ) -> None:
        assert code_comparator is not None, (
            "libclang required for FakeJump migration baseline"
        )
        func_ea = get_func_ea(function_name)
        if func_ea == idaapi.BADADDR:
            pytest.skip(f"Function '{function_name}' not found")

        with d810_state() as state:
            code_before = _decompile_without_d810(state, func_ea, pseudocode_to_string)
            legacy_code = _decompile_with_project(
                state,
                func_ea,
                project_name,
                pseudocode_to_string,
                engine_wrappers_only=False,
            )
            engine_code = _decompile_with_project(
                state,
                func_ea,
                project_name,
                pseudocode_to_string,
                engine_wrappers_only=True,
            )

        observed = {
            "legacy_project": project_name,
            "legacy_changed": legacy_code != code_before,
            "engine_changed": engine_code != code_before,
            "engine_matches_legacy": code_comparator.are_equivalent(
                engine_code, legacy_code
            ),
            "legacy_ast": code_comparator.count_ast_statements(legacy_code),
            "engine_ast": code_comparator.count_ast_statements(engine_code),
        }
        expected = FAKE_JUMP_BASELINES[function_name]

        print(
            "FAKE_JUMP_MIGRATION_BASELINE "
            f"function={function_name} "
            f"observed={observed}"
        )

        assert expected is not None, (
            f"Lock FakeJump baseline for {function_name}: {observed}"
        )
        assert observed == expected

    @pytest.mark.parametrize(
        ("function_name", "project_name"),
        SINGLE_ITERATION_CASES,
        ids=[case[0] for case in SINGLE_ITERATION_CASES],
    )
    def test_single_iteration_migration_baseline(
        self,
        function_name: str,
        project_name: str,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
    ) -> None:
        assert code_comparator is not None, (
            "libclang required for SingleIteration migration baseline"
        )
        func_ea = get_func_ea(function_name)
        if func_ea == idaapi.BADADDR:
            pytest.skip(f"Function '{function_name}' not found")

        with d810_state() as state:
            code_before = _decompile_without_d810(state, func_ea, pseudocode_to_string)
            legacy_code = _decompile_with_project(
                state,
                func_ea,
                project_name,
                pseudocode_to_string,
                engine_wrappers_only=False,
            )
            engine_code = _decompile_with_project(
                state,
                func_ea,
                project_name,
                pseudocode_to_string,
                engine_wrappers_only=True,
            )

        observed = {
            "legacy_project": project_name,
            "legacy_changed": legacy_code != code_before,
            "engine_changed": engine_code != code_before,
            "engine_matches_legacy": code_comparator.are_equivalent(
                engine_code, legacy_code
            ),
            "legacy_ast": code_comparator.count_ast_statements(legacy_code),
            "engine_ast": code_comparator.count_ast_statements(engine_code),
        }
        expected = SINGLE_ITERATION_BASELINES[function_name]

        print(
            "SINGLE_ITERATION_MIGRATION_BASELINE "
            f"function={function_name} "
            f"observed={observed}"
        )

        assert expected is not None, (
            f"Lock SingleIteration baseline for {function_name}: {observed}"
        )
        assert observed == expected
