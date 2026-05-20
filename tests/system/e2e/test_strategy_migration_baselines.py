"""Retired characterization baselines for extracted engine-wrapper migrations.

These tests compare the legacy rule path against the extracted engine-wrapper
path on real libobfuscated fixtures. The expectations intentionally lock the
current behavior rather than claiming full parity.

When a non-parity case fails, first check the primary correctness gate for that
fixture. If the primary gate still passes and no semantic oracle regressed, this
test usually needs a characterization refresh, not an optimizer repair.

The legacy-off ablation branch intentionally removes the legacy side of this
comparison. Keeping this class as a gate would compare the engine to itself or
to stale expectations. Use the primary fixture gates instead.
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


pytestmark = pytest.mark.skip(
    reason=(
        "legacy-vs-engine migration characterization is obsolete in the "
        "legacy-unflatteners-off ablation; use primary fixture gates"
    )
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
)

HODUR_ENGINE_WRAPPER_CASES = (
    ("_hodur_func", "example_libobfuscated.json"),
)

SINGLE_ITERATION_CASES = (
    ("single_iteration_simple", "example_libobfuscated.json"),
    ("single_iteration_residual", "example_libobfuscated.json"),
    ("single_iteration_state_machine", "example_libobfuscated.json"),
)

CHARACTERIZATION_RUNTIME_KEYS = (
    "legacy_project",
    "legacy_changed",
    "engine_changed",
    "engine_matches_legacy",
    "legacy_ast",
    "engine_ast",
)

INSPECT_AND_REFRESH = (
    "Inspect the engine-wrapper output. If the primary correctness gate and any "
    "semantic oracle still pass, refresh this characterization instead of "
    "treating the drift as a correctness regression."
)

HODUR_CHARACTERIZATION_ACTION = (
    "This is not the primary Hodur correctness gate. First run "
    "tests/system/e2e/test_hodur_baselines.py::"
    "TestHodurBaselines::test_hodur_baseline[hodur_func]. If that passes and "
    "no semantic oracle regressed, refresh this engine-wrapper characterization."
)

# These baselines lock current engine-wrapper-only behavior against the legacy
# rule output; they are not all parity claims.
FAKE_JUMP_BASELINES = {
    "abc_f6_sub_dispatch": {
        "purpose": "fake_jump_engine_wrapper_characterization_not_parity",
        "action_on_failure": INSPECT_AND_REFRESH,
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
        "purpose": "fake_jump_engine_wrapper_parity_characterization",
        "action_on_failure": INSPECT_AND_REFRESH,
        "legacy_project": "example_libobfuscated.json",
        "legacy_changed": True,
        "engine_changed": True,
        "engine_matches_legacy": True,
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

HODUR_ENGINE_WRAPPER_BASELINES = {
    "_hodur_func": {
        "purpose": "hodur_engine_wrapper_coverage_characterization_not_parity",
        "action_on_failure": HODUR_CHARACTERIZATION_ACTION,
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
            "statements": 40,
            "returns": 3,
            "whiles": 0,
            "gotos": 0,
            "ifs": 11,
            "calls": 2,
        },
    },
}

SINGLE_ITERATION_BASELINES = {
    "single_iteration_simple": {
        "purpose": "single_iteration_engine_wrapper_characterization_not_parity",
        "action_on_failure": INSPECT_AND_REFRESH,
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
        "purpose": "single_iteration_engine_wrapper_characterization_not_parity",
        "action_on_failure": INSPECT_AND_REFRESH,
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
        "purpose": "single_iteration_engine_wrapper_characterization_not_parity",
        "action_on_failure": INSPECT_AND_REFRESH,
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


def _runtime_expectation(expected: dict) -> dict:
    return {key: expected[key] for key in CHARACTERIZATION_RUNTIME_KEYS}


def _assert_engine_wrapper_characterization(
    *,
    label: str,
    function_name: str,
    observed: dict,
    expected: dict,
) -> None:
    expected_runtime = _runtime_expectation(expected)
    assert observed == expected_runtime, (
        f"{label} engine-wrapper characterization changed for {function_name}.\n"
        f"purpose={expected['purpose']}\n"
        f"action_on_failure={expected['action_on_failure']}\n"
        f"removed_legacy_rules={ENGINE_WRAPPER_REMOVED_RULES}\n"
        f"observed={observed}\n"
        f"expected={expected_runtime}"
    )


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


def _observe_engine_wrapper_characterization(
    *,
    function_name: str,
    project_name: str,
    d810_state,
    pseudocode_to_string,
    code_comparator,
) -> dict:
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

    return {
        "legacy_project": project_name,
        "legacy_changed": legacy_code != code_before,
        "engine_changed": engine_code != code_before,
        "engine_matches_legacy": code_comparator.are_equivalent(
            engine_code, legacy_code
        ),
        "legacy_ast": code_comparator.count_ast_statements(legacy_code),
        "engine_ast": code_comparator.count_ast_statements(engine_code),
    }


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
    def test_fake_jump_engine_wrapper_characterization(
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
        observed = _observe_engine_wrapper_characterization(
            function_name=function_name,
            project_name=project_name,
            d810_state=d810_state,
            pseudocode_to_string=pseudocode_to_string,
            code_comparator=code_comparator,
        )
        expected = FAKE_JUMP_BASELINES[function_name]

        print(
            "FAKE_JUMP_ENGINE_WRAPPER_CHARACTERIZATION "
            f"function={function_name} "
            f"purpose={expected['purpose']} "
            f"observed={observed}"
        )

        _assert_engine_wrapper_characterization(
            label="FakeJump",
            function_name=function_name,
            observed=observed,
            expected=expected,
        )

    @pytest.mark.parametrize(
        ("function_name", "project_name"),
        HODUR_ENGINE_WRAPPER_CASES,
        ids=[case[0] for case in HODUR_ENGINE_WRAPPER_CASES],
    )
    def test_hodur_engine_wrapper_characterization(
        self,
        function_name: str,
        project_name: str,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
    ) -> None:
        assert code_comparator is not None, (
            "libclang required for Hodur engine-wrapper characterization"
        )
        observed = _observe_engine_wrapper_characterization(
            function_name=function_name,
            project_name=project_name,
            d810_state=d810_state,
            pseudocode_to_string=pseudocode_to_string,
            code_comparator=code_comparator,
        )
        expected = HODUR_ENGINE_WRAPPER_BASELINES[function_name]

        print(
            "HODUR_ENGINE_WRAPPER_CHARACTERIZATION "
            f"function={function_name} "
            f"purpose={expected['purpose']} "
            f"observed={observed}"
        )

        _assert_engine_wrapper_characterization(
            label="Hodur",
            function_name=function_name,
            observed=observed,
            expected=expected,
        )

    @pytest.mark.parametrize(
        ("function_name", "project_name"),
        SINGLE_ITERATION_CASES,
        ids=[case[0] for case in SINGLE_ITERATION_CASES],
    )
    def test_single_iteration_engine_wrapper_characterization(
        self,
        function_name: str,
        project_name: str,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
    ) -> None:
        assert code_comparator is not None, (
            "libclang required for SingleIteration engine-wrapper characterization"
        )
        observed = _observe_engine_wrapper_characterization(
            function_name=function_name,
            project_name=project_name,
            d810_state=d810_state,
            pseudocode_to_string=pseudocode_to_string,
            code_comparator=code_comparator,
        )
        expected = SINGLE_ITERATION_BASELINES[function_name]

        print(
            "SINGLE_ITERATION_ENGINE_WRAPPER_CHARACTERIZATION "
            f"function={function_name} "
            f"purpose={expected['purpose']} "
            f"observed={observed}"
        )

        _assert_engine_wrapper_characterization(
            label="SingleIteration",
            function_name=function_name,
            observed=observed,
            expected=expected,
        )
