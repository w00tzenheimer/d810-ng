"""Focused checks for the emulated-dispatcher engine family."""

from __future__ import annotations

import os
import platform

import pytest

import idaapi

from d810.testing.runner import _resolve_test_project_index, get_func_ea


pytestmark = [pytest.mark.e2e]

TEMP_ENGINE_WRAPPER_NOTES = "temporary engine-wrapper test profile"


def _get_default_binary() -> str:
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    return (
        "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"
    )


def _apply_engine_wrapper_profile(ctx) -> None:
    ctx.add_rule("HodurUnflattener")
    ctx.add_rule("EmulatedDispatcherUnflattener")


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
    if not idaapi.init_hexrays_plugin():
        pytest.skip("Hex-Rays decompiler plugin not available")
    return ida_database


def _decompile_with_engine_wrapper_profile(
    state,
    func_ea: int,
    pseudocode_to_string,
    *,
    project_name: str,
) -> tuple[str, tuple[str, ...], dict[str, object] | None]:
    state.stop_d810()
    project_index = _resolve_test_project_index(state, project_name)
    state.load_project(project_index)
    with state.for_project(project_name) as ctx:
        _apply_engine_wrapper_profile(ctx)
        dispatcher_rule = next(
            (
                rule
                for rule in ctx.active_blk_rules
                if type(rule).__name__ == "EmulatedDispatcherUnflattener"
            ),
            None,
        )
        state.stats.reset()
        state.start_d810()
        previous_override = _force_rule_scope_to_current_profile(state, ctx, func_ea)
        try:
            cfunc = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert cfunc is not None, (
                f"Decompilation with d810 failed for function at 0x{func_ea:x}"
            )
            rendered = pseudocode_to_string(cfunc.get_pseudocode())
            fired_rules = tuple(state.stats.get_fired_rule_names())
            gap_summary = (
                dispatcher_rule.get_last_observation()
                if dispatcher_rule is not None
                and hasattr(dispatcher_rule, "get_last_observation")
                else None
            )
        finally:
            _restore_forced_rule_scope(state, func_ea, previous_override)
    state.stop_d810()
    return rendered, fired_rules, gap_summary


class TestEmulatedDispatcherParity:
    """Focused checks for the emulated-dispatcher engine-wrapper profile."""

    binary_name = _get_default_binary()

    def test_approov_vm_dispatcher_engine_wrapper_matches_project_and_emits_guard(
        self,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
    ) -> None:
        assert code_comparator is not None, (
            "libclang required for explicit emulated-dispatcher parity assertions"
        )
        func_ea = get_func_ea("approov_vm_dispatcher")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'approov_vm_dispatcher' not found")

        with d810_state() as state:
            code_before = _decompile_without_d810(state, func_ea, pseudocode_to_string)
            legacy_code = _decompile_with_project(
                state,
                func_ea,
                "default_unflattening_approov.json",
                pseudocode_to_string,
                engine_wrappers_only=False,
            )
            code_after, _fired_rules, gap_summary = _decompile_with_engine_wrapper_profile(
                state,
                func_ea,
                pseudocode_to_string,
                project_name="default_unflattening_approov.json",
            )

        assert code_after != code_before
        assert code_comparator.are_equivalent(code_after, legacy_code)
        assert "while (" not in code_after
        assert "qword_18001D320 |= 0xF6A20uLL;" in code_after
        assert "if ( (_DWORD)qword_18001D320 == 0xF6A20 )" in code_after
        assert "dword_18001D318 = a1;" in code_after
        assert "dword_18001D318 += a1;" in code_after
        assert "qword_18001D320 |= 0x40uLL;" in code_after
        assert gap_summary is not None
