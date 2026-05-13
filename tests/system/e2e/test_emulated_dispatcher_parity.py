"""Focused parity checks for the emulated-dispatcher engine family."""

from __future__ import annotations

import pytest

import idaapi

from d810.testing.runner import _resolve_test_project_index, get_func_ea
from tests.system.e2e.test_approov_engine_wrapper_baselines import (
    _apply_engine_wrapper_profile,
    _decompile_with_project,
    _decompile_without_d810,
    _force_rule_scope_to_current_profile,
    _get_default_binary,
    _restore_forced_rule_scope,
)


pytestmark = [pytest.mark.e2e]


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
    """Parity checks for the emulated-dispatcher engine-wrapper profile."""

    binary_name = _get_default_binary()

    def test_approov_vm_dispatcher_engine_wrapper_matches_legacy(
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
            code_after, fired_rules, gap_summary = _decompile_with_engine_wrapper_profile(
                state,
                func_ea,
                pseudocode_to_string,
                project_name="default_unflattening_approov.json",
            )

        assert code_comparator.are_equivalent(code_after, legacy_code), (
            "approov_vm_dispatcher still diverges from legacy under the isolated "
            "engine-wrapper profile; "
            f"fired_rules={fired_rules}; "
            f"dispatcher_observation={gap_summary}"
        )
