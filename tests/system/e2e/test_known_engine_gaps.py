"""Explicit non-default failing tests for known extracted-engine gaps."""

from __future__ import annotations

import pytest

import idaapi

from d810.testing.runner import _resolve_test_project_index, get_func_ea
from tests.system.e2e.test_approov_engine_wrapper_baselines import (
    _apply_engine_wrapper_profile,
    _decompile_without_d810,
    _get_default_binary,
)


pytestmark = [pytest.mark.e2e, pytest.mark.known_gap]


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
) -> tuple[str, tuple[str, ...]]:
    state.stop_d810()
    project_index = _resolve_test_project_index(state, project_name)
    state.load_project(project_index)
    with state.for_project(project_name) as ctx:
        _apply_engine_wrapper_profile(ctx)
        state.stats.reset()
        state.start_d810()
        cfunc = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
        assert cfunc is not None, (
            f"Decompilation with d810 failed for function at 0x{func_ea:x}"
        )
        rendered = pseudocode_to_string(cfunc.get_pseudocode())
        fired_rules = tuple(state.stats.get_fired_rule_names())
    state.stop_d810()
    return rendered, fired_rules


class TestKnownEngineGaps:
    """Known extracted-engine gaps that should stay visible but non-default."""

    binary_name = _get_default_binary()

    def test_approov_vm_dispatcher_engine_wrapper_still_must_change(
        self,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
    ) -> None:
        func_ea = get_func_ea("approov_vm_dispatcher")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'approov_vm_dispatcher' not found")

        with d810_state() as state:
            code_before = _decompile_without_d810(state, func_ea, pseudocode_to_string)
            code_after, fired_rules = _decompile_with_engine_wrapper_profile(
                state,
                func_ea,
                pseudocode_to_string,
                project_name="default_unflattening_approov.json",
            )

        assert code_after != code_before, (
            "approov_vm_dispatcher is still unchanged under the isolated "
            f"engine-wrapper profile; fired_rules={fired_rules}"
        )
