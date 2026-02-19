"""System/runtime tests for export_to_c action runtime behaviour.

These tests verify the context-manager and decompile helpers in
export_to_c by passing real idaapi where the function signature
accepts an idaapi-like shim.  The conftest.py for tests/system/runtime
automatically marks all items here as ida_required / runtime / hexrays.
"""
from __future__ import annotations

import pytest

try:
    import idaapi

    IDA_AVAILABLE = True
except ImportError:
    IDA_AVAILABLE = False

from d810.ui.actions import export_to_c


# ---------------------------------------------------------------------------
# test_temporary_hexrays_config_restores
# ---------------------------------------------------------------------------
# _temporary_hexrays_config accepts any object with change_hexrays_config.
# We pass real idaapi so IDA records the directive changes, and monkeypatch
# the restore-directive reader so the test is deterministic.
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not IDA_AVAILABLE, reason="Requires IDA Pro")
def test_temporary_hexrays_config_restores(monkeypatch):
    calls: list[str] = []
    original = idaapi.change_hexrays_config

    def _recording_change(directive: str) -> None:
        calls.append(directive)
        original(directive)

    monkeypatch.setattr(idaapi, "change_hexrays_config", _recording_change)
    monkeypatch.setattr(
        export_to_c,
        "_get_collapse_lvars_restore_directive",
        lambda: "COLLAPSE_LVARS = YES",
    )

    with export_to_c._temporary_hexrays_config(idaapi, "COLLAPSE_LVARS = NO"):
        assert calls == ["COLLAPSE_LVARS = NO"]

    assert calls == ["COLLAPSE_LVARS = NO", "COLLAPSE_LVARS = YES"]


# ---------------------------------------------------------------------------
# test_temporary_hexrays_config_no_restore_if_apply_fails
# ---------------------------------------------------------------------------
# Pass an object whose change_hexrays_config raises on the first call.
# The context manager must not attempt a restore in that case.
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not IDA_AVAILABLE, reason="Requires IDA Pro")
def test_temporary_hexrays_config_no_restore_if_apply_fails():
    class _FailingShim:
        def __init__(self):
            self.calls: list[str] = []

        def change_hexrays_config(self, directive: str) -> None:
            self.calls.append(directive)
            raise RuntimeError("boom")

    shim = _FailingShim()

    with export_to_c._temporary_hexrays_config(shim, "COLLAPSE_LVARS = NO"):
        pass

    assert shim.calls == ["COLLAPSE_LVARS = NO"]


# ---------------------------------------------------------------------------
# test_decompile_function_temporarily_disables_lvar_collapse
# ---------------------------------------------------------------------------
# Requires a loaded binary with a decompilable function.  Skip when no
# binary is open (BADADDR lookup fails or decompile returns None).
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not IDA_AVAILABLE, reason="Requires IDA Pro")
@pytest.mark.skip(reason="requires loaded binary with a decompilable function")
def test_decompile_function_temporarily_disables_lvar_collapse(monkeypatch):
    import idc

    func_ea = idc.get_name_ea_simple("main")
    if func_ea == idaapi.BADADDR:
        pytest.skip("No 'main' symbol in loaded binary")

    monkeypatch.setattr(
        export_to_c,
        "_get_collapse_lvars_restore_directive",
        lambda: "COLLAPSE_LVARS = YES",
    )

    result = export_to_c._decompile_function(func_ea, idaapi)

    assert result is not None
    func_name, lines = result
    assert func_name is not None
    assert len(lines) > 0
