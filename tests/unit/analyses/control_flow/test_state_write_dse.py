"""Tests for render-level dead dispatcher-state-write elimination."""
from __future__ import annotations

from d810.analyses.control_flow.state_write_dse import (
    infer_state_var_name,
    prune_dead_state_writes,
)

# sub_7FFD3338C040 dispatcher state constants (subset).
STATE_CONSTS = {0x139F2922, 0x16F7FF74, 0x298372CC, 0x606DC166}


def test_infer_state_var_name_from_constant_assignments():
    payload = {
        14: ("var_680 = *var_6A8", "var_64 = 0x139F2922"),
        20: ("/* assert */ var_64 = 0x16F7FF74", "var_478 = var_680"),
        30: ("var_64 = 0x606DC166",),
    }
    assert infer_state_var_name(payload, STATE_CONSTS) == "var_64"


def test_infer_returns_none_without_state_consts():
    payload = {1: ("var_64 = 0x139F2922",)}
    assert infer_state_var_name(payload, set()) is None


def test_prune_drops_state_var_assignments_constant_and_computed():
    lines = (
        "var_680 = *var_6A8",
        "var_64 = 0x139F2922",
        "/* assert */ var_64 = 0x139F2922",
        "var_64 = (var_770 ^ var_778) - var_780",  # computed state write
        "var_670 = var_3E8 + var_3F0",  # live
    )
    out = prune_dead_state_writes(lines, "var_64", STATE_CONSTS)
    assert out == ("var_680 = *var_6A8", "var_670 = var_3E8 + var_3F0")


def test_prune_drops_leaked_state_constant_write_noise():
    # The cosmetic 0x298372CC dead state-write is removed.
    lines = ("var_64 = 0x298372CC", "/* assert */ var_64 = 0x298372CC", "x = y + 1")
    out = prune_dead_state_writes(lines, "var_64", STATE_CONSTS)
    assert out == ("x = y + 1",)
    assert all("298372CC" not in line for line in out)


def test_prune_bare_const_fallback_without_name():
    # Even when the name can't be inferred, bare state-constant writes are dropped.
    lines = ("var_64 = 0x139F2922", "real = compute()")
    out = prune_dead_state_writes(lines, None, STATE_CONSTS)
    assert out == ("real = compute()",)


def test_prune_preserves_non_state_constant_returns():
    # A real 64-bit constant return value is NOT a dispatcher state -> preserved.
    lines = ("var_8 = 0xC5FB34A1D9A6E315", "var_8 = a5 + 0xD0")
    out = prune_dead_state_writes(lines, "var_64", STATE_CONSTS)
    assert out == lines  # neither is a state constant; both kept
