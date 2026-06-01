"""Portable tests for use-def-safe redirect filtering (no IDA)."""
from __future__ import annotations

from d810.capabilities.use_def_safety import SeveranceViolation
from d810.transforms.graph_modification import RedirectGoto
from d810.transforms.use_def_redirect_filter import (
    filter_use_def_severing_redirects,
)

STATE_VAR = 0x3C


def _goto(frm: int) -> RedirectGoto:
    return RedirectGoto(from_serial=frm, old_target=frm + 100, new_target=frm + 200)


class _FakeUseDef:
    """Returns a fixed violation tuple for every redirect (intent ignored)."""

    def __init__(self, violations=()):
        self._violations = tuple(violations)

    def redirect_use_def_violations(self, mod, live_function, pre_cfg):
        return self._violations


def _violation(var_stkoff: int) -> SeveranceViolation:
    return SeveranceViolation(
        src_block=1,
        new_target=3,
        var_stkoff=var_stkoff,
        var_size=4,
        use_block=9,
        use_ea=0x1000,
    )


def test_no_capability_keeps_all():
    mods = [_goto(1), _goto(2)]
    out = filter_use_def_severing_redirects(
        mods, use_def_safety=None, live_function=None, pre_cfg=None
    )
    assert out == mods


def test_no_live_function_keeps_all():
    mods = [_goto(1)]
    out = filter_use_def_severing_redirects(
        mods, use_def_safety=_FakeUseDef(), live_function=None, pre_cfg=None
    )
    assert out == mods


def test_vetoes_non_state_var_severance():
    mods = [_goto(1)]
    cap = _FakeUseDef([_violation(0x100)])  # non-state-var use orphaned -> drop
    out = filter_use_def_severing_redirects(
        mods,
        use_def_safety=cap,
        live_function=object(),
        pre_cfg=None,
        state_var_stkoff=STATE_VAR,
    )
    assert out == []


def test_state_var_severance_is_kept():
    mods = [_goto(1)]
    cap = _FakeUseDef([_violation(STATE_VAR)])  # only the state var -> the unflattening
    out = filter_use_def_severing_redirects(
        mods,
        use_def_safety=cap,
        live_function=object(),
        pre_cfg=None,
        state_var_stkoff=STATE_VAR,
    )
    assert out == mods


def test_no_violations_keeps_all():
    mods = [_goto(1), _goto(2)]
    out = filter_use_def_severing_redirects(
        mods,
        use_def_safety=_FakeUseDef([]),
        live_function=object(),
        pre_cfg=None,
        state_var_stkoff=STATE_VAR,
    )
    assert out == mods
