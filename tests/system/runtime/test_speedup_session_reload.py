"""Exercise the session-only Cython policy across production reload ordering."""

from __future__ import annotations

import os

import pytest

from d810._vendor.ida_reloader import reload_package
from d810.core.cymode import CythonMode
from d810.hexrays.expr import ast as ast_dispatcher
from d810.optimizers.microcode.instructions.pattern_matching import (
    engine as pattern_dispatcher,
)


_RELOAD_GATE_ENV = "D810_RELOAD_GATE"


def _reload_gate_enabled() -> bool:
    """Require an explicit standalone-process opt-in for package reloads.

    ``reload_package`` replaces live module/class identities.  Forking a
    multithreaded IDA process to contain that mutation is unsafe, so this test
    must run in its own runner process with ``D810_RELOAD_GATE=1``.
    """

    return os.environ.get(_RELOAD_GATE_ENV) == "1"


def _reload_through_production_package_ordering() -> None:
    """Use the full-package ordering called by ``D810Plugin.reload``."""
    import d810

    reload_package(
        d810,
        skip=["d810.core.registry", "d810._vendor"],
        suppress_errors=False,
    )


def test_reload_gate_is_explicitly_opt_in(monkeypatch) -> None:
    monkeypatch.delenv(_RELOAD_GATE_ENV, raising=False)
    assert _reload_gate_enabled() is False

    monkeypatch.setenv(_RELOAD_GATE_ENV, "1")
    assert _reload_gate_enabled() is True


def test_session_cython_policy_rebinds_core_dispatchers_after_reload() -> None:
    if not _reload_gate_enabled():
        pytest.skip(
            "package reload is standalone-only; set D810_RELOAD_GATE=1 in a "
            "dedicated runner process"
        )

    mode = CythonMode()
    original_enabled = mode.is_enabled()
    try:
        mode.enable()
        _reload_through_production_package_ordering()
        assert ast_dispatcher._USING_CYTHON is True
        assert pattern_dispatcher.get_engine_info()["backend"] == "cython"

        mode.disable()
        _reload_through_production_package_ordering()
        assert ast_dispatcher._USING_CYTHON is False
        assert pattern_dispatcher.get_engine_info()["backend"] == "python"

        mode.enable()
        _reload_through_production_package_ordering()
        assert ast_dispatcher._USING_CYTHON is True
        assert pattern_dispatcher.get_engine_info()["backend"] == "cython"
    finally:
        if mode.is_enabled() != original_enabled:
            if original_enabled:
                mode.enable()
            else:
                mode.disable()
            _reload_through_production_package_ordering()
