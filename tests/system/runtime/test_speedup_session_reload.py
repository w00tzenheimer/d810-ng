"""Exercise the session-only Cython policy across production reload ordering."""

from __future__ import annotations

import pytest

from d810._vendor.ida_reloader import reload_package
from d810.core.cymode import CythonMode
from d810.hexrays.expr import ast as ast_dispatcher
from d810.optimizers.microcode.instructions.pattern_matching import (
    engine as pattern_dispatcher,
)


def _reload_through_production_package_ordering() -> None:
    """Use the full-package ordering called by ``D810Plugin.reload``."""
    import d810

    reload_package(
        d810,
        skip=["d810.core.registry", "d810._vendor"],
        suppress_errors=False,
    )


@pytest.mark.forked
def test_session_cython_policy_rebinds_core_dispatchers_after_reload() -> None:
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
