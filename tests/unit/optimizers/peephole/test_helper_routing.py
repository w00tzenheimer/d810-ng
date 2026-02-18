"""Unit tests: peephole rules route helper lookup through HelperRegistry.

Phase 4 of the evaluator refactor replaces ``getattr(rotate_helpers, name, None)``
in :class:`RotateHelperInlineRule` and :class:`ConstantCallResultFoldRule` with
``get_registry().lookup(name)``.  These tests verify that the lookup is driven
by the registry so that injecting a custom helper is sufficient to change rule
behaviour — no monkey-patching of ``d810.core.bits`` needed.

No IDA dependencies.  The peephole rule classes import ``ida_hexrays`` at the
top level; we therefore mock that module so the import succeeds without an IDA
installation.  The actual ``check_and_replace`` methods are NOT exercised here
(they require live ``minsn_t`` objects); only the registry wiring is tested.
"""
from __future__ import annotations

import sys
import types
import unittest.mock as mock
from typing import Callable

import pytest


# ---------------------------------------------------------------------------
# Lightweight IDA stubs so the peephole modules can be imported without IDA.
# ---------------------------------------------------------------------------

def _install_ida_stubs() -> None:
    """Insert minimal stub modules for ida_hexrays and idaapi."""
    for mod_name in ("ida_hexrays", "idaapi"):
        if mod_name not in sys.modules:
            stub = types.ModuleType(mod_name)
            # Provide integer constants the peephole modules reference at
            # import time (e.g. MMAT_LOCOPT, m_mov, m_call, m_ldc, mop_r …).
            for attr in (
                "MMAT_LOCOPT", "MMAT_CALLS", "MMAT_GLBOPT1",
                "m_mov", "m_call", "m_ldc",
                "mop_r", "mop_l", "mop_S", "mop_v", "mop_d", "mop_h",
                "mop_f", "mop_n", "mop_z",
                "EQ_IGNSIZE",
            ):
                setattr(stub, attr, mock.MagicMock())
            # minsn_t and mop_t need to be instantiatable
            stub.minsn_t = mock.MagicMock  # type: ignore[attr-defined]
            stub.mop_t = mock.MagicMock  # type: ignore[attr-defined]
            sys.modules[mod_name] = stub


_install_ida_stubs()


# ---------------------------------------------------------------------------
# Import the modules under test AFTER stubs are in place.
# ---------------------------------------------------------------------------

from d810.evaluator.helpers import HelperRegistry, get_registry  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_spy_helper(name: str) -> Callable[[int, int], int]:
    """Return a callable that records calls and has a ``name`` attribute."""
    calls: list[tuple[int, int]] = []

    def spy(value: int, count: int) -> int:
        calls.append((value, count))
        return value ^ count  # arbitrary but deterministic result

    spy.name = name  # type: ignore[attr-defined]
    spy.calls = calls  # type: ignore[attr-defined]
    return spy


# ---------------------------------------------------------------------------
# Tests: registry is used, not getattr(bits, …)
# ---------------------------------------------------------------------------


class TestHelperRoutingViaRegistry:
    """Verify that peephole lookup goes through the HelperRegistry."""

    def test_get_registry_provides_rol4(self) -> None:
        """The singleton registry exposes __ROL4__ to callers."""
        reg = get_registry()
        fn = reg.lookup("__ROL4__")
        assert fn is not None
        assert callable(fn)

    def test_get_registry_returns_none_for_unknown(self) -> None:
        """Looking up an unregistered name returns None."""
        reg = get_registry()
        assert reg.lookup("__NONEXISTENT_HELPER__") is None

    def test_injected_helper_is_returned_by_lookup(self) -> None:
        """A helper injected into a fresh registry is immediately visible."""
        reg = HelperRegistry()
        spy = _make_spy_helper("__ROL4__")
        reg.register("__ROL4__", spy)
        result = reg.lookup("__ROL4__")
        assert result is spy

    def test_injected_helper_is_callable_and_records_invocation(self) -> None:
        """The injected spy can be called and tracks its invocations."""
        reg = HelperRegistry()
        spy = _make_spy_helper("__ROL4__")
        reg.register("__ROL4__", spy)
        fn = reg.lookup("__ROL4__")
        assert fn is not None
        fn(0xDEADBEEF, 8)
        assert spy.calls == [(0xDEADBEEF, 8)]  # type: ignore[attr-defined]

    @pytest.mark.parametrize("helper_name", [
        "__ROL1__", "__ROL2__", "__ROL4__", "__ROL8__",
        "__ROR1__", "__ROR2__", "__ROR4__", "__ROR8__",
    ])
    def test_all_rotate_helpers_present_in_singleton(self, helper_name: str) -> None:
        """The singleton registry is pre-populated with all 8 ROL/ROR helpers."""
        reg = get_registry()
        fn = reg.lookup(helper_name)
        assert fn is not None, f"singleton registry missing {helper_name}"
        assert callable(fn), f"{helper_name} is not callable"

    def test_fold_rotatehelper_imports_get_registry(self) -> None:
        """fold_rotatehelper.py source uses get_registry, not bits directly.

        Verified via source-level grep so no IDA runtime is required.
        """
        import pathlib
        src = pathlib.Path(
            "src/d810/optimizers/microcode/instructions/peephole/fold_rotatehelper.py"
        ).read_text()
        assert "get_registry" in src, (
            "fold_rotatehelper.py must import/use get_registry from evaluator.helpers"
        )
        assert "from d810.core import bits as rotate_helpers" not in src, (
            "fold_rotatehelper.py must not import 'd810.core.bits as rotate_helpers'"
        )

    def test_constant_call_imports_get_registry(self) -> None:
        """constant_call.py source uses get_registry, not bits directly."""
        import pathlib
        src = pathlib.Path(
            "src/d810/optimizers/microcode/instructions/peephole/constant_call.py"
        ).read_text()
        assert "get_registry" in src, (
            "constant_call.py must import/use get_registry from evaluator.helpers"
        )
        assert "from d810.core import bits as rotate_helpers" not in src, (
            "constant_call.py must not import 'd810.core.bits as rotate_helpers'"
        )

    def test_p_ast_does_not_import_rotate_helpers(self) -> None:
        """p_ast.py source must not contain the dead _rotate_helpers import."""
        import pathlib
        src = pathlib.Path("src/d810/expr/p_ast.py").read_text()
        assert "from d810.core import bits as _rotate_helpers" not in src, (
            "p_ast.py must not contain 'from d810.core import bits as _rotate_helpers'"
        )
