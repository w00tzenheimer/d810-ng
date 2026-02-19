"""Unit tests: peephole rules route helper lookup through _RotateHelper.

Phase 4 of the evaluator refactor replaces ``getattr(rotate_helpers, name, None)``
in :class:`RotateHelperInlineRule` and :class:`ConstantCallResultFoldRule` with
``_RotateHelper.lookup(name)``.  These tests verify that the lookup is driven
by the class-based Registrant registry.

No IDA dependencies.  The peephole rule classes import ``ida_hexrays`` at the
top level; we therefore mock that module so the import succeeds without an IDA
installation.  The actual ``check_and_replace`` methods are NOT exercised here
(they require live ``minsn_t`` objects); only the registry wiring is tested.
"""
from __future__ import annotations

import pytest

from d810.evaluator.helpers.rotate import _RotateHelper


# ---------------------------------------------------------------------------
# Tests: registry is used via _RotateHelper.lookup
# ---------------------------------------------------------------------------


class TestHelperRoutingViaRegistry:
    """Verify that peephole lookup goes through _RotateHelper."""

    def test_rotate_helper_provides_rol4(self) -> None:
        """The class registry exposes __ROL4__ to callers."""
        fn = _RotateHelper.lookup("__ROL4__")
        assert fn is not None
        assert callable(fn)

    def test_rotate_helper_returns_none_for_unknown(self) -> None:
        """Looking up an unregistered name returns None."""
        assert _RotateHelper.lookup("__NONEXISTENT_HELPER__") is None

    @pytest.mark.parametrize("helper_name", [
        "__ROL1__", "__ROL2__", "__ROL4__", "__ROL8__",
        "__ROR1__", "__ROR2__", "__ROR4__", "__ROR8__",
    ])
    def test_all_rotate_helpers_present(self, helper_name: str) -> None:
        """The class registry is pre-populated with all 8 ROL/ROR helpers."""
        fn = _RotateHelper.lookup(helper_name)
        assert fn is not None, f"_RotateHelper registry missing {helper_name}"
        assert callable(fn), f"{helper_name} is not callable"

    def test_fold_rotatehelper_imports_rotate_helper(self) -> None:
        """fold_rotatehelper.py source uses _RotateHelper.lookup, not bits directly.

        Verified via source-level grep so no IDA runtime is required.
        """
        import pathlib
        src = pathlib.Path(
            "src/d810/optimizers/microcode/instructions/peephole/fold_rotatehelper.py"
        ).read_text()
        assert "_RotateHelper" in src, (
            "fold_rotatehelper.py must import/use _RotateHelper from evaluator.helpers.rotate"
        )
        assert "from d810.core import bits as rotate_helpers" not in src, (
            "fold_rotatehelper.py must not import 'd810.core.bits as rotate_helpers'"
        )

    def test_constant_call_imports_rotate_helper(self) -> None:
        """constant_call.py source uses _RotateHelper.lookup, not bits directly."""
        import pathlib
        src = pathlib.Path(
            "src/d810/optimizers/microcode/instructions/peephole/constant_call.py"
        ).read_text()
        assert "_RotateHelper" in src, (
            "constant_call.py must import/use _RotateHelper from evaluator.helpers.rotate"
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
