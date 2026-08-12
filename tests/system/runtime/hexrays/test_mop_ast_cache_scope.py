"""Regression coverage for MBA-owned operands in the global AST cache."""

from __future__ import annotations

import os
import platform
from types import SimpleNamespace

import ida_hexrays
import pytest

from d810.core.cymode import CythonMode
from d810.hexrays.ir.mop_snapshot import MopSnapshot
from d810.hexrays.ir import mop_utils


def _empty_operand() -> object:
    return SimpleNamespace(t=int(ida_hexrays.mop_z))


def _stack_operand(owner: int, offset: int = 0xA0) -> object:
    return SimpleNamespace(
        t=int(ida_hexrays.mop_S),
        s=SimpleNamespace(
            off=int(offset),
            mba=SimpleNamespace(this=int(owner)),
        ),
    )


def _nested_operand(stack: object) -> object:
    return SimpleNamespace(
        t=int(ida_hexrays.mop_d),
        d=SimpleNamespace(
            l=stack,
            r=_empty_operand(),
            d=_empty_operand(),
        ),
    )


def test_ast_cache_key_scopes_root_stack_operands_by_mba(monkeypatch) -> None:
    monkeypatch.setattr(mop_utils, "get_mop_key", lambda _mop: ("same",))

    assert mop_utils._mop_ast_cache_key(_stack_operand(0x1111)) != (
        mop_utils._mop_ast_cache_key(_stack_operand(0x2222))
    )


def test_ast_cache_key_scopes_nested_stack_operands_by_mba(monkeypatch) -> None:
    monkeypatch.setattr(mop_utils, "get_mop_key", lambda _mop: ("same",))

    assert mop_utils._mop_ast_cache_key(
        _nested_operand(_stack_operand(0x1111))
    ) != mop_utils._mop_ast_cache_key(_nested_operand(_stack_operand(0x2222)))


@pytest.mark.parametrize("nested", (False, True))
def test_cython_ast_cache_key_scopes_stack_operands_by_mba(
    monkeypatch,
    nested: bool,
) -> None:
    if not CythonMode().is_enabled():
        pytest.skip("Cython speedups are disabled for this runtime")
    c_ast = pytest.importorskip("d810.speedups.expr.c_ast")
    monkeypatch.setattr(c_ast, "get_mop_key", lambda _mop: ("same",))
    first = _stack_operand(0x1111)
    second = _stack_operand(0x2222)
    if nested:
        first = _nested_operand(first)
        second = _nested_operand(second)

    assert c_ast._mop_ast_cache_key(first) != c_ast._mop_ast_cache_key(second)


class TestCythonAstMopSnapshot:
    binary_name = os.environ.get(
        "D810_TEST_BINARY",
        "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll",
    )

    def test_leaf_materializes_register_snapshot(self, ida_database) -> None:
        """Cython replacements must turn a cached operand back into a live mop_t."""
        if not CythonMode().is_enabled():
            pytest.skip("Cython speedups are disabled for this runtime")
        c_ast = pytest.importorskip("d810.speedups.expr.c_ast")
        leaf = c_ast.AstLeaf("register")
        leaf.mop = MopSnapshot(t=ida_hexrays.mop_r, size=4, reg=1)

        materialized = leaf.create_mop(0x401000)

        assert materialized.t == ida_hexrays.mop_r
        assert materialized.r == 1
        assert materialized.size == 4
