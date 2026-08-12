"""Regression coverage for MBA-owned operands in the global AST cache."""

from __future__ import annotations

from types import SimpleNamespace

import ida_hexrays
import pytest

from d810.core.cymode import CythonMode
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
