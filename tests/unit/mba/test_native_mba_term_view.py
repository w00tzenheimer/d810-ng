"""Portable contract tests for the direct native MBA term view."""

from __future__ import annotations

from types import SimpleNamespace

from d810.backends.mba.native_mba_term_view import (
    NativeMbaTermView,
    NativeMopRuntime,
)
from d810.mba.island_profile import IslandBlocker


class _Mop:
    def __init__(
        self,
        kind: int,
        size: int,
        *,
        key: str | None = None,
        value: int | None = None,
        definition: _Insn | None = None,
    ) -> None:
        self.t = kind
        self.size = size
        self.key = key
        self.nnn = SimpleNamespace(value=value) if value is not None else None
        self.d = definition


class _Insn:
    def __init__(
        self,
        opcode: int,
        left: _Mop,
        right: _Mop | None,
        destination_size: int,
    ) -> None:
        self.opcode = opcode
        self.l = left
        self.r = right
        self.d = _Mop(_RUNTIME.mop_z, destination_size)


_RUNTIME = NativeMopRuntime(
    mop_z=0,
    mop_n=1,
    mop_d=2,
    leaf_kinds=frozenset({3}),
    operation_by_opcode={10: "add", 11: "and", 12: "bnot"},
    blocker_by_opcode={13: IslandBlocker.CAST},
    get_mop_key=lambda mop: (mop.key,),
)


def _leaf(key: str, size: int = 4) -> _Mop:
    return _Mop(3, size, key=key)


def _constant(value: int, size: int = 4) -> _Mop:
    return _Mop(_RUNTIME.mop_n, size, value=value)


def _nested(definition: _Insn, size: int = 4) -> _Mop:
    return _Mop(_RUNTIME.mop_d, size, definition=definition)


def test_direct_view_canonicalizes_ac_children_without_mutating_mops() -> None:
    right = _leaf("a")
    left = _leaf("b")
    instruction = _Insn(10, left, right, 4)

    result = NativeMbaTermView.from_instruction(
        instruction, destination_size=4, runtime=_RUNTIME
    )

    assert result.view is not None
    assert [child.leaf_key for child in result.view.canonical_children()] == [
        ("mop", "a"),
        ("mop", "b"),
    ]
    assert instruction.l is left
    assert instruction.r is right


def test_direct_view_recurses_mop_d_without_an_ast_adapter() -> None:
    x = _leaf("x")
    y = _leaf("y")
    nested = _Insn(11, x, y, 4)
    instruction = _Insn(10, _nested(nested), _constant(2), 4)

    result = NativeMbaTermView.from_instruction(
        instruction, destination_size=4, runtime=_RUNTIME
    )

    assert result.view is not None
    assert result.view.operation == "add"
    assert result.view.children[0].operation == "and"
    assert result.view.children[1].constant_value == 2


def test_direct_view_masks_constants_after_validating_width() -> None:
    instruction = _Insn(10, _leaf("x"), _constant(0x1_0000_0001), 4)

    result = NativeMbaTermView.from_instruction(
        instruction, destination_size=4, runtime=_RUNTIME
    )

    assert result.view is not None
    assert result.view.children[1].constant_value == 1


def test_direct_view_rejects_conflicting_mop_width() -> None:
    instruction = _Insn(10, _leaf("x", size=2), _leaf("y"), 4)

    result = NativeMbaTermView.from_instruction(
        instruction, destination_size=4, runtime=_RUNTIME
    )

    assert result.view is None
    assert result.profile.blockers == (IslandBlocker.MIXED_WIDTH,)


def test_direct_view_rejects_cast_and_unknown_mop_kinds() -> None:
    cast = _Insn(13, _leaf("x"), None, 4)
    cast_result = NativeMbaTermView.from_instruction(
        cast, destination_size=4, runtime=_RUNTIME
    )
    unknown = _Insn(10, _Mop(99, 4), _leaf("y"), 4)
    unknown_result = NativeMbaTermView.from_instruction(
        unknown, destination_size=4, runtime=_RUNTIME
    )

    assert cast_result.view is None
    assert cast_result.profile.blockers == (IslandBlocker.CAST,)
    assert unknown_result.view is None
    assert unknown_result.profile.blockers == (IslandBlocker.UNSUPPORTED_OPCODE,)
