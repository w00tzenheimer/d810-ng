"""Unit tests for the portable Varnode spine."""
from __future__ import annotations

import dataclasses

import pytest

from d810.ir.flowgraph import MopSnapshot, OperandKind
from d810.ir.mop_identity import mop_snapshot_key, mop_snapshot_offset
from d810.ir.varnode import (
    Space,
    Varnode,
    varnode_from_mop_snapshot,
    varnode_key,
    varnode_offset,
)


def test_keyed_spaces_emit_prefix_plus_offset() -> None:
    assert varnode_key(Varnode(Space.REGISTER, 3, 8)) == "r3"
    assert varnode_key(Varnode(Space.STACK, 2032, 8)) == "S2032"
    assert varnode_key(Varnode(Space.GLOBAL, 6144, 8)) == "v6144"
    assert varnode_key(Varnode(Space.LVAR, 8, 4)) == "l8"


def test_non_identity_spaces_have_no_key() -> None:
    assert varnode_key(Varnode(Space.CONST, 5, 8)) is None
    assert varnode_key(Varnode(Space.TEMP, 1, 8)) is None
    assert varnode_key(Varnode(Space.UNKNOWN, 0, 0)) is None
    assert varnode_key(None) is None


def test_offset_zero_for_non_identity_spaces() -> None:
    assert varnode_offset(Varnode(Space.REGISTER, 3, 8)) == 3
    assert varnode_offset(Varnode(Space.STACK, 2032, 8)) == 2032
    assert varnode_offset(Varnode(Space.CONST, 5, 8)) == 0
    assert varnode_offset(Varnode(Space.UNKNOWN, 0, 0)) == 0
    assert varnode_offset(None) == 0


def test_varnode_is_frozen_and_hashable() -> None:
    vn = Varnode(Space.REGISTER, 3, 8)
    assert {vn: 1}[vn] == 1
    with pytest.raises(dataclasses.FrozenInstanceError):
        vn.offset = 9  # type: ignore[misc]


def test_varnode_api_is_exported_from_ir_package() -> None:
    import d810.ir as ir

    assert ir.Space is Space
    assert ir.Varnode is Varnode
    assert ir.varnode_key is varnode_key
    assert ir.varnode_offset is varnode_offset


_MOPS = (
    MopSnapshot(kind=OperandKind.REGISTER, reg=3, size=8),
    MopSnapshot(kind=OperandKind.STACK, stkoff=2032, size=8),
    MopSnapshot(kind=OperandKind.GLOBAL, gaddr=6144, size=8),
    MopSnapshot(kind=OperandKind.LVAR, lvar_off=8, size=4),
    MopSnapshot(kind=OperandKind.REGISTER, reg=None, size=8),
    MopSnapshot(kind=OperandKind.NUMBER, value=5, size=8),
    MopSnapshot(kind=OperandKind.UNKNOWN),
)


@pytest.mark.parametrize("mop", _MOPS)
def test_adapter_key_is_byte_identical_to_legacy(mop: MopSnapshot) -> None:
    assert varnode_key(varnode_from_mop_snapshot(mop)) == mop_snapshot_key(mop)


@pytest.mark.parametrize("mop", _MOPS)
def test_adapter_offset_is_byte_identical_to_legacy(mop: MopSnapshot) -> None:
    assert varnode_offset(varnode_from_mop_snapshot(mop)) == mop_snapshot_offset(mop)


def test_adapter_maps_number_to_const_space() -> None:
    vn = varnode_from_mop_snapshot(
        MopSnapshot(kind=OperandKind.NUMBER, value=5, size=8)
    )

    assert vn == Varnode(Space.CONST, 5, 8)


def test_adapter_register_with_none_reg_is_unknown() -> None:
    vn = varnode_from_mop_snapshot(MopSnapshot(kind=OperandKind.REGISTER, reg=None))

    assert vn == Varnode(Space.UNKNOWN, 0, 0)
