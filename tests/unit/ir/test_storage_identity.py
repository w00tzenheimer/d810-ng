"""Unit tests for the portable storage identity boundary."""

from __future__ import annotations

import dataclasses

import pytest

from d810.ir.flowgraph import InsnKind, InsnSnapshot, MopSnapshot, OperandKind
from d810.ir.storage_identity import (
    StorageIdentity,
    StorageIdentityKind,
    operand_storage_identities,
    storage_identity_from_mop_snapshot,
    storage_identity_from_record,
    storage_identity_from_varnode,
    storage_identity_key,
    storage_identity_offset,
)
from d810.ir.varnode import Space, Varnode


class _KindlessLiftedOperand:
    def __init__(
        self,
        *,
        size: int = 8,
        value: int | None = None,
        reg: int | None = None,
        stkoff: int | None = None,
        gaddr: int | None = None,
        lvar_off: int | None = None,
    ) -> None:
        self.size = size
        self.value = value
        self.reg = reg
        self.stkoff = stkoff
        self.gaddr = gaddr
        self.lvar_off = lvar_off

    @property
    def g(self):
        raise AssertionError("raw live global alias should not be read")


def test_storage_identity_is_frozen_hashable_and_size_agnostic() -> None:
    byte_stack = storage_identity_from_mop_snapshot(
        MopSnapshot(kind=OperandKind.STACK, stkoff=0x40, size=1)
    )
    qword_stack = storage_identity_from_mop_snapshot(
        MopSnapshot(kind=OperandKind.STACK, stkoff=0x40, size=8)
    )

    assert byte_stack == StorageIdentity(StorageIdentityKind.STACK, 0x40)
    assert byte_stack == qword_stack
    assert {byte_stack: "state"}[qword_stack] == "state"
    with pytest.raises(dataclasses.FrozenInstanceError):
        byte_stack.offset = 9  # type: ignore[misc]


def test_storage_identity_preserves_legacy_key_prefixes() -> None:
    assert (
        storage_identity_key(StorageIdentity(StorageIdentityKind.REGISTER, 3)) == "r3"
    )
    assert storage_identity_key(StorageIdentity(StorageIdentityKind.STACK, 64)) == "S64"
    assert (
        storage_identity_key(StorageIdentity(StorageIdentityKind.GLOBAL, 0x1400))
        == "v5120"
    )
    assert storage_identity_key(StorageIdentity(StorageIdentityKind.LVAR, 8)) == "l8"
    assert storage_identity_key(None) is None


def test_storage_identity_offset_zero_for_missing_identity() -> None:
    assert (
        storage_identity_offset(StorageIdentity(StorageIdentityKind.REGISTER, 3)) == 3
    )
    assert storage_identity_offset(None) == 0


def test_storage_identity_from_varnode_rejects_non_identity_spaces() -> None:
    assert storage_identity_from_varnode(Varnode(Space.REGISTER, 3, 8)) == (
        StorageIdentity(StorageIdentityKind.REGISTER, 3)
    )
    assert storage_identity_from_varnode(Varnode(Space.CONST, 3, 8)) is None
    assert storage_identity_from_varnode(None) is None


def test_storage_identity_accepts_kindless_lifted_global_snapshot() -> None:
    assert storage_identity_from_mop_snapshot(
        _KindlessLiftedOperand(gaddr=0x180021320)
    ) == StorageIdentity(StorageIdentityKind.GLOBAL, 0x180021320)


def test_storage_identity_accepts_kindless_lifted_stack_snapshot() -> None:
    byte_stack = storage_identity_from_mop_snapshot(
        _KindlessLiftedOperand(size=1, stkoff=0x40)
    )
    qword_stack = storage_identity_from_mop_snapshot(
        _KindlessLiftedOperand(size=8, stkoff=0x40)
    )

    assert byte_stack == StorageIdentity(StorageIdentityKind.STACK, 0x40)
    assert byte_stack == qword_stack


def test_storage_identity_record_roundtrip() -> None:
    identity = StorageIdentity(StorageIdentityKind.STACK, 0x40)
    record = identity.to_record()

    assert record == {
        "kind": "stack",
        "prefix": "S",
        "offset": 0x40,
        "key": "S64",
    }
    assert storage_identity_from_record(record) == identity
    assert storage_identity_from_record({"prefix": "S", "offset": 0x40}) == identity


def test_storage_identity_unknown_record_rejected() -> None:
    with pytest.raises(ValueError):
        storage_identity_from_record({"kind": "const", "offset": 1})


def test_operand_storage_identities_returns_only_identity_slots() -> None:
    insn = InsnSnapshot(
        opcode=1,
        ea=0x401000,
        operands=(),
        kind=InsnKind.MOV,
        l=MopSnapshot(kind=OperandKind.STACK, stkoff=0x20, size=1),
        r=MopSnapshot(kind=OperandKind.NUMBER, value=7, size=4),
        d=MopSnapshot(kind=OperandKind.REGISTER, reg=0, size=8),
    )

    assert operand_storage_identities(insn) == (
        ("l", StorageIdentity(StorageIdentityKind.STACK, 0x20)),
        ("d", StorageIdentity(StorageIdentityKind.REGISTER, 0)),
    )


def test_storage_identity_api_is_exported_from_ir_package() -> None:
    import d810.ir as ir

    assert ir.StorageIdentity is StorageIdentity
    assert ir.StorageIdentityKind is StorageIdentityKind
    assert ir.storage_identity_from_mop_snapshot is storage_identity_from_mop_snapshot
    assert ir.storage_identity_from_varnode is storage_identity_from_varnode
    assert ir.storage_identity_key is storage_identity_key
    assert ir.storage_identity_offset is storage_identity_offset
