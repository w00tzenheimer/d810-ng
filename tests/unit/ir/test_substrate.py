"""Smoke tests for the LS8 ir substrate (locations / value_refs / expressions /
confidence / InsnHandle). Pure-Python, no IDA: these are portable dataclasses
and NewTypes.
"""
from __future__ import annotations

import dataclasses

import pytest

from d810.ir import (
    Add,
    AggregateLocation,
    Const,
    DefinitionRef,
    ExprRef,
    FactConfidence,
    InsnHandle,
    InstructionResultRef,
    Load,
    MemoryCell,
    Move,
    RegisterLocation,
    SSAValueRef,
    StackSlot,
    Store,
    StorageLocation,
    Sub,
    TemporaryRef,
    ValueOpKind,
    ValueRef,
)


def test_newtypes_are_identity_wrappers() -> None:
    assert InsnHandle(7) == 7
    assert FactConfidence(0.5) == 0.5
    # NewType is a plain passthrough at runtime.
    assert isinstance(InsnHandle(7), int)
    assert isinstance(FactConfidence(0.5), float)


def test_locations_construct_and_are_frozen() -> None:
    slot = StackSlot(offset=0x20, size=4)
    reg = RegisterLocation(register_id=3, size=8)
    cell = MemoryCell(address=0x180010000, size=8)
    assert (slot.offset, slot.size) == (0x20, 4)
    assert (reg.register_id, cell.address) == (3, 0x180010000)
    with pytest.raises(dataclasses.FrozenInstanceError):
        slot.offset = 0  # type: ignore[misc]


def test_aggregate_location_nests_members() -> None:
    agg = AggregateLocation(members=(StackSlot(0, 4), RegisterLocation(1, 4)))
    assert len(agg.members) == 2
    assert isinstance(agg.members[0], StackSlot)


def test_storage_location_union_covers_families() -> None:
    members = set(StorageLocation.__args__)
    assert {StackSlot, RegisterLocation, MemoryCell, AggregateLocation} <= members


def test_value_refs_construct() -> None:
    d = DefinitionRef(location=StackSlot(0x20, 4), version=2)
    s = SSAValueRef(value_id=11)
    t = TemporaryRef(temp_id=4)
    r = InstructionResultRef(insn=InsnHandle(0x1800134A5))
    assert d.version == 2 and s.value_id == 11 and t.temp_id == 4
    assert r.insn == 0x1800134A5 and r.result_index == 0


def test_value_ref_union_covers_families() -> None:
    members = set(ValueRef.__args__)
    assert {DefinitionRef, SSAValueRef, TemporaryRef, InstructionResultRef} <= members


def test_expressions_compose() -> None:
    # i_next = i + 1  modeled as Add(Move(<value>), Const(1))
    i = SSAValueRef(value_id=1)
    expr = Add(left=Move(source=i), right=Const(value=1))
    assert isinstance(expr.left, Move)
    assert isinstance(expr.right, Const)
    assert expr.right.value == 1


def test_expression_families_construct() -> None:
    base = Const(0)
    assert isinstance(Sub(base, base), Sub)
    assert isinstance(Load(base), Load)
    assert isinstance(Store(base, base), Store)


def test_value_op_kind_members() -> None:
    names = {k.name for k in ValueOpKind}
    assert {"CONST", "MOVE", "ADD", "SUB", "LOAD", "STORE"} <= names


def test_expr_ref_union_covers_families() -> None:
    members = set(ExprRef.__args__)
    assert {Const, Move, Add, Sub, Load, Store} <= members


def test_expressions_are_frozen() -> None:
    c = Const(1)
    with pytest.raises(dataclasses.FrozenInstanceError):
        c.value = 2  # type: ignore[misc]
