"""Owned inventory readers never borrow public inventory descendants."""

import pytest

from d810.core.structural_identity import StructuralIdentityError, StructuralNodeKind, StructuralTable
from d810.transforms.unflatten_authority import inventory_inputs, inventory_values, model
from tests.unit.transforms.unflatten_authority.helpers import projected_site_fixture


def test_owned_inventory_reads_detached_block_anchor() -> None:
    public = projected_site_fixture().source_inventory
    table = StructuralTable()
    root = inventory_inputs.capture_inventory(table, public)
    blocks = inventory_values.inventory_field(table, root, "blocks")
    block = inventory_values.sequence_children(table, blocks)[0]
    anchor = inventory_values.record_field(table, block, "anchor_ea")
    expected = public.blocks[0].anchor_ea
    object.__setattr__(public.blocks[0], "anchor_ea", expected + 64)
    assert inventory_values.scalar_value(table, anchor) == expected
    assert inventory_values.inventory_field(table, root, "blocks") is blocks
    with pytest.raises((TypeError, ValueError)):
        model.validate_semantic_graph_inventory(public)


@pytest.mark.parametrize("operation", ["foreign", "closed"])
def test_owned_inventory_reader_requires_live_owner(operation: str) -> None:
    table = StructuralTable()
    root = inventory_inputs.capture_inventory(table, projected_site_fixture().source_inventory)
    if operation == "foreign":
        table = StructuralTable()
    else:
        table.close()
    with pytest.raises(StructuralIdentityError):
        inventory_values.inventory_field(table, root, "blocks")


def test_owned_inventory_repeated_reads_do_not_capture_or_materialize(monkeypatch) -> None:
    table = StructuralTable()
    root = inventory_inputs.capture_inventory(table, projected_site_fixture().source_inventory)

    def forbidden(*args, **kwargs):
        raise AssertionError("owned read attempted capture or reconstruction")

    monkeypatch.setattr(inventory_inputs, "capture_inventory", forbidden)
    monkeypatch.setattr(StructuralTable, "intern", forbidden)
    for _ in range(10):
        blocks = inventory_values.inventory_field(table, root, "blocks")
        block = inventory_values.sequence_children(table, blocks)[0]
        anchor = inventory_values.record_field(table, block, "anchor_ea")
        assert type(inventory_values.scalar_value(table, anchor)) is int


def test_owned_inventory_reader_rejects_foreign_resolver_before_callback() -> None:
    table = StructuralTable()
    root = inventory_inputs.capture_inventory(table, projected_site_fixture().source_inventory)
    calls = []

    class Resolver:
        def resolve(self, *args):
            calls.append(args)
            return table.resolve(*args)

    with pytest.raises(TypeError):
        inventory_values.inventory_field(Resolver(), root, "blocks")
    assert calls == []


def test_owned_inventory_enum_payload_does_not_retain_enum_alias() -> None:
    public = projected_site_fixture().source_inventory
    table = StructuralTable()
    root = inventory_inputs.capture_inventory(table, public)
    phase = inventory_values.inventory_field(table, root, "phase")
    before = table.resolve(phase, StructuralNodeKind.ENUM).payload
    member = public.phase
    original = object.__getattribute__(member, "_value_")
    try:
        object.__setattr__(member, "_value_", "foreign-phase")
        assert table.resolve(phase, StructuralNodeKind.ENUM).payload == before
        assert before[-1] == original
        with pytest.raises((TypeError, ValueError)):
            model.validate_semantic_graph_inventory(public)
    finally:
        object.__setattr__(member, "_value_", original)
