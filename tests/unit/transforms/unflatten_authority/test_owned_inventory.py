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


def test_owned_effect_join_uses_same_owner_reference_without_public_reads(monkeypatch) -> None:
    public = projected_site_fixture().source_inventory
    row = public.effects[0]
    table = StructuralTable()
    root = inventory_inputs.capture_inventory(table, public)
    owner = inventory_inputs.capture_inventory_reference(table, row.owner_ref)
    anchor, ea, kind = row.owner_anchor_ea, row.instruction_ea, row.effect_kind.value
    expected = inventory_values.sequence_children(
        table, inventory_values.inventory_field(table, root, "effects")
    )[0]
    object.__setattr__(row, "instruction_ea", ea + 1)

    def forbidden(*args, **kwargs):
        raise AssertionError("join reconstructed or captured a public value")

    monkeypatch.setattr(StructuralTable, "intern", forbidden)
    monkeypatch.setattr(inventory_inputs.proposal_inputs, "_materialize", forbidden)
    assert inventory_values.matching_effect_rows(
        table, root, owner, anchor, ea, kind
    ) == (expected,)
    assert inventory_values.matching_effect_rows(
        table, root, owner, anchor, ea + 1, kind
    ) == ()


def test_owned_effect_join_rejects_equal_reference_from_foreign_partition() -> None:
    public = projected_site_fixture().source_inventory
    row = public.effects[0]
    source = StructuralTable()
    projected = StructuralTable()
    root = inventory_inputs.capture_inventory(source, public)
    foreign = inventory_inputs.capture_inventory_reference(projected, row.owner_ref)
    with pytest.raises(StructuralIdentityError):
        inventory_values.matching_effect_rows(
            source, root, foreign, row.owner_anchor_ea, row.instruction_ea,
            row.effect_kind.value,
        )
