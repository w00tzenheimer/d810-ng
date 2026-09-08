"""Private local-alias drafting must read owned inventory rows directly."""

import pytest

from d810.core.structural_identity import StructuralNodeKind as Kind
from d810.transforms.unflatten_authority import inventory_values
from d810.core.runtime_identity import RuntimeAuthorityArena, RuntimeAuthorityScope
from d810.transforms.unflatten_authority import bind, inventory_inputs, inventory_publication
from d810.transforms.unflatten_authority import inventory_alias
from tests.unit.transforms.unflatten_authority.test_bind import _c_local_alias_fixture


def test_owned_local_alias_draft_selects_legacy_rows_without_public_reads(monkeypatch):
    fixture = _c_local_alias_fixture()
    public_source = fixture["source_inventory"]
    public_projected = fixture["projected_inventory"]
    claim = fixture["claim"]
    legacy = bind._draft_local_alias_binding(
        claim=claim, patch_step_fact=fixture["patch_step_fact"],
        source_inventory=public_source, projected_inventory=public_projected,
    )
    source = RuntimeAuthorityArena(RuntimeAuthorityScope("alias-source"))
    projected = RuntimeAuthorityArena(RuntimeAuthorityScope("alias-projected"))
    source_root = inventory_publication.publish_inventory(source, public_source).root
    projected_root = inventory_publication.publish_inventory(projected, public_projected).root
    source_owner = inventory_inputs.capture_inventory_reference(
        source.structural, claim.owner_subject.block_ref,
    )
    projected_owner = inventory_inputs.capture_inventory_reference(
        projected.structural, claim.owner_subject.block_ref,
    )
    inputs = inventory_alias.LocalAliasInputs(
        source_owner=source_owner, projected_owner=projected_owner,
        owner_anchor_ea=claim.owner_subject.anchor_ea,
        source_generation=claim.source_generation, host_ea=claim.host_ea,
        host_opcode=claim.host_opcode, value_size=claim.value_size,
        native_width=claim.owner_subject.block_ref.identity.native_key.bitness // 8,
        alias_token=claim.alias_token, base_token=claim.base_token,
    )
    expected = (
        legacy.source_row.instruction_ea,
        legacy.source_observation.ordinal,
        legacy.projected_block.serial,
        legacy.projected_observation.ordinal,
    )
    object.__setattr__(legacy.source_row, "instruction_ea", -1)
    object.__setattr__(legacy.projected_observation, "display_text", "foreign")

    def no_reconstruction(*args, **kwargs):
        raise AssertionError("owned draft must not recapture or reconstruct public rows")

    monkeypatch.setattr(inventory_inputs, "capture_inventory", no_reconstruction)
    monkeypatch.setattr(inventory_inputs, "materialize_inventory", no_reconstruction)
    result = inventory_alias.draft_local_alias(
        source_table=source.structural, source_inventory=source_root,
        projected_table=projected.structural, projected_inventory=projected_root,
        inputs=inputs,
    )
    assert result.coordinates == expected


def test_owned_local_alias_rejects_foreign_scalar_protocol_before_table_access():
    class ForeignInt(int):
        def __eq__(self, other):
            raise AssertionError("foreign comparison protocol executed")

    inputs = inventory_alias.LocalAliasInputs(
        source_owner=None, projected_owner=None, owner_anchor_ea=1,
        source_generation=ForeignInt(1), host_ea=1, host_opcode=0,
        value_size=8, native_width=8, alias_token="alias", base_token="base",
    )
    with pytest.raises(TypeError, match="local alias coordinates"):
        inventory_alias.draft_local_alias(
            source_table=None, source_inventory=None,
            projected_table=None, projected_inventory=None, inputs=inputs,
        )


def test_owned_local_alias_enum_reader_rejects_foreign_enum_with_equal_raw_value():
    fixture = _c_local_alias_fixture()
    arena = RuntimeAuthorityArena(RuntimeAuthorityScope("alias-enum"))
    root = inventory_publication.publish_inventory(arena, fixture["source_inventory"]).root
    table = arena.structural
    block = inventory_values.sequence_children(table, inventory_values.inventory_field(table, root, "blocks"))[0]
    observation = inventory_values.sequence_children(table, inventory_values.record_field(table, block, "instruction_observations"))[0]
    node = table.resolve(observation, Kind.SUBJECT)
    forged = table.intern(Kind.ENUM, None, ("foreign", "Kind", "STORE", "store"), ())
    children = list(node.children)
    children[inventory_values.INVENTORY_FIELDS["InventoryInstructionObservation"].index("instruction_kind")] = forged
    observation = table.intern(Kind.SUBJECT, None, node.payload, tuple(children))
    with pytest.raises(TypeError, match="enum schema"):
        inventory_alias._enum(table, observation, "instruction_kind")


def _prepared_alias():
    fixture = _c_local_alias_fixture()
    claim = fixture["claim"]
    source = RuntimeAuthorityArena(RuntimeAuthorityScope("alias-source"))
    projected = RuntimeAuthorityArena(RuntimeAuthorityScope("alias-projected"))
    source_root = inventory_publication.publish_inventory(source, fixture["source_inventory"]).root
    projected_root = inventory_publication.publish_inventory(projected, fixture["projected_inventory"]).root
    inputs = inventory_alias.LocalAliasInputs(
        source_owner=inventory_inputs.capture_inventory_reference(source.structural, claim.owner_subject.block_ref),
        projected_owner=inventory_inputs.capture_inventory_reference(projected.structural, claim.owner_subject.block_ref),
        owner_anchor_ea=claim.owner_subject.anchor_ea,
        source_generation=claim.source_generation, host_ea=claim.host_ea,
        host_opcode=claim.host_opcode, value_size=claim.value_size,
        native_width=claim.owner_subject.block_ref.identity.native_key.bitness // 8,
        alias_token=claim.alias_token, base_token=claim.base_token,
    )
    return fixture, source, projected, dict(
        source_table=source.structural, source_inventory=source_root,
        projected_table=projected.structural, projected_inventory=projected_root,
        inputs=inputs,
    )


@pytest.mark.parametrize("field,value", [
    ("source_generation", 999), ("host_ea", 999), ("host_opcode", 999),
    ("value_size", 999), ("alias_token", "foreign"), ("base_token", "foreign"),
])
def test_owned_local_alias_matches_legacy_coordinate_refusals(field, value):
    fixture, _source, _projected, kwargs = _prepared_alias()
    object.__setattr__(fixture["claim"], field, value)
    if field in ("host_ea", "host_opcode"):
        object.__setattr__(fixture["patch_step_fact"], field, value)
    kwargs["inputs"] = kwargs["inputs"]._replace(**{field: value})
    with pytest.raises(ValueError):
        bind._draft_local_alias_binding(
            claim=fixture["claim"], patch_step_fact=fixture["patch_step_fact"],
            source_inventory=fixture["source_inventory"], projected_inventory=fixture["projected_inventory"],
        )
    with pytest.raises(ValueError):
        inventory_alias.draft_local_alias(**kwargs)


@pytest.mark.parametrize("mode", ["source-closed", "projected-closed", "foreign-projected-owner"])
def test_owned_local_alias_rejects_closed_or_foreign_partition(mode):
    _fixture, source, projected, kwargs = _prepared_alias()
    if mode == "source-closed":
        source.close()
    elif mode == "projected-closed":
        projected.close()
    else:
        kwargs["inputs"] = kwargs["inputs"]._replace(projected_owner=kwargs["inputs"].source_owner)
    with pytest.raises((TypeError, ValueError)):
        inventory_alias.draft_local_alias(**kwargs)


def test_owned_local_alias_refuses_foreign_projected_table_before_callback():
    _fixture, _source, _projected, kwargs = _prepared_alias()
    table = kwargs["projected_table"]
    calls = []

    class ForeignTable:
        def resolve(self, *args):
            calls.append(args)
            return table.resolve(*args)

    kwargs["projected_table"] = ForeignTable()
    with pytest.raises(TypeError):
        inventory_alias.draft_local_alias(**kwargs)
    assert calls == []


def test_owned_local_alias_keeps_original_row_positions_for_export_origins():
    fixture, _source, _projected, kwargs = _prepared_alias()
    legacy = bind._draft_local_alias_binding(
        claim=fixture["claim"], patch_step_fact=fixture["patch_step_fact"],
        source_inventory=fixture["source_inventory"], projected_inventory=fixture["projected_inventory"],
    )
    result = inventory_alias.draft_local_alias(**kwargs)
    source_blocks = fixture["source_inventory"].blocks
    source_block = next(block for block in source_blocks
                        if any(item is legacy.source_observation for item in block.instruction_observations))
    assert result.positions == (
        next(i for i, row in enumerate(fixture["source_inventory"].effects) if row is legacy.source_row),
        next(i for i, row in enumerate(source_blocks) if row is source_block),
        next(i for i, row in enumerate(source_block.instruction_observations) if row is legacy.source_observation),
        next(i for i, row in enumerate(fixture["projected_inventory"].blocks) if row is legacy.projected_block),
        next(i for i, row in enumerate(legacy.projected_block.instruction_observations) if row is legacy.projected_observation),
    )
