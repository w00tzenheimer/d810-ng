"""Inventory origin references preserve publication checks, not cached validity."""

from dataclasses import replace

import pytest

from d810.core.runtime_identity import RuntimeAuthorityArena, RuntimeAuthorityScope
from d810.transforms.unflatten_authority import inventory_publication, inventory_values, model
from d810.transforms.unflatten_authority.canonical_session import (
    CanonicalSessionPhase,
    _canonical_validation_session,
)
from d810.transforms.unflatten_authority.ids import canonical_bytes
from d810.transforms.unflatten_authority.transaction_facts import TransactionFacts, fact_scope
from tests.unit.transforms.unflatten_authority.helpers import projected_site_fixture


def _refresh_inventory_digest(value: model.SemanticGraphInventory) -> None:
    object.__setattr__(value, "inventory_digest", model.semantic_graph_inventory_digest(
        value.phase, value.graph_fingerprint, value.generation, value.blocks,
        value.subjects, value.bindings, value.effects, value.terminals,
        value.topology, value.reachable_serials, value.entry_serial,
        value.source_subject_ids, value.function_ea,
        value.observed_route_topology_occurrences,
        value.observed_lowered_conditional_topology_occurrences,
    ))


def test_inventory_publication_preserves_equal_row_replacement_refusal() -> None:
    public = projected_site_fixture().source_inventory
    arena = RuntimeAuthorityArena(RuntimeAuthorityScope("inventory-test"))
    published = inventory_publication.publish_inventory(arena, public)
    origin = inventory_publication.retain_inventory_row_origin(
        arena, public.effects[0]
    )
    public_effects = public.effects
    object.__setattr__(public, "effects", (replace(public_effects[0]), *public_effects[1:]))
    model.validate_semantic_graph_inventory(public)
    inventory_publication.require_inventory_export(arena, published, public)
    with pytest.raises(ValueError, match="occurrence"):
        inventory_publication.require_inventory_row_origin(arena, origin, public.effects[0])


def test_inventory_publication_reads_owned_data_but_export_refuses_public_drift() -> None:
    public = projected_site_fixture().source_inventory
    arena = RuntimeAuthorityArena(RuntimeAuthorityScope("inventory-test"))
    published = inventory_publication.publish_inventory(arena, public)
    root = inventory_publication.inventory_root(arena, published)
    block = inventory_values.sequence_children(
        arena.structural, inventory_values.inventory_field(arena.structural, root, "blocks")
    )[0]
    original = public.blocks[0].anchor_ea
    object.__setattr__(public.blocks[0], "anchor_ea", original + 64)
    assert inventory_values.scalar_value(
        arena.structural, inventory_values.record_field(arena.structural, block, "anchor_ea")
    ) == original
    with pytest.raises((TypeError, ValueError)):
        inventory_publication.require_inventory_export(arena, published, public)


def test_inventory_publication_cannot_outlive_its_existing_arena() -> None:
    public = projected_site_fixture().source_inventory
    arena = RuntimeAuthorityArena(RuntimeAuthorityScope("inventory-test"))
    published = inventory_publication.publish_inventory(arena, public)
    arena.close()
    with pytest.raises((RuntimeError, ValueError)):
        inventory_publication.inventory_root(arena, published)


def test_inventory_publication_skips_initial_materialization(monkeypatch) -> None:
    public = projected_site_fixture().source_inventory
    arena = RuntimeAuthorityArena(RuntimeAuthorityScope("inventory-test"))

    def forbidden(*_args, **_kwargs):
        raise AssertionError("initial publication must not materialize inventory")

    monkeypatch.setattr(
        inventory_publication.inventory_inputs, "materialize_inventory", forbidden,
    )
    published = inventory_publication.publish_inventory(arena, public)
    inventory_publication.require_inventory_export(arena, published, public)


def test_inventory_publication_rejects_transient_capture_window_mutation(monkeypatch) -> None:
    public = projected_site_fixture().source_inventory
    arena = RuntimeAuthorityArena(RuntimeAuthorityScope("inventory-test"))
    original_capture = inventory_publication.inventory_inputs.capture_inventory
    effect = public.effects[0]
    original_ea = effect.instruction_ea
    first_capture = True

    def capture_with_transient_mutation(table, value):
        nonlocal first_capture
        if not first_capture:
            return original_capture(table, value)
        first_capture = False
        object.__setattr__(effect, "instruction_ea", original_ea + 1)
        try:
            return original_capture(table, value)
        finally:
            object.__setattr__(effect, "instruction_ea", original_ea)

    monkeypatch.setattr(inventory_publication.inventory_inputs, "capture_inventory", capture_with_transient_mutation)
    published = inventory_publication.publish_inventory(arena, public)
    assert public.effects[0].instruction_ea == original_ea
    with pytest.raises(ValueError, match="structural root"):
        inventory_publication.require_inventory_export(arena, published, public)


def test_inventory_export_fully_validates_transaction_owned_descendants() -> None:
    public = projected_site_fixture().source_inventory
    owner = TransactionFacts()
    arena = RuntimeAuthorityArena(RuntimeAuthorityScope("inventory-test"))
    with fact_scope(owner):
        owned = owner.capture(public)
        published = inventory_publication.publish_inventory(arena, owned)
        observation = owned.blocks[0].instruction_observations[0]
        object.__setattr__(observation, "display_text", "persistent drift")
        with pytest.raises(ValueError):
            inventory_publication.require_inventory_export(arena, published, owned)


def test_inventory_export_fully_validates_sealed_descendants() -> None:
    public = projected_site_fixture().source_inventory
    arena = RuntimeAuthorityArena(RuntimeAuthorityScope("inventory-test"))
    published = inventory_publication.publish_inventory(arena, public)
    observation = public.blocks[0].instruction_observations[0]
    with _canonical_validation_session(
        CanonicalSessionPhase.PROJECTED_PREPARATION, trust_sealed=True,
    ):
        model.validate_semantic_graph_inventory(public)
        object.__setattr__(observation, "display_text", "sealed drift")
        assert model.validate_semantic_graph_inventory(public) is public
        with pytest.raises(ValueError):
            inventory_publication.require_inventory_export(
                arena, published, public,
            )


def test_inventory_export_rejects_self_consistent_changed_structural_root() -> None:
    public = projected_site_fixture().source_inventory
    arena = RuntimeAuthorityArena(RuntimeAuthorityScope("inventory-test"))
    published = inventory_publication.publish_inventory(arena, public)
    observation = public.blocks[0].instruction_observations[0]
    object.__setattr__(observation, "display_text", "self-consistent drift")
    _refresh_inventory_digest(public)
    model.validate_semantic_graph_inventory(public)
    with pytest.raises(ValueError, match="structural root"):
        inventory_publication.require_inventory_export(arena, published, public)


@pytest.mark.parametrize("phase", ["source_inventory", "projected_inventory"])
def test_inventory_publication_replays_exact_canonical_content(phase: str) -> None:
    public = getattr(projected_site_fixture(), phase)
    before = canonical_bytes(public)
    arena = RuntimeAuthorityArena(RuntimeAuthorityScope("inventory-test"))
    published = inventory_publication.publish_inventory(arena, public)
    detached = inventory_publication.inventory_inputs.materialize_inventory(
        arena.structural, inventory_publication.inventory_root(arena, published)
    )
    assert detached is not public
    assert canonical_bytes(detached) == before
    assert detached.inventory_digest == public.inventory_digest
    assert inventory_publication.inventory_inputs.capture_inventory(arena.structural, detached) is published.root


def test_selected_origin_uses_rows_before_equal_replacement_during_capture(monkeypatch):
    public = projected_site_fixture().source_inventory
    original = public.effects[0]
    arena = RuntimeAuthorityArena(RuntimeAuthorityScope("before-capture"))
    occurrences = inventory_publication.snapshot_inventory_rows(public)
    capture = inventory_publication.inventory_inputs.capture_inventory
    replaced = False

    def replace_during_capture(table, value):
        nonlocal replaced
        if value is public and not replaced:
            object.__setattr__(public, "effects", (replace(original), *public.effects[1:]))
            replaced = True
        return capture(table, value)

    monkeypatch.setattr(inventory_publication.inventory_inputs, "capture_inventory", replace_during_capture)
    publication = inventory_publication.publish_inventory(arena, public)
    origin = inventory_publication.retain_inventory_position_origin(
        arena, publication, occurrences, "effects", (0,),
    )
    inventory_publication.require_inventory_export(arena, publication, public)
    with pytest.raises(ValueError, match="occurrence"):
        inventory_publication.require_inventory_row_origin(arena, origin, public.effects[0])
