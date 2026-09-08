"""Private owned inventory alias chain; public validation remains at export."""

from d810.core.runtime_identity import RuntimeAuthorityArena
from d810.core.typing import NamedTuple
from d810.transforms.unflatten_authority import model
from d810.transforms.unflatten_authority import inventory_alias as algorithm
from d810.transforms.unflatten_authority import inventory_publication as publication


class OwnedInventoryPair(NamedTuple):
    source: RuntimeAuthorityArena
    projected: RuntimeAuthorityArena
    source_publication: publication.InventoryPublication
    projected_publication: publication.InventoryPublication
    source_occurrences: publication.InventoryRowOccurrences | None
    projected_occurrences: publication.InventoryRowOccurrences | None


class OwnedAliasDraft(NamedTuple):
    claim: object
    patch_step_fact: object
    inputs: publication.LocalAliasInputPublication
    rows: algorithm.LocalAliasRows
    origins: tuple[publication.InventoryOrigin, ...]



def _require_pair(pair):
    if (type(pair) is not OwnedInventoryPair
            or type(pair.source) is not RuntimeAuthorityArena
            or type(pair.projected) is not RuntimeAuthorityArena
            or pair.source is pair.projected):
        raise TypeError("owned alias requires exact distinct inventory owners")


def publish_pair(source, projected, source_inventory, projected_inventory):
    source_occurrences = publication.snapshot_inventory_rows(source_inventory)
    projected_occurrences = publication.snapshot_inventory_rows(projected_inventory)
    source_publication = publication.publish_inventory(source, source_inventory)
    projected_publication = publication.publish_inventory(projected, projected_inventory)
    return OwnedInventoryPair(source, projected, source_publication, projected_publication,
                              source_occurrences, projected_occurrences)


def release_occurrence_snapshots(pair):
    _require_pair(pair)
    return pair._replace(source_occurrences=None, projected_occurrences=None)


def _select(pair, inputs, allow_retirement):
    _require_pair(pair)
    return algorithm.draft_local_alias(
        source_table=pair.source.structural,
        source_inventory=pair.source_publication.root,
        projected_table=pair.projected.structural,
        projected_inventory=pair.projected_publication.root,
        inputs=inputs, allow_route_owned_retirement=allow_retirement,
    )


def draft_alias(pair, claim, fact, allow_retirement, *, inputs=None):
    if type(pair) is not OwnedInventoryPair:
        raise TypeError("owned alias requires exact inventory pair")
    if inputs is None:
        inputs = publication.publish_local_alias_inputs(pair.source, pair.projected, claim, fact)
    rows = _select(pair, inputs.inputs, allow_retirement)
    effect, source_block, source_insn, projected_block, projected_insn = rows.positions
    origin = publication.retain_inventory_position_origin
    origins = (
        origin(pair.source, pair.source_publication, pair.source_occurrences, "effects", (effect,)),
        origin(pair.source, pair.source_publication, pair.source_occurrences, "instructions", (source_block, source_insn)),
        origin(pair.projected, pair.projected_publication, pair.projected_occurrences, "blocks", (projected_block,)),
        origin(pair.projected, pair.projected_publication, pair.projected_occurrences, "instructions", (projected_block, projected_insn)),
    )
    return OwnedAliasDraft(claim, fact, inputs, rows, origins)


def replay_alias(pair, draft, claim, fact, allow_retirement):
    if type(pair) is not OwnedInventoryPair or type(draft) is not OwnedAliasDraft:
        raise TypeError("owned alias replay requires exact private records")
    if draft.claim is not claim or draft.patch_step_fact is not fact:
        raise ValueError("owned local alias claim/fact occurrence differs")
    state, subject, owner = publication._local_alias_state(claim, fact)
    if (state != draft.inputs.scalar_state or subject is not draft.inputs.subject_origin
            or owner is not draft.inputs.owner_origin):
        raise ValueError("local alias claim changed before replay")
    expected = _select(pair, draft.inputs.inputs, allow_retirement)
    if expected != draft.rows:
        raise ValueError("owned local alias draft correlation differs")


def require_pair_export(pair, source_inventory, projected_inventory):
    if type(pair) is not OwnedInventoryPair:
        raise TypeError("owned alias export requires exact inventory pair")
    publication.require_inventory_export(pair.source, pair.source_publication, source_inventory)
    publication.require_inventory_export(pair.projected, pair.projected_publication, projected_inventory)


def require_alias_export(pair, draft, source_inventory, projected_inventory):
    if type(pair) is not OwnedInventoryPair or type(draft) is not OwnedAliasDraft:
        raise TypeError("owned alias export requires exact private records")
    publication.require_local_alias_inputs_export(
        pair.source, pair.projected, draft.inputs, draft.claim, draft.patch_step_fact,
    )
    return require_alias_occurrences(pair, draft, source_inventory, projected_inventory)


def require_alias_occurrences(pair, draft, source_inventory, projected_inventory):
    _require_pair(pair)
    if type(draft) is not OwnedAliasDraft or type(draft.origins) is not tuple or len(draft.origins) != 4:
        raise TypeError("owned alias occurrence export requires four origins")
    if type(source_inventory) is not model.SemanticGraphInventory or type(projected_inventory) is not model.SemanticGraphInventory:
        raise TypeError("owned alias occurrence export requires exact inventories")
    effect, source_block, source_insn, projected_block, projected_insn = draft.rows.positions
    def current_row(inventory, family, block_index, instruction_index=None):
        rows = getattr(inventory, family)
        if type(rows) is not tuple:
            raise TypeError("inventory occurrence collection changed")
        if block_index >= len(rows):
            raise ValueError("inventory occurrence path changed")
        row = rows[block_index]
        if instruction_index is not None:
            if type(row) is not model.InventoryBlockObservation:
                raise TypeError("inventory block occurrence changed")
            observations = row.instruction_observations
            if type(observations) is not tuple or instruction_index >= len(observations):
                raise ValueError("inventory instruction occurrence path changed")
            row = observations[instruction_index]
        return row
    # Read the CURRENT path, never compare the retained old occurrence to itself.
    current = (
        current_row(source_inventory, "effects", effect),
        current_row(source_inventory, "blocks", source_block, source_insn),
        current_row(projected_inventory, "blocks", projected_block),
        current_row(projected_inventory, "blocks", projected_block, projected_insn),
    )
    for arena, origin, row in zip(
        (pair.source, pair.source, pair.projected, pair.projected), draft.origins, current,
    ):
        publication.require_inventory_row_origin(arena, origin, row)
    return current
