"""Owned inventory publication with separate occurrence-only export provenance.

The existing runtime arena retains origins. Internal readers use structural
values; an origin reference never proves that a mutable record is unchanged.
"""

from d810.core.runtime_identity import (
    RuntimeAuthorityArena, RuntimeAuthorityKind, RuntimeAuthorityRef,
)
from d810.core.structural_identity import StructuralNodeKind, StructuralRef
from d810.core.typing import NamedTuple
from d810.transforms.unflatten_authority import inventory_inputs, inventory_values, model


class InventoryOrigin(NamedTuple):
    """Immutable coordinates for an occurrence in the existing runtime owner."""

    ordinal: int
    owner: object


class InventoryPublication(NamedTuple):
    root: StructuralRef
    origin: InventoryOrigin


def _require_arena(arena: RuntimeAuthorityArena) -> None:
    if type(arena) is not RuntimeAuthorityArena:
        raise TypeError("inventory publication requires the existing exact arena")


def _retain(arena: RuntimeAuthorityArena, value: object) -> InventoryOrigin:
    ref = arena.mint(RuntimeAuthorityKind.INVENTORY, value)
    # RuntimeAuthorityRef is a frozen dataclass, so retain immutable coordinates
    # rather than exposing a mutable-by-object.__setattr__ reference as a key.
    return InventoryOrigin(ref.ordinal, ref._owner)


def _origin(arena: RuntimeAuthorityArena, origin: InventoryOrigin) -> object:
    _require_arena(arena)
    if type(origin) is not InventoryOrigin:
        raise TypeError("inventory origin requires exact immutable coordinates")
    return arena.get(RuntimeAuthorityRef(
        RuntimeAuthorityKind.INVENTORY, origin.ordinal, origin.owner,
    ))


def publish_inventory(
    arena: RuntimeAuthorityArena, value: model.SemanticGraphInventory,
) -> InventoryPublication:
    """Validate ingress and captured content before retaining an origin."""
    _require_arena(arena)
    model.validate_semantic_graph_inventory(value)
    validated_digest = value.inventory_digest
    root = inventory_inputs.capture_inventory(arena.structural, value)
    # Replay the captured value itself. A public-before/public-after check can
    # miss a transient mutation that affected only the captured terms.
    detached = inventory_inputs.materialize_inventory(arena.structural, root)
    if detached.inventory_digest != validated_digest:
        raise ValueError("captured inventory differs from validated ingress")
    if inventory_inputs.capture_inventory(arena.structural, detached) is not root:
        raise ValueError("captured inventory constructor normalization differs")
    return InventoryPublication(root, _retain(arena, value))


def inventory_root(
    arena: RuntimeAuthorityArena, publication: InventoryPublication,
) -> StructuralRef:
    _require_arena(arena)
    if type(publication) is not InventoryPublication:
        raise TypeError("inventory publication requires its exact owned record")
    arena.structural.resolve(publication.root, StructuralNodeKind.SUBJECT)
    inventory_values.inventory_field(arena.structural, publication.root, "inventory_digest")
    return publication.root


def retain_inventory_row_origin(arena: RuntimeAuthorityArena, row: object) -> InventoryOrigin:
    """Retain a selected row only for later exact occurrence comparison."""
    _require_arena(arena)
    if type(row) not in (
        model.InventoryEffectSite, model.InventoryBlockObservation,
        model.InventoryInstructionObservation,
    ):
        raise TypeError("inventory origin requires an exact selected row")
    return _retain(arena, row)


def require_inventory_row_origin(
    arena: RuntimeAuthorityArena, origin: InventoryOrigin, row: object,
) -> None:
    if _origin(arena, origin) is not row:
        raise ValueError("inventory row occurrence changed before export")


def require_inventory_export(
    arena: RuntimeAuthorityArena, publication: InventoryPublication,
    value: model.SemanticGraphInventory,
) -> None:
    """Keep full public validation and exact origin checks at export."""
    root = inventory_root(arena, publication)
    if _origin(arena, publication.origin) is not value:
        raise ValueError("inventory occurrence changed before export")
    model.validate_semantic_graph_inventory(value)
    digest = inventory_values.scalar_value(
        arena.structural,
        inventory_values.inventory_field(arena.structural, root, "inventory_digest"),
    )
    if digest != value.inventory_digest:
        raise ValueError("inventory content changed before export")
