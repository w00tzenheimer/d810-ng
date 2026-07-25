"""Serial-free inventory for one semantic-fragment root publication."""

from __future__ import annotations

from dataclasses import dataclass

from d810.ir.semantic_edge import SemanticEdgeRole


def semantic_fragment_root_group_id(predecessor_block_id: str) -> str:
    """Return the serial-free publication-group identity for one predecessor."""
    predecessor_block_id = str(predecessor_block_id)
    if not predecessor_block_id:
        raise ValueError("root publication group requires a predecessor block id")
    return f"root-group:{predecessor_block_id}"


@dataclass(frozen=True, slots=True)
class SemanticFragmentRootInventoryItem:
    """One incoming root operation known before fragment staging."""

    edge_id: str
    root_block_id: str
    original_block_id: str
    predecessor_block_id: str
    role: SemanticEdgeRole
    requires_helper: bool

    def __post_init__(self) -> None:
        if not all(
            str(value)
            for value in (
                self.edge_id,
                self.root_block_id,
                self.original_block_id,
                self.predecessor_block_id,
            )
        ):
            raise ValueError("root inventory item requires complete block identity")
        if not isinstance(self.role, SemanticEdgeRole):
            raise TypeError("root inventory item requires a semantic edge role")
        if not isinstance(self.requires_helper, bool):
            raise TypeError("root inventory helper requirement must be boolean")


@dataclass(frozen=True, slots=True)
class SemanticFragmentRootInventoryGroup:
    """All root edges whose publication shares one predecessor authority."""

    group_id: str
    predecessor_block_id: str
    items: tuple[SemanticFragmentRootInventoryItem, ...]

    def __post_init__(self) -> None:
        expected_group_id = semantic_fragment_root_group_id(self.predecessor_block_id)
        if self.group_id != expected_group_id:
            raise ValueError("root inventory group identity drifted")
        if not self.items or any(
            item.predecessor_block_id != self.predecessor_block_id
            for item in self.items
        ):
            raise ValueError(
                "root inventory group requires one predecessor-owned edge set"
            )
        edge_ids = tuple(item.edge_id for item in self.items)
        if len(set(edge_ids)) != len(edge_ids):
            raise ValueError("root inventory group contains duplicate edge ids")


@dataclass(frozen=True, slots=True)
class SemanticFragmentRootInventory:
    """Complete incoming root plan captured before opening the transaction."""

    plan_id: str
    atomic_group_id: str
    items: tuple[SemanticFragmentRootInventoryItem, ...]

    def __post_init__(self) -> None:
        if not self.plan_id or not self.atomic_group_id or not self.items:
            raise ValueError("root inventory requires plan, atomic group, and edges")
        edge_ids = tuple(item.edge_id for item in self.items)
        if len(set(edge_ids)) != len(edge_ids):
            raise ValueError("root inventory contains duplicate edge ids")

    @property
    def groups(self) -> tuple[SemanticFragmentRootInventoryGroup, ...]:
        grouped: dict[str, list[SemanticFragmentRootInventoryItem]] = {}
        for item in self.items:
            grouped.setdefault(item.predecessor_block_id, []).append(item)
        return tuple(
            SemanticFragmentRootInventoryGroup(
                group_id=semantic_fragment_root_group_id(predecessor_block_id),
                predecessor_block_id=predecessor_block_id,
                items=tuple(items),
            )
            for predecessor_block_id, items in grouped.items()
        )


__all__ = [
    "SemanticFragmentRootInventory",
    "SemanticFragmentRootInventoryGroup",
    "SemanticFragmentRootInventoryItem",
    "semantic_fragment_root_group_id",
]
