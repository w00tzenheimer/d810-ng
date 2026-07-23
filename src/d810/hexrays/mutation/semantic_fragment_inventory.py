"""Serial-free inventory for one semantic-fragment root publication."""

from __future__ import annotations

from dataclasses import dataclass

from d810.ir.semantic_edge import SemanticEdgeRole


@dataclass(frozen=True, slots=True)
class SemanticFragmentRootInventoryItem:
    """One incoming root operation known before fragment staging."""

    edge_id: str
    root_block_id: str
    predecessor_block_id: str
    role: SemanticEdgeRole

    @property
    def requires_helper(self) -> bool:
        return self.role in {
            SemanticEdgeRole.CALL_FALLTHROUGH,
            SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
        }


@dataclass(frozen=True, slots=True)
class SemanticFragmentRootInventory:
    """Complete incoming root plan captured before opening the transaction."""

    plan_id: str
    atomic_group_id: str
    items: tuple[SemanticFragmentRootInventoryItem, ...]


__all__ = [
    "SemanticFragmentRootInventory",
    "SemanticFragmentRootInventoryItem",
]
