"""Logical-proxy semantic edge operations for one live MBA."""

from __future__ import annotations

from dataclasses import dataclass

from d810.hexrays.ir.logical_block_proxy import LogicalBlockProxy
from d810.ir.semantic_edge import SemanticEdgeRole


class SemanticEdgeOperationRejected(RuntimeError):
    """A semantic edge operation cannot be realized without guessing."""


@dataclass(frozen=True, slots=True)
class LogicalSemanticEdge:
    """One role-tagged destination in a logical semantic edge operation."""

    role: SemanticEdgeRole
    target: LogicalBlockProxy
    expected_target: LogicalBlockProxy | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.role, SemanticEdgeRole):
            raise TypeError("logical semantic edge requires a semantic edge role")
        if not isinstance(self.target, LogicalBlockProxy):
            raise TypeError("logical semantic edge requires a target proxy")
        if self.expected_target is not None and not isinstance(
            self.expected_target,
            LogicalBlockProxy,
        ):
            raise TypeError("logical semantic edge expected target must be a proxy")


@dataclass(frozen=True, slots=True)
class LogicalSemanticEdgeOperation:
    """One gateway-owned edge operation over versioned logical proxies.

    A single edge represents a direct or one-arm redirect.  A conditional
    reconstruction is deliberately one operation containing both conditional
    roles and the exact predicate anchor, so no caller can publish only half
    of the reconstructed branch.
    """

    source: LogicalBlockProxy
    edges: tuple[LogicalSemanticEdge, ...]
    predicate_anchor_ea: int | None = None
    rewrite_anchor_ea: int | None = None
    description: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.source, LogicalBlockProxy):
            raise TypeError("semantic edge operation requires a source proxy")
        edges = tuple(self.edges)
        if len(edges) not in {1, 2}:
            raise ValueError("semantic edge operation requires one or two edges")
        if any(not isinstance(edge, LogicalSemanticEdge) for edge in edges):
            raise TypeError("semantic edge operation contains an invalid edge")
        roles = tuple(edge.role for edge in edges)
        if len(set(roles)) != len(roles):
            raise ValueError(
                "semantic edge operation requires unique semantic edge roles"
            )

        conditional_roles = frozenset(
            {
                SemanticEdgeRole.CONDITIONAL_TAKEN,
                SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
            }
        )
        if len(edges) == 2:
            if frozenset(roles) != conditional_roles:
                raise ValueError(
                    "conditional reconstruction requires both conditional roles"
                )
            if self.predicate_anchor_ea is None:
                raise ValueError(
                    "conditional reconstruction requires a predicate anchor"
                )
            if edges[0].target is edges[1].target:
                raise ValueError("conditional reconstruction requires distinct targets")
            if self.rewrite_anchor_ea is not None:
                raise ValueError(
                    "a rewrite anchor belongs only to a direct semantic edge"
                )
        else:
            if self.predicate_anchor_ea is not None:
                raise ValueError(
                    "a predicate anchor belongs only to conditional reconstruction"
                )
            if (
                self.rewrite_anchor_ea is not None
                and edges[0].role is not SemanticEdgeRole.DIRECT
            ):
                raise ValueError(
                    "a rewrite anchor belongs only to a direct semantic edge"
                )

        if self.predicate_anchor_ea is not None:
            predicate_anchor_ea = int(self.predicate_anchor_ea)
            if not 0 <= predicate_anchor_ea < 0xFFFFFFFFFFFFFFFF:
                raise ValueError("predicate anchor must be a native EA")
            object.__setattr__(
                self,
                "predicate_anchor_ea",
                predicate_anchor_ea,
            )
        if self.rewrite_anchor_ea is not None:
            rewrite_anchor_ea = int(self.rewrite_anchor_ea)
            if not 0 <= rewrite_anchor_ea < 0xFFFFFFFFFFFFFFFF:
                raise ValueError("rewrite anchor must be a native EA")
            object.__setattr__(
                self,
                "rewrite_anchor_ea",
                rewrite_anchor_ea,
            )
        object.__setattr__(self, "edges", edges)
        object.__setattr__(self, "description", str(self.description))

    @property
    def roles(self) -> frozenset[SemanticEdgeRole]:
        return frozenset(edge.role for edge in self.edges)


__all__ = [
    "LogicalSemanticEdge",
    "LogicalSemanticEdgeOperation",
    "SemanticEdgeOperationRejected",
]
