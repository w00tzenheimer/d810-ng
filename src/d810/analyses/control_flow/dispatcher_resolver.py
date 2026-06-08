"""Ranked DispatcherResolver chain over a portable FlowGraph (llr-g3l8 slice 1).

Leaf module: imports only the resolution value types, ``RouterKind``, and the
portable ``FlowGraph``.  It must NOT import ``dispatcher_recovery`` or
``switch_table_analysis`` (those import *this* module to register concrete
resolvers), so the chain stays cycle-free under the ``check-cycles`` contract.

``DispatcherResolver.accepts()`` returns ranked evidence (``ResolverCandidate``),
NEVER a bool, so :func:`resolve_dispatcher` can rank competing providers
deterministically by ``(specificity, confidence)`` before committing to one.
"""
from __future__ import annotations

from d810.core.typing import Protocol, runtime_checkable

from d810.analyses.control_flow.dispatcher_resolution import (
    DispatcherResolution,
    ResolverCandidate,
)
from d810.capabilities.dispatcher import RouterKind
from d810.ir.flowgraph import FlowGraph

__all__ = ["DispatcherResolver", "resolve_dispatcher"]


@runtime_checkable
class DispatcherResolver(Protocol):
    """A ranked provider that can recognize and resolve one dispatcher shape."""

    name: str
    router_kind: RouterKind

    def accepts(self, graph: FlowGraph) -> ResolverCandidate | None:
        """Return ranked evidence (``ResolverCandidate``) or ``None``. NOT a bool."""
        ...

    def resolve(
        self, graph: FlowGraph, candidate: ResolverCandidate
    ) -> DispatcherResolution | None:
        """Return a ``DispatcherResolution`` or ``None`` (may fail after accepts())."""
        ...


def resolve_dispatcher(
    graph: FlowGraph | None,
    resolvers: tuple[DispatcherResolver, ...],
) -> DispatcherResolution | None:
    """Rank accepting resolvers and resolve via the best, falling back in order.

    Collects every resolver whose ``accepts(graph)`` returns a candidate, ranks
    them by ``(specificity, confidence)`` descending, then tries ``resolve()`` on
    each in rank order, returning the first non-``None`` resolution.
    """
    if graph is None:
        return None
    accepted: list[tuple[DispatcherResolver, ResolverCandidate]] = []
    for resolver in resolvers:
        candidate = resolver.accepts(graph)
        if candidate is not None:
            accepted.append((resolver, candidate))
    if not accepted:
        return None
    accepted.sort(
        key=lambda pair: (pair[1].specificity, pair[1].confidence),
        reverse=True,
    )
    for resolver, candidate in accepted:
        resolution = resolver.resolve(graph, candidate)
        if resolution is not None:
            return resolution
    return None
