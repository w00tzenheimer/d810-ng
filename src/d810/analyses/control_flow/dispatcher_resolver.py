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
    DispatcherCandidateIdentity,
    DispatcherResolution,
    ResolverCandidate,
    StateDispatcherMap,
)
from d810.capabilities.dispatcher import RouterKind, TableProvenance
from d810.ir.flowgraph import FlowGraph

__all__ = [
    "DispatcherResolver",
    "dispatcher_map_identity",
    "dispatcher_resolution_identity",
    "resolve_dispatcher",
]


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
    *,
    excluded_identities: frozenset[DispatcherCandidateIdentity] = frozenset(),
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
        if resolution is None:
            continue
        if dispatcher_resolution_identity(graph, resolution) in excluded_identities:
            continue
        return resolution
    return None


def dispatcher_resolution_identity(
    graph: FlowGraph,
    resolution: DispatcherResolution,
) -> DispatcherCandidateIdentity:
    """Project a resolution to native/state identity, never block serial identity."""
    return dispatcher_map_identity(
        graph,
        resolution.dispatcher_map,
        resolver_name=resolution.resolver_name,
        router_kind=resolution.router_kind,
        table_provenance=resolution.table_provenance,
    )


def dispatcher_map_identity(
    graph: FlowGraph,
    dmap: StateDispatcherMap,
    *,
    resolver_name: str,
    router_kind: RouterKind,
    table_provenance: TableProvenance | None,
) -> DispatcherCandidateIdentity:
    """Project a dispatcher map plus resolver provenance to stable identity."""
    dispatcher_block = graph.blocks.get(int(dmap.dispatcher_entry_block))
    dispatcher_ea = 0
    if dispatcher_block is not None:
        native_start_ea = getattr(dispatcher_block, "native_start_ea", None)
        dispatcher_ea = int(
            dispatcher_block.start_ea
            if native_start_ea is None
            else native_start_ea
        )
    if dmap.state_var_stkoff is not None:
        state_kind = "stack"
        state_value = int(dmap.state_var_stkoff)
    elif dmap.state_var_reg is not None:
        state_kind = "register"
        state_value = int(dmap.state_var_reg)
    else:
        state_kind = "unknown"
        state_value = None
    return DispatcherCandidateIdentity(
        resolver_name=str(resolver_name),
        router_kind=router_kind,
        table_provenance=table_provenance,
        dispatcher_entry_ea=dispatcher_ea,
        state_location_kind=state_kind,
        state_location_value=state_value,
    )
