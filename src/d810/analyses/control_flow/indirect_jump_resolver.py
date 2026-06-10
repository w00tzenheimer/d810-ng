"""Portable indirect jump-table ``DispatcherResolver`` (llr-dczv).

The portable ``recover_dispatcher`` front-end (``build_dispatch_map_any_kind``)
recognizes equality-chain and switch-table dispatchers over a portable
:class:`~d810.ir.flowgraph.FlowGraph` alone.  The Tigress computed-goto
dispatcher lowers to a native ``jmp reg`` (``m_ijmp``) indexing a qword label
table -- *resolving* it requires reading that table from the binary, which a
portable resolver cannot do.  This resolver depends ONLY on the portable
``FlowGraph`` plus an injected :class:`~d810.capabilities.indirect_jump_table`.
``IndirectJumpTableCapability`` (the binary read lives in the backend impl), so
it stays IDA-free (``portable-core-no-ida``).  It is injected into the shared
front-end at runtime via
:func:`d810.analyses.control_flow.dispatcher_recovery.register_extra_dispatcher_resolver`
(the unflatten entry constructs it with a ``HexRaysIndirectJumpTableCapability`` bound
to the live ``mba``).

RECOGNITION SURVIVES MATERIALIZATION (llr-tm3i).  The unflatten indirect prepass
*materializes* the computed-goto label bodies before the MBA is built, which
REMOVES the ``m_ijmp`` (direct flow; there is no ``m_jtbl`` either).  So a gate
that REQUIRES an ``m_ijmp`` tail would reject the very dispatcher it just made
recoverable.  Because this resolver is registered ONLY under the unflatten indirect
config (the registry is config-gated, so it never runs for hodur/approov/switch),
``accepts()`` can afford a more lenient gate:

    accept if (portable graph still has an ``m_ijmp`` tail)
           OR (the capability's analysis returns a non-empty StateDispatcherMap)

The capability's own self-gating (it returns ``None`` when there is no table) is
the real filter -- and it is cheap relative to a decompile, only running under
the indirect config -- so the materialized hub (resolved by the backend's
``_find_materialized_dispatcher_serial``) is recognized end-to-end.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from d810.core.logging import getLogger
from d810.analyses.control_flow.dispatcher_resolution import (
    DispatcherResolution,
    ResolverCandidate,
)
from d810.capabilities.dispatcher import RouterKind
from d810.capabilities.indirect_jump_table import IndirectJumpTableCapability
from d810.analyses.control_flow.indirect_jump_table_analysis import (
    IndirectJumpTableResult,
)
from d810.ir.flowgraph import FlowGraph, InsnKind

logger = getLogger("D810.analyses.indirect_jump_resolver")


def _graph_has_indirect_jump(graph: FlowGraph) -> bool:
    """Cheap pre-gate: does any block tail carry a single-target indirect jump?

    Keyed off the portable ``InsnKind.INDIRECT_JUMP`` (the lifter's projection of
    Hex-Rays ``m_ijmp``), so the cheap accept runs over the portable graph with
    no binary read.  Multi-target ``TABLE_JUMP`` (``m_jtbl``) is the switch-table
    resolver's province, NOT this one.  AFTER materialization this returns
    ``False`` (the ``m_ijmp`` is gone), so it is a fast-accept, NOT the sole gate
    -- ``accepts()`` falls through to the capability's self-gating analysis.
    """
    for blk in graph.blocks.values():
        tail = getattr(blk, "tail", None)
        if tail is not None and getattr(tail, "kind", None) is InsnKind.INDIRECT_JUMP:
            return True
        for insn in getattr(blk, "insn_snapshots", ()):
            if getattr(insn, "kind", None) is InsnKind.INDIRECT_JUMP:
                return True
    return False


@dataclass
class IndirectJumpDispatcherResolver:
    """Resolve a Tigress indirect / materialized jump-table dispatcher (portable).

    Depends only on the portable ``FlowGraph`` and an injected
    :class:`IndirectJumpTableCapability`; the binary read lives behind the
    capability so this resolver is IDA-free.  ``goto_table_info`` is the OPTIONAL
    config override passed through to the capability; when empty the table layout
    is discovered structurally, so the resolver fires address-agnostically.

    ``specificity`` is high (12) so a genuine indirect dispatcher out-ranks the
    portable equality-chain (10) / switch-table (5) resolvers if they were to also
    accept -- in practice they return ``None`` on an indirect graph, so ranking is
    behaviour-neutral and the gate keeps this resolver inert elsewhere (it is only
    registered under the unflatten indirect config).
    """

    indirect_tables: IndirectJumpTableCapability
    goto_table_info: dict = field(default_factory=dict)
    name: str = "indirect_jump_table"
    router_kind: RouterKind = RouterKind.INDIRECT_TABLE
    specificity: int = 12

    def _analyze(self, graph: FlowGraph) -> IndirectJumpTableResult | None:
        """Run the injected capability; ``None`` on any miss/failure."""
        try:
            return self.indirect_tables.analyze_indirect_dispatcher(
                graph, goto_table_info=self.goto_table_info or {}
            )
        except Exception:  # noqa: BLE001 — analysis is best-effort; never break detection
            logger.debug("indirect jump-table analysis failed", exc_info=True)
            return None

    def accepts(self, graph: FlowGraph) -> ResolverCandidate | None:
        # The cheap m_ijmp pre-gate is a fast-ACCEPT, not the sole filter: after
        # materialization there is no m_ijmp tail, so we still consult the
        # capability (its own self-gating returns None for non-dispatchers, and
        # it only runs under the indirect config). Recognition therefore survives
        # materialization.
        result = self._analyze(graph)
        if result is None:
            return None
        dmap = result.state_dispatcher_map
        if not getattr(dmap, "rows", None):
            return None
        return ResolverCandidate(
            resolver_name=self.name,
            router_kind=self.router_kind,
            confidence=float(len(dmap.rows)),
            specificity=self.specificity,
            reasons=(
                "indirect-jump-table",
                "materialized" if not _graph_has_indirect_jump(graph) else "m_ijmp",
                "rows=%d" % len(dmap.rows),
                "missing_targets=%d" % int(result.missing_target_count),
            ),
        )

    def resolve(
        self, graph: FlowGraph, candidate: ResolverCandidate
    ) -> DispatcherResolution | None:
        result = self._analyze(graph)
        if result is None:
            return None
        dmap = result.state_dispatcher_map
        if not getattr(dmap, "rows", None):
            return None
        return DispatcherResolution(
            dispatcher_map=dmap,
            resolver_name=self.name,
            router_kind=self.router_kind,
            confidence=candidate.confidence,
            ranking_reason=candidate.reasons,
        )


__all__ = ["IndirectJumpDispatcherResolver"]
