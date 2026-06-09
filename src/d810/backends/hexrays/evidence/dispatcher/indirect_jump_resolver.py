"""IDA-bound indirect jump-table ``DispatcherResolver`` (llr-qb33).

The portable ``recover_dispatcher`` front-end (``build_dispatch_map_any_kind``)
recognizes equality-chain and switch-table dispatchers over a portable
``FlowGraph`` alone.  The Tigress computed-goto dispatcher lowers to a native
``jmp reg`` (``m_ijmp``) indexing a qword label table -- *resolving* it requires
reading that table from the binary (``ida_bytes``), which a portable resolver
cannot do.  This resolver wraps the IDA-bound discovery
(``discover_indirect_jump_table`` + ``analyze_tigress_indirect_dispatcher_from_config``)
behind the portable ``DispatcherResolver`` Protocol and is injected into the
shared front-end at runtime via
:func:`d810.analyses.control_flow.dispatcher_recovery.register_extra_dispatcher_resolver`
(the §1a entry binds the live ``mba`` into the instance).

``accepts()`` is deliberately SPECIFIC: it returns a candidate ONLY when the
function actually has a register-indirect jump (``m_ijmp``) whose qword table is
recoverable and whose decoded rows are non-empty.  On every non-indirect graph it
returns ``None``, so it never over-fires and cannot regress golden.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from d810.core.logging import getLogger
from d810.analyses.control_flow.dispatcher_resolution import (
    DispatcherResolution,
    ResolverCandidate,
)
from d810.capabilities.dispatcher import RouterKind
from d810.ir.flowgraph import FlowGraph, InsnKind
from d810.backends.hexrays.evidence.dispatcher.indirect_jump_table_analysis import (
    analyze_tigress_indirect_dispatcher_from_config,
)

logger = getLogger("D810.backends.indirect_jump_resolver")


def _graph_has_indirect_jump(graph: FlowGraph) -> bool:
    """Structural gate: does any block tail carry a single-target indirect jump?

    Keyed off the portable ``InsnKind.INDIRECT_JUMP`` (the lifter's projection of
    Hex-Rays ``m_ijmp``), so the cheap reject runs over the portable graph before
    any binary read.  Multi-target ``TABLE_JUMP`` (``m_jtbl``) is the switch-table
    resolver's province, NOT this one.
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
    """Resolve a Tigress ``m_ijmp`` indirect jump-table dispatcher (IDA-bound).

    Bound to one live ``mba`` (the function being decompiled).  ``goto_table_info``
    is the OPTIONAL config override consumed by
    ``analyze_tigress_indirect_dispatcher_from_config``; when empty the table layout
    is discovered structurally, so the resolver fires address-agnostically.

    ``specificity`` is high (12) so a genuine indirect dispatcher out-ranks the
    portable equality-chain (10) / switch-table (5) resolvers if they were to also
    accept -- in practice they return ``None`` on an ``m_ijmp`` graph, so ranking is
    behaviour-neutral and the gate keeps this resolver inert elsewhere.
    """

    mba: object
    goto_table_info: dict = field(default_factory=dict)
    name: str = "indirect_jump_table"
    router_kind: RouterKind = RouterKind.INDIRECT_TABLE
    specificity: int = 12

    def _analyze(self):
        """Run the IDA-bound indirect analysis; ``None`` on any miss/failure."""
        try:
            return analyze_tigress_indirect_dispatcher_from_config(
                self.mba, self.goto_table_info or {}
            )
        except Exception:  # noqa: BLE001 — analysis is best-effort; never break detection
            logger.debug("indirect jump-table analysis failed", exc_info=True)
            return None

    def accepts(self, graph: FlowGraph) -> ResolverCandidate | None:
        # Cheap portable structural gate first: no m_ijmp tail -> definitely not us.
        if not _graph_has_indirect_jump(graph):
            return None
        result = self._analyze()
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
                "rows=%d" % len(dmap.rows),
                "missing_targets=%d" % int(result.missing_target_count),
            ),
        )

    def resolve(
        self, graph: FlowGraph, candidate: ResolverCandidate
    ) -> DispatcherResolution | None:
        result = self._analyze()
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
