"""Hex-Rays implementation of the indirect jump-table capability (llr-dczv).

Wraps the IDA-bound table decode
(:func:`analyze_tigress_indirect_dispatcher_from_config` -- reads the qword label
table via ``ida_bytes`` and maps native label EAs to live MBA blocks) behind the
portable :class:`~d810.capabilities.indirect_jump_table.IndirectJumpTableCapability`
Protocol, so the portable resolver in ``d810.analyses.control_flow`` stays
IDA-free.  Bound to one live ``mba`` (the function being decompiled); the unflatten
entry constructs it with the live mba and injects it into
:class:`d810.analyses.control_flow.indirect_jump_resolver.IndirectJumpDispatcherResolver`.

The underlying analysis already handles BOTH the register-indirect (``m_ijmp``)
hub and the *materialized* hub (via ``_find_materialized_dispatcher_serial``), so
the portable resolver's lenient ``accepts()`` -- which consults this capability
after materialization removes the ``m_ijmp`` -- recovers the dispatcher rows
end-to-end.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.core.logging import getLogger
from d810.analyses.control_flow.indirect_jump_table_analysis import (
    IndirectJumpTableResult,
)
from d810.ir.flowgraph import FlowGraph
from d810.backends.hexrays.evidence.dispatcher.indirect_jump_table_analysis import (
    analyze_tigress_indirect_dispatcher_from_config,
)

logger = getLogger("D810.backends.indirect_jump_capability")


@dataclass
class HexRaysIndirectJumpTableCapability:
    """Decode an indirect / materialized jump-table over the live ``mba``.

    ``mba`` is the live ``ida_hexrays.mba_t`` for the function being decompiled.
    ``analyze_indirect_dispatcher`` ignores the portable ``graph`` argument (the
    decode reads the binary table + the live MBA directly) -- it is part of the
    Protocol signature so a portable resolver can be consulted with the CFG it
    already holds; a future angr backend would use it.
    """

    mba: object

    def analyze_indirect_dispatcher(
        self,
        graph: FlowGraph,
        *,
        goto_table_info: dict | None = None,
    ) -> IndirectJumpTableResult | None:
        """Decode the table for this function; ``None`` on any miss/failure."""
        try:
            return analyze_tigress_indirect_dispatcher_from_config(
                self.mba, goto_table_info or {}
            )
        except Exception:  # noqa: BLE001 — analysis is best-effort; never break detection
            logger.debug("indirect jump-table analysis failed", exc_info=True)
            return None


__all__ = ["HexRaysIndirectJumpTableCapability"]
