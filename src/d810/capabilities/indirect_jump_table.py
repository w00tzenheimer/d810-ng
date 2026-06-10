"""Indirect jump-table capability Protocol (llr-dczv).

Describes the backend boundary for "decode the qword label table behind a
register-indirect (``m_ijmp``) or *materialized* computed-goto dispatcher and
return its exact ``state_const -> handler-block`` rows".

A portable resolver
(:class:`d810.analyses.control_flow.indirect_jump_resolver.IndirectJumpDispatcherResolver`
-- the unflatten indirect spine) depends ONLY on a portable
:class:`~d810.ir.flowgraph.FlowGraph` and this Protocol; the live binary read
(``ida_bytes.get_qword`` over the table, native label-EA -> MBA-block mapping)
lives in the Hex-Rays implementation
(:class:`d810.backends.hexrays.evidence.dispatcher.indirect_jump_capability.HexRaysIndirectJumpTableCapability`).
A future angr / Ghidra backend would implement this Protocol over its own binary
reader.

``goto_table_info`` is the OPTIONAL per-function config override consumed by the
backend (stale after a rebuild -> the backend falls back to structural
discovery), passed through untyped so this layer stays config-format agnostic.

The portable result is ``IndirectJumpTableResult`` -- the SAME model the resolver
consumes, defined at
:mod:`d810.analyses.control_flow.indirect_jump_table_analysis` (it wraps a
portable :class:`~d810.analyses.control_flow.dispatcher_resolution.StateDispatcherMap`
of int block serials -- no ``BlockRef`` -- plus the count of table rows whose
native label has no live MBA block, ``missing_target_count``).  The result model
lives in ``d810.analyses`` (the layer that owns ``StateDispatcherMap``); the
layered-architecture contract forbids the lower ``capabilities`` layer from
importing it at runtime, so it is referenced here only under ``TYPE_CHECKING``
(excluded from import-linter) for the Protocol return annotation.  Call sites in
``d810.analyses`` import the concrete type directly from its home module.

This module must stay IDA-free (``portable-core-no-ida``): it imports only
``Protocol``, ``FlowGraph``, and (type-checking only) the result type.
"""
from __future__ import annotations

from d810.core.typing import TYPE_CHECKING, Protocol, runtime_checkable

from d810.ir.flowgraph import FlowGraph

if TYPE_CHECKING:
    from d810.analyses.control_flow.indirect_jump_table_analysis import (
        IndirectJumpTableResult,
    )

__all__ = ["IndirectJumpTableCapability"]


@runtime_checkable
class IndirectJumpTableCapability(Protocol):
    """Capability boundary for indirect / materialized jump-table decoding.

    A concrete backend answers: "given this function's portable CFG, decode the
    qword label table behind its register-indirect (or materialized) dispatcher
    and return the exact ``state_const -> handler-block`` rows".  The portable
    answer is an ``IndirectJumpTableResult`` (or ``None`` when the function has no
    such table -- this self-gating IS the real filter the portable resolver
    relies on).
    """

    def analyze_indirect_dispatcher(
        self,
        graph: FlowGraph,
        *,
        goto_table_info: dict | None = None,
    ) -> "IndirectJumpTableResult | None":
        """Return the decoded indirect jump-table result, or ``None`` on a miss.

        Args:
            graph: Portable CFG snapshot of the function being analyzed.  The
                backend may rely on its own live function handle for the binary
                read; ``graph`` carries the portable structure the resolver
                already holds (block serials, tails) so the capability can be
                consulted without re-lifting.
            goto_table_info: OPTIONAL per-function config override (table
                address / count / dispatch-jump EA / state-machine params).  When
                empty or stale the backend recovers the layout structurally, so a
                partial / absent mapping is fine.

        Returns:
            An ``IndirectJumpTableResult`` whose ``state_dispatcher_map`` has
            non-empty rows, or ``None`` when the function carries no indirect /
            materialized jump-table dispatcher.
        """
        ...
