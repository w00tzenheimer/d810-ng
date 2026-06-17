"""Portable carrier-resolution boundary for exit-path effect discovery.

Recon (this layer) computes carrier classification from portable
``FlowGraph`` snapshots alone.  When a state-variable write is indirect
and the snapshot cannot name the constant, recon delegates that single
genuinely-live question -- "what constant did this indirect state write
resolve to?" -- to an injected :class:`CarrierResolver`.

The live implementation lives in the optimizer layer (which is permitted
to import Hex-Rays), so recon never imports ``d810.hexrays`` to answer it.
"""
from __future__ import annotations

from d810.core.typing import Protocol, runtime_checkable
from d810.analyses.control_flow.state_machine_analysis import CarrierResolutionResult


@runtime_checkable
class CarrierResolver(Protocol):
    """Resolve an indirect state-var write the snapshot alone cannot.

    Implemented in the optimizer/backend layer, which holds the live
    ``mba``.  Returns ``None`` when the write cannot be resolved, in
    which case recon keeps its snapshot-derived carrier bucket.
    """

    def resolve_indirect_state_write(
        self,
        candidate_serial: int,
        state_var_stkoff: int,
    ) -> CarrierResolutionResult | None:
        ...
