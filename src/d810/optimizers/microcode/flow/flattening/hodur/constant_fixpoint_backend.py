"""Hodur constant-fixpoint backend boundary.

The ``ConstantFixpointBackend`` Protocol's canonical home is
``d810.capabilities.constant_fixpoint`` (slice 3 of the
llvm-lisa-restructure plan).  This module keeps the symbol importable
from the old path for back-compat with the 7 existing import sites
under ``hodur/`` and ``hodur/strategies/``.  New code should import
from the canonical location.
"""
from __future__ import annotations

# Canonical home for ConstantFixpointBackend; re-exported below for back-compat.
from d810.capabilities.constant_fixpoint import ConstantFixpointBackend
from d810.recon.flow.state_machine_analysis import run_snapshot_constant_fixpoint


class HodurConstantFixpointBackend:
    """Default constant-fixpoint backend for Hodur strategies."""

    def compute(
        self,
        flow_graph: object,
        state_var_stkoff: int,
    ) -> object:
        return run_snapshot_constant_fixpoint(flow_graph, state_var_stkoff)


DEFAULT_HODUR_CONSTANT_FIXPOINT_BACKEND: ConstantFixpointBackend = (
    HodurConstantFixpointBackend()
)


__all__ = [
    "ConstantFixpointBackend",
    "DEFAULT_HODUR_CONSTANT_FIXPOINT_BACKEND",
    "HodurConstantFixpointBackend",
]
