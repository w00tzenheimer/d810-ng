"""Hodur constant-fixpoint backend boundary.

The capability Protocol's canonical home is
``d810.capabilities.constant_fixpoint`` (slice 3 of the
llvm-lisa-restructure plan).  This module keeps the symbol importable
from the old path for back-compat with the 7 existing import sites
under ``hodur/`` and ``hodur/strategies/``.  New code should import
``ConstantFixpointCapability`` from the canonical location.

Slice 6 (naming cleanup): the canonical class is now
``ConstantFixpointCapability``, matching the ``*Capability`` discipline
established by slice 5's ``UseDefSafetyCapability``.  The legacy name
``ConstantFixpointBackend`` is preserved as a back-compat alias.
"""
from __future__ import annotations

# Canonical home for the capability Protocol; both names re-exported
# below for back-compat (ConstantFixpointBackend) and new-code use
# (ConstantFixpointCapability).
from d810.capabilities.constant_fixpoint import (
    ConstantFixpointBackend,
    ConstantFixpointCapability,
)
from d810.recon.flow.state_machine_analysis import run_snapshot_constant_fixpoint


class HodurConstantFixpointBackend:
    """Default constant-fixpoint backend for Hodur strategies."""

    def compute(
        self,
        flow_graph: object,
        state_var_stkoff: int,
    ) -> object:
        return run_snapshot_constant_fixpoint(flow_graph, state_var_stkoff)


DEFAULT_HODUR_CONSTANT_FIXPOINT_BACKEND: ConstantFixpointCapability = (
    HodurConstantFixpointBackend()
)


__all__ = [
    "ConstantFixpointBackend",  # back-compat alias of ConstantFixpointCapability
    "ConstantFixpointCapability",  # re-export of canonical capability
    "DEFAULT_HODUR_CONSTANT_FIXPOINT_BACKEND",
    "HodurConstantFixpointBackend",
]
