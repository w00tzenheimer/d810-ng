"""Hodur constant-fixpoint backend boundary."""
from __future__ import annotations

from d810.core.typing import Protocol
from d810.recon.flow.state_machine_analysis import run_snapshot_constant_fixpoint


class ConstantFixpointBackend(Protocol):
    """Backend boundary for state-variable constant propagation evidence."""

    def compute(
        self,
        flow_graph: object,
        state_var_stkoff: int,
    ) -> object:
        """Compute constant propagation facts for a flow graph snapshot."""


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
