"""LFG residual-handoff resolution backend boundary."""
from __future__ import annotations

from d810.core.typing import Protocol
from d810.recon.flow.residual_handoff_discovery import (
    resolve_assignment_map_handoff_target,
    resolve_immediate_handoff_target,
    resolve_projected_path_tail_target,
    resolve_projected_snapshot_handoff_target,
)
from d810.recon.flow.residual_handoff_resolution import (
    resolve_effective_target_entry,
    resolve_synthesized_handoff_target,
)


class LinearizedFlowGraphHandoffResolutionBackend(Protocol):
    """Backend boundary for LFG residual-handoff target callbacks."""

    def resolve_effective_target_entry(self, *args, **kwargs) -> object:
        """Resolve the effective target entry for a DAG edge."""

    def resolve_synthesized_handoff_target(self, *args, **kwargs) -> object:
        """Resolve a synthesized handoff target."""

    def resolve_projected_path_tail_target(self, *args, **kwargs) -> object:
        """Resolve a projected path-tail handoff target."""

    def resolve_immediate_handoff_target(self, *args, **kwargs) -> object:
        """Resolve an immediate handoff target."""

    def resolve_projected_snapshot_handoff_target(self, *args, **kwargs) -> object:
        """Resolve a projected snapshot handoff target."""

    def resolve_assignment_map_handoff_target(self, *args, **kwargs) -> object:
        """Resolve a handoff target from state-machine assignment evidence."""


class HodurLinearizedFlowGraphHandoffResolutionBackend:
    """Default LFG handoff-resolution backend."""

    def resolve_effective_target_entry(self, *args, **kwargs) -> object:
        return resolve_effective_target_entry(*args, **kwargs)

    def resolve_synthesized_handoff_target(self, *args, **kwargs) -> object:
        return resolve_synthesized_handoff_target(*args, **kwargs)

    def resolve_projected_path_tail_target(self, *args, **kwargs) -> object:
        return resolve_projected_path_tail_target(*args, **kwargs)

    def resolve_immediate_handoff_target(self, *args, **kwargs) -> object:
        return resolve_immediate_handoff_target(*args, **kwargs)

    def resolve_projected_snapshot_handoff_target(self, *args, **kwargs) -> object:
        return resolve_projected_snapshot_handoff_target(*args, **kwargs)

    def resolve_assignment_map_handoff_target(self, *args, **kwargs) -> object:
        return resolve_assignment_map_handoff_target(*args, **kwargs)


DEFAULT_HODUR_LFG_HANDOFF_RESOLUTION_BACKEND: (
    LinearizedFlowGraphHandoffResolutionBackend
) = HodurLinearizedFlowGraphHandoffResolutionBackend()


__all__ = [
    "DEFAULT_HODUR_LFG_HANDOFF_RESOLUTION_BACKEND",
    "HodurLinearizedFlowGraphHandoffResolutionBackend",
    "LinearizedFlowGraphHandoffResolutionBackend",
]
