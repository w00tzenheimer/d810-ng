"""State-machine CFF family compatibility exports for the native pass spine."""
from __future__ import annotations

from d810.passes.state_machine_spine import (
    CLEANUP_ANALYSES,
    DISPATCHER_ANALYSES,
    LOWER_ANALYSES,
    REGION_ANALYSES,
    TRANSITION_ANALYSES,
    register_state_machine_passes,
    state_machine_pass_registry,
    state_machine_pass_spec,
    standard_state_machine_passes,
)

__all__ = [
    "CLEANUP_ANALYSES",
    "DISPATCHER_ANALYSES",
    "LOWER_ANALYSES",
    "REGION_ANALYSES",
    "TRANSITION_ANALYSES",
    "register_state_machine_passes",
    "state_machine_pass_registry",
    "state_machine_pass_spec",
    "standard_state_machine_passes",
]
