"""Named operational registry composition for config-v2 pass execution."""

from __future__ import annotations

from d810.passes.cleanup_family_adapter import register_cleanup_family_adapter_passes
from d810.passes.constant_simplification import (
    register_constant_simplification_pass,
)
from d810.passes.hook_transform_passes import register_hook_transform_passes
from d810.passes.mba_simplify import register_mba_simplify_pass
from d810.passes.mba_egraph import register_mba_egraph_pass
from d810.passes.mba_solve import register_mba_solve_pass
from d810.passes.rotate_idiom_recovery import register_rotate_idiom_recovery_pass
from d810.passes.registry import PassRegistry
from d810.passes.state_machine_spine import register_state_machine_passes

CONFIG_V2_OPERATIONAL_REGISTRY_NAME = "config_v2_operational"


def register_operational_config_v2_passes(registry: PassRegistry) -> PassRegistry:
    """Register currently executable config-v2 pass ids on ``registry``."""
    register_mba_simplify_pass(registry)
    register_mba_egraph_pass(registry)
    register_mba_solve_pass(registry)
    register_rotate_idiom_recovery_pass(registry)
    register_constant_simplification_pass(registry)
    register_state_machine_passes(registry)
    register_hook_transform_passes(registry)
    register_cleanup_family_adapter_passes(registry)
    return registry


def operational_config_v2_pass_registry() -> PassRegistry:
    """Return the D810-native config-v2 operational registry."""
    return register_operational_config_v2_passes(PassRegistry())


def default_pass_registries() -> dict[str, PassRegistry]:
    """Return default named pass registries for ModulePassManager."""
    return {CONFIG_V2_OPERATIONAL_REGISTRY_NAME: operational_config_v2_pass_registry()}


__all__ = [
    "CONFIG_V2_OPERATIONAL_REGISTRY_NAME",
    "default_pass_registries",
    "operational_config_v2_pass_registry",
    "register_operational_config_v2_passes",
]
