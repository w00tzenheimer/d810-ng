"""Deprecated import shim for the config-v2 hook runtime.

The compiler moved to :mod:`d810.passes.config_v2_hook_runtime`.  This module
is intentionally import-only for the staged cutover and is deleted once all
remaining consumers have moved.
"""

from d810.passes.config_v2_hook_runtime import (
    _rule_config,
    STATE_MACHINE_NATIVE_PASS_IDS,
    STATE_MACHINE_RUNTIME_HOST,
    STATE_MACHINE_UNFLATTENER_RULE,
    ConfigV2HookSchedule,
    ConfigV2HookSchedule as PipelineV2HookActivation,
    compile_config_v2_hook_schedule,
    compile_config_v2_hook_schedule as pipeline_v2_hook_activation,
    config_v2_native_state_machine_configs,
    config_v2_native_state_machine_configs as pipeline_v2_native_state_machine_configs,
    requires_native_preanalysis_handlers,
)

__all__ = [
    "ConfigV2HookSchedule",
    "PipelineV2HookActivation",
    "STATE_MACHINE_NATIVE_PASS_IDS",
    "STATE_MACHINE_RUNTIME_HOST",
    "STATE_MACHINE_UNFLATTENER_RULE",
    "compile_config_v2_hook_schedule",
    "config_v2_native_state_machine_configs",
    "pipeline_v2_hook_activation",
    "pipeline_v2_native_state_machine_configs",
    "requires_native_preanalysis_handlers",
]
