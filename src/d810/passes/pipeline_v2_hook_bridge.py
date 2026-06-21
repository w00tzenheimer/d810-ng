"""Explicit config-v2 bridge to the existing live Hex-Rays hook machinery.

This module does not make config-v2 pass ids magically executable through the
portable pass manager.  It derives the legacy live hook rule activations needed
for an explicit ``pipeline_v2_mode: config-v2`` project, while leaving the
generated ``pipeline_v2`` payload as the source of truth.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from d810.core.config import ProjectConfiguration, RuleConfiguration
from d810.passes.legacy_flow_rules import build_legacy_flow_rule_pass
from d810.passes.mba_simplify import MBA_SIMPLIFY_PASS_ID, build_mba_simplify_pass
from d810.passes.pass_pipeline import PipelineConfig, PipelineConfigError
from d810.passes.pipeline_config_parser import (
    PipelineV2Mode,
    pipeline_configs_from_project_config,
    pipeline_v2_mode_from_project_config,
)
from d810.passes.state_machine_spine import standard_state_machine_passes

STATE_MACHINE_UNFLATTENER_RULE = "StateMachineCffUnflattener"
STATE_MACHINE_NATIVE_PASS_IDS = tuple(
    spec.pass_id for spec in standard_state_machine_passes()
)


@dataclass(frozen=True)
class PipelineV2HookActivation:
    """Live hook rule activations derived from explicit config-v2 payloads."""

    enabled: bool
    configured_pass_ids: tuple[str, ...] = ()
    instruction_rules: tuple[RuleConfiguration, ...] = ()
    block_rules: tuple[RuleConfiguration, ...] = ()
    native_state_machine_pass_ids: tuple[str, ...] = ()


def _rule_config(name: str, config: object) -> RuleConfiguration:
    if config is None:
        config = {}
    if not isinstance(config, Mapping):
        raise PipelineConfigError(f"{name} runtime hook options must be a mapping")
    return RuleConfiguration(
        name=name,
        is_activated=True,
        config=dict(config),
    )


def _state_machine_rule_config(configs: tuple[PipelineConfig, ...]) -> RuleConfiguration:
    native_configs = tuple(
        config for config in configs if config.pass_id in STATE_MACHINE_NATIVE_PASS_IDS
    )
    if not native_configs:
        raise PipelineConfigError("state-machine native spine is empty")
    pass_ids = tuple(config.pass_id for config in native_configs)
    if pass_ids != STATE_MACHINE_NATIVE_PASS_IDS:
        raise PipelineConfigError(
            "config-v2 state-machine spine must contain the complete native pass "
            f"sequence: {list(STATE_MACHINE_NATIVE_PASS_IDS)}"
        )

    options_payloads: list[dict[str, object]] = []
    for config in native_configs:
        options = dict(config.options)
        legacy_rule = options.get("legacy_rule")
        if legacy_rule != STATE_MACHINE_UNFLATTENER_RULE:
            raise PipelineConfigError(
                "state-machine native spine entries must preserve "
                f"options.legacy_rule={STATE_MACHINE_UNFLATTENER_RULE!r}"
            )
        native_pipeline = tuple(options.get("native_pipeline", ()))
        if native_pipeline != STATE_MACHINE_NATIVE_PASS_IDS:
            raise PipelineConfigError(
                "state-machine native spine entries must preserve the native "
                "pipeline pass list"
            )
        legacy_options = options.get("legacy_rule_options", {})
        if not isinstance(legacy_options, dict):
            raise PipelineConfigError(
                "state-machine native spine entries require mapping "
                "options.legacy_rule_options"
            )
        options_payloads.append(dict(legacy_options))

    first = options_payloads[0]
    if any(payload != first for payload in options_payloads[1:]):
        raise PipelineConfigError(
            "state-machine native spine entries disagree on legacy_rule_options"
        )
    return _rule_config(STATE_MACHINE_UNFLATTENER_RULE, first)


def _instruction_rules_from(config: PipelineConfig) -> tuple[RuleConfiguration, ...]:
    adapter = build_mba_simplify_pass(config)
    return tuple(
        _rule_config(
            rule_name,
            adapter.rule_options.get(rule_name, {}),
        )
        for rule_name in adapter.rule_names
    )


def _flow_rule_from(config: PipelineConfig) -> RuleConfiguration:
    adapter = build_legacy_flow_rule_pass(config)
    return _rule_config(adapter.legacy_rule, adapter.rule_options)


def _dedupe_rule_configs(
    rules: list[RuleConfiguration],
    *,
    field_name: str,
) -> tuple[RuleConfiguration, ...]:
    seen: dict[str, dict[str, object]] = {}
    ordered: list[RuleConfiguration] = []
    for rule in rules:
        name = str(rule.name or "")
        if not name:
            raise PipelineConfigError(f"{field_name} contains an empty rule name")
        config = dict(rule.config)
        if name in seen:
            if seen[name] != config:
                raise PipelineConfigError(
                    f"{field_name} contains conflicting duplicate config for {name}"
                )
            continue
        seen[name] = config
        ordered.append(rule)
    return tuple(ordered)


def pipeline_v2_hook_activation(project_config) -> PipelineV2HookActivation:
    """Derive live Hex-Rays hook activation from explicit config-v2 projects.

    Legacy/default project modes return ``enabled=False``.  In config-v2 mode,
    legacy ``ins_rules`` / ``blk_rules`` are deliberately ignored by callers;
    this helper derives the live hook rules from ``pipeline_v2`` only.
    """
    mode = pipeline_v2_mode_from_project_config(project_config)
    if mode is not PipelineV2Mode.CONFIG_V2:
        return PipelineV2HookActivation(enabled=False)

    configs = pipeline_configs_from_project_config(project_config)
    if not configs:
        raise PipelineConfigError(
            "pipeline_v2_mode='config-v2' requires a pipeline_v2 payload"
        )

    instruction_rules: list[RuleConfiguration] = []
    block_rules: list[RuleConfiguration] = []
    native_present = any(
        config.pass_id in STATE_MACHINE_NATIVE_PASS_IDS for config in configs
    )
    if native_present:
        block_rules.append(_state_machine_rule_config(configs))

    for config in configs:
        pass_id = config.pass_id
        if pass_id == MBA_SIMPLIFY_PASS_ID:
            instruction_rules.extend(_instruction_rules_from(config))
            continue
        if pass_id in STATE_MACHINE_NATIVE_PASS_IDS:
            continue
        block_rules.append(_flow_rule_from(config))

    return PipelineV2HookActivation(
        enabled=True,
        configured_pass_ids=tuple(config.pass_id for config in configs),
        instruction_rules=_dedupe_rule_configs(
            instruction_rules,
            field_name="pipeline_v2 instruction rules",
        ),
        block_rules=_dedupe_rule_configs(
            block_rules,
            field_name="pipeline_v2 block rules",
        ),
        native_state_machine_pass_ids=(
            STATE_MACHINE_NATIVE_PASS_IDS if native_present else ()
        ),
    )


def pipeline_v2_native_state_machine_configs(project_config) -> tuple[PipelineConfig, ...]:
    """Return only native state-machine spine configs from an explicit v2 payload."""
    return tuple(
        config
        for config in pipeline_configs_from_project_config(project_config)
        if config.pass_id in STATE_MACHINE_NATIVE_PASS_IDS
    )


__all__ = [
    "PipelineV2HookActivation",
    "STATE_MACHINE_NATIVE_PASS_IDS",
    "STATE_MACHINE_UNFLATTENER_RULE",
    "pipeline_v2_hook_activation",
    "pipeline_v2_native_state_machine_configs",
]
