"""Explicit config-v2 bridge to the existing live Hex-Rays hook machinery.

This module does not make config-v2 pass ids magically executable through the
portable pass manager.  It derives the legacy live hook rule activations needed
for an explicit ``pipeline_v2_mode: config-v2`` project, while leaving the
generated ``pipeline_v2`` payload as the source of truth.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from d810.core.config import RuleConfiguration
from d810.passes.cleanup_family_adapter import (
    SIMPLE_FLATTENING_CLEANUP_PASS_ID,
    build_cleanup_family_adapter_pass,
)
from d810.passes.constant_simplification import (
    CONSTANT_SIMPLIFICATION_PASS_ID,
    constant_simplification_hook_rules,
)
from d810.passes.hook_transform_passes import build_hook_transform_pass
from d810.passes.mba_simplify import MBA_SIMPLIFY_PASS_ID, build_mba_simplify_pass
from d810.passes.mba_solve import (
    MBA_SOLVE_PASS_ID,
    build_mba_solve_pass,
    mba_solve_implementation,
)
from d810.passes.pass_pipeline import PipelineConfig, PipelineConfigError
from d810.passes.pipeline_config_parser import (
    PipelineV2Mode,
    pipeline_configs_from_project_config,
    pipeline_v2_mode_from_project_config,
)
from d810.passes.state_machine_options import (
    STATE_MACHINE_NATIVE_PASS_IDS,
    StateMachineCffFamily,
    StateMachineRecoveryStrategy,
    state_machine_cff_options_from_config,
)

STATE_MACHINE_UNFLATTENER_RULE = "StateMachineCffUnflattener"


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


def _state_machine_rule_config(
    configs: tuple[PipelineConfig, ...],
) -> RuleConfiguration:
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

    options = tuple(
        state_machine_cff_options_from_config(config) for config in native_configs
    )
    first = options[0]
    if any(value != first for value in options[1:]):
        raise PipelineConfigError(
            "state-machine native spine entries disagree on typed options"
        )
    hook_options: dict[str, object] = {
        "min_state_constant": first.min_state_constant
    }
    if first.family is StateMachineCffFamily.TIGRESS_INDIRECT:
        hook_options["profile"] = "tigress_indirect"
    if first.recovery_strategy is StateMachineRecoveryStrategy.REDUCED_PRODUCT:
        hook_options["recovery_engine"] = "reduced_product"
    return _rule_config(
        STATE_MACHINE_UNFLATTENER_RULE,
        hook_options,
    )


def _instruction_rules_from(config: PipelineConfig) -> tuple[RuleConfiguration, ...]:
    adapter = build_mba_simplify_pass(config)
    return tuple(
        _rule_config(
            implementation_name,
            adapter.transform_options.get(transform_id, {}),
        )
        for transform_id, implementation_name in zip(
            adapter.transform_ids,
            adapter.implementation_names,
            strict=True,
        )
    )


# The rule implementing ``mba-solve`` is declared by whichever extension
# provides it; d810 ships no solver. See ``mba_solve.mba_solve_implementation``.


def _mba_solve_options(config: PipelineConfig) -> dict[str, object]:
    """Validate ``mba-solve`` options through its pass and pass them to the rule."""
    adapter = build_mba_solve_pass(config)
    return {
        "max_leaves": adapter.max_leaves,
        "require_proof": adapter.require_proof,
        # Portable IRMaturity names; the rule maps them to MMAT_* so this layer
        # stays hexrays-agnostic.
        "maturities": list(adapter.maturities),
        # The rule sees only what is forwarded here, so anything the pass
        # validates and the editor offers must appear in this dict or it is a
        # setting that looks configurable and silently does nothing.
        "auto_install_solver": adapter.auto_install_solver,
    }


def _flow_rule_from(config: PipelineConfig) -> RuleConfiguration:
    adapter = build_hook_transform_pass(config)
    return _rule_config(adapter.implementation_name, adapter.transform_options)


def _cleanup_family_rule_from(config: PipelineConfig) -> RuleConfiguration:
    adapter = build_cleanup_family_adapter_pass(config)
    return _rule_config(adapter.implementation_name, adapter.transform_options)


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


def _validate_constant_simplification_ownership(
    configs: tuple[PipelineConfig, ...],
) -> None:
    bundles = tuple(
        config
        for config in configs
        if config.pass_id == CONSTANT_SIMPLIFICATION_PASS_ID
    )
    if not bundles:
        return
    if len(bundles) != 1:
        raise PipelineConfigError(
            "constant-simplification may appear at most once in pipeline_v2"
        )
    conflicting_passes = {"forward-constant-propagation"}
    for config in configs:
        if config.pass_id in conflicting_passes:
            raise PipelineConfigError(
                "constant-simplification cannot coexist with legacy constant pass "
                f"{config.pass_id!r}"
            )


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
    _validate_constant_simplification_ownership(configs)

    instruction_rules: list[RuleConfiguration] = []
    block_rules: list[RuleConfiguration] = []
    native_present = any(
        config.pass_id in STATE_MACHINE_NATIVE_PASS_IDS for config in configs
    )
    if native_present:
        block_rules.append(_state_machine_rule_config(configs))

    for config in configs:
        pass_id = config.pass_id
        if pass_id == CONSTANT_SIMPLIFICATION_PASS_ID:
            bundle = constant_simplification_hook_rules(config)
            instruction_rules.extend(bundle.instruction_rules)
            block_rules.extend(bundle.block_rules)
            continue
        if pass_id == MBA_SIMPLIFY_PASS_ID:
            instruction_rules.extend(_instruction_rules_from(config))
            continue
        if pass_id == MBA_SOLVE_PASS_ID:
            # Solver-backed simplification is a single instruction rule rather
            # than a transform list, so it needs its own branch: without one it
            # falls through to _flow_rule_from below and is misfiled as a block
            # rule, which silently never runs.
            rule_name = mba_solve_implementation()
            if rule_name is None:
                # Nothing installed implements it. Emitting a rule config for a
                # class that will never register would put an unresolvable name
                # into the hook pipeline; skipping leaves mba-solve simply
                # absent, which is what "no solver installed" means.
                continue
            instruction_rules.append(
                _rule_config(rule_name, _mba_solve_options(config))
            )
            continue
        if pass_id in STATE_MACHINE_NATIVE_PASS_IDS:
            continue
        if pass_id == SIMPLE_FLATTENING_CLEANUP_PASS_ID:
            block_rules.append(_cleanup_family_rule_from(config))
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


def pipeline_v2_native_state_machine_configs(
    project_config,
) -> tuple[PipelineConfig, ...]:
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
