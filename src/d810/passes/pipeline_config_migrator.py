"""Deterministic legacy ProjectConfiguration to PipelineConfig v2 shadow migration."""
from __future__ import annotations

import json
from pathlib import Path

from d810.core.config import ProjectConfiguration, RuleConfiguration
from d810.passes.pass_pipeline import PipelineConfigError


_EXPRESSION_MATURITY = {
    "range": {
        "min": "ir.canonical",
        "max": "ir.global.optimized",
    }
}

_BLOCK_MATURITY = {
    "range": {
        "min": "ir.canonical",
        "max": "ir.global.optimized",
    }
}

_STATE_MACHINE_MATURITY = {
    "runs_at": "ir.global.analyzed",
}

_BLOCK_RULE_PASS_IDS = {
    "BlockLevelEgglogOptimizer": "block-level-egglog-optimizer",
    "GlobalConstantInliner": "global-constant-inliner",
    "ForwardConstantPropagationRule": "forward-constant-propagation",
    "MbaStatePreconditioner": "mba-state-preconditioner",
    "StateMachineCffUnflattener": "state-machine-cff-unflattener",
    "JumpFixer": "jump-fixer",
}

_STATE_MACHINE_NATIVE_PIPELINE = [
    "recover_dispatcher",
    "recover_state_transitions",
    "plan_semantic_regions",
    "lower_state_machine",
    "cleanup_residual_dispatcher",
]

_Z3_INSTRUCTION_RULES = frozenset(
    {
        "Z3ConstantOptimization",
    }
)


def _json_copy(value: object, field_name: str) -> object:
    try:
        return json.loads(json.dumps(value))
    except (TypeError, ValueError) as exc:
        raise PipelineConfigError(f"{field_name} must be JSON-compatible") from exc


def _rule_name(rule: RuleConfiguration, field_name: str) -> str:
    if not isinstance(rule.name, str) or not rule.name:
        raise PipelineConfigError(f"{field_name} name must be a non-empty string")
    return rule.name


def _active_rules(rules: list[RuleConfiguration]) -> list[RuleConfiguration]:
    return [rule for rule in rules if rule.is_activated]


def _non_empty_rule_options(
    rules: list[RuleConfiguration],
    *,
    field_name: str,
) -> dict[str, object]:
    options: dict[str, object] = {}
    for rule in rules:
        rule_name = _rule_name(rule, field_name)
        if rule.config:
            options[rule_name] = _json_copy(rule.config, f"{field_name}.{rule_name}")
    return options


def _instruction_rule_requires_z3(rule_name: str) -> bool:
    return rule_name.startswith("Z3") or rule_name in _Z3_INSTRUCTION_RULES


def _instruction_capabilities(rules: list[RuleConfiguration]) -> list[str]:
    capabilities = ["local_instruction_rewrite"]
    if any(
        _instruction_rule_requires_z3(_rule_name(rule, "ins_rules"))
        for rule in rules
    ):
        capabilities.append("z3_solver")
    return capabilities


def _instruction_pass(
    rules: list[RuleConfiguration],
    *,
    source_config: str,
) -> dict[str, object]:
    active_rules = _active_rules(rules)
    return {
        "pass": "mba-simplify",
        "scope": "expression",
        "maturity": _json_copy(_EXPRESSION_MATURITY, "maturity"),
        "requires": {
            "capabilities": _instruction_capabilities(active_rules)
        },
        "migration": {
            "source_config": source_config,
            "source_section": "ins_rules",
        },
        "rules": {
            "include": [
                _rule_name(rule, "ins_rules")
                for rule in active_rules
            ],
            "exclude": [],
            "options": _non_empty_rule_options(
                active_rules,
                field_name="ins_rules",
            ),
        },
    }


def _block_pass(
    rule: RuleConfiguration,
    *,
    source_config: str,
) -> dict[str, object]:
    rule_name = _rule_name(rule, "blk_rules")
    try:
        pass_id = _BLOCK_RULE_PASS_IDS[rule_name]
    except KeyError as exc:
        raise PipelineConfigError(
            f"unsupported legacy block rule for pipeline_v2 shadow: {rule_name}"
        ) from exc

    if rule_name == "StateMachineCffUnflattener":
        scope = "function"
        maturity = _STATE_MACHINE_MATURITY
    else:
        scope = "block"
        maturity = _BLOCK_MATURITY

    copied_config = _json_copy(rule.config, f"blk_rules.{rule_name}")
    if not isinstance(copied_config, dict):
        raise PipelineConfigError(f"blk_rules.{rule_name} config must be a mapping")

    options = {
        "legacy_rule": rule_name,
        **copied_config,
    }
    if rule_name == "StateMachineCffUnflattener":
        options["native_pipeline"] = list(_STATE_MACHINE_NATIVE_PIPELINE)

    return {
        "pass": pass_id,
        "scope": scope,
        "maturity": _json_copy(maturity, "maturity"),
        "migration": {
            "source_config": source_config,
            "source_section": "blk_rules",
            "source_rule": rule_name,
        },
        "options": options,
    }


def _shadow_metadata(
    project_config: ProjectConfiguration,
    *,
    source_config: str,
) -> dict[str, object]:
    metadata: dict[str, object] = {
        "source_config": source_config,
        "runtime_source": "legacy",
    }
    if "enable_pass_pipeline" in project_config.additional_configuration:
        metadata["enable_pass_pipeline"] = _json_copy(
            project_config.additional_configuration["enable_pass_pipeline"],
            "additional_configuration.enable_pass_pipeline",
        )
    return metadata


def legacy_project_config_to_pipeline_v2_shadow(
    project_config: ProjectConfiguration,
    *,
    source_config: str | None = None,
) -> dict[str, object]:
    """Return a JSON-compatible PipelineConfig v2 shadow for a legacy config.

    The legacy config remains the runtime source of truth; this migrator only
    renders deterministic shadow metadata that the parser can inspect.
    """
    source_name = source_config or Path(project_config.path).name
    pipeline_v2: list[dict[str, object]] = []
    if _active_rules(project_config.ins_rules):
        pipeline_v2.append(
            _instruction_pass(project_config.ins_rules, source_config=source_name)
        )
    for rule in _active_rules(project_config.blk_rules):
        pipeline_v2.append(_block_pass(rule, source_config=source_name))

    return {
        "description": (
            f"Config-v2 shadow representation of {source_name}. "
            "The legacy JSON remains the runtime source of truth."
        ),
        "ins_rules": [],
        "blk_rules": [],
        "additional_configuration": {
            "pipeline_v2_shadow": _shadow_metadata(
                project_config,
                source_config=source_name,
            ),
            "pipeline_v2": pipeline_v2,
        },
    }


def legacy_project_file_to_pipeline_v2_shadow(path: Path | str) -> dict[str, object]:
    """Load ``path`` and return its deterministic PipelineConfig v2 shadow."""
    return legacy_project_config_to_pipeline_v2_shadow(
        ProjectConfiguration.from_file(path)
    )
