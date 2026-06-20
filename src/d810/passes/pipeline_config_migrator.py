"""Deterministic legacy ProjectConfiguration to PipelineConfig v2 shadow migration."""
from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from d810.core.config import ConfigConstants, ProjectConfiguration, RuleConfiguration
from d810.passes.pass_pipeline import MaturityRange, PipelineConfigError, PassSpec
from d810.passes.state_machine_spine import standard_state_machine_passes


class LegacyBlockRuleAdapterKind(str, Enum):
    """Config-v2 adapter boundary for a legacy block/flow rule."""

    PIPELINE_V2_SHADOW_PASS = "pipeline_v2_shadow_pass"
    NATIVE_STATE_MACHINE_SPINE = "native_state_machine_spine"
    LEGACY_FLOW_RULE_ADAPTER = "legacy_flow_rule_adapter"
    CLEANUP_FAMILY_ADAPTER = "cleanup_family_adapter"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class LegacyBlockRuleAdapterBoundary:
    """Buildability classification for one legacy block rule name."""

    rule_name: str
    adapter_kind: LegacyBlockRuleAdapterKind
    supported: bool
    pass_id: str | None = None
    reason: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "rule": self.rule_name,
            "adapter_kind": self.adapter_kind.value,
            "supported": self.supported,
            "pass_id": self.pass_id,
            "reason": self.reason,
        }


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

_BLOCK_RULE_PASS_IDS = {
    "BlockLevelEgglogOptimizer": "block-level-egglog-optimizer",
    "GlobalConstantInliner": "global-constant-inliner",
    "ForwardConstantPropagationRule": "forward-constant-propagation",
    "MbaStatePreconditioner": "mba-state-preconditioner",
    "JumpFixer": "jump-fixer",
}
_SUPPORTED_BLOCK_RULE_ADAPTERS = {
    rule_name: LegacyBlockRuleAdapterBoundary(
        rule_name=rule_name,
        adapter_kind=LegacyBlockRuleAdapterKind.PIPELINE_V2_SHADOW_PASS,
        supported=True,
        pass_id=pass_id,
    )
    for rule_name, pass_id in _BLOCK_RULE_PASS_IDS.items()
}
_SUPPORTED_BLOCK_RULE_ADAPTERS["StateMachineCffUnflattener"] = (
    LegacyBlockRuleAdapterBoundary(
        rule_name="StateMachineCffUnflattener",
        adapter_kind=LegacyBlockRuleAdapterKind.NATIVE_STATE_MACHINE_SPINE,
        supported=True,
        reason="expands to the native state-machine spine",
    )
)

# These legacy FlowOptimizationRule implementations are intentionally not
# rendered as config-v2 shadows until their live IDA-backed adapter boundary is
# represented. Inventory reports the concrete gap instead of emitting fake
# pass ids.
_UNSUPPORTED_BLOCK_RULE_ADAPTERS = {
    "IndirectCallResolver": LegacyBlockRuleAdapterBoundary(
        rule_name="IndirectCallResolver",
        adapter_kind=LegacyBlockRuleAdapterKind.LEGACY_FLOW_RULE_ADAPTER,
        supported=False,
        reason="requires an IDA-backed indirect-call FlowOptimizationRule adapter",
    ),
    "SimpleFlatteningCleanupUnflattener": LegacyBlockRuleAdapterBoundary(
        rule_name="SimpleFlatteningCleanupUnflattener",
        adapter_kind=LegacyBlockRuleAdapterKind.CLEANUP_FAMILY_ADAPTER,
        supported=False,
        reason="requires a cleanup-family planner/executor adapter",
    ),
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


class LegacyConfigMigrationStatus(str, Enum):
    """Dry-run classification for a legacy ProjectConfiguration."""

    MIGRATABLE = "migratable"
    EMPTY = "empty"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True)
class LegacyConfigMigrationInventoryItem:
    """One deterministic legacy config-v2 migration dry-run result."""

    config_name: str
    path: Path
    status: LegacyConfigMigrationStatus
    active_instruction_rules: int
    active_block_rules: tuple[str, ...]
    reason: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "config": self.config_name,
            "path": str(self.path),
            "status": self.status.value,
            "active_instruction_rules": self.active_instruction_rules,
            "active_block_rules": list(self.active_block_rules),
            "reason": self.reason,
        }


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


def _active_instruction_rules(
    project_config: ProjectConfiguration,
) -> list[RuleConfiguration]:
    return _active_rules(project_config.ins_rules)


def _active_block_rules(project_config: ProjectConfiguration) -> list[RuleConfiguration]:
    return _active_rules(project_config.blk_rules)


def _active_block_rule_names(
    rules: list[RuleConfiguration],
) -> tuple[str, ...]:
    return tuple(_rule_name(rule, "blk_rules") for rule in rules)


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
) -> tuple[dict[str, object], ...]:
    rule_name = _rule_name(rule, "blk_rules")
    boundary = legacy_block_rule_adapter_boundary(rule_name)
    if not boundary.supported:
        raise PipelineConfigError(_unsupported_block_rule_message(rule_name))
    if rule_name == "StateMachineCffUnflattener":
        return _state_machine_spine_passes(rule, source_config=source_config)

    pass_id = boundary.pass_id
    if pass_id is None:
        raise PipelineConfigError(
            f"legacy block rule has no pipeline_v2 pass id: {rule_name}"
        )

    scope = "block"
    maturity = _BLOCK_MATURITY

    copied_config = _json_copy(rule.config, f"blk_rules.{rule_name}")
    if not isinstance(copied_config, dict):
        raise PipelineConfigError(f"blk_rules.{rule_name} config must be a mapping")

    options = {
        "legacy_rule": rule_name,
        **copied_config,
    }

    return (
        {
            "pass": pass_id,
            "scope": scope,
            "maturity": _json_copy(maturity, "maturity"),
            "migration": {
                "source_config": source_config,
                "source_section": "blk_rules",
                "source_rule": rule_name,
            },
            "options": options,
        },
    )


def _maturity_to_user_shape(maturity: MaturityRange) -> dict[str, object]:
    if maturity.min is None or maturity.max is None:
        raise PipelineConfigError(
            "state-machine native spine maturity must have min and max"
        )
    if maturity.min is maturity.max:
        return {"runs_at": maturity.min.value}
    return {
        "range": {
            "min": maturity.min.value,
            "max": maturity.max.value,
        }
    }


def _pass_contract_payload(spec: PassSpec) -> dict[str, object]:
    contract = spec.contract
    requires = contract.requires.to_dict()
    capability_names = set(requires.get("capabilities", ()))
    capability_names.update(spec.requirements.required)
    requires["capabilities"] = sorted(str(name) for name in capability_names)
    return {
        "scope": contract.scope.value,
        "maturity": _maturity_to_user_shape(contract.maturity),
        "requires": requires,
        "outputs": contract.outputs.to_dict(),
        "preserves": contract.preserves.to_dict(),
        "invalidates": contract.invalidates.to_dict(),
        "safety": contract.safety.to_dict(),
        "analyses": {
            "required": sorted(spec.analyses.required),
            "provided": sorted(spec.analyses.provided),
        },
    }


def _state_machine_spine_passes(
    rule: RuleConfiguration,
    *,
    source_config: str,
) -> tuple[dict[str, object], ...]:
    rule_name = _rule_name(rule, "blk_rules")
    copied_config = _json_copy(rule.config, f"blk_rules.{rule_name}")
    if not isinstance(copied_config, dict):
        raise PipelineConfigError(f"blk_rules.{rule_name} config must be a mapping")

    result: list[dict[str, object]] = []
    spine_specs = standard_state_machine_passes()
    for index, spec in enumerate(spine_specs):
        entry = {
            "pass": spec.pass_id,
            **_pass_contract_payload(spec),
            "migration": {
                "source_config": source_config,
                "source_section": "blk_rules",
                "source_rule": rule_name,
                "expansion": "native_state_machine_spine",
                "stage_index": index,
                "stage_count": len(spine_specs),
            },
            "options": {
                "legacy_rule": rule_name,
                "legacy_rule_options": copied_config,
                "native_pipeline": list(_STATE_MACHINE_NATIVE_PIPELINE),
            },
        }
        result.append(entry)
    return tuple(result)


def legacy_block_rule_adapter_boundary(
    rule_name: str,
) -> LegacyBlockRuleAdapterBoundary:
    """Return the config-v2 adapter boundary for a legacy block rule name."""
    if rule_name in _SUPPORTED_BLOCK_RULE_ADAPTERS:
        return _SUPPORTED_BLOCK_RULE_ADAPTERS[rule_name]
    if rule_name in _UNSUPPORTED_BLOCK_RULE_ADAPTERS:
        return _UNSUPPORTED_BLOCK_RULE_ADAPTERS[rule_name]
    return LegacyBlockRuleAdapterBoundary(
        rule_name=rule_name,
        adapter_kind=LegacyBlockRuleAdapterKind.UNKNOWN,
        supported=False,
        reason="no config-v2 adapter boundary registered",
    )


def _unsupported_block_rule_message(rule_name: str) -> str:
    boundary = legacy_block_rule_adapter_boundary(rule_name)
    if not boundary.reason:
        return f"unsupported legacy block rule for pipeline_v2 shadow: {rule_name}"
    return (
        "unsupported legacy block rule for pipeline_v2 shadow: "
        f"{rule_name} ({boundary.reason})"
    )


def _unsupported_block_rules_message(rule_names: tuple[str, ...]) -> str:
    return (
        "unsupported legacy block rules for pipeline_v2 shadow: "
        + ", ".join(
            _unsupported_block_rule_message(rule_name).removeprefix(
                "unsupported legacy block rule for pipeline_v2 shadow: "
            )
            for rule_name in rule_names
        )
    )


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
    active_instruction_rules = _active_instruction_rules(project_config)
    active_block_rules = _active_block_rules(project_config)
    if not active_instruction_rules and not active_block_rules:
        raise PipelineConfigError(
            f"{source_name} has no active legacy rules; no pipeline_v2 shadow generated"
        )

    pipeline_v2: list[dict[str, object]] = []
    if active_instruction_rules:
        pipeline_v2.append(
            _instruction_pass(project_config.ins_rules, source_config=source_name)
        )
    for rule in active_block_rules:
        pipeline_v2.extend(_block_pass(rule, source_config=source_name))

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


def inventory_legacy_project_config(
    project_config: ProjectConfiguration,
    *,
    source_config: str | None = None,
) -> LegacyConfigMigrationInventoryItem:
    """Classify one legacy project config without writing a shadow file."""
    source_name = source_config or Path(project_config.path).name
    active_instruction_rules = _active_instruction_rules(project_config)
    active_block_rules = _active_block_rules(project_config)
    active_block_rule_names = _active_block_rule_names(active_block_rules)
    if not active_instruction_rules and not active_block_rules:
        return LegacyConfigMigrationInventoryItem(
            config_name=source_name,
            path=Path(project_config.path),
            status=LegacyConfigMigrationStatus.EMPTY,
            active_instruction_rules=0,
            active_block_rules=(),
            reason="no active legacy rules",
        )
    unsupported_block_rules = tuple(
        rule_name
        for rule_name in active_block_rule_names
        if not legacy_block_rule_adapter_boundary(rule_name).supported
    )
    if unsupported_block_rules:
        return LegacyConfigMigrationInventoryItem(
            config_name=source_name,
            path=Path(project_config.path),
            status=LegacyConfigMigrationStatus.UNSUPPORTED,
            active_instruction_rules=len(active_instruction_rules),
            active_block_rules=active_block_rule_names,
            reason=_unsupported_block_rules_message(unsupported_block_rules),
        )
    try:
        legacy_project_config_to_pipeline_v2_shadow(
            project_config,
            source_config=source_name,
        )
    except PipelineConfigError as exc:
        return LegacyConfigMigrationInventoryItem(
            config_name=source_name,
            path=Path(project_config.path),
            status=LegacyConfigMigrationStatus.UNSUPPORTED,
            active_instruction_rules=len(active_instruction_rules),
            active_block_rules=active_block_rule_names,
            reason=str(exc),
        )
    return LegacyConfigMigrationInventoryItem(
        config_name=source_name,
        path=Path(project_config.path),
        status=LegacyConfigMigrationStatus.MIGRATABLE,
        active_instruction_rules=len(active_instruction_rules),
        active_block_rules=active_block_rule_names,
    )


def inventory_legacy_project_file(path: Path | str) -> LegacyConfigMigrationInventoryItem:
    """Load and classify one legacy project config without writing a shadow file."""
    return inventory_legacy_project_config(ProjectConfiguration.from_file(path))


def inventory_legacy_config_directory(
    config_dir: Path | str,
) -> tuple[LegacyConfigMigrationInventoryItem, ...]:
    """Classify legacy project JSON configs under ``config_dir`` deterministically."""
    root = Path(config_dir)
    return tuple(
        inventory_legacy_project_file(path)
        for path in sorted(root.glob("*.json"))
        if path.name != ConfigConstants.OPTIONS_FILENAME
        and not path.name.endswith(".pipeline_v2.json")
    )
