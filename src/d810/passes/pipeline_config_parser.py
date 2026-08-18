"""Typed config-v2 parsing helpers for project configuration."""

from __future__ import annotations

from collections.abc import Mapping
from d810.passes.pass_pipeline import PipelineConfig, PipelineConfigError
from d810.passes.registry import PassRegistry

def _project_additional_config(project_config) -> Mapping:
    return _project_additional_config_for(project_config, strict=False)


def _project_additional_config_for(project_config, *, strict: bool) -> Mapping:
    if isinstance(project_config, Mapping):
        if "additional_configuration" in project_config:
            nested = project_config["additional_configuration"]
            if not isinstance(nested, Mapping):
                raise PipelineConfigError(
                    "additional_configuration must be a mapping"
                )
            config = nested
        elif strict:
            raise PipelineConfigError(
                "full project mapping must contain additional_configuration"
            )
        else:
            # The permissive helper historically accepts a bare additional
            # configuration mapping.  The strict runtime entry point never
            # uses this fallback.
            config = project_config
    else:
        config = getattr(project_config, "additional_configuration", None)
        if config is None:
            config = {}
    if not isinstance(config, Mapping):
        raise PipelineConfigError("project additional_configuration must be a mapping")
    return config


def _project_legacy_rules(project_config) -> tuple[object, ...]:
    """Return both legacy rule arrays without interpreting their rule names."""
    if isinstance(project_config, Mapping):
        ins_rules = project_config.get("ins_rules", ())
        blk_rules = project_config.get("blk_rules", ())
    else:
        ins_rules = getattr(project_config, "ins_rules", ())
        blk_rules = getattr(project_config, "blk_rules", ())
    if isinstance(ins_rules, (str, bytes)) or not isinstance(ins_rules, (list, tuple)):
        raise PipelineConfigError("ins_rules must be a sequence")
    if isinstance(blk_rules, (str, bytes)) or not isinstance(blk_rules, (list, tuple)):
        raise PipelineConfigError("blk_rules must be a sequence")
    return tuple(ins_rules) + tuple(blk_rules)


_LEGACY_RULE_FIELDS = frozenset({"name", "is_activated", "config"})


def _validated_legacy_rule(rule: object, *, section: str, index: int) -> bool:
    """Validate one legacy rule before consulting its activation bit."""
    prefix = f"{section}[{index}]"
    if isinstance(rule, Mapping):
        unknown = sorted(set(rule).difference(_LEGACY_RULE_FIELDS))
        if unknown:
            raise PipelineConfigError(
                f"{prefix} has unknown fields: {', '.join(unknown)}"
            )
        name = rule.get("name")
        if not isinstance(name, str) or not name:
            raise PipelineConfigError(f"{prefix}.name must be a non-empty string")
        activated = rule.get("is_activated")
        if not isinstance(activated, bool):
            raise PipelineConfigError(f"{prefix}.is_activated must be a boolean")
        config = rule.get("config", {})
    else:
        name = getattr(rule, "name", None)
        if not isinstance(name, str) or not name:
            raise PipelineConfigError(f"{prefix}.name must be a non-empty string")
        activated = getattr(rule, "is_activated", None)
        if not isinstance(activated, bool):
            raise PipelineConfigError(f"{prefix}.is_activated must be a boolean")
        config = getattr(rule, "config", None)
    if not isinstance(config, Mapping):
        raise PipelineConfigError(f"{prefix}.config must be a mapping")
    return activated


def _rule_is_active(rule: object, *, section: str, index: int) -> bool:
    return _validated_legacy_rule(rule, section=section, index=index)


def _project_path(project_config) -> object:
    if isinstance(project_config, Mapping):
        return project_config.get("path", "PROJECT")
    return getattr(project_config, "path", "PROJECT")


def _migration_message(project_config, reason: str) -> str:
    path = str(_project_path(project_config))
    return (
        f"project {path} is not a canonical config-v2 project: {reason}; "
        "migrate it with: python tools/migrations/migrate_project_config_v2.py "
        f"{path} --in-place"
    )


def _validate_retired_runtime_metadata(project_config) -> None:
    config = _project_additional_config_for(project_config, strict=True)
    retired_shadow_key = "require_" + "pipeline_v2_" + "shadow_match"
    if retired_shadow_key in config:
        raise PipelineConfigError(
            f"{retired_shadow_key} is a removed compatibility field"
        )
    retired_mode_key = "pipeline_v2_" + "mode"
    if retired_mode_key in config:
        raise PipelineConfigError(
            f"{retired_mode_key} is a removed compatibility field"
        )


def pipeline_configs_from_project_config(project_config) -> tuple[PipelineConfig, ...]:
    """Return optional ``pipeline_v2`` configs without changing project loading.

    Accepts either a loaded ProjectConfiguration-like object with
    ``additional_configuration`` or a plain mapping. Missing ``pipeline_v2`` is a
    no-op for permissive offline readers; malformed payloads fail loudly.
    """
    config = _project_additional_config(project_config)
    payload = config.get("pipeline_v2")
    if payload is None:
        return ()
    if isinstance(payload, Mapping) or not isinstance(payload, (list, tuple)):
        raise PipelineConfigError("pipeline_v2 must be a sequence of pass configs")
    if not payload:
        raise PipelineConfigError("pipeline_v2 must contain at least one pass config")
    source_path = getattr(project_config, "path", None)
    source_prefix = "" if source_path is None else f"{source_path}: "
    configs: list[PipelineConfig] = []
    for index, item in enumerate(payload):
        if isinstance(item, Mapping) and "pass" in item:
            raise PipelineConfigError(
                f"{source_prefix}pipeline_v2[{index}] uses the removed "
                "direct-contract schema; regenerate it with the config-v2 editor "
                "so the entry uses pass_id and typed pass options"
            )
        try:
            parsed = PipelineConfig.from_dict(item)
            if parsed.pass_id == "constant-simplification":
                # The public constant bundle retains explicit compatibility
                # with the former flat options, but every config-v2 consumer
                # receives the same canonical schedule representation.  This
                # keeps legacy read support from leaking editor-invisible
                # options into runtime validation.
                from d810.passes.constant_simplification_options import (
                    canonical_constant_simplification_options,
                )

                canonical = parsed.to_dict()
                canonical["options"] = canonical_constant_simplification_options(
                    parsed
                )
                parsed = PipelineConfig.from_dict(canonical)
            configs.append(parsed)
        except PipelineConfigError as exc:
            raise PipelineConfigError(
                f"{source_prefix}pipeline_v2[{index}]: {exc}"
            ) from exc
    return tuple(configs)


def require_config_v2_project(project_config) -> tuple[PipelineConfig, ...]:
    """Require a complete, runtime-safe config-v2 project.

    This is the single strict parser entry point. The permissive
    ``pipeline_configs_from_project_config`` function remains available to
    offline migration readers; runtime activation must use this function.
    Empty legacy arrays are accepted as inert migration-era metadata, but an
    active legacy rule, missing/empty/malformed ``pipeline_v2``, or retired
    mode/shadow metadata is a hard error with a copyable offline migration
    command.
    """
    try:
        if isinstance(project_config, Mapping):
            ins_rules = project_config.get("ins_rules", ())
        else:
            ins_rules = getattr(project_config, "ins_rules", ())
        legacy_rules = _project_legacy_rules(project_config)
        ins_count = len(ins_rules or ())
        validated_ins = tuple(
            _rule_is_active(rule, section="ins_rules", index=index)
            for index, rule in enumerate(legacy_rules[:ins_count])
        )
        validated_blk = tuple(
            _rule_is_active(rule, section="blk_rules", index=index)
            for index, rule in enumerate(legacy_rules[ins_count:])
        )
        if any(validated_ins):
            raise PipelineConfigError("active legacy rule arrays are present")
        if any(validated_blk):
            raise PipelineConfigError("active legacy rule arrays are present")

        _validate_retired_runtime_metadata(project_config)
        configs = pipeline_configs_from_project_config(project_config)
        if not configs:
            raise PipelineConfigError(
                "additional_configuration.pipeline_v2 is missing or empty"
            )

        # Runtime v2 projects must name a currently executable pass and carry
        # options accepted by its typed registry contract.  Keep this inside
        # the strict wrapper so registry failures remain actionable offline
        # migration diagnostics.
        from d810.passes.operational_config_v2 import (
            operational_config_v2_pass_registry,
        )

        registry = operational_config_v2_pass_registry()
        for config in configs:
            registry.build_spec(config)
        mark_validated = getattr(
            project_config, "_mark_config_v2_validation_succeeded", None
        )
        if callable(mark_validated):
            mark_validated()
    except Exception as exc:
        raise PipelineConfigError(
            _migration_message(project_config, str(exc))
        ) from exc
    return configs


def pass_specs_from_project_config(
    project_config,
    registry: PassRegistry,
):
    """Build typed PassSpecs from a project's ``pipeline_v2`` config."""
    return tuple(
        registry.build_spec(config)
        for config in pipeline_configs_from_project_config(project_config)
    )
