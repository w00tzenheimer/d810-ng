"""Fail-closed, IDA-free migration of legacy project configurations.

The runtime only consumes typed ``pipeline_v2`` entries.  This module is the
offline compatibility boundary for old project files: it validates the whole
document, projects only known rule ownership, and refuses to guess whenever a
legacy value has no lossless typed representation.

The historical bundled portfolios are deliberately keyed by both basename and
document fingerprint.  Their old rule arrays contain option combinations that
were normalized intentionally when the current v2 canaries were produced; a
nearby custom document must therefore take the strict generic path instead of
inheriting a bundled projection.
"""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

from d810.passes.mba_transform_options import (
    MBA_TRANSFORM_OPTION_FIELDS,
    mba_transform_stages,
)
from d810.passes.pass_pipeline import PipelineConfig, PipelineConfigError
from d810.passes.state_machine_options import STATE_MACHINE_NATIVE_PASS_IDS


class LegacyMigrationError(ValueError):
    """Raised when a legacy project cannot be migrated without loss."""


@dataclass(frozen=True, slots=True)
class LegacyRule:
    """One validated legacy rule entry with a stable source path."""

    section: str
    index: int
    name: str
    options: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class LegacyProject:
    """Validated legacy project data separated from projection/serialization."""

    source_name: str
    description: str
    active_rules: tuple[LegacyRule, ...]
    additional_configuration: Mapping[str, object]
    canonical_fingerprint: str


@dataclass(frozen=True, slots=True)
class KnownPortfolio:
    """Frozen historical source identity and its current pass sequence."""

    source_name: str
    fingerprint: str
    donor_name: str
    pass_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class LegacyRuleProjection:
    """Table-driven ownership projection for a legacy rule family."""

    rule_name: str
    pass_ids: tuple[str, ...]
    project: Callable[[Mapping[str, object]], tuple[dict[str, object], ...]]


_STATE_MACHINE_PASS_IDS = tuple(str(item) for item in STATE_MACHINE_NATIVE_PASS_IDS)

_NATIVE_SPINE = (
    "recover_dispatcher",
    "recover_state_transitions",
    "plan_semantic_regions",
    "lower_state_machine",
    "cleanup_residual_dispatcher",
)

_JUMP_FIXER_RULE_NAMES = (
    "CompareConstantRule1",
    "CompareConstantRule2",
    "CompareConstantRule3",
    "CompareConstantRule4",
    "JaeRule1",
    "JbRule1",
    "JmpRuleAffineEq",
    "JmpRuleFlagsOpaquePredicate",
    "JmpRuleReachingConst",
    "JmpRuleZ3Const",
    "JnzRule1",
    "JnzRule2",
    "JnzRule3",
    "JnzRule4",
    "JnzRule5",
    "JnzRule6",
    "JnzRule7",
    "JnzRule8",
    "JnzRuleModIdentity",
    "JnzRuleSmodSubIdentity",
    "JnzRuleUmodAddIdentity",
    "JnzRuleUmodSubIdentity",
)
_JUMP_FIXER_RULE_NAME_SET = frozenset(_JUMP_FIXER_RULE_NAMES)

_STATE_RULE_NAME = "StateMachineCffUnflattener"
_JUMP_RULE_NAME = "JumpFixer"
_CONSTANT_RULE_NAMES = frozenset(
    {
        "FoldReadonlyDataRule",
        "ConstantSubtreeFoldRule",
        "ForwardConstantPropagationRule",
    }
)
_CONSTANT_INSTRUCTION_RULE_NAMES = frozenset(
    {"FoldReadonlyDataRule", "ConstantSubtreeFoldRule"}
)

# These are the non-rule project settings consumed by current project/pass
# services.  ``pipeline_v2``, its former mode, and the canary marker are
# handled separately and are never copied to canonical output.
_OWNED_ADDITIONAL_KEYS = frozenset(
    {
        "enable_pass_pipeline",
        "function_analysis_priors",
        "legacy_direct_indirect_materialization",
        "preanalysis_profile_modules",
        "semantic_route_oracle_manifests",
    }
)
_ADDITIONAL_TRANSIENT_KEYS = frozenset(
    {"pipeline_v2", "pipeline_v2_mode", "config_v2_canary"}
)

_RULE_FIELDS = frozenset({"name", "is_activated", "config"})
_MISSING = object()


def _portfolio(
    source_name: str,
    fingerprint: str,
    donor_name: str,
    pass_ids: Sequence[str],
) -> KnownPortfolio:
    return KnownPortfolio(
        source_name=source_name,
        fingerprint=fingerprint,
        donor_name=donor_name,
        pass_ids=tuple(pass_ids),
    )


# Exact historical identities from the approved implementation appendix.
_KNOWN_PORTFOLIOS = (
    _portfolio(
        "default_instruction_only.json",
        "b3f0944b2119e880d2976821953ebf2c50f2646a18a1898ee7ffc0d636c02ab2",
        "default_instruction_only_config_v2_canary.json",
        ("constant-simplification", "mba-simplify", "jump-fixer"),
    ),
    _portfolio(
        "default_unflattening_tigress_engine.json",
        "1d343499a5cb0dec68b2a7efedf3237703dce6fc39b2aae61186feb1a0471db2",
        "default_unflattening_tigress_engine_config_v2_canary.json",
        _NATIVE_SPINE,
    ),
    _portfolio(
        "hodur_flag2.json",
        "2c57256b924f15329eb0166edbfc693f19f56d57a4e317b2c1d03d5458fbc9eb",
        "hodur_flag2_config_v2_canary.json",
        (*_NATIVE_SPINE, "jump-fixer"),
    ),
    _portfolio(
        "hodur_glbopt2_only.json",
        "c6a288756aed1880a54981c5cf596bbb5abddc09e74cefd2c6af60406445c986",
        "hodur_glbopt2_only_config_v2_canary.json",
        _NATIVE_SPINE,
    ),
    _portfolio(
        "eidolon.json",
        "bc241830174e4e5433a0b7d3aaac3f042d56978e9e77c6ed46d000c76cbbcd6c",
        "eidolon_config_v2_canary.json",
        ("mba-simplify",),
    ),
    _portfolio(
        "default_unflattening_approov.json",
        "83f454590e43ae04800cff57670a33e06185cd66ff7daf2141e1f84f62d1c9ac",
        "default_unflattening_approov_config_v2_canary.json",
        (
            "mba-simplify",
            "mba-state-preconditioner",
            *_NATIVE_SPINE,
            "jump-fixer",
        ),
    ),
    _portfolio(
        "default_unflattening_approov_s1a.json",
        "1ca9be3289dd1ef4ec4893434612dbafaed5058bc12b2422ca86218ed51eda05",
        "default_unflattening_approov_s1a_config_v2_canary.json",
        (
            "mba-simplify",
            "mba-state-preconditioner",
            *_NATIVE_SPINE,
            "jump-fixer",
        ),
    ),
    _portfolio(
        "hodur_flag2_s1a.json",
        "11d0f3aa77a291c12715550156585afe577010e865faaf55bdf04b4f2aef2e63",
        "hodur_flag2_s1a_config_v2_canary.json",
        (*_NATIVE_SPINE, "jump-fixer"),
    ),
    _portfolio(
        "hodur_flag2_with_fcp.json",
        "8bbdc05360b7d3f5fe9c345c19a70d8d5269fc0f6d64c5b49bef42ac8e52ae10",
        "hodur_flag2_with_fcp_config_v2_canary.json",
        (
            "mba-simplify",
            *_NATIVE_SPINE,
            "jump-fixer",
            "constant-simplification",
        ),
    ),
    _portfolio(
        "identity_call.json",
        "cd035f21e1ba345d0a6108616344375f1e93866a8cfdee23c6f6770224525339",
        "identity_call_config_v2_canary.json",
        ("identity-call-resolver",),
    ),
    _portfolio(
        "default_unflattening_tigress_engine_transition_facts.json",
        "33a35478e5adcf6b952ec30f30727524a31f721c1d502c89f80165c9b01c4750",
        "default_unflattening_tigress_engine_transition_facts_config_v2_canary.json",
        ("constant-simplification", "mba-simplify", *_NATIVE_SPINE),
    ),
    _portfolio(
        "example_libobfuscated_abc.json",
        "dcf343cfb6ce6f701e5954c64607d8cd8a3512345d1f3057f2be7cf7a006fa5e",
        "example_libobfuscated_abc_config_v2_canary.json",
        (*("constant-simplification", "mba-simplify"), *_NATIVE_SPINE, "jump-fixer"),
    ),
    _portfolio(
        "flatfold.json",
        "fb2f480fcc9088f637a83c9ed5fc9354ed9c40ae61f0fe134ae7f237160d56dd",
        "flatfold_config_v2_canary.json",
        (
            "constant-simplification",
            "mba-simplify",
            "mba-state-preconditioner",
            "jump-fixer",
            *_NATIVE_SPINE,
        ),
    ),
    _portfolio(
        "example_hodur.json",
        "859f94847f7796fb4166b2a7feb70d927a0c54fb50c3f750c7209cddb8c8e6c0",
        "example_hodur_config_v2_canary.json",
        (*("constant-simplification", "mba-simplify"), *_NATIVE_SPINE, "jump-fixer"),
    ),
    _portfolio(
        "default_unflattening_ollvm.json",
        "176a9441b7c866ca37d174c9bf3bcd494521acd94c4ec29c55d115cd951451cb",
        "default_unflattening_ollvm_config_v2_canary.json",
        (
            "constant-simplification",
            "mba-simplify",
            "indirect-call-resolver",
            "mba-state-preconditioner",
            *_NATIVE_SPINE,
            "simple-flattening-cleanup-unflattener",
            "jump-fixer",
        ),
    ),
    _portfolio(
        "default_indirect_resolution.json",
        "3ad2011d8a652b62a1d7c33a4c42f43a9c66f95d8bd4ce42a48f0514baa2a3ee",
        "default_indirect_resolution_config_v2_canary.json",
        ("indirect-branch-resolver", "indirect-call-resolver"),
    ),
    _portfolio(
        "default_unflattening_tigress_indirect.json",
        "2101314f6b7a8213922818e88b4c8aa54d57048aa83dc2c414e6640b74ea9ec9",
        "default_unflattening_tigress_indirect_config_v2_canary.json",
        ("mba-simplify", *_NATIVE_SPINE, "jump-fixer"),
    ),
    _portfolio(
        "default.json",
        "3ad2011d8a652b62a1d7c33a4c42f43a9c66f95d8bd4ce42a48f0514baa2a3ee",
        "default_config_v2_canary.json",
        ("indirect-branch-resolver", "indirect-call-resolver"),
    ),
    _portfolio(
        "example_libobfuscated_no_fixprecedessor.json",
        "9bf4606216bfe471d526b1f12d19cb6da17fdd7a542c51f8283ab350da98c457",
        "example_libobfuscated_no_fixprecedessor_config_v2_canary.json",
        (
            "constant-simplification",
            "mba-simplify",
            "simple-flattening-cleanup-unflattener",
            "jump-fixer",
        ),
    ),
    _portfolio(
        "bogus_loops.json",
        "a1c7a9b5ce95589848c0444413af458e33c599093f722dc89617bbf081a16945",
        "bogus_loops_config_v2_canary.json",
        ("single-trip-loop-peel", "mba-state-preconditioner", "jump-fixer"),
    ),
    _portfolio(
        "example_libobfuscated.json",
        "0e24934ca11872a24d65384967a9830fb567caf2d9b64ae4e15b88ec2d49f546",
        "example_libobfuscated_config_v2_canary.json",
        (
            "constant-simplification",
            "mba-simplify",
            "mba-state-preconditioner",
            *_NATIVE_SPINE,
            "jump-fixer",
        ),
    ),
)
_KNOWN_BY_IDENTITY = {
    (item.source_name, item.fingerprint): item for item in _KNOWN_PORTFOLIOS
}


def _source_basename(source_name: str) -> str:
    """Normalize POSIX and Windows path spellings to a basename."""

    if not isinstance(source_name, str) or not source_name:
        raise LegacyMigrationError("source_name must be a non-empty string")
    return source_name.replace("\\", "/").rsplit("/", 1)[-1]


def _source_path(document: Mapping[str, object]) -> str:
    """Return a stable canonical JSON representation for hashing."""

    try:
        encoded = json.dumps(
            document,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise LegacyMigrationError(
            "document contains a value that is not canonical JSON"
        ) from exc
    return hashlib.sha256(encoded).hexdigest()


def _deep_json_copy(value: object, path: str) -> object:
    """Copy JSON data while rejecting non-JSON values and non-string keys."""

    if value is None or isinstance(value, (str, int, float, bool)):
        if isinstance(value, float) and (value != value or value in (float("inf"), float("-inf"))):
            raise LegacyMigrationError(f"{path} must contain only finite JSON numbers")
        return value
    if isinstance(value, Mapping):
        result: dict[str, object] = {}
        for key, child in value.items():
            if not isinstance(key, str) or not key:
                raise LegacyMigrationError(f"{path} mapping keys must be non-empty strings")
            result[key] = _deep_json_copy(child, f"{path}.{key}")
        return result
    if isinstance(value, (list, tuple)):
        return [_deep_json_copy(child, f"{path}[{index}]") for index, child in enumerate(value)]
    raise LegacyMigrationError(f"{path} must be JSON-compatible")


def _require_mapping(value: object, path: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise LegacyMigrationError(f"{path} must be a mapping")
    return value


def _parse_rules(
    document: Mapping[str, object], section: str
) -> tuple[LegacyRule, ...]:
    raw_rules = document.get(section, [])
    if isinstance(raw_rules, (str, bytes)) or not isinstance(raw_rules, Sequence):
        raise LegacyMigrationError(f"{section} must be a sequence")
    parsed: list[LegacyRule] = []
    for index, raw_rule in enumerate(raw_rules):
        path = f"{section}[{index}]"
        rule = _require_mapping(raw_rule, path)
        unknown = sorted(set(rule).difference(_RULE_FIELDS))
        if unknown:
            raise LegacyMigrationError(f"{path}.{unknown[0]} is not a supported rule field")
        name = rule.get("name", _MISSING)
        if not isinstance(name, str) or not name:
            raise LegacyMigrationError(f"{path}.name must be a non-empty string")
        activated = rule.get("is_activated", _MISSING)
        if not isinstance(activated, bool):
            raise LegacyMigrationError(f"{path}.is_activated must be a boolean")
        options = rule.get("config", _MISSING)
        if not isinstance(options, Mapping):
            raise LegacyMigrationError(f"{path}.config must be a mapping")
        copied = _deep_json_copy(options, f"{path}.config")
        assert isinstance(copied, dict)
        if activated:
            parsed.append(
                LegacyRule(
                    section=section,
                    index=index,
                    name=name,
                    options=copied,
                )
            )
    return tuple(parsed)


def _parse_legacy_document(
    document: Mapping[str, object], *, source_name: str
) -> LegacyProject:
    if not isinstance(document, Mapping):
        raise LegacyMigrationError("document must be a mapping")
    basename = _source_basename(source_name)
    allowed_top = frozenset(
        {"description", "ins_rules", "blk_rules", "additional_configuration"}
    )
    unknown_top = sorted(set(document).difference(allowed_top))
    if unknown_top:
        raise LegacyMigrationError(f"document.{unknown_top[0]} is not a supported field")
    description = document.get("description", "")
    if not isinstance(description, str):
        raise LegacyMigrationError("description must be a string")
    additional = document.get("additional_configuration", {})
    if not isinstance(additional, Mapping):
        raise LegacyMigrationError("additional_configuration must be a mapping")
    copied_additional = _deep_json_copy(additional, "additional_configuration")
    assert isinstance(copied_additional, dict)
    ins_rules = _parse_rules(document, "ins_rules")
    blk_rules = _parse_rules(document, "blk_rules")
    active_rules = (*ins_rules, *blk_rules)
    return LegacyProject(
        source_name=basename,
        description=description,
        active_rules=active_rules,
        additional_configuration=copied_additional,
        canonical_fingerprint=_source_path(document),
    )


def _pipeline_payload(legacy: LegacyProject) -> object:
    return legacy.additional_configuration.get("pipeline_v2", _MISSING)


def _error_for_rule(rule: LegacyRule, message: str, *, field: str | None = None) -> LegacyMigrationError:
    path = f"{rule.section}[{rule.index}]"
    if field:
        path = f"{path}.{field}"
    return LegacyMigrationError(f"{path}: {message}")


def _validate_v2_entries(
    payload: object, *, path_prefix: str
) -> tuple[dict[str, object], ...]:
    if isinstance(payload, (str, bytes)) or not isinstance(payload, Sequence):
        raise LegacyMigrationError(f"{path_prefix} must be a sequence of pass configs")
    if not payload:
        raise LegacyMigrationError(f"{path_prefix} must contain at least one pass config")

    # Importing the operational registry is intentionally lazy.  The module can
    # be imported by offline tooling without importing the entire runtime until
    # a project actually needs typed validation.
    from d810.passes.operational_config_v2 import operational_config_v2_pass_registry

    registry = operational_config_v2_pass_registry()
    entries: list[dict[str, object]] = []
    seen_pass_ids: dict[str, int] = {}
    for index, raw_entry in enumerate(payload):
        path = f"{path_prefix}[{index}]"
        if not isinstance(raw_entry, Mapping):
            raise LegacyMigrationError(f"{path} must be a mapping")
        try:
            config = PipelineConfig.from_dict(raw_entry)
            if config.pass_id in seen_pass_ids:
                previous = seen_pass_ids[config.pass_id]
                raise PipelineConfigError(
                    f"duplicate pass ownership for {config.pass_id!r}; "
                    f"already declared at {path_prefix}[{previous}]"
                )
            registry.build_spec(config)
        except (PipelineConfigError, ValueError, RuntimeError) as exc:
            raise LegacyMigrationError(f"{path}: {exc}") from exc
        seen_pass_ids[config.pass_id] = index
        # Retain the input's complete durable shape when normalizing an already
        # v2 document; typed validation above proves it is safe to keep.
        copied = _deep_json_copy(raw_entry, path)
        assert isinstance(copied, dict)
        entries.append(copied)
    return tuple(entries)


def _normalize_description(description: str, source_name: str) -> str:
    lowered = description.lower()
    if any(token in lowered for token in ("canary", "shadow", "legacy source", "alternate runtime")):
        return f"Canonical config-v2 project for {source_name}"
    if description:
        return description
    return f"Migrated legacy project {source_name} to config-v2"


def _owned_additional(
    additional: Mapping[str, object], *, pipeline: tuple[dict[str, object], ...]
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in additional.items():
        if key in _ADDITIONAL_TRANSIENT_KEYS:
            continue
        if key not in _OWNED_ADDITIONAL_KEYS:
            raise LegacyMigrationError(
                f"additional_configuration.{key} is not owned by a current pass or editor"
            )
        result[key] = _deep_json_copy(value, f"additional_configuration.{key}")
    result["pipeline_v2"] = [copy.deepcopy(item) for item in pipeline]
    return result


def _canonical_document(
    legacy: LegacyProject,
    entries: tuple[dict[str, object], ...],
) -> dict[str, object]:
    additional = _owned_additional(legacy.additional_configuration, pipeline=entries)
    return {
        "description": _normalize_description(legacy.description, legacy.source_name),
        "additional_configuration": additional,
    }


def _find_rule(rules: Sequence[LegacyRule], name: str) -> LegacyRule | None:
    for rule in rules:
        if rule.name == name:
            return rule
    return None


def _find_rules(rules: Sequence[LegacyRule], name: str) -> tuple[LegacyRule, ...]:
    return tuple(rule for rule in rules if rule.name == name)


def _legacy_rule_path(rule: LegacyRule, field: str) -> str:
    return f"{rule.section}[{rule.index}].config.{field}"


def _copy_option_path(
    target: dict[str, object], path: Sequence[str], value: object
) -> None:
    cursor = target
    for segment in path[:-1]:
        child = cursor.setdefault(segment, {})
        if not isinstance(child, dict):
            raise LegacyMigrationError(f"options.{'.'.join(path)} has conflicting ownership")
        cursor = child
    cursor[path[-1]] = copy.deepcopy(value)


def _mba_transform_map() -> dict[str, str]:
    return {stage.implementation_name: stage.stage_id for stage in mba_transform_stages()}


def _project_transform_options(rule: LegacyRule, transform_id: str) -> dict[str, object]:
    fields = MBA_TRANSFORM_OPTION_FIELDS.get(transform_id, ())
    fields_by_name = {field.path[-1]: field for field in fields if field.path}
    projected: dict[str, object] = {}
    for key, value in rule.options.items():
        field = fields_by_name.get(key)
        if field is None:
            raise _error_for_rule(
                rule,
                f"no typed option exists for MBA transform {transform_id!r}",
                field=f"config.{key}",
            )
        _copy_option_path(projected, field.path, value)
    return projected


def _project_mba_rules(
    rules: Sequence[LegacyRule], *, allow_duplicate_transforms: bool = False
) -> dict[str, object] | None:
    transform_map = _mba_transform_map()
    transforms: list[str] = []
    transform_options: dict[str, object] = {}
    owners: dict[str, LegacyRule] = {}
    for rule in rules:
        transform_id = transform_map.get(rule.name)
        if transform_id is None:
            if rule.name in _CONSTANT_RULE_NAMES or rule.name in {
                _STATE_RULE_NAME,
                _JUMP_RULE_NAME,
                "MbaStatePreconditioner",
                "IdentityCallResolver",
                "IndirectBranchResolver",
                "IndirectCallResolver",
                "SimpleFlatteningCleanupUnflattener",
                "SingleTripLoopPeel",
            }:
                continue
            raise _error_for_rule(rule, "unknown instruction rule", field="name")
        if transform_id in owners and not allow_duplicate_transforms:
            raise _error_for_rule(
                rule,
                f"conflicting duplicate ownership with ins_rules[{owners[transform_id].index}]",
                field="name",
            )
        if transform_id in owners:
            # Historical known portfolios intentionally contained duplicate
            # entries.  Their donor semantics retain the first occurrence.
            continue
        owners[transform_id] = rule
        transforms.append(transform_id)
        options = _project_transform_options(rule, transform_id)
        if options:
            transform_options[transform_id] = options
    if not transforms:
        return None
    options: dict[str, object] = {"transforms": transforms}
    options["transform_options"] = transform_options
    return options


def _constant_options(rules: Sequence[LegacyRule]) -> dict[str, object]:
    fold = _find_rule(rules, "FoldReadonlyDataRule")
    subtree = _find_rule(rules, "ConstantSubtreeFoldRule")
    fcp = _find_rule(rules, "ForwardConstantPropagationRule")
    if fold is None or subtree is None or fcp is None:
        owner = fold or subtree or fcp
        if owner is not None:
            missing = sorted(_CONSTANT_RULE_NAMES.difference({item.name for item in rules}))
            raise _error_for_rule(
                owner,
                "constant-simplification requires the complete owner bundle; "
                f"missing {missing}",
                field="name",
            )
        return {}
    allowed_fold = {"fold_writable_constants", "allow_executable_readonly", "rva_guard"}
    for key in fold.options:
        if key not in allowed_fold:
            raise _error_for_rule(fold, "unsupported constant-fold option", field=f"config.{key}")
    for rule in (subtree, fcp):
        if rule.options:
            key = next(iter(rule.options))
            raise _error_for_rule(rule, "constant bundle does not expose this option", field=f"config.{key}")
    fold_writable = fold.options.get("fold_writable_constants", False)
    if not isinstance(fold_writable, bool):
        raise _error_for_rule(fold, "must be a boolean", field="config.fold_writable_constants")
    options: dict[str, object] = {
        "memory_policy": "aggressive_no_direct_writes" if fold_writable else "strict",
        "allow_executable_readonly": fold.options.get("allow_executable_readonly", False),
    }
    if "rva_guard" in fold.options:
        options["rva_guard"] = fold.options["rva_guard"]
    return options


def _state_options(rule: LegacyRule) -> dict[str, object]:
    allowed = {
        "min_state_constant",
        "family",
        "recovery_strategy",
        "native_cfg_persistence",
    }
    for key in rule.options:
        if key not in allowed:
            raise _error_for_rule(rule, "state-machine option has no typed equivalent", field=f"config.{key}")
    result = dict(rule.options)
    if "native_cfg_persistence" in result and not isinstance(result["native_cfg_persistence"], bool):
        raise _error_for_rule(rule, "must be a boolean", field="config.native_cfg_persistence")
    return result


def _jump_options(rule: LegacyRule) -> dict[str, object]:
    allowed = {"enabled_rules"}
    for key in rule.options:
        if key not in allowed:
            raise _error_for_rule(rule, "jump-fixer option has no typed equivalent", field=f"config.{key}")
    if "enabled_rules" not in rule.options:
        return {}
    enabled = rule.options["enabled_rules"]
    if isinstance(enabled, (str, bytes)) or not isinstance(enabled, Sequence):
        raise _error_for_rule(rule, "must be an ordered list of rule names", field="config.enabled_rules")
    values = list(enabled)
    if any(not isinstance(item, str) for item in values):
        raise _error_for_rule(rule, "must contain only rule names", field="config.enabled_rules")
    unknown = [item for item in values if item not in _JUMP_FIXER_RULE_NAME_SET]
    if unknown:
        raise _error_for_rule(rule, f"unknown rule(s): {unknown}", field="config.enabled_rules")
    if len(values) != len(set(values)):
        raise _error_for_rule(rule, "contains duplicate rule names", field="config.enabled_rules")
    return {"enabled_rules": values}


def _direct_options(rule: LegacyRule, pass_id: str) -> dict[str, object]:
    # ``PipelineConfig`` + the operational registry provide the authoritative
    # field/type validation for direct adapters.  The explicit copy keeps the
    # legacy module independent from their implementation classes.
    if pass_id == "jump-fixer":
        return _jump_options(rule)
    if pass_id in _STATE_MACHINE_PASS_IDS:
        return _state_options(rule)
    if pass_id == "constant-simplification":
        return _constant_options((rule,))
    if pass_id in {"forward-constant-propagation", "single-trip-loop-peel", "simple-flattening-cleanup-unflattener"}:
        allowed = {"enable_dead_store_elimination"} if pass_id == "simple-flattening-cleanup-unflattener" else set()
        unknown = sorted(set(rule.options).difference(allowed))
        if unknown:
            raise _error_for_rule(rule, "option has no typed equivalent", field=f"config.{unknown[0]}")
        return dict(rule.options)
    return dict(rule.options)


_BLOCK_RULE_TO_PASS = {
    "ForwardConstantPropagationRule": "forward-constant-propagation",
    "IdentityCallResolver": "identity-call-resolver",
    "IndirectBranchResolver": "indirect-branch-resolver",
    "IndirectCallResolver": "indirect-call-resolver",
    "MbaStatePreconditioner": "mba-state-preconditioner",
    "SingleTripLoopPeel": "single-trip-loop-peel",
    "SimpleFlatteningCleanupUnflattener": "simple-flattening-cleanup-unflattener",
}


def _project_instruction_portfolio(
    rules: Sequence[LegacyRule], *, known: bool = False
) -> list[dict[str, object]]:
    constant_rules = [rule for rule in rules if rule.name in _CONSTANT_RULE_NAMES]
    entries: list[dict[str, object]] = []
    # A known portfolio may intentionally contain a partial historical bundle;
    # its donor/fallback handles that normalization.  Generic documents must
    # prove complete ownership before a public pass is emitted.
    if constant_rules and not known:
        if not _find_rule(rules, "FoldReadonlyDataRule") or not _find_rule(rules, "ConstantSubtreeFoldRule"):
            owner = constant_rules[0]
            raise _error_for_rule(owner, "partial constant-simplification bundle", field="name")
        # FCP is normally in blk_rules; complete cross-section validation is
        # performed by the caller before this helper is used for custom input.
    mba = _project_mba_rules(rules, allow_duplicate_transforms=known)
    if constant_rules:
        # The caller supplies all sections when generic migration is used; this
        # branch is only reached for the complete instruction-only portion.
        pass
    if mba is not None:
        entries.append({"pass_id": "mba-simplify", "options": mba})
    return entries


def _project_block_rules(
    rules: Sequence[LegacyRule], *, known: bool = False, bundled_constant: bool = False
) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    owners: dict[str, LegacyRule] = {}
    for rule in rules:
        name = rule.name
        if name in _CONSTANT_RULE_NAMES:
            if name == "ForwardConstantPropagationRule" and bundled_constant:
                continue
            if name in _CONSTANT_INSTRUCTION_RULE_NAMES:
                raise _error_for_rule(rule, "instruction rule is in blk_rules", field="name")
            continue
        if name == _STATE_RULE_NAME:
            pass_ids = _STATE_MACHINE_PASS_IDS
            options = _state_options(rule) if not known else _state_options(rule)
        elif name == _JUMP_RULE_NAME:
            pass_ids = ("jump-fixer",)
            options = _jump_options(rule) if not known else _jump_options(rule)
        else:
            pass_id = _BLOCK_RULE_TO_PASS.get(name)
            if pass_id is None:
                # Instruction transforms appearing in blk_rules are not a
                # valid current owner, but unknown names must still be named.
                if name in _mba_transform_map():
                    raise _error_for_rule(rule, "instruction rule is in blk_rules", field="name")
                raise _error_for_rule(rule, "unknown block rule", field="name")
            pass_ids = (pass_id,)
            options = _direct_options(rule, pass_id)
        for pass_id in pass_ids:
            if pass_id in owners and not known:
                raise _error_for_rule(rule, "conflicting duplicate ownership", field="name")
            owners[pass_id] = rule
            entries.append({"pass_id": pass_id, "options": copy.deepcopy(options)})
    return entries


def _config_entry(pass_id: str, options: Mapping[str, object]) -> dict[str, object]:
    config = PipelineConfig(pass_id=pass_id, options=dict(options))
    # Typed validation is intentionally performed before serialization.  This
    # catches unknown pass IDs, malformed fields, and editor-invisible values.
    _validate_v2_entries((config.to_dict(),), path_prefix="pipeline_v2")
    return config.to_dict()


def _validate_project_pipeline(entries: Sequence[Mapping[str, object]]) -> tuple[dict[str, object], ...]:
    return _validate_v2_entries(entries, path_prefix="additional_configuration.pipeline_v2")


def _fallback_transform_options(legacy: LegacyProject) -> dict[str, object] | None:
    transforms: list[str] = []
    transform_options: dict[str, object] = {}
    transform_map = _mba_transform_map()
    for rule in legacy.active_rules:
        transform_id = transform_map.get(rule.name)
        if transform_id is None:
            continue
        if transform_id in transforms:
            continue
        transforms.append(transform_id)
        fields = MBA_TRANSFORM_OPTION_FIELDS.get(transform_id, ())
        fields_by_name = {field.path[-1]: field for field in fields if field.path}
        typed: dict[str, object] = {}
        for key, value in rule.options.items():
            field = fields_by_name.get(key)
            if field is None or value is None:
                continue
            _copy_option_path(typed, field.path, value)
        if typed:
            transform_options[transform_id] = typed
    if not transforms:
        return None
    options: dict[str, object] = {"transforms": transforms}
    # Historical canaries serialize this container even when no transform has
    # a typed option (for example the Tigress portfolio).
    options["transform_options"] = transform_options
    return options


def _fallback_constant_options(legacy: LegacyProject) -> dict[str, object]:
    fold = _find_rule(legacy.active_rules, "FoldReadonlyDataRule")
    fold_writable = False
    if fold is not None:
        def has_true(value: object) -> bool:
            if value is True:
                return True
            if isinstance(value, Mapping):
                return any(has_true(child) for child in value.values())
            if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
                return any(has_true(child) for child in value)
            return False

        def find_true_option(value: object) -> bool:
            if isinstance(value, Mapping):
                for key, child in value.items():
                    if key == "fold_writable_constants" and has_true(child):
                        return True
                    if find_true_option(child):
                        return True
            elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
                return any(find_true_option(child) for child in value)
            return False

        fold_writable = find_true_option(fold.options)
    return {
        "memory_policy": "aggressive_no_direct_writes" if fold_writable else "strict",
        "allow_executable_readonly": False,
    }


def _fallback_state_options(legacy: LegacyProject) -> dict[str, object]:
    state = _find_rule(legacy.active_rules, _STATE_RULE_NAME)
    options: dict[str, object] = {"min_state_constant": 16777216}
    if state is None:
        return options
    raw_min = state.options.get("min_state_constant")
    if isinstance(raw_min, int) and not isinstance(raw_min, bool):
        options["min_state_constant"] = raw_min
    profile = state.options.get("profile")
    if profile == "tigress_indirect":
        options["family"] = "tigress-indirect"
    strategy = state.options.get("recovery_engine")
    if strategy == "reduced_product":
        options["recovery_strategy"] = "reduced-product"
    return options


def _fallback_jump_options(legacy: LegacyProject) -> dict[str, object]:
    jump = _find_rule(legacy.active_rules, _JUMP_RULE_NAME)
    options: dict[str, object] = {}
    if jump is not None and isinstance(jump.options.get("enabled_rules"), Sequence):
        options["enabled_rules"] = list(jump.options["enabled_rules"])
    if legacy.source_name == "default_unflattening_ollvm.json" and jump is not None:
        for key in (
            "preserve_z3_discarded_side_effects",
            "preserve_z3_discarded_side_effect_depth",
            "preserve_z3_discarded_side_effect_constants",
        ):
            if key in jump.options:
                options[key] = copy.deepcopy(jump.options[key])
    if legacy.source_name == "bogus_loops.json" and jump is not None:
        options["dump_intermediate_microcode"] = False
    return options


def _fallback_direct_options(legacy: LegacyProject, pass_id: str) -> dict[str, object]:
    names = {
        "identity-call-resolver": "IdentityCallResolver",
        "indirect-branch-resolver": "IndirectBranchResolver",
        "indirect-call-resolver": "IndirectCallResolver",
        "mba-state-preconditioner": "MbaStatePreconditioner",
        "simple-flattening-cleanup-unflattener": "SimpleFlatteningCleanupUnflattener",
    }
    rule_name = names.get(pass_id)
    if rule_name is None:
        return {}
    rule = _find_rule(legacy.active_rules, rule_name)
    if rule is None:
        return {}
    options = dict(rule.options)
    # Legacy cleanup configs only carried an inert dump flag; current cleanup
    # has no equivalent and the historical canary intentionally dropped it.
    if pass_id == "simple-flattening-cleanup-unflattener":
        return {key: value for key, value in options.items() if key == "enable_dead_store_elimination"}
    return options


_HODUR_FLAG2_PRIORS = {
    "sub_7FFD3338C040": {
        "aliases": ["0x180014BE0"],
        "return_frontier_artifacts": {
            "known_impossible_return_constants": ["0xC5FB34A1D9A6E315"],
            "impossible_return_artifact_edges": [
                {
                    "source_block": 27,
                    "artifact_block": 28,
                    "old_target_block": 92,
                    "continuation_block": 29,
                    "proof_ids": [
                        "sub7ffd_return_frontier_artifact",
                        "layout:source27_artifact28_continuation29",
                    ],
                }
            ],
        },
    }
}


def _fallback_known_entries(
    legacy: LegacyProject, portfolio: KnownPortfolio
) -> tuple[dict[str, object], ...]:
    mba = _fallback_transform_options(legacy)
    state_options = _fallback_state_options(legacy)
    direct = {
        "constant-simplification": _fallback_constant_options(legacy),
        "mba-simplify": mba or {},
        "mba-state-preconditioner": _fallback_direct_options(legacy, "mba-state-preconditioner"),
        "jump-fixer": _fallback_jump_options(legacy),
        "identity-call-resolver": _fallback_direct_options(legacy, "identity-call-resolver"),
        "indirect-branch-resolver": _fallback_direct_options(legacy, "indirect-branch-resolver"),
        "indirect-call-resolver": _fallback_direct_options(legacy, "indirect-call-resolver"),
        "simple-flattening-cleanup-unflattener": _fallback_direct_options(legacy, "simple-flattening-cleanup-unflattener"),
        "single-trip-loop-peel": {},
        "forward-constant-propagation": {},
    }
    entries: list[dict[str, object]] = []
    for pass_id in portfolio.pass_ids:
        options = state_options if pass_id in _STATE_MACHINE_PASS_IDS else direct.get(pass_id, {})
        entries.append(_config_entry(pass_id, options))
    return tuple(entries)


def _known_additional_fallback(legacy: LegacyProject) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in legacy.additional_configuration.items():
        if key in _ADDITIONAL_TRANSIENT_KEYS:
            continue
        if key in _OWNED_ADDITIONAL_KEYS:
            result[key] = copy.deepcopy(value)
    if legacy.source_name == "default_unflattening_ollvm.json":
        result.setdefault(
            "semantic_route_oracle_manifests",
            ["semantic_route_oracles/a560_v33_full_flow_routes.json"],
        )
    if legacy.source_name == "hodur_flag2.json":
        result.setdefault("function_analysis_priors", copy.deepcopy(_HODUR_FLAG2_PRIORS))
    return result


def _known_projection(
    legacy: LegacyProject, portfolio: KnownPortfolio
) -> dict[str, object]:
    # The donor name is retained in ``KnownPortfolio`` as historical evidence,
    # but migration does not read donor files at runtime.  The compact typed
    # templates below are what keep the tool usable after Task 5 deletes the
    # canary files.
    entries = _fallback_known_entries(legacy, portfolio)
    additional = _known_additional_fallback(legacy)
    additional["pipeline_v2"] = [copy.deepcopy(entry) for entry in entries]
    return {
        "description": _normalize_description(legacy.description, legacy.source_name),
        "additional_configuration": additional,
    }


def _generic_projection(legacy: LegacyProject) -> dict[str, object]:
    ins_rules = tuple(rule for rule in legacy.active_rules if rule.section == "ins_rules")
    blk_rules = tuple(rule for rule in legacy.active_rules if rule.section == "blk_rules")
    all_names = {rule.name for rule in legacy.active_rules}
    constant_names = all_names.intersection(_CONSTANT_RULE_NAMES)
    complete_bundle = _CONSTANT_RULE_NAMES.issubset(all_names)
    if constant_names and not complete_bundle:
        owner = next(rule for rule in legacy.active_rules if rule.name in _CONSTANT_RULE_NAMES)
        raise _error_for_rule(owner, "partial constant-simplification owner bundle", field="name")

    entries: list[dict[str, object]] = []
    if complete_bundle:
        constant_rules = tuple(rule for rule in legacy.active_rules if rule.name in _CONSTANT_RULE_NAMES)
        entries.append(_config_entry("constant-simplification", _constant_options(constant_rules)))
    instruction_rules = tuple(rule for rule in ins_rules if rule.name not in _CONSTANT_INSTRUCTION_RULE_NAMES)
    mba_options = _project_mba_rules(instruction_rules)
    if mba_options is not None:
        entries.append(_config_entry("mba-simplify", mba_options))
    block_rules = tuple(rule for rule in blk_rules if not (rule.name == "ForwardConstantPropagationRule" and complete_bundle))
    for entry in _project_block_rules(block_rules, bundled_constant=complete_bundle):
        entries.append(_config_entry(str(entry["pass_id"]), entry.get("options", {})))
    if not entries:
        raise LegacyMigrationError("migration produced an empty pipeline_v2")
    return _canonical_document(legacy, _validate_project_pipeline(entries))


def _normalize_v2(legacy: LegacyProject, payload: object) -> dict[str, object]:
    entries = _validate_v2_entries(payload, path_prefix="additional_configuration.pipeline_v2")
    return _canonical_document(legacy, entries)


def migrate_legacy_document(
    document: Mapping[str, object], *, source_name: str
) -> dict[str, object]:
    """Convert one legacy or already-v2 project document to canonical v2.

    The function is deterministic and performs no filesystem writes.  Known
    bundled documents use an exact fingerprinted donor projection; all other
    legacy documents are converted through strict current typed ownership.
    """

    legacy = _parse_legacy_document(document, source_name=source_name)
    payload = _pipeline_payload(legacy)
    active_legacy = legacy.active_rules
    mode = legacy.additional_configuration.get("pipeline_v2_mode", _MISSING)
    if mode is not _MISSING and mode != "config-v2":
        raise LegacyMigrationError(
            "additional_configuration.pipeline_v2_mode must be 'config-v2'"
        )
    if payload is not _MISSING:
        if active_legacy:
            raise LegacyMigrationError("mixed v2 and active legacy configuration")
        return _normalize_v2(legacy, payload)

    portfolio = _KNOWN_BY_IDENTITY.get((legacy.source_name, legacy.canonical_fingerprint))
    if portfolio is not None:
        result = _known_projection(legacy, portfolio)
        _validate_v2_entries(
            result["additional_configuration"]["pipeline_v2"],
            path_prefix="additional_configuration.pipeline_v2",
        )
        return result
    return _generic_projection(legacy)


def is_canonical_v2_document(document: Mapping[str, object]) -> bool:
    """Return whether a document is already normalized canonical config-v2."""

    try:
        legacy = _parse_legacy_document(document, source_name="canonical.json")
        if legacy.active_rules:
            return False
        payload = _pipeline_payload(legacy)
        if payload is _MISSING:
            return False
        additional = legacy.additional_configuration
        if "pipeline_v2_mode" in additional or "config_v2_canary" in additional:
            return False
        _validate_v2_entries(payload, path_prefix="additional_configuration.pipeline_v2")
        _owned_additional(additional, pipeline=())
        return True
    except (LegacyMigrationError, TypeError, ValueError, RuntimeError):
        return False


__all__ = [
    "KnownPortfolio",
    "LegacyMigrationError",
    "LegacyProject",
    "LegacyRule",
    "LegacyRuleProjection",
    "is_canonical_v2_document",
    "migrate_legacy_document",
]
