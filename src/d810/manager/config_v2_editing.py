"""Lossless, structured config-v2 project editing without Qt or IDA."""

from __future__ import annotations

import copy
import dataclasses
import hashlib
import json
import math
import pathlib
import uuid
from collections.abc import Mapping, Sequence

from d810.core.config import ProjectConfiguration
from d810.core.project_config_persistence import (
    ProjectConfigurationWriteError,
    write_project_document_atomically,
)
from d810.families.registry import registered_families
from d810.manager.config_v2_edit_models import (
    ConfigV2EditDiagnostic,
    ConfigV2EditableField,
    ConfigV2FieldSerializer,
    ConfigV2ProjectDraft,
    ConfigV2ProjectValidation,
)
from d810.manager.workbench_recipe_models import PipelineRecipeDraft
from d810.passes.operational_config_v2 import operational_config_v2_pass_registry
from d810.passes.pass_pipeline import PipelineConfig, PipelineConfigError
from d810.passes.pipeline_config_parser import pipeline_configs_from_project_config
from d810.passes.pipeline_v2_hook_bridge import pipeline_v2_hook_activation
from d810.passes.registry import PassRegistry, PassRegistryError, UnknownPassIdError


class ConfigV2EditError(RuntimeError):
    """A structured config-v2 edit or save is unsafe."""


_SERIALIZERS = (
    ConfigV2FieldSerializer(
        ConfigV2EditableField.DESCRIPTION,
        "Description",
        "string",
        ("description",),
    ),
    ConfigV2FieldSerializer(
        ConfigV2EditableField.PIPELINE_SELECTION,
        "Ordered registered passes",
        "pipeline",
        ("additional_configuration", "pipeline_v2"),
    ),
    ConfigV2FieldSerializer(
        ConfigV2EditableField.PASS_RULES,
        "Pass rule selection",
        "rule-selection",
        ("additional_configuration", "pipeline_v2", "*", "rules"),
    ),
    ConfigV2FieldSerializer(
        ConfigV2EditableField.ROUTER_RESOLUTION,
        "Profile routing override",
        "router-resolution",
        ("additional_configuration", "router_resolution"),
    ),
)


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _document(value: str) -> dict[str, object]:
    parsed = json.loads(value)
    if not isinstance(parsed, dict):
        raise ConfigV2EditError("project document must be an object")
    return parsed


def _file_sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _additional(document: dict[str, object]) -> dict[str, object]:
    value = document.get("additional_configuration")
    if not isinstance(value, dict):
        raise ConfigV2EditError("additional_configuration must be an object")
    return value


def _pipeline(document: dict[str, object]) -> list[dict[str, object]]:
    value = _additional(document).get("pipeline_v2")
    if not isinstance(value, list):
        raise ConfigV2EditError("pipeline_v2 must be an ordered list")
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise ConfigV2EditError(f"pipeline_v2[{index}] must be an object")
    return value


def _pass_id(entry: Mapping[str, object]) -> str:
    value = entry.get("pass_id", entry.get("pass"))
    if not isinstance(value, str) or not value:
        raise ConfigV2EditError("pipeline entry pass ID must be a non-empty string")
    return value


def _unsupported_projection(document: dict[str, object]) -> object:
    projected = copy.deepcopy(document)
    projected.pop("description", None)
    additional = projected.get("additional_configuration")
    if isinstance(additional, dict):
        additional.pop("pipeline_v2", None)
        additional.pop("router_resolution", None)
    return projected


class ConfigV2EditingService:
    """Own complete-document structured edits and full pre-commit validation."""

    def __init__(self, registry: PassRegistry | None = None) -> None:
        self._registry = registry or operational_config_v2_pass_registry()

    @staticmethod
    def serializer_manifest() -> tuple[ConfigV2FieldSerializer, ...]:
        return _SERIALIZERS

    def create_draft(
        self,
        runtime_project: ProjectConfiguration,
        *,
        destination: pathlib.Path,
    ) -> ConfigV2ProjectDraft:
        source = pathlib.Path(runtime_project.path).resolve()
        try:
            raw = source.read_bytes()
            document = json.loads(raw.decode("utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise ConfigV2EditError(f"cannot read complete runtime project: {error}") from error
        if not isinstance(document, dict):
            raise ConfigV2EditError("runtime project document must be an object")
        canonical = _canonical_json(document)
        draft = ConfigV2ProjectDraft(
            draft_id=str(uuid.uuid4()),
            revision=0,
            source_path=source,
            destination_path=pathlib.Path(destination).expanduser().resolve(),
            source_sha256=hashlib.sha256(raw).hexdigest(),
            original_document_json=canonical,
            document_json=canonical,
        )
        validation = self.validate(draft)
        if not validation.valid:
            raise ConfigV2EditError(
                "runtime project is not a valid editable config-v2 document: "
                + "; ".join(item.message for item in validation.diagnostics)
            )
        return draft

    @staticmethod
    def _updated(
        draft: ConfigV2ProjectDraft, document: dict[str, object]
    ) -> ConfigV2ProjectDraft:
        return dataclasses.replace(
            draft,
            revision=draft.revision + 1,
            document_json=_canonical_json(document),
        )

    def set_field(
        self, draft: ConfigV2ProjectDraft, field: str, value: object
    ) -> ConfigV2ProjectDraft:
        try:
            editable = ConfigV2EditableField(field)
        except ValueError as error:
            raise ConfigV2EditError(
                f"field {field!r} has no declared structured serializer"
            ) from error
        if editable is ConfigV2EditableField.DESCRIPTION:
            if not isinstance(value, str):
                raise ConfigV2EditError("description serializer requires a string")
            return self.set_description(draft, value)
        raise ConfigV2EditError(
            f"field {field!r} requires its typed structured serializer"
        )

    def set_description(
        self, draft: ConfigV2ProjectDraft, description: str
    ) -> ConfigV2ProjectDraft:
        if not isinstance(description, str):
            raise ConfigV2EditError("description must be a string")
        document = _document(draft.document_json)
        document["description"] = description
        return self._updated(draft, document)

    def pipeline_pass_ids(
        self, draft: ConfigV2ProjectDraft
    ) -> tuple[str, ...]:
        return tuple(_pass_id(entry) for entry in _pipeline(_document(draft.document_json)))

    def add_pass(
        self,
        draft: ConfigV2ProjectDraft,
        pass_id: str,
        *,
        index: int | None = None,
    ) -> ConfigV2ProjectDraft:
        try:
            template = self._registry.config_template_for(pass_id)
            self._registry.build_spec(template)
        except (UnknownPassIdError, PassRegistryError, PipelineConfigError) as error:
            raise ConfigV2EditError(str(error)) from error
        document = _document(draft.document_json)
        pipeline = _pipeline(document)
        insertion = len(pipeline) if index is None else int(index)
        if not 0 <= insertion <= len(pipeline):
            raise ConfigV2EditError("pass insertion index is out of range")
        pipeline.insert(insertion, template.to_dict())
        return self._updated(draft, document)

    def remove_pass(
        self, draft: ConfigV2ProjectDraft, pass_index: int
    ) -> ConfigV2ProjectDraft:
        document = _document(draft.document_json)
        pipeline = _pipeline(document)
        if not 0 <= pass_index < len(pipeline):
            raise ConfigV2EditError("pass index is out of range")
        pipeline.pop(pass_index)
        return self._updated(draft, document)

    def reorder_pass(
        self,
        draft: ConfigV2ProjectDraft,
        pass_index: int,
        new_index: int,
    ) -> ConfigV2ProjectDraft:
        document = _document(draft.document_json)
        pipeline = _pipeline(document)
        if not 0 <= pass_index < len(pipeline) or not 0 <= new_index < len(pipeline):
            raise ConfigV2EditError("pass reorder index is out of range")
        entry = pipeline.pop(pass_index)
        pipeline.insert(new_index, entry)
        return self._updated(draft, document)

    def set_pass_rules(
        self,
        draft: ConfigV2ProjectDraft,
        *,
        pass_index: int,
        include: Sequence[str],
        exclude: Sequence[str],
        options: Mapping[str, object],
    ) -> ConfigV2ProjectDraft:
        document = _document(draft.document_json)
        pipeline = _pipeline(document)
        if not 0 <= pass_index < len(pipeline):
            raise ConfigV2EditError("pass index is out of range")
        entry = pipeline[pass_index]
        rules = entry.get("rules", {})
        if not isinstance(rules, dict):
            raise ConfigV2EditError("pass rules must be an object")
        rules["include"] = [str(value) for value in include]
        rules["exclude"] = [str(value) for value in exclude]
        rules["options"] = copy.deepcopy(dict(options))
        entry["rules"] = rules
        try:
            config = PipelineConfig.from_dict(entry)
            self._registry.build_spec(config)
        except (PipelineConfigError, PassRegistryError, TypeError, ValueError) as error:
            raise ConfigV2EditError(f"invalid pass rule selection: {error}") from error
        return self._updated(draft, document)

    @staticmethod
    def _routing_policy(
        *,
        prefer: Mapping[str, float],
        require: str | None,
        deny: Sequence[str],
    ) -> dict[str, object]:
        known = {str(family.name) for family in registered_families()}
        deny_values = tuple(dict.fromkeys(str(value) for value in deny))
        prefer_values = dict(prefer)
        referenced = set(deny_values).union(prefer_values)
        if require is not None:
            referenced.add(str(require))
        unknown = sorted(referenced.difference(known))
        if unknown:
            raise ConfigV2EditError("unknown family name(s): " + ", ".join(unknown))
        for name, bias in prefer_values.items():
            if isinstance(bias, bool) or not isinstance(bias, (int, float)):
                raise ConfigV2EditError(f"prefer bias for {name} must be numeric")
            if not math.isfinite(float(bias)):
                raise ConfigV2EditError(f"prefer bias for {name} must be finite")
        denied = set(deny_values)
        if require is not None and require in denied:
            raise ConfigV2EditError("required family cannot also be denied")
        if denied.intersection(prefer_values):
            raise ConfigV2EditError("preferred family cannot also be denied")
        if require is not None and set(prefer_values).difference({require}):
            raise ConfigV2EditError(
                "prefer may name only the required family when require is set"
            )
        return {
            "prefer": {
                name: float(prefer_values[name]) for name in sorted(prefer_values)
            },
            "require": require,
            "deny": list(deny_values),
        }

    def set_routing_override(
        self,
        draft: ConfigV2ProjectDraft,
        *,
        prefer: Mapping[str, float],
        require: str | None,
        deny: Sequence[str],
    ) -> ConfigV2ProjectDraft:
        policy = self._routing_policy(prefer=prefer, require=require, deny=deny)
        document = _document(draft.document_json)
        _additional(document)["router_resolution"] = policy
        return self._updated(draft, document)

    def materialize_recipe(
        self,
        draft: ConfigV2ProjectDraft,
        recipe: PipelineRecipeDraft,
    ) -> ConfigV2ProjectDraft:
        document = _document(draft.document_json)
        raw_pipeline = _pipeline(document)
        available: dict[str, list[dict[str, object]]] = {}
        for entry in raw_pipeline:
            available.setdefault(_pass_id(entry), []).append(entry)
        materialized: list[dict[str, object]] = []
        for item in recipe.passes:
            if not item.enabled:
                continue
            try:
                payload = json.loads(item.config_json)
                if not isinstance(payload, dict):
                    raise PipelineConfigError("recipe pass config must be an object")
                config = PipelineConfig.from_dict(payload)
                if config.pass_id != item.pass_id:
                    raise PipelineConfigError("recipe pass identity mismatch")
                self._registry.build_spec(config)
            except (
                json.JSONDecodeError,
                PipelineConfigError,
                PassRegistryError,
                TypeError,
                ValueError,
            ) as error:
                raise ConfigV2EditError(f"invalid recipe pass {item.pass_id}: {error}") from error
            candidates = available.get(item.pass_id, [])
            if candidates:
                entry = copy.deepcopy(candidates.pop(0))
                canonical = config.to_dict()
                entry["options"] = copy.deepcopy(canonical["options"])
                entry["rules"] = copy.deepcopy(canonical["rules"])
            else:
                entry = config.to_dict()
            materialized.append(entry)
        _additional(document)["pipeline_v2"] = materialized
        return self._updated(draft, document)

    def _validate_semantics(
        self, document: dict[str, object], path: pathlib.Path
    ) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...], str]:
        additional = _additional(document)
        if additional.get("pipeline_v2_mode") != "config-v2":
            raise ConfigV2EditError(
                "pipeline_v2_mode must remain 'config-v2'; flat rule downgrade is refused"
            )
        configs = pipeline_configs_from_project_config(additional)
        for config in configs:
            self._registry.build_spec(config)
        project = ProjectConfiguration(
            path=path,
            description=str(document.get("description", "")),
            additional_configuration=copy.deepcopy(additional),
        )
        activation = pipeline_v2_hook_activation(project)
        if not activation.enabled:
            raise ConfigV2EditError("config-v2 live hook activation is not enabled")
        policy = additional.get("router_resolution", {})
        if policy:
            if not isinstance(policy, dict):
                raise ConfigV2EditError("router_resolution must be an object")
            unknown_keys = set(policy).difference({"prefer", "require", "deny"})
            if unknown_keys:
                raise ConfigV2EditError(
                    "router_resolution has unsupported fields: "
                    + ", ".join(sorted(unknown_keys))
                )
            canonical_policy = self._routing_policy(
                prefer=policy.get("prefer", {}) or {},
                require=policy.get("require"),
                deny=policy.get("deny", ()) or (),
            )
        else:
            canonical_policy = {}
        return (
            tuple(config.pass_id for config in configs),
            tuple(str(rule.name) for rule in activation.instruction_rules),
            tuple(str(rule.name) for rule in activation.block_rules),
            _canonical_json(canonical_policy),
        )

    def validate(self, draft: ConfigV2ProjectDraft) -> ConfigV2ProjectValidation:
        diagnostics: list[ConfigV2EditDiagnostic] = []
        pass_ids: tuple[str, ...] = ()
        instruction_rules: tuple[str, ...] = ()
        block_rules: tuple[str, ...] = ()
        routing = "{}"
        try:
            document = _document(draft.document_json)
            original = _document(draft.original_document_json)
        except (ConfigV2EditError, json.JSONDecodeError) as error:
            diagnostics.append(ConfigV2EditDiagnostic("invalid-document", str(error), None))
            document = {}
            original = {}
        if document and original:
            if _unsupported_projection(document) != _unsupported_projection(original):
                diagnostics.append(
                    ConfigV2EditDiagnostic(
                        "unsupported-field-change",
                        "document fields outside declared serializers changed",
                        None,
                    )
                )
            try:
                if _file_sha256(draft.source_path) != draft.source_sha256:
                    diagnostics.append(
                        ConfigV2EditDiagnostic(
                            "source-drift",
                            "source runtime document changed after the draft was created",
                            str(draft.source_path),
                        )
                    )
            except OSError as error:
                diagnostics.append(
                    ConfigV2EditDiagnostic("source-drift", str(error), str(draft.source_path))
                )
            try:
                pass_ids, instruction_rules, block_rules, routing = self._validate_semantics(
                    document, draft.destination_path
                )
            except (
                ConfigV2EditError,
                PipelineConfigError,
                PassRegistryError,
                TypeError,
                ValueError,
            ) as error:
                diagnostics.append(
                    ConfigV2EditDiagnostic("invalid-pipeline", str(error), "pipeline_v2")
                )
        return ConfigV2ProjectValidation(
            draft_id=draft.draft_id,
            revision=draft.revision,
            valid=not diagnostics,
            pass_ids=pass_ids,
            instruction_rule_names=instruction_rules,
            block_rule_names=block_rules,
            routing_policy_json=routing,
            diagnostics=tuple(diagnostics),
        )

    def save(
        self,
        draft: ConfigV2ProjectDraft,
        validation: ConfigV2ProjectValidation,
    ) -> ProjectConfiguration:
        if (
            validation.draft_id != draft.draft_id
            or validation.revision != draft.revision
        ):
            raise ConfigV2EditError("stale config-v2 validation identity")
        current = self.validate(draft)
        if not validation.valid or current != validation:
            raise ConfigV2EditError(
                "stale or invalid config-v2 validation; validate the current draft"
            )
        document = _document(draft.document_json)

        def validate_reload(project: ProjectConfiguration) -> None:
            reloaded_document = json.loads(project.path.read_text(encoding="utf-8"))
            if not isinstance(reloaded_document, dict):
                raise ConfigV2EditError("reloaded project document is not an object")
            self._validate_semantics(reloaded_document, project.path)

        try:
            return write_project_document_atomically(
                draft.destination_path,
                document,
                validator=validate_reload,
            )
        except ProjectConfigurationWriteError as error:
            raise ConfigV2EditError(str(error)) from error


__all__ = [
    "ConfigV2EditDiagnostic",
    "ConfigV2EditError",
    "ConfigV2EditableField",
    "ConfigV2EditingService",
    "ConfigV2FieldSerializer",
    "ConfigV2ProjectDraft",
    "ConfigV2ProjectValidation",
]
