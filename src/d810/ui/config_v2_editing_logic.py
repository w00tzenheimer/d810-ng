"""Pure projection and action logic for structured config-v2 editing."""

from __future__ import annotations

import copy
import dataclasses
import json

from d810.manager.config_v2_edit_models import (
    ConfigV2FieldSerializer,
    ConfigV2ProjectDraft,
    ConfigV2ProjectValidation,
)


@dataclasses.dataclass(frozen=True, slots=True)
class ConfigV2SerializerRow:
    field_id: str
    label: str
    value_kind: str
    path: str


@dataclasses.dataclass(frozen=True, slots=True)
class ConfigV2ActionState:
    action_id: str
    enabled: bool
    reason: str


@dataclasses.dataclass(frozen=True, slots=True)
class ConfigV2PipelineRow:
    index: int
    pass_id: str
    rules_json: str
    config_json: str


@dataclasses.dataclass(frozen=True, slots=True)
class ConfigV2DocumentView:
    description: str
    pipeline_rows: tuple[ConfigV2PipelineRow, ...]
    routing_json: str
    complete_document_json: str
    unsupported_document_json: str


def _pretty_json(value: object) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False)


def project_config_v2_document(
    draft: ConfigV2ProjectDraft,
) -> ConfigV2DocumentView:
    document = json.loads(draft.document_json)
    if not isinstance(document, dict):
        raise ValueError("config-v2 project document must be an object")
    additional = document.get("additional_configuration")
    if not isinstance(additional, dict):
        raise ValueError("additional_configuration must be an object")
    pipeline = additional.get("pipeline_v2")
    if not isinstance(pipeline, list):
        raise ValueError("pipeline_v2 must be an ordered list")

    rows: list[ConfigV2PipelineRow] = []
    for index, entry in enumerate(pipeline):
        if not isinstance(entry, dict):
            raise ValueError(f"pipeline_v2[{index}] must be an object")
        pass_id = entry.get("pass_id", entry.get("pass"))
        if not isinstance(pass_id, str) or not pass_id:
            raise ValueError(f"pipeline_v2[{index}] has no stable pass ID")
        rules = entry.get("rules", {})
        if not isinstance(rules, dict):
            raise ValueError(f"pipeline_v2[{index}].rules must be an object")
        rows.append(
            ConfigV2PipelineRow(
                index=index,
                pass_id=pass_id,
                rules_json=_pretty_json(rules),
                config_json=_pretty_json(entry),
            )
        )

    routing = additional.get("router_resolution", {})
    if not isinstance(routing, dict):
        raise ValueError("router_resolution must be an object")

    unsupported = copy.deepcopy(document)
    unsupported.pop("description", None)
    unsupported_additional = unsupported.get("additional_configuration")
    if isinstance(unsupported_additional, dict):
        unsupported_additional.pop("pipeline_v2", None)
        unsupported_additional.pop("router_resolution", None)

    return ConfigV2DocumentView(
        description=str(document.get("description", "")),
        pipeline_rows=tuple(rows),
        routing_json=_pretty_json(routing),
        complete_document_json=_pretty_json(document),
        unsupported_document_json=_pretty_json(unsupported),
    )


def project_serializer_rows(
    serializers: tuple[ConfigV2FieldSerializer, ...],
) -> tuple[ConfigV2SerializerRow, ...]:
    return tuple(
        ConfigV2SerializerRow(
            field_id=item.field.value,
            label=item.label,
            value_kind=item.value_kind,
            path=".".join(item.document_path),
        )
        for item in serializers
    )


def config_v2_action_states(
    draft: ConfigV2ProjectDraft,
    validation: ConfigV2ProjectValidation,
) -> tuple[ConfigV2ActionState, ...]:
    exact = (
        validation.draft_id == draft.draft_id
        and validation.revision == draft.revision
    )
    if not exact:
        reason = "Validate the current draft before saving."
    elif not validation.valid:
        reason = "; ".join(item.message for item in validation.diagnostics)
    else:
        reason = ""
    return (
        ConfigV2ActionState("validate", True, ""),
        ConfigV2ActionState("save_project", exact and validation.valid, reason),
    )


__all__ = [
    "ConfigV2ActionState",
    "ConfigV2DocumentView",
    "ConfigV2PipelineRow",
    "ConfigV2SerializerRow",
    "config_v2_action_states",
    "project_config_v2_document",
    "project_serializer_rows",
]
