"""Pure projection and action logic for structured config-v2 editing."""

from __future__ import annotations

import dataclasses

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
    "ConfigV2SerializerRow",
    "config_v2_action_states",
    "project_serializer_rows",
]
