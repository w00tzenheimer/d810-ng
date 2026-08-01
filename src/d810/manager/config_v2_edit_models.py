"""Immutable records for lossless structured config-v2 project editing."""

from __future__ import annotations

import dataclasses
import enum
import pathlib


class ConfigV2EditableField(str, enum.Enum):
    DESCRIPTION = "description"
    PIPELINE_SELECTION = "pipeline_selection"
    PASS_RULES = "pass_rules"
    ROUTER_RESOLUTION = "router_resolution"


@dataclasses.dataclass(frozen=True, slots=True)
class ConfigV2FieldSerializer:
    field: ConfigV2EditableField
    label: str
    value_kind: str
    document_path: tuple[str, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class ConfigV2ProjectDraft:
    draft_id: str
    revision: int
    source_path: pathlib.Path
    destination_path: pathlib.Path
    source_sha256: str
    original_document_json: str
    document_json: str


@dataclasses.dataclass(frozen=True, slots=True)
class ConfigV2EditDiagnostic:
    code: str
    message: str
    path: str | None


@dataclasses.dataclass(frozen=True, slots=True)
class ConfigV2ProjectValidation:
    draft_id: str
    revision: int
    valid: bool
    pass_ids: tuple[str, ...]
    instruction_rule_names: tuple[str, ...]
    block_rule_names: tuple[str, ...]
    routing_policy_json: str
    diagnostics: tuple[ConfigV2EditDiagnostic, ...]


__all__ = [
    "ConfigV2EditDiagnostic",
    "ConfigV2EditableField",
    "ConfigV2FieldSerializer",
    "ConfigV2ProjectDraft",
    "ConfigV2ProjectValidation",
]
