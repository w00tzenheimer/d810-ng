"""Immutable, IDA-independent Recipe Composer records."""

from __future__ import annotations

import dataclasses

from d810.core.deobfuscation_case import StrategyWorkflowStage
from d810.core.pass_editor_spec import PassEditorSpec
from d810.manager.workbench_models import OutcomeStatus


@dataclasses.dataclass(frozen=True, slots=True)
class PassCatalogEntry:
    pass_id: str
    display_name: str
    contract_json: str
    option_template_json: str
    granularity: str
    maturity: str
    backend_route: str
    safety_policy: str
    transform_ids: tuple[str, ...]
    stage_ids: tuple[str, ...]
    configured: bool
    editor_spec: PassEditorSpec
    workflow_stage: StrategyWorkflowStage = StrategyWorkflowStage.CANONICAL_PIPELINE


@dataclasses.dataclass(frozen=True, slots=True)
class RecipePass:
    item_id: str
    pass_id: str
    enabled: bool
    config_json: str


@dataclasses.dataclass(frozen=True, slots=True)
class PipelineRecipeDraft:
    draft_id: str
    schema_version: int
    revision: int
    function_ea: int
    function_fingerprint: str | None
    workbench_generation: int
    source_path: str
    runtime_path: str
    passes: tuple[RecipePass, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class RecipeDiagnostic:
    code: str
    message: str
    ordinal: int | None
    pass_id: str | None
    namespace: str | None
    missing: tuple[str, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class RecipeValidation:
    draft_id: str
    revision: int
    satisfied: bool
    diagnostics: tuple[RecipeDiagnostic, ...]
    manifest_json: str


@dataclasses.dataclass(frozen=True, slots=True)
class FunctionPipelineOverride:
    schema_version: int
    function_ea: int
    function_fingerprint: str | None
    source_path: str
    runtime_path: str
    pass_configs_json: str
    updated_at: float


@dataclasses.dataclass(frozen=True, slots=True)
class RecipeCommandRequest:
    command: str
    draft_id: str
    draft_revision: int
    function_ea: int
    expected_workbench_generation: int
    function_fingerprint: str | None


@dataclasses.dataclass(frozen=True, slots=True)
class RecipeCommandResult:
    command: str
    draft_id: str
    draft_revision: int
    function_ea: int
    requested_workbench_generation: int
    function_fingerprint: str | None
    status: OutcomeStatus
    succeeded: bool
    accepted: bool
    refresh_requested: bool
    message: str


__all__ = [
    "FunctionPipelineOverride",
    "PassCatalogEntry",
    "PipelineRecipeDraft",
    "RecipeCommandRequest",
    "RecipeCommandResult",
    "RecipeDiagnostic",
    "RecipePass",
    "RecipeValidation",
]
