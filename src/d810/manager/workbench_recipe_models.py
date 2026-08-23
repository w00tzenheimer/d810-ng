"""Immutable, IDA-independent Recipe Composer records."""

from __future__ import annotations

import dataclasses
import enum

from d810.core.deobfuscation_case import StrategyWorkflowStage
from d810.core.pass_editor_spec import PassEditorSpec
from d810.manager.workbench_models import OutcomeStatus


DEFAULT_PASS_PURPOSE = "Registered config-v2 pass."


class PassImplementationStatus(str, enum.Enum):
    """Operator-facing state of one pass's external implementation."""

    READY = "ready"
    NOT_INSTALLED = "not_installed"
    INSTALLED_NOT_LOADED = "installed_not_loaded"
    UNAVAILABLE = "unavailable"
    INCOMPATIBLE = "incompatible"
    BROKEN = "broken"
    AMBIGUOUS = "ambiguous"
    UNKNOWN = "unknown"


@dataclasses.dataclass(frozen=True, slots=True)
class PassImplementationAvailability:
    """Pure provider status rendered consistently by every UI surface."""

    distribution: str
    status: PassImplementationStatus
    status_label: str
    detail: str
    activation_required: bool
    backend_names: tuple[str, ...] = ()

    @property
    def catalog_label(self) -> str:
        return f"{self.distribution} - {self.status_label}"


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
    purpose: str = DEFAULT_PASS_PURPOSE
    implementation: PassImplementationAvailability | None = None


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
    project_path: str
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
    project_path: str
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
    "DEFAULT_PASS_PURPOSE",
    "PassCatalogEntry",
    "PassImplementationAvailability",
    "PassImplementationStatus",
    "PipelineRecipeDraft",
    "RecipeCommandRequest",
    "RecipeCommandResult",
    "RecipeDiagnostic",
    "RecipePass",
    "RecipeValidation",
]
