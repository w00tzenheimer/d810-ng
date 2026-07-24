"""Immutable, IDA-independent data returned by the deobfuscation workbench."""

from __future__ import annotations

import dataclasses
import enum

from d810.core.deobfuscation_case import DeobfuscationCaseSnapshot

class OutcomeStatus(str, enum.Enum):
    """Approved status labels shared by passes and supporting consumers."""

    NOT_RUN = "Not run"
    READY = "Ready"
    NOT_ELIGIBLE = "Not eligible"
    NO_MATCH = "No match"
    CHANGED = "Changed"
    UNCHANGED = "Unchanged"
    ABSTAINED = "Abstained"
    BLOCKED = "Blocked"
    FAILED = "Failed"
    STALE = "Stale"


class SnapshotFreshness(str, enum.Enum):
    """Whether a snapshot still describes the selected function generation."""

    CURRENT = "current"
    STALE = "stale"
    UNAVAILABLE = "unavailable"


class ArtifactFreshness(str, enum.Enum):
    CURRENT = "current"
    STALE = "stale"
    MISSING = "missing"


@dataclasses.dataclass(frozen=True, slots=True)
class FunctionRef:
    ea: int
    name: str
    fingerprint: str | None
    generation: int


@dataclasses.dataclass(frozen=True, slots=True)
class RuntimeConfigRef:
    source_name: str
    source_path: str
    runtime_name: str
    runtime_path: str
    mode: str
    routed: bool
    hook_mode: str | None
    pass_ids: tuple[str, ...]
    recipe_scope: str = "project"


@dataclasses.dataclass(frozen=True, slots=True)
class AttackSummary:
    observed_shape: str
    mechanism: str
    selected_profile: str | None
    selection_mode: str
    confidence: float | None
    recommended_inferences: tuple[str, ...]
    suppressed_rules: tuple[str, ...]
    candidate_kinds: tuple[str, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class WorkbenchDiagnostic:
    code: str
    message: str
    pass_id: str | None
    namespace: str | None
    missing: tuple[str, ...]
    available: tuple[str, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class PipelineStageSnapshot:
    ordinal: int
    pass_id: str
    phase: str
    scope: str
    maturity: str
    status: OutcomeStatus
    summary: str
    contract_json: str
    diagnostics: tuple[WorkbenchDiagnostic, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class ConsumerOutcomeSnapshot:
    phase: str
    consumer_name: str
    status: OutcomeStatus
    detail: str
    provenance_json: str | None


@dataclasses.dataclass(frozen=True, slots=True)
class RuleScopeSummary:
    project_instruction_rules: tuple[str, ...]
    project_block_rules: tuple[str, ...]
    function_enabled_rules: tuple[str, ...]
    function_disabled_rules: tuple[str, ...]
    function_tags: tuple[str, ...]
    function_notes: str
    inference_name: str | None
    inference_enabled_rules: tuple[str, ...]
    inference_disabled_rules: tuple[str, ...]
    inference_applies: bool


@dataclasses.dataclass(frozen=True, slots=True)
class CountEntry:
    name: str
    count: int


@dataclasses.dataclass(frozen=True, slots=True)
class PatchCountEntry:
    name: str
    uses: int
    total_patches: int


@dataclasses.dataclass(frozen=True, slots=True)
class StatisticsSummary:
    optimizer_matches: tuple[CountEntry, ...]
    rule_matches: tuple[CountEntry, ...]
    cfg_patches: tuple[PatchCountEntry, ...]
    total_rule_firings: int
    cycles_detected: tuple[CountEntry, ...]
    total_cycles_detected: int


@dataclasses.dataclass(frozen=True, slots=True)
class ArtifactRef:
    kind: str
    label: str
    path: str | None
    available: bool


@dataclasses.dataclass(frozen=True, slots=True)
class BaselineRef:
    available: bool
    fingerprint: str | None
    path: str | None
    generation: int | None
    function_ea: int | None = None
    idb_identity: str | None = None
    type_generation: str | None = None
    hexrays_version: str | None = None
    captured_at: float | None = None
    pseudocode: str | None = None
    line_count: int = 0
    character_count: int = 0
    content_sha256: str | None = None


@dataclasses.dataclass(frozen=True, slots=True)
class D810OutputRef:
    available: bool
    fingerprint: str | None
    path: str | None
    generation: int | None
    function_ea: int | None = None
    idb_identity: str | None = None
    type_generation: str | None = None
    hexrays_version: str | None = None
    captured_at: float | None = None
    pseudocode: str | None = None
    line_count: int = 0
    character_count: int = 0
    content_sha256: str | None = None
    runtime_path: str | None = None
    runtime_pass_ids: tuple[str, ...] = ()
    runtime_generation: int | None = None


@dataclasses.dataclass(frozen=True, slots=True)
class ComparisonMetric:
    name: str
    native_value: int
    d810_value: int
    delta: int


@dataclasses.dataclass(frozen=True, slots=True)
class WorkbenchComparisonSnapshot:
    function_ea: int
    baseline: BaselineRef
    d810_output: D810OutputRef
    baseline_freshness: ArtifactFreshness
    d810_freshness: ArtifactFreshness
    baseline_stale_reasons: tuple[str, ...]
    d810_stale_reasons: tuple[str, ...]
    text_changed: bool | None
    metrics: tuple[ComparisonMetric, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class DeobfuscationWorkbenchSnapshot:
    generation: int
    function: FunctionRef
    runtime: RuntimeConfigRef
    attack: AttackSummary
    pipeline: tuple[PipelineStageSnapshot, ...]
    consumers: tuple[ConsumerOutcomeSnapshot, ...]
    rule_scope: RuleScopeSummary
    statistics: StatisticsSummary
    baseline: BaselineRef
    latest_output: D810OutputRef
    artifacts: tuple[ArtifactRef, ...]
    freshness: SnapshotFreshness
    engine_started: bool
    collection_errors: tuple[str, ...]
    case: DeobfuscationCaseSnapshot | None = None


@dataclasses.dataclass(frozen=True, slots=True)
class WorkbenchCommandRequest:
    command: str
    function_ea: int
    expected_generation: int
    function_fingerprint: str | None


@dataclasses.dataclass(frozen=True, slots=True)
class WorkbenchCommandResult:
    command: str
    function_ea: int
    requested_generation: int
    function_fingerprint: str | None
    status: OutcomeStatus
    succeeded: bool
    accepted: bool
    refresh_requested: bool
    message: str


__all__ = [
    "ArtifactRef",
    "ArtifactFreshness",
    "AttackSummary",
    "BaselineRef",
    "ConsumerOutcomeSnapshot",
    "ComparisonMetric",
    "CountEntry",
    "D810OutputRef",
    "DeobfuscationWorkbenchSnapshot",
    "FunctionRef",
    "OutcomeStatus",
    "PatchCountEntry",
    "PipelineStageSnapshot",
    "RuleScopeSummary",
    "RuntimeConfigRef",
    "SnapshotFreshness",
    "StatisticsSummary",
    "WorkbenchCommandRequest",
    "WorkbenchCommandResult",
    "WorkbenchComparisonSnapshot",
    "WorkbenchDiagnostic",
]
