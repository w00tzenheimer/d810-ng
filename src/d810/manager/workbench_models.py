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
    recipe_scope: str = "project-runtime"


@dataclasses.dataclass(frozen=True, slots=True)
class AttackSummary:
    observed_shape: str
    mechanism: str
    selected_profile: str | None
    selection_mode: str
    confidence: float | None
    recommended_inferences: tuple[str, ...]
    suppressed_stages: tuple[str, ...]
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
class EffectiveStageDecisionSummary:
    pass_id: str
    stage_id: str
    pipeline: str
    maturities: tuple[int, ...]
    active: bool
    reason: str
    detail: str


@dataclasses.dataclass(frozen=True, slots=True)
class ExecutionScopeSummary:
    public_passes: tuple[str, ...]
    function_tags: tuple[str, ...]
    inference_names: tuple[str, ...]
    decisions: tuple[EffectiveStageDecisionSummary, ...]
    unknown_targets: tuple[str, ...]


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
    stage_matches: tuple[CountEntry, ...]
    total_stage_firings: int
    stage_patches: tuple[PatchCountEntry, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class ExecutionAttemptSummary:
    sequence: int
    parent_sequence: int | None
    stage_id: str
    domain: str
    status: str
    reason_code: str | None
    elapsed_ms: float | None
    effect_refs_json: str
    details_json: str


@dataclasses.dataclass(frozen=True, slots=True)
class ExecutionLedgerSummary:
    session_id: str | None
    function_ea: int
    attempts: tuple[ExecutionAttemptSummary, ...]
    terminal_attempts: int
    in_progress_attempts: int


@dataclasses.dataclass(frozen=True, slots=True)
class ExecutionProfileCandidateSummary:
    stage_id: str
    domain: str
    attempt_count: int
    attempt_to_effect_rate: float
    p95_elapsed_ms: float | None
    priority_score: float
    proof_failure_count: int
    mean_reduction: float | None
    reason_counts_json: str


@dataclasses.dataclass(frozen=True, slots=True)
class ExecutionProfileSummary:
    identity_json: str | None
    candidates: tuple[ExecutionProfileCandidateSummary, ...]
    ignored_in_progress_count: int
    ignored_identity_mismatch_count: int = 0
    is_read_only: bool = True


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
class PreparationScriptSummary:
    script_id: str
    display_name: str
    path: str
    configured_source_sha256: str
    current_source_sha256: str | None
    source_hash_matches: bool
    enabled: bool
    portable: bool


@dataclasses.dataclass(frozen=True, slots=True)
class PreparationTransactionSummary:
    transaction_id: str
    database_identity: str
    anchor_function_ea: int
    script_id: str
    script_path: str
    script_source_sha256: str
    state: str
    bytes_changed: int
    byte_ranges: tuple[tuple[int, int], ...]
    type_annotations: int
    affected_function_eas: tuple[int, ...]
    live_after_image: bool
    restore_allowed: bool
    restore_blocker: str
    recovery_required: bool


@dataclasses.dataclass(frozen=True, slots=True)
class PreparationWorkbenchSummary:
    database_identity: str | None
    scripts: tuple[PreparationScriptSummary, ...] = ()
    transactions: tuple[PreparationTransactionSummary, ...] = ()


@dataclasses.dataclass(frozen=True, slots=True)
class EffectiveScheduleStage:
    configured_index: int
    runtime_order: int
    pass_id: str
    stage_id: str
    pipeline: str
    implementation_name: str
    requirements: tuple[str, ...]
    provider_maturities: tuple[str, ...]
    maturity_source: str
    enabled: bool = True
    supported_maturities: tuple[str, ...] = ()
    requested_maturities: tuple[str, ...] = ()
    pass_maturity_gates: tuple[str, ...] = ()
    effective_maturities: tuple[str, ...] = ()
    lifecycle_domain: str = "microcode"
    schedule_source: str = "live rule"
    inactive_reason: str | None = None
    preparation_state: str | None = None
    preparation_reason: str | None = None
    preparation_pending_count: int = 0
    preparation_applied_count: int = 0
    preparation_conflicting_count: int = 0
    preparation_restored_count: int = 0
    preparation_unknown_count: int = 0
    preparation_provider_failures: tuple[str, ...] = ()


@dataclasses.dataclass(frozen=True, slots=True)
class EffectiveMaturityScheduleRow:
    ordinal: int
    ir_maturity: str
    provider_maturity: str
    pipeline_stages: tuple[tuple[str, tuple[EffectiveScheduleStage, ...]], ...] = ()

    def contains(self, stage_id: str) -> bool:
        return any(
            stage.stage_id == stage_id
            for _pipeline, stages in self.pipeline_stages
            for stage in stages
        )


@dataclasses.dataclass(frozen=True, slots=True)
class EffectiveMaturitySchedule:
    rows: tuple[EffectiveMaturityScheduleRow, ...] = ()
    stages: tuple[EffectiveScheduleStage, ...] = ()

    def at(self, provider_maturity: str) -> EffectiveMaturityScheduleRow:
        for row in self.rows:
            if row.provider_maturity == provider_maturity:
                return row
        return EffectiveMaturityScheduleRow(-1, "unknown", provider_maturity)

    def stage(self, stage_id: str) -> EffectiveScheduleStage:
        for stage in self.stages:
            if stage.stage_id == stage_id:
                return stage
        raise KeyError(stage_id)


@dataclasses.dataclass(frozen=True, slots=True)
class DeobfuscationWorkbenchSnapshot:
    generation: int
    function: FunctionRef
    runtime: RuntimeConfigRef
    attack: AttackSummary
    pipeline: tuple[PipelineStageSnapshot, ...]
    consumers: tuple[ConsumerOutcomeSnapshot, ...]
    execution_scope: ExecutionScopeSummary
    statistics: StatisticsSummary
    baseline: BaselineRef
    latest_output: D810OutputRef
    artifacts: tuple[ArtifactRef, ...]
    freshness: SnapshotFreshness
    engine_started: bool
    collection_errors: tuple[str, ...]
    preparation: PreparationWorkbenchSummary = dataclasses.field(
        default_factory=lambda: PreparationWorkbenchSummary(None)
    )
    effective_schedule: EffectiveMaturitySchedule = dataclasses.field(
        default_factory=EffectiveMaturitySchedule
    )
    execution_ledger: ExecutionLedgerSummary = dataclasses.field(
        default_factory=lambda: ExecutionLedgerSummary(None, 0, (), 0, 0)
    )
    execution_profile: ExecutionProfileSummary = dataclasses.field(
        default_factory=lambda: ExecutionProfileSummary(None, (), 0)
    )
    case: DeobfuscationCaseSnapshot | None = None


@dataclasses.dataclass(frozen=True, slots=True)
class WorkbenchCommandRequest:
    command: str
    function_ea: int
    expected_generation: int
    function_fingerprint: str | None
    database_identity: str | None = None
    script_source_hashes: tuple[tuple[str, str], ...] = ()
    transaction_id: str | None = None


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
    "EffectiveStageDecisionSummary",
    "EffectiveMaturitySchedule",
    "EffectiveMaturityScheduleRow",
    "EffectiveScheduleStage",
    "ExecutionAttemptSummary",
    "ExecutionLedgerSummary",
    "ExecutionProfileCandidateSummary",
    "ExecutionProfileSummary",
    "FunctionRef",
    "OutcomeStatus",
    "PatchCountEntry",
    "PreparationScriptSummary",
    "PreparationTransactionSummary",
    "PreparationWorkbenchSummary",
    "PipelineStageSnapshot",
    "ExecutionScopeSummary",
    "RuntimeConfigRef",
    "SnapshotFreshness",
    "StatisticsSummary",
    "WorkbenchCommandRequest",
    "WorkbenchCommandResult",
    "WorkbenchComparisonSnapshot",
    "WorkbenchDiagnostic",
]
