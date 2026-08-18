"""Pure projection logic for immutable deobfuscation workbench snapshots."""

from __future__ import annotations

import dataclasses
import enum
import json

from d810.manager.workbench_models import (
    ArtifactFreshness,
    ComparisonMetric,
    DeobfuscationWorkbenchSnapshot,
    OutcomeStatus,
    SnapshotFreshness,
    WorkbenchCommandRequest,
    WorkbenchCommandResult,
    WorkbenchComparisonSnapshot,
)


class WorkbenchSection(str, enum.Enum):
    CONTEXT = "context"
    ATTACK = "attack"
    PREPARATION = "preparation"
    PIPELINE = "pipeline"
    SUPPORTING = "supporting"
    EVIDENCE = "evidence"
    HISTORY = "history"


@dataclasses.dataclass(frozen=True, slots=True)
class StatusPresentation:
    color_role: str
    tooltip: str


@dataclasses.dataclass(frozen=True, slots=True)
class WorkbenchRow:
    key: str
    section: WorkbenchSection
    ordinal: int
    label: str
    summary: str
    detail: str
    status: OutcomeStatus
    color_role: str
    tooltip: str


@dataclasses.dataclass(frozen=True, slots=True)
class WorkbenchActionState:
    action_id: str
    label: str
    enabled: bool
    reason: str


@dataclasses.dataclass(frozen=True, slots=True)
class ComparisonArtifactView:
    label: str
    text: str
    freshness: ArtifactFreshness
    status: str
    reasons: tuple[str, ...]
    is_current: bool


@dataclasses.dataclass(frozen=True, slots=True)
class ComparisonMetricView:
    label: str
    native_value: int
    d810_value: int
    delta: int


@dataclasses.dataclass(frozen=True, slots=True)
class ComparisonView:
    function_ea: int
    native: ComparisonArtifactView
    d810: ComparisonArtifactView
    comparable: bool
    text_changed: bool | None
    metrics: tuple[ComparisonMetricView, ...]
    summary: str


_STATUS_PRESENTATIONS = {
    OutcomeStatus.NOT_RUN: StatusPresentation(
        "muted", "This stage or evidence source has not run."
    ),
    OutcomeStatus.READY: StatusPresentation(
        "info", "The static requirements are available; execution is not implied."
    ),
    OutcomeStatus.NOT_ELIGIBLE: StatusPresentation(
        "muted", "The required source artifacts were unavailable."
    ),
    OutcomeStatus.NO_MATCH: StatusPresentation(
        "neutral", "The consumer ran but found no applicable match."
    ),
    OutcomeStatus.CHANGED: StatusPresentation(
        "success", "The recorded consumer verdict changed the function state."
    ),
    OutcomeStatus.UNCHANGED: StatusPresentation(
        "neutral", "The recorded operation completed without a change."
    ),
    OutcomeStatus.ABSTAINED: StatusPresentation(
        "warning", "The consumer produced a decision but deliberately did not apply it."
    ),
    OutcomeStatus.BLOCKED: StatusPresentation(
        "warning", "A declared prerequisite or safety gate blocked this stage."
    ),
    OutcomeStatus.FAILED: StatusPresentation(
        "danger", "Collection or execution reported a failure."
    ),
    OutcomeStatus.STALE: StatusPresentation(
        "stale", "This evidence belongs to an older function generation."
    ),
}


def status_presentation(status: OutcomeStatus) -> StatusPresentation:
    return _STATUS_PRESENTATIONS[status]


def _row(
    *,
    key: str,
    section: WorkbenchSection,
    ordinal: int,
    label: str,
    summary: str,
    detail: str,
    status: OutcomeStatus,
) -> WorkbenchRow:
    presentation = status_presentation(status)
    return WorkbenchRow(
        key=key,
        section=section,
        ordinal=ordinal,
        label=label,
        summary=summary,
        detail=detail,
        status=status,
        color_role=presentation.color_role,
        tooltip=presentation.tooltip,
    )


def _context_status(snapshot: DeobfuscationWorkbenchSnapshot) -> OutcomeStatus:
    if snapshot.freshness is SnapshotFreshness.STALE:
        return OutcomeStatus.STALE
    if snapshot.freshness is SnapshotFreshness.UNAVAILABLE:
        return OutcomeStatus.FAILED
    return OutcomeStatus.READY


def _execution_scope_detail(snapshot: DeobfuscationWorkbenchSnapshot) -> str:
    scope = snapshot.execution_scope
    parts = [
        "passes: " + (", ".join(scope.public_passes) or "none"),
        "tags: " + (", ".join(scope.function_tags) or "none"),
        "inferences: " + (", ".join(scope.inference_names) or "none"),
    ]
    parts.extend(
        f"{decision.pipeline} {decision.pass_id}/{decision.stage_id}"
        f" [{','.join(str(value) for value in decision.maturities) or 'any'}]: "
        f"{decision.reason} - {decision.detail}"
        for decision in scope.decisions
    )
    if scope.unknown_targets:
        parts.append("unknown execution targets: " + ", ".join(scope.unknown_targets))
    return "\n".join(parts)


def _statistics_detail(snapshot: DeobfuscationWorkbenchSnapshot) -> str:
    stats = snapshot.statistics
    lines = [
        *(f"stage {entry.name}: {entry.count}" for entry in stats.stage_matches),
        *(
            f"cfg {entry.name}: {entry.uses} uses, {entry.total_patches} patches"
            for entry in stats.stage_patches
        ),
        f"total stage firings: {stats.total_stage_firings}",
    ]
    return "\n".join(lines)


def _execution_ledger_detail(snapshot: DeobfuscationWorkbenchSnapshot) -> str:
    ledger = snapshot.execution_ledger
    if ledger.session_id is None:
        return "No recorded decompilation session for this function."
    lines = [f"session: {ledger.session_id}"]
    for attempt in ledger.attempts:
        parent = (
            "root" if attempt.parent_sequence is None else str(attempt.parent_sequence)
        )
        elapsed = (
            "elapsed=unavailable"
            if attempt.elapsed_ms is None
            else f"elapsed={attempt.elapsed_ms:.3f}ms"
        )
        reason = "" if attempt.reason_code is None else f" reason={attempt.reason_code}"
        lines.append(
            f"{attempt.sequence} <- {parent} {attempt.domain} {attempt.stage_id}: "
            f"{attempt.status} {elapsed}{reason}"
        )
        if attempt.effect_refs_json != "[]":
            lines.append(f"  effects={attempt.effect_refs_json}")
        if attempt.details_json != "{}":
            lines.append(f"  details={attempt.details_json}")
    return "\n".join(lines)


def _execution_ledger_status(
    snapshot: DeobfuscationWorkbenchSnapshot,
) -> OutcomeStatus:
    ledger = snapshot.execution_ledger
    if not ledger.attempts:
        return OutcomeStatus.NOT_RUN
    if any(
        attempt.status in {"failed", "poisoned_restart_required"}
        for attempt in ledger.attempts
    ):
        return OutcomeStatus.FAILED
    return OutcomeStatus.READY


def _execution_profile_detail(snapshot: DeobfuscationWorkbenchSnapshot) -> str:
    profile = snapshot.execution_profile
    if profile.identity_json is None:
        return "No attested execution profile is available for this function."
    lines = [f"identity={profile.identity_json}", "authority=read-only preview"]
    for candidate in profile.candidates:
        p95 = (
            "unavailable"
            if candidate.p95_elapsed_ms is None
            else f"{candidate.p95_elapsed_ms:.3f}ms"
        )
        reduction = (
            "unavailable"
            if candidate.mean_reduction is None
            else f"{candidate.mean_reduction:.3f}"
        )
        lines.append(
            f"{candidate.domain} {candidate.stage_id}: score={candidate.priority_score:.3f} "
            f"effect_rate={candidate.attempt_to_effect_rate:.3f} p95={p95} "
            f"proof_failures={candidate.proof_failure_count} reduction={reduction} "
            f"reasons={candidate.reason_counts_json}"
        )
    return "\n".join(lines)


def project_workbench_rows(
    snapshot: DeobfuscationWorkbenchSnapshot,
) -> tuple[WorkbenchRow, ...]:
    """Project a snapshot without deriving runtime or execution truth."""
    context_status = _context_status(snapshot)
    runtime = snapshot.runtime
    attack = snapshot.attack
    recipe_scope_suffix = (
        " (saved recipe: Deobfuscate This only)"
        if runtime.recipe_scope == "saved-recipe-explicit"
        else ""
    )
    recipe_scope_detail = {
        "saved-recipe-explicit": (
            "ordinary refresh uses project runtime; Deobfuscate This uses the saved recipe"
        ),
        "saved-recipe-blocked": (
            "ordinary refresh uses project runtime; saved recipe is blocked"
        ),
        "project-runtime": "ordinary refresh and execution use project runtime",
    }.get(runtime.recipe_scope, f"scope: {runtime.recipe_scope}")
    rows: list[WorkbenchRow] = [
        _row(
            key="context:function",
            section=WorkbenchSection.CONTEXT,
            ordinal=0,
            label=snapshot.function.name or f"sub_{snapshot.function.ea:x}",
            summary=f"0x{snapshot.function.ea:X}",
            detail=(
                f"generation: {snapshot.function.generation}\n"
                f"fingerprint: {snapshot.function.fingerprint or 'unavailable'}"
            ),
            status=context_status,
        ),
        _row(
            key="context:runtime",
            section=WorkbenchSection.CONTEXT,
            ordinal=1,
            label="Effective runtime",
            summary=(
                f"{runtime.runtime_name} from {runtime.source_name}"
                if runtime.routed
                else runtime.runtime_name
            )
            + recipe_scope_suffix,
            detail=(
                f"source: {runtime.source_path}\n"
                f"runtime: {runtime.runtime_path}\n"
                f"mode: {runtime.mode}\n"
                f"hook mode: {runtime.hook_mode or 'none'}\n"
                f"{recipe_scope_detail}\n"
                f"passes: {', '.join(runtime.pass_ids) or 'none'}"
            ),
            status=context_status,
        ),
        _row(
            key="attack:summary",
            section=WorkbenchSection.ATTACK,
            ordinal=0,
            label="Attack summary",
            summary=attack.observed_shape,
            detail=(
                f"mechanism: {attack.mechanism}\n"
                f"profile: {attack.selected_profile or 'unavailable'}\n"
                f"selection: {attack.selection_mode}\n"
                f"confidence: "
                + (
                    "unavailable"
                    if attack.confidence is None
                    else f"{attack.confidence:.2f}"
                )
                + "\n"
                f"inferences: {', '.join(attack.recommended_inferences) or 'none'}\n"
                f"candidate kinds: {', '.join(attack.candidate_kinds) or 'none'}"
            ),
            status=(
                OutcomeStatus.NOT_RUN
                if attack.observed_shape == "unknown"
                else OutcomeStatus.READY
            ),
        ),
    ]

    for ordinal, script in enumerate(snapshot.preparation.scripts):
        source_status = (
            "source attested"
            if script.source_hash_matches
            else "source changed or unavailable"
        )
        portability = "portable" if script.portable else "absolute path"
        rows.append(
            _row(
                key=f"preparation:script:{script.script_id}",
                section=WorkbenchSection.PREPARATION,
                ordinal=ordinal,
                label=script.display_name,
                summary=f"{source_status}; {portability}",
                detail=(
                    f"id: {script.script_id}\n"
                    f"path: {script.path}\n"
                    f"enabled: {script.enabled}\n"
                    f"portable: {script.portable}\n"
                    f"configured sha256: {script.configured_source_sha256}\n"
                    f"current sha256: {script.current_source_sha256 or 'unavailable'}\n"
                    "Raw scripts may modify unmanaged metadata outside the exact "
                    "byte/type restore contract."
                ),
                status=(
                    OutcomeStatus.READY
                    if script.source_hash_matches and script.enabled
                    else (
                        OutcomeStatus.BLOCKED
                        if script.enabled
                        else OutcomeStatus.NOT_ELIGIBLE
                    )
                ),
            )
        )

    for ordinal, transaction in enumerate(snapshot.preparation.transactions):
        range_count = len(transaction.byte_ranges)
        summary = (
            f"{transaction.bytes_changed} bytes in {range_count} ranges; "
            f"{transaction.type_annotations} type annotations"
        )
        ranges = (
            ", ".join(
                f"0x{start:X}..0x{end:X}" for start, end in transaction.byte_ranges
            )
            or "none"
        )
        affected = (
            ", ".join(
                f"0x{function_ea:X}"
                for function_ea in transaction.affected_function_eas
            )
            or "none"
        )
        rows.append(
            _row(
                key=f"preparation:tx:{transaction.transaction_id}",
                section=WorkbenchSection.HISTORY,
                ordinal=ordinal,
                label=f"{transaction.script_id} [{transaction.state}]",
                summary=summary,
                detail=(
                    f"transaction: {transaction.transaction_id}\n"
                    f"database: {transaction.database_identity}\n"
                    f"anchor: 0x{transaction.anchor_function_ea:X}\n"
                    f"script: {transaction.script_path}\n"
                    f"source sha256: {transaction.script_source_sha256}\n"
                    f"ranges: {ranges}\n"
                    f"affected functions: {affected}\n"
                    f"live after-image: {transaction.live_after_image}\n"
                    f"restore: "
                    + (
                        "available"
                        if transaction.restore_allowed
                        else transaction.restore_blocker
                    )
                ),
                status=(
                    OutcomeStatus.BLOCKED
                    if transaction.recovery_required
                    else (
                        OutcomeStatus.CHANGED
                        if transaction.state == "idb_prepared"
                        else (
                            OutcomeStatus.UNCHANGED
                            if transaction.state == "restored"
                            else OutcomeStatus.FAILED
                        )
                    )
                ),
            )
        )

    for schedule_row in snapshot.effective_schedule.rows:
        if not schedule_row.stages:
            continue
        stage_labels = tuple(
            f"{stage.pass_id} (configured {stage.configured_index + 1})"
            for stage in schedule_row.stages
        )
        schedule_details: list[str] = []
        for stage in schedule_row.stages:
            callback_order = (
                f"runtime callback order {stage.runtime_order}"
                if stage.runtime_order >= 0
                else "runtime callback order unavailable"
            )
            schedule_details.append(
                f"{stage.pipeline} {stage.pass_id}/{stage.stage_id}: "
                f"{callback_order}; maturity authority {stage.maturity_source}; "
                f"requires {', '.join(stage.requirements) or 'none'}"
            )
        schedule_detail = "\n".join(schedule_details)
        rows.append(
            _row(
                key=f"pipeline:maturity:{schedule_row.provider_maturity}",
                section=WorkbenchSection.PIPELINE,
                ordinal=schedule_row.ordinal,
                label=(
                    f"{schedule_row.provider_maturity} / {schedule_row.ir_maturity}"
                ),
                summary="; ".join(stage_labels),
                detail=(
                    "Configured position is descriptive, not global execution order.\n"
                    + schedule_detail
                ),
                status=OutcomeStatus.READY,
            )
        )

    configured_ordinal_offset = len(snapshot.effective_schedule.rows)
    for stage in snapshot.pipeline:
        diagnostic_text = "\n".join(item.message for item in stage.diagnostics)
        detail = (
            f"phase: {stage.phase}\nscope: {stage.scope}\n"
            f"maturity: {stage.maturity}\ncontract: {stage.contract_json}"
        )
        if diagnostic_text:
            detail += "\ndiagnostics:\n" + diagnostic_text
        rows.append(
            _row(
                key=f"pipeline:{stage.ordinal}:{stage.pass_id}",
                section=WorkbenchSection.PIPELINE,
                ordinal=configured_ordinal_offset + stage.ordinal,
                label=f"{stage.ordinal + 1}. {stage.pass_id}",
                summary=stage.summary,
                detail=detail,
                status=stage.status,
            )
        )

    for ordinal, outcome in enumerate(snapshot.consumers):
        detail = outcome.detail
        if outcome.provenance_json:
            detail = (detail + "\n" if detail else "") + outcome.provenance_json
        rows.append(
            _row(
                key=f"consumer:{outcome.consumer_name}",
                section=WorkbenchSection.SUPPORTING,
                ordinal=ordinal,
                label=outcome.consumer_name,
                summary=outcome.status.value,
                detail=detail,
                status=outcome.status,
            )
        )

    rows.extend(
        (
            _row(
                key="supporting:execution-scope",
                section=WorkbenchSection.SUPPORTING,
                ordinal=len(snapshot.consumers),
                label="Effective execution",
                summary=(
                    f"{sum(1 for item in snapshot.execution_scope.decisions if item.active)} active, "
                    f"{sum(1 for item in snapshot.execution_scope.decisions if not item.active)} excluded"
                ),
                detail=_execution_scope_detail(snapshot),
                status=OutcomeStatus.READY,
            ),
            _row(
                key="supporting:execution-ledger",
                section=WorkbenchSection.SUPPORTING,
                ordinal=len(snapshot.consumers) + 1,
                label="Execution ledger",
                summary=(
                    f"{snapshot.execution_ledger.terminal_attempts} terminal, "
                    f"{snapshot.execution_ledger.in_progress_attempts} in progress"
                ),
                detail=_execution_ledger_detail(snapshot),
                status=_execution_ledger_status(snapshot),
            ),
            _row(
                key="supporting:statistics",
                section=WorkbenchSection.SUPPORTING,
                ordinal=len(snapshot.consumers) + 3,
                label="Legacy counters",
                summary=f"{snapshot.statistics.total_stage_firings} stage firings",
                detail=_statistics_detail(snapshot),
                status=(
                    OutcomeStatus.READY
                    if snapshot.statistics.total_stage_firings
                    else OutcomeStatus.NOT_RUN
                ),
            ),
            _row(
                key="supporting:execution-profile",
                section=WorkbenchSection.SUPPORTING,
                ordinal=len(snapshot.consumers) + 2,
                label="Execution profile preview",
                summary=(
                    f"{len(snapshot.execution_profile.candidates)} ranked candidates"
                ),
                detail=_execution_profile_detail(snapshot),
                status=(
                    OutcomeStatus.READY
                    if snapshot.execution_profile.identity_json is not None
                    else OutcomeStatus.NOT_RUN
                ),
            ),
        )
    )

    rows.extend(
        (
            _row(
                key="evidence:baseline",
                section=WorkbenchSection.EVIDENCE,
                ordinal=0,
                label="Native baseline",
                summary=(snapshot.baseline.path or "No baseline captured"),
                detail=f"fingerprint: {snapshot.baseline.fingerprint or 'unavailable'}",
                status=(
                    OutcomeStatus.READY
                    if snapshot.baseline.available
                    else OutcomeStatus.NOT_RUN
                ),
            ),
            _row(
                key="evidence:d810-output",
                section=WorkbenchSection.EVIDENCE,
                ordinal=1,
                label="Latest D810 output",
                summary=snapshot.latest_output.path or "No output captured",
                detail=(
                    "fingerprint: "
                    + (snapshot.latest_output.fingerprint or "unavailable")
                ),
                status=(
                    OutcomeStatus.READY
                    if snapshot.latest_output.available
                    else OutcomeStatus.NOT_RUN
                ),
            ),
        )
    )
    for ordinal, artifact in enumerate(snapshot.artifacts, start=2):
        rows.append(
            _row(
                key=f"artifact:{artifact.kind}",
                section=WorkbenchSection.EVIDENCE,
                ordinal=ordinal,
                label=artifact.label,
                summary=artifact.path or "Unavailable",
                detail=f"kind: {artifact.kind}",
                status=(
                    OutcomeStatus.READY
                    if artifact.available
                    else OutcomeStatus.NOT_ELIGIBLE
                ),
            )
        )
    for ordinal, error in enumerate(
        snapshot.collection_errors,
        start=2 + len(snapshot.artifacts),
    ):
        rows.append(
            _row(
                key=f"error:{ordinal}",
                section=WorkbenchSection.EVIDENCE,
                ordinal=ordinal,
                label="Collection error",
                summary=error,
                detail=error,
                status=OutcomeStatus.FAILED,
            )
        )
    return tuple(rows)


def filter_workbench_rows(
    rows: tuple[WorkbenchRow, ...],
    query: str,
) -> tuple[WorkbenchRow, ...]:
    normalized = query.strip().casefold()
    if not normalized:
        return rows
    return tuple(
        row
        for row in rows
        if normalized
        in "\n".join((row.label, row.summary, row.detail, row.status.value)).casefold()
    )


def _comparison_artifact_view(
    *,
    label: str,
    text: str | None,
    available: bool,
    freshness: ArtifactFreshness,
    reasons: tuple[str, ...],
) -> ComparisonArtifactView:
    is_current = available and freshness is ArtifactFreshness.CURRENT
    if is_current:
        status = "Current"
    elif freshness is ArtifactFreshness.STALE:
        status = "Stale"
    else:
        status = "Missing"
    return ComparisonArtifactView(
        label=label,
        text=text or "",
        freshness=freshness,
        status=status,
        reasons=reasons,
        is_current=is_current,
    )


def _comparison_metric_view(metric: ComparisonMetric) -> ComparisonMetricView:
    return ComparisonMetricView(
        label=metric.name,
        native_value=metric.native_value,
        d810_value=metric.d810_value,
        delta=metric.delta,
    )


def comparison_view(snapshot: WorkbenchComparisonSnapshot) -> ComparisonView:
    """Project comparison evidence without making a correctness claim."""
    native = _comparison_artifact_view(
        label="Native",
        text=snapshot.baseline.pseudocode,
        available=snapshot.baseline.available,
        freshness=snapshot.baseline_freshness,
        reasons=snapshot.baseline_stale_reasons,
    )
    d810 = _comparison_artifact_view(
        label="D810",
        text=snapshot.d810_output.pseudocode,
        available=snapshot.d810_output.available,
        freshness=snapshot.d810_freshness,
        reasons=snapshot.d810_stale_reasons,
    )
    comparable = native.is_current and d810.is_current
    if not comparable:
        summary = "Comparison unavailable until both artifacts are current."
    elif snapshot.text_changed:
        summary = "Pseudocode text differs."
    else:
        summary = "Pseudocode text matches."
    return ComparisonView(
        function_ea=snapshot.function_ea,
        native=native,
        d810=d810,
        comparable=comparable,
        text_changed=snapshot.text_changed if comparable else None,
        metrics=(
            tuple(_comparison_metric_view(metric) for metric in snapshot.metrics)
            if comparable
            else ()
        ),
        summary=summary,
    )


def action_states(
    snapshot: DeobfuscationWorkbenchSnapshot,
) -> tuple[WorkbenchActionState, ...]:
    current = snapshot.freshness is SnapshotFreshness.CURRENT
    engine_ready = current and snapshot.engine_started
    engine_reason = (
        ""
        if engine_ready
        else (
            "Refresh the stale workbench snapshot before running this command."
            if not current
            else "Start D810 before running this command."
        )
    )
    return (
        WorkbenchActionState("refresh", "Refresh", True, ""),
        WorkbenchActionState("export", "Export evidence", True, ""),
        WorkbenchActionState("analyze", "Analyze", engine_ready, engine_reason),
        WorkbenchActionState(
            "deobfuscate",
            "Deobfuscate",
            engine_ready,
            engine_reason,
        ),
        WorkbenchActionState("compare", "Compare", engine_ready, engine_reason),
        WorkbenchActionState(
            "recipe",
            "Recipe",
            current,
            (
                ""
                if current
                else "Refresh the stale workbench snapshot before editing a recipe."
            ),
        ),
        WorkbenchActionState(
            "diagnostics",
            "Diagnostics",
            current,
            (
                ""
                if current
                else "Refresh the stale workbench snapshot before opening diagnostics."
            ),
        ),
    )


def preparation_action_states(
    snapshot: DeobfuscationWorkbenchSnapshot,
    *,
    selected_transaction_id: str | None = None,
) -> tuple[WorkbenchActionState, ...]:
    current = snapshot.freshness is SnapshotFreshness.CURRENT
    available = current and snapshot.preparation.database_identity is not None
    drifted = tuple(
        script.display_name
        for script in snapshot.preparation.scripts
        if script.enabled and not script.source_hash_matches
    )
    if not current:
        preparation_reason = "Refresh the stale Workbench snapshot."
    elif snapshot.preparation.database_identity is None:
        preparation_reason = "Start D810 to initialize IDB preparation."
    elif drifted:
        preparation_reason = "Script source changed after preview: " + ", ".join(
            drifted
        )
    else:
        preparation_reason = ""
    execute_enabled = available and not drifted

    selected = next(
        (
            transaction
            for transaction in snapshot.preparation.transactions
            if transaction.transaction_id == selected_transaction_id
        ),
        None,
    )
    if selected is None:
        restore_enabled = False
        restore_reason = "Select an applied preparation transaction."
    elif selected.database_identity != snapshot.preparation.database_identity:
        restore_enabled = False
        restore_reason = "The selected transaction belongs to another database."
    elif selected.state in {
        "prepared",
        "script_running",
        "capture_pending",
        "captured",
        "analysis_pending",
        "restoring",
        "rolling_back",
    }:
        restore_enabled = False
        restore_reason = f"The transaction is still running ({selected.state})."
    elif not selected.live_after_image:
        restore_enabled = False
        restore_reason = selected.restore_blocker or "Exact after-image is absent."
    else:
        restore_enabled = selected.restore_allowed
        restore_reason = "" if restore_enabled else selected.restore_blocker

    return (
        WorkbenchActionState(
            "preview_preparation",
            "Preview",
            available,
            "" if available else preparation_reason,
        ),
        WorkbenchActionState(
            "prepare_only",
            "Prepare only",
            execute_enabled,
            preparation_reason,
        ),
        WorkbenchActionState(
            "prepare_and_decompile",
            "Prepare & Decompile",
            execute_enabled,
            preparation_reason,
        ),
        WorkbenchActionState(
            "restore_preparation",
            "Restore",
            restore_enabled,
            restore_reason,
        ),
    )


def command_request(
    snapshot: DeobfuscationWorkbenchSnapshot,
    command: str,
    *,
    transaction_id: str | None = None,
) -> WorkbenchCommandRequest:
    return WorkbenchCommandRequest(
        command=str(command),
        function_ea=snapshot.function.ea,
        expected_generation=snapshot.generation,
        function_fingerprint=snapshot.function.fingerprint,
        database_identity=snapshot.preparation.database_identity,
        script_source_hashes=tuple(
            (script.script_id, script.current_source_sha256 or "")
            for script in snapshot.preparation.scripts
            if script.enabled
        ),
        transaction_id=transaction_id,
    )


def stale_snapshot(
    snapshot: DeobfuscationWorkbenchSnapshot,
) -> DeobfuscationWorkbenchSnapshot:
    return dataclasses.replace(
        snapshot,
        pipeline=tuple(
            dataclasses.replace(stage, status=OutcomeStatus.STALE)
            for stage in snapshot.pipeline
        ),
        consumers=tuple(
            dataclasses.replace(outcome, status=OutcomeStatus.STALE)
            for outcome in snapshot.consumers
        ),
        freshness=SnapshotFreshness.STALE,
    )


def should_accept_command_result(
    snapshot: DeobfuscationWorkbenchSnapshot,
    result: WorkbenchCommandResult,
) -> bool:
    return (
        result.accepted
        and result.function_ea == snapshot.function.ea
        and result.requested_generation == snapshot.generation
        and result.function_fingerprint == snapshot.function.fingerprint
    )


def detail_text(row: WorkbenchRow) -> str:
    return row.detail


def _jsonable(value: object) -> object:
    if isinstance(value, enum.Enum):
        return value.value
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {
            field.name: _jsonable(getattr(value, field.name))
            for field in dataclasses.fields(value)
        }
    if isinstance(value, tuple):
        return [_jsonable(item) for item in value]
    if isinstance(value, list):
        return [_jsonable(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    return value


def export_evidence_json(snapshot: DeobfuscationWorkbenchSnapshot) -> str:
    """Return a stable UTF-8 JSON representation with one trailing newline."""
    return (
        json.dumps(
            _jsonable(snapshot),
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n"
    )


__all__ = [
    "ComparisonArtifactView",
    "ComparisonMetricView",
    "ComparisonView",
    "StatusPresentation",
    "WorkbenchActionState",
    "WorkbenchRow",
    "WorkbenchSection",
    "action_states",
    "command_request",
    "comparison_view",
    "detail_text",
    "export_evidence_json",
    "filter_workbench_rows",
    "project_workbench_rows",
    "preparation_action_states",
    "should_accept_command_result",
    "stale_snapshot",
    "status_presentation",
]
