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
    PIPELINE = "pipeline"
    SUPPORTING = "supporting"
    EVIDENCE = "evidence"


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


def _rule_scope_detail(snapshot: DeobfuscationWorkbenchSnapshot) -> str:
    scope = snapshot.rule_scope
    parts = [
        "project instruction rules: "
        + (", ".join(scope.project_instruction_rules) or "none"),
        "project block rules: " + (", ".join(scope.project_block_rules) or "none"),
        "function enabled: " + (", ".join(scope.function_enabled_rules) or "none"),
        "function disabled: " + (", ".join(scope.function_disabled_rules) or "none"),
        "tags: " + (", ".join(scope.function_tags) or "none"),
    ]
    if scope.inference_name:
        parts.append(
            f"inference: {scope.inference_name} "
            f"({'applies' if scope.inference_applies else 'does not apply'})"
        )
    if scope.function_notes:
        parts.append("notes: " + scope.function_notes)
    return "\n".join(parts)


def _statistics_detail(snapshot: DeobfuscationWorkbenchSnapshot) -> str:
    stats = snapshot.statistics
    lines = [
        *(
            f"optimizer {entry.name}: {entry.count}"
            for entry in stats.optimizer_matches
        ),
        *(f"rule {entry.name}: {entry.count}" for entry in stats.rule_matches),
        *(
            f"cfg {entry.name}: {entry.uses} uses, {entry.total_patches} patches"
            for entry in stats.cfg_patches
        ),
        f"total rule firings: {stats.total_rule_firings}",
        f"total cycles broken: {stats.total_cycles_detected}",
    ]
    return "\n".join(lines)


def project_workbench_rows(
    snapshot: DeobfuscationWorkbenchSnapshot,
) -> tuple[WorkbenchRow, ...]:
    """Project a snapshot without deriving runtime or execution truth."""
    context_status = _context_status(snapshot)
    runtime = snapshot.runtime
    attack = snapshot.attack
    recipe_scope_suffix = (
        " (function recipe)" if runtime.recipe_scope == "function-recipe" else ""
    )
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
                f"scope: {runtime.recipe_scope}\n"
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
                ordinal=stage.ordinal,
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
                key="supporting:rule-scope",
                section=WorkbenchSection.SUPPORTING,
                ordinal=len(snapshot.consumers),
                label="Rule scope",
                summary=(
                    f"{len(snapshot.rule_scope.function_enabled_rules)} enabled, "
                    f"{len(snapshot.rule_scope.function_disabled_rules)} disabled"
                ),
                detail=_rule_scope_detail(snapshot),
                status=OutcomeStatus.READY,
            ),
            _row(
                key="supporting:statistics",
                section=WorkbenchSection.SUPPORTING,
                ordinal=len(snapshot.consumers) + 1,
                label="Supporting statistics",
                summary=f"{snapshot.statistics.total_rule_firings} rule firings",
                detail=_statistics_detail(snapshot),
                status=(
                    OutcomeStatus.READY
                    if snapshot.statistics.total_rule_firings
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
    override_reason = (
        ""
        if current
        else "Refresh the stale workbench snapshot before editing overrides."
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
        WorkbenchActionState(
            "function_override",
            "Function override",
            current,
            override_reason,
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
            False,
            "The diagnostic explorer is delivered in workstream D0.",
        ),
    )


def command_request(
    snapshot: DeobfuscationWorkbenchSnapshot,
    command: str,
) -> WorkbenchCommandRequest:
    return WorkbenchCommandRequest(
        command=str(command),
        function_ea=snapshot.function.ea,
        expected_generation=snapshot.generation,
        function_fingerprint=snapshot.function.fingerprint,
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
    "should_accept_command_result",
    "stale_snapshot",
    "status_presentation",
]
