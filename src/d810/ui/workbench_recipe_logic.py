"""Pure presentation and action logic for registered-pass recipes."""

from __future__ import annotations

import dataclasses
import json

from d810.core.deobfuscation_case import (
    DeobfuscationCaseSnapshot,
    StrategyWorkflowStage,
)
from d810.ir.maturity import IRMaturity, ir_maturity_rank
from d810.manager.workbench_models import OutcomeStatus
from d810.manager.workbench_recipe_models import (
    PassCatalogEntry,
    PipelineRecipeDraft,
    RecipeCommandRequest,
    RecipeCommandResult,
    RecipeValidation,
)
from d810.passes.pass_pipeline import PipelineConfig
from d810.passes.state_machine_options import (
    STATE_MACHINE_NATIVE_PASS_IDS as _STATE_MACHINE_NATIVE_PASS_IDS,
    StateMachineCffOptions,
    state_machine_cff_options_from_config,
)

STATE_MACHINE_NATIVE_PASS_IDS = _STATE_MACHINE_NATIVE_PASS_IDS


def parse_state_cff_minimum_constant(text: str) -> StateMachineCffOptions:
    """Parse decimal or Python-style hexadecimal input into typed options."""
    try:
        value = int(str(text).strip(), 0)
    except (TypeError, ValueError) as exc:
        raise ValueError("state-CFF minimum constant must be an integer") from exc
    return StateMachineCffOptions(min_state_constant=value)


def state_cff_minimum_constant_from_config_json(config_json: str) -> int:
    """Project the typed threshold from one serialized spine entry."""
    payload = json.loads(config_json)
    return state_machine_cff_options_from_config(
        PipelineConfig.from_dict(payload)
    ).min_state_constant


@dataclasses.dataclass(frozen=True, slots=True)
class RecipeCatalogRow:
    pass_id: str
    label: str
    workflow_stage: StrategyWorkflowStage
    workflow_stage_label: str
    summary: str
    detail: str
    stage_children: tuple[str, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class RecipeDraftRow:
    item_id: str
    pass_id: str
    ordinal: int
    label: str
    enabled: bool
    status: OutcomeStatus
    diagnostics: tuple[str, ...]
    config_json: str


@dataclasses.dataclass(frozen=True, slots=True)
class RecipeActionState:
    action_id: str
    label: str
    enabled: bool
    reason: str


@dataclasses.dataclass(frozen=True, slots=True)
class RecipeStrategyView:
    strategy_summary: str
    blocked_reason: str | None
    can_add_transform: bool = False


_WORKFLOW_STAGE_LABELS = {
    StrategyWorkflowStage.EVIDENCE_PROVIDER: "Evidence provider",
    StrategyWorkflowStage.FRONTEND_NORMALIZATION: "Frontend normalization",
    StrategyWorkflowStage.CANONICAL_ANALYSIS: "Canonical analysis",
    StrategyWorkflowStage.CANONICAL_TRANSFORM: "Canonical transform",
    StrategyWorkflowStage.BACKEND_PUBLICATION: "Backend publication",
    StrategyWorkflowStage.CANONICAL_PIPELINE: "Canonical pipeline",
}
_WORKFLOW_STAGE_ORDER = {
    stage: ordinal for ordinal, stage in enumerate(StrategyWorkflowStage)
}


class CanvasAddError(ValueError):
    """Reject a canvas addition before it reaches mutable recipe state."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _maturity_boundary(value: object) -> IRMaturity | None:
    normalized = str(value).strip()
    if normalized == "any":
        return None
    boundary = normalized.removeprefix(">=").removeprefix("<=").split("..", 1)[0]
    try:
        return IRMaturity(boundary)
    except ValueError:
        try:
            return IRMaturity[boundary]
        except KeyError:
            return None


def _maturity_range(
    value: object,
) -> tuple[IRMaturity | None, IRMaturity | None] | None:
    normalized = str(value).strip()
    if normalized == "any":
        return None, None
    if normalized.startswith(">="):
        minimum = _maturity_boundary(normalized)
        return (minimum, None) if minimum is not None else None
    if normalized.startswith("<="):
        maximum = _maturity_boundary(normalized)
        return (None, maximum) if maximum is not None else None
    if ".." in normalized:
        minimum_text, maximum_text = normalized.split("..", 1)
        minimum = _maturity_boundary(minimum_text)
        maximum = _maturity_boundary(maximum_text)
        if minimum is None or maximum is None:
            return None
        if ir_maturity_rank(minimum) > ir_maturity_rank(maximum):
            return None
        return minimum, maximum
    maturity = _maturity_boundary(normalized)
    return (maturity, maturity) if maturity is not None else None


def _canvas_stage(stage_id: object) -> IRMaturity | None:
    normalized = str(stage_id).strip()
    if normalized == "any":
        return None
    return _maturity_boundary(normalized)


def _is_legal_canvas_stage(entry: PassCatalogEntry, stage_id: object) -> bool:
    normalized_stage = str(stage_id).strip()
    stage = _canvas_stage(normalized_stage)
    if normalized_stage == "any":
        return str(entry.maturity).strip() == "any"
    if stage is None:
        return False
    maturity_range = _maturity_range(entry.maturity)
    if maturity_range is None:
        return False
    minimum, maximum = maturity_range
    if minimum is None and maximum is None:
        return False
    rank = ir_maturity_rank(stage)
    return (minimum is None or ir_maturity_rank(minimum) <= rank) and (
        maximum is None or rank <= ir_maturity_rank(maximum)
    )


def canvas_add_candidates(
    catalog: tuple[PassCatalogEntry, ...],
    stage_id: str,
    draft: PipelineRecipeDraft,
) -> tuple[PassCatalogEntry, ...]:
    """Return configured, non-duplicate passes that are legal at a canvas stage."""
    normalized_stage = str(stage_id).strip()
    if normalized_stage != "any" and _canvas_stage(normalized_stage) is None:
        raise CanvasAddError("unknown-stage")
    used_pass_ids = {item.pass_id for item in draft.passes}
    return tuple(
        entry
        for entry in catalog
        if entry.configured
        and entry.pass_id not in used_pass_ids
        and _is_legal_canvas_stage(entry, normalized_stage)
    )


def enables_dangerous_executable_readonly(
    pass_id: str,
    current_options: object,
    proposed_options: object,
) -> bool:
    """Return whether an edit newly enables the dangerous constant override."""
    if pass_id != "constant-simplification":
        return False
    if not isinstance(current_options, dict) or not isinstance(proposed_options, dict):
        return False
    return (
        current_options.get("allow_executable_readonly") is not True
        and proposed_options.get("allow_executable_readonly") is True
    )


def workflow_stage_label(stage: StrategyWorkflowStage) -> str:
    """Return a stable UI label for explicit pass registration metadata."""
    return _WORKFLOW_STAGE_LABELS[stage]


def project_recipe_strategy(
    case: DeobfuscationCaseSnapshot | None,
    entries: tuple[PassCatalogEntry, ...],
) -> RecipeStrategyView:
    """Explain how registered passes relate to the current case, without editing it."""
    del entries
    if case is None:
        return RecipeStrategyView(
            strategy_summary="No current case strategy is available.",
            blocked_reason="Return to the Workbench and build a case first.",
        )
    if case.strategy is None:
        if case.direct_run_permitted:
            return RecipeStrategyView(
                strategy_summary="Current saved function recipe.",
                blocked_reason=None,
            )
        return RecipeStrategyView(
            strategy_summary="No validated strategy is selected.",
            blocked_reason="Build the case dossier before composing a run.",
        )
    if case.evidence is None:
        return RecipeStrategyView(
            strategy_summary=case.strategy.summary,
            blocked_reason="Build the case dossier before composing a run.",
        )
    available = {finding.finding_id for finding in case.evidence.findings}
    missing = tuple(
        finding_id
        for finding_id in case.strategy.required_finding_ids
        if finding_id not in available
    )
    if missing:
        return RecipeStrategyView(
            strategy_summary=case.strategy.summary,
            blocked_reason="Validate required evidence: " + ", ".join(missing),
        )
    return RecipeStrategyView(
        strategy_summary=case.strategy.summary,
        blocked_reason=None,
    )


def project_catalog_rows(
    entries: tuple[PassCatalogEntry, ...],
    *,
    query: str = "",
    sort_by: str = "name",
) -> tuple[RecipeCatalogRow, ...]:
    normalized = query.strip().casefold()
    filtered = tuple(
        entry
        for entry in entries
        if not normalized
        or normalized
        in "\n".join(
            (
                entry.pass_id,
                entry.display_name,
                entry.contract_json,
                entry.option_template_json,
                entry.granularity,
                entry.maturity,
                entry.backend_route,
                entry.safety_policy,
                entry.workflow_stage.value,
                *entry.transform_ids,
                *entry.stage_ids,
            )
        ).casefold()
    )
    key_functions = {
        "name": lambda entry: (entry.display_name.casefold(), entry.pass_id),
        "pass_id": lambda entry: (entry.pass_id.casefold(), entry.pass_id),
        "maturity": lambda entry: (entry.maturity.casefold(), entry.pass_id),
        "backend": lambda entry: (entry.backend_route.casefold(), entry.pass_id),
        "stage": lambda entry: (
            _WORKFLOW_STAGE_ORDER[entry.workflow_stage],
            entry.pass_id,
        ),
    }
    if sort_by not in key_functions:
        raise ValueError(f"unsupported recipe catalog sort: {sort_by!r}")
    ordered = sorted(filtered, key=key_functions[sort_by])
    return tuple(
        RecipeCatalogRow(
            pass_id=entry.pass_id,
            label=entry.display_name,
            workflow_stage=entry.workflow_stage,
            workflow_stage_label=workflow_stage_label(entry.workflow_stage),
            summary=(
                f"{workflow_stage_label(entry.workflow_stage)}; "
                f"{entry.granularity}; {entry.maturity}; {entry.backend_route}"
            ),
            detail=(
                f"stage: {workflow_stage_label(entry.workflow_stage)}\n"
                f"safety: {entry.safety_policy}\n"
                f"transforms: {', '.join(entry.transform_ids) or 'none'}\n"
                f"options: {entry.option_template_json}\n"
                f"contract: {entry.contract_json}"
            ),
            stage_children=entry.stage_ids,
        )
        for entry in ordered
    )


def project_draft_rows(
    draft: PipelineRecipeDraft,
    validation: RecipeValidation,
) -> tuple[RecipeDraftRow, ...]:
    diagnostics_by_ordinal: dict[int, list[str]] = {}
    if validation.draft_id == draft.draft_id and validation.revision == draft.revision:
        for diagnostic in validation.diagnostics:
            if diagnostic.ordinal is not None:
                diagnostics_by_ordinal.setdefault(diagnostic.ordinal, []).append(
                    diagnostic.message
                )
    rows: list[RecipeDraftRow] = []
    for ordinal, item in enumerate(draft.passes):
        diagnostics = tuple(diagnostics_by_ordinal.get(ordinal, ()))
        if not item.enabled:
            status = OutcomeStatus.NOT_RUN
        elif diagnostics:
            status = OutcomeStatus.BLOCKED
        else:
            status = OutcomeStatus.READY
        rows.append(
            RecipeDraftRow(
                item_id=item.item_id,
                pass_id=item.pass_id,
                ordinal=ordinal,
                label=f"{ordinal + 1}. {item.pass_id}",
                enabled=item.enabled,
                status=status,
                diagnostics=diagnostics,
                config_json=item.config_json,
            )
        )
    return tuple(rows)


def recipe_action_states(
    draft: PipelineRecipeDraft,
    validation: RecipeValidation,
    *,
    workbench_current: bool,
    engine_started: bool,
    project_profile_save_available: bool = False,
) -> tuple[RecipeActionState, ...]:
    exact_validation = (
        validation.draft_id == draft.draft_id and validation.revision == draft.revision
    )
    valid = exact_validation and validation.satisfied
    stale_reason = "Refresh the workbench before editing this recipe."
    validation_reason = (
        "" if valid else "Resolve recipe validation diagnostics before this action."
    )
    apply_enabled = workbench_current and engine_started and valid
    if not workbench_current:
        apply_reason = stale_reason
    elif not engine_started:
        apply_reason = "Start D810 before applying this recipe."
    else:
        apply_reason = validation_reason
    save_enabled = workbench_current and valid
    project_save_enabled = save_enabled and project_profile_save_available
    if not project_profile_save_available:
        project_save_reason = (
            "A lossless config-v2 serializer is not available for this project."
        )
    elif not workbench_current:
        project_save_reason = stale_reason
    else:
        project_save_reason = validation_reason
    return (
        RecipeActionState(
            "reset",
            "Reset to effective pipeline",
            workbench_current,
            "" if workbench_current else stale_reason,
        ),
        RecipeActionState(
            "analyze",
            "Analyze recipe",
            workbench_current,
            "" if workbench_current else stale_reason,
        ),
        RecipeActionState("apply_once", "Apply once", apply_enabled, apply_reason),
        RecipeActionState(
            "save_function",
            "Save for Deobfuscate This",
            save_enabled,
            (
                ""
                if save_enabled
                else (stale_reason if not workbench_current else validation_reason)
            ),
        ),
        RecipeActionState(
            "save_project",
            "Save as project profile",
            project_save_enabled,
            "" if project_save_enabled else project_save_reason,
        ),
    )


def recipe_command_request(
    draft: PipelineRecipeDraft,
    command: str,
) -> RecipeCommandRequest:
    return RecipeCommandRequest(
        command=str(command),
        draft_id=draft.draft_id,
        draft_revision=draft.revision,
        function_ea=draft.function_ea,
        expected_workbench_generation=draft.workbench_generation,
        function_fingerprint=draft.function_fingerprint,
    )


def should_accept_recipe_result(
    draft: PipelineRecipeDraft,
    result: RecipeCommandResult,
) -> bool:
    return (
        result.accepted
        and result.draft_id == draft.draft_id
        and result.draft_revision == draft.revision
        and result.function_ea == draft.function_ea
        and result.requested_workbench_generation == draft.workbench_generation
        and result.function_fingerprint == draft.function_fingerprint
    )


__all__ = [
    "CanvasAddError",
    "RecipeActionState",
    "RecipeCatalogRow",
    "RecipeDraftRow",
    "RecipeStrategyView",
    "canvas_add_candidates",
    "project_catalog_rows",
    "project_draft_rows",
    "project_recipe_strategy",
    "recipe_action_states",
    "recipe_command_request",
    "should_accept_recipe_result",
    "workflow_stage_label",
]
