"""Pure presentation and action logic for registered-pass recipes."""

from __future__ import annotations

import dataclasses

from d810.manager.workbench_models import OutcomeStatus
from d810.manager.workbench_recipe_models import (
    PassCatalogEntry,
    PipelineRecipeDraft,
    RecipeCommandRequest,
    RecipeCommandResult,
    RecipeValidation,
)


@dataclasses.dataclass(frozen=True, slots=True)
class RecipeCatalogRow:
    pass_id: str
    label: str
    summary: str
    detail: str
    transform_children: tuple[str, ...]


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
                *entry.owned_rules,
                *entry.transforms,
            )
        ).casefold()
    )
    key_functions = {
        "name": lambda entry: (entry.display_name.casefold(), entry.pass_id),
        "pass_id": lambda entry: (entry.pass_id.casefold(), entry.pass_id),
        "maturity": lambda entry: (entry.maturity.casefold(), entry.pass_id),
        "backend": lambda entry: (entry.backend_route.casefold(), entry.pass_id),
    }
    if sort_by not in key_functions:
        raise ValueError(f"unsupported recipe catalog sort: {sort_by!r}")
    ordered = sorted(filtered, key=key_functions[sort_by])
    return tuple(
        RecipeCatalogRow(
            pass_id=entry.pass_id,
            label=entry.display_name,
            summary=(
                f"{entry.granularity}; {entry.maturity}; {entry.backend_route}"
            ),
            detail=(
                f"safety: {entry.safety_policy}\n"
                f"rules: {', '.join(entry.owned_rules) or 'none'}\n"
                f"options: {entry.option_template_json}\n"
                f"contract: {entry.contract_json}"
            ),
            transform_children=entry.transforms,
        )
        for entry in ordered
    )


def project_draft_rows(
    draft: PipelineRecipeDraft,
    validation: RecipeValidation,
) -> tuple[RecipeDraftRow, ...]:
    diagnostics_by_ordinal: dict[int, list[str]] = {}
    if (
        validation.draft_id == draft.draft_id
        and validation.revision == draft.revision
    ):
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
) -> tuple[RecipeActionState, ...]:
    exact_validation = (
        validation.draft_id == draft.draft_id
        and validation.revision == draft.revision
    )
    valid = exact_validation and validation.satisfied
    stale_reason = "Refresh the workbench before editing this recipe."
    validation_reason = (
        ""
        if valid
        else "Resolve recipe validation diagnostics before this action."
    )
    apply_enabled = workbench_current and engine_started and valid
    if not workbench_current:
        apply_reason = stale_reason
    elif not engine_started:
        apply_reason = "Start D810 before applying this recipe."
    else:
        apply_reason = validation_reason
    save_enabled = workbench_current and valid
    return (
        RecipeActionState("reset", "Reset to effective pipeline", workbench_current, "" if workbench_current else stale_reason),
        RecipeActionState("analyze", "Analyze recipe", workbench_current, "" if workbench_current else stale_reason),
        RecipeActionState("apply_once", "Apply once", apply_enabled, apply_reason),
        RecipeActionState(
            "save_function",
            "Save for this function",
            save_enabled,
            "" if save_enabled else (stale_reason if not workbench_current else validation_reason),
        ),
        RecipeActionState(
            "save_project",
            "Save as project profile",
            False,
            "Lossless project-profile editing is delivered in Slice 5.",
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
    "RecipeActionState",
    "RecipeCatalogRow",
    "RecipeDraftRow",
    "project_catalog_rows",
    "project_draft_rows",
    "recipe_action_states",
    "recipe_command_request",
    "should_accept_recipe_result",
]
