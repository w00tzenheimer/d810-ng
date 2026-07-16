"""Generation-safe application commands for validated recipe drafts."""

from __future__ import annotations

from collections.abc import Callable

from d810.manager.workbench_models import OutcomeStatus
from d810.manager.workbench_recipe_models import (
    PipelineRecipeDraft,
    RecipeCommandRequest,
    RecipeCommandResult,
    RecipeValidation,
)


class WorkbenchRecipeCommandService:
    """Invoke recipe side effects once while enforcing exact workbench identity."""

    def __init__(
        self,
        *,
        identity_is_current: Callable[[RecipeCommandRequest], bool],
    ) -> None:
        self._identity_is_current = identity_is_current

    @staticmethod
    def _result(
        request: RecipeCommandRequest,
        *,
        status: OutcomeStatus,
        succeeded: bool,
        accepted: bool,
        refresh_requested: bool,
        message: str,
    ) -> RecipeCommandResult:
        return RecipeCommandResult(
            command=request.command,
            draft_id=request.draft_id,
            draft_revision=request.draft_revision,
            function_ea=request.function_ea,
            requested_workbench_generation=request.expected_workbench_generation,
            function_fingerprint=request.function_fingerprint,
            status=status,
            succeeded=succeeded,
            accepted=accepted,
            refresh_requested=refresh_requested,
            message=message,
        )

    def _validate(
        self,
        request: RecipeCommandRequest,
        draft: PipelineRecipeDraft,
        validation: RecipeValidation,
        *,
        expected_command: str,
    ) -> RecipeCommandResult | None:
        if request.command != expected_command:
            return self._result(
                request,
                status=OutcomeStatus.FAILED,
                succeeded=False,
                accepted=False,
                refresh_requested=False,
                message=f"Expected recipe command {expected_command!r}",
            )
        if (
            request.draft_id != draft.draft_id
            or request.draft_revision != draft.revision
            or request.function_ea != draft.function_ea
            or request.expected_workbench_generation != draft.workbench_generation
            or request.function_fingerprint != draft.function_fingerprint
        ):
            return self._result(
                request,
                status=OutcomeStatus.FAILED,
                succeeded=False,
                accepted=False,
                refresh_requested=False,
                message="Recipe command identity does not match the current draft",
            )
        if (
            validation.draft_id != draft.draft_id
            or validation.revision != draft.revision
        ):
            return self._result(
                request,
                status=OutcomeStatus.FAILED,
                succeeded=False,
                accepted=False,
                refresh_requested=False,
                message="Recipe validation describes an older draft revision",
            )
        if not validation.satisfied:
            return self._result(
                request,
                status=OutcomeStatus.BLOCKED,
                succeeded=False,
                accepted=True,
                refresh_requested=False,
                message="Recipe contract preflight is blocked",
            )
        if not self._identity_is_current(request):
            return self._result(
                request,
                status=OutcomeStatus.STALE,
                succeeded=False,
                accepted=False,
                refresh_requested=False,
                message="Recipe command belongs to an older workbench generation",
            )
        return None

    def _after_callback(
        self,
        request: RecipeCommandRequest,
        *,
        label: str,
    ) -> RecipeCommandResult:
        if not self._identity_is_current(request):
            return self._result(
                request,
                status=OutcomeStatus.STALE,
                succeeded=True,
                accepted=False,
                refresh_requested=False,
                message=f"{label} completed for an older workbench generation",
            )
        return self._result(
            request,
            status=OutcomeStatus.READY,
            succeeded=True,
            accepted=True,
            refresh_requested=True,
            message=f"{label} completed",
        )

    def execute_apply_once(
        self,
        request: RecipeCommandRequest,
        draft: PipelineRecipeDraft,
        validation: RecipeValidation,
        *,
        lifecycle: Callable[[PipelineRecipeDraft], bool],
    ) -> RecipeCommandResult:
        invalid = self._validate(
            request,
            draft,
            validation,
            expected_command="apply_recipe_once",
        )
        if invalid is not None:
            return invalid
        try:
            succeeded = bool(lifecycle(draft))
        except Exception as exc:
            return self._result(
                request,
                status=OutcomeStatus.FAILED,
                succeeded=False,
                accepted=True,
                refresh_requested=False,
                message=f"Apply recipe once failed: {exc}",
            )
        if not succeeded:
            return self._result(
                request,
                status=OutcomeStatus.FAILED,
                succeeded=False,
                accepted=True,
                refresh_requested=False,
                message="Apply recipe once did not complete",
            )
        return self._after_callback(request, label="Apply recipe once")

    def execute_save(
        self,
        request: RecipeCommandRequest,
        draft: PipelineRecipeDraft,
        validation: RecipeValidation,
        *,
        persistence: Callable[[PipelineRecipeDraft, RecipeValidation], object],
    ) -> RecipeCommandResult:
        invalid = self._validate(
            request,
            draft,
            validation,
            expected_command="save_function_recipe",
        )
        if invalid is not None:
            return invalid
        try:
            persistence(draft, validation)
        except Exception as exc:
            return self._result(
                request,
                status=OutcomeStatus.FAILED,
                succeeded=False,
                accepted=True,
                refresh_requested=False,
                message=f"Save function recipe failed: {exc}",
            )
        return self._after_callback(request, label="Save function recipe")


__all__ = ["WorkbenchRecipeCommandService"]
