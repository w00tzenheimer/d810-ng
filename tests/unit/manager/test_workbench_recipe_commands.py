from __future__ import annotations

from d810.manager.workbench_models import OutcomeStatus
from d810.manager.workbench_recipe_commands import WorkbenchRecipeCommandService
from d810.manager.workbench_recipe_models import (
    PipelineRecipeDraft,
    RecipeCommandRequest,
    RecipePass,
    RecipeValidation,
)
from d810.manager.workbench_service import WorkbenchService


def _draft() -> PipelineRecipeDraft:
    return PipelineRecipeDraft(
        draft_id="draft-1",
        schema_version=1,
        revision=2,
        function_ea=0x401000,
        function_fingerprint="sha256:abc",
        workbench_generation=4,
        source_path="/source.json",
        runtime_path="/runtime.json",
        passes=(RecipePass("item-1", "jump-fixer", True, "{}"),),
    )


def _validation(*, satisfied: bool = True) -> RecipeValidation:
    return RecipeValidation("draft-1", 2, satisfied, (), "[]")


def _request(command: str) -> RecipeCommandRequest:
    return RecipeCommandRequest(
        command=command,
        draft_id="draft-1",
        draft_revision=2,
        function_ea=0x401000,
        expected_workbench_generation=4,
        function_fingerprint="sha256:abc",
    )


def test_apply_once_invokes_existing_lifecycle_exactly_once() -> None:
    current = True
    calls: list[PipelineRecipeDraft] = []
    service = WorkbenchRecipeCommandService(
        identity_is_current=lambda request: current,
    )

    result = service.execute_apply_once(
        _request("apply_recipe_once"),
        _draft(),
        _validation(),
        lifecycle=lambda draft: calls.append(draft) or True,
    )

    assert calls == [_draft()]
    assert result.status is OutcomeStatus.READY
    assert result.succeeded is True
    assert result.accepted is True
    assert result.refresh_requested is True


def test_save_invokes_persistence_exactly_once() -> None:
    calls: list[tuple[object, object]] = []
    service = WorkbenchRecipeCommandService(identity_is_current=lambda request: True)

    result = service.execute_save(
        _request("save_function_recipe"),
        _draft(),
        _validation(),
        persistence=lambda draft, validation: calls.append((draft, validation)),
    )

    assert calls == [(_draft(), _validation())]
    assert result.succeeded is True
    assert result.accepted is True
    assert result.refresh_requested is True


def test_stale_before_command_has_no_side_effects() -> None:
    calls: list[object] = []
    service = WorkbenchRecipeCommandService(identity_is_current=lambda request: False)

    result = service.execute_apply_once(
        _request("apply_recipe_once"),
        _draft(),
        _validation(),
        lifecycle=lambda draft: calls.append(draft) or True,
    )

    assert calls == []
    assert result.status is OutcomeStatus.STALE
    assert result.succeeded is False
    assert result.accepted is False


def test_stale_after_callback_rejects_result_without_repeating_callback() -> None:
    checks = iter((True, False))
    calls: list[object] = []
    service = WorkbenchRecipeCommandService(
        identity_is_current=lambda request: next(checks)
    )

    result = service.execute_save(
        _request("save_function_recipe"),
        _draft(),
        _validation(),
        persistence=lambda draft, validation: calls.append(draft),
    )

    assert calls == [_draft()]
    assert result.status is OutcomeStatus.STALE
    assert result.succeeded is True
    assert result.accepted is False
    assert result.refresh_requested is False


def test_mismatched_or_unvalidated_draft_is_rejected_before_callback() -> None:
    calls: list[object] = []
    service = WorkbenchRecipeCommandService(identity_is_current=lambda request: True)

    mismatch = service.execute_save(
        _request("save_function_recipe"),
        _draft(),
        RecipeValidation("draft-1", 1, True, (), "[]"),
        persistence=lambda draft, validation: calls.append(draft),
    )
    blocked = service.execute_save(
        _request("save_function_recipe"),
        _draft(),
        _validation(satisfied=False),
        persistence=lambda draft, validation: calls.append(draft),
    )

    assert calls == []
    assert mismatch.status is OutcomeStatus.FAILED
    assert blocked.status is OutcomeStatus.BLOCKED


def test_wrong_command_name_is_rejected_without_callback() -> None:
    calls: list[object] = []
    service = WorkbenchRecipeCommandService(identity_is_current=lambda request: True)

    result = service.execute_apply_once(
        _request("save_function_recipe"),
        _draft(),
        _validation(),
        lifecycle=lambda draft: calls.append(draft) or True,
    )

    assert calls == []
    assert result.status is OutcomeStatus.FAILED


def test_workbench_service_recipe_identity_check_uses_latest_collection_identity() -> None:
    service = WorkbenchService.__new__(WorkbenchService)
    service._generation = 4
    service._latest_function_ea = 0x401000
    service._latest_function_fingerprint = "sha256:abc"

    assert service.recipe_request_is_current(_request("apply_recipe_once")) is True
    assert service.recipe_request_is_current(
        RecipeCommandRequest(
            command="apply_recipe_once",
            draft_id="draft-1",
            draft_revision=2,
            function_ea=0x401000,
            expected_workbench_generation=3,
            function_fingerprint="sha256:abc",
        )
    ) is False
