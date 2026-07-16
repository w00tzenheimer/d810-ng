"""Storage-backed function recipe persistence and scoped invalidation."""

from __future__ import annotations

from collections.abc import Callable

from d810.core.rule_scope import (
    RuleScopeEvent,
    RuleScopeInvalidation,
)
from d810.manager.workbench_recipe_models import (
    FunctionPipelineOverride,
    PipelineRecipeDraft,
    RecipeValidation,
)


class FunctionRecipePersistenceError(RuntimeError):
    """A recipe was unavailable or had not passed exact-draft validation."""


class FunctionRecipeRuntime:
    """Persist full function recipes without touching function-rule records."""

    def __init__(
        self,
        *,
        storage_provider: Callable[[], object | None],
        event_emitter: object,
        project_name_provider: Callable[[], str],
    ) -> None:
        self._storage_provider = storage_provider
        self._event_emitter = event_emitter
        self._project_name_provider = project_name_provider

    def _storage(self) -> object:
        storage = self._storage_provider()
        if storage is None:
            raise FunctionRecipePersistenceError(
                "Function recipe storage is unavailable"
            )
        return storage

    @staticmethod
    def _override(persisted: object) -> FunctionPipelineOverride:
        return FunctionPipelineOverride(
            schema_version=int(getattr(persisted, "schema_version")),
            function_ea=int(getattr(persisted, "function_addr")),
            function_fingerprint=getattr(persisted, "function_fingerprint", None),
            source_path=str(getattr(persisted, "source_path")),
            runtime_path=str(getattr(persisted, "runtime_path")),
            pass_configs_json=str(getattr(persisted, "pass_configs_json")),
            updated_at=float(getattr(persisted, "updated_at")),
        )

    def _emit_invalidation(self, function_ea: int) -> None:
        event = RuleScopeEvent.FUNCTION_RECIPE_UPDATED
        self._event_emitter.emit(
            event,
            RuleScopeInvalidation(
                reason=event,
                project_name=str(self._project_name_provider()),
                func_eas=frozenset({int(function_ea)}),
                changed_rules=frozenset(),
            ),
        )

    def get(self, function_ea: int) -> FunctionPipelineOverride | None:
        persisted = self._storage().get_function_recipe(int(function_ea))
        if persisted is None:
            return None
        return self._override(persisted)

    def save(
        self,
        draft: PipelineRecipeDraft,
        validation: RecipeValidation,
        *,
        pass_configs_json: str,
    ) -> FunctionPipelineOverride:
        if not validation.satisfied:
            raise FunctionRecipePersistenceError(
                "Function recipe cannot be saved until validation succeeds"
            )
        if (
            validation.draft_id != draft.draft_id
            or validation.revision != draft.revision
        ):
            raise FunctionRecipePersistenceError(
                "Recipe validation does not describe the current draft revision"
            )
        storage = self._storage()
        storage.set_function_recipe(
            function_addr=draft.function_ea,
            schema_version=draft.schema_version,
            function_fingerprint=draft.function_fingerprint,
            source_path=draft.source_path,
            runtime_path=draft.runtime_path,
            pass_configs_json=str(pass_configs_json),
        )
        persisted = storage.get_function_recipe(draft.function_ea)
        if persisted is None:
            raise FunctionRecipePersistenceError(
                "Function recipe storage did not return the saved record"
            )
        self._emit_invalidation(draft.function_ea)
        return self._override(persisted)

    def clear(self, function_ea: int) -> bool:
        storage = self._storage()
        if storage.get_function_recipe(int(function_ea)) is None:
            return False
        storage.clear_function_recipe(int(function_ea))
        self._emit_invalidation(function_ea)
        return True


__all__ = ["FunctionRecipePersistenceError", "FunctionRecipeRuntime"]
