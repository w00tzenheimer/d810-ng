"""Thin live-IDA command adapter for the registered-pass Recipe Composer."""

from __future__ import annotations

from types import SimpleNamespace

from d810.core.provider_phase import provider_phase_snapshot_from_level
from d810.manager.workbench_recipe_models import (
    PipelineRecipeDraft,
    RecipeCommandResult,
    RecipeValidation,
)
from d810.ui.workbench_recipe_logic import recipe_command_request


class WorkbenchRecipeAdapter:
    """Reacquire live pseudocode state and delegate recipe policy to services."""

    def __init__(
        self,
        state: object,
        idaapi_shim: object,
        ctx: object,
        snapshot: object,
    ) -> None:
        self._state = state
        self._idaapi = idaapi_shim
        self._ctx = ctx
        self._snapshot = snapshot
        original_widget = getattr(ctx, "widget", None)
        get_widget_vdui = getattr(idaapi_shim, "get_widget_vdui", None)
        vdui = get_widget_vdui(original_widget) if callable(get_widget_vdui) else None
        stable_widget = getattr(vdui, "ct", None) if vdui is not None else None
        self._widget = original_widget if stable_widget is None else stable_widget
        self._facts: object | None = None

    def _action_context(self) -> object:
        if self._widget is getattr(self._ctx, "widget", None):
            return self._ctx
        return SimpleNamespace(widget=self._widget)

    def _current_mba(self, function_ea: int) -> object:
        get_widget_vdui = getattr(self._idaapi, "get_widget_vdui", None)
        vdui = get_widget_vdui(self._widget) if callable(get_widget_vdui) else None
        cfunc = getattr(vdui, "cfunc", None) if vdui is not None else None
        if cfunc is None:
            raise RuntimeError("Recipe analysis requires current pseudocode")
        entry_ea = getattr(cfunc, "entry_ea", None)
        if entry_ea is None or int(entry_ea) != int(function_ea):
            raise RuntimeError(
                "Recipe pseudocode widget now shows a different function"
            )
        target = getattr(cfunc, "mba", None)
        if target is None:
            raise RuntimeError("Recipe analysis requires current microcode")
        return target

    def catalog(self) -> tuple[object, ...]:
        return tuple(self._state.get_workbench_recipe_catalog())

    def case(self) -> object | None:
        """Return the immutable case captured with this Recipe Composer session."""
        return getattr(self._snapshot, "case", None)

    def validate(self, draft: PipelineRecipeDraft) -> RecipeValidation:
        return self._state.validate_workbench_recipe(draft, facts=self._facts)

    def reset(self) -> tuple[PipelineRecipeDraft, RecipeValidation]:
        self._facts = None
        draft = self._state.create_workbench_recipe_draft(self._snapshot)
        return draft, self.validate(draft)

    def _edited(
        self, draft: PipelineRecipeDraft
    ) -> tuple[PipelineRecipeDraft, RecipeValidation]:
        return draft, self.validate(draft)

    def add_pass(
        self,
        draft: PipelineRecipeDraft,
        pass_id: str,
    ) -> tuple[PipelineRecipeDraft, RecipeValidation]:
        return self._edited(self._state.add_workbench_recipe_pass(draft, pass_id))

    def remove_pass(
        self,
        draft: PipelineRecipeDraft,
        item_id: str,
    ) -> tuple[PipelineRecipeDraft, RecipeValidation]:
        return self._edited(self._state.remove_workbench_recipe_pass(draft, item_id))

    def set_enabled(
        self,
        draft: PipelineRecipeDraft,
        item_id: str,
        enabled: bool,
    ) -> tuple[PipelineRecipeDraft, RecipeValidation]:
        return self._edited(
            self._state.set_workbench_recipe_pass_enabled(
                draft,
                item_id,
                enabled,
            )
        )

    def reorder_pass(
        self,
        draft: PipelineRecipeDraft,
        item_id: str,
        new_index: int,
    ) -> tuple[PipelineRecipeDraft, RecipeValidation]:
        return self._edited(
            self._state.reorder_workbench_recipe_pass(
                draft,
                item_id,
                new_index,
            )
        )

    def replace_options(
        self,
        draft: PipelineRecipeDraft,
        item_id: str,
        options: dict[str, object],
    ) -> tuple[PipelineRecipeDraft, RecipeValidation]:
        return self._edited(
            self._state.replace_workbench_recipe_pass_options(
                draft,
                item_id,
                options,
            )
        )

    def analyze(self, draft: PipelineRecipeDraft) -> RecipeValidation:
        target = self._current_mba(draft.function_ea)
        provider_level = getattr(target, "maturity", None)
        if provider_level is None:
            raise RuntimeError("Recipe analysis requires a current provider level")
        provider_phase = provider_phase_snapshot_from_level(
            int(provider_level),
            provider_name="hexrays_microcode",
        )
        self._facts = self._state.analyze_workbench_recipe(
            function_ea=draft.function_ea,
            target=target,
            provider_phase=provider_phase,
        )
        return self.validate(draft)

    def apply_once(
        self,
        draft: PipelineRecipeDraft,
        validation: RecipeValidation,
    ) -> RecipeCommandResult:
        def lifecycle(candidate: PipelineRecipeDraft) -> bool:
            from d810.ui.actions.deobfuscate_this import DeobfuscateThisFunction

            action = DeobfuscateThisFunction(
                self._state,
                ida_modules={"idaapi": self._idaapi},
            )
            return action.execute_with_recipe(self._action_context(), candidate) == 1

        return self._state.execute_workbench_apply_recipe_once(
            recipe_command_request(draft, "apply_recipe_once"),
            draft,
            validation,
            lifecycle=lifecycle,
        )

    def save_function(
        self,
        draft: PipelineRecipeDraft,
        validation: RecipeValidation,
    ) -> RecipeCommandResult:
        return self._state.execute_workbench_save_function_recipe(
            recipe_command_request(draft, "save_function_recipe"),
            draft,
            validation,
        )

    def is_current(self, draft: PipelineRecipeDraft) -> bool:
        return bool(
            self._state.workbench_recipe_request_is_current(
                recipe_command_request(draft, "recipe_status")
            )
        )

    def engine_started(self) -> bool:
        return bool(getattr(getattr(self._state, "manager", None), "started", False))


__all__ = ["WorkbenchRecipeAdapter"]
