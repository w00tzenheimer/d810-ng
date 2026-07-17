"""Thin command adapter for manager-owned config-v2 project editing."""

from __future__ import annotations

import pathlib
from collections.abc import Mapping, Sequence

from d810.manager.config_v2_edit_models import (
    ConfigV2ProjectDraft,
    ConfigV2ProjectValidation,
)
from d810.manager.workbench_recipe_models import PipelineRecipeDraft


class ConfigV2EditingAdapter:
    """Delegate typed edits and persistence to the current D810 state."""

    def __init__(
        self,
        state: object,
        *,
        destination: pathlib.Path,
        recipe: PipelineRecipeDraft | None = None,
    ) -> None:
        self._state = state
        self._destination = pathlib.Path(destination)
        self._recipe = recipe

    @property
    def destination(self) -> pathlib.Path:
        return self._destination

    def manifest(self) -> tuple[object, ...]:
        return tuple(self._state.get_config_v2_serializer_manifest())

    def catalog(self) -> tuple[object, ...]:
        return tuple(self._state.get_workbench_recipe_catalog())

    def validate(self, draft: ConfigV2ProjectDraft) -> ConfigV2ProjectValidation:
        return self._state.validate_config_v2_project_draft(draft)

    def reset(
        self,
    ) -> tuple[ConfigV2ProjectDraft, ConfigV2ProjectValidation]:
        draft = self._state.create_config_v2_project_draft(self._destination)
        if self._recipe is not None:
            draft = self._state.materialize_recipe_as_config_v2(
                draft,
                self._recipe,
            )
        return self._edited(draft)

    def _edited(
        self, draft: ConfigV2ProjectDraft
    ) -> tuple[ConfigV2ProjectDraft, ConfigV2ProjectValidation]:
        return draft, self.validate(draft)

    def set_description(
        self,
        draft: ConfigV2ProjectDraft,
        description: str,
    ) -> tuple[ConfigV2ProjectDraft, ConfigV2ProjectValidation]:
        return self._edited(self._state.set_config_v2_description(draft, description))

    def add_pass(
        self,
        draft: ConfigV2ProjectDraft,
        pass_id: str,
        *,
        index: int | None = None,
    ) -> tuple[ConfigV2ProjectDraft, ConfigV2ProjectValidation]:
        return self._edited(self._state.add_config_v2_pass(draft, pass_id, index=index))

    def remove_pass(
        self,
        draft: ConfigV2ProjectDraft,
        pass_index: int,
    ) -> tuple[ConfigV2ProjectDraft, ConfigV2ProjectValidation]:
        return self._edited(self._state.remove_config_v2_pass(draft, pass_index))

    def reorder_pass(
        self,
        draft: ConfigV2ProjectDraft,
        pass_index: int,
        new_index: int,
    ) -> tuple[ConfigV2ProjectDraft, ConfigV2ProjectValidation]:
        return self._edited(
            self._state.reorder_config_v2_pass(draft, pass_index, new_index)
        )

    def set_pass_rules(
        self,
        draft: ConfigV2ProjectDraft,
        *,
        pass_index: int,
        include: Sequence[str],
        exclude: Sequence[str],
        options: Mapping[str, object],
    ) -> tuple[ConfigV2ProjectDraft, ConfigV2ProjectValidation]:
        return self._edited(
            self._state.set_config_v2_pass_rules(
                draft,
                pass_index=pass_index,
                include=include,
                exclude=exclude,
                options=options,
            )
        )

    def set_routing_override(
        self,
        draft: ConfigV2ProjectDraft,
        *,
        prefer: Mapping[str, float],
        require: str | None,
        deny: Sequence[str],
    ) -> tuple[ConfigV2ProjectDraft, ConfigV2ProjectValidation]:
        return self._edited(
            self._state.set_config_v2_routing_override(
                draft,
                prefer=prefer,
                require=require,
                deny=deny,
            )
        )

    def save(
        self,
        draft: ConfigV2ProjectDraft,
        validation: ConfigV2ProjectValidation,
    ) -> object:
        return self._state.save_and_reload_config_v2_project(draft, validation)


__all__ = ["ConfigV2EditingAdapter"]
