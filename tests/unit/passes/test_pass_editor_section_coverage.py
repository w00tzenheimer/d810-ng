"""Operational config-v2 registrations expose complete editor sections."""

from __future__ import annotations

import json

from d810.core.pass_editor_spec import PassEditorKind, PassEditorSectionPresentation
from d810.manager.workbench_recipe_service import RecipeService
from d810.passes.operational_config_v2 import operational_config_v2_pass_registry


def _operational_catalog():
    return RecipeService(operational_config_v2_pass_registry()).catalog()


def test_every_operational_editor_field_is_in_exactly_one_section() -> None:
    for entry in _operational_catalog():
        field_ids = {field.field_id for field in entry.editor_spec.fields}
        sectioned_ids = {
            field_id
            for section in entry.editor_spec.sections
            for field_id in section.field_ids
        }

        assert sectioned_ids == field_ids, entry.pass_id
        assert all(section.field_ids for section in entry.editor_spec.sections), entry.pass_id


def test_operational_editor_defaults_match_registered_templates() -> None:
    for entry in _operational_catalog():
        assert entry.editor_spec.default_options() == json.loads(
            entry.option_template_json
        ), entry.pass_id


def test_operational_editor_sections_have_one_primary_and_catalog_secondaries() -> None:
    for entry in _operational_catalog():
        sections = entry.editor_spec.sections
        assert sum(
            section.presentation is PassEditorSectionPresentation.PRIMARY
            for section in sections
        ) <= 1, entry.pass_id

        if entry.editor_spec.kind in {
            PassEditorKind.RULE_CATALOG,
            PassEditorKind.TRANSFORM_CATALOG,
        }:
            assert all(
                section.presentation is PassEditorSectionPresentation.SECONDARY
                for section in sections
            ), entry.pass_id
