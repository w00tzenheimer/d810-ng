"""The public config-v2 contract for the hard-cut e-graph pass name."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from d810.manager.workbench_recipe_service import RecipeService
from d810.passes.operational_config_v2 import operational_config_v2_pass_registry
from d810.passes.pipeline_config_parser import pass_specs_from_project_config
from d810.passes.registry import UnknownPassIdError


def test_legacy_config_fixture_is_rejected_as_unknown():
    fixture_dir = Path(__file__).resolve().parents[2] / "fixtures" / "mba_portfolio"
    fixtures = tuple(fixture_dir.glob("invalid-old-*.json"))
    assert len(fixtures) == 1
    fixture = fixtures[0]
    payload = json.loads(fixture.read_text(encoding="utf-8"))
    with pytest.raises(UnknownPassIdError):
        pass_specs_from_project_config(
            payload,
            operational_config_v2_pass_registry(),
        )


def test_egraph_editor_contract_exists_without_extension():
    catalog = RecipeService(operational_config_v2_pass_registry()).catalog()
    entry = next(item for item in catalog if item.pass_id == "mba-egraph")
    assert entry.editor_spec is not None
