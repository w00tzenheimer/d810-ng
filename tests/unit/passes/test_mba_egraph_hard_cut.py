"""The public config-v2 contract for the hard-cut Egglog pass rename."""

from __future__ import annotations

import pytest

from d810.manager.workbench_recipe_service import RecipeService
from d810.passes.operational_config_v2 import operational_config_v2_pass_registry
from d810.passes.pipeline_config_parser import pass_specs_from_project_config
from d810.passes.registry import UnknownPassIdError


def test_old_mba_egglog_config_is_rejected_as_unknown():
    with pytest.raises(UnknownPassIdError, match="unknown pass id: 'mba-egglog'"):
        pass_specs_from_project_config(
            {"pipeline_v2": [{"pass_id": "mba-egglog", "options": {}}]},
            operational_config_v2_pass_registry(),
        )


def test_egraph_editor_contract_exists_without_extension():
    catalog = RecipeService(operational_config_v2_pass_registry()).catalog()
    entry = next(item for item in catalog if item.pass_id == "mba-egraph")
    assert entry.editor_spec is not None
