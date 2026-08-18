from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
FORBIDDEN_CONFIG_KEYS = {
    "rules",
    "legacy_rule",
    "legacy_rule_options",
    "native_pipeline",
}
FORBIDDEN_PUBLIC_COPY = {
    "Rule scope",
    "Pass rule selection",
    "unknown/stale rule names",
}


def _walk(value: object):
    yield value
    if isinstance(value, dict):
        for key, child in value.items():
            yield key
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


def test_bundled_projects_use_only_strict_pass_and_transform_keys() -> None:
    bundled_projects = tuple(sorted((ROOT / "src/d810/conf").glob("*.json")))
    canonical_projects = []
    for path in bundled_projects:
        document = json.loads(path.read_text(encoding="utf-8"))
        additional = document.get("additional_configuration", {})
        pipeline = additional.get("pipeline_v2") if isinstance(additional, dict) else None
        if pipeline is None:
            continue
        canonical_projects.append(path)
        for entry in pipeline:
            found = FORBIDDEN_CONFIG_KEYS.intersection(
                value for value in _walk(entry) if isinstance(value, str)
            )
            assert not found, f"{path.name} contains former config keys: {found}"
            assert "pass_id" in entry
            assert "pass" not in entry
    assert canonical_projects


def test_recipe_models_do_not_serialize_private_implementation_selection() -> None:
    paths = (
        ROOT / "src/d810/manager/workbench_recipe_models.py",
        ROOT / "src/d810/manager/config_v2_edit_models.py",
        ROOT / "src/d810/core/function_recipe.py",
    )
    source = "\n".join(
        path.read_text(encoding="utf-8") for path in paths if path.is_file()
    )
    for forbidden in (
        "enabled_rule_names",
        "instruction_rule_names",
        "block_rule_names",
        "FunctionRuleConfig",
    ):
        assert forbidden not in source


def test_user_facing_ui_uses_pass_stage_transform_vocabulary() -> None:
    paths = (
        ROOT / "src/d810/ui/ida_ui.py",
        ROOT / "src/d810/ui/pass_tree.py",
        ROOT / "src/d810/ui/project_config_logic.py",
        ROOT / "src/d810/ui/workbench_logic.py",
        ROOT / "src/d810/ui/workbench_recipe_panel.py",
    )
    source = "\n".join(path.read_text(encoding="utf-8") for path in paths)
    for forbidden in FORBIDDEN_PUBLIC_COPY:
        assert forbidden not in source
    assert "Effective execution" in source
    assert "Pass pipeline" in source
    assert "Transform:" in source
    assert "Stage:" in source


def test_manager_runtime_has_no_legacy_project_save_command() -> None:
    paths = (
        ROOT / "src/d810/manager/state.py",
        ROOT / "src/d810/manager/project_runtime.py",
        ROOT / "src/d810/core/project_config_persistence.py",
    )
    source = "\n".join(path.read_text(encoding="utf-8") for path in paths)
    assert "save_legacy_project" not in source
