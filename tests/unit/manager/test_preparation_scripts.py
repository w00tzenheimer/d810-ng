from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from d810.core.config import ProjectConfiguration
from d810.manager.preparation_scripts import (
    PreparationScriptConfigurationError,
    PreparationScriptRegistry,
)
from d810.manager.project_runtime import build_project_runtime_snapshot
from d810.passes.pipeline_v2_hook_bridge import pipeline_v2_hook_activation

pytestmark = pytest.mark.pure_python


def _script(
    path: Path, source: str = "preparation.note_function(function_ea)\n"
) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    return path


def test_relative_script_path_resolves_from_project_directory(tmp_path: Path) -> None:
    project = tmp_path / "configs" / "profile.json"
    script = _script(tmp_path / "configs" / "scripts" / "normalize.py")

    registry = PreparationScriptRegistry.from_project(
        project,
        {
            "pre_hexrays": {
                "scripts": [
                    {
                        "id": "normalize",
                        "path": "scripts/normalize.py",
                        "enabled": True,
                    }
                ]
            }
        },
    )

    descriptor = registry.require("normalize")
    assert descriptor.path == str(script.resolve())
    assert descriptor.portable is True
    assert descriptor.source_sha256 == hashlib.sha256(script.read_bytes()).hexdigest()


def test_absolute_script_path_is_explicitly_nonportable(tmp_path: Path) -> None:
    script = _script(tmp_path / "normalize.py")

    registry = PreparationScriptRegistry.from_project(
        tmp_path / "profile.json",
        {
            "pre_hexrays": {
                "scripts": [{"id": "normalize", "path": str(script), "enabled": True}]
            }
        },
    )

    assert registry.require("normalize").portable is False


def test_registry_preserves_configuration_order_and_disabled_entries(
    tmp_path: Path,
) -> None:
    _script(tmp_path / "first.py")
    _script(tmp_path / "second.py")

    registry = PreparationScriptRegistry.from_project(
        tmp_path / "profile.json",
        {
            "pre_hexrays": {
                "scripts": [
                    {"id": "first", "path": "first.py", "enabled": False},
                    {"id": "second", "path": "second.py", "enabled": True},
                ]
            }
        },
    )

    assert tuple(item.script_id for item in registry.descriptors) == (
        "first",
        "second",
    )
    assert tuple(item.script_id for item in registry.enabled_descriptors) == ("second",)


@pytest.mark.parametrize(
    ("entries", "message"),
    [
        (
            [
                {"id": "same", "path": "first.py", "enabled": True},
                {"id": "same", "path": "second.py", "enabled": True},
            ],
            "duplicate script id",
        ),
        (
            [{"id": "../bad", "path": "first.py", "enabled": True}],
            "stable identifier",
        ),
        (
            [{"id": "first", "path": "first.txt", "enabled": True}],
            "must end in .py",
        ),
    ],
)
def test_registry_rejects_invalid_entries(
    tmp_path: Path, entries: list[dict[str, object]], message: str
) -> None:
    _script(tmp_path / "first.py")
    _script(tmp_path / "second.py")
    (tmp_path / "first.txt").write_text("ignored", encoding="utf-8")

    with pytest.raises(PreparationScriptConfigurationError, match=message):
        PreparationScriptRegistry.from_project(
            tmp_path / "profile.json",
            {"pre_hexrays": {"scripts": entries}},
        )


def test_project_runtime_projects_attested_preparation_scripts(tmp_path: Path) -> None:
    script = _script(tmp_path / "scripts" / "normalize.py")
    project = ProjectConfiguration(
        path=tmp_path / "profile.json",
        additional_configuration={
            "pre_hexrays": {
                "scripts": [
                    {
                        "id": "normalize",
                        "path": "scripts/normalize.py",
                        "enabled": True,
                    }
                ]
            }
        },
    )

    snapshot = build_project_runtime_snapshot(
        source_project=project,
        runtime_project=project,
        default_selection=None,
        hook_activation=pipeline_v2_hook_activation(project),
        hook_mode=None,
    )

    assert len(snapshot.preparation_scripts) == 1
    assert snapshot.preparation_scripts[0].path == str(script.resolve())
