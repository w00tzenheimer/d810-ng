from __future__ import annotations

import importlib
import importlib.util
from pathlib import Path

from d810.core.config import ProjectConfiguration


def _logic_module():
    spec = importlib.util.find_spec("d810.ui.project_picker_logic")
    if spec is None:
        return None
    return importlib.import_module("d810.ui.project_picker_logic")


def _project(filename: str, description: str = "") -> ProjectConfiguration:
    return ProjectConfiguration(path=Path("/configs") / filename, description=description)


def test_picker_entries_keep_project_indices_and_describe_canonical_projects() -> None:
    logic = _logic_module()
    assert logic is not None

    entries = logic.build_project_picker_entries(
        (
            _project("default_unflattening_ollvm.json", "OLLVM default"),
            _project("other.json", "standalone experiment"),
        )
    )

    assert [(entry.project_index, entry.filename) for entry in entries] == [
        (0, "default_unflattening_ollvm.json"),
        (1, "other.json"),
    ]
    assert entries[0].behavior == "Config v2 project"
    assert entries[1].behavior == "Config v2 project"


def test_picker_filter_matches_project_and_description_without_reindexing() -> None:
    logic = _logic_module()
    assert logic is not None
    entries = logic.build_project_picker_entries(
        (
            _project("default_unflattening_ollvm.json", "OLLVM default"),
            _project("other.json", "standalone experiment"),
        )
    )

    filtered = logic.filter_project_picker_entries(entries, "OLLVM")
    description = logic.filter_project_picker_entries(entries, "standalone")

    assert [(entry.project_index, entry.filename) for entry in filtered] == [
        (0, "default_unflattening_ollvm.json"),
    ]
    assert [(entry.project_index, entry.filename) for entry in description] == [
        (1, "other.json"),
    ]
