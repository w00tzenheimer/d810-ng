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


def test_picker_entries_keep_project_indices_and_describe_present_v2_pairs() -> None:
    logic = _logic_module()
    assert logic is not None

    entries = logic.build_project_picker_entries(
        (
            _project("default_unflattening_ollvm.json", "OLLVM default"),
            _project("default_unflattening_ollvm_config_v2_canary.json"),
            _project("other.json", "standalone experiment"),
        )
    )

    assert [(entry.project_index, entry.filename) for entry in entries] == [
        (0, "default_unflattening_ollvm.json"),
        (1, "default_unflattening_ollvm_config_v2_canary.json"),
        (2, "other.json"),
    ]
    assert (
        entries[0].behavior
        == "Config v2 -> default_unflattening_ollvm_config_v2_canary.json"
    )
    assert entries[1].behavior == "Config v2 runtime (direct)"
    assert entries[2].behavior == "Direct project"


def test_picker_filter_matches_routing_and_description_without_reindexing() -> None:
    logic = _logic_module()
    assert logic is not None
    entries = logic.build_project_picker_entries(
        (
            _project("default_unflattening_ollvm.json", "OLLVM default"),
            _project("default_unflattening_ollvm_config_v2_canary.json"),
            _project("other.json", "standalone experiment"),
        )
    )

    routed = logic.filter_project_picker_entries(entries, "config v2 runtime")
    description = logic.filter_project_picker_entries(entries, "standalone")

    assert [(entry.project_index, entry.filename) for entry in routed] == [
        (0, "default_unflattening_ollvm.json"),
        (1, "default_unflattening_ollvm_config_v2_canary.json"),
    ]
    assert [(entry.project_index, entry.filename) for entry in description] == [
        (2, "other.json"),
    ]
