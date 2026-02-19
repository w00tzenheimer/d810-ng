"""System/runtime tests for deterministic project resolution in test runner."""

from __future__ import annotations

import pathlib
from types import SimpleNamespace

import pytest

import d810.testing.runner as runner


class _FakeProjectManager:
    def __init__(self, current_path: pathlib.Path | None, index_value: int = 0):
        self._index_value = index_value
        self.current_path = current_path
        self.updated: tuple[str, object] | None = None
        self.added: tuple[str, object] | None = None

    def index(self, _name: str) -> int:
        return self._index_value

    def get(self, _name: str):
        if self.current_path is None:
            raise KeyError("missing")
        return SimpleNamespace(path=self.current_path)

    def update(self, name: str, project: object) -> None:
        self.updated = (name, project)

    def add(self, project: object) -> None:
        self.added = ("add", project)


def test_resolve_test_project_index_updates_user_override():
    state = SimpleNamespace(
        project_manager=_FakeProjectManager(
            current_path=pathlib.Path("/tmp/user/default_instruction_only.json"),
            index_value=7,
        )
    )

    idx = runner._resolve_test_project_index(state, "default_instruction_only.json")

    assert idx == 7
    assert state.project_manager.updated is not None
    updated_name, updated_project = state.project_manager.updated
    assert updated_name == "default_instruction_only.json"
    assert pathlib.Path(updated_project.path).name == "default_instruction_only.json"
    assert "src/d810/conf" in str(updated_project.path)


def test_resolve_test_project_index_falls_back_for_unknown_project():
    state = SimpleNamespace(
        project_manager=_FakeProjectManager(
            current_path=pathlib.Path("/tmp/user/custom.json"),
            index_value=3,
        )
    )

    idx = runner._resolve_test_project_index(state, "custom_project_that_does_not_exist.json")

    assert idx == 3
    assert state.project_manager.updated is None
    assert state.project_manager.added is None
