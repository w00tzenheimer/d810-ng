"""Runtime tests for manager-level execution-scope lifecycle."""

from __future__ import annotations

import contextlib
from pathlib import Path

from d810.core.persistence import FunctionStorageLocator
from d810.core.execution_scope import ExecutionScopeEvent, ExecutionScopeInvalidation
from d810.manager import D810Manager


class _FakeStorage:
    def __init__(self):
        self._function_tags: dict[FunctionStorageLocator, set[str]] = {}

    def close(self) -> None:
        return

    def get_function_tags(self, locator: FunctionStorageLocator) -> set[str]:
        return set(self._function_tags.get(locator, set()))

    def set_function_tags(
        self, locator: FunctionStorageLocator, tags: set[str]
    ) -> None:
        self._function_tags[locator] = set(tags)


def _build_manager() -> D810Manager:
    manager = D810Manager(Path("."))
    manager.configure(project_name="proj", idb_key="idb")
    return manager


@contextlib.contextmanager
def _managed_manager():
    manager = _build_manager()
    try:
        yield manager
    finally:
        manager.stop()


def test_set_function_tags_emits_function_level_invalidation():
    with _managed_manager() as manager:
        fake_storage = _FakeStorage()
        manager.storage = fake_storage

        captured: list[ExecutionScopeInvalidation] = []
        manager.event_emitter.on(
            ExecutionScopeEvent.FUNCTION_TAGS_UPDATED,
            lambda payload: captured.append(payload),
        )

        manager.set_function_tags(
            function_addr=0x401000, tags={"flattened", "dispatcher"}
        )

        locator = FunctionStorageLocator("idb", "proj", 0x401000)
        assert fake_storage.get_function_tags(locator) == {"flattened", "dispatcher"}
        assert len(captured) == 1
        assert captured[0].reason == ExecutionScopeEvent.FUNCTION_TAGS_UPDATED
        assert captured[0].func_eas == frozenset({0x401000})
