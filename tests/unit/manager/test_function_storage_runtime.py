from __future__ import annotations

from d810.core.persistence import FunctionStorageLocator
from d810.core.registry import EventEmitter
from d810.core.execution_scope import ExecutionScopeEvent, ExecutionScopeInvalidation
from d810.core.function_storage_config import (
    FunctionRecipeStorageBackend,
    FunctionRecipeStorageConfig,
)
from d810.manager.function_storage_runtime import FunctionStorageRuntime


class _FakeStorage:
    def __init__(self):
        self._function_tags: dict[FunctionStorageLocator, set[str]] = {}
        self.closed = False

    def close(self) -> None:
        self.closed = True

    def get_function_tags(self, locator: FunctionStorageLocator) -> set[str]:
        return set(self._function_tags.get(locator, set()))

    def set_function_tags(
        self, locator: FunctionStorageLocator, tags: set[str]
    ) -> None:
        self._function_tags[locator] = set(tags)


def _build_runtime(
    storage: _FakeStorage,
    *,
    project_name: str = "proj",
    targets: list[tuple[object, str]] | None = None,
) -> FunctionStorageRuntime:
    emitter = EventEmitter()

    def _factory(target, *, backend: str = "sqlite"):
        if targets is not None:
            targets.append((target, backend))
        return storage

    return FunctionStorageRuntime(
        storage_factory=_factory,
        event_emitter=emitter,
        project_name_provider=lambda: project_name,
        database_identity_provider=lambda: "sample.i64",
    )


def test_initialize_sqlite_storage_uses_only_typed_configuration(tmp_path):
    storage = _FakeStorage()
    targets: list[tuple[object, str]] = []
    runtime = _build_runtime(storage, targets=targets)

    reloaded: list[ExecutionScopeInvalidation] = []
    runtime._event_emitter.on(
        ExecutionScopeEvent.IDB_METADATA_RELOADED,
        lambda payload: reloaded.append(payload),
    )
    database_path = (tmp_path / "recipes.db").resolve()
    runtime.initialize_storage(
        FunctionRecipeStorageConfig(
            FunctionRecipeStorageBackend.SQLITE,
            database_path,
        )
    )

    assert targets == [(database_path, "sqlite")]
    assert len(reloaded) == 1
    assert reloaded[0].reason == ExecutionScopeEvent.IDB_METADATA_RELOADED


def test_initialize_storage_defaults_to_idb_local_netnode() -> None:
    storage = _FakeStorage()
    targets: list[tuple[object, str]] = []
    runtime = _build_runtime(storage, targets=targets)

    runtime.initialize_storage(
        FunctionRecipeStorageConfig(FunctionRecipeStorageBackend.NETNODE, None)
    )

    assert targets == [("$ d810.optimization_storage", "netnode")]


def test_reconfigure_opens_replacement_before_closing_current_storage(tmp_path) -> None:
    first = _FakeStorage()
    second = _FakeStorage()
    calls: list[tuple[object, str, bool]] = []

    def factory(target, *, backend: str):
        calls.append((target, backend, first.closed))
        return first if len(calls) == 1 else second

    runtime = FunctionStorageRuntime(
        storage_factory=factory,
        event_emitter=EventEmitter(),
        project_name_provider=lambda: "proj",
        database_identity_provider=lambda: "sample.i64",
    )
    runtime.initialize_storage(
        FunctionRecipeStorageConfig(FunctionRecipeStorageBackend.NETNODE, None)
    )
    runtime.initialize_storage(
        FunctionRecipeStorageConfig(
            FunctionRecipeStorageBackend.SQLITE,
            (tmp_path / "recipes.sqlite3").resolve(),
        )
    )

    assert calls[1][2] is False
    assert first.closed is True
    assert second.closed is False
    assert runtime.storage is second


def test_failed_reconfiguration_keeps_current_storage() -> None:
    current = _FakeStorage()
    call_count = 0

    def factory(_target, *, backend: str):
        nonlocal call_count
        call_count += 1
        if call_count == 2:
            raise OSError(f"cannot open {backend}")
        return current

    runtime = FunctionStorageRuntime(
        storage_factory=factory,
        event_emitter=EventEmitter(),
        project_name_provider=lambda: "proj",
        database_identity_provider=lambda: "sample.i64",
    )
    runtime.initialize_storage(
        FunctionRecipeStorageConfig(FunctionRecipeStorageBackend.NETNODE, None)
    )
    runtime.initialize_storage(
        FunctionRecipeStorageConfig(FunctionRecipeStorageBackend.SQLITE, None)
    )

    assert current.closed is False
    assert runtime.storage is current


def test_scoped_tags_emit_function_invalidations():
    storage = _FakeStorage()
    runtime = _build_runtime(storage)
    runtime.storage = storage

    tags: list[ExecutionScopeInvalidation] = []
    runtime._event_emitter.on(
        ExecutionScopeEvent.FUNCTION_TAGS_UPDATED,
        lambda payload: tags.append(payload),
    )

    runtime.set_function_tags(function_addr=0x401000, tags={"flattened", ""})

    assert runtime.get_function_tags(0x401000) == {"flattened"}
    assert storage.get_function_tags(
        FunctionStorageLocator("sample.i64", "proj", 0x401000)
    ) == {"flattened"}
    assert tags[0].func_eas == frozenset({0x401000})
