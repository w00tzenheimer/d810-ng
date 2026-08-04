from __future__ import annotations

from d810.core.persistence import FunctionStorageLocator
from d810.core.registry import EventEmitter
from d810.core.rule_scope import RuleScopeEvent, RuleScopeInvalidation
from d810.manager.rule_scope_runtime import RuleScopeRuntime


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
) -> RuleScopeRuntime:
    emitter = EventEmitter()

    def _factory(target, *, backend: str = "sqlite"):
        if targets is not None:
            targets.append((target, backend))
        return storage

    return RuleScopeRuntime(
        storage_factory=_factory,
        event_emitter=emitter,
        project_name_provider=lambda: project_name,
        database_identity_provider=lambda: "sample.i64",
    )


def test_initialize_storage_emits_reload_without_persisted_operator_inference(tmp_path):
    storage = _FakeStorage()
    targets: list[tuple[object, str]] = []
    runtime = _build_runtime(storage, targets=targets)
    runtime.configure({"function_recipe_storage": tmp_path / "recipes.db"})

    reloaded: list[RuleScopeInvalidation] = []
    runtime._event_emitter.on(
        RuleScopeEvent.IDB_OVERLAY_RELOADED,
        lambda payload: reloaded.append(payload),
    )
    runtime.initialize_storage()

    assert targets == [(tmp_path / "recipes.db", "sqlite")]
    assert len(reloaded) == 1
    assert reloaded[0].reason == RuleScopeEvent.IDB_OVERLAY_RELOADED


def test_initialize_storage_defaults_to_idb_local_netnode() -> None:
    storage = _FakeStorage()
    targets: list[tuple[object, str]] = []
    runtime = _build_runtime(storage, targets=targets)

    runtime.initialize_storage()

    assert targets == [("$ d810.optimization_storage", "netnode")]


def test_explicit_sqlite_backend_requires_non_log_storage_path() -> None:
    storage = _FakeStorage()
    targets: list[tuple[object, str]] = []
    runtime = _build_runtime(storage, targets=targets)
    runtime.configure({"function_recipe_backend": "sqlite"})

    runtime.initialize_storage()

    assert targets == []
    assert runtime.storage is None


def test_scoped_tags_emit_function_invalidations():
    storage = _FakeStorage()
    runtime = _build_runtime(storage)
    runtime.storage = storage

    tags: list[RuleScopeInvalidation] = []
    runtime._event_emitter.on(
        RuleScopeEvent.FUNCTION_TAGS_UPDATED,
        lambda payload: tags.append(payload),
    )

    runtime.set_function_tags(function_addr=0x401000, tags={"flattened", ""})

    assert runtime.get_function_tags(0x401000) == {"flattened"}
    assert storage.get_function_tags(
        FunctionStorageLocator("sample.i64", "proj", 0x401000)
    ) == {"flattened"}
    assert tags[0].func_eas == frozenset({0x401000})
