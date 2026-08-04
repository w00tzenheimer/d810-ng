from __future__ import annotations

from pathlib import Path

from d810.core.persistence import (
    FunctionStorageLocator,
    NetnodeOptimizationStorage,
    SQLiteOptimizationStorage,
)


_RECIPE_JSON = '[{"options":{"legacy_rule":"JumpFixer"},"pass_id":"jump-fixer"}]\n'


_FIRST = FunctionStorageLocator("first.i64", "sample", 0x401000)
_SECOND = FunctionStorageLocator("second.i64", "sample", 0x401000)


def _save(storage: object, locator: FunctionStorageLocator, fingerprint: str) -> None:
    storage.set_function_tags(locator, {locator.database_identity})
    storage.set_function_recipe(
        locator=locator,
        schema_version=1,
        function_fingerprint=fingerprint,
        source_path=f"/{locator.database_identity}/source.json",
        runtime_path=f"/{locator.database_identity}/runtime.json",
        pass_configs_json=_RECIPE_JSON,
    )


def _assert_round_trip(storage: object) -> None:
    assert storage.get_function_recipe(_FIRST) is None

    _save(storage, _FIRST, "sha256:first")
    _save(storage, _SECOND, "sha256:second")

    first = storage.get_function_recipe(_FIRST)
    second = storage.get_function_recipe(_SECOND)
    assert first is not None
    assert second is not None
    assert first.locator == _FIRST
    assert second.locator == _SECOND
    assert first.function_fingerprint == "sha256:first"
    assert second.function_fingerprint == "sha256:second"
    assert first.source_path == "/first.i64/source.json"
    assert second.source_path == "/second.i64/source.json"
    assert first.pass_configs_json == _RECIPE_JSON
    assert first.updated_at > 0
    assert storage.get_function_tags(_FIRST) == {"first.i64"}
    assert storage.get_function_tags(_SECOND) == {"second.i64"}

    storage.clear_function_recipe(_FIRST)

    assert storage.get_function_recipe(_FIRST) is None
    assert storage.get_function_recipe(_SECOND) == second


def test_sqlite_function_recipes_are_scoped(tmp_path: Path) -> None:
    storage = SQLiteOptimizationStorage(tmp_path / "recipes.db")
    try:
        _assert_round_trip(storage)
        tables = {
            str(row[0])
            for row in storage.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        assert "function_recipes_v2" in tables
        assert "function_tags_v2" in tables
    finally:
        storage.close()


def test_netnode_function_recipes_are_scoped() -> None:
    storage = NetnodeOptimizationStorage.__new__(NetnodeOptimizationStorage)
    storage._state = {
        "functions": {},
        "results": {},
        "patches": {},
        "function_tags_v2": {},
        "function_recipes_v2": {},
    }
    storage._flush_state = lambda: None

    _assert_round_trip(storage)


def test_netnode_legacy_private_rule_state_is_discarded() -> None:
    storage = NetnodeOptimizationStorage.__new__(NetnodeOptimizationStorage)

    migrated = storage._deserialize(
        {
            "functions": {},
            "results": {},
            "patches": {},
            "function_rules": {},
        }
    )

    assert migrated["function_tags_v2"] == {}
    assert migrated["function_recipes_v2"] == {}
    assert "function_rules" not in migrated
    assert "active_inference" not in migrated
