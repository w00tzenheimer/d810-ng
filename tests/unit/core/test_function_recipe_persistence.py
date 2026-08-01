from __future__ import annotations

from pathlib import Path

from d810.core.persistence import (
    NetnodeOptimizationStorage,
    SQLiteOptimizationStorage,
)


_RECIPE_JSON = (
    '[{"options":{"legacy_rule":"JumpFixer"},"pass_id":"jump-fixer"}]\n'
)


def _assert_round_trip(storage: object) -> None:
    assert storage.get_function_recipe(0x401000) is None

    storage.set_function_rules(
        0x401000,
        enabled_rules={"ExistingRule"},
        disabled_rules={"OtherRule"},
        notes="keep me",
    )
    storage.set_function_tags(0x401000, {"tagged"})
    storage.set_function_recipe(
        function_addr=0x401000,
        schema_version=1,
        function_fingerprint="sha256:abc",
        source_path="/source.json",
        runtime_path="/runtime.json",
        pass_configs_json=_RECIPE_JSON,
    )

    recipe = storage.get_function_recipe(0x401000)
    rules = storage.get_function_rules(0x401000)
    assert recipe is not None
    assert recipe.function_addr == 0x401000
    assert recipe.schema_version == 1
    assert recipe.function_fingerprint == "sha256:abc"
    assert recipe.source_path == "/source.json"
    assert recipe.runtime_path == "/runtime.json"
    assert recipe.pass_configs_json == _RECIPE_JSON
    assert recipe.updated_at > 0
    assert rules is not None
    assert rules.enabled_rules == {"ExistingRule"}
    assert rules.disabled_rules == {"OtherRule"}
    assert rules.tags == {"tagged"}
    assert rules.notes == "keep me"

    storage.clear_function_recipe(0x401000)

    assert storage.get_function_recipe(0x401000) is None
    assert storage.get_function_rules(0x401000) == rules


def test_sqlite_function_recipe_is_sibling_to_function_rules(tmp_path: Path) -> None:
    storage = SQLiteOptimizationStorage(tmp_path / "recipes.db")
    try:
        _assert_round_trip(storage)
        tables = {
            str(row[0])
            for row in storage.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        assert "function_recipes" in tables
    finally:
        storage.close()


def test_netnode_function_recipe_is_sibling_to_function_rules() -> None:
    storage = NetnodeOptimizationStorage.__new__(NetnodeOptimizationStorage)
    storage._state = {
        "functions": {},
        "results": {},
        "patches": {},
        "function_rules": {},
        "function_recipes": {},
        "active_inference": None,
    }
    storage._flush_state = lambda: None

    _assert_round_trip(storage)


def test_netnode_legacy_state_migrates_empty_recipe_map() -> None:
    storage = NetnodeOptimizationStorage.__new__(NetnodeOptimizationStorage)

    migrated = storage._deserialize(
        {
            "functions": {},
            "results": {},
            "patches": {},
            "function_rules": {},
        }
    )

    assert migrated["function_recipes"] == {}
