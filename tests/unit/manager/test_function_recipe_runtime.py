from __future__ import annotations

import ast
from types import SimpleNamespace
from pathlib import Path

import pytest

from d810.core.rule_scope import RuleScopeEvent, RuleScopeService, ScopeKey
from d810.manager.function_recipe_runtime import (
    FunctionRecipePersistenceError,
    FunctionRecipeRuntime,
)
from d810.manager.workbench_recipe_models import (
    PipelineRecipeDraft,
    RecipePass,
    RecipeValidation,
)


class _Storage:
    def __init__(self) -> None:
        self.recipe = None
        self.saved: list[dict[str, object]] = []
        self.cleared: list[int] = []
        self.function_rule_calls: list[object] = []

    def set_function_recipe(self, **kwargs: object) -> None:
        self.saved.append(dict(kwargs))
        self.recipe = SimpleNamespace(**kwargs, updated_at=12.5)

    def get_function_recipe(self, function_addr: int):
        if self.recipe is None or self.recipe.function_addr != function_addr:
            return None
        return self.recipe

    def clear_function_recipe(self, function_addr: int) -> None:
        self.cleared.append(function_addr)
        self.recipe = None

    def set_function_rules(self, *args: object, **kwargs: object) -> None:
        self.function_rule_calls.append((args, kwargs))


class _Emitter:
    def __init__(self) -> None:
        self.events: list[tuple[object, object]] = []

    def emit(self, event: object, payload: object) -> None:
        self.events.append((event, payload))


def _draft() -> PipelineRecipeDraft:
    return PipelineRecipeDraft(
        draft_id="draft-1",
        schema_version=1,
        revision=2,
        function_ea=0x401000,
        function_fingerprint="sha256:abc",
        workbench_generation=4,
        source_path="/source.json",
        runtime_path="/runtime.json",
        passes=(RecipePass("item-1", "jump-fixer", True, "{}"),),
    )


def _validation(*, satisfied: bool = True, revision: int = 2) -> RecipeValidation:
    return RecipeValidation(
        draft_id="draft-1",
        revision=revision,
        satisfied=satisfied,
        diagnostics=(),
        manifest_json="[]",
    )


def test_save_uses_sibling_storage_and_emits_one_function_scoped_invalidation() -> None:
    storage = _Storage()
    emitter = _Emitter()
    runtime = FunctionRecipeRuntime(
        storage_provider=lambda: storage,
        event_emitter=emitter,
        project_name_provider=lambda: "sample",
    )

    saved = runtime.save(
        _draft(),
        _validation(),
        pass_configs_json='[{"pass_id":"jump-fixer"}]\n',
    )

    assert saved.function_ea == 0x401000
    assert saved.updated_at == 12.5
    assert len(storage.saved) == 1
    assert storage.function_rule_calls == []
    assert len(emitter.events) == 1
    event, payload = emitter.events[0]
    assert event is RuleScopeEvent.FUNCTION_RECIPE_UPDATED
    assert payload.reason is RuleScopeEvent.FUNCTION_RECIPE_UPDATED
    assert payload.func_eas == frozenset({0x401000})


@pytest.mark.parametrize(
    "validation",
    (
        _validation(satisfied=False),
        _validation(revision=1),
        RecipeValidation("other", 2, True, (), "[]"),
    ),
)
def test_save_rejects_unvalidated_or_mismatched_draft(
    validation: RecipeValidation,
) -> None:
    storage = _Storage()
    runtime = FunctionRecipeRuntime(
        storage_provider=lambda: storage,
        event_emitter=_Emitter(),
        project_name_provider=lambda: "sample",
    )

    with pytest.raises(FunctionRecipePersistenceError):
        runtime.save(_draft(), validation, pass_configs_json="[]\n")

    assert storage.saved == []


def test_clear_removes_only_recipe_and_invalidates_once() -> None:
    storage = _Storage()
    emitter = _Emitter()
    runtime = FunctionRecipeRuntime(
        storage_provider=lambda: storage,
        event_emitter=emitter,
        project_name_provider=lambda: "sample",
    )
    runtime.save(_draft(), _validation(), pass_configs_json="[]\n")
    emitter.events.clear()

    assert runtime.clear(0x401000) is True

    assert storage.cleared == [0x401000]
    assert storage.function_rule_calls == []
    assert len(emitter.events) == 1


def test_recipe_event_uses_existing_function_scoped_cache_invalidation_path() -> None:
    service = RuleScopeService()
    service._caches.active_by_scope = {
        ScopeKey("sample", "idb", 0x401000, "flow"): object(),
        ScopeKey("sample", "idb", 0x402000, "flow"): object(),
    }

    service.invalidate(
        SimpleNamespace(
            reason=RuleScopeEvent.FUNCTION_RECIPE_UPDATED,
            func_eas=frozenset({0x401000}),
        )
    )

    assert {key.func_ea for key in service._caches.active_by_scope} == {0x402000}


def _method(path: Path, class_name: str, method_name: str) -> ast.FunctionDef:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name == method_name:
                    return item
    raise AssertionError(f"{class_name}.{method_name} not found")


def _calls(method: ast.FunctionDef) -> set[str]:
    return {
        node.func.attr if isinstance(node.func, ast.Attribute) else node.func.id
        for node in ast.walk(method)
        if isinstance(node, ast.Call)
        and isinstance(node.func, (ast.Attribute, ast.Name))
    }


def test_manager_owns_recipe_services_and_state_exposes_only_facades() -> None:
    root = Path(__file__).parents[3]
    manager_path = root / "src/d810/manager/manager.py"
    state_path = root / "src/d810/manager/state.py"

    post_init = _calls(_method(manager_path, "D810Manager", "__post_init__"))
    assert "RecipeService" in post_init
    assert "FunctionRecipeRuntime" in post_init
    assert "WorkbenchRecipeCommandService" in post_init
    assert "serialize_enabled_configs" in _calls(
        _method(manager_path, "D810Manager", "save_workbench_function_recipe")
    )
    assert "save" in _calls(
        _method(manager_path, "D810Manager", "save_workbench_function_recipe")
    )
    for method_name in (
        "get_workbench_recipe_catalog",
        "create_workbench_recipe_draft",
        "validate_workbench_recipe",
        "save_workbench_function_recipe",
        "clear_workbench_function_recipe",
        "execute_workbench_apply_recipe_once",
        "execute_workbench_save_function_recipe",
    ):
        assert method_name in _calls(_method(state_path, "D810State", method_name))
