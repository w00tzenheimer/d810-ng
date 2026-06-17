from __future__ import annotations

from d810.core.persistence import ActiveRuleInferenceConfig, FunctionRuleConfig
from d810.core.registry import EventEmitter
from d810.core.rule_scope import RuleScopeEvent, RuleScopeInvalidation, RuleScopeService
from d810.manager.rule_scope_runtime import RuleScopeRuntime


class _FakeStorage:
    def __init__(self, inference: ActiveRuleInferenceConfig | None = None):
        self._function_rules: dict[int, FunctionRuleConfig] = {}
        self._function_tags: dict[int, set[str]] = {}
        self._active_inference = inference
        self.closed = False
        self.inference_set_count = 0
        self.inference_clear_count = 0

    def close(self) -> None:
        self.closed = True

    def set_function_rules(
        self,
        *,
        function_addr: int,
        enabled_rules: set[str] | None = None,
        disabled_rules: set[str] | None = None,
        notes: str = "",
    ) -> None:
        existing = self._function_rules.get(int(function_addr))
        self._function_rules[int(function_addr)] = FunctionRuleConfig(
            function_addr=int(function_addr),
            enabled_rules=set(enabled_rules or set()),
            disabled_rules=set(disabled_rules or set()),
            tags=set(existing.tags) if existing is not None else set(),
            notes=notes,
        )

    def get_function_rules(self, function_addr: int) -> FunctionRuleConfig | None:
        return self._function_rules.get(int(function_addr))

    def clear_function_rules(self, function_addr: int) -> None:
        self._function_rules.pop(int(function_addr), None)

    def get_function_tags(self, function_addr: int) -> set[str]:
        return set(self._function_tags.get(int(function_addr), set()))

    def set_function_tags(self, function_addr: int, tags: set[str]) -> None:
        self._function_tags[int(function_addr)] = set(tags)

    def set_active_rule_inference(self, inference: ActiveRuleInferenceConfig) -> None:
        self._active_inference = inference
        self.inference_set_count += 1

    def get_active_rule_inference(self) -> ActiveRuleInferenceConfig | None:
        return self._active_inference

    def clear_active_rule_inference(self) -> None:
        self._active_inference = None
        self.inference_clear_count += 1


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
        rule_scope_service=RuleScopeService(),
        event_emitter=emitter,
        log_dir=".",
        project_name_provider=lambda: project_name,
    )


def test_initialize_storage_loads_persisted_inference_and_emits_events(tmp_path):
    persisted = ActiveRuleInferenceConfig(
        name="persisted",
        enabled_rules={"RuleA"},
        disabled_rules={"RuleB"},
        target_func_eas={0x401000},
        target_tags_any={"flattened"},
        target_tags_all={"dispatcher"},
        notes="stored",
    )
    storage = _FakeStorage(persisted)
    targets: list[tuple[object, str]] = []
    runtime = _build_runtime(storage, targets=targets)
    runtime.configure({"function_rules_storage": tmp_path / "rules.db"})

    reloaded: list[RuleScopeInvalidation] = []
    applied: list[RuleScopeInvalidation] = []
    runtime._event_emitter.on(
        RuleScopeEvent.IDB_OVERLAY_RELOADED,
        lambda payload: reloaded.append(payload),
    )
    runtime._event_emitter.on(
        RuleScopeEvent.INFERENCE_APPLIED,
        lambda payload: applied.append(payload),
    )

    runtime.initialize_storage()

    assert targets == [(tmp_path / "rules.db", "sqlite")]
    active = runtime.get_active_rule_inference()
    assert active is not None
    assert active.name == "persisted"
    assert active.enabled_rules == frozenset({"RuleA"})
    assert active.disabled_rules == frozenset({"RuleB"})
    assert len(applied) == 1
    assert applied[0].changed_rules == frozenset({"RuleA", "RuleB"})
    assert len(reloaded) == 1
    assert reloaded[0].reason == RuleScopeEvent.IDB_OVERLAY_RELOADED


def test_set_function_rules_and_tags_emit_function_invalidations():
    storage = _FakeStorage()
    runtime = _build_runtime(storage)
    runtime.storage = storage

    overrides: list[RuleScopeInvalidation] = []
    tags: list[RuleScopeInvalidation] = []
    runtime._event_emitter.on(
        RuleScopeEvent.FUNCTION_OVERRIDE_UPDATED,
        lambda payload: overrides.append(payload),
    )
    runtime._event_emitter.on(
        RuleScopeEvent.FUNCTION_TAGS_UPDATED,
        lambda payload: tags.append(payload),
    )

    runtime.set_function_rule_override(
        function_addr=0x401000,
        enabled_rules={"RuleA"},
        disabled_rules={"RuleB"},
        notes="manual",
    )
    runtime.set_function_tags(function_addr=0x401000, tags={"flattened", ""})

    stored = storage.get_function_rules(0x401000)
    assert stored is not None
    assert stored.enabled_rules == {"RuleA"}
    assert stored.disabled_rules == {"RuleB"}
    assert stored.notes == "manual"
    assert runtime.get_function_tags(0x401000) == {"flattened"}
    assert overrides[0].func_eas == frozenset({0x401000})
    assert overrides[0].changed_rules == frozenset({"RuleA", "RuleB"})
    assert tags[0].func_eas == frozenset({0x401000})


def test_active_rule_inference_persists_and_clears():
    storage = _FakeStorage()
    runtime = _build_runtime(storage)
    runtime.storage = storage

    applied: list[RuleScopeInvalidation] = []
    cleared: list[RuleScopeInvalidation] = []
    runtime._event_emitter.on(
        RuleScopeEvent.INFERENCE_APPLIED,
        lambda payload: applied.append(payload),
    )
    runtime._event_emitter.on(
        RuleScopeEvent.INFERENCE_CLEARED,
        lambda payload: cleared.append(payload),
    )

    runtime.set_active_rule_inference(
        inference_name="focused",
        enabled_rules={"RuleA"},
        disabled_rules={"RuleB"},
        target_func_eas={0x401000},
        target_tags_any={"flattened"},
    )

    active = runtime.get_active_rule_inference()
    assert active is not None
    assert active.name == "focused"
    assert active.target_func_eas == frozenset({0x401000})
    assert storage.inference_set_count == 1
    assert applied[0].changed_rules == frozenset({"RuleA", "RuleB"})

    runtime.clear_active_rule_inference()

    assert runtime.get_active_rule_inference() is None
    assert storage.inference_clear_count == 1
    assert cleared[0].reason == RuleScopeEvent.INFERENCE_CLEARED
