"""Runtime tests for manager-level rule-scope event emission and lifecycle."""

from __future__ import annotations

from pathlib import Path

import tempfile

from d810.core.persistence import ActiveRuleInferenceConfig, create_optimization_storage
from d810.core.rule_scope import RuleScopeEvent, RuleScopeInvalidation
from d810.manager import D810Manager


class _FakeStorage:
    def __init__(self, inference: ActiveRuleInferenceConfig | None = None):
        self._function_tags: dict[int, set[str]] = {}
        self._active_inference = inference
        self.inference_set_count = 0
        self.inference_clear_count = 0

    def close(self) -> None:
        return

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



def _build_manager() -> D810Manager:
    manager = D810Manager(Path("."))
    manager.configure(project_name="proj", idb_key="idb")
    return manager


def test_set_function_tags_emits_function_level_invalidation():
    manager = _build_manager()
    fake_storage = _FakeStorage()
    manager.storage = fake_storage

    captured: list[RuleScopeInvalidation] = []
    manager.event_emitter.on(
        RuleScopeEvent.FUNCTION_TAGS_UPDATED,
        lambda payload: captured.append(payload),
    )

    manager.set_function_tags(function_addr=0x401000, tags={"flattened", "dispatcher"})

    assert fake_storage.get_function_tags(0x401000) == {"flattened", "dispatcher"}
    assert len(captured) == 1
    assert captured[0].reason == RuleScopeEvent.FUNCTION_TAGS_UPDATED
    assert captured[0].func_eas == frozenset({0x401000})


def test_inference_apply_and_clear_emit_events_and_persist():
    manager = _build_manager()
    fake_storage = _FakeStorage()
    manager.storage = fake_storage

    applied: list[RuleScopeInvalidation] = []
    cleared: list[RuleScopeInvalidation] = []
    manager.event_emitter.on(RuleScopeEvent.INFERENCE_APPLIED, lambda payload: applied.append(payload))
    manager.event_emitter.on(RuleScopeEvent.INFERENCE_CLEARED, lambda payload: cleared.append(payload))

    manager.set_active_rule_inference(
        inference_name="focused_inference",
        enabled_rules={"RuleA", "RuleB"},
        disabled_rules={"RuleC"},
        target_func_eas={0x401000},
        target_tags_any={"flattened"},
        notes="runtime test",
    )

    active = manager.get_active_rule_inference()
    assert active is not None
    assert active.name == "focused_inference"
    assert active.enabled_rules == frozenset({"RuleA", "RuleB"})
    assert active.disabled_rules == frozenset({"RuleC"})
    assert fake_storage.inference_set_count == 1
    assert len(applied) == 1
    assert applied[0].changed_rules == frozenset({"RuleA", "RuleB", "RuleC"})

    manager.clear_active_rule_inference()

    assert manager.get_active_rule_inference() is None
    assert fake_storage.inference_clear_count == 1
    assert len(cleared) == 1
    assert cleared[0].reason == RuleScopeEvent.INFERENCE_CLEARED


def test_init_storage_loads_persisted_inference_and_emits_events():
    persisted = ActiveRuleInferenceConfig(
        name="persisted_inference",
        enabled_rules={"RuleA"},
        disabled_rules={"RuleB"},
        target_func_eas={0x402000},
        target_tags_any={"dispatcher"},
        target_tags_all={"flattened"},
        notes="persisted",
    )

    with tempfile.TemporaryDirectory() as tmp:
        db_path = Path(tmp) / "test_rules.db"

        # Pre-seed a real SQLite storage with the persisted inference.
        seed = create_optimization_storage(db_path)
        seed.set_active_rule_inference(persisted)
        seed.close()

        manager = _build_manager()
        # Point _init_storage at our pre-seeded DB.
        manager.config["function_rules_storage"] = db_path
        manager.storage = None
        manager.rule_scope_service.attach(manager.event_emitter)

        captured_reloaded: list[RuleScopeInvalidation] = []
        captured_applied: list[RuleScopeInvalidation] = []
        manager.event_emitter.on(
            RuleScopeEvent.IDB_OVERLAY_RELOADED,
            lambda payload: captured_reloaded.append(payload),
        )
        manager.event_emitter.on(
            RuleScopeEvent.INFERENCE_APPLIED,
            lambda payload: captured_applied.append(payload),
        )

        manager._init_storage()

        active = manager.get_active_rule_inference()
        assert active is not None
        assert active.name == "persisted_inference"
        assert active.enabled_rules == frozenset({"RuleA"})
        assert active.disabled_rules == frozenset({"RuleB"})
        assert len(captured_applied) == 1
        assert len(captured_reloaded) == 1

        if manager.storage is not None:
            manager.storage.close()
