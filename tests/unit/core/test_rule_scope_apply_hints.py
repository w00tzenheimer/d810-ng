"""Tests for RuleScopeService.apply_hints() and supporting types."""
import logging

import pytest
from dataclasses import dataclass, field

from d810.core.rule_scope import (
    ApplyHintsResult,
    FunctionRuleOverlay,
    HintOverlayProvider,
    InferenceFactory,
    PIPELINE_INSTRUCTION,
    RuleDelta,
    RuleInferenceOverlay,
    RuleScopeService,
)


# ---------------------------------------------------------------------------
# RuleDelta
# ---------------------------------------------------------------------------

class TestRuleDelta:
    def test_create_suppress_delta(self) -> None:
        delta = RuleDelta(rule_name="ConstantFolding", action="suppress", overrides={})
        assert delta.rule_name == "ConstantFolding"
        assert delta.action == "suppress"
        assert delta.overrides == {}

    def test_create_override_delta(self) -> None:
        delta = RuleDelta(
            rule_name="HodurUnflattener",
            action="override",
            overrides={"max_passes": 10, "max_calls_exit_blocks": 500},
        )
        assert delta.overrides["max_passes"] == 10

    def test_frozen(self) -> None:
        delta = RuleDelta(rule_name="X", action="suppress", overrides={})
        with pytest.raises(AttributeError):
            delta.rule_name = "Y"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

@dataclass
class _DummyRule:
    name: str
    maturities: list[int] = field(default_factory=list)
    tags_any: list[str] = field(default_factory=list)
    tags_all: list[str] = field(default_factory=list)
    use_whitelist: bool = False
    whitelisted_function_ea_list: list[int | str] = field(default_factory=list)
    use_blacklist: bool = False
    blacklisted_function_ea_list: list[int | str] = field(default_factory=list)


@dataclass(frozen=True)
class _DummyHints:
    """Minimal duck-typed stand-in for DeobfuscationHints."""
    func_ea: int
    recommended_inferences: tuple[str, ...] = ()
    suppress_rules: tuple[str, ...] = ()


def _make_activate_factory(*rule_names: str) -> InferenceFactory:
    """Create a factory that activates the given rules."""
    def factory(hints: object) -> list[RuleDelta]:
        return [RuleDelta(rule_name=r, action="activate", overrides={}) for r in rule_names]
    return factory


def _make_service_with_rules(*rules: _DummyRule) -> RuleScopeService:
    """Create a service with compiled instruction rules."""
    svc = RuleScopeService()
    svc.compile_base_rules(
        project_name="proj",
        instruction_rules=rules,
        flow_rules=(),
        ctree_rules=(),
    )
    return svc


def _active_names(svc: RuleScopeService, func_ea: int, maturity: int = 1) -> tuple[str, ...]:
    """Return rule names active for *func_ea* at *maturity*."""
    rules = svc.get_active_rules(
        project_name="proj",
        idb_key="idb",
        func_ea=func_ea,
        pipeline=PIPELINE_INSTRUCTION,
        maturity=maturity,
    )
    return tuple(r.name for r in rules)


# ---------------------------------------------------------------------------
# ApplyHintsResult
# ---------------------------------------------------------------------------

class TestApplyHintsResult:
    def test_frozen(self) -> None:
        r = ApplyHintsResult(
            func_ea=0x1000,
            inferences_applied=("r1",),
            inferences_not_found=(),
            rules_suppressed=("s1",),
            cache_invalidated=True,
            generation_before=0,
            generation_after=1,
        )
        assert r.func_ea == 0x1000
        assert r.inferences_applied == ("r1",)
        assert r.rules_suppressed == ("s1",)

    def test_immutable(self) -> None:
        r = ApplyHintsResult(
            func_ea=0x1000,
            inferences_applied=(),
            inferences_not_found=(),
            rules_suppressed=(),
            cache_invalidated=False,
            generation_before=0,
            generation_after=0,
        )
        try:
            r.func_ea = 0x2000  # type: ignore[misc]
            assert False, "should have raised"
        except AttributeError:
            pass


# ---------------------------------------------------------------------------
# HintOverlayProvider
# ---------------------------------------------------------------------------

class TestHintOverlayProvider:
    def test_no_delegate_no_suppressions_returns_none(self) -> None:
        prov = HintOverlayProvider()
        assert prov(0x1000) is None

    def test_suppress_rules_without_delegate(self) -> None:
        prov = HintOverlayProvider()
        prov.suppress_rules(0x1000, frozenset({"BadRule"}))
        overlay = prov(0x1000)
        assert overlay is not None
        assert "BadRule" in overlay.disabled_rules
        assert overlay.enabled_rules == frozenset()

    def test_suppress_rules_merges_with_delegate(self) -> None:
        delegate = lambda ea: FunctionRuleOverlay(
            disabled_rules=frozenset({"DelegateRule"}),
            function_tags=frozenset({"tag1"}),
        )
        prov = HintOverlayProvider(delegate=delegate)
        prov.suppress_rules(0x1000, frozenset({"HintRule"}))
        overlay = prov(0x1000)
        assert overlay is not None
        assert "DelegateRule" in overlay.disabled_rules
        assert "HintRule" in overlay.disabled_rules
        assert "tag1" in overlay.function_tags

    def test_has_suppressions(self) -> None:
        prov = HintOverlayProvider()
        assert not prov.has_suppressions(0x1000)
        prov.suppress_rules(0x1000, frozenset({"R"}))
        assert prov.has_suppressions(0x1000)

    def test_clear_suppressions_specific(self) -> None:
        prov = HintOverlayProvider()
        prov.suppress_rules(0x1000, frozenset({"R1"}))
        prov.suppress_rules(0x2000, frozenset({"R2"}))
        prov.clear_suppressions(0x1000)
        assert not prov.has_suppressions(0x1000)
        assert prov.has_suppressions(0x2000)

    def test_clear_suppressions_all(self) -> None:
        prov = HintOverlayProvider()
        prov.suppress_rules(0x1000, frozenset({"R1"}))
        prov.suppress_rules(0x2000, frozenset({"R2"}))
        prov.clear_suppressions()
        assert not prov.has_suppressions(0x1000)
        assert not prov.has_suppressions(0x2000)

    def test_accumulates_suppressions(self) -> None:
        prov = HintOverlayProvider()
        prov.suppress_rules(0x1000, frozenset({"A"}))
        prov.suppress_rules(0x1000, frozenset({"B"}))
        overlay = prov(0x1000)
        assert overlay is not None
        assert overlay.disabled_rules == frozenset({"A", "B"})

    def test_delegate_property(self) -> None:
        d = lambda ea: None
        prov = HintOverlayProvider(delegate=d)
        assert prov.delegate is d

    def test_unaffected_function_passes_delegate_through(self) -> None:
        delegate = lambda ea: FunctionRuleOverlay(
            enabled_rules=frozenset({"R1"}),
        )
        prov = HintOverlayProvider(delegate=delegate)
        prov.suppress_rules(0x2000, frozenset({"X"}))
        # 0x1000 has no suppressions -> delegate result only
        overlay = prov(0x1000)
        assert overlay is not None
        assert overlay.enabled_rules == frozenset({"R1"})
        assert overlay.disabled_rules == frozenset()


# ---------------------------------------------------------------------------
# RuleScopeService.register_inference / get_registered_inference
# ---------------------------------------------------------------------------

class TestInferenceRegistry:
    def test_register_and_retrieve(self) -> None:
        svc = RuleScopeService()
        factory = _make_activate_factory("R1")
        svc.register_inference("test_inference", factory)
        assert svc.get_registered_inference("test_inference") is factory

    def test_missing_returns_none(self) -> None:
        svc = RuleScopeService()
        assert svc.get_registered_inference("nope") is None

    def test_overwrite(self) -> None:
        svc = RuleScopeService()
        f1 = _make_activate_factory("A")
        f2 = _make_activate_factory("B")
        svc.register_inference("r", f1)
        svc.register_inference("r", f2)
        assert svc.get_registered_inference("r") is f2

    def test_factory_receives_hints(self) -> None:
        """Factory callable receives the hints object passed to apply_hints."""
        svc = _make_service_with_rules(
            _DummyRule(name="R1", maturities=[1]),
        )
        received: list[object] = []

        def capturing_factory(hints: object) -> list[RuleDelta]:
            received.append(hints)
            return [RuleDelta(rule_name="R1", action="activate", overrides={})]

        svc.register_inference("cap", capturing_factory)
        hints = _DummyHints(func_ea=0x1000, recommended_inferences=("cap",))
        svc.apply_hints(hints)
        assert len(received) == 1
        assert received[0] is hints

    def test_factory_returns_deltas(self) -> None:
        """Factory-produced deltas are converted to overlay correctly."""
        svc = _make_service_with_rules(
            _DummyRule(name="R1", maturities=[1]),
            _DummyRule(name="R2", maturities=[1]),
            _DummyRule(name="R3", maturities=[1]),
        )

        def mixed_factory(hints: object) -> list[RuleDelta]:
            return [
                RuleDelta(rule_name="R1", action="activate", overrides={}),
                RuleDelta(rule_name="R3", action="suppress", overrides={}),
            ]

        svc.register_inference("mixed", mixed_factory)
        hints = _DummyHints(func_ea=0x1000, recommended_inferences=("mixed",))
        result = svc.apply_hints(hints)
        assert result.inferences_applied == ("mixed",)

        active = _active_names(svc, 0x1000)
        assert "R1" in active
        assert "R3" not in active


# ---------------------------------------------------------------------------
# RuleScopeService.apply_hints
# ---------------------------------------------------------------------------

class TestApplyHints:
    def test_empty_hints_no_change(self) -> None:
        svc = _make_service_with_rules(_DummyRule(name="R1", maturities=[1]))
        gen_before = svc.generation
        hints = _DummyHints(func_ea=0x1000)
        result = svc.apply_hints(hints)

        assert result.func_ea == 0x1000
        assert result.inferences_applied == ()
        assert result.inferences_not_found == ()
        assert result.rules_suppressed == ()
        assert not result.cache_invalidated
        assert result.generation_before == gen_before
        assert result.generation_after == gen_before  # no change

    def test_inference_applied_activates_inference(self) -> None:
        svc = _make_service_with_rules(
            _DummyRule(name="R1", maturities=[1]),
            _DummyRule(name="R2", maturities=[1]),
        )
        svc.register_inference("only_r2", _make_activate_factory("R2"))
        hints = _DummyHints(func_ea=0x1000, recommended_inferences=("only_r2",))
        result = svc.apply_hints(hints)

        assert result.inferences_applied == ("only_r2",)
        assert result.inferences_not_found == ()
        assert result.cache_invalidated
        assert result.generation_after > result.generation_before

        # The inference should filter rules for func_ea 0x1000
        active = _active_names(svc, 0x1000)
        assert active == ("R2",)

    def test_inference_not_found(self) -> None:
        svc = _make_service_with_rules(_DummyRule(name="R1", maturities=[1]))
        hints = _DummyHints(
            func_ea=0x1000,
            recommended_inferences=("nonexistent_inference",),
        )
        result = svc.apply_hints(hints)

        assert result.inferences_applied == ()
        assert result.inferences_not_found == ("nonexistent_inference",)
        assert not result.cache_invalidated

    def test_mixed_found_and_not_found_inferences(self) -> None:
        svc = _make_service_with_rules(
            _DummyRule(name="R1", maturities=[1]),
            _DummyRule(name="R2", maturities=[1]),
        )
        svc.register_inference("good_inference", _make_activate_factory("R1"))
        hints = _DummyHints(
            func_ea=0x1000,
            recommended_inferences=("good_inference", "bad_inference"),
        )
        result = svc.apply_hints(hints)

        assert result.inferences_applied == ("good_inference",)
        assert result.inferences_not_found == ("bad_inference",)
        assert result.cache_invalidated

    def test_suppress_rules_disables_rules(self) -> None:
        svc = _make_service_with_rules(
            _DummyRule(name="RuleA", maturities=[1]),
            _DummyRule(name="RuleB", maturities=[1]),
            _DummyRule(name="RuleC", maturities=[1]),
        )
        # Baseline: all three active
        assert _active_names(svc, 0x1000) == ("RuleA", "RuleB", "RuleC")

        hints = _DummyHints(
            func_ea=0x1000,
            suppress_rules=("RuleA", "RuleC"),
        )
        result = svc.apply_hints(hints)

        assert result.rules_suppressed == ("RuleA", "RuleC")
        assert result.cache_invalidated
        assert _active_names(svc, 0x1000) == ("RuleB",)

    def test_suppress_does_not_affect_other_functions(self) -> None:
        svc = _make_service_with_rules(
            _DummyRule(name="RuleA", maturities=[1]),
            _DummyRule(name="RuleB", maturities=[1]),
        )
        hints = _DummyHints(
            func_ea=0x1000,
            suppress_rules=("RuleA",),
        )
        svc.apply_hints(hints)

        # 0x1000 suppressed
        assert _active_names(svc, 0x1000) == ("RuleB",)
        # 0x2000 unaffected
        assert _active_names(svc, 0x2000) == ("RuleA", "RuleB")

    def test_inference_and_suppress_combined(self) -> None:
        svc = _make_service_with_rules(
            _DummyRule(name="R1", maturities=[1]),
            _DummyRule(name="R2", maturities=[1]),
            _DummyRule(name="R3", maturities=[1]),
        )
        svc.register_inference("enable_r1_r2", _make_activate_factory("R1", "R2"))
        hints = _DummyHints(
            func_ea=0x1000,
            recommended_inferences=("enable_r1_r2",),
            suppress_rules=("R2",),
        )
        result = svc.apply_hints(hints)

        assert result.inferences_applied == ("enable_r1_r2",)
        assert result.rules_suppressed == ("R2",)
        # Inference allows R1 and R2; suppress removes R2 -> only R1
        assert _active_names(svc, 0x1000) == ("R1",)

    def test_hint_overlay_composes_with_existing_provider(self) -> None:
        svc = _make_service_with_rules(
            _DummyRule(name="RuleA", maturities=[1]),
            _DummyRule(name="RuleB", maturities=[1]),
            _DummyRule(name="RuleC", maturities=[1]),
        )
        # Pre-existing overlay disables RuleA for 0x1000
        svc.set_overlay_provider(
            lambda ea: FunctionRuleOverlay(disabled_rules=frozenset({"RuleA"}))
            if ea == 0x1000
            else None
        )
        assert _active_names(svc, 0x1000) == ("RuleB", "RuleC")

        # Hints additionally suppress RuleB
        hints = _DummyHints(func_ea=0x1000, suppress_rules=("RuleB",))
        svc.apply_hints(hints)

        # Both delegate disable (RuleA) and hint suppress (RuleB) active
        assert _active_names(svc, 0x1000) == ("RuleC",)

    def test_multiple_apply_hints_replaces_suppressions(self) -> None:
        """Second apply_hints replaces (not accumulates) suppressions."""
        svc = _make_service_with_rules(
            _DummyRule(name="R1", maturities=[1]),
            _DummyRule(name="R2", maturities=[1]),
            _DummyRule(name="R3", maturities=[1]),
        )
        svc.apply_hints(_DummyHints(func_ea=0x1000, suppress_rules=("R1",)))
        svc.apply_hints(_DummyHints(func_ea=0x1000, suppress_rules=("R2",)))

        # Only R2 suppressed (second call replaced first); R1 is back.
        assert _active_names(svc, 0x1000) == ("R1", "R3")

    def test_generation_advances_on_change(self) -> None:
        svc = _make_service_with_rules(_DummyRule(name="R1", maturities=[1]))
        svc.register_inference("r", _make_activate_factory("R1"))

        g0 = svc.generation
        result = svc.apply_hints(
            _DummyHints(func_ea=0x1000, recommended_inferences=("r",))
        )
        assert result.generation_before == g0
        assert result.generation_after == g0 + 1
        assert svc.generation == g0 + 1

    def test_no_generation_advance_when_nothing_applied(self) -> None:
        svc = _make_service_with_rules(_DummyRule(name="R1", maturities=[1]))
        g0 = svc.generation
        result = svc.apply_hints(_DummyHints(func_ea=0x1000))
        assert result.generation_before == g0
        assert result.generation_after == g0
        assert svc.generation == g0

    def test_apply_hints_multiple_inferences_all_active(self) -> None:
        """All recommended inferences for the same function must be active."""
        svc = _make_service_with_rules(
            _DummyRule(name="R1", maturities=[1]),
            _DummyRule(name="R2", maturities=[1]),
            _DummyRule(name="R3", maturities=[1]),
        )
        svc.register_inference("inference_a", _make_activate_factory("R1"))
        svc.register_inference("inference_b", _make_activate_factory("R2"))

        hints = _DummyHints(
            func_ea=0x1000,
            recommended_inferences=("inference_a", "inference_b"),
        )
        result = svc.apply_hints(hints)

        assert result.inferences_applied == ("inference_a", "inference_b")
        # Both R1 (from inference_a) and R2 (from inference_b) must be active,
        # not just R2 (last inference).
        active = _active_names(svc, 0x1000)
        assert "R1" in active, f"R1 missing from active rules: {active}"
        assert "R2" in active, f"R2 missing from active rules: {active}"
        # R3 is NOT in any inference's enabled_rules, so it should be blocked
        assert "R3" not in active, f"R3 should be blocked: {active}"

    def test_apply_hints_different_functions_independent(self) -> None:
        """Hints for func_A must not clobber hints for func_B."""
        svc = _make_service_with_rules(
            _DummyRule(name="R1", maturities=[1]),
            _DummyRule(name="R2", maturities=[1]),
            _DummyRule(name="R3", maturities=[1]),
        )
        svc.register_inference("inference_for_a", _make_activate_factory("R1"))
        svc.register_inference("inference_for_b", _make_activate_factory("R2"))

        # Apply hints for func_A first, then func_B
        svc.apply_hints(_DummyHints(
            func_ea=0xA000,
            recommended_inferences=("inference_for_a",),
        ))
        svc.apply_hints(_DummyHints(
            func_ea=0xB000,
            recommended_inferences=("inference_for_b",),
        ))

        # func_A should still have inference_for_a active (R1 only)
        active_a = _active_names(svc, 0xA000)
        assert "R1" in active_a, f"func_A lost R1: {active_a}"
        assert "R2" not in active_a, f"func_A should not have R2: {active_a}"

        # func_B should have inference_for_b active (R2 only)
        active_b = _active_names(svc, 0xB000)
        assert "R2" in active_b, f"func_B lost R2: {active_b}"
        assert "R1" not in active_b, f"func_B should not have R1: {active_b}"

        # func_C (no hints) should have all rules (no inference filtering)
        active_c = _active_names(svc, 0xC000)
        assert active_c == ("R1", "R2", "R3"), f"func_C unexpected: {active_c}"

    def test_apply_hints_replaces_previous_for_same_func(self) -> None:
        """Applying hints with inference B after inference A replaces, not appends."""
        svc = _make_service_with_rules(
            _DummyRule(name="R1", maturities=[1]),
            _DummyRule(name="R2", maturities=[1]),
            _DummyRule(name="R3", maturities=[1]),
        )
        svc.register_inference("inference_a", _make_activate_factory("R1"))
        svc.register_inference("inference_b", _make_activate_factory("R2"))

        svc.apply_hints(_DummyHints(func_ea=0x1000, recommended_inferences=("inference_a",)))
        assert _active_names(svc, 0x1000) == ("R1",)

        # Second call replaces -- only inference_b active now
        svc.apply_hints(_DummyHints(func_ea=0x1000, recommended_inferences=("inference_b",)))
        active = _active_names(svc, 0x1000)
        assert active == ("R2",), f"Expected only R2 after replace, got {active}"

    def test_apply_hints_empty_clears_previous(self) -> None:
        """Applying empty hints for a function clears all previous hint state."""
        svc = _make_service_with_rules(
            _DummyRule(name="R1", maturities=[1]),
            _DummyRule(name="R2", maturities=[1]),
        )
        svc.register_inference("only_r1", _make_activate_factory("R1"))

        svc.apply_hints(_DummyHints(func_ea=0x1000, recommended_inferences=("only_r1",)))
        assert _active_names(svc, 0x1000) == ("R1",)

        # Apply empty hints -- should clear, restoring all rules
        svc.apply_hints(_DummyHints(func_ea=0x1000))
        active = _active_names(svc, 0x1000)
        assert active == ("R1", "R2"), f"Expected all rules after clear, got {active}"

    def test_with_real_deobfuscation_hints(self) -> None:
        """Verify apply_hints works with the actual DeobfuscationHints type."""
        from d810.recon.models import DeobfuscationHints

        svc = _make_service_with_rules(
            _DummyRule(name="R1", maturities=[1]),
            _DummyRule(name="R2", maturities=[1]),
        )
        svc.register_inference("unflatten", _make_activate_factory("R1"))

        hints = DeobfuscationHints(
            func_ea=0x401000,
            obfuscation_type="ollvm_flat",
            confidence=0.9,
            recommended_inferences=("unflatten",),
            candidates=(),
            suppress_rules=("R2",),
        )
        result = svc.apply_hints(hints)

        assert result.inferences_applied == ("unflatten",)
        assert result.rules_suppressed == ("R2",)
        assert _active_names(svc, 0x401000) == ("R1",)


# ---------------------------------------------------------------------------
# RuleScopeService.get_hint_state_summary
# ---------------------------------------------------------------------------

class TestGetHintStateSummary:
    def test_empty_state(self) -> None:
        svc = RuleScopeService()
        summary = svc.get_hint_state_summary(0x1000)
        assert summary["func_ea"] == 0x1000
        assert summary["has_hint_inferences"] is False
        assert summary["inference_names"] == []
        assert summary["suppressed_rules"] == []
        assert summary["generation"] == svc.generation

    def test_after_inference_applied(self) -> None:
        svc = _make_service_with_rules(
            _DummyRule(name="R1", maturities=[1]),
            _DummyRule(name="R2", maturities=[1]),
        )
        svc.register_inference("only_r1", _make_activate_factory("R1"))
        svc.apply_hints(_DummyHints(
            func_ea=0x1000,
            recommended_inferences=("only_r1",),
        ))

        summary = svc.get_hint_state_summary(0x1000)
        assert summary["has_hint_inferences"] is True
        assert "only_r1" in summary["inference_names"]

    def test_after_suppress_rules(self) -> None:
        svc = _make_service_with_rules(
            _DummyRule(name="R1", maturities=[1]),
            _DummyRule(name="R2", maturities=[1]),
        )
        svc.apply_hints(_DummyHints(
            func_ea=0x1000,
            suppress_rules=("R2", "R1"),
        ))

        summary = svc.get_hint_state_summary(0x1000)
        assert summary["has_hint_inferences"] is False
        # suppressed_rules is sorted
        assert summary["suppressed_rules"] == ["R1", "R2"]

    def test_unaffected_function_empty(self) -> None:
        svc = _make_service_with_rules(
            _DummyRule(name="R1", maturities=[1]),
        )
        svc.apply_hints(_DummyHints(
            func_ea=0x1000,
            suppress_rules=("R1",),
        ))

        # Different function should show empty state
        summary = svc.get_hint_state_summary(0x2000)
        assert summary["has_hint_inferences"] is False
        assert summary["suppressed_rules"] == []

    def test_generation_tracks(self) -> None:
        svc = _make_service_with_rules(
            _DummyRule(name="R1", maturities=[1]),
        )
        gen_before = svc.generation
        svc.apply_hints(_DummyHints(
            func_ea=0x1000,
            suppress_rules=("R1",),
        ))
        summary = svc.get_hint_state_summary(0x1000)
        assert summary["generation"] == gen_before + 1

    def test_summary_excludes_delegate_overlay_suppressions(self) -> None:
        """Suppressions from delegate overlay must NOT appear in hint summary."""
        svc = RuleScopeService()
        # Set a delegate that disables "BaseRule"
        svc.set_overlay_provider(
            lambda ea: FunctionRuleOverlay(disabled_rules=frozenset({"BaseRule"}))
        )

        # No hints applied -- summary should show empty suppressions
        summary = svc.get_hint_state_summary(0x1000)
        assert summary["suppressed_rules"] == [], (
            f"Delegate suppressions leaked into hint summary: {summary['suppressed_rules']}"
        )

    def test_summary_includes_hint_owned_suppressions(self) -> None:
        """Hint-driven suppressions must appear in the summary."""
        from d810.recon.models import DeobfuscationHints

        svc = RuleScopeService()
        hints = DeobfuscationHints(
            func_ea=0x2000,
            obfuscation_type="ollvm_flat",
            confidence=0.9,
            recommended_inferences=(),
            candidates=(),
            suppress_rules=("BadRule",),
        )
        svc.apply_hints(hints)
        summary = svc.get_hint_state_summary(0x2000)
        assert summary["suppressed_rules"] == ["BadRule"]


# ---------------------------------------------------------------------------
# TestApplyHintsWithInferenceFactory (Task 4 — E2E factory verification)
# ---------------------------------------------------------------------------

class TestApplyHintsWithInferenceFactory:
    """End-to-end verification that registered inference factories are
    called correctly by ``apply_hints`` and produce observable effects."""

    def test_factory_called_and_suppress_applied(self) -> None:
        """Factory returns suppress delta -> rule is disabled via inference overlay."""
        svc = _make_service_with_rules(
            _DummyRule(name="ConstantFolding", maturities=[1]),
            _DummyRule(name="OtherRule", maturities=[1]),
        )

        def unflattening(hints: object) -> list[RuleDelta]:
            return [RuleDelta("ConstantFolding", "suppress", {})]

        svc.register_inference("unflattening", unflattening)

        hints = _DummyHints(
            func_ea=0x1000,
            recommended_inferences=("unflattening",),
        )
        result = svc.apply_hints(hints)

        assert "unflattening" in result.inferences_applied
        assert "unflattening" not in result.inferences_not_found

        # Verify inference is tracked in hint state summary
        summary = svc.get_hint_state_summary(0x1000)
        assert summary["has_hint_inferences"] is True
        assert "unflattening" in summary["inference_names"]

        # Verify suppressed rule is not active (disabled via inference overlay)
        active = _active_names(svc, 0x1000)
        assert "ConstantFolding" not in active
        assert "OtherRule" in active  # only ConstantFolding is suppressed

    def test_unknown_inference_in_not_found(self) -> None:
        """Unknown inference names go to inferences_not_found."""
        svc = _make_service_with_rules(
            _DummyRule(name="R1", maturities=[1]),
        )
        hints = _DummyHints(
            func_ea=0x1000,
            recommended_inferences=("nonexistent",),
        )
        result = svc.apply_hints(hints)

        assert "nonexistent" in result.inferences_not_found
        assert result.inferences_applied == ()

    def test_inferences_applied_populated(self) -> None:
        """inferences_applied tracks all factories that ran successfully."""
        svc = _make_service_with_rules(
            _DummyRule(name="R1", maturities=[1]),
            _DummyRule(name="R2", maturities=[1]),
            _DummyRule(name="R3", maturities=[1]),
        )

        def factory_a(hints: object) -> list[RuleDelta]:
            return [RuleDelta("R1", "suppress", {})]

        def factory_b(hints: object) -> list[RuleDelta]:
            return [RuleDelta("R2", "suppress", {})]

        svc.register_inference("a", factory_a)
        svc.register_inference("b", factory_b)

        hints = _DummyHints(
            func_ea=0x1000,
            recommended_inferences=("a", "b"),
        )
        result = svc.apply_hints(hints)

        assert result.inferences_applied == ("a", "b")
        # Verify both inferences are tracked in summary
        summary = svc.get_hint_state_summary(0x1000)
        assert "a" in summary["inference_names"]
        assert "b" in summary["inference_names"]
        # Verify suppressed rules are not active
        active = _active_names(svc, 0x1000)
        assert "R1" not in active
        assert "R2" not in active
        assert "R3" in active

    def test_mixed_found_and_not_found(self) -> None:
        """Mix of known and unknown inferences populates both lists."""
        svc = _make_service_with_rules(
            _DummyRule(name="R1", maturities=[1]),
        )

        def good_factory(hints: object) -> list[RuleDelta]:
            return [RuleDelta("R1", "suppress", {})]

        svc.register_inference("good", good_factory)

        hints = _DummyHints(
            func_ea=0x1000,
            recommended_inferences=("good", "bad"),
        )
        result = svc.apply_hints(hints)

        assert result.inferences_applied == ("good",)
        assert result.inferences_not_found == ("bad",)


# ---------------------------------------------------------------------------
# Conflict detection: user config overrides inference delta
# ---------------------------------------------------------------------------


class TestInferenceConflictLogging:
    def test_suppress_overridden_by_whitelist(self, caplog: pytest.LogCaptureFixture) -> None:
        """When user whitelists a function for a rule, suppress delta is overridden."""
        svc = _make_service_with_rules(
            _DummyRule(
                name="ConstantFolding",
                maturities=[1],
                use_whitelist=True,
                whitelisted_function_ea_list=[0x1000],
            ),
            _DummyRule(name="OtherRule", maturities=[1]),
        )

        def suppress_cf(hints: object) -> list[RuleDelta]:
            return [RuleDelta("ConstantFolding", "suppress", {})]

        svc.register_inference("test", suppress_cf)

        hints = _DummyHints(func_ea=0x1000, recommended_inferences=("test",))
        with caplog.at_level(logging.WARNING, logger="D810.rule_scope"):
            svc.apply_hints(hints)

        assert "overridden by user config" in caplog.text
        assert "whitelisted" in caplog.text

        # The rule should still be active because suppression was overridden
        active = _active_names(svc, 0x1000)
        assert "ConstantFolding" in active

    def test_suppress_not_overridden_when_func_not_whitelisted(
        self, caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Suppress delta is applied when func_ea is NOT in the whitelist."""
        svc = _make_service_with_rules(
            _DummyRule(
                name="ConstantFolding",
                maturities=[1],
                use_whitelist=True,
                whitelisted_function_ea_list=[0x9999],  # different func
            ),
        )

        def suppress_cf(hints: object) -> list[RuleDelta]:
            return [RuleDelta("ConstantFolding", "suppress", {})]

        svc.register_inference("test", suppress_cf)

        hints = _DummyHints(func_ea=0x1000, recommended_inferences=("test",))
        with caplog.at_level(logging.WARNING, logger="D810.rule_scope"):
            svc.apply_hints(hints)

        assert "overridden by user config" not in caplog.text

    def test_activate_overridden_by_blacklist(self, caplog: pytest.LogCaptureFixture) -> None:
        """When user blacklists a function for a rule, activate delta is overridden."""
        svc = _make_service_with_rules(
            _DummyRule(
                name="SomeRule",
                maturities=[1],
                use_blacklist=True,
                blacklisted_function_ea_list=[0x2000],
            ),
        )

        def activate_rule(hints: object) -> list[RuleDelta]:
            return [RuleDelta("SomeRule", "activate", {})]

        svc.register_inference("test", activate_rule)

        hints = _DummyHints(func_ea=0x2000, recommended_inferences=("test",))
        with caplog.at_level(logging.WARNING, logger="D810.rule_scope"):
            svc.apply_hints(hints)

        assert "overridden by user config" in caplog.text
        assert "blacklisted" in caplog.text

    def test_no_conflict_without_whitelist_or_blacklist(
        self, caplog: pytest.LogCaptureFixture,
    ) -> None:
        """No conflict logged when rule has no whitelist/blacklist."""
        svc = _make_service_with_rules(
            _DummyRule(name="PlainRule", maturities=[1]),
        )

        def suppress_plain(hints: object) -> list[RuleDelta]:
            return [RuleDelta("PlainRule", "suppress", {})]

        svc.register_inference("test", suppress_plain)

        hints = _DummyHints(func_ea=0x1000, recommended_inferences=("test",))
        with caplog.at_level(logging.WARNING, logger="D810.rule_scope"):
            svc.apply_hints(hints)

        assert "overridden by user config" not in caplog.text

    def test_suppress_applied_when_no_whitelist(self) -> None:
        """Without whitelist, suppress delta still disables the rule."""
        svc = _make_service_with_rules(
            _DummyRule(name="R1", maturities=[1]),
        )

        def suppress_r1(hints: object) -> list[RuleDelta]:
            return [RuleDelta("R1", "suppress", {})]

        svc.register_inference("test", suppress_r1)
        hints = _DummyHints(func_ea=0x1000, recommended_inferences=("test",))
        svc.apply_hints(hints)

        active = _active_names(svc, 0x1000)
        assert "R1" not in active
