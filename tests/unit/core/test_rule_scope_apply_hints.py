"""Tests for RuleScopeService.apply_hints() and supporting types."""
import pytest
from dataclasses import dataclass, field

from d810.core.rule_scope import (
    ApplyHintsResult,
    FunctionRuleOverlay,
    HintOverlayProvider,
    PIPELINE_INSTRUCTION,
    RuleDelta,
    RuleRecipeOverlay,
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
    recommended_recipes: tuple[str, ...] = ()
    suppress_rules: tuple[str, ...] = ()


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
            recipes_applied=("r1",),
            recipes_not_found=(),
            rules_suppressed=("s1",),
            cache_invalidated=True,
            generation_before=0,
            generation_after=1,
        )
        assert r.func_ea == 0x1000
        assert r.recipes_applied == ("r1",)
        assert r.rules_suppressed == ("s1",)

    def test_immutable(self) -> None:
        r = ApplyHintsResult(
            func_ea=0x1000,
            recipes_applied=(),
            recipes_not_found=(),
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
# RuleScopeService.register_recipe / get_registered_recipe
# ---------------------------------------------------------------------------

class TestRecipeRegistry:
    def test_register_and_retrieve(self) -> None:
        svc = RuleScopeService()
        recipe = RuleRecipeOverlay(
            name="test_recipe",
            enabled_rules=frozenset({"R1"}),
        )
        svc.register_recipe(recipe)
        assert svc.get_registered_recipe("test_recipe") is recipe

    def test_missing_returns_none(self) -> None:
        svc = RuleScopeService()
        assert svc.get_registered_recipe("nope") is None

    def test_overwrite(self) -> None:
        svc = RuleScopeService()
        r1 = RuleRecipeOverlay(name="r", enabled_rules=frozenset({"A"}))
        r2 = RuleRecipeOverlay(name="r", enabled_rules=frozenset({"B"}))
        svc.register_recipe(r1)
        svc.register_recipe(r2)
        assert svc.get_registered_recipe("r") is r2


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
        assert result.recipes_applied == ()
        assert result.recipes_not_found == ()
        assert result.rules_suppressed == ()
        assert not result.cache_invalidated
        assert result.generation_before == gen_before
        assert result.generation_after == gen_before  # no change

    def test_recipe_applied_activates_recipe(self) -> None:
        svc = _make_service_with_rules(
            _DummyRule(name="R1", maturities=[1]),
            _DummyRule(name="R2", maturities=[1]),
        )
        recipe = RuleRecipeOverlay(
            name="only_r2",
            enabled_rules=frozenset({"R2"}),
        )
        svc.register_recipe(recipe)
        hints = _DummyHints(func_ea=0x1000, recommended_recipes=("only_r2",))
        result = svc.apply_hints(hints)

        assert result.recipes_applied == ("only_r2",)
        assert result.recipes_not_found == ()
        assert result.cache_invalidated
        assert result.generation_after > result.generation_before

        # The recipe should filter rules for func_ea 0x1000
        active = _active_names(svc, 0x1000)
        assert active == ("R2",)

    def test_recipe_not_found(self) -> None:
        svc = _make_service_with_rules(_DummyRule(name="R1", maturities=[1]))
        hints = _DummyHints(
            func_ea=0x1000,
            recommended_recipes=("nonexistent_recipe",),
        )
        result = svc.apply_hints(hints)

        assert result.recipes_applied == ()
        assert result.recipes_not_found == ("nonexistent_recipe",)
        assert not result.cache_invalidated

    def test_mixed_found_and_not_found_recipes(self) -> None:
        svc = _make_service_with_rules(
            _DummyRule(name="R1", maturities=[1]),
            _DummyRule(name="R2", maturities=[1]),
        )
        recipe = RuleRecipeOverlay(
            name="good_recipe",
            enabled_rules=frozenset({"R1"}),
        )
        svc.register_recipe(recipe)
        hints = _DummyHints(
            func_ea=0x1000,
            recommended_recipes=("good_recipe", "bad_recipe"),
        )
        result = svc.apply_hints(hints)

        assert result.recipes_applied == ("good_recipe",)
        assert result.recipes_not_found == ("bad_recipe",)
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

    def test_recipe_and_suppress_combined(self) -> None:
        svc = _make_service_with_rules(
            _DummyRule(name="R1", maturities=[1]),
            _DummyRule(name="R2", maturities=[1]),
            _DummyRule(name="R3", maturities=[1]),
        )
        recipe = RuleRecipeOverlay(
            name="enable_r1_r2",
            enabled_rules=frozenset({"R1", "R2"}),
        )
        svc.register_recipe(recipe)
        hints = _DummyHints(
            func_ea=0x1000,
            recommended_recipes=("enable_r1_r2",),
            suppress_rules=("R2",),
        )
        result = svc.apply_hints(hints)

        assert result.recipes_applied == ("enable_r1_r2",)
        assert result.rules_suppressed == ("R2",)
        # Recipe allows R1 and R2; suppress removes R2 -> only R1
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
        recipe = RuleRecipeOverlay(name="r", enabled_rules=frozenset({"R1"}))
        svc.register_recipe(recipe)

        g0 = svc.generation
        result = svc.apply_hints(
            _DummyHints(func_ea=0x1000, recommended_recipes=("r",))
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

    def test_apply_hints_multiple_recipes_all_active(self) -> None:
        """All recommended recipes for the same function must be active."""
        svc = _make_service_with_rules(
            _DummyRule(name="R1", maturities=[1]),
            _DummyRule(name="R2", maturities=[1]),
            _DummyRule(name="R3", maturities=[1]),
        )
        recipe_a = RuleRecipeOverlay(
            name="recipe_a",
            enabled_rules=frozenset({"R1"}),
        )
        recipe_b = RuleRecipeOverlay(
            name="recipe_b",
            enabled_rules=frozenset({"R2"}),
        )
        svc.register_recipe(recipe_a)
        svc.register_recipe(recipe_b)

        hints = _DummyHints(
            func_ea=0x1000,
            recommended_recipes=("recipe_a", "recipe_b"),
        )
        result = svc.apply_hints(hints)

        assert result.recipes_applied == ("recipe_a", "recipe_b")
        # Both R1 (from recipe_a) and R2 (from recipe_b) must be active,
        # not just R2 (last recipe).
        active = _active_names(svc, 0x1000)
        assert "R1" in active, f"R1 missing from active rules: {active}"
        assert "R2" in active, f"R2 missing from active rules: {active}"
        # R3 is NOT in any recipe's enabled_rules, so it should be blocked
        assert "R3" not in active, f"R3 should be blocked: {active}"

    def test_apply_hints_different_functions_independent(self) -> None:
        """Hints for func_A must not clobber hints for func_B."""
        svc = _make_service_with_rules(
            _DummyRule(name="R1", maturities=[1]),
            _DummyRule(name="R2", maturities=[1]),
            _DummyRule(name="R3", maturities=[1]),
        )
        recipe_for_a = RuleRecipeOverlay(
            name="recipe_for_a",
            enabled_rules=frozenset({"R1"}),
        )
        recipe_for_b = RuleRecipeOverlay(
            name="recipe_for_b",
            enabled_rules=frozenset({"R2"}),
        )
        svc.register_recipe(recipe_for_a)
        svc.register_recipe(recipe_for_b)

        # Apply hints for func_A first, then func_B
        svc.apply_hints(_DummyHints(
            func_ea=0xA000,
            recommended_recipes=("recipe_for_a",),
        ))
        svc.apply_hints(_DummyHints(
            func_ea=0xB000,
            recommended_recipes=("recipe_for_b",),
        ))

        # func_A should still have recipe_for_a active (R1 only)
        active_a = _active_names(svc, 0xA000)
        assert "R1" in active_a, f"func_A lost R1: {active_a}"
        assert "R2" not in active_a, f"func_A should not have R2: {active_a}"

        # func_B should have recipe_for_b active (R2 only)
        active_b = _active_names(svc, 0xB000)
        assert "R2" in active_b, f"func_B lost R2: {active_b}"
        assert "R1" not in active_b, f"func_B should not have R1: {active_b}"

        # func_C (no hints) should have all rules (no recipe filtering)
        active_c = _active_names(svc, 0xC000)
        assert active_c == ("R1", "R2", "R3"), f"func_C unexpected: {active_c}"

    def test_apply_hints_replaces_previous_for_same_func(self) -> None:
        """Applying hints with recipe B after recipe A replaces, not appends."""
        svc = _make_service_with_rules(
            _DummyRule(name="R1", maturities=[1]),
            _DummyRule(name="R2", maturities=[1]),
            _DummyRule(name="R3", maturities=[1]),
        )
        recipe_a = RuleRecipeOverlay(name="recipe_a", enabled_rules=frozenset({"R1"}))
        recipe_b = RuleRecipeOverlay(name="recipe_b", enabled_rules=frozenset({"R2"}))
        svc.register_recipe(recipe_a)
        svc.register_recipe(recipe_b)

        svc.apply_hints(_DummyHints(func_ea=0x1000, recommended_recipes=("recipe_a",)))
        assert _active_names(svc, 0x1000) == ("R1",)

        # Second call replaces — only recipe_b active now
        svc.apply_hints(_DummyHints(func_ea=0x1000, recommended_recipes=("recipe_b",)))
        active = _active_names(svc, 0x1000)
        assert active == ("R2",), f"Expected only R2 after replace, got {active}"

    def test_apply_hints_empty_clears_previous(self) -> None:
        """Applying empty hints for a function clears all previous hint state."""
        svc = _make_service_with_rules(
            _DummyRule(name="R1", maturities=[1]),
            _DummyRule(name="R2", maturities=[1]),
        )
        recipe = RuleRecipeOverlay(name="only_r1", enabled_rules=frozenset({"R1"}))
        svc.register_recipe(recipe)

        svc.apply_hints(_DummyHints(func_ea=0x1000, recommended_recipes=("only_r1",)))
        assert _active_names(svc, 0x1000) == ("R1",)

        # Apply empty hints — should clear, restoring all rules
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
        recipe = RuleRecipeOverlay(
            name="unflatten",
            enabled_rules=frozenset({"R1"}),
        )
        svc.register_recipe(recipe)

        hints = DeobfuscationHints(
            func_ea=0x401000,
            obfuscation_type="ollvm_flat",
            confidence=0.9,
            recommended_recipes=("unflatten",),
            candidates=(),
            suppress_rules=("R2",),
        )
        result = svc.apply_hints(hints)

        assert result.recipes_applied == ("unflatten",)
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
        assert summary["has_hint_recipes"] is False
        assert summary["recipe_names"] == []
        assert summary["suppressed_rules"] == []
        assert summary["generation"] == svc.generation

    def test_after_recipe_applied(self) -> None:
        svc = _make_service_with_rules(
            _DummyRule(name="R1", maturities=[1]),
            _DummyRule(name="R2", maturities=[1]),
        )
        recipe = RuleRecipeOverlay(
            name="only_r1",
            enabled_rules=frozenset({"R1"}),
        )
        svc.register_recipe(recipe)
        svc.apply_hints(_DummyHints(
            func_ea=0x1000,
            recommended_recipes=("only_r1",),
        ))

        summary = svc.get_hint_state_summary(0x1000)
        assert summary["has_hint_recipes"] is True
        assert "only_r1" in summary["recipe_names"]

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
        assert summary["has_hint_recipes"] is False
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
        assert summary["has_hint_recipes"] is False
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
            recommended_recipes=(),
            candidates=(),
            suppress_rules=("BadRule",),
        )
        svc.apply_hints(hints)
        summary = svc.get_hint_state_summary(0x2000)
        assert summary["suppressed_rules"] == ["BadRule"]
