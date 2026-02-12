from dataclasses import dataclass, field

from d810.core.registry import EventEmitter
from d810.core.rule_scope import (
    FunctionRuleOverlay,
    PIPELINE_FLOW,
    PIPELINE_INSTRUCTION,
    RuleScopeEvent,
    RuleScopeInvalidation,
    RuleScopeService,
)


@dataclass
class _DummyRule:
    name: str
    maturities: list[int] = field(default_factory=list)
    use_whitelist: bool = False
    whitelisted_function_ea_list: list[int | str] = field(default_factory=list)
    use_blacklist: bool = False
    blacklisted_function_ea_list: list[int | str] = field(default_factory=list)


def test_compile_and_filter_by_maturity_and_addr():
    svc = RuleScopeService()
    allow_only_1000 = _DummyRule(
        name="AllowOnly1000",
        maturities=[1],
        use_whitelist=True,
        whitelisted_function_ea_list=["0x1000"],
    )
    deny_1000 = _DummyRule(
        name="Deny1000",
        maturities=[1],
        use_blacklist=True,
        blacklisted_function_ea_list=[0x1000],
    )

    svc.compile_base_rules(
        project_name="proj",
        instruction_rules=(),
        flow_rules=(allow_only_1000, deny_1000),
        ctree_rules=(),
    )

    active_1000 = svc.get_active_rules(
        project_name="proj",
        idb_key="idb",
        func_ea=0x1000,
        pipeline=PIPELINE_FLOW,
        maturity=1,
    )
    assert tuple(rule.name for rule in active_1000) == ("AllowOnly1000",)

    active_2000 = svc.get_active_rules(
        project_name="proj",
        idb_key="idb",
        func_ea=0x2000,
        pipeline=PIPELINE_FLOW,
        maturity=1,
    )
    assert tuple(rule.name for rule in active_2000) == ("Deny1000",)

    wrong_maturity = svc.get_active_rules(
        project_name="proj",
        idb_key="idb",
        func_ea=0x1000,
        pipeline=PIPELINE_FLOW,
        maturity=2,
    )
    assert wrong_maturity == ()


def test_bundle_reuses_scope_and_adds_new_maturity():
    svc = RuleScopeService()
    rule_m1 = _DummyRule(name="R1", maturities=[1])
    rule_m2 = _DummyRule(name="R2", maturities=[2])
    svc.compile_base_rules(
        project_name="proj",
        instruction_rules=(),
        flow_rules=(rule_m1, rule_m2),
        ctree_rules=(),
    )

    m1 = svc.get_active_rules(
        project_name="proj",
        idb_key="idb",
        func_ea=0x401000,
        pipeline=PIPELINE_FLOW,
        maturity=1,
    )
    assert tuple(rule.name for rule in m1) == ("R1",)
    assert svc.active_cache_size == 1

    m2 = svc.get_active_rules(
        project_name="proj",
        idb_key="idb",
        func_ea=0x401000,
        pipeline=PIPELINE_FLOW,
        maturity=2,
    )
    assert tuple(rule.name for rule in m2) == ("R2",)
    assert svc.active_cache_size == 1


def test_partial_invalidation_removes_only_target_functions():
    svc = RuleScopeService()
    rule = _DummyRule(name="R", maturities=[1])
    svc.compile_base_rules(
        project_name="proj",
        instruction_rules=(rule,),
        flow_rules=(),
        ctree_rules=(),
    )

    svc.get_active_rules(
        project_name="proj",
        idb_key="idb",
        func_ea=0x1000,
        pipeline=PIPELINE_INSTRUCTION,
        maturity=1,
    )
    svc.get_active_rules(
        project_name="proj",
        idb_key="idb",
        func_ea=0x2000,
        pipeline=PIPELINE_INSTRUCTION,
        maturity=1,
    )
    assert svc.active_cache_size == 2

    svc.invalidate(
        RuleScopeInvalidation(
            reason=RuleScopeEvent.FUNCTION_OVERRIDE_UPDATED,
            func_eas=frozenset({0x1000}),
        )
    )
    assert svc.active_cache_size == 1


def test_event_emitter_full_invalidation_on_project_reload():
    svc = RuleScopeService()
    emitter: EventEmitter = EventEmitter()
    svc.attach(emitter)

    rule = _DummyRule(name="R", maturities=[1])
    svc.compile_base_rules(
        project_name="proj",
        instruction_rules=(rule,),
        flow_rules=(),
        ctree_rules=(),
    )
    svc.get_active_rules(
        project_name="proj",
        idb_key="idb",
        func_ea=0x1000,
        pipeline=PIPELINE_INSTRUCTION,
        maturity=1,
    )
    assert svc.active_cache_size == 1
    generation_before = svc.generation

    emitter.emit(
        RuleScopeEvent.PROJECT_RULES_RELOADED,
        RuleScopeInvalidation(
            reason=RuleScopeEvent.PROJECT_RULES_RELOADED,
            project_name="proj",
        ),
    )

    assert svc.generation == generation_before + 1
    assert svc.active_cache_size == 0


def test_overlay_provider_filters_enabled_and_disabled_rules():
    svc = RuleScopeService()
    rule_a = _DummyRule(name="RuleA", maturities=[1])
    rule_b = _DummyRule(name="RuleB", maturities=[1])
    svc.compile_base_rules(
        project_name="proj",
        instruction_rules=(rule_a, rule_b),
        flow_rules=(),
        ctree_rules=(),
    )

    svc.set_overlay_provider(
        lambda ea: FunctionRuleOverlay(
            enabled_rules=frozenset({"RuleA"}),
            disabled_rules=frozenset({"RuleB"}),
        )
        if ea == 0x1337
        else None
    )

    filtered = svc.get_active_rules(
        project_name="proj",
        idb_key="idb",
        func_ea=0x1337,
        pipeline=PIPELINE_INSTRUCTION,
        maturity=1,
    )
    assert tuple(rule.name for rule in filtered) == ("RuleA",)


def test_overlay_cache_is_refreshed_by_function_override_invalidation():
    svc = RuleScopeService()
    rule_a = _DummyRule(name="RuleA", maturities=[1])
    rule_b = _DummyRule(name="RuleB", maturities=[1])
    svc.compile_base_rules(
        project_name="proj",
        instruction_rules=(rule_a, rule_b),
        flow_rules=(),
        ctree_rules=(),
    )
    overlays = {
        0x2000: FunctionRuleOverlay(enabled_rules=frozenset({"RuleA"})),
    }
    svc.set_overlay_provider(lambda ea: overlays.get(ea))

    first = svc.get_active_rules(
        project_name="proj",
        idb_key="idb",
        func_ea=0x2000,
        pipeline=PIPELINE_INSTRUCTION,
        maturity=1,
    )
    assert tuple(rule.name for rule in first) == ("RuleA",)

    overlays[0x2000] = FunctionRuleOverlay(enabled_rules=frozenset({"RuleB"}))
    svc.invalidate(
        RuleScopeInvalidation(
            reason=RuleScopeEvent.FUNCTION_OVERRIDE_UPDATED,
            func_eas=frozenset({0x2000}),
        )
    )

    second = svc.get_active_rules(
        project_name="proj",
        idb_key="idb",
        func_ea=0x2000,
        pipeline=PIPELINE_INSTRUCTION,
        maturity=1,
    )
    assert tuple(rule.name for rule in second) == ("RuleB",)


def test_overlay_precedence_over_project_config():
    svc = RuleScopeService()
    rule_a = _DummyRule(
        name="RuleA",
        maturities=[1],
        use_whitelist=True,
        whitelisted_function_ea_list=["0x3000"],
    )
    rule_b = _DummyRule(
        name="RuleB",
        maturities=[1],
        use_whitelist=True,
        whitelisted_function_ea_list=["0x3000"],
    )
    svc.compile_base_rules(
        project_name="proj",
        instruction_rules=(rule_a, rule_b),
        flow_rules=(),
        ctree_rules=(),
    )

    baseline = svc.get_active_rules(
        project_name="proj",
        idb_key="idb",
        func_ea=0x3000,
        pipeline=PIPELINE_INSTRUCTION,
        maturity=1,
    )
    assert tuple(rule.name for rule in baseline) == ("RuleA", "RuleB")

    svc.set_overlay_provider(
        lambda ea: FunctionRuleOverlay(enabled_rules=frozenset({"RuleB"}))
        if ea == 0x3000
        else None
    )
    svc.invalidate(
        RuleScopeInvalidation(
            reason=RuleScopeEvent.FUNCTION_OVERRIDE_UPDATED,
            func_eas=frozenset({0x3000}),
        )
    )
    overridden = svc.get_active_rules(
        project_name="proj",
        idb_key="idb",
        func_ea=0x3000,
        pipeline=PIPELINE_INSTRUCTION,
        maturity=1,
    )
    assert tuple(rule.name for rule in overridden) == ("RuleB",)


def test_event_emitter_partial_invalidation_on_function_override():
    svc = RuleScopeService()
    emitter: EventEmitter = EventEmitter()
    svc.attach(emitter)

    rule = _DummyRule(name="RuleA", maturities=[1])
    svc.compile_base_rules(
        project_name="proj",
        instruction_rules=(rule,),
        flow_rules=(),
        ctree_rules=(),
    )
    svc.get_active_rules(
        project_name="proj",
        idb_key="idb",
        func_ea=0x1111,
        pipeline=PIPELINE_INSTRUCTION,
        maturity=1,
    )
    svc.get_active_rules(
        project_name="proj",
        idb_key="idb",
        func_ea=0x2222,
        pipeline=PIPELINE_INSTRUCTION,
        maturity=1,
    )
    assert svc.active_cache_size == 2
    generation_before = svc.generation

    emitter.emit(
        RuleScopeEvent.FUNCTION_OVERRIDE_UPDATED,
        RuleScopeInvalidation(
            reason=RuleScopeEvent.FUNCTION_OVERRIDE_UPDATED,
            func_eas=frozenset({0x1111}),
        ),
    )
    assert svc.generation == generation_before + 1
    assert svc.active_cache_size == 1
