from dataclasses import dataclass, field

from d810.core.registry import EventEmitter
from d810.core.rule_scope import (
    EffectiveRuleScopeReport,
    FunctionRuleOverlay,
    PIPELINE_FLOW,
    PIPELINE_INSTRUCTION,
    RuleInferenceOverlay,
    RuleScopeEvent,
    RuleScopeInvalidation,
    RuleScopeService,
)


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
            reason=RuleScopeEvent.FUNCTION_TAGS_UPDATED,
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


def test_overlay_cache_is_refreshed_by_function_tag_invalidation():
    svc = RuleScopeService()
    tagged = _DummyRule(name="Tagged", maturities=[1], tags_any=["flat"])
    svc.compile_base_rules(
        project_name="proj",
        instruction_rules=(tagged,),
        flow_rules=(),
        ctree_rules=(),
    )
    overlays = {
        0x2000: FunctionRuleOverlay(function_tags=frozenset({"flat"})),
    }
    svc.set_overlay_provider(lambda ea: overlays.get(ea))

    first = svc.get_active_rules(
        project_name="proj",
        idb_key="idb",
        func_ea=0x2000,
        pipeline=PIPELINE_INSTRUCTION,
        maturity=1,
    )
    assert tuple(rule.name for rule in first) == ("Tagged",)

    overlays[0x2000] = FunctionRuleOverlay()
    svc.invalidate(
        RuleScopeInvalidation(
            reason=RuleScopeEvent.FUNCTION_TAGS_UPDATED,
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
    assert second == ()


def test_event_emitter_partial_invalidation_on_function_tags():
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
        RuleScopeEvent.FUNCTION_TAGS_UPDATED,
        RuleScopeInvalidation(
            reason=RuleScopeEvent.FUNCTION_TAGS_UPDATED,
            func_eas=frozenset({0x1111}),
        ),
    )
    assert svc.generation == generation_before + 1
    assert svc.active_cache_size == 1


def test_selector_consumes_function_tags_from_overlay():
    svc = RuleScopeService()
    rule_tagged = _DummyRule(name="Tagged", maturities=[1], tags_any=["flattened"])
    rule_plain = _DummyRule(name="Plain", maturities=[1])
    svc.compile_base_rules(
        project_name="proj",
        instruction_rules=(rule_tagged, rule_plain),
        flow_rules=(),
        ctree_rules=(),
    )
    svc.set_overlay_provider(
        lambda ea: (
            FunctionRuleOverlay(function_tags=frozenset({"flattened"}))
            if ea == 0x5555
            else None
        )
    )

    tagged_active = svc.get_active_rules(
        project_name="proj",
        idb_key="idb",
        func_ea=0x5555,
        pipeline=PIPELINE_INSTRUCTION,
        maturity=1,
    )
    assert tuple(rule.name for rule in tagged_active) == ("Tagged", "Plain")

    untagged_active = svc.get_active_rules(
        project_name="proj",
        idb_key="idb",
        func_ea=0x6666,
        pipeline=PIPELINE_INSTRUCTION,
        maturity=1,
    )
    assert tuple(rule.name for rule in untagged_active) == ("Plain",)


def test_active_inference_filters_targeted_scope_only():
    svc = RuleScopeService()
    rule_a = _DummyRule(name="RuleA", maturities=[1])
    rule_b = _DummyRule(name="RuleB", maturities=[1])
    svc.compile_base_rules(
        project_name="proj",
        instruction_rules=(rule_a, rule_b),
        flow_rules=(),
        ctree_rules=(),
    )
    svc.set_active_inference(
        RuleInferenceOverlay(
            name="targeted_inference",
            enabled_rules=frozenset({"RuleB"}),
            target_func_eas=frozenset({0x7000}),
        )
    )

    targeted = svc.get_active_rules(
        project_name="proj",
        idb_key="idb",
        func_ea=0x7000,
        pipeline=PIPELINE_INSTRUCTION,
        maturity=1,
    )
    assert tuple(rule.name for rule in targeted) == ("RuleA", "RuleB")

    untargeted = svc.get_active_rules(
        project_name="proj",
        idb_key="idb",
        func_ea=0x7001,
        pipeline=PIPELINE_INSTRUCTION,
        maturity=1,
    )
    assert tuple(rule.name for rule in untargeted) == ("RuleA", "RuleB")


def test_effective_scope_report_and_execution_share_one_decision_path():
    svc = RuleScopeService()
    active = _DummyRule(name="Active", maturities=[1])
    wrong_ea = _DummyRule(
        name="WrongEa",
        maturities=[1],
        use_whitelist=True,
        whitelisted_function_ea_list=[0x5000],
    )
    needs_tag = _DummyRule(name="NeedsTag", maturities=[1], tags_all=["flat"])
    suppressed = _DummyRule(name="Suppressed", maturities=[1])
    svc.compile_base_rules(
        project_name="proj",
        instruction_rules=(active, wrong_ea, needs_tag, suppressed),
        flow_rules=(),
        ctree_rules=(),
    )
    svc.set_active_inference(
        RuleInferenceOverlay(
            name="runtime-hint",
            disabled_rules=frozenset({"Suppressed", "StaleRule"}),
            target_func_eas=frozenset({0x401000}),
        )
    )

    report = svc.explain_effective_scope(
        project_name="proj",
        idb_key="sample.i64",
        func_ea=0x401000,
    )
    selected = svc.get_active_rules(
        project_name="proj",
        idb_key="sample.i64",
        func_ea=0x401000,
        pipeline=PIPELINE_INSTRUCTION,
        maturity=1,
    )

    assert isinstance(report, EffectiveRuleScopeReport)
    assert tuple(rule.name for rule in selected) == ("Active",)
    assert {
        decision.rule_name: (decision.active, decision.reason)
        for decision in report.decisions
    } == {
        "Active": (True, "active"),
        "WrongEa": (False, "selector-ea-not-allowed"),
        "NeedsTag": (False, "selector-tags-all-missing"),
        "Suppressed": (False, "inference-suppressed"),
    }
    assert report.inference_names == ("runtime-hint",)
    assert report.unknown_rule_names == ("StaleRule",)
    details = {decision.rule_name: decision.detail for decision in report.decisions}
    assert "0x401000" in details["WrongEa"]
    assert "flat" in details["NeedsTag"]
    assert "runtime-hint" in details["Suppressed"]


def test_hint_suppression_is_reported_without_private_function_rule_overlay():
    svc = RuleScopeService()
    rule = _DummyRule(name="Unsafe", maturities=[1])
    svc.compile_base_rules(
        project_name="proj",
        instruction_rules=(rule,),
        flow_rules=(),
        ctree_rules=(),
    )
    svc.apply_hints(
        type(
            "Hints",
            (),
            {
                "func_ea": 0x401000,
                "recommended_inferences": (),
                "suppress_rules": ("Unsafe", "RemovedRule"),
            },
        )()
    )

    report = svc.explain_effective_scope(
        project_name="proj",
        idb_key="sample.i64",
        func_ea=0x401000,
    )

    assert report.decisions[0].reason == "hint-suppressed"
    assert report.unknown_rule_names == ("RemovedRule",)


def test_effective_report_matches_execution_at_each_declared_maturity():
    svc = RuleScopeService()
    rules = (
        _DummyRule(name="M1", maturities=[1]),
        _DummyRule(name="M2", maturities=[2]),
        _DummyRule(name="Any"),
    )
    svc.compile_base_rules(
        project_name="proj",
        instruction_rules=rules,
        flow_rules=(),
        ctree_rules=(),
    )
    report = svc.explain_effective_scope(
        project_name="proj",
        idb_key="sample.i64",
        func_ea=0x401000,
    )

    for maturity in (1, 2):
        explained = tuple(
            decision.rule_name
            for decision in report.decisions
            if decision.pipeline == PIPELINE_INSTRUCTION
            and decision.active
            and (not decision.maturities or maturity in decision.maturities)
        )
        executed = tuple(
            rule.name
            for rule in svc.get_active_rules(
                project_name="proj",
                idb_key="sample.i64",
                func_ea=0x401000,
                pipeline=PIPELINE_INSTRUCTION,
                maturity=maturity,
            )
        )
        assert explained == executed
