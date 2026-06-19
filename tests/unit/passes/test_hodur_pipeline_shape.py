"""unflatten acceptance (structural): HodurFamily.pipeline_for IS the real call graph.

This is the "does the running code look like the north-star pseudocode" gate at the unit level:
the family returns the five named PassSpecs in order, each builds a PipelinePass, and every pass
runs end-to-end over a portable (null) context returning a well-formed PassResult. Skeleton
transforms emit empty PatchPlans; the shape is what this locks in.
"""
from __future__ import annotations

from d810.passes.pass_pipeline import (
    FunctionPipelineContext,
    PassFact,
    PassScope,
    PassResult,
    PipelinePass,
    default,
    golden,
    live_mba,
    no_caps,
)
from d810.ir.maturity import IRMaturity
from d810.transforms.plan import PatchPlan
from d810.families.state_machine_cff import HodurFamily

EXPECTED = (
    ("recover_dispatcher", live_mba, default),
    ("recover_state_transitions", live_mba, default),
    ("plan_semantic_regions", no_caps, default),
    ("lower_state_machine", no_caps, golden),
    ("cleanup_residual_dispatcher", no_caps, golden),
)


def _null_ctx() -> FunctionPipelineContext:
    return FunctionPipelineContext(
        source=None, graph=None, maturity=None, project_config=None, facts=None
    )


def test_pipeline_for_returns_the_five_named_passes_in_order():
    specs = HodurFamily().pipeline_for(match=None, context=None)
    assert tuple(s.name for s in specs) == tuple(e[0] for e in EXPECTED)


def test_each_spec_carries_the_north_star_policies():
    specs = HodurFamily().pipeline_for(match=None, context=None)
    for spec, (name, caps, safety) in zip(specs, EXPECTED):
        assert spec.requirements is caps, name
        assert spec.safety_policy is safety, name


def test_each_spec_carries_native_state_machine_contract():
    specs = HodurFamily().pipeline_for(match=None, context=None)
    contracts = {spec.name: spec.contract for spec in specs}

    for spec in specs:
        assert spec.contract.scope is PassScope.FUNCTION
        assert spec.contract.maturity.min is IRMaturity.CALL_MODELED
        assert spec.contract.maturity.max is IRMaturity.GLOBAL_ANALYZED
        assert spec.contract.maturity.preferred is IRMaturity.GLOBAL_ANALYZED
        assert not spec.contract.requires.evidence

    assert contracts["recover_dispatcher"].outputs.facts == frozenset(
        {"dispatcher_family"}
    )
    assert contracts["recover_state_transitions"].requires.analyses == frozenset(
        {"recover_dispatcher"}
    )
    assert contracts["recover_state_transitions"].outputs.facts == frozenset(
        {"state_transition"}
    )
    assert contracts["plan_semantic_regions"].requires.analyses == frozenset(
        {"recover_dispatcher", "transition_result"}
    )
    assert contracts["plan_semantic_regions"].outputs.facts == frozenset(
        {"semantic_region"}
    )
    assert contracts["lower_state_machine"].requires.analyses == frozenset(
        {"plan_semantic_regions", "recover_dispatcher", "transition_result"}
    )
    assert contracts["lower_state_machine"].outputs.facts == frozenset(
        {"recovered_cfg_edge"}
    )
    assert contracts["lower_state_machine"].invalidates.facts == frozenset(
        {"stale_cfg_shape"}
    )


def test_state_machine_specs_are_maturity_range_gated():
    specs = HodurFamily().pipeline_for(match=None, context=None)

    assert all(spec.enabled_at(IRMaturity.CALL_MODELED) for spec in specs)
    assert all(spec.enabled_at(IRMaturity.GLOBAL_ANALYZED) for spec in specs)
    assert not any(spec.enabled_at(IRMaturity.LOCAL_OPTIMIZED) for spec in specs)
    assert not any(spec.enabled_at(None) for spec in specs)


def test_each_pass_factory_builds_a_pipeline_pass():
    for spec in HodurFamily().pipeline_for(match=None, context=None):
        p = spec.pass_factory()
        assert isinstance(p, PipelinePass)
        assert p.name == spec.name


def test_full_pipeline_runs_end_to_end_on_a_portable_context():
    ctx = _null_ctx()
    results = [spec.pass_factory().run(ctx) for spec in HodurFamily().pipeline_for(None, None)]
    assert all(isinstance(r, PassResult) for r in results)
    # analysis passes (#1-#3) carry facts; transform passes (#4-#5) carry an empty plan.
    assert results[0].facts and results[1].facts and results[2].facts
    assert all(isinstance(fact, PassFact) for r in results for fact in r.facts)
    assert tuple(fact.kind for fact in results[0].facts) == ("dispatcher_family",)
    assert tuple(fact.kind for fact in results[1].facts) == ("state_transition",)
    assert tuple(fact.kind for fact in results[2].facts) == ("semantic_region",)
    assert tuple(fact.kind for fact in results[3].facts) == ("recovered_cfg_edge",)
    for r in results[3:]:
        assert isinstance(r.rewrite_plan, PatchPlan)
        assert not r.rewrite_plan.operations if hasattr(r.rewrite_plan, "operations") else True


def test_detect_returns_none_without_a_dispatcher():
    # detect is real (portable equality-chain detector); no graph / no dispatcher -> no match.
    assert HodurFamily().detect(graph=None, capabilities=None) is None
    assert HodurFamily().detect(graph="not-a-graph", capabilities=None) is None
