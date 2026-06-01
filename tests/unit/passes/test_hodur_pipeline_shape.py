"""§1a acceptance (structural): HodurFamily.pipeline_for IS the real call graph.

This is the "does the running code look like the north-star pseudocode" gate at the unit level:
the family returns the five named PassSpecs in order, each builds a PipelinePass, and every pass
runs end-to-end over a portable (null) context returning a well-formed PassResult. Skeleton
transforms emit empty PatchPlans; the shape is what this locks in.
"""
from __future__ import annotations

from d810.passes.pass_pipeline import (
    FunctionPipelineContext,
    PassResult,
    PipelinePass,
    default,
    golden,
    live_mba,
    no_caps,
)
from d810.transforms.plan import PatchPlan
from d810.families.state_machine_cff.hodur_pipeline import HodurFamily

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
    for r in results[3:]:
        assert isinstance(r.rewrite_plan, PatchPlan)
        assert not r.rewrite_plan.operations if hasattr(r.rewrite_plan, "operations") else True


def test_detect_is_inert_until_wired():
    # The family stays a no-op match until recover_dispatcher carries detection (seam pending).
    assert HodurFamily().detect(graph=None, capabilities=None) is None
