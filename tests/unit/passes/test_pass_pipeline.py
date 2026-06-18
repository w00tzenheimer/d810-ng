"""Phase A pipeline-vocabulary conformance (pure-Python, no IDA)."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from d810.ir.maturity import IRMaturity
from d810.passes import pass_pipeline as pp
from d810.passes.scheduler import RunLater
from d810.transforms.plan import PatchPlan


def test_defaults():
    assert pp.PassResult().rewrite_plan == PatchPlan()
    assert pp.PassResult().run_later == ()
    assert pp.PassResult().analysis_outputs == {}
    assert pp.CapabilityPolicy().required == frozenset()
    assert pp.SafetyPolicy().name == "default"
    assert pp.SafetyPolicy().golden_required is False


def test_pass_result_analysis_outputs_is_read_only():
    result = pp.PassResult(analysis_outputs={"domtree": "D"})
    assert result.analysis_outputs["domtree"] == "D"
    with pytest.raises(TypeError):
        result.analysis_outputs["domtree"] = "changed"


def test_rewriteplan_alias_is_patchplan():
    assert pp.RewritePlan is PatchPlan


def test_preserved_analyses():
    assert pp.PassResult().preserved.preserves("anything") is True  # default all
    assert pp.PassResult().preserved_explicit is False
    assert (
        pp.PassResult(preserved=pp.PreservedAnalyses.none()).preserved_explicit
        is True
    )
    assert pp.PreservedAnalyses.none().preserves("x") is False
    keep = pp.PreservedAnalyses.preserving({"dominators"})
    assert keep.preserves("dominators") is True
    assert keep.preserves("scc") is False


def test_pass_result_accepts_run_later_requests():
    request = RunLater(at=IRMaturity.GLOBAL_ANALYZED, reason="later facts")
    result = pp.PassResult(run_later=(request,))
    assert result.run_later == (request,)


def test_pipeline_pass_conformance():
    class _FakePass:
        name = "fake"

        def run(self, ctx):
            return pp.PassResult()

    assert isinstance(_FakePass(), pp.PipelinePass)


def test_mutation_backend_conformance():
    class _FakeBackend:
        def apply(self, rewrite_plan, live_source, safety_policy):
            return SimpleNamespace()  # stands in for a FlowGraph

    assert isinstance(_FakeBackend(), pp.MutationBackend)


def test_function_source_conformance():
    src = SimpleNamespace(flow_graph=object(), func_ea=0x1000, live_source=object())
    assert isinstance(src, pp.FunctionSource)


def test_pass_spec_factory_builds_a_pass():
    class _FakePass:
        name = "fake"

        def run(self, ctx):
            return pp.PassResult()

    spec = pp.PassSpec("fake", _FakePass, pp.no_caps, pp.default)
    built = spec.pass_factory()
    assert isinstance(built, pp.PipelinePass)
    assert spec.requirements.required == frozenset()
    assert spec.safety_policy.name == "default"


def test_pass_spec_exposes_pipeline_config_v2_defaults():
    class _FakePass:
        name = "fake"

        def run(self, ctx):
            return pp.PassResult()

    spec = pp.PassSpec("fake", _FakePass, pp.no_caps, pp.default)

    assert spec.pass_id == "fake"
    assert spec.config.pass_id == "fake"
    assert spec.config.granularity is pp.PassGranularity.FUNCTION
    assert spec.config.scheduler_policy is pp.SchedulerPolicy.WORKLIST
    assert spec.config.backend_route is pp.BackendRoute.MUTATION_BACKEND
    assert spec.config.requirements is spec.requirements
    assert spec.config.safety_policy is spec.safety_policy
    assert spec.enabled_at(IRMaturity.CANONICAL) is True


def test_pass_spec_maturity_gates_are_explicit():
    class _FakePass:
        name = "fake"

        def run(self, ctx):
            return pp.PassResult()

    spec = pp.PassSpec(
        "fake",
        _FakePass,
        pp.no_caps,
        pp.default,
        maturity_gates=frozenset({IRMaturity.GLOBAL_ANALYZED}),
    )

    assert spec.enabled_at(IRMaturity.CANONICAL) is False
    assert spec.enabled_at(IRMaturity.GLOBAL_ANALYZED) is True


def test_pipeline_config_roundtrip_preserves_contract_fields():
    config = pp.PipelineConfig(
        pass_id="recover_dispatcher",
        maturity_gates=frozenset(
            {IRMaturity.CALL_MODELED, IRMaturity.GLOBAL_ANALYZED}
        ),
        granularity=pp.PassGranularity.CFG,
        requirements=pp.CapabilityPolicy(
            required=frozenset({"emulation", "live_mba"})
        ),
        analyses=pp.AnalysisContract(
            required=frozenset({"range_evidence"}),
            provided=frozenset({"recover_dispatcher"}),
        ),
        preservation=pp.PreservedAnalyses.preserving({"range_evidence"}),
        scheduler_policy=pp.SchedulerPolicy.REPLAY_AFTER_PIPELINE,
        backend_route=pp.BackendRoute.ANALYSIS_ONLY,
        safety_policy=pp.SafetyPolicy(name="golden", golden_required=True),
    )

    payload = config.to_dict()
    assert payload["granularity"] == "cfg"
    assert payload["scheduler_policy"] == "replay_after_pipeline"
    assert payload["backend_route"] == "analysis_only"
    assert pp.PipelineConfig.from_dict(payload) == config


def test_pipeline_config_parses_enum_names_and_maturity_values():
    config = pp.PipelineConfig.from_dict(
        {
            "pass_id": "recover_dispatcher",
            "maturity_gates": ["CALL_MODELED", "ir.global.analyzed"],
            "granularity": "FUNCTION",
            "scheduler_policy": "WORKLIST",
            "backend_route": "MUTATION_BACKEND",
        }
    )

    assert config.maturity_gates == frozenset(
        {IRMaturity.CALL_MODELED, IRMaturity.GLOBAL_ANALYZED}
    )
    assert config.granularity is pp.PassGranularity.FUNCTION
    assert config.scheduler_policy is pp.SchedulerPolicy.WORKLIST
    assert config.backend_route is pp.BackendRoute.MUTATION_BACKEND


def test_pipeline_config_rejects_invalid_enum_and_maturity_values():
    with pytest.raises(pp.PipelineConfigError, match="scheduler_policy"):
        pp.PipelineConfig.from_dict(
            {"pass_id": "recover_dispatcher", "scheduler_policy": "later"}
        )
    with pytest.raises(pp.PipelineConfigError, match="maturity_gates"):
        pp.PipelineConfig.from_dict(
            {"pass_id": "recover_dispatcher", "maturity_gates": ["MMAT_GLBOPT1"]}
        )
    with pytest.raises(pp.PipelineConfigError, match="maturity_gates"):
        pp.PipelineConfig.from_dict(
            {"pass_id": "recover_dispatcher", "maturity_gates": "CALL_MODELED"}
        )
    with pytest.raises(pp.PipelineConfigError, match="safety_policy.name"):
        pp.PipelineConfig.from_dict(
            {
                "pass_id": "recover_dispatcher",
                "safety_policy": {"name": 123},
            }
        )
    with pytest.raises(pp.PipelineConfigError, match="safety_policy.name"):
        pp.PipelineConfig.from_dict(
            {
                "pass_id": "recover_dispatcher",
                "safety_policy": {"name": ""},
            }
        )


def test_analysis_contract_records_required_and_provided_keys():
    contract = pp.AnalysisContract(
        required=frozenset({"domtree"}),
        provided=frozenset({"state_transitions"}),
    )

    assert contract.required == frozenset({"domtree"})
    assert contract.provided == frozenset({"state_transitions"})


def test_authoring_singletons():
    assert pp.live_mba.required == frozenset({"live_mba"})
    assert pp.golden.golden_required is True
