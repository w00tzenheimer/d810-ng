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
    assert pp.PassResult().evidence_outputs == {}
    assert pp.CapabilityPolicy().required == frozenset()
    assert pp.SafetyPolicy().name == "default"
    assert pp.SafetyPolicy().golden_required is False
    assert pp.RuleSelection().to_dict() == {
        "include_groups": [],
        "include": [],
        "exclude_groups": [],
        "exclude": [],
        "options": {},
    }


def test_pass_result_analysis_outputs_is_read_only():
    result = pp.PassResult(analysis_outputs={"domtree": "D"})
    assert result.analysis_outputs["domtree"] == "D"
    with pytest.raises(TypeError):
        result.analysis_outputs["domtree"] = "changed"


def test_pass_result_evidence_outputs_is_read_only():
    result = pp.PassResult(evidence_outputs={"branch_targets": "E"})
    assert result.evidence_outputs["branch_targets"] == "E"
    with pytest.raises(TypeError):
        result.evidence_outputs["branch_targets"] = "changed"


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


def test_pipeline_config_roundtrip_preserves_native_pass_contract():
    contract = pp.PassContract(
        scope=pp.PassScope.FUNCTION,
        maturity=pp.MaturityRange(
            min=IRMaturity.CALL_MODELED,
            max=IRMaturity.GLOBAL_ANALYZED,
            preferred=IRMaturity.CALL_MODELED,
        ),
        requires=pp.PassRequires(
            capabilities=frozenset({"live_mba"}),
            analyses=frozenset({"def_use", "dominators"}),
            evidence=frozenset(
                {"state_variable_writes", "ir.memory_def.candidate"}
            ),
            facts=pp.FactRequirement(
                required=frozenset({"dispatcher_family"}),
                optional=frozenset({"effect.memory_def.observable"}),
            ),
        ),
        outputs=pp.PassOutputs(
            facts=frozenset({"state_transition"}),
            evidence=frozenset({"branch_targets", "ir.branch_cond.candidate"}),
        ),
        preserves=pp.PassPreserves(
            analyses=frozenset({"function_boundaries"}),
            facts=frozenset({"raw_instruction_addresses"}),
        ),
        invalidates=pp.PassInvalidates(
            analyses=frozenset({"dominators"}),
            facts=frozenset({"stale_cfg_shape"}),
        ),
        safety=pp.PassSafety(policy="guarded-rewrite", requires_oracle=False),
    )
    config = pp.PipelineConfig(pass_id="recover-state-machine", contract=contract)

    payload = config.to_dict()
    assert payload["contract"]["requires"]["capabilities"] == ["live_mba"]
    assert payload["contract"]["requires"]["evidence"] == [
        "ir.memory_def.candidate",
        "state_variable_writes",
    ]
    assert payload["contract"]["outputs"]["evidence"] == [
        "branch_targets",
        "ir.branch_cond.candidate",
    ]
    assert pp.PipelineConfig.from_dict(payload) == config


def test_pipeline_config_roundtrip_preserves_rule_selection_metadata():
    config = pp.PipelineConfig(
        pass_id="mba-simplify",
        contract=pp.PassContract(scope=pp.PassScope.EXPRESSION),
        rules=pp.RuleSelection(
            include_groups=frozenset({"legacy.default_instruction_only"}),
            include=frozenset({"FoldReadonlyDataRule", "Add_OllvmRule_1"}),
            exclude_groups=frozenset({"experimental"}),
            exclude=frozenset({"UnsafeRule"}),
            options={
                "FoldReadonlyDataRule": {"fold_writable_constants": True},
                "Z3ConstantOptimization": {
                    "min_nb_opcode": 4,
                    "min_nb_constant": 3,
                },
            },
        ),
    )

    payload = config.to_dict()

    assert payload["rules"] == {
        "include_groups": ["legacy.default_instruction_only"],
        "include": ["Add_OllvmRule_1", "FoldReadonlyDataRule"],
        "exclude_groups": ["experimental"],
        "exclude": ["UnsafeRule"],
        "options": {
            "FoldReadonlyDataRule": {"fold_writable_constants": True},
            "Z3ConstantOptimization": {
                "min_nb_opcode": 4,
                "min_nb_constant": 3,
            },
        },
    }
    assert pp.PipelineConfig.from_dict(payload) == config


def test_pipeline_config_roundtrip_preserves_pass_options_metadata():
    config = pp.PipelineConfig(
        pass_id="jump-fixer",
        contract=pp.PassContract(scope=pp.PassScope.BLOCK),
        options={
            "legacy_rule": "JumpFixer",
            "enabled_rules": ["JnzRule1", "JnzRule2"],
        },
    )

    payload = config.to_dict()

    assert payload["options"] == {
        "legacy_rule": "JumpFixer",
        "enabled_rules": ["JnzRule1", "JnzRule2"],
    }
    assert pp.PipelineConfig.from_dict(payload) == config


@pytest.mark.parametrize(
    ("payload", "field_name"),
    [
        ({"pass": "x", "rules": []}, "rules"),
        (
            {"pass": "x", "rules": {"include_groups": [1]}},
            "rules.include_groups",
        ),
        ({"pass": "x", "rules": {"include": "Add_OllvmRule_1"}}, "rules.include"),
        ({"pass": "x", "rules": {"exclude_groups": [1]}}, "rules.exclude_groups"),
        ({"pass": "x", "rules": {"exclude": [1]}}, "rules.exclude"),
        ({"pass": "x", "rules": {"options": []}}, "rules.options"),
        (
            {"pass": "x", "rules": {"options": {"FoldReadonlyDataRule": []}}},
            "rules.options.FoldReadonlyDataRule",
        ),
        (
            {
                "pass": "x",
                "rules": {
                    "options": {
                        "FoldReadonlyDataRule": {"fold_writable_constants": object()}
                    }
                },
            },
            "rules.options.FoldReadonlyDataRule.fold_writable_constants",
        ),
    ],
)
def test_pipeline_config_rejects_malformed_rule_selection_metadata(
    payload,
    field_name,
):
    with pytest.raises(pp.PipelineConfigError, match=field_name):
        pp.PipelineConfig.from_dict(payload)


@pytest.mark.parametrize(
    ("payload", "field_name"),
    [
        ({"pass": "x", "options": []}, "options"),
        ({"pass": "x", "options": {"": True}}, "options"),
        ({"pass": "x", "options": {1: True}}, "options"),
        ({"pass": "x", "options": {"enabled_rules": object()}}, "options.enabled_rules"),
    ],
)
def test_pipeline_config_rejects_malformed_pass_options_metadata(
    payload,
    field_name,
):
    with pytest.raises(pp.PipelineConfigError, match=field_name):
        pp.PipelineConfig.from_dict(payload)


def test_pipeline_config_accepts_direct_native_contract_yaml_shape():
    config = pp.PipelineConfig.from_dict(
        {
            "pass": "recover-state-machine",
            "scope": "function",
            "maturity": {
                "min": "ir.call.modeled",
                "max": "ir.global.analyzed",
                "preferred": "ir.call.modeled",
            },
            "requires": {
                "capabilities": ["live_mba"],
                "analyses": ["dominators"],
                "evidence": [
                    "dispatcher_predicates",
                    "ir.memory_def.candidate",
                    "ir.branch_cond.candidate",
                ],
                "facts": {
                    "required": [],
                    "optional": ["effect.memory_def.observable"],
                },
            },
            "outputs": {
                "facts": ["state_transition"],
                "evidence": ["branch_targets", "ir.induction_var.candidate"],
            },
            "preserves": {
                "analyses": ["dominators"],
                "facts": ["raw_instruction_addresses"],
            },
            "invalidates": {
                "analyses": ["postdominators"],
                "facts": ["stale_cfg_shape"],
            },
            "safety": {"policy": "guarded-rewrite", "requires_oracle": False},
        }
    )

    assert config.pass_id == "recover-state-machine"
    assert config.contract.scope is pp.PassScope.FUNCTION
    assert config.contract.requires.capabilities == frozenset({"live_mba"})
    assert config.contract.requires.analyses == frozenset({"dominators"})
    assert config.contract.requires.evidence == frozenset(
        {
            "dispatcher_predicates",
            "ir.memory_def.candidate",
            "ir.branch_cond.candidate",
        }
    )
    assert config.contract.outputs.evidence == frozenset(
        {"branch_targets", "ir.induction_var.candidate"}
    )
    assert config.contract.preserves.analyses == frozenset({"dominators"})
    assert config.contract.invalidates.facts == frozenset({"stale_cfg_shape"})
    assert config.safety_policy == pp.SafetyPolicy()
    assert config.contract.safety == pp.PassSafety(
        policy="guarded-rewrite",
        requires_oracle=False,
    )


def test_pipeline_config_accepts_user_facing_maturity_runs_at_shape():
    config = pp.PipelineConfig.from_dict(
        {
            "pass": "recover-state-machine",
            "maturity": {"runs_at": "ir.call.modeled"},
        }
    )

    assert config.contract.maturity == pp.MaturityRange(
        min=IRMaturity.CALL_MODELED,
        max=IRMaturity.CALL_MODELED,
        preferred=IRMaturity.CALL_MODELED,
    )
    assert config.enabled_at(IRMaturity.CALL_MODELED) is True
    assert config.enabled_at(IRMaturity.GLOBAL_ANALYZED) is False
    assert config.to_dict()["contract"]["maturity"] == {
        "min": "ir.call.modeled",
        "max": "ir.call.modeled",
        "preferred": "ir.call.modeled",
    }
    assert pp.PipelineConfig.from_dict(config.to_dict()) == config


def test_pipeline_config_accepts_user_facing_maturity_range_shape():
    config = pp.PipelineConfig.from_dict(
        {
            "pass": "recover-state-machine",
            "maturity": {
                "range": {
                    "min": "ir.call.modeled",
                    "max": "ir.global.analyzed",
                },
            },
        }
    )

    assert config.contract.maturity == pp.MaturityRange(
        min=IRMaturity.CALL_MODELED,
        max=IRMaturity.GLOBAL_ANALYZED,
        preferred=None,
    )
    assert config.enabled_at(IRMaturity.CALL_MODELED) is True
    assert config.enabled_at(IRMaturity.GLOBAL_ANALYZED) is True
    assert config.enabled_at(IRMaturity.LOCAL_OPTIMIZED) is False
    assert pp.PipelineConfig.from_dict(config.to_dict()) == config


@pytest.mark.parametrize(
    ("payload", "field_name"),
    [
        ({"pass": "x", "maturity": []}, "contract.maturity"),
        ({"pass": "x", "requires": []}, "requires"),
        ({"pass": "x", "requires": {"facts": []}}, "requires.facts"),
        ({"pass": "x", "outputs": []}, "outputs"),
        ({"pass": "x", "preserves": []}, "preserves"),
        ({"pass": "x", "invalidates": []}, "invalidates"),
        ({"pass": "x", "safety": []}, "safety"),
        ({"pass": "x", "contract": []}, "contract"),
        ({"pass": "x", "maturity": {"range": []}}, "maturity.range"),
    ],
)
def test_pipeline_config_rejects_malformed_native_contract_sections(
    payload,
    field_name,
):
    with pytest.raises(pp.PipelineConfigError, match=f"{field_name} must be a mapping"):
        pp.PipelineConfig.from_dict(payload)


@pytest.mark.parametrize(
    ("payload", "field_name"),
    [
        (
            {"pass": "x", "maturity": {"runs_at": "MMAT_GLBOPT1"}},
            "maturity.runs_at",
        ),
        (
            {
                "pass": "x",
                "maturity": {
                    "runs_at": "ir.call.modeled",
                    "range": {"min": "ir.call.modeled"},
                },
            },
            "maturity.runs_at",
        ),
        (
            {"pass": "x", "maturity": {"range": {}}},
            "maturity.range.min",
        ),
        (
            {
                "pass": "x",
                "maturity": {
                    "range": {"max": "ir.global.analyzed"},
                },
            },
            "maturity.range.min",
        ),
        (
            {
                "pass": "x",
                "maturity": {
                    "range": {"min": "ir.call.modeled"},
                },
            },
            "maturity.range.max",
        ),
        (
            {
                "pass": "x",
                "maturity": {
                    "range": {
                        "min": None,
                        "max": "ir.global.analyzed",
                    },
                },
            },
            "maturity.range.min",
        ),
        (
            {
                "pass": "x",
                "maturity": {
                    "range": {
                        "min": "ir.call.modeled",
                        "max": None,
                    },
                },
            },
            "maturity.range.max",
        ),
        (
            {
                "pass": "x",
                "maturity": {
                    "range": {
                        "min": None,
                        "max": None,
                    },
                },
            },
            "maturity.range.min",
        ),
        (
            {
                "pass": "x",
                "maturity": {
                    "range": {
                        "min": "MMAT_GLBOPT1",
                        "max": "ir.global.analyzed",
                    },
                },
            },
            "maturity.range.min",
        ),
        (
            {
                "pass": "x",
                "maturity": {
                    "range": {
                        "min": "ir.global.analyzed",
                        "max": "ir.call.modeled",
                    },
                },
            },
            "maturity.range.min",
        ),
        (
            {
                "pass": "x",
                "maturity": {
                    "range": {"min": "ir.call.modeled"},
                    "preferred": "ir.call.modeled",
                },
            },
            "maturity.range",
        ),
    ],
)
def test_pipeline_config_rejects_malformed_user_facing_maturity_shapes(
    payload,
    field_name,
):
    with pytest.raises(pp.PipelineConfigError, match=field_name):
        pp.PipelineConfig.from_dict(payload)


def test_pipeline_config_keeps_legacy_maturity_null_endpoint_compatibility():
    config = pp.PipelineConfig.from_dict(
        {
            "pass": "legacy",
            "maturity": {
                "min": None,
                "max": "ir.global.analyzed",
                "preferred": None,
            },
        }
    )

    assert config.contract.maturity == pp.MaturityRange(
        min=None,
        max=IRMaturity.GLOBAL_ANALYZED,
        preferred=None,
    )


@pytest.mark.parametrize(
    ("payload", "field_name"),
    [
        ({"pass": "x", "requires": {"capabilities": "live_mba"}}, "requires.capabilities"),
        ({"pass": "x", "requires": {"capabilities": [1]}}, "requires.capabilities"),
    ],
)
def test_pipeline_config_rejects_malformed_capability_requirements(
    payload,
    field_name,
):
    with pytest.raises(pp.PipelineConfigError, match=field_name):
        pp.PipelineConfig.from_dict(payload)


@pytest.mark.parametrize(
    ("payload", "field_name"),
    [
        ({"pass": "x", "outputs": {"evidence": "branch_targets"}}, "outputs.evidence"),
        ({"pass": "x", "outputs": {"evidence": [1]}}, "outputs.evidence"),
    ],
)
def test_pipeline_config_rejects_malformed_evidence_outputs(
    payload,
    field_name,
):
    with pytest.raises(pp.PipelineConfigError, match=field_name):
        pp.PipelineConfig.from_dict(payload)


def test_native_contract_keeps_analysis_evidence_and_fact_validity_separate():
    contract = pp.PassContract(
        preserves=pp.PassPreserves(analyses=frozenset({"dominators"})),
        invalidates=pp.PassInvalidates(
            facts=frozenset({"stale_cfg_shape", "raw_dispatcher_evidence"})
        ),
    )

    assert "dominators" in contract.preserves.analyses
    assert "dominators" not in contract.invalidates.facts
    assert "stale_cfg_shape" in contract.invalidates.facts
    assert contract.preserves.facts == frozenset()


def test_maturity_range_contains_and_validates_preferred():
    maturity = pp.MaturityRange(
        min=IRMaturity.CALL_MODELED,
        max=IRMaturity.GLOBAL_ANALYZED,
        preferred=IRMaturity.CALL_MODELED,
    )

    assert maturity.contains(IRMaturity.CALL_MODELED) is True
    assert maturity.contains(IRMaturity.GLOBAL_ANALYZED) is True
    assert maturity.contains(IRMaturity.LOCAL_OPTIMIZED) is False
    assert maturity.contains(IRMaturity.GLOBAL_OPTIMIZED) is False
    with pytest.raises(pp.PipelineConfigError, match="preferred"):
        pp.MaturityRange(
            min=IRMaturity.CALL_MODELED,
            max=IRMaturity.GLOBAL_ANALYZED,
            preferred=IRMaturity.GLOBAL_OPTIMIZED,
        )
    with pytest.raises(pp.PipelineConfigError, match="min"):
        pp.MaturityRange(
            min=IRMaturity.GLOBAL_ANALYZED,
            max=IRMaturity.CALL_MODELED,
        )


def test_pipeline_config_contract_maturity_range_does_not_break_legacy_gates():
    range_config = pp.PipelineConfig(
        pass_id="recover-state-machine",
        contract=pp.PassContract(
            maturity=pp.MaturityRange(
                min=IRMaturity.CALL_MODELED,
                max=IRMaturity.GLOBAL_ANALYZED,
                preferred=IRMaturity.CALL_MODELED,
            )
        ),
    )

    assert range_config.enabled_at(IRMaturity.CALL_MODELED) is True
    assert range_config.enabled_at(IRMaturity.GLOBAL_ANALYZED) is True
    assert range_config.enabled_at(IRMaturity.LOCAL_OPTIMIZED) is False
    assert range_config.enabled_at(IRMaturity.GLOBAL_OPTIMIZED) is False
    assert range_config.enabled_at(None) is False

    legacy_config = pp.PipelineConfig(
        pass_id="legacy",
        maturity_gates=frozenset({IRMaturity.GLOBAL_OPTIMIZED}),
        contract=range_config.contract,
    )

    assert legacy_config.enabled_at(IRMaturity.CALL_MODELED) is False
    assert legacy_config.enabled_at(IRMaturity.GLOBAL_OPTIMIZED) is True

    default_config = pp.PipelineConfig(pass_id="legacy-default")
    assert default_config.enabled_at(None) is True


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
