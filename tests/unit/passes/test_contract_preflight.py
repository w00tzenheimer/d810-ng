from __future__ import annotations

from types import SimpleNamespace

from d810.analyses.value_flow.contract_evidence import contract_evidence_payload
from d810.passes.analysis_manager import AnalysisManager
from d810.passes.contract_preflight import (
    preflight_pass_contract,
    preflight_pipeline_contract,
)
from d810.passes.pass_pipeline import (
    FactRequirement,
    PassContract,
    PassOutputs,
    PassRequires,
    PassSpec,
    default,
    no_caps,
)


def _raising_factory():
    raise AssertionError("preflight must not instantiate pass factories")


def _spec(
    name: str,
    *,
    requires: PassRequires = PassRequires(),
    outputs: PassOutputs = PassOutputs(),
) -> PassSpec:
    return PassSpec(
        name,
        _raising_factory,
        no_caps,
        default,
        contract=PassContract(
            requires=requires,
            outputs=outputs,
        ),
    )


def test_preflight_missing_analysis_returns_structured_diagnostic():
    result = preflight_pass_contract(
        _spec("needs_domtree", requires=PassRequires(analyses=frozenset({"domtree"}))),
        AnalysisManager("G0"),
    )

    assert not result.satisfied
    assert len(result.diagnostics) == 1
    diagnostic = result.diagnostics[0]
    assert diagnostic.pass_id == "needs_domtree"
    assert diagnostic.namespace == "requires.analyses"
    assert diagnostic.missing == ("domtree",)


def test_preflight_missing_multiple_namespaces_returns_separate_diagnostics():
    spec = _spec(
        "needs_everything",
        requires=PassRequires(
            analyses=frozenset({"domtree"}),
            facts=FactRequirement(required=frozenset({"dispatcher_family"})),
            evidence=frozenset({"branch_targets"}),
        ),
    )

    result = preflight_pass_contract(spec, AnalysisManager("G0"))

    assert not result.satisfied
    assert [diagnostic.namespace for diagnostic in result.diagnostics] == [
        "requires.analyses",
        "requires.facts.required",
        "requires.evidence",
    ]
    assert [diagnostic.missing for diagnostic in result.diagnostics] == [
        ("domtree",),
        ("dispatcher_family",),
        ("branch_targets",),
    ]


def test_preflight_available_analysis_providers_do_not_compute():
    calls: list[str] = []
    facts = AnalysisManager(
        "G0",
        providers={
            "domtree": lambda graph: calls.append("computed") or object(),
        },
    )
    spec = _spec(
        "needs_postdom",
        requires=PassRequires(analyses=frozenset({"postdomtree"})),
    )

    result = preflight_pass_contract(spec, facts)

    assert calls == []
    assert result.diagnostics[0].available == ("domtree",)


def test_preflight_published_and_visible_live_facts_and_evidence_satisfy_requirements():
    observation = SimpleNamespace(
        kind="dispatcher_family",
        payload=contract_evidence_payload("branch_targets"),
    )
    facts = AnalysisManager(
        "G0",
        input_facts=SimpleNamespace(active_observations=(observation,)),
    )
    facts.put_fact("state_transition", object())
    facts.put_evidence("state_variable_writes")
    spec = _spec(
        "needs_live_context",
        requires=PassRequires(
            facts=FactRequirement(
                required=frozenset({"dispatcher_family", "state_transition"})
            ),
            evidence=frozenset({"branch_targets", "state_variable_writes"}),
        ),
    )

    result = preflight_pass_contract(spec, facts)

    assert result.satisfied
    assert result.diagnostics == ()


def test_preflight_aliases_legacy_facts_and_evidence_to_canonical_requirements():
    observation = SimpleNamespace(
        kind="dispatcher_family",
        payload=contract_evidence_payload("branch_targets"),
    )
    facts = AnalysisManager(
        "G0",
        input_facts=SimpleNamespace(active_observations=(observation,)),
    )
    facts.put_fact("state_transition", object())
    facts.put_evidence("state_variable_writes")
    spec = _spec(
        "needs_canonical_context",
        requires=PassRequires(
            facts=FactRequirement(
                required=frozenset(
                    {"recovered.state_transition", "role.dispatcher"}
                )
            ),
            evidence=frozenset({"ir.branch_target", "ir.state_variable_write"}),
        ),
    )

    result = preflight_pass_contract(spec, facts)

    assert result.satisfied
    assert result.diagnostics == ()


def test_preflight_optional_facts_missing_do_not_fail():
    result = preflight_pass_contract(
        _spec(
            "optional_carrier",
            requires=PassRequires(
                facts=FactRequirement(optional=frozenset({"carrier_store_candidates"}))
            ),
        ),
        object(),
    )

    assert result.satisfied
    assert result.diagnostics == ()


def test_pipeline_preflight_declared_outputs_can_satisfy_later_fact_requirement():
    facts = AnalysisManager("G0")
    first = _spec(
        "produce_transition",
        outputs=PassOutputs(facts=frozenset({"state_transition"})),
    )
    second = _spec(
        "consume_transition",
        requires=PassRequires(
            facts=FactRequirement(required=frozenset({"state_transition"}))
        ),
    )

    result = preflight_pipeline_contract((first, second), facts)

    assert result.satisfied
    assert [item.satisfied for item in result.results] == [True, True]
    assert facts.available_facts() == ()


def test_pipeline_preflight_declared_canonical_outputs_satisfy_legacy_requirement():
    facts = AnalysisManager("G0")
    first = _spec(
        "produce_transition",
        outputs=PassOutputs(facts=frozenset({"recovered.state_transition"})),
    )
    second = _spec(
        "consume_transition",
        requires=PassRequires(
            facts=FactRequirement(required=frozenset({"state_transition"}))
        ),
    )

    result = preflight_pipeline_contract((first, second), facts)

    assert result.satisfied
    assert [item.satisfied for item in result.results] == [True, True]


def test_pipeline_preflight_declared_outputs_can_satisfy_later_evidence_requirement():
    facts = AnalysisManager("G0")
    first = _spec(
        "produce_branch_targets",
        outputs=PassOutputs(evidence=frozenset({"branch_targets"})),
    )
    second = _spec(
        "consume_branch_targets",
        requires=PassRequires(evidence=frozenset({"branch_targets"})),
    )

    result = preflight_pipeline_contract((first, second), facts)

    assert result.satisfied
    assert [item.satisfied for item in result.results] == [True, True]
    assert facts.available_evidence() == ()


def test_pipeline_preflight_can_disable_declared_output_overlay():
    first = _spec(
        "produce_transition",
        outputs=PassOutputs(facts=frozenset({"state_transition"})),
    )
    second = _spec(
        "consume_transition",
        requires=PassRequires(
            facts=FactRequirement(required=frozenset({"state_transition"}))
        ),
    )

    result = preflight_pipeline_contract(
        (first, second),
        AnalysisManager("G0"),
        include_declared_outputs=False,
    )

    assert not result.satisfied
    assert result.diagnostics[0].pass_id == "consume_transition"
    assert result.diagnostics[0].namespace == "requires.facts.required"
    assert result.diagnostics[0].missing == ("state_transition",)


def test_pipeline_preflight_can_disable_declared_evidence_output_overlay():
    first = _spec(
        "produce_branch_targets",
        outputs=PassOutputs(evidence=frozenset({"branch_targets"})),
    )
    second = _spec(
        "consume_branch_targets",
        requires=PassRequires(evidence=frozenset({"branch_targets"})),
    )

    result = preflight_pipeline_contract(
        (first, second),
        AnalysisManager("G0"),
        include_declared_outputs=False,
    )

    assert not result.satisfied
    assert result.diagnostics[0].pass_id == "consume_branch_targets"
    assert result.diagnostics[0].namespace == "requires.evidence"
    assert result.diagnostics[0].missing == ("branch_targets",)


def test_pipeline_preflight_existing_fact_satisfies_when_declared_overlay_disabled():
    facts = AnalysisManager("G0")
    facts.put_fact("state_transition", object())
    first = _spec(
        "produce_transition",
        outputs=PassOutputs(facts=frozenset({"state_transition"})),
    )
    second = _spec(
        "consume_transition",
        requires=PassRequires(
            facts=FactRequirement(required=frozenset({"state_transition"}))
        ),
    )

    result = preflight_pipeline_contract(
        (first, second),
        facts,
        include_declared_outputs=False,
    )

    assert result.satisfied
    assert facts.available_facts() == ("state_transition",)


def test_preflight_custom_facts_view_without_available_methods_reports_empty_available():
    class _Facts:
        def has_analysis(self, name):
            return False

    result = preflight_pass_contract(
        _spec("needs_domtree", requires=PassRequires(analyses=frozenset({"domtree"}))),
        _Facts(),
    )

    assert result.diagnostics[0].available == ()


def test_preflight_custom_facts_view_missing_has_method_reports_diagnostic():
    spec = _spec(
        "needs_contract",
        requires=PassRequires(
            analyses=frozenset({"domtree"}),
            facts=FactRequirement(required=frozenset({"dispatcher_family"})),
            evidence=frozenset({"branch_targets"}),
        ),
    )

    result = preflight_pass_contract(spec, object())

    assert not result.satisfied
    assert [diagnostic.namespace for diagnostic in result.diagnostics] == [
        "requires.analyses",
        "requires.facts.required",
        "requires.evidence",
    ]
    assert [diagnostic.detail for diagnostic in result.diagnostics] == [
        "facts view does not support has_analysis",
        "facts view does not support has_fact",
        "facts view does not support has_evidence",
    ]


def test_preflight_does_not_instantiate_or_run_pass_factory():
    result = preflight_pipeline_contract(
        (
            _spec("first"),
            _spec(
                "second",
                requires=PassRequires(
                    facts=FactRequirement(required=frozenset({"state_transition"}))
                ),
            ),
        ),
        AnalysisManager("G0"),
    )

    assert not result.satisfied
    assert result.diagnostics[0].pass_id == "second"
