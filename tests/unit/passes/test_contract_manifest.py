"""Native pass-contract manifest export tests."""
from __future__ import annotations

from d810.families.state_machine_cff.pipeline import standard_state_machine_passes
from d810.ir.maturity import IRMaturity
from d810.passes.contract_manifest import (
    pass_contract_manifest,
    pass_contract_diagnostic_manifest,
    pass_contract_preflight_manifest,
    pipeline_contract_manifest,
    pipeline_contract_preflight_manifest,
)
from d810.passes.contract_preflight import (
    PassContractPreflightResult,
    PipelineContractPreflightResult,
)
from d810.passes.driver import PassContractDiagnostic
from d810.passes.pass_pipeline import (
    AnalysisContract,
    FactRequirement,
    PassContract,
    PassInvalidates,
    PassOutputs,
    PassPreserves,
    PassRequires,
    PassSpec,
    PipelineConfig,
    default,
    no_caps,
)
from d810.passes.unflatten.state_machine import PlanSemanticRegions


def _manifest_by_pass_id() -> dict[str, dict[str, object]]:
    return {
        item["pass"]: item
        for item in pipeline_contract_manifest(standard_state_machine_passes())
    }


def test_transition_contract_manifest_uses_direct_yaml_shape():
    manifest = _manifest_by_pass_id()["recover_state_transitions"]

    assert manifest["pass"] == "recover_state_transitions"
    assert manifest["scope"] == "function"
    assert manifest["maturity"] == {
        "min": IRMaturity.CALL_MODELED.value,
        "max": IRMaturity.GLOBAL_ANALYZED.value,
        "preferred": IRMaturity.GLOBAL_ANALYZED.value,
    }
    assert manifest["requires"] == {
        "analyses": ["recover_dispatcher"],
        "evidence": ["branch_targets", "state_variable_writes"],
        "facts": {
            "required": ["dispatcher_family"],
            "optional": [],
        },
    }
    assert manifest["outputs"] == {"facts": ["state_transition"], "evidence": []}
    assert "runtime" in manifest
    assert "contract" not in manifest
    assert "pass_id" not in manifest


def test_lower_contract_manifest_exports_mutating_metadata():
    manifest = _manifest_by_pass_id()["lower_state_machine"]

    assert manifest["preserves"] == {
        "analyses": ["function_boundaries"],
        "facts": ["raw_instruction_addresses", "recovered_cfg_edge"],
    }
    assert manifest["invalidates"] == {
        "analyses": ["dominators", "loop_info", "postdominators", "regions"],
        "facts": ["stale_cfg_shape"],
    }
    assert manifest["safety"] == {
        "policy": "golden",
        "requires_oracle": True,
    }


def test_pipeline_contract_manifest_preserves_standard_pass_order():
    manifest = pipeline_contract_manifest(standard_state_machine_passes())

    assert tuple(item["pass"] for item in manifest) == (
        "recover_dispatcher",
        "recover_state_transitions",
        "plan_semantic_regions",
        "lower_state_machine",
        "cleanup_residual_dispatcher",
    )


def test_pass_contract_manifest_roundtrips_native_contract_shape():
    spec = standard_state_machine_passes()[3]
    manifest = pass_contract_manifest(spec)
    config = PipelineConfig.from_dict(manifest)

    assert config.pass_id == spec.pass_id
    assert config.contract == spec.contract


def test_manifest_keeps_analysis_evidence_and_fact_namespaces_separate():
    spec = PassSpec(
        "namespace_probe",
        PlanSemanticRegions,
        no_caps,
        default,
        analyses=AnalysisContract(required=frozenset({"legacy_analysis"})),
        contract=PassContract(
            preserves=PassPreserves(analyses=frozenset({"dominators"})),
            invalidates=PassInvalidates(facts=frozenset({"stale_cfg_shape"})),
        ),
    )

    manifest = pass_contract_manifest(spec)

    assert manifest["requires"] == {
        "analyses": [],
        "evidence": [],
        "facts": {
            "required": [],
            "optional": [],
        },
    }
    assert manifest["preserves"] == {
        "analyses": ["dominators"],
        "facts": [],
    }
    assert manifest["invalidates"] == {
        "analyses": [],
        "facts": ["stale_cfg_shape"],
    }
    assert manifest["runtime"]["analyses"]["required"] == ["legacy_analysis"]


def test_diagnostic_manifest_uses_stable_lists_and_keys():
    diagnostic = PassContractDiagnostic(
        pass_id="recover_state_transitions",
        namespace="requires.evidence",
        missing=("state_variable_writes", "branch_targets"),
        undeclared=("unexpected",),
        available=("state_variable_writes",),
        detail="facts view does not support has_evidence",
    )

    manifest = pass_contract_diagnostic_manifest(diagnostic)

    assert manifest == {
        "pass": "recover_state_transitions",
        "namespace": "requires.evidence",
        "missing": ["branch_targets", "state_variable_writes"],
        "undeclared": ["unexpected"],
        "available": ["state_variable_writes"],
        "detail": "facts view does not support has_evidence",
    }


def test_pass_preflight_manifest_preserves_contract_shape_and_adds_status_only():
    spec = PassSpec(
        "needs_transition",
        PlanSemanticRegions,
        no_caps,
        default,
        contract=PassContract(
            requires=PassRequires(
                evidence=frozenset({"branch_targets"}),
                facts=FactRequirement(required=frozenset({"dispatcher_family"})),
            ),
            outputs=PassOutputs(facts=frozenset({"state_transition"})),
        ),
    )
    diagnostic = PassContractDiagnostic(
        pass_id=spec.pass_id,
        namespace="requires.evidence",
        missing=("branch_targets",),
        available=("state_variable_writes",),
    )
    result = PassContractPreflightResult(
        pass_id=spec.pass_id,
        diagnostics=(diagnostic,),
        satisfied=False,
        declared_output_facts=("state_transition",),
    )

    manifest = pass_contract_preflight_manifest(spec, result)
    plain_manifest = pass_contract_manifest(spec)

    assert {
        key: value
        for key, value in manifest.items()
        if key != "preflight"
    } == plain_manifest
    assert manifest["preflight"] == {
        "satisfied": False,
        "declared_output_facts": ["state_transition"],
        "declared_output_evidence": [],
        "diagnostics": [
            {
                "pass": "needs_transition",
                "namespace": "requires.evidence",
                "missing": ["branch_targets"],
                "undeclared": [],
                "available": ["state_variable_writes"],
                "detail": "",
            },
        ],
    }


def test_pipeline_preflight_manifest_preserves_spec_order():
    specs = standard_state_machine_passes()[:2]
    result = PipelineContractPreflightResult(
        results=tuple(
            PassContractPreflightResult(
                pass_id=spec.pass_id,
                satisfied=True,
                declared_output_facts=tuple(sorted(spec.contract.outputs.facts)),
                declared_output_evidence=tuple(
                    sorted(spec.contract.outputs.evidence)
                ),
            )
            for spec in specs
        ),
        satisfied=True,
    )

    manifest = pipeline_contract_preflight_manifest(specs, result)

    assert tuple(item["pass"] for item in manifest) == (
        "recover_dispatcher",
        "recover_state_transitions",
    )
    assert [item["preflight"]["satisfied"] for item in manifest] == [True, True]


def test_pass_preflight_manifest_rejects_mismatched_pass_id():
    spec = standard_state_machine_passes()[0]
    result = PassContractPreflightResult(pass_id="other")

    try:
        pass_contract_preflight_manifest(spec, result)
    except ValueError as exc:
        assert "does not match" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_pipeline_preflight_manifest_rejects_length_mismatch():
    specs = standard_state_machine_passes()[:2]
    result = PipelineContractPreflightResult(
        results=(PassContractPreflightResult(pass_id=specs[0].pass_id),)
    )

    try:
        pipeline_contract_preflight_manifest(specs, result)
    except ValueError as exc:
        assert "length does not match" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_pipeline_preflight_manifest_rejects_ordered_pass_id_mismatch():
    specs = standard_state_machine_passes()[:2]
    result = PipelineContractPreflightResult(
        results=(
            PassContractPreflightResult(pass_id=specs[0].pass_id),
            PassContractPreflightResult(pass_id="wrong_second"),
        )
    )

    try:
        pipeline_contract_preflight_manifest(specs, result)
    except ValueError as exc:
        assert "does not match" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_preflight_manifest_does_not_instantiate_pass_factory_and_roundtrips_config():
    def _raising_factory():
        raise AssertionError("manifest rendering must not instantiate pass factories")

    spec = PassSpec(
        "manifest_probe",
        _raising_factory,
        no_caps,
        default,
        contract=PassContract(
            requires=PassRequires(analyses=frozenset({"domtree"})),
        ),
    )
    result = PassContractPreflightResult(pass_id=spec.pass_id, satisfied=True)

    manifest = pass_contract_preflight_manifest(spec, result)
    config = PipelineConfig.from_dict(manifest)

    assert manifest["preflight"] == {
        "satisfied": True,
        "declared_output_facts": [],
        "declared_output_evidence": [],
        "diagnostics": [],
    }
    assert config.pass_id == spec.pass_id
    assert config.contract == spec.contract
