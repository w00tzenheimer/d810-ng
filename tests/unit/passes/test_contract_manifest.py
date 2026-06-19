"""Native pass-contract manifest export tests."""
from __future__ import annotations

from d810.families.state_machine_cff.pipeline import standard_state_machine_passes
from d810.ir.maturity import IRMaturity
from d810.passes.contract_manifest import (
    pass_contract_manifest,
    pipeline_contract_manifest,
)
from d810.passes.pass_pipeline import (
    AnalysisContract,
    PassContract,
    PassInvalidates,
    PassPreserves,
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
    assert manifest["outputs"] == {"facts": ["state_transition"]}
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
