from __future__ import annotations

import ast
from dataclasses import replace
import inspect
import json
from pathlib import Path

import d810.manager.rhad_generated_checksum as generated_reference
import pytest
from d810.manager.rhad_generated_checksum import (
    BOUNDARY_EXIT_EAS,
    IMPORTED_BLOCK_IDS,
    TEMPLATE_ROOT_EAS,
    build_rhad_generated_reference_plan,
    reference_batch_for_native_key,
)
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.ir.semantics import PredicateKind
from d810.transforms.fragment_plan import (
    FragmentReferencedImportedConditionalSelectEnvelope,
    FragmentSetccIndexedTableNormalization,
)
from d810.transforms.rhad_reference_compiler import RhadCompilerRejection
from tests.native_preanalysis import make_native_key


_REPO = Path(__file__).resolve().parents[4]


def _native_key():
    return make_native_key(
        input_identity=(
            "sha256:2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c"
        ),
        function_rva=0xA560,
    )


def test_checksum_producer_compiles_row17_scaled_lookup_reference() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(),
        evidence_generation=7,
    )

    operation = plan.operation("rhad:route@0x40A605")
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None
    assert plan.plan_id.endswith(batch.aggregate_program_identity)
    assert plan.block("native@0x40A5AE").semantic_anchor_ea == 0x40A5AE
    assert operation.predicate_anchor_ea == 0x40A5F6
    assert operation.computed_branch_normalization.condition_producer_ea == 0x40A5F0
    assert operation.computed_branch_normalization.unresolved_transfer_ea == 0x40A605
    assert plan.flag_corridors[0].consumer.instruction_ea == 0x40A5F6
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40B6C0",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40A607",
    }
    assert plan.native_bodies[0].block_ids == IMPORTED_BLOCK_IDS
    assert len(IMPORTED_BLOCK_IDS) == 56
    assert TEMPLATE_ROOT_EAS == (
        0x40A607,
        0x40B6C0,
        0x40A61B,
        0x40A68C,
        0x40A6B4,
        0x40A800,
        0x40A74C,
        0x40A766,
        0x40A9DE,
        0x40A77E,
        0x40ABC6,
        0x40A794,
        0x40A7AE,
        0x40AEE6,
    )
    assert tuple(operation.operation_id for operation in plan.operations) == (
        "rhad:route@0x40A605",
        "route:rhad-direct@0x40A619",
        "route:rhad-direct@0x40A68A",
        "rhad:route@0x40A6A4",
        "route:rhad-direct@0x40A74A",
        "rhad:route@0x40A764",
        "rhad:route@0x40A77C",
        "rhad:route@0x40A792",
        "rhad:route@0x40A7AC",
    )
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert tuple(payload["boundary_exit_eas"]) == (
        0x40A61B,
        0x40A68C,
        0x40B790,
    )
    direct = plan.operation("route:rhad-direct@0x40A619")
    assert direct.source_block_id == "native@0x40A615"
    assert direct.direct_transfer_rewrite.rewrite_anchor_ea == 0x40A619
    assert direct.direct_transfer_rewrite.owner_anchor_ea == 0x40A615
    assert direct.edges[0].target_block_id == "native@0x40A61B"
    native_body = plan.native_bodies[0]
    direct_sources = {
        candidate.source_block_id
        for candidate in plan.operations
        if candidate.direct_transfer_rewrite is not None
    }
    direct_payload = json.loads(
        direct.reference_route_authority.reference_route.reference_ledger_json
    )
    assert tuple(direct_payload["boundary_exit_eas"]) == (0x40A633, 0x40A74C)
    dependency = plan.operation("route:rhad-direct@0x40A68A")
    assert dependency.direct_transfer_rewrite.rewrite_anchor_ea == 0x40A68A
    assert dependency.edges[0].target_block_id == "native@0x40A68C"
    selected = plan.operation("rhad:route@0x40A6A4")
    assert selected.predicate_anchor_ea == 0x40A698
    selected_normalization = selected.computed_branch_normalization
    assert selected_normalization is not None
    assert selected_normalization.predicate_kind is PredicateKind.SLT
    assert selected_normalization.condition_producer_ea == 0x40A692
    assert selected_normalization.unresolved_transfer_ea == 0x40A6A4
    assert isinstance(
        selected_normalization.conditional_select_envelope,
        FragmentReferencedImportedConditionalSelectEnvelope,
    )
    selected_envelope = selected_normalization.conditional_select_envelope
    fourth_existing = plan.operation("rhad:route@0x40A764")
    fourth_existing_envelope = (
        fourth_existing.computed_branch_normalization.conditional_select_envelope
    )
    fourth = plan.operation("rhad:route@0x40A77C")
    sixth_existing = plan.operation("rhad:route@0x40A7AC")
    sixth_existing_envelope = (
        sixth_existing.computed_branch_normalization.conditional_select_envelope
    )
    operation_topology = direct_sources | {
        selected.source_block_id,
        selected_envelope.selected_value_block_id,
        selected_envelope.join_block_id,
        fourth_existing.source_block_id,
        fourth_existing_envelope.selected_value_block_id,
        fourth_existing_envelope.join_block_id,
        fourth.source_block_id,
        "native@0x40A77E",
        sixth_existing.source_block_id,
        sixth_existing_envelope.selected_value_block_id,
        sixth_existing_envelope.join_block_id,
    }
    preserved_sources = set(native_body.preserved_native_transfer_block_ids)
    assert operation_topology.isdisjoint(preserved_sources)
    assert operation_topology | preserved_sources == set(native_body.block_ids)
    assert {edge.role: edge.target_block_id for edge in selected.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40A6B4",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40A800",
    }
    assert selected.reference_route_authority is not None
    assert selected.reference_route_authority.reference_route.true_target_ea == 0x40A6A6
    fourth_direct = plan.operation("route:rhad-direct@0x40A74A")
    assert fourth_direct.edges[0].target_block_id == "native@0x40A74C"
    assert {edge.role: edge.target_block_id for edge in fourth_existing.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40A766",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40A9DE",
    }
    assert isinstance(
        fourth.computed_branch_normalization,
        FragmentSetccIndexedTableNormalization,
    )
    assert fourth.computed_branch_normalization.condition_producer_ea == 0x40A768
    assert fourth.computed_branch_normalization.table_evidence.table_base_ea == 0x48B81C
    assert (
        fourth.computed_branch_normalization.table_evidence.true_entry.decoded_target_ea
        == 0x40A77E
    )
    assert (
        fourth.computed_branch_normalization.table_evidence.false_entry.decoded_target_ea
        == 0x40ABC6
    )
    fifth = plan.operation("rhad:route@0x40A792")
    fifth_evidence = fifth.computed_branch_normalization.table_evidence
    assert fifth.computed_branch_normalization.predicate_kind is PredicateKind.SGE
    assert fifth_evidence.index_scaling.kind.value == "scaled_lookup"
    assert fifth_evidence.index_scaling.lookup_ea == 0x40A789
    assert fifth_evidence.index_scaling.scale_bytes == 8
    assert fifth_evidence.true_entry.decoded_target_ea == 0x40AEE6
    assert fifth_evidence.false_entry.decoded_target_ea == 0x40A794
    fourth_payload = json.loads(
        fourth.reference_route_authority.reference_route.reference_ledger_json
    )
    assert fourth_payload["aggregate_program_identity"] == (
        batch.aggregate_program_identity
    )
    assert fourth_payload["proof_artifact"]["content_identity"] == (
        "sha256:cab149ee6cce29957798829cceba0a2da5e17bbf3fda4c6d55dad62d64ec3785"
    )
    assert fourth_payload["proof_artifact"]["proof"]["binding"] == {
        "function_ea": 0x40A560,
        "input_sha256": generated_reference.INPUT_SHA256,
        "operation_id": "rhad:route@0x40A77C",
        "reference_commit": "21b0d4783703bc4fb6910cfae51d92cd683d2c65",
        "reference_order": 16,
    }
    assert BOUNDARY_EXIT_EAS == (
        0x40A5F0,
        0x40A633,
        0x40A9A0,
        0x40AD6E,
        0x40B1D0,
        0x40B790,
    )


def test_checksum_producer_compiles_row18_existing_conditional_reference() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(),
        evidence_generation=7,
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None
    operation_ids = tuple(operation.operation_id for operation in plan.operations)

    assert "rhad:route@0x40A7AC" in operation_ids
    operation = plan.operation("rhad:route@0x40A7AC")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.EQ
    assert normalization.condition_producer_ea == 0x40A79A
    assert normalization.unresolved_transfer_ea == 0x40A7AC
    assert isinstance(
        normalization.conditional_select_envelope,
        FragmentReferencedImportedConditionalSelectEnvelope,
    )
    envelope = normalization.conditional_select_envelope
    assert envelope.selected_value_block_id == "native@0x40A7A2"
    assert envelope.join_block_id == "native@0x40A7A8"
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40A7AE",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40A5F0",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 18
    assert payload["observed_predicate_kind"] == PredicateKind.NE.value
    assert payload["predicate_kind"] == PredicateKind.EQ.value
    assert payload["comparison_constant"] == 0x1F0B7687
    assert payload["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
    closure = {
        "native@0x40A7AE",
        "native@0x40A7BA",
        "native@0x40A7CD",
        "native@0x40A7E5",
        "native@0x40A7EF",
        "native@0x40B4C5",
        "native@0x40B4E2",
        "native@0x40B4EE",
    }
    assert closure.issubset(plan.native_bodies[0].block_ids)
    template = next(
        fragment
        for fragment in batch.template_fragments
        if fragment.root_ea == 0x40A7AE
    )
    assert template.preserved_transfer_exit_map == {
        0x40A7EF: (0x40B6C0,),
        0x40B4EE: (0x40A607,),
    }


def test_generated_batch_registry_selects_by_complete_native_identity() -> None:
    selected = reference_batch_for_native_key(_native_key())

    assert selected is not None
    assert selected.function_ea == 0x40A560
    assert selected.native_function_rva == 0xA560
    assert selected.template_root_eas == TEMPLATE_ROOT_EAS
    nested_target = next(
        fragment
        for fragment in selected.template_fragments
        if fragment.root_ea == 0x40A6B4
    )
    assert nested_target.owned_ranges == (
        (0x40A6B4, 0x40A6BA),
        (0x40A6BA, 0x40A6C0),
    )
    assert nested_target.boundary_exit_eas == ()
    target_block = build_rhad_generated_reference_plan(
        native_key=_native_key(),
        evidence_generation=7,
    ).block("native@0x40A6B4")
    assert target_block.semantic_anchor_ea == 0x40A6B4
    assert target_block.stable_identity.native_ranges.contains(0x40A6B4)
    assert (
        reference_batch_for_native_key(
            make_native_key(
                input_identity=f"sha256:{'d' * 64}",
                function_rva=0xA560,
            )
        )
        is None
    )


def test_generated_template_partitions_each_preserved_transfer_boundary() -> None:
    assert hasattr(generated_reference, "RhadGeneratedPreservedTransfer")
    evidence_type = generated_reference.RhadGeneratedPreservedTransfer
    fragment_type = generated_reference.RhadGeneratedTemplateFragment
    first = evidence_type(
        transfer_ea=0x40A7EF,
        boundary_exit_eas=(0x40B6C0,),
    )
    second = evidence_type(
        transfer_ea=0x40B4EE,
        boundary_exit_eas=(0x40A607,),
    )
    fragment = fragment_type(
        root_ea=0x40A7AE,
        owned_ranges=((0x40A7AE, 0x40A7F1), (0x40B4C5, 0x40B4F0)),
        owned_block_entry_eas=(
            0x40A7AE,
            0x40A7BA,
            0x40A7CD,
            0x40A7E5,
            0x40B4C5,
            0x40B4E2,
        ),
        boundary_ranges=(),
        boundary_exit_eas=(0x40A607, 0x40B6C0),
        direct_boundary_routes=(),
        preserved_unresolved_transfers=(first, second),
    )

    assert fragment.preserved_unresolved_transfer_eas == (0x40A7EF, 0x40B4EE)
    assert fragment.preserved_transfer_exit_map == {
        0x40A7EF: (0x40B6C0,),
        0x40B4EE: (0x40A607,),
    }

    with pytest.raises(ValueError, match="duplicate preserved transfer"):
        replace(fragment, preserved_unresolved_transfers=(first, first))
    with pytest.raises(ValueError, match="boundary ownership"):
        replace(
            fragment,
            preserved_unresolved_transfers=(
                replace(first, boundary_exit_eas=(0x40A607,)),
                second,
            ),
        )
    with pytest.raises(ValueError, match="owned native range"):
        replace(
            fragment,
            preserved_unresolved_transfers=(
                replace(first, transfer_ea=0x40C000),
                second,
            ),
        )
    assert (
        reference_batch_for_native_key(
            make_native_key(
                input_identity=_native_key().input_identity,
                function_rva=0xA561,
            )
        )
        is None
    )


def test_row16_proof_artifact_is_required_and_content_addressed(
    tmp_path: Path,
) -> None:
    artifact = generated_reference.load_row16_table_proof_artifact()
    checked_in = json.loads(
        generated_reference.ROW16_TABLE_PROOF_PATH.read_text(encoding="utf-8")
    )

    assert artifact.content_identity == checked_in["content_identity"]
    assert artifact.proof_payload == checked_in["proof"]

    with pytest.raises(RhadCompilerRejection, match="artifact is unavailable"):
        generated_reference.load_row16_table_proof_artifact(
            tmp_path / "missing-row16-proof.json"
        )

    mismatched_path = tmp_path / "mismatched-row16-proof.json"
    checked_in["content_identity"] = "sha256:" + ("0" * 64)
    mismatched_path.write_text(json.dumps(checked_in), encoding="utf-8")
    with pytest.raises(RhadCompilerRejection, match="content identity"):
        generated_reference.load_row16_table_proof_artifact(mismatched_path)


def test_row17_proof_artifact_is_required_and_content_addressed(
    tmp_path: Path,
) -> None:
    artifact = generated_reference.load_row17_table_proof_artifact()
    checked_in = json.loads(
        generated_reference.ROW17_TABLE_PROOF_PATH.read_text(encoding="utf-8")
    )

    assert artifact.content_identity == (
        "sha256:a67a3d2cc432df11ca627c90f06f3a854004a9463a529ee1d0cdf1f759406e67"
    )
    assert artifact.proof_payload == checked_in["proof"]
    assert artifact.operation_id == "rhad:route@0x40A792"
    assert artifact.reference_order == 17

    with pytest.raises(RhadCompilerRejection, match="artifact is unavailable"):
        generated_reference.load_row17_table_proof_artifact(
            tmp_path / "missing-row17-proof.json"
        )


def test_stable_228_row_inventory_references_required_table_artifacts() -> None:
    inventory = json.loads(
        (
            _REPO
            / "docs"
            / "experiments"
            / "rhad-a560-indirect-jump-reference-inventory.json"
        ).read_text(encoding="utf-8")
    )
    operations = inventory["operations"]
    row_keys = {tuple(sorted(operation)) for operation in operations}
    row16 = next(
        operation for operation in operations if operation["reference_order"] == 16
    )
    row17 = next(
        operation for operation in operations if operation["reference_order"] == 17
    )
    row16_artifact = generated_reference.load_row16_table_proof_artifact()
    row17_artifact = generated_reference.load_row17_table_proof_artifact()

    assert inventory["schema_version"] == 1
    assert inventory["operation_count"] == len(operations) == 228
    assert [operation["reference_order"] for operation in operations] == list(
        range(228)
    )
    assert len(row_keys) == 1
    assert row16["operation_id"] == row16_artifact.operation_id
    assert row16["current_generated_proof"]["proof_artifact_identity"] == (
        row16_artifact.content_identity
    )
    assert row17["operation_id"] == row17_artifact.operation_id
    assert row17["current_compiler_support"] == "typed_setcc_indexed_table"
    assert row17["current_generated_proof"] == {
        "accepted_commits": ["53eed0e43", "a33311661"],
        "proof_artifact_identity": row17_artifact.content_identity,
        "status": "accepted_generated_c6",
    }


def test_indirect_jump_coverage_summary_matches_committed_row17_batch() -> None:
    summary = json.loads(
        (
            _REPO
            / "docs"
            / "experiments"
            / "rhad-a560-indirect-jump-coverage-summary.json"
        ).read_text(encoding="utf-8")
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None
    setcc = next(
        row
        for row in summary["variants"]
        if row["operation_variant"] == "setcc_indexed_table"
    )

    assert summary["accepted_code_sha"] == ("a333116618c6cfa0ff42a5870a2a87e36edf1795")
    accepted_operation_ids = summary["accepted_receipt_operation_ids"]
    assert accepted_operation_ids == [
        operation.operation_id
        for operation in batch.operations[: len(accepted_operation_ids)]
    ]
    assert setcc == {
        "operation_variant": "setcc_indexed_table",
        "total_reference_operations": 8,
        "compiler_supported_operations": 8,
        "compiled_operation_instances": 2,
        "vertically_proved_operations": 2,
        "accepted_receipt_operations": 2,
        "earliest_unproved_reference_order": 68,
        "earliest_unproved_operation_id": "rhad:route@0x40AE3C",
        "first_missing_typed_obligation": (
            "instantiate the proved RhadSetccIndexedTableRoute vocabulary with "
            "exact per-operation proof artifact and dependency closure"
        ),
    }


def test_production_dispatch_and_compilation_have_no_sample_ea_guards() -> None:
    guarded_functions = (
        generated_reference.reference_batch_for_native_key,
        generated_reference.build_rhad_generated_reference_plan,
        generated_reference.prepare_rhad_generated_reference_templates,
        generated_reference.publish_rhad_generated_reference_batch,
    )
    forbidden_eas = {0x40A560, 0x40A605, 0x40A619}

    for function in guarded_functions:
        tree = ast.parse(inspect.getsource(function))
        guarded_constants = {
            int(node.value)
            for compare in ast.walk(tree)
            if isinstance(compare, (ast.If, ast.IfExp))
            for node in ast.walk(compare.test)
            if isinstance(node, ast.Constant) and isinstance(node.value, int)
        }
        assert forbidden_eas.isdisjoint(guarded_constants), function.__name__
