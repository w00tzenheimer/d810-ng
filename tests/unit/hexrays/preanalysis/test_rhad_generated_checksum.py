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


def test_aggregate_identity_binds_typed_direct_reference_evidence() -> None:
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None
    direct = batch.operations[1]
    changed = replace(direct, reference_order=direct.reference_order + 1)
    changed_batch = replace(
        batch,
        operations=(batch.operations[0], changed, *batch.operations[2:]),
    )

    assert changed_batch.aggregate_program_identity != batch.aggregate_program_identity


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
    assert len(IMPORTED_BLOCK_IDS) == 140
    assert TEMPLATE_ROOT_EAS == (
        0x40A607,
        0x40B6C0,
        0x40A61B,
        0x40A633,
        0x40A64B,
        0x40A663,
        0x40A68C,
        0x40A6A6,
        0x40A6C0,
        0x40A960,
        0x40A6DA,
        0x40AB76,
        0x40A6F4,
        0x40AE8B,
        0x40A70E,
        0x40A800,
        0x40A81A,
        0x40A834,
        0x40A84E,
        0x40AFDF,
        0x40A868,
        0x40A8B5,
        0x40A8CF,
        0x40ACBF,
        0x40AC3D,
        0x40AA60,
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
        "route:rhad-direct@0x40A631",
        "route:rhad-direct@0x40A649",
        "route:rhad-direct@0x40A661",
        "route:rhad-direct@0x40A68A",
        "rhad:route@0x40A6A4",
        "rhad:route@0x40A6BE",
        "rhad:route@0x40A6D8",
        "rhad:route@0x40A6F2",
        "rhad:route@0x40A70C",
        "route:rhad-direct@0x40A74A",
        "rhad:route@0x40A764",
        "rhad:route@0x40A77C",
        "rhad:route@0x40A792",
        "rhad:route@0x40A7AC",
        "rhad:route@0x40A818",
        "rhad:route@0x40A832",
        "rhad:route@0x40A84C",
        "rhad:route@0x40A866",
        "rhad:route@0x40A8CD",
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
    assert direct_payload["reference_operation_id"] == "rhad:route@0x40A619"
    assert direct_payload["reference_order"] == 2
    assert direct_payload["operation_variant"] == "simple_indirect_jump"
    assert direct_payload["reference_symbol"] == (
        "JumpInliner._fixup_jmp_and_possible_jcc"
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
    row9 = plan.operation("rhad:route@0x40A6BE")
    row9_envelope = row9.computed_branch_normalization.conditional_select_envelope
    row10 = plan.operation("rhad:route@0x40A6D8")
    row10_envelope = row10.computed_branch_normalization.conditional_select_envelope
    row11 = plan.operation("rhad:route@0x40A6F2")
    row11_envelope = row11.computed_branch_normalization.conditional_select_envelope
    row12 = plan.operation("rhad:route@0x40A70C")
    row12_envelope = row12.computed_branch_normalization.conditional_select_envelope
    fourth_existing = plan.operation("rhad:route@0x40A764")
    fourth_existing_envelope = (
        fourth_existing.computed_branch_normalization.conditional_select_envelope
    )
    fourth = plan.operation("rhad:route@0x40A77C")
    sixth_existing = plan.operation("rhad:route@0x40A7AC")
    sixth_existing_envelope = (
        sixth_existing.computed_branch_normalization.conditional_select_envelope
    )
    row20 = plan.operation("rhad:route@0x40A818")
    row20_envelope = row20.computed_branch_normalization.conditional_select_envelope
    row21 = plan.operation("rhad:route@0x40A832")
    row21_envelope = row21.computed_branch_normalization.conditional_select_envelope
    row22 = plan.operation("rhad:route@0x40A84C")
    row22_envelope = row22.computed_branch_normalization.conditional_select_envelope
    row23 = plan.operation("rhad:route@0x40A866")
    row23_envelope = row23.computed_branch_normalization.conditional_select_envelope
    row26 = plan.operation("rhad:route@0x40A8CD")
    row26_envelope = row26.computed_branch_normalization.conditional_select_envelope
    operation_topology = direct_sources | {
        selected.source_block_id,
        selected_envelope.selected_value_block_id,
        selected_envelope.join_block_id,
        row9.source_block_id,
        row9_envelope.selected_value_block_id,
        row9_envelope.join_block_id,
        row10.source_block_id,
        row10_envelope.selected_value_block_id,
        row10_envelope.join_block_id,
        row11.source_block_id,
        row11_envelope.selected_value_block_id,
        row11_envelope.join_block_id,
        row12.source_block_id,
        row12_envelope.selected_value_block_id,
        row12_envelope.join_block_id,
        fourth_existing.source_block_id,
        fourth_existing_envelope.selected_value_block_id,
        fourth_existing_envelope.join_block_id,
        fourth.source_block_id,
        "native@0x40A77E",
        sixth_existing.source_block_id,
        sixth_existing_envelope.selected_value_block_id,
        sixth_existing_envelope.join_block_id,
        row20.source_block_id,
        row20_envelope.selected_value_block_id,
        row20_envelope.join_block_id,
        row21.source_block_id,
        row21_envelope.selected_value_block_id,
        row21_envelope.join_block_id,
        row22.source_block_id,
        row22_envelope.selected_value_block_id,
        row22_envelope.join_block_id,
        row23.source_block_id,
        row23_envelope.selected_value_block_id,
        row23_envelope.join_block_id,
        row26.source_block_id,
        row26_envelope.selected_value_block_id,
        row26_envelope.join_block_id,
    }
    preserved_sources = set(native_body.preserved_native_transfer_block_ids)
    assert operation_topology.isdisjoint(preserved_sources)
    assert operation_topology | preserved_sources == set(native_body.block_ids)
    assert {edge.role: edge.target_block_id for edge in selected.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40A6A6",
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
        0x40A5CA,
        0x40A5F0,
        0x40A8E9,
        0x40A9A0,
        0x40AAFD,
        0x40AD1E,
        0x40AD6E,
        0x40ADBE,
        0x40AE26,
        0x40B024,
        0x40B17F,
        0x40B1D0,
        0x40B21C,
        0x40B26D,
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


def test_checksum_producer_compiles_row9_existing_conditional_reference() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(),
        evidence_generation=7,
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40A6BE")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.SLT
    assert normalization.condition_producer_ea == 0x40A6AC
    assert normalization.unresolved_transfer_ea == 0x40A6BE
    assert isinstance(
        normalization.conditional_select_envelope,
        FragmentReferencedImportedConditionalSelectEnvelope,
    )
    envelope = normalization.conditional_select_envelope
    assert envelope.selected_value_block_id == "native@0x40A6B4"
    assert envelope.join_block_id == "native@0x40A6BA"
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40A6C0",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40A960",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 9
    assert payload["observed_predicate_kind"] == PredicateKind.SGE.value
    assert payload["predicate_kind"] == PredicateKind.SLT.value
    assert payload["comparison_constant"] == 0x4DFFC906
    assert payload["boundary_exit_eas"] == [
        0x40A6DA,
        0x40AB76,
        0x40AD1E,
    ]
    closure = {
        "native@0x40A6C0",
        "native@0x40A6CE",
        "native@0x40A6D4",
        "native@0x40A6D8",
        "native@0x40A960",
        "native@0x40A96E",
        "native@0x40A974",
        "native@0x40A978",
    }
    assert closure.issubset(plan.native_bodies[0].block_ids)
    true_template = next(
        fragment for fragment in batch.template_fragments if fragment.root_ea == 0x40A6C0
    )
    assert true_template.preserved_transfer_exit_map == {
        0x40A6D8: (0x40A6DA, 0x40AB76),
    }
    false_template = next(
        fragment for fragment in batch.template_fragments if fragment.root_ea == 0x40A960
    )
    assert false_template.preserved_transfer_exit_map == {
        0x40A978: (0x40AD1E,),
    }


def test_checksum_producer_compiles_row10_existing_conditional_reference() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(),
        evidence_generation=7,
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40A6D8")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.SLT
    assert normalization.condition_producer_ea == 0x40A6C6
    assert normalization.unresolved_transfer_ea == 0x40A6D8
    assert isinstance(
        normalization.conditional_select_envelope,
        FragmentReferencedImportedConditionalSelectEnvelope,
    )
    envelope = normalization.conditional_select_envelope
    assert envelope.selected_value_block_id == "native@0x40A6CE"
    assert envelope.join_block_id == "native@0x40A6D4"
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40A6DA",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40AB76",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 10
    assert payload["observed_predicate_kind"] == PredicateKind.SGE.value
    assert payload["predicate_kind"] == PredicateKind.SLT.value
    assert payload["comparison_constant"] == 0x40D5B460
    assert payload["boundary_exit_eas"] == [
        0x40A6F4,
        0x40AE8B,
        0x40B17F,
    ]
    closure = {
        "native@0x40A6DA",
        "native@0x40A6E8",
        "native@0x40A6EE",
        "native@0x40A6F2",
        "native@0x40AB76",
        "native@0x40AB84",
        "native@0x40AB8A",
        "native@0x40AB8E",
    }
    assert closure.issubset(plan.native_bodies[0].block_ids)
    true_template = next(
        fragment for fragment in batch.template_fragments if fragment.root_ea == 0x40A6DA
    )
    assert true_template.preserved_transfer_exit_map == {
        0x40A6F2: (0x40A6F4, 0x40AE8B),
    }
    false_template = next(
        fragment for fragment in batch.template_fragments if fragment.root_ea == 0x40AB76
    )
    assert false_template.preserved_transfer_exit_map == {
        0x40AB8E: (0x40B17F,),
    }


def test_checksum_producer_compiles_row11_existing_conditional_reference() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(),
        evidence_generation=7,
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40A6F2")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.SLT
    assert normalization.condition_producer_ea == 0x40A6E0
    assert normalization.unresolved_transfer_ea == 0x40A6F2
    assert isinstance(
        normalization.conditional_select_envelope,
        FragmentReferencedImportedConditionalSelectEnvelope,
    )
    envelope = normalization.conditional_select_envelope
    assert envelope.selected_value_block_id == "native@0x40A6E8"
    assert envelope.join_block_id == "native@0x40A6EE"
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40A6F4",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40AE8B",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 11
    assert payload["observed_predicate_kind"] == PredicateKind.SGE.value
    assert payload["predicate_kind"] == PredicateKind.SLT.value
    assert payload["comparison_constant"] == 0x40ABF871
    assert payload["boundary_exit_eas"] == [0x40A5F0, 0x40A70E]
    closure = {
        "native@0x40A6F4",
        "native@0x40A702",
        "native@0x40A708",
        "native@0x40A70C",
        "native@0x40AE8B",
        "native@0x40AE99",
        "native@0x40AE9F",
        "native@0x40AEA3",
    }
    assert closure.issubset(plan.native_bodies[0].block_ids)
    true_template = next(
        fragment for fragment in batch.template_fragments if fragment.root_ea == 0x40A6F4
    )
    assert true_template.preserved_transfer_exit_map == {
        0x40A70C: (0x40A5F0, 0x40A70E),
    }
    false_template = next(
        fragment for fragment in batch.template_fragments if fragment.root_ea == 0x40AE8B
    )
    assert false_template.preserved_transfer_exit_map == {
        0x40AEA3: (0x40A5F0,),
    }


def test_checksum_producer_compiles_row12_existing_conditional_reference() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(),
        evidence_generation=7,
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40A70C")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.EQ
    assert normalization.condition_producer_ea == 0x40A6FA
    assert normalization.unresolved_transfer_ea == 0x40A70C
    assert isinstance(
        normalization.conditional_select_envelope,
        FragmentReferencedImportedConditionalSelectEnvelope,
    )
    envelope = normalization.conditional_select_envelope
    assert envelope.selected_value_block_id == "native@0x40A702"
    assert envelope.join_block_id == "native@0x40A708"
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40A70E",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40A5F0",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 12
    assert payload["observed_predicate_kind"] == PredicateKind.NE.value
    assert payload["predicate_kind"] == PredicateKind.EQ.value
    assert payload["comparison_constant"] == 0x357A351E
    assert payload["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
    assert {"native@0x40A70E", "native@0x40A73D"}.issubset(
        plan.native_bodies[0].block_ids
    )
    true_template = next(
        fragment for fragment in batch.template_fragments if fragment.root_ea == 0x40A70E
    )
    assert true_template.preserved_transfer_exit_map == {
        0x40A73D: (0x40A607, 0x40B6C0),
    }


def test_checksum_producer_compiles_row20_existing_conditional_reference() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(),
        evidence_generation=7,
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40A818")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.SLT
    assert normalization.condition_producer_ea == 0x40A806
    assert normalization.unresolved_transfer_ea == 0x40A818
    assert isinstance(
        normalization.conditional_select_envelope,
        FragmentReferencedImportedConditionalSelectEnvelope,
    )
    envelope = normalization.conditional_select_envelope
    assert envelope.selected_value_block_id == "native@0x40A80E"
    assert envelope.join_block_id == "native@0x40A814"
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40A81A",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40AA60",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 20
    assert payload["observed_predicate_kind"] == PredicateKind.SGE.value
    assert payload["predicate_kind"] == PredicateKind.SLT.value
    assert payload["comparison_constant"] == 0x742F372A
    assert payload["boundary_exit_eas"] == [0x40A834, 0x40AC3D, 0x40ADBE]
    assert {
        "native@0x40A81A",
        "native@0x40A832",
        "native@0x40AA60",
        "native@0x40AA78",
    }.issubset(plan.native_bodies[0].block_ids)
    true_template = next(
        fragment for fragment in batch.template_fragments if fragment.root_ea == 0x40A81A
    )
    assert true_template.preserved_transfer_exit_map == {
        0x40A832: (0x40A834, 0x40AC3D),
    }
    false_template = next(
        fragment for fragment in batch.template_fragments if fragment.root_ea == 0x40AA60
    )
    assert false_template.preserved_transfer_exit_map == {
        0x40AA78: (0x40ADBE,),
    }


def test_checksum_producer_compiles_row21_existing_conditional_reference() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40A832")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.SLT
    assert normalization.condition_producer_ea == 0x40A820
    assert normalization.unresolved_transfer_ea == 0x40A832
    assert isinstance(
        normalization.conditional_select_envelope,
        FragmentReferencedImportedConditionalSelectEnvelope,
    )
    envelope = normalization.conditional_select_envelope
    assert envelope.selected_value_block_id == "native@0x40A828"
    assert envelope.join_block_id == "native@0x40A82E"
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40A834",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40AC3D",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 21
    assert payload["observed_predicate_kind"] == PredicateKind.SGE.value
    assert payload["predicate_kind"] == PredicateKind.SLT.value
    assert payload["comparison_constant"] == 0x6D56E4D2
    assert payload["boundary_exit_eas"] == [0x40A84E, 0x40AFDF, 0x40B21C]
    assert {
        "native@0x40A834",
        "native@0x40A84C",
        "native@0x40AC3D",
        "native@0x40AC54",
    }.issubset(plan.native_bodies[0].block_ids)
    true_template = next(
        fragment for fragment in batch.template_fragments if fragment.root_ea == 0x40A834
    )
    assert true_template.preserved_transfer_exit_map == {
        0x40A84C: (0x40A84E, 0x40AFDF),
    }
    false_template = next(
        fragment for fragment in batch.template_fragments if fragment.root_ea == 0x40AC3D
    )
    assert false_template.preserved_transfer_exit_map == {
        0x40AC54: (0x40B21C,),
    }


def test_checksum_producer_compiles_row22_existing_conditional_reference() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40A84C")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.SLT
    assert normalization.condition_producer_ea == 0x40A83A
    assert normalization.unresolved_transfer_ea == 0x40A84C
    assert isinstance(
        normalization.conditional_select_envelope,
        FragmentReferencedImportedConditionalSelectEnvelope,
    )
    envelope = normalization.conditional_select_envelope
    assert envelope.selected_value_block_id == "native@0x40A842"
    assert envelope.join_block_id == "native@0x40A848"
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40A84E",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40AFDF",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 22
    assert payload["observed_predicate_kind"] == PredicateKind.SGE.value
    assert payload["predicate_kind"] == PredicateKind.SLT.value
    assert payload["comparison_constant"] == 0x6859ABF3
    assert payload["boundary_exit_eas"] == [0x40A5F0, 0x40A868]
    assert {
        "native@0x40A84E",
        "native@0x40A866",
        "native@0x40AFDF",
        "native@0x40AFF7",
    }.issubset(plan.native_bodies[0].block_ids)
    true_template = next(
        fragment for fragment in batch.template_fragments if fragment.root_ea == 0x40A84E
    )
    assert true_template.preserved_transfer_exit_map == {
        0x40A866: (0x40A5F0, 0x40A868),
    }
    false_template = next(
        fragment for fragment in batch.template_fragments if fragment.root_ea == 0x40AFDF
    )
    assert false_template.preserved_transfer_exit_map == {
        0x40AFF7: (0x40A5F0,),
    }


def test_checksum_producer_compiles_row23_existing_conditional_reference() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40A866")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.EQ
    assert normalization.condition_producer_ea == 0x40A854
    assert normalization.unresolved_transfer_ea == 0x40A866
    assert isinstance(
        normalization.conditional_select_envelope,
        FragmentReferencedImportedConditionalSelectEnvelope,
    )
    envelope = normalization.conditional_select_envelope
    assert envelope.selected_value_block_id == "native@0x40A85C"
    assert envelope.join_block_id == "native@0x40A862"
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40A868",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40A5F0",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 23
    assert payload["observed_predicate_kind"] == PredicateKind.NE.value
    assert payload["predicate_kind"] == PredicateKind.EQ.value
    assert payload["comparison_constant"] == 0x65203D55
    assert payload["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
    assert {
        "native@0x40A868",
        "native@0x40A8A0",
        "native@0x40A8A3",
        "native@0x40A8A7",
    }.issubset(
        plan.native_bodies[0].block_ids
    )
    true_template = next(
        fragment for fragment in batch.template_fragments if fragment.root_ea == 0x40A868
    )
    assert true_template.preserved_transfer_exit_map == {
        0x40A8A7: (0x40A607, 0x40B6C0),
    }


def test_checksum_producer_compiles_row26_existing_conditional_reference() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40A8CD")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.SLT
    assert normalization.condition_producer_ea == 0x40A8BB
    assert normalization.unresolved_transfer_ea == 0x40A8CD
    assert isinstance(
        normalization.conditional_select_envelope,
        FragmentReferencedImportedConditionalSelectEnvelope,
    )
    envelope = normalization.conditional_select_envelope
    assert envelope.selected_value_block_id == "native@0x40A8C3"
    assert envelope.join_block_id == "native@0x40A8C9"
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40A8CF",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40ACBF",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 26
    assert payload["comparison_constant"] == 0x0E9795EF
    assert payload["boundary_exit_eas"] == [0x40A8E9, 0x40B024, 0x40B26D]
    assert {
        "native@0x40A8B5",
        "native@0x40A8CD",
        "native@0x40A8CF",
        "native@0x40A8E7",
        "native@0x40ACBF",
        "native@0x40ACD7",
    }.issubset(plan.native_bodies[0].block_ids)
    source_template = next(
        fragment for fragment in batch.template_fragments if fragment.root_ea == 0x40A8B5
    )
    assert source_template.preserved_transfer_exit_map == {
        0x40A8CD: (0x40A8CF, 0x40ACBF),
    }


def test_checksum_producer_compiles_row3_row4_direct_delivery_chain() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    row3 = plan.operation("route:rhad-direct@0x40A631")
    row4 = plan.operation("route:rhad-direct@0x40A649")
    assert row3.direct_transfer_rewrite.rewrite_anchor_ea == 0x40A631
    assert row3.edges[0].target_block_id == "native@0x40A633"
    assert row4.direct_transfer_rewrite.rewrite_anchor_ea == 0x40A649
    assert row4.edges[0].target_block_id == "native@0x40A8B5"
    row3_payload = json.loads(
        row3.reference_route_authority.reference_route.reference_ledger_json
    )
    row4_payload = json.loads(
        row4.reference_route_authority.reference_route.reference_ledger_json
    )
    assert row3_payload["reference_operation_id"] == "rhad:route@0x40A631"
    assert row3_payload["reference_order"] == 3
    assert row4_payload["reference_operation_id"] == "rhad:route@0x40A649"
    assert row4_payload["reference_order"] == 4
    operation_by_id = {operation.operation_id: operation for operation in batch.operations}
    assert operation_by_id["route:rhad-direct@0x40A631"].depends_on == (
        "route:rhad-direct@0x40A619",
    )
    assert operation_by_id["route:rhad-direct@0x40A649"].depends_on == (
        "route:rhad-direct@0x40A631",
    )
    assert operation_by_id["rhad:route@0x40A8CD"].depends_on == (
        "route:rhad-direct@0x40A649",
    )
    delivery = next(
        fragment for fragment in batch.template_fragments if fragment.root_ea == 0x40A633
    )
    assert delivery.preserved_transfer_exit_map == {
        0x40A649: (0x40A8B5,),
        0x40A8B3: (0x40A64B,),
    }


def test_checksum_producer_compiles_row5_direct_route() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    row5 = plan.operation("route:rhad-direct@0x40A661")
    assert row5.direct_transfer_rewrite.rewrite_anchor_ea == 0x40A661
    assert row5.edges[0].target_block_id == "native@0x40A663"
    payload = json.loads(
        row5.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_operation_id"] == "rhad:route@0x40A661"
    assert payload["reference_order"] == 5
    assert payload["operation_variant"] == "simple_indirect_jump"
    operation_by_id = {operation.operation_id: operation for operation in batch.operations}
    assert operation_by_id["route:rhad-direct@0x40A661"].depends_on == (
        "route:rhad-direct@0x40A631",
    )
    source = next(
        fragment for fragment in batch.template_fragments if fragment.root_ea == 0x40A64B
    )
    assert source.owned_ranges == (
        (0x40A64B, 0x40A663),
        (0x40AAF1, 0x40AAFD),
    )
    assert source.preserved_transfer_exit_map == {0x40AAFB: (0x40AAFD,)}
    closure = next(
        fragment for fragment in batch.template_fragments if fragment.root_ea == 0x40A663
    )
    assert closure.owned_ranges == (
        (0x40A663, 0x40A67B),
        (0x40AE1A, 0x40AE26),
    )
    assert closure.preserved_transfer_exit_map == {
        0x40A679: (0x40AE26,),
        0x40AE24: (0x40A5CA,),
    }


def test_row17_delivery_closure_includes_row18_typed_branch_arms() -> None:
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    assert generated_reference._typed_delivery_block_closure(
        batch,
        "native@0x40A794",
    ) == (
        "native@0x40A794",
        "native@0x40A7AE",
        "native@0x40A5F0",
        "native@0x40B6C0",
        "native@0x40A607",
    )


def test_generated_batch_registry_selects_by_complete_native_identity() -> None:
    selected = reference_batch_for_native_key(_native_key())

    assert selected is not None
    assert selected.function_ea == 0x40A560
    assert selected.native_function_rva == 0xA560
    assert selected.template_root_eas == TEMPLATE_ROOT_EAS
    nested_target = next(
        fragment
        for fragment in selected.template_fragments
        if fragment.root_ea == 0x40A6A6
    )
    assert nested_target.owned_ranges == (
        (0x40A6A6, 0x40A6B4),
        (0x40A6B4, 0x40A6BA),
        (0x40A6BA, 0x40A6C0),
    )
    assert nested_target.boundary_exit_eas == (0x40A6C0, 0x40A960)
    target_block = build_rhad_generated_reference_plan(
        native_key=_native_key(),
        evidence_generation=7,
    ).block("native@0x40A6A6")
    assert target_block.semantic_anchor_ea == 0x40A6A6
    assert target_block.stable_identity.native_ranges.contains(0x40A6A6)
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
    row5 = next(
        operation for operation in operations if operation["reference_order"] == 5
    )
    row11 = next(
        operation for operation in operations if operation["reference_order"] == 11
    )
    row12 = next(
        operation for operation in operations if operation["reference_order"] == 12
    )
    row20 = next(
        operation for operation in operations if operation["reference_order"] == 20
    )
    row21 = next(
        operation for operation in operations if operation["reference_order"] == 21
    )
    row22 = next(
        operation for operation in operations if operation["reference_order"] == 22
    )
    row23 = next(
        operation for operation in operations if operation["reference_order"] == 23
    )
    row26 = next(
        operation for operation in operations if operation["reference_order"] == 26
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None
    row16_artifact = generated_reference.load_row16_table_proof_artifact()
    row17_artifact = generated_reference.load_row17_table_proof_artifact()

    assert inventory["schema_version"] == 1
    assert inventory["operation_count"] == len(operations) == 228
    assert [operation["reference_order"] for operation in operations] == list(
        range(228)
    )
    assert len(row_keys) == 1
    rows_by_operation_id = {row["operation_id"]: row for row in operations}
    accepted_receipt_operation_ids = set(
        json.loads(
            (
                _REPO
                / "docs"
                / "experiments"
                / "rhad-a560-indirect-jump-coverage-summary.json"
            ).read_text(encoding="utf-8")
        )["accepted_receipt_operation_ids"]
    )
    for operation in batch.operations:
        if operation.operation_id not in accepted_receipt_operation_ids:
            continue
        reference_operation_id = getattr(
            operation,
            "reference_operation_id",
            operation.operation_id,
        )
        assert rows_by_operation_id[reference_operation_id][
            "current_generated_proof"
        ]["status"] == "accepted_generated_c6"
    assert row5["operation_id"] == "rhad:route@0x40A661"
    assert row5["current_compiler_support"] == "typed_simple_indirect_jump"
    assert row5["current_generated_proof"] == {
        "accepted_commits": ["fa02b0aa0", "c9485af58", "0e0c9ab2a"],
        "status": "accepted_generated_c6",
    }
    assert row5["boundary_exit_eas"] == [0x40A5CA, 0x40AAFD, 0x40AE26]
    assert row5["imported_closure_block_anchor_eas"] == [
        0x40A64B,
        0x40A65D,
        0x40A661,
        0x40AAF1,
        0x40AAFB,
        0x40A663,
        0x40A675,
        0x40A679,
        0x40AE1A,
        0x40AE24,
    ]
    assert row11["operation_id"] == "rhad:route@0x40A6F2"
    assert row11["current_compiler_support"] == (
        "typed_existing_conditional_plus_indirect"
    )
    assert row11["current_generated_proof"] == {
        "accepted_commits": ["37f43bd32", "d5fc37ba9"],
        "status": "accepted_generated_c6",
    }
    assert row11["imported_closure_block_anchor_eas"] == [
        0x40A6F4,
        0x40A702,
        0x40A708,
        0x40A70C,
        0x40AE8B,
        0x40AE99,
        0x40AE9F,
        0x40AEA3,
    ]
    assert row11["unavailable_closure_exit_eas"] == []
    assert row12["operation_id"] == "rhad:route@0x40A70C"
    assert row12["current_compiler_support"] == (
        "typed_existing_conditional_plus_indirect"
    )
    assert row12["current_generated_proof"] == {
        "accepted_commits": ["ab95c7829", "0089071a8", "4e9059237"],
        "status": "accepted_generated_c6",
    }
    assert row12["imported_closure_block_anchor_eas"] == [
        0x40A5F0,
        0x40A605,
        0x40A70E,
        0x40A73D,
    ]
    assert row12["unavailable_closure_exit_eas"] == []
    assert row20["operation_id"] == "rhad:route@0x40A818"
    assert row20["current_compiler_support"] == (
        "typed_existing_conditional_plus_indirect"
    )
    assert row20["current_generated_proof"] == {
        "accepted_commits": ["d03742e0a", "b6bad7b7a"],
        "status": "accepted_generated_c6",
    }
    assert row20["imported_closure_block_anchor_eas"] == [
        0x40A81A,
        0x40A828,
        0x40A82E,
        0x40A832,
        0x40AA60,
        0x40AA6E,
        0x40AA74,
        0x40AA78,
    ]
    assert row20["unavailable_closure_exit_eas"] == []
    assert row21["operation_id"] == "rhad:route@0x40A832"
    assert row21["current_compiler_support"] == (
        "typed_existing_conditional_plus_indirect"
    )
    assert row21["current_generated_proof"] == {
        "accepted_commits": ["8bc7424c9", "608b1de9d"],
        "status": "accepted_generated_c6",
    }
    assert row21["imported_closure_block_anchor_eas"] == [
        0x40A834,
        0x40A842,
        0x40A848,
        0x40A84C,
        0x40AC3D,
        0x40AC4A,
        0x40AC50,
        0x40AC54,
    ]
    assert row21["unavailable_closure_exit_eas"] == []
    assert row22["operation_id"] == "rhad:route@0x40A84C"
    assert row22["current_compiler_support"] == (
        "typed_existing_conditional_plus_indirect"
    )
    assert row22["current_generated_proof"] == {
        "accepted_commits": ["d2bd5469a", "5a4ce7138"],
        "status": "accepted_generated_c6",
    }
    assert row22["imported_closure_block_anchor_eas"] == [
        0x40A84E,
        0x40A85C,
        0x40A862,
        0x40A866,
        0x40AFDF,
        0x40AFED,
        0x40AFF3,
        0x40AFF7,
    ]
    assert row22["unavailable_closure_exit_eas"] == []
    assert row23["operation_id"] == "rhad:route@0x40A866"
    assert row23["current_compiler_support"] == (
        "typed_existing_conditional_plus_indirect"
    )
    assert row23["current_generated_proof"] == {
        "accepted_commits": ["641658579", "e075f8f21", "08914197e"],
        "status": "accepted_generated_c6",
    }
    assert row23["imported_closure_block_anchor_eas"] == [
        0x40A5F0,
        0x40A605,
        0x40A868,
        0x40A8A7,
    ]
    assert row23["unavailable_closure_exit_eas"] == []
    assert row26["operation_id"] == "rhad:route@0x40A8CD"
    assert row26["current_compiler_support"] == (
        "typed_existing_conditional_plus_indirect"
    )
    assert row26["current_generated_proof"] == {
        "accepted_commits": ["b4cce169c", "30b09eb5b", "1e14763f1"],
        "status": "accepted_generated_c6",
    }
    assert row26["imported_closure_block_anchor_eas"] == [
        0x40A8B5,
        0x40A8CD,
        0x40A8CF,
        0x40A8E7,
        0x40ACBF,
        0x40ACD7,
    ]
    assert row26["unavailable_closure_exit_eas"] == []
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


def test_indirect_jump_coverage_summary_matches_committed_row5_batch() -> None:
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
    existing = next(
        row
        for row in summary["variants"]
        if row["operation_variant"] == "existing_conditional_plus_indirect"
    )
    simple = next(
        row
        for row in summary["variants"]
        if row["operation_variant"] == "simple_indirect_jump"
    )

    assert summary["accepted_code_sha"] == ("0e0c9ab2a9b680ef73384f85624c785e864d7998")
    accepted_operation_ids = summary["accepted_receipt_operation_ids"]
    assert accepted_operation_ids == [
        operation.operation_id for operation in batch.operations
    ]
    assert simple == {
        "operation_variant": "simple_indirect_jump",
        "total_reference_operations": 64,
        "compiler_supported_operations": 64,
        "compiled_operation_instances": 6,
        "vertically_proved_operations": 6,
        "accepted_receipt_operations": 6,
        "earliest_unproved_reference_order": 6,
        "earliest_unproved_operation_id": "rhad:route@0x40A679",
        "first_missing_typed_obligation": (
            "instantiate the proved RhadDirectRoute vocabulary with exact "
            "per-operation native-body proof and dependency closure"
        ),
    }
    assert existing == {
        "operation_variant": "existing_conditional_plus_indirect",
        "total_reference_operations": 117,
        "compiler_supported_operations": 117,
        "compiled_operation_instances": 12,
        "vertically_proved_operations": 12,
        "accepted_receipt_operations": 12,
        "earliest_unproved_reference_order": 27,
        "earliest_unproved_operation_id": "rhad:route@0x40A8E7",
        "first_missing_typed_obligation": (
            "complete the unavailable 0x40A8E9 true-root closure with typed "
            "evidence before mutation"
        ),
    }
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
