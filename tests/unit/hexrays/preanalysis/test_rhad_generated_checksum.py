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
    FragmentSetccFallthroughDelivery,
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


def test_aggregate_identity_binds_conditional_boundary_evidence() -> None:
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None
    row38 = next(
        operation
        for operation in batch.operations
        if operation.operation_id == "rhad:route@0x40AA78"
    )
    changed = replace(
        row38,
        boundary_exit_eas=(0x40AA94, 0x40B0F4, 0x40B21C),
    )
    changed_batch = replace(
        batch,
        operations=tuple(
            changed if operation is row38 else operation
            for operation in batch.operations
        ),
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
    assert len(IMPORTED_BLOCK_IDS) == 434
    assert TEMPLATE_ROOT_EAS == (
        0x40A607,
        0x40B6C0,
        0x40A61B,
        0x40A633,
        0x40A64B,
        0x40A663,
        0x40A5CA,
        0x40AE26,
        0x40AE3E,
        0x40A68C,
        0x40A6A6,
        0x40A6C0,
        0x40A960,
        0x40A6DA,
        0x40AB76,
        0x40A6F4,
        0x40AE8B,
        0x40AEA5,
        0x40AF00,
        0x40A70E,
        0x40A800,
        0x40A81A,
        0x40A834,
        0x40A84E,
        0x40AFDF,
        0x40AFF9,
        0x40A868,
        0x40A8B5,
        0x40A8CF,
        0x40ACBF,
        0x40ACD9,
        0x40B26D,
        0x40B287,
        0x40ACF3,
        0x40A8E9,
        0x40B024,
        0x40A903,
        0x40A97A,
        0x40AD1E,
        0x40AD38,
        0x40AD52,
        0x40B2DB,
        0x40B2F5,
        0x40A994,
        0x40B071,
        0x40A9AE,
        0x40AC3D,
        0x40AC56,
        0x40AC70,
        0x40B21C,
        0x40B236,
        0x40AA60,
        0x40A74C,
        0x40A766,
        0x40A9DE,
        0x40A9F8,
        0x40AD6E,
        0x40AD88,
        0x40ADA2,
        0x40B32C,
        0x40B342,
        0x40AA12,
        0x40B0BC,
        0x40B0D6,
        0x40AA2C,
        0x40AA7A,
        0x40AA88,
        0x40AA94,
        0x40AAA2,
        0x40AAFD,
        0x40AB31,
        0x40AB90,
        0x40B17F,
        0x40B0F2,
        0x40B10C,
        0x40B163,
        0x40B199,
        0x40ADBE,
        0x40ADD8,
        0x40B37C,
        0x40B396,
        0x40B3E5,
        0x40ADF2,
        0x40A77E,
        0x40ABC6,
        0x40ABE0,
        0x40B1D0,
        0x40B1EA,
        0x40ABFA,
        0x40A794,
        0x40A7AE,
        0x40AEE6,
        0x40B03E,
        0x40B08B,
    )
    assert tuple(operation.operation_id for operation in plan.operations) == (
        "rhad:route@0x40A605",
        "route:rhad-direct@0x40A619",
        "route:rhad-direct@0x40A631",
        "route:rhad-direct@0x40A649",
        "route:rhad-direct@0x40A661",
        "route:rhad-direct@0x40A679",
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
        "route:rhad-direct@0x40A7EF",
        "rhad:route@0x40A818",
        "rhad:route@0x40A832",
        "rhad:route@0x40A84C",
        "rhad:route@0x40A866",
        "route:rhad-direct@0x40A8B3",
        "rhad:route@0x40A8CD",
        "rhad:route@0x40A8E7",
        "rhad:route@0x40A901",
        "route:rhad-direct@0x40A95E",
        "rhad:route@0x40A978",
        "rhad:route@0x40A992",
        "rhad:route@0x40A9AC",
        "rhad:route@0x40A9DC",
        "rhad:route@0x40A9F6",
        "rhad:route@0x40AA10",
        "rhad:route@0x40AA2A",
        "rhad:route@0x40AA5E",
        "rhad:route@0x40AA78",
        "rhad:route@0x40AA92",
        "rhad:route@0x40AAAC",
        "route:rhad-direct@0x40AAFB",
        "rhad:route@0x40AB15",
        "rhad:route@0x40AB2F",
        "route:rhad-direct@0x40AB74",
        "rhad:route@0x40AB8E",
        "rhad:route@0x40ABA8",
        "rhad:route@0x40ABDE",
        "rhad:route@0x40ABF8",
        "route:rhad-direct@0x40AC3B",
        "rhad:route@0x40AC54",
        "rhad:route@0x40AC6E",
        "route:rhad-direct@0x40ACBD",
        "rhad:route@0x40ACD7",
        "rhad:route@0x40ACF1",
        "route:rhad-direct@0x40AD1C",
        "rhad:route@0x40AD36",
        "rhad:route@0x40AD50",
        "rhad:route@0x40AD6C",
        "rhad:route@0x40AD86",
        "rhad:route@0x40ADA0",
        "rhad:route@0x40ADBC",
        "rhad:route@0x40ADD6",
        "rhad:route@0x40ADF0",
        "rhad:route@0x40AE18",
        "route:rhad-direct@0x40AE24",
        "rhad:route@0x40AE3C",
        "rhad:route@0x40AE89",
        "rhad:route@0x40AEA3",
        "route:rhad-direct@0x40AEE4",
        "rhad:route@0x40AEFE",
        "route:rhad-direct@0x40AFDD",
        "rhad:route@0x40AFF7",
        "route:rhad-direct@0x40B022",
        "rhad:route@0x40B03C",
        "route:rhad-direct@0x40B06F",
        "rhad:route@0x40B089",
        "rhad:route@0x40B0BA",
        "rhad:route@0x40B0D4",
        "rhad:route@0x40B0F0",
        "rhad:route@0x40B10A",
        "rhad:route@0x40B147",
        "rhad:route@0x40B161",
        "rhad:route@0x40B17D",
        "rhad:route@0x40B197",
        "route:rhad-direct@0x40B1CE",
        "rhad:route@0x40B1E8",
        "rhad:route@0x40B21A",
        "rhad:route@0x40B234",
        "rhad:route@0x40B26B",
        "rhad:route@0x40B285",
            "route:rhad-direct@0x40B2D9",
            "rhad:route@0x40B2F3",
            "route:rhad-direct@0x40B32A",
            "rhad:route@0x40B340",
            "rhad:route@0x40B37A",
            "rhad:route@0x40B394",
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
    row27 = plan.operation("rhad:route@0x40A8E7")
    row27_envelope = row27.computed_branch_normalization.conditional_select_envelope
    row28 = plan.operation("rhad:route@0x40A901")
    row28_envelope = row28.computed_branch_normalization.conditional_select_envelope
    row30 = plan.operation("rhad:route@0x40A978")
    row30_envelope = row30.computed_branch_normalization.conditional_select_envelope
    row31 = plan.operation("rhad:route@0x40A992")
    row31_envelope = row31.computed_branch_normalization.conditional_select_envelope
    row32 = plan.operation("rhad:route@0x40A9AC")
    row32_envelope = row32.computed_branch_normalization.conditional_select_envelope
    row33 = plan.operation("rhad:route@0x40A9DC")
    row33_envelope = row33.computed_branch_normalization.conditional_select_envelope
    row34 = plan.operation("rhad:route@0x40A9F6")
    row34_envelope = row34.computed_branch_normalization.conditional_select_envelope
    row35 = plan.operation("rhad:route@0x40AA10")
    row35_envelope = row35.computed_branch_normalization.conditional_select_envelope
    row36 = plan.operation("rhad:route@0x40AA2A")
    row36_envelope = row36.computed_branch_normalization.conditional_select_envelope
    row37 = plan.operation("rhad:route@0x40AA5E")
    row37_envelope = row37.computed_branch_normalization.conditional_select_envelope
    row38 = plan.operation("rhad:route@0x40AA78")
    row38_envelope = row38.computed_branch_normalization.conditional_select_envelope
    row39 = plan.operation("rhad:route@0x40AA92")
    row39_envelope = row39.computed_branch_normalization.conditional_select_envelope
    row40 = plan.operation("rhad:route@0x40AAAC")
    row40_envelope = row40.computed_branch_normalization.conditional_select_envelope
    row43 = plan.operation("rhad:route@0x40AB15")
    row43_envelope = row43.computed_branch_normalization.conditional_select_envelope
    row44 = plan.operation("rhad:route@0x40AB2F")
    row44_envelope = row44.computed_branch_normalization.conditional_select_envelope
    row46 = plan.operation("rhad:route@0x40AB8E")
    row46_envelope = row46.computed_branch_normalization.conditional_select_envelope
    row47 = plan.operation("rhad:route@0x40ABA8")
    row47_envelope = row47.computed_branch_normalization.conditional_select_envelope
    row49 = plan.operation("rhad:route@0x40ABDE")
    row49_envelope = row49.computed_branch_normalization.conditional_select_envelope
    row50 = plan.operation("rhad:route@0x40ABF8")
    row50_envelope = row50.computed_branch_normalization.conditional_select_envelope
    row52 = plan.operation("rhad:route@0x40AC54")
    row52_envelope = row52.computed_branch_normalization.conditional_select_envelope
    row53 = plan.operation("rhad:route@0x40AC6E")
    row53_envelope = row53.computed_branch_normalization.conditional_select_envelope
    row55 = plan.operation("rhad:route@0x40ACD7")
    row55_envelope = row55.computed_branch_normalization.conditional_select_envelope
    row56 = plan.operation("rhad:route@0x40ACF1")
    row56_envelope = row56.computed_branch_normalization.conditional_select_envelope
    row58 = plan.operation("rhad:route@0x40AD36")
    row58_envelope = row58.computed_branch_normalization.conditional_select_envelope
    row59 = plan.operation("rhad:route@0x40AD50")
    row59_envelope = row59.computed_branch_normalization.conditional_select_envelope
    row60 = plan.operation("rhad:route@0x40AD6C")
    row60_envelope = row60.computed_branch_normalization.conditional_select_envelope
    row61 = plan.operation("rhad:route@0x40AD86")
    row61_envelope = row61.computed_branch_normalization.conditional_select_envelope
    row62 = plan.operation("rhad:route@0x40ADA0")
    row62_envelope = row62.computed_branch_normalization.conditional_select_envelope
    row63 = plan.operation("rhad:route@0x40ADBC")
    row63_envelope = row63.computed_branch_normalization.conditional_select_envelope
    row64 = plan.operation("rhad:route@0x40ADD6")
    row64_envelope = row64.computed_branch_normalization.conditional_select_envelope
    row65 = plan.operation("rhad:route@0x40ADF0")
    row65_envelope = row65.computed_branch_normalization.conditional_select_envelope
    row66 = plan.operation("rhad:route@0x40AE18")
    row66_envelope = row66.computed_branch_normalization.conditional_select_envelope
    row68 = plan.operation("rhad:route@0x40AE3C")
    row69 = plan.operation("rhad:route@0x40AE89")
    row69_envelope = row69.computed_branch_normalization.conditional_select_envelope
    row70 = plan.operation("rhad:route@0x40AEA3")
    row70_envelope = row70.computed_branch_normalization.conditional_select_envelope
    row72 = plan.operation("rhad:route@0x40AEFE")
    row72_envelope = row72.computed_branch_normalization.conditional_select_envelope
    row74 = plan.operation("rhad:route@0x40AFF7")
    row74_envelope = row74.computed_branch_normalization.conditional_select_envelope
    row76 = plan.operation("rhad:route@0x40B03C")
    row76_envelope = row76.computed_branch_normalization.conditional_select_envelope
    row78 = plan.operation("rhad:route@0x40B089")
    row78_envelope = row78.computed_branch_normalization.conditional_select_envelope
    row79 = plan.operation("rhad:route@0x40B0BA")
    row79_envelope = row79.computed_branch_normalization.conditional_select_envelope
    row80 = plan.operation("rhad:route@0x40B0D4")
    row80_envelope = row80.computed_branch_normalization.conditional_select_envelope
    row81 = plan.operation("rhad:route@0x40B0F0")
    row81_envelope = row81.computed_branch_normalization.conditional_select_envelope
    row82 = plan.operation("rhad:route@0x40B10A")
    row82_envelope = row82.computed_branch_normalization.conditional_select_envelope
    row83 = plan.operation("rhad:route@0x40B147")
    row83_envelope = row83.computed_branch_normalization.conditional_select_envelope
    row84 = plan.operation("rhad:route@0x40B161")
    row84_envelope = row84.computed_branch_normalization.conditional_select_envelope
    row85 = plan.operation("rhad:route@0x40B17D")
    row85_envelope = row85.computed_branch_normalization.conditional_select_envelope
    row86 = plan.operation("rhad:route@0x40B197")
    row86_envelope = row86.computed_branch_normalization.conditional_select_envelope
    row88 = plan.operation("rhad:route@0x40B1E8")
    row88_envelope = row88.computed_branch_normalization.conditional_select_envelope
    row89 = plan.operation("rhad:route@0x40B21A")
    row89_envelope = row89.computed_branch_normalization.conditional_select_envelope
    row90 = plan.operation("rhad:route@0x40B234")
    row90_envelope = row90.computed_branch_normalization.conditional_select_envelope
    row91 = plan.operation("rhad:route@0x40B26B")
    row91_envelope = row91.computed_branch_normalization.conditional_select_envelope
    row92 = plan.operation("rhad:route@0x40B285")
    row92_envelope = row92.computed_branch_normalization.conditional_select_envelope
    row94 = plan.operation("rhad:route@0x40B2F3")
    row94_envelope = row94.computed_branch_normalization.conditional_select_envelope
    row96 = plan.operation("rhad:route@0x40B340")
    row97 = plan.operation("rhad:route@0x40B37A")
    row97_envelope = row97.computed_branch_normalization.conditional_select_envelope
    row98 = plan.operation("rhad:route@0x40B394")
    row98_envelope = row98.computed_branch_normalization.conditional_select_envelope
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
        row27.source_block_id,
        row27_envelope.selected_value_block_id,
        row27_envelope.join_block_id,
        row28.source_block_id,
        row28_envelope.selected_value_block_id,
        row28_envelope.join_block_id,
        row30.source_block_id,
        row30_envelope.selected_value_block_id,
        row30_envelope.join_block_id,
        row31.source_block_id,
        row31_envelope.selected_value_block_id,
        row31_envelope.join_block_id,
        row32.source_block_id,
        row32_envelope.selected_value_block_id,
        row32_envelope.join_block_id,
        row33.source_block_id,
        row33_envelope.selected_value_block_id,
        row33_envelope.join_block_id,
        row34.source_block_id,
        row34_envelope.selected_value_block_id,
        row34_envelope.join_block_id,
        row35.source_block_id,
        row35_envelope.selected_value_block_id,
        row35_envelope.join_block_id,
        row36.source_block_id,
        row36_envelope.selected_value_block_id,
        row36_envelope.join_block_id,
        row37.source_block_id,
        row37_envelope.selected_value_block_id,
        row37_envelope.join_block_id,
        row38.source_block_id,
        row38_envelope.selected_value_block_id,
        row38_envelope.join_block_id,
        row39.source_block_id,
        row39_envelope.selected_value_block_id,
        row39_envelope.join_block_id,
        row40.source_block_id,
        row40_envelope.selected_value_block_id,
        row40_envelope.join_block_id,
        row43.source_block_id,
        row43_envelope.selected_value_block_id,
        row43_envelope.join_block_id,
        row44.source_block_id,
        row44_envelope.selected_value_block_id,
        row44_envelope.join_block_id,
        row46.source_block_id,
        row46_envelope.selected_value_block_id,
        row46_envelope.join_block_id,
        row47.source_block_id,
        row47_envelope.selected_value_block_id,
        row47_envelope.join_block_id,
        row49.source_block_id,
        row49_envelope.selected_value_block_id,
        row49_envelope.join_block_id,
        row50.source_block_id,
        row50_envelope.selected_value_block_id,
        row50_envelope.join_block_id,
        row52.source_block_id,
        row52_envelope.selected_value_block_id,
        row52_envelope.join_block_id,
        row53.source_block_id,
        row53_envelope.selected_value_block_id,
        row53_envelope.join_block_id,
        row55.source_block_id,
        row55_envelope.selected_value_block_id,
        row55_envelope.join_block_id,
        row56.source_block_id,
        row56_envelope.selected_value_block_id,
        row56_envelope.join_block_id,
        row58.source_block_id,
        row58_envelope.selected_value_block_id,
        row58_envelope.join_block_id,
        row59.source_block_id,
        row59_envelope.selected_value_block_id,
        row59_envelope.join_block_id,
        row60.source_block_id,
        row60_envelope.selected_value_block_id,
        row60_envelope.join_block_id,
        row61.source_block_id,
        row61_envelope.selected_value_block_id,
        row61_envelope.join_block_id,
        row62.source_block_id,
        row62_envelope.selected_value_block_id,
        row62_envelope.join_block_id,
        row63.source_block_id,
        row63_envelope.selected_value_block_id,
        row63_envelope.join_block_id,
        row64.source_block_id,
        row64_envelope.selected_value_block_id,
        row64_envelope.join_block_id,
        row65.source_block_id,
        row65_envelope.selected_value_block_id,
        row65_envelope.join_block_id,
        row66.source_block_id,
        row66_envelope.selected_value_block_id,
        row66_envelope.join_block_id,
        row68.source_block_id,
        row69.source_block_id,
        row69_envelope.selected_value_block_id,
        row69_envelope.join_block_id,
        row70.source_block_id,
        row70_envelope.selected_value_block_id,
        row70_envelope.join_block_id,
        row72.source_block_id,
        row72_envelope.selected_value_block_id,
        row72_envelope.join_block_id,
        row74.source_block_id,
        row74_envelope.selected_value_block_id,
        row74_envelope.join_block_id,
        row76.source_block_id,
        row76_envelope.selected_value_block_id,
        row76_envelope.join_block_id,
        row78.source_block_id,
        row78_envelope.selected_value_block_id,
        row78_envelope.join_block_id,
        row79.source_block_id,
        row79_envelope.selected_value_block_id,
        row79_envelope.join_block_id,
        row80.source_block_id,
        row80_envelope.selected_value_block_id,
        row80_envelope.join_block_id,
        row81.source_block_id,
        row81_envelope.selected_value_block_id,
        row81_envelope.join_block_id,
        row82.source_block_id,
        row82_envelope.selected_value_block_id,
        row82_envelope.join_block_id,
        row83.source_block_id,
        row83_envelope.selected_value_block_id,
        row83_envelope.join_block_id,
        row84.source_block_id,
        row84_envelope.selected_value_block_id,
        row84_envelope.join_block_id,
        row85.source_block_id,
        row85_envelope.selected_value_block_id,
        row85_envelope.join_block_id,
        row86.source_block_id,
        row86_envelope.selected_value_block_id,
        row86_envelope.join_block_id,
        row88.source_block_id,
        row88_envelope.selected_value_block_id,
        row88_envelope.join_block_id,
        row89.source_block_id,
        row89_envelope.selected_value_block_id,
        row89_envelope.join_block_id,
        row90.source_block_id,
        row90_envelope.selected_value_block_id,
        row90_envelope.join_block_id,
        row91.source_block_id,
        row91_envelope.selected_value_block_id,
        row91_envelope.join_block_id,
        row92.source_block_id,
        row92_envelope.selected_value_block_id,
        row92_envelope.join_block_id,
        row94.source_block_id,
        row94_envelope.selected_value_block_id,
        row94_envelope.join_block_id,
        row96.source_block_id,
        row97.source_block_id,
        row97_envelope.selected_value_block_id,
        row97_envelope.join_block_id,
        row98.source_block_id,
        row98_envelope.selected_value_block_id,
        row98_envelope.join_block_id,
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
        0x40A5F0,
        0x40A9A0,
        0x40B3B0,
        0x40B3FF,
        0x40B55B,
        0x40B790,
        0x40C898,
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
        fragment
        for fragment in batch.template_fragments
        if fragment.root_ea == 0x40A6C0
    )
    assert true_template.preserved_transfer_exit_map == {
        0x40A6D8: (0x40A6DA, 0x40AB76),
    }
    false_template = next(
        fragment
        for fragment in batch.template_fragments
        if fragment.root_ea == 0x40A960
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
        fragment
        for fragment in batch.template_fragments
        if fragment.root_ea == 0x40A6DA
    )
    assert true_template.preserved_transfer_exit_map == {
        0x40A6F2: (0x40A6F4, 0x40AE8B),
    }
    false_template = next(
        fragment
        for fragment in batch.template_fragments
        if fragment.root_ea == 0x40AB76
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
        fragment
        for fragment in batch.template_fragments
        if fragment.root_ea == 0x40A6F4
    )
    assert true_template.preserved_transfer_exit_map == {
        0x40A70C: (0x40A5F0, 0x40A70E),
    }
    false_template = next(
        fragment
        for fragment in batch.template_fragments
        if fragment.root_ea == 0x40AE8B
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
        fragment
        for fragment in batch.template_fragments
        if fragment.root_ea == 0x40A70E
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
        fragment
        for fragment in batch.template_fragments
        if fragment.root_ea == 0x40A81A
    )
    assert true_template.preserved_transfer_exit_map == {
        0x40A832: (0x40A834, 0x40AC3D),
    }
    false_template = next(
        fragment
        for fragment in batch.template_fragments
        if fragment.root_ea == 0x40AA60
    )
    assert false_template.preserved_transfer_exit_map == {
        0x40AA78: (0x40AA7A, 0x40ADBE),
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
        fragment
        for fragment in batch.template_fragments
        if fragment.root_ea == 0x40A834
    )
    assert true_template.preserved_transfer_exit_map == {
        0x40A84C: (0x40A84E, 0x40AFDF),
    }
    false_template = next(
        fragment
        for fragment in batch.template_fragments
        if fragment.root_ea == 0x40AC3D
    )
    assert false_template.preserved_transfer_exit_map == {
        0x40AC54: (0x40AC56, 0x40B21C),
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
        fragment
        for fragment in batch.template_fragments
        if fragment.root_ea == 0x40A84E
    )
    assert true_template.preserved_transfer_exit_map == {
        0x40A866: (0x40A5F0, 0x40A868),
    }
    false_template = next(
        fragment
        for fragment in batch.template_fragments
        if fragment.root_ea == 0x40AFDF
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
    }.issubset(plan.native_bodies[0].block_ids)
    true_template = next(
        fragment
        for fragment in batch.template_fragments
        if fragment.root_ea == 0x40A868
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
        fragment
        for fragment in batch.template_fragments
        if fragment.root_ea == 0x40A8B5
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
    operation_by_id = {
        operation.operation_id: operation for operation in batch.operations
    }
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
        fragment
        for fragment in batch.template_fragments
        if fragment.root_ea == 0x40A633
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
    operation_by_id = {
        operation.operation_id: operation for operation in batch.operations
    }
    assert operation_by_id["route:rhad-direct@0x40A661"].depends_on == (
        "route:rhad-direct@0x40A631",
    )
    source = next(
        fragment
        for fragment in batch.template_fragments
        if fragment.root_ea == 0x40A64B
    )
    assert source.owned_ranges == (
        (0x40A64B, 0x40A663),
        (0x40AAF1, 0x40AAFD),
    )
    assert source.preserved_transfer_exit_map == {0x40AAFB: (0x40AAFD,)}
    closure = next(
        fragment
        for fragment in batch.template_fragments
        if fragment.root_ea == 0x40A663
    )
    assert closure.owned_ranges == (
        (0x40A663, 0x40A67B),
        (0x40AE1A, 0x40AE26),
    )
    assert closure.preserved_transfer_exit_map == {
        0x40A679: (0x40AE26,),
        0x40AE24: (0x40A5CA,),
    }


def test_checksum_producer_compiles_row6_direct_route() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    row6 = plan.operation("route:rhad-direct@0x40A679")
    assert row6.direct_transfer_rewrite.rewrite_anchor_ea == 0x40A679
    assert row6.edges[0].target_block_id == "native@0x40AE26"
    payload = json.loads(
        row6.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_operation_id"] == "rhad:route@0x40A679"
    assert payload["reference_order"] == 6
    assert payload["operation_variant"] == "simple_indirect_jump"
    operation_by_id = {
        operation.operation_id: operation for operation in batch.operations
    }
    assert operation_by_id["route:rhad-direct@0x40A679"].depends_on == (
        "route:rhad-direct@0x40A661",
    )
    closure = next(
        fragment
        for fragment in batch.template_fragments
        if fragment.root_ea == 0x40AE26
    )
    assert closure.owned_ranges == ((0x40AE26, 0x40AE3E),)
    assert closure.preserved_transfer_exit_map == {
        0x40AE3C: (0x40A5F0, 0x40AE3E),
    }
    assert {"native@0x40AE26", "native@0x40AE3C"}.issubset(
        batch.native_body_entry_block_ids
    )


def test_checksum_producer_compiles_row19_direct_route() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    row19 = plan.operation("route:rhad-direct@0x40A7EF")
    assert row19.direct_transfer_rewrite.rewrite_anchor_ea == 0x40A7EF
    assert row19.edges[0].target_block_id == "native@0x40B6C0"
    payload = json.loads(
        row19.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_operation_id"] == "rhad:route@0x40A7EF"
    assert payload["reference_order"] == 19
    assert payload["operation_variant"] == "simple_indirect_jump"
    assert payload["source_native_ea"] == 0x40A7CD
    assert payload["source_block_anchor_ea"] == 0x40A7E5
    assert payload["owned_corridor_instruction_eas"] == [
        0x40A7CD,
        0x40A7E5,
        0x40A7E7,
        0x40A7E9,
        0x40A7EF,
    ]
    assert payload["imported_closure_block_ids"] == [
        "native@0x40B6C0",
        "native@0x40B6CA",
        "native@0x40B6D0",
        "native@0x40B6D4",
    ]
    assert payload["boundary_exit_eas"] == [0x40B790]
    operation_by_id = {
        operation.operation_id: operation for operation in batch.operations
    }
    assert operation_by_id["route:rhad-direct@0x40A7EF"].depends_on == (
        "rhad:route@0x40A7AC",
    )


def test_checksum_producer_compiles_row25_direct_route() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    row25 = plan.operation("route:rhad-direct@0x40A8B3")
    assert row25.direct_transfer_rewrite.rewrite_anchor_ea == 0x40A8B3
    assert row25.edges[0].target_block_id == "native@0x40A64B"
    payload = json.loads(
        row25.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_operation_id"] == "rhad:route@0x40A8B3"
    assert payload["reference_order"] == 25
    assert payload["operation_variant"] == "simple_indirect_jump"
    assert payload["source_native_ea"] == 0x40A63F
    assert payload["source_block_anchor_ea"] == 0x40A8A9
    assert payload["owned_corridor_instruction_eas"] == [
        0x40A63F,
        0x40A8A9,
        0x40A8AF,
        0x40A8B1,
        0x40A8B3,
    ]
    assert payload["imported_closure_block_ids"] == [
        "native@0x40A64B",
        "native@0x40A65D",
        "native@0x40A661",
        "native@0x40AAF1",
        "native@0x40AAFB",
    ]
    assert payload["boundary_exit_eas"] == [0x40A663, 0x40AAFD]
    operation_by_id = {
        operation.operation_id: operation for operation in batch.operations
    }
    assert operation_by_id["route:rhad-direct@0x40A8B3"].depends_on == (
        "route:rhad-direct@0x40A631",
    )


def test_checksum_producer_compiles_row27_existing_conditional_reference() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40A8E7")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.SLT
    assert normalization.condition_producer_ea == 0x40A8D5
    assert normalization.unresolved_transfer_ea == 0x40A8E7
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40A8E9",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40B024",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 27
    assert payload["observed_predicate_kind"] == PredicateKind.SGE.value
    assert payload["predicate_kind"] == PredicateKind.SLT.value
    assert payload["comparison_constant"] == 0x0CDF90C9
    assert payload["boundary_exit_eas"] == [0x40A5F0, 0x40A903]
    operation_by_id = {
        operation.operation_id: operation for operation in batch.operations
    }
    assert operation_by_id["rhad:route@0x40A8E7"].depends_on == ("rhad:route@0x40A8CD",)
    assert {
        "native@0x40A8E9",
        "native@0x40A8F7",
        "native@0x40A8FD",
        "native@0x40A901",
        "native@0x40B024",
        "native@0x40B032",
        "native@0x40B038",
        "native@0x40B03C",
    }.issubset(plan.native_bodies[0].block_ids)
    true_template = next(
        fragment
        for fragment in batch.template_fragments
        if fragment.root_ea == 0x40A8E9
    )
    assert true_template.preserved_transfer_exit_map == {
        0x40A901: (0x40A5F0, 0x40A903),
    }


def test_checksum_producer_compiles_row28_existing_conditional_reference() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40A901")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.EQ
    assert normalization.condition_producer_ea == 0x40A8EF
    assert normalization.unresolved_transfer_ea == 0x40A901
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40A903",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40A5F0",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 28
    assert payload["observed_predicate_kind"] == PredicateKind.NE.value
    assert payload["predicate_kind"] == PredicateKind.EQ.value
    assert payload["comparison_constant"] == 0x0BB2D365
    assert payload["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
    operation_by_id = {
        operation.operation_id: operation for operation in batch.operations
    }
    assert operation_by_id["rhad:route@0x40A901"].depends_on == ("rhad:route@0x40A8E7",)
    assert {
        "native@0x40A903",
        "native@0x40A922",
        "native@0x40A93C",
        "native@0x40A954",
        "native@0x40A95E",
        "native@0x40B4F0",
        "native@0x40B50D",
        "native@0x40B519",
    }.issubset(plan.native_bodies[0].block_ids)
    true_template = next(
        fragment
        for fragment in batch.template_fragments
        if fragment.root_ea == 0x40A903
    )
    assert true_template.preserved_transfer_exit_map == {
        0x40A95E: (0x40A607, 0x40B6C0),
        0x40B519: (0x40A607, 0x40B6C0),
    }


def test_checksum_producer_compiles_row29_direct_route() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("route:rhad-direct@0x40A95E")
    assert operation.direct_transfer_rewrite is not None
    assert operation.direct_transfer_rewrite.rewrite_anchor_ea == 0x40A95E
    assert operation.direct_transfer_rewrite.owner_anchor_ea == 0x40A954
    assert operation.edges[0].target_block_id == "native@0x40B6C0"
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_operation_id"] == "rhad:route@0x40A95E"
    assert payload["reference_order"] == 29
    assert payload["operation_variant"] == "simple_indirect_jump"
    assert payload["source_native_ea"] == 0x40A93C
    assert payload["source_block_anchor_ea"] == 0x40A954
    assert payload["transfer_ea"] == 0x40A95E
    assert payload["owned_corridor_instruction_eas"] == [
        0x40A93C,
        0x40A954,
        0x40A956,
        0x40A958,
        0x40A95E,
    ]
    assert payload["imported_closure_block_ids"] == [
        "native@0x40B6C0",
        "native@0x40B6CA",
        "native@0x40B6D0",
        "native@0x40B6D4",
    ]
    assert payload["boundary_exit_eas"] == [0x40B790]
    operation_by_id = {
        operation.operation_id: operation for operation in batch.operations
    }
    assert operation_by_id["route:rhad-direct@0x40A95E"].depends_on == (
        "rhad:route@0x40A901",
    )


def test_checksum_producer_compiles_row30_existing_conditional_reference() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40A978")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.SLT
    assert normalization.condition_producer_ea == 0x40A966
    assert normalization.unresolved_transfer_ea == 0x40A978
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40A97A",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40AD1E",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 30
    assert payload["observed_predicate_kind"] == PredicateKind.SGE.value
    assert payload["predicate_kind"] == PredicateKind.SLT.value
    assert payload["comparison_constant"] == 0x636961E8
    assert payload["boundary_exit_eas"] == [0x40A994, 0x40B071, 0x40B55B]
    operation_by_id = {
        operation.operation_id: operation for operation in batch.operations
    }
    assert operation_by_id["rhad:route@0x40A978"].depends_on == ("rhad:route@0x40A6BE",)
    assert {
        "native@0x40A97A",
        "native@0x40A988",
        "native@0x40A98E",
        "native@0x40A992",
        "native@0x40AD1E",
        "native@0x40AD2C",
        "native@0x40AD32",
        "native@0x40AD36",
    }.issubset(plan.native_bodies[0].block_ids)


def test_checksum_producer_compiles_row31_existing_conditional_reference() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40A992")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.SLT
    assert normalization.condition_producer_ea == 0x40A980
    assert normalization.unresolved_transfer_ea == 0x40A992
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40A994",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40B071",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 31
    assert payload["observed_predicate_kind"] == PredicateKind.SGE.value
    assert payload["predicate_kind"] == PredicateKind.SLT.value
    assert payload["comparison_constant"] == 0x5E07BA29
    assert payload["boundary_exit_eas"] == [0x40A5F0, 0x40A9AE]
    operation_by_id = {
        operation.operation_id: operation for operation in batch.operations
    }
    assert operation_by_id["rhad:route@0x40A992"].depends_on == ("rhad:route@0x40A978",)
    assert {
        "native@0x40A994",
        "native@0x40A9A2",
        "native@0x40A9A8",
        "native@0x40A9AC",
        "native@0x40B071",
        "native@0x40B07F",
        "native@0x40B085",
        "native@0x40B089",
    }.issubset(plan.native_bodies[0].block_ids)


def test_checksum_producer_compiles_row32_existing_conditional_reference() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40A9AC")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.EQ
    assert normalization.condition_producer_ea == 0x40A99A
    assert normalization.unresolved_transfer_ea == 0x40A9AC
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40A9AE",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40A5F0",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 32
    assert payload["observed_predicate_kind"] == PredicateKind.NE.value
    assert payload["predicate_kind"] == PredicateKind.EQ.value
    assert payload["comparison_constant"] == 0x4DFFC906
    assert payload["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
    operation_by_id = {
        operation.operation_id: operation for operation in batch.operations
    }
    assert operation_by_id["rhad:route@0x40A9AC"].depends_on == ("rhad:route@0x40A992",)
    assert {
        "native@0x40A9AE",
        "native@0x40A9D5",
        "native@0x40A9D8",
        "native@0x40A9DC",
    }.issubset(plan.native_bodies[0].block_ids)


def test_checksum_producer_compiles_row33_cmov_selected_reference() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40A9DC")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.SLT
    assert normalization.condition_producer_ea == 0x40A9C7
    assert normalization.unresolved_transfer_ea == 0x40A9DC
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40B6C0",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40A607",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 33
    assert payload["reference_symbol"] == "JumpInliner._fixup_cmov"
    assert payload["operation_variant"] == "cmov_selected_indirect"
    assert payload["source_native_ea"] == 0x40A9B3
    assert payload["source_block_anchor_ea"] == 0x40A9AE
    assert payload["observed_predicate_kind"] == PredicateKind.SGE.value
    assert payload["predicate_kind"] == PredicateKind.SLT.value
    assert payload["comparison_constant"] == 0x0BB2D365
    assert payload["true_target_ea"] == 0x40B6C0
    assert payload["false_target_ea"] == 0x40A607
    assert payload["boundary_exit_eas"] == [0x40A61B, 0x40A68C, 0x40B790]
    operation_by_id = {
        operation.operation_id: operation for operation in batch.operations
    }
    assert operation_by_id["rhad:route@0x40A9DC"].depends_on == ("rhad:route@0x40A9AC",)


def test_checksum_producer_compiles_row34_existing_conditional_reference() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )

    operation = plan.operation("rhad:route@0x40A9F6")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.SLT
    assert normalization.condition_producer_ea == 0x40A9E4
    assert normalization.unresolved_transfer_ea == 0x40A9F6
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40A9F8",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40AD6E",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 34
    assert payload["reference_symbol"] == ("JumpInliner._fixup_jmp_and_possible_jcc")
    assert payload["operation_variant"] == "existing_conditional_plus_indirect"
    assert payload["source_native_ea"] == 0x40A9DE
    assert payload["source_block_anchor_ea"] == 0x40A9F2
    assert payload["observed_predicate_kind"] == PredicateKind.SGE.value
    assert payload["predicate_kind"] == PredicateKind.SLT.value
    assert payload["comparison_constant"] == 0x2B8162DC
    assert payload["true_target_ea"] == 0x40A9F8
    assert payload["false_target_ea"] == 0x40AD6E
    assert payload["boundary_exit_eas"] == [
        0x40AA12,
        0x40AD88,
        0x40B0BC,
        0x40B32C,
    ]


def test_checksum_producer_compiles_row35_existing_conditional_reference() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )

    operation = plan.operation("rhad:route@0x40AA10")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.SLT
    assert normalization.condition_producer_ea == 0x40A9FE
    assert normalization.unresolved_transfer_ea == 0x40AA10
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40AA12",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40B0BC",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 35
    assert payload["reference_symbol"] == ("JumpInliner._fixup_jmp_and_possible_jcc")
    assert payload["operation_variant"] == "existing_conditional_plus_indirect"
    assert payload["source_native_ea"] == 0x40A9F8
    assert payload["source_block_anchor_ea"] == 0x40AA0C
    assert payload["observed_predicate_kind"] == PredicateKind.SGE.value
    assert payload["predicate_kind"] == PredicateKind.SLT.value
    assert payload["comparison_constant"] == 0x29947C85
    assert payload["true_target_ea"] == 0x40AA12
    assert payload["false_target_ea"] == 0x40B0BC
    assert payload["boundary_exit_eas"] == [0x40A5F0]


def test_checksum_producer_compiles_row36_existing_conditional_reference() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )

    operation = plan.operation("rhad:route@0x40AA2A")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.EQ
    assert normalization.condition_producer_ea == 0x40AA18
    assert normalization.unresolved_transfer_ea == 0x40AA2A
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40AA2C",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40A5F0",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 36
    assert payload["reference_symbol"] == ("JumpInliner._fixup_jmp_and_possible_jcc")
    assert payload["operation_variant"] == "existing_conditional_plus_indirect"
    assert payload["source_native_ea"] == 0x40AA12
    assert payload["source_block_anchor_ea"] == 0x40AA26
    assert payload["observed_predicate_kind"] == PredicateKind.NE.value
    assert payload["predicate_kind"] == PredicateKind.EQ.value
    assert payload["comparison_constant"] == 0x23B8E806
    assert payload["true_target_ea"] == 0x40AA2C
    assert payload["false_target_ea"] == 0x40A5F0
    assert payload["imported_closure_block_ids"] == [
        "native@0x40AA2C",
        "native@0x40AA35",
        "native@0x40AA57",
        "native@0x40AA5A",
        "native@0x40AA5E",
    ]
    assert payload["boundary_exit_eas"] == [0x40A607, 0x40B6C0]


def test_checksum_producer_compiles_row37_cmov_selected_reference() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40AA5E")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.SLT
    assert normalization.condition_producer_ea == 0x40AA49
    assert normalization.unresolved_transfer_ea == 0x40AA5E
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40B6C0",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40A607",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 37
    assert payload["reference_symbol"] == "JumpInliner._fixup_cmov"
    assert payload["operation_variant"] == "cmov_selected_indirect"
    assert payload["source_native_ea"] == 0x40AA3B
    assert payload["source_block_anchor_ea"] == 0x40AA35
    assert payload["observed_predicate_kind"] == PredicateKind.SGE.value
    assert payload["predicate_kind"] == PredicateKind.SLT.value
    assert payload["comparison_constant"] == 0x0BB2D365
    assert payload["true_target_ea"] == 0x40B6C0
    assert payload["false_target_ea"] == 0x40A607
    assert payload["boundary_exit_eas"] == [0x40A61B, 0x40A68C, 0x40B790]
    operation_by_id = {
        operation.operation_id: operation for operation in batch.operations
    }
    assert operation_by_id["rhad:route@0x40AA5E"].depends_on == ("rhad:route@0x40AA2A",)


def test_checksum_producer_compiles_row38_existing_conditional_reference() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40AA78")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.SLT
    assert normalization.condition_producer_ea == 0x40AA66
    assert normalization.unresolved_transfer_ea == 0x40AA78
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40AA7A",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40ADBE",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 38
    assert payload["reference_symbol"] == "JumpInliner._fixup_jmp_and_possible_jcc"
    assert payload["operation_variant"] == "existing_conditional_plus_indirect"
    assert payload["source_native_ea"] == 0x40AA60
    assert payload["source_block_anchor_ea"] == 0x40AA74
    assert payload["observed_predicate_kind"] == PredicateKind.SGE.value
    assert payload["predicate_kind"] == PredicateKind.SLT.value
    assert payload["comparison_constant"] == 0x7C4FB03D
    assert payload["true_target_ea"] == 0x40AA7A
    assert payload["false_target_ea"] == 0x40ADBE
    assert payload["imported_closure_block_ids"] == [
        "native@0x40AA7A",
        "native@0x40AA88",
        "native@0x40AA8E",
        "native@0x40AA92",
        "native@0x40ADBE",
        "native@0x40ADCC",
        "native@0x40ADD2",
        "native@0x40ADD6",
    ]
    assert payload["boundary_exit_eas"] == [
        0x40AA94,
        0x40ADD8,
        0x40B0F2,
        0x40B37C,
    ]
    operation_by_id = {
        operation.operation_id: operation for operation in batch.operations
    }
    assert operation_by_id["rhad:route@0x40AA78"].depends_on == ("rhad:route@0x40A818",)
    true_template = next(
        fragment
        for fragment in batch.template_fragments
        if fragment.root_ea == 0x40AA88
    )
    assert true_template.preserved_transfer_exit_map == {
        0x40AA92: (0x40AA94, 0x40B0F2),
    }
    false_template = next(
        fragment
        for fragment in batch.template_fragments
        if fragment.root_ea == 0x40ADBE
    )
    assert false_template.preserved_transfer_exit_map == {
        0x40ADD6: (0x40ADD8, 0x40B37C),
    }
    assert {"native@0x40AA88", "native@0x40ADBE"}.issubset(
        batch.native_body_entry_block_ids
    )


def test_checksum_producer_compiles_row39_existing_conditional_reference() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40AA92")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.SLT
    assert normalization.condition_producer_ea == 0x40AA80
    assert normalization.unresolved_transfer_ea == 0x40AA92
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40AA94",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40B0F2",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 39
    assert payload["reference_symbol"] == "JumpInliner._fixup_jmp_and_possible_jcc"
    assert payload["operation_variant"] == "existing_conditional_plus_indirect"
    assert payload["source_native_ea"] == 0x40AA7A
    assert payload["source_block_anchor_ea"] == 0x40AA88
    assert payload["observed_predicate_kind"] == PredicateKind.SGE.value
    assert payload["predicate_kind"] == PredicateKind.SLT.value
    assert payload["comparison_constant"] == 0x78BAC34B
    assert payload["true_target_ea"] == 0x40AA94
    assert payload["false_target_ea"] == 0x40B0F2
    assert payload["imported_closure_block_ids"] == [
        "native@0x40AA94",
        "native@0x40AAA2",
        "native@0x40AAA8",
        "native@0x40AAAC",
        "native@0x40B0F2",
        "native@0x40B100",
        "native@0x40B106",
        "native@0x40B10A",
    ]
    assert payload["boundary_exit_eas"] == [0x40A5F0, 0x40AAAE]
    operation_by_id = {
        operation.operation_id: operation for operation in batch.operations
    }
    assert operation_by_id["rhad:route@0x40AA92"].depends_on == ("rhad:route@0x40AA78",)
    source_template = next(
        fragment
        for fragment in batch.template_fragments
        if fragment.root_ea == 0x40AA7A
    )
    assert source_template.boundary_exit_eas == (
        0x40AA88,
        0x40AA8E,
        0x40AA94,
        0x40B0F2,
    )
    assert source_template.preserved_transfer_exit_map == {
        0x40AA92: (0x40AA94, 0x40B0F2),
    }
    true_template = next(
        fragment
        for fragment in batch.template_fragments
        if fragment.root_ea == 0x40AAA2
    )
    assert true_template.preserved_transfer_exit_map[0x40AAAC] == (
        0x40A5F0,
        0x40AAAE,
    )
    false_template = next(
        fragment
        for fragment in batch.template_fragments
        if fragment.root_ea == 0x40B0F2
    )
    assert false_template.preserved_transfer_exit_map == {
        0x40B10A: (0x40A5F0,),
    }
    assert {
        "native@0x40AA7A",
        "native@0x40AAA2",
        "native@0x40B0F2",
    }.issubset(batch.native_body_entry_block_ids)


def test_checksum_producer_compiles_row40_existing_conditional_reference() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40AAAC")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.EQ
    assert normalization.condition_producer_ea == 0x40AA9A
    assert normalization.unresolved_transfer_ea == 0x40AAAC
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40AAAE",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40A5F0",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 40
    assert payload["reference_symbol"] == "JumpInliner._fixup_jmp_and_possible_jcc"
    assert payload["operation_variant"] == "existing_conditional_plus_indirect"
    assert payload["source_native_ea"] == 0x40AA94
    assert payload["source_block_anchor_ea"] == 0x40AAA2
    assert payload["join_ea"] == 0x40AAA8
    assert payload["observed_predicate_kind"] == PredicateKind.NE.value
    assert payload["predicate_kind"] == PredicateKind.EQ.value
    assert payload["comparison_constant"] == 0x742F372A
    assert payload["true_target_ea"] == 0x40AAAE
    assert payload["false_target_ea"] == 0x40A5F0
    assert payload["owned_corridor_instruction_eas"] == [
        0x40AA94,
        0x40AA9A,
        0x40AAA0,
        0x40AAA2,
        0x40AAA8,
        0x40AAAA,
        0x40AAAC,
    ]
    assert payload["imported_closure_block_ids"] == [
        "native@0x40AAAE",
        "native@0x40AAE8",
        "native@0x40AAEB",
        "native@0x40AAEF",
    ]
    assert payload["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
    operation_by_id = {
        operation.operation_id: operation for operation in batch.operations
    }
    assert operation_by_id["rhad:route@0x40AAAC"].depends_on == ("rhad:route@0x40AA92",)
    source_template = next(
        fragment
        for fragment in batch.template_fragments
        if fragment.root_ea == 0x40AA94
    )
    assert source_template.boundary_exit_eas == (
        0x40AAA2,
        0x40AAA8,
        0x40A5F0,
        0x40AAAE,
    )
    assert source_template.preserved_transfer_exit_map == {
        0x40AAAC: (0x40A5F0, 0x40AAAE),
    }
    true_template = next(
        fragment
        for fragment in batch.template_fragments
        if fragment.root_ea == 0x40AAA2
    )
    assert true_template.preserved_transfer_exit_map[0x40AAEF] == (
        0x40A607,
        0x40B6C0,
    )
    assert {
        "native@0x40AA94",
        "native@0x40AAAE",
    }.issubset(batch.native_body_entry_block_ids)
    assert batch.source.block_id == "native@0x40A5F0"


def test_checksum_producer_compiles_row42_direct_dependency() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("route:rhad-direct@0x40AAFB")
    assert operation.direct_transfer_rewrite.rewrite_anchor_ea == 0x40AAFB
    assert operation.edges[0].target_block_id == "native@0x40AAFD"
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_operation_id"] == "rhad:route@0x40AAFB"
    assert payload["reference_order"] == 42
    assert payload["operation_variant"] == "simple_indirect_jump"
    assert payload["source_native_ea"] == 0x40A657
    assert payload["source_block_anchor_ea"] == 0x40AAF1
    assert payload["transfer_ea"] == 0x40AAFB
    assert payload["direct_target_block_id"] == "native@0x40AAFD"
    assert payload["owned_corridor_instruction_eas"] == [
        0x40A657,
        0x40AAF1,
        0x40AAF7,
        0x40AAF9,
        0x40AAFB,
    ]
    assert payload["imported_closure_block_ids"] == [
        "native@0x40AAFD",
        "native@0x40AB0B",
        "native@0x40AB11",
        "native@0x40AB15",
    ]
    assert payload["boundary_exit_eas"] == [0x40AB17, 0x40B149]
    assert next(
        operation
        for operation in batch.operations
        if operation.operation_id == "route:rhad-direct@0x40AAFB"
    ).depends_on == ("route:rhad-direct@0x40A661",)


def test_checksum_producer_compiles_row43_existing_conditional_reference() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40AB15")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.SLT
    assert normalization.condition_producer_ea == 0x40AB03
    assert normalization.unresolved_transfer_ea == 0x40AB15
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40AB17",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40B149",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 43
    assert payload["reference_symbol"] == "JumpInliner._fixup_jmp_and_possible_jcc"
    assert payload["operation_variant"] == "existing_conditional_plus_indirect"
    assert payload["source_native_ea"] == 0x40AAFD
    assert payload["source_block_anchor_ea"] == 0x40AB0B
    assert payload["join_ea"] == 0x40AB11
    assert payload["observed_predicate_kind"] == PredicateKind.SGE.value
    assert payload["predicate_kind"] == PredicateKind.SLT.value
    assert payload["comparison_constant"] == 0x1EBFFA3C
    assert payload["true_target_ea"] == 0x40AB17
    assert payload["false_target_ea"] == 0x40B149
    assert payload["owned_corridor_instruction_eas"] == [
        0x40AAFD,
        0x40AB03,
        0x40AB09,
        0x40AB0B,
        0x40AB11,
        0x40AB13,
        0x40AB15,
    ]
    assert payload["imported_closure_block_ids"] == [
        "native@0x40AB17",
        "native@0x40AB25",
        "native@0x40AB2B",
        "native@0x40AB2F",
        "native@0x40B149",
        "native@0x40B157",
        "native@0x40B15D",
        "native@0x40B161",
    ]
    assert payload["boundary_exit_eas"] == [0x40A5F0, 0x40AB31]
    assert next(
        operation
        for operation in batch.operations
        if operation.operation_id == "rhad:route@0x40AB15"
    ).depends_on == ("route:rhad-direct@0x40AAFB",)


def test_checksum_producer_compiles_row44_existing_conditional_reference() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40AB2F")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.EQ
    assert normalization.condition_producer_ea == 0x40AB1D
    assert normalization.unresolved_transfer_ea == 0x40AB2F
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40AB31",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40A5F0",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 44
    assert payload["operation_variant"] == "existing_conditional_plus_indirect"
    assert payload["source_native_ea"] == 0x40AB17
    assert payload["source_block_anchor_ea"] == 0x40AB25
    assert payload["join_ea"] == 0x40AB2B
    assert payload["observed_predicate_kind"] == PredicateKind.NE.value
    assert payload["predicate_kind"] == PredicateKind.EQ.value
    assert payload["comparison_constant"] == 0x1BAABD04
    assert payload["true_target_ea"] == 0x40AB31
    assert payload["false_target_ea"] == 0x40A5F0
    assert payload["imported_closure_block_ids"] == [
        "native@0x40AB31",
        "native@0x40AB56",
        "native@0x40AB6A",
        "native@0x40AB74",
        "native@0x40B51B",
        "native@0x40B534",
        "native@0x40B540",
    ]
    assert payload["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
    assert next(
        operation
        for operation in batch.operations
        if operation.operation_id == "rhad:route@0x40AB2F"
    ).depends_on == ("rhad:route@0x40AB15",)


def test_checksum_producer_compiles_row45_direct_dependency() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("route:rhad-direct@0x40AB74")
    assert operation.direct_transfer_rewrite.rewrite_anchor_ea == 0x40AB74
    assert operation.edges[0].target_block_id == "native@0x40B6C0"
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_operation_id"] == "rhad:route@0x40AB74"
    assert payload["reference_order"] == 45
    assert payload["operation_variant"] == "simple_indirect_jump"
    assert payload["source_native_ea"] == 0x40AB56
    assert payload["source_block_anchor_ea"] == 0x40AB6A
    assert payload["transfer_ea"] == 0x40AB74
    assert payload["direct_target_block_id"] == "native@0x40B6C0"
    assert payload["boundary_exit_eas"] == [0x40B790]
    assert next(
        operation
        for operation in batch.operations
        if operation.operation_id == "route:rhad-direct@0x40AB74"
    ).depends_on == ("rhad:route@0x40AB2F",)


def test_checksum_producer_compiles_row46_existing_conditional_reference() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40AB8E")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.SLT
    assert normalization.condition_producer_ea == 0x40AB7C
    assert normalization.unresolved_transfer_ea == 0x40AB8E
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40AB90",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40B17F",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 46
    assert payload["operation_variant"] == "existing_conditional_plus_indirect"
    assert payload["source_native_ea"] == 0x40AB76
    assert payload["source_block_anchor_ea"] == 0x40AB84
    assert payload["join_ea"] == 0x40AB8A
    assert payload["observed_predicate_kind"] == PredicateKind.SGE.value
    assert payload["predicate_kind"] == PredicateKind.SLT.value
    assert payload["comparison_constant"] == 0x456A4274
    assert payload["true_target_ea"] == 0x40AB90
    assert payload["false_target_ea"] == 0x40B17F
    assert payload["owned_corridor_instruction_eas"] == [
        0x40AB76,
        0x40AB7C,
        0x40AB82,
        0x40AB84,
        0x40AB8A,
        0x40AB8C,
        0x40AB8E,
    ]
    assert payload["imported_closure_block_ids"] == [
        "native@0x40AB90",
        "native@0x40AB9E",
        "native@0x40ABA4",
        "native@0x40ABA8",
        "native@0x40B17F",
        "native@0x40B18D",
        "native@0x40B193",
        "native@0x40B197",
    ]
    assert payload["boundary_exit_eas"] == [0x40A5F0, 0x40ABAA, 0x40B199]
    assert next(
        operation
        for operation in batch.operations
        if operation.operation_id == "rhad:route@0x40AB8E"
    ).depends_on == ("rhad:route@0x40A6D8",)

    true_source = next(
        fragment
        for fragment in batch.template_fragments
        if fragment.root_ea == 0x40AB90
    )
    assert true_source.preserved_transfer_exit_map == {
        0x40ABA8: (0x40A5F0, 0x40ABAA),
        0x40ABC4: (0x40A607, 0x40B6C0),
    }
    false_source = next(
        fragment
        for fragment in batch.template_fragments
        if fragment.root_ea == 0x40B17F
    )
    assert false_source.preserved_transfer_exit_map == {
        0x40B197: (0x40A5F0, 0x40B199),
    }


def test_checksum_producer_compiles_row47_existing_conditional_reference() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40ABA8")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.EQ
    assert normalization.condition_producer_ea == 0x40AB96
    assert normalization.unresolved_transfer_ea == 0x40ABA8
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40ABAA",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40A5F0",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 47
    assert payload["operation_variant"] == "existing_conditional_plus_indirect"
    assert payload["source_native_ea"] == 0x40AB90
    assert payload["source_block_anchor_ea"] == 0x40AB9E
    assert payload["join_ea"] == 0x40ABA4
    assert payload["observed_predicate_kind"] == PredicateKind.NE.value
    assert payload["predicate_kind"] == PredicateKind.EQ.value
    assert payload["comparison_constant"] == 0x40D5B460
    assert payload["true_target_ea"] == 0x40ABAA
    assert payload["false_target_ea"] == 0x40A5F0
    assert payload["owned_corridor_instruction_eas"] == [
        0x40AB90,
        0x40AB96,
        0x40AB9C,
        0x40AB9E,
        0x40ABA4,
        0x40ABA6,
        0x40ABA8,
    ]
    assert payload["imported_closure_block_ids"] == [
        "native@0x40ABAA",
        "native@0x40ABBD",
        "native@0x40ABC0",
        "native@0x40ABC4",
    ]
    assert payload["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
    assert next(
        operation
        for operation in batch.operations
        if operation.operation_id == "rhad:route@0x40ABA8"
    ).depends_on == ("rhad:route@0x40AB8E",)

    row47_source = next(
        fragment
        for fragment in batch.template_fragments
        if fragment.root_ea == 0x40AB90
    )
    assert row47_source.owned_ranges == ((0x40AB90, 0x40ABC6),)
    assert row47_source.preserved_transfer_exit_map == {
        0x40ABA8: (0x40A5F0, 0x40ABAA),
        0x40ABC4: (0x40A607, 0x40B6C0),
    }
    imported_by_id = {block.block_id: block for block in batch.imported_blocks}
    assert imported_by_id["native@0x40ABAA"].end_ea == 0x40ABC0
    assert imported_by_id["native@0x40ABAA"].exact_instruction_eas == (
        0x40ABAA,
        0x40ABAF,
        0x40ABB5,
        0x40ABB7,
        0x40ABBD,
    )
    assert imported_by_id["native@0x40ABBD"].end_ea == 0x40ABC0


def test_checksum_producer_compiles_row49_existing_conditional_reference() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40ABDE")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.SLT
    assert normalization.condition_producer_ea == 0x40ABCC
    assert normalization.unresolved_transfer_ea == 0x40ABDE
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40ABE0",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40B1D0",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 49
    assert payload["operation_variant"] == "existing_conditional_plus_indirect"
    assert payload["source_native_ea"] == 0x40ABC6
    assert payload["source_block_anchor_ea"] == 0x40ABD4
    assert payload["join_ea"] == 0x40ABDA
    assert payload["observed_predicate_kind"] == PredicateKind.SGE.value
    assert payload["predicate_kind"] == PredicateKind.SLT.value
    assert payload["comparison_constant"] == 0x22C02855
    assert payload["true_target_ea"] == 0x40ABE0
    assert payload["false_target_ea"] == 0x40B1D0
    assert payload["owned_corridor_instruction_eas"] == [
        0x40ABC6,
        0x40ABCC,
        0x40ABD2,
        0x40ABD4,
        0x40ABDA,
        0x40ABDC,
        0x40ABDE,
    ]
    assert payload["imported_closure_block_ids"] == [
        "native@0x40ABE0",
        "native@0x40ABEE",
        "native@0x40ABF4",
        "native@0x40ABF8",
        "native@0x40B1D0",
        "native@0x40B1DE",
        "native@0x40B1E4",
        "native@0x40B1E8",
    ]
    assert payload["boundary_exit_eas"] == [0x40A5F0, 0x40ABFA, 0x40B1EA]
    assert next(
        operation
        for operation in batch.operations
        if operation.operation_id == "rhad:route@0x40ABDE"
    ).depends_on == ("rhad:route@0x40A77C",)

    source = next(
        fragment
        for fragment in batch.template_fragments
        if fragment.root_ea == 0x40ABC6
    )
    assert source.preserved_transfer_exit_map == {
        0x40ABDE: (0x40ABE0, 0x40B1D0),
    }
    true_source = next(
        fragment
        for fragment in batch.template_fragments
        if fragment.root_ea == 0x40ABE0
    )
    assert true_source.owned_ranges == ((0x40ABE0, 0x40ABFA),)
    assert true_source.preserved_transfer_exit_map == {
        0x40ABF8: (0x40A5F0, 0x40ABFA),
    }
    false_source = next(
        fragment
        for fragment in batch.template_fragments
        if fragment.root_ea == 0x40B1D0
    )
    assert false_source.owned_ranges == ((0x40B1D0, 0x40B1EA),)
    assert false_source.preserved_transfer_exit_map == {
        0x40B1E8: (0x40A5F0, 0x40B1EA),
    }


def test_checksum_producer_compiles_row50_existing_conditional_reference() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40ABF8")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.EQ
    assert normalization.condition_producer_ea == 0x40ABE6
    assert normalization.unresolved_transfer_ea == 0x40ABF8
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40ABFA",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40A5F0",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 50
    assert payload["operation_variant"] == "existing_conditional_plus_indirect"
    assert payload["source_native_ea"] == 0x40ABE0
    assert payload["source_block_anchor_ea"] == 0x40ABEE
    assert payload["join_ea"] == 0x40ABF4
    assert payload["observed_predicate_kind"] == PredicateKind.NE.value
    assert payload["predicate_kind"] == PredicateKind.EQ.value
    assert payload["comparison_constant"] == 0x22642D96
    assert payload["true_target_ea"] == 0x40ABFA
    assert payload["false_target_ea"] == 0x40A5F0
    assert payload["owned_corridor_instruction_eas"] == [
        0x40ABE0,
        0x40ABE6,
        0x40ABEC,
        0x40ABEE,
        0x40ABF4,
        0x40ABF6,
        0x40ABF8,
    ]
    assert payload["imported_closure_block_ids"] == [
        "native@0x40ABFA",
        "native@0x40ABFF",
        "native@0x40AC19",
        "native@0x40AC31",
        "native@0x40AC3B",
        "native@0x40B542",
        "native@0x40B55F",
        "native@0x40B56B",
    ]
    assert payload["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
    assert next(
        operation
        for operation in batch.operations
        if operation.operation_id == "rhad:route@0x40ABF8"
    ).depends_on == ("rhad:route@0x40ABDE",)

    source = next(
        fragment
        for fragment in batch.template_fragments
        if fragment.root_ea == 0x40ABE0
    )
    assert source.preserved_transfer_exit_map == {
        0x40ABF8: (0x40A5F0, 0x40ABFA),
    }
    true_source = next(
        fragment
        for fragment in batch.template_fragments
        if fragment.root_ea == 0x40ABFA
    )
    assert true_source.owned_ranges == (
        (0x40ABFA, 0x40AC3D),
        (0x40B542, 0x40B56D),
    )
    assert true_source.preserved_transfer_exit_map == {
        0x40AC3B: (0x40B6C0,),
        0x40B56B: (0x40A607,),
    }


def test_checksum_producer_compiles_row51_direct_dependency() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("route:rhad-direct@0x40AC3B")
    assert operation.direct_transfer_rewrite.rewrite_anchor_ea == 0x40AC3B
    assert operation.direct_transfer_rewrite.owner_anchor_ea == 0x40AC31
    assert operation.edges[0].target_block_id == "native@0x40B6C0"
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_operation_id"] == "rhad:route@0x40AC3B"
    assert payload["reference_order"] == 51
    assert payload["operation_variant"] == "simple_indirect_jump"
    assert payload["source_native_ea"] == 0x40AC19
    assert payload["source_block_anchor_ea"] == 0x40AC31
    assert payload["transfer_ea"] == 0x40AC3B
    assert payload["direct_target_block_id"] == "native@0x40B6C0"
    assert payload["boundary_exit_eas"] == [0x40B790]
    assert next(
        operation
        for operation in batch.operations
        if operation.operation_id == "route:rhad-direct@0x40AC3B"
    ).depends_on == ("rhad:route@0x40ABF8",)


def test_checksum_producer_compiles_row52_existing_conditional_reference() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40AC54")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.SLT
    assert normalization.condition_producer_ea == 0x40AC42
    assert normalization.unresolved_transfer_ea == 0x40AC54
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40AC56",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40B21C",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 52
    assert payload["operation_variant"] == "existing_conditional_plus_indirect"
    assert payload["source_native_ea"] == 0x40AC3D
    assert payload["source_block_anchor_ea"] == 0x40AC4A
    assert payload["join_ea"] == 0x40AC50
    assert payload["observed_predicate_kind"] == PredicateKind.SGE.value
    assert payload["predicate_kind"] == PredicateKind.SLT.value
    assert payload["comparison_constant"] == 0x7278AB7F
    assert payload["true_target_ea"] == 0x40AC56
    assert payload["false_target_ea"] == 0x40B21C
    assert payload["owned_corridor_instruction_eas"] == [
        0x40AC3D,
        0x40AC42,
        0x40AC48,
        0x40AC4A,
        0x40AC50,
        0x40AC52,
        0x40AC54,
    ]
    assert payload["imported_closure_block_ids"] == [
        "native@0x40AC56",
        "native@0x40AC64",
        "native@0x40AC6A",
        "native@0x40AC6E",
        "native@0x40B21C",
        "native@0x40B22A",
        "native@0x40B230",
        "native@0x40B234",
    ]
    assert payload["boundary_exit_eas"] == [0x40A5F0, 0x40AC70]
    assert next(
        operation
        for operation in batch.operations
        if operation.operation_id == "rhad:route@0x40AC54"
    ).depends_on == ("rhad:route@0x40A832",)

    source = next(
        fragment
        for fragment in batch.template_fragments
        if fragment.root_ea == 0x40AC3D
    )
    assert source.preserved_transfer_exit_map == {
        0x40AC54: (0x40AC56, 0x40B21C),
    }
    true_source = next(
        fragment
        for fragment in batch.template_fragments
        if fragment.root_ea == 0x40AC56
    )
    assert true_source.preserved_transfer_exit_map == {
        0x40AC6E: (0x40A5F0, 0x40AC70),
    }
    false_source = next(
        fragment
        for fragment in batch.template_fragments
        if fragment.root_ea == 0x40B21C
    )
    assert false_source.preserved_transfer_exit_map == {
        0x40B234: (0x40A5F0,),
    }


def test_checksum_producer_compiles_row53_existing_conditional_reference() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40AC6E")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.EQ
    assert normalization.condition_producer_ea == 0x40AC5C
    assert normalization.unresolved_transfer_ea == 0x40AC6E
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40AC70",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40A5F0",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 53
    assert payload["operation_variant"] == "existing_conditional_plus_indirect"
    assert payload["source_native_ea"] == 0x40AC56
    assert payload["source_block_anchor_ea"] == 0x40AC64
    assert payload["join_ea"] == 0x40AC6A
    assert payload["observed_predicate_kind"] == PredicateKind.NE.value
    assert payload["predicate_kind"] == PredicateKind.EQ.value
    assert payload["comparison_constant"] == 0x6D56E4D2
    assert payload["true_target_ea"] == 0x40AC70
    assert payload["false_target_ea"] == 0x40A5F0
    assert payload["owned_corridor_instruction_eas"] == [
        0x40AC56,
        0x40AC5C,
        0x40AC62,
        0x40AC64,
        0x40AC6A,
        0x40AC6C,
        0x40AC6E,
    ]
    assert payload["imported_closure_block_ids"] == [
        "native@0x40AC70",
        "native@0x40AC81",
        "native@0x40AC9B",
        "native@0x40ACB3",
        "native@0x40ACBD",
        "native@0x40B56D",
        "native@0x40B58A",
        "native@0x40B596",
    ]
    assert payload["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
    assert next(
        operation
        for operation in batch.operations
        if operation.operation_id == "rhad:route@0x40AC6E"
    ).depends_on == ("rhad:route@0x40AC54",)

    source = next(
        fragment
        for fragment in batch.template_fragments
        if fragment.root_ea == 0x40AC56
    )
    assert source.preserved_transfer_exit_map == {
        0x40AC6E: (0x40A5F0, 0x40AC70),
    }
    true_source = next(
        fragment
        for fragment in batch.template_fragments
        if fragment.root_ea == 0x40AC70
    )
    assert true_source.preserved_transfer_exit_map == {
        0x40ACBD: (0x40B6C0,),
        0x40B596: (0x40A607,),
    }


def test_checksum_producer_compiles_row54_direct_dependency() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("route:rhad-direct@0x40ACBD")
    assert operation.direct_transfer_rewrite.rewrite_anchor_ea == 0x40ACBD
    assert operation.direct_transfer_rewrite.owner_anchor_ea == 0x40ACB3
    assert operation.edges[0].target_block_id == "native@0x40B6C0"
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_operation_id"] == "rhad:route@0x40ACBD"
    assert payload["reference_order"] == 54
    assert payload["operation_variant"] == "simple_indirect_jump"
    assert payload["source_native_ea"] == 0x40AC9B
    assert payload["source_block_anchor_ea"] == 0x40ACB3
    assert payload["transfer_ea"] == 0x40ACBD
    assert payload["direct_target_block_id"] == "native@0x40B6C0"
    assert payload["owned_corridor_instruction_eas"] == [
        0x40AC9B,
        0x40ACB3,
        0x40ACB5,
        0x40ACB7,
        0x40ACBD,
    ]
    assert payload["boundary_exit_eas"] == [0x40B790]
    assert next(
        operation
        for operation in batch.operations
        if operation.operation_id == "route:rhad-direct@0x40ACBD"
    ).depends_on == ("rhad:route@0x40AC6E",)


def test_checksum_producer_compiles_row55_existing_conditional_dependency() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40ACD7")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.SGE
    assert normalization.condition_producer_ea == 0x40ACC5
    assert normalization.unresolved_transfer_ea == 0x40ACD7
    assert isinstance(
        normalization.conditional_select_envelope,
        FragmentReferencedImportedConditionalSelectEnvelope,
    )
    envelope = normalization.conditional_select_envelope
    assert envelope.selected_value_block_id == "native@0x40ACCD"
    assert envelope.join_block_id == "native@0x40ACD3"
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40ACD9",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40B26D",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 55
    assert payload["operation_variant"] == "existing_conditional_plus_indirect"
    assert payload["source_native_ea"] == 0x40ACBF
    assert payload["source_block_anchor_ea"] == 0x40ACD3
    assert payload["join_ea"] == 0x40ACD3
    assert payload["observed_predicate_kind"] == PredicateKind.SLT.value
    assert payload["predicate_kind"] == PredicateKind.SGE.value
    assert payload["comparison_constant"] == 0x13921E0E
    assert payload["true_target_ea"] == 0x40ACD9
    assert payload["false_target_ea"] == 0x40B26D
    assert payload["owned_corridor_instruction_eas"] == [
        0x40ACBF,
        0x40ACC5,
        0x40ACCB,
        0x40ACCD,
        0x40ACD3,
        0x40ACD5,
        0x40ACD7,
    ]
    assert payload["imported_closure_block_ids"] == [
        "native@0x40ACD9",
        "native@0x40ACE7",
        "native@0x40ACED",
        "native@0x40ACF1",
        "native@0x40B26D",
        "native@0x40B27B",
        "native@0x40B281",
        "native@0x40B285",
    ]
    assert payload["boundary_exit_eas"] == [0x40A5F0, 0x40ACF3]
    assert next(
        operation
        for operation in batch.operations
        if operation.operation_id == "rhad:route@0x40ACD7"
    ).depends_on == ("route:rhad-direct@0x40ACBD",)


def test_checksum_producer_compiles_row56_existing_conditional_dependency() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40ACF1")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.EQ
    assert normalization.condition_producer_ea == 0x40ACDF
    assert normalization.unresolved_transfer_ea == 0x40ACF1
    assert isinstance(
        normalization.conditional_select_envelope,
        FragmentReferencedImportedConditionalSelectEnvelope,
    )
    envelope = normalization.conditional_select_envelope
    assert envelope.selected_value_block_id == "native@0x40ACE7"
    assert envelope.join_block_id == "native@0x40ACED"
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40ACF3",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40A5F0",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 56
    assert payload["observed_predicate_kind"] == PredicateKind.NE.value
    assert payload["predicate_kind"] == PredicateKind.EQ.value
    assert payload["comparison_constant"] == 0x0E9795EF
    assert payload["owned_corridor_instruction_eas"] == [
        0x40ACD9,
        0x40ACDF,
        0x40ACE5,
        0x40ACE7,
        0x40ACED,
        0x40ACEF,
        0x40ACF1,
    ]
    assert payload["imported_closure_block_ids"] == [
        "native@0x40ACF3",
        "native@0x40AD06",
        "native@0x40AD18",
        "native@0x40AD1C",
        "native@0x40B598",
        "native@0x40B5AF",
        "native@0x40B5B5",
    ]
    assert payload["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
    assert next(
        operation
        for operation in batch.operations
        if operation.operation_id == "rhad:route@0x40ACF1"
    ).depends_on == ("rhad:route@0x40ACD7",)


def test_checksum_producer_compiles_row57_direct_dependency() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("route:rhad-direct@0x40AD1C")
    assert operation.direct_transfer_rewrite.rewrite_anchor_ea == 0x40AD1C
    assert operation.direct_transfer_rewrite.owner_anchor_ea == 0x40AD18
    assert operation.edges[0].target_block_id == "native@0x40B6C0"
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_operation_id"] == "rhad:route@0x40AD1C"
    assert payload["reference_order"] == 57
    assert payload["operation_variant"] == "simple_indirect_jump"
    assert payload["source_native_ea"] == 0x40AD06
    assert payload["source_block_anchor_ea"] == 0x40AD18
    assert payload["transfer_ea"] == 0x40AD1C
    assert payload["direct_target_block_id"] == "native@0x40B6C0"
    assert payload["owned_corridor_instruction_eas"] == [
        0x40AD06,
        0x40AD18,
        0x40AD1A,
        0x40AD1C,
    ]
    assert payload["boundary_exit_eas"] == [0x40B790]
    assert next(
        operation
        for operation in batch.operations
        if operation.operation_id == "route:rhad-direct@0x40AD1C"
    ).depends_on == ("rhad:route@0x40ACF1",)


def test_checksum_producer_compiles_row58_existing_conditional_dependency() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40AD36")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.SGE
    assert normalization.condition_producer_ea == 0x40AD24
    assert normalization.unresolved_transfer_ea == 0x40AD36
    assert isinstance(
        normalization.conditional_select_envelope,
        FragmentReferencedImportedConditionalSelectEnvelope,
    )
    envelope = normalization.conditional_select_envelope
    assert envelope.selected_value_block_id == "native@0x40AD2C"
    assert envelope.join_block_id == "native@0x40AD32"
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40AD38",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40B2DB",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 58
    assert payload["operation_variant"] == "existing_conditional_plus_indirect"
    assert payload["source_native_ea"] == 0x40AD1E
    assert payload["source_block_anchor_ea"] == 0x40AD32
    assert payload["join_ea"] == 0x40AD32
    assert payload["observed_predicate_kind"] == PredicateKind.SLT.value
    assert payload["predicate_kind"] == PredicateKind.SGE.value
    assert payload["comparison_constant"] == 0x6487820D
    assert payload["true_target_ea"] == 0x40AD38
    assert payload["false_target_ea"] == 0x40B2DB
    assert payload["owned_corridor_instruction_eas"] == [
        0x40AD1E,
        0x40AD24,
        0x40AD2A,
        0x40AD2C,
        0x40AD32,
        0x40AD34,
        0x40AD36,
    ]
    assert payload["imported_closure_block_ids"] == [
        "native@0x40AD38",
        "native@0x40AD46",
        "native@0x40AD4C",
        "native@0x40AD50",
        "native@0x40B2DB",
        "native@0x40B2E9",
        "native@0x40B2EF",
        "native@0x40B2F3",
    ]
    assert payload["boundary_exit_eas"] == [0x40A5F0, 0x40AD52]
    assert next(
        operation
        for operation in batch.operations
        if operation.operation_id == "rhad:route@0x40AD36"
    ).depends_on == ("route:rhad-direct@0x40AD1C",)


def test_checksum_producer_compiles_row59_existing_conditional_dependency() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40AD50")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.NE
    assert normalization.condition_producer_ea == 0x40AD3E
    assert normalization.unresolved_transfer_ea == 0x40AD50
    assert isinstance(
        normalization.conditional_select_envelope,
        FragmentReferencedImportedConditionalSelectEnvelope,
    )
    envelope = normalization.conditional_select_envelope
    assert envelope.selected_value_block_id == "native@0x40AD46"
    assert envelope.join_block_id == "native@0x40AD4C"
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40AD52",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40A5F0",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 59
    assert payload["operation_variant"] == "existing_conditional_plus_indirect"
    assert payload["source_native_ea"] == 0x40AD38
    assert payload["source_block_anchor_ea"] == 0x40AD4C
    assert payload["join_ea"] == 0x40AD4C
    assert payload["observed_predicate_kind"] == PredicateKind.EQ.value
    assert payload["predicate_kind"] == PredicateKind.NE.value
    assert payload["comparison_constant"] == 0x636961E8
    assert payload["true_target_ea"] == 0x40AD52
    assert payload["false_target_ea"] == 0x40A5F0
    assert payload["owned_corridor_instruction_eas"] == [
        0x40AD38,
        0x40AD3E,
        0x40AD44,
        0x40AD46,
        0x40AD4C,
        0x40AD4E,
        0x40AD50,
    ]
    assert payload["imported_closure_block_ids"] == [
        "native@0x40AD52",
        "native@0x40AD65",
        "native@0x40AD68",
        "native@0x40AD6C",
    ]
    assert payload["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
    assert next(
        operation
        for operation in batch.operations
        if operation.operation_id == "rhad:route@0x40AD50"
    ).depends_on == ("rhad:route@0x40AD36",)


def test_checksum_producer_compiles_row60_cmov_selected_dependency() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40AD6C")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.SLT
    assert normalization.condition_producer_ea == 0x40AD57
    assert normalization.unresolved_transfer_ea == 0x40AD6C
    assert isinstance(
        normalization.conditional_select_envelope,
        FragmentReferencedImportedConditionalSelectEnvelope,
    )
    envelope = normalization.conditional_select_envelope
    assert envelope.selected_value_block_id == "native@0x40AD65"
    assert envelope.join_block_id == "native@0x40AD68"
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40B6C0",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40A607",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 60
    assert payload["reference_symbol"] == "JumpInliner._fixup_cmov"
    assert payload["operation_variant"] == "cmov_selected_indirect"
    assert payload["source_native_ea"] == 0x40AD5D
    assert payload["source_block_anchor_ea"] == 0x40AD52
    assert payload["observed_predicate_kind"] == PredicateKind.SGE.value
    assert payload["predicate_kind"] == PredicateKind.SLT.value
    assert payload["comparison_constant"] == 0x0BB2D365
    assert payload["true_target_ea"] == 0x40B6C0
    assert payload["false_target_ea"] == 0x40A607
    assert payload["owned_corridor_instruction_eas"] == [
        0x40AD5D,
        0x40AD5F,
        0x40AD65,
        0x40AD68,
        0x40AD6A,
        0x40AD6C,
    ]
    assert payload["imported_closure_block_ids"] == list(
        generated_reference.ACCEPTED_IMPORTED_BLOCK_IDS
    )
    assert payload["boundary_exit_eas"] == [0x40A61B, 0x40A68C, 0x40B790]
    assert next(
        operation
        for operation in batch.operations
        if operation.operation_id == "rhad:route@0x40AD6C"
    ).depends_on == ("rhad:route@0x40AD50",)


def test_checksum_producer_compiles_row61_existing_conditional_dependency() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40AD86")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.SGE
    assert normalization.condition_producer_ea == 0x40AD74
    assert normalization.unresolved_transfer_ea == 0x40AD86
    assert isinstance(
        normalization.conditional_select_envelope,
        FragmentReferencedImportedConditionalSelectEnvelope,
    )
    envelope = normalization.conditional_select_envelope
    assert envelope.selected_value_block_id == "native@0x40AD7C"
    assert envelope.join_block_id == "native@0x40AD82"
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40AD88",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40B32C",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 61
    assert payload["reference_symbol"] == "JumpInliner._fixup_jmp_and_possible_jcc"
    assert payload["operation_variant"] == "existing_conditional_plus_indirect"
    assert payload["source_native_ea"] == 0x40AD6E
    assert payload["source_block_anchor_ea"] == 0x40AD82
    assert payload["join_ea"] == 0x40AD82
    assert payload["observed_predicate_kind"] == PredicateKind.SLT.value
    assert payload["predicate_kind"] == PredicateKind.SGE.value
    assert payload["comparison_constant"] == 0x304E8694
    assert payload["true_target_ea"] == 0x40AD88
    assert payload["false_target_ea"] == 0x40B32C
    assert payload["owned_corridor_instruction_eas"] == [
        0x40AD6E,
        0x40AD74,
        0x40AD7A,
        0x40AD7C,
        0x40AD82,
        0x40AD84,
        0x40AD86,
    ]
    assert payload["imported_closure_block_ids"] == [
        "native@0x40AD88",
        "native@0x40AD96",
        "native@0x40AD9C",
        "native@0x40ADA0",
        "native@0x40B32C",
        "native@0x40B340",
    ]
    assert payload["boundary_exit_eas"] == [0x40A5F0, 0x40ADA2, 0x40B342]
    assert {
        "native@0x40AD88",
        "native@0x40B32C",
    }.issubset(batch.native_body_entry_block_ids)
    assert next(
        operation
        for operation in batch.operations
        if operation.operation_id == "rhad:route@0x40AD86"
    ).depends_on == ("rhad:route@0x40AD6C",)


def test_checksum_producer_compiles_row62_existing_conditional_dependency() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40ADA0")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.NE
    assert normalization.condition_producer_ea == 0x40AD8E
    assert normalization.unresolved_transfer_ea == 0x40ADA0
    assert isinstance(
        normalization.conditional_select_envelope,
        FragmentReferencedImportedConditionalSelectEnvelope,
    )
    envelope = normalization.conditional_select_envelope
    assert envelope.selected_value_block_id == "native@0x40AD96"
    assert envelope.join_block_id == "native@0x40AD9C"
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40ADA2",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40A5F0",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 62
    assert payload["reference_symbol"] == "JumpInliner._fixup_jmp_and_possible_jcc"
    assert payload["operation_variant"] == "existing_conditional_plus_indirect"
    assert payload["source_native_ea"] == 0x40AD88
    assert payload["source_block_anchor_ea"] == 0x40AD9C
    assert payload["join_ea"] == 0x40AD9C
    assert payload["observed_predicate_kind"] == PredicateKind.EQ.value
    assert payload["predicate_kind"] == PredicateKind.NE.value
    assert payload["comparison_constant"] == 0x2B8162DC
    assert payload["true_target_ea"] == 0x40ADA2
    assert payload["false_target_ea"] == 0x40A5F0
    assert payload["owned_corridor_instruction_eas"] == [
        0x40AD88,
        0x40AD8E,
        0x40AD94,
        0x40AD96,
        0x40AD9C,
        0x40AD9E,
        0x40ADA0,
    ]
    assert payload["imported_closure_block_ids"] == [
        "native@0x40ADA2",
        "native@0x40ADB5",
        "native@0x40ADB8",
        "native@0x40ADBC",
    ]
    assert payload["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
    assert next(
        operation
        for operation in batch.operations
        if operation.operation_id == "rhad:route@0x40ADA0"
    ).depends_on == ("rhad:route@0x40AD86",)


def test_checksum_producer_compiles_row63_cmov_selected_dependency() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40ADBC")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.SLT
    assert normalization.condition_producer_ea == 0x40ADA7
    assert normalization.unresolved_transfer_ea == 0x40ADBC
    assert isinstance(
        normalization.conditional_select_envelope,
        FragmentReferencedImportedConditionalSelectEnvelope,
    )
    envelope = normalization.conditional_select_envelope
    assert envelope.selected_value_block_id == "native@0x40ADB5"
    assert envelope.join_block_id == "native@0x40ADB8"
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40B6C0",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40A607",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 63
    assert payload["reference_symbol"] == "JumpInliner._fixup_cmov"
    assert payload["operation_variant"] == "cmov_selected_indirect"
    assert payload["source_native_ea"] == 0x40ADAD
    assert payload["source_block_anchor_ea"] == 0x40ADA2
    assert payload["observed_predicate_kind"] == PredicateKind.SGE.value
    assert payload["predicate_kind"] == PredicateKind.SLT.value
    assert payload["comparison_constant"] == 0x0BB2D365
    assert payload["true_target_ea"] == 0x40B6C0
    assert payload["false_target_ea"] == 0x40A607
    assert payload["owned_corridor_instruction_eas"] == [
        0x40ADAD,
        0x40ADAF,
        0x40ADB5,
        0x40ADB8,
        0x40ADBA,
        0x40ADBC,
    ]
    assert payload["imported_closure_block_ids"] == list(
        generated_reference.ACCEPTED_IMPORTED_BLOCK_IDS
    )
    assert payload["boundary_exit_eas"] == [0x40A61B, 0x40A68C, 0x40B790]
    assert next(
        operation
        for operation in batch.operations
        if operation.operation_id == "rhad:route@0x40ADBC"
    ).depends_on == ("rhad:route@0x40ADA0",)


def test_checksum_producer_compiles_row64_existing_conditional_dependency() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40ADD6")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.SGE
    assert normalization.condition_producer_ea == 0x40ADC4
    assert normalization.unresolved_transfer_ea == 0x40ADD6
    assert isinstance(
        normalization.conditional_select_envelope,
        FragmentReferencedImportedConditionalSelectEnvelope,
    )
    envelope = normalization.conditional_select_envelope
    assert envelope.selected_value_block_id == "native@0x40ADCC"
    assert envelope.join_block_id == "native@0x40ADD2"
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40ADD8",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40B37C",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 64
    assert payload["reference_symbol"] == "JumpInliner._fixup_jmp_and_possible_jcc"
    assert payload["operation_variant"] == "existing_conditional_plus_indirect"
    assert payload["source_native_ea"] == 0x40ADBE
    assert payload["source_block_anchor_ea"] == 0x40ADD2
    assert payload["join_ea"] == 0x40ADD2
    assert payload["observed_predicate_kind"] == PredicateKind.SLT.value
    assert payload["predicate_kind"] == PredicateKind.SGE.value
    assert payload["comparison_constant"] == 0x7E46FA09
    assert payload["true_target_ea"] == 0x40ADD8
    assert payload["false_target_ea"] == 0x40B37C
    assert payload["owned_corridor_instruction_eas"] == [
        0x40ADBE,
        0x40ADC4,
        0x40ADCA,
        0x40ADCC,
        0x40ADD2,
        0x40ADD4,
        0x40ADD6,
    ]
    assert payload["imported_closure_block_ids"] == [
        "native@0x40ADD8",
        "native@0x40ADE6",
        "native@0x40ADEC",
        "native@0x40ADF0",
        "native@0x40B37C",
        "native@0x40B38A",
        "native@0x40B390",
        "native@0x40B394",
    ]
    assert payload["boundary_exit_eas"] == [
        0x40A5F0,
        0x40ADF2,
        0x40B396,
        0x40B3E5,
    ]
    assert {
        "native@0x40ADD8",
        "native@0x40B37C",
    }.issubset(batch.native_body_entry_block_ids)
    assert next(
        operation
        for operation in batch.operations
        if operation.operation_id == "rhad:route@0x40ADD6"
    ).depends_on == ("rhad:route@0x40ADBC",)


def test_checksum_producer_compiles_row65_existing_conditional_dependency() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40ADF0")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.NE
    assert normalization.condition_producer_ea == 0x40ADDE
    assert normalization.unresolved_transfer_ea == 0x40ADF0
    assert isinstance(
        normalization.conditional_select_envelope,
        FragmentReferencedImportedConditionalSelectEnvelope,
    )
    envelope = normalization.conditional_select_envelope
    assert envelope.selected_value_block_id == "native@0x40ADE6"
    assert envelope.join_block_id == "native@0x40ADEC"
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40ADF2",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40A5F0",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 65
    assert payload["reference_symbol"] == "JumpInliner._fixup_jmp_and_possible_jcc"
    assert payload["operation_variant"] == "existing_conditional_plus_indirect"
    assert payload["source_native_ea"] == 0x40ADD8
    assert payload["source_block_anchor_ea"] == 0x40ADEC
    assert payload["join_ea"] == 0x40ADEC
    assert payload["observed_predicate_kind"] == PredicateKind.EQ.value
    assert payload["predicate_kind"] == PredicateKind.NE.value
    assert payload["comparison_constant"] == 0x7C4FB03D
    assert payload["true_target_ea"] == 0x40ADF2
    assert payload["false_target_ea"] == 0x40A5F0
    assert payload["owned_corridor_instruction_eas"] == [
        0x40ADD8,
        0x40ADDE,
        0x40ADE4,
        0x40ADE6,
        0x40ADEC,
        0x40ADEE,
        0x40ADF0,
    ]
    assert payload["imported_closure_block_ids"] == [
        "native@0x40ADF2",
        "native@0x40AE05",
        "native@0x40AE08",
        "native@0x40AE18",
    ]
    assert payload["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
    assert "native@0x40ADF2" in batch.native_body_entry_block_ids
    assert next(
        operation
        for operation in batch.operations
        if operation.operation_id == "rhad:route@0x40ADF0"
    ).depends_on == ("rhad:route@0x40ADD6",)


def test_checksum_producer_compiles_row66_cmov_selected_dependency() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40AE18")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.SLT
    assert normalization.condition_producer_ea == 0x40ADF7
    assert normalization.unresolved_transfer_ea == 0x40AE18
    assert isinstance(
        normalization.conditional_select_envelope,
        FragmentReferencedImportedConditionalSelectEnvelope,
    )
    envelope = normalization.conditional_select_envelope
    assert envelope.selected_value_block_id == "native@0x40AE05"
    assert envelope.join_block_id == "native@0x40AE08"
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40B6C0",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40A607",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 66
    assert payload["reference_symbol"] == "JumpInliner._fixup_cmov"
    assert payload["operation_variant"] == "cmov_selected_indirect"
    assert payload["source_native_ea"] == 0x40ADFD
    assert payload["source_block_anchor_ea"] == 0x40ADF2
    assert payload["observed_predicate_kind"] == PredicateKind.SGE.value
    assert payload["predicate_kind"] == PredicateKind.SLT.value
    assert payload["comparison_constant"] == 0x0BB2D365
    assert payload["true_target_ea"] == 0x40B6C0
    assert payload["false_target_ea"] == 0x40A607
    assert payload["owned_corridor_instruction_eas"] == [
        0x40ADFD,
        0x40ADFF,
        0x40AE05,
        0x40AE08,
        0x40AE0A,
        0x40AE18,
    ]
    assert payload["imported_closure_block_ids"] == list(
        generated_reference.ACCEPTED_IMPORTED_BLOCK_IDS
    )
    assert payload["boundary_exit_eas"] == [0x40A61B, 0x40A68C, 0x40B790]
    assert next(
        operation
        for operation in batch.operations
        if operation.operation_id == "rhad:route@0x40AE18"
    ).depends_on == ("rhad:route@0x40ADF0",)


def test_checksum_producer_compiles_row67_simple_indirect_dependency() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("route:rhad-direct@0x40AE24")
    rewrite = operation.direct_transfer_rewrite
    assert rewrite is not None
    assert operation.source_block_id == "native@0x40AE1A"
    assert rewrite.owner_anchor_ea == 0x40AE1A
    assert rewrite.rewrite_anchor_ea == 0x40AE24
    assert rewrite.proof_corridor_instruction_eas == (
        0x40A66F,
        0x40AE1A,
        0x40AE20,
        0x40AE22,
        0x40AE24,
    )
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.DIRECT: "native@0x40A5CA",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_operation_id"] == "rhad:route@0x40AE24"
    assert payload["reference_order"] == 67
    assert payload["reference_symbol"] == ("JumpInliner._fixup_jmp_and_possible_jcc")
    assert payload["operation_variant"] == "simple_indirect_jump"
    assert payload["source_native_ea"] == 0x40A66F
    assert payload["source_block_anchor_ea"] == 0x40AE1A
    assert payload["transfer_ea"] == 0x40AE24
    assert payload["direct_target_block_id"] == "native@0x40A5CA"
    assert payload["owned_corridor_instruction_eas"] == [
        0x40A66F,
        0x40AE1A,
        0x40AE20,
        0x40AE22,
        0x40AE24,
    ]
    assert payload["imported_closure_block_ids"] == [
        "native@0x40A5CA",
        "native@0x40A5DC",
        "native@0x40A5DF",
        "native@0x40A5E3",
    ]
    assert payload["boundary_exit_eas"] == [0x40A5F0, 0x40C898]
    assert next(
        operation
        for operation in batch.operations
        if operation.operation_id == "route:rhad-direct@0x40AE24"
    ).depends_on == ("rhad:route@0x40AE18",)


def test_checksum_producer_compiles_row68_setcc_table_dependency() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40AE3C")
    normalization = operation.computed_branch_normalization
    assert isinstance(normalization, FragmentSetccIndexedTableNormalization)
    assert normalization.predicate_kind is PredicateKind.EQ
    assert (
        normalization.fallthrough_delivery
        is FragmentSetccFallthroughDelivery.PLANNED_HELPER
    )
    assert operation.requires_fallthrough_helper is True
    assert normalization.condition_producer_ea == 0x40AE28
    assert normalization.unresolved_transfer_ea == 0x40AE3C
    evidence = normalization.table_evidence
    assert evidence.table_base_ea == 0x48B650
    assert evidence.index_scaling.kind.value == "explicit_shift"
    assert evidence.index_scaling.shift_ea == 0x40AE31
    assert evidence.index_scaling.shift_bits == 6
    assert evidence.stride_bytes == 64
    assert evidence.true_entry.decoded_target_ea == 0x40AE3E
    assert evidence.false_entry.decoded_target_ea == 0x40A5F0
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40AE3E",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40A5F0",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 68
    assert payload["reference_symbol"] == "JumpInliner._fixup_index_access"
    assert payload["operation_variant"] == "setcc_indexed_table"
    assert payload["source_native_ea"] == 0x40AE26
    assert payload["condition_producer_ea"] == 0x40AE28
    assert payload["predicate_anchor_ea"] == 0x40AE2E
    assert payload["fallthrough_delivery"] == "planned_helper"
    assert payload["transfer_ea"] == 0x40AE3C
    assert payload["owned_corridor_instruction_eas"] == [
        0x40AE26,
        0x40AE28,
        0x40AE2E,
        0x40AE31,
        0x40AE34,
        0x40AE3A,
        0x40AE3C,
    ]
    assert payload["imported_closure_block_ids"] == [
        "native@0x40AE3E",
        "native@0x40AE63",
        "native@0x40AE82",
        "native@0x40AE85",
        "native@0x40AE89",
    ]
    assert payload["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
    assert payload["proof_artifact"]["proof"]["binding"] == {
        "function_ea": 0x40A560,
        "input_sha256": generated_reference.INPUT_SHA256,
        "operation_id": "rhad:route@0x40AE3C",
        "reference_commit": "21b0d4783703bc4fb6910cfae51d92cd683d2c65",
        "reference_order": 68,
    }
    assert payload["proof_artifact"]["content_identity"] == (
        "sha256:9eb674af190cee8d9b391605feb930a59bcf708c9fbb519f2d8bd26cac27fdd0"
    )
    assert next(
        operation
        for operation in batch.operations
        if operation.operation_id == "rhad:route@0x40AE3C"
    ).depends_on == ("route:rhad-direct@0x40AE24",)


def test_checksum_producer_compiles_row69_cmov_selected_dependency() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40AE89")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.SLT
    assert normalization.condition_producer_ea == 0x40AE74
    assert normalization.unresolved_transfer_ea == 0x40AE89
    assert isinstance(
        normalization.conditional_select_envelope,
        FragmentReferencedImportedConditionalSelectEnvelope,
    )
    envelope = normalization.conditional_select_envelope
    assert envelope.selected_value_block_id == "native@0x40AE82"
    assert envelope.join_block_id == "native@0x40AE85"
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40B6C0",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40A607",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 69
    assert payload["reference_symbol"] == "JumpInliner._fixup_cmov"
    assert payload["operation_variant"] == "cmov_selected_indirect"
    assert payload["source_native_ea"] == 0x40AE69
    assert payload["source_block_anchor_ea"] == 0x40AE63
    assert payload["observed_predicate_kind"] == PredicateKind.SGE.value
    assert payload["predicate_kind"] == PredicateKind.SLT.value
    assert payload["comparison_constant"] == 0x0BB2D365
    assert payload["true_target_ea"] == 0x40B6C0
    assert payload["false_target_ea"] == 0x40A607
    assert payload["owned_corridor_instruction_eas"] == [
        0x40AE69,
        0x40AE7A,
        0x40AE7C,
        0x40AE82,
        0x40AE85,
        0x40AE87,
        0x40AE89,
    ]
    assert payload["imported_closure_block_ids"] == list(
        generated_reference.ACCEPTED_IMPORTED_BLOCK_IDS
    )
    assert payload["boundary_exit_eas"] == [0x40A61B, 0x40A68C, 0x40B790]
    assert next(
        operation
        for operation in batch.operations
        if operation.operation_id == "rhad:route@0x40AE89"
    ).depends_on == ("rhad:route@0x40AE3C",)


def test_checksum_producer_compiles_row70_existing_conditional_dependency() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40AEA3")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.NE
    assert normalization.condition_producer_ea == 0x40AE91
    assert normalization.unresolved_transfer_ea == 0x40AEA3
    assert isinstance(
        normalization.conditional_select_envelope,
        FragmentReferencedImportedConditionalSelectEnvelope,
    )
    envelope = normalization.conditional_select_envelope
    assert envelope.selected_value_block_id == "native@0x40AE99"
    assert envelope.join_block_id == "native@0x40AE9F"
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40AEA5",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40A5F0",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 70
    assert payload["reference_symbol"] == "JumpInliner._fixup_jmp_and_possible_jcc"
    assert payload["operation_variant"] == "existing_conditional_plus_indirect"
    assert payload["source_native_ea"] == 0x40AE8B
    assert payload["source_block_anchor_ea"] == 0x40AE9F
    assert payload["join_ea"] == 0x40AE9F
    assert payload["observed_predicate_kind"] == PredicateKind.EQ.value
    assert payload["predicate_kind"] == PredicateKind.NE.value
    assert payload["comparison_constant"] == 0x40ABF871
    assert payload["true_target_ea"] == 0x40AEA5
    assert payload["false_target_ea"] == 0x40A5F0
    assert payload["owned_corridor_instruction_eas"] == [
        0x40AE8B,
        0x40AE91,
        0x40AE97,
        0x40AE99,
        0x40AE9F,
        0x40AEA1,
        0x40AEA3,
    ]
    assert payload["imported_closure_block_ids"] == [
        "native@0x40AEA5",
        "native@0x40AEC6",
        "native@0x40AEDA",
        "native@0x40AEE4",
        "native@0x40B5B7",
        "native@0x40B5D0",
        "native@0x40B5DC",
    ]
    assert payload["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
    assert next(
        operation
        for operation in batch.operations
        if operation.operation_id == "rhad:route@0x40AEA3"
    ).depends_on == ("rhad:route@0x40AE89",)


def test_checksum_producer_compiles_row71_simple_indirect_dependency() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("route:rhad-direct@0x40AEE4")
    rewrite = operation.direct_transfer_rewrite
    assert rewrite is not None
    assert operation.source_block_id == "native@0x40AEDA"
    assert rewrite.owner_anchor_ea == 0x40AEDA
    assert rewrite.rewrite_anchor_ea == 0x40AEE4
    assert rewrite.proof_corridor_instruction_eas == (
        0x40AEC6,
        0x40AEDA,
        0x40AEDC,
        0x40AEDE,
        0x40AEE4,
    )
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.DIRECT: "native@0x40B6C0",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_operation_id"] == "rhad:route@0x40AEE4"
    assert payload["reference_order"] == 71
    assert payload["reference_symbol"] == ("JumpInliner._fixup_jmp_and_possible_jcc")
    assert payload["operation_variant"] == "simple_indirect_jump"
    assert payload["source_native_ea"] == 0x40AEC6
    assert payload["source_block_anchor_ea"] == 0x40AEDA
    assert payload["transfer_ea"] == 0x40AEE4
    assert payload["direct_target_block_id"] == "native@0x40B6C0"
    assert payload["owned_corridor_instruction_eas"] == [
        0x40AEC6,
        0x40AEDA,
        0x40AEDC,
        0x40AEDE,
        0x40AEE4,
    ]
    assert payload["imported_closure_block_ids"] == [
        "native@0x40B6C0",
        "native@0x40B6CA",
        "native@0x40B6D0",
        "native@0x40B6D4",
    ]
    assert payload["boundary_exit_eas"] == [0x40B790]
    assert next(
        operation
        for operation in batch.operations
        if operation.operation_id == "route:rhad-direct@0x40AEE4"
    ).depends_on == ("rhad:route@0x40AEA3",)


def test_checksum_producer_compiles_row72_existing_conditional_dependency() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40AEFE")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.NE
    assert normalization.condition_producer_ea == 0x40AEEC
    assert normalization.unresolved_transfer_ea == 0x40AEFE
    assert isinstance(
        normalization.conditional_select_envelope,
        FragmentReferencedImportedConditionalSelectEnvelope,
    )
    envelope = normalization.conditional_select_envelope
    assert envelope.selected_value_block_id == "native@0x40AEF4"
    assert envelope.join_block_id == "native@0x40AEFA"
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40AF00",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40A5F0",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 72
    assert payload["reference_symbol"] == "JumpInliner._fixup_jmp_and_possible_jcc"
    assert payload["operation_variant"] == "existing_conditional_plus_indirect"
    assert payload["source_native_ea"] == 0x40AEE6
    assert payload["source_block_anchor_ea"] == 0x40AEFA
    assert payload["join_ea"] == 0x40AEFA
    assert payload["observed_predicate_kind"] == PredicateKind.EQ.value
    assert payload["predicate_kind"] == PredicateKind.NE.value
    assert payload["comparison_constant"] == 0x2100AFDD
    assert payload["true_target_ea"] == 0x40AF00
    assert payload["false_target_ea"] == 0x40A5F0
    assert payload["owned_corridor_instruction_eas"] == [
        0x40AEE6,
        0x40AEEC,
        0x40AEF2,
        0x40AEF4,
        0x40AEFA,
        0x40AEFC,
        0x40AEFE,
    ]
    assert payload["imported_closure_block_ids"] == [
        "native@0x40AF00",
        "native@0x40AF1C",
        "native@0x40AF2F",
        "native@0x40AF9D",
        "native@0x40AFBB",
        "native@0x40AFD3",
        "native@0x40AFDD",
        "native@0x40B5DE",
        "native@0x40B5FB",
        "native@0x40B607",
    ]
    assert payload["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
    assert next(
        operation
        for operation in batch.operations
        if operation.operation_id == "rhad:route@0x40AEFE"
    ).depends_on == ("route:rhad-direct@0x40AEE4",)


def test_checksum_producer_compiles_row73_simple_indirect_dependency() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("route:rhad-direct@0x40AFDD")
    rewrite = operation.direct_transfer_rewrite
    assert rewrite is not None
    assert operation.source_block_id == "native@0x40AFD3"
    assert rewrite.owner_anchor_ea == 0x40AFD3
    assert rewrite.rewrite_anchor_ea == 0x40AFDD
    assert rewrite.proof_corridor_instruction_eas == (
        0x40AFBB,
        0x40AFD3,
        0x40AFD5,
        0x40AFD7,
        0x40AFDD,
    )
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.DIRECT: "native@0x40B6C0",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_operation_id"] == "rhad:route@0x40AFDD"
    assert payload["reference_order"] == 73
    assert payload["reference_symbol"] == ("JumpInliner._fixup_jmp_and_possible_jcc")
    assert payload["operation_variant"] == "simple_indirect_jump"
    assert payload["source_native_ea"] == 0x40AFBB
    assert payload["source_block_anchor_ea"] == 0x40AFD3
    assert payload["transfer_ea"] == 0x40AFDD
    assert payload["direct_target_block_id"] == "native@0x40B6C0"
    assert payload["owned_corridor_instruction_eas"] == [
        0x40AFBB,
        0x40AFD3,
        0x40AFD5,
        0x40AFD7,
        0x40AFDD,
    ]
    assert payload["imported_closure_block_ids"] == [
        "native@0x40B6C0",
        "native@0x40B6CA",
        "native@0x40B6D0",
        "native@0x40B6D4",
    ]
    assert payload["boundary_exit_eas"] == [0x40B790]
    assert next(
        operation
        for operation in batch.operations
        if operation.operation_id == "route:rhad-direct@0x40AFDD"
    ).depends_on == ("rhad:route@0x40AEFE",)


def test_checksum_producer_compiles_row74_existing_conditional_dependency() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40AFF7")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.NE
    assert normalization.condition_producer_ea == 0x40AFE5
    assert normalization.unresolved_transfer_ea == 0x40AFF7
    assert isinstance(
        normalization.conditional_select_envelope,
        FragmentReferencedImportedConditionalSelectEnvelope,
    )
    envelope = normalization.conditional_select_envelope
    assert envelope.selected_value_block_id == "native@0x40AFED"
    assert envelope.join_block_id == "native@0x40AFF3"
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40AFF9",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40A5F0",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 74
    assert payload["reference_symbol"] == "JumpInliner._fixup_jmp_and_possible_jcc"
    assert payload["operation_variant"] == "existing_conditional_plus_indirect"
    assert payload["source_native_ea"] == 0x40AFDF
    assert payload["source_block_anchor_ea"] == 0x40AFF3
    assert payload["join_ea"] == 0x40AFF3
    assert payload["observed_predicate_kind"] == PredicateKind.EQ.value
    assert payload["predicate_kind"] == PredicateKind.NE.value
    assert payload["comparison_constant"] == 0x6859ABF3
    assert payload["true_target_ea"] == 0x40AFF9
    assert payload["false_target_ea"] == 0x40A5F0
    assert payload["owned_corridor_instruction_eas"] == [
        0x40AFDF,
        0x40AFE5,
        0x40AFEB,
        0x40AFED,
        0x40AFF3,
        0x40AFF5,
        0x40AFF7,
    ]
    assert payload["imported_closure_block_ids"] == [
        "native@0x40AFF9",
        "native@0x40B00C",
        "native@0x40B01E",
        "native@0x40B022",
        "native@0x40B609",
        "native@0x40B620",
        "native@0x40B626",
    ]
    assert payload["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
    assert next(
        operation
        for operation in batch.operations
        if operation.operation_id == "rhad:route@0x40AFF7"
    ).depends_on == ("route:rhad-direct@0x40AFDD",)


def test_checksum_producer_compiles_row75_simple_indirect_dependency() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("route:rhad-direct@0x40B022")
    rewrite = operation.direct_transfer_rewrite
    assert rewrite is not None
    assert operation.source_block_id == "native@0x40B01E"
    assert rewrite.owner_anchor_ea == 0x40B01E
    assert rewrite.rewrite_anchor_ea == 0x40B022
    assert rewrite.proof_corridor_instruction_eas == (
        0x40B00C,
        0x40B01E,
        0x40B020,
        0x40B022,
    )
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.DIRECT: "native@0x40B6C0",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_operation_id"] == "rhad:route@0x40B022"
    assert payload["reference_order"] == 75
    assert payload["operation_variant"] == "simple_indirect_jump"
    assert payload["source_native_ea"] == 0x40B00C
    assert payload["source_block_anchor_ea"] == 0x40B01E
    assert payload["transfer_ea"] == 0x40B022
    assert payload["direct_target_block_id"] == "native@0x40B6C0"
    assert payload["owned_corridor_instruction_eas"] == [
        0x40B00C,
        0x40B01E,
        0x40B020,
        0x40B022,
    ]
    assert payload["boundary_exit_eas"] == [0x40B790]
    assert next(
        operation
        for operation in batch.operations
        if operation.operation_id == "route:rhad-direct@0x40B022"
    ).depends_on == ("rhad:route@0x40AFF7",)


def test_checksum_producer_compiles_row76_existing_conditional_dependency() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40B03C")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.NE
    assert normalization.condition_producer_ea == 0x40B02A
    assert normalization.unresolved_transfer_ea == 0x40B03C
    assert isinstance(
        normalization.conditional_select_envelope,
        FragmentReferencedImportedConditionalSelectEnvelope,
    )
    envelope = normalization.conditional_select_envelope
    assert envelope.selected_value_block_id == "native@0x40B032"
    assert envelope.join_block_id == "native@0x40B038"
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40B03E",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40A5F0",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 76
    assert payload["reference_symbol"] == "JumpInliner._fixup_jmp_and_possible_jcc"
    assert payload["operation_variant"] == "existing_conditional_plus_indirect"
    assert payload["source_native_ea"] == 0x40B024
    assert payload["source_block_anchor_ea"] == 0x40B038
    assert payload["join_ea"] == 0x40B038
    assert payload["observed_predicate_kind"] == PredicateKind.EQ.value
    assert payload["predicate_kind"] == PredicateKind.NE.value
    assert payload["comparison_constant"] == 0x0CDF90C9
    assert payload["true_target_ea"] == 0x40B03E
    assert payload["false_target_ea"] == 0x40A5F0
    assert payload["owned_corridor_instruction_eas"] == [
        0x40B024,
        0x40B02A,
        0x40B030,
        0x40B032,
        0x40B038,
        0x40B03A,
        0x40B03C,
    ]
    assert payload["imported_closure_block_ids"] == [
        "native@0x40B03E",
        "native@0x40B059",
        "native@0x40B06B",
        "native@0x40B06F",
        "native@0x40B628",
        "native@0x40B63F",
        "native@0x40B645",
    ]
    assert payload["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
    assert next(
        operation
        for operation in batch.operations
        if operation.operation_id == "rhad:route@0x40B03C"
    ).depends_on == ("route:rhad-direct@0x40B022",)


def test_checksum_producer_compiles_row77_simple_indirect_dependency() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("route:rhad-direct@0x40B06F")
    rewrite = operation.direct_transfer_rewrite
    assert rewrite is not None
    assert operation.source_block_id == "native@0x40B06B"
    assert rewrite.owner_anchor_ea == 0x40B06B
    assert rewrite.rewrite_anchor_ea == 0x40B06F
    assert rewrite.proof_corridor_instruction_eas == (
        0x40B059,
        0x40B06B,
        0x40B06D,
        0x40B06F,
    )
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.DIRECT: "native@0x40B6C0",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_operation_id"] == "rhad:route@0x40B06F"
    assert payload["reference_order"] == 77
    assert payload["operation_variant"] == "simple_indirect_jump"
    assert payload["source_native_ea"] == 0x40B059
    assert payload["source_block_anchor_ea"] == 0x40B06B
    assert payload["transfer_ea"] == 0x40B06F
    assert payload["direct_target_block_id"] == "native@0x40B6C0"
    assert payload["owned_corridor_instruction_eas"] == [
        0x40B059,
        0x40B06B,
        0x40B06D,
        0x40B06F,
    ]
    assert payload["boundary_exit_eas"] == [0x40B790]
    assert next(
        operation
        for operation in batch.operations
        if operation.operation_id == "route:rhad-direct@0x40B06F"
    ).depends_on == ("rhad:route@0x40B03C",)


def test_checksum_producer_compiles_row78_existing_conditional_dependency() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40B089")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.NE
    assert normalization.condition_producer_ea == 0x40B077
    assert normalization.unresolved_transfer_ea == 0x40B089
    assert isinstance(
        normalization.conditional_select_envelope,
        FragmentReferencedImportedConditionalSelectEnvelope,
    )
    envelope = normalization.conditional_select_envelope
    assert envelope.selected_value_block_id == "native@0x40B07F"
    assert envelope.join_block_id == "native@0x40B085"
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40B08B",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40A5F0",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 78
    assert payload["operation_variant"] == "existing_conditional_plus_indirect"
    assert payload["source_native_ea"] == 0x40B071
    assert payload["source_block_anchor_ea"] == 0x40B085
    assert payload["join_ea"] == 0x40B085
    assert payload["observed_predicate_kind"] == PredicateKind.EQ.value
    assert payload["predicate_kind"] == PredicateKind.NE.value
    assert payload["comparison_constant"] == 0x5E07BA29
    assert payload["true_target_ea"] == 0x40B08B
    assert payload["false_target_ea"] == 0x40A5F0
    assert payload["owned_corridor_instruction_eas"] == [
        0x40B071,
        0x40B077,
        0x40B07D,
        0x40B07F,
        0x40B085,
        0x40B087,
        0x40B089,
    ]
    assert payload["imported_closure_block_ids"] == [
        "native@0x40B08B",
        "native@0x40B094",
        "native@0x40B0B3",
        "native@0x40B0B6",
        "native@0x40B0BA",
    ]
    assert payload["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
    target_template = next(
        fragment
        for fragment in batch.template_fragments
        if fragment.root_ea == 0x40B08B
    )
    assert target_template.owned_block_entry_eas == (
        0x40B08B,
        0x40B094,
        0x40B0B3,
        0x40B0B6,
        0x40B0BA,
    )
    assert plan.block(
        "native@0x40B094"
    ).stable_identity.exact_instruction_eas == frozenset(
        {
            0x40B094,
            0x40B09A,
            0x40B0A0,
            0x40B0A5,
            0x40B0AB,
            0x40B0AD,
            0x40B0B3,
        }
    )
    assert plan.block(
        "native@0x40B0B3"
    ).stable_identity.exact_instruction_eas == frozenset({0x40B0B3})
    assert plan.block(
        "native@0x40B0B6"
    ).stable_identity.exact_instruction_eas == frozenset({0x40B0B6, 0x40B0B8, 0x40B0BA})
    assert next(
        operation
        for operation in batch.operations
        if operation.operation_id == "rhad:route@0x40B089"
    ).depends_on == ("route:rhad-direct@0x40B06F",)


def test_checksum_producer_compiles_row79_cmov_dependency() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40B0BA")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.SLT
    assert normalization.condition_producer_ea == 0x40B0A5
    assert normalization.unresolved_transfer_ea == 0x40B0BA
    assert isinstance(
        normalization.conditional_select_envelope,
        FragmentReferencedImportedConditionalSelectEnvelope,
    )
    envelope = normalization.conditional_select_envelope
    assert envelope.selected_value_block_id == "native@0x40B0B3"
    assert envelope.join_block_id == "native@0x40B0B6"
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40B6C0",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40A607",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 79
    assert payload["operation_variant"] == "cmov_selected_indirect"
    assert payload["source_native_ea"] == 0x40B09A
    assert payload["source_block_anchor_ea"] == 0x40B094
    assert payload["condition_producer_ea"] == 0x40B0A5
    assert payload["predicate_anchor_ea"] == 0x40B0B3
    assert payload["predicate_kind"] == PredicateKind.SLT.value
    assert payload["observed_predicate_kind"] == PredicateKind.SGE.value
    assert payload["comparison_constant"] == 0x0BB2D365
    assert payload["transfer_ea"] == 0x40B0BA
    assert payload["true_target_ea"] == 0x40B6C0
    assert payload["false_target_ea"] == 0x40A607
    assert payload["owned_corridor_instruction_eas"] == [
        0x40B09A,
        0x40B0AB,
        0x40B0AD,
        0x40B0B3,
        0x40B0B6,
        0x40B0B8,
        0x40B0BA,
    ]
    assert payload["imported_closure_block_ids"] == list(
        generated_reference.ACCEPTED_IMPORTED_BLOCK_IDS
    )
    assert payload["boundary_exit_eas"] == [0x40A61B, 0x40A68C, 0x40B790]
    assert next(
        operation
        for operation in batch.operations
        if operation.operation_id == "rhad:route@0x40B0BA"
    ).depends_on == ("rhad:route@0x40B089",)


def test_checksum_producer_compiles_row80_existing_conditional_dependency() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40B0D4")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.NE
    assert normalization.condition_producer_ea == 0x40B0C2
    assert normalization.unresolved_transfer_ea == 0x40B0D4
    assert isinstance(
        normalization.conditional_select_envelope,
        FragmentReferencedImportedConditionalSelectEnvelope,
    )
    envelope = normalization.conditional_select_envelope
    assert envelope.selected_value_block_id == "native@0x40B0CA"
    assert envelope.join_block_id == "native@0x40B0D0"
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40B0D6",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40A5F0",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 80
    assert payload["operation_variant"] == "existing_conditional_plus_indirect"
    assert payload["source_native_ea"] == 0x40B0BC
    assert payload["source_block_anchor_ea"] == 0x40B0D0
    assert payload["join_ea"] == 0x40B0D0
    assert payload["condition_producer_ea"] == 0x40B0C2
    assert payload["predicate_anchor_ea"] == 0x40B0C8
    assert payload["observed_predicate_kind"] == PredicateKind.EQ.value
    assert payload["predicate_kind"] == PredicateKind.NE.value
    assert payload["comparison_constant"] == 0x29947C85
    assert payload["transfer_ea"] == 0x40B0D4
    assert payload["true_target_ea"] == 0x40B0D6
    assert payload["false_target_ea"] == 0x40A5F0
    assert payload["owned_corridor_instruction_eas"] == [
        0x40B0BC,
        0x40B0C2,
        0x40B0C8,
        0x40B0CA,
        0x40B0D0,
        0x40B0D2,
        0x40B0D4,
    ]
    assert payload["imported_closure_block_ids"] == [
        "native@0x40B0D6",
        "native@0x40B0E9",
        "native@0x40B0EC",
        "native@0x40B0F0",
    ]
    assert payload["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
    assert next(
        operation
        for operation in batch.operations
        if operation.operation_id == "rhad:route@0x40B0D4"
    ).depends_on == ("rhad:route@0x40B0BA",)


def test_row81_inventory_corridor_includes_flag_producer() -> None:
    inventory = json.loads(
        (
            _REPO
            / "docs"
            / "experiments"
            / "rhad-a560-indirect-jump-reference-inventory.json"
        ).read_text(encoding="utf-8")
    )
    row81 = next(
        operation
        for operation in inventory["operations"]
        if operation["reference_order"] == 81
    )

    assert row81["flag_producer_native_ea"] == 0x40B0DB
    assert row81["owned_corridor_instruction_eas"] == [
        0x40B0DB,
        0x40B0E1,
        0x40B0E3,
        0x40B0E9,
        0x40B0EC,
        0x40B0EE,
        0x40B0F0,
    ]


def test_checksum_producer_compiles_row81_cmov_dependency() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40B0F0")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.SLT
    assert normalization.condition_producer_ea == 0x40B0DB
    assert normalization.unresolved_transfer_ea == 0x40B0F0
    assert isinstance(
        normalization.conditional_select_envelope,
        FragmentReferencedImportedConditionalSelectEnvelope,
    )
    envelope = normalization.conditional_select_envelope
    assert envelope.selected_value_block_id == "native@0x40B0E9"
    assert envelope.join_block_id == "native@0x40B0EC"
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40B6C0",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40A607",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 81
    assert payload["operation_variant"] == "cmov_selected_indirect"
    assert payload["source_native_ea"] == 0x40B0E1
    assert payload["source_block_anchor_ea"] == 0x40B0D6
    assert payload["condition_producer_ea"] == 0x40B0DB
    assert payload["predicate_anchor_ea"] == 0x40B0E9
    assert payload["predicate_kind"] == PredicateKind.SLT.value
    assert payload["observed_predicate_kind"] == PredicateKind.SGE.value
    assert payload["comparison_constant"] == 0x0BB2D365
    assert payload["transfer_ea"] == 0x40B0F0
    assert payload["true_target_ea"] == 0x40B6C0
    assert payload["false_target_ea"] == 0x40A607
    assert payload["owned_corridor_instruction_eas"] == [
        0x40B0DB,
        0x40B0E1,
        0x40B0E3,
        0x40B0E9,
        0x40B0EC,
        0x40B0EE,
        0x40B0F0,
    ]
    assert payload["imported_closure_block_ids"] == list(
        generated_reference.ACCEPTED_IMPORTED_BLOCK_IDS
    )
    assert payload["boundary_exit_eas"] == [0x40A61B, 0x40A68C, 0x40B790]
    assert next(
        operation
        for operation in batch.operations
        if operation.operation_id == "rhad:route@0x40B0F0"
    ).depends_on == ("rhad:route@0x40B0D4",)


def test_row82_inventory_corridor_includes_flag_producer() -> None:
    inventory = json.loads(
        (
            _REPO
            / "docs"
            / "experiments"
            / "rhad-a560-indirect-jump-reference-inventory.json"
        ).read_text(encoding="utf-8")
    )
    row82 = next(
        operation
        for operation in inventory["operations"]
        if operation["reference_order"] == 82
    )

    assert row82["flag_producer_native_ea"] == 0x40B0F8
    assert row82["owned_corridor_instruction_eas"] == [
        0x40B0F2,
        0x40B0F8,
        0x40B0FE,
        0x40B100,
        0x40B106,
        0x40B108,
        0x40B10A,
    ]


def test_checksum_producer_compiles_row82_existing_conditional_dependency() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40B10A")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.NE
    assert normalization.condition_producer_ea == 0x40B0F8
    assert normalization.unresolved_transfer_ea == 0x40B10A
    assert isinstance(
        normalization.conditional_select_envelope,
        FragmentReferencedImportedConditionalSelectEnvelope,
    )
    envelope = normalization.conditional_select_envelope
    assert envelope.selected_value_block_id == "native@0x40B100"
    assert envelope.join_block_id == "native@0x40B106"
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40B10C",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40A5F0",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 82
    assert payload["operation_variant"] == "existing_conditional_plus_indirect"
    assert payload["source_native_ea"] == 0x40B0F2
    assert payload["source_block_anchor_ea"] == 0x40B106
    assert payload["join_ea"] == 0x40B106
    assert payload["condition_producer_ea"] == 0x40B0F8
    assert payload["predicate_anchor_ea"] == 0x40B0FE
    assert payload["observed_predicate_kind"] == PredicateKind.EQ.value
    assert payload["predicate_kind"] == PredicateKind.NE.value
    assert payload["comparison_constant"] == 0x78BAC34B
    assert payload["transfer_ea"] == 0x40B10A
    assert payload["true_target_ea"] == 0x40B10C
    assert payload["false_target_ea"] == 0x40A5F0
    assert payload["owned_corridor_instruction_eas"] == [
        0x40B0F2,
        0x40B0F8,
        0x40B0FE,
        0x40B100,
        0x40B106,
        0x40B108,
        0x40B10A,
    ]
    assert payload["imported_closure_block_ids"] == [
        "native@0x40B10C",
        "native@0x40B11A",
        "native@0x40B121",
        "native@0x40B140",
        "native@0x40B143",
        "native@0x40B147",
    ]
    assert payload["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
    assert next(
        operation
        for operation in batch.operations
        if operation.operation_id == "rhad:route@0x40B10A"
    ).depends_on == ("rhad:route@0x40B0F0",)


def test_row83_inventory_corridor_includes_flag_producer() -> None:
    inventory = json.loads(
        (
            _REPO
            / "docs"
            / "experiments"
            / "rhad-a560-indirect-jump-reference-inventory.json"
        ).read_text(encoding="utf-8")
    )
    row83 = next(
        operation
        for operation in inventory["operations"]
        if operation["reference_order"] == 83
    )

    assert row83["flag_producer_native_ea"] == 0x40B132
    assert row83["owned_corridor_instruction_eas"] == [
        0x40B127,
        0x40B132,
        0x40B138,
        0x40B13A,
        0x40B140,
        0x40B143,
        0x40B145,
        0x40B147,
    ]


def test_checksum_producer_compiles_row83_cmov_dependency() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40B147")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.SLT
    assert normalization.condition_producer_ea == 0x40B132
    assert normalization.unresolved_transfer_ea == 0x40B147
    assert isinstance(
        normalization.conditional_select_envelope,
        FragmentReferencedImportedConditionalSelectEnvelope,
    )
    envelope = normalization.conditional_select_envelope
    assert envelope.selected_value_block_id == "native@0x40B140"
    assert envelope.join_block_id == "native@0x40B143"
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40B6C0",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40A607",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 83
    assert payload["operation_variant"] == "cmov_selected_indirect"
    assert payload["source_native_ea"] == 0x40B127
    assert payload["source_block_anchor_ea"] == 0x40B121
    assert payload["condition_producer_ea"] == 0x40B132
    assert payload["predicate_anchor_ea"] == 0x40B140
    assert payload["predicate_kind"] == PredicateKind.SLT.value
    assert payload["observed_predicate_kind"] == PredicateKind.SGE.value
    assert payload["comparison_constant"] == 0x0BB2D365
    assert payload["transfer_ea"] == 0x40B147
    assert payload["true_target_ea"] == 0x40B6C0
    assert payload["false_target_ea"] == 0x40A607
    assert payload["owned_corridor_instruction_eas"] == [
        0x40B127,
        0x40B132,
        0x40B138,
        0x40B13A,
        0x40B140,
        0x40B143,
        0x40B145,
        0x40B147,
    ]
    assert payload["imported_closure_block_ids"] == list(
        generated_reference.ACCEPTED_IMPORTED_BLOCK_IDS
    )
    assert payload["boundary_exit_eas"] == [0x40A61B, 0x40A68C, 0x40B790]
    assert next(
        operation
        for operation in batch.operations
        if operation.operation_id == "rhad:route@0x40B147"
    ).depends_on == ("rhad:route@0x40B10A",)


def test_row84_inventory_corridor_includes_flag_producer() -> None:
    inventory = json.loads(
        (
            _REPO
            / "docs"
            / "experiments"
            / "rhad-a560-indirect-jump-reference-inventory.json"
        ).read_text(encoding="utf-8")
    )
    row84 = next(
        operation
        for operation in inventory["operations"]
        if operation["reference_order"] == 84
    )

    assert row84["flag_producer_native_ea"] == 0x40B14F
    assert row84["owned_corridor_instruction_eas"] == [
        0x40B149,
        0x40B14F,
        0x40B155,
        0x40B157,
        0x40B15D,
        0x40B15F,
        0x40B161,
    ]


def test_checksum_producer_compiles_row84_existing_conditional_dependency() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40B161")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.NE
    assert normalization.condition_producer_ea == 0x40B14F
    assert normalization.unresolved_transfer_ea == 0x40B161
    assert isinstance(
        normalization.conditional_select_envelope,
        FragmentReferencedImportedConditionalSelectEnvelope,
    )
    envelope = normalization.conditional_select_envelope
    assert envelope.selected_value_block_id == "native@0x40B157"
    assert envelope.join_block_id == "native@0x40B15D"
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40B163",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40A5F0",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 84
    assert payload["operation_variant"] == "existing_conditional_plus_indirect"
    assert payload["source_native_ea"] == 0x40B149
    assert payload["source_block_anchor_ea"] == 0x40B15D
    assert payload["join_ea"] == 0x40B15D
    assert payload["condition_producer_ea"] == 0x40B14F
    assert payload["predicate_anchor_ea"] == 0x40B155
    assert payload["observed_predicate_kind"] == PredicateKind.EQ.value
    assert payload["predicate_kind"] == PredicateKind.NE.value
    assert payload["comparison_constant"] == 0x1EBFFA3C
    assert payload["transfer_ea"] == 0x40B161
    assert payload["true_target_ea"] == 0x40B163
    assert payload["false_target_ea"] == 0x40A5F0
    assert payload["owned_corridor_instruction_eas"] == [
        0x40B149,
        0x40B14F,
        0x40B155,
        0x40B157,
        0x40B15D,
        0x40B15F,
        0x40B161,
    ]
    assert payload["imported_closure_block_ids"] == [
        "native@0x40B163",
        "native@0x40B176",
        "native@0x40B179",
        "native@0x40B17D",
    ]
    assert payload["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
    assert next(
        operation
        for operation in batch.operations
        if operation.operation_id == "rhad:route@0x40B161"
    ).depends_on == ("rhad:route@0x40B147",)


def test_row85_inventory_corridor_includes_flag_producer() -> None:
    inventory = json.loads(
        (
            _REPO
            / "docs"
            / "experiments"
            / "rhad-a560-indirect-jump-reference-inventory.json"
        ).read_text(encoding="utf-8")
    )
    row85 = next(
        operation
        for operation in inventory["operations"]
        if operation["reference_order"] == 85
    )

    assert row85["flag_producer_native_ea"] == 0x40B168
    assert row85["owned_corridor_instruction_eas"] == [
        0x40B168,
        0x40B16E,
        0x40B170,
        0x40B176,
        0x40B179,
        0x40B17B,
        0x40B17D,
    ]


def test_checksum_producer_compiles_row85_cmov_dependency() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40B17D")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.SLT
    assert normalization.condition_producer_ea == 0x40B168
    assert normalization.unresolved_transfer_ea == 0x40B17D
    assert isinstance(
        normalization.conditional_select_envelope,
        FragmentReferencedImportedConditionalSelectEnvelope,
    )
    envelope = normalization.conditional_select_envelope
    assert envelope.selected_value_block_id == "native@0x40B176"
    assert envelope.join_block_id == "native@0x40B179"
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40B6C0",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40A607",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 85
    assert payload["operation_variant"] == "cmov_selected_indirect"
    assert payload["source_native_ea"] == 0x40B16E
    assert payload["source_block_anchor_ea"] == 0x40B163
    assert payload["condition_producer_ea"] == 0x40B168
    assert payload["predicate_anchor_ea"] == 0x40B176
    assert payload["predicate_kind"] == PredicateKind.SLT.value
    assert payload["observed_predicate_kind"] == PredicateKind.SGE.value
    assert payload["comparison_constant"] == 0x0BB2D365
    assert payload["transfer_ea"] == 0x40B17D
    assert payload["true_target_ea"] == 0x40B6C0
    assert payload["false_target_ea"] == 0x40A607
    assert payload["owned_corridor_instruction_eas"] == [
        0x40B168,
        0x40B16E,
        0x40B170,
        0x40B176,
        0x40B179,
        0x40B17B,
        0x40B17D,
    ]
    assert payload["imported_closure_block_ids"] == list(
        generated_reference.ACCEPTED_IMPORTED_BLOCK_IDS
    )
    assert payload["boundary_exit_eas"] == [0x40A61B, 0x40A68C, 0x40B790]
    assert next(
        operation
        for operation in batch.operations
        if operation.operation_id == "rhad:route@0x40B17D"
    ).depends_on == ("rhad:route@0x40B161",)


def test_row86_inventory_corridor_includes_flag_producer() -> None:
    inventory = json.loads(
        (
            _REPO
            / "docs"
            / "experiments"
            / "rhad-a560-indirect-jump-reference-inventory.json"
        ).read_text(encoding="utf-8")
    )
    row86 = next(
        operation
        for operation in inventory["operations"]
        if operation["reference_order"] == 86
    )

    assert row86["flag_producer_native_ea"] == 0x40B185
    assert row86["owned_corridor_instruction_eas"] == [
        0x40B17F,
        0x40B185,
        0x40B18B,
        0x40B18D,
        0x40B193,
        0x40B195,
        0x40B197,
    ]


def test_row88_inventory_corridor_includes_flag_producer() -> None:
    inventory = json.loads(
        (
            _REPO
            / "docs"
            / "experiments"
            / "rhad-a560-indirect-jump-reference-inventory.json"
        ).read_text(encoding="utf-8")
    )
    row88 = next(
        operation
        for operation in inventory["operations"]
        if operation["reference_order"] == 88
    )

    assert row88["flag_producer_native_ea"] == 0x40B1D6
    assert row88["owned_corridor_instruction_eas"] == [
        0x40B1D0,
        0x40B1D6,
        0x40B1DC,
        0x40B1DE,
        0x40B1E4,
        0x40B1E6,
        0x40B1E8,
    ]


def test_row89_inventory_corridor_includes_flag_producer() -> None:
    inventory = json.loads(
        (
            _REPO
            / "docs"
            / "experiments"
            / "rhad-a560-indirect-jump-reference-inventory.json"
        ).read_text(encoding="utf-8")
    )
    row89 = next(
        operation
        for operation in inventory["operations"]
        if operation["reference_order"] == 89
    )

    assert row89["flag_producer_native_ea"] == 0x40B205
    assert row89["owned_corridor_instruction_eas"] == [
        0x40B1FA,
        0x40B205,
        0x40B20B,
        0x40B20D,
        0x40B213,
        0x40B216,
        0x40B218,
        0x40B21A,
    ]


def test_row90_inventory_corridor_includes_flag_producer() -> None:
    inventory = json.loads(
        (
            _REPO
            / "docs"
            / "experiments"
            / "rhad-a560-indirect-jump-reference-inventory.json"
        ).read_text(encoding="utf-8")
    )
    row90 = next(
        operation
        for operation in inventory["operations"]
        if operation["reference_order"] == 90
    )

    assert row90["flag_producer_native_ea"] == 0x40B222
    assert row90["owned_corridor_instruction_eas"] == [
        0x40B21C,
        0x40B222,
        0x40B228,
        0x40B22A,
        0x40B230,
        0x40B232,
        0x40B234,
    ]
    assert row90["imported_closure_block_anchor_eas"] == [
        0x40A5F0,
        0x40A605,
        0x40B236,
        0x40B242,
        0x40B264,
        0x40B267,
    ]
    target_closure = next(
        closure
        for closure in row90["target_rooted_closures"]
        if closure["root_ea"] == 0x40B236
    )
    assert target_closure["expected_generated_block_anchor_eas"] == [
        0x40B236,
        0x40B242,
        0x40B264,
        0x40B267,
    ]
    assert target_closure["owned_native_block_entry_eas"] == [
        0x40B236,
        0x40B242,
        0x40B264,
        0x40B267,
    ]


def test_checksum_producer_compiles_row86_existing_conditional_dependency() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40B197")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.NE
    assert normalization.condition_producer_ea == 0x40B185
    assert normalization.unresolved_transfer_ea == 0x40B197
    assert isinstance(
        normalization.conditional_select_envelope,
        FragmentReferencedImportedConditionalSelectEnvelope,
    )
    envelope = normalization.conditional_select_envelope
    assert envelope.selected_value_block_id == "native@0x40B18D"
    assert envelope.join_block_id == "native@0x40B193"
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40B199",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40A5F0",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 86
    assert payload["operation_variant"] == "existing_conditional_plus_indirect"
    assert payload["source_native_ea"] == 0x40B17F
    assert payload["source_block_anchor_ea"] == 0x40B193
    assert payload["join_ea"] == 0x40B193
    assert payload["condition_producer_ea"] == 0x40B185
    assert payload["predicate_anchor_ea"] == 0x40B18B
    assert payload["observed_predicate_kind"] == PredicateKind.EQ.value
    assert payload["predicate_kind"] == PredicateKind.NE.value
    assert payload["comparison_constant"] == 0x456A4274
    assert payload["transfer_ea"] == 0x40B197
    assert payload["true_target_ea"] == 0x40B199
    assert payload["false_target_ea"] == 0x40A5F0
    assert payload["owned_corridor_instruction_eas"] == [
        0x40B17F,
        0x40B185,
        0x40B18B,
        0x40B18D,
        0x40B193,
        0x40B195,
        0x40B197,
    ]
    assert payload["imported_closure_block_ids"] == [
        "native@0x40B199",
        "native@0x40B1B6",
        "native@0x40B1CA",
        "native@0x40B1CE",
        "native@0x40B647",
        "native@0x40B660",
        "native@0x40B666",
    ]
    assert payload["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
    assert next(
        operation
        for operation in batch.operations
        if operation.operation_id == "rhad:route@0x40B197"
    ).depends_on == ("rhad:route@0x40B17D",)


def test_checksum_producer_compiles_row87_simple_indirect_dependency() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("route:rhad-direct@0x40B1CE")
    assert operation.direct_transfer_rewrite.rewrite_anchor_ea == 0x40B1CE
    assert operation.direct_transfer_rewrite.owner_anchor_ea == 0x40B1CA
    assert operation.edges[0].target_block_id == "native@0x40B6C0"
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_operation_id"] == "rhad:route@0x40B1CE"
    assert payload["reference_order"] == 87
    assert payload["operation_variant"] == "simple_indirect_jump"
    assert payload["source_native_ea"] == 0x40B1B6
    assert payload["source_block_anchor_ea"] == 0x40B1CA
    assert payload["transfer_ea"] == 0x40B1CE
    assert payload["direct_target_block_id"] == "native@0x40B6C0"
    assert payload["owned_corridor_instruction_eas"] == [
        0x40B1B6,
        0x40B1CA,
        0x40B1CC,
        0x40B1CE,
    ]
    assert payload["imported_closure_block_ids"] == [
        "native@0x40B6C0",
        "native@0x40B6CA",
        "native@0x40B6D0",
        "native@0x40B6D4",
    ]
    assert payload["boundary_exit_eas"] == [0x40B790]
    assert next(
        operation
        for operation in batch.operations
        if operation.operation_id == "route:rhad-direct@0x40B1CE"
    ).depends_on == ("rhad:route@0x40B197",)


def test_checksum_producer_compiles_row88_existing_conditional_dependency() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40B1E8")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.NE
    assert normalization.condition_producer_ea == 0x40B1D6
    assert normalization.unresolved_transfer_ea == 0x40B1E8
    assert isinstance(
        normalization.conditional_select_envelope,
        FragmentReferencedImportedConditionalSelectEnvelope,
    )
    envelope = normalization.conditional_select_envelope
    assert envelope.selected_value_block_id == "native@0x40B1DE"
    assert envelope.join_block_id == "native@0x40B1E4"
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40B1EA",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40A5F0",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 88
    assert payload["operation_variant"] == "existing_conditional_plus_indirect"
    assert payload["source_native_ea"] == 0x40B1D0
    assert payload["source_block_anchor_ea"] == 0x40B1E4
    assert payload["join_ea"] == 0x40B1E4
    assert payload["condition_producer_ea"] == 0x40B1D6
    assert payload["predicate_anchor_ea"] == 0x40B1DC
    assert payload["observed_predicate_kind"] == PredicateKind.EQ.value
    assert payload["predicate_kind"] == PredicateKind.NE.value
    assert payload["comparison_constant"] == 0x22C02855
    assert payload["transfer_ea"] == 0x40B1E8
    assert payload["true_target_ea"] == 0x40B1EA
    assert payload["false_target_ea"] == 0x40A5F0
    assert payload["owned_corridor_instruction_eas"] == [
        0x40B1D0,
        0x40B1D6,
        0x40B1DC,
        0x40B1DE,
        0x40B1E4,
        0x40B1E6,
        0x40B1E8,
    ]
    assert payload["imported_closure_block_ids"] == [
        "native@0x40B1EA",
        "native@0x40B1F4",
        "native@0x40B213",
        "native@0x40B216",
        "native@0x40B21A",
    ]
    assert payload["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
    assert next(
        operation
        for operation in batch.operations
        if operation.operation_id == "rhad:route@0x40B1E8"
    ).depends_on == ("route:rhad-direct@0x40B1CE",)


def test_checksum_producer_compiles_row89_cmov_dependency() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40B21A")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.SLT
    assert normalization.condition_producer_ea == 0x40B205
    assert normalization.unresolved_transfer_ea == 0x40B21A
    assert isinstance(
        normalization.conditional_select_envelope,
        FragmentReferencedImportedConditionalSelectEnvelope,
    )
    envelope = normalization.conditional_select_envelope
    assert envelope.selected_value_block_id == "native@0x40B213"
    assert envelope.join_block_id == "native@0x40B216"
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40B6C0",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40A607",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 89
    assert payload["operation_variant"] == "cmov_selected_indirect"
    assert payload["source_native_ea"] == 0x40B1FA
    assert payload["source_block_anchor_ea"] == 0x40B1F4
    assert payload["condition_producer_ea"] == 0x40B205
    assert payload["predicate_anchor_ea"] == 0x40B213
    assert payload["predicate_kind"] == PredicateKind.SLT.value
    assert payload["observed_predicate_kind"] == PredicateKind.SGE.value
    assert payload["comparison_constant"] == 0x0BB2D365
    assert payload["transfer_ea"] == 0x40B21A
    assert payload["true_target_ea"] == 0x40B6C0
    assert payload["false_target_ea"] == 0x40A607
    assert payload["owned_corridor_instruction_eas"] == [
        0x40B1FA,
        0x40B205,
        0x40B20B,
        0x40B20D,
        0x40B213,
        0x40B216,
        0x40B218,
        0x40B21A,
    ]
    assert payload["imported_closure_block_ids"] == list(
        generated_reference.ACCEPTED_IMPORTED_BLOCK_IDS
    )
    assert payload["boundary_exit_eas"] == [0x40A61B, 0x40A68C, 0x40B790]
    assert next(
        operation
        for operation in batch.operations
        if operation.operation_id == "rhad:route@0x40B21A"
    ).depends_on == ("rhad:route@0x40B1E8",)


def test_checksum_producer_compiles_row90_existing_conditional_dependency() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40B234")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.NE
    assert normalization.condition_producer_ea == 0x40B222
    assert normalization.unresolved_transfer_ea == 0x40B234
    assert isinstance(
        normalization.conditional_select_envelope,
        FragmentReferencedImportedConditionalSelectEnvelope,
    )
    envelope = normalization.conditional_select_envelope
    assert envelope.selected_value_block_id == "native@0x40B22A"
    assert envelope.join_block_id == "native@0x40B230"
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40B236",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40A5F0",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 90
    assert payload["operation_variant"] == "existing_conditional_plus_indirect"
    assert payload["source_native_ea"] == 0x40B21C
    assert payload["source_block_anchor_ea"] == 0x40B230
    assert payload["condition_producer_ea"] == 0x40B222
    assert payload["predicate_anchor_ea"] == 0x40B228
    assert payload["predicate_kind"] == PredicateKind.NE.value
    assert payload["observed_predicate_kind"] == PredicateKind.EQ.value
    assert payload["comparison_constant"] == 0x7278AB7F
    assert payload["transfer_ea"] == 0x40B234
    assert payload["true_target_ea"] == 0x40B236
    assert payload["false_target_ea"] == 0x40A5F0
    assert payload["owned_corridor_instruction_eas"] == [
        0x40B21C,
        0x40B222,
        0x40B228,
        0x40B22A,
        0x40B230,
        0x40B232,
        0x40B234,
    ]
    assert payload["imported_closure_block_ids"] == [
        "native@0x40B236",
        "native@0x40B242",
        "native@0x40B264",
        "native@0x40B267",
    ]
    assert payload["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
    assert next(
        operation
        for operation in batch.operations
        if operation.operation_id == "rhad:route@0x40B234"
    ).depends_on == ("rhad:route@0x40B21A",)
    target_template = next(
        fragment
        for fragment in batch.template_fragments
        if fragment.root_ea == 0x40B236
    )
    assert target_template.owned_block_entry_eas == (
        0x40B236,
        0x40B242,
        0x40B264,
        0x40B267,
    )
    assert {
        "native@0x40B236",
        "native@0x40B242",
        "native@0x40B264",
        "native@0x40B267",
    }.issubset(batch.native_body_entry_block_ids)
    assert plan.block(
        "native@0x40B242"
    ).stable_identity.exact_instruction_eas == frozenset(
        {
            0x40B242,
            0x40B248,
            0x40B251,
            0x40B256,
            0x40B25C,
            0x40B25E,
            0x40B264,
        }
    )
    assert plan.block(
        "native@0x40B264"
    ).stable_identity.exact_instruction_eas == frozenset({0x40B264})
    assert plan.block(
        "native@0x40B267"
    ).stable_identity.exact_instruction_eas == frozenset(
        {0x40B267, 0x40B269, 0x40B26B}
    )


def test_row91_inventory_corridor_includes_flag_producer() -> None:
    inventory = json.loads(
        (
            _REPO
            / "docs"
            / "experiments"
            / "rhad-a560-indirect-jump-reference-inventory.json"
        ).read_text(encoding="utf-8")
    )
    row91 = next(
        operation
        for operation in inventory["operations"]
        if operation["reference_order"] == 91
    )

    assert row91["flag_producer_native_ea"] == 0x40B256
    assert row91["owned_corridor_instruction_eas"] == [
        0x40B248,
        0x40B256,
        0x40B25C,
        0x40B25E,
        0x40B264,
        0x40B267,
        0x40B269,
        0x40B26B,
    ]


def test_checksum_producer_compiles_row91_cmov_dependency() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40B26B")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.SLT
    assert normalization.condition_producer_ea == 0x40B256
    assert normalization.unresolved_transfer_ea == 0x40B26B
    assert isinstance(
        normalization.conditional_select_envelope,
        FragmentReferencedImportedConditionalSelectEnvelope,
    )
    envelope = normalization.conditional_select_envelope
    assert envelope.selected_value_block_id == "native@0x40B264"
    assert envelope.join_block_id == "native@0x40B267"
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40B6C0",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40A607",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 91
    assert payload["operation_variant"] == "cmov_selected_indirect"
    assert payload["source_native_ea"] == 0x40B248
    assert payload["source_block_anchor_ea"] == 0x40B242
    assert payload["condition_producer_ea"] == 0x40B256
    assert payload["predicate_anchor_ea"] == 0x40B264
    assert payload["predicate_kind"] == PredicateKind.SLT.value
    assert payload["observed_predicate_kind"] == PredicateKind.SGE.value
    assert payload["comparison_constant"] == 0x0BB2D365
    assert payload["transfer_ea"] == 0x40B26B
    assert payload["true_target_ea"] == 0x40B6C0
    assert payload["false_target_ea"] == 0x40A607
    assert payload["owned_corridor_instruction_eas"] == [
        0x40B248,
        0x40B256,
        0x40B25C,
        0x40B25E,
        0x40B264,
        0x40B267,
        0x40B269,
        0x40B26B,
    ]
    assert payload["imported_closure_block_ids"] == list(
        generated_reference.ACCEPTED_IMPORTED_BLOCK_IDS
    )
    assert payload["boundary_exit_eas"] == [0x40A61B, 0x40A68C, 0x40B790]
    assert next(
        operation
        for operation in batch.operations
        if operation.operation_id == "rhad:route@0x40B26B"
    ).depends_on == ("rhad:route@0x40B234",)


def test_row92_inventory_corridor_includes_flag_producer() -> None:
    inventory = json.loads(
        (
            _REPO
            / "docs"
            / "experiments"
            / "rhad-a560-indirect-jump-reference-inventory.json"
        ).read_text(encoding="utf-8")
    )
    row92 = next(
        operation
        for operation in inventory["operations"]
        if operation["reference_order"] == 92
    )

    assert row92["flag_producer_native_ea"] == 0x40B273
    assert row92["owned_corridor_instruction_eas"] == [
        0x40B26D,
        0x40B273,
        0x40B279,
        0x40B27B,
        0x40B281,
        0x40B283,
        0x40B285,
    ]


def test_checksum_producer_compiles_row92_existing_conditional_dependency() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40B285")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.NE
    assert normalization.condition_producer_ea == 0x40B273
    assert normalization.unresolved_transfer_ea == 0x40B285
    assert isinstance(
        normalization.conditional_select_envelope,
        FragmentReferencedImportedConditionalSelectEnvelope,
    )
    envelope = normalization.conditional_select_envelope
    assert envelope.selected_value_block_id == "native@0x40B27B"
    assert envelope.join_block_id == "native@0x40B281"
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40B287",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40A5F0",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 92
    assert payload["operation_variant"] == "existing_conditional_plus_indirect"
    assert payload["source_native_ea"] == 0x40B26D
    assert payload["source_block_anchor_ea"] == 0x40B281
    assert payload["condition_producer_ea"] == 0x40B273
    assert payload["predicate_anchor_ea"] == 0x40B279
    assert payload["predicate_kind"] == PredicateKind.NE.value
    assert payload["observed_predicate_kind"] == PredicateKind.EQ.value
    assert payload["comparison_constant"] == 0x13921E0E
    assert payload["transfer_ea"] == 0x40B285
    assert payload["true_target_ea"] == 0x40B287
    assert payload["false_target_ea"] == 0x40A5F0
    assert payload["owned_corridor_instruction_eas"] == [
        0x40B26D,
        0x40B273,
        0x40B279,
        0x40B27B,
        0x40B281,
        0x40B283,
        0x40B285,
    ]
    assert payload["imported_closure_block_ids"] == [
        "native@0x40B287",
        "native@0x40B2A6",
        "native@0x40B2B7",
        "native@0x40B2CF",
        "native@0x40B2D9",
        "native@0x40B668",
        "native@0x40B685",
        "native@0x40B691",
    ]
    assert payload["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
    assert next(
        operation
        for operation in batch.operations
        if operation.operation_id == "rhad:route@0x40B285"
    ).depends_on == ("rhad:route@0x40B26B",)
    target_template = next(
        fragment
        for fragment in batch.template_fragments
        if fragment.root_ea == 0x40B287
    )
    assert target_template.owned_block_entry_eas == (
        0x40B287,
        0x40B2A6,
        0x40B2B7,
        0x40B2CF,
        0x40B2D9,
        0x40B668,
        0x40B685,
        0x40B691,
    )
    assert {
        "native@0x40B287",
        "native@0x40B2A6",
        "native@0x40B2B7",
        "native@0x40B2CF",
        "native@0x40B2D9",
        "native@0x40B668",
        "native@0x40B685",
        "native@0x40B691",
    }.issubset(batch.native_body_entry_block_ids)
    assert target_template.preserved_unresolved_transfers == (
        generated_reference.RhadGeneratedPreservedTransfer(
            transfer_ea=0x40B2D9,
            boundary_exit_eas=(0x40B6C0,),
        ),
        generated_reference.RhadGeneratedPreservedTransfer(
            transfer_ea=0x40B691,
            boundary_exit_eas=(0x40A607,),
        ),
    )
    assert plan.block(
        "native@0x40B287"
    ).stable_identity.exact_instruction_eas == frozenset(
        {
            0x40B287,
            0x40B28C,
            0x40B291,
            0x40B293,
            0x40B297,
            0x40B29B,
            0x40B29C,
            0x40B2A0,
        }
    )
    assert plan.block(
        "native@0x40B2CF"
    ).stable_identity.exact_instruction_eas == frozenset(
        {0x40B2CF, 0x40B2D1, 0x40B2D3, 0x40B2D9}
    )
    assert plan.block(
        "native@0x40B691"
    ).stable_identity.exact_instruction_eas == frozenset({0x40B691})


def test_checksum_producer_compiles_row93_simple_indirect_dependency() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("route:rhad-direct@0x40B2D9")
    assert operation.direct_transfer_rewrite.rewrite_anchor_ea == 0x40B2D9
    assert operation.direct_transfer_rewrite.owner_anchor_ea == 0x40B2CF
    assert operation.edges[0].target_block_id == "native@0x40B6C0"
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_operation_id"] == "rhad:route@0x40B2D9"
    assert payload["reference_order"] == 93
    assert payload["operation_variant"] == "simple_indirect_jump"
    assert payload["source_native_ea"] == 0x40B2B7
    assert payload["source_block_anchor_ea"] == 0x40B2CF
    assert payload["transfer_ea"] == 0x40B2D9
    assert payload["direct_target_block_id"] == "native@0x40B6C0"
    assert payload["owned_corridor_instruction_eas"] == [
        0x40B2B7,
        0x40B2CF,
        0x40B2D1,
        0x40B2D3,
        0x40B2D9,
    ]
    assert payload["imported_closure_block_ids"] == [
        "native@0x40B6C0",
        "native@0x40B6CA",
        "native@0x40B6D0",
        "native@0x40B6D4",
    ]
    assert payload["boundary_exit_eas"] == [0x40B790]
    assert next(
        operation
        for operation in batch.operations
        if operation.operation_id == "route:rhad-direct@0x40B2D9"
    ).depends_on == ("rhad:route@0x40B285",)


def test_row94_inventory_corridor_includes_flag_producer() -> None:
    inventory = json.loads(
        (
            _REPO
            / "docs"
            / "experiments"
            / "rhad-a560-indirect-jump-reference-inventory.json"
        ).read_text(encoding="utf-8")
    )
    row94 = next(
        operation
        for operation in inventory["operations"]
        if operation["reference_order"] == 94
    )

    assert row94["flag_producer_native_ea"] == 0x40B2E1
    assert row94["owned_corridor_instruction_eas"] == [
        0x40B2DB,
        0x40B2E1,
        0x40B2E7,
        0x40B2E9,
        0x40B2EF,
        0x40B2F1,
        0x40B2F3,
    ]


def test_checksum_producer_compiles_row94_existing_conditional_dependency() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40B2F3")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.NE
    assert normalization.condition_producer_ea == 0x40B2E1
    assert normalization.unresolved_transfer_ea == 0x40B2F3
    assert isinstance(
        normalization.conditional_select_envelope,
        FragmentReferencedImportedConditionalSelectEnvelope,
    )
    envelope = normalization.conditional_select_envelope
    assert envelope.selected_value_block_id == "native@0x40B2E9"
    assert envelope.join_block_id == "native@0x40B2EF"
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40B2F5",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40A5F0",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 94
    assert payload["operation_variant"] == "existing_conditional_plus_indirect"
    assert payload["source_native_ea"] == 0x40B2DB
    assert payload["source_block_anchor_ea"] == 0x40B2EF
    assert payload["condition_producer_ea"] == 0x40B2E1
    assert payload["predicate_anchor_ea"] == 0x40B2E7
    assert payload["predicate_kind"] == PredicateKind.NE.value
    assert payload["observed_predicate_kind"] == PredicateKind.EQ.value
    assert payload["comparison_constant"] == 0x6487820D
    assert payload["transfer_ea"] == 0x40B2F3
    assert payload["true_target_ea"] == 0x40B2F5
    assert payload["false_target_ea"] == 0x40A5F0
    assert payload["owned_corridor_instruction_eas"] == [
        0x40B2DB,
        0x40B2E1,
        0x40B2E7,
        0x40B2E9,
        0x40B2EF,
        0x40B2F1,
        0x40B2F3,
    ]
    assert payload["imported_closure_block_ids"] == [
        "native@0x40B2F5",
        "native@0x40B312",
        "native@0x40B326",
        "native@0x40B32A",
        "native@0x40B693",
        "native@0x40B6AC",
        "native@0x40B6B2",
    ]
    assert payload["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
    assert next(
        operation
        for operation in batch.operations
        if operation.operation_id == "rhad:route@0x40B2F3"
    ).depends_on == ("route:rhad-direct@0x40B2D9",)
    target_template = next(
        fragment
        for fragment in batch.template_fragments
        if fragment.root_ea == 0x40B2F5
    )
    assert target_template.owned_block_entry_eas == (
        0x40B2F5,
        0x40B312,
        0x40B326,
        0x40B32A,
        0x40B693,
        0x40B6AC,
        0x40B6B2,
    )
    assert {
        "native@0x40B2F5",
        "native@0x40B312",
        "native@0x40B326",
        "native@0x40B32A",
        "native@0x40B693",
        "native@0x40B6AC",
        "native@0x40B6B2",
    }.issubset(batch.native_body_entry_block_ids)
    assert target_template.preserved_unresolved_transfers == (
        generated_reference.RhadGeneratedPreservedTransfer(
            transfer_ea=0x40B32A,
            boundary_exit_eas=(0x40B6C0,),
        ),
        generated_reference.RhadGeneratedPreservedTransfer(
            transfer_ea=0x40B6B2,
            boundary_exit_eas=(0x40A607,),
        ),
    )
    assert plan.block(
        "native@0x40B2F5"
    ).stable_identity.exact_instruction_eas == frozenset(
        {0x40B2F5, 0x40B2F7, 0x40B2FC, 0x40B301, 0x40B303, 0x40B308, 0x40B30C}
    )
    assert plan.block(
        "native@0x40B326"
    ).stable_identity.exact_instruction_eas == frozenset(
        {0x40B326, 0x40B328, 0x40B32A}
    )
    assert plan.block(
        "native@0x40B6B2"
    ).stable_identity.exact_instruction_eas == frozenset({0x40B6B2})


def test_checksum_producer_compiles_row95_simple_indirect_dependency() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("route:rhad-direct@0x40B32A")
    assert operation.direct_transfer_rewrite.rewrite_anchor_ea == 0x40B32A
    assert operation.direct_transfer_rewrite.owner_anchor_ea == 0x40B326
    assert operation.edges[0].target_block_id == "native@0x40B6C0"
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_operation_id"] == "rhad:route@0x40B32A"
    assert payload["reference_order"] == 95
    assert payload["operation_variant"] == "simple_indirect_jump"
    assert payload["source_native_ea"] == 0x40B312
    assert payload["source_block_anchor_ea"] == 0x40B326
    assert payload["transfer_ea"] == 0x40B32A
    assert payload["direct_target_block_id"] == "native@0x40B6C0"
    assert payload["owned_corridor_instruction_eas"] == [
        0x40B312,
        0x40B326,
        0x40B328,
        0x40B32A,
    ]
    assert payload["imported_closure_block_ids"] == [
        "native@0x40B6C0",
        "native@0x40B6CA",
        "native@0x40B6D0",
        "native@0x40B6D4",
    ]
    assert payload["boundary_exit_eas"] == [0x40B790]
    assert next(
        operation
        for operation in batch.operations
        if operation.operation_id == "route:rhad-direct@0x40B32A"
    ).depends_on == ("rhad:route@0x40B2F3",)


def test_checksum_producer_compiles_row96_setcc_table_dependency() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40B340")
    normalization = operation.computed_branch_normalization
    assert isinstance(normalization, FragmentSetccIndexedTableNormalization)
    assert normalization.predicate_kind is PredicateKind.NE
    assert (
        normalization.fallthrough_delivery
        is FragmentSetccFallthroughDelivery.PLANNED_HELPER
    )
    assert operation.requires_fallthrough_helper is True
    assert normalization.condition_producer_ea == 0x40B32E
    assert normalization.unresolved_transfer_ea == 0x40B340
    evidence = normalization.table_evidence
    assert evidence.table_base_ea == 0x48B618
    assert evidence.index_scaling.kind.value == "scaled_lookup"
    assert evidence.index_scaling.lookup_ea == 0x40B337
    assert evidence.index_scaling.scale_bytes == 4
    assert evidence.stride_bytes == 4
    assert evidence.true_entry.decoded_target_ea == 0x40A5F0
    assert evidence.false_entry.decoded_target_ea == 0x40B342
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40A5F0",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40B342",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 96
    assert payload["reference_symbol"] == "JumpInliner._fixup_index_access"
    assert payload["operation_variant"] == "setcc_indexed_table"
    assert payload["source_native_ea"] == 0x40B32C
    assert payload["condition_producer_ea"] == 0x40B32E
    assert payload["predicate_anchor_ea"] == 0x40B334
    assert payload["fallthrough_delivery"] == "planned_helper"
    assert payload["transfer_ea"] == 0x40B340
    assert payload["owned_corridor_instruction_eas"] == [
        0x40B32C,
        0x40B32E,
        0x40B334,
        0x40B337,
        0x40B33E,
        0x40B340,
    ]
    assert payload["imported_closure_block_ids"] == [
        "native@0x40B342",
        "native@0x40B354",
        "native@0x40B373",
        "native@0x40B376",
        "native@0x40B37A",
    ]
    assert payload["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
    assert payload["proof_artifact"]["content_identity"] == (
        "sha256:84e0228bce62ddd78ae00141b1f07db44216ad30418cc82f4039613591d02e50"
    )
    assert next(
        operation
        for operation in batch.operations
        if operation.operation_id == "rhad:route@0x40B340"
    ).depends_on == ("route:rhad-direct@0x40B32A",)


def test_row97_inventory_corridor_includes_flag_producer() -> None:
    inventory = json.loads(
        (
            _REPO
            / "docs"
            / "experiments"
            / "rhad-a560-indirect-jump-reference-inventory.json"
        ).read_text(encoding="utf-8")
    )
    row97 = next(
        operation
        for operation in inventory["operations"]
        if operation["reference_order"] == 97
    )

    assert row97["flag_producer_native_ea"] == 0x40B365
    assert row97["owned_corridor_instruction_eas"] == [
        0x40B35A,
        0x40B365,
        0x40B36B,
        0x40B36D,
        0x40B373,
        0x40B376,
        0x40B378,
        0x40B37A,
    ]


def test_row98_inventory_owns_flag_producer_and_complete_target_closures() -> None:
    inventory = json.loads(
        (
            _REPO
            / "docs"
            / "experiments"
            / "rhad-a560-indirect-jump-reference-inventory.json"
        ).read_text(encoding="utf-8")
    )
    row98 = next(
        operation
        for operation in inventory["operations"]
        if operation["reference_order"] == 98
    )

    assert row98["flag_producer_native_ea"] == 0x40B382
    assert row98["owned_corridor_instruction_eas"] == [
        0x40B37C,
        0x40B382,
        0x40B388,
        0x40B38A,
        0x40B390,
        0x40B392,
        0x40B394,
    ]
    assert row98["imported_closure_block_anchor_eas"] == [
        0x40B396,
        0x40B3A4,
        0x40B3AA,
        0x40B3AE,
        0x40B3E5,
        0x40B3F3,
        0x40B3F9,
        0x40B3FD,
    ]
    assert row98["boundary_exit_eas"] == [0x40A5F0, 0x40B3B0, 0x40B3FF]
    assert row98["unavailable_closure_exit_eas"] == []
    assert row98["target_rooted_closures"] == [
        {
            "boundary_exit_eas": [0x40A5F0, 0x40B3B0],
            "expected_generated_block_anchor_eas": [
                0x40B396,
                0x40B3A4,
                0x40B3AA,
                0x40B3AE,
            ],
            "owned_native_block_entry_eas": [0x40B396, 0x40B3A4, 0x40B3AA],
            "root_ea": 0x40B396,
            "status": "complete",
            "unavailable_exit_eas": [],
        },
        {
            "boundary_exit_eas": [0x40A5F0, 0x40B3FF],
            "expected_generated_block_anchor_eas": [
                0x40B3E5,
                0x40B3F3,
                0x40B3F9,
                0x40B3FD,
            ],
            "owned_native_block_entry_eas": [0x40B3E5, 0x40B3F3, 0x40B3F9],
            "root_ea": 0x40B3E5,
            "status": "complete",
            "unavailable_exit_eas": [],
        },
    ]


def test_row99_inventory_corridor_includes_flag_producer() -> None:
    inventory = json.loads(
        (
            _REPO
            / "docs"
            / "experiments"
            / "rhad-a560-indirect-jump-reference-inventory.json"
        ).read_text(encoding="utf-8")
    )
    row99 = next(
        operation
        for operation in inventory["operations"]
        if operation["reference_order"] == 99
    )

    assert row99["flag_producer_native_ea"] == 0x40B39C
    assert row99["owned_corridor_instruction_eas"] == [
        0x40B396,
        0x40B39C,
        0x40B3A2,
        0x40B3A4,
        0x40B3AA,
        0x40B3AC,
        0x40B3AE,
    ]
    assert row99["imported_closure_block_anchor_eas"] == [
        0x40A5F0,
        0x40A605,
        0x40B3B0,
        0x40B3E3,
    ]
    assert row99["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
    assert row99["unavailable_closure_exit_eas"] == []
    assert all(
        closure["status"] == "complete"
        and closure["unavailable_exit_eas"] == []
        for closure in row99["target_rooted_closures"]
    )


def test_checksum_producer_compiles_row97_cmov_dependency() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40B37A")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.SLT
    assert normalization.condition_producer_ea == 0x40B365
    assert normalization.unresolved_transfer_ea == 0x40B37A
    assert isinstance(
        normalization.conditional_select_envelope,
        FragmentReferencedImportedConditionalSelectEnvelope,
    )
    envelope = normalization.conditional_select_envelope
    assert envelope.selected_value_block_id == "native@0x40B373"
    assert envelope.join_block_id == "native@0x40B376"
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40B6C0",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40A607",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 97
    assert payload["reference_symbol"] == "JumpInliner._fixup_cmov"
    assert payload["operation_variant"] == "cmov_selected_indirect"
    assert payload["source_native_ea"] == 0x40B35A
    assert payload["source_block_anchor_ea"] == 0x40B354
    assert payload["condition_producer_ea"] == 0x40B365
    assert payload["predicate_anchor_ea"] == 0x40B373
    assert payload["predicate_kind"] == PredicateKind.SLT.value
    assert payload["observed_predicate_kind"] == PredicateKind.SGE.value
    assert payload["comparison_constant"] == 0x0BB2D365
    assert payload["transfer_ea"] == 0x40B37A
    assert payload["true_target_ea"] == 0x40B6C0
    assert payload["false_target_ea"] == 0x40A607
    assert payload["owned_corridor_instruction_eas"] == [
        0x40B35A,
        0x40B365,
        0x40B36B,
        0x40B36D,
        0x40B373,
        0x40B376,
        0x40B378,
        0x40B37A,
    ]
    assert payload["imported_closure_block_ids"] == list(
        generated_reference.ACCEPTED_IMPORTED_BLOCK_IDS
    )
    assert payload["boundary_exit_eas"] == [0x40A61B, 0x40A68C, 0x40B790]
    assert next(
        operation
        for operation in batch.operations
        if operation.operation_id == "rhad:route@0x40B37A"
    ).depends_on == ("rhad:route@0x40B340",)


def test_checksum_producer_compiles_row98_existing_conditional_dependency() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(), evidence_generation=7
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None

    operation = plan.operation("rhad:route@0x40B394")
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.predicate_kind is PredicateKind.SGE
    assert normalization.condition_producer_ea == 0x40B382
    assert normalization.unresolved_transfer_ea == 0x40B394
    assert isinstance(
        normalization.conditional_select_envelope,
        FragmentReferencedImportedConditionalSelectEnvelope,
    )
    envelope = normalization.conditional_select_envelope
    assert envelope.selected_value_block_id == "native@0x40B38A"
    assert envelope.join_block_id == "native@0x40B390"
    assert {edge.role: edge.target_block_id for edge in operation.edges} == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40B396",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40B3E5",
    }
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 98
    assert payload["reference_symbol"] == "JumpInliner._fixup_jmp_and_possible_jcc"
    assert payload["operation_variant"] == "existing_conditional_plus_indirect"
    assert payload["source_native_ea"] == 0x40B37C
    assert payload["source_block_anchor_ea"] == 0x40B390
    assert payload["condition_producer_ea"] == 0x40B382
    assert payload["predicate_anchor_ea"] == 0x40B388
    assert payload["predicate_kind"] == PredicateKind.SGE.value
    assert payload["observed_predicate_kind"] == PredicateKind.SLT.value
    assert payload["comparison_constant"] == 0x7F9D6412
    assert payload["transfer_ea"] == 0x40B394
    assert payload["true_target_ea"] == 0x40B396
    assert payload["false_target_ea"] == 0x40B3E5
    assert payload["owned_corridor_instruction_eas"] == [
        0x40B37C,
        0x40B382,
        0x40B388,
        0x40B38A,
        0x40B390,
        0x40B392,
        0x40B394,
    ]
    assert payload["imported_closure_block_ids"] == [
        "native@0x40B396",
        "native@0x40B3A4",
        "native@0x40B3AA",
        "native@0x40B3AE",
        "native@0x40B3E5",
        "native@0x40B3F3",
        "native@0x40B3F9",
        "native@0x40B3FD",
    ]
    assert payload["boundary_exit_eas"] == [0x40A5F0, 0x40B3B0, 0x40B3FF]
    assert next(
        operation
        for operation in batch.operations
        if operation.operation_id == "rhad:route@0x40B394"
    ).depends_on == ("rhad:route@0x40B37A",)


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
    with pytest.raises(ValueError, match="captured native range"):
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
    assert artifact.content_identity == (
        "sha256:cab149ee6cce29957798829cceba0a2da5e17bbf3fda4c6d55dad62d64ec3785"
    )
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


def test_row68_proof_artifact_is_required_and_content_addressed(
    tmp_path: Path,
) -> None:
    artifact = generated_reference.load_row68_table_proof_artifact()
    checked_in = json.loads(
        generated_reference.ROW68_TABLE_PROOF_PATH.read_text(encoding="utf-8")
    )

    assert artifact.content_identity == checked_in["content_identity"]
    assert artifact.content_identity == (
        "sha256:9eb674af190cee8d9b391605feb930a59bcf708c9fbb519f2d8bd26cac27fdd0"
    )
    assert artifact.proof_payload == checked_in["proof"]
    assert artifact.operation_id == "rhad:route@0x40AE3C"
    assert artifact.reference_order == 68

    with pytest.raises(RhadCompilerRejection, match="artifact is unavailable"):
        generated_reference.load_row68_table_proof_artifact(
            tmp_path / "missing-row68-proof.json"
        )

    mismatched_path = tmp_path / "mismatched-row68-proof.json"
    checked_in["content_identity"] = "sha256:" + ("0" * 64)
    mismatched_path.write_text(json.dumps(checked_in), encoding="utf-8")
    with pytest.raises(RhadCompilerRejection, match="content identity"):
        generated_reference.load_row68_table_proof_artifact(mismatched_path)


def test_row96_proof_artifact_is_required_and_content_addressed(
    tmp_path: Path,
) -> None:
    artifact = generated_reference.load_row96_table_proof_artifact()
    checked_in = json.loads(
        generated_reference.ROW96_TABLE_PROOF_PATH.read_text(encoding="utf-8")
    )

    assert artifact.content_identity == checked_in["content_identity"]
    assert artifact.content_identity == (
        "sha256:84e0228bce62ddd78ae00141b1f07db44216ad30418cc82f4039613591d02e50"
    )
    assert artifact.proof_payload == checked_in["proof"]
    assert artifact.operation_id == "rhad:route@0x40B340"
    assert artifact.reference_order == 96

    with pytest.raises(RhadCompilerRejection, match="artifact is unavailable"):
        generated_reference.load_row96_table_proof_artifact(
            tmp_path / "missing-row96-proof.json"
        )

    mismatched_path = tmp_path / "mismatched-row96-proof.json"
    checked_in["content_identity"] = "sha256:" + ("0" * 64)
    mismatched_path.write_text(json.dumps(checked_in), encoding="utf-8")
    with pytest.raises(RhadCompilerRejection, match="content identity"):
        generated_reference.load_row96_table_proof_artifact(mismatched_path)


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
    row6 = next(
        operation for operation in operations if operation["reference_order"] == 6
    )
    row19 = next(
        operation for operation in operations if operation["reference_order"] == 19
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
    row25 = next(
        operation for operation in operations if operation["reference_order"] == 25
    )
    row26 = next(
        operation for operation in operations if operation["reference_order"] == 26
    )
    row30 = next(
        operation for operation in operations if operation["reference_order"] == 30
    )
    row31 = next(
        operation for operation in operations if operation["reference_order"] == 31
    )
    row32 = next(
        operation for operation in operations if operation["reference_order"] == 32
    )
    row33 = next(
        operation for operation in operations if operation["reference_order"] == 33
    )
    row34 = next(
        operation for operation in operations if operation["reference_order"] == 34
    )
    row35 = next(
        operation for operation in operations if operation["reference_order"] == 35
    )
    row36 = next(
        operation for operation in operations if operation["reference_order"] == 36
    )
    row37 = next(
        operation for operation in operations if operation["reference_order"] == 37
    )
    row38 = next(
        operation for operation in operations if operation["reference_order"] == 38
    )
    row39 = next(
        operation for operation in operations if operation["reference_order"] == 39
    )
    row40 = next(
        operation for operation in operations if operation["reference_order"] == 40
    )
    row52 = next(
        operation for operation in operations if operation["reference_order"] == 52
    )
    row53 = next(
        operation for operation in operations if operation["reference_order"] == 53
    )
    row54 = next(
        operation for operation in operations if operation["reference_order"] == 54
    )
    row55 = next(
        operation for operation in operations if operation["reference_order"] == 55
    )
    row56 = next(
        operation for operation in operations if operation["reference_order"] == 56
    )
    row57 = next(
        operation for operation in operations if operation["reference_order"] == 57
    )
    row58 = next(
        operation for operation in operations if operation["reference_order"] == 58
    )
    row59 = next(
        operation for operation in operations if operation["reference_order"] == 59
    )
    row60 = next(
        operation for operation in operations if operation["reference_order"] == 60
    )
    row61 = next(
        operation for operation in operations if operation["reference_order"] == 61
    )
    row62 = next(
        operation for operation in operations if operation["reference_order"] == 62
    )
    row63 = next(
        operation for operation in operations if operation["reference_order"] == 63
    )
    row64 = next(
        operation for operation in operations if operation["reference_order"] == 64
    )
    row65 = next(
        operation for operation in operations if operation["reference_order"] == 65
    )
    row66 = next(
        operation for operation in operations if operation["reference_order"] == 66
    )
    row67 = next(
        operation for operation in operations if operation["reference_order"] == 67
    )
    row68 = next(
        operation for operation in operations if operation["reference_order"] == 68
    )
    row69 = next(
        operation for operation in operations if operation["reference_order"] == 69
    )
    row70 = next(
        operation for operation in operations if operation["reference_order"] == 70
    )
    row71 = next(
        operation for operation in operations if operation["reference_order"] == 71
    )
    row72 = next(
        operation for operation in operations if operation["reference_order"] == 72
    )
    row73 = next(
        operation for operation in operations if operation["reference_order"] == 73
    )
    row74 = next(
        operation for operation in operations if operation["reference_order"] == 74
    )
    row75 = next(
        operation for operation in operations if operation["reference_order"] == 75
    )
    row76 = next(
        operation for operation in operations if operation["reference_order"] == 76
    )
    row77 = next(
        operation for operation in operations if operation["reference_order"] == 77
    )
    row78 = next(
        operation for operation in operations if operation["reference_order"] == 78
    )
    row79 = next(
        operation for operation in operations if operation["reference_order"] == 79
    )
    row80 = next(
        operation for operation in operations if operation["reference_order"] == 80
    )
    row81 = next(
        operation for operation in operations if operation["reference_order"] == 81
    )
    row82 = next(
        operation for operation in operations if operation["reference_order"] == 82
    )
    row83 = next(
        operation for operation in operations if operation["reference_order"] == 83
    )
    row84 = next(
        operation for operation in operations if operation["reference_order"] == 84
    )
    row85 = next(
        operation for operation in operations if operation["reference_order"] == 85
    )
    row86 = next(
        operation for operation in operations if operation["reference_order"] == 86
    )
    row87 = next(
        operation for operation in operations if operation["reference_order"] == 87
    )
    row88 = next(
        operation for operation in operations if operation["reference_order"] == 88
    )
    row89 = next(
        operation for operation in operations if operation["reference_order"] == 89
    )
    row96 = next(
        operation for operation in operations if operation["reference_order"] == 96
    )
    row97 = next(
        operation for operation in operations if operation["reference_order"] == 97
    )
    row98 = next(
        operation for operation in operations if operation["reference_order"] == 98
    )
    batch = reference_batch_for_native_key(_native_key())
    assert batch is not None
    row16_artifact = generated_reference.load_row16_table_proof_artifact()
    row17_artifact = generated_reference.load_row17_table_proof_artifact()
    row68_artifact = generated_reference.load_row68_table_proof_artifact()
    row96_artifact = generated_reference.load_row96_table_proof_artifact()

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
        assert (
            rows_by_operation_id[reference_operation_id]["current_generated_proof"][
                "status"
            ]
            == "accepted_generated_c6"
        )
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
    assert row6["operation_id"] == "rhad:route@0x40A679"
    assert row6["current_compiler_support"] == "typed_simple_indirect_jump"
    assert row6["current_generated_proof"] == {
        "accepted_commits": ["5b813d0d6", "c93634ba6", "d0cc04417"],
        "status": "accepted_generated_c6",
    }
    assert row6["boundary_exit_eas"] == [0x40A5F0, 0x40AE3E]
    assert row6["imported_closure_block_anchor_eas"] == [
        0x40AE26,
        0x40AE3C,
    ]
    assert row19["operation_id"] == "rhad:route@0x40A7EF"
    assert row19["current_compiler_support"] == "typed_simple_indirect_jump"
    assert row19["current_generated_proof"] == {
        "accepted_commits": ["0543fe2dd", "1b3fadea3"],
        "status": "accepted_generated_c6",
    }
    assert row19["boundary_exit_eas"] == [0x40B790]
    assert row19["imported_closure_block_anchor_eas"] == [
        0x40B6C0,
        0x40B6CA,
        0x40B6D0,
        0x40B6D4,
    ]
    assert row25["operation_id"] == "rhad:route@0x40A8B3"
    assert row25["current_compiler_support"] == "typed_simple_indirect_jump"
    assert row25["current_generated_proof"] == {
        "accepted_commits": ["e29df2aec", "52e5a1162"],
        "status": "accepted_generated_c6",
    }
    assert row25["boundary_exit_eas"] == [0x40A663, 0x40AAFD]
    assert row25["imported_closure_block_anchor_eas"] == [
        0x40A64B,
        0x40A65D,
        0x40A661,
        0x40AAF1,
        0x40AAFB,
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
    assert row30["operation_id"] == "rhad:route@0x40A978"
    assert row30["current_compiler_support"] == (
        "typed_existing_conditional_plus_indirect"
    )
    assert row30["current_generated_proof"] == {
        "accepted_commits": ["620eeb259", "294bdbb15"],
        "status": "accepted_generated_c6",
    }
    assert row30["boundary_exit_eas"] == [0x40A994, 0x40B071, 0x40B55B]
    assert row30["imported_closure_block_anchor_eas"] == [
        0x40A97A,
        0x40A988,
        0x40A98E,
        0x40A992,
        0x40AD1E,
        0x40AD2C,
        0x40AD32,
        0x40AD36,
    ]
    assert row30["target_rooted_closures"][1]["boundary_exit_eas"] == [0x40B55B]
    assert row30["unavailable_closure_exit_eas"] == []
    assert row31["operation_id"] == "rhad:route@0x40A992"
    assert row31["current_compiler_support"] == (
        "typed_existing_conditional_plus_indirect"
    )
    assert row31["current_generated_proof"] == {
        "accepted_commits": ["ff0941c18", "4afb20ad7"],
        "status": "accepted_generated_c6",
    }
    assert row31["boundary_exit_eas"] == [0x40A5F0, 0x40A9AE]
    assert row31["imported_closure_block_anchor_eas"] == [
        0x40A994,
        0x40A9A2,
        0x40A9A8,
        0x40A9AC,
        0x40B071,
        0x40B07F,
        0x40B085,
        0x40B089,
    ]
    assert row31["unavailable_closure_exit_eas"] == []
    assert row32["operation_id"] == "rhad:route@0x40A9AC"
    assert row32["current_compiler_support"] == (
        "typed_existing_conditional_plus_indirect"
    )
    assert row32["current_generated_proof"] == {
        "accepted_commits": ["2fd07814a", "5723247f9", "89b6a47fa"],
        "status": "accepted_generated_c6",
    }
    assert row32["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
    assert row32["imported_closure_block_anchor_eas"] == [
        0x40A5F0,
        0x40A605,
        0x40A9AE,
        0x40A9D5,
        0x40A9D8,
        0x40A9DC,
    ]
    assert row32["target_rooted_closures"][0][
        "expected_generated_block_anchor_eas"
    ] == [0x40A9AE, 0x40A9D5, 0x40A9D8, 0x40A9DC]
    assert row32["unavailable_closure_exit_eas"] == []
    assert row33["operation_id"] == "rhad:route@0x40A9DC"
    assert row33["current_compiler_support"] == "typed_cmov_selected_indirect"
    assert row33["current_generated_proof"] == {
        "accepted_commits": ["99201719f", "f0e2a8007", "1b29d8a0b"],
        "status": "accepted_generated_c6",
    }
    assert row33["boundary_exit_eas"] == [0x40A61B, 0x40A68C, 0x40B790]
    assert row33["imported_closure_block_anchor_eas"] == [
        0x40A607,
        0x40A615,
        0x40A619,
        0x40A680,
        0x40A68A,
        0x40B6C0,
        0x40B6CA,
        0x40B6D0,
        0x40B6D4,
    ]
    assert row33["unavailable_closure_exit_eas"] == []
    assert row34["operation_id"] == "rhad:route@0x40A9F6"
    assert row34["current_compiler_support"] == (
        "typed_existing_conditional_plus_indirect"
    )
    assert row34["current_generated_proof"] == {
        "accepted_commits": ["f75d38ce6", "1eaedd01b"],
        "status": "accepted_generated_c6",
    }
    assert row34["boundary_exit_eas"] == [
        0x40AA12,
        0x40AD88,
        0x40B0BC,
        0x40B32C,
    ]
    assert row34["imported_closure_block_anchor_eas"] == [
        0x40A9F8,
        0x40AA06,
        0x40AA0C,
        0x40AA10,
        0x40AD6E,
        0x40AD7C,
        0x40AD82,
        0x40AD86,
    ]
    assert row34["unavailable_closure_exit_eas"] == []
    assert row35["operation_id"] == "rhad:route@0x40AA10"
    assert row35["current_compiler_support"] == (
        "typed_existing_conditional_plus_indirect"
    )
    assert row35["current_generated_proof"] == {
        "accepted_commits": ["ef3c74eb7", "67adb36f9"],
        "status": "accepted_generated_c6",
    }
    assert row35["boundary_exit_eas"] == [0x40A5F0]
    assert row35["imported_closure_block_anchor_eas"] == [
        0x40AA12,
        0x40AA20,
        0x40AA26,
        0x40AA2A,
        0x40B0BC,
        0x40B0CA,
        0x40B0D0,
        0x40B0D4,
    ]
    assert row35["unavailable_closure_exit_eas"] == []
    assert row36["operation_id"] == "rhad:route@0x40AA2A"
    assert row36["current_compiler_support"] == (
        "typed_existing_conditional_plus_indirect"
    )
    assert row36["current_generated_proof"] == {
        "accepted_commits": ["0d862a2ff", "d7b921827", "bb90e8626"],
        "status": "accepted_generated_c6",
    }
    assert row36["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
    assert row36["imported_closure_block_anchor_eas"] == [
        0x40A5F0,
        0x40A605,
        0x40AA2C,
        0x40AA35,
        0x40AA57,
        0x40AA5A,
        0x40AA5E,
    ]
    assert row36["unavailable_closure_exit_eas"] == []
    assert row37["operation_id"] == "rhad:route@0x40AA5E"
    assert row37["current_compiler_support"] == "typed_cmov_selected_indirect"
    assert row37["current_generated_proof"] == {
        "accepted_commits": ["65ffe2cee", "aff6b8a33"],
        "status": "accepted_generated_c6",
    }
    assert row37["owned_corridor_instruction_eas"] == [
        0x40AA3B,
        0x40AA49,
        0x40AA4F,
        0x40AA51,
        0x40AA57,
        0x40AA5A,
        0x40AA5C,
        0x40AA5E,
    ]
    assert row37["boundary_exit_eas"] == [0x40A61B, 0x40A68C, 0x40B790]
    assert row37["unavailable_closure_exit_eas"] == []
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
    assert row38["current_compiler_support"] == (
        "typed_existing_conditional_plus_indirect"
    )
    assert row38["current_generated_proof"] == {
        "accepted_commits": [
            "76232a390",
            "52c9e0f87",
            "6c2bff534",
            "b6d0322d4",
            "9312086c4",
            "cffc7ba57",
            "167bb503c",
            "65c6bea52",
        ],
        "status": "accepted_generated_c6",
    }
    assert row38["boundary_exit_eas"] == [
        0x40AA94,
        0x40ADD8,
        0x40B0F2,
        0x40B37C,
    ]
    assert row38["imported_closure_block_anchor_eas"] == [
        0x40AA88,
        0x40AA8E,
        0x40AA92,
        0x40ADBE,
        0x40ADCC,
        0x40ADD2,
        0x40ADD6,
    ]
    assert row38["unavailable_closure_exit_eas"] == []
    assert row39["current_compiler_support"] == (
        "typed_existing_conditional_plus_indirect"
    )
    assert row39["current_generated_proof"] == {
        "accepted_commits": ["cffc7ba57", "167bb503c", "65c6bea52"],
        "status": "accepted_generated_c6",
    }
    assert row39["owned_corridor_instruction_eas"] == [
        0x40AA7A,
        0x40AA80,
        0x40AA86,
        0x40AA88,
        0x40AA8E,
        0x40AA90,
        0x40AA92,
    ]
    assert row39["boundary_exit_eas"] == [0x40A5F0, 0x40AAAE]
    assert row39["imported_closure_block_anchor_eas"] == [
        0x40AAA2,
        0x40AAA8,
        0x40AAAC,
        0x40B0F2,
        0x40B100,
        0x40B106,
        0x40B10A,
    ]
    assert row39["unavailable_closure_exit_eas"] == []
    assert row40["current_compiler_support"] == (
        "typed_existing_conditional_plus_indirect"
    )
    assert row40["current_generated_proof"] == {
        "accepted_commits": ["6a083ec90", "bc6aa9a92", "7f7296027"],
        "status": "accepted_generated_c6",
    }
    assert row40["owned_corridor_instruction_eas"] == [
        0x40AA94,
        0x40AA9A,
        0x40AAA0,
        0x40AAA2,
        0x40AAA8,
        0x40AAAA,
        0x40AAAC,
    ]
    assert row40["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
    assert row40["imported_closure_block_anchor_eas"] == [
        0x40A5F0,
        0x40A605,
        0x40AAAE,
        0x40AAE8,
        0x40AAEB,
        0x40AAEF,
    ]
    assert row40["unavailable_closure_exit_eas"] == []
    assert row52["current_compiler_support"] == (
        "typed_existing_conditional_plus_indirect"
    )
    assert row52["current_generated_proof"] == {
        "accepted_commits": ["31d88d834", "5ae27b590"],
        "status": "accepted_generated_c6",
    }
    assert row52["owned_corridor_instruction_eas"] == [
        0x40AC3D,
        0x40AC42,
        0x40AC48,
        0x40AC4A,
        0x40AC50,
        0x40AC52,
        0x40AC54,
    ]
    assert row52["boundary_exit_eas"] == [0x40A5F0, 0x40AC70]
    assert row52["imported_closure_block_anchor_eas"] == [
        0x40AC56,
        0x40AC64,
        0x40AC6A,
        0x40AC6E,
        0x40B21C,
        0x40B22A,
        0x40B230,
        0x40B234,
    ]
    assert row52["unavailable_closure_exit_eas"] == []
    assert row53["current_compiler_support"] == (
        "typed_existing_conditional_plus_indirect"
    )
    assert row53["current_generated_proof"] == {
        "accepted_commits": ["4d103e464", "6aefe9d66"],
        "status": "accepted_generated_c6",
    }
    assert row53["owned_corridor_instruction_eas"] == [
        0x40AC56,
        0x40AC5C,
        0x40AC62,
        0x40AC64,
        0x40AC6A,
        0x40AC6C,
        0x40AC6E,
    ]
    assert row53["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
    assert row53["imported_closure_block_anchor_eas"] == [
        0x40A5F0,
        0x40A605,
        0x40AC70,
        0x40AC81,
        0x40AC9B,
        0x40ACB3,
        0x40ACBD,
        0x40B56D,
        0x40B58A,
        0x40B596,
    ]
    assert row53["unavailable_closure_exit_eas"] == []
    assert row54["operation_id"] == "rhad:route@0x40ACBD"
    assert row54["current_compiler_support"] == "typed_simple_indirect_jump"
    assert row54["current_generated_proof"] == {
        "accepted_commits": ["61f2f9073", "19745aac8"],
        "status": "accepted_generated_c6",
    }
    assert row54["owned_corridor_instruction_eas"] == [
        0x40AC9B,
        0x40ACB3,
        0x40ACB5,
        0x40ACB7,
        0x40ACBD,
    ]
    assert row54["boundary_exit_eas"] == [0x40B790]
    assert row54["imported_closure_block_anchor_eas"] == [
        0x40B6C0,
        0x40B6CA,
        0x40B6D0,
        0x40B6D4,
    ]
    assert row54["unavailable_closure_exit_eas"] == []
    assert row55["operation_id"] == "rhad:route@0x40ACD7"
    assert row55["current_compiler_support"] == (
        "typed_existing_conditional_plus_indirect"
    )
    assert row55["current_generated_proof"] == {
        "accepted_commits": ["00f77d70f", "ca4618829"],
        "status": "accepted_generated_c6",
    }
    assert row55["owned_corridor_instruction_eas"] == [
        0x40ACBF,
        0x40ACC5,
        0x40ACCB,
        0x40ACCD,
        0x40ACD3,
        0x40ACD5,
        0x40ACD7,
    ]
    assert row55["boundary_exit_eas"] == [0x40A5F0, 0x40ACF3]
    assert row55["imported_closure_block_anchor_eas"] == [
        0x40ACD9,
        0x40ACE7,
        0x40ACED,
        0x40ACF1,
        0x40B26D,
        0x40B27B,
        0x40B281,
        0x40B285,
    ]
    assert row55["unavailable_closure_exit_eas"] == []
    assert row56["operation_id"] == "rhad:route@0x40ACF1"
    assert row56["current_compiler_support"] == (
        "typed_existing_conditional_plus_indirect"
    )
    assert row56["current_generated_proof"] == {
        "accepted_commits": ["b8e2453e6", "19633326b"],
        "status": "accepted_generated_c6",
    }
    assert row56["owned_corridor_instruction_eas"] == [
        0x40ACD9,
        0x40ACDF,
        0x40ACE5,
        0x40ACE7,
        0x40ACED,
        0x40ACEF,
        0x40ACF1,
    ]
    assert row56["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
    assert row56["imported_closure_block_anchor_eas"] == [
        0x40A5F0,
        0x40A605,
        0x40ACF3,
        0x40AD06,
        0x40AD18,
        0x40AD1C,
        0x40B598,
        0x40B5AF,
        0x40B5B5,
    ]
    assert row56["unavailable_closure_exit_eas"] == []
    assert row57["operation_id"] == "rhad:route@0x40AD1C"
    assert row57["current_compiler_support"] == "typed_simple_indirect_jump"
    assert row57["current_generated_proof"] == {
        "accepted_commits": ["b2c469e37", "36dea3978"],
        "status": "accepted_generated_c6",
    }
    assert row57["owned_corridor_instruction_eas"] == [
        0x40AD06,
        0x40AD18,
        0x40AD1A,
        0x40AD1C,
    ]
    assert row57["boundary_exit_eas"] == [0x40B790]
    assert row57["imported_closure_block_anchor_eas"] == [
        0x40B6C0,
        0x40B6CA,
        0x40B6D0,
        0x40B6D4,
    ]
    assert row57["unavailable_closure_exit_eas"] == []
    assert row58["operation_id"] == "rhad:route@0x40AD36"
    assert row58["current_compiler_support"] == (
        "typed_existing_conditional_plus_indirect"
    )
    assert row58["current_generated_proof"] == {
        "accepted_commits": ["14b877f1f", "6ee99227d"],
        "status": "accepted_generated_c6",
    }
    assert row58["owned_corridor_instruction_eas"] == [
        0x40AD1E,
        0x40AD2A,
        0x40AD2C,
        0x40AD32,
        0x40AD34,
        0x40AD36,
    ]
    assert row58["boundary_exit_eas"] == [0x40A5F0, 0x40AD52]
    assert row58["imported_closure_block_anchor_eas"] == [
        0x40AD38,
        0x40AD46,
        0x40AD4C,
        0x40AD50,
        0x40B2DB,
        0x40B2E9,
        0x40B2EF,
        0x40B2F3,
    ]
    assert row58["unavailable_closure_exit_eas"] == []
    assert row59["operation_id"] == "rhad:route@0x40AD50"
    assert row59["current_compiler_support"] == (
        "typed_existing_conditional_plus_indirect"
    )
    assert row59["current_generated_proof"] == {
        "accepted_commits": ["404c49cc7", "0dd17a23f"],
        "status": "accepted_generated_c6",
    }
    assert row59["owned_corridor_instruction_eas"] == [
        0x40AD38,
        0x40AD44,
        0x40AD46,
        0x40AD4C,
        0x40AD4E,
        0x40AD50,
    ]
    assert row59["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
    assert row59["imported_closure_block_anchor_eas"] == [
        0x40A5F0,
        0x40A605,
        0x40AD52,
        0x40AD65,
        0x40AD68,
        0x40AD6C,
    ]
    assert row59["unavailable_closure_exit_eas"] == []
    assert row60["operation_id"] == "rhad:route@0x40AD6C"
    assert row60["current_compiler_support"] == "typed_cmov_selected_indirect"
    assert row60["current_generated_proof"] == {
        "accepted_commits": ["d1b0b92a0", "e91750b95", "1760d5bb1"],
        "status": "accepted_generated_c6",
    }
    assert row60["owned_corridor_instruction_eas"] == [
        0x40AD5D,
        0x40AD5F,
        0x40AD65,
        0x40AD68,
        0x40AD6A,
        0x40AD6C,
    ]
    assert row60["flag_producer_native_ea"] == 0x40AD57
    assert row60["boundary_exit_eas"] == [0x40A61B, 0x40A68C, 0x40B790]
    assert row60["imported_closure_block_anchor_eas"] == [
        0x40A607,
        0x40A615,
        0x40A619,
        0x40A680,
        0x40A68A,
        0x40B6C0,
        0x40B6CA,
        0x40B6D0,
        0x40B6D4,
    ]
    assert row60["unavailable_closure_exit_eas"] == []
    assert row61["operation_id"] == "rhad:route@0x40AD86"
    assert row61["current_compiler_support"] == (
        "typed_existing_conditional_plus_indirect"
    )
    assert row61["current_generated_proof"] == {
        "accepted_commits": ["eb0bd4fd3", "cf077c56b", "b4107ad0e"],
        "status": "accepted_generated_c6",
    }
    assert row61["owned_corridor_instruction_eas"] == [
        0x40AD6E,
        0x40AD7A,
        0x40AD7C,
        0x40AD82,
        0x40AD84,
        0x40AD86,
    ]
    assert row61["flag_producer_native_ea"] == 0x40AD74
    assert row61["boundary_exit_eas"] == [0x40A5F0, 0x40ADA2, 0x40B342]
    assert row61["imported_closure_block_anchor_eas"] == [
        0x40AD88,
        0x40AD96,
        0x40AD9C,
        0x40ADA0,
        0x40B32C,
        0x40B340,
    ]
    assert row61["unavailable_closure_exit_eas"] == []
    assert row62["operation_id"] == "rhad:route@0x40ADA0"
    assert row62["current_compiler_support"] == (
        "typed_existing_conditional_plus_indirect"
    )
    assert row62["current_generated_proof"] == {
        "accepted_commits": ["12f589574", "9a5df9b84"],
        "status": "accepted_generated_c6",
    }
    assert row62["owned_corridor_instruction_eas"] == [
        0x40AD88,
        0x40AD94,
        0x40AD96,
        0x40AD9C,
        0x40AD9E,
        0x40ADA0,
    ]
    assert row62["flag_producer_native_ea"] == 0x40AD8E
    assert row62["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
    assert row62["imported_closure_block_anchor_eas"] == [
        0x40A5F0,
        0x40A605,
        0x40ADA2,
        0x40ADB5,
        0x40ADB8,
        0x40ADBC,
    ]
    assert row62["target_rooted_closures"][0][
        "expected_generated_block_anchor_eas"
    ] == [0x40ADA2, 0x40ADB5, 0x40ADB8, 0x40ADBC]
    assert row62["unavailable_closure_exit_eas"] == []
    assert row63["operation_id"] == "rhad:route@0x40ADBC"
    assert row63["current_compiler_support"] == "typed_cmov_selected_indirect"
    assert row63["current_generated_proof"] == {
        "accepted_commits": ["3d7abe9bb", "fb5e4e9e0"],
        "status": "accepted_generated_c6",
    }
    assert row63["owned_corridor_instruction_eas"] == [
        0x40ADAD,
        0x40ADAF,
        0x40ADB5,
        0x40ADB8,
        0x40ADBA,
        0x40ADBC,
    ]
    assert row63["flag_producer_native_ea"] == 0x40ADA7
    assert row63["boundary_exit_eas"] == [0x40A61B, 0x40A68C, 0x40B790]
    assert row63["imported_closure_block_anchor_eas"] == [
        0x40A607,
        0x40A615,
        0x40A619,
        0x40A680,
        0x40A68A,
        0x40B6C0,
        0x40B6CA,
        0x40B6D0,
        0x40B6D4,
    ]
    assert row63["unavailable_closure_exit_eas"] == []
    assert row64["operation_id"] == "rhad:route@0x40ADD6"
    assert row64["current_compiler_support"] == (
        "typed_existing_conditional_plus_indirect"
    )
    assert row64["current_generated_proof"] == {
        "accepted_commits": ["de9a81a41", "ccca75fed"],
        "status": "accepted_generated_c6",
    }
    assert row64["owned_corridor_instruction_eas"] == [
        0x40ADBE,
        0x40ADC4,
        0x40ADCA,
        0x40ADCC,
        0x40ADD2,
        0x40ADD4,
        0x40ADD6,
    ]
    assert row64["flag_producer_native_ea"] == 0x40ADC4
    assert row64["boundary_exit_eas"] == [
        0x40A5F0,
        0x40ADF2,
        0x40B396,
        0x40B3E5,
    ]
    assert row64["imported_closure_block_anchor_eas"] == [
        0x40ADD8,
        0x40ADE6,
        0x40ADEC,
        0x40ADF0,
        0x40B37C,
        0x40B38A,
        0x40B390,
        0x40B394,
    ]
    assert row64["target_rooted_closures"][0][
        "expected_generated_block_anchor_eas"
    ] == [0x40ADD8, 0x40ADE6, 0x40ADEC, 0x40ADF0]
    assert row64["target_rooted_closures"][1][
        "expected_generated_block_anchor_eas"
    ] == [0x40B37C, 0x40B38A, 0x40B390, 0x40B394]
    assert row64["unavailable_closure_exit_eas"] == []
    assert row65["operation_id"] == "rhad:route@0x40ADF0"
    assert row65["current_compiler_support"] == (
        "typed_existing_conditional_plus_indirect"
    )
    assert row65["current_generated_proof"] == {
        "accepted_commits": ["47a8d719b", "8bf6f12f4", "1d18f5e25"],
        "status": "accepted_generated_c6",
    }
    assert row65["owned_corridor_instruction_eas"] == [
        0x40ADD8,
        0x40ADDE,
        0x40ADE4,
        0x40ADE6,
        0x40ADEC,
        0x40ADEE,
        0x40ADF0,
    ]
    assert row65["source_block_anchor_ea"] == 0x40ADEC
    assert row65["flag_producer_native_ea"] == 0x40ADDE
    assert row65["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
    assert row65["imported_closure_block_anchor_eas"] == [
        0x40A5F0,
        0x40A605,
        0x40ADF2,
        0x40AE05,
        0x40AE08,
        0x40AE18,
    ]
    assert row65["target_rooted_closures"][0][
        "expected_generated_block_anchor_eas"
    ] == [0x40ADF2, 0x40AE05, 0x40AE08, 0x40AE18]
    assert row65["target_rooted_closures"][1][
        "expected_generated_block_anchor_eas"
    ] == [0x40A5F0, 0x40A605]
    assert row65["unavailable_closure_exit_eas"] == []
    assert row66["operation_id"] == "rhad:route@0x40AE18"
    assert row66["current_compiler_support"] == "typed_cmov_selected_indirect"
    assert row66["current_generated_proof"] == {
        "accepted_commits": ["d87a51f62", "b8ec38c4a"],
        "status": "accepted_generated_c6",
    }
    assert row66["owned_corridor_instruction_eas"] == [
        0x40ADFD,
        0x40ADFF,
        0x40AE05,
        0x40AE08,
        0x40AE0A,
        0x40AE18,
    ]
    assert row66["source_block_anchor_ea"] == 0x40ADF2
    assert row66["flag_producer_native_ea"] == 0x40ADF7
    assert row66["boundary_exit_eas"] == [0x40A61B, 0x40A68C, 0x40B790]
    assert row66["imported_closure_block_anchor_eas"] == [
        0x40A607,
        0x40A615,
        0x40A619,
        0x40A680,
        0x40A68A,
        0x40B6C0,
        0x40B6CA,
        0x40B6D0,
        0x40B6D4,
    ]
    assert row66["unavailable_closure_exit_eas"] == []
    assert row67["current_compiler_support"] == "typed_simple_indirect_jump"
    assert row67["current_generated_proof"] == {
        "accepted_commits": ["fb320e8d0", "6ea3a9cb6"],
        "status": "accepted_generated_c6",
    }
    assert row67["boundary_exit_eas"] == [0x40A5F0, 0x40C898]
    assert row67["imported_closure_block_anchor_eas"] == [
        0x40A5CA,
        0x40A5DC,
        0x40A5DF,
        0x40A5E3,
    ]
    assert row67["unavailable_closure_exit_eas"] == []
    assert row68["operation_id"] == row68_artifact.operation_id
    assert row68["current_compiler_support"] == "typed_setcc_indexed_table"
    assert row68["current_generated_proof"] == {
        "accepted_commits": [
            "5cbd276d8",
            "79a5ad4dc",
            "77e02c991",
            "4a0a640f0",
            "bae7580a7",
        ],
        "proof_artifact_identity": row68_artifact.content_identity,
        "status": "accepted_generated_c6",
    }
    assert row68["owned_corridor_instruction_eas"] == [
        0x40AE26,
        0x40AE2E,
        0x40AE31,
        0x40AE34,
        0x40AE3A,
        0x40AE3C,
    ]
    assert row68["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
    assert row68["imported_closure_block_anchor_eas"] == [
        0x40AE3E,
        0x40AE63,
        0x40AE82,
        0x40AE85,
        0x40AE89,
    ]
    assert row68["unavailable_closure_exit_eas"] == []
    assert row69["operation_id"] == "rhad:route@0x40AE89"
    assert row69["current_compiler_support"] == "typed_cmov_selected_indirect"
    assert row69["current_generated_proof"] == {
        "accepted_commits": ["ab22da4b9", "3e46b7135"],
        "status": "accepted_generated_c6",
    }
    assert row69["owned_corridor_instruction_eas"] == [
        0x40AE69,
        0x40AE7A,
        0x40AE7C,
        0x40AE82,
        0x40AE85,
        0x40AE87,
        0x40AE89,
    ]
    assert row69["boundary_exit_eas"] == [0x40A61B, 0x40A68C, 0x40B790]
    assert row69["imported_closure_block_anchor_eas"] == [
        0x40A607,
        0x40A615,
        0x40A619,
        0x40A680,
        0x40A68A,
        0x40B6C0,
        0x40B6CA,
        0x40B6D0,
        0x40B6D4,
    ]
    assert row69["unavailable_closure_exit_eas"] == []
    assert row70["operation_id"] == "rhad:route@0x40AEA3"
    assert row70["current_compiler_support"] == (
        "typed_existing_conditional_plus_indirect"
    )
    assert row70["current_generated_proof"] == {
        "accepted_commits": ["29f7363d1", "1e3f87d89"],
        "status": "accepted_generated_c6",
    }
    assert row70["owned_corridor_instruction_eas"] == [
        0x40AE8B,
        0x40AE91,
        0x40AE97,
        0x40AE99,
        0x40AE9F,
        0x40AEA1,
        0x40AEA3,
    ]
    assert row70["source_block_anchor_ea"] == 0x40AE9F
    assert row70["flag_producer_native_ea"] == 0x40AE91
    assert row70["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
    assert row70["imported_closure_block_anchor_eas"] == [
        0x40A5F0,
        0x40A605,
        0x40AEA5,
        0x40AEC6,
        0x40AEDA,
        0x40AEE4,
        0x40B5B7,
        0x40B5D0,
        0x40B5DC,
    ]
    assert row70["target_rooted_closures"][0][
        "expected_generated_block_anchor_eas"
    ] == [
        0x40AEA5,
        0x40AEC6,
        0x40AEDA,
        0x40AEE4,
        0x40B5B7,
        0x40B5D0,
        0x40B5DC,
    ]
    assert row70["target_rooted_closures"][1][
        "expected_generated_block_anchor_eas"
    ] == [0x40A5F0, 0x40A605]
    assert row70["unavailable_closure_exit_eas"] == []
    assert row71["operation_id"] == "rhad:route@0x40AEE4"
    assert row71["current_compiler_support"] == "typed_simple_indirect_jump"
    assert row71["current_generated_proof"] == {
        "accepted_commits": ["2cc92789b", "fb6d0f1a0"],
        "status": "accepted_generated_c6",
    }
    assert row71["owned_corridor_instruction_eas"] == [
        0x40AEC6,
        0x40AEDA,
        0x40AEDC,
        0x40AEDE,
        0x40AEE4,
    ]
    assert row71["source_block_anchor_ea"] == 0x40AEDA
    assert row71["flag_producer_native_ea"] is None
    assert row71["boundary_exit_eas"] == [0x40B790]
    assert row71["imported_closure_block_anchor_eas"] == [
        0x40B6C0,
        0x40B6CA,
        0x40B6D0,
        0x40B6D4,
    ]
    assert row71["target_rooted_closures"][0][
        "expected_generated_block_anchor_eas"
    ] == [0x40B6C0, 0x40B6CA, 0x40B6D0, 0x40B6D4]
    assert row71["unavailable_closure_exit_eas"] == []
    assert row72["operation_id"] == "rhad:route@0x40AEFE"
    assert row72["current_compiler_support"] == (
        "typed_existing_conditional_plus_indirect"
    )
    assert row72["current_generated_proof"] == {
        "accepted_commits": ["76d431096", "f96104ba5"],
        "status": "accepted_generated_c6",
    }
    assert row72["owned_corridor_instruction_eas"] == [
        0x40AEE6,
        0x40AEEC,
        0x40AEF2,
        0x40AEF4,
        0x40AEFA,
        0x40AEFC,
        0x40AEFE,
    ]
    assert row72["source_block_anchor_ea"] == 0x40AEFA
    assert row72["flag_producer_native_ea"] == 0x40AEEC
    assert row72["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
    assert row72["imported_closure_block_anchor_eas"] == [
        0x40A5F0,
        0x40A605,
        0x40AF00,
        0x40AF1C,
        0x40AF2F,
        0x40AF9D,
        0x40AFBB,
        0x40AFD3,
        0x40AFDD,
        0x40B5DE,
        0x40B5FB,
        0x40B607,
    ]
    assert row72["target_rooted_closures"][0][
        "expected_generated_block_anchor_eas"
    ] == [
        0x40AF00,
        0x40AF1C,
        0x40AF2F,
        0x40AF9D,
        0x40AFBB,
        0x40AFD3,
        0x40AFDD,
        0x40B5DE,
        0x40B5FB,
        0x40B607,
    ]
    assert row72["target_rooted_closures"][1][
        "expected_generated_block_anchor_eas"
    ] == [0x40A5F0, 0x40A605]
    assert row72["unavailable_closure_exit_eas"] == []
    assert row73["operation_id"] == "rhad:route@0x40AFDD"
    assert row73["current_compiler_support"] == "typed_simple_indirect_jump"
    assert row73["current_generated_proof"] == {
        "accepted_commits": ["f07ec5022", "58ec8dde5"],
        "status": "accepted_generated_c6",
    }
    assert row73["owned_corridor_instruction_eas"] == [
        0x40AFBB,
        0x40AFD3,
        0x40AFD5,
        0x40AFD7,
        0x40AFDD,
    ]
    assert row73["source_block_anchor_ea"] == 0x40AFD3
    assert row73["flag_producer_native_ea"] is None
    assert row73["boundary_exit_eas"] == [0x40B790]
    assert row73["imported_closure_block_anchor_eas"] == [
        0x40B6C0,
        0x40B6CA,
        0x40B6D0,
        0x40B6D4,
    ]
    assert row73["target_rooted_closures"][0][
        "expected_generated_block_anchor_eas"
    ] == [0x40B6C0, 0x40B6CA, 0x40B6D0, 0x40B6D4]
    assert row73["unavailable_closure_exit_eas"] == []
    assert row74["operation_id"] == "rhad:route@0x40AFF7"
    assert row74["current_compiler_support"] == (
        "typed_existing_conditional_plus_indirect"
    )
    assert row74["current_generated_proof"] == {
        "accepted_commits": ["665cc23c0", "83325183a"],
        "status": "accepted_generated_c6",
    }
    assert row74["owned_corridor_instruction_eas"] == [
        0x40AFDF,
        0x40AFE5,
        0x40AFEB,
        0x40AFED,
        0x40AFF3,
        0x40AFF5,
        0x40AFF7,
    ]
    assert row74["source_block_anchor_ea"] == 0x40AFF3
    assert row74["flag_producer_native_ea"] == 0x40AFE5
    assert row74["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
    assert row74["imported_closure_block_anchor_eas"] == [
        0x40A5F0,
        0x40A605,
        0x40AFF9,
        0x40B00C,
        0x40B01E,
        0x40B022,
        0x40B609,
        0x40B620,
        0x40B626,
    ]
    assert row74["target_rooted_closures"][0][
        "expected_generated_block_anchor_eas"
    ] == [
        0x40AFF9,
        0x40B00C,
        0x40B01E,
        0x40B022,
        0x40B609,
        0x40B620,
        0x40B626,
    ]
    assert row74["target_rooted_closures"][1][
        "expected_generated_block_anchor_eas"
    ] == [0x40A5F0, 0x40A605]
    assert row74["unavailable_closure_exit_eas"] == []
    assert row75["operation_id"] == "rhad:route@0x40B022"
    assert row75["current_compiler_support"] == "typed_simple_indirect_jump"
    assert row75["current_generated_proof"] == {
        "accepted_commits": ["0e7fa0452", "5c5501604"],
        "status": "accepted_generated_c6",
    }
    assert row75["owned_corridor_instruction_eas"] == [
        0x40B00C,
        0x40B01E,
        0x40B020,
        0x40B022,
    ]
    assert row75["source_block_anchor_ea"] == 0x40B01E
    assert row75["flag_producer_native_ea"] is None
    assert row75["boundary_exit_eas"] == [0x40B790]
    assert row75["imported_closure_block_anchor_eas"] == [
        0x40B6C0,
        0x40B6CA,
        0x40B6D0,
        0x40B6D4,
    ]
    assert row75["unavailable_closure_exit_eas"] == []
    assert row76["operation_id"] == "rhad:route@0x40B03C"
    assert row76["current_compiler_support"] == (
        "typed_existing_conditional_plus_indirect"
    )
    assert row76["current_generated_proof"] == {
        "accepted_commits": ["fe16d3911", "e04ef319c"],
        "status": "accepted_generated_c6",
    }
    assert row76["owned_corridor_instruction_eas"] == [
        0x40B024,
        0x40B02A,
        0x40B030,
        0x40B032,
        0x40B038,
        0x40B03A,
        0x40B03C,
    ]
    assert row76["source_block_anchor_ea"] == 0x40B038
    assert row76["flag_producer_native_ea"] == 0x40B02A
    assert row76["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
    assert row76["imported_closure_block_anchor_eas"] == [
        0x40A5F0,
        0x40A605,
        0x40B03E,
        0x40B059,
        0x40B06B,
        0x40B06F,
        0x40B628,
        0x40B63F,
        0x40B645,
    ]
    assert row76["target_rooted_closures"][0][
        "expected_generated_block_anchor_eas"
    ] == [
        0x40B03E,
        0x40B059,
        0x40B06B,
        0x40B06F,
        0x40B628,
        0x40B63F,
        0x40B645,
    ]
    assert row76["target_rooted_closures"][1][
        "expected_generated_block_anchor_eas"
    ] == [0x40A5F0, 0x40A605]
    assert row76["unavailable_closure_exit_eas"] == []
    assert row77["operation_id"] == "rhad:route@0x40B06F"
    assert row77["current_compiler_support"] == "typed_simple_indirect_jump"
    assert row77["current_generated_proof"] == {
        "accepted_commits": ["05e03eccc", "b34258975"],
        "status": "accepted_generated_c6",
    }
    assert row77["owned_corridor_instruction_eas"] == [
        0x40B059,
        0x40B06B,
        0x40B06D,
        0x40B06F,
    ]
    assert row77["source_block_anchor_ea"] == 0x40B06B
    assert row77["flag_producer_native_ea"] is None
    assert row77["boundary_exit_eas"] == [0x40B790]
    assert row77["imported_closure_block_anchor_eas"] == [
        0x40B6C0,
        0x40B6CA,
        0x40B6D0,
        0x40B6D4,
    ]
    assert row77["unavailable_closure_exit_eas"] == []
    assert row78["operation_id"] == "rhad:route@0x40B089"
    assert row78["current_compiler_support"] == (
        "typed_existing_conditional_plus_indirect"
    )
    assert row78["current_generated_proof"] == {
        "accepted_commits": ["3e8bff3ae", "941e9dc24", "f562849db"],
        "status": "accepted_generated_c6",
    }
    assert row78["owned_corridor_instruction_eas"] == [
        0x40B071,
        0x40B077,
        0x40B07D,
        0x40B07F,
        0x40B085,
        0x40B087,
        0x40B089,
    ]
    assert row78["source_block_anchor_ea"] == 0x40B085
    assert row78["flag_producer_native_ea"] == 0x40B077
    assert row78["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
    assert row78["imported_closure_block_anchor_eas"] == [
        0x40A5F0,
        0x40A605,
        0x40B08B,
        0x40B094,
        0x40B0B3,
        0x40B0B6,
        0x40B0BA,
    ]
    assert row78["unavailable_closure_exit_eas"] == []
    assert row79["operation_id"] == "rhad:route@0x40B0BA"
    assert row79["current_compiler_support"] == "typed_cmov_selected_indirect"
    assert row79["current_generated_proof"] == {
        "accepted_commits": ["cd552ef57", "3fa7cb9c2"],
        "status": "accepted_generated_c6",
    }
    assert row79["owned_corridor_instruction_eas"] == [
        0x40B09A,
        0x40B0AB,
        0x40B0AD,
        0x40B0B3,
        0x40B0B6,
        0x40B0B8,
        0x40B0BA,
    ]
    assert row79["source_block_anchor_ea"] == 0x40B094
    assert row79["flag_producer_native_ea"] == 0x40B0A5
    assert row79["boundary_exit_eas"] == [0x40A61B, 0x40A68C, 0x40B790]
    assert row79["imported_closure_block_anchor_eas"] == [
        0x40A607,
        0x40A615,
        0x40A619,
        0x40A680,
        0x40A68A,
        0x40B6C0,
        0x40B6CA,
        0x40B6D0,
        0x40B6D4,
    ]
    assert row79["unavailable_closure_exit_eas"] == []
    assert row80["operation_id"] == "rhad:route@0x40B0D4"
    assert row80["current_compiler_support"] == (
        "typed_existing_conditional_plus_indirect"
    )
    assert row80["current_generated_proof"] == {
        "accepted_commits": ["51de20001", "0caad2676"],
        "status": "accepted_generated_c6",
    }
    assert row80["owned_corridor_instruction_eas"] == [
        0x40B0BC,
        0x40B0C2,
        0x40B0C8,
        0x40B0CA,
        0x40B0D0,
        0x40B0D2,
        0x40B0D4,
    ]
    assert row80["source_block_anchor_ea"] == 0x40B0D0
    assert row80["flag_producer_native_ea"] == 0x40B0C2
    assert row80["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
    assert row80["imported_closure_block_anchor_eas"] == [
        0x40A5F0,
        0x40A605,
        0x40B0D6,
        0x40B0F0,
    ]
    assert row80["unavailable_closure_exit_eas"] == []
    assert row81["operation_id"] == "rhad:route@0x40B0F0"
    assert row81["current_compiler_support"] == "typed_cmov_selected_indirect"
    assert row81["current_generated_proof"] == {
        "accepted_commits": ["0cbdde446", "cb9a70d00", "5d88a6dd6"],
        "status": "accepted_generated_c6",
    }
    assert row81["owned_corridor_instruction_eas"] == [
        0x40B0DB,
        0x40B0E1,
        0x40B0E3,
        0x40B0E9,
        0x40B0EC,
        0x40B0EE,
        0x40B0F0,
    ]
    assert row81["source_block_anchor_ea"] == 0x40B0D6
    assert row81["flag_producer_native_ea"] == 0x40B0DB
    assert row81["boundary_exit_eas"] == [0x40A61B, 0x40A68C, 0x40B790]
    assert row81["imported_closure_block_anchor_eas"] == [
        0x40A607,
        0x40A615,
        0x40A619,
        0x40A680,
        0x40A68A,
        0x40B6C0,
        0x40B6CA,
        0x40B6D0,
        0x40B6D4,
    ]
    assert row81["unavailable_closure_exit_eas"] == []
    assert row82["operation_id"] == "rhad:route@0x40B10A"
    assert row82["current_compiler_support"] == (
        "typed_existing_conditional_plus_indirect"
    )
    assert row82["current_generated_proof"] == {
        "accepted_commits": ["5ec600932", "bc100d02c", "b85939d65"],
        "status": "accepted_generated_c6",
    }
    assert row82["owned_corridor_instruction_eas"] == [
        0x40B0F2,
        0x40B0F8,
        0x40B0FE,
        0x40B100,
        0x40B106,
        0x40B108,
        0x40B10A,
    ]
    assert row82["source_block_anchor_ea"] == 0x40B106
    assert row82["flag_producer_native_ea"] == 0x40B0F8
    assert row82["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
    assert row82["imported_closure_block_anchor_eas"] == [
        0x40A5F0,
        0x40A605,
        0x40B10C,
        0x40B11A,
        0x40B121,
        0x40B147,
    ]
    assert row82["unavailable_closure_exit_eas"] == []
    assert row83["operation_id"] == "rhad:route@0x40B147"
    assert row83["current_compiler_support"] == "typed_cmov_selected_indirect"
    assert row83["current_generated_proof"] == {
        "accepted_commits": ["9dd7bba29", "1a690346d", "f9f32034d"],
        "status": "accepted_generated_c6",
    }
    assert row83["owned_corridor_instruction_eas"] == [
        0x40B127,
        0x40B132,
        0x40B138,
        0x40B13A,
        0x40B140,
        0x40B143,
        0x40B145,
        0x40B147,
    ]
    assert row83["source_block_anchor_ea"] == 0x40B121
    assert row83["flag_producer_native_ea"] == 0x40B132
    assert row83["boundary_exit_eas"] == [0x40A61B, 0x40A68C, 0x40B790]
    assert row83["imported_closure_block_anchor_eas"] == [
        0x40A607,
        0x40A615,
        0x40A619,
        0x40A680,
        0x40A68A,
        0x40B6C0,
        0x40B6CA,
        0x40B6D0,
        0x40B6D4,
    ]
    assert row83["unavailable_closure_exit_eas"] == []
    assert row84["operation_id"] == "rhad:route@0x40B161"
    assert row84["current_compiler_support"] == (
        "typed_existing_conditional_plus_indirect"
    )
    assert row84["current_generated_proof"] == {
        "accepted_commits": ["1274c1014", "3c1da42ae", "ecbea0387"],
        "status": "accepted_generated_c6",
    }
    assert row84["owned_corridor_instruction_eas"] == [
        0x40B149,
        0x40B14F,
        0x40B155,
        0x40B157,
        0x40B15D,
        0x40B15F,
        0x40B161,
    ]
    assert row84["source_block_anchor_ea"] == 0x40B15D
    assert row84["flag_producer_native_ea"] == 0x40B14F
    assert row84["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
    assert row84["imported_closure_block_anchor_eas"] == [
        0x40A5F0,
        0x40A605,
        0x40B163,
        0x40B17D,
    ]
    assert row84["unavailable_closure_exit_eas"] == []
    assert row85["operation_id"] == "rhad:route@0x40B17D"
    assert row85["current_compiler_support"] == "typed_cmov_selected_indirect"
    assert row85["current_generated_proof"] == {
        "accepted_commits": ["c33f22767", "d9938c5eb", "df1e02cc4"],
        "status": "accepted_generated_c6",
    }
    assert row85["owned_corridor_instruction_eas"] == [
        0x40B168,
        0x40B16E,
        0x40B170,
        0x40B176,
        0x40B179,
        0x40B17B,
        0x40B17D,
    ]
    assert row85["source_block_anchor_ea"] == 0x40B163
    assert row85["flag_producer_native_ea"] == 0x40B168
    assert row85["boundary_exit_eas"] == [0x40A61B, 0x40A68C, 0x40B790]
    assert row85["imported_closure_block_anchor_eas"] == [
        0x40A607,
        0x40A615,
        0x40A619,
        0x40A680,
        0x40A68A,
        0x40B6C0,
        0x40B6CA,
        0x40B6D0,
        0x40B6D4,
    ]
    assert row85["unavailable_closure_exit_eas"] == []
    assert row86["operation_id"] == "rhad:route@0x40B197"
    assert row86["current_compiler_support"] == (
        "typed_existing_conditional_plus_indirect"
    )
    assert row86["current_generated_proof"] == {
        "accepted_commits": ["677dd2ee7", "da8366da3", "40e6327c5"],
        "status": "accepted_generated_c6",
    }
    assert row86["owned_corridor_instruction_eas"] == [
        0x40B17F,
        0x40B185,
        0x40B18B,
        0x40B18D,
        0x40B193,
        0x40B195,
        0x40B197,
    ]
    assert row86["source_block_anchor_ea"] == 0x40B193
    assert row86["flag_producer_native_ea"] == 0x40B185
    assert row86["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
    assert row86["imported_closure_block_anchor_eas"] == [
        0x40A5F0,
        0x40A605,
        0x40B199,
        0x40B1B6,
        0x40B1CA,
        0x40B1CE,
        0x40B647,
        0x40B660,
        0x40B666,
    ]
    assert row86["unavailable_closure_exit_eas"] == []
    assert row87["operation_id"] == "rhad:route@0x40B1CE"
    assert row87["current_compiler_support"] == "typed_simple_indirect_jump"
    assert row87["current_generated_proof"] == {
        "accepted_commits": ["d550d3fd0", "58d06984e"],
        "status": "accepted_generated_c6",
    }
    assert row87["owned_corridor_instruction_eas"] == [
        0x40B1B6,
        0x40B1CA,
        0x40B1CC,
        0x40B1CE,
    ]
    assert row87["source_block_anchor_ea"] == 0x40B1CA
    assert row87["flag_producer_native_ea"] is None
    assert row87["boundary_exit_eas"] == [0x40B790]
    assert row87["imported_closure_block_anchor_eas"] == [
        0x40B6C0,
        0x40B6CA,
        0x40B6D0,
        0x40B6D4,
    ]
    assert row87["unavailable_closure_exit_eas"] == []
    assert row88["operation_id"] == "rhad:route@0x40B1E8"
    assert row88["current_compiler_support"] == (
        "typed_existing_conditional_plus_indirect"
    )
    assert row88["current_generated_proof"] == {
        "accepted_commits": ["fc47af771", "79df98344", "caf267b99"],
        "status": "accepted_generated_c6",
    }
    assert row88["owned_corridor_instruction_eas"] == [
        0x40B1D0,
        0x40B1D6,
        0x40B1DC,
        0x40B1DE,
        0x40B1E4,
        0x40B1E6,
        0x40B1E8,
    ]
    assert row88["source_block_anchor_ea"] == 0x40B1E4
    assert row88["flag_producer_native_ea"] == 0x40B1D6
    assert row88["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
    assert row88["imported_closure_block_anchor_eas"] == [
        0x40A5F0,
        0x40A605,
        0x40B1EA,
        0x40B1F4,
        0x40B21A,
    ]
    assert row88["unavailable_closure_exit_eas"] == []
    assert row89["operation_id"] == "rhad:route@0x40B21A"
    assert row89["current_compiler_support"] == "typed_cmov_selected_indirect"
    assert row89["current_generated_proof"] == {
        "accepted_commits": ["cf4ed68a9", "6528f89b7", "2df92cff1"],
        "status": "accepted_generated_c6",
    }
    assert row89["owned_corridor_instruction_eas"] == [
        0x40B1FA,
        0x40B205,
        0x40B20B,
        0x40B20D,
        0x40B213,
        0x40B216,
        0x40B218,
        0x40B21A,
    ]
    assert row89["source_block_anchor_ea"] == 0x40B1F4
    assert row89["flag_producer_native_ea"] == 0x40B205
    assert row89["boundary_exit_eas"] == [0x40A61B, 0x40A68C, 0x40B790]
    assert row89["imported_closure_block_anchor_eas"] == [
        0x40A607,
        0x40A615,
        0x40A619,
        0x40A680,
        0x40A68A,
        0x40B6C0,
        0x40B6CA,
        0x40B6D0,
        0x40B6D4,
    ]
    assert row89["unavailable_closure_exit_eas"] == []
    assert row96["operation_id"] == row96_artifact.operation_id
    assert row96["current_compiler_support"] == "typed_setcc_indexed_table"
    assert row96["current_generated_proof"] == {
        "accepted_commits": ["518467c9f", "749f3db59", "c90b88543"],
        "proof_artifact_identity": row96_artifact.content_identity,
        "status": "accepted_generated_c6",
    }
    assert row97["operation_id"] == "rhad:route@0x40B37A"
    assert row97["current_compiler_support"] == "typed_cmov_selected_indirect"
    assert row97["current_generated_proof"] == {
        "accepted_commits": ["9e648564f", "9bc350b73", "850518a72"],
        "status": "accepted_generated_c6",
    }
    assert row98["operation_id"] == "rhad:route@0x40B394"
    assert row98["current_compiler_support"] == (
        "typed_existing_conditional_plus_indirect"
    )
    assert row98["current_generated_proof"] == {
        "accepted_commits": ["c4551f857", "b1ee2cfd7", "47fae218d"],
        "status": "accepted_generated_c6",
    }


def test_indirect_jump_coverage_summary_matches_committed_acceptance_prefix() -> None:
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
    cmov = next(
        row
        for row in summary["variants"]
        if row["operation_variant"] == "cmov_selected_indirect"
    )
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

    assert summary["accepted_code_sha"] == ("47fae218d2aa69c5f07c49df62a972ddbeb405f8")
    accepted_operation_ids = summary["accepted_receipt_operation_ids"]
    compiled_operation_ids = [operation.operation_id for operation in batch.operations]
    assert len(accepted_operation_ids) == 94
    assert accepted_operation_ids[-1] == "rhad:route@0x40B394"
    assert (
        accepted_operation_ids == compiled_operation_ids[: len(accepted_operation_ids)]
    )
    assert cmov == {
        "operation_variant": "cmov_selected_indirect",
        "total_reference_operations": 39,
        "compiler_supported_operations": 39,
        "compiled_operation_instances": 14,
        "vertically_proved_operations": 14,
        "accepted_receipt_operations": 14,
        "earliest_unproved_reference_order": 0,
        "earliest_unproved_operation_id": "rhad:route@0x40A5E3",
        "first_missing_typed_obligation": (
            "instantiate existing RhadConditionalRoute vocabulary with exact "
            "per-operation evidence and dependency closure"
        ),
    }
    assert simple == {
        "operation_variant": "simple_indirect_jump",
        "total_reference_operations": 64,
        "compiler_supported_operations": 64,
        "compiled_operation_instances": 23,
        "vertically_proved_operations": 23,
        "accepted_receipt_operations": 23,
        "earliest_unproved_reference_order": 103,
        "earliest_unproved_operation_id": "rhad:route@0x40B4EE",
        "first_missing_typed_obligation": (
            "instantiate the proved RhadDirectRoute vocabulary with exact "
            "per-operation native-body proof and dependency closure"
        ),
    }
    assert existing == {
        "operation_variant": "existing_conditional_plus_indirect",
        "total_reference_operations": 117,
        "compiler_supported_operations": 117,
        "compiled_operation_instances": 53,
        "vertically_proved_operations": 53,
        "accepted_receipt_operations": 53,
        "earliest_unproved_reference_order": 99,
        "earliest_unproved_operation_id": "rhad:route@0x40B3AE",
        "first_missing_typed_obligation": (
            "instantiate the proved RhadExistingConditionalRoute vocabulary with "
            "exact per-operation native-body proof and dependency closure"
        ),
    }
    assert setcc == {
        "operation_variant": "setcc_indexed_table",
        "total_reference_operations": 8,
        "compiler_supported_operations": 8,
        "compiled_operation_instances": 4,
        "vertically_proved_operations": 4,
        "accepted_receipt_operations": 4,
        "earliest_unproved_reference_order": 126,
        "earliest_unproved_operation_id": "rhad:route@0x40B7F4",
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
