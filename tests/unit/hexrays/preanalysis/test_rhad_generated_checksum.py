from __future__ import annotations

import ast
import inspect
import json

import d810.manager.rhad_generated_checksum as generated_reference
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
from tests.native_preanalysis import make_native_key


def _native_key():
    return make_native_key(
        input_identity=(
            "sha256:2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c"
        ),
        function_rva=0xA560,
    )


def test_checksum_producer_compiles_four_serial_free_reference_shapes() -> None:
    plan = build_rhad_generated_reference_plan(
        native_key=_native_key(),
        evidence_generation=7,
    )

    operation = plan.operation("rhad:route@0x40A605")
    assert plan.plan_id.endswith("rhad-generated-reference@0x40A560:g7")
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
    assert len(IMPORTED_BLOCK_IDS) == 40
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
    )
    assert tuple(operation.operation_id for operation in plan.operations) == (
        "rhad:route@0x40A605",
        "route:rhad-direct@0x40A619",
        "route:rhad-direct@0x40A68A",
        "rhad:route@0x40A6A4",
        "route:rhad-direct@0x40A74A",
        "rhad:route@0x40A764",
        "rhad:route@0x40A77C",
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
    operation_topology = direct_sources | {
        selected.source_block_id,
        selected_envelope.selected_value_block_id,
        selected_envelope.join_block_id,
        fourth_existing.source_block_id,
        fourth_existing_envelope.selected_value_block_id,
        fourth_existing_envelope.join_block_id,
        fourth.source_block_id,
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
    assert BOUNDARY_EXIT_EAS == (
        0x40A633,
        0x40A794,
        0x40A9A0,
        0x40AD6E,
        0x40AEE6,
        0x40B1D0,
        0x40B790,
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
    assert (
        reference_batch_for_native_key(
            make_native_key(
                input_identity=_native_key().input_identity,
                function_rva=0xA561,
            )
        )
        is None
    )


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
