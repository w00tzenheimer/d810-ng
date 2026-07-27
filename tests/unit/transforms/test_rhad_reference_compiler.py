"""Pure compiler contract for the first Rhad GENERATED checksum route."""

from __future__ import annotations

from dataclasses import replace
import importlib
import importlib.util
import json

import pytest

from d810.core.semantic_route_oracle import RouteOracleRun, SemanticTransferKind
from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.ir.semantics import PredicateKind
from d810.transforms.fragment_plan import (
    FragmentBlock,
    FragmentBlockMaterialization,
    FragmentBlockRole,
    FragmentEdge,
    FragmentNativeBody,
    FragmentOperation,
    FragmentPlan,
    FragmentPublicationPurpose,
    FragmentWorkItemScope,
)
from tests.native_preanalysis import make_native_key


INPUT_SHA256 = "2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c"
NATIVE_KEY = make_native_key(
    input_identity=f"sha256:{INPUT_SHA256}",
    function_rva=0x40A560,
)
IMPORTED_RANGES = (
    (0x40A607, 0x40A615),
    (0x40A615, 0x40A61B),
    (0x40A619, 0x40A61B),
    (0x40A680, 0x40A68C),
    (0x40A68A, 0x40A68C),
    (0x40B6C0, 0x40B6CA),
    (0x40B6CA, 0x40B6D0),
    (0x40B6D0, 0x40B6D6),
    (0x40B6D4, 0x40B6D6),
)
IMPORTED_BLOCK_IDS = tuple(f"native@0x{start_ea:X}" for start_ea, _ in IMPORTED_RANGES)
BOUNDARY_EXIT_EAS = (0x40A61B, 0x40A68C, 0x40B790)
DIRECT_IMPORTED_RANGES = (
    (0x40A61B, 0x40A62D),
    (0x40A62D, 0x40A633),
    (0x40A631, 0x40A633),
    (0x40A740, 0x40A74C),
    (0x40A74A, 0x40A74C),
)
DIRECT_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}" for start_ea, _ in DIRECT_IMPORTED_RANGES
)
COMBINED_IMPORTED_BLOCK_IDS = IMPORTED_BLOCK_IDS + DIRECT_IMPORTED_BLOCK_IDS
COMBINED_BOUNDARY_EXIT_EAS = (0x40A633, 0x40A68C, 0x40A74C, 0x40B790)


def _compiler_module():
    module_name = "d810.transforms.rhad_reference_compiler"
    assert importlib.util.find_spec(module_name) is not None, (
        "the pure Rhad reference compiler is not implemented"
    )
    return importlib.import_module(module_name)


def _identity(
    start_ea: int,
    end_ea: int,
    *exact_instruction_eas: int,
) -> StableBlockIdentity:
    return StableBlockIdentity.from_intervals(
        (NativeEaInterval(start_ea, end_ea),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(exact_instruction_eas or (start_ea,)),
    )


def _reference_run() -> RouteOracleRun:
    return RouteOracleRun(
        run_id="rhad-a560-generated-checksum",
        function_ea=0x40A560,
        fixture_sha256=INPUT_SHA256,
        reference_binary_sha256="1" * 64,
        candidate_binary_sha256=INPUT_SHA256,
        reference_commit="21b0d4783703bc4fb6910cfae51d92cd683d2c65",
        runtime_image="d810-idapro-9.3-test-runtime:py313-v1",
        runtime_image_id="sha256:360f91d9d4ac",
        cache_disabled=True,
    )


def _base_plan() -> FragmentPlan:
    source_identity = _identity(
        0x40A5F0,
        0x40A607,
        0x40A5F0,
        0x40A5F6,
        0x40A5FE,
        0x40A601,
        0x40A605,
    )
    source_original = FragmentBlock(
        block_id="native-original@0x40A5F0",
        role=FragmentBlockRole.ORIGINAL,
        materialization=FragmentBlockMaterialization.REUSE_PUBLISHED,
        semantic_anchor_ea=0x40A5F0,
        stable_identity=source_identity,
    )
    source_replacement = FragmentBlock(
        block_id="native@0x40A5F0",
        role=FragmentBlockRole.REPLACEMENT,
        materialization=FragmentBlockMaterialization.CLONE_PUBLISHED,
        semantic_anchor_ea=0x40A5F0,
        stable_identity=source_identity,
        replaces_block_id=source_original.block_id,
    )
    selected_value = FragmentBlock(
        block_id="native@0x40A5FE",
        role=FragmentBlockRole.EXTERNAL,
        materialization=FragmentBlockMaterialization.REUSE_PUBLISHED,
        semantic_anchor_ea=0x40A5FE,
        stable_identity=_identity(0x40A5FE, 0x40A601, 0x40A5FE),
    )
    join = FragmentBlock(
        block_id="native@0x40A601",
        role=FragmentBlockRole.EXTERNAL,
        materialization=FragmentBlockMaterialization.REUSE_PUBLISHED,
        semantic_anchor_ea=0x40A601,
        stable_identity=_identity(0x40A601, 0x40A607, 0x40A601, 0x40A605),
    )
    body_id = "rhad-a560-generated-native-body"
    imported = tuple(
        FragmentBlock(
            block_id=block_id,
            role=FragmentBlockRole.IMPORTED,
            materialization=FragmentBlockMaterialization.IMPORT_NATIVE,
            semantic_anchor_ea=start_ea,
            stable_identity=_identity(start_ea, end_ea, start_ea),
            native_body_id=body_id,
        )
        for block_id, (start_ea, end_ea) in zip(
            IMPORTED_BLOCK_IDS,
            IMPORTED_RANGES,
            strict=True,
        )
    )
    return FragmentPlan(
        plan_id="rhad-a560-generated-base",
        atomic_group_id="rhad-a560-generated-base:g1",
        publication_purpose=FragmentPublicationPurpose.FRONTEND_NORMALIZATION,
        native_key=NATIVE_KEY,
        blocks=(source_original, source_replacement, selected_value, join, *imported),
        roots=(source_replacement.block_id,),
        owned_originals=(source_original.block_id,),
        prohibited_dispatcher_blocks=(),
        operations=(
            FragmentOperation(
                operation_id="placeholder@0x40A605",
                source_block_id=source_replacement.block_id,
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.DIRECT,
                        target_block_id="native@0x40A607",
                    ),
                ),
            ),
        ),
        work_item_scope=FragmentWorkItemScope(
            work_item_id="rhad-generated-checksum@0x40A605:g1",
            selected_obligation_ids=("rhad:route@0x40A605",),
            remaining_obligation_ids=(),
            unreachable_obligation_ids=(),
        ),
        native_bodies=(
            FragmentNativeBody(
                body_id=body_id,
                block_ids=IMPORTED_BLOCK_IDS,
                entry_block_ids=("native@0x40A607", "native@0x40B6C0"),
                terminal_block_ids=IMPORTED_BLOCK_IDS,
                native_ranges=(
                    NativeEaInterval(0x40A607, 0x40A61B),
                    NativeEaInterval(0x40A680, 0x40A68C),
                    NativeEaInterval(0x40B6C0, 0x40B6D6),
                ),
                proof_ids=("native-body@0x40A605",),
            ),
        ),
    )


def _ledger():
    compiler = _compiler_module()
    route = compiler.RhadConditionalRoute(
        operation_id="rhad:route@0x40A605",
        source_block_id="native@0x40A5F0",
        transfer_ea=0x40A605,
        predicate_anchor_ea=0x40A5F6,
        normalization_start_ea=0x40A5F6,
        condition_producer_ea=0x40A5F0,
        conditional_select_ea=0x40A5FE,
        selected_value_block_id="native@0x40A5FE",
        join_block_id="native@0x40A601",
        observed_predicate_kind=PredicateKind.SGE,
        predicate_kind=PredicateKind.SLT,
        true_target_block_id="native@0x40B6C0",
        false_target_block_id="native@0x40A607",
        comparison_constant=0x0BB2D365,
        owned_corridor_instruction_eas=(
            0x40A5F0,
            0x40A5F6,
            0x40A5FE,
            0x40A601,
            0x40A605,
        ),
        imported_closure_block_ids=IMPORTED_BLOCK_IDS,
        boundary_exit_eas=BOUNDARY_EXIT_EAS,
        flag_corridor_id="flags-intact@0x40A5F0",
        phase=compiler.RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    )
    return compiler.RhadReferenceLedger(
        ledger_id="rhad-generated-reference@0x40A560:g1",
        function_ea=0x40A560,
        evidence_generation=1,
        base_plan=_base_plan(),
        reference_oracle_run=_reference_run(),
        operations=(route,),
        required_boundary_exit_eas=BOUNDARY_EXIT_EAS,
        reference_provenance={
            "reference_commit": "21b0d4783703bc4fb6910cfae51d92cd683d2c65",
            "operation_shape": "cmovl_selected_indirect_transfer",
        },
    )


def _mixed_ledger():
    compiler = _compiler_module()
    base = _base_plan()
    body_id = base.native_bodies[0].body_id
    direct_imported = tuple(
        FragmentBlock(
            block_id=block_id,
            role=FragmentBlockRole.IMPORTED,
            materialization=FragmentBlockMaterialization.IMPORT_NATIVE,
            semantic_anchor_ea=start_ea,
            stable_identity=_identity(start_ea, end_ea, start_ea),
            native_body_id=body_id,
        )
        for block_id, (start_ea, end_ea) in zip(
            DIRECT_IMPORTED_BLOCK_IDS,
            DIRECT_IMPORTED_RANGES,
            strict=True,
        )
    )
    placeholder_direct = FragmentOperation(
        operation_id="placeholder@0x40A619",
        source_block_id="native@0x40A619",
        edges=(
            FragmentEdge(
                role=SemanticEdgeRole.DIRECT,
                target_block_id="native@0x40A61B",
            ),
        ),
    )
    base = replace(
        base,
        blocks=base.blocks + direct_imported,
        operations=base.operations + (placeholder_direct,),
        work_item_scope=replace(
            base.work_item_scope,
            selected_obligation_ids=(
                "rhad:route@0x40A605",
                "route:rhad-direct@0x40A619",
            ),
        ),
        native_bodies=(
            FragmentNativeBody(
                body_id=body_id,
                block_ids=COMBINED_IMPORTED_BLOCK_IDS,
                entry_block_ids=(
                    "native@0x40A607",
                    "native@0x40A619",
                    "native@0x40B6C0",
                    "native@0x40A61B",
                    "native@0x40A631",
                    "native@0x40A74A",
                ),
                terminal_block_ids=tuple(
                    block_id
                    for block_id in COMBINED_IMPORTED_BLOCK_IDS
                    if block_id != "native@0x40A619"
                ),
                native_ranges=(
                    NativeEaInterval(0x40A607, 0x40A61B),
                    NativeEaInterval(0x40A61B, 0x40A633),
                    NativeEaInterval(0x40A680, 0x40A68C),
                    NativeEaInterval(0x40A740, 0x40A74C),
                    NativeEaInterval(0x40B6C0, 0x40B6D6),
                ),
                proof_ids=(
                    "native-body@0x40A605",
                    "route:rhad-direct@0x40A619",
                ),
            ),
        ),
    )
    accepted_route = _ledger().operations[0]
    direct_route = compiler.RhadDirectRoute(
        operation_id="route:rhad-direct@0x40A619",
        source_block_id="native@0x40A619",
        transfer_ea=0x40A619,
        owner_anchor_ea=0x40A619,
        direct_target_block_id="native@0x40A61B",
        owned_corridor_instruction_eas=(
            0x40A607,
            0x40A615,
            0x40A617,
            0x40A619,
        ),
        imported_closure_block_ids=DIRECT_IMPORTED_BLOCK_IDS,
        boundary_exit_eas=(0x40A633, 0x40A74C),
        phase=compiler.RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
        depends_on=(accepted_route.operation_id,),
    )
    return compiler.RhadReferenceLedger(
        ledger_id="rhad-generated-reference@0x40A560:g1",
        function_ea=0x40A560,
        evidence_generation=1,
        base_plan=base,
        reference_oracle_run=_reference_run(),
        operations=(accepted_route, direct_route),
        required_boundary_exit_eas=COMBINED_BOUNDARY_EXIT_EAS,
        reference_provenance={
            "reference_commit": "21b0d4783703bc4fb6910cfae51d92cd683d2c65",
            "operation_shapes": (
                "cmovl_selected_indirect_transfer",
                "simple_indirect_jump",
            ),
        },
    )


def test_compiler_emits_distinct_direct_route_in_one_reference_batch() -> None:
    compiler = _compiler_module()

    plan = compiler.compile_rhad_reference_fragment(
        _mixed_ledger(),
        expected_evidence_generation=1,
    )

    assert tuple(operation.operation_id for operation in plan.operations) == (
        "rhad:route@0x40A605",
        "route:rhad-direct@0x40A619",
    )
    direct = plan.operation("route:rhad-direct@0x40A619")
    assert direct.predicate_anchor_ea is None
    assert direct.edges == (
        FragmentEdge(
            role=SemanticEdgeRole.DIRECT,
            target_block_id="native@0x40A61B",
        ),
    )
    rewrite = direct.direct_transfer_rewrite
    assert rewrite is not None
    assert rewrite.route_proof_id == "rhad-direct@0x40A619"
    assert rewrite.owner_anchor_ea == 0x40A619
    assert rewrite.rewrite_anchor_ea == 0x40A619
    assert rewrite.delivery_region == NativeEaInterval(0x40A619, 0x40A61B)
    assert rewrite.proof_corridor_instruction_eas == (
        0x40A607,
        0x40A615,
        0x40A617,
        0x40A619,
    )
    authority = direct.reference_route_authority
    assert authority is not None
    assert authority.reference_route.final_transfer_kind is SemanticTransferKind.DIRECT
    assert authority.reference_route.direct_target_ea == 0x40A61B
    payload = json.loads(authority.reference_route.reference_ledger_json)
    assert payload["imported_closure_block_ids"] == list(DIRECT_IMPORTED_BLOCK_IDS)
    assert payload["boundary_exit_eas"] == [0x40A633, 0x40A74C]
    assert payload["direct_target_block_id"] == "native@0x40A61B"
    assert len(plan.flag_corridors) == 1


def test_compiler_rejects_direct_route_from_non_imported_source() -> None:
    compiler = _compiler_module()
    ledger = _mixed_ledger()
    accepted, direct = ledger.operations

    with pytest.raises(compiler.RhadCompilerRejection, match="imported native-body"):
        compiler.compile_rhad_reference_fragment(
            replace(
                ledger,
                operations=(
                    accepted,
                    replace(direct, source_block_id="native@0x40A5F0"),
                ),
            ),
            expected_evidence_generation=1,
        )


def test_compiler_rejects_direct_route_without_native_body_proof() -> None:
    compiler = _compiler_module()
    ledger = _mixed_ledger()
    body = ledger.base_plan.native_bodies[0]

    with pytest.raises(compiler.RhadCompilerRejection, match="operation proof"):
        compiler.compile_rhad_reference_fragment(
            replace(
                ledger,
                base_plan=replace(
                    ledger.base_plan,
                    native_bodies=(replace(body, proof_ids=("native-body@0x40A605",)),),
                ),
            ),
            expected_evidence_generation=1,
        )


def test_compiler_rejects_direct_corridor_outside_native_body() -> None:
    compiler = _compiler_module()
    ledger = _mixed_ledger()
    accepted, direct = ledger.operations

    with pytest.raises(compiler.RhadCompilerRejection, match="corridor.*native body"):
        compiler.compile_rhad_reference_fragment(
            replace(
                ledger,
                operations=(
                    accepted,
                    replace(
                        direct,
                        owned_corridor_instruction_eas=(0x40A000, 0x40A619),
                    ),
                ),
            ),
            expected_evidence_generation=1,
        )


def test_compiler_rejects_direct_target_outside_operation_closure() -> None:
    compiler = _compiler_module()
    ledger = _mixed_ledger()
    accepted, direct = ledger.operations

    with pytest.raises(compiler.RhadCompilerRejection, match="target.*closure"):
        compiler.compile_rhad_reference_fragment(
            replace(
                ledger,
                operations=(
                    accepted,
                    replace(
                        direct,
                        direct_target_block_id="native@0x40A607",
                    ),
                ),
            ),
            expected_evidence_generation=1,
        )


def test_compiler_rejects_incomplete_mixed_operation_closure_union() -> None:
    compiler = _compiler_module()
    ledger = _mixed_ledger()
    accepted, direct = ledger.operations

    with pytest.raises(compiler.RhadCompilerRejection, match="closure union"):
        compiler.compile_rhad_reference_fragment(
            replace(
                ledger,
                operations=(
                    accepted,
                    replace(
                        direct,
                        imported_closure_block_ids=(
                            direct.imported_closure_block_ids[:-1]
                        ),
                    ),
                ),
            ),
            expected_evidence_generation=1,
        )


def test_compiler_rejects_mixed_boundary_that_keeps_internalized_exit() -> None:
    compiler = _compiler_module()
    ledger = _mixed_ledger()

    with pytest.raises(compiler.RhadCompilerRejection, match="derived batch"):
        compiler.compile_rhad_reference_fragment(
            replace(
                ledger,
                required_boundary_exit_eas=(
                    0x40A61B,
                    *COMBINED_BOUNDARY_EXIT_EAS,
                ),
            ),
            expected_evidence_generation=1,
        )


def test_a560_compiler_preserves_reference_semantics_and_exact_closure() -> None:
    compiler = _compiler_module()

    plan = compiler.compile_rhad_reference_fragment(
        _ledger(),
        expected_evidence_generation=1,
    )

    assert plan.plan_id == (
        "rhad-reference-compiler:rhad-generated-reference@0x40A560:g1"
    )
    assert plan.atomic_group_id == "rhad-generated-reference@0x40A560:g1"
    operation = plan.operation("rhad:route@0x40A605")
    assert operation.predicate_anchor_ea == 0x40A5F6
    assert operation.computed_branch_normalization is not None
    assert operation.computed_branch_normalization.condition_producer_ea == 0x40A5F0
    assert operation.computed_branch_normalization.unresolved_transfer_ea == 0x40A605
    assert operation.computed_branch_normalization.predicate_kind is PredicateKind.SLT
    edge_by_role = {edge.role: edge for edge in operation.edges}
    assert (
        edge_by_role[SemanticEdgeRole.CONDITIONAL_TAKEN].target_block_id
        == "native@0x40B6C0"
    )
    assert (
        edge_by_role[SemanticEdgeRole.CONDITIONAL_FALLTHROUGH].target_block_id
        == "native@0x40A607"
    )
    imported = tuple(
        block for block in plan.blocks if block.role is FragmentBlockRole.IMPORTED
    )
    assert tuple(block.semantic_anchor_ea for block in imported) == tuple(
        start_ea for start_ea, _end_ea in IMPORTED_RANGES
    )
    authority = operation.reference_route_authority
    assert authority is not None
    reference_payload = json.loads(authority.reference_route.reference_ledger_json)
    assert reference_payload["comparison_constant"] == 0x0BB2D365
    assert reference_payload["boundary_exit_eas"] == list(BOUNDARY_EXIT_EAS)
    assert reference_payload["imported_closure_block_ids"] == list(IMPORTED_BLOCK_IDS)


def test_compiler_rejects_stale_evidence_before_plan_publication() -> None:
    compiler = _compiler_module()

    with pytest.raises(compiler.RhadCompilerRejection, match="generation"):
        compiler.compile_rhad_reference_fragment(
            _ledger(),
            expected_evidence_generation=2,
        )


def test_compiler_rejects_incomplete_imported_closure() -> None:
    compiler = _compiler_module()
    ledger = _ledger()
    route = ledger.operations[0]
    incomplete = replace(
        route,
        imported_closure_block_ids=route.imported_closure_block_ids[:-1],
    )

    with pytest.raises(compiler.RhadCompilerRejection, match="closure"):
        compiler.compile_rhad_reference_fragment(
            replace(ledger, operations=(incomplete,)),
            expected_evidence_generation=1,
        )


def test_compiler_rejects_missing_boundary_exit() -> None:
    compiler = _compiler_module()
    ledger = _ledger()
    route = ledger.operations[0]

    with pytest.raises(compiler.RhadCompilerRejection, match="boundary"):
        compiler.compile_rhad_reference_fragment(
            replace(
                ledger,
                operations=(replace(route, boundary_exit_eas=(0x40A61B, 0x40A68C)),),
            ),
            expected_evidence_generation=1,
        )


def test_compiler_rejects_unadmitted_reference_shape() -> None:
    compiler = _compiler_module()
    ledger = replace(
        _ledger(),
        unsupported_shape_ids=("deob_consts.sbb_absolute",),
    )

    with pytest.raises(compiler.RhadCompilerRejection, match="sbb_absolute"):
        compiler.compile_rhad_reference_fragment(
            ledger,
            expected_evidence_generation=1,
        )


def test_compiler_rejects_unknown_phase_dependency() -> None:
    compiler = _compiler_module()
    ledger = _ledger()
    route = replace(ledger.operations[0], depends_on=("missing-operation",))

    with pytest.raises(compiler.RhadCompilerRejection, match="dependency"):
        compiler.compile_rhad_reference_fragment(
            replace(ledger, operations=(route,)),
            expected_evidence_generation=1,
        )
