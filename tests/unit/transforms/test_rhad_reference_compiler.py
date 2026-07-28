"""Pure compiler contract for the first Rhad GENERATED checksum route."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import importlib
import importlib.util
import json

import pytest

from d810.core.semantic_route_oracle import RouteOracleRun, SemanticTransferKind
from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.ir.semantics import PredicateKind
import d810.transforms.fragment_plan as fragment_plan
from d810.transforms.fragment_plan import (
    FragmentBlock,
    FragmentBlockMaterialization,
    FragmentBlockRole,
    FragmentEdge,
    FragmentImportedConditionalSelectEnvelope,
    FragmentNativeBody,
    FragmentOperation,
    FragmentPlan,
    FragmentPlanRejected,
    FragmentPublicationPurpose,
    FragmentWorkItemScope,
    superseded_direct_transfer_carrier_block_ids,
    superseded_referenced_conditional_carrier_block_ids,
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


def _row16_table_proof_mapping() -> dict[str, object]:
    proof = {
        "artifact_type": "rhad_setcc_indexed_table_proof",
        "schema_version": 1,
        "binding": {
            "function_ea": 0x40A560,
            "input_sha256": INPUT_SHA256,
            "operation_id": "rhad:route@0x40A77C",
            "reference_commit": "21b0d4783703bc4fb6910cfae51d92cd683d2c65",
            "reference_order": 16,
        },
        "table_evidence": {
            "additive_key": 0xFDEE1C81,
            "additive_key_producer_ea": 0x40A5BD,
            "byte_order": "little",
            "decode_ea": 0x40A77A,
            "entries": [
                {
                    "decoded_target_ea": 0x40ABC6,
                    "entry_ea": 0x48B81C,
                    "index": 0,
                    "raw_value": 0x02528F45,
                },
                {
                    "decoded_target_ea": 0x40A77E,
                    "entry_ea": 0x48B83C,
                    "index": 1,
                    "raw_value": 0x02528AFD,
                },
            ],
            "entry_width_bytes": 4,
            "extension_kind": "zero_extend_by_full_register_prezero",
            "false_index": 0,
            "index_width_bits": 32,
            "interpretation": "add_constant_modulo_entry_width",
            "lookup_ea": 0x40A774,
            "setcc_destination_width_bits": 8,
            "setcc_ea": 0x40A76E,
            "shift_bits": 5,
            "shift_ea": 0x40A771,
            "stride_bytes": 32,
            "table_base_ea": 0x48B81C,
            "table_identity": "native-table@0x48B81C:stride-0x20:u32le:add-esi",
            "true_index": 1,
            "zeroed_width_bits": 32,
            "zeroing_ea": 0x40A766,
        },
    }
    canonical = json.dumps(proof, sort_keys=True, separators=(",", ":"))
    return {
        "content_identity": f"sha256:{hashlib.sha256(canonical.encode()).hexdigest()}",
        "proof": proof,
    }


def _row16_table_proof_artifact(compiler):
    return compiler.RhadSetccIndexedTableProofArtifact.from_mapping(
        _row16_table_proof_mapping()
    )


def _row17_table_proof_mapping() -> dict[str, object]:
    row16 = _row16_table_proof_mapping()
    proof = row16["proof"]
    assert isinstance(proof, dict)
    proof["schema_version"] = 2
    binding = proof["binding"]
    assert isinstance(binding, dict)
    binding["operation_id"] = "rhad:route@0x40A792"
    binding["reference_order"] = 17
    table = proof["table_evidence"]
    assert isinstance(table, dict)
    table.update(
        {
            "decode_ea": 0x40A790,
            "entries": [
                {
                    "decoded_target_ea": 0x40A794,
                    "entry_ea": 0x48B4F8,
                    "index": 0,
                    "raw_value": 0x02528B13,
                },
                {
                    "decoded_target_ea": 0x40AEE6,
                    "entry_ea": 0x48B500,
                    "index": 1,
                    "raw_value": 0x02529265,
                },
            ],
            "index_scaling": {
                "kind": "scaled_lookup",
                "lookup_ea": 0x40A789,
                "scale_bytes": 8,
            },
            "lookup_ea": 0x40A789,
            "setcc_ea": 0x40A786,
            "stride_bytes": 8,
            "table_base_ea": 0x48B4F8,
            "table_identity": "native-table@0x48B4F8:stride-8:u32le:add-esi",
            "zeroing_ea": 0x40A77E,
        }
    )
    del table["shift_bits"]
    del table["shift_ea"]
    canonical = json.dumps(proof, sort_keys=True, separators=(",", ":"))
    return {
        "content_identity": f"sha256:{hashlib.sha256(canonical.encode()).hexdigest()}",
        "proof": proof,
    }


def test_direct_route_requires_exact_typed_reference_identity() -> None:
    compiler = _compiler_module()

    route = compiler.RhadDirectRoute(
        operation_id="route:rhad-direct@0x40A631",
        reference_operation_id="rhad:route@0x40A631",
        reference_order=3,
        operation_variant=compiler.RhadOperationVariant.SIMPLE_INDIRECT_JUMP,
        reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
        source_block_id="native@0x40A62D",
        source_native_ea=0x40A61B,
        transfer_ea=0x40A631,
        owner_anchor_ea=0x40A62D,
        direct_target_block_id="native@0x40A633",
        owned_corridor_instruction_eas=(0x40A61B, 0x40A62D, 0x40A62F, 0x40A631),
        imported_closure_block_ids=("native@0x40A633",),
        boundary_exit_eas=(0x40A64B, 0x40A8B5),
        phase=compiler.RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
        depends_on=("route:rhad-direct@0x40A619",),
    )

    assert route.operation_id == "route:rhad-direct@0x40A631"
    assert route.reference_operation_id == "rhad:route@0x40A631"
    assert route.reference_order == 3
    assert route.operation_variant is compiler.RhadOperationVariant.SIMPLE_INDIRECT_JUMP
    assert route.reference_symbol == "JumpInliner._fixup_jmp_and_possible_jcc"


def test_row17_table_proof_artifact_persists_scaled_lookup() -> None:
    compiler = _compiler_module()

    artifact = compiler.RhadSetccIndexedTableProofArtifact.from_mapping(
        _row17_table_proof_mapping()
    )

    assert artifact.schema_version == 2
    assert artifact.operation_id == "rhad:route@0x40A792"
    assert artifact.reference_order == 17
    assert isinstance(
        artifact.table_evidence.index_scaling,
        fragment_plan.FragmentSetccScaledLookupScaling,
    )
    assert artifact.table_evidence.index_scaling.scale_bytes == 8
    assert (
        json.loads(artifact.canonical_proof_json)
        == (_row17_table_proof_mapping()["proof"])
    )


def test_row16_table_proof_artifact_is_typed_canonical_and_bound() -> None:
    compiler = _compiler_module()

    artifact = compiler.RhadSetccIndexedTableProofArtifact.from_mapping(
        _row16_table_proof_mapping()
    )

    assert artifact.input_sha256 == INPUT_SHA256
    assert artifact.function_ea == 0x40A560
    assert artifact.operation_id == "rhad:route@0x40A77C"
    assert artifact.reference_order == 16
    assert artifact.content_identity.startswith("sha256:")
    assert artifact.table_evidence.true_entry.decoded_target_ea == 0x40A77E
    assert artifact.table_evidence.false_entry.decoded_target_ea == 0x40ABC6
    assert (
        json.loads(artifact.canonical_proof_json)
        == (_row16_table_proof_mapping()["proof"])
    )


def test_row16_table_proof_artifact_rejects_content_identity_mismatch() -> None:
    compiler = _compiler_module()
    mapping = _row16_table_proof_mapping()
    mapping["content_identity"] = "sha256:" + ("0" * 64)

    with pytest.raises(compiler.RhadCompilerRejection, match="content identity"):
        compiler.RhadSetccIndexedTableProofArtifact.from_mapping(mapping)


def test_row16_table_proof_artifact_rejects_noncanonical_fields() -> None:
    compiler = _compiler_module()
    mapping = _row16_table_proof_mapping()
    proof = mapping["proof"]
    assert isinstance(proof, dict)
    proof["compatibility_metadata"] = {}

    with pytest.raises(compiler.RhadCompilerRejection, match="exact typed fields"):
        compiler.RhadSetccIndexedTableProofArtifact.from_mapping(mapping)


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
        reference_order=1,
        operation_variant=compiler.RhadOperationVariant.CMOV_SELECTED_INDIRECT,
        reference_symbol="JumpInliner._fixup_cmov",
        source_block_id="native@0x40A5F0",
        source_value_block_id="native@0x40A5F0",
        source_native_ea=0x40A5F0,
        source_block_anchor_ea=0x40A5F0,
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
        true_target_ea=0x40B6C0,
        false_target_ea=0x40A607,
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
        native_function_ea=0x40A560,
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
        source_block_id="native@0x40A615",
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
                    if block_id != "native@0x40A615"
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
        reference_operation_id="rhad:route@0x40A619",
        reference_order=2,
        operation_variant=compiler.RhadOperationVariant.SIMPLE_INDIRECT_JUMP,
        reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
        source_block_id="native@0x40A615",
        source_native_ea=0x40A607,
        transfer_ea=0x40A619,
        owner_anchor_ea=0x40A615,
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
        native_function_ea=0x40A560,
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


def test_conditional_flag_producer_may_precede_the_owned_rewrite_corridor() -> None:
    compiler = _compiler_module()
    ledger = _ledger()
    route = replace(
        ledger.operations[0],
        owned_corridor_instruction_eas=(
            0x40A5F6,
            0x40A5FE,
            0x40A601,
            0x40A605,
        ),
    )

    plan = compiler.compile_rhad_reference_fragment(
        replace(ledger, operations=(route,)),
        expected_evidence_generation=1,
    )

    operation = plan.operation(route.operation_id)
    assert operation.computed_branch_normalization.condition_producer_ea == 0x40A5F0
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["owned_corridor_instruction_eas"] == [
        0x40A5F6,
        0x40A5FE,
        0x40A601,
        0x40A605,
    ]
    assert payload["source_value_block_id"] == "native@0x40A5F0"


def test_compiler_rejects_missing_conditional_source_value_binding() -> None:
    compiler = _compiler_module()
    ledger = _ledger()
    route = replace(
        ledger.operations[0],
        source_value_block_id="native@0x40A5BD",
    )

    with pytest.raises(
        compiler.RhadCompilerRejection,
        match="block binding is incomplete.*native@0x40A5BD",
    ):
        compiler.compile_rhad_reference_fragment(
            replace(ledger, operations=(route,)),
            expected_evidence_generation=1,
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
    assert rewrite.owner_anchor_ea == 0x40A615
    assert rewrite.rewrite_anchor_ea == 0x40A619
    assert rewrite.delivery_region == NativeEaInterval(0x40A615, 0x40A61B)
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
    assert payload["operation_variant"] == "simple_indirect_jump"
    assert payload["reference_operation_id"] == "rhad:route@0x40A619"
    assert payload["reference_order"] == 2
    assert payload["reference_symbol"] == "JumpInliner._fixup_jmp_and_possible_jcc"
    assert payload["imported_closure_block_ids"] == list(DIRECT_IMPORTED_BLOCK_IDS)
    assert payload["boundary_exit_eas"] == [0x40A633, 0x40A74C]
    assert payload["direct_target_block_id"] == "native@0x40A61B"
    assert payload["source_native_ea"] == 0x40A607
    assert payload["source_block_anchor_ea"] == 0x40A615
    assert len(plan.flag_corridors) == 1


def test_compiled_plan_identifies_only_the_detached_superseded_carrier() -> None:
    compiler = _compiler_module()

    plan = compiler.compile_rhad_reference_fragment(
        _mixed_ledger(),
        expected_evidence_generation=1,
    )

    assert superseded_direct_transfer_carrier_block_ids(plan) == frozenset(
        {"native@0x40A619"}
    )


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
                        source_native_ea=0x40A000,
                        owned_corridor_instruction_eas=(
                            0x40A000,
                            0x40A615,
                            0x40A619,
                        ),
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


def _third_shape_ledger():
    compiler = _compiler_module()
    mixed = _mixed_ledger()
    base = mixed.base_plan
    body = base.native_bodies[0]
    body_id = body.body_id
    added_ranges = (
        (0x40A68C, 0x40A69A, (0x40A68C, 0x40A692, 0x40A698)),
        (0x40A69A, 0x40A6A0, (0x40A69A,)),
        (0x40A6A0, 0x40A6A6, (0x40A6A0, 0x40A6A2, 0x40A6A4)),
        (0x40A6A4, 0x40A6A6, (0x40A6A4,)),
        (0x40A6B4, 0x40A6BA, (0x40A6B4,)),
        (0x40A6BA, 0x40A6C0, (0x40A6BA, 0x40A6BC, 0x40A6BE)),
        (0x40A800, 0x40A80E, (0x40A800, 0x40A806, 0x40A80C)),
        (0x40A80E, 0x40A814, (0x40A80E,)),
        (0x40A814, 0x40A81A, (0x40A814, 0x40A816, 0x40A818)),
        (0x40A818, 0x40A81A, (0x40A818,)),
    )
    added_blocks = tuple(
        FragmentBlock(
            block_id=f"native@0x{start_ea:X}",
            role=FragmentBlockRole.IMPORTED,
            materialization=FragmentBlockMaterialization.IMPORT_NATIVE,
            semantic_anchor_ea=start_ea,
            stable_identity=_identity(start_ea, end_ea, *exact_eas),
            native_body_id=body_id,
        )
        for start_ea, end_ea, exact_eas in added_ranges
    )
    dependency_id = "route:rhad-direct@0x40A68A"
    selected_id = "rhad:route@0x40A6A4"
    dependency = compiler.RhadDirectRoute(
        operation_id=dependency_id,
        reference_operation_id="rhad:route@0x40A68A",
        reference_order=7,
        operation_variant=compiler.RhadOperationVariant.SIMPLE_INDIRECT_JUMP,
        reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
        source_block_id="native@0x40A680",
        source_native_ea=0x40A613,
        transfer_ea=0x40A68A,
        owner_anchor_ea=0x40A680,
        direct_target_block_id="native@0x40A68C",
        owned_corridor_instruction_eas=(
            0x40A613,
            0x40A680,
            0x40A686,
            0x40A688,
            0x40A68A,
        ),
        imported_closure_block_ids=(
            "native@0x40A68C",
            "native@0x40A69A",
            "native@0x40A6A0",
            "native@0x40A6A4",
        ),
        boundary_exit_eas=(0x40A800,),
        phase=compiler.RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
        depends_on=(mixed.operations[0].operation_id,),
    )
    selected = compiler.RhadExistingConditionalRoute(
        operation_id=selected_id,
        reference_order=8,
        operation_variant=(
            compiler.RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT
        ),
        reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
        source_block_id="native@0x40A68C",
        selected_value_block_id="native@0x40A69A",
        join_block_id="native@0x40A6A0",
        source_native_ea=0x40A68C,
        source_block_anchor_ea=0x40A6A0,
        join_ea=0x40A6A0,
        transfer_ea=0x40A6A4,
        condition_producer_ea=0x40A692,
        predicate_anchor_ea=0x40A698,
        normalization_start_ea=0x40A698,
        source_branch_ea=0x40A698,
        selected_value_ea=0x40A69A,
        observed_predicate_kind=PredicateKind.SGE,
        predicate_kind=PredicateKind.SLT,
        true_target_block_id="native@0x40A6B4",
        false_target_block_id="native@0x40A800",
        true_target_ea=0x40A6A6,
        false_target_ea=0x40A800,
        comparison_constant=0x65203D55,
        owned_corridor_instruction_eas=(
            0x40A68C,
            0x40A692,
            0x40A698,
            0x40A69A,
            0x40A6A0,
            0x40A6A2,
            0x40A6A4,
        ),
        imported_closure_block_ids=(
            "native@0x40A6B4",
            "native@0x40A6BA",
            "native@0x40A800",
            "native@0x40A80E",
            "native@0x40A814",
            "native@0x40A818",
        ),
        boundary_exit_eas=(0x40A9A0,),
        flag_corridor_id="flags-intact@0x40A692",
        phase=compiler.RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
        depends_on=(dependency_id,),
    )
    placeholders = (
        FragmentOperation(
            operation_id=f"placeholder:{dependency_id}",
            source_block_id=dependency.source_block_id,
            edges=(
                FragmentEdge(
                    role=SemanticEdgeRole.DIRECT,
                    target_block_id=dependency.direct_target_block_id,
                ),
            ),
        ),
        FragmentOperation(
            operation_id=f"placeholder:{selected_id}",
            source_block_id=selected.source_block_id,
            predicate_anchor_ea=selected.predicate_anchor_ea,
            edges=(
                FragmentEdge(
                    role=SemanticEdgeRole.CONDITIONAL_TAKEN,
                    target_block_id=selected.true_target_block_id,
                ),
                FragmentEdge(
                    role=SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
                    target_block_id=selected.false_target_block_id,
                ),
            ),
        ),
    )
    all_block_ids = body.block_ids + tuple(block.block_id for block in added_blocks)
    operation_source_ids = {
        "native@0x40A615",
        dependency.source_block_id,
        selected.source_block_id,
    }
    expanded_body = FragmentNativeBody(
        body_id=body_id,
        block_ids=all_block_ids,
        entry_block_ids=body.entry_block_ids
        + (
            "native@0x40A68C",
            "native@0x40A6B4",
            "native@0x40A800",
            "native@0x40A818",
        ),
        terminal_block_ids=tuple(
            block_id
            for block_id in all_block_ids
            if block_id not in operation_source_ids
        ),
        native_ranges=tuple(
            sorted(
                body.native_ranges
                + (
                    NativeEaInterval(0x40A68C, 0x40A6C0),
                    NativeEaInterval(0x40A800, 0x40A81A),
                ),
                key=lambda interval: int(interval.start_ea),
            )
        ),
        proof_ids=body.proof_ids + (dependency_id, selected_id),
    )
    plan = replace(
        base,
        blocks=base.blocks + added_blocks,
        operations=base.operations + placeholders,
        work_item_scope=replace(
            base.work_item_scope,
            selected_obligation_ids=tuple(
                operation.operation_id
                for operation in (*mixed.operations, dependency, selected)
            ),
        ),
        native_bodies=(expanded_body,),
    )
    return compiler.RhadReferenceLedger(
        ledger_id="rhad-generated-reference@0x40A560:g1",
        function_ea=0x40A560,
        native_function_ea=0x40A560,
        evidence_generation=1,
        base_plan=plan,
        reference_oracle_run=_reference_run(),
        operations=(*mixed.operations, dependency, selected),
        required_boundary_exit_eas=(0x40A633, 0x40A74C, 0x40A9A0, 0x40B790),
        reference_provenance={
            "reference_commit": "21b0d4783703bc4fb6910cfae51d92cd683d2c65",
            "inventory_identity": "rhad-a560-indirect-jump-reference-inventory:v1",
        },
    )


def test_compiler_emits_imported_existing_conditional_route() -> None:
    compiler = _compiler_module()

    plan = compiler.compile_rhad_reference_fragment(
        _third_shape_ledger(),
        expected_evidence_generation=1,
    )

    assert tuple(operation.operation_id for operation in plan.operations) == (
        "rhad:route@0x40A605",
        "route:rhad-direct@0x40A619",
        "route:rhad-direct@0x40A68A",
        "rhad:route@0x40A6A4",
    )
    operation = plan.operation("rhad:route@0x40A6A4")
    assert operation.predicate_anchor_ea == 0x40A698
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    assert normalization.condition_producer_ea == 0x40A692
    assert normalization.unresolved_transfer_ea == 0x40A6A4
    assert normalization.predicate_kind is PredicateKind.SLT
    assert isinstance(
        normalization.conditional_select_envelope,
        FragmentImportedConditionalSelectEnvelope,
    )
    envelope = normalization.conditional_select_envelope
    assert envelope.source_branch_ea == 0x40A698
    assert envelope.selected_value_ea == 0x40A69A
    assert envelope.selected_value_block_id == "native@0x40A69A"
    assert envelope.join_block_id == "native@0x40A6A0"
    assert envelope.join_identity.native_ranges.contains(0x40A6A4)
    assert operation.edges == (
        FragmentEdge(
            role=SemanticEdgeRole.CONDITIONAL_TAKEN,
            target_block_id="native@0x40A6B4",
        ),
        FragmentEdge(
            role=SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
            target_block_id="native@0x40A800",
        ),
    )
    authority = operation.reference_route_authority
    assert authority is not None
    assert authority.reference_route.final_transfer_kind is (
        SemanticTransferKind.CONDITIONAL
    )
    assert authority.reference_route.true_target_ea == 0x40A6A6
    assert authority.imported_closure_block_ids == (
        "native@0x40A6B4",
        "native@0x40A6BA",
        "native@0x40A800",
        "native@0x40A80E",
        "native@0x40A814",
        "native@0x40A818",
    )
    assert superseded_referenced_conditional_carrier_block_ids(plan) == frozenset(
        {"native@0x40A69A", "native@0x40A6A0", "native@0x40A6A4"}
    )
    payload = json.loads(authority.reference_route.reference_ledger_json)
    assert payload["reference_order"] == 8
    assert payload["operation_variant"] == "existing_conditional_plus_indirect"
    assert payload["reference_symbol"] == ("JumpInliner._fixup_jmp_and_possible_jcc")
    assert payload["source_native_ea"] == 0x40A68C
    assert payload["source_block_anchor_ea"] == 0x40A6A0
    assert payload["join_ea"] == 0x40A6A0
    assert payload["comparison_constant"] == 0x65203D55


def test_existing_conditional_may_target_the_owned_replacement_root() -> None:
    compiler = _compiler_module()
    ledger = _third_shape_ledger()
    *dependencies, selected = ledger.operations
    selected = replace(
        selected,
        false_target_block_id="native@0x40A5F0",
        false_target_ea=0x40A5F0,
    )

    plan = compiler.compile_rhad_reference_fragment(
        replace(ledger, operations=(*dependencies, selected)),
        expected_evidence_generation=1,
    )

    assert plan.operation(selected.operation_id).edges[-1] == FragmentEdge(
        role=SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
        target_block_id="native@0x40A5F0",
    )


def test_existing_conditional_rejects_nonreplacement_nonimported_arm() -> None:
    compiler = _compiler_module()
    ledger = _third_shape_ledger()
    *dependencies, selected = ledger.operations
    selected = replace(
        selected,
        false_target_block_id="native-original@0x40A5F0",
        false_target_ea=0x40A5F0,
    )

    with pytest.raises(compiler.RhadCompilerRejection, match="owned branch arms"):
        compiler.compile_rhad_reference_fragment(
            replace(ledger, operations=(*dependencies, selected)),
            expected_evidence_generation=1,
        )


def test_frontend_imported_conditional_rejects_missing_reference_authority() -> None:
    compiler = _compiler_module()
    plan = compiler.compile_rhad_reference_fragment(
        _third_shape_ledger(),
        expected_evidence_generation=1,
    )
    selected = plan.operation("rhad:route@0x40A6A4")

    with pytest.raises(FragmentPlanRejected, match="reference.*authority"):
        replace(
            plan,
            operations=tuple(
                (
                    replace(operation, reference_route_authority=None)
                    if operation is selected
                    else operation
                )
                for operation in plan.operations
            ),
        )


def test_compiler_rejects_existing_conditional_incomplete_branch_arm() -> None:
    compiler = _compiler_module()
    ledger = _third_shape_ledger()
    *dependencies, selected = ledger.operations

    with pytest.raises(compiler.RhadCompilerRejection, match="complete.*arms"):
        compiler.compile_rhad_reference_fragment(
            replace(
                ledger,
                operations=(
                    *dependencies,
                    replace(selected, true_target_block_id="native@0x40A607"),
                ),
            ),
            expected_evidence_generation=1,
        )


def test_compiler_rejects_existing_conditional_predicate_orientation() -> None:
    compiler = _compiler_module()
    ledger = _third_shape_ledger()
    selected = ledger.operations[-1]

    with pytest.raises(compiler.RhadCompilerRejection, match="orientation"):
        replace(selected, observed_predicate_kind=PredicateKind.SLT)


def test_compiler_rejects_existing_conditional_without_body_proof() -> None:
    compiler = _compiler_module()
    ledger = _third_shape_ledger()
    body = ledger.base_plan.native_bodies[0]

    with pytest.raises(compiler.RhadCompilerRejection, match="operation proof"):
        compiler.compile_rhad_reference_fragment(
            replace(
                ledger,
                base_plan=replace(
                    ledger.base_plan,
                    native_bodies=(
                        replace(
                            body,
                            proof_ids=body.proof_ids[:-1],
                        ),
                    ),
                ),
            ),
            expected_evidence_generation=1,
        )


def test_compiler_rejects_existing_conditional_foreign_oracle_run() -> None:
    compiler = _compiler_module()
    ledger = _third_shape_ledger()

    with pytest.raises(compiler.RhadCompilerRejection, match="different inputs"):
        compiler.compile_rhad_reference_fragment(
            replace(
                ledger,
                reference_oracle_run=replace(
                    ledger.reference_oracle_run,
                    function_ea=0x40C8B0,
                ),
            ),
            expected_evidence_generation=1,
        )


def test_compiler_rejects_unselected_existing_conditional_obligation() -> None:
    compiler = _compiler_module()
    ledger = _third_shape_ledger()
    scope = ledger.base_plan.work_item_scope
    assert scope is not None

    with pytest.raises(compiler.RhadCompilerRejection, match="work-item authority"):
        compiler.compile_rhad_reference_fragment(
            replace(
                ledger,
                base_plan=replace(
                    ledger.base_plan,
                    work_item_scope=replace(
                        scope,
                        selected_obligation_ids=scope.selected_obligation_ids[:-1],
                    ),
                ),
            ),
            expected_evidence_generation=1,
        )


def test_compiler_rejects_existing_conditional_ambiguous_native_anchor() -> None:
    compiler = _compiler_module()
    ledger = _third_shape_ledger()
    selected = ledger.operations[-1]

    with pytest.raises(compiler.RhadCompilerRejection, match="ambiguous.*corridor"):
        replace(selected, source_branch_ea=0x40A697)


def _fourth_shape_ledger():
    compiler = _compiler_module()
    third = _third_shape_ledger()
    base = third.base_plan
    body = base.native_bodies[0]
    body_id = body.body_id
    added_ranges = (
        (0x40A74C, 0x40A75A, (0x40A74C, 0x40A752, 0x40A758)),
        (0x40A75A, 0x40A760, (0x40A75A,)),
        (0x40A760, 0x40A766, (0x40A760, 0x40A762, 0x40A764)),
        (0x40A764, 0x40A766, (0x40A764,)),
        (
            0x40A766,
            0x40A77E,
            (
                0x40A766,
                0x40A768,
                0x40A76E,
                0x40A771,
                0x40A774,
                0x40A77A,
                0x40A77C,
            ),
        ),
        (0x40A77C, 0x40A77E, (0x40A77C,)),
        (
            0x40A77E,
            0x40A794,
            (0x40A77E, 0x40A780, 0x40A786, 0x40A789, 0x40A790, 0x40A792),
        ),
        (0x40A792, 0x40A794, (0x40A792,)),
        (0x40A9DE, 0x40A9EC, (0x40A9DE, 0x40A9E4, 0x40A9EA)),
        (0x40A9EC, 0x40A9F2, (0x40A9EC,)),
        (0x40A9F2, 0x40A9F8, (0x40A9F2, 0x40A9F4, 0x40A9F6)),
        (0x40A9F6, 0x40A9F8, (0x40A9F6,)),
        (0x40ABC6, 0x40ABD4, (0x40ABC6, 0x40ABCC, 0x40ABD2)),
        (0x40ABD4, 0x40ABDA, (0x40ABD4,)),
        (0x40ABDA, 0x40ABE0, (0x40ABDA, 0x40ABDC, 0x40ABDE)),
        (0x40ABDE, 0x40ABE0, (0x40ABDE,)),
    )
    added_blocks = tuple(
        FragmentBlock(
            block_id=f"native@0x{start_ea:X}",
            role=FragmentBlockRole.IMPORTED,
            materialization=FragmentBlockMaterialization.IMPORT_NATIVE,
            semantic_anchor_ea=start_ea,
            stable_identity=_identity(start_ea, end_ea, *exact_eas),
            native_body_id=body_id,
        )
        for start_ea, end_ea, exact_eas in added_ranges
    )
    direct_id = "route:rhad-direct@0x40A74A"
    existing_id = "rhad:route@0x40A764"
    selected_id = "rhad:route@0x40A77C"
    direct = compiler.RhadDirectRoute(
        operation_id=direct_id,
        reference_operation_id="rhad:route@0x40A74A",
        reference_order=14,
        operation_variant=compiler.RhadOperationVariant.SIMPLE_INDIRECT_JUMP,
        reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
        source_block_id="native@0x40A740",
        source_native_ea=0x40A607,
        transfer_ea=0x40A74A,
        owner_anchor_ea=0x40A740,
        direct_target_block_id="native@0x40A74C",
        owned_corridor_instruction_eas=(
            0x40A607,
            0x40A740,
            0x40A746,
            0x40A748,
            0x40A74A,
        ),
        imported_closure_block_ids=(
            "native@0x40A74C",
            "native@0x40A75A",
            "native@0x40A760",
            "native@0x40A764",
        ),
        boundary_exit_eas=(0x40A9DE,),
        phase=compiler.RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
        depends_on=(third.operations[1].operation_id,),
    )
    existing = compiler.RhadExistingConditionalRoute(
        operation_id=existing_id,
        reference_order=15,
        operation_variant=(
            compiler.RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT
        ),
        reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
        source_block_id="native@0x40A74C",
        selected_value_block_id="native@0x40A75A",
        join_block_id="native@0x40A760",
        source_native_ea=0x40A74C,
        source_block_anchor_ea=0x40A760,
        join_ea=0x40A760,
        transfer_ea=0x40A764,
        condition_producer_ea=0x40A752,
        predicate_anchor_ea=0x40A758,
        normalization_start_ea=0x40A758,
        source_branch_ea=0x40A758,
        selected_value_ea=0x40A75A,
        observed_predicate_kind=PredicateKind.SGE,
        predicate_kind=PredicateKind.SLT,
        true_target_block_id="native@0x40A766",
        false_target_block_id="native@0x40A9DE",
        true_target_ea=0x40A766,
        false_target_ea=0x40A9DE,
        comparison_constant=0x23B8E806,
        owned_corridor_instruction_eas=(
            0x40A74C,
            0x40A752,
            0x40A758,
            0x40A75A,
            0x40A760,
            0x40A762,
            0x40A764,
        ),
        imported_closure_block_ids=(
            "native@0x40A766",
            "native@0x40A77C",
            "native@0x40A9DE",
            "native@0x40A9EC",
            "native@0x40A9F2",
            "native@0x40A9F6",
        ),
        boundary_exit_eas=(0x40A77E, 0x40ABC6, 0x40AD6E),
        flag_corridor_id="flags-intact@0x40A752",
        phase=compiler.RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
        depends_on=(direct_id,),
    )
    assert hasattr(compiler, "RhadSetccIndexedTableRoute"), (
        "the compiler has no typed setcc-indexed-table operation"
    )
    table_proof_artifact = _row16_table_proof_artifact(compiler)
    selected = compiler.RhadSetccIndexedTableRoute(
        operation_id=selected_id,
        reference_order=16,
        operation_variant=compiler.RhadOperationVariant.SETCC_INDEXED_TABLE,
        reference_symbol="JumpInliner._fixup_index_access",
        source_block_id="native@0x40A766",
        source_native_ea=0x40A766,
        source_block_anchor_ea=0x40A766,
        transfer_ea=0x40A77C,
        condition_producer_ea=0x40A768,
        predicate_anchor_ea=0x40A76E,
        predicate_kind=PredicateKind.SLT,
        fallthrough_delivery=(
            compiler.FragmentSetccFallthroughDelivery.PHYSICAL_ADJACENCY
        ),
        true_target_block_id="native@0x40A77E",
        false_target_block_id="native@0x40ABC6",
        true_target_ea=0x40A77E,
        false_target_ea=0x40ABC6,
        table_proof_artifact=table_proof_artifact,
        owned_corridor_instruction_eas=(
            0x40A766,
            0x40A768,
            0x40A76E,
            0x40A771,
            0x40A774,
            0x40A77A,
            0x40A77C,
        ),
        imported_closure_block_ids=(
            "native@0x40A77E",
            "native@0x40A792",
            "native@0x40ABC6",
            "native@0x40ABD4",
            "native@0x40ABDA",
            "native@0x40ABDE",
        ),
        boundary_exit_eas=(0x40A794, 0x40AEE6, 0x40B1D0),
        flag_corridor_id="flags-intact@0x40A768",
        phase=compiler.RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
        depends_on=(existing_id,),
    )
    placeholders = tuple(
        FragmentOperation(
            operation_id=f"placeholder:{operation.operation_id}",
            source_block_id=operation.source_block_id,
            edges=(
                FragmentEdge(
                    role=SemanticEdgeRole.DIRECT,
                    target_block_id=(
                        operation.direct_target_block_id
                        if isinstance(operation, compiler.RhadDirectRoute)
                        else operation.false_target_block_id
                    ),
                ),
            ),
        )
        for operation in (direct, existing, selected)
    )
    false_target_block = next(
        block
        for block in added_blocks
        if block.block_id == selected.false_target_block_id
    )
    ordered_added_blocks = tuple(
        block for block in added_blocks if block is not false_target_block
    )
    source_index = next(
        index
        for index, block in enumerate(ordered_added_blocks)
        if block.block_id == selected.source_block_id
    )
    ordered_added_blocks = (
        ordered_added_blocks[: source_index + 1]
        + (false_target_block,)
        + ordered_added_blocks[source_index + 1 :]
    )
    all_block_ids = body.block_ids + tuple(
        block.block_id for block in ordered_added_blocks
    )
    operation_source_ids = {
        operation.source_block_id
        for operation in (*third.operations, direct, existing, selected)
    }
    expanded_body = FragmentNativeBody(
        body_id=body_id,
        block_ids=all_block_ids,
        entry_block_ids=body.entry_block_ids
        + (
            "native@0x40A74C",
            "native@0x40A764",
            "native@0x40A766",
            "native@0x40A77C",
            "native@0x40A77E",
            "native@0x40A792",
            "native@0x40A9DE",
            "native@0x40A9F6",
            "native@0x40ABC6",
            "native@0x40ABDE",
        ),
        terminal_block_ids=tuple(
            block_id
            for block_id in all_block_ids
            if block_id not in operation_source_ids
        ),
        native_ranges=tuple(
            sorted(
                body.native_ranges
                + (
                    NativeEaInterval(0x40A74C, 0x40A77E),
                    NativeEaInterval(0x40A77E, 0x40A794),
                    NativeEaInterval(0x40A9DE, 0x40A9F8),
                    NativeEaInterval(0x40ABC6, 0x40ABE0),
                ),
                key=lambda interval: int(interval.start_ea),
            )
        ),
        proof_ids=body.proof_ids + (direct_id, existing_id, selected_id),
    )
    plan = replace(
        base,
        blocks=base.blocks + ordered_added_blocks,
        operations=base.operations + placeholders,
        work_item_scope=replace(
            base.work_item_scope,
            selected_obligation_ids=tuple(
                operation.operation_id
                for operation in (*third.operations, direct, existing, selected)
            ),
        ),
        native_bodies=(expanded_body,),
    )
    return compiler.RhadReferenceLedger(
        ledger_id="rhad-generated-reference@0x40A560:g1",
        function_ea=0x40A560,
        native_function_ea=0x40A560,
        evidence_generation=1,
        base_plan=plan,
        reference_oracle_run=_reference_run(),
        operations=(*third.operations, direct, existing, selected),
        required_boundary_exit_eas=(
            0x40A633,
            0x40A794,
            0x40A9A0,
            0x40AD6E,
            0x40AEE6,
            0x40B1D0,
            0x40B790,
        ),
        reference_provenance={
            "reference_commit": "21b0d4783703bc4fb6910cfae51d92cd683d2c65",
            "inventory_identity": "rhad-a560-indirect-jump-reference-inventory:v1",
            "setcc_proof_artifact_identity": table_proof_artifact.content_identity,
        },
    )


def test_compiler_emits_typed_setcc_indexed_table_route() -> None:
    compiler = _compiler_module()

    plan = compiler.compile_rhad_reference_fragment(
        _fourth_shape_ledger(),
        expected_evidence_generation=1,
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
    operation = plan.operation("rhad:route@0x40A77C")
    normalization = operation.computed_branch_normalization
    assert isinstance(
        normalization,
        fragment_plan.FragmentSetccIndexedTableNormalization,
    )
    assert normalization.condition_producer_ea == 0x40A768
    assert normalization.normalization_start_ea == 0x40A76E
    assert normalization.unresolved_transfer_ea == 0x40A77C
    assert normalization.table_evidence.true_entry.decoded_target_ea == 0x40A77E
    assert normalization.table_evidence.false_entry.decoded_target_ea == 0x40ABC6
    assert operation.edges == (
        FragmentEdge(
            role=SemanticEdgeRole.CONDITIONAL_TAKEN,
            target_block_id="native@0x40A77E",
        ),
        FragmentEdge(
            role=SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
            target_block_id="native@0x40ABC6",
        ),
    )
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 16
    assert payload["operation_variant"] == "setcc_indexed_table"
    assert payload["proof_artifact"]["content_identity"] == (
        _row16_table_proof_artifact(compiler).content_identity
    )
    assert payload["proof_artifact"]["proof"]["binding"]["reference_order"] == 16
    assert payload["aggregate_program_identity"] == (
        _fourth_shape_ledger().aggregate_program_identity
    )
    assert plan.plan_id.endswith(payload["aggregate_program_identity"])
    assert payload["setcc_table"]["table_base_ea"] == 0x48B81C
    assert payload["setcc_table"]["entries"][1]["decoded_target_ea"] == 0x40A77E


def test_aggregate_identity_binds_existing_conditional_boundary_evidence() -> None:
    ledger = _fourth_shape_ledger()
    operation = next(
        operation
        for operation in ledger.operations
        if operation.operation_id == "rhad:route@0x40A764"
    )
    changed_operation = replace(
        operation,
        boundary_exit_eas=(0x40A78E, 0x40AB48, 0x40B1D2),
    )
    changed_ledger = replace(
        ledger,
        operations=tuple(
            changed_operation if candidate is operation else candidate
            for candidate in ledger.operations
        ),
        required_boundary_exit_eas=(
            0x40A633,
            0x40A794,
            0x40A9A0,
            0x40AD6E,
            0x40AEE6,
            0x40B1D2,
            0x40B790,
        ),
    )

    assert (
        changed_ledger.aggregate_program_identity != ledger.aggregate_program_identity
    )


def test_compiler_rejects_setcc_route_without_native_body_proof() -> None:
    compiler = _compiler_module()
    ledger = _fourth_shape_ledger()
    body = ledger.base_plan.native_bodies[0]

    with pytest.raises(compiler.RhadCompilerRejection, match="operation proof"):
        compiler.compile_rhad_reference_fragment(
            replace(
                ledger,
                base_plan=replace(
                    ledger.base_plan,
                    native_bodies=(replace(body, proof_ids=body.proof_ids[:-1]),),
                ),
            ),
            expected_evidence_generation=1,
        )


def test_compiler_rejects_setcc_route_with_mismatched_derived_target() -> None:
    compiler = _compiler_module()
    ledger = _fourth_shape_ledger()
    *dependencies, selected = ledger.operations

    with pytest.raises(compiler.RhadCompilerRejection, match="derived.*target"):
        compiler.compile_rhad_reference_fragment(
            replace(
                ledger,
                operations=(
                    *dependencies,
                    replace(selected, true_target_ea=0x40A780),
                ),
            ),
            expected_evidence_generation=1,
        )


def test_compiler_rejects_setcc_proof_artifact_bound_to_another_operation() -> None:
    compiler = _compiler_module()
    ledger = _fourth_shape_ledger()
    *dependencies, selected = ledger.operations
    mapping = _row16_table_proof_mapping()
    proof = mapping["proof"]
    assert isinstance(proof, dict)
    binding = proof["binding"]
    assert isinstance(binding, dict)
    binding["operation_id"] = "rhad:route@0x40A792"
    canonical = json.dumps(proof, sort_keys=True, separators=(",", ":"))
    mapping["content_identity"] = (
        f"sha256:{hashlib.sha256(canonical.encode()).hexdigest()}"
    )
    foreign_artifact = compiler.RhadSetccIndexedTableProofArtifact.from_mapping(mapping)

    with pytest.raises(compiler.RhadCompilerRejection, match="artifact binding"):
        compiler.compile_rhad_reference_fragment(
            replace(
                ledger,
                operations=(
                    *dependencies,
                    replace(selected, table_proof_artifact=foreign_artifact),
                ),
            ),
            expected_evidence_generation=1,
        )


@pytest.mark.parametrize(
    ("binding_field", "foreign_value", "expected_rejection"),
    (
        ("input_sha256", "d" * 64, "artifact binding.*ledger"),
        ("function_ea", 0x40C8B0, "artifact binding.*ledger"),
        ("reference_commit", "f" * 40, "artifact binding.*ledger"),
        ("reference_order", 17, "artifact binding.*route"),
    ),
)
def test_compiler_rejects_row16_artifact_bound_to_foreign_authority(
    binding_field: str,
    foreign_value: object,
    expected_rejection: str,
) -> None:
    compiler = _compiler_module()
    ledger = _fourth_shape_ledger()
    *dependencies, selected = ledger.operations
    mapping = _row16_table_proof_mapping()
    proof = mapping["proof"]
    assert isinstance(proof, dict)
    binding = proof["binding"]
    assert isinstance(binding, dict)
    binding[binding_field] = foreign_value
    canonical = json.dumps(proof, sort_keys=True, separators=(",", ":"))
    mapping["content_identity"] = (
        f"sha256:{hashlib.sha256(canonical.encode()).hexdigest()}"
    )
    foreign_artifact = compiler.RhadSetccIndexedTableProofArtifact.from_mapping(mapping)

    with pytest.raises(compiler.RhadCompilerRejection, match=expected_rejection):
        foreign_route = replace(
            selected,
            table_proof_artifact=foreign_artifact,
        )
        compiler.compile_rhad_reference_fragment(
            replace(
                ledger,
                operations=(*dependencies, foreign_route),
            ),
            expected_evidence_generation=1,
        )


def test_compiler_rejects_unselected_setcc_route() -> None:
    compiler = _compiler_module()
    ledger = _fourth_shape_ledger()
    scope = ledger.base_plan.work_item_scope
    assert scope is not None

    with pytest.raises(compiler.RhadCompilerRejection, match="work-item authority"):
        compiler.compile_rhad_reference_fragment(
            replace(
                ledger,
                base_plan=replace(
                    ledger.base_plan,
                    work_item_scope=replace(
                        scope,
                        selected_obligation_ids=scope.selected_obligation_ids[:-1],
                    ),
                ),
            ),
            expected_evidence_generation=1,
        )


def test_setcc_split_transfer_carrier_is_superseded_creation_evidence() -> None:
    compiler = _compiler_module()
    plan = compiler.compile_rhad_reference_fragment(
        _fourth_shape_ledger(),
        expected_evidence_generation=1,
    )

    assert "native@0x40A77C" in superseded_referenced_conditional_carrier_block_ids(
        plan
    )


def _fifth_shape_ledger():
    compiler = _compiler_module()
    fourth = _fourth_shape_ledger()
    base = fourth.base_plan
    body = base.native_bodies[0]
    body_id = body.body_id
    added_ranges = (
        (0x40A794, 0x40A7A2, (0x40A794, 0x40A79A, 0x40A7A0)),
        (0x40A7A2, 0x40A7A8, (0x40A7A2,)),
        (0x40A7A8, 0x40A7AE, (0x40A7A8, 0x40A7AA, 0x40A7AC)),
        (0x40A7AC, 0x40A7AE, (0x40A7AC,)),
        (0x40AEE6, 0x40AEF4, (0x40AEE6, 0x40AEEC, 0x40AEF2)),
        (0x40AEF4, 0x40AEFA, (0x40AEF4,)),
        (0x40AEFA, 0x40AF00, (0x40AEFA, 0x40AEFC, 0x40AEFE)),
        (0x40AEFE, 0x40AF00, (0x40AEFE,)),
    )
    added_blocks = tuple(
        FragmentBlock(
            block_id=f"native@0x{start_ea:X}",
            role=FragmentBlockRole.IMPORTED,
            materialization=FragmentBlockMaterialization.IMPORT_NATIVE,
            semantic_anchor_ea=start_ea,
            stable_identity=_identity(start_ea, end_ea, *exact_eas),
            native_body_id=body_id,
        )
        for start_ea, end_ea, exact_eas in added_ranges
    )
    selected_id = "rhad:route@0x40A792"
    table_proof_artifact = compiler.RhadSetccIndexedTableProofArtifact.from_mapping(
        _row17_table_proof_mapping()
    )
    selected = compiler.RhadSetccIndexedTableRoute(
        operation_id=selected_id,
        reference_order=17,
        operation_variant=compiler.RhadOperationVariant.SETCC_INDEXED_TABLE,
        reference_symbol="JumpInliner._fixup_index_access",
        source_block_id="native@0x40A77E",
        source_native_ea=0x40A77E,
        source_block_anchor_ea=0x40A77E,
        transfer_ea=0x40A792,
        condition_producer_ea=0x40A780,
        predicate_anchor_ea=0x40A786,
        predicate_kind=PredicateKind.SGE,
        fallthrough_delivery=(
            compiler.FragmentSetccFallthroughDelivery.PHYSICAL_ADJACENCY
        ),
        true_target_block_id="native@0x40AEE6",
        false_target_block_id="native@0x40A794",
        true_target_ea=0x40AEE6,
        false_target_ea=0x40A794,
        table_proof_artifact=table_proof_artifact,
        owned_corridor_instruction_eas=(
            0x40A77E,
            0x40A780,
            0x40A786,
            0x40A789,
            0x40A790,
            0x40A792,
        ),
        imported_closure_block_ids=tuple(block.block_id for block in added_blocks),
        boundary_exit_eas=(0x40A5F0,),
        flag_corridor_id="flags-intact@0x40A780",
        phase=compiler.RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
        depends_on=(fourth.operations[-1].operation_id,),
    )
    source_block_index = next(
        index
        for index, block in enumerate(base.blocks)
        if block.block_id == selected.source_block_id
    )
    ordered_blocks = (
        base.blocks[: source_block_index + 1]
        + added_blocks
        + base.blocks[source_block_index + 1 :]
    )
    source_body_index = body.block_ids.index(selected.source_block_id)
    all_block_ids = (
        body.block_ids[: source_body_index + 1]
        + tuple(block.block_id for block in added_blocks)
        + body.block_ids[source_body_index + 1 :]
    )
    operation_source_ids = {
        operation.source_block_id for operation in (*fourth.operations, selected)
    }
    expanded_body = FragmentNativeBody(
        body_id=body_id,
        block_ids=all_block_ids,
        entry_block_ids=body.entry_block_ids
        + tuple(block.block_id for block in added_blocks),
        terminal_block_ids=tuple(
            block_id
            for block_id in all_block_ids
            if block_id not in operation_source_ids
        ),
        native_ranges=tuple(
            sorted(
                body.native_ranges
                + (
                    NativeEaInterval(0x40A794, 0x40A7AE),
                    NativeEaInterval(0x40AEE6, 0x40AF00),
                ),
                key=lambda interval: int(interval.start_ea),
            )
        ),
        proof_ids=body.proof_ids + (selected_id,),
    )
    placeholder = FragmentOperation(
        operation_id=f"placeholder:{selected_id}",
        source_block_id=selected.source_block_id,
        edges=(
            FragmentEdge(
                role=SemanticEdgeRole.DIRECT,
                target_block_id=selected.false_target_block_id,
            ),
        ),
    )
    plan = replace(
        base,
        blocks=ordered_blocks,
        operations=base.operations + (placeholder,),
        work_item_scope=replace(
            base.work_item_scope,
            selected_obligation_ids=tuple(
                operation.operation_id for operation in (*fourth.operations, selected)
            ),
        ),
        native_bodies=(expanded_body,),
    )
    return compiler.RhadReferenceLedger(
        ledger_id="rhad-generated-reference@0x40A560:g1",
        function_ea=0x40A560,
        native_function_ea=0x40A560,
        evidence_generation=1,
        base_plan=plan,
        reference_oracle_run=_reference_run(),
        operations=(*fourth.operations, selected),
        required_boundary_exit_eas=(
            0x40A5F0,
            0x40A633,
            0x40A9A0,
            0x40AD6E,
            0x40B1D0,
            0x40B790,
        ),
        reference_provenance={
            "reference_commit": "21b0d4783703bc4fb6910cfae51d92cd683d2c65",
            "inventory_identity": "rhad-a560-indirect-jump-reference-inventory:v1",
            "setcc_proof_artifact_identities": (
                fourth.operations[-1].table_proof_artifact.content_identity,
                table_proof_artifact.content_identity,
            ),
        },
    )


def test_compiler_emits_scaled_lookup_setcc_route_for_row17() -> None:
    compiler = _compiler_module()
    ledger = _fifth_shape_ledger()

    plan = compiler.compile_rhad_reference_fragment(
        ledger,
        expected_evidence_generation=1,
    )

    operation = plan.operation("rhad:route@0x40A792")
    normalization = operation.computed_branch_normalization
    assert isinstance(
        normalization,
        fragment_plan.FragmentSetccIndexedTableNormalization,
    )
    assert isinstance(
        normalization.table_evidence.index_scaling,
        fragment_plan.FragmentSetccScaledLookupScaling,
    )
    assert normalization.table_evidence.index_scaling.lookup_ea == 0x40A789
    assert normalization.table_evidence.index_scaling.scale_bytes == 8
    assert operation.edges == (
        FragmentEdge(
            role=SemanticEdgeRole.CONDITIONAL_TAKEN,
            target_block_id="native@0x40AEE6",
        ),
        FragmentEdge(
            role=SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
            target_block_id="native@0x40A794",
        ),
    )
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert payload["reference_order"] == 17
    assert payload["proof_artifact"]["content_identity"] == (
        "sha256:a67a3d2cc432df11ca627c90f06f3a854004a9463a529ee1d0cdf1f759406e67"
    )
    assert payload["setcc_table"]["index_scaling"] == {
        "kind": "scaled_lookup",
        "lookup_ea": 0x40A789,
        "scale_bytes": 8,
    }
    assert plan.plan_id.endswith(ledger.aggregate_program_identity)


def test_compiler_rejects_setcc_without_false_target_physical_adjacency() -> None:
    compiler = _compiler_module()
    ledger = _fifth_shape_ledger()
    blocks = list(ledger.base_plan.blocks)
    source_index = next(
        index
        for index, block in enumerate(blocks)
        if block.block_id == "native@0x40A77E"
    )
    false_target = blocks.pop(source_index + 1)
    blocks.append(false_target)

    with pytest.raises(
        compiler.RhadCompilerRejection,
        match="false-target physical adjacency",
    ):
        compiler.compile_rhad_reference_fragment(
            replace(
                ledger,
                base_plan=replace(ledger.base_plan, blocks=tuple(blocks)),
            ),
            expected_evidence_generation=1,
        )


def test_compiler_accepts_typed_setcc_planned_helper_without_adjacency() -> None:
    compiler = _compiler_module()
    ledger = _fifth_shape_ledger()
    blocks = list(ledger.base_plan.blocks)
    source_index = next(
        index
        for index, block in enumerate(blocks)
        if block.block_id == "native@0x40A77E"
    )
    false_target = blocks.pop(source_index + 1)
    blocks.append(false_target)
    *dependencies, selected = ledger.operations
    helper_selected = replace(
        selected,
        fallthrough_delivery=(
            compiler.FragmentSetccFallthroughDelivery.PLANNED_HELPER
        ),
    )
    helper_ledger = replace(
        ledger,
        base_plan=replace(ledger.base_plan, blocks=tuple(blocks)),
        operations=(*dependencies, helper_selected),
    )

    plan = compiler.compile_rhad_reference_fragment(
        helper_ledger,
        expected_evidence_generation=1,
    )

    operation = plan.operation(helper_selected.operation_id)
    assert operation.requires_fallthrough_helper is True
    assert (
        operation.computed_branch_normalization.fallthrough_delivery
        is compiler.FragmentSetccFallthroughDelivery.PLANNED_HELPER
    )


def test_compiler_accepts_setcc_not_equal_predicate_kind() -> None:
    compiler = _compiler_module()
    ledger = _fifth_shape_ledger()
    *dependencies, selected = ledger.operations
    selected = replace(selected, predicate_kind=PredicateKind.NE)

    plan = compiler.compile_rhad_reference_fragment(
        replace(ledger, operations=(*dependencies, selected)),
        expected_evidence_generation=1,
    )

    assert (
        plan.operation(selected.operation_id).computed_branch_normalization.predicate_kind
        is PredicateKind.NE
    )


def test_compiler_rejects_unsupported_setcc_predicate_kind() -> None:
    compiler = _compiler_module()
    ledger = _fifth_shape_ledger()
    *dependencies, selected = ledger.operations

    with pytest.raises(
        compiler.RhadCompilerRejection, match="supported typed predicate"
    ):
        replace(selected, predicate_kind=PredicateKind.ULT)
