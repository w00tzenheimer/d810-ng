"""Portable semantic-fragment planning contract."""

from __future__ import annotations

from dataclasses import fields, replace

import pytest

from d810.core.semantic_route_oracle import (
    ReferenceRouteRewrite,
    RouteOracleRun,
    SemanticTransferKind,
)
from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
from d810.ir.expressions import ValueOpKind
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.ir.semantics import PredicateKind
from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
import d810.transforms.fragment_plan as fragment_plan
from d810.transforms.fragment_plan import (
    FragmentBlock,
    FragmentBlockMaterialization,
    FragmentBlockRole,
    FragmentComputedBranchNormalization,
    FragmentDataFlowObligation,
    FragmentDataFlowRole,
    FragmentDirectTransferRewrite,
    FragmentEdge,
    FragmentFlagCorridor,
    FragmentImportedConditionalSelectEnvelope,
    FragmentNativeBody,
    FragmentOperation,
    FragmentPlan,
    FragmentPlanRejected,
    FragmentPublicationPurpose,
    FragmentRangeAssumption,
    FragmentRangeObservation,
    FragmentStoragePredicateMaterialization,
    FragmentReferenceRouteAuthority,
    FragmentValueSite,
    FragmentWorkItemScope,
)
from tests.native_preanalysis import make_native_key


NATIVE_KEY = make_native_key(function_rva=0x40A560)
CONDITION_STORAGE = StorageIdentity(StorageIdentityKind.REGISTER, offset=0x10)


def _identity(start_ea: int, end_ea: int | None = None) -> StableBlockIdentity:
    end_ea = start_ea + 1 if end_ea is None else end_ea
    return StableBlockIdentity.from_intervals(
        (NativeEaInterval(start_ea, end_ea),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(start_ea,),
    )


def _native_block(
    block_id: str,
    role: FragmentBlockRole,
    start_ea: int,
    *,
    replaces: str | None = None,
) -> FragmentBlock:
    return FragmentBlock(
        block_id=block_id,
        role=role,
        materialization=(
            FragmentBlockMaterialization.CLONE_PUBLISHED
            if role is FragmentBlockRole.REPLACEMENT
            else FragmentBlockMaterialization.REUSE_PUBLISHED
        ),
        semantic_anchor_ea=start_ea,
        stable_identity=_identity(start_ea, start_ea + 0x10),
        replaces_block_id=replaces,
    )


def _valid_plan() -> FragmentPlan:
    original = _native_block(
        "predicate.original",
        FragmentBlockRole.ORIGINAL,
        0x40BECC,
    )
    replacement = FragmentBlock(
        block_id="predicate.replacement",
        role=FragmentBlockRole.REPLACEMENT,
        materialization=FragmentBlockMaterialization.CLONE_PUBLISHED,
        semantic_anchor_ea=0x40BECC,
        stable_identity=original.stable_identity,
        replaces_block_id=original.block_id,
    )
    true_target = _native_block(
        "handler.true",
        FragmentBlockRole.EXTERNAL,
        0x40C100,
    )
    false_target = _native_block(
        "handler.false",
        FragmentBlockRole.EXTERNAL,
        0x40C200,
    )
    dispatcher = _native_block(
        "dispatcher.residual",
        FragmentBlockRole.EXTERNAL,
        0x40C300,
    )
    condition_definition = FragmentValueSite(
        site_id="condition.flags",
        block_id=replacement.block_id,
        value_id="flags:consumer-choice",
        instruction_ea=0x40BECC,
        storage_identity=CONDITION_STORAGE,
        width=1,
    )
    condition_use = FragmentValueSite(
        site_id="condition.branch",
        block_id=replacement.block_id,
        value_id="flags:consumer-choice",
        instruction_ea=0x40BECD,
        storage_identity=CONDITION_STORAGE,
        width=1,
    )
    return FragmentPlan(
        plan_id="rhad-a560-consumer-route",
        atomic_group_id="consumer-route@0x40BECC",
        publication_purpose=FragmentPublicationPurpose.CANONICAL_SEMANTIC_LOWERING,
        native_key=NATIVE_KEY,
        blocks=(
            original,
            replacement,
            true_target,
            false_target,
            dispatcher,
        ),
        roots=(replacement.block_id,),
        owned_originals=(original.block_id,),
        prohibited_dispatcher_blocks=(dispatcher.block_id,),
        operations=(
            FragmentOperation(
                operation_id="publish-consumer-condition",
                source_block_id=replacement.block_id,
                predicate_anchor_ea=0x40BECD,
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.CONDITIONAL_TAKEN,
                        target_block_id=true_target.block_id,
                    ),
                    FragmentEdge(
                        role=SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
                        target_block_id=false_target.block_id,
                    ),
                ),
            ),
        ),
        data_flow_obligations=(
            FragmentDataFlowObligation(
                obligation_id="condition-use-def",
                role=FragmentDataFlowRole.CONDITION,
                definition=condition_definition,
                uses=(condition_use,),
            ),
        ),
        flag_corridors=(
            FragmentFlagCorridor(
                corridor_id="condition-flags",
                producer=condition_definition,
                consumer=condition_use,
                block_path=(replacement.block_id,),
                permitted_flag_write_eas=frozenset({0x40BECC}),
            ),
        ),
        value_range_assumptions=(
            FragmentRangeAssumption(
                assumption_id="condition-domain",
                site=condition_definition,
                observation=FragmentRangeObservation.AFTER_INSTRUCTION,
                lo=0,
                hi=1,
            ),
        ),
    )


def test_fragment_plan_requires_typed_publication_purpose() -> None:
    plan = _valid_plan()

    assert (
        plan.publication_purpose
        is FragmentPublicationPurpose.CANONICAL_SEMANTIC_LOWERING
    )
    with pytest.raises(TypeError, match="FragmentPublicationPurpose"):
        FragmentPlan(
            **{
                field.name: (
                    "frontend_normalization"
                    if field.name == "publication_purpose"
                    else getattr(plan, field.name)
                )
                for field in fields(FragmentPlan)
            }
        )


def test_replacement_root_may_own_exact_storage_predicate_materialization() -> None:
    plan = _valid_plan()
    operation = replace(
        plan.operations[0],
        predicate_anchor_ea=0x40BECC,
        storage_predicate_materialization=FragmentStoragePredicateMaterialization(
            predicate_kind=PredicateKind.EQ,
            storage_identity=StorageIdentity(StorageIdentityKind.STACK, 0x40),
            width=4,
            compare_constant=0xEC71CA67,
            cut_after_ea=0x40BECC,
        ),
    )

    plan = replace(plan, operations=(operation,))

    assert plan.operations == (operation,)
    assert plan.block(operation.source_block_id).role is FragmentBlockRole.REPLACEMENT


def test_fragment_plan_is_serial_free_and_groups_complete_conditional() -> None:
    plan = _valid_plan()

    assert plan.plan_id == "rhad-a560-consumer-route"
    assert plan.atomic_group_id == "consumer-route@0x40BECC"
    assert plan.operations[0].roles == frozenset(
        {
            SemanticEdgeRole.CONDITIONAL_TAKEN,
            SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
        }
    )

    forbidden_coordinate_names = {
        "serial",
        "mba",
        "mblock",
        "proxy",
        "version",
    }
    model_types = (
        FragmentBlock,
        FragmentEdge,
        FragmentImportedConditionalSelectEnvelope,
        FragmentDirectTransferRewrite,
        FragmentOperation,
        fragment_plan.FragmentReturnSource,
        fragment_plan.FragmentReturnCarrier,
        fragment_plan.FragmentTerminalReturn,
        fragment_plan.FragmentTerminalRoute,
        FragmentValueSite,
        FragmentDataFlowObligation,
        FragmentFlagCorridor,
        FragmentRangeAssumption,
        FragmentPlan,
    )
    for model_type in model_types:
        names = {field.name.lower() for field in fields(model_type)}
        assert forbidden_coordinate_names.isdisjoint(names)


def test_fragment_operation_supports_explicit_call_fallthrough() -> None:
    operation = FragmentOperation(
        operation_id="call-continuation",
        source_block_id="call",
        edges=(
            FragmentEdge(
                role=SemanticEdgeRole.CALL_FALLTHROUGH,
                target_block_id="continuation",
            ),
        ),
    )

    assert operation.roles == frozenset({SemanticEdgeRole.CALL_FALLTHROUGH})
    assert operation.predicate_anchor_ea is None


def test_direct_transfer_rewrite_separates_proof_origin_from_operation_owner() -> None:
    rewrite = FragmentDirectTransferRewrite(
        route_proof_id="flow_route:0x40BB63",
        owner_identity=_identity(0x40BB51, 0x40BB69),
        owner_anchor_ea=0x40BB51,
        rewrite_anchor_ea=0x40BB63,
        delivery_region=NativeEaInterval(0x40BB63, 0x40BB64),
        proof_corridor_instruction_eas=(0x40BB44, 0x40BB4B, 0x40BB63),
        superseded_instruction_eas=(0x40BB63,),
        source_transfer_kind=SemanticTransferKind.INDIRECT,
    )
    operation = FragmentOperation(
        operation_id="route:state_assignment@0x40BB63:0xE9795EF",
        source_block_id="native@0x40BB51",
        direct_transfer_rewrite=rewrite,
        edges=(
            FragmentEdge(
                role=SemanticEdgeRole.DIRECT,
                target_block_id="native@0x40ACF3",
            ),
        ),
    )

    assert operation.direct_transfer_rewrite is rewrite
    assert rewrite.owner_anchor_ea == 0x40BB51
    assert rewrite.proof_corridor_instruction_eas[0] == 0x40BB44
    assert rewrite.rewrite_anchor_ea == 0x40BB63
    assert rewrite.proof_corridor_instruction_eas[-1] == 0x40BB63
    assert rewrite.superseded_instruction_eas == (0x40BB63,)


def test_direct_transfer_rewrite_rejects_incomplete_or_conditional_ownership() -> None:
    with pytest.raises(FragmentPlanRejected, match="end at its rewrite anchor"):
        FragmentDirectTransferRewrite(
            route_proof_id="flow_route:0x40BB63",
            owner_identity=_identity(0x40BB44, 0x40BB64),
            owner_anchor_ea=0x40BB44,
            rewrite_anchor_ea=0x40BB63,
            delivery_region=NativeEaInterval(0x40BB63, 0x40BB64),
            proof_corridor_instruction_eas=(0x40BB44, 0x40BB4B),
            superseded_instruction_eas=(0x40BB63,),
            source_transfer_kind=SemanticTransferKind.INDIRECT,
        )

    with pytest.raises(FragmentPlanRejected, match="proof-corridor subset"):
        FragmentDirectTransferRewrite(
            route_proof_id="flow_route:0x40BB63",
            owner_identity=_identity(0x40BB44, 0x40BB64),
            owner_anchor_ea=0x40BB44,
            rewrite_anchor_ea=0x40BB63,
            delivery_region=NativeEaInterval(0x40BB63, 0x40BB64),
            proof_corridor_instruction_eas=(0x40BB44, 0x40BB63),
            superseded_instruction_eas=(0x40BB4B, 0x40BB63),
            source_transfer_kind=SemanticTransferKind.INDIRECT,
        )

    with pytest.raises(
        FragmentPlanRejected,
        match="owner must lie between its proof origin and rewrite anchor",
    ) as exc_info:
        FragmentDirectTransferRewrite(
            route_proof_id="flow_route:0x40BB63",
            owner_identity=_identity(0x40BB40, 0x40BB69),
            owner_anchor_ea=0x40BB40,
            rewrite_anchor_ea=0x40BB63,
            delivery_region=NativeEaInterval(0x40BB63, 0x40BB64),
            proof_corridor_instruction_eas=(0x40BB44, 0x40BB63),
            superseded_instruction_eas=(0x40BB63,),
            source_transfer_kind=SemanticTransferKind.INDIRECT,
        )
    assert exc_info.value.reason_code == "direct_transfer_owner_outside_corridor"
    assert exc_info.value.anchor_ea == 0x40BB63
    assert exc_info.value.payload == {
        "route_proof_id": "flow_route:0x40BB63",
        "owner_anchor_ea": "0x40BB40",
        "proof_origin_ea": "0x40BB44",
        "rewrite_anchor_ea": "0x40BB63",
    }

    with pytest.raises(FragmentPlanRejected, match="only to one direct edge"):
        FragmentOperation(
            operation_id="conditional-with-direct-rewrite",
            source_block_id="native@0x40BB51",
            predicate_anchor_ea=0x40BB63,
            direct_transfer_rewrite=FragmentDirectTransferRewrite(
                route_proof_id="flow_route:0x40BB63",
                owner_identity=_identity(0x40BB44, 0x40BB64),
                owner_anchor_ea=0x40BB44,
                rewrite_anchor_ea=0x40BB63,
                delivery_region=NativeEaInterval(0x40BB63, 0x40BB64),
                proof_corridor_instruction_eas=(0x40BB44, 0x40BB63),
                superseded_instruction_eas=(0x40BB63,),
                source_transfer_kind=SemanticTransferKind.CONDITIONAL,
            ),
            edges=(
                FragmentEdge(
                    role=SemanticEdgeRole.CONDITIONAL_TAKEN,
                    target_block_id="native@0x40C6F7",
                ),
                FragmentEdge(
                    role=SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
                    target_block_id="native@0x40BB69",
                ),
            ),
        )


def test_fragment_plan_rejects_competing_semantic_transfer_envelopes() -> None:
    plan = _valid_plan()
    direct_original = _native_block(
        "direct.original",
        FragmentBlockRole.ORIGINAL,
        0x40BEC0,
    )
    direct_replacement = FragmentBlock(
        block_id="direct.replacement",
        role=FragmentBlockRole.REPLACEMENT,
        materialization=FragmentBlockMaterialization.CLONE_PUBLISHED,
        semantic_anchor_ea=0x40BEC0,
        stable_identity=direct_original.stable_identity,
        replaces_block_id=direct_original.block_id,
    )
    direct_operation = FragmentOperation(
        operation_id="route:flow-route@0x40BECD",
        source_block_id=direct_replacement.block_id,
        direct_transfer_rewrite=FragmentDirectTransferRewrite(
            route_proof_id="flow-route@0x40BECD",
            owner_identity=_identity(0x40BECC, 0x40BECE),
            owner_anchor_ea=0x40BECC,
            rewrite_anchor_ea=0x40BECD,
            delivery_region=NativeEaInterval(0x40BECD, 0x40BECE),
            proof_corridor_instruction_eas=(0x40BECC, 0x40BECD),
            superseded_instruction_eas=(0x40BECD,),
            source_transfer_kind=SemanticTransferKind.INDIRECT,
        ),
        edges=(
            FragmentEdge(
                role=SemanticEdgeRole.DIRECT,
                target_block_id="handler.true",
            ),
        ),
    )

    with pytest.raises(
        FragmentPlanRejected,
        match="semantic transfer envelopes compete at 0x40BECD",
    ):
        replace(
            plan,
            blocks=plan.blocks + (direct_original, direct_replacement),
            owned_originals=plan.owned_originals + (direct_original.block_id,),
            operations=plan.operations + (direct_operation,),
        )


def test_fragment_plan_allows_preserved_proof_corridor_overlap() -> None:
    plan = _valid_plan()
    direct_original = _native_block(
        "direct.original",
        FragmentBlockRole.ORIGINAL,
        0x40BEC0,
    )
    direct_replacement = FragmentBlock(
        block_id="direct.replacement",
        role=FragmentBlockRole.REPLACEMENT,
        materialization=FragmentBlockMaterialization.CLONE_PUBLISHED,
        semantic_anchor_ea=0x40BEC0,
        stable_identity=direct_original.stable_identity,
        replaces_block_id=direct_original.block_id,
    )
    direct_operation = FragmentOperation(
        operation_id="route:flow-route@0x40BECF",
        source_block_id=direct_replacement.block_id,
        direct_transfer_rewrite=FragmentDirectTransferRewrite(
            route_proof_id="flow-route@0x40BECF",
            owner_identity=_identity(0x40BECC, 0x40BED0),
            owner_anchor_ea=0x40BECC,
            rewrite_anchor_ea=0x40BECF,
            delivery_region=NativeEaInterval(0x40BECF, 0x40BED0),
            proof_corridor_instruction_eas=(
                0x40BECC,
                0x40BECD,
                0x40BECF,
            ),
            superseded_instruction_eas=(0x40BECF,),
            source_transfer_kind=SemanticTransferKind.INDIRECT,
        ),
        edges=(
            FragmentEdge(
                role=SemanticEdgeRole.DIRECT,
                target_block_id="handler.true",
            ),
        ),
    )

    rebuilt = replace(
        plan,
        blocks=plan.blocks + (direct_original, direct_replacement),
        owned_originals=plan.owned_originals + (direct_original.block_id,),
        operations=plan.operations + (direct_operation,),
    )

    assert rebuilt.operations[-1] is direct_operation


def test_fragment_plan_rejects_direct_rewrite_outside_canonical_lowering() -> None:
    plan = _valid_plan()
    direct_operation = FragmentOperation(
        operation_id="route:flow-route@0x40BECC",
        source_block_id="predicate.replacement",
        direct_transfer_rewrite=FragmentDirectTransferRewrite(
            route_proof_id="flow-route@0x40BECC",
            owner_identity=_identity(0x40BECC),
            owner_anchor_ea=0x40BECC,
            rewrite_anchor_ea=0x40BECC,
            delivery_region=NativeEaInterval(0x40BECC, 0x40BECD),
            proof_corridor_instruction_eas=(0x40BECC,),
            superseded_instruction_eas=(0x40BECC,),
            source_transfer_kind=SemanticTransferKind.INDIRECT,
        ),
        edges=(
            FragmentEdge(
                role=SemanticEdgeRole.DIRECT,
                target_block_id="handler.true",
            ),
        ),
    )

    with pytest.raises(
        FragmentPlanRejected,
        match="requires owned canonical route proof",
    ):
        replace(
            plan,
            publication_purpose=(FragmentPublicationPurpose.FRONTEND_NORMALIZATION),
            work_item_scope=FragmentWorkItemScope(
                work_item_id="frontend-normalization:g1:direct",
                selected_obligation_ids=("route@0x40BECC",),
                remaining_obligation_ids=(),
                unreachable_obligation_ids=(),
            ),
            operations=(direct_operation,),
            data_flow_obligations=(),
            flag_corridors=(),
            value_range_assumptions=(),
        )


def _referenced_frontend_direct_plan() -> FragmentPlan:
    fixture_sha256 = "a" * 64
    native_key = make_native_key(
        input_identity=f"sha256:{fixture_sha256}",
        function_rva=0x40A560,
    )

    def identity(start_ea: int, end_ea: int) -> StableBlockIdentity:
        return StableBlockIdentity.from_intervals(
            (NativeEaInterval(start_ea, end_ea),),
            native_key=native_key,
            exact_instruction_eas=(start_ea,),
        )

    operation_id = "route:rhad-direct@0x40A619"
    body_id = "rhad-a560-generated-native-body"
    root_identity = identity(0x40A607, 0x40A619)
    original = FragmentBlock(
        block_id="native-original@0x40A607",
        role=FragmentBlockRole.ORIGINAL,
        materialization=FragmentBlockMaterialization.REUSE_PUBLISHED,
        semantic_anchor_ea=0x40A607,
        stable_identity=root_identity,
    )
    replacement = FragmentBlock(
        block_id="native@0x40A607",
        role=FragmentBlockRole.REPLACEMENT,
        materialization=FragmentBlockMaterialization.CLONE_PUBLISHED,
        semantic_anchor_ea=0x40A607,
        stable_identity=root_identity,
        replaces_block_id=original.block_id,
    )
    source_identity = identity(0x40A619, 0x40A61B)
    source = FragmentBlock(
        block_id="native@0x40A619",
        role=FragmentBlockRole.IMPORTED,
        materialization=FragmentBlockMaterialization.IMPORT_NATIVE,
        semantic_anchor_ea=0x40A619,
        stable_identity=source_identity,
        native_body_id=body_id,
    )
    target = FragmentBlock(
        block_id="native@0x40A61B",
        role=FragmentBlockRole.IMPORTED,
        materialization=FragmentBlockMaterialization.IMPORT_NATIVE,
        semantic_anchor_ea=0x40A61B,
        stable_identity=identity(0x40A61B, 0x40A62D),
        native_body_id=body_id,
    )
    reference_route = ReferenceRouteRewrite(
        route_id=operation_id,
        function_ea=0x40A560,
        owner_ea=0x40A619,
        rewrite_anchor_ea=0x40A619,
        corridor=((0x40A619, 0x40A61B),),
        reference_phase="indirect_jump_reconstruction",
        original_transfer_kind=SemanticTransferKind.INDIRECT,
        final_transfer_kind=SemanticTransferKind.DIRECT,
        direct_target_ea=0x40A61B,
        reference_ledger_identity="rhad-generated-reference@0x40A560:g1",
    )
    operation = FragmentOperation(
        operation_id=operation_id,
        source_block_id=source.block_id,
        edges=(
            FragmentEdge(
                role=SemanticEdgeRole.DIRECT,
                target_block_id=target.block_id,
            ),
        ),
        direct_transfer_rewrite=FragmentDirectTransferRewrite(
            route_proof_id="rhad-direct@0x40A619",
            owner_identity=source_identity,
            owner_anchor_ea=0x40A619,
            rewrite_anchor_ea=0x40A619,
            delivery_region=NativeEaInterval(0x40A619, 0x40A61B),
            proof_corridor_instruction_eas=(0x40A619,),
            superseded_instruction_eas=(0x40A619,),
            source_transfer_kind=SemanticTransferKind.INDIRECT,
        ),
        reference_route_authority=FragmentReferenceRouteAuthority(
            reference_route=reference_route,
            candidate_rewrite_anchor_ea=0x40A619,
            imported_closure_block_ids=(),
        ),
    )
    return FragmentPlan(
        plan_id="rhad-a560-generated-two-operation-base",
        atomic_group_id="rhad-a560-generated-two-operation:g1",
        publication_purpose=FragmentPublicationPurpose.FRONTEND_NORMALIZATION,
        native_key=native_key,
        blocks=(original, replacement, source, target),
        roots=(replacement.block_id,),
        owned_originals=(original.block_id,),
        prohibited_dispatcher_blocks=(),
        operations=(
            FragmentOperation(
                operation_id="publish-native@0x40A607",
                source_block_id=replacement.block_id,
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.DIRECT,
                        target_block_id=source.block_id,
                    ),
                ),
            ),
            operation,
        ),
        work_item_scope=FragmentWorkItemScope(
            work_item_id="rhad-generated-reference:g1",
            selected_obligation_ids=(operation_id,),
            remaining_obligation_ids=(),
            unreachable_obligation_ids=(),
        ),
        native_bodies=(
            FragmentNativeBody(
                body_id=body_id,
                block_ids=(source.block_id, target.block_id),
                entry_block_ids=(source.block_id, target.block_id),
                terminal_block_ids=(target.block_id,),
                native_ranges=(
                    NativeEaInterval(0x40A619, 0x40A61B),
                    NativeEaInterval(0x40A61B, 0x40A62D),
                ),
                proof_ids=(operation_id,),
            ),
        ),
        reference_oracle_run=RouteOracleRun(
            run_id="rhad-a560-generated-two-operation",
            function_ea=0x40A560,
            fixture_sha256=fixture_sha256,
            reference_binary_sha256="b" * 64,
            candidate_binary_sha256=fixture_sha256,
            reference_commit="21b0d4783703bc4fb6910cfae51d92cd683d2c65",
            runtime_image="d810-idapro-9.3-test-runtime:py313-v1",
            runtime_image_id="sha256:" + "c" * 64,
            cache_disabled=True,
        ),
    )


def test_fragment_plan_admits_reference_owned_frontend_imported_direct_route() -> None:
    plan = _referenced_frontend_direct_plan()

    operation = plan.operation("route:rhad-direct@0x40A619")
    assert plan.publication_purpose is FragmentPublicationPurpose.FRONTEND_NORMALIZATION
    assert operation.source_block_id == "native@0x40A619"
    assert operation.edges[0].target_block_id == "native@0x40A61B"


@pytest.mark.parametrize(
    "missing_contract",
    ("reference_authority", "native_body_proof", "selected_obligation", "oracle_run"),
)
def test_fragment_plan_rejects_incomplete_referenced_frontend_direct_route(
    missing_contract: str,
) -> None:
    plan = _referenced_frontend_direct_plan()
    entry_operation, direct_operation = plan.operations
    changes: dict[str, object]
    if missing_contract == "reference_authority":
        changes = {
            "operations": (
                entry_operation,
                replace(direct_operation, reference_route_authority=None),
            )
        }
    elif missing_contract == "native_body_proof":
        changes = {
            "native_bodies": (
                replace(plan.native_bodies[0], proof_ids=("unrelated-proof",)),
            )
        }
    elif missing_contract == "selected_obligation":
        changes = {
            "work_item_scope": replace(
                plan.work_item_scope,
                selected_obligation_ids=("unrelated-obligation",),
            )
        }
    else:
        changes = {"reference_oracle_run": None}

    with pytest.raises(
        FragmentPlanRejected,
        match="referenced frontend route proof",
    ):
        replace(plan, **changes)


def test_fragment_plan_rejects_foreign_oracle_for_frontend_direct_route() -> None:
    plan = _referenced_frontend_direct_plan()

    with pytest.raises(FragmentPlanRejected, match="oracle authority"):
        replace(
            plan,
            reference_oracle_run=replace(
                plan.reference_oracle_run,
                candidate_binary_sha256="d" * 64,
            ),
        )


def test_work_item_scope_keeps_root_unreachable_obligations_disjoint() -> None:
    scope = FragmentWorkItemScope(
        work_item_id="frontend-normalization:g1:reachable",
        selected_obligation_ids=("route@0x401000",),
        remaining_obligation_ids=("route@0x402000",),
        unreachable_obligation_ids=("route@0x403000",),
    )

    assert scope.unreachable_obligation_ids == ("route@0x403000",)
    with pytest.raises(FragmentPlanRejected, match="root-unreachable.*disjoint"):
        FragmentWorkItemScope(
            work_item_id="frontend-normalization:g1:overlap",
            selected_obligation_ids=("route@0x401000",),
            remaining_obligation_ids=(),
            unreachable_obligation_ids=("route@0x401000",),
        )


def test_fragment_operation_carries_typed_computed_branch_normalization() -> None:
    normalization = FragmentComputedBranchNormalization(
        predicate_kind=PredicateKind.EQ,
        normalization_start_ea=0x40AE2E,
        condition_producer_ea=0x40AE28,
        unresolved_transfer_ea=0x40AE3C,
    )
    operation = FragmentOperation(
        operation_id="native-indirect-transfer@0x40AE3C",
        source_block_id="native@0x40AE26",
        predicate_anchor_ea=0x40AE2E,
        computed_branch_normalization=normalization,
        edges=(
            FragmentEdge(
                role=SemanticEdgeRole.CONDITIONAL_TAKEN,
                target_block_id="native@0x40AE3E",
            ),
            FragmentEdge(
                role=SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
                target_block_id="native@0x40A5F0",
            ),
        ),
    )

    assert operation.computed_branch_normalization is normalization


def test_setcc_indexed_table_normalization_persists_exact_target_derivation() -> None:
    assert hasattr(fragment_plan, "FragmentSetccIndexedTableEntry"), (
        "setcc table entries require a dedicated portable type"
    )
    assert hasattr(fragment_plan, "FragmentSetccIndexedTableEvidence"), (
        "setcc table derivation requires dedicated portable evidence"
    )
    assert hasattr(fragment_plan, "FragmentSetccIndexedTableNormalization"), (
        "setcc table routes require a dedicated normalization subtype"
    )
    assert hasattr(fragment_plan, "FragmentSetccIndexExtensionKind")
    assert hasattr(fragment_plan, "FragmentTableByteOrder")
    assert hasattr(fragment_plan, "FragmentTableEntryInterpretation")

    entries = (
        fragment_plan.FragmentSetccIndexedTableEntry(
            index=0,
            entry_ea=0x48B81C,
            raw_value=0x02528F45,
            decoded_target_ea=0x40ABC6,
        ),
        fragment_plan.FragmentSetccIndexedTableEntry(
            index=1,
            entry_ea=0x48B83C,
            raw_value=0x02528AFD,
            decoded_target_ea=0x40A77E,
        ),
    )
    evidence = fragment_plan.FragmentSetccIndexedTableEvidence(
        table_identity="native-table@0x48B81C:stride-0x20:u32le:add-esi",
        zeroing_ea=0x40A766,
        zeroed_width_bits=32,
        setcc_ea=0x40A76E,
        setcc_destination_width_bits=8,
        extension_kind=(
            fragment_plan.FragmentSetccIndexExtensionKind.ZERO_EXTEND_BY_FULL_REGISTER_PREZERO
        ),
        index_width_bits=32,
        shift_ea=0x40A771,
        shift_bits=5,
        lookup_ea=0x40A774,
        table_base_ea=0x48B81C,
        stride_bytes=32,
        entry_width_bytes=4,
        byte_order=fragment_plan.FragmentTableByteOrder.LITTLE,
        interpretation=(
            fragment_plan.FragmentTableEntryInterpretation.ADD_CONSTANT_MODULO_ENTRY_WIDTH
        ),
        decode_ea=0x40A77A,
        additive_key_producer_ea=0x40A5BD,
        additive_key=0xFDEE1C81,
        true_index=1,
        false_index=0,
        entries=entries,
    )
    normalization = fragment_plan.FragmentSetccIndexedTableNormalization(
        predicate_kind=PredicateKind.SLT,
        normalization_start_ea=0x40A76E,
        condition_producer_ea=0x40A768,
        unresolved_transfer_ea=0x40A77C,
        table_evidence=evidence,
    )

    assert normalization.table_evidence.entries == entries
    assert normalization.table_evidence.true_entry.decoded_target_ea == 0x40A77E
    assert normalization.table_evidence.false_entry.decoded_target_ea == 0x40ABC6


@pytest.mark.parametrize(
    ("field_name", "wrong_value", "message"),
    (
        ("stride_bytes", 16, "shift.*stride"),
        ("table_base_ea", 0x48B820, "entry address"),
        ("additive_key", 0xFDEE1C80, "decoded target"),
        ("true_index", 0, "distinct Boolean indices"),
    ),
)
def test_setcc_indexed_table_rejects_inconsistent_derivation(
    field_name,
    wrong_value,
    message,
) -> None:
    assert hasattr(fragment_plan, "FragmentSetccIndexedTableEvidence")
    entries = (
        fragment_plan.FragmentSetccIndexedTableEntry(
            index=0,
            entry_ea=0x48B81C,
            raw_value=0x02528F45,
            decoded_target_ea=0x40ABC6,
        ),
        fragment_plan.FragmentSetccIndexedTableEntry(
            index=1,
            entry_ea=0x48B83C,
            raw_value=0x02528AFD,
            decoded_target_ea=0x40A77E,
        ),
    )
    kwargs = {
        "table_identity": "native-table@0x48B81C:stride-0x20:u32le:add-esi",
        "zeroing_ea": 0x40A766,
        "zeroed_width_bits": 32,
        "setcc_ea": 0x40A76E,
        "setcc_destination_width_bits": 8,
        "extension_kind": (
            fragment_plan.FragmentSetccIndexExtensionKind.ZERO_EXTEND_BY_FULL_REGISTER_PREZERO
        ),
        "index_width_bits": 32,
        "shift_ea": 0x40A771,
        "shift_bits": 5,
        "lookup_ea": 0x40A774,
        "table_base_ea": 0x48B81C,
        "stride_bytes": 32,
        "entry_width_bytes": 4,
        "byte_order": fragment_plan.FragmentTableByteOrder.LITTLE,
        "interpretation": (
            fragment_plan.FragmentTableEntryInterpretation.ADD_CONSTANT_MODULO_ENTRY_WIDTH
        ),
        "decode_ea": 0x40A77A,
        "additive_key_producer_ea": 0x40A5BD,
        "additive_key": 0xFDEE1C81,
        "true_index": 1,
        "false_index": 0,
        "entries": entries,
    }
    kwargs[field_name] = wrong_value

    with pytest.raises(FragmentPlanRejected, match=message):
        fragment_plan.FragmentSetccIndexedTableEvidence(**kwargs)


@pytest.mark.parametrize(
    "relocated_instruction_eas",
    (
        (0x40AE36, 0x40AE34),
        (0x40AE34, 0x40AE34),
        (0x40AE2E,),
        (0x40AE3C,),
    ),
)
def test_computed_branch_rejects_unowned_relocated_instruction_inventory(
    relocated_instruction_eas,
) -> None:
    with pytest.raises(
        FragmentPlanRejected,
        match="ordered unique anchors inside the normalization extent",
    ):
        FragmentComputedBranchNormalization(
            predicate_kind=PredicateKind.EQ,
            normalization_start_ea=0x40AE2E,
            condition_producer_ea=0x40AE28,
            unresolved_transfer_ea=0x40AE3C,
            relocated_instruction_eas=relocated_instruction_eas,
        )


def test_direct_rewrite_rejects_unpaired_source_normalization() -> None:
    normalization = FragmentComputedBranchNormalization(
        predicate_kind=PredicateKind.SLT,
        normalization_start_ea=0x40ADFD,
        condition_producer_ea=0x40ADF7,
        unresolved_transfer_ea=0x40AE18,
        relocated_instruction_eas=(0x40AE0C, 0x40AE0E, 0x40AE12, 0x40AE16),
    )

    with pytest.raises(
        FragmentPlanRejected,
        match="source normalization requires its predicate anchor",
    ):
        FragmentDirectTransferRewrite(
            route_proof_id="state_assignment@0x40AE09:0xF6A636EF",
            owner_identity=_identity(0x40ADF2),
            owner_anchor_ea=0x40ADF2,
            rewrite_anchor_ea=0x40AE09,
            delivery_region=NativeEaInterval(0x40ADFD, 0x40AE1A),
            proof_corridor_instruction_eas=(0x40ADF2, 0x40ADF7, 0x40AE09),
            superseded_instruction_eas=(0x40AE09,),
            source_transfer_kind=SemanticTransferKind.CONDITIONAL,
            source_computed_branch_normalization=normalization,
        )


def test_direct_rewrite_rejects_indirect_kind_with_conditional_normalization() -> None:
    normalization = FragmentComputedBranchNormalization(
        predicate_kind=PredicateKind.SLT,
        normalization_start_ea=0x40ADFD,
        condition_producer_ea=0x40ADF7,
        unresolved_transfer_ea=0x40AE18,
        relocated_instruction_eas=(),
    )

    with pytest.raises(
        FragmentPlanRejected,
        match="conditional normalization requires a conditional source kind",
    ):
        FragmentDirectTransferRewrite(
            route_proof_id="state_assignment@0x40AE09:0xF6A636EF",
            owner_identity=_identity(0x40ADF2),
            owner_anchor_ea=0x40ADF2,
            rewrite_anchor_ea=0x40AE09,
            delivery_region=NativeEaInterval(0x40ADFD, 0x40AE1A),
            proof_corridor_instruction_eas=(0x40ADF2, 0x40ADF7, 0x40AE09),
            superseded_instruction_eas=(0x40AE09,),
            source_transfer_kind=SemanticTransferKind.INDIRECT,
            source_computed_branch_normalization=normalization,
            source_predicate_anchor_ea=0x40AE09,
        )


def _same_ea_imported_conditional_plan(
    *,
    selected_identity: StableBlockIdentity | None = None,
) -> FragmentPlan:
    original = _native_block(
        "entry.original",
        FragmentBlockRole.ORIGINAL,
        0x4000,
    )
    replacement = FragmentBlock(
        block_id="entry.replacement",
        role=FragmentBlockRole.REPLACEMENT,
        materialization=FragmentBlockMaterialization.CLONE_PUBLISHED,
        semantic_anchor_ea=0x4000,
        stable_identity=original.stable_identity,
        replaces_block_id=original.block_id,
    )
    source_identity = StableBlockIdentity.from_intervals(
        (
            NativeEaInterval(0x5000, 0x5001),
            NativeEaInterval(0x5002, 0x5003),
            NativeEaInterval(0x5004, 0x5005),
            NativeEaInterval(0x5006, 0x5007),
        ),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x5000, 0x5002, 0x5004, 0x5006),
    )
    source = FragmentBlock(
        block_id="split.imported",
        role=FragmentBlockRole.IMPORTED,
        materialization=FragmentBlockMaterialization.IMPORT_NATIVE,
        semantic_anchor_ea=0x5000,
        stable_identity=source_identity,
        native_body_id="native-body:split",
    )
    selected_identity = selected_identity or _identity(0x5006)
    join_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x5010, 0x5013),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x5010, 0x5012),
    )
    taken = _native_block(
        "split.taken",
        FragmentBlockRole.EXTERNAL,
        0x6000,
    )
    fallthrough = _native_block(
        "split.fallthrough",
        FragmentBlockRole.EXTERNAL,
        0x7000,
    )
    operation_id = "native-indirect-transfer@0x5012"
    return FragmentPlan(
        plan_id="canonical-same-ea-split",
        atomic_group_id="canonical-same-ea-split:g1",
        publication_purpose=(FragmentPublicationPurpose.CANONICAL_SEMANTIC_LOWERING),
        native_key=NATIVE_KEY,
        blocks=(original, replacement, source, taken, fallthrough),
        roots=(replacement.block_id,),
        owned_originals=(original.block_id,),
        prohibited_dispatcher_blocks=(),
        operations=(
            FragmentOperation(
                operation_id="entry-route",
                source_block_id=replacement.block_id,
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.DIRECT,
                        target_block_id=source.block_id,
                    ),
                ),
            ),
            FragmentOperation(
                operation_id=operation_id,
                source_block_id=source.block_id,
                predicate_anchor_ea=0x5002,
                computed_branch_normalization=(
                    FragmentComputedBranchNormalization(
                        predicate_kind=PredicateKind.SLT,
                        normalization_start_ea=0x5002,
                        condition_producer_ea=0x5000,
                        unresolved_transfer_ea=0x5012,
                        conditional_select_envelope=(
                            FragmentImportedConditionalSelectEnvelope(
                                source_branch_ea=0x5006,
                                selected_value_ea=0x5006,
                                selected_value_identity=selected_identity,
                                join_identity=join_identity,
                            )
                        ),
                    )
                ),
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.CONDITIONAL_TAKEN,
                        target_block_id=taken.block_id,
                    ),
                    FragmentEdge(
                        role=SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
                        target_block_id=fallthrough.block_id,
                    ),
                ),
            ),
        ),
        native_bodies=(
            FragmentNativeBody(
                body_id="native-body:split",
                block_ids=(source.block_id,),
                entry_block_ids=(source.block_id,),
                terminal_block_ids=(),
                native_ranges=(
                    NativeEaInterval(0x5000, 0x5007),
                    NativeEaInterval(0x5010, 0x5013),
                ),
                proof_ids=(operation_id,),
            ),
        ),
    )


def test_imported_conditional_select_allows_one_role_shared_ea() -> None:
    plan = _same_ea_imported_conditional_plan()

    operation = plan.operations[1]
    normalization = operation.computed_branch_normalization
    assert normalization is not None
    envelope = normalization.conditional_select_envelope
    assert isinstance(envelope, FragmentImportedConditionalSelectEnvelope)
    assert envelope.source_branch_ea == envelope.selected_value_ea == 0x5006


def test_imported_conditional_select_rejects_wider_role_overlap() -> None:
    selected_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x5004, 0x5007),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x5004, 0x5006),
    )

    with pytest.raises(
        FragmentPlanRejected,
        match="overlaps outside its one role-shared source/select EA",
    ):
        _same_ea_imported_conditional_plan(
            selected_identity=selected_identity,
        )


def test_direct_fragment_operation_rejects_computed_branch_normalization() -> None:
    with pytest.raises(FragmentPlanRejected, match="complete conditional"):
        FragmentOperation(
            operation_id="invalid-direct-normalization",
            source_block_id="source",
            computed_branch_normalization=FragmentComputedBranchNormalization(
                predicate_kind=PredicateKind.EQ,
                normalization_start_ea=0x40AE2E,
                condition_producer_ea=0x40AE28,
                unresolved_transfer_ea=0x40AE3C,
            ),
            edges=(
                FragmentEdge(
                    role=SemanticEdgeRole.DIRECT,
                    target_block_id="target",
                ),
            ),
        )


def test_canonical_live_replacement_rejects_frontend_branch_normalization() -> None:
    plan = _valid_plan()
    (operation,) = plan.operations
    normalization = FragmentComputedBranchNormalization(
        predicate_kind=PredicateKind.EQ,
        normalization_start_ea=0x40BECE,
        condition_producer_ea=0x40BECF,
        unresolved_transfer_ea=0x40BED0,
    )

    with pytest.raises(
        FragmentPlanRejected,
        match=(
            "canonical computed branch normalization requires "
            "imported native-body proof"
        ),
    ):
        replace(
            plan,
            operations=(
                replace(
                    operation,
                    computed_branch_normalization=normalization,
                ),
            ),
        )


def test_fragment_block_materialization_is_explicit_and_role_complete() -> None:
    plan = _valid_plan()

    assert {block.role: block.materialization for block in plan.blocks} == {
        FragmentBlockRole.ORIGINAL: FragmentBlockMaterialization.REUSE_PUBLISHED,
        FragmentBlockRole.REPLACEMENT: FragmentBlockMaterialization.CLONE_PUBLISHED,
        FragmentBlockRole.EXTERNAL: FragmentBlockMaterialization.REUSE_PUBLISHED,
    }

    with pytest.raises(FragmentPlanRejected, match="replacement.*clone"):
        FragmentBlock(
            block_id="invalid.replacement",
            role=FragmentBlockRole.REPLACEMENT,
            materialization=FragmentBlockMaterialization.REUSE_PUBLISHED,
            semantic_anchor_ea=0x40BECC,
            stable_identity=plan.block("predicate.original").stable_identity,
            replaces_block_id="predicate.original",
        )

    with pytest.raises(FragmentPlanRejected, match="synthetic.*empty"):
        FragmentBlock(
            block_id="invalid.synthetic",
            role=FragmentBlockRole.SYNTHETIC,
            materialization=FragmentBlockMaterialization.REUSE_PUBLISHED,
            semantic_anchor_ea=0x40D000,
        )


def test_fragment_block_anchor_rejection_identifies_portable_owner() -> None:
    identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40C89B, 0x40C8A2),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x40C89B, 0x40C89C, 0x40C89D, 0x40C89E),
    )

    with pytest.raises(FragmentPlanRejected) as exc_info:
        FragmentBlock(
            block_id="native-terminal@0x40C898",
            role=FragmentBlockRole.IMPORTED,
            materialization=FragmentBlockMaterialization.IMPORT_NATIVE,
            semantic_anchor_ea=0x40C898,
            stable_identity=identity,
            native_body_id="rhad-a560-terminal",
        )

    rejection = exc_info.value
    assert rejection.reason_code == ("fragment_block_semantic_anchor_identity_mismatch")
    assert rejection.anchor_ea == 0x40C898
    assert rejection.payload == {
        "block_id": "native-terminal@0x40C898",
        "block_role": FragmentBlockRole.IMPORTED.value,
        "block_materialization": FragmentBlockMaterialization.IMPORT_NATIVE.value,
        "semantic_anchor_ea": "0x40C898",
        "stable_identity": identity.diagnostic_label(),
    }


def test_fragment_plan_rejects_partial_conditional_operation() -> None:
    with pytest.raises(FragmentPlanRejected, match="both conditional roles"):
        FragmentOperation(
            operation_id="partial-condition",
            source_block_id="source",
            predicate_anchor_ea=0x40BECD,
            edges=(
                FragmentEdge(
                    role=SemanticEdgeRole.CONDITIONAL_TAKEN,
                    target_block_id="target",
                ),
            ),
        )


def test_fragment_plan_rejects_direct_operation_with_predicate() -> None:
    with pytest.raises(FragmentPlanRejected, match="predicate belongs only"):
        FragmentOperation(
            operation_id="direct-with-predicate",
            source_block_id="source",
            predicate_anchor_ea=0x40BECD,
            edges=(
                FragmentEdge(
                    role=SemanticEdgeRole.DIRECT,
                    target_block_id="target",
                ),
            ),
        )


def test_fragment_plan_rejects_multiple_operations_for_one_source() -> None:
    plan = _valid_plan()
    duplicate_source = FragmentOperation(
        operation_id="second-condition",
        source_block_id=plan.operations[0].source_block_id,
        predicate_anchor_ea=plan.operations[0].predicate_anchor_ea,
        edges=plan.operations[0].edges,
    )

    with pytest.raises(
        FragmentPlanRejected, match="duplicate fragment operation source"
    ):
        FragmentPlan(
            plan_id=plan.plan_id,
            atomic_group_id=plan.atomic_group_id,
            publication_purpose=plan.publication_purpose,
            native_key=plan.native_key,
            blocks=plan.blocks,
            roots=plan.roots,
            owned_originals=plan.owned_originals,
            prohibited_dispatcher_blocks=plan.prohibited_dispatcher_blocks,
            operations=plan.operations + (duplicate_source,),
            data_flow_obligations=plan.data_flow_obligations,
            flag_corridors=plan.flag_corridors,
            value_range_assumptions=plan.value_range_assumptions,
        )


def test_fragment_plan_requires_replacement_identity_to_match_original() -> None:
    plan = _valid_plan()
    original = plan.block("predicate.original")
    mismatched_replacement = FragmentBlock(
        block_id="predicate.replacement",
        role=FragmentBlockRole.REPLACEMENT,
        materialization=FragmentBlockMaterialization.CLONE_PUBLISHED,
        semantic_anchor_ea=0x40D000,
        stable_identity=_identity(0x40D000, 0x40D010),
        replaces_block_id=original.block_id,
    )

    with pytest.raises(FragmentPlanRejected, match="stable identity must match"):
        FragmentPlan(
            plan_id=plan.plan_id,
            atomic_group_id=plan.atomic_group_id,
            publication_purpose=plan.publication_purpose,
            native_key=plan.native_key,
            blocks=tuple(
                mismatched_replacement
                if block.role is FragmentBlockRole.REPLACEMENT
                else block
                for block in plan.blocks
            ),
            roots=plan.roots,
            owned_originals=plan.owned_originals,
            prohibited_dispatcher_blocks=plan.prohibited_dispatcher_blocks,
            operations=plan.operations,
            data_flow_obligations=plan.data_flow_obligations,
            flag_corridors=plan.flag_corridors,
            value_range_assumptions=plan.value_range_assumptions,
        )


def test_fragment_plan_requires_owned_original_for_every_replacement() -> None:
    plan = _valid_plan()

    with pytest.raises(FragmentPlanRejected, match="must own its replaced original"):
        FragmentPlan(
            plan_id=plan.plan_id,
            atomic_group_id=plan.atomic_group_id,
            publication_purpose=plan.publication_purpose,
            native_key=plan.native_key,
            blocks=plan.blocks,
            roots=plan.roots,
            owned_originals=(),
            prohibited_dispatcher_blocks=plan.prohibited_dispatcher_blocks,
            operations=plan.operations,
            data_flow_obligations=plan.data_flow_obligations,
            flag_corridors=plan.flag_corridors,
            value_range_assumptions=plan.value_range_assumptions,
        )


def test_fragment_plan_requires_all_references_to_belong_to_the_plan() -> None:
    plan = _valid_plan()
    invalid_operation = FragmentOperation(
        operation_id="unknown-target",
        source_block_id="predicate.replacement",
        edges=(
            FragmentEdge(
                role=SemanticEdgeRole.DIRECT,
                target_block_id="missing.block",
            ),
        ),
    )

    with pytest.raises(FragmentPlanRejected, match="unknown target block"):
        FragmentPlan(
            plan_id=plan.plan_id,
            atomic_group_id=plan.atomic_group_id,
            publication_purpose=plan.publication_purpose,
            native_key=plan.native_key,
            blocks=plan.blocks,
            roots=plan.roots,
            owned_originals=plan.owned_originals,
            prohibited_dispatcher_blocks=plan.prohibited_dispatcher_blocks,
            operations=(invalid_operation,),
            data_flow_obligations=plan.data_flow_obligations,
            flag_corridors=plan.flag_corridors,
            value_range_assumptions=plan.value_range_assumptions,
        )


def test_fragment_plan_rejects_cross_function_stable_identity() -> None:
    plan = _valid_plan()
    other_key = make_native_key(function_rva=0x40D200)
    foreign = FragmentBlock(
        block_id="foreign",
        role=FragmentBlockRole.EXTERNAL,
        materialization=FragmentBlockMaterialization.REUSE_PUBLISHED,
        semantic_anchor_ea=0x40D348,
        stable_identity=StableBlockIdentity.from_intervals(
            (NativeEaInterval(0x40D348, 0x40D349),),
            native_key=other_key,
        ),
    )

    with pytest.raises(FragmentPlanRejected, match="native identity mismatch"):
        FragmentPlan(
            plan_id=plan.plan_id,
            atomic_group_id=plan.atomic_group_id,
            publication_purpose=plan.publication_purpose,
            native_key=plan.native_key,
            blocks=plan.blocks + (foreign,),
            roots=plan.roots,
            owned_originals=plan.owned_originals,
            prohibited_dispatcher_blocks=plan.prohibited_dispatcher_blocks,
            operations=plan.operations,
            data_flow_obligations=plan.data_flow_obligations,
            flag_corridors=plan.flag_corridors,
            value_range_assumptions=plan.value_range_assumptions,
        )


def test_fragment_plan_rejects_invalid_flag_corridor_and_range() -> None:
    plan = _valid_plan()
    definition = plan.data_flow_obligations[0].definition
    use = plan.data_flow_obligations[0].uses[0]

    with pytest.raises(FragmentPlanRejected, match="start at its producer"):
        FragmentFlagCorridor(
            corridor_id="broken-path",
            producer=definition,
            consumer=use,
            block_path=("handler.true",),
            permitted_flag_write_eas=frozenset({definition.instruction_ea}),
        )

    with pytest.raises(FragmentPlanRejected, match="lower bound exceeds"):
        FragmentRangeAssumption(
            assumption_id="broken-range",
            site=definition,
            observation=FragmentRangeObservation.AFTER_INSTRUCTION,
            lo=2,
            hi=1,
        )

    with pytest.raises(FragmentPlanRejected, match="unsigned site width"):
        FragmentRangeAssumption(
            assumption_id="negative-range",
            site=definition,
            observation=FragmentRangeObservation.AFTER_INSTRUCTION,
            lo=-1,
            hi=1,
        )

    with pytest.raises(FragmentPlanRejected, match="unsigned site width"):
        FragmentRangeAssumption(
            assumption_id="oversized-range",
            site=definition,
            observation=FragmentRangeObservation.AFTER_INSTRUCTION,
            lo=0,
            hi=1 << (definition.width * 8),
        )


def test_fragment_plan_rejects_ambiguous_value_site_identity() -> None:
    plan = _valid_plan()
    duplicate_site_id = FragmentValueSite(
        site_id=plan.data_flow_obligations[0].definition.site_id,
        block_id="handler.true",
        value_id="call:result",
        instruction_ea=0x40C100,
        storage_identity=CONDITION_STORAGE,
        width=1,
    )
    call_use = FragmentValueSite(
        site_id="call.use",
        block_id="handler.true",
        value_id="call:result",
        instruction_ea=0x40C101,
        storage_identity=CONDITION_STORAGE,
        width=1,
    )

    with pytest.raises(FragmentPlanRejected, match="value site id .* is ambiguous"):
        FragmentPlan(
            plan_id=plan.plan_id,
            atomic_group_id=plan.atomic_group_id,
            publication_purpose=plan.publication_purpose,
            native_key=plan.native_key,
            blocks=plan.blocks,
            roots=plan.roots,
            owned_originals=plan.owned_originals,
            prohibited_dispatcher_blocks=plan.prohibited_dispatcher_blocks,
            operations=plan.operations,
            data_flow_obligations=plan.data_flow_obligations
            + (
                FragmentDataFlowObligation(
                    obligation_id="call-flow",
                    role=FragmentDataFlowRole.CALL,
                    definition=duplicate_site_id,
                    uses=(call_use,),
                ),
            ),
            flag_corridors=plan.flag_corridors,
            value_range_assumptions=plan.value_range_assumptions,
        )


def test_data_flow_and_ranges_require_portable_storage_identity() -> None:
    definition = FragmentValueSite(
        site_id="unbound.def",
        block_id="replacement",
        value_id="state",
        instruction_ea=0x40BECC,
    )
    use = FragmentValueSite(
        site_id="unbound.use",
        block_id="replacement",
        value_id="state",
        instruction_ea=0x40BED0,
    )

    with pytest.raises(FragmentPlanRejected, match="storage identity"):
        FragmentDataFlowObligation(
            obligation_id="unbound-flow",
            role=FragmentDataFlowRole.STATE_VALUE,
            definition=definition,
            uses=(use,),
        )
    with pytest.raises(FragmentPlanRejected, match="storage identity"):
        FragmentRangeAssumption(
            assumption_id="unbound-range",
            site=definition,
            observation=FragmentRangeObservation.AFTER_INSTRUCTION,
            lo=0,
            hi=1,
        )


def test_data_flow_requires_one_portable_storage_identity_and_width() -> None:
    definition = FragmentValueSite(
        site_id="bound.def",
        block_id="replacement",
        value_id="state",
        instruction_ea=0x40BECC,
        storage_identity=CONDITION_STORAGE,
        width=4,
    )
    mismatched_identity = FragmentValueSite(
        site_id="identity.use",
        block_id="replacement",
        value_id="state",
        instruction_ea=0x40BED0,
        storage_identity=StorageIdentity(
            StorageIdentityKind.REGISTER,
            offset=0x20,
        ),
        width=4,
    )
    mismatched_width = FragmentValueSite(
        site_id="width.use",
        block_id="replacement",
        value_id="state",
        instruction_ea=0x40BED4,
        storage_identity=CONDITION_STORAGE,
        width=1,
    )

    with pytest.raises(FragmentPlanRejected, match="storage identity and width"):
        FragmentDataFlowObligation(
            obligation_id="identity-mismatch",
            role=FragmentDataFlowRole.STATE_VALUE,
            definition=definition,
            uses=(mismatched_identity,),
        )
    with pytest.raises(FragmentPlanRejected, match="storage identity and width"):
        FragmentDataFlowObligation(
            obligation_id="width-mismatch",
            role=FragmentDataFlowRole.STATE_VALUE,
            definition=definition,
            uses=(mismatched_width,),
        )


def test_value_site_storage_identity_and_width_are_coherent() -> None:
    with pytest.raises(FragmentPlanRejected, match="zero width"):
        FragmentValueSite(
            site_id="width-without-storage",
            block_id="replacement",
            value_id="state",
            instruction_ea=0x40BECC,
            width=4,
        )
    with pytest.raises(FragmentPlanRejected, match="positive width"):
        FragmentValueSite(
            site_id="storage-without-width",
            block_id="replacement",
            value_id="state",
            instruction_ea=0x40BECC,
            storage_identity=CONDITION_STORAGE,
        )


def test_flag_corridor_sites_do_not_require_fake_storage_identity() -> None:
    plan = _valid_plan()
    producer = FragmentValueSite(
        site_id="flags.producer",
        block_id="predicate.replacement",
        value_id="condition-codes:consumer-choice",
        instruction_ea=0x40BECC,
    )
    consumer = FragmentValueSite(
        site_id="flags.consumer",
        block_id="predicate.replacement",
        value_id="condition-codes:consumer-choice",
        instruction_ea=0x40BECD,
    )

    rebuilt = FragmentPlan(
        plan_id=plan.plan_id,
        atomic_group_id=plan.atomic_group_id,
        publication_purpose=plan.publication_purpose,
        native_key=plan.native_key,
        blocks=plan.blocks,
        roots=plan.roots,
        owned_originals=plan.owned_originals,
        prohibited_dispatcher_blocks=plan.prohibited_dispatcher_blocks,
        operations=plan.operations,
        data_flow_obligations=plan.data_flow_obligations,
        flag_corridors=(
            FragmentFlagCorridor(
                corridor_id="condition-codes",
                producer=producer,
                consumer=consumer,
                block_path=("predicate.replacement",),
                permitted_flag_write_eas=frozenset({0x40BECC}),
            ),
        ),
        value_range_assumptions=plan.value_range_assumptions,
    )

    assert rebuilt.flag_corridors[0].producer.storage_identity is None


def _terminal_plan() -> FragmentPlan:
    source_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40C7E5, 0x40C7F4),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x40C7E5, 0x40C7EA),
    )
    terminal_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40C898, 0x40C8A0),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x40C898,),
    )
    source_original = FragmentBlock(
        block_id="terminal.source.original",
        role=FragmentBlockRole.ORIGINAL,
        materialization=FragmentBlockMaterialization.REUSE_PUBLISHED,
        semantic_anchor_ea=0x40C7E5,
        stable_identity=source_identity,
    )
    source_replacement = FragmentBlock(
        block_id="terminal.source.replacement",
        role=FragmentBlockRole.REPLACEMENT,
        materialization=FragmentBlockMaterialization.CLONE_PUBLISHED,
        semantic_anchor_ea=0x40C7E5,
        stable_identity=source_identity,
        replaces_block_id=source_original.block_id,
    )
    return_original = FragmentBlock(
        block_id="terminal.return.original",
        role=FragmentBlockRole.ORIGINAL,
        materialization=FragmentBlockMaterialization.REUSE_PUBLISHED,
        semantic_anchor_ea=0x40C898,
        stable_identity=terminal_identity,
    )
    return_replacement = FragmentBlock(
        block_id="terminal.return.replacement",
        role=FragmentBlockRole.REPLACEMENT,
        materialization=FragmentBlockMaterialization.CLONE_PUBLISHED,
        semantic_anchor_ea=0x40C898,
        stable_identity=terminal_identity,
        replaces_block_id=return_original.block_id,
    )
    return FragmentPlan(
        plan_id="terminal-route",
        atomic_group_id="terminal-route@0x40C7E5",
        publication_purpose=FragmentPublicationPurpose.CANONICAL_SEMANTIC_LOWERING,
        native_key=NATIVE_KEY,
        blocks=(
            source_original,
            source_replacement,
            return_original,
            return_replacement,
        ),
        roots=(source_replacement.block_id,),
        owned_originals=(source_original.block_id, return_original.block_id),
        prohibited_dispatcher_blocks=(),
        operations=(
            FragmentOperation(
                operation_id="route-to-return",
                source_block_id=source_replacement.block_id,
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.DIRECT,
                        target_block_id=return_replacement.block_id,
                    ),
                ),
            ),
        ),
        return_carriers=(
            fragment_plan.FragmentReturnCarrier(
                carrier_id="return-value",
                block_id=source_replacement.block_id,
                state_write_ea=0x40C7E5,
                carrier_ea=0x40C7EA,
                operation=ValueOpKind.MOVE,
                source=fragment_plan.FragmentReturnSource(
                    kind=fragment_plan.FragmentReturnSourceKind.STORAGE_VALUE,
                    width=4,
                    storage_identity=StorageIdentity(
                        StorageIdentityKind.GLOBAL,
                        0x48B8A4,
                    ),
                ),
                return_width=4,
                corridor_instruction_eas=(0x40C7E5, 0x40C7EA),
            ),
        ),
        terminal_returns=(
            fragment_plan.FragmentTerminalReturn(
                return_id="function-return",
                block_id=return_replacement.block_id,
                instruction_ea=0x40C898,
                return_width=4,
            ),
        ),
        terminal_routes=(
            fragment_plan.FragmentTerminalRoute(
                terminal_route_id="route-return-value",
                operation_id="route-to-return",
                carrier_id="return-value",
                return_id="function-return",
            ),
        ),
    )


def test_fragment_plan_groups_terminal_carrier_return_and_route_atomically() -> None:
    plan = _terminal_plan()

    assert plan.return_carriers[0].carrier_ea == 0x40C7EA
    assert plan.terminal_returns[0].instruction_ea == 0x40C898
    assert plan.terminal_routes == (
        fragment_plan.FragmentTerminalRoute(
            terminal_route_id="route-return-value",
            operation_id="route-to-return",
            carrier_id="return-value",
            return_id="function-return",
        ),
    )


def test_fragment_plan_rejects_orphaned_terminal_effects() -> None:
    plan = _terminal_plan()

    with pytest.raises(
        FragmentPlanRejected,
        match="every fragment return carrier must belong",
    ):
        replace(plan, terminal_routes=())


def test_fragment_plan_requires_terminal_route_to_name_its_direct_edge() -> None:
    plan = _terminal_plan()
    source_block_id = plan.operations[0].source_block_id
    unrelated_operation = FragmentOperation(
        operation_id=plan.operations[0].operation_id,
        source_block_id=source_block_id,
        edges=(
            FragmentEdge(
                role=SemanticEdgeRole.DIRECT,
                target_block_id=source_block_id,
            ),
        ),
    )

    with pytest.raises(
        FragmentPlanRejected,
        match="one direct edge to its terminal return block",
    ):
        replace(plan, operations=(unrelated_operation,))


def test_fragment_plan_requires_terminal_carrier_and_return_width_parity() -> None:
    plan = _terminal_plan()

    with pytest.raises(
        FragmentPlanRejected,
        match="carrier and return widths must match",
    ):
        replace(
            plan,
            terminal_returns=(replace(plan.terminal_returns[0], return_width=8),),
        )


def test_fragment_plan_requires_exact_terminal_effect_anchors() -> None:
    plan = _terminal_plan()
    carrier = plan.return_carriers[0]

    with pytest.raises(FragmentPlanRejected) as exc_info:
        replace(
            plan,
            return_carriers=(
                replace(
                    carrier,
                    carrier_ea=0x40C7EB,
                    corridor_instruction_eas=(0x40C7E5, 0x40C7EB),
                ),
            ),
        )

    rejection = exc_info.value
    source = plan.block(carrier.block_id)
    assert source.stable_identity is not None
    assert rejection.reason_code == "fragment_return_carrier_exact_anchor_missing"
    assert rejection.anchor_ea == 0x40C7EB
    assert rejection.payload == {
        "carrier_id": carrier.carrier_id,
        "block_id": source.block_id,
        "block_role": source.role.value,
        "block_semantic_anchor_ea": "0x40C7E5",
        "block_identity": source.stable_identity.diagnostic_label(),
        "state_write_ea": "0x40C7E5",
        "carrier_ea": "0x40C7EB",
        "corridor_instruction_eas": ("0x40C7E5", "0x40C7EB"),
        "exact_instruction_eas": ("0x40C7E5", "0x40C7EA"),
        "missing_anchor_eas": ("0x40C7EB",),
    }


def test_fragment_return_source_rejects_nonportable_storage_and_constants() -> None:
    with pytest.raises(FragmentPlanRejected, match="constant.*fit"):
        fragment_plan.FragmentReturnSource(
            kind=fragment_plan.FragmentReturnSourceKind.CONSTANT,
            width=1,
            constant=0x100,
        )

    with pytest.raises(FragmentPlanRejected, match="stack or global"):
        fragment_plan.FragmentReturnSource(
            kind=fragment_plan.FragmentReturnSourceKind.STORAGE_VALUE,
            width=4,
            storage_identity=StorageIdentity(
                StorageIdentityKind.REGISTER,
                0,
            ),
        )
