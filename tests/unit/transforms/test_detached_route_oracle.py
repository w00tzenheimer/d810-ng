"""Detached reference-oracle checks for unpublished semantic routes."""

from __future__ import annotations

from dataclasses import replace

import pytest

from d810.core.semantic_route_oracle import (
    ReferenceRouteRewrite,
    ReferenceRouteOracleSelection,
    RouteOracleRun,
    SemanticTransferKind,
)
from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
from d810.ir.flowgraph import BlockKind, InsnKind
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.ir.semantics import PredicateKind
from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
from d810.transforms.detached_route_oracle import (
    DetachedRouteOracleRejected,
    bind_fragment_reference_oracle,
    compare_detached_route_oracle,
)
from d810.transforms.fragment_plan import (
    FragmentBlock,
    FragmentBlockMaterialization,
    FragmentBlockRole,
    FragmentBoundaryPort,
    FragmentBoundaryPortKind,
    FragmentDirectTransferRewrite,
    FragmentEdge,
    FragmentOperation,
    FragmentPlan,
    FragmentPlanRejected,
    FragmentPublicationPurpose,
    FragmentReferenceRouteAuthority,
    FragmentStoragePredicateMaterialization,
)
from d810.transforms.fragment_validation import (
    FragmentBindingState,
    ProjectedFallthroughHelper,
    ProjectedFragment,
    ProjectedFragmentBlock,
    ProjectedIdentityBinding,
)
from tests.native_preanalysis import make_native_key


_FUNCTION_EA = 0x40A560
_FUNCTION_RVA = 0xA560
_OWNER_EA = 0x40B51B
_REWRITE_ANCHOR_EA = 0x40B52E
_TARGET_EA = 0x40AE3E
_FIXTURE_SHA256 = "a" * 64
_REFERENCE_SHA256 = "b" * 64


def _identity(
    start_ea: int,
    end_ea: int,
    *exact_instruction_eas: int,
) -> StableBlockIdentity:
    return StableBlockIdentity.from_intervals(
        (NativeEaInterval(start_ea, end_ea),),
        native_key=_native_key(),
        exact_instruction_eas=exact_instruction_eas,
    )


def _native_key():
    return make_native_key(
        input_identity=f"sha256:{_FIXTURE_SHA256}",
        function_rva=_FUNCTION_RVA,
    )


def _reference_run() -> RouteOracleRun:
    return RouteOracleRun(
        run_id="a560-v33-boundary-40ae3e",
        function_ea=_FUNCTION_EA,
        fixture_sha256=_FIXTURE_SHA256,
        reference_binary_sha256=_REFERENCE_SHA256,
        candidate_binary_sha256=_FIXTURE_SHA256,
        reference_commit="21b0d4783703bc4fb6910cfae51d92cd683d2c65",
        runtime_image="d810-idapro-9.3-test-runtime:py313-v1",
        runtime_image_id="sha256:" + "c" * 64,
        cache_disabled=True,
    )


def _reference_route() -> ReferenceRouteRewrite:
    return ReferenceRouteRewrite(
        route_id="rhad:0x40A560:flow_route:0x40B52E",
        function_ea=_FUNCTION_EA,
        owner_ea=_OWNER_EA,
        rewrite_anchor_ea=_REWRITE_ANCHOR_EA,
        corridor=((_OWNER_EA, 0x40B534),),
        reference_phase="flow_route",
        original_transfer_kind=SemanticTransferKind.CONDITIONAL,
        final_transfer_kind=SemanticTransferKind.DIRECT,
        direct_target_ea=_TARGET_EA,
        reference_ledger_identity="flow_route:0x40B52E",
        reference_ledger_json=(
            '{"planned_branches":[{"anchor_ea":4232494,'
            '"opcode":"e9","target_ea":4238910}],"status":"committed"}'
        ),
    )


def _plan() -> FragmentPlan:
    native_key = _native_key()
    entry = FragmentBlock(
        block_id="entry",
        role=FragmentBlockRole.EXTERNAL,
        materialization=FragmentBlockMaterialization.REUSE_PUBLISHED,
        semantic_anchor_ea=_FUNCTION_EA,
        stable_identity=StableBlockIdentity.from_intervals(
            (NativeEaInterval(_FUNCTION_EA, _FUNCTION_EA + 1),),
            native_key=native_key,
            exact_instruction_eas=(_FUNCTION_EA,),
        ),
    )
    source_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(_OWNER_EA, 0x40B534),),
        native_key=native_key,
        exact_instruction_eas=(_OWNER_EA, _REWRITE_ANCHOR_EA),
    )
    original = FragmentBlock(
        block_id="route.original",
        role=FragmentBlockRole.ORIGINAL,
        materialization=FragmentBlockMaterialization.REUSE_PUBLISHED,
        semantic_anchor_ea=_OWNER_EA,
        stable_identity=source_identity,
    )
    replacement = FragmentBlock(
        block_id="route.replacement",
        role=FragmentBlockRole.REPLACEMENT,
        materialization=FragmentBlockMaterialization.CLONE_PUBLISHED,
        semantic_anchor_ea=_OWNER_EA,
        stable_identity=source_identity,
        replaces_block_id=original.block_id,
    )
    target = FragmentBlock(
        block_id="target",
        role=FragmentBlockRole.EXTERNAL,
        materialization=FragmentBlockMaterialization.REUSE_PUBLISHED,
        semantic_anchor_ea=_TARGET_EA,
        stable_identity=StableBlockIdentity.from_intervals(
            (NativeEaInterval(_TARGET_EA, _TARGET_EA + 0x10),),
            native_key=native_key,
            exact_instruction_eas=(_TARGET_EA,),
        ),
    )
    return FragmentPlan(
        plan_id="canonical-boundary@0x40AE3E",
        atomic_group_id="route@0x40B52E",
        publication_purpose=FragmentPublicationPurpose.CANONICAL_SEMANTIC_LOWERING,
        native_key=native_key,
        blocks=(entry, original, replacement, target),
        roots=(replacement.block_id,),
        owned_originals=(original.block_id,),
        prohibited_dispatcher_blocks=(),
        operations=(
            FragmentOperation(
                operation_id="route:state_assignment@0x40B52E:0x13B0D3B2",
                source_block_id=replacement.block_id,
                direct_transfer_rewrite=FragmentDirectTransferRewrite(
                    route_proof_id="state_assignment@0x40B52E:0x13B0D3B2",
                    owner_identity=source_identity,
                    owner_anchor_ea=_OWNER_EA,
                    rewrite_anchor_ea=_REWRITE_ANCHOR_EA,
                    delivery_region=NativeEaInterval(
                        _REWRITE_ANCHOR_EA,
                        0x40B534,
                    ),
                    proof_corridor_instruction_eas=(
                        _OWNER_EA,
                        _REWRITE_ANCHOR_EA,
                    ),
                    superseded_instruction_eas=(_REWRITE_ANCHOR_EA,),
                ),
                reference_route_authority=FragmentReferenceRouteAuthority(
                    reference_route=_reference_route(),
                    candidate_rewrite_anchor_ea=_REWRITE_ANCHOR_EA,
                ),
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.DIRECT,
                        target_block_id=target.block_id,
                    ),
                ),
            ),
        ),
        reference_oracle_run=_reference_run(),
    )


def _binding(
    plan: FragmentPlan,
    block_id: str,
    *,
    owner: str,
    version: int,
    state: FragmentBindingState,
    previous_version: int | None = None,
) -> ProjectedIdentityBinding:
    return ProjectedIdentityBinding(
        block_id=block_id,
        logical_owner_id=owner,
        version=version,
        generation=1,
        state=state,
        stable_identity=plan.block(block_id).stable_identity,
        previous_version=previous_version,
    )


def _projection(plan: FragmentPlan) -> ProjectedFragment:
    return ProjectedFragment(
        entry_block_id="entry",
        blocks=(
            ProjectedFragmentBlock(
                block_id="entry",
                kind=BlockKind.ONE_WAY,
                successors=("route.replacement",),
                predecessors=(),
                physical_position=0,
                adjacent_fallthrough_target_id=None,
                instruction_eas=(_FUNCTION_EA,),
                terminator_ea=_FUNCTION_EA,
                terminator_kind=InsnKind.GOTO,
            ),
            ProjectedFragmentBlock(
                block_id="route.replacement",
                kind=BlockKind.ONE_WAY,
                successors=("target",),
                predecessors=("entry",),
                physical_position=1,
                adjacent_fallthrough_target_id=None,
                instruction_eas=(_OWNER_EA, _REWRITE_ANCHOR_EA),
                terminator_ea=_REWRITE_ANCHOR_EA,
                terminator_kind=InsnKind.GOTO,
            ),
            ProjectedFragmentBlock(
                block_id="target",
                kind=BlockKind.ZERO_WAY,
                successors=(),
                predecessors=("route.replacement",),
                physical_position=2,
                adjacent_fallthrough_target_id=None,
                instruction_eas=(_TARGET_EA,),
                terminator_ea=None,
                terminator_kind=InsnKind.UNKNOWN,
            ),
            ProjectedFragmentBlock(
                block_id="route.original",
                kind=BlockKind.ZERO_WAY,
                successors=(),
                predecessors=(),
                physical_position=3,
                adjacent_fallthrough_target_id=None,
                instruction_eas=(_OWNER_EA,),
                terminator_ea=None,
                terminator_kind=InsnKind.UNKNOWN,
            ),
        ),
        identity_bindings=(
            _binding(
                plan,
                "entry",
                owner="logical:entry",
                version=0,
                state=FragmentBindingState.PUBLISHED,
            ),
            _binding(
                plan,
                "route.original",
                owner="logical:route",
                version=1,
                state=FragmentBindingState.PUBLISHED,
            ),
            _binding(
                plan,
                "route.replacement",
                owner="logical:route",
                version=2,
                state=FragmentBindingState.STAGED,
                previous_version=1,
            ),
            _binding(
                plan,
                "target",
                owner="logical:target",
                version=0,
                state=FragmentBindingState.PUBLISHED,
            ),
        ),
    )


def _projection_behind_temporary_port(
    plan: FragmentPlan,
) -> tuple[FragmentPlan, ProjectedFragment]:
    predecessor = FragmentBlock(
        block_id="temporary.port.predecessor",
        role=FragmentBlockRole.EXTERNAL,
        materialization=FragmentBlockMaterialization.REUSE_PUBLISHED,
        semantic_anchor_ea=0x40A570,
        stable_identity=_identity(0x40A570, 0x40A571, 0x40A570),
    )
    plan = replace(
        plan,
        blocks=plan.blocks + (predecessor,),
        boundary_ports=(
            FragmentBoundaryPort(
                port_id="temporary-dispatcher-entry@0x40B51B",
                kind=FragmentBoundaryPortKind.TEMPORARY_DISPATCHER_ENTRY,
                source_block_id=predecessor.block_id,
                target_block_id="route.replacement",
                retirement_obligation_id=(
                    "retire-temporary-dispatcher-entry@0x40B51B:"
                    "publish-semantic-predecessor@0x40A570"
                ),
            ),
        ),
    )
    projection = _projection(plan)
    projection = replace(
        projection,
        blocks=tuple(
            replace(block, kind=BlockKind.ZERO_WAY, successors=())
            if block.block_id == "entry"
            else replace(block, predecessors=(predecessor.block_id,))
            if block.block_id == "route.replacement"
            else block
            for block in projection.blocks
        )
        + (
            ProjectedFragmentBlock(
                block_id=predecessor.block_id,
                kind=BlockKind.ONE_WAY,
                successors=("route.replacement",),
                predecessors=(),
                physical_position=4,
                adjacent_fallthrough_target_id=None,
                instruction_eas=(0x40A570,),
                terminator_ea=0x40A570,
                terminator_kind=InsnKind.GOTO,
            ),
        ),
        identity_bindings=projection.identity_bindings
        + (
            _binding(
                plan,
                predecessor.block_id,
                owner="logical:temporary-port-predecessor",
                version=0,
                state=FragmentBindingState.PUBLISHED,
            ),
        ),
    )
    return plan, projection


def _unbound_plan() -> FragmentPlan:
    plan = _plan()
    operation = plan.operations[0]
    return replace(
        plan,
        operations=(
            replace(
                operation,
                reference_route_authority=None,
            ),
        ),
        reference_oracle_run=None,
    )


def test_bind_fragment_reference_oracle_attaches_exact_authority() -> None:
    plan = _unbound_plan()
    selection = ReferenceRouteOracleSelection(
        run=_reference_run(),
        publication_root_ea=_OWNER_EA,
        routes=(_reference_route(),),
    )

    bound = bind_fragment_reference_oracle(plan, selection)

    assert bound.reference_oracle_run == selection.run
    authority = bound.operations[0].reference_route_authority
    assert authority is not None
    assert authority.reference_route == selection.routes[0]
    assert authority.candidate_rewrite_anchor_ea == _REWRITE_ANCHOR_EA


def test_bind_fragment_reference_oracle_rebinds_unique_donor_patch_coordinate() -> None:
    plan = _unbound_plan()
    route = replace(
        _reference_route(),
        rewrite_anchor_ea=_REWRITE_ANCHOR_EA + 1,
    )
    selection = ReferenceRouteOracleSelection(
        run=_reference_run(),
        publication_root_ea=_OWNER_EA,
        routes=(route,),
    )

    bound = bind_fragment_reference_oracle(plan, selection)

    authority = bound.operations[0].reference_route_authority
    assert authority is not None
    assert authority.reference_route == route
    assert authority.candidate_rewrite_anchor_ea == _REWRITE_ANCHOR_EA

    result = compare_detached_route_oracle(bound, _projection(bound))
    assert result.passed
    assert result.comparisons[0].rewrite_anchor_ea == _REWRITE_ANCHOR_EA


def test_bind_fragment_reference_oracle_rebinds_complete_conditional_route() -> None:
    plan = _unbound_plan()
    source = plan.block("route.replacement")
    false_target_ea = _TARGET_EA + 0x20
    false_target = FragmentBlock(
        block_id="false-target",
        role=FragmentBlockRole.EXTERNAL,
        materialization=FragmentBlockMaterialization.REUSE_PUBLISHED,
        semantic_anchor_ea=false_target_ea,
        stable_identity=_identity(
            false_target_ea,
            false_target_ea + 0x10,
            false_target_ea,
        ),
    )
    plan = replace(
        plan,
        blocks=(*plan.blocks, false_target),
        operations=(
            FragmentOperation(
                operation_id="route:state-choice@0x40B51B",
                source_block_id=source.block_id,
                predicate_anchor_ea=_OWNER_EA,
                storage_predicate_materialization=(
                    FragmentStoragePredicateMaterialization(
                        predicate_kind=PredicateKind.EQ,
                        storage_identity=StorageIdentity(
                            StorageIdentityKind.STACK,
                            0x40,
                        ),
                        width=4,
                        compare_constant=0,
                        cut_after_ea=_OWNER_EA,
                    )
                ),
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.CONDITIONAL_TAKEN,
                        target_block_id="target",
                    ),
                    FragmentEdge(
                        role=SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
                        target_block_id=false_target.block_id,
                    ),
                ),
            ),
        ),
    )
    route = replace(
        _reference_route(),
        final_transfer_kind=SemanticTransferKind.CONDITIONAL,
        direct_target_ea=None,
        true_target_ea=_TARGET_EA,
        false_target_ea=false_target_ea,
        predicate_kind="z",
    )
    selection = ReferenceRouteOracleSelection(
        run=_reference_run(),
        publication_root_ea=_OWNER_EA,
        routes=(route,),
    )

    bound = bind_fragment_reference_oracle(plan, selection)

    authority = bound.operations[0].reference_route_authority
    assert authority is not None
    assert authority.reference_route == route
    assert authority.candidate_rewrite_anchor_ea == _OWNER_EA
    operation = bound.operations[0]
    helper_id = f"fallthrough-helper:{operation.operation_id}"
    projection = ProjectedFragment(
        entry_block_id="entry",
        blocks=(
            ProjectedFragmentBlock(
                block_id="entry",
                kind=BlockKind.ONE_WAY,
                successors=(source.block_id,),
                predecessors=(),
                physical_position=0,
                adjacent_fallthrough_target_id=None,
                instruction_eas=(_FUNCTION_EA,),
                terminator_ea=_FUNCTION_EA,
                terminator_kind=InsnKind.GOTO,
            ),
            ProjectedFragmentBlock(
                block_id=source.block_id,
                kind=BlockKind.TWO_WAY,
                successors=(helper_id, "target"),
                predecessors=("entry",),
                physical_position=1,
                adjacent_fallthrough_target_id=helper_id,
                instruction_eas=(_OWNER_EA,),
                terminator_ea=_OWNER_EA,
                terminator_kind=InsnKind.EQUALITY_JUMP,
            ),
            ProjectedFragmentBlock(
                block_id=helper_id,
                kind=BlockKind.ONE_WAY,
                successors=(false_target.block_id,),
                predecessors=(source.block_id,),
                physical_position=2,
                adjacent_fallthrough_target_id=None,
                instruction_eas=(),
                terminator_ea=None,
                terminator_kind=InsnKind.GOTO,
            ),
            ProjectedFragmentBlock(
                block_id=false_target.block_id,
                kind=BlockKind.ZERO_WAY,
                successors=(),
                predecessors=(helper_id,),
                physical_position=3,
                adjacent_fallthrough_target_id=None,
                instruction_eas=(false_target_ea,),
                terminator_ea=None,
                terminator_kind=InsnKind.UNKNOWN,
            ),
            ProjectedFragmentBlock(
                block_id="target",
                kind=BlockKind.ZERO_WAY,
                successors=(),
                predecessors=(source.block_id,),
                physical_position=4,
                adjacent_fallthrough_target_id=None,
                instruction_eas=(_TARGET_EA,),
                terminator_ea=None,
                terminator_kind=InsnKind.UNKNOWN,
            ),
            ProjectedFragmentBlock(
                block_id="route.original",
                kind=BlockKind.ZERO_WAY,
                successors=(),
                predecessors=(),
                physical_position=5,
                adjacent_fallthrough_target_id=None,
                instruction_eas=(_OWNER_EA,),
                terminator_ea=None,
                terminator_kind=InsnKind.UNKNOWN,
            ),
        ),
        identity_bindings=(
            _binding(
                bound,
                "entry",
                owner="logical:entry",
                version=0,
                state=FragmentBindingState.PUBLISHED,
            ),
            _binding(
                bound,
                "route.original",
                owner="logical:route",
                version=1,
                state=FragmentBindingState.PUBLISHED,
            ),
            _binding(
                bound,
                source.block_id,
                owner="logical:route",
                version=2,
                state=FragmentBindingState.STAGED,
                previous_version=1,
            ),
            ProjectedIdentityBinding(
                block_id=helper_id,
                logical_owner_id=f"plan:{bound.plan_id}:{helper_id}",
                version=0,
                generation=1,
                state=FragmentBindingState.STAGED,
                stable_identity=None,
            ),
            _binding(
                bound,
                "target",
                owner="logical:true-target",
                version=0,
                state=FragmentBindingState.PUBLISHED,
            ),
            _binding(
                bound,
                false_target.block_id,
                owner="logical:false-target",
                version=0,
                state=FragmentBindingState.PUBLISHED,
            ),
        ),
        fallthrough_helpers=(
            ProjectedFallthroughHelper(
                helper_block_id=helper_id,
                operation_id=operation.operation_id,
                source_block_id=operation.source_block_id,
                semantic_target_block_id=false_target.block_id,
            ),
        ),
    )

    result = compare_detached_route_oracle(bound, projection)

    assert result.passed
    comparison = result.comparisons[0]
    assert comparison.candidate_shape is not None
    assert comparison.candidate_shape.predicate_kind == "z"
    assert comparison.candidate_shape.true_target_ea == _TARGET_EA
    assert comparison.candidate_shape.false_target_ea == false_target_ea
    assert comparison.candidate_shape.physical_fallthrough_ea == false_target_ea

    unowned_helper_projection = replace(
        projection,
        identity_bindings=tuple(
            replace(binding, state=FragmentBindingState.PUBLISHED)
            if binding.block_id == helper_id
            else binding
            for binding in projection.identity_bindings
        ),
    )
    unowned_result = compare_detached_route_oracle(bound, unowned_helper_projection)
    assert not unowned_result.passed
    assert (
        unowned_result.comparisons[0].failed_invariant
        == "staged_helper_ownership"
    )


def test_bind_fragment_reference_oracle_rejects_partial_authority() -> None:
    plan = _unbound_plan()
    route = replace(
        _reference_route(),
        route_id="rhad:0x40A560:flow_route:0x40B52F",
        owner_ea=0x40B51C,
        rewrite_anchor_ea=0x40B52F,
        direct_target_ea=0x40AE3F,
        reference_ledger_identity="flow_route:0x40B52F",
    )
    selection = ReferenceRouteOracleSelection(
        run=_reference_run(),
        publication_root_ea=_OWNER_EA,
        routes=(route,),
    )

    with pytest.raises(
        DetachedRouteOracleRejected,
        match="exact rewrite anchors",
    ) as exc_info:
        bind_fragment_reference_oracle(plan, selection)

    error = exc_info.value
    assert error.reason_code == "fragment_reference_rewrite_anchor_set_mismatch"
    assert error.payload == {
        "coordinate_rebindings": (),
        "missing_rewrite_anchors": ("0x40B52F",),
        "planned_rewrite_anchors": ("0x40B52E",),
        "selected_rewrite_anchors": ("0x40B52F",),
        "unexpected_rewrite_anchors": ("0x40B52E",),
    }


def test_bind_fragment_reference_oracle_reports_identity_mismatch() -> None:
    plan = _unbound_plan()
    route = replace(
        _reference_route(),
        owner_ea=_OWNER_EA - 1,
        corridor=((_OWNER_EA - 1, 0x40B534),),
    )
    selection = ReferenceRouteOracleSelection(
        run=_reference_run(),
        publication_root_ea=_OWNER_EA,
        routes=(route,),
    )

    with pytest.raises(FragmentPlanRejected) as exc_info:
        bind_fragment_reference_oracle(plan, selection)

    error = exc_info.value
    assert error.reason_code == "fragment_reference_route_identity_mismatch"
    assert error.anchor_ea == _REWRITE_ANCHOR_EA
    assert error.payload == {
        "operation_id": "route:state_assignment@0x40B52E:0x13B0D3B2",
        "candidate_rewrite_anchor_ea": "0x40B52E",
        "reference_patch_anchor_ea": "0x40B52E",
        "operation_owner_anchor_ea": "0x40B51B",
        "operation_owner_identity": plan.block(
            "route.replacement"
        ).stable_identity.diagnostic_label(),
        "delivery_source_block_id": "route.replacement",
        "delivery_source_identity": plan.block(
            "route.replacement"
        ).stable_identity.diagnostic_label(),
        "reference_owner_ea": "0x40B51A",
        "owner_bound": False,
        "targets": (
            {
                "role": "direct",
                "target_block_id": "target",
                "target_identity": plan.block(
                    "target"
                ).stable_identity.diagnostic_label(),
                "reference_target_ea": "0x40AE3E",
                "target_bound": True,
            },
        ),
    }


def test_bind_fragment_reference_oracle_rejects_wrong_publication_root() -> None:
    plan = _unbound_plan()
    selection = ReferenceRouteOracleSelection(
        run=_reference_run(),
        publication_root_ea=_TARGET_EA,
        routes=(_reference_route(),),
    )

    with pytest.raises(DetachedRouteOracleRejected, match="publication root"):
        bind_fragment_reference_oracle(plan, selection)


def test_reference_owner_is_independent_of_delivery_block_identity() -> None:
    plan = _plan()
    owner_identity = plan.block("route.replacement").stable_identity
    delivery_identity = _identity(
        _REWRITE_ANCHOR_EA,
        _REWRITE_ANCHOR_EA + 1,
        _REWRITE_ANCHOR_EA,
    )
    operation = plan.operations[0]
    rewrite = operation.direct_transfer_rewrite
    assert owner_identity is not None
    assert rewrite is not None

    split_plan = replace(
        plan,
        blocks=tuple(
            replace(
                block,
                semantic_anchor_ea=_REWRITE_ANCHOR_EA,
                stable_identity=delivery_identity,
            )
            if block.block_id in {"route.original", "route.replacement"}
            else block
            for block in plan.blocks
        ),
        operations=(
            replace(
                operation,
                direct_transfer_rewrite=replace(
                    rewrite,
                    owner_identity=owner_identity,
                    owner_anchor_ea=_OWNER_EA,
                    delivery_region=NativeEaInterval(
                        _REWRITE_ANCHOR_EA,
                        _REWRITE_ANCHOR_EA + 1,
                    ),
                ),
            ),
        ),
    )

    split_rewrite = split_plan.operations[0].direct_transfer_rewrite
    assert split_rewrite is not None
    assert split_rewrite.owner_identity == owner_identity
    assert split_rewrite.owner_anchor_ea == _OWNER_EA
    assert not split_plan.block(
        split_plan.operations[0].source_block_id
    ).stable_identity.native_ranges.contains(_OWNER_EA)


def test_detached_route_matches_reference_before_root_publication() -> None:
    plan = _plan()

    result = compare_detached_route_oracle(plan, _projection(plan))

    assert result.passed
    assert len(result.comparisons) == 1
    comparison = result.comparisons[0]
    assert comparison.outcome == "matched"
    assert comparison.failed_invariant is None
    assert comparison.oracle_shape is not None
    assert comparison.candidate_shape is not None
    assert comparison.candidate_shape.terminator_opcode == InsnKind.GOTO.value
    assert comparison.candidate_shape.direct_target_ea == _TARGET_EA
    assert comparison.candidate_shape.reachable_from_entry


def test_detached_route_identifies_missing_staged_rewrite_anchor() -> None:
    plan = _plan()
    projection = _projection(plan)
    malformed = replace(
        projection,
        blocks=tuple(
            replace(
                block,
                instruction_eas=(_OWNER_EA,),
                terminator_ea=_OWNER_EA,
            )
            if block.block_id == "route.replacement"
            else block
            for block in projection.blocks
        ),
    )

    result = compare_detached_route_oracle(plan, malformed)

    comparison = result.comparisons[0]
    assert comparison.failed_invariant == "staged_rewrite_anchor_missing"
    assert comparison.reason == (
        "route rhad:0x40A560:flow_route:0x40B52E "
        "staged_rewrite_anchor_missing: "
        "source_block_id='route.replacement' "
        "expected_rewrite_anchor_ea=0x40B52E "
        "staged_terminator_ea=0x40B51B "
        "staged_terminator_kind=goto "
        "staged_instruction_eas=[0x40B51B]"
    )


def test_detached_route_identifies_staged_rewrite_terminator_mismatch() -> None:
    plan = _plan()
    projection = _projection(plan)
    malformed = replace(
        projection,
        blocks=tuple(
            replace(
                block,
                instruction_eas=(
                    _OWNER_EA,
                    _REWRITE_ANCHOR_EA,
                    _REWRITE_ANCHOR_EA + 1,
                ),
                terminator_ea=_REWRITE_ANCHOR_EA + 1,
            )
            if block.block_id == "route.replacement"
            else block
            for block in projection.blocks
        ),
    )

    result = compare_detached_route_oracle(plan, malformed)

    comparison = result.comparisons[0]
    assert comparison.failed_invariant == "staged_rewrite_terminator_mismatch"
    assert comparison.reason == (
        "route rhad:0x40A560:flow_route:0x40B52E "
        "staged_rewrite_terminator_mismatch: "
        "source_block_id='route.replacement' "
        "expected_rewrite_anchor_ea=0x40B52E "
        "staged_terminator_ea=0x40B52F "
        "staged_terminator_kind=goto "
        "staged_instruction_eas=[0x40B51B,0x40B52E,0x40B52F]"
    )


def test_detached_route_normalizes_exact_temporary_port_as_entry_authority() -> None:
    plan, projection = _projection_behind_temporary_port(_plan())

    result = compare_detached_route_oracle(plan, projection)

    assert result.passed
    comparison = result.comparisons[0]
    assert comparison.candidate_shape is not None
    assert comparison.candidate_shape.reachable_from_entry


def test_detached_route_rejects_disconnected_source_without_typed_port() -> None:
    plan = _plan()
    projection = _projection(plan)
    projection = replace(
        projection,
        blocks=tuple(
            replace(block, kind=BlockKind.ZERO_WAY, successors=())
            if block.block_id == "entry"
            else replace(block, predecessors=())
            if block.block_id == "route.replacement"
            else block
            for block in projection.blocks
        ),
    )

    result = compare_detached_route_oracle(plan, projection)

    assert not result.passed
    assert result.comparisons[0].failed_invariant == "reachable_from_entry"


def test_detached_route_rejects_api_success_without_semantic_replacement() -> None:
    plan = _plan()
    projection = _projection(plan)
    replacement = projection.block("route.replacement")
    malformed = replace(
        projection,
        blocks=tuple(
            replace(block, terminator_kind=InsnKind.COND_JUMP)
            if block.block_id == replacement.block_id
            else block
            for block in projection.blocks
        ),
    )

    result = compare_detached_route_oracle(plan, malformed)

    assert not result.passed
    assert len(result.comparisons) == 1
    comparison = result.comparisons[0]
    assert comparison.outcome == "diverged"
    assert comparison.first_divergence
    assert comparison.failed_invariant == "transfer_kind"
