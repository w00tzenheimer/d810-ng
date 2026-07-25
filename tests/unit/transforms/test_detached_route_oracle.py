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
from d810.transforms.detached_route_oracle import (
    DetachedRouteOracleRejected,
    bind_fragment_reference_oracle,
    compare_detached_route_oracle,
)
from d810.transforms.fragment_plan import (
    FragmentBlock,
    FragmentBlockMaterialization,
    FragmentBlockRole,
    FragmentDirectTransferRewrite,
    FragmentEdge,
    FragmentOperation,
    FragmentPlan,
    FragmentPlanRejected,
    FragmentPublicationPurpose,
)
from d810.transforms.fragment_validation import (
    FragmentBindingState,
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
                    rewrite_anchor_ea=_REWRITE_ANCHOR_EA,
                    proof_corridor_instruction_eas=(
                        _OWNER_EA,
                        _REWRITE_ANCHOR_EA,
                    ),
                    superseded_instruction_eas=(_REWRITE_ANCHOR_EA,),
                    reference_route=_reference_route(),
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


def _unbound_plan() -> FragmentPlan:
    plan = _plan()
    operation = plan.operations[0]
    rewrite = operation.direct_transfer_rewrite
    assert rewrite is not None
    return replace(
        plan,
        operations=(
            replace(
                operation,
                direct_transfer_rewrite=replace(rewrite, reference_route=None),
            ),
        ),
        reference_oracle_run=None,
    )


def test_bind_fragment_reference_oracle_attaches_exact_authority() -> None:
    plan = _unbound_plan()
    selection = ReferenceRouteOracleSelection(
        run=_reference_run(),
        routes=(_reference_route(),),
    )

    bound = bind_fragment_reference_oracle(plan, selection)

    assert bound.reference_oracle_run == selection.run
    rewrite = bound.operations[0].direct_transfer_rewrite
    assert rewrite is not None
    assert rewrite.reference_route == selection.routes[0]


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
        routes=(route,),
    )

    with pytest.raises(DetachedRouteOracleRejected, match="exact rewrite anchors"):
        bind_fragment_reference_oracle(plan, selection)


def test_bind_fragment_reference_oracle_reports_identity_mismatch() -> None:
    plan = _unbound_plan()
    route = replace(
        _reference_route(),
        owner_ea=_OWNER_EA - 1,
        corridor=((_OWNER_EA - 1, 0x40B534),),
    )
    selection = ReferenceRouteOracleSelection(
        run=_reference_run(),
        routes=(route,),
    )

    with pytest.raises(FragmentPlanRejected) as exc_info:
        bind_fragment_reference_oracle(plan, selection)

    error = exc_info.value
    assert error.reason_code == "fragment_reference_route_identity_mismatch"
    assert error.anchor_ea == _REWRITE_ANCHOR_EA
    assert error.payload == {
        "operation_id": "route:state_assignment@0x40B52E:0x13B0D3B2",
        "source_block_id": "route.replacement",
        "source_identity": plan.block(
            "route.replacement"
        ).stable_identity.diagnostic_label(),
        "reference_owner_ea": "0x40B51A",
        "owner_bound": False,
        "target_block_id": "target",
        "target_identity": plan.block("target").stable_identity.diagnostic_label(),
        "reference_target_ea": "0x40AE3E",
        "target_bound": True,
    }


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
