"""Projected semantic-fragment validation before root publication."""

from __future__ import annotations

from dataclasses import replace

from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
from d810.ir.flowgraph import BlockKind
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.transforms.fragment_plan import (
    FragmentBlock,
    FragmentBlockMaterialization,
    FragmentBlockRole,
    FragmentDataFlowObligation,
    FragmentDataFlowRole,
    FragmentEdge,
    FragmentFlagCorridor,
    FragmentOperation,
    FragmentPlan,
    FragmentRangeAssumption,
    FragmentValueSite,
)
from d810.transforms.fragment_validation import (
    FragmentBindingState,
    FragmentValidationPostcondition,
    PublishedFragmentObservation,
    ProjectedDataFlowRelation,
    ProjectedFragment,
    ProjectedFragmentBlock,
    ProjectedIdentityBinding,
    ProjectedRangeFact,
    validate_fragment_projection,
    validate_published_fragment_observation,
)
from tests.native_preanalysis import make_native_key


NATIVE_KEY = make_native_key(function_rva=0x40A560)


def _identity(start_ea: int) -> StableBlockIdentity:
    return StableBlockIdentity.from_intervals(
        (NativeEaInterval(start_ea, start_ea + 0x10),),
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
        stable_identity=_identity(start_ea),
        replaces_block_id=replaces,
    )


def _plan() -> FragmentPlan:
    entry = _native_block("entry", FragmentBlockRole.EXTERNAL, 0x5000)
    original = _native_block("original", FragmentBlockRole.ORIGINAL, 0x1000)
    replacement = FragmentBlock(
        block_id="replacement",
        role=FragmentBlockRole.REPLACEMENT,
        materialization=FragmentBlockMaterialization.CLONE_PUBLISHED,
        semantic_anchor_ea=0x1000,
        stable_identity=original.stable_identity,
        replaces_block_id=original.block_id,
    )
    true_target = _native_block("true", FragmentBlockRole.EXTERNAL, 0x2000)
    false_target = _native_block("false", FragmentBlockRole.EXTERNAL, 0x3000)
    dispatcher = _native_block("dispatcher", FragmentBlockRole.EXTERNAL, 0x4000)
    definition = FragmentValueSite(
        site_id="flags.def",
        block_id="replacement",
        value_id="flags:choice",
        instruction_ea=0x1000,
    )
    use = FragmentValueSite(
        site_id="flags.use",
        block_id="replacement",
        value_id="flags:choice",
        instruction_ea=0x1004,
    )
    return FragmentPlan(
        plan_id="semantic-fragment",
        atomic_group_id="condition@0x1004",
        native_key=NATIVE_KEY,
        blocks=(entry, original, replacement, true_target, false_target, dispatcher),
        roots=("replacement",),
        owned_originals=("original",),
        prohibited_dispatcher_blocks=("dispatcher",),
        operations=(
            FragmentOperation(
                operation_id="condition",
                source_block_id="replacement",
                predicate_anchor_ea=0x1004,
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.CONDITIONAL_TAKEN,
                        target_block_id="true",
                    ),
                    FragmentEdge(
                        role=SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
                        target_block_id="false",
                    ),
                ),
            ),
        ),
        data_flow_obligations=(
            FragmentDataFlowObligation(
                obligation_id="condition-flow",
                role=FragmentDataFlowRole.CONDITION,
                definition=definition,
                uses=(use,),
            ),
        ),
        flag_corridors=(
            FragmentFlagCorridor(
                corridor_id="condition-flags",
                producer=definition,
                consumer=use,
                block_path=("replacement",),
                permitted_flag_write_eas=frozenset({0x1000}),
            ),
        ),
        value_range_assumptions=(
            FragmentRangeAssumption(
                assumption_id="boolean-condition",
                site=definition,
                lo=0,
                hi=1,
            ),
        ),
    )


def _projected_block(
    block_id: str,
    kind: BlockKind,
    successors: tuple[str, ...],
    predecessors: tuple[str, ...],
    position: int,
    *,
    instruction_eas: tuple[int, ...] = (),
    flag_write_eas: frozenset[int] = frozenset(),
) -> ProjectedFragmentBlock:
    return ProjectedFragmentBlock(
        block_id=block_id,
        kind=kind,
        successors=successors,
        predecessors=predecessors,
        physical_position=position,
        instruction_eas=instruction_eas,
        flag_write_eas=flag_write_eas,
    )


def _binding(
    plan: FragmentPlan,
    block_id: str,
    owner: str,
    version: int,
    generation: int,
    state: FragmentBindingState,
    *,
    previous_version: int | None = None,
) -> ProjectedIdentityBinding:
    return ProjectedIdentityBinding(
        block_id=block_id,
        logical_owner_id=owner,
        version=version,
        generation=generation,
        state=state,
        stable_identity=plan.block(block_id).stable_identity,
        previous_version=previous_version,
    )


def _projection(plan: FragmentPlan | None = None) -> ProjectedFragment:
    plan = _plan() if plan is None else plan
    return ProjectedFragment(
        entry_block_id="entry",
        blocks=(
            _projected_block("entry", BlockKind.ONE_WAY, ("replacement",), (), 0),
            _projected_block(
                "replacement",
                BlockKind.TWO_WAY,
                ("true", "false"),
                ("entry",),
                1,
                instruction_eas=(0x1000, 0x1004),
                flag_write_eas=frozenset({0x1000}),
            ),
            _projected_block("false", BlockKind.ZERO_WAY, (), ("replacement",), 2),
            _projected_block("true", BlockKind.ZERO_WAY, (), ("replacement",), 3),
            _projected_block("original", BlockKind.ZERO_WAY, (), (), 4),
            _projected_block("dispatcher", BlockKind.ZERO_WAY, (), (), 5),
        ),
        identity_bindings=(
            _binding(
                plan, "entry", "logical:entry", 0, 2, FragmentBindingState.PUBLISHED
            ),
            _binding(
                plan,
                "original",
                "logical:predicate",
                3,
                2,
                FragmentBindingState.PUBLISHED,
            ),
            _binding(
                plan,
                "replacement",
                "logical:predicate",
                4,
                3,
                FragmentBindingState.STAGED,
                previous_version=3,
            ),
            _binding(
                plan, "true", "logical:true", 0, 2, FragmentBindingState.PUBLISHED
            ),
            _binding(
                plan, "false", "logical:false", 0, 2, FragmentBindingState.PUBLISHED
            ),
            _binding(
                plan,
                "dispatcher",
                "logical:dispatcher",
                0,
                2,
                FragmentBindingState.PUBLISHED,
            ),
        ),
        data_flow_relations=(
            ProjectedDataFlowRelation(
                value_id="flags:choice",
                definition_site_id="flags.def",
                use_site_id="flags.use",
            ),
        ),
        value_ranges=(
            ProjectedRangeFact(
                site_id="flags.def",
                value_id="flags:choice",
                lo=0,
                hi=1,
            ),
        ),
    )


def _replace_blocks(
    projection: ProjectedFragment,
    *replacements: ProjectedFragmentBlock,
) -> ProjectedFragment:
    by_id = {block.block_id: block for block in replacements}
    return replace(
        projection,
        blocks=tuple(by_id.get(block.block_id, block) for block in projection.blocks),
    )


def _failed_codes(
    plan: FragmentPlan, projection: ProjectedFragment
) -> set[FragmentValidationPostcondition]:
    return {
        outcome.postcondition
        for outcome in validate_fragment_projection(plan, projection).failures
    }


def test_valid_projection_proves_every_required_postcondition() -> None:
    result = validate_fragment_projection(_plan(), _projection())

    assert result.passed
    assert result.failures == ()
    assert {
        FragmentValidationPostcondition.INTERNAL_CONNECTIVITY,
        FragmentValidationPostcondition.OPERATION_REACHABILITY,
        FragmentValidationPostcondition.ORIGINAL_SUPERSESSION,
        FragmentValidationPostcondition.DISPATCHER_ABSENCE,
        FragmentValidationPostcondition.PRED_SUCC_SYMMETRY,
        FragmentValidationPostcondition.FALLTHROUGH_TOPOLOGY,
        FragmentValidationPostcondition.USE_DEF_INTEGRITY,
        FragmentValidationPostcondition.DEF_USE_INTEGRITY,
        FragmentValidationPostcondition.FLAG_CORRIDOR_INTEGRITY,
        FragmentValidationPostcondition.VALUE_RANGE_PROVEN,
        FragmentValidationPostcondition.IDENTITY_OWNERSHIP,
        FragmentValidationPostcondition.VERSION_LINEAGE,
    }.issubset({outcome.postcondition for outcome in result.outcomes})


def test_unreachable_replacement_root_is_rejected() -> None:
    projection = _projection()
    projection = _replace_blocks(
        projection,
        replace(projection.block("entry"), successors=("true",)),
        replace(projection.block("replacement"), predecessors=()),
        replace(projection.block("true"), predecessors=("entry", "replacement")),
    )

    failed = _failed_codes(_plan(), projection)

    assert FragmentValidationPostcondition.ROOT_REACHABILITY in failed


def test_operation_disconnected_from_fragment_roots_is_rejected() -> None:
    plan = _plan()
    synthetic = FragmentBlock(
        block_id="detached.helper",
        role=FragmentBlockRole.SYNTHETIC,
        materialization=FragmentBlockMaterialization.CREATE_EMPTY,
        semantic_anchor_ea=0x6000,
    )
    plan = replace(
        plan,
        blocks=plan.blocks + (synthetic,),
        operations=plan.operations
        + (
            FragmentOperation(
                operation_id="detached-operation",
                source_block_id=synthetic.block_id,
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.DIRECT,
                        target_block_id="true",
                    ),
                ),
            ),
        ),
    )
    projection = _projection(plan)
    projection = replace(
        projection,
        blocks=projection.blocks
        + (
            _projected_block(
                synthetic.block_id,
                BlockKind.ZERO_WAY,
                (),
                (),
                6,
            ),
        ),
        identity_bindings=projection.identity_bindings
        + (
            ProjectedIdentityBinding(
                block_id=synthetic.block_id,
                logical_owner_id="logical:detached-helper",
                version=0,
                generation=3,
                state=FragmentBindingState.STAGED,
                stable_identity=None,
            ),
        ),
    )

    failed = _failed_codes(plan, projection)

    assert FragmentValidationPostcondition.INTERNAL_CONNECTIVITY in failed
    assert FragmentValidationPostcondition.OPERATION_REACHABILITY in failed


def test_reachable_owned_original_is_rejected() -> None:
    projection = _projection()
    projection = _replace_blocks(
        projection,
        replace(projection.block("entry"), successors=("original",)),
        replace(projection.block("replacement"), predecessors=()),
        replace(projection.block("original"), predecessors=("entry",)),
    )

    assert FragmentValidationPostcondition.ORIGINAL_SUPERSESSION in _failed_codes(
        _plan(),
        projection,
    )


def test_reachable_residual_dispatcher_route_is_rejected() -> None:
    projection = _projection()
    projection = _replace_blocks(
        projection,
        replace(
            projection.block("false"),
            kind=BlockKind.ONE_WAY,
            successors=("dispatcher",),
        ),
        replace(projection.block("dispatcher"), predecessors=("false",)),
    )

    assert FragmentValidationPostcondition.DISPATCHER_ABSENCE in _failed_codes(
        _plan(),
        projection,
    )


def test_predecessor_successor_asymmetry_is_rejected() -> None:
    projection = _projection()
    projection = _replace_blocks(
        projection,
        replace(projection.block("false"), predecessors=()),
    )

    assert FragmentValidationPostcondition.PRED_SUCC_SYMMETRY in _failed_codes(
        _plan(),
        projection,
    )


def test_nonadjacent_conditional_fallthrough_is_rejected() -> None:
    projection = _projection()
    projection = _replace_blocks(
        projection,
        replace(projection.block("false"), physical_position=3),
        replace(projection.block("true"), physical_position=2),
    )

    assert FragmentValidationPostcondition.FALLTHROUGH_TOPOLOGY in _failed_codes(
        _plan(),
        projection,
    )


def test_broken_use_def_and_def_use_relations_are_rejected() -> None:
    projection = replace(_projection(), data_flow_relations=())

    failed = _failed_codes(_plan(), projection)

    assert FragmentValidationPostcondition.USE_DEF_INTEGRITY in failed
    assert FragmentValidationPostcondition.DEF_USE_INTEGRITY in failed


def test_intervening_flag_clobber_is_rejected() -> None:
    projection = _projection()
    replacement = projection.block("replacement")
    projection = _replace_blocks(
        projection,
        replace(
            replacement,
            instruction_eas=(0x1000, 0x1002, 0x1004),
            flag_write_eas=replacement.flag_write_eas | {0x1002},
        ),
    )

    assert FragmentValidationPostcondition.FLAG_CORRIDOR_INTEGRITY in _failed_codes(
        _plan(),
        projection,
    )


def test_flag_consumer_before_producer_is_rejected() -> None:
    projection = _projection()
    projection = _replace_blocks(
        projection,
        replace(
            projection.block("replacement"),
            instruction_eas=(0x1004, 0x1000),
        ),
    )

    assert FragmentValidationPostcondition.FLAG_CORRIDOR_INTEGRITY in _failed_codes(
        _plan(),
        projection,
    )


def test_range_wider_than_required_assumption_is_rejected() -> None:
    projection = replace(
        _projection(),
        value_ranges=(
            ProjectedRangeFact(
                site_id="flags.def",
                value_id="flags:choice",
                lo=0,
                hi=2,
            ),
        ),
    )

    assert FragmentValidationPostcondition.VALUE_RANGE_PROVEN in _failed_codes(
        _plan(),
        projection,
    )


def test_identity_owner_and_replacement_lineage_drift_are_rejected() -> None:
    plan = _plan()
    projection = _projection(plan)
    replacement_binding = projection.binding("replacement")
    projection = replace(
        projection,
        identity_bindings=tuple(
            replace(
                binding,
                logical_owner_id="logical:wrong-owner",
                previous_version=2,
            )
            if binding.block_id == "replacement"
            else binding
            for binding in projection.identity_bindings
        ),
    )
    assert replacement_binding.previous_version == 3

    failed = _failed_codes(plan, projection)

    assert FragmentValidationPostcondition.IDENTITY_OWNERSHIP in failed
    assert FragmentValidationPostcondition.VERSION_LINEAGE in failed


def test_block_kind_must_match_projected_successor_shape() -> None:
    projection = _projection()
    projection = _replace_blocks(
        projection,
        replace(projection.block("replacement"), kind=BlockKind.ONE_WAY),
    )

    assert FragmentValidationPostcondition.BLOCK_TOPOLOGY in _failed_codes(
        _plan(),
        projection,
    )


def _published_observation(
    plan: FragmentPlan | None = None,
) -> PublishedFragmentObservation:
    plan = _plan() if plan is None else plan
    prevalidation = validate_fragment_projection(plan, _projection(plan))
    assert prevalidation.passed
    return PublishedFragmentObservation(
        plan_id=plan.plan_id,
        atomic_group_id=plan.atomic_group_id,
        published_root_ids=plan.roots,
        observable_operations=plan.operations,
        semantic_outcomes=prevalidation.outcomes,
    )


def test_postpublication_accepts_observable_semantics_without_physical_blocks() -> None:
    plan = _plan()
    observation = _published_observation(plan)

    result = validate_published_fragment_observation(plan, observation)

    assert result.passed
    assert result.failures == ()
    assert FragmentValidationPostcondition.ROOT_AUTHORITY in {
        outcome.postcondition for outcome in result.outcomes
    }
    assert FragmentValidationPostcondition.OBSERVABLE_OPERATION in {
        outcome.postcondition for outcome in result.outcomes
    }


def test_postpublication_rejects_changed_semantic_operation() -> None:
    plan = _plan()
    observation = _published_observation(plan)
    changed_operation = replace(
        plan.operations[0],
        edges=(
            FragmentEdge(
                role=SemanticEdgeRole.DIRECT,
                target_block_id="true",
            ),
        ),
        predicate_anchor_ea=None,
    )
    observation = replace(
        observation,
        observable_operations=(changed_operation,),
    )

    result = validate_published_fragment_observation(plan, observation)

    assert FragmentValidationPostcondition.OBSERVABLE_OPERATION in {
        outcome.postcondition for outcome in result.failures
    }


def test_postpublication_rejects_missing_semantic_postcondition() -> None:
    plan = _plan()
    observation = _published_observation(plan)
    observation = replace(
        observation,
        semantic_outcomes=tuple(
            outcome
            for outcome in observation.semantic_outcomes
            if outcome.postcondition
            is not FragmentValidationPostcondition.FLAG_CORRIDOR_INTEGRITY
        ),
    )

    result = validate_published_fragment_observation(plan, observation)

    assert FragmentValidationPostcondition.POSTVALIDATION_COVERAGE in {
        outcome.postcondition for outcome in result.failures
    }


def test_postpublication_rejects_missing_root_authority() -> None:
    plan = _plan()
    observation = replace(
        _published_observation(plan),
        published_root_ids=(),
    )

    result = validate_published_fragment_observation(plan, observation)

    assert FragmentValidationPostcondition.ROOT_AUTHORITY in {
        outcome.postcondition for outcome in result.failures
    }
