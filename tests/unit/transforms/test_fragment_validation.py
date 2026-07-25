"""Projected semantic-fragment validation before root publication."""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
from d810.ir.expressions import ValueOpKind
from d810.ir.flowgraph import BlockKind, InsnKind
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
from d810.transforms.fragment_plan import (
    FragmentBlock,
    FragmentBlockMaterialization,
    FragmentBlockRole,
    FragmentBoundaryPort,
    FragmentBoundaryPortKind,
    FragmentDataFlowObligation,
    FragmentDataFlowRole,
    FragmentEdge,
    FragmentFlagCorridor,
    FragmentNativeBody,
    FragmentOperation,
    FragmentPlan,
    FragmentPublicationPurpose,
    FragmentRangeAssumption,
    FragmentRangeObservation,
    FragmentReturnCarrier,
    FragmentReturnSource,
    FragmentReturnSourceKind,
    FragmentTerminalReturn,
    FragmentTerminalRoute,
    FragmentValueSite,
)
from d810.transforms.fragment_projection import (
    FragmentProjectionBlockInput,
    FragmentProjectionFailure,
    FragmentProjectionInput,
    project_fragment,
)
from d810.transforms.fragment_validation import (
    FragmentBindingState,
    FragmentValidationPostcondition,
    PublishedFragmentObservation,
    ProjectedDataFlowRelation,
    ProjectedFallthroughHelper,
    ProjectedFragment,
    ProjectedFragmentBlock,
    ProjectedIdentityBinding,
    ProjectedRangeFact,
    ProjectedRootFallthroughHelper,
    ProjectedTerminalEffectDiagnostic,
    validate_fragment_projection,
    validate_published_fragment_projection,
    validate_published_fragment_observation,
)
from tests.native_preanalysis import make_native_key


NATIVE_KEY = make_native_key(function_rva=0x40A560)
CONDITION_STORAGE = StorageIdentity(StorageIdentityKind.REGISTER, offset=0x10)


def test_fragment_projection_failure_is_prewrite_evidence() -> None:
    failure = FragmentProjectionFailure(
        FragmentValidationPostcondition.ROOT_AUTHORITY,
        "root-inventory",
        "projection rejected",
    )

    assert failure.live_mutation_started is False
    assert failure.failure_phase == "projection"


def test_project_fragment_derives_replacement_and_root_rewrite_from_snapshots() -> None:
    plan = _plan()
    staged = _projection(plan)
    replacement = replace(
        staged.block("replacement"),
        terminator_ea=0x1004,
        terminator_kind=InsnKind.COND_JUMP,
    )
    plan_block_ids = {block.block_id for block in plan.blocks}
    snapshot = FragmentProjectionInput(
        snapshot_id="snapshot:projection-test",
        entry_block_id="entry",
        blocks=tuple(
            FragmentProjectionBlockInput(
                block_id=block.block_id,
                kind=block.kind,
                successors=("original",)
                if block.block_id == "entry"
                else block.successors,
                predecessors=("entry",)
                if block.block_id == "original"
                else block.predecessors,
                physical_position=block.physical_position,
                adjacent_fallthrough_target_id=(
                    block.adjacent_fallthrough_target_id
                ),
                terminator_ea=(
                    replacement.terminator_ea
                    if block.block_id == "original"
                    else block.terminator_ea
                ),
                terminator_kind=(
                    replacement.terminator_kind
                    if block.block_id == "original"
                    else block.terminator_kind
                ),
                instruction_eas=(
                    replacement.instruction_eas
                    if block.block_id == "original"
                    else block.instruction_eas
                ),
                flag_write_eas=(
                    replacement.flag_write_eas
                    if block.block_id == "original"
                    else block.flag_write_eas
                ),
            )
            for block in staged.blocks
            if block.block_id in plan_block_ids
            and block.block_id != "replacement"
        ),
        identity_bindings=tuple(
            binding
            for binding in staged.identity_bindings
            if binding.block_id in plan_block_ids
            and binding.block_id != "replacement"
        ),
        data_flow_relations=staged.data_flow_relations,
        value_ranges=staged.value_ranges,
    )
    inventory = SimpleNamespace(
        plan_id=plan.plan_id,
        atomic_group_id=plan.atomic_group_id,
        items=(
            SimpleNamespace(
                root_block_id="replacement",
                original_block_id="original",
                predecessor_block_id="entry",
                role=SemanticEdgeRole.DIRECT,
                requires_helper=False,
            ),
        ),
    )

    projection = project_fragment(plan, snapshot, inventory)

    assert projection.block("entry").successors == ("replacement",)
    assert projection.block("original").predecessors == ()
    assert projection.block("replacement").successors == (
        "fallthrough-helper:condition",
        "true",
    )
    assert projection.block("replacement").terminator_ea == 0x1004
    assert projection.block("replacement").terminator_kind is InsnKind.COND_JUMP
    assert tuple(
        helper.helper_block_id for helper in projection.fallthrough_helpers
    ) == ("fallthrough-helper:condition",)
    assert (
        projection.binding("replacement").previous_version
        == projection.binding("original").version
    )
    assert validate_fragment_projection(plan, projection).passed


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
        storage_identity=CONDITION_STORAGE,
        width=1,
    )
    use = FragmentValueSite(
        site_id="flags.use",
        block_id="replacement",
        value_id="flags:choice",
        instruction_ea=0x1004,
        storage_identity=CONDITION_STORAGE,
        width=1,
    )
    return FragmentPlan(
        plan_id="semantic-fragment",
        atomic_group_id="condition@0x1004",
        publication_purpose=FragmentPublicationPurpose.CANONICAL_SEMANTIC_LOWERING,
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
                observation=FragmentRangeObservation.AFTER_INSTRUCTION,
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
    adjacent_fallthrough_target_id: str | None = None,
    instruction_eas: tuple[int, ...] = (),
    flag_write_eas: frozenset[int] = frozenset(),
) -> ProjectedFragmentBlock:
    if (
        adjacent_fallthrough_target_id is None
        and kind is BlockKind.TWO_WAY
        and successors
    ):
        adjacent_fallthrough_target_id = successors[0]
    return ProjectedFragmentBlock(
        block_id=block_id,
        kind=kind,
        successors=successors,
        predecessors=predecessors,
        physical_position=position,
        adjacent_fallthrough_target_id=adjacent_fallthrough_target_id,
        terminator_ea=None,
        terminator_kind=InsnKind.UNKNOWN,
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
                ("condition.fallthrough", "true"),
                ("entry",),
                1,
                instruction_eas=(0x1000, 0x1004),
                flag_write_eas=frozenset({0x1000}),
            ),
            _projected_block(
                "condition.fallthrough",
                BlockKind.ONE_WAY,
                ("false",),
                ("replacement",),
                2,
            ),
            _projected_block(
                "false", BlockKind.ZERO_WAY, (), ("condition.fallthrough",), 3
            ),
            _projected_block("true", BlockKind.ZERO_WAY, (), ("replacement",), 4),
            _projected_block("original", BlockKind.ZERO_WAY, (), (), 5),
            _projected_block("dispatcher", BlockKind.ZERO_WAY, (), (), 6),
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
            ProjectedIdentityBinding(
                block_id="condition.fallthrough",
                logical_owner_id="logical:condition-fallthrough",
                version=0,
                generation=3,
                state=FragmentBindingState.STAGED,
                stable_identity=None,
            ),
        ),
        fallthrough_helpers=(
            ProjectedFallthroughHelper(
                helper_block_id="condition.fallthrough",
                operation_id="condition",
                source_block_id="replacement",
                semantic_target_block_id="false",
            ),
        ),
        data_flow_relations=(
            ProjectedDataFlowRelation(
                value_id="flags:choice",
                definition_site_id="flags.def",
                use_site_id="flags.use",
                use_def_observed=True,
                def_use_observed=True,
            ),
        ),
        value_ranges=(
            ProjectedRangeFact(
                site_id="flags.def",
                value_id="flags:choice",
                observation=FragmentRangeObservation.AFTER_INSTRUCTION,
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


def _projection_with_root_fallthrough_helper(
    plan: FragmentPlan,
) -> ProjectedFragment:
    projection = _projection(plan)
    root_helper_id = "root.fallthrough"
    return replace(
        projection,
        blocks=(
            _projected_block(
                "entry",
                BlockKind.TWO_WAY,
                (root_helper_id, "true"),
                (),
                0,
            ),
            _projected_block(
                root_helper_id,
                BlockKind.ONE_WAY,
                ("replacement",),
                ("entry",),
                1,
            ),
            replace(
                projection.block("replacement"),
                predecessors=(root_helper_id,),
                physical_position=2,
            ),
            replace(
                projection.block("condition.fallthrough"),
                physical_position=3,
            ),
            replace(projection.block("false"), physical_position=4),
            replace(
                projection.block("true"),
                predecessors=("entry", "replacement"),
                physical_position=5,
            ),
            replace(projection.block("original"), physical_position=6),
            replace(projection.block("dispatcher"), physical_position=7),
        ),
        identity_bindings=projection.identity_bindings
        + (
            ProjectedIdentityBinding(
                block_id=root_helper_id,
                logical_owner_id="logical:root-fallthrough",
                version=0,
                generation=3,
                state=FragmentBindingState.STAGED,
                stable_identity=None,
            ),
        ),
        root_fallthrough_helpers=(
            ProjectedRootFallthroughHelper(
                helper_block_id=root_helper_id,
                source_block_id="entry",
                root_block_id="replacement",
            ),
        ),
    )


def _failed_codes(
    plan: FragmentPlan, projection: ProjectedFragment
) -> set[FragmentValidationPostcondition]:
    return {
        outcome.postcondition
        for outcome in validate_fragment_projection(plan, projection).failures
    }


def _terminal_plan() -> FragmentPlan:
    source_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x1000, 0x1010),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x1000, 0x1004),
    )
    terminal_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x2000, 0x2010),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x2000,),
    )
    source_original = FragmentBlock(
        block_id="terminal-source.original",
        role=FragmentBlockRole.ORIGINAL,
        materialization=FragmentBlockMaterialization.REUSE_PUBLISHED,
        semantic_anchor_ea=0x1000,
        stable_identity=source_identity,
    )
    source_replacement = FragmentBlock(
        block_id="terminal-source.replacement",
        role=FragmentBlockRole.REPLACEMENT,
        materialization=FragmentBlockMaterialization.CLONE_PUBLISHED,
        semantic_anchor_ea=0x1000,
        stable_identity=source_identity,
        replaces_block_id=source_original.block_id,
    )
    return_original = FragmentBlock(
        block_id="terminal-return.original",
        role=FragmentBlockRole.ORIGINAL,
        materialization=FragmentBlockMaterialization.REUSE_PUBLISHED,
        semantic_anchor_ea=0x2000,
        stable_identity=terminal_identity,
    )
    return_replacement = FragmentBlock(
        block_id="terminal-return.replacement",
        role=FragmentBlockRole.REPLACEMENT,
        materialization=FragmentBlockMaterialization.CLONE_PUBLISHED,
        semantic_anchor_ea=0x2000,
        stable_identity=terminal_identity,
        replaces_block_id=return_original.block_id,
    )
    return FragmentPlan(
        plan_id="terminal-fragment",
        atomic_group_id="terminal@0x1000",
        publication_purpose=FragmentPublicationPurpose.CANONICAL_SEMANTIC_LOWERING,
        native_key=NATIVE_KEY,
        blocks=(
            _native_block("entry", FragmentBlockRole.EXTERNAL, 0x5000),
            source_original,
            source_replacement,
            return_original,
            return_replacement,
            _native_block("dispatcher", FragmentBlockRole.EXTERNAL, 0x4000),
        ),
        roots=(source_replacement.block_id,),
        owned_originals=(source_original.block_id, return_original.block_id),
        prohibited_dispatcher_blocks=("dispatcher",),
        operations=(
            FragmentOperation(
                operation_id="route-to-terminal",
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
            FragmentReturnCarrier(
                carrier_id="return-carrier",
                block_id=source_replacement.block_id,
                state_write_ea=0x1000,
                carrier_ea=0x1004,
                operation=ValueOpKind.MOVE,
                source=FragmentReturnSource(
                    kind=FragmentReturnSourceKind.CONSTANT,
                    width=4,
                    constant=7,
                ),
                return_width=4,
                corridor_instruction_eas=(0x1000, 0x1004),
            ),
        ),
        terminal_returns=(
            FragmentTerminalReturn(
                return_id="return",
                block_id=return_replacement.block_id,
                instruction_ea=0x2000,
                return_width=4,
            ),
        ),
        terminal_routes=(
            FragmentTerminalRoute(
                terminal_route_id="terminal-route",
                operation_id="route-to-terminal",
                carrier_id="return-carrier",
                return_id="return",
            ),
        ),
    )


def _terminal_projection(plan: FragmentPlan) -> ProjectedFragment:
    return ProjectedFragment(
        entry_block_id="entry",
        blocks=(
            _projected_block(
                "entry",
                BlockKind.ONE_WAY,
                ("terminal-source.replacement",),
                (),
                0,
            ),
            _projected_block(
                "terminal-source.replacement",
                BlockKind.ONE_WAY,
                ("terminal-return.replacement",),
                ("entry",),
                1,
                instruction_eas=(0x1000, 0x1004),
            ),
            _projected_block(
                "terminal-return.replacement",
                BlockKind.ZERO_WAY,
                (),
                ("terminal-source.replacement",),
                2,
                instruction_eas=(0x2000,),
            ),
            _projected_block(
                "terminal-source.original",
                BlockKind.ZERO_WAY,
                (),
                (),
                3,
            ),
            _projected_block(
                "terminal-return.original",
                BlockKind.ZERO_WAY,
                (),
                (),
                4,
            ),
            _projected_block("dispatcher", BlockKind.ZERO_WAY, (), (), 5),
        ),
        identity_bindings=(
            _binding(
                plan,
                "entry",
                "logical:entry",
                0,
                2,
                FragmentBindingState.PUBLISHED,
            ),
            _binding(
                plan,
                "terminal-source.original",
                "logical:terminal-source",
                1,
                2,
                FragmentBindingState.PUBLISHED,
            ),
            _binding(
                plan,
                "terminal-source.replacement",
                "logical:terminal-source",
                2,
                3,
                FragmentBindingState.STAGED,
                previous_version=1,
            ),
            _binding(
                plan,
                "terminal-return.original",
                "logical:terminal-return",
                4,
                2,
                FragmentBindingState.PUBLISHED,
            ),
            _binding(
                plan,
                "terminal-return.replacement",
                "logical:terminal-return",
                5,
                3,
                FragmentBindingState.STAGED,
                previous_version=4,
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
        return_carriers=plan.return_carriers,
        terminal_returns=plan.terminal_returns,
    )


def test_terminal_projection_proves_carrier_return_and_route_atomically() -> None:
    plan = _terminal_plan()

    result = validate_fragment_projection(plan, _terminal_projection(plan))

    assert result.passed, result.failures
    assert {
        FragmentValidationPostcondition.RETURN_CARRIER_INTEGRITY,
        FragmentValidationPostcondition.TERMINAL_RETURN_INTEGRITY,
        FragmentValidationPostcondition.TERMINAL_ROUTE_ATOMICITY,
    }.issubset({outcome.postcondition for outcome in result.outcomes})


def test_terminal_projection_rejects_missing_carrier_as_atomic_route_failure() -> None:
    plan = _terminal_plan()
    projection = replace(
        _terminal_projection(plan),
        return_carriers=(),
    )

    failures = validate_fragment_projection(plan, projection).failures

    assert {
        FragmentValidationPostcondition.RETURN_CARRIER_INTEGRITY,
        FragmentValidationPostcondition.TERMINAL_ROUTE_ATOMICITY,
    }.issubset({outcome.postcondition for outcome in failures})
    carrier_failure = next(
        outcome
        for outcome in failures
        if outcome.postcondition
        is FragmentValidationPostcondition.RETURN_CARRIER_INTEGRITY
    )
    assert "observed_count=0" in carrier_failure.reason
    assert "corridor_present=1" in carrier_failure.reason


def test_terminal_projection_reports_live_carrier_observation_failure() -> None:
    plan = _terminal_plan()
    carrier = plan.return_carriers[0]
    projection = replace(
        _terminal_projection(plan),
        return_carriers=(),
        terminal_effect_diagnostics=(
            ProjectedTerminalEffectDiagnostic(
                effect_id=carrier.carrier_id,
                reason="destination_register=4 expected=0",
            ),
        ),
    )

    result = validate_fragment_projection(plan, projection)
    carrier_failure = next(
        outcome
        for outcome in result.failures
        if outcome.postcondition
        is FragmentValidationPostcondition.RETURN_CARRIER_INTEGRITY
    )

    assert "live_observation=destination_register=4 expected=0" in (
        carrier_failure.reason
    )


def test_terminal_projection_rejects_nonterminal_return_block() -> None:
    plan = _terminal_plan()
    projection = _terminal_projection(plan)
    projection = _replace_blocks(
        projection,
        replace(
            projection.block("terminal-return.replacement"),
            kind=BlockKind.ONE_WAY,
            successors=("dispatcher",),
        ),
        replace(
            projection.block("dispatcher"),
            predecessors=("terminal-return.replacement",),
        ),
    )

    failures = validate_fragment_projection(plan, projection).failures

    assert {
        FragmentValidationPostcondition.TERMINAL_RETURN_INTEGRITY,
        FragmentValidationPostcondition.TERMINAL_ROUTE_ATOMICITY,
    }.issubset({outcome.postcondition for outcome in failures})
    return_failure = next(
        outcome
        for outcome in failures
        if outcome.postcondition
        is FragmentValidationPostcondition.TERMINAL_RETURN_INTEGRITY
    )
    assert "observed_count=1" in return_failure.reason
    assert "kind=one_way" in return_failure.reason
    assert "successor_count=1" in return_failure.reason


def test_terminal_projection_rejects_nonempty_special_stop_block() -> None:
    plan = _terminal_plan()
    projection = _terminal_projection(plan)
    projection = _replace_blocks(
        projection,
        replace(
            projection.block("terminal-return.replacement"),
            kind=BlockKind.STOP,
        ),
    )

    result = validate_fragment_projection(plan, projection)

    assert FragmentValidationPostcondition.TERMINAL_RETURN_INTEGRITY in {
        outcome.postcondition for outcome in result.failures
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


def test_call_fallthrough_projection_requires_one_adjacent_helper() -> None:
    plan = _plan()
    plan = replace(
        plan,
        operations=(
            FragmentOperation(
                operation_id="condition",
                source_block_id="replacement",
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.CALL_FALLTHROUGH,
                        target_block_id="false",
                    ),
                ),
            ),
        ),
    )
    projection = _projection(plan)
    projection = _replace_blocks(
        projection,
        replace(
            projection.block("replacement"),
            kind=BlockKind.ONE_WAY,
            successors=("condition.fallthrough",),
        ),
        replace(projection.block("true"), predecessors=()),
    )

    result = validate_fragment_projection(plan, projection)

    assert result.passed
    assert FragmentValidationPostcondition.FALLTHROUGH_TOPOLOGY in {
        outcome.postcondition for outcome in result.outcomes
    }


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


def test_temporary_boundary_port_is_explicit_reachability_authority() -> None:
    plan = _plan()
    port_predecessor = _native_block(
        "temporary.port.predecessor",
        FragmentBlockRole.EXTERNAL,
        0x6000,
    )
    retirement_obligation_id = (
        "retire-temporary-dispatcher-entry@0x1000:publish-semantic-predecessor@0x6000"
    )
    plan = replace(
        plan,
        blocks=plan.blocks + (port_predecessor,),
        boundary_ports=(
            FragmentBoundaryPort(
                port_id="temporary-dispatcher-entry@0x1000",
                kind=FragmentBoundaryPortKind.TEMPORARY_DISPATCHER_ENTRY,
                predecessor_block_id=port_predecessor.block_id,
                root_block_id="replacement",
                retirement_obligation_id=retirement_obligation_id,
            ),
        ),
    )
    projection = _projection(plan)
    projection = _replace_blocks(
        projection,
        replace(
            projection.block("entry"),
            kind=BlockKind.ZERO_WAY,
            successors=(),
        ),
        replace(
            projection.block("replacement"),
            predecessors=(port_predecessor.block_id,),
        ),
    )
    projection = replace(
        projection,
        blocks=projection.blocks
        + (
            _projected_block(
                port_predecessor.block_id,
                BlockKind.ONE_WAY,
                ("replacement",),
                (),
                7,
                instruction_eas=(0x6000,),
            ),
        ),
        identity_bindings=projection.identity_bindings
        + (
            _binding(
                plan,
                port_predecessor.block_id,
                "logical:temporary-port-predecessor",
                0,
                2,
                FragmentBindingState.PUBLISHED,
            ),
        ),
    )

    prepublication = validate_fragment_projection(plan, projection)
    published = validate_published_fragment_projection(plan, projection)

    assert prepublication.passed
    assert published.passed
    for result in (prepublication, published):
        root_outcome = next(
            outcome
            for outcome in result.outcomes
            if outcome.postcondition
            is FragmentValidationPostcondition.ROOT_REACHABILITY
        )
        assert root_outcome.passed
        assert retirement_obligation_id in root_outcome.reason
        assert root_outcome.block_ids == (
            port_predecessor.block_id,
            "replacement",
        )


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
                7,
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


def test_detached_native_body_entry_is_only_a_prepublication_connectivity_root() -> (
    None
):
    plan = _plan()
    body_id = "detached-native-body"
    imported = FragmentBlock(
        block_id="detached.imported",
        role=FragmentBlockRole.IMPORTED,
        materialization=FragmentBlockMaterialization.IMPORT_NATIVE,
        semantic_anchor_ea=0x6000,
        stable_identity=_identity(0x6000),
        native_body_id=body_id,
    )
    plan = replace(
        plan,
        blocks=plan.blocks + (imported,),
        operations=plan.operations
        + (
            FragmentOperation(
                operation_id="detached-native-operation",
                source_block_id=imported.block_id,
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.DIRECT,
                        target_block_id="true",
                    ),
                ),
            ),
        ),
        native_bodies=(
            FragmentNativeBody(
                body_id=body_id,
                block_ids=(imported.block_id,),
                entry_block_ids=(imported.block_id,),
                terminal_block_ids=(),
                native_ranges=(NativeEaInterval(0x6000, 0x6010),),
                proof_ids=("detached-native-operation",),
            ),
        ),
    )
    projection = _projection(plan)
    projection = _replace_blocks(
        projection,
        replace(
            projection.block("true"),
            predecessors=("replacement", imported.block_id),
        ),
    )
    projection = replace(
        projection,
        blocks=projection.blocks
        + (
            _projected_block(
                imported.block_id,
                BlockKind.ONE_WAY,
                ("true",),
                (),
                7,
                instruction_eas=(0x6000,),
            ),
        ),
        identity_bindings=projection.identity_bindings
        + (
            ProjectedIdentityBinding(
                block_id=imported.block_id,
                logical_owner_id="logical:detached-imported",
                version=0,
                generation=3,
                state=FragmentBindingState.STAGED,
                stable_identity=imported.stable_identity,
            ),
        ),
    )

    result = validate_fragment_projection(plan, projection)

    assert result.passed
    assert not {
        FragmentValidationPostcondition.INTERNAL_CONNECTIVITY,
        FragmentValidationPostcondition.OPERATION_REACHABILITY,
    }.intersection(outcome.postcondition for outcome in result.failures)

    published = validate_published_fragment_projection(plan, projection)
    failures = {
        (outcome.postcondition, outcome.subject_id): outcome
        for outcome in published.failures
    }
    operation_failure = failures[
        (
            FragmentValidationPostcondition.OPERATION_REACHABILITY,
            "detached-native-operation",
        )
    ]
    assert operation_failure.block_ids == (imported.block_id,)
    assert "function entry" in operation_failure.reason


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

    failure = next(
        outcome
        for outcome in validate_fragment_projection(_plan(), projection).failures
        if outcome.postcondition is FragmentValidationPostcondition.DISPATCHER_ABSENCE
    )
    assert failure.block_ids == (
        "entry",
        "replacement",
        "condition.fallthrough",
        "false",
        "dispatcher",
    )
    assert (
        "witness=entry -> replacement -> condition.fallthrough -> false -> dispatcher"
        in failure.reason
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


def test_staged_block_with_opaque_endpoint_is_not_closed() -> None:
    projection = _projection()
    projection = _replace_blocks(
        projection,
        replace(
            projection.block("replacement"),
            successors=("condition.fallthrough", "unowned:blk77@0x1000"),
        ),
        replace(projection.block("true"), predecessors=()),
    )

    assert FragmentValidationPostcondition.GRAPH_CLOSURE in _failed_codes(
        _plan(),
        projection,
    )


def test_published_block_may_observe_opaque_boundary_edges() -> None:
    projection = _projection()
    projection = _replace_blocks(
        projection,
        replace(
            projection.block("original"),
            kind=BlockKind.ONE_WAY,
            successors=("unowned:blk78@0x1010",),
            predecessors=("unowned:blk79@0x0FF0",),
        ),
    )

    result = validate_fragment_projection(_plan(), projection)

    assert result.passed, result.failures


def _reachable_opaque_published_conditional_projection(
    *,
    witness: str | None,
) -> ProjectedFragment:
    projection = _projection()
    opaque_fallthrough = "unowned:blk9@0x401100"
    opaque_taken = "unowned:blk14@0x401140"
    return _replace_blocks(
        projection,
        replace(
            projection.block("true"),
            kind=BlockKind.TWO_WAY,
            successors=(opaque_fallthrough, opaque_taken),
            adjacent_fallthrough_target_id=witness,
        ),
        replace(projection.block("original"), physical_position=6),
        replace(projection.block("dispatcher"), physical_position=7),
    )


def test_reachable_published_conditional_uses_opaque_fallthrough_witness() -> None:
    projection = _reachable_opaque_published_conditional_projection(
        witness="unowned:blk9@0x401100",
    )

    result = validate_fragment_projection(_plan(), projection)

    assert result.passed, result.failures


def test_reachable_published_conditional_rejects_missing_fallthrough_witness() -> None:
    projection = _reachable_opaque_published_conditional_projection(witness=None)

    result = validate_fragment_projection(_plan(), projection)

    failures = {
        (outcome.postcondition, outcome.subject_id) for outcome in result.failures
    }
    assert (
        FragmentValidationPostcondition.FALLTHROUGH_TOPOLOGY,
        "true",
    ) in failures


def test_unreachable_published_conditional_keeps_same_ea_boundaries_distinct() -> None:
    projection = _projection()
    projection = _replace_blocks(
        projection,
        replace(
            projection.block("original"),
            kind=BlockKind.TWO_WAY,
            successors=(
                "unowned:blk80@0x1004",
                "unowned:blk81@0x1004",
            ),
        ),
    )

    result = validate_fragment_projection(_plan(), projection)

    assert result.passed, result.failures


def test_nonadjacent_conditional_fallthrough_is_rejected() -> None:
    projection = _projection()
    projection = _replace_blocks(
        projection,
        replace(projection.block("condition.fallthrough"), physical_position=4),
        replace(projection.block("true"), physical_position=2),
    )

    assert FragmentValidationPostcondition.FALLTHROUGH_TOPOLOGY in _failed_codes(
        _plan(),
        projection,
    )


def test_nonadjacent_external_conditional_fallthrough_is_rejected() -> None:
    projection = _projection()
    projection = _replace_blocks(
        projection,
        replace(
            projection.block("entry"),
            kind=BlockKind.TWO_WAY,
            successors=("true", "replacement"),
        ),
        replace(
            projection.block("true"),
            predecessors=("entry", "replacement"),
        ),
    )

    assert FragmentValidationPostcondition.FALLTHROUGH_TOPOLOGY in _failed_codes(
        _plan(),
        projection,
    )


def test_fallthrough_helper_must_be_transparent_and_operation_owned() -> None:
    projection = _projection()
    projection = _replace_blocks(
        projection,
        replace(
            projection.block("condition.fallthrough"),
            successors=("true",),
        ),
        replace(projection.block("false"), predecessors=()),
        replace(
            projection.block("true"),
            predecessors=("replacement", "condition.fallthrough"),
        ),
    )

    failed = _failed_codes(_plan(), projection)

    assert FragmentValidationPostcondition.OPERATION_TOPOLOGY in failed
    assert FragmentValidationPostcondition.FALLTHROUGH_TOPOLOGY in failed


def test_broken_use_def_and_def_use_relations_are_rejected() -> None:
    projection = replace(_projection(), data_flow_relations=())

    failures = validate_fragment_projection(_plan(), projection).failures
    failed = {outcome.postcondition for outcome in failures}

    assert FragmentValidationPostcondition.USE_DEF_INTEGRITY in failed
    assert FragmentValidationPostcondition.DEF_USE_INTEGRITY in failed
    use_def = next(
        outcome
        for outcome in failures
        if outcome.postcondition is FragmentValidationPostcondition.USE_DEF_INTEGRITY
    )
    assert "missing_sites=()" in use_def.reason
    assert "observed_use_def=(('flags.use', (), 0),)" in use_def.reason
    def_use = next(
        outcome
        for outcome in failures
        if outcome.postcondition is FragmentValidationPostcondition.DEF_USE_INTEGRITY
    )
    assert "expected_uses=('flags.use',)" in def_use.reason
    assert "observed_uses=()" in def_use.reason
    assert "observed_relation_count=0" in def_use.reason


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


def test_missing_flag_producer_write_is_rejected() -> None:
    projection = _projection()
    projection = _replace_blocks(
        projection,
        replace(
            projection.block("replacement"),
            flag_write_eas=frozenset(),
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
                observation=FragmentRangeObservation.AFTER_INSTRUCTION,
                lo=0,
                hi=2,
            ),
        ),
    )

    assert FragmentValidationPostcondition.VALUE_RANGE_PROVEN in _failed_codes(
        _plan(),
        projection,
    )


def test_range_at_wrong_instruction_observation_is_rejected() -> None:
    projection = _projection()
    projection = replace(
        projection,
        value_ranges=(
            replace(
                projection.value_ranges[0],
                observation=FragmentRangeObservation.BEFORE_INSTRUCTION,
            ),
        ),
    )

    assert FragmentValidationPostcondition.VALUE_RANGE_PROVEN in _failed_codes(
        _plan(),
        projection,
    )


def test_data_flow_requires_independent_ud_and_du_observations() -> None:
    projection = _projection()
    relation = projection.data_flow_relations[0]

    only_use_def = replace(
        projection,
        data_flow_relations=(replace(relation, def_use_observed=False),),
    )
    only_def_use = replace(
        projection,
        data_flow_relations=(replace(relation, use_def_observed=False),),
    )

    assert _failed_codes(_plan(), only_use_def) == {
        FragmentValidationPostcondition.DEF_USE_INTEGRITY,
    }
    assert _failed_codes(_plan(), only_def_use) == {
        FragmentValidationPostcondition.USE_DEF_INTEGRITY,
    }


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


def test_external_block_kind_accepts_zero_successor_frontier() -> None:
    projection = _projection()
    projection = _replace_blocks(
        projection,
        replace(projection.block("true"), kind=BlockKind.EXTERNAL),
    )

    result = validate_fragment_projection(_plan(), projection)

    assert result.passed, result.failures


def test_unknown_block_kind_is_rejected_without_exception() -> None:
    projection = _projection()
    projection = _replace_blocks(
        projection,
        replace(projection.block("true"), kind=BlockKind.UNKNOWN),
    )

    assert FragmentValidationPostcondition.BLOCK_TOPOLOGY in _failed_codes(
        _plan(),
        projection,
    )


def _published_observation(
    plan: FragmentPlan | None = None,
) -> PublishedFragmentObservation:
    plan = _plan() if plan is None else plan
    projection = _projection(plan)
    prevalidation = validate_fragment_projection(plan, projection)
    assert prevalidation.passed
    return PublishedFragmentObservation(
        plan_id=plan.plan_id,
        atomic_group_id=plan.atomic_group_id,
        published_root_ids=plan.roots,
        observable_operations=plan.operations,
        semantic_outcomes=prevalidation.outcomes,
        fallthrough_helpers=projection.fallthrough_helpers,
        root_fallthrough_helpers=projection.root_fallthrough_helpers,
    )


def _published_terminal_observation(
    plan: FragmentPlan,
) -> PublishedFragmentObservation:
    projection = _terminal_projection(plan)
    prevalidation = validate_fragment_projection(plan, projection)
    assert prevalidation.passed
    return PublishedFragmentObservation(
        plan_id=plan.plan_id,
        atomic_group_id=plan.atomic_group_id,
        published_root_ids=plan.roots,
        observable_operations=plan.operations,
        semantic_outcomes=prevalidation.outcomes,
        fallthrough_helpers=(),
        root_fallthrough_helpers=(),
        observable_return_carriers=plan.return_carriers,
        observable_terminal_returns=plan.terminal_returns,
    )


def test_postpublication_requires_observable_terminal_effects() -> None:
    plan = _terminal_plan()
    projection = _terminal_projection(plan)

    result = validate_published_fragment_observation(
        plan,
        _published_terminal_observation(plan),
        projection,
    )

    assert result.passed, result.failures
    assert {
        FragmentValidationPostcondition.OBSERVABLE_RETURN_CARRIER,
        FragmentValidationPostcondition.OBSERVABLE_TERMINAL_RETURN,
    }.issubset({outcome.postcondition for outcome in result.outcomes})


def test_postpublication_rejects_disappeared_return_carrier() -> None:
    plan = _terminal_plan()
    projection = _terminal_projection(plan)
    observation = replace(
        _published_terminal_observation(plan),
        observable_return_carriers=(),
    )

    result = validate_published_fragment_observation(
        plan,
        observation,
        projection,
    )

    assert FragmentValidationPostcondition.OBSERVABLE_RETURN_CARRIER in {
        outcome.postcondition for outcome in result.failures
    }


def test_postpublication_accepts_observable_semantics_without_physical_blocks() -> None:
    plan = _plan()
    observation = _published_observation(plan)

    result = validate_published_fragment_observation(
        plan, observation, _projection(plan)
    )

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

    result = validate_published_fragment_observation(
        plan, observation, _projection(plan)
    )

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

    result = validate_published_fragment_observation(
        plan, observation, _projection(plan)
    )

    assert FragmentValidationPostcondition.POSTVALIDATION_COVERAGE in {
        outcome.postcondition for outcome in result.failures
    }


def test_postpublication_rejects_missing_root_authority() -> None:
    plan = _plan()
    observation = replace(
        _published_observation(plan),
        published_root_ids=(),
    )

    result = validate_published_fragment_observation(
        plan, observation, _projection(plan)
    )

    assert FragmentValidationPostcondition.ROOT_AUTHORITY in {
        outcome.postcondition for outcome in result.failures
    }


def test_postpublication_rejects_missing_projected_fallthrough_helper() -> None:
    plan = _plan()
    projection = _projection(plan)
    observation = replace(
        _published_observation(plan),
        fallthrough_helpers=(),
    )

    result = validate_published_fragment_observation(plan, observation, projection)

    assert FragmentValidationPostcondition.OBSERVABLE_FALLTHROUGH_HELPER in {
        outcome.postcondition for outcome in result.failures
    }


def test_postpublication_rejects_helper_without_live_topology_outcome() -> None:
    plan = _plan()
    projection = _projection(plan)
    observation = _published_observation(plan)
    observation = replace(
        observation,
        semantic_outcomes=tuple(
            outcome
            for outcome in observation.semantic_outcomes
            if outcome.postcondition
            is not FragmentValidationPostcondition.FALLTHROUGH_TOPOLOGY
        ),
    )

    result = validate_published_fragment_observation(plan, observation, projection)

    assert FragmentValidationPostcondition.POSTVALIDATION_COVERAGE in {
        outcome.postcondition for outcome in result.failures
    }


def test_postpublication_rejects_missing_projected_root_fallthrough_helper() -> None:
    plan = _plan()
    projection = _projection_with_root_fallthrough_helper(plan)
    prevalidation = validate_fragment_projection(plan, projection)
    assert prevalidation.passed
    observation = PublishedFragmentObservation(
        plan_id=plan.plan_id,
        atomic_group_id=plan.atomic_group_id,
        published_root_ids=plan.roots,
        observable_operations=plan.operations,
        semantic_outcomes=prevalidation.outcomes,
        fallthrough_helpers=projection.fallthrough_helpers,
        root_fallthrough_helpers=(),
    )

    result = validate_published_fragment_observation(plan, observation, projection)

    assert FragmentValidationPostcondition.OBSERVABLE_FALLTHROUGH_HELPER in {
        outcome.postcondition for outcome in result.failures
    }
