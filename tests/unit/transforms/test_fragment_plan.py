"""Portable semantic-fragment planning contract."""

from __future__ import annotations

from dataclasses import fields, replace

import pytest

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
    FragmentEdge,
    FragmentFlagCorridor,
    FragmentOperation,
    FragmentPlan,
    FragmentPlanRejected,
    FragmentPublicationPurpose,
    FragmentRangeAssumption,
    FragmentRangeObservation,
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
            terminal_returns=(
                replace(plan.terminal_returns[0], return_width=8),
            ),
        )


def test_fragment_plan_requires_exact_terminal_effect_anchors() -> None:
    plan = _terminal_plan()
    carrier = plan.return_carriers[0]

    with pytest.raises(
        FragmentPlanRejected,
        match="exact anchors owned by its block identity",
    ):
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
