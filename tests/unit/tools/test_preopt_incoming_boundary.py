from d810.analyses.control_flow.materialized_indirect_transfer import (
    MaterializedIndirectTransfer,
)
from tools.scripts.rhad_investigation.preopt_incoming_boundary import (
    PreoptDirectReplayMode,
    PreoptIncomingBoundaryAbstentionReason,
    classify_preopt_direct_replay_shape,
    expand_preopt_boundary_target_closure,
    exclude_conflicting_direct_boundaries_by_source,
    exclude_direct_boundaries_with_conditional_source,
    orient_preopt_conditional_boundary,
    plan_preopt_incoming_boundaries,
)


def _direct(
    source_ea: int,
    target_ea: int,
    state: int,
) -> MaterializedIndirectTransfer:
    return MaterializedIndirectTransfer(
        source_jmp_ea=source_ea,
        source_block_ea=source_ea,
        materialized_anchor_eas=(source_ea,),
        target_eas=(target_ea,),
        selector_state_constant=state,
        selector_state_var_reg=20,
        resolver_kind="residual_state_route_evidence",
    )


def _conditional(
    predicate_ea: int,
    true_target_ea: int,
    false_target_ea: int,
    *,
    true_is_taken: bool = False,
) -> MaterializedIndirectTransfer:
    return MaterializedIndirectTransfer(
        source_jmp_ea=predicate_ea,
        source_block_ea=predicate_ea - 0x10,
        materialized_anchor_eas=(predicate_ea,),
        target_eas=(true_target_ea, false_target_ea),
        condition_code=5,
        true_target_ea=true_target_ea,
        false_target_ea=false_target_ea,
        selector_state_var_reg=20,
        resolver_kind="conditional_handler_bridge",
        predicate_register=12,
        predicate_size=4,
        predicate_true_state=0x11111111,
        predicate_false_state=0x22222222,
        predicate_true_is_taken=true_is_taken,
        predicate_preserve_live=True,
    )


def _handler_route(
    target_ea: int,
    ranges: tuple[tuple[int, int], ...],
) -> MaterializedIndirectTransfer:
    return MaterializedIndirectTransfer(
        source_jmp_ea=target_ea - 1,
        source_block_ea=target_ea - 1,
        materialized_anchor_eas=(),
        target_eas=(target_ea,),
        resolver_kind="static_handler_entry_route",
        owned_native_ranges=ranges,
    )


def test_plans_singleton_direct_boundary_into_imported_union() -> None:
    plan = plan_preopt_incoming_boundaries(
        (_direct(0x401020, 0x402000, 0xAABBCCDD),),
        imported_target_eas=frozenset({0x402000}),
    )

    assert plan.direct == (
        plan.direct[0].__class__(
            source_ea=0x401020,
            target_ea=0x402000,
            state_constant=0xAABBCCDD,
            state_register=20,
            requires_literal_state_write=True,
        ),
    )
    assert plan.conditional == ()
    assert plan.abstentions == ()


def test_conflicting_direct_boundary_abstains_atomically() -> None:
    plan = plan_preopt_incoming_boundaries(
        (
            _direct(0x401020, 0x402000, 1),
            _direct(0x401020, 0x403000, 2),
        ),
        imported_target_eas=frozenset({0x402000, 0x403000}),
    )

    assert plan.direct == ()
    assert plan.abstentions[0].source_ea == 0x401020
    assert (
        plan.abstentions[0].reason
        is PreoptIncomingBoundaryAbstentionReason.CONFLICTING_DIRECT_EVIDENCE
    )


def test_plans_complete_conditional_when_either_arm_enters_union() -> None:
    transfer = _conditional(0x404040, 0x405000, 0x406000)

    plan = plan_preopt_incoming_boundaries(
        (transfer,),
        imported_target_eas=frozenset({0x406000}),
    )

    assert len(plan.conditional) == 1
    boundary = plan.conditional[0]
    assert boundary.predicate_ea == 0x404040
    assert boundary.source_block_ea == 0x404030
    assert boundary.true_target_ea == 0x405000
    assert boundary.false_target_ea == 0x406000
    assert boundary.predicate_register == 12
    assert boundary.predicate_size == 4
    assert boundary.state_register == 20
    assert boundary.true_state == 0x11111111
    assert boundary.false_state == 0x22222222
    assert boundary.true_is_taken is False
    assert boundary.preserve_live is True
    assert plan.direct == ()
    assert plan.abstentions == ()


def test_incomplete_conditional_boundary_abstains() -> None:
    incomplete = _conditional(0x407040, 0x408000, 0x409000)
    incomplete = MaterializedIndirectTransfer(
        source_jmp_ea=incomplete.source_jmp_ea,
        source_block_ea=incomplete.source_block_ea,
        materialized_anchor_eas=incomplete.materialized_anchor_eas,
        target_eas=incomplete.target_eas,
        condition_code=incomplete.condition_code,
        true_target_ea=incomplete.true_target_ea,
        false_target_ea=incomplete.false_target_ea,
        resolver_kind=incomplete.resolver_kind,
        predicate_register=incomplete.predicate_register,
        predicate_size=incomplete.predicate_size,
        predicate_true_state=None,
        predicate_false_state=incomplete.predicate_false_state,
        predicate_true_is_taken=incomplete.predicate_true_is_taken,
    )

    plan = plan_preopt_incoming_boundaries(
        (incomplete,),
        imported_target_eas=frozenset({0x408000}),
    )

    assert plan.conditional == ()
    assert plan.abstentions[0].source_ea == 0x407040
    assert (
        plan.abstentions[0].reason
        is PreoptIncomingBoundaryAbstentionReason.INCOMPLETE_CONDITIONAL_EVIDENCE
    )


def test_conditional_orientation_tracks_original_taken_polarity() -> None:
    logical_true_taken = plan_preopt_incoming_boundaries(
        (_conditional(0x501040, 0x502000, 0x503000, true_is_taken=True),),
        imported_target_eas=frozenset({0x502000}),
    ).conditional[0]
    original_taken = orient_preopt_conditional_boundary(logical_true_taken)
    assert (
        original_taken.false_target_ea,
        original_taken.true_target_ea,
        original_taken.false_state,
        original_taken.true_state,
    ) == (0x503000, 0x502000, 0x22222222, 0x11111111)

    logical_false_taken_transfer = _conditional(0x504040, 0x505000, 0x506000)
    logical_false_taken_transfer = MaterializedIndirectTransfer(
        source_jmp_ea=logical_false_taken_transfer.source_jmp_ea,
        source_block_ea=logical_false_taken_transfer.source_block_ea,
        materialized_anchor_eas=logical_false_taken_transfer.materialized_anchor_eas,
        target_eas=logical_false_taken_transfer.target_eas,
        condition_code=logical_false_taken_transfer.condition_code,
        true_target_ea=logical_false_taken_transfer.true_target_ea,
        false_target_ea=logical_false_taken_transfer.false_target_ea,
        selector_state_var_reg=logical_false_taken_transfer.selector_state_var_reg,
        resolver_kind=logical_false_taken_transfer.resolver_kind,
        predicate_register=logical_false_taken_transfer.predicate_register,
        predicate_size=logical_false_taken_transfer.predicate_size,
        predicate_true_state=logical_false_taken_transfer.predicate_true_state,
        predicate_false_state=logical_false_taken_transfer.predicate_false_state,
        predicate_true_is_taken=False,
        predicate_preserve_live=True,
    )
    logical_false_taken = plan_preopt_incoming_boundaries(
        (logical_false_taken_transfer,),
        imported_target_eas=frozenset({0x505000}),
    ).conditional[0]
    original_taken = orient_preopt_conditional_boundary(logical_false_taken)
    assert (
        original_taken.false_target_ea,
        original_taken.true_target_ea,
        original_taken.false_state,
        original_taken.true_state,
    ) == (0x505000, 0x506000, 0x11111111, 0x22222222)


def test_conditional_source_suppresses_direct_sibling_atomically() -> None:
    plan = plan_preopt_incoming_boundaries(
        (
            _direct(0x601020, 0x602000, 1),
            _direct(0x603020, 0x604000, 2),
            _conditional(0x601030, 0x605000, 0x602000),
        ),
        imported_target_eas=frozenset({0x602000, 0x604000}),
    )

    selected = exclude_direct_boundaries_with_conditional_source(
        plan.direct,
        plan.conditional,
        source_identity_by_ea={
            0x601020: 7,
            0x601030: 7,
            0x603020: 9,
        },
    )

    assert tuple(row.source_ea for row in selected) == (0x603020,)


def test_multiple_direct_rows_bound_to_one_preopt_block_abstain_atomically() -> None:
    plan = plan_preopt_incoming_boundaries(
        (
            _direct(0x701020, 0x702000, 1),
            _direct(0x701030, 0x703000, 2),
            _direct(0x704020, 0x705000, 3),
        ),
        imported_target_eas=frozenset({0x702000, 0x703000, 0x705000}),
    )

    selected, conflicts = exclude_conflicting_direct_boundaries_by_source(
        plan.direct,
        source_identity_by_ea={
            0x701020: 7,
            0x701030: 7,
            0x704020: 9,
        },
    )

    assert tuple(row.source_ea for row in selected) == (0x704020,)
    assert conflicts == (0x701020, 0x701030)


def test_call_bearing_via_route_requires_adjacent_helper_replay() -> None:
    assert (
        classify_preopt_direct_replay_shape(
            has_via=True,
            source_nsucc=0,
            tail_is_call=True,
            tail_is_goto=False,
            tail_is_indirect_jump=False,
            tail_is_closing=True,
            via_is_adjacent=True,
            successor_is_via=False,
        )
        is PreoptDirectReplayMode.PRESERVE_CALL
    )


def test_call_bearing_via_route_abstains_without_adjacent_native_fallthrough() -> None:
    assert (
        classify_preopt_direct_replay_shape(
            has_via=True,
            source_nsucc=0,
            tail_is_call=True,
            tail_is_goto=False,
            tail_is_indirect_jump=False,
            tail_is_closing=True,
            via_is_adjacent=False,
            successor_is_via=False,
        )
        is PreoptDirectReplayMode.ABSTAIN
    )


def test_noncall_via_route_keeps_terminal_goto_replay() -> None:
    assert (
        classify_preopt_direct_replay_shape(
            has_via=True,
            source_nsucc=1,
            tail_is_call=False,
            tail_is_goto=False,
            tail_is_indirect_jump=False,
            tail_is_closing=False,
            via_is_adjacent=False,
            successor_is_via=True,
        )
        is PreoptDirectReplayMode.REDIRECT_EDGE
    )


def test_zero_way_goto_via_route_seeds_then_redirects_existing_edge() -> None:
    assert (
        classify_preopt_direct_replay_shape(
            has_via=True,
            source_nsucc=0,
            tail_is_call=False,
            tail_is_goto=True,
            tail_is_indirect_jump=False,
            tail_is_closing=True,
            via_is_adjacent=False,
            successor_is_via=False,
        )
        is PreoptDirectReplayMode.REDIRECT_EDGE
    )


def test_conditional_via_route_abstains_without_both_arm_proofs() -> None:
    assert (
        classify_preopt_direct_replay_shape(
            has_via=True,
            source_nsucc=0,
            tail_is_call=False,
            tail_is_goto=False,
            tail_is_indirect_jump=False,
            tail_is_closing=True,
            via_is_adjacent=True,
            successor_is_via=False,
        )
        is PreoptDirectReplayMode.ABSTAIN
    )


def test_expands_imported_targets_through_unique_handler_owners() -> None:
    transfers = (
        _handler_route(0x1000, ((0x1000, 0x1100),)),
        _handler_route(0x2000, ((0x2000, 0x2100),)),
        _handler_route(0x3000, ((0x3000, 0x3100),)),
        _handler_route(0x4000, ((0x4000, 0x4100),)),
        _direct(0x1050, 0x2000, 1),
        _conditional(0x3050, 0x1000, 0x4000),
        _direct(0x0500, 0x3000, 2),
    )

    closure = expand_preopt_boundary_target_closure(
        transfers,
        imported_target_eas=frozenset({0x2000}),
    )

    assert closure.target_eas == (0x1000, 0x2000, 0x3000)
    assert closure.ambiguous_source_eas == ()


def test_target_closure_reports_ambiguous_handler_ownership() -> None:
    transfers = (
        _handler_route(0x5000, ((0x5000, 0x5100),)),
        _handler_route(0x6000, ((0x6000, 0x6100),)),
        _handler_route(0x7000, ((0x6080, 0x6180),)),
        _direct(0x6090, 0x5000, 3),
    )

    closure = expand_preopt_boundary_target_closure(
        transfers,
        imported_target_eas=frozenset({0x5000}),
    )

    assert closure.target_eas == (0x5000,)
    assert closure.ambiguous_source_eas == (0x6090,)


def test_ignores_evidence_that_does_not_enter_imported_union() -> None:
    plan = plan_preopt_incoming_boundaries(
        (
            _direct(0x40A000, 0x40B000, 3),
            _conditional(0x40C000, 0x40D000, 0x40E000),
        ),
        imported_target_eas=frozenset({0x40F000}),
    )

    assert plan.direct == ()
    assert plan.conditional == ()
    assert plan.abstentions == ()
