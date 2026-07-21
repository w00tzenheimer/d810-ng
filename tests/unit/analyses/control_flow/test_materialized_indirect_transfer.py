"""Tests for resolver-proven computed-goto transfer evidence."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from d810.analyses.control_flow.interval_map import IntervalDispatcher, IntervalRow
from d810.analyses.control_flow.materialized_indirect_transfer import (
    MaterializedIndirectTransfer,
    MaterializedStateRoute,
    ResidualIndirectCallNeutralizationPlan,
    ResidualStateRouteBridgePlan,
    TerminalReturnCarrierRequest,
    exact_materialized_handler_override_serial,
    override_materialized_handler_targets,
    select_materialized_handler_owner_serial,
    merge_materialized_handler_maps,
    find_unique_target_block,
    find_unique_target_entry_block,
    instruction_backed_materialized_handler_owners,
    lookup_state_keyed_transfer_target,
    lookup_singleton_transfer_target,
    materialized_dispatcher_router_native_ranges,
    mutation_authoritative_materialized_transfers,
    native_origin_blocks_in_ranges,
    materialized_terminal_target_eas_by_source,
    missing_materialized_handler_targets,
    plan_terminal_return_carrier_requests,
    plan_terminal_return_carrier_requests_from_native_routes,
    plan_terminal_return_carrier_requests_from_state_writes,
    plan_resolver_proven_indirect_call_neutralizations,
    route_materialized_transfer_chain,
    route_transfer_target_through_condition_chain,
    plan_residual_state_route_bridges,
    unique_materialized_conditional_handler_entry_eas,
    unique_materialized_equality_target_eas,
    unique_materialized_state_register,
)
from d810.analyses.control_flow.minimal_state_recovery import (
    HandlerTransition,
    StateWriteTransition,
    TransitionArm,
    resolve_materialized_handler_exit_states,
    resolve_materialized_handler_transition_targets,
    resolve_materialized_indirect_transfer_targets,
)
from d810.analyses.control_flow.route_predicate import DecisionDag, RouteComparison
from d810.ir.flowgraph import (
    BlockKind,
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)


def test_mutation_projection_excludes_observation_only_transfer_kinds() -> None:
    static = MaterializedIndirectTransfer(
        0x1010,
        0x1000,
        (0x1010,),
        (0x2000,),
        resolver_kind="static_fixpoint",
    )
    exit_route = MaterializedIndirectTransfer(
        0x2010,
        0x2000,
        (),
        (0x3000,),
        selector_state_var_reg=28,
        selector_state_constant=0xAABBCCDD,
        resolver_kind="static_handler_exit_route",
    )
    observation = MaterializedIndirectTransfer(
        0x3010,
        0x3000,
        (),
        (0x4000,),
        selector_state_var_reg=28,
        selector_state_constant=0xAABBCCDD,
        resolver_kind="condition_chain_handler_evidence",
    )
    raw_choice = MaterializedIndirectTransfer(
        0x4010,
        0x4000,
        (0x4010,),
        (),
        selector_state_var_reg=28,
        predicate_true_state=1,
        predicate_false_state=2,
        resolver_kind="static_conditional_state_choice",
    )
    transfers = (static, observation, raw_choice, exit_route)

    assert mutation_authoritative_materialized_transfers(transfers) == (
        static,
        exit_route,
    )
    assert transfers == (static, observation, raw_choice, exit_route)


def test_mutation_projection_prefers_stronger_equivalent_static_predicate() -> None:
    stronger = MaterializedIndirectTransfer(
        0x40E20E,
        0x40E1F6,
        (0x40E200, 0x40E20E),
        (0x40F12D, 0x40DC04),
        condition_code=4,
        true_target_ea=0x40F12D,
        false_target_ea=0x40DC04,
        selector_state_var_reg=28,
        predicate_true_state=0x3AF41FBE,
        predicate_false_state=0x85AE90D3,
        resolver_kind="static_conditional_state_choice_bridge",
    )
    weaker_equivalent = MaterializedIndirectTransfer(
        0x40E20E,
        0x40E208,
        (0x40E20E,),
        (0x40DC04, 0x40F12D),
        condition_code=5,
        true_target_ea=0x40DC04,
        false_target_ea=0x40F12D,
        selector_state_var_reg=28,
        predicate_true_state=0x85AE90D3,
        predicate_false_state=0x3AF41FBE,
        resolver_kind="static_conditional_state_choice_bridge",
    )
    unique_branch = MaterializedIndirectTransfer(
        0x40E300,
        0x40E2F0,
        (0x40E300,),
        (0x40E400, 0x40E500),
        condition_code=4,
        true_target_ea=0x40E400,
        false_target_ea=0x40E500,
        selector_state_var_reg=28,
        predicate_true_state=3,
        predicate_false_state=4,
        resolver_kind="static_conditional_state_choice_bridge",
    )
    conflicting = MaterializedIndirectTransfer(
        0x40E300,
        0x40E2F0,
        (0x40E2F8, 0x40E300),
        (0x40E400, 0x40E600),
        condition_code=4,
        true_target_ea=0x40E400,
        false_target_ea=0x40E600,
        selector_state_var_reg=28,
        predicate_true_state=3,
        predicate_false_state=4,
        resolver_kind="static_conditional_state_choice_bridge",
    )

    assert mutation_authoritative_materialized_transfers(
        (weaker_equivalent, stronger, unique_branch, conflicting)
    ) == (stronger,)


def test_mutation_projection_rejects_shared_entry_dispatch_navigation_source() -> None:
    first_handler = MaterializedIndirectTransfer(
        0x5000,
        0x5000,
        (),
        (0x5100,),
        selector_state_var_reg=28,
        selector_state_constant=1,
        resolver_kind="static_handler_entry_route",
    )
    second_handler = MaterializedIndirectTransfer(
        0x6000,
        0x6000,
        (),
        (0x6100,),
        selector_state_var_reg=28,
        selector_state_constant=2,
        resolver_kind="static_handler_entry_route",
    )
    navigation_first = MaterializedIndirectTransfer(
        0x4000,
        0x4000,
        (),
        (0x5100,),
        selector_state_var_reg=28,
        selector_state_constant=1,
        resolver_kind="static_handler_entry_route",
    )
    navigation_second = MaterializedIndirectTransfer(
        0x4000,
        0x4000,
        (),
        (0x6100,),
        selector_state_var_reg=28,
        selector_state_constant=2,
        resolver_kind="static_handler_entry_route",
    )

    assert mutation_authoritative_materialized_transfers(
        (
            navigation_first,
            first_handler,
            navigation_second,
            second_handler,
        )
    ) == (first_handler, second_handler)


def _block(
    serial: int,
    start_ea: int,
    insn_eas: tuple[int, ...] = (),
    succs: tuple[int, ...] = (),
) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=0,
        succs=succs,
        preds=(),
        flags=0,
        start_ea=start_ea,
        insn_snapshots=tuple(
            InsnSnapshot(opcode=0, ea=ea, operands=()) for ea in insn_eas
        ),
    )


def _graph() -> FlowGraph:
    return FlowGraph(
        blocks={
            1: _block(1, 0x1000, (0x1002,)),
            2: _block(2, 0x2000, (0x2000, 0x2004)),
            3: _block(3, 0x3000, (0x3000,)),
        },
        entry_serial=1,
        func_ea=0x1000,
    )


def test_unique_materialized_state_register_accepts_exact_resolver_consensus():
    transfers = (
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40CA05,
            source_block_ea=0x40C9EC,
            materialized_anchor_eas=(0x40C9F2,),
            target_eas=(0x40CA22, 0x40CA60),
            selector_state_var_reg=20,
            selector_compare_constant=0xA7AFB008,
            resolver_kind="static_fixpoint",
        ),
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40CA3B,
            source_block_ea=0x40CA22,
            materialized_anchor_eas=(0x40CA28,),
            target_eas=(0x40C9DB, 0x40CA3D),
            selector_state_var_reg=20,
            selector_state_constant=0x960C145D,
            resolver_kind="static_handler_entry_route",
        ),
    )

    assert unique_materialized_state_register(transfers) == 20


def test_unique_materialized_state_register_abstains_on_conflicting_resolvers():
    transfers = (
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40CA05,
            source_block_ea=0x40C9EC,
            materialized_anchor_eas=(0x40C9F2,),
            target_eas=(0x40CA22, 0x40CA60),
            selector_state_var_reg=20,
            selector_compare_constant=0xA7AFB008,
            resolver_kind="static_fixpoint",
        ),
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40CA50,
            source_block_ea=0x40CA3D,
            materialized_anchor_eas=(0x40CA47,),
            target_eas=(0x40C9EC, 0x40CBB0),
            selector_state_var_reg=28,
            selector_compare_constant=0x069225E4,
            resolver_kind="static_fixpoint",
        ),
    )

    assert unique_materialized_state_register(transfers) is None


def test_unique_materialized_state_register_prefers_state_routes_over_navigation_alias():
    transfers = (
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40CE90,
            source_block_ea=0x40CE90,
            materialized_anchor_eas=(0x40CE96,),
            target_eas=(0x40CEAB,),
            selector_state_var_reg=16,
            selector_state_constant=0x255387B6,
            resolver_kind="static_handler_entry_route",
        ),
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40CDBA,
            source_block_ea=0x40CDB7,
            materialized_anchor_eas=(0x40CDD0,),
            target_eas=(0x40CEAB,),
            selector_state_var_reg=16,
            selector_state_constant=0x255387B6,
            resolver_kind="residual_state_route_evidence",
        ),
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40CEC6,
            source_block_ea=0x40CEAB,
            materialized_anchor_eas=(0x40CEB0,),
            target_eas=(0x40CE10, 0x40CE78),
            selector_state_var_reg=28,
            selector_compare_constant=0x255387B6,
            resolver_kind="static_fixpoint",
        ),
    )

    assert unique_materialized_state_register(transfers) == 16


def test_unique_materialized_state_register_ignores_non_state_evidence():
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x40CA05,
        source_block_ea=0x40C9EC,
        materialized_anchor_eas=(0x40C9F2,),
        target_eas=(0x40CA22,),
        selector_state_var_reg=28,
        resolver_kind="detached_static_fixpoint",
    )

    assert unique_materialized_state_register((transfer,)) is None


def test_conditional_handler_entries_project_unique_state_targets():
    true_state = 0x5C46FC3C
    false_state = 0x3EEFBA76
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0xF1C000B8,
        source_block_ea=0x40CDA0,
        materialized_anchor_eas=(0xF1C000B8,),
        target_eas=(0x40CF38, 0x40CF01),
        true_target_ea=0x40CF38,
        false_target_ea=0x40CF01,
        predicate_true_state=true_state,
        predicate_false_state=false_state,
        resolver_kind="conditional_handler_bridge",
    )

    assert unique_materialized_conditional_handler_entry_eas(
        (transfer,),
        {true_state: 25, false_state: 23},
    ) == {23: 0x40CF01, 25: 0x40CF38}


def test_conditional_handler_entries_abstain_on_serial_identity_conflict():
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0xF1C000B8,
        source_block_ea=0x40CDA0,
        materialized_anchor_eas=(0xF1C000B8,),
        target_eas=(0x40CF38, 0x40CF01),
        true_target_ea=0x40CF38,
        false_target_ea=0x40CF01,
        predicate_true_state=0x5C46FC3C,
        predicate_false_state=0x3EEFBA76,
        resolver_kind="conditional_handler_bridge",
    )

    assert unique_materialized_conditional_handler_entry_eas(
        (transfer,),
        {0x5C46FC3C: 25, 0x3EEFBA76: 25},
    ) == {}


def test_missing_materialized_handler_targets_reports_unmapped_exact_states():
    assert missing_materialized_handler_targets(
        {
            0x11111111: 0x401000,
            0x22222222: 0x402000,
        },
        {
            0x11111111: 10,
        },
    ) == ((0x22222222, 0x402000),)


def test_missing_materialized_handler_targets_accepts_complete_exact_map():
    assert missing_materialized_handler_targets(
        {
            0x11111111: 0x401000,
            0x22222222: 0x402000,
        },
        {
            0x11111111: 10,
            0x22222222: 20,
        },
    ) == ()


def test_missing_materialized_handler_targets_accepts_proven_terminal_state():
    assert missing_materialized_handler_targets(
        {
            0x11111111: 0x401000,
            0x22222222: 0x402000,
        },
        {
            0x11111111: 10,
        },
        terminal_state_targets=((0x22222222, 0x402000),),
    ) == ()


def test_instruction_backed_handler_owners_reject_external_placeholders():
    live_state = 0x11111111
    placeholder_state = 0x22222222
    unrelated_state = 0x33333333
    graph = FlowGraph(
        blocks={
            10: _block(10, 0x401000, (0x401000,)),
            20: BlockSnapshot(
                serial=20,
                block_type=0,
                succs=(),
                preds=(10,),
                flags=0,
                start_ea=0x402000,
                insn_snapshots=(),
                kind=BlockKind.EXTERNAL,
            ),
            30: _block(30, 0x403000, (0x403000,)),
        },
        entry_serial=10,
        func_ea=0x400000,
    )

    assert instruction_backed_materialized_handler_owners(
        {
            live_state: 0x401000,
            placeholder_state: 0x402000,
        },
        {
            live_state: 10,
            placeholder_state: 20,
            unrelated_state: 30,
        },
        graph,
    ) == {live_state: 10}


def test_instruction_backed_handler_owner_precedes_imported_clone():
    state = 0xB8D2E088
    graph = FlowGraph(
        blocks={194: _block(194, 0x40E37B, (0x40E37B, 0x40E387))},
        entry_serial=194,
        func_ea=0x40D200,
    )

    assert select_materialized_handler_owner_serial(
        state_constant=state,
        instruction_backed_owners={state: 194},
        exact_target_serial=670,
        exact_target_ea=0x40E387,
        flow_graph=graph,
    ) == 194


def test_adjacent_router_arm_does_not_replace_explicit_handler_entry():
    state = 0x699BC698
    graph = FlowGraph(
        blocks={268: _block(268, 0x40EA9B, (0x40EA9B, 0x40EAA5))},
        entry_serial=268,
        func_ea=0x40D200,
    )

    assert select_materialized_handler_owner_serial(
        state_constant=state,
        instruction_backed_owners={state: 268},
        exact_target_serial=777,
        exact_target_ea=0x40EAA7,
        flow_graph=graph,
    ) == 777


def test_imported_handler_owner_fills_missing_live_state():
    graph = FlowGraph(blocks={}, entry_serial=0, func_ea=0x40D200)

    assert select_materialized_handler_owner_serial(
        state_constant=0xB8D2E088,
        instruction_backed_owners={},
        exact_target_serial=670,
        exact_target_ea=0x40E387,
        flow_graph=graph,
    ) == 670


@pytest.mark.parametrize(
    (
        "target_ea",
        "block_native_identity_ea",
        "imported_target_eas",
        "expected",
    ),
    (
        (0x40C4F6, 0x40C4F6, frozenset(), 204),
        (0x40C4F6, 0x40BC50, frozenset(), None),
        (0x40B0D6, 0x40B0D6, frozenset(), 204),
        (0x40BF1B, 0x40A560, frozenset({0x40BF1B}), 252),
    ),
    ids=(
        "native-exact-entry",
        "native-containing-router",
        "native-first-surviving-instruction",
        "imported-root",
    ),
)
def test_exact_handler_override_requires_native_entry_or_imported_root(
    target_ea: int,
    block_native_identity_ea: int,
    imported_target_eas: frozenset[int],
    expected: int | None,
) -> None:
    assert exact_materialized_handler_override_serial(
        target_ea=target_ea,
        target_serial=204 if expected != 252 else 252,
        target_native_identity_ea=block_native_identity_ea,
        imported_target_eas=imported_target_eas,
    ) == expected


def test_singleton_anchor_transfer_resolves_exact_live_target_block():
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x1010,
        source_block_ea=0x1000,
        materialized_anchor_eas=(0x1002,),
        target_eas=(0x2000,),
    )

    assert lookup_singleton_transfer_target(_graph(), transfer, source_block=1) == 2


def test_transfer_lookup_abstains_without_anchor_or_single_target():
    graph = _graph()
    no_anchor = MaterializedIndirectTransfer(
        source_jmp_ea=0x1010,
        source_block_ea=0x1000,
        materialized_anchor_eas=(0xDEAD,),
        target_eas=(0x2000,),
    )
    two_way = MaterializedIndirectTransfer(
        source_jmp_ea=0x1010,
        source_block_ea=0x1000,
        materialized_anchor_eas=(0x1002,),
        target_eas=(0x2000, 0x3000),
        condition_code=4,
        true_target_ea=0x2000,
        false_target_ea=0x3000,
    )

    assert lookup_singleton_transfer_target(graph, no_anchor, source_block=1) is None
    assert lookup_singleton_transfer_target(graph, two_way, source_block=1) is None


def test_equality_target_projection_uses_condition_chain_fallback() -> None:
    state = 0xB34CE2DF
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x40A7C7,
        source_block_ea=0x40A7AE,
        materialized_anchor_eas=(),
        target_eas=(0x40BCA3,),
        selector_state_var_reg=20,
        selector_state_constant=state,
        resolver_kind="condition_chain_handler_evidence",
    )

    assert unique_materialized_equality_target_eas((transfer,), 20) == {
        state: 0x40BCA3,
    }


def test_equality_target_projection_accepts_static_fixpoint_equality_arm() -> None:
    state = 0x64B9DC19
    equality = MaterializedIndirectTransfer(
        source_jmp_ea=0x40CCE4,
        source_block_ea=0x40CCCB,
        materialized_anchor_eas=(0x40CCD8, 0x40CCDE),
        target_eas=(0x40C9DB, 0x40CCE6),
        condition_code=4,
        true_target_ea=0x40CCE6,
        false_target_ea=0x40C9DB,
        selector_state_var_reg=20,
        selector_compare_constant=state,
        resolver_kind="static_fixpoint",
    )
    range_comparison = MaterializedIndirectTransfer(
        source_jmp_ea=0x40CC54,
        source_block_ea=0x40CC40,
        materialized_anchor_eas=(0x40CC48, 0x40CC4E),
        target_eas=(0x40CC56, 0x40CCB0),
        condition_code=13,
        true_target_ea=0x40CCB0,
        false_target_ea=0x40CC56,
        selector_state_var_reg=20,
        selector_compare_constant=state,
        resolver_kind="static_fixpoint",
    )

    assert unique_materialized_equality_target_eas(
        (equality, range_comparison),
        20,
    ) == {state: 0x40CCE6}


def test_equality_candidate_requires_registered_live_target() -> None:
    state = 0xAB7BA295
    target_ea = 0x40DD70
    candidate = MaterializedIndirectTransfer(
        source_jmp_ea=0x40DD6E,
        source_block_ea=0x40DD58,
        materialized_anchor_eas=(),
        target_eas=(target_ea,),
        selector_state_var_reg=28,
        selector_state_constant=state,
        resolver_kind="static_equality_candidate",
    )

    assert unique_materialized_equality_target_eas((candidate,), 28) == {}
    assert unique_materialized_equality_target_eas(
        (candidate,),
        28,
        validated_candidate_target_eas=frozenset({target_ea}),
    ) == {state: target_ea}


def test_static_handler_entry_route_outranks_condition_chain_leaf() -> None:
    state = 0x1EBFFA3C
    leaf = MaterializedIndirectTransfer(
        source_jmp_ea=0x40B149,
        source_block_ea=0x40B149,
        materialized_anchor_eas=(),
        target_eas=(0x40B157,),
        selector_state_var_reg=20,
        selector_state_constant=state,
        resolver_kind="condition_chain_handler_evidence",
    )
    handler_entry = MaterializedIndirectTransfer(
        source_jmp_ea=0x40B149,
        source_block_ea=0x40B149,
        materialized_anchor_eas=(),
        target_eas=(0x40B163,),
        selector_state_var_reg=20,
        selector_state_constant=state,
        resolver_kind="static_handler_entry_route",
    )

    assert unique_materialized_equality_target_eas(
        (leaf, handler_entry),
        20,
    ) == {state: 0x40B163}


def test_equality_target_projection_accepts_exact_residual_state_route() -> None:
    state = 0xF32B2D3A
    residual = MaterializedIndirectTransfer(
        source_jmp_ea=0x40B06B,
        source_block_ea=0x40B06B,
        materialized_anchor_eas=(0x40B06B,),
        target_eas=(0x40BF1B,),
        selector_state_var_reg=20,
        selector_state_constant=state,
        resolver_kind="residual_state_route",
    )

    assert unique_materialized_equality_target_eas((residual,), 20) == {
        state: 0x40BF1B,
    }


def test_equality_target_projection_rejects_resolver_landing_in_dispatcher() -> None:
    """A computed-goto landing can be another BST router, not a handler."""
    state = 0x699BC698
    router_ea = 0x40EAA7
    residual = MaterializedIndirectTransfer(
        source_jmp_ea=0x40D348,
        source_block_ea=0x40D313,
        materialized_anchor_eas=(0x40D348,),
        target_eas=(router_ea,),
        dispatcher_router_eas=(router_ea, 0x40D370),
        selector_state_var_reg=28,
        selector_state_constant=state,
        resolver_kind="residual_state_route",
    )

    assert unique_materialized_equality_target_eas((residual,), 28) == {}


def test_explicit_handler_entry_may_also_be_a_dispatcher_router() -> None:
    """A bootstrap handler can reload state and immediately dispatch again."""
    state = 0x699BC698
    bootstrap_ea = 0x40EAA7
    route = MaterializedIndirectTransfer(
        source_jmp_ea=0x40EA8D,
        source_block_ea=0x40EA8D,
        materialized_anchor_eas=(),
        target_eas=(bootstrap_ea,),
        dispatcher_router_eas=(bootstrap_ea, 0x40D370),
        selector_state_var_reg=28,
        selector_state_constant=state,
        resolver_kind="static_handler_entry_route",
    )

    assert unique_materialized_equality_target_eas((route,), 28) == {
        state: bootstrap_ea,
    }


def test_imported_router_microblocks_follow_resolver_proven_native_range() -> None:
    """Split PREOPT blocks inherit router identity from native instruction EAs."""
    router_ea = 0x40EAA7
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x40EABA,
        source_block_ea=router_ea,
        materialized_anchor_eas=(0x40EABA,),
        target_eas=(0x40EA9B, 0x40D370),
        dispatcher_router_eas=(router_ea, 0x40D370),
        selector_state_var_reg=28,
        selector_compare_constant=0x10B85E45,
        resolver_kind="static_fixpoint",
    )

    ranges = materialized_dispatcher_router_native_ranges((transfer,))

    assert ranges == ((0x40EAA7, 0x40EABB),)
    assert native_origin_blocks_in_ranges(
        {
            777: frozenset({0x40EAA7}),
            778: frozenset({0x40EAAB, 0x40EAB0}),
            779: frozenset({0x40EAB6, 0x40EABA}),
            780: frozenset({0x40EABB}),
        },
        ranges,
    ) == frozenset({777, 778, 779})


def test_router_native_ranges_ignore_unproven_source_blocks() -> None:
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x40D38F,
        source_block_ea=0x40D38B,
        materialized_anchor_eas=(0x40D38F,),
        target_eas=(0x40D391,),
        dispatcher_router_eas=(0x40EAA7,),
        resolver_kind="static_fixpoint",
    )

    assert materialized_dispatcher_router_native_ranges((transfer,)) == ()


def test_residual_state_route_bridge_requires_unique_live_one_way_endpoints() -> None:
    evidence = MaterializedIndirectTransfer(
        source_jmp_ea=0x40B360,
        source_block_ea=0x40B342,
        materialized_anchor_eas=(),
        target_eas=(0x40B8E6,),
        selector_state_var_reg=20,
        selector_state_constant=0xA5A94B86,
        resolver_kind="residual_state_route_evidence",
    )
    live_blocks = {0x40B360: 113, 0x40B8E6: 270}

    assert plan_residual_state_route_bridges(
        (evidence,),
        live_blocks_by_ea=live_blocks,
        one_way_source_blocks=frozenset({113}),
    ) == (
        ResidualStateRouteBridgePlan(
            source_block_serial=113,
            target_block_serial=270,
            source_write_ea=0x40B360,
            target_ea=0x40B8E6,
            state_constant=0xA5A94B86,
        ),
    )
    assert plan_residual_state_route_bridges(
        (evidence,),
        live_blocks_by_ea=live_blocks,
        one_way_source_blocks=frozenset(),
    ) == ()

    conflicting = MaterializedIndirectTransfer(
        source_jmp_ea=0x40B360,
        source_block_ea=0x40B342,
        materialized_anchor_eas=(),
        target_eas=(0x40C4B4,),
        selector_state_var_reg=20,
        selector_state_constant=0xF6A636EF,
        resolver_kind="residual_state_route_evidence",
    )
    assert plan_residual_state_route_bridges(
        (evidence, conflicting),
        live_blocks_by_ea={**live_blocks, 0x40C4B4: 300},
        one_way_source_blocks=frozenset({113}),
    ) == ()


def test_residual_state_route_bridge_activates_one_source_per_state_target() -> None:
    state = 0x10203040
    target_ea = 0x401500
    first = MaterializedIndirectTransfer(
        source_jmp_ea=0x401120,
        source_block_ea=0x401110,
        materialized_anchor_eas=(),
        target_eas=(target_ea,),
        selector_state_var_reg=20,
        selector_state_constant=state,
        resolver_kind="residual_state_route_evidence",
    )
    second = MaterializedIndirectTransfer(
        source_jmp_ea=0x401220,
        source_block_ea=0x401210,
        materialized_anchor_eas=(),
        target_eas=(target_ea,),
        selector_state_var_reg=20,
        selector_state_constant=state,
        resolver_kind="residual_state_route_evidence",
    )

    assert plan_residual_state_route_bridges(
        (second, first),
        live_blocks_by_ea={
            first.source_jmp_ea: 11,
            second.source_jmp_ea: 12,
            target_ea: 50,
        },
        one_way_source_blocks=frozenset({11, 12}),
    ) == (
        ResidualStateRouteBridgePlan(
            source_block_serial=11,
            target_block_serial=50,
            source_write_ea=first.source_jmp_ea,
            target_ea=target_ea,
            state_constant=state,
        ),
    )


def test_terminal_state_route_requests_early_maturity_return_carrier() -> None:
    state = 0x19A7218A
    graph = FlowGraph(
        blocks={
            273: _block(273, 0x40C7E5, (0x40C7E5,), succs=(303,)),
            303: BlockSnapshot(
                serial=303,
                block_type=6,
                succs=(),
                preds=(273,),
                flags=0,
                start_ea=0x40C898,
                insn_snapshots=(),
                kind=BlockKind.EXTERNAL,
            ),
        },
        entry_serial=273,
        func_ea=0x40A560,
    )

    assert plan_terminal_return_carrier_requests(
        graph,
        (
            MaterializedStateRoute(
                source_block_serial=273,
                state_constant=state,
                target_handler_serial=303,
                proof_kind="terminal_state_route",
            ),
        ),
        state_var_reg=20,
    ) == (
        TerminalReturnCarrierRequest(
            source_handler_ea=0x40C7E5,
            terminal_target_ea=0x40C898,
            state_var_reg=20,
            state_constant=state,
        ),
    )


def test_terminal_route_uses_native_identities_when_live_blocks_are_synthetic() -> None:
    state = 0x69225E4
    graph = FlowGraph(
        blocks={
            41: _block(41, 0x40C8B0, succs=(74,)),
            74: BlockSnapshot(
                serial=74,
                block_type=7,
                succs=(),
                preds=(41,),
                flags=0,
                start_ea=0xFFFFFFFFFFFFFFFF,
                insn_snapshots=(),
                kind=BlockKind.STOP,
            ),
        },
        entry_serial=41,
        func_ea=0x40C8B0,
    )

    assert plan_terminal_return_carrier_requests(
        graph,
        (
            MaterializedStateRoute(
                source_block_serial=41,
                state_constant=state,
                target_handler_serial=74,
                proof_kind="terminal_state_route",
                source_native_ea=0x40CC1C,
                target_native_ea=0x40CD8C,
            ),
        ),
        state_var_reg=20,
    ) == (
        TerminalReturnCarrierRequest(
            source_handler_ea=0x40CC1C,
            terminal_target_ea=0x40CD8C,
            state_var_reg=20,
            state_constant=state,
        ),
    )


def test_native_exit_and_applied_port_request_return_carrier() -> None:
    state = 0x69225E4
    handler_ea = 0x40CC1C
    terminal_ea = 0x40CD8C
    transfers = (
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40CC34,
            source_block_ea=handler_ea,
            materialized_anchor_eas=(),
            target_eas=(terminal_ea,),
            selector_state_var_reg=20,
            selector_state_constant=state,
            resolver_kind="static_handler_exit_route",
        ),
    )
    direct_ports = (
        SimpleNamespace(
            source_block_ea=handler_ea,
            endpoint_block_ea=handler_ea,
            target_ea=terminal_ea,
            old_successor_eas=(),
            delivery_mode="terminal_goto",
        ),
    )

    assert plan_terminal_return_carrier_requests_from_native_routes(
        transfers,
        direct_ports,
        state_var_reg=20,
    ) == (
        TerminalReturnCarrierRequest(
            source_handler_ea=handler_ea,
            terminal_target_ea=terminal_ea,
            state_var_reg=20,
            state_constant=state,
        ),
    )


def test_terminal_target_identity_requests_validated_source_carrier() -> None:
    state = 0x19A7218A
    terminal_ea = 0x40C898
    transfers = (
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40A5CA,
            source_block_ea=0x40A5CA,
            materialized_anchor_eas=(),
            target_eas=(terminal_ea,),
            selector_state_var_reg=20,
            selector_state_constant=state,
            resolver_kind="static_handler_entry_route",
        ),
    )
    direct_ports = (
        SimpleNamespace(
            source_block_ea=0x40C7E5,
            endpoint_block_ea=0x40C7E5,
            target_ea=terminal_ea,
            old_successor_eas=(),
            delivery_mode="terminal_goto",
        ),
    )

    assert plan_terminal_return_carrier_requests_from_native_routes(
        transfers,
        direct_ports,
        state_var_reg=20,
    ) == (
        TerminalReturnCarrierRequest(
            source_handler_ea=0x40C7E5,
            terminal_target_ea=terminal_ea,
            state_var_reg=20,
            state_constant=state,
        ),
    )


def test_preopt_state_writes_request_only_unique_terminal_identity() -> None:
    state = 0x19A7218A
    terminal_ea = 0x40C898
    transfers = (
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40A5CA,
            source_block_ea=0x40A5CA,
            materialized_anchor_eas=(),
            target_eas=(terminal_ea,),
            selector_state_var_reg=20,
            selector_state_constant=state,
            resolver_kind="static_handler_entry_route",
        ),
    )

    assert plan_terminal_return_carrier_requests_from_state_writes(
        transfers,
        {state: (0x40A5D0, 0x40C7E5)},
        (terminal_ea,),
        state_var_reg=20,
    ) == (
        TerminalReturnCarrierRequest(0x40A5D0, terminal_ea, 20, state),
        TerminalReturnCarrierRequest(0x40C7E5, terminal_ea, 20, state),
    )


def test_return_carrier_request_abstains_for_nonterminal_or_ambiguous_route() -> None:
    state = 0x19A7218A
    graph = FlowGraph(
        blocks={
            273: _block(273, 0x40C7E5, (0x40C7E5,), succs=(303, 304)),
            303: _block(303, 0x40C898),
            304: _block(304, 0x40C8A0),
        },
        entry_serial=273,
        func_ea=0x40A560,
    )
    ordinary = MaterializedStateRoute(273, state, 303)
    conflicting = (
        MaterializedStateRoute(
            273,
            state,
            303,
            proof_kind="terminal_state_route",
        ),
        MaterializedStateRoute(
            273,
            state,
            304,
            proof_kind="terminal_state_route",
        ),
    )

    assert plan_terminal_return_carrier_requests(
        graph,
        (ordinary,),
        state_var_reg=20,
    ) == ()
    assert plan_terminal_return_carrier_requests(
        graph,
        conflicting,
        state_var_reg=20,
    ) == ()


def test_resolver_proven_native_jump_neutralizes_exact_mislifted_call() -> None:
    transfer_ea = 0x40AE89
    call_expression = MopSnapshot(
        t=4,
        size=4,
        kind=OperandKind.SUBINSN,
        sub_kind=InsnKind.CALL,
    )
    graph = FlowGraph(
        blocks={
            83: BlockSnapshot(
                serial=83,
                block_type=0,
                succs=(318,),
                preds=(82,),
                flags=0,
                start_ea=0x40AE3E,
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=4,
                        ea=transfer_ea,
                        operands=(),
                        l=call_expression,
                        kind=InsnKind.MOV,
                    ),
                    InsnSnapshot(
                        opcode=55,
                        ea=transfer_ea,
                        operands=(),
                        kind=InsnKind.GOTO,
                        is_unconditional_jump=True,
                    ),
                ),
            ),
            43: _block(43, 0x40AA20),
            318: _block(318, 0x40A607),
        },
        entry_serial=83,
        func_ea=0x40A560,
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=transfer_ea,
        source_block_ea=0x40AE3E,
        materialized_anchor_eas=(),
        target_eas=(0x40A607, 0x40B6C0),
        resolver_kind="detached_static_fixpoint",
    )

    assert plan_resolver_proven_indirect_call_neutralizations(
        (transfer,),
        graph,
        redirected_targets_by_source={83: (43,)},
        allowed_target_serials=frozenset({43}),
    ) == (
        ResidualIndirectCallNeutralizationPlan(
            source_block_serial=83,
            source_jmp_ea=transfer_ea,
            redirected_target_serial=43,
        ),
    )


@pytest.mark.parametrize(
    ("resolver_kind", "redirects", "allowed_targets"),
    (
        ("condition_chain_handler_evidence", {83: (43,)}, frozenset({43})),
        ("detached_static_fixpoint", {}, frozenset({43})),
        ("detached_static_fixpoint", {83: (43, 44)}, frozenset({43, 44})),
        ("detached_static_fixpoint", {83: (43,)}, frozenset()),
    ),
    ids=("not-native-jump-proof", "no-redirect", "ambiguous-redirect", "not-handler"),
)
def test_resolver_proven_indirect_call_neutralization_abstains_without_full_proof(
    resolver_kind: str,
    redirects: dict[int, tuple[int, ...]],
    allowed_targets: frozenset[int],
) -> None:
    transfer_ea = 0x40AE89
    graph = FlowGraph(
        blocks={
            83: BlockSnapshot(
                serial=83,
                block_type=0,
                succs=(318,),
                preds=(82,),
                flags=0,
                start_ea=0x40AE3E,
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=57,
                        ea=transfer_ea,
                        operands=(),
                        kind=InsnKind.CALL,
                        is_call=True,
                    ),
                ),
            ),
            43: _block(43, 0x40AA20),
            44: _block(44, 0x40AB00),
            318: _block(318, 0x40A607),
        },
        entry_serial=83,
        func_ea=0x40A560,
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=transfer_ea,
        source_block_ea=0x40AE3E,
        materialized_anchor_eas=(),
        target_eas=(0x40A607, 0x40B6C0),
        resolver_kind=resolver_kind,
    )

    assert plan_resolver_proven_indirect_call_neutralizations(
        (transfer,),
        graph,
        redirected_targets_by_source=redirects,
        allowed_target_serials=allowed_targets,
    ) == ()


def test_equality_target_projection_abstains_on_conflicting_primary_routes() -> None:
    state = 0x82F1899D
    transfers = (
        MaterializedIndirectTransfer(
            source_jmp_ea=0x401000,
            source_block_ea=0x401000,
            materialized_anchor_eas=(),
            target_eas=(0x402000,),
            selector_state_var_reg=20,
            selector_state_constant=state,
            resolver_kind="static_equality_route",
        ),
        MaterializedIndirectTransfer(
            source_jmp_ea=0x401010,
            source_block_ea=0x401010,
            materialized_anchor_eas=(),
            target_eas=(0x403000,),
            selector_state_var_reg=20,
            selector_state_constant=state,
            resolver_kind="static_equality_route",
        ),
        MaterializedIndirectTransfer(
            source_jmp_ea=0x401020,
            source_block_ea=0x401020,
            materialized_anchor_eas=(),
            target_eas=(0x404000,),
            selector_state_var_reg=20,
            selector_state_constant=state,
            resolver_kind="condition_chain_handler_evidence",
        ),
    )

    assert unique_materialized_equality_target_eas(transfers, 20) == {}


def test_validated_import_target_resolves_conflicting_handler_entry_routes() -> None:
    state = 0x2F0F683D
    source_ea = 0x40CC6E
    dispatcher_target = 0x40CBB0
    imported_handler_target = 0x40CC89
    transfers = tuple(
        MaterializedIndirectTransfer(
            source_jmp_ea=source_ea,
            source_block_ea=source_ea,
            materialized_anchor_eas=(),
            target_eas=(target_ea,),
            selector_state_var_reg=20,
            selector_state_constant=state,
            resolver_kind="static_handler_entry_route",
        )
        for target_ea in (dispatcher_target, imported_handler_target)
    )

    assert unique_materialized_equality_target_eas(transfers, 20) == {}
    assert unique_materialized_equality_target_eas(
        transfers,
        20,
        validated_candidate_target_eas=frozenset({imported_handler_target}),
    ) == {state: imported_handler_target}


def test_terminal_multi_target_uses_exact_state_snapshot_handler_ea() -> None:
    state = 0x7F9D6412
    equality = MaterializedIndirectTransfer(
        source_jmp_ea=0x40B3F1,
        source_block_ea=0x40B3E5,
        materialized_anchor_eas=(),
        target_eas=(0x40B3F3,),
        selector_state_constant=state,
        selector_state_var_reg=20,
        resolver_kind="condition_chain_handler_evidence",
    )
    terminal = MaterializedIndirectTransfer(
        source_jmp_ea=0x40C1F0,
        source_block_ea=0x40C1A0,
        materialized_anchor_eas=(),
        target_eas=(0x40A607, 0x40B6C0),
        source_register_values=((20, state),),
        resolver_kind="detached_static_fixpoint",
    )

    assert materialized_terminal_target_eas_by_source(
        (equality, terminal),
        20,
    ) == {0x40C1F0: (0x40B3F3,)}


def test_target_mapper_abstains_when_exact_ea_is_not_unique():
    graph = FlowGraph(
        blocks={
            1: _block(1, 0x1000, (0x2000,)),
            2: _block(2, 0x2000, ()),
        },
        entry_serial=1,
        func_ea=0x1000,
    )

    assert find_unique_target_block(graph, 0x2000) is None
    assert find_unique_target_entry_block(graph, 0x2000) == 2


def test_state_keyed_route_maps_folded_native_entry_with_bounded_next_label():
    graph = FlowGraph(
        blocks={
            1: _block(1, 0x1000, (0x1002,)),
            2: _block(2, 0x1FF0, (0x2004, 0x2008)),
            3: _block(3, 0x2010, (0x2010,)),
        },
        entry_serial=1,
        func_ea=0x1000,
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x1010,
        source_block_ea=0x1000,
        materialized_anchor_eas=(),
        target_eas=(0x2000,),
        next_target_ea=0x2010,
        selector_state_constant=0x304E8694,
        resolver_kind="static_equality_route",
    )

    assert lookup_state_keyed_transfer_target(graph, transfer, 0x304E8694) == 2


def test_target_mapper_excludes_known_shadow_block_from_bounded_owner():
    graph = FlowGraph(
        blocks={
            1: _block(1, 0x1000, (0x1002,)),
            2: _block(2, 0x1FF0, (0x2004, 0x2008)),
            3: _block(3, 0x1000, (0x2004, 0x2008)),
        },
        entry_serial=1,
        func_ea=0x1000,
    )

    assert find_unique_target_entry_block(graph, 0x2000, 0x2005) is None
    assert find_unique_target_entry_block(
        graph,
        0x2000,
        0x2005,
        excluded_serials=frozenset({3}),
    ) == 2


def test_state_keyed_equality_transfer_selects_matching_arm():
    graph = _graph()
    jz = MaterializedIndirectTransfer(
        source_jmp_ea=0x1010,
        source_block_ea=0x1000,
        materialized_anchor_eas=(0xDEAD,),
        target_eas=(0x2000, 0x3000),
        condition_code=4,
        true_target_ea=0x2000,
        false_target_ea=0x3000,
        selector_state_constant=0xEC71CA67,
        resolver_kind="residual_microcode",
    )
    jnz = MaterializedIndirectTransfer(
        source_jmp_ea=0x1020,
        source_block_ea=0x1000,
        materialized_anchor_eas=(0xBEEF,),
        target_eas=(0x2000, 0x3000),
        condition_code=5,
        true_target_ea=0x2000,
        false_target_ea=0x3000,
        selector_state_constant=0xEC71CA67,
        resolver_kind="residual_microcode",
    )

    assert lookup_state_keyed_transfer_target(graph, jz, 0xEC71CA67) == 2
    assert lookup_state_keyed_transfer_target(graph, jnz, 0xEC71CA67) == 3


def test_state_keyed_completed_route_selects_single_microcode_handler():
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x40B8E4,
        source_block_ea=0x40B8CE,
        materialized_anchor_eas=(),
        target_eas=(0x2000,),
        selector_state_constant=0xA5A94B86,
        resolver_kind="static_equality_route",
    )

    assert (
        lookup_state_keyed_transfer_target(_graph(), transfer, 0xA5A94B86)
        == 2
    )
    assert lookup_state_keyed_transfer_target(_graph(), transfer, 0xAE5A330B) is None


def test_exact_equality_route_does_not_override_live_coarse_router_target():
    state = 0xA5A94B86
    transition = StateWriteTransition(1, state, 3, False, None)
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x40B8E4,
        source_block_ea=0x40B8CC,
        materialized_anchor_eas=(),
        target_eas=(0x2000,),
        selector_state_constant=state,
        resolver_kind="static_equality_route",
    )

    (resolved,) = resolve_materialized_indirect_transfer_targets(
        (transition,),
        _graph(),
        IntervalDispatcher([IntervalRow(0, 1 << 32, 3)]),
        (transfer,),
        condition_chain_handlers=frozenset({3}),
        state_var_reg=20,
    )

    assert resolved == transition


def test_exact_equality_route_recovers_terminal_router_miss():
    state = 0xA5A94B86
    transition = StateWriteTransition(1, state, None, True, None)
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x40B8E4,
        source_block_ea=0x40B8CC,
        materialized_anchor_eas=(),
        target_eas=(0x2000,),
        selector_state_constant=state,
        resolver_kind="static_equality_route",
    )

    (resolved,) = resolve_materialized_indirect_transfer_targets(
        (transition,),
        _graph(),
        IntervalDispatcher([IntervalRow(0, 1 << 32, 3)]),
        (transfer,),
        condition_chain_handlers=frozenset({3}),
        state_var_reg=20,
    )

    assert resolved.target_handler == 2
    assert resolved.is_return is False
    assert resolved.proof is not None
    assert resolved.proof.kind == "computed_goto_exact_equality_route"


def test_source_keyed_state_route_outranks_global_exact_equality_route():
    state = 0xCCEC5DE0
    transition = StateWriteTransition(1, state, None, True, None)
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x40C168,
        source_block_ea=0x40C150,
        materialized_anchor_eas=(),
        target_eas=(0x2000,),
        selector_state_constant=state,
        resolver_kind="static_equality_route",
    )

    (resolved,) = resolve_materialized_indirect_transfer_targets(
        (transition,),
        _graph(),
        IntervalDispatcher([IntervalRow(0, 1 << 32, 3)]),
        (transfer,),
        materialized_state_routes=(MaterializedStateRoute(1, state, 3),),
        condition_chain_handlers=frozenset({3}),
        state_var_reg=20,
    )

    assert resolved.target_handler == 3
    assert resolved.is_return is False
    assert resolved.proof is not None
    assert resolved.proof.kind == "computed_goto_state_route"


def test_snapshot_state_route_overrides_weaker_handler_arm_target():
    state = 0xA5540595
    handler = HandlerTransition(
        handler=1,
        states=(0x10,),
        arms=(TransitionArm(state, 3, False, 1, 1, 1, (1,)),),
    )

    (resolved,) = resolve_materialized_handler_transition_targets(
        (handler,),
        (MaterializedStateRoute(1, state, 2),),
        frozenset({2, 3}),
        dispatcher_block_serials=frozenset({3}),
    )

    assert resolved.arms[0].target_handler == 2
    assert resolved.arms[0].is_return is False
    assert resolved.arms[0].source_keyed_block == 1


def test_snapshot_state_route_preserves_non_router_target_and_source_keys_owner():
    state = 0xF6A636EF
    handler = HandlerTransition(
        handler=1,
        states=(0x10,),
        arms=(TransitionArm(state, 3, False, 1, 1, 1, (1,)),),
    )

    (resolved,) = resolve_materialized_handler_transition_targets(
        (handler,),
        (
            MaterializedStateRoute(
                1,
                state,
                2,
                source_handler_serial=1,
                handler_exit_proven=True,
            ),
        ),
        frozenset({2, 3}),
        dispatcher_block_serials=frozenset(),
    )

    assert resolved.arms[0].target_handler == 3
    assert resolved.arms[0].is_return is False
    assert resolved.arms[0].source_keyed_block == 1


def test_corroborated_exact_exit_route_overrides_non_router_target():
    state = 0xF6A636EF
    handler = HandlerTransition(
        handler=1,
        states=(0x10,),
        arms=(TransitionArm(state, 3, False, 1, 1, 1, (1,)),),
    )

    (resolved,) = resolve_materialized_handler_transition_targets(
        (handler,),
        (
            MaterializedStateRoute(
                1,
                state,
                2,
                source_handler_serial=1,
                handler_exit_proven=True,
            ),
            MaterializedStateRoute(1, state, 2),
        ),
        frozenset({2, 3}),
        dispatcher_block_serials=frozenset(),
    )

    assert resolved.arms[0].target_handler == 2
    assert resolved.arms[0].is_return is False
    assert resolved.arms[0].source_keyed_block == 1


def test_replayed_handler_route_does_not_override_recovered_arm():
    state = 0xA5540595
    handler = HandlerTransition(
        handler=1,
        states=(0x10,),
        arms=(TransitionArm(state, 3, False, 1, 1, 1, (1,)),),
    )

    assert resolve_materialized_handler_transition_targets(
        (handler,),
        (
            MaterializedStateRoute(
                1,
                state,
                2,
                source_handler_serial=1,
            ),
        ),
        frozenset({2, 3}),
    ) == (handler,)


def test_fallback_state_route_does_not_override_recovered_non_router_arm():
    state = 0xA5540595
    handler = HandlerTransition(
        handler=1,
        states=(0x10,),
        arms=(TransitionArm(state, 3, False, 1, 1, 1, (1,)),),
    )

    assert resolve_materialized_handler_transition_targets(
        (handler,),
        (MaterializedStateRoute(1, state, 2),),
        frozenset({2, 3}),
    ) == (handler,)


def test_agreeing_snapshot_route_does_not_source_key_recovered_arm():
    state = 0xE9795EF
    handler = HandlerTransition(
        handler=187,
        states=(0xFED7FAC0,),
        arms=(TransitionArm(state, 187, False, None, 9, 9, (187, 9)),),
    )

    assert resolve_materialized_handler_transition_targets(
        (handler,),
        (MaterializedStateRoute(187, state, 187),),
        frozenset({187}),
    ) == (handler,)


def test_replayed_exact_exit_source_keys_agreeing_recovered_arm():
    state = 0x7C4FB03D
    handler = HandlerTransition(
        handler=143,
        states=(0xCB1F8618,),
        arms=(TransitionArm(state, 77, False, None, 26, 26, (143, 26)),),
    )

    (resolved,) = resolve_materialized_handler_transition_targets(
        (handler,),
        (
            MaterializedStateRoute(
                26,
                state,
                77,
                source_handler_serial=143,
                handler_exit_proven=True,
            ),
        ),
        frozenset({77, 143}),
    )

    assert resolved.arms[0].target_handler == 77
    assert resolved.arms[0].source_keyed_block == 26


def test_replayed_proven_exit_can_source_key_handler_block_itself():
    state = 0x7C4FB03D
    handler = HandlerTransition(
        handler=143,
        states=(0xCB1F8618,),
        arms=(TransitionArm(state, 77, False, None, 143, 143, (143,)),),
    )

    (resolved,) = resolve_materialized_handler_transition_targets(
        (handler,),
        (
            MaterializedStateRoute(
                143,
                state,
                77,
                source_handler_serial=143,
                handler_exit_proven=True,
            ),
        ),
        frozenset({77, 143}),
    )

    assert resolved.arms[0].source_keyed_block == 143


def test_snapshot_state_route_abstains_when_two_arms_share_source_and_state():
    state = 0xA5540595
    transitions = (
        HandlerTransition(
            handler=1,
            states=(0x10,),
            arms=(TransitionArm(state, 3, False, 1, 10, 10, (1, 10)),),
        ),
        HandlerTransition(
            handler=2,
            states=(0x20,),
            arms=(TransitionArm(state, 3, False, 2, 10, 10, (2, 10)),),
        ),
    )

    assert resolve_materialized_handler_transition_targets(
        transitions,
        (MaterializedStateRoute(10, state, 4),),
        frozenset({3, 4}),
    ) == transitions


def test_snapshot_state_route_abstains_on_conflicting_targets():
    state = 0xA5540595
    transition = HandlerTransition(
        handler=1,
        states=(0x10,),
        arms=(TransitionArm(state, 3, False, 1, 10, 10, (1, 10)),),
    )

    assert resolve_materialized_handler_transition_targets(
        (transition,),
        (
            MaterializedStateRoute(10, state, 2),
            MaterializedStateRoute(10, state, 3),
        ),
        frozenset({2, 3}),
    ) == (transition,)


def test_replayed_handler_route_recovers_microcode_dropped_register_write():
    state = 0xBCDE2EFB
    transition = HandlerTransition(
        handler=1,
        states=(0xA5540595,),
        arms=(TransitionArm(None, None, True, None, 9, 9, (1, 9)),),
    )

    (resolved,) = resolve_materialized_handler_exit_states(
        (transition,),
        (MaterializedStateRoute(1, state, 2),),
        frozenset({2}),
    )

    assert resolved.arms[0].next_state == state
    assert resolved.arms[0].target_handler == 2
    assert resolved.arms[0].is_return is False
    assert resolved.arms[0].source_keyed_block == 1


def test_replayed_handler_route_abstains_when_two_arms_own_same_source():
    state = 0xBCDE2EFB
    transitions = tuple(
        HandlerTransition(
            handler=handler,
            states=(handler,),
            arms=(TransitionArm(None, None, True, None, 1, 1, (handler, 1)),),
        )
        for handler in (2, 3)
    )

    assert resolve_materialized_handler_exit_states(
        transitions,
        (MaterializedStateRoute(1, state, 2),),
        frozenset({2}),
    ) == transitions


def test_replayed_default_route_abstains_for_non_handler_target():
    """A replayed range/default state has no equality-map authority by itself."""
    state = 0xBCDE2EFB
    transition = HandlerTransition(
        handler=1,
        states=(0xA5540595,),
        arms=(TransitionArm(None, None, True, None, 9, 9, (1, 9)),),
    )

    assert resolve_materialized_handler_exit_states(
        (transition,),
        (
            MaterializedStateRoute(
                9,
                state,
                99,
                source_handler_serial=1,
                handler_exit_proven=True,
            ),
        ),
        frozenset({2}),
    ) == (transition,)


def test_replayed_handler_route_prefers_its_owning_handler_over_shared_path():
    state = 0xBCDE2EFB
    transitions = (
        HandlerTransition(
            handler=212,
            states=(0x11111111,),
            arms=(
                TransitionArm(
                    0x11111111,
                    212,
                    False,
                    None,
                    9,
                    9,
                    (212, 213, 9),
                ),
            ),
        ),
        HandlerTransition(
            handler=213,
            states=(0xA5540595,),
            arms=(TransitionArm(None, None, True, None, 9, 9, (213, 9)),),
        ),
    )

    resolved = resolve_materialized_handler_exit_states(
        transitions,
        (
            MaterializedStateRoute(213, 0x5E07BA29, 89),
            MaterializedStateRoute(
                213,
                state,
                178,
                source_handler_serial=213,
            ),
        ),
        frozenset({89, 178, 212, 213}),
    )

    assert resolved[0] == transitions[0]
    assert resolved[1].arms[0].next_state == state
    assert resolved[1].arms[0].target_handler == 178
    assert resolved[1].arms[0].source_keyed_block == 213


def test_materialized_handler_maps_include_condition_chain_only_handler():
    handler_states, handler_targets, handler_serials = (
        merge_materialized_handler_maps(
            {0x11111111: 10},
            {20: 0x22222222},
            {0xA5540595: 213},
        )
    )

    assert handler_states == {
        10: (0x11111111,),
        20: (0x22222222,),
        213: (0xA5540595,),
    }
    assert handler_targets == {
        0x11111111: 10,
        0x22222222: 20,
        0xA5540595: 213,
    }
    assert handler_serials == frozenset({10, 20, 213})


def test_materialized_handler_maps_abstain_on_conflicting_state_owner():
    handler_states, handler_targets, handler_serials = (
        merge_materialized_handler_maps(
            {0xA5540595: 10},
            {213: 0xA5540595},
        )
    )

    assert handler_states == {}
    assert handler_targets == {}
    assert handler_serials == frozenset({10, 213})


def test_imported_root_overrides_original_materialized_handler_target():
    state = 0xA5A94B86

    handler_states, handler_targets, handler_serials = (
        override_materialized_handler_targets(
            {
                state: 165,
                0x11111111: 10,
            },
            frozenset({10, 165}),
            {state: 309},
        )
    )

    assert handler_states == {
        10: (0x11111111,),
        309: (state,),
    }
    assert handler_targets == {
        0x11111111: 10,
        state: 309,
    }
    assert handler_serials == frozenset({10, 165, 309})


def test_exact_imported_root_adds_state_missing_from_dispatcher_map():
    state = 0x2100AFDD

    handler_states, handler_targets, handler_serials = (
        override_materialized_handler_targets(
            {0x11111111: 10},
            frozenset({10}),
            {state: 281},
        )
    )

    assert handler_states == {
        10: (0x11111111,),
        281: (state,),
    }
    assert handler_targets == {
        0x11111111: 10,
        state: 281,
    }
    assert handler_serials == frozenset({10, 281})


def test_exact_dispatcher_point_remains_authoritative_over_resolver_route():
    state = 0xA5A94B86
    transition = StateWriteTransition(1, state, 3, False, None)
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x40B8E4,
        source_block_ea=0x40B8CC,
        materialized_anchor_eas=(),
        target_eas=(0x2000,),
        selector_state_constant=state,
        resolver_kind="static_equality_route",
    )

    (resolved,) = resolve_materialized_indirect_transfer_targets(
        (transition,),
        _graph(),
        IntervalDispatcher([IntervalRow(state, state + 1, 3)]),
        (transfer,),
        condition_chain_handlers=frozenset({3}),
        state_var_reg=20,
    )

    assert resolved == transition


def test_state_keyed_transfer_abstains_without_exact_equality_proof():
    graph = _graph()
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x1010,
        source_block_ea=0x1000,
        materialized_anchor_eas=(0x1002,),
        target_eas=(0x2000, 0x3000),
        condition_code=12,
        true_target_ea=0x2000,
        false_target_ea=0x3000,
        selector_state_constant=0xEC71CA67,
        resolver_kind="residual_microcode",
    )

    assert lookup_state_keyed_transfer_target(graph, transfer, 0xEC71CA67) is None
    assert lookup_state_keyed_transfer_target(graph, transfer, 0xA0716E5B) is None


def test_state_keyed_signed_range_transfer_selects_proven_arm():
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x1010,
        source_block_ea=0x1000,
        materialized_anchor_eas=(0x1002,),
        target_eas=(0x2000, 0x3000),
        condition_code=12,
        true_target_ea=0x2000,
        false_target_ea=0x3000,
        selector_state_var_reg=20,
        selector_compare_constant=0xBB2D365,
        selector_state_on_left=True,
    )

    assert lookup_state_keyed_transfer_target(
        _graph(), transfer, 0xA0000000, state_var_reg=20
    ) == 2
    assert lookup_state_keyed_transfer_target(
        _graph(), transfer, 0xF6A636EF, state_var_reg=20
    ) == 2
    assert lookup_state_keyed_transfer_target(
        _graph(), transfer, 0x70000000, state_var_reg=20
    ) == 3
    assert lookup_state_keyed_transfer_target(
        _graph(), transfer, 0xA0000000, state_var_reg=8
    ) is None


def test_materialized_transfer_chain_walks_detached_bst_to_known_handler():
    graph = FlowGraph(
        blocks={
            1: _block(1, 0x1000, (0x1002,)),
            2: _block(2, 0x2000, (0x2002,)),
            3: _block(3, 0x3000),
            4: _block(4, 0x4000),
            99: _block(99, 0x9900),
        },
        entry_serial=1,
        func_ea=0x1000,
    )
    transfers = (
        MaterializedIndirectTransfer(
            source_jmp_ea=0x1010,
            source_block_ea=0x1000,
            materialized_anchor_eas=(0x1002,),
            target_eas=(0x2000, 0x9900),
            condition_code=13,
            true_target_ea=0x2000,
            false_target_ea=0x9900,
            selector_state_var_reg=20,
            selector_compare_constant=0x80000000,
            selector_state_on_left=True,
        ),
        MaterializedIndirectTransfer(
            source_jmp_ea=0x2010,
            source_block_ea=0x2000,
            materialized_anchor_eas=(0xDEAD,),
            target_eas=(0x3000, 0x4000),
            condition_code=4,
            true_target_ea=0x3000,
            false_target_ea=0x4000,
            selector_state_var_reg=20,
            selector_compare_constant=0xA0000000,
            selector_state_on_left=True,
        ),
    )

    assert route_materialized_transfer_chain(
        graph,
        transfers,
        start_block=1,
        state_constant=0xA0000000,
        state_var_reg=20,
        handler_serials=frozenset({3, 4}),
    ) == 3


def test_materialized_transfer_chain_does_not_erase_state_key_mismatch():
    graph = FlowGraph(
        blocks={
            1: _block(1, 0x1000, (0x1002,)),
            2: _block(2, 0x2000),
        },
        entry_serial=1,
        func_ea=0x1000,
    )
    keyed_singleton = MaterializedIndirectTransfer(
        source_jmp_ea=0x1010,
        source_block_ea=0x1000,
        materialized_anchor_eas=(0x1002,),
        target_eas=(0x2000,),
        selector_state_constant=0xE0606B6D,
        resolver_kind="static_equality_route",
    )

    assert route_materialized_transfer_chain(
        graph,
        (keyed_singleton,),
        start_block=1,
        state_constant=0xE0606B6D,
        state_var_reg=20,
        handler_serials=frozenset({2}),
    ) == 2
    assert route_materialized_transfer_chain(
        graph,
        (keyed_singleton,),
        start_block=1,
        state_constant=0xDC71BBC5,
        state_var_reg=20,
        handler_serials=frozenset({2}),
    ) is None


def _condition_chain_graph() -> FlowGraph:
    return FlowGraph(
        blocks={
            1: _block(1, 0x1000, (0x1002,)),
            2: _block(2, 0x2000, succs=(3,)),
            3: _block(3, 0x3000),
            4: _block(4, 0x4000, succs=(5,)),
            5: _block(5, 0x5000),
        },
        entry_serial=1,
        func_ea=0x1000,
    )


def _source_anchored_transfer() -> MaterializedIndirectTransfer:
    return MaterializedIndirectTransfer(
        source_jmp_ea=0x1010,
        source_block_ea=0x1000,
        materialized_anchor_eas=(0x1002,),
        target_eas=(0x2000,),
    )


def _condition_chain_dag() -> DecisionDag:
    return DecisionDag(
        32,
        {
            2: RouteComparison(2, "jz", 0xDEAD, 3, 99),
            4: RouteComparison(4, "jz", 0xDEAD, 5, 99),
        },
        root=2,
    )


def test_condition_chain_router_ownership_wins_over_range_handler_alias() -> None:
    graph = FlowGraph(
        blocks={
            1: _block(1, 0x1000, succs=(2,)),
            2: _block(2, 0x2000, succs=(3, 4)),
            3: _block(3, 0x3000),
            4: _block(4, 0x4000),
        },
        entry_serial=1,
        func_ea=0x1000,
    )
    dag = DecisionDag(
        32,
        {2: RouteComparison(2, "jz", 0xDEAD, 3, 4)},
        root=2,
    )

    assert route_transfer_target_through_condition_chain(
        graph,
        dag,
        target_block=1,
        state_constant=0xDEAD,
        # Interval backfill can alias a router as a provisional handler.
        handler_serials=frozenset({2, 3, 4}),
    ) == 3


@pytest.mark.parametrize(
    ("rows", "routed_target"),
    [
        ((), None),
        ((IntervalRow(0xDEAD, 0xDEAE, 2),), 2),
    ],
    ids=("router-miss", "router-spine"),
)
def test_source_anchored_transfer_walks_from_any_router_root_to_handler(
    rows: tuple[IntervalRow, ...],
    routed_target: int | None,
) -> None:
    transition = StateWriteTransition(1, 0xDEAD, routed_target, True, None)

    (resolved,) = resolve_materialized_indirect_transfer_targets(
        (transition,),
        _condition_chain_graph(),
        IntervalDispatcher(list(rows), default_target=99),
        (_source_anchored_transfer(),),
        condition_chain_dag=_condition_chain_dag(),
        condition_chain_handlers=frozenset({3, 5}),
    )

    assert resolved.target_handler == 3
    assert resolved.is_return is False


@pytest.mark.parametrize("ambiguous", (False, True), ids=("missing", "ambiguous"))
def test_missing_or_ambiguous_condition_chain_evidence_abstains(ambiguous: bool) -> None:
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x1010,
        source_block_ea=0x1000,
        materialized_anchor_eas=(0x1002,),
        target_eas=(0x2000, 0x4000),
        condition_code=12,
        true_target_ea=0x2000,
        false_target_ea=0x4000,
    )
    transfers = (transfer,)
    if ambiguous:
        transfers = (
            _source_anchored_transfer(),
            MaterializedIndirectTransfer(
                source_jmp_ea=0x1010,
                source_block_ea=0x1000,
                materialized_anchor_eas=(0x1002,),
                target_eas=(0x4000,),
            ),
        )
    transition = StateWriteTransition(1, 0xDEAD, None, True, None)
    assert resolve_materialized_indirect_transfer_targets(
        (transition,),
        _condition_chain_graph(),
        IntervalDispatcher([], default_target=99),
        transfers,
        condition_chain_dag=_condition_chain_dag() if ambiguous else None,
        condition_chain_handlers=frozenset({3, 5}),
    ) == (transition,)
