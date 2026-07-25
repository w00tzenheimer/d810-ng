from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from d810.analyses.control_flow.materialized_indirect_transfer import (
    MaterializedIndirectTransfer,
    TerminalReturnCarrierRequest,
)


SCRIPT = (
    Path(__file__).resolve().parents[3]
    / "tools"
    / "scripts"
    / "rhad_investigation"
    / "preopt_boundary_port.py"
)


def _load_planner():
    assert SCRIPT.is_file(), "PREOPT boundary-port planner has not been created"
    module_name = "rhad_preopt_boundary_port_test"
    spec = importlib.util.spec_from_file_location(module_name, SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _direct(
    source_block_ea: int,
    source_write_ea: int,
    target_ea: int,
    *,
    state: int = 0x2100AFDD,
) -> MaterializedIndirectTransfer:
    return MaterializedIndirectTransfer(
        source_jmp_ea=source_write_ea,
        source_block_ea=source_block_ea,
        materialized_anchor_eas=(),
        target_eas=(target_ea,),
        selector_state_var_reg=20,
        selector_state_constant=state,
        resolver_kind="residual_state_route_evidence",
    )


def _conditional(
    *,
    source_block_ea: int = 0x3000,
    predicate_ea: int = 0x3008,
    true_target_ea: int = 0x4000,
    false_target_ea: int = 0x5000,
    true_is_taken: bool = False,
) -> MaterializedIndirectTransfer:
    return MaterializedIndirectTransfer(
        source_jmp_ea=predicate_ea,
        source_block_ea=source_block_ea,
        materialized_anchor_eas=(),
        target_eas=(true_target_ea, false_target_ea),
        condition_code=5,
        true_target_ea=true_target_ea,
        false_target_ea=false_target_ea,
        selector_state_var_reg=20,
        predicate_register=8,
        predicate_size=4,
        predicate_true_state=0x11111111,
        predicate_false_state=0x22222222,
        predicate_true_is_taken=true_is_taken,
        resolver_kind="conditional_handler_bridge",
    )


def test_preserves_distinct_same_state_source_ports():
    ports = _load_planner()

    result = ports.plan_preopt_resolver_boundary_ports(
        (
            _direct(0x1000, 0x1008, 0x2000),
            _direct(0x1100, 0x1108, 0x2000),
        ),
        imported_block_ranges={
            0x1000: (0x1000, 0x1010),
            0x1100: (0x1100, 0x1110),
            0x2000: (0x2000, 0x2010),
        },
        live_native_eas=frozenset(),
    )

    assert tuple(
        (row.source_block_ea, row.source_instruction_ea) for row in result.direct
    ) == ((0x1000, 0x1008), (0x1100, 0x1108))


def test_classifies_imported_and_live_port_endpoints():
    ports = _load_planner()
    owner = ports.PreoptBoundaryEndpointOwner

    result = ports.plan_preopt_resolver_boundary_ports(
        (
            _direct(0x1000, 0x1008, 0x2000),
            _direct(0x3000, 0x3008, 0x2000, state=0x31),
            _direct(0x1000, 0x100C, 0x4000, state=0x41),
        ),
        imported_block_ranges={
            0x1000: (0x1000, 0x1010),
            0x2000: (0x2000, 0x2010),
        },
        live_native_eas=frozenset({0x3000, 0x3008, 0x4000}),
    )

    assert tuple((row.source_owner, row.target_owner) for row in result.direct) == (
        (owner.IMPORTED, owner.IMPORTED),
        (owner.IMPORTED, owner.LIVE),
        (owner.LIVE, owner.IMPORTED),
    )


def test_orients_conditional_targets_to_native_taken_and_fallthrough_arms():
    ports = _load_planner()

    result = ports.plan_preopt_resolver_boundary_ports(
        (_conditional(true_is_taken=False),),
        imported_block_ranges={
            0x3000: (0x3000, 0x3010),
            0x4000: (0x4000, 0x4010),
        },
        live_native_eas=frozenset({0x5000}),
    )

    (port,) = result.conditional
    assert port.taken_target_ea == 0x5000
    assert port.fallthrough_target_ea == 0x4000
    assert port.taken_state == 0x22222222
    assert port.fallthrough_state == 0x11111111


def test_preserves_a_resolver_proven_conditional_when_all_owners_are_live():
    ports = _load_planner()
    owner = ports.PreoptBoundaryEndpointOwner

    result = ports.plan_preopt_resolver_boundary_ports(
        (_conditional(true_is_taken=False),),
        imported_block_ranges={},
        live_native_eas=frozenset(
            {
                0x3000,
                0x3008,
                0x4000,
                0x5000,
            }
        ),
    )

    (port,) = result.conditional
    assert port.source_owner is owner.LIVE
    assert port.taken_target_owner is owner.LIVE
    assert port.fallthrough_target_owner is owner.LIVE
    assert port.taken_target_ea == 0x5000
    assert port.fallthrough_target_ea == 0x4000
    assert result.abstentions == ()


def test_rebinds_conditional_states_to_proven_payload_handlers():
    ports = _load_planner()

    result = ports.plan_preopt_resolver_boundary_ports(
        (_conditional(true_is_taken=False),),
        imported_block_ranges={
            0x3000: (0x3000, 0x3010),
            0x4100: (0x4100, 0x4110),
        },
        live_native_eas=frozenset({0x5100}),
        state_payload_handler_eas={
            0x11111111: (0x4100,),
            0x22222222: (0x5100,),
        },
    )

    (port,) = result.conditional
    assert port.taken_target_ea == 0x5100
    assert port.fallthrough_target_ea == 0x4100
    assert port.taken_state == 0x22222222
    assert port.fallthrough_state == 0x11111111


def test_collapses_exact_duplicate_direct_proofs():
    ports = _load_planner()
    transfer = _direct(0x1000, 0x1008, 0x2000)

    result = ports.plan_preopt_resolver_boundary_ports(
        (transfer, transfer),
        imported_block_ranges={
            0x1000: (0x1000, 0x1010),
            0x2000: (0x2000, 0x2010),
        },
        live_native_eas=frozenset(),
    )

    assert len(result.direct) == 1
    assert result.abstentions == ()


def test_conflicting_direct_targets_contaminate_the_whole_source():
    ports = _load_planner()

    result = ports.plan_preopt_resolver_boundary_ports(
        (
            _direct(0x1000, 0x1008, 0x2000),
            _direct(0x1000, 0x1008, 0x2100),
        ),
        imported_block_ranges={
            0x1000: (0x1000, 0x1010),
            0x2000: (0x2000, 0x2010),
            0x2100: (0x2100, 0x2110),
        },
        live_native_eas=frozenset(),
    )

    assert result.direct == ()
    assert result.abstentions == (
        ports.PreoptBoundaryPortAbstention(
            source_ea=0x1008,
            reason=ports.PreoptBoundaryPortAbstentionReason.CONFLICTING_SOURCE,
            target_ea=None,
        ),
    )


def test_abstains_when_a_relevant_port_endpoint_has_no_owner():
    ports = _load_planner()

    result = ports.plan_preopt_resolver_boundary_ports(
        (_direct(0x3000, 0x3008, 0x2000),),
        imported_block_ranges={0x2000: (0x2000, 0x2010)},
        live_native_eas=frozenset(),
    )

    assert result.direct == ()
    assert result.abstentions == (
        ports.PreoptBoundaryPortAbstention(
            source_ea=0x3008,
            reason=ports.PreoptBoundaryPortAbstentionReason.MISSING_SOURCE_OWNER,
            target_ea=0x2000,
        ),
    )


def test_abstains_when_only_the_source_block_not_the_instruction_is_live():
    ports = _load_planner()

    result = ports.plan_preopt_resolver_boundary_ports(
        (_conditional(predicate_ea=0xF1000000),),
        imported_block_ranges={
            0x4000: (0x4000, 0x4010),
            0x5000: (0x5000, 0x5010),
        },
        live_native_eas=frozenset({0x3000}),
    )

    assert result.conditional == ()
    assert result.abstentions == (
        ports.PreoptBoundaryPortAbstention(
            source_ea=0xF1000000,
            reason=ports.PreoptBoundaryPortAbstentionReason.MISSING_SOURCE_OWNER,
            target_ea=None,
        ),
    )


def test_complete_conditional_subsumes_matching_direct_arm_from_same_block():
    ports = _load_planner()

    result = ports.plan_preopt_resolver_boundary_ports(
        (
            _direct(0x3000, 0x3004, 0x4000, state=0x11111111),
            _conditional(source_block_ea=0x3000, predicate_ea=0x3008),
        ),
        imported_block_ranges={
            0x3000: (0x3000, 0x3010),
            0x4000: (0x4000, 0x4010),
            0x5000: (0x5000, 0x5010),
        },
        live_native_eas=frozenset(),
    )

    assert result.direct == ()
    assert len(result.conditional) == 1
    assert result.abstentions == ()


def test_inconsistent_direct_arm_contaminates_complete_conditional_source():
    ports = _load_planner()

    result = ports.plan_preopt_resolver_boundary_ports(
        (
            _direct(0x3000, 0x3004, 0x4000, state=0xDEADBEEF),
            _conditional(source_block_ea=0x3000, predicate_ea=0x3008),
        ),
        imported_block_ranges={
            0x3000: (0x3000, 0x3010),
            0x4000: (0x4000, 0x4010),
            0x5000: (0x5000, 0x5010),
        },
        live_native_eas=frozenset(),
    )

    assert result.direct == ()
    assert result.conditional == ()
    assert result.abstentions == (
        ports.PreoptBoundaryPortAbstention(
            source_ea=0x3008,
            reason=ports.PreoptBoundaryPortAbstentionReason.CONFLICTING_SOURCE,
            target_ea=None,
        ),
    )


def _planned_conditional_port(ports, *, resolver_kind: str, taken=0x4000):
    owner = ports.PreoptBoundaryEndpointOwner
    return ports.PreoptConditionalBoundaryPort(
        source_block_ea=0x3000,
        predicate_ea=0x3008,
        taken_target_ea=taken,
        fallthrough_target_ea=0x5000,
        state_register=20,
        taken_state=0x11,
        fallthrough_state=0x22,
        source_owner=owner.LIVE,
        taken_target_owner=owner.IMPORTED,
        fallthrough_target_owner=owner.LIVE,
        resolver_kind=resolver_kind,
    )


def test_coalesces_semantically_identical_conditional_proofs():
    ports = _load_planner()
    resolver_port = _planned_conditional_port(
        ports,
        resolver_kind="conditional_handler_bridge",
    )
    state_path_port = _planned_conditional_port(
        ports,
        resolver_kind="preopt_pruned_conditional_state_choice",
    )

    conditional, abstentions = ports.coalesce_preopt_conditional_boundary_ports(
        (resolver_port, state_path_port)
    )

    assert conditional == (resolver_port,)
    assert abstentions == ()


def test_conflicting_conditional_proofs_abstain_for_the_whole_source():
    ports = _load_planner()

    conditional, abstentions = ports.coalesce_preopt_conditional_boundary_ports(
        (
            _planned_conditional_port(
                ports,
                resolver_kind="conditional_handler_bridge",
            ),
            _planned_conditional_port(
                ports,
                resolver_kind="preopt_pruned_conditional_state_choice",
                taken=0x6000,
            ),
        )
    )

    assert conditional == ()
    assert abstentions == (
        ports.PreoptBoundaryPortAbstention(
            source_ea=0x3008,
            reason=ports.PreoptBoundaryPortAbstentionReason.CONFLICTING_SOURCE,
        ),
    )


def _routing_topology(ports):
    return ports.PreoptConditionalTopologyFact(
        source_block_ea=0x1000,
        predicate_ea=0x1008,
        taken_successor_ea=0x1100,
        fallthrough_successor_ea=0x1200,
    )


def test_plans_resolver_proven_conditional_routing_to_distinct_endpoints():
    ports = _load_planner()
    owner = ports.PreoptBoundaryEndpointOwner

    result = ports.plan_preopt_conditional_routing_boundary_ports(
        (_routing_topology(ports),),
        exact_targets_by_source_ea={
            0x1100: (0x2000,),
            0x1200: (0x1300,),
            0x1300: (0x3000,),
        },
        stable_endpoint_eas=(0x2000, 0x3000),
        imported_block_ranges={
            0x1000: (0x1000, 0x1010),
            0x2000: (0x2000, 0x2010),
        },
        live_native_eas=(0x3000,),
    )

    assert result.conditional == (
        ports.PreoptConditionalBoundaryPort(
            source_block_ea=0x1000,
            predicate_ea=0x1008,
            taken_target_ea=0x2000,
            fallthrough_target_ea=0x3000,
            state_register=None,
            taken_state=None,
            fallthrough_state=None,
            source_owner=owner.IMPORTED,
            taken_target_owner=owner.IMPORTED,
            fallthrough_target_owner=owner.LIVE,
            resolver_kind="preopt_resolver_conditional_routing",
        ),
    )
    assert result.abstentions == ()


def test_conditional_routing_abstains_from_ambiguous_arm():
    ports = _load_planner()

    result = ports.plan_preopt_conditional_routing_boundary_ports(
        (_routing_topology(ports),),
        exact_targets_by_source_ea={
            0x1100: (0x2000, 0x2100),
            0x1200: (0x3000,),
        },
        stable_endpoint_eas=(0x2000, 0x2100, 0x3000),
        imported_block_ranges={0x1000: (0x1000, 0x1010)},
        live_native_eas=(0x2000, 0x2100, 0x3000),
    )

    assert result.conditional == ()
    assert result.abstentions[0].reason is (
        ports.PreoptBoundaryPortAbstentionReason.AMBIGUOUS_ROUTE
    )


def test_conditional_routing_abstains_from_unresolved_arm():
    ports = _load_planner()

    result = ports.plan_preopt_conditional_routing_boundary_ports(
        (_routing_topology(ports),),
        exact_targets_by_source_ea={0x1100: (0x2000,)},
        stable_endpoint_eas=(0x2000, 0x3000),
        imported_block_ranges={0x1000: (0x1000, 0x1010)},
        live_native_eas=(0x2000, 0x3000),
    )

    assert result.conditional == ()
    assert result.abstentions[0].reason is (
        ports.PreoptBoundaryPortAbstentionReason.UNRESOLVED_ROUTE
    )


def test_conditional_routing_abstains_when_arms_converge():
    ports = _load_planner()

    result = ports.plan_preopt_conditional_routing_boundary_ports(
        (_routing_topology(ports),),
        exact_targets_by_source_ea={
            0x1100: (0x2000,),
            0x1200: (0x2000,),
        },
        stable_endpoint_eas=(0x2000,),
        imported_block_ranges={
            0x1000: (0x1000, 0x1010),
            0x2000: (0x2000, 0x2010),
        },
        live_native_eas=(),
    )

    assert result.conditional == ()
    assert result.abstentions[0].reason is (
        ports.PreoptBoundaryPortAbstentionReason.CONVERGED_CONDITIONAL_ARMS
    )


def test_conditional_routing_abstains_when_endpoint_has_no_owner():
    ports = _load_planner()

    result = ports.plan_preopt_conditional_routing_boundary_ports(
        (_routing_topology(ports),),
        exact_targets_by_source_ea={
            0x1100: (0x2000,),
            0x1200: (0x3000,),
        },
        stable_endpoint_eas=(0x2000, 0x3000),
        imported_block_ranges={
            0x1000: (0x1000, 0x1010),
            0x2000: (0x2000, 0x2010),
        },
        live_native_eas=(),
    )

    assert result.conditional == ()
    assert result.abstentions[0] == ports.PreoptBoundaryPortAbstention(
        source_ea=0x1008,
        reason=ports.PreoptBoundaryPortAbstentionReason.MISSING_TARGET_OWNER,
        target_ea=0x3000,
    )


def test_exact_route_targets_replace_weaker_native_successors():
    ports = _load_planner()

    merged = ports.merge_preopt_exact_route_targets(
        {
            0x1100: (0x1110, 0x1120),
            0x1200: (0x1210,),
        },
        exact_routes=(
            (0x1100, 0x2000),
            (0x1100, 0x2000),
            (0x1200, 0x3000),
            (0x1200, 0x3100),
        ),
    )

    assert merged == {
        0x1100: {0x2000},
        0x1200: {0x3000, 0x3100},
    }


def test_derives_retained_arm_target_from_source_and_one_distinct_override():
    ports = _load_planner()

    routes = ports.derive_preopt_fixed_source_arm_routes(
        (_routing_topology(ports),),
        source_sensitive_targets_by_source_ea={
            0x1000: (0x3000,),
            0x1100: (0x2000,),
        },
    )

    assert routes == ((0x1200, 0x3000),)


def test_fixed_source_arm_derivation_abstains_without_one_override():
    ports = _load_planner()

    assert (
        ports.derive_preopt_fixed_source_arm_routes(
            (_routing_topology(ports),),
            source_sensitive_targets_by_source_ea={
                0x1000: (0x3000,),
                0x1100: (0x2000,),
                0x1200: (0x2100,),
            },
        )
        == ()
    )


def test_stronger_plan_excludes_same_predicate_after_block_entry_moves():
    ports = _load_planner()
    topology = _routing_topology(ports)
    planned = ports.PreoptConditionalBoundaryPort(
        source_block_ea=0x0FF0,
        predicate_ea=topology.predicate_ea,
        taken_target_ea=0x2000,
        fallthrough_target_ea=0x3000,
        state_register=20,
        taken_state=0x11,
        fallthrough_state=0x22,
        source_owner=ports.PreoptBoundaryEndpointOwner.LIVE,
        taken_target_owner=ports.PreoptBoundaryEndpointOwner.IMPORTED,
        fallthrough_target_owner=ports.PreoptBoundaryEndpointOwner.IMPORTED,
        resolver_kind="conditional_state_choice",
    )

    assert (
        ports.exclude_preopt_conditional_topology_with_planned_predicates(
            (topology,),
            (planned,),
        )
        == ()
    )


def _terminal_return_request(
    *,
    source_handler_ea: int = 0x1008,
    terminal_target_ea: int = 0x4000,
    state_constant: int = 0x11,
) -> TerminalReturnCarrierRequest:
    return TerminalReturnCarrierRequest(
        source_handler_ea=source_handler_ea,
        terminal_target_ea=terminal_target_ea,
        state_var_reg=20,
        state_constant=state_constant,
    )


def test_plans_terminal_return_on_taken_arm_and_preserves_native_sibling():
    ports = _load_planner()
    owner = ports.PreoptBoundaryEndpointOwner
    topology = ports.PreoptConditionalTopologyFact(
        source_block_ea=0x1000,
        predicate_ea=0x1008,
        taken_successor_ea=0x4000,
        fallthrough_successor_ea=0x2000,
    )

    result = ports.plan_preopt_terminal_return_boundary_ports(
        (topology,),
        (_terminal_return_request(),),
        imported_block_ranges={0x4000: (0x4000, 0x4010)},
        live_native_eas=(0x1000, 0x1008, 0x2000),
    )

    assert result.conditional == (
        ports.PreoptConditionalBoundaryPort(
            source_block_ea=0x1000,
            predicate_ea=0x1008,
            taken_target_ea=0x4000,
            fallthrough_target_ea=0x2000,
            state_register=20,
            taken_state=0x11,
            fallthrough_state=None,
            source_owner=owner.LIVE,
            taken_target_owner=owner.IMPORTED,
            fallthrough_target_owner=owner.LIVE,
            resolver_kind="preopt_terminal_return_boundary",
        ),
    )
    assert result.abstentions == ()


def test_plans_terminal_return_on_fallthrough_arm():
    ports = _load_planner()
    topology = ports.PreoptConditionalTopologyFact(
        source_block_ea=0x1000,
        predicate_ea=0x1008,
        taken_successor_ea=0x2000,
        fallthrough_successor_ea=0x4000,
    )

    result = ports.plan_preopt_terminal_return_boundary_ports(
        (topology,),
        (_terminal_return_request(),),
        imported_block_ranges={0x4000: (0x4000, 0x4010)},
        live_native_eas=(0x1000, 0x1008, 0x2000),
    )

    (port,) = result.conditional
    assert port.taken_target_ea == 0x2000
    assert port.fallthrough_target_ea == 0x4000
    assert port.taken_state is None
    assert port.fallthrough_state == 0x11
    assert result.abstentions == ()


def test_terminal_return_planner_ignores_request_without_predicate_match():
    ports = _load_planner()

    result = ports.plan_preopt_terminal_return_boundary_ports(
        (_routing_topology(ports),),
        (_terminal_return_request(source_handler_ea=0x9000),),
        imported_block_ranges={0x4000: (0x4000, 0x4010)},
        live_native_eas=(0x1000, 0x1008, 0x1100, 0x1200),
    )

    assert result == ports.PreoptBoundaryPortPlan((), (), ())


def test_conflicting_terminal_return_requests_abstain_for_predicate():
    ports = _load_planner()
    topology = ports.PreoptConditionalTopologyFact(
        source_block_ea=0x1000,
        predicate_ea=0x1008,
        taken_successor_ea=0x4000,
        fallthrough_successor_ea=0x2000,
    )

    result = ports.plan_preopt_terminal_return_boundary_ports(
        (topology,),
        (
            _terminal_return_request(state_constant=0x11),
            _terminal_return_request(state_constant=0x22),
        ),
        imported_block_ranges={0x4000: (0x4000, 0x4010)},
        live_native_eas=(0x1000, 0x1008, 0x2000),
    )

    assert result.conditional == ()
    assert result.abstentions == (
        ports.PreoptBoundaryPortAbstention(
            source_ea=0x1008,
            reason=ports.PreoptBoundaryPortAbstentionReason.CONFLICTING_SOURCE,
        ),
    )
