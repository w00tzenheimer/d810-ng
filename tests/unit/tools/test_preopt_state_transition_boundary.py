from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from d810.analyses.control_flow.materialized_indirect_transfer import (
    TerminalReturnCarrierRequest,
)


SCRIPT_DIR = (
    Path(__file__).resolve().parents[3] / "tools" / "scripts" / "rhad_investigation"
)


def _load_script(module_name: str, filename: str):
    path = SCRIPT_DIR / filename
    assert path.is_file(), f"{filename} has not been created"
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _modules():
    ports = _load_script("preopt_boundary_port", "preopt_boundary_port.py")
    capture = _load_script(
        "preopt_boundary_port_capture",
        "preopt_boundary_port_capture.py",
    )
    transition = _load_script(
        "preopt_state_transition_boundary_test",
        "preopt_state_transition_boundary.py",
    )
    return ports, capture, transition


def _fact(
    capture,
    start_ea: int,
    *,
    successors: tuple[int, ...] = (),
    constants: tuple[tuple[int, int, int], ...] = (),
    writes: tuple[tuple[int, int], ...] = (),
    copies: tuple[tuple[int, int, int], ...] = (),
    stack_loads: tuple[tuple[int, int, int, int], ...] = (),
    stack_stores: tuple[tuple[int, int, int, int], ...] = (),
    extra_instruction_eas: tuple[int, ...] = (),
    tail_ea: int | None = None,
    taken_successor_ea: int | None = None,
    fallthrough_successor_ea: int | None = None,
    tail_kind: str = "INDIRECT",
):
    instruction_eas = tuple(
        sorted(
            {
                *(write_ea for _register, _constant, write_ea in constants),
                *(write_ea for _register, write_ea in writes),
                *(write_ea for _dest, _source, write_ea in copies),
                *(write_ea for _dest, _off, _size, write_ea in stack_loads),
                *(write_ea for _off, _size, _source, write_ea in stack_stores),
                *extra_instruction_eas,
                *((tail_ea,) if tail_ea is not None else ()),
            }
        )
    )
    return capture.PreoptPortBlockFact(
        start_ea=start_ea,
        end_ea=start_ea + 0x10,
        instruction_eas=instruction_eas,
        successor_eas=successors,
        register_constant_writes=constants,
        register_write_eas=(
            writes
            + tuple((register, write_ea) for register, _constant, write_ea in constants)
            + tuple(
                (dest_register, write_ea)
                for dest_register, _source_register, write_ea in copies
            )
            + tuple(
                (dest_register, write_ea)
                for dest_register, _off, _size, write_ea in stack_loads
            )
        ),
        register_copy_writes=copies,
        register_stack_loads=stack_loads,
        stack_register_stores=stack_stores,
        tail_ea=tail_ea,
        taken_successor_ea=taken_successor_ea,
        fallthrough_successor_ea=fallthrough_successor_ea,
        tail_kind=(
            capture.PreoptPortTailKind[tail_kind]
            if tail_ea is not None
            else capture.PreoptPortTailKind.OTHER
        ),
    )


def test_terminal_return_targets_extend_semantic_seeds_for_state_register():
    _ports, _capture, transition = _modules()

    seeds = transition.extend_semantic_seed_eas_with_terminal_targets(
        (0x1000, 0x2000),
        (
            TerminalReturnCarrierRequest(0x3000, 0x4000, 20, 0x11),
            TerminalReturnCarrierRequest(0x5000, 0x2000, 20, 0x22),
            TerminalReturnCarrierRequest(0x6000, 0x7000, 24, 0x33),
        ),
        state_register=20,
    )

    assert seeds == (0x1000, 0x2000, 0x4000)


def _cut(transition, *, block_ea: int = 0x1200, tail_ea: int = 0x1208):
    return transition.PreoptUnresolvedStateCut(
        source_block_ea=block_ea,
        tail_ea=tail_ea,
        state_register=20,
    )


def test_merges_only_exact_targets_for_the_selected_state_register():
    _ports, _capture, transition = _modules()

    merged = transition.merge_exact_state_payload_handler_eas(
        {0x11: {0x4000}},
        state_register=20,
        exact_routes=(
            (20, 0x22, 0x5000),
            (21, 0x33, 0x6000),
            (20, 0x11, 0x7000),
        ),
    )

    assert merged == {
        0x11: {0x7000},
        0x22: {0x5000},
    }


def _plan(
    transition,
    capture,
    *,
    blocks,
    state_handlers,
    cuts=None,
    choices=(),
):
    return transition.plan_preopt_state_transition_boundary_ports(
        ((_cut(transition),) if cuts is None else cuts),
        blocks_by_ea=blocks,
        state_handler_eas=state_handlers,
        conditional_choices=choices,
        imported_block_ranges={
            block_ea: (block_ea, block_ea + 0x10)
            for block_ea in {*blocks, 0x4000, 0x5000}
        },
        live_native_eas=frozenset(),
    )


def test_plans_direct_port_from_unique_reaching_literal_state_write():
    ports, capture, transition = _modules()
    blocks = {
        0x1000: _fact(
            capture,
            0x1000,
            successors=(0x1200,),
            constants=((20, 0x11, 0x1004),),
        ),
        0x1200: _fact(capture, 0x1200, tail_ea=0x1208),
    }

    result = _plan(
        transition,
        capture,
        blocks=blocks,
        state_handlers={0x11: (0x4000,)},
    )

    assert result.abstentions == ()
    assert result.conditional == ()
    assert result.direct == (
        ports.PreoptDirectBoundaryPort(
            source_block_ea=0x1000,
            source_instruction_ea=0x1004,
            target_ea=0x4000,
            state_register=20,
            state_constant=0x11,
            source_owner=ports.PreoptBoundaryEndpointOwner.IMPORTED,
            target_owner=ports.PreoptBoundaryEndpointOwner.IMPORTED,
            resolver_kind="preopt_state_transition",
        ),
    )


def test_plans_every_mapped_literal_state_write_without_a_cut():
    ports, capture, transition = _modules()
    blocks = {
        0x1000: _fact(
            capture,
            0x1000,
            constants=((20, 0x11, 0x1004),),
        ),
        0x2000: _fact(
            capture,
            0x2000,
            constants=((20, 0x22, 0x2004),),
        ),
    }

    result = transition.plan_preopt_literal_state_write_boundary_ports(
        blocks_by_ea=blocks,
        state_register=20,
        state_handler_eas={0x11: (0x4000,), 0x22: (0x5000,)},
        imported_block_ranges={
            0x1000: (0x1000, 0x1010),
            0x4000: (0x4000, 0x4010),
        },
        live_native_eas=frozenset({0x2000, 0x2004, 0x5000}),
    )

    assert result.abstentions == ()
    assert result.conditional == ()
    assert tuple(
        (
            row.source_instruction_ea,
            row.target_ea,
            row.source_owner,
            row.target_owner,
        )
        for row in result.direct
    ) == (
        (
            0x1004,
            0x4000,
            ports.PreoptBoundaryEndpointOwner.IMPORTED,
            ports.PreoptBoundaryEndpointOwner.IMPORTED,
        ),
        (
            0x2004,
            0x5000,
            ports.PreoptBoundaryEndpointOwner.LIVE,
            ports.PreoptBoundaryEndpointOwner.LIVE,
        ),
    )


def test_owned_literal_planner_adds_live_to_imported_state_route():
    ports, capture, transition = _modules()
    state = 0x82F1899D
    source_ea = 0x40BF43
    write_ea = 0x40BF5B
    target_ea = 0x40B758

    result = transition.plan_preopt_owned_literal_state_write_boundary_ports(
        imported_blocks_by_ea={
            target_ea: _fact(capture, target_ea),
        },
        live_blocks_by_ea={
            source_ea: _fact(
                capture,
                source_ea,
                constants=((20, state, write_ea),),
            ),
        },
        state_register=20,
        state_handler_eas={state: (target_ea,)},
        imported_block_ranges={
            target_ea: (target_ea, target_ea + 0x10),
        },
        live_native_eas=frozenset({source_ea, write_ea}),
    )

    assert result.abstentions == ()
    assert result.conditional == ()
    assert result.direct == (
        ports.PreoptDirectBoundaryPort(
            source_block_ea=source_ea,
            source_instruction_ea=write_ea,
            target_ea=target_ea,
            state_register=20,
            state_constant=state,
            source_owner=ports.PreoptBoundaryEndpointOwner.LIVE,
            target_owner=ports.PreoptBoundaryEndpointOwner.IMPORTED,
            resolver_kind="preopt_state_transition",
        ),
    )


def test_recognizes_pruned_live_conditional_state_path_from_native_topology():
    ports, capture, transition = _modules()
    default_state = 0x636961E8
    alternate_state = 0x0BB2D365
    source_ea = 0x1000
    predicate_ea = 0x100C
    taken_ea = 0x1100
    fallthrough_ea = 0x1200

    choices = transition.recognize_preopt_pruned_conditional_state_choices(
        blocks_by_ea={
            source_ea: _fact(
                capture,
                source_ea,
                constants=((20, default_state, 0x1008),),
                tail_ea=predicate_ea,
                tail_kind="CONDITIONAL",
            ),
            taken_ea: _fact(
                capture,
                taken_ea,
                constants=((20, alternate_state, taken_ea),),
            ),
            fallthrough_ea: _fact(capture, fallthrough_ea),
        },
        native_topology_by_ea={
            source_ea: transition.PreoptConditionalTopologyFact(
                source_block_ea=source_ea,
                predicate_ea=predicate_ea,
                taken_successor_ea=taken_ea,
                fallthrough_successor_ea=fallthrough_ea,
            ),
        },
        state_register=20,
        source_owner=ports.PreoptBoundaryEndpointOwner.LIVE,
    )

    assert choices == (
        transition.PreoptConditionalStateChoice(
            consumer_tail_ea=predicate_ea,
            predicate_block_ea=source_ea,
            predicate_ea=predicate_ea,
            state_register=20,
            taken_state=alternate_state,
            fallthrough_state=default_state,
            resolver_kind="preopt_pruned_conditional_state_choice",
            source_owner=ports.PreoptBoundaryEndpointOwner.LIVE,
        ),
    )

    result = transition.plan_preopt_conditional_state_choice_boundary_ports(
        choices,
        state_handler_eas={
            default_state: (0x4000,),
            alternate_state: (0x5000,),
        },
        imported_block_ranges={0x5000: (0x5000, 0x5010)},
        live_native_eas=frozenset({source_ea, predicate_ea, 0x4000}),
    )

    assert result.abstentions == ()
    assert result.direct == ()
    assert result.conditional == (
        ports.PreoptConditionalBoundaryPort(
            source_block_ea=source_ea,
            predicate_ea=predicate_ea,
            taken_target_ea=0x5000,
            fallthrough_target_ea=0x4000,
            state_register=20,
            taken_state=alternate_state,
            fallthrough_state=default_state,
            source_owner=ports.PreoptBoundaryEndpointOwner.LIVE,
            taken_target_owner=(ports.PreoptBoundaryEndpointOwner.IMPORTED),
            fallthrough_target_owner=ports.PreoptBoundaryEndpointOwner.LIVE,
            resolver_kind="preopt_pruned_conditional_state_choice",
        ),
    )


def test_pruned_conditional_state_path_abstains_when_both_arms_write_state():
    ports, capture, transition = _modules()
    source_ea = 0x1000
    predicate_ea = 0x100C

    choices = transition.recognize_preopt_pruned_conditional_state_choices(
        blocks_by_ea={
            source_ea: _fact(
                capture,
                source_ea,
                constants=((20, 0x11, 0x1008),),
                tail_ea=predicate_ea,
                tail_kind="CONDITIONAL",
            ),
            0x1100: _fact(
                capture,
                0x1100,
                constants=((20, 0x22, 0x1100),),
            ),
            0x1200: _fact(
                capture,
                0x1200,
                constants=((20, 0x33, 0x1200),),
            ),
        },
        native_topology_by_ea={
            source_ea: transition.PreoptConditionalTopologyFact(
                source_block_ea=source_ea,
                predicate_ea=predicate_ea,
                taken_successor_ea=0x1100,
                fallthrough_successor_ea=0x1200,
            ),
        },
        state_register=20,
        source_owner=ports.PreoptBoundaryEndpointOwner.LIVE,
    )

    assert choices == ()


def test_proves_fixed_state_cut_when_both_native_arms_enter_router():
    ports, capture, transition = _modules()
    source_ea = 0x1000
    predicate_ea = 0x100C
    topology = transition.PreoptConditionalTopologyFact(
        source_block_ea=source_ea,
        predicate_ea=predicate_ea,
        taken_successor_ea=0x2000,
        fallthrough_successor_ea=0x2100,
    )

    proven = transition.prove_preopt_pruned_conditional_fixed_state_sources(
        blocks_by_ea={
            source_ea: _fact(
                capture,
                source_ea,
                constants=((20, 0x11, 0x1008),),
                tail_ea=predicate_ea,
                tail_kind="CONDITIONAL",
            ),
        },
        native_topology_by_ea={source_ea: topology},
        state_register=20,
        dispatcher_router_eas=frozenset({0x2000, 0x2100}),
    )

    assert proven == frozenset({source_ea})


def test_fixed_state_cut_rejects_a_non_router_arm():
    _ports, capture, transition = _modules()
    source_ea = 0x1000
    predicate_ea = 0x100C

    proven = transition.prove_preopt_pruned_conditional_fixed_state_sources(
        blocks_by_ea={
            source_ea: _fact(
                capture,
                source_ea,
                constants=((20, 0x11, 0x1008),),
                tail_ea=predicate_ea,
                tail_kind="CONDITIONAL",
            ),
        },
        native_topology_by_ea={
            source_ea: transition.PreoptConditionalTopologyFact(
                source_block_ea=source_ea,
                predicate_ea=predicate_ea,
                taken_successor_ea=0x2000,
                fallthrough_successor_ea=0x3000,
            ),
        },
        state_register=20,
        dispatcher_router_eas=frozenset({0x2000}),
    )

    assert proven == frozenset()


def test_fixed_state_cut_accepts_resolver_proven_bridge_to_router():
    _ports, capture, transition = _modules()
    source_ea = 0x1000
    predicate_ea = 0x100C
    false_bridge_ea = 0x1012

    proven = transition.prove_preopt_pruned_conditional_fixed_state_sources(
        blocks_by_ea={
            source_ea: _fact(
                capture,
                source_ea,
                constants=((20, 0x11, 0x1008),),
                tail_ea=predicate_ea,
                tail_kind="CONDITIONAL",
            ),
        },
        native_topology_by_ea={
            source_ea: transition.PreoptConditionalTopologyFact(
                source_block_ea=source_ea,
                predicate_ea=predicate_ea,
                taken_successor_ea=0x2000,
                fallthrough_successor_ea=false_bridge_ea,
            ),
        },
        state_register=20,
        dispatcher_router_eas=frozenset({0x2000, 0x2100}),
        resolver_bridge_targets_by_source_ea={
            false_bridge_ea: (0x2100,),
        },
    )

    assert proven == frozenset({source_ea})


def test_fixed_state_cut_accepts_exact_handler_arm_for_source_state():
    _ports, capture, transition = _modules()
    source_ea = 0x1000
    predicate_ea = 0x100C
    handler_bridge_ea = 0x1012
    handler_ea = 0x4000

    proven = transition.prove_preopt_pruned_conditional_fixed_state_sources(
        blocks_by_ea={
            source_ea: _fact(
                capture,
                source_ea,
                writes=((20, 0x1004),),
                extra_instruction_eas=(0x1008,),
                tail_ea=predicate_ea,
                tail_kind="CONDITIONAL",
            ),
        },
        native_topology_by_ea={
            source_ea: transition.PreoptConditionalTopologyFact(
                source_block_ea=source_ea,
                predicate_ea=predicate_ea,
                taken_successor_ea=0x2000,
                fallthrough_successor_ea=handler_bridge_ea,
            ),
        },
        state_register=20,
        dispatcher_router_eas=frozenset({0x2000}),
        resolver_bridge_targets_by_source_ea={
            handler_bridge_ea: (handler_ea,),
        },
        expected_target_eas_by_source_ea={source_ea: (handler_ea,)},
        expected_state_write_eas_by_source_ea={source_ea: (0x1008,)},
    )

    assert proven == frozenset({source_ea})


def test_fixed_state_cut_rejects_expected_handler_without_source_write_anchor():
    _ports, capture, transition = _modules()
    source_ea = 0x1000
    predicate_ea = 0x100C

    proven = transition.prove_preopt_pruned_conditional_fixed_state_sources(
        blocks_by_ea={
            source_ea: _fact(
                capture,
                source_ea,
                extra_instruction_eas=(0x1008,),
                tail_ea=predicate_ea,
                tail_kind="CONDITIONAL",
            ),
        },
        native_topology_by_ea={
            source_ea: transition.PreoptConditionalTopologyFact(
                source_block_ea=source_ea,
                predicate_ea=predicate_ea,
                taken_successor_ea=0x2000,
                fallthrough_successor_ea=0x4000,
            ),
        },
        state_register=20,
        dispatcher_router_eas=frozenset({0x2000}),
        expected_target_eas_by_source_ea={source_ea: (0x4000,)},
    )

    assert proven == frozenset()


def test_fixed_state_cut_accepts_proven_indirect_without_native_arms():
    _ports, capture, transition = _modules()
    source_ea = 0x1000
    predicate_ea = 0x100C

    proven = transition.prove_preopt_pruned_conditional_fixed_state_sources(
        blocks_by_ea={
            source_ea: _fact(
                capture,
                source_ea,
                constants=((20, 0x11, 0x1008),),
                tail_ea=predicate_ea,
                tail_kind="CONDITIONAL",
            ),
        },
        native_topology_by_ea={},
        state_register=20,
        dispatcher_router_eas=frozenset(),
        expected_target_eas_by_source_ea={source_ea: (0x4000,)},
        expected_state_write_eas_by_source_ea={source_ea: (0x1008,)},
        proven_indirect_source_block_eas=frozenset({source_ea}),
    )

    assert proven == frozenset({source_ea})


def test_fixed_state_cut_rejects_pruned_source_without_indirect_proof():
    _ports, capture, transition = _modules()
    source_ea = 0x1000
    predicate_ea = 0x100C

    proven = transition.prove_preopt_pruned_conditional_fixed_state_sources(
        blocks_by_ea={
            source_ea: _fact(
                capture,
                source_ea,
                constants=((20, 0x11, 0x1008),),
                tail_ea=predicate_ea,
                tail_kind="CONDITIONAL",
            ),
        },
        native_topology_by_ea={},
        state_register=20,
        dispatcher_router_eas=frozenset(),
        expected_target_eas_by_source_ea={source_ea: (0x4000,)},
        expected_state_write_eas_by_source_ea={source_ea: (0x1008,)},
    )

    assert proven == frozenset()


def test_fixed_state_cut_rejects_nonunique_expected_handler():
    _ports, capture, transition = _modules()
    source_ea = 0x1000
    predicate_ea = 0x100C

    proven = transition.prove_preopt_pruned_conditional_fixed_state_sources(
        blocks_by_ea={
            source_ea: _fact(
                capture,
                source_ea,
                constants=((20, 0x11, 0x1008),),
                tail_ea=predicate_ea,
                tail_kind="CONDITIONAL",
            ),
        },
        native_topology_by_ea={
            source_ea: transition.PreoptConditionalTopologyFact(
                source_block_ea=source_ea,
                predicate_ea=predicate_ea,
                taken_successor_ea=0x2000,
                fallthrough_successor_ea=0x4000,
            ),
        },
        state_register=20,
        dispatcher_router_eas=frozenset({0x2000}),
        expected_target_eas_by_source_ea={
            source_ea: (0x4000, 0x5000),
        },
    )

    assert proven == frozenset()


def test_fixed_state_cut_accepts_transitive_resolver_bridge_chain():
    _ports, capture, transition = _modules()
    source_ea = 0x1000
    predicate_ea = 0x100C

    proven = transition.prove_preopt_pruned_conditional_fixed_state_sources(
        blocks_by_ea={
            source_ea: _fact(
                capture,
                source_ea,
                constants=((20, 0x11, 0x1008),),
                tail_ea=predicate_ea,
                tail_kind="CONDITIONAL",
            ),
        },
        native_topology_by_ea={
            source_ea: transition.PreoptConditionalTopologyFact(
                source_block_ea=source_ea,
                predicate_ea=predicate_ea,
                taken_successor_ea=0x1100,
                fallthrough_successor_ea=0x1200,
            ),
        },
        state_register=20,
        dispatcher_router_eas=frozenset({0x3000}),
        resolver_bridge_targets_by_source_ea={
            0x1100: (0x2100,),
            0x1200: (0x2200,),
            0x2100: (0x3000,),
            0x2200: (0x3000,),
        },
    )

    assert proven == frozenset({source_ea})


def test_fixed_state_cut_rejects_ambiguous_resolver_bridge():
    _ports, capture, transition = _modules()
    source_ea = 0x1000
    predicate_ea = 0x100C

    proven = transition.prove_preopt_pruned_conditional_fixed_state_sources(
        blocks_by_ea={
            source_ea: _fact(
                capture,
                source_ea,
                constants=((20, 0x11, 0x1008),),
                tail_ea=predicate_ea,
                tail_kind="CONDITIONAL",
            ),
        },
        native_topology_by_ea={
            source_ea: transition.PreoptConditionalTopologyFact(
                source_block_ea=source_ea,
                predicate_ea=predicate_ea,
                taken_successor_ea=0x2000,
                fallthrough_successor_ea=0x2100,
            ),
        },
        state_register=20,
        dispatcher_router_eas=frozenset({0x2000, 0x3000}),
        resolver_bridge_targets_by_source_ea={
            0x2100: (0x3000, 0x4000),
        },
    )

    assert proven == frozenset()


def test_fixed_state_cut_excludes_a_recognized_state_choice_source():
    _ports, capture, transition = _modules()
    source_ea = 0x1000
    predicate_ea = 0x100C

    proven = transition.prove_preopt_pruned_conditional_fixed_state_sources(
        blocks_by_ea={
            source_ea: _fact(
                capture,
                source_ea,
                constants=((20, 0x11, 0x1008),),
                tail_ea=predicate_ea,
                tail_kind="CONDITIONAL",
            ),
        },
        native_topology_by_ea={
            source_ea: transition.PreoptConditionalTopologyFact(
                source_block_ea=source_ea,
                predicate_ea=predicate_ea,
                taken_successor_ea=0x2000,
                fallthrough_successor_ea=0x2100,
            ),
        },
        state_register=20,
        dispatcher_router_eas=frozenset({0x2000, 0x2100}),
        excluded_source_eas=frozenset({source_ea}),
    )

    assert proven == frozenset()


def test_owned_literal_planner_keeps_fully_live_and_ignores_unmapped_states():
    ports, capture, transition = _modules()
    mapped_state = 0x11
    unmapped_terminal_state = 0x22

    result = transition.plan_preopt_owned_literal_state_write_boundary_ports(
        imported_blocks_by_ea={},
        live_blocks_by_ea={
            0x1000: _fact(
                capture,
                0x1000,
                constants=(
                    (20, mapped_state, 0x1004),
                    (20, unmapped_terminal_state, 0x1008),
                ),
            ),
            0x4000: _fact(capture, 0x4000),
        },
        state_register=20,
        state_handler_eas={mapped_state: (0x4000,)},
        imported_block_ranges={},
        live_native_eas=frozenset({0x1000, 0x1004, 0x1008, 0x4000}),
    )

    assert result.direct == (
        ports.PreoptDirectBoundaryPort(
            source_block_ea=0x1000,
            source_instruction_ea=0x1004,
            target_ea=0x4000,
            state_register=20,
            state_constant=mapped_state,
            source_owner=ports.PreoptBoundaryEndpointOwner.LIVE,
            target_owner=ports.PreoptBoundaryEndpointOwner.LIVE,
            resolver_kind="preopt_state_transition",
        ),
    )
    assert result.conditional == ()
    assert result.abstentions == ()


def test_owned_literal_planner_rejects_conflict_within_live_owner():
    ports, capture, transition = _modules()
    write_ea = 0x1004

    result = transition.plan_preopt_owned_literal_state_write_boundary_ports(
        imported_blocks_by_ea={
            0x4000: _fact(capture, 0x4000),
            0x5000: _fact(capture, 0x5000),
        },
        live_blocks_by_ea={
            0x1000: _fact(
                capture,
                0x1000,
                constants=((20, 0x11, write_ea), (20, 0x22, write_ea)),
            ),
        },
        state_register=20,
        state_handler_eas={0x11: (0x4000,), 0x22: (0x5000,)},
        imported_block_ranges={
            0x4000: (0x4000, 0x4010),
            0x5000: (0x5000, 0x5010),
        },
        live_native_eas=frozenset({0x1000, write_ea}),
    )

    assert result.direct == ()
    assert result.conditional == ()
    assert result.abstentions == (
        ports.PreoptBoundaryPortAbstention(
            write_ea,
            ports.PreoptBoundaryPortAbstentionReason.CONFLICTING_SOURCE,
        ),
    )


def test_literal_state_write_planner_abstains_on_unmapped_state():
    ports, capture, transition = _modules()
    blocks = {
        0x1000: _fact(
            capture,
            0x1000,
            constants=((20, 0xDEAD, 0x1004),),
        ),
    }

    result = transition.plan_preopt_literal_state_write_boundary_ports(
        blocks_by_ea=blocks,
        state_register=20,
        state_handler_eas={},
        imported_block_ranges={0x1000: (0x1000, 0x1010)},
        live_native_eas=frozenset(),
    )

    assert result.direct == ()
    assert result.conditional == ()
    assert result.abstentions == (
        ports.PreoptBoundaryPortAbstention(
            source_ea=0x1004,
            reason=(ports.PreoptBoundaryPortAbstentionReason.MISSING_STATE_HANDLER),
        ),
    )


def test_locates_preopt_cut_block_by_tail_after_a_call_split():
    _ports, capture, transition = _modules()
    blocks = {
        0x1000: _fact(capture, 0x1000, successors=(0x1100,)),
        0x1100: _fact(
            capture,
            0x1100,
            successors=(0x1200,),
            constants=((20, 0x11, 0x1104),),
        ),
        0x1200: _fact(capture, 0x1200, tail_ea=0x1208),
    }
    native_unsplit_cut = _cut(
        transition,
        block_ea=0x1000,
        tail_ea=0x1208,
    )

    result = _plan(
        transition,
        capture,
        blocks=blocks,
        state_handlers={0x11: (0x4000,)},
        cuts=(native_unsplit_cut,),
    )

    assert result.abstentions == ()
    assert tuple(row.source_instruction_ea for row in result.direct) == (0x1104,)


def test_plans_source_sensitive_ports_for_two_state_arms_before_a_merge():
    _ports, capture, transition = _modules()
    blocks = {
        0x1000: _fact(
            capture,
            0x1000,
            successors=(0x1200,),
            constants=((20, 0x11, 0x1004),),
        ),
        0x1100: _fact(
            capture,
            0x1100,
            successors=(0x1200,),
            constants=((20, 0x22, 0x1104),),
        ),
        0x1200: _fact(capture, 0x1200, tail_ea=0x1208),
    }

    result = _plan(
        transition,
        capture,
        blocks=blocks,
        state_handlers={0x11: (0x4000,), 0x22: (0x5000,)},
    )

    assert result.abstentions == ()
    assert tuple(
        (
            row.source_block_ea,
            row.source_instruction_ea,
            row.state_constant,
            row.target_ea,
        )
        for row in result.direct
    ) == (
        (0x1000, 0x1004, 0x11, 0x4000),
        (0x1100, 0x1104, 0x22, 0x5000),
    )


def test_plans_oriented_conditional_port_for_explicit_state_choice():
    ports, capture, transition = _modules()
    blocks = {
        0x1000: _fact(capture, 0x1000, successors=(0x1200, 0x1100)),
        0x1100: _fact(capture, 0x1100, successors=(0x1200,)),
        0x1200: _fact(capture, 0x1200, tail_ea=0x1208),
    }
    choice = transition.PreoptConditionalStateChoice(
        consumer_tail_ea=0x1208,
        predicate_block_ea=0x1000,
        predicate_ea=0x1008,
        state_register=20,
        taken_state=0x22,
        fallthrough_state=0x11,
        resolver_kind="entry_bridge_evidence",
    )

    result = _plan(
        transition,
        capture,
        blocks=blocks,
        state_handlers={0x11: (0x4000,), 0x22: (0x5000,)},
        choices=(choice,),
    )

    assert result.abstentions == ()
    assert result.direct == ()
    assert result.conditional == (
        ports.PreoptConditionalBoundaryPort(
            source_block_ea=0x1000,
            predicate_ea=0x1008,
            taken_target_ea=0x5000,
            fallthrough_target_ea=0x4000,
            state_register=20,
            taken_state=0x22,
            fallthrough_state=0x11,
            source_owner=ports.PreoptBoundaryEndpointOwner.IMPORTED,
            taken_target_owner=ports.PreoptBoundaryEndpointOwner.IMPORTED,
            fallthrough_target_owner=ports.PreoptBoundaryEndpointOwner.IMPORTED,
            resolver_kind="entry_bridge_evidence",
        ),
    )


def test_preserves_proven_live_conditional_source_across_import_overlap():
    ports, capture, transition = _modules()
    blocks = {
        0x1000: _fact(capture, 0x1000, successors=(0x1200, 0x1100)),
        0x1100: _fact(capture, 0x1100, successors=(0x1200,)),
        0x1200: _fact(capture, 0x1200, tail_ea=0x1208),
    }
    choice = transition.PreoptConditionalStateChoice(
        consumer_tail_ea=0x1208,
        predicate_block_ea=0x1000,
        predicate_ea=0x1008,
        state_register=20,
        taken_state=0x22,
        fallthrough_state=0x11,
        resolver_kind="entry_bridge_evidence",
        source_owner=ports.PreoptBoundaryEndpointOwner.LIVE,
        logical_source_anchor_ea=0x1204,
        predicate_ida_stkoff=0x18,
        predicate_size=4,
        condition_code=5,
    )

    result = transition.plan_preopt_state_transition_boundary_ports(
        (_cut(transition),),
        blocks_by_ea=blocks,
        state_handler_eas={0x11: (0x4000,), 0x22: (0x5000,)},
        conditional_choices=(choice,),
        imported_block_ranges={
            0x1000: (0x1000, 0x1010),
            0x4000: (0x4000, 0x4010),
            0x5000: (0x5000, 0x5010),
        },
        live_native_eas=frozenset({0x1000, 0x1008}),
    )

    assert result.abstentions == ()
    assert result.conditional[0].source_owner is (
        ports.PreoptBoundaryEndpointOwner.LIVE
    )
    assert result.conditional[0].logical_source_anchor_ea == 0x1204
    assert result.conditional[0].predicate_ida_stkoff == 0x18
    assert result.conditional[0].predicate_size == 4
    assert result.conditional[0].condition_code == 5


def test_recognizes_conditional_skip_state_choice_from_preopt_diamond():
    _ports, capture, transition = _modules()
    blocks = {
        0x1000: _fact(
            capture,
            0x1000,
            successors=(0x1200, 0x1100),
            constants=((20, 0x11, 0x1004), (8, 0x22, 0x1006)),
            tail_ea=0x1008,
            taken_successor_ea=0x1200,
            fallthrough_successor_ea=0x1100,
            tail_kind="CONDITIONAL",
        ),
        0x1100: _fact(
            capture,
            0x1100,
            successors=(0x1200,),
            copies=((20, 8, 0x1008),),
        ),
        0x1200: _fact(capture, 0x1200, successors=(0x1300,)),
        0x1300: _fact(capture, 0x1300, tail_ea=0x1308),
    }
    cut = _cut(transition, block_ea=0x1300, tail_ea=0x1308)

    choices = transition.recognize_preopt_conditional_state_choices(
        (cut,),
        blocks_by_ea=blocks,
    )

    assert choices == (
        transition.PreoptConditionalStateChoice(
            consumer_tail_ea=0x1308,
            predicate_block_ea=0x1000,
            predicate_ea=0x1008,
            state_register=20,
            taken_state=0x11,
            fallthrough_state=0x22,
            resolver_kind="preopt_conditional_state_choice",
        ),
    )


def test_orients_conditional_state_choice_when_taken_arm_performs_copy():
    _ports, capture, transition = _modules()
    blocks = {
        0x1000: _fact(
            capture,
            0x1000,
            successors=(0x1100, 0x1200),
            constants=((20, 0x11, 0x1004), (8, 0x22, 0x1006)),
            tail_ea=0x1008,
            taken_successor_ea=0x1100,
            fallthrough_successor_ea=0x1200,
            tail_kind="CONDITIONAL",
        ),
        0x1100: _fact(
            capture,
            0x1100,
            successors=(0x1200,),
            copies=((20, 8, 0x1008),),
        ),
        0x1200: _fact(capture, 0x1200, successors=(0x1300,)),
        0x1300: _fact(capture, 0x1300, tail_ea=0x1308),
    }

    choices = transition.recognize_preopt_conditional_state_choices(
        (_cut(transition, block_ea=0x1300, tail_ea=0x1308),),
        blocks_by_ea=blocks,
    )

    assert choices[0].taken_state == 0x22
    assert choices[0].fallthrough_state == 0x11


def test_abstains_from_conditional_skip_without_unique_temp_constant():
    _ports, capture, transition = _modules()
    blocks = {
        0x1000: _fact(
            capture,
            0x1000,
            successors=(0x1200, 0x1100),
            constants=((20, 0x11, 0x1004),),
            tail_ea=0x1008,
            taken_successor_ea=0x1200,
            fallthrough_successor_ea=0x1100,
            tail_kind="CONDITIONAL",
        ),
        0x1100: _fact(
            capture,
            0x1100,
            successors=(0x1200,),
            copies=((20, 8, 0x1008),),
        ),
        0x1200: _fact(capture, 0x1200, successors=(0x1300,)),
        0x1300: _fact(capture, 0x1300, tail_ea=0x1308),
    }

    choices = transition.recognize_preopt_conditional_state_choices(
        (_cut(transition, block_ea=0x1300, tail_ea=0x1308),),
        blocks_by_ea=blocks,
    )

    assert choices == ()


def test_recognizes_entry_evidence_carried_through_a_stack_cell():
    from d810.analyses.control_flow.residual_entry_bridge import (
        EntryBridgeEvidence,
    )

    _ports, capture, transition = _modules()
    blocks = {
        0x1000: _fact(
            capture,
            0x1000,
            successors=(0x1200, 0x1100),
            extra_instruction_eas=(0x1004,),
            tail_ea=0x1008,
            taken_successor_ea=0x1200,
            fallthrough_successor_ea=0x1100,
            tail_kind="CONDITIONAL",
        ),
        0x1100: _fact(capture, 0x1100, successors=(0x1200,)),
        0x1200: _fact(
            capture,
            0x1200,
            stack_stores=((0x70, 4, 8, 0x1204),),
        ),
        0x1300: _fact(
            capture,
            0x1300,
            stack_loads=((20, 0x70, 4, 0x1304),),
            tail_ea=0x1308,
        ),
    }
    evidence = EntryBridgeEvidence(
        predicate_ea=0x1004,
        condition_code=5,
        predicate_stack_identity=(0x20, 4),
        stack_cell_identity=(0x70, 4),
        taken_state_constant=0x22,
        fallthrough_state_constant=0x11,
        source_store_ea=0x1204,
    )

    choices = transition.recognize_preopt_stack_carried_state_choices(
        (_cut(transition, block_ea=0x1300, tail_ea=0x1308),),
        blocks_by_ea=blocks,
        entry_bridge_evidence=(evidence,),
    )

    assert choices == (
        transition.PreoptConditionalStateChoice(
            consumer_tail_ea=0x1308,
            predicate_block_ea=0x1000,
            predicate_ea=0x1008,
            state_register=20,
            taken_state=0x22,
            fallthrough_state=0x11,
            resolver_kind="preopt_stack_carried_state_choice",
        ),
    )


def test_recognizes_external_live_entry_evidence_at_imported_stack_load():
    from d810.analyses.control_flow.residual_entry_bridge import (
        EntryBridgeEvidence,
    )

    ports, capture, transition = _modules()
    blocks = {
        0x1300: _fact(
            capture,
            0x1300,
            stack_loads=((20, 0x40, 4, 0x1304),),
            tail_ea=0x1308,
        ),
    }
    evidence = EntryBridgeEvidence(
        predicate_ea=0x1004,
        condition_code=5,
        predicate_stack_identity=(0x20, 4),
        stack_cell_identity=(0x70, 4),
        taken_state_constant=0x22,
        fallthrough_state_constant=0x11,
        source_store_ea=0x1204,
        canonical_stack_cell_identity=(0x40, 4),
        canonical_predicate_stack_identity=(0x18, 4),
        predicate_block_ea=0x1000,
        taken_arm_entry_ea=0x1200,
        fallthrough_arm_entry_ea=0x1100,
        conditional_tail_ea=0x1008,
    )

    choices = transition.recognize_preopt_stack_carried_state_choices(
        (_cut(transition, block_ea=0x1300, tail_ea=0x1308),),
        blocks_by_ea=blocks,
        entry_bridge_evidence=(evidence,),
    )

    assert choices == (
        transition.PreoptConditionalStateChoice(
            consumer_tail_ea=0x1308,
            predicate_block_ea=0x1000,
            predicate_ea=0x1008,
            state_register=20,
            taken_state=0x22,
            fallthrough_state=0x11,
            resolver_kind="preopt_stack_carried_state_choice",
            source_owner=ports.PreoptBoundaryEndpointOwner.LIVE,
            logical_source_anchor_ea=0x1204,
            predicate_ida_stkoff=0x18,
            predicate_size=4,
            condition_code=5,
        ),
    )


def test_builds_external_live_entry_source_fact_from_proven_topology():
    from d810.analyses.control_flow.residual_entry_bridge import (
        EntryBridgeEvidence,
    )

    _ports, capture, transition = _modules()
    evidence = EntryBridgeEvidence(
        predicate_ea=0x1004,
        condition_code=5,
        predicate_stack_identity=(0x20, 4),
        stack_cell_identity=(0x70, 4),
        taken_state_constant=0x22,
        fallthrough_state_constant=0x11,
        source_store_ea=0x1204,
        canonical_stack_cell_identity=(0x40, 4),
        predicate_block_ea=0x1000,
        taken_arm_entry_ea=0x1200,
        fallthrough_arm_entry_ea=0x1100,
        conditional_tail_ea=0x1008,
    )

    fact = transition.preopt_entry_bridge_source_fact(evidence)

    assert fact == capture.PreoptPortBlockFact(
        start_ea=0x1000,
        end_ea=0x1009,
        instruction_eas=(0x1008,),
        successor_eas=(0x1200, 0x1100),
        successors_complete=True,
        has_side_effects=False,
        tail_ea=0x1008,
        taken_successor_ea=0x1200,
        fallthrough_successor_ea=0x1100,
        tail_kind=capture.PreoptPortTailKind.CONDITIONAL,
    )


def test_external_entry_source_fact_abstains_without_complete_topology():
    from d810.analyses.control_flow.residual_entry_bridge import (
        EntryBridgeEvidence,
    )

    _ports, _capture, transition = _modules()
    evidence = EntryBridgeEvidence(
        predicate_ea=0x1008,
        condition_code=5,
        predicate_stack_identity=(0x20, 4),
        stack_cell_identity=(0x70, 4),
        taken_state_constant=0x22,
        fallthrough_state_constant=0x11,
        source_store_ea=0x1204,
    )

    assert transition.preopt_entry_bridge_source_fact(evidence) is None


def test_external_entry_source_fact_abstains_without_conditional_tail():
    from d810.analyses.control_flow.residual_entry_bridge import (
        EntryBridgeEvidence,
    )

    _ports, _capture, transition = _modules()
    evidence = EntryBridgeEvidence(
        predicate_ea=0x1004,
        condition_code=5,
        predicate_stack_identity=(0x20, 4),
        stack_cell_identity=(0x70, 4),
        taken_state_constant=0x22,
        fallthrough_state_constant=0x11,
        source_store_ea=0x1204,
        canonical_stack_cell_identity=(0x40, 4),
        predicate_block_ea=0x1000,
        taken_arm_entry_ea=0x1200,
        fallthrough_arm_entry_ea=0x1100,
    )

    assert transition.preopt_entry_bridge_source_fact(evidence) is None


def test_abstains_when_entry_evidence_cell_does_not_reach_state_register():
    from d810.analyses.control_flow.residual_entry_bridge import (
        EntryBridgeEvidence,
    )

    _ports, capture, transition = _modules()
    blocks = {
        0x1000: _fact(
            capture,
            0x1000,
            successors=(0x1200, 0x1100),
            extra_instruction_eas=(0x1004,),
            tail_ea=0x1008,
            taken_successor_ea=0x1200,
            fallthrough_successor_ea=0x1100,
            tail_kind="CONDITIONAL",
        ),
        0x1100: _fact(capture, 0x1100, successors=(0x1200,)),
        0x1200: _fact(
            capture,
            0x1200,
            stack_stores=((0x70, 4, 8, 0x1204),),
        ),
        0x1300: _fact(
            capture,
            0x1300,
            stack_loads=((20, 0x74, 4, 0x1304),),
            tail_ea=0x1308,
        ),
    }
    evidence = EntryBridgeEvidence(
        predicate_ea=0x1004,
        condition_code=5,
        predicate_stack_identity=(0x20, 4),
        stack_cell_identity=(0x70, 4),
        taken_state_constant=0x22,
        fallthrough_state_constant=0x11,
        source_store_ea=0x1204,
    )

    choices = transition.recognize_preopt_stack_carried_state_choices(
        (_cut(transition, block_ea=0x1300, tail_ea=0x1308),),
        blocks_by_ea=blocks,
        entry_bridge_evidence=(evidence,),
    )

    assert choices == ()


def test_abstains_when_a_state_has_no_handler_target():
    ports, capture, transition = _modules()
    blocks = {
        0x1000: _fact(
            capture,
            0x1000,
            successors=(0x1200,),
            constants=((20, 0x11, 0x1004),),
        ),
        0x1200: _fact(capture, 0x1200, tail_ea=0x1208),
    }

    result = _plan(
        transition,
        capture,
        blocks=blocks,
        state_handlers={},
    )

    assert result.direct == ()
    assert result.abstentions[0].source_ea == 0x1004
    assert result.abstentions[0].reason is (
        ports.PreoptBoundaryPortAbstentionReason.MISSING_STATE_HANDLER
    )


def test_abstains_when_a_state_has_ambiguous_handler_targets():
    ports, capture, transition = _modules()
    blocks = {
        0x1000: _fact(
            capture,
            0x1000,
            successors=(0x1200,),
            constants=((20, 0x11, 0x1004),),
        ),
        0x1200: _fact(capture, 0x1200, tail_ea=0x1208),
    }

    result = _plan(
        transition,
        capture,
        blocks=blocks,
        state_handlers={0x11: (0x4000, 0x5000)},
    )

    assert result.direct == ()
    assert result.abstentions[0].reason is (
        ports.PreoptBoundaryPortAbstentionReason.AMBIGUOUS_STATE_HANDLER
    )


def test_abstains_on_a_nonconstant_reaching_state_definition():
    ports, capture, transition = _modules()
    blocks = {
        0x1000: _fact(
            capture,
            0x1000,
            successors=(0x1200,),
            writes=((20, 0x1004),),
        ),
        0x1200: _fact(capture, 0x1200, tail_ea=0x1208),
    }

    result = _plan(
        transition,
        capture,
        blocks=blocks,
        state_handlers={0x11: (0x4000,)},
    )

    assert result.direct == ()
    assert result.abstentions[0].source_ea == 0x1004
    assert result.abstentions[0].reason is (
        ports.PreoptBoundaryPortAbstentionReason.UNRESOLVED_STATE_DEFINITION
    )


def test_exact_duplicate_cuts_collapse_but_conflicting_source_facts_abstain():
    ports, capture, transition = _modules()
    duplicate_blocks = {
        0x1000: _fact(
            capture,
            0x1000,
            successors=(0x1200,),
            constants=((20, 0x11, 0x1004),),
        ),
        0x1200: _fact(capture, 0x1200, tail_ea=0x1208),
    }
    cut = _cut(transition)

    duplicate_result = _plan(
        transition,
        capture,
        blocks=duplicate_blocks,
        state_handlers={0x11: (0x4000,)},
        cuts=(cut, cut),
    )

    assert len(duplicate_result.direct) == 1
    assert duplicate_result.abstentions == ()

    conflicting_blocks = {
        0x1000: _fact(
            capture,
            0x1000,
            successors=(0x1200,),
            constants=((20, 0x11, 0x1004), (20, 0x22, 0x1004)),
        ),
        0x1200: _fact(capture, 0x1200, tail_ea=0x1208),
    }
    conflict_result = _plan(
        transition,
        capture,
        blocks=conflicting_blocks,
        state_handlers={0x11: (0x4000,), 0x22: (0x5000,)},
    )

    assert conflict_result.direct == ()
    assert conflict_result.abstentions[0].reason is (
        ports.PreoptBoundaryPortAbstentionReason.CONFLICTING_SOURCE
    )


def test_prefers_proven_payload_handler_over_live_equality_router():
    _ports, capture, transition = _modules()
    state = 0xFA72F85A
    router_ea = 0x40C3A0
    payload_ea = 0x40B08B
    blocks = {
        0x1000: _fact(
            capture,
            0x1000,
            successors=(0x1200,),
            constants=((20, state, 0x1004),),
        ),
        0x1200: _fact(capture, 0x1200, tail_ea=0x1208),
        router_ea: _fact(capture, router_ea, successors=(router_ea + 0x10,)),
        router_ea + 0x10: _fact(capture, router_ea + 0x10),
    }

    result = transition.plan_preopt_state_transition_boundary_ports(
        (_cut(transition),),
        blocks_by_ea=blocks,
        state_handler_eas={state: (router_ea,)},
        state_payload_handler_eas={state: (payload_ea,)},
        imported_block_ranges={
            0x1000: (0x1000, 0x1010),
            0x1200: (0x1200, 0x1210),
        },
        live_native_eas=frozenset({router_ea, router_ea + 0x10, payload_ea}),
    )

    assert result.abstentions == ()
    assert tuple(row.target_ea for row in result.direct) == (payload_ea,)


def test_falls_back_to_equality_router_when_payload_state_is_absent():
    _ports, capture, transition = _modules()
    state = 0x11
    router_ea = 0x4000
    blocks = {
        0x1000: _fact(
            capture,
            0x1000,
            successors=(0x1200,),
            constants=((20, state, 0x1004),),
        ),
        0x1200: _fact(capture, 0x1200, tail_ea=0x1208),
    }

    result = transition.plan_preopt_state_transition_boundary_ports(
        (_cut(transition),),
        blocks_by_ea=blocks,
        state_handler_eas={state: (router_ea,)},
        state_payload_handler_eas={0x22: (0x5000,)},
        imported_block_ranges={
            0x1000: (0x1000, 0x1010),
            0x1200: (0x1200, 0x1210),
        },
        live_native_eas=frozenset({router_ea}),
    )

    assert result.abstentions == ()
    assert tuple(row.target_ea for row in result.direct) == (router_ea,)


def test_abstains_when_payload_state_has_no_handler():
    ports, capture, transition = _modules()
    state = 0x11
    blocks = {
        0x1000: _fact(
            capture,
            0x1000,
            successors=(0x1200,),
            constants=((20, state, 0x1004),),
        ),
        0x1200: _fact(capture, 0x1200, tail_ea=0x1208),
    }

    result = transition.plan_preopt_state_transition_boundary_ports(
        (_cut(transition),),
        blocks_by_ea=blocks,
        state_handler_eas={state: (0x4000,)},
        state_payload_handler_eas={state: ()},
        imported_block_ranges={
            0x1000: (0x1000, 0x1010),
            0x1200: (0x1200, 0x1210),
        },
        live_native_eas=frozenset({0x4000}),
    )

    assert result.direct == ()
    assert result.abstentions[0].reason is (
        ports.PreoptBoundaryPortAbstentionReason.MISSING_STATE_HANDLER
    )


def test_abstains_when_payload_state_has_multiple_handlers():
    ports, capture, transition = _modules()
    state = 0x11
    blocks = {
        0x1000: _fact(
            capture,
            0x1000,
            successors=(0x1200,),
            constants=((20, state, 0x1004),),
        ),
        0x1200: _fact(capture, 0x1200, tail_ea=0x1208),
    }

    result = transition.plan_preopt_state_transition_boundary_ports(
        (_cut(transition),),
        blocks_by_ea=blocks,
        state_handler_eas={state: (0x4000,)},
        state_payload_handler_eas={state: (0x5000, 0x6000)},
        imported_block_ranges={
            0x1000: (0x1000, 0x1010),
            0x1200: (0x1200, 0x1210),
        },
        live_native_eas=frozenset({0x4000, 0x5000, 0x6000}),
    )

    assert result.direct == ()
    assert result.abstentions[0].reason is (
        ports.PreoptBoundaryPortAbstentionReason.AMBIGUOUS_STATE_HANDLER
    )
