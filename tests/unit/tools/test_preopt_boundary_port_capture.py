from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from d810.analyses.control_flow.materialized_indirect_transfer import (
    MaterializedIndirectTransfer,
)
from d810.analyses.control_flow.detached_handler_island import (
    DetachedSnippetBoundaryPortOwner,
    DetachedSnippetConditionalBoundaryPort,
)


SCRIPT_DIR = (
    Path(__file__).resolve().parents[3]
    / "tools"
    / "scripts"
    / "rhad_investigation"
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
        "preopt_boundary_port_capture_test",
        "preopt_boundary_port_capture.py",
    )
    return ports, capture


def _direct_plan(
    ports,
    *,
    source=0x1000,
    write=0x1008,
    target=0x4000,
    state=0x2100AFDD,
):
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=write,
        source_block_ea=source,
        materialized_anchor_eas=(),
        target_eas=(target,),
        selector_state_var_reg=20,
        selector_state_constant=state,
        resolver_kind="residual_state_route_evidence",
    )
    return ports.plan_preopt_resolver_boundary_ports(
        (transfer,),
        imported_block_ranges={
            source: (source, source + 0x10),
            target: (target, target + 0x10),
        },
        live_native_eas=frozenset(),
    )


def _fact(
    capture,
    start,
    *,
    instructions=(),
    successors=(),
    successors_complete=True,
    register_constant_writes=(),
    register_write_eas=(),
    has_synthetic_function_exit_successor=False,
    has_side_effects=False,
    tail=None,
    taken_successor=None,
    fallthrough_successor=None,
    kind="OTHER",
):
    normalized_constant_writes = tuple(register_constant_writes)
    if not normalized_constant_writes and 0x1008 in instructions:
        normalized_constant_writes = ((20, 0x2100AFDD, 0x1008),)
    return capture.PreoptPortBlockFact(
        start_ea=start,
        end_ea=start + 0x10,
        instruction_eas=tuple(instructions),
        successor_eas=tuple(successors),
        successors_complete=successors_complete,
        register_constant_writes=normalized_constant_writes,
        register_write_eas=(
            tuple(register_write_eas)
            or tuple(
                (register, write_ea)
                for register, _constant, write_ea in normalized_constant_writes
            )
        ),
        has_synthetic_function_exit_successor=(
            has_synthetic_function_exit_successor
        ),
        has_side_effects=has_side_effects,
        tail_ea=tail,
        taken_successor_ea=taken_successor,
        fallthrough_successor_ea=fallthrough_successor,
        tail_kind=capture.PreoptPortTailKind[kind],
    )


def test_canonicalizes_snippet_stack_offset_with_live_return_address_size():
    _ports, capture = _modules()

    assert capture.canonical_snippet_stack_offset(0x44, 4) == 0x40


def test_rejects_snippet_stack_offset_inside_return_address():
    _ports, capture = _modules()

    try:
        capture.canonical_snippet_stack_offset(2, 4)
    except ValueError as exc:
        assert "return address" in str(exc)
    else:
        raise AssertionError("expected an invalid snippet stack offset")


def test_preserves_explicit_live_owner_when_endpoint_is_also_imported():
    ports, capture = _modules()

    owner = capture.classify_captured_endpoint_owner(
        0x1000,
        imported_block_eas=frozenset({0x1000}),
        live_native_eas=frozenset({0x1000}),
        preferred_owner=ports.PreoptBoundaryEndpointOwner.LIVE,
    )

    assert owner is ports.PreoptBoundaryEndpointOwner.LIVE


def test_rejects_explicit_live_owner_when_endpoint_is_not_live():
    ports, capture = _modules()

    owner = capture.classify_captured_endpoint_owner(
        0x1000,
        imported_block_eas=frozenset({0x1000}),
        live_native_eas=frozenset(),
        preferred_owner=ports.PreoptBoundaryEndpointOwner.LIVE,
    )

    assert owner is None


def test_selects_one_owner_binding_when_source_and_endpoint_do_not_overlap():
    ports, capture = _modules()
    request = ports.PreoptDirectBoundaryPort(
        source_block_ea=0x1000,
        source_instruction_ea=0x1008,
        target_ea=0x4000,
        state_register=20,
        state_constant=0x2100AFDD,
        source_owner=ports.PreoptBoundaryEndpointOwner.LIVE,
        target_owner=ports.PreoptBoundaryEndpointOwner.IMPORTED,
        resolver_kind="state_write",
    )

    assert capture.select_captured_direct_owner_bindings(
        request,
        endpoint_ea=0x1100,
        imported_block_eas=frozenset({0x1100}),
        live_native_eas=frozenset({0x1000}),
    ) == (
        capture.PreoptDirectOwnerBinding(
            source_owner=ports.PreoptBoundaryEndpointOwner.LIVE,
            endpoint_owner=ports.PreoptBoundaryEndpointOwner.IMPORTED,
        ),
    )


def test_selects_coherent_imported_and_live_bindings_for_duplicate_endpoint():
    ports, capture = _modules()
    request = ports.PreoptDirectBoundaryPort(
        source_block_ea=0x1000,
        source_instruction_ea=0x1008,
        target_ea=0x4000,
        state_register=20,
        state_constant=0x2100AFDD,
        source_owner=ports.PreoptBoundaryEndpointOwner.IMPORTED,
        target_owner=ports.PreoptBoundaryEndpointOwner.IMPORTED,
        resolver_kind="state_write",
    )

    assert capture.select_captured_direct_owner_bindings(
        request,
        endpoint_ea=0x1100,
        old_successor_eas=(0x1200,),
        imported_block_eas=frozenset({0x1000, 0x1100, 0x1200}),
        live_native_eas=frozenset({0x1000, 0x1100, 0x1200}),
    ) == (
        capture.PreoptDirectOwnerBinding(
            source_owner=ports.PreoptBoundaryEndpointOwner.IMPORTED,
            endpoint_owner=ports.PreoptBoundaryEndpointOwner.IMPORTED,
            old_successor_owners=(
                ports.PreoptBoundaryEndpointOwner.IMPORTED,
            ),
        ),
        capture.PreoptDirectOwnerBinding(
            source_owner=ports.PreoptBoundaryEndpointOwner.LIVE,
            endpoint_owner=ports.PreoptBoundaryEndpointOwner.LIVE,
            old_successor_owners=(ports.PreoptBoundaryEndpointOwner.LIVE,),
        ),
    )


def test_does_not_invent_live_binding_when_only_endpoint_is_live():
    ports, capture = _modules()
    request = ports.PreoptDirectBoundaryPort(
        source_block_ea=0x1000,
        source_instruction_ea=0x1008,
        target_ea=0x4000,
        state_register=20,
        state_constant=0x2100AFDD,
        source_owner=ports.PreoptBoundaryEndpointOwner.IMPORTED,
        target_owner=ports.PreoptBoundaryEndpointOwner.IMPORTED,
        resolver_kind="state_write",
    )

    assert capture.select_captured_direct_owner_bindings(
        request,
        endpoint_ea=0x1100,
        imported_block_eas=frozenset({0x1000, 0x1100}),
        live_native_eas=frozenset({0x1100}),
    ) == (
        capture.PreoptDirectOwnerBinding(
            source_owner=ports.PreoptBoundaryEndpointOwner.IMPORTED,
            endpoint_owner=ports.PreoptBoundaryEndpointOwner.IMPORTED,
        ),
    )


def test_keeps_live_duplicate_when_its_old_successor_was_pruned():
    ports, capture = _modules()
    request = ports.PreoptDirectBoundaryPort(
        source_block_ea=0x1000,
        source_instruction_ea=0x1008,
        target_ea=0x4000,
        state_register=20,
        state_constant=0x2100AFDD,
        source_owner=ports.PreoptBoundaryEndpointOwner.IMPORTED,
        target_owner=ports.PreoptBoundaryEndpointOwner.IMPORTED,
        resolver_kind="state_write",
    )

    assert capture.select_captured_direct_owner_bindings(
        request,
        endpoint_ea=0x1100,
        old_successor_eas=(0x1200,),
        imported_block_eas=frozenset({0x1000, 0x1100, 0x1200}),
        live_native_eas=frozenset({0x1000, 0x1100}),
    ) == (
        capture.PreoptDirectOwnerBinding(
            source_owner=ports.PreoptBoundaryEndpointOwner.IMPORTED,
            endpoint_owner=ports.PreoptBoundaryEndpointOwner.IMPORTED,
            old_successor_owners=(
                ports.PreoptBoundaryEndpointOwner.IMPORTED,
            ),
        ),
        capture.PreoptDirectOwnerBinding(
            source_owner=ports.PreoptBoundaryEndpointOwner.LIVE,
            endpoint_owner=ports.PreoptBoundaryEndpointOwner.LIVE,
            old_successor_owners=(ports.PreoptBoundaryEndpointOwner.LIVE,),
        ),
    )

def test_excludes_live_direct_endpoint_bypassed_by_a_replacement_conditional():
    ports, capture = _modules()
    direct_request = ports.PreoptDirectBoundaryPort(
        source_block_ea=0x1100,
        source_instruction_ea=0x1110,
        target_ea=0x4000,
        state_register=20,
        state_constant=0xABCD,
        source_owner=ports.PreoptBoundaryEndpointOwner.LIVE,
        target_owner=ports.PreoptBoundaryEndpointOwner.IMPORTED,
        resolver_kind="state_write",
    )
    conditional_request = ports.PreoptConditionalBoundaryPort(
        source_block_ea=0x1000,
        predicate_ea=0x1008,
        taken_target_ea=0x5000,
        fallthrough_target_ea=0x6000,
        state_register=20,
        taken_state=0x11,
        fallthrough_state=0x22,
        source_owner=ports.PreoptBoundaryEndpointOwner.LIVE,
        taken_target_owner=ports.PreoptBoundaryEndpointOwner.IMPORTED,
        fallthrough_target_owner=ports.PreoptBoundaryEndpointOwner.IMPORTED,
        resolver_kind="conditional_state_choice",
    )
    captured = capture.CapturedPreoptBoundaryPorts(
        direct=(
            capture.CapturedDirectBoundaryPort(
                request=direct_request,
                corridor_block_eas=(0x1100,),
                frontier_edges=(),
                delivery_mode=capture.PreoptPortDeliveryMode.TERMINAL_GOTO,
                terminal_endpoint_block_eas=(0x1100,),
            ),
        ),
        conditional=(
            capture.CapturedConditionalBoundaryPort(
                request=conditional_request,
                source_block_ea=0x1000,
                predicate_ea=0x1008,
                old_taken_target_ea=0x1100,
                old_fallthrough_target_ea=0x1200,
                taken_target_ea=0x5000,
                fallthrough_target_ea=0x6000,
            ),
        ),
        abstentions=(),
    )

    result = capture.exclude_direct_endpoints_superseded_by_conditionals(
        captured
    )

    assert result.direct == ()
    assert result.conditional == captured.conditional


def test_excludes_direct_port_that_shares_a_physical_conditional_source():
    ports, capture = _modules()
    direct_request = ports.PreoptDirectBoundaryPort(
        source_block_ea=0x1000,
        source_instruction_ea=0x1004,
        target_ea=0x4000,
        state_register=20,
        state_constant=0x11,
        source_owner=ports.PreoptBoundaryEndpointOwner.LIVE,
        target_owner=ports.PreoptBoundaryEndpointOwner.LIVE,
        resolver_kind="preopt_state_transition",
    )
    conditional_request = ports.PreoptConditionalBoundaryPort(
        source_block_ea=0x0FF0,
        predicate_ea=0x1008,
        taken_target_ea=0x5000,
        fallthrough_target_ea=0x6000,
        state_register=20,
        taken_state=0x22,
        fallthrough_state=0x33,
        source_owner=ports.PreoptBoundaryEndpointOwner.LIVE,
        taken_target_owner=ports.PreoptBoundaryEndpointOwner.IMPORTED,
        fallthrough_target_owner=ports.PreoptBoundaryEndpointOwner.IMPORTED,
        resolver_kind="conditional_state_choice",
    )
    captured = capture.CapturedPreoptBoundaryPorts(
        direct=(
            capture.CapturedDirectBoundaryPort(
                request=direct_request,
                corridor_block_eas=(0x1000,),
                frontier_edges=(),
                delivery_mode=capture.PreoptPortDeliveryMode.TERMINAL_GOTO,
                terminal_endpoint_block_eas=(0x1000,),
            ),
        ),
        conditional=(
            capture.CapturedConditionalBoundaryPort(
                request=conditional_request,
                source_block_ea=0x1000,
                predicate_ea=0x1008,
                old_taken_target_ea=0x1100,
                old_fallthrough_target_ea=0x1200,
                taken_target_ea=0x5000,
                fallthrough_target_ea=0x6000,
            ),
        ),
        abstentions=(),
    )

    result = capture.exclude_direct_endpoints_superseded_by_conditionals(
        captured
    )

    assert result.direct == ()
    assert result.conditional == captured.conditional


def test_captures_unique_corridor_and_stops_before_dispatcher():
    ports, capture = _modules()
    plan = _direct_plan(ports)
    facts = {
        0x1000: _fact(
            capture,
            0x1000,
            instructions=(0x1008,),
            successors=(0x1100,),
            tail=0x100C,
        ),
        0x1100: _fact(
            capture,
            0x1100,
            instructions=(0x1104,),
            successors=(0x2000,),
            tail=0x1104,
            kind="GOTO",
        ),
        0x2000: _fact(capture, 0x2000, instructions=(0x2000,)),
    }

    result = capture.capture_preopt_boundary_ports(
        plan,
        blocks_by_ea=facts,
        dispatcher_entry_eas=frozenset({0x2000}),
    )

    (direct,) = result.direct
    assert direct.corridor_block_eas == (0x1000, 0x1100)
    assert direct.frontier_edges == (
        capture.PreoptPortBoundaryEdge(0x1100, 0x2000),
    )
    assert direct.delivery_mode is capture.PreoptPortDeliveryMode.REDIRECT_EDGE
    assert result.abstentions == ()


def test_captures_a_live_owned_source_from_the_live_preopt_graph():
    ports, capture = _modules()
    request = ports.PreoptDirectBoundaryPort(
        source_block_ea=0x1000,
        source_instruction_ea=0x1008,
        target_ea=0x4000,
        state_register=20,
        state_constant=0x2100AFDD,
        source_owner=ports.PreoptBoundaryEndpointOwner.LIVE,
        target_owner=ports.PreoptBoundaryEndpointOwner.IMPORTED,
        resolver_kind="live_state_transition",
    )
    plan = ports.PreoptBoundaryPortPlan(
        direct=(request,),
        conditional=(),
        abstentions=(),
    )
    imported_facts = {
        0x4000: _fact(capture, 0x4000, instructions=(0x4000,)),
    }
    live_facts = {
        0x1000: _fact(
            capture,
            0x1000,
            instructions=(0x1008,),
            successors=(0x1100,),
            register_constant_writes=((20, 0x2100AFDD, 0x1008),),
            tail=0x100C,
        ),
        0x1100: _fact(
            capture,
            0x1100,
            instructions=(0x1104,),
            successors=(0x2000,),
            tail=0x1104,
            kind="GOTO",
        ),
    }

    result = capture.capture_preopt_boundary_ports(
        plan,
        blocks_by_ea=imported_facts,
        live_blocks_by_ea=live_facts,
        dispatcher_entry_eas=frozenset({0x2000}),
    )

    (direct,) = result.direct
    assert direct.corridor_block_eas == (0x1000, 0x1100)
    assert direct.frontier_edges == (
        capture.PreoptPortBoundaryEdge(0x1100, 0x2000),
    )
    assert result.abstentions == ()


def test_live_facts_do_not_override_an_imported_owned_source():
    ports, capture = _modules()
    plan = _direct_plan(ports)
    imported_facts = {
        0x1000: _fact(
            capture,
            0x1000,
            instructions=(0x1008,),
            successors=(0x2000,),
            register_constant_writes=((20, 0x2100AFDD, 0x1008),),
            tail=0x100C,
        ),
    }
    live_facts = {
        0x1000: _fact(
            capture,
            0x1000,
            instructions=(0x1004,),
            successors=(0x3000,),
            tail=0x1004,
        ),
    }

    result = capture.capture_preopt_boundary_ports(
        plan,
        blocks_by_ea=imported_facts,
        live_blocks_by_ea=live_facts,
        dispatcher_entry_eas=frozenset({0x2000}),
    )

    (direct,) = result.direct
    assert direct.frontier_edges == (
        capture.PreoptPortBoundaryEdge(0x1000, 0x2000),
    )
    assert result.abstentions == ()


def test_abstains_from_direct_rewrite_when_live_conditional_arms_were_pruned():
    ports, capture = _modules()
    request = ports.PreoptDirectBoundaryPort(
        source_block_ea=0x1000,
        source_instruction_ea=0x1008,
        target_ea=0x4000,
        state_register=20,
        state_constant=0x2100AFDD,
        source_owner=ports.PreoptBoundaryEndpointOwner.LIVE,
        target_owner=ports.PreoptBoundaryEndpointOwner.IMPORTED,
        resolver_kind="live_state_transition",
    )
    plan = ports.PreoptBoundaryPortPlan((request,), (), ())
    live_facts = {
        0x1000: _fact(
            capture,
            0x1000,
            instructions=(0x1008, 0x100C),
            register_constant_writes=((20, 0x2100AFDD, 0x1008),),
            tail=0x100C,
            kind="CONDITIONAL",
        ),
    }

    result = capture.capture_preopt_boundary_ports(
        plan,
        blocks_by_ea={
            0x4000: _fact(capture, 0x4000, instructions=(0x4000,)),
        },
        live_blocks_by_ea=live_facts,
        dispatcher_entry_eas=frozenset({0x2000}),
    )

    assert result.direct == ()
    assert result.abstentions == (
        capture.PreoptPortCaptureAbstention(
            source_ea=0x1008,
            reason=(
                capture.PreoptPortCaptureAbstentionReason.NO_SOURCE_SENSITIVE_FRONTIER
            ),
            block_ea=0x1000,
        ),
    )


def test_allows_direct_rewrite_for_proven_pruned_router_conditional():
    ports, capture = _modules()
    request = ports.PreoptDirectBoundaryPort(
        source_block_ea=0x1000,
        source_instruction_ea=0x1008,
        target_ea=0x4000,
        state_register=20,
        state_constant=0x2100AFDD,
        source_owner=ports.PreoptBoundaryEndpointOwner.LIVE,
        target_owner=ports.PreoptBoundaryEndpointOwner.IMPORTED,
        resolver_kind="live_state_transition",
    )
    live_facts = {
        0x1000: _fact(
            capture,
            0x1000,
            instructions=(0x1008, 0x100C),
            register_constant_writes=((20, 0x2100AFDD, 0x1008),),
            tail=0x100C,
            kind="CONDITIONAL",
        ),
    }

    result = capture.capture_preopt_boundary_ports(
        ports.PreoptBoundaryPortPlan((request,), (), ()),
        blocks_by_ea={
            0x4000: _fact(capture, 0x4000, instructions=(0x4000,)),
        },
        live_blocks_by_ea=live_facts,
        dispatcher_entry_eas=frozenset({0x2000}),
        proven_pruned_conditional_direct_source_eas=frozenset({0x1000}),
    )

    (direct,) = result.direct
    assert direct.delivery_mode is capture.PreoptPortDeliveryMode.TERMINAL_GOTO
    assert direct.terminal_endpoint_block_eas == (0x1000,)
    assert result.abstentions == ()


def test_does_not_infer_a_logical_transfer_for_an_imported_zero_way_source():
    ports, capture = _modules()
    plan = _direct_plan(ports)
    imported_facts = {
        0x1000: _fact(
            capture,
            0x1000,
            instructions=(0x1008, 0x100C),
            register_constant_writes=((20, 0x2100AFDD, 0x1008),),
            tail=0x100C,
            kind="CONDITIONAL",
        ),
    }

    result = capture.capture_preopt_boundary_ports(
        plan,
        blocks_by_ea=imported_facts,
        dispatcher_entry_eas=frozenset({0x2000}),
    )

    assert result.direct == ()
    assert result.abstentions[0].reason is (
        capture.PreoptPortCaptureAbstentionReason.NO_SOURCE_SENSITIVE_FRONTIER
    )


def test_captures_a_live_conditional_when_hexrays_pruned_both_old_arms():
    ports, capture = _modules()
    request = ports.PreoptConditionalBoundaryPort(
        source_block_ea=0x1000,
        predicate_ea=0x1008,
        taken_target_ea=0x4000,
        fallthrough_target_ea=0x5000,
        state_register=20,
        taken_state=0x1111,
        fallthrough_state=0x2222,
        source_owner=ports.PreoptBoundaryEndpointOwner.LIVE,
        taken_target_owner=ports.PreoptBoundaryEndpointOwner.IMPORTED,
        fallthrough_target_owner=ports.PreoptBoundaryEndpointOwner.IMPORTED,
        resolver_kind="live_conditional_state_transition",
    )
    live_facts = {
        0x1000: _fact(
            capture,
            0x1000,
            instructions=(0x1004, 0x1008),
            tail=0x1008,
            kind="CONDITIONAL",
        ),
    }

    result = capture.capture_preopt_boundary_ports(
        ports.PreoptBoundaryPortPlan((), (request,), ()),
        blocks_by_ea={},
        live_blocks_by_ea=live_facts,
        dispatcher_entry_eas=frozenset(),
    )

    (conditional,) = result.conditional
    assert conditional.old_taken_target_ea is None
    assert conditional.old_fallthrough_target_ea is None
    assert conditional.taken_target_ea == 0x4000
    assert conditional.fallthrough_target_ea == 0x5000
    assert result.abstentions == ()


def test_indexes_only_instruction_eas_present_in_captured_port_facts():
    _ports, capture = _modules()
    facts = {
        0x1000: _fact(
            capture,
            0x1000,
            instructions=(0x1000, 0x1004),
        ),
        0x2000: _fact(
            capture,
            0x2000,
            instructions=(0x2000,),
        ),
    }

    assert capture.captured_port_instruction_eas(facts) == frozenset(
        {0x1000, 0x1004, 0x2000}
    )


def test_semantic_delta_owns_partial_and_fully_missing_blocks_only():
    _ports, capture = _modules()
    facts = {
        0x1000: capture.PreoptPortBlockFact(
            0x1000,
            0x1010,
            instruction_eas=(0x1000, 0x1004),
        ),
        0x2000: capture.PreoptPortBlockFact(
            0x2000,
            0x2010,
            instruction_eas=(0x2000, 0x2004),
        ),
        0x3000: capture.PreoptPortBlockFact(
            0x3000,
            0x3010,
        ),
    }

    assert capture.semantic_delta_block_entry_eas(
        facts,
        live_native_eas=(0x1000, 0x2000, 0x2004),
    ) == frozenset({0x1000, 0x3000})


def test_semantic_delta_keeps_requested_transparent_root_for_owned_successor():
    _ports, capture = _modules()
    facts = {
        0x1000: capture.PreoptPortBlockFact(
            0x1000,
            0x1010,
            successor_eas=(0x1100,),
        ),
        0x1100: capture.PreoptPortBlockFact(
            0x1100,
            0x1110,
            instruction_eas=(0x1100,),
        ),
    }

    assert capture.semantic_delta_block_entry_eas(
        facts,
        live_native_eas=(0x1000,),
        requested_root_eas=(0x1000,),
    ) == frozenset({0x1000, 0x1100})


def test_preserves_call_at_the_terminal_corridor_endpoint():
    ports, capture = _modules()
    plan = _direct_plan(ports)
    facts = {
        0x1000: _fact(
            capture,
            0x1000,
            instructions=(0x1008,),
            successors=(0x2000,),
            tail=0x100C,
            kind="CALL",
        ),
        0x2000: _fact(capture, 0x2000, instructions=(0x2000,)),
    }

    result = capture.capture_preopt_boundary_ports(
        plan,
        blocks_by_ea=facts,
        dispatcher_entry_eas=frozenset({0x2000}),
    )

    (direct,) = result.direct
    assert direct.frontier_edges == (
        capture.PreoptPortBoundaryEdge(0x1000, 0x2000),
    )
    assert direct.delivery_mode is capture.PreoptPortDeliveryMode.PRESERVE_CALL


def test_restores_pruned_post_call_route_without_replacing_the_call():
    ports, capture = _modules()
    plan = ports.PreoptBoundaryPortPlan(
        direct=(
            ports.PreoptDirectBoundaryPort(
                source_block_ea=0x1000,
                source_instruction_ea=0x1040,
                target_ea=0x4000,
                state_register=20,
                state_constant=0x2100AFDD,
                source_owner=ports.PreoptBoundaryEndpointOwner.LIVE,
                target_owner=ports.PreoptBoundaryEndpointOwner.IMPORTED,
                resolver_kind="live_state_transition",
            ),
        ),
        conditional=(),
        abstentions=(),
    )
    facts = {
        0x1000: _fact(
            capture,
            0x1000,
            instructions=(0x1040, 0x1048),
            register_constant_writes=((20, 0x2100AFDD, 0x1040),),
            tail=0x1048,
            kind="CALL",
        ),
    }

    result = capture.capture_preopt_boundary_ports(
        plan,
        blocks_by_ea=facts,
        live_blocks_by_ea=facts,
        dispatcher_entry_eas=(),
    )

    assert result.abstentions == ()
    (direct,) = result.direct
    assert direct.corridor_block_eas == (0x1000,)
    assert direct.frontier_edges == ()
    assert direct.terminal_endpoint_block_eas == (0x1000,)
    assert direct.delivery_mode is capture.PreoptPortDeliveryMode.PRESERVE_CALL
    assert (
        capture.direct_endpoint_delivery_mode(
            direct,
            old_successor_eas=(),
        )
        is capture.PreoptPortDeliveryMode.PRESERVE_CALL
    )


def test_preserves_branch_and_redirects_only_its_dispatcher_frontier_arm():
    ports, capture = _modules()
    plan = _direct_plan(ports)
    facts = {
        0x1000: _fact(
            capture,
            0x1000,
            instructions=(0x1008,),
            successors=(0x1100, 0x2000),
            tail=0x100C,
            kind="CONDITIONAL",
        ),
        0x1100: _fact(
            capture,
            0x1100,
            instructions=(0x1104,),
            tail=0x1104,
            kind="RETURN",
        ),
    }

    result = capture.capture_preopt_boundary_ports(
        plan,
        blocks_by_ea=facts,
        dispatcher_entry_eas=frozenset({0x2000}),
    )

    (direct,) = result.direct
    assert direct.corridor_block_eas == (0x1000, 0x1100)
    assert direct.frontier_edges == (
        capture.PreoptPortBoundaryEdge(0x1000, 0x2000),
    )
    assert result.abstentions == ()


def test_preserves_a_synthetic_function_stop_arm_without_redirecting_it():
    ports, capture = _modules()
    plan = _direct_plan(ports)
    facts = {
        0x1000: _fact(
            capture,
            0x1000,
            instructions=(0x1008,),
            successors=(0x1100, 0x2000),
            kind="CONDITIONAL",
        ),
        0x1100: _fact(
            capture,
            0x1100,
            instructions=(0x1104,),
            tail=0x1104,
            kind="GOTO",
            has_synthetic_function_exit_successor=True,
        ),
    }

    result = capture.capture_preopt_boundary_ports(
        plan,
        blocks_by_ea=facts,
        dispatcher_entry_eas=frozenset({0x2000}),
    )

    (direct,) = result.direct
    assert direct.frontier_edges == (
        capture.PreoptPortBoundaryEdge(0x1000, 0x2000),
    )
    assert direct.terminal_endpoint_block_eas == ()


def test_stops_a_sibling_arm_at_another_proven_state_transition_source():
    ports, capture = _modules()
    first = _direct_plan(ports)
    second = _direct_plan(
        ports,
        source=0x1100,
        write=0x1104,
        target=0x5000,
    )
    plan = ports.PreoptBoundaryPortPlan(
        direct=first.direct + second.direct,
        conditional=(),
        abstentions=(),
    )
    facts = {
        0x1000: _fact(
            capture,
            0x1000,
            instructions=(0x1008,),
            successors=(0x1100, 0x2000),
            tail=0x100C,
            kind="CONDITIONAL",
        ),
        0x1100: _fact(
            capture,
            0x1100,
            instructions=(0x1104,),
            successors=(0x2000,),
            register_constant_writes=((20, 0x2100AFDD, 0x1104),),
        ),
    }

    result = capture.capture_preopt_boundary_ports(
        plan,
        blocks_by_ea=facts,
        dispatcher_entry_eas=frozenset({0x2000}),
    )

    first_capture = next(
        row for row in result.direct if row.request.source_block_ea == 0x1000
    )
    assert first_capture.corridor_block_eas == (0x1000,)
    assert first_capture.frontier_edges == (
        capture.PreoptPortBoundaryEdge(0x1000, 0x2000),
    )


def test_abstains_on_a_cycle_before_the_dispatcher():
    ports, capture = _modules()
    plan = _direct_plan(ports)
    facts = {
        0x1000: _fact(
            capture,
            0x1000,
            instructions=(0x1008,),
            successors=(0x1100, 0x2000),
            kind="CONDITIONAL",
        ),
        0x1100: _fact(
            capture,
            0x1100,
            instructions=(0x1104,),
            successors=(0x1000,),
        ),
    }

    result = capture.capture_preopt_boundary_ports(
        plan,
        blocks_by_ea=facts,
        dispatcher_entry_eas=frozenset({0x2000}),
    )

    (direct,) = result.direct
    assert direct.frontier_edges == (
        capture.PreoptPortBoundaryEdge(0x1000, 0x2000),
    )
    assert result.abstentions == ()


def test_stops_before_an_unlisted_later_literal_state_write():
    ports, capture = _modules()
    plan = _direct_plan(ports)
    facts = {
        0x1000: _fact(
            capture,
            0x1000,
            instructions=(0x1008,),
            successors=(0x1100, 0x2000),
            kind="CONDITIONAL",
        ),
        0x1100: _fact(
            capture,
            0x1100,
            instructions=(0x1104,),
            successors=(0x2000,),
            register_constant_writes=((20, 0x22, 0x1104),),
        ),
    }

    result = capture.capture_preopt_boundary_ports(
        plan,
        blocks_by_ea=facts,
        dispatcher_entry_eas=frozenset({0x2000}),
    )

    (direct,) = result.direct
    assert direct.corridor_block_eas == (0x1000,)
    assert direct.frontier_edges == (
        capture.PreoptPortBoundaryEdge(0x1000, 0x2000),
    )


def test_accepts_only_resolver_proven_indirect_as_a_terminal_frontier():
    ports, capture = _modules()
    plan = _direct_plan(ports)
    facts = {
        0x1000: _fact(
            capture,
            0x1000,
            instructions=(0x1008,),
            successors=(0x1100,),
        ),
        0x1100: _fact(
            capture,
            0x1100,
            instructions=(0x1108,),
            tail=0x1108,
            kind="INDIRECT",
        ),
    }

    result = capture.capture_preopt_boundary_ports(
        plan,
        blocks_by_ea=facts,
        dispatcher_entry_eas=frozenset({0x2000}),
        resolver_cut_instruction_eas=frozenset({0x1108}),
    )

    (direct,) = result.direct
    assert direct.frontier_edges == ()
    assert direct.terminal_endpoint_block_eas == (0x1100,)


def test_mixed_frontier_uses_terminal_goto_only_for_zero_way_endpoint():
    ports, capture = _modules()
    plan = _direct_plan(ports)
    facts = {
        0x1000: _fact(
            capture,
            0x1000,
            instructions=(0x1008,),
            successors=(0x1100, 0x1200),
        ),
        0x1100: _fact(
            capture,
            0x1100,
            instructions=(0x1104,),
            successors=(0x2000,),
        ),
        0x1200: _fact(
            capture,
            0x1200,
            instructions=(0x1208,),
            tail=0x1208,
            kind="INDIRECT",
        ),
    }

    result = capture.capture_preopt_boundary_ports(
        plan,
        blocks_by_ea=facts,
        dispatcher_entry_eas=frozenset({0x2000}),
        resolver_cut_instruction_eas=frozenset({0x1208}),
    )

    (direct,) = result.direct
    assert direct.frontier_edges == (
        capture.PreoptPortBoundaryEdge(0x1100, 0x2000),
    )
    assert direct.terminal_endpoint_block_eas == (0x1200,)
    assert capture.direct_endpoint_delivery_mode(
        direct,
        old_successor_eas=(0x2000,),
    ) is capture.PreoptPortDeliveryMode.REDIRECT_EDGE
    assert capture.direct_endpoint_delivery_mode(
        direct,
        old_successor_eas=(),
    ) is capture.PreoptPortDeliveryMode.TERMINAL_GOTO
    assert capture.state_transition_owned_endpoint_eas(result) == frozenset(
        {0x1100, 0x1200}
    )


def test_capture_owner_prefers_actual_imported_block_over_live_alias():
    ports, capture = _modules()

    assert capture.classify_captured_endpoint_owner(
        0x1200,
        imported_block_eas=frozenset({0x1200}),
        live_native_eas=frozenset({0x1200}),
    ) is ports.PreoptBoundaryEndpointOwner.IMPORTED


def test_shared_dispatcher_edge_with_two_reaching_writes_is_not_owned():
    ports, capture = _modules()
    first = _direct_plan(ports)
    second = _direct_plan(
        ports,
        source=0x1100,
        write=0x1108,
        target=0x5000,
        state=0x31,
    )
    plan = ports.PreoptBoundaryPortPlan(
        direct=first.direct + second.direct,
        conditional=(),
        abstentions=(),
    )
    facts = {
        0x1000: _fact(
            capture,
            0x1000,
            instructions=(0x1008,),
            successors=(0x1200,),
        ),
        0x1100: _fact(
            capture,
            0x1100,
            instructions=(0x1108,),
            successors=(0x1200,),
            register_constant_writes=((20, 0x31, 0x1108),),
        ),
        0x1200: _fact(
            capture,
            0x1200,
            instructions=(0x1204,),
            successors=(0x2000,),
        ),
    }

    result = capture.capture_preopt_boundary_ports(
        plan,
        blocks_by_ea=facts,
        dispatcher_entry_eas=frozenset({0x2000}),
    )

    assert result.direct == ()
    assert {
        row.reason for row in result.abstentions
    } == {capture.PreoptPortCaptureAbstentionReason.NO_SOURCE_SENSITIVE_FRONTIER}


def test_extends_router_cut_through_side_effect_free_resolver_source():
    ports, capture = _modules()
    plan = _direct_plan(ports)
    facts = {
        0x1000: _fact(
            capture,
            0x1000,
            instructions=(0x1008,),
            successors=(0x1500,),
        ),
        0x1500: _fact(
            capture,
            0x1500,
            instructions=(0x1504,),
            successors=(0x2000,),
            kind="GOTO",
        ),
        0x1100: _fact(
            capture,
            0x1100,
            instructions=(0x1108,),
            successors=(0x1500,),
            register_constant_writes=((20, 0x31, 0x1108),),
        ),
        0x2000: _fact(capture, 0x2000, instructions=(0x2000,)),
    }

    result = capture.capture_preopt_boundary_ports(
        plan,
        blocks_by_ea=facts,
        dispatcher_entry_eas=frozenset({0x2000}),
        resolver_targets_by_source_block_ea={0x1500: frozenset({0x2000})},
    )

    (direct,) = result.direct
    assert direct.frontier_edges == (
        capture.PreoptPortBoundaryEdge(0x1000, 0x1500),
    )


def test_excludes_imported_overlay_when_native_internal_edge_reaches_target():
    ports, capture = _modules()
    plan = _direct_plan(ports)
    facts = {
        0x1000: _fact(
            capture,
            0x1000,
            instructions=(0x1008,),
            successors=(0x2000,),
        ),
    }
    captured = capture.capture_preopt_boundary_ports(
        plan,
        blocks_by_ea=facts,
        dispatcher_entry_eas=frozenset({0x2000}),
    )

    result = capture.exclude_ports_satisfied_by_internal_edges(
        captured,
        proven_internal_edges=frozenset({(0x2000, 0x4000)}),
    )

    assert result.direct == ()
    assert result.conditional == captured.conditional
    assert result.abstentions == captured.abstentions


def test_keeps_overlay_when_internal_edge_does_not_reach_requested_target():
    ports, capture = _modules()
    plan = _direct_plan(ports)
    facts = {
        0x1000: _fact(
            capture,
            0x1000,
            instructions=(0x1008,),
            successors=(0x2000,),
        ),
    }
    captured = capture.capture_preopt_boundary_ports(
        plan,
        blocks_by_ea=facts,
        dispatcher_entry_eas=frozenset({0x2000}),
    )

    result = capture.exclude_ports_satisfied_by_internal_edges(
        captured,
        proven_internal_edges=frozenset({(0x2000, 0x5000)}),
    )

    assert result.direct == captured.direct


def test_does_not_bypass_resolver_source_with_side_effects():
    ports, capture = _modules()
    plan = _direct_plan(ports)
    facts = {
        0x1000: _fact(
            capture,
            0x1000,
            instructions=(0x1008,),
            successors=(0x1500,),
        ),
        0x1500: _fact(
            capture,
            0x1500,
            instructions=(0x1504,),
            successors=(0x2000,),
            has_side_effects=True,
        ),
        0x1100: _fact(
            capture,
            0x1100,
            instructions=(0x1108,),
            successors=(0x1500,),
            register_constant_writes=((20, 0x31, 0x1108),),
        ),
        0x2000: _fact(capture, 0x2000, instructions=(0x2000,)),
    }

    result = capture.capture_preopt_boundary_ports(
        plan,
        blocks_by_ea=facts,
        dispatcher_entry_eas=frozenset({0x2000}),
        resolver_targets_by_source_block_ea={0x1500: frozenset({0x2000})},
    )

    assert result.direct == ()
    assert result.abstentions[0].reason is (
        capture.PreoptPortCaptureAbstentionReason.NO_SOURCE_SENSITIVE_FRONTIER
    )


def test_abstains_when_a_corridor_successor_has_no_stable_ea_identity():
    ports, capture = _modules()
    plan = _direct_plan(ports)
    facts = {
        0x1000: _fact(
            capture,
            0x1000,
            instructions=(0x1008,),
            successors=(),
            successors_complete=False,
        ),
    }

    result = capture.capture_preopt_boundary_ports(
        plan,
        blocks_by_ea=facts,
        dispatcher_entry_eas=frozenset({0x2000}),
    )

    assert result.direct == ()
    assert result.abstentions[0].reason is (
        capture.PreoptPortCaptureAbstentionReason.MISSING_SUCCESSOR_IDENTITY
    )


def test_captures_conditional_only_when_predicate_is_the_closing_tail():
    ports, capture = _modules()
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x3008,
        source_block_ea=0x3000,
        materialized_anchor_eas=(),
        target_eas=(0x4000, 0x5000),
        condition_code=5,
        true_target_ea=0x4000,
        false_target_ea=0x5000,
        selector_state_var_reg=20,
        predicate_register=8,
        predicate_size=4,
        predicate_true_state=0x11,
        predicate_false_state=0x22,
        predicate_true_is_taken=True,
        resolver_kind="conditional_handler_bridge",
    )
    plan = ports.plan_preopt_resolver_boundary_ports(
        (transfer,),
        imported_block_ranges={
            0x3000: (0x3000, 0x3010),
            0x4000: (0x4000, 0x4010),
            0x5000: (0x5000, 0x5010),
        },
        live_native_eas=frozenset(),
    )
    fact = _fact(
        capture,
        0x3000,
        instructions=(0x3004, 0x3008),
        successors=(0x3200, 0x3100),
        tail=0x3008,
        taken_successor=0x3100,
        fallthrough_successor=0x3200,
        kind="CONDITIONAL",
    )

    result = capture.capture_preopt_boundary_ports(
        plan,
        blocks_by_ea={0x3000: fact},
        dispatcher_entry_eas=frozenset(),
    )

    (conditional,) = result.conditional
    assert conditional.source_block_ea == 0x3000
    assert conditional.predicate_ea == 0x3008
    assert conditional.old_taken_target_ea == 0x3100
    assert conditional.old_fallthrough_target_ea == 0x3200
    assert conditional.taken_target_ea == 0x4000
    assert conditional.fallthrough_target_ea == 0x5000


def test_abstains_when_conditional_predicate_is_not_the_tail():
    ports, capture = _modules()
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x3008,
        source_block_ea=0x3000,
        materialized_anchor_eas=(),
        target_eas=(0x4000, 0x5000),
        condition_code=5,
        true_target_ea=0x4000,
        false_target_ea=0x5000,
        selector_state_var_reg=20,
        predicate_register=8,
        predicate_size=4,
        predicate_true_state=0x11,
        predicate_false_state=0x22,
        predicate_true_is_taken=True,
        resolver_kind="conditional_handler_bridge",
    )
    plan = ports.plan_preopt_resolver_boundary_ports(
        (transfer,),
        imported_block_ranges={
            0x3000: (0x3000, 0x3010),
            0x4000: (0x4000, 0x4010),
            0x5000: (0x5000, 0x5010),
        },
        live_native_eas=frozenset(),
    )
    fact = _fact(
        capture,
        0x3000,
        instructions=(0x3008, 0x300C),
        successors=(0x3100, 0x3200),
        tail=0x300C,
        kind="CONDITIONAL",
    )

    result = capture.capture_preopt_boundary_ports(
        plan,
        blocks_by_ea={0x3000: fact},
        dispatcher_entry_eas=frozenset(),
    )

    assert result.conditional == ()
    assert result.abstentions[0].reason is (
        capture.PreoptPortCaptureAbstentionReason.PREDICATE_NOT_TAIL
    )


def test_captures_live_to_imported_direct_closure_crossing():
    _ports, capture = _modules()
    facts = {
        0x1000: _fact(
            capture,
            0x1000,
            instructions=(0x1004, 0x1008),
            successors=(0x2000,),
            tail=0x1008,
            kind="GOTO",
        ),
        0x2000: _fact(
            capture,
            0x2000,
            instructions=(0x2004,),
        ),
    }

    result = capture.capture_preopt_live_to_imported_crossings(
        blocks_by_ea=facts,
        proven_internal_edges=((0x1000, 0x2000),),
        imported_block_eas=frozenset({0x2000}),
        live_native_eas=frozenset({0x1000, 0x2000}),
    )

    assert result.abstentions == ()
    assert result.conditional == ()
    (direct,) = result.direct
    assert direct.source_block_ea == 0x1000
    assert direct.source_instruction_ea == 0x1008
    assert direct.old_successor_eas == (0x2000,)
    assert direct.old_successor_owners == (
        DetachedSnippetBoundaryPortOwner.LIVE,
    )
    assert direct.target_ea == 0x2000
    assert direct.source_owner is DetachedSnippetBoundaryPortOwner.LIVE
    assert direct.target_owner is DetachedSnippetBoundaryPortOwner.IMPORTED


def test_captures_live_conditional_with_one_imported_arm():
    _ports, capture = _modules()
    facts = {
        0x3000: _fact(
            capture,
            0x3000,
            instructions=(0x3004, 0x3008),
            successors=(0x3100, 0x3200),
            tail=0x3008,
            taken_successor=0x3100,
            fallthrough_successor=0x3200,
            kind="CONDITIONAL",
        ),
        0x3100: _fact(capture, 0x3100, instructions=(0x3104,)),
        0x3200: _fact(capture, 0x3200, instructions=(0x3204,)),
    }

    result = capture.capture_preopt_live_to_imported_crossings(
        blocks_by_ea=facts,
        proven_internal_edges=((0x3000, 0x3100), (0x3000, 0x3200)),
        imported_block_eas=frozenset({0x3100}),
        live_native_eas=frozenset({0x3000, 0x3100, 0x3200}),
    )

    assert result.abstentions == ()
    assert result.direct == ()
    (conditional,) = result.conditional
    assert conditional.source_block_ea == 0x3000
    assert conditional.predicate_ea == 0x3008
    assert conditional.old_taken_target_ea == 0x3100
    assert conditional.old_fallthrough_target_ea == 0x3200
    assert conditional.taken_target_ea == 0x3100
    assert conditional.fallthrough_target_ea == 0x3200
    assert conditional.old_taken_target_owner is (
        DetachedSnippetBoundaryPortOwner.LIVE
    )
    assert conditional.old_fallthrough_target_owner is (
        DetachedSnippetBoundaryPortOwner.LIVE
    )
    assert conditional.taken_target_owner is (
        DetachedSnippetBoundaryPortOwner.IMPORTED
    )
    assert conditional.fallthrough_target_owner is (
        DetachedSnippetBoundaryPortOwner.LIVE
    )


def test_captured_conditional_supersedes_same_closure_predicate_only():
    ports, capture = _modules()
    request = ports.PreoptConditionalBoundaryPort(
        source_block_ea=0x3000,
        predicate_ea=0x3008,
        taken_target_ea=0x5000,
        fallthrough_target_ea=0x6000,
        state_register=None,
        taken_state=None,
        fallthrough_state=None,
        source_owner=ports.PreoptBoundaryEndpointOwner.LIVE,
        taken_target_owner=ports.PreoptBoundaryEndpointOwner.IMPORTED,
        fallthrough_target_owner=ports.PreoptBoundaryEndpointOwner.IMPORTED,
        resolver_kind="conditional_exact_route",
    )
    captured = capture.CapturedPreoptBoundaryPorts(
        direct=(),
        conditional=(
            capture.CapturedConditionalBoundaryPort(
                request=request,
                source_block_ea=0x3000,
                predicate_ea=0x3008,
                old_taken_target_ea=0x3100,
                old_fallthrough_target_ea=0x3200,
                taken_target_ea=0x5000,
                fallthrough_target_ea=0x6000,
            ),
        ),
        abstentions=(),
    )

    def closure_conditional(source, predicate, taken, fallthrough):
        return DetachedSnippetConditionalBoundaryPort(
            source_block_ea=source,
            predicate_ea=predicate,
            old_taken_target_ea=taken,
            old_fallthrough_target_ea=fallthrough,
            taken_target_ea=taken,
            fallthrough_target_ea=fallthrough,
            state_register=None,
            taken_state=None,
            fallthrough_state=None,
            source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
            taken_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
            fallthrough_target_owner=DetachedSnippetBoundaryPortOwner.LIVE,
            resolver_kind="native_closure_crossing",
        )

    matching = closure_conditional(0x3000, 0x3008, 0x3100, 0x3200)
    unrelated = closure_conditional(0x4000, 0x4008, 0x4100, 0x4200)
    crossings = capture.CapturedPreoptClosureCrossings(
        direct=(),
        conditional=(matching, unrelated),
        abstentions=(),
    )

    result = capture.exclude_closure_conditionals_superseded_by_captured(
        crossings,
        captured,
    )

    assert result.direct == crossings.direct
    assert result.conditional == (unrelated,)
    assert result.abstentions == crossings.abstentions


def test_abstains_when_live_to_imported_crossing_shape_is_incomplete():
    _ports, capture = _modules()
    facts = {
        0x3000: _fact(
            capture,
            0x3000,
            instructions=(0x3008,),
            successors=(0x3100,),
            successors_complete=False,
            tail=0x3008,
            kind="CONDITIONAL",
        ),
    }

    result = capture.capture_preopt_live_to_imported_crossings(
        blocks_by_ea=facts,
        proven_internal_edges=((0x3000, 0x3100),),
        imported_block_eas=frozenset({0x3100}),
        live_native_eas=frozenset({0x3000, 0x3100}),
    )

    assert result.direct == ()
    assert result.conditional == ()
    assert result.abstentions[0].reason is (
        capture.PreoptClosureCrossingAbstentionReason.INCOMPLETE_SUCCESSORS
    )


def test_skips_closure_crossing_owned_by_state_transition_port():
    _ports, capture = _modules()
    facts = {
        0x1000: _fact(
            capture,
            0x1000,
            instructions=(0x1008,),
            successors=(0x2000,),
            tail=0x1008,
            kind="GOTO",
        ),
    }

    result = capture.capture_preopt_live_to_imported_crossings(
        blocks_by_ea=facts,
        proven_internal_edges=((0x1000, 0x2000),),
        imported_block_eas=frozenset({0x2000}),
        live_native_eas=frozenset({0x1000, 0x2000}),
        excluded_source_eas=frozenset({0x1000}),
    )

    assert result.direct == ()
    assert result.conditional == ()
    assert result.abstentions == ()
