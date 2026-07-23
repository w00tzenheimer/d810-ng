"""Runtime-layer regression tests for the computed-goto resolver."""

from __future__ import annotations

import inspect
import sys
from dataclasses import replace
from types import ModuleType, SimpleNamespace

import pytest

from d810.core.maturity_labels import IDA_MMAT_LOCOPT, IDA_MMAT_PREOPTIMIZED
from d810.optimizers.microcode.flow.jumps.computed_goto_resolver import (
    ComputedGotoResolution,
    _ConcreteDispatchResult,
    _ConcreteHandlerStateWrite,
    _build_conditional_handler_state_routes,
    _build_materialized_state_routes,
    _apply_concrete_equality_setcc,
    _canonical_low_byte_parent,
    _native_equality_selector_is_materializable,
    _native_final_state_write_before_live_tail,
    _native_target_is_return_epilogue,
    _NativeEqualityRow,
    _PatchPlan,
    _static_equality_route_candidate,
    _static_absorb_eas,
    _static_equality_candidate_target,
    _bootstrap_native_replay_inputs,
    _native_entry_corridor_serials,
    _static_native_handler_entry_eas,
    _static_native_bootstrap_route_candidates,
    _states_with_validated_exact_equality_routes,
    _setcc_equality_delivery_targets,
    _encode_two_way_branch,
    _encode_direct_jump,
    _encode_x86_register_immediate32,
    _equality_setcc_condition_code,
    _equality_fragment_owned_ranges,
    _exact_equality_fragment_transfers,
    _equality_transfers_activated_by_targets,
    _exact_equality_native_target,
    _dispatcher_context_register_values,
    _function_context_register_values,
    _branch_state_choice_candidates,
    _make_static_conditional_state_choice,
    _is_concrete_handler_entry,
    _is_ignorable_corridor_store,
    _is_materialized_dispatch_instruction,
    _state_write_values_match,
    _insn_writes_first_operand,
    _sv_process_writer,
    _corridor_memory_spaces_may_alias,
    _plan_detached_resolver_cut_boundary_ports,
    recover_conditional_handler_bridge_transfers_from_mba,
    _recover_condition_chain_handler_transfers_from_mba,
    _recover_static_handler_entry_route_transfers,
    _recover_static_choice_handler_entry_routes,
    _enrich_preopt_union_route_ranges,
    _resolve_native_setcc_route_facts,
    _claim_exact_function_tail_range,
    _resolve_concrete_handler_state_write,
    _unique_static_equality_handler_targets,
    _resolve_static_conditional_state_choice_targets,
    is_computed_goto_materialized,
    _on_build_callinfo,
    _callinfo_profile_resolution,
    _proven_callinfo_reentry_eas,
    _zero_arg_call_type_is_proven,
)
from d810.optimizers.microcode.flow.jumps import computed_goto_resolver
from d810.hexrays.hooks.optimization_suppression import (
    d810_optimization_is_suppressed,
)
from d810.hexrays.mutation.detached_handler_island import (
    _resolver_cut_target_for_synthetic_successor,
)
from d810.analyses.control_flow.call_abi import (
    StackCallAbiEvidence,
    StackCallAbiProof,
)
from d810.analyses.control_flow.materialized_indirect_transfer import (
    MaterializedIndirectTransfer,
    MaterializedStateRoute,
    PortableStateWriteRouteEvidence,
    StateWriteRouteDeliveryKind,
    StateWriteRouteProofKind,
    TerminalReturnCarrierRequest,
)
from d810.analyses.control_flow.residual_entry_bridge import EntryBridgeEvidence
from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity


def test_preopt_entry_bridge_projects_exact_portable_state_targets() -> None:
    taken_state = 0xA0716E5B
    fallthrough_state = 0xEC71CA67
    taken_target = 0x40C26D
    fallthrough_target = 0x40B9A6
    evidence = EntryBridgeEvidence(
        predicate_ea=0x40A5A0,
        condition_code=5,
        predicate_stack_identity=(0x20, 4),
        stack_cell_identity=(0x80, 4),
        taken_state_constant=taken_state,
        fallthrough_state_constant=fallthrough_state,
        source_store_ea=0x40A5C0,
        canonical_stack_cell_identity=(0x40, 4),
        canonical_predicate_stack_identity=(-0x20, 4),
        predicate_block_ea=0x40A560,
        taken_arm_entry_ea=0x40A5C0,
        fallthrough_arm_entry_ea=0x40A5B0,
        conditional_tail_ea=0x40A5AB,
    )
    routes = (
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40C253,
            source_block_ea=0x40C253,
            materialized_anchor_eas=(),
            target_eas=(taken_target,),
            selector_state_var_reg=20,
            selector_state_constant=taken_state,
            resolver_kind="static_handler_entry_route",
        ),
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40B98C,
            source_block_ea=0x40B98C,
            materialized_anchor_eas=(),
            target_eas=(fallthrough_target,),
            selector_state_var_reg=20,
            selector_state_constant=fallthrough_state,
            resolver_kind="static_handler_entry_route",
        ),
    )

    transfer = computed_goto_resolver._preopt_entry_bridge_transfer(
        evidence,
        routes,
    )

    assert transfer == MaterializedIndirectTransfer(
        source_jmp_ea=0x40A5AB,
        source_block_ea=0x40A560,
        materialized_anchor_eas=(0x40A5C0,),
        target_eas=(taken_target, fallthrough_target),
        condition_code=5,
        true_target_ea=taken_target,
        false_target_ea=fallthrough_target,
        selector_state_var_reg=20,
        resolver_kind="preopt_entry_bridge",
        predicate_size=4,
        predicate_true_state=taken_state,
        predicate_false_state=fallthrough_state,
        predicate_true_is_taken=True,
        predicate_preserve_live=True,
        predicate_stack_ida_stkoff=-0x20,
        state_carrier_store_ea=0x40A5C0,
        state_carrier_ida_stkoff=0x40,
    )


def test_preopt_entry_bridge_requires_portable_original_predicate_identity() -> None:
    evidence = EntryBridgeEvidence(
        predicate_ea=0x40A5A0,
        condition_code=5,
        predicate_stack_identity=(0x20, 4),
        stack_cell_identity=(0x80, 4),
        taken_state_constant=0xA0716E5B,
        fallthrough_state_constant=0xEC71CA67,
        source_store_ea=0x40A5C0,
        canonical_stack_cell_identity=(0x40, 4),
        canonical_predicate_stack_identity=None,
        predicate_block_ea=0x40A560,
        conditional_tail_ea=0x40A5AB,
    )
    routes = (
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40C253,
            source_block_ea=0x40C253,
            materialized_anchor_eas=(),
            target_eas=(0x40C26D,),
            selector_state_var_reg=20,
            selector_state_constant=0xA0716E5B,
            resolver_kind="static_handler_entry_route",
        ),
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40B98C,
            source_block_ea=0x40B98C,
            materialized_anchor_eas=(),
            target_eas=(0x40B9A6,),
            selector_state_var_reg=20,
            selector_state_constant=0xEC71CA67,
            resolver_kind="static_handler_entry_route",
        ),
    )

    assert computed_goto_resolver._preopt_entry_bridge_transfer(evidence, routes) is None


def test_stack_carried_consumer_reserves_imported_dispatcher_envelope() -> None:
    consumer_entry_ea = 0x40BECC
    consumer_load_ea = 0x40BECC
    generic_cut = DetachedSnippetConditionalBoundaryPort(
        source_block_ea=consumer_entry_ea,
        predicate_ea=0x40BED0,
        old_taken_target_ea=None,
        old_fallthrough_target_ea=None,
        taken_target_ea=0x40B6C0,
        fallthrough_target_ea=0x40A607,
        state_register=20,
        taken_state=None,
        fallthrough_state=None,
        source_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        taken_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        fallthrough_target_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        resolver_kind="resolver_proven_register_compare_cut",
    )
    unrelated_cut = replace(
        generic_cut,
        source_block_ea=0x40BF00,
        predicate_ea=0x40BF08,
    )
    choice = MaterializedIndirectTransfer(
        source_jmp_ea=0x40A5AB,
        source_block_ea=0x40A59D,
        materialized_anchor_eas=(0x40A5AE,),
        target_eas=(0x40C26D, 0x40B9A6),
        condition_code=5,
        true_target_ea=0x40C26D,
        false_target_ea=0x40B9A6,
        selector_state_var_reg=20,
        resolver_kind="preopt_entry_bridge",
        predicate_size=4,
        predicate_true_state=0xA0716E5B,
        predicate_false_state=0xEC71CA67,
        state_carrier_store_ea=0x40A5AE,
        state_carrier_consumer_load_eas=(consumer_load_ea,),
        state_carrier_ida_stkoff=0x40,
    )

    native_cfg = NativeCfg(
        {
            consumer_entry_ea: NativeBlock(consumer_entry_ea, 0x40BEE1),
            0x40BF00: NativeBlock(0x40BF00, 0x40BF10),
        }
    )
    supersession_diagnostic: dict[str, object] = {}
    assert computed_goto_resolver._without_replaced_imported_dispatcher_ports(
        (generic_cut, unrelated_cut),
        (
            choice,
            replace(
                choice,
                resolver_kind="static_stack_carried_state_choice",
                true_target_ea=choice.false_target_ea,
                false_target_ea=choice.true_target_ea,
                predicate_true_state=choice.predicate_false_state,
                predicate_false_state=choice.predicate_true_state,
            ),
        ),
        native_cfg=native_cfg,
        diagnostic=supersession_diagnostic,
    ) == (unrelated_cut,)
    assert supersession_diagnostic["outcome"] == "suppressed"
    assert supersession_diagnostic["choice_count"] == 2
    assert supersession_diagnostic["signature_count"] == 1
    assert supersession_diagnostic["suppressed_port_count"] == 1
    assert computed_goto_resolver._refresh_preopt_union_boundary_ports(
        DetachedSnippetBoundaryPorts((), (generic_cut, unrelated_cut)),
        DetachedSnippetBoundaryPorts((), ()),
        replacement_transfers=(choice,),
        native_cfg=native_cfg,
    ) == DetachedSnippetBoundaryPorts((), (unrelated_cut,))


def test_preopt_boundary_keeps_stack_consumer_as_evidence_only() -> None:
    consumer_ea = 0x40BECC
    choice = MaterializedIndirectTransfer(
        source_jmp_ea=0x40A5AB,
        source_block_ea=0x40A59D,
        materialized_anchor_eas=(0x40A5AE,),
        target_eas=(0x40C26D, 0x40B9A6),
        condition_code=5,
        true_target_ea=0x40C26D,
        false_target_ea=0x40B9A6,
        selector_state_var_reg=20,
        resolver_kind="preopt_entry_bridge",
        predicate_size=4,
        predicate_true_state=0xA0716E5B,
        predicate_false_state=0xEC71CA67,
        state_carrier_store_ea=0x40A5AE,
        state_carrier_consumer_load_eas=(consumer_ea,),
        state_carrier_ida_stkoff=0x40,
        owned_native_ranges=((consumer_ea, 0x40BEE7),),
    )
    diagnostic: dict[str, object] = {}

    ports = computed_goto_resolver._preopt_union_boundary_ports(
        SimpleNamespace(
            included_block_eas=(consumer_ea, 0x40C26D, 0x40B9A6),
            proven_import_boundary_edges=(),
        ),
        live_native_eas=frozenset(),
        transfers=(choice,),
        native_cfg=NativeCfg(
            {
                consumer_ea: NativeBlock(consumer_ea, 0x40BEE7),
                0x40C26D: NativeBlock(0x40C26D, 0x40C280),
                0x40B9A6: NativeBlock(0x40B9A6, 0x40B9C0),
            }
        ),
        entry_consumer_port_diagnostic=diagnostic,
    )

    assert ports == DetachedSnippetBoundaryPorts((), ())
    assert diagnostic["outcome"] == "not_present"
    assert diagnostic["choice_count"] == 1
    assert diagnostic["suppressed_port_count"] == 0


def test_preopt_entry_bridge_publishes_unique_native_stack_consumer() -> None:
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x40A5AB,
        source_block_ea=0x40A59D,
        materialized_anchor_eas=(0x40A5AE,),
        target_eas=(0x40C26D, 0x40B9A6),
        condition_code=5,
        true_target_ea=0x40C26D,
        false_target_ea=0x40B9A6,
        selector_state_var_reg=20,
        resolver_kind="preopt_entry_bridge",
        predicate_size=4,
        predicate_true_state=0xA0716E5B,
        predicate_false_state=0xEC71CA67,
        state_carrier_store_ea=0x40A5AE,
        state_carrier_ida_stkoff=0x40,
    )

    bound = computed_goto_resolver._bind_preopt_entry_bridge_consumers(
        (transfer,),
        consumer_load_eas_by_displacement={0x40: (0x40BECC,)},
        store_displacement_resolver=lambda store_ea: (
            0x40 if int(store_ea) == 0x40A5AE else None
        ),
    )
    assert bound == (
        replace(
            transfer,
            state_carrier_stack_displacement=0x40,
            state_carrier_consumer_load_eas=(0x40BECC,),
        ),
    )
    assert computed_goto_resolver._bind_preopt_entry_consumer_owned_ranges(
        bound,
        native_cfg=NativeCfg(
            {0x40BECC: NativeBlock(0x40BECC, 0x40BEE7)}
        ),
    ) == (
        replace(bound[0], owned_native_ranges=((0x40BECC, 0x40BEE7),)),
    )


def test_preopt_entry_bridge_capture_publishes_lifecycle_evidence(
    monkeypatch,
) -> None:
    evidence = EntryBridgeEvidence(
        predicate_ea=0x1004,
        condition_code=5,
        predicate_stack_identity=(0x20, 4),
        stack_cell_identity=(0x80, 4),
        taken_state_constant=0x11,
        fallthrough_state_constant=0x22,
        source_store_ea=0x1020,
        predicate_block_ea=0x1000,
        taken_arm_entry_ea=0x1020,
        fallthrough_arm_entry_ea=0x1010,
        conditional_tail_ea=0x1008,
    )
    _session, state = _resolver_session()
    monkeypatch.setattr(
        computed_goto_resolver,
        "recognize_preoptimized_residual_entry_bridge",
        lambda _mba: evidence,
        raising=False,
    )

    assert computed_goto_resolver._capture_preopt_entry_bridge_evidence(
        state,
        object(),
    )
    assert not computed_goto_resolver._capture_preopt_entry_bridge_evidence(
        state,
        object(),
    )
    assert state.portable_evidence.preopt_entry_bridges == (evidence,)


def test_preopt_entry_bridge_projection_abstains_on_conflicting_live_proofs() -> None:
    first = EntryBridgeEvidence(
        predicate_ea=0x1004,
        condition_code=5,
        predicate_stack_identity=(0x20, 4),
        stack_cell_identity=(0x80, 4),
        taken_state_constant=0x11,
        fallthrough_state_constant=0x22,
        source_store_ea=0x1020,
        predicate_block_ea=0x1000,
        conditional_tail_ea=0x1008,
    )
    second = replace(first, fallthrough_state_constant=0x33)

    assert (
        computed_goto_resolver._preopt_entry_bridge_transfers(
            (first, second),
            (),
        )
        == ()
    )


def test_prepatch_generation_retains_pristine_entry_prefix() -> None:
    assert computed_goto_resolver._preopt_generation_ranges_with_entry_prefix(
        0x40A560,
        (
            (0x40A5F0, 0x40A615),
            (0x40A680, 0x40A69A),
        ),
    ) == (
        (0x40A560, 0x40A5F0),
        (0x40A5F0, 0x40A615),
        (0x40A680, 0x40A69A),
    )


def test_preopt_union_range_enrichment_reuses_existing_target_ownership(
    monkeypatch,
) -> None:
    precise_ranges = (
        (0x40C10A, 0x40C132),
        (0x40C132, 0x40C144),
    )
    precise = MaterializedIndirectTransfer(
        source_jmp_ea=0x40C0F0,
        source_block_ea=0x40C0F0,
        materialized_anchor_eas=(),
        target_eas=(0x40C10A,),
        selector_state_var_reg=20,
        selector_state_constant=0x886CCA9F,
        resolver_kind="static_handler_entry_route",
        owned_native_ranges=precise_ranges,
    )
    duplicate = replace(
        precise,
        source_jmp_ea=0x40A5C8,
        source_block_ea=0x40A5C8,
        owned_native_ranges=(),
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "_native_residual_fragment_ranges",
        lambda *_args, **_kwargs: pytest.fail(
            "stable target ownership must win over regenerated native CFG"
        ),
    )

    enriched = _enrich_preopt_union_route_ranges(
        SimpleNamespace(
            function_ea=0x40A560,
            reachable_eas=(0x40A560,),
            block_entries=(0x40A560,),
        ),
        (precise, duplicate),
    )

    assert enriched[0].owned_native_ranges == precise_ranges
    assert enriched[1].owned_native_ranges == precise_ranges


def test_preopt_union_captures_terminal_carrier_into_session(
    monkeypatch,
) -> None:
    state_constant = 0x19A7218A
    terminal_ea = 0x40C898
    source_ea = 0x40C7E5
    carrier_ea = 0x40C7EA
    delivery_ea = 0x40C7F0
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x40A5CA,
        source_block_ea=0x40A5CA,
        materialized_anchor_eas=(),
        target_eas=(terminal_ea,),
        selector_state_var_reg=20,
        selector_state_constant=state_constant,
        resolver_kind="static_handler_entry_route",
    )
    resolution = ComputedGotoResolution(
        function_ea=0x40A560,
        jmp_targets={},
        reachable_eas=(0x40A560,),
        arch="x86",
        executed_insns=0,
        seeds_run=0,
    )
    _session, state = _resolver_session(resolution)
    route = PortableStateWriteRouteEvidence(
        write_identity=StableBlockIdentity.from_intervals(
            (NativeEaInterval(source_ea, source_ea + 1),),
            native_key=state.native_key,
        ),
        delivery_identity=StableBlockIdentity.from_intervals(
            (NativeEaInterval(delivery_ea, delivery_ea + 1),),
            native_key=state.native_key,
        ),
        source_write_ea=source_ea,
        delivery_ea=delivery_ea,
        delivery_region_start_ea=source_ea,
        delivery_region_end_ea=delivery_ea + 1,
        corridor_instruction_eas=(source_ea, carrier_ea, delivery_ea),
        state_var_reg=20,
        state_constant=state_constant,
        target_identity=StableBlockIdentity.from_intervals(
            (NativeEaInterval(terminal_ea, terminal_ea + 1),),
            native_key=state.native_key,
        ),
        target_ea=terminal_ea,
    )
    assert state.native_preanalysis.merge_state_write_routes(
        state.native_key,
        (route,),
    )
    captured = []
    captured_evidence = []
    monkeypatch.setattr(
        computed_goto_resolver,
        "_native_target_is_return_epilogue",
        lambda target_ea: int(target_ea) == terminal_ea,
    )
    from d810.analyses.control_flow.terminal_return_carrier_evidence import (
        TerminalReturnCarrierEvidence,
        TerminalReturnCarrierSource,
        TerminalReturnCarrierSourceKind,
    )
    from d810.hexrays.mutation import detached_handler_island
    from d810.ir.expressions import ValueOpKind
    from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind

    def capture_portable(
        function_ea,
        request,
        _mba,
        *,
        capture_identity,
        terminal_identity,
    ):
        evidence = TerminalReturnCarrierEvidence(
            request=request,
            capture_identity=capture_identity,
            terminal_identity=terminal_identity,
            state_write_ea=source_ea,
            carrier_ea=carrier_ea,
            operation=ValueOpKind.MOVE,
            source=TerminalReturnCarrierSource(
                kind=TerminalReturnCarrierSourceKind.STORAGE_VALUE,
                width=4,
                storage_identity=StorageIdentity(
                    StorageIdentityKind.GLOBAL,
                    0x48B8A4,
                ),
            ),
            return_width=4,
            corridor_instruction_eas=(source_ea, carrier_ea),
        )
        captured.append(
            (
                function_ea,
                request,
                capture_identity,
                terminal_identity,
            )
        )
        captured_evidence.append(evidence)
        return evidence

    monkeypatch.setattr(
        detached_handler_island,
        "capture_terminal_return_carrier_evidence",
        capture_portable,
    )
    monkeypatch.setattr(
        detached_handler_island,
        "capture_terminal_return_carrier_template",
        lambda *_args, **_kwargs: pytest.fail(
            "production capture must not publish legacy templates"
        ),
    )

    assert (
        computed_goto_resolver._capture_preopt_union_terminal_return_carriers(
            state,
            function_ea=0x40A560,
            mba=SimpleNamespace(maturity=IDA_MMAT_PREOPTIMIZED),
            transfers=(transfer,),
        )
        == 1
    )
    assert len(captured) == 1
    function_ea, request, capture_identity, terminal_identity = captured[0]
    assert function_ea == 0x40A560
    assert request == TerminalReturnCarrierRequest(
        source_handler_ea=source_ea,
        terminal_target_ea=terminal_ea,
        state_var_reg=20,
        state_constant=state_constant,
    )
    assert capture_identity.exact_instruction_eas == frozenset(
        {source_ea, carrier_ea, delivery_ea}
    )
    assert terminal_identity.exact_instruction_eas == frozenset({terminal_ea})
    assert state.portable_evidence.terminal_return_carrier_requests == (request,)
    assert state.portable_evidence.terminal_return_carriers == tuple(
        captured_evidence
    )


def test_branch_state_choice_recovers_default_and_overriding_dispatch_states() -> None:
    choices = _branch_state_choice_candidates(
        source_block_ea=0x40E1F6,
        predicate_ea=0x40E20E,
        condition_code=4,
        source_state={
            "ebp": frozenset({0x85AE90D3}),
            "eax": frozenset({0x11111111}),
        },
        taken_state={
            "ebp": frozenset({0x3AF41FBE}),
            "eax": frozenset({0x22222222}),
        },
        fallthrough_state={
            "ebp": frozenset({0x85AE90D3}),
            "eax": frozenset({0x33333333}),
        },
        taken_resolved_target_ea=0x40F12D,
        fallthrough_resolved_target_ea=0x40DC04,
        register_mregs={"eax": 8, "ebp": 28},
        predicate_register_names=frozenset({"eax"}),
    )

    assert choices == (
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40E20E,
            source_block_ea=0x40E1F6,
            materialized_anchor_eas=(0x40E20E,),
            target_eas=(),
            condition_code=4,
            selector_state_var_reg=28,
            predicate_true_state=0x3AF41FBE,
            predicate_false_state=0x85AE90D3,
            resolver_kind="static_conditional_state_choice",
        ),
    )


@pytest.mark.parametrize(
    ("source_values", "taken_values", "fallthrough_values", "taken_frontier"),
    (
        (frozenset({1, 2}), frozenset({3}), frozenset({1}), 0x2000),
        (frozenset({1}), frozenset({2}), frozenset({3}), 0x2000),
        (frozenset({1}), frozenset({2}), frozenset({1}), 0),
    ),
)
def test_branch_state_choice_abstains_without_exact_default_or_frontiers(
    source_values: frozenset[int],
    taken_values: frozenset[int],
    fallthrough_values: frozenset[int],
    taken_frontier: int,
) -> None:
    assert (
        _branch_state_choice_candidates(
            source_block_ea=0x1000,
            predicate_ea=0x1010,
            condition_code=4,
            source_state={"ebp": source_values},
            taken_state={"ebp": taken_values},
            fallthrough_state={"ebp": fallthrough_values},
            taken_resolved_target_ea=taken_frontier,
            fallthrough_resolved_target_ea=0x3000,
            register_mregs={"ebp": 28},
        )
        == ()
    )


def test_static_conditional_state_choice_binds_unique_distinct_handler_arms() -> None:
    choice = MaterializedIndirectTransfer(
        source_jmp_ea=0x40E20E,
        source_block_ea=0x40E1F6,
        materialized_anchor_eas=(0x40E20E,),
        target_eas=(),
        condition_code=4,
        selector_state_var_reg=28,
        predicate_true_state=0x3AF41FBE,
        predicate_false_state=0x85AE90D3,
        resolver_kind="static_conditional_state_choice",
    )
    routes = (
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40F127,
            source_block_ea=0x40F121,
            materialized_anchor_eas=(),
            target_eas=(0x40F12D,),
            selector_state_var_reg=28,
            selector_state_constant=0x3AF41FBE,
            resolver_kind="static_handler_entry_route",
        ),
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40DBF8,
            source_block_ea=0x40DBF8,
            materialized_anchor_eas=(),
            target_eas=(0x40DC04,),
            selector_state_var_reg=28,
            selector_state_constant=0x85AE90D3,
            resolver_kind="static_handler_entry_route",
        ),
    )

    assert _resolve_static_conditional_state_choice_targets((choice,), routes) == (
        replace(
            choice,
            target_eas=(0x40F12D, 0x40DC04),
            true_target_ea=0x40F12D,
            false_target_ea=0x40DC04,
            predicate_true_is_taken=True,
            predicate_preserve_live=True,
            resolver_kind="static_conditional_state_choice_bridge",
        ),
    )


def test_static_conditional_state_choice_abstains_on_ambiguous_or_same_target() -> None:
    choice = MaterializedIndirectTransfer(
        source_jmp_ea=0x1010,
        source_block_ea=0x1000,
        materialized_anchor_eas=(0x1010,),
        target_eas=(),
        condition_code=4,
        selector_state_var_reg=28,
        predicate_true_state=0x11111111,
        predicate_false_state=0x22222222,
        resolver_kind="static_conditional_state_choice",
    )

    ambiguous = (
        MaterializedIndirectTransfer(
            0x2000,
            0x2000,
            (),
            (0x3000,),
            selector_state_var_reg=28,
            selector_state_constant=0x11111111,
            resolver_kind="static_handler_entry_route",
        ),
        MaterializedIndirectTransfer(
            0x2010,
            0x2010,
            (),
            (0x3010,),
            selector_state_var_reg=28,
            selector_state_constant=0x11111111,
            resolver_kind="static_handler_entry_route",
        ),
        MaterializedIndirectTransfer(
            0x2020,
            0x2020,
            (),
            (0x3000,),
            selector_state_var_reg=28,
            selector_state_constant=0x22222222,
            resolver_kind="static_handler_entry_route",
        ),
    )
    same_target = (
        replace(ambiguous[0], source_jmp_ea=0x2100),
        ambiguous[2],
    )

    assert _resolve_static_conditional_state_choice_targets((choice,), ambiguous) == ()
    assert (
        _resolve_static_conditional_state_choice_targets((choice,), same_target) == ()
    )


def test_static_conditional_state_choice_accepts_static_fixpoint_router_proof() -> None:
    choice = MaterializedIndirectTransfer(
        source_jmp_ea=0x40E20E,
        source_block_ea=0x40E1F6,
        materialized_anchor_eas=(0x40E20E,),
        target_eas=(),
        condition_code=4,
        selector_state_var_reg=28,
        predicate_true_state=0x3AF41FBE,
        predicate_false_state=0x85AE90D3,
        resolver_kind="static_conditional_state_choice",
    )
    router = (
        MaterializedIndirectTransfer(
            source_jmp_ea=0x410000,
            source_block_ea=0x40FFF0,
            materialized_anchor_eas=(0x410000,),
            target_eas=(0x40F12D, 0x40D370),
            condition_code=4,
            true_target_ea=0x40F12D,
            false_target_ea=0x40D370,
            selector_state_var_reg=28,
            selector_compare_constant=0x3AF41FBE,
            resolver_kind="static_fixpoint",
        ),
        MaterializedIndirectTransfer(
            source_jmp_ea=0x410010,
            source_block_ea=0x410008,
            materialized_anchor_eas=(0x410010,),
            target_eas=(0x40D370, 0x40DC04),
            condition_code=5,
            true_target_ea=0x40D370,
            false_target_ea=0x40DC04,
            selector_state_var_reg=28,
            selector_compare_constant=0x85AE90D3,
            resolver_kind="static_fixpoint",
        ),
        MaterializedIndirectTransfer(
            source_jmp_ea=0x410020,
            source_block_ea=0x410018,
            materialized_anchor_eas=(0x410020,),
            target_eas=(0x420000, 0x430000),
            condition_code=4,
            true_target_ea=0x420000,
            false_target_ea=0x430000,
            selector_state_var_reg=8,
            selector_compare_constant=0x12345678,
            resolver_kind="static_fixpoint",
        ),
    )

    assert _resolve_static_conditional_state_choice_targets((choice,), router) == (
        replace(
            choice,
            target_eas=(0x40F12D, 0x40DC04),
            true_target_ea=0x40F12D,
            false_target_ea=0x40DC04,
            predicate_true_is_taken=True,
            predicate_preserve_live=True,
            resolver_kind="static_conditional_state_choice_bridge",
        ),
    )


def test_static_choice_routes_require_independent_entry_dispatch_replay() -> None:
    true_state = 0x3AF41FBE
    false_state = 0x85AE90D3
    choice = MaterializedIndirectTransfer(
        source_jmp_ea=0x40E20E,
        source_block_ea=0x40E1F6,
        materialized_anchor_eas=(0x40E20E,),
        target_eas=(),
        condition_code=4,
        selector_state_var_reg=28,
        predicate_true_state=true_state,
        predicate_false_state=false_state,
        resolver_kind="static_conditional_state_choice",
    )
    resolution = ComputedGotoResolution(
        function_ea=0x40D200,
        jmp_targets={0x40D37F: (0x40F12D, 0x40DC04)},
        reachable_eas=(),
        arch="x86",
        executed_insns=1,
        seeds_run=0,
        block_entries=(0x40F12D, 0x40DC04),
        conditional_state_choices=(choice,),
    )
    replayed: list[tuple[int, dict[int, int]]] = []

    routes = _recover_static_choice_handler_entry_routes(
        resolution,
        (choice,),
        entry_seed_resolver=lambda _function_ea, _selectors: (
            computed_goto_resolver.NativeEntryBootstrapSeed(
                source_anchor_ea=0x40D348,
                direct_target_ea=0x40D380,
                state_mreg=28,
                state_constant=0x699BC698,
            ),
        ),
        route_resolver=lambda source_ea, **kwargs: (
            replayed.append((source_ea, dict(kwargs["initial_mregs"])))
            or {
                true_state: 0x40F12D,
                false_state: 0x40DC04,
            }.get(kwargs["initial_mregs"][28])
        ),
    )

    assert replayed == [
        (0x40D348, {28: true_state}),
        (0x40D348, {28: false_state}),
    ]
    assert tuple(
        (route.selector_state_constant, route.target_eas) for route in routes
    ) == (
        (true_state, (0x40F12D,)),
        (false_state, (0x40DC04,)),
    )
    assert {route.resolver_kind for route in routes} == {"static_handler_entry_route"}


from d810.analyses.control_flow.native_semantic_closure import (
    NativeBlock,
    NativeCfg,
    NativeEdge,
    NativeEdgeKind,
    NativeRange,
    NativeTerminalKind,
    ResolverProvenHandlerEntry,
    plan_native_semantic_closure,
)
from d810.analyses.control_flow.detached_handler_island import (
    DetachedSnippetBoundaryPortOwner,
    DetachedSnippetBoundaryPorts,
    DetachedSnippetConditionalBoundaryPort,
    DetachedSnippetDirectBoundaryPort,
)
from d810.analyses.control_flow.semantic_transition import StateWriteAnchor
from d810.analyses.control_flow.route_predicate import DecisionDag, RouteComparison
from d810.analyses.control_flow.native_preanalysis_session import (
    NativePreanalysisSessionState,
)
from d810.capabilities.dispatcher import RouterKind
from d810.ir.flowgraph import (
    BlockKind,
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)
from tests.native_preanalysis import make_native_key


NATIVE_KEY = make_native_key()


def _resolver_session(
    resolution: ComputedGotoResolution | None = None,
):
    session = SimpleNamespace(
        native_preanalysis=NativePreanalysisSessionState(),
        resolver_attachment=None,
        native_key=NATIVE_KEY,
    )
    state = computed_goto_resolver.resolver_session_state(session)
    if resolution is not None:
        state.native_preanalysis.set_computed_goto_resolution(
            state.native_key,
            resolution,
        )
    return session, state


def test_bootstrap_native_replay_inputs_preserve_path_local_corridor_snapshots():
    """Bootstrap replay refills only the resolver's exact dispatcher entry."""
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x40D37F,
        source_block_ea=0x40D370,
        materialized_anchor_eas=(0x40D37F,),
        target_eas=(0x40E5C0,),
        selector_state_var_reg=28,
        context_register_values=(),
        source_register_values=(
            (12, 0x48BD94),
            (16, 0x48BF50),
            (20, 0xD1978CAF),
            (32, 0x48BDE4),
            (36, 0x48BB98),
        ),
    )

    context_mregs, snapshots_by_ea, dispatch_anchor_eas = (
        _bootstrap_native_replay_inputs((transfer,))
    )

    assert context_mregs == {}
    assert snapshots_by_ea == {
        0x40D370: {
            12: 0x48BD94,
            16: 0x48BF50,
            20: 0xD1978CAF,
            32: 0x48BDE4,
            36: 0x48BB98,
        }
    }
    assert dispatch_anchor_eas == frozenset((0x40D37F,))


def test_static_native_handler_entry_eas_exclude_current_dispatcher_blocks():
    graph = FlowGraph(
        blocks={
            0: BlockSnapshot(
                serial=0,
                block_type=0,
                succs=(1,),
                preds=(),
                flags=0,
                start_ea=0x40D313,
                insn_snapshots=(),
            ),
            1: BlockSnapshot(
                serial=1,
                block_type=0,
                succs=(2,),
                preds=(0,),
                flags=0,
                start_ea=0x40D370,
                insn_snapshots=(),
            ),
            2: BlockSnapshot(
                serial=2,
                block_type=0,
                succs=(),
                preds=(1,),
                flags=0,
                start_ea=0x40EAA7,
                insn_snapshots=(),
            ),
        },
        entry_serial=0,
        func_ea=0x40D200,
    )

    assert _static_native_handler_entry_eas(graph, frozenset((1,))) == frozenset(
        (0x40D313, 0x40EAA7)
    )


def test_static_native_bootstrap_candidate_uses_the_entry_state_write_and_tail():
    """A static handler entry may be rebound from an entry-owned state write."""
    state = 0x699BC698
    source_anchor_ea = 0x40D348
    handler_ea = 0x40EAA7
    graph = FlowGraph(
        blocks={
            0: BlockSnapshot(
                serial=0,
                block_type=0,
                succs=(1,),
                preds=(),
                flags=0,
                start_ea=0x40D200,
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=0,
                        ea=0x40D20F,
                        operands=(),
                        kind=InsnKind.GOTO,
                    ),
                ),
            ),
            1: BlockSnapshot(
                serial=1,
                block_type=0,
                succs=(2,),
                preds=(0, 3),
                flags=0,
                start_ea=0x40D313,
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=0,
                        ea=0x40D317,
                        operands=(),
                        kind=InsnKind.MOV,
                        l=MopSnapshot(
                            kind=OperandKind.NUMBER,
                            value=state,
                            size=4,
                        ),
                        d=MopSnapshot(
                            kind=OperandKind.REGISTER,
                            reg=28,
                            size=4,
                        ),
                    ),
                    InsnSnapshot(
                        opcode=0,
                        ea=source_anchor_ea,
                        operands=(),
                        kind=InsnKind.GOTO,
                    ),
                ),
            ),
            2: BlockSnapshot(
                serial=2,
                block_type=0,
                succs=(3,),
                preds=(1,),
                flags=0,
                start_ea=0x40D370,
                insn_snapshots=(),
            ),
            # A later handler state write loops back into the dispatcher. It
            # must not make the native entry seed look non-bootstrap.
            3: BlockSnapshot(
                serial=3,
                block_type=0,
                succs=(1,),
                preds=(2,),
                flags=0,
                start_ea=0x40E000,
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=0,
                        ea=0x40E004,
                        operands=(),
                        kind=InsnKind.MOV,
                        l=MopSnapshot(
                            kind=OperandKind.NUMBER,
                            value=state,
                            size=4,
                        ),
                        d=MopSnapshot(
                            kind=OperandKind.REGISTER,
                            reg=28,
                            size=4,
                        ),
                    ),
                ),
            ),
        },
        entry_serial=0,
        func_ea=0x40D200,
    )
    transfers = (
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40D36E,
            source_block_ea=0x40D370,
            materialized_anchor_eas=(),
            target_eas=(handler_ea,),
            selector_state_var_reg=28,
            selector_state_constant=state,
            resolver_kind="static_handler_entry_route",
        ),
    )

    assert _static_native_bootstrap_route_candidates(graph, transfers) == (
        (source_anchor_ea, state, handler_ea),
    )


def test_native_entry_corridor_stops_at_the_first_non_linear_block():
    """Bootstrap discovery must not scan arbitrary dispatcher successors."""
    graph = FlowGraph(
        blocks={
            0: BlockSnapshot(
                serial=0,
                block_type=0,
                succs=(1,),
                preds=(),
                flags=0,
                start_ea=0x401000,
                insn_snapshots=(),
            ),
            1: BlockSnapshot(
                serial=1,
                block_type=0,
                succs=(2,),
                preds=(0,),
                flags=0,
                start_ea=0x401010,
                insn_snapshots=(),
            ),
            2: BlockSnapshot(
                serial=2,
                block_type=0,
                succs=(3, 4),
                preds=(1,),
                flags=0,
                start_ea=0x401020,
                insn_snapshots=(),
            ),
            3: BlockSnapshot(
                serial=3,
                block_type=0,
                succs=(),
                preds=(2,),
                flags=0,
                start_ea=0x402000,
                insn_snapshots=(),
            ),
            4: BlockSnapshot(
                serial=4,
                block_type=0,
                succs=(),
                preds=(2,),
                flags=0,
                start_ea=0x403000,
                insn_snapshots=(),
            ),
        },
        entry_serial=0,
        func_ea=0x401000,
    )

    assert _native_entry_corridor_serials(graph) == (0, 1, 2)


def test_static_native_bootstrap_candidate_rejects_a_non_entry_state_write():
    state = 0x699BC698
    graph = FlowGraph(
        blocks={
            0: BlockSnapshot(
                serial=0,
                block_type=0,
                succs=(1,),
                preds=(),
                flags=0,
                start_ea=0x401000,
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=0,
                        ea=0x401002,
                        operands=(),
                        kind=InsnKind.MOV,
                        l=MopSnapshot(
                            kind=OperandKind.NUMBER,
                            value=state,
                            size=4,
                        ),
                        d=MopSnapshot(
                            kind=OperandKind.REGISTER,
                            reg=28,
                            size=4,
                        ),
                    ),
                ),
            ),
            1: BlockSnapshot(
                serial=1,
                block_type=0,
                succs=(2,),
                preds=(0,),
                flags=0,
                start_ea=0x401010,
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=0,
                        ea=0x401011,
                        operands=(),
                        kind=InsnKind.MOV,
                        l=MopSnapshot(
                            kind=OperandKind.NUMBER,
                            value=state,
                            size=4,
                        ),
                        d=MopSnapshot(
                            kind=OperandKind.REGISTER,
                            reg=28,
                            size=4,
                        ),
                    ),
                    InsnSnapshot(
                        opcode=0,
                        ea=0x401016,
                        operands=(),
                        kind=InsnKind.GOTO,
                    ),
                ),
            ),
            2: BlockSnapshot(
                serial=2,
                block_type=0,
                succs=(),
                preds=(1,),
                flags=0,
                start_ea=0x401020,
                insn_snapshots=(),
            ),
        },
        entry_serial=0,
        func_ea=0x401000,
    )
    transfers = (
        MaterializedIndirectTransfer(
            source_jmp_ea=0x401030,
            source_block_ea=0x401020,
            materialized_anchor_eas=(),
            target_eas=(0x401100,),
            selector_state_var_reg=28,
            selector_state_constant=state,
            resolver_kind="static_handler_entry_route",
        ),
    )

    assert _static_native_bootstrap_route_candidates(graph, transfers) == ()


def test_static_native_bootstrap_candidate_uses_injected_native_handler_proof():
    state = 0x699BC698
    source_anchor_ea = 0x40D348
    handler_ea = 0x40EAA7
    graph = FlowGraph(
        blocks={
            0: BlockSnapshot(
                serial=0,
                block_type=0,
                succs=(1,),
                preds=(),
                flags=0,
                start_ea=0x40D200,
                insn_snapshots=(),
            ),
            1: BlockSnapshot(
                serial=1,
                block_type=0,
                succs=(2,),
                preds=(0,),
                flags=0,
                start_ea=0x40D313,
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=0,
                        ea=0x40D317,
                        operands=(),
                        kind=InsnKind.MOV,
                        l=MopSnapshot(
                            kind=OperandKind.NUMBER,
                            value=state,
                            size=4,
                        ),
                        d=MopSnapshot(
                            kind=OperandKind.REGISTER,
                            reg=28,
                            size=4,
                        ),
                    ),
                    InsnSnapshot(
                        opcode=0,
                        ea=source_anchor_ea,
                        operands=(),
                        kind=InsnKind.GOTO,
                    ),
                ),
            ),
            2: BlockSnapshot(
                serial=2,
                block_type=0,
                succs=(),
                preds=(1,),
                flags=0,
                start_ea=0x40D370,
                insn_snapshots=(),
            ),
        },
        entry_serial=0,
        func_ea=0x40D200,
    )
    transfers = (
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40D37F,
            source_block_ea=0x40D370,
            materialized_anchor_eas=(),
            target_eas=(0x40D381,),
            selector_state_var_reg=28,
            resolver_kind="static_fixpoint",
        ),
    )

    assert _static_native_bootstrap_route_candidates(
        graph,
        transfers,
        native_route_resolver=lambda source_ea, state_reg, state_constant: (
            handler_ea
            if (source_ea, state_reg, state_constant) == (source_anchor_ea, 28, state)
            else None
        ),
    ) == ((source_anchor_ea, state, handler_ea),)


def test_flowchart_preflight_discovers_bootstrap_evidence_before_its_redo(
    monkeypatch,
):
    session, state = _resolver_session()
    state.native_preanalysis.mark_evidence_changed(
        evidence_family="test_evidence",
        reason="test evidence changed",
    )
    state.begin_materialization(object())
    monkeypatch.setattr(
        computed_goto_resolver,
        "discover_static_native_bootstrap_routes",
        lambda _function_ea, _state: True,
    )
    decision = {"session": session}

    computed_goto_resolver._on_flowchart_preanalysis(
        function_ea=0x401000,
        mba=object(),
        decision=decision,
    )

    assert decision == {
        "session": session,
        "request_redo": True,
        "reason": "computed_goto_bootstrap_route",
        "details": {
            "function_ea": 0x401000,
            "evidence_generation": 1,
        },
    }

    retry = {"session": session}
    computed_goto_resolver._on_flowchart_preanalysis(
        function_ea=0x401000,
        mba=object(),
        decision=retry,
    )
    assert retry == {"session": session}


def test_native_tail_state_scan_does_not_cross_block_start(monkeypatch):
    import idautils

    scanned_ranges: list[tuple[int, int]] = []

    def record_heads(start_ea: int, end_ea: int):
        scanned_ranges.append((int(start_ea), int(end_ea)))
        return ()

    monkeypatch.setattr(idautils, "Heads", record_heads)
    block = BlockSnapshot(
        serial=100,
        block_type=1,
        succs=(316,),
        preds=(99,),
        flags=0,
        start_ea=0x40B157,
        insn_snapshots=(
            InsnSnapshot(opcode=0, ea=0x40B157, operands=()),
            InsnSnapshot(opcode=0, ea=0xF1C0072C, operands=()),
        ),
    )

    assert (
        _native_final_state_write_before_live_tail(
            block,
            state_var_reg=20,
            incoming_state=0xCCEC5DE0,
        )
        is None
    )
    assert (0x40B157, 0x40B158) in scanned_ranges


def test_function_context_register_values_require_one_non_top_singleton():
    states = {
        0x1000: {},
        0x1010: {"esi": frozenset({0xFDEE1C81}), "edx": frozenset({0x48B744})},
        0x1020: {"esi": frozenset({0xFDEE1C81}), "edx": None},
        0x1030: {"esi": frozenset({0xFDEE1C81}), "eax": frozenset({1, 2})},
    }

    assert _function_context_register_values(states) == (("esi", 0xFDEE1C81),)


def test_static_handler_entry_route_is_an_exact_state_target() -> None:
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x40D381,
        source_block_ea=0x40D381,
        materialized_anchor_eas=(),
        target_eas=(0x40D48E,),
        selector_state_var_reg=28,
        selector_state_constant=0x81F82C5E,
        resolver_kind="static_handler_entry_route",
    )

    assert _unique_static_equality_handler_targets((transfer,), 28) == {
        0x81F82C5E: 0x40D48E,
    }


def test_static_handler_exit_route_maps_exact_state_to_final_handler() -> None:
    entry_routes = (
        MaterializedIndirectTransfer(
            source_jmp_ea=0x401000,
            source_block_ea=0x401000,
            materialized_anchor_eas=(),
            target_eas=(0x405000,),
            selector_state_var_reg=20,
            selector_state_constant=0x11111111,
            resolver_kind="static_handler_entry_route",
        ),
        MaterializedIndirectTransfer(
            source_jmp_ea=0x401100,
            source_block_ea=0x401100,
            materialized_anchor_eas=(),
            target_eas=(0x406000,),
            selector_state_var_reg=20,
            selector_state_constant=0x22222222,
            resolver_kind="static_handler_entry_route",
        ),
    )
    terminal = MaterializedIndirectTransfer(
        source_jmp_ea=0x405030,
        source_block_ea=0x405000,
        materialized_anchor_eas=(),
        target_eas=(0x407000,),
        source_register_values=((20, 0x22222222), (28, 0x407000)),
        resolver_kind="detached_static_fixpoint",
    )

    (route,) = computed_goto_resolver._resolve_static_handler_exit_routes(
        (terminal,),
        entry_routes,
    )

    assert route.source_block_ea == 0x405000
    assert route.source_jmp_ea == 0x405030
    assert route.target_eas == (0x406000,)
    assert route.selector_state_var_reg == 20
    assert route.selector_state_constant == 0x22222222
    assert route.dispatcher_envelope_target_eas == (0x407000,)
    assert route.resolver_kind == "static_handler_exit_route"


def test_static_handler_exit_routes_abstain_on_ambiguous_state_register() -> None:
    entry_routes = tuple(
        MaterializedIndirectTransfer(
            source_jmp_ea=0x401000 + register,
            source_block_ea=0x401000 + register,
            materialized_anchor_eas=(),
            target_eas=(0x405000 + register,),
            selector_state_var_reg=register,
            selector_state_constant=0x11111111,
            resolver_kind="static_handler_entry_route",
        )
        for register in (20, 28)
    )

    assert (
        computed_goto_resolver._resolve_static_handler_exit_routes(
            (),
            entry_routes,
        )
        == ()
    )


def test_exact_handler_exit_route_replaces_dispatcher_cut_target() -> None:
    dispatcher_cut = MaterializedIndirectTransfer(
        source_jmp_ea=0x405030,
        source_block_ea=0x405000,
        materialized_anchor_eas=(),
        target_eas=(0x407000,),
        resolver_kind="static_fixpoint",
    )
    exact_route = MaterializedIndirectTransfer(
        source_jmp_ea=0x405030,
        source_block_ea=0x405000,
        materialized_anchor_eas=(),
        target_eas=(0x406000,),
        selector_state_var_reg=20,
        selector_state_constant=0x22222222,
        resolver_kind="static_handler_exit_route",
    )

    assert computed_goto_resolver._resolver_targets_by_source(
        (dispatcher_cut, exact_route)
    ) == {0x405030: (0x406000,)}


def test_connected_fixpoint_snapshot_recovers_final_handler_route(monkeypatch) -> None:
    plan = _PatchPlan(
        jmp_ea=0x405030,
        block_entry=0x405000,
        patch_start=0x405020,
        patch_bytes=b"\x90",
        region_end=0x405032,
        insn_heads=(0x405020,),
        new_block_eas=(),
        target_eas=(0x407000,),
    )
    resolution = ComputedGotoResolution(
        function_ea=0x401000,
        jmp_targets={0x405030: (0x407000,)},
        reachable_eas=(0x401000, 0x405000),
        arch="x86",
        executed_insns=10,
        seeds_run=0,
        patch_plans=(plan,),
        corridor_register_snapshots=((0x405000, (("ebx", 0x11111111),)),),
    )
    entry_routes = (
        MaterializedIndirectTransfer(
            source_jmp_ea=0x401000,
            source_block_ea=0x401000,
            materialized_anchor_eas=(),
            target_eas=(0x406000,),
            selector_state_var_reg=20,
            selector_state_constant=0x22222222,
            resolver_kind="static_handler_entry_route",
        ),
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "_native_register_mreg",
        lambda name: 20 if name == "ebx" else None,
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "_static_register_state_before_jmp",
        lambda block_entry, state, jmp_ea: {
            **state,
            "ebx": frozenset({0x22222222}),
        },
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "_residual_context_mregs",
        lambda values: {20: dict(values)["ebx"]},
    )

    (route,) = computed_goto_resolver._recover_connected_static_handler_exit_routes(
        resolution,
        entry_routes,
    )

    assert route.source_block_ea == 0x405000
    assert route.source_jmp_ea == 0x405030
    assert route.target_eas == (0x406000,)
    assert route.selector_state_constant == 0x22222222
    assert route.source_register_values == ((20, 0x22222222),)


def test_static_state_write_delivery_selects_last_matching_native_write() -> None:
    insn = computed_goto_resolver._DecodedStateRouteInstruction
    decoded = (
        insn(0x40A5A6, 0x40A5AC, "mov", 16, True, 0x11111111),
        insn(0x40A5B2, 0x40A5B8, "mov", 16, True, 0xABB95547),
        insn(0x40A5B8, 0x40A5C2, "lea", 0, True, None),
        insn(0x40A5C2, 0x40A5C8, "add", 0, True, None),
        insn(0x40A5C8, 0x40A5CA, "jmp", None, False, None),
    )

    assert computed_goto_resolver._select_static_state_write_delivery(
        decoded,
        state_var_reg=16,
        state_constant=0xABB95547,
        delivery_ea=0x40A5C8,
    ) == (
        0x40A5B2,
        (0x40A5B2, 0x40A5B8, 0x40A5C2, 0x40A5C8),
    )


def test_static_state_write_delivery_rejects_conditional_corridor() -> None:
    insn = computed_goto_resolver._DecodedStateRouteInstruction
    decoded = (
        insn(0x401000, 0x401006, "mov", 16, True, 0x12345678),
        insn(0x401006, 0x401008, "jnz", None, False, None),
        insn(0x401008, 0x40100A, "jmp", None, False, None),
    )

    assert (
        computed_goto_resolver._select_static_state_write_delivery(
            decoded,
            state_var_reg=16,
            state_constant=0x12345678,
            delivery_ea=0x401008,
        )
        is None
    )


def test_immediate_native_state_routes_preserve_each_source_site() -> None:
    insn = computed_goto_resolver._DecodedNativeFlowInstruction
    decoded = (
        insn(0x401000, 0x401006, "mov", 16, True, 0x11111111),
        insn(0x401006, 0x40100C, "cmp", 16, False, 0x22222222),
        insn(0x40100C, 0x40100E, "jne", None, False, None, 0x401030),
        insn(0x401020, 0x401026, "mov", 16, True, 0x11111111),
        insn(0x401026, 0x40102C, "cmp", 16, False, 0x33333333),
        insn(0x40102C, 0x40102E, "je", None, False, None, 0x401040),
    )

    routes = computed_goto_resolver._discover_immediate_native_state_routes(
        decoded,
        state_var_reg=16,
        state_targets={0x11111111: 0x402000},
    )

    assert tuple(route.source_write_ea for route in routes) == (0x401000, 0x401020)
    assert tuple(route.delivery_ea for route in routes) == (0x40100C, 0x40102C)
    assert {route.target_ea for route in routes} == {0x402000}
    assert routes[0].corridor_instruction_eas == (
        0x401000,
        0x401006,
        0x40100C,
    )


def test_immediate_native_state_routes_accept_bootstrap_jump() -> None:
    insn = computed_goto_resolver._DecodedNativeFlowInstruction
    decoded = (
        insn(0x401000, 0x401006, "mov", 16, True, 0x11111111),
        insn(0x401006, 0x40100B, "jmp", None, False, None, 0x401100),
    )

    (route,) = computed_goto_resolver._discover_immediate_native_state_routes(
        decoded,
        state_var_reg=16,
        state_targets={0x11111111: 0x402000},
    )

    assert route.source_write_ea == 0x401000
    assert route.delivery_ea == 0x401006
    assert route.corridor_instruction_eas == (0x401000, 0x401006)


def test_immediate_native_state_routes_abstain_on_branch_staging() -> None:
    insn = computed_goto_resolver._DecodedNativeFlowInstruction
    decoded = (
        insn(0x401000, 0x401006, "mov", 16, True, 0x11111111),
        insn(0x401006, 0x401008, "jne", None, False, None, 0x401010),
        insn(0x401008, 0x40100E, "mov", 16, True, 0x22222222),
        insn(0x401010, 0x401016, "cmp", 16, False, 0x44444444),
        insn(0x401016, 0x401018, "jne", None, False, None, 0x401040),
    )

    routes = computed_goto_resolver._discover_immediate_native_state_routes(
        decoded,
        state_var_reg=16,
        state_targets={0x11111111: 0x402000, 0x22222222: 0x403000},
    )

    assert routes == ()


def test_static_state_write_routes_publish_before_live_mba(monkeypatch) -> None:
    plan = _PatchPlan(
        jmp_ea=0x40A5C8,
        block_entry=0x40A5A6,
        patch_start=0x40A5C8,
        patch_bytes=b"\x90",
        region_end=0x40A5CD,
        insn_heads=(0x40A5C8,),
        new_block_eas=(),
        target_eas=(0x40B000,),
    )
    resolution = ComputedGotoResolution(
        function_ea=0x40A560,
        jmp_targets={0x40A5C8: (0x40B000,)},
        reachable_eas=(0x40A560, 0x40A5A6),
        arch="x86",
        executed_insns=10,
        seeds_run=0,
        patch_plans=(plan,),
    )
    route = MaterializedIndirectTransfer(
        source_jmp_ea=0x40BEB2,
        source_block_ea=0x40BEB2,
        materialized_anchor_eas=(),
        target_eas=(0x40BECC,),
        selector_state_var_reg=16,
        selector_state_constant=0xABB95547,
        resolver_kind="static_handler_entry_route",
    )
    decoded = (
        computed_goto_resolver._DecodedStateRouteInstruction(
            0x40A5B2, 0x40A5B8, "mov", 16, True, 0xABB95547
        ),
        computed_goto_resolver._DecodedStateRouteInstruction(
            0x40A5C8, 0x40A5CA, "jmp", None, False, None
        ),
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "_decode_static_state_route_corridor",
        lambda _start_ea, _delivery_ea: decoded,
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "_decode_native_flow_route_inventory",
        lambda *_args: (),
    )
    _session, state = _resolver_session(resolution)

    (evidence,) = computed_goto_resolver._discover_static_state_write_routes(
        state,
        resolution,
        (route,),
    )

    assert evidence.source_write_ea == 0x40A5B2
    assert evidence.delivery_ea == 0x40A5C8
    assert evidence.delivery_region_start_ea == 0x40A5C8
    assert evidence.target_ea == 0x40BECC
    assert evidence.corridor_instruction_eas == (0x40A5B2, 0x40A5C8)
    assert state.portable_evidence.state_write_routes == (evidence,)
    assert state.evidence_generation == 1


def test_static_state_write_routes_include_direct_dispatcher_delivery(
    monkeypatch,
) -> None:
    resolution = ComputedGotoResolution(
        function_ea=0x40A560,
        jmp_targets={},
        reachable_eas=(0x40A560, 0x40A5C8),
        arch="x86",
        executed_insns=10,
        seeds_run=0,
        patch_plans=(),
    )
    route = MaterializedIndirectTransfer(
        source_jmp_ea=0x40BEB2,
        source_block_ea=0x40BEB2,
        materialized_anchor_eas=(),
        target_eas=(0x40BECC,),
        selector_state_var_reg=16,
        selector_state_constant=0xABB95547,
        resolver_kind="static_handler_entry_route",
        dispatcher_router_eas=(0x40A5F0,),
    )
    decoded = (
        computed_goto_resolver._DecodedStateRouteInstruction(
            0x40A5B2, 0x40A5B7, "mov", 16, True, 0xABB95547
        ),
        computed_goto_resolver._DecodedStateRouteInstruction(
            0x40A5C8, 0x40A5CA, "jmp", None, False, None
        ),
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "_native_direct_dispatch_delivery_sites",
        lambda *_args, **_kwargs: (
            computed_goto_resolver._NativeStateRouteDeliverySite(
                0x40A59D,
                0x40A5C8,
                0x40A5C8,
                0x40A5CA,
            ),
        ),
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "_decode_static_state_route_corridor",
        lambda _start_ea, _delivery_ea: decoded,
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "_decode_native_flow_route_inventory",
        lambda *_args: (),
    )
    _session, state = _resolver_session(resolution)

    (evidence,) = computed_goto_resolver._discover_static_state_write_routes(
        state,
        resolution,
        (route,),
    )

    assert evidence.source_write_ea == 0x40A5B2
    assert evidence.delivery_ea == 0x40A5C8
    assert evidence.delivery_region_start_ea == 0x40A5C8
    assert evidence.delivery_region_end_ea == 0x40A5CA
    assert evidence.target_ea == 0x40BECC


def test_static_state_write_routes_publish_immediate_native_inventory(
    monkeypatch,
) -> None:
    resolution = ComputedGotoResolution(
        function_ea=0x40A560,
        jmp_targets={},
        reachable_eas=(0x40A560, 0x40A5C8),
        arch="x86",
        executed_insns=10,
        seeds_run=0,
        patch_plans=(),
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x40BEB2,
        source_block_ea=0x40BEB2,
        materialized_anchor_eas=(),
        target_eas=(0x40BECC,),
        selector_state_var_reg=16,
        selector_state_constant=0xABB95547,
        resolver_kind="static_handler_entry_route",
    )
    insn = computed_goto_resolver._DecodedNativeFlowInstruction
    monkeypatch.setattr(
        computed_goto_resolver,
        "_decode_native_flow_route_inventory",
        lambda *_args: (
            insn(0x40A5B2, 0x40A5B8, "mov", 16, True, 0xABB95547),
            insn(0x40A5B8, 0x40A5BE, "cmp", 16, False, 0x11111111),
            insn(0x40A5BE, 0x40A5C0, "jne", None, False, None, 0x40A5F0),
        ),
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "_native_direct_dispatch_delivery_sites",
        lambda *_args, **_kwargs: (),
    )
    _session, state = _resolver_session(resolution)

    (evidence,) = computed_goto_resolver._discover_static_state_write_routes(
        state,
        resolution,
        (transfer,),
    )

    assert evidence.source_write_ea == 0x40A5B2
    assert evidence.delivery_ea == 0x40A5BE
    assert evidence.delivery_region_end_ea == 0x40A5C0
    assert evidence.target_ea == 0x40BECC
    assert evidence.proof_kind is StateWriteRouteProofKind.STATE_ASSIGNMENT
    assert evidence.delivery_kind is StateWriteRouteDeliveryKind.DIRECT_TARGET


def test_static_conditional_state_choice_maps_both_unique_handler_arms() -> None:
    choice = _make_static_conditional_state_choice(
        source_block_ea=0x40D252,
        compare_ea=0x40D256,
        select_ea=0x40D266,
        condition_code=12,
        predicate_register=20,
        predicate_size=4,
        predicate_constant=0x113,
        true_values=frozenset({0xB13A6E93}),
        false_values=frozenset({0x4D34CF70}),
    )
    assert choice is not None
    routes = (
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40DAA3,
            source_block_ea=0x40DAA3,
            materialized_anchor_eas=(),
            target_eas=(0x40DABB,),
            selector_state_var_reg=28,
            selector_state_constant=0xB13A6E93,
            resolver_kind="static_handler_entry_route",
        ),
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40F1F1,
            source_block_ea=0x40F1F1,
            materialized_anchor_eas=(),
            target_eas=(0x40F20B,),
            selector_state_var_reg=28,
            selector_state_constant=0x4D34CF70,
            resolver_kind="static_handler_entry_route",
        ),
    )

    assert _resolve_static_conditional_state_choice_targets((choice,), routes) == (
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40D266,
            source_block_ea=0x40D252,
            materialized_anchor_eas=(0x40D256, 0x40D266),
            target_eas=(0x40DABB, 0x40F20B),
            condition_code=12,
            true_target_ea=0x40DABB,
            false_target_ea=0x40F20B,
            selector_state_var_reg=28,
            predicate_register=20,
            predicate_size=4,
            predicate_compare_constant=0x113,
            predicate_true_state=0xB13A6E93,
            predicate_false_state=0x4D34CF70,
            predicate_true_is_taken=True,
            predicate_preserve_live=True,
            resolver_kind="static_conditional_state_choice_bridge",
        ),
    )


def test_branch_state_choice_recovers_default_and_overriding_dispatch_states() -> None:
    choices = _branch_state_choice_candidates(
        source_block_ea=0x40E1F6,
        predicate_ea=0x40E20E,
        condition_code=4,
        source_state={
            "ebp": frozenset({0x85AE90D3}),
            "eax": frozenset({0x11111111}),
        },
        taken_state={
            "ebp": frozenset({0x3AF41FBE}),
            "eax": frozenset({0x22222222}),
        },
        fallthrough_state={
            "ebp": frozenset({0x85AE90D3}),
            "eax": frozenset({0x33333333}),
        },
        taken_resolved_target_ea=0x40E5C0,
        fallthrough_resolved_target_ea=0x40D381,
        register_mregs={"eax": 8, "ebp": 28},
    )

    assert choices == (
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40E20E,
            source_block_ea=0x40E1F6,
            materialized_anchor_eas=(0x40E20E,),
            target_eas=(),
            condition_code=4,
            selector_state_var_reg=28,
            predicate_true_state=0x3AF41FBE,
            predicate_false_state=0x85AE90D3,
            resolver_kind="static_conditional_state_choice",
        ),
    )


@pytest.mark.parametrize(
    ("source_values", "taken_values", "fallthrough_values", "taken_frontier"),
    (
        (frozenset({1, 2}), frozenset({3}), frozenset({1}), 0x2000),
        (frozenset({1}), frozenset({2}), frozenset({3}), 0x2000),
        (frozenset({1}), frozenset({2}), frozenset({1}), 0),
    ),
)
def test_branch_state_choice_abstains_without_exact_default_or_frontiers(
    source_values: frozenset[int],
    taken_values: frozenset[int],
    fallthrough_values: frozenset[int],
    taken_frontier: int,
) -> None:
    assert (
        _branch_state_choice_candidates(
            source_block_ea=0x1000,
            predicate_ea=0x1010,
            condition_code=4,
            source_state={"ebp": source_values},
            taken_state={"ebp": taken_values},
            fallthrough_state={"ebp": fallthrough_values},
            taken_resolved_target_ea=taken_frontier,
            fallthrough_resolved_target_ea=0x3000,
            register_mregs={"ebp": 28},
        )
        == ()
    )


def test_static_stack_carried_choice_defers_source_bridge_and_rebases_consumer() -> (
    None
):
    store_ea = 0x40D269
    consumer_load_ea = 0x40EAA7
    carrier_displacement = 0x44
    choice = _make_static_conditional_state_choice(
        source_block_ea=0x40D252,
        compare_ea=0x40D256,
        select_ea=0x40D266,
        condition_code=12,
        predicate_register=20,
        predicate_size=4,
        predicate_constant=0x113,
        true_values=frozenset({0xB13A6E93}),
        false_values=frozenset({0x4D34CF70}),
        state_carrier_store_ea=store_ea,
        state_carrier_stack_displacement=carrier_displacement,
    )
    assert choice is not None
    routes = (
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40DAA3,
            source_block_ea=0x40DAA3,
            materialized_anchor_eas=(),
            target_eas=(0x40DABB,),
            selector_state_var_reg=28,
            selector_state_constant=0xB13A6E93,
            resolver_kind="static_handler_entry_route",
        ),
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40F1F1,
            source_block_ea=0x40F1F1,
            materialized_anchor_eas=(),
            target_eas=(0x40F20B,),
            selector_state_var_reg=28,
            selector_state_constant=0x4D34CF70,
            resolver_kind="static_handler_entry_route",
        ),
    )

    resolved = _resolve_static_conditional_state_choice_targets((choice,), routes)

    assert len(resolved) == 1
    assert resolved[0].resolver_kind == "static_stack_carried_state_choice"
    assert resolved[0].source_jmp_ea == 0x40D266
    assert resolved[0].state_carrier_store_ea == store_ea
    assert resolved[0].state_carrier_stack_displacement == carrier_displacement
    assert resolved[0].target_eas == (0x40DABB, 0x40F20B)
    assert computed_goto_resolver._static_stack_carrier_frame_offset_overrides(
        (choice,),
        consumer_load_eas_by_displacement={
            carrier_displacement: (consumer_load_ea,),
        },
        native_stack_frame_offsets_by_ea={
            store_ea: (84,),
            consumer_load_ea: (220,),
        },
    ) == {consumer_load_ea: (84,)}


def test_static_stack_carried_choice_binds_native_consumer_identity() -> None:
    store_ea = 0x40D269
    consumer_load_ea = 0x40EAA7
    carrier_displacement = 0x44
    choice = _make_static_conditional_state_choice(
        source_block_ea=0x40D252,
        compare_ea=0x40D256,
        select_ea=0x40D266,
        condition_code=12,
        predicate_register=20,
        predicate_size=4,
        predicate_constant=0x113,
        true_values=frozenset({0xB13A6E93}),
        false_values=frozenset({0x4D34CF70}),
        state_carrier_store_ea=store_ea,
        state_carrier_stack_displacement=carrier_displacement,
    )
    assert choice is not None

    (bound,) = computed_goto_resolver._bind_static_stack_carrier_consumers(
        (choice,),
        consumer_load_eas_by_displacement={
            carrier_displacement: (consumer_load_ea,),
        },
        native_stack_frame_offsets_by_ea={store_ea: (84,)},
    )

    assert bound.state_carrier_consumer_load_eas == (consumer_load_ea,)
    assert bound.state_carrier_ida_stkoff == 84


def test_static_stack_carried_choice_recognizes_test_zero_cmov_store(
    monkeypatch,
) -> None:
    """Treat ``test reg, reg`` as the zero predicate feeding a CMOV choice."""
    register_ids = {
        name: reg for reg, name in computed_goto_resolver._SV_REG_NAMES.items()
    }
    eax = register_ids["eax"]
    ecx = register_ids["ecx"]
    edi = register_ids["edi"]
    esp = register_ids["esp"]

    idaapi = ModuleType("idaapi")
    idaapi.o_void = 0
    idaapi.o_reg = 1
    idaapi.o_imm = 2
    idaapi.o_displ = 4
    idaapi.CF_CHG1 = 0x2
    mnemonics = {
        0x40D215: "test",
        0x40D217: "mov",
        0x40D21C: "mov",
        0x40D221: "cmovz",
        0x40D224: "mov",
        0x40D228: "jmp",
    }
    idaapi.print_insn_mnem = lambda ea: mnemonics.get(int(ea), "")
    monkeypatch.setitem(sys.modules, "idaapi", idaapi)
    monkeypatch.setattr(computed_goto_resolver, "idaapi", idaapi)

    class Operand:
        def __init__(
            self,
            kind=0,
            *,
            reg=0,
            value=0,
            phrase=0,
            addr=0,
        ):
            self.type = kind
            self.reg = reg
            self.value = value
            self.phrase = phrase
            self.addr = addr

    class Instruction:
        def __init__(self):
            self.ops = [Operand(), Operand()]
            self._feature = 0

        def get_canon_feature(self) -> int:
            return self._feature

    encoded = {
        0x40D215: (
            2,
            0,
            Operand(idaapi.o_reg, reg=edi),
            Operand(idaapi.o_reg, reg=edi),
        ),
        0x40D217: (
            5,
            idaapi.CF_CHG1,
            Operand(idaapi.o_reg, reg=ecx),
            Operand(idaapi.o_imm, value=0x142718FC),
        ),
        0x40D21C: (
            5,
            idaapi.CF_CHG1,
            Operand(idaapi.o_reg, reg=eax),
            Operand(idaapi.o_imm, value=0xF6D08EC5),
        ),
        0x40D221: (
            3,
            idaapi.CF_CHG1,
            Operand(idaapi.o_reg, reg=eax),
            Operand(idaapi.o_reg, reg=ecx),
        ),
        0x40D224: (
            4,
            idaapi.CF_CHG1,
            Operand(idaapi.o_displ, reg=esp, phrase=esp, addr=0x4C),
            Operand(idaapi.o_reg, reg=eax),
        ),
        0x40D228: (2, 0, Operand(), Operand()),
    }

    ida_ua = ModuleType("ida_ua")
    ida_ua.insn_t = Instruction

    def decode_insn(insn, ea):
        length, feature, op0, op1 = encoded[int(ea)]
        insn._feature = feature
        insn.ops = [op0, op1]
        return length

    ida_ua.decode_insn = decode_insn
    monkeypatch.setitem(sys.modules, "ida_ua", ida_ua)

    ida_bytes = ModuleType("ida_bytes")
    ida_bytes.get_bytes = lambda ea, size: (
        b"\x0f\x44\xc1" if int(ea) == 0x40D221 else b"\x90" * int(size)
    )
    monkeypatch.setitem(sys.modules, "ida_bytes", ida_bytes)

    monkeypatch.setattr(
        computed_goto_resolver,
        "_native_register_mreg",
        lambda name: 36 if name == "edi" else None,
    )

    assert computed_goto_resolver._static_conditional_state_choices({0x40D215: {}}) == (
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40D221,
            source_block_ea=0x40D215,
            materialized_anchor_eas=(0x40D215, 0x40D221, 0x40D224),
            target_eas=(),
            condition_code=4,
            predicate_register=36,
            predicate_size=4,
            predicate_compare_constant=0,
            predicate_true_state=0x142718FC,
            predicate_false_state=0xF6D08EC5,
            resolver_kind="static_conditional_state_choice",
            state_carrier_store_ea=0x40D224,
            state_carrier_stack_displacement=0x4C,
        ),
    )


def test_static_materialized_transfer_batch_persists_conditional_state_choice() -> None:
    store_ea = 0x40D269
    consumer_load_ea = 0x40EAA7
    choice = _make_static_conditional_state_choice(
        source_block_ea=0x40D252,
        compare_ea=0x40D256,
        select_ea=0x40D266,
        condition_code=12,
        predicate_register=20,
        predicate_size=4,
        predicate_constant=0x113,
        true_values=frozenset({0xB13A6E93}),
        false_values=frozenset({0x4D34CF70}),
        state_carrier_store_ea=store_ea,
        state_carrier_stack_displacement=0x44,
    )
    assert choice is not None
    (choice,) = computed_goto_resolver._bind_static_stack_carrier_consumers(
        (choice,),
        consumer_load_eas_by_displacement={0x44: (consumer_load_ea,)},
        native_stack_frame_offsets_by_ea={store_ea: (84,)},
    )
    resolution = ComputedGotoResolution(
        function_ea=0x40D200,
        jmp_targets={},
        reachable_eas=(),
        arch="x86",
        executed_insns=0,
        seeds_run=0,
        conditional_state_choices=(choice,),
    )
    true_route = MaterializedIndirectTransfer(
        source_jmp_ea=0x40DAA3,
        source_block_ea=0x40DAA3,
        materialized_anchor_eas=(),
        target_eas=(0x40DABB,),
        selector_state_var_reg=28,
        selector_state_constant=0xB13A6E93,
        resolver_kind="static_handler_entry_route",
    )
    false_route = MaterializedIndirectTransfer(
        source_jmp_ea=0x40F1F1,
        source_block_ea=0x40F1F1,
        materialized_anchor_eas=(),
        target_eas=(0x40F20B,),
        selector_state_var_reg=28,
        selector_state_constant=0x4D34CF70,
        resolver_kind="static_handler_entry_route",
    )

    batch = computed_goto_resolver._static_materialized_transfer_batch(
        resolution,
        static_transfers=(),
        equality_transfers=(),
        static_handler_entry_routes=(true_route,),
        native_handler_entry_routes=(false_route,),
    )

    assert batch[-1].resolver_kind == "static_stack_carried_state_choice"
    assert batch[-1].target_eas == (0x40DABB, 0x40F20B)
    assert batch[-1].predicate_register == 20
    assert batch[-1].state_carrier_consumer_load_eas == (consumer_load_ea,)
    assert batch[-1].state_carrier_ida_stkoff == 84


def test_static_conditional_state_choice_abstains_on_ambiguous_or_missing_arm() -> None:
    choice = _make_static_conditional_state_choice(
        source_block_ea=0x1000,
        compare_ea=0x1004,
        select_ea=0x100E,
        condition_code=12,
        predicate_register=28,
        predicate_size=4,
        predicate_constant=0x113,
        true_values=frozenset({0x11111111}),
        false_values=frozenset({0x22222222}),
    )
    assert choice is not None
    ambiguous_routes = (
        MaterializedIndirectTransfer(
            source_jmp_ea=0x2000,
            source_block_ea=0x2000,
            materialized_anchor_eas=(),
            target_eas=(0x3000,),
            selector_state_var_reg=28,
            selector_state_constant=0x11111111,
            resolver_kind="static_handler_entry_route",
        ),
        MaterializedIndirectTransfer(
            source_jmp_ea=0x2010,
            source_block_ea=0x2010,
            materialized_anchor_eas=(),
            target_eas=(0x3010,),
            selector_state_var_reg=28,
            selector_state_constant=0x11111111,
            resolver_kind="static_handler_entry_route",
        ),
    )

    assert (
        _resolve_static_conditional_state_choice_targets((choice,), ambiguous_routes)
        == ()
    )


def test_zero_arg_call_type_requires_profile_and_first_access_clobbers() -> None:
    assert _zero_arg_call_type_is_proven(
        profile_owned=True,
        direct_call=True,
        has_operand_type=False,
        has_callee_type=False,
        guessed_arg_count=0,
        callee_argsize=0,
        first_fastcall_register_accesses=("write", "write"),
    )


def test_zero_arg_call_type_abstains_on_register_read_or_existing_type() -> None:
    common = {
        "profile_owned": True,
        "direct_call": True,
        "has_operand_type": False,
        "has_callee_type": False,
        "guessed_arg_count": 0,
        "callee_argsize": 0,
    }

    assert not _zero_arg_call_type_is_proven(
        **common,
        first_fastcall_register_accesses=("write", "read"),
    )
    assert not _zero_arg_call_type_is_proven(
        **{**common, "has_callee_type": True},
        first_fastcall_register_accesses=("write", "write"),
    )


def test_build_callinfo_applies_proven_three_argument_stdcall(monkeypatch) -> None:
    import ida_hexrays
    import ida_nalt

    function_ea = 0x1000
    call_ea = 0x1030
    reentry_ea = 0x2020
    resolution = ComputedGotoResolution(
        function_ea=function_ea,
        jmp_targets={reentry_ea: (0x3000,)},
        reachable_eas=(),
        arch="x86",
        executed_insns=0,
        seeds_run=0,
    )
    session, _state = _resolver_session(resolution)
    monkeypatch.setattr(ida_nalt, "get_op_tinfo", lambda *_args: False)
    monkeypatch.setattr(
        computed_goto_resolver,
        "native_call_stack_deficit",
        lambda _block, _call_ea: 12,
        raising=False,
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "native_corridor_has_no_stack_adjustment",
        lambda _call_ea, _reentry_eas: True,
        raising=False,
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "collect_three_argument_callee_purged_evidence",
        lambda *_args, **_kwargs: StackCallAbiEvidence(
            word_size=4,
            outgoing_stack_offsets=(-12, -8, -4),
            call_stack_deficit=12,
            argument_values_proven=True,
            continuation_is_linear=True,
            continuation_reaches_proven_reentry=True,
            caller_stack_adjustment=0,
            has_authoritative_type=False,
        ),
        raising=False,
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "prove_three_argument_callee_purged_call",
        lambda _evidence: StackCallAbiProof(3, 12),
        raising=False,
    )
    applied: list[StackCallAbiProof] = []
    monkeypatch.setattr(
        computed_goto_resolver,
        "apply_three_argument_stdcall_type",
        lambda _call_type, proof: not applied.append(proof),
        raising=False,
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "build_three_argument_stdcall_callinfo",
        lambda _block, _call_type, _proof: "prepared-callinfo",
        raising=False,
    )
    block = SimpleNamespace(
        mba=SimpleNamespace(qty=0),
        tail=SimpleNamespace(
            opcode=ida_hexrays.m_icall,
            ea=call_ea,
        ),
    )

    decision: dict[str, object] = {"callinfo": None, "session": session}
    _on_build_callinfo(
        function_ea=function_ea,
        block=block,
        call_type=object(),
        decision=decision,
    )

    assert applied == [StackCallAbiProof(3, 12)]
    assert decision["callinfo"] == "prepared-callinfo"


def test_build_callinfo_uses_native_ea_route_template_before_type_guessing(
    monkeypatch,
) -> None:
    import ida_hexrays

    function_ea = 0x1000
    imported_call_ea = 0xF10020
    native_call_ea = 0x2030
    resolution = ComputedGotoResolution(
        function_ea=function_ea,
        jmp_targets={},
        reachable_eas=(),
        arch="x86",
        executed_insns=0,
        seeds_run=0,
    )
    session, _state = _resolver_session(resolution)
    monkeypatch.setattr(
        computed_goto_resolver,
        "imported_detached_snippet_instruction_origins",
        lambda _mba: ((imported_call_ea, native_call_ea),),
    )

    def copied(_destination, _source):
        return True

    monkeypatch.setattr(computed_goto_resolver, "_copy_mcallinfo", copied)
    prepared = SimpleNamespace(args=(), call_spd=0, stkargs_top=0)
    calls: list[tuple[object, ...]] = []

    def prepare(*args: object, **kwargs: object) -> object:
        calls.append((*args, kwargs["copy_callinfo"]))
        return prepared

    monkeypatch.setattr(
        computed_goto_resolver,
        "prepare_detached_callinfo_template",
        prepare,
    )
    mba = SimpleNamespace(entry_ea=function_ea)
    raw_call = SimpleNamespace(
        opcode=ida_hexrays.m_call,
        ea=imported_call_ea,
        l=SimpleNamespace(t=ida_hexrays.mop_v, g=0x5000),
    )
    block = SimpleNamespace(tail=raw_call, mba=mba)
    decision: dict[str, object] = {"callinfo": None, "session": session}

    _on_build_callinfo(
        function_ea=function_ea,
        block=block,
        call_type=object(),
        decision=decision,
    )

    assert decision["callinfo"] is prepared
    assert calls == [
        (
            function_ea,
            native_call_ea,
            raw_call,
            mba,
            copied,
        )
    ]


def test_build_callinfo_does_not_replay_route_template_into_source_mba(
    monkeypatch,
) -> None:
    import ida_hexrays
    import ida_nalt

    profile_ea = 0x1000
    source_mba_ea = 0x2000
    native_call_ea = 0x2030
    resolution = ComputedGotoResolution(
        function_ea=profile_ea,
        jmp_targets={},
        reachable_eas=(),
        arch="x86",
        executed_insns=0,
        seeds_run=0,
    )
    session, _state = _resolver_session(resolution)
    monkeypatch.setattr(
        computed_goto_resolver,
        "imported_detached_snippet_instruction_origins",
        lambda _mba: (),
    )
    monkeypatch.setattr(ida_nalt, "get_op_tinfo", lambda *_args: True)
    monkeypatch.setattr(
        computed_goto_resolver,
        "_copy_mcallinfo",
        lambda _destination, _source: True,
    )
    replayed: list[tuple[object, ...]] = []

    def prepare(*args: object, **_kwargs: object) -> object:
        replayed.append(args)
        return SimpleNamespace(args=(), call_spd=0, stkargs_top=0)

    monkeypatch.setattr(
        computed_goto_resolver,
        "prepare_detached_callinfo_template",
        prepare,
    )
    mba = SimpleNamespace(entry_ea=source_mba_ea)
    block = SimpleNamespace(
        tail=SimpleNamespace(
            opcode=ida_hexrays.m_icall,
            ea=native_call_ea,
        ),
        mba=mba,
    )
    decision: dict[str, object] = {"callinfo": None, "session": session}

    _on_build_callinfo(
        function_ea=source_mba_ea,
        block=block,
        call_type=object(),
        decision=decision,
    )

    assert decision["callinfo"] is None
    assert replayed == []


def test_stkpnts_projects_native_spd_to_imported_and_call_eas(
    monkeypatch,
) -> None:
    import ida_frame
    import ida_funcs

    function_ea = 0x1000
    imported_call_ea = 0xF10020
    imported_body_ea = 0xF10024
    native_call_ea = 0x2030
    native_body_ea = 0x2034
    resolution = ComputedGotoResolution(
        function_ea=function_ea,
        jmp_targets={},
        reachable_eas=(),
        arch="x86",
        executed_insns=0,
        seeds_run=0,
    )
    session, _state = _resolver_session(resolution)
    monkeypatch.setattr(
        computed_goto_resolver,
        "imported_detached_snippet_instruction_origins",
        lambda _mba: (),
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "last_imported_detached_snippet_instruction_origins",
        lambda _function_ea: (
            (imported_call_ea, native_call_ea),
            (imported_body_ea, native_body_ea),
        ),
        raising=False,
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "detached_callinfo_template_eas",
        lambda _function_ea: (native_call_ea,),
        raising=False,
    )
    function = object()
    monkeypatch.setattr(
        ida_funcs,
        "get_func",
        lambda ea: function if int(ea) == function_ea else None,
    )
    spd_by_ea = {native_call_ea: -12, native_body_ea: -8}
    monkeypatch.setattr(
        ida_frame,
        "get_spd",
        lambda candidate, ea: spd_by_ea[int(ea)] if candidate is function else 0,
    )
    applied: list[tuple[object, int, int]] = []
    monkeypatch.setattr(
        computed_goto_resolver,
        "_upsert_stkpnt",
        lambda points, ea, spd: not applied.append((points, ea, spd)),
        raising=False,
    )
    stack_points = object()
    decision: dict[str, object] = {"session": session}

    computed_goto_resolver._on_stkpnts(
        function_ea=function_ea,
        mba=SimpleNamespace(entry_ea=function_ea, frsize=1168, frregs=0),
        stack_points=stack_points,
        decision=decision,
    )

    assert applied == [
        (stack_points, native_call_ea, -12),
        (stack_points, imported_call_ea, -12),
        (stack_points, imported_body_ea, -8),
    ]
    assert decision["stack_points_modified"] == 3


@pytest.mark.parametrize(
    ("native_call_spd", "expected_call_spd"),
    ((-1168, -1172), (-1172, -1172)),
)
def test_stkpnts_merges_detached_call_push_delta_exactly_once(
    monkeypatch,
    native_call_spd: int,
    expected_call_spd: int,
) -> None:
    import ida_frame
    import ida_funcs

    function_ea = 0x1000
    imported_call_ea = 0xF10020
    imported_body_ea = 0xF10024
    native_call_ea = 0x2030
    native_body_ea = 0x2034
    resolution = ComputedGotoResolution(
        function_ea=function_ea,
        jmp_targets={},
        reachable_eas=(),
        arch="x86",
        executed_insns=0,
        seeds_run=0,
    )
    session, _state = _resolver_session(resolution)
    session.identity_key = "diag-session"
    session.function_ea = function_ea
    session.current_mba_generation = 7
    monkeypatch.setattr(
        computed_goto_resolver,
        "imported_detached_snippet_instruction_origins",
        lambda _mba: (),
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "last_imported_detached_snippet_instruction_origins",
        lambda _function_ea: (
            (imported_call_ea, native_call_ea),
            (imported_body_ea, native_body_ea),
        ),
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "detached_callinfo_template_eas",
        lambda _function_ea: (),
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "detached_preopt_call_stack_points",
        lambda _function_ea: ((native_call_ea, -4),),
        raising=False,
    )
    function = object()
    monkeypatch.setattr(
        ida_funcs,
        "get_func",
        lambda ea: function if int(ea) == function_ea else None,
    )
    monkeypatch.setattr(
        ida_frame,
        "get_spd",
        lambda candidate, ea: (
            native_call_spd
            if candidate is function and int(ea) == native_call_ea
            else -1168 if candidate is function else 0
        ),
    )
    applied: list[tuple[object, int, int]] = []
    monkeypatch.setattr(
        computed_goto_resolver,
        "_upsert_stkpnt",
        lambda points, ea, spd: not applied.append((points, ea, spd)),
    )
    observed = []
    monkeypatch.setattr(
        computed_goto_resolver,
        "emit_diagnostic",
        observed.append,
    )
    stack_points = object()
    decision: dict[str, object] = {"session": session}

    computed_goto_resolver._on_stkpnts(
        function_ea=function_ea,
        mba=SimpleNamespace(entry_ea=function_ea, frsize=1168, frregs=0),
        stack_points=stack_points,
        decision=decision,
    )

    assert applied == [
        (stack_points, native_call_ea, expected_call_spd),
        (stack_points, imported_call_ea, expected_call_spd),
        (stack_points, imported_body_ea, -1168),
    ]
    assert decision == {"session": session, "stack_points_modified": 3}
    assert len(observed) == 1
    event = observed[0]
    assert event.event_kind == "stack_point_projection"
    assert event.session_id == "diag-session"
    assert event.evidence_generation == 0
    assert event.mba_generation_before == 7
    assert event.payload == {
        "capture_active": False,
        "points": [
            {
                "applied_spd": expected_call_spd,
                "canonical_spd": -1168,
                "live_ea": "0x2030",
                "native_ea": "0x2030",
                "native_spd": native_call_spd,
                "outcome": "applied",
                "reason": "merged",
                "route_call_delta": -4,
            },
            {
                "applied_spd": expected_call_spd,
                "canonical_spd": -1168,
                "live_ea": "0xf10020",
                "native_ea": "0x2030",
                "native_spd": native_call_spd,
                "outcome": "applied",
                "reason": "merged",
                "route_call_delta": -4,
            },
            {
                "applied_spd": -1168,
                "canonical_spd": None,
                "live_ea": "0xf10024",
                "native_ea": "0x2034",
                "native_spd": -1168,
                "outcome": "applied",
                "reason": "native_spd",
                "route_call_delta": None,
            },
        ],
    }


def test_stkpnts_projects_native_spd_into_isolated_capture_ranges(
    monkeypatch,
) -> None:
    import ida_bytes
    import ida_frame
    import ida_funcs
    import idautils

    profile_ea = 0x1000
    capture_entry_ea = 0x2000
    first_instruction_ea = 0x2010
    second_instruction_ea = 0x2014
    resolution = ComputedGotoResolution(
        function_ea=profile_ea,
        jmp_targets={},
        reachable_eas=(),
        arch="x86",
        executed_insns=0,
        seeds_run=0,
    )
    session, state = _resolver_session(resolution)
    assert state.begin_snippet_capture(profile_ea)

    class _Ranges(list):
        def size(self) -> int:
            return len(self)

    mba = SimpleNamespace(
        entry_ea=capture_entry_ea,
        mbr=SimpleNamespace(
            ranges=_Ranges(
                [SimpleNamespace(start_ea=first_instruction_ea, end_ea=0x2020)]
            )
        ),
    )
    monkeypatch.setattr(
        idautils,
        "Heads",
        lambda start_ea, end_ea: (
            (
                first_instruction_ea,
                second_instruction_ea,
            )
            if (int(start_ea), int(end_ea)) == (first_instruction_ea, 0x2020)
            else ()
        ),
    )
    monkeypatch.setattr(ida_bytes, "get_flags", lambda _ea: 1)
    monkeypatch.setattr(ida_bytes, "is_code", lambda flags: int(flags) == 1)
    function = object()
    monkeypatch.setattr(
        ida_funcs,
        "get_func",
        lambda ea: function if int(ea) == profile_ea else None,
    )
    spd_by_ea = {first_instruction_ea: -8, second_instruction_ea: -12}
    monkeypatch.setattr(
        ida_frame,
        "get_spd",
        lambda candidate, ea: spd_by_ea[int(ea)] if candidate is function else 0,
    )
    applied: list[tuple[object, int, int]] = []
    monkeypatch.setattr(
        computed_goto_resolver,
        "_upsert_stkpnt",
        lambda points, ea, spd: not applied.append((points, ea, spd)),
    )
    stack_points = object()
    decision: dict[str, object] = {"session": session}

    computed_goto_resolver._on_stkpnts(
        function_ea=capture_entry_ea,
        mba=mba,
        stack_points=stack_points,
        decision=decision,
    )

    assert applied == [
        (stack_points, first_instruction_ea, -8),
        (stack_points, second_instruction_ea, -12),
    ]
    assert decision["stack_points_modified"] == 2


def test_build_callinfo_reuses_proof_after_cfg_rewrite_hides_reentry(
    monkeypatch,
) -> None:
    import ida_hexrays
    import ida_nalt

    function_ea = 0x810000
    call_ea = 0x810030
    reentry_ea = 0x820020
    resolution = ComputedGotoResolution(
        function_ea=function_ea,
        jmp_targets={reentry_ea: (0x830000,)},
        reachable_eas=(),
        arch="x86",
        executed_insns=0,
        seeds_run=0,
    )
    session, _state = _resolver_session(resolution)
    monkeypatch.setattr(ida_nalt, "get_op_tinfo", lambda *_args: False)
    monkeypatch.setattr(
        computed_goto_resolver,
        "native_call_stack_deficit",
        lambda _block, _call_ea: 12,
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "native_corridor_has_no_stack_adjustment",
        lambda _call_ea, _reentry_eas: True,
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "collect_three_argument_callee_purged_evidence",
        lambda *_args, **_kwargs: StackCallAbiEvidence(
            word_size=4,
            outgoing_stack_offsets=(-12, -8, -4),
            call_stack_deficit=12,
            argument_values_proven=True,
            continuation_is_linear=False,
            continuation_reaches_proven_reentry=False,
            caller_stack_adjustment=0,
            has_authoritative_type=False,
        ),
    )
    proof_calls: list[StackCallAbiProof | None] = [
        StackCallAbiProof(3, 12),
        None,
    ]
    monkeypatch.setattr(
        computed_goto_resolver,
        "prove_three_argument_callee_purged_call",
        lambda _evidence: proof_calls.pop(0),
    )
    applied: list[StackCallAbiProof] = []
    monkeypatch.setattr(
        computed_goto_resolver,
        "apply_three_argument_stdcall_type",
        lambda _call_type, proof: not applied.append(proof),
    )
    prepared = [object(), object()]
    built: list[object] = []

    def build_callinfo(_block, _call_type, _proof):
        result = prepared[len(built)]
        built.append(result)
        return result

    monkeypatch.setattr(
        computed_goto_resolver,
        "build_three_argument_stdcall_callinfo",
        build_callinfo,
    )
    block = SimpleNamespace(
        mba=SimpleNamespace(qty=0),
        tail=SimpleNamespace(opcode=ida_hexrays.m_icall, ea=call_ea),
    )
    first: dict[str, object] = {"callinfo": None, "session": session}
    second: dict[str, object] = {"callinfo": None, "session": session}

    _on_build_callinfo(
        function_ea=function_ea,
        block=block,
        call_type=object(),
        decision=first,
    )
    _on_build_callinfo(
        function_ea=function_ea,
        block=block,
        call_type=object(),
        decision=second,
    )

    assert first["callinfo"] is prepared[0]
    assert second["callinfo"] is prepared[1]
    assert applied == [StackCallAbiProof(3, 12), StackCallAbiProof(3, 12)]
    assert proof_calls == [None]


def test_callinfo_reentry_accepts_only_exact_native_resolver_evidence() -> None:
    resolution = ComputedGotoResolution(
        function_ea=0x1000,
        jmp_targets={},
        reachable_eas=(),
        arch="x86",
        executed_insns=0,
        seeds_run=0,
    )
    exact = MaterializedIndirectTransfer(
        source_jmp_ea=0x2020,
        source_block_ea=0x2000,
        materialized_anchor_eas=(),
        target_eas=(0x3000,),
        resolver_kind="detached_static_fixpoint",
    )
    inferred = MaterializedIndirectTransfer(
        source_jmp_ea=0x4040,
        source_block_ea=0x4000,
        materialized_anchor_eas=(),
        target_eas=(0x5000,),
        resolver_kind="condition_chain_handler_evidence",
    )

    assert _proven_callinfo_reentry_eas(resolution, (exact, inferred)) == frozenset(
        {0x2020}
    )


def test_build_callinfo_derives_exact_detached_reentry_before_calls(
    monkeypatch,
) -> None:
    import ida_hexrays
    import ida_nalt

    function_ea = 0x1000
    call_ea = 0x1030
    reentry_ea = 0x2020
    resolution = ComputedGotoResolution(
        function_ea=function_ea,
        jmp_targets={0x4040: (0x5000,)},
        reachable_eas=(),
        arch="x86",
        executed_insns=0,
        seeds_run=0,
    )
    exact = MaterializedIndirectTransfer(
        source_jmp_ea=reentry_ea,
        source_block_ea=0x2000,
        materialized_anchor_eas=(),
        target_eas=(0x3000,),
        resolver_kind="detached_static_fixpoint",
    )
    session, state = _resolver_session(resolution)
    monkeypatch.setattr(ida_nalt, "get_op_tinfo", lambda *_args: False)
    monkeypatch.setattr(
        computed_goto_resolver,
        "_detached_static_terminal_transfers",
        lambda _resolution, entry_eas, *, entry_context_transfers=(): (
            (exact,) if entry_eas == (0x1010,) and entry_context_transfers == () else ()
        ),
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "native_call_stack_deficit",
        lambda _block, _call_ea: 12,
    )
    observed_reentries: list[frozenset[int]] = []

    def no_adjustment(_call_ea, reentry_eas):
        observed_reentries.append(reentry_eas)
        return True if reentry_ea in reentry_eas else None

    monkeypatch.setattr(
        computed_goto_resolver,
        "native_corridor_has_no_stack_adjustment",
        no_adjustment,
    )

    def evidence(_block, **kwargs):
        return StackCallAbiEvidence(
            word_size=4,
            outgoing_stack_offsets=(-12, -8, -4),
            call_stack_deficit=kwargs["call_stack_deficit"],
            argument_values_proven=True,
            continuation_is_linear=True,
            continuation_reaches_proven_reentry=True,
            caller_stack_adjustment=kwargs["caller_stack_adjustment"],
            has_authoritative_type=False,
        )

    monkeypatch.setattr(
        computed_goto_resolver,
        "collect_three_argument_callee_purged_evidence",
        evidence,
    )
    applied: list[StackCallAbiProof] = []
    monkeypatch.setattr(
        computed_goto_resolver,
        "apply_three_argument_stdcall_type",
        lambda _call_type, proof: not applied.append(proof),
    )
    prepared_callinfo = object()
    monkeypatch.setattr(
        computed_goto_resolver,
        "build_three_argument_stdcall_callinfo",
        lambda _block, _call_type, _proof: prepared_callinfo,
    )
    block = SimpleNamespace(
        mba=SimpleNamespace(qty=0),
        start=0x1010,
        tail=SimpleNamespace(opcode=ida_hexrays.m_icall, ea=call_ea),
    )
    decision: dict[str, object] = {"session": session}

    _on_build_callinfo(
        function_ea=function_ea,
        block=block,
        call_type=object(),
        decision=decision,
    )

    assert observed_reentries == [
        frozenset({0x4040}),
        frozenset({0x2020, 0x4040}),
    ]
    assert state.materialized_transfers == (exact,)
    assert applied == [StackCallAbiProof(3, 12)]
    assert decision["callinfo"] is prepared_callinfo


def test_callinfo_profile_rebinds_isolated_snippet_to_native_owner() -> None:
    resolution = ComputedGotoResolution(
        function_ea=0x1000,
        jmp_targets={0x2020: (0x3000,)},
        reachable_eas=(),
        arch="x86",
        executed_insns=0,
        seeds_run=0,
    )
    _session, state = _resolver_session(resolution)
    assert state.begin_snippet_capture(0x1000)

    assert _callinfo_profile_resolution(state, 0x1010, 0x1030) == (
        0x1000,
        resolution,
    )


def test_callinfo_profile_uses_active_detached_capture_owner() -> None:
    resolution = ComputedGotoResolution(
        function_ea=0x1000,
        jmp_targets={0x2020: (0x3000,)},
        reachable_eas=(),
        arch="x86",
        executed_insns=0,
        seeds_run=0,
    )
    _session, state = _resolver_session(resolution)
    assert state.begin_snippet_capture(0x1000)

    assert _callinfo_profile_resolution(state, 0x1010, 0x1030) == (
        0x1000,
        resolution,
    )


def test_build_callinfo_preserves_authoritative_indirect_type(monkeypatch) -> None:
    import ida_hexrays
    import ida_nalt

    function_ea = 0x1000
    resolution = ComputedGotoResolution(
        function_ea=function_ea,
        jmp_targets={0x2020: (0x3000,)},
        reachable_eas=(),
        arch="x86",
        executed_insns=0,
        seeds_run=0,
    )
    session, _state = _resolver_session(resolution)
    monkeypatch.setattr(ida_nalt, "get_op_tinfo", lambda *_args: True)
    called: list[bool] = []
    monkeypatch.setattr(
        computed_goto_resolver,
        "collect_three_argument_callee_purged_evidence",
        lambda *_args, **_kwargs: called.append(True),
        raising=False,
    )
    block = SimpleNamespace(
        mba=SimpleNamespace(qty=0),
        tail=SimpleNamespace(
            opcode=ida_hexrays.m_icall,
            ea=0x1030,
        ),
    )

    _on_build_callinfo(
        function_ea=function_ea,
        block=block,
        call_type=object(),
        decision={"session": session},
    )

    assert called == []


def test_nested_snippet_generation_suppresses_d810() -> None:
    observed = []

    def generate(*args):
        observed.append((args, d810_optimization_is_suppressed()))
        return "snippet"

    assert (
        computed_goto_resolver._generate_microcode_without_d810(
            generate,
            "ranges",
            "failure",
            None,
            0x10,
            3,
        )
        == "snippet"
    )
    assert observed == [
        (("ranges", "failure", None, 0x10, 3), True),
    ]


def test_route_callinfo_capture_rotates_each_native_range_to_entry(
    monkeypatch,
) -> None:
    import ida_hexrays
    import idaapi

    class FakeRanges:
        def __init__(self) -> None:
            self.ranges = self
            self.items: list[tuple[int, int]] = []

        def push_back(self, native_range: tuple[int, int]) -> None:
            self.items.append(native_range)

    class FakeFailure:
        def desc(self) -> str:
            return "no error"

    native_ranges = ((0x1000, 0x1010), (0x2000, 0x2020), (0x3000, 0x3010))
    resolution = ComputedGotoResolution(
        function_ea=0x4000,
        jmp_targets={},
        reachable_eas=(),
        arch="x86",
        executed_insns=0,
        seeds_run=0,
    )
    _session, state = _resolver_session(resolution)
    generated_orders: list[tuple[tuple[int, int], ...]] = []
    snippets = [object(), object(), object()]

    monkeypatch.setattr(ida_hexrays, "mba_ranges_t", FakeRanges)
    monkeypatch.setattr(ida_hexrays, "hexrays_failure_t", FakeFailure)
    monkeypatch.setattr(idaapi, "range_t", lambda start, end: (start, end))

    def generate(
        _generator,
        ranges,
        _failure,
        _retlist,
        _flags,
        maturity,
    ):
        assert int(maturity) == int(ida_hexrays.MMAT_CALLS)
        generated_orders.append(tuple(ranges.items))
        return snippets[len(generated_orders) - 1]

    monkeypatch.setattr(
        computed_goto_resolver,
        "_generate_microcode_without_d810",
        generate,
    )
    captured: list[tuple[int, object]] = []

    def capture(function_ea: int, snippet: object) -> tuple[int, ...]:
        captured.append((function_ea, snippet))
        return {
            snippets[0]: (0x1018,),
            snippets[1]: (0x2028, 0x1018),
            snippets[2]: (),
        }[snippet]

    monkeypatch.setattr(
        computed_goto_resolver,
        "capture_detached_callinfo_templates",
        capture,
    )

    assert computed_goto_resolver.capture_detached_route_callinfo_templates(
        state,
        native_ranges,
    ) == (0x1018, 0x2028)
    assert generated_orders == [
        (native_ranges[0], native_ranges[1], native_ranges[2]),
        (native_ranges[1], native_ranges[0], native_ranges[2]),
        (native_ranges[2], native_ranges[0], native_ranges[1]),
    ]
    assert captured == [
        (0x4000, snippets[0]),
        (0x4000, snippets[1]),
        (0x4000, snippets[2]),
    ]


def test_live_mba_native_eas_rebind_imported_instruction_origins() -> None:
    class Instruction:
        def __init__(self, ea: int, next_instruction=None) -> None:
            self.ea = ea
            self.next = next_instruction

    tail = Instruction(0xF1C00008)
    head = Instruction(0xF1C00004, tail)

    block = SimpleNamespace(
        start=0x40B157,
        head=head,
        tail=tail,
    )

    class Mba:
        qty = 1

        @staticmethod
        def get_mblock(serial: int):
            assert serial == 0
            return block

    assert computed_goto_resolver._live_mba_native_eas(
        Mba(),
        imported_instruction_origins=(
            (0xF1C00004, 0x40B163),
            (0xF1C00008, 0x40B168),
        ),
    ) == frozenset({0x40B157, 0x40B163, 0x40B168})


def test_live_mba_native_eas_excludes_empty_external_placeholder() -> None:
    block = SimpleNamespace(
        start=0x40CD46,
        head=None,
        tail=None,
    )

    class Mba:
        qty = 1

        @staticmethod
        def get_mblock(serial: int):
            assert serial == 0
            return block

    assert computed_goto_resolver._live_mba_native_eas(Mba()) == frozenset()


def test_static_transfer_preserves_register_across_nonwriting_cmp(
    monkeypatch,
) -> None:
    idaapi = ModuleType("idaapi")
    idaapi.o_reg = 1
    idaapi.CF_CHG1 = 0x2
    monkeypatch.setitem(sys.modules, "idaapi", idaapi)

    class Operand:
        type = idaapi.o_reg
        reg = 3

    class Instruction:
        ops = (Operand(), Operand())

        @staticmethod
        def get_canon_feature() -> int:
            return 0

    state = {"ebx": frozenset({0x7F9D6412})}

    _sv_process_writer("cmp", Instruction(), state)

    assert state["ebx"] == frozenset({0x7F9D6412})


def test_static_transfer_setcc_updates_parent_of_separate_low_byte_register(
    monkeypatch,
) -> None:
    idaapi = ModuleType("idaapi")
    idaapi.o_reg = 1
    idaapi.CF_CHG1 = 0x2
    idaapi.get_reg_name = lambda reg, width: "dl" if (reg, width) == (99, 1) else ""
    monkeypatch.setitem(sys.modules, "idaapi", idaapi)

    class Operand:
        type = idaapi.o_reg
        reg = 99

    class Instruction:
        ops = (Operand(), Operand())

        @staticmethod
        def get_canon_feature() -> int:
            return idaapi.CF_CHG1

    state = {"edx": frozenset({0x123456FF})}

    _sv_process_writer("setne", Instruction(), state)

    assert state["edx"] == frozenset({0x12345600, 0x12345601})


def test_two_way_replay_setcc_updates_parent_of_separate_low_byte_register(
    monkeypatch,
) -> None:
    register_ids = {
        name: reg for reg, name in computed_goto_resolver._SV_REG_NAMES.items()
    }
    edx = register_ids["edx"]
    ebx = register_ids["ebx"]
    dl = max(computed_goto_resolver._SV_REG_NAMES) + 100

    idaapi = ModuleType("idaapi")
    idaapi.o_void = 0
    idaapi.o_reg = 1
    idaapi.o_imm = 2
    idaapi.CF_CHG1 = 0x2
    idaapi.get_reg_name = lambda reg, width: "dl" if (reg, width) == (dl, 1) else ""
    mnemonics = {
        0x1000: "mov",
        0x1005: "cmp",
        0x100B: "setne",
        0x100E: "jmp",
    }
    idaapi.print_insn_mnem = lambda ea: mnemonics.get(int(ea), "")
    monkeypatch.setitem(sys.modules, "idaapi", idaapi)

    class Operand:
        def __init__(self, kind=0, *, reg=0, value=0):
            self.type = kind
            self.reg = reg
            self.value = value

    class Instruction:
        def __init__(self):
            self.ops = [Operand(), Operand()]
            self._feature = 0

        def get_canon_feature(self) -> int:
            return self._feature

    encoded = {
        0x1000: (
            5,
            idaapi.CF_CHG1,
            Operand(idaapi.o_reg, reg=edx),
            Operand(idaapi.o_imm, value=0x2000),
        ),
        0x1005: (
            6,
            0,
            Operand(idaapi.o_reg, reg=ebx),
            Operand(idaapi.o_imm, value=0x64B9DC19),
        ),
        0x100B: (
            3,
            idaapi.CF_CHG1,
            Operand(idaapi.o_reg, reg=dl),
            Operand(),
        ),
        0x100E: (
            2,
            0,
            Operand(idaapi.o_reg, reg=edx),
            Operand(),
        ),
    }

    ida_ua = ModuleType("ida_ua")
    ida_ua.insn_t = Instruction

    def decode_insn(insn, ea):
        length, feature, op0, op1 = encoded[int(ea)]
        insn._feature = feature
        insn.ops = [op0, op1]
        return length

    ida_ua.decode_insn = decode_insn
    monkeypatch.setitem(sys.modules, "ida_ua", ida_ua)

    ida_bytes = ModuleType("ida_bytes")
    ida_bytes.get_bytes = lambda ea, size: b"\x0f\x95\xc2"
    monkeypatch.setitem(sys.modules, "ida_bytes", ida_bytes)

    info = computed_goto_resolver._replay_two_way(
        0x1000,
        {"ebx": frozenset({0x64B9DC19})},
        0x100E,
    )

    assert info == {
        "ea": 0x100B,
        "cc": 5,
        "condition_producer_ea": 0x1005,
        "selector_register_name": "ebx",
        "selector_compare_constant": 0x64B9DC19,
        "selector_state_on_left": True,
        "false": 0x2000,
        "true": 0x2001,
    }


def test_native_return_epilogue_accepts_stack_loaded_return_value(
    monkeypatch,
) -> None:
    idaapi = ModuleType("idaapi")
    idaapi.o_void = 0
    idaapi.o_reg = 1
    idaapi.o_imm = 2
    idaapi.o_displ = 4
    idaapi.o_phrase = 5
    mnemonics = {
        0x40F821: "mov",
        0x40F825: "add",
        0x40F828: "pop",
        0x40F829: "pop",
        0x40F82A: "pop",
        0x40F82B: "pop",
        0x40F82C: "ret",
    }
    idaapi.print_insn_mnem = lambda ea: mnemonics.get(int(ea), "")
    monkeypatch.setitem(sys.modules, "idaapi", idaapi)

    class Operand:
        def __init__(self, kind=0, *, reg=0, value=0):
            self.type = kind
            self.reg = reg
            self.value = value

    class Instruction:
        def __init__(self):
            self.ops = [Operand(), Operand()]

    ida_ua = ModuleType("ida_ua")
    ida_ua.insn_t = Instruction
    return_destination_reg = [0]

    def decode_insn(insn, ea):
        sizes = {
            0x40F821: 4,
            0x40F825: 3,
            0x40F828: 1,
            0x40F829: 1,
            0x40F82A: 1,
            0x40F82B: 1,
            0x40F82C: 3,
        }
        if int(ea) == 0x40F821:
            insn.ops = [
                Operand(idaapi.o_reg, reg=return_destination_reg[0]),
                Operand(idaapi.o_displ, reg=4),
            ]
        elif int(ea) == 0x40F825:
            insn.ops = [
                Operand(idaapi.o_reg, reg=4),
                Operand(idaapi.o_imm, value=0x78),
            ]
        elif int(ea) in {0x40F828, 0x40F829, 0x40F82A, 0x40F82B}:
            insn.ops = [Operand(idaapi.o_reg, reg=6), Operand()]
        else:
            insn.ops = [Operand(), Operand()]
        return sizes.get(int(ea), 0)

    ida_ua.decode_insn = decode_insn
    monkeypatch.setitem(sys.modules, "ida_ua", ida_ua)

    assert _native_target_is_return_epilogue(0x40F821)
    return_destination_reg[0] = 1
    assert not _native_target_is_return_epilogue(0x40F821)


def test_handler_state_replay_crosses_call_for_callee_saved_state_register(
    monkeypatch,
) -> None:
    idaapi = ModuleType("idaapi")
    idaapi.o_void = 0
    idaapi.o_reg = 1
    idaapi.o_imm = 2
    idaapi.o_mem = 3
    idaapi.o_displ = 4
    idaapi.o_phrase = 5
    idaapi.CF_CHG1 = 0x2
    mnemonics = {
        0x40C1BB: "call",
        0x40C1D6: "mov",
        0x40C1F0: "jmp",
    }
    idaapi.print_insn_mnem = lambda ea: mnemonics.get(int(ea), "")
    monkeypatch.setitem(sys.modules, "idaapi", idaapi)
    monkeypatch.setitem(sys.modules, "ida_bytes", ModuleType("ida_bytes"))

    class Operand:
        def __init__(self, kind=0, *, reg=0, value=0):
            self.type = kind
            self.reg = reg
            self.value = value

    class Instruction:
        def __init__(self):
            self.ops = [Operand(), Operand()]
            self._feature = 0

        def get_canon_feature(self) -> int:
            return self._feature

    ida_ua = ModuleType("ida_ua")
    ida_ua.insn_t = Instruction

    def decode_insn(insn, ea):
        if int(ea) == 0x40C1BB:
            insn.ops = [Operand(), Operand()]
            insn._feature = 0
            return 0x1B
        if int(ea) == 0x40C1D6:
            insn.ops = [
                Operand(idaapi.o_reg, reg=3),
                Operand(idaapi.o_imm, value=0x7F9D6412),
            ]
            insn._feature = idaapi.CF_CHG1
            return 0x1A
        if int(ea) == 0x40C1F0:
            insn.ops = [Operand(), Operand()]
            insn._feature = 0
            return 2
        return 0

    ida_ua.decode_insn = decode_insn
    monkeypatch.setitem(sys.modules, "ida_ua", ida_ua)
    monkeypatch.setattr(
        computed_goto_resolver,
        "_native_register_state",
        lambda _mregs: {"ebx": frozenset({0xA7933EA0})},
    )

    assert _resolve_concrete_handler_state_write(
        0x40C1BB,
        initial_mregs={20: 0xA7933EA0},
        state_register_name="ebx",
    ) == _ConcreteHandlerStateWrite(0x7F9D6412, 0x40C1F0)


def test_static_handler_entry_route_replays_condition_chain_leaf() -> None:
    state = 0x1EBFFA3C
    context = 0xFDEE1C81
    leaf = MaterializedIndirectTransfer(
        source_jmp_ea=0x40B149,
        source_block_ea=0x40B149,
        materialized_anchor_eas=(),
        target_eas=(0x40B157,),
        selector_state_var_reg=20,
        selector_state_constant=state,
        resolver_kind="condition_chain_handler_evidence",
    )
    context_evidence = MaterializedIndirectTransfer(
        source_jmp_ea=0x40A5E3,
        source_block_ea=0x40A5CA,
        materialized_anchor_eas=(0x40A5CA,),
        target_eas=(0x40A5F0,),
        context_register_values=((36, context),),
        resolver_kind="static_fixpoint",
    )
    calls = []

    def resolve(start_ea: int, **kwargs):
        calls.append((start_ea, kwargs))
        return 0x40B163

    assert _recover_static_handler_entry_route_transfers(
        (leaf, context_evidence),
        route_resolver=resolve,
    ) == (
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40B149,
            source_block_ea=0x40B149,
            materialized_anchor_eas=(),
            target_eas=(0x40B163,),
            selector_state_var_reg=20,
            selector_state_constant=state,
            context_register_values=((36, context),),
            resolver_kind="static_handler_entry_route",
        ),
    )
    assert calls == [
        (
            0x40B149,
            {
                "initial_mregs": {20: state, 36: context},
                "handler_eas": frozenset(),
                "dispatch_anchor_eas": frozenset({0x40A5CA}),
                "return_first_indirect_target": True,
            },
        )
    ]


def test_prepatch_handler_entry_route_replays_native_equality_leaf(
    monkeypatch,
) -> None:
    state = 0x1EBFFA3C
    context = 0xFDEE1C81
    row = _NativeEqualityRow(
        register_name="ebx",
        state_constant=state,
        direct_target_ea=0x40B157,
        block_entry_ea=0x40B149,
        branch_ea=0x40B155,
        branch_size=2,
        condition_code=4,
        terminal_jmp_ea=0x40B161,
        terminal_end_ea=0x40B163,
        selector_kind="jcc",
    )
    resolution = ComputedGotoResolution(
        function_ea=0x40A560,
        jmp_targets={},
        reachable_eas=(0x40A560,),
        arch="x86",
        executed_insns=0,
        seeds_run=0,
        function_context_register_values=(("esi", context),),
    )
    calls = []
    monkeypatch.setattr(
        computed_goto_resolver,
        "_native_register_mreg",
        lambda name: {"ebx": 20, "esi": 36}.get(name),
    )

    def resolve(start_ea: int, **kwargs):
        calls.append((start_ea, kwargs))
        return 0x40B163

    assert computed_goto_resolver._recover_prepatch_handler_entry_routes(
        resolution,
        (row,),
        route_resolver=resolve,
        range_resolver=lambda target_ea: ((target_ea, 0x40B17F),),
    ) == (
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40B149,
            source_block_ea=0x40B149,
            materialized_anchor_eas=(),
            target_eas=(0x40B163,),
            selector_state_var_reg=20,
            selector_state_constant=state,
            context_register_values=((36, context),),
            resolver_kind="static_handler_entry_route",
            owned_native_ranges=((0x40B163, 0x40B17F),),
        ),
    )
    assert calls == [
        (
            0x40B149,
            {
                "initial_mregs": {20: state, 36: context},
                "handler_eas": frozenset(),
                "return_first_indirect_target": True,
            },
        )
    ]


def test_prepatch_handler_entry_route_uses_exact_entry_register_snapshot(
    monkeypatch,
) -> None:
    state = 0x1EBFFA3C
    invariant = 0xFDEE1C81
    path_local = 0x48BD94
    entry_ea = 0x40B149
    target_ea = 0x40B163
    row = _NativeEqualityRow(
        register_name="ebx",
        state_constant=state,
        direct_target_ea=0x40B157,
        block_entry_ea=entry_ea,
        branch_ea=0x40B155,
        branch_size=2,
        condition_code=4,
        terminal_jmp_ea=0x40B161,
        terminal_end_ea=target_ea,
        selector_kind="jcc",
    )
    resolution = ComputedGotoResolution(
        function_ea=0x40A560,
        jmp_targets={},
        reachable_eas=(0x40A560,),
        arch="x86",
        executed_insns=0,
        seeds_run=0,
        function_context_register_values=(("esi", invariant),),
        corridor_register_snapshots=((entry_ea, (("edi", path_local),)),),
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "_native_register_mreg",
        lambda name: {"ebx": 20, "esi": 36, "edi": 40}.get(name),
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "_residual_context_mregs",
        lambda values: {
            {"ebx": 20, "esi": 36, "edi": 40}[name]: value for name, value in values
        },
    )

    def resolve(_start_ea: int, **kwargs):
        return (
            target_ea
            if kwargs["initial_mregs"] == {20: state, 36: invariant, 40: path_local}
            else None
        )

    routes = computed_goto_resolver._recover_prepatch_handler_entry_routes(
        resolution,
        (row,),
        route_resolver=resolve,
        range_resolver=lambda resolved_ea: ((resolved_ea, 0x40B17F),),
    )

    assert len(routes) == 1
    assert routes[0].target_eas == (target_ea,)


def test_prepatch_handler_entry_route_replays_native_setcc_equality_leaf(
    monkeypatch,
) -> None:
    state = 0x64B9DC19
    context = 0x48BD94
    row = _NativeEqualityRow(
        register_name="ebx",
        state_constant=state,
        direct_target_ea=0x40CCDF,
        block_entry_ea=0x40CCCB,
        branch_ea=0x40CCDF,
        branch_size=3,
        condition_code=4,
        terminal_jmp_ea=0x40CCE4,
        terminal_end_ea=0x40CCE6,
        selector_kind="setcc",
    )
    resolution = ComputedGotoResolution(
        function_ea=0x40C8B0,
        jmp_targets={},
        reachable_eas=(0x40C8B0,),
        arch="x86",
        executed_insns=0,
        seeds_run=0,
        function_context_register_values=(("esi", context),),
    )
    calls = []
    monkeypatch.setattr(
        computed_goto_resolver,
        "_native_register_mreg",
        lambda name: {"ebx": 20, "esi": 36}.get(name),
    )

    def resolve(start_ea: int, **kwargs):
        calls.append((start_ea, kwargs))
        return 0x40CCE6

    assert computed_goto_resolver._recover_prepatch_handler_entry_routes(
        resolution,
        (row,),
        route_resolver=resolve,
        range_resolver=lambda target_ea: ((target_ea, 0x40CCFB),),
    ) == (
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40CCCB,
            source_block_ea=0x40CCCB,
            materialized_anchor_eas=(),
            target_eas=(0x40CCE6,),
            selector_state_var_reg=20,
            selector_state_constant=state,
            context_register_values=((36, context),),
            resolver_kind="static_handler_entry_route",
            owned_native_ranges=((0x40CCE6, 0x40CCFB),),
        ),
    )
    assert calls == [
        (
            0x40CCCB,
            {
                "initial_mregs": {20: state, 36: context},
                "handler_eas": frozenset(),
                "return_first_indirect_target": True,
            },
        )
    ]


def test_static_fixpoint_equality_preserves_prepatch_handler_closure() -> None:
    state = 0x64B9DC19
    target_ea = 0x40CCE6
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x40CCE4,
        source_block_ea=0x40CCCB,
        materialized_anchor_eas=(0x40CCDF, 0x40CCE5),
        target_eas=(target_ea, 0x40C9DB),
        condition_code=4,
        true_target_ea=target_ea,
        false_target_ea=0x40C9DB,
        selector_state_var_reg=20,
        selector_compare_constant=state,
        context_register_values=((36, 0x48BD94),),
        resolver_kind="static_fixpoint",
    )
    handler_transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x40CCF9,
        source_block_ea=target_ea,
        materialized_anchor_eas=(0x40CCF0, 0x40CCF6),
        target_eas=(0x40C9EC, 0x40CBB0),
        condition_code=12,
        true_target_ea=0x40C9EC,
        false_target_ea=0x40CBB0,
        selector_state_var_reg=20,
        selector_compare_constant=0x69225E4,
        resolver_kind="static_fixpoint",
        materialized_region_end_ea=0x40CD00,
    )
    resolution = ComputedGotoResolution(
        function_ea=0x40C8B0,
        jmp_targets={},
        reachable_eas=(0x40C8B0,),
        arch="x86",
        executed_insns=0,
        seeds_run=0,
    )

    assert computed_goto_resolver._recover_static_fixpoint_handler_entry_routes(
        resolution,
        (transfer, handler_transfer),
        range_resolver=lambda entry_ea: ((entry_ea, 0x40CCFB),),
    ) == (
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40CCCB,
            source_block_ea=0x40CCCB,
            materialized_anchor_eas=(),
            target_eas=(target_ea,),
            selector_state_var_reg=20,
            selector_state_constant=state,
            context_register_values=((36, 0x48BD94),),
            resolver_kind="static_handler_entry_route",
            owned_native_ranges=((target_ea, 0x40CD00),),
        ),
    )


def test_static_handler_entry_route_abstains_on_conflicting_context() -> None:
    leaf = MaterializedIndirectTransfer(
        source_jmp_ea=0x40B149,
        source_block_ea=0x40B149,
        materialized_anchor_eas=(),
        target_eas=(0x40B157,),
        selector_state_var_reg=20,
        selector_state_constant=0x1EBFFA3C,
        resolver_kind="condition_chain_handler_evidence",
    )
    conflicting_context = tuple(
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40A5E3 + index,
            source_block_ea=0x40A5CA,
            materialized_anchor_eas=(0x40A5CA,),
            target_eas=(0x40A5F0,),
            context_register_values=((36, value),),
            resolver_kind="static_fixpoint",
        )
        for index, value in enumerate((0xFDEE1C81, 0xA0716E5B))
    )

    assert (
        _recover_static_handler_entry_route_transfers(
            (leaf, *conflicting_context),
            route_resolver=lambda *_args, **_kwargs: 0x40B163,
        )
        == ()
    )


def test_static_handler_entry_route_abstains_on_conflicting_leaf_proofs() -> None:
    leaves = tuple(
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40B149,
            source_block_ea=0x40B149,
            materialized_anchor_eas=(),
            target_eas=(target_ea,),
            selector_state_var_reg=20,
            selector_state_constant=0x1EBFFA3C,
            resolver_kind="condition_chain_handler_evidence",
        )
        for target_ea in (0x40B157, 0x40B15E)
    )
    context = MaterializedIndirectTransfer(
        source_jmp_ea=0x40A5E3,
        source_block_ea=0x40A5CA,
        materialized_anchor_eas=(0x40A5CA,),
        target_eas=(0x40A5F0,),
        context_register_values=((36, 0xFDEE1C81),),
        resolver_kind="static_fixpoint",
    )

    assert (
        _recover_static_handler_entry_route_transfers(
            (*leaves, context),
            route_resolver=lambda *_args, **_kwargs: 0x40B163,
        )
        == ()
    )


def test_prepare_detached_snippets_enriches_session_before_union_gate(
    monkeypatch,
) -> None:
    function_ea = 0x40A560
    leaf = MaterializedIndirectTransfer(
        source_jmp_ea=0x40B149,
        source_block_ea=0x40B149,
        materialized_anchor_eas=(),
        target_eas=(0x40B157,),
        selector_state_var_reg=20,
        selector_state_constant=0x1EBFFA3C,
        resolver_kind="condition_chain_handler_evidence",
    )
    route = MaterializedIndirectTransfer(
        source_jmp_ea=0x40B149,
        source_block_ea=0x40B149,
        materialized_anchor_eas=(),
        target_eas=(0x40B163,),
        selector_state_var_reg=20,
        selector_state_constant=0x1EBFFA3C,
        context_register_values=((36, 0xFDEE1C81),),
        resolver_kind="static_handler_entry_route",
    )
    resolution = ComputedGotoResolution(
        function_ea=function_ea,
        jmp_targets={},
        reachable_eas=(function_ea,),
        arch="x86",
        executed_insns=0,
        seeds_run=0,
    )
    planned = []

    _session, state = _resolver_session(resolution)
    assert state.native_preanalysis.merge_materialized_transfers(
        state.native_key, (leaf,)
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "_recover_static_handler_entry_route_transfers",
        lambda _transfers: (route,),
    )
    fake_hexrays = ModuleType("ida_hexrays")
    fake_hexrays.MMAT_PREOPTIMIZED = IDA_MMAT_PREOPTIMIZED
    fake_hexrays.MMAT_LOCOPT = IDA_MMAT_LOCOPT
    monkeypatch.setitem(sys.modules, "ida_hexrays", fake_hexrays)
    monkeypatch.setitem(sys.modules, "idaapi", ModuleType("idaapi"))
    mutation_module = ModuleType("d810.hexrays.mutation.detached_handler_island")
    for name in (
        "capture_detached_replacement_snippet_template",
        "capture_detached_snippet_template",
        "capture_terminal_return_carrier_template",
        "detached_snippet_requires_analyzed_calls",
        "has_detached_replacement_snippet_template",
        "has_detached_snippet_template",
        "has_terminal_return_carrier_template",
        "imported_detached_snippet_instruction_origins",
    ):
        setattr(mutation_module, name, lambda *_args, **_kwargs: False)
    monkeypatch.setitem(
        sys.modules,
        "d810.hexrays.mutation.detached_handler_island",
        mutation_module,
    )

    from d810.analyses.control_flow import detached_handler_island

    monkeypatch.setattr(
        detached_handler_island,
        "plan_detached_snippet_routes",
        lambda transfers, **_kwargs: planned.append(transfers) or (),
    )

    assert computed_goto_resolver.prepare_detached_handler_snippets(state) == 0
    assert state.materialized_transfers == (leaf, route)
    assert planned == []


def test_prepare_terminal_return_carrier_evidence_is_independent_of_materialization(
    monkeypatch,
) -> None:
    function_ea = 0x40A560
    request = TerminalReturnCarrierRequest(
        source_handler_ea=0x40C7E5,
        terminal_target_ea=0x40C898,
        state_var_reg=20,
        state_constant=0x19A7218A,
    )
    captured: list[tuple[int, tuple[TerminalReturnCarrierRequest, ...]]] = []

    resolution = ComputedGotoResolution(
        function_ea=function_ea,
        jmp_targets={},
        reachable_eas=(),
        arch="x86",
        executed_insns=0,
        seeds_run=0,
    )
    _session, state = _resolver_session(resolution)
    assert state.native_preanalysis.merge_terminal_return_carrier_requests(
        state.native_key,
        (request,),
    )

    def capture_requests(candidate_state, key, requests):
        if candidate_state is not state:
            pytest.fail("capture must use the current resolver session")
        captured.append((key, requests))
        return 1

    monkeypatch.setattr(
        computed_goto_resolver,
        "_capture_terminal_return_carrier_requests",
        capture_requests,
        raising=False,
    )
    assert computed_goto_resolver.prepare_terminal_return_carrier_evidence(state) == 1
    assert captured == [(function_ea, (request,))]


def test_detached_static_terminal_transfers_seed_each_island_from_function_context(
    monkeypatch,
) -> None:
    source_state = 0x7F9D6412
    resolution = ComputedGotoResolution(
        function_ea=0x40A560,
        jmp_targets={},
        reachable_eas=(0x40A560,),
        arch="x86",
        executed_insns=1,
        seeds_run=0,
        function_context_register_values=(("esi", 0xFDEE1C81),),
    )
    calls: list[tuple[int, tuple[tuple[str, int], ...]]] = []

    def fixpoint(
        entry_ea: int,
        *,
        initial_register_values: tuple[tuple[str, int], ...] = (),
        follow_indirect_targets: bool = True,
    ) -> tuple[dict, dict, dict, dict, int]:
        assert not follow_indirect_targets
        calls.append((entry_ea, initial_register_values))
        return (
            {0x40C703: {"ebx": frozenset({source_state})}},
            {0x40C703: [0x40AF00]},
            {},
            {0x40C703: 0x40C6DA},
            17,
        )

    monkeypatch.setattr(computed_goto_resolver, "_static_resolver_fixpoint", fixpoint)
    monkeypatch.setattr(
        computed_goto_resolver,
        "_static_register_state_before_jmp",
        lambda _block_entry, _entry_state, _jmp_ea: {"ebx": frozenset({source_state})},
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "_residual_context_mregs",
        lambda values: {20: int(dict(values)["ebx"])} if "ebx" in dict(values) else {},
    )

    (transfer,) = computed_goto_resolver._detached_static_terminal_transfers(
        resolution,
        (0x40B9A6,),
    )

    assert calls == [(0x40B9A6, (("esi", 0xFDEE1C81),))]
    assert transfer.source_jmp_ea == 0x40C703
    assert transfer.source_block_ea == 0x40C6DA
    assert transfer.target_eas == (0x40AF00,)
    assert transfer.source_register_values == ((20, source_state),)
    assert transfer.resolver_kind == "detached_static_fixpoint"


@pytest.mark.parametrize(
    "context_target_eas",
    (
        (0x402000,),
        (0x402000, 0x405000),
    ),
)
def test_detached_static_terminal_transfers_replay_common_target_context_and_polarity(
    monkeypatch,
    context_target_eas,
) -> None:
    resolution = ComputedGotoResolution(
        function_ea=0x401000,
        jmp_targets={},
        reachable_eas=(0x401000,),
        arch="x86",
        executed_insns=1,
        seeds_run=0,
        function_context_register_values=(("ebx", 0x1000),),
    )
    entry_ea = 0x402000
    terminal_ea = 0x402010
    target_context = MaterializedIndirectTransfer(
        source_jmp_ea=0x401100,
        source_block_ea=0x4010F0,
        materialized_anchor_eas=(),
        target_eas=context_target_eas,
        target_register_values=((32, 0x5000), (36, 0x6000)),
        resolver_kind="static_equality_candidate",
    )
    calls: list[tuple[int, tuple[tuple[str, int], ...]]] = []

    def fixpoint(
        start_ea: int,
        *,
        initial_register_values: tuple[tuple[str, int], ...] = (),
        follow_indirect_targets: bool = True,
    ) -> tuple[dict, dict, dict, dict, int]:
        assert not follow_indirect_targets
        calls.append((start_ea, initial_register_values))
        return (
            {entry_ea: {"eax": frozenset({0})}},
            {terminal_ea: [0x403000, 0x404000]},
            {},
            {terminal_ea: entry_ea},
            7,
        )

    monkeypatch.setattr(computed_goto_resolver, "_static_resolver_fixpoint", fixpoint)
    monkeypatch.setattr(
        computed_goto_resolver,
        "_native_register_values",
        lambda values: tuple(
            (name, value)
            for mreg, value in values
            for name in ({32: "edi", 36: "esi"}[mreg],)
        ),
        raising=False,
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "_static_register_state_before_jmp",
        lambda *_args: {"eax": frozenset({0x403000, 0x404000})},
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "_replay_two_way",
        lambda *_args: {
            "cc": 12,
            "true": 0x403000,
            "false": 0x404000,
            "selector_register_name": "ebp",
            "selector_compare_constant": 0x12345678,
            "selector_state_on_left": True,
        },
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "_residual_context_mregs",
        lambda _values: {},
    )

    (transfer,) = computed_goto_resolver._detached_static_terminal_transfers(
        resolution,
        (entry_ea,),
        entry_context_transfers=(target_context,),
    )

    assert calls == [
        (
            entry_ea,
            (("ebx", 0x1000), ("edi", 0x5000), ("esi", 0x6000)),
        )
    ]
    assert transfer.source_jmp_ea == terminal_ea
    assert transfer.target_eas == (0x403000, 0x404000)
    assert transfer.condition_code == 12
    assert transfer.true_target_ea == 0x403000
    assert transfer.false_target_ea == 0x404000
    assert transfer.selector_compare_constant == 0x12345678
    assert transfer.selector_state_on_left is True


def test_static_absorb_set_includes_resolver_proven_terminal_targets() -> None:
    epilogue_ea = 0x40C898
    plan = _PatchPlan(
        jmp_ea=0x40A5E3,
        block_entry=0x40A5CA,
        patch_start=0x40A5D0,
        patch_bytes=b"\x90",
        region_end=0x40A5E5,
        insn_heads=(0x40A5D0,),
        new_block_eas=(0x40A5D6,),
        target_eas=(epilogue_ea, 0x40A5F0),
    )
    resolution = ComputedGotoResolution(
        function_ea=0x40A560,
        jmp_targets={0x40A5E3: (epilogue_ea, 0x40A5F0)},
        reachable_eas=(0x40A560,),
        arch="x86",
        executed_insns=1,
        seeds_run=0,
        patch_plans=(plan,),
        block_entries=(0x40A5CA,),
    )

    assert epilogue_ea in _static_absorb_eas(
        resolution,
        new_block_eas=(0x40A5D6,),
    )


def test_static_transfer_evidence_names_router_sources_but_not_handler_sources(
    monkeypatch,
) -> None:
    router_root = 0x40C9EC
    equality_leaf = 0x40CA22
    handler_entry = 0x40CA3D
    plans = (
        _PatchPlan(
            jmp_ea=0x40CA05,
            block_entry=router_root,
            patch_start=0x40C9F2,
            patch_bytes=b"\x90",
            region_end=0x40CA07,
            insn_heads=(0x40C9F2,),
            new_block_eas=(0x40C9F8,),
            target_eas=(equality_leaf, 0x40CA60),
            condition_code=12,
            true_target_ea=equality_leaf,
            false_target_ea=0x40CA60,
            selector_register_name="ebx",
            selector_compare_constant=0xA7AFB008,
            selector_state_on_left=True,
        ),
        _PatchPlan(
            jmp_ea=0x40CA3B,
            block_entry=equality_leaf,
            patch_start=0x40CA28,
            patch_bytes=b"\x90",
            region_end=handler_entry,
            insn_heads=(0x40CA28,),
            new_block_eas=(0x40CA2E,),
            target_eas=(0x40C9DB, handler_entry),
            condition_code=4,
            true_target_ea=handler_entry,
            false_target_ea=0x40C9DB,
            selector_register_name="ebx",
            selector_compare_constant=0x960C145D,
            selector_state_on_left=True,
        ),
        _PatchPlan(
            jmp_ea=0x40CA50,
            block_entry=handler_entry,
            patch_start=0x40CA47,
            patch_bytes=b"\x90",
            region_end=0x40CA52,
            insn_heads=(0x40CA47,),
            new_block_eas=(0x40CA4D,),
            target_eas=(router_root, 0x40CBB0),
            condition_code=12,
            true_target_ea=router_root,
            false_target_ea=0x40CBB0,
            selector_register_name="ebx",
            selector_compare_constant=0x069225E4,
            selector_state_on_left=True,
        ),
    )
    resolution = ComputedGotoResolution(
        function_ea=0x40C8B0,
        jmp_targets={plan.jmp_ea: plan.target_eas for plan in plans},
        reachable_eas=(0x40C8B0,),
        arch="x86",
        executed_insns=1,
        seeds_run=0,
        patch_plans=plans,
        block_entries=tuple(plan.block_entry for plan in plans),
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "_native_register_mreg",
        lambda name: 20 if name == "ebx" else None,
    )

    transfers = computed_goto_resolver._static_materialized_transfers(resolution)

    assert {transfer.dispatcher_router_eas for transfer in transfers} == {
        (router_root, equality_leaf)
    }


def test_conditional_handler_bridge_requires_residual_route_not_predicate_patch(
    monkeypatch,
) -> None:
    state_register = 20
    false_state = 0xA5A94B86
    true_state = 0x304E8694
    transfers = (
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40A607,
            source_block_ea=0x40A607,
            materialized_anchor_eas=(),
            target_eas=(0x40B8E6,),
            selector_state_var_reg=state_register,
            selector_state_constant=false_state,
            resolver_kind="condition_chain_handler_evidence",
        ),
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40A620,
            source_block_ea=0x40A620,
            materialized_anchor_eas=(),
            target_eas=(0x40A7AE,),
            selector_state_var_reg=state_register,
            selector_state_constant=true_state,
            resolver_kind="condition_chain_handler_evidence",
        ),
    )
    bridge_module = ModuleType("d810.backends.hexrays.evidence.residual_entry_bridge")
    bridge_module.recognize_conditional_handler_bridges = lambda *_args, **_kwargs: (
        SimpleNamespace(
            predicate_ea=0x40C404,
            source_block_ea=0x40C3F0,
            condition_code=5,
            predicate_register=44,
            predicate_size=4,
            predicate_compare_register=None,
            predicate_compare_constant=None,
            predicate_predecessor_ea=0x40C3FC,
            true_state=true_state,
            false_state=false_state,
            true_target_ea=0x40A7AE,
            false_target_ea=0x40B8E6,
            true_is_taken=True,
        ),
    )
    bridge_module.predicate_arm_reaches_ea = lambda _mba, *, predicate_ea, route_ea: (
        (predicate_ea, route_ea) == (0x40C404, 0x40C422)
    )
    monkeypatch.setitem(
        sys.modules,
        "d810.backends.hexrays.evidence.residual_entry_bridge",
        bridge_module,
    )
    assert (
        recover_conditional_handler_bridge_transfers_from_mba(
            transfers,
            object(),
        )
        == ()
    )

    residual_route = MaterializedIndirectTransfer(
        source_jmp_ea=0x40C422,
        source_block_ea=0x40C422,
        materialized_anchor_eas=(),
        target_eas=(0x40A7AE,),
        selector_state_var_reg=state_register,
        selector_state_constant=true_state,
        resolver_kind="residual_state_route",
    )
    (bridge,) = recover_conditional_handler_bridge_transfers_from_mba(
        transfers + (residual_route,),
        object(),
    )

    assert bridge.resolver_kind == "conditional_handler_bridge"
    assert bridge.source_jmp_ea == 0x40C404
    assert bridge.target_eas == (0x40A7AE, 0x40B8E6)


def test_conditional_handler_bridge_accepts_matching_static_native_state_choice(
    monkeypatch,
) -> None:
    state_register = 28
    true_state = 0x3AF41FBE
    false_state = 0x85AE90D3
    predicate_ea = 0x40E20E
    true_target = 0x40F12D
    false_target = 0x40DC04
    transfers = (
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40F121,
            source_block_ea=0x40F121,
            materialized_anchor_eas=(),
            target_eas=(true_target,),
            selector_state_var_reg=state_register,
            selector_state_constant=true_state,
            resolver_kind="static_handler_entry_route",
        ),
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40DBF8,
            source_block_ea=0x40DBF8,
            materialized_anchor_eas=(),
            target_eas=(false_target,),
            selector_state_var_reg=state_register,
            selector_state_constant=false_state,
            resolver_kind="static_handler_entry_route",
        ),
        MaterializedIndirectTransfer(
            source_jmp_ea=predicate_ea,
            source_block_ea=0x40E1F6,
            materialized_anchor_eas=(predicate_ea,),
            target_eas=(),
            condition_code=4,
            selector_state_var_reg=state_register,
            predicate_true_state=true_state,
            predicate_false_state=false_state,
            resolver_kind="static_conditional_state_choice",
        ),
        MaterializedIndirectTransfer(
            source_jmp_ea=predicate_ea,
            source_block_ea=0x40E1F6,
            materialized_anchor_eas=(predicate_ea,),
            target_eas=(true_target, false_target),
            condition_code=4,
            true_target_ea=true_target,
            false_target_ea=false_target,
            selector_state_var_reg=state_register,
            predicate_true_state=true_state,
            predicate_false_state=false_state,
            predicate_true_is_taken=True,
            predicate_preserve_live=True,
            resolver_kind="static_conditional_state_choice_bridge",
        ),
    )
    bridge_module = ModuleType("d810.backends.hexrays.evidence.residual_entry_bridge")
    bridge_module.recognize_conditional_handler_bridges = lambda *_args, **_kwargs: (
        SimpleNamespace(
            predicate_ea=predicate_ea,
            source_block_ea=0x40E1F6,
            condition_code=5,
            predicate_register=8,
            predicate_size=4,
            predicate_compare_register=None,
            predicate_compare_constant=0,
            predicate_predecessor_ea=0x40E207,
            true_state=true_state,
            false_state=false_state,
            true_target_ea=true_target,
            false_target_ea=false_target,
            true_is_taken=True,
        ),
    )
    bridge_module.predicate_arm_reaches_ea = lambda *_args, **_kwargs: False
    monkeypatch.setitem(
        sys.modules,
        "d810.backends.hexrays.evidence.residual_entry_bridge",
        bridge_module,
    )

    (bridge,) = recover_conditional_handler_bridge_transfers_from_mba(
        transfers,
        object(),
    )

    assert bridge.source_jmp_ea == predicate_ea
    assert bridge.target_eas == (true_target, false_target)
    assert bridge.resolver_kind == "static_conditional_state_choice_bridge"
    assert bridge.condition_code == 5
    assert bridge.predicate_register == 8
    assert bridge.predicate_size == 4
    assert bridge.predicate_preserve_live is True


def test_conditional_handler_bridge_refreshes_stale_targets_from_ranked_routes(
    monkeypatch,
) -> None:
    state_register = 20
    predicate_ea = 0x40CDB4
    true_state = 0x09269BD2
    false_state = 0x255387B6
    true_target = 0x40CE3C
    false_target = 0x40CEAB
    dispatcher_target = 0x40CDF8
    stale = MaterializedIndirectTransfer(
        source_jmp_ea=predicate_ea,
        source_block_ea=0x40CDA0,
        materialized_anchor_eas=(predicate_ea,),
        target_eas=(0x40CE27, 0x40CF80),
        condition_code=5,
        true_target_ea=0x40CE27,
        false_target_ea=0x40CF80,
        selector_state_var_reg=state_register,
        resolver_kind="conditional_handler_bridge",
        predicate_true_state=true_state,
        predicate_false_state=false_state,
    )
    exact_true = MaterializedIndirectTransfer(
        source_jmp_ea=0x40CD74,
        source_block_ea=0x40CD5B,
        materialized_anchor_eas=(0x40CD68, 0x40CD6E),
        target_eas=(true_target, dispatcher_target),
        condition_code=4,
        true_target_ea=true_target,
        false_target_ea=dispatcher_target,
        selector_state_var_reg=state_register,
        selector_compare_constant=true_state,
        resolver_kind="static_equality_fixpoint",
    )
    exact_false = MaterializedIndirectTransfer(
        source_jmp_ea=0x40CDBA,
        source_block_ea=0x40CDB7,
        materialized_anchor_eas=(),
        target_eas=(false_target,),
        selector_state_var_reg=state_register,
        selector_state_constant=false_state,
        resolver_kind="residual_state_route_evidence",
    )
    observed_targets: dict[int, int] = {}

    def recognize(_mba, *, state_register, state_targets, **_kwargs):
        assert state_register == 20
        observed_targets.update(state_targets)
        return (
            SimpleNamespace(
                predicate_ea=predicate_ea,
                source_block_ea=0x40CDA0,
                condition_code=5,
                predicate_register=8,
                predicate_size=4,
                predicate_compare_register=None,
                predicate_compare_constant=0,
                predicate_predecessor_ea=0x40CDAF,
                true_state=true_state,
                false_state=false_state,
                true_target_ea=state_targets[true_state],
                false_target_ea=state_targets[false_state],
                true_is_taken=True,
            ),
        )

    bridge_module = ModuleType("d810.backends.hexrays.evidence.residual_entry_bridge")
    bridge_module.recognize_conditional_handler_bridges = recognize
    bridge_module.predicate_arm_reaches_ea = lambda _mba, *, predicate_ea, route_ea: (
        predicate_ea == 0x40CDB4 and route_ea == 0x40CDBA
    )
    monkeypatch.setitem(
        sys.modules,
        "d810.backends.hexrays.evidence.residual_entry_bridge",
        bridge_module,
    )

    (refreshed,) = recover_conditional_handler_bridge_transfers_from_mba(
        (stale, exact_true, exact_false),
        object(),
    )

    assert observed_targets == {
        true_state: true_target,
        false_state: false_target,
    }
    assert refreshed.source_jmp_ea == predicate_ea
    assert refreshed.target_eas == (true_target, false_target)
    assert refreshed.true_target_ea == true_target
    assert refreshed.false_target_ea == false_target


def test_conditional_handler_bridge_accepts_imported_predicate_with_exact_arms(
    monkeypatch,
) -> None:
    state_register = 20
    true_state = 0x2100AFDD
    false_state = 0x0E9795EF
    predicate_ea = 0xF1C00248
    native_predicate_ea = 0x40AE74
    native_predecessor_ea = 0x40AE70
    true_target = 0x40AF00
    false_target = 0x40ACE7
    transfers = (
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40ACD3,
            source_block_ea=0x40ACD3,
            materialized_anchor_eas=(),
            target_eas=(false_target,),
            selector_state_var_reg=state_register,
            selector_state_constant=false_state,
            resolver_kind="condition_chain_handler_evidence",
        ),
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40AEFE,
            source_block_ea=0x40AEEC,
            materialized_anchor_eas=(0x40AEF2,),
            target_eas=(true_target, 0x40A5F0),
            condition_code=4,
            true_target_ea=true_target,
            false_target_ea=0x40A5F0,
            selector_state_var_reg=state_register,
            selector_compare_constant=true_state,
            resolver_kind="static_equality_fixpoint",
        ),
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40ACFB,
            source_block_ea=0x40ACE7,
            materialized_anchor_eas=(),
            target_eas=(false_target,),
            selector_state_var_reg=state_register,
            selector_state_constant=false_state,
            resolver_kind="residual_state_route",
        ),
    )
    bridge_module = ModuleType("d810.backends.hexrays.evidence.residual_entry_bridge")
    bridge_module.recognize_conditional_handler_bridges = lambda *_args, **_kwargs: (
        SimpleNamespace(
            predicate_ea=predicate_ea,
            source_block_ea=predicate_ea,
            condition_code=5,
            predicate_register=8,
            predicate_size=4,
            predicate_compare_register=None,
            predicate_compare_constant=None,
            predicate_predecessor_ea=predicate_ea + 4,
            true_state=true_state,
            false_state=false_state,
            true_target_ea=true_target,
            false_target_ea=false_target,
            true_is_taken=True,
        ),
    )
    bridge_module.predicate_arm_reaches_ea = lambda *_args, **_kwargs: True
    monkeypatch.setitem(
        sys.modules,
        "d810.backends.hexrays.evidence.residual_entry_bridge",
        bridge_module,
    )

    (bridge,) = recover_conditional_handler_bridge_transfers_from_mba(
        transfers,
        object(),
        imported_predicate_eas=frozenset({predicate_ea}),
        imported_instruction_origins={
            predicate_ea: native_predicate_ea,
            predicate_ea + 4: native_predecessor_ea,
        },
    )

    assert bridge.source_jmp_ea == native_predicate_ea
    assert bridge.source_block_ea == native_predicate_ea
    assert bridge.materialized_anchor_eas == (native_predicate_ea,)
    assert bridge.predicate_predecessor_ea == native_predecessor_ea
    assert bridge.target_eas == (true_target, false_target)
    assert bridge.predicate_true_state == true_state
    assert bridge.predicate_false_state == false_state
    assert bridge.predicate_preserve_live is True

    imported_sibling_ea = predicate_ea - 4
    predicate_instruction = SimpleNamespace(ea=predicate_ea, next=None)
    imported_sibling = SimpleNamespace(
        ea=imported_sibling_ea,
        next=predicate_instruction,
    )
    imported_source = SimpleNamespace(
        head=imported_sibling,
        tail=predicate_instruction,
    )
    imported_mba = SimpleNamespace(
        qty=1,
        get_mblock=lambda _serial: imported_source,
    )
    bridge_module.predicate_arm_reaches_ea = lambda *_args, **_kwargs: False

    (block_owned_bridge,) = recover_conditional_handler_bridge_transfers_from_mba(
        transfers,
        imported_mba,
        imported_predicate_eas=frozenset({imported_sibling_ea}),
    )

    assert block_owned_bridge.source_jmp_ea == predicate_ea
    assert block_owned_bridge.predicate_preserve_live is True


def test_conditional_handler_bridge_canonicalizes_imported_source_with_native_cfg(
    monkeypatch,
) -> None:
    state_register = 20
    true_state = 0x65203D55
    false_state = 0x4DFFC906
    imported_predicate_ea = 0xF1C00A74
    imported_predecessor_ea = 0xF1C00A68
    native_source_entry_ea = 0x40B199
    native_predecessor_ea = 0x40B1A7
    native_predicate_ea = 0x40B1B0
    true_target = 0x40A868
    false_target = 0x40A9AE
    transfers = (
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40A850,
            source_block_ea=0x40A850,
            materialized_anchor_eas=(),
            target_eas=(true_target,),
            selector_state_var_reg=state_register,
            selector_state_constant=true_state,
            resolver_kind="condition_chain_handler_evidence",
        ),
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40A996,
            source_block_ea=0x40A996,
            materialized_anchor_eas=(),
            target_eas=(false_target,),
            selector_state_var_reg=state_register,
            selector_state_constant=false_state,
            resolver_kind="condition_chain_handler_evidence",
        ),
    )
    bridge_module = ModuleType("d810.backends.hexrays.evidence.residual_entry_bridge")
    bridge_module.recognize_conditional_handler_bridges = lambda *_args, **_kwargs: (
        SimpleNamespace(
            predicate_ea=imported_predicate_ea,
            source_block_ea=0x40A560,
            condition_code=5,
            predicate_register=None,
            predicate_size=4,
            predicate_compare_register=None,
            predicate_compare_constant=0x40,
            predicate_predecessor_ea=imported_predecessor_ea,
            true_state=true_state,
            false_state=false_state,
            true_target_ea=true_target,
            false_target_ea=false_target,
            true_is_taken=True,
        ),
    )
    bridge_module.predicate_arm_reaches_ea = lambda *_args, **_kwargs: False
    monkeypatch.setitem(
        sys.modules,
        "d810.backends.hexrays.evidence.residual_entry_bridge",
        bridge_module,
    )

    (bridge,) = recover_conditional_handler_bridge_transfers_from_mba(
        transfers,
        object(),
        imported_predicate_eas=frozenset({imported_predicate_ea}),
        imported_instruction_origins={
            imported_predecessor_ea: native_predecessor_ea,
            imported_predicate_ea: native_predicate_ea,
        },
        native_cfg=NativeCfg(
            {
                native_source_entry_ea: NativeBlock(
                    native_source_entry_ea,
                    0x40B1C4,
                )
            }
        ),
    )

    assert bridge.source_block_ea == native_source_entry_ea
    assert bridge.source_jmp_ea == native_predicate_ea
    assert bridge.predicate_predecessor_ea == native_predecessor_ea


def test_imported_predicate_accepts_static_equality_state_register_proof(
    monkeypatch,
) -> None:
    state_register = 20
    true_state = 0x7F9D6412
    false_state = 0xA7933EA0
    predicate_ea = 0xF1C00410
    true_target = 0x40B3F3
    false_target = 0x40A560
    dispatcher_target = 0x40A607

    def static_route(
        source_ea: int,
        state: int,
        target_ea: int,
    ) -> MaterializedIndirectTransfer:
        return MaterializedIndirectTransfer(
            source_jmp_ea=source_ea,
            source_block_ea=source_ea,
            materialized_anchor_eas=(source_ea,),
            target_eas=(target_ea, dispatcher_target),
            condition_code=4,
            true_target_ea=target_ea,
            false_target_ea=dispatcher_target,
            selector_state_var_reg=state_register,
            selector_compare_constant=state,
            resolver_kind="static_equality_fixpoint",
        )

    transfers = (
        static_route(0x40B3E5, true_state, true_target),
        static_route(0x40B6C8, false_state, false_target),
    )
    bridge_module = ModuleType("d810.backends.hexrays.evidence.residual_entry_bridge")
    bridge_module.recognize_conditional_handler_bridges = lambda *_args, **_kwargs: (
        SimpleNamespace(
            predicate_ea=predicate_ea,
            source_block_ea=predicate_ea,
            condition_code=5,
            predicate_register=8,
            predicate_size=4,
            predicate_compare_register=None,
            predicate_compare_constant=None,
            predicate_predecessor_ea=predicate_ea,
            true_state=true_state,
            false_state=false_state,
            true_target_ea=true_target,
            false_target_ea=false_target,
            true_is_taken=True,
        ),
    )
    bridge_module.predicate_arm_reaches_ea = lambda *_args, **_kwargs: False
    monkeypatch.setitem(
        sys.modules,
        "d810.backends.hexrays.evidence.residual_entry_bridge",
        bridge_module,
    )

    (bridge,) = recover_conditional_handler_bridge_transfers_from_mba(
        transfers,
        object(),
        imported_predicate_eas=frozenset({predicate_ea}),
    )

    assert bridge.selector_state_var_reg == state_register
    assert bridge.predicate_true_state == true_state
    assert bridge.predicate_false_state == false_state
    assert bridge.predicate_preserve_live is True


def test_live_opaque_bridge_accepts_exact_inherited_handler_route(
    monkeypatch,
) -> None:
    state_register = 20
    inherited_state = 0x742F372A
    taken_state = 0xCCEC5DE0
    predicate_ea = 0x40C22F
    transfers = tuple(
        MaterializedIndirectTransfer(
            source_jmp_ea=source_ea,
            source_block_ea=source_ea,
            materialized_anchor_eas=(),
            target_eas=(target_ea,),
            selector_state_var_reg=state_register,
            selector_state_constant=state,
            resolver_kind="condition_chain_handler_evidence",
        )
        for source_ea, state, target_ea in (
            (0x40AA8E, inherited_state, 0x40AAA2),
            (0x40C168, taken_state, 0x40C16A),
        )
    )
    bridge_module = ModuleType("d810.backends.hexrays.evidence.residual_entry_bridge")
    bridge_module.recognize_conditional_handler_bridges = lambda *_args, **_kwargs: (
        SimpleNamespace(
            predicate_ea=predicate_ea,
            source_block_ea=0x40C20C,
            condition_code=5,
            predicate_register=None,
            predicate_size=4,
            predicate_compare_register=None,
            predicate_compare_constant=0x62,
            predicate_predecessor_ea=0x40C217,
            true_state=taken_state,
            false_state=inherited_state,
            true_target_ea=0x40C16A,
            false_target_ea=0x40AAA2,
            true_is_taken=True,
        ),
    )
    bridge_module.predicate_arm_reaches_ea = lambda *_args, **_kwargs: False
    monkeypatch.setitem(
        sys.modules,
        "d810.backends.hexrays.evidence.residual_entry_bridge",
        bridge_module,
    )

    (bridge,) = recover_conditional_handler_bridge_transfers_from_mba(
        transfers,
        object(),
        inherited_states_by_predicate_ea={predicate_ea: inherited_state},
    )

    assert bridge.source_jmp_ea == predicate_ea
    assert bridge.predicate_register is None
    assert bridge.predicate_false_state == inherited_state
    assert bridge.false_target_ea == 0x40AAA2
    assert bridge.predicate_preserve_live is True


def test_live_register_predicate_accepts_exact_inherited_handler_route(
    monkeypatch,
) -> None:
    state_register = 20
    inherited_state = 0x1F0B7687
    taken_state = 0x78BAC34B
    predicate_ea = 0x40C5D1
    inherited_target = 0x40A7AE
    taken_target = 0x40B100
    transfers = tuple(
        MaterializedIndirectTransfer(
            source_jmp_ea=source_ea,
            source_block_ea=source_ea,
            materialized_anchor_eas=(),
            target_eas=(target_ea,),
            selector_state_var_reg=state_register,
            selector_state_constant=state,
            resolver_kind="condition_chain_handler_evidence",
        )
        for source_ea, state, target_ea in (
            (0x40C5EF, inherited_state, inherited_target),
            (0x40C85F, taken_state, taken_target),
        )
    )
    bridge_module = ModuleType("d810.backends.hexrays.evidence.residual_entry_bridge")
    bridge_module.recognize_conditional_handler_bridges = lambda *_args, **_kwargs: (
        SimpleNamespace(
            predicate_ea=predicate_ea,
            source_block_ea=0x40C5BD,
            condition_code=5,
            predicate_register=44,
            predicate_size=4,
            predicate_compare_register=None,
            predicate_compare_constant=0,
            predicate_predecessor_ea=0x40C5CA,
            true_state=taken_state,
            false_state=inherited_state,
            true_target_ea=taken_target,
            false_target_ea=inherited_target,
            true_is_taken=True,
        ),
    )
    bridge_module.predicate_arm_reaches_ea = lambda *_args, **_kwargs: False
    monkeypatch.setitem(
        sys.modules,
        "d810.backends.hexrays.evidence.residual_entry_bridge",
        bridge_module,
    )

    (bridge,) = recover_conditional_handler_bridge_transfers_from_mba(
        transfers,
        object(),
        inherited_states_by_predicate_ea={predicate_ea: inherited_state},
    )

    assert bridge.source_jmp_ea == predicate_ea
    assert bridge.predicate_register == 44
    assert bridge.true_target_ea == taken_target
    assert bridge.false_target_ea == inherited_target
    assert bridge.predicate_preserve_live is True


def test_state_write_values_require_exact_native_mov_identity() -> None:
    assert _state_write_values_match(
        mnemonic="mov",
        destination_mreg=20,
        immediate=0x304E8694,
        state_var_reg=20,
        state_constant=0x304E8694,
    )
    assert not _state_write_values_match(
        mnemonic="jmp",
        destination_mreg=None,
        immediate=None,
        state_var_reg=20,
        state_constant=0x304E8694,
    )
    assert not _state_write_values_match(
        mnemonic="mov",
        destination_mreg=20,
        immediate=0xA5A94B86,
        state_var_reg=20,
        state_constant=0x304E8694,
    )


def test_materialized_profile_is_published_after_preanalysis_fixed_point():
    _session, state = _resolver_session()
    state.complete_materialization()

    assert is_computed_goto_materialized(state)


def test_materialized_profile_is_published_during_staged_preanalysis():
    _session, state = _resolver_session()
    state.begin_materialization(object())

    assert is_computed_goto_materialized(state)


def test_flowchart_publishes_static_resolution_without_pending_byte_delivery(
    monkeypatch,
) -> None:
    function_ea = 0x401000
    plan = _PatchPlan(
        jmp_ea=0x401020,
        block_entry=0x401010,
        patch_start=0x401018,
        patch_bytes=b"\x90",
        region_end=0x401022,
        insn_heads=(0x401018,),
        new_block_eas=(),
        target_eas=(0x402000,),
    )
    resolution = ComputedGotoResolution(
        function_ea=function_ea,
        jmp_targets={plan.jmp_ea: plan.target_eas},
        reachable_eas=(function_ea,),
        arch="x86",
        executed_insns=1,
        seeds_run=0,
        patch_plans=(plan,),
    )
    session, state = _resolver_session()
    monkeypatch.setattr(
        computed_goto_resolver,
        "_has_unresolved_computed_goto",
        lambda _function_ea: True,
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "_resolve_computed_goto_resolution",
        lambda _function_ea: resolution,
        raising=False,
    )
    decision: dict[str, object] = {"session": session}

    computed_goto_resolver._on_flowchart_preanalysis(
        function_ea=function_ea,
        mba=object(),
        decision=decision,
    )

    assert state.portable_evidence.computed_goto_resolution is resolution
    assert state.materialization is not None
    assert not hasattr(state, "pending_prepatch_materialization")
    assert decision == {"session": session}


def test_manager_preanalysis_publishes_static_resolution_without_byte_delivery(
    monkeypatch,
) -> None:
    function_ea = 0x401000
    plan = _PatchPlan(
        jmp_ea=0x401020,
        block_entry=0x401010,
        patch_start=0x401018,
        patch_bytes=b"\x90",
        region_end=0x401022,
        insn_heads=(0x401018,),
        new_block_eas=(),
        target_eas=(0x402000,),
    )
    resolution = ComputedGotoResolution(
        function_ea=function_ea,
        jmp_targets={plan.jmp_ea: plan.target_eas},
        reachable_eas=(function_ea,),
        arch="x86",
        executed_insns=1,
        seeds_run=0,
        patch_plans=(plan,),
    )
    _session, state = _resolver_session()
    monkeypatch.setattr(
        computed_goto_resolver,
        "_resolve_computed_goto_resolution",
        lambda _function_ea: resolution,
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "materialize_computed_gotos",
        lambda *_args, **_kwargs: pytest.fail(
            "static delivery must wait until the prepatch source is captured"
        ),
    )

    assert (
        computed_goto_resolver.stage_computed_goto_preanalysis(
            function_ea,
            state=state,
        )
        is resolution
    )
    assert state.portable_evidence.computed_goto_resolution is resolution
    assert state.materialization is not None
    assert not hasattr(state, "pending_prepatch_materialization")


def test_function_context_register_values_abstain_on_conflicting_or_unknown_values():
    states = {
        0x1000: {"esi": frozenset({1})},
        0x1010: {"esi": frozenset({2}), "edi": None},
    }

    assert _function_context_register_values(states) == ()


def test_dispatcher_context_register_values_require_consensus_at_every_site():
    states = {
        0x1000: {"ebx": frozenset({0xD197A4AF}), "eax": None},
        0x1010: {"ebx": frozenset({0xD197A4AF}), "eax": frozenset({1})},
        0x1020: {"ebx": None, "eax": frozenset({2})},
        0x2000: {"ebx": frozenset({0xDEADBEEF})},
    }

    assert _dispatcher_context_register_values(states, (0x1000, 0x1010)) == (
        ("ebx", 0xD197A4AF),
    )
    assert (
        _dispatcher_context_register_values(
            states,
            (0x1000, 0x1010, 0x1020),
        )
        == ()
    )


def test_encode_two_way_branch_preserves_conditional_arm_polarity():
    body = _encode_two_way_branch(
        branch_ea=0x1000,
        condition_code=4,
        true_target_ea=0x2000,
        false_target_ea=0x3000,
    )

    assert body == b"\x0f\x84\xfa\x0f\x00\x00\xe9\xf5\x1f\x00\x00"


def test_equality_setcc_condition_code_normalizes_x86_aliases():
    assert _equality_setcc_condition_code("sete") == 4
    assert _equality_setcc_condition_code("setz") == 4
    assert _equality_setcc_condition_code("setne") == 5
    assert _equality_setcc_condition_code("setnz") == 5
    assert _equality_setcc_condition_code("setl") is None


def test_apply_concrete_equality_setcc_updates_only_low_byte():
    assert _apply_concrete_equality_setcc("setne", (7, 7), 0x123456FF) == 0x12345600
    assert _apply_concrete_equality_setcc("setne", (7, 8), 0x12345600) == 0x12345601
    assert _apply_concrete_equality_setcc("setz", (7, 7), 0) == 1
    assert _apply_concrete_equality_setcc("setl", (7, 8), 0) is None


def test_canonical_low_byte_parent_handles_separate_ida_subregister_ids():
    assert _canonical_low_byte_parent("al") == "eax"
    assert _canonical_low_byte_parent("cl") == "ecx"
    assert _canonical_low_byte_parent("dl") == "edx"
    assert _canonical_low_byte_parent("bl") == "ebx"
    assert _canonical_low_byte_parent("ah") is None


def test_setcc_equality_rows_are_route_evidence_not_byte_delivery():
    assert _native_equality_selector_is_materializable("jcc")
    assert not _native_equality_selector_is_materializable("setcc")


def test_setcc_equality_candidate_preserves_native_target_until_live_validation():
    row = _NativeEqualityRow(
        "ebx",
        0x304E8694,
        0x40B334,
        0x40B32C,
        0x40B334,
        3,
        5,
        0x40B340,
        0x40B342,
        "setcc",
    )

    candidate = _static_equality_route_candidate(
        row,
        _PatchPlan(
            0x40B340,
            0x40B32C,
            0x40B334,
            b"\xe9\x09\x00\x00\x00",
            0x40B342,
            (0x40B334,),
            (0x40B334,),
            target_eas=(0x40B342,),
        ),
        state_var_reg=20,
        context_mregs={36: 0xFDEE1C81},
    )

    assert candidate is not None
    assert candidate.resolver_kind == "static_equality_candidate"
    assert candidate.selector_state_constant == 0x304E8694
    assert candidate.selector_state_var_reg == 20
    assert candidate.source_jmp_ea == 0x40B340
    assert candidate.source_block_ea == 0x40B32C
    assert candidate.target_eas == (0x40B342,)
    assert candidate.materialized_region_end_ea == 0x40B342
    assert _static_equality_candidate_target(
        candidate,
        20,
        live_target_block=203,
        dispatcher_blocks=frozenset({124, 129}),
        dispatch_anchor_eas=frozenset({0x40A5F0}),
        dispatcher_fallback_eas=frozenset({0x40A5F0}),
    ) == (
        0x304E8694,
        0x40B342,
    )
    assert (
        _static_equality_candidate_target(
            candidate,
            21,
            live_target_block=203,
            dispatcher_blocks=frozenset({124, 129}),
            dispatch_anchor_eas=frozenset({0x40A5F0}),
            dispatcher_fallback_eas=frozenset({0x40A5F0}),
        )
        is None
    )
    assert (
        _static_equality_candidate_target(
            candidate,
            20,
            live_target_block=124,
            dispatcher_blocks=frozenset({124, 129}),
            dispatch_anchor_eas=frozenset({0x40A5F0}),
            dispatcher_fallback_eas=frozenset({0x40A5F0}),
        )
        is None
    )
    dispatcher_candidate = candidate.__class__(
        source_jmp_ea=candidate.source_jmp_ea,
        source_block_ea=candidate.source_block_ea,
        materialized_anchor_eas=(),
        target_eas=(0x40A5F0,),
        selector_state_constant=0x13B0D3B2,
        selector_state_var_reg=20,
        resolver_kind="static_equality_candidate",
    )
    assert (
        _static_equality_candidate_target(
            dispatcher_candidate,
            20,
            live_target_block=203,
            dispatcher_blocks=frozenset({124, 129}),
            dispatch_anchor_eas=frozenset(),
            dispatcher_fallback_eas=frozenset({0x40A5F0}),
        )
        is None
    )
    # Candidate evidence owns the native blocks but is not a logical route
    # until CALLS maps the target EA to exactly one live microcode handler.
    assert _exact_equality_native_target((candidate,), 0x304E8694) is None


def test_setcc_equality_candidate_abstains_without_discriminating_targets():
    row = _NativeEqualityRow(
        "ebx",
        0x304E8694,
        0x40B334,
        0x40B32C,
        0x40B334,
        3,
        5,
        0x40B340,
        0x40B342,
        "setcc",
    )

    assert (
        _static_equality_route_candidate(
            row,
            _PatchPlan(
                0x40B340,
                0x40B32C,
                0x40B334,
                b"",
                0x40B342,
                (),
                (),
                target_eas=(0x40B342, 0x40A5F0),
            ),
            state_var_reg=20,
            context_mregs={},
        )
        is None
    )


def test_setcc_equality_candidate_uses_replay_proven_post_terminal_match():
    row = _NativeEqualityRow(
        "ebx",
        0x13B0D3B2,
        0x40AE28,
        0x40AE26,
        0x40AE2E,
        3,
        4,
        0x40AE3C,
        0x40AE3E,
        "setcc",
    )
    plan = _PatchPlan(
        0x40AE3C,
        0x40AE26,
        0x40AE28,
        b"\xe9\xc3\xf7\xff\xff",
        0x40AE3E,
        (0x40AE28,),
        (0x40AE28,),
        target_eas=(0x40A5F0,),
    )

    candidate = _static_equality_route_candidate(
        row,
        plan,
        state_var_reg=20,
        context_mregs={36: 0xFDEE1C81},
        replay_match_target_ea=0x40AE3E,
        replay_nonmatch_target_ea=0x40A5F0,
    )

    assert candidate is not None
    assert candidate.selector_state_constant == 0x13B0D3B2
    assert candidate.target_eas == (0x40AE3E,)
    assert candidate.materialized_region_end_ea == 0x40AE3E
    assert candidate.dispatcher_entry_ea == 0x40A5F0

    ports = _plan_detached_resolver_cut_boundary_ports(
        (candidate,),
        target_ea=0x40AE3E,
        ranges=((0x40AE3E, 0x40AE60),),
        exit_finder=lambda _ranges: (0x40AE50, 0x40AE5E),
    )
    assert len(ports) == 1
    assert ports[0].source_instruction_ea == 0x40AE5E
    assert ports[0].target_ea == 0x40A5F0
    assert ports[0].resolver_kind == "static_equality_candidate_dispatcher_cut"
    assert (
        _resolver_cut_target_for_synthetic_successor(
            ports,
            0x40AE5E,
        )
        == 0x40A5F0
    )


def test_setcc_equality_candidate_uses_replay_without_patch_plan():
    row = _NativeEqualityRow(
        "ebp",
        0xDC71BBC5,
        0x40E14B,
        0x40E14B,
        0x40E153,
        3,
        4,
        0x40E161,
        0x40E163,
        "setcc",
    )

    candidate = _static_equality_route_candidate(
        row,
        None,
        state_var_reg=28,
        context_mregs={},
        replay_match_target_ea=0x40E163,
        replay_nonmatch_target_ea=0x40D370,
    )

    assert candidate is not None
    assert candidate.selector_state_constant == 0xDC71BBC5
    assert candidate.source_jmp_ea == 0x40E161
    assert candidate.source_block_ea == 0x40E14B
    assert candidate.target_eas == (0x40E163,)
    assert candidate.dispatcher_entry_ea == 0x40D370


def test_setcc_replay_uses_exact_corridor_entry_snapshot(monkeypatch):
    row = _NativeEqualityRow(
        "ebp",
        0xB13A6E93,
        0x40DAAB,
        0x40DAA3,
        0x40DAAB,
        3,
        4,
        0x40DAB9,
        0x40DABB,
        "setcc",
    )
    resolution = ComputedGotoResolution(
        function_ea=0x40D200,
        jmp_targets={},
        reachable_eas=(),
        arch="x86",
        executed_insns=0,
        seeds_run=0,
        corridor_register_snapshots=((0x40DAA3, (("ebx", 0xD1978CAF),)),),
    )
    seen_initial_values = []
    match_register_values_by_row = {}
    monkeypatch.setattr(
        computed_goto_resolver,
        "_native_register_mreg",
        lambda name: {"ebp": 20, "ebx": 36}.get(name),
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "_residual_context_mregs",
        lambda values: {{"ebp": 20, "ebx": 36}[name]: value for name, value in values},
    )

    def resolve_route(
        _start_ea,
        *,
        initial_mregs,
        handler_eas,
        return_first_indirect_target,
        return_first_indirect_result=False,
    ):
        assert not handler_eas
        assert return_first_indirect_target
        values = frozenset(initial_mregs.values())
        seen_initial_values.append(values)
        assert 0xD1978CAF in values
        target = 0x40DABB if 0xB13A6E93 in values else 0x40D370
        if return_first_indirect_result:
            state = 0xB13A6E93 if 0xB13A6E93 in values else 0xB13A6E92
            return _ConcreteDispatchResult(
                target,
                (("ebp", state), ("ebx", 0xD1978CAF)),
            )
        return target

    assert _resolve_native_setcc_route_facts(
        resolution,
        (row,),
        route_resolver=resolve_route,
        match_register_values_by_row=match_register_values_by_row,
    ) == ((row, 0x40DABB, 0x40D370),)
    assert len(seen_initial_values) == 2
    assert match_register_values_by_row == {
        row: (("ebp", 0xB13A6E93), ("ebx", 0xD1978CAF)),
    }


def test_setcc_equality_candidate_rejects_unproven_post_terminal_match():
    row = _NativeEqualityRow(
        "ebx",
        0x13B0D3B2,
        0x40AE28,
        0x40AE26,
        0x40AE2E,
        3,
        4,
        0x40AE3C,
        0x40AE3E,
        "setcc",
    )
    plan = _PatchPlan(
        0x40AE3C,
        0x40AE26,
        0x40AE28,
        b"",
        0x40AE3E,
        (),
        (),
        target_eas=(0x40A5F0,),
    )

    assert (
        _static_equality_route_candidate(
            row,
            plan,
            state_var_reg=20,
            context_mregs={},
            replay_match_target_ea=0x40AE40,
            replay_nonmatch_target_ea=0x40A5F0,
        )
        is None
    )
    assert (
        _static_equality_route_candidate(
            row,
            plan,
            state_var_reg=20,
            context_mregs={},
            replay_match_target_ea=0x40AE3E,
            replay_nonmatch_target_ea=0x40A600,
        )
        is None
    )


def test_setcc_equality_delivery_requires_match_handler_and_nonmatch_fallback():
    row = _NativeEqualityRow(
        "ebx",
        0x304E8694,
        0x40B334,
        0x40B32C,
        0x40B334,
        3,
        5,
        0x40B340,
        0x40B342,
        "setcc",
    )

    assert _setcc_equality_delivery_targets(
        row,
        match_target_ea=0x40B342,
        nonmatch_target_ea=0x40A5F0,
        proven_match_target_ea=0x40B342,
        dispatcher_fallback_eas=frozenset({0x40A5F0}),
    ) == (0x40A5F0, 0x40B342)
    assert (
        _setcc_equality_delivery_targets(
            row,
            match_target_ea=0x40A5F0,
            nonmatch_target_ea=0x40B342,
            proven_match_target_ea=0x40A5F0,
            dispatcher_fallback_eas=frozenset({0x40A5F0}),
        )
        is None
    )
    assert (
        _setcc_equality_delivery_targets(
            row,
            match_target_ea=0x40B342,
            nonmatch_target_ea=0x40B344,
            proven_match_target_ea=0x40B342,
            dispatcher_fallback_eas=frozenset({0x40A5F0}),
        )
        is None
    )
    assert (
        _setcc_equality_delivery_targets(
            row,
            match_target_ea=0x40B342,
            nonmatch_target_ea=0x40A5F0,
            proven_match_target_ea=0x40B344,
            dispatcher_fallback_eas=frozenset({0x40A5F0}),
        )
        is None
    )


def test_encode_direct_jump_preserves_short_site_or_abstains():
    assert _encode_direct_jump(0x1000, 2, 0x1070) == b"\xeb\x6e"
    assert _encode_direct_jump(0x1000, 2, 0x2000) is None
    assert _encode_direct_jump(0x1000, 5, 0x2000) == b"\xe9\xfb\x0f\x00\x00"


def test_encode_x86_register_immediate32_is_register_generic_and_bounded():
    assert _encode_x86_register_immediate32(3, 0xA0716E5B) == b"\xbb\x5b\x6e\x71\xa0"
    assert _encode_x86_register_immediate32(0, 0x12345678) == b"\xb8\x78\x56\x34\x12"
    assert _encode_x86_register_immediate32(8, 1) is None


def test_entry_bridge_selects_only_jump_before_first_routing_node() -> None:
    assert computed_goto_resolver._select_prologue_entry_jump(
        ((0x40A5C8, 2), (0x40A5D6, 5)),
        routing_start_ea=0x40A5CA,
    ) == (0x40A5C8, 2)
    assert (
        computed_goto_resolver._select_prologue_entry_jump(
            ((0x40A5C8, 2), (0x40A5C9, 2)),
            routing_start_ea=0x40A5CA,
        )
        is None
    )


def test_exact_equality_native_target_selects_matching_arm_and_abstains_on_conflict():
    state = 0xEC71CA67
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x40B9A4,
        source_block_ea=0x40B98C,
        materialized_anchor_eas=(0x40B998, 0x40B99E),
        target_eas=(0x40B9A6, 0x40A5F0),
        condition_code=4,
        true_target_ea=0x40B9A6,
        false_target_ea=0x40A5F0,
        selector_state_var_reg=20,
        selector_compare_constant=state,
        selector_state_on_left=True,
        resolver_kind="static_equality_fixpoint",
    )

    residual_route = MaterializedIndirectTransfer(
        source_jmp_ea=0x40C6F7,
        source_block_ea=0x40C6F7,
        materialized_anchor_eas=(0x40C6F7,),
        target_eas=(0x40AEE6,),
        selector_state_constant=state,
        resolver_kind="residual_state_route",
    )
    assert _exact_equality_native_target((transfer, residual_route), state) == 0x40B9A6
    conflicting = MaterializedIndirectTransfer(
        source_jmp_ea=0x5000,
        source_block_ea=0x4FF0,
        materialized_anchor_eas=(),
        target_eas=(0x6000,),
        selector_state_constant=state,
        resolver_kind="static_equality_route",
    )
    assert _exact_equality_native_target((transfer, conflicting), state) is None

    route_evidence = MaterializedIndirectTransfer(
        source_jmp_ea=0x40C629,
        source_block_ea=0x40C623,
        materialized_anchor_eas=(),
        target_eas=(0x40B9A6,),
        selector_state_var_reg=20,
        selector_state_constant=state,
        resolver_kind="residual_state_route_evidence",
    )
    assert _exact_equality_native_target((route_evidence,), state) == 0x40B9A6


def test_exact_equality_native_target_prefers_static_fixpoint_over_condition_chain_continuation():
    state = 0x19A7218A
    static_fixpoint = MaterializedIndirectTransfer(
        source_jmp_ea=0x40A5E3,
        source_block_ea=0x40A5CA,
        materialized_anchor_eas=(0x40A5DF, 0x40A5E5),
        target_eas=(0x40A5F0, 0x40C898),
        condition_code=4,
        true_target_ea=0x40C898,
        false_target_ea=0x40A5F0,
        selector_state_var_reg=20,
        selector_compare_constant=state,
        selector_state_on_left=True,
        resolver_kind="static_fixpoint",
    )
    condition_chain_continuation = MaterializedIndirectTransfer(
        source_jmp_ea=0x40A5CA,
        source_block_ea=0x40A5CA,
        materialized_anchor_eas=(),
        target_eas=(0x40A5D0,),
        selector_state_var_reg=20,
        selector_state_constant=state,
        resolver_kind="condition_chain_handler_evidence",
    )

    assert (
        _exact_equality_native_target(
            (static_fixpoint, condition_chain_continuation),
            state,
        )
        == 0x40C898
    )


def test_validated_exact_route_suppresses_duplicate_condition_chain_glue_evidence():
    state = 0x304E8694
    validated = MaterializedIndirectTransfer(
        source_jmp_ea=0x40B340,
        source_block_ea=0x40B32C,
        materialized_anchor_eas=(),
        target_eas=(0x40B342,),
        selector_state_constant=state,
        resolver_kind="static_equality_route",
    )
    candidate = MaterializedIndirectTransfer(
        source_jmp_ea=0x40B340,
        source_block_ea=0x40B32C,
        materialized_anchor_eas=(),
        target_eas=(0x40B342,),
        selector_state_constant=state,
        resolver_kind="static_equality_candidate",
    )

    assert _states_with_validated_exact_equality_routes(
        (candidate, validated),
    ) == frozenset({state})


def test_materialized_state_replay_prefers_exact_equality_handler_over_coarse_range():
    incoming_state = 0xEC71CA67
    next_state = 0xA5A94B86
    graph = FlowGraph(
        blocks={
            8: _block(8, 0x40A607),
            111: _block(111, 0x40B36B),
            163: _block(163, 0x40BCA3),
            216: _block(216, 0x40C4F6),
        },
        entry_serial=111,
        func_ea=0x40A560,
    )
    transfers = (
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40B36B,
            source_block_ea=0x40B36B,
            materialized_anchor_eas=(),
            target_eas=(0x40B36B,),
            selector_state_constant=incoming_state,
            resolver_kind="condition_chain_handler_evidence",
        ),
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40C4F4,
            source_block_ea=0x40C4DC,
            materialized_anchor_eas=(0x40C4E8, 0x40C4EE),
            target_eas=(0x40C4F6, 0x40A5F0),
            condition_code=4,
            true_target_ea=0x40C4F6,
            false_target_ea=0x40A5F0,
            selector_state_var_reg=20,
            selector_compare_constant=next_state,
            resolver_kind="static_equality_fixpoint",
        ),
    )

    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(),
        out_reg_maps={},
        dispatcher_entry_serial=8,
        state_var_reg=20,
        handler_serials=frozenset({111, 163, 216}),
        transfers=transfers,
        handler_states={111: (incoming_state,)},
        handler_targets={incoming_state: 111},
        handler_target_resolver=lambda _state: 163,
        handler_state_resolver=lambda *_args, **_kwargs: _ConcreteHandlerStateWrite(
            next_state, 0x40B36B
        ),
        state_register_name="ebx",
    )

    assert routes == (
        MaterializedStateRoute(
            111,
            next_state,
            216,
            source_handler_serial=111,
            handler_exit_proven=True,
        ),
    )


def test_validated_exact_equality_handler_seeds_outgoing_state_replay():
    incoming_state = 0xA5540595
    next_state = 0xBCDE2EFB
    graph = FlowGraph(
        blocks={
            8: _block(8, 0x40A607),
            186: _block(186, 0x40C069),
            216: _block(216, 0x40C4F6),
        },
        entry_serial=216,
        func_ea=0x40A560,
    )
    incoming_route = MaterializedIndirectTransfer(
        source_jmp_ea=0x40C4F4,
        source_block_ea=0x40C4DC,
        materialized_anchor_eas=(),
        target_eas=(0x40C4F6,),
        selector_state_constant=incoming_state,
        resolver_kind="static_equality_route",
    )

    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(),
        out_reg_maps={},
        dispatcher_entry_serial=8,
        state_var_reg=20,
        handler_serials=frozenset({186}),
        transfers=(incoming_route,),
        handler_targets={next_state: 186},
        handler_state_resolver=lambda *_args, **_kwargs: _ConcreteHandlerStateWrite(
            next_state, 0x40C525
        ),
        state_register_name="ebx",
    )

    assert routes == (
        MaterializedStateRoute(
            216,
            next_state,
            186,
            source_handler_serial=216,
            handler_exit_proven=True,
        ),
    )


def test_materialized_state_anchor_canonicalizes_coarse_route_to_live_exact_handler():
    state = 0x2100AFDD
    graph = FlowGraph(
        blocks={
            8: _block(8, 0x40A607),
            82: _block(82, 0x40C6DA),
            59: _block(59, 0x40ABEE),
            226: _block(226, 0x40AF00),
        },
        entry_serial=82,
        func_ea=0x40A560,
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x40AEFE,
        source_block_ea=0x40AEE6,
        materialized_anchor_eas=(0x40AEF2, 0x40AEF8),
        target_eas=(0x40AF00, 0x40A5F0),
        condition_code=4,
        true_target_ea=0x40AF00,
        false_target_ea=0x40A5F0,
        selector_state_var_reg=20,
        selector_compare_constant=state,
        resolver_kind="static_equality_fixpoint",
    )

    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(StateWriteAnchor(82, state, state_var_reg=20),),
        out_reg_maps={82: {20: state}},
        dispatcher_entry_serial=8,
        state_var_reg=20,
        handler_serials=frozenset({59, 226}),
        transfers=(transfer,),
        route_resolver=lambda *_args, **_kwargs: 0x40ABEE,
    )

    assert routes == (MaterializedStateRoute(82, state, 226),)


def test_materialized_state_anchor_rejects_stale_unowned_self_route():
    state = 0x699BC698
    write_ea = 0x40EAA7
    graph = FlowGraph(
        blocks={
            31: _block(31, 0x40D370),
            233: BlockSnapshot(
                serial=233,
                block_type=0,
                succs=(31,),
                preds=(),
                flags=0,
                start_ea=0x40EA9B,
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=0,
                        ea=write_ea,
                        operands=(),
                        kind=InsnKind.MOV,
                        l=MopSnapshot(
                            kind=OperandKind.STACK,
                            stkoff=0x44C,
                            size=4,
                        ),
                        d=MopSnapshot(
                            kind=OperandKind.REGISTER,
                            reg=28,
                            size=4,
                        ),
                    ),
                ),
            ),
        },
        entry_serial=233,
        func_ea=0x40D200,
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x40D36E,
        source_block_ea=0x40D370,
        materialized_anchor_eas=(),
        target_eas=(0x40EA9B,),
        selector_state_var_reg=28,
        selector_state_constant=state,
        resolver_kind="static_equality_route",
    )

    assert (
        _build_materialized_state_routes(
            graph,
            state_write_anchors=(
                StateWriteAnchor(
                    233,
                    state,
                    state_var_reg=28,
                    instruction_ea=write_ea,
                ),
            ),
            out_reg_maps={233: {28: state}},
            dispatcher_entry_serial=31,
            state_var_reg=28,
            handler_serials=frozenset({233}),
            transfers=(transfer,),
        )
        == ()
    )


def test_materialized_state_anchor_keeps_live_constant_self_route():
    state = 0x699BC698
    write_ea = 0x40EAA7
    graph = FlowGraph(
        blocks={
            31: _block(31, 0x40D370),
            233: BlockSnapshot(
                serial=233,
                block_type=0,
                succs=(31,),
                preds=(),
                flags=0,
                start_ea=0x40EA9B,
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=0,
                        ea=write_ea,
                        operands=(),
                        kind=InsnKind.MOV,
                        l=MopSnapshot(
                            kind=OperandKind.NUMBER,
                            value=state,
                            size=4,
                        ),
                        d=MopSnapshot(
                            kind=OperandKind.REGISTER,
                            reg=28,
                            size=4,
                        ),
                    ),
                ),
            ),
        },
        entry_serial=233,
        func_ea=0x40D200,
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x40D36E,
        source_block_ea=0x40D370,
        materialized_anchor_eas=(),
        target_eas=(0x40EA9B,),
        selector_state_var_reg=28,
        selector_state_constant=state,
        resolver_kind="static_equality_route",
    )

    assert _build_materialized_state_routes(
        graph,
        state_write_anchors=(
            StateWriteAnchor(
                233,
                state,
                state_var_reg=28,
                instruction_ea=write_ea,
            ),
        ),
        out_reg_maps={233: {28: state}},
        dispatcher_entry_serial=31,
        state_var_reg=28,
        handler_serials=frozenset({233}),
        transfers=(transfer,),
    ) == (MaterializedStateRoute(233, state, 233),)


def test_materialized_state_anchor_prefers_imported_replacement_over_native_handler():
    state = 0x2100AFDD
    graph = FlowGraph(
        blocks={
            8: _block(8, 0x40A607),
            82: _block(82, 0x40C6DA),
            226: _block(226, 0x40AF00),
            281: _block(281, 0x40A560),
        },
        entry_serial=82,
        func_ea=0x40A560,
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x40AEFE,
        source_block_ea=0x40AEE6,
        materialized_anchor_eas=(0x40AEF2, 0x40AEF8),
        target_eas=(0x40AF00, 0x40A5F0),
        condition_code=4,
        true_target_ea=0x40AF00,
        false_target_ea=0x40A5F0,
        selector_state_var_reg=20,
        selector_compare_constant=state,
        resolver_kind="static_equality_fixpoint",
    )

    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(StateWriteAnchor(82, state, state_var_reg=20),),
        out_reg_maps={82: {20: state}},
        dispatcher_entry_serial=8,
        state_var_reg=20,
        handler_serials=frozenset({226, 281}),
        transfers=(transfer,),
        handler_targets={state: 281},
        replacement_handler_serials=frozenset({281}),
    )

    assert routes == (MaterializedStateRoute(82, state, 281),)


def test_materialized_state_anchor_prefers_exact_live_handler_over_bst_router():
    state = 0xA5540595
    graph = FlowGraph(
        blocks={
            8: _block(8, 0x40A607),
            146: _block(146, 0x40B668),
            175: _block(175, 0x40BC50),
            204: _block(204, 0x40C4F6),
        },
        entry_serial=146,
        func_ea=0x40A560,
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x40B668,
        source_block_ea=0x40B668,
        materialized_anchor_eas=(0x40B668,),
        target_eas=(0x40C4F6,),
        selector_state_var_reg=20,
        selector_state_constant=state,
        resolver_kind="residual_state_route",
    )

    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(StateWriteAnchor(146, state, state_var_reg=20),),
        out_reg_maps={146: {20: state}},
        dispatcher_entry_serial=8,
        state_var_reg=20,
        handler_serials=frozenset({175, 204}),
        dispatcher_block_serials=frozenset({8, 175}),
        transfers=(transfer,),
        handler_targets={state: 204},
        exact_handler_override_serials=frozenset({204}),
    )

    assert routes == (MaterializedStateRoute(146, state, 204),)


def test_live_residual_state_edge_survives_when_state_write_was_folded_away():
    state = 0xA5540595
    graph = FlowGraph(
        blocks={
            8: _block(8, 0x40A607),
            146: _block(146, 0x40B668, succs=(243,)),
            147: _block(147, 0x40B685, (0x40B668,), succs=(243,)),
            175: _block(175, 0x40BC21),
            243: _block(243, 0x40C4F6, preds=(146,)),
        },
        entry_serial=146,
        func_ea=0x40A560,
    )
    evidence = MaterializedIndirectTransfer(
        source_jmp_ea=0x40B668,
        source_block_ea=0x40B668,
        materialized_anchor_eas=(),
        target_eas=(0x40C4F6,),
        selector_state_var_reg=20,
        selector_state_constant=state,
        resolver_kind="residual_state_route_evidence",
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x40B685,
        source_block_ea=0x40B685,
        materialized_anchor_eas=(0x40B685,),
        target_eas=(0x40C4F6,),
        selector_state_var_reg=20,
        selector_state_constant=state,
        resolver_kind="residual_state_route",
    )

    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(),
        out_reg_maps={},
        dispatcher_entry_serial=8,
        state_var_reg=20,
        handler_serials=frozenset({175, 243}),
        dispatcher_block_serials=frozenset({8, 175}),
        transfers=(evidence, transfer),
        handler_targets={state: 243},
        exact_handler_override_serials=frozenset({243}),
        state_register_name="ebx",
    )

    assert routes == (
        MaterializedStateRoute(
            146,
            state,
            243,
            proof_kind="exact_live_state_edge",
        ),
    )


def test_materialized_state_anchor_uses_validated_exact_route_when_corridor_abstains():
    state = 0x304E8694
    graph = FlowGraph(
        blocks={
            8: _block(8, 0x40A607),
            203: _block(203, 0x40B342),
            234: _block(234, 0x40C842),
        },
        entry_serial=234,
        func_ea=0x40A560,
    )
    validated = MaterializedIndirectTransfer(
        source_jmp_ea=0x40B340,
        source_block_ea=0x40B32C,
        materialized_anchor_eas=(),
        target_eas=(0x40B342,),
        selector_state_constant=state,
        resolver_kind="static_equality_route",
    )

    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(
            StateWriteAnchor(234, state, state_var_reg=20, instruction_ea=0x40C842),
        ),
        out_reg_maps={234: {20: state}},
        dispatcher_entry_serial=8,
        state_var_reg=20,
        handler_serials=frozenset({203}),
        transfers=(validated,),
        route_resolver=lambda *_args, **_kwargs: None,
    )

    assert routes == (MaterializedStateRoute(234, state, 203),)


def test_materialized_state_anchor_keeps_exact_terminal_endpoint():
    state = 0x19A7218A
    graph = FlowGraph(
        blocks={
            8: _block(8, 0x40A5F0),
            198: _block(198, 0x40C309),
            239: _block(239, 0x40A5D0),
            300: BlockSnapshot(
                serial=300,
                block_type=6,
                succs=(),
                preds=(),
                flags=0,
                start_ea=0x40C898,
                insn_snapshots=(),
                kind=BlockKind.EXTERNAL,
            ),
        },
        entry_serial=198,
        func_ea=0x40A560,
    )
    static_fixpoint = MaterializedIndirectTransfer(
        source_jmp_ea=0x40A5E3,
        source_block_ea=0x40A5CA,
        materialized_anchor_eas=(0x40A5DF, 0x40A5E5),
        target_eas=(0x40A5F0, 0x40C898),
        condition_code=4,
        true_target_ea=0x40C898,
        false_target_ea=0x40A5F0,
        selector_state_var_reg=20,
        selector_compare_constant=state,
        selector_state_on_left=True,
        resolver_kind="static_fixpoint",
    )
    condition_chain_continuation = MaterializedIndirectTransfer(
        source_jmp_ea=0x40A5CA,
        source_block_ea=0x40A5CA,
        materialized_anchor_eas=(),
        target_eas=(0x40A5D0,),
        selector_state_var_reg=20,
        selector_state_constant=state,
        resolver_kind="condition_chain_handler_evidence",
    )

    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(
            StateWriteAnchor(198, state, state_var_reg=20, instruction_ea=0x40C328),
        ),
        out_reg_maps={198: {20: state}},
        dispatcher_entry_serial=8,
        state_var_reg=20,
        handler_serials=frozenset({239}),
        transfers=(static_fixpoint, condition_chain_continuation),
        handler_targets={state: 239},
        replacement_handler_serials=frozenset({239}),
        route_resolver=lambda *_args, **_kwargs: 0x40A5D0,
        handler_state_resolver=lambda *_args, **_kwargs: None,
        terminal_target_resolver=lambda _target_ea: True,
        state_register_name="ebx",
    )

    assert routes == (
        MaterializedStateRoute(
            198,
            state,
            300,
            proof_kind="terminal_state_route",
        ),
    )


def test_materialized_state_anchor_maps_omitted_terminal_endpoint_to_stop():
    state = 0x69225E4
    source_native_ea = 0x40CC1C
    terminal_native_ea = 0x40CD8C
    graph = FlowGraph(
        blocks={
            8: _block(8, 0x40C9DB),
            41: BlockSnapshot(
                serial=41,
                block_type=0,
                succs=(8,),
                preds=(),
                flags=0,
                start_ea=0x40C8B0,
                insn_snapshots=(
                    InsnSnapshot(
                        ea=0xF1C0008C,
                        opcode=4,
                        operands=(),
                        kind=InsnKind.MOV,
                        l=MopSnapshot(
                            t=2,
                            size=4,
                            kind=OperandKind.NUMBER,
                            value=state,
                        ),
                        d=MopSnapshot(
                            t=1,
                            size=4,
                            kind=OperandKind.REGISTER,
                            reg=20,
                        ),
                    ),
                ),
            ),
            74: BlockSnapshot(
                serial=74,
                block_type=7,
                succs=(),
                preds=(),
                flags=0,
                start_ea=0xFFFFFFFFFFFFFFFF,
                insn_snapshots=(),
                kind=BlockKind.STOP,
            ),
        },
        entry_serial=41,
        func_ea=0x40C8B0,
    )
    static_fixpoint = MaterializedIndirectTransfer(
        source_jmp_ea=0x40C9D9,
        source_block_ea=0x40C9C0,
        materialized_anchor_eas=(0x40C9C6, 0x40C9DB),
        target_eas=(0x40C9DB, terminal_native_ea),
        condition_code=4,
        true_target_ea=terminal_native_ea,
        false_target_ea=0x40C9DB,
        selector_state_var_reg=20,
        selector_compare_constant=state,
        selector_state_on_left=True,
        resolver_kind="static_fixpoint",
    )

    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(
            StateWriteAnchor(
                41,
                state,
                state_var_reg=20,
                instruction_ea=0xF1C0008C,
            ),
        ),
        out_reg_maps={41: {20: state}},
        dispatcher_entry_serial=8,
        state_var_reg=20,
        handler_serials=frozenset({41}),
        transfers=(static_fixpoint,),
        handler_entry_eas_by_serial={41: source_native_ea},
        route_resolver=lambda *_args, **_kwargs: None,
        handler_state_resolver=lambda *_args, **_kwargs: None,
        terminal_target_resolver=lambda target_ea: target_ea == terminal_native_ea,
        state_register_name="ebx",
    )

    assert routes == (
        MaterializedStateRoute(
            41,
            state,
            74,
            proof_kind="terminal_state_route",
            source_native_ea=source_native_ea,
            target_native_ea=terminal_native_ea,
        ),
    )


def test_equality_fragment_claims_detached_source_and_handler_before_analysis():
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x40AEFE,
        source_block_ea=0x40AEE6,
        materialized_anchor_eas=(0x40AEF2, 0x40AEF8),
        target_eas=(0x40AF00, 0x40A5F0),
        condition_code=4,
        true_target_ea=0x40AF00,
        false_target_ea=0x40A5F0,
        selector_state_var_reg=20,
        selector_compare_constant=0x2100AFDD,
        selector_state_on_left=True,
        resolver_kind="static_equality_fixpoint",
        materialized_region_end_ea=0x40AF00,
    )

    unrelated = MaterializedIndirectTransfer(
        source_jmp_ea=0x40C4F4,
        source_block_ea=0x40C4DC,
        materialized_anchor_eas=(),
        target_eas=(0x40C4F6, 0x40A5F0),
        resolver_kind="static_equality_fixpoint",
    )
    assert _equality_transfers_activated_by_targets(
        (transfer, unrelated),
        (0x40AEE6,),
    ) == (transfer,)

    assert _equality_fragment_owned_ranges(
        (transfer,),
        block_end=lambda ea: ea + 0x20,
    ) == (
        (0x40A5F0, 0x40A610),
        (0x40AEE6, 0x40AF00),
        (0x40AF00, 0x40AF20),
    )


def _block(
    serial: int,
    start_ea: int,
    insn_eas: tuple[int, ...] = (),
    *,
    preds: tuple[int, ...] = (),
    succs: tuple[int, ...] = (),
) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=0,
        succs=succs,
        preds=preds,
        flags=0,
        start_ea=start_ea,
        insn_snapshots=tuple(
            InsnSnapshot(opcode=0, ea=ea, operands=()) for ea in insn_eas
        ),
    )


def test_conditional_handler_routes_bind_imported_target_serial() -> None:
    predicate_ea = 0xF1C00400
    true_state = 0x7F9D6412
    false_state = 0xA7933EA0
    graph = FlowGraph(
        blocks={
            124: _block(124, 0x40B3F3),
            300: _block(300, 0x40A560),
            304: _block(304, 0x40A560, (predicate_ea,)),
        },
        entry_serial=304,
        func_ea=0x40A560,
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=predicate_ea,
        source_block_ea=0x40A560,
        materialized_anchor_eas=(predicate_ea,),
        target_eas=(0x40B3F3, 0x40C1A0),
        condition_code=5,
        true_target_ea=0x40B3F3,
        false_target_ea=0x40C1A0,
        resolver_kind="conditional_handler_bridge",
        predicate_true_state=true_state,
        predicate_false_state=false_state,
        predicate_true_is_taken=True,
        predicate_preserve_live=True,
    )

    assert _build_conditional_handler_state_routes(
        graph,
        (transfer,),
        target_serial_resolver=lambda ea: 300 if ea == 0x40C1A0 else None,
    ) == (
        MaterializedStateRoute(304, true_state, 124, proof_kind="conditional_arm"),
        MaterializedStateRoute(304, false_state, 300, proof_kind="conditional_arm"),
    )


def test_conditional_handler_routes_bind_both_arms_from_exact_state_map() -> None:
    predicate_ea = 0xF1C01534
    true_state = 0x7F9D6412
    false_state = 0xA7933EA0
    graph = FlowGraph(
        blocks={
            124: _block(124, 0x40A560),
            300: _block(300, 0x40A560),
            304: _block(304, 0x40A560, (predicate_ea,)),
        },
        entry_serial=304,
        func_ea=0x40A560,
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=predicate_ea,
        source_block_ea=0x40A560,
        materialized_anchor_eas=(predicate_ea,),
        target_eas=(0x40B3F3, 0x40C1A0),
        condition_code=5,
        true_target_ea=0x40B3F3,
        false_target_ea=0x40C1A0,
        resolver_kind="conditional_handler_bridge",
        predicate_true_state=true_state,
        predicate_false_state=false_state,
        predicate_true_is_taken=True,
        predicate_preserve_live=True,
    )

    assert _build_conditional_handler_state_routes(
        graph,
        (transfer,),
        exact_handler_by_state={true_state: 124, false_state: 300},
    ) == (
        MaterializedStateRoute(304, true_state, 124, proof_kind="conditional_arm"),
        MaterializedStateRoute(304, false_state, 300, proof_kind="conditional_arm"),
    )


def test_conditional_handler_routes_prefer_imported_target_over_native_copy() -> None:
    predicate_ea = 0x40C5D1
    true_state = 0x78BAC34B
    false_state = 0x1F0B7687
    graph = FlowGraph(
        blocks={
            21: _block(21, 0x40A7AE),
            98: _block(98, 0x40B100),
            247: BlockSnapshot(
                serial=247,
                block_type=0,
                succs=(248, 415),
                preds=(246,),
                flags=0,
                start_ea=0x40C586,
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=0,
                        ea=predicate_ea,
                        operands=(),
                        kind=InsnKind.EQUALITY_JUMP,
                        is_conditional_jump=True,
                    ),
                ),
            ),
            307: _block(307, 0x40A560),
            308: _block(308, 0x40A560, (predicate_ea,)),
        },
        entry_serial=247,
        func_ea=0x40A560,
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=predicate_ea,
        source_block_ea=0x40C5BD,
        materialized_anchor_eas=(predicate_ea,),
        target_eas=(0x40B100, 0x40A7AE),
        condition_code=5,
        true_target_ea=0x40B100,
        false_target_ea=0x40A7AE,
        resolver_kind="conditional_handler_bridge",
        predicate_true_state=true_state,
        predicate_false_state=false_state,
        predicate_true_is_taken=True,
        predicate_preserve_live=True,
    )

    assert _build_conditional_handler_state_routes(
        graph,
        (transfer,),
        target_serial_resolver=lambda ea: 307 if ea == 0x40A7AE else None,
    ) == (
        MaterializedStateRoute(247, false_state, 307, proof_kind="conditional_arm"),
        MaterializedStateRoute(247, true_state, 98, proof_kind="conditional_arm"),
    )


def test_conditional_handler_routes_bind_imported_arm_successors() -> None:
    predicate_ea = 0xF1C00400
    true_state = 0xB34CE2DF
    false_state = 0x82F1899D
    graph = FlowGraph(
        blocks={
            156: _block(156, 0x40BC50),
            179: _block(179, 0x40BCBA),
            305: _block(305, 0x40A560, succs=(306, 308)),
            306: _block(306, 0x40A560, preds=(305,), succs=(307,)),
            307: _block(307, 0x40A560, preds=(306, 308)),
            308: _block(308, 0x40A560, preds=(305,), succs=(307,)),
        },
        entry_serial=305,
        func_ea=0x40A560,
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=predicate_ea,
        source_block_ea=0x40A560,
        materialized_anchor_eas=(predicate_ea,),
        target_eas=(0x40BCBA, 0x40BC50),
        condition_code=5,
        true_target_ea=0x40BCBA,
        false_target_ea=0x40BC50,
        resolver_kind="conditional_handler_bridge",
        predicate_true_state=true_state,
        predicate_false_state=false_state,
        predicate_true_is_taken=True,
        predicate_preserve_live=True,
    )

    assert _build_conditional_handler_state_routes(
        graph,
        (transfer,),
        arm_source_serial_resolver=lambda _transfer: (306, 308),
    ) == (
        MaterializedStateRoute(306, true_state, 179, proof_kind="conditional_arm"),
        MaterializedStateRoute(308, false_state, 156, proof_kind="conditional_arm"),
    )


def test_validated_setcc_target_survives_live_condition_chain_snapshot_and_lowering(
    monkeypatch,
):
    state = 0x304E8694
    unrelated_state = 0xA7933EA0
    graph = FlowGraph(
        blocks={
            124: _block(124, 0x40A5F0),
            129: _block(129, 0x40B32C),
            130: _block(130, 0x40C180),
            203: _block(203, 0x40B33A, (0x40B34E,)),
            204: _block(204, 0x40C1A0),
            234: _block(234, 0x40C842),
        },
        entry_serial=234,
        func_ea=0x40A560,
    )
    validated = MaterializedIndirectTransfer(
        source_jmp_ea=0x40B340,
        source_block_ea=0x40B32C,
        materialized_anchor_eas=(),
        target_eas=(0x40B342,),
        next_target_ea=0x40B354,
        selector_state_var_reg=20,
        selector_state_constant=state,
        resolver_kind="static_equality_route",
    )

    class _Row:
        def __init__(self, state_const: int, target_block: int, compare_block: int):
            self.state_const = state_const
            self.target_block = target_block
            self.compare_block = compare_block

    class _DispatchMap:
        router_kind = RouterKind.CONDITION_CHAIN
        dispatcher_entry_block = 124
        dispatcher_blocks = frozenset({124, 129, 130})
        rows = (
            _Row(state, 203, 129),
            _Row(unrelated_state, 204, 130),
        )

    class _Recovery:
        dispatch_map = _DispatchMap()
        state_var_reg = 20

    from d810.analyses.control_flow import dispatcher_recovery

    translator_module = ModuleType("d810.hexrays.mutation.ir_translator")
    translator_module.lift = lambda _mba: graph
    monkeypatch.setitem(
        sys.modules,
        "d810.hexrays.mutation.ir_translator",
        translator_module,
    )
    monkeypatch.setattr(
        dispatcher_recovery,
        "recover_dispatcher",
        lambda _graph, _hints, *, materialized_indirect_transfers: _Recovery(),
    )

    snapshot_evidence = _recover_condition_chain_handler_transfers_from_mba(
        (validated,),
        object(),
    )

    # The live router reports a glue block for the same state, but the already
    # validated native body is authoritative.  The unrelated row proves the
    # collector ran instead of merely returning no evidence.
    live_rows = tuple(
        transfer
        for transfer in snapshot_evidence
        if transfer.resolver_kind == "live_state_dispatcher_row_evidence"
    )
    assert tuple(transfer.selector_state_constant for transfer in live_rows) == (
        state,
        unrelated_state,
    )
    assert {transfer.dispatcher_entry_ea for transfer in live_rows} == {0x40A5F0}
    assert {transfer.dispatcher_router_eas for transfer in live_rows} == {
        (0x40A5F0, 0x40B32C, 0x40C180)
    }
    condition_rows = tuple(
        transfer
        for transfer in snapshot_evidence
        if transfer.resolver_kind == "condition_chain_handler_evidence"
    )
    assert tuple(transfer.selector_state_constant for transfer in condition_rows) == (
        unrelated_state,
    )
    assert condition_rows[0].dispatcher_entry_ea == 0x40A5F0
    assert condition_rows[0].target_eas == (0x40C1A0,)

    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(
            StateWriteAnchor(234, state, state_var_reg=20, instruction_ea=0x40C842),
        ),
        out_reg_maps={234: {20: state}},
        dispatcher_entry_serial=124,
        state_var_reg=20,
        handler_serials=frozenset({204}),
        dispatcher_block_serials=frozenset({124, 129}),
        handler_targets={state: 129},
        state_register_name="ebx",
        handler_state_resolver=lambda *_args, **_kwargs: None,
        transfers=(validated, *snapshot_evidence),
        route_resolver=lambda *_args, **_kwargs: None,
    )

    assert routes == (MaterializedStateRoute(234, state, 203),)


def test_materialized_state_routes_use_latest_matching_transfer_and_full_reg_snapshot():
    state = 0xF6A636EF
    graph = FlowGraph(
        blocks={
            71: _block(71, 0x7100, (0x7110,)),
            124: _block(124, 0x4000),
            203: _block(203, 0x9000, (0x9004,)),
        },
        entry_serial=71,
        func_ea=0x40A560,
    )
    transfers = (
        MaterializedIndirectTransfer(
            0x7105,
            0x4100,
            (0x7100,),
            (0x9000,),
            context_register_values=((28, 0xFDEE1C81),),
            source_register_values=((12, 0x48B7FC),),
            corridor_register_snapshots=((0x4200, ((16, 0x48B7FC),)),),
        ),
        MaterializedIndirectTransfer(
            0x7110,
            0x5000,
            (0x7110,),
            (0x9000,),
            context_register_values=((28, 0xFDEE1C81),),
            source_register_values=((12, 0x48B7FC),),
        ),
    )
    calls = []

    def route(
        start_ea,
        *,
        initial_mregs,
        handler_eas,
        register_snapshots_by_ea,
        dispatch_anchor_eas,
    ):
        calls.append(
            (
                start_ea,
                dict(initial_mregs),
                handler_eas,
                register_snapshots_by_ea,
                dispatch_anchor_eas,
            )
        )
        return 0x9000

    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(StateWriteAnchor(71, state, state_var_reg=20),),
        out_reg_maps={71: {4: 0x1234, 20: 0}},
        dispatcher_entry_serial=124,
        state_var_reg=20,
        handler_serials=frozenset({203}),
        transfers=transfers,
        route_resolver=route,
    )

    assert routes == (MaterializedStateRoute(71, state, 203),)
    assert calls == [
        (
            0x5000,
            {4: 0x1234, 20: state, 28: 0xFDEE1C81},
            frozenset({0x9000, 0x9004}),
            {
                0x4100: {12: 0x48B7FC},
                0x4200: {16: 0x48B7FC},
                0x5000: {12: 0x48B7FC},
            },
            frozenset({0x7100, 0x7110}),
        )
    ]


def test_materialized_state_routes_replay_handler_when_microcode_lost_state_write():
    incoming_state = 0xA5540595
    next_state = 0xBCDE2EFB
    graph = FlowGraph(
        blocks={
            8: _block(8, 0x4000),
            183: _block(183, 0x3000),
            213: _block(213, 0x40C4F6),
        },
        entry_serial=213,
        func_ea=0x40A560,
    )
    calls = []

    def replay_handler_state(
        start_ea,
        *,
        initial_mregs,
        state_register_name,
        dispatch_anchor_eas,
    ):
        calls.append((start_ea, dict(initial_mregs), state_register_name))
        return _ConcreteHandlerStateWrite(next_state, 0x4000)

    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(),
        out_reg_maps={},
        dispatcher_entry_serial=8,
        state_var_reg=20,
        handler_serials=frozenset({183}),
        dispatcher_block_serials=frozenset({8}),
        transfers=(
            MaterializedIndirectTransfer(
                source_jmp_ea=0x40A5F0,
                source_block_ea=0x40A5F0,
                materialized_anchor_eas=(0x40A5F0,),
                target_eas=(0x40C4F6,),
                selector_state_constant=incoming_state,
                resolver_kind="condition_chain_handler_evidence",
            ),
        ),
        handler_targets={next_state: 183},
        handler_state_resolver=replay_handler_state,
        state_register_name="ebx",
    )

    assert routes == (
        MaterializedStateRoute(
            213,
            next_state,
            183,
            source_handler_serial=213,
            handler_exit_proven=True,
        ),
    )
    assert calls == [
        (
            0x40C4F6,
            {20: incoming_state},
            "ebx",
        )
    ]


def test_materialized_state_routes_replay_imported_handler_at_native_entry_alias():
    incoming_state = 0x1F0B7687
    next_state = 0xB34CE2DF
    graph = FlowGraph(
        blocks={
            8: _block(8, 0x4000),
            179: _block(179, 0x40BCBA),
            304: _block(304, 0x40A560),
        },
        entry_serial=304,
        func_ea=0x40A560,
    )
    replay_starts = []

    def replay_handler_state(
        start_ea,
        *,
        initial_mregs,
        state_register_name,
        dispatch_anchor_eas,
    ):
        replay_starts.append(start_ea)
        return _ConcreteHandlerStateWrite(next_state, 0x40A7EF)

    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(),
        out_reg_maps={},
        dispatcher_entry_serial=8,
        state_var_reg=20,
        handler_serials=frozenset({179, 304}),
        dispatcher_block_serials=frozenset({8}),
        transfers=(),
        handler_states={304: (incoming_state,)},
        handler_targets={next_state: 179},
        handler_entry_eas_by_serial={304: 0x40A7AE},
        handler_state_resolver=replay_handler_state,
        state_register_name="ebx",
    )

    assert routes == (
        MaterializedStateRoute(
            304,
            next_state,
            179,
            source_handler_serial=304,
            handler_exit_proven=True,
        ),
    )
    assert replay_starts == [0x40A7AE]


def test_materialized_state_routes_recover_final_state_near_live_handler_tail():
    incoming_state = 0x96B0D1E5
    final_state = 0x7F9D6412
    graph = FlowGraph(
        blocks={
            8: _block(8, 0x40A5F0),
            116: _block(116, 0x40B3F3),
            207: _block(207, 0x40C3E7),
        },
        entry_serial=207,
        func_ea=0x40A560,
    )
    tail_calls = []

    def replay_unchanged_state(
        start_ea,
        *,
        initial_mregs,
        state_register_name,
        dispatch_anchor_eas,
    ):
        assert start_ea == 0x40C3E7
        return _ConcreteHandlerStateWrite(incoming_state, start_ea)

    def recover_tail_state(block, *, state_var_reg, incoming_state):
        tail_calls.append((block.serial, state_var_reg, incoming_state))
        return final_state

    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(),
        out_reg_maps={},
        dispatcher_entry_serial=8,
        state_var_reg=20,
        handler_serials=frozenset({116, 207}),
        dispatcher_block_serials=frozenset({8}),
        transfers=(),
        handler_states={207: (incoming_state,)},
        handler_targets={final_state: 116},
        handler_state_resolver=replay_unchanged_state,
        handler_exit_state_resolver=recover_tail_state,
        state_register_name="ebx",
    )

    assert routes == (
        MaterializedStateRoute(
            207,
            final_state,
            116,
            source_handler_serial=207,
            handler_exit_proven=True,
        ),
    )
    assert tail_calls == [(207, 20, incoming_state)]


def test_materialized_state_routes_prefer_live_tail_over_intermediate_replay():
    incoming_state = 0x96B0D1E5
    intermediate_state = 0xA5A94B86
    final_state = 0x7F9D6412
    graph = FlowGraph(
        blocks={
            8: _block(8, 0x40A5F0),
            116: _block(116, 0x40B3F3),
            162: _block(162, 0x40BCA3),
            207: _block(207, 0x40C3E7),
        },
        entry_serial=207,
        func_ea=0x40A560,
    )

    def replay_intermediate_state(
        start_ea,
        *,
        initial_mregs,
        state_register_name,
        dispatch_anchor_eas,
    ):
        return _ConcreteHandlerStateWrite(intermediate_state, start_ea)

    def recover_tail_state(block, *, state_var_reg, incoming_state):
        assert block.serial == 207
        return final_state

    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(),
        out_reg_maps={},
        dispatcher_entry_serial=8,
        state_var_reg=20,
        handler_serials=frozenset({116, 162, 207}),
        dispatcher_block_serials=frozenset({8}),
        transfers=(),
        handler_states={207: (incoming_state,)},
        handler_targets={intermediate_state: 162, final_state: 116},
        handler_state_resolver=replay_intermediate_state,
        handler_exit_state_resolver=recover_tail_state,
        state_register_name="ebx",
    )

    assert routes == (
        MaterializedStateRoute(
            207,
            final_state,
            116,
            source_handler_serial=207,
            handler_exit_proven=True,
        ),
    )


def test_materialized_handler_exit_route_preserves_live_terminal_corridor():
    incoming_state = 0x96397DAD
    final_state = 0x69225E4
    source_native_ea = 0x40CC1C
    terminal_native_ea = 0x40CD8C
    graph = FlowGraph(
        blocks={
            8: _block(8, 0x40C9DB),
            118: _block(118, source_native_ea, (source_native_ea,), succs=(119,)),
            119: _block(
                119,
                source_native_ea + 1,
                (source_native_ea + 1,),
                succs=(74,),
            ),
            74: BlockSnapshot(
                serial=74,
                block_type=1,
                succs=(178,),
                preds=(119,),
                flags=0,
                start_ea=terminal_native_ea,
                insn_snapshots=(),
                kind=BlockKind.ONE_WAY,
            ),
            178: BlockSnapshot(
                serial=178,
                block_type=7,
                succs=(),
                preds=(74,),
                flags=0,
                start_ea=0xFFFFFFFFFFFFFFFF,
                insn_snapshots=(),
                kind=BlockKind.STOP,
            ),
        },
        entry_serial=118,
        func_ea=0x40C8B0,
    )
    terminal_exit = MaterializedIndirectTransfer(
        source_jmp_ea=0x40CC34,
        source_block_ea=source_native_ea,
        materialized_anchor_eas=(),
        target_eas=(terminal_native_ea,),
        selector_state_var_reg=20,
        selector_state_constant=final_state,
        resolver_kind="static_handler_exit_route",
    )
    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(),
        out_reg_maps={},
        dispatcher_entry_serial=8,
        state_var_reg=20,
        handler_serials=frozenset({74, 118}),
        dispatcher_block_serials=frozenset({8}),
        transfers=(terminal_exit,),
        handler_states={118: (incoming_state,)},
        handler_targets={final_state: 74},
        handler_entry_eas_by_serial={118: source_native_ea},
        handler_exit_state_resolver=(
            lambda _block, *, state_var_reg, incoming_state: final_state
        ),
        terminal_target_resolver=lambda ea: int(ea) == terminal_native_ea,
        state_register_name="ebx",
    )

    assert routes == (
        MaterializedStateRoute(
            119,
            final_state,
            178,
            source_handler_serial=118,
            handler_exit_proven=True,
            proof_kind="terminal_state_route",
            source_native_ea=source_native_ea,
            target_native_ea=terminal_native_ea,
        ),
    )


def test_live_tail_state_preserves_precise_replayed_exit_owner():
    incoming_state = 0x1F0B7687
    final_state = 0xB34CE2DF
    graph = FlowGraph(
        blocks={
            8: _block(8, 0x40A607),
            21: _block(21, 0x40A7AE),
            23: _block(23, 0x40A7E5, (0x40A7EF,)),
            179: _block(179, 0x40BCA3),
        },
        entry_serial=21,
        func_ea=0x40A560,
    )

    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(),
        out_reg_maps={},
        dispatcher_entry_serial=8,
        state_var_reg=20,
        handler_serials=frozenset({21, 179}),
        transfers=(),
        handler_states={21: (incoming_state,)},
        handler_targets={final_state: 179},
        handler_state_resolver=lambda *_args, **_kwargs: _ConcreteHandlerStateWrite(
            final_state, 0x40A7EF
        ),
        handler_exit_state_resolver=lambda *_args, **_kwargs: final_state,
        state_register_name="ebx",
    )

    assert routes == (
        MaterializedStateRoute(
            23,
            final_state,
            179,
            source_handler_serial=21,
            handler_exit_proven=True,
        ),
    )


def test_materialized_state_routes_use_live_tail_when_native_replay_raises():
    incoming_state = 0x96B0D1E5
    final_state = 0x7F9D6412
    graph = FlowGraph(
        blocks={
            8: _block(8, 0x40A5F0),
            116: _block(116, 0x40B3F3),
            207: _block(207, 0x40C3E7),
        },
        entry_serial=207,
        func_ea=0x40A560,
    )

    def replay_detached_native_tail(*_args, **_kwargs):
        raise RuntimeError("native replay cannot enter the detached tail")

    def recover_tail_state(block, *, state_var_reg, incoming_state):
        assert block.serial == 207
        assert state_var_reg == 20
        return final_state

    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(),
        out_reg_maps={},
        dispatcher_entry_serial=8,
        state_var_reg=20,
        handler_serials=frozenset({116, 207}),
        dispatcher_block_serials=frozenset({8}),
        transfers=(
            MaterializedIndirectTransfer(
                source_jmp_ea=0x40C3D9,
                source_block_ea=0x40C3D9,
                materialized_anchor_eas=(0x40C3D9,),
                target_eas=(0x40C3E7,),
                selector_state_constant=incoming_state,
                resolver_kind="condition_chain_handler_evidence",
            ),
        ),
        handler_targets={final_state: 116},
        handler_state_resolver=replay_detached_native_tail,
        handler_exit_state_resolver=recover_tail_state,
        state_register_name="ebx",
    )

    assert routes == (
        MaterializedStateRoute(
            207,
            final_state,
            116,
            source_handler_serial=207,
            handler_exit_proven=True,
        ),
    )


def test_unique_handler_evidence_exonerates_dispatcher_labeled_replay_source():
    incoming_state = 0x96B0D1E5
    final_state = 0x7F9D6412
    graph = FlowGraph(
        blocks={
            8: _block(8, 0x40A5F0),
            116: _block(116, 0x40B3F3),
            207: _block(207, 0x40C3E7),
        },
        entry_serial=207,
        func_ea=0x40A560,
    )

    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(),
        out_reg_maps={},
        dispatcher_entry_serial=8,
        state_var_reg=20,
        handler_serials=frozenset({116}),
        dispatcher_block_serials=frozenset({8, 207}),
        transfers=(
            MaterializedIndirectTransfer(
                source_jmp_ea=0x40C3D9,
                source_block_ea=0x40C3D9,
                materialized_anchor_eas=(0x40C3D9,),
                target_eas=(0x40C3E7,),
                selector_state_constant=incoming_state,
                resolver_kind="condition_chain_handler_evidence",
            ),
        ),
        handler_targets={final_state: 116},
        handler_state_resolver=lambda *_args, **_kwargs: None,
        handler_exit_state_resolver=lambda *_args, **_kwargs: final_state,
        state_register_name="ebx",
    )

    assert routes == (
        MaterializedStateRoute(
            207,
            final_state,
            116,
            source_handler_serial=207,
            handler_exit_proven=True,
        ),
    )


def test_materialized_state_routes_route_replayed_range_state_through_dispatcher():
    incoming_state = 0x7C4FB03D
    next_state = 0xF6A636EF
    graph = FlowGraph(
        blocks={
            8: _block(8, 0x40A5F0),
            77: _block(77, 0x40AD96),
            154: _block(154, 0x40BCF9),
        },
        entry_serial=77,
        func_ea=0x40A560,
    )
    dispatch_calls = []
    interval_calls = []

    def replay_handler_state(
        start_ea,
        *,
        initial_mregs,
        state_register_name,
        dispatch_anchor_eas,
    ):
        assert start_ea == 0x40AD96
        assert initial_mregs[20] == incoming_state
        return _ConcreteHandlerStateWrite(next_state, 0x40A5F0)

    def route_dispatcher(
        start_ea,
        *,
        initial_mregs,
        handler_eas,
        register_snapshots_by_ea,
        dispatch_anchor_eas,
    ):
        dispatch_calls.append((start_ea, dict(initial_mregs), handler_eas))
        return 0x40BCF9

    def route_interval(state):
        interval_calls.append(state)
        return 154

    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(),
        out_reg_maps={},
        dispatcher_entry_serial=8,
        state_var_reg=20,
        handler_serials=frozenset({77, 154}),
        dispatcher_block_serials=frozenset({8}),
        transfers=(),
        route_resolver=route_dispatcher,
        handler_states={77: (incoming_state,)},
        handler_targets={incoming_state: 77},
        handler_target_resolver=route_interval,
        handler_state_resolver=replay_handler_state,
        state_register_name="ebx",
    )

    assert routes == (
        MaterializedStateRoute(
            77,
            next_state,
            154,
            source_handler_serial=77,
            handler_exit_proven=True,
        ),
    )
    assert interval_calls == [next_state]
    assert dispatch_calls == []


def test_materialized_state_routes_continue_from_internal_router_block():
    incoming_state = 0x7C4FB03D
    next_state = 0xF6A636EF
    graph = FlowGraph(
        blocks={
            8: _block(8, 0x40A5F0),
            9: _block(9, 0x40B6C0),
            77: _block(77, 0x40AD96),
            154: _block(154, 0x40BCF9),
        },
        entry_serial=77,
        func_ea=0x40A560,
    )

    def replay_handler_state(
        start_ea,
        *,
        initial_mregs,
        state_register_name,
        dispatch_anchor_eas,
    ):
        return _ConcreteHandlerStateWrite(next_state, 0x40A5F0)

    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(),
        out_reg_maps={},
        dispatcher_entry_serial=8,
        state_var_reg=20,
        handler_serials=frozenset({77, 154}),
        dispatcher_block_serials=frozenset({8, 9}),
        transfers=(
            MaterializedIndirectTransfer(
                source_jmp_ea=0x40B6C5,
                source_block_ea=0x40B6C0,
                materialized_anchor_eas=(0x40B6C0,),
                target_eas=(0x40BCF9,),
                selector_state_constant=next_state,
                resolver_kind="static_equality_route",
            ),
        ),
        route_resolver=lambda *_args, **_kwargs: None,
        handler_states={77: (incoming_state,)},
        handler_targets={incoming_state: 77},
        handler_target_resolver=lambda _state: 9,
        handler_state_resolver=replay_handler_state,
        state_register_name="ebx",
    )

    assert routes == (
        MaterializedStateRoute(
            77,
            next_state,
            154,
            source_handler_serial=77,
            handler_exit_proven=True,
        ),
    )


def test_materialized_state_routes_evaluate_condition_chain_after_glue():
    incoming_state = 0x4A7ECCB8
    next_state = 0xDC71BBC5
    graph = FlowGraph(
        blocks={
            8: _block(8, 0x4000),
            9: _block(9, 0x5000, succs=(10,)),
            10: _block(10, 0x6000, succs=(154, 155)),
            77: _block(77, 0x7000),
            154: _block(154, 0x8000),
            155: _block(155, 0x9000),
        },
        entry_serial=77,
        func_ea=0x1000,
    )
    decision_dag = DecisionDag(
        32,
        {10: RouteComparison(10, "jz", next_state, 154, 155)},
        root=10,
    )

    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(),
        out_reg_maps={},
        dispatcher_entry_serial=8,
        state_var_reg=20,
        handler_serials=frozenset({77, 154, 155}),
        dispatcher_block_serials=frozenset({8, 9, 10}),
        transfers=(),
        handler_states={77: (incoming_state,)},
        handler_targets={incoming_state: 77, next_state: 9},
        handler_state_resolver=lambda *_args, **_kwargs: _ConcreteHandlerStateWrite(
            next_state,
            0x7000,
        ),
        condition_chain_dag=decision_dag,
        state_register_name="ebx",
    )

    assert routes == (
        MaterializedStateRoute(
            77,
            next_state,
            154,
            source_handler_serial=77,
            handler_exit_proven=True,
        ),
    )


def test_materialized_state_routes_replay_from_microcode_selected_router_anchor():
    incoming_state = 0x7C4FB03D
    next_state = 0xF6A636EF
    graph = FlowGraph(
        blocks={
            8: _block(8, 0x40A5F0),
            145: _block(145, 0x40B940),
            77: _block(77, 0x40AD96),
            154: _block(154, 0x40BCF9),
        },
        entry_serial=77,
        func_ea=0x40A560,
    )
    dispatch_starts = []

    def replay_handler_state(
        start_ea,
        *,
        initial_mregs,
        state_register_name,
        dispatch_anchor_eas,
    ):
        return _ConcreteHandlerStateWrite(next_state, 0x40A5F0)

    def route_dispatcher(
        start_ea,
        *,
        initial_mregs,
        handler_eas,
        register_snapshots_by_ea,
        dispatch_anchor_eas,
    ):
        dispatch_starts.append(start_ea)
        return 0x40BCF9 if start_ea == 0x40B940 else None

    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(),
        out_reg_maps={},
        dispatcher_entry_serial=8,
        state_var_reg=20,
        handler_serials=frozenset({77, 154}),
        dispatcher_block_serials=frozenset({8, 145}),
        transfers=(),
        route_resolver=route_dispatcher,
        handler_states={77: (incoming_state,)},
        handler_targets={incoming_state: 77},
        handler_target_resolver=lambda _state: 145,
        handler_state_resolver=replay_handler_state,
        state_register_name="ebx",
    )

    assert routes == (
        MaterializedStateRoute(
            77,
            next_state,
            154,
            source_handler_serial=77,
            handler_exit_proven=True,
        ),
    )
    assert dispatch_starts == [0x40B940]


def test_materialized_state_routes_try_dispatch_entry_router_successors():
    incoming_state = 0x7C4FB03D
    next_state = 0xF6A636EF
    graph = FlowGraph(
        blocks={
            8: _block(8, 0x40A5F0, succs=(9, 131)),
            9: _block(9, 0x40A607),
            131: _block(131, 0x40B6C0),
            145: _block(145, 0x40B940),
            77: _block(77, 0x40AD96),
            154: _block(154, 0x40BCF9),
        },
        entry_serial=77,
        func_ea=0x40A560,
    )
    dispatch_starts = []

    def replay_handler_state(
        start_ea,
        *,
        initial_mregs,
        state_register_name,
        dispatch_anchor_eas,
    ):
        return _ConcreteHandlerStateWrite(next_state, 0x40A5F0)

    def route_dispatcher(
        start_ea,
        *,
        initial_mregs,
        handler_eas,
        register_snapshots_by_ea,
        dispatch_anchor_eas,
    ):
        dispatch_starts.append(start_ea)
        return 0x40BCF9 if start_ea == 0x40B6C0 else None

    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(),
        out_reg_maps={},
        dispatcher_entry_serial=8,
        state_var_reg=20,
        handler_serials=frozenset({77, 154}),
        dispatcher_block_serials=frozenset({8, 9, 131, 145}),
        transfers=(),
        route_resolver=route_dispatcher,
        handler_states={77: (incoming_state,)},
        handler_targets={incoming_state: 77},
        handler_target_resolver=lambda _state: 145,
        handler_state_resolver=replay_handler_state,
        state_register_name="ebx",
    )

    assert routes == (
        MaterializedStateRoute(
            77,
            next_state,
            154,
            source_handler_serial=77,
            handler_exit_proven=True,
        ),
    )
    assert dispatch_starts == [0x40B940, 0x40A607, 0x40B6C0]


def test_materialized_state_routes_abstain_when_router_successors_disagree():
    incoming_state = 0x7C4FB03D
    next_state = 0xF6A636EF
    graph = FlowGraph(
        blocks={
            8: _block(8, 0x40A5F0, succs=(9, 131)),
            9: _block(9, 0x40A607),
            131: _block(131, 0x40B6C0),
            145: _block(145, 0x40B940),
            77: _block(77, 0x40AD96),
            154: _block(154, 0x40BCF9),
            155: _block(155, 0x40BD10),
        },
        entry_serial=77,
        func_ea=0x40A560,
    )

    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(),
        out_reg_maps={},
        dispatcher_entry_serial=8,
        state_var_reg=20,
        handler_serials=frozenset({77, 154, 155}),
        dispatcher_block_serials=frozenset({8, 9, 131, 145}),
        transfers=(),
        route_resolver=lambda start_ea, **_kwargs: {
            0x40A607: 0x40BCF9,
            0x40B6C0: 0x40BD10,
        }.get(start_ea),
        handler_states={77: (incoming_state,)},
        handler_targets={incoming_state: 77},
        handler_target_resolver=lambda _state: 145,
        handler_state_resolver=lambda *_args, **_kwargs: _ConcreteHandlerStateWrite(
            next_state, 0x40A5F0
        ),
        state_register_name="ebx",
    )

    assert routes == ()


def test_materialized_state_routes_reject_dispatcher_node_as_handler_target():
    state = 0xE9795EF
    graph = FlowGraph(
        blocks={
            8: _block(8, 0x4000),
            67: _block(67, 0x40ACE7),
            71: _block(71, 0x7100),
            187: _block(187, 0x40C0C8),
        },
        entry_serial=71,
        func_ea=0x40A560,
    )

    def route_to_dispatcher_node(*_args, **_kwargs):
        return 0x40C0C8

    assert (
        _build_materialized_state_routes(
            graph,
            state_write_anchors=(StateWriteAnchor(71, state, state_var_reg=20),),
            out_reg_maps={71: {20: state}},
            dispatcher_entry_serial=8,
            state_var_reg=20,
            handler_serials=frozenset({67, 187}),
            dispatcher_block_serials=frozenset({8, 187}),
            transfers=(),
            route_resolver=route_to_dispatcher_node,
        )
        == ()
    )


def test_materialized_state_routes_keep_exact_handler_over_router_overlap():
    state = 0xF7088159
    graph = FlowGraph(
        blocks={
            8: _block(8, 0x40A5F0),
            71: _block(71, 0x7100),
            164: _block(164, 0x40BD0D),
        },
        entry_serial=71,
        func_ea=0x40A560,
    )

    assert _build_materialized_state_routes(
        graph,
        state_write_anchors=(StateWriteAnchor(71, state, state_var_reg=20),),
        out_reg_maps={71: {20: state}},
        dispatcher_entry_serial=8,
        state_var_reg=20,
        handler_serials=frozenset({164}),
        authoritative_handler_serials=frozenset({164}),
        dispatcher_block_serials=frozenset({8, 164}),
        transfers=(),
        route_resolver=lambda *_args, **_kwargs: 0x40BD0D,
    ) == (MaterializedStateRoute(71, state, 164),)


def test_materialized_state_routes_keep_resolver_proven_handler_over_router_overlap():
    state = 0xF7088159
    graph = FlowGraph(
        blocks={
            8: _block(8, 0x40A5F0),
            71: _block(71, 0x7100),
            164: _block(164, 0x40BD0D),
        },
        entry_serial=71,
        func_ea=0x40A560,
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x40BCF4,
        source_block_ea=0x40BCF9,
        materialized_anchor_eas=(0x40BCF9,),
        target_eas=(0x40BD0D,),
        selector_state_constant=state,
        resolver_kind="condition_chain_handler_evidence",
    )

    assert _build_materialized_state_routes(
        graph,
        state_write_anchors=(StateWriteAnchor(71, state, state_var_reg=20),),
        out_reg_maps={71: {20: state}},
        dispatcher_entry_serial=8,
        state_var_reg=20,
        handler_serials=frozenset(),
        dispatcher_block_serials=frozenset({8, 164}),
        transfers=(transfer,),
        route_resolver=lambda *_args, **_kwargs: 0x40BD0D,
    ) == (MaterializedStateRoute(71, state, 164),)


def test_materialized_state_routes_limit_corridor_to_state_expected_handler():
    state = 0xE9795EF
    graph = FlowGraph(
        blocks={
            8: _block(8, 0x4000),
            67: _block(67, 0x40ACE7),
            71: _block(71, 0x7100),
            187: _block(187, 0x40C0C8),
        },
        entry_serial=71,
        func_ea=0x40A560,
    )
    accepted_handler_sets = []

    def route_to_expected_handler(
        _start_ea,
        *,
        initial_mregs,
        handler_eas,
        register_snapshots_by_ea,
        dispatch_anchor_eas,
    ):
        accepted_handler_sets.append(handler_eas)
        return 0x40ACE7

    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(StateWriteAnchor(71, state, state_var_reg=20),),
        out_reg_maps={71: {20: state}},
        dispatcher_entry_serial=8,
        state_var_reg=20,
        handler_serials=frozenset({67, 187}),
        handler_targets={state: 67},
        transfers=(),
        route_resolver=route_to_expected_handler,
    )

    assert routes == (MaterializedStateRoute(71, state, 67),)
    assert accepted_handler_sets == [frozenset({0x40ACE7})]


def test_handler_replay_follows_entry_dispatch_and_keys_exact_exit_block():
    incoming_state = 0xCB1F8618
    next_state = 0x7C4FB03D
    graph = FlowGraph(
        blocks={
            8: _block(8, 0x4000),
            26: _block(26, 0x40B810, (0x40B879,)),
            77: _block(77, 0x40ADE6),
            143: _block(143, 0x40B804, (0x40B810,)),
        },
        entry_serial=143,
        func_ea=0x40A560,
    )
    replay_calls = []

    def replay_handler_state(
        start_ea,
        *,
        initial_mregs,
        state_register_name,
        dispatch_anchor_eas,
    ):
        replay_calls.append(start_ea)
        if start_ea == 0x40B804:
            return _ConcreteHandlerStateWrite(incoming_state, 0x40B80E)
        return _ConcreteHandlerStateWrite(next_state, 0x40B879)

    def resolve_handler_body(
        start_ea,
        *,
        initial_mregs,
        handler_eas,
        register_snapshots_by_ea,
        dispatch_anchor_eas,
        return_first_indirect_target,
    ):
        assert start_ea == 0x40B804
        assert handler_eas == frozenset({0x40B804, 0x40B810})
        assert not return_first_indirect_target
        return 0x40B810

    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(),
        out_reg_maps={},
        dispatcher_entry_serial=8,
        state_var_reg=20,
        handler_serials=frozenset({77, 143}),
        transfers=(),
        handler_states={143: (incoming_state,)},
        handler_targets={next_state: 77},
        handler_state_resolver=replay_handler_state,
        handler_entry_resolver=resolve_handler_body,
        state_register_name="ebx",
    )

    assert routes == (
        MaterializedStateRoute(
            26,
            next_state,
            77,
            source_handler_serial=143,
            handler_exit_proven=True,
        ),
    )
    assert replay_calls == [0x40B804, 0x40B810]


def test_concrete_handler_entry_requires_completed_indirect_dispatch():
    handler_eas = frozenset({0x9000, 0x9004})

    assert not _is_concrete_handler_entry(0x9004, handler_eas, 0)
    assert _is_concrete_handler_entry(0x9004, handler_eas, 1)
    assert not _is_concrete_handler_entry(0x9010, handler_eas, 3)


def test_native_writer_detection_uses_canonical_change_bit():
    class FakeInsn:
        def __init__(self, features):
            self.features = features

        def get_canon_feature(self):
            return self.features

    change_first = 0x2

    assert _insn_writes_first_operand(FakeInsn(0x2), change_first)
    assert _insn_writes_first_operand(FakeInsn(0xA), change_first)
    assert not _insn_writes_first_operand(FakeInsn(0x1), change_first)


def test_concrete_corridor_skips_only_flag_neutral_mov_store():
    assert _is_ignorable_corridor_store("mov")
    assert not _is_ignorable_corridor_store("add")
    assert not _is_ignorable_corridor_store("call")


def test_materialized_dispatch_instruction_accepts_both_branch_arms():
    assert _is_materialized_dispatch_instruction("jge")
    assert _is_materialized_dispatch_instruction("jmp")
    assert not _is_materialized_dispatch_instruction("mov")


def test_corridor_memory_alias_guard_distinguishes_stack_from_nonstack():
    assert _corridor_memory_spaces_may_alias("stack", "stack")
    assert _corridor_memory_spaces_may_alias("unknown", "nonstack")
    assert not _corridor_memory_spaces_may_alias("stack", "nonstack")


def test_materialized_state_routes_fall_back_to_dispatcher_and_abstain_off_handler():
    state = 0xA5A94B86
    graph = FlowGraph(
        blocks={
            71: _block(71, 0x7100),
            124: _block(124, 0x4000),
            203: _block(203, 0x9000),
        },
        entry_serial=71,
        func_ea=0x40A560,
    )
    starts: list[int] = []

    def route(
        start_ea,
        *,
        initial_mregs,
        handler_eas,
        register_snapshots_by_ea,
        dispatch_anchor_eas,
    ):
        starts.append(start_ea)
        return 0xDEAD

    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(
            StateWriteAnchor(71, state, state_var_reg=20),
            StateWriteAnchor(71, state, state_var_stkoff=0x44C),
        ),
        out_reg_maps={71: {20: state}},
        dispatcher_entry_serial=124,
        state_var_reg=20,
        handler_serials=frozenset({203}),
        transfers=(),
        route_resolver=route,
    )

    assert routes == ()
    assert starts == [0x4000]


def test_materialized_state_routes_partition_register_snapshot_at_anchor_ea():
    state = 0xAE5A330B
    graph = FlowGraph(
        blocks={
            70: _block(70, 0x7000),
            71: _block(71, 0x7100, preds=(70,)),
            124: _block(124, 0x4000),
            203: _block(203, 0x9000),
        },
        entry_serial=70,
        func_ea=0x40A560,
    )
    calls: list[tuple[int, dict[int, int]]] = []

    def route(
        start_ea,
        *,
        initial_mregs,
        handler_eas,
        register_snapshots_by_ea,
        dispatch_anchor_eas,
    ):
        calls.append((start_ea, dict(initial_mregs)))
        return 0x9000 if start_ea == 0x4000 and initial_mregs.get(4) == 0x1234 else None

    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(
            StateWriteAnchor(71, state, state_var_reg=20, instruction_ea=0x7110),
        ),
        in_stk_maps={71: {}},
        in_reg_maps={71: {}},
        out_stk_maps={70: {}},
        out_reg_maps={70: {4: 0x1234}, 71: {20: state}},
        dispatcher_entry_serial=124,
        state_var_reg=20,
        handler_serials=frozenset({203}),
        transfers=(),
        route_resolver=route,
    )

    assert routes == (MaterializedStateRoute(71, state, 203),)
    assert calls == [
        (0x7110, {20: state}),
        (0x7110, {4: 0x1234, 20: state}),
        (0x4000, {20: state}),
        (0x4000, {4: 0x1234, 20: state}),
    ]


def test_materialized_state_route_aliases_proven_dispatch_predecessor() -> None:
    state = 0xF32B2D3A
    graph = FlowGraph(
        blocks={
            80: _block(80, 0x8000, preds=(79,), succs=(81, 119)),
            81: _block(81, 0x8100, preds=(80,), succs=(124,)),
            119: _block(119, 0x8900, preds=(80,), succs=(6,)),
            124: _block(124, 0x4000, preds=(81,)),
            154: _block(154, 0x9000),
        },
        entry_serial=80,
        func_ea=0x40A560,
    )

    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(
            StateWriteAnchor(80, state, state_var_reg=20, instruction_ea=0x8010),
        ),
        in_stk_maps={80: {}},
        in_reg_maps={80: {}},
        out_stk_maps={79: {}},
        out_reg_maps={79: {}, 80: {20: state}, 81: {20: state}},
        dispatcher_entry_serial=124,
        state_var_reg=20,
        handler_serials=frozenset({154}),
        transfers=(),
        route_resolver=lambda *_args, **_kwargs: 0x9000,
    )

    assert routes == (
        MaterializedStateRoute(80, state, 154),
        MaterializedStateRoute(81, state, 154),
    )


def test_unique_static_equality_handler_targets_select_matching_arm() -> None:
    state = 0x2100AFDD
    exact = MaterializedIndirectTransfer(
        source_jmp_ea=0x40AEFE,
        source_block_ea=0x40AEE6,
        materialized_anchor_eas=(0x40AEF2, 0x40AEF8),
        target_eas=(0x40AF00, 0x40A5F0),
        condition_code=4,
        true_target_ea=0x40AF00,
        false_target_ea=0x40A5F0,
        selector_state_var_reg=20,
        selector_compare_constant=state,
        resolver_kind="static_equality_fixpoint",
    )
    residual = MaterializedIndirectTransfer(
        source_jmp_ea=0x40C6F7,
        source_block_ea=0x40C6F7,
        materialized_anchor_eas=(0x40C6F7,),
        target_eas=(0x40AEE6,),
        selector_state_constant=state,
        resolver_kind="residual_state_route",
    )
    assert _unique_static_equality_handler_targets((exact, residual), 20) == {
        state: 0x40AF00,
    }


def test_unique_static_equality_handler_targets_accept_static_fixpoint_leaf() -> None:
    state = 0x67C0FFE0
    exact = MaterializedIndirectTransfer(
        source_jmp_ea=0x40CD74,
        source_block_ea=0x40CD5B,
        materialized_anchor_eas=(0x40CD68, 0x40CD6E),
        target_eas=(0x40C9DB, 0x40CD76),
        condition_code=4,
        true_target_ea=0x40CD76,
        false_target_ea=0x40C9DB,
        selector_state_var_reg=20,
        selector_compare_constant=state,
        resolver_kind="static_fixpoint",
    )

    assert _unique_static_equality_handler_targets((exact,), 20) == {
        state: 0x40CD76,
    }


def test_claim_exact_function_tail_reparents_standalone_handler() -> None:
    parent = SimpleNamespace(start_ea=0x40A560, end_ea=0x40C700)
    detached = SimpleNamespace(start_ea=0x40B8E6, end_ea=0x40B940)
    owners = {0x40B8E6: detached}
    calls: list[tuple[object, ...]] = []

    def append_tail(function: object, start_ea: int, end_ea: int) -> bool:
        calls.append(("append", function, start_ea, end_ea))
        if owners.get(start_ea) is detached:
            return False
        owners[start_ea] = parent
        return True

    def delete_function(start_ea: int) -> bool:
        calls.append(("delete", start_ea))
        owners.pop(start_ea, None)
        return True

    assert _claim_exact_function_tail_range(
        parent,
        0x40B8E6,
        0x40B940,
        get_function=lambda ea: owners.get(ea),
        append_function_tail=append_tail,
        delete_function=delete_function,
    )
    assert calls == [
        ("append", parent, 0x40B8E6, 0x40B940),
        ("delete", 0x40B8E6),
        ("append", parent, 0x40B8E6, 0x40B940),
    ]


def test_claim_exact_function_tail_abstains_from_deleting_broader_owner() -> None:
    parent = SimpleNamespace(start_ea=0x40A560, end_ea=0x40C700)
    broader = SimpleNamespace(start_ea=0x40B800, end_ea=0x40BA00)
    deleted: list[int] = []

    assert not _claim_exact_function_tail_range(
        parent,
        0x40B8E6,
        0x40B940,
        get_function=lambda _ea: broader,
        append_function_tail=lambda *_args: False,
        delete_function=lambda ea: deleted.append(ea) or True,
    )
    assert deleted == []


def test_exact_equality_fragment_ownership_excludes_unvalidated_candidates() -> None:
    exact = MaterializedIndirectTransfer(
        source_jmp_ea=0x40BECA,
        source_block_ea=0x40BEB2,
        materialized_anchor_eas=(0x40BEBE, 0x40BEC4),
        target_eas=(0x40BECC, 0x40A5F0),
        resolver_kind="static_equality_fixpoint",
    )
    candidate = MaterializedIndirectTransfer(
        source_jmp_ea=0x40BECA,
        source_block_ea=0x40BEB2,
        materialized_anchor_eas=(0x40BEBE,),
        target_eas=(0x40BECC,),
        resolver_kind="static_equality_candidate",
    )
    route = MaterializedIndirectTransfer(
        source_jmp_ea=0x40C422,
        source_block_ea=0x40C422,
        materialized_anchor_eas=(0x40C422,),
        target_eas=(0x40B8E6,),
        resolver_kind="residual_state_route",
    )

    assert _exact_equality_fragment_transfers((exact, candidate, route)) == (exact,)


class _PreoptUnionFakeRanges:
    def __init__(self) -> None:
        self.ranges = self
        self.items: list[tuple[int, int]] = []

    def push_back(self, native_range: tuple[int, int]) -> None:
        self.items.append(native_range)


class _PreoptUnionFakeFailure:
    def desc(self) -> str:
        return "no error"


class _PreoptUnionFakeMba:
    def __init__(self, maturity: int, opcode: int, events: list[str]) -> None:
        self.maturity = int(maturity)
        self.qty = 1
        empty_operand = SimpleNamespace(t=0)
        instruction = SimpleNamespace(
            ea=0x2004,
            opcode=int(opcode),
            l=empty_operand,
            r=empty_operand,
            d=empty_operand,
            next=None,
        )
        self._block = SimpleNamespace(head=instruction, tail=instruction)
        self._events = events

    def get_mblock(self, serial: int):
        assert int(serial) == 0
        return self._block

    def build_graph(self) -> None:
        self._events.append("build_preopt_graph")


def test_preopt_resolver_cuts_exclude_materialized_multi_target_sites() -> None:
    resolution = ComputedGotoResolution(
        function_ea=0x1000,
        jmp_targets={
            0x1010: (0x2000,),
            0x1020: (0x2000, 0x3000),
        },
        reachable_eas=(0x1000,),
        arch="x86",
        executed_insns=0,
        seeds_run=0,
    )

    assert computed_goto_resolver._preopt_resolver_cut_eas(resolution) == (0x1010,)


def _install_preopt_union_success_harness(
    monkeypatch,
    *,
    closure_edges: tuple[NativeEdge, ...] | None = None,
    live_eas: frozenset[int] = frozenset({0x1100}),
    include_call: bool = True,
    capture_succeeds: bool = True,
    closure_terminal: NativeTerminalKind = NativeTerminalKind.NONE,
) -> dict[str, object]:
    import ida_funcs
    import ida_hexrays
    import idaapi

    function_ea = 0x1000
    seed_ea = 0x2000
    cut_ea = 0x200C
    resolution = ComputedGotoResolution(
        function_ea=function_ea,
        jmp_targets={cut_ea: tuple(sorted(live_eas))},
        reachable_eas=(function_ea, seed_ea),
        arch="x86",
        executed_insns=0,
        seeds_run=0,
    )
    route = MaterializedIndirectTransfer(
        source_jmp_ea=0x1800,
        source_block_ea=0x1800,
        materialized_anchor_eas=(),
        target_eas=(seed_ea,),
        resolver_kind="static_handler_entry_route",
        selector_state_var_reg=8,
        selector_state_constant=0x12345678,
    )
    cut = MaterializedIndirectTransfer(
        source_jmp_ea=cut_ea,
        source_block_ea=seed_ea,
        materialized_anchor_eas=(),
        target_eas=tuple(sorted(live_eas)),
        resolver_kind="detached_static_fixpoint",
    )
    exit_route = MaterializedIndirectTransfer(
        source_jmp_ea=cut_ea,
        source_block_ea=seed_ea,
        materialized_anchor_eas=(),
        target_eas=(0x1100,),
        resolver_kind="static_handler_exit_route",
        selector_state_var_reg=8,
        selector_state_constant=0x87654321,
    )
    _session, state = _resolver_session(resolution)
    state.materialized = True
    assert state.native_preanalysis.merge_materialized_transfers(
        state.native_key, (route, cut, exit_route)
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "_recover_static_handler_entry_route_transfers",
        lambda _transfers: (),
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "imported_detached_snippet_instruction_origins",
        lambda _mba: (),
    )
    range_calls: list[int] = []

    def native_ranges(target_ea: int, **_kwargs):
        range_calls.append(int(target_ea))
        return ((seed_ea, 0x2020),)

    monkeypatch.setattr(
        computed_goto_resolver,
        "_native_residual_fragment_ranges",
        native_ranges,
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "_live_mba_native_eas",
        lambda _mba, **_kwargs: live_eas,
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "imported_detached_snippet_instruction_origins",
        lambda _mba: (),
    )
    monkeypatch.setattr(
        ida_funcs,
        "get_func",
        lambda ea: (
            SimpleNamespace(start_ea=function_ea, end_ea=0x3000)
            if int(ea) == function_ea
            else None
        ),
    )
    edges = closure_edges
    if edges is None:
        edges = (
            NativeEdge(
                NativeEdgeKind.INDIRECT,
                0x1100,
                resolver_proven=True,
                provenance="resolver_cut",
                source_instruction_ea=cut_ea,
            ),
        )
    backend_calls: list[dict[str, object]] = []

    def build_cfg(function, **kwargs):
        backend_calls.append({"function": function, **kwargs})
        return SimpleNamespace(
            cfg=NativeCfg(
                {
                    seed_ea: NativeBlock(
                        seed_ea,
                        0x2010,
                        outgoing_edges=edges,
                        terminal=closure_terminal,
                    )
                }
            ),
            abstentions=(),
        )

    monkeypatch.setattr(
        computed_goto_resolver,
        "build_native_semantic_cfg",
        build_cfg,
        raising=False,
    )
    monkeypatch.setattr(ida_hexrays, "mba_ranges_t", _PreoptUnionFakeRanges)
    monkeypatch.setattr(ida_hexrays, "hexrays_failure_t", _PreoptUnionFakeFailure)
    monkeypatch.setattr(ida_hexrays, "DECOMP_NO_WAIT", 0x10, raising=False)
    monkeypatch.setattr(ida_hexrays, "DECOMP_ALL_BLKS", 0x20, raising=False)
    monkeypatch.setattr(ida_hexrays, "MMAT_PREOPTIMIZED", 1, raising=False)
    monkeypatch.setattr(ida_hexrays, "MMAT_CALLS", 4, raising=False)
    monkeypatch.setattr(ida_hexrays, "m_call", 7, raising=False)
    monkeypatch.setattr(ida_hexrays, "m_icall", 8, raising=False)
    monkeypatch.setattr(idaapi, "range_t", lambda start, end: (start, end))

    events: list[str] = []
    generated: list[tuple[tuple[tuple[int, int], ...], int, int]] = []
    preopt_mba = _PreoptUnionFakeMba(
        ida_hexrays.MMAT_PREOPTIMIZED,
        ida_hexrays.m_call if include_call else 0,
        events,
    )

    def generate(_generator, ranges, _failure, _retlist, flags, maturity):
        generated.append((tuple(ranges.items), int(flags), int(maturity)))
        events.append(f"generate_{int(maturity)}")
        return preopt_mba

    monkeypatch.setattr(
        computed_goto_resolver,
        "_generate_microcode_without_d810",
        generate,
    )
    captures: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def capture(*args: object, **kwargs: object):
        events.append("capture_preopt_union")
        captures.append((args, kwargs))
        return bool(capture_succeeds)

    monkeypatch.setattr(
        computed_goto_resolver,
        "capture_preopt_union_snippet_template",
        capture,
        raising=False,
    )
    return {
        "state": state,
        "function_ea": function_ea,
        "seed_ea": seed_ea,
        "cut_ea": cut_ea,
        "range_calls": range_calls,
        "backend_calls": backend_calls,
        "generated": generated,
        "captures": captures,
        "events": events,
        "live_mba": object(),
    }


def test_prepare_preopt_union_closure_publishes_one_idempotent_union(
    monkeypatch,
) -> None:
    harness = _install_preopt_union_success_harness(monkeypatch)

    first = computed_goto_resolver.prepare_preopt_union_closure(
        harness["state"],
        live_mba=harness["live_mba"],
    )
    second = computed_goto_resolver.prepare_preopt_union_closure(
        harness["state"],
        live_mba=harness["live_mba"],
    )

    assert first.prepared and first.published
    assert second.prepared and not second.published
    assert first.primary_seed_ea == harness["seed_ea"]
    assert first.seed_eas == (harness["seed_ea"],)
    assert first.native_ranges == ((harness["seed_ea"], 0x2010),)
    assert first.imported_block_entry_eas == (harness["seed_ea"],)
    assert (
        computed_goto_resolver.get_prepared_preopt_union_closure(harness["state"])
        == first
    )
    facts = harness["state"].native_preanalysis.facts
    assert facts is not None
    assert facts.semantic_closure is not None
    assert facts.semantic_closure.included_block_eas == (harness["seed_ea"],)
    assert (
        facts.native_cfg.blocks_by_ea[harness["seed_ea"]].start_ea == harness["seed_ea"]
    )
    assert len(facts.boundary_ports.direct) == 1
    assert facts.boundary_ports.conditional == ()
    resolver_evidence = harness["state"].native_preanalysis.resolver_evidence
    assert resolver_evidence is not None
    assert resolver_evidence.terminal_return_carrier_requests == (
        TerminalReturnCarrierRequest(
            source_handler_ea=harness["seed_ea"],
            terminal_target_ea=0x1100,
            state_var_reg=8,
            state_constant=0x87654321,
        ),
    )
    assert len(harness["captures"]) == 1


def test_prepare_preopt_union_recovers_live_conditional_bridges_before_ports(
    monkeypatch,
) -> None:
    harness = _install_preopt_union_success_harness(monkeypatch)
    observed: list[tuple[tuple[MaterializedIndirectTransfer, ...], object]] = []

    def recover(transfers, mba, **_kwargs):
        observed.append((transfers, mba))
        return ()

    monkeypatch.setattr(
        computed_goto_resolver,
        "recover_conditional_handler_bridge_transfers_from_mba",
        recover,
    )

    result = computed_goto_resolver.prepare_preopt_union_closure(
        harness["state"],
        live_mba=harness["live_mba"],
    )

    assert result.prepared
    assert len(observed) == 1
    assert observed[0][1] is harness["live_mba"]
    assert {transfer.resolver_kind for transfer in observed[0][0]} == {
        "static_handler_entry_route",
        "static_handler_exit_route",
        "detached_static_fixpoint",
    }


def test_prepare_preopt_union_binds_matching_prepatch_source_without_regeneration(
    monkeypatch,
) -> None:
    harness = _install_preopt_union_success_harness(monkeypatch)
    function_ea = harness["function_ea"]
    seed_ea = harness["seed_ea"]
    cut_ea = harness["cut_ea"]
    live_eas = frozenset({0x1100})
    pristine_cfg = NativeCfg(
        {
            seed_ea: NativeBlock(
                seed_ea,
                0x2010,
                outgoing_edges=(
                    NativeEdge(
                        NativeEdgeKind.INDIRECT,
                        0x1100,
                        resolver_proven=True,
                        provenance="resolver_cut",
                        source_instruction_ea=cut_ea,
                    ),
                ),
            )
        }
    )
    pristine_closure = plan_native_semantic_closure(
        pristine_cfg,
        (
            ResolverProvenHandlerEntry(
                entry_ea=seed_ea,
                provenance="static_handler_entry_route",
            ),
        ),
        import_boundary_target_eas=live_eas,
    )
    harness["state"].native_preanalysis.set_prepatch_preopt_union_source(
        harness["state"].native_key,
        computed_goto_resolver._PrepatchPreoptUnionSource(
            primary_seed_ea=seed_ea,
            seed_eas=(seed_ea,),
            seed_native_ranges=((seed_ea, ((seed_ea, 0x2010),)),),
            native_ranges=((seed_ea, 0x2010),),
            imported_block_entry_eas=(seed_ea,),
            cfg=pristine_cfg,
            closure=pristine_closure,
        ),
    )
    assert harness["state"].native_preanalysis.merge_materialized_transfers(
        harness["state"].native_key,
        (
            MaterializedIndirectTransfer(
                source_jmp_ea=0x1900,
                source_block_ea=0x1900,
                materialized_anchor_eas=(),
                target_eas=(seed_ea,),
                resolver_kind="static_handler_entry_route",
                owned_native_ranges=((seed_ea, 0x2040),),
            ),
        ),
    )
    bound: list[tuple[int, int, object]] = []
    monkeypatch.setattr(
        computed_goto_resolver,
        "bind_preopt_union_snippet_boundary_ports",
        lambda owner_ea, target_ea, ports: (
            bound.append((owner_ea, target_ea, ports)) or True
        ),
        raising=False,
    )

    result = computed_goto_resolver.prepare_preopt_union_closure(
        harness["state"],
        live_mba=harness["live_mba"],
    )

    assert result.prepared
    assert len(bound) == 1
    assert bound[0][:2] == (function_ea, seed_ea)
    assert harness["generated"] == []
    assert harness["captures"] == []
    assert harness["backend_calls"] == []
    harness["state"].native_preanalysis.set_preopt_union_preparation(
        harness["state"].native_key,
        None,
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "imported_detached_snippet_instruction_origins",
        lambda _mba: ((0xF1C00010, seed_ea),),
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "_live_mba_native_eas",
        lambda _mba, *, imported_instruction_origins: (
            live_eas
            if not imported_instruction_origins
            else frozenset({*live_eas, seed_ea})
        ),
    )

    refreshed = computed_goto_resolver.prepare_preopt_union_closure(
        harness["state"],
        live_mba=harness["live_mba"],
        refresh_existing=True,
    )

    assert refreshed.prepared
    assert len(bound) == 2
    assert harness["generated"] == []
    assert harness["captures"] == []
    assert harness["backend_calls"] == []


def test_preopt_refresh_preserves_proven_port_hidden_by_its_own_rewrite() -> None:
    entry_port = DetachedSnippetDirectBoundaryPort(
        source_block_ea=0x40D252,
        source_instruction_ea=0x40D348,
        endpoint_block_ea=0x40D348,
        old_successor_eas=(),
        target_ea=0x40EAA7,
        state_register=28,
        state_constant=0x699BC698,
        source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        endpoint_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        delivery_mode="redirect_edge",
        resolver_kind="residual_state_route_evidence",
    )
    previous = DetachedSnippetBoundaryPorts((entry_port,), ())
    refreshed = DetachedSnippetBoundaryPorts((), ())

    merged = computed_goto_resolver._merge_preopt_union_boundary_ports(
        previous,
        refreshed,
    )

    assert merged == previous


def test_preopt_refresh_conditional_boundary_supersedes_bootstrap_direct() -> None:
    entry_port = DetachedSnippetDirectBoundaryPort(
        source_block_ea=0x40D313,
        source_instruction_ea=0x40D348,
        endpoint_block_ea=0x40D348,
        old_successor_eas=(),
        target_ea=0x40EAA7,
        state_register=28,
        state_constant=0x699BC698,
        source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        endpoint_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        delivery_mode="redirect_edge",
        resolver_kind="residual_state_route_evidence",
    )
    entry_choice = DetachedSnippetConditionalBoundaryPort(
        source_block_ea=0x40D252,
        predicate_ea=0x40D266,
        old_taken_target_ea=None,
        old_fallthrough_target_ea=None,
        taken_target_ea=0x40DABB,
        fallthrough_target_ea=0x40F20B,
        state_register=28,
        taken_state=0xB13A6E93,
        fallthrough_state=0x4D34CF70,
        source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        taken_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        fallthrough_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        resolver_kind="resolver_proven_static_stack_carried_entry_choice",
        logical_source_anchor_ea=0x40D348,
        predicate_ida_stkoff=84,
        predicate_stack_value=0xB13A6E93,
        predicate_size=4,
        condition_code=12,
        predicate_register=8,
        predicate_constant=0x113,
        predicate_true_is_taken=True,
    )

    merged = computed_goto_resolver._merge_preopt_union_boundary_ports(
        DetachedSnippetBoundaryPorts((entry_port,), ()),
        DetachedSnippetBoundaryPorts((), (entry_choice,)),
    )

    assert merged.direct == ()
    assert merged.conditional == (entry_choice,)


def test_preopt_refresh_keeps_static_choice_port_across_maturity_shape_drift() -> None:
    baseline = DetachedSnippetConditionalBoundaryPort(
        source_block_ea=0x40DFA2,
        predicate_ea=0x40E04B,
        old_taken_target_ea=0x40E052,
        old_fallthrough_target_ea=0x40E04D,
        taken_target_ea=0x40F177,
        fallthrough_target_ea=0x40D848,
        state_register=28,
        taken_state=0x6BD791A0,
        fallthrough_state=0x0698355C,
        source_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        taken_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        fallthrough_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        resolver_kind="resolver_proven_static_conditional_state_choice",
        old_taken_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        old_fallthrough_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        logical_source_anchor_ea=0x40E04B,
        condition_code=4,
        predicate_true_is_taken=True,
    )
    calls_shape = replace(
        baseline,
        taken_target_ea=baseline.fallthrough_target_ea,
        fallthrough_target_ea=baseline.taken_target_ea,
        taken_state=baseline.fallthrough_state,
        fallthrough_state=baseline.taken_state,
        taken_target_owner=baseline.fallthrough_target_owner,
        fallthrough_target_owner=baseline.taken_target_owner,
        old_taken_target_ea=baseline.old_fallthrough_target_ea,
        old_fallthrough_target_ea=baseline.old_taken_target_ea,
        old_taken_target_owner=baseline.old_fallthrough_target_owner,
        old_fallthrough_target_owner=baseline.old_taken_target_owner,
        predicate_size=4,
        condition_code=5,
        predicate_register=8,
        predicate_constant=0,
        predicate_true_is_taken=False,
    )

    merged = computed_goto_resolver._merge_preopt_union_boundary_ports(
        DetachedSnippetBoundaryPorts((), (baseline,)),
        DetachedSnippetBoundaryPorts((), (calls_shape,)),
    )

    assert merged.conditional == (baseline,)
    with pytest.raises(ValueError, match="conflicting conditional boundary port"):
        computed_goto_resolver._merge_preopt_union_boundary_ports(
            DetachedSnippetBoundaryPorts((), (baseline,)),
            DetachedSnippetBoundaryPorts(
                (),
                (replace(calls_shape, fallthrough_target_ea=0x40F178),),
            ),
        )


def test_calls_refresh_reimports_an_unchanged_port_set_for_new_evidence(
    monkeypatch,
) -> None:
    harness = _install_preopt_union_success_harness(monkeypatch)
    state = harness["state"]
    previous = computed_goto_resolver.PreoptUnionPreparationResult(
        function_ea=harness["function_ea"],
        prepared=True,
        published=True,
    )
    state.native_preanalysis.set_preopt_union_preparation(
        state.native_key,
        previous,
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "prepare_preopt_union_closure",
        lambda current_state, **_kwargs: previous if current_state is state else None,
    )

    assert computed_goto_resolver._refresh_preopt_union_from_calls_evidence(
        state,
        harness["live_mba"],
    )
    assert state.pending_preopt_reimport


def test_calls_refresh_restores_previous_authority_when_rebuild_raises(
    monkeypatch,
) -> None:
    harness = _install_preopt_union_success_harness(monkeypatch)
    state = harness["state"]
    previous = computed_goto_resolver.PreoptUnionPreparationResult(
        function_ea=harness["function_ea"],
        prepared=True,
        published=True,
        primary_seed_ea=harness["seed_ea"],
    )
    state.native_preanalysis.set_preopt_union_preparation(
        state.native_key,
        previous,
    )

    def raise_refresh(*_args, **_kwargs):
        assert state.portable_evidence.preopt_union_preparation is None
        raise RuntimeError("refresh failed")

    monkeypatch.setattr(
        computed_goto_resolver,
        "prepare_preopt_union_closure",
        raise_refresh,
    )

    assert not computed_goto_resolver._refresh_preopt_union_from_calls_evidence(
        state,
        harness["live_mba"],
    )
    assert state.portable_evidence.preopt_union_preparation == previous
    assert not state.pending_preopt_reimport


def test_prepare_preopt_union_closure_uses_exact_ownership_and_atomic_cut_port(
    monkeypatch,
) -> None:
    import ida_hexrays

    harness = _install_preopt_union_success_harness(monkeypatch)

    result = computed_goto_resolver.prepare_preopt_union_closure(
        harness["state"],
        live_mba=harness["live_mba"],
    )

    assert result.prepared
    assert harness["range_calls"] == [harness["seed_ea"]]
    assert harness["backend_calls"][0]["resolver_cut_eas"] == (harness["cut_ea"],)
    assert harness["backend_calls"][0]["seed_eas"] == (
        harness["function_ea"],
        harness["seed_ea"],
    )
    assert harness["backend_calls"][0]["resolver_proven_unmarked_entry_eas"] == (
        harness["seed_ea"],
    )
    assert harness["generated"] == [
        (
            ((harness["seed_ea"], 0x2010),),
            int(ida_hexrays.DECOMP_NO_WAIT | ida_hexrays.DECOMP_ALL_BLKS),
            int(ida_hexrays.MMAT_PREOPTIMIZED),
        ),
    ]
    assert harness["events"] == [
        "generate_1",
        "build_preopt_graph",
        "capture_preopt_union",
    ]
    ((function_ea, target_ea, _preopt, ranges), capture_kwargs) = harness["captures"][0]
    assert (function_ea, target_ea, ranges) == (
        harness["function_ea"],
        harness["seed_ea"],
        ((harness["seed_ea"], 0x2010),),
    )
    assert capture_kwargs["owned_block_entry_eas"] == (harness["seed_ea"],)
    ports = capture_kwargs["boundary_ports"]
    assert isinstance(ports, DetachedSnippetBoundaryPorts)
    assert ports.conditional == ()
    assert len(ports.direct) == 1
    assert ports.direct[0].source_block_ea == harness["seed_ea"]
    assert ports.direct[0].source_instruction_ea == harness["cut_ea"]
    assert ports.direct[0].source_owner is DetachedSnippetBoundaryPortOwner.IMPORTED
    assert ports.direct[0].target_owner is DetachedSnippetBoundaryPortOwner.LIVE


def test_prepare_preopt_union_uses_generation_envelope_but_exact_capture_ownership(
    monkeypatch,
) -> None:
    harness = _install_preopt_union_success_harness(monkeypatch)
    generation_range = NativeRange(harness["seed_ea"], 0x2050)
    monkeypatch.setattr(
        computed_goto_resolver,
        "plan_native_generation_ranges",
        lambda _closure, **_kwargs: (generation_range,),
        raising=False,
    )

    result = computed_goto_resolver.prepare_preopt_union_closure(
        harness["state"],
        live_mba=harness["live_mba"],
    )

    assert result.prepared
    assert result.native_ranges == ((harness["seed_ea"], 0x2010),)
    assert {
        generated_ranges for generated_ranges, _flags, _maturity in harness["generated"]
    } == {((harness["seed_ea"], 0x2050),)}
    ((_, _, _, capture_ranges), capture_kwargs) = harness["captures"][0]
    assert capture_ranges == ((harness["seed_ea"], 0x2010),)
    assert capture_kwargs["owned_block_entry_eas"] == (harness["seed_ea"],)


def test_prepare_preopt_union_threads_proven_native_return_entries(monkeypatch) -> None:
    harness = _install_preopt_union_success_harness(
        monkeypatch,
        closure_edges=(),
        closure_terminal=NativeTerminalKind.RETURN,
    )

    result = computed_goto_resolver.prepare_preopt_union_closure(
        harness["state"],
        live_mba=harness["live_mba"],
    )

    assert result.prepared
    (_capture_args, capture_kwargs) = harness["captures"][0]
    assert capture_kwargs["terminal_return_entry_eas"] == (harness["seed_ea"],)


def test_preopt_union_cut_port_classifies_an_imported_target() -> None:
    source_ea = 0x2000
    target_ea = 0x2100
    cut_ea = 0x200C
    closure = SimpleNamespace(
        included_block_eas=(source_ea, target_ea),
        proven_import_boundary_edges=(
            SimpleNamespace(
                source_ea=source_ea,
                source_instruction_ea=cut_ea,
                target_ea=target_ea,
                kind=NativeEdgeKind.INDIRECT,
                provenance="resolver_cut",
            ),
        ),
    )

    ports = computed_goto_resolver._preopt_union_boundary_ports(
        closure,
        live_native_eas=frozenset(),
    )

    assert ports is not None
    assert len(ports.direct) == 1
    assert ports.direct[0].source_owner is DetachedSnippetBoundaryPortOwner.IMPORTED
    assert ports.direct[0].target_owner is DetachedSnippetBoundaryPortOwner.IMPORTED


def test_preopt_union_internal_successor_proof_requires_one_imported_target() -> None:
    source_ea = 0x2000
    target_ea = 0x2100
    cut_ea = 0x200C
    closure = SimpleNamespace(
        included_block_eas=(source_ea, target_ea),
        proven_import_boundary_edges=(
            SimpleNamespace(
                source_instruction_ea=cut_ea,
                target_ea=target_ea,
            ),
        ),
    )

    assert computed_goto_resolver._preopt_union_internal_successor_eas(closure) == {
        cut_ea: target_ea
    }

    closure.proven_import_boundary_edges = (
        *closure.proven_import_boundary_edges,
        SimpleNamespace(
            source_instruction_ea=cut_ea,
            target_ea=0x2200,
        ),
    )
    assert computed_goto_resolver._preopt_union_internal_successor_eas(closure) == {}


def test_preopt_union_internal_successor_excludes_semantic_state_routes() -> None:
    """Frontend capture cannot consume final state-machine route authority."""
    parameters = inspect.signature(
        computed_goto_resolver._preopt_union_internal_successor_eas
    ).parameters

    assert tuple(parameters) == ("closure",)


def test_preopt_union_groups_two_resolver_cut_targets_into_one_conditional_port() -> (
    None
):
    source_ea = 0x40CDE0
    resolver_ea = 0x40CDF6
    true_target_ea = 0x40CDF8
    false_target_ea = 0x40CF80
    closure = SimpleNamespace(
        included_block_eas=(source_ea, true_target_ea, false_target_ea),
        proven_import_boundary_edges=tuple(
            SimpleNamespace(
                source_ea=source_ea,
                source_instruction_ea=resolver_ea,
                target_ea=target_ea,
                kind=NativeEdgeKind.INDIRECT,
                provenance="resolver_cut",
            )
            for target_ea in (true_target_ea, false_target_ea)
        ),
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=resolver_ea,
        source_block_ea=source_ea,
        materialized_anchor_eas=(),
        target_eas=(true_target_ea, false_target_ea),
        condition_code=5,
        true_target_ea=true_target_ea,
        false_target_ea=false_target_ea,
        selector_state_var_reg=16,
        selector_compare_constant=0xA4C94734,
        resolver_kind="static_fixpoint",
    )

    ports = computed_goto_resolver._preopt_union_boundary_ports(
        closure,
        live_native_eas=frozenset(),
        transfers=(transfer,),
    )

    assert ports is not None
    assert ports.direct == ()
    assert len(ports.conditional) == 1
    (port,) = ports.conditional
    assert port.source_block_ea == source_ea
    assert port.predicate_ea == resolver_ea
    assert port.taken_target_ea == true_target_ea
    assert port.fallthrough_target_ea == false_target_ea
    assert port.predicate_register == 16
    assert port.predicate_size == 4
    assert port.predicate_constant == 0xA4C94734
    assert port.condition_code == 5
    assert port.source_owner is DetachedSnippetBoundaryPortOwner.IMPORTED
    assert port.taken_target_owner is DetachedSnippetBoundaryPortOwner.IMPORTED
    assert port.fallthrough_target_owner is DetachedSnippetBoundaryPortOwner.IMPORTED


def test_preopt_union_classifies_one_native_return_arm_as_atomic_terminal_port() -> (
    None
):
    source_ea = 0x40A5CA
    resolver_ea = 0x40A5E3
    live_predicate_ea = 0x40A5D0
    return_target_ea = 0x40C898
    sibling_target_ea = 0x40A5F0
    closure = SimpleNamespace(
        included_block_eas=(return_target_ea, sibling_target_ea),
        proven_import_boundary_edges=(),
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=resolver_ea,
        source_block_ea=source_ea,
        materialized_anchor_eas=(live_predicate_ea,),
        target_eas=(return_target_ea, sibling_target_ea),
        materialized_predicate_ea=live_predicate_ea,
        condition_code=4,
        true_target_ea=return_target_ea,
        false_target_ea=sibling_target_ea,
        selector_state_var_reg=20,
        selector_compare_constant=0x19A7218A,
        resolver_kind="static_fixpoint",
    )
    native_cfg = SimpleNamespace(
        blocks_by_ea={
            return_target_ea: SimpleNamespace(
                start_ea=return_target_ea,
                end_ea=return_target_ea + 0xA,
                terminal=NativeTerminalKind.RETURN,
            ),
            sibling_target_ea: SimpleNamespace(
                start_ea=sibling_target_ea,
                end_ea=sibling_target_ea + 0x10,
                terminal=NativeTerminalKind.NONE,
            ),
        }
    )
    ports = computed_goto_resolver._preopt_union_boundary_ports(
        closure,
        live_native_eas=frozenset(),
        transfers=(transfer,),
        native_cfg=native_cfg,
    )

    assert ports is not None
    assert ports.direct == ()
    assert len(ports.conditional) == 1
    (port,) = ports.conditional
    assert port.resolver_kind == "preopt_terminal_return_boundary"
    assert port.state_register == 20
    assert port.taken_state == 0x19A7218A
    assert port.fallthrough_state is None
    assert port.taken_target_ea == return_target_ea
    assert port.fallthrough_target_ea == sibling_target_ea
    assert port.source_owner is DetachedSnippetBoundaryPortOwner.LIVE
    assert port.source_block_ea == source_ea
    assert port.predicate_ea == live_predicate_ea
    assert port.predicate_true_is_taken is True


def test_preopt_union_prefers_complete_live_conditional_bridge_over_shared_tail() -> (
    None
):
    predicate_ea = 0x40CDB4
    true_state = 0x09269BD2
    false_state = 0x255387B6
    true_target_ea = 0x40CE3C
    false_target_ea = 0x40CEAB
    router_ea = 0x40CDF8
    closure = SimpleNamespace(
        included_block_eas=(true_target_ea, false_target_ea),
        proven_import_boundary_edges=(),
    )
    transfers = (
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40CDAF,
            source_block_ea=0x40CDA0,
            materialized_anchor_eas=(),
            target_eas=(true_target_ea,),
            selector_state_var_reg=20,
            selector_state_constant=true_state,
            resolver_kind="residual_state_route_evidence",
        ),
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40CDBA,
            source_block_ea=0x40CDB7,
            materialized_anchor_eas=(),
            target_eas=(false_target_ea,),
            selector_state_var_reg=20,
            selector_state_constant=false_state,
            resolver_kind="residual_state_route_evidence",
        ),
        MaterializedIndirectTransfer(
            source_jmp_ea=router_ea,
            source_block_ea=router_ea,
            materialized_anchor_eas=(),
            target_eas=(false_target_ea,),
            selector_state_var_reg=20,
            selector_state_constant=false_state,
            resolver_kind="condition_chain_handler_evidence",
            dispatcher_router_eas=(router_ea,),
        ),
        MaterializedIndirectTransfer(
            source_jmp_ea=predicate_ea,
            source_block_ea=0x40CDA0,
            materialized_anchor_eas=(predicate_ea,),
            target_eas=(true_target_ea, false_target_ea),
            condition_code=5,
            true_target_ea=true_target_ea,
            false_target_ea=false_target_ea,
            selector_state_var_reg=20,
            resolver_kind="conditional_handler_bridge",
            predicate_register=8,
            predicate_size=4,
            predicate_compare_constant=0,
            predicate_true_state=true_state,
            predicate_false_state=false_state,
            predicate_true_is_taken=True,
        ),
    )

    ports = computed_goto_resolver._preopt_union_boundary_ports(
        closure,
        live_native_eas=frozenset({0x40CDA0, predicate_ea}),
        transfers=transfers,
    )

    assert ports is not None
    assert ports.direct == ()
    assert len(ports.conditional) == 1
    (port,) = ports.conditional
    assert port.source_block_ea == 0x40CDA0
    assert port.predicate_ea == predicate_ea
    assert port.taken_target_ea == true_target_ea
    assert port.fallthrough_target_ea == false_target_ea
    assert port.taken_state == true_state
    assert port.fallthrough_state == false_state
    assert port.source_owner is DetachedSnippetBoundaryPortOwner.LIVE
    assert port.taken_target_owner is DetachedSnippetBoundaryPortOwner.IMPORTED
    assert port.fallthrough_target_owner is DetachedSnippetBoundaryPortOwner.IMPORTED
    assert port.predicate_register == 8
    assert port.predicate_size == 4
    assert port.predicate_constant == 0
    assert port.condition_code == 5
    assert port.predicate_true_is_taken is True

    imported_ports = computed_goto_resolver._preopt_union_boundary_ports(
        SimpleNamespace(
            included_block_eas=(
                0x40CDA0,
                true_target_ea,
                false_target_ea,
            ),
            proven_import_boundary_edges=(),
        ),
        live_native_eas=frozenset(),
        transfers=transfers,
    )
    assert imported_ports is not None
    assert len(imported_ports.conditional) == 1
    assert (
        imported_ports.conditional[0].source_owner
        is DetachedSnippetBoundaryPortOwner.IMPORTED
    )


def test_preopt_union_reanchors_imported_conditional_source_from_predicate() -> None:
    function_ea = 0x40D200
    source_ea = 0x40DFA2
    predicate_ea = 0x40E04B
    old_taken_ea = 0x40E052
    old_fallthrough_ea = 0x40E04D
    true_state = 0x11111111
    false_state = 0x22222222
    true_target_ea = 0x40D848
    false_target_ea = 0x40F177
    transfers = (
        MaterializedIndirectTransfer(
            source_jmp_ea=predicate_ea,
            source_block_ea=function_ea,
            materialized_anchor_eas=(predicate_ea,),
            target_eas=(true_target_ea, false_target_ea),
            condition_code=5,
            true_target_ea=true_target_ea,
            false_target_ea=false_target_ea,
            selector_state_var_reg=28,
            resolver_kind="conditional_handler_bridge",
            predicate_register=8,
            predicate_size=4,
            predicate_true_state=true_state,
            predicate_false_state=false_state,
            predicate_true_is_taken=True,
        ),
        MaterializedIndirectTransfer(
            source_jmp_ea=0x5000,
            source_block_ea=0x5000,
            materialized_anchor_eas=(),
            target_eas=(true_target_ea,),
            selector_state_var_reg=28,
            selector_state_constant=true_state,
            resolver_kind="residual_state_route_evidence",
        ),
        MaterializedIndirectTransfer(
            source_jmp_ea=0x5004,
            source_block_ea=0x5004,
            materialized_anchor_eas=(),
            target_eas=(false_target_ea,),
            selector_state_var_reg=28,
            selector_state_constant=false_state,
            resolver_kind="residual_state_route_evidence",
        ),
    )
    native_cfg = NativeCfg(
        {
            source_ea: NativeBlock(
                source_ea,
                0x40E04D,
                outgoing_edges=(
                    NativeEdge(
                        NativeEdgeKind.CONDITIONAL_TRUE,
                        old_taken_ea,
                        source_instruction_ea=predicate_ea,
                    ),
                    NativeEdge(
                        NativeEdgeKind.CONDITIONAL_FALSE,
                        old_fallthrough_ea,
                        source_instruction_ea=predicate_ea,
                    ),
                ),
            ),
            old_taken_ea: NativeBlock(old_taken_ea, old_taken_ea + 1),
            old_fallthrough_ea: NativeBlock(
                old_fallthrough_ea,
                old_fallthrough_ea + 1,
            ),
            true_target_ea: NativeBlock(true_target_ea, true_target_ea + 1),
            false_target_ea: NativeBlock(false_target_ea, false_target_ea + 1),
        }
    )

    ports = computed_goto_resolver._preopt_live_conditional_bridge_boundary_ports(
        transfers,
        live_native_eas=frozenset(),
        imported_entry_eas=frozenset(
            {
                source_ea,
                old_taken_ea,
                old_fallthrough_ea,
                true_target_ea,
                false_target_ea,
            }
        ),
        native_cfg=native_cfg,
    )

    assert ports is not None
    assert len(ports) == 1
    assert ports[0].source_block_ea == source_ea
    assert ports[0].predicate_ea == predicate_ea
    assert ports[0].source_owner is DetachedSnippetBoundaryPortOwner.IMPORTED
    assert ports[0].old_taken_target_ea == old_taken_ea
    assert ports[0].old_fallthrough_target_ea == old_fallthrough_ea
    assert ports[0].old_taken_target_owner is DetachedSnippetBoundaryPortOwner.IMPORTED
    assert (
        ports[0].old_fallthrough_target_owner
        is DetachedSnippetBoundaryPortOwner.IMPORTED
    )


def test_preopt_static_choice_uses_native_predicate_when_prior_mba_folded_it() -> None:
    source_ea = 0x40B8E6
    predicate_ea = 0x40B90F
    old_taken_ea = 0x40C6B5
    old_fallthrough_ea = 0x40B915
    true_state = 0x7F9D6412
    false_state = 0xA7933EA0
    true_target_ea = 0x40B3FF
    false_target_ea = 0x40C1A0
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=predicate_ea,
        source_block_ea=source_ea,
        materialized_anchor_eas=(predicate_ea,),
        target_eas=(true_target_ea, false_target_ea),
        condition_code=5,
        true_target_ea=true_target_ea,
        false_target_ea=false_target_ea,
        selector_state_var_reg=20,
        predicate_true_state=true_state,
        predicate_false_state=false_state,
        predicate_true_is_taken=True,
        resolver_kind="static_conditional_state_choice_bridge",
    )
    native_cfg = NativeCfg(
        {
            source_ea: NativeBlock(
                source_ea,
                old_fallthrough_ea,
                outgoing_edges=(
                    NativeEdge(
                        NativeEdgeKind.CONDITIONAL_TRUE,
                        old_taken_ea,
                        source_instruction_ea=predicate_ea,
                    ),
                    NativeEdge(
                        NativeEdgeKind.CONDITIONAL_FALSE,
                        old_fallthrough_ea,
                        source_instruction_ea=predicate_ea,
                    ),
                ),
            ),
            old_taken_ea: NativeBlock(old_taken_ea, old_taken_ea + 1),
            old_fallthrough_ea: NativeBlock(
                old_fallthrough_ea,
                old_fallthrough_ea + 1,
            ),
            true_target_ea: NativeBlock(true_target_ea, true_target_ea + 1),
            false_target_ea: NativeBlock(false_target_ea, false_target_ea + 1),
        }
    )

    ports = computed_goto_resolver._preopt_live_conditional_bridge_boundary_ports(
        (transfer,),
        live_mba=None,
        live_native_eas=frozenset(),
        imported_entry_eas=frozenset(
            {
                source_ea,
                old_taken_ea,
                old_fallthrough_ea,
                true_target_ea,
                false_target_ea,
            }
        ),
        native_cfg=native_cfg,
    )

    assert ports is not None
    assert len(ports) == 1
    (port,) = ports
    assert port.source_block_ea == source_ea
    assert port.predicate_ea == predicate_ea
    assert port.old_taken_target_ea == old_taken_ea
    assert port.old_fallthrough_target_ea == old_fallthrough_ea
    assert port.taken_state == true_state
    assert port.taken_target_ea == true_target_ea
    assert port.fallthrough_state == false_state
    assert port.fallthrough_target_ea == false_target_ea
    assert port.predicate_true_is_taken is True


def test_preopt_static_choice_survives_an_equivalent_stale_live_bridge() -> None:
    source_ea = 0x40B8E6
    predicate_ea = 0x40B90F
    old_taken_ea = 0x40C6B5
    old_fallthrough_ea = 0x40B915
    true_state = 0x7F9D6412
    false_state = 0xA7933EA0
    true_target_ea = 0x40B3FF
    false_target_ea = 0x40C1A0
    static_choice = MaterializedIndirectTransfer(
        source_jmp_ea=predicate_ea,
        source_block_ea=source_ea,
        materialized_anchor_eas=(predicate_ea,),
        target_eas=(true_target_ea, false_target_ea),
        condition_code=5,
        true_target_ea=true_target_ea,
        false_target_ea=false_target_ea,
        selector_state_var_reg=20,
        predicate_true_state=true_state,
        predicate_false_state=false_state,
        predicate_true_is_taken=True,
        resolver_kind="static_conditional_state_choice_bridge",
    )
    stale_live_bridge = replace(
        static_choice,
        predicate_register=8,
        predicate_size=4,
        predicate_preserve_live=True,
        resolver_kind="conditional_handler_bridge",
    )
    native_cfg = NativeCfg(
        {
            source_ea: NativeBlock(
                source_ea,
                old_fallthrough_ea,
                outgoing_edges=(
                    NativeEdge(
                        NativeEdgeKind.CONDITIONAL_TRUE,
                        old_taken_ea,
                        source_instruction_ea=predicate_ea,
                    ),
                    NativeEdge(
                        NativeEdgeKind.CONDITIONAL_FALSE,
                        old_fallthrough_ea,
                        source_instruction_ea=predicate_ea,
                    ),
                ),
            ),
            old_taken_ea: NativeBlock(old_taken_ea, old_taken_ea + 1),
            old_fallthrough_ea: NativeBlock(
                old_fallthrough_ea,
                old_fallthrough_ea + 1,
            ),
            true_target_ea: NativeBlock(true_target_ea, true_target_ea + 1),
            false_target_ea: NativeBlock(false_target_ea, false_target_ea + 1),
        }
    )

    ports = computed_goto_resolver._preopt_live_conditional_bridge_boundary_ports(
        (static_choice, stale_live_bridge),
        live_mba=None,
        live_native_eas=frozenset(),
        imported_entry_eas=frozenset(
            {
                source_ea,
                old_taken_ea,
                old_fallthrough_ea,
                true_target_ea,
                false_target_ea,
            }
        ),
        native_cfg=native_cfg,
    )

    assert ports is not None
    assert len(ports) == 1
    assert ports[0].resolver_kind == "resolver_proven_static_conditional_state_choice"


def test_preopt_static_choice_defers_one_way_native_shape_to_template_proof() -> None:
    source_ea = 0x40B8E6
    predicate_ea = 0x40B90F
    old_taken_ea = 0x40C6B5
    true_target_ea = 0x40B3FF
    false_target_ea = 0x40C1A0
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=predicate_ea,
        source_block_ea=source_ea,
        materialized_anchor_eas=(predicate_ea,),
        target_eas=(true_target_ea, false_target_ea),
        condition_code=5,
        true_target_ea=true_target_ea,
        false_target_ea=false_target_ea,
        selector_state_var_reg=20,
        predicate_true_state=0x7F9D6412,
        predicate_false_state=0xA7933EA0,
        predicate_true_is_taken=True,
        resolver_kind="static_conditional_state_choice_bridge",
    )
    native_cfg = NativeCfg(
        {
            source_ea: NativeBlock(
                source_ea,
                0x40B915,
                outgoing_edges=(NativeEdge(NativeEdgeKind.DIRECT_JUMP, old_taken_ea),),
            ),
            old_taken_ea: NativeBlock(old_taken_ea, old_taken_ea + 1),
            true_target_ea: NativeBlock(true_target_ea, true_target_ea + 1),
            false_target_ea: NativeBlock(false_target_ea, false_target_ea + 1),
        }
    )

    ports = computed_goto_resolver._preopt_live_conditional_bridge_boundary_ports(
        (transfer,),
        live_mba=None,
        live_native_eas=frozenset(),
        imported_entry_eas=frozenset(
            {source_ea, old_taken_ea, true_target_ea, false_target_ea}
        ),
        native_cfg=native_cfg,
    )

    assert ports is not None
    assert len(ports) == 1
    assert ports[0].old_taken_target_ea is None
    assert ports[0].old_fallthrough_target_ea is None


@pytest.mark.parametrize(
    (
        "condition_code",
        "predicate_true_is_taken",
        "expected_taken_state",
        "expected_taken_target_ea",
        "expected_fallthrough_state",
        "expected_fallthrough_target_ea",
    ),
    (
        (5, True, 0x09269BD2, 0x40CE3C, 0x255387B6, 0x40CEAB),
        (4, False, 0x255387B6, 0x40CEAB, 0x09269BD2, 0x40CE3C),
    ),
    ids=("jnz_true_is_taken", "jz_true_is_fallthrough"),
)
def test_preopt_live_conditional_bridge_projects_physical_taken_and_fallthrough_arms(
    condition_code: int,
    predicate_true_is_taken: bool,
    expected_taken_state: int,
    expected_taken_target_ea: int,
    expected_fallthrough_state: int,
    expected_fallthrough_target_ea: int,
) -> None:
    true_state = 0x09269BD2
    false_state = 0x255387B6
    true_target_ea = 0x40CE3C
    false_target_ea = 0x40CEAB
    transfers = (
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40CDAF,
            source_block_ea=0x40CDA0,
            materialized_anchor_eas=(),
            target_eas=(true_target_ea,),
            selector_state_var_reg=20,
            selector_state_constant=true_state,
            resolver_kind="residual_state_route_evidence",
        ),
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40CDBA,
            source_block_ea=0x40CDB7,
            materialized_anchor_eas=(),
            target_eas=(false_target_ea,),
            selector_state_var_reg=20,
            selector_state_constant=false_state,
            resolver_kind="residual_state_route_evidence",
        ),
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40CDB4,
            source_block_ea=0x40CDA0,
            materialized_anchor_eas=(0x40CDB4,),
            target_eas=(true_target_ea, false_target_ea),
            condition_code=condition_code,
            true_target_ea=true_target_ea,
            false_target_ea=false_target_ea,
            selector_state_var_reg=20,
            predicate_size=4,
            predicate_true_state=true_state,
            predicate_false_state=false_state,
            predicate_register=8,
            predicate_true_is_taken=predicate_true_is_taken,
            resolver_kind="conditional_handler_bridge",
        ),
    )

    ports = computed_goto_resolver._preopt_live_conditional_bridge_boundary_ports(
        transfers,
        live_native_eas=frozenset({0x40CDA0, 0x40CDB4}),
        imported_entry_eas=frozenset({true_target_ea, false_target_ea}),
    )

    assert ports is not None
    assert len(ports) == 1
    (port,) = ports
    assert port.condition_code == condition_code
    assert port.predicate_true_is_taken is predicate_true_is_taken
    assert port.taken_state == expected_taken_state
    assert port.taken_target_ea == expected_taken_target_ea
    assert port.fallthrough_state == expected_fallthrough_state
    assert port.fallthrough_target_ea == expected_fallthrough_target_ea


def test_preopt_live_conditional_bridge_revalidates_flag_only_cmov_predicate(
    monkeypatch,
) -> None:
    """A native CMOV condition may survive without explicit mop operands."""
    predicate_ea = 0x40C4C3
    source_ea = 0x40C4B4
    true_state = 0x2B8162DC
    false_state = 0x456A4274
    true_target_ea = 0x40ADA2
    false_target_ea = 0x40B199
    live_source = SimpleNamespace(serial=7, start=source_ea)
    transfers = (
        MaterializedIndirectTransfer(
            source_jmp_ea=predicate_ea,
            source_block_ea=0x40A560,
            materialized_anchor_eas=(predicate_ea,),
            target_eas=(true_target_ea, false_target_ea),
            condition_code=5,
            true_target_ea=true_target_ea,
            false_target_ea=false_target_ea,
            selector_state_var_reg=20,
            resolver_kind="conditional_handler_bridge",
            predicate_size=4,
            predicate_compare_constant=5,
            predicate_true_state=true_state,
            predicate_false_state=false_state,
            predicate_true_is_taken=True,
            predicate_preserve_live=True,
        ),
    )
    native_cfg = NativeCfg(
        {
            source_ea: NativeBlock(source_ea, 0x40C4C6),
            true_target_ea: NativeBlock(true_target_ea, true_target_ea + 1),
            false_target_ea: NativeBlock(false_target_ea, false_target_ea + 1),
        }
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "_find_unique_live_predicate_block",
        lambda _mba, candidate_ea: (
            live_source if int(candidate_ea) == predicate_ea else None
        ),
    )
    orientations = []

    def orient(*_args, **kwargs):
        orientations.append(kwargs)
        return False

    monkeypatch.setattr(
        computed_goto_resolver,
        "exact_live_predicate_true_is_taken",
        orient,
    )

    ports = computed_goto_resolver._preopt_live_conditional_bridge_boundary_ports(
        transfers,
        live_mba=object(),
        live_native_eas=frozenset({source_ea, predicate_ea}),
        imported_entry_eas=frozenset({true_target_ea, false_target_ea}),
        native_cfg=native_cfg,
    )

    assert ports is not None
    assert len(ports) == 1
    (port,) = ports
    assert port.source_block_ea == source_ea
    assert port.predicate_ea == predicate_ea
    assert port.taken_target_ea == false_target_ea
    assert port.fallthrough_target_ea == true_target_ea
    assert port.predicate_register is None
    assert port.predicate_size is None
    assert port.predicate_constant is None
    assert port.predicate_true_is_taken is False
    assert orientations == [
        {
            "predicate_ea": predicate_ea,
            "condition_code": 5,
            "predicate_register": None,
            "predicate_size": None,
            "predicate_constant": None,
        }
    ]


def test_preopt_live_conditional_bridge_rejects_unbound_flag_only_cmov_predicate(
    monkeypatch,
) -> None:
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x40C4C3,
        source_block_ea=0x40C4B4,
        materialized_anchor_eas=(0x40C4C3,),
        target_eas=(0x40ADA2, 0x40B199),
        condition_code=5,
        true_target_ea=0x40ADA2,
        false_target_ea=0x40B199,
        selector_state_var_reg=20,
        resolver_kind="conditional_handler_bridge",
        predicate_size=4,
        predicate_compare_constant=5,
        predicate_true_state=0x2B8162DC,
        predicate_false_state=0x456A4274,
        predicate_true_is_taken=True,
        predicate_preserve_live=True,
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "_find_unique_live_predicate_block",
        lambda *_args, **_kwargs: None,
    )

    ports = computed_goto_resolver._preopt_live_conditional_bridge_boundary_ports(
        (transfer,),
        live_mba=object(),
        live_native_eas=frozenset({0x40C4B4, 0x40C4C3}),
        imported_entry_eas=frozenset({0x40ADA2, 0x40B199}),
    )

    assert ports == ()


def test_preopt_live_conditional_bridge_revalidates_explicit_call_result_predicate(
    monkeypatch,
) -> None:
    predicate_ea = 0x40A936
    source_ea = 0x40A903
    true_target_ea = 0x40C47E
    false_target_ea = 0x40C665
    live_source = SimpleNamespace(serial=7, start=source_ea)
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=predicate_ea,
        source_block_ea=source_ea,
        materialized_anchor_eas=(predicate_ea,),
        target_eas=(true_target_ea, false_target_ea),
        condition_code=5,
        true_target_ea=true_target_ea,
        false_target_ea=false_target_ea,
        selector_state_var_reg=20,
        resolver_kind="conditional_handler_bridge",
        predicate_register=8,
        predicate_size=4,
        predicate_compare_constant=7,
        predicate_true_state=0xAE5A330B,
        predicate_false_state=0x09FE690C,
        predicate_true_is_taken=True,
        predicate_preserve_live=True,
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "_find_unique_live_predicate_block",
        lambda _mba, candidate_ea: (
            live_source if int(candidate_ea) == predicate_ea else None
        ),
    )
    orientations = []

    def orient(*_args, **kwargs):
        orientations.append(kwargs)
        return False

    monkeypatch.setattr(
        computed_goto_resolver,
        "exact_live_predicate_true_is_taken",
        orient,
    )

    ports = computed_goto_resolver._preopt_live_conditional_bridge_boundary_ports(
        (transfer,),
        live_mba=object(),
        live_native_eas=frozenset({source_ea, predicate_ea}),
        imported_entry_eas=frozenset({true_target_ea, false_target_ea}),
    )

    assert ports is not None
    assert len(ports) == 1
    assert ports[0].taken_target_ea == false_target_ea
    assert ports[0].fallthrough_target_ea == true_target_ea
    assert ports[0].predicate_register == 8
    assert ports[0].predicate_size == 4
    assert ports[0].predicate_constant == 7
    assert orientations == [
        {
            "predicate_ea": predicate_ea,
            "condition_code": 5,
            "predicate_register": 8,
            "predicate_size": 4,
            "predicate_constant": 7,
        }
    ]


def test_preopt_live_conditional_bridge_rejects_unbound_explicit_predicate(
    monkeypatch,
) -> None:
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x40A936,
        source_block_ea=0x40A903,
        materialized_anchor_eas=(0x40A936,),
        target_eas=(0x40C47E, 0x40C665),
        condition_code=5,
        true_target_ea=0x40C47E,
        false_target_ea=0x40C665,
        selector_state_var_reg=20,
        resolver_kind="conditional_handler_bridge",
        predicate_register=8,
        predicate_size=4,
        predicate_compare_constant=7,
        predicate_true_state=0xAE5A330B,
        predicate_false_state=0x09FE690C,
        predicate_true_is_taken=True,
        predicate_preserve_live=True,
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "_find_unique_live_predicate_block",
        lambda *_args, **_kwargs: None,
    )

    ports = computed_goto_resolver._preopt_live_conditional_bridge_boundary_ports(
        (transfer,),
        live_mba=object(),
        live_native_eas=frozenset({0x40A903, 0x40A936}),
        imported_entry_eas=frozenset({0x40C47E, 0x40C665}),
    )

    assert ports == ()


def test_preopt_live_conditional_bridge_prefers_equivalent_explicit_predicate(
    monkeypatch,
) -> None:
    flag_only = MaterializedIndirectTransfer(
        source_jmp_ea=0x40C4C3,
        source_block_ea=0x40C4B4,
        materialized_anchor_eas=(0x40C4C3,),
        target_eas=(0x40ADA2, 0x40B199),
        condition_code=5,
        true_target_ea=0x40ADA2,
        false_target_ea=0x40B199,
        selector_state_var_reg=20,
        resolver_kind="conditional_handler_bridge",
        predicate_size=4,
        predicate_compare_constant=5,
        predicate_true_state=0x2B8162DC,
        predicate_false_state=0x456A4274,
        predicate_true_is_taken=True,
        predicate_preserve_live=True,
    )
    explicit = replace(
        flag_only,
        predicate_register=8,
    )
    residual_routes = (
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40ADA2,
            source_block_ea=0x40ADA2,
            materialized_anchor_eas=(),
            target_eas=(0x40ADA2,),
            selector_state_var_reg=20,
            selector_state_constant=0x2B8162DC,
            resolver_kind="residual_state_route_evidence",
        ),
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40B199,
            source_block_ea=0x40B199,
            materialized_anchor_eas=(),
            target_eas=(0x40B199,),
            selector_state_var_reg=20,
            selector_state_constant=0x456A4274,
            resolver_kind="residual_state_route_evidence",
        ),
    )
    live_source = SimpleNamespace(serial=7, start=0x40C4B4)
    monkeypatch.setattr(
        computed_goto_resolver,
        "_find_unique_live_predicate_block",
        lambda *_args, **_kwargs: live_source,
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "exact_live_predicate_true_is_taken",
        lambda *_args, **_kwargs: True,
    )

    ports = computed_goto_resolver._preopt_live_conditional_bridge_boundary_ports(
        (*residual_routes, flag_only, explicit),
        live_mba=object(),
        live_native_eas=frozenset({0x40C4B4, 0x40C4C3}),
        imported_entry_eas=frozenset({0x40ADA2, 0x40B199}),
    )

    assert ports is not None
    assert len(ports) == 1
    assert ports[0].predicate_register == 8
    assert ports[0].predicate_size == 4
    assert ports[0].predicate_constant == 5


def test_preopt_live_conditional_bridge_rejects_mixed_target_conflict(
    monkeypatch,
) -> None:
    flag_only = MaterializedIndirectTransfer(
        source_jmp_ea=0x40C4C3,
        source_block_ea=0x40C4B4,
        materialized_anchor_eas=(0x40C4C3,),
        target_eas=(0x40ADA2, 0x40B199),
        condition_code=5,
        true_target_ea=0x40ADA2,
        false_target_ea=0x40B199,
        selector_state_var_reg=20,
        resolver_kind="conditional_handler_bridge",
        predicate_size=4,
        predicate_compare_constant=5,
        predicate_true_state=0x2B8162DC,
        predicate_false_state=0x456A4274,
        predicate_true_is_taken=True,
        predicate_preserve_live=True,
    )
    explicit = replace(
        flag_only,
        predicate_register=8,
        target_eas=(0x40ADA3, 0x40B199),
        true_target_ea=0x40ADA3,
    )
    residual_routes = (
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40ADA2,
            source_block_ea=0x40ADA2,
            materialized_anchor_eas=(),
            target_eas=(0x40ADA2,),
            selector_state_var_reg=20,
            selector_state_constant=0x2B8162DC,
            resolver_kind="residual_state_route_evidence",
        ),
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40B199,
            source_block_ea=0x40B199,
            materialized_anchor_eas=(),
            target_eas=(0x40B199,),
            selector_state_var_reg=20,
            selector_state_constant=0x456A4274,
            resolver_kind="residual_state_route_evidence",
        ),
    )
    live_source = SimpleNamespace(serial=7, start=0x40C4B4)
    monkeypatch.setattr(
        computed_goto_resolver,
        "_find_unique_live_predicate_block",
        lambda *_args, **_kwargs: live_source,
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "exact_live_predicate_true_is_taken",
        lambda *_args, **_kwargs: True,
    )

    ports = computed_goto_resolver._preopt_live_conditional_bridge_boundary_ports(
        (*residual_routes, flag_only, explicit),
        live_mba=object(),
        live_native_eas=frozenset({0x40C4B4, 0x40C4C3}),
        imported_entry_eas=frozenset({0x40ADA2, 0x40ADA3, 0x40B199}),
    )

    assert ports is None


def test_preopt_stack_carried_choice_is_deferred_to_its_live_consumer(
    monkeypatch,
) -> None:
    """The original predicate outranks its later stack-carried bootstrap."""
    predicate_ea = 0x40D266
    true_state = 0xB13A6E93
    false_state = 0x4D34CF70
    true_target_ea = 0x40DABB
    false_target_ea = 0x40F20B
    live_source = SimpleNamespace(serial=7, start=0x40D252)
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=predicate_ea,
        source_block_ea=0x40D252,
        materialized_anchor_eas=(0x40D256, predicate_ea, 0x40D269),
        target_eas=(true_target_ea, false_target_ea),
        condition_code=12,
        true_target_ea=true_target_ea,
        false_target_ea=false_target_ea,
        selector_state_var_reg=28,
        resolver_kind="static_stack_carried_state_choice",
        predicate_register=20,
        predicate_size=4,
        predicate_compare_constant=0x113,
        predicate_true_state=true_state,
        predicate_false_state=false_state,
        state_carrier_store_ea=0x40D269,
        state_carrier_stack_displacement=0x44,
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "_find_unique_live_predicate_block",
        lambda _mba, candidate_ea: (
            live_source if int(candidate_ea) == predicate_ea else None
        ),
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "exact_live_predicate_true_is_taken",
        lambda *_args, **_kwargs: False,
    )

    ports = computed_goto_resolver._preopt_live_conditional_bridge_boundary_ports(
        (transfer,),
        live_mba=object(),
        live_native_eas=frozenset({0x40D252, 0x40D256, predicate_ea}),
        imported_entry_eas=frozenset({true_target_ea, false_target_ea}),
    )

    assert ports == ()


def test_preopt_static_branch_choice_defers_to_equivalent_live_bridge(
    monkeypatch,
) -> None:
    predicate_ea = 0x40DD38
    source_ea = 0x40DD21
    taken_state = 0xF448A3A2
    fallthrough_state = 0x4E9CC9CC
    taken_target = 0x40D738
    fallthrough_target = 0x40F562
    static_choice = MaterializedIndirectTransfer(
        source_jmp_ea=predicate_ea,
        source_block_ea=source_ea,
        materialized_anchor_eas=(predicate_ea,),
        target_eas=(taken_target, fallthrough_target),
        condition_code=4,
        true_target_ea=taken_target,
        false_target_ea=fallthrough_target,
        selector_state_var_reg=28,
        predicate_true_state=taken_state,
        predicate_false_state=fallthrough_state,
        resolver_kind="static_conditional_state_choice_bridge",
    )
    live_bridge = replace(
        static_choice,
        target_eas=(fallthrough_target, taken_target),
        true_target_ea=fallthrough_target,
        false_target_ea=taken_target,
        predicate_register=8,
        predicate_size=4,
        predicate_true_state=fallthrough_state,
        predicate_false_state=taken_state,
        predicate_true_is_taken=False,
        resolver_kind="conditional_handler_bridge",
    )
    residual_routes = (
        MaterializedIndirectTransfer(
            source_jmp_ea=0x5000,
            source_block_ea=0x5000,
            materialized_anchor_eas=(),
            target_eas=(taken_target,),
            selector_state_var_reg=28,
            selector_state_constant=taken_state,
            resolver_kind="residual_state_route_evidence",
        ),
        MaterializedIndirectTransfer(
            source_jmp_ea=0x5010,
            source_block_ea=0x5010,
            materialized_anchor_eas=(),
            target_eas=(fallthrough_target,),
            selector_state_var_reg=28,
            selector_state_constant=fallthrough_state,
            resolver_kind="residual_state_route_evidence",
        ),
    )
    live_source = SimpleNamespace(serial=7, start=source_ea)
    monkeypatch.setattr(
        computed_goto_resolver,
        "_find_unique_live_predicate_block",
        lambda _mba, candidate_ea: (
            live_source if int(candidate_ea) == predicate_ea else None
        ),
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "exact_live_predicate_true_is_taken",
        lambda *_args, **_kwargs: True,
    )

    ports = computed_goto_resolver._preopt_live_conditional_bridge_boundary_ports(
        (*residual_routes, static_choice, live_bridge),
        live_mba=object(),
        live_native_eas=frozenset({source_ea, predicate_ea}),
        imported_entry_eas=frozenset({taken_target, fallthrough_target}),
    )

    assert ports is not None
    assert len(ports) == 1
    assert ports[0].resolver_kind == "resolver_proven_live_conditional_bridge"


def test_prepare_preopt_union_closure_defers_raw_call_analysis_to_live_mba(
    monkeypatch,
) -> None:
    import ida_hexrays

    harness = _install_preopt_union_success_harness(
        monkeypatch,
        include_call=True,
    )

    result = computed_goto_resolver.prepare_preopt_union_closure(
        harness["state"],
        live_mba=harness["live_mba"],
    )

    assert result.prepared
    assert len(harness["generated"]) == 1
    assert harness["generated"][0][2] == int(ida_hexrays.MMAT_PREOPTIMIZED)


def test_prepare_preopt_union_closure_abstains_without_resolver_evidence(
    monkeypatch,
) -> None:
    function_ea = 0x1000
    resolution = ComputedGotoResolution(
        function_ea=function_ea,
        jmp_targets={},
        reachable_eas=(function_ea,),
        arch="x86",
        executed_insns=0,
        seeds_run=0,
    )
    _session, state = _resolver_session(resolution)
    state.materialized = True
    monkeypatch.setattr(
        computed_goto_resolver,
        "_recover_static_handler_entry_route_transfers",
        lambda _transfers: (),
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "imported_detached_snippet_instruction_origins",
        lambda _mba: (),
    )
    captures: list[object] = []
    monkeypatch.setattr(
        computed_goto_resolver,
        "capture_preopt_union_snippet_template",
        lambda *_args, **_kwargs: captures.append(object()),
        raising=False,
    )

    result = computed_goto_resolver.prepare_preopt_union_closure(
        state,
        live_mba=object(),
    )

    assert not result.prepared
    assert result.primary_seed_ea is None
    assert captures == []
    assert computed_goto_resolver.get_prepared_preopt_union_closure(state) is None


def test_prepare_preopt_union_closure_abstains_on_unknown_indirect(
    monkeypatch,
) -> None:
    harness = _install_preopt_union_success_harness(
        monkeypatch,
        closure_edges=(
            NativeEdge(
                NativeEdgeKind.INDIRECT,
                resolver_proven=False,
                provenance="unknown_indirect",
                source_instruction_ea=0x200C,
            ),
        ),
    )

    result = computed_goto_resolver.prepare_preopt_union_closure(
        harness["state"],
        live_mba=harness["live_mba"],
    )

    assert not result.prepared
    assert harness["generated"] == []
    assert harness["captures"] == []
    assert (
        computed_goto_resolver.get_prepared_preopt_union_closure(harness["state"])
        is None
    )


def test_prepare_preopt_union_closure_does_not_publish_recovered_routes_on_abstention(
    monkeypatch,
) -> None:
    harness = _install_preopt_union_success_harness(
        monkeypatch,
        closure_edges=(
            NativeEdge(
                NativeEdgeKind.INDIRECT,
                resolver_proven=False,
                provenance="unknown_indirect",
                source_instruction_ea=0x200C,
            ),
        ),
    )
    recovered = MaterializedIndirectTransfer(
        source_jmp_ea=0x1810,
        source_block_ea=0x1810,
        materialized_anchor_eas=(),
        target_eas=(harness["seed_ea"],),
        resolver_kind="static_handler_entry_route",
    )
    transfers_before = harness["state"].materialized_transfers
    monkeypatch.setattr(
        computed_goto_resolver,
        "_recover_static_handler_entry_route_transfers",
        lambda _transfers: (recovered,),
    )

    result = computed_goto_resolver.prepare_preopt_union_closure(
        harness["state"],
        live_mba=harness["live_mba"],
    )

    assert not result.prepared
    assert harness["state"].materialized_transfers == transfers_before


def test_prepare_preopt_union_closure_abstains_on_incomplete_conditional_boundary(
    monkeypatch,
) -> None:
    harness = _install_preopt_union_success_harness(
        monkeypatch,
        closure_edges=(NativeEdge(NativeEdgeKind.CONDITIONAL_TRUE, 0x1100),),
    )

    result = computed_goto_resolver.prepare_preopt_union_closure(
        harness["state"],
        live_mba=harness["live_mba"],
    )

    assert not result.prepared
    assert harness["generated"] == []
    assert harness["captures"] == []


def test_prepare_preopt_union_closure_abstains_on_conflicting_cut_owners(
    monkeypatch,
) -> None:
    harness = _install_preopt_union_success_harness(
        monkeypatch,
        live_eas=frozenset({0x1100, 0x1200}),
        closure_edges=(
            NativeEdge(
                NativeEdgeKind.INDIRECT,
                0x1100,
                resolver_proven=True,
                provenance="first_cut",
                source_instruction_ea=0x200C,
            ),
            NativeEdge(
                NativeEdgeKind.INDIRECT,
                0x1200,
                resolver_proven=True,
                provenance="second_cut",
                source_instruction_ea=0x200C,
            ),
        ),
    )

    result = computed_goto_resolver.prepare_preopt_union_closure(
        harness["state"],
        live_mba=harness["live_mba"],
    )

    assert not result.prepared
    assert harness["generated"] == []
    assert harness["captures"] == []


def test_prepare_preopt_union_closure_does_not_publish_after_capture_failure(
    monkeypatch,
) -> None:
    harness = _install_preopt_union_success_harness(
        monkeypatch,
        capture_succeeds=False,
    )

    result = computed_goto_resolver.prepare_preopt_union_closure(
        harness["state"],
        live_mba=harness["live_mba"],
    )

    assert not result.prepared
    assert len(harness["captures"]) == 1
    assert (
        computed_goto_resolver.get_prepared_preopt_union_closure(harness["state"])
        is None
    )


def test_prepare_detached_snippets_union_success_uses_session_path(
    monkeypatch,
) -> None:
    function_ea = 0x1000
    resolution = ComputedGotoResolution(
        function_ea=function_ea,
        jmp_targets={},
        reachable_eas=(function_ea,),
        arch="x86",
        executed_insns=0,
        seeds_run=0,
    )
    _session, state = _resolver_session(resolution)
    monkeypatch.setattr(
        computed_goto_resolver,
        "prepare_preopt_union_closure",
        lambda _state, *, live_mba: SimpleNamespace(
            prepared=True,
            published=True,
        ),
        raising=False,
    )

    assert (
        computed_goto_resolver.prepare_detached_handler_snippets(
            state,
            live_mba=object(),
        )
        == 1
    )


def test_prepare_detached_snippets_cached_union_stops_decompile_rounds(
    monkeypatch,
) -> None:
    function_ea = 0x1000
    resolution = ComputedGotoResolution(
        function_ea=function_ea,
        jmp_targets={},
        reachable_eas=(function_ea,),
        arch="x86",
        executed_insns=0,
        seeds_run=0,
    )
    _session, state = _resolver_session(resolution)
    monkeypatch.setattr(
        computed_goto_resolver,
        "prepare_preopt_union_closure",
        lambda _state, *, live_mba: SimpleNamespace(
            prepared=True,
            published=False,
        ),
        raising=False,
    )

    assert (
        computed_goto_resolver.prepare_detached_handler_snippets(
            state,
            live_mba=object(),
        )
        == 0
    )


def test_prepare_detached_snippets_consumes_pending_preopt_reimport(
    monkeypatch,
) -> None:
    function_ea = 0x1000
    resolution = ComputedGotoResolution(
        function_ea=function_ea,
        jmp_targets={},
        reachable_eas=(function_ea,),
        arch="x86",
        executed_insns=0,
        seeds_run=0,
    )
    _session, state = _resolver_session(resolution)
    state.pending_preopt_reimport = True
    monkeypatch.setattr(
        computed_goto_resolver,
        "prepare_preopt_union_closure",
        lambda *_args, **_kwargs: pytest.fail(
            "a rebound template needs only a new top-level decompile"
        ),
    )

    assert (
        computed_goto_resolver.prepare_detached_handler_snippets(
            state,
            live_mba=object(),
        )
        == 1
    )
    assert not state.pending_preopt_reimport


def test_static_prepatch_capture_defers_all_publication_to_frontend_fragment(
    monkeypatch,
) -> None:
    function_ea = 0x1000
    live_mba = object()
    plan = _PatchPlan(
        jmp_ea=0x1010,
        block_entry=0x1000,
        patch_start=0x1008,
        patch_bytes=b"\x90",
        region_end=0x1012,
        insn_heads=(0x1008,),
        new_block_eas=(),
        target_eas=(0x1020,),
    )
    resolution = ComputedGotoResolution(
        function_ea=function_ea,
        jmp_targets={plan.jmp_ea: plan.target_eas},
        reachable_eas=(function_ea,),
        arch="x86",
        executed_insns=1,
        seeds_run=0,
        patch_plans=(plan,),
    )
    _session, state = _resolver_session(resolution)
    state.begin_materialization(resolution)
    captured: list[tuple[object, object, object]] = []
    monkeypatch.setattr(
        computed_goto_resolver,
        "_static_prepatch_union_source_transfers",
        lambda _resolution: (),
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "_capture_prepatch_preopt_union_source",
        lambda _state, _resolution, _transfers: (
            captured.append((_state, _resolution, _transfers)) or True
        ),
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "materialize_computed_gotos",
        lambda *_args, **_kwargs: pytest.fail(
            "static discovery must not patch native bytes"
        ),
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "prepare_preopt_union_closure",
        lambda *_args, **_kwargs: pytest.fail(
            "live union publication belongs to the frontend fragment"
        ),
    )
    monkeypatch.setattr(
        computed_goto_resolver.ida_hexrays,
        "decompile",
        lambda _function_ea: pytest.fail("staged decompile must not run"),
    )

    assert (
        computed_goto_resolver.prepare_detached_handler_snippets(
            state,
            live_mba=live_mba,
        )
        == 1
    )
    assert captured == [(state, resolution, ())]


@pytest.mark.parametrize("union_behavior", ("abstain", "raise"))
def test_prepare_detached_snippets_union_failure_has_no_fallback(
    monkeypatch,
    union_behavior: str,
) -> None:
    function_ea = 0x1000
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x1010,
        source_block_ea=0x1010,
        materialized_anchor_eas=(),
        target_eas=(0x1020,),
        resolver_kind="condition_chain_handler_evidence",
    )
    resolution = ComputedGotoResolution(
        function_ea=function_ea,
        jmp_targets={},
        reachable_eas=(function_ea,),
        arch="x86",
        executed_insns=0,
        seeds_run=0,
    )
    _session, state = _resolver_session(resolution)
    assert state.native_preanalysis.merge_materialized_transfers(
        state.native_key, (transfer,)
    )
    events: list[object] = []

    def prepare_union(_state: object, *, live_mba: object):
        del live_mba
        events.append("union_abstain")
        if union_behavior == "raise":
            raise RuntimeError("synthetic union preparation failure")
        return SimpleNamespace(prepared=False, published=False)

    monkeypatch.setattr(
        computed_goto_resolver,
        "prepare_preopt_union_closure",
        prepare_union,
        raising=False,
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "_recover_static_handler_entry_route_transfers",
        lambda _transfers: (),
    )
    assert (
        computed_goto_resolver.prepare_detached_handler_snippets(
            state,
            live_mba=object(),
        )
        == 0
    )
    assert events == ["union_abstain"]
def test_install_does_not_register_resolver_owned_preopt_mutation(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        computed_goto_resolver,
        "register_flowchart_preanalysis_handler",
        lambda *_args: None,
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "register_calls_done_preanalysis_handler",
        lambda *_args: None,
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "register_callinfo_preanalysis_handler",
        lambda *_args: None,
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "register_stkpnts_preanalysis_handler",
        lambda *_args: None,
    )

    computed_goto_resolver.install()

    assert not hasattr(
        computed_goto_resolver,
        "register_preopt_preanalysis_handler",
    )
