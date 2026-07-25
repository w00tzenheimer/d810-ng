from __future__ import annotations

from dataclasses import replace

import pytest

from d810.analyses.control_flow import detached_handler_island
from d810.analyses.control_flow.detached_handler_island import (
    ConditionalHandlerBridgePlan,
    ConditionalHandlerTargetTopology,
    ConditionalRouteEvidence,
    conditional_bridge_pre_dce_target_eas,
    conditional_bridge_requires_pre_dce_preservation,
    conditional_bridge_route_evidence_converged,
    DetachedHandlerIslandCandidate,
    DetachedHandlerIslandPlan,
    DetachedSnippetRoutePlan,
    DetachedSnippetReplacementEvidence,
    DetachedSnippetReplacementPlan,
    DetachedSnippetTerminalEvidence,
    DetachedSnippetTerminalRoutePlan,
    DetachedSnippetBoundaryPortOwner,
    DetachedSnippetDirectBoundaryPort,
    DetachedRouteEvidence,
    DetachedSourcePath,
    plan_detached_handler_island,
    plan_detached_snippet_routes,
    plan_live_handler_template_replacements,
    plan_detached_snippet_terminal_routes,
    merge_detached_snippet_ranges,
    plan_conditional_handler_bridges,
    select_detached_source_path,
)
from d810.analyses.control_flow.materialized_indirect_transfer import (
    MaterializedIndirectTransfer,
)


def test_merge_detached_snippet_ranges_coalesces_overlapping_branch_ranges() -> None:
    assert merge_detached_snippet_ranges(
        (
            (0x40C4B4, 0x40C4D4),
            (0x40C4D4, 0x40C4DC),
            (0x40C4D6, 0x40C4DC),
        )
    ) == ((0x40C4B4, 0x40C4DC),)


def _live_handler_replacement_evidence(
    *,
    target_ea: int = 0x40B8E6,
    branch_ea: int = 0x40B90F,
    calls_verify_safe: bool = True,
    contains_calls: bool | None = None,
) -> DetachedSnippetReplacementEvidence:
    return DetachedSnippetReplacementEvidence(
        target_ea=target_ea,
        conditional_branch_ea=branch_ea,
        conditional_target_eas=(0x40B915, 0x40C6B5),
        terminal_exit_eas=(0x40B931, 0x40C6D8),
        calls_verify_safe=calls_verify_safe,
        contains_calls=(
            not calls_verify_safe if contains_calls is None else contains_calls
        ),
    )


def test_live_handler_replacement_joins_state_branch_and_terminal_proofs() -> None:
    assert plan_live_handler_template_replacements(
        (_live_handler_replacement_evidence(),),
        state_targets={0xA5A94B86: 0x40B8E6},
        complete_live_branch_eas=frozenset(),
        resolver_targets={
            0x40B931: (0x40B6C0,),
            0x40C6D8: (0x40A607,),
        },
    ) == (
        DetachedSnippetReplacementPlan(
            target_ea=0x40B8E6,
            selector_states=(0xA5A94B86,),
            conditional_branch_ea=0x40B90F,
            conditional_target_eas=(0x40B915, 0x40C6B5),
            terminal_routes=(
                (0x40B931, 0x40B6C0),
                (0x40C6D8, 0x40A607),
            ),
        ),
    )


def test_empty_external_block_uses_valid_native_start_ea() -> None:
    assert (
        detached_handler_island.select_unique_block_native_ea(
            0x40B6C0,
            (),
        )
        == 0x40B6C0
    )
    assert (
        detached_handler_island.select_unique_block_native_ea(
            0xFFFFFFFFFFFFFFFF,
            (),
        )
        is None
    )


def test_owned_ranges_include_empty_native_block_start() -> None:
    ranges = ((0x40AF00, 0x40AFDF),)

    assert detached_handler_island.block_intersects_owned_ranges(
        0x40AFB5,
        (),
        ranges,
    )
    assert detached_handler_island.block_intersects_owned_ranges(
        0xF1000000,
        (0x40AFB5,),
        ranges,
    )
    assert not detached_handler_island.block_intersects_owned_ranges(
        0x40AFDF,
        (),
        ranges,
    )


def _direct_boundary_port(
    *,
    target_ea: int = 0x1400,
    endpoint_block_ea: int = 0x1010,
) -> DetachedSnippetDirectBoundaryPort:
    return DetachedSnippetDirectBoundaryPort(
        source_block_ea=0x1000,
        source_instruction_ea=0x1008,
        endpoint_block_ea=endpoint_block_ea,
        old_successor_eas=(0x1200,),
        target_ea=target_ea,
        state_register=7,
        state_constant=0x1234,
        source_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        endpoint_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        delivery_mode="redirect_edge",
        resolver_kind="unit_test",
    )


def test_boundary_port_template_records_deduplicate_exact_duplicates() -> None:
    port = _direct_boundary_port()

    normalized = detached_handler_island.normalize_detached_snippet_boundary_ports(
        (port, port),
        (),
    )

    assert normalized.direct == (port,)
    assert normalized.conditional == ()


def test_boundary_port_template_records_reject_conflicting_source() -> None:
    with pytest.raises(ValueError, match="conflicting direct boundary port"):
        detached_handler_island.normalize_detached_snippet_boundary_ports(
            (_direct_boundary_port(), _direct_boundary_port(target_ea=0x1500)),
            (),
        )


def test_boundary_port_template_records_keep_distinct_frontier_endpoints() -> None:
    first = _direct_boundary_port(endpoint_block_ea=0x1010)
    second = _direct_boundary_port(endpoint_block_ea=0x1020)

    normalized = detached_handler_island.normalize_detached_snippet_boundary_ports(
        (second, first),
        (),
    )

    assert normalized.direct == (first, second)


def test_boundary_port_template_records_keep_distinct_owner_bindings() -> None:
    imported = _direct_boundary_port()
    live = replace(
        imported,
        source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        endpoint_owner=DetachedSnippetBoundaryPortOwner.LIVE,
    )

    normalized = detached_handler_island.normalize_detached_snippet_boundary_ports(
        (live, imported),
        (),
    )

    assert normalized.direct == (imported, live)


def test_boundary_port_template_records_reject_conflict_per_owner_binding() -> None:
    imported = _direct_boundary_port()
    conflicting = replace(imported, target_ea=0x1500)

    with pytest.raises(ValueError, match="conflicting direct boundary port"):
        detached_handler_island.normalize_detached_snippet_boundary_ports(
            (imported, conflicting),
            (),
        )


def test_resolver_cut_boundary_port_uses_no_synthetic_state_identity() -> None:
    port = detached_handler_island.make_resolver_cut_boundary_port(
        source_block_ea=0x40A7E5,
        source_instruction_ea=0x40A7EF,
        target_ea=0x40B6C0,
        source_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        target_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        provenance="static_fixpoint",
    )

    assert port.endpoint_block_ea == 0x40A7E5
    assert port.old_successor_eas == ()
    assert port.state_register is None
    assert port.state_constant is None
    assert port.source_owner == DetachedSnippetBoundaryPortOwner.IMPORTED
    assert port.endpoint_owner == DetachedSnippetBoundaryPortOwner.IMPORTED
    assert port.target_owner == DetachedSnippetBoundaryPortOwner.LIVE
    assert port.delivery_mode == "terminal_goto"


def test_live_handler_replacement_accepts_multiple_states_for_one_handler() -> None:
    assert plan_live_handler_template_replacements(
        (_live_handler_replacement_evidence(),),
        state_targets={
            0x10203040: 0x40B8E6,
            0xA5A94B86: 0x40B8E6,
        },
        complete_live_branch_eas=frozenset(),
        resolver_targets={
            0x40B931: (0x40B6C0,),
            0x40C6D8: (0x40A607,),
        },
    )[0].selector_states == (0x10203040, 0xA5A94B86)


def test_live_handler_replacement_accepts_sdk_verified_call_payloads() -> None:
    plans = plan_live_handler_template_replacements(
        (
            _live_handler_replacement_evidence(
                calls_verify_safe=True,
                contains_calls=True,
            ),
        ),
        state_targets={0xA5A94B86: 0x40B8E6},
        complete_live_branch_eas=frozenset(),
        resolver_targets={
            0x40B931: (0x40B6C0,),
            0x40C6D8: (0x40A607,),
        },
    )

    assert len(plans) == 1
    assert plans[0].target_ea == 0x40B8E6


def test_live_handler_replacement_restores_partial_live_fork() -> None:
    plans = plan_live_handler_template_replacements(
        (_live_handler_replacement_evidence(),),
        state_targets={0xA5A94B86: 0x40B8E6},
        complete_live_branch_eas=frozenset(),
        resolver_targets={
            0x40B931: (0x40B6C0,),
            0x40C6D8: (0x40A607,),
        },
    )

    assert len(plans) == 1


def test_live_handler_replacement_restores_absent_fork() -> None:
    plans = plan_live_handler_template_replacements(
        (_live_handler_replacement_evidence(),),
        state_targets={0xA5A94B86: 0x40B8E6},
        complete_live_branch_eas=frozenset(),
        resolver_targets={
            0x40B931: (0x40B6C0,),
            0x40C6D8: (0x40A607,),
        },
    )

    assert len(plans) == 1


def test_live_handler_replacement_preserves_complete_live_fork() -> None:
    assert (
        plan_live_handler_template_replacements(
            (_live_handler_replacement_evidence(),),
            state_targets={0xA5A94B86: 0x40B8E6},
            complete_live_branch_eas=frozenset({0x40B90F}),
            resolver_targets={
                0x40B931: (0x40B6C0,),
                0x40C6D8: (0x40A607,),
            },
        )
        == ()
    )


def test_live_handler_replacement_abstains_without_complete_exact_evidence() -> None:
    kwargs = {
        "state_targets": {0xA5A94B86: 0x40B8E6},
        "complete_live_branch_eas": frozenset(),
        "resolver_targets": {
            0x40B931: (0x40B6C0,),
            0x40C6D8: (0x40A607,),
        },
    }
    evidence = _live_handler_replacement_evidence()

    assert (
        plan_live_handler_template_replacements(
            (evidence,),
            **{
                **kwargs,
                "complete_live_branch_eas": frozenset({0x40B90F}),
            },
        )
        == ()
    )
    assert (
        plan_live_handler_template_replacements(
            (evidence,),
            **{**kwargs, "state_targets": {0xA5A94B86: 0x40B9A6}},
        )
        == ()
    )
    assert (
        plan_live_handler_template_replacements(
            (evidence,),
            **{
                **kwargs,
                "resolver_targets": {
                    0x40B931: (0x40B6C0, 0x40A607),
                    0x40C6D8: (0x40A607,),
                },
            },
        )
        == ()
    )
    assert (
        plan_live_handler_template_replacements(
            (_live_handler_replacement_evidence(calls_verify_safe=False),),
            **kwargs,
        )
        == ()
    )
    assert (
        plan_live_handler_template_replacements(
            (
                evidence,
                _live_handler_replacement_evidence(branch_ea=0x40B910),
            ),
            **kwargs,
        )
        == ()
    )


def test_plan_detached_snippet_route_selects_unique_missing_static_target() -> None:
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x40ADF2,
        source_block_ea=0x40ADE6,
        materialized_anchor_eas=(0x40ADF2,),
        target_eas=(0x40C4B4,),
        selector_state_constant=0xF6A636EF,
        resolver_kind="residual_state_route_evidence",
    )

    assert plan_detached_snippet_routes(
        (transfer,),
        live_eas=frozenset({0x40ADE6, 0x40ADF2}),
    ) == (
        DetachedSnippetRoutePlan(
            source_ea=0x40ADF2,
            target_ea=0x40C4B4,
            state_constant=0xF6A636EF,
        ),
    )


def test_plan_detached_snippet_route_imports_static_handler_entry() -> None:
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
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x40B149,
        source_block_ea=0x40B149,
        materialized_anchor_eas=(),
        target_eas=(0x40B163,),
        selector_state_var_reg=20,
        selector_state_constant=state,
        resolver_kind="static_handler_entry_route",
        owned_native_ranges=((0x40B163, 0x40B17F),),
    )

    assert (
        plan_detached_snippet_routes(
            (leaf, transfer),
            live_eas=frozenset({0x40B149, 0x40B163}),
        )
        == ()
    )
    assert plan_detached_snippet_routes(
        (leaf, transfer),
        live_eas=frozenset({0x40B149, 0x40B163}),
        live_target_eas=frozenset({0x40B149}),
    ) == (
        DetachedSnippetRoutePlan(
            source_ea=0x40B149,
            target_ea=0x40B163,
            state_constant=0x1EBFFA3C,
            evidence_kind="static_handler_entry_route",
            owned_native_ranges=((0x40B163, 0x40B17F),),
        ),
    )
    assert (
        plan_detached_snippet_routes(
            (leaf, transfer),
            live_eas=frozenset({0x40B149, 0x40B163}),
            live_target_eas=frozenset({0x40B163}),
        )
        == ()
    )


def test_static_handler_capture_ranges_use_prepatch_owned_ranges() -> None:
    plan = DetachedSnippetRoutePlan(
        source_ea=0x40B149,
        target_ea=0x40B163,
        state_constant=0x1EBFFA3C,
        evidence_kind="static_handler_entry_route",
        owned_native_ranges=((0x40B163, 0x40B17F),),
    )

    assert detached_handler_island.select_detached_snippet_capture_ranges(
        (plan,),
        target_ea=0x40B163,
    ) == ((0x40B163, 0x40B17F),)
    assert (
        detached_handler_island.select_detached_snippet_capture_ranges(
            (
                plan,
                DetachedSnippetRoutePlan(
                    source_ea=0x40B149,
                    target_ea=0x40B163,
                    state_constant=0x1EBFFA3C,
                    evidence_kind="static_handler_entry_route",
                    owned_native_ranges=((0x40B163, 0x40B180),),
                ),
            ),
            target_ea=0x40B163,
        )
        == ()
    )


def test_static_fixpoint_equality_route_inherits_prepatch_owned_ranges() -> None:
    state = 0x64B9DC19
    target_ea = 0x40CCE6
    equality = MaterializedIndirectTransfer(
        source_jmp_ea=0x40CCE4,
        source_block_ea=0x40CCCB,
        materialized_anchor_eas=(0x40CCDF, 0x40CCE5),
        target_eas=(target_ea, 0x40C9DB),
        condition_code=4,
        true_target_ea=target_ea,
        false_target_ea=0x40C9DB,
        selector_state_var_reg=20,
        selector_compare_constant=state,
        resolver_kind="static_fixpoint",
    )
    handler = MaterializedIndirectTransfer(
        source_jmp_ea=0x40CCCB,
        source_block_ea=0x40CCCB,
        materialized_anchor_eas=(),
        target_eas=(target_ea,),
        selector_state_var_reg=20,
        selector_state_constant=state,
        resolver_kind="static_handler_entry_route",
        owned_native_ranges=((target_ea, 0x40CCFB),),
    )

    assert plan_detached_snippet_routes(
        (equality, handler),
        live_eas=frozenset({0x40CCDF, 0x40CCE4, 0x40CCE5}),
        live_target_eas=frozenset({0x40CCCB}),
    ) == (
        DetachedSnippetRoutePlan(
            source_ea=0x40CCDF,
            target_ea=target_ea,
            state_constant=state,
            evidence_kind="static_fixpoint",
            owned_native_ranges=((target_ea, 0x40CCFB),),
        ),
    )
    assert detached_handler_island.select_detached_snippet_capture_ranges(
        plan_detached_snippet_routes(
            (equality, handler),
            live_eas=frozenset({0x40CCDF, 0x40CCE4, 0x40CCE5}),
            live_target_eas=frozenset({0x40CCCB}),
        ),
        target_ea=target_ea,
    ) == ((target_ea, 0x40CCFB),)


def test_plan_detached_snippet_route_skips_live_static_handler_entry() -> None:
    state = 0xCCEC5DE0
    leaf = MaterializedIndirectTransfer(
        source_jmp_ea=0x40C150,
        source_block_ea=0x40C150,
        materialized_anchor_eas=(),
        target_eas=(0x40C16A,),
        selector_state_var_reg=20,
        selector_state_constant=state,
        resolver_kind="condition_chain_handler_evidence",
    )
    handler_entry = MaterializedIndirectTransfer(
        source_jmp_ea=0x40C150,
        source_block_ea=0x40C150,
        materialized_anchor_eas=(),
        target_eas=(0x40C16A,),
        selector_state_var_reg=20,
        selector_state_constant=state,
        resolver_kind="static_handler_entry_route",
    )

    assert (
        plan_detached_snippet_routes(
            (leaf, handler_entry),
            live_eas=frozenset({0x40C150}),
        )
        == ()
    )


def test_plan_detached_snippet_route_abstains_for_live_or_conflicting_target() -> None:
    def transfer(target: int) -> MaterializedIndirectTransfer:
        return MaterializedIndirectTransfer(
            source_jmp_ea=0x40ADF2,
            source_block_ea=0x40ADE6,
            materialized_anchor_eas=(0x40ADF2,),
            target_eas=(target,),
            selector_state_constant=0xF6A636EF,
            resolver_kind="residual_state_route_evidence",
        )

    assert (
        plan_detached_snippet_routes(
            (transfer(0x40C4B4),),
            live_eas=frozenset({0x40ADF2, 0x40C4B4}),
        )
        == ()
    )
    assert (
        plan_detached_snippet_routes(
            (transfer(0x40C4B4), transfer(0x40C500)),
            live_eas=frozenset({0x40ADF2}),
        )
        == ()
    )


def test_plan_detached_snippet_route_requires_routable_target_entry() -> None:
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x40B04A,
        source_block_ea=0x40B038,
        materialized_anchor_eas=(),
        target_eas=(0x40BF1B,),
        selector_state_constant=0xF32B2D3A,
        resolver_kind="residual_state_route_evidence",
    )

    assert plan_detached_snippet_routes(
        (transfer,),
        live_eas=frozenset({0x40B04A, 0x40BF1B}),
        live_target_eas=frozenset(),
    ) == (
        DetachedSnippetRoutePlan(
            source_ea=0x40B04A,
            target_ea=0x40BF1B,
            state_constant=0xF32B2D3A,
        ),
    )


def test_plan_detached_snippet_route_accepts_live_residual_delivery_anchor() -> None:
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x40B06B,
        source_block_ea=0x40B06B,
        materialized_anchor_eas=(0x40B06B,),
        target_eas=(0x40BF1B,),
        selector_state_constant=0xF32B2D3A,
        resolver_kind="residual_state_route",
    )

    assert plan_detached_snippet_routes(
        (transfer,),
        live_eas=frozenset({0x40B06B}),
        live_target_eas=frozenset(),
    ) == (
        DetachedSnippetRoutePlan(
            source_ea=0x40B06B,
            target_ea=0x40BF1B,
            state_constant=0xF32B2D3A,
            evidence_kind="residual_state_route",
        ),
    )


def test_plan_detached_snippet_terminal_route_joins_exact_native_target() -> None:
    imported_exit_ea = 0xF1C002D0
    native_exit_ea = 0x40C703
    target_ea = 0x40AF00

    assert plan_detached_snippet_terminal_routes(
        (
            DetachedSnippetTerminalEvidence(
                imported_exit_ea=imported_exit_ea,
                native_exit_ea=native_exit_ea,
            ),
        ),
        resolver_targets={native_exit_ea: (target_ea,)},
        source_blocks_by_imported_ea={imported_exit_ea: 77},
        target_blocks_by_ea={target_ea: 70},
        zero_way_source_blocks=frozenset({77}),
    ) == (
        DetachedSnippetTerminalRoutePlan(
            source_block_serial=77,
            target_block_serial=70,
            native_exit_ea=native_exit_ea,
            target_ea=target_ea,
        ),
    )


def test_plan_detached_snippet_terminal_route_abstains_on_ambiguous_target() -> None:
    evidence = DetachedSnippetTerminalEvidence(
        imported_exit_ea=0xF1C002D0,
        native_exit_ea=0x40C703,
    )

    assert (
        plan_detached_snippet_terminal_routes(
            (evidence,),
            resolver_targets={0x40C703: (0x40AF00, 0x40ACF3)},
            source_blocks_by_imported_ea={0xF1C002D0: 77},
            target_blocks_by_ea={0x40AF00: 70, 0x40ACF3: 68},
            zero_way_source_blocks=frozenset({77}),
        )
        == ()
    )


def test_plan_detached_snippet_route_selects_missing_static_equality_arm() -> None:
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x40A5E3,
        source_block_ea=0x40A5CA,
        materialized_anchor_eas=(0x40A5CA,),
        target_eas=(0x40C898, 0x40A5F0),
        condition_code=4,
        true_target_ea=0x40C898,
        false_target_ea=0x40A5F0,
        selector_compare_constant=0x19A7218A,
        resolver_kind="static_equality_fixpoint",
    )

    assert plan_detached_snippet_routes(
        (transfer,),
        live_eas=frozenset({0x40A5F0}),
    ) == (
        DetachedSnippetRoutePlan(
            source_ea=0x40A5CA,
            target_ea=0x40C898,
            state_constant=0x19A7218A,
            evidence_kind="static_equality_fixpoint",
        ),
    )


def test_plan_detached_snippet_route_selects_static_fixpoint_equality_arm() -> None:
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x40CD44,
        source_block_ea=0x40CD2B,
        materialized_anchor_eas=(0x40CD38, 0x40CD3E),
        target_eas=(0x40C9DB, 0x40CD46),
        condition_code=4,
        true_target_ea=0x40CD46,
        false_target_ea=0x40C9DB,
        selector_compare_constant=0x34170401,
        resolver_kind="static_fixpoint",
    )

    assert plan_detached_snippet_routes(
        (transfer,),
        live_eas=frozenset({0x40CD38, 0x40C9DB}),
        live_target_eas=frozenset({0x40C9DB}),
    ) == (
        DetachedSnippetRoutePlan(
            source_ea=0x40CD38,
            target_ea=0x40CD46,
            state_constant=0x34170401,
            evidence_kind="static_fixpoint",
        ),
    )


def test_plan_detached_snippet_route_seeds_missing_static_equality_candidate() -> None:
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x40DAB9,
        source_block_ea=0x40DAA8,
        materialized_anchor_eas=(),
        target_eas=(0x40DABB,),
        selector_state_var_reg=28,
        selector_state_constant=0xB13A6E93,
        resolver_kind="static_equality_candidate",
    )

    assert plan_detached_snippet_routes(
        (transfer,),
        live_eas=frozenset({0x40D381}),
        live_target_eas=frozenset({0x40D381}),
    ) == (
        DetachedSnippetRoutePlan(
            source_ea=0x40DAB9,
            target_ea=0x40DABB,
            state_constant=0xB13A6E93,
            evidence_kind="static_equality_candidate",
        ),
    )

    # Once that exact target is represented by the live MBA, no detached
    # capture is needed.
    assert (
        plan_detached_snippet_routes(
            (transfer,),
            live_eas=frozenset({0x40D381, 0x40DABB}),
            live_target_eas=frozenset({0x40D381, 0x40DABB}),
        )
        == ()
    )


def test_plan_detached_snippet_route_rejects_conflicting_equality_candidates() -> None:
    def candidate(target_ea: int) -> MaterializedIndirectTransfer:
        return MaterializedIndirectTransfer(
            source_jmp_ea=0x40DAB9,
            source_block_ea=0x40DAA8,
            materialized_anchor_eas=(),
            target_eas=(target_ea,),
            selector_state_var_reg=28,
            selector_state_constant=0xB13A6E93,
            resolver_kind="static_equality_candidate",
        )

    assert (
        plan_detached_snippet_routes(
            (candidate(0x40DABB), candidate(0x40DAD0)),
            live_eas=frozenset({0x40D381}),
            live_target_eas=frozenset({0x40D381}),
        )
        == ()
    )


def test_conditional_bridge_preserves_imported_target_without_router_predecessor() -> (
    None
):
    plan = _conditional_bridge(
        true_target=0x40AF00,
        false_target=0x40ACE7,
    )

    assert conditional_bridge_pre_dce_target_eas(
        plan,
        target_topologies={},
        imported_target_eas=frozenset({0x40AF00}),
    ) == (0x40AF00,)


def _conditional_bridge(
    *,
    source_ea: int = 0x40C404,
    true_is_taken: bool = True,
    true_state: int = 0x304E8694,
    false_state: int = 0xA5A94B86,
    true_target: int = 0x40B342,
    false_target: int = 0x40B8E6,
) -> MaterializedIndirectTransfer:
    return MaterializedIndirectTransfer(
        source_jmp_ea=source_ea,
        source_block_ea=0x40C3F9,
        materialized_anchor_eas=(source_ea,),
        target_eas=(true_target, false_target),
        condition_code=5,
        true_target_ea=true_target,
        false_target_ea=false_target,
        predicate_register=8,
        predicate_size=4,
        predicate_predecessor_ea=0x40C3FE,
        predicate_true_state=true_state,
        predicate_false_state=false_state,
        predicate_true_is_taken=true_is_taken,
        resolver_kind="conditional_handler_bridge",
    )


def test_plan_conditional_handler_bridge_resolves_taken_and_fallthrough_arms() -> None:
    transfer = _conditional_bridge()

    assert plan_conditional_handler_bridges(
        (transfer,),
        state_register=20,
        state_size=4,
        state_targets={
            0x304E8694: 0x40B342,
            0xA5A94B86: 0x40B8E6,
        },
    ) == (
        ConditionalHandlerBridgePlan(
            source_predicate_ea=0x40C404,
            predicate_register=8,
            predicate_size=4,
            state_register=20,
            state_size=4,
            false_state=0xA5A94B86,
            true_state=0x304E8694,
            false_target_ea=0x40B8E6,
            true_target_ea=0x40B342,
        ),
    )

    inverted = _conditional_bridge(true_is_taken=False)
    assert plan_conditional_handler_bridges(
        (inverted,),
        state_register=20,
        state_size=4,
        state_targets={
            0x304E8694: 0x40B342,
            0xA5A94B86: 0x40B8E6,
        },
    ) == (
        ConditionalHandlerBridgePlan(
            source_predicate_ea=0x40C404,
            predicate_register=8,
            predicate_size=4,
            state_register=20,
            state_size=4,
            false_state=0xA5A94B86,
            true_state=0x304E8694,
            false_target_ea=0x40B8E6,
            true_target_ea=0x40B342,
        ),
    )


def test_plan_conditional_handler_bridge_requires_exact_state_paths() -> None:
    assert (
        plan_conditional_handler_bridges(
            (_conditional_bridge(),),
            state_targets={
                0x304E8694: 0x40B342,
                0xA5A94B86: 0x40DEAD,
            },
        )
        == ()
    )


def test_plan_conditional_handler_bridge_abstains_on_conflicting_source() -> None:
    assert (
        plan_conditional_handler_bridges(
            (
                _conditional_bridge(),
                _conditional_bridge(false_target=0x40B900),
            ),
            state_targets={
                0x304E8694: 0x40B342,
                0xA5A94B86: 0x40B8E6,
            },
        )
        == ()
    )


def test_conditional_bridge_waits_for_exact_residual_route_convergence() -> None:
    state = 0xA5A94B86
    residual = MaterializedIndirectTransfer(
        source_jmp_ea=0x40C422,
        source_block_ea=0x40C422,
        materialized_anchor_eas=(0x40C422,),
        target_eas=(0x40B8E6,),
        selector_state_constant=state,
        resolver_kind="residual_state_route",
    )
    exact = MaterializedIndirectTransfer(
        source_jmp_ea=0x40B8E4,
        source_block_ea=0x40B8CC,
        materialized_anchor_eas=(0x40B8D8,),
        target_eas=(0x40B8E6,),
        selector_state_constant=state,
        resolver_kind="static_equality_route",
    )

    assert not conditional_bridge_route_evidence_converged(
        (_conditional_bridge(), residual),
    )
    assert conditional_bridge_route_evidence_converged(
        (_conditional_bridge(), residual, exact),
    )


def test_conditional_bridge_preserves_router_only_multiblock_target() -> None:
    plan = plan_conditional_handler_bridges(
        (_conditional_bridge(),),
        state_targets={
            0x304E8694: 0x40B342,
            0xA5A94B86: 0x40B8E6,
        },
    )[0]

    target_topologies = {
        0x40B342: ConditionalHandlerTargetTopology(
            target_ea=0x40B342,
            router_block=212,
            dispatcher_block=9,
            predecessor_blocks=(212, 470),
            successor_blocks=(214,),
        ),
        0x40B8E6: ConditionalHandlerTargetTopology(
            target_ea=0x40B8E6,
            router_block=413,
            dispatcher_block=9,
            predecessor_blocks=(413,),
            successor_blocks=(281,),
        ),
    }

    assert conditional_bridge_pre_dce_target_eas(
        plan,
        target_topologies=target_topologies,
    ) == (0x40B8E6,)
    assert conditional_bridge_requires_pre_dce_preservation(
        plan,
        target_topologies=target_topologies,
    )


def test_conditional_bridge_leaves_single_block_state_targets_to_calls() -> None:
    plan = plan_conditional_handler_bridges(
        (_conditional_bridge(),),
        state_targets={
            0x304E8694: 0x40B342,
            0xA5A94B86: 0x40B8E6,
        },
    )[0]

    assert not conditional_bridge_requires_pre_dce_preservation(
        plan,
        target_topologies={
            0x40B342: ConditionalHandlerTargetTopology(
                target_ea=0x40B342,
                router_block=212,
                dispatcher_block=9,
                predecessor_blocks=(212,),
                successor_blocks=(9,),
            ),
            0x40B8E6: ConditionalHandlerTargetTopology(
                target_ea=0x40B8E6,
                router_block=413,
                dispatcher_block=9,
                predecessor_blocks=(413,),
                successor_blocks=(9,),
            ),
        },
    )


def test_conditional_bridge_abstains_when_payload_has_live_nonrouter_owner() -> None:
    plan = plan_conditional_handler_bridges(
        (_conditional_bridge(),),
        state_targets={
            0x304E8694: 0x40B342,
            0xA5A94B86: 0x40B8E6,
        },
    )[0]

    assert not conditional_bridge_requires_pre_dce_preservation(
        plan,
        target_topologies={
            0x40B342: ConditionalHandlerTargetTopology(
                target_ea=0x40B342,
                router_block=212,
                dispatcher_block=9,
                predecessor_blocks=(212, 470),
                successor_blocks=(214,),
            ),
            0x40B8E6: ConditionalHandlerTargetTopology(
                target_ea=0x40B8E6,
                router_block=413,
                dispatcher_block=9,
                predecessor_blocks=(413, 500),
                successor_blocks=(281,),
            ),
        },
    )


def test_select_detached_source_path_matches_one_conditional_arm() -> None:
    assert select_detached_source_path(
        residual_routes=(DetachedRouteEvidence(0x401000, 0x402000),),
        conditional_routes=(
            ConditionalRouteEvidence(
                source_predicate_ea=0x401000,
                condition_code=5,
                true_target_ea=0x403000,
                false_target_ea=0x402000,
            ),
        ),
    ) == DetachedSourcePath(
        source_predicate_ea=0x401000,
        detached_entry_ea=0x402000,
        live_sibling_target_ea=0x403000,
        detached_is_true=False,
    )


def test_select_detached_source_path_correlates_distinct_producers_by_target() -> None:
    assert select_detached_source_path(
        residual_routes=(DetachedRouteEvidence(0x40C5EF, 0x40A7AE),),
        conditional_routes=(
            ConditionalRouteEvidence(
                source_predicate_ea=0x40C5D1,
                condition_code=5,
                true_target_ea=0x40B100,
                false_target_ea=0x40A7AE,
            ),
        ),
    ) == DetachedSourcePath(
        source_predicate_ea=0x40C5D1,
        detached_entry_ea=0x40A7AE,
        live_sibling_target_ea=0x40B100,
        detached_is_true=False,
    )


def test_select_detached_source_path_abstains_on_ambiguous_routes() -> None:
    residual = DetachedRouteEvidence(0x401000, 0x402000)
    assert (
        select_detached_source_path(
            residual_routes=(residual, residual),
            conditional_routes=(
                ConditionalRouteEvidence(0x401000, 5, 0x403000, 0x402000),
            ),
        )
        is None
    )


def _candidate(*, condition_code: int = 5) -> DetachedHandlerIslandCandidate:
    return DetachedHandlerIslandCandidate(
        source_path=DetachedSourcePath(
            source_predicate_ea=0x401000,
            detached_entry_ea=0x402000,
            live_sibling_target_ea=0x403000,
            detached_is_true=False,
        ),
        detached_end_ea=0x402040,
        call_target_ea=0x410000,
        call_argument_ida_stkoff=0xCC,
        predicate_ida_stkoff=0x1C,
        state_register=20,
        condition_code=condition_code,
        inherited_state=0xB34CE2DF,
        taken_state=0x82F1899D,
        state_targets=(
            (0xB34CE2DF, 0x40BCA3),
            (0x82F1899D, 0x40B74C),
        ),
    )


def test_plan_detached_handler_island_normalizes_jnz_arms() -> None:
    assert plan_detached_handler_island(_candidate()) == DetachedHandlerIslandPlan(
        source_predicate_ea=0x401000,
        detached_entry_ea=0x402000,
        detached_end_ea=0x402040,
        call_target_ea=0x410000,
        call_argument_ida_stkoff=0xCC,
        predicate_ida_stkoff=0x1C,
        state_register=20,
        false_state=0xB34CE2DF,
        true_state=0x82F1899D,
        false_target_ea=0x40BCA3,
        true_target_ea=0x40B74C,
    )


def test_plan_detached_handler_island_normalizes_jz_arms() -> None:
    plan = plan_detached_handler_island(_candidate(condition_code=4))
    assert plan is not None
    assert (plan.false_state, plan.true_state) == (0x82F1899D, 0xB34CE2DF)
    assert (plan.false_target_ea, plan.true_target_ea) == (0x40B74C, 0x40BCA3)


def test_plan_detached_handler_island_abstains_without_both_state_routes() -> None:
    candidate = _candidate()
    candidate = DetachedHandlerIslandCandidate(
        source_path=candidate.source_path,
        detached_end_ea=candidate.detached_end_ea,
        call_target_ea=candidate.call_target_ea,
        call_argument_ida_stkoff=candidate.call_argument_ida_stkoff,
        predicate_ida_stkoff=candidate.predicate_ida_stkoff,
        state_register=candidate.state_register,
        condition_code=candidate.condition_code,
        inherited_state=candidate.inherited_state,
        taken_state=candidate.taken_state,
        state_targets=((candidate.inherited_state, 0x40BCA3),),
    )
    assert plan_detached_handler_island(candidate) is None


def test_plan_detached_handler_island_abstains_on_conflicting_state_route() -> None:
    candidate = _candidate()
    candidate = DetachedHandlerIslandCandidate(
        source_path=candidate.source_path,
        detached_end_ea=candidate.detached_end_ea,
        call_target_ea=candidate.call_target_ea,
        call_argument_ida_stkoff=candidate.call_argument_ida_stkoff,
        predicate_ida_stkoff=candidate.predicate_ida_stkoff,
        state_register=candidate.state_register,
        condition_code=candidate.condition_code,
        inherited_state=candidate.inherited_state,
        taken_state=candidate.taken_state,
        state_targets=candidate.state_targets + ((candidate.taken_state, 0x40D000),),
    )
    assert plan_detached_handler_island(candidate) is None
