"""Tests for in-memory state-dispatcher transition resolution."""
from __future__ import annotations

from d810.analyses.control_flow.dispatcher_kind import DispatcherType
from d810.analyses.control_flow.dispatcher_resolution import StateDispatcherMap, StateDispatcherRow
from d810.analyses.control_flow.semantic_transition import (
    StateTransitionFact,
    StateWriteAnchor,
    facts_from_validated_view,
    resolve_state_transitions_with_dispatcher_map,
)
from d810.recon.facts.model import FactObservation, ValidatedFactView


def _dispatch_map() -> StateDispatcherMap:
    return StateDispatcherMap(
        rows=(
            StateDispatcherRow(
                state_const=0x10,
                target_block=7,
                dispatcher_block=2,
                compare_block=2,
                branch_kind="switch_case",
                source=DispatcherType.SWITCH_TABLE,
            ),
            StateDispatcherRow(
                state_const=0x20,
                target_block=2,
                dispatcher_block=2,
                compare_block=2,
                branch_kind="switch_self_loop",
                source=DispatcherType.SWITCH_TABLE,
                row_kind="dispatcher_self_loop",
            ),
        ),
        dispatcher_entry_block=2,
        dispatcher_blocks=frozenset({2}),
        state_var_stkoff=0x3C,
        state_var_lvar_idx=None,
        source=DispatcherType.SWITCH_TABLE,
    )


def test_resolves_exact_state_and_next_state_write() -> None:
    resolutions = resolve_state_transitions_with_dispatcher_map(
        (
            StateTransitionFact(
                fact_id="transition:blk=100",
                source_block_serial=100,
                source_state_const=0x10,
                source_state_const_hex="0x00000010",
                state_var_stkoff=0x3C,
            ),
        ),
        dispatch_map=_dispatch_map(),
        state_write_anchors=(
            StateWriteAnchor(
                block_serial=7,
                state_const=0x55,
                state_var_stkoff=0x3C,
            ),
        ),
    )

    assert len(resolutions) == 1
    assert resolutions[0].resolved_next_block_serial == 7
    assert resolutions[0].resolved_next_state_const_u64 == 0x55
    assert resolutions[0].resolved_next_state_const_hex == "0x0000000000000055"
    assert resolutions[0].resolution_reason == "resolved_exact_state"


def test_reports_dispatcher_self_loop_target() -> None:
    resolutions = resolve_state_transitions_with_dispatcher_map(
        (
            StateTransitionFact(
                fact_id="transition:blk=101",
                source_block_serial=101,
                source_state_const=0x20,
            ),
        ),
        dispatch_map=_dispatch_map(),
    )

    assert resolutions[0].resolved_next_block_serial is None
    assert resolutions[0].resolution_reason == "target_is_dispatcher_block"


def test_non_branch_successor_is_not_dispatcher_bound() -> None:
    resolutions = resolve_state_transitions_with_dispatcher_map(
        (
            StateTransitionFact(
                fact_id="transition:blk=102",
                source_block_serial=102,
                source_state_const=0x10,
                successor_kind="fallthrough",
            ),
        ),
        dispatch_map=_dispatch_map(),
    )

    assert resolutions[0].resolved_next_block_serial is None
    assert "not a dispatcher-bound transition" in resolutions[0].resolution_reason


def test_projects_validated_fact_view_to_transition_evidence() -> None:
    view = ValidatedFactView(
        maturity="MMAT_GLBOPT1",
        observations=(
            FactObservation(
                fact_id="state_transition_anchor:blk=100",
                kind="StateTransitionAnchorFact",
                semantic_key="state_transition_anchor:blk=100",
                maturity="MMAT_GLBOPT1",
                phase="pre_d810",
                confidence=0.85,
                payload={
                    "source_block_serial": 100,
                    "source_state_const": 0x10,
                    "source_state_const_hex": "0x00000010",
                    "successor_kind": "branch",
                    "state_var_stkoff": 0x3C,
                },
            ),
            FactObservation(
                fact_id="state_write_anchor:blk=7",
                kind="StateWriteAnchorFact",
                semantic_key="state_write_anchor:blk=7",
                maturity="MMAT_GLBOPT1",
                phase="pre_d810",
                confidence=0.9,
                payload={
                    "block_serial": 7,
                    "state_const_u64": 0x55,
                    "state_var_stkoff": 0x3C,
                },
            ),
        ),
    )

    transition_facts, state_write_anchors = facts_from_validated_view(view)

    assert transition_facts == (
        StateTransitionFact(
            fact_id="state_transition_anchor:blk=100",
            source_block_serial=100,
            source_state_const=0x10,
            source_state_const_hex="0x00000010",
            successor_kind="branch",
            state_var_stkoff=0x3C,
        ),
    )
    assert state_write_anchors == (
        StateWriteAnchor(
            block_serial=7,
            state_const=0x55,
            state_var_stkoff=0x3C,
        ),
    )
