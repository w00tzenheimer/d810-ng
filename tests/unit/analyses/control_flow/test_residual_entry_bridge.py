"""Tests for the portable residual-entry bridge planner."""

from __future__ import annotations

from d810.analyses.control_flow.residual_entry_bridge import (
    EntryBridgeEvidence,
    StateRoutingNode,
    plan_residual_entry_bridge,
)


def _evidence() -> EntryBridgeEvidence:
    return EntryBridgeEvidence(
        predicate_ea=0x100,
        condition_code=5,
        predicate_stack_identity=(0x20, 4),
        stack_cell_identity=(0x80, 4),
        taken_state_constant=0xA0716E5B,
        fallthrough_state_constant=0xEC71CA67,
        source_store_ea=0x110,
    )


def test_planner_follows_proven_initial_state_to_leaf_and_resolves_both_arms():
    plan = plan_residual_entry_bridge(
        evidence=_evidence(),
        initial_state=0xABB95547,
        routing_nodes=(
            StateRoutingNode(
                source_block_ea=0x120,
                patch_window_end_ea=0x12C,
                condition_code=4,
                compared_state_constant=0xBB2D365,
                true_target_ea=0x900,
                false_target_ea=0x140,
            ),
            StateRoutingNode(
                source_block_ea=0x140,
                patch_window_end_ea=0x14C,
                condition_code=12,
                compared_state_constant=0xBB2D365,
                true_target_ea=0xA00,
                false_target_ea=0xB00,
            ),
        ),
        live_state_targets={0xA0716E5B: 0xC261},
        residual_state_targets={0xEC71CA67: 0xB9A6},
    )

    assert plan is not None
    assert plan.anchor_ea == 0x140
    assert plan.condition_code == 5
    assert plan.true_target_ea == 0xC261
    assert plan.false_target_ea == 0xB9A6


def test_planner_abstains_when_one_initial_state_has_no_proven_target():
    assert (
        plan_residual_entry_bridge(
            evidence=_evidence(),
            initial_state=0xABB95547,
            routing_nodes=(
                StateRoutingNode(
                    source_block_ea=0x120,
                    patch_window_end_ea=0x12C,
                    condition_code=4,
                    compared_state_constant=0xBB2D365,
                    true_target_ea=0x900,
                    false_target_ea=0xB00,
                ),
            ),
            live_state_targets={0xA0716E5B: 0xC261},
            residual_state_targets={},
        )
        is None
    )


def test_planner_abstains_on_a_cycle_in_the_materialized_state_path():
    assert (
        plan_residual_entry_bridge(
            evidence=_evidence(),
            initial_state=0xABB95547,
            routing_nodes=(
                StateRoutingNode(0x120, 0x12C, 4, 0xBB2D365, 0x900, 0x140),
                StateRoutingNode(0x140, 0x14C, 5, 0xBB2D365, 0xA00, 0x120),
            ),
            live_state_targets={0xA0716E5B: 0xC261},
            residual_state_targets={0xEC71CA67: 0xB9A6},
        )
        is None
    )


def test_planner_requires_room_for_replayed_predicate_prefix():
    assert (
        plan_residual_entry_bridge(
            evidence=_evidence(),
            initial_state=0xABB95547,
            routing_nodes=(StateRoutingNode(0x120, 0x12F, 4, 0xBB2D365, 0x900, 0xA00),),
            live_state_targets={0xA0716E5B: 0xC261},
            residual_state_targets={0xEC71CA67: 0xB9A6},
            required_patch_size=16,
        )
        is None
    )
