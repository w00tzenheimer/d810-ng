from __future__ import annotations

from d810.transforms.residual_dispatcher_attempt_building import (
    ResidualGotoAttemptBuildContext,
    ResidualPredSplitAttemptBuildContext,
    ResidualPrefixAttemptBuildContext,
    build_residual_goto_attempt,
    build_residual_pred_split_attempt,
    build_residual_prefix_attempt,
)


class TestResidualDispatcherAttemptBuilding:
    def test_builds_prefix_attempt_with_branch_and_peel_contexts(self):
        attempt = build_residual_prefix_attempt(
            ResidualPrefixAttemptBuildContext(
                via_pred=10,
                prefix_target=22,
                claimed_branch_target=22,
                owned_transition=(0x1234, 0x5678),
                edge_kind_name="transition",
                is_conditional_branch_source=True,
                branch_source=8,
                source_block=14,
                branch_succs=(14, 30),
                old_target=14,
                ordered_path=(8, 10, 14),
                dispatcher_serial=6,
                bst_node_blocks=frozenset({2, 4}),
                target_reaches_branch=False,
                via_pred_succs=(14, 18),
                target_reaches_pred=False,
                already_emitted=False,
                existing_target=None,
                via_pred_succ_count=2,
            )
        )

        assert attempt.via_pred == 10
        assert attempt.prefix_target == 22
        assert attempt.branch_context is not None
        assert attempt.branch_context.branch_source == 8
        assert attempt.peel_context is not None
        assert attempt.peel_context.peel_context.via_pred == 10

    def test_builds_pred_split_attempt(self):
        attempt = build_residual_pred_split_attempt(
            ResidualPredSplitAttemptBuildContext(
                via_pred=10,
                target_entry=18,
                state_value=0x1111,
                source_block=14,
                dispatcher_serial=6,
                bst_node_blocks=frozenset({2}),
                valid_pair=True,
                target_reaches_via_pred=False,
                already_emitted=False,
            )
        )

        assert attempt.via_pred == 10
        assert attempt.target_entry == 18
        assert attempt.context.valid_pair
        assert attempt.context.dispatcher_serial == 6

    def test_builds_goto_attempt(self):
        attempt = build_residual_goto_attempt(
            ResidualGotoAttemptBuildContext(
                target_entry=18,
                state_value=0x1234,
                source_block=14,
                dispatcher_serial=6,
                bst_node_blocks=frozenset({2}),
                allow_family_fallback_tail=True,
                is_shared_suffix_conditional_tail=False,
                has_prior_branch_cut=False,
                target_reaches_source=False,
                already_emitted=False,
                live_oneway_noop=False,
            )
        )

        assert attempt.target_entry == 18
        assert attempt.state_value == 0x1234
        assert attempt.context.allow_family_fallback_tail
        assert attempt.context.dispatcher_serial == 6
