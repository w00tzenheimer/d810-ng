from d810.transforms.exit_transition_planning import (
    ExitRedirectAttempt,
    plan_exit_redirects,
)


class TestPlanExitRedirects:
    def test_accepts_oneway_goto_redirect(self):
        selection = plan_exit_redirects(
            (
                ExitRedirectAttempt(
                    source_block=10,
                    target_entry=30,
                    state_value=0xAA,
                    discovery_kind="write",
                ),
            ),
            block_nsucc_map={10: 1},
            block_succ_map={10: (20,)},
            condition_chain_blocks=set(),
            dispatcher_region={20},
            owned_blocks=set(),
            emitted=set(),
            claimed_1way={},
        )

        assert len(selection.accepted) == 1
        decision = selection.accepted[0]
        assert decision.redirect_kind == "goto"
        assert decision.source_block == 10
        assert decision.target_entry == 30
        assert selection.claimed_1way == {10: 30}

    def test_accepts_two_way_edge_redirect_using_condition_chain_old_target(self):
        selection = plan_exit_redirects(
            (
                ExitRedirectAttempt(
                    source_block=10,
                    target_entry=30,
                    state_value=0xAA,
                    discovery_kind="condition_chain_walk",
                ),
            ),
            block_nsucc_map={10: 2},
            block_succ_map={10: (21, 22)},
            condition_chain_blocks={21},
            dispatcher_region={21, 22},
            owned_blocks=set(),
            emitted=set(),
            claimed_1way={},
        )

        assert len(selection.accepted) == 1
        decision = selection.accepted[0]
        assert decision.redirect_kind == "edge"
        assert decision.old_target == 21

    def test_skips_two_way_when_old_target_cannot_be_resolved(self):
        selection = plan_exit_redirects(
            (
                ExitRedirectAttempt(
                    source_block=10,
                    target_entry=30,
                    state_value=0xAA,
                ),
            ),
            block_nsucc_map={10: 2},
            block_succ_map={10: (30,)},
            condition_chain_blocks=set(),
            dispatcher_region=set(),
            owned_blocks={30},
            emitted=set(),
            claimed_1way={},
        )

        assert selection.accepted == ()

    def test_target_allowlist_filters_and_updates_remaining_targets(self):
        selection = plan_exit_redirects(
            (
                ExitRedirectAttempt(source_block=10, target_entry=30, state_value=1),
                ExitRedirectAttempt(source_block=11, target_entry=31, state_value=2),
            ),
            block_nsucc_map={10: 1, 11: 1},
            block_succ_map={10: (20,), 11: (21,)},
            condition_chain_blocks=set(),
            dispatcher_region={20, 21},
            owned_blocks=set(),
            emitted=set(),
            claimed_1way={},
            target_allowlist={31},
        )

        assert [d.target_entry for d in selection.accepted] == [31]
        assert selection.remaining_targets == frozenset()

    def test_skip_owned_sources_only_when_requested(self):
        attempt = ExitRedirectAttempt(source_block=10, target_entry=30, state_value=1)

        rejected = plan_exit_redirects(
            (attempt,),
            block_nsucc_map={10: 1},
            block_succ_map={10: (20,)},
            condition_chain_blocks=set(),
            dispatcher_region={20},
            owned_blocks={10},
            emitted=set(),
            claimed_1way={},
            skip_owned_sources=True,
        )
        accepted = plan_exit_redirects(
            (attempt,),
            block_nsucc_map={10: 1},
            block_succ_map={10: (20,)},
            condition_chain_blocks=set(),
            dispatcher_region={20},
            owned_blocks={10},
            emitted=set(),
            claimed_1way={},
            skip_owned_sources=False,
        )

        assert rejected.accepted == ()
        assert len(accepted.accepted) == 1
