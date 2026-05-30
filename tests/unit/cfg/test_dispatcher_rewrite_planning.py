from d810.transforms.dispatcher_rewrite_planning import (
    DispatcherPredecessorRewriteInput,
    plan_dispatcher_predecessor_rewrite,
)
from d810.transforms.graph_modification import (
    ConvertToGoto,
    CreateConditionalRedirect,
    InsertBlock,
    RedirectGoto,
)


def test_plans_insert_block_for_safe_side_effects() -> None:
    decision = plan_dispatcher_predecessor_rewrite(
        DispatcherPredecessorRewriteInput(
            source_serial=9,
            source_nsucc=1,
            source_old_target=4,
            source_is_conditional=False,
            target_serial=1,
            target_nsucc=1,
            target_is_conditional=False,
            safe_copy_instructions=("snap:safe",),
            raw_side_effect_count=1,
            safe_side_effect_count=1,
        )
    )

    assert decision.blocker is None
    assert decision.modifications == (
        InsertBlock(
            pred_serial=9,
            succ_serial=1,
            instructions=("snap:safe",),
            old_target_serial=4,
        ),
    )


def test_defers_safe_side_effects_at_early_maturity() -> None:
    decision = plan_dispatcher_predecessor_rewrite(
        DispatcherPredecessorRewriteInput(
            source_serial=9,
            source_nsucc=1,
            source_old_target=4,
            source_is_conditional=False,
            target_serial=1,
            target_nsucc=1,
            target_is_conditional=False,
            safe_copy_instructions=("snap:safe",),
            raw_side_effect_count=1,
            safe_side_effect_count=1,
            defer_side_effects=True,
        )
    )

    assert decision.modifications == ()
    assert decision.blocker == "dispatcher_side_effects_deferred_to_later_maturity"
    assert decision.defer_side_effects is True


def test_plans_conditional_target_clone_when_requested() -> None:
    decision = plan_dispatcher_predecessor_rewrite(
        DispatcherPredecessorRewriteInput(
            source_serial=9,
            source_nsucc=1,
            source_old_target=4,
            source_is_conditional=False,
            target_serial=1,
            target_nsucc=2,
            target_is_conditional=True,
            target_conditional_target=2,
            target_fallthrough_target=3,
            clone_conditional_targets=True,
        )
    )

    assert decision.blocker is None
    assert decision.modifications == (
        CreateConditionalRedirect(
            source_block=9,
            ref_block=1,
            conditional_target=2,
            fallthrough_target=3,
        ),
    )


def test_plans_simple_redirect_for_one_way_source() -> None:
    decision = plan_dispatcher_predecessor_rewrite(
        DispatcherPredecessorRewriteInput(
            source_serial=9,
            source_nsucc=1,
            source_old_target=4,
            source_is_conditional=False,
            target_serial=1,
            target_nsucc=1,
            target_is_conditional=False,
        )
    )

    assert decision.modifications == (
        RedirectGoto(from_serial=9, old_target=4, new_target=1),
    )


def test_plans_convert_to_goto_for_conditional_source() -> None:
    decision = plan_dispatcher_predecessor_rewrite(
        DispatcherPredecessorRewriteInput(
            source_serial=9,
            source_nsucc=2,
            source_old_target=None,
            source_is_conditional=True,
            target_serial=1,
            target_nsucc=1,
            target_is_conditional=False,
        )
    )

    assert decision.modifications == (
        ConvertToGoto(block_serial=9, goto_target=1),
    )


def test_blocks_unsafe_side_effects() -> None:
    decision = plan_dispatcher_predecessor_rewrite(
        DispatcherPredecessorRewriteInput(
            source_serial=9,
            source_nsucc=1,
            source_old_target=4,
            source_is_conditional=False,
            target_serial=1,
            target_nsucc=1,
            target_is_conditional=False,
            raw_side_effect_count=1,
            safe_side_effect_count=0,
        )
    )

    assert decision.modifications == ()
    assert decision.blocker == "dispatcher_side_effects_not_dependency_safe"
