from __future__ import annotations

from d810.transforms.dispatcher_backedge_disconnect_planning import (
    DispatcherBackedgeDisconnectPlan,
    plan_dispatcher_backedge_disconnects,
)


def test_plan_dispatcher_backedge_disconnects_skips_already_redirected_sources() -> None:
    plans = plan_dispatcher_backedge_disconnects(
        block_nsucc_map={2: 0, 10: 2, 11: 2},
        block_succ_map={10: (2, 30), 11: (31, 2)},
        dispatcher_serial=2,
        condition_chain_blocks={10},
        emitted={(10, 30)},
    )

    assert plans == (
        DispatcherBackedgeDisconnectPlan(
            source_block=11,
            keep_target=31,
            is_condition_chain=False,
        ),
    )


def test_plan_dispatcher_backedge_disconnects_keeps_non_dispatcher_target() -> None:
    plans = plan_dispatcher_backedge_disconnects(
        block_nsucc_map={2: 0, 10: 2, 11: 2, 12: 1},
        block_succ_map={10: (2, 30), 11: (31, 2), 12: (2,)},
        dispatcher_serial=2,
        condition_chain_blocks={10},
        emitted=set(),
    )

    assert plans == (
        DispatcherBackedgeDisconnectPlan(
            source_block=10,
            keep_target=30,
            is_condition_chain=True,
        ),
        DispatcherBackedgeDisconnectPlan(
            source_block=11,
            keep_target=31,
            is_condition_chain=False,
        ),
    )
