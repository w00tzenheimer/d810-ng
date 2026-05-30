from __future__ import annotations

from types import SimpleNamespace

from d810.transforms.dispatcher_residue_cleanup_planning import (
    plan_dispatcher_residue_cleanup,
    plan_unreachable_region_cleanup,
)


def test_plan_dispatcher_residue_cleanup_uses_structural_recon_facts() -> None:
    facts = SimpleNamespace(
        dispatcher_serial=2,
        one_way_predecessors=(10,),
        two_way_predecessors=(
            SimpleNamespace(
                block_serial=11,
                keep_successor=20,
                successors=(2, 20),
            ),
        ),
        dispatcher_outgoing_successors=(3, 4),
    )

    plan = plan_dispatcher_residue_cleanup(facts)

    assert plan.dispatcher_serial == 2
    assert plan.one_way_edge_severs == (10,)
    assert plan.two_way_conversions[0].block_serial == 11
    assert plan.two_way_conversions[0].keep_successor == 20
    assert plan.expected_handler_edge_changes == 2


def test_plan_unreachable_region_cleanup_uses_structural_recon_facts() -> None:
    facts = SimpleNamespace(
        stop_serial=9,
        cleanup_candidates=frozenset({4, 5}),
        blocks=(
            SimpleNamespace(block_serial=4, successors=(5,)),
            SimpleNamespace(block_serial=5, successors=(4,)),
        ),
        forward_redirects=(
            SimpleNamespace(block_serial=4, old_target=5, new_target=9),
        ),
    )

    plan = plan_unreachable_region_cleanup(facts)

    assert plan.cleanup_candidates == frozenset({4, 5})
    assert [block.block_serial for block in plan.blocks] == [4, 5]
    assert plan.forward_redirects[0].old_target == 5
    assert plan.forward_redirects[0].new_target == 9
