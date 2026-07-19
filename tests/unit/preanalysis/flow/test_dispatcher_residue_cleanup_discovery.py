from __future__ import annotations

from d810.analyses.control_flow.dispatcher_residue_cleanup_discovery import (
    discover_dispatcher_residue_cleanup_facts,
    discover_unreachable_region_cleanup_facts,
)
from d810.ir.flowgraph import BlockSnapshot, FlowGraph


def _fg(blocks: dict[int, tuple[tuple[int, ...], tuple[int, ...]]]) -> FlowGraph:
    """Build a portable FlowGraph from ``{serial: (succs, preds)}`` specs.

    Topology only (no instructions). Predecessors are taken verbatim — these
    fixtures intentionally use preds that are not the inverse of succs to
    exercise the dispatcher-component backward walk.
    """
    snapshots = {
        serial: BlockSnapshot(
            serial=serial,
            block_type=0,
            succs=tuple(succs),
            preds=tuple(preds),
            flags=0,
            start_ea=0,
            insn_snapshots=(),
        )
        for serial, (succs, preds) in blocks.items()
    }
    return FlowGraph(blocks=snapshots, entry_serial=0, func_ea=0)


def test_dispatcher_residue_cleanup_discovery_classifies_dispatcher_edges() -> None:
    fg = _fg(
        {
            0: ((10,), ()),
            2: ((3, 4), (10, 11, 3)),
            3: ((2,), ()),
            4: ((), ()),
            10: ((2,), ()),
            11: ((2, 20), ()),
            20: ((), ()),
        }
    )

    facts = discover_dispatcher_residue_cleanup_facts(
        fg,
        dispatcher_region={3},
        dispatcher_serial=2,
    )

    assert facts.dispatcher_region == frozenset({2, 3})
    assert facts.one_way_predecessors == (10,)
    assert len(facts.two_way_predecessors) == 1
    assert facts.two_way_predecessors[0].block_serial == 11
    assert facts.two_way_predecessors[0].keep_successor == 20
    assert facts.dispatcher_outgoing_successors == (3, 4)


def test_unreachable_soft_kill_discovery_preserves_reconstruction_live() -> None:
    fg = _fg(
        {
            0: ((1,), ()),
            1: ((7,), (0,)),
            2: ((3,), (4,)),
            3: ((), (2,)),
            4: ((5,), ()),
            5: ((4,), ()),
            6: ((5,), ()),
            7: ((), (1,)),
        }
    )

    facts = discover_unreachable_region_cleanup_facts(
        fg,
        dispatcher_serial=2,
        dispatcher_region={2, 3},
        stop_serial=7,
        reconstruction_live={6},
    )

    assert facts.reachable == frozenset({0, 1, 7})
    assert facts.protected == frozenset({4, 5, 6})
    assert facts.cleanup_candidates == frozenset({2, 3})
    assert [block.block_serial for block in facts.blocks] == [2]
    assert [(r.block_serial, r.old_target, r.new_target) for r in facts.forward_redirects] == [
        (2, 3, 7),
    ]


def test_unreachable_soft_kill_discovery_emits_dead_zone_redirects() -> None:
    fg = _fg(
        {
            0: ((1,), ()),
            1: ((6,), (0,)),
            2: ((3,), (4,)),
            3: ((), (2,)),
            4: ((5,), ()),
            5: ((4,), ()),
            6: ((), (1,)),
        }
    )

    facts = discover_unreachable_region_cleanup_facts(
        fg,
        dispatcher_serial=2,
        dispatcher_region={2, 3},
        stop_serial=6,
    )

    assert facts.cleanup_candidates == frozenset({2, 3, 4, 5})
    assert (4, 5, 6) in {
        (redirect.block_serial, redirect.old_target, redirect.new_target)
        for redirect in facts.forward_redirects
    }
    assert (5, 4, 6) in {
        (redirect.block_serial, redirect.old_target, redirect.new_target)
        for redirect in facts.forward_redirects
    }


def test_unreachable_region_cleanup_uses_bound_stop_serial() -> None:
    fg = _fg(
        {
            0: ((1,), ()),
            1: ((4,), (0,)),
            2: ((3,), (5,)),
            3: ((), (2,)),
            4: ((), (1,)),
            5: ((2,), ()),
            6: ((3,), ()),
        }
    )

    facts = discover_unreachable_region_cleanup_facts(
        fg,
        dispatcher_serial=2,
        dispatcher_region={2, 3},
        stop_serial=4,
    )

    assert 4 not in facts.cleanup_candidates
    assert 6 in facts.cleanup_candidates
    assert (6, 3, 4) in {
        (redirect.block_serial, redirect.old_target, redirect.new_target)
        for redirect in facts.forward_redirects
    }
