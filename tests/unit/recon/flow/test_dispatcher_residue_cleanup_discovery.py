from __future__ import annotations

from d810.analyses.control_flow.dispatcher_residue_cleanup_discovery import (
    discover_dispatcher_residue_cleanup_facts,
    discover_unreachable_region_cleanup_facts,
)


class _Block:
    def __init__(
        self,
        serial: int,
        succs: tuple[int, ...] = (),
        preds: tuple[int, ...] = (),
    ) -> None:
        self.serial = serial
        self._succs = tuple(succs)
        self._preds = tuple(preds)

    def nsucc(self) -> int:
        return len(self._succs)

    def succ(self, index: int) -> int:
        return self._succs[index]

    def npred(self) -> int:
        return len(self._preds)

    def pred(self, index: int) -> int:
        return self._preds[index]


class _Mba:
    def __init__(self, blocks: dict[int, _Block]) -> None:
        self._blocks = dict(blocks)
        self.qty = max(blocks) + 1

    def get_mblock(self, serial: int) -> _Block | None:
        return self._blocks.get(serial)


def test_dispatcher_residue_cleanup_discovery_classifies_dispatcher_edges() -> None:
    mba = _Mba(
        {
            0: _Block(0, (10,)),
            2: _Block(2, (3, 4), (10, 11, 3)),
            3: _Block(3, (2,)),
            4: _Block(4),
            10: _Block(10, (2,)),
            11: _Block(11, (2, 20)),
            20: _Block(20),
        }
    )

    facts = discover_dispatcher_residue_cleanup_facts(
        mba,
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
    mba = _Mba(
        {
            0: _Block(0, (1,)),
            1: _Block(1, (7,), (0,)),
            2: _Block(2, (3,), (4,)),
            3: _Block(3, (), (2,)),
            4: _Block(4, (5,)),
            5: _Block(5, (4,)),
            6: _Block(6, (5,)),
            7: _Block(7, (), (1,)),
        }
    )

    facts = discover_unreachable_region_cleanup_facts(
        mba,
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
    mba = _Mba(
        {
            0: _Block(0, (1,)),
            1: _Block(1, (6,), (0,)),
            2: _Block(2, (3,), (4,)),
            3: _Block(3, (), (2,)),
            4: _Block(4, (5,)),
            5: _Block(5, (4,)),
            6: _Block(6, (), (1,)),
        }
    )

    facts = discover_unreachable_region_cleanup_facts(
        mba,
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
    mba = _Mba(
        {
            0: _Block(0, (1,)),
            1: _Block(1, (4,), (0,)),
            2: _Block(2, (3,), (5,)),
            3: _Block(3, (), (2,)),
            4: _Block(4, (), (1,)),
            5: _Block(5, (2,)),
            6: _Block(6, (3,)),
        }
    )

    facts = discover_unreachable_region_cleanup_facts(
        mba,
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
