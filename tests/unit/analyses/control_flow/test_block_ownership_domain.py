"""Tests for the block-ownership forward fixpoint (owner-set domain).

The owner-set domain answers "which handler region(s) own each block" -- the
companion to the state-value dispatcher discovery (which answers "which
state(s) a block holds").  Together they let ``read_dag_from`` project a
``LinearizedStateDag`` as a read-off of two fixpoints rather than the
anchor/corridor/supplemental heuristics.

These tests pin the correctness invariants (spec §8):

* dispatcher-KILL -- the handler->dispatcher->handler back-edges must NOT make
  every block owned by every handler;
* shared epilogue -- a tail block two handlers fall into is owned by both;
* infrastructure -- the dispatcher head and condition-chain compare blocks are owned by
  nobody (``frozenset()``);
* range-backed -- a handler reached for a multi-constant range is still ONE
  owner;
* determinism -- the read-off is sorted and set-valued (no duplicates).
"""
from __future__ import annotations

from d810.analyses.control_flow.block_ownership_domain import (
    analyze_block_ownership,
    block_owners,
    exclusive_blocks,
    owned_blocks,
    shared_suffix_blocks,
)


def _pred_of(succ: dict[int, list[int]]) -> dict[int, list[int]]:
    pred: dict[int, list[int]] = {n: [] for n in succ}
    for src, dsts in succ.items():
        for dst in dsts:
            pred[dst].append(src)
    return pred


# --- canonical dispatcher: two exact handlers sharing one epilogue ----------
#   1  dispatcher head           -> 2
#   2  condition-chain compare (s == K1?)    -> 10 (h1) | 20 (h2)
#   10 h1 entry -> 11 -> 30
#   20 h2 entry -> 21 -> 30
#   30 shared epilogue           -> 1   (back-edge to the dispatcher head)
_SUCC = {1: [2], 2: [10, 20], 10: [11], 11: [30], 20: [21], 21: [30], 30: [1]}
_PRED = _pred_of(_SUCC)
_HANDLER_ENTRIES = {10, 20}
_DISPATCHER_REGION = {1, 2}


def _analyze():
    return analyze_block_ownership(
        nodes=list(_SUCC),
        successors_of=lambda n: _SUCC.get(int(n), ()),
        predecessors_of=lambda n: _PRED.get(int(n), ()),
        handler_entries=_HANDLER_ENTRIES,
        dispatcher_region=_DISPATCHER_REGION,
    )


def test_fixpoint_converges():
    assert _analyze().converged is True


def test_dispatcher_and_condition_chain_blocks_owned_by_nobody():
    # §8 Infrastructure: dispatcher head + condition-chain compare own no handler region.
    # NB: the dispatcher's IN-state is the back-edge fan-in of *every* handler;
    # only the OUT-state (post-KILL) reads as empty -- this is why the read-off
    # is over out_states.
    owners = block_owners(_analyze())
    assert owners[1] == frozenset()
    assert owners[2] == frozenset()


def test_handler_entry_owns_itself():
    # The IN-vs-OUT discriminator: a handler entry's IN arrives empty from the
    # killed dispatcher; only the GEN (in the OUT-state) makes it own itself.
    owners = block_owners(_analyze())
    assert owners[10] == frozenset({10})
    assert owners[20] == frozenset({20})


def test_dispatcher_kill_prevents_cross_handler_ownership():
    # §8 Dispatcher-KILL invariant: the 30 -> 1 back-edge must NOT make h1's
    # body reachable-from-h2.  Without the KILL every block would own {10, 20}.
    owners = block_owners(_analyze())
    assert owners[11] == frozenset({10})  # h1 body, h1 only
    assert owners[21] == frozenset({20})  # h2 body, h2 only
    assert 11 not in owned_blocks(owners, 20)
    assert 21 not in owned_blocks(owners, 10)


def test_shared_epilogue_is_shared_suffix_not_exclusive():
    # §8 Shared epilogue: block 30 falls in from BOTH handlers.
    owners = block_owners(_analyze())
    assert owners[30] == frozenset({10, 20})
    assert 30 in shared_suffix_blocks(owners, 10)
    assert 30 in shared_suffix_blocks(owners, 20)
    assert 30 not in exclusive_blocks(owners, 10)
    assert 30 not in exclusive_blocks(owners, 20)


def test_exclusive_blocks_are_the_private_region():
    owners = block_owners(_analyze())
    assert exclusive_blocks(owners, 10) == [10, 11]
    assert exclusive_blocks(owners, 20) == [20, 21]


def test_owned_blocks_sorted_and_complete():
    # §8 Determinism: owned_blocks is sorted; set-valued so no duplicates.
    owners = block_owners(_analyze())
    assert owned_blocks(owners, 10) == [10, 11, 30]
    assert owned_blocks(owners, 20) == [20, 21, 30]


# --- range-routed handler: two states fall through to ONE handler -----------
#   1 head -> 2
#   2 compare s == K2 -> 20 | 3
#   3 compare s == K3 -> 20 | 99 (terminal return)
#   20 h_range -> 21 -> 1
_R_SUCC = {1: [2], 2: [20, 3], 3: [20, 99], 20: [21], 21: [1], 99: []}
_R_PRED = _pred_of(_R_SUCC)


def test_range_routed_handler_has_single_owner():
    # §8 Range-backed: a handler reached for {K2, K3} is still ONE owner.
    result = analyze_block_ownership(
        nodes=list(_R_SUCC),
        successors_of=lambda n: _R_SUCC.get(int(n), ()),
        predecessors_of=lambda n: _R_PRED.get(int(n), ()),
        handler_entries={20},
        dispatcher_region={1, 2, 3},
    )
    owners = block_owners(result)
    assert owned_blocks(owners, 20) == [20, 21]
    assert owners[20] == frozenset({20})
    assert owners[99] == frozenset()  # terminal return, no handler owns it
