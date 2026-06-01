"""The LiSA dispatcher discovery: a value-set fixpoint replaces the BST walk (no IDA).

Models a 3-state OLLVM equality-chain dispatcher and shows the dispatcher structure
(handler map, range-routed intermediate, loop header, transitions) falls out of the fixpoint.

CFG (state var ``s``, K1<K2<K3):
    0 entry -> 1
    1  if s==K1 -> 10 (h1) else 2        # BST comparison
    2  if s==K2 -> 20 (h2) else 3        # BST comparison
    3  if s==K3 -> 30 (h3) else 99       # BST comparison
    10 h1: s = K2 -> 1                    # transition K1->K2 (back-edge)
    20 h2: s = K3 -> 1                    # transition K2->K3 (back-edge)
    30 h3: (no write) -> 99              # terminal: K3 returns
    99 exit
"""
from __future__ import annotations

from d810.analyses.control_flow.state_transition_domain import (
    StateValue,
    recover_transition_result,
)
from d810.analyses.control_flow.dispatcher_discovery_fixpoint import (
    BstComparison,
    assume_state,
    discover_dispatcher,
)

K1, K2, K3 = 0x10000001, 0x10000002, 0x10000003

_SUCC = {0: [1], 1: [10, 2], 2: [20, 3], 3: [30, 99], 10: [1], 20: [1], 30: [99], 99: []}
_PRED: dict[int, list[int]] = {n: [] for n in _SUCC}
for _p, _ss in _SUCC.items():
    for _s in _ss:
        _PRED[_s].append(_p)

_STATE_WRITES = {10: StateValue.of(K2), 20: StateValue.of(K3)}
_COMPARISONS = {
    1: BstComparison(block=1, const=K1, eq_target=10, ne_target=2),
    2: BstComparison(block=2, const=K2, eq_target=20, ne_target=3),
    3: BstComparison(block=3, const=K3, eq_target=30, ne_target=99),
}


def _discover():
    return discover_dispatcher(
        nodes=_SUCC.keys(),
        entry_nodes=[0],
        successors_of=lambda n: _SUCC.get(int(n), ()),
        predecessors_of=lambda n: _PRED.get(int(n), ()),
        state_writes=_STATE_WRITES,
        comparisons=_COMPARISONS,
        entry_state=StateValue.of(K1),  # the recovered pre-header initial state
    )


# --- the assume primitive ---------------------------------------------------


def test_assume_equal_arm_collapses_to_singleton():
    cmp1 = _COMPARISONS[1]
    assert assume_state(StateValue.top(), cmp1, 10) == StateValue.of(K1)  # ⊤ ⊓ {K1}
    assert assume_state(StateValue.of_many([K1, K2]), cmp1, 10) == StateValue.of(K1)


def test_assume_notequal_arm_excludes():
    cmp1 = _COMPARISONS[1]
    assert assume_state(StateValue.of_many([K1, K2, K3]), cmp1, 2) == StateValue.of_many([K2, K3])
    assert assume_state(StateValue.top(), cmp1, 2).is_top  # ⊤ ∖ {K1} stays ⊤ (sound)


def test_assume_infeasible_arm_is_bottom():
    # state set {K3} hitting "s == K1" arm: K1 not possible here -> dead edge
    assert assume_state(StateValue.of(K3), _COMPARISONS[1], 10).is_bottom


# --- discovery (the BST walk replaced) --------------------------------------


def test_discovers_handler_entry_by_state():
    view = _discover()
    assert view.handler_entry_by_state == {K1: 10, K2: 20, K3: 30}


def test_discovers_loop_header_as_widest_join():
    view = _discover()
    # block 1 carries {K1,K2,K3} (entry ∪ both back-edges) -> the dispatcher head
    assert view.dispatcher_entry == 1


def test_discovers_range_routed_intermediate():
    view = _discover()
    # block 2 is reached with {K2,K3} (K1 already peeled off) -> RANGE_BACKED
    assert view.handler_range_map.get(2) == (K2, K3)
    assert 1 not in view.handler_range_map  # head is the dispatcher, not a handler


def test_bst_node_blocks_are_the_comparisons():
    assert _discover().bst_node_blocks == frozenset({1, 2, 3})


# --- transitions recovered from the same fixpoint ---------------------------


def test_transitions_fall_out_of_the_fixpoint():
    view = _discover()
    result = view.result
    tr = recover_transition_result(
        result=result,
        dispatcher_entry=view.dispatcher_entry,
        handler_entry_by_state=view.handler_entry_by_state,
        successors_of=lambda n: _SUCC.get(int(n), ()),
        predecessors_of=lambda n: _PRED.get(int(n), ()),
    )
    edges = {(t.from_state, t.to_state) for t in tr.transitions}
    assert (K1, K2) in edges  # h1 writes K2
    assert (K2, K3) in edges  # h2 writes K3
    # K3 is terminal (h3 has no write reaching the dispatcher back-edge) -> a return, not a transition
    assert not any(t.from_state == K3 for t in tr.transitions)
