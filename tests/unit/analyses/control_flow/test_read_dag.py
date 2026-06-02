"""Tests for read_dag_from: the portable LinearizedStateDag node read-off.

``read_dag_from`` projects one canonical ``StateDagNode`` per handler as a
read-off of two fixpoints -- the dispatcher discovery (``DispatcherView``:
key/kind) x the block-ownership fixpoint (owned/exclusive/shared_suffix) --
reusing the canonical types.  It is the portable replacement for the live
``build_live_linearized_state_dag_from_graph`` node construction.

This first increment pins the node projection; local segment/edge structure and
outer transition edges land next.
"""
from __future__ import annotations

from d810.analyses.control_flow.block_ownership_domain import analyze_block_ownership
from d810.analyses.control_flow.dispatcher_discovery_fixpoint import DispatcherView
from d810.analyses.control_flow.linearized_state_dag import (
    LocalEdgeKind,
    LocalSegmentKind,
    SemanticEdgeKind,
    StateNodeKind,
)
from d810.analyses.control_flow.read_dag import read_dag_from
from d810.analyses.control_flow.transition_builder import (
    StateHandler,
    StateTransition,
    TransitionResult,
)

K1, K2, K3 = 0x10000001, 0x10000002, 0x10000003

# h1=10 (exact K1); h_range=20 (range {K2,K3}); shared suffix 30; head=1, compare=2
_SUCC = {1: [2], 2: [10, 20], 10: [30], 20: [30], 30: [1]}
_PRED: dict[int, list[int]] = {n: [] for n in _SUCC}
for _p, _ss in _SUCC.items():
    for _s in _ss:
        _PRED[_s].append(_p)


def _owner_result():
    return analyze_block_ownership(
        nodes=list(_SUCC),
        successors_of=lambda n: _SUCC.get(int(n), ()),
        predecessors_of=lambda n: _PRED.get(int(n), ()),
        handler_entries={10, 20},
        dispatcher_region={1, 2},
    )


def _view():
    return DispatcherView(
        handler_entry_by_state={K1: 10, K2: 20},
        handler_range_map={20: (K2, K3)},
        bst_node_blocks=frozenset({2}),
        dispatcher_entry=1,
        result=None,
    )


def _dag():
    return read_dag_from(
        view=_view(), owner_result=_owner_result(), dispatcher_entry_serial=1
    )


def test_one_node_per_handler():
    assert {n.handler_serial for n in _dag().nodes} == {10, 20}


def test_exact_handler_node_key_and_kind():
    node = next(n for n in _dag().nodes if n.handler_serial == 10)
    assert node.kind is StateNodeKind.EXACT
    assert node.key.state_const == K1
    assert node.key.range_lo is None and node.key.range_hi is None


def test_range_handler_node_key_and_kind():
    node = next(n for n in _dag().nodes if n.handler_serial == 20)
    assert node.kind is StateNodeKind.RANGE_BACKED
    assert node.key.range_lo == K2 and node.key.range_hi == K3


def test_owner_set_fields_are_read_off():
    nodes = {n.handler_serial: n for n in _dag().nodes}
    # block 30 is the shared epilogue (owned by both 10 and 20).
    assert nodes[10].owned_blocks == (10, 30)
    assert nodes[10].exclusive_blocks == (10,)
    assert nodes[10].shared_suffix_blocks == (30,)
    assert nodes[20].owned_blocks == (20, 30)
    assert nodes[20].exclusive_blocks == (20,)
    assert nodes[20].shared_suffix_blocks == (30,)


def test_nodes_sorted_by_handler_serial():
    serials = [n.handler_serial for n in _dag().nodes]
    assert serials == sorted(serials)


def test_container_carries_dispatcher_and_bst_blocks():
    dag = _dag()
    assert dag.dispatcher_entry_serial == 1
    assert dag.bst_node_blocks == (2,)


def test_local_structure_populated_when_topology_provided():
    dag = read_dag_from(
        view=_view(),
        owner_result=_owner_result(),
        successors_of=lambda n: _SUCC.get(int(n), ()),
        predecessors_of=lambda n: _PRED.get(int(n), ()),
        dispatcher_entry_serial=1,
    )
    node10 = next(n for n in dag.nodes if n.handler_serial == 10)
    # owned = (10, 30); 30 is the shared epilogue.
    assert {s.segment_id for s in node10.local_segments} == {"blk[10]", "blk[30]"}
    kinds = {s.segment_id: s.kind for s in node10.local_segments}
    assert kinds["blk[30]"] is LocalSegmentKind.SHARED_SUFFIX
    e = {(x.source_segment_id, x.target_segment_id, x.kind) for x in node10.local_edges}
    assert ("blk[10]", "blk[30]", LocalEdgeKind.SHARED_SUFFIX) in e


def test_outer_transition_edge_from_transition_result():
    # h1 (state K1) transitions to h_range (state K2).
    tr = TransitionResult(
        transitions=[StateTransition(from_state=K1, to_state=K2, from_block=10)]
    )
    dag = read_dag_from(
        view=_view(), owner_result=_owner_result(), transitions=tr, dispatcher_entry_serial=1
    )
    assert len(dag.edges) == 1
    edge = dag.edges[0]
    assert edge.kind is SemanticEdgeKind.TRANSITION
    assert edge.source_key.handler_serial == 10  # state K1 -> handler 10
    assert edge.target_key.handler_serial == 20  # state K2 -> handler 20
    assert edge.target_state == K2
    assert edge.source_anchor.block_serial == 10


def test_state_level_expansion_from_transition_handlers():
    # The spine needs one node per ROUTED STATE (the legacy's 103 state-level nodes),
    # not just per exact handler.  When the transition result's handler map covers
    # more states than handler_entry_by_state (here K1 AND K2 both route to handler
    # block 10), read_dag_from expands to one node per state, sharing the handler's
    # owner-set region -- so the edge set can cover ALL transitions.
    view = DispatcherView(
        handler_entry_by_state={K1: 10},
        handler_range_map={},
        bst_node_blocks=frozenset({2}),
        dispatcher_entry=1,
        result=None,
    )
    tr = TransitionResult(
        transitions=[StateTransition(from_state=K1, to_state=K2, from_block=10)],
        handlers={
            K1: StateHandler(state_value=K1, check_block=10, handler_blocks=[10]),
            K2: StateHandler(state_value=K2, check_block=10, handler_blocks=[10]),
        },
    )
    dag = read_dag_from(view=view, owner_result=_owner_result(), transitions=tr)
    # two state-level nodes, both routing to handler block 10
    assert len(dag.nodes) == 2
    assert sorted(n.key.state_const for n in dag.nodes) == [K1, K2]
    assert all(n.handler_serial == 10 for n in dag.nodes)
    # both share handler 10's owner-set region
    assert dag.nodes[0].owned_blocks == dag.nodes[1].owned_blocks
    # the K1 -> K2 transition is now an edge (both states are mapped)
    assert any(e.target_state == K2 for e in dag.edges)


def test_conditional_transition_edge_kind():
    tr = TransitionResult(
        transitions=[
            StateTransition(
                from_state=K1,
                to_state=K2,
                from_block=10,
                condition_block=10,
                is_conditional=True,
            )
        ]
    )
    dag = read_dag_from(view=_view(), owner_result=_owner_result(), transitions=tr)
    assert dag.edges[0].kind is SemanticEdgeKind.CONDITIONAL_TRANSITION
    assert dag.edges[0].source_anchor.kind.name == "CONDITIONAL_BRANCH"


def test_conditional_arm_to_unmapped_state_is_conditional_return():
    # #3.2: a conditional arm whose to_state maps to no handler node is a
    # return/exit, not a transition.  Legacy (linearized_state_dag pass 2) emits
    # CONDITIONAL_RETURN with target=None / "RETURN" -- read_dag must match so the
    # read-off recovers the CONDITIONAL_RETURN edges (currently 0 vs legacy's many).
    unmapped = 0x10009999  # no handler in _view()
    tr = TransitionResult(
        transitions=[
            StateTransition(
                from_state=K1,
                to_state=unmapped,
                from_block=10,
                condition_block=10,
                is_conditional=True,
            )
        ]
    )
    dag = read_dag_from(view=_view(), owner_result=_owner_result(), transitions=tr)
    edge = dag.edges[0]
    assert edge.kind is SemanticEdgeKind.CONDITIONAL_RETURN
    assert edge.target_key is None
    assert edge.target_state is None
    assert edge.target_label == "RETURN"
    assert edge.source_anchor.kind.name == "CONDITIONAL_BRANCH"


def test_conditional_arms_from_same_branch_get_distinct_branch_arms():
    # #3.2: two conditional transitions out of the same branch block are the two
    # arms of one fork; each edge carries a distinct branch_arm so lowering can
    # target the right successor (legacy keys edges by branch_arm).
    K4 = 0x10000004
    succ = {1: [2], 2: [10, 20, 40], 10: [30], 20: [30], 40: [30], 30: [1]}
    pred: dict[int, list[int]] = {n: [] for n in succ}
    for _p, _ss in succ.items():
        for _s in _ss:
            pred[_s].append(_p)
    owner_result = analyze_block_ownership(
        nodes=list(succ),
        successors_of=lambda n: succ.get(int(n), ()),
        predecessors_of=lambda n: pred.get(int(n), ()),
        handler_entries={10, 20, 40},
        dispatcher_region={1, 2},
    )
    view = DispatcherView(
        handler_entry_by_state={K1: 10, K2: 20, K4: 40},
        handler_range_map={},
        bst_node_blocks=frozenset({2}),
        dispatcher_entry=1,
        result=None,
    )
    tr = TransitionResult(
        transitions=[
            StateTransition(from_state=K1, to_state=K2, from_block=10,
                            condition_block=10, is_conditional=True),
            StateTransition(from_state=K1, to_state=K4, from_block=10,
                            condition_block=10, is_conditional=True),
        ]
    )
    dag = read_dag_from(view=view, owner_result=owner_result, transitions=tr)
    cond_edges = [
        e for e in dag.edges if e.kind is SemanticEdgeKind.CONDITIONAL_TRANSITION
    ]
    assert len(cond_edges) == 2
    assert {e.source_anchor.branch_arm for e in cond_edges} == {0, 1}


def test_conditional_edges_from_conds_emits_conditional_transition():
    # #3.2 (reuse): the legacy's path-derived ConditionalTransition (from
    # detect_conditional_transitions) -> a CONDITIONAL_TRANSITION edge keyed by
    # the branch block + arm, target resolved via the state node set.
    from d810.analyses.control_flow.read_dag import _conditional_edges_from_conds
    from d810.analyses.control_flow.state_machine_analysis import (
        ConditionalTransition,
    )

    nodes = list(_dag().nodes)  # handler 10 (K1), handler 20 (K2)
    node_by_state = {
        int(n.key.state_const): n for n in nodes if n.key.state_const is not None
    }
    node_by_handler = {int(n.handler_serial): n for n in nodes}
    conds = {
        10: [
            ConditionalTransition(
                handler_entry=10,
                branch_block=5,
                target_state=K2,
                target_handler=None,
                state_write_block=6,
                state_write_ea=None,
                branch_arm=1,
            )
        ]
    }
    edges = _conditional_edges_from_conds(conds, node_by_handler, node_by_state)
    assert len(edges) == 1
    e = edges[0]
    assert e.kind is SemanticEdgeKind.CONDITIONAL_TRANSITION
    assert e.source_key.handler_serial == 10
    assert e.target_key.handler_serial == 20
    assert e.target_state == K2
    assert e.source_anchor.block_serial == 5
    assert e.source_anchor.branch_arm == 1


def test_conditional_edges_from_conds_emits_conditional_return_for_terminal():
    # A terminal conditional arm (is_terminal_no_write) -> CONDITIONAL_RETURN with
    # target=None / "RETURN" (the legacy pass-2 terminal branch).
    from d810.analyses.control_flow.read_dag import _conditional_edges_from_conds
    from d810.analyses.control_flow.state_machine_analysis import (
        ConditionalTransition,
    )

    nodes = list(_dag().nodes)
    node_by_state = {
        int(n.key.state_const): n for n in nodes if n.key.state_const is not None
    }
    node_by_handler = {int(n.handler_serial): n for n in nodes}
    conds = {
        10: [
            ConditionalTransition(
                handler_entry=10,
                branch_block=7,
                target_state=0xDEAD,
                target_handler=None,
                state_write_block=None,
                state_write_ea=None,
                branch_arm=0,
                is_terminal_no_write=True,
            )
        ]
    }
    edges = _conditional_edges_from_conds(conds, node_by_handler, node_by_state)
    assert len(edges) == 1
    e = edges[0]
    assert e.kind is SemanticEdgeKind.CONDITIONAL_RETURN
    assert e.target_key is None
    assert e.target_state is None
    assert e.target_label == "RETURN"


def test_injected_conds_by_handler_produce_conditional_edges():
    # #3.2 (reuse-now): conds discovered with the live mba at the call site are
    # injected into read_dag as portable data; read_dag projects them to edges.
    from d810.analyses.control_flow.state_machine_analysis import (
        ConditionalTransition,
    )

    conds = {
        10: [
            ConditionalTransition(
                handler_entry=10,
                branch_block=5,
                target_state=K2,
                target_handler=None,
                state_write_block=6,
                state_write_ea=None,
                branch_arm=1,
            )
        ]
    }
    dag = read_dag_from(
        view=_view(),
        owner_result=_owner_result(),
        conds_by_handler=conds,
        dispatcher_entry_serial=1,
    )
    cond = [e for e in dag.edges if e.kind is SemanticEdgeKind.CONDITIONAL_TRANSITION]
    assert len(cond) == 1
    assert cond[0].source_key.handler_serial == 10
    assert cond[0].target_key.handler_serial == 20
    assert cond[0].source_anchor.branch_arm == 1
