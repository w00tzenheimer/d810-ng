"""Tests for the state-DAG -> block-CFG adapter.

The adapter projects a recovered :class:`LinearizedStateDag` back to a
block-granularity CFG the goto-free structurer can consume: handler blocks only
(no dispatcher/BST nodes), intra-handler edges from the base CFG restricted to
each handler's owned set, and inter-handler edges from the DAG's semantic
transitions. The synthetic graphs mirror the real sub_7FFD3338C040 shapes the
diag DB surfaced (shared-suffix fan-in, a forward-flowing range-backed node, an
EXIT_ROUTINE convergence corridor).
"""
from __future__ import annotations

from d810.analyses.control_flow.linearized_state_dag import (
    LinearizedStateDag,
    LocalSegmentKind,
    RedirectSourceKind,
    SemanticEdgeKind,
    StateDagEdge,
    StateDagNode,
    StateLocalSegment,
    StateNodeKind,
    StateRedirectAnchor,
)
from d810.analyses.control_flow.state_dag_cfg_adapter import (
    StateDagCfg,
    build_state_dag_cfg,
)
from d810.ir.state_dag_key import StateDagNodeKey


def _node(state, entry, owned, *, kind=StateNodeKind.EXACT):
    key = StateDagNodeKey(handler_serial=entry, state_const=state)
    return StateDagNode(
        key=key,
        kind=kind,
        state_label=f"STATE_{state:08X}",
        handler_serial=entry,
        entry_anchor=entry,
        owned_blocks=tuple(owned),
        exclusive_blocks=tuple(owned),
        shared_suffix_blocks=(),
        local_segments=(
            StateLocalSegment(
                segment_id=f"s{entry}",
                kind=LocalSegmentKind.STRAIGHT_LINE,
                blocks=tuple(owned),
            ),
        ),
        local_edges=(),
    )


def _edge(kind, src_state, tgt_state, src_block, tgt_entry, path):
    return StateDagEdge(
        kind=kind,
        source_key=StateDagNodeKey(handler_serial=src_block, state_const=src_state),
        target_key=(
            StateDagNodeKey(handler_serial=tgt_entry, state_const=tgt_state)
            if tgt_state is not None
            else None
        ),
        target_state=tgt_state,
        target_entry_anchor=tgt_entry,
        target_label=f"STATE_{tgt_state:08X}" if tgt_state is not None else "",
        source_anchor=StateRedirectAnchor(
            kind=RedirectSourceKind.UNCONDITIONAL, block_serial=src_block
        ),
        ordered_path=tuple(path),
    )


def _dag(nodes, edges, *, initial_state=None, dispatcher_entry=2):
    return LinearizedStateDag(
        dispatcher_entry_serial=dispatcher_entry,
        state_var_stkoff=0x64,
        pre_header_serial=None,
        initial_state=initial_state,
        bst_node_blocks=(),
        nodes=tuple(nodes),
        edges=tuple(edges),
    )


def test_intra_handler_edges_restricted_to_owned_set():
    # Node A owns {10, 11}; base CFG has 10->11 (intra) and 11->99 (dispatcher
    # round-trip, leaves the owned set -> dropped).
    dag = _dag([_node(0xA, 10, [10, 11])], [], initial_state=0xA)
    cfg = build_state_dag_cfg(dag, base_successors={10: (11,), 11: (99,)})
    assert isinstance(cfg, StateDagCfg)
    assert set(cfg.blocks) == {10, 11}
    assert cfg.successors(10) == (11,)
    assert cfg.successors(11) == ()  # 99 is not owned -> dropped (no dispatcher)
    assert cfg.entry_serial == 10


def test_transition_edge_replaces_dispatcher_round_trip():
    # A (owns 10,11) --TRANSITION block11->entry20--> B (owns 20). The base CFG
    # would send 11 into the dispatcher; the DAG edge rewires 11->20 directly.
    nodes = [_node(0xA, 10, [10, 11]), _node(0xB, 20, [20])]
    edges = [_edge(SemanticEdgeKind.TRANSITION, 0xA, 0xB, 11, 20, [10, 11])]
    cfg = build_state_dag_cfg(
        dag := _dag(nodes, edges, initial_state=0xA),
        base_successors={10: (11,), 11: (99,), 20: (99,)},
    )
    assert cfg.successors(11) == (20,)
    assert cfg.predecessors(20) == (11,)
    assert cfg.successors(20) == ()  # terminal
    assert dag.initial_state == 0xA


def test_conditional_transition_makes_two_way_branch():
    # Branch block 20 has two CONDITIONAL_TRANSITION arms -> 30 and -> 40.
    nodes = [_node(0xB, 20, [20]), _node(0xC, 30, [30]), _node(0xD, 40, [40])]
    edges = [
        _edge(SemanticEdgeKind.CONDITIONAL_TRANSITION, 0xB, 0xC, 20, 30, [20]),
        _edge(SemanticEdgeKind.CONDITIONAL_TRANSITION, 0xB, 0xD, 20, 40, [20]),
    ]
    cfg = build_state_dag_cfg(_dag(nodes, edges, initial_state=0xB), base_successors={})
    assert set(cfg.successors(20)) == {30, 40}
    assert cfg.get_block(20).nsucc == 2


def test_exit_routine_wires_corridor_to_terminal_return():
    # EXIT_ROUTINE wires its ordered_path corridor (20->224->225) with the tail
    # (225) left terminal -> the structurer emits the function return there.
    # UNKNOWN adds no forward edge (no spurious self-loop).
    nodes = [_node(0xB, 20, [20, 224, 225])]
    edges = [
        _edge(SemanticEdgeKind.EXIT_ROUTINE, 0xB, None, 20, None, [20, 224, 225]),
        _edge(SemanticEdgeKind.UNKNOWN, 0xB, 0xB, 20, 20, [20]),
    ]
    cfg = build_state_dag_cfg(_dag(nodes, edges, initial_state=0xB), base_successors={})
    assert cfg.successors(20) == (224,)
    assert cfg.successors(224) == (225,)
    assert cfg.successors(225) == ()  # corridor tail = terminal return


def test_exit_routine_tail_is_a_return_terminal():
    # The EXIT_ROUTINE corridor tail (225) is flagged as a genuine function
    # return; a dead-end block at a recovery gap is NOT.
    nodes = [_node(0xB, 20, [20, 224, 225]), _node(0xC, 30, [30])]
    edges = [
        _edge(SemanticEdgeKind.EXIT_ROUTINE, 0xB, None, 20, None, [20, 224, 225]),
        _edge(SemanticEdgeKind.TRANSITION, 0xC, 0xB, 30, 20, [30]),
    ]
    cfg = build_state_dag_cfg(_dag(nodes, edges, initial_state=0xC), base_successors={})
    assert cfg.return_terminals == frozenset({225})
    assert cfg.successors(225) == ()


def test_self_loop_transition_is_dropped():
    # A TRANSITION whose source state == target state is a recovery
    # unresolved/spin artifact; dropping it keeps the node a terminal instead of
    # a while(1) that terminates the chain (the sub_7FFD 0x139F2922 / blk136 case).
    nodes = [_node(0x139F2922, 136, [136])]
    edges = [_edge(SemanticEdgeKind.TRANSITION, 0x139F2922, 0x139F2922, 136, 136, [136])]
    cfg = build_state_dag_cfg(_dag(nodes, edges, initial_state=0x139F2922), base_successors={})
    assert cfg.successors(136) == ()  # no self-loop


def test_block_level_self_edge_dropped_when_target_state_none():
    # The enriched DAG's self-loop edges can carry target_state=None but resolve
    # via target_entry_anchor back to the source block (block 8). The state-level
    # guard (source_state==target_state) misses this; the block-level guard must
    # still drop the 8->8 self-edge so no spurious do/while is emitted.
    nodes = [_node(0x610BB4D9, 8, [8])]
    edge = StateDagEdge(
        kind=SemanticEdgeKind.TRANSITION,
        source_key=StateDagNodeKey(handler_serial=8, state_const=0x610BB4D9),
        target_key=None,
        target_state=None,
        target_entry_anchor=8,  # resolves back to the source block
        target_label="",
        source_anchor=StateRedirectAnchor(
            kind=RedirectSourceKind.UNCONDITIONAL, block_serial=8
        ),
        ordered_path=(8,),
    )
    cfg = build_state_dag_cfg(_dag(nodes, [edge], initial_state=0x610BB4D9), base_successors={})
    assert cfg.successors(8) == ()  # no 8->8 self-edge


def test_prefix_ordered_paths_build_internal_branch_chain():
    # sub_7FFD node 0x606DC166 (blk14) shape: nested prefix paths
    # [14,140] [14,140,141] [14,140,142] each transitioning to a different next
    # state. ordered_path chaining reconstructs the internal spine 14->140->141,
    # 140->142, with each tail connecting to its target handler entry.
    nodes = [
        _node(0x606DC166, 14, [14, 140, 141, 142]),
        _node(0xAA, 21, [21]),
        _node(0xBB, 211, [211]),
        _node(0xCC, 151, [151]),
    ]
    edges = [
        _edge(SemanticEdgeKind.TRANSITION, 0x606DC166, 0xAA, 140, 21, [14, 140]),
        _edge(SemanticEdgeKind.TRANSITION, 0x606DC166, 0xBB, 141, 211, [14, 140, 141]),
        _edge(SemanticEdgeKind.TRANSITION, 0x606DC166, 0xCC, 142, 151, [14, 140, 141, 142]),
    ]
    cfg = build_state_dag_cfg(_dag(nodes, edges, initial_state=0x606DC166), base_successors={})
    assert cfg.successors(14) == (140,)
    assert set(cfg.successors(140)) == {141, 21}   # continue or transition
    assert set(cfg.successors(141)) == {142, 211}
    assert set(cfg.successors(142)) == {151}


def test_shared_suffix_fan_in_converges_on_single_return():
    # Mirror sub_7FFD: three states each end in the shared return corridor
    # 224->225. Block-granularity dedup makes 225 a single fan-in terminal.
    nodes = [
        _node(0x1, 10, [10, 224, 225]),
        _node(0x2, 20, [20, 224, 225]),
        _node(0x3, 30, [30, 224, 225]),
    ]
    base = {
        10: (224,), 20: (224,), 30: (224,),
        224: (225,), 225: (),
    }
    cfg = build_state_dag_cfg(_dag(nodes, [], initial_state=0x1), base_successors=base)
    # 224 and 225 appear once (deduped), 225 is the sole terminal.
    assert {10, 20, 30, 224, 225} <= set(cfg.blocks)
    assert set(cfg.predecessors(224)) == {10, 20, 30}
    assert cfg.successors(224) == (225,)
    assert cfg.successors(225) == ()
    terminals = [s for s, b in cfg.blocks.items() if b.nsucc == 0]
    assert terminals == [225]


def test_range_backed_node_flows_forward_not_terminal():
    # The 0x298372CC leak case: a RANGE_BACKED node (entry 206, suffix 24) with a
    # forward TRANSITION (24->23). It must NOT be a terminal -> no spurious
    # `return 0x298372CC`.
    nodes = [
        _node(0x298372CC, 206, [206, 24], kind=StateNodeKind.RANGE_BACKED),
        _node(0x6465D165, 23, [23]),
    ]
    edges = [_edge(SemanticEdgeKind.TRANSITION, 0x298372CC, 0x6465D165, 24, 23, [206, 24])]
    cfg = build_state_dag_cfg(
        _dag(nodes, edges, initial_state=0x298372CC),
        base_successors={206: (24,), 24: (99,), 23: ()},
    )
    assert cfg.successors(206) == (24,)
    assert cfg.successors(24) == (23,)  # forward transition, not terminal
    assert 206 not in [s for s, b in cfg.blocks.items() if b.nsucc == 0]


def test_default_entry_resolves_from_initial_state():
    nodes = [_node(0x5, 10, [10]), _node(0x7, 20, [20])]
    cfg = build_state_dag_cfg(_dag(nodes, [], initial_state=0x7), base_successors={})
    assert cfg.entry_serial == 20


def test_entry_override_wins():
    nodes = [_node(0x5, 10, [10]), _node(0x7, 20, [20])]
    cfg = build_state_dag_cfg(
        _dag(nodes, [], initial_state=0x7), base_successors={}, entry_serial=10
    )
    assert cfg.entry_serial == 10


def test_adapter_feeds_structurer_goto_free_with_carrier_return():
    # End-to-end on a synthetic graph mirroring sub_7FFD: entry handler flows
    # through a forward range-backed node into the shared return corridor; the
    # structurer must emit goto-free text whose sole terminal returns the real
    # carrier (not a leaked state constant).
    from d810.analyses.control_flow.structurer import structure_recovered_program
    from d810.analyses.value_flow.stack_value_flow import CarrierVerdict

    nodes = [
        _node(0x1, 10, [10]),  # entry handler
        _node(0x298372CC, 206, [206, 24], kind=StateNodeKind.RANGE_BACKED),
        _node(0x6465D165, 23, [23, 224, 225]),  # ends in return corridor
    ]
    edges = [
        _edge(SemanticEdgeKind.TRANSITION, 0x1, 0x298372CC, 10, 206, [10]),
        _edge(SemanticEdgeKind.TRANSITION, 0x298372CC, 0x6465D165, 24, 23, [206, 24]),
    ]
    base = {10: (206,), 206: (24,), 24: (99,), 23: (224,), 224: (225,), 225: ()}
    cfg = build_state_dag_cfg(_dag(nodes, edges, initial_state=0x1), base_successors=base)

    # Terminal 225 (the return slot) reaches only the entry-default leak site and
    # the state var is dead there -> deliver the real carrier.
    leak_site = (10, 0x1000)
    verdicts = {
        225: CarrierVerdict(
            return_reaching=frozenset({leak_site}),
            carrier_dominates=True,
            state_dead=True,
        )
    }
    text = structure_recovered_program(
        cfg,
        render_block=lambda blk: (f"/* blk {blk.serial} */",),
        render_condition=lambda blk: "cond",
        carrier_verdicts=verdicts,
        carrier_expr="a5 + 0xD0",
        leak_def_sites=(leak_site,),
    )
    assert "goto" not in text
    assert "0x298372CC" not in text and "return 0x298372CC" not in text
    assert "return a5 + 0xD0;" in text
