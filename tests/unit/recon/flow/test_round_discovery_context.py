from __future__ import annotations

from d810.ir.state_dag_key import StateDagNodeKey
from d810.analyses.control_flow.linearized_state_dag import (
    LinearizedStateDag,
    LocalEdgeKind,
    LocalSegmentKind,
    StateDagNode,
    StateLocalEdge,
    StateLocalSegment,
    StateNodeKind,
)
from d810.analyses.control_flow.round_discovery_context import _build_dag_local_facts


def test_build_dag_local_facts_indexes_node_local_cfg() -> None:
    edge = StateLocalEdge("blk[205]", "blk[207]", LocalEdgeKind.TAKEN, 1)
    node = StateDagNode(
        key=StateDagNodeKey(handler_serial=205, state_const=0x298372CC),
        kind=StateNodeKind.RANGE_BACKED,
        state_label="STATE_298372CC",
        handler_serial=205,
        entry_anchor=205,
        owned_blocks=(205, 207, 206, 217, 218),
        exclusive_blocks=(205, 207, 206),
        shared_suffix_blocks=(217, 218),
        local_segments=(
            StateLocalSegment("blk[205]", LocalSegmentKind.BRANCH, (205,)),
            StateLocalSegment("blk[207]", LocalSegmentKind.STRAIGHT_LINE, (207,)),
        ),
        local_edges=(edge,),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=1,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=0x298372CC,
        condition_chain_blocks=(),
        nodes=(node,),
        edges=(),
    )

    facts = _build_dag_local_facts(dag)

    assert facts.node_by_entry[205] is node
    assert facts.node_by_handler[205] is node
    assert facts.node_by_owned_block[217] is node
    assert facts.node_by_any_local_block[207] is node
    assert facts.owned_blocks_by_entry[205] == frozenset({205, 207, 206, 217, 218})
    assert facts.shared_suffix_by_entry[205] == frozenset({217, 218})
    assert facts.local_edges_by_entry[205] == (edge,)
