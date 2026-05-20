from __future__ import annotations

from types import SimpleNamespace

from d810.cfg.flowgraph import BlockKind, BlockSnapshot, FlowGraph
from d810.cfg.reorder_blocks_planning import compute_reorder_blocks


def _flow_graph(block_kinds: dict[int, BlockKind]) -> FlowGraph:
    return FlowGraph(
        blocks={
            serial: BlockSnapshot(
                serial=serial,
                block_type=-1,
                succs=(),
                preds=(),
                flags=0,
                start_ea=0,
                insn_snapshots=(),
                kind=block_kind,
            )
            for serial, block_kind in block_kinds.items()
        },
        entry_serial=next(iter(block_kinds)),
        func_ea=0,
    )


def test_compute_reorder_blocks_returns_none_without_state_machine():
    snapshot = SimpleNamespace(state_machine=None, flow_graph=None)
    assert compute_reorder_blocks(snapshot, resolve_target_entry=lambda state: None) is None


def test_compute_reorder_blocks_orders_handlers_and_splits_two_way():
    state_machine = SimpleNamespace(
        initial_state=1,
        handlers={
            1: SimpleNamespace(handler_blocks=(10, 11)),
            2: SimpleNamespace(handler_blocks=(20,)),
            3: SimpleNamespace(handler_blocks=(30,)),
        },
        transitions=(
            SimpleNamespace(from_block=10, to_state=2, is_conditional=False),
            SimpleNamespace(from_block=11, to_state=3, is_conditional=True),
        ),
    )
    bst_result = SimpleNamespace(
        handler_state_map={200: 2, 300: 3},
        handler_range_map={},
        bst_node_blocks=frozenset(),
    )
    snapshot = SimpleNamespace(
        state_machine=state_machine,
        flow_graph=_flow_graph(
            {
                10: BlockKind.ONE_WAY,
                11: BlockKind.TWO_WAY,
                20: BlockKind.ONE_WAY,
                30: BlockKind.ONE_WAY,
            }
        ),
    )

    result = compute_reorder_blocks(
        snapshot,
        resolve_target_entry=lambda state: {2: 200, 3: 300}.get(state),
        handler_entry_state_map=bst_result.handler_state_map,
        dispatcher_blocks=bst_result.bst_node_blocks,
    )
    assert result is not None
    assert result.dfs_block_order == (10, 11, 20, 30)
    assert result.non_2way_serials == (10, 20, 30)
    assert result.two_way_serials == (11,)
