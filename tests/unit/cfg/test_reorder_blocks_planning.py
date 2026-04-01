from __future__ import annotations

from types import SimpleNamespace

from d810.cfg.reorder_blocks_planning import compute_reorder_blocks


class _FakeMBA:
    def __init__(self, block_types: dict[int, int]):
        self._blocks = {
            serial: SimpleNamespace(type=block_type)
            for serial, block_type in block_types.items()
        }

    def get_mblock(self, serial: int):
        return self._blocks.get(serial)


def test_compute_reorder_blocks_returns_none_without_state_machine():
    snapshot = SimpleNamespace(state_machine=None, bst_result=None, mba=None)
    assert compute_reorder_blocks(snapshot, resolve_target_entry=lambda bst, state: None) is None


def test_compute_reorder_blocks_orders_handlers_and_splits_two_way(monkeypatch):
    import d810.cfg.reorder_blocks_planning as planning

    monkeypatch.setattr(planning, "_BLT_2WAY", 2)

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
    mba = _FakeMBA({10: 1, 11: 2, 20: 1, 30: 1})
    snapshot = SimpleNamespace(
        state_machine=state_machine,
        bst_result=bst_result,
        mba=mba,
    )

    result = compute_reorder_blocks(
        snapshot,
        resolve_target_entry=lambda bst_result, state: {2: 200, 3: 300}.get(state),
    )
    assert result is not None
    assert result.dfs_block_order == (10, 11, 20, 30)
    assert result.non_2way_serials == (10, 20, 30)
    assert result.two_way_serials == (11,)
