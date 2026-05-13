from __future__ import annotations

from types import SimpleNamespace

import pytest

from d810.optimizers.microcode.flow.flattening.hodur.strategies.exact_conditional_node import (
    analyze_exact_conditional_sites,
)


class _FakeBlock:
    def __init__(self, serial: int, succs: tuple[int, ...], preds: tuple[int, ...] = ()):
        self.serial = serial
        self.succs = tuple(succs)
        self.preds = tuple(preds)
        self.nsucc = len(self.succs)
        self.npred = len(self.preds)


class _FakeFlowGraph:
    def __init__(self, blocks: list[_FakeBlock]):
        self.blocks = {block.serial: block for block in blocks}
        self.entry_serial = min(self.blocks) if self.blocks else -1

    def get_block(self, serial: int):
        return self.blocks.get(int(serial))

    def successors(self, serial: int):
        block = self.get_block(serial)
        return tuple(block.succs) if block is not None else ()


class _FakeEdge:
    def __init__(
        self,
        *,
        source_state: int,
        source_block: int,
        target_state: int,
        target_entry_anchor: int,
        source_branch_arm: int,
        ordered_path: tuple[int, ...],
        kind_name: str = "CONDITIONAL_TRANSITION",
    ) -> None:
        self.kind = SimpleNamespace(name=kind_name)
        self.source_key = SimpleNamespace(state_const=source_state)
        self.target_state = target_state
        self.target_entry_anchor = target_entry_anchor
        self.source_anchor = SimpleNamespace(
            block_serial=source_block,
            branch_arm=source_branch_arm,
        )
        self.ordered_path = ordered_path


def _build_round_summary(edges: list[_FakeEdge]) -> SimpleNamespace:
    return SimpleNamespace(
        dag=SimpleNamespace(edges=tuple(edges)),
        plannable_edges=tuple(SimpleNamespace(edge=edge) for edge in edges),
    )


@pytest.mark.parametrize("source_block", [28, 98, 136, 181])
def test_analyze_exact_conditional_sites_accepts_alias_duplicated_multi_transition_sites(
    source_block: int,
) -> None:
    taken_successor = source_block + 1
    fallback_successor = source_block + 10
    taken_tail_a = source_block + 20
    taken_tail_b = source_block + 21

    source_state = 0x10000000 + source_block
    transition_a = _FakeEdge(
        source_state=source_state,
        source_block=source_block,
        target_state=0x20000000 + source_block,
        target_entry_anchor=source_block + 100,
        source_branch_arm=0,
        ordered_path=(source_block, taken_successor, taken_tail_a),
    )
    transition_b = _FakeEdge(
        source_state=source_state,
        source_block=source_block,
        target_state=0x30000000 + source_block,
        target_entry_anchor=source_block + 200,
        source_branch_arm=1,
        ordered_path=(source_block, taken_successor, taken_tail_b),
    )
    return_edge = _FakeEdge(
        source_state=source_state,
        source_block=source_block,
        target_state=0x40000000 + source_block,
        target_entry_anchor=source_block + 300,
        source_branch_arm=1,
        ordered_path=(source_block, fallback_successor, fallback_successor + 1),
        kind_name="CONDITIONAL_RETURN",
    )
    flow_graph = _FakeFlowGraph(
        [
            _FakeBlock(source_block, (taken_successor, fallback_successor)),
            _FakeBlock(taken_tail_a, (2,), preds=(source_block,)),
            _FakeBlock(taken_tail_b, (2,), preds=(source_block,)),
            _FakeBlock(fallback_successor, (fallback_successor + 1,), preds=(source_block,)),
            _FakeBlock(fallback_successor + 1, (), preds=(fallback_successor,)),
            _FakeBlock(2, (), preds=(taken_tail_a, taken_tail_b)),
        ]
    )

    sites, inventory = analyze_exact_conditional_sites(
        _build_round_summary([transition_a, transition_b, return_edge]),
        flow_graph,
    )

    assert inventory.selected_count >= 1
    assert any(item[0] == source_block for item in inventory.multi_transition_blocks)
    assert source_block not in inventory.shape_rejected_blocks
    assert any(site.source_block == source_block for site in sites)


def test_analyze_exact_conditional_sites_accepts_mixed_shape_multi_transition_site() -> None:
    source_block = 163
    taken_successor = 164
    fallback_successor = 170
    source_state = 0x50000000

    valid_transition = _FakeEdge(
        source_state=source_state,
        source_block=source_block,
        target_state=0x6CAA9521,
        target_entry_anchor=98,
        source_branch_arm=0,
        ordered_path=(source_block, taken_successor, 69),
    )
    mixed_transition = _FakeEdge(
        source_state=source_state,
        source_block=source_block,
        target_state=0x6E958F9A,
        target_entry_anchor=160,
        source_branch_arm=1,
        ordered_path=(source_block, fallback_successor, fallback_successor + 1),
    )
    return_edge = _FakeEdge(
        source_state=source_state,
        source_block=source_block,
        target_state=0x6AAAAAAA,
        target_entry_anchor=161,
        source_branch_arm=1,
        ordered_path=(source_block, fallback_successor, fallback_successor + 1),
        kind_name="CONDITIONAL_RETURN",
    )
    flow_graph = _FakeFlowGraph(
        [
            _FakeBlock(source_block, (taken_successor, fallback_successor)),
            _FakeBlock(69, (2,), preds=(taken_successor,)),
            _FakeBlock(fallback_successor, (fallback_successor + 1,), preds=(source_block,)),
            _FakeBlock(fallback_successor + 1, (), preds=(fallback_successor,)),
            _FakeBlock(2, (), preds=(69,)),
        ]
    )

    sites, inventory = analyze_exact_conditional_sites(
        _build_round_summary([valid_transition, mixed_transition, return_edge]),
        flow_graph,
    )

    assert inventory.selected_count >= 1
    assert any(item[0] == 163 for item in inventory.multi_transition_blocks)
    assert any(site.target_entry == 98 for site in sites)
