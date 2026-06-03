"""Acyclic structural analysis: CFG -> goto-free region tree (Slice B core)."""
from __future__ import annotations

from dataclasses import dataclass

from d810.analyses.control_flow.structurer import build_region_tree
from d810.ir.structured_region import (
    BlockRegion,
    ConditionRegion,
    LoopRegion,
    SequenceRegion,
    render_region,
)


@dataclass(frozen=True)
class _Blk:
    serial: int
    succs: tuple
    preds: tuple = ()

    @property
    def nsucc(self) -> int:
        return len(self.succs)


class _Graph:
    def __init__(self, blocks, entry_serial):
        self.blocks = {b.serial: b for b in blocks}
        self.entry_serial = entry_serial

    def get_block(self, serial):
        return self.blocks.get(serial)


def _lines(blk):
    return (f"/* blk {blk.serial} */",)


def _cond(blk):
    return f"c{blk.serial}"


def test_carrier_diamond_with_returning_arms_becomes_condition():
    # 0 -> {1, 2}; both arms are returning terminals (no common real join).
    graph = _Graph(
        [
            _Blk(0, (1, 2)),
            _Blk(1, (), (0,)),
            _Blk(2, (), (0,)),
        ],
        entry_serial=0,
    )
    tree = build_region_tree(graph, render_block=_lines, render_condition=_cond)

    assert isinstance(tree, SequenceRegion)
    block0, cond = tree.regions
    assert isinstance(block0, BlockRegion) and block0.serial == 0
    assert isinstance(cond, ConditionRegion)
    assert isinstance(cond.then_region, BlockRegion) and cond.then_region.serial == 1
    assert isinstance(cond.else_region, BlockRegion) and cond.else_region.serial == 2
    assert "goto" not in render_region(tree)


def test_real_merge_diamond_continues_after_join():
    # 0 -> {1, 2} -> 3 : if/else then continue at the post-dominator 3.
    graph = _Graph(
        [
            _Blk(0, (1, 2)),
            _Blk(1, (3,), (0,)),
            _Blk(2, (3,), (0,)),
            _Blk(3, (), (1, 2)),
        ],
        entry_serial=0,
    )
    tree = build_region_tree(graph, render_block=_lines, render_condition=_cond)

    assert isinstance(tree, SequenceRegion)
    serials_top = [r.serial for r in tree.regions if isinstance(r, BlockRegion)]
    assert serials_top == [0, 3]  # block 0, then the join block 3
    cond = next(r for r in tree.regions if isinstance(r, ConditionRegion))
    assert cond.then_region.serial == 1
    assert cond.else_region.serial == 2
    text = render_region(tree)
    assert "goto" not in text
    assert "if ( c0 )" in text


def test_linear_chain_folds_to_sequence():
    graph = _Graph(
        [_Blk(0, (1,)), _Blk(1, (2,), (0,)), _Blk(2, (), (1,))],
        entry_serial=0,
    )
    tree = build_region_tree(graph, render_block=_lines, render_condition=_cond)
    assert isinstance(tree, SequenceRegion)
    assert [r.serial for r in tree.regions] == [0, 1, 2]
    assert "goto" not in render_region(tree)


def test_back_edge_does_not_loop_forever():
    # 0 -> 1 -> 2 -> 1 (back-edge): the structurer must terminate.
    graph = _Graph(
        [_Blk(0, (1,)), _Blk(1, (2,), (0, 2)), _Blk(2, (1,), (1,))],
        entry_serial=0,
    )
    tree = build_region_tree(graph, render_block=_lines, render_condition=_cond)
    assert "goto" not in render_region(tree)  # terminates, goto-free


def test_carrier_verdict_threads_fixed_return_into_aligned_terminal():
    # The Layer-1 carrier verdict says the aligned terminal (block 1) must
    # deliver a5+0xD0, not the leaked dispatcher state 0x298372CC.
    graph = _Graph(
        [_Blk(0, (1, 2)), _Blk(1, (), (0,)), _Blk(2, (), (0,))],
        entry_serial=0,
    )
    delivered = {1: "a5 + 0xD0", 2: "result"}
    tree = build_region_tree(
        graph,
        render_block=_lines,
        render_condition=_cond,
        terminal_return=lambda serial: delivered.get(serial),
    )
    text = render_region(tree)
    assert "return a5 + 0xD0;" in text   # aligned terminal delivers the carrier
    assert "0x298372CC" not in text       # the leaked state is gone
    assert "goto" not in text


def test_while_loop_header_is_condition():
    # 0 -> 1(cond) ; 1 -> {2 body, 3 exit} ; 2 -> 1 (back-edge)
    graph = _Graph(
        [_Blk(0, (1,)), _Blk(1, (2, 3)), _Blk(2, (1,)), _Blk(3, ())],
        entry_serial=0,
    )
    tree = build_region_tree(graph, render_block=_lines, render_condition=_cond)
    text = render_region(tree)
    assert "while ( c1 )" in text
    assert "goto" not in text
    loop = next(r for r in tree.regions if isinstance(r, LoopRegion))
    assert loop.kind == "while" and loop.condition == "c1"
    assert [r.serial for r in tree.regions if isinstance(r, BlockRegion)] == [0, 3]


def test_do_while_latch_is_condition():
    # 0 -> 1 -> 2(cond) ; 2 -> {1 back-edge, 3 exit}
    graph = _Graph(
        [_Blk(0, (1,)), _Blk(1, (2,)), _Blk(2, (1, 3)), _Blk(3, ())],
        entry_serial=0,
    )
    tree = build_region_tree(graph, render_block=_lines, render_condition=_cond)
    text = render_region(tree)
    assert "do" in text and "while ( c2 );" in text
    assert "goto" not in text
    loop = next(r for r in tree.regions if isinstance(r, LoopRegion))
    assert loop.kind == "do_while" and loop.condition == "c2"
