"""Tests for portable-FlowGraph dominator computation."""
from __future__ import annotations

from d810.analyses.control_flow.dominator import compute_dominators, dominates
from d810.ir.flowgraph import BlockSnapshot, FlowGraph


def _flow_graph_from_preds(pred_lists: list[list[int]]) -> FlowGraph:
    """Build a portable :class:`FlowGraph` from per-block predecessor lists.

    ``pred_lists[i]`` is the list of predecessor serials of block ``i``;
    successors are derived by inversion. Blocks carry no instructions —
    only the topology the dominator algorithm consumes.
    """
    n = len(pred_lists)
    succs: dict[int, list[int]] = {i: [] for i in range(n)}
    for serial, preds in enumerate(pred_lists):
        for pred in preds:
            succs[pred].append(serial)
    blocks = {
        serial: BlockSnapshot(
            serial=serial,
            block_type=0,
            succs=tuple(succs[serial]),
            preds=tuple(pred_lists[serial]),
            flags=0,
            start_ea=0,
            insn_snapshots=(),
        )
        for serial in range(n)
    }
    return FlowGraph(blocks=blocks, entry_serial=0, func_ea=0)


class TestComputeDominators:
    def test_single_block(self) -> None:
        fg = _flow_graph_from_preds([[]])
        dom = compute_dominators(fg)
        assert len(dom) == 1
        assert dom[0] == {0}

    def test_empty_flow_graph(self) -> None:
        fg = _flow_graph_from_preds([])
        dom = compute_dominators(fg)
        assert dom == []

    def test_linear_chain(self) -> None:
        fg = _flow_graph_from_preds([[], [0], [1], [2]])
        dom = compute_dominators(fg)
        assert dom[0] == {0}
        assert dom[1] == {0, 1}
        assert dom[2] == {0, 1, 2}
        assert dom[3] == {0, 1, 2, 3}

    def test_diamond_cfg(self) -> None:
        fg = _flow_graph_from_preds([[], [0], [0], [1, 2]])
        dom = compute_dominators(fg)
        assert dom[0] == {0}
        assert dom[1] == {0, 1}
        assert dom[2] == {0, 2}
        assert dom[3] == {0, 3}

    def test_diamond_dominates_entry_dominates_all(self) -> None:
        fg = _flow_graph_from_preds([[], [0], [0], [1, 2]])
        dom = compute_dominators(fg)
        assert dominates(dom, 0, 0)
        assert dominates(dom, 0, 1)
        assert dominates(dom, 0, 2)
        assert dominates(dom, 0, 3)

    def test_diamond_branch_does_not_dominate_exit(self) -> None:
        fg = _flow_graph_from_preds([[], [0], [0], [1, 2]])
        dom = compute_dominators(fg)
        assert not dominates(dom, 1, 3)
        assert not dominates(dom, 2, 3)

    def test_dominates_out_of_range_returns_false(self) -> None:
        fg = _flow_graph_from_preds([[], [0]])
        dom = compute_dominators(fg)
        assert not dominates(dom, 0, 99)

    def test_block_dominates_itself(self) -> None:
        fg = _flow_graph_from_preds([[], [0], [1]])
        dom = compute_dominators(fg)
        for i in range(3):
            assert dominates(dom, i, i)
