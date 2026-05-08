"""Tests for live-CFG SCC analysis."""
from __future__ import annotations

from d810.cfg.scc import (
    CfgSCC,
    compute_live_cfg_sccs,
    nontrivial_sccs,
)


class TestComputeLiveCfgSccs:
    def test_empty_graph(self) -> None:
        sccs = compute_live_cfg_sccs({})
        assert sccs == ()

    def test_linear_chain_is_acyclic(self) -> None:
        sccs = compute_live_cfg_sccs({0: (1,), 1: (2,), 2: (3,), 3: ()})
        assert all(s.is_trivial for s in sccs)
        assert all(not s.is_cyclic for s in sccs)
        assert all(s.has_self_loop is False for s in sccs)
        assert nontrivial_sccs(sccs) == ()
        assert len(sccs) == 4

    def test_single_self_loop(self) -> None:
        # blk[0] -> blk[1] -> blk[1] (self-loop) -> blk[2]
        sccs = compute_live_cfg_sccs({0: (1,), 1: (1, 2), 2: ()})
        cyclic = nontrivial_sccs(sccs)
        assert len(cyclic) == 1
        scc = cyclic[0]
        assert scc.blocks == frozenset({1})
        assert scc.has_self_loop is True
        assert scc.is_cyclic is True
        assert scc.size == 1
        assert scc.cyclic_edges == frozenset({(1, 1)})

    def test_two_block_cycle(self) -> None:
        # ENTRY -> 1 -> 2 -> 1 (cycle) -> 3 -> EXIT
        # Mirrors REF's blk[9]/blk[10] equivalent structure where the
        # head-byte 2-stride loop has body and test in different blocks.
        sccs = compute_live_cfg_sccs(
            {0: (1,), 1: (2,), 2: (1, 3), 3: ()}
        )
        cyclic = nontrivial_sccs(sccs)
        assert len(cyclic) == 1
        scc = cyclic[0]
        assert scc.blocks == frozenset({1, 2})
        assert scc.size == 2
        assert scc.has_self_loop is False
        assert scc.cyclic_edges == frozenset({(1, 2), (2, 1)})

    def test_diamond_is_fully_acyclic(self) -> None:
        # 0 -> 1 -> 3
        #  \-> 2 -> 3
        sccs = compute_live_cfg_sccs(
            {0: (1, 2), 1: (3,), 2: (3,), 3: ()}
        )
        assert nontrivial_sccs(sccs) == ()
        assert len(sccs) == 4
        assert all(s.size == 1 and not s.has_self_loop for s in sccs)

    def test_two_disjoint_self_loops(self) -> None:
        # Mirrors REF GLBOPT1 shape: 2 isolated self-loops + acyclic body.
        # ENTRY -> 1 (self-loop) -> 2 -> 3 (self-loop) -> 4 -> EXIT
        sccs = compute_live_cfg_sccs(
            {0: (1,), 1: (1, 2), 2: (3,), 3: (3, 4), 4: ()}
        )
        cyclic = nontrivial_sccs(sccs)
        assert len(cyclic) == 2
        loops = sorted(cyclic, key=lambda s: min(s.blocks))
        assert loops[0].blocks == frozenset({1})
        assert loops[0].has_self_loop is True
        assert loops[0].cyclic_edges == frozenset({(1, 1)})
        assert loops[1].blocks == frozenset({3})
        assert loops[1].has_self_loop is True
        assert loops[1].cyclic_edges == frozenset({(3, 3)})

    def test_giant_scc_with_multiple_back_edges(self) -> None:
        # Models the sub_7FFD shape: many back-edges close one big SCC.
        # 0 -> 1 -> 2 -> 3 -> 4 -> EXIT, with back-edges 4->1, 3->2, 4->2.
        sccs = compute_live_cfg_sccs(
            {0: (1,), 1: (2,), 2: (3,), 3: (2, 4), 4: (1, 2, 5), 5: ()}
        )
        cyclic = nontrivial_sccs(sccs)
        assert len(cyclic) == 1
        scc = cyclic[0]
        assert scc.blocks == frozenset({1, 2, 3, 4})
        assert scc.size == 4
        assert scc.has_self_loop is False
        # Three back-edges plus the forward edges inside the SCC.
        assert (4, 1) in scc.cyclic_edges
        assert (3, 2) in scc.cyclic_edges
        assert (4, 2) in scc.cyclic_edges
        assert (1, 2) in scc.cyclic_edges
        assert (2, 3) in scc.cyclic_edges
        assert (3, 4) in scc.cyclic_edges
        # 4 -> 5 is NOT cyclic (5 is outside the SCC).
        assert (4, 5) not in scc.cyclic_edges

    def test_cyclic_edges_excludes_exits(self) -> None:
        sccs = compute_live_cfg_sccs(
            {0: (1,), 1: (1, 2), 2: ()}
        )
        cyclic = nontrivial_sccs(sccs)
        assert len(cyclic) == 1
        # Self-loop edge is the only cyclic edge; the exit edge to blk[2]
        # is forward, not cyclic.
        assert cyclic[0].cyclic_edges == frozenset({(1, 1)})

    def test_unreferenced_successor_appears_as_leaf(self) -> None:
        # blk[1] has succ blk[5] but blk[5] is not in the input map.
        # compute_live_cfg_sccs should still place it as a trivial SCC.
        sccs = compute_live_cfg_sccs({0: (1,), 1: (5,)})
        all_blocks = {next(iter(s.blocks)) for s in sccs if s.size == 1}
        assert 5 in all_blocks

    def test_back_edges_count_matches_known_gap(self) -> None:
        # The structural delta we measured for sub_7FFD against the
        # canonical compiled REF: REF has 2 back-edges (2 self-loops);
        # D810 post-D810 has 12 back-edges in one giant SCC. This test
        # codifies the small-scale analog: a 4-block SCC with 4 back-edges
        # should report all 4 in cyclic_edges.
        # Edges: 1->2, 2->3, 3->4, 4->1 (ring), 2->1, 3->1, 4->2 (extras)
        sccs = compute_live_cfg_sccs(
            {0: (1,), 1: (2,), 2: (3, 1), 3: (4, 1), 4: (1, 2, 5), 5: ()}
        )
        cyclic = nontrivial_sccs(sccs)
        assert len(cyclic) == 1
        scc = cyclic[0]
        # Forward + back edges inside SCC: 1->2, 2->3, 2->1, 3->4, 3->1, 4->1, 4->2 = 7
        assert len(scc.cyclic_edges) == 7
        # Edges to/from outside (4->5) excluded.
        assert (4, 5) not in scc.cyclic_edges


class TestCfgSccDataclass:
    def test_is_cyclic_inverse_of_is_trivial(self) -> None:
        scc = CfgSCC(
            scc_id=0, blocks=frozenset({0}), cyclic_edges=frozenset(),
            has_self_loop=False, is_trivial=True,
        )
        assert scc.is_cyclic is False
        assert scc.size == 1

    def test_self_loop_singleton_is_cyclic(self) -> None:
        scc = CfgSCC(
            scc_id=0, blocks=frozenset({5}), cyclic_edges=frozenset({(5, 5)}),
            has_self_loop=True, is_trivial=False,
        )
        assert scc.is_cyclic is True
        assert scc.size == 1
