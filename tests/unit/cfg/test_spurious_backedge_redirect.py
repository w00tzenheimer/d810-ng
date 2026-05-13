"""Tests for the spurious back-edge redirect planner."""
from __future__ import annotations

from d810.cfg.spurious_backedge_redirect import (
    SpuriousRedirectPlan,
    plan_spurious_backedge_redirects,
)


class TestPlanner:
    def test_empty_inputs(self) -> None:
        plans = plan_spurious_backedge_redirects(
            block_succs={},
            block_types={},
            block_writes={},
            block_predicate_reads={},
        )
        assert plans == ()

    def test_acyclic_graph_returns_no_plans(self) -> None:
        plans = plan_spurious_backedge_redirects(
            block_succs={0: (1,), 1: (2,), 2: ()},
            block_types={0: "BLT_1WAY", 1: "BLT_1WAY", 2: "BLT_STOP"},
            block_writes={},
            block_predicate_reads={},
        )
        assert plans == ()

    def test_spurious_blt_2way_redirected(self) -> None:
        # blk[15] BLT_2WAY succs=[16, 13]; SPURIOUS edge 15->13.
        # safe_alternative = 16. Expect a single redirect plan.
        block_succs = {
            13: (15,), 14: (13,), 15: (16, 13), 16: ()
        }
        block_types = {
            13: "BLT_1WAY", 14: "BLT_1WAY", 15: "BLT_2WAY", 16: "BLT_STOP",
        }
        # blk[15]'s tail predicate reads %var_330 (not written by 13/14).
        # blk[15] writes %var_5B8 (an MBA opaque — not read by tgt).
        # Edge 15->13 must classify as SPURIOUS.
        block_writes = {
            13: frozenset(),
            14: frozenset(),
            15: frozenset({"%var_5B8"}),
        }
        block_predicate_reads = {
            13: frozenset({"%var_F0"}),    # tgt's predicate reads var_F0
            14: frozenset(),
            15: frozenset({"%var_330"}),
        }
        plans = plan_spurious_backedge_redirects(
            block_succs=block_succs,
            block_types=block_types,
            block_writes=block_writes,
            block_predicate_reads=block_predicate_reads,
        )
        assert len(plans) == 1
        plan = plans[0]
        assert plan.src_serial == 15
        assert plan.old_target == 13
        assert plan.new_target == 16

    def test_spurious_blt_1way_skipped(self) -> None:
        # blk[14] BLT_1WAY -> blk[6]; SPURIOUS edge 14->6.
        # No safe alternative -> conservative skip.
        block_succs = {6: (14,), 14: (6,)}
        block_types = {6: "BLT_1WAY", 14: "BLT_1WAY"}
        block_writes = {6: frozenset(), 14: frozenset()}
        block_predicate_reads = {
            6: frozenset({"%var_F0"}),
            14: frozenset({"%var_330"}),
        }
        plans = plan_spurious_backedge_redirects(
            block_succs=block_succs,
            block_types=block_types,
            block_writes=block_writes,
            block_predicate_reads=block_predicate_reads,
        )
        assert plans == ()

    def test_real_loop_never_redirected(self) -> None:
        # blk[10] BLT_2WAY succs=[20, 4]; back-edge 10->4 is REAL_LOOP
        # because 10 writes the carrier read by 4's predicate.
        block_succs = {4: (10,), 10: (20, 4), 20: ()}
        block_types = {4: "BLT_1WAY", 10: "BLT_2WAY", 20: "BLT_STOP"}
        block_writes = {10: frozenset({"%var_178"})}
        block_predicate_reads = {
            4: frozenset({"%var_178"}),    # carrier overlap → REAL_LOOP
            10: frozenset(),
        }
        plans = plan_spurious_backedge_redirects(
            block_succs=block_succs,
            block_types=block_types,
            block_writes=block_writes,
            block_predicate_reads=block_predicate_reads,
        )
        assert plans == ()

    def test_unknown_classification_never_redirected(self) -> None:
        # blk[12] BLT_2WAY succs=[20, 5]; back-edge 12->5 is UNKNOWN
        # because blk[5] has no predicate reads in the maps.
        block_succs = {5: (12,), 12: (20, 5), 20: ()}
        block_types = {5: "BLT_1WAY", 12: "BLT_2WAY", 20: "BLT_STOP"}
        block_writes = {12: frozenset({"%var_330"})}
        block_predicate_reads = {12: frozenset()}  # blk[5] missing entirely
        plans = plan_spurious_backedge_redirects(
            block_succs=block_succs,
            block_types=block_types,
            block_writes=block_writes,
            block_predicate_reads=block_predicate_reads,
        )
        assert plans == ()

    def test_two_independent_sccs_yield_independent_plans(self) -> None:
        # Two disjoint SCCs, each a 2-block self-cycle through a
        # SPURIOUS edge from a BLT_2WAY source.
        # SCC #1: 1 <-> 15 (15 BLT_2WAY succs=[16, 1])
        # SCC #2: 2 <-> 25 (25 BLT_2WAY succs=[26, 2])
        block_succs = {
            0: (1, 2),
            1: (15,),
            2: (25,),
            15: (16, 1),
            16: (),
            25: (26, 2),
            26: (),
        }
        block_types = {
            0: "BLT_2WAY", 1: "BLT_1WAY", 2: "BLT_1WAY",
            15: "BLT_2WAY", 16: "BLT_STOP",
            25: "BLT_2WAY", 26: "BLT_STOP",
        }
        block_writes = {
            15: frozenset({"%var_5B8"}),
            25: frozenset({"%var_5B8"}),
        }
        block_predicate_reads = {
            1: frozenset({"%var_F0"}),
            2: frozenset({"%var_F0"}),
            15: frozenset({"%var_330"}),
            25: frozenset({"%var_330"}),
        }
        plans = plan_spurious_backedge_redirects(
            block_succs=block_succs,
            block_types=block_types,
            block_writes=block_writes,
            block_predicate_reads=block_predicate_reads,
        )
        sources = sorted(p.src_serial for p in plans)
        assert sources == [15, 25]
        for p in plans:
            assert p.old_target in {1, 2}
            assert p.new_target in {16, 26}

    def test_blt_2way_predicate_block_in_scc_without_dom_backedge_skipped(self) -> None:
        # blk[13] is a BLT_2WAY whose two succs are both in the SCC.
        # Neither 13->15 nor 13->25 is a dominator back-edge, so a strict
        # back-edge planner must not redirect them just because they are
        # intra-SCC and locally SPURIOUS.
        block_succs = {
            13: (15, 25),
            15: (13,),
            25: (13,),
        }
        block_types = {
            13: "BLT_2WAY", 15: "BLT_1WAY", 25: "BLT_1WAY",
        }
        block_writes = {13: frozenset()}  # 13 writes nothing
        block_predicate_reads = {
            15: frozenset({"%var_F0"}),
            25: frozenset({"%var_330"}),
        }
        plans = plan_spurious_backedge_redirects(
            block_succs=block_succs,
            block_types=block_types,
            block_writes=block_writes,
            block_predicate_reads=block_predicate_reads,
        )
        assert plans == ()

    def test_actual_dominator_backedge_can_redirect_to_in_scc_successor(self) -> None:
        block_succs = {
            0: (13,),
            13: (15,),
            15: (16, 13),
            16: (13,),
        }
        block_types = {
            0: "BLT_1WAY",
            13: "BLT_1WAY",
            15: "BLT_2WAY",
            16: "BLT_1WAY",
        }
        block_writes = {15: frozenset({"%var_5B8"})}
        block_predicate_reads = {13: frozenset({"%var_F0"})}
        plans = plan_spurious_backedge_redirects(
            block_succs=block_succs,
            block_types=block_types,
            block_writes=block_writes,
            block_predicate_reads=block_predicate_reads,
        )
        assert [(p.src_serial, p.old_target, p.new_target) for p in plans] == [
            (15, 13, 16)
        ]

    def test_blt_2way_with_three_succs_skipped_defensively(self) -> None:
        block_succs = {15: (16, 17, 13), 13: (15,), 16: (), 17: ()}
        block_types = {
            15: "BLT_2WAY", 13: "BLT_1WAY", 16: "BLT_STOP", 17: "BLT_STOP",
        }
        block_writes = {15: frozenset({"%var_5B8"})}
        block_predicate_reads = {13: frozenset({"%var_F0"}), 15: frozenset({"%var_330"})}
        plans = plan_spurious_backedge_redirects(
            block_succs=block_succs,
            block_types=block_types,
            block_writes=block_writes,
            block_predicate_reads=block_predicate_reads,
        )
        # 15 has 3 successors — defensive skip.
        assert plans == ()

    def test_sub7ffd_shape_yields_one_actionable_plan(self) -> None:
        # Mirrors the actual sub_7FFD3338C040 GLBOPT1 post-D810 shape:
        # 5 SPURIOUS back-edges of which only one (15->13) has a
        # BLT_2WAY source. Expect exactly 1 plan.
        block_succs = {
            # SCC nodes (subset, just enough to exercise the algorithm).
            2: (3, 19),       # chunk-size check (real-loop tgt for 18->2)
            3: (4, 5),
            4: (5, 10),       # head-byte stride test (real-loop tgt for 10->4)
            5: (6, 12),
            6: (8, 14),       # tgt for 14->6 (SPURIOUS)
            10: (4, 20),      # head-byte body BLT_2WAY (real-loop)
            12: (5, 21),      # 12->5 UNKNOWN (no tgt reads)
            13: (15, 22),     # tgt for 15->13 (SPURIOUS)
            14: (6,),         # BLT_1WAY -> 6
            15: (16, 13),     # SPURIOUS source (BLT_2WAY) — actionable!
            16: (), 19: (), 20: (), 21: (), 22: (),
        }
        block_types = {
            2: "BLT_2WAY", 3: "BLT_2WAY", 4: "BLT_2WAY", 5: "BLT_2WAY",
            6: "BLT_2WAY", 10: "BLT_2WAY", 12: "BLT_2WAY", 13: "BLT_2WAY",
            14: "BLT_1WAY", 15: "BLT_2WAY",
            16: "BLT_STOP", 19: "BLT_STOP", 20: "BLT_STOP",
            21: "BLT_STOP", 22: "BLT_STOP",
        }
        block_writes = {
            10: frozenset({"%var_178"}),    # carrier — REAL_LOOP for 10->4
            12: frozenset({"%var_330"}),    # writes; tgt has no reads → UNKNOWN
            14: frozenset(),
            15: frozenset({"%var_5B8"}),    # MBA opaque
        }
        block_predicate_reads = {
            2: frozenset({"%var_1C8"}),
            4: frozenset({"%var_178"}),      # carrier — REAL_LOOP
            5: frozenset(),                  # empty → 12->5 UNKNOWN
            6: frozenset({"%var_F0"}),       # 14->6 SPURIOUS
            13: frozenset({"%var_F0"}),      # 15->13 SPURIOUS
        }
        plans = plan_spurious_backedge_redirects(
            block_succs=block_succs,
            block_types=block_types,
            block_writes=block_writes,
            block_predicate_reads=block_predicate_reads,
        )
        assert len(plans) == 1
        p = plans[0]
        assert (p.src_serial, p.old_target, p.new_target) == (15, 13, 16)


class TestSpuriousRedirectPlanDataclass:
    def test_frozen_fields(self) -> None:
        p = SpuriousRedirectPlan(
            src_serial=15, old_target=13, new_target=16, reason="x"
        )
        assert p.src_serial == 15
        assert p.old_target == 13
        assert p.new_target == 16
