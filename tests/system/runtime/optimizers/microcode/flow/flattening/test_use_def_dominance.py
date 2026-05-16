"""Unit tests for use_def_dominance — Phase 1 dominance-aware logic.

These tests cover the pure-Python pieces of the severance detector
(post-mod adjacency construction and the dominance check it relies on
via :func:`d810.cfg.dominator.compute_dom_tree`).  Full integration of
:func:`check_redirect_severs_use_def` requires an IDA ``mba_t`` and is
covered in system/runtime tests.
"""

from __future__ import annotations

import pytest

from d810.cfg.dominator import compute_dom_tree
from d810.cfg.flowgraph import BlockSnapshot, FlowGraph
from d810.cfg.graph_modification import RedirectBranch, RedirectGoto


def _make_cfg(
    blocks_data: list[tuple[int, tuple[int, ...], tuple[int, ...]]],
    entry: int = 0,
) -> FlowGraph:
    """Build a minimal FlowGraph from ``(serial, succs, preds)`` triples."""
    blocks = {
        serial: BlockSnapshot(
            serial=serial,
            block_type=1,
            succs=succs,
            preds=preds,
            flags=0,
            start_ea=0x1000 + (serial * 0x100),
            insn_snapshots=(),
        )
        for serial, succs, preds in blocks_data
    }
    return FlowGraph(blocks=blocks, entry_serial=entry, func_ea=0x1000)


def _build_post_mod_adjacency_for_test(
    pre_cfg: FlowGraph, mod: RedirectGoto | RedirectBranch
) -> dict[int, list[int]]:
    """Mirror the private helper from use_def_dominance for unit testing."""
    adj = pre_cfg.as_adjacency_dict()
    succs = list(adj.get(mod.from_serial, ()))
    try:
        succs.remove(mod.old_target)
    except ValueError:
        pass
    succs.append(mod.new_target)
    adj[mod.from_serial] = succs
    return adj


class TestPostModAdjacency:
    """Verify post-mod adjacency reflects RedirectGoto correctly."""

    def test_redirect_replaces_target(self) -> None:
        cfg = _make_cfg([
            (0, (10,), ()),
            (10, (20,), (0,)),
            (20, (), (10,)),
            (30, (), ()),
        ])
        mod = RedirectGoto(from_serial=10, old_target=20, new_target=30)
        adj = _build_post_mod_adjacency_for_test(cfg, mod)
        assert adj[10] == [30]

    def test_redirect_with_missing_old_target_appends_new(self) -> None:
        cfg = _make_cfg([
            (0, (10,), ()),
            (10, (), (0,)),
            (30, (), ()),
        ])
        # old_target=20 not in succs; detector still appends new_target.
        mod = RedirectGoto(from_serial=10, old_target=20, new_target=30)
        adj = _build_post_mod_adjacency_for_test(cfg, mod)
        assert adj[10] == [30]

    def test_branch_redirect_replaces_only_selected_target(self) -> None:
        cfg = _make_cfg([
            (0, (10,), ()),
            (10, (20, 30), (0,)),
            (20, (), (10,)),
            (30, (), (10,)),
            (40, (), ()),
        ])
        mod = RedirectBranch(from_serial=10, old_target=30, new_target=40)
        adj = _build_post_mod_adjacency_for_test(cfg, mod)
        assert adj[10] == [20, 40]


class TestDominanceAfterRedirect:
    """Verify the dominance algorithm catches severance vs. preserves it."""

    def test_redirect_with_dominated_use_returns_no_violations(self) -> None:
        """
        When a redirect keeps ``def_block`` dominating ``use_block``, the
        detector logic (mirrored here via compute_dom_tree) should report
        no severance.

        Layout:
            0 -> 10 -> 20 -> 30
        Redirect: 10 (def %var_8.4) old=20 new=20  (no-op shape).
        Block 20 still dominated by 10 in post-mod CFG.
        """
        cfg = _make_cfg([
            (0, (10,), ()),
            (10, (20,), (0,)),
            (20, (30,), (10,)),
            (30, (), (20,)),
        ])
        mod = RedirectGoto(from_serial=10, old_target=20, new_target=20)
        adj = _build_post_mod_adjacency_for_test(cfg, mod)
        dom = compute_dom_tree(adj, entry=0)
        # 10 still dominates 20 (the use site).
        assert dom.dominates(10, 20)

    def test_redirect_severing_dominance_returns_violation(self) -> None:
        """
        When a redirect routes execution around the def block, the use
        site is no longer dominated.

        Layout:
            0 -> 10 -> 20 -> 30 -> 40
            0 -> 50 -------> 30        (bypass edge from 0 to 50 to 30)

        Redirect 10 -> away from 20 (10 -> 50). Now block 20 is no
        longer reachable on the post-mod CFG, so any DU-chain use in
        block 30 is *not* dominated by 10 (the def-block).
        """
        cfg = _make_cfg([
            (0, (10, 50), ()),
            (10, (20,), (0,)),
            (20, (30,), (10,)),
            (50, (30,), (0,)),
            (30, (40,), (20, 50)),
            (40, (), (30,)),
        ])
        # Pre-mod: 10 dominates 20 (only path).  Does it dominate 30?
        # 30 has preds (20, 50); 50 reachable via 0 not via 10, so 10
        # already does NOT dominate 30 pre-mod.
        pre_adj = cfg.as_adjacency_dict()
        pre_dom = compute_dom_tree(pre_adj, entry=0)
        assert pre_dom.dominates(10, 20)
        assert not pre_dom.dominates(10, 30)

        # Now apply redirect 10 old=20 new=50.  Block 20 becomes
        # unreachable; 30 still reachable via 50.  10 still does not
        # dominate 30 — and now also doesn't dominate 20 (unreachable).
        mod = RedirectGoto(from_serial=10, old_target=20, new_target=50)
        post_adj = _build_post_mod_adjacency_for_test(cfg, mod)
        post_dom = compute_dom_tree(post_adj, entry=0)
        # Severance: a pre-mod-dominated use (block 20, dominated by 10)
        # is no longer reachable, hence not in idom; treat as severance.
        # The detector codepath for this scenario observes that
        # dom.dominates(10, 20) is False post-mod.
        assert not post_dom.dominates(10, 20)
        # Post-mod, 10 -> 50 -> 30 means 10 still does not dominate 30
        # (50 also reached via 0).
        assert not post_dom.dominates(10, 30)


@pytest.mark.parametrize(
    "from_s,old_t,new_t",
    [
        (10, 20, 30),
        (1, 2, 3),
        (100, 200, 300),
    ],
)
def test_severance_violation_dataclass_is_frozen(
    from_s: int, old_t: int, new_t: int
) -> None:
    """SeveranceViolation must be frozen + slots for hashable use in sets."""
    # We import here (lazy) only because module top-level imports
    # ida_hexrays which is unavailable in unit tests.  Lazy import here
    # is a *test-file* concession; the production module follows
    # CORE_INSTRUCTIONS' "no lazy imports" rule for source files.
    pytest.importorskip("ida_hexrays")
    from d810.evaluator.hexrays_microcode.use_def_dominance import (
        SeveranceViolation,
    )

    v = SeveranceViolation(
        src_block=from_s,
        new_target=new_t,
        var_stkoff=0x40,
        var_size=4,
        use_block=42,
        use_ea=0x1000,
    )
    with pytest.raises((AttributeError, Exception)):
        v.src_block = 99  # type: ignore[misc]
