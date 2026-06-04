"""Tests for the decision-DAG route-predicate oracle.

Covers the exact interval-set arithmetic, per-comparison signedness (the
sign-bit-XOR reduction -- the bug a global signed flag introduces), and the
ground-truth sub_7FFD3338C040 dispatcher BST: routing must match the microcode
trace (``.tmp/bst_trace.py``), and blk56's partition cell must be EXACTLY
``{0x7D9C16EC}`` -- the only state that reaches it.
"""
from __future__ import annotations

from d810.analyses.abstract_domains.interval_set import Interval, IntervalSet
from d810.analyses.control_flow.route_predicate import (
    BstComparison,
    DecisionDag,
    satisfying_set,
)

W = 32


def _node(serial, op, const, true_t, false_t):
    return BstComparison(serial, op, const, true_t, false_t)


# --------------------------------------------------------------- IntervalSet
def test_interval_set_complement_uint32():
    s = satisfying_set(W, "ja", 1000)  # state > 1000
    assert s.intervals == (Interval(1001, 0xFFFFFFFF),)
    assert s.complement().intervals == (Interval(0, 1000),)


def test_interval_set_holes_from_ne_chain():
    # >100 AND !=150 AND <200 over 8 bits -> [101,149] U [151,199] (exact holes).
    u = IntervalSet.universe(8)
    r = (
        u.intersect(satisfying_set(8, "ja", 100))
        .intersect(satisfying_set(8, "jnz", 150))
        .intersect(satisfying_set(8, "jb", 200))
    )
    assert r.intervals == (Interval(101, 149), Interval(151, 199))


# ----------------------------------------------- PROBE B: per-comparison sign
def test_signed_vs_unsigned_greater_than_max_positive():
    # The prototype's global-signed-flag bug: unsigned > 0x7FFFFFFF MUST contain
    # 0xFFFFFFFF; signed > 0x7FFFFFFF must NOT (nothing is > max-positive signed).
    assert satisfying_set(W, "ja", 0x7FFFFFFF).contains(0xFFFFFFFF)
    assert not satisfying_set(W, "jg", 0x7FFFFFFF).contains(0xFFFFFFFF)
    # signed > 0 == [1, 0x7FFFFFFF]; negatives (0x80000000+) are excluded.
    sg = satisfying_set(W, "jg", 0)
    assert sg.intervals == (Interval(1, 0x7FFFFFFF),)
    # signed < 0 == the negatives [0x80000000, 0xFFFFFFFF].
    assert satisfying_set(W, "jl", 0).intervals == (Interval(0x80000000, 0xFFFFFFFF),)


# --------------------------------------------- sub_7FFD ground-truth routing
def _sub7ffd_bst():
    # The real dispatcher path to blk55 (snap5 microcode); leaves dangle.
    nodes = {
        2: _node(2, "jbe", 0x37B42A3F, 112, 3),
        3: _node(3, "jbe", 0x606DC165, 58, 4),
        4: _node(4, "ja", 0x6B588048, 36, 5),
        36: _node(36, "ja", 0x737189D4, 49, 37),
        49: _node(49, "ja", 0x7C2C021F, 53, 50),
        53: _node(53, "jnz", 0x7C2C0220, 55, 54),
        55: _node(55, "jnz", 0x7D9C16EC, 57, 56),
    }
    return DecisionDag(W, nodes, root=2)


def test_sub7ffd_routes_match_microcode_trace():
    dag = _sub7ffd_bst()
    assert dag.route(0x7FDCE054) == 57  # != 0x7D9C16EC -> jump arm (blk35's state)
    assert dag.route(0x7D9C16EC) == 56  # == 0x7D9C16EC -> fallthrough arm
    sib = dag.sibling_arms()
    assert 56 in sib[57] and 57 in sib[56]  # blk55's two arms are siblings


def test_blk56_partition_cell_is_exactly_0x7D9C16EC():
    # What routes to blk56? Only state 0x7D9C16EC -- proven by the partition.
    dag = _sub7ffd_bst()
    cells56 = [p for p in dag.resolve_paths() if p.target == 56]
    assert len(cells56) == 1
    assert cells56[0].domain.intervals == (Interval(0x7D9C16EC, 0x7D9C16EC),)
    assert not cells56[0].domain.contains(0x7FDCE054)  # blk35's state is NOT here


# ------------------------------------------- soundness & completeness proof
def test_partition_sound_and_complete():
    nodes = {
        1: _node(1, "jae", 0x80, 2, 3),
        2: _node(2, "jae", 0xC0, 200, 201),
        3: _node(3, "jb", 0x40, 300, 301),
    }
    dag = DecisionDag(8, nodes, root=1)
    cells = dag.resolve_paths()
    # completeness: union of all cells == the whole 8-bit space.
    acc = IntervalSet.empty(8)
    for c in cells:
        acc = acc.union(c.domain)
    assert acc == IntervalSet.universe(8)
    # soundness: cells are pairwise disjoint (no state routes two ways).
    for i in range(len(cells)):
        for j in range(i + 1, len(cells)):
            assert cells[i].domain.intersect(cells[j].domain).is_empty()
