"""Unit tests for the cost-aware system-suite batch planner.

The planner replaces the fixed ``--batch-size 20`` split with a plan that keeps
the *isolation contract* the fixed size was chosen for while spending far fewer
fresh interpreters on cheap tests. The contract, from
``run_system_test_batches`` and ``tests/system/conftest.py``: IDA and Hex-Rays
retain native allocations after ``idapro.close_database``, and the database is
opened by the **class-scoped** ``ida_database`` fixture, so what a fresh
interpreter really bounds is the number of database-open groups, not the number
of test functions. ``batch_size=20`` admitted at most 20 such groups per
interpreter; ``max_group_keys=20`` admits exactly the same worst case.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parents[3]
SCRIPT = REPO / "tools/scripts/system_batch_planner.py"


def _module():
    spec = importlib.util.spec_from_file_location("system_batch_planner", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --------------------------------------------------------------------------
# group_key
# --------------------------------------------------------------------------


def test_group_key_folds_parametrizations_of_one_class_together() -> None:
    planner = _module()
    assert (
        planner.group_key("tests/system/e2e/test_a.py::TestC::test_x[p1]")
        == "tests/system/e2e/test_a.py::TestC"
    )
    assert (
        planner.group_key("tests/system/e2e/test_a.py::TestC::test_y")
        == "tests/system/e2e/test_a.py::TestC"
    )


def test_group_key_of_a_module_level_test_is_its_module() -> None:
    planner = _module()
    assert (
        planner.group_key("tests/system/e2e/test_a.py::test_x[p]")
        == "tests/system/e2e/test_a.py"
    )


def test_group_key_of_a_nodeid_without_a_separator_is_itself() -> None:
    planner = _module()
    assert planner.group_key("tests/system/e2e/test_a.py") == (
        "tests/system/e2e/test_a.py"
    )


# --------------------------------------------------------------------------
# load_cost_table
# --------------------------------------------------------------------------


def _write_ledger(path: Path, records: list[dict]) -> None:
    path.write_text(
        "".join(json.dumps(record, sort_keys=True) + "\n" for record in records),
        encoding="utf-8",
    )


def test_load_cost_table_sums_phases_per_nodeid(tmp_path) -> None:
    planner = _module()
    ledger = tmp_path / "system_batches.jsonl"
    _write_ledger(
        ledger,
        [
            {
                "batch_index": 1,
                "test_count": 2,
                "wall_seconds": 20.0,
                "durations": [
                    {"nodeid": "t.py::A::a", "phase": "call", "seconds": 10.0},
                    {"nodeid": "t.py::A::a", "phase": "setup", "seconds": 2.0},
                    {"nodeid": "t.py::A::b", "phase": "call", "seconds": 3.0},
                ],
            }
        ],
    )
    table = planner.load_cost_table([str(ledger)])
    assert table.seconds["t.py::A::a"] == pytest.approx(12.0)
    assert table.seconds["t.py::A::b"] == pytest.approx(3.0)
    assert table.measured == 2
    assert table.sources == (str(ledger),)


def test_load_cost_table_keeps_the_most_expensive_observation(tmp_path) -> None:
    planner = _module()
    ledger = tmp_path / "system_batches.jsonl"
    _write_ledger(
        ledger,
        [
            {
                "batch_index": 1,
                "test_count": 1,
                "wall_seconds": 5.0,
                "durations": [
                    {"nodeid": "t.py::A::a", "phase": "call", "seconds": 4.0}
                ],
            },
            {
                "batch_index": 2,
                "test_count": 1,
                "wall_seconds": 30.0,
                "durations": [
                    {"nodeid": "t.py::A::a", "phase": "call", "seconds": 29.0}
                ],
            },
        ],
    )
    table = planner.load_cost_table([str(ledger)])
    assert table.seconds["t.py::A::a"] == pytest.approx(29.0)


def test_load_cost_table_derives_the_unmeasured_default_from_batch_residual(
    tmp_path,
) -> None:
    """pytest --durations only reports the slowest N phases, so most node ids
    carry no measurement. Their cost is the batch residual, net of the fixed
    per-interpreter overhead, spread over the unmeasured node ids."""
    planner = _module()
    ledger = tmp_path / "system_batches.jsonl"
    _write_ledger(
        ledger,
        [
            {
                "batch_index": 1,
                "test_count": 12,
                "wall_seconds": 30.0,
                "durations": [
                    {"nodeid": "t.py::A::a", "phase": "call", "seconds": 15.0},
                    {"nodeid": "t.py::A::b", "phase": "call", "seconds": 3.0},
                ],
            }
        ],
    )
    table = planner.load_cost_table([str(ledger)], batch_overhead_seconds=2.0)
    # residual = 30 - 18 - 2 (overhead) = 10 over 10 unmeasured node ids
    assert table.default_seconds == pytest.approx(1.0)
    assert table.cost_of("t.py::A::never-seen") == pytest.approx(1.0)
    assert table.cost_of("t.py::A::a") == pytest.approx(15.0)


def test_load_cost_table_falls_back_when_no_ledger_exists(tmp_path) -> None:
    planner = _module()
    table = planner.load_cost_table(
        [str(tmp_path / "absent.jsonl")], fallback_seconds=0.5
    )
    assert table.seconds == {}
    assert table.sources == ()
    assert table.default_seconds == pytest.approx(0.5)


def test_load_cost_table_never_returns_a_negative_default(tmp_path) -> None:
    planner = _module()
    ledger = tmp_path / "system_batches.jsonl"
    _write_ledger(
        ledger,
        [
            {
                "batch_index": 1,
                "test_count": 3,
                "wall_seconds": 4.0,
                "durations": [
                    {"nodeid": "t.py::A::a", "phase": "call", "seconds": 3.9}
                ],
            }
        ],
    )
    table = planner.load_cost_table(
        [str(ledger)], batch_overhead_seconds=2.0, fallback_seconds=0.25
    )
    assert table.default_seconds == pytest.approx(0.25)


# --------------------------------------------------------------------------
# plan_batches
# --------------------------------------------------------------------------


def _uniform_costs(planner, nodeids, seconds):
    return planner.CostTable(
        seconds={nodeid: seconds for nodeid in nodeids},
        default_seconds=seconds,
        sources=(),
        measured=len(nodeids),
    )


def test_plan_batches_packs_cheap_tests_far_beyond_twenty() -> None:
    planner = _module()
    nodeids = tuple(f"t.py::G{index // 10}::test_{index}" for index in range(300))
    costs = _uniform_costs(planner, nodeids, 0.1)
    batches = planner.plan_batches(
        nodeids, costs=costs, max_group_keys=20, cost_budget_seconds=120.0
    )
    assert len(batches) == 2  # 30 groups -> 20 + 10
    assert [len(batch.nodeids) for batch in batches] == [200, 100]
    assert sum(len(batch.nodeids) for batch in batches) == 300


def test_plan_batches_never_exceeds_the_group_isolation_bound() -> None:
    planner = _module()
    nodeids = tuple(f"t.py::G{index}::test_a" for index in range(45))
    costs = _uniform_costs(planner, nodeids, 0.1)
    batches = planner.plan_batches(
        nodeids, costs=costs, max_group_keys=20, cost_budget_seconds=1e9
    )
    assert [batch.group_keys for batch in batches] == [20, 20, 5]


def test_plan_batches_never_splits_one_group_across_interpreters() -> None:
    planner = _module()
    nodeids = tuple(f"t.py::A::test_{index}" for index in range(50))
    costs = _uniform_costs(planner, nodeids, 10.0)
    batches = planner.plan_batches(
        nodeids, costs=costs, max_group_keys=20, cost_budget_seconds=30.0, max_tests=5
    )
    assert len(batches) == 1
    assert batches[0].nodeids == nodeids


def test_plan_batches_gives_a_heavy_test_its_own_interpreter() -> None:
    planner = _module()
    nodeids = (
        "t.py::A::cheap_1",
        "t.py::B::heavy",
        "t.py::C::cheap_2",
    )
    costs = planner.CostTable(
        seconds={
            "t.py::A::cheap_1": 0.2,
            "t.py::B::heavy": 334.0,
            "t.py::C::cheap_2": 0.3,
        },
        default_seconds=0.2,
        sources=(),
        measured=3,
    )
    batches = planner.plan_batches(
        nodeids, costs=costs, max_group_keys=20, cost_budget_seconds=120.0
    )
    assert [batch.nodeids for batch in batches] == [
        ("t.py::A::cheap_1",),
        ("t.py::B::heavy",),
        ("t.py::C::cheap_2",),
    ]
    assert batches[1].estimated_seconds == pytest.approx(334.0)


def test_plan_batches_preserves_collection_order_and_loses_nothing() -> None:
    planner = _module()
    nodeids = tuple(f"t{index % 7}.py::G{index % 3}::test_{index}" for index in range(97))
    costs = _uniform_costs(planner, nodeids, 1.0)
    batches = planner.plan_batches(
        nodeids, costs=costs, max_group_keys=4, cost_budget_seconds=9.0
    )
    flattened = tuple(nodeid for batch in batches for nodeid in batch.nodeids)
    assert sorted(flattened) == sorted(nodeids)
    assert len(flattened) == len(set(flattened))


def test_plan_batches_runs_isolated_nodeids_alone_and_last() -> None:
    planner = _module()
    nodeids = ("t.py::A::a", "oracle.py::O::big", "t.py::A::b")
    costs = _uniform_costs(planner, nodeids, 1.0)
    batches = planner.plan_batches(
        nodeids,
        costs=costs,
        isolated=frozenset({"oracle.py::O::big"}),
        max_group_keys=20,
        cost_budget_seconds=120.0,
    )
    assert batches[-1].nodeids == ("oracle.py::O::big",)
    assert sum(len(batch.nodeids) for batch in batches) == 3


def test_plan_batches_rejects_a_non_positive_group_bound() -> None:
    planner = _module()
    with pytest.raises(ValueError):
        planner.plan_batches(("t.py::A::a",), costs=None, max_group_keys=0)


# --------------------------------------------------------------------------
# assign_shards (LPT)
# --------------------------------------------------------------------------


def _batches(planner, seconds):
    return tuple(
        planner.PlannedBatch(
            nodeids=(f"t.py::G{index}::a",),
            estimated_seconds=value,
            group_keys=1,
        )
        for index, value in enumerate(seconds)
    )


def test_assign_shards_places_the_longest_batch_first() -> None:
    planner = _module()
    batches = _batches(planner, [1.0, 9.0, 5.0, 5.0])
    assignment = planner.assign_shards(batches, 2)
    # LPT: 9 -> s0; 5 -> s1; 5 -> s1 (5 < 9); 1 -> s1 (10 vs 9)? no: after
    # 9|5 the lightest is s1(5), so 5 -> s1 => 9|10, then 1 -> s0 => 10|10.
    assert planner.shard_loads(batches, assignment) == pytest.approx([10.0, 10.0])


def test_assign_shards_returns_ascending_batch_indices_per_shard() -> None:
    planner = _module()
    batches = _batches(planner, [1.0, 9.0, 5.0, 5.0])
    assignment = planner.assign_shards(batches, 2)
    for indices in assignment:
        assert list(indices) == sorted(indices)


def test_assign_shards_covers_every_batch_exactly_once() -> None:
    planner = _module()
    batches = _batches(planner, [3.0, 1.0, 4.0, 1.0, 5.0, 9.0, 2.0, 6.0])
    assignment = planner.assign_shards(batches, 3)
    flattened = [index for indices in assignment for index in indices]
    assert sorted(flattened) == list(range(len(batches)))


def test_assign_shards_with_one_shard_preserves_the_serial_order() -> None:
    planner = _module()
    batches = _batches(planner, [3.0, 1.0, 4.0])
    assert planner.assign_shards(batches, 1) == ((0, 1, 2),)


def test_assign_shards_beats_round_robin_on_a_skewed_load() -> None:
    planner = _module()
    seconds = [334.0, 160.0, 124.0, 113.0, 112.0, 105.0, 104.0, 89.0]
    batches = _batches(planner, seconds)
    lpt = max(planner.shard_loads(batches, planner.assign_shards(batches, 3)))
    round_robin = tuple(
        tuple(index for index in range(len(seconds)) if index % 3 == shard)
        for shard in range(3)
    )
    assert lpt <= max(planner.shard_loads(batches, round_robin))


def test_assign_shards_rejects_a_non_positive_shard_count() -> None:
    planner = _module()
    with pytest.raises(ValueError):
        planner.assign_shards(_batches(planner, [1.0]), 0)


def test_assign_shards_allows_more_shards_than_batches() -> None:
    planner = _module()
    batches = _batches(planner, [1.0, 2.0])
    assignment = planner.assign_shards(batches, 4)
    assert len(assignment) == 4
    assert sorted(index for indices in assignment for index in indices) == [0, 1]


# --------------------------------------------------------------------------
# Lane planning: one fast interpreter, isolated slow tests
#
# User ruling 2026-09-06: "batching isn't even needed, just batch only the slow
# tests - most of the fast tests can run in one docker image for 10 min and
# then batch only the slow tests."
# --------------------------------------------------------------------------


def test_split_lanes_sends_everything_under_the_threshold_to_the_fast_lane() -> None:
    planner = _module()
    costs = planner.CostTable(
        seconds={"t.py::A::slow": 334.0, "t.py::A::quick": 0.4},
        default_seconds=0.75,
        sources=(),
        measured=2,
    )
    fast, slow = planner.split_lanes(
        ("t.py::A::quick", "t.py::A::slow", "t.py::A::unmeasured"),
        costs=costs,
        threshold_seconds=30.0,
    )
    assert fast == ("t.py::A::quick", "t.py::A::unmeasured")
    assert slow == ("t.py::A::slow",)


def test_split_lanes_treats_an_unmeasured_test_as_fast() -> None:
    planner = _module()
    costs = planner.CostTable(seconds={}, default_seconds=0.75, sources=(), measured=0)
    fast, slow = planner.split_lanes(
        ("t.py::A::a", "t.py::A::b"), costs=costs, threshold_seconds=30.0
    )
    assert slow == ()
    assert fast == ("t.py::A::a", "t.py::A::b")


def test_split_lanes_always_isolates_a_proven_isolated_nodeid() -> None:
    """``ISOLATED_NODEIDS`` is evidence, not cost: commit acd064dda pulled the
    OLLVM fla/bcf oracle out of shared interpreters for memory, and it must
    stay out even when a ledger prices it under the threshold."""
    planner = _module()
    costs = planner.CostTable(
        seconds={"oracle.py::O::big": 1.0}, default_seconds=0.75, sources=(), measured=1
    )
    fast, slow = planner.split_lanes(
        ("t.py::A::a", "oracle.py::O::big"),
        costs=costs,
        threshold_seconds=30.0,
        isolated=frozenset({"oracle.py::O::big"}),
    )
    assert fast == ("t.py::A::a",)
    assert slow == ("oracle.py::O::big",)


def test_plan_lane_batches_puts_the_whole_fast_lane_in_one_interpreter() -> None:
    planner = _module()
    nodeids = tuple(f"t.py::G{index}::test_a" for index in range(500))
    costs = planner.CostTable(seconds={}, default_seconds=0.05, sources=(), measured=0)
    batches = planner.plan_lane_batches(
        nodeids, costs=costs, threshold_seconds=30.0
    )
    assert len(batches) == 1
    assert batches[0].lane == "fast"
    assert batches[0].nodeids == nodeids


def test_plan_lane_batches_gives_each_slow_test_its_own_interpreter() -> None:
    planner = _module()
    nodeids = ("t.py::A::quick", "t.py::B::slow1", "t.py::C::slow2")
    costs = planner.CostTable(
        seconds={"t.py::B::slow1": 334.0, "t.py::C::slow2": 124.0},
        default_seconds=0.4,
        sources=(),
        measured=2,
    )
    batches = planner.plan_lane_batches(nodeids, costs=costs, threshold_seconds=30.0)
    assert [batch.lane for batch in batches] == ["fast", "slow", "slow"]
    assert [batch.nodeids for batch in batches] == [
        ("t.py::A::quick",),
        ("t.py::B::slow1",),
        ("t.py::C::slow2",),
    ]
    assert batches[1].estimated_seconds == pytest.approx(334.0)


def test_plan_lane_batches_emits_no_fast_batch_when_everything_is_slow() -> None:
    planner = _module()
    costs = planner.CostTable(
        seconds={"t.py::A::a": 40.0}, default_seconds=0.4, sources=(), measured=1
    )
    batches = planner.plan_lane_batches(
        ("t.py::A::a",), costs=costs, threshold_seconds=30.0
    )
    assert [batch.lane for batch in batches] == ["slow"]


def test_plan_lane_batches_can_split_an_oversized_fast_lane() -> None:
    """The fast lane is one interpreter by default; ``fast_max_tests`` exists
    only so an operator who *measures* a memory problem can bound it without
    reverting to the fixed split."""
    planner = _module()
    nodeids = tuple(f"t.py::G{index}::test_a" for index in range(10))
    costs = planner.CostTable(seconds={}, default_seconds=0.1, sources=(), measured=0)
    batches = planner.plan_lane_batches(
        nodeids, costs=costs, threshold_seconds=30.0, fast_max_tests=4
    )
    assert [len(batch.nodeids) for batch in batches] == [4, 4, 2]
    assert {batch.lane for batch in batches} == {"fast"}


def test_assign_lane_shards_reserves_shard_zero_for_the_fast_lane() -> None:
    planner = _module()
    batches = (
        planner.PlannedBatch(("fast",), 1500.0, 1, "fast"),
        planner.PlannedBatch(("s1",), 334.0, 1, "slow"),
        planner.PlannedBatch(("s2",), 160.0, 1, "slow"),
        planner.PlannedBatch(("s3",), 124.0, 1, "slow"),
    )
    assignment = planner.assign_lane_shards(batches, 3)
    assert assignment[0] == (0,)
    assert sorted(index for shard in assignment[1:] for index in shard) == [1, 2, 3]


def test_assign_lane_shards_balances_the_slow_lane_by_lpt() -> None:
    planner = _module()
    batches = (planner.PlannedBatch(("fast",), 10.0, 1, "fast"),) + tuple(
        planner.PlannedBatch((f"s{index}",), value, 1, "slow")
        for index, value in enumerate([334.0, 160.0, 124.0, 113.0])
    )
    assignment = planner.assign_lane_shards(batches, 3)
    loads = planner.shard_loads(batches, assignment)
    assert loads[0] == pytest.approx(10.0)
    # 334 | 160+124+113: LPT's makespan on 2 machines, against an ideal of
    # 365.5. The 334 s test is the floor; no assignment beats it.
    assert sorted(loads[1:]) == pytest.approx([334.0, 397.0])


def test_assign_lane_shards_with_one_shard_runs_everything_in_order() -> None:
    planner = _module()
    batches = (
        planner.PlannedBatch(("fast",), 10.0, 1, "fast"),
        planner.PlannedBatch(("s1",), 334.0, 1, "slow"),
    )
    assert planner.assign_lane_shards(batches, 1) == ((0, 1),)


def test_assign_lane_shards_falls_back_to_plain_lpt_without_a_fast_lane() -> None:
    planner = _module()
    batches = tuple(
        planner.PlannedBatch((f"s{index}",), value, 1, "slow")
        for index, value in enumerate([5.0, 5.0, 5.0])
    )
    assignment = planner.assign_lane_shards(batches, 3)
    assert sorted(index for shard in assignment for index in shard) == [0, 1, 2]
    assert planner.shard_loads(batches, assignment) == pytest.approx([5.0, 5.0, 5.0])
