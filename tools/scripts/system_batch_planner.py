#!/usr/bin/env python3
"""Cost-aware batch planning and shard assignment for the system suite.

Why this exists
---------------
``run_system_test_batches.py`` originally split the suite into fixed slices of
20 node ids and started one fresh interpreter per slice. The fixed size was
never the point; the *isolation contract* was. From that driver's own
docstring: IDA and Hex-Rays retain native allocations after database teardown,
so one interpreter cannot host the whole suite. What actually opens a database
is ``tests/system/conftest.py``'s **class-scoped** ``ida_database`` fixture, so
the quantity a fresh interpreter has to bound is the number of database-open
groups it hosts, not the number of test functions.

``batch_size=20`` bounded that quantity only incidentally, and at its worst
case: 20 node ids can name at most 20 distinct classes. ``max_group_keys=20``
below bounds exactly the same worst case directly, which makes it never weaker
than the configuration the suite already runs green under -- while letting a
class of 200 cheap parametrizations share a single interpreter instead of
burning ten of them. It is also strictly *cheaper* on database opens, because
a group is never split across a batch boundary (the fixed split routinely cut a
parametrized class in three, paying three ``open_database`` calls for it).

The second bound is cost: a batch stops accumulating once its estimated wall
reaches ``cost_budget_seconds``. That keeps resume granularity useful and gives
``assign_shards`` pieces small enough to balance.

Costs come from the runner's own ledger (``system_batches.jsonl``), so the plan
is measured, not guessed. ``pytest --durations=N`` only reports the slowest N
phases per batch, so most node ids carry no measurement; those are priced from
the batch residual (wall minus measured phases minus the fixed per-interpreter
overhead) spread over the node ids the durations block did not name.

Everything here is pure Python with no IDA, pytest or d810 imports, so it is
unit-tested directly under ``tests/unit/tools/``.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
import json
import math
import os
from typing import NamedTuple

#: Fixed cost of starting one fresh interpreter and importing the system
#: conftest, measured on the 2026-09-06 serial candidate run: 59.01 min wall
#: minus 48.30 min of test seconds over 237 batches = 2.71 s/batch.
DEFAULT_BATCH_OVERHEAD_SECONDS = 2.71

#: Used when no ledger is readable at all, so packing degrades to a pure
#: group/count split rather than failing.
DEFAULT_FALLBACK_SECONDS = 0.75

#: The worst case the historical ``--batch-size 20`` already admitted.
DEFAULT_MAX_GROUP_KEYS = 20

DEFAULT_COST_BUDGET_SECONDS = 120.0

DEFAULT_MAX_TESTS = 400

#: A test at or above this measured cost is isolated instead of joining the
#: fast lane. 30 s selects the 18 tests that hold 45%+ of the suite's test
#: seconds on the 2026-09-06 ledger while leaving 649 of 667 measured tests
#: (and every unmeasured one) in a single interpreter.
DEFAULT_LANE_THRESHOLD_SECONDS = 30.0

#: No budget by default: user ruling 2026-09-06 is that the fast lane stays ONE
#: interpreter and ~20 min is acceptable. Splitting it is available (pass a
#: finite budget, or an explicit lane count) because chunking is what would let
#: shard assignment interleave the fast lane with the slow tests and approach
#: the balance floor -- but it is opt-in, never the default.
DEFAULT_FAST_LANE_BUDGET_SECONDS = math.inf


class CostTable(NamedTuple):
    """Per-node-id cost estimates plus a price for unmeasured node ids."""

    seconds: Mapping[str, float]
    default_seconds: float
    sources: tuple[str, ...]
    measured: int

    def cost_of(self, nodeid: str) -> float:
        """Return the estimated wall seconds for *nodeid*.

        >>> table = CostTable({"a": 3.0}, 0.5, (), 1)
        >>> table.cost_of("a"), table.cost_of("b")
        (3.0, 0.5)
        """
        return self.seconds.get(nodeid, self.default_seconds)


class PlannedBatch(NamedTuple):
    """One fresh interpreter's worth of work.

    ``lane`` is ``"fast"`` for the March-style bulk interpreter and ``"slow"``
    for a test that is isolated on purpose. Batches produced by the fixed and
    cost plans carry the default lane; only ``plan_lane_batches`` sets it
    meaningfully, and only ``assign_lane_shards`` reads it.
    """

    nodeids: tuple[str, ...]
    estimated_seconds: float
    group_keys: int
    lane: str = "fast"


def group_key(nodeid: str) -> str:
    """Return the database-open group a node id belongs to.

    The group is everything before the final ``::`` component, which is the
    scope ``ida_database`` (``scope="class"``) is cached at: a class for tests
    inside one, the module otherwise.

    >>> group_key("tests/system/e2e/test_a.py::TestC::test_x[p1]")
    'tests/system/e2e/test_a.py::TestC'
    >>> group_key("tests/system/e2e/test_a.py::test_x[p]")
    'tests/system/e2e/test_a.py'
    >>> group_key("tests/system/e2e/test_a.py")
    'tests/system/e2e/test_a.py'
    """
    separator = nodeid.rfind("::")
    if separator == -1:
        return nodeid
    return nodeid[:separator]


def file_key(nodeid: str) -> str:
    """Return the test file a node id belongs to.

    Fast-lane chunks are packed by file, never by class: a file is the unit
    module-level state, module-scoped fixtures and import side effects are
    cached at, so splitting one across two interpreters pays for its imports
    twice and can change what the tests see.

    >>> file_key("tests/system/e2e/test_a.py::TestC::test_x[p1]")
    'tests/system/e2e/test_a.py'
    >>> file_key("tests/system/e2e/test_a.py::test_x")
    'tests/system/e2e/test_a.py'
    """
    separator = nodeid.find("::")
    if separator == -1:
        return nodeid
    return nodeid[:separator]


def _iter_ledger_records(path: str) -> Iterable[dict]:
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if isinstance(record, dict):
                yield record


def load_cost_table(
    paths: Sequence[str],
    *,
    batch_overhead_seconds: float = DEFAULT_BATCH_OVERHEAD_SECONDS,
    fallback_seconds: float = DEFAULT_FALLBACK_SECONDS,
) -> CostTable:
    """Build a :class:`CostTable` from one or more ``system_batches.jsonl``.

    Phase seconds are summed per node id inside a record; across records the
    most expensive observation wins, so a plan is never optimistic about a test
    whose cost varies with host load.
    """
    seconds: dict[str, float] = {}
    sources: list[str] = []
    residual_total = 0.0
    unmeasured_total = 0
    for path in paths:
        if not path or not os.path.isfile(path):
            continue
        sources.append(path)
        for record in _iter_ledger_records(path):
            per_nodeid: dict[str, float] = {}
            for entry in record.get("durations", ()) or ():
                nodeid = entry.get("nodeid")
                if not nodeid:
                    continue
                try:
                    value = float(entry.get("seconds", 0.0))
                except (TypeError, ValueError):
                    continue
                per_nodeid[nodeid] = per_nodeid.get(nodeid, 0.0) + value
            for nodeid, value in per_nodeid.items():
                if value > seconds.get(nodeid, 0.0):
                    seconds[nodeid] = value
            try:
                wall = float(record.get("wall_seconds", 0.0))
                test_count = int(record.get("test_count", 0))
            except (TypeError, ValueError):
                continue
            unmeasured = test_count - len(per_nodeid)
            residual = wall - sum(per_nodeid.values()) - batch_overhead_seconds
            if unmeasured > 0 and residual > 0.0:
                residual_total += residual
                unmeasured_total += unmeasured

    if unmeasured_total > 0:
        default_seconds = residual_total / unmeasured_total
    else:
        default_seconds = fallback_seconds
    if default_seconds <= 0.0:
        default_seconds = fallback_seconds
    return CostTable(
        seconds=seconds,
        default_seconds=default_seconds,
        sources=tuple(sources),
        measured=len(seconds),
    )


def _group_runs(nodeids: Sequence[str]) -> list[tuple[str, list[str]]]:
    """Split *nodeids* into consecutive runs sharing one group key."""
    runs: list[tuple[str, list[str]]] = []
    for nodeid in nodeids:
        key = group_key(nodeid)
        if runs and runs[-1][0] == key:
            runs[-1][1].append(nodeid)
        else:
            runs.append((key, [nodeid]))
    return runs


def plan_batches(
    nodeids: Sequence[str],
    *,
    costs: CostTable | None,
    isolated: frozenset[str] = frozenset(),
    max_group_keys: int = DEFAULT_MAX_GROUP_KEYS,
    cost_budget_seconds: float = DEFAULT_COST_BUDGET_SECONDS,
    max_tests: int = DEFAULT_MAX_TESTS,
) -> tuple[PlannedBatch, ...]:
    """Pack *nodeids* into interpreter batches, cheapest plan first.

    Invariants (all unit-tested):

    * collection order is preserved and every node id appears exactly once;
    * a group key is never split across two batches;
    * a batch holds at most *max_group_keys* distinct group keys;
    * a batch's estimated cost stays within *cost_budget_seconds* unless one
      indivisible group already exceeds it, which is how a 334 s test ends up
      alone in its own interpreter;
    * node ids in *isolated* each get their own batch, appended last.
    """
    if max_group_keys < 1:
        raise ValueError("max_group_keys must be positive")
    if max_tests < 1:
        raise ValueError("max_tests must be positive")

    regular = tuple(nodeid for nodeid in nodeids if nodeid not in isolated)
    isolated_ids = tuple(nodeid for nodeid in nodeids if nodeid in isolated)

    batches: list[PlannedBatch] = []
    current: list[str] = []
    current_keys: list[str] = []
    current_cost = 0.0

    def _flush() -> None:
        nonlocal current, current_keys, current_cost
        if current:
            batches.append(
                PlannedBatch(
                    nodeids=tuple(current),
                    estimated_seconds=current_cost,
                    group_keys=len(current_keys),
                )
            )
        current = []
        current_keys = []
        current_cost = 0.0

    for key, members in _group_runs(regular):
        member_cost = (
            sum(costs.cost_of(nodeid) for nodeid in members)
            if costs is not None
            else float(len(members))
        )
        if current:
            over_keys = key not in current_keys and len(current_keys) >= max_group_keys
            over_cost = current_cost + member_cost > cost_budget_seconds
            over_tests = len(current) + len(members) > max_tests
            if over_keys or over_cost or over_tests:
                _flush()
        if key not in current_keys:
            current_keys.append(key)
        current.extend(members)
        current_cost += member_cost
    _flush()

    for nodeid in isolated_ids:
        cost = costs.cost_of(nodeid) if costs is not None else 1.0
        batches.append(
            PlannedBatch(nodeids=(nodeid,), estimated_seconds=cost, group_keys=1)
        )
    return tuple(batches)


def assign_shards(
    batches: Sequence[PlannedBatch], shard_count: int
) -> tuple[tuple[int, ...], ...]:
    """Assign batch indices to *shard_count* shards, longest-processing-time first.

    LPT is the classical 4/3-approximation for makespan on identical machines
    and needs no lookahead, which matters because the shards are independent
    containers that cannot rebalance once started. Ties go to the lowest shard
    index so the assignment is deterministic and reproducible across shards --
    every shard computes the whole assignment locally and then runs only its
    own slice, so a non-deterministic tie-break would silently drop or double
    tests.

    Each shard's indices come back ascending, preserving the serial ordering of
    the work it does own.
    """
    if shard_count < 1:
        raise ValueError("shard_count must be positive")
    buckets: list[list[int]] = [[] for _ in range(shard_count)]
    loads = [0.0] * shard_count
    order = sorted(
        range(len(batches)),
        key=lambda index: (-batches[index].estimated_seconds, index),
    )
    for index in order:
        target = min(range(shard_count), key=lambda shard: (loads[shard], shard))
        buckets[target].append(index)
        loads[target] += batches[index].estimated_seconds
    return tuple(tuple(sorted(bucket)) for bucket in buckets)


def shard_loads(
    batches: Sequence[PlannedBatch], assignment: Sequence[Sequence[int]]
) -> list[float]:
    """Return the estimated wall seconds each shard in *assignment* carries.

    >>> batches = (PlannedBatch(("a",), 3.0, 1), PlannedBatch(("b",), 1.0, 1))
    >>> shard_loads(batches, ((0,), (1,)))
    [3.0, 1.0]
    """
    return [
        sum(batches[index].estimated_seconds for index in indices)
        for indices in assignment
    ]


def split_lanes(
    nodeids: Sequence[str],
    *,
    costs: CostTable,
    threshold_seconds: float = DEFAULT_LANE_THRESHOLD_SECONDS,
    isolated: frozenset[str] = frozenset(),
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Split *nodeids* into (fast, slow), preserving collection order.

    A node id is slow when its *measured* cost reaches *threshold_seconds*, or
    when it is named in *isolated*. Anything the ledger never measured is fast:
    ``pytest --durations`` only reports the slowest phases, so "unmeasured"
    already means "not among the slowest", and pricing it as slow would empty
    the fast lane on the first run against a missing ledger.
    """
    fast: list[str] = []
    slow: list[str] = []
    for nodeid in nodeids:
        if nodeid in isolated or costs.seconds.get(nodeid, 0.0) >= threshold_seconds:
            slow.append(nodeid)
        else:
            fast.append(nodeid)
    return tuple(fast), tuple(slow)


def plan_lane_batches(
    nodeids: Sequence[str],
    *,
    costs: CostTable,
    threshold_seconds: float = DEFAULT_LANE_THRESHOLD_SECONDS,
    isolated: frozenset[str] = frozenset(),
    fast_max_tests: int | None = None,
    fast_lanes: int | None = None,
    fast_lane_budget_seconds: float = DEFAULT_FAST_LANE_BUDGET_SECONDS,
) -> tuple[PlannedBatch, ...]:
    """Plan one fast interpreter plus one interpreter per slow test.

    This is the shape the March 2026 suite had (1953 tests, one pytest process,
    499.82 s) with the one concession the intervening year proved necessary:
    the handful of tests that are individually expensive, and the node ids
    commit acd064dda isolated for memory, do not share that process.

    *fast_max_tests* is deliberately ``None`` by default. If the single fast
    interpreter reproduces the failure ``d86971ad9`` was written against
    (unbounded RSS after ``idapro.close_database``), that is a finding to
    report with the offending file, not something to paper over by re-batching.
    """
    fast, slow = split_lanes(
        nodeids,
        costs=costs,
        threshold_seconds=threshold_seconds,
        isolated=isolated,
    )
    batches: list[PlannedBatch] = []
    if fast:
        chunks = pack_fast_lane(
            fast,
            costs=costs,
            budget_seconds=fast_lane_budget_seconds,
            lanes=fast_lanes,
        )
        if fast_max_tests is not None:
            bound = max(1, fast_max_tests)
            chunks = tuple(
                chunk[start : start + bound]
                for chunk in chunks
                for start in range(0, len(chunk), bound)
            )
        for piece in chunks:
            batches.append(
                PlannedBatch(
                    nodeids=piece,
                    estimated_seconds=sum(costs.cost_of(nodeid) for nodeid in piece),
                    group_keys=len({group_key(nodeid) for nodeid in piece}),
                    lane="fast",
                )
            )
    for nodeid in slow:
        batches.append(
            PlannedBatch(
                nodeids=(nodeid,),
                estimated_seconds=costs.cost_of(nodeid),
                group_keys=1,
                lane="slow",
            )
        )
    return tuple(batches)


def pack_fast_lane(
    nodeids: Sequence[str],
    *,
    costs: CostTable,
    budget_seconds: float = DEFAULT_FAST_LANE_BUDGET_SECONDS,
    lanes: int | None = None,
) -> tuple[tuple[str, ...], ...]:
    """Split the fast lane into chunks of at most *budget_seconds*, by file.

    A single fast interpreter makes the fast lane's own cost the floor on the
    whole run's critical path, however many shards there are. Chunking it lets
    ``assign_shards`` interleave the pieces with the slow lane and approach the
    balance floor instead.

    With *lanes* unset the chunk count is the smallest K that fits the budget,
    starting from ``ceil(total / budget)`` and growing only while a chunk is
    still over budget and there are files left to separate. A file is never
    split, so a single file costing more than the budget simply exceeds it --
    that is a fact about the file, and splitting it would cost its imports
    twice without fixing anything.
    """
    if not nodeids:
        return ()
    files: list[str] = []
    members: dict[str, list[str]] = {}
    for nodeid in nodeids:
        key = file_key(nodeid)
        if key not in members:
            members[key] = []
            files.append(key)
        members[key].append(nodeid)
    weights = {
        key: sum(costs.cost_of(nodeid) for nodeid in group)
        for key, group in members.items()
    }
    total = sum(weights.values())

    def _pack(count: int) -> tuple[tuple[str, ...], ...]:
        buckets: list[list[str]] = [[] for _ in range(count)]
        loads = [0.0] * count
        for key in sorted(files, key=lambda name: (-weights[name], files.index(name))):
            target = min(range(count), key=lambda index: (loads[index], index))
            buckets[target].append(key)
            loads[target] += weights[key]
        packed = []
        for bucket in buckets:
            ordered = [key for key in files if key in set(bucket)]
            packed.append(tuple(nodeid for key in ordered for nodeid in members[key]))
        return tuple(chunk for chunk in packed if chunk)

    if lanes is not None:
        if lanes < 1:
            raise ValueError("lanes must be positive")
        return _pack(min(lanes, len(files)))

    if budget_seconds <= 0.0:
        raise ValueError("budget_seconds must be positive")
    count = max(1, math.ceil(total / budget_seconds))
    count = min(count, len(files))
    while True:
        chunks = _pack(count)
        over = max(
            sum(costs.cost_of(nodeid) for nodeid in chunk) for chunk in chunks
        )
        if over <= budget_seconds or count >= len(files):
            return chunks
        count += 1
