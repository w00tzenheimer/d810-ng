#!/usr/bin/env python3
"""Run IDA system tests in fresh, bounded interpreter batches.

IDA and Hex-Rays retain native allocations after database teardown. A single
pytest process for the complete system suite eventually reaches the container
memory limit, while ``pytest-forked`` is unsafe after the IDA runtime has been
initialized. This driver collects node IDs once, then starts a clean Python
process for each bounded batch and propagates the first failing status.

When ``log_dir`` is supplied, each batch also appends one JSON line to
``<log_dir>/system_batches.jsonl`` recording wall time, the parsed pytest
summary counts, and the slowest per-test durations (via ``--durations``), so
a full suite run produces its own time profile. See
``tools/scripts/batch_profile.py`` for the report reader.

Two opt-in levers sit on top of the fixed split, both off by default so an
unadorned invocation behaves exactly as before:

``--plan lane`` (the shape the suite is meant to run in)
    One interpreter for every test the ledger prices under
    ``--lane-threshold-seconds`` (30 s), March-style, plus one interpreter per
    slow test. ``--plan cost`` is the intermediate shape: cost-aware packing
    that still bounds database-open groups per interpreter. ``--plan fixed``
    (the default) is the historical ``--batch-size`` split.

``--shard-count N`` / ``--shard-index K``
    Every shard collects and plans the *same* batches, assigns them to N shards
    with longest-processing-time-first, and runs only its own. There is no
    coordination between shards: the plan is a pure function of the collected
    node ids and the cost ledger, so N containers agree on it independently.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
import json
import os
import re
import subprocess
import sys
import threading
import time
import uuid

# The planner is a sibling script, not an installed package: this driver runs
# inside the IDA container as a plain path (``$PYTHON tools/scripts/...``), so
# its directory is on sys.path already; the insert only covers loaders that do
# not set sys.path[0] (importlib.spec_from_file_location, python -P).
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if _SCRIPT_DIR not in sys.path:
    sys.path.insert(0, _SCRIPT_DIR)

import system_batch_planner as planner  # noqa: E402


Run = Callable[..., subprocess.CompletedProcess]

ISOLATED_NODEIDS = frozenset(
    {
        "tests/system/e2e/test_ollvm_fla_bcf_sub_oracle.py::"
        "TestOllvmFlaBcfSubOracle::test_fla_bcf_sub_oracle",
    }
)

DEFAULT_DURATIONS = 25
BATCH_LOG_FILENAME = "system_batches.jsonl"

_SUMMARY_LINE_RE = re.compile(
    r"=*\s*(?P<counts>\d+\s+\w+(?:,\s*\d+\s+\w+)*)\s+in\s+"
    r"(?P<seconds>[\d.]+)s(?:\s*\([^)]*\))?\s*=*\s*$"
)
_SUMMARY_ENTRY_RE = re.compile(r"(\d+)\s+([a-zA-Z]+)")
_DURATIONS_HEADER_RE = re.compile(r"=+\s*slowest\s+\d+\s+durations\s*=+")
_DURATION_LINE_RE = re.compile(r"^\s*([\d.]+)s\s+(setup|call|teardown)\s+(\S+)\s*$")


def parse_collected_nodeids(output: str) -> tuple[str, ...]:
    return tuple(
        line.strip()
        for line in output.splitlines()
        if line.startswith("tests/") and "::" in line
    )


def parse_pytest_summary_counts(output: str) -> dict[str, int]:
    """Return category counts parsed from pytest's final summary line.

    Recognizes lines such as::

        ============== 1 failed, 1 passed, 1 skipped, 1 xfailed in 0.18s ===============
        668 passed in 29.57s

    Returns an empty dict when no summary line is found (e.g. a crashed
    subprocess with no pytest output at all).
    """
    counts: dict[str, int] = {}
    for line in reversed(output.splitlines()):
        match = _SUMMARY_LINE_RE.search(line.strip())
        if not match:
            continue
        for entry_match in _SUMMARY_ENTRY_RE.finditer(match.group("counts")):
            count, label = entry_match.groups()
            counts[label] = counts.get(label, 0) + int(count)
        return counts
    return counts


def parse_pytest_durations(output: str) -> list[dict[str, float | str]]:
    """Return the slowest-durations block pytest prints for ``--durations``.

    Each entry is ``{"nodeid": str, "phase": "setup"|"call"|"teardown",
    "seconds": float}``. Returns an empty list when the block is absent or
    every duration was below the hidden threshold.
    """
    lines = output.splitlines()
    start = None
    for index, line in enumerate(lines):
        if _DURATIONS_HEADER_RE.search(line.strip()):
            start = index + 1
            break
    if start is None:
        return []

    durations: list[dict[str, float | str]] = []
    for line in lines[start:]:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("=") or stripped.startswith("("):
            break
        match = _DURATION_LINE_RE.match(line)
        if not match:
            break
        seconds_str, phase, nodeid = match.groups()
        durations.append(
            {"nodeid": nodeid, "phase": phase, "seconds": float(seconds_str)}
        )
    return durations


def _augment_pytest_args_with_durations(
    pytest_args: Sequence[str], durations: int
) -> tuple[str, ...]:
    if durations <= 0:
        return tuple(pytest_args)
    if any(
        arg == "--durations" or arg.startswith("--durations=") for arg in pytest_args
    ):
        return tuple(pytest_args)
    return tuple(pytest_args) + (f"--durations={durations}",)


def _stream_and_capture(
    command: Sequence[str],
    *,
    popen: Callable[..., subprocess.Popen] = subprocess.Popen,
    stdout_sink=None,
    stderr_sink=None,
) -> subprocess.CompletedProcess:
    """Run *command*, tee-ing stdout/stderr to the parent live while also
    capturing full text for the ``--durations`` and jsonl-record parsers.

    A 20-minute batch previously produced no output at all until it exited
    (``capture_output=True`` buffers everything), which looked hung. This
    reads both pipes concurrently in dedicated threads -- never sequentially
    -- so a full buffer on one stream can never block progress on the other,
    and writes each line to the parent as soon as it arrives.
    """
    out_sink = stdout_sink if stdout_sink is not None else sys.stdout
    err_sink = stderr_sink if stderr_sink is not None else sys.stderr
    process = popen(
        list(command),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    captured: dict[str, list[str]] = {"stdout": [], "stderr": []}

    def _pump(pipe, sink, key: str) -> None:
        try:
            for line in iter(pipe.readline, ""):
                sink.write(line)
                sink.flush()
                captured[key].append(line)
        finally:
            pipe.close()

    threads = (
        threading.Thread(target=_pump, args=(process.stdout, out_sink, "stdout")),
        threading.Thread(target=_pump, args=(process.stderr, err_sink, "stderr")),
    )
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    returncode = process.wait()
    return subprocess.CompletedProcess(
        list(command),
        returncode,
        stdout="".join(captured["stdout"]),
        stderr="".join(captured["stderr"]),
    )


def _write_batch_record(log_dir: str, record: dict) -> None:
    os.makedirs(log_dir, exist_ok=True)
    path = os.path.join(log_dir, BATCH_LOG_FILENAME)
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True))
        handle.write("\n")


def _batches(values: Sequence[str], size: int) -> tuple[tuple[str, ...], ...]:
    if size < 1:
        raise ValueError("batch size must be positive")
    return tuple(
        tuple(values[index : index + size]) for index in range(0, len(values), size)
    )


PLAN_MODES = ("fixed", "cost", "lane")


def _plan(
    nodeids: Sequence[str],
    *,
    batch_size: int,
    plan: str,
    costs: planner.CostTable,
    cost_budget_seconds: float,
    max_group_keys: int,
    max_tests: int,
    lane_threshold_seconds: float,
    fast_max_tests: int | None,
) -> tuple[planner.PlannedBatch, ...]:
    """Return the batch plan for *plan* mode.

    Every shape comes back as ``PlannedBatch`` so shard assignment can price a
    fixed-size split too: without a ledger every node id costs the same, which
    makes the LPT assignment fall back to balancing test counts.
    """
    if plan == "lane":
        return planner.plan_lane_batches(
            nodeids,
            costs=costs,
            threshold_seconds=lane_threshold_seconds,
            isolated=frozenset(ISOLATED_NODEIDS),
            fast_max_tests=fast_max_tests,
        )
    if plan == "cost":
        return planner.plan_batches(
            nodeids,
            costs=costs,
            isolated=frozenset(ISOLATED_NODEIDS),
            max_group_keys=max_group_keys,
            cost_budget_seconds=cost_budget_seconds,
            max_tests=max_tests,
        )
    regular_nodeids = tuple(
        nodeid for nodeid in nodeids if nodeid not in ISOLATED_NODEIDS
    )
    isolated_nodeids = tuple(nodeid for nodeid in nodeids if nodeid in ISOLATED_NODEIDS)
    slices = _batches(regular_nodeids, batch_size) + tuple(
        (nodeid,) for nodeid in isolated_nodeids
    )
    return tuple(
        planner.PlannedBatch(
            nodeids=batch,
            estimated_seconds=sum(costs.cost_of(nodeid) for nodeid in batch),
            group_keys=len({planner.group_key(nodeid) for nodeid in batch}),
        )
        for batch in slices
    )


def run_batches(
    *,
    python: str,
    root: str,
    pytest_args: Sequence[str],
    batch_size: int,
    start_batch: int = 1,
    run: Run = subprocess.run,
    popen: Callable[..., subprocess.Popen] = subprocess.Popen,
    log_dir: str | None = None,
    run_id: str | None = None,
    durations: int = DEFAULT_DURATIONS,
    now: Callable[[], float] = time.time,
    plan: str = "fixed",
    cost_ledgers: Sequence[str] = (),
    lane_threshold_seconds: float = planner.DEFAULT_LANE_THRESHOLD_SECONDS,
    fast_max_tests: int | None = None,
    cost_budget_seconds: float = planner.DEFAULT_COST_BUDGET_SECONDS,
    max_group_keys: int = planner.DEFAULT_MAX_GROUP_KEYS,
    max_tests: int = planner.DEFAULT_MAX_TESTS,
    shard_index: int = 0,
    shard_count: int = 1,
) -> int:
    collect_command = [
        python,
        "-m",
        "pytest",
        "--collect-only",
        "-q",
        root,
        *pytest_args,
    ]
    collected = run(collect_command, check=False, capture_output=True, text=True)
    if collected.returncode != 0:
        sys.stdout.write(collected.stdout or "")
        sys.stderr.write(collected.stderr or "")
        return int(collected.returncode)

    nodeids = parse_collected_nodeids(collected.stdout)
    if not nodeids:
        sys.stderr.write("[system-batch] collection selected no tests\n")
        return 5

    if shard_count < 1 or not 0 <= shard_index < shard_count:
        sys.stderr.write(
            f"[system-batch] shard_index={shard_index} outside "
            f"0..{shard_count - 1}\n"
        )
        return 5

    if plan not in PLAN_MODES:
        sys.stderr.write(f"[system-batch] unknown plan mode: {plan}\n")
        return 5
    costs = planner.load_cost_table(tuple(cost_ledgers))
    planned = _plan(
        nodeids,
        batch_size=batch_size,
        plan=plan,
        costs=costs,
        cost_budget_seconds=cost_budget_seconds,
        max_group_keys=max_group_keys,
        max_tests=max_tests,
        lane_threshold_seconds=lane_threshold_seconds,
        fast_max_tests=fast_max_tests,
    )
    if plan == "lane":
        assignment = planner.assign_lane_shards(planned, shard_count)
    else:
        assignment = planner.assign_shards(planned, shard_count)
    owned = assignment[shard_index]
    batches = tuple(planned[index] for index in owned)
    isolated_nodeids = tuple(nodeid for nodeid in nodeids if nodeid in ISOLATED_NODEIDS)
    if start_batch < 1 or start_batch > max(len(batches), 1):
        sys.stderr.write(
            f"[system-batch] start_batch={start_batch} outside 1..{len(batches)}\n"
        )
        return 5
    loads = planner.shard_loads(planned, assignment)
    print(
        f"[system-batch] collected={len(nodeids)} "
        f"plan={plan} batch_size={batch_size} "
        f"planned_batches={len(planned)} "
        f"shard={shard_index}/{shard_count} batches={len(batches)} "
        f"estimated={loads[shard_index]:.1f}s "
        f"cost_sources={len(costs.sources)} measured={costs.measured} "
        f"default_cost={costs.default_seconds:.3f}s "
        f"isolated={len(isolated_nodeids)} "
        f"start_batch={start_batch}",
        flush=True,
    )
    effective_run_id = run_id or f"{time.strftime('%Y%m%dT%H%M%S')}-{uuid.uuid4().hex[:8]}"
    augmented_pytest_args = _augment_pytest_args_with_durations(pytest_args, durations)
    ran = 0
    for index, planned_batch in enumerate(batches[start_batch - 1 :], start=start_batch):
        batch = planned_batch.nodeids
        global_index = owned[index - 1] + 1
        print(
            f"[system-batch {index}/{len(batches)}] "
            f"shard={shard_index} global={global_index}/{len(planned)} "
            f"lane={planned_batch.lane} "
            f"tests={len(batch)} groups={planned_batch.group_keys} "
            f"estimated={planned_batch.estimated_seconds:.1f}s first={batch[0]}",
            flush=True,
        )
        command = [python, "-m", "pytest", "-v", *batch, *augmented_pytest_args]
        start_epoch = now()
        if log_dir is not None:
            completed = _stream_and_capture(command, popen=popen)
            end_epoch = now()
            combined_output = (completed.stdout or "") + (completed.stderr or "")
            record = {
                "run_id": effective_run_id,
                "shard": shard_index,
                "shard_count": shard_count,
                "batch_index": index,
                "batch_total": len(batches),
                "global_batch_index": global_index,
                "global_batch_total": len(planned),
                "estimated_seconds": planned_batch.estimated_seconds,
                "lane": planned_batch.lane,
                "first_nodeid": batch[0],
                "test_count": len(batch),
                "start_epoch": start_epoch,
                "end_epoch": end_epoch,
                "wall_seconds": end_epoch - start_epoch,
                "exit_code": int(completed.returncode),
                "counts": parse_pytest_summary_counts(combined_output),
                "durations": parse_pytest_durations(combined_output),
            }
            _write_batch_record(log_dir, record)
        else:
            completed = run(command, check=False)
        ran += len(batch)
        if completed.returncode != 0:
            print(
                f"[system-batch {index}/{len(batches)}] "
                f"shard={shard_index} failed exit={completed.returncode}",
                file=sys.stderr,
                flush=True,
            )
            return int(completed.returncode)

    print(
        f"[system-batch] shard={shard_index}/{shard_count} completed={ran} exit=0",
        flush=True,
    )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root")
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--batch-size", type=int, default=20)
    parser.add_argument("--start-batch", type=int, default=1)
    parser.add_argument(
        "--log-dir",
        default=None,
        help=(
            "Directory to append system_batches.jsonl timing records to. "
            "Defaults to no timing log (pass ~/.idapro/logs/d810_logs to "
            "match the diagnostic-snapshot convention)."
        ),
    )
    parser.add_argument(
        "--run-id",
        default=None,
        help="Explicit run id to group jsonl records; defaults to a fresh id.",
    )
    parser.add_argument(
        "--durations",
        type=int,
        default=DEFAULT_DURATIONS,
        help="pytest --durations=N to request per batch (0 disables).",
    )
    parser.add_argument(
        "--plan",
        choices=PLAN_MODES,
        default="fixed",
        help=(
            "fixed: the historical --batch-size split (default). "
            "cost: cost-aware packing bounded by database-open groups. "
            "lane: one interpreter for every test under "
            "--lane-threshold-seconds plus one per slow test."
        ),
    )
    parser.add_argument(
        "--lane-threshold-seconds",
        type=float,
        default=planner.DEFAULT_LANE_THRESHOLD_SECONDS,
        help="Measured cost at which a test leaves the fast lane (--plan lane).",
    )
    parser.add_argument(
        "--fast-max-tests",
        type=int,
        default=None,
        help=(
            "Bound the fast lane to N tests per interpreter. Unset by default: "
            "a fast lane that runs out of memory is a finding to report, not "
            "something to silently re-batch."
        ),
    )
    parser.add_argument(
        "--cost-ledger",
        action="append",
        default=[],
        dest="cost_ledgers",
        help=(
            "system_batches.jsonl to price tests from; repeatable. Absent files "
            "are ignored and packing degrades to a uniform-cost group split."
        ),
    )
    parser.add_argument(
        "--cost-budget-seconds",
        type=float,
        default=planner.DEFAULT_COST_BUDGET_SECONDS,
        help="Estimated wall a packed batch may reach before it is closed.",
    )
    parser.add_argument(
        "--max-group-keys",
        type=int,
        default=planner.DEFAULT_MAX_GROUP_KEYS,
        help=(
            "Database-open groups (class scopes) one interpreter may host. "
            "20 reproduces the worst case --batch-size 20 already admitted."
        ),
    )
    parser.add_argument(
        "--max-tests",
        type=int,
        default=planner.DEFAULT_MAX_TESTS,
        help="Hard cap on node ids per packed batch (resume granularity).",
    )
    parser.add_argument(
        "--shard-index",
        type=int,
        default=0,
        help="0-based index of this shard within --shard-count.",
    )
    parser.add_argument(
        "--shard-count",
        type=int,
        default=1,
        help=(
            "Number of shards the plan is split across. 1 (the default) runs "
            "every batch, which is the historical behaviour."
        ),
    )
    parser.add_argument("pytest_args", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    pytest_args = tuple(args.pytest_args)
    if pytest_args[:1] == ("--",):
        pytest_args = pytest_args[1:]
    return run_batches(
        python=args.python,
        root=args.root,
        pytest_args=pytest_args,
        batch_size=args.batch_size,
        start_batch=args.start_batch,
        log_dir=args.log_dir,
        run_id=args.run_id,
        durations=args.durations,
        plan=args.plan,
        cost_ledgers=tuple(args.cost_ledgers),
        lane_threshold_seconds=args.lane_threshold_seconds,
        fast_max_tests=args.fast_max_tests,
        cost_budget_seconds=args.cost_budget_seconds,
        max_group_keys=args.max_group_keys,
        max_tests=args.max_tests,
        shard_index=args.shard_index,
        shard_count=args.shard_count,
    )


if __name__ == "__main__":
    raise SystemExit(main())
