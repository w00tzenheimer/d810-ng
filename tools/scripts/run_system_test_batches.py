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
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
import json
import os
import re
import subprocess
import sys
import time
import uuid


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


def run_batches(
    *,
    python: str,
    root: str,
    pytest_args: Sequence[str],
    batch_size: int,
    start_batch: int = 1,
    run: Run = subprocess.run,
    log_dir: str | None = None,
    run_id: str | None = None,
    durations: int = DEFAULT_DURATIONS,
    now: Callable[[], float] = time.time,
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

    regular_nodeids = tuple(
        nodeid for nodeid in nodeids if nodeid not in ISOLATED_NODEIDS
    )
    isolated_nodeids = tuple(nodeid for nodeid in nodeids if nodeid in ISOLATED_NODEIDS)
    batches = _batches(regular_nodeids, batch_size) + tuple(
        (nodeid,) for nodeid in isolated_nodeids
    )
    if start_batch < 1 or start_batch > len(batches):
        sys.stderr.write(
            f"[system-batch] start_batch={start_batch} outside 1..{len(batches)}\n"
        )
        return 5
    print(
        f"[system-batch] collected={len(nodeids)} "
        f"batch_size={batch_size} batches={len(batches)} "
        f"isolated={len(isolated_nodeids)} "
        f"start_batch={start_batch}",
        flush=True,
    )
    effective_run_id = run_id or f"{time.strftime('%Y%m%dT%H%M%S')}-{uuid.uuid4().hex[:8]}"
    augmented_pytest_args = _augment_pytest_args_with_durations(pytest_args, durations)
    for index, batch in enumerate(batches[start_batch - 1 :], start=start_batch):
        print(
            f"[system-batch {index}/{len(batches)}] "
            f"tests={len(batch)} first={batch[0]}",
            flush=True,
        )
        command = [python, "-m", "pytest", "-v", *batch, *augmented_pytest_args]
        start_epoch = now()
        if log_dir is not None:
            completed = run(command, check=False, capture_output=True, text=True)
            end_epoch = now()
            sys.stdout.write(completed.stdout or "")
            sys.stderr.write(completed.stderr or "")
            combined_output = (completed.stdout or "") + (completed.stderr or "")
            record = {
                "run_id": effective_run_id,
                "batch_index": index,
                "batch_total": len(batches),
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
        if completed.returncode != 0:
            print(
                f"[system-batch {index}/{len(batches)}] "
                f"failed exit={completed.returncode}",
                file=sys.stderr,
                flush=True,
            )
            return int(completed.returncode)

    print(f"[system-batch] completed={len(nodeids)} exit=0", flush=True)
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
    )


if __name__ == "__main__":
    raise SystemExit(main())
