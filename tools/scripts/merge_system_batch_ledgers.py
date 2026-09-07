#!/usr/bin/env python3
"""Merge per-shard ``system_batches.jsonl`` ledgers into one, and summarise it.

A sharded system run produces one ledger per container. Every consumer of the
ledger (``tools/scripts/batch_profile.py``, the packing cost table in
``system_batch_planner.py``, any wall-time comparison) wants a single file, and
a sharded run's wall time is the *slowest shard*, not the sum of the batches --
reporting the sum would overstate a sharded run by the shard count.

Records are keyed by ``(run_id, shard, batch_index)``; a later record for the
same key supersedes an earlier one, which is what a ``--start-batch`` resume
produces. Records written before sharding existed carry no ``shard`` field and
are read as shard 0, so old ledgers merge and summarise unchanged.
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence
import json
import os
import sys
from typing import NamedTuple

MERGED_FILENAME = "system_batches.jsonl"


class MergeSummary(NamedTuple):
    """What a merged ledger says about the run as a whole."""

    counts: dict[str, int]
    per_shard_wall: dict[int, float]
    critical_path_shard: int | None
    wall_seconds: float
    serial_seconds: float
    failing_batches: tuple[dict, ...]
    batches: int
    tests: int


def _shard_of(record: dict) -> int:
    try:
        return int(record.get("shard", 0) or 0)
    except (TypeError, ValueError):
        return 0


def read_records(path: str) -> tuple[dict, ...]:
    """Return every JSON object in the jsonl at *path* (missing file -> empty)."""
    if not path or not os.path.isfile(path):
        return ()
    records: list[dict] = []
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
                records.append(record)
    return tuple(records)


def merge_records(paths: Sequence[str]) -> tuple[dict, ...]:
    """Merge the ledgers at *paths*, newest record per key winning."""
    latest: dict[tuple[str, int, int], dict] = {}
    order: list[tuple[str, int, int]] = []
    for path in paths:
        for record in read_records(path):
            shard = _shard_of(record)
            record = {**record, "shard": shard}
            try:
                batch_index = int(record.get("batch_index", 0) or 0)
            except (TypeError, ValueError):
                batch_index = 0
            key = (str(record.get("run_id", "")), shard, batch_index)
            if key not in latest:
                order.append(key)
            latest[key] = record
    return tuple(
        latest[key]
        for key in sorted(order, key=lambda key: (key[1], key[2], key[0]))
    )


def summarize(records: Sequence[dict]) -> MergeSummary:
    """Aggregate *records* into the numbers a run report needs."""
    counts: dict[str, int] = {}
    spans: dict[int, list[float]] = {}
    failing: list[dict] = []
    serial_seconds = 0.0
    tests = 0
    for record in records:
        shard = _shard_of(record)
        for label, value in (record.get("counts") or {}).items():
            try:
                counts[label] = counts.get(label, 0) + int(value)
            except (TypeError, ValueError):
                continue
        try:
            start = float(record.get("start_epoch", 0.0))
            end = float(record.get("end_epoch", 0.0))
        except (TypeError, ValueError):
            start = end = 0.0
        bucket = spans.setdefault(shard, [start, end])
        bucket[0] = min(bucket[0], start)
        bucket[1] = max(bucket[1], end)
        try:
            serial_seconds += float(record.get("wall_seconds", 0.0))
        except (TypeError, ValueError):
            pass
        try:
            tests += int(record.get("test_count", 0))
        except (TypeError, ValueError):
            pass
        if int(record.get("exit_code", 0) or 0) != 0:
            failing.append(record)

    per_shard_wall = {shard: end - start for shard, (start, end) in spans.items()}
    critical = (
        max(per_shard_wall, key=lambda shard: (per_shard_wall[shard], -shard))
        if per_shard_wall
        else None
    )
    return MergeSummary(
        counts=counts,
        per_shard_wall=per_shard_wall,
        critical_path_shard=critical,
        wall_seconds=max(per_shard_wall.values()) if per_shard_wall else 0.0,
        serial_seconds=serial_seconds,
        failing_batches=tuple(failing),
        batches=len(records),
        tests=tests,
    )


def render(summary: MergeSummary) -> str:
    """Render *summary* as the block the runner prints after a sharded run."""
    lines = [
        f"[merge] shards={len(summary.per_shard_wall)} "
        f"batches={summary.batches} tests={summary.tests}",
        "[merge] counts: "
        + ", ".join(f"{label}={count}" for label, count in sorted(summary.counts.items())),
        f"[merge] wall={summary.wall_seconds / 60.0:.2f}min "
        f"(serial batch seconds {summary.serial_seconds / 60.0:.2f}min)",
    ]
    for shard in sorted(summary.per_shard_wall):
        marker = " <- critical path" if shard == summary.critical_path_shard else ""
        lines.append(
            f"[merge]   shard {shard}: "
            f"{summary.per_shard_wall[shard] / 60.0:.2f}min{marker}"
        )
    for record in summary.failing_batches:
        lines.append(
            f"[merge] FAILED shard={record.get('shard')} "
            f"batch={record.get('batch_index')} "
            f"exit={record.get('exit_code')} first={record.get('first_nodeid')}"
        )
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, help="Path to write the merged jsonl.")
    parser.add_argument("inputs", nargs="+", help="Per-shard system_batches.jsonl paths.")
    args = parser.parse_args(argv)

    merged = merge_records(args.inputs)
    directory = os.path.dirname(os.path.abspath(args.out))
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as handle:
        for record in merged:
            handle.write(json.dumps(record, sort_keys=True))
            handle.write("\n")

    summary = summarize(merged)
    print(render(summary), flush=True)
    return 1 if summary.failing_batches else 0


if __name__ == "__main__":
    raise SystemExit(main())
