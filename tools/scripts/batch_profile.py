#!/usr/bin/env python3
"""Summarize the per-batch timing JSONL written by run_system_test_batches.py.

Usage::

    python -m tools.scripts.batch_profile <jsonl> [--top N] [--slow-factor F]

Reads ``<jsonl>`` (one JSON object per line, append-only, possibly spanning
multiple runs/resumes distinguished by ``run_id``) and prints:

  (a) total wall time across every recorded batch;
  (b) the top N test FILES by summed duration (from pytest's ``--durations``
      block captured per batch) with cumulative share;
  (c) the top N slowest individual tests;
  (d) batches whose wall time exceeds ``--slow-factor`` times the median
      batch wall time.

Pure stdlib; no third-party dependencies.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from collections.abc import Sequence
import json
import statistics
import sys


def load_records(path: str) -> list[dict]:
    records: list[dict] = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
    return records


def total_wall_seconds(records: Sequence[dict]) -> float:
    return sum(float(record.get("wall_seconds", 0.0)) for record in records)


def _file_of(nodeid: str) -> str:
    return nodeid.split("::", 1)[0]


def top_files_by_duration(
    records: Sequence[dict], limit: int = 20
) -> tuple[list[dict], float]:
    """Rank test files by summed captured duration.

    The denominator is the sum of *captured* per-test durations only (each
    batch's pytest ``--durations`` block is capped, so this undercounts
    total wall time and must not be read as a share of the grand total).
    """
    totals: dict[str, float] = defaultdict(float)
    for record in records:
        for entry in record.get("durations", []):
            totals[_file_of(entry["nodeid"])] += float(entry["seconds"])
    grand_total = sum(totals.values())
    ranked = sorted(totals.items(), key=lambda kv: kv[1], reverse=True)[:limit]
    rows: list[dict] = []
    cumulative = 0.0
    for path, seconds in ranked:
        cumulative += seconds
        share = (seconds / grand_total * 100.0) if grand_total else 0.0
        cumulative_share = (cumulative / grand_total * 100.0) if grand_total else 0.0
        rows.append(
            {
                "file": path,
                "seconds": seconds,
                "share_pct": share,
                "cumulative_share_pct": cumulative_share,
            }
        )
    return rows, grand_total


def top_slowest_tests(records: Sequence[dict], limit: int = 20) -> list[dict]:
    entries: list[dict] = []
    for record in records:
        for entry in record.get("durations", []):
            entries.append(
                {
                    "nodeid": entry["nodeid"],
                    "phase": entry["phase"],
                    "seconds": float(entry["seconds"]),
                    "run_id": record.get("run_id"),
                    "batch_index": record.get("batch_index"),
                }
            )
    entries.sort(key=lambda entry: entry["seconds"], reverse=True)
    return entries[:limit]


def slow_batches(
    records: Sequence[dict], factor: float = 3.0
) -> tuple[list[dict], float]:
    walls = [float(r["wall_seconds"]) for r in records if "wall_seconds" in r]
    if len(walls) < 2:
        return [], (walls[0] if walls else 0.0)
    median = statistics.median(walls)
    threshold = median * factor
    flagged = [r for r in records if float(r.get("wall_seconds", 0.0)) > threshold]
    flagged.sort(key=lambda r: float(r.get("wall_seconds", 0.0)), reverse=True)
    return flagged, median


def _fmt_seconds(seconds: float) -> str:
    return f"{seconds:.2f}s"


def render_report(records: Sequence[dict], top_n: int = 20, factor: float = 3.0) -> str:
    lines: list[str] = []
    run_ids = sorted({r["run_id"] for r in records if r.get("run_id")})
    total = total_wall_seconds(records)

    lines.append("== summary ==")
    lines.append(
        f"batches recorded: {len(records)}  runs: {len(run_ids)}  "
        f"total wall (sum of per-batch wall_seconds): {_fmt_seconds(total)}"
    )
    if run_ids:
        lines.append(f"run_ids: {', '.join(run_ids)}")

    lines.append("")
    lines.append(f"== top {top_n} files by summed captured duration ==")
    file_rows, files_total = top_files_by_duration(records, limit=top_n)
    if not file_rows:
        lines.append("(no --durations entries captured)")
    else:
        lines.append(
            f"(denominator = {_fmt_seconds(files_total)} of captured per-test "
            "duration entries, NOT total wall time)"
        )
        for rank, row in enumerate(file_rows, start=1):
            lines.append(
                f"{rank:2d}. {_fmt_seconds(row['seconds']):>10}  "
                f"{row['share_pct']:5.1f}%  cum {row['cumulative_share_pct']:5.1f}%  "
                f"{row['file']}"
            )

    lines.append("")
    lines.append(f"== top {top_n} slowest individual tests ==")
    slow_tests = top_slowest_tests(records, limit=top_n)
    if not slow_tests:
        lines.append("(no --durations entries captured)")
    else:
        for rank, entry in enumerate(slow_tests, start=1):
            lines.append(
                f"{rank:2d}. {_fmt_seconds(entry['seconds']):>10}  "
                f"{entry['phase']:<8}  {entry['nodeid']}  "
                f"(run={entry['run_id']} batch={entry['batch_index']})"
            )

    lines.append("")
    lines.append(f"== batches slower than {factor:g}x the median batch wall time ==")
    flagged, median = slow_batches(records, factor=factor)
    lines.append(f"median batch wall time: {_fmt_seconds(median)}")
    if not flagged:
        lines.append("(none)")
    else:
        for record in flagged:
            lines.append(
                f"run={record.get('run_id')} "
                f"batch={record.get('batch_index')}/{record.get('batch_total')}  "
                f"wall={_fmt_seconds(float(record.get('wall_seconds', 0.0)))}  "
                f"first={record.get('first_nodeid')}  "
                f"exit={record.get('exit_code')}"
            )

    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("jsonl", help="Path to system_batches.jsonl")
    parser.add_argument("--top", type=int, default=20, help="Rows per top-N section")
    parser.add_argument(
        "--slow-factor",
        type=float,
        default=3.0,
        help="Flag batches slower than this multiple of the median batch wall time",
    )
    args = parser.parse_args(argv)

    try:
        records = load_records(args.jsonl)
    except FileNotFoundError:
        sys.stderr.write(f"[batch-profile] no such file: {args.jsonl}\n")
        return 2

    if not records:
        sys.stderr.write(f"[batch-profile] no batch records found in {args.jsonl}\n")
        return 1

    print(render_report(records, top_n=args.top, factor=args.slow_factor))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
