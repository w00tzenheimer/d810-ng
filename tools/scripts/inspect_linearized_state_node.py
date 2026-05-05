#!/usr/bin/env python3
"""Inspect one semantic state node in a Hodur diag DB and optional dump.

Usage:
    python3 tools/scripts/inspect_linearized_state_node.py \
        --db .tmp/logs/d810_logs/0000000180012b60_1776463950_33.diag.sqlite3 \
        --state 0x5FE86821 \
        --dump .tmp/sub7ffd_recon_only_onepass_20260417_1630.txt

The script prints:
1. The latest `semantic_reference_like` context for the requested state label.
2. Matching lines from the dump's `--- AFTER ---` pseudocode region.

This is meant for the node-by-node workflow: pick one exact semantic node,
compare its trusted linearized form against the current CFG/pseudocode, then
design the smallest possible lowering step for that node alone.
"""

from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path
from typing import Iterable


def _normalize_state(text: str) -> tuple[str, str]:
    raw = text.strip().upper()
    if raw.startswith("0X"):
        raw = raw[2:]
    raw = raw.lstrip("0") or "0"
    return raw, f"0x{raw}"


def _latest_semantic_snapshot_id(conn: sqlite3.Connection) -> int | None:
    row = conn.execute(
        """
        SELECT MAX(snapshot_id)
        FROM rendered_program_lines
        WHERE variant_name='semantic_reference_like'
        """
    ).fetchone()
    value = row[0] if row else None
    return int(value) if value is not None else None


def _fetch_lines(
    conn: sqlite3.Connection,
    snapshot_id: int,
    start_line: int,
    end_line: int,
) -> list[tuple[int, str]]:
    rows = conn.execute(
        """
        SELECT line_no, text
        FROM rendered_program_lines
        WHERE snapshot_id=? AND variant_name='semantic_reference_like'
          AND line_no BETWEEN ? AND ?
        ORDER BY line_no
        """,
        (snapshot_id, start_line, end_line),
    ).fetchall()
    return [(int(line_no), str(text)) for line_no, text in rows]


def _find_semantic_context(
    conn: sqlite3.Connection,
    snapshot_id: int,
    state_label: str,
    context: int,
) -> list[tuple[int, str]]:
    row = conn.execute(
        """
        SELECT MIN(line_no), MAX(line_no)
        FROM rendered_program_lines
        WHERE snapshot_id=? AND variant_name='semantic_reference_like'
          AND text LIKE ?
        """,
        (snapshot_id, f"%STATE_{state_label}%"),
    ).fetchone()
    if not row or row[0] is None:
        return []
    start = max(1, int(row[0]) - context)
    end = int(row[1]) + context
    return _fetch_lines(conn, snapshot_id, start, end)


def _extract_after_lines(dump_path: Path) -> list[str]:
    lines = dump_path.read_text().splitlines()
    start = end = None
    for i, line in enumerate(lines):
        if line.strip() == "--- AFTER ---":
            start = i + 1
        elif start is not None and line.startswith("=== STATS:"):
            end = i
            break
    if start is None or end is None or start >= end:
        return []
    return lines[start:end]


def _matching_after_lines(
    after_lines: Iterable[str],
    tokens: Iterable[str],
    context: int,
) -> list[tuple[int, str]]:
    token_list = [token for token in tokens if token]
    indexed = list(enumerate(after_lines, start=1))
    hits = [
        line_no
        for line_no, text in indexed
        if any(token in text for token in token_list)
    ]
    if not hits:
        return []
    selected: set[int] = set()
    for hit in hits:
        for line_no in range(max(1, hit - context), hit + context + 1):
            selected.add(line_no)
    selected_rows = [
        (line_no, text)
        for line_no, text in indexed
        if line_no in selected
    ]
    return selected_rows


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Inspect one semantic state node from the diag DB and compare it "
            "with the dump's AFTER pseudocode."
        )
    )
    parser.add_argument("--db", required=True, help="Path to the diag sqlite DB")
    parser.add_argument("--state", required=True, help="State constant, e.g. 0x5FE86821")
    parser.add_argument(
        "--dump",
        help="Optional dump file to scan inside the AFTER pseudocode region",
    )
    parser.add_argument(
        "--context",
        type=int,
        default=6,
        help="Number of surrounding lines to include around each match",
    )
    args = parser.parse_args()

    state_hex, state_token = _normalize_state(args.state)
    db_path = Path(args.db)
    conn = sqlite3.connect(str(db_path))
    try:
        snapshot_id = _latest_semantic_snapshot_id(conn)
        if snapshot_id is None:
            raise SystemExit("No semantic_reference_like snapshot found")

        print(f"=== semantic_reference_like snapshot {snapshot_id} ===")
        semantic_rows = _find_semantic_context(conn, snapshot_id, state_hex, args.context)
        if not semantic_rows:
            print(f"(no semantic lines for STATE_{state_hex})")
        else:
            for line_no, text in semantic_rows:
                print(f"{line_no:>5}: {text}")
    finally:
        conn.close()

    if args.dump:
        dump_path = Path(args.dump)
        after_lines = _extract_after_lines(dump_path)
        print()
        print(f"=== AFTER matches for {state_token} ===")
        rows = _matching_after_lines(
            after_lines,
            tokens=(
                state_token,
                state_hex,
                f"0x{state_hex.lower()}",
            ),
            context=args.context,
        )
        if not rows:
            print("(no AFTER matches)")
        else:
            for line_no, text in rows:
                print(f"{line_no:>5}: {text}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
