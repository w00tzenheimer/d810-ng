#!/usr/bin/env python3
"""Extract the manual-review pseudocode body from a Hodur dump file.

This prints the lines between the ``--- AFTER ---`` marker and the following
``=== STATS:`` block. Pass the dump file path as the positional argument so the
review target is explicit and never hardcoded.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


START_MARKER = "--- AFTER ---"
END_MARKER_PREFIX = "=== STATS:"


def extract_after_pseudocode(lines: list[str]) -> tuple[int, int]:
    """Return the [start, end) slice for the AFTER pseudocode body."""
    start = None
    end = None

    for index, raw in enumerate(lines):
        if raw.strip() == START_MARKER:
            start = index + 1
            continue
        if start is not None and raw.startswith(END_MARKER_PREFIX):
            end = index
            break

    if start is None:
        raise ValueError(f"missing start marker: {START_MARKER!r}")
    if end is None:
        end = len(lines)
    return start, end


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Print the AFTER pseudocode body from a Hodur dump file for manual "
            "review. Reads the region between '--- AFTER ---' and the next "
            "'=== STATS:' block."
        ),
    )
    parser.add_argument(
        "dump_file",
        type=Path,
        help=(
            "Path to the Hodur dump file to inspect; the script extracts the "
            "pseudocode between '--- AFTER ---' and '=== STATS:' from this file"
        ),
    )
    parser.add_argument(
        "-n",
        "--line-numbers",
        action="store_true",
        help=(
            "Prefix emitted lines with 1-based dump-file line numbers so manual "
            "review findings can be traced back into the full artifact"
        ),
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        lines = args.dump_file.read_text().splitlines()
        start, end = extract_after_pseudocode(lines)
    except FileNotFoundError:
        print(f"error: dump file not found: {args.dump_file}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    for line_no in range(start, end):
        line = lines[line_no]
        if args.line_numbers:
            print(f"{line_no + 1}: {line}")
        else:
            print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
