"""Extract the AFTER pseudocode body from a Hodur dump.

The Hodur Docker dump emits the manual-review pseudocode between the
``--- AFTER ---`` marker and the next ``=== STATS:`` block. This module
hosts the pure parser plus a small CLI handler used by the
``dump-after`` subcommand of ``python -m d810.diagnostics``.

The parser is intentionally text-only so it can be unit-tested without
loading sqlite, IDA, or any optimizer code.
"""
from __future__ import annotations

import argparse
from pathlib import Path

from d810.diagnostics.output import add_output_argument, get_output, write_output

START_MARKER = "--- AFTER ---"
END_MARKER_PREFIX = "=== STATS:"


def extract_after_pseudocode(lines: list[str]) -> tuple[int, int]:
    """Return the ``[start, end)`` slice for the AFTER pseudocode body.

    ``start`` is the first body line (one past the ``--- AFTER ---``
    marker). ``end`` is exclusive and points at the next
    ``=== STATS:`` line, or ``len(lines)`` if the dump was truncated.

    Raises:
        ValueError: if no ``--- AFTER ---`` marker is present.
    """
    start: int | None = None
    end: int | None = None

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


def render_after_pseudocode(lines: list[str], *, line_numbers: bool) -> list[str]:
    """Render the AFTER body as a list of output lines.

    When ``line_numbers`` is true, each line is prefixed with the 1-based
    line number from the original dump (matching the legacy
    ``extract_after_pseudocode.py -n`` output format).
    """
    start, end = extract_after_pseudocode(lines)
    out: list[str] = []
    for line_no in range(start, end):
        body = lines[line_no]
        if line_numbers:
            out.append(f"{line_no + 1}: {body}")
        else:
            out.append(body)
    return out


def register_parser(sub) -> None:
    """Register the ``dump-after`` subparser on ``sub``.

    No ``common`` parent: this command is a pure text parser and never
    needs a diag DB, snapshot id, maturity, or phase.
    """
    p = sub.add_parser(
        "dump-after",
        help=(
            "Print the AFTER pseudocode body from a Hodur dump file."
            " Reads the region between '--- AFTER ---' and the next"
            " '=== STATS:' block."
        ),
    )
    p.add_argument(
        "dump_file",
        type=Path,
        help=(
            "Path to the Hodur dump file to inspect; the AFTER pseudocode"
            " region is printed in order."
        ),
    )
    p.add_argument(
        "-n",
        "--line-numbers",
        action="store_true",
        help=(
            "Prefix each emitted line with its 1-based dump-file line"
            " number so manual review findings can be traced back into"
            " the full artifact."
        ),
    )
    add_output_argument(p)


def run(args: argparse.Namespace) -> int:
    """Execute ``dump-after`` from parsed args; return exit code."""
    dump_path: Path = args.dump_file
    try:
        text = dump_path.read_text()
    except FileNotFoundError:
        write_output(get_output(args), f"error: dump file not found: {dump_path}")
        return 1
    lines = text.splitlines()
    try:
        rendered = render_after_pseudocode(lines, line_numbers=args.line_numbers)
    except ValueError as exc:
        write_output(get_output(args), f"error: {exc}")
        return 1
    for line in rendered:
        write_output(get_output(args), line)
    return 0
