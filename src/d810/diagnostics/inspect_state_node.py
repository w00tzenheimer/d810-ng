"""Inspect one semantic state node in a Hodur diag DB and optional dump.

The ``inspect-state-node`` diagnostics subcommand prints:

1. The latest ``semantic_reference_like`` rendered-program context for the
   requested state label.
2. Optional matching lines from the ``--- AFTER ---`` pseudocode region
   of a dump file.

This supports the node-by-node lowering workflow: pick one exact
semantic node, compare its trusted linearized form against the current
CFG/pseudocode, then design the smallest possible lowering step.
"""
from __future__ import annotations

import argparse
import sqlite3
from collections.abc import Iterable
from pathlib import Path

from d810._vendor.peewee import fn
from d810.core.diag import open_diag_database
from d810.core.diag.models import RenderedProgramLine
from d810.diagnostics.output import add_output_argument, get_output, write_output
from d810.diagnostics.dump_after import extract_after_pseudocode



def normalize_state(text: str) -> tuple[str, str]:
    """Return ``(canonical_hex_no_prefix, "0x"+canonical)`` for ``text``.

    Strips ``0x`` prefix, upper-cases, and trims leading zeros to a single
    ``"0"`` minimum. ``normalize_state("0x05fe86821")`` is ``("5FE86821",
    "0x5FE86821")``; ``normalize_state("0")`` is ``("0", "0x0")``.
    """
    raw = text.strip().upper()
    if raw.startswith("0X"):
        raw = raw[2:]
    raw = raw.lstrip("0") or "0"
    return raw, f"0x{raw}"


def latest_semantic_snapshot_id(conn: sqlite3.Connection) -> int | None:
    """Return the highest snapshot_id with ``semantic_reference_like`` lines,
    or ``None`` if no such snapshot exists in the DB.
    """
    value = (
        RenderedProgramLine.select(fn.MAX(RenderedProgramLine.snapshot_id))
        .where(RenderedProgramLine.variant_name == "semantic_reference_like")
        .scalar()
    )
    return int(value) if value is not None else None


def _fetch_lines(
    conn: sqlite3.Connection,
    snapshot_id: int,
    start_line: int,
    end_line: int,
) -> list[tuple[int, str]]:
    rows = (
        RenderedProgramLine.select(
            RenderedProgramLine.line_no, RenderedProgramLine.text
        )
        .where(
            (RenderedProgramLine.snapshot_id == snapshot_id)
            & (RenderedProgramLine.variant_name == "semantic_reference_like")
            & (RenderedProgramLine.line_no.between(start_line, end_line))
        )
        .order_by(RenderedProgramLine.line_no)
        .tuples()
    )
    return [(int(line_no), str(text)) for line_no, text in rows]


def find_semantic_context(
    conn: sqlite3.Connection,
    snapshot_id: int,
    state_label: str,
    context: int,
) -> list[tuple[int, str]]:
    """Return ``[(line_no, text), ...]`` for the semantic snapshot lines
    containing ``STATE_<state_label>``, with ``context`` lines on each side.

    Returns ``[]`` when no semantic line mentions the state.
    """
    row = (
        RenderedProgramLine.select(
            fn.MIN(RenderedProgramLine.line_no),
            fn.MAX(RenderedProgramLine.line_no),
        )
        .where(
            (RenderedProgramLine.snapshot_id == snapshot_id)
            & (RenderedProgramLine.variant_name == "semantic_reference_like")
            # ``**`` is peewee's ILIKE -> SQLite ``LIKE`` (``%`` map gives
            # GLOB on SQLite); pattern kept verbatim so the ``_`` after
            # ``STATE`` stays a LIKE wildcard exactly like the raw query.
            & (RenderedProgramLine.text ** f"%STATE_{state_label}%")
        )
        .tuples()
        .first()
    )
    if not row or row[0] is None:
        return []
    start = max(1, int(row[0]) - context)
    end = int(row[1]) + context
    return _fetch_lines(conn, snapshot_id, start, end)


def extract_after_lines(dump_path: Path) -> list[str]:
    """Return the body of the AFTER pseudocode region, or ``[]`` if missing.

    Wraps the pure parser from ``dump_after`` so the marker logic stays
    in one place.
    """
    lines = dump_path.read_text().splitlines()
    try:
        start, end = extract_after_pseudocode(lines)
    except ValueError:
        return []
    if start >= end:
        return []
    return lines[start:end]


def matching_after_lines(
    after_lines: Iterable[str],
    tokens: Iterable[str],
    context: int,
) -> list[tuple[int, str]]:
    """Return ``[(line_no, text), ...]`` for AFTER lines containing any
    ``token``, plus ``context`` neighbours on each side.

    ``line_no`` is 1-based relative to the AFTER region (NOT the original
    dump file), matching the legacy script.
    """
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
    return [(line_no, text) for line_no, text in indexed if line_no in selected]


def register_parser(sub) -> None:
    """Register the ``inspect-state-node`` subparser.

    No ``common`` parent: state-node inspection takes its own ``--db``
    (different default semantics than the diag DB heuristic) and never
    consults the snapshot/maturity/phase resolver.
    """
    p = sub.add_parser(
        "inspect-state-node",
        help=(
            "Inspect one semantic state node from the diag DB and"
            " optionally cross-reference the AFTER pseudocode of a dump."
        ),
    )
    p.add_argument("--db", required=True, help="Path to the diag sqlite DB")
    p.add_argument("--state", required=True, help="State constant, e.g. 0x5FE86821")
    p.add_argument(
        "--dump",
        default=None,
        help="Optional dump file to scan inside the AFTER pseudocode region",
    )
    p.add_argument(
        "--context",
        type=int,
        default=6,
        help="Number of surrounding lines to include around each match",
    )
    add_output_argument(p)


def run(args: argparse.Namespace) -> int:
    """Execute ``inspect-state-node`` from parsed args; return exit code."""
    state_hex, state_token = normalize_state(args.state)
    db_path = Path(args.db)
    if not db_path.exists():
        write_output(get_output(args), f"error: db not found: {db_path}")
        return 2
    db = open_diag_database(str(db_path))
    conn = db.connection()
    try:
        snapshot_id = latest_semantic_snapshot_id(conn)
        if snapshot_id is None:
            write_output(get_output(args), "error: no semantic_reference_like snapshot found")
            return 2

        write_output(get_output(args), f"=== semantic_reference_like snapshot {snapshot_id} ===")
        semantic_rows = find_semantic_context(
            conn, snapshot_id, state_hex, args.context,
        )
        if not semantic_rows:
            write_output(get_output(args), f"(no semantic lines for STATE_{state_hex})")
        else:
            for line_no, text in semantic_rows:
                write_output(get_output(args), f"{line_no:>5}: {text}")
    finally:
        db.close()

    if args.dump:
        dump_path = Path(args.dump)
        after_lines = extract_after_lines(dump_path)
        write_output(get_output(args))
        write_output(get_output(args), f"=== AFTER matches for {state_token} ===")
        rows = matching_after_lines(
            after_lines,
            tokens=(
                state_token,
                state_hex,
                f"0x{state_hex.lower()}",
            ),
            context=args.context,
        )
        if not rows:
            write_output(get_output(args), "(no AFTER matches)")
        else:
            for line_no, text in rows:
                write_output(get_output(args), f"{line_no:>5}: {text}")

    return 0
