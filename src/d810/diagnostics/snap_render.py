"""Render a diag-DB snapshot's microcode as a C-like block-by-block listing.

The diag DB captures every instruction's IDA ``_dstr()`` per snapshot.
At ``post_bundle_stabilize`` (typically snap17), D810's linearization
work is complete and the program is correctly unflattened -- but IDA's
later ``optimize_global`` (snap17 -> snap18) DCEs writes whose
consumers it cannot prove intraprocedurally.

This subcommand renders that snapshot directly: per block, header line
plus each instruction's pre-captured ``dstr``.  Bypasses IDA's
post-D810 pipeline so callers can inspect the linearized program as
D810 actually emitted it.

Pure SQL + text emit; no IDA or Hex-Rays imports.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path

from d810.diagnostics.output import add_output_argument, get_output, write_output
from d810.core.typing import Iterable



def _resolve_snapshot_id(
    conn: sqlite3.Connection,
    *,
    snapshot_id: int | None,
    label: str | None,
) -> tuple[int, str]:
    """Resolve ``--snapshot-id`` or ``--label`` to a concrete ``(id, label)``.

    When both arguments are unset, returns the most recent snapshot in
    the DB (highest ``id``).  When ``label`` is provided, picks the
    HIGHEST id whose label matches (covers the common dual-round case
    where ``post_bundle_stabilize`` appears at both snap17 and snap27).
    """
    if snapshot_id is not None:
        row = conn.execute(
            "SELECT id, label FROM snapshots WHERE id = ?",
            (int(snapshot_id),),
        ).fetchone()
        if row is None:
            raise ValueError(f"snapshot id {snapshot_id} not in DB")
        return int(row[0]), str(row[1])
    if label is not None:
        row = conn.execute(
            "SELECT id, label FROM snapshots WHERE label = ?"
            " ORDER BY id DESC LIMIT 1",
            (label,),
        ).fetchone()
        if row is None:
            raise ValueError(f"no snapshot with label {label!r}")
        return int(row[0]), str(row[1])
    row = conn.execute(
        "SELECT id, label FROM snapshots ORDER BY id DESC LIMIT 1",
    ).fetchone()
    if row is None:
        raise ValueError("diag DB has no snapshots")
    return int(row[0]), str(row[1])


def _iter_block_rows(
    conn: sqlite3.Connection,
    snapshot_id: int,
    *,
    only_serials: tuple[int, ...] | None,
) -> Iterable[tuple[int, str, str, str, int]]:
    """Yield ``(serial, type_name, succs_json, preds_json, insn_count)``."""
    if only_serials:
        placeholders = ",".join("?" for _ in only_serials)
        cur = conn.execute(
            f"SELECT serial, type_name, succs, preds, insn_count"
            f"   FROM blocks"
            f"  WHERE snapshot_id = ? AND serial IN ({placeholders})"
            f"  ORDER BY serial",
            (snapshot_id, *only_serials),
        )
    else:
        cur = conn.execute(
            "SELECT serial, type_name, succs, preds, insn_count"
            "   FROM blocks"
            "  WHERE snapshot_id = ?"
            "  ORDER BY serial",
            (snapshot_id,),
        )
    yield from cur


def _iter_insn_rows(
    conn: sqlite3.Connection,
    snapshot_id: int,
    block_serial: int,
) -> Iterable[tuple[int, str, str, str]]:
    """Yield ``(insn_index, opcode_name, ea_hex, dstr)`` for a block."""
    cur = conn.execute(
        "SELECT insn_index, opcode_name, ea_hex, COALESCE(dstr, '')"
        "   FROM instructions"
        "  WHERE snapshot_id = ? AND block_serial = ?"
        "  ORDER BY insn_index",
        (snapshot_id, int(block_serial)),
    )
    yield from cur


def render_snapshot(
    db_path: Path,
    *,
    snapshot_id: int | None,
    label: str | None,
    only_serials: tuple[int, ...] | None,
    include_eas: bool,
) -> list[str]:
    """Render the requested snapshot's blocks + instructions to a string list."""
    conn = sqlite3.connect(str(db_path))
    try:
        snap_id, snap_label = _resolve_snapshot_id(
            conn, snapshot_id=snapshot_id, label=label,
        )
        meta = conn.execute(
            "SELECT block_count, maturity, phase FROM snapshots WHERE id = ?",
            (snap_id,),
        ).fetchone() or (None, None, None)
        out: list[str] = [
            f"# snapshot id={snap_id} label={snap_label} blocks={meta[0]} "
            f"maturity={meta[1]} phase={meta[2]}",
        ]
        for serial, type_name, succs_json, preds_json, insn_count in _iter_block_rows(
            conn, snap_id, only_serials=only_serials,
        ):
            try:
                succs = json.loads(succs_json or "[]")
                preds = json.loads(preds_json or "[]")
            except json.JSONDecodeError:
                succs, preds = succs_json, preds_json
            out.append(
                f"--- blk[{serial}] type={type_name} preds={preds}"
                f" succs={succs} insns={insn_count} ---"
            )
            for insn_index, opcode, ea_hex, dstr in _iter_insn_rows(
                conn, snap_id, serial,
            ):
                if include_eas:
                    out.append(f"  [{insn_index}] {ea_hex} {opcode}  {dstr}")
                else:
                    out.append(f"  [{insn_index}] {opcode}  {dstr}")
        return out
    finally:
        conn.close()


def register_parser(sub) -> None:
    """Register the ``snap-render`` subparser.

    No ``common`` parent: this command takes its own ``--db`` because
    the typical caller wires the worktree's latest diag DB explicitly
    and never needs the shared snapshot/maturity/phase plumbing.
    """
    p = sub.add_parser(
        "snap-render",
        help=(
            "Render a diag-DB snapshot's microcode as a block-by-block "
            "listing.  Bypasses IDA's post-D810 pipeline so the caller "
            "can inspect the linearized program as D810 emitted it."
        ),
    )
    p.add_argument(
        "--db",
        type=Path,
        required=True,
        help="Path to the diag SQLite DB to render from.",
    )
    sel = p.add_mutually_exclusive_group()
    sel.add_argument(
        "--snapshot-id",
        type=int,
        help="Render this specific snapshot id; default is the most recent.",
    )
    sel.add_argument(
        "--label",
        type=str,
        help=(
            "Resolve snapshot by label (e.g. 'post_bundle_stabilize'); "
            "picks the HIGHEST matching id when the label repeats."
        ),
    )
    p.add_argument(
        "--serials",
        type=str,
        default=None,
        help=(
            "Restrict to a comma-separated list of block serials (e.g. "
            "'116,118,238,56') for focused inspection."
        ),
    )
    p.add_argument(
        "--include-eas",
        action="store_true",
        help="Emit each instruction's ea_hex alongside opcode + dstr.",
    )
    add_output_argument(p)


def run(args: argparse.Namespace) -> int:
    """Execute ``snap-render`` from parsed args; return exit code."""
    db_path: Path = args.db
    if not db_path.exists():
        write_output(get_output(args), f"error: diag DB not found: {db_path}")
        return 1
    only_serials: tuple[int, ...] | None = None
    if args.serials:
        try:
            only_serials = tuple(int(s) for s in args.serials.split(",") if s.strip())
        except ValueError:
            write_output(get_output(args), f"error: --serials must be comma-separated integers: {args.serials!r}")
            return 1
    try:
        rendered = render_snapshot(
            db_path,
            snapshot_id=args.snapshot_id,
            label=args.label,
            only_serials=only_serials,
            include_eas=args.include_eas,
        )
    except ValueError as exc:
        write_output(get_output(args), f"error: {exc}")
        return 1
    for line in rendered:
        write_output(get_output(args), line)
    return 0
