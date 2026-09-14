"""Strict diagnostic receipts for the seven hash-bound MASM recoveries."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path


HASH_BOUND_LINKED_EXTENTS = {
    "sub_7FFB0E53C420": 0x4279,
    "sub_7FFB0DE51120": 0x745E,
    "sub_7FFB0DF992D0": 0x4FD4,
    "sub_7FFB0DFD1D70": 0x1E74C,
    "sub_7FFB0E1E69E0": 0x15A,
    "sub_7FFB0E0A2C90": 0x95BD,
    "sub_7FFB0E086BE0": 0x8C97,
}


@dataclass(frozen=True)
class SelectorIdentity:
    kind: str
    identifier: int
    width: int


@dataclass(frozen=True)
class HashBoundFixtureReceipt:
    function: str
    function_ea: int
    code_size: int
    cfunc_available: bool
    disposition: str | None
    corridor_count: int | None
    selector_store_count: int | None
    applied: int | None
    rejected: int | None
    wall_seconds: float
    diagnostics_db: Path
    run_directory: Path


def assert_complete_recovery(receipt: HashBoundFixtureReceipt) -> None:
    assert receipt.function_ea > 0, "missing function EA"
    assert receipt.code_size > 0, "missing linked code extent"
    assert receipt.cfunc_available, "no cfunc was produced"
    assert receipt.disposition == "applied_observed", (
        f"terminal disposition is {receipt.disposition!r}, not applied_observed"
    )
    assert receipt.corridor_count == 0, (
        f"{receipt.corridor_count!r} residual dispatcher corridor blocks remain"
    )
    assert receipt.selector_store_count == 0, (
        f"{receipt.selector_store_count!r} live selector stores remain"
    )
    assert receipt.applied is not None and receipt.rejected is not None, (
        "rewrite counts are unavailable"
    )
    assert receipt.applied > 0 and receipt.rejected >= 0, (
        f"invalid rewrite counts: applied={receipt.applied}, rejected={receipt.rejected}"
    )
    assert receipt.wall_seconds > 0.0, "wall time was not recorded"
    database = receipt.diagnostics_db.resolve()
    run_directory = receipt.run_directory.resolve()
    assert database.is_relative_to(run_directory), (
        f"diagnostics DB escaped run directory: {database}"
    )
    assert database.is_file(), f"diagnostics DB is missing: {database}"


def _latest_session(connection: sqlite3.Connection) -> sqlite3.Row:
    row = connection.execute(
        "SELECT s.session_id,h.func_ea_i64,h.cfunc_available "
        "FROM diagnostic_sessions AS s "
        "JOIN host_decompilation_outcomes AS h ON h.session_id=s.session_id "
        "ORDER BY s.started_at DESC LIMIT 1"
    ).fetchone()
    if row is None:
        raise ValueError("diagnostics DB has no host decompilation outcome")
    return row


def load_hash_bound_fixture_receipt(
    *,
    function: str,
    code_size: int,
    diagnostics_db: Path,
    run_directory: Path,
    wall_seconds: float,
    selector: SelectorIdentity | None,
) -> HashBoundFixtureReceipt:
    """Load one receipt without guessing which storage cell is the selector."""
    diagnostics_db = Path(diagnostics_db)
    run_directory = Path(run_directory)
    connection = sqlite3.connect(diagnostics_db)
    connection.row_factory = sqlite3.Row
    try:
        session = _latest_session(connection)
        session_id = str(session["session_id"])
        candidate = connection.execute(
            "SELECT disposition,coverage_residual "
            "FROM unflatten_candidate_outcomes WHERE session_id=? "
            "ORDER BY event_id DESC LIMIT 1",
            (session_id,),
        ).fetchone()
        counts = connection.execute(
            "SELECT COALESCE(SUM(r.applied_operation_count),0) AS applied,"
            "COALESCE(SUM(r.planned_operation_count-r.applied_operation_count),0) "
            "AS rejected FROM mutation_receipts AS r "
            "JOIN lifecycle_events AS e ON e.event_id=r.event_id "
            "WHERE e.session_id=?",
            (session_id,),
        ).fetchone()

        selector_store_count: int | None = None
        if selector is not None:
            rows = connection.execute(
                "SELECT block_start_ea_i64,insn_ea_i64,ordinal "
                "FROM dead_store_rejections WHERE session_id=? "
                "AND destination_kind=? AND destination_id=? "
                "AND destination_width=?",
                (
                    session_id,
                    selector.kind,
                    selector.identifier,
                    selector.width,
                ),
            ).fetchall()
            selector_store_count = len(
                {
                    (
                        int(row["block_start_ea_i64"]),
                        int(row["insn_ea_i64"]),
                        int(row["ordinal"]),
                    )
                    for row in rows
                }
            )

        return HashBoundFixtureReceipt(
            function=function,
            function_ea=int(session["func_ea_i64"]) & ((1 << 64) - 1),
            code_size=int(code_size),
            cfunc_available=bool(session["cfunc_available"]),
            disposition=None if candidate is None else str(candidate["disposition"]),
            corridor_count=(
                None
                if candidate is None or candidate["coverage_residual"] is None
                else int(candidate["coverage_residual"])
            ),
            selector_store_count=selector_store_count,
            applied=int(counts["applied"]),
            rejected=int(counts["rejected"]),
            wall_seconds=float(wall_seconds),
            diagnostics_db=diagnostics_db,
            run_directory=run_directory,
        )
    finally:
        connection.close()
