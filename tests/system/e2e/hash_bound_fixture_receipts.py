"""Strict diagnostic receipts for the seven hash-bound MASM recoveries."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path


HASH_BOUND_LINKED_EXTENTS = {
    "sub_7FFB0E53C420": 0x4279,
    "sub_7FFB0DE51120": 0x745E,
    "sub_7FFB0DF992D0": 0x4FE9,
    "sub_7FFB0DFD1D70": 0x1E74C,
    "sub_7FFB0E1E69E0": 0x15A,
    "sub_7FFB0E0A2C90": 0x95BD,
    "sub_7FFB0E086BE0": 0x8CAB,
}

# The DF992 recovery deliberately retains one initial-entry comparison while
# publishing the transition partition. Hex-Rays folds that constant corridor
# before rendering; it is therefore an intermediate coverage fact, not a
# surviving dispatcher in the verified final pseudocode.
HASH_BOUND_ALLOWED_INTERMEDIATE_CORRIDORS = {
    "sub_7FFB0DF992D0": 1,
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
    failed_transactions: int
    semantic_authority_batches: int
    semantic_route_proofs: int
    semantic_claimed_proofs: int
    final_output_verified: bool
    allowed_intermediate_corridors: int
    wall_seconds: float
    diagnostics_db: Path
    run_directory: Path


def assert_complete_recovery(receipt: HashBoundFixtureReceipt) -> None:
    assert receipt.function_ea > 0, "missing function EA"
    assert receipt.code_size > 0, "missing linked code extent"
    assert receipt.cfunc_available, "no cfunc was produced"
    assert receipt.final_output_verified, "final pseudocode was not verified"
    assert receipt.disposition == "applied_observed", (
        f"last committed disposition is {receipt.disposition!r}, not applied_observed"
    )
    assert receipt.corridor_count is not None and (
        0 <= receipt.corridor_count <= receipt.allowed_intermediate_corridors
    ), (
        f"{receipt.corridor_count!r} intermediate dispatcher corridors exceed "
        f"the fixture allowance {receipt.allowed_intermediate_corridors}"
    )
    if receipt.selector_store_count is not None:
        assert receipt.selector_store_count == 0, (
            f"{receipt.selector_store_count!r} selector-store rejections remain"
        )
    assert receipt.applied is not None and receipt.rejected is not None, (
        "rewrite counts are unavailable"
    )
    assert receipt.applied > 0 and receipt.rejected >= 0, (
        f"invalid rewrite counts: applied={receipt.applied}, rejected={receipt.rejected}"
    )
    assert receipt.failed_transactions == 0, (
        f"{receipt.failed_transactions} mutation transactions failed"
    )
    assert receipt.semantic_authority_batches > 0, (
        "no canonical unflatten authority was retained in diagnostics"
    )
    assert receipt.semantic_route_proofs > 0, "unflatten authority has no route proofs"
    assert receipt.semantic_claimed_proofs > 0, (
        "unflatten authority claims no route proofs"
    )
    assert receipt.semantic_claimed_proofs <= receipt.semantic_route_proofs, (
        "unflatten authority claims proofs outside its canonical evidence"
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


def load_committed_unflatten_proposals(
    connection: sqlite3.Connection,
    *,
    session_id: str | None = None,
) -> tuple[object, ...]:
    """Decode only authority attached to mutation batches that committed."""

    from d810.transforms.unflatten_authority.ids import canonical_decode

    sql = (
        "SELECT json_extract(le.payload_json,'$.unflatten_authority_json') "
        "AS authority_json FROM lifecycle_events AS le "
        "JOIN mutation_receipts AS r ON r.mutation_batch_id=le.correlation_id "
        "WHERE le.event_kind='mutation_plan' AND r.outcome='committed' "
        "AND json_extract(le.payload_json,'$.unflatten_authority_json') != '' "
    )
    parameters: tuple[object, ...] = ()
    if session_id is not None:
        sql += "AND le.session_id=? "
        parameters = (session_id,)
    rows = connection.execute(sql + "ORDER BY le.event_id", parameters).fetchall()
    return tuple(canonical_decode(str(row[0]).encode("ascii")) for row in rows)


def load_hash_bound_fixture_receipt(
    *,
    function: str,
    code_size: int,
    diagnostics_db: Path,
    run_directory: Path,
    wall_seconds: float,
    selector: SelectorIdentity | None,
    final_output_verified: bool,
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
            "FROM unflatten_candidate_outcomes "
            "WHERE session_id=? AND func_ea_i64=? "
            "AND disposition='applied_observed' "
            "ORDER BY event_id DESC LIMIT 1",
            (session_id, int(session["func_ea_i64"])),
        ).fetchone()
        counts = connection.execute(
            "SELECT COALESCE(SUM(r.applied_operation_count),0) AS applied,"
            "COALESCE(SUM(r.planned_operation_count-r.applied_operation_count),0) "
            "AS rejected,"
            "COALESCE(SUM(CASE WHEN r.outcome='committed' THEN 0 ELSE 1 END),0) "
            "AS failed FROM mutation_receipts AS r "
            "JOIN lifecycle_events AS le ON le.event_id=r.event_id "
            "WHERE le.session_id=?",
            (session_id,),
        ).fetchone()
        proposals = load_committed_unflatten_proposals(
            connection, session_id=session_id
        )
        semantic_route_proofs = 0
        semantic_claimed_proofs = 0
        if proposals:
            from d810.transforms.unflatten_authority.model import (
                ExactInfeasibleEffectClaim,
                EquivalentSemanticRouteClaim,
                TerminalCycleBreakClaim,
            )

            for proposal in proposals:
                available = {
                    proof.proof_id for proof in proposal.route_evidence.route_proofs
                }
                claimed: set[str] = set()
                for claim in proposal.claims:
                    if isinstance(
                        claim,
                        (
                            ExactInfeasibleEffectClaim,
                            EquivalentSemanticRouteClaim,
                            TerminalCycleBreakClaim,
                        ),
                    ):
                        claimed.update(claim.route_proof_ids)
                if not claimed <= available:
                    raise ValueError("unflatten proposal claims foreign route proofs")
                semantic_route_proofs += len(available)
                semantic_claimed_proofs += len(claimed)

        selector_store_count: int | None = None
        if selector is not None:
            rows = connection.execute(
                "SELECT block_start_ea_i64,insn_ea_i64,ordinal "
                "FROM dead_store_rejections WHERE session_id=? AND func_ea_i64=? "
                "AND destination_kind=? AND destination_id=? "
                "AND destination_width=?",
                (
                    session_id,
                    int(session["func_ea_i64"]),
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
            failed_transactions=int(counts["failed"]),
            semantic_authority_batches=len(proposals),
            semantic_route_proofs=semantic_route_proofs,
            semantic_claimed_proofs=semantic_claimed_proofs,
            final_output_verified=bool(final_output_verified),
            allowed_intermediate_corridors=(
                HASH_BOUND_ALLOWED_INTERMEDIATE_CORRIDORS.get(function, 0)
            ),
            wall_seconds=float(wall_seconds),
            diagnostics_db=diagnostics_db,
            run_directory=run_directory,
        )
    finally:
        connection.close()
