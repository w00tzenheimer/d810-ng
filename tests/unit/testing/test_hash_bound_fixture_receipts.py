from __future__ import annotations

import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest

from tests.system.e2e.hash_bound_fixture_receipts import (
    HashBoundFixtureReceipt,
    SelectorIdentity,
    assert_complete_recovery,
    load_hash_bound_fixture_receipt,
)


def _complete_receipt(tmp_path: Path) -> HashBoundFixtureReceipt:
    run_directory = tmp_path / "run"
    run_directory.mkdir()
    diagnostics_db = run_directory / "function.diag.sqlite3"
    diagnostics_db.touch()
    return HashBoundFixtureReceipt(
        function="fixture",
        function_ea=0x180001000,
        code_size=0x120,
        cfunc_available=True,
        disposition="applied_observed",
        corridor_count=0,
        selector_store_count=0,
        applied=12,
        rejected=0,
        failed_transactions=0,
        semantic_authority_batches=1,
        semantic_route_proofs=12,
        semantic_claimed_proofs=12,
        final_output_verified=True,
        allowed_intermediate_corridors=0,
        wall_seconds=1.25,
        diagnostics_db=diagnostics_db,
        run_directory=run_directory,
    )


def test_complete_receipt_accepts_only_full_recovery(tmp_path: Path) -> None:
    assert_complete_recovery(_complete_receipt(tmp_path))


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"cfunc_available": False}, "cfunc"),
        ({"disposition": "not_submitted_safe_bail"}, "disposition"),
        ({"corridor_count": 1}, "intermediate dispatcher corridor"),
        ({"selector_store_count": 1}, "selector-store"),
        ({"applied": None}, "rewrite counts"),
        ({"rejected": None}, "rewrite counts"),
        ({"failed_transactions": 1}, "transactions failed"),
        ({"semantic_authority_batches": 0}, "canonical unflatten authority"),
        ({"semantic_route_proofs": 0}, "no route proofs"),
        ({"semantic_claimed_proofs": 0}, "claims no route proofs"),
        ({"final_output_verified": False}, "final pseudocode"),
        ({"wall_seconds": 0.0}, "wall time"),
    ],
)
def test_complete_receipt_rejects_incomplete_evidence(
    tmp_path: Path, changes: dict[str, object], message: str
) -> None:
    with pytest.raises(AssertionError, match=message):
        assert_complete_recovery(replace(_complete_receipt(tmp_path), **changes))


def test_complete_receipt_rejects_database_outside_run_directory(
    tmp_path: Path,
) -> None:
    receipt = replace(
        _complete_receipt(tmp_path), diagnostics_db=tmp_path / "escaped.sqlite3"
    )

    with pytest.raises(AssertionError, match="run directory"):
        assert_complete_recovery(receipt)


def test_complete_receipt_accepts_verified_entry_only_intermediate_corridor(
    tmp_path: Path,
) -> None:
    receipt = replace(
        _complete_receipt(tmp_path),
        function="sub_7FFB0DF992D0",
        corridor_count=1,
        allowed_intermediate_corridors=1,
    )

    assert_complete_recovery(receipt)


def test_receipt_parser_correlates_terminal_and_per_site_diagnostics(
    tmp_path: Path,
) -> None:
    run_directory = tmp_path / "run"
    run_directory.mkdir()
    diagnostics_db = run_directory / "function.diag.sqlite3"
    conn = sqlite3.connect(diagnostics_db)
    conn.executescript(
        """
        CREATE TABLE diagnostic_sessions (
            session_id TEXT PRIMARY KEY, func_ea_i64 INTEGER, started_at REAL
        );
        CREATE TABLE host_decompilation_outcomes (
            session_id TEXT PRIMARY KEY, func_ea_i64 INTEGER,
            cfunc_available INTEGER
        );
        CREATE TABLE unflatten_candidate_outcomes (
            event_id INTEGER PRIMARY KEY, session_id TEXT, disposition TEXT,
            coverage_residual INTEGER, func_ea_i64 INTEGER
        );
        CREATE TABLE lifecycle_events (
            event_id INTEGER PRIMARY KEY, session_id TEXT, event_kind TEXT,
            correlation_id TEXT, payload_json TEXT
        );
        CREATE TABLE mutation_receipts (
            event_id INTEGER PRIMARY KEY, planned_operation_count INTEGER,
            applied_operation_count INTEGER, outcome TEXT, mutation_batch_id TEXT
        );
        CREATE TABLE dead_store_rejections (
            session_id TEXT, block_start_ea_i64 INTEGER, insn_ea_i64 INTEGER,
            ordinal INTEGER, destination_kind TEXT, destination_id_hex TEXT,
            destination_id_i64 INTEGER,
            destination_width INTEGER, func_ea_i64 INTEGER
        );
        INSERT INTO diagnostic_sessions VALUES ('s1', 6442455040, 1.0);
        INSERT INTO diagnostic_sessions VALUES ('stale', 6442455040, 0.5);
        INSERT INTO host_decompilation_outcomes VALUES ('s1', 6442455040, 1);
        INSERT INTO host_decompilation_outcomes VALUES ('stale', 6442455040, 1);
        INSERT INTO unflatten_candidate_outcomes VALUES
            (10, 's1', 'applied_observed', 0, 6442455040);
        INSERT INTO unflatten_candidate_outcomes VALUES
            (9, 'stale', 'applied_observed', 99, 6442455040);
        INSERT INTO lifecycle_events VALUES
            (20, 's1', 'mutation_receipt', 'batch-1', '{}');
        INSERT INTO lifecycle_events VALUES
            (21, 's1', 'mutation_receipt', 'batch-2', '{}');
        INSERT INTO lifecycle_events VALUES
            (19, 'stale', 'mutation_receipt', 'stale-batch', '{}');
        INSERT INTO mutation_receipts VALUES (20, 7, 7, 'committed', 'batch-1');
        INSERT INTO mutation_receipts VALUES (21, 5, 4, 'committed', 'batch-2');
        INSERT INTO mutation_receipts VALUES
            (19, 100, 1, 'failed', 'stale-batch');
        INSERT INTO dead_store_rejections VALUES
            ('s1', 6442455296, 6442455300, 0, 'stack', '0x000000000000003c', 60, 4, 6442455040);
        INSERT INTO dead_store_rejections VALUES
            ('stale', 6442455396, 6442455400, 0, 'stack', '0x000000000000003c', 60, 4, 6442455040);
        INSERT INTO dead_store_rejections VALUES
            ('s1', 6442455296, 6442455300, 0, 'stack', '0x000000000000003c', 60, 4, 6442455040);
        """
    )
    conn.commit()
    conn.close()

    receipt = load_hash_bound_fixture_receipt(
        function="fixture",
        code_size=0x120,
        diagnostics_db=diagnostics_db,
        run_directory=run_directory,
        wall_seconds=3.5,
        selector=SelectorIdentity("stack", 60, 4),
        final_output_verified=True,
    )

    assert receipt.function_ea == 0x180001000
    assert receipt.cfunc_available is True
    assert receipt.disposition == "applied_observed"
    assert receipt.corridor_count == 0
    assert receipt.selector_store_count == 1
    assert receipt.applied == 11
    assert receipt.rejected == 1
    assert receipt.failed_transactions == 0
    assert receipt.semantic_authority_batches == 0
    assert receipt.semantic_route_proofs == 0
    assert receipt.semantic_claimed_proofs == 0
