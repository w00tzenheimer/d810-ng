from __future__ import annotations

import argparse
import json
import sqlite3

from d810.transforms.dag_frontier_closure import FrontierClosureDiagnosticRow
from d810.core.diag.schema import create_tables
from d810.core.diag.snapshot import snapshot_dag_frontier_closure_diagnostics
from d810.diagnostics.frontier_diagnostics import (
    format_frontier_diagnostics,
    load_frontier_diagnostics,
    run,
)


def _make_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    create_tables(conn)
    conn.execute(
        "INSERT INTO snapshots "
        "(id, label, func_ea_hex, func_ea_i64, maturity, phase, "
        " block_count, timestamp) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (
            7,
            "handler_chain_composer_state_write_reconstruction_post_apply",
            "0x00000001800134e0",
            0x1800134E0,
            "MMAT_GLBOPT1",
            "post_apply",
            245,
            1.0,
        ),
    )
    return conn


def _unresolved_row() -> FrontierClosureDiagnosticRow:
    return FrontierClosureDiagnosticRow(
        kind="unresolved",
        reason="same_scc_alternate_disabled",
        source_block=129,
        observed_target=130,
        branch_arm=0,
        from_dag_scc=11,
        to_dag_scc=19,
        candidate_targets=(131,),
        path=(129, 130, 143, 145, 155, 171),
        cfg_scc_size=201,
        payload={"behavior": "diagnostic_only"},
    )


def _resolved_row() -> FrontierClosureDiagnosticRow:
    return FrontierClosureDiagnosticRow(
        kind="resolved",
        reason="bst_interval_proven_frontier",
        source_block=129,
        observed_target=130,
        branch_arm=0,
        from_dag_scc=11,
        to_dag_scc=19,
        candidate_targets=(131,),
        path=(129, 130, 143, 145, 155, 171),
        cfg_scc_size=201,
        payload={
            "proof": "BST_INTERVAL_PROVEN_FRONTIER",
            "state": "0x0ACD0BD5",
        },
    )


def test_persists_frontier_diagnostic_rows() -> None:
    conn = _make_db()

    snapshot_dag_frontier_closure_diagnostics(conn, 7, [_unresolved_row()])

    row = conn.execute(
        "SELECT kind, reason, source_block, observed_target, branch_arm, "
        "from_dag_scc, to_dag_scc, candidate_targets_json, path_json, "
        "cfg_scc_size, payload_json "
        "FROM state_cfg_frontier_closure_diagnostics WHERE snapshot_id=7"
    ).fetchone()
    assert row[:7] == (
        "unresolved",
        "same_scc_alternate_disabled",
        129,
        130,
        0,
        11,
        19,
    )
    assert json.loads(row[7]) == [131]
    assert json.loads(row[8]) == [129, 130, 143, 145, 155, 171]
    assert row[9] == 201
    assert json.loads(row[10]) == {"behavior": "diagnostic_only"}


def test_frontier_diagnostics_report_formats_unresolved_rows() -> None:
    conn = _make_db()
    snapshot_dag_frontier_closure_diagnostics(conn, 7, [_unresolved_row()])

    rows = load_frontier_diagnostics(conn)
    text = format_frontier_diagnostics(rows)

    assert "snapshot 7 0x00000001800134e0" in text
    assert "kind=unresolved" in text
    assert "reason=same_scc_alternate_disabled" in text
    assert "source=blk[129]" in text
    assert "observed=blk[130]" in text
    assert "arm=0" in text
    assert "candidates=[131]" in text
    assert "path=[129,130,143,145,155,171]" in text


def test_frontier_diagnostics_report_formats_resolved_bst_proof() -> None:
    conn = _make_db()
    snapshot_dag_frontier_closure_diagnostics(conn, 7, [_resolved_row()])

    rows = load_frontier_diagnostics(conn, kind="resolved")
    text = format_frontier_diagnostics(rows)

    assert "kind=resolved" in text
    assert "reason=bst_interval_proven_frontier" in text
    assert "candidates=[131]" in text
    assert "state=0x0ACD0BD5" in text
    assert "proof=BST_INTERVAL_PROVEN_FRONTIER" in text


def test_frontier_diagnostics_cli_prints_unresolved_rows(tmp_path, capsys) -> None:
    db_path = tmp_path / "diag.sqlite3"
    conn = sqlite3.connect(db_path)
    create_tables(conn)
    conn.execute(
        "INSERT INTO snapshots "
        "(id, label, func_ea_hex, func_ea_i64, maturity, phase, "
        " block_count, timestamp) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (
            7,
            "handler_chain_composer_state_write_reconstruction_post_apply",
            "0x00000001800134e0",
            0x1800134E0,
            "MMAT_GLBOPT1",
            "post_apply",
            245,
            1.0,
        ),
    )
    snapshot_dag_frontier_closure_diagnostics(conn, 7, [_unresolved_row()])
    conn.close()

    rc = run(
        argparse.Namespace(
            db=str(db_path),
            snapshot_id=None,
            kind="unresolved",
            all_kinds=False,
            json_output=False,
        )
    )

    assert rc == 0
    out = capsys.readouterr().out
    assert "reason=same_scc_alternate_disabled" in out
    assert "source=blk[129]" in out
    assert "observed=blk[130]" in out
