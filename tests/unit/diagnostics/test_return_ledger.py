"""Tests for the return-ledger diag subcommand."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from d810.core.diag import open_diag_database
from d810.diagnostics.return_ledger import (
    AfterReturn,
    DEFAULT_RETURN_SLOT_STKOFF,
    DEFAULT_V660_STKOFF,
    ReturnPath,
    ReturnSlotWriter,
    bfs_reachable,
    extract_after_returns,
    format_writer,
    list_snapshots,
    pick_snapshot,
    query_blocks,
    query_return_slot_writers,
    query_v660_writers,
    render_json,
    render_text,
    run_ledger,
    trace_return_paths,
)


# ---------------------------------------------------------------------------
# Synthetic diag DB fixture
# ---------------------------------------------------------------------------


def _make_diag_db(tmp_path: Path) -> Path:
    """Build a tiny diag SQLite with two snapshots:

    snap 10: post_apply, 250 blocks   (the one pick_snapshot should choose)
    snap 11: post_gut_and_wire, 60 blocks
    snap 12: post_apply, 220 blocks (latest fallback)

    The block layout for snap 10:
      - blk[0]  -> blk[5]
      - blk[5]  -> blk[6], blk[7]
      - blk[6]  -> blk[100]   (BLT_STOP)
      - blk[7]  -> blk[100]
      - blk[100] is BLT_STOP with preds=[6, 7]
      - blk[200] is unreachable (no edges from blk[0])

    Return-slot writer at blk[6] (m_mov #1, 0x7F0).
    v660 writer at blk[7]   (m_mov #0xDEAD, 0x660).
    """
    db = tmp_path / "diag.sqlite3"
    conn = sqlite3.connect(str(db))
    try:
        conn.executescript(
            """
            CREATE TABLE snapshots(id INTEGER PRIMARY KEY, label TEXT,
                block_count INTEGER);
            CREATE TABLE blocks(snapshot_id INTEGER, serial INTEGER,
                type_name TEXT, preds TEXT, succs TEXT, meta TEXT);
            CREATE TABLE instructions(snapshot_id INTEGER, block_serial INTEGER,
                opcode_name TEXT, src_l_type TEXT, src_l_stkoff INTEGER,
                src_l_value_hex TEXT, dstr TEXT, dest_stkoff INTEGER);
            INSERT INTO snapshots VALUES
                (10, 'state_write_reconstruction_post_apply', 250),
                (11, 'state_write_reconstruction_post_gut_and_wire', 60),
                (12, 'state_write_reconstruction_post_apply', 220);
            """
        )
        for sid in (10, 12):
            conn.executemany(
                "INSERT INTO blocks VALUES (?, ?, ?, ?, ?, ?)",
                [
                    (sid, 0,   "BLT_NWAY", "[]",      "[5]",     "{}"),
                    (sid, 5,   "BLT_2WAY", "[0]",     "[6, 7]",  "{}"),
                    (sid, 6,   "BLT_1WAY", "[5]",     "[100]",
                     '{"valranges": "rax: [1, 1]"}'),
                    (sid, 7,   "BLT_1WAY", "[5]",     "[100]",   "{}"),
                    (sid, 100, "BLT_STOP", "[6, 7]",  "[]",      "{}"),
                    (sid, 200, "BLT_1WAY", "[]",      "[]",      "{}"),
                ],
            )
        # Return slot writer at blk[6] for snap 10.
        conn.execute(
            "INSERT INTO instructions VALUES (?,?,?,?,?,?,?,?)",
            (10, 6, "m_mov", "const", None, "0x1",
             "mov #0x1.8, %var_8.8", DEFAULT_RETURN_SLOT_STKOFF),
        )
        # v660 writer at blk[7] for snap 10.
        conn.execute(
            "INSERT INTO instructions VALUES (?,?,?,?,?,?,?,?)",
            (10, 7, "m_mov", "const", None, "0xDEAD",
             "mov #0xDEAD.8, %var_660.8", DEFAULT_V660_STKOFF),
        )
        conn.commit()
    finally:
        conn.close()
    return db


@pytest.fixture()
def diag_db(tmp_path: Path) -> Path:
    return _make_diag_db(tmp_path)


# ---------------------------------------------------------------------------
# pick_snapshot
# ---------------------------------------------------------------------------


def test_pick_snapshot_returns_pre_gut_and_wire_post_apply(diag_db: Path) -> None:
    db = open_diag_database(str(diag_db))
    try:
        assert pick_snapshot(db.connection()) == 10
    finally:
        db.close()


def test_pick_snapshot_returns_explicit_id_verbatim(diag_db: Path) -> None:
    db = open_diag_database(str(diag_db))
    try:
        assert pick_snapshot(db.connection(), snapshot_id=12) == 12
    finally:
        db.close()


def test_pick_snapshot_falls_back_to_last_post_apply_above_200(
    tmp_path: Path,
) -> None:
    """No gut_and_wire snapshot exists -- pick the most recent post_apply
    snapshot with >200 blocks."""
    db_path = tmp_path / "x.sqlite3"
    conn = sqlite3.connect(str(db_path))
    try:
        conn.executescript(
            "CREATE TABLE snapshots(id INTEGER PRIMARY KEY, label TEXT,"
            " block_count INTEGER);"
            "INSERT INTO snapshots VALUES (1, 'something_post_apply', 100);"
            "INSERT INTO snapshots VALUES (2, 'something_post_apply', 240);"
            "INSERT INTO snapshots VALUES (3, 'other', 50);"
        )
        conn.commit()
    finally:
        conn.close()
    db = open_diag_database(str(db_path))
    try:
        assert pick_snapshot(db.connection()) == 2
    finally:
        db.close()


def test_pick_snapshot_returns_last_snapshot_when_no_post_apply(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "x.sqlite3"
    conn = sqlite3.connect(str(db_path))
    try:
        conn.executescript(
            "CREATE TABLE snapshots(id INTEGER PRIMARY KEY, label TEXT,"
            " block_count INTEGER);"
            "INSERT INTO snapshots VALUES (1, 'pre_d810', 10);"
            "INSERT INTO snapshots VALUES (7, 'pre_d810', 12);"
        )
        conn.commit()
    finally:
        conn.close()
    db = open_diag_database(str(db_path))
    try:
        assert pick_snapshot(db.connection()) == 7
    finally:
        db.close()


def test_list_snapshots_returns_all_rows(diag_db: Path) -> None:
    db = open_diag_database(str(diag_db))
    try:
        rows = list_snapshots(db.connection())
    finally:
        db.close()
    assert [r[0] for r in rows] == [10, 11, 12]
    assert rows[0][2] == 250


# ---------------------------------------------------------------------------
# query_blocks / query_return_slot_writers / query_v660_writers
# ---------------------------------------------------------------------------


def test_query_blocks_parses_preds_succs_and_meta(diag_db: Path) -> None:
    db = open_diag_database(str(diag_db))
    try:
        blocks = query_blocks(db.connection(), 10)
    finally:
        db.close()
    assert sorted(blocks) == [0, 5, 6, 7, 100, 200]
    assert blocks[100]["type"] == "BLT_STOP"
    assert blocks[100]["preds"] == [6, 7]
    assert "rax" in blocks[6]["valranges"]


def test_query_return_slot_writers_pulls_writer(diag_db: Path) -> None:
    db = open_diag_database(str(diag_db))
    try:
        writers = query_return_slot_writers(db.connection(), 10)
    finally:
        db.close()
    assert list(writers) == [6]
    w = writers[6]
    assert w.opcode == "m_mov"
    assert w.src_value == "0x1"


def test_query_v660_writers_returns_block_to_const_map(diag_db: Path) -> None:
    db = open_diag_database(str(diag_db))
    try:
        v660 = query_v660_writers(db.connection(), 10)
    finally:
        db.close()
    assert v660 == {7: "0xDEAD"}


# ---------------------------------------------------------------------------
# bfs_reachable / trace_return_paths
# ---------------------------------------------------------------------------


def test_bfs_reachable_walks_from_block_zero(diag_db: Path) -> None:
    db = open_diag_database(str(diag_db))
    try:
        blocks = query_blocks(db.connection(), 10)
    finally:
        db.close()
    reachable = bfs_reachable(blocks)
    # 200 is the unreachable island; everything else is reachable.
    assert reachable == {0, 5, 6, 7, 100}


def test_trace_return_paths_emits_per_feeder_family(diag_db: Path) -> None:
    db = open_diag_database(str(diag_db))
    try:
        conn = db.connection()
        blocks = query_blocks(conn, 10)
        writers = query_return_slot_writers(conn, 10)
        v660 = query_v660_writers(conn, 10)
    finally:
        db.close()
    reachable = bfs_reachable(blocks)
    paths = trace_return_paths(blocks, writers, v660, reachable)
    # BLT_STOP has 2 preds (6, 7); each pred has exactly 1 pred (blk[5]),
    # so is_pts=True fires for both and the walk roots at blk[5]. The
    # algorithm emits one ReturnPath per pred-of-BLT_STOP, each rooted at
    # blk[5] with the appropriate pred + BLT_STOP suffix.
    assert len(paths) == 2
    assert all(p.reachable for p in paths)
    assert all(p.is_pts for p in paths)
    assert all(p.root_serial == 5 for p in paths)
    chains = sorted(p.chain for p in paths)
    assert chains == [[5, 6, 100], [5, 7, 100]]


def test_trace_return_paths_shared_epilogue_walks_through_each_feeder(
    tmp_path: Path,
) -> None:
    """When the BLT_STOP-pred has multiple preds itself (a shared epilogue),
    the tracer should walk through each feeder and surface the writer
    sitting on a feeder block."""
    blocks: dict[int, dict] = {
        0:   {"serial": 0,   "type": "BLT_NWAY", "preds": [],     "succs": [10, 11], "valranges": ""},
        10:  {"serial": 10,  "type": "BLT_1WAY", "preds": [0],    "succs": [99],     "valranges": ""},
        11:  {"serial": 11,  "type": "BLT_1WAY", "preds": [0],    "succs": [99],     "valranges": ""},
        99:  {"serial": 99,  "type": "BLT_1WAY", "preds": [10, 11], "succs": [100], "valranges": ""},  # shared epilogue
        100: {"serial": 100, "type": "BLT_STOP", "preds": [99],   "succs": [],       "valranges": ""},
    }
    writer = ReturnSlotWriter(
        block_serial=10, opcode="m_mov", src_type="const",
        src_stkoff=None, src_value="0xAA", dstr="mov #0xAA, %var_8.8",
    )
    paths = trace_return_paths(blocks, {10: writer}, {}, set(blocks))
    # 99 has 2 preds AND it is also the sole pred of 100, so is_pts=False
    # AND the pred chain walks through each feeder of 99 (10, 11).
    feeder_roots = sorted(p.root_serial for p in paths)
    assert feeder_roots == [10, 11]
    by_root = {p.root_serial: p for p in paths}
    assert by_root[10].writer is not None
    assert by_root[10].writer.block_serial == 10
    assert by_root[11].writer is None


def test_trace_return_paths_empty_when_no_blt_stop(tmp_path: Path) -> None:
    blocks: dict[int, dict] = {
        0: {"serial": 0, "type": "BLT_1WAY", "preds": [], "succs": [1], "valranges": ""},
        1: {"serial": 1, "type": "BLT_1WAY", "preds": [0], "succs": [], "valranges": ""},
    }
    assert trace_return_paths(blocks, {}, {}, set(blocks)) == []


# ---------------------------------------------------------------------------
# extract_after_returns
# ---------------------------------------------------------------------------


def test_extract_after_returns_finds_two_returns() -> None:
    dump = "\n".join(
        [
            "BEFORE: foo",
            "--- AFTER ---",
            "// some comment",
            "__int64 sub_X(...)",
            "{",
            "    if (cond)",
            "        return 1;",
            "    return v42;",
            "}",
            "AFTER: lines=20",
        ]
    ).splitlines(keepends=False)
    rets = extract_after_returns(dump)
    assert [r.ordinal for r in rets] == [1, 2]
    assert rets[0].expr == "1"
    assert rets[1].expr == "v42"


def test_extract_after_returns_ignores_when_no_after_marker() -> None:
    assert extract_after_returns(["return x;", "no marker"]) == []


def test_extract_after_returns_skips_return_substring_in_identifier() -> None:
    dump = [
        "--- AFTER ---",
        "    return_label = 0;",
        "AFTER: lines=2",
    ]
    assert extract_after_returns(dump) == []


# ---------------------------------------------------------------------------
# format_writer
# ---------------------------------------------------------------------------


def test_format_writer_none() -> None:
    assert format_writer(None) == "(none)"


def test_format_writer_prefers_value_then_stkoff_then_type() -> None:
    w = ReturnSlotWriter(1, "m_mov", "stk", 0x1F, "0x42", "dstr")
    assert format_writer(w) == "m_mov src=#0x42"
    w2 = ReturnSlotWriter(2, "m_xdu", "stk", 0x20, None, "dstr")
    assert format_writer(w2) == "m_xdu src=stkoff=0x20"
    w3 = ReturnSlotWriter(3, "m_ldx", "expr", None, None, "dstr")
    assert format_writer(w3) == "m_ldx src=expr"


# ---------------------------------------------------------------------------
# render_text / render_json
# ---------------------------------------------------------------------------


def _sample_render_inputs(diag_db: Path) -> dict:
    db = open_diag_database(str(diag_db))
    try:
        conn = db.connection()
        blocks = query_blocks(conn, 10)
        writers = query_return_slot_writers(conn, 10)
        v660 = query_v660_writers(conn, 10)
    finally:
        db.close()
    reachable = bfs_reachable(blocks)
    paths = trace_return_paths(blocks, writers, v660, reachable)
    return dict(
        db_path=diag_db,
        snapshot_id=10,
        snap_label="state_write_reconstruction_post_apply",
        blocks=blocks,
        reachable=reachable,
        writers=writers,
        v660_map=v660,
        paths=paths,
        after_returns=[],
    )


def test_render_text_emits_header_and_summary(diag_db: Path) -> None:
    out = render_text(**_sample_render_inputs(diag_db))
    assert "=== RETURN FAMILY LEDGER ===" in out
    assert "BLT_STOP: blk[100]" in out
    assert "Return-slot writers (dest=0x7F0): blk[6]" in out
    assert "v660 writers (dest=0x660):" in out
    assert "Live Return Paths" in out


def test_render_json_round_trips_to_dict(diag_db: Path) -> None:
    out = render_json(**_sample_render_inputs(diag_db))
    payload = json.loads(out)
    assert payload["snapshot_id"] == 10
    assert payload["blt_stop"] == 100
    assert payload["blt_stop_preds"] == [6, 7]
    assert payload["return_slot_writers"]["6"]["opcode"] == "m_mov"


# ---------------------------------------------------------------------------
# run_ledger orchestrator
# ---------------------------------------------------------------------------


def test_run_ledger_emits_header_for_real_db(diag_db: Path) -> None:
    out = run_ledger(diag_db)
    assert "RETURN FAMILY LEDGER" in out
    assert "BLT_STOP: blk[100]" in out


def test_run_ledger_correlates_after_returns_when_dump_provided(
    diag_db: Path, tmp_path: Path,
) -> None:
    dump = tmp_path / "dump.txt"
    dump.write_text(
        "--- AFTER ---\n"
        "    return 1;\n"
        "    return 2;\n"
        "AFTER: lines=3\n"
    )
    out = run_ledger(diag_db, dump_path=dump)
    assert "2 AFTER Returns" in out
    assert "R1  line" in out and "R2  line" in out


def test_run_ledger_json_mode_emits_dict(diag_db: Path) -> None:
    out = run_ledger(diag_db, as_json=True)
    payload = json.loads(out)
    assert payload["snapshot_id"] == 10
    assert payload["blt_stop"] == 100


def test_run_ledger_list_snapshots_short_circuits(diag_db: Path) -> None:
    out = run_ledger(diag_db, list_snapshots_only=True)
    assert "snapshots:" in out
    assert "[10]" in out
    assert "[12]" in out


def test_run_ledger_missing_db_returns_error(tmp_path: Path) -> None:
    out = run_ledger(tmp_path / "missing.sqlite3")
    assert out.startswith("Error: diag DB not found")


def test_run_ledger_explicit_snapshot_id_honoured(diag_db: Path) -> None:
    # Snapshot 12 is post_apply with 220 blocks (above 200 threshold).
    out = run_ledger(diag_db, snapshot_id=12)
    assert "Snapshot: [12]" in out
