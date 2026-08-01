from __future__ import annotations

import os
import sqlite3
from pathlib import Path

from d810.diagnostics.workbench_inventory import DiagnosticInventoryService
from d810.diagnostics.workbench_models import DiagnosticViewKind


def _database(path: Path, snapshots: tuple[tuple[object, ...], ...]) -> Path:
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE snapshots (
            id INTEGER PRIMARY KEY, label TEXT, func_ea_hex TEXT,
            func_ea_i64 INTEGER, maturity TEXT, phase TEXT,
            block_count INTEGER, timestamp REAL
        );
        CREATE TABLE blocks (
            snapshot_id INTEGER, serial INTEGER, start_ea_hex TEXT,
            succs TEXT, PRIMARY KEY (snapshot_id, serial)
        );
        CREATE TABLE instructions (
            snapshot_id INTEGER, block_serial INTEGER, insn_index INTEGER,
            ea_hex TEXT, dstr TEXT,
            PRIMARY KEY (snapshot_id, block_serial, insn_index)
        );
        CREATE TABLE state_cfg_edges (
            snapshot_id INTEGER, source_block INTEGER, target_entry INTEGER
        );
        CREATE TABLE modifications (
            snapshot_id INTEGER, source_block INTEGER, target_block INTEGER,
            description TEXT
        );
        CREATE TABLE fact_observations (
            snapshot_id INTEGER, source_block INTEGER, fact_key TEXT
        );
        CREATE TABLE fact_conflicts (
            snapshot_id INTEGER, source_block INTEGER, detail TEXT
        );
        CREATE TABLE cfg_provenance (
            snapshot_id INTEGER, block_serial INTEGER, target_serial INTEGER
        );
        CREATE TABLE rendered_programs (
            snapshot_id INTEGER, profile TEXT, rendered_text TEXT
        );
        PRAGMA user_version = 1;
        """
    )
    connection.executemany("INSERT INTO snapshots VALUES (?,?,?,?,?,?,?,?)", snapshots)
    connection.commit()
    connection.close()
    return path


def test_inventory_uses_recorded_timestamp_not_filename_or_mtime(tmp_path: Path):
    newer = _database(
        tmp_path / "000-old-name.diag.sqlite3",
        ((1, "new", "0x401000", 0x401000, "M2", "post_d810", 1, 90.0),),
    )
    older = _database(
        tmp_path / "zzz-new-name.diag.sqlite3",
        ((1, "old", "0x402000", 0x402000, "M1", "pre_d810", 1, 10.0),),
    )
    os.utime(newer, (1, 1))
    os.utime(older, (100, 100))

    summaries = DiagnosticInventoryService(
        roots=(tmp_path,), active_paths_provider=lambda: (newer,)
    ).databases()

    assert [item.path for item in summaries] == [str(newer), str(older)]
    assert summaries[0].recorded_at == 90.0
    assert summaries[0].recorded_at_source == "snapshot"
    assert summaries[0].active is True
    assert summaries[0].snapshot_count == 1
    assert summaries[0].function_eas == (0x401000,)
    assert summaries[0].row_count == 1


def test_snapshot_inventory_is_newest_first_with_id_tie_breaker(tmp_path: Path):
    path = _database(
        tmp_path / "a.diag.sqlite3",
        (
            (2, "same-newer-id", "0x401000", 0x401000, "M2", "post_d810", 1, 20.0),
            (1, "same", "0x401000", 0x401000, "M1", "pre_d810", 1, 20.0),
            (3, "old", "0x401000", 0x401000, "M0", "unknown", 1, 10.0),
        ),
    )
    connection = sqlite3.connect(path)
    connection.executemany(
        "INSERT INTO blocks VALUES (?,?,?,?)",
        ((2, 7, "0x401010", "[]"), (2, 8, None, "[]")),
    )
    connection.commit()
    connection.close()

    snapshots = DiagnosticInventoryService(roots=(tmp_path,)).snapshots(path)

    assert [item.snapshot_id for item in snapshots] == [2, 1, 3]
    assert snapshots[0].row_count == 2


def test_structured_views_anchor_every_block_identity_and_omit_unanchored_serials(
    tmp_path: Path,
):
    path = _database(
        tmp_path / "a.diag.sqlite3",
        ((1, "one", "0x401000", 0x401000, "M1", "post_d810", 2, 20.0),),
    )
    connection = sqlite3.connect(path)
    connection.executemany(
        "INSERT INTO blocks VALUES (?,?,?,?)",
        ((1, 7, "0x401010", "[8]"), (1, 8, None, "[]")),
    )
    connection.execute(
        "INSERT INTO instructions VALUES (?,?,?,?,?)",
        (1, 8, 0, "0x401020", "goto blk7"),
    )
    connection.execute("INSERT INTO state_cfg_edges VALUES (?,?,?)", (1, 7, 99))
    connection.commit()
    connection.close()

    service = DiagnosticInventoryService(roots=(tmp_path,))
    block_records = service.records(path, 1, DiagnosticViewKind.BLOCKS)
    state_records = service.records(path, 1, DiagnosticViewKind.STATE_MACHINE)

    first = {field.name: field for field in block_records[0].fields}
    assert first["serial"].display == "blk7@0x401010"
    assert block_records[0].anchor_ea == 0x401010
    assert first["succs"].display == "blk8@0x401020"
    edge = {field.name: field for field in state_records[0].fields}
    assert edge["source_block"].display == "blk7@0x401010"
    assert edge["target_entry"].value is None
    assert edge["target_entry"].display == "<block anchor unavailable>"
    assert state_records[0].warnings == ("Block anchor unavailable for target_entry",)


def test_supported_legacy_state_cfg_tables_remain_structurally_inspectable(
    tmp_path: Path,
):
    path = _database(
        tmp_path / "legacy.diag.sqlite3",
        ((1, "one", "0x401000", 0x401000, "M1", "post_d810", 1, 20.0),),
    )
    connection = sqlite3.connect(path)
    connection.execute(
        "CREATE TABLE dag_nodes (snapshot_id INTEGER, entry_block INTEGER)"
    )
    connection.execute("INSERT INTO blocks VALUES (?,?,?,?)", (1, 7, "0x401010", "[]"))
    connection.execute("INSERT INTO dag_nodes VALUES (?,?)", (1, 7))
    connection.commit()
    connection.close()

    records = DiagnosticInventoryService(roots=(tmp_path,)).records(
        path, 1, DiagnosticViewKind.STATE_MACHINE
    )

    assert records[0].source_table == "dag_nodes"
    assert {field.name: field.display for field in records[0].fields}[
        "entry_block"
    ] == ("blk7@0x401010")


def test_unreadable_or_non_database_file_is_reported_without_mutation(tmp_path: Path):
    path = tmp_path / "broken.diag.sqlite3"
    path.write_text("not sqlite", encoding="utf-8")
    before = path.read_bytes()

    result = DiagnosticInventoryService(roots=(tmp_path,)).databases()[0]

    assert result.readable is False
    assert result.error
    assert path.read_bytes() == before


def test_browsing_preserves_database_wal_and_shm_bytes_and_metadata(tmp_path: Path):
    path = _database(
        tmp_path / "stable.diag.sqlite3",
        ((1, "one", "0x401000", 0x401000, "M1", "post_d810", 1, 20.0),),
    )
    connection = sqlite3.connect(path)
    connection.execute("INSERT INTO blocks VALUES (?,?,?,?)", (1, 7, "0x401010", "[]"))
    connection.commit()
    connection.close()
    wal = Path(str(path) + "-wal")
    shm = Path(str(path) + "-shm")
    wal.write_bytes(b"")
    shm.write_bytes(b"stable-sidecar")
    candidates = (path, wal, shm)
    before = tuple(
        (candidate.read_bytes(), candidate.stat().st_mtime_ns)
        for candidate in candidates
    )
    service = DiagnosticInventoryService(roots=(tmp_path,))

    database = service.databases()[0]
    snapshots = service.snapshots(path)
    records = service.records(path, 1, DiagnosticViewKind.BLOCKS)

    after = tuple(
        (candidate.read_bytes(), candidate.stat().st_mtime_ns)
        for candidate in candidates
    )
    assert database.readable is True
    assert snapshots[0].snapshot_id == 1
    assert records[0].anchor_ea == 0x401010
    assert after == before


def test_uncheckpointed_wal_fails_closed_without_touching_sidecars(tmp_path: Path):
    path = _database(
        tmp_path / "wal.diag.sqlite3",
        ((1, "one", "0x401000", 0x401000, "M1", "post_d810", 1, 20.0),),
    )
    wal = Path(str(path) + "-wal")
    shm = Path(str(path) + "-shm")
    wal.write_bytes(b"uncheckpointed")
    shm.write_bytes(b"stable-sidecar")
    before = tuple(
        (candidate.read_bytes(), candidate.stat().st_mtime_ns)
        for candidate in (path, wal, shm)
    )

    summary = DiagnosticInventoryService(roots=(tmp_path,)).databases()[0]

    after = tuple(
        (candidate.read_bytes(), candidate.stat().st_mtime_ns)
        for candidate in (path, wal, shm)
    )
    assert summary.readable is False
    assert "uncheckpointed WAL" in (summary.error or "")
    assert after == before


def test_inventory_excludes_manager_owned_quarantine_tree(tmp_path: Path):
    live = _database(
        tmp_path / "live.diag.sqlite3",
        ((1, "live", "0x401000", 0x401000, "M1", "post_d810", 1, 20.0),),
    )
    quarantine = tmp_path / "diagnostic_quarantine"
    quarantine.mkdir()
    quarantined = _database(
        quarantine / "removed.diag.sqlite3",
        ((1, "removed", "0x402000", 0x402000, "M1", "post_d810", 1, 30.0),),
    )

    paths = DiagnosticInventoryService(
        roots=(tmp_path,),
        excluded_roots=(quarantine,),
    ).paths()

    assert paths == (live.resolve(),)
    assert quarantined.resolve() not in paths
