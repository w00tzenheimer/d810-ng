"""Tests for locating the lifecycle-authoritative diagnostic database."""

from __future__ import annotations

import os

from d810.core.diag import create_diag_database, find_latest_diag_db_path


def _create_session_db(path, *, file_func_ea: int, session_func_ea: int) -> None:
    db_path = path / f"{file_func_ea:016x}_1_1.diag.sqlite3"
    db = create_diag_database(str(db_path))
    conn = db.connection()
    conn.execute(
        "INSERT INTO diagnostic_sessions VALUES (?,?,?,?,?,?,?,?,?)",
        (
            f"session:0x{session_func_ea:X}:1",
            f"0x{session_func_ea:016x}",
            session_func_ea,
            1,
            "{}",
            1.0,
            2.0,
            "finished",
            0,
        ),
    )
    conn.commit()
    db.close()


def test_find_latest_uses_session_owner_instead_of_bootstrap_filename(tmp_path) -> None:
    func_ea = 0x40A560
    stale_path = tmp_path / f"{func_ea:016x}_1_1.diag.sqlite3"
    _create_session_db(
        tmp_path,
        file_func_ea=func_ea,
        session_func_ea=0x40B000,
    )
    _create_session_db(
        tmp_path,
        file_func_ea=0x40C898,
        session_func_ea=func_ea,
    )
    authoritative_path = tmp_path / f"{0x40C898:016x}_1_1.diag.sqlite3"
    os.utime(stale_path, (1.0, 1.0))
    os.utime(authoritative_path, (2.0, 2.0))

    assert find_latest_diag_db_path(func_ea, str(tmp_path)) == authoritative_path
