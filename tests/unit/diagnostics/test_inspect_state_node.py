"""Unit tests for ``python -m d810.diagnostics inspect-state-node``.

Covers the pure helpers (``normalize_state``,
``find_semantic_context``, ``matching_after_lines``,
``extract_after_lines``) with synthetic SQLite + dump text fixtures, and
the end-to-end CLI invocation against an on-disk fixture DB.
"""
from __future__ import annotations

import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from d810.core.diag import create_diag_database
from d810.core.diag.models import RenderedProgramLine
from d810.diagnostics.inspect_state_node import (
    extract_after_lines,
    find_semantic_context,
    latest_semantic_snapshot_id,
    matching_after_lines,
    normalize_state,
)


REPO_ROOT = Path(__file__).resolve().parents[3]


# ---------------------------------------------------------------------------
# normalize_state
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected_canon,expected_token",
    [
        ("0x5FE86821", "5FE86821", "0x5FE86821"),
        ("5fe86821", "5FE86821", "0x5FE86821"),
        ("0x05fe86821", "5FE86821", "0x5FE86821"),
        ("0X000000FF", "FF", "0xFF"),
        ("  0x4C77464F  ", "4C77464F", "0x4C77464F"),
        ("0", "0", "0x0"),
        ("0x000", "0", "0x0"),
    ],
)
def test_normalize_state_canonical_and_token(raw, expected_canon, expected_token):
    canon, token = normalize_state(raw)
    assert canon == expected_canon
    assert token == expected_token


# ---------------------------------------------------------------------------
# SQLite-backed helpers (synthetic fixtures)
# ---------------------------------------------------------------------------


def _make_conn():
    # create_diag_database binds the peewee Models to this in-memory DB, so the
    # ORM reads in inspect_state_node hit this fixture data.
    return create_diag_database(":memory:")


def _insert_lines(
    db,
    snapshot_id: int,
    variant: str,
    rows: list[tuple[int, str]],
) -> None:
    RenderedProgramLine.insert_many(
        [
            {
                "snapshot_id": snapshot_id,
                "variant_name": variant,
                "line_no": line_no,
                "node_index": None,
                "indent_level": 0,
                "line_kind": "code",
                "target_label": None,
                "text": text,
            }
            for line_no, text in rows
        ]
    ).execute()


def test_latest_semantic_snapshot_id_returns_max():
    db = _make_conn()
    _insert_lines(db, 3, "semantic_reference_like", [(1, "a")])
    _insert_lines(db, 7, "semantic_reference_like", [(1, "b")])
    _insert_lines(db, 9, "other_variant", [(1, "c")])
    assert latest_semantic_snapshot_id(db.connection()) == 7


def test_latest_semantic_snapshot_id_returns_none_when_empty():
    db = _make_conn()
    assert latest_semantic_snapshot_id(db.connection()) is None


def test_find_semantic_context_picks_hits_with_neighbours():
    db = _make_conn()
    rows = [
        (1, "preamble"),
        (2, "more preamble"),
        (3, "STATE_5FE86821 entry"),
        (4, "body line A"),
        (5, "body line B"),
        (6, "STATE_5FE86821 second"),
        (7, "trailing"),
        (8, "way after"),
    ]
    _insert_lines(db, 12, "semantic_reference_like", rows)
    out = find_semantic_context(db.connection(), 12, "5FE86821", context=2)
    line_nos = [n for n, _ in out]
    # min match = 3, max match = 6; context=2 → [1..8]
    assert line_nos == [1, 2, 3, 4, 5, 6, 7, 8]


def test_find_semantic_context_returns_empty_for_unknown_state():
    db = _make_conn()
    _insert_lines(db, 12, "semantic_reference_like", [(1, "no match here")])
    assert find_semantic_context(db.connection(), 12, "DEADBEEF", context=3) == []


def test_find_semantic_context_clamps_start_to_one():
    """When the first match is at line 1 and context > 0, start must
    clamp to 1 — not 0 or negative."""
    db = _make_conn()
    _insert_lines(
        db, 12, "semantic_reference_like",
        [(1, "STATE_DEADBEEF first"), (2, "next"), (3, "third")],
    )
    out = find_semantic_context(db.connection(), 12, "DEADBEEF", context=5)
    assert out[0][0] == 1


def test_find_semantic_context_only_reads_named_variant():
    db = _make_conn()
    _insert_lines(db, 12, "semantic_reference_like", [(5, "STATE_X here")])
    _insert_lines(db, 12, "other_variant", [(5, "STATE_X also here")])
    out = find_semantic_context(db.connection(), 12, "X", context=0)
    assert out == [(5, "STATE_X here")]


# ---------------------------------------------------------------------------
# AFTER-region helpers
# ---------------------------------------------------------------------------


SAMPLE_DUMP = """\
=== BEFORE ===
preamble

--- AFTER ---
__int64 hodur_func()
{
  if (state == 0x5FE86821)
    return 0;
  return 1;
}

=== STATS: ===
done
""".splitlines()


def test_extract_after_lines_returns_body(tmp_path: Path):
    dump = tmp_path / "dump.txt"
    dump.write_text("\n".join(SAMPLE_DUMP) + "\n")
    lines = extract_after_lines(dump)
    assert lines[0] == "__int64 hodur_func()"
    assert any("0x5FE86821" in line for line in lines)
    assert all(not line.startswith("=== STATS:") for line in lines)


def test_extract_after_lines_returns_empty_when_marker_missing(tmp_path: Path):
    dump = tmp_path / "dump.txt"
    dump.write_text("no markers at all\n")
    assert extract_after_lines(dump) == []


def test_matching_after_lines_includes_context_window():
    after = [
        "noise A",
        "noise B",
        "if (state == 0x5FE86821)",
        "body",
        "more body",
        "tail",
    ]
    rows = matching_after_lines(after, tokens=("0x5FE86821",), context=1)
    nos = [n for n, _ in rows]
    # hit at line 3, context=1 → [2, 3, 4]
    assert nos == [2, 3, 4]


def test_matching_after_lines_returns_empty_when_no_hits():
    after = ["x", "y", "z"]
    rows = matching_after_lines(after, tokens=("0xDEAD",), context=2)
    assert rows == []


def test_matching_after_lines_dedupes_overlapping_windows():
    """Two close hits with overlapping windows must not duplicate lines."""
    after = [
        "STATE_A",   # line 1
        "between",   # line 2
        "STATE_A",   # line 3 (hit again)
        "tail",      # line 4
    ]
    rows = matching_after_lines(after, tokens=("STATE_A",), context=1)
    assert [n for n, _ in rows] == [1, 2, 3, 4]


def test_matching_after_lines_ignores_empty_tokens():
    after = ["hello world"]
    # Empty tokens must not collapse into a match-everything probe.
    rows = matching_after_lines(after, tokens=("",), context=0)
    assert rows == []


# ---------------------------------------------------------------------------
# End-to-end CLI: `python -m d810.diagnostics inspect-state-node`
# ---------------------------------------------------------------------------


@pytest.fixture
def fixture_db(tmp_path: Path) -> Path:
    db = tmp_path / "diag.sqlite3"
    conn = sqlite3.connect(str(db))
    conn.execute(
        """
        CREATE TABLE rendered_program_lines (
            snapshot_id INTEGER NOT NULL,
            variant_name TEXT NOT NULL,
            line_no INTEGER NOT NULL,
            text TEXT NOT NULL
        )
        """
    )
    conn.executemany(
        "INSERT INTO rendered_program_lines (snapshot_id, variant_name, line_no, text)"
        " VALUES (?, ?, ?, ?)",
        [
            (5, "semantic_reference_like", 1, "header"),
            (5, "semantic_reference_like", 2, "STATE_5FE86821 entry"),
            (5, "semantic_reference_like", 3, "body"),
            (5, "semantic_reference_like", 4, "trailer"),
        ],
    )
    conn.commit()
    conn.close()
    return db


def _run_cli(*args: str) -> subprocess.CompletedProcess:
    env_path = str(REPO_ROOT / "src")
    return subprocess.run(
        [sys.executable, "-m", "d810.diagnostics", "inspect-state-node", *args],
        capture_output=True,
        text=True,
        env={"PYTHONPATH": env_path, "PATH": ""},
        cwd=str(REPO_ROOT),
    )


def test_cli_prints_semantic_context_for_known_state(fixture_db: Path):
    result = _run_cli("--db", str(fixture_db), "--state", "0x5FE86821", "--context", "1")
    assert result.returncode == 0, result.stderr
    assert "semantic_reference_like snapshot 5" in result.stdout
    assert "STATE_5FE86821" in result.stdout
    assert "(no semantic lines" not in result.stdout


def test_cli_reports_no_match_for_unknown_state(fixture_db: Path):
    result = _run_cli("--db", str(fixture_db), "--state", "0xDEADBEEF")
    assert result.returncode == 0, result.stderr
    assert "(no semantic lines for STATE_DEADBEEF)" in result.stdout


def test_cli_correlates_against_dump_after_region(
    fixture_db: Path, tmp_path: Path,
):
    dump = tmp_path / "dump.txt"
    dump.write_text("\n".join(SAMPLE_DUMP) + "\n")
    result = _run_cli(
        "--db", str(fixture_db),
        "--state", "0x5FE86821",
        "--dump", str(dump),
        "--context", "1",
    )
    assert result.returncode == 0, result.stderr
    assert "AFTER matches for 0x5FE86821" in result.stdout
    assert "0x5FE86821" in result.stdout


def test_cli_returns_two_for_missing_db(tmp_path: Path):
    missing = tmp_path / "no-such.sqlite3"
    result = _run_cli("--db", str(missing), "--state", "0x1")
    assert result.returncode == 2
    assert "db not found" in result.stdout


def test_cli_returns_two_when_db_has_no_semantic_snapshots(tmp_path: Path):
    empty = tmp_path / "empty.sqlite3"
    conn = sqlite3.connect(str(empty))
    conn.execute(
        "CREATE TABLE rendered_program_lines ("
        "snapshot_id INTEGER NOT NULL, variant_name TEXT NOT NULL,"
        " line_no INTEGER NOT NULL, text TEXT NOT NULL)"
    )
    conn.commit()
    conn.close()
    result = _run_cli("--db", str(empty), "--state", "0x1")
    assert result.returncode == 2
    assert "no semantic_reference_like snapshot" in result.stdout
