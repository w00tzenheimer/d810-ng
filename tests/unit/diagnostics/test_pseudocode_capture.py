"""Unit tests for pseudocode capture parsing and persistence."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from d810.diagnostics.pseudocode_capture import (
    capture_dump_file_to_db,
    capture_dump_text_to_db,
    init_capture_db,
    parse_capture_dump,
    render_capture_summary,
)


SEPARATOR = "=" * 88
SAMPLE_DUMP = f"""\
FUNCTION: test_xor @ 0x180012340
BINARY: libobfuscated.dll
PROJECT: example_libobfuscated.json
CODE_CHANGED: True
RULES_FIRED (instruction):
  XorRule [@MMAT_GLBOPT1:1]
RULES_FIRED (block):
  EmulatedDispatcherUnflattener [@MMAT_GLBOPT1:1p]

--- BEFORE ---
int test_xor()
{{
  return a + b - 2 * (a & b);
}}

--- AFTER ---
int test_xor()
{{
  return a ^ b;
}}
{SEPARATOR}
=== STATS: test_xor ===
BEFORE: lines=4 returns=1 whiles=0 gotos=0 calls=0 ifs=0
AFTER:  lines=4 returns=1 whiles=0 gotos=0 calls=0 ifs=0
"""


def test_parse_capture_dump_extracts_metadata_sections_and_rules() -> None:
    parsed = parse_capture_dump(SAMPLE_DUMP)

    assert parsed.function_name == "test_xor"
    assert parsed.function_address == "0x180012340"
    assert parsed.project_config == "example_libobfuscated.json"
    assert parsed.binary_name == "libobfuscated.dll"
    assert parsed.code_changed is True
    assert "a + b" in parsed.code_before
    assert "a ^ b" in parsed.code_after
    assert SEPARATOR not in parsed.code_after
    assert parsed.rules_fired == (
        "XorRule",
        "EmulatedDispatcherUnflattener",
    )


def test_capture_dump_text_to_db_inserts_schema_row(tmp_path: Path) -> None:
    db_path = tmp_path / "capture.sqlite3"
    conn = init_capture_db(db_path)
    try:
        row = capture_dump_text_to_db(conn, SAMPLE_DUMP)
        stored = conn.execute(
            """
            SELECT function_name, function_address, code_changed, rules_fired,
                   project_config, binary_name
            FROM pseudocode_capture
            """
        ).fetchone()
    finally:
        conn.close()

    assert row["function_name"] == "test_xor"
    assert stored == (
        "test_xor",
        "0x180012340",
        1,
        json.dumps(["XorRule", "EmulatedDispatcherUnflattener"]),
        "example_libobfuscated.json",
        "libobfuscated.dll",
    )


def test_capture_dump_file_to_db_supports_overrides_and_summary(tmp_path: Path) -> None:
    dump_path = tmp_path / "dump.txt"
    db_path = tmp_path / "capture.sqlite3"
    dump_path.write_text(SAMPLE_DUMP)

    row = capture_dump_file_to_db(
        dump_path=dump_path,
        db_path=db_path,
        function_name="test_xor_override",
        project_config="override.json",
        binary_name="override.dll",
    )
    summary = render_capture_summary(row)

    assert row["function_name"] == "test_xor_override"
    assert row["project_config"] == "override.json"
    assert row["binary_name"] == "override.dll"
    assert row["db_path"] == str(db_path)
    assert "FUNCTION=test_xor_override" in summary
    assert "RULES_FIRED=XorRule, EmulatedDispatcherUnflattener" in summary

    conn = sqlite3.connect(db_path)
    try:
        count = conn.execute("SELECT COUNT(*) FROM pseudocode_capture").fetchone()[0]
    finally:
        conn.close()
    assert count == 1
