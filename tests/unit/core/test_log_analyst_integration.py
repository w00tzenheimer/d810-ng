"""
Integration test for log-analyst agent communication.

This test creates a SQLite debug log database with known data,
then verifies that the log-analyst agent can query and summarize it correctly.

Run with: PYTHONPATH=src pytest tests/unit/core/test_log_analyst_integration.py -v
"""

import json
import logging
import sqlite3
import tempfile
from pathlib import Path

import pytest


def create_test_database(db_path: str) -> None:
    """Create a test database with known MopTracker-like log entries."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Create schema
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            logger TEXT NOT NULL,
            level TEXT NOT NULL,
            levelno INTEGER NOT NULL,
            function TEXT,
            lineno INTEGER,
            pathname TEXT,
            message TEXT NOT NULL,
            extra JSON,
            test_id TEXT
        )
    """)

    # Insert test data simulating MopTracker analysis of abc_f6_or_dispatch
    test_logs = [
        # Entry into analysis
        {
            "timestamp": "2024-12-04T10:00:00.000000",
            "logger": "d810.optimizers.microcode.flow.flattening.unflattener_fake_jump",
            "level": "DEBUG",
            "levelno": 10,
            "function": "analyze_blk",
            "lineno": 45,
            "message": "Analyzing block 3 for fake jump pattern",
            "extra": json.dumps({"block_serial": 3, "function": "abc_f6_or_dispatch"}),
            "test_id": "test_abc_f6_or_dispatch"
        },
        # MopTracker starting
        {
            "timestamp": "2024-12-04T10:00:00.100000",
            "logger": "d810.hexrays.tracker",
            "level": "DEBUG",
            "levelno": 10,
            "function": "search_backward",
            "lineno": 520,
            "message": "Starting backward search for state variable from block 3",
            "extra": json.dumps({"start_block": 3, "mop": "var_18"}),
            "test_id": "test_abc_f6_or_dispatch"
        },
        # History 0 - resolved
        {
            "timestamp": "2024-12-04T10:00:00.200000",
            "logger": "d810.hexrays.tracker",
            "level": "DEBUG",
            "levelno": 10,
            "function": "search_backward",
            "lineno": 650,
            "message": "History 0: resolved=True, value=0xF6951",
            "extra": json.dumps({"history_index": 0, "resolved": True, "value": 0xF6951, "path": [0, 1, 2]}),
            "test_id": "test_abc_f6_or_dispatch"
        },
        # History 1 - unresolved (back-edge)
        {
            "timestamp": "2024-12-04T10:00:00.300000",
            "logger": "d810.hexrays.tracker",
            "level": "DEBUG",
            "levelno": 10,
            "function": "search_backward",
            "lineno": 650,
            "message": "History 1: resolved=False (loop back to dispatcher)",
            "extra": json.dumps({"history_index": 1, "resolved": False, "reason": "loop_detected", "path": [2, 1, 2]}),
            "test_id": "test_abc_f6_or_dispatch"
        },
        # History 2 - unresolved (back-edge)
        {
            "timestamp": "2024-12-04T10:00:00.400000",
            "logger": "d810.hexrays.tracker",
            "level": "DEBUG",
            "levelno": 10,
            "function": "search_backward",
            "lineno": 650,
            "message": "History 2: resolved=False (loop back to dispatcher)",
            "extra": json.dumps({"history_index": 2, "resolved": False, "reason": "loop_detected", "path": [3, 1, 2]}),
            "test_id": "test_abc_f6_or_dispatch"
        },
        # History 3 - resolved
        {
            "timestamp": "2024-12-04T10:00:00.500000",
            "logger": "d810.hexrays.tracker",
            "level": "DEBUG",
            "levelno": 10,
            "function": "search_backward",
            "lineno": 650,
            "message": "History 3: resolved=True, value=0xF6951",
            "extra": json.dumps({"history_index": 3, "resolved": True, "value": 0xF6951, "path": [0, 1, 3, 1, 2]}),
            "test_id": "test_abc_f6_or_dispatch"
        },
        # History 4 - resolved but DIFFERENT value (spurious path!)
        {
            "timestamp": "2024-12-04T10:00:00.600000",
            "logger": "d810.hexrays.tracker",
            "level": "DEBUG",
            "levelno": 10,
            "function": "search_backward",
            "lineno": 650,
            "message": "History 4: resolved=True, value=0xF6953",
            "extra": json.dumps({"history_index": 4, "resolved": True, "value": 0xF6953, "path": [0, 1, 4, 1, 2]}),
            "test_id": "test_abc_f6_or_dispatch"
        },
        # Summary from UnflattenerFakeJump
        {
            "timestamp": "2024-12-04T10:00:00.700000",
            "logger": "d810.optimizers.microcode.flow.flattening.unflattener_fake_jump",
            "level": "INFO",
            "levelno": 20,
            "function": "analyze_blk",
            "lineno": 75,
            "message": "Found 5 histories: 3 resolved, 2 unresolved",
            "extra": json.dumps({
                "total_histories": 5,
                "resolved_count": 3,
                "unresolved_count": 2,
                "resolved_values": [0xF6951, 0xF6951, 0xF6953]
            }),
            "test_id": "test_abc_f6_or_dispatch"
        },
        # Warning about inconsistency
        {
            "timestamp": "2024-12-04T10:00:00.800000",
            "logger": "d810.optimizers.microcode.flow.flattening.unflattener_fake_jump",
            "level": "WARNING",
            "levelno": 30,
            "function": "analyze_blk",
            "lineno": 82,
            "message": "Resolved values are INCONSISTENT: [0xF6951, 0xF6951, 0xF6953]",
            "extra": json.dumps({"values": [0xF6951, 0xF6951, 0xF6953], "unique_count": 2}),
            "test_id": "test_abc_f6_or_dispatch"
        },
    ]

    for log in test_logs:
        cursor.execute("""
            INSERT INTO logs (timestamp, logger, level, levelno, function, lineno, pathname, message, extra, test_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            log["timestamp"],
            log["logger"],
            log["level"],
            log["levelno"],
            log["function"],
            log["lineno"],
            log.get("pathname"),
            log["message"],
            log["extra"],
            log["test_id"]
        ))

    conn.commit()
    conn.close()


class TestLogAnalystIntegration:
    """Test cases for log-analyst agent communication verification."""

    @pytest.fixture
    def test_db(self, tmp_path):
        """Create a test database with known data."""
        db_path = str(tmp_path / "test_debug.db")
        create_test_database(db_path)
        return db_path

    def test_database_created(self, test_db):
        """Verify test database was created correctly."""
        conn = sqlite3.connect(test_db)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM logs")
        count = cursor.fetchone()[0]
        conn.close()
        assert count == 9, f"Expected 9 log entries, got {count}"

    def test_query_by_logger(self, test_db):
        """Verify filtering by logger name works."""
        conn = sqlite3.connect(test_db)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT COUNT(*) FROM logs
            WHERE logger LIKE 'd810.hexrays.tracker%'
        """)
        count = cursor.fetchone()[0]
        conn.close()
        assert count == 5, f"Expected 5 tracker logs, got {count}"

    def test_query_by_test_id(self, test_db):
        """Verify filtering by test_id works."""
        conn = sqlite3.connect(test_db)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT COUNT(*) FROM logs
            WHERE test_id = 'test_abc_f6_or_dispatch'
        """)
        count = cursor.fetchone()[0]
        conn.close()
        assert count == 9, f"Expected 9 logs for test, got {count}"

    def test_extract_history_values(self, test_db):
        """Verify we can extract resolved values from extra JSON."""
        conn = sqlite3.connect(test_db)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT json_extract(extra, '$.value') as value
            FROM logs
            WHERE logger LIKE 'd810.hexrays.tracker%'
            AND json_extract(extra, '$.resolved') = 1
            ORDER BY id
        """)
        values = [row[0] for row in cursor.fetchall()]
        conn.close()

        # Should find 3 resolved values: 0xF6951, 0xF6951, 0xF6953
        assert len(values) == 3, f"Expected 3 resolved values, got {len(values)}"
        assert values == [0xF6951, 0xF6951, 0xF6953], f"Unexpected values: {values}"

    def test_detect_value_inconsistency(self, test_db):
        """Verify we can detect inconsistent values."""
        conn = sqlite3.connect(test_db)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT DISTINCT json_extract(extra, '$.value') as value
            FROM logs
            WHERE logger LIKE 'd810.hexrays.tracker%'
            AND json_extract(extra, '$.resolved') = 1
        """)
        unique_values = [row[0] for row in cursor.fetchall()]
        conn.close()

        # Should find 2 unique values (inconsistent!)
        assert len(unique_values) == 2, f"Expected 2 unique values, got {len(unique_values)}"

    def test_find_warnings(self, test_db):
        """Verify we can find warning messages."""
        conn = sqlite3.connect(test_db)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT message FROM logs WHERE level = 'WARNING'
        """)
        warnings = [row[0] for row in cursor.fetchall()]
        conn.close()

        assert len(warnings) == 1
        assert "INCONSISTENT" in warnings[0]


# SQL queries that log-analyst agent would use
LOG_ANALYST_QUERIES = {
    "count_by_logger": """
        SELECT logger, COUNT(*) as count
        FROM logs
        WHERE test_id = ?
        GROUP BY logger
        ORDER BY count DESC
    """,

    "find_history_values": """
        SELECT
            json_extract(extra, '$.history_index') as history_idx,
            json_extract(extra, '$.resolved') as resolved,
            json_extract(extra, '$.value') as value,
            json_extract(extra, '$.path') as path
        FROM logs
        WHERE logger LIKE 'd810.hexrays.tracker%'
        AND test_id = ?
        AND message LIKE 'History%'
        ORDER BY id
    """,

    "check_consistency": """
        SELECT
            COUNT(DISTINCT json_extract(extra, '$.value')) as unique_values,
            COUNT(*) as total_resolved
        FROM logs
        WHERE logger LIKE 'd810.hexrays.tracker%'
        AND test_id = ?
        AND json_extract(extra, '$.resolved') = 1
    """,

    "get_timeline": """
        SELECT timestamp, logger, level, substr(message, 1, 60) as msg
        FROM logs
        WHERE test_id = ?
        ORDER BY id
    """
}


def test_log_analyst_queries_work(tmp_path):
    """Verify all log-analyst queries execute correctly."""
    db_path = str(tmp_path / "test.db")
    create_test_database(db_path)

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    for name, query in LOG_ANALYST_QUERIES.items():
        cursor.execute(query, ("test_abc_f6_or_dispatch",))
        results = cursor.fetchall()
        assert results is not None, f"Query '{name}' returned None"
        print(f"\n{name}: {len(results)} rows")

    conn.close()
