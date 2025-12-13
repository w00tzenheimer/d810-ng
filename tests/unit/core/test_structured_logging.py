"""
Unit tests for structured logging module.
"""

import json
import logging
import os
import sqlite3
import tempfile
from pathlib import Path

import pytest

from d810.core.structured_logging import SQLiteHandler, debug_scope, query_logs


class TestSQLiteHandler:
    """Tests for SQLiteHandler class."""

    @pytest.fixture
    def temp_db(self):
        """Create a temporary database file."""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = f.name

        yield db_path

        # Cleanup
        if os.path.exists(db_path):
            os.unlink(db_path)

    def test_sqlite_handler_creates_table(self, temp_db):
        """Verify schema is created on first use."""
        # Create handler
        handler = SQLiteHandler(temp_db)

        # Check that tables exist
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()

        # Check logs table exists
        cursor.execute("""
            SELECT name FROM sqlite_master
            WHERE type='table' AND name='logs'
        """)
        assert cursor.fetchone() is not None

        # Check indexes exist
        cursor.execute("""
            SELECT name FROM sqlite_master
            WHERE type='index' AND name LIKE 'idx_logs_%'
        """)
        indexes = {row[0] for row in cursor.fetchall()}
        expected_indexes = {
            'idx_logs_logger',
            'idx_logs_test_id',
            'idx_logs_level',
            'idx_logs_timestamp'
        }
        assert expected_indexes.issubset(indexes)

        conn.close()
        handler.close()

    def test_sqlite_handler_inserts_records(self, temp_db):
        """Verify logs are inserted correctly."""
        # Create handler and logger
        handler = SQLiteHandler(temp_db, test_id='test_123')
        logger = logging.getLogger('test_logger')
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)

        # Log some messages
        logger.debug("Debug message")
        logger.info("Info message")
        logger.warning("Warning message")
        logger.error("Error message")

        # Query database
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM logs ORDER BY id")
        rows = cursor.fetchall()

        assert len(rows) == 4

        # Check first record
        row = rows[0]
        assert row[2] == 'test_logger'  # logger name
        assert row[3] == 'DEBUG'  # level
        assert row[4] == 10  # levelno
        assert 'Debug message' in row[8]  # message
        assert row[10] == 'test_123'  # test_id

        conn.close()
        logger.removeHandler(handler)
        handler.close()

    def test_sqlite_handler_extra_json(self, temp_db):
        """Verify extra data is serialized as JSON."""
        # Create handler and logger
        handler = SQLiteHandler(temp_db)
        logger = logging.getLogger('test_extra')
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)

        # Log with extra data
        extra_data = {
            'user_id': 42,
            'action': 'test',
            'values': [1, 2, 3],
            'nested': {'key': 'value'}
        }
        logger.info("Message with extra", extra=extra_data)

        # Query database
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        cursor.execute("SELECT extra FROM logs WHERE logger='test_extra'")
        row = cursor.fetchone()

        # Parse extra field
        extra_json = row[0]
        assert extra_json is not None
        parsed = json.loads(extra_json)

        # Check that our extra data is there
        assert 'user_id' in parsed
        assert parsed['user_id'] == 42
        assert 'action' in parsed
        assert parsed['action'] == 'test'
        assert 'values' in parsed
        assert parsed['values'] == [1, 2, 3]
        assert 'nested' in parsed
        assert parsed['nested'] == {'key': 'value'}

        conn.close()
        logger.removeHandler(handler)
        handler.close()

    def test_sqlite_handler_thread_safety(self, temp_db):
        """Verify thread-safe operation."""
        import threading
        import time

        handler = SQLiteHandler(temp_db)
        logger = logging.getLogger('test_threads')
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)

        # Function to log from thread
        def log_from_thread(thread_id, count):
            for i in range(count):
                logger.info(f"Thread {thread_id} message {i}")
                time.sleep(0.001)  # Small delay to encourage interleaving

        # Create and start threads
        threads = []
        num_threads = 5
        messages_per_thread = 10

        for i in range(num_threads):
            t = threading.Thread(target=log_from_thread, args=(i, messages_per_thread))
            threads.append(t)
            t.start()

        # Wait for all threads
        for t in threads:
            t.join()

        # Check all messages were logged
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM logs")
        count = cursor.fetchone()[0]

        assert count == num_threads * messages_per_thread

        conn.close()
        logger.removeHandler(handler)
        handler.close()


class TestDebugScope:
    """Tests for debug_scope context manager."""

    @pytest.fixture
    def temp_db(self):
        """Create a temporary database file."""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = f.name

        yield db_path

        # Cleanup
        if os.path.exists(db_path):
            os.unlink(db_path)

    def test_debug_scope_enables_debug(self, temp_db):
        """Verify debug level is enabled within scope."""
        logger = logging.getLogger('test_scope')
        original_level = logger.level

        # Log outside scope (should not be captured)
        logger.debug("Outside scope debug")

        with debug_scope(
            loggers='test_scope',
            db_path=temp_db,
            test_id='scope_test',
            level=logging.DEBUG
        ):
            # Check that level was changed
            assert logger.level == logging.DEBUG

            # Log within scope
            logger.debug("Inside scope debug")
            logger.info("Inside scope info")

        # Query logs
        logs = query_logs(temp_db, test_id='scope_test')
        assert len(logs) == 2
        assert logs[0]['message'] == "Inside scope debug"
        assert logs[1]['message'] == "Inside scope info"

    def test_debug_scope_restores_level(self, temp_db):
        """Verify original log level is restored after scope."""
        logger = logging.getLogger('test_restore')

        # Set initial level
        logger.setLevel(logging.WARNING)
        original_level = logger.level
        original_handlers = logger.handlers.copy()

        with debug_scope(
            loggers='test_restore',
            db_path=temp_db,
            level=logging.DEBUG
        ):
            # Level should be DEBUG in scope
            assert logger.level == logging.DEBUG
            # Should have added a handler
            assert len(logger.handlers) > len(original_handlers)

        # After scope, level should be restored
        assert logger.level == original_level
        # Handlers should be restored
        assert len(logger.handlers) == len(original_handlers)

    def test_debug_scope_multiple_loggers(self, temp_db):
        """Verify debug_scope works with multiple loggers."""
        logger1 = logging.getLogger('test.logger1')
        logger2 = logging.getLogger('test.logger2')

        # Set different initial levels
        logger1.setLevel(logging.WARNING)
        logger2.setLevel(logging.ERROR)

        with debug_scope(
            loggers=['test.logger1', 'test.logger2'],
            db_path=temp_db,
            test_id='multi_test',
            level=logging.DEBUG
        ):
            # Both should be at DEBUG level
            assert logger1.level == logging.DEBUG
            assert logger2.level == logging.DEBUG

            # Log from both
            logger1.debug("Logger1 debug")
            logger2.debug("Logger2 debug")

        # Query logs
        logs = query_logs(temp_db, test_id='multi_test')
        assert len(logs) == 2
        loggers_found = {log['logger'] for log in logs}
        assert loggers_found == {'test.logger1', 'test.logger2'}

    def test_debug_scope_yields_handler(self, temp_db):
        """Verify debug_scope yields the SQLiteHandler instance."""
        with debug_scope(
            loggers='test_yield',
            db_path=temp_db,
            test_id='yield_test'
        ) as handler:
            assert isinstance(handler, SQLiteHandler)
            assert handler.db_path == temp_db
            assert handler.test_id == 'yield_test'


class TestQueryLogs:
    """Tests for query_logs function."""

    @pytest.fixture
    def populated_db(self):
        """Create and populate a test database."""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = f.name

        # Populate with test data
        handler = SQLiteHandler(db_path, test_id='test1')

        # Create multiple loggers
        logger1 = logging.getLogger('module.submodule1')
        logger2 = logging.getLogger('module.submodule2')

        logger1.addHandler(handler)
        logger2.addHandler(handler)
        logger1.setLevel(logging.DEBUG)
        logger2.setLevel(logging.DEBUG)

        # Log various messages
        logger1.debug("Debug 1")
        logger1.info("Info 1")
        logger1.warning("Warning 1")
        logger2.debug("Debug 2")
        logger2.error("Error 2")

        # Log with different test_id
        handler.test_id = 'test2'
        logger1.info("Info with test2")

        logger1.removeHandler(handler)
        logger2.removeHandler(handler)
        handler.close()

        yield db_path

        # Cleanup
        if os.path.exists(db_path):
            os.unlink(db_path)

    def test_query_logs_filters(self, populated_db):
        """Verify query filtering works correctly."""
        # Query all logs
        all_logs = query_logs(populated_db)
        assert len(all_logs) == 6

        # Filter by logger
        logger1_logs = query_logs(populated_db, logger='module.submodule1')
        assert len(logger1_logs) == 4
        assert all(log['logger'] == 'module.submodule1' for log in logger1_logs)

        # Filter by test_id
        test1_logs = query_logs(populated_db, test_id='test1')
        assert len(test1_logs) == 5

        test2_logs = query_logs(populated_db, test_id='test2')
        assert len(test2_logs) == 1
        assert test2_logs[0]['message'] == 'Info with test2'

        # Filter by level
        debug_logs = query_logs(populated_db, level='DEBUG')
        assert len(debug_logs) == 2
        assert all(log['level'] == 'DEBUG' for log in debug_logs)

        error_logs = query_logs(populated_db, level='ERROR')
        assert len(error_logs) == 1
        assert error_logs[0]['message'] == 'Error 2'

        # Combine filters
        logger1_debug = query_logs(
            populated_db,
            logger='module.submodule1',
            level='DEBUG'
        )
        assert len(logger1_debug) == 1
        assert logger1_debug[0]['message'] == 'Debug 1'

    def test_query_logs_limit(self, populated_db):
        """Verify limit parameter works."""
        # Query with limit
        limited_logs = query_logs(populated_db, limit=3)
        assert len(limited_logs) == 3

        # Should return oldest first (chronological order)
        all_logs = query_logs(populated_db)
        assert limited_logs == all_logs[:3]

    def test_query_logs_chronological_order(self, populated_db):
        """Verify logs are returned in chronological order."""
        logs = query_logs(populated_db)

        # Check messages are in expected order
        expected_order = [
            'Debug 1', 'Info 1', 'Warning 1',
            'Debug 2', 'Error 2', 'Info with test2'
        ]
        actual_order = [log['message'] for log in logs]
        assert actual_order == expected_order

    def test_query_logs_extra_deserialization(self, populated_db):
        """Verify extra field is deserialized from JSON."""
        # Add a log with extra data
        handler = SQLiteHandler(populated_db)
        logger = logging.getLogger('test_extra_query')
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)

        extra_data = {'key': 'value', 'num': 42}
        logger.info("With extra", extra=extra_data)

        logger.removeHandler(handler)
        handler.close()

        # Query and check extra field
        logs = query_logs(populated_db, logger='test_extra_query')
        assert len(logs) == 1
        log = logs[0]
        assert 'extra' in log
        assert isinstance(log['extra'], dict)
        assert log['extra']['key'] == 'value'
        assert log['extra']['num'] == 42