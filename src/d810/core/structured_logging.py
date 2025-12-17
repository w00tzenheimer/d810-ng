"""
SQLite-based structured logging handler for d810.

This module provides a SQLite logging handler that captures structured log data,
enabling agents to query debug logs without reading raw log files.
"""

import json
import logging
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union


class SQLiteHandler(logging.Handler):
    """
    A logging handler that writes records to a SQLite database.

    Thread-safe implementation using a lock for database operations.
    """

    # Standard LogRecord attributes to exclude from extra field
    STANDARD_ATTRS = {
        'name', 'msg', 'args', 'created', 'msecs', 'levelname', 'levelno',
        'pathname', 'filename', 'module', 'lineno', 'funcName', 'thread',
        'threadName', 'processName', 'process', 'message', 'relativeCreated',
        'exc_info', 'exc_text', 'stack_info', 'asctime'
    }

    def __init__(self, db_path: str, test_id: str = None):
        """
        Initialize SQLite logging handler.

        Args:
            db_path: Path to SQLite database file.
            test_id: Optional test identifier for correlating logs.
        """
        super().__init__()
        self.db_path = db_path
        self.test_id = test_id
        self._lock = threading.Lock()

        # Ensure parent directory exists
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)

        # Initialize database schema
        self._init_schema()

    def _init_schema(self):
        """Create the database schema if it doesn't exist."""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.cursor()
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

                # Create indexes for common queries
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_logger ON logs(logger)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_test_id ON logs(test_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_level ON logs(level)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp)")

                conn.commit()
            finally:
                conn.close()

    def emit(self, record: logging.LogRecord):
        """
        Write a log record to the database.

        Args:
            record: The log record to write.
        """
        try:
            # Format timestamp as ISO 8601
            timestamp = datetime.fromtimestamp(record.created).strftime('%Y-%m-%dT%H:%M:%S.%f')

            # Extract extra fields
            extra = {}
            for key, value in record.__dict__.items():
                if key not in self.STANDARD_ATTRS:
                    try:
                        # Ensure value is JSON serializable
                        json.dumps(value)
                        extra[key] = value
                    except (TypeError, ValueError):
                        # If not serializable, convert to string
                        extra[key] = str(value)

            # Serialize extra as JSON string, or None if empty
            extra_json = json.dumps(extra) if extra else None

            # Get formatted message
            msg = self.format(record)

            # Insert record into database
            with self._lock:
                conn = sqlite3.connect(self.db_path)
                try:
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT INTO logs (
                            timestamp, logger, level, levelno, function,
                            lineno, pathname, message, extra, test_id
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        timestamp,
                        record.name,
                        record.levelname,
                        record.levelno,
                        record.funcName,
                        record.lineno,
                        record.pathname,
                        msg,
                        extra_json,
                        self.test_id
                    ))
                    conn.commit()
                finally:
                    conn.close()

        except Exception as e:
            # Don't raise exceptions from emit() - log handler errors shouldn't crash the app
            # We can't use logging here as it might cause infinite recursion
            # Instead, we'll silently fail (as per logging best practices)
            pass

    def close(self):
        """Close the handler (no persistent connection to close)."""
        super().close()


@contextmanager
def debug_scope(
    loggers: Union[List[str], str] = 'd810',
    db_path: str = '.d810_debug.db',
    test_id: str = None,
    level: int = logging.DEBUG
):
    """
    Context manager that temporarily enables DEBUG logging to SQLite.

    Usage:
        with debug_scope(
            loggers=['d810.hexrays.tracker'],
            db_path='test.db',
            test_id='test_abc_f6'
        ):
            # Code here has DEBUG logging captured to SQLite
            result = some_function()

        # After scope: logs in SQLite, original levels restored

    Args:
        loggers: Logger name(s) to enable debug for. Can be single string or list.
        db_path: Path to SQLite database file.
        test_id: Optional test identifier for correlating logs.
        level: Log level to set (default DEBUG).

    Yields:
        SQLiteHandler instance (for querying db_path after scope)
    """
    # Normalize loggers to list
    if isinstance(loggers, str):
        loggers = [loggers]

    # Create SQLite handler
    handler = SQLiteHandler(db_path, test_id)
    handler.setLevel(level)

    # Store original levels and handlers
    original_state = []

    try:
        # Configure each logger
        for logger_name in loggers:
            logger = logging.getLogger(logger_name)

            # Store original state
            original_state.append({
                'logger': logger,
                'level': logger.level,
                'propagate': logger.propagate,
                'handlers': logger.handlers.copy()
            })

            # Set new level and add handler
            logger.setLevel(level)
            logger.addHandler(handler)

        # Yield the handler for potential use
        yield handler

    finally:
        # Restore original state
        for state in original_state:
            logger = state['logger']
            logger.setLevel(state['level'])
            logger.removeHandler(handler)

        # Close the handler
        handler.close()


def query_logs(
    db_path: str,
    logger: str = None,
    test_id: str = None,
    level: str = None,
    limit: int = 100
) -> List[Dict[str, Any]]:
    """
    Query logs from SQLite database.

    Args:
        db_path: Path to SQLite database file.
        logger: Optional logger name to filter by.
        test_id: Optional test ID to filter by.
        level: Optional log level to filter by.
        limit: Maximum number of records to return.

    Returns:
        List of dicts with log record fields.
    """
    # Build query with filters
    query = "SELECT * FROM logs WHERE 1=1"
    params = []

    if logger:
        query += " AND logger = ?"
        params.append(logger)

    if test_id:
        query += " AND test_id = ?"
        params.append(test_id)

    if level:
        query += " AND level = ?"
        params.append(level)

    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    # Execute query
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row  # Enable column access by name

    try:
        cursor = conn.cursor()
        cursor.execute(query, params)

        # Convert rows to dicts
        results = []
        for row in cursor.fetchall():
            record = dict(row)
            # Deserialize extra field if present
            if record.get('extra'):
                try:
                    record['extra'] = json.loads(record['extra'])
                except json.JSONDecodeError:
                    pass  # Leave as string if not valid JSON
            results.append(record)

        # Return in chronological order (we selected in reverse)
        return results[::-1]

    finally:
        conn.close()