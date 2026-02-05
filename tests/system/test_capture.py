"""SQLite-based test result capture system for comparing deobfuscation outputs.

This module provides:
1. SQLite database schema for storing test results
2. Pytest plugin/fixture for automatic capture via --capture-to-db
3. Query helpers for comparing results between test runs

Usage:
    # Run tests and capture results
    pytest tests/system/test_libdeobfuscated.py --capture-to-db
    pytest tests/system/test_libdeobfuscated_dsl.py --capture-to-db

    # Query and compare results
    python -m tests.system.test_capture list-functions
    python -m tests.system.test_capture compare-suites test_libdeobfuscated test_libdeobfuscated_dsl
    python -m tests.system.test_capture get-function test_chained_add
"""

from __future__ import annotations

import datetime
import json
import pathlib
import sqlite3
from typing import Any, Optional

# Database path
DB_PATH = pathlib.Path(__file__).parent / ".test_results.db"

# Schema version for migrations
SCHEMA_VERSION = 1


# =============================================================================
# Schema & Database Setup
# =============================================================================

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS test_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Test identification
    test_suite TEXT NOT NULL,           -- e.g., 'test_libdeobfuscated.py'
    test_name TEXT NOT NULL,            -- e.g., 'test_simplify_chained_add'
    test_class TEXT,                    -- e.g., 'TestLibDeobfuscated'
    test_file TEXT,                     -- Full path to test file (optional)

    -- Function identification
    function_name TEXT NOT NULL,        -- e.g., 'test_chained_add'
    binary_name TEXT,                   -- e.g., 'libobfuscated.dylib'
    function_address TEXT,              -- e.g., '0x180001000'

    -- Deobfuscation results
    code_before TEXT,                   -- Obfuscated pseudocode
    code_after TEXT,                    -- Deobfuscated pseudocode
    code_changed BOOLEAN,               -- Did deobfuscation change the code?

    -- Statistics (JSON)
    rules_fired TEXT,                   -- JSON list of rule names
    stats_dict TEXT,                    -- JSON of full stats dict
    optimizer_usage TEXT,               -- JSON of optimizer usage
    cfg_rule_usage TEXT,                -- JSON of CFG rule usage

    -- Test outcome
    passed BOOLEAN NOT NULL,            -- Test passed?
    error_message TEXT,                 -- Error message if failed
    skipped BOOLEAN DEFAULT 0,          -- Test was skipped?
    skip_reason TEXT,                   -- Reason for skip

    -- Metadata
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    test_duration REAL,                 -- Test duration in seconds
    pytest_nodeid TEXT                  -- Full pytest node ID
);

CREATE INDEX IF NOT EXISTS idx_test_suite ON test_results(test_suite);
CREATE INDEX IF NOT EXISTS idx_function_name ON test_results(function_name);
CREATE INDEX IF NOT EXISTS idx_test_name ON test_results(test_name);
CREATE INDEX IF NOT EXISTS idx_timestamp ON test_results(timestamp);
CREATE INDEX IF NOT EXISTS idx_passed ON test_results(passed);

-- View for latest results per function
CREATE VIEW IF NOT EXISTS latest_results AS
SELECT
    function_name,
    test_suite,
    test_name,
    MAX(timestamp) as latest_timestamp,
    code_after,
    passed,
    rules_fired
FROM test_results
GROUP BY function_name, test_suite, test_name;

-- View for function coverage across test suites
CREATE VIEW IF NOT EXISTS function_coverage AS
SELECT
    function_name,
    COUNT(DISTINCT test_suite) as suite_count,
    GROUP_CONCAT(DISTINCT test_suite) as test_suites,
    COUNT(*) as total_runs,
    SUM(CASE WHEN passed THEN 1 ELSE 0 END) as passed_runs
FROM test_results
GROUP BY function_name;
"""


def init_database(db_path: pathlib.Path = DB_PATH) -> sqlite3.Connection:
    """Initialize the test results database.

    Args:
        db_path: Path to the SQLite database file.

    Returns:
        Database connection.
    """
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row

    # Create schema
    conn.executescript(SCHEMA_SQL)

    # Set/check schema version
    cursor = conn.execute("SELECT version FROM schema_version")
    row = cursor.fetchone()
    if row is None:
        conn.execute("INSERT INTO schema_version (version) VALUES (?)", (SCHEMA_VERSION,))
        conn.commit()

    return conn


# =============================================================================
# Result Capture
# =============================================================================

class TestResultCapture:
    """Capture test results to database."""

    def __init__(self, db_path: pathlib.Path = DB_PATH):
        self.db_path = db_path
        self.conn: Optional[sqlite3.Connection] = None

    def __enter__(self):
        self.conn = init_database(self.db_path)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.conn:
            self.conn.commit()
            self.conn.close()

    def capture_result(
        self,
        test_suite: str,
        test_name: str,
        function_name: str,
        code_before: str,
        code_after: str,
        stats_dict: dict,
        passed: bool,
        test_class: Optional[str] = None,
        test_file: Optional[str] = None,
        binary_name: Optional[str] = None,
        function_address: Optional[str] = None,
        error_message: Optional[str] = None,
        test_duration: Optional[float] = None,
        pytest_nodeid: Optional[str] = None,
        skipped: bool = False,
        skip_reason: Optional[str] = None,
    ) -> int:
        """Capture a test result.

        Args:
            test_suite: Test suite name (e.g., 'test_libdeobfuscated.py')
            test_name: Test name (e.g., 'test_simplify_chained_add')
            function_name: Function being tested (e.g., 'test_chained_add')
            code_before: Obfuscated pseudocode
            code_after: Deobfuscated pseudocode
            stats_dict: Statistics dictionary from state.stats.to_dict()
            passed: Whether the test passed
            test_class: Test class name
            test_file: Full path to test file
            binary_name: Binary being tested
            function_address: Function address
            error_message: Error message if failed
            test_duration: Test duration in seconds
            pytest_nodeid: Full pytest node ID
            skipped: Whether test was skipped
            skip_reason: Reason for skip

        Returns:
            Row ID of inserted result.
        """
        assert self.conn is not None, "Must use as context manager"

        # Extract rule information from stats
        rules_fired = list(stats_dict.get("instruction_rule_matches", {}).keys())
        optimizer_usage = stats_dict.get("optimizer_matches", {})
        cfg_rule_usage = stats_dict.get("cfg_rule_usages", {})

        code_changed = code_before != code_after

        cursor = self.conn.execute(
            """
            INSERT INTO test_results (
                test_suite, test_name, test_class, test_file,
                function_name, binary_name, function_address,
                code_before, code_after, code_changed,
                rules_fired, stats_dict, optimizer_usage, cfg_rule_usage,
                passed, error_message, skipped, skip_reason,
                test_duration, pytest_nodeid
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                test_suite, test_name, test_class, test_file,
                function_name, binary_name, function_address,
                code_before, code_after, code_changed,
                json.dumps(rules_fired), json.dumps(stats_dict),
                json.dumps(optimizer_usage), json.dumps(cfg_rule_usage),
                passed, error_message, skipped, skip_reason,
                test_duration, pytest_nodeid,
            ),
        )
        self.conn.commit()
        return cursor.lastrowid


# =============================================================================
# Query Helpers
# =============================================================================

class TestResultQuery:
    """Query test results from database."""

    def __init__(self, db_path: pathlib.Path = DB_PATH):
        self.db_path = db_path
        if not db_path.exists():
            raise FileNotFoundError(f"Database not found: {db_path}")
        self.conn = init_database(db_path)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.conn:
            self.conn.close()

    def list_functions(self) -> list[dict[str, Any]]:
        """List all functions tested with coverage information.

        Returns:
            List of dicts with function name, test suites, and run counts.
        """
        cursor = self.conn.execute(
            """
            SELECT * FROM function_coverage
            ORDER BY function_name
            """
        )
        return [dict(row) for row in cursor.fetchall()]

    def get_function_results(
        self,
        function_name: str,
        limit: Optional[int] = None,
    ) -> list[dict[str, Any]]:
        """Get all results for a specific function.

        Args:
            function_name: Function to query.
            limit: Maximum number of results to return.

        Returns:
            List of result dicts ordered by timestamp (newest first).
        """
        query = """
            SELECT * FROM test_results
            WHERE function_name = ?
            ORDER BY timestamp DESC
        """
        if limit:
            query += f" LIMIT {limit}"

        cursor = self.conn.execute(query, (function_name,))
        results = []
        for row in cursor.fetchall():
            result = dict(row)
            # Parse JSON fields
            if result.get("rules_fired"):
                result["rules_fired"] = json.loads(result["rules_fired"])
            if result.get("stats_dict"):
                result["stats_dict"] = json.loads(result["stats_dict"])
            if result.get("optimizer_usage"):
                result["optimizer_usage"] = json.loads(result["optimizer_usage"])
            if result.get("cfg_rule_usage"):
                result["cfg_rule_usage"] = json.loads(result["cfg_rule_usage"])
            results.append(result)
        return results

    def compare_suites(
        self,
        suite1: str,
        suite2: str,
        show_code_diff: bool = False,
    ) -> dict[str, Any]:
        """Compare results between two test suites.

        Args:
            suite1: First test suite (e.g., 'test_libdeobfuscated.py')
            suite2: Second test suite (e.g., 'test_libdeobfuscated_dsl.py')
            show_code_diff: Include code diffs in output

        Returns:
            Dictionary with comparison results:
            - common_functions: Functions tested by both
            - only_in_suite1: Functions only in suite1
            - only_in_suite2: Functions only in suite2
            - differences: Functions with different outcomes
        """
        # Get latest results for each suite
        cursor1 = self.conn.execute(
            """
            SELECT DISTINCT function_name, code_after, rules_fired, passed
            FROM test_results
            WHERE test_suite = ?
            AND timestamp = (
                SELECT MAX(timestamp) FROM test_results t2
                WHERE t2.test_suite = test_results.test_suite
                AND t2.function_name = test_results.function_name
            )
            """,
            (suite1,)
        )
        suite1_results = {
            row["function_name"]: dict(row)
            for row in cursor1.fetchall()
        }

        cursor2 = self.conn.execute(
            """
            SELECT DISTINCT function_name, code_after, rules_fired, passed
            FROM test_results
            WHERE test_suite = ?
            AND timestamp = (
                SELECT MAX(timestamp) FROM test_results t2
                WHERE t2.test_suite = test_results.test_suite
                AND t2.function_name = test_results.function_name
            )
            """,
            (suite2,)
        )
        suite2_results = {
            row["function_name"]: dict(row)
            for row in cursor2.fetchall()
        }

        functions1 = set(suite1_results.keys())
        functions2 = set(suite2_results.keys())

        common = functions1 & functions2
        only_1 = functions1 - functions2
        only_2 = functions2 - functions1

        differences = []
        for func in common:
            r1 = suite1_results[func]
            r2 = suite2_results[func]

            diff_entry = {
                "function": func,
                "passed_in_suite1": r1["passed"],
                "passed_in_suite2": r2["passed"],
                "code_changed": r1.get("code_after") != r2.get("code_after"),
            }

            # Parse JSON if needed
            rules1 = json.loads(r1["rules_fired"]) if r1.get("rules_fired") else []
            rules2 = json.loads(r2["rules_fired"]) if r2.get("rules_fired") else []

            rules1_set = set(rules1)
            rules2_set = set(rules2)

            diff_entry["rules_only_in_suite1"] = list(rules1_set - rules2_set)
            diff_entry["rules_only_in_suite2"] = list(rules2_set - rules1_set)
            diff_entry["common_rules"] = list(rules1_set & rules2_set)

            if show_code_diff and diff_entry["code_changed"]:
                diff_entry["code_suite1"] = r1.get("code_after", "")
                diff_entry["code_suite2"] = r2.get("code_after", "")

            # Only include if there are actual differences
            if (
                diff_entry["passed_in_suite1"] != diff_entry["passed_in_suite2"]
                or diff_entry["code_changed"]
                or diff_entry["rules_only_in_suite1"]
                or diff_entry["rules_only_in_suite2"]
            ):
                differences.append(diff_entry)

        return {
            "suite1": suite1,
            "suite2": suite2,
            "common_functions": sorted(common),
            "only_in_suite1": sorted(only_1),
            "only_in_suite2": sorted(only_2),
            "differences": differences,
            "total_functions_suite1": len(functions1),
            "total_functions_suite2": len(functions2),
            "total_common": len(common),
        }

    def get_test_suites(self) -> list[str]:
        """Get list of all test suites in database.

        Returns:
            List of test suite names.
        """
        cursor = self.conn.execute(
            "SELECT DISTINCT test_suite FROM test_results ORDER BY test_suite"
        )
        return [row["test_suite"] for row in cursor.fetchall()]

    def get_recent_runs(self, limit: int = 10) -> list[dict[str, Any]]:
        """Get recent test runs.

        Args:
            limit: Maximum number of runs to return.

        Returns:
            List of recent test results.
        """
        cursor = self.conn.execute(
            """
            SELECT
                test_suite,
                test_name,
                function_name,
                passed,
                timestamp,
                test_duration
            FROM test_results
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (limit,)
        )
        return [dict(row) for row in cursor.fetchall()]

    def get_stats_summary(self) -> dict[str, Any]:
        """Get overall statistics summary.

        Returns:
            Dictionary with database statistics.
        """
        cursor = self.conn.execute(
            """
            SELECT
                COUNT(*) as total_tests,
                COUNT(DISTINCT test_suite) as total_suites,
                COUNT(DISTINCT function_name) as total_functions,
                SUM(CASE WHEN passed THEN 1 ELSE 0 END) as passed_count,
                SUM(CASE WHEN skipped THEN 1 ELSE 0 END) as skipped_count,
                AVG(test_duration) as avg_duration
            FROM test_results
            """
        )
        return dict(cursor.fetchone())


# =============================================================================
# Pytest Plugin
# =============================================================================

def pytest_addoption(parser):
    """Add pytest command-line options."""
    parser.addoption(
        "--capture-to-db",
        action="store_true",
        default=False,
        help="Capture test results to SQLite database",
    )


def pytest_configure(config):
    """Configure pytest plugin."""
    if config.getoption("--capture-to-db"):
        config.pluginmanager.register(CapturePlugin(config), "capture_plugin")


class CapturePlugin:
    """Pytest plugin for capturing test results."""

    def __init__(self, config):
        self.config = config
        self.capture = TestResultCapture()
        self.capture.__enter__()

    def pytest_sessionfinish(self, session):
        """Called after whole test run finished."""
        self.capture.__exit__(None, None, None)

    def pytest_runtest_makereport(self, item, call):
        """Hook called when test report is created."""
        # We process results in pytest_runtest_logreport instead
        pass

    def pytest_runtest_logreport(self, report):
        """Hook called for each test report phase (setup/call/teardown)."""
        # Only process the "call" phase (actual test execution)
        if report.when != "call":
            return

        # Extract test information
        test_suite = pathlib.Path(report.fspath).name
        test_name = report.location[2]  # function name
        test_class = None
        if hasattr(report, "instance") and report.instance is not None:
            test_class = report.instance.__class__.__name__

        # Try to extract function name and test data from fixtures
        # This requires cooperation from the test - look for specific attributes
        function_name = None
        code_before = None
        code_after = None
        stats_dict = {}
        binary_name = None
        function_address = None

        # Try to get data from test item
        if hasattr(report, "user_properties"):
            for key, value in report.user_properties:
                if key == "function_name":
                    function_name = value
                elif key == "code_before":
                    code_before = value
                elif key == "code_after":
                    code_after = value
                elif key == "stats_dict":
                    stats_dict = value
                elif key == "binary_name":
                    binary_name = value
                elif key == "function_address":
                    function_address = value

        # If we don't have the essential data, skip capture
        if not function_name:
            return

        # Determine pass/fail/skip
        passed = report.outcome == "passed"
        skipped = report.outcome == "skipped"
        skip_reason = report.longrepr if skipped else None
        error_message = str(report.longrepr) if report.failed else None

        # Capture result
        try:
            self.capture.capture_result(
                test_suite=test_suite,
                test_name=test_name,
                function_name=function_name,
                code_before=code_before or "",
                code_after=code_after or "",
                stats_dict=stats_dict,
                passed=passed,
                test_class=test_class,
                test_file=report.fspath,
                binary_name=binary_name,
                function_address=function_address,
                error_message=error_message,
                test_duration=report.duration,
                pytest_nodeid=report.nodeid,
                skipped=skipped,
                skip_reason=skip_reason,
            )
        except Exception as e:
            # Don't let capture errors break tests
            print(f"Warning: Failed to capture test result: {e}")


# =============================================================================
# Pytest Fixture (for manual capture in tests)
# =============================================================================

def pytest_configure_for_fixtures(config):
    """Make fixtures available."""
    pass


try:
    import pytest

    @pytest.fixture
    def db_capture(request):
        """Fixture for manually capturing test results in tests.

        Usage:
            def test_something(self, d810_state, db_capture):
                with d810_state() as state:
                    # ... run test ...
                    db_capture.record(
                        function_name="test_func",
                        code_before=before,
                        code_after=after,
                        stats=state.stats,
                        passed=True
                    )
        """
        if not request.config.getoption("--capture-to-db", default=False):
            # Return a no-op object if capture is disabled
            class NoOpCapture:
                def record(self, **kwargs):
                    pass
            return NoOpCapture()

        # Get test context
        test_suite = pathlib.Path(request.fspath).name
        test_name = request.node.name
        test_class = request.cls.__name__ if request.cls else None
        binary_name = getattr(request.cls, "binary_name", None)

        class CaptureHelper:
            """Helper for manual result capture."""

            def record(
                self,
                function_name: str,
                code_before: str,
                code_after: str,
                stats: Any,
                passed: bool,
                function_address: Optional[str] = None,
                error_message: Optional[str] = None,
            ):
                """Record a test result."""
                # Store as user properties so pytest hooks can access
                request.node.user_properties.append(("function_name", function_name))
                request.node.user_properties.append(("code_before", code_before))
                request.node.user_properties.append(("code_after", code_after))
                request.node.user_properties.append(("stats_dict", stats.to_dict()))
                if binary_name:
                    request.node.user_properties.append(("binary_name", binary_name))
                if function_address:
                    request.node.user_properties.append(("function_address", function_address))

        return CaptureHelper()

except ImportError:
    # pytest not available (e.g., when running as script)
    pass


# =============================================================================
# CLI Interface
# =============================================================================

def main():
    """Command-line interface for querying test results."""
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Query D810 test results")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # list-functions command
    subparsers.add_parser(
        "list-functions",
        help="List all functions tested with coverage info"
    )

    # get-function command
    func_parser = subparsers.add_parser(
        "get-function",
        help="Get all results for a specific function"
    )
    func_parser.add_argument("function_name", help="Function name to query")
    func_parser.add_argument("--limit", type=int, help="Limit number of results")

    # compare-suites command
    compare_parser = subparsers.add_parser(
        "compare-suites",
        help="Compare results between two test suites"
    )
    compare_parser.add_argument("suite1", help="First test suite")
    compare_parser.add_argument("suite2", help="Second test suite")
    compare_parser.add_argument(
        "--show-code",
        action="store_true",
        help="Show code differences"
    )

    # list-suites command
    subparsers.add_parser(
        "list-suites",
        help="List all test suites in database"
    )

    # recent command
    recent_parser = subparsers.add_parser(
        "recent",
        help="Show recent test runs"
    )
    recent_parser.add_argument(
        "--limit",
        type=int,
        default=10,
        help="Number of recent runs to show"
    )

    # stats command
    subparsers.add_parser(
        "stats",
        help="Show database statistics"
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    # Check database exists
    if not DB_PATH.exists():
        print(f"Error: Database not found at {DB_PATH}", file=sys.stderr)
        print("Run tests with --capture-to-db to create it", file=sys.stderr)
        return 1

    with TestResultQuery() as query:
        if args.command == "list-functions":
            functions = query.list_functions()
            print(f"{'Function':<40} {'Suites':<3} {'Runs':<5} {'Passed':<6} {'Test Suites'}")
            print("=" * 100)
            for func in functions:
                print(
                    f"{func['function_name']:<40} "
                    f"{func['suite_count']:<3} "
                    f"{func['total_runs']:<5} "
                    f"{func['passed_runs']:<6} "
                    f"{func['test_suites']}"
                )

        elif args.command == "get-function":
            results = query.get_function_results(
                args.function_name,
                limit=args.limit
            )
            if not results:
                print(f"No results found for function: {args.function_name}")
                return 1

            for i, result in enumerate(results, 1):
                print(f"\n{'='*80}")
                print(f"Result {i} of {len(results)}")
                print(f"{'='*80}")
                print(f"Test: {result['test_suite']} :: {result['test_name']}")
                print(f"Function: {result['function_name']}")
                print(f"Passed: {result['passed']}")
                print(f"Timestamp: {result['timestamp']}")
                print(f"Code Changed: {result['code_changed']}")
                print(f"\nRules Fired ({len(result.get('rules_fired', []))}):")
                for rule in result.get("rules_fired", []):
                    print(f"  - {rule}")
                if result.get("code_after"):
                    print(f"\nDeobfuscated Code:")
                    print(result["code_after"])

        elif args.command == "compare-suites":
            comparison = query.compare_suites(
                args.suite1,
                args.suite2,
                show_code_diff=args.show_code
            )

            print(f"\nComparison: {comparison['suite1']} vs {comparison['suite2']}")
            print(f"{'='*80}")
            print(f"Total functions in {comparison['suite1']}: {comparison['total_functions_suite1']}")
            print(f"Total functions in {comparison['suite2']}: {comparison['total_functions_suite2']}")
            print(f"Common functions: {comparison['total_common']}")
            print(f"Only in {comparison['suite1']}: {len(comparison['only_in_suite1'])}")
            print(f"Only in {comparison['suite2']}: {len(comparison['only_in_suite2'])}")

            if comparison["only_in_suite1"]:
                print(f"\nFunctions only in {comparison['suite1']}:")
                for func in comparison["only_in_suite1"]:
                    print(f"  - {func}")

            if comparison["only_in_suite2"]:
                print(f"\nFunctions only in {comparison['suite2']}:")
                for func in comparison["only_in_suite2"]:
                    print(f"  - {func}")

            if comparison["differences"]:
                print(f"\nDifferences in common functions ({len(comparison['differences'])}):")
                for diff in comparison["differences"]:
                    print(f"\n  {diff['function']}:")
                    print(f"    Passed in suite1: {diff['passed_in_suite1']}")
                    print(f"    Passed in suite2: {diff['passed_in_suite2']}")
                    print(f"    Code changed: {diff['code_changed']}")
                    if diff['rules_only_in_suite1']:
                        print(f"    Rules only in suite1: {', '.join(diff['rules_only_in_suite1'])}")
                    if diff['rules_only_in_suite2']:
                        print(f"    Rules only in suite2: {', '.join(diff['rules_only_in_suite2'])}")
                    if args.show_code and diff['code_changed']:
                        print(f"\n    Code in suite1:")
                        for line in diff['code_suite1'].split('\n'):
                            print(f"      {line}")
                        print(f"\n    Code in suite2:")
                        for line in diff['code_suite2'].split('\n'):
                            print(f"      {line}")
            else:
                print("\nNo differences found in common functions!")

        elif args.command == "list-suites":
            suites = query.get_test_suites()
            print("Test Suites:")
            for suite in suites:
                print(f"  - {suite}")

        elif args.command == "recent":
            runs = query.get_recent_runs(limit=args.limit)
            print(f"{'Timestamp':<20} {'Suite':<30} {'Function':<30} {'Passed':<7} {'Duration'}")
            print("=" * 120)
            for run in runs:
                print(
                    f"{run['timestamp']:<20} "
                    f"{run['test_suite']:<30} "
                    f"{run['function_name']:<30} "
                    f"{'✓' if run['passed'] else '✗':<7} "
                    f"{run['test_duration']:.3f}s" if run['test_duration'] else ""
                )

        elif args.command == "stats":
            stats = query.get_stats_summary()
            print("Database Statistics:")
            print(f"  Total tests: {stats['total_tests']}")
            print(f"  Test suites: {stats['total_suites']}")
            print(f"  Functions tested: {stats['total_functions']}")
            print(f"  Passed: {stats['passed_count']}")
            print(f"  Skipped: {stats['skipped_count']}")
            print(f"  Failed: {stats['total_tests'] - stats['passed_count'] - stats['skipped_count']}")
            if stats['avg_duration']:
                print(f"  Average duration: {stats['avg_duration']:.3f}s")

    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
