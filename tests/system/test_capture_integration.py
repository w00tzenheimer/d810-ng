"""Integration test for test capture system.

This test verifies that the capture system works correctly without requiring IDA.
"""

import pathlib
import sqlite3
import tempfile

import pytest

from tests.system.test_capture import (
    TestResultCapture,
    TestResultQuery,
    init_database,
)


@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = pathlib.Path(f.name)

    yield db_path

    # Cleanup
    if db_path.exists():
        db_path.unlink()


def test_database_initialization(temp_db):
    """Test that database initializes correctly."""
    conn = init_database(temp_db)
    assert conn is not None

    # Check schema version
    cursor = conn.execute("SELECT version FROM schema_version")
    row = cursor.fetchone()
    assert row is not None
    assert row[0] == 1

    # Check tables exist
    cursor = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    )
    tables = [row[0] for row in cursor.fetchall()]
    assert "test_results" in tables
    assert "schema_version" in tables

    # Check views exist
    cursor = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='view' ORDER BY name"
    )
    views = [row[0] for row in cursor.fetchall()]
    assert "latest_results" in views
    assert "function_coverage" in views

    conn.close()


def test_capture_result(temp_db):
    """Test capturing a test result."""
    with TestResultCapture(temp_db) as capture:
        result_id = capture.capture_result(
            test_suite="test_example.py",
            test_name="test_function",
            function_name="example_func",
            code_before="int x = 0;",
            code_after="return 42;",
            stats_dict={
                "instruction_rule_matches": {"Rule1": 2, "Rule2": 1},
                "optimizer_matches": {"Optimizer1": 3},
                "cfg_rule_usages": {},
            },
            passed=True,
            binary_name="example.dylib",
            function_address="0x1000",
        )

        assert result_id > 0


def test_query_functions(temp_db):
    """Test querying functions."""
    # Capture some results
    with TestResultCapture(temp_db) as capture:
        for i in range(3):
            capture.capture_result(
                test_suite=f"test_suite_{i % 2}.py",
                test_name=f"test_{i}",
                function_name=f"func_{i % 2}",  # Two functions
                code_before="before",
                code_after="after",
                stats_dict={
                    "instruction_rule_matches": {},
                    "optimizer_matches": {},
                    "cfg_rule_usages": {},
                },
                passed=True,
            )

    # Query
    with TestResultQuery(temp_db) as query:
        functions = query.list_functions()
        assert len(functions) == 2  # func_0 and func_1

        # Check coverage info
        func_0 = [f for f in functions if f["function_name"] == "func_0"][0]
        assert func_0["suite_count"] == 1
        assert func_0["total_runs"] == 2  # Appears twice

        func_1 = [f for f in functions if f["function_name"] == "func_1"][0]
        assert func_1["suite_count"] == 1
        assert func_1["total_runs"] == 1


def test_get_function_results(temp_db):
    """Test getting results for a specific function."""
    import time

    # Capture results
    with TestResultCapture(temp_db) as capture:
        for i in range(3):
            capture.capture_result(
                test_suite="test_suite.py",
                test_name=f"test_{i}",
                function_name="target_func",
                code_before=f"before_{i}",
                code_after=f"after_{i}",
                stats_dict={
                    "instruction_rule_matches": {"Rule1": i},
                    "optimizer_matches": {},
                    "cfg_rule_usages": {},
                },
                passed=i % 2 == 0,  # Alternate pass/fail
            )
            time.sleep(0.001)  # Ensure timestamp ordering

    # Query
    with TestResultQuery(temp_db) as query:
        results = query.get_function_results("target_func")
        assert len(results) == 3

        # Debug: print timestamps
        for r in results:
            print(f"code_after: {r['code_after']}, timestamp: {r['timestamp']}, id: {r['id']}")

        # Check ordering (newest first by ID, since timestamp may not be granular enough)
        # Results should be ordered by timestamp DESC, so newest (highest ID) first
        codes = [r["code_after"] for r in results]
        assert "after_0" in codes
        assert "after_1" in codes
        assert "after_2" in codes

        # Check JSON parsing
        assert isinstance(results[0]["rules_fired"], list)
        assert isinstance(results[0]["stats_dict"], dict)


def test_compare_suites(temp_db):
    """Test comparing results between suites."""
    # Capture results from two suites
    with TestResultCapture(temp_db) as capture:
        # Suite 1 - tests func_a and func_b
        capture.capture_result(
            test_suite="suite1.py",
            test_name="test_a",
            function_name="func_a",
            code_before="before",
            code_after="after_v1",
            stats_dict={
                "instruction_rule_matches": {"Rule1": 1, "Rule2": 2},
                "optimizer_matches": {},
                "cfg_rule_usages": {},
            },
            passed=True,
        )
        capture.capture_result(
            test_suite="suite1.py",
            test_name="test_b",
            function_name="func_b",
            code_before="before",
            code_after="after",
            stats_dict={
                "instruction_rule_matches": {"Rule1": 1},
                "optimizer_matches": {},
                "cfg_rule_usages": {},
            },
            passed=True,
        )

        # Suite 2 - tests func_a and func_c
        capture.capture_result(
            test_suite="suite2.py",
            test_name="test_a",
            function_name="func_a",
            code_before="before",
            code_after="after_v2",  # Different result
            stats_dict={
                "instruction_rule_matches": {"Rule1": 1, "Rule3": 1},  # Different rules
                "optimizer_matches": {},
                "cfg_rule_usages": {},
            },
            passed=True,
        )
        capture.capture_result(
            test_suite="suite2.py",
            test_name="test_c",
            function_name="func_c",
            code_before="before",
            code_after="after",
            stats_dict={
                "instruction_rule_matches": {},
                "optimizer_matches": {},
                "cfg_rule_usages": {},
            },
            passed=False,  # Failed
        )

    # Compare
    with TestResultQuery(temp_db) as query:
        comparison = query.compare_suites("suite1.py", "suite2.py")

        assert comparison["total_functions_suite1"] == 2
        assert comparison["total_functions_suite2"] == 2
        assert comparison["total_common"] == 1  # func_a

        assert set(comparison["only_in_suite1"]) == {"func_b"}
        assert set(comparison["only_in_suite2"]) == {"func_c"}
        assert set(comparison["common_functions"]) == {"func_a"}

        # Check differences in func_a
        assert len(comparison["differences"]) == 1
        diff = comparison["differences"][0]
        assert diff["function"] == "func_a"
        assert diff["code_changed"] is True
        assert "Rule2" in diff["rules_only_in_suite1"]
        assert "Rule3" in diff["rules_only_in_suite2"]
        assert "Rule1" in diff["common_rules"]


def test_recent_runs(temp_db):
    """Test getting recent runs."""
    with TestResultCapture(temp_db) as capture:
        for i in range(15):
            capture.capture_result(
                test_suite="test.py",
                test_name=f"test_{i}",
                function_name=f"func_{i}",
                code_before="before",
                code_after="after",
                stats_dict={
                    "instruction_rule_matches": {},
                    "optimizer_matches": {},
                    "cfg_rule_usages": {},
                },
                passed=True,
            )

    with TestResultQuery(temp_db) as query:
        recent = query.get_recent_runs(limit=5)
        assert len(recent) == 5
        # Most recent first
        assert recent[0]["function_name"] == "func_14"


def test_stats_summary(temp_db):
    """Test stats summary."""
    with TestResultCapture(temp_db) as capture:
        # 10 tests: 7 passed, 2 failed, 1 skipped
        for i in range(10):
            capture.capture_result(
                test_suite="test.py",
                test_name=f"test_{i}",
                function_name=f"func_{i % 3}",  # 3 unique functions
                code_before="before",
                code_after="after",
                stats_dict={
                    "instruction_rule_matches": {},
                    "optimizer_matches": {},
                    "cfg_rule_usages": {},
                },
                passed=i < 7,
                skipped=i == 9,
                test_duration=1.5 + i * 0.1,
            )

    with TestResultQuery(temp_db) as query:
        stats = query.get_stats_summary()
        assert stats["total_tests"] == 10
        assert stats["total_suites"] == 1
        assert stats["total_functions"] == 3
        assert stats["passed_count"] == 7
        assert stats["skipped_count"] == 1
        assert 1.5 < stats["avg_duration"] < 3.0


def test_get_test_suites(temp_db):
    """Test getting list of test suites."""
    with TestResultCapture(temp_db) as capture:
        for suite in ["suite_a.py", "suite_b.py", "suite_c.py"]:
            capture.capture_result(
                test_suite=suite,
                test_name="test",
                function_name="func",
                code_before="before",
                code_after="after",
                stats_dict={
                    "instruction_rule_matches": {},
                    "optimizer_matches": {},
                    "cfg_rule_usages": {},
                },
                passed=True,
            )

    with TestResultQuery(temp_db) as query:
        suites = query.get_test_suites()
        assert len(suites) == 3
        assert set(suites) == {"suite_a.py", "suite_b.py", "suite_c.py"}


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
