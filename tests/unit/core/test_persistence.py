"""Tests for OptimizationStorage (IDA-independent persistence layer)."""

import tempfile
import pytest
from pathlib import Path

from d810.core.persistence import (
    OptimizationStorage,
    FunctionFingerprint,
    CachedResult,
    FunctionRuleConfig,
)


@pytest.fixture
def temp_db():
    """Create a temporary database file."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = Path(f.name)
    yield db_path
    # Cleanup
    if db_path.exists():
        db_path.unlink()


@pytest.fixture
def storage(temp_db):
    """Create a storage instance with temporary database."""
    s = OptimizationStorage(temp_db)
    yield s
    s.close()


class TestFunctionFingerprint:
    """Tests for FunctionFingerprint dataclass."""

    def test_create_fingerprint(self):
        """Test creating a fingerprint."""
        fp = FunctionFingerprint(
            address=0x401000,
            size=100,
            bytes_hash="abc123",
            block_count=5,
            instruction_count=50
        )

        assert fp.address == 0x401000
        assert fp.size == 100
        assert fp.bytes_hash == "abc123"
        assert fp.block_count == 5
        assert fp.instruction_count == 50


class TestOptimizationStorage:
    """Tests for OptimizationStorage class."""

    def test_init_creates_database(self, temp_db):
        """Test that initialization creates the database file."""
        storage = OptimizationStorage(temp_db)
        assert temp_db.exists()
        storage.close()

    def test_save_and_load_result(self, storage):
        """Test saving and loading optimization results."""
        fingerprint = FunctionFingerprint(
            address=0x401000,
            size=100,
            bytes_hash="test_hash_123",
            block_count=5,
            instruction_count=50
        )

        patches = [
            {"type": "redirect_edge", "from": 1, "to": 2},
            {"type": "insert_block", "after": 3},
        ]

        # Save result
        storage.save_result(
            function_addr=0x401000,
            fingerprint=fingerprint,
            maturity=5,
            changes=42,
            patches=patches
        )

        # Load result
        result = storage.load_result(0x401000, maturity=5)

        assert result is not None
        assert result.function_addr == 0x401000
        assert result.maturity == 5
        assert result.changes_made == 42
        assert len(result.patches) == 2
        assert result.fingerprint == "test_hash_123"

    def test_load_nonexistent_result(self, storage):
        """Test loading a result that doesn't exist."""
        result = storage.load_result(0x999999, maturity=1)
        assert result is None

    def test_has_valid_cache(self, storage):
        """Test cache validation."""
        fingerprint = FunctionFingerprint(
            address=0x401000,
            size=100,
            bytes_hash="valid_hash",
            block_count=5,
            instruction_count=50
        )

        # Save fingerprint
        storage.save_fingerprint(fingerprint)

        # Check with matching hash
        assert storage.has_valid_cache(0x401000, "valid_hash") is True

        # Check with different hash
        assert storage.has_valid_cache(0x401000, "different_hash") is False

        # Check nonexistent function
        assert storage.has_valid_cache(0x999999, "any_hash") is False

    def test_set_and_get_function_rules(self, storage):
        """Test per-function rule configuration."""
        storage.set_function_rules(
            function_addr=0x401000,
            enabled_rules={"Rule1", "Rule2"},
            disabled_rules={"SlowRule"},
            notes="Testing rule config"
        )

        config = storage.get_function_rules(0x401000)

        assert config is not None
        assert config.function_addr == 0x401000
        assert "Rule1" in config.enabled_rules
        assert "Rule2" in config.enabled_rules
        assert "SlowRule" in config.disabled_rules
        assert config.notes == "Testing rule config"

    def test_get_nonexistent_function_rules(self, storage):
        """Test getting rules for function without config."""
        config = storage.get_function_rules(0x999999)
        assert config is None

    def test_should_run_rule_no_config(self, storage):
        """Test should_run_rule with no configuration."""
        # No config = run all rules
        assert storage.should_run_rule(0x401000, "AnyRule") is True

    def test_should_run_rule_with_enabled_list(self, storage):
        """Test should_run_rule with enabled rules list."""
        storage.set_function_rules(
            function_addr=0x401000,
            enabled_rules={"AllowedRule"}
        )

        assert storage.should_run_rule(0x401000, "AllowedRule") is True
        assert storage.should_run_rule(0x401000, "OtherRule") is False

    def test_should_run_rule_with_disabled_list(self, storage):
        """Test should_run_rule with disabled rules list."""
        storage.set_function_rules(
            function_addr=0x401000,
            disabled_rules={"BannedRule"}
        )

        assert storage.should_run_rule(0x401000, "BannedRule") is False
        assert storage.should_run_rule(0x401000, "OtherRule") is True

    def test_invalidate_function(self, storage):
        """Test invalidating cached data for a function."""
        fingerprint = FunctionFingerprint(
            address=0x401000,
            size=100,
            bytes_hash="test_hash",
            block_count=5,
            instruction_count=50
        )

        # Save data
        storage.save_result(
            function_addr=0x401000,
            fingerprint=fingerprint,
            maturity=5,
            changes=10,
            patches=[]
        )

        # Verify it exists
        assert storage.load_result(0x401000, 5) is not None

        # Invalidate
        storage.invalidate_function(0x401000)

        # Verify it's gone
        assert storage.load_result(0x401000, 5) is None
        assert storage.has_valid_cache(0x401000, "test_hash") is False

    def test_get_statistics(self, storage):
        """Test statistics retrieval."""
        fingerprint = FunctionFingerprint(
            address=0x401000,
            size=100,
            bytes_hash="test_hash",
            block_count=5,
            instruction_count=50
        )

        storage.save_result(
            function_addr=0x401000,
            fingerprint=fingerprint,
            maturity=5,
            changes=10,
            patches=[{"type": "test"}]
        )

        storage.set_function_rules(0x401000, disabled_rules={"TestRule"})

        stats = storage.get_statistics()

        assert stats['functions_cached'] == 1
        assert stats['results_cached'] == 1
        assert stats['patches_stored'] == 1
        assert stats['functions_with_custom_rules'] == 1

    def test_context_manager(self, temp_db):
        """Test context manager support."""
        with OptimizationStorage(temp_db) as storage:
            fingerprint = FunctionFingerprint(
                address=0x401000,
                size=100,
                bytes_hash="test",
                block_count=1,
                instruction_count=10
            )
            storage.save_fingerprint(fingerprint)

        # Connection should be closed
        assert storage.conn is None

    def test_multiple_maturities(self, storage):
        """Test storing results for multiple maturity levels."""
        fingerprint = FunctionFingerprint(
            address=0x401000,
            size=100,
            bytes_hash="test_hash",
            block_count=5,
            instruction_count=50
        )

        # Save results for different maturities
        storage.save_result(0x401000, fingerprint, maturity=1, changes=5, patches=[])
        storage.save_result(0x401000, fingerprint, maturity=3, changes=10, patches=[])
        storage.save_result(0x401000, fingerprint, maturity=5, changes=15, patches=[])

        # Load and verify
        r1 = storage.load_result(0x401000, 1)
        r3 = storage.load_result(0x401000, 3)
        r5 = storage.load_result(0x401000, 5)

        assert r1.changes_made == 5
        assert r3.changes_made == 10
        assert r5.changes_made == 15

    def test_update_existing_result(self, storage):
        """Test updating an existing result."""
        fingerprint = FunctionFingerprint(
            address=0x401000,
            size=100,
            bytes_hash="test_hash",
            block_count=5,
            instruction_count=50
        )

        # Save initial result
        storage.save_result(
            function_addr=0x401000,
            fingerprint=fingerprint,
            maturity=5,
            changes=10,
            patches=[{"type": "old"}]
        )

        # Update with new result
        storage.save_result(
            function_addr=0x401000,
            fingerprint=fingerprint,
            maturity=5,
            changes=20,
            patches=[{"type": "new1"}, {"type": "new2"}]
        )

        # Load and verify updated
        result = storage.load_result(0x401000, 5)
        assert result.changes_made == 20
        assert len(result.patches) == 2
        assert result.patches[0]["type"] == "new1"
