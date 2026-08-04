"""Tests for sqlite persistence backend."""

import sqlite3
import tempfile
import pytest
from pathlib import Path

from d810.core.persistence import (
    FunctionFingerprint,
    FunctionStorageLocator,
    SQLiteOptimizationStorage,
    create_optimization_storage,
)
from d810.core.provider_phase import ProviderPhaseSnapshot


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
    s = SQLiteOptimizationStorage(temp_db)
    yield s
    s.close()


def provider_phase(level=5, friendly_level="MMAT_GLBOPT1"):
    return ProviderPhaseSnapshot(
        provider_name="hexrays_microcode",
        provider_level=level,
        friendly_provider_level=friendly_level,
    )


class TestFunctionFingerprint:
    """Tests for FunctionFingerprint dataclass."""

    def test_create_fingerprint(self):
        """Test creating a fingerprint."""
        fp = FunctionFingerprint(
            address=0x401000,
            size=100,
            bytes_hash="abc123",
            block_count=5,
            instruction_count=50,
        )

        assert fp.address == 0x401000
        assert fp.size == 100
        assert fp.bytes_hash == "abc123"
        assert fp.block_count == 5
        assert fp.instruction_count == 50


class TestSQLiteOptimizationStorage:
    """Tests for SQLiteOptimizationStorage class."""

    def test_init_creates_database(self, temp_db):
        """Test that initialization creates the database file."""
        storage = SQLiteOptimizationStorage(temp_db)
        assert temp_db.exists()
        storage.close()

    def test_save_and_load_result(self, storage):
        """Test saving and loading optimization results."""
        fingerprint = FunctionFingerprint(
            address=0x401000,
            size=100,
            bytes_hash="test_hash_123",
            block_count=5,
            instruction_count=50,
        )

        patches = [
            {"type": "redirect_edge", "from": 1, "to": 2},
            {"type": "insert_block", "after": 3},
        ]

        # Save result
        storage.save_result(
            function_addr=0x401000,
            fingerprint=fingerprint,
            provider_phase=provider_phase(),
            changes=42,
            patches=patches,
        )

        # Load result
        result = storage.load_result(0x401000, provider_phase=provider_phase())

        assert result is not None
        assert result.function_addr == 0x401000
        assert result.provider_level == 5
        assert result.friendly_provider_level == "MMAT_GLBOPT1"
        assert result.changes_made == 42
        assert len(result.patches) == 2
        assert result.fingerprint == "test_hash_123"

    def test_load_nonexistent_result(self, storage):
        """Test loading a result that doesn't exist."""
        result = storage.load_result(0x999999, provider_phase=provider_phase(1))
        assert result is None

    def test_has_valid_cache(self, storage):
        """Test cache validation."""
        fingerprint = FunctionFingerprint(
            address=0x401000,
            size=100,
            bytes_hash="valid_hash",
            block_count=5,
            instruction_count=50,
        )

        # Save fingerprint
        storage.save_fingerprint(fingerprint)

        # Check with matching hash
        assert storage.has_valid_cache(0x401000, "valid_hash") is True

        # Check with different hash
        assert storage.has_valid_cache(0x401000, "different_hash") is False

        # Check nonexistent function
        assert storage.has_valid_cache(0x999999, "any_hash") is False

    def test_set_and_get_function_tags(self, storage):
        """Function tags are keyed by database, project, and EA."""
        locator = FunctionStorageLocator("sample.i64", "sample", 0x401000)
        storage.set_function_tags(locator, {"flattened", "opaque_pred"})
        tags = storage.get_function_tags(locator)
        assert tags == {"flattened", "opaque_pred"}

    def test_same_ea_tags_do_not_collide_across_database_identity(self, storage):
        first = FunctionStorageLocator("first.i64", "sample", 0x401000)
        second = FunctionStorageLocator("second.i64", "sample", 0x401000)

        storage.set_function_tags(first, {"first"})
        storage.set_function_tags(second, {"second"})

        assert storage.get_function_tags(first) == {"first"}
        assert storage.get_function_tags(second) == {"second"}

    def test_invalidate_function(self, storage):
        """Test invalidating cached data for a function."""
        fingerprint = FunctionFingerprint(
            address=0x401000,
            size=100,
            bytes_hash="test_hash",
            block_count=5,
            instruction_count=50,
        )

        # Save data
        storage.save_result(
            function_addr=0x401000,
            fingerprint=fingerprint,
            provider_phase=provider_phase(),
            changes=10,
            patches=[],
        )

        # Verify it exists
        assert storage.load_result(0x401000, provider_phase()) is not None

        # Invalidate
        storage.invalidate_function(0x401000)

        # Verify it's gone
        assert storage.load_result(0x401000, provider_phase()) is None
        assert storage.has_valid_cache(0x401000, "test_hash") is False

    def test_get_statistics(self, storage):
        """Test statistics retrieval."""
        fingerprint = FunctionFingerprint(
            address=0x401000,
            size=100,
            bytes_hash="test_hash",
            block_count=5,
            instruction_count=50,
        )

        storage.save_result(
            function_addr=0x401000,
            fingerprint=fingerprint,
            provider_phase=provider_phase(),
            changes=10,
            patches=[{"type": "test"}],
        )

        stats = storage.get_statistics()

        assert stats["functions_cached"] == 1
        assert stats["results_cached"] == 1
        assert stats["patches_stored"] == 1

    def test_migrates_legacy_phase_schema(self, temp_db):
        """Test migrating cache rows from the pre-provider phase schema."""
        conn = sqlite3.connect(str(temp_db))
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE functions (
                address INTEGER PRIMARY KEY,
                size INTEGER NOT NULL,
                bytes_hash TEXT NOT NULL,
                block_count INTEGER NOT NULL,
                instruction_count INTEGER NOT NULL,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            )
        """
        )
        cursor.execute(
            """
            CREATE TABLE patches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                function_addr INTEGER NOT NULL,
                maturity INTEGER NOT NULL,
                patch_type TEXT NOT NULL,
                patch_data TEXT NOT NULL,
                created_at REAL NOT NULL
            )
        """
        )
        cursor.execute(
            """
            CREATE TABLE results (
                function_addr INTEGER NOT NULL,
                maturity INTEGER NOT NULL,
                changes_made INTEGER NOT NULL,
                fingerprint TEXT NOT NULL,
                timestamp REAL NOT NULL,
                PRIMARY KEY (function_addr, maturity)
            )
        """
        )
        cursor.execute(
            """
            INSERT INTO functions
            (
                address,
                size,
                bytes_hash,
                block_count,
                instruction_count,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
            (0x401000, 100, "legacy_hash", 5, 50, 1.0, 1.0),
        )
        cursor.execute(
            """
            INSERT INTO results
            (function_addr, maturity, changes_made, fingerprint, timestamp)
            VALUES (?, ?, ?, ?, ?)
        """,
            (0x401000, 5, 7, "legacy_hash", 2.0),
        )
        cursor.execute(
            """
            INSERT INTO patches
            (function_addr, maturity, patch_type, patch_data, created_at)
            VALUES (?, ?, ?, ?, ?)
        """,
            (0x401000, 5, "legacy_patch", '{"type": "legacy_patch"}', 2.0),
        )
        conn.commit()
        conn.close()

        storage = SQLiteOptimizationStorage(temp_db)
        try:
            result = storage.load_result(0x401000, provider_phase())
            assert result is not None
            assert result.provider_name == "hexrays_microcode"
            assert result.provider_level == 5
            assert result.changes_made == 7
            assert result.patches == [{"type": "legacy_patch"}]

            cursor = storage.conn.cursor()
            cursor.execute("PRAGMA table_info(results)")
            result_columns = {row["name"] for row in cursor.fetchall()}
            assert "provider_level" in result_columns
            assert "maturity" not in result_columns
        finally:
            storage.close()

    def test_context_manager(self, temp_db):
        """Test context manager support."""
        with SQLiteOptimizationStorage(temp_db) as storage:
            fingerprint = FunctionFingerprint(
                address=0x401000,
                size=100,
                bytes_hash="test",
                block_count=1,
                instruction_count=10,
            )
            storage.save_fingerprint(fingerprint)

        # Connection should be closed
        assert storage.conn is None

    def test_multiple_provider_levels(self, storage):
        """Test storing results for multiple provider levels."""
        fingerprint = FunctionFingerprint(
            address=0x401000,
            size=100,
            bytes_hash="test_hash",
            block_count=5,
            instruction_count=50,
        )

        # Save results for different provider levels
        phase_1 = provider_phase(1, "MMAT_GENERATED")
        phase_3 = provider_phase(3, "MMAT_CALLS")
        phase_5 = provider_phase(5, "MMAT_GLBOPT1")
        storage.save_result(
            0x401000, fingerprint, provider_phase=phase_1, changes=5, patches=[]
        )
        storage.save_result(
            0x401000, fingerprint, provider_phase=phase_3, changes=10, patches=[]
        )
        storage.save_result(
            0x401000, fingerprint, provider_phase=phase_5, changes=15, patches=[]
        )

        # Load and verify
        r1 = storage.load_result(0x401000, phase_1)
        r3 = storage.load_result(0x401000, phase_3)
        r5 = storage.load_result(0x401000, phase_5)

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
            instruction_count=50,
        )

        # Save initial result
        storage.save_result(
            function_addr=0x401000,
            fingerprint=fingerprint,
            provider_phase=provider_phase(),
            changes=10,
            patches=[{"type": "old"}],
        )

        # Update with new result
        storage.save_result(
            function_addr=0x401000,
            fingerprint=fingerprint,
            provider_phase=provider_phase(),
            changes=20,
            patches=[{"type": "new1"}, {"type": "new2"}],
        )

        # Load and verify updated
        result = storage.load_result(0x401000, provider_phase())
        assert result.changes_made == 20
        assert len(result.patches) == 2
        assert result.patches[0]["type"] == "new1"


class TestStorageBackends:
    def test_factory_returns_sqlite_backend(self, temp_db):
        storage = create_optimization_storage(temp_db, backend="sqlite")
        try:
            assert isinstance(storage, SQLiteOptimizationStorage)
        finally:
            storage.close()

    def test_factory_rejects_unknown_backend(self, temp_db):
        with pytest.raises(ValueError, match="Unknown persistence backend"):
            create_optimization_storage(temp_db, backend="unknown")
