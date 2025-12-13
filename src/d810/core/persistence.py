"""Persistent storage layer for optimization results.

This module provides IDA-independent SQLite-backed storage for:
- Function fingerprints (for cache validation)
- Optimization results and patches
- Per-function rule configuration

The storage survives restarts and allows results to be reused across
sessions, dramatically speeding up repeated analysis.

Architecture:
    - Functions table: Stores function metadata and hash
    - Blocks table: Stores block-level def/use information
    - Patches table: Stores optimization transformations
    - FunctionRules table: Per-function rule configuration
    - Results table: Optimization results per function

Usage:
    storage = OptimizationStorage("analysis.db")

    # Save results
    storage.save_result(
        function_addr=0x401000,
        fingerprint=fingerprint,
        maturity=5,
        changes=42,
        patches=[...]
    )

    # Load results
    result = storage.load_result(0x401000, maturity=5)

    # Configure per-function rules
    storage.set_function_rules(
        function_addr=0x401000,
        enabled_rules={"UnflattenerRule", "XorOptimization"},
        disabled_rules={"SlowRule"}
    )
"""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from .logging import getLogger

logger = getLogger("D810.persistence")


@dataclass
class FunctionFingerprint:
    """Fingerprint of a function for cache validation.

    This is IDA-independent - the actual fingerprint computation
    happens in the IDA-aware layer.
    """

    address: int
    size: int
    bytes_hash: str  # SHA-256 of function bytes
    block_count: int
    instruction_count: int


@dataclass
class CachedResult:
    """Cached optimization result for a function."""

    function_addr: int
    maturity: int
    changes_made: int
    patches: List[Dict[str, Any]]
    timestamp: float
    fingerprint: str


@dataclass
class FunctionRuleConfig:
    """Per-function rule configuration.

    This allows fine-grained control over which rules run on which functions.
    Use cases:
    - Disable slow rules on large functions
    - Enable experimental rules only on specific functions
    - Skip unflattening on functions that aren't flattened
    """

    function_addr: int
    enabled_rules: Set[str]
    disabled_rules: Set[str]
    notes: str = ""


class OptimizationStorage:
    """SQLite-backed storage for optimization results.

    This is the IDA-independent storage layer. It handles:
    1. Function fingerprints (for validation)
    2. Block-level information (def/use lists)
    3. Optimization patches (transformations applied)
    4. Per-function rule configuration
    5. Optimization results (for quick lookup)

    Example:
        >>> storage = OptimizationStorage("/tmp/analysis.db")
        >>>
        >>> # Check if we have cached results
        >>> if storage.has_valid_cache(func_addr, current_hash):
        ...     result = storage.load_result(func_addr, maturity)
        ...     apply_cached_patches(result.patches)
        ... else:
        ...     # Run optimization
        ...     changes = run_optimization(mba)
        ...     storage.save_result(func_addr, fingerprint, maturity, changes, patches)
        >>>
        >>> # Configure rules for specific function
        >>> storage.set_function_rules(
        ...     function_addr=0x401000,
        ...     enabled_rules={"UnflattenerRule"},
        ...     disabled_rules={"SlowPatternRule"}
        ... )
    """

    def __init__(self, db_path: str | Path):
        """Initialize the storage.

        Args:
            db_path: Path to SQLite database file.
        """
        self.db_path = Path(db_path)
        self.conn: Optional[sqlite3.Connection] = None
        self._init_database()
        logger.info(f"Optimization storage initialized: {self.db_path}")

    def _init_database(self) -> None:
        """Initialize the database schema."""
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row

        cursor = self.conn.cursor()

        # Functions table: stores function metadata and fingerprints
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS functions (
                address INTEGER PRIMARY KEY,
                size INTEGER NOT NULL,
                bytes_hash TEXT NOT NULL,
                block_count INTEGER NOT NULL,
                instruction_count INTEGER NOT NULL,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            )
        """)

        # Blocks table: stores block-level def/use information
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS blocks (
                function_addr INTEGER NOT NULL,
                block_serial INTEGER NOT NULL,
                block_hash TEXT NOT NULL,
                use_list TEXT,  -- JSON array
                def_list TEXT,  -- JSON array
                PRIMARY KEY (function_addr, block_serial),
                FOREIGN KEY (function_addr) REFERENCES functions(address)
            )
        """)

        # Patches table: stores optimization transformations
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS patches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                function_addr INTEGER NOT NULL,
                maturity INTEGER NOT NULL,
                patch_type TEXT NOT NULL,  -- 'redirect_edge', 'insert_block', etc.
                patch_data TEXT NOT NULL,  -- JSON
                created_at REAL NOT NULL,
                FOREIGN KEY (function_addr) REFERENCES functions(address)
            )
        """)

        # Function rules table: per-function rule configuration
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS function_rules (
                function_addr INTEGER PRIMARY KEY,
                enabled_rules TEXT,   -- JSON array of rule names
                disabled_rules TEXT,  -- JSON array of rule names
                notes TEXT,
                updated_at REAL NOT NULL,
                FOREIGN KEY (function_addr) REFERENCES functions(address)
            )
        """)

        # Results table: cached optimization results
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS results (
                function_addr INTEGER NOT NULL,
                maturity INTEGER NOT NULL,
                changes_made INTEGER NOT NULL,
                fingerprint TEXT NOT NULL,
                timestamp REAL NOT NULL,
                PRIMARY KEY (function_addr, maturity),
                FOREIGN KEY (function_addr) REFERENCES functions(address)
            )
        """)

        # Create indices for faster lookups
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_patches_function
            ON patches(function_addr, maturity)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_results_function
            ON results(function_addr, maturity)
        """)

        self.conn.commit()
        logger.debug("Database schema initialized")

    def has_valid_cache(self, function_addr: int, current_hash: str) -> bool:
        """Check if we have a valid cache entry for a function.

        Args:
            function_addr: Function address.
            current_hash: Current fingerprint hash to compare against.

        Returns:
            True if cache is valid and can be used.
        """
        if not self.conn:
            return False

        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT bytes_hash FROM functions WHERE address = ?",
            (function_addr,)
        )
        row = cursor.fetchone()

        if not row:
            return False

        # Check if hash matches
        cached_hash = row['bytes_hash']
        if cached_hash != current_hash:
            logger.info(
                f"Cache invalidated for function {function_addr:x}: "
                "fingerprint mismatch"
            )
            return False

        return True

    def save_fingerprint(self, fingerprint: FunctionFingerprint) -> None:
        """Save a function fingerprint.

        Args:
            fingerprint: The function fingerprint to save.
        """
        if not self.conn:
            return

        timestamp = time.time()
        cursor = self.conn.cursor()

        # Upsert function metadata
        cursor.execute("""
            INSERT OR REPLACE INTO functions
            (address, size, bytes_hash, block_count, instruction_count, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            fingerprint.address,
            fingerprint.size,
            fingerprint.bytes_hash,
            fingerprint.block_count,
            fingerprint.instruction_count,
            timestamp,
            timestamp
        ))

        self.conn.commit()

    def save_result(
        self,
        function_addr: int,
        fingerprint: FunctionFingerprint,
        maturity: int,
        changes: int,
        patches: List[Dict[str, Any]]
    ) -> None:
        """Save optimization result to storage.

        Args:
            function_addr: Function address.
            fingerprint: Function fingerprint.
            maturity: Maturity level.
            changes: Number of changes made.
            patches: List of patch descriptions.
        """
        if not self.conn:
            return

        timestamp = time.time()
        cursor = self.conn.cursor()

        # Save fingerprint first
        self.save_fingerprint(fingerprint)

        # Save result
        cursor.execute("""
            INSERT OR REPLACE INTO results
            (function_addr, maturity, changes_made, fingerprint, timestamp)
            VALUES (?, ?, ?, ?, ?)
        """, (
            function_addr,
            maturity,
            changes,
            fingerprint.bytes_hash,
            timestamp
        ))

        # Delete old patches for this function/maturity combo
        cursor.execute(
            "DELETE FROM patches WHERE function_addr = ? AND maturity = ?",
            (function_addr, maturity)
        )

        # Save new patches
        for patch in patches:
            cursor.execute("""
                INSERT INTO patches
                (function_addr, maturity, patch_type, patch_data, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (
                function_addr,
                maturity,
                patch.get('type', 'unknown'),
                json.dumps(patch),
                timestamp
            ))

        self.conn.commit()
        logger.info(
            f"Saved optimization result for {function_addr:x} "
            f"at maturity {maturity}: {changes} changes, {len(patches)} patches"
        )

    def load_result(
        self,
        function_addr: int,
        maturity: int
    ) -> Optional[CachedResult]:
        """Load cached optimization result.

        Args:
            function_addr: Function address.
            maturity: Maturity level.

        Returns:
            Cached result if found, None otherwise.
        """
        if not self.conn:
            return None

        cursor = self.conn.cursor()

        # Load result
        cursor.execute("""
            SELECT changes_made, fingerprint, timestamp
            FROM results
            WHERE function_addr = ? AND maturity = ?
        """, (function_addr, maturity))

        row = cursor.fetchone()
        if not row:
            return None

        # Load patches
        cursor.execute("""
            SELECT patch_type, patch_data
            FROM patches
            WHERE function_addr = ? AND maturity = ?
            ORDER BY id
        """, (function_addr, maturity))

        patches = [json.loads(r['patch_data']) for r in cursor.fetchall()]

        logger.info(
            f"Loaded cached result for {function_addr:x} "
            f"at maturity {maturity}: {row['changes_made']} changes"
        )

        return CachedResult(
            function_addr=function_addr,
            maturity=maturity,
            changes_made=row['changes_made'],
            patches=patches,
            timestamp=row['timestamp'],
            fingerprint=row['fingerprint']
        )

    def set_function_rules(
        self,
        function_addr: int,
        enabled_rules: Optional[Set[str]] = None,
        disabled_rules: Optional[Set[str]] = None,
        notes: str = ""
    ) -> None:
        """Configure which rules should run on a specific function.

        This allows per-function optimization control:
        - Enable only specific rules
        - Disable slow/buggy rules
        - Document why rules are configured this way

        Args:
            function_addr: Function address.
            enabled_rules: Set of rule names to enable (None = all enabled).
            disabled_rules: Set of rule names to disable (None = none disabled).
            notes: Human-readable notes about this configuration.

        Example:
            >>> # Only run unflattening on this function
            >>> storage.set_function_rules(
            ...     0x401000,
            ...     enabled_rules={"UnflattenerRule"},
            ...     notes="Large switch statement, other rules too slow"
            ... )
            >>>
            >>> # Disable a problematic rule
            >>> storage.set_function_rules(
            ...     0x402000,
            ...     disabled_rules={"BuggyPatternRule"},
            ...     notes="This rule crashes on this function"
            ... )
        """
        if not self.conn:
            return

        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO function_rules
            (function_addr, enabled_rules, disabled_rules, notes, updated_at)
            VALUES (?, ?, ?, ?, ?)
        """, (
            function_addr,
            json.dumps(list(enabled_rules or [])),
            json.dumps(list(disabled_rules or [])),
            notes,
            time.time()
        ))

        self.conn.commit()
        logger.info(f"Updated rule configuration for function {function_addr:x}")

    def get_function_rules(self, function_addr: int) -> Optional[FunctionRuleConfig]:
        """Get rule configuration for a function.

        Args:
            function_addr: Function address.

        Returns:
            Rule configuration if found, None otherwise.
        """
        if not self.conn:
            return None

        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT enabled_rules, disabled_rules, notes
            FROM function_rules
            WHERE function_addr = ?
        """, (function_addr,))

        row = cursor.fetchone()
        if not row:
            return None

        return FunctionRuleConfig(
            function_addr=function_addr,
            enabled_rules=set(json.loads(row['enabled_rules'])),
            disabled_rules=set(json.loads(row['disabled_rules'])),
            notes=row['notes']
        )

    def should_run_rule(self, function_addr: int, rule_name: str) -> bool:
        """Check if a rule should run on a function.

        This consults the per-function rule configuration.

        Args:
            function_addr: Function address.
            rule_name: Name of the rule.

        Returns:
            True if the rule should run, False otherwise.

        Logic:
            - If enabled_rules is set, only those rules run
            - If disabled_rules is set, those rules are skipped
            - If both are empty, all rules run (default)
        """
        config = self.get_function_rules(function_addr)

        if not config:
            return True  # No config = run all rules

        # If enabled_rules is specified, only run those
        if config.enabled_rules:
            return rule_name in config.enabled_rules

        # Otherwise, run unless explicitly disabled
        return rule_name not in config.disabled_rules

    def invalidate_function(self, function_addr: int) -> None:
        """Invalidate all cached data for a function.

        Use this when you know a function has changed or want to
        force re-optimization.

        Args:
            function_addr: Function address.
        """
        if not self.conn:
            return

        cursor = self.conn.cursor()

        cursor.execute("DELETE FROM results WHERE function_addr = ?", (function_addr,))
        cursor.execute("DELETE FROM patches WHERE function_addr = ?", (function_addr,))
        cursor.execute("DELETE FROM blocks WHERE function_addr = ?", (function_addr,))
        cursor.execute("DELETE FROM functions WHERE address = ?", (function_addr,))

        self.conn.commit()
        logger.info(f"Invalidated cache for function {function_addr:x}")

    def get_statistics(self) -> Dict[str, Any]:
        """Get storage statistics.

        Returns:
            Dictionary with storage statistics.
        """
        if not self.conn:
            return {}

        cursor = self.conn.cursor()

        stats = {}

        cursor.execute("SELECT COUNT(*) as count FROM functions")
        stats['functions_cached'] = cursor.fetchone()['count']

        cursor.execute("SELECT COUNT(*) as count FROM results")
        stats['results_cached'] = cursor.fetchone()['count']

        cursor.execute("SELECT COUNT(*) as count FROM patches")
        stats['patches_stored'] = cursor.fetchone()['count']

        cursor.execute("SELECT COUNT(*) as count FROM function_rules")
        stats['functions_with_custom_rules'] = cursor.fetchone()['count']

        return stats

    def close(self) -> None:
        """Close the database connection."""
        if self.conn:
            self.conn.close()
            self.conn = None
            logger.debug("Storage database closed")

    def __enter__(self):
        """Context manager support."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager support."""
        self.close()
