"""IDA-aware caching layer for optimization results.

This module provides:

1. Re-exports of MOP caches from d810.core (MOP_CONSTANT_CACHE, MOP_TO_AST_CACHE)
2. IDA-specific integration for persistent caching via `core.persistence`
3. Function fingerprinting using IDA's mba_t (microcode block array)

For the underlying storage implementation, see `d810.core.persistence`.
For MOP cache definitions, see `d810.core` (moved there to avoid circular imports).

Usage:
    cache = OptimizationCache("analysis.db")

    # Save results (computes fingerprint from mba)
    cache.save_optimization_result(
        function_addr=0x401000,
        mba=mba,
        maturity=MMAT_GLBOPT1,
        changes=42,
        patches=[...]
    )

    # Load results
    result = cache.load_optimization_result(0x401000, MMAT_GLBOPT1)

    # Check cache validity
    if cache.has_valid_cache(func_addr, mba):
        # Use cached results
        ...
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import ida_hexrays

from d810.core import MOP_CONSTANT_CACHE, MOP_TO_AST_CACHE, getLogger
from d810.core.persistence import (
    CachedResult,
    FunctionFingerprint,
    FunctionRuleConfig,
    OptimizationStorage,
)

logger = getLogger("D810.caching")


# =============================================================================
# Persistent IDA-aware caching
# =============================================================================


class OptimizationCache:
    """IDA-aware cache for optimization results.

    This class wraps `OptimizationStorage` and adds IDA-specific functionality:
    - Computing function fingerprints from mba_t
    - Validating cache using IDA's microcode representation

    Example:
        >>> cache = OptimizationCache("/tmp/analysis.db")
        >>>
        >>> # Check if we have cached results
        >>> if cache.has_valid_cache(func_addr, mba):
        ...     result = cache.load_optimization_result(func_addr, maturity)
        ...     apply_cached_patches(result.patches)
        ... else:
        ...     # Run optimization
        ...     changes = run_optimization(mba)
        ...     cache.save_optimization_result(func_addr, mba, maturity, changes, patches)
    """

    def __init__(self, db_path: str | Path):
        """Initialize the cache.

        Args:
            db_path: Path to SQLite database file.
        """
        self._storage = OptimizationStorage(db_path)
        logger.info(f"Optimization cache initialized: {db_path}")

    @property
    def db_path(self) -> Path:
        """Get the database path."""
        return self._storage.db_path

    def compute_function_fingerprint(
        self, mba: ida_hexrays.mba_t, function_addr: Optional[int] = None
    ) -> FunctionFingerprint:
        """Compute a fingerprint for a function using IDA's microcode.

        The fingerprint is based on:
        - Microcode structure (block count, maturity)
        - Instruction count across all blocks

        Args:
            mba: The microcode array for the function.
            function_addr: Optional function address (extracted from mba if not provided).

        Returns:
            Function fingerprint.
        """
        # Build fingerprint data from microcode structure
        # In a real implementation, you might also hash the actual bytes
        function_data = f"{mba.qty}:{mba.maturity}".encode("utf-8")
        bytes_hash = hashlib.sha256(function_data).hexdigest()

        # Count instructions across all blocks
        instruction_count = 0
        for i in range(mba.qty):
            block = mba.get_mblock(i)
            if block:
                ins = block.head
                while ins:
                    instruction_count += 1
                    ins = ins.next

        # Try to get function address from mba if not provided
        if function_addr is None:
            function_addr = getattr(mba, "entry_ea", 0)

        return FunctionFingerprint(
            address=function_addr,
            size=0,  # TODO: Get from IDA's function info
            bytes_hash=bytes_hash,
            block_count=mba.qty,
            instruction_count=instruction_count,
        )

    def has_valid_cache(self, function_addr: int, mba: ida_hexrays.mba_t) -> bool:
        """Check if we have a valid cache entry for a function.

        Validates that the cached fingerprint matches the current function.

        Args:
            function_addr: Function address.
            mba: Current microcode array.

        Returns:
            True if cache is valid and can be used.
        """
        current_fp = self.compute_function_fingerprint(mba, function_addr)
        return self._storage.has_valid_cache(function_addr, current_fp.bytes_hash)

    def save_optimization_result(
        self,
        function_addr: int,
        mba: ida_hexrays.mba_t,
        maturity: int,
        changes: int,
        patches: List[Dict[str, Any]],
    ) -> None:
        """Save optimization result to cache.

        Args:
            function_addr: Function address.
            mba: Microcode array (for fingerprinting).
            maturity: Maturity level.
            changes: Number of changes made.
            patches: List of patch descriptions.
        """
        fingerprint = self.compute_function_fingerprint(mba, function_addr)
        self._storage.save_result(
            function_addr=function_addr,
            fingerprint=fingerprint,
            maturity=maturity,
            changes=changes,
            patches=patches,
        )

    def load_optimization_result(
        self, function_addr: int, maturity: int
    ) -> Optional[CachedResult]:
        """Load cached optimization result.

        Args:
            function_addr: Function address.
            maturity: Maturity level.

        Returns:
            Cached result if found, None otherwise.
        """
        return self._storage.load_result(function_addr, maturity)

    def set_function_rules(
        self,
        function_addr: int,
        enabled_rules: Optional[Set[str]] = None,
        disabled_rules: Optional[Set[str]] = None,
        notes: str = "",
    ) -> None:
        """Configure which rules should run on a specific function.

        Args:
            function_addr: Function address.
            enabled_rules: Set of rule names to enable (None = all enabled).
            disabled_rules: Set of rule names to disable (None = none disabled).
            notes: Human-readable notes about this configuration.
        """
        self._storage.set_function_rules(
            function_addr=function_addr,
            enabled_rules=enabled_rules,
            disabled_rules=disabled_rules,
            notes=notes,
        )

    def get_function_rules(self, function_addr: int) -> Optional[FunctionRuleConfig]:
        """Get rule configuration for a function.

        Args:
            function_addr: Function address.

        Returns:
            Rule configuration if found, None otherwise.
        """
        return self._storage.get_function_rules(function_addr)

    def should_run_rule(self, function_addr: int, rule_name: str) -> bool:
        """Check if a rule should run on a function.

        Args:
            function_addr: Function address.
            rule_name: Name of the rule.

        Returns:
            True if the rule should run, False otherwise.
        """
        return self._storage.should_run_rule(function_addr, rule_name)

    def invalidate_function(self, function_addr: int) -> None:
        """Invalidate all cached data for a function.

        Args:
            function_addr: Function address.
        """
        self._storage.invalidate_function(function_addr)

    def get_statistics(self) -> Dict[str, Any]:
        """Get cache statistics.

        Returns:
            Dictionary with cache statistics.
        """
        return self._storage.get_statistics()

    def close(self) -> None:
        """Close the cache."""
        self._storage.close()

    def __enter__(self):
        """Context manager support."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager support."""
        self.close()
