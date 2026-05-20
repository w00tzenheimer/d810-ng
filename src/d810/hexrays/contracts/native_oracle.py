"""Native oracle for blocked-by-api INTERR checks.

Wraps the Cython extension ``_cblock_oracle`` with a graceful Python fallback
when the speedups extension has not been compiled.

Each check returns a list of ``(interr_code, block_serial, message)`` tuples.
An empty list means no violations were detected.
"""

from __future__ import annotations

from d810.core import logging, getLogger
from d810.core.typing import TYPE_CHECKING

if TYPE_CHECKING:
    from d810.core.typing import List, Tuple

logger = getLogger(__name__)

try:
    from d810.speedups.cythxr._cblock_oracle import (
        oracle_check_block,
        oracle_check_mba,
    )
    NATIVE_ORACLE_AVAILABLE = True
except ImportError:
    NATIVE_ORACLE_AVAILABLE = False
    logger.debug(
        "Native oracle not available (Cython speedups not built); "
        "blocked-by-api INTERR checks will be skipped."
    )

_WARNED_ONCE = False


def oracle_available() -> bool:
    """Returns True if the native Cython oracle is importable."""
    return NATIVE_ORACLE_AVAILABLE


def check_mba_native(mba) -> List[Tuple[int, int, str]]:
    """Run native oracle checks on a full MBA.

    Args:
        mba: A SWIG-wrapped ``ida_hexrays.mba_t`` object.

    Returns:
        List of ``(interr_code, block_serial, message)`` tuples.
        Returns an empty list when the native oracle is not available.
    """
    global _WARNED_ONCE
    if not NATIVE_ORACLE_AVAILABLE:
        if not _WARNED_ONCE:
            logger.warning(
                "Native oracle not available (Cython speedups not built). "
                "15 blocked-by-api INTERR codes will not be checked."
            )
            _WARNED_ONCE = True
        return []
    return oracle_check_mba(mba)


def check_block_native(block) -> List[Tuple[int, int, str]]:
    """Run native oracle checks on a single block.

    Args:
        block: A SWIG-wrapped ``ida_hexrays.mblock_t`` object.

    Returns:
        List of ``(interr_code, block_serial, message)`` tuples.
        Returns an empty list when the native oracle is not available.
    """
    global _WARNED_ONCE
    if not NATIVE_ORACLE_AVAILABLE:
        if not _WARNED_ONCE:
            logger.warning(
                "Native oracle not available (Cython speedups not built). "
                "15 blocked-by-api INTERR codes will not be checked."
            )
            _WARNED_ONCE = True
        return []
    return oracle_check_block(block)
