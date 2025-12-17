"""Fast block helper functions with Cython acceleration.

This module provides fast access to mblock_t fields. When the Cython speedups
are available, it uses direct C++ pointer access to bypass SWIG overhead.
Otherwise, it falls back to pure Python implementations using SWIG accessors.

Usage:
    from d810.hexrays.block_helpers import (
        get_block_serial,
        get_block_info,
        get_pred_serials,
        get_succ_serials,
        get_pred_serial_set,
        get_succ_serial_set,
    )

    serial = get_block_serial(blk)  # Fast serial access
    serial, npred, nsucc = get_block_info(blk)  # Get multiple fields at once
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import ida_hexrays

from d810.core.cymode import CythonMode

# Flag to track whether Cython speedups are available
_CYTHON_AVAILABLE = False

# Try to import Cython speedups if CythonMode is enabled
if CythonMode().is_enabled():
    try:
        from d810.speedups.cythxr._cblock_helpers import (
            get_block_serial,
            get_block_info,
            get_pred_serials,
            get_succ_serials,
            get_pred_serial_set,
            get_succ_serial_set,
            block_has_predecessor,
            block_has_successor,
        )
        _CYTHON_AVAILABLE = True
    except ImportError:
        pass

if not _CYTHON_AVAILABLE:
    # Cython speedups not available, use pure Python fallbacks

    def get_block_serial(py_blk: "ida_hexrays.mblock_t") -> int:
        """Get the serial number of a block.

        Args:
            py_blk: An ida_hexrays.mblock_t object

        Returns:
            The block's serial number (int)
        """
        return py_blk.serial

    def get_block_info(py_blk: "ida_hexrays.mblock_t") -> tuple[int, int, int]:
        """Get (serial, npred, nsucc) from a block in a single call.

        Args:
            py_blk: An ida_hexrays.mblock_t object

        Returns:
            Tuple of (serial, npred, nsucc)
        """
        return (py_blk.serial, py_blk.npred(), py_blk.nsucc())

    def get_pred_serials(py_blk: "ida_hexrays.mblock_t") -> tuple[int, ...]:
        """Get tuple of predecessor serial numbers.

        Args:
            py_blk: An ida_hexrays.mblock_t object

        Returns:
            Tuple of predecessor block serial numbers
        """
        return tuple(py_blk.pred(i) for i in range(py_blk.npred()))

    def get_succ_serials(py_blk: "ida_hexrays.mblock_t") -> tuple[int, ...]:
        """Get tuple of successor serial numbers.

        Args:
            py_blk: An ida_hexrays.mblock_t object

        Returns:
            Tuple of successor block serial numbers
        """
        return tuple(py_blk.succ(i) for i in range(py_blk.nsucc()))

    def get_pred_serial_set(py_blk: "ida_hexrays.mblock_t") -> frozenset[int]:
        """Get frozenset of predecessor serial numbers.

        Args:
            py_blk: An ida_hexrays.mblock_t object

        Returns:
            Frozenset of predecessor block serial numbers
        """
        return frozenset(py_blk.pred(i) for i in range(py_blk.npred()))

    def get_succ_serial_set(py_blk: "ida_hexrays.mblock_t") -> frozenset[int]:
        """Get frozenset of successor serial numbers.

        Args:
            py_blk: An ida_hexrays.mblock_t object

        Returns:
            Frozenset of successor block serial numbers
        """
        return frozenset(py_blk.succ(i) for i in range(py_blk.nsucc()))

    def block_has_predecessor(py_blk: "ida_hexrays.mblock_t", pred_serial: int) -> bool:
        """Check if a block has a specific predecessor.

        Args:
            py_blk: An ida_hexrays.mblock_t object
            pred_serial: Serial number to check for

        Returns:
            True if pred_serial is a predecessor of the block
        """
        for i in range(py_blk.npred()):
            if py_blk.pred(i) == pred_serial:
                return True
        return False

    def block_has_successor(py_blk: "ida_hexrays.mblock_t", succ_serial: int) -> bool:
        """Check if a block has a specific successor.

        Args:
            py_blk: An ida_hexrays.mblock_t object
            succ_serial: Serial number to check for

        Returns:
            True if succ_serial is a successor of the block
        """
        for i in range(py_blk.nsucc()):
            if py_blk.succ(i) == succ_serial:
                return True
        return False


def is_cython_available() -> bool:
    """Check if Cython speedups are available.

    Returns:
        True if Cython block helpers are loaded
    """
    return _CYTHON_AVAILABLE


__all__ = [
    "get_block_serial",
    "get_block_info",
    "get_pred_serials",
    "get_succ_serials",
    "get_pred_serial_set",
    "get_succ_serial_set",
    "block_has_predecessor",
    "block_has_successor",
    "is_cython_available",
]
