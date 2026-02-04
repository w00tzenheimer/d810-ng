# cython: language_level=3, embedsignature=True, boundscheck=False, wraparound=False
# distutils: language=c++
"""Cython helpers for fast mblock_t field access.

This module provides fast access to mblock_t fields by bypassing the SWIG
wrapper overhead. It extracts the raw C++ pointer from SWIG-wrapped Python
objects and accesses fields directly.

Usage:
    from d810.speedups.cythxr._cblock_helpers import (
        get_block_serial,
        get_block_info,
        get_pred_serials,
        get_succ_serials,
    )

    serial = get_block_serial(py_blk)  # Fast serial access
    serial, npred, nsucc = get_block_info(py_blk)  # Get multiple fields at once
    preds = get_pred_serials(py_blk)  # Tuple of predecessor serial numbers
"""

from ._chexrays cimport mblock_t, mba_t, _swig_ptr


# ---------- Internal C functions ----------

cdef inline int _get_serial(const mblock_t* blk) noexcept:
    """Get serial number from mblock_t pointer."""
    return blk.serial


cdef inline int _get_npred(const mblock_t* blk) noexcept:
    """Get predecessor count from mblock_t pointer."""
    return blk.npred()


cdef inline int _get_nsucc(const mblock_t* blk) noexcept:
    """Get successor count from mblock_t pointer."""
    return blk.nsucc()


cdef inline int _get_pred(const mblock_t* blk, int n) noexcept:
    """Get predecessor serial at index n."""
    return blk.pred(n)


cdef inline int _get_succ(const mblock_t* blk, int n) noexcept:
    """Get successor serial at index n."""
    return blk.succ(n)


# ---------- Python-callable functions ----------

cpdef int get_block_serial(object py_blk):
    """Get the serial number of a block without SWIG overhead.

    Args:
        py_blk: A SWIG-wrapped ida_hexrays.mblock_t object

    Returns:
        The block's serial number (int)
    """
    cdef const mblock_t* blk = <const mblock_t*> _swig_ptr(py_blk)
    return _get_serial(blk)


cpdef tuple get_block_info(object py_blk):
    """Get (serial, npred, nsucc) from a block in a single call.

    This is more efficient than calling individual accessors when
    multiple fields are needed.

    Args:
        py_blk: A SWIG-wrapped ida_hexrays.mblock_t object

    Returns:
        Tuple of (serial, npred, nsucc)
    """
    cdef const mblock_t* blk = <const mblock_t*> _swig_ptr(py_blk)
    return (_get_serial(blk), _get_npred(blk), _get_nsucc(blk))


cpdef tuple get_pred_serials(object py_blk):
    """Get tuple of predecessor serial numbers.

    Args:
        py_blk: A SWIG-wrapped ida_hexrays.mblock_t object

    Returns:
        Tuple of predecessor block serial numbers
    """
    cdef const mblock_t* blk = <const mblock_t*> _swig_ptr(py_blk)
    cdef int n = _get_npred(blk)
    cdef int i
    cdef list preds = []
    for i in range(n):
        preds.append(_get_pred(blk, i))
    return tuple(preds)


cpdef tuple get_succ_serials(object py_blk):
    """Get tuple of successor serial numbers.

    Args:
        py_blk: A SWIG-wrapped ida_hexrays.mblock_t object

    Returns:
        Tuple of successor block serial numbers
    """
    cdef const mblock_t* blk = <const mblock_t*> _swig_ptr(py_blk)
    cdef int n = _get_nsucc(blk)
    cdef int i
    cdef list succs = []
    for i in range(n):
        succs.append(_get_succ(blk, i))
    return tuple(succs)


cpdef frozenset get_pred_serial_set(object py_blk):
    """Get frozenset of predecessor serial numbers.

    This is useful for set operations on block predecessors.

    Args:
        py_blk: A SWIG-wrapped ida_hexrays.mblock_t object

    Returns:
        Frozenset of predecessor block serial numbers
    """
    cdef const mblock_t* blk = <const mblock_t*> _swig_ptr(py_blk)
    cdef int n = _get_npred(blk)
    cdef int i
    cdef set preds = set()
    for i in range(n):
        preds.add(_get_pred(blk, i))
    return frozenset(preds)


cpdef frozenset get_succ_serial_set(object py_blk):
    """Get frozenset of successor serial numbers.

    This is useful for set operations on block successors.

    Args:
        py_blk: A SWIG-wrapped ida_hexrays.mblock_t object

    Returns:
        Frozenset of successor block serial numbers
    """
    cdef const mblock_t* blk = <const mblock_t*> _swig_ptr(py_blk)
    cdef int n = _get_nsucc(blk)
    cdef int i
    cdef set succs = set()
    for i in range(n):
        succs.add(_get_succ(blk, i))
    return frozenset(succs)


cpdef bint block_has_predecessor(object py_blk, int pred_serial):
    """Check if a block has a specific predecessor.

    More efficient than building a set when checking a single value.

    Args:
        py_blk: A SWIG-wrapped ida_hexrays.mblock_t object
        pred_serial: Serial number to check for

    Returns:
        True if pred_serial is a predecessor of the block
    """
    cdef const mblock_t* blk = <const mblock_t*> _swig_ptr(py_blk)
    cdef int n = _get_npred(blk)
    cdef int i
    for i in range(n):
        if _get_pred(blk, i) == pred_serial:
            return True
    return False


cpdef bint block_has_successor(object py_blk, int succ_serial):
    """Check if a block has a specific successor.

    More efficient than building a set when checking a single value.

    Args:
        py_blk: A SWIG-wrapped ida_hexrays.mblock_t object
        succ_serial: Serial number to check for

    Returns:
        True if succ_serial is a successor of the block
    """
    cdef const mblock_t* blk = <const mblock_t*> _swig_ptr(py_blk)
    cdef int n = _get_nsucc(blk)
    cdef int i
    for i in range(n):
        if _get_succ(blk, i) == succ_serial:
            return True
    return False
