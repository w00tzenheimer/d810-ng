# cython: language_level=3, embedsignature=True
# distutils: language=c++
"""Cython declarations for block helper functions.

These declarations are used by _cblock_helpers.pyx to provide fast
access to mblock_t fields without SWIG overhead.
"""

from ._chexrays cimport mblock_t, mba_t

# Internal C functions
cdef int _get_serial(const mblock_t* blk) noexcept
cdef int _get_npred(const mblock_t* blk) noexcept
cdef int _get_nsucc(const mblock_t* blk) noexcept
cdef int _get_pred(const mblock_t* blk, int n) noexcept
cdef int _get_succ(const mblock_t* blk, int n) noexcept
