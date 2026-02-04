# cython: language_level=3, embedsignature=True
# distutils: language=c++
from libcpp.unordered_map cimport unordered_map
from libc.stdint cimport uintptr_t

from ._chexrays cimport (
    mop_t,
    ea_t,
    uint64,
    qstring,
)



# ---------- tiny hash combiner (FNV-1a-ish) ----------
cdef uint64 _mix64(uint64 h, uint64 x) noexcept nogil
cdef uint64 _mask_nbits(uint64 v, int size) noexcept nogil
# ---------- core recursive hasher ----------
cdef uint64 _hash_mop_ptr(const mop_t* op,
                            ea_t func_ea,
                            unordered_map[uintptr_t, uint64]* insn_memo,
                            int depth) noexcept nogil
cdef qstring stack_var_name(mop_t* op)
