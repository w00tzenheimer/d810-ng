cdef extern from "d810_simd.h":
    ctypedef enum D810SimdLevel:
        D810_SIMD_BEST_SUPPORTED
        D810_SIMD_SCALAR
        D810_SIMD_SSE2
        D810_SIMD_AVX2
        D810_SIMD_NEON

    D810SimdLevel d810_simd_best_level() nogil
    unsigned int d810_tzcnt32(unsigned int x) nogil
    bint mem_eq_16(const void *a, const void *b) nogil
    bint mem_eq_32(const void *a, const void *b) nogil
    unsigned long long hash_u64(unsigned long long x) nogil
    unsigned long long hash_combine(unsigned long long h1, unsigned long long h2) nogil
