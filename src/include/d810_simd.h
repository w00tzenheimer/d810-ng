// d810_simd.h - Portable SIMD utilities for fast pattern rejection
// Supports SSE2, AVX2, ARM NEON, with scalar fallback
//
// Used by Cython extensions for:
//   - Fast 16-byte fingerprint comparison (mem_eq_16)
//   - Fast 32-byte fingerprint comparison (mem_eq_32, AVX2 only)
//   - Integer hashing for opcode fingerprints (hash_u64)
//   - Hash combining for composite keys (hash_combine)
//   - Runtime SIMD capability detection (d810_simd_best_level)
//   - Portable trailing-zero-count (d810_tzcnt32)
//
// Runtime CPUID + XGETBV detection adapted from ida-sigmaker's
// simd_support.hpp (https://github.com/ajkhoury/ida-sigmaker).
#ifndef D810_SIMD_H
#define D810_SIMD_H

#include <cstdint>
#include <cstring>

// --------------------------------------------------------------------------
// Platform detection
// --------------------------------------------------------------------------
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
    #define D810_X86 1
    #if defined(__SSE2__) || defined(_M_X64) || (defined(_M_IX86_FP) && _M_IX86_FP >= 2)
        #define D810_SSE2 1
        #include <emmintrin.h>
    #endif
    #if defined(__AVX2__)
        #define D810_AVX2 1
        #include <immintrin.h>
    #endif
#elif defined(__aarch64__) || defined(_M_ARM64)
    #define D810_ARM64 1
    #define D810_NEON 1
    #include <arm_neon.h>
#elif defined(__arm__) && defined(__ARM_NEON)
    #define D810_ARM32 1
    #define D810_NEON 1
    #include <arm_neon.h>
#endif

// MSVC CPUID intrinsic header
#if defined(D810_X86) && defined(_MSC_VER)
    #include <intrin.h>
#endif

// Force inline macro
#ifdef _MSC_VER
    #define D810_FORCE_INLINE __forceinline
#else
    #define D810_FORCE_INLINE inline __attribute__((always_inline))
#endif

// --------------------------------------------------------------------------
// SimdLevel: Runtime SIMD capability enumeration
// --------------------------------------------------------------------------
enum D810SimdLevel {
    D810_SIMD_BEST_SUPPORTED = 0,
    D810_SIMD_SCALAR         = 1,
    D810_SIMD_SSE2           = 2,
    D810_SIMD_AVX2           = 3,
    D810_SIMD_NEON           = 4
};

// --------------------------------------------------------------------------
// d810_simd_best_level: Runtime probe for best available SIMD level
//
// On x86, uses CPUID leaf 1 (AVX + OSXSAVE) and leaf 7 (AVX2), plus
// XGETBV to verify OS has enabled XSAVE for XMM/YMM state.
// On ARM, NEON is architecturally guaranteed on AArch64.
//
// Adapted from ida-sigmaker's simd_support_best_level().
// --------------------------------------------------------------------------
static inline D810SimdLevel d810_simd_best_level(void)
{
#if defined(__aarch64__) || defined(_M_ARM64) || defined(__ARM_NEON)
    return D810_SIMD_NEON;
#elif defined(D810_X86)
    // x86: detect AVX2 safely at runtime using CPUID + XGETBV
#if defined(_MSC_VER)
    int r1[4] = {0, 0, 0, 0};
    int r7[4] = {0, 0, 0, 0};
    __cpuidex(r1, 1, 0);
    __cpuidex(r7, 7, 0);
    unsigned ecx1 = (unsigned)r1[2];
    unsigned ebx7 = (unsigned)r7[1];
    int has_avx     = (ecx1 & (1u << 28)) != 0;
    int has_osxsave = (ecx1 & (1u << 27)) != 0;
    if (has_avx && has_osxsave) {
        unsigned __int64 x = _xgetbv(0);
        int xmm  = (x & (1ull << 1)) != 0;
        int ymm  = (x & (1ull << 2)) != 0;
        int avx2 = (ebx7 & (1u << 5)) != 0;
        if (xmm && ymm && avx2)
            return D810_SIMD_AVX2;
    }
#else  // GCC / Clang
    unsigned a = 0, b = 0, c = 0, d = 0;
    // CPUID leaf 1: check AVX (ECX.28) and OSXSAVE (ECX.27)
    __asm__ __volatile__("cpuid"
                         : "=a"(a), "=b"(b), "=c"(c), "=d"(d)
                         : "a"(1), "c"(0));
    unsigned ecx1 = c;
    int has_avx     = (ecx1 & (1u << 28)) != 0;
    int has_osxsave = (ecx1 & (1u << 27)) != 0;
    if (has_avx && has_osxsave) {
        // XGETBV: verify OS enabled XSAVE for XMM (bit 1) and YMM (bit 2)
        unsigned eax_xcr0 = 0, edx_xcr0 = 0;
        unsigned ecx_in = 0;
        __asm__ __volatile__("xgetbv"
                             : "=a"(eax_xcr0), "=d"(edx_xcr0)
                             : "c"(ecx_in));
        unsigned long long x = ((unsigned long long)edx_xcr0 << 32)
                             | (unsigned long long)eax_xcr0;
        int xmm = (x & (1ull << 1)) != 0;
        int ymm = (x & (1ull << 2)) != 0;
        // CPUID leaf 7 subleaf 0: check AVX2 (EBX.5)
        __asm__ __volatile__("cpuid"
                             : "=a"(a), "=b"(b), "=c"(c), "=d"(d)
                             : "a"(7), "c"(0));
        unsigned ebx7 = b;
        int avx2 = (ebx7 & (1u << 5)) != 0;
        if (xmm && ymm && avx2)
            return D810_SIMD_AVX2;
    }
#endif // _MSC_VER
    return D810_SIMD_SSE2;
#else
    return D810_SIMD_SCALAR;
#endif
}

// --------------------------------------------------------------------------
// d810_tzcnt32: Portable trailing-zero-count for 32-bit unsigned
// Returns 32 when x == 0.
//
// Adapted from ida-sigmaker's _tzcnt32_inline().
// --------------------------------------------------------------------------
static inline unsigned d810_tzcnt32(unsigned x)
{
#if defined(__has_builtin)
#if __has_builtin(__builtin_ctz)
    if (x == 0u)
        return 32u;
    return (unsigned)__builtin_ctz(x);
#endif
#endif
#if defined(_MSC_VER)
    unsigned long idx;
    if (_BitScanForward(&idx, x))
        return (unsigned)idx;
    return 32u;
#else
    // Scalar fallback
    if (x == 0u)
        return 32u;
    unsigned c = 0u;
    while ((x & 1u) == 0u) {
        x >>= 1u;
        ++c;
    }
    return c;
#endif
}

// --------------------------------------------------------------------------
// mem_eq_16: Compare two 16-byte memory regions
// Used for PatternFingerprint comparison (12 bytes padded to 16)
// --------------------------------------------------------------------------
D810_FORCE_INLINE bool mem_eq_16(const void* a, const void* b)
{
#if defined(D810_SSE2)
    __m128i va = _mm_loadu_si128(reinterpret_cast<const __m128i*>(a));
    __m128i vb = _mm_loadu_si128(reinterpret_cast<const __m128i*>(b));
    __m128i cmp = _mm_cmpeq_epi8(va, vb);
    return _mm_movemask_epi8(cmp) == 0xFFFF;
#elif defined(D810_NEON)
    uint8x16_t va = vld1q_u8(reinterpret_cast<const uint8_t*>(a));
    uint8x16_t vb = vld1q_u8(reinterpret_cast<const uint8_t*>(b));
    uint8x16_t cmp = vceqq_u8(va, vb);
    uint64x2_t cmp64 = vreinterpretq_u64_u8(cmp);
    return vgetq_lane_u64(cmp64, 0) == ~0ULL &&
           vgetq_lane_u64(cmp64, 1) == ~0ULL;
#else
    // Scalar fallback
    return memcmp(a, b, 16) == 0;
#endif
}

// --------------------------------------------------------------------------
// mem_eq_32: Compare two 32-byte memory regions (AVX2 only)
// Guarded by D810_AVX2; falls back to two mem_eq_16 calls otherwise.
// --------------------------------------------------------------------------
D810_FORCE_INLINE bool mem_eq_32(const void* a, const void* b)
{
#if defined(D810_AVX2)
    __m256i va = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(a));
    __m256i vb = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(b));
    __m256i cmp = _mm256_cmpeq_epi8(va, vb);
    return _mm256_movemask_epi8(cmp) == (int)0xFFFFFFFF;
#else
    // Fallback: two 16-byte comparisons
    return mem_eq_16(a, b) &&
           mem_eq_16(static_cast<const char*>(a) + 16,
                     static_cast<const char*>(b) + 16);
#endif
}

// --------------------------------------------------------------------------
// hash_u64: Murmur3 finalizer for 64-bit integers
// Fast, well-distributed hash for opcode values
// --------------------------------------------------------------------------
D810_FORCE_INLINE uint64_t hash_u64(uint64_t x)
{
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ULL;
    x ^= x >> 33;
    return x;
}

// --------------------------------------------------------------------------
// hash_combine: Combine two hash values with good bit mixing
// Based on boost::hash_combine with 64-bit golden ratio
// --------------------------------------------------------------------------
D810_FORCE_INLINE uint64_t hash_combine(uint64_t h1, uint64_t h2)
{
    h1 ^= h2 + 0x9e3779b97f4a7c15ULL + (h1 << 6) + (h1 >> 2);
    return h1;
}

#endif // D810_SIMD_H
