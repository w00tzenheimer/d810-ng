/*
 * Independently authored, post-lowering-shaped MBA corpus.
 *
 * These pairs intentionally preserve simple binary operator trees at -O0.  They
 * are semantic fixtures, not claims that every compiler version emits an
 * identical instruction sequence.  Every shape has a simple sibling for the
 * pre-D810 semantic gate.
 */
#include <stdint.h>

#include "platform.h"

#define DEFINE_PAIR(T, SHAPE, TRUTH, SHAPE_EXPR, TRUTH_EXPR) \
    EXPORT T SHAPE(T a, T b, T c, T d, T e, T f, T g, T h) { \
        return (T)(SHAPE_EXPR); \
    } \
    EXPORT T TRUTH(T a, T b, T c, T d, T e, T f, T g, T h) { \
        return (T)(TRUTH_EXPR); \
    }

static uint32_t mba_shape_static_words[4] = {
    UINT32_C(0x10203040), UINT32_C(0x55667788),
    UINT32_C(0x90ABCDEF), UINT32_C(0x13579BDF)
};

static uint32_t mba_shape_pure_call(uint32_t value)
{
    return value ^ UINT32_C(0x5A5A5A5A);
}

/* Keep the truth sibling portable across the pinned Clang and older GCC
 * images. The shape still presents complementary shifts to IDA. */
#if defined(__has_builtin)
#if __has_builtin(__builtin_rotateleft32)
#define MBA_TRUTH_ROL32(value, count) __builtin_rotateleft32((value), (count))
#endif
#endif
#ifndef MBA_TRUTH_ROL32
#define MBA_TRUTH_ROL32(value, count) \
    ((uint32_t)(((value) << (count)) | ((value) >> (32u - (count)))))
#endif

/* Existing same-width chain algebra: folding, duplicate, complement, cancel. */
DEFINE_PAIR(uint8_t, mba_shape_chain_01, mba_truth_chain_01, a + (b - b), a)
DEFINE_PAIR(uint16_t, mba_shape_chain_02, mba_truth_chain_02, a ^ a, 0)
DEFINE_PAIR(uint32_t, mba_shape_chain_03, mba_truth_chain_03, a & ~a, 0)
DEFINE_PAIR(uint64_t, mba_shape_chain_04, mba_truth_chain_04, (a + b) - b, a)
DEFINE_PAIR(uint8_t, mba_shape_chain_05, mba_truth_chain_05, a | (a & b), a)
DEFINE_PAIR(uint16_t, mba_shape_chain_06, mba_truth_chain_06, (a ^ b) ^ b, a)
DEFINE_PAIR(uint32_t, mba_shape_chain_07, mba_truth_chain_07, a + b + c - c - b, a)
DEFINE_PAIR(uint64_t, mba_shape_chain_08, mba_truth_chain_08, (a & b) + (a & ~b), a)

/* Certified direct MBA identities, including declared/swapped operands. */
DEFINE_PAIR(uint32_t, mba_shape_catalogue_01, mba_truth_catalogue_01, (a ^ b) + (UINT32_C(2) * (a & b)), a + b)
DEFINE_PAIR(uint64_t, mba_shape_catalogue_02, mba_truth_catalogue_02, (a & b) + (a | b), a + b)
DEFINE_PAIR(uint32_t, mba_shape_catalogue_03, mba_truth_catalogue_03, (a + b) - (UINT32_C(2) * (a & b)), a ^ b)
DEFINE_PAIR(uint64_t, mba_shape_catalogue_04, mba_truth_catalogue_04, (a ^ b) - (UINT64_C(2) * (a & ~b)), b - a)
DEFINE_PAIR(uint32_t, mba_shape_catalogue_05, mba_truth_catalogue_05, (a & b) + (a ^ b), a | b)
DEFINE_PAIR(uint64_t, mba_shape_catalogue_06, mba_truth_catalogue_06, (a | b) - (a ^ b), a & b)
DEFINE_PAIR(uint32_t, mba_shape_catalogue_07, mba_truth_catalogue_07, (b ^ a) + (UINT32_C(2) * (b & a)), a + b)
DEFINE_PAIR(uint64_t, mba_shape_catalogue_08, mba_truth_catalogue_08, (UINT64_C(2) * (a | b)) - (a ^ b), a + b)
DEFINE_PAIR(uint32_t, mba_shape_catalogue_09, mba_truth_catalogue_09, (a + b) - (a & b), a | b)
DEFINE_PAIR(uint64_t, mba_shape_catalogue_10, mba_truth_catalogue_10, (a | b) - (a & b), a ^ b)

/* Equal-arity homogeneous reassociation; no operand represents a group. */
DEFINE_PAIR(uint32_t, mba_shape_reassociation_01, mba_truth_reassociation_01, ((a ^ b) + (UINT32_C(2) * (a & b))) + c, a + b + c)
DEFINE_PAIR(uint64_t, mba_shape_reassociation_02, mba_truth_reassociation_02, a + ((b ^ c) + (UINT64_C(2) * (b & c))), a + b + c)
DEFINE_PAIR(uint32_t, mba_shape_reassociation_03, mba_truth_reassociation_03, ((a & b) + (a ^ b)) + (c & d), (a | b) + (c & d))
DEFINE_PAIR(uint64_t, mba_shape_reassociation_04, mba_truth_reassociation_04, (a | b) + ((c + d) - (UINT64_C(2) * (c & d))), (a | b) + (c ^ d))
DEFINE_PAIR(uint32_t, mba_shape_reassociation_05, mba_truth_reassociation_05, (a + b) + (c + d), a + b + c + d)
DEFINE_PAIR(uint64_t, mba_shape_reassociation_06, mba_truth_reassociation_06, ((a + b) + c) + d, a + b + c + d)
DEFINE_PAIR(uint32_t, mba_shape_reassociation_07, mba_truth_reassociation_07, (a ^ b) + (UINT32_C(2) * (a & b)) + c + d, a + b + c + d)
DEFINE_PAIR(uint64_t, mba_shape_reassociation_08, mba_truth_reassociation_08, a + b + ((c ^ d) + (UINT64_C(2) * (c & d))), a + b + c + d)

/* Short two-rule compositions. */
DEFINE_PAIR(uint32_t, mba_shape_degree2_01, mba_truth_degree2_01, ((a ^ b) + (UINT32_C(2) * (a & b))) + ((c ^ d) + (UINT32_C(2) * (c & d))), a + b + c + d)
DEFINE_PAIR(uint64_t, mba_shape_degree2_02, mba_truth_degree2_02, ((a & b) + (a | b)) ^ ((c & d) + (c | d)), (a + b) ^ (c + d))
DEFINE_PAIR(uint32_t, mba_shape_degree2_03, mba_truth_degree2_03, ((a + b) - (UINT32_C(2) * (a & b))) + ((c + d) - (UINT32_C(2) * (c & d))), (a ^ b) + (c ^ d))
DEFINE_PAIR(uint64_t, mba_shape_degree2_04, mba_truth_degree2_04, ((a ^ b) - (UINT64_C(2) * (a & ~b))) + ((c ^ d) - (UINT64_C(2) * (c & ~d))), (b - a) + (d - c))
DEFINE_PAIR(uint32_t, mba_shape_degree2_05, mba_truth_degree2_05, ((a & b) + (a ^ b)) + ((c & d) + (c ^ d)), (a | b) + (c | d))
DEFINE_PAIR(uint64_t, mba_shape_degree2_06, mba_truth_degree2_06, ((a | b) - (a ^ b)) + ((c | d) - (c ^ d)), (a & b) + (c & d))
DEFINE_PAIR(uint32_t, mba_shape_degree2_07, mba_truth_degree2_07, (((a ^ b) + (UINT32_C(2) * (a & b))) ^ c) + ((d ^ e) + (UINT32_C(2) * (d & e))), ((a + b) ^ c) + d + e)
DEFINE_PAIR(uint64_t, mba_shape_degree2_08, mba_truth_degree2_08, ((a & b) + (a | b)) + ((c ^ d) + (UINT64_C(2) * (c & d))), a + b + c + d)
DEFINE_PAIR(uint32_t, mba_shape_degree2_09, mba_truth_degree2_09, ((a + b) - (UINT32_C(2) * (a & b))) ^ ((c + d) - (UINT32_C(2) * (c & d))), (a ^ b) ^ (c ^ d))
DEFINE_PAIR(uint64_t, mba_shape_degree2_10, mba_truth_degree2_10, ((a ^ b) + (UINT64_C(2) * (a & b))) + ((c & d) + (c | d)), a + b + c + d)

/* Linear mixed Boolean-arithmetic coefficient residuals. */
DEFINE_PAIR(uint32_t, mba_shape_coefficient_01, mba_truth_coefficient_01, 3*(a ^ b) + 6*(a & b), 3*(a + b))
DEFINE_PAIR(uint64_t, mba_shape_coefficient_02, mba_truth_coefficient_02, 5*(a | b) + 5*(a & b), 5*(a + b))
DEFINE_PAIR(uint32_t, mba_shape_coefficient_03, mba_truth_coefficient_03, 7*(a + b) - 14*(a & b), 7*(a ^ b))
DEFINE_PAIR(uint64_t, mba_shape_coefficient_04, mba_truth_coefficient_04, 9*(a | b) - 9*(a & b), 9*(a ^ b))
DEFINE_PAIR(uint32_t, mba_shape_coefficient_05, mba_truth_coefficient_05, 11*(a ^ b) + 22*(a & b) + c, 11*(a + b) + c)
DEFINE_PAIR(uint64_t, mba_shape_coefficient_06, mba_truth_coefficient_06, 13*(a | b) + 13*(a & b) - c, 13*(a + b) - c)
DEFINE_PAIR(uint32_t, mba_shape_coefficient_07, mba_truth_coefficient_07, 15*(a + b) - 30*(a & b) + c, 15*(a ^ b) + c)
DEFINE_PAIR(uint64_t, mba_shape_coefficient_08, mba_truth_coefficient_08, 17*(a | b) - 17*(a & b) + c, 17*(a ^ b) + c)
DEFINE_PAIR(uint32_t, mba_shape_coefficient_09, mba_truth_coefficient_09, 19*(a ^ b) + 38*(a & b) - c, 19*(a + b) - c)
DEFINE_PAIR(uint64_t, mba_shape_coefficient_10, mba_truth_coefficient_10, 21*(a | b) + 21*(a & b) + c, 21*(a + b) + c)

/* Nonlinear shells reserved for future substitution/lifting experiments. */
DEFINE_PAIR(uint32_t, mba_shape_nonlinear_01, mba_truth_nonlinear_01, (a * b) + (c ^ d), (a * b) + (c ^ d))
DEFINE_PAIR(uint64_t, mba_shape_nonlinear_02, mba_truth_nonlinear_02, (a * b) ^ (c * d), (a * b) ^ (c * d))
DEFINE_PAIR(uint8_t, mba_shape_nonlinear_03, mba_truth_nonlinear_03, (a * b) + (c * d) + e, (a * b) + (c * d) + e)
DEFINE_PAIR(uint16_t, mba_shape_nonlinear_04, mba_truth_nonlinear_04, (a & b) * (c ^ d), (a & b) * (c ^ d))
DEFINE_PAIR(uint32_t, mba_shape_nonlinear_05, mba_truth_nonlinear_05, (a * b) + (c * d) - (e * f), (a * b) + (c * d) - (e * f))
DEFINE_PAIR(uint64_t, mba_shape_nonlinear_06, mba_truth_nonlinear_06, (a | b) * (c + d), (a | b) * (c + d))
DEFINE_PAIR(uint8_t, mba_shape_nonlinear_07, mba_truth_nonlinear_07, (a * b) ^ ((c ^ d) + ((uint64_t)2 * (c & d))), (a * b) ^ (c + d))
DEFINE_PAIR(uint16_t, mba_shape_nonlinear_08, mba_truth_nonlinear_08, (a * b) + (c * d) + (e * f) + (g * h), (a * b) + (c * d) + (e * f) + (g * h))

/* Fail-closed casts, mixed widths, loads, calls, and data-dependent shifts. */
DEFINE_PAIR(uint32_t, mba_shape_unsafe_01, mba_truth_unsafe_01, a + ((uint8_t)b - (uint8_t)b), a)
DEFINE_PAIR(uint64_t, mba_shape_unsafe_02, mba_truth_unsafe_02, a + ((uint16_t)b - (uint16_t)b), a)
DEFINE_PAIR(uint8_t, mba_shape_unsafe_03, mba_truth_unsafe_03, a + ((uint32_t)b - (uint32_t)b), a)
DEFINE_PAIR(uint16_t, mba_shape_unsafe_04, mba_truth_unsafe_04, a + ((uint64_t)b - (uint64_t)b), a)
DEFINE_PAIR(uint32_t, mba_shape_unsafe_05, mba_truth_unsafe_05, a + ((uint32_t)mba_shape_static_words[b & 3] - (uint32_t)mba_shape_static_words[b & 3]), a)
DEFINE_PAIR(uint64_t, mba_shape_unsafe_06, mba_truth_unsafe_06, a ^ ((uint32_t)mba_shape_static_words[c & 3] ^ (uint32_t)mba_shape_static_words[c & 3]), a)
DEFINE_PAIR(uint8_t, mba_shape_unsafe_07, mba_truth_unsafe_07, a + ((uint32_t)mba_shape_pure_call((uint32_t)b) - (uint32_t)mba_shape_pure_call((uint32_t)b)), a)
DEFINE_PAIR(uint16_t, mba_shape_unsafe_08, mba_truth_unsafe_08, a ^ ((uint32_t)mba_shape_pure_call((uint32_t)c) ^ (uint32_t)mba_shape_pure_call((uint32_t)c)), a)
DEFINE_PAIR(uint32_t, mba_shape_unsafe_09, mba_truth_unsafe_09, a ^ ((a << (b & 7)) ^ (a << (b & 7))), a)
DEFINE_PAIR(uint64_t, mba_shape_unsafe_10, mba_truth_unsafe_10, a + ((a >> (c & 7)) - (a >> (c & 7))), a)

/*
 * Pending shadow-matcher evidence. These are structural chains, not existing
 * MBA simplifications or width blockers. Task7 must execute the labels below
 * before this stratum can be used as provider-routing evidence.
 */
DEFINE_PAIR(uint32_t, mba_shape_matcher_refusal_01, mba_truth_matcher_refusal_01, ((a + b) + c) + d, ((a + b) + c) + d)
DEFINE_PAIR(uint64_t, mba_shape_matcher_refusal_02, mba_truth_matcher_refusal_02, (a + b) + (c + d), (a + b) + (c + d))
DEFINE_PAIR(uint32_t, mba_shape_matcher_refusal_03, mba_truth_matcher_refusal_03, a + b + c + d + e + f + g + h, a + b + c + d + e + f + g + h)
DEFINE_PAIR(uint64_t, mba_shape_matcher_refusal_04, mba_truth_matcher_refusal_04, a + (b ^ (c & d)), a + (b ^ (c & d)))
DEFINE_PAIR(uint32_t, mba_shape_matcher_refusal_05, mba_truth_matcher_refusal_05, (a ^ b) ^ c, (a ^ b) ^ c)
DEFINE_PAIR(uint64_t, mba_shape_matcher_refusal_06, mba_truth_matcher_refusal_06, ((a & b) | (c & d)) ^ ((e & f) | (g & h)), ((a & b) | (c & d)) ^ ((e & f) | (g & h)))

/*
 * Domain-lifted semantic evidence.  The first two rows are intentionally
 * equivalent historical spellings of XOR: the negative modular coefficient
 * should canonicalize to the subtraction root without changing raw cost.
 * The fixed-shift rows cover one exact complementary rotate and three
 * fail-closed shapes that must not be treated as rotate identities.
 */
DEFINE_PAIR(uint32_t, mba_shape_canonical_xor_negative_coefficient_32, mba_truth_canonical_xor_32, (a + b) + ((UINT32_C(0) - UINT32_C(2)) * (a & b)), a ^ b)
DEFINE_PAIR(uint32_t, mba_shape_equivalent_xor_replay_32, mba_truth_equivalent_xor_32, (a + b) - (UINT32_C(2) * (a & b)), a ^ b)
DEFINE_PAIR(uint32_t, mba_shape_fixed_rotate_complementary_32, mba_truth_fixed_rotate_complementary_32, (a << 7) | (a >> 25), MBA_TRUTH_ROL32(a, 7))
DEFINE_PAIR(uint32_t, mba_shape_fixed_shift_noncomplementary_32, mba_truth_fixed_shift_noncomplementary_32, (a << 5) | (a >> 26), (a << 5) | (a >> 26))
DEFINE_PAIR(uint32_t, mba_shape_fixed_shift_arithmetic_right_32, mba_truth_fixed_shift_arithmetic_right_32, (a << 7) | ((int32_t)a >> 25), (a << 7) | ((int32_t)a >> 25))
DEFINE_PAIR(uint32_t, mba_shape_fixed_shift_variable_count_32, mba_truth_fixed_shift_variable_count_32, (a << (b & 31)) | (a >> ((32 - (b & 31)) & 31)), (a << (b & 31)) | (a >> ((32 - (b & 31)) & 31)))

#undef DEFINE_PAIR
#undef MBA_TRUTH_ROL32
