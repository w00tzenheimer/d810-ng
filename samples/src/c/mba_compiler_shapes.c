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

/* Linear coefficient residuals, intentionally beyond direct catalogue scope. */
DEFINE_PAIR(uint8_t, mba_shape_coefficient_01, mba_truth_coefficient_01, 3*a + 5*b - 2*c, 3*a + 5*b - 2*c)
DEFINE_PAIR(uint16_t, mba_shape_coefficient_02, mba_truth_coefficient_02, 7*a - 4*b + 9*c - d, 7*a - 4*b + 9*c - d)
DEFINE_PAIR(uint32_t, mba_shape_coefficient_03, mba_truth_coefficient_03, 2*a + 3*b + 5*c + 7*d, 2*a + 3*b + 5*c + 7*d)
DEFINE_PAIR(uint64_t, mba_shape_coefficient_04, mba_truth_coefficient_04, 11*a - 6*b + 4*c - 3*d + e, 11*a - 6*b + 4*c - 3*d + e)
DEFINE_PAIR(uint8_t, mba_shape_coefficient_05, mba_truth_coefficient_05, a + 2*b + 3*c + 4*d + 5*e + 6*f, a + 2*b + 3*c + 4*d + 5*e + 6*f)
DEFINE_PAIR(uint16_t, mba_shape_coefficient_06, mba_truth_coefficient_06, 13*a + 17*b - 19*c + 23*d - 29*e, 13*a + 17*b - 19*c + 23*d - 29*e)
DEFINE_PAIR(uint32_t, mba_shape_coefficient_07, mba_truth_coefficient_07, 3*a + 3*b + 3*c + 3*d + 3*e + 3*f + 3*g, 3*(a + b + c + d + e + f + g))
DEFINE_PAIR(uint64_t, mba_shape_coefficient_08, mba_truth_coefficient_08, 31*a - 7*b + 2*c + 9*d - 5*e + 12*f, 31*a - 7*b + 2*c + 9*d - 5*e + 12*f)
DEFINE_PAIR(uint8_t, mba_shape_coefficient_09, mba_truth_coefficient_09, a - b + c - d + e - f + g - h, a - b + c - d + e - f + g - h)
DEFINE_PAIR(uint16_t, mba_shape_coefficient_10, mba_truth_coefficient_10, 8*a + 6*b + 4*c + 2*d + e + 3*f + 5*g + 7*h, 8*a + 6*b + 4*c + 2*d + e + 3*f + 5*g + 7*h)

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

/* Structural matcher refusals: labels are contracts for Task 7 shadow mode. */
DEFINE_PAIR(uint8_t, mba_shape_matcher_refusal_01, mba_truth_matcher_refusal_01, (a + b) + (c ^ c), a + b)
DEFINE_PAIR(uint16_t, mba_shape_matcher_refusal_02, mba_truth_matcher_refusal_02, a + (b ^ b) + (c & ~c), a)
DEFINE_PAIR(uint32_t, mba_shape_matcher_refusal_03, mba_truth_matcher_refusal_03, (a ^ b) + ((uint64_t)2 * (a & b)), a + b)
DEFINE_PAIR(uint64_t, mba_shape_matcher_refusal_04, mba_truth_matcher_refusal_04, (a & b) + (a & ~b), a)
DEFINE_PAIR(uint8_t, mba_shape_matcher_refusal_05, mba_truth_matcher_refusal_05, (a + b) - (b + a), 0)
DEFINE_PAIR(uint16_t, mba_shape_matcher_refusal_06, mba_truth_matcher_refusal_06, (a ^ b) ^ (c ^ c), a ^ b)

#undef DEFINE_PAIR
