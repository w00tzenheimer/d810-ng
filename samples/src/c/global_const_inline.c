/**
 * global_const_inline.c - Test cases for global constant inlining optimizer
 *
 * Creates functions that load constant values from global read-only data
 * (const arrays, const tables). The global constant inlining optimizer should
 * detect reads from read-only global memory and replace them with the actual
 * constant values, enabling further constant folding and dead code elimination.
 *
 * Patterns created:
 * - Simple const array lookup (uint32_t)
 * - XOR decrypt pattern with const key + const encrypted data
 * - Multi-size const loads (byte, word, dword, qword)
 * - State machine transition table lookups
 * - RVA-like constant guard (must NOT become MEMORY[0x...])
 *
 * Target optimizer: fold_readonlydata / global constant propagation
 *
 * Compiled with: -O0 -g -fno-inline -fno-builtin
 */

#include "platform.h"
#include <stdint.h>

/* Prevent dead-code elimination */
volatile int g_const_inline_sink = 0;

/* ============================================================================
 * Constant data tables (read-only)
 * ============================================================================ */

/* Simple lookup table */
static const uint32_t LOOKUP_TABLE[8] = {
    0x12345678, 0x9ABCDEF0, 0x13579BDF, 0x2468ACE0,
    0xDEADBEEF, 0xCAFEBABE, 0xFEEDFACE, 0x8BADF00D
};

/* XOR key table */
static const uint32_t XOR_KEYS[4] = {
    0xA5A5A5A5, 0x5A5A5A5A, 0x3C3C3C3C, 0xC3C3C3C3
};

/* Encrypted data (each entry is LOOKUP_TABLE[i] ^ XOR_KEYS[i % 4]) */
static const uint32_t ENCRYPTED_DATA[4] = {
    0x12345678 ^ 0xA5A5A5A5,  /* = 0xB791F3DD */
    0x9ABCDEF0 ^ 0x5A5A5A5A,  /* = 0xC0E684AA */
    0x13579BDF ^ 0x3C3C3C3C,  /* = 0x2F6BA7E3 */
    0x2468ACE0 ^ 0xC3C3C3C3   /* = 0xE7AB6F23 */
};

/* Multi-size constant data */
static const uint8_t  CONST_BYTES[4]  = { 0x11, 0x22, 0x33, 0x44 };
static const uint16_t CONST_WORDS[4]  = { 0x1111, 0x2222, 0x3333, 0x4444 };
static const uint32_t CONST_DWORDS[4] = { 0x11111111, 0x22222222, 0x33333333, 0x44444444 };
static const uint64_t CONST_QWORDS[4] = {
    0x1111111111111111ULL, 0x2222222222222222ULL,
    0x3333333333333333ULL, 0x4444444444444444ULL
};

/* State machine transition table: next_state = STATE_TABLE[current_state][input_bit]
 * Each row is [next_if_0, next_if_1] */
static const int STATE_TABLE[6][2] = {
    { 1, 2 },  /* state 0 */
    { 3, 4 },  /* state 1 */
    { 4, 5 },  /* state 2 */
    { 1, 5 },  /* state 3 */
    { 2, 0 },  /* state 4 */
    { 0, 3 },  /* state 5 (accepting) */
};

/* RVA-guard constants:
 * - SAFE_INLINE_CONST should be inlined by GlobalConstantInliner.
 * - RVA_LIKE_OFFSET must NOT be inlined as a raw address-like immediate. */
static const uint64_t SAFE_INLINE_CONST = 0x1122334455667788ULL;
static const uint64_t RVA_LIKE_OFFSET = 0x2000ULL;
volatile uint8_t g_rva_guard_sink = 0;

/* ============================================================================
 * Function 1: Simple const array lookup
 *
 * Reads a value from a const uint32_t array. The optimizer should replace
 * the memory load with the actual constant value when the index is known.
 * ============================================================================ */
EXPORT __attribute__((noinline))
uint32_t global_const_simple_lookup(int index)
{
    uint32_t value;

    /* Clamp index to valid range */
    index = index & 0x7;

    /* Load from const table -- should be folded to constant */
    value = LOOKUP_TABLE[index];
    g_const_inline_sink = (int)value;

    return value;
}

/* ============================================================================
 * Function 2: XOR decrypt from const tables
 *
 * Loads a key from one const table and encrypted data from another, then
 * XORs them. Both tables are read-only, so the optimizer should fold
 * both loads and compute the XOR result at decompile time.
 * ============================================================================ */
EXPORT __attribute__((noinline))
uint32_t global_const_xor_decrypt(int index)
{
    uint32_t key, encrypted, decrypted;

    /* Clamp index to valid range */
    index = index & 0x3;

    /* Load key and encrypted data from const tables */
    key = XOR_KEYS[index];
    encrypted = ENCRYPTED_DATA[index];

    /* Decrypt -- both operands are from const tables */
    decrypted = encrypted ^ key;
    g_const_inline_sink = (int)decrypted;

    return decrypted;
}

/* ============================================================================
 * Function 3: Multi-size const loads
 *
 * Loads const values of different sizes (byte, word, dword, qword) to test
 * that the optimizer correctly handles all memory access widths when reading
 * from read-only global data.
 * ============================================================================ */
EXPORT __attribute__((noinline))
uint64_t global_const_multi_size(void)
{
    uint8_t  b = CONST_BYTES[2];
    uint16_t w = CONST_WORDS[1];
    uint32_t d = CONST_DWORDS[3];
    uint64_t q = CONST_QWORDS[0];

    /* Combine all sizes into one result */
    uint64_t result = (uint64_t)b + (uint64_t)w + (uint64_t)d + q;
    g_const_inline_sink = (int)result;

    return result;
}

/* ============================================================================
 * Function 4: State machine transition table
 *
 * Uses a const 2D transition table to drive a state machine. The optimizer
 * should be able to fold the table lookups when the state and input are
 * known at each step.
 * ============================================================================ */
EXPORT __attribute__((noinline))
int global_const_state_table(int initial_state)
{
    int state = initial_state % 6;
    int steps = 0;

    /* Run the state machine for a fixed number of transitions */
    for (int i = 0; i < 10; i++) {
        int input_bit = (i & 1);  /* alternate 0 and 1 */
        state = STATE_TABLE[state][input_bit];
        steps++;

        /* Exit early if we reach the accepting state (5) */
        if (state == 5) {
            g_const_inline_sink = steps;
            return steps;
        }
    }

    g_const_inline_sink = steps;
    return steps;
}

/* ============================================================================
 * Function 5: RVA-like value guard
 *
 * This function mixes two constant global loads:
 * - a normal numeric constant (safe to inline)
 * - an RVA-like offset that can become imagebase-relative
 *
 * Regression target:
 * - GlobalConstantInliner should inline SAFE_INLINE_CONST.
 * - GlobalConstantInliner should NOT inline RVA_LIKE_OFFSET into
 *   a raw MEMORY[0x...] expression.
 * ============================================================================ */
EXPORT __attribute__((noinline))
uint64_t global_const_rva_guard(void)
{
    uint64_t safe = *(const volatile uint64_t *)&SAFE_INLINE_CONST;
    uint64_t rva_like = *(const volatile uint64_t *)&RVA_LIKE_OFFSET;
    uintptr_t target = 0x180000000ULL + (uintptr_t)rva_like;
    uint8_t loaded = *(const volatile uint8_t *)target;

    g_rva_guard_sink = loaded;
    return safe ^ (uint64_t)loaded;
}
