/**
 * indirect_call.c - Test cases for indirect call resolution optimizer
 *
 * Creates functions that call through encoded function pointer tables. The
 * indirect call optimizer should resolve these by analyzing the function
 * pointer table contents and replacing m_icall (indirect call) instructions
 * with direct m_call instructions to the actual targets.
 *
 * Patterns created:
 * - Plain function pointer table dispatch
 * - Offset-encoded function pointer table (table[i] + OFFSET)
 * - XOR-encoded function pointer table (table[i] ^ XOR_KEY)
 * - Switch-case wrapper dispatching through table
 *
 * Target optimizer: indirect call resolution / m_icall simplification
 *
 * Compiled with: -O0 -g -fno-inline -fno-builtin
 */

#include "platform.h"
#include <stdint.h>

/* Prevent dead-code elimination */
volatile int g_ind_call_sink = 0;

/* ============================================================================
 * Helper target functions (noinline to preserve as separate call targets)
 * ============================================================================ */

__attribute__((noinline))
static int call_target_add(int a, int b)
{
    int r = a + b;
    g_ind_call_sink = r;
    return r;
}

__attribute__((noinline))
static int call_target_sub(int a, int b)
{
    int r = a - b;
    g_ind_call_sink = r;
    return r;
}

__attribute__((noinline))
static int call_target_mul(int a, int b)
{
    int r = a * b;
    g_ind_call_sink = r;
    return r;
}

__attribute__((noinline))
static int call_target_xor(int a, int b)
{
    int r = a ^ b;
    g_ind_call_sink = r;
    return r;
}

/* Function pointer type for all targets */
typedef int (*binary_op_t)(int, int);

/* ============================================================================
 * Function 1: Plain function pointer table
 *
 * A straightforward table of function pointers. The optimizer should resolve
 * the indirect call by reading the table contents from the binary.
 * ============================================================================ */
EXPORT __attribute__((noinline))
int indirect_call_direct_table(int index, int a, int b)
{
    static binary_op_t func_table[] = {
        call_target_add,
        call_target_sub,
        call_target_mul,
        call_target_xor
    };

    /* Clamp index */
    index = index & 0x3;

    /* Indirect call through table */
    int result = func_table[index](a, b);
    g_ind_call_sink = result;
    return result;
}

/* ============================================================================
 * Function 2: Offset-encoded function pointer table
 *
 * Function pointers are stored with a constant offset subtracted. Before
 * calling, the offset is added back. This simulates an obfuscation pattern:
 *   stored = (uintptr_t)func - OFFSET
 *   call = (func_ptr)(stored + OFFSET)
 *
 * The encoding is applied at runtime initialization to avoid link-time
 * issues with non-constant initializers.
 * ============================================================================ */

#define FP_OFFSET 0x100000UL

EXPORT __attribute__((noinline))
int indirect_call_offset_table(int index, int a, int b)
{
    /* Build the offset-encoded table at runtime */
    uintptr_t encoded_table[4];
    encoded_table[0] = (uintptr_t)call_target_add - FP_OFFSET;
    encoded_table[1] = (uintptr_t)call_target_sub - FP_OFFSET;
    encoded_table[2] = (uintptr_t)call_target_mul - FP_OFFSET;
    encoded_table[3] = (uintptr_t)call_target_xor - FP_OFFSET;

    /* Clamp index */
    index = index & 0x3;

    /* Decode: add offset back before calling */
    uintptr_t decoded = encoded_table[index] + FP_OFFSET;
    binary_op_t func = (binary_op_t)decoded;

    int result = func(a, b);
    g_ind_call_sink = result;
    return result;
}

/* ============================================================================
 * Function 3: XOR-encoded function pointer table
 *
 * Function pointers are XOR-encoded with a constant key. Before calling,
 * they are decoded by XORing with the same key. This is a common
 * obfuscation technique for hiding call targets.
 * ============================================================================ */

#define FP_XOR_KEY 0xDEADBEEFUL

EXPORT __attribute__((noinline))
int indirect_call_xor_table(int index, int a, int b)
{
    /* Build the XOR-encoded table at runtime */
    uintptr_t xor_table[4];
    xor_table[0] = (uintptr_t)call_target_add ^ FP_XOR_KEY;
    xor_table[1] = (uintptr_t)call_target_sub ^ FP_XOR_KEY;
    xor_table[2] = (uintptr_t)call_target_mul ^ FP_XOR_KEY;
    xor_table[3] = (uintptr_t)call_target_xor ^ FP_XOR_KEY;

    /* Clamp index */
    index = index & 0x3;

    /* Decode: XOR with key before calling */
    uintptr_t decoded = xor_table[index] ^ FP_XOR_KEY;
    binary_op_t func = (binary_op_t)decoded;

    int result = func(a, b);
    g_ind_call_sink = result;
    return result;
}

/* ============================================================================
 * Function 4: Switch-case wrapper dispatching through table
 *
 * Uses a switch-case to select from the function pointer table. This creates
 * a different microcode pattern (switch/jtbl -> indirect call) compared to
 * the direct table index patterns above.
 * ============================================================================ */
EXPORT __attribute__((noinline))
int indirect_call_wrapper_dispatch(int op, int a, int b)
{
    static binary_op_t dispatch_table[] = {
        call_target_add,
        call_target_sub,
        call_target_mul,
        call_target_xor
    };

    binary_op_t func;
    int result;

    switch (op) {
    case 0:
        func = dispatch_table[0];
        break;
    case 1:
        func = dispatch_table[1];
        break;
    case 2:
        func = dispatch_table[2];
        break;
    case 3:
        func = dispatch_table[3];
        break;
    default:
        func = dispatch_table[0];
        break;
    }

    result = func(a, b);
    g_ind_call_sink = result;
    return result;
}
