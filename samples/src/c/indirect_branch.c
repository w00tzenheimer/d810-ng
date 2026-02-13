/**
 * indirect_branch.c - Test cases for indirect branch resolution optimizer
 *
 * Creates functions with computed goto (GCC labels-as-values extension) that
 * produce m_ijmp (indirect jump) instructions in IDA's microcode. The indirect
 * branch optimizer should resolve these computed gotos by analyzing the jump
 * table contents and replacing m_ijmp with direct conditional/unconditional
 * branches.
 *
 * Patterns created:
 * - Plain computed goto with 4-entry label table
 * - XOR-encoded jump table (encode on store, decode before use)
 * - Offset-based dispatch (base + offset[i])
 * - Large 8-entry table with AND mask for bounds
 *
 * Target optimizer: indirect branch resolution / m_ijmp simplification
 *
 * Compiled with: -O0 -g -fno-inline -fno-builtin
 * Requires: GCC/Clang labels-as-values extension (&&label)
 */

#include "platform.h"
#include <stdint.h>

/* Prevent dead-code elimination */
volatile int g_ind_branch_sink = 0;

/* ============================================================================
 * Function 1: Plain computed goto (4-entry table)
 *
 * Direct labels-as-values dispatch. The jump table contains raw label
 * addresses and the function jumps to table[index].
 * ============================================================================ */
EXPORT __attribute__((noinline))
int indirect_branch_direct(int index, int a)
{
    int result = a;

    static void *jump_table[] = { &&case0, &&case1, &&case2, &&case3 };

    /* Clamp index */
    index = index & 0x3;

    goto *jump_table[index];

case0:
    result = result + 10;
    goto done;
case1:
    result = result * 2;
    goto done;
case2:
    result = result - 5;
    goto done;
case3:
    result = result ^ 0xFF;
    goto done;

done:
    g_ind_branch_sink = result;
    return result;
}

/* ============================================================================
 * Function 2: XOR-encoded jump table
 *
 * The jump table entries are XOR-encoded with a key. Before dispatching,
 * the entry is decoded by XORing with the same key. This simulates an
 * obfuscation pattern where jump targets are encoded in the table.
 * ============================================================================ */
EXPORT __attribute__((noinline))
int indirect_branch_xor_table(int index, int a)
{
    int result = a;

    static void *raw_table[] = { &&xcase0, &&xcase1, &&xcase2, &&xcase3 };

    /* Clamp index */
    index = index & 0x3;

    /* XOR-decode the table entry before jumping */
    uintptr_t encoded = (uintptr_t)raw_table[index] ^ (uintptr_t)0xDEAD;
    uintptr_t decoded = encoded ^ (uintptr_t)0xDEAD;
    goto *(void *)decoded;

xcase0:
    result = result + 100;
    goto xdone;
xcase1:
    result = result - 50;
    goto xdone;
xcase2:
    result = result * 3;
    goto xdone;
xcase3:
    result = result / 2;
    goto xdone;

xdone:
    g_ind_branch_sink = result;
    return result;
}

/* ============================================================================
 * Function 3: Offset-based dispatch
 *
 * Instead of storing absolute addresses, the table stores offsets relative
 * to a base address. The dispatch computes: base + offset[index].
 * This pattern appears in PIC (position-independent code) jump tables.
 * ============================================================================ */
EXPORT __attribute__((noinline))
int indirect_branch_offset_table(int index, int a)
{
    int result = a;

    /* Base label for offset computation */
    static void *targets[] = { &&ocase0, &&ocase1, &&ocase2, &&ocase3 };

    /* Clamp index */
    index = index & 0x3;

    /* Compute offset from base and add back */
    uintptr_t base = (uintptr_t)&&ocase0;
    intptr_t offset = (intptr_t)((uintptr_t)targets[index] - base);
    void *target = (void *)(base + offset);
    goto *target;

ocase0:
    result = result + 1;
    goto odone;
ocase1:
    result = result + 2;
    goto odone;
ocase2:
    result = result + 4;
    goto odone;
ocase3:
    result = result + 8;
    goto odone;

odone:
    g_ind_branch_sink = result;
    return result;
}

/* ============================================================================
 * Function 4: Large 8-entry table with AND mask
 *
 * An 8-entry computed goto table with index masked by AND 0x7. Tests that
 * the optimizer handles larger dispatch tables and recognizes the bitmask
 * as a bounds check.
 * ============================================================================ */
EXPORT __attribute__((noinline))
int indirect_branch_large_table(int index, int a)
{
    int result = a;

    static void *big_table[] = {
        &&lcase0, &&lcase1, &&lcase2, &&lcase3,
        &&lcase4, &&lcase5, &&lcase6, &&lcase7
    };

    /* AND mask bounds the index to [0, 7] */
    index = index & 0x7;

    goto *big_table[index];

lcase0:
    result = result + 0x10;
    goto ldone;
lcase1:
    result = result + 0x20;
    goto ldone;
lcase2:
    result = result + 0x30;
    goto ldone;
lcase3:
    result = result + 0x40;
    goto ldone;
lcase4:
    result = result ^ 0x10;
    goto ldone;
lcase5:
    result = result ^ 0x20;
    goto ldone;
lcase6:
    result = result ^ 0x30;
    goto ldone;
lcase7:
    result = result ^ 0x40;
    goto ldone;

ldone:
    g_ind_branch_sink = result;
    return result;
}
