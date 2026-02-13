/**
 * block_merge.c - Test cases for block merging flow optimizer
 *
 * Creates goto chains between basic blocks where each intermediate block has
 * a single predecessor. The block merge optimizer should detect these chains
 * and merge consecutive blocks with single predecessor/successor relationships
 * into a single block, simplifying the CFG.
 *
 * Patterns created:
 * - Linear goto chains (3-block, 5-block) simulating Hikari block-splitting
 * - Goto chains inside one arm of a conditional
 * - Goto chains inside loop bodies
 *
 * Target optimizer: UnflattenerBlockMerge / block merge passes
 *
 * Compiled with: -O0 -g -fno-inline -fno-builtin
 */

#include "platform.h"
#include <stdint.h>

/* Prevent dead-code elimination */
volatile int g_block_merge_sink = 0;

/* ============================================================================
 * Function 1: Simple 3-block goto chain
 *
 * Creates a linear chain of 3 blocks connected by unconditional jumps:
 *   Block A -> Block B -> Block C -> return
 * Each intermediate block has exactly one predecessor.
 * ============================================================================ */
EXPORT __attribute__((noinline))
int block_merge_goto_chain(int a, int b)
{
    int result;

    result = a + b;
    goto block_b;

block_b:
    result = result * 3;
    g_block_merge_sink = result;
    goto block_c;

block_c:
    result = result - 7;
    g_block_merge_sink = result;

    return result;
}

/* ============================================================================
 * Function 2: Long 5-block goto chain (Hikari block-splitting simulation)
 *
 * Simulates the Hikari obfuscator's block-splitting pass, which breaks a
 * single basic block into many small blocks connected by unconditional jumps:
 *   Block 1 -> Block 2 -> Block 3 -> Block 4 -> Block 5 -> return
 * ============================================================================ */
EXPORT __attribute__((noinline))
int block_merge_long_chain(int x)
{
    int result;

    /* Block 1: initialization */
    result = x;
    goto step2;

step2:
    /* Block 2: first operation */
    result = result + 0x1234;
    goto step3;

step3:
    /* Block 3: second operation */
    result = result ^ 0x5678;
    goto step4;

step4:
    /* Block 4: third operation */
    result = result * 5;
    g_block_merge_sink = result;
    goto step5;

step5:
    /* Block 5: final operation */
    result = result - 0xABCD;
    g_block_merge_sink = result;

    return result;
}

/* ============================================================================
 * Function 3: Goto chain inside one arm of if/else
 *
 * The true-branch of the conditional contains a goto chain, while the
 * false-branch is a single block. This tests that the block merge optimizer
 * correctly handles chains nested inside conditional structures.
 * ============================================================================ */
EXPORT __attribute__((noinline))
int block_merge_conditional_chain(int a, int cond)
{
    int result = a;

    if (cond > 0) {
        /* True branch: 3-block goto chain */
        result = result + 10;
        goto true_step2;

    true_step2:
        result = result * 2;
        goto true_step3;

    true_step3:
        result = result - 5;
        g_block_merge_sink = result;
    } else {
        /* False branch: single block (no chain) */
        result = result - 100;
        g_block_merge_sink = result;
    }

    return result;
}

/* ============================================================================
 * Function 4: Goto chain inside a loop body
 *
 * Each iteration of the loop body contains a goto chain. The block merge
 * optimizer should merge the chain within the loop body without disturbing
 * the loop structure itself.
 * ============================================================================ */
EXPORT __attribute__((noinline))
int block_merge_loop_body(int n)
{
    int result = 0;

    for (int i = 0; i < n; i++) {
        /* Start of chain inside loop body */
        result = result + i;
        goto loop_step2;

    loop_step2:
        result = result ^ (i * 3);
        goto loop_step3;

    loop_step3:
        result = result + 1;
        g_block_merge_sink = result;
    }

    return result;
}
