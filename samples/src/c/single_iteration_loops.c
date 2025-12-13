/*
 * Single Iteration Loop Patterns for D810-ng
 *
 * This file demonstrates control-flow patterns where a flattened loop
 * executes exactly once, allowing the UnflattenerSingleIteration optimizer
 * to simplify the CFG.
 *
 * Pattern Detection Requirements:
 * - Block 1: mov #INIT, state  ->  Block 2
 * - Block 2: jnz state, #CHECK, @exit  ->  Block 3 (body) or Block 4 (exit)
 * - Block 3: body; mov #UPDATE, state; goto @2
 *
 * Key Property: INIT == CHECK and UPDATE != CHECK
 * Result: Loop runs exactly once (body executes, then exits)
 */

#include "ida_types.h"

/* ============================================================================
 * Pattern 1: Simple Single Iteration Loop
 *
 * Classic pattern where state is initialized to CHECK value,
 * body executes once, then state is updated to non-CHECK value.
 * ============================================================================ */
__attribute__((noinline))
int single_iteration_simple(int a)
{
    volatile int result = a;
    volatile int state = 0x1234;  // INIT == CHECK

    // This loop executes exactly once
    while (state == 0x1234)
    {
        result += 10;
        state = 0x5678;  // UPDATE != CHECK, exit loop
    }

    return result;
}

/* ============================================================================
 * Pattern 2: Single Iteration with Multiple Operations
 *
 * More complex body but still single iteration.
 * ============================================================================ */
__attribute__((noinline))
int single_iteration_complex(int a, int b)
{
    volatile int result = 0;
    volatile int state = 0xABCD;  // INIT == CHECK

    while (state == 0xABCD)
    {
        result = a + b;
        result *= 2;
        result -= 5;
        state = 0x9999;  // UPDATE != CHECK, exit loop
    }

    return result;
}

/* ============================================================================
 * Pattern 3: Single Iteration with Conditional Inside
 *
 * Loop runs once, but body has conditional logic.
 * ============================================================================ */
__attribute__((noinline))
int single_iteration_conditional(int a)
{
    volatile int result = a;
    volatile int state = 0x2000;  // INIT == CHECK

    while (state == 0x2000)
    {
        if (a > 0)
        {
            result += 100;
        }
        else
        {
            result += 200;
        }
        state = 0x3000;  // UPDATE != CHECK, exit loop
    }

    return result;
}

/* ============================================================================
 * Pattern 4: Single Iteration with Nested Block
 *
 * More complex CFG within single-iteration loop.
 * ============================================================================ */
__attribute__((noinline))
int single_iteration_nested(int a, int b)
{
    volatile int result = 0;
    volatile int state = 0x4000;  // INIT == CHECK

    while (state == 0x4000)
    {
        if (a > 0)
        {
            if (b > 0)
            {
                result = a + b;
            }
            else
            {
                result = a - b;
            }
        }
        else
        {
            result = a * b;
        }
        state = 0x5000;  // UPDATE != CHECK, exit loop
    }

    return result;
}

/* ============================================================================
 * Pattern 5: Single Iteration After Dispatcher
 *
 * Residual loop left after main unflattening.
 * This simulates what might remain after a larger dispatcher is unflattened.
 * ============================================================================ */
__attribute__((noinline))
int single_iteration_residual(int input)
{
    volatile int result = input;
    volatile int state = 0x8000;  // Initial dispatcher state

    // Main dispatch logic (would be unflattened first)
    switch (state)
    {
    case 0x8000:
        result += 5;
        state = 0x9000;
        break;
    default:
        break;
    }

    // Residual single-iteration loop
    // After dispatcher unflattening, this pattern remains
    while (state == 0x9000)
    {
        result *= 2;
        state = 0xFFFF;  // UPDATE != CHECK, exit
    }

    return result;
}

/* ============================================================================
 * Pattern 6: Single Iteration with Magic Constants
 *
 * Uses large constants typical of obfuscated code.
 * Tests the magic constant range detection (DEFAULT_MIN_MAGIC = 0x1000).
 * ============================================================================ */
__attribute__((noinline))
int single_iteration_magic(int a)
{
    volatile int result = a;
    volatile unsigned int state = 0xDEADBEEF;  // INIT == CHECK (large magic constant)

    while (state == 0xDEADBEEF)
    {
        result += 777;
        state = 0xCAFEBABE;  // UPDATE != CHECK, exit loop
    }

    return result;
}

/* ============================================================================
 * Pattern 7: Single Iteration with Multiple Predecessors
 *
 * Loop header has multiple predecessors, all setting same initial state.
 * ============================================================================ */
__attribute__((noinline))
int single_iteration_multi_pred(int a)
{
    volatile int result = 0;
    volatile int state;

    // Multiple paths converge to same state value
    if (a > 0)
    {
        state = 0x6000;
    }
    else
    {
        state = 0x6000;  // Same value regardless of branch
    }

    // Single iteration loop
    while (state == 0x6000)
    {
        result = a * 10;
        state = 0x7000;  // UPDATE != CHECK, exit
    }

    return result;
}

/* ============================================================================
 * Pattern 8: Chained Single Iterations
 *
 * Multiple single-iteration loops in sequence.
 * Each should be detected and simplified independently.
 * ============================================================================ */
__attribute__((noinline))
int single_iteration_chained(int a)
{
    volatile int result = a;
    volatile int state1 = 0x1111;
    volatile int state2 = 0x2222;

    // First single-iteration loop
    while (state1 == 0x1111)
    {
        result += 10;
        state1 = 0xAAAA;
    }

    // Second single-iteration loop
    while (state2 == 0x2222)
    {
        result *= 2;
        state2 = 0xBBBB;
    }

    return result;
}

/* ============================================================================
 * Pattern 9: Single Iteration with Boundary Magic Value
 *
 * Tests the minimum magic constant threshold (0x1000).
 * ============================================================================ */
__attribute__((noinline))
int single_iteration_boundary(int a)
{
    volatile int result = a;
    volatile int state = 0x1000;  // Exactly at DEFAULT_MIN_MAGIC

    while (state == 0x1000)
    {
        result += 42;
        state = 0x1001;  // UPDATE != CHECK, exit
    }

    return result;
}

/* ============================================================================
 * Pattern 10: Single Iteration in State Machine Context
 *
 * Simulates what remains after partial unflattening of a state machine.
 * ============================================================================ */
__attribute__((noinline))
int single_iteration_state_machine(int input)
{
    volatile int result = 0;
    volatile int state = 0xA000;

    // Simplified state machine (already partially unflattened)
    if (input > 0)
    {
        state = 0xB000;
    }

    // Residual single-iteration check
    while (state == 0xB000)
    {
        result = input + 999;
        state = 0xC000;  // UPDATE != CHECK, exit
    }

    return result;
}
