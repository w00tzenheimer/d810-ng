/**
 * ABC XOR Dispatch Pattern Test
 *
 * This sample tests the father_patcher_abc_from_or_xor_* methods in
 * GenericDispatcherUnflatteningRule. It uses XOR-based state transitions
 * instead of simple assignment, which exercises the ABC (Arithmetic/Bitwise/Constant)
 * patching logic.
 *
 * Pattern tested:
 *   state = state ^ CONSTANT  (XOR transition)
 *   switch ((state ^ DISPATCH_KEY) & MASK) { ... }
 */

#include "ida_types.h"

/* Volatile to prevent compiler optimization */
volatile int global_accumulator = 0;

/**
 * XOR-based flattened control flow
 *
 * State transitions use XOR: state = state ^ constant
 * Dispatcher uses: switch ((state ^ 0xDEADBEEF) & 0xFF)
 */
int abc_xor_dispatch(int input)
{
    unsigned int state = 0x12345678;
    int result = 0;
    int i;

    while (1)
    {
        /* XOR-based dispatcher - tests father_patcher_abc_from_or_xor_v1 */
        switch ((state ^ 0xDEADBEEF) & 0xFF)
        {
        case 0x00:  /* Entry: Initialize */
            result = input;
            state = state ^ 0x11111111;  /* XOR transition to state 1 */
            break;

        case 0x11:  /* State 1: Add operation */
            result = result + 42;
            state = state ^ 0x22222222;  /* XOR transition to state 2 */
            break;

        case 0x33:  /* State 2: Multiply */
            result = result * 2;
            state = state ^ 0x44444444;  /* XOR transition to state 3 */
            break;

        case 0x77:  /* State 3: Check condition */
            if (result > 100)
            {
                state = state ^ 0x88888888;  /* XOR to exit path A */
            }
            else
            {
                state = state ^ 0x99999999;  /* XOR to exit path B */
            }
            break;

        case 0xFF:  /* Exit A: Return positive */
            return result;

        case 0xEE:  /* Exit B: Return negative */
            return -result;

        default:
            /* Dead code - should never reach */
            global_accumulator++;
            state = state ^ 0xFFFFFFFF;
            break;
        }
    }
}

/**
 * OR-based state manipulation
 *
 * State transitions use OR with masks: state = (state & ~mask) | value
 * Tests father_patcher_abc_from_or_xor_v2/v3
 */
int abc_or_dispatch(int input)
{
    unsigned int state = 0;
    int result = input;

    while (1)
    {
        /* OR-based dispatcher */
        switch (state & 0xF)
        {
        case 0:  /* Entry */
            result = result + 10;
            state = (state & ~0xF) | 1;  /* Set low nibble to 1 */
            break;

        case 1:  /* Process */
            result = result * 3;
            state = (state & ~0xF) | 2;  /* Set low nibble to 2 */
            break;

        case 2:  /* Finalize */
            result = result - 5;
            state = (state & ~0xF) | 3;  /* Set low nibble to 3 */
            break;

        case 3:  /* Exit */
            return result;

        default:
            state = (state & ~0xF) | 3;  /* Force exit */
            break;
        }
    }
}

/**
 * Combined XOR/OR state manipulation
 *
 * Uses both XOR and OR in transitions to test multiple ABC patterns
 */
int abc_mixed_dispatch(int input, int mode)
{
    unsigned int state = 0x00000000;
    int result = input;

    while (1)
    {
        switch (state)
        {
        case 0x00000000:  /* Entry */
            if (mode == 0)
            {
                state = state ^ 0xAAAAAAAA;  /* XOR path */
            }
            else
            {
                state = state | 0x55555555;  /* OR path */
            }
            break;

        case 0xAAAAAAAA:  /* XOR path processing */
            result = result ^ 0x12345678;
            state = state ^ 0xFFFFFFFF;  /* XOR to common exit */
            break;

        case 0x55555555:  /* OR path processing */
            result = result | 0x87654321;
            state = state ^ 0xAAAAAAAA;  /* XOR to common exit */
            break;

        case 0x55555555 ^ 0xAAAAAAAA:  /* Common exit: 0xFFFFFFFF */
            return result;

        default:
            return -1;  /* Error state */
        }
    }
}
