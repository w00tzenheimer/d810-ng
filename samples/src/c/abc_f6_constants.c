/**
 * ABC F6 Constants Pattern Test
 *
 * This sample specifically tests the father_patcher_abc_* code path in
 * GenericDispatcherUnflatteningRule. It uses constants in the specific range
 * that the ABC code detects:
 *
 * Magic constant range: 1010000-1011999 (decimal) = 0xF6950-0xF719F (hex)
 *
 * The ABC code checks: cnst > 1010000 && cnst < 1011999
 *
 * See: src/d810/optimizers/microcode/flow/flattening/generic.py:919
 */

#include "ida_types.h"

/* Volatile to prevent compiler optimization */
volatile int global_side_effect = 0;

/**
 * ABC Pattern - Uses magic constants in the 0xF6xxx/101xxxx range
 *
 * The ABC splitter looks for instructions like:
 *   add reg, 0xF6A00  (where constant is in range 1010000-1011999)
 *   sub reg, 0xF6B00
 *   xor reg, 0xF6C00
 *   or reg, 0xF6D00
 *
 * When detected, it splits the block into two paths based on condition.
 */
int abc_f6_add_dispatch(int input)
{
    unsigned int state = 1010001;  /* 0xF6951 - in ABC range */
    int result = 0;

    while (1)
    {
        /* Use ADD with ABC-range constants */
        unsigned int dispatch_key = state + 0;  /* No change */

        switch (dispatch_key)
        {
        case 1010001:  /* Entry state */
            result = input;
            state = state + 1;  /* 1010001 -> 1010002 */
            break;

        case 1010002:  /* Process state */
            result = result * 2;
            state = state + 1;  /* 1010002 -> 1010003 */
            break;

        case 1010003:  /* Check state */
            if (result > 50)
            {
                state = 1010010;  /* Branch to exit A */
            }
            else
            {
                state = 1010020;  /* Branch to exit B */
            }
            break;

        case 1010010:  /* Exit A */
            return result;

        case 1010020:  /* Exit B */
            return -result;

        default:
            /* Error - force exit */
            global_side_effect++;
            return 0;
        }
    }
}

/**
 * ABC Pattern using SUB with 0xF6xxx constants
 */
int abc_f6_sub_dispatch(int input)
{
    unsigned int state = 1011000;  /* Near upper bound of ABC range */
    int result = input;

    while (1)
    {
        /* Use SUB with ABC-range constants */
        unsigned int dispatch_key = state - 0;

        switch (dispatch_key)
        {
        case 1011000:  /* Entry */
            result = result + 10;
            state = state - 100;  /* 1011000 -> 1010900 */
            break;

        case 1010900:  /* Middle */
            result = result * 3;
            state = state - 100;  /* 1010900 -> 1010800 */
            break;

        case 1010800:  /* Check */
            if (result > 100)
            {
                state = 1010100;  /* Exit A path */
            }
            else
            {
                state = 1010200;  /* Exit B path */
            }
            break;

        case 1010100:  /* Exit A */
            return result;

        case 1010200:  /* Exit B */
            return result / 2;

        default:
            global_side_effect++;
            return -1;
        }
    }
}

/**
 * ABC Pattern using XOR with 0xF6xxx constants
 *
 * XOR-based state transitions are common in obfuscated code.
 */
int abc_f6_xor_dispatch(int input)
{
    unsigned int state = 1010500;  /* 0xF6B54 */
    int result = input;

    while (1)
    {
        switch (state)
        {
        case 1010500:  /* Entry */
            result = result ^ 0xFF;
            state = state ^ 1;  /* 1010500 ^ 1 = 1010501 */
            break;

        case 1010501:  /* Process */
            result = result + 42;
            state = state ^ 3;  /* 1010501 ^ 3 = 1010502 */
            break;

        case 1010502:  /* Finalize */
            result = result - 10;
            state = state ^ 7;  /* 1010502 ^ 7 = 1010497 */
            break;

        case 1010497:  /* Exit */
            return result;

        default:
            global_side_effect++;
            return -1;
        }
    }
}

/**
 * ABC Pattern using OR with 0xF6xxx constants
 */
int abc_f6_or_dispatch(int input)
{
    unsigned int state = 1010000;  /* Lower bound */
    int result = input;

    while (1)
    {
        switch (state)
        {
        case 1010000:  /* Entry */
            result = result | 0xF0;
            state = state | 1;  /* 1010000 | 1 = 1010001 */
            break;

        case 1010001:  /* Process */
            result = result | 0x0F;
            state = state | 2;  /* 1010001 | 2 = 1010003 */
            break;

        case 1010003:  /* Exit */
            return result;

        default:
            global_side_effect++;
            return -1;
        }
    }
}

/**
 * Combined ABC pattern with nested conditions
 *
 * This exercises the recursive nature of father_history_patcher_abc
 */
int abc_f6_nested(int a, int b)
{
    unsigned int state = 1010100;
    int result = 0;

    while (1)
    {
        switch (state)
        {
        case 1010100:  /* Entry */
            if (a > 0)
            {
                state = 1010200;  /* Path A */
            }
            else
            {
                state = 1010300;  /* Path B */
            }
            break;

        case 1010200:  /* Path A: check b */
            result = a;
            if (b > 0)
            {
                state = 1010400;  /* A + B positive */
            }
            else
            {
                state = 1010500;  /* A positive, B non-positive */
            }
            break;

        case 1010300:  /* Path B: check b */
            result = -a;
            if (b > 0)
            {
                state = 1010600;  /* A non-positive, B positive */
            }
            else
            {
                state = 1010700;  /* Both non-positive */
            }
            break;

        case 1010400:  /* Result: a + b */
            return result + b;

        case 1010500:  /* Result: a - b */
            return result - b;

        case 1010600:  /* Result: b - a (via -a) */
            return result + b;

        case 1010700:  /* Result: -(a + b) */
            return -(result - b);

        default:
            global_side_effect++;
            return 0;
        }
    }
}

/**
 * 64-bit constant pattern
 *
 * The ABC code also handles high(sub(or(x, #0xF6A12_0000_005F.8), y))
 * where the constant has the ABC value in the high 32 bits.
 */
int abc_f6_64bit_pattern(int input)
{
    /* 64-bit constant: 0x F6A12 00000000 (high 32 bits = 1010194) */
    unsigned long long state = 0xF6A1200000000ULL;
    int result = input;

    while (1)
    {
        unsigned int dispatch = (unsigned int)(state >> 32);

        switch (dispatch)
        {
        case 0xF6A12:  /* 1010194 in decimal */
            result = result + 1;
            state = 0xF6B0000000000ULL;  /* High bits = 0xF6B00 = 1010432 */
            break;

        case 0xF6B00:  /* 1010432 */
            result = result * 2;
            state = 0xF6C0000000000ULL;  /* High bits = 0xF6C00 = 1010688 */
            break;

        case 0xF6C00:  /* 1010688 */
            return result;

        default:
            global_side_effect++;
            return -1;
        }
    }
}
