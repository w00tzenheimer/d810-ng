/*
 * Dispatcher Pattern Test Cases for D810-ng
 *
 * This file demonstrates different control-flow flattening dispatcher patterns
 * that dispatcher_detection.py should detect:
 *
 * 1. Pattern 1: High fan-in dispatcher (many blocks jump to same dispatcher)
 * 2. Pattern 2: State variable comparison against large constants (>0x10000)
 * 3. Pattern 3: Nested while(1) loop pattern (Hodur-style)
 * 4. Pattern 4: Simple switch-case dispatcher (O-LLVM style with jtbl)
 * 5. Pattern 5: Mixed pattern combining multiple strategies
 *
 * Expected detection by dispatcher_detection.py:
 * - HIGH_FAN_IN: Blocks with >= 5 predecessors
 * - STATE_COMPARISON: Comparisons against constants > 0x10000
 * - LOOP_HEADER: Blocks with >= 2 back-edges
 * - NESTED_LOOP: Hodur-style deeply nested while(1) loops
 * - SWITCH_JUMP: Blocks with switch/jtbl instructions
 * - SMALL_BLOCK: Tight loops <= 20 instructions
 */

#include "ida_types.h"
#include <stdio.h>
#include <string.h>

/* ============================================================================
 * Pattern 1: High Fan-In Dispatcher
 * Expected: HIGH_FAN_IN, PREDECESSOR_UNIFORM, SMALL_BLOCK
 * ============================================================================ */
int high_fan_in_pattern(int input)
{
    int state = 0;
    int result = 0;

    while (state != 0xFF)
    {
        // This switch becomes a dispatcher block with high fan-in
        // All case blocks will jump back here, creating many predecessors
        switch (state)
        {
        case 0:
            result += input;
            state = (input > 0) ? 1 : 2;
            break;
        case 1:
            result *= 2;
            state = 3;
            break;
        case 2:
            result -= 5;
            state = 4;
            break;
        case 3:
            result += 10;
            state = 5;
            break;
        case 4:
            result *= 3;
            state = 5;
            break;
        case 5:
            result /= 2;
            state = 6;
            break;
        case 6:
            result += 1;
            state = 7;
            break;
        case 7:
            result -= 1;
            state = 0xFF;
            break;
        default:
            state = 0xFF;
            break;
        }
    }

    return result;
}

/* ============================================================================
 * Pattern 2: State Comparison with Large Constants (Hodur-style)
 * Expected: STATE_COMPARISON, CONSTANT_FREQUENCY, BACK_EDGE
 * ============================================================================ */
int state_comparison_pattern(int input)
{
    // Use large 32-bit constants typical of Hodur obfuscation
    int32_t state = 0x6F5E1A2B; // Initial state (>0x10000)
    int result = input;

    while (1)
    {
        // Dispatcher block compares state against large constants
        if (state == 0x6F5E1A2B)
        {
            result += 5;
            state = 0x4C8D9E3F;
        }
        else if (state == 0x4C8D9E3F)
        {
            result *= 2;
            state = (result > 100) ? 0x89AB1234 : 0x5678CDEF;
        }
        else if (state == 0x89AB1234)
        {
            result -= 10;
            state = 0x12345678;
        }
        else if (state == 0x5678CDEF)
        {
            result += 20;
            state = 0x12345678;
        }
        else if (state == 0x12345678)
        {
            result /= 3;
            state = 0xDEADBEEF;
        }
        else if (state == 0xDEADBEEF)
        {
            result ^= 0x42;
            break; // Exit
        }
        else
        {
            break; // Unknown state
        }
    }

    return result;
}

/* ============================================================================
 * Pattern 3: Nested While Loop Pattern (Hodur-style)
 * Expected: NESTED_LOOP, LOOP_HEADER, BACK_EDGE, STATE_COMPARISON
 * ============================================================================ */
int nested_while_hodur_pattern(int input)
{
    int32_t state = 0x1A2B3C4D;
    int result = input;
    int outer_state = 1;

    // Outer while(1) loop
    while (outer_state)
    {
        // Inner while(1) loop (nested dispatcher)
        while (1)
        {
            // Nested while(1) with more levels
            while (1)
            {
                if (state == 0x1A2B3C4D)
                {
                    result += 1;
                    state = 0x2E3F4A5B;
                    break;
                }
                else if (state == 0x2E3F4A5B)
                {
                    result *= 2;
                    state = 0x3C4D5E6F;
                    break;
                }
                else if (state == 0x3C4D5E6F)
                {
                    result -= 5;
                    state = 0x4A5B6C7D;
                    break;
                }
                else
                {
                    break;
                }
            }

            if (state == 0x4A5B6C7D)
            {
                result /= 2;
                state = 0x5B6C7D8E;
            }
            else if (state == 0x5B6C7D8E)
            {
                result += 10;
                state = 0x6C7D8E9F;
            }
            else if (state == 0x6C7D8E9F)
            {
                result ^= 0xFF;
                outer_state = 0;
                break;
            }
            else
            {
                break;
            }
        }
    }

    return result;
}

/* ============================================================================
 * Pattern 4: Simple Switch-Case Dispatcher (O-LLVM style)
 * Expected: SWITCH_JUMP, HIGH_FAN_IN
 * ============================================================================ */
int switch_case_ollvm_pattern(int input)
{
    int state = 0;
    int result = 0;

    // O-LLVM style with explicit switch (will generate jtbl in microcode)
    while (state != 100)
    {
        switch (state)
        {
        case 0:
            result = input + 5;
            state = 1;
            break;
        case 1:
            result *= 2;
            state = (result > 50) ? 2 : 3;
            break;
        case 2:
            result -= 10;
            state = 4;
            break;
        case 3:
            result += 15;
            state = 4;
            break;
        case 4:
            result /= 2;
            state = 5;
            break;
        case 5:
            result ^= 0x42;
            state = 6;
            break;
        case 6:
            result += result >> 2;
            state = 7;
            break;
        case 7:
            result -= 3;
            state = 100;
            break;
        default:
            state = 100;
            break;
        }
    }

    return result;
}

/* ============================================================================
 * Pattern 5: Mixed Pattern (Combines Multiple Strategies)
 * Expected: Multiple flags - HIGH_FAN_IN, STATE_COMPARISON, LOOP_HEADER, SMALL_BLOCK
 * ============================================================================ */
int mixed_dispatcher_pattern(int x, int y)
{
    int32_t state = 0xABCD1234;
    int result = x + y;

    // Outer loop creates back-edges
    while (1)
    {
        // Dispatcher comparing large constants (STATE_COMPARISON)
        // Multiple predecessors from all cases below (HIGH_FAN_IN)
        // Small tight loop (SMALL_BLOCK)
        if (state == 0xABCD1234)
        {
            result += 10;
            state = (result > 100) ? 0x12345678 : 0x9ABCDEF0;
        }
        else if (state == 0x12345678)
        {
            result *= 2;
            state = 0x23456789;
        }
        else if (state == 0x23456789)
        {
            result -= 5;
            state = 0x3456789A;
        }
        else if (state == 0x3456789A)
        {
            result /= 3;
            state = 0x456789AB;
        }
        else if (state == 0x456789AB)
        {
            result += 7;
            state = 0x56789ABC;
        }
        else if (state == 0x56789ABC)
        {
            result ^= 0xDEAD;
            state = 0x6789ABCD;
        }
        else if (state == 0x6789ABCD)
        {
            result &= 0xFFFF;
            state = 0x789ABCDE;
        }
        else if (state == 0x789ABCDE)
        {
            result |= 0x1000;
            state = 0x9ABCDEF0;
        }
        else if (state == 0x9ABCDEF0)
        {
            result -= 1;
            if (result < 50)
            {
                break; // Exit condition
            }
            state = 0xABCD1234; // Loop back
        }
        else
        {
            break; // Unknown state
        }
    }

    return result;
}

/* ============================================================================
 * Pattern 6: Predecessor Uniformity Test
 * Expected: PREDECESSOR_UNIFORM, HIGH_FAN_IN
 * Most predecessors are unconditional jumps (goto blocks)
 * ============================================================================ */
int predecessor_uniformity_pattern(int input)
{
    int state = 0;
    int result = input;

    // All case blocks end with unconditional jumps to dispatcher
    while (state != 10)
    {
        switch (state)
        {
        case 0:
            result += 1;
            state = 1;
            break; // Unconditional jump
        case 1:
            result += 2;
            state = 2;
            break;
        case 2:
            result += 3;
            state = 3;
            break;
        case 3:
            result += 4;
            state = 4;
            break;
        case 4:
            result += 5;
            state = 5;
            break;
        case 5:
            result += 6;
            state = 6;
            break;
        case 6:
            result += 7;
            state = 7;
            break;
        case 7:
            result += 8;
            state = 8;
            break;
        case 8:
            result += 9;
            state = 9;
            break;
        case 9:
            result += 10;
            state = 10;
            break;
        default:
            state = 10;
            break;
        }
    }

    return result;
}

/* ============================================================================
 * Test harness - calls all patterns
 * ============================================================================ */
int test_all_patterns(void)
{
    int r1 = high_fan_in_pattern(42);
    int r2 = state_comparison_pattern(100);
    int r3 = nested_while_hodur_pattern(50);
    int r4 = switch_case_ollvm_pattern(25);
    int r5 = mixed_dispatcher_pattern(10, 20);
    int r6 = predecessor_uniformity_pattern(5);

    return r1 + r2 + r3 + r4 + r5 + r6;
}
