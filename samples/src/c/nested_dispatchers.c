/**
 * Nested Dispatcher Pattern Test
 *
 * This sample tests the sub-dispatcher detection and removal logic in
 * GenericDispatcherUnflatteningRule. It contains nested while-switch
 * structures where inner dispatchers are embedded within outer ones.
 *
 * Tests:
 *   - is_sub_dispatcher() detection
 *   - remove_sub_dispatchers() filtering
 *   - get_shared_internal_blocks() identification
 */

#include "ida_types.h"

/* External to prevent inlining */
extern int external_condition(int x);

/**
 * Simple nested dispatcher
 *
 * Outer dispatcher controls overall flow, inner dispatcher handles
 * a specific processing phase.
 */
int nested_simple(int input)
{
    int outer_state = 0;
    int inner_state = 0;
    int result = input;

    /* Outer dispatcher */
    while (1)
    {
        switch (outer_state)
        {
        case 0:  /* Outer: Initialize */
            result = result + 100;
            outer_state = 1;
            inner_state = 0;  /* Reset inner state */
            break;

        case 1:  /* Outer: Inner processing phase */
            /* Inner dispatcher - tests sub-dispatcher detection */
            switch (inner_state)
            {
            case 0:  /* Inner: Step 1 */
                result = result * 2;
                inner_state = 1;
                break;

            case 1:  /* Inner: Step 2 */
                result = result - 50;
                inner_state = 2;
                break;

            case 2:  /* Inner: Exit to outer */
                outer_state = 2;  /* Advance outer state */
                break;

            default:
                inner_state = 2;  /* Force inner exit */
                break;
            }
            break;

        case 2:  /* Outer: Finalize */
            result = result / 2;
            outer_state = 3;
            break;

        case 3:  /* Outer: Exit */
            return result;

        default:
            return -1;
        }
    }
}

/**
 * Deeply nested dispatchers (3 levels)
 *
 * Tests handling of multiple nesting levels:
 * L1 -> L2 -> L3 dispatch chains
 */
int nested_deep(int input, int depth)
{
    int L1_state = 0;
    int L2_state = 0;
    int L3_state = 0;
    int result = input;

    /* Level 1 dispatcher */
    while (1)
    {
        switch (L1_state)
        {
        case 0:  /* L1: Start */
            if (depth >= 1)
            {
                L1_state = 1;  /* Enter L2 */
                L2_state = 0;
            }
            else
            {
                L1_state = 9;  /* Skip to exit */
            }
            break;

        case 1:  /* L1: Run L2 dispatcher */
            /* Level 2 dispatcher */
            switch (L2_state)
            {
            case 0:  /* L2: Start */
                result = result + 10;
                if (depth >= 2)
                {
                    L2_state = 1;  /* Enter L3 */
                    L3_state = 0;
                }
                else
                {
                    L2_state = 9;  /* L2 exit */
                }
                break;

            case 1:  /* L2: Run L3 dispatcher */
                /* Level 3 dispatcher */
                switch (L3_state)
                {
                case 0:
                    result = result * 2;
                    L3_state = 1;
                    break;

                case 1:
                    result = result - 5;
                    L3_state = 2;
                    break;

                case 2:  /* L3 exit */
                    L2_state = 9;
                    break;

                default:
                    L3_state = 2;
                    break;
                }
                break;

            case 9:  /* L2: Exit */
                L1_state = 9;
                break;

            default:
                L2_state = 9;
                break;
            }
            break;

        case 9:  /* L1: Exit */
            return result;

        default:
            return -1;
        }
    }
}

/**
 * Parallel nested dispatchers
 *
 * Tests handling of sibling dispatchers at the same nesting level
 */
int nested_parallel(int input, int path)
{
    int outer_state = 0;
    int inner_a_state = 0;
    int inner_b_state = 0;
    int result = input;

    while (1)
    {
        switch (outer_state)
        {
        case 0:  /* Entry: Choose path */
            if (path == 0)
            {
                outer_state = 1;  /* Path A */
                inner_a_state = 0;
            }
            else
            {
                outer_state = 2;  /* Path B */
                inner_b_state = 0;
            }
            break;

        case 1:  /* Path A: Inner dispatcher A */
            switch (inner_a_state)
            {
            case 0:
                result = result + 100;
                inner_a_state = 1;
                break;
            case 1:
                result = result * 3;
                inner_a_state = 2;
                break;
            case 2:
                outer_state = 3;  /* Exit to merge point */
                break;
            default:
                inner_a_state = 2;
                break;
            }
            break;

        case 2:  /* Path B: Inner dispatcher B */
            switch (inner_b_state)
            {
            case 0:
                result = result - 50;
                inner_b_state = 1;
                break;
            case 1:
                result = result / 2;
                inner_b_state = 2;
                break;
            case 2:
                outer_state = 3;  /* Exit to merge point */
                break;
            default:
                inner_b_state = 2;
                break;
            }
            break;

        case 3:  /* Merge and exit */
            return result;

        default:
            return -1;
        }
    }
}

/**
 * Dispatcher with shared blocks
 *
 * Tests get_shared_internal_blocks() - multiple dispatchers
 * share some internal processing blocks
 */
int nested_shared_blocks(int input)
{
    int state = 0;
    int result = input;
    int sub_state = 0;

    while (1)
    {
        switch (state)
        {
        case 0:  /* Entry */
            result = result + 1;
            state = 1;
            break;

        case 1:  /* Shared processing block */
            /* This block is "shared" - reachable from multiple paths */
            result = result * 2;

            /* Sub-dispatcher decides next step */
            switch (sub_state)
            {
            case 0:
                sub_state = 1;
                state = 2;  /* Go to state 2 */
                break;
            case 1:
                sub_state = 0;
                state = 3;  /* Go to state 3 */
                break;
            default:
                state = 4;  /* Exit */
                break;
            }
            break;

        case 2:  /* Processing A */
            result = result + 10;
            state = 1;  /* Return to shared block */
            break;

        case 3:  /* Processing B */
            result = result - 5;
            state = 1;  /* Return to shared block */
            break;

        case 4:  /* Exit */
            return result;

        default:
            return -1;
        }
    }
}
