/**
 * Exception Path Test Cases
 *
 * This sample tests edge cases and exception handling paths in
 * GenericDispatcherUnflatteningRule:
 *
 *   - NotResolvableFatherException: State cannot be resolved to a constant
 *   - NotDuplicableFatherException: Path cannot be safely duplicated
 *   - Deep path duplication (tests DEFAULT_MAX_DUPLICATION_PASSES = 20)
 *   - Unresolvable indirect state transitions
 */

#include "ida_types.h"

/* External functions to prevent optimization and create unresolvable paths */
extern int get_external_value(void);
extern int external_transform(int x);
extern void external_side_effect(int x);

/**
 * Unresolvable state from external source
 *
 * Tests NotResolvableFatherException - state comes from external
 * function that cannot be statically resolved.
 */
int unresolvable_external(int input)
{
    int state = get_external_value();  /* Can't resolve - external source */
    int result = input;

    while (1)
    {
        switch (state)
        {
        case 0:
            result = result + 10;
            state = 1;
            break;

        case 1:
            result = result * 2;
            state = 2;
            break;

        case 2:
            return result;

        default:
            /* Unknown state from external - partially unresolvable */
            result = result ^ 0xFF;
            state = (state + 1) % 3;  /* Try to recover */
            break;
        }
    }
}

/**
 * Unresolvable computed state
 *
 * State is computed from input in a way that prevents static resolution.
 */
int unresolvable_computed(int input, int key)
{
    /* State depends on runtime values - partially unresolvable */
    int state = (input ^ key) % 5;
    int result = 0;

    while (1)
    {
        switch (state)
        {
        case 0:
            result = input + 1;
            state = 1;
            break;

        case 1:
            result = result + 2;
            state = 2;
            break;

        case 2:
            result = result + 3;
            state = 3;
            break;

        case 3:
            result = result + 4;
            state = 4;
            break;

        case 4:
            return result;

        default:
            return -1;
        }
    }
}

/**
 * Non-duplicable path with side effects
 *
 * Tests NotDuplicableFatherException - path contains side effects
 * that prevent safe duplication.
 */
int non_duplicable_side_effects(int input)
{
    int state = 0;
    int result = input;

    while (1)
    {
        /* Side effect before dispatcher - can't be safely duplicated */
        external_side_effect(result);

        switch (state)
        {
        case 0:
            result = result + 10;
            state = 1;
            break;

        case 1:
            /* Another side effect in the middle */
            external_side_effect(result);
            result = result * 2;
            state = 2;
            break;

        case 2:
            result = result - 5;
            state = 3;
            break;

        case 3:
            return result;

        default:
            return -1;
        }
    }
}

/**
 * Deep path requiring many duplication passes
 *
 * Tests DEFAULT_MAX_DUPLICATION_PASSES (20) limit.
 * The path chains through many states before resolution.
 */
int deep_duplication_path(int input)
{
    int state = 0;
    int result = input;
    int counter = 0;

    while (1)
    {
        switch (state)
        {
        /* Chain of 25 states - exceeds DEFAULT_MAX_DUPLICATION_PASSES */
        case 0:  result++; state = 1; break;
        case 1:  result++; state = 2; break;
        case 2:  result++; state = 3; break;
        case 3:  result++; state = 4; break;
        case 4:  result++; state = 5; break;
        case 5:  result++; state = 6; break;
        case 6:  result++; state = 7; break;
        case 7:  result++; state = 8; break;
        case 8:  result++; state = 9; break;
        case 9:  result++; state = 10; break;
        case 10: result++; state = 11; break;
        case 11: result++; state = 12; break;
        case 12: result++; state = 13; break;
        case 13: result++; state = 14; break;
        case 14: result++; state = 15; break;
        case 15: result++; state = 16; break;
        case 16: result++; state = 17; break;
        case 17: result++; state = 18; break;
        case 18: result++; state = 19; break;
        case 19: result++; state = 20; break;
        case 20: result++; state = 21; break;
        case 21: result++; state = 22; break;
        case 22: result++; state = 23; break;
        case 23: result++; state = 24; break;
        case 24: result++; state = 25; break;
        case 25:
            return result;

        default:
            return -1;
        }
    }
}

/**
 * Loop-dependent state transition
 *
 * State depends on loop iteration count - creates partial resolution.
 */
int loop_dependent_state(int input, int iterations)
{
    int state = 0;
    int result = input;
    int i;

    while (1)
    {
        switch (state)
        {
        case 0:  /* Entry */
            i = 0;
            state = 1;
            break;

        case 1:  /* Loop check */
            if (i < iterations)
            {
                state = 2;  /* Continue loop */
            }
            else
            {
                state = 3;  /* Exit loop */
            }
            break;

        case 2:  /* Loop body */
            result = result + i;
            i++;
            state = 1;  /* Back to loop check */
            break;

        case 3:  /* Exit */
            return result;

        default:
            return -1;
        }
    }
}

/**
 * Indirect state via pointer
 *
 * State is loaded through a pointer - tests indirect dispatcher patterns.
 */
int indirect_state_pointer(int input, int *state_ptr)
{
    int result = input;

    while (1)
    {
        /* Indirect state load - harder to resolve */
        switch (*state_ptr)
        {
        case 0:
            result = result + 10;
            *state_ptr = 1;
            break;

        case 1:
            result = result * 2;
            *state_ptr = 2;
            break;

        case 2:
            return result;

        default:
            *state_ptr = 2;  /* Force exit */
            break;
        }
    }
}

/**
 * State transition via external transform
 *
 * State is modified by external function - fully unresolvable.
 */
int external_transform_state(int input)
{
    int state = 0;
    int result = input;

    while (1)
    {
        switch (state)
        {
        case 0:
            result = result + 10;
            state = external_transform(state);  /* Can't resolve */
            break;

        case 1:
            result = result * 2;
            state = external_transform(state);
            break;

        case 2:
            return result;

        default:
            /* External function might return any value */
            if (state > 2)
            {
                return result;
            }
            state = 0;  /* Reset */
            break;
        }
    }
}
