/**
 * unsafe_unflattener_test.c - Test case for UnflattenerFakeJump safety check.
 *
 * This function is designed to trigger the UNSAFE scenario where:
 * - MopTracker resolves some backward paths but not others
 * - The unresolved paths have DIFFERENT state values than resolved paths
 * - Ignoring unresolved paths would lead to INCORRECT CFG modification
 *
 * The Critical Scenario:
 * ======================
 * Consider a dispatcher block checking: if (state == 0xDEAD0003)
 *
 * Predecessor block B has TWO outgoing state assignments:
 *   - Path 1 (resolved):   state = 0xDEAD0001  -> jump NOT taken (go to else)
 *   - Path 2 (unresolved): state = 0xDEAD0003  -> jump TAKEN (go to if-body)
 *
 * If UnflattenerFakeJump only considers the RESOLVED path (0xDEAD0001),
 * it would incorrectly conclude the jump is NEVER taken and redirect
 * block B to always go to the else branch.
 *
 * But this is WRONG! The unresolved path sets state = 0xDEAD0003, which
 * WOULD take the jump. By ignoring this path, we break the CFG.
 *
 * Expected Behavior:
 * - UnflattenerFakeJump should detect that unresolved paths exist
 * - The rule should NOT fire when unresolved paths could have different outcomes
 * - CFG should remain correct
 *
 * Test Function Behavior:
 * - Input <= 0: Returns 0 (immediate exit)
 * - Input 1-10: Loops (input) times, accumulating result, returns result + input
 * - Input > 10: Executes once, multiplies by 2, returns result * 2
 */

#include <stdint.h>

// Force no inlining so the function is preserved
#if defined(__clang__) || defined(__GNUC__)
#define NOINLINE __attribute__((noinline))
#elif defined(_MSC_VER)
#define NOINLINE __declspec(noinline)
#else
#define NOINLINE
#endif

// State constants - easily identifiable in disassembly
#define STATE_INIT      0xDEAD0001
#define STATE_LOOP_BODY 0xDEAD0002
#define STATE_LOOP_CHECK 0xDEAD0003
#define STATE_FINAL     0xDEAD0004
#define STATE_EXIT      0xDEAD0005

/**
 * unsafe_unflattener_test - Flattened function with unsafe path scenario
 *
 * This function has a loop back-edge that creates an unresolved path.
 * The key unsafe pattern is in STATE_LOOP_CHECK:
 *
 *   STATE_LOOP_CHECK has two incoming paths:
 *     1. From STATE_LOOP_BODY (after loop iteration) - sets counter, loops back
 *     2. From initial entry (first iteration)
 *
 *   The back-edge from LOOP_BODY to LOOP_CHECK creates a cycle that
 *   MopTracker may not fully resolve, leading to the unsafe scenario.
 *
 * Control Flow (when input is in range 1-10):
 *   INIT -> LOOP_BODY -> LOOP_CHECK -> (if counter > 0) -> LOOP_BODY -> ...
 *                                   -> (if counter <= 0) -> FINAL -> EXIT
 */
NOINLINE int unsafe_unflattener_test(int input) {
    // State variable for flattened control flow
    uint32_t state = STATE_INIT;

    // Working variables
    int result = 0;
    int counter = 0;

    // Dispatcher loop
    while (1) {
        // Dispatcher: Check state against each possible value
        // This creates the characteristic jz/jnz pattern

        if (state == STATE_INIT) {
            // Initial block: Set up based on input
            if (input <= 0) {
                // Early exit path
                state = STATE_EXIT;
            } else if (input > 10) {
                // Single execution path (no loop)
                result = input * 2;
                state = STATE_FINAL;
            } else {
                // Loop path - this is where the unsafe scenario occurs
                counter = input;
                result = 0;
                state = STATE_LOOP_BODY;
            }
        }
        else if (state == STATE_LOOP_BODY) {
            // Loop body: Accumulate result
            // This block ALWAYS transitions to STATE_LOOP_CHECK
            result += counter;
            counter--;
            state = STATE_LOOP_CHECK;
        }
        else if (state == STATE_LOOP_CHECK) {
            /**
             * CRITICAL BLOCK FOR UNSAFE SCENARIO
             * ==================================
             * This block has multiple predecessors with different state values:
             *
             * Incoming edges:
             *   1. From STATE_LOOP_BODY: state = STATE_LOOP_CHECK (resolved)
             *   2. Back-edge from previous iteration (may be unresolved)
             *
             * The back-edge creates a cycle. When MopTracker analyzes
             * predecessors of the dispatcher block checking state == STATE_LOOP_BODY,
             * it may:
             *   - Resolve the direct edge from STATE_LOOP_CHECK (state = STATE_LOOP_BODY)
             *   - NOT resolve the back-edge (cycle in CFG)
             *
             * If the check is: if (state == STATE_LOOP_BODY)
             *   - Resolved path says: state = STATE_LOOP_CHECK -> NOT taken
             *   - Unresolved path (back-edge) actually has: state = STATE_LOOP_BODY -> TAKEN
             *
             * Incorrectly ignoring the unresolved path would break the loop!
             */
            if (counter > 0) {
                // Continue loop - GO BACK to loop body
                // This creates the back-edge that may not be resolved
                state = STATE_LOOP_BODY;
            } else {
                // Exit loop - proceed to final block
                state = STATE_FINAL;
            }
        }
        else if (state == STATE_FINAL) {
            // Final processing before exit
            result += input;  // Add original input to result
            state = STATE_EXIT;
        }
        else {
            // STATE_EXIT or unknown state - break out
            break;
        }
    }

    return result;
}

/**
 * unsafe_unflattener_test2 - More complex unsafe scenario with nested conditionals
 *
 * This variant has MULTIPLE back-edges and conditional state transitions,
 * making it even harder for MopTracker to resolve all paths.
 */
NOINLINE int unsafe_unflattener_test2(int a, int b) {
    uint32_t state = STATE_INIT;
    int result = 0;
    int i = 0;
    int j = 0;

    while (1) {
        if (state == STATE_INIT) {
            // Initial setup
            i = a;
            j = b;
            result = 0;

            if (a <= 0 || b <= 0) {
                state = STATE_EXIT;
            } else {
                state = STATE_LOOP_BODY;
            }
        }
        else if (state == STATE_LOOP_BODY) {
            /**
             * UNSAFE SCENARIO 2: Multiple conditional state transitions
             *
             * This block can transition to THREE different states:
             *   1. STATE_LOOP_CHECK (when j > 0)
             *   2. STATE_FINAL (when j <= 0 and i <= 0)
             *   3. STATE_LOOP_BODY (when j <= 0 and i > 0) - BACK-EDGE
             *
             * The back-edge to itself creates an unresolved path.
             * MopTracker may only resolve some of these transitions.
             */
            result += i * j;

            if (j > 0) {
                j--;
                state = STATE_LOOP_CHECK;
            } else {
                // Inner loop finished, check outer counter
                i--;
                if (i > 0) {
                    // Reset inner counter and continue - BACK-EDGE
                    j = b;
                    state = STATE_LOOP_BODY;  // Back to self!
                } else {
                    // Both loops done
                    state = STATE_FINAL;
                }
            }
        }
        else if (state == STATE_LOOP_CHECK) {
            /**
             * Another check point that can go multiple ways
             */
            if (j > 0) {
                // Continue inner loop
                state = STATE_LOOP_BODY;
            } else {
                // Inner loop complete
                state = STATE_FINAL;
            }
        }
        else if (state == STATE_FINAL) {
            result = result + a + b;
            state = STATE_EXIT;
        }
        else {
            break;
        }
    }

    return result;
}

/**
 * unsafe_unflattener_test3 - Unsafe scenario with data-dependent state
 *
 * The state transition depends on COMPUTED values, not just loop counters.
 * This makes path resolution even harder.
 */
NOINLINE int unsafe_unflattener_test3(int input, int threshold) {
    uint32_t state = STATE_INIT;
    int value = input;
    int result = 0;

    while (1) {
        if (state == STATE_INIT) {
            if (input <= 0) {
                state = STATE_EXIT;
            } else {
                state = STATE_LOOP_BODY;
            }
        }
        else if (state == STATE_LOOP_BODY) {
            /**
             * UNSAFE SCENARIO 3: Data-dependent state transition
             *
             * The next state depends on a COMPUTED value (value % threshold).
             * MopTracker cannot statically determine this, creating
             * unresolved paths with different outcomes.
             *
             * Path 1: value > threshold -> STATE_LOOP_CHECK, subtract threshold
             * Path 2: value <= threshold -> STATE_FINAL
             *
             * The value changes each iteration, so the same code path
             * can have DIFFERENT state outcomes at runtime.
             */
            result += value;

            if (value > threshold) {
                value -= threshold;
                // Check if we should continue or switch to different path
                if ((value & 1) == 0) {
                    state = STATE_LOOP_CHECK;
                } else {
                    // Odd value - continue in loop body (back-edge)
                    state = STATE_LOOP_BODY;
                }
            } else {
                state = STATE_FINAL;
            }
        }
        else if (state == STATE_LOOP_CHECK) {
            /**
             * Additional check that creates more path complexity
             */
            if (value > 0) {
                // Another back-edge
                state = STATE_LOOP_BODY;
            } else {
                state = STATE_FINAL;
            }
        }
        else if (state == STATE_FINAL) {
            result *= 2;
            state = STATE_EXIT;
        }
        else {
            break;
        }
    }

    return result;
}

/*
 * Summary of Unsafe Scenarios:
 * ============================
 *
 * 1. unsafe_unflattener_test:
 *    - Simple loop with back-edge
 *    - STATE_LOOP_CHECK -> STATE_LOOP_BODY creates cycle
 *    - Unresolved back-edge has state = STATE_LOOP_BODY
 *    - Resolved forward edge has state = STATE_LOOP_CHECK
 *
 * 2. unsafe_unflattener_test2:
 *    - Nested loop with multiple back-edges
 *    - STATE_LOOP_BODY can go to self (back-edge)
 *    - Multiple conditional transitions make resolution harder
 *
 * 3. unsafe_unflattener_test3:
 *    - Data-dependent state transitions
 *    - Same code path has different outcomes based on computed values
 *    - MopTracker cannot resolve data-dependent conditions
 *
 * In all cases, if UnflattenerFakeJump ignores unresolved paths,
 * it would make incorrect assumptions about which state values are
 * possible, leading to broken control flow.
 *
 * The correct behavior is to BAIL OUT when unresolved paths exist
 * that could have different outcomes than the resolved paths.
 */
