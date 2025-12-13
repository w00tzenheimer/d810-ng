/**
 * fake_jumps_complex.c - Complex patterns to trigger UnflattenerFakeJump
 *
 * These functions use more complex patterns that survive compiler optimization
 * but still result in fake jumps at the microcode level.
 */

#include <stdint.h>

#if defined(__clang__) || defined(__GNUC__)
#define NOINLINE __attribute__((noinline))
#define OPAQUE __attribute__((optnone))
#elif defined(_MSC_VER)
#define NOINLINE __declspec(noinline)
#define OPAQUE
#else
#define NOINLINE
#define OPAQUE
#endif

// Volatile variables to prevent constant propagation at source level
volatile int g_flag = 0;
volatile int g_state = 0;

/**
 * Test 1: Fake jump with volatile write followed by non-volatile read
 *
 * The compiler can't optimize the initial assignment through volatile,
 * but at microcode level after the write we know the value.
 */
NOINLINE int fake_jump_volatile_pattern(int a) {
    int local_state;

    // Write through volatile to prevent source-level optimization
    g_state = 123;

    // Read into local (non-volatile)
    local_state = g_state;

    // At microcode level, we should track that local_state is 123
    // But compiler won't optimize this away at source level
    int result = a;
    if (local_state == 123) {
        result += 100;
    } else {
        result += 200;  // Dead code at microcode level
    }

    return result;
}

/**
 * Test 2: Opaque predicate pattern (classic obfuscation technique)
 *
 * Uses mathematical identities that are always true/false.
 * The compiler won't optimize these due to optnone.
 */
OPAQUE NOINLINE int fake_jump_opaque_predicate(int x, int y) {
    int result = x + y;

    // Opaque predicate: (x - 1) * x is always even (divisible by 2)
    // So ((x - 1) * x) & 1 is always 0
    int predicate = ((x - 1) * x) & 1;

    // This check is always true (predicate is always 0)
    if (predicate == 0) {
        result *= 2;
    } else {
        result *= 3;  // Dead code
    }

    return result;
}

/**
 * Test 3: State machine with deterministic transitions
 *
 * Multiple paths all converge to the same state value.
 */
NOINLINE int fake_jump_state_machine(int a, int b, int c) {
    int state = 0;
    int result = 0;

    // Initial state assignment based on conditions
    if (a > 0) {
        state = 42;
        result = a;
    } else if (b > 0) {
        state = 42;  // Same value!
        result = b;
    } else {
        state = 42;  // All paths lead to 42
        result = c;
    }

    // This comparison should always be true
    if (state == 42) {
        result += 1000;
    } else {
        result += 2000;  // Dead code
    }

    return result;
}

/**
 * Test 4: Dispatcher-like pattern (simplified CFF)
 *
 * Simulates a control flow flattening dispatcher where
 * the state variable is deterministic.
 */
NOINLINE int fake_jump_dispatcher_like(int input) {
    int state = 100;  // Initial state
    int result = 0;

    // First "basic block" - always executes
    if (state == 100) {
        result += input;
        state = 200;
    }

    // Second "basic block" - fake jump because state is always 200
    if (state == 200) {
        result *= 2;
    } else {
        result *= 3;  // Dead code
    }

    return result;
}

/**
 * Test 5: Loop with invariant conditional
 *
 * A conditional inside the loop that's invariant across iterations.
 */
NOINLINE int fake_jump_loop_invariant(int n) {
    int result = 0;
    int loop_constant = 7;

    for (int i = 0; i < n; i++) {
        // This check is the same in every iteration
        if (loop_constant == 7) {
            result += i;
        } else {
            result += i * 2;  // Dead code
        }
    }

    return result;
}

/**
 * Test 6: Bitwise identity pattern
 *
 * Uses bitwise operations that result in deterministic values.
 */
NOINLINE int fake_jump_bitwise_identity(int x) {
    int result = x;

    // x ^ x is always 0
    int xor_result = x ^ x;

    // This check is always true
    if (xor_result == 0) {
        result += 50;
    } else {
        result += 100;  // Dead code
    }

    return result;
}

/**
 * Test 7: Comparison after masking
 *
 * A value is masked and then compared to an impossible value.
 */
NOINLINE int fake_jump_mask_comparison(int x) {
    int result = x;

    // Mask off all but lower 4 bits (result is 0-15)
    int masked = x & 0xF;

    // This comparison is always false (masked can't be > 20)
    if (masked > 20) {
        result += 200;  // Dead code
    } else {
        result += 300;
    }

    return result;
}

/**
 * Test 8: Self-assignment pattern
 *
 * Variable is assigned to itself through pointer aliasing.
 */
NOINLINE int fake_jump_self_assign(int x) {
    int state = 55;
    int *ptr = &state;

    // "Complex" assignment that's actually self-assignment
    *ptr = state;

    // State is still 55
    int result = x;
    if (state == 55) {
        result += 10;
    } else {
        result += 20;  // Dead code
    }

    return result;
}

/**
 * Test 9: Multiple fake jumps in CFG
 *
 * A function with several fake conditionals throughout.
 */
NOINLINE int fake_jump_multiple_cfg(int x) {
    int state = 1;
    int result = x;

    // First fake jump
    if (state == 1) {
        result += 10;
        state = 2;
    } else {
        result += 20;  // Dead
    }

    // Second fake jump
    if (state == 2) {
        result *= 2;
        state = 3;
    } else {
        result *= 3;  // Dead
    }

    // Third fake jump
    if (state == 3) {
        result += 5;
    } else {
        result += 15;  // Dead
    }

    return result;
}

/**
 * Test 10: Fake jump after function call with constant return
 *
 * Function always returns the same value.
 */
static int always_returns_99(void) {
    // Use volatile to prevent inlining optimization
    volatile int val = 99;
    return val;
}

NOINLINE int fake_jump_after_constant_call(int x) {
    int result = x;
    int val = always_returns_99();

    // Should be optimizable if we track the return value
    if (val == 99) {
        result += 7;
    } else {
        result += 8;  // Dead code
    }

    return result;
}
