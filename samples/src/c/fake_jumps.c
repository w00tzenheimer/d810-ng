/**
 * fake_jumps.c - Test cases for UnflattenerFakeJump optimizer
 *
 * These functions contain conditional jumps (jz/jnz) that are always taken
 * or never taken based on value analysis from predecessor blocks.
 * The UnflattenerFakeJump optimizer should detect and remove these fake jumps.
 */

#include <stdint.h>

// Force no inlining so each function is preserved
#if defined(__clang__) || defined(__GNUC__)
#define NOINLINE __attribute__((noinline))
#elif defined(_MSC_VER)
#define NOINLINE __declspec(noinline)
#else
#define NOINLINE
#endif

/**
 * Test 1: Conditional always true
 *
 * The comparison is always true because x is always set to 42,
 * so the if branch is always taken (jump never taken).
 */
NOINLINE int fake_jump_always_true(int a) {
    int x = 42;  // Always 42
    int result = a;

    // This comparison is always true (x == 42), so jump never taken
    if (x == 42) {
        result += 10;
    } else {
        result += 20;  // Dead code
    }

    return result;
}

/**
 * Test 2: Conditional always false
 *
 * The comparison is always false because y is set to 100,
 * so the if branch is never taken (jump always taken).
 */
NOINLINE int fake_jump_always_false(int a) {
    int y = 100;  // Always 100
    int result = a;

    // This comparison is always false (y != 100), so jump always taken
    if (y != 100) {
        result += 30;  // Dead code
    } else {
        result += 40;
    }

    return result;
}

/**
 * Test 3: Multiple fake jumps in sequence
 *
 * Chain of conditionals where all branches can be determined statically.
 */
NOINLINE int fake_jump_sequence(int a) {
    int x = 5;
    int result = a;

    // First fake jump - always true
    if (x == 5) {
        result += 1;
    } else {
        result += 2;  // Dead
    }

    // Second fake jump - always false
    if (x != 5) {
        result += 3;  // Dead
    } else {
        result += 4;
    }

    return result;
}

/**
 * Test 4: Fake jump with zero comparison (jz pattern)
 *
 * Classic jz pattern where value is always zero or always non-zero.
 */
NOINLINE int fake_jump_zero_check(int a) {
    int flag = 0;  // Always zero
    int result = a;

    // jz pattern - will always take the zero branch
    if (flag) {
        result += 100;  // Dead code
    } else {
        result += 200;
    }

    return result;
}

/**
 * Test 5: Fake jump with non-zero comparison (jnz pattern)
 *
 * Classic jnz pattern where value is always non-zero.
 */
NOINLINE int fake_jump_nonzero_check(int a) {
    int flag = 1;  // Always non-zero
    int result = a;

    // jnz pattern - will always take the non-zero branch
    if (flag) {
        result += 300;
    } else {
        result += 400;  // Dead code
    }

    return result;
}

/**
 * Test 6: Fake jump after arithmetic
 *
 * Value computed through arithmetic but still deterministic.
 */
NOINLINE int fake_jump_after_arithmetic(int a) {
    int x = 10;
    int y = 20;
    int sum = x + y;  // Always 30
    int result = a;

    // This comparison result is always known
    if (sum == 30) {
        result *= 2;
    } else {
        result *= 3;  // Dead code
    }

    return result;
}

/**
 * Test 7: Nested fake jumps
 *
 * Fake jumps inside control flow structures.
 */
NOINLINE int fake_jump_nested(int a, int b) {
    int x = 42;
    int result = a;

    if (a > 0) {
        // Inner fake jump - always true
        if (x == 42) {
            result += b;
        } else {
            result += b * 2;  // Dead code
        }
    }

    return result;
}

/**
 * Test 8: Fake jump in loop
 *
 * A fake jump that occurs inside a loop body.
 */
NOINLINE int fake_jump_in_loop(int n) {
    int result = 0;
    int constant = 7;  // Always 7

    for (int i = 0; i < n; i++) {
        // This check is always true in every iteration
        if (constant == 7) {
            result += i;
        } else {
            result += i * 2;  // Dead code
        }
    }

    return result;
}

/**
 * Test 9: Fake jump with bitwise comparison
 *
 * Using bitwise operations but still deterministic.
 */
NOINLINE int fake_jump_bitwise(int a) {
    int mask = 0xFF;  // Always 0xFF
    int result = a;

    // This bitwise comparison result is always known
    if ((mask & 0xFF) == 0xFF) {
        result += 50;
    } else {
        result += 60;  // Dead code
    }

    return result;
}

/**
 * Test 10: Complex fake jump with multiple predecessors
 *
 * Multiple paths converge, but all set the same value,
 * making the subsequent comparison deterministic.
 */
NOINLINE int fake_jump_multi_predecessor(int a, int b) {
    int state;
    int result;

    // All paths set state to the same value
    if (a > 0) {
        state = 123;  // Path 1
        result = a;
    } else {
        state = 123;  // Path 2 - same value!
        result = b;
    }

    // This comparison is always true regardless of which path was taken
    if (state == 123) {
        result += 777;
    } else {
        result += 888;  // Dead code
    }

    return result;
}

/**
 * Test 11: Fake jump with explicit goto (unusual pattern)
 *
 * Using goto to create explicit control flow with fake conditional.
 */
NOINLINE int fake_jump_with_goto(int a) {
    int x = 99;
    int result = a;

    // Check that's always true
    if (x != 99) {
        goto dead_branch;  // Never taken
    }

    result += 10;
    goto end;

dead_branch:
    result += 20;  // Dead code

end:
    return result;
}

/**
 * Test 12: Fake jump after function call result
 *
 * Even with a function call, if we track that the return is constant,
 * the jump can be determined. (Note: This tests more advanced tracking)
 */
static int always_returns_42(void) {
    return 42;
}

NOINLINE int fake_jump_after_call(int a) {
    int x = always_returns_42();  // Always 42
    int result = a;

    // If the optimizer tracks that always_returns_42() returns 42,
    // this comparison is deterministic
    if (x == 42) {
        result += 5;
    } else {
        result += 6;  // Dead code
    }

    return result;
}
