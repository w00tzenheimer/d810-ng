/**
 * mba_hard.c - MBA patterns that IDA Pro 9+ cannot simplify natively
 *
 * These patterns are verified with Z3 SMT solver to be equivalent
 * to their simplified forms, but IDA's template-based simplification
 * cannot handle them.
 */

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __attribute__((visibility("default")))
#endif

/**
 * Pattern 1: Multi-layer nested XOR MBA
 *
 * Layer 1: (a + b) - 2*(a & b) = a ^ b
 * Layer 2: (layer1 + c) - 2*(layer1 & c) = layer1 ^ c = a ^ b ^ c
 *
 * Expected result: a ^ b ^ c
 */
EXPORT long test_multilayer_xor(long a, long b, long c, long *out) {
    // First layer: XOR MBA for a ^ b
    long layer1 = (a + b) - 2 * (a & b);
    // Second layer: XOR MBA using layer1 result
    out[0] = (layer1 + c) - 2 * (layer1 & c);
    return out[0];
}

/**
 * Pattern 2: MBA with complex arithmetic subexpressions
 *
 * Pattern: ((2*a + 1) + (b - 3)) - 2*((2*a + 1) & (b - 3))
 * Result: (2*a + 1) ^ (b - 3)
 *
 * IDA cannot simplify because operands are complex expressions, not variables.
 */
EXPORT long test_complex_operand_xor(long a, long b, long *out) {
    long expr1 = 2 * a + 1;
    long expr2 = b - 3;
    out[0] = (expr1 + expr2) - 2 * (expr1 & expr2);
    return out[0];
}

/**
 * Pattern 3: HODUR-style constrained constants
 *
 * Pattern: ((c_0 - x) & ~z) ^ ((x - c_3) & z)
 * Constraint: c_0 + 1 == c_3
 * Result: ~((x - c_3) ^ z)
 *
 * IDA cannot verify the algebraic relationship between constants.
 */
EXPORT long test_hodur_constraint(long x, long z, long *out) {
    long c_0 = 0x1C;
    long c_3 = 0x1D;  // c_0 + 1
    out[0] = ((c_0 - x) & ~z) ^ ((x - c_3) & z);
    return out[0];
}

/**
 * Pattern 4: Nested OR via two MBA layers
 *
 * Layer 1: (a & b) + (a ^ b) = a | b
 * Layer 2: (layer1 & c) + (layer1 ^ c) = layer1 | c = a | b | c
 *
 * Expected result: a | b | c
 */
EXPORT long test_nested_or(long a, long b, long c, long *out) {
    // First layer: OR MBA for a | b
    long layer1 = (a & b) + (a ^ b);
    // Second layer: OR MBA using layer1 result
    out[0] = (layer1 & c) + (layer1 ^ c);
    return out[0];
}

/**
 * Pattern 5: 3-variable WeirdRule5 identity
 *
 * Pattern: ((~x | (~y & z)) + (x + (y & z))) - z
 * Result: x | (y | ~z)
 *
 * This is a complex 3-variable identity not in IDA's template library.
 */
EXPORT long test_3var_weird(long x, long y, long z, long *out) {
    out[0] = ((~x | (~y & z)) + (x + (y & z))) - z;
    return out[0];
}

/**
 * Pattern 6: Chained XOR through temps (cross-instruction)
 *
 * This tests if the optimizer can track through temporary variables
 * to reconstruct: t1 + 2*t2 = a + b when t1 = a ^ b, t2 = a & b
 */
EXPORT long test_chained_temps(long a, long b, long *out) {
    long t1 = a ^ b;
    long t2 = a & b;
    out[0] = t1 + 2 * t2;  // Should simplify to a + b
    return out[0];
}
