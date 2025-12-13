#include "export.h"

EXPORT int test_chained_add(int *a) {
  return (((a[0] + 23) + a[2]) -
          (-a[1] + (-17 - (12 + ((a[1] - a[0]) + ~a[2])))));
}

EXPORT int test_cst_simplification(int *a) {
  int a1 = ((a[0] & 0x3) | 0x222E69C2) - ((a[0] & 0x3) | 0x2);
  a[1] = a1;
  int a2 =
      ((a[1] & 0x50211120) | 0x83020001) + ((a[1] & 0x50211120) ^ 0x50295930);
  a[2] = a2;
  int a3 =
      (((~a[2] & 0x10500855) | 0x5204000) + ((a[2] & 0x10500855) | 0x2009500)) ^
      0x15482637;
  a[3] = a3;
  int a4 = ((((a[3] + 0x4) - (a3 | 0x4)) & 0x7FFFFC) >> 2) | 0xA29;
  a[4] = a4;
  return a1 + a2 + a3 + a4;
}

EXPORT int test_opaque_predicate(volatile int *a) {
  if ((a[0] * (a[0] + 1)) % 2 != 0) {
    return 91;
  }
  int a1 = (int)((a[1] * (a[1] - 1)) % 2 == 0);
  int a2 = (int)(((a[1] & a[2]) | (~a[1] & ~a[2])) != ~(a[1] ^ a[2]));
  int a3 = (int)(((a[3] | a[4]) - (a[3] & a[4])) != (a[3] ^ a[4]));
  int a4 = (int)((a[4] & 0x23) == 0x1);
  int a5 = (int)((a[6] & 0x42) != 0x2);
  a[1] = a1;
  a[2] = a2;
  a[3] = a3;
  a[4] = a4;
  a[5] = a5;
  return 12 + 3 * a1 + 5 * a2 + 7 * a3 + 9 * a4 + 11 * a5;
}

EXPORT long test_xor(long a, long b, long c, long *d) {
  d[0] = (a + b) - 2 * (a & b);
  d[1] = (a * c + (b - 3)) - 2 * ((a * c) & (b - 3));
  return d[0] + d[1];
}

EXPORT long test_or(long a, long b, long c, long *d) {
  // MBA pattern for OR: (a & b) + (a ^ b) => a | b
  d[0] = (a & b) + (a ^ b);
  d[1] = (b & c) + (b ^ c);
  d[2] = ((a + 1) & (b - 2)) + ((a + 1) ^ (b - 2));
  return d[0] + d[1] + d[2];
}

EXPORT long test_and(long a, long b, long c, long *d) {
  // MBA pattern for AND: (a | b) - (a ^ b) => a & b
  d[0] = (a | b) - (a ^ b);
  d[1] = (b | c) - (b ^ c);
  d[2] = ((a * 2) | (b + c)) - ((a * 2) ^ (b + c));
  return d[0] + d[1] + d[2];
}

EXPORT long test_neg(long a, long *d) {
  // Negation pattern: -x can be expressed as ~x + 1 (two's complement)
  d[0] = ~a + 1;
  d[1] = ~(a + 5) + 1;
  d[2] = ~(a * 2) + 1;
  return d[0] + d[1] + d[2];
}

EXPORT long test_mba_guessing(long a, long b, long c, long d) {
  return (((((~(((a ^ ~d) + ((a | d) + (a | d))) + 1) | a) +
             (((a ^ ~d) + ((a | d) + (a | d))) + 1)) +
            1) -
           ((a ^ c) + ((a & c) + (a & c)))) -
          (((((~(((a ^ ~d) + ((a | d) + (a | d))) + 1) | a) +
              (((a ^ ~d) + ((a | d) + (a | d))) + 1)) +
             1) |
            ~((a ^ c) + ((a & c) + (a & c)))) +
           ((((~(((a ^ ~d) + ((a | d) + (a | d))) + 1) | a) +
              (((a ^ ~d) + ((a | d) + (a | d))) + 1)) +
             1) |
            ~((a ^ c) + ((a & c) + (a & c)))))) -
         2;
}

// ============================================================================
// Hard MBA patterns that IDA Pro 9+ cannot simplify natively
// ============================================================================

/**
 * Multi-layer nested XOR MBA
 * Layer 1: (a + b) - 2*(a & b) = a ^ b
 * Layer 2: (layer1 + c) - 2*(layer1 & c) = a ^ b ^ c
 */
EXPORT long test_multilayer_xor(long a, long b, long c, long *out) {
    long layer1 = (a + b) - 2 * (a & b);
    out[0] = (layer1 + c) - 2 * (layer1 & c);
    return out[0];
}

/**
 * Nested OR via two MBA layers
 * Layer 1: (a & b) + (a ^ b) = a | b
 * Layer 2: (layer1 & c) + (layer1 ^ c) = a | b | c
 */
EXPORT long test_nested_or(long a, long b, long c, long *out) {
    long layer1 = (a & b) + (a ^ b);
    out[0] = (layer1 & c) + (layer1 ^ c);
    return out[0];
}

/**
 * Cross-instruction MBA through temps
 * t1 + 2*t2 = a + b when t1 = a ^ b, t2 = a & b
 */
EXPORT long test_chained_temps(long a, long b, long *out) {
    long t1 = a ^ b;
    long t2 = a & b;
    out[0] = t1 + 2 * t2;
    return out[0];
}