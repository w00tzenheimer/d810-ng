

int test_chained_add(int *a) {
  return (((a[0] + 23) + a[2]) -
          (-a[1] + (-17 - (12 + ((a[1] - a[0]) + ~a[2])))));
}

int test_cst_simplification(int *a) {
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

int test_opaque_predicate(volatile int *a) {
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

long test_xor(long a, long b, long c, long *d) {
  d[0] = (a + b) - 2 * (a & b);
  d[1] = (a * c + (b - 3)) - 2 * ((a * c) & (b - 3));
  return d[0] + d[1];
}

long test_mba_guessing(long a, long b, long c, long d) {
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