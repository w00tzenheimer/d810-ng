// test_function_ollvm_fla_bcf_sub - EXPECTED (ideal deobfuscated output)
// Address: 0x932c
//
// OLLVM obfuscation applied:
// - FLA (Control Flow Flattening): 8 nested while loops + 40 switch cases
// - BCF (Bogus Control Flow): Opaque predicates like (((x-1)*x) & 1) == 0
// - SUB (Instruction Substitution): MBA expressions
//
// The opaque predicates use:
//   ((((_BYTE)x - 1) * (_BYTE)x) & 1) == 0
// This is ALWAYS TRUE because (n-1)*n is always even (one of n or n-1 is even).
//
// The predicate (y < 0xA) depends on runtime value of global 'y'.

__int64 __fastcall test_function_ollvm_fla_bcf_sub(__int64 result, __int64 a2)
{
    char buffer[100];
    struct timeval tv;

    memset(buffer, 0, 100);
    gettimeofday(&tv, 0);

    // MBA-obfuscated constant computation (should fold)
    // Original: complex expression with 0xAFDEEEDF, 0x50211120, etc.
    // Simplified: some constant manipulation of tv.tv_sec

    printf("Please enter password:");
    scanf("%s", buffer);

    result = strncmp(buffer, "secret", 100);

    if (result != 0) {
        // Password incorrect path
        // Loop computing some hash/checksum of buffer
        int sum = 0;
        for (int i = 0; i < 100; i++) {
            sum += tv.tv_sec * buffer[i];
            sum = (sum * 6) & 3;  // Some transformation
        }
        // XOR result into output
        *(_DWORD*)tv.tv_sec = sum ^ 0x173063C1;
    } else {
        // Password correct path
        *(_DWORD*)tv.tv_sec = 0;
    }

    return result;
}
