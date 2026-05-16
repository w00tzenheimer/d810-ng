// test_function_ollvm_fla_bcf_sub - REFERENCE
//
// OLLVM obfuscation applied:
// - FLA: control-flow flattening with a massive nested dispatcher
// - BCF: bogus control flow and opaque predicates
// - SUB: instruction substitution and bit-manipulation noise
//
// This reference is intentionally semantic and readable. It documents the
// behavior the e2e test should move toward, not the current partial D810 output.
// Do not use it as an exact AST expected_code oracle until D810 emits a
// structurally comparable result.

EXPORT void test_function_ollvm_fla_bcf_sub(unsigned int *input, unsigned int *output)
{
    /* ==================== CLEAN UNFLATTENED VERSION ==================== */
    /* All control-flow flattening, bogus control flow (BCF), opaque predicates,
       state variable, nested dispatcher loops, and anti-analysis junk removed.
       Only the real semantic logic remains. */

    char password_buffer[100] = {0};
    int strcmp_result = 0;
    unsigned int working_value = 0;
    int password_ok = 0;

    /* === PHASE 1: Password prompt and verification === */
    printf("Please enter password:");
    scanf("%s", password_buffer);

    strcmp_result = strncmp(password_buffer, "secret", 100);
    password_ok = (strcmp_result == 0);

    /* === PHASE 2: Process input array into output array === */
    if (input)
        working_value = *input;

    working_value = working_value + 5 * working_value;
    working_value += 66;
    working_value = (working_value & 0xFFFFFFBD) | (~working_value & 0x42);
    working_value *= 2;

    if (password_ok)
    {
        working_value = (working_value & 0xE8CF9C3E) | (~working_value & 0x173063C1);
        working_value ^= 0x259CF55E;

        if (output)
            *output = working_value;

        if (output && output != input)
            output[1] = 0;
    }
    else
    {
        working_value = (working_value & 0xCD536960) | (~working_value & 0x32AC969F);
        working_value ^= 0x259CF55E;

        if (output)
            *output = ~working_value;
    }

    /* === PHASE 3: Preserved anti-analysis side effect === */
    struct timeval tv;
    gettimeofday(&tv, NULL);

    if (input && output && input != output)
    {
        output[2] = input[0] + 5 * input[0];
        output[3] = working_value;
    }
}
