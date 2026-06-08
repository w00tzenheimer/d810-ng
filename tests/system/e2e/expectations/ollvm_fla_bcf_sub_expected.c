// test_function_ollvm_fla_bcf_sub - REFERENCE (TRUE ORIGINAL)
//
// OLLVM obfuscation applied to the binary:
// - FLA: control-flow flattening with a nested dispatcher
// - BCF: bogus control flow + opaque predicates over the globals x, y
// - SUB: instruction substitution / MBA noise
//
// This is the actual pre-obfuscation source the binary was built from. It has a
// SINGLE terminal output write, `*output = local_state ^ 0x173063C1`. The
// `0xCD536960 / 0x259CF55E` second write seen in the obfuscated decompilation is
// BCF the obfuscator inserted (guard is constant-false at the uninitialised
// opaque globals x=y=0) -- it is dead code, NOT a real password-fail arm.

void test_function_original(unsigned int *input, unsigned int *output)
{
    unsigned int local_state;
    unsigned int ref_input_value;
    struct timeval time_info;
    unsigned int nb_seconds;
    char password[100];
    unsigned int tmp;
    unsigned int failed;
    unsigned int stringCompareResult;
    unsigned int activationCode;
    unsigned int i;
    int tmp___0;

    password[0] = (char)'\000';
    tmp = 1U;
    while (!(tmp >= 100U)) {
        password[tmp] = (char)0;
        tmp++;
    }
    failed = 0U;
    gettimeofday(&time_info, (void *)0);
    nb_seconds = (unsigned int)(time_info.tv_sec & 4294967295L);
    ref_input_value = ((nb_seconds & 1344344352U) | 2197946369U)
                    + ((nb_seconds & 1344344352U) ^ 1344887088U);
    local_state = (unsigned int)((unsigned long)*(input + 0UL) + 650604291UL);
    printf("Please enter password:");
    scanf("%s", password);
    activationCode = *(input + 0UL);
    tmp___0 = strncmp((char const *)(password), "secret", 100U);
    stringCompareResult = (unsigned int)tmp___0;
    failed |= (unsigned int)((unsigned long)stringCompareResult != 0UL);
    failed |= (unsigned int)(activationCode != ref_input_value);
    if (failed) {
        *(output + 0) = 0U;
    }
    if (local_state & 1U) {
        local_state = 5U * local_state + activationCode;
        switch ((unsigned long)((int)local_state) % 4UL) {
        case 0UL:
            local_state ^= 66U;
            break;
        case 1UL:
            local_state += 66U;
            break;
        default:
            local_state -= 66U;
            break;
        }
    } else {
        i = 0U;
        while ((unsigned long)i < 100UL) {
            local_state += (unsigned int)password[i] * ref_input_value;
            i = (unsigned int)((unsigned long)i + 1UL);
        }
    }
    *(output + 0UL) = (unsigned int)((unsigned long)local_state ^ 389047233UL);
    return;
}
