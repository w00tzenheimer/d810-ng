/**
 * Hardened OLLVM Conditional Chain Test
 *
 * This sample reproduces a hardened OLLVM control-flow flattening pattern
 * modeled after real-world binary sub_7FFC1EB47830. Key characteristics:
 *
 * - while(1) with nested if/else (NOT switch/case) -- binary search tree
 * - State variable compared via <= and == (binary search over state space)
 * - State transitions computed via opaque constant table expressions:
 *     state = (g_opaque_table[N] ^ K1) + K2
 * - Each state block does real computation on the input parameters
 * - Designed to exercise FixPredecessorOfConditionalJumpBlock rule
 *
 * Function 1 (simple, 6 states): result = input * 3 + 7
 * Function 2 (complex, 10 states): result = (a + b) * (a - b)
 *
 * The opaque constant table and XOR/add constants are carefully chosen
 * so that each state transition expression evaluates to the correct
 * target state value at runtime.
 */

#include "polyfill.h"
#include "export.h"

/* Opaque constant table - values chosen to produce specific state transitions
 * when plugged into the expressions below. Volatile to prevent compile-time
 * folding so IDA sees the full obfuscation pattern. */
volatile DWORD g_opaque_table[12] = {
    0x3A7B2C5D, 0x1F8E4A6B, 0x5C9D3E7F, 0x2B6A1D4E,
    0x7E3F5A8C, 0x4D1C6B9A, 0x6A5B3C8D, 0x8F2E7D4C,
    0x1D4A5B6C, 0x9C3D2E1F, 0x5A6B7C8D, 0x3E4F5A6B
};

volatile int g_side_effect = 0;

/* Prevent optimization of helper calls */
DONT_OPTIMIZE()

/* ============================================================================
 * Function 1: Simple hardened conditional chain (6 states)
 *
 * Computes: result = input * 3 + 7
 *
 * State machine:
 *   STATE_1 (0x1000): result = input
 *   STATE_2 (0x2000): result = result * 3
 *   STATE_3 (0x4000): result = result + 7
 *   STATE_4 (0x5000): g_side_effect = result
 *   STATE_5 (0x6000): finalize (nop)
 *   STATE_EXIT (0x7000): break
 *
 * Binary search tree structure for dispatch:
 *   if (state <= 0x3000)
 *       if (state == 0x1000) -> S1
 *       else if (state == 0x2000) -> S2
 *       else -> exit
 *   else
 *       if (state <= 0x5500)
 *           if (state == 0x4000) -> S3
 *           else if (state == 0x5000) -> S4
 *           else -> exit
 *       else
 *           if (state == 0x6000) -> S5
 *           else -> exit (including 0x7000)
 *
 * Each transition uses: state = (g_opaque_table[N] ^ K1) + K2
 * Constants verified via Python to produce correct target states.
 * ============================================================================ */
EXPORT int hardened_cond_chain_simple(int input)
{
    int result = 0;
    /* Init: (g_opaque_table[0] ^ 0xC584CDEC) + 0x2E4F = 0x1000 */
    unsigned int state = (g_opaque_table[0] ^ 0xC584CDECu) + 0x2E4Fu;

    while (1)
    {
        if (state <= 0x3000u)
        {
            if (state == 0x1000u)
            {
                /* STATE_1: Initialize result with input */
                result = input;
                /* -> STATE_2: (table[1] ^ 0xE071AF82) + 0x3A17 = 0x2000 */
                state = (g_opaque_table[1] ^ 0xE071AF82u) + 0x3A17u;
            }
            else if (state == 0x2000u)
            {
                /* STATE_2: Multiply by 3 */
                result = result * 3;
                /* -> STATE_3: (table[2] ^ 0x5C9D1ADC) + 0x1B5D = 0x4000 */
                state = (g_opaque_table[2] ^ 0x5C9D1ADCu) + 0x1B5Du;
            }
            else
            {
                /* Default: exit */
                break;
            }
        }
        else
        {
            if (state <= 0x5500u)
            {
                if (state == 0x4000u)
                {
                    /* STATE_3: Add 7 */
                    result = result + 7;
                    /* -> STATE_4: (table[3] ^ 0x2B6A1E90) + 0x4C22 = 0x5000 */
                    state = (g_opaque_table[3] ^ 0x2B6A1E90u) + 0x4C22u;
                }
                else if (state == 0x5000u)
                {
                    /* STATE_4: Store side effect */
                    g_side_effect = result;
                    /* -> STATE_5: (table[4] ^ 0x7E3F6CC3) + 0x29B1 = 0x6000 */
                    state = (g_opaque_table[4] ^ 0x7E3F6CC3u) + 0x29B1u;
                }
                else
                {
                    break;
                }
            }
            else
            {
                if (state == 0x6000u)
                {
                    /* STATE_5: Finalize - no computation, just transition to exit */
                    /* -> STATE_EXIT: (table[5] ^ 0x4D1C7B77) + 0x5F13 = 0x7000 */
                    state = (g_opaque_table[5] ^ 0x4D1C7B77u) + 0x5F13u;
                }
                else
                {
                    /* STATE_EXIT (0x7000) or any unexpected value: exit */
                    break;
                }
            }
        }
    }
    return result;
}

/* ============================================================================
 * Real decompiled function: sub_7FFC1EB47830
 *
 * This is the actual decompiled output from a hardened OLLVM-obfuscated
 * malware sample, made compilable for test purposes. Key characteristics:
 *
 * - 14+ states in a binary-search conditional chain (nested if/else, NOT switch)
 * - State transitions computed via opaque DWORD table with complex MBA expressions
 * - Nested while(1) { while(1) { while(1) { ... } } } dispatcher structure
 * - Each DWORD is volatile to prevent compile-time folding
 * - External function calls stubbed for compilability
 *
 * This exercises FixPredecessorOfConditionalJumpBlock rule with real-world
 * complexity that synthetic samples cannot reproduce.
 * ============================================================================ */

#include <stdarg.h>

/* Opaque DWORD table - volatile to prevent compile-time folding */
volatile DWORD dword_7FFC1ECAEC74 = 0x7160450c;
volatile DWORD dword_7FFC1ECAEC78 = 0xf4f99b1f;
volatile DWORD dword_7FFC1ECAEC7C = 0xb77d6780;
volatile DWORD dword_7FFC1ECAEC80 = 0xb8e2f419;
volatile DWORD dword_7FFC1ECAEC84 = 0x133e9816;
volatile DWORD dword_7FFC1ECAEC88 = 0x24382eba;
volatile DWORD dword_7FFC1ECAEC8C = 0x5a5482c1;
volatile DWORD dword_7FFC1ECAEC90 = 0xf7de90f4;
volatile DWORD dword_7FFC1ECAEC94 = 0xbbbf7157;
volatile DWORD dword_7FFC1ECAEC98 = 0x25a5a658;
volatile DWORD dword_7FFC1ECAEC9C = 0xd1600344;
volatile DWORD dword_7FFC1ECAECA0 = 0xa0b80ec6;
volatile DWORD dword_7FFC1ECAECA4 = 0x970dfd93;
volatile DWORD dword_7FFC1ECAECA8 = 0x900cb847;
volatile DWORD dword_7FFC1ECAECAC = 0x22a9d8a5;
volatile DWORD dword_7FFC1ECAECB0 = 0x59988e4d;
volatile DWORD dword_7FFC1ECAECB4 = 0x0e6175e5;
volatile DWORD dword_7FFC1ECAECB8 = 0xaef42e86;
volatile DWORD dword_7FFC1ECAECBC = 0x7e79e385;
volatile DWORD dword_7FFC1ECAECC0 = 0xfcd18094;
volatile DWORD dword_7FFC1ECAECC4 = 0x3c2daf03;
volatile DWORD dword_7FFC1ECAECC8 = 0xf9721eb1;

/* Extern globals (placeholders) */
volatile unsigned __int64 qword_7FFC1EC98BB8 = 0x1234567890ABCDEFuLL;
volatile unsigned __int64 qword_7FFC1ECB19F8 = 0;
volatile char unk_7FFC1ECB1A00 = 0;

/* Stub external functions - we only care about compilability, not behavior */
static __int64 stub_sub_7FFC1EB17C30(int a1, __int64 a2, int a3, unsigned int a4, void *a5)
{ (void)a1; (void)a2; (void)a3; (void)a4; (void)a5; return 0; }

static __int64 stub_sub_7FFC1EC16C50(__int64 a1)
{ (void)a1; return 0; }

static void stub_RtlAcquireSRWLockExclusive_w(int a1, int a2, __int64 a3)
{ (void)a1; (void)a2; (void)a3; }

static __int64 stub_RtlReleaseSRWLockExclusive_w(int a1, int a2, int a3, __int64 a4)
{ (void)a1; (void)a2; (void)a3; (void)a4; return 0; }

static __int64 stub_sub_7FFC1E6E8320(__int64 a1, int a2, int a3, int a4)
{ (void)a1; (void)a2; (void)a3; (void)a4; return 0; }

static void stub_sub_7FFC1EC291B0(void *a1, void *a2, unsigned __int64 a3)
{ (void)a1; (void)a2; (void)a3; }

static void stub_sub_7FFC1E9D3BB0(int a1, unsigned __int64 a2, int a3, int a4)
{ (void)a1; (void)a2; (void)a3; (void)a4; }

EXPORT __int64 sub_7FFC1EB47830(__int64 a1, ...)
{
    va_list va, v5;
    __int64 v6, v7, v8, v9, v10, v11, v12, v13, v14, v15;
    __int64 v16, v17, v18, v19, v20, v21, v22, v23, v24, v25;
    __int64 v26, v27, v28, v29, v31, v33;
    __int64 _R8;
    unsigned int i, i_1;
    char MultiByteStr[256];

    /* Suppress uninitialized warnings - IDA decompilation assumes prior state */
    v6 = v7 = v8 = v9 = v10 = v11 = v12 = v13 = v14 = v15 = 0;
    v16 = v17 = v18 = v19 = v20 = v21 = v22 = v23 = v24 = v25 = 0;
    v26 = v27 = v28 = v29 = v31 = v33 = 0;
    _R8 = 0;
    i_1 = 0;

    va_start(va, a1);
    v33 = 0xFFFFFFFFFFFFFFFEuLL;
    for ( i = (unsigned int)(((dword_7FFC1ECAEC74 - 0x5B6B3E41) ^ (dword_7FFC1ECAEC74 - 0x22843B9C) ^ 0x65425357) - dword_7FFC1ECAEC74 + 0x36AE2D6A); ; i = (unsigned int)(((((dword_7FFC1ECAECBC ^ 0xCF8E4060) + 0x7AD332AE) ^ 0xDFAFDE85) + 0x19EBC2DB) ^ ((dword_7FFC1ECAECBC ^ 0xCF8E4060) + (((dword_7FFC1ECAECBC ^ 0xCF8E4060) + 0x7AD332AE) ^ 0xDFAFDE85 ^ ((dword_7FFC1ECAECBC ^ 0xCF8E4060) + 0x7AD332AE - (((((dword_7FFC1ECAECBC ^ 0xCF8E4060) + 0x7AD332AE) ^ 0xDFAFDE85) + 0x19EBC2DB) ^ 0xF2E1E16D) - dword_7FFC1ECAECBC - (((((dword_7FFC1ECAECBC ^ 0xCF8E4060) + 0x7AD332AE) ^ 0xDFAFDE85) + 0x19EBC2DB) ^ 0xF2E1E16D) - 0x229CA15C)))) )
    {
        while ( 1 ) { while ( 1 ) { while ( 1 ) {
            while ( i <= 0x229632CBu ) {
                if ( i <= 0xE2419EEu ) {
                    if ( i <= 0x57B2522u ) {
                        if ( i == 0x1EADC3Bu ) {
                            v9 = v10 - (v29 ^ 0xAAF517DCEE1EBB9CuLL) - v12;
                            i = (unsigned int)((dword_7FFC1ECAECB4 + 0x6C7A001F) ^ (((dword_7FFC1ECAECB4 - 0xB5F8BE6) ^ (dword_7FFC1ECAECB4 + 0x8A990F2) ^ 0x9E9B8066) - 0x751F5BC6));
                        } else {
                            i_1 = (unsigned int)(((dword_7FFC1ECAEC78 - 0x6188275) ^ (0xD0A1D5AC - dword_7FFC1ECAEC78) ^ 0x99CB25C5) + dword_7FFC1ECAEC78 + 0x7E6A0B96);
LABEL_x47990:
                            i = i_1;
                        }
                    } else {
                        if ( i == 0x57B2523u ) {
                            v19 = 3 * (v31 ^ 0x57D8A1E44A3671C3LL);
                            v18 = v31 & 0xA8275E1BB5C98E3CuLL;
                            i_1 = (unsigned int)((((dword_7FFC1ECAEC9C ^ 0x9DD5F08) - 0x7B8A0EB0) ^ 0xF72ED900) + (dword_7FFC1ECAEC9C ^ 0x9DD5F08 ^ ((dword_7FFC1ECAEC9C ^ 0x9DD5F08) - (((dword_7FFC1ECAEC9C ^ 0x9DD5F08) - 0x7B8A0EB0) ^ 0xF72ED900) - 0x31B6869F)) - ((dword_7FFC1ECAEC9C ^ 0x9DD5F08) - 0x7B8A0EB0) + dword_7FFC1ECAEC9C + (dword_7FFC1ECAEC9C ^ 0x9DD5F08) + 0x73A6EDF);
                            goto LABEL_x47990;
                        }
                        if ( i == 0x5DA0D7Fu ) {
                            va_copy(v5, va);
                            stub_sub_7FFC1EB17C30(0x40, a1, 0x40, (unsigned int)(unsigned __int64)va, MultiByteStr);
                            _R8 = stub_sub_7FFC1EC16C50((__int64)MultiByteStr);
                            stub_RtlAcquireSRWLockExclusive_w(0x3C, 0x5D, (__int64)&unk_7FFC1ECB1A00);
                            i = (unsigned int)(((dword_7FFC1ECAEC7C ^ 0xB3279F74) - 0x663AEF03) ^ ((dword_7FFC1ECAEC7C ^ 0xB3279F74) - 0x518A1119) ^ dword_7FFC1ECAEC7C ^ (0xBA91B165 - (dword_7FFC1ECAEC7C ^ 0xB3279F74)));
                        } else {
                            i = (unsigned int)(dword_7FFC1ECAEC8C + ((((dword_7FFC1ECAEC8C - 0x3BFC8B64) ^ 0x85BF2EB2) + 0x239395C1) ^ (((dword_7FFC1ECAEC8C - 0x3BFC8B64) ^ 0x85BF2EB2) + ((dword_7FFC1ECAEC8C - 0x276480BE) ^ 0x47AA3AC) - 0x5299AEB2)) - (((dword_7FFC1ECAEC8C - 0x3BFC8B64) ^ 0x85BF2EB2) - 0x22B19B40) - ((dword_7FFC1ECAEC8C - 0x3BFC8B64) ^ 0x85BF2EB2));
                        }
                    }
                } else if ( i > 0x1C5AE195u ) {
                    if ( i == 0x1C5AE196u ) {
                        v21 = v22;
                        v20 = v31 | 0xA8275E1BB5C98E3CuLL;
                        i_1 = (unsigned int)(dword_7FFC1ECAEC98 + ((dword_7FFC1ECAEC98 - 0x7F42C6E3) ^ 0x8D7851B3) - ((dword_7FFC1ECAEC98 - 0x7F42C6E3) ^ 0xA325A02F) + dword_7FFC1ECAEC98 - 0x6BA336F9);
                        goto LABEL_x47990;
                    }
                    if ( i == 0x1FE5AE97u ) {
                        i = (unsigned int)(dword_7FFC1ECAEC80 ^ ((((dword_7FFC1ECAEC80 ^ 0x3C0FFE33) + 0x32D84493) ^ 0xC382A700) + (dword_7FFC1ECAEC80 ^ 0x3C0FFE33) + (dword_7FFC1ECAEC80 ^ 0x3C0FFE33 ^ ((dword_7FFC1ECAEC80 ^ 0xD27CFCF1) - 0x15036E8C)) - 0x4DEB552C)) - ((dword_7FFC1ECAEC80 ^ 0x3C0FFE33) + 0x32D84493);
                    } else {
                        v26 = stub_sub_7FFC1E6E8320(v27, *(unsigned int *)(v28 + 0x10), 0x31, 0x4A);
                        i = (unsigned int)((dword_7FFC1ECAEC88 - 0x3674642F) ^ dword_7FFC1ECAEC88 ^ (dword_7FFC1ECAEC88 - 0x209412D0) ^ 0xA8A1D44D);
                    }
                } else {
                    if ( i == 0xE2419EFu ) {
                        v12 = 2 * ~v13;
                        v11 = v29 & 0xAAF517DCEE1EBB9CuLL;
                        i_1 = (unsigned int)(((dword_7FFC1ECAECAC + 0x511C293B) ^ 0xE32DE1ED) + ((dword_7FFC1ECAECAC + 0x511C293B) ^ (((dword_7FFC1ECAECAC + 0x511C293B) ^ 0xE32DE1ED) + ((0xB1AF1CC4 - (2 * ((dword_7FFC1ECAECAC + 0x511C293B) ^ 0xE32DE1ED) - 0x4A4F9BE3)) ^ (dword_7FFC1ECAECAC + 0x511C293B) ^ dword_7FFC1ECAECAC) + 0x34566AC5) ^ 0xC299EDB3));
                        goto LABEL_x47990;
                    }
                    if ( i == 0x117734E6u ) {
                        v22 = ~v31 & 0xA8275E1BB5C98E3CuLL;
                        i = (unsigned int)(dword_7FFC1ECAEC94 + ((dword_7FFC1ECAEC94 + 0x2CD47C30) ^ (dword_7FFC1ECAEC94 - 0x33B6D39F)));
                    } else {
                        v6 = v25 + v15 + (v14 ^ v7) - (unsigned __int64)_R8;
                        i = (unsigned int)(dword_7FFC1ECAECC4 ^ (((dword_7FFC1ECAECC4 - 0x6310D3DB) ^ 0x205AED73) - ((dword_7FFC1ECAECC4 - 0x6310D3DB) ^ 0x76BB5C76) - dword_7FFC1ECAECC4 - dword_7FFC1ECAECC4 + 0x3F290B8E));
                    }
                }
            }
            if ( i <= 0x62FE2B95u ) break;
            if ( i <= 0x6FA9658Bu ) {
                if ( i == 0x62FE2B96u ) {
                    v25 = qword_7FFC1EC98BB8 ^ 0x398190EE39C3B018LL;
                    v29 = (qword_7FFC1EC98BB8 ^ 0x398190EE39C3B018LL) - 0x797BE2A289A0C37LL;
                    v24 = v29 ^ 0x4B4BEEBED4D15BDBLL;
                    v31 = (v29 ^ 0x4B4BEEBED4D15BDBLL) + 0x978458AE4550AFDLL;
                    v23 = 4 * (~v31 & 0x17D8A1E44A3671C3LL);
                    i = (unsigned int)(0xD777F270 - (2 * dword_7FFC1ECAEC84 + 0x46227AA4 + dword_7FFC1ECAEC84 + 0x46227AA4));
                } else {
                    v15 = v21 + v19 + v16 - v17 - v20 - v23;
                    v14 = v15 + 0x1B63257754F53886LL;
                    v13 = v29 | 0xAAF517DCEE1EBB9CuLL;
                    i = (unsigned int)(dword_7FFC1ECAECA8 ^ ((((dword_7FFC1ECAECA8 ^ 0x63D34FF7) - 0x65FFA34) ^ 0xDBB87C18) + (((dword_7FFC1ECAECA8 ^ 0x63D34FF7) - 0x65FFA34) ^ 0x8A1EDD38)));
                }
            } else if ( i == 0x6FA9658Cu ) {
                v8 = v31 + v9;
                i = (unsigned int)((((dword_7FFC1ECAECB8 - 0x2BD31237) ^ 0x8D9230F3) + ((dword_7FFC1ECAECB8 - 0x62EC5A49) ^ (dword_7FFC1ECAECB8 + 0x5F152144))) ^ dword_7FFC1ECAECB8 ^ (dword_7FFC1ECAECB8 - 0x12EA2127));
            } else {
                if ( i != 0x72C060D6u ) {
                    i_1 = (unsigned int)(((((dword_7FFC1ECAECA4 - 0x57C30EBF) ^ 0xC2132B37) - 0x2D0DA931) ^ 0xADD9845D) + dword_7FFC1ECAECA4 + ((((dword_7FFC1ECAECA4 - 0x57C30EBF) ^ 0xC2132B37) - 0x2D0DA931) ^ (((((dword_7FFC1ECAECA4 - 0x57C30EBF) ^ 0xC2132B37) - 0x2D0DA931) ^ 0xADD9845D) + ((((dword_7FFC1ECAECA4 - 0x57C30EBF) ^ 0xC2132B37) - 0x2D0DA931) ^ 0xADD9845D) - 2 * ((dword_7FFC1ECAECA4 - 0x57C30EBF) ^ 0xC2132B37) - 0x39C840C8)) + 0x1709A376);
                    goto LABEL_x47990;
                }
                v10 = 2 * ~v11;
                i = (unsigned int)((((dword_7FFC1ECAECB0 + 0x7D85B2C6) ^ 0xB6F959ED) + 0x30B55066) ^ (((dword_7FFC1ECAECB0 + 0x7D85B2C6) ^ (((((dword_7FFC1ECAECB0 + 0x7D85B2C6) ^ 0xB6F959ED) + 0x30B55066) ^ 0x9283FA70) + ((dword_7FFC1ECAECB0 + 0x7D85B2C6) ^ 0x4AFEC9E2) - 0x4395EA74)) - ((((dword_7FFC1ECAECB0 + 0x7D85B2C6) ^ 0xB6F959ED) + 0x30B55066) ^ 0x9283FA70) + 0x621D7F1));
            }
        }
        if ( i > 0x3C7C5C9Fu ) break;
        if ( i == 0x229632CCu ) {
            v17 = v18;
            v16 = v31 & 0x57D8A1E44A3671C3LL;
            i_1 = (unsigned int)(dword_7FFC1ECAECA0 + (dword_7FFC1ECAECA0 ^ (((dword_7FFC1ECAECA0 + 0x74798DB3) ^ 0x698782E0) - 0x753F6F4F)) - (dword_7FFC1ECAECA0 + 0x74798DB3) + ((dword_7FFC1ECAECA0 + 0x74798DB3) ^ 0x698782E0) - 0x4B1D288B);
            goto LABEL_x47990;
        }
        if ( i == 0x2C41F386u ) {
            stub_sub_7FFC1EC291B0((void *)(v6 + v26), MultiByteStr, (unsigned __int64)_R8);
            i_1 = (unsigned int)((dword_7FFC1ECAECC8 ^ 0xFE4B82BB) + (dword_7FFC1ECAECC8 ^ 0xAE28A866) + (dword_7FFC1ECAECC8 ^ 0x6A5F7E00) + 0x7483DFBA + 0xFA99A26);
            goto LABEL_x47990;
        }
        stub_sub_7FFC1E9D3BB0(0x27, qword_7FFC1ECB19F8, 0x33, (_DWORD)_R8 + *(_DWORD *)(qword_7FFC1ECB19F8 + 0x10));
        v28 = qword_7FFC1ECB19F8;
        v27 = *(_QWORD *)(qword_7FFC1ECB19F8 + 8);
        i = (unsigned int)(dword_7FFC1ECAEC90 - (dword_7FFC1ECAEC90 - 0x486928BF) - dword_7FFC1ECAEC90 - (dword_7FFC1ECAEC90 - 0x486928BF) - dword_7FFC1ECAEC90 + 0x77B27934);
        }
        if ( i != 0x3C7C5CA0u ) break;
        v7 = v24 ^ v8;
        i = (unsigned int)(((dword_7FFC1ECAECC0 - 0x6C09F37) ^ (((dword_7FFC1ECAECC0 - 0x6C09F37) ^ 0x9B341BB8) - 0x78844C8A) ^ 0xC6C3D08A) - ((dword_7FFC1ECAECC0 - 0x6C09F37) ^ 0x9B341BB8) - dword_7FFC1ECAECC0 - 0x4112DDBE);
        }
        if ( i != 0x623FEB6Au ) break;
    }
    va_end(va);
    return stub_RtlReleaseSRWLockExclusive_w(0x11, 0xA, 0x2B, (__int64)&unk_7FFC1ECB1A00);
}

ENABLE_OPTIMIZE()
