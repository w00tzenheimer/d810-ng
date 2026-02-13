/**
 * sub_7FFC1E9D3BB0 - Buffer Resize with OLLVM Control-Flow Flattening
 *
 * Reproduces a real-world OLLVM CFF pattern from a production binary.
 * The underlying function is a buffer resize/realloc with zero-fill.
 *
 * Clean logic:
 *   1. Compare new_size vs current size and capacity
 *   2. If new_size > capacity: call grow_buffer (realloc)
 *   3. Zero-fill from old_size to new_size
 *   4. Update size field, return pointer to size
 *
 * Obfuscation:
 *   - while(1) with nested if/else binary search dispatcher
 *   - State variable computed from opaque constant table via MBA expressions
 *   - 7+ state values: 0x7E069F35 (init), 0x4DFE3D51, 0x3C837EFA, etc.
 *   - Opaque table values from real binary (verified against IDA MCP)
 *
 * This exercises:
 *   - FoldReadonlyDataRule (fold_writable_constants for opaque table)
 *   - FixPredecessorOfConditionalJumpBlock (conditional chain dispatch)
 *   - Unflattener (nested while/if CFF pattern)
 *   - GlobalConstantInliner (resolve opaque table loads)
 */

#include "polyfill.h"
#include "platform.h"

/* Opaque constant table - volatile to prevent compile-time folding.
 * Values from real binary dword_7FFC1ECA872C..dword_7FFC1ECA874C. */
volatile DWORD g_resize_opaque_table[9] = {
    0x334dce82,  /* [0] was dword_7FFC1ECA872C */
    0x8c1b4613,  /* [1] was dword_7FFC1ECA8730 */
    0x6f919bc5,  /* [2] was dword_7FFC1ECA8734 */
    0x6ba50cd0,  /* [3] was dword_7FFC1ECA8738 */
    0xdb7079ac,  /* [4] was dword_7FFC1ECA873C */
    0x3916a6d7,  /* [5] was dword_7FFC1ECA8740 */
    0xc6e3ab72,  /* [6] was dword_7FFC1ECA8744 */
    0x96ddcda1,  /* [7] was dword_7FFC1ECA8748 */
    0x78d90805,  /* [8] was dword_7FFC1ECA874C */
};

/* Buffer structure accessed via pointer arithmetic */
typedef struct {
    __int64 reserved;      /* +0x00 */
    __int64 *data;         /* +0x08 - pointer to byte buffer */
    unsigned int size;     /* +0x10 - current size */
    unsigned int capacity; /* +0x14 - allocated capacity */
} resize_buf_t;

/* Stub for buffer grow/realloc helper */
static void grow_buffer(__int64 a2, unsigned int n8, int a, int b)
{
    (void)a2; (void)n8; (void)a; (void)b;
    /* In real binary: sub_7FFC1E8840F0 */
}

DONT_OPTIMIZE()

EXPORT unsigned int * sub_7FFC1E9D3BB0_resize(__int64 a1, __int64 a2, __int64 a3, unsigned int n8)
{
    unsigned int n0x3C837EFA; /* state variable */
    __int64 *v6;
    unsigned int n8_1, n8_2, n8_3, n8_4, n8_5, n8_6, n8_7;
    _QWORD v15;
    __int64 *v17;
    _QWORD v19;
    unsigned int *v13;

    (void)a1;
    (void)a3;

    /* Suppress uninitialized warnings - IDA decompilation assumes prior state */
    n8_2 = n8_3 = n8_4 = n8_5 = n8_6 = n8_7 = 0;
    v15 = 0;
    v17 = 0;
    v19 = 0;
    v13 = 0;

    /* Initial state computation via MBA on opaque table */
    n0x3C837EFA = ((g_resize_opaque_table[1] + 0x41698846) ^ 0xF7BC95A) - 0x44F867CE;
    v6 = (__int64 *)(a2 + 8);
    n8_1 = n8;

    while ( 1 )
    {
        while ( 1 )
        {
            while ( n0x3C837EFA <= 0x4DFE3D50u )
            {
                if ( n0x3C837EFA > 0x274B9544u )
                {
                    if ( n0x3C837EFA != 0x3C837EFAu )
                        goto LABEL_xFC6;

                    /* STATE 0x3C837EFA: read data pointer, check null */
                    n8_7 = n8_6;
                    v19 = v15;
                    if ( v15 )
                        n0x3C837EFA = (g_resize_opaque_table[7] + 0x67CEB118)
                                    ^ 0x3E118C46
                                    ^ (((g_resize_opaque_table[7] + 0x67CEB118) ^ 0x3E118C46)
                                     + ((((g_resize_opaque_table[7] + 0x67CEB118) ^ 0x3E118C46) - 0x21711818)
                                      ^ (0x82B6D9 - (((g_resize_opaque_table[7] + 0x67CEB118) ^ 0x552321D8) + g_resize_opaque_table[7] + 0x67CEB118)))
                                     - ((g_resize_opaque_table[7] + 0x67CEB118) ^ 0x5EA4F8DF)
                                     - 0x342768EF);
                    else
                        n0x3C837EFA = (((g_resize_opaque_table[5] ^ 0x7A6A4D46) + 0x3282125F) ^ 0x23D4F17)
                                    - ((g_resize_opaque_table[5] ^ 0x7A6A4D46) + 0x3282125F);
                }
                else if ( n0x3C837EFA == 0x1C4B4F7u )
                {
                    /* STATE 0x1C4B4F7: loop check / null-terminate */
                    if ( n8_7 + 1 == n8_2 )
                    {
                        n0x3C837EFA = (g_resize_opaque_table[0] ^ 0x1BBA5115)
                                    + g_resize_opaque_table[0] - 0x34F9D8D4;
                    }
                    else
                    {
                        v15 = *v17;
LABEL_xEF7:
                        n8_6 = n8_7 + 1;
                        n0x3C837EFA = ((g_resize_opaque_table[6] - 0x512E53E8) ^ 0x381A62FF)
                                    + ((g_resize_opaque_table[6] - 0x512E53E8) ^ 0x381A62FF ^ (0xCC24D567 - g_resize_opaque_table[6]))
                                    + g_resize_opaque_table[6] - 0x20FD7E6D;
                    }
                }
                else
                {
                    /* STATE init: read data ptr */
                    v17 = v6;
                    if ( *(_QWORD *)(a2 + 8) )
                    {
                        n8_2 = n8_1;
                        v15 = *(_QWORD *)(a2 + 8);
                        n8_6 = n8_5;
LABEL_xD0A:
                        /* jump to state 0x3C837EFA handler */
                        n0x3C837EFA = ((g_resize_opaque_table[6] - 0x512E53E8) ^ 0x381A62FF)
                                    + ((g_resize_opaque_table[6] - 0x512E53E8) ^ 0x381A62FF ^ (0xCC24D567 - g_resize_opaque_table[6]))
                                    + g_resize_opaque_table[6] - 0x20FD7E6D;
                        (void)0; /* suppress label-at-end-of-block warning */
                    }
                    else
                    {
                        n0x3C837EFA = (((g_resize_opaque_table[8] ^ 0xFDB21B72) + 0x5F6026DC)
                                     ^ ((g_resize_opaque_table[8] ^ 0xFDB21B72) + 0x2E716FC7)
                                     ^ g_resize_opaque_table[8]
                                     ^ (0x1A29F313 - (g_resize_opaque_table[8] ^ 0xFDB21B72)))
                                    - (g_resize_opaque_table[8] ^ 0xFDB21B72);
                    }
                }
            }

            if ( n0x3C837EFA > 0x7BE4032Fu )
                break;

            if ( n0x3C837EFA != 0x4DFE3D51u )
            {
                /* STATE 0x7BE4032F: zero-fill byte */
                *(_BYTE *)(v19 + n8_7) = 0;
                goto LABEL_xEF7; /* jump to loop check */
            }

            /* STATE 0x4DFE3D51: shrink setup */
            n8_3 = n8_4;
            /* fall through to LABEL_xDCB */
LABEL_xDCB:
            n8_5 = n8_3;
            if ( n8_3 >= n8 )
                n0x3C837EFA = 2 * g_resize_opaque_table[4] - 0x3AFCF028;
            else
                n0x3C837EFA = (g_resize_opaque_table[2]
                             ^ (0xAF1FEB35 - (g_resize_opaque_table[2]
                               + ((g_resize_opaque_table[2] - 0x5E1D7976) ^ 0x6EC3340A)
                               - 0x6DE10B1E - 0x5E1D7976)))
                            + 0x6AAACF67
                            - (((((g_resize_opaque_table[2] - 0x5E1D7976) ^ 0x6EC3340A) - 0x6DE10B1E) ^ 0xC420562A) - 0x6AAACF67)
                            + 0x386EF508;
        }

        if ( n0x3C837EFA != 0x7E069F35u )
            break;

        /* STATE 0x7E069F35: size comparison */
        v13 = (unsigned int *)(a2 + 0x10);
        n8_4 = *(_DWORD *)(a2 + 0x10);
        if ( n8 < n8_4 )
            break;

        if ( n8 > *(_DWORD *)(a2 + 0x14) )
        {
            grow_buffer(a2, n8, 0xA, 0x44);
            n8_3 = *v13;
            goto LABEL_xDCB;
        }

        n0x3C837EFA = ((g_resize_opaque_table[3] + 0x4E4B3851) ^ 0x357E7409)
                    - (2 * g_resize_opaque_table[3] + 0x4E4B3851)
                    - 0x18FAA1E6;
    }

LABEL_xFC6:
    *v13 = n8;
    return v13;
}

ENABLE_OPTIMIZE()
