/**
 * Approov-style Control Flow Flattening Test
 *
 * This sample mimics the EXACT decompiled output from real Approov-obfuscated code.
 *
 * The BadWhileLoop detector looks for:
 * - blk.tail.opcode == m_jz with constant in 0xF6000-0xF6FFF range
 * - blk.prevb.tail.opcode == m_mov with constant in range
 * - blk.nextb.tail.opcode == m_jz with constant in range
 *
 * Key pattern from real decompiled Approov code:
 *   LABEL_13:
 *     v8 = 1010207;
 *     while (v8 != 1010208) {
 *       if (v8 == 1010208) { ... goto LABEL_13; }
 *       if (*v6) v8 = 1010206; else v8 = 1010208;
 *     }
 *
 * Constants:
 * - 1010206 = 0xF6A1E
 * - 1010207 = 0xF6A1F
 * - 1010208 = 0xF6A20
 * - 1010213 = 0xF6A25
 */

#include "ida_types.h"

/* External functions to prevent inlining */
extern int sub_D28B(int a1, char *v6, __int64 v7, __int64 v5);
extern void sub_216C8(__int64 a, __int64 b, char *c);
extern __int64 sub_258F0(char *v6);
extern __int64 sub_26A5ae(__int64 a2, int v4);

/* Volatile to prevent optimization */
volatile int approov_global_state = 0;
volatile uint64 approov_qword = 0;

/**
 * Real Approov pattern - uses while(!=) to generate jz instruction
 *
 * Pattern requirements for BadWhileLoop:
 * - Entry block: jz with constant in 0xF6000-0xF6FFF
 * - prevb: mov #magic, reg
 * - nextb: jz/jnz with constant in 0xF6000-0xF6FFF
 */
__int64 approov_real_pattern(int a1, __int64 a2)
{
    int v4;
    __int64 v5;
    char *v6;
    __int64 v7;
    int v8;
    int v10;

    v6 = (char *)a1;
    v10 = 0;

LABEL_13:
    v8 = 1010207;  /* 0xF6A1F - initial state */

    /* Use while(!=) to generate jz instruction like approov_multistate */
    while (v8 != 1010213)  /* 0xF6A25 - exit condition generates jz */
    {
        if (v8 == 1010208)  /* 0xF6A20 - process state */
        {
            if (!sub_D28B(a1, v6, v7, v5))
            {
                sub_216C8(101LL, 0LL, v6);
                v10 = 1;
            }
            v6 += sub_258F0(v6) + 1;
            goto LABEL_13;
        }
        else if (v8 == 1010207)  /* 0xF6A1F - initial state */
        {
            v5 = 1010213LL;  /* 0xF6A25 */
            if (*v6)
                v8 = 1010206;  /* 0xF6A1E */
            else
                v8 = 1010213;  /* 0xF6A25 - exit */
            v7 = 0LL;
            v4 = v10;
        }
        else if (v8 == 1010206)  /* 0xF6A1E - intermediate state */
        {
            v8 = 1010208;  /* 0xF6A20 - go to process */
        }
    }
    return sub_26A5ae(a2, v4);
}

/**
 * Simplified version of the real Approov pattern
 *
 * Same structure but self-contained (no external calls)
 * Uses while(!=) to generate jz instruction
 */
int approov_simplified(int input)
{
    int v4;
    int v8;
    int result;

    v4 = 0;
    result = input;

LABEL_ENTRY:
    v8 = 1010207;  /* 0xF6A1F */

    /* Use while(!=) to generate jz instruction like approov_multistate */
    while (v8 != 1010213)  /* 0xF6A25 - exit condition generates jz */
    {
        if (v8 == 1010208)  /* 0xF6A20 - process */
        {
            result = result + 10;
            v4 = 1;
            goto LABEL_ENTRY;
        }
        else if (v8 == 1010207)  /* 0xF6A1F - initial */
        {
            if (result > 50)
                v8 = 1010206;  /* 0xF6A1E */
            else
                v8 = 1010213;  /* 0xF6A25 - exit */
            v4 = result;
        }
        else if (v8 == 1010206)  /* 0xF6A1E - intermediate */
        {
            v8 = 1010208;  /* 0xF6A20 */
        }
    }
    return v4;
}

/**
 * Approov pattern with multiple state transitions
 *
 * More states to test comprehensive handling
 */
int approov_multistate(int a1, int a2)
{
    int state;
    int result;
    int temp;

    result = a1;
    temp = a2;

DISPATCH_ENTRY:
    state = 1010207;  /* 0xF6A1F - entry state */

    while (state != 1010213)  /* 0xF6A25 - final exit */
    {
        if (state == 1010206)  /* 0xF6A1E - state A */
        {
            result = result + temp;
            temp = temp - 1;
            if (temp > 0)
                state = 1010207;  /* back to entry */
            else
                state = 1010208;  /* to state B */
        }
        else if (state == 1010207)  /* 0xF6A1F - entry state */
        {
            if (result < 100)
                state = 1010206;  /* to state A */
            else
                state = 1010208;  /* to state B */
        }
        else if (state == 1010208)  /* 0xF6A20 - state B */
        {
            result = result * 2;
            if (result > 1000)
            {
                approov_global_state++;
                goto DISPATCH_ENTRY;  /* reset */
            }
            state = 1010213;  /* exit */
        }
    }
    return result;
}

/**
 * Approov VM dispatcher - the characteristic switch pattern
 */
__int64 approov_vm_dispatcher(int vm_context)
{
    int opcode;

    opcode = 1010207;  /* 0xF6A1F */

    while (1)
    {
        switch (opcode)
        {
            case 1010206:  /* 0xF6A1E */
                approov_global_state += vm_context;
                approov_qword |= 0x40;
                return (__int64)approov_qword;

            case 1010207:  /* 0xF6A1F */
                opcode = (int)(approov_qword |= 1010208);
                continue;

            case 1010208:  /* 0xF6A20 */
                approov_global_state = vm_context;
                opcode = 1010206;
                break;

            default:
                break;
        }
    }
}

/**
 * Approov pattern using goto for explicit control flow
 */
int approov_goto_dispatcher(int input)
{
    int state;
    int result;

    result = input;
    state = 1010207;  /* 0xF6A1F */

DISPATCHER:
    switch (state)
    {
        case 1010206:  /* 0xF6A1E */
            result = result + 10;
            state = 1010208;
            goto DISPATCHER;

        case 1010207:  /* 0xF6A1F */
            result = result * 2;
            state = 1010206;
            goto DISPATCHER;

        case 1010208:  /* 0xF6A20 */
            result = result - 5;
            state = 1010213;
            goto DISPATCHER;

        case 1010213:  /* 0xF6A25 - exit */
            return result;

        default:
            approov_global_state++;
            return -1;
    }
}

/**
 * Simple loop pattern - uses while(!=) like approov_multistate
 * The while(!=) generates jz which is what BadWhileLoop expects
 */
int approov_simple_loop(int input)
{
    int v1;
    int result;

    result = input;
    v1 = 1010207;  /* 0xF6A1F */

    /* Use while(!=) to generate jz instruction like approov_multistate */
    while (v1 != 1010213)  /* 0xF6A25 - exit condition generates jz */
    {
        if (v1 == 1010206)  /* 0xF6A1E */
        {
            result += 10;
            v1 = 1010208;
        }
        else if (v1 == 1010207)  /* 0xF6A1F */
        {
            result *= 2;
            v1 = 1010206;
        }
        else if (v1 == 1010208)  /* 0xF6A20 */
        {
            result -= 5;
            v1 = 1010213;
        }
        else
        {
            approov_global_state++;
            return -1;
        }
    }
    return result;
}
