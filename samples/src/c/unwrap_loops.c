#include "polyfill.h"

RTL_CRITICAL_SECTION g_mutex = {0};

extern void unk_1802CCC58(int);
extern int lolclose(unsigned __int64 hObject);
extern void sub_1800D3BF0(int, int, int, int, __int64);
extern void sub_180221640(unsigned __int64, int, int, unsigned __int64, int, int);

/**
 * @brief
 *
 * @param n0x59
 * @param n0xA
 * @param n0x48
 * @param a4
 *
 */
__int64 __fastcall SafeCloseHandle(
    int unusedParam1,
    int unusedParam2,
    int unusedParam3,
    unsigned __int64 hHandleToClose)
{
    int cleanupState;
    int finalState;
    unsigned __int64 hObject;

    for (cleanupState = 0;; cleanupState = 2)
    {
        while (1)
        {
            finalState = cleanupState;
            if (cleanupState)
                break;

            hObject = hHandleToClose;
            if (hHandleToClose == (unsigned __int64)0xFFFFFFFFFFFFFFFFULL)
                cleanupState = 2;
            else
                cleanupState = 1;
        }

        if (cleanupState != 1)
            break;

        lolclose(hObject);
        hHandleToClose = (unsigned __int64)0xFFFFFFFFFFFFFFFFULL;
    }

    return finalState;
}

void bogus_loops(int n0x59, int n0xA, int n0x48, unsigned int *a4)
{
    int i;           // [rsp+Ch] [rbp-Ch]
    unsigned int v5; // [rsp+14h] [rbp-4h]

    for (i = 0; !i; i = 1)
        v5 = *a4 ^ (*a4 << 0xD) ^ ((*a4 ^ (*a4 << 0xD)) >> 0x11);

    *a4 = v5 ^ (0x20 * v5);
}

__int64 unwrap_loops()
{
    int i;
    int v2;
    int result;

    for (i = 0;; i = 2)
    {
        while (1)
        {
            result = i;
            if (i)
                break;

            v2 = 0;
            if (!_InterlockedCompareExchange((volatile signed __int32 *)&g_mutex.SpinCount, 1, 0))
                goto LABEL_x379;

        LABEL_x2B0:
            i = 1;
        }

        if (i != 1)
            break;

        unk_1802CCC58(v2++ >= 0x20);
        if (_InterlockedCompareExchange((volatile signed __int32 *)&g_mutex.SpinCount, 1, 0))
            goto LABEL_x2B0;

    LABEL_x379:;
    }

    return result;
}

__int64 unwrap_loops_2(unsigned int n8, __int64 a2, int n0x4E, int n0x5F)
{
    int i;
    int v9;
    int v6;
    int result;

    for (i = 0;; i = 1)
    {
        while (1)
        {
            result = i;
            if (i)
                break;

            v9 = *(_DWORD *)(a2 + 0x14);
            if (v9 >= n8)
                i = 1;
            else
                i = 2;
        }

        if (i != 2)
            break;

        v6 = v9 + (v9 >> 1);
        if (v6 <= n8)
            v6 = n8;

        if (v6 < 9)
            v6 = 8;

        sub_1800D3BF0(6, 0x4D, 0x3B, v6, a2);
    }

    return result;
}

// Hidden C++ exception states: #wind=1
__int64 unwrap_loops_3(int n0x5C, unsigned int a2, int n0x53, int n9, __int64 a5)
{
    int v5;
    int v10;
    int v7;
    int v8;
    int v9;

    v5 = a2;
    if (a2)
    {
        v10 = 0;
        for (HIDWORD(v7) = 2;; HIDWORD(v7) = 2)
        {
            v9 = v10;
            sub_180221640(
                *(_QWORD *)(a5 + (v10 << 6) + 0x28),
                0xA,
                0x5E,
                *(_QWORD *)(a5 + (v10 << 6) + 0x30),
                0x45,
                v7);
            HIDWORD(v8) = 3;
            sub_180221640(
                *(_QWORD *)(a5 + (v10 << 6) + 0x10),
                0x62,
                0x2A,
                *(_QWORD *)(a5 + (v10 << 6) + 0x18),
                0x19,
                v8);
            ++v10;
            if (v9 + 1 == v5)
                break;
        }
    }

    return 4;
}
