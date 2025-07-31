/*
Currently flattening and folding results in this:

__int64 __fastcall sub_180001000(
        int n0x1C,
        int n0xC,
        int n0x19,
        syshdr::win::_EXCEPTION_POINTERS *exception)
{
    // [COLLAPSED LOCAL DECLARATIONS. PRESS NUMPAD "+" TO EXPAND]

    p_ContextRecord = &exception->ContextRecord;
    if ( (~exception->ContextRecord->ContextFlags & 0x100010) != 0 )
        return 1;

    v46 = __ROL8__(
              __ROL8__(
                  (((__ROL4__(__ROL4__(0x6EBCBAA1, 4) + 0x6B9F6F9A, 3) ^ 0x770BB7B8u) + 0x33AC85C6)
                 ^ 0x281C3663DA3197B5LL)
                + 0x3A9CCBED1AC47F6LL,
                  0x20)
            ^ 0xDE838D86533A540LL,
              0x3C);
    Dr0 = (*p_ContextRecord)->Dr0;
    v5 = __ROL8__(
             __ROL8__(
                 (((unsigned long)g_encDataRandomTable[((v46 >> 0x34) & 0xF)
                                                                        + 0x60] << 0x34)
                | (0x10LL * g_encDataRandomTable[((unsigned __int8)v46 >> 4) + 0x60])
                | ((unsigned long)g_encDataRandomTable[((v46 >> 0x28) & 0xF)
                                                                        + 0x60] << 0x28)
                | (g_encDataRandomTable[(((unsigned int)v46 >> 8) & 0xF) + 0x60] << 8)
                | ((unsigned long)g_encDataRandomTable[(v46 >> 0x3C) + 0x60] << 0x3C)
                | ((unsigned long)g_encDataRandomTable[((v46 >> 0x2C) & 0xF)
                                                                        + 0x60] << 0x2C)
                | (g_encDataRandomTable[(((unsigned int)v46 >> 0x14) & 0xF) + 0x60] << 0x14)
                | ((unsigned long)g_encDataRandomTable[(BYTE6(v46) & 0xF) + 0x60] << 0x30)
                | (g_encDataRandomTable[(BYTE3(v46) & 0xF) + 0x60] << 0x18)
                | (g_encDataRandomTable[((unsigned __int16)v46 >> 0xC) + 0x60] << 0xC)
                | ((unsigned long)g_encDataRandomTable[(HIBYTE(v46) & 0xF) + 0x60] << 0x38)
                | ((unsigned long)g_encDataRandomTable[(BYTE4(v46) & 0xF) + 0x60] << 0x20)
                | (g_encDataRandomTable[(BYTE2(v46) & 0xF) + 0x60] << 0x10)
                | ((unsigned long)g_encDataRandomTable[((unsigned int)v46 >> 0x1C)
                                                                        + 0x60] << 0x1C)
                | ((unsigned long)g_encDataRandomTable[((v46 >> 0x24) & 0xF)
                                                                        + 0x60] << 0x24)
                | g_encDataRandomTable[(v46 & 0xF) + 0x60])
               - 0x2662A2D5F43B2FCCLL,
                 0x2E),
             0x12)
       + 0x2662A2D5F43B2FCCLL;
    v15 = g_encDataRandomTable[(v5 & 0xF) + 0x50]
        | (g_encDataRandomTable[((unsigned __int16)v5 >> 0xC) + 0x50] << 0xC)
        | ((unsigned long)g_encDataRandomTable[(v5 >> 0x3C) + 0x50] << 0x3C)
        | (0x10
         * (unsigned int)g_encDataRandomTable[((unsigned __int8)v5 >> 4) + 0x50])
        | ((unsigned long)g_encDataRandomTable[((v5 >> 0x28) & 0xF) + 0x50] << 0x28)
        | (g_encDataRandomTable[(BYTE1(v5) & 0xF) + 0x50] << 8)
        | ((unsigned long)g_encDataRandomTable[((v5 >> 0x2C) & 0xF) + 0x50] << 0x2C)
        | (g_encDataRandomTable[(((unsigned int)v5 >> 0x14) & 0xF) + 0x50] << 0x14)
        | ((unsigned long)g_encDataRandomTable[(BYTE6(v5) & 0xF) + 0x50] << 0x30)
        | (g_encDataRandomTable[(BYTE3(v5) & 0xF) + 0x50] << 0x18)
        | ((unsigned long)g_encDataRandomTable[(HIBYTE(v5) & 0xF) + 0x50] << 0x38)
        | ((unsigned long)g_encDataRandomTable[(BYTE4(v5) & 0xF) + 0x50] << 0x20)
        | ((unsigned long)g_encDataRandomTable[(BYTE2(v5) & 0xF) + 0x50] << 0x10)
        | ((unsigned long)g_encDataRandomTable[((unsigned int)v5 >> 0x1C) + 0x50] << 0x1C)
        | ((unsigned long)g_encDataRandomTable[((v5 >> 0x24) & 0xF) + 0x50] << 0x24)
        | ((unsigned long)g_encDataRandomTable[((v5 >> 0x34) & 0xF) + 0x50] << 0x34);
    v47 = __ROL8__(v15, 4);
    if ( (qword_1802D2B19 ^ Dr0 ^ (__ROL8__(v47 ^ 0xDE838D86533A540LL, 0x20) - 0x3A9CCBED1AC47F6LL)) == 0x4F )
    {
        ContextRecord = *p_ContextRecord;
        Dr1 = (*p_ContextRecord)->Dr1;
        v48 = __ROL8__(v15, 4);
        if ( (qword_1802D2B19
            ^ Dr1
            ^ (__ROL8__(v48 ^ 0xDE838D86533A540LL, 0x20) - 0x3A9CCBED1AC47F6LL)) == 0x4F )
        {
            Dr2 = ContextRecord->Dr2;
            v49 = __ROL8__(v15, 4);
            if ( (qword_1802D2B19
                ^ Dr2
                ^ (__ROL8__(v49 ^ 0xDE838D86533A540LL, 0x20) - 0x3A9CCBED1AC47F6LL)) == 0x4F )
            {
                Dr3 = ContextRecord->Dr3;
                v50 = __ROL8__(v15, 4);
                if ( (qword_1802D2B19
                    ^ Dr3
                    ^ (__ROL8__(v50 ^ 0xDE838D86533A540LL, 0x20) - 0x3A9CCBED1AC47F6LL)) == 0x4F )
                    return 1;
            }
        }
    }

    v45 = __ROL4__(
              __ROL4__((__ROL4__(0xEF449E19, 0x10) + 0x500EBDB) ^ 0xA33ADB1F, 0x16) - 0x5D8D7E02,
              0x18);
    v51 = __ROL4__(
              __ROL4__(
                  qword_1802D2C51
                ^ (__ROL4__(
                       __ROL4__((__ROL4__(v45 + 0x2773BBB2, 6) ^ 0x74A2863C) - 0x1E9A0ECF, 0x15),
                       0xB)
                 + 0x1E9A0ECF)
                ^ 0x4F991284,
                  0x1A)
            - 0x2773BBB2,
              8)
        + 0x5D8D7E02;
    v22 = v51;
    v6 = (__ROL8__(
              (__ROL8__(
                   (((v1014 ^ v1805) + 0x61BBE9D7149134B0LL) ^ 0xDFEE542C76A7AAF0uLL)
                 - 0x1509678523D640EALL,
                   0xE)
             ^ 0xF0LL)
            - 0x57033546396F782ALL,
              0xE)
        + 0x7D019B7AE2EB4B6FLL)
       ^ 0x2EFFBB12A651F46CLL;
    if ( (unsigned int)outlined_helper_1(
                           0x51,
                           0x1E,
                           0x2D,
                           (unsigned int *)(__ROL8__(
                                                ((unsigned long)g_encDataRandomTable[((unsigned int)v6 >> 0x1C) + 0x70] << 0x1C)
                                              | (g_encDataRandomTable[(((unsigned int)v6 >> 0x14) & 0xF) + 0x70] << 0x14)
                                              | ((unsigned long)g_encDataRandomTable[((v6 >> 0x34) & 0xF) + 0x70] << 0x34)
                                              | ((unsigned long)g_encDataRandomTable[(v6 >> 0x3C) + 0x70] << 0x3C)
                                              | (g_encDataRandomTable[(((unsigned int)v6 >> 8) & 0xF) + 0x70] << 8)
                                              | (g_encDataRandomTable[(BYTE3(v6) & 0xF) + 0x70] << 0x18)
                                              | ((unsigned long)g_encDataRandomTable[((v6 >> 0x24) & 0xF) + 0x70] << 0x24)
                                              | (0x10
                                               * (unsigned int)g_encDataRandomTable[((unsigned __int8)v6 >> 4) + 0x70])
                                              | ((unsigned long)g_encDataRandomTable[(BYTE4(v6) & 0xF) + 0x70] << 0x20)
                                              | ((unsigned long)g_encDataRandomTable[((v6 >> 0x2C) & 0xF) + 0x70] << 0x2C)
                                              | (g_encDataRandomTable[((unsigned __int16)v6 >> 0xC) + 0x70] << 0xC)
                                              | ((unsigned long)g_encDataRandomTable[(HIBYTE(v6) & 0xF) + 0x70] << 0x38)
                                              | (g_encDataRandomTable[(BYTE2(v6) & 0xF) + 0x70] << 0x10)
                                              | ((unsigned long)g_encDataRandomTable[(BYTE5(v6) & 0xF) + 0x70] << 0x28)
                                              | ((unsigned long)g_encDataRandomTable[(BYTE6(v6) & 0xF) + 0x70] << 0x30)
                                              | g_encDataRandomTable[(v6 & 0xF) + 0x70],
                                                0x2B)
                                          + 0x8CLL)) == __ROL4__(
                                                            __ROL4__(0xB10E2EB7, 0x1E) ^ 0xBAB0DDC4,
                                                            0x1D) )
    {
        v7 = (__ROL8__(
                  (__ROL8__(
                       (((v1014 ^ v1805) + 0x61BBE9D7149134B0LL) ^ 0xDFEE542C76A7AAF0uLL)
                     - 0x1509678523D640EALL,
                       0xE)
                 ^ 0xF0LL)
                - 0x57033546396F782ALL,
                  0xE)
            + 0x7D019B7AE2EB4B6FLL)
           ^ 0x2EFFBB12A651F46CLL;
        v31 = __ROL8__(
                  ((unsigned long)g_encDataRandomTable[((unsigned int)v7 >> 0x1C)
                                                                        + 0x70] << 0x1C)
                | ((unsigned long)g_encDataRandomTable[(BYTE5(v7) & 0xF) + 0x70] << 0x28)
                | ((unsigned long)g_encDataRandomTable[(v7 >> 0x3C) + 0x70] << 0x3C)
                | (g_encDataRandomTable[(((unsigned int)v7 >> 8) & 0xF) + 0x70] << 8)
                | (g_encDataRandomTable[(BYTE3(v7) & 0xF) + 0x70] << 0x18)
                | ((unsigned long)g_encDataRandomTable[((v7 >> 0x24) & 0xF)
                                                                        + 0x70] << 0x24)
                | (0x10
                 * (unsigned int)g_encDataRandomTable[((unsigned __int8)v7 >> 4)
                                                                    + 0x70])
                | ((unsigned long)g_encDataRandomTable[((v7 >> 0x34) & 0xF)
                                                                        + 0x70] << 0x34)
                | ((unsigned long)g_encDataRandomTable[(BYTE4(v7) & 0xF) + 0x70] << 0x20)
                | ((unsigned long)g_encDataRandomTable[((v7 >> 0x2C) & 0xF)
                                                                        + 0x70] << 0x2C)
                | ((unsigned long)g_encDataRandomTable[(((unsigned int)v7 >> 0x14)
                                                                         & 0xF)
                                                                        + 0x70] << 0x14)
                | (g_encDataRandomTable[((unsigned __int16)v7 >> 0xC) + 0x70] << 0xC)
                | ((unsigned long)g_encDataRandomTable[(HIBYTE(v7) & 0xF) + 0x70] << 0x38)
                | (g_encDataRandomTable[(BYTE2(v7) & 0xF) + 0x70] << 0x10)
                | ((unsigned long)g_encDataRandomTable[(BYTE6(v7) & 0xF) + 0x70] << 0x30)
                | g_encDataRandomTable[(v7 & 0xF) + 0x70],
                  0x2B);
        v32 = __ROL8__(
                  (__ROL8__(
                       (((__ROL8__(0xAFD87C7224F64144uLL, 2) - 0x4492141EEFDBF1ALL)
                       ^ 0xAEBFE7573B59B0CDuLL)
                      - 0x15A737D11F84F535LL)
                     ^ 0x65,
                       0x38)
                 ^ 0x9F7C0F65EF8A2AALL)
                - 0x49AE6B1EC26FFFC0LL,
                  0x2F)
            - 0x7605BC927F8FF8DLL;
        v23 = __ROL4__(
                  __ROL4__(
                      *(_DWORD *)((__ROL8__(
                                       (__ROL8__(v32 + 0x7605BC927F8FF8DLL, 0x11)
                                      + 0x49AE6B1EC26FFFC0LL)
                                     ^ *(__int64 *)((char *)&qword_1802D2C99 + 2)
                                     ^ 0x12A31EF5AA976FA7LL,
                                       8)
                                 ^ 0x65LL)
                                + 4),
                      0x1D),
                  2);
        v10 = v23 ^ 0x88A8C6E5;
        v37 = __ROL4__(
                  __ROL4__(
                      ((g_encDataRandomTable[(v10 >> 0x1C) + 0x80] << 0x1C)
                     | (0x10
                      * g_encDataRandomTable[((unsigned __int8)(v23 ^ 0xE5) >> 4)
                                                           + 0x80])
                     | g_encDataRandomTable[(((unsigned __int8)v23 ^ 0xE5) & 0xF)
                                                          + 0x80]
                     | (g_encDataRandomTable[((unsigned __int16)v10 >> 0xC) + 0x80] << 0xC)
                     | (g_encDataRandomTable[(((unsigned int)v10 >> 0x14) & 0xF)
                                                           + 0x80] << 0x14)
                     | (g_encDataRandomTable[(BYTE1(v10) & 0xF) + 0x80] << 8)
                     | (g_encDataRandomTable[(BYTE2(v10) & 0xF) + 0x80] << 0x10)
                     | (g_encDataRandomTable[(BYTE3(v10) & 0xF) + 0x80] << 0x18))
                    - 0x25288DCE,
                      0x17)
                - 0x709572C9,
                  2);
        a3 = ((__ROL8__(
                   (__ROL8__(
                        *(_QWORD *)((__ROL8__(
                                         *(__int64 *)((char *)&qword_1802D2C99 + 2)
                                       ^ (__ROL8__(v32 + 0x7605BC927F8FF8DLL, 0x11)
                                        + 0x49AE6B1EC26FFFC0LL)
                                       ^ 0x12A31EF5AA976FA7LL,
                                         8)
                                   ^ 0x65LL)
                                  + 0x320)
                      ^ 0x65LL,
                        0x38)
                  ^ 0x9F7C0F65EF8A2AALL)
                 - 0x49AE6B1EC26FFFC0LL,
                   0x2F)
             - 0x6A8D0E53289361BCLL)
            ^ 0xA64FEBFB4B051FDEuLL)
           - 0x646810A5E064C719LL;
        a3 = ((a3 + 0x646810A5E064C719LL) ^ 0xA64FEBFB4B051FDEuLL) + 0x632CB28A009A622FLL;
        v33 = __ROL8__(
                  *(__int64 *)((char *)&qword_1802D2C99 + 2)
                ^ (__ROL8__(a3 + 0x7605BC927F8FF8DLL, 0x11) + 0x49AE6B1EC26FFFC0LL)
                ^ 0x12A31EF5AA976FA7LL,
                  8)
            ^ 0x65LL;
        outlined_helper_2(&v37);
        v9 = (unsigned int)(v37 - 0x45EEEDD7);
        v39 = __ROL8__(
                  __ROL8__(
                      (v33
                     * (unsigned int)__ROL4__(
                                         dword_1802D2E48
                                       ^ ((g_encDataRandomTable[(BYTE2(v9) & 0xF) + 0x90] << 0x10)
                                        | g_encDataRandomTable[(((_BYTE)v37 + 0x29)
                                                                              & 0xF)
                                                                             + 0x90]
                                        | (g_encDataRandomTable[((unsigned __int16)v9 >> 0xC) + 0x90] << 0xC)
                                        | (0x10
                                         * g_encDataRandomTable[((unsigned __int8)(v37 + 0x29) >> 4) + 0x90])
                                        | (g_encDataRandomTable[(((unsigned int)v9 >> 0x14) & 0xF) + 0x90] << 0x14)
                                        | (g_encDataRandomTable[(v9 >> 0x1C) + 0x90] << 0x1C)
                                        | (g_encDataRandomTable[(BYTE1(v9) & 0xF) + 0x90] << 8)
                                        | (g_encDataRandomTable[(BYTE3(v9) & 0xF) + 0x90] << 0x18)),
                                         1))
                    ^ 0x9BD8FE58859C535FuLL,
                      0x2A)
                - 0x13BC3E8B476C15C4LL,
                  0x2A);
        v39 -= 0x5EDBD69FE0AFCFEALL;
        v25 = (g_encDataRandomTable[(BYTE3(v39) & 0xF) + 0xA0] << 0x18)
            | (unsigned long)(g_encDataRandomTable[((unsigned __int16)v39 >> 0xC)
                                                                    + 0xA0] << 0xC)
            | ((unsigned long)g_encDataRandomTable[(BYTE6(v39) & 0xF) + 0xA0] << 0x30)
            | (0x10
             * (unsigned int)g_encDataRandomTable[((unsigned __int8)v39 >> 4) + 0xA0])
            | ((unsigned long)g_encDataRandomTable[(HIBYTE(v39) & 0xF) + 0xA0] << 0x38)
            | ((unsigned long)g_encDataRandomTable[(BYTE2(v39) & 0xF) + 0xA0] << 0x10);
        v26 = v25
            | ((unsigned long)g_encDataRandomTable[(v39 >> 0x3C) + 0xA0] << 0x3C);
        v11 = v26
            | ((unsigned long)g_encDataRandomTable[((v39 >> 0x2C) & 0xF) + 0xA0] << 0x2C)
            | (g_encDataRandomTable[(BYTE1(v39) & 0xF) + 0xA0] << 8);
        v16 = v11 | g_encDataRandomTable[(v39 & 0xF) + 0xA0];
        v17 = v16
            | (g_encDataRandomTable[(((unsigned int)v39 >> 0x14) & 0xF) + 0xA0] << 0x14)
            | ((unsigned long)g_encDataRandomTable[(BYTE4(v39) & 0xF) + 0xA0] << 0x20);
        v12 = v17
            | ((unsigned long)g_encDataRandomTable[((v39 >> 0x24) & 0xF) + 0xA0] << 0x24)
            | ((unsigned long)g_encDataRandomTable[((v39 >> 0x34) & 0xF) + 0xA0] << 0x34);
        v18 = v12
            | ((unsigned long)g_encDataRandomTable[(BYTE5(v39) & 0xF) + 0xA0] << 0x28)
            | ((unsigned long)g_encDataRandomTable[((unsigned int)v39 >> 0x1C)
                                                                    + 0xA0] << 0x1C);
        v41 = ((unsigned long)g_encDataRandomTable[((v12 >> 0x34) & 0xF) + 0xB0] << 0x34)
            | ((unsigned long)g_encDataRandomTable[(v26 >> 0x3C) + 0xB0] << 0x3C)
            | (0x10
             * (unsigned int)g_encDataRandomTable[((unsigned __int8)v16 >> 4) + 0xB0])
            | ((unsigned long)g_encDataRandomTable[(BYTE3(v17) & 0xF) + 0xB0] << 0x18)
            | (g_encDataRandomTable[((unsigned __int16)v11 >> 0xC) + 0xB0] << 0xC)
            | ((unsigned long)g_encDataRandomTable[(BYTE6(v11) & 0xF) + 0xB0] << 0x30)
            | ((unsigned long)g_encDataRandomTable[(HIBYTE(v12) & 0xF) + 0xB0] << 0x38)
            | (g_encDataRandomTable[(BYTE2(v25) & 0xF) + 0xB0] << 0x10)
            | ((unsigned long)g_encDataRandomTable[((v18 >> 0x2C) & 0xF) + 0xB0] << 0x2C)
            | (g_encDataRandomTable[(BYTE1(v11) & 0xF) + 0xB0] << 8)
            | g_encDataRandomTable[(v16 & 0xF) + 0xB0]
            | ((unsigned long)g_encDataRandomTable[(((unsigned int)v17 >> 0x14)
                                                                     & 0xF)
                                                                    + 0xB0] << 0x14)
            | ((unsigned long)g_encDataRandomTable[(BYTE4(v18) & 0xF) + 0xB0] << 0x20)
            | ((unsigned long)g_encDataRandomTable[((v12 >> 0x24) & 0xF) + 0xB0] << 0x24)
            | ((unsigned long)g_encDataRandomTable[(BYTE5(v18) & 0xF) + 0xB0] << 0x28)
            | ((unsigned long)g_encDataRandomTable[((unsigned int)v18 >> 0x1C)
                                                                    + 0xB0] << 0x1C);
        v41 += 0x5EDBD69FE0AFCFEALL;
        v40 = __ROL8__(
                  __ROL8__(
                      ((v1702 ^ __ROL8__(__ROL8__(v41, 0x16) + 0x13BC3E8B476C15C4LL, 0x16) ^ 0x2BuLL) >> __ROL4__(__ROL4__(0xEB5EB44B, 0x1D) - 0x7D6BD67D, 1))
                    ^ 0x9BD8FE58859C535FuLL,
                      0x2A)
                - 0x13BC3E8B476C15C4LL,
                  0x2A);
        v40 -= 0x5EDBD69FE0AFCFEALL;
        v27 = (g_encDataRandomTable[(BYTE3(v40) & 0xF) + 0xA0] << 0x18)
            | (unsigned long)(g_encDataRandomTable[((unsigned __int16)v40 >> 0xC)
                                                                    + 0xA0] << 0xC)
            | ((unsigned long)g_encDataRandomTable[(BYTE6(v40) & 0xF) + 0xA0] << 0x30)
            | (0x10
             * (unsigned int)g_encDataRandomTable[((unsigned __int8)v40 >> 4) + 0xA0])
            | ((unsigned long)g_encDataRandomTable[(HIBYTE(v40) & 0xF) + 0xA0] << 0x38)
            | (g_encDataRandomTable[(BYTE2(v40) & 0xF) + 0xA0] << 0x10);
        v28 = v27
            | ((unsigned long)g_encDataRandomTable[(v40 >> 0x3C) + 0xA0] << 0x3C);
        v13 = v28
            | ((unsigned long)g_encDataRandomTable[((v40 >> 0x2C) & 0xF) + 0xA0] << 0x2C)
            | (g_encDataRandomTable[(BYTE1(v40) & 0xF) + 0xA0] << 8);
        v19 = v13 | g_encDataRandomTable[(v40 & 0xF) + 0xA0];
        v20 = v19
            | ((unsigned long)g_encDataRandomTable[(((unsigned int)v40 >> 0x14)
                                                                     & 0xF)
                                                                    + 0xA0] << 0x14)
            | ((unsigned long)g_encDataRandomTable[(BYTE4(v40) & 0xF) + 0xA0] << 0x20);
        v14 = v20
            | ((unsigned long)g_encDataRandomTable[((v40 >> 0x24) & 0xF) + 0xA0] << 0x24)
            | ((unsigned long)g_encDataRandomTable[((v40 >> 0x34) & 0xF) + 0xA0] << 0x34);
        v21 = v14
            | ((unsigned long)g_encDataRandomTable[(BYTE5(v40) & 0xF) + 0xA0] << 0x28)
            | ((unsigned long)g_encDataRandomTable[((unsigned int)v40 >> 0x1C)
                                                                    + 0xA0] << 0x1C);
        v42 = g_encDataRandomTable[(v19 & 0xF) + 0xB0]
            | (g_encDataRandomTable[(BYTE3(v20) & 0xF) + 0xB0] << 0x18)
            | (unsigned long)(g_encDataRandomTable[((unsigned __int16)v13 >> 0xC)
                                                                    + 0xB0] << 0xC)
            | ((unsigned long)g_encDataRandomTable[(BYTE6(v13) & 0xF) + 0xB0] << 0x30)
            | (0x10LL * g_encDataRandomTable[((unsigned __int8)v19 >> 4) + 0xB0])
            | ((unsigned long)g_encDataRandomTable[(HIBYTE(v14) & 0xF) + 0xB0] << 0x38)
            | (g_encDataRandomTable[(BYTE2(v27) & 0xF) + 0xB0] << 0x10)
            | ((unsigned long)g_encDataRandomTable[(v28 >> 0x3C) + 0xB0] << 0x3C)
            | ((unsigned long)g_encDataRandomTable[((v21 >> 0x2C) & 0xF) + 0xB0] << 0x2C)
            | (g_encDataRandomTable[(BYTE1(v13) & 0xF) + 0xB0] << 8)
            | (g_encDataRandomTable[(((unsigned int)v20 >> 0x14) & 0xF) + 0xB0] << 0x14)
            | ((unsigned long)g_encDataRandomTable[(BYTE4(v21) & 0xF) + 0xB0] << 0x20)
            | ((unsigned long)g_encDataRandomTable[((v14 >> 0x24) & 0xF) + 0xB0] << 0x24)
            | ((unsigned long)g_encDataRandomTable[((v14 >> 0x34) & 0xF) + 0xB0] << 0x34)
            | ((unsigned long)g_encDataRandomTable[(BYTE5(v21) & 0xF) + 0xB0] << 0x28)
            | ((unsigned long)g_encDataRandomTable[((unsigned int)v21 >> 0x1C)
                                                                    + 0xB0] << 0x1C);
        v42 += 0x5EDBD69FE0AFCFEALL;
        v43 = __ROL4__(
                  __ROL4__(
                      v1702
                    ^ __ROL8__(__ROL8__(v42, 0x16) + 0x13BC3E8B476C15C4LL, 0x16)
                    ^ 0x4A49784E,
                      0x15),
                  0xB);
        v43 = __ROL4__(__ROL4__(v43 ^ 0x24E79C6B, 9) - 0x7E716580, 0x13);
        v43 = __ROL4__(__ROL4__(v43, 0xD) + 0x7E716580, 0x17) ^ 0x24E79C6B;
        v44 = __ROL4__(
                  ((__ROL4__(__ROL4__(v43 ^ dword_1802D2DBC ^ 0xBE8137A1, 0x18), 0x12) ^ 0x7A6EDE8D)
                 - 0x63F55234)
                ^ 0x39FBAC8C,
                  0x13);
        _InterlockedExchangeW(0x30, 0x63, 0x4D, (v44 - 0x6976D47F) ^ 0x10262F9D, v31 + 0x58);
        v8 = (__ROL8__(
                  (__ROL8__(
                       (((v1014 ^ v1805) + 0x61BBE9D7149134B0LL) ^ 0xDFEE542C76A7AAF0uLL)
                     - 0x1509678523D640EALL,
                       0xE)
                 ^ 0xF0LL)
                - 0x57033546396F782ALL,
                  0xE)
            + 0x7D019B7AE2EB4B6FLL)
           ^ 0x2EFFBB12A651F46CLL;
        _InterlockedExchangeW(
            0x37,
            0xF,
            1,
            __ROL4__(
                __ROL4__(__ROL4__((v22 ^ 0xB341EFE5) - 0x6D0B6F70, 0x1E) ^ 0xE0838EAA, 0x1E)
              ^ 0xBAB0DDC4,
                0x1D),
            __ROL8__(
                ((unsigned long)g_encDataRandomTable[((v8 >> 0x2C) & 0xF) + 0x70] << 0x2C)
              | ((unsigned long)g_encDataRandomTable[(v8 >> 0x3C) + 0x70] << 0x3C)
              | (g_encDataRandomTable[(((unsigned int)v8 >> 8) & 0xF) + 0x70] << 8)
              | ((unsigned long)g_encDataRandomTable[(BYTE3(v8) & 0xF) + 0x70] << 0x18)
              | ((unsigned long)g_encDataRandomTable[((v8 >> 0x24) & 0xF) + 0x70] << 0x24)
              | (0x10
               * (unsigned int)g_encDataRandomTable[((unsigned __int8)v8 >> 4)
                                                                  + 0x70])
              | ((unsigned long)g_encDataRandomTable[((v8 >> 0x34) & 0xF) + 0x70] << 0x34)
              | ((unsigned long)g_encDataRandomTable[(BYTE4(v8) & 0xF) + 0x70] << 0x20)
              | (g_encDataRandomTable[(((unsigned int)v8 >> 0x14) & 0xF) + 0x70] << 0x14)
              | (g_encDataRandomTable[((unsigned __int16)v8 >> 0xC) + 0x70] << 0xC)
              | ((unsigned long)g_encDataRandomTable[(HIBYTE(v8) & 0xF) + 0x70] << 0x38)
              | (g_encDataRandomTable[(BYTE2(v8) & 0xF) + 0x70] << 0x10)
              | ((unsigned long)g_encDataRandomTable[(BYTE5(v8) & 0xF) + 0x70] << 0x28)
              | ((unsigned long)g_encDataRandomTable[(BYTE6(v8) & 0xF) + 0x70] << 0x30)
              | ((unsigned long)g_encDataRandomTable[((unsigned int)v8 >> 0x1C)
                                                                      + 0x70] << 0x1C)
              | g_encDataRandomTable[(v8 & 0xF) + 0x70],
                0x2B)
          + 0x8CLL);
    }

    return 1;
}
*/

#include "ida_types.h"

/* 62 */
enum AccessMask
{
  Delete = 0x10000,
  ReadControl = 0x20000,
  WriteDac = 0x40000,
  WriteOwner = 0x80000,
  Synchronize = 0x100000,
  StandardRightsRequired = 0xF0000,
  StandardRightsRead = 0x20000,
  StandardRightsWrite = 0x20000,
  StandardRightsExecute = 0x20000,
  StandardRightsAll = 0x1F0000,
  SpecificRightsAll = 0xFFFF,
  AccessSystemSecurity = 0x1000000,
  MaximumAllowed = 0x2000000,
  GenericRead = 0x80000000,
  GenericWrite = 0x40000000,
  GenericExecute = 0x20000000,
  GenericAll = 0x10000000,
  FileReadData = 0x1,
  FileListDirectory = 0x1,
  FileWriteData = 0x2,
  FileAddFile = 0x2,
  FileAppendData = 0x4,
  FileAddSubdirectory = 0x4,
  FileCreatePipeInstance = 0x4,
  FileReadEa = 0x8,
  FileWriteEa = 0x10,
  FileExecute = 0x20,
  FileTraverse = 0x20,
  FileDeleteChild = 0x40,
  FileReadAttributes = 0x80,
  FileWriteAttributes = 0x100,
  FileAllAccess = 0x1F01FF,
  FileGenericRead = 0x120089,
  FileGenericWrite = 0x120116,
  FileGenericExecute = 0x1200A0,
  DirectoryQuery = 0x1,
  DirectoryTraverse = 0x2,
  DirectoryCreateObject = 0x4,
  DirectoryCreateSubDirectory = 0x8,
  DirectoryAllAccess = 0xF000F,
  ProcessTerminate = 0x1,
  ProcessCreateThread = 0x2,
  ProcessSetSessionId = 0x4,
  ProcessVmOperation = 0x8,
  ProcessVmRead = 0x10,
  ProcessVmWrite = 0x20,
  ProcessDupHandle = 0x40,
  ProcessCreateProcess = 0x80,
  ProcessSetQuota = 0x100,
  ProcessSetInformation = 0x200,
  ProcessQueryInformation = 0x400,
  ProcessSuspendResume = 0x800,
  ProcessQueryLimitedInformation = 0x1000,
  ProcessSetLimitedInformation = 0x2000,
  ProcessAllAccess = 0x1F0FFF,
  ProcessAllAccessEx = 0x1FFFFF,
  ThreadTerminate = 0x1,
  ThreadSuspendResume = 0x2,
  ThreadGetContext = 0x8,
  ThreadSetContext = 0x10,
  ThreadQueryInformation = 0x40,
  ThreadSetInformation = 0x20,
  ThreadSetThreadToken = 0x80,
  ThreadImpersonate = 0x100,
  ThreadDirectImpersonate = 0x200,
  ThreadSetLimitedInformation = 0x400,
  ThreadQueryLimitedInformation = 0x800,
  ThreadResume = 0x1000,
  ThreadAllAccess = 0x1F3FFF,
  ThreadAllAccessEx = 0x1FFFFF,
  SectionQuery = 0x1,
  SectionMapWrite = 0x2,
  SectionMapRead = 0x4,
  SectionMapExecute = 0x8,
  SectionExtendSize = 0x10,
  SectionMapExecuteExplicit = 0x20,
  SectionAllAccess = 0xF001F,
  FileMapWrite = 0x2,
  FileMapRead = 0x4,
  FileMapAllAccess = 0xF001F,
  FileMapExecute = 0x20,
  FileMapCopy = 0x1,
  FileMapReserve = 0x80000000,
  FileMapTargetsInvalid = 0x40000000,
  FileMapLargePages = 0x20000000
};
enum NtStatus 
{
  Success = 0x0,
  Wait0 = 0x0,
  Wait1 = 0x1,
  Wait2 = 0x2,
  Wait3 = 0x3,
  Wait63 = 0x3F,
  Abandoned = 0x80,
  AbandonedWait0 = 0x80,
  AbandonedWait63 = 0xBF,
  UserApc = 0xC0,
  Alerted = 0x101,
  Timeout = 0x102,
  Pending = 0x103,
  Reparse = 0x104,
  MoreEntries = 0x105,
  NotAllAssigned = 0x106,
  SomeNotMapped = 0x107,
  OplockBreakInProgress = 0x108,
  VolumeMounted = 0x109,
  RxactCommitted = 0x10A,
  NotifyCleanup = 0x10B,
  NotifyEnumDir = 0x10C,
  NoQuotasForAccount = 0x10D,
  PrimaryTransportConnectFailed = 0x10E,
  PageFaultTransition = 0x110,
  PageFaultDemandZero = 0x111,
  PageFaultCopyOnWrite = 0x112,
  PageFaultGuardPage = 0x113,
  PageFaultPagingFile = 0x114,
  CachePageLocked = 0x115,
  CrashDump = 0x116,
  BufferAllZeros = 0x117,
  ReparseObject = 0x118,
  ResourceRequirementsChanged = 0x119,
  TranslationComplete = 0x120,
  DsMembershipEvaluatedLocally = 0x121,
  NothingToTerminate = 0x122,
  ProcessNotInJob = 0x123,
  ProcessInJob = 0x124,
  VolsnapHibernateReady = 0x125,
  FsfilterOpCompletedSuccessfully = 0x126,
  InterruptVectorAlreadyConnected = 0x127,
  InterruptStillConnected = 0x128,
  ProcessCloned = 0x129,
  FileLockedWithOnlyReaders = 0x12A,
  FileLockedWithWriters = 0x12B,
  ResourcemanagerReadOnly = 0x202,
  WaitForOplock = 0x367,
  DbgExceptionHandled = 0x10001,
  DbgContinue = 0x10002,
  FltIoComplete = 0x1C0001,
  ObjectNameExists = 0x40000000,
  ThreadWasSuspended = 0x40000001,
  WorkingSetLimitRange = 0x40000002,
  ImageNotAtBase = 0x40000003,
  RxactStateCreated = 0x40000004,
  SegmentNotification = 0x40000005,
  LocalUserSessionKey = 0x40000006,
  BadCurrentDirectory = 0x40000007,
  SerialMoreWrites = 0x40000008,
  RegistryRecovered = 0x40000009,
  FtReadRecoveryFromBackup = 0x4000000A,
  FtWriteRecovery = 0x4000000B,
  SerialCounterTimeout = 0x4000000C,
  NullLmPassword = 0x4000000D,
  ImageMachineTypeMismatch = 0x4000000E,
  ReceivePartial = 0x4000000F,
  ReceiveExpedited = 0x40000010,
  ReceivePartialExpedited = 0x40000011,
  EventDone = 0x40000012,
  EventPending = 0x40000013,
  CheckingFileSystem = 0x40000014,
  FatalAppExit = 0x40000015,
  PredefinedHandle = 0x40000016,
  WasUnlocked = 0x40000017,
  ServiceNotification = 0x40000018,
  WasLocked = 0x40000019,
  LogHardError = 0x4000001A,
  AlreadyWin32 = 0x4000001B,
  Wx86Unsimulate = 0x4000001C,
  Wx86Continue = 0x4000001D,
  Wx86SingleStep = 0x4000001E,
  Wx86Breakpoint = 0x4000001F,
  Wx86ExceptionContinue = 0x40000020,
  Wx86ExceptionLastchance = 0x40000021,
  Wx86ExceptionChain = 0x40000022,
  ImageMachineTypeMismatchExe = 0x40000023,
  NoYieldPerformed = 0x40000024,
  TimerResumeIgnored = 0x40000025,
  ArbitrationUnhandled = 0x40000026,
  CardbusNotSupported = 0x40000027,
  Wx86Createwx86tib = 0x40000028,
  MpProcessorMismatch = 0x40000029,
  Hibernated = 0x4000002A,
  ResumeHibernation = 0x4000002B,
  FirmwareUpdated = 0x4000002C,
  DriversLeakingLockedPages = 0x4000002D,
  MessageRetrieved = 0x4000002E,
  SystemPowerstateTransition = 0x4000002F,
  AlpcCheckCompletionList = 0x40000030,
  SystemPowerstateComplexTransition = 0x40000031,
  AccessAuditByPolicy = 0x40000032,
  AbandonHiberfile = 0x40000033,
  BizrulesNotEnabled = 0x40000034,
  WakeSystem = 0x40000294,
  DsShuttingDown = 0x40000370,
  DbgReplyLater = 0x40010001,
  DbgUnableToProvideHandle = 0x40010002,
  DbgTerminateThread = 0x40010003,
  DbgTerminateProcess = 0x40010004,
  DbgControlC = 0x40010005,
  DbgPrintexceptionC = 0x40010006,
  DbgRipexception = 0x40010007,
  DbgControlBreak = 0x40010008,
  DbgCommandException = 0x40010009,
  RpcNtUuidLocalOnly = 0x40020056,
  RpcNtSendIncomplete = 0x400200AF,
  CtxCdmConnect = 0x400A0004,
  CtxCdmDisconnect = 0x400A0005,
  SxsReleaseActivationContext = 0x4015000D,
  RecoveryNotNeeded = 0x40190034,
  RmAlreadyStarted = 0x40190035,
  LogNoRestart = 0x401A000C,
  VideoDriverDebugReportRequest = 0x401B00EC,
  GraphicsPartialDataPopulated = 0x401E000A,
  GraphicsDriverMismatch = 0x401E0117,
  GraphicsModeNotPinned = 0x401E0307,
  GraphicsNoPreferredMode = 0x401E031E,
  GraphicsDatasetIsEmpty = 0x401E034B,
  GraphicsNoMoreElementsInDataset = 0x401E034C,
  GraphicsPathContentGeometryTransformationNotPinned = 0x401E0351,
  GraphicsUnknownChildStatus = 0x401E042F,
  GraphicsLeadlinkStartDeferred = 0x401E0437,
  GraphicsPollingTooFrequently = 0x401E0439,
  GraphicsStartDeferred = 0x401E043A,
  NdisIndicationRequired = 0x40230001,
  GuardPageViolation = 0x80000001,
  DatatypeMisalignment = 0x80000002,
  Breakpoint = 0x80000003,
  SingleStep = 0x80000004,
  BufferOverflow = 0x80000005,
  NoMoreFiles = 0x80000006,
  WakeSystemDebugger = 0x80000007,
  HandlesClosed = 0x8000000A,
  NoInheritance = 0x8000000B,
  GuidSubstitutionMade = 0x8000000C,
  PartialCopy = 0x8000000D,
  DevicePaperEmpty = 0x8000000E,
  DevicePoweredOff = 0x8000000F,
  DeviceOffLine = 0x80000010,
  DeviceBusy = 0x80000011,
  NoMoreEas = 0x80000012,
  InvalidEaName = 0x80000013,
  EaListInconsistent = 0x80000014,
  InvalidEaFlag = 0x80000015,
  VerifyRequired = 0x80000016,
  ExtraneousInformation = 0x80000017,
  RxactCommitNecessary = 0x80000018,
  NoMoreEntries = 0x8000001A,
  FilemarkDetected = 0x8000001B,
  MediaChanged = 0x8000001C,
  BusReset = 0x8000001D,
  EndOfMedia = 0x8000001E,
  BeginningOfMedia = 0x8000001F,
  MediaCheck = 0x80000020,
  SetmarkDetected = 0x80000021,
  NoDataDetected = 0x80000022,
  RedirectorHasOpenHandles = 0x80000023,
  ServerHasOpenHandles = 0x80000024,
  AlreadyDisconnected = 0x80000025,
  Longjump = 0x80000026,
  CleanerCartridgeInstalled = 0x80000027,
  PlugplayQueryVetoed = 0x80000028,
  UnwindConsolidate = 0x80000029,
  RegistryHiveRecovered = 0x8000002A,
  DllMightBeInsecure = 0x8000002B,
  DllMightBeIncompatible = 0x8000002C,
  StoppedOnSymlink = 0x8000002D,
  DeviceRequiresCleaning = 0x80000288,
  DeviceDoorOpen = 0x80000289,
  DataLostRepair = 0x80000803,
  DbgExceptionNotHandled = 0x80010001,
  ClusterNodeAlreadyUp = 0x80130001,
  ClusterNodeAlreadyDown = 0x80130002,
  ClusterNetworkAlreadyOnline = 0x80130003,
  ClusterNetworkAlreadyOffline = 0x80130004,
  ClusterNodeAlreadyMember = 0x80130005,
  CouldNotResizeLog = 0x80190009,
  NoTxfMetadata = 0x80190029,
  CantRecoverWithHandleOpen = 0x80190031,
  TxfMetadataAlreadyPresent = 0x80190041,
  TransactionScopeCallbacksNotSet = 0x80190042,
  VideoHungDisplayDriverThreadRecovered = 0x801B00EB,
  FltBufferTooSmall = 0x801C0001,
  FvePartialMetadata = 0x80210001,
  FveTransientState = 0x80210002,
  Unsuccessful = 0xC0000001,
  NotImplemented = 0xC0000002,
  InvalidInfoClass = 0xC0000003,
  InfoLengthMismatch = 0xC0000004,
  AccessViolation = 0xC0000005,
  InPageError = 0xC0000006,
  PagefileQuota = 0xC0000007,
  InvalidHandle = 0xC0000008,
  BadInitialStack = 0xC0000009,
  BadInitialPc = 0xC000000A,
  InvalidCid = 0xC000000B,
  TimerNotCanceled = 0xC000000C,
  InvalidParameter = 0xC000000D,
  NoSuchDevice = 0xC000000E,
  NoSuchFile = 0xC000000F,
  InvalidDeviceRequest = 0xC0000010,
  EndOfFile = 0xC0000011,
  WrongVolume = 0xC0000012,
  NoMediaInDevice = 0xC0000013,
  UnrecognizedMedia = 0xC0000014,
  NonexistentSector = 0xC0000015,
  MoreProcessingRequired = 0xC0000016,
  NoMemory = 0xC0000017,
  ConflictingAddresses = 0xC0000018,
  NotMappedView = 0xC0000019,
  UnableToFreeVm = 0xC000001A,
  UnableToDeleteSection = 0xC000001B,
  InvalidSystemService = 0xC000001C,
  IllegalInstruction = 0xC000001D,
  InvalidLockSequence = 0xC000001E,
  InvalidViewSize = 0xC000001F,
  InvalidFileForSection = 0xC0000020,
  AlreadyCommitted = 0xC0000021,
  AccessDenied = 0xC0000022,
  BufferTooSmall = 0xC0000023,
  ObjectTypeMismatch = 0xC0000024,
  NoncontinuableException = 0xC0000025,
  InvalidDisposition = 0xC0000026,
  Unwind = 0xC0000027,
  BadStack = 0xC0000028,
  InvalidUnwindTarget = 0xC0000029,
  NotLocked = 0xC000002A,
  ParityError = 0xC000002B,
  UnableToDecommitVm = 0xC000002C,
  NotCommitted = 0xC000002D,
  InvalidPortAttributes = 0xC000002E,
  PortMessageTooLong = 0xC000002F,
  InvalidParameterMix = 0xC0000030,
  InvalidQuotaLower = 0xC0000031,
  DiskCorruptError = 0xC0000032,
  ObjectNameInvalid = 0xC0000033,
  ObjectNameNotFound = 0xC0000034,
  ObjectNameCollision = 0xC0000035,
  PortDisconnected = 0xC0000037,
  DeviceAlreadyAttached = 0xC0000038,
  ObjectPathInvalid = 0xC0000039,
  ObjectPathNotFound = 0xC000003A,
  ObjectPathSyntaxBad = 0xC000003B,
  DataOverrun = 0xC000003C,
  DataLateError = 0xC000003D,
  DataError = 0xC000003E,
  CrcError = 0xC000003F,
  SectionTooBig = 0xC0000040,
  PortConnectionRefused = 0xC0000041,
  InvalidPortHandle = 0xC0000042,
  SharingViolation = 0xC0000043,
  QuotaExceeded = 0xC0000044,
  InvalidPageProtection = 0xC0000045,
  MutantNotOwned = 0xC0000046,
  SemaphoreLimitExceeded = 0xC0000047,
  PortAlreadySet = 0xC0000048,
  SectionNotImage = 0xC0000049,
  SuspendCountExceeded = 0xC000004A,
  ThreadIsTerminating = 0xC000004B,
  BadWorkingSetLimit = 0xC000004C,
  IncompatibleFileMap = 0xC000004D,
  SectionProtection = 0xC000004E,
  EasNotSupported = 0xC000004F,
  EaTooLarge = 0xC0000050,
  NonexistentEaEntry = 0xC0000051,
  NoEasOnFile = 0xC0000052,
  EaCorruptError = 0xC0000053,
  FileLockConflict = 0xC0000054,
  LockNotGranted = 0xC0000055,
  DeletePending = 0xC0000056,
  CtlFileNotSupported = 0xC0000057,
  UnknownRevision = 0xC0000058,
  RevisionMismatch = 0xC0000059,
  InvalidOwner = 0xC000005A,
  InvalidPrimaryGroup = 0xC000005B,
  NoImpersonationToken = 0xC000005C,
  CantDisableMandatory = 0xC000005D,
  NoLogonServers = 0xC000005E,
  NoSuchLogonSession = 0xC000005F,
  NoSuchPrivilege = 0xC0000060,
  PrivilegeNotHeld = 0xC0000061,
  InvalidAccountName = 0xC0000062,
  UserExists = 0xC0000063,
  NoSuchUser = 0xC0000064,
  GroupExists = 0xC0000065,
  NoSuchGroup = 0xC0000066,
  MemberInGroup = 0xC0000067,
  MemberNotInGroup = 0xC0000068,
  LastAdmin = 0xC0000069,
  WrongPassword = 0xC000006A,
  IllFormedPassword = 0xC000006B,
  PasswordRestriction = 0xC000006C,
  LogonFailure = 0xC000006D,
  AccountRestriction = 0xC000006E,
  InvalidLogonHours = 0xC000006F,
  InvalidWorkstation = 0xC0000070,
  PasswordExpired = 0xC0000071,
  AccountDisabled = 0xC0000072,
  NoneMapped = 0xC0000073,
  TooManyLuidsRequested = 0xC0000074,
  LuidsExhausted = 0xC0000075,
  InvalidSubAuthority = 0xC0000076,
  InvalidAcl = 0xC0000077,
  InvalidSid = 0xC0000078,
  InvalidSecurityDescr = 0xC0000079,
  ProcedureNotFound = 0xC000007A,
  InvalidImageFormat = 0xC000007B,
  NoToken = 0xC000007C,
  BadInheritanceAcl = 0xC000007D,
  RangeNotLocked = 0xC000007E,
  DiskFull = 0xC000007F,
  ServerDisabled = 0xC0000080,
  ServerNotDisabled = 0xC0000081,
  TooManyGuidsRequested = 0xC0000082,
  GuidsExhausted = 0xC0000083,
  InvalidIdAuthority = 0xC0000084,
  AgentsExhausted = 0xC0000085,
  InvalidVolumeLabel = 0xC0000086,
  SectionNotExtended = 0xC0000087,
  NotMappedData = 0xC0000088,
  ResourceDataNotFound = 0xC0000089,
  ResourceTypeNotFound = 0xC000008A,
  ResourceNameNotFound = 0xC000008B,
  ArrayBoundsExceeded = 0xC000008C,
  FloatDenormalOperand = 0xC000008D,
  FloatDivideByZero = 0xC000008E,
  FloatInexactResult = 0xC000008F,
  FloatInvalidOperation = 0xC0000090,
  FloatOverflow = 0xC0000091,
  FloatStackCheck = 0xC0000092,
  FloatUnderflow = 0xC0000093,
  IntegerDivideByZero = 0xC0000094,
  IntegerOverflow = 0xC0000095,
  PrivilegedInstruction = 0xC0000096,
  TooManyPagingFiles = 0xC0000097,
  FileInvalid = 0xC0000098,
  AllottedSpaceExceeded = 0xC0000099,
  InsufficientResources = 0xC000009A,
  DfsExitPathFound = 0xC000009B,
  DeviceDataError = 0xC000009C,
  DeviceNotConnected = 0xC000009D,
  FreeVmNotAtBase = 0xC000009F,
  MemoryNotAllocated = 0xC00000A0,
  WorkingSetQuota = 0xC00000A1,
  MediaWriteProtected = 0xC00000A2,
  DeviceNotReady = 0xC00000A3,
  InvalidGroupAttributes = 0xC00000A4,
  BadImpersonationLevel = 0xC00000A5,
  CantOpenAnonymous = 0xC00000A6,
  BadValidationClass = 0xC00000A7,
  BadTokenType = 0xC00000A8,
  BadMasterBootRecord = 0xC00000A9,
  InstructionMisalignment = 0xC00000AA,
  InstanceNotAvailable = 0xC00000AB,
  PipeNotAvailable = 0xC00000AC,
  InvalidPipeState = 0xC00000AD,
  PipeBusy = 0xC00000AE,
  IllegalFunction = 0xC00000AF,
  PipeDisconnected = 0xC00000B0,
  PipeClosing = 0xC00000B1,
  PipeConnected = 0xC00000B2,
  PipeListening = 0xC00000B3,
  InvalidReadMode = 0xC00000B4,
  IoTimeout = 0xC00000B5,
  FileForcedClosed = 0xC00000B6,
  ProfilingNotStarted = 0xC00000B7,
  ProfilingNotStopped = 0xC00000B8,
  CouldNotInterpret = 0xC00000B9,
  FileIsADirectory = 0xC00000BA,
  NotSupported = 0xC00000BB,
  RemoteNotListening = 0xC00000BC,
  DuplicateName = 0xC00000BD,
  BadNetworkPath = 0xC00000BE,
  NetworkBusy = 0xC00000BF,
  DeviceDoesNotExist = 0xC00000C0,
  TooManyCommands = 0xC00000C1,
  AdapterHardwareError = 0xC00000C2,
  InvalidNetworkResponse = 0xC00000C3,
  UnexpectedNetworkError = 0xC00000C4,
  BadRemoteAdapter = 0xC00000C5,
  PrintQueueFull = 0xC00000C6,
  NoSpoolSpace = 0xC00000C7,
  PrintCancelled = 0xC00000C8,
  NetworkNameDeleted = 0xC00000C9,
  NetworkAccessDenied = 0xC00000CA,
  BadDeviceType = 0xC00000CB,
  BadNetworkName = 0xC00000CC,
  TooManyNames = 0xC00000CD,
  TooManySessions = 0xC00000CE,
  SharingPaused = 0xC00000CF,
  RequestNotAccepted = 0xC00000D0,
  RedirectorPaused = 0xC00000D1,
  NetWriteFault = 0xC00000D2,
  ProfilingAtLimit = 0xC00000D3,
  NotSameDevice = 0xC00000D4,
  FileRenamed = 0xC00000D5,
  VirtualCircuitClosed = 0xC00000D6,
  NoSecurityOnObject = 0xC00000D7,
  CantWait = 0xC00000D8,
  PipeEmpty = 0xC00000D9,
  CantAccessDomainInfo = 0xC00000DA,
  CantTerminateSelf = 0xC00000DB,
  InvalidServerState = 0xC00000DC,
  InvalidDomainState = 0xC00000DD,
  InvalidDomainRole = 0xC00000DE,
  NoSuchDomain = 0xC00000DF,
  DomainExists = 0xC00000E0,
  DomainLimitExceeded = 0xC00000E1,
  OplockNotGranted = 0xC00000E2,
  InvalidOplockProtocol = 0xC00000E3,
  InternalDbCorruption = 0xC00000E4,
  InternalError = 0xC00000E5,
  GenericNotMapped = 0xC00000E6,
  BadDescriptorFormat = 0xC00000E7,
  InvalidUserBuffer = 0xC00000E8,
  UnexpectedIoError = 0xC00000E9,
  UnexpectedMmCreateErr = 0xC00000EA,
  UnexpectedMmMapError = 0xC00000EB,
  UnexpectedMmExtendErr = 0xC00000EC,
  NotLogonProcess = 0xC00000ED,
  LogonSessionExists = 0xC00000EE,
  InvalidParameter1 = 0xC00000EF,
  InvalidParameter2 = 0xC00000F0,
  InvalidParameter3 = 0xC00000F1,
  InvalidParameter4 = 0xC00000F2,
  InvalidParameter5 = 0xC00000F3,
  InvalidParameter6 = 0xC00000F4,
  InvalidParameter7 = 0xC00000F5,
  InvalidParameter8 = 0xC00000F6,
  InvalidParameter9 = 0xC00000F7,
  InvalidParameter10 = 0xC00000F8,
  InvalidParameter11 = 0xC00000F9,
  InvalidParameter12 = 0xC00000FA,
  RedirectorNotStarted = 0xC00000FB,
  RedirectorStarted = 0xC00000FC,
  StackOverflow = 0xC00000FD,
  NoSuchPackage = 0xC00000FE,
  BadFunctionTable = 0xC00000FF,
  VariableNotFound = 0xC0000100,
  DirectoryNotEmpty = 0xC0000101,
  FileCorruptError = 0xC0000102,
  NotADirectory = 0xC0000103,
  BadLogonSessionState = 0xC0000104,
  LogonSessionCollision = 0xC0000105,
  NameTooLong = 0xC0000106,
  FilesOpen = 0xC0000107,
  ConnectionInUse = 0xC0000108,
  MessageNotFound = 0xC0000109,
  ProcessIsTerminating = 0xC000010A,
  InvalidLogonType = 0xC000010B,
  NoGuidTranslation = 0xC000010C,
  CannotImpersonate = 0xC000010D,
  ImageAlreadyLoaded = 0xC000010E,
  NoLdt = 0xC0000117,
  InvalidLdtSize = 0xC0000118,
  InvalidLdtOffset = 0xC0000119,
  InvalidLdtDescriptor = 0xC000011A,
  InvalidImageNeFormat = 0xC000011B,
  RxactInvalidState = 0xC000011C,
  RxactCommitFailure = 0xC000011D,
  MappedFileSizeZero = 0xC000011E,
  TooManyOpenedFiles = 0xC000011F,
  Cancelled = 0xC0000120,
  CannotDelete = 0xC0000121,
  InvalidComputerName = 0xC0000122,
  FileDeleted = 0xC0000123,
  SpecialAccount = 0xC0000124,
  SpecialGroup = 0xC0000125,
  SpecialUser = 0xC0000126,
  MembersPrimaryGroup = 0xC0000127,
  FileClosed = 0xC0000128,
  TooManyThreads = 0xC0000129,
  ThreadNotInProcess = 0xC000012A,
  TokenAlreadyInUse = 0xC000012B,
  PagefileQuotaExceeded = 0xC000012C,
  CommitmentLimit = 0xC000012D,
  InvalidImageLeFormat = 0xC000012E,
  InvalidImageNotMz = 0xC000012F,
  InvalidImageProtect = 0xC0000130,
  InvalidImageWin16 = 0xC0000131,
  LogonServerConflict = 0xC0000132,
  TimeDifferenceAtDc = 0xC0000133,
  SynchronizationRequired = 0xC0000134,
  DllNotFound = 0xC0000135,
  OpenFailed = 0xC0000136,
  IoPrivilegeFailed = 0xC0000137,
  OrdinalNotFound = 0xC0000138,
  EntrypointNotFound = 0xC0000139,
  ControlCExit = 0xC000013A,
  LocalDisconnect = 0xC000013B,
  RemoteDisconnect = 0xC000013C,
  RemoteResources = 0xC000013D,
  LinkFailed = 0xC000013E,
  LinkTimeout = 0xC000013F,
  InvalidConnection = 0xC0000140,
  InvalidAddress = 0xC0000141,
  DllInitFailed = 0xC0000142,
  MissingSystemfile = 0xC0000143,
  UnhandledException = 0xC0000144,
  AppInitFailure = 0xC0000145,
  PagefileCreateFailed = 0xC0000146,
  NoPagefile = 0xC0000147,
  InvalidLevel = 0xC0000148,
  WrongPasswordCore = 0xC0000149,
  IllegalFloatContext = 0xC000014A,
  PipeBroken = 0xC000014B,
  RegistryCorrupt = 0xC000014C,
  RegistryIoFailed = 0xC000014D,
  NoEventPair = 0xC000014E,
  UnrecognizedVolume = 0xC000014F,
  SerialNoDeviceInited = 0xC0000150,
  NoSuchAlias = 0xC0000151,
  MemberNotInAlias = 0xC0000152,
  MemberInAlias = 0xC0000153,
  AliasExists = 0xC0000154,
  LogonNotGranted = 0xC0000155,
  TooManySecrets = 0xC0000156,
  SecretTooLong = 0xC0000157,
  InternalDbError = 0xC0000158,
  FullscreenMode = 0xC0000159,
  TooManyContextIds = 0xC000015A,
  LogonTypeNotGranted = 0xC000015B,
  NotRegistryFile = 0xC000015C,
  NtCrossEncryptionRequired = 0xC000015D,
  DomainCtrlrConfigError = 0xC000015E,
  FtMissingMember = 0xC000015F,
  IllFormedServiceEntry = 0xC0000160,
  IllegalCharacter = 0xC0000161,
  UnmappableCharacter = 0xC0000162,
  UndefinedCharacter = 0xC0000163,
  FloppyVolume = 0xC0000164,
  FloppyIdMarkNotFound = 0xC0000165,
  FloppyWrongCylinder = 0xC0000166,
  FloppyUnknownError = 0xC0000167,
  FloppyBadRegisters = 0xC0000168,
  DiskRecalibrateFailed = 0xC0000169,
  DiskOperationFailed = 0xC000016A,
  DiskResetFailed = 0xC000016B,
  SharedIrqBusy = 0xC000016C,
  FtOrphaning = 0xC000016D,
  BiosFailedToConnectInterrupt = 0xC000016E,
  PartitionFailure = 0xC0000172,
  InvalidBlockLength = 0xC0000173,
  DeviceNotPartitioned = 0xC0000174,
  UnableToLockMedia = 0xC0000175,
  UnableToUnloadMedia = 0xC0000176,
  EomOverflow = 0xC0000177,
  NoMedia = 0xC0000178,
  NoSuchMember = 0xC000017A,
  InvalidMember = 0xC000017B,
  KeyDeleted = 0xC000017C,
  NoLogSpace = 0xC000017D,
  TooManySids = 0xC000017E,
  LmCrossEncryptionRequired = 0xC000017F,
  KeyHasChildren = 0xC0000180,
  ChildMustBeVolatile = 0xC0000181,
  DeviceConfigurationError = 0xC0000182,
  DriverInternalError = 0xC0000183,
  InvalidDeviceState = 0xC0000184,
  IoDeviceError = 0xC0000185,
  DeviceProtocolError = 0xC0000186,
  BackupController = 0xC0000187,
  LogFileFull = 0xC0000188,
  TooLate = 0xC0000189,
  NoTrustLsaSecret = 0xC000018A,
  NoTrustSamAccount = 0xC000018B,
  TrustedDomainFailure = 0xC000018C,
  TrustedRelationshipFailure = 0xC000018D,
  EventlogFileCorrupt = 0xC000018E,
  EventlogCantStart = 0xC000018F,
  TrustFailure = 0xC0000190,
  MutantLimitExceeded = 0xC0000191,
  NetlogonNotStarted = 0xC0000192,
  AccountExpired = 0xC0000193,
  PossibleDeadlock = 0xC0000194,
  NetworkCredentialConflict = 0xC0000195,
  RemoteSessionLimit = 0xC0000196,
  EventlogFileChanged = 0xC0000197,
  NologonInterdomainTrustAccount = 0xC0000198,
  NologonWorkstationTrustAccount = 0xC0000199,
  NologonServerTrustAccount = 0xC000019A,
  DomainTrustInconsistent = 0xC000019B,
  FsDriverRequired = 0xC000019C,
  ImageAlreadyLoadedAsDll = 0xC000019D,
  IncompatibleWithGlobalShortNameRegistrySetting = 0xC000019E,
  ShortNamesNotEnabledOnVolume = 0xC000019F,
  SecurityStreamIsInconsistent = 0xC00001A0,
  InvalidLockRange = 0xC00001A1,
  InvalidAceCondition = 0xC00001A2,
  ImageSubsystemNotPresent = 0xC00001A3,
  NotificationGuidAlreadyDefined = 0xC00001A4,
  NetworkOpenRestriction = 0xC0000201,
  NoUserSessionKey = 0xC0000202,
  UserSessionDeleted = 0xC0000203,
  ResourceLangNotFound = 0xC0000204,
  InsuffServerResources = 0xC0000205,
  InvalidBufferSize = 0xC0000206,
  InvalidAddressComponent = 0xC0000207,
  InvalidAddressWildcard = 0xC0000208,
  TooManyAddresses = 0xC0000209,
  AddressAlreadyExists = 0xC000020A,
  AddressClosed = 0xC000020B,
  ConnectionDisconnected = 0xC000020C,
  ConnectionReset = 0xC000020D,
  TooManyNodes = 0xC000020E,
  TransactionAborted = 0xC000020F,
  TransactionTimedOut = 0xC0000210,
  TransactionNoRelease = 0xC0000211,
  TransactionNoMatch = 0xC0000212,
  TransactionResponded = 0xC0000213,
  TransactionInvalidId = 0xC0000214,
  TransactionInvalidType = 0xC0000215,
  NotServerSession = 0xC0000216,
  NotClientSession = 0xC0000217,
  CannotLoadRegistryFile = 0xC0000218,
  DebugAttachFailed = 0xC0000219,
  SystemProcessTerminated = 0xC000021A,
  DataNotAccepted = 0xC000021B,
  NoBrowserServersFound = 0xC000021C,
  VdmHardError = 0xC000021D,
  DriverCancelTimeout = 0xC000021E,
  ReplyMessageMismatch = 0xC000021F,
  MappedAlignment = 0xC0000220,
  ImageChecksumMismatch = 0xC0000221,
  LostWritebehindData = 0xC0000222,
  ClientServerParametersInvalid = 0xC0000223,
  PasswordMustChange = 0xC0000224,
  NotFound = 0xC0000225,
  NotTinyStream = 0xC0000226,
  RecoveryFailure = 0xC0000227,
  StackOverflowRead = 0xC0000228,
  FailCheck = 0xC0000229,
  DuplicateObjectid = 0xC000022A,
  ObjectidExists = 0xC000022B,
  ConvertToLarge = 0xC000022C,
  Retry = 0xC000022D,
  FoundOutOfScope = 0xC000022E,
  AllocateBucket = 0xC000022F,
  PropsetNotFound = 0xC0000230,
  MarshallOverflow = 0xC0000231,
  InvalidVariant = 0xC0000232,
  DomainControllerNotFound = 0xC0000233,
  AccountLockedOut = 0xC0000234,
  HandleNotClosable = 0xC0000235,
  ConnectionRefused = 0xC0000236,
  GracefulDisconnect = 0xC0000237,
  AddressAlreadyAssociated = 0xC0000238,
  AddressNotAssociated = 0xC0000239,
  ConnectionInvalid = 0xC000023A,
  ConnectionActive = 0xC000023B,
  NetworkUnreachable = 0xC000023C,
  HostUnreachable = 0xC000023D,
  ProtocolUnreachable = 0xC000023E,
  PortUnreachable = 0xC000023F,
  RequestAborted = 0xC0000240,
  ConnectionAborted = 0xC0000241,
  BadCompressionBuffer = 0xC0000242,
  UserMappedFile = 0xC0000243,
  AuditFailed = 0xC0000244,
  TimerResolutionNotSet = 0xC0000245,
  ConnectionCountLimit = 0xC0000246,
  LoginTimeRestriction = 0xC0000247,
  LoginWkstaRestriction = 0xC0000248,
  ImageMpUpMismatch = 0xC0000249,
  InsufficientLogonInfo = 0xC0000250,
  BadDllEntrypoint = 0xC0000251,
  BadServiceEntrypoint = 0xC0000252,
  LpcReplyLost = 0xC0000253,
  IpAddressConflict1 = 0xC0000254,
  IpAddressConflict2 = 0xC0000255,
  RegistryQuotaLimit = 0xC0000256,
  PathNotCovered = 0xC0000257,
  NoCallbackActive = 0xC0000258,
  LicenseQuotaExceeded = 0xC0000259,
  PwdTooShort = 0xC000025A,
  PwdTooRecent = 0xC000025B,
  PwdHistoryConflict = 0xC000025C,
  PlugplayNoDevice = 0xC000025E,
  UnsupportedCompression = 0xC000025F,
  InvalidHwProfile = 0xC0000260,
  InvalidPlugplayDevicePath = 0xC0000261,
  DriverOrdinalNotFound = 0xC0000262,
  DriverEntrypointNotFound = 0xC0000263,
  ResourceNotOwned = 0xC0000264,
  TooManyLinks = 0xC0000265,
  QuotaListInconsistent = 0xC0000266,
  FileIsOffline = 0xC0000267,
  EvaluationExpiration = 0xC0000268,
  IllegalDllRelocation = 0xC0000269,
  LicenseViolation = 0xC000026A,
  DllInitFailedLogoff = 0xC000026B,
  DriverUnableToLoad = 0xC000026C,
  DfsUnavailable = 0xC000026D,
  VolumeDismounted = 0xC000026E,
  Wx86InternalError = 0xC000026F,
  Wx86FloatStackCheck = 0xC0000270,
  ValidateContinue = 0xC0000271,
  NoMatch = 0xC0000272,
  NoMoreMatches = 0xC0000273,
  NotAReparsePoint = 0xC0000275,
  IoReparseTagInvalid = 0xC0000276,
  IoReparseTagMismatch = 0xC0000277,
  IoReparseDataInvalid = 0xC0000278,
  IoReparseTagNotHandled = 0xC0000279,
  ReparsePointNotResolved = 0xC0000280,
  DirectoryIsAReparsePoint = 0xC0000281,
  RangeListConflict = 0xC0000282,
  SourceElementEmpty = 0xC0000283,
  DestinationElementFull = 0xC0000284,
  IllegalElementAddress = 0xC0000285,
  MagazineNotPresent = 0xC0000286,
  ReinitializationNeeded = 0xC0000287,
  EncryptionFailed = 0xC000028A,
  DecryptionFailed = 0xC000028B,
  RangeNotFound = 0xC000028C,
  NoRecoveryPolicy = 0xC000028D,
  NoEfs = 0xC000028E,
  WrongEfs = 0xC000028F,
  NoUserKeys = 0xC0000290,
  FileNotEncrypted = 0xC0000291,
  NotExportFormat = 0xC0000292,
  FileEncrypted = 0xC0000293,
  WmiGuidNotFound = 0xC0000295,
  WmiInstanceNotFound = 0xC0000296,
  WmiItemidNotFound = 0xC0000297,
  WmiTryAgain = 0xC0000298,
  SharedPolicy = 0xC0000299,
  PolicyObjectNotFound = 0xC000029A,
  PolicyOnlyInDs = 0xC000029B,
  VolumeNotUpgraded = 0xC000029C,
  RemoteStorageNotActive = 0xC000029D,
  RemoteStorageMediaError = 0xC000029E,
  NoTrackingService = 0xC000029F,
  ServerSidMismatch = 0xC00002A0,
  DsNoAttributeOrValue = 0xC00002A1,
  DsInvalidAttributeSyntax = 0xC00002A2,
  DsAttributeTypeUndefined = 0xC00002A3,
  DsAttributeOrValueExists = 0xC00002A4,
  DsBusy = 0xC00002A5,
  DsUnavailable = 0xC00002A6,
  DsNoRidsAllocated = 0xC00002A7,
  DsNoMoreRids = 0xC00002A8,
  DsIncorrectRoleOwner = 0xC00002A9,
  DsRidmgrInitError = 0xC00002AA,
  DsObjClassViolation = 0xC00002AB,
  DsCantOnNonLeaf = 0xC00002AC,
  DsCantOnRdn = 0xC00002AD,
  DsCantModObjClass = 0xC00002AE,
  DsCrossDomMoveFailed = 0xC00002AF,
  DsGcNotAvailable = 0xC00002B0,
  DirectoryServiceRequired = 0xC00002B1,
  ReparseAttributeConflict = 0xC00002B2,
  CantEnableDenyOnly = 0xC00002B3,
  FloatMultipleFaults = 0xC00002B4,
  FloatMultipleTraps = 0xC00002B5,
  DeviceRemoved = 0xC00002B6,
  JournalDeleteInProgress = 0xC00002B7,
  JournalNotActive = 0xC00002B8,
  Nointerface = 0xC00002B9,
  DsAdminLimitExceeded = 0xC00002C1,
  DriverFailedSleep = 0xC00002C2,
  MutualAuthenticationFailed = 0xC00002C3,
  CorruptSystemFile = 0xC00002C4,
  DatatypeMisalignmentError = 0xC00002C5,
  WmiReadOnly = 0xC00002C6,
  WmiSetFailure = 0xC00002C7,
  CommitmentMinimum = 0xC00002C8,
  RegNatConsumption = 0xC00002C9,
  TransportFull = 0xC00002CA,
  DsSamInitFailure = 0xC00002CB,
  OnlyIfConnected = 0xC00002CC,
  DsSensitiveGroupViolation = 0xC00002CD,
  PnpRestartEnumeration = 0xC00002CE,
  JournalEntryDeleted = 0xC00002CF,
  DsCantModPrimarygroupid = 0xC00002D0,
  SystemImageBadSignature = 0xC00002D1,
  PnpRebootRequired = 0xC00002D2,
  PowerStateInvalid = 0xC00002D3,
  DsInvalidGroupType = 0xC00002D4,
  DsNoNestGlobalgroupInMixeddomain = 0xC00002D5,
  DsNoNestLocalgroupInMixeddomain = 0xC00002D6,
  DsGlobalCantHaveLocalMember = 0xC00002D7,
  DsGlobalCantHaveUniversalMember = 0xC00002D8,
  DsUniversalCantHaveLocalMember = 0xC00002D9,
  DsGlobalCantHaveCrossdomainMember = 0xC00002DA,
  DsLocalCantHaveCrossdomainLocalMember = 0xC00002DB,
  DsHavePrimaryMembers = 0xC00002DC,
  WmiNotSupported = 0xC00002DD,
  InsufficientPower = 0xC00002DE,
  SamNeedBootkeyPassword = 0xC00002DF,
  SamNeedBootkeyFloppy = 0xC00002E0,
  DsCantStart = 0xC00002E1,
  DsInitFailure = 0xC00002E2,
  SamInitFailure = 0xC00002E3,
  DsGcRequired = 0xC00002E4,
  DsLocalMemberOfLocalOnly = 0xC00002E5,
  DsNoFpoInUniversalGroups = 0xC00002E6,
  DsMachineAccountQuotaExceeded = 0xC00002E7,
  CurrentDomainNotAllowed = 0xC00002E9,
  CannotMake = 0xC00002EA,
  SystemShutdown = 0xC00002EB,
  DsInitFailureConsole = 0xC00002EC,
  DsSamInitFailureConsole = 0xC00002ED,
  UnfinishedContextDeleted = 0xC00002EE,
  NoTgtReply = 0xC00002EF,
  ObjectidNotFound = 0xC00002F0,
  NoIpAddresses = 0xC00002F1,
  WrongCredentialHandle = 0xC00002F2,
  CryptoSystemInvalid = 0xC00002F3,
  MaxReferralsExceeded = 0xC00002F4,
  MustBeKdc = 0xC00002F5,
  StrongCryptoNotSupported = 0xC00002F6,
  TooManyPrincipals = 0xC00002F7,
  NoPaData = 0xC00002F8,
  PkinitNameMismatch = 0xC00002F9,
  SmartcardLogonRequired = 0xC00002FA,
  KdcInvalidRequest = 0xC00002FB,
  KdcUnableToRefer = 0xC00002FC,
  KdcUnknownEtype = 0xC00002FD,
  ShutdownInProgress = 0xC00002FE,
  ServerShutdownInProgress = 0xC00002FF,
  NotSupportedOnSbs = 0xC0000300,
  WmiGuidDisconnected = 0xC0000301,
  WmiAlreadyDisabled = 0xC0000302,
  WmiAlreadyEnabled = 0xC0000303,
  MftTooFragmented = 0xC0000304,
  CopyProtectionFailure = 0xC0000305,
  CssAuthenticationFailure = 0xC0000306,
  CssKeyNotPresent = 0xC0000307,
  CssKeyNotEstablished = 0xC0000308,
  CssScrambledSector = 0xC0000309,
  CssRegionMismatch = 0xC000030A,
  CssResetsExhausted = 0xC000030B,
  PkinitFailure = 0xC0000320,
  SmartcardSubsystemFailure = 0xC0000321,
  NoKerbKey = 0xC0000322,
  HostDown = 0xC0000350,
  UnsupportedPreauth = 0xC0000351,
  EfsAlgBlobTooBig = 0xC0000352,
  PortNotSet = 0xC0000353,
  DebuggerInactive = 0xC0000354,
  DsVersionCheckFailure = 0xC0000355,
  AuditingDisabled = 0xC0000356,
  Prent4MachineAccount = 0xC0000357,
  DsAgCantHaveUniversalMember = 0xC0000358,
  InvalidImageWin32 = 0xC0000359,
  InvalidImageWin64 = 0xC000035A,
  BadBindings = 0xC000035B,
  NetworkSessionExpired = 0xC000035C,
  ApphelpBlock = 0xC000035D,
  AllSidsFiltered = 0xC000035E,
  NotSafeModeDriver = 0xC000035F,
  AccessDisabledByPolicyDefault = 0xC0000361,
  AccessDisabledByPolicyPath = 0xC0000362,
  AccessDisabledByPolicyPublisher = 0xC0000363,
  AccessDisabledByPolicyOther = 0xC0000364,
  FailedDriverEntry = 0xC0000365,
  DeviceEnumerationError = 0xC0000366,
  MountPointNotResolved = 0xC0000368,
  InvalidDeviceObjectParameter = 0xC0000369,
  McaOccured = 0xC000036A,
  DriverBlockedCritical = 0xC000036B,
  DriverBlocked = 0xC000036C,
  DriverDatabaseError = 0xC000036D,
  SystemHiveTooLarge = 0xC000036E,
  InvalidImportOfNonDll = 0xC000036F,
  NoSecrets = 0xC0000371,
  AccessDisabledNoSaferUiByPolicy = 0xC0000372,
  FailedStackSwitch = 0xC0000373,
  HeapCorruption = 0xC0000374,
  SmartcardWrongPin = 0xC0000380,
  SmartcardCardBlocked = 0xC0000381,
  SmartcardCardNotAuthenticated = 0xC0000382,
  SmartcardNoCard = 0xC0000383,
  SmartcardNoKeyContainer = 0xC0000384,
  SmartcardNoCertificate = 0xC0000385,
  SmartcardNoKeyset = 0xC0000386,
  SmartcardIoError = 0xC0000387,
  DowngradeDetected = 0xC0000388,
  SmartcardCertRevoked = 0xC0000389,
  IssuingCaUntrusted = 0xC000038A,
  RevocationOfflineC = 0xC000038B,
  PkinitClientFailure = 0xC000038C,
  SmartcardCertExpired = 0xC000038D,
  DriverFailedPriorUnload = 0xC000038E,
  SmartcardSilentContext = 0xC000038F,
  PerUserTrustQuotaExceeded = 0xC0000401,
  AllUserTrustQuotaExceeded = 0xC0000402,
  UserDeleteTrustQuotaExceeded = 0xC0000403,
  DsNameNotUnique = 0xC0000404,
  DsDuplicateIdFound = 0xC0000405,
  DsGroupConversionError = 0xC0000406,
  VolsnapPrepareHibernate = 0xC0000407,
  User2userRequired = 0xC0000408,
  StackBufferOverrun = 0xC0000409,
  NoS4uProtSupport = 0xC000040A,
  CrossrealmDelegationFailure = 0xC000040B,
  RevocationOfflineKdc = 0xC000040C,
  IssuingCaUntrustedKdc = 0xC000040D,
  KdcCertExpired = 0xC000040E,
  KdcCertRevoked = 0xC000040F,
  ParameterQuotaExceeded = 0xC0000410,
  HibernationFailure = 0xC0000411,
  DelayLoadFailed = 0xC0000412,
  AuthenticationFirewallFailed = 0xC0000413,
  VdmDisallowed = 0xC0000414,
  HungDisplayDriverThread = 0xC0000415,
  InsufficientResourceForSpecifiedSharedSectionSize = 0xC0000416,
  InvalidCruntimeParameter = 0xC0000417,
  NtlmBlocked = 0xC0000418,
  DsSrcSidExistsInForest = 0xC0000419,
  DsDomainNameExistsInForest = 0xC000041A,
  DsFlatNameExistsInForest = 0xC000041B,
  InvalidUserPrincipalName = 0xC000041C,
  AssertionFailure = 0xC0000420,
  VerifierStop = 0xC0000421,
  CallbackPopStack = 0xC0000423,
  IncompatibleDriverBlocked = 0xC0000424,
  HiveUnloaded = 0xC0000425,
  CompressionDisabled = 0xC0000426,
  FileSystemLimitation = 0xC0000427,
  InvalidImageHash = 0xC0000428,
  NotCapable = 0xC0000429,
  RequestOutOfSequence = 0xC000042A,
  ImplementationLimit = 0xC000042B,
  ElevationRequired = 0xC000042C,
  NoSecurityContext = 0xC000042D,
  Pku2uCertFailure = 0xC000042E,
  BeyondVdl = 0xC0000432,
  EncounteredWriteInProgress = 0xC0000433,
  PteChanged = 0xC0000434,
  PurgeFailed = 0xC0000435,
  CredRequiresConfirmation = 0xC0000440,
  CsEncryptionInvalidServerResponse = 0xC0000441,
  CsEncryptionUnsupportedServer = 0xC0000442,
  CsEncryptionExistingEncryptedFile = 0xC0000443,
  CsEncryptionNewEncryptedFile = 0xC0000444,
  CsEncryptionFileNotCse = 0xC0000445,
  InvalidLabel = 0xC0000446,
  DriverProcessTerminated = 0xC0000450,
  AmbiguousSystemDevice = 0xC0000451,
  SystemDeviceNotFound = 0xC0000452,
  RestartBootApplication = 0xC0000453,
  InsufficientNvramResources = 0xC0000454,
  NoRangesProcessed = 0xC0000460,
  DeviceFeatureNotSupported = 0xC0000463,
  DeviceUnreachable = 0xC0000464,
  InvalidToken = 0xC0000465,
  ServerUnavailable = 0xC0000466,
  InvalidTaskName = 0xC0000500,
  InvalidTaskIndex = 0xC0000501,
  ThreadAlreadyInTask = 0xC0000502,
  CallbackBypass = 0xC0000503,
  FailFastException = 0xC0000602,
  ImageCertRevoked = 0xC0000603,
  PortClosed = 0xC0000700,
  MessageLost = 0xC0000701,
  InvalidMessage = 0xC0000702,
  RequestCanceled = 0xC0000703,
  RecursiveDispatch = 0xC0000704,
  LpcReceiveBufferExpected = 0xC0000705,
  LpcInvalidConnectionUsage = 0xC0000706,
  LpcRequestsNotAllowed = 0xC0000707,
  ResourceInUse = 0xC0000708,
  HardwareMemoryError = 0xC0000709,
  ThreadpoolHandleException = 0xC000070A,
  ThreadpoolSetEventOnCompletionFailed = 0xC000070B,
  ThreadpoolReleaseSemaphoreOnCompletionFailed = 0xC000070C,
  ThreadpoolReleaseMutexOnCompletionFailed = 0xC000070D,
  ThreadpoolFreeLibraryOnCompletionFailed = 0xC000070E,
  ThreadpoolReleasedDuringOperation = 0xC000070F,
  CallbackReturnedWhileImpersonating = 0xC0000710,
  ApcReturnedWhileImpersonating = 0xC0000711,
  ProcessIsProtected = 0xC0000712,
  McaException = 0xC0000713,
  CertificateMappingNotUnique = 0xC0000714,
  SymlinkClassDisabled = 0xC0000715,
  InvalidIdnNormalization = 0xC0000716,
  NoUnicodeTranslation = 0xC0000717,
  AlreadyRegistered = 0xC0000718,
  ContextMismatch = 0xC0000719,
  PortAlreadyHasCompletionList = 0xC000071A,
  CallbackReturnedThreadPriority = 0xC000071B,
  InvalidThread = 0xC000071C,
  CallbackReturnedTransaction = 0xC000071D,
  CallbackReturnedLdrLock = 0xC000071E,
  CallbackReturnedLang = 0xC000071F,
  CallbackReturnedPriBack = 0xC0000720,
  DiskRepairDisabled = 0xC0000800,
  DsDomainRenameInProgress = 0xC0000801,
  DiskQuotaExceeded = 0xC0000802,
  ContentBlocked = 0xC0000804,
  BadClusters = 0xC0000805,
  VolumeDirty = 0xC0000806,
  FileCheckedOut = 0xC0000901,
  CheckoutRequired = 0xC0000902,
  BadFileType = 0xC0000903,
  FileTooLarge = 0xC0000904,
  FormsAuthRequired = 0xC0000905,
  VirusInfected = 0xC0000906,
  VirusDeleted = 0xC0000907,
  BadMcfgTable = 0xC0000908,
  CannotBreakOplock = 0xC0000909,
  WowAssertion = 0xC0009898,
  InvalidSignature = 0xC000A000,
  HmacNotSupported = 0xC000A001,
  IpsecQueueOverflow = 0xC000A010,
  NdQueueOverflow = 0xC000A011,
  HoplimitExceeded = 0xC000A012,
  ProtocolNotSupported = 0xC000A013,
  LostWritebehindDataNetworkDisconnected = 0xC000A080,
  LostWritebehindDataNetworkServerError = 0xC000A081,
  LostWritebehindDataLocalDiskError = 0xC000A082,
  XmlParseError = 0xC000A083,
  XmldsigError = 0xC000A084,
  WrongCompartment = 0xC000A085,
  AuthipFailure = 0xC000A086,
  DsOidMappedGroupCantHaveMembers = 0xC000A087,
  DsOidNotFound = 0xC000A088,
  HashNotSupported = 0xC000A100,
  HashNotPresent = 0xC000A101,
  OffloadReadFltNotSupported = 0xC000A2A1,
  OffloadWriteFltNotSupported = 0xC000A2A2,
  OffloadReadFileNotSupported = 0xC000A2A3,
  OffloadWriteFileNotSupported = 0xC000A2A4,
  DbgNoStateChange = 0xC0010001,
  DbgAppNotIdle = 0xC0010002,
  RpcNtInvalidStringBinding = 0xC0020001,
  RpcNtWrongKindOfBinding = 0xC0020002,
  RpcNtInvalidBinding = 0xC0020003,
  RpcNtProtseqNotSupported = 0xC0020004,
  RpcNtInvalidRpcProtseq = 0xC0020005,
  RpcNtInvalidStringUuid = 0xC0020006,
  RpcNtInvalidEndpointFormat = 0xC0020007,
  RpcNtInvalidNetAddr = 0xC0020008,
  RpcNtNoEndpointFound = 0xC0020009,
  RpcNtInvalidTimeout = 0xC002000A,
  RpcNtObjectNotFound = 0xC002000B,
  RpcNtAlreadyRegistered = 0xC002000C,
  RpcNtTypeAlreadyRegistered = 0xC002000D,
  RpcNtAlreadyListening = 0xC002000E,
  RpcNtNoProtseqsRegistered = 0xC002000F,
  RpcNtNotListening = 0xC0020010,
  RpcNtUnknownMgrType = 0xC0020011,
  RpcNtUnknownIf = 0xC0020012,
  RpcNtNoBindings = 0xC0020013,
  RpcNtNoProtseqs = 0xC0020014,
  RpcNtCantCreateEndpoint = 0xC0020015,
  RpcNtOutOfResources = 0xC0020016,
  RpcNtServerUnavailable = 0xC0020017,
  RpcNtServerTooBusy = 0xC0020018,
  RpcNtInvalidNetworkOptions = 0xC0020019,
  RpcNtNoCallActive = 0xC002001A,
  RpcNtCallFailed = 0xC002001B,
  RpcNtCallFailedDne = 0xC002001C,
  RpcNtProtocolError = 0xC002001D,
  RpcNtUnsupportedTransSyn = 0xC002001F,
  RpcNtUnsupportedType = 0xC0020021,
  RpcNtInvalidTag = 0xC0020022,
  RpcNtInvalidBound = 0xC0020023,
  RpcNtNoEntryName = 0xC0020024,
  RpcNtInvalidNameSyntax = 0xC0020025,
  RpcNtUnsupportedNameSyntax = 0xC0020026,
  RpcNtUuidNoAddress = 0xC0020028,
  RpcNtDuplicateEndpoint = 0xC0020029,
  RpcNtUnknownAuthnType = 0xC002002A,
  RpcNtMaxCallsTooSmall = 0xC002002B,
  RpcNtStringTooLong = 0xC002002C,
  RpcNtProtseqNotFound = 0xC002002D,
  RpcNtProcnumOutOfRange = 0xC002002E,
  RpcNtBindingHasNoAuth = 0xC002002F,
  RpcNtUnknownAuthnService = 0xC0020030,
  RpcNtUnknownAuthnLevel = 0xC0020031,
  RpcNtInvalidAuthIdentity = 0xC0020032,
  RpcNtUnknownAuthzService = 0xC0020033,
  EptNtInvalidEntry = 0xC0020034,
  EptNtCantPerformOp = 0xC0020035,
  EptNtNotRegistered = 0xC0020036,
  RpcNtNothingToExport = 0xC0020037,
  RpcNtIncompleteName = 0xC0020038,
  RpcNtInvalidVersOption = 0xC0020039,
  RpcNtNoMoreMembers = 0xC002003A,
  RpcNtNotAllObjsUnexported = 0xC002003B,
  RpcNtInterfaceNotFound = 0xC002003C,
  RpcNtEntryAlreadyExists = 0xC002003D,
  RpcNtEntryNotFound = 0xC002003E,
  RpcNtNameServiceUnavailable = 0xC002003F,
  RpcNtInvalidNafId = 0xC0020040,
  RpcNtCannotSupport = 0xC0020041,
  RpcNtNoContextAvailable = 0xC0020042,
  RpcNtInternalError = 0xC0020043,
  RpcNtZeroDivide = 0xC0020044,
  RpcNtAddressError = 0xC0020045,
  RpcNtFpDivZero = 0xC0020046,
  RpcNtFpUnderflow = 0xC0020047,
  RpcNtFpOverflow = 0xC0020048,
  RpcNtCallInProgress = 0xC0020049,
  RpcNtNoMoreBindings = 0xC002004A,
  RpcNtGroupMemberNotFound = 0xC002004B,
  EptNtCantCreate = 0xC002004C,
  RpcNtInvalidObject = 0xC002004D,
  RpcNtNoInterfaces = 0xC002004F,
  RpcNtCallCancelled = 0xC0020050,
  RpcNtBindingIncomplete = 0xC0020051,
  RpcNtCommFailure = 0xC0020052,
  RpcNtUnsupportedAuthnLevel = 0xC0020053,
  RpcNtNoPrincName = 0xC0020054,
  RpcNtNotRpcError = 0xC0020055,
  RpcNtSecPkgError = 0xC0020057,
  RpcNtNotCancelled = 0xC0020058,
  RpcNtInvalidAsyncHandle = 0xC0020062,
  RpcNtInvalidAsyncCall = 0xC0020063,
  RpcNtProxyAccessDenied = 0xC0020064,
  RpcNtNoMoreEntries = 0xC0030001,
  RpcNtSsCharTransOpenFail = 0xC0030002,
  RpcNtSsCharTransShortFile = 0xC0030003,
  RpcNtSsInNullContext = 0xC0030004,
  RpcNtSsContextMismatch = 0xC0030005,
  RpcNtSsContextDamaged = 0xC0030006,
  RpcNtSsHandlesMismatch = 0xC0030007,
  RpcNtSsCannotGetCallHandle = 0xC0030008,
  RpcNtNullRefPointer = 0xC0030009,
  RpcNtEnumValueOutOfRange = 0xC003000A,
  RpcNtByteCountTooSmall = 0xC003000B,
  RpcNtBadStubData = 0xC003000C,
  RpcNtInvalidEsAction = 0xC0030059,
  RpcNtWrongEsVersion = 0xC003005A,
  RpcNtWrongStubVersion = 0xC003005B,
  RpcNtInvalidPipeObject = 0xC003005C,
  RpcNtInvalidPipeOperation = 0xC003005D,
  RpcNtWrongPipeVersion = 0xC003005E,
  RpcNtPipeClosed = 0xC003005F,
  RpcNtPipeDisciplineError = 0xC0030060,
  RpcNtPipeEmpty = 0xC0030061,
  PnpBadMpsTable = 0xC0040035,
  PnpTranslationFailed = 0xC0040036,
  PnpIrqTranslationFailed = 0xC0040037,
  PnpInvalidId = 0xC0040038,
  IoReissueAsCached = 0xC0040039,
  CtxWinstationNameInvalid = 0xC00A0001,
  CtxInvalidPd = 0xC00A0002,
  CtxPdNotFound = 0xC00A0003,
  CtxClosePending = 0xC00A0006,
  CtxNoOutbuf = 0xC00A0007,
  CtxModemInfNotFound = 0xC00A0008,
  CtxInvalidModemname = 0xC00A0009,
  CtxResponseError = 0xC00A000A,
  CtxModemResponseTimeout = 0xC00A000B,
  CtxModemResponseNoCarrier = 0xC00A000C,
  CtxModemResponseNoDialtone = 0xC00A000D,
  CtxModemResponseBusy = 0xC00A000E,
  CtxModemResponseVoice = 0xC00A000F,
  CtxTdError = 0xC00A0010,
  CtxLicenseClientInvalid = 0xC00A0012,
  CtxLicenseNotAvailable = 0xC00A0013,
  CtxLicenseExpired = 0xC00A0014,
  CtxWinstationNotFound = 0xC00A0015,
  CtxWinstationNameCollision = 0xC00A0016,
  CtxWinstationBusy = 0xC00A0017,
  CtxBadVideoMode = 0xC00A0018,
  CtxGraphicsInvalid = 0xC00A0022,
  CtxNotConsole = 0xC00A0024,
  CtxClientQueryTimeout = 0xC00A0026,
  CtxConsoleDisconnect = 0xC00A0027,
  CtxConsoleConnect = 0xC00A0028,
  CtxShadowDenied = 0xC00A002A,
  CtxWinstationAccessDenied = 0xC00A002B,
  CtxInvalidWd = 0xC00A002E,
  CtxWdNotFound = 0xC00A002F,
  CtxShadowInvalid = 0xC00A0030,
  CtxShadowDisabled = 0xC00A0031,
  RdpProtocolError = 0xC00A0032,
  CtxClientLicenseNotSet = 0xC00A0033,
  CtxClientLicenseInUse = 0xC00A0034,
  CtxShadowEndedByModeChange = 0xC00A0035,
  CtxShadowNotRunning = 0xC00A0036,
  CtxLogonDisabled = 0xC00A0037,
  CtxSecurityLayerError = 0xC00A0038,
  TsIncompatibleSessions = 0xC00A0039,
  MuiFileNotFound = 0xC00B0001,
  MuiInvalidFile = 0xC00B0002,
  MuiInvalidRcConfig = 0xC00B0003,
  MuiInvalidLocaleName = 0xC00B0004,
  MuiInvalidUltimatefallbackName = 0xC00B0005,
  MuiFileNotLoaded = 0xC00B0006,
  ResourceEnumUserStop = 0xC00B0007,
  ClusterInvalidNode = 0xC0130001,
  ClusterNodeExists = 0xC0130002,
  ClusterJoinInProgress = 0xC0130003,
  ClusterNodeNotFound = 0xC0130004,
  ClusterLocalNodeNotFound = 0xC0130005,
  ClusterNetworkExists = 0xC0130006,
  ClusterNetworkNotFound = 0xC0130007,
  ClusterNetinterfaceExists = 0xC0130008,
  ClusterNetinterfaceNotFound = 0xC0130009,
  ClusterInvalidRequest = 0xC013000A,
  ClusterInvalidNetworkProvider = 0xC013000B,
  ClusterNodeDown = 0xC013000C,
  ClusterNodeUnreachable = 0xC013000D,
  ClusterNodeNotMember = 0xC013000E,
  ClusterJoinNotInProgress = 0xC013000F,
  ClusterInvalidNetwork = 0xC0130010,
  ClusterNoNetAdapters = 0xC0130011,
  ClusterNodeUp = 0xC0130012,
  ClusterNodePaused = 0xC0130013,
  ClusterNodeNotPaused = 0xC0130014,
  ClusterNoSecurityContext = 0xC0130015,
  ClusterNetworkNotInternal = 0xC0130016,
  ClusterPoisoned = 0xC0130017,
  AcpiInvalidOpcode = 0xC0140001,
  AcpiStackOverflow = 0xC0140002,
  AcpiAssertFailed = 0xC0140003,
  AcpiInvalidIndex = 0xC0140004,
  AcpiInvalidArgument = 0xC0140005,
  AcpiFatal = 0xC0140006,
  AcpiInvalidSupername = 0xC0140007,
  AcpiInvalidArgtype = 0xC0140008,
  AcpiInvalidObjtype = 0xC0140009,
  AcpiInvalidTargettype = 0xC014000A,
  AcpiIncorrectArgumentCount = 0xC014000B,
  AcpiAddressNotMapped = 0xC014000C,
  AcpiInvalidEventtype = 0xC014000D,
  AcpiHandlerCollision = 0xC014000E,
  AcpiInvalidData = 0xC014000F,
  AcpiInvalidRegion = 0xC0140010,
  AcpiInvalidAccessSize = 0xC0140011,
  AcpiAcquireGlobalLock = 0xC0140012,
  AcpiAlreadyInitialized = 0xC0140013,
  AcpiNotInitialized = 0xC0140014,
  AcpiInvalidMutexLevel = 0xC0140015,
  AcpiMutexNotOwned = 0xC0140016,
  AcpiMutexNotOwner = 0xC0140017,
  AcpiRsAccess = 0xC0140018,
  AcpiInvalidTable = 0xC0140019,
  AcpiRegHandlerFailed = 0xC0140020,
  AcpiPowerRequestFailed = 0xC0140021,
  SxsSectionNotFound = 0xC0150001,
  SxsCantGenActctx = 0xC0150002,
  SxsInvalidActctxdataFormat = 0xC0150003,
  SxsAssemblyNotFound = 0xC0150004,
  SxsManifestFormatError = 0xC0150005,
  SxsManifestParseError = 0xC0150006,
  SxsActivationContextDisabled = 0xC0150007,
  SxsKeyNotFound = 0xC0150008,
  SxsVersionConflict = 0xC0150009,
  SxsWrongSectionType = 0xC015000A,
  SxsThreadQueriesDisabled = 0xC015000B,
  SxsAssemblyMissing = 0xC015000C,
  SxsProcessDefaultAlreadySet = 0xC015000E,
  SxsEarlyDeactivation = 0xC015000F,
  SxsInvalidDeactivation = 0xC0150010,
  SxsMultipleDeactivation = 0xC0150011,
  SxsSystemDefaultActivationContextEmpty = 0xC0150012,
  SxsProcessTerminationRequested = 0xC0150013,
  SxsCorruptActivationStack = 0xC0150014,
  SxsCorruption = 0xC0150015,
  SxsInvalidIdentityAttributeValue = 0xC0150016,
  SxsInvalidIdentityAttributeName = 0xC0150017,
  SxsIdentityDuplicateAttribute = 0xC0150018,
  SxsIdentityParseError = 0xC0150019,
  SxsComponentStoreCorrupt = 0xC015001A,
  SxsFileHashMismatch = 0xC015001B,
  SxsManifestIdentitySameButContentsDifferent = 0xC015001C,
  SxsIdentitiesDifferent = 0xC015001D,
  SxsAssemblyIsNotADeployment = 0xC015001E,
  SxsFileNotPartOfAssembly = 0xC015001F,
  AdvancedInstallerFailed = 0xC0150020,
  XmlEncodingMismatch = 0xC0150021,
  SxsManifestTooBig = 0xC0150022,
  SxsSettingNotRegistered = 0xC0150023,
  SxsTransactionClosureIncomplete = 0xC0150024,
  SmiPrimitiveInstallerFailed = 0xC0150025,
  GenericCommandFailed = 0xC0150026,
  SxsFileHashMissing = 0xC0150027,
  TransactionalConflict = 0xC0190001,
  InvalidTransaction = 0xC0190002,
  TransactionNotActive = 0xC0190003,
  TmInitializationFailed = 0xC0190004,
  RmNotActive = 0xC0190005,
  RmMetadataCorrupt = 0xC0190006,
  TransactionNotJoined = 0xC0190007,
  DirectoryNotRm = 0xC0190008,
  TransactionsUnsupportedRemote = 0xC019000A,
  LogResizeInvalidSize = 0xC019000B,
  RemoteFileVersionMismatch = 0xC019000C,
  CrmProtocolAlreadyExists = 0xC019000F,
  TransactionPropagationFailed = 0xC0190010,
  CrmProtocolNotFound = 0xC0190011,
  TransactionSuperiorExists = 0xC0190012,
  TransactionRequestNotValid = 0xC0190013,
  TransactionNotRequested = 0xC0190014,
  TransactionAlreadyAborted = 0xC0190015,
  TransactionAlreadyCommitted = 0xC0190016,
  TransactionInvalidMarshallBuffer = 0xC0190017,
  CurrentTransactionNotValid = 0xC0190018,
  LogGrowthFailed = 0xC0190019,
  ObjectNoLongerExists = 0xC0190021,
  StreamMiniversionNotFound = 0xC0190022,
  StreamMiniversionNotValid = 0xC0190023,
  MiniversionInaccessibleFromSpecifiedTransaction = 0xC0190024,
  CantOpenMiniversionWithModifyIntent = 0xC0190025,
  CantCreateMoreStreamMiniversions = 0xC0190026,
  HandleNoLongerValid = 0xC0190028,
  LogCorruptionDetected = 0xC0190030,
  RmDisconnected = 0xC0190032,
  EnlistmentNotSuperior = 0xC0190033,
  FileIdentityNotPersistent = 0xC0190036,
  CantBreakTransactionalDependency = 0xC0190037,
  CantCrossRmBoundary = 0xC0190038,
  TxfDirNotEmpty = 0xC0190039,
  IndoubtTransactionsExist = 0xC019003A,
  TmVolatile = 0xC019003B,
  RollbackTimerExpired = 0xC019003C,
  TxfAttributeCorrupt = 0xC019003D,
  EfsNotAllowedInTransaction = 0xC019003E,
  TransactionalOpenNotAllowed = 0xC019003F,
  TransactedMappingUnsupportedRemote = 0xC0190040,
  TransactionRequiredPromotion = 0xC0190043,
  CannotExecuteFileInTransaction = 0xC0190044,
  TransactionsNotFrozen = 0xC0190045,
  TransactionFreezeInProgress = 0xC0190046,
  NotSnapshotVolume = 0xC0190047,
  NoSavepointWithOpenFiles = 0xC0190048,
  SparseNotAllowedInTransaction = 0xC0190049,
  TmIdentityMismatch = 0xC019004A,
  FloatedSection = 0xC019004B,
  CannotAcceptTransactedWork = 0xC019004C,
  CannotAbortTransactions = 0xC019004D,
  TransactionNotFound = 0xC019004E,
  ResourcemanagerNotFound = 0xC019004F,
  EnlistmentNotFound = 0xC0190050,
  TransactionmanagerNotFound = 0xC0190051,
  TransactionmanagerNotOnline = 0xC0190052,
  TransactionmanagerRecoveryNameCollision = 0xC0190053,
  TransactionNotRoot = 0xC0190054,
  TransactionObjectExpired = 0xC0190055,
  CompressionNotAllowedInTransaction = 0xC0190056,
  TransactionResponseNotEnlisted = 0xC0190057,
  TransactionRecordTooLong = 0xC0190058,
  NoLinkTrackingInTransaction = 0xC0190059,
  OperationNotSupportedInTransaction = 0xC019005A,
  TransactionIntegrityViolated = 0xC019005B,
  ExpiredHandle = 0xC0190060,
  TransactionNotEnlisted = 0xC0190061,
  LogSectorInvalid = 0xC01A0001,
  LogSectorParityInvalid = 0xC01A0002,
  LogSectorRemapped = 0xC01A0003,
  LogBlockIncomplete = 0xC01A0004,
  LogInvalidRange = 0xC01A0005,
  LogBlocksExhausted = 0xC01A0006,
  LogReadContextInvalid = 0xC01A0007,
  LogRestartInvalid = 0xC01A0008,
  LogBlockVersion = 0xC01A0009,
  LogBlockInvalid = 0xC01A000A,
  LogReadModeInvalid = 0xC01A000B,
  LogMetadataCorrupt = 0xC01A000D,
  LogMetadataInvalid = 0xC01A000E,
  LogMetadataInconsistent = 0xC01A000F,
  LogReservationInvalid = 0xC01A0010,
  LogCantDelete = 0xC01A0011,
  LogContainerLimitExceeded = 0xC01A0012,
  LogStartOfLog = 0xC01A0013,
  LogPolicyAlreadyInstalled = 0xC01A0014,
  LogPolicyNotInstalled = 0xC01A0015,
  LogPolicyInvalid = 0xC01A0016,
  LogPolicyConflict = 0xC01A0017,
  LogPinnedArchiveTail = 0xC01A0018,
  LogRecordNonexistent = 0xC01A0019,
  LogRecordsReservedInvalid = 0xC01A001A,
  LogSpaceReservedInvalid = 0xC01A001B,
  LogTailInvalid = 0xC01A001C,
  LogFull = 0xC01A001D,
  LogMultiplexed = 0xC01A001E,
  LogDedicated = 0xC01A001F,
  LogArchiveNotInProgress = 0xC01A0020,
  LogArchiveInProgress = 0xC01A0021,
  LogEphemeral = 0xC01A0022,
  LogNotEnoughContainers = 0xC01A0023,
  LogClientAlreadyRegistered = 0xC01A0024,
  LogClientNotRegistered = 0xC01A0025,
  LogFullHandlerInProgress = 0xC01A0026,
  LogContainerReadFailed = 0xC01A0027,
  LogContainerWriteFailed = 0xC01A0028,
  LogContainerOpenFailed = 0xC01A0029,
  LogContainerStateInvalid = 0xC01A002A,
  LogStateInvalid = 0xC01A002B,
  LogPinned = 0xC01A002C,
  LogMetadataFlushFailed = 0xC01A002D,
  LogInconsistentSecurity = 0xC01A002E,
  LogAppendedFlushFailed = 0xC01A002F,
  LogPinnedReservation = 0xC01A0030,
  VideoHungDisplayDriverThread = 0xC01B00EA,
  FltNoHandlerDefined = 0xC01C0001,
  FltContextAlreadyDefined = 0xC01C0002,
  FltInvalidAsynchronousRequest = 0xC01C0003,
  FltDisallowFastIo = 0xC01C0004,
  FltInvalidNameRequest = 0xC01C0005,
  FltNotSafeToPostOperation = 0xC01C0006,
  FltNotInitialized = 0xC01C0007,
  FltFilterNotReady = 0xC01C0008,
  FltPostOperationCleanup = 0xC01C0009,
  FltInternalError = 0xC01C000A,
  FltDeletingObject = 0xC01C000B,
  FltMustBeNonpagedPool = 0xC01C000C,
  FltDuplicateEntry = 0xC01C000D,
  FltCbdqDisabled = 0xC01C000E,
  FltDoNotAttach = 0xC01C000F,
  FltDoNotDetach = 0xC01C0010,
  FltInstanceAltitudeCollision = 0xC01C0011,
  FltInstanceNameCollision = 0xC01C0012,
  FltFilterNotFound = 0xC01C0013,
  FltVolumeNotFound = 0xC01C0014,
  FltInstanceNotFound = 0xC01C0015,
  FltContextAllocationNotFound = 0xC01C0016,
  FltInvalidContextRegistration = 0xC01C0017,
  FltNameCacheMiss = 0xC01C0018,
  FltNoDeviceObject = 0xC01C0019,
  FltVolumeAlreadyMounted = 0xC01C001A,
  FltAlreadyEnlisted = 0xC01C001B,
  FltContextAlreadyLinked = 0xC01C001C,
  FltNoWaiterForReply = 0xC01C0020,
  MonitorNoDescriptor = 0xC01D0001,
  MonitorUnknownDescriptorFormat = 0xC01D0002,
  MonitorInvalidDescriptorChecksum = 0xC01D0003,
  MonitorInvalidStandardTimingBlock = 0xC01D0004,
  MonitorWmiDatablockRegistrationFailed = 0xC01D0005,
  MonitorInvalidSerialNumberMondscBlock = 0xC01D0006,
  MonitorInvalidUserFriendlyMondscBlock = 0xC01D0007,
  MonitorNoMoreDescriptorData = 0xC01D0008,
  MonitorInvalidDetailedTimingBlock = 0xC01D0009,
  MonitorInvalidManufactureDate = 0xC01D000A,
  GraphicsNotExclusiveModeOwner = 0xC01E0000,
  GraphicsInsufficientDmaBuffer = 0xC01E0001,
  GraphicsInvalidDisplayAdapter = 0xC01E0002,
  GraphicsAdapterWasReset = 0xC01E0003,
  GraphicsInvalidDriverModel = 0xC01E0004,
  GraphicsPresentModeChanged = 0xC01E0005,
  GraphicsPresentOccluded = 0xC01E0006,
  GraphicsPresentDenied = 0xC01E0007,
  GraphicsCannotcolorconvert = 0xC01E0008,
  GraphicsPresentRedirectionDisabled = 0xC01E000B,
  GraphicsPresentUnoccluded = 0xC01E000C,
  GraphicsNoVideoMemory = 0xC01E0100,
  GraphicsCantLockMemory = 0xC01E0101,
  GraphicsAllocationBusy = 0xC01E0102,
  GraphicsTooManyReferences = 0xC01E0103,
  GraphicsTryAgainLater = 0xC01E0104,
  GraphicsTryAgainNow = 0xC01E0105,
  GraphicsAllocationInvalid = 0xC01E0106,
  GraphicsUnswizzlingApertureUnavailable = 0xC01E0107,
  GraphicsUnswizzlingApertureUnsupported = 0xC01E0108,
  GraphicsCantEvictPinnedAllocation = 0xC01E0109,
  GraphicsInvalidAllocationUsage = 0xC01E0110,
  GraphicsCantRenderLockedAllocation = 0xC01E0111,
  GraphicsAllocationClosed = 0xC01E0112,
  GraphicsInvalidAllocationInstance = 0xC01E0113,
  GraphicsInvalidAllocationHandle = 0xC01E0114,
  GraphicsWrongAllocationDevice = 0xC01E0115,
  GraphicsAllocationContentLost = 0xC01E0116,
  GraphicsGpuExceptionOnDevice = 0xC01E0200,
  GraphicsInvalidVidpnTopology = 0xC01E0300,
  GraphicsVidpnTopologyNotSupported = 0xC01E0301,
  GraphicsVidpnTopologyCurrentlyNotSupported = 0xC01E0302,
  GraphicsInvalidVidpn = 0xC01E0303,
  GraphicsInvalidVideoPresentSource = 0xC01E0304,
  GraphicsInvalidVideoPresentTarget = 0xC01E0305,
  GraphicsVidpnModalityNotSupported = 0xC01E0306,
  GraphicsInvalidVidpnSourcemodeset = 0xC01E0308,
  GraphicsInvalidVidpnTargetmodeset = 0xC01E0309,
  GraphicsInvalidFrequency = 0xC01E030A,
  GraphicsInvalidActiveRegion = 0xC01E030B,
  GraphicsInvalidTotalRegion = 0xC01E030C,
  GraphicsInvalidVideoPresentSourceMode = 0xC01E0310,
  GraphicsInvalidVideoPresentTargetMode = 0xC01E0311,
  GraphicsPinnedModeMustRemainInSet = 0xC01E0312,
  GraphicsPathAlreadyInTopology = 0xC01E0313,
  GraphicsModeAlreadyInModeset = 0xC01E0314,
  GraphicsInvalidVideopresentsourceset = 0xC01E0315,
  GraphicsInvalidVideopresenttargetset = 0xC01E0316,
  GraphicsSourceAlreadyInSet = 0xC01E0317,
  GraphicsTargetAlreadyInSet = 0xC01E0318,
  GraphicsInvalidVidpnPresentPath = 0xC01E0319,
  GraphicsNoRecommendedVidpnTopology = 0xC01E031A,
  GraphicsInvalidMonitorFrequencyrangeset = 0xC01E031B,
  GraphicsInvalidMonitorFrequencyrange = 0xC01E031C,
  GraphicsFrequencyrangeNotInSet = 0xC01E031D,
  GraphicsFrequencyrangeAlreadyInSet = 0xC01E031F,
  GraphicsStaleModeset = 0xC01E0320,
  GraphicsInvalidMonitorSourcemodeset = 0xC01E0321,
  GraphicsInvalidMonitorSourceMode = 0xC01E0322,
  GraphicsNoRecommendedFunctionalVidpn = 0xC01E0323,
  GraphicsModeIdMustBeUnique = 0xC01E0324,
  GraphicsEmptyAdapterMonitorModeSupportIntersection = 0xC01E0325,
  GraphicsVideoPresentTargetsLessThanSources = 0xC01E0326,
  GraphicsPathNotInTopology = 0xC01E0327,
  GraphicsAdapterMustHaveAtLeastOneSource = 0xC01E0328,
  GraphicsAdapterMustHaveAtLeastOneTarget = 0xC01E0329,
  GraphicsInvalidMonitordescriptorset = 0xC01E032A,
  GraphicsInvalidMonitordescriptor = 0xC01E032B,
  GraphicsMonitordescriptorNotInSet = 0xC01E032C,
  GraphicsMonitordescriptorAlreadyInSet = 0xC01E032D,
  GraphicsMonitordescriptorIdMustBeUnique = 0xC01E032E,
  GraphicsInvalidVidpnTargetSubsetType = 0xC01E032F,
  GraphicsResourcesNotRelated = 0xC01E0330,
  GraphicsSourceIdMustBeUnique = 0xC01E0331,
  GraphicsTargetIdMustBeUnique = 0xC01E0332,
  GraphicsNoAvailableVidpnTarget = 0xC01E0333,
  GraphicsMonitorCouldNotBeAssociatedWithAdapter = 0xC01E0334,
  GraphicsNoVidpnmgr = 0xC01E0335,
  GraphicsNoActiveVidpn = 0xC01E0336,
  GraphicsStaleVidpnTopology = 0xC01E0337,
  GraphicsMonitorNotConnected = 0xC01E0338,
  GraphicsSourceNotInTopology = 0xC01E0339,
  GraphicsInvalidPrimarysurfaceSize = 0xC01E033A,
  GraphicsInvalidVisibleregionSize = 0xC01E033B,
  GraphicsInvalidStride = 0xC01E033C,
  GraphicsInvalidPixelformat = 0xC01E033D,
  GraphicsInvalidColorbasis = 0xC01E033E,
  GraphicsInvalidPixelvalueaccessmode = 0xC01E033F,
  GraphicsTargetNotInTopology = 0xC01E0340,
  GraphicsNoDisplayModeManagementSupport = 0xC01E0341,
  GraphicsVidpnSourceInUse = 0xC01E0342,
  GraphicsCantAccessActiveVidpn = 0xC01E0343,
  GraphicsInvalidPathImportanceOrdinal = 0xC01E0344,
  GraphicsInvalidPathContentGeometryTransformation = 0xC01E0345,
  GraphicsPathContentGeometryTransformationNotSupported = 0xC01E0346,
  GraphicsInvalidGammaRamp = 0xC01E0347,
  GraphicsGammaRampNotSupported = 0xC01E0348,
  GraphicsMultisamplingNotSupported = 0xC01E0349,
  GraphicsModeNotInModeset = 0xC01E034A,
  GraphicsInvalidVidpnTopologyRecommendationReason = 0xC01E034D,
  GraphicsInvalidPathContentType = 0xC01E034E,
  GraphicsInvalidCopyprotectionType = 0xC01E034F,
  GraphicsUnassignedModesetAlreadyExists = 0xC01E0350,
  GraphicsInvalidScanlineOrdering = 0xC01E0352,
  GraphicsTopologyChangesNotAllowed = 0xC01E0353,
  GraphicsNoAvailableImportanceOrdinals = 0xC01E0354,
  GraphicsIncompatiblePrivateFormat = 0xC01E0355,
  GraphicsInvalidModePruningAlgorithm = 0xC01E0356,
  GraphicsInvalidMonitorCapabilityOrigin = 0xC01E0357,
  GraphicsInvalidMonitorFrequencyrangeConstraint = 0xC01E0358,
  GraphicsMaxNumPathsReached = 0xC01E0359,
  GraphicsCancelVidpnTopologyAugmentation = 0xC01E035A,
  GraphicsInvalidClientType = 0xC01E035B,
  GraphicsClientvidpnNotSet = 0xC01E035C,
  GraphicsSpecifiedChildAlreadyConnected = 0xC01E0400,
  GraphicsChildDescriptorNotSupported = 0xC01E0401,
  GraphicsNotALinkedAdapter = 0xC01E0430,
  GraphicsLeadlinkNotEnumerated = 0xC01E0431,
  GraphicsChainlinksNotEnumerated = 0xC01E0432,
  GraphicsAdapterChainNotReady = 0xC01E0433,
  GraphicsChainlinksNotStarted = 0xC01E0434,
  GraphicsChainlinksNotPoweredOn = 0xC01E0435,
  GraphicsInconsistentDeviceLinkState = 0xC01E0436,
  GraphicsNotPostDeviceDriver = 0xC01E0438,
  GraphicsAdapterAccessNotExcluded = 0xC01E043B,
  GraphicsOpmNotSupported = 0xC01E0500,
  GraphicsCoppNotSupported = 0xC01E0501,
  GraphicsUabNotSupported = 0xC01E0502,
  GraphicsOpmInvalidEncryptedParameters = 0xC01E0503,
  GraphicsOpmParameterArrayTooSmall = 0xC01E0504,
  GraphicsOpmNoProtectedOutputsExist = 0xC01E0505,
  GraphicsPvpNoDisplayDeviceCorrespondsToName = 0xC01E0506,
  GraphicsPvpDisplayDeviceNotAttachedToDesktop = 0xC01E0507,
  GraphicsPvpMirroringDevicesNotSupported = 0xC01E0508,
  GraphicsOpmInvalidPointer = 0xC01E050A,
  GraphicsOpmInternalError = 0xC01E050B,
  GraphicsOpmInvalidHandle = 0xC01E050C,
  GraphicsPvpNoMonitorsCorrespondToDisplayDevice = 0xC01E050D,
  GraphicsPvpInvalidCertificateLength = 0xC01E050E,
  GraphicsOpmSpanningModeEnabled = 0xC01E050F,
  GraphicsOpmTheaterModeEnabled = 0xC01E0510,
  GraphicsPvpHfsFailed = 0xC01E0511,
  GraphicsOpmInvalidSrm = 0xC01E0512,
  GraphicsOpmOutputDoesNotSupportHdcp = 0xC01E0513,
  GraphicsOpmOutputDoesNotSupportAcp = 0xC01E0514,
  GraphicsOpmOutputDoesNotSupportCgmsa = 0xC01E0515,
  GraphicsOpmHdcpSrmNeverSet = 0xC01E0516,
  GraphicsOpmResolutionTooHigh = 0xC01E0517,
  GraphicsOpmAllHdcpHardwareAlreadyInUse = 0xC01E0518,
  GraphicsOpmProtectedOutputNoLongerExists = 0xC01E051A,
  GraphicsOpmSessionTypeChangeInProgress = 0xC01E051B,
  GraphicsOpmProtectedOutputDoesNotHaveCoppSemantics = 0xC01E051C,
  GraphicsOpmInvalidInformationRequest = 0xC01E051D,
  GraphicsOpmDriverInternalError = 0xC01E051E,
  GraphicsOpmProtectedOutputDoesNotHaveOpmSemantics = 0xC01E051F,
  GraphicsOpmSignalingNotSupported = 0xC01E0520,
  GraphicsOpmInvalidConfigurationRequest = 0xC01E0521,
  GraphicsI2cNotSupported = 0xC01E0580,
  GraphicsI2cDeviceDoesNotExist = 0xC01E0581,
  GraphicsI2cErrorTransmittingData = 0xC01E0582,
  GraphicsI2cErrorReceivingData = 0xC01E0583,
  GraphicsDdcciVcpNotSupported = 0xC01E0584,
  GraphicsDdcciInvalidData = 0xC01E0585,
  GraphicsDdcciMonitorReturnedInvalidTimingStatusByte = 0xC01E0586,
  GraphicsDdcciInvalidCapabilitiesString = 0xC01E0587,
  GraphicsMcaInternalError = 0xC01E0588,
  GraphicsDdcciInvalidMessageCommand = 0xC01E0589,
  GraphicsDdcciInvalidMessageLength = 0xC01E058A,
  GraphicsDdcciInvalidMessageChecksum = 0xC01E058B,
  GraphicsInvalidPhysicalMonitorHandle = 0xC01E058C,
  GraphicsMonitorNoLongerExists = 0xC01E058D,
  GraphicsOnlyConsoleSessionSupported = 0xC01E05E0,
  GraphicsNoDisplayDeviceCorrespondsToName = 0xC01E05E1,
  GraphicsDisplayDeviceNotAttachedToDesktop = 0xC01E05E2,
  GraphicsMirroringDevicesNotSupported = 0xC01E05E3,
  GraphicsInvalidPointer = 0xC01E05E4,
  GraphicsNoMonitorsCorrespondToDisplayDevice = 0xC01E05E5,
  GraphicsParameterArrayTooSmall = 0xC01E05E6,
  GraphicsInternalError = 0xC01E05E7,
  GraphicsSessionTypeChangeInProgress = 0xC01E05E8,
  FveLockedVolume = 0xC0210000,
  FveNotEncrypted = 0xC0210001,
  FveBadInformation = 0xC0210002,
  FveTooSmall = 0xC0210003,
  FveFailedWrongFs = 0xC0210004,
  FveFailedBadFs = 0xC0210005,
  FveFsNotExtended = 0xC0210006,
  FveFsMounted = 0xC0210007,
  FveNoLicense = 0xC0210008,
  FveActionNotAllowed = 0xC0210009,
  FveBadData = 0xC021000A,
  FveVolumeNotBound = 0xC021000B,
  FveNotDataVolume = 0xC021000C,
  FveConvReadError = 0xC021000D,
  FveConvWriteError = 0xC021000E,
  FveOverlappedUpdate = 0xC021000F,
  FveFailedSectorSize = 0xC0210010,
  FveFailedAuthentication = 0xC0210011,
  FveNotOsVolume = 0xC0210012,
  FveKeyfileNotFound = 0xC0210013,
  FveKeyfileInvalid = 0xC0210014,
  FveKeyfileNoVmk = 0xC0210015,
  FveTpmDisabled = 0xC0210016,
  FveTpmSrkAuthNotZero = 0xC0210017,
  FveTpmInvalidPcr = 0xC0210018,
  FveTpmNoVmk = 0xC0210019,
  FvePinInvalid = 0xC021001A,
  FveAuthInvalidApplication = 0xC021001B,
  FveAuthInvalidConfig = 0xC021001C,
  FveDebuggerEnabled = 0xC021001D,
  FveDryRunFailed = 0xC021001E,
  FveBadMetadataPointer = 0xC021001F,
  FveOldMetadataCopy = 0xC0210020,
  FveRebootRequired = 0xC0210021,
  FveRawAccess = 0xC0210022,
  FveRawBlocked = 0xC0210023,
  FveNoFeatureLicense = 0xC0210026,
  FvePolicyUserDisableRdvNotAllowed = 0xC0210027,
  FveConvRecoveryFailed = 0xC0210028,
  FveVirtualizedSpaceTooBig = 0xC0210029,
  FveVolumeTooSmall = 0xC0210030,
  FwpCalloutNotFound = 0xC0220001,
  FwpConditionNotFound = 0xC0220002,
  FwpFilterNotFound = 0xC0220003,
  FwpLayerNotFound = 0xC0220004,
  FwpProviderNotFound = 0xC0220005,
  FwpProviderContextNotFound = 0xC0220006,
  FwpSublayerNotFound = 0xC0220007,
  FwpNotFound = 0xC0220008,
  FwpAlreadyExists = 0xC0220009,
  FwpInUse = 0xC022000A,
  FwpDynamicSessionInProgress = 0xC022000B,
  FwpWrongSession = 0xC022000C,
  FwpNoTxnInProgress = 0xC022000D,
  FwpTxnInProgress = 0xC022000E,
  FwpTxnAborted = 0xC022000F,
  FwpSessionAborted = 0xC0220010,
  FwpIncompatibleTxn = 0xC0220011,
  FwpTimeout = 0xC0220012,
  FwpNetEventsDisabled = 0xC0220013,
  FwpIncompatibleLayer = 0xC0220014,
  FwpKmClientsOnly = 0xC0220015,
  FwpLifetimeMismatch = 0xC0220016,
  FwpBuiltinObject = 0xC0220017,
  FwpTooManyBoottimeFilters = 0xC0220018,
  FwpTooManyCallouts = 0xC0220018,
  FwpNotificationDropped = 0xC0220019,
  FwpTrafficMismatch = 0xC022001A,
  FwpIncompatibleSaState = 0xC022001B,
  FwpNullPointer = 0xC022001C,
  FwpInvalidEnumerator = 0xC022001D,
  FwpInvalidFlags = 0xC022001E,
  FwpInvalidNetMask = 0xC022001F,
  FwpInvalidRange = 0xC0220020,
  FwpInvalidInterval = 0xC0220021,
  FwpZeroLengthArray = 0xC0220022,
  FwpNullDisplayName = 0xC0220023,
  FwpInvalidActionType = 0xC0220024,
  FwpInvalidWeight = 0xC0220025,
  FwpMatchTypeMismatch = 0xC0220026,
  FwpTypeMismatch = 0xC0220027,
  FwpOutOfBounds = 0xC0220028,
  FwpReserved = 0xC0220029,
  FwpDuplicateCondition = 0xC022002A,
  FwpDuplicateKeymod = 0xC022002B,
  FwpActionIncompatibleWithLayer = 0xC022002C,
  FwpActionIncompatibleWithSublayer = 0xC022002D,
  FwpContextIncompatibleWithLayer = 0xC022002E,
  FwpContextIncompatibleWithCallout = 0xC022002F,
  FwpIncompatibleAuthMethod = 0xC0220030,
  FwpIncompatibleDhGroup = 0xC0220031,
  FwpEmNotSupported = 0xC0220032,
  FwpNeverMatch = 0xC0220033,
  FwpProviderContextMismatch = 0xC0220034,
  FwpInvalidParameter = 0xC0220035,
  FwpTooManySublayers = 0xC0220036,
  FwpCalloutNotificationFailed = 0xC0220037,
  FwpIncompatibleAuthConfig = 0xC0220038,
  FwpIncompatibleCipherConfig = 0xC0220039,
  FwpDuplicateAuthMethod = 0xC022003C,
  FwpTcpipNotReady = 0xC0220100,
  FwpInjectHandleClosing = 0xC0220101,
  FwpInjectHandleStale = 0xC0220102,
  FwpCannotPend = 0xC0220103,
  NdisClosing = 0xC0230002,
  NdisBadVersion = 0xC0230004,
  NdisBadCharacteristics = 0xC0230005,
  NdisAdapterNotFound = 0xC0230006,
  NdisOpenFailed = 0xC0230007,
  NdisDeviceFailed = 0xC0230008,
  NdisMulticastFull = 0xC0230009,
  NdisMulticastExists = 0xC023000A,
  NdisMulticastNotFound = 0xC023000B,
  NdisRequestAborted = 0xC023000C,
  NdisResetInProgress = 0xC023000D,
  NdisInvalidPacket = 0xC023000F,
  NdisInvalidDeviceRequest = 0xC0230010,
  NdisAdapterNotReady = 0xC0230011,
  NdisInvalidLength = 0xC0230014,
  NdisInvalidData = 0xC0230015,
  NdisBufferTooShort = 0xC0230016,
  NdisInvalidOid = 0xC0230017,
  NdisAdapterRemoved = 0xC0230018,
  NdisUnsupportedMedia = 0xC0230019,
  NdisGroupAddressInUse = 0xC023001A,
  NdisFileNotFound = 0xC023001B,
  NdisErrorReadingFile = 0xC023001C,
  NdisAlreadyMapped = 0xC023001D,
  NdisResourceConflict = 0xC023001E,
  NdisMediaDisconnected = 0xC023001F,
  NdisInvalidAddress = 0xC0230022,
  NdisPaused = 0xC023002A,
  NdisInterfaceNotFound = 0xC023002B,
  NdisUnsupportedRevision = 0xC023002C,
  NdisInvalidPort = 0xC023002D,
  NdisInvalidPortState = 0xC023002E,
  NdisLowPowerState = 0xC023002F,
  NdisNotSupported = 0xC02300BB,
  NdisOffloadPolicy = 0xC023100F,
  NdisOffloadConnectionRejected = 0xC0231012,
  NdisOffloadPathRejected = 0xC0231013,
  NdisDot11AutoConfigEnabled = 0xC0232000,
  NdisDot11MediaInUse = 0xC0232001,
  NdisDot11PowerStateInvalid = 0xC0232002,
  NdisPmWolPatternListFull = 0xC0232003,
  NdisPmProtocolOffloadListFull = 0xC0232004,
  IpsecBadSpi = 0xC0360001,
  IpsecSaLifetimeExpired = 0xC0360002,
  IpsecWrongSa = 0xC0360003,
  IpsecReplayCheckFailed = 0xC0360004,
  IpsecInvalidPacket = 0xC0360005,
  IpsecIntegrityCheckFailed = 0xC0360006,
  IpsecClearTextDrop = 0xC0360007,
  IpsecAuthFirewallDrop = 0xC0360008,
  IpsecThrottleDrop = 0xC0360009,
  IpsecDospBlock = 0xC0368000,
  IpsecDospReceivedMulticast = 0xC0368001,
  IpsecDospInvalidPacket = 0xC0368002,
  IpsecDospStateLookupFailed = 0xC0368003,
  IpsecDospMaxEntries = 0xC0368004,
  IpsecDospKeymodNotAllowed = 0xC0368005,
  IpsecDospMaxPerIpRatelimitQueues = 0xC0368006,
  VolmgrMirrorNotSupported = 0xC038005B,
  VolmgrRaid5NotSupported = 0xC038005C,
  VirtdiskProviderNotFound = 0xC03A0014,
  VirtdiskNotVirtualDisk = 0xC03A0015,
  VhdParentVhdAccessDenied = 0xC03A0016,
  VhdChildParentSizeMismatch = 0xC03A0017,
  VhdDifferencingChainCycleDetected = 0xC03A0018,
  VhdDifferencingChainErrorInParent = 0xC03A0019,
};

/* 63 */
typedef enum AccessMask ContextFlags;

/* 61 */
struct _M128A
{
  unsigned __int64 Low;
  __int64 High;
};

/* 64 */
struct _XSAVE_FORMAT
{
  unsigned __int16 ControlWord;
  unsigned __int16 StatusWord;
  unsigned __int8 TagWord;
  unsigned __int8 Reserved1;
  unsigned __int16 ErrorOpcode;
  unsigned int ErrorOffset;
  unsigned __int16 ErrorSelector;
  unsigned __int16 Reserved2;
  unsigned int DataOffset;
  unsigned __int16 DataSelector;
  unsigned __int16 Reserved3;
  unsigned int MxCsr;
  unsigned int MxCsr_Mask;
  struct _M128A FloatRegisters[8];
  struct _M128A XmmRegisters[16];
  unsigned __int8 Reserved4[96];
};

/* 65 */
struct _SIMD_REGISTERS
{
  struct _M128A Header[2];
  struct _M128A Legacy[8];
  struct _M128A Xmm0;
  struct _M128A Xmm1;
  struct _M128A Xmm2;
  struct _M128A Xmm3;
  struct _M128A Xmm4;
  struct _M128A Xmm5;
  struct _M128A Xmm6;
  struct _M128A Xmm7;
  struct _M128A Xmm8;
  struct _M128A Xmm9;
  struct _M128A Xmm10;
  struct _M128A Xmm11;
  struct _M128A Xmm12;
  struct _M128A Xmm13;
  struct _M128A Xmm14;
  struct _M128A Xmm15;
};

/* 66 */
union _XSAVE_UNION
{
  struct _XSAVE_FORMAT FltSave;
  struct _SIMD_REGISTERS SimdRegisters;
};

/* 67 */
struct _CONTEXT_X64
{
  unsigned __int64 P1Home;
  unsigned __int64 P2Home;
  unsigned __int64 P3Home;
  unsigned __int64 P4Home;
  unsigned __int64 P5Home;
  unsigned __int64 P6Home;
  ContextFlags ContextFlags;
  unsigned int MxCsr;
  unsigned __int16 SegCs;
  unsigned __int16 SegDs;
  unsigned __int16 SegEs;
  unsigned __int16 SegFs;
  unsigned __int16 SegGs;
  unsigned __int16 SegSs;
  unsigned int EFlags;
  unsigned __int64 Dr0;
  unsigned __int64 Dr1;
  unsigned __int64 Dr2;
  unsigned __int64 Dr3;
  unsigned __int64 Dr6;
  unsigned __int64 Dr7;
  unsigned __int64 Rax;
  unsigned __int64 Rcx;
  unsigned __int64 Rdx;
  unsigned __int64 Rbx;
  unsigned __int64 Rsp;
  unsigned __int64 Rbp;
  unsigned __int64 Rsi;
  unsigned __int64 Rdi;
  unsigned __int64 R8;
  unsigned __int64 R9;
  unsigned __int64 R10;
  unsigned __int64 R11;
  unsigned __int64 R12;
  unsigned __int64 R13;
  unsigned __int64 R14;
  unsigned __int64 R15;
  unsigned __int64 Rip;
  union _XSAVE_UNION ___u38;
  struct _M128A VectorRegister[26];
  unsigned __int64 VectorControl;
  unsigned __int64 DebugControl;
  unsigned __int64 LastBranchToRip;
  unsigned __int64 LastBranchFromRip;
  unsigned __int64 LastExceptionToRip;
  unsigned __int64 LastExceptionFromRip;
};

/* 68 */

/* 69 */
struct _EXCEPTION_RECORD
{
  enum NtStatus ExceptionCode;
  unsigned int ExceptionFlags;
  struct _EXCEPTION_RECORD *ExceptionRecord;
  void *ExceptionAddress;
  unsigned int NumberParameters;
  unsigned __int64 ExceptionInformation[15];
};


/* 70 */
struct _EXCEPTION_POINTERS
{
  struct _EXCEPTION_RECORD *ExceptionRecord;
  struct _CONTEXT_X64 *ContextRecord;
};

const unsigned __int8 g_encDataRandomTable[700] = {
    0x0C, 0x05, 0x09, 0x03, 0x0B, 0x08, 0x0D, 0x00, 0x0E, 0x0A, 0x06, 0x02, 0x0F, 0x04, 0x07, 0x01, 
    0x01, 0x06, 0x09, 0x07, 0x05, 0x00, 0x0D, 0x0E, 0x02, 0x04, 0x03, 0x0B, 0x08, 0x0F, 0x0C, 0x0A, 
    0x08, 0x04, 0x02, 0x0C, 0x01, 0x00, 0x0F, 0x09, 0x0D, 0x07, 0x05, 0x06, 0x0B, 0x0A, 0x0E, 0x03, 
    0x05, 0x00, 0x08, 0x0A, 0x09, 0x04, 0x01, 0x03, 0x0C, 0x02, 0x0F, 0x0B, 0x0E, 0x06, 0x07, 0x0D, 
    0x05, 0x04, 0x02, 0x0F, 0x01, 0x0A, 0x0B, 0x09, 0x00, 0x07, 0x0D, 0x0C, 0x03, 0x08, 0x0E, 0x06, 
    0x02, 0x08, 0x0F, 0x0B, 0x04, 0x09, 0x05, 0x00, 0x0A, 0x0C, 0x0E, 0x0D, 0x03, 0x07, 0x01, 0x06, 
    0x07, 0x0E, 0x00, 0x0C, 0x04, 0x06, 0x0F, 0x0D, 0x01, 0x05, 0x08, 0x03, 0x09, 0x0B, 0x0A, 0x02, 
    0x06, 0x08, 0x0D, 0x05, 0x0A, 0x03, 0x0B, 0x01, 0x0F, 0x02, 0x00, 0x04, 0x07, 0x09, 0x0C, 0x0E, 
    0x0E, 0x0D, 0x00, 0x0A, 0x08, 0x09, 0x0F, 0x07, 0x01, 0x06, 0x0B, 0x04, 0x02, 0x0C, 0x05, 0x03, 
    0x02, 0x08, 0x0C, 0x0F, 0x0B, 0x0E, 0x09, 0x07, 0x04, 0x05, 0x03, 0x0A, 0x0D, 0x01, 0x00, 0x06, 
    0x0C, 0x00, 0x01, 0x09, 0x07, 0x0E, 0x04, 0x03, 0x0A, 0x0B, 0x0D, 0x05, 0x0F, 0x08, 0x06, 0x02, 
    0x01, 0x02, 0x0F, 0x07, 0x06, 0x0B, 0x0E, 0x04, 0x0D, 0x03, 0x08, 0x09, 0x00, 0x0A, 0x05, 0x0C, 
    0x0F, 0x0A, 0x02, 0x08, 0x04, 0x0B, 0x01, 0x05, 0x00, 0x0D, 0x07, 0x03, 0x0E, 0x0C, 0x09, 0x06, 
    0x3F, 0x85, 0xE9, 0xC6, 0xAB, 0xAB, 0x32, 0xA6, 0x58, 0x5E, 0x23, 0xC6, 0xF1, 0xC0, 0xC9, 0x43, 
    0x46, 0x1B, 0x76, 0x1F, 0xFC, 0xF4, 0x7C, 0x55, 0x35, 0xBE, 0x92, 0x7F, 0x1C, 0x68, 0x10, 0xFF, 
    0x6E, 0xB3, 0x96, 0x3A, 0x41, 0xE0, 0xF9, 0xBC, 0x7E, 0xBD, 0xFE, 0x41, 0xCC, 0x3F, 0x28, 0xF6, 
    0xD6, 0xF9, 0xE0, 0x56, 0x27, 0xE7, 0xA5, 0x0B, 0x79, 0xF2, 0x51, 0xF3, 0xF8, 0xB8, 0x7F, 0x78, 
    0x99, 0x5C, 0xB3, 0x97, 0xCE, 0xFB, 0xD1, 0x61, 0x13, 0x53, 0x36, 0xE8, 0x54, 0x2C, 0x7D, 0x02, 
    0x1D, 0xA8, 0x16, 0x05, 0x7A, 0x1F, 0xC9, 0x3E, 0xF7, 0xB0, 0x18, 0xEE, 0xEE, 0x7B, 0x7B, 0x1F, 
    0xF6, 0x57, 0x29, 0x5F, 0x0F, 0x29, 0xDD, 0x60, 0x94, 0x37, 0xE7, 0x3F, 0x77, 0x55, 0xA7, 0xA4, 
    0xB5, 0x6D, 0x87, 0x55, 0x92, 0xB3, 0x44, 0x98, 0x52, 0xAB, 0x2F, 0x32, 0xFA, 0xFB, 0xBE, 0xF0, 
    0x10, 0xBF, 0x30, 0x5B, 0xAB, 0x3A, 0xF0, 0x6D, 0x1C, 0x6D, 0x26, 0x90, 0x23, 0x28, 0xC9, 0x68, 
    0x59, 0x35, 0x43, 0xAA, 0xB6, 0x31, 0xE0, 0x79, 0x48, 0xCF, 0x40, 0x0F, 0x92, 0x4D, 0xF0, 0xE8, 
    0x62, 0xBF, 0x1D, 0xA5, 0x2C, 0xD9, 0x69, 0xA1, 0x25, 0x01, 0x8D, 0x4C, 0xF4, 0xE7, 0xC3, 0x9B, 
    0x6D, 0xD1, 0x64, 0xCB, 0x27, 0x06, 0x74, 0xC5, 0x92, 0x60, 0x40, 0xE5, 0xCD, 0x00, 0xE0, 0xCE, 
    0x71, 0x85, 0x84, 0x46, 0xB2, 0x13, 0x01, 0x29, 0xC0, 0xCC, 0x6F, 0x44, 0x59, 0xB5, 0x72, 0xD6, 
    0x21, 0x5B, 0xCB, 0xFC, 0x90, 0x15, 0x9A, 0x1E, 0x40, 0x8F, 0xAD, 0xC8, 0xA0, 0x18, 0x5E, 0x29, 
    0xD6, 0xE3, 0xC1, 0x4A, 0x92, 0x28, 0xB9, 0x03, 0xCB, 0xC6, 0xAA, 0x23, 0xA6, 0x77, 0xFF, 0xC8, 
    0xCF, 0x10, 0xF5, 0x19, 0x22, 0x39, 0x2E, 0xDF, 0x6C, 0x75, 0xE3, 0x3D, 0x93, 0x97, 0x15, 0x5C, 
    0xFA, 0x31, 0xF2, 0x69, 0x63, 0xC0, 0x86, 0x06, 0x04, 0x5C, 0x19, 0xE6, 0x30, 0xA3, 0xC8, 0xC3, 
    0x86, 0x0F, 0x8A, 0xBC, 0x18, 0xF2, 0x5B, 0xC5, 0x04, 0xA3, 0xCE, 0xB0, 0xD5, 0xB9, 0x4A, 0x69, 
    0x55, 0x7B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x02, 0x03, 0x05, 0x07, 0x0B, 0x0D, 0x11, 0x13, 0x17, 0x1D, 0x1F, 0x25, 0x29, 0x2B, 0x2F, 0x35, 
    0x3B, 0x3D, 0x43, 0x47, 0x49, 0x4F, 0x53, 0x59, 0x61, 0x65, 0x67, 0x6B, 0x6D, 0x71, 0x7F, 0x83, 
    0x89, 0x8B, 0x95, 0x97, 0x9D, 0xA3, 0xA7, 0xAD, 0xB3, 0xB5, 0xBF, 0xC1, 0xC5, 0xC7, 0xD3, 0xDF, 
    0xE3, 0xE5, 0xE9, 0xEF, 0xF1, 0xFB, 0x8E, 0x66, 0x9E, 0xD3, 0xF6, 0xCA, 0xA9, 0xA6, 0x92, 0x1B, 
    0x34, 0xBF, 0x74, 0x16, 0xE6, 0xE7, 0x61, 0x6C, 0xB8, 0x21, 0xD1, 0x7C, 0x31, 0x51, 0xB6, 0x3C, 
    0x49, 0xC8, 0x64, 0xF6, 0xAE, 0xEA, 0x75, 0x31, 0x2C, 0x09, 0x37, 0x75, 0x22, 0xC8, 0xA4, 0xC8, 
    0xFE, 0x7C, 0xAF, 0x9C, 0x30, 0xCD, 0x83, 0x8A, 0x94, 0x2D, 0x2F, 0x55, 0x79, 0xAE, 0xDB, 0x2E, 
    0x50, 0xA3, 0x2B, 0x7E, 0x39, 0x93, 0x7C, 0xDF, 0x4C, 0xEC, 0xED, 0xF4, 0x51, 0x3E, 0xFD, 0x3B, 
    0x41, 0x1C, 0xB1, 0x9B, 0x06, 0xAE, 0xE6, 0xAB, 0x1B, 0x14, 0x3F, 0x61, 0xD9, 0x1F, 0xB3, 0x26, 
    0x22, 0x34, 0xB9, 0x00
};


const unsigned __int64 v1702 =  0x9BD8FE58859C5374;
const unsigned __int64 qword_1802D2B19 = 0x281C3663DA3197FA;
const unsigned __int64 qword_1802D2C51 = 0xB76BFFAE3B3B94B8;
const unsigned __int64 qword_1802D2C99 = 0xDE03F46FCD0D7CAA;
const unsigned __int32 dword_1802D2E48 = 0x88A8C6E5;
const unsigned __int32 dword_1802D2DBC = 0xF4C84FC4;


extern void _InterlockedExchangeW(int, int, int, int, int);

DONT_OPTIMIZE();
__int64 constant_folding_test1() {
    bool b = 0;
    unsigned __int64 v46 = __ROL8__(
              __ROL8__(
                  (((__ROL4__(__ROL4__(0x6EBCBAA1, 4) + 0x6B9F6F9A, 3) ^ 0x770BB7B8u) + 0x33AC85C6)
                 ^ 0x281C3663DA3197B5LL)
                + 0x3A9CCBED1AC47F6LL,
                  0x20)
            ^ 0xDE838D86533A540LL,
              0x3C);
    unsigned __int64 v5 = __ROL8__(
             __ROL8__(
                 (((unsigned long)g_encDataRandomTable[((v46 >> 0x34) & 0xF)
                                                                        + 0x60] << 0x34)
                | (0x10LL * g_encDataRandomTable[((unsigned __int8)v46 >> 4) + 0x60])
                | ((unsigned long)g_encDataRandomTable[((v46 >> 0x28) & 0xF)
                                                                        + 0x60] << 0x28)
                | (g_encDataRandomTable[(((unsigned int)v46 >> 8) & 0xF) + 0x60] << 8)
                | ((unsigned long)g_encDataRandomTable[(v46 >> 0x3C) + 0x60] << 0x3C)
                | ((unsigned long)g_encDataRandomTable[((v46 >> 0x2C) & 0xF)
                                                                        + 0x60] << 0x2C)
                | (g_encDataRandomTable[(((unsigned int)v46 >> 0x14) & 0xF) + 0x60] << 0x14)
                | ((unsigned long)g_encDataRandomTable[(BYTE6(v46) & 0xF) + 0x60] << 0x30)
                | (g_encDataRandomTable[(BYTE3(v46) & 0xF) + 0x60] << 0x18)
                | (g_encDataRandomTable[((unsigned __int16)v46 >> 0xC) + 0x60] << 0xC)
                | ((unsigned long)g_encDataRandomTable[(HIBYTE(v46) & 0xF) + 0x60] << 0x38)
                | ((unsigned long)g_encDataRandomTable[(BYTE4(v46) & 0xF) + 0x60] << 0x20)
                | (g_encDataRandomTable[(BYTE2(v46) & 0xF) + 0x60] << 0x10)
                | ((unsigned long)g_encDataRandomTable[((unsigned int)v46 >> 0x1C)
                                                                        + 0x60] << 0x1C)
                | ((unsigned long)g_encDataRandomTable[((v46 >> 0x24) & 0xF)
                                                                        + 0x60] << 0x24)
                | g_encDataRandomTable[(v46 & 0xF) + 0x60])
               - 0x2662A2D5F43B2FCCLL,
                 0x2E),
             0x12)
       + 0x2662A2D5F43B2FCCLL;
    unsigned __int64 v15 = g_encDataRandomTable[(v5 & 0xF) + 0x50]
        | (g_encDataRandomTable[((unsigned __int16)v5 >> 0xC) + 0x50] << 0xC)
        | ((unsigned long)g_encDataRandomTable[(v5 >> 0x3C) + 0x50] << 0x3C)
        | (0x10
         * (unsigned int)g_encDataRandomTable[((unsigned __int8)v5 >> 4) + 0x50])
        | ((unsigned long)g_encDataRandomTable[((v5 >> 0x28) & 0xF) + 0x50] << 0x28)
        | (g_encDataRandomTable[(BYTE1(v5) & 0xF) + 0x50] << 8)
        | ((unsigned long)g_encDataRandomTable[((v5 >> 0x2C) & 0xF) + 0x50] << 0x2C)
        | (g_encDataRandomTable[(((unsigned int)v5 >> 0x14) & 0xF) + 0x50] << 0x14)
        | ((unsigned long)g_encDataRandomTable[(BYTE6(v5) & 0xF) + 0x50] << 0x30)
        | (g_encDataRandomTable[(BYTE3(v5) & 0xF) + 0x50] << 0x18)
        | ((unsigned long)g_encDataRandomTable[(HIBYTE(v5) & 0xF) + 0x50] << 0x38)
        | ((unsigned long)g_encDataRandomTable[(BYTE4(v5) & 0xF) + 0x50] << 0x20)
        | ((unsigned long)g_encDataRandomTable[(BYTE2(v5) & 0xF) + 0x50] << 0x10)
        | ((unsigned long)g_encDataRandomTable[((unsigned int)v5 >> 0x1C) + 0x50] << 0x1C)
        | ((unsigned long)g_encDataRandomTable[((v5 >> 0x24) & 0xF) + 0x50] << 0x24)
        | ((unsigned long)g_encDataRandomTable[((v5 >> 0x34) & 0xF) + 0x50] << 0x34);
    unsigned __int64 v47 = __ROL8__(v15, 4);
    if ( (qword_1802D2B19 ^ (__ROL8__(v47 ^ 0xDE838D86533A540LL, 0x20) - 0x3A9CCBED1AC47F6LL)) == 0x4F )
    {
        unsigned __int64 v48 = __ROL8__(v15, 4);
        if ( (qword_1802D2B19
            ^ (__ROL8__(v48 ^ 0xDE838D86533A540LL, 0x20) - 0x3A9CCBED1AC47F6LL)) == 0x4F )
        {
            unsigned __int64 v49 = __ROL8__(v15, 4);
            if ( (qword_1802D2B19
                ^ (__ROL8__(v49 ^ 0xDE838D86533A540LL, 0x20) - 0x3A9CCBED1AC47F6LL)) == 0x4F )
            {
                unsigned __int64 v50 = __ROL8__(v15, 4);
                if ( (qword_1802D2B19
                    ^ (__ROL8__(v50 ^ 0xDE838D86533A540LL, 0x20) - 0x3A9CCBED1AC47F6LL)) == 0x4F )
                    b = 1;
            }
        }
    }

    unsigned __int64 v45 = __ROL4__(
              __ROL4__((__ROL4__(0xEF449E19, 0x10) + 0x500EBDB) ^ 0xA33ADB1F, 0x16) - 0x5D8D7E02,
              0x18);
    unsigned __int64 v51 = __ROL4__(
              __ROL4__(
                  qword_1802D2C51
                ^ (__ROL4__(
                       __ROL4__((__ROL4__(v45 + 0x2773BBB2, 6) ^ 0x74A2863C) - 0x1E9A0ECF, 0x15),
                       0xB)
                 + 0x1E9A0ECF)
                ^ 0x4F991284,
                  0x1A)
            - 0x2773BBB2,
              8)
        + 0x5D8D7E02;
    unsigned __int64 v6 = (__ROL8__(
              (__ROL8__(
                   (((v51 ^ dword_1802D2DBC) + 0x61BBE9D7149134B0LL) ^ 0xDFEE542C76A7AAF0uLL)
                 - 0x1509678523D640EALL,
                   0xE)
             ^ 0xF0LL)
            - 0x57033546396F782ALL,
              0xE)
        + 0x7D019B7AE2EB4B6FLL)
       ^ 0x2EFFBB12A651F46CLL;
    return v6;
}
ENABLE_OPTIMIZE();

// outlined function 1
__int64 outlined_helper_1(__int64 a1, __int64 a2, __int64 a3, unsigned int *a4)
{
    return *a4;
}

// outlined function 2
__int64 outlined_helper_2(_DWORD *a1)
{
    __int64 result = (unsigned int)(__ROL4__(__ROL4__(*a1, 0x1E) + 0x709572C9, 9) + 0x6B177BA5);
    *a1 = result;
    return result;
}

__int64 AntiDebug_ExceptionFilter(
        int unused1,
        int unused2,
        int unused3,
        struct _EXCEPTION_POINTERS *exception)
{
    unsigned int n2_1;
    unsigned int n2; // [rsp+34h] [rbp-C64h]
    unsigned __int64 v7; // [rsp+38h] [rbp-C60h]
    unsigned __int64 v8; // [rsp+40h] [rbp-C58h]
    unsigned __int64 v9; // [rsp+48h] [rbp-C50h]
    unsigned __int8 v10; // [rsp+56h] [rbp-C42h]
    unsigned __int8 v11; // [rsp+57h] [rbp-C41h]
    unsigned __int8 v12; // [rsp+58h] [rbp-C40h]
    unsigned __int8 v13; // [rsp+59h] [rbp-C3Fh]
    unsigned __int8 v14; // [rsp+5Ah] [rbp-C3Eh]
    unsigned __int8 v15; // [rsp+5Bh] [rbp-C3Dh]
    unsigned __int8 v16; // [rsp+5Ch] [rbp-C3Ch]
    unsigned __int8 v17; // [rsp+5Dh] [rbp-C3Bh]
    unsigned __int8 v18; // [rsp+5Eh] [rbp-C3Ah]
    unsigned __int8 v19; // [rsp+5Fh] [rbp-C39h]
    unsigned __int8 v20; // [rsp+60h] [rbp-C38h]
    unsigned __int8 v21; // [rsp+61h] [rbp-C37h]
    unsigned __int8 v22; // [rsp+62h] [rbp-C36h]
    unsigned __int8 v23; // [rsp+63h] [rbp-C35h]
    unsigned __int8 v24; // [rsp+64h] [rbp-C34h]
    unsigned __int8 v25; // [rsp+65h] [rbp-C33h]
    unsigned __int8 v26; // [rsp+66h] [rbp-C32h]
    unsigned __int8 v27; // [rsp+67h] [rbp-C31h]
    unsigned __int64 v28; // [rsp+68h] [rbp-C30h]
    unsigned __int64 v29; // [rsp+70h] [rbp-C28h]
    unsigned __int64 v30; // [rsp+78h] [rbp-C20h]
    unsigned __int64 v31; // [rsp+80h] [rbp-C18h]
    unsigned __int64 v32; // [rsp+88h] [rbp-C10h]
    unsigned __int64 v33; // [rsp+90h] [rbp-C08h]
    unsigned __int64 v34; // [rsp+98h] [rbp-C00h]
    unsigned __int64 v35; // [rsp+A0h] [rbp-BF8h]
    unsigned __int64 v36; // [rsp+A8h] [rbp-BF0h]
    unsigned __int64 v37; // [rsp+B0h] [rbp-BE8h]
    unsigned __int64 v38; // [rsp+B8h] [rbp-BE0h]
    __int64 v39; // [rsp+C0h] [rbp-BD8h]
    unsigned __int64 v40; // [rsp+C8h] [rbp-BD0h]
    unsigned __int64 v41; // [rsp+D0h] [rbp-BC8h]
    unsigned __int64 v42; // [rsp+D8h] [rbp-BC0h]
    unsigned __int64 v43; // [rsp+E0h] [rbp-BB8h]
    unsigned __int64 v44; // [rsp+E8h] [rbp-BB0h]
    unsigned __int64 v45; // [rsp+F0h] [rbp-BA8h]
    int n0x6EBCBAA1; // [rsp+104h] [rbp-B94h]
    unsigned int v47; // [rsp+108h] [rbp-B90h]
    int v48; // [rsp+10Ch] [rbp-B8Ch]
    int v49; // [rsp+110h] [rbp-B88h]
    int v50; // [rsp+114h] [rbp-B84h]
    int v51; // [rsp+118h] [rbp-B80h]
    int v52; // [rsp+11Ch] [rbp-B7Ch]
    int v53; // [rsp+120h] [rbp-B78h]
    int v54; // [rsp+124h] [rbp-B74h]
    int v55; // [rsp+128h] [rbp-B70h]
    int v56; // [rsp+12Ch] [rbp-B6Ch]
    int v57; // [rsp+130h] [rbp-B68h]
    int v58; // [rsp+134h] [rbp-B64h]
    unsigned __int8 v59; // [rsp+138h] [rbp-B60h]
    int v60; // [rsp+13Ch] [rbp-B5Ch]
    int v61; // [rsp+140h] [rbp-B58h]
    int v62; // [rsp+144h] [rbp-B54h]
    int v63; // [rsp+148h] [rbp-B50h]
    int v64; // [rsp+14Ch] [rbp-B4Ch]
    int v65; // [rsp+150h] [rbp-B48h]
    int v66; // [rsp+154h] [rbp-B44h]
    int v67; // [rsp+158h] [rbp-B40h]
    int v68; // [rsp+15Ch] [rbp-B3Ch]
    unsigned __int8 v69; // [rsp+160h] [rbp-B38h]
    int v70; // [rsp+164h] [rbp-B34h]
    int v71; // [rsp+168h] [rbp-B30h]
    int v72; // [rsp+16Ch] [rbp-B2Ch]
    int v73; // [rsp+170h] [rbp-B28h]
    int v74; // [rsp+174h] [rbp-B24h]
    int v75; // [rsp+178h] [rbp-B20h]
    int v76; // [rsp+17Ch] [rbp-B1Ch]
    int v77; // [rsp+180h] [rbp-B18h]
    int v78; // [rsp+184h] [rbp-B14h]
    int v79; // [rsp+188h] [rbp-B10h]
    unsigned int v80; // [rsp+18Ch] [rbp-B0Ch]
    char v81; // [rsp+190h] [rbp-B08h]
    int v82; // [rsp+194h] [rbp-B04h]
    int v83; // [rsp+198h] [rbp-B00h]
    int v84; // [rsp+19Ch] [rbp-AFCh]
    unsigned int v85; // [rsp+1A0h] [rbp-AF8h]
    int v86; // [rsp+1A4h] [rbp-AF4h]
    int v87; // [rsp+1A8h] [rbp-AF0h]
    int v88; // [rsp+1ACh] [rbp-AECh]
    int v89; // [rsp+1B0h] [rbp-AE8h]
    unsigned int v90; // [rsp+1B4h] [rbp-AE4h]
    int v91; // [rsp+1B8h] [rbp-AE0h]
    int v92; // [rsp+1BCh] [rbp-ADCh]
    struct _CONTEXT_X64 **p_ContextRecord; // [rsp+1C0h] [rbp-AD8h]
    unsigned __int64 v94; // [rsp+1C8h] [rbp-AD0h]
    unsigned __int64 v95; // [rsp+1D0h] [rbp-AC8h]
    unsigned __int64 v96; // [rsp+1D8h] [rbp-AC0h]
    __int64 v97; // [rsp+1E0h] [rbp-AB8h]
    unsigned __int64 ContextRecord_1; // [rsp+1E8h] [rbp-AB0h]
    struct _CONTEXT_X64 *ContextRecord_3; // [rsp+1F0h] [rbp-AA8h]
    __int64 v100; // [rsp+200h] [rbp-A98h]
    __int64 v101; // [rsp+208h] [rbp-A90h]
    __int64 v102; // [rsp+210h] [rbp-A88h]
    __int64 v103; // [rsp+218h] [rbp-A80h]
    unsigned __int8 *v104; // [rsp+220h] [rbp-A78h]
    unsigned __int64 v105; // [rsp+228h] [rbp-A70h]
    unsigned __int64 v106; // [rsp+230h] [rbp-A68h]
    char v107; // [rsp+238h] [rbp-A60h]
    __int64 v108; // [rsp+240h] [rbp-A58h]
    unsigned __int64 v109; // [rsp+248h] [rbp-A50h]
    __int64 v110; // [rsp+250h] [rbp-A48h]
    unsigned __int64 v111; // [rsp+258h] [rbp-A40h]
    unsigned __int64 v112; // [rsp+260h] [rbp-A38h]
    unsigned __int64 v113; // [rsp+268h] [rbp-A30h]
    __int64 v114; // [rsp+270h] [rbp-A28h]
    unsigned __int64 v115; // [rsp+278h] [rbp-A20h]
    unsigned __int64 v116; // [rsp+280h] [rbp-A18h]
    unsigned __int8 *v117; // [rsp+288h] [rbp-A10h]
    unsigned __int64 v118; // [rsp+290h] [rbp-A08h]
    unsigned __int64 v119; // [rsp+298h] [rbp-A00h]
    unsigned __int64 v120; // [rsp+2A0h] [rbp-9F8h]
    unsigned __int64 v121; // [rsp+2A8h] [rbp-9F0h]
    unsigned __int64 v122; // [rsp+2B0h] [rbp-9E8h]
    __int64 v123; // [rsp+2B8h] [rbp-9E0h]
    unsigned __int64 v124; // [rsp+2C0h] [rbp-9D8h]
    __int64 v125; // [rsp+2C8h] [rbp-9D0h]
    unsigned __int64 v126; // [rsp+2D0h] [rbp-9C8h]
    unsigned __int64 v127; // [rsp+2D8h] [rbp-9C0h]
    unsigned __int64 v128; // [rsp+2E0h] [rbp-9B8h]
    __int64 ContextRecord; // [rsp+2E8h] [rbp-9B0h]
    struct _CONTEXT_X64 *ContextRecord_2; // [rsp+2F0h] [rbp-9A8h]
    unsigned __int64 Dr0; // [rsp+2F8h] [rbp-9A0h]
    __int64 v132; // [rsp+300h] [rbp-998h]
    unsigned __int64 v133; // [rsp+308h] [rbp-990h]
    unsigned __int64 v134; // [rsp+310h] [rbp-988h]
    unsigned __int64 v135; // [rsp+318h] [rbp-980h]
    unsigned __int64 v136; // [rsp+320h] [rbp-978h]
    unsigned __int64 v137; // [rsp+328h] [rbp-970h]
    unsigned __int64 v138; // [rsp+330h] [rbp-968h]
    unsigned __int8 *v139; // [rsp+338h] [rbp-960h]
    unsigned __int64 v140; // [rsp+340h] [rbp-958h]
    unsigned __int64 v141; // [rsp+348h] [rbp-950h]
    unsigned __int64 v142; // [rsp+350h] [rbp-948h]
    __int64 v143; // [rsp+358h] [rbp-940h]
    unsigned __int64 v144; // [rsp+360h] [rbp-938h]
    __int64 v145; // [rsp+368h] [rbp-930h]
    unsigned __int64 v146; // [rsp+370h] [rbp-928h]
    __int64 v147; // [rsp+378h] [rbp-920h]
    __int64 v148; // [rsp+380h] [rbp-918h]
    unsigned __int64 v149; // [rsp+388h] [rbp-910h]
    char v150; // [rsp+390h] [rbp-908h]
    unsigned __int64 v151; // [rsp+398h] [rbp-900h]
    __int64 v152; // [rsp+3A0h] [rbp-8F8h]
    unsigned __int64 v153; // [rsp+3A8h] [rbp-8F0h]
    unsigned __int8 *v154; // [rsp+3B0h] [rbp-8E8h]
    unsigned __int64 v155; // [rsp+3B8h] [rbp-8E0h]
    unsigned __int64 v156; // [rsp+3C0h] [rbp-8D8h]
    __int64 v157; // [rsp+3C8h] [rbp-8D0h]
    unsigned __int64 v158; // [rsp+3D0h] [rbp-8C8h]
    unsigned __int8 *v159; // [rsp+3D8h] [rbp-8C0h]
    __int64 v160; // [rsp+3E0h] [rbp-8B8h]
    __int64 v161; // [rsp+3E8h] [rbp-8B0h]
    __int64 v1014; // [rsp+3F0h] [rbp-8A8h]
    __int64 v163; // [rsp+3F8h] [rbp-8A0h]
    unsigned __int64 v164; // [rsp+400h] [rbp-898h]
    unsigned __int64 v165; // [rsp+408h] [rbp-890h]
    unsigned __int8 *v166; // [rsp+410h] [rbp-888h]
    unsigned __int64 v167; // [rsp+418h] [rbp-880h]
    unsigned __int64 v168; // [rsp+420h] [rbp-878h]
    unsigned __int64 v169; // [rsp+428h] [rbp-870h]
    unsigned __int64 v170; // [rsp+430h] [rbp-868h]
    unsigned __int64 v171; // [rsp+438h] [rbp-860h]
    unsigned __int64 v172; // [rsp+440h] [rbp-858h]
    unsigned __int64 v173; // [rsp+448h] [rbp-850h]
    unsigned __int64 v174; // [rsp+450h] [rbp-848h]
    unsigned __int64 v175; // [rsp+458h] [rbp-840h]
    unsigned __int8 *v176; // [rsp+460h] [rbp-838h]
    unsigned __int64 v177; // [rsp+468h] [rbp-830h]
    unsigned __int64 v178; // [rsp+470h] [rbp-828h]
    unsigned __int64 v179; // [rsp+478h] [rbp-820h]
    unsigned __int64 v180; // [rsp+480h] [rbp-818h]
    __int64 v181; // [rsp+488h] [rbp-810h]
    unsigned __int64 v182; // [rsp+490h] [rbp-808h]
    unsigned __int64 v183; // [rsp+498h] [rbp-800h]
    unsigned __int64 v184; // [rsp+4A0h] [rbp-7F8h]
    unsigned __int64 v185; // [rsp+4A8h] [rbp-7F0h]
    unsigned __int8 *v186; // [rsp+4B0h] [rbp-7E8h]
    unsigned __int64 v187; // [rsp+4B8h] [rbp-7E0h]
    unsigned __int64 v188; // [rsp+4C0h] [rbp-7D8h]
    unsigned __int64 v189; // [rsp+4C8h] [rbp-7D0h]
    unsigned __int64 v190; // [rsp+4D0h] [rbp-7C8h]
    unsigned __int64 v191; // [rsp+4D8h] [rbp-7C0h]
    __int64 v192; // [rsp+4E0h] [rbp-7B8h]
    __int64 v193; // [rsp+4E8h] [rbp-7B0h]
    __int64 v1014_1; // [rsp+4F0h] [rbp-7A8h]
    __int64 v1805; // [rsp+4F8h] [rbp-7A0h]
    __int64 v196; // [rsp+500h] [rbp-798h]
    unsigned __int64 v197; // [rsp+508h] [rbp-790h]
    unsigned __int64 v198; // [rsp+510h] [rbp-788h]
    unsigned __int8 *v199; // [rsp+518h] [rbp-780h]
    unsigned __int64 v200; // [rsp+520h] [rbp-778h]
    unsigned __int64 v201; // [rsp+528h] [rbp-770h]
    unsigned __int64 v202; // [rsp+530h] [rbp-768h]
    unsigned __int64 v203; // [rsp+538h] [rbp-760h]
    unsigned __int8 *v204; // [rsp+540h] [rbp-758h]
    unsigned __int64 v205; // [rsp+548h] [rbp-750h]
    unsigned __int64 v206; // [rsp+550h] [rbp-748h]
    unsigned __int64 v207; // [rsp+558h] [rbp-740h]
    unsigned __int64 v208; // [rsp+560h] [rbp-738h]
    __int64 v209; // [rsp+568h] [rbp-730h]
    unsigned __int64 v210; // [rsp+570h] [rbp-728h]
    unsigned __int8 *v211; // [rsp+578h] [rbp-720h]
    unsigned __int64 v212; // [rsp+580h] [rbp-718h]
    unsigned __int64 v213; // [rsp+588h] [rbp-710h]
    unsigned __int64 v214; // [rsp+590h] [rbp-708h]
    unsigned __int64 v215; // [rsp+598h] [rbp-700h]
    __int64 v216; // [rsp+5A0h] [rbp-6F8h]
    unsigned __int64 v217; // [rsp+5A8h] [rbp-6F0h]
    __int64 v218; // [rsp+5B0h] [rbp-6E8h]
    unsigned __int64 v219; // [rsp+5B8h] [rbp-6E0h]
    __int64 v220; // [rsp+5C0h] [rbp-6D8h]
    unsigned __int64 v221; // [rsp+5C8h] [rbp-6D0h]
    unsigned __int64 v222; // [rsp+5D0h] [rbp-6C8h]
    __int64 v223; // [rsp+5D8h] [rbp-6C0h]
    unsigned __int64 v224; // [rsp+5E0h] [rbp-6B8h]
    unsigned __int64 v225; // [rsp+5E8h] [rbp-6B0h]
    unsigned __int8 *v226; // [rsp+5F0h] [rbp-6A8h]
    unsigned __int64 v227; // [rsp+5F8h] [rbp-6A0h]
    unsigned __int64 v228; // [rsp+600h] [rbp-698h]
    unsigned __int64 v229; // [rsp+608h] [rbp-690h]
    unsigned __int8 *v230; // [rsp+610h] [rbp-688h]
    __int64 v231; // [rsp+618h] [rbp-680h]
    unsigned __int64 v232; // [rsp+620h] [rbp-678h]
    unsigned __int64 v233; // [rsp+628h] [rbp-670h]
    unsigned __int64 v234; // [rsp+630h] [rbp-668h]
    __int64 v235; // [rsp+638h] [rbp-660h]
    __int64 v236; // [rsp+640h] [rbp-658h]
    __int64 v237; // [rsp+648h] [rbp-650h]
    unsigned __int64 v238; // [rsp+650h] [rbp-648h]
    __int64 v239; // [rsp+658h] [rbp-640h]
    __int64 v240; // [rsp+660h] [rbp-638h]
    _DWORD *v241; // [rsp+668h] [rbp-630h]
    unsigned __int8 *v242; // [rsp+670h] [rbp-628h]
    unsigned __int64 v243; // [rsp+678h] [rbp-620h]
    unsigned __int64 v244; // [rsp+680h] [rbp-618h]
    unsigned __int64 v245; // [rsp+688h] [rbp-610h]
    __int64 v246; // [rsp+690h] [rbp-608h]
    unsigned __int64 v247; // [rsp+698h] [rbp-600h]
    __int64 v248; // [rsp+6A0h] [rbp-5F8h]
    unsigned __int64 v249; // [rsp+6A8h] [rbp-5F0h]
    __int64 v250; // [rsp+6B0h] [rbp-5E8h]
    __int64 v251; // [rsp+6B8h] [rbp-5E0h]
    __int64 v252; // [rsp+6C0h] [rbp-5D8h]
    __int64 v253; // [rsp+6C8h] [rbp-5D0h]
    __int64 v254; // [rsp+6D0h] [rbp-5C8h]
    __int64 v255; // [rsp+6D8h] [rbp-5C0h]
    __int64 v256; // [rsp+6E0h] [rbp-5B8h]
    unsigned __int64 v257; // [rsp+6E8h] [rbp-5B0h]
    unsigned __int64 v258; // [rsp+6F0h] [rbp-5A8h]
    unsigned __int64 v259; // [rsp+6F8h] [rbp-5A0h]
    __int64 v260; // [rsp+700h] [rbp-598h]
    __int64 v261; // [rsp+708h] [rbp-590h]
    __int64 v262; // [rsp+710h] [rbp-588h]
    __int64 v263; // [rsp+718h] [rbp-580h]
    __int64 v264; // [rsp+720h] [rbp-578h]
    unsigned __int64 v265; // [rsp+728h] [rbp-570h]
    __int64 v266; // [rsp+730h] [rbp-568h]
    unsigned __int64 v267; // [rsp+738h] [rbp-560h]
    unsigned __int64 v268; // [rsp+740h] [rbp-558h]
    unsigned __int64 v269; // [rsp+748h] [rbp-550h]
    char v270; // [rsp+750h] [rbp-548h]
    unsigned __int64 v271; // [rsp+758h] [rbp-540h]
    __int64 v272; // [rsp+760h] [rbp-538h]
    unsigned __int64 v273; // [rsp+768h] [rbp-530h]
    unsigned __int64 v274; // [rsp+770h] [rbp-528h]
    unsigned __int64 v275; // [rsp+778h] [rbp-520h]
    unsigned __int8 *v276; // [rsp+780h] [rbp-518h]
    __int64 v277; // [rsp+788h] [rbp-510h]
    char v278; // [rsp+790h] [rbp-508h]
    __int64 v279; // [rsp+798h] [rbp-500h]
    __int64 v280; // [rsp+7A0h] [rbp-4F8h]
    unsigned __int8 *v281; // [rsp+7A8h] [rbp-4F0h]
    unsigned __int64 v282; // [rsp+7B0h] [rbp-4E8h]
    __int64 v283; // [rsp+7B8h] [rbp-4E0h]
    __int64 v284; // [rsp+7C0h] [rbp-4D8h]
    __int64 v285; // [rsp+7C8h] [rbp-4D0h]
    unsigned __int64 v286; // [rsp+7D0h] [rbp-4C8h]
    unsigned __int8 *v287; // [rsp+7D8h] [rbp-4C0h]
    __int64 v288; // [rsp+7E0h] [rbp-4B8h]
    char v289; // [rsp+7E8h] [rbp-4B0h]
    unsigned __int64 v290; // [rsp+7F0h] [rbp-4A8h]
    __int64 v291; // [rsp+7F8h] [rbp-4A0h]
    unsigned __int64 v292; // [rsp+800h] [rbp-498h]
    char v293; // [rsp+808h] [rbp-490h]
    unsigned __int64 v294; // [rsp+810h] [rbp-488h]
    unsigned __int64 v295; // [rsp+818h] [rbp-480h]
    unsigned __int64 v296; // [rsp+820h] [rbp-478h]
    unsigned __int64 v297; // [rsp+828h] [rbp-470h]
    unsigned __int64 v298; // [rsp+830h] [rbp-468h]
    __int64 v299; // [rsp+838h] [rbp-460h]
    unsigned __int64 v300; // [rsp+840h] [rbp-458h]
    unsigned __int64 v301; // [rsp+848h] [rbp-450h]
    unsigned __int64 v302; // [rsp+850h] [rbp-448h]
    __int64 v303; // [rsp+858h] [rbp-440h]
    unsigned __int64 v304; // [rsp+860h] [rbp-438h]
    __int64 v305; // [rsp+868h] [rbp-430h]
    unsigned __int64 v306; // [rsp+870h] [rbp-428h]
    unsigned __int64 v307; // [rsp+878h] [rbp-420h]
    unsigned __int64 v308; // [rsp+880h] [rbp-418h]
    unsigned __int64 v309; // [rsp+888h] [rbp-410h]
    unsigned __int64 v310; // [rsp+890h] [rbp-408h]
    unsigned __int64 v311; // [rsp+898h] [rbp-400h]
    __int64 v312; // [rsp+8A0h] [rbp-3F8h]
    unsigned __int64 v313; // [rsp+8A8h] [rbp-3F0h]
    unsigned __int64 v314; // [rsp+8B0h] [rbp-3E8h]
    __int64 v315; // [rsp+8B8h] [rbp-3E0h]
    unsigned __int8 *v316; // [rsp+8C0h] [rbp-3D8h]
    __int64 v317; // [rsp+8C8h] [rbp-3D0h]
    unsigned __int64 v318; // [rsp+8D0h] [rbp-3C8h]
    __int64 v319; // [rsp+8D8h] [rbp-3C0h]
    __int64 v320; // [rsp+8E0h] [rbp-3B8h]
    __int64 v321; // [rsp+8E8h] [rbp-3B0h]
    unsigned __int8 *v322; // [rsp+8F0h] [rbp-3A8h]
    __int64 v323; // [rsp+8F8h] [rbp-3A0h]
    __int64 v324; // [rsp+900h] [rbp-398h]
    __int64 v325; // [rsp+908h] [rbp-390h]
    unsigned __int64 v326; // [rsp+910h] [rbp-388h]
    unsigned __int64 v327; // [rsp+918h] [rbp-380h]
    __int64 v328; // [rsp+920h] [rbp-378h]
    __int64 v329; // [rsp+928h] [rbp-370h]
    __int64 v330; // [rsp+930h] [rbp-368h]
    __int64 v331; // [rsp+938h] [rbp-360h]
    __int64 v332; // [rsp+940h] [rbp-358h]
    __int64 v333; // [rsp+948h] [rbp-350h]
    unsigned __int64 v334; // [rsp+950h] [rbp-348h]
    unsigned __int64 v335; // [rsp+958h] [rbp-340h]
    unsigned __int8 *v336; // [rsp+960h] [rbp-338h]
    unsigned __int64 v337; // [rsp+968h] [rbp-330h]
    unsigned __int64 v338; // [rsp+970h] [rbp-328h]
    __int64 v339; // [rsp+978h] [rbp-320h]
    unsigned __int64 v340; // [rsp+980h] [rbp-318h]
    unsigned __int8 *v341; // [rsp+988h] [rbp-310h]
    __int64 v342; // [rsp+990h] [rbp-308h]
    char v343; // [rsp+998h] [rbp-300h]
    unsigned __int64 v344; // [rsp+9A0h] [rbp-2F8h]
    __int64 v345; // [rsp+9A8h] [rbp-2F0h]
    __int64 v346; // [rsp+9B0h] [rbp-2E8h]
    __int64 v347; // [rsp+9B8h] [rbp-2E0h]
    unsigned __int64 v348; // [rsp+9C0h] [rbp-2D8h]
    unsigned __int64 v349; // [rsp+9C8h] [rbp-2D0h]
    unsigned __int64 v350; // [rsp+9D0h] [rbp-2C8h]
    unsigned __int64 v351; // [rsp+9D8h] [rbp-2C0h]
    unsigned __int8 *v352; // [rsp+9E0h] [rbp-2B8h]
    unsigned __int64 v353; // [rsp+9E8h] [rbp-2B0h]
    unsigned __int64 v354; // [rsp+9F0h] [rbp-2A8h]
    __int64 v355; // [rsp+9F8h] [rbp-2A0h]
    unsigned __int64 v356; // [rsp+A00h] [rbp-298h]
    unsigned __int64 v357; // [rsp+A08h] [rbp-290h]
    unsigned __int64 v358; // [rsp+A10h] [rbp-288h]
    unsigned __int64 v359; // [rsp+A18h] [rbp-280h]
    unsigned __int64 v360; // [rsp+A20h] [rbp-278h]
    unsigned __int64 v361; // [rsp+A28h] [rbp-270h]
    __int64 v362; // [rsp+A30h] [rbp-268h]
    unsigned __int64 v363; // [rsp+A38h] [rbp-260h]
    __int64 v364; // [rsp+A40h] [rbp-258h]
    __int64 v365; // [rsp+A48h] [rbp-250h]
    __int64 v366; // [rsp+A50h] [rbp-248h]
    __int64 v367; // [rsp+A58h] [rbp-240h]
    char v368; // [rsp+A60h] [rbp-238h]
    unsigned __int64 v369; // [rsp+A68h] [rbp-230h]
    unsigned __int8 *v370; // [rsp+A70h] [rbp-228h]
    unsigned __int64 v371; // [rsp+A78h] [rbp-220h]
    __int64 v372; // [rsp+A80h] [rbp-218h]
    unsigned __int64 v373; // [rsp+A88h] [rbp-210h]
    unsigned __int64 v374; // [rsp+A90h] [rbp-208h]
    unsigned __int64 v375; // [rsp+A98h] [rbp-200h]
    unsigned __int64 v376; // [rsp+AA0h] [rbp-1F8h]
    unsigned __int64 v377; // [rsp+AA8h] [rbp-1F0h]
    unsigned __int64 v378; // [rsp+AB0h] [rbp-1E8h]
    unsigned __int8 *v379; // [rsp+AB8h] [rbp-1E0h]
    unsigned __int64 v380; // [rsp+AC0h] [rbp-1D8h]
    unsigned __int64 v381; // [rsp+AC8h] [rbp-1D0h]
    unsigned __int64 v382; // [rsp+AD0h] [rbp-1C8h]
    unsigned __int64 v383; // [rsp+AD8h] [rbp-1C0h]
    unsigned __int64 v384; // [rsp+AE0h] [rbp-1B8h]
    unsigned __int64 v385; // [rsp+AE8h] [rbp-1B0h]
    unsigned __int8 *v386; // [rsp+AF0h] [rbp-1A8h]
    unsigned __int64 v387; // [rsp+AF8h] [rbp-1A0h]
    unsigned __int64 v388; // [rsp+B00h] [rbp-198h]
    unsigned __int64 v389; // [rsp+B08h] [rbp-190h]
    unsigned __int64 v390; // [rsp+B10h] [rbp-188h]
    unsigned __int64 v391; // [rsp+B18h] [rbp-180h]
    unsigned __int64 v392; // [rsp+B20h] [rbp-178h]
    __int64 v393; // [rsp+B28h] [rbp-170h]
    unsigned __int64 v394; // [rsp+B30h] [rbp-168h]
    unsigned __int64 v395; // [rsp+B38h] [rbp-160h]
    unsigned __int64 v396; // [rsp+B40h] [rbp-158h]
    unsigned __int64 v397; // [rsp+B48h] [rbp-150h]
    __int64 v398; // [rsp+B50h] [rbp-148h]
    __int64 v399; // [rsp+B58h] [rbp-140h]
    unsigned __int64 Dr1; // [rsp+B60h] [rbp-138h]
    __int64 v401; // [rsp+B68h] [rbp-130h]
    __int64 v402; // [rsp+B70h] [rbp-128h]
    unsigned __int64 Dr2; // [rsp+B78h] [rbp-120h]
    __int64 n0x4F; // [rsp+B80h] [rbp-118h]
    __int64 n0x4F_2; // [rsp+B88h] [rbp-110h]
    unsigned __int64 Dr3; // [rsp+B90h] [rbp-108h]
    unsigned __int64 n0x4F_1; // [rsp+B98h] [rbp-100h]
    __int64 n0x4F_3; // [rsp+BA0h] [rbp-F8h]
    unsigned int v409; // [rsp+BC0h] [rbp-D8h]
    unsigned __int64 v410; // [rsp+BD0h] [rbp-C8h]
    int v411; // [rsp+BE4h] [rbp-B4h] BYREF
    unsigned __int64 a3; // [rsp+BE8h] [rbp-B0h]
    unsigned __int64 v413; // [rsp+BF0h] [rbp-A8h]
    unsigned __int64 v414; // [rsp+BF8h] [rbp-A0h]
    unsigned __int64 v415; // [rsp+C00h] [rbp-98h]
    unsigned __int64 v416; // [rsp+C08h] [rbp-90h]
    int v417; // [rsp+C14h] [rbp-84h]
    int v418; // [rsp+C18h] [rbp-80h]
    int v419; // [rsp+C1Ch] [rbp-7Ch]
    __int64 v420; // [rsp+C20h] [rbp-78h]
    __int64 v421; // [rsp+C28h] [rbp-70h]
    __int64 v422; // [rsp+C30h] [rbp-68h]
    __int64 v423; // [rsp+C38h] [rbp-60h]
    unsigned __int64 v424; // [rsp+C40h] [rbp-58h]
    int v425; // [rsp+C4Ch] [rbp-4Ch]

    n2 = 0;
    while ( 1 )
    {
        n2_1 = n2;
        switch ( n2 )
        {
            case 0u:
                p_ContextRecord = &exception->ContextRecord;
                if ( (~exception->ContextRecord->ContextFlags & 0x100010) != 0 )
                    n2 = 1;
                else
                    n2 = 2;

                break;

            case 1u:
                return n2_1;

            case 2u:
                n0x6EBCBAA1 = 0x6EBCBAA1;
                n2 = 3;
                break;

            case 3u:
                v47 = (__ROL4__(__ROL4__(n0x6EBCBAA1, 4) + 0x6B9F6F9A, 3) ^ 0x770BB7B8) + 0x33AC85C6;
                n2 = 4;
                break;

            case 4u:
                v100 = v47;
                n2 = 5;
                break;

            case 5u:
                n2 = 6;
                break;

            case 6u:
                n2 = 7;
                break;

            case 7u:
                v101 = (v100 ^ 0x281C3663DA3197B5LL) + 0x3A9CCBED1AC47F6LL;
                n2 = 8;
                break;

            case 8u:
                v420 = __ROL8__(v101, 0x20) ^ 0xDE838D86533A540LL;
                v420 = __ROL8__(v420, 0x3C);
                v7 = v420;
                n2 = 9;
                break;

            case 9u:
                v102 = g_encDataRandomTable[((unsigned __int8)v7 >> 4) + 0x60];
                n2 = 0xA;
                break;

            case 0xAu:
                v103 = 0x10 * v102;
                v104 = &g_encDataRandomTable[((v7 >> 0x28) & 0xF) + 0x60];
                n2 = 0xB;
                break;

            case 0xBu:
                v105 = v103 | ((unsigned __int64)*v104 << 0x28);
                n2 = 0xC;
                break;

            case 0xCu:
                v106 = v105
                     | (g_encDataRandomTable[(((unsigned int)v7 >> 8) & 0xF) + 0x60] << 8);
                n2 = 0xD;
                break;

            case 0xDu:
                v107 = HIBYTE(v7);
                v108 = g_encDataRandomTable[(v7 >> 0x3C) + 0x60];
                n2 = 0xE;
                break;

            case 0xEu:
                v109 = v106 | (v108 << 0x3C);
                v110 = (v7 >> 0x2C) & 0xF;
                n2 = 0xF;
                break;

            case 0xFu:
                v111 = v109
                     | ((unsigned __int64)g_encDataRandomTable[v110 + 0x60] << 0x2C);
                n2 = 0x10;
                break;

            case 0x10u:
                v112 = v7 >> 0x10;
                v113 = v111
                     | (g_encDataRandomTable[(((unsigned int)v7 >> 0x14) & 0xF)
                                                           + 0x60] << 0x14);
                n2 = 0x11;
                break;

            case 0x11u:
                v114 = BYTE6(v7) & 0xF;
                n2 = 0x12;
                break;

            case 0x12u:
                v115 = v113
                     | ((unsigned __int64)g_encDataRandomTable[v114 + 0x60] << 0x30);
                n2 = 0x13;
                break;

            case 0x13u:
                v116 = v115
                     | (g_encDataRandomTable[(BYTE3(v7) & 0xF) + 0x60] << 0x18);
                n2 = 0x14;
                break;

            case 0x14u:
                v117 = &g_encDataRandomTable[((unsigned __int16)v7 >> 0xC) + 0x60];
                n2 = 0x15;
                break;

            case 0x15u:
                v118 = v116 | (*v117 << 0xC);
                n2 = 0x16;
                break;

            case 0x16u:
                v119 = v118
                     | ((unsigned __int64)g_encDataRandomTable[(v107 & 0xF) + 0x60] << 0x38);
                n2 = 0x17;
                break;

            case 0x17u:
                v10 = g_encDataRandomTable[(BYTE4(v7) & 0xF) + 0x60];
                n2 = 0x18;
                break;

            case 0x18u:
                v120 = v119 | ((unsigned __int64)v10 << 0x20);
                v121 = v112 & 0xF;
                n2 = 0x19;
                break;

            case 0x19u:
                v122 = v120 | (g_encDataRandomTable[v121 + 0x60] << 0x10);
                n2 = 0x1A;
                break;

            case 0x1Au:
                v123 = g_encDataRandomTable[((unsigned int)v7 >> 0x1C) + 0x60];
                n2 = 0x1B;
                break;

            case 0x1Bu:
                v124 = v122 | (v123 << 0x1C);
                v125 = (v7 >> 0x24) & 0xF;
                n2 = 0x1C;
                break;

            case 0x1Cu:
                v126 = v124
                     | ((unsigned __int64)g_encDataRandomTable[v125 + 0x60] << 0x24);
                n2 = 0x1D;
                break;

            case 0x1Du:
                v127 = v126 | g_encDataRandomTable[(v7 & 0xF) + 0x60];
                n2 = 0x1E;
                break;

            case 0x1Eu:
                v128 = (unsigned __int64)g_encDataRandomTable[((v7 >> 0x34) & 0xF)
                                                                            + 0x60] << 0x34;
                n2 = 0x1F;
                break;

            case 0x1Fu:
                ContextRecord = __ROL8__((v128 | v127) - 0x2662A2D5F43B2FCCLL, 0x2E);
                ContextRecord_2 = *p_ContextRecord;
                n2 = 0x20;
                break;

            case 0x20u:
                Dr0 = ContextRecord_2->Dr0;
                n2 = 0x21;
                break;

            case 0x21u:
                v8 = __ROL8__(ContextRecord, 0x12) + 0x2662A2D5F43B2FCCLL;
                n2 = 0x22;
                break;

            case 0x22u:
                v132 = 0x10
                     * (unsigned int)g_encDataRandomTable[((unsigned __int8)v8 >> 4)
                                                                        + 0x50];
                n2 = 0x23;
                break;

            case 0x23u:
                v11 = g_encDataRandomTable[((v8 >> 0x28) & 0xF) + 0x50];
                n2 = 0x24;
                break;

            case 0x24u:
                v133 = v132 | ((unsigned __int64)v11 << 0x28);
                v134 = v8 >> 8;
                n2 = 0x25;
                break;

            case 0x25u:
                v135 = v133 | (g_encDataRandomTable[(v134 & 0xF) + 0x50] << 8);
                n2 = 0x26;
                break;

            case 0x26u:
                v136 = HIBYTE(v8);
                v137 = (unsigned __int64)g_encDataRandomTable[(v8 >> 0x3C) + 0x50] << 0x3C;
                n2 = 0x27;
                break;

            case 0x27u:
                v138 = v137 | v135;
                v139 = &g_encDataRandomTable[((v8 >> 0x2C) & 0xF) + 0x50];
                n2 = 0x28;
                break;

            case 0x28u:
                v140 = v138 | ((unsigned __int64)*v139 << 0x2C);
                n2 = 0x29;
                break;

            case 0x29u:
                v141 = v8 >> 0x10;
                v142 = v140
                     | (g_encDataRandomTable[(((unsigned int)v8 >> 0x14) & 0xF)
                                                           + 0x50] << 0x14);
                n2 = 0x2A;
                break;

            case 0x2Au:
                v143 = g_encDataRandomTable[(BYTE6(v8) & 0xF) + 0x50];
                n2 = 0x2B;
                break;

            case 0x2Bu:
                v144 = v142 | (v143 << 0x30);
                v145 = BYTE3(v8) & 0xF;
                n2 = 0x2C;
                break;

            case 0x2Cu:
                v146 = v144 | (g_encDataRandomTable[v145 + 0x50] << 0x18);
                n2 = 0x2D;
                break;

            case 0x2Du:
                v147 = g_encDataRandomTable[((unsigned __int16)v8 >> 0xC) + 0x50] << 0xC;
                n2 = 0x2E;
                break;

            case 0x2Eu:
                v148 = v147 | v146;
                v12 = g_encDataRandomTable[(v136 & 0xF) + 0x50];
                n2 = 0x2F;
                break;

            case 0x2Fu:
                v149 = v148 | ((unsigned __int64)v12 << 0x38);
                v150 = BYTE4(v8);
                n2 = 0x30;
                break;

            case 0x30u:
                v151 = v149
                     | ((unsigned __int64)g_encDataRandomTable[(v150 & 0xF) + 0x50] << 0x20);
                n2 = 0x31;
                break;

            case 0x31u:
                v152 = g_encDataRandomTable[(v141 & 0xF) + 0x50];
                n2 = 0x32;
                break;

            case 0x32u:
                v153 = v151 | (v152 << 0x10);
                v154 = &g_encDataRandomTable[((unsigned int)v8 >> 0x1C) + 0x50];
                n2 = 0x33;
                break;

            case 0x33u:
                v155 = v153 | ((unsigned __int64)*v154 << 0x1C);
                n2 = 0x34;
                break;

            case 0x34u:
                v156 = v155
                     | ((unsigned __int64)g_encDataRandomTable[((v8 >> 0x24) & 0xF)
                                                                             + 0x50] << 0x24);
                n2 = 0x35;
                break;

            case 0x35u:
                v157 = g_encDataRandomTable[(v8 & 0xF) + 0x50];
                n2 = 0x36;
                break;

            case 0x36u:
                v158 = v157 | v156;
                v159 = &g_encDataRandomTable[((v8 >> 0x34) & 0xF) + 0x50];
                n2 = 0x37;
                break;

            case 0x37u:
                v38 = v158 | ((unsigned __int64)*v159 << 0x34);
                v421 = __ROL8__(v38, 4);
                v160 = v421;
                n2 = 0x38;
                break;

            case 0x38u:
                v161 = __ROL8__(v160 ^ 0xDE838D86533A540LL, 0x20) - 0x3A9CCBED1AC47F6LL;
                n2 = 0x39;
                break;

            case 0x39u:
                v39 = qword_1802D2B19;
                if ( (qword_1802D2B19 ^ Dr0 ^ v161) == 0x4F )
                    n2 = 0x14B;
                else
                    n2 = 0x3A;

                break;

            case 0x3Au:
                v48 = __ROL4__(0xEF449E19, 0x10);
                n2 = 0x3B;
                break;

            case 0x3Bu:
                v49 = __ROL4__((v48 + 0x500EBDB) ^ 0xA33ADB1F, 0x16);
                n2 = 0x3C;
                break;

            case 0x3Cu:
                n2 = 0x3D;
                break;

            case 0x3Du:
                v419 = __ROL4__(v49 - 0x5D8D7E02, 0x18);
                n2 = 0x3E;
                break;

            case 0x3Eu:
                v50 = __ROL4__(v419 + 0x2773BBB2, 6);
                n2 = 0x3F;
                break;

            case 0x3Fu:
                v51 = (v50 ^ 0x74A2863C) - 0x1E9A0ECF;
                n2 = 0x40;
                break;

            case 0x40u:
                v52 = __ROL4__(v51, 0x15);
                n2 = 0x41;
                break;

            case 0x41u:
                v53 = __ROL4__(v52, 0xB) + 0x1E9A0ECF;
                n2 = 0x42;
                break;

            case 0x42u:
                v54 = __ROL4__(qword_1802D2C51 ^ v53 ^ 0x4F991284, 0x1A) - 0x2773BBB2;
                n2 = 0x43;
                break;

            case 0x43u:
                v425 = __ROL4__(v54, 8) + 0x5D8D7E02;
                v55 = v425;
                n2 = 0x44;
                break;

            case 0x44u:
                v1014 = v1014;
                n2 = 0x45;
                break;

            case 0x45u:
                v163 = __ROL8__(
                           (((v1014 ^ v1805) + 0x61BBE9D7149134B0LL) ^ 0xDFEE542C76A7AAF0uLL)
                         - 0x1509678523D640EALL,
                           0xE);
                n2 = 0x46;
                break;

            case 0x46u:
                v29 = (__ROL8__((v163 ^ 0xF0) - 0x57033546396F782ALL, 0xE) + 0x7D019B7AE2EB4B6FLL)
                    ^ 0x2EFFBB12A651F46CLL;
                n2 = 0x47;
                break;

            case 0x47u:
                v164 = HIBYTE(v29);
                v165 = (unsigned __int64)g_encDataRandomTable[(v29 >> 0x3C) + 0x70] << 0x3C;
                n2 = 0x48;
                break;

            case 0x48u:
                v166 = &g_encDataRandomTable[(((unsigned int)v29 >> 8) & 0xF) + 0x70];
                n2 = 0x49;
                break;

            case 0x49u:
                v167 = v165 | (*v166 << 8);
                n2 = 0x4A;
                break;

            case 0x4Au:
                v168 = v167
                     | (g_encDataRandomTable[(BYTE3(v29) & 0xF) + 0x70] << 0x18);
                n2 = 0x4B;
                break;

            case 0x4Bu:
                v169 = HIDWORD(v29);
                v13 = g_encDataRandomTable[((v29 >> 0x24) & 0xF) + 0x70];
                n2 = 0x4C;
                break;

            case 0x4Cu:
                v170 = v168 | ((unsigned __int64)v13 << 0x24);
                v171 = v29 >> 4;
                n2 = 0x4D;
                break;

            case 0x4Du:
                v172 = v170
                     | (0x10
                      * (unsigned int)g_encDataRandomTable[(v171 & 0xF) + 0x70]);
                n2 = 0x4E;
                break;

            case 0x4Eu:
                v173 = HIWORD(v29);
                v174 = (unsigned __int64)g_encDataRandomTable[((v29 >> 0x34) & 0xF)
                                                                            + 0x70] << 0x34;
                n2 = 0x4F;
                break;

            case 0x4Fu:
                v175 = v174 | v172;
                v176 = &g_encDataRandomTable[(v169 & 0xF) + 0x70];
                n2 = 0x50;
                break;

            case 0x50u:
                v177 = v175 | ((unsigned __int64)*v176 << 0x20);
                v178 = v29 >> 0x28;
                n2 = 0x51;
                break;

            case 0x51u:
                v179 = v177
                     | ((unsigned __int64)g_encDataRandomTable[((v29 >> 0x2C) & 0xF)
                                                                             + 0x70] << 0x2C);
                n2 = 0x52;
                break;

            case 0x52u:
                v180 = v29 >> 0x10;
                v181 = g_encDataRandomTable[(((unsigned int)v29 >> 0x14) & 0xF)
                                                          + 0x70] << 0x14;
                n2 = 0x53;
                break;

            case 0x53u:
                v182 = v181 | v179;
                v14 = g_encDataRandomTable[((unsigned __int16)v29 >> 0xC) + 0x70];
                n2 = 0x54;
                break;

            case 0x54u:
                v183 = v182 | (v14 << 0xC);
                n2 = 0x55;
                break;

            case 0x55u:
                v184 = v183
                     | ((unsigned __int64)g_encDataRandomTable[(v164 & 0xF) + 0x70] << 0x38);
                n2 = 0x56;
                break;

            case 0x56u:
                v185 = v184 | (g_encDataRandomTable[(v180 & 0xF) + 0x70] << 0x10);
                n2 = 0x57;
                break;

            case 0x57u:
                v186 = &g_encDataRandomTable[(v178 & 0xF) + 0x70];
                n2 = 0x58;
                break;

            case 0x58u:
                v187 = v185 | ((unsigned __int64)*v186 << 0x28);
                n2 = 0x59;
                break;

            case 0x59u:
                v188 = v187
                     | ((unsigned __int64)g_encDataRandomTable[(v173 & 0xF) + 0x70] << 0x30);
                n2 = 0x5A;
                break;

            case 0x5Au:
                v189 = (unsigned __int64)g_encDataRandomTable[((unsigned int)v29 >> 0x1C)
                                                                            + 0x70] << 0x1C;
                n2 = 0x5B;
                break;

            case 0x5Bu:
                v190 = v189 | v188;
                v191 = v29 & 0xF;
                n2 = 0x5C;
                break;

            case 0x5Cu:
                v192 = __ROL8__(v190 | g_encDataRandomTable[v191 + 0x70], 0x2B);
                n2 = 0x5D;
                break;

            case 0x5Du:
                n2 = 0x5E;
                break;

            case 0x5Eu:
                n2 = 0x5F;
                break;

            case 0x5Fu:
                v193 = v192;
                v409 = __ROL4__(0xB10E2EB7, 0x1E) ^ 0xBAB0DD00;
                n2 = 0x60;
                break;

            case 0x60u:
                v56 = __ROL4__(v409 ^ 0xC4, 0x1D);
                n2 = 0x61;
                break;

            case 0x61u:
                if ( (unsigned int)outlined_helper_1(0x51, 0x1E, 0x2D, (unsigned int *)(v193 + 0x8C)) == v56 )
                    n2 = 0x62;
                else
                    n2 = 1;

                break;

            case 0x62u:
                v1014_1 = v1014;
                v1805 = v1805;
                n2 = 0x63;
                break;

            case 0x63u:
                v196 = __ROL8__(
                           (((v1014_1 ^ v1805) + 0x61BBE9D7149134B0LL) ^ 0xDFEE542C76A7AAF0uLL)
                         - 0x1509678523D640EALL,
                           0xE);
                n2 = 0x64;
                break;

            case 0x64u:
                v30 = (__ROL8__((v196 ^ 0xF0) - 0x57033546396F782ALL, 0xE) + 0x7D019B7AE2EB4B6FLL)
                    ^ 0x2EFFBB12A651F46CLL;
                n2 = 0x65;
                break;

            case 0x65u:
                v197 = HIBYTE(v30);
                v198 = (unsigned __int64)g_encDataRandomTable[(v30 >> 0x3C) + 0x70] << 0x3C;
                n2 = 0x66;
                break;

            case 0x66u:
                v199 = &g_encDataRandomTable[(((unsigned int)v30 >> 8) & 0xF) + 0x70];
                n2 = 0x67;
                break;

            case 0x67u:
                v200 = v198 | (*v199 << 8);
                v201 = v30 >> 0x18;
                n2 = 0x68;
                break;

            case 0x68u:
                v202 = v200 | (g_encDataRandomTable[(v201 & 0xF) + 0x70] << 0x18);
                n2 = 0x69;
                break;

            case 0x69u:
                v203 = HIDWORD(v30);
                v204 = &g_encDataRandomTable[((v30 >> 0x24) & 0xF) + 0x70];
                n2 = 0x6A;
                break;

            case 0x6Au:
                v205 = v202 | ((unsigned __int64)*v204 << 0x24);
                v206 = v30 >> 4;
                n2 = 0x6B;
                break;

            case 0x6Bu:
                v207 = v205
                     | (0x10
                      * (unsigned int)g_encDataRandomTable[(v206 & 0xF) + 0x70]);
                n2 = 0x6C;
                break;

            case 0x6Cu:
                v208 = HIWORD(v30);
                v209 = g_encDataRandomTable[((v30 >> 0x34) & 0xF) + 0x70];
                n2 = 0x6D;
                break;

            case 0x6Du:
                v210 = v207 | (v209 << 0x34);
                v211 = &g_encDataRandomTable[(v203 & 0xF) + 0x70];
                n2 = 0x6E;
                break;

            case 0x6Eu:
                v212 = v210 | ((unsigned __int64)*v211 << 0x20);
                v213 = v30 >> 0x28;
                n2 = 0x6F;
                break;

            case 0x6Fu:
                v214 = v212
                     | ((unsigned __int64)g_encDataRandomTable[((v30 >> 0x2C) & 0xF)
                                                                             + 0x70] << 0x2C);
                n2 = 0x70;
                break;

            case 0x70u:
                v215 = v30 >> 0x10;
                v216 = g_encDataRandomTable[(((unsigned int)v30 >> 0x14) & 0xF)
                                                          + 0x70];
                n2 = 0x71;
                break;

            case 0x71u:
                v217 = v214 | (v216 << 0x14);
                v218 = (unsigned __int16)v30 >> 0xC;
                n2 = 0x72;
                break;

            case 0x72u:
                v219 = v217 | (g_encDataRandomTable[v218 + 0x70] << 0xC);
                n2 = 0x73;
                break;

            case 0x73u:
                v220 = g_encDataRandomTable[(v197 & 0xF) + 0x70];
                n2 = 0x74;
                break;

            case 0x74u:
                v221 = v219 | (v220 << 0x38);
                v222 = v215 & 0xF;
                n2 = 0x75;
                break;

            case 0x75u:
                v223 = v221 | (g_encDataRandomTable[v222 + 0x70] << 0x10);
                n2 = 0x76;
                break;

            case 0x76u:
                v224 = (unsigned __int64)g_encDataRandomTable[(v213 & 0xF) + 0x70] << 0x28;
                n2 = 0x77;
                break;

            case 0x77u:
                v225 = v224 | v223;
                v226 = &g_encDataRandomTable[(v208 & 0xF) + 0x70];
                n2 = 0x78;
                break;

            case 0x78u:
                v227 = v225 | ((unsigned __int64)*v226 << 0x30);
                n2 = 0x79;
                break;

            case 0x79u:
                v228 = (unsigned __int64)g_encDataRandomTable[((unsigned int)v30 >> 0x1C)
                                                                            + 0x70] << 0x1C;
                n2 = 0x7A;
                break;

            case 0x7Au:
                v229 = v228 | v227;
                v230 = &g_encDataRandomTable[(v30 & 0xF) + 0x70];
                n2 = 0x7B;
                break;

            case 0x7Bu:
                v231 = __ROL8__(v229 | *v230, 0x2B);
                n2 = 0x7C;
                break;

            case 0x7Cu:
                v232 = 0xAFD87C7224F64144uLL;
                n2 = 0x7D;
                break;

            case 0x7Du:
                v233 = (__ROL8__(v232, 2) - 0x4492141EEFDBF1ALL) ^ 0xAEBFE7573B59B0CDuLL;
                n2 = 0x7E;
                break;

            case 0x7Eu:
                v234 = v233 - 0x15A737D11F84F535LL;
                n2 = 0x7F;
                break;

            case 0x7Fu:
                v235 = v234 ^ 0x65;
                n2 = 0x80;
                break;

            case 0x80u:
                v236 = __ROL8__(v235, 0x38);
                n2 = 0x81;
                break;

            case 0x81u:
                n2 = 0x82;
                break;

            case 0x82u:
                v237 = __ROL8__((v236 ^ 0x9F7C0F65EF8A2AALL) - 0x49AE6B1EC26FFFC0LL, 0x2F)
                     - 0x7605BC927F8FF8DLL;
                n2 = 0x83;
                break;

            case 0x83u:
                v94 = ((v237 - 0x632CB28A009A622FLL) ^ 0xA64FEBFB4B051FDEuLL) - 0x646810A5E064C719LL;
                n2 = 0x84;
                break;

            case 0x84u:
                v410 = v94;
                n2 = 0x85;
                break;

            case 0x85u:
                v410 = ((v410 + 0x646810A5E064C719LL) ^ 0xA64FEBFB4B051FDEuLL)
                     + 0x632CB28A009A622FLL;
                v238 = v410 + 0x7605BC927F8FF8DLL;
                n2 = 0x86;
                break;

            case 0x86u:
                v239 = *(__int64 *)((char *)&qword_1802D2C99 + 2);
                v240 = __ROL8__(
                           (__ROL8__(v238, 0x11) + 0x49AE6B1EC26FFFC0LL)
                         ^ *(__int64 *)((char *)&qword_1802D2C99 + 2)
                         ^ 0x12A31EF5AA976FA7LL,
                           8);
                n2 = 0x87;
                break;

            case 0x87u:
                v241 = (_DWORD *)((v240 ^ 0x65) + 4);
                n2 = 0x88;
                break;

            case 0x88u:
                v57 = __ROL4__(*v241, 0x1D);
                n2 = 0x89;
                break;

            case 0x89u:
                v58 = __ROL4__(v57, 2);
                n2 = 0x8A;
                break;

            case 0x8Au:
                n2 = 0x8B;
                break;

            case 0x8Bu:
                v59 = v58 ^ 0xE5;
                v33 = v58 ^ 0x88A8C6E5;
                n2 = 0x8C;
                break;

            case 0x8Cu:
                v15 = v59;
                v242 = &g_encDataRandomTable[(v59 & 0xF) + 0x80];
                n2 = 0x8D;
                break;

            case 0x8Du:
                v60 = *v242;
                v243 = v33 >> 8;
                v244 = v33 >> 0xC;
                n2 = 0x8E;
                break;

            case 0x8Eu:
                v61 = v60 | (g_encDataRandomTable[(v244 & 0xF) + 0x80] << 0xC);
                n2 = 0x8F;
                break;

            case 0x8Fu:
                v62 = 0x10 * g_encDataRandomTable[(v15 >> 4) + 0x80];
                n2 = 0x90;
                break;

            case 0x90u:
                v63 = v62 | v61;
                v245 = v33 >> 0x10;
                v246 = ((unsigned int)v33 >> 0x14) & 0xF;
                n2 = 0x91;
                break;

            case 0x91u:
                v64 = v63 | (g_encDataRandomTable[v246 + 0x80] << 0x14);
                n2 = 0x92;
                break;

            case 0x92u:
                v247 = v33 >> 0x18;
                v65 = g_encDataRandomTable[(v33 >> 0x1C) + 0x80] << 0x1C;
                n2 = 0x93;
                break;

            case 0x93u:
                v66 = v65 | v64;
                v248 = v243 & 0xF;
                n2 = 0x94;
                break;

            case 0x94u:
                v67 = v66 | (g_encDataRandomTable[v248 + 0x80] << 8);
                n2 = 0x95;
                break;

            case 0x95u:
                v68 = v67 | (g_encDataRandomTable[(v245 & 0xF) + 0x80] << 0x10);
                n2 = 0x96;
                break;

            case 0x96u:
                v16 = g_encDataRandomTable[(v247 & 0xF) + 0x80];
                n2 = 0x97;
                break;

            case 0x97u:
                v411 = __ROL4__(__ROL4__((v68 | (v16 << 0x18)) - 0x25288DCE, 0x17) - 0x709572C9, 2);
                n2 = 0x98;
                break;

            case 0x98u:
                n2 = 0x99;
                break;

            case 0x99u:
                v249 = ((v94 + 0x646810A5E064C719LL) ^ 0xA64FEBFB4B051FDEuLL) + 0x632CB28A009A622FLL;
                n2 = 0x9A;
                break;

            case 0x9Au:
                v250 = v239
                     ^ (__ROL8__(v249 + 0x7605BC927F8FF8DLL, 0x11) + 0x49AE6B1EC26FFFC0LL)
                     ^ 0x12A31EF5AA976FA7LL;
                n2 = 0x9B;
                break;

            case 0x9Bu:
                v251 = __ROL8__(v250, 8) ^ 0x65LL;
                n2 = 0x9C;
                break;

            case 0x9Cu:
                v252 = *(_QWORD *)(v251 + 0x320);
                n2 = 0x9D;
                break;

            case 0x9Du:
                v253 = __ROL8__(v252 ^ 0x65, 0x38);
                n2 = 0x9E;
                break;

            case 0x9Eu:
                n2 = 0x9F;
                break;

            case 0x9Fu:
                v254 = v253 ^ 0x9F7C0F65EF8A2AALL;
                n2 = 0xA0;
                break;

            case 0xA0u:
                a3 = __ROL8__(v254 - 0x49AE6B1EC26FFFC0LL, 0x2F) - 0x7605BC927F8FF8DLL;
                a3 = ((a3 - 0x632CB28A009A622FLL) ^ 0xA64FEBFB4B051FDEuLL) - 0x646810A5E064C719LL;
                n2 = 0xA1;
                break;

            case 0xA1u:
                n2 = 0xA2;
                break;

            case 0xA2u:
                a3 = ((a3 + 0x646810A5E064C719LL) ^ 0xA64FEBFB4B051FDEuLL) + 0x632CB28A009A622FLL;
                v255 = __ROL8__(a3 + 0x7605BC927F8FF8DLL, 0x11) + 0x49AE6B1EC26FFFC0LL;
                n2 = 0xA3;
                break;

            case 0xA3u:
                v256 = __ROL8__(
                           *(__int64 *)((char *)&qword_1802D2C99 + 2) ^ v255 ^ 0x12A31EF5AA976FA7LL,
                           8)
                     ^ 0x65LL;
                n2 = 0xA4;
                break;

            case 0xA4u:
                n2 = 0xA5;
                break;

            case 0xA5u:
                outlined_helper_2(&v411);
                v69 = v411 + 0x29;
                v32 = (unsigned int)(v411 - 0x45EEEDD7);
                n2 = 0xA6;
                break;

            case 0xA6u:
                v17 = v69;
                v70 = g_encDataRandomTable[(v69 & 0xF) + 0x90];
                n2 = 0xA7;
                break;

            case 0xA7u:
                v257 = v32 >> 8;
                v71 = g_encDataRandomTable[((unsigned __int16)v32 >> 0xC) + 0x90];
                n2 = 0xA8;
                break;

            case 0xA8u:
                v72 = v70 | (v71 << 0xC);
                v18 = v17 >> 4;
                n2 = 0xA9;
                break;

            case 0xA9u:
                v73 = v72 | (0x10 * g_encDataRandomTable[v18 + 0x90]);
                n2 = 0xAA;
                break;

            case 0xAAu:
                v258 = v32 >> 0x10;
                v74 = v73
                    | (g_encDataRandomTable[(((unsigned int)v32 >> 0x14) & 0xF)
                                                          + 0x90] << 0x14);
                n2 = 0xAB;
                break;

            case 0xABu:
                v259 = v32 >> 0x18;
                v19 = g_encDataRandomTable[(v32 >> 0x1C) + 0x90];
                n2 = 0xAC;
                break;

            case 0xACu:
                v75 = v74 | (v19 << 0x1C);
                v260 = v257 & 0xF;
                n2 = 0xAD;
                break;

            case 0xADu:
                v76 = v75 | (g_encDataRandomTable[v260 + 0x90] << 8);
                n2 = 0xAE;
                break;

            case 0xAEu:
                v77 = g_encDataRandomTable[(v258 & 0xF) + 0x90] << 0x10;
                n2 = 0xAF;
                break;

            case 0xAFu:
                v78 = v77 | v76;
                v261 = v259 & 0xF;
                n2 = 0xB0;
                break;

            case 0xB0u:
                v79 = dword_1802D2E48
                    ^ (v78 | (g_encDataRandomTable[v261 + 0x90] << 0x18));
                n2 = 0xB1;
                break;

            case 0xB1u:
                v262 = v256 * (unsigned int)__ROL4__(v79, 1);
                n2 = 0xB2;
                break;

            case 0xB2u:
                n2 = 0xB3;
                break;

            case 0xB3u:
                n2 = 0xB4;
                break;

            case 0xB4u:
                n2 = 0xB5;
                break;

            case 0xB5u:
                n2 = 0xB6;
                break;

            case 0xB6u:
                n2 = 0xB7;
                break;

            case 0xB7u:
                v263 = __ROL8__(v262 ^ 0x9BD8FE58859C535FuLL, 0x2A) - 0x13BC3E8B476C15C4LL;
                n2 = 0xB8;
                break;

            case 0xB8u:
                v413 = __ROL8__(v263, 0x2A);
                v413 -= 0x5EDBD69FE0AFCFEALL;
                v9 = v413;
                n2 = 0xB9;
                break;

            case 0xB9u:
                v20 = g_encDataRandomTable[(BYTE3(v9) & 0xF) + 0xA0];
                n2 = 0xBA;
                break;

            case 0xBAu:
                v264 = v20 << 0x18;
                n2 = 0xBB;
                break;

            case 0xBBu:
                v265 = v9 >> 8;
                v266 = v264
                     | (g_encDataRandomTable[((unsigned __int16)v9 >> 0xC) + 0xA0] << 0xC);
                n2 = 0xBC;
                break;

            case 0xBCu:
                v21 = g_encDataRandomTable[(BYTE6(v9) & 0xF) + 0xA0];
                n2 = 0xBD;
                break;

            case 0xBDu:
                v267 = v266 | ((unsigned __int64)v21 << 0x30);
                v268 = v9 >> 4;
                n2 = 0xBE;
                break;

            case 0xBEu:
                v269 = v267
                     | (0x10
                      * (unsigned int)g_encDataRandomTable[(v268 & 0xF) + 0xA0]);
                n2 = 0xBF;
                break;

            case 0xBFu:
                v270 = HIBYTE(v9);
                n2 = 0xC0;
                break;

            case 0xC0u:
                v271 = v269
                     | ((unsigned __int64)g_encDataRandomTable[(v270 & 0xF) + 0xA0] << 0x38);
                n2 = 0xC1;
                break;

            case 0xC1u:
                v272 = g_encDataRandomTable[(BYTE2(v9) & 0xF) + 0xA0];
                n2 = 0xC2;
                break;

            case 0xC2u:
                v95 = v271 | (v272 << 0x10);
                v22 = g_encDataRandomTable[(v9 >> 0x3C) + 0xA0];
                n2 = 0xC3;
                break;

            case 0xC3u:
                v96 = v95 | ((unsigned __int64)v22 << 0x3C);
                n2 = 0xC4;
                break;

            case 0xC4u:
                v273 = v9 >> 0x28;
                v274 = (unsigned __int64)g_encDataRandomTable[((v9 >> 0x2C) & 0xF)
                                                                            + 0xA0] << 0x2C;
                n2 = 0xC5;
                break;

            case 0xC5u:
                v275 = v274 | (g_encDataRandomTable[(v265 & 0xF) + 0xA0] << 8);
                n2 = 0xC6;
                break;

            case 0xC6u:
                v34 = v96 | v275;
                v23 = g_encDataRandomTable[(v9 & 0xF) + 0xA0];
                n2 = 0xC7;
                break;

            case 0xC7u:
                v40 = v34 | v23;
                v276 = &g_encDataRandomTable[(((unsigned int)v9 >> 0x14) & 0xF)
                                                           + 0xA0];
                n2 = 0xC8;
                break;

            case 0xC8u:
                v277 = *v276 << 0x14;
                v278 = BYTE4(v9);
                n2 = 0xC9;
                break;

            case 0xC9u:
                v41 = v40
                    | v277
                    | ((unsigned __int64)g_encDataRandomTable[(v278 & 0xF) + 0xA0] << 0x20);
                n2 = 0xCA;
                break;

            case 0xCAu:
                v279 = g_encDataRandomTable[((v9 >> 0x24) & 0xF) + 0xA0];
                n2 = 0xCB;
                break;

            case 0xCBu:
                v280 = v279 << 0x24;
                v281 = &g_encDataRandomTable[((v9 >> 0x34) & 0xF) + 0xA0];
                n2 = 0xCC;
                break;

            case 0xCCu:
                v35 = v41 | v280 | ((unsigned __int64)*v281 << 0x34);
                n2 = 0xCD;
                break;

            case 0xCDu:
                v282 = (unsigned __int64)g_encDataRandomTable[(v273 & 0xF) + 0xA0] << 0x28;
                n2 = 0xCE;
                break;

            case 0xCEu:
                v283 = g_encDataRandomTable[((unsigned int)v9 >> 0x1C) + 0xA0];
                n2 = 0xCF;
                break;

            case 0xCFu:
                v42 = v35 | v282 | (v283 << 0x1C);
                n2 = 0xD0;
                break;

            case 0xD0u:
                v80 = 0xEB5EB44B;
                n2 = 0xD1;
                break;

            case 0xD1u:
                v81 = __ROL4__(__ROL4__(v80, 0x1D) - 0x7D6BD67D, 1);
                n2 = 0xD2;
                break;

            case 0xD2u:
                n2 = 0xD3;
                break;

            case 0xD3u:
                v284 = g_encDataRandomTable[(BYTE3(v41) & 0xF) + 0xB0];
                n2 = 0xD4;
                break;

            case 0xD4u:
                v285 = v284 << 0x18;
                v286 = v34 >> 8;
                v287 = &g_encDataRandomTable[((unsigned __int16)v34 >> 0xC) + 0xB0];
                n2 = 0xD5;
                break;

            case 0xD5u:
                v288 = v285 | (*v287 << 0xC);
                v289 = BYTE6(v34);
                n2 = 0xD6;
                break;

            case 0xD6u:
                v290 = v288
                     | ((unsigned __int64)g_encDataRandomTable[(v289 & 0xF) + 0xB0] << 0x30);
                n2 = 0xD7;
                break;

            case 0xD7u:
                v291 = 0x10
                     * (unsigned int)g_encDataRandomTable[((unsigned __int8)v40 >> 4)
                                                                        + 0xB0];
                n2 = 0xD8;
                break;

            case 0xD8u:
                v292 = v291 | v290;
                v293 = HIBYTE(v35);
                n2 = 0xD9;
                break;

            case 0xD9u:
                v294 = v292
                     | ((unsigned __int64)g_encDataRandomTable[(v293 & 0xF) + 0xB0] << 0x38);
                n2 = 0xDA;
                break;

            case 0xDAu:
                v295 = v294
                     | (g_encDataRandomTable[(BYTE2(v95) & 0xF) + 0xB0] << 0x10);
                n2 = 0xDB;
                break;

            case 0xDBu:
                v296 = (unsigned __int64)g_encDataRandomTable[(v96 >> 0x3C) + 0xB0] << 0x3C;
                n2 = 0xDC;
                break;

            case 0xDCu:
                v297 = v296 | v295;
                v298 = v42 >> 0x28;
                v299 = (v42 >> 0x2C) & 0xF;
                n2 = 0xDD;
                break;

            case 0xDDu:
                v300 = v297
                     | ((unsigned __int64)g_encDataRandomTable[v299 + 0xB0] << 0x2C);
                n2 = 0xDE;
                break;

            case 0xDEu:
                v301 = v300 | (g_encDataRandomTable[(v286 & 0xF) + 0xB0] << 8);
                n2 = 0xDF;
                break;

            case 0xDFu:
                v302 = v301 | g_encDataRandomTable[(v40 & 0xF) + 0xB0];
                n2 = 0xE0;
                break;

            case 0xE0u:
                v303 = g_encDataRandomTable[(((unsigned int)v41 >> 0x14) & 0xF)
                                                          + 0xB0];
                n2 = 0xE1;
                break;

            case 0xE1u:
                v304 = v302 | (v303 << 0x14);
                v305 = BYTE4(v42) & 0xF;
                n2 = 0xE2;
                break;

            case 0xE2u:
                v306 = v304
                     | ((unsigned __int64)g_encDataRandomTable[v305 + 0xB0] << 0x20);
                n2 = 0xE3;
                break;

            case 0xE3u:
                v307 = v306
                     | ((unsigned __int64)g_encDataRandomTable[((v35 >> 0x24) & 0xF)
                                                                             + 0xB0] << 0x24);
                n2 = 0xE4;
                break;

            case 0xE4u:
                v308 = (unsigned __int64)g_encDataRandomTable[((v35 >> 0x34) & 0xF)
                                                                            + 0xB0] << 0x34;
                n2 = 0xE5;
                break;

            case 0xE5u:
                v309 = v308 | v307;
                v24 = g_encDataRandomTable[(v298 & 0xF) + 0xB0];
                n2 = 0xE6;
                break;

            case 0xE6u:
                v310 = v309 | ((unsigned __int64)v24 << 0x28);
                v311 = v42 >> 0x1C;
                n2 = 0xE7;
                break;

            case 0xE7u:
                v415 = v310
                     | ((unsigned __int64)g_encDataRandomTable[(v311 & 0xF) + 0xB0] << 0x1C);
                n2 = 0xE8;
                break;

            case 0xE8u:
                v415 += 0x5EDBD69FE0AFCFEALL;
                v312 = __ROL8__(v415, 0x16) + 0x13BC3E8B476C15C4LL;
                n2 = 0xE9;
                break;

            case 0xE9u:
                v313 = v1702 ^ __ROL8__(v312, 0x16) ^ 0x2B;
                n2 = 0xEA;
                break;

            case 0xEAu:
                v314 = v313 >> v81;
                n2 = 0xEB;
                break;

            case 0xEBu:
                n2 = 0xEC;
                break;

            case 0xECu:
                n2 = 0xED;
                break;

            case 0xEDu:
                n2 = 0xEE;
                break;

            case 0xEEu:
                n2 = 0xEF;
                break;

            case 0xEFu:
                v315 = __ROL8__(v314 ^ 0x9BD8FE58859C535FuLL, 0x2A);
                n2 = 0xF0;
                break;

            case 0xF0u:
                v414 = __ROL8__(v315 - 0x13BC3E8B476C15C4LL, 0x2A);
                v414 -= 0x5EDBD69FE0AFCFEALL;
                n2 = 0xF1;
                break;

            case 0xF1u:
                v28 = v414;
                v316 = &g_encDataRandomTable[(BYTE3(v414) & 0xF) + 0xA0];
                n2 = 0xF2;
                break;

            case 0xF2u:
                v317 = *v316 << 0x18;
                v318 = v28 >> 8;
                n2 = 0xF3;
                break;

            case 0xF3u:
                v319 = v317
                     | (g_encDataRandomTable[((unsigned __int16)v28 >> 0xC) + 0xA0] << 0xC);
                n2 = 0xF4;
                break;

            case 0xF4u:
                v320 = g_encDataRandomTable[(BYTE6(v28) & 0xF) + 0xA0];
                n2 = 0xF5;
                break;

            case 0xF5u:
                v321 = v319 | (v320 << 0x30);
                v322 = &g_encDataRandomTable[((unsigned __int8)v28 >> 4) + 0xA0];
                n2 = 0xF6;
                break;

            case 0xF6u:
                v323 = v321 | (0x10 * (unsigned int)*v322);
                n2 = 0xF7;
                break;

            case 0xF7u:
                v324 = g_encDataRandomTable[(HIBYTE(v28) & 0xF) + 0xA0];
                n2 = 0xF8;
                break;

            case 0xF8u:
                v325 = v323 | (v324 << 0x38);
                v326 = v28 >> 0x10;
                n2 = 0xF9;
                break;

            case 0xF9u:
                v97 = v325 | (g_encDataRandomTable[(v326 & 0xF) + 0xA0] << 0x10);
                n2 = 0xFA;
                break;

            case 0xFAu:
                ContextRecord_1 = v97
                                | ((unsigned __int64)g_encDataRandomTable[(v28 >> 0x3C) + 0xA0] << 0x3C);
                n2 = 0xFB;
                break;

            case 0xFBu:
                v327 = v28 >> 0x28;
                v328 = g_encDataRandomTable[((v28 >> 0x2C) & 0xF) + 0xA0];
                n2 = 0xFC;
                break;

            case 0xFCu:
                v329 = v328 << 0x2C;
                v330 = v318 & 0xF;
                n2 = 0xFD;
                break;

            case 0xFDu:
                v36 = ContextRecord_1
                    | v329
                    | (g_encDataRandomTable[v330 + 0xA0] << 8);
                n2 = 0xFE;
                break;

            case 0xFEu:
                v43 = v36 | g_encDataRandomTable[(v28 & 0xF) + 0xA0];
                n2 = 0xFF;
                break;

            case 0xFFu:
                v331 = g_encDataRandomTable[(((unsigned int)v28 >> 0x14) & 0xF)
                                                          + 0xA0];
                n2 = 0x100;
                break;

            case 0x100u:
                v332 = v331 << 0x14;
                v333 = BYTE4(v28) & 0xF;
                n2 = 0x101;
                break;

            case 0x101u:
                v44 = v43
                    | v332
                    | ((unsigned __int64)g_encDataRandomTable[v333 + 0xA0] << 0x20);
                n2 = 0x102;
                break;

            case 0x102u:
                v334 = (unsigned __int64)g_encDataRandomTable[((v28 >> 0x24) & 0xF)
                                                                            + 0xA0] << 0x24;
                n2 = 0x103;
                break;

            case 0x103u:
                v335 = (unsigned __int64)g_encDataRandomTable[((v28 >> 0x34) & 0xF)
                                                                            + 0xA0] << 0x34;
                n2 = 0x104;
                break;

            case 0x104u:
                v37 = v44 | v334 | v335;
                v336 = &g_encDataRandomTable[(v327 & 0xF) + 0xA0];
                n2 = 0x105;
                break;

            case 0x105u:
                v337 = (unsigned __int64)*v336 << 0x28;
                v338 = v28 >> 0x1C;
                n2 = 0x106;
                break;

            case 0x106u:
                v45 = v37
                    | v337
                    | ((unsigned __int64)g_encDataRandomTable[(v338 & 0xF) + 0xA0] << 0x1C);
                n2 = 0x107;
                break;

            case 0x107u:
                n2 = 0x108;
                break;

            case 0x108u:
                v339 = g_encDataRandomTable[(BYTE3(v44) & 0xF) + 0xB0] << 0x18;
                n2 = 0x109;
                break;

            case 0x109u:
                v340 = v36 >> 8;
                v341 = &g_encDataRandomTable[((unsigned __int16)v36 >> 0xC) + 0xB0];
                n2 = 0x10A;
                break;

            case 0x10Au:
                v342 = v339 | (*v341 << 0xC);
                v343 = BYTE6(v36);
                n2 = 0x10B;
                break;

            case 0x10Bu:
                v344 = v342
                     | ((unsigned __int64)g_encDataRandomTable[(v343 & 0xF) + 0xB0] << 0x30);
                n2 = 0x10C;
                break;

            case 0x10Cu:
                v345 = g_encDataRandomTable[((unsigned __int8)v43 >> 4) + 0xB0];
                n2 = 0x10D;
                break;

            case 0x10Du:
                v346 = v344 | (0x10 * v345);
                v347 = HIBYTE(v37) & 0xF;
                n2 = 0x10E;
                break;

            case 0x10Eu:
                v348 = v346
                     | ((unsigned __int64)g_encDataRandomTable[v347 + 0xB0] << 0x38);
                n2 = 0x10F;
                break;

            case 0x10Fu:
                v349 = v348
                     | (g_encDataRandomTable[(BYTE2(v97) & 0xF) + 0xB0] << 0x10);
                n2 = 0x110;
                break;

            case 0x110u:
                v350 = v349
                     | ((unsigned __int64)g_encDataRandomTable[(ContextRecord_1 >> 0x3C)
                                                                             + 0xB0] << 0x3C);
                n2 = 0x111;
                break;

            case 0x111u:
                v351 = v45 >> 0x28;
                v352 = &g_encDataRandomTable[((v45 >> 0x2C) & 0xF) + 0xB0];
                n2 = 0x112;
                break;

            case 0x112u:
                v353 = v350 | ((unsigned __int64)*v352 << 0x2C);
                n2 = 0x113;
                break;

            case 0x113u:
                v354 = v353 | (g_encDataRandomTable[(v340 & 0xF) + 0xB0] << 8);
                n2 = 0x114;
                break;

            case 0x114u:
                v355 = g_encDataRandomTable[(v43 & 0xF) + 0xB0];
                n2 = 0x115;
                break;

            case 0x115u:
                v356 = v355 | v354;
                v25 = g_encDataRandomTable[(((unsigned int)v44 >> 0x14) & 0xF)
                                                         + 0xB0];
                n2 = 0x116;
                break;

            case 0x116u:
                v357 = v356 | (v25 << 0x14);
                n2 = 0x117;
                break;

            case 0x117u:
                v358 = v357
                     | ((unsigned __int64)g_encDataRandomTable[(BYTE4(v45) & 0xF)
                                                                             + 0xB0] << 0x20);
                n2 = 0x118;
                break;

            case 0x118u:
                v26 = g_encDataRandomTable[((v37 >> 0x24) & 0xF) + 0xB0];
                n2 = 0x119;
                break;

            case 0x119u:
                v359 = v358 | ((unsigned __int64)v26 << 0x24);
                n2 = 0x11A;
                break;

            case 0x11Au:
                v360 = v359
                     | ((unsigned __int64)g_encDataRandomTable[((v37 >> 0x34) & 0xF)
                                                                             + 0xB0] << 0x34);
                n2 = 0x11B;
                break;

            case 0x11Bu:
                v361 = v360
                     | ((unsigned __int64)g_encDataRandomTable[(v351 & 0xF) + 0xB0] << 0x28);
                n2 = 0x11C;
                break;

            case 0x11Cu:
                v362 = g_encDataRandomTable[((unsigned int)v45 >> 0x1C) + 0xB0];
                n2 = 0x11D;
                break;

            case 0x11Du:
                v416 = v361 | (v362 << 0x1C);
                v416 += 0x5EDBD69FE0AFCFEALL;
                v363 = v416;
                n2 = 0x11E;
                break;

            case 0x11Eu:
                v364 = v1702 ^ __ROL8__(__ROL8__(v363, 0x16) + 0x13BC3E8B476C15C4LL, 0x16);
                n2 = 0x11F;
                break;

            case 0x11Fu:
                v82 = v364;
                n2 = 0x120;
                break;

            case 0x120u:
                n2 = 0x121;
                break;

            case 0x121u:
                v83 = __ROL4__(v82 ^ 0x4A49784E, 0x15);
                n2 = 0x122;
                break;

            case 0x122u:
                v417 = __ROL4__(v83, 0xB);
                v417 = __ROL4__(__ROL4__(v417 ^ 0x24E79C6B, 9) - 0x7E716580, 0x13);
                n2 = 0x123;
                break;

            case 0x123u:
                n2 = 0x124;
                break;

            case 0x124u:
                v417 = __ROL4__(__ROL4__(v417, 0xD) + 0x7E716580, 0x17) ^ 0x24E79C6B;
                v84 = v417;
                n2 = 0x125;
                break;

            case 0x125u:
                v85 = v84 ^ dword_1802D2DBC ^ 0xBE8137A1;
                n2 = 0x126;
                break;

            case 0x126u:
                v86 = __ROL4__(v85, 0x18);
                n2 = 0x127;
                break;

            case 0x127u:
                v87 = __ROL4__(v86, 0x12);
                n2 = 0x128;
                break;

            case 0x128u:
                v365 = v231;
                v88 = v87 ^ 0x7A6EDE8D;
                n2 = 0x129;
                break;

            case 0x129u:
                v418 = __ROL4__((v88 - 0x63F55234) ^ 0x39FBAC8C, 0x13);
                v89 = (v418 - 0x6976D47F) ^ 0x10262F9D;
                n2 = 0x12A;
                break;

            case 0x12Au:
                _InterlockedExchangeW(0x30, 0x63, 0x4D, v89, v365 + 0x58);
                n2 = 0x12B;
                break;

            case 0x12Bu:
                v366 = v1014 ^ v1805;
                n2 = 0x12C;
                break;

            case 0x12Cu:
                v367 = __ROL8__(
                           ((v366 + 0x61BBE9D7149134B0LL) ^ 0xDFEE542C76A7AAF0uLL)
                         - 0x1509678523D640EALL,
                           0xE)
                     ^ 0xF0LL;
                n2 = 0x12D;
                break;

            case 0x12Du:
                v31 = (__ROL8__(v367 - 0x57033546396F782ALL, 0xE) + 0x7D019B7AE2EB4B6FLL)
                    ^ 0x2EFFBB12A651F46CLL;
                n2 = 0x12E;
                break;

            case 0x12Eu:
                v368 = HIBYTE(v31);
                v369 = (unsigned __int64)g_encDataRandomTable[(v31 >> 0x3C) + 0x70] << 0x3C;
                n2 = 0x12F;
                break;

            case 0x12Fu:
                v370 = &g_encDataRandomTable[(((unsigned int)v31 >> 8) & 0xF) + 0x70];
                n2 = 0x130;
                break;

            case 0x130u:
                v371 = v369 | (*v370 << 8);
                n2 = 0x131;
                break;

            case 0x131u:
                v372 = g_encDataRandomTable[(BYTE3(v31) & 0xF) + 0x70];
                n2 = 0x132;
                break;

            case 0x132u:
                v373 = v371 | (v372 << 0x18);
                v374 = HIDWORD(v31);
                v375 = v31 >> 0x24;
                n2 = 0x133;
                break;

            case 0x133u:
                v376 = v373
                     | ((unsigned __int64)g_encDataRandomTable[(v375 & 0xF) + 0x70] << 0x24);
                n2 = 0x134;
                break;

            case 0x134u:
                v377 = v376
                     | (0x10
                      * (unsigned int)g_encDataRandomTable[((unsigned __int8)v31 >> 4)
                                                                         + 0x70]);
                n2 = 0x135;
                break;

            case 0x135u:
                v378 = HIWORD(v31);
                v379 = &g_encDataRandomTable[((v31 >> 0x34) & 0xF) + 0x70];
                n2 = 0x136;
                break;

            case 0x136u:
                v380 = v377 | ((unsigned __int64)*v379 << 0x34);
                n2 = 0x137;
                break;

            case 0x137u:
                v381 = v380
                     | ((unsigned __int64)g_encDataRandomTable[(v374 & 0xF) + 0x70] << 0x20);
                n2 = 0x138;
                break;

            case 0x138u:
                v382 = v31 >> 0x28;
                v383 = (unsigned __int64)g_encDataRandomTable[((v31 >> 0x2C) & 0xF)
                                                                            + 0x70] << 0x2C;
                n2 = 0x139;
                break;

            case 0x139u:
                v384 = v383 | v381;
                v385 = v31 >> 0x10;
                v386 = &g_encDataRandomTable[(((unsigned int)v31 >> 0x14) & 0xF)
                                                           + 0x70];
                n2 = 0x13A;
                break;

            case 0x13Au:
                v387 = v384 | (*v386 << 0x14);
                n2 = 0x13B;
                break;

            case 0x13Bu:
                v388 = v387
                     | (g_encDataRandomTable[((unsigned __int16)v31 >> 0xC) + 0x70] << 0xC);
                n2 = 0x13C;
                break;

            case 0x13Cu:
                v27 = g_encDataRandomTable[(v368 & 0xF) + 0x70];
                n2 = 0x13D;
                break;

            case 0x13Du:
                v389 = v388 | ((unsigned __int64)v27 << 0x38);
                v390 = v385 & 0xF;
                n2 = 0x13E;
                break;

            case 0x13Eu:
                v391 = v389 | (g_encDataRandomTable[v390 + 0x70] << 0x10);
                n2 = 0x13F;
                break;

            case 0x13Fu:
                v392 = v391
                     | ((unsigned __int64)g_encDataRandomTable[(v382 & 0xF) + 0x70] << 0x28);
                n2 = 0x140;
                break;

            case 0x140u:
                v393 = g_encDataRandomTable[(v378 & 0xF) + 0x70];
                n2 = 0x141;
                break;

            case 0x141u:
                v394 = v392 | (v393 << 0x30);
                v395 = v31 >> 0x1C;
                n2 = 0x142;
                break;

            case 0x142u:
                v396 = v394
                     | ((unsigned __int64)g_encDataRandomTable[(v395 & 0xF) + 0x70] << 0x1C);
                n2 = 0x143;
                break;

            case 0x143u:
                v397 = v396 | g_encDataRandomTable[(v31 & 0xF) + 0x70];
                n2 = 0x144;
                break;

            case 0x144u:
                v398 = __ROL8__(v397, 0x2B);
                n2 = 0x145;
                break;

            case 0x145u:
                n2 = 0x146;
                break;

            case 0x146u:
                n2 = 0x147;
                break;

            case 0x147u:
                v90 = v55 ^ 0xB341EFE5;
                n2 = 0x148;
                break;

            case 0x148u:
                v399 = v398;
                v91 = __ROL4__(v90 - 0x6D0B6F70, 0x1E);
                n2 = 0x149;
                break;

            case 0x149u:
                v92 = __ROL4__(__ROL4__(v91 ^ 0xE0838EAA, 0x1E) ^ 0xBAB0DDC4, 0x1D);
                n2 = 0x14A;
                break;

            case 0x14Au:
                _InterlockedExchangeW(0x37, 0xF, 1, v92, v399 + 0x8C);
                n2 = 1;
                break;

            case 0x14Bu:
                ContextRecord_3 = *p_ContextRecord;
                Dr1 = (*p_ContextRecord)->Dr1;
                n2 = 0x14C;
                break;

            case 0x14Cu:
                n2 = 0x14D;
                break;

            case 0x14Du:
                n2 = 0x14E;
                break;

            case 0x14Eu:
                n2 = 0x14F;
                break;

            case 0x14Fu:
                n2 = 0x150;
                break;

            case 0x150u:
                n2 = 0x151;
                break;

            case 0x151u:
                n2 = 0x152;
                break;

            case 0x152u:
                n2 = 0x153;
                break;

            case 0x153u:
                n2 = 0x154;
                break;

            case 0x154u:
                n2 = 0x155;
                break;

            case 0x155u:
                v422 = __ROL8__(v38, 4);
                v401 = v422 ^ 0xDE838D86533A540LL;
                n2 = 0x156;
                break;

            case 0x156u:
                v402 = Dr1 ^ (__ROL8__(v401, 0x20) - 0x3A9CCBED1AC47F6LL);
                n2 = 0x157;
                break;

            case 0x157u:
                if ( (v39 ^ v402) == 0x4F )
                    n2 = 0x158;
                else
                    n2 = 0x3A;

                break;

            case 0x158u:
                Dr2 = ContextRecord_3->Dr2;
                n2 = 0x159;
                break;

            case 0x159u:
                n2 = 0x15A;
                break;

            case 0x15Au:
                n2 = 0x15B;
                break;

            case 0x15Bu:
                n2 = 0x15C;
                break;

            case 0x15Cu:
                n2 = 0x15D;
                break;

            case 0x15Du:
                n2 = 0x15E;
                break;

            case 0x15Eu:
                n2 = 0x15F;
                break;

            case 0x15Fu:
                n2 = 0x160;
                break;

            case 0x160u:
                n2 = 0x161;
                break;

            case 0x161u:
                n2 = 0x162;
                break;

            case 0x162u:
                v423 = __ROL8__(v38, 4);
                n0x4F = v423 ^ 0xDE838D86533A540LL;
                n2 = 0x163;
                break;

            case 0x163u:
                n0x4F_2 = v39 ^ Dr2 ^ (__ROL8__(n0x4F, 0x20) - 0x3A9CCBED1AC47F6LL);
                n2 = 0x164;
                break;

            case 0x164u:
                if ( n0x4F_2 == 0x4F )
                    n2 = 0x165;
                else
                    n2 = 0x3A;

                break;

            case 0x165u:
                Dr3 = ContextRecord_3->Dr3;
                n2 = 0x166;
                break;

            case 0x166u:
                n2 = 0x167;
                break;

            case 0x167u:
                n2 = 0x168;
                break;

            case 0x168u:
                n2 = 0x169;
                break;

            case 0x169u:
                n2 = 0x16A;
                break;

            case 0x16Au:
                n2 = 0x16B;
                break;

            case 0x16Bu:
                n2 = 0x16C;
                break;

            case 0x16Cu:
                n2 = 0x16D;
                break;

            case 0x16Du:
                n2 = 0x16E;
                break;

            case 0x16Eu:
                n2 = 0x16F;
                break;

            case 0x16Fu:
                v424 = __ROL8__(v38, 4);
                n0x4F_1 = v424 ^ 0xDE838D86533A540LL;
                n2 = 0x170;
                break;

            case 0x170u:
                n0x4F_3 = v39 ^ Dr3 ^ (__ROL8__(n0x4F_1, 0x20) - 0x3A9CCBED1AC47F6LL);
                n2 = 0x171;
                break;

            case 0x171u:
                if ( n0x4F_3 == 0x4F )
                    n2 = 1;
                else
                    n2 = 0x3A;

                break;

            default:
                continue;
        }
    }
}