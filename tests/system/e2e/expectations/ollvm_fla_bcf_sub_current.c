// test_function_ollvm_fla_bcf_sub - CURRENT OUTPUT (PARTIAL)
// Address: 0x932c
// Generated: 2024-11-30
//
// STATUS: PARTIAL SUCCESS
// - 73% code reduction (578 -> 152 lines)
// - Core logic preserved (password check against "secret")
// - Opaque predicates NOT removed
// - Still has goto spaghetti

void __fastcall test_function_ollvm_fla_bcf_sub(__int64 result, __int64 a2)
{
    // [COLLAPSED LOCAL DECLARATIONS. PRESS NUMPAD "+" TO EXPAND]

    v10[0xD] = result;
    HIDWORD(v10[0xC]) = HIDWORD(a2);
    memset(v10, 0, 0x64u);
    LODWORD(v11.tv_sec) = 0;
    LODWORD(v10[0xB]) = gettimeofday(&v11, 0);
    v10[0xA] = &v11;
    v10[9] = 0xFFFFFFFFLL;
    LODWORD(v11.tv_sec) = 0xD32B5931;
    LODWORD(v11.tv_sec) = *(_DWORD *)v11.tv_sec + 0x26C76F03;
    printf("Please enter password:");
    HIDWORD(v10[8]) = scanf("%s", v10);
    LODWORD(v11.tv_sec) = *(_DWORD *)v11.tv_sec;
    LODWORD(v10[8]) = strncmp((const char *)v10, "secret", 0x64u);
    v10[6] = &v11;
    LODWORD(v11.tv_sec) = v10[8];
    LODWORD(v11.tv_sec) |= LODWORD(v11.tv_sec) != 0;
    v10[5] = &v11;
    HIDWORD(v10[7]) = 0xC6C7D681;
    HIDWORD(v10[4]) = 0x40977B1B;
    if ( LODWORD(v11.tv_sec) )
        HIDWORD(v10[4]) = 0x15BFDD50;

    v5 = HIDWORD(v10[4]);
    while ( v5 != 0x15BFDD50 )
    {
        if ( v5 == 0x31FFBFE4 )
        {
            LODWORD(v11.tv_sec) += 0x42;

LABEL_xA794:
            for ( LODWORD(v11.tv_sec) += 0x42;
                  ;
                  *(_DWORD *)v11.tv_sec = (~LODWORD(v11.tv_sec)
                                         ^ LODWORD(v11.tv_sec))
                                        & 0x173063C1
                                        ^ LODWORD(v11.tv_sec) )
            {
LABEL_xA8D4:
                ;
            }
        }

        if ( v5 == 0x40977B1B )
            goto LABEL_xB49C;

        if ( v5 != 0x4364F663 )
        {
            if ( v5 != 0x5F3E61FD )
                goto LABEL_xA8D4;

            v7 = 0x31FFBFE4;
            if ( y < 0xA != (((((_BYTE)x - 1) * (_BYTE)x) & 1) == 0) )
                v7 = 0xFB962B33;

            v5 = v7;
            goto LABEL_xA768;
        }

        tv_sec = v11.tv_sec;
        tv_sec_low = LODWORD(v11.tv_sec);
        ++LODWORD(v11.tv_sec);
        for ( LODWORD(v11.tv_sec) += tv_sec * *((char *)v10 + tv_sec_low); ; LODWORD(v11.tv_sec) = 0 )
        {
            v6 = 0xC0554C4A;
            if ( LODWORD(v11.tv_sec) < 0x64 )
                v6 = 0x4364F663;

            v5 = v6;
            if ( v6 == 0xC0554C4A )
                goto LABEL_xA8D4;

LABEL_xA3C8:
            if ( v5 == 0xE01F6CFA )
            {
                v8 = 0xA5E465F;
                if ( !v4 )
                    v8 = 0xE5EB36B2;

                v5 = v8;
            }

            if ( v5 == 0xE5EB36B2 )
            {
                LODWORD(v11.tv_sec) = ~(~(LODWORD(v11.tv_sec) ^ LOBYTE(v11.tv_sec))
                                      & 0xFFFFFFBD
                                      ^ LOBYTE(v11.tv_sec));
                goto LABEL_xA8D4;
            }

LABEL_xA768:
            if ( v5 == 0xFB962B33 )
                goto LABEL_xA794;

LABEL_xA9E0:
            if ( v5 != 0x50B4560 )
                break;
        }

LABEL_xAC68:
        if ( v5 == 0xA5E465F )
        {
            LODWORD(v11.tv_sec) -= 0x42;
            goto LABEL_xA8D4;
        }
    }

    LODWORD(v10[4]) = 0x50EFC03F;
    *(_DWORD *)v11.tv_sec = 0;
    HIDWORD(v10[3]) = 0x2B96AD49;

LABEL_xB49C:
    LODWORD(v10[3]) = 0x1AEAC8BB;
    HIDWORD(v10[2]) = v11.tv_sec;
    LODWORD(v10[2]) = 0xC9D9D7CC;
    HIDWORD(v10[1]) = 0x50B4560;
    if ( (v11.tv_sec & 1) != 0 )
        HIDWORD(v10[1]) = 0xA6642397;

    v5 = HIDWORD(v10[1]);
    if ( HIDWORD(v10[1]) == 0xA6642397 )
    {
        LODWORD(v10[1]) = 0xBE1B9481;
        LODWORD(v11.tv_sec) *= 6;
        v4 = v11.tv_sec & 3;
        HIDWORD(v10[0]) = 0x4DFCE08E;
        LODWORD(v10[0]) = 0xA3130002;
        if ( (v11.tv_sec & 3) == 0 )
            LODWORD(v10[0]) = 0xE01F6CFA;

        v5 = v10[0];
        if ( LODWORD(v10[0]) == 0xA3130002 )
        {
            v9 = 0xA5E465F;
            if ( v4 == 1 )
                v9 = 0x5F3E61FD;

            v5 = v9;
            goto LABEL_xAC68;
        }

        goto LABEL_xA3C8;
    }

    goto LABEL_xA9E0;
}
