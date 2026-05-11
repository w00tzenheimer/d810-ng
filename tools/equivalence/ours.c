#include "mock.h"

__int64 sub_7FFD3338C040_OUR(
        __int64 a1,
        __int64 a2,
        __int64 a3,
        __int64 a4,
        __int64 a5)
{
    unsigned int i; // [rsp+3Ch] [rbp-7BCh]
    __int64 v7; // [rsp+70h] [rbp-788h]
    __int64 v8; // [rsp+1F8h] [rbp-600h]
    __int64 v9; // [rsp+238h] [rbp-5C0h]
    unsigned __int64 v10; // [rsp+2D0h] [rbp-528h]
    __int64 v11; // [rsp+2E0h] [rbp-518h]
    unsigned __int64 v12; // [rsp+2E8h] [rbp-510h]
    __int64 v13; // [rsp+2F0h] [rbp-508h]
    __int64 v14; // [rsp+300h] [rbp-4F8h]
    __int64 v15; // [rsp+3B8h] [rbp-440h]
    __int64 v16; // [rsp+3F8h] [rbp-400h]
    __int64 v17; // [rsp+400h] [rbp-3F8h]
    char v18; // [rsp+408h] [rbp-3F0h]
    unsigned __int64 v19; // [rsp+410h] [rbp-3E8h]
    __int64 v20; // [rsp+418h] [rbp-3E0h]
    char v21; // [rsp+420h] [rbp-3D8h]
    __int64 v22; // [rsp+428h] [rbp-3D0h]
    __int64 v23; // [rsp+440h] [rbp-3B8h]
    __int64 v24; // [rsp+448h] [rbp-3B0h]
    __int64 v25; // [rsp+450h] [rbp-3A8h]
    __int64 v26; // [rsp+4A0h] [rbp-358h]
    char v27; // [rsp+4B0h] [rbp-348h]
    __int64 v28; // [rsp+4C0h] [rbp-338h]
    __int64 v29; // [rsp+4D8h] [rbp-320h]
    __int64 v30; // [rsp+4E8h] [rbp-310h]
    __int64 v31; // [rsp+4F0h] [rbp-308h]
    unsigned __int64 v32; // [rsp+520h] [rbp-2D8h]
    int v33; // [rsp+550h] [rbp-2A8h]
    int v34; // [rsp+578h] [rbp-280h]
    unsigned int v35; // [rsp+580h] [rbp-278h]
    int v36; // [rsp+588h] [rbp-270h]
    unsigned int v37; // [rsp+590h] [rbp-268h]
    __int64 v38; // [rsp+5A0h] [rbp-258h]
    __int64 v39; // [rsp+5D8h] [rbp-220h]
    __int64 v40; // [rsp+5E0h] [rbp-218h]
    __int64 v41; // [rsp+5E8h] [rbp-210h]
    __int64 v42; // [rsp+5F0h] [rbp-208h]
    unsigned __int64 v43; // [rsp+5F8h] [rbp-200h]
    __int64 v44; // [rsp+608h] [rbp-1F0h]
    __int64 v45; // [rsp+610h] [rbp-1E8h]
    __int64 v46; // [rsp+630h] [rbp-1C8h]
    __int64 v47; // [rsp+640h] [rbp-1B8h]
    __int64 v48; // [rsp+650h] [rbp-1A8h]
    __int64 v49; // [rsp+658h] [rbp-1A0h]
    unsigned __int8 *v50; // [rsp+668h] [rbp-190h]
    __int64 v51; // [rsp+670h] [rbp-188h]
    __int64 *v52; // [rsp+680h] [rbp-178h]
    __int64 v53; // [rsp+6D0h] [rbp-128h]
    __int64 v54; // [rsp+6D8h] [rbp-120h]
    __int64 v55; // [rsp+6E0h] [rbp-118h]
    __int64 v56; // [rsp+738h] [rbp-C0h]
    __int64 v57; // [rsp+740h] [rbp-B8h]
    __int64 v58; // [rsp+760h] [rbp-98h]
    __int64 v59; // [rsp+768h] [rbp-90h]

    v52 = (__int64 *)(a5 + 0xD0);
    v49 = *(_QWORD *)(a5 + 0xD0);
    if ( !(8 * (*v52 & 7)
         + 0xD * (*v52 & 0xFFFFFFFFFFFFFFF8uLL)
         - 7 * (*v52 | 0xFFFFFFFFFFFFFFF8uLL)
         - 6 * (~*v52 | 0xFFFFFFF8LL)
         + 0xD * ~(*v52 | 7)
         + 6 * ~(*v52 | 0xFFFFFFFFFFFFFFF8uLL)) )
    {
        v25 = *v52;
        v24 = a3;
        v23 = 0x20;
        goto LABEL_x622F;
    }

    v58 = MEM(v49, 0x4D, 0x57, 8);
    v44 = v58;
    if ( v58 >= 0x20 )
        v58 = 0x20;

    v47 = v58;
    if ( !v44 )
    {
        *v52 = v49 + v58;
        v25 = v49 + v58;
        v24 = v58 + a3;
        v23 = 0x20 - v58;

LABEL_x622F:
        v41 = v23;
        v42 = v24;
        v48 = v25;
        v14 = 7LL * (~(_BYTE)v25 & 0x7F);
        v13 = ~(v25 | 0x7F);
        v12 = v25 | 0xFFFFFFFFFFFFFF80uLL;
        v11 = 7 * (v25 ^ 0x7F);
        v10 = 2 * (unsigned int)(v25 & 0x7F) + v11 - 6 * (v25 & 0x7FFFFFFFFFFFFF80LL) - v12;
        goto LABEL_x40BD;
    }

    v15 = 0x6FE2B37214B84CE1LL;
    v43 = 0xF5872016D7FAC063uLL;
    for ( i = 0x63F502FA; ; i = 0 )
    {
        while ( 1 )
        {
            while ( i > 0x37B42A3F )
            {
                if ( v44 == 1 )
                {
                    v32 = 8 * (v43 & 0xD17DA1C86E91436DuLL)
                        + 5 * ~(v43 | 0x2E825E37916EBC92LL)
                        + 3 * ~(v43 | 0xD17DA1C86E91436DuLL)
                        - 2 * (v43 ^ 0x2E825E37916EBC92LL)
                        - 0x177428EA28D65121LL;
                    if ( ((((((v32 ^ 0x38B49E60BFFE681LL)
                            + (v32 ^ 0x38B49E60BFFE681LL)
                            - v15
                            + 0x4B73FBBE70FE5CB4LL)
                           ^ v43)
                          - v32)
                         ^ v32
                         ^ 0x4520678B9CC77B2FLL)
                        & v47) == 0 )
                        goto LABEL_x3480;

                    *(_QWORD *)(8 * (v26 >> 3) + v51) |= (unsigned __int64)v50[1] << (8 * (unsigned __int8)v26);
                    i = 0;
                }
                else
                {
                    i = 0;
                }
            }

            v10 = 2 * (unsigned int)(v48 & 0x7F) + v11 - 6 * (v48 & 0x7FFFFFFFFFFFFF80LL) - v12;

LABEL_x40BD:
            if ( v10 + v13 == v14 )
            {
                v55 = v48;
                v54 = v42;
                v53 = v41;
                goto LABEL_x3BEF;
            }

            v57 = MEM(v48, 0x5D, 0x18, 0x80);
            v56 = v41;
            if ( v57 < v41 )
                v56 = v57;

            v31 = a5 + 0x50;
            MEM(0x55, v42, (v48 & 0xFFFFFFFFFFFFFFF8uLL) + a5 + 0x50, v56 >> 3);
            v59 = v56 & 0x38;
            v30 = *v52 + v59;
            *v52 = v30;
            v40 = v42 + v59;
            v46 = v41 - v59;
            v29 = v46 >> 7;
            if ( v46 >= 0x80 )
                break;

            v55 = v30;
            v54 = v42 + v59;
            v53 = v41 - v59;

LABEL_x3BEF:
            v7 = v55;
            v38 = v54;
            v45 = v53;
            if ( !v53 )
                return 0x5644FD01B1049C4BLL;

LABEL_x3480:
            if ( !v7 )
            {
                v18 = v45;
                v17 = v45;
                v16 = v38;
                goto LABEL_x32DA;
            }

            if ( v7 == 0x80 )
            {
                v21 = v45;
                v20 = v38;
                v19 = v45;

LABEL_x325D:
                MEM(0, 0x27, 0x36, a5);
                *v52 = 0;
                v18 = v21;
                v17 = v19;
                v16 = v20;

LABEL_x32DA:
                sub_180016770(a5 + 0xC0, (__int64)&unk_180018E95, 0x10);
                sub_180016770(a5 + 0xB0, (__int64)&unk_180018E95, 0x10);
                sub_180016770(a5 + 0xA0, (__int64)&unk_180018E95, 0x10);
                sub_180016770(a5 + 0x90, (__int64)&unk_180018E95, 0x10);
                sub_180016770(a5 + 0x80, (__int64)&unk_180018E95, 0x10);
                sub_180016770(a5 + 0x70, (__int64)&unk_180018E95, 0x10);
                sub_180016770(a5 + 0x60, (__int64)&unk_180018E95, 0x10);
                sub_180016770(a5 + 0x50, (__int64)&unk_180018E95, 0x10);
                v27 = v18;
                v51 = a5 + 0x50;
                MEM(0x2E, v16, a5 + 0x50, v17 >> 3);
                v39 = *v52;
                v8 = 0x11 * ~(v39 | v18 & 0x78)
                   + 7 * ~(*v52 | ~(unsigned __int64)(v18 & 0x78))
                   + 0xC * (~(unsigned __int64)(v18 & 0x78) & v39)
                   + 0x13LL * ((unsigned int)*v52 & v18 & 0x78)
                   - 0xB * (*v52 | ~(unsigned __int64)(v18 & 0x78))
                   - 6 * ~(v39 & ~(unsigned __int64)(v18 & 0x78));
                *v52 = v8;
                v50 = (unsigned __int8 *)(v16 + (v18 & 0x78));
                goto LABEL_x6448;
            }

            v27 = v45;
            v51 = a5 + 0x50;
            MEM(0x2E, v38, a5 + 0x50, v45 >> 3);
            v39 = *v52;
            v8 = 0x11 * ~(v39 | v45 & 0x78)
               + 7 * ~(*v52 | ~(unsigned __int64)(v45 & 0x78))
               + 0xC * (~(unsigned __int64)(v45 & 0x78) & v39)
               + 0x13 * ((unsigned int)*v52 & v45 & 0x78)
               - 0xB * (*v52 | ~(unsigned __int64)(v45 & 0x78))
               - 6 * ~(v39 & ~(unsigned __int64)(v45 & 0x78));
            *v52 = v8;
            v50 = (unsigned __int8 *)(v38 + (v45 & 0x78));

LABEL_x6448:
            if ( (v27 & 7) == 0 )
                return 0x5644FD01B1049C4BLL;

            *(_QWORD *)(8 * (v8 >> 3) + v51) |= (unsigned __int64)*v50 << ((8 * v39) & 0x38);
            v26 = *v52 + 1;
            *v52 = v26;
            i = 0;
        }

        if ( v30 == 0x80 )
            break;
    }

    MEM((unsigned int)(v33 - 0x3D0E54C7 + 0x1D4AFF82), 0x11, 0x4A, a5);
    MEM(0x62, v40, v31, 0x10);
    *v52 = 0x80;
    if ( v29 == 1 )
    {
        v22 = v40 + 0x80;
    }
    else
    {
        while ( 1 )
        {
            MEM(
                2 * (v37 & (v34 - v35 - v36))
              + 3 * ~(v37 & (v34 - v35 - v36))
              + 7 * ~(v34 - v35 - v36)
              - 2 * (~v37 & (v34 - v35 - v36))
              - 0xA * ~((v34 - v35 - v36) | v37)
              - 9 * ~((v34 - v35 - v36) | ~v37),
                0x2C,
                0x44,
                a5);
            MEM(0x44, v28, v31, 0x10);
            *v52 = 0x80;
            if ( v9 - 0xD98748F8C4E3EF8LL + 0xD98748F8C4E3EF9LL == v29 )
                break;

            v9 = v9 - 0xD98748F8C4E3EF8LL + 0xD98748F8C4E3EF9LL;
            v28 += 0x80;
            v37 = 0xB140360B;
            v36 = 0x4A00E104;
            v35 = 0xA5627292;
            v34 = 0x3E231D8B;
        }

        v22 = v28 + 0x80;
    }

    if ( 4 * (v46 | 0xFFFFFFFFFFFFFF80uLL)
       - (4 * (v46 & 0x3FFFFFFFFFFFFF80LL)
        + 5 * (v46 & 0x7F))
       - 4 * (~v46 & 0x3FFFFFFFFFFFFF80LL)
       - 2 * ~((unsigned __int8)v46 | 0xFFFFFF80) != 0xFFFFFFFFFFFFFF02uLL )
    {
        v21 = v41 - v59;
        v20 = v22;
        v19 = 4 * (v46 | 0xFFFFFFFFFFFFFF80uLL)
            - (4 * (v46 & 0x3FFFFFFFFFFFFF80LL)
             + 5 * (v46 & 0x7F))
            - 4 * (~v46 & 0x3FFFFFFFFFFFFF80LL)
            - 2 * ~((unsigned __int8)v46 | 0xFFFFFF80)
            + 0xFE;
        goto LABEL_x325D;
    }

    return 4 * (v46 | 0xFFFFFFFFFFFFFF80uLL)
         - (4 * (v46 & 0x3FFFFFFFFFFFFF80LL)
          + 5 * (v46 & 0x7F))
         - 4 * (~v46 & 0x3FFFFFFFFFFFFF80LL)
         - 2 * ~((unsigned __int8)v46 | 0xFFFFFF80)
         + 0xFE;
}
