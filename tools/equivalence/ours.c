/* ours.c — D810 AFTER pseudocode for sub_7FFD3338C040 (counter_hoist build).
 *
 * Source: .tmp/sub7FFD_promote_1777908050.txt AFTER block (lines 100478..100783)
 * Counter-hoist promotion: 6 sites (blk 75/101/103/132/161/163)
 * Induction restored: ++*v54; visible in tail; v28 += 0x80; visible in inner loop.
 */
#include "mock.h"

__int64 sub_7FFD3338C040_OUR(_QWORD a1, __int64 a2, unsigned __int8 *a3, __int64 a4, __int64 a5)
{
    __int64 v6 = 0; // [rsp+70h] [rbp-788h]
    __int64 v7 = 0; // [rsp+1F8h] [rbp-600h]
    __int64 v8 = 0; // [rsp+238h] [rbp-5C0h]
    unsigned __int64 v9 = 0; // [rsp+2D0h] [rbp-528h]
    __int64 v10 = 0; // [rsp+2E0h] [rbp-518h]
    __int64 v11 = 0; // [rsp+2E8h] [rbp-510h]
    __int64 v12 = 0; // [rsp+2F0h] [rbp-508h]
    __int64 v13 = 0; // [rsp+300h] [rbp-4F8h]
    unsigned __int8 *v14 = 0; // [rsp+3F8h] [rbp-400h]
    __int64 v15 = 0; // [rsp+400h] [rbp-3F8h]
    char v16 = 0; // [rsp+408h] [rbp-3F0h]
    unsigned __int64 v17 = 0; // [rsp+410h] [rbp-3E8h]
    unsigned __int8 *v18 = 0; // [rsp+418h] [rbp-3E0h]
    char v19 = 0; // [rsp+420h] [rbp-3D8h]
    unsigned __int8 *v20 = 0; // [rsp+428h] [rbp-3D0h]
    __int64 v21 = 0; // [rsp+440h] [rbp-3B8h]
    unsigned __int8 *v22 = 0; // [rsp+448h] [rbp-3B0h]
    __int64 v23 = 0; // [rsp+450h] [rbp-3A8h]
    __int64 v24 = 0; // [rsp+478h] [rbp-380h]
    __int64 v25 = 0; // [rsp+4A0h] [rbp-358h]
    __int64 v26 = 0; // [rsp+4A0h] [rbp-358h]
    char v27 = 0; // [rsp+4B0h] [rbp-348h]
    __int64 v28 = 0; // [rsp+4C0h] [rbp-338h]
    __int64 v29 = 0; // [rsp+4D8h] [rbp-320h]
    __int64 v30 = 0; // [rsp+4E8h] [rbp-310h]
    __int64 v31 = 0; // [rsp+4F0h] [rbp-308h]
    unsigned __int64 v32 = 0; // [rsp+528h] [rbp-2D0h]
    int v33 = 0; // [rsp+550h] [rbp-2A8h]
    int v34 = 0; // [rsp+578h] [rbp-280h]
    unsigned int v35 = 0; // [rsp+580h] [rbp-278h]
    int v36 = 0; // [rsp+588h] [rbp-270h]
    unsigned int v37 = 0; // [rsp+590h] [rbp-268h]
    unsigned __int8 *v38 = 0; // [rsp+5A0h] [rbp-258h]
    __int64 v39 = 0; // [rsp+5D8h] [rbp-220h]
    unsigned __int8 *v40 = 0; // [rsp+5E0h] [rbp-218h]
    __int64 v41 = 0; // [rsp+5E8h] [rbp-210h]
    unsigned __int8 *v42 = 0; // [rsp+5F0h] [rbp-208h]
    unsigned __int64 *v43 = 0; // [rsp+600h] [rbp-1F8h]
    __int64 v44 = 0; // [rsp+608h] [rbp-1F0h]
    __int64 v45 = 0; // [rsp+610h] [rbp-1E8h]
    __int64 v46 = 0; // [rsp+630h] [rbp-1C8h]
    unsigned __int64 v47 = 0; // [rsp+648h] [rbp-1B0h]
    __int64 v48 = 0; // [rsp+650h] [rbp-1A8h]
    __int64 v49 = 0; // [rsp+658h] [rbp-1A0h]
    __int64 v50 = 0; // [rsp+668h] [rbp-190h]
    unsigned __int8 *v51 = 0; // [rsp+668h] [rbp-190h]
    __int64 v52 = 0; // [rsp+670h] [rbp-188h]
    __int64 v53 = 0; // [rsp+670h] [rbp-188h]
    __int64 *v54 = 0; // [rsp+680h] [rbp-178h]
    unsigned __int64 v55 = 0; // [rsp+690h] [rbp-168h]
    __int64 v56 = 0; // [rsp+6D0h] [rbp-128h]
    unsigned __int8 *v57 = 0; // [rsp+6D8h] [rbp-120h]
    __int64 v58 = 0; // [rsp+6E0h] [rbp-118h]
    __int64 v59 = 0; // [rsp+738h] [rbp-C0h]
    __int64 v60 = 0; // [rsp+740h] [rbp-B8h]
    __int64 v61 = 0; // [rsp+760h] [rbp-98h]
    __int64 v62 = 0; // [rsp+768h] [rbp-90h]

    v54 = (__int64 *)(a5 + 0xD0);
    v49 = *(_QWORD *)(a5 + 0xD0);
    v47 = 8 * (*v54 & 7)
        + 0xD * (*v54 & 0xFFFFFFFFFFFFFFF8uLL)
        - 7 * (*v54 | 0xFFFFFFFFFFFFFFF8uLL)
        - 6 * (~*v54 | 0xFFFFFFF8LL)
        + 0xD * ~(*v54 | 7)
        + 6 * ~(*v54 | 0xFFFFFFFFFFFFFFF8uLL);
    if ( v47 )
    {
        v61 = MEM(v49, 0x4D, 0x57, 8);
        v44 = v61;
        if ( v61 >= 0x20 )
            v61 = 0x20;

        if ( v44 )
        {
            v43 = (unsigned __int64 *)((v49 & 0xFFFFFFFFFFFFFFF8uLL) + a5 + 0x50);
            v32 = *v43;
            do
            {
                if ( v44 == 1 )
                    break;

                v55 = ((unsigned __int64)*a3 << (8
                                               * (0xFF
                                                - 4 * ~(_BYTE)v47
                                                - 3
                                                - 3 * (unsigned __int8)v47)))
                    | v32;
                *v43 = v55;
                *v43 = ((unsigned __int64)a3[1] << (8 * ((unsigned __int8)v47 + 1))) | v55;
            }
            while ( (v61 & 0x3E) != 2 );

            if ( (v61 & 1) == 0 )
                goto LABEL_x31F0;

            *(_QWORD *)(8 * (v25 >> 3) + v52) |= (unsigned __int64)*(unsigned __int8 *)(v50 + 1) << (8 * (unsigned __int8)v25);
            v9 = 2 * (unsigned int)(v48 & 0x7F) + v10 - 6 * (v48 & 0x7FFFFFFFFFFFFF80LL) - v11;
            goto LABEL_x3E2D;
        }

        *v54 = v49 + v61;
        v23 = v49 + v61;
        v22 = &a3[v61];
        v21 = 0x20 - v61;
    }
    else
    {
        v23 = *v54;
        v22 = a3;
        v21 = 0x20;
    }

    v41 = v21;
    v42 = v22;
    v48 = v23;
    v13 = 7LL * (~(_BYTE)v23 & 0x7F);
    v12 = ~(v23 | 0x7F);
    v9 = 2 * (unsigned int)(v23 & 0x7F)
       + 7 * (v23 ^ 0x7F)
       - 6 * (v23 & 0x7FFFFFFFFFFFFF80LL)
       - (v23 | 0xFFFFFFFFFFFFFF80uLL);

LABEL_x3E2D:
    if ( v9 + v12 == v13 )
    {
        v58 = v48;
        v57 = v42;
        v56 = v41;
        goto LABEL_x395F;
    }

    while ( 1 )
    {
        v60 = MEM(v48, 0x5D, 0x18, 0x80);
        v59 = v41;
        if ( v60 < v41 )
            v59 = v60;

        v31 = a5 + 0x50;
        MEM(0x55, v42, (v48 & 0xFFFFFFFFFFFFFFF8uLL) + a5 + 0x50, v59 >> 3);
        v62 = v59 & 0x38;
        v30 = *v54 + v62;
        *v54 = v30;
        v40 = &v42[v62];
        v46 = v41 - v62;
        v29 = v46 >> 7;
        if ( v46 >= 0x80 )
        {
            if ( v30 == 0x80 )
                MEM((unsigned int)(v33 - 0x3D0E54C7 + 0x1D4AFF82), 0x11, 0x4A, a5);

            MEM(0x62, v40, v31, 0x10);
            *v54 = 0x80;
            if ( v29 == 1 )
            {
                v20 = v40 + 0x80;
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
                    *v54 = 0x80;
                    if ( v8 - 0xD98748F8C4E3EF8LL + 0xD98748F8C4E3EF9LL == v29 )
                        break;

                    v8 = v8 - 0xD98748F8C4E3EF8LL + 0xD98748F8C4E3EF9LL;
                    v28 += 0x80;
                    v37 = 0xB140360B;
                    v36 = 0x4A00E104;
                    v35 = 0xA5627292;
                    v34 = 0x3E231D8B;
                }

                v20 = (unsigned __int8 *)(v28 + 0x80);
            }

            if ( 4 * (v46 | 0xFFFFFFFFFFFFFF80uLL)
               - (4 * (v46 & 0x3FFFFFFFFFFFFF80LL)
                + 5 * (v46 & 0x7F))
               - 4 * (~v46 & 0x3FFFFFFFFFFFFF80LL)
               - 2 * ~((unsigned __int8)v46 | 0xFFFFFF80) == 0xFFFFFFFFFFFFFF02uLL )
                return 4 * (v46 | 0xFFFFFFFFFFFFFF80uLL)
                     - (4 * (v46 & 0x3FFFFFFFFFFFFF80LL)
                      + 5 * (v46 & 0x7F))
                     - 4 * (~v46 & 0x3FFFFFFFFFFFFF80LL)
                     - 2 * ~((unsigned __int8)v46 | 0xFFFFFF80)
                     + 0xFE;

            v19 = v41 - v62;
            v18 = v20;
            v17 = 4 * (v46 | 0xFFFFFFFFFFFFFF80uLL)
                - (4 * (v46 & 0x3FFFFFFFFFFFFF80LL)
                 + 5 * (v46 & 0x7F))
                - 4 * (~v46 & 0x3FFFFFFFFFFFFF80LL)
                - 2 * ~((unsigned __int8)v46 | 0xFFFFFF80)
                + 0xFE;
            goto LABEL_x2FCD;
        }

        v58 = v30;
        v57 = &v42[v62];
        v56 = v41 - v62;

LABEL_x395F:
        v6 = v58;
        v38 = v57;
        v45 = v56;
        if ( !v56 )
            return 0x5644FD01B1049C4BLL;

LABEL_x31F0:
        if ( !v6 )
        {
            v16 = v45;
            v15 = v45;
            v14 = v38;
            goto LABEL_x304A;
        }

        if ( v6 == 0x80 )
        {
            v19 = v45;
            v18 = v38;
            v17 = v45;

LABEL_x2FCD:
            MEM(0, 0x27, 0x36, a5);
            *v54 = 0;
            v16 = v19;
            v15 = v17;
            v14 = v18;

LABEL_x304A:
            sub_1800164E0(a5 + 0xC0, &unk_180018E95, 0x10);
            sub_1800164E0(a5 + 0xB0, &unk_180018E95, 0x10);
            sub_1800164E0(a5 + 0xA0, &unk_180018E95, 0x10);
            sub_1800164E0(a5 + 0x90, &unk_180018E95, 0x10);
            sub_1800164E0(a5 + 0x80, &unk_180018E95, 0x10);
            sub_1800164E0(a5 + 0x70, &unk_180018E95, 0x10);
            sub_1800164E0(a5 + 0x60, &unk_180018E95, 0x10);
            sub_1800164E0(a5 + 0x50, &unk_180018E95, 0x10);
            v27 = v16;
            v53 = a5 + 0x50;
            MEM(0x2E, v14, a5 + 0x50, v15 >> 3);
            v39 = *v54;
            v7 = 0x11 * ~(v39 | v16 & 0x78)
               + 7 * ~(*v54 | ~(unsigned __int64)(v16 & 0x78))
               + 0xC * (~(unsigned __int64)(v16 & 0x78) & v39)
               + 0x13LL * ((unsigned int)*v54 & v16 & 0x78)
               - 0xB * (*v54 | ~(unsigned __int64)(v16 & 0x78))
               - 6 * ~(v39 & ~(unsigned __int64)(v16 & 0x78));
            *v54 = v7;
            v51 = &v14[v16 & 0x78];
            goto LABEL_x61B8;
        }

        v27 = v45;
        v53 = a5 + 0x50;
        MEM(0x2E, v38, a5 + 0x50, v45 >> 3);
        v39 = *v54;
        v7 = 0x11 * ~(v39 | v45 & 0x78)
           + 7 * ~(*v54 | ~(unsigned __int64)(v45 & 0x78))
           + 0xC * (~(unsigned __int64)(v45 & 0x78) & v39)
           + 0x13 * ((unsigned int)*v54 & v45 & 0x78)
           - 0xB * (*v54 | ~(unsigned __int64)(v45 & 0x78))
           - 6 * ~(v39 & ~(unsigned __int64)(v45 & 0x78));
        *v54 = v7;
        v51 = &v38[v45 & 0x78];

LABEL_x61B8:
        if ( (v27 & 7) == 0 )
            break;

        *(_QWORD *)(8 * (v7 >> 3) + v53) |= (unsigned __int64)*v51 << ((8 * v39) & 0x38);
        v26 = *v54 + 1;
        *v54 = v26;
        if ( (v27 & 7) == 1 )
            return 0xC5FB34A1D9A6E315uLL;

        *(_QWORD *)(8 * (v26 >> 3) + v53) |= (unsigned __int64)v51[1] << (8 * (unsigned __int8)v26);
    }

    *(_QWORD *)((v24 & 0xFFFFFFFFFFFFFFF8uLL) + v53) |= (unsigned __int64)v51[6] << (8 * (unsigned __int8)v24);
    ++*v54;
    return a5 + 0xD0;
}