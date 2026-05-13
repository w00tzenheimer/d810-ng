/* ref.c — reference (manually unflattened) sub_7FFD3338C040 wired to trace stubs.
 *
 * Source: ~/src/idapro/d810/_gitless/sub_7FFD3338C040_unflattened.c
 * Modifications:
 *   - Replaced #include "polyfill.h" / "platform.h" with #include "mock.h"
 *   - Stripped __fastcall / EXPORT / D810_NOINLINE (mock.h provides empties)
 *   - Renamed entry to sub_7FFD3338C040_REF
 *   - Removed `volatile int g_..._sink` (unused, simplifies link)
 *   - Body kept verbatim; calls to sub_7FFD32FF8F30/...050180/...333B4500 bind
 *     to mock.c stubs which record CallEvents.
 */
#include "mock.h"

__int64 sub_7FFD3338C040_REF(_QWORD a1, __int64 a2, __int64 a3, __int64 a4, __int64 a5)
{
    __int64 *v49 = (__int64 *)(a5 + 0xD0);
    __int64 v54 = *v49;

    __int64 v135 = 6 * ~(*v49 | 0xFFFFFFFFFFFFFFF8uLL);
    __int64 v136 = 0xD * ~(*v49 | 7);
    __int64 v137 = 0xD * (*v49 & 0xFFFFFFFFFFFFFFF8uLL)
                 + 8 * (*v49 & 7)
                 - 7 * (*v49 | 0xFFFFFFFFFFFFFFF8uLL)
                 - 6 * (~*v49 | 0xFFFFFFF8LL);
    __int64 v56 = v135 + v136 + v137;

    __int64 v55, v67, v68;
    __int64 v57 = 0;

    if ( v56 )
    {
        __int64 v20 = sub_7FFD32FF8F30((_QWORD)(v54), 0x4D, 0x57, 8);
        __int64 v64 = v20;
        if ( v20 >= 0x20 )
            v20 = 0x20;

        v57 = v20;
        if ( v64 )
        {
            unsigned __int64 *v65 = (unsigned __int64 *)(a5 + (v54 & 0xFFFFFFFFFFFFFFF8uLL) + 0x50);
            __int64 v92 = *v65;
            __int64 v138 = 0x6FE2B37214B84CE1LL;
            __int64 v66 = 0xF5872016D7FAC063uLL;

            __int64 v139 = 3 * ~(v66 | 0xD17DA1C86E91436DuLL);
            __int64 v140 = v66 | 0x2E825E37916EBC92LL;
            __int64 v93 = v139 + 5 * ~v140 + 8 * (v66 & 0xD17DA1C86E91436DuLL) - 2 * (v66 ^ 0x2E825E37916EBC92LL) - 0x177428EA28D65121LL;
            __int64 v141 = v93 ^ 0x4520678B9CC77B2FLL;
            __int64 v142 = (v66 ^ ((v93 ^ 0x38B49E60BFFE681LL) - v138 + (v93 ^ 0x38B49E60BFFE681LL) + 0x4B73FBBE70FE5CB4LL)) - v93;

            __int64 v143 = v57 & (v141 ^ v142);
            __int64 v117 = 0, v118 = 0;

            if ( v64 == 1 )
            {
                v117 = v92;
                v118 = 0;
            }
            else
            {
                __int64 v144 = v57 & 0x3E;
                __int64 v115 = v92;
                __int64 v116 = 0;
                __int64 v58, v145, v146, v147, v148, v149, v150, v46, v95, v96;
                v95 = v115; v96 = 0;
                do
                {
                    v58 = v116;
                    v145 = v115;
                    v146 = *(unsigned __int8 *)(a3 + v116);
                    v147 = ~v56;
                    v148 = 3 * ~(v58 | v147);
                    v149 = ~(v58 & ~v56) - (2 * (v58 & ~v56) + 2 * (v56 & v58)) - 4 * ~(v56 | v58) - 3;
                    v150 = v149 - v148;

                    v46 = v145 | (v146 << (v150 << (0xFA ^ (unsigned __int8)(((0x54 + 0x24 - 2) ^ 0x30 ^ (0x24 + 0x54 - 0x33) ^ (0xB7 - 0x62)) - 0x5D))));
                    *v65 = v46;
                    v95 = v46 | ((unsigned __int64)*(unsigned __int8 *)(a3 + v58 + 1) << (8 * ((unsigned __int8)v56 + ((unsigned __int8)v58 | 1u))));
                    *v65 = v95;
                    v96 = v58 + 2;
                    v115 = v95;
                    v116 = v96;
                } while ( v58 + 2 != v144 );
                v117 = v95;
                v118 = v96;
            }

            __int64 v157 = v118;
            __int64 v156 = v117;
            if ( v143 )
            {
                *v65 = v156 | ((unsigned __int64)*(unsigned __int8 *)(a3 + v157) << (8 * ((unsigned __int8)v56 + (unsigned __int8)v157)));
            }
        }

        __int64 v16 = *v49;
        __int64 v158 = v16;
        __int64 v159 = v57 + v158;
        *v49 = v159;
        __int64 v160 = a3 + v57;

        v55 = v159;
        v67 = v160;
        v68 = 0x20 - v57;
    }
    else
    {
        v55 = v54;
        v67 = a3;
        v68 = 0x20;
    }

    __int64 v161 = 7LL * (~(_BYTE)v55 & 0x7F);
    __int64 v162 = v55 | 0x7F;
    __int64 v163 = ~v162;
    __int64 v164 = v55 | 0xFFFFFFFFFFFFFF80uLL;
    __int64 v165 = 7 * (v55 ^ 0x7F);
    __int64 v166 = 6 * (v55 & 0x7FFFFFFFFFFFFF80LL);
    __int64 v167 = v165 + 2 * (unsigned int)(v55 & 0x7F) - v166 - v164;

    __int64 v36, v37, v38;

    if ( v163 + v167 == v161 )
    {
        v36 = v55;
        v37 = v67;
        v38 = v68;
    }
    else
    {
        __int64 v168 = 0x91FA460CD2D32E41uLL;
        __int64 v169 = 0x37F13911D652CC78LL;
        __int64 v170 = 0xADC4CF83D2CF56F0uLL;
        __int64 v97 = 0xF035F04C254451F3uLL;
        __int64 v171 = v97 + 0x7552BC11D833A13ALL;
        __int64 v172 = (v97 + 0x7552BC11D833A13ALL) ^ 0x9EDA0CA9221A129LL;

        __int64 v24 = sub_7FFD32FF8F30(
                  v55,
                  0x5D,
                  0x18,
                  v97 + (v170 ^ (v172 - v169 - v171 + 0x3D15731BE3B5F7DFLL)) - v168);

        __int64 v25 = v68;
        if ( v24 < v68 )
            v25 = v24;

        __int64 v98 = v25;
        __int64 v99 = a5 + 0x50;

        sub_7FFD33050180(
            0x55,
            v67,
            a5 + (v55 & 0xFFFFFFFFFFFFFFF8uLL) + 0x50,
            v98 >> 3);

        __int64 v19 = v98 & 0x38;
        __int64 v100 = v19 + *v49;
        *v49 = v100;
        __int64 v69 = v19 + v67;
        __int64 v59 = v68 - v19;

        __int64 v102 = v59 >> 7;

        if ( v59 >= 0x80 )
        {
            __int64 v103 = 0x989C93011F7C5B59uLL;
            __int64 v182 = 0x9A2F7F3952A0EA97uLL;
            __int64 v183 = v103 + 0x2FA79C4916F275A9LL;
            __int64 v184 = v103 - 0x1A57180B6086323DLL;
            __int64 v185 = v103 + 0x238DAEF738FB5AD7LL;

            if ( v100 == (__int64)((v103 ^ (v184 + v183 + v185)) - v182) )
            {
                __int64 v85 = 0xB2AD891A;
                __int64 v86 = 0x7A0A9ACD;
                __int64 v50 = 0xE03CAABA;
                __int64 v87 = ~v50;
                __int64 v88 = v87;
                __int64 v89 = v50 | 0x2FC42221;
                __int64 v90 = (v50 | 0xD03BDDDE) + (v50 & 0x2FC42221) - 0xB * (v50 & 0xD03BDDDE) - 0xB * ~v89 + v88 - 0xD6D7775;
                __int64 v91 = v86 ^ 0x6740654F;

                sub_7FFD333B4500((int)(v90 + v85 + v91), 0x11, 0x4A, (__int64 *)a5);
            }

            sub_7FFD33050180((_QWORD)(0x62), v69, v99, 0x10);
            __int64 v104 = v69 + 0x80;
            *v49 = 0x80;

            __int64 v124;
            if ( v102 == 1 )
            {
                v124 = v104;
            }
            else
            {
                __int64 v122 = v104;
                __int64 v123 = 1;
                do
                {
                    __int64 v186 = v123;
                    __int64 v105 = v122;
                    __int64 v79 = 0xB140360B;
                    __int64 v80 = 0x4A00E104;
                    __int64 v81 = 0xA5627292;
                    __int64 v82 = 0x3E231D8B;
                    __int64 v29 = v82 - v81 - v80;

                    sub_7FFD333B4500(
                        (int)(7 * ~v29 + 3 * ~(v29 & v79) + 2 * (v29 & v79) - 2 * (v29 & ~v79) - 0xA * ~(v79 | v29) - 9 * ~(~v79 | v29)),
                        0x2C,
                        0x44,
                        (__int64 *)a5);
                    sub_7FFD33050180((_QWORD)(0x44), v105, v99, 0x10);

                    __int64 v106 = v105 + 0x80;
                    *v49 = 0x80;

                    __int64 v187 = 0xF2678B7073B1C107uLL;
                    __int64 v188 = 0;
                    __int64 v189 = 0xF2678B7073B1C108uLL;
                    __int64 v190 = v186 + v189 - v188 - v187;

                    v122 = v106;
                    v123 = v190;
                } while ( v123 != v102 );
                v124 = v122;
            }

            __int64 result = 4 * (v59 | 0xFFFFFFFFFFFFFF80uLL) - (5 * (v59 & 0x7F) + 4 * (v59 & 0x3FFFFFFFFFFFFF80LL)) - 4 * (~v59 & 0x3FFFFFFFFFFFFF80LL) - 2 * ~((unsigned __int8)v59 | 0xFFFFFF80) + 0xFE;
            if ( (uint64_t)result == 0xFFFFFFFFFFFFFF02uLL )
                return result;

            __int64 v125 = v59;
            __int64 v126 = v124;
            __int64 v127 = result;

            __int64 v83 = 0x3CD7CD57;
            __int64 v84 = 0x6758EA10;

            sub_7FFD333B4500((int)((v84 ^ 0x62A57986) - v84 - v83 - 0x61CCDC2F), 0x27, 0x36, (__int64 *)a5);
            *v49 = 0;

            STORE_OWORD_N(a5, 12, &D810_ZERO_OWORD);
            STORE_OWORD_N(a5, 11, &D810_ZERO_OWORD);
            STORE_OWORD_N(a5, 10, &D810_ZERO_OWORD);
            STORE_OWORD_N(a5, 9, &D810_ZERO_OWORD);
            STORE_OWORD_N(a5, 8, &D810_ZERO_OWORD);
            STORE_OWORD_N(a5, 7, &D810_ZERO_OWORD);
            STORE_OWORD_N(a5, 6, &D810_ZERO_OWORD);
            STORE_OWORD_N(a5, 5, &D810_ZERO_OWORD);

            v36 = v125;
            v37 = v126;
            v38 = v127;
        }
        else
        {
            v36 = v100;
            v37 = v69;
            v38 = v59;
        }
    }

    __int64 v243 = v36;
    __int64 v77 = v37;
    __int64 v63 = v38;
    __int64 v244 = 0x344436EA9527C8AELL;
    __int64 v245 = 0xA9287151E95AB0BEuLL;
    __int64 v78 = 0xCC6A6928AA358512uLL;
    __int64 v246 = 0x1294169555CA5A41LL;
    __int64 v247 = 2 * v246;
    __int64 v248 = 2 * ~(v78 & 0xA121C04AA20525AEuLL);
    __int64 v249 = v248 - (v78 ^ 0xA121C04AA20525AEuLL);

    __int64 result = 0x5644FD01B1049C4BLL;
    if ( v63 == v244 + v247 - v249 + (v245 ^ 0x604AFCF8563706BLL) - v78 + 0x5644FD01B1049C4BLL )
        return result;

    __int64 v131, v132, v133;
    if ( v243 )
    {
        if ( v243 == 0x80 )
        {
            __int64 v83 = 0x3CD7CD57;
            __int64 v84 = 0x6758EA10;
            sub_7FFD333B4500((int)((v84 ^ 0x62A57986) - v84 - v83 - 0x61CCDC2F), 0x27, 0x36, (__int64 *)a5);
            *v49 = 0;

            STORE_OWORD_N(a5, 12, &D810_ZERO_OWORD);
            STORE_OWORD_N(a5, 11, &D810_ZERO_OWORD);
            STORE_OWORD_N(a5, 10, &D810_ZERO_OWORD);
            STORE_OWORD_N(a5, 9, &D810_ZERO_OWORD);
            STORE_OWORD_N(a5, 8, &D810_ZERO_OWORD);
            STORE_OWORD_N(a5, 7, &D810_ZERO_OWORD);
            STORE_OWORD_N(a5, 6, &D810_ZERO_OWORD);
            STORE_OWORD_N(a5, 5, &D810_ZERO_OWORD);
        }
        v131 = v63;
        v132 = v63;
        v133 = v77;
    }
    else
    {
        STORE_OWORD_N(a5, 12, &D810_ZERO_OWORD);
        STORE_OWORD_N(a5, 11, &D810_ZERO_OWORD);
        STORE_OWORD_N(a5, 10, &D810_ZERO_OWORD);
        STORE_OWORD_N(a5, 9, &D810_ZERO_OWORD);
        STORE_OWORD_N(a5, 8, &D810_ZERO_OWORD);
        STORE_OWORD_N(a5, 7, &D810_ZERO_OWORD);
        STORE_OWORD_N(a5, 6, &D810_ZERO_OWORD);
        STORE_OWORD_N(a5, 5, &D810_ZERO_OWORD);
        v131 = v63;
        v132 = v63;
        v133 = v77;
    }

    __int64 v107 = v131;
    __int64 v51 = a5 + 0x50;
    sub_7FFD33050180(0x2E, v133, a5 + 0x50, v132 >> 3);

    __int64 v28 = v131 & 0x78;
    __int64 v70 = *v49;
    __int64 v194 = 0x13LL * ((unsigned int)v28 & (unsigned int)*v49) + 0xC * (v70 & ~v28) - 0xB * (~v28 | *v49) - 6 * ~(~v28 & v70) + 7 * ~(~v28 | *v49) + 0x11 * ~(v28 | v70);
    *v49 = v194;

    unsigned char *v52 = (unsigned __int8 *)(v28 + v133);
    __int64 v195 = 0xC7040DEF7B0F10C5uLL;
    __int64 v196 = 0xF89735C1B4F67C3CuLL;
    __int64 v197 = 0xCE6CD82DC6189490uLL;

    __int64 v53 = v107 & (v196 + v197 - v195);

    if ( !v53 )
        return result;

    __int64 v198 = v194 >> 3;
    __int64 v199 = *v52;
    __int64 v200 = 8 * v70;
    (void)v198; (void)v199; (void)v200;

    /* The big MBA-byte-emit chain follows; for trace purposes the side effects
     * we care about are calls. The buffer writes here mutate a5 — we keep them
     * so memory-hash comparison stays meaningful. */
    *(_QWORD *)(v51 + 8 * (v194 >> 3)) |= ((uint64_t)v199) << ((8 * v70) & 0x38);
    __int64 v109 = *v49 + 1;
    *v49 = v109;

    __int64 v203 = 0xD3A768BA35526030uLL;
    __int64 v71 = 0xF9520CA799C88D0LL;
    __int64 v204 = 0xD724EF6803290A0BuLL;
    __int64 v205 = 0x93E48C21862BDBEDuLL;
    __int64 v206 = 0xB8030AF2D411C2E1uLL;
    __int64 v9b = v205 ^ (v204 + v206);
    __int64 v10b = 0x15 * ~(v9b | ~v71);
    __int64 v11b = 0xB * ~(v9b & v71);
    result = 0x15 * (v9b & ~v71) + 9 * (v71 & v9b);

    if ( v53 == v203 + v11b + 0xB * (v71 | v205 ^ (v204 + v206)) - result - 0xB * ~(v71 | v205 ^ (v204 + v206)) - v10b )
        return result;

    __int64 v207 = v109 >> 3;
    __int64 v208 = (unsigned __int64)v52[1] << (8 * (unsigned __int8)v109);
    *(_QWORD *)(v51 + 8 * v207) |= (_QWORD)(v208);

    __int64 v72 = *v49;
    __int64 v110 = 0x13 * (v72 & 1) + 0xC * (v72 & ~1ULL) - 0xB * (~1ULL | v72) - 6 * ~(~1ULL & v72) + 7 * ~(~1ULL | v72) + 0x11 * ~(1ULL | v72);

    result = (__int64)v49;
    *v49 = v110;

    if ( v53 == 2 )
        return result;

    __int64 v211 = v110 >> 3;
    __int64 v212 = v52[2];

    __int64 *v219 = (__int64 *)(v51 + 8 * v211);
    __int64 v220 = *v219 | (v212 << ((v110 << 3) & 0x38));
    *v219 = v220;

    result = *v49 + 1;
    *v49 = result;

    if ( v53 == 3 )
        return result;

    *(_QWORD *)(v51 + (result & 0xFFFFFFFFFFFFFFF8uLL)) |= (_QWORD)((unsigned __int64)v52[3] << (8 * (unsigned __int8)result));
    __int64 v111 = *v49 + 1;
    *v49 = v111;

    if ( v53 == 4 )
        return result;

    __int64 v227 = v111 >> 3;
    __int64 v228 = v52[4];

    __int64 v237 = (v111 << 3) & 0x38;

    *(_QWORD *)(v51 + 8 * v227) |= (_QWORD)(v228 << v237);

    __int64 v47 = *v49 + 1;
    *v49 = v47;

    if ( v53 == 6 )
        return result;

    *(_QWORD *)(v51 + (v47 & 0xFFFFFFFFFFFFFFF8uLL)) |= (_QWORD)((unsigned __int64)v52[5] << ((8 * v47) & 0x38));
    __int64 v114 = *v49 + 1;
    *v49 = v114;

    if ( v53 == 6 )
        return result;

    *(_QWORD *)(v51 + (v114 & 0xFFFFFFFFFFFFFFF8uLL)) |= (_QWORD)((unsigned __int64)v52[6] << (8 * (unsigned __int8)v114));
    ++*v49;

    return (__int64)v49;
}
