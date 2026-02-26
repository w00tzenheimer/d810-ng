/**
 * Function: sub_7FFD3338C040
 * Address: 0x7ffd3338c040
 *
 * Deobfuscation applied:
 *   ChainOptimizer: 3 matches
 *   PatternOptimizer: 5 matches
 *   PeepholeOptimizer: 108 matches
 *   MBA rules: 116 simplifications
 * Compilation flags (recommended):
 *   -O0 -g -fno-inline -fno-builtin
 */



#include "polyfill.h"
#include "platform.h"

// Forward declarations
extern __int64 __fastcall sub_7FFD32FF8F30(_QWORD, _QWORD, _QWORD, _QWORD);
extern __int64 __fastcall sub_7FFD33050180(_QWORD, _QWORD, _QWORD, _QWORD);
extern __int64 *__fastcall sub_7FFD333B4500(int, __int64, __int64, __int64 *);

// Sink variable to prevent optimization
volatile int g_sub_7FFD3338C040_sink = 0;

// Function: sub_7FFD3338C040 at 0x7ffd3338c040
EXPORT D810_NOINLINE __int64 __fastcall sub_7FFD3338C040(_QWORD a1, __int64 a2, __int64 a3, __int64 a4, __int64 a5)
{
    // [COLLAPSED LOCAL DECLARATIONS. PRESS NUMPAD "+" TO EXPAND]
    __int64 v7;
    __int64 v8;
    __int64 v9;
    __int64 v10;
    __int64 v11;
    __int64 v12;
    __int64 v13;
    __int64 v14;
    __int64 v15;
    __int64 v16;
    __int64 v17;
    __int64 v18;
    __int64 v19;
    __int64 v20;
    __int64 v21;
    __int64 v22;
    __int64 v23;
    __int64 v24;
    __int64 v25;
    __int64 v26;
    __int64 v27;
    __int64 v28;
    __int64 v29;
    __int64 v30;
    __int64 v31;
    __int64 v32;
    __int64 v33;
    __int64 v34;
    __int64 v35;
    __int64 v36;
    __int64 v37;
    __int64 v38;
    __int64 v39;
    __int64 v40;
    __int64 v41;
    __int64 v42;
    __int64 v43;
    __int64 v44;
    __int64 v45;
    __int64 v46;
    __int64 v47;
    __int64 *v49;
    __int64 v50;
    __int64 v51;
    unsigned char *v52;
    __int64 v53;
    __int64 v54;
    __int64 v55;
    __int64 v56;
    __int64 v57;
    __int64 v58;
    __int64 v59;
    __int64 v60;
    __int64 v61;
    __int64 v62;
    __int64 v63;
    __int64 v64;
    __int64 *v65;
    __int64 v66;
    __int64 v67;
    __int64 v68;
    __int64 v69;
    __int64 v70;
    __int64 v71;
    __int64 v72;
    __int64 v73;
    __int64 v74;
    __int64 v75;
    __int64 v76;
    __int64 v77;
    __int64 v78;
    __int64 v79;
    __int64 v80;
    __int64 v81;
    __int64 v82;
    __int64 v83;
    __int64 v84;
    __int64 v85;
    __int64 v86;
    __int64 v87;
    __int64 v88;
    __int64 v89;
    __int64 v90;
    __int64 v91;
    __int64 v92;
    __int64 v93;
    __int64 v94;
    __int64 v95;
    __int64 v96;
    __int64 v97;
    __int64 v98;
    __int64 v99;
    __int64 v100;
    __int64 v101;
    __int64 v102;
    __int64 v103;
    __int64 v104;
    __int64 v105;
    __int64 v106;
    __int64 v107;
    __int64 v108;
    __int64 v109;
    __int64 v110;
    __int64 v111;
    __int64 v112;
    __int64 v113;
    __int64 v114;
    __int64 v115;
    __int64 v116;
    __int64 v117;
    __int64 v118;
    __int64 v119;
    __int64 v120;
    __int64 v121;
    __int64 v122;
    __int64 v123;
    __int64 v124;
    __int64 v125;
    __int64 v126;
    __int64 v127;
    __int64 v128;
    __int64 v129;
    __int64 v130;
    __int64 v131;
    __int64 v132;
    __int64 v133;
    __int64 v134;
    __int64 v135;
    __int64 v136;
    __int64 v137;
    __int64 v138;
    __int64 v139;
    __int64 v140;
    __int64 v141;
    __int64 v142;
    __int64 v143;
    __int64 v144;
    __int64 v145;
    __int64 v146;
    __int64 v147;
    __int64 v148;
    __int64 v149;
    __int64 v150;
    __int64 v151;
    __int64 v152;
    __int64 v153;
    __int64 v154;
    __int64 v155;
    __int64 v156;
    __int64 v157;
    __int64 v158;
    __int64 v159;
    __int64 v160;
    __int64 v161;
    __int64 v162;
    __int64 v163;
    __int64 v164;
    __int64 v165;
    __int64 v166;
    __int64 v167;
    __int64 v168;
    __int64 v169;
    __int64 v170;
    __int64 v171;
    __int64 v172;
    __int64 v173;
    __int64 v174;
    __int64 v175;
    __int64 v176;
    __int64 v177;
    __int64 v178;
    __int64 v179;
    __int64 v180;
    __int64 v181;
    __int64 v182;
    __int64 v183;
    __int64 v184;
    __int64 v185;
    __int64 v186;
    __int64 v187;
    __int64 v188;
    __int64 v189;
    __int64 v190;
    __int64 v191;
    __int64 v192;
    __int64 v193;
    __int64 v194;
    __int64 v195;
    __int64 v196;
    __int64 v197;
    __int64 v198;
    __int64 v199;
    __int64 v200;
    __int64 v201;
    __int64 v202;
    __int64 v203;
    __int64 v204;
    __int64 v205;
    __int64 v206;
    __int64 v207;
    __int64 v208;
    __int64 v209;
    __int64 v210;
    __int64 v211;
    __int64 v212;
    __int64 v213;
    __int64 v214;
    __int64 v215;
    __int64 v216;
    __int64 v217;
    __int64 v218;
    __int64 *v219;
    __int64 v220;
    __int64 v221;
    __int64 v222;
    __int64 v223;
    __int64 v224;
    __int64 v225;
    __int64 v226;
    __int64 v227;
    __int64 v228;
    __int64 v229;
    __int64 v230;
    __int64 v231;
    __int64 v232;
    __int64 v233;
    __int64 v234;
    __int64 v235;
    __int64 v236;
    __int64 v237;
    __int64 v238;
    __int64 v239;
    __int64 v240;
    __int64 v241;
    __int64 v242;
    __int64 v243;
    __int64 v244;
    __int64 v245;
    __int64 v246;
    __int64 v247;
    __int64 v248;
    __int64 v249;
    unsigned int i;
    __int64 result;

    for ( i = 0x5D0AEBD3; ; i = 0x3FFC21D2 )
    {
        while ( 1 )
        {
            while ( 1 )
            {
                while ( 1 )
                {
                    while ( 1 )
                    {
                        while ( 1 )
                        {
                            while ( 1 )
                            {
                                result = (unsigned int)i;
                                if ( i <= 0x37B42A3F )
                                    break;

                                if ( i > 0x606DC165 )
                                {
                                    if ( i <= 0x6B588048 )
                                    {
                                        if ( i <= 0x63D54754 )
                                        {
                                            if ( i > 0x610BB4D8 )
                                            {
                                                if ( i == 0x610BB4D9 )
                                                {
                                                    v102 = v59 >> (((v101 ^ 0x23) + 0x79)
                                                                 ^ (0x54 - (v101 + (v101 ^ 0x23)))
                                                                 ^ 0xE3u);
                                                    if ( v59 >= 0x80 )
                                                    {
                                                        v21 = 0xCD4068E9;
                                                        v22 = 0x3D766243;
                                                        v23 = 0xD778CBDF;

LABEL_x92641:
                                                        i = (v22 ^ v23) - v21;
                                                    }
                                                    else
                                                    {
                                                        i = 0x3873BC54;
                                                    }
                                                }
                                                else
                                                {
                                                    v249 = v248 - (v78 ^ 0xA121C04AA20525AEuLL);
                                                    i = 0x64AFC49D;
                                                }
                                            }

                                            else if ( i == 0x606DC166 )
                                            {
                                                v54 = *v49;
                                                v135 = 6 * ~(*v49 | 0xFFFFFFFFFFFFFFF8uLL);
                                                v136 = 0xD * ~(*v49 | 7);
                                                v137 = 0xD * (*v49 & 0xFFFFFFFFFFFFFFF8uLL)
                                                     + 8 * (*v49 & 7)
                                                     - 7 * (*v49 | 0xFFFFFFFFFFFFFFF8uLL)
                                                     - 6 * (~*v49 | 0xFFFFFFF8LL);
                                                i = 0x139F2922;
                                            }
                                            else
                                            {
                                                v31 = v238
                                                    + v239
                                                    + v240
                                                    + (v76 & 0x65F5CA3EE93E08BBLL)
                                                    + 0xB * (v76 & 0x9A0A35C116C1F744uLL)
                                                    - v242;
                                                v32 = v31 + 0x43DC1B5AE8F2871ELL;
                                                v33 = v76 + 0x6AE9D418B40DF218LL - v31;
                                                if ( v53 == ~(~v32 | v33)
                                                          + 6 * (~v32 & v33)
                                                          + 8 * (v32 & v33)
                                                          - 5 * (~v32 | v33)
                                                          - 3 * ~(v33 ^ v32)
                                                          + 8 * ~(v32 | v33) )
                                                    i = 0x4C77464F;
                                                else
                                                    i = 0x296F2452;
                                            }
                                        }

                                        else if ( i <= 0x6465D164 )
                                        {
                                            if ( i != 0x63D54755 )
                                            {
                                                v139 = 3 * ~(v66 | 0xD17DA1C86E91436DuLL);
                                                v140 = v66 | 0x2E825E37916EBC92LL;
                                                v7 = 0x5F373C53;
                                                v8 = 0x5FF7F9CC;
                                                goto LABEL_x927BA;
                                            }

                                            v180 = v176 + v177 + v178 + v179;
                                            v181 = v173 - v174 + 0x16;
                                            i = 0x57BE6FD0;
                                        }
                                        else
                                        {
                                            if ( i == 0x6465D165 )
                                            {
                                                sub_7FFD333B4500(
                                                    (v84 ^ 0x62A57986) - v84 - v83 - 0x61CCDC2F,
                                                    0x27,
                                                    0x36,
                                                    (__int64 *)a5);
                                                *v49 = 0;
                                                v128 = v191;
                                                v129 = v193;
                                                v130 = v192;

LABEL_x8F290:
                                                STORE_OWORD_N(a5, 12, &D810_ZERO_OWORD);
                                                STORE_OWORD_N(a5, 11, &D810_ZERO_OWORD);
                                                STORE_OWORD_N(a5, 10, &D810_ZERO_OWORD);
                                                STORE_OWORD_N(a5, 9, &D810_ZERO_OWORD);
                                                STORE_OWORD_N(a5, 8, &D810_ZERO_OWORD);
                                                STORE_OWORD_N(a5, 7, &D810_ZERO_OWORD);
                                                STORE_OWORD_N(a5, 6, &D810_ZERO_OWORD);
                                                STORE_OWORD_N(a5, 5, &D810_ZERO_OWORD);
                                                v131 = v128;
                                                v132 = v129;
                                                v133 = v130;
                                                goto LABEL_x8F34A;
                                            }

                                            if ( i == 0x64AFC49D )
                                            {
                                                result = 0x5644FD01B1049C4BLL;
                                                if ( v63 == v244
                                                          + v247
                                                          - v249
                                                          + (v245 ^ 0x604AFCF8563706BLL)
                                                          - v78
                                                          + 0x5644FD01B1049C4BLL )
                                                    return result;

                                                if ( v243 )
                                                {
                                                    if ( v243 == 0x80 )
                                                    {
                                                        v125 = v63;
                                                        v126 = v77;
                                                        v127 = v63;
                                                        i = 0x258ED455;
                                                    }
                                                    else
                                                    {
                                                        v131 = v63;
                                                        v132 = v63;
                                                        v133 = v77;

LABEL_x8F34A:
                                                        v107 = v131;
                                                        v51 = a5 + 0x50;
                                                        sub_7FFD33050180(
                                                            0x2E,
                                                            v133,
                                                            a5 + 0x50,
                                                            v132 >> 3);
                                                        v28 = v131 & 0x78;
                                                        v70 = *v49;
                                                        v194 = 0x13LL
                                                             * ((unsigned int)v28
                                                              & (unsigned int)*v49)
                                                             + 0xC * (v70 & ~v28)
                                                             - 0xB * (~v28 | *v49)
                                                             - 6 * ~(~v28 & v70)
                                                             + 7 * ~(~v28 | *v49)
                                                             + 0x11 * ~(v28 | v70);
                                                        *v49 = v194;
                                                        v52 = (unsigned __int8 *)(v28 + v133);
                                                        v195 = 0xC7040DEF7B0F10C5uLL;
                                                        v196 = 0xF89735C1B4F67C3CuLL;
                                                        v197 = 0xCE6CD82DC6189490uLL;
                                                        i = 0x432DC789;
                                                    }
                                                }
                                                else
                                                {
                                                    v128 = v63;
                                                    v129 = v63;
                                                    v130 = v77;
                                                    i = 0x27EEEA11;
                                                }
                                            }
                                            else
                                            {
LABEL_x92004:
                                                v16 = *v49;

LABEL_x9200C:
                                                v158 = v16;
                                                i = 0x7FDCE054;
                                            }
                                        }
                                    }

                                    else if ( i <= 0x737189D4 )
                                    {
                                        if ( i > 0x6E958F99 )
                                        {
                                            if ( i == 0x71E22BF3 )
                                            {
                                                v219 = (__int64 *)(v51 + 8 * v211);
                                                v220 = *v219 | (v212 << ((v110 << v218) & 0x38));
                                                i = 0x11CD1DA3;
                                            }
                                            else
                                            {
                                                if ( i != 0x72AFE1BC )
                                                    return result;

                                                v217 = v216
                                                     + 8 * (v61 & ~v60)
                                                     - 2 * (v60 & v61)
                                                     - 7 * (v60 ^ v61)
                                                     - v215;
                                                i = 0x737189D5;
                                            }
                                        }

                                        else if ( i == 0x6B588049 )
                                        {
                                            v148 = 3 * ~(v58 | v147);
                                            v149 = ~(v58 & ~v56)
                                                 - (2 * (v58 & ~v56)
                                                  + 2 * (v56 & v58))
                                                 - 4 * ~(v56 | v58)
                                                 - 3;
                                            v13 = 0x96ED9A7B;
                                            v14 = 0x9E964E76;

LABEL_x8F797:
                                            i = v14 - v13;
                                        }
                                        else
                                        {
                                            if ( i != 0x6D207773 )
                                                return result;

                                            v90 = (v50 | 0xD03BDDDE)
                                                + (v50 & 0x2FC42221)
                                                - 0xB * (v50 & 0xD03BDDDE)
                                                - 0xB * ~v89
                                                + v88
                                                - 0xD6D7775;
                                            v91 = v86 ^ 0x6740654F;
                                            i = 0xB2FECE0;
                                        }
                                    }

                                    else if ( i <= 0x7C2C021F )
                                    {
                                        if ( i == 0x737189D5 )
                                        {
                                            v218 = v214 + v217 - v213;
                                            v15 = 0x71E22BF3;
                                            goto LABEL_x90BB4;
                                        }

                                        v167 = v165 + 2 * (unsigned int)(v55 & 0x7F) - v166 - v164;
                                        i = 0x5FE86821;
                                    }

                                    else if ( i == 0x7C2C0220 )
                                    {
                                        v237 = v233 & (v234 + v236 - v235);
                                        i = 0x385BBE2D;
                                    }

                                    else if ( i == 0x7D9C16EC )
                                    {
                                        v211 = v110 >> 3;
                                        v212 = v52[2];
                                        v213 = 0x25;
                                        v60 = 0xE;
                                        v61 = 0x1A;
                                        v214 = 0x20;
                                        v215 = 0x84;
                                        v216 = 0xAC;
                                        i = 0x72AFE1BC;
                                    }
                                    else
                                    {
                                        v159 = v57 + v158;
                                        *v49 = v57 + v158;
                                        v160 = a3 + v57;
                                        i = 0x307BF0E5;
                                    }
                                }

                                else if ( i > 0x432DC788 )
                                {
                                    if ( i <= 0x57BE6FCF )
                                    {
                                        if ( i <= 0x474EEEBA )
                                        {
                                            if ( i == 0x432DC789 )
                                            {
                                                v53 = v107 & (v196 + v197 - v195);
                                                i = 0x298372CC;
                                            }
                                            else
                                            {
                                                v36 = v55;
                                                v37 = v67;
                                                v38 = v68;

LABEL_x91A2D:
                                                v243 = v36;
                                                v77 = v37;
                                                v63 = v38;
                                                v244 = 0x344436EA9527C8AELL;
                                                v245 = 0xA9287151E95AB0BEuLL;
                                                v78 = 0xCC6A6928AA358512uLL;
                                                v246 = 0x1294169555CA5A41LL;
                                                i = 0x5A21D9DB;
                                            }
                                        }

                                        else if ( i == 0x474EEEBB )
                                        {
                                            v46 = v145
                                                | (v146 << (v150 << (v153
                                                                   ^ (unsigned __int8)(((v154 + v155 - 2) ^ v151 ^ (v155 + v154 - 0x33) ^ (v152 - 0x62)) - v94))));
                                            *v65 = v46;
                                            v95 = v46
                                                | ((unsigned __int64)*(unsigned __int8 *)(a3 + v58 + 1) << (8 * ((unsigned __int8)v56 + ((unsigned __int8)v58 | 1u))));
                                            *v65 = v95;
                                            v96 = v58 + 2;
                                            if ( v58 + 2 == v144 )
                                            {
                                                i = 0x32FCD904;
                                            }
                                            else
                                            {
                                                v7 = 0xD5AE3D17;
                                                v8 = 0xC702C637;

LABEL_x927BA:
                                                i = v7 ^ v8;
                                            }
                                        }
                                        else
                                        {
                                            if ( i != 0x4E69F350 )
                                                return result;

                                            v227 = v111 >> (((unsigned __int8)(v225
                                                                             + v226
                                                                             - (2 * (v112 & 0x22)
                                                                              + 2 * (v112 & 0xDD))
                                                                             - v224
                                                                             - v223)
                                                           ^ (unsigned __int8)(v221 + (v222 ^ 0x9A)))
                                                          - v112);
                                            v228 = v52[4];
                                            v73 = 0x1A;
                                            v113 = 0xA0;
                                            v62 = 0x88;
                                            v229 = 0x9C;
                                            v230 = 0xC;
                                            v231 = 0x7F;
                                            i = 0x2A5ADB57;
                                        }
                                    }

                                    else if ( i <= 0x5D0AEBD2 )
                                    {
                                        if ( i == 0x57BE6FD0 )
                                        {
                                            v99 = a5 + 0x50;
                                            sub_7FFD33050180(
                                                0x55,
                                                v67,
                                                a5 + (v55 & 0xFFFFFFFFFFFFFFF8uLL) + 0x50,
                                                v98 >> (v180 ^ (unsigned __int8)(v175 + v181)));
                                            v19 = v98 & 0x38;
                                            v100 = v19 + *v49;
                                            *v49 = v100;
                                            v69 = v19 + v67;
                                            v59 = v68 - v19;
                                            v101 = 0xD7;
                                            i = 0x3E42B03;
                                        }
                                        else
                                        {
                                            v247 = 2 * v246;
                                            v248 = 2 * ~(v78 & 0xA121C04AA20525AEuLL);
                                            i = 0x63B2C08B;
                                        }
                                    }

                                    else if ( i == 0x5D0AEBD3 )
                                    {
                                        v49 = (__int64 *)(a5 + 0xD0);
                                        i = 0x606DC166;
                                    }
                                    else
                                    {
                                        if ( i != 0x5FE86821 )
                                        {
                                            v72 = *v49;
                                            v209 = 0xB493FD3C199D9EBAuLL;
                                            v210 = 0xB493FD3C199D9EBBuLL;
                                            v34 = 0xE6334342;
                                            v35 = 0x1C6BAB0E;
                                            goto LABEL_x929BB;
                                        }

                                        if ( v163 + v167 == v161 )
                                        {
                                            i = 0x45B18E82;
                                        }
                                        else
                                        {
                                            v168 = 0x91FA460CD2D32E41uLL;
                                            v169 = 0x37F13911D652CC78LL;
                                            v170 = 0xADC4CF83D2CF56F0uLL;
                                            v97 = 0xF035F04C254451F3uLL;
                                            i = 0x2760C0D;
                                        }
                                    }
                                }

                                else if ( i > 0x3FFC21D1 )
                                {
                                    if ( i <= 0x41FB8FBA )
                                    {
                                        if ( i == 0x3FFC21D2 )
                                        {
                                            v183 = v103 + 0x2FA79C4916F275A9LL;
                                            v184 = v103 - 0x1A57180B6086323DLL;
                                            v185 = v103 + 0x238DAEF738FB5AD7LL;
                                            i = 0x393685BA;
                                        }
                                        else
                                        {
                                            v163 = ~v162;
                                            v164 = v55 | 0xFFFFFFFFFFFFFF80uLL;
                                            v165 = 7 * (v55 ^ 0x7F);
                                            i = 0x2512824;
                                        }
                                    }

                                    else if ( i == 0x41FB8FBB )
                                    {
                                        v87 = ~v50;
                                        i = 0x1864829A;
                                    }
                                    else
                                    {
                                        if ( i != 0x42267E66 )
                                        {
                                            *v65 = v156
                                                 | ((unsigned __int64)*(unsigned __int8 *)(a3 + v157) << (8 * ((unsigned __int8)v56 + (unsigned __int8)v157)));
                                            goto LABEL_x92004;
                                        }

                                        v9 = v205 ^ (v204 + v206);
                                        v10 = 0x15 * ~(v9 | ~v71);
                                        v11 = 0xB * ~(v9 & v71);
                                        result = 0x15 * (v9 & ~v71) + 9 * (v71 & v9);
                                        if ( v53 == v203
                                                  + v11
                                                  + 0xB * (v71 | v205 ^ (v204 + v206))
                                                  - result
                                                  - 0xB * ~(v71 | v205 ^ (v204 + v206))
                                                  - v10 )
                                            return result;

                                        v207 = v109 >> 3;
                                        i = 0x24E2E77A;
                                    }
                                }

                                else if ( i <= 0x3873BC53 )
                                {
                                    if ( i == 0x37B42A40 )
                                    {
                                        v24 = sub_7FFD32FF8F30(
                                                  v55,
                                                  0x5D,
                                                  0x18,
                                                  v97
                                                + (v170 ^ (v172 - v169 - v171 + 0x3D15731BE3B5F7DFLL))
                                                - v168);
                                        v25 = v68;
                                        if ( v24 < v68 )
                                            v25 = v24;

                                        v98 = v25;
                                        v173 = 0x86;
                                        v174 = 0x59;
                                        v175 = 0x52;
                                        v176 = 0xD3;
                                        v177 = 0x22;
                                        v178 = 0x8A;
                                        v179 = 0x17;
                                        i = 0x63D54755;
                                    }
                                    else
                                    {
                                        *(_QWORD *)(v51 + 8 * v227) |= (_QWORD)(v228 << v237);
                                        v47 = *v49 + 1;
                                        *v49 = v47;
                                        if ( v53 == 5 )
                                        {
                                            v7 = 0x45BA4824;
                                            v8 = 0x2910DD05;
                                            goto LABEL_x927BA;
                                        }

                                        *(_QWORD *)(v51 + (v47 & 0xFFFFFFFFFFFFFFF8uLL)) |= (_QWORD)((unsigned __int64)v52[5] << ((8 * v47) & 0x38));
                                        v114 = *v49 + 1;
                                        *v49 = v114;
                                        v76 = 0x5B22243FF89F5980LL;
                                        v238 = 0xA4DDDBC00760A67FuLL;
                                        v239 = 0x80489FC03845D864uLL;
                                        v240 = 0x7059E4000B40024ELL;
                                        v241 = 0xBEDFFFC117E1F77FuLL;
                                        v34 = 0x95C81062;
                                        v35 = 0x7AAC2BEA;

LABEL_x929BB:
                                        i = v35 + v34;
                                    }
                                }
                                else
                                {
                                    if ( i == 0x3873BC54 )
                                    {
                                        v36 = v100;
                                        v37 = v69;
                                        v38 = v59;
                                        goto LABEL_x91A2D;
                                    }

                                    if ( i == 0x393685BA )
                                    {
                                        if ( v100 == (v103 ^ (v184 + v183 + v185)) - v182 )
                                        {
                                            v85 = 0xB2AD891A;
                                            v86 = 0x7A0A9ACD;
                                            v50 = 0xE03CAABA;
                                            i = 0x34D0F5D6;
                                        }
                                        else
                                        {
                                            i = 0x149AED27;
                                        }
                                    }
                                    else
                                    {
                                        *(_QWORD *)(v51 + 8 * v207) |= (_QWORD)(v208);
                                        i = 0x604AAEA6;
                                    }
                                }
                            }

                            if ( i > 0x1A9A9DD8 )
                                break;

                            if ( i <= 0xD64F20E )
                            {
                                if ( i <= 0x3E42B02 )
                                {
                                    if ( i > 0x2760C0C )
                                    {
                                        if ( i == 0x2760C0D )
                                        {
                                            v171 = v97 + 0x7552BC11D833A13ALL;
                                            v172 = (v97 + 0x7552BC11D833A13ALL)
                                                 ^ 0x9EDA0CA9221A129LL;
                                            i = 0x37B42A40;
                                        }
                                        else
                                        {
                                            v110 = 0x13 * (v72 & (v210 - v209))
                                                 + 0xC * (v72 & ~(v210 - v209))
                                                 - 0xB * (~(v210 - v209) | v72)
                                                 - 6 * ~(~(v210 - v209) & v72)
                                                 + 7 * ~(~(v210 - v209) | v72)
                                                 + 0x11 * ~((v210 - v209) | v72);
                                            result = (__int64)v49;
                                            *v49 = v110;
                                            if ( v53 == 2 )
                                                return result;

                                            i = 0x7D9C16EC;
                                        }
                                    }
                                    else
                                    {
                                        if ( i == 0xC0C59F )
                                        {
                                            v93 = v139
                                                + 5 * ~v140
                                                + 8 * (v66 & 0xD17DA1C86E91436DuLL)
                                                - 2 * (v66 ^ 0x2E825E37916EBC92LL)
                                                - 0x177428EA28D65121LL;
                                            v13 = 0x4A2BE3B8;
                                            v14 = 0x79E629C9;
                                            goto LABEL_x8F797;
                                        }

                                        v166 = 6 * (v55 & 0x7FFFFFFFFFFFFF80LL);
                                        i = 0x79F598F7;
                                    }
                                }

                                else if ( i <= 0x9EB3381 )
                                {
                                    if ( i == 0x3E42B03 )
                                    {
                                        v26 = 0x3101B616;
                                        v27 = 0x500A02CF;
                                        goto LABEL_x91116;
                                    }

                                    v150 = v149 - v148;
                                    v151 = 0x30;
                                    v152 = 0xB7;
                                    v153 = 0xFA;
                                    v94 = 0x5D;
                                    v154 = 0x54;
                                    v155 = 0x24;
                                    i = 0x474EEEBB;
                                }
                                else
                                {
                                    if ( i != 0x9EB3382 )
                                    {
                                        if ( i != 0xACD0BD5 )
                                        {
                                            sub_7FFD333B4500(
                                                v90 + v85 + v91,
                                                0x11,
                                                0x4A,
                                                (__int64 *)a5);
                                            goto LABEL_x8E4A1;
                                        }

                                        goto LABEL_x8F934;
                                    }

                                    v39 = 2
                                        * ~((8
                                           * ((v201
                                             + (v108 ^ 0xBF)
                                             + 6 * (v108 & 0x40)
                                             + 6 * (v108 & 0xBF)
                                             - v202)
                                            & 0x2A)
                                           - 2
                                           * ((v201
                                             + (v108 ^ 0xBF)
                                             + 6 * (v108 & 0x40)
                                             + 6 * (v108 & 0xBF)
                                             - v202)
                                            & 0xD5)
                                           - 7
                                           * ((v201
                                             + (v108 ^ 0xBF)
                                             + 6 * (v108 & 0x40)
                                             + 6 * (v108 & 0xBF)
                                             - v202)
                                            ^ 0xD5)
                                           + 4
                                           * ((v201
                                             + (v108 ^ 0xBF)
                                             + 6 * (v108 & 0x40)
                                             + 6 * (v108 & 0xBF)
                                             - v202)
                                            ^ 0x2A)
                                           - 4
                                           * ~((v201
                                              + (v108 ^ 0xBF)
                                              + 6 * (v108 & 0x40)
                                              + 6 * (v108 & 0xBF)
                                              - v202)
                                             | 0xD5)
                                           + 8
                                           * ~((v201
                                              + (v108 ^ 0xBF)
                                              + 6 * (v108 & 0x40)
                                              + 6 * (v108 & 0xBF)
                                              - v202)
                                             | 0x2A))
                                          | 0x80);
                                    v40 = 2
                                        * ~((8
                                           * ((v201
                                             + (v108 ^ 0xBF)
                                             + 6 * (v108 & 0x40)
                                             + 6 * (v108 & 0xBF)
                                             - v202)
                                            & 0x2A)
                                           - 2
                                           * ((v201
                                             + (v108 ^ 0xBF)
                                             + 6 * (v108 & 0x40)
                                             + 6 * (v108 & 0xBF)
                                             - v202)
                                            & 0xD5)
                                           - 7
                                           * ((v201
                                             + (v108 ^ 0xBF)
                                             + 6 * (v108 & 0x40)
                                             + 6 * (v108 & 0xBF)
                                             - v202)
                                            ^ 0xD5)
                                           + 4
                                           * ((v201
                                             + (v108 ^ 0xBF)
                                             + 6 * (v108 & 0x40)
                                             + 6 * (v108 & 0xBF)
                                             - v202)
                                            ^ 0x2A)
                                           - 4
                                           * ~((v201
                                              + (v108 ^ 0xBF)
                                              + 6 * (v108 & 0x40)
                                              + 6 * (v108 & 0xBF)
                                              - v202)
                                             | 0xD5)
                                           + 8
                                           * ~((v201
                                              + (v108 ^ 0xBF)
                                              + 6 * (v108 & 0x40)
                                              + 6 * (v108 & 0xBF)
                                              - v202)
                                             | 0x2A))
                                          & 0x80);
                                    v41 = v40
                                        - ((8
                                          * ((v201
                                            + (v108 ^ 0xBF)
                                            + 6 * (v108 & 0x40)
                                            + 6 * (v108 & 0xBF)
                                            - v202)
                                           & 0x2A)
                                          - 2
                                          * ((v201
                                            + (v108 ^ 0xBF)
                                            + 6 * (v108 & 0x40)
                                            + 6 * (v108 & 0xBF)
                                            - v202)
                                           & 0xD5)
                                          - 7
                                          * ((v201
                                            + (v108 ^ 0xBF)
                                            + 6 * (v108 & 0x40)
                                            + 6 * (v108 & 0xBF)
                                            - v202)
                                           ^ 0xD5)
                                          + 4
                                          * ((v201
                                            + (v108 ^ 0xBF)
                                            + 6 * (v108 & 0x40)
                                            + 6 * (v108 & 0xBF)
                                            - v202)
                                           ^ 0x2A)
                                          - 4
                                          * ~((v201
                                             + (v108 ^ 0xBF)
                                             + 6 * (v108 & 0x40)
                                             + 6 * (v108 & 0xBF)
                                             - v202)
                                            | 0xD5)
                                          + 8
                                          * ~((v201
                                             + (v108 ^ 0xBF)
                                             + 6 * (v108 & 0x40)
                                             + 6 * (v108 & 0xBF)
                                             - v202)
                                            | 0x2A))
                                         ^ 0x80)
                                        - v39;
                                    v134 = ~v41;
                                    v42 = ((~v41 & 0xD2)
                                         + (v41 & 0x2D)
                                         + 2 * ~(v41 | 0xD2)
                                         - 2 * ~v41)
                                        ^ 0x39;
                                    v43 = (((~v41 & 0xD2)
                                          + (v41 & 0x2D)
                                          + 2 * ~(v41 | 0xD2)
                                          - 2 * v134)
                                         ^ 0x39
                                         | 0xC8)
                                        + 3 * v42
                                        + 4
                                        * (((~v41 & 0xD2)
                                          + (v41 & 0x2D)
                                          + 2 * ~(v41 | 0xD2)
                                          - 2 * v134)
                                         & 0xC8
                                         ^ 8)
                                        - 3
                                        * ((((~v41 & 0xD2)
                                           + (v41 & 0x2D)
                                           + 2 * ~(v41 | 0xD2)
                                           - 2 * v134)
                                          ^ 0x39)
                                         & 0x37)
                                        + 6
                                        * ~(((~v41 & 0xD2)
                                           + (v41 & 0x2D)
                                           + 2 * ~(v41 | 0xD2)
                                           - 2 * v134)
                                          ^ 0x39
                                          | 0x37)
                                        + 0x4A;
                                    v44 = ((((~v41 & 0xD2)
                                           + (v41 & 0x2D)
                                           + 2 * ~(v41 | 0xD2)
                                           - 2 * v134)
                                          ^ 0x39
                                          | 0xC8)
                                         + 3 * v42
                                         + 4
                                         * (((~v41 & 0xD2)
                                           + (v41 & 0x2D)
                                           + 2 * ~(v41 | 0xD2)
                                           - 2 * v134)
                                          & 0xC8
                                          ^ 8)
                                         - 3
                                         * ((((~v41 & 0xD2)
                                            + (v41 & 0x2D)
                                            + 2 * ~(v41 | 0xD2)
                                            - 2 * v134)
                                           ^ 0x39)
                                          & 0x37)
                                         + 6
                                         * ~(((~v41 & 0xD2)
                                            + (v41 & 0x2D)
                                            + 2 * ~(v41 | 0xD2)
                                            - 2 * v134)
                                           ^ 0x39
                                           | 0x37)
                                         + 0x51)
                                        ^ 0x8D;
                                    v45 = (~v41 & 0xD2)
                                        + (v41 & 0x2D)
                                        + 2 * ~(v41 | 0xD2)
                                        - 2 * ~v41
                                        + 0xB * ~(v44 & v43)
                                        + 0xB * (v43 | v44)
                                        - (0x15 * (v44 & ~v43)
                                         + 9 * (v44 & v43))
                                        - 0xB * ~(v43 | v44)
                                        - 0x15 * ~(~v43 | v44)
                                        - (v201
                                         + (v108 ^ 0xBF)
                                         + 6 * (v108 & 0x40)
                                         + 6 * (v108 & 0xBF)
                                         - v202)
                                        - v42
                                        - v108;
                                    *(_QWORD *)(v51 + 8 * v198) |= v199 << (v200
                                                                          & (unsigned __int8)(8 * ~v45 + v45 + 1 + 3 * ~(v45 & v41) + 2 * (v45 & v41) - 2 * (~v41 & v45) - 0xA * ~(v41 | v45) - 9 * ~(~v41 | v45)));
                                    v109 = *v49 + 1;
                                    *v49 = v109;
                                    v203 = 0xD3A768BA35526030uLL;
                                    v71 = 0xF9520CA799C88D0LL;
                                    v204 = 0xD724EF6803290A0BuLL;
                                    v205 = 0x93E48C21862BDBEDuLL;
                                    v206 = 0xB8030AF2D411C2E1uLL;
                                    i = 0x42267E66;
                                }
                            }

                            else if ( i > 0x139F2921 )
                            {
                                if ( i <= 0x149F5A97 )
                                {
                                    if ( i == 0x139F2922 )
                                    {
                                        v56 = v135 + v136 + v137;
                                        if ( v56 )
                                        {
                                            v20 = sub_7FFD32FF8F30((_QWORD)(v54), 0x4D, 0x57, 8);
                                            v64 = v20;
                                            if ( v20 >= 0x20 )
                                                v20 = 0x20;

                                            v57 = v20;
                                            if ( v64 )
                                            {
                                                v65 = (unsigned __int64 *)(a5
                                                                         + (v54
                                                                          & 0xFFFFFFFFFFFFFFF8uLL)
                                                                         + 0x50);
                                                v92 = *v65;
                                                v138 = 0x6FE2B37214B84CE1LL;
                                                v66 = 0xF5872016D7FAC063uLL;
                                                i = 0x63F502FA;
                                            }
                                            else
                                            {
                                                i = 0x2315233C;
                                            }
                                        }
                                        else
                                        {
                                            i = 0x16F7FF74;
                                        }
                                    }
                                    else
                                    {
LABEL_x8E4A1:
                                        sub_7FFD33050180((_QWORD)(0x62), v69, v99, 0x10);
                                        v104 = v69 + 0x80;
                                        *v49 = 0x80;
                                        if ( v102 == 1 )
                                        {
                                            v21 = 0xDC240D83;
                                            v22 = 0x71D1654B;
                                            v23 = 0x77535232;
                                            goto LABEL_x92641;
                                        }

                                        i = 0x1031EAF4;
                                    }
                                }

                                else if ( i == 0x149F5A98 )
                                {
                                    v190 = v186 + v189 - v188 - v187;
                                    if ( v190 == v102 )
                                    {
                                        v124 = v106;
                                        i = 0xACD0BD5;
                                    }
                                    else
                                    {
                                        i = 0x2981423A;
                                    }
                                }
                                else
                                {
                                    if ( i == 0x16F7FF74 )
                                    {
                                        v119 = v54;
                                        v120 = a3;
                                        v121 = 0x20;
                                        goto LABEL_x8F153;
                                    }

                                    v88 = v87;
                                    v89 = v50 | 0x2FC42221;
                                    i = 0x6D207773;
                                }
                            }

                            else if ( i <= 0x10743C4B )
                            {
                                if ( i != 0xD64F20F )
                                {
                                    v122 = v104;
                                    v123 = 1;
                                }

                                v186 = v123;
                                v105 = v122;
                                v79 = 0xB140360B;
                                v80 = 0x4A00E104;
                                v81 = 0xA5627292;
                                v82 = 0x3E231D8B;
                                i = 0x2F3C0CA1;
                            }

                            else if ( i == 0x10743C4C )
                            {
                                v242 = 0xB * v241;
                                i = 0x6107F8EC;
                            }
                            else
                            {
                                if ( i != 0x11CD1DA3 )
                                {
                                    v115 = v95;
                                    v116 = v96;
                                    goto LABEL_x926BC;
                                }

                                *v219 = v220;
                                result = *v49 + 1;
                                *v49 = result;
                                if ( v53 == 3 )
                                    return result;

                                *(_QWORD *)(v51 + (result & 0xFFFFFFFFFFFFFFF8uLL)) |= (_QWORD)((unsigned __int64)v52[3] << (8 * (unsigned __int8)result));
                                v111 = *v49 + 1;
                                *v49 = v111;
                                if ( v53 == 4 )
                                {
                                    v7 = 0xFCE60313;
                                    v8 = 0x92738C89;
                                    goto LABEL_x927BA;
                                }

                                v221 = 0x87;
                                v222 = 0x79;
                                v112 = 0x45;
                                v223 = 0xC8;
                                v224 = 0x88;
                                v225 = 0xFF;
                                v226 = 0xFD;
                                i = 0x4E69F350;
                            }
                        }

                        if ( i <= 0x2A5ADB56 )
                            break;

                        if ( i <= 0x2FBA4610 )
                        {
                            if ( i > 0x2E6C61F2 )
                            {
                                if ( i == 0x2E6C61F3 )
                                {
                                    i = 0x652D7A98;
                                }
                                else
                                {
                                    v29 = v82 - v81 - v80;
                                    sub_7FFD333B4500(
                                        7 * ~v29
                                      + 3 * ~(v29 & v79)
                                      + 2 * (v29 & v79)
                                      - 2 * (v29 & ~v79)
                                      - 0xA * ~(v79 | v29)
                                      - 9 * ~(~v79 | v29),
                                        0x2C,
                                        0x44,
                                        (__int64 *)a5);
                                    sub_7FFD33050180((_QWORD)(0x44), v105, v99, 0x10);
                                    v106 = v105 + 0x80;
                                    *v49 = 0x80;
                                    v187 = 0xF2678B7073B1C107uLL;
                                    v188 = 0;
                                    v189 = 0xF2678B7073B1C108uLL;
                                    i = 0x149F5A98;
                                }
                            }
                            else
                            {
                                if ( i != 0x2A5ADB57 )
                                {
                                    v124 = v104;

LABEL_x8F934:
                                    result = 4 * (v59 | 0xFFFFFFFFFFFFFF80uLL)
                                           - (5 * (v59 & 0x7F)
                                            + 4 * (v59 & 0x3FFFFFFFFFFFFF80LL))
                                           - 4 * (~v59 & 0x3FFFFFFFFFFFFF80LL)
                                           - 2 * ~((unsigned __int8)v59 | 0xFFFFFF80)
                                           + 0xFE;
                                    if ( 4 * (v59 | 0xFFFFFFFFFFFFFF80uLL)
                                       - (5 * (v59 & 0x7F)
                                        + 4 * (v59 & 0x3FFFFFFFFFFFFF80LL))
                                       - 4 * (~v59 & 0x3FFFFFFFFFFFFF80LL)
                                       - 2 * ~((unsigned __int8)v59 | 0xFFFFFF80) == 0xFFFFFFFFFFFFFF02uLL )
                                        return result;

                                    v125 = v59;
                                    v126 = v124;
                                    v127 = 4 * (v59 | 0xFFFFFFFFFFFFFF80uLL)
                                         - (5 * (v59 & 0x7F)
                                          + 4 * (v59 & 0x3FFFFFFFFFFFFF80LL))
                                         - 4 * (~v59 & 0x3FFFFFFFFFFFFF80LL)
                                         - 2 * ~((unsigned __int8)v59 | 0xFFFFFF80)
                                         + 0xFE;
                                    goto LABEL_x8FA2D;
                                }

                                v12 = v231 - (2 * (v62 & 0xC3) + 2 * (v62 & 0x3C)) - v230 - v229;
                                v232 = v12 - 0x19;
                                v74 = v12 + 0x41;
                                v75 = v62 + v73 + ((v12 - 0x4B) ^ 0xF);
                                i = 0x1AB9946F;
                            }
                        }

                        else if ( i <= 0x307BF0E4 )
                        {
                            if ( i == 0x2FBA4611 )
                            {
                                v141 = v93 ^ 0x4520678B9CC77B2FLL;
                                v142 = (v66
                                      ^ ((v93 ^ 0x38B49E60BFFE681LL)
                                       - v138
                                       + (v93 ^ 0x38B49E60BFFE681LL)
                                       + 0x4B73FBBE70FE5CB4LL))
                                     - v93;
                                v17 = 0x9A319577;
                                v18 = 0xAA61F61C;
                                goto LABEL_x8ECD1;
                            }

                            v143 = v57 & (v141 ^ v142);
                            if ( v64 == 1 )
                            {
                                v117 = v92;
                                v118 = 0;
                                goto LABEL_x9105A;
                            }

                            v144 = v57 & 0x3E;
                            v115 = v92;
                            v116 = 0;

LABEL_x926BC:
                            v58 = v116;
                            v145 = v115;
                            v146 = *(unsigned __int8 *)(a3 + v116);
                            v147 = ~v56;
                            i = 0x6B588049;
                        }

                        else if ( i == 0x307BF0E5 )
                        {
                            v119 = v159;
                            v120 = v160;
                            v121 = 0x20 - v57;

LABEL_x8F153:
                            v68 = v121;
                            v67 = v120;
                            v55 = v119;
                            v161 = 7LL * (~(_BYTE)v119 & 0x7F);
                            v162 = v119 | 0x7F;
                            i = 0x41B585C8;
                        }

                        else if ( i == 0x32FCD904 )
                        {
                            v117 = v95;
                            v118 = v96;

LABEL_x9105A:
                            v157 = v118;
                            v156 = v117;
                            if ( v143 )
                            {
                                v26 = 0xEA67984D;
                                v27 = 0xA805A51A;

LABEL_x91116:
                                i = v26 ^ v27;
                            }
                            else
                            {
                                i = 0x2E6C61F3;
                            }
                        }
                        else
                        {
                            v15 = 0x41FB8FBB;

LABEL_x90BB4:
                            i = v15;
                        }
                    }

                    if ( i <= 0x258ED454 )
                        break;

                    if ( i <= 0x296F2451 )
                    {
                        if ( i != 0x258ED455 )
                            goto LABEL_x8F290;

LABEL_x8FA2D:
                        v193 = v127;
                        v192 = v126;
                        v191 = v125;
                        v83 = 0x3CD7CD57;
                        v84 = 0x6758EA10;
                        i = 0x6465D165;
                    }

                    else if ( i == 0x296F2452 )
                    {
                        v17 = 0xAD1FB9EC;
                        v18 = 0xB7852435;

LABEL_x8ECD1:
                        i = v17 ^ v18;
                    }

                    else if ( i == 0x2981423A )
                    {
                        v122 = v106;
                        v123 = v190;
                        i = 0xD64F20F;
                    }
                    else
                    {
                        if ( !v53 )
                            return result;

                        v198 = v194 >> 3;
                        v199 = *v52;
                        v200 = 8 * v70;
                        v108 = 0xEE;
                        v201 = 0;
                        v202 = 0x94;
                        i = 0x9EB3382;
                    }
                }

                if ( i <= 0x2315233B )
                    break;

                if ( i == 0x2315233C )
                {
                    v16 = v54;
                    goto LABEL_x9200C;
                }

                v208 = (unsigned __int64)v52[1] << (8 * (unsigned __int8)v109);
                i = 0x3E7EA8B8;
            }

            if ( i != 0x1AB9946F )
                break;

            v30 = 2 * (v113 & v75)
                - 6 * (v75 & ~v113)
                + 3 * ~(v113 | v75)
                + 7 * (v113 ^ v75)
                - 3 * ~(v75 | ~v113)
                - 3 * ~v75;
            v233 = v111 << (v232
                          ^ (unsigned __int8)((v30 | ~v74)
                                            + 3 * v30
                                            + 4 * (v30 & ~v74)
                                            - 3 * (v74 & v30)
                                            + 6 * ~(v30 | v74)
                                            - 6 * ~v74
                                            + 1));
            v234 = 0xBE;
            v235 = 0xE4;
            v236 = 0x5E;
            i = 0x7C2C0220;
        }

        if ( i != 0x1CCE40B3 )
            break;

        v182 = 0x9A2F7F3952A0EA97uLL;
        v103 = 0x989C93011F7C5B59uLL;
    }

    *(_QWORD *)(v51 + (v114 & 0xFFFFFFFFFFFFFFF8uLL)) |= (_QWORD)((unsigned __int64)v52[6] << (8 * (unsigned __int8)v114));
    ++*v49;
    return (__int64)v49;
}
