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
    __int64 result; // rax
    unsigned int v7; // ecx
    unsigned int v8; // eax
    unsigned __int64 v9; // rax
    __int64 v10; // rcx
    __int64 v11; // rdx
    char v12; // al
    unsigned int v13; // ecx
    unsigned int v14; // eax
    int v15; // ecx
    __int64 v16; // rax
    unsigned int v17; // eax
    unsigned int v18; // ecx
    unsigned __int64 v19; // rax
    unsigned __int64 v20; // rax
    unsigned int v21; // eax
    int v22; // ecx
    unsigned int v23; // edx
    unsigned __int64 v24; // rax
    unsigned __int64 v25; // rcx
    unsigned int v26; // ecx
    unsigned int v27; // eax
    unsigned __int64 v28; // rax
    unsigned int v29; // edx
    char v30; // al
    unsigned __int64 v31; // rax
    unsigned __int64 v32; // rcx
    __int64 v33; // rax
    unsigned int v34; // eax
    int v35; // ecx
    unsigned __int64 v36; // rax
    __int64 v37; // rcx
    unsigned __int64 v38; // rdx
    char v39; // r8
    char v40; // cl
    char v41; // cl
    char v42; // r9
    char v43; // bp
    char v44; // r14
    char v45; // r10
    unsigned __int64 v46; // rdx
    __int64 v47; // rdx
    int i; // [rsp+34h] [rbp-694h]
    __int64 *v49; // [rsp+38h] [rbp-690h]
    unsigned int v50; // [rsp+44h] [rbp-684h]
    __int64 v51; // [rsp+48h] [rbp-680h]
    unsigned __int8 *v52; // [rsp+50h] [rbp-678h]
    unsigned __int64 v53; // [rsp+58h] [rbp-670h]
    unsigned __int64 v54; // [rsp+60h] [rbp-668h]
    unsigned __int64 v55; // [rsp+68h] [rbp-660h]
    unsigned __int64 v56; // [rsp+70h] [rbp-658h]
    unsigned __int64 v57; // [rsp+78h] [rbp-650h]
    __int64 v58; // [rsp+80h] [rbp-648h]
    unsigned __int64 v59; // [rsp+88h] [rbp-640h]
    char v60; // [rsp+90h] [rbp-638h]
    char v61; // [rsp+98h] [rbp-630h]
    char v62; // [rsp+A0h] [rbp-628h]
    unsigned __int64 v63; // [rsp+A8h] [rbp-620h]
    unsigned __int64 v64; // [rsp+B0h] [rbp-618h]
    unsigned __int64 *v65; // [rsp+B8h] [rbp-610h]
    unsigned __int64 v66; // [rsp+C0h] [rbp-608h]
    __int64 v67; // [rsp+C8h] [rbp-600h]
    unsigned __int64 v68; // [rsp+D0h] [rbp-5F8h]
    __int64 v69; // [rsp+D8h] [rbp-5F0h]
    __int64 v70; // [rsp+E0h] [rbp-5E8h]
    __int64 v71; // [rsp+E8h] [rbp-5E0h]
    __int64 v72; // [rsp+F0h] [rbp-5D8h]
    char v73; // [rsp+F8h] [rbp-5D0h]
    char v74; // [rsp+100h] [rbp-5C8h]
    char v75; // [rsp+108h] [rbp-5C0h]
    __int64 v76; // [rsp+110h] [rbp-5B8h]
    __int64 v77; // [rsp+118h] [rbp-5B0h]
    unsigned __int64 v78; // [rsp+120h] [rbp-5A8h]
    unsigned int v79; // [rsp+12Ch] [rbp-59Ch]
    int v80; // [rsp+130h] [rbp-598h]
    unsigned int v81; // [rsp+134h] [rbp-594h]
    int v82; // [rsp+138h] [rbp-590h]
    int v83; // [rsp+13Ch] [rbp-58Ch]
    int v84; // [rsp+140h] [rbp-588h]
    unsigned int v85; // [rsp+144h] [rbp-584h]
    int v86; // [rsp+148h] [rbp-580h]
    int v87; // [rsp+14Ch] [rbp-57Ch]
    int v88; // [rsp+150h] [rbp-578h]
    int v89; // [rsp+154h] [rbp-574h]
    unsigned int v90; // [rsp+158h] [rbp-570h]
    int v91; // [rsp+15Ch] [rbp-56Ch]
    unsigned __int64 v92; // [rsp+160h] [rbp-568h]
    unsigned __int64 v93; // [rsp+168h] [rbp-560h]
    char v94; // [rsp+170h] [rbp-558h]
    unsigned __int64 v95; // [rsp+178h] [rbp-550h]
    __int64 v96; // [rsp+180h] [rbp-548h]
    unsigned __int64 v97; // [rsp+188h] [rbp-540h]
    unsigned __int64 v98; // [rsp+190h] [rbp-538h]
    __int64 v99; // [rsp+198h] [rbp-530h]
    unsigned __int64 v100; // [rsp+1A0h] [rbp-528h]
    char v101; // [rsp+1A8h] [rbp-520h]
    unsigned __int64 v102; // [rsp+1B0h] [rbp-518h]
    unsigned __int64 v103; // [rsp+1B8h] [rbp-510h]
    __int64 v104; // [rsp+1C0h] [rbp-508h]
    __int64 v105; // [rsp+1C8h] [rbp-500h]
    __int64 v106; // [rsp+1D0h] [rbp-4F8h]
    unsigned __int64 v107; // [rsp+1D8h] [rbp-4F0h]
    char v108; // [rsp+1E0h] [rbp-4E8h]
    unsigned __int64 v109; // [rsp+1E8h] [rbp-4E0h]
    unsigned __int64 v110; // [rsp+1F0h] [rbp-4D8h]
    unsigned __int64 v111; // [rsp+1F8h] [rbp-4D0h]
    char v112; // [rsp+200h] [rbp-4C8h]
    char v113; // [rsp+208h] [rbp-4C0h]
    __int64 v114; // [rsp+210h] [rbp-4B8h]
    unsigned __int64 v115; // [rsp+218h] [rbp-4B0h]
    __int64 v116; // [rsp+220h] [rbp-4A8h]
    unsigned __int64 v117; // [rsp+228h] [rbp-4A0h]
    __int64 v118; // [rsp+230h] [rbp-498h]
    unsigned __int64 v119; // [rsp+240h] [rbp-488h]
    __int64 v120; // [rsp+248h] [rbp-480h]
    __int64 v121; // [rsp+250h] [rbp-478h]
    __int64 v122; // [rsp+258h] [rbp-470h]
    __int64 v123; // [rsp+260h] [rbp-468h]
    __int64 v124; // [rsp+268h] [rbp-460h]
    unsigned __int64 v125; // [rsp+270h] [rbp-458h]
    __int64 v126; // [rsp+278h] [rbp-450h]
    unsigned __int64 v127; // [rsp+280h] [rbp-448h]
    unsigned __int64 v128; // [rsp+288h] [rbp-440h]
    unsigned __int64 v129; // [rsp+290h] [rbp-438h]
    __int64 v130; // [rsp+298h] [rbp-430h]
    unsigned __int64 v131; // [rsp+2A0h] [rbp-428h]
    unsigned __int64 v132; // [rsp+2A8h] [rbp-420h]
    __int64 v133; // [rsp+2B0h] [rbp-418h]
    unsigned __int64 v134; // [rsp+2D8h] [rbp-3F0h]
    __int64 v135; // [rsp+2E0h] [rbp-3E8h]
    unsigned __int64 v136; // [rsp+2E8h] [rbp-3E0h]
    __int64 v137; // [rsp+2F0h] [rbp-3D8h]
    unsigned __int64 v138; // [rsp+2F8h] [rbp-3D0h]
    __int64 v139; // [rsp+300h] [rbp-3C8h]
    __int64 v140; // [rsp+308h] [rbp-3C0h]
    unsigned __int64 v141; // [rsp+310h] [rbp-3B8h]
    __int64 v142; // [rsp+318h] [rbp-3B0h]
    unsigned __int64 v143; // [rsp+320h] [rbp-3A8h]
    unsigned __int64 v144; // [rsp+328h] [rbp-3A0h]
    __int64 v145; // [rsp+330h] [rbp-398h]
    unsigned __int64 v146; // [rsp+338h] [rbp-390h]
    __int64 v147; // [rsp+340h] [rbp-388h]
    __int64 v148; // [rsp+348h] [rbp-380h]
    __int64 v149; // [rsp+350h] [rbp-378h]
    char v150; // [rsp+358h] [rbp-370h]
    char v151; // [rsp+360h] [rbp-368h]
    char v152; // [rsp+368h] [rbp-360h]
    char v153; // [rsp+370h] [rbp-358h]
    char v154; // [rsp+378h] [rbp-350h]
    unsigned __int64 v155; // [rsp+380h] [rbp-348h]
    __int64 v156; // [rsp+388h] [rbp-340h]
    __int64 v157; // [rsp+390h] [rbp-338h]
    unsigned __int64 v158; // [rsp+398h] [rbp-330h]
    __int64 v159; // [rsp+3A0h] [rbp-328h]
    __int64 v160; // [rsp+3A8h] [rbp-320h]
    __int64 v161; // [rsp+3B0h] [rbp-318h]
    __int64 v162; // [rsp+3B8h] [rbp-310h]
    unsigned __int64 v163; // [rsp+3C0h] [rbp-308h]
    __int64 v164; // [rsp+3C8h] [rbp-300h]
    __int64 v165; // [rsp+3D0h] [rbp-2F8h]
    unsigned __int64 v166; // [rsp+3D8h] [rbp-2F0h]
    unsigned __int64 v167; // [rsp+3E0h] [rbp-2E8h]
    __int64 v168; // [rsp+3E8h] [rbp-2E0h]
    unsigned __int64 v169; // [rsp+3F0h] [rbp-2D8h]
    unsigned __int64 v170; // [rsp+3F8h] [rbp-2D0h]
    __int64 v171; // [rsp+400h] [rbp-2C8h]
    char v172; // [rsp+408h] [rbp-2C0h]
    char v173; // [rsp+410h] [rbp-2B8h]
    char v174; // [rsp+418h] [rbp-2B0h]
    char v175; // [rsp+420h] [rbp-2A8h]
    char v176; // [rsp+428h] [rbp-2A0h]
    char v177; // [rsp+430h] [rbp-298h]
    char v178; // [rsp+438h] [rbp-290h]
    char v179; // [rsp+440h] [rbp-288h]
    char v180; // [rsp+448h] [rbp-280h]
    unsigned __int64 v181; // [rsp+450h] [rbp-278h]
    unsigned __int64 v182; // [rsp+458h] [rbp-270h]
    unsigned __int64 v183; // [rsp+460h] [rbp-268h]
    unsigned __int64 v184; // [rsp+468h] [rbp-260h]
    __int64 v185; // [rsp+470h] [rbp-258h]
    unsigned __int64 v186; // [rsp+478h] [rbp-250h]
    __int64 v187; // [rsp+480h] [rbp-248h]
    unsigned __int64 v188; // [rsp+488h] [rbp-240h]
    __int64 v189; // [rsp+490h] [rbp-238h]
    unsigned __int64 v190; // [rsp+498h] [rbp-230h]
    __int64 v191; // [rsp+4A0h] [rbp-228h]
    unsigned __int64 v192; // [rsp+4A8h] [rbp-220h]
    unsigned __int64 v193; // [rsp+4B0h] [rbp-218h]
    unsigned __int64 v194; // [rsp+4B8h] [rbp-210h]
    unsigned __int64 v195; // [rsp+4C0h] [rbp-208h]
    unsigned __int64 v196; // [rsp+4C8h] [rbp-200h]
    unsigned __int64 v197; // [rsp+4D0h] [rbp-1F8h]
    __int64 v198; // [rsp+4D8h] [rbp-1F0h]
    char v199; // [rsp+4E0h] [rbp-1E8h]
    char v200; // [rsp+4E8h] [rbp-1E0h]
    char v201; // [rsp+4F0h] [rbp-1D8h]
    unsigned __int64 v202; // [rsp+4F8h] [rbp-1D0h]
    unsigned __int64 v203; // [rsp+500h] [rbp-1C8h]
    unsigned __int64 v204; // [rsp+508h] [rbp-1C0h]
    unsigned __int64 v205; // [rsp+510h] [rbp-1B8h]
    unsigned __int64 v206; // [rsp+518h] [rbp-1B0h]
    unsigned __int64 v207; // [rsp+520h] [rbp-1A8h]
    unsigned __int64 v208; // [rsp+528h] [rbp-1A0h]
    unsigned __int64 v209; // [rsp+530h] [rbp-198h]
    unsigned __int64 v210; // [rsp+538h] [rbp-190h]
    __int64 v211; // [rsp+540h] [rbp-188h]
    char v212; // [rsp+548h] [rbp-180h]
    char v213; // [rsp+550h] [rbp-178h]
    char v214; // [rsp+558h] [rbp-170h]
    char v215; // [rsp+560h] [rbp-168h]
    char v216; // [rsp+568h] [rbp-160h]
    char v217; // [rsp+570h] [rbp-158h]
    __int64 *v218; // [rsp+578h] [rbp-150h]
    __int64 v219; // [rsp+580h] [rbp-148h]
    char v220; // [rsp+588h] [rbp-140h]
    char v221; // [rsp+590h] [rbp-138h]
    char v222; // [rsp+598h] [rbp-130h]
    char v223; // [rsp+5A0h] [rbp-128h]
    char v224; // [rsp+5A8h] [rbp-120h]
    char v225; // [rsp+5B0h] [rbp-118h]
    unsigned __int64 v226; // [rsp+5B8h] [rbp-110h]
    __int64 v227; // [rsp+5C0h] [rbp-108h]
    char v228; // [rsp+5C8h] [rbp-100h]
    char v229; // [rsp+5D0h] [rbp-F8h]
    char v230; // [rsp+5D8h] [rbp-F0h]
    char v231; // [rsp+5E0h] [rbp-E8h]
    unsigned __int64 v232; // [rsp+5E8h] [rbp-E0h]
    char v233; // [rsp+5F0h] [rbp-D8h]
    char v234; // [rsp+5F8h] [rbp-D0h]
    char v235; // [rsp+600h] [rbp-C8h]
    char v236; // [rsp+608h] [rbp-C0h]
    unsigned __int64 v237; // [rsp+610h] [rbp-B8h]
    unsigned __int64 v238; // [rsp+618h] [rbp-B0h]
    __int64 v239; // [rsp+620h] [rbp-A8h]
    unsigned __int64 v240; // [rsp+628h] [rbp-A0h]
    __int64 v241; // [rsp+630h] [rbp-98h]
    unsigned __int64 v242; // [rsp+638h] [rbp-90h]
    __int64 v243; // [rsp+640h] [rbp-88h]
    unsigned __int64 v244; // [rsp+648h] [rbp-80h]
    __int64 v245; // [rsp+650h] [rbp-78h]
    __int64 v246; // [rsp+658h] [rbp-70h]
    unsigned __int64 v247; // [rsp+660h] [rbp-68h]
    unsigned __int64 v248; // [rsp+668h] [rbp-60h] 

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
                                                    v248 = v247 - (v78 ^ 0xA121C04AA20525AEuLL);
                                                    i = 0x64AFC49D;
                                                }
                                            }

                                            else if ( i == 0x606DC166 )
                                            {
                                                v54 = *v49;
                                                v134 = 6 * ~(*v49 | 0xFFFFFFFFFFFFFFF8uLL);
                                                v135 = 0xD * ~(*v49 | 7);
                                                v136 = 0xD * (*v49 & 0xFFFFFFFFFFFFFFF8uLL)
                                                     + 8 * (*v49 & 7)
                                                     - 7 * (*v49 | 0xFFFFFFFFFFFFFFF8uLL)
                                                     - 6 * ~(*v49 & 7);
                                                i = 0x139F2922;
                                            }
                                            else
                                            {
                                                v31 = v237
                                                    + v238
                                                    + v239
                                                    + (v76 & 0x65F5CA3EE93E08BBLL)
                                                    + 0xB * (v76 & 0x9A0A35C116C1F744uLL)
                                                    - v241;
                                                v32 = v31 + 0x43DC1B5AE8F2871ELL;
                                                v33 = v76
                                                    + 0x71B4B1196DCBBB74LL
                                                    - (v31
                                                     - 0x71B4B1196DCBBB74LL)
                                                    - 0x787F8E1A278984D0LL;
                                                if ( v53 == ~(~v32 | v33)
                                                          + 6 * (~v32 & v33)
                                                          + 8 * (v32 & v33)
                                                          - 5 * (~v32 | v33)
                                                          - 3 * (v33 ^ ~v32)
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
                                                v138 = 3 * ~(v66 | 0xD17DA1C86E91436DuLL);
                                                v139 = v66 | 0x2E825E37916EBC92LL;
                                                v7 = 0x5F373C53;
                                                v8 = 0x5FF7F9CC;
                                                goto LABEL_x927BA;
                                            }

                                            v179 = v175 + v176 + v177 + v178;
                                            v180 = v172 - v173 + 0x16;
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
                                                v128 = v190;
                                                v129 = v192;
                                                v130 = v191;

LABEL_x8F290:
                                                *(_OWORD *)(a5 + 0xC0) = D810_ZERO_OWORD;
                                                *(_OWORD *)(a5 + 0xB0) = D810_ZERO_OWORD;
                                                *(_OWORD *)(a5 + 0xA0) = D810_ZERO_OWORD;
                                                *(_OWORD *)(a5 + 0x90) = D810_ZERO_OWORD;
                                                *(_OWORD *)(a5 + 0x80) = D810_ZERO_OWORD;
                                                *(_OWORD *)(a5 + 0x70) = D810_ZERO_OWORD;
                                                *(_OWORD *)(a5 + 0x60) = D810_ZERO_OWORD;
                                                *(_OWORD *)(a5 + 0x50) = D810_ZERO_OWORD;
                                                v131 = v128;
                                                v132 = v129;
                                                v133 = v130;
                                                goto LABEL_x8F34A;
                                            }

                                            if ( i == 0x64AFC49D )
                                            {
                                                result = 0x5644FD01B1049C4BLL;
                                                if ( v63 == v243
                                                          + v246
                                                          - v248
                                                          + (v244 ^ 0x604AFCF8563706BLL)
                                                          - v78
                                                          + 0x5644FD01B1049C4BLL )
                                                    return result;

                                                if ( v242 )
                                                {
                                                    if ( v242 == 0x80 )
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
                                                        v193 = 0x13LL
                                                             * ((unsigned int)v28
                                                              & (unsigned int)*v49)
                                                             + 0xC * (v70 & ~v28)
                                                             - 0xB * (~v28 | *v49)
                                                             - 6 * ~(~v28 & v70)
                                                             + 7 * ~(~v28 | *v49)
                                                             + 0x11 * ~(v28 | v70);
                                                        *v49 = v193;
                                                        v52 = (unsigned __int8 *)(v28 + v133);
                                                        v194 = 0xC7040DEF7B0F10C5uLL;
                                                        v195 = 0xF89735C1B4F67C3CuLL;
                                                        v196 = 0xCE6CD82DC6189490uLL;
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
                                                v157 = v16;
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
                                                v218 = (__int64 *)(v51 + 8 * v210);
                                                v219 = *v218 | (v211 << ((v110 << v217) & 0x38));
                                                i = 0x11CD1DA3;
                                            }
                                            else
                                            {
                                                if ( i != 0x72AFE1BC )
                                                    return result;

                                                v216 = v215
                                                     + 8 * (v61 & ~v60)
                                                     - 2 * (v60 & v61)
                                                     - 7 * (v60 ^ v61)
                                                     - v214;
                                                i = 0x737189D5;
                                            }
                                        }

                                        else if ( i == 0x6B588049 )
                                        {
                                            v147 = 3 * ~(v58 | v146);
                                            v148 = ~(v58 & ~v56)
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
                                            v217 = v213 + v216 - v212;
                                            v15 = 0x71E22BF3;
                                            goto LABEL_x90BB4;
                                        }

                                        v166 = v164 + 2 * (unsigned int)(v55 & 0x7F) - v165 - v163;
                                        i = 0x5FE86821;
                                    }

                                    else if ( i == 0x7C2C0220 )
                                    {
                                        v236 = v232 & (v233 + v235 - v234);
                                        i = 0x385BBE2D;
                                    }

                                    else if ( i == 0x7D9C16EC )
                                    {
                                        v210 = v110 >> 3;
                                        v211 = v52[2];
                                        v212 = 0x25;
                                        v60 = 0xE;
                                        v61 = 0x1A;
                                        v213 = 0x20;
                                        v214 = 0x84;
                                        v215 = 0xAC;
                                        i = 0x72AFE1BC;
                                    }
                                    else
                                    {
                                        v158 = v57 + v157;
                                        *v49 = v57 + v157;
                                        v159 = a3 + v57;
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
                                                v53 = v107 & (v195 + v196 - v194);
                                                i = 0x298372CC;
                                            }
                                            else
                                            {
                                                v36 = v55;
                                                v37 = v67;
                                                v38 = v68;

LABEL_x91A2D:
                                                v242 = v36;
                                                v77 = v37;
                                                v63 = v38;
                                                v243 = 0x344436EA9527C8AELL;
                                                v244 = 0xA9287151E95AB0BEuLL;
                                                v78 = 0xCC6A6928AA358512uLL;
                                                v245 = 0x1294169555CA5A41LL;
                                                i = 0x5A21D9DB;
                                            }
                                        }

                                        else if ( i == 0x474EEEBB )
                                        {
                                            v46 = v144
                                                | (v145 << (v149 << (v152
                                                                   ^ (unsigned __int8)(((v153 + v154 - 2) ^ v150 ^ (v154 + v153 - 0x33) ^ (v151 - 0x62)) - v94))));
                                            *v65 = v46;
                                            v95 = v46
                                                | ((unsigned __int64)*(unsigned __int8 *)(a3 + v58 + 1) << (8 * ((unsigned __int8)v56 + ((unsigned __int8)v58 | 1u))));
                                            *v65 = v95;
                                            v96 = v58 + 2;
                                            if ( v58 + 2 == v143 )
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

                                            v226 = v111 >> (((unsigned __int8)(v224
                                                                             + v225
                                                                             - (2 * (v112 & 0x22)
                                                                              + 2 * (v112 & 0xDD))
                                                                             - v223
                                                                             - v222)
                                                           ^ (unsigned __int8)(v220 + (v221 ^ 0x9A)))
                                                          - v112);
                                            v227 = v52[4];
                                            v73 = 0x1A;
                                            v113 = 0xA0;
                                            v62 = 0x88;
                                            v228 = 0x9C;
                                            v229 = 0xC;
                                            v230 = 0x7F;
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
                                                v98 >> (v179 ^ (unsigned __int8)(v174 + v180)));
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
                                            v246 = 2 * v245;
                                            v247 = 2 * ~(v78 & 0xA121C04AA20525AEuLL);
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
                                            v208 = 0xB493FD3C199D9EBAuLL;
                                            v209 = 0xB493FD3C199D9EBBuLL;
                                            v34 = 0xE6334342;
                                            v35 = 0x1C6BAB0E;
                                            goto LABEL_x929BB;
                                        }

                                        if ( v162 + v166 == v160 )
                                        {
                                            i = 0x45B18E82;
                                        }
                                        else
                                        {
                                            v167 = 0x91FA460CD2D32E41uLL;
                                            v168 = 0x37F13911D652CC78LL;
                                            v169 = 0xADC4CF83D2CF56F0uLL;
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
                                            v182 = v103 + 0x2FA79C4916F275A9LL;
                                            v183 = v103 - 0x1A57180B6086323DLL;
                                            v184 = v103 + 0x238DAEF738FB5AD7LL;
                                            i = 0x393685BA;
                                        }
                                        else
                                        {
                                            v162 = ~v161;
                                            v163 = v55 | 0xFFFFFFFFFFFFFF80uLL;
                                            v164 = 7 * (v55 ^ 0x7F);
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
                                            *v65 = v155
                                                 | ((unsigned __int64)*(unsigned __int8 *)(a3 + v156) << (8 * ((unsigned __int8)v56 + (unsigned __int8)v156)));
                                            goto LABEL_x92004;
                                        }

                                        v9 = v204 ^ (v203 + v205);
                                        v10 = 0x15 * ~(v9 | ~v71);
                                        v11 = 0xB * ~(v9 & v71);
                                        result = 0x15 * (v9 & ~v71) + 9 * (v71 & v9);
                                        if ( v53 == v202
                                                  + v11
                                                  + 0xB * (v71 | (v204 ^ (v203 + v205)))
                                                  - result
                                                  - 0xB * ~(v71 | (v204 ^ (v203 + v205)))
                                                  - v10 )
                                            return result;

                                        v206 = v109 >> 3;
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
                                                + (v169 ^ (v171 - v168 - v170 + 0x3D15731BE3B5F7DFLL))
                                                - v167);
                                        v25 = v68;
                                        if ( v24 < v68 )
                                            v25 = v24;

                                        v98 = v25;
                                        v172 = 0x86;
                                        v173 = 0x59;
                                        v174 = 0x52;
                                        v175 = 0xD3;
                                        v176 = 0x22;
                                        v177 = 0x8A;
                                        v178 = 0x17;
                                        i = 0x63D54755;
                                    }
                                    else
                                    {
                                        *(_QWORD *)(v51 + 8 * v226) |= v227 << v236;
                                        v47 = *v49 + 1;
                                        *v49 = v47;
                                        if ( v53 == 5 )
                                        {
                                            v7 = 0x45BA4824;
                                            v8 = 0x2910DD05;
                                            goto LABEL_x927BA;
                                        }

                                        *(_QWORD *)(v51 + (v47 & 0xFFFFFFFFFFFFFFF8uLL)) |= (unsigned __int64)v52[5] << ((8 * v47) & 0x38);
                                        v114 = *v49 + 1;
                                        *v49 = v114;
                                        v76 = 0x5B22243FF89F5980LL;
                                        v237 = 0xA4DDDBC00760A67FuLL;
                                        v238 = 0x80489FC03845D864uLL;
                                        v239 = 0x7059E4000B40024ELL;
                                        v240 = 0xBEDFFFC117E1F77FuLL;
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
                                        if ( v100 == (v103 ^ (v183 + v182 + v184)) - v181 )
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
                                        *(_QWORD *)(v51 + 8 * v206) |= v207;
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
                                            v170 = v97 + 0x7552BC11D833A13ALL;
                                            v171 = (v97 + 0x7552BC11D833A13ALL)
                                                 ^ 0x9EDA0CA9221A129LL;
                                            i = 0x37B42A40;
                                        }
                                        else
                                        {
                                            v110 = 0x13 * (v72 & (v209 - v208))
                                                 + 0xC * (v72 & ~(v209 - v208))
                                                 - 0xB * (~(v209 - v208) | v72)
                                                 - 6 * ~(~(v209 - v208) & v72)
                                                 + 7 * ~(~(v209 - v208) | v72)
                                                 + 0x11 * ~((v209 - v208) | v72);
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
                                            v93 = v138
                                                + 5 * ~v139
                                                + 8 * (v66 & 0xD17DA1C86E91436DuLL)
                                                - 2 * (v66 ^ 0x2E825E37916EBC92LL)
                                                - 0x177428EA28D65121LL;
                                            v13 = 0x4A2BE3B8;
                                            v14 = 0x79E629C9;
                                            goto LABEL_x8F797;
                                        }

                                        v165 = 6 * (v55 & 0x7FFFFFFFFFFFFF80LL);
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

                                    v149 = v148 - v147;
                                    v150 = 0x30;
                                    v151 = 0xB7;
                                    v152 = 0xFA;
                                    v94 = 0x5D;
                                    v153 = 0x54;
                                    v154 = 0x24;
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
                                           * ((v200
                                             + (v108 ^ 0xBF)
                                             + 6 * (v108 & 0x40)
                                             + 6 * (v108 & 0xBF)
                                             - v201)
                                            & 0x2A)
                                           - 2
                                           * ((v200
                                             + (v108 ^ 0xBF)
                                             + 6 * (v108 & 0x40)
                                             + 6 * (v108 & 0xBF)
                                             - v201)
                                            & 0xD5)
                                           - 7
                                           * ((v200
                                             + (v108 ^ 0xBF)
                                             + 6 * (v108 & 0x40)
                                             + 6 * (v108 & 0xBF)
                                             - v201)
                                            ^ 0xD5)
                                           + 4
                                           * ~((v200
                                              + (v108 ^ 0xBF)
                                              + 6 * (v108 & 0x40)
                                              + 6 * (v108 & 0xBF)
                                              - v201)
                                             ^ 0xD5)
                                           - 4
                                           * ~((v200
                                              + (v108 ^ 0xBF)
                                              + 6 * (v108 & 0x40)
                                              + 6 * (v108 & 0xBF)
                                              - v201)
                                             | 0xD5)
                                           + 8
                                           * ~((v200
                                              + (v108 ^ 0xBF)
                                              + 6 * (v108 & 0x40)
                                              + 6 * (v108 & 0xBF)
                                              - v201)
                                             | 0x2A))
                                          | 0x80);
                                    v40 = 2
                                        * ~((8
                                           * ((v200
                                             + (v108 ^ 0xBF)
                                             + 6 * (v108 & 0x40)
                                             + 6 * (v108 & 0xBF)
                                             - v201)
                                            & 0x2A)
                                           - 2
                                           * ((v200
                                             + (v108 ^ 0xBF)
                                             + 6 * (v108 & 0x40)
                                             + 6 * (v108 & 0xBF)
                                             - v201)
                                            & 0xD5)
                                           - 7
                                           * ((v200
                                             + (v108 ^ 0xBF)
                                             + 6 * (v108 & 0x40)
                                             + 6 * (v108 & 0xBF)
                                             - v201)
                                            ^ 0xD5)
                                           + 4
                                           * ~((v200
                                              + (v108 ^ 0xBF)
                                              + 6 * (v108 & 0x40)
                                              + 6 * (v108 & 0xBF)
                                              - v201)
                                             ^ 0xD5)
                                           - 4
                                           * ~((v200
                                              + (v108 ^ 0xBF)
                                              + 6 * (v108 & 0x40)
                                              + 6 * (v108 & 0xBF)
                                              - v201)
                                             | 0xD5)
                                           + 8
                                           * ~((v200
                                              + (v108 ^ 0xBF)
                                              + 6 * (v108 & 0x40)
                                              + 6 * (v108 & 0xBF)
                                              - v201)
                                             | 0x2A))
                                          & 0x80);
                                    v41 = v40
                                        - ((8
                                          * ((v200
                                            + (v108 ^ 0xBF)
                                            + 6 * (v108 & 0x40)
                                            + 6 * (v108 & 0xBF)
                                            - v201)
                                           & 0x2A)
                                          - 2
                                          * ((v200
                                            + (v108 ^ 0xBF)
                                            + 6 * (v108 & 0x40)
                                            + 6 * (v108 & 0xBF)
                                            - v201)
                                           & 0xD5)
                                          - 7
                                          * ((v200
                                            + (v108 ^ 0xBF)
                                            + 6 * (v108 & 0x40)
                                            + 6 * (v108 & 0xBF)
                                            - v201)
                                           ^ 0xD5)
                                          + 4
                                          * ~((v200
                                             + (v108 ^ 0xBF)
                                             + 6 * (v108 & 0x40)
                                             + 6 * (v108 & 0xBF)
                                             - v201)
                                            ^ 0xD5)
                                          - 4
                                          * ~((v200
                                             + (v108 ^ 0xBF)
                                             + 6 * (v108 & 0x40)
                                             + 6 * (v108 & 0xBF)
                                             - v201)
                                            | 0xD5)
                                          + 8
                                          * ~((v200
                                             + (v108 ^ 0xBF)
                                             + 6 * (v108 & 0x40)
                                             + 6 * (v108 & 0xBF)
                                             - v201)
                                            | 0x2A))
                                         ^ 0x80)
                                        - v39;
                                    v42 = ((~v41 & 0xD2)
                                         + (v41 & 0x2D)
                                         + 2 * ~(v41 | 0xD2)
                                         - 2 * ~v41)
                                        ^ 0x39;
                                    v43 = (v42 | 0xC8)
                                        + 3 * v42
                                        + 4 * (v42 & 0xC8)
                                        - 3 * (v42 & 0x37)
                                        + 6 * ~(v42 | 0x37)
                                        + 0x4A;
                                    v44 = ((v42 | 0xC8)
                                         + 3 * v42
                                         + 4 * (v42 & 0xC8)
                                         - 3 * (v42 & 0x37)
                                         + 6 * ~(v42 | 0x37)
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
                                        - (v200
                                         + (v108 ^ 0xBF)
                                         + 6 * (v108 & 0x40)
                                         + 6 * (v108 & 0xBF)
                                         - v201)
                                        - v42
                                        - v108;
                                    *(_QWORD *)(v51 + 8 * v197) |= v198 << (v199
                                                                          & (unsigned __int8)(8 * ~v45 + v45 + 1 + 3 * ~(v45 & v41) + 2 * (v45 & v41) - 2 * (~v41 & v45) - 0xA * ~(v41 | v45) - 9 * ~(~v41 | v45)));
                                    v109 = *v49 + 1;
                                    *v49 = v109;
                                    v202 = 0xD3A768BA35526030uLL;
                                    v71 = 0xF9520CA799C88D0LL;
                                    v203 = 0xD724EF6803290A0BuLL;
                                    v204 = 0x93E48C21862BDBEDuLL;
                                    v205 = 0xB8030AF2D411C2E1uLL;
                                    i = 0x42267E66;
                                }
                            }

                            else if ( i > 0x139F2921 )
                            {
                                if ( i <= 0x149F5A97 )
                                {
                                    if ( i == 0x139F2922 )
                                    {
                                        v56 = v134 + v135 + v136;
                                        if ( v56 )
                                        {
                                            v20 = sub_7FFD32FF8F30(v54, 0x4D, 0x57, 8);
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
                                                v137 = 0x6FE2B37214B84CE1LL;
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
                                        sub_7FFD33050180(0x62, v69, v99, 0x10);
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
                                    v189 = v185 + v188 - v187 - v186;
                                    if ( v189 == v102 )
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

                                v185 = v123;
                                v105 = v122;
                                v79 = 0xB140360B;
                                v80 = 0x4A00E104;
                                v81 = 0xA5627292;
                                v82 = 0x3E231D8B;
                                i = 0x2F3C0CA1;
                            }

                            else if ( i == 0x10743C4C )
                            {
                                v241 = 0xB * v240;
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

                                *v218 = v219;
                                result = *v49 + 1;
                                *v49 = result;
                                if ( v53 == 3 )
                                    return result;

                                *(_QWORD *)(v51 + (result & 0xFFFFFFFFFFFFFFF8uLL)) |= (unsigned __int64)v52[3] << (8 * (unsigned __int8)result);
                                v111 = *v49 + 1;
                                *v49 = v111;
                                if ( v53 == 4 )
                                {
                                    v7 = 0xFCE60313;
                                    v8 = 0x92738C89;
                                    goto LABEL_x927BA;
                                }

                                v220 = 0x87;
                                v221 = 0x79;
                                v112 = 0x45;
                                v222 = 0xC8;
                                v223 = 0x88;
                                v224 = 0xFF;
                                v225 = 0xFD;
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
                                    sub_7FFD33050180(0x44, v105, v99, 0x10);
                                    v106 = v105 + 0x80;
                                    *v49 = 0x80;
                                    v186 = 0xF2678B7073B1C107uLL;
                                    v187 = 0;
                                    v188 = 0xF2678B7073B1C108uLL;
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

                                v12 = v230 - (2 * (v62 & 0xC3) + 2 * (v62 & 0x3C)) - v229 - v228;
                                v231 = v12 - 0x19;
                                v74 = v12 + 0x41;
                                v75 = v62 + v73 + ((v12 - 0x4B) ^ 0xF);
                                i = 0x1AB9946F;
                            }
                        }

                        else if ( i <= 0x307BF0E4 )
                        {
                            if ( i == 0x2FBA4611 )
                            {
                                v140 = v93 ^ 0x4520678B9CC77B2FLL;
                                v141 = (v66
                                      ^ ((v93 ^ 0x38B49E60BFFE681LL)
                                       - v137
                                       + (v93 ^ 0x38B49E60BFFE681LL)
                                       + 0x4B73FBBE70FE5CB4LL))
                                     - v93;
                                v17 = 0x9A319577;
                                v18 = 0xAA61F61C;
                                goto LABEL_x8ECD1;
                            }

                            v142 = v57 & (v140 ^ v141);
                            if ( v64 == 1 )
                            {
                                v117 = v92;
                                v118 = 0;
                                goto LABEL_x9105A;
                            }

                            v143 = v57 & 0x3E;
                            v115 = v92;
                            v116 = 0;

LABEL_x926BC:
                            v58 = v116;
                            v144 = v115;
                            v145 = *(unsigned __int8 *)(a3 + v116);
                            v146 = ~v56;
                            i = 0x6B588049;
                        }

                        else if ( i == 0x307BF0E5 )
                        {
                            v119 = v158;
                            v120 = v159;
                            v121 = 0x20 - v57;

LABEL_x8F153:
                            v68 = v121;
                            v67 = v120;
                            v55 = v119;
                            v160 = 7LL * (~(_BYTE)v119 & 0x7F);
                            v161 = v119 | 0x7F;
                            i = 0x41B585C8;
                        }

                        else if ( i == 0x32FCD904 )
                        {
                            v117 = v95;
                            v118 = v96;

LABEL_x9105A:
                            v156 = v118;
                            v155 = v117;
                            if ( v142 )
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
                        v192 = v127;
                        v191 = v126;
                        v190 = v125;
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
                        v123 = v189;
                        i = 0xD64F20F;
                    }
                    else
                    {
                        if ( !v53 )
                            return result;

                        v197 = v193 >> 3;
                        v198 = *v52;
                        v199 = 8 * v70;
                        v108 = 0xEE;
                        v200 = 0;
                        v201 = 0x94;
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

                v207 = (unsigned __int64)v52[1] << (8 * (unsigned __int8)v109);
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
            v232 = v111 << (v231
                          ^ (unsigned __int8)((v30 | ~v74)
                                            + 3 * v30
                                            + 4 * (v30 & ~v74)
                                            - 3 * (v74 & v30)
                                            + 6 * ~(v30 | v74)
                                            - 6 * ~v74
                                            + 1));
            v233 = 0xBE;
            v234 = 0xE4;
            v235 = 0x5E;
            i = 0x7C2C0220;
        }

        if ( i != 0x1CCE40B3 )
            break;

        v181 = 0x9A2F7F3952A0EA97uLL;
        v103 = 0x989C93011F7C5B59uLL;
    }

    *(_QWORD *)(v51 + (v114 & 0xFFFFFFFFFFFFFFF8uLL)) |= (unsigned __int64)v52[6] << (8 * (unsigned __int8)v114);
    ++*v49;
    return (__int64)v49;
}