#include "ida_types.h"
#include "platform.h"

int x, y;

struct timeval {
   long tv_sec ;
   int tv_usec ;
};

extern int gettimeofday(struct timeval *tv , void *tz ) ;
extern int printf(char const   *format  , ...) ;
extern int scanf(char const   *format  , ...) ;
extern int strncmp(char const   *s1 , char const   *s2 , unsigned int maxlen ) ;
extern int memcpy(void *dest, const void *src, size_t n);
extern void *memset(void *dest, int c, size_t n);


EXPORT void test_function_ollvm_fla_bcf_sub(unsigned int *input, unsigned int *output)
{
  int v2; // esi
  int v3; // eax
  int *v4; // edi
  int v5; // ebx
  unsigned int v6; // edi
  int v7; // eax
  int v8; // eax
  int v9; // ecx
  int *v10; // edi
  int *v11; // eax
  int v12; // eax
  int v13; // eax
  int v14; // esi
  int v15; // esi
  unsigned int v16; // ebx
  int v17; // esi
  int v18; // eax
  int v19; // esi
  int v20; // eax
  int v21; // eax
  int v22; // eax
  int v23; // eax
  int v24; // eax
  int v25; // eax
  int v26; // eax
  int v27; // edx
  int v28; // eax
  int v29; // eax
  int v30; // esi
  int v31; // eax
  int v32; // eax
  int v33; // eax
  int v34; // esi
  int v35; // eax
  int v36; // esi
  int v37; // eax
  int v38; // esi
  int v39; // eax
  int v40; // esi
  int v41; // esi
  int v42; // esi
  int v43; // eax
  int v44; // eax
  int *v45; // edi
  int v46; // ebx
  unsigned int v47; // edi
  int v48; // ebx
  int v49; // eax
  int v50; // eax
  int *v51; // edx
  int v52; // esi
  int v53; // edi
  unsigned int v54; // ebx
  unsigned char v55[16]; // [esp-10h] [ebp-238h] BYREF
  unsigned int v56[4]; // [esp+0h] [ebp-228h] BYREF
  int v57; // [esp+10h] [ebp-218h]
  int v58; // [esp+14h] [ebp-214h]
  int v59; // [esp+18h] [ebp-210h]
  int v60; // [esp+1Ch] [ebp-20Ch]
  char *v61; // [esp+20h] [ebp-208h]
  int v62; // [esp+24h] [ebp-204h]
  int v63; // [esp+28h] [ebp-200h]
  unsigned int *v64; // [esp+2Ch] [ebp-1FCh]
  unsigned int **v65; // [esp+30h] [ebp-1F8h]
  int v66; // [esp+34h] [ebp-1F4h]
  unsigned int *v67; // [esp+38h] [ebp-1F0h]
  unsigned int *v68; // [esp+3Ch] [ebp-1ECh]
  int *v69; // [esp+40h] [ebp-1E8h]
  unsigned int *v70; // [esp+44h] [ebp-1E4h]
  char *s1; // [esp+48h] [ebp-1E0h]
  int *v72; // [esp+4Ch] [ebp-1DCh]
  struct timeval *v73; // [esp+50h] [ebp-1D8h]
  int v74; // [esp+54h] [ebp-1D4h]
  unsigned char v75; // [esp+5Bh] [ebp-1CDh]
  int v76; // [esp+5Ch] [ebp-1CCh]
  unsigned char v77; // [esp+62h] [ebp-1C6h]
  unsigned char v78; // [esp+63h] [ebp-1C5h]
  int v79; // [esp+64h] [ebp-1C4h]
  unsigned char v80; // [esp+6Bh] [ebp-1BDh]
  int v81; // [esp+6Ch] [ebp-1BCh]
  unsigned char v82; // [esp+72h] [ebp-1B6h]
  unsigned char v83; // [esp+73h] [ebp-1B5h]
  int v84; // [esp+74h] [ebp-1B4h]
  char v85; // [esp+7Ah] [ebp-1AEh]
  unsigned char v86; // [esp+7Bh] [ebp-1ADh]
  int v87; // [esp+7Ch] [ebp-1ACh]
  char v88; // [esp+82h] [ebp-1A6h]
  unsigned char v89; // [esp+83h] [ebp-1A5h]
  int v90; // [esp+84h] [ebp-1A4h]
  unsigned char v91; // [esp+8Ah] [ebp-19Eh]
  unsigned char v92; // [esp+8Bh] [ebp-19Dh]
  int v93; // [esp+8Ch] [ebp-19Ch]
  unsigned char v94; // [esp+92h] [ebp-196h]
  unsigned char v95; // [esp+93h] [ebp-195h]
  int v96; // [esp+94h] [ebp-194h]
  char v97; // [esp+9Ah] [ebp-18Eh]
  unsigned char v98; // [esp+9Bh] [ebp-18Dh]
  int v99; // [esp+9Ch] [ebp-18Ch]
  unsigned char v100; // [esp+A3h] [ebp-185h]
  int v101; // [esp+A4h] [ebp-184h]
  unsigned char v102; // [esp+AAh] [ebp-17Eh]
  unsigned char v103; // [esp+ABh] [ebp-17Dh]
  int v104; // [esp+ACh] [ebp-17Ch]
  int v105; // [esp+B0h] [ebp-178h]
  int v106; // [esp+B4h] [ebp-174h]
  int v107; // [esp+B8h] [ebp-170h]
  unsigned int v108; // [esp+BCh] [ebp-16Ch]
  int v109; // [esp+C0h] [ebp-168h]
  int v110; // [esp+C4h] [ebp-164h]
  unsigned int v111; // [esp+C8h] [ebp-160h]
  char *format; // [esp+CCh] [ebp-15Ch]
  unsigned int v113; // [esp+D0h] [ebp-158h]
  int v114; // [esp+D4h] [ebp-154h]
  unsigned int v115; // [esp+D8h] [ebp-150h]
  int v116; // [esp+DCh] [ebp-14Ch]
  int *v117; // [esp+E0h] [ebp-148h]
  struct timeval *tv; // [esp+E4h] [ebp-144h]
  unsigned int **v119; // [esp+E8h] [ebp-140h]
  int *v120; // [esp+ECh] [ebp-13Ch]
  int v121; // [esp+F0h] [ebp-138h]
  int *v122; // [esp+F4h] [ebp-134h]
  int v123; // [esp+F8h] [ebp-130h]
  char v124; // [esp+FFh] [ebp-129h]
  int v125; // [esp+100h] [ebp-128h]
  int v126; // [esp+104h] [ebp-124h]
  int v127; // [esp+108h] [ebp-120h]
  int v128; // [esp+10Ch] [ebp-11Ch]
  int v129; // [esp+110h] [ebp-118h]
  int v130; // [esp+114h] [ebp-114h]
  int v131; // [esp+118h] [ebp-110h]
  int v132; // [esp+11Ch] [ebp-10Ch]
  int v133; // [esp+120h] [ebp-108h]
  int v134; // [esp+124h] [ebp-104h]
  int v135; // [esp+128h] [ebp-100h]
  int v136; // [esp+12Ch] [ebp-FCh]
  int v137; // [esp+130h] [ebp-F8h]
  int v138; // [esp+134h] [ebp-F4h]
  int v139; // [esp+138h] [ebp-F0h]
  int v140; // [esp+13Ch] [ebp-ECh]
  int v141; // [esp+140h] [ebp-E8h]
  int v142; // [esp+144h] [ebp-E4h]
  int v143; // [esp+148h] [ebp-E0h]
  int v144; // [esp+14Ch] [ebp-DCh]
  int v145; // [esp+150h] [ebp-D8h]
  int v146; // [esp+154h] [ebp-D4h]
  int v147; // [esp+158h] [ebp-D0h]
  int v148; // [esp+15Ch] [ebp-CCh]
  int v149; // [esp+160h] [ebp-C8h]
  int v150; // [esp+164h] [ebp-C4h]
  int v151; // [esp+168h] [ebp-C0h]
  int v152; // [esp+16Ch] [ebp-BCh]
  int v153; // [esp+170h] [ebp-B8h]
  int v154; // [esp+174h] [ebp-B4h]
  int v155; // [esp+178h] [ebp-B0h]
  int v156; // [esp+17Ch] [ebp-ACh]
  int v157; // [esp+180h] [ebp-A8h]
  int v158; // [esp+184h] [ebp-A4h]
  int v159; // [esp+188h] [ebp-A0h]
  int v160; // [esp+18Ch] [ebp-9Ch]
  int v161; // [esp+190h] [ebp-98h]
  int v162; // [esp+194h] [ebp-94h]
  int v163; // [esp+198h] [ebp-90h]
  int v164; // [esp+19Ch] [ebp-8Ch]
  int v165; // [esp+1A0h] [ebp-88h]
  int v166; // [esp+1A4h] [ebp-84h]
  int v167; // [esp+1A8h] [ebp-80h]
  int v168; // [esp+1ACh] [ebp-7Ch]
  int v169; // [esp+1B0h] [ebp-78h]
  int v170; // [esp+1B4h] [ebp-74h]
  int v171; // [esp+1B8h] [ebp-70h]
  int v172; // [esp+1BCh] [ebp-6Ch]
  int v173; // [esp+1C0h] [ebp-68h]
  int v174; // [esp+1C4h] [ebp-64h]
  int v175; // [esp+1C8h] [ebp-60h]
  int v176; // [esp+1CCh] [ebp-5Ch]
  int v177; // [esp+1D0h] [ebp-58h]
  int v178; // [esp+1D4h] [ebp-54h]
  int v179; // [esp+1D8h] [ebp-50h]
  int v180; // [esp+1DCh] [ebp-4Ch]
  int v181; // [esp+1E0h] [ebp-48h]
  int v182; // [esp+1E4h] [ebp-44h]
  unsigned int *v183; // [esp+1E8h] [ebp-40h]
  unsigned int *v184; // [esp+1ECh] [ebp-3Ch]
  int v185; // [esp+1F0h] [ebp-38h]
  char v186; // [esp+1F6h] [ebp-32h]
  char v187; // [esp+1F7h] [ebp-31h]
  unsigned int **v188; // [esp+1F8h] [ebp-30h]
  unsigned int *v189; // [esp+1FCh] [ebp-2Ch]
  unsigned int *v190; // [esp+200h] [ebp-28h]
  void *s; // [esp+204h] [ebp-24h]
  unsigned int *v192; // [esp+208h] [ebp-20h]
  unsigned int *v193; // [esp+20Ch] [ebp-1Ch]
  unsigned char v194; // [esp+212h] [ebp-16h]
  unsigned char v195; // [esp+213h] [ebp-15h]
  int v196; // [esp+214h] [ebp-14h]
  unsigned char v197; // [esp+21Bh] [ebp-Dh]

  v186 = ((((unsigned char)x - 1) * (unsigned char)x) & 1) == 0;
  v187 = y < 10;
  v185 = 1864864255;
  v184 = output;
  v183 = input;
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
              while ( 1 )
              {
                while ( 1 )
                {
                  while ( 1 )
                  {
                    while ( 1 )
                    {
                      v182 = v185;
                      v181 = v185 + 1992264890;
                      if ( v185 != -1992264890 )
                        break;
                      *v193 = 0;
                      v185 = -517899469;
                    }
                    v180 = v182 + 1651491551;
                    if ( v182 != -1651491551 )
                      break;
                    *v189 = *v192 + 5 * *v189;
                    v185 = -1105488767;
                    v56[2] = *v189;
                  }
                  v179 = v182 + 1559035902;
                  if ( v182 != -1559035902 )
                    break;
                  v22 = 173950559;
                  if ( v196 == 1 )
                    v22 = 1597923837;
                  v185 = v22;
                }
                v178 = v182 + 1503386729;
                if ( v182 != -1503386729 )
                  break;
                v96 = -1651491551;
                v95 = y < 10;
                v94 = !(y < 10);
                v19 = -1651491551;
                if ( (((((v94 | (unsigned char)!(((((unsigned char)x - 1) * (unsigned char)x) & 1) == 0)) & 1) == 0) | (unsigned char)(v94 ^ !(((((unsigned char)x - 1) * (unsigned char)x) & 1) == 0))) & 1) != 0 )
                  v19 = -1105488767;
                v185 = v19;
              }
              v177 = v182 + 1447535114;
              if ( v182 != -1447535114 )
                break;
              v185 = -1361975838;
            }
            v176 = v182 + 1377092966;
            if ( v182 != -1377092966 )
              break;
            v37 = -1068151734;
            if ( v197 )
              v37 = 1130690147;
            v185 = v37;
          }
          v175 = v182 + 1361975838;
          if ( v182 != -1361975838 )
            break;
          v35 = 1844111039;
          if ( (y < 10) ^ (((((unsigned char)x - 1) * (unsigned char)x) & 1) == 0) | (y < 10 && ((((unsigned char)x - 1) * (unsigned char)x) & 1) == 0) )
            v35 = 1379958948;
          v185 = v35;
        }
        v174 = v182 + 1304707820;
        if ( v182 != -1304707820 )
          break;
        *v189 -= 66;
        v185 = 1752374020;
      }
      v173 = v182 + 1105488767;
      if ( v182 != -1105488767 )
        break;
      v20 = -1651491551;
      *v189 = *v192 + 5 * *v189;
      v196 = *v189 & 3;
      if ( (y < 10) ^ (((((unsigned char)x - 1) * (unsigned char)x) & 1) == 0) | (y < 10 && ((((unsigned char)x - 1) * (unsigned char)x) & 1) == 0) )
        v20 = 1308418190;
      v185 = v20;
    }
    v172 = v182 + 1074287435;
    if ( v182 == -1074287435 )
      break;
    v171 = v182 + 1068151734;
    if ( v182 == -1068151734 )
    {
      v81 = -330460440;
      v80 = !(y < 10);
      v40 = -330460440;
      if ( (((((v80 | (unsigned char)!(((((unsigned char)x - 1) * (unsigned char)x) & 1) == 0)) & 1) == 0) | (unsigned char)(v80 ^ !(((((unsigned char)x - 1) * (unsigned char)x) & 1) == 0))) & 1) != 0 )
        v40 = 1095172522;
      v185 = v40;
    }
    else
    {
      v170 = v182 + 959981951;
      if ( v182 == -959981951 )
      {
        v12 = 1083669275;
        if ( v194 )
          v12 = 364895568;
        v185 = v12;
      }
      else
      {
        v169 = v182 + 950294055;
        if ( v182 == -950294055 )
        {
          v25 = 500092720;
          *v189 = *v189 & 0xFFFFFFBD | ~(unsigned char)*v189 & 0x42;
          if ( (y < 10) ^ (((((unsigned char)x - 1) * (unsigned char)x) & 1) == 0) | (y < 10 && ((((unsigned char)x - 1) * (unsigned char)x) & 1) == 0) )
            v25 = 2030706667;
          v185 = v25;
        }
        else
        {
          v168 = v182 + 929715150;
          if ( v182 == -929715150 )
          {
            v39 = 778274193;
            *v189 += *v190 * *((char *)s + (*v193)++);
            if ( (y < 10) ^ (((((unsigned char)x - 1) * (unsigned char)x) & 1) == 0) | (y < 10 && ((((unsigned char)x - 1) * (unsigned char)x) & 1) == 0) )
              v39 = 772307190;
            v185 = v39;
          }
          else
          {
            v167 = v182 + 917904435;
            if ( v182 == -917904435 )
            {
              v188 = (unsigned int **)v55;
              v189 = (unsigned int *)v55;
              v190 = v55;
              s = &v56[-28];
              v123 = 0;
              v122 = (int *)v55;
              v192 = v55;
              v193 = v55;
              v121 = 100;
              v120 = (int *)v55;
              v119 = (unsigned int **)v55;
              tv = (struct timeval *)v55;
              v117 = (int *)v55;
              memset(&v56[-28], 0, 0x64u);
              *v120 = 0;
              v3 = gettimeofday(tv, 0);
              v4 = v117;
              *v117 = tv->tv_sec;
              v5 = *v4;
              v116 = v3;
              v6 = ~(v5 & (v5 ^ 0xAFDEEEDF));
              v115 = v5 & (v5 ^ 0xAFDEEEDF);
              v114 = 1245210162;
              v113 = v6 & 0xB5C799CD;
              format = "Please enter password:";
              v111 = v115 & 0x4A386632;
              v110 = 0x2000000;
              v109 = 885365196;
              v108 = v115 & 0x4A386632 | v6 & 0xB5C799CD;
              *v190 = (~(~*v117 | 0xAFDEEEDF) & 0xAFD6A6CF | (~*v117 | 0xAFDEEEDF) & 0x50295930)
                    + (~(v6 | 0x7CFDFFFE) | v108 ^ 0x36C599CC);
              *v189 = **v119 + 650604291;
              v107 = printf(format);
              v7 = scanf("%s", s);
              *v192 = **v119;
              v106 = v7;
              v105 = 100;
              v8 = strncmp((const char *)s, "secret", 0x64u);
              v9 = 547843145;
              v10 = v122;
              *v122 = v8;
              *v120 = (*v10 != 0) ^ *v120 | (*v10 != 0) & *v120;
              v11 = v120;
              *v120 = (*v192 != *v190) ^ *v120 | (*v192 != *v190) & *v120;
              v194 = *v11 != 0;
              if ( (y < 10) ^ (((((unsigned char)x - 1) * (unsigned char)x) & 1) == 0) | (y < 10
                                                                       && ((((unsigned char)x - 1) * (unsigned char)x) & 1) == 0) )
                v9 = -959981951;
              v185 = v9;
            }
            else
            {
              v166 = v182 + 908470324;
              if ( v182 == -908470324 )
              {
                v18 = 84624736;
                if ( v195 )
                  v18 = -1503386729;
                v185 = v18;
              }
              else
              {
                v165 = v182 + 615617076;
                if ( v182 == -615617076 )
                {
                  v185 = 1023171243;
                }
                else
                {
                  v164 = v182 + 534811398;
                  if ( v182 == -534811398 )
                  {
                    v23 = 173950559;
                    if ( !v196 )
                      v23 = -437569870;
                    v185 = v23;
                  }
                  else
                  {
                    v163 = v182 + 517899469;
                    if ( v182 == -517899469 )
                    {
                      *v193 = 0;
                      v90 = -1992264890;
                      v89 = y < 10;
                      v88 = 0;
                      v34 = -1992264890;
                      if ( ((((unsigned char)!(y < 10) | (unsigned char)!(((((unsigned char)x - 1) * (unsigned char)x) & 1) == 0)) & 1) == 0) | (y < 10) ^ (((((unsigned char)x - 1) * (unsigned char)x) & 1) == 0) )
                        v34 = -1447535114;
                      v185 = v34;
                    }
                    else
                    {
                      v162 = v182 + 444484485;
                      if ( v182 == -444484485 )
                      {
                        v31 = 156191264;
                        if ( (y < 10) ^ (((((unsigned char)x - 1) * (unsigned char)x) & 1) == 0) | (y < 10
                                                                                 && ((((unsigned char)x - 1) * (unsigned char)x) & 1) == 0) )
                          v31 = 1134014071;
                        v185 = v31;
                      }
                      else
                      {
                        v161 = v182 + 437569870;
                        if ( v182 == -437569870 )
                        {
                          v24 = 500092720;
                          if ( (y < 10) ^ (((((unsigned char)x - 1) * (unsigned char)x) & 1) == 0) | (y < 10
                                                                                   && ((((unsigned char)x - 1) * (unsigned char)x) & 1) == 0) )
                            v24 = -950294055;
                          v185 = v24;
                        }
                        else
                        {
                          v160 = v182 + 330460440;
                          if ( v182 == -330460440 )
                          {
                            v185 = 1095172522;
                          }
                          else
                          {
                            v159 = v182 + 74044621;
                            if ( v182 == -74044621 )
                            {
                              v28 = 838844388;
                              *v189 += 66;
                              if ( (y < 10) ^ (((((unsigned char)x - 1) * (unsigned char)x) & 1) == 0) | (y < 10
                                                                                       && ((((unsigned char)x - 1) * (unsigned char)x) & 1) == 0) )
                                v28 = 1364524005;
                              v185 = v28;
                            }
                            else
                            {
                              v158 = v182 + 5880276;
                              if ( v182 == -5880276 )
                              {
                                v185 = -444484485;
                              }
                              else
                              {
                                v157 = v182 - 77583267;
                                if ( v182 == 77583267 )
                                {
                                  v43 = 717248173;
                                  **v188 = *v189 & 0xE8CF9C3E | ~*v189 & 0x173063C1;
                                  if ( (y < 10) ^ (((((unsigned char)x - 1) * (unsigned char)x) & 1) == 0) | (y < 10
                                                                                           && ((((unsigned char)x - 1) * (unsigned char)x) & 1) == 0) )
                                    v43 = -1074287435;
                                  v185 = v43;
                                }
                                else
                                {
                                  v156 = v182 - 84624736;
                                  if ( v182 == 84624736 )
                                  {
                                    v33 = -1992264890;
                                    if ( (y < 10) ^ (((((unsigned char)x - 1) * (unsigned char)x) & 1) == 0) | (y < 10
                                                                                             && ((((unsigned char)x - 1)
                                                                                                * (unsigned char)x) & 1) == 0) )
                                      v33 = -517899469;
                                    v185 = v33;
                                  }
                                  else
                                  {
                                    v155 = v182 - 88222453;
                                    if ( v182 == 88222453 )
                                    {
                                      v29 = -1304707820;
                                      if ( (y < 10) ^ (((((unsigned char)x - 1) * (unsigned char)x) & 1) == 0) | (y < 10
                                                                                               && ((((unsigned char)x - 1)
                                                                                                  * (unsigned char)x) & 1) == 0) )
                                        v29 = 1752374020;
                                      v185 = v29;
                                    }
                                    else
                                    {
                                      v154 = v182 - 120229909;
                                      if ( v182 == 120229909 )
                                      {
                                        v185 = 451594427;
                                        v56[3] = *v189;
                                      }
                                      else
                                      {
                                        v153 = v182 - 156191264;
                                        if ( v182 == 156191264 )
                                        {
                                          v185 = 1134014071;
                                        }
                                        else
                                        {
                                          v152 = v182 - 158741209;
                                          if ( v182 == 158741209 )
                                          {
                                            v185 = 1023171243;
                                          }
                                          else
                                          {
                                            v151 = v182 - 173950559;
                                            if ( v182 == 173950559 )
                                            {
                                              v185 = 88222453;
                                            }
                                            else
                                            {
                                              v150 = v182 - 364895568;
                                              if ( v182 == 364895568 )
                                              {
                                                v13 = 2067663704;
                                                if ( (y < 10) ^ (((((unsigned char)x - 1) * (unsigned char)x) & 1) == 0) | (y < 10 && ((((unsigned char)x - 1) * (unsigned char)x) & 1) == 0) )
                                                  v13 = 1357889599;
                                                v185 = v13;
                                              }
                                              else
                                              {
                                                v149 = v182 - 451594427;
                                                if ( v182 == 451594427 )
                                                {
                                                  v16 = *v189;
                                                  v99 = 120229909;
                                                  v195 = (v16 & (v16 ^ 0xFFFFFFFE)) != 0;
                                                  v98 = y < 10;
                                                  v97 = 0;
                                                  v17 = 120229909;
                                                  if ( ((((unsigned char)!(y < 10) | (unsigned char)!(((((unsigned char)x - 1) * (unsigned char)x) & 1) == 0)) & 1) == 0) | (y < 10) ^ (((((unsigned char)x - 1) * (unsigned char)x) & 1) == 0) )
                                                    v17 = -908470324;
                                                  v185 = v17;
                                                }
                                                else
                                                {
                                                  v148 = v182 - 500092720;
                                                  if ( v182 == 500092720 )
                                                  {
                                                    *v189 = *v189 & 0xFFFFFFBD | ~(unsigned char)*v189 & 0x42;
                                                    v185 = -950294055;
                                                  }
                                                  else
                                                  {
                                                    v147 = v182 - 547843145;
                                                    if ( v182 == 547843145 )
                                                    {
                                                      v74 = 0;
                                                      v73 = (struct timeval *)v55;
                                                      v72 = (int *)v55;
                                                      s1 = (char *)&v56[-28];
                                                      v70 = v55;
                                                      v69 = (int *)v55;
                                                      v68 = v55;
                                                      v67 = v55;
                                                      v66 = 100;
                                                      v65 = (unsigned int **)v55;
                                                      v64 = v55;
                                                      memset(&v56[-28], 0, 0x64u);
                                                      *v70 = 0;
                                                      v44 = gettimeofday(v73, 0);
                                                      v45 = v72;
                                                      *v72 = v73->tv_sec;
                                                      v46 = *v45;
                                                      v63 = v44;
                                                      v47 = v46 & (v46 ^ 0xAFDEEEDF) ^ 0x83020001 | v46 & (v46 ^ 0xAFDEEEDF) & 0x83020001;
                                                      v48 = *v72;
                                                      v62 = -1344344353;
                                                      v61 = "Please enter password:";
                                                      *v67 = ((v48 & (v48 ^ 0xAFDEEEDF) & 0xFC9DFA46 | ~(v48 & (v48 ^ 0xAFDEEEDF)) & 0x36205B9) ^ 0x534B5C89)
                                                           + v47;
                                                      *v64 = **v65 + 650604291;
                                                      v60 = printf(v61);
                                                      v49 = scanf("%s", s1);
                                                      *v68 = **v65;
                                                      v59 = v49;
                                                      v58 = 100;
                                                      v50 = strncmp(s1, "secret", 0x64u);
                                                      v51 = v69;
                                                      *v69 = v50;
                                                      v52 = *v51 != 0;
                                                      v53 = ~*v70 & 0x3090ABA;
                                                      v54 = *v70 & 0xFCF6F545;
                                                      v57 = ~*v70;
                                                      *v70 = ~(~v52 | v57) | (v52 & 0xFCF6F545 | ~v52 & 0x3090ABA) ^ (v54 | v53);
                                                      *v70 = (*v68 != *v67) ^ *v70 | (*v68 != *v67) & *v70;
                                                      v185 = -917904435;
                                                    }
                                                    else
                                                    {
                                                      v146 = v182 - 717248173;
                                                      if ( v182 == 717248173 )
                                                      {
                                                        **v188 = (*v189 & 0xCD536960 | ~*v189 & 0x32AC969F) ^ 0x259CF55E;
                                                        v185 = 77583267;
                                                      }
                                                      else
                                                      {
                                                        v145 = v182 - 731295049;
                                                        if ( v182 == 731295049 )
                                                        {
                                                          v185 = 1083669275;
                                                        }
                                                        else
                                                        {
                                                          v144 = v182 - 772307190;
                                                          if ( v182 == 772307190 )
                                                          {
                                                            v185 = -1361975838;
                                                          }
                                                          else
                                                          {
                                                            v143 = v182 - 778274193;
                                                            if ( v182 == 778274193 )
                                                            {
                                                              *v189 += *v190 * *((char *)s + (*v193)++);
                                                              v185 = -929715150;
                                                            }
                                                            else
                                                            {
                                                              v142 = v182 - 838844388;
                                                              if ( v182 == 838844388 )
                                                              {
                                                                *v189 += 66;
                                                                v185 = -74044621;
                                                              }
                                                              else
                                                              {
                                                                v141 = v182 - 1023171243;
                                                                if ( v182 == 1023171243 )
                                                                {
                                                                  v76 = 717248173;
                                                                  v75 = !(y < 10);
                                                                  v42 = 717248173;
                                                                  if ( (((((v75 | (unsigned char)!(((((unsigned char)x - 1) * (unsigned char)x) & 1) == 0)) & 1) == 0) | (unsigned char)(v75 ^ !(((((unsigned char)x - 1) * (unsigned char)x) & 1) == 0))) & 1) != 0 )
                                                                    v42 = 77583267;
                                                                  v185 = v42;
                                                                }
                                                                else
                                                                {
                                                                  v140 = v182 - 1083669275;
                                                                  if ( v182 == 1083669275 )
                                                                  {
                                                                    v101 = 120229909;
                                                                    v100 = !(y < 10);
                                                                    v15 = 120229909;
                                                                    if ( (((((v100 | (unsigned char)!(((((unsigned char)x - 1) * (unsigned char)x) & 1) == 0)) & 1) == 0) | (unsigned char)(v100 ^ !(((((unsigned char)x - 1) * (unsigned char)x) & 1) == 0))) & 1) != 0 )
                                                                      v15 = 451594427;
                                                                    v185 = v15;
                                                                  }
                                                                  else
                                                                  {
                                                                    v139 = v182 - 1095172522;
                                                                    if ( v182 == 1095172522 )
                                                                    {
                                                                      v79 = -330460440;
                                                                      v78 = y < 10;
                                                                      v77 = !(y < 10);
                                                                      v41 = -330460440;
                                                                      if ( (((((v77 | (unsigned char)!(((((unsigned char)x - 1) * (unsigned char)x) & 1) == 0)) & 1) == 0) | (unsigned char)(v77 ^ !(((((unsigned char)x - 1) * (unsigned char)x) & 1) == 0))) & 1) != 0 )
                                                                        v41 = 158741209;
                                                                      v185 = v41;
                                                                    }
                                                                    else
                                                                    {
                                                                      v138 = v182 - 1130690147;
                                                                      if ( v182 == 1130690147 )
                                                                      {
                                                                        v84 = 778274193;
                                                                        v83 = y < 10;
                                                                        v82 = !(y < 10);
                                                                        v38 = 778274193;
                                                                        if ( (((((v82 | (unsigned char)!(((((unsigned char)x - 1) * (unsigned char)x) & 1) == 0)) & 1) == 0) | (unsigned char)(v82 ^ !(((((unsigned char)x - 1) * (unsigned char)x) & 1) == 0))) & 1) != 0 )
                                                                          v38 = -929715150;
                                                                        v185 = v38;
                                                                      }
                                                                      else
                                                                      {
                                                                        v137 = v182 - 1134014071;
                                                                        if ( v182 == 1134014071 )
                                                                        {
                                                                          v32 = 156191264;
                                                                          if ( (y < 10) ^ (((((unsigned char)x - 1) * (unsigned char)x) & 1) == 0) | (y < 10 && ((((unsigned char)x - 1) * (unsigned char)x) & 1) == 0) )
                                                                            v32 = -615617076;
                                                                          v185 = v32;
                                                                        }
                                                                        else
                                                                        {
                                                                          v136 = v182 - 1308418190;
                                                                          if ( v182 == 1308418190 )
                                                                          {
                                                                            v185 = 1948034374;
                                                                          }
                                                                          else
                                                                          {
                                                                            v135 = v182 - 1357889599;
                                                                            if ( v182 == 1357889599 )
                                                                            {
                                                                              **v188 = 0;
                                                                              v104 = 2067663704;
                                                                              v103 = y < 10;
                                                                              v102 = !(y < 10);
                                                                              v14 = 2067663704;
                                                                              if ( (((((v102 | (unsigned char)!(((((unsigned char)x - 1) * (unsigned char)x) & 1) == 0)) & 1) == 0) | (unsigned char)(v102 ^ !(((((unsigned char)x - 1) * (unsigned char)x) & 1) == 0))) & 1) != 0 )
                                                                                v14 = 731295049;
                                                                              v185 = v14;
                                                                            }
                                                                            else
                                                                            {
                                                                              v134 = v182 - 1364524005;
                                                                              if ( v182 == 1364524005 )
                                                                              {
                                                                                v185 = -444484485;
                                                                              }
                                                                              else
                                                                              {
                                                                                v133 = v182 - 1379958948;
                                                                                if ( v182 == 1379958948 )
                                                                                {
                                                                                  v197 = *v193 < 0x64u;
                                                                                  v87 = 1844111039;
                                                                                  v86 = y < 10;
                                                                                  v85 = 0;
                                                                                  v36 = 1844111039;
                                                                                  if ( ((((unsigned char)!(y < 10) | (unsigned char)!(((((unsigned char)x - 1) * (unsigned char)x) & 1) == 0)) & 1) == 0) | (y < 10) ^ (((((unsigned char)x - 1) * (unsigned char)x) & 1) == 0) )
                                                                                    v36 = -1377092966;
                                                                                  v185 = v36;
                                                                                }
                                                                                else
                                                                                {
                                                                                  v132 = v182 - 1597923837;
                                                                                  if ( v182 == 1597923837 )
                                                                                  {
                                                                                    v26 = 838844388;
                                                                                    v27 = (((unsigned char)x - 57 + 56)
                                                                                         * (unsigned char)x) & 1;
                                                                                    if ( (y < 10) ^ (v27 == 0) | (y < 10 && v27 == 0) )
                                                                                      v26 = -74044621;
                                                                                    v185 = v26;
                                                                                  }
                                                                                  else
                                                                                  {
                                                                                    v131 = v182 - 1752374020;
                                                                                    if ( v182 == 1752374020 )
                                                                                    {
                                                                                      *v189 -= 66;
                                                                                      v93 = -1304707820;
                                                                                      v92 = y < 10;
                                                                                      v91 = !(y < 10);
                                                                                      v30 = -1304707820;
                                                                                      if ( (((((v91 | (unsigned char)!(((((unsigned char)x - 1) * (unsigned char)x) & 1) == 0)) & 1) == 0) | (unsigned char)(v91 ^ !(((((unsigned char)x - 1) * (unsigned char)x) & 1) == 0))) & 1) != 0 )
                                                                                        v30 = -5880276;
                                                                                      v185 = v30;
                                                                                    }
                                                                                    else
                                                                                    {
                                                                                      v130 = v182 - 1844111039;
                                                                                      if ( v182 == 1844111039 )
                                                                                      {
                                                                                        v185 = 1379958948;
                                                                                        v56[1] = *v193;
                                                                                      }
                                                                                      else
                                                                                      {
                                                                                        v129 = v182 - 1864864255;
                                                                                        if ( v182 == 1864864255 )
                                                                                        {
                                                                                          v125 = 547843145;
                                                                                          v124 = !v187;
                                                                                          v2 = 547843145;
                                                                                          if ( ((((unsigned char)!v187 | (unsigned char)!v186) & 1) == 0) | v187 & 1 ^ v186 & 1 )
                                                                                            v2 = -917904435;
                                                                                          v185 = v2;
                                                                                        }
                                                                                        else
                                                                                        {
                                                                                          v128 = v182 - 1948034374;
                                                                                          if ( v182 == 1948034374 )
                                                                                          {
                                                                                            v21 = -1559035902;
                                                                                            if ( v196 < 1 )
                                                                                              v21 = -534811398;
                                                                                            v185 = v21;
                                                                                          }
                                                                                          else
                                                                                          {
                                                                                            v127 = v182 - 2030706667;
                                                                                            if ( v182 == 2030706667 )
                                                                                            {
                                                                                              v185 = -444484485;
                                                                                            }
                                                                                            else
                                                                                            {
                                                                                              v126 = v182 - 2067663704;
                                                                                              if ( v182 == 2067663704 )
                                                                                              {
                                                                                                **v188 = 0;
                                                                                                v185 = 1357889599;
                                                                                              }
                                                                                            }
                                                                                          }
                                                                                        }
                                                                                      }
                                                                                    }
                                                                                  }
                                                                                }
                                                                              }
                                                                            }
                                                                          }
                                                                        }
                                                                      }
                                                                    }
                                                                  }
                                                                }
                                                              }
                                                            }
                                                          }
                                                        }
                                                      }
                                                    }
                                                  }
                                                }
                                              }
                                            }
                                          }
                                        }
                                      }
                                    }
                                  }
                                }
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
