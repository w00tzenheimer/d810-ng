#include "platform.h"

struct timeval {
  long tv_sec;
  int tv_usec;
};

extern int gettimeofday(struct timeval *tv, void *tz);
extern int printf(char const *format, ...);
extern int scanf(char const *format, ...);
extern int strncmp(char const *s1, char const *s2, unsigned int maxlen);

// https://github.com/Neutrino6/thesis_project/blob/main/C_files_analysis/C_obfuscated/minmaxarray_tigress.c
/** Original code:
 *  #include<stdio.h>
 *  int main(int argc, char* argv[]){
 *  if(argc < 11) return 1;
 *   int a[10],i,big,small;
 *
 *   //  printf("\nEnter the size of the array: ");
 *   //  scanf("%d",&size);
 *   //  printf("\nEnter %d elements in to the array: ", size);
 *   //  for(i=0;i<size;i++)
 *   //      scanf("%d",&a[i]);
 *
 *   for(i=1;i<argc;i++)
 *       a[i-1] = argv[i][0];
 *
 *   big=a[0];
 *   for(i=1;i<argc-1;i++){
 *       if(big<a[i])
 *           big=a[i];
 *   }
 *   printf("Largest element: %d\n",big);
 *
 *   small=a[0];
 *   for(i=1;i<argc-1;i++){
 *       if(small>a[i])
 *           small=a[i];
 *   }
 *   printf("Smallest element: %d\n",small);
 *
 *   return 0;
 *   }
 */

extern int printf2(char const   * __restrict  __format  , ...);


int _global_argc;
char **_global_argv;
char **_global_envp;

EXPORT int tigress_minmaxarray(int argc , char **argv , char **_formal_envp ) 
{ 
  int a[10] ;
  int i ;
  int big ;
  int small ;
  int _BARRIER_0 ;
  unsigned long _1_main_next ;

  {
  {
  {
  {
  {
  goto _global_envp_i$nit_INLINE__global_envp_i$nit;
  }
  _global_envp_i$nit_INLINE__global_envp_i$nit: /* CIL Label */ ;
  }
  {
  {
  goto _global_argv_i$nit_INLINE__global_argv_i$nit;
  }
  _global_argv_i$nit_INLINE__global_argv_i$nit: /* CIL Label */ ;
  }
  {
  {
  goto _global_argc_i$nit_INLINE__global_argc_i$nit;
  }
  _global_argc_i$nit_INLINE__global_argc_i$nit: /* CIL Label */ ;
  }
  goto megaInit_INLINE_megaInit;
  }
  megaInit_INLINE_megaInit: /* CIL Label */ ;
  }
  _global_argc = argc;
  _global_argv = argv;
  _global_envp = _formal_envp;
  _BARRIER_0 = 1;
  {
  _1_main_next = 11UL;
  }
  while (1) {
    switch (_1_main_next) {
    case 18: 
    small = a[i];
    {
    _1_main_next = 3UL;
    }
    break;
    case 4: ;
    if (argc < 11) {
      {
      _1_main_next = 9UL;
      }
    } else {
      {
      _1_main_next = 13UL;
      }
    }
    break;
    case 14: ;
    if (small > a[i]) {
      {
      _1_main_next = 18UL;
      }
    } else {
      {
      _1_main_next = 3UL;
      }
    }
    break;
    case 15: ;
    if (i < argc - 1) {
      {
      _1_main_next = 14UL;
      }
    } else {
      {
      _1_main_next = 22UL;
      }
    }
    break;
    case 12: 
    big = a[0];
    i = 1;
    {
    _1_main_next = 17UL;
    }
    break;
    case 8: ;
    if (big < a[i]) {
      {
      _1_main_next = 1UL;
      }
    } else {
      {
      _1_main_next = 16UL;
      }
    }
    break;
    case 1: 
    big = a[i];
    {
    _1_main_next = 16UL;
    }
    break;
    case 23: ;
    if (i < argc) {
      {
      _1_main_next = 0UL;
      }
    } else {
      {
      _1_main_next = 12UL;
      }
    }
    break;
    case 3: 
    i ++;
    {
    _1_main_next = 15UL;
    }
    break;
    case 16: 
    i ++;
    {
    _1_main_next = 17UL;
    }
    break;
    case 11: ;
    {
    _1_main_next = 4UL;
    }
    break;
    case 9: ;
    return (1);
    break;
    case 13: 
    i = 1;
    {
    _1_main_next = 23UL;
    }
    break;
    case 19: ;
    return (0);
    break;
    case 17: ;
    if (i < argc - 1) {
      {
      _1_main_next = 8UL;
      }
    } else {
      {
      _1_main_next = 7UL;
      }
    }
    break;
    case 22: 
    printf2((char const   */* __restrict  */)"Smallest element: %d\n", small);
    {
    _1_main_next = 19UL;
    }
    break;
    case 0: 
    a[i - 1] = (int )*(*(argv + i) + 0);
    i ++;
    {
    _1_main_next = 23UL;
    }
    break;
    case 7: 
    printf2((char const   */* __restrict  */)"Largest element: %d\n", big);
    small = a[0];
    i = 1;
    {
    _1_main_next = 15UL;
    }
    break;
    }
  }
}
}

EXPORT void tigress_flatten_indirect(unsigned int *input, unsigned int *output)
{
  unsigned int local_state;
  unsigned int ref_input_value;
  struct timeval time_info;
  unsigned int nb_seconds;
  char password[100];
  unsigned int tmp;
  unsigned int failed;
  unsigned int stringCompareResult;
  unsigned int activationCode;
  unsigned int i;
  int tmp___0;
  volatile unsigned long _3_tigress_flatten_indirect_next;
  void *_3_tigress_flatten_indirect_jumpTab[37] = {
      &&_3_tigress_flatten_indirect_lab1,
      &&_3_tigress_flatten_indirect_lab2,
      &&_3_tigress_flatten_indirect_lab3,
      &&_3_tigress_flatten_indirect_lab4,
      &&_3_tigress_flatten_indirect_lab5,
      &&_3_tigress_flatten_indirect_lab1,
      &&_3_tigress_flatten_indirect_lab7,
      &&_3_tigress_flatten_indirect_lab8,
      &&_3_tigress_flatten_indirect_lab9,
      &&_3_tigress_flatten_indirect_lab1,
      &&_3_tigress_flatten_indirect_lab11,
      &&_3_tigress_flatten_indirect_lab12,
      &&_3_tigress_flatten_indirect_lab13,
      &&_3_tigress_flatten_indirect_lab1,
      &&_3_tigress_flatten_indirect_lab15,
      &&_3_tigress_flatten_indirect_lab1,
      &&_3_tigress_flatten_indirect_lab17,
      &&_3_tigress_flatten_indirect_lab18,
      &&_3_tigress_flatten_indirect_lab19,
      &&_3_tigress_flatten_indirect_lab20,
      &&_3_tigress_flatten_indirect_lab21,
      &&_3_tigress_flatten_indirect_lab22,
      &&_3_tigress_flatten_indirect_lab23,
      &&_3_tigress_flatten_indirect_lab1,
      &&_3_tigress_flatten_indirect_lab25,
      &&_3_tigress_flatten_indirect_lab26,
      &&_3_tigress_flatten_indirect_lab27,
      &&_3_tigress_flatten_indirect_lab28,
      &&_3_tigress_flatten_indirect_lab29,
      &&_3_tigress_flatten_indirect_lab30,
      &&_3_tigress_flatten_indirect_lab1,
      &&_3_tigress_flatten_indirect_lab32,
      &&_3_tigress_flatten_indirect_lab33,
      &&_3_tigress_flatten_indirect_lab34,
      &&_3_tigress_flatten_indirect_lab35,
      &&_3_tigress_flatten_indirect_lab36,
      &&_3_tigress_flatten_indirect_lab37};

  _3_tigress_flatten_indirect_next = 34UL;
  goto *(_3_tigress_flatten_indirect_jumpTab[_3_tigress_flatten_indirect_next - 1]);

_3_tigress_flatten_indirect_lab35:
  scanf("%s", password);
  _3_tigress_flatten_indirect_next = 26UL;
  goto *(_3_tigress_flatten_indirect_jumpTab[_3_tigress_flatten_indirect_next - 1]);

_3_tigress_flatten_indirect_lab12:
  i = 0U;
  _3_tigress_flatten_indirect_next = 28UL;
  goto *(_3_tigress_flatten_indirect_jumpTab[_3_tigress_flatten_indirect_next - 1]);

_3_tigress_flatten_indirect_lab25:
  password[tmp] = (char)0;
  _3_tigress_flatten_indirect_next = 15UL;
  goto *(_3_tigress_flatten_indirect_jumpTab[_3_tigress_flatten_indirect_next - 1]);

_3_tigress_flatten_indirect_lab4:
  failed = 0U;
  _3_tigress_flatten_indirect_next = 1UL;
  goto *(_3_tigress_flatten_indirect_jumpTab[_3_tigress_flatten_indirect_next - 1]);

_3_tigress_flatten_indirect_lab19:
  failed = (failed & ~((unsigned int)((int)((((((activationCode - ref_input_value) + (activationCode - ref_input_value)) & ((int)(activationCode - ref_input_value) >> 31)) - (activationCode - ref_input_value)) >> 31U) & 1U)))) + (unsigned int)((int)((((((activationCode - ref_input_value) + (activationCode - ref_input_value)) & ((int)(activationCode - ref_input_value) >> 31)) - (activationCode - ref_input_value)) >> 31U) & 1U));
  _3_tigress_flatten_indirect_next = 33UL;
  goto *(_3_tigress_flatten_indirect_jumpTab[_3_tigress_flatten_indirect_next - 1]);

_3_tigress_flatten_indirect_lab22:
  stringCompareResult = (unsigned int)tmp___0;
  _3_tigress_flatten_indirect_next = 27UL;
  goto *(_3_tigress_flatten_indirect_jumpTab[_3_tigress_flatten_indirect_next - 1]);

_3_tigress_flatten_indirect_lab1:
  gettimeofday(&time_info, (void *)0);
  _3_tigress_flatten_indirect_next = 3UL;
  goto *(_3_tigress_flatten_indirect_jumpTab[_3_tigress_flatten_indirect_next - 1]);

_3_tigress_flatten_indirect_lab7:
  printf("Please enter password:");
  _3_tigress_flatten_indirect_next = 35UL;
  goto *(_3_tigress_flatten_indirect_jumpTab[_3_tigress_flatten_indirect_next - 1]);

_3_tigress_flatten_indirect_lab23:
  return;

_3_tigress_flatten_indirect_lab9:
  tmp___0 = strncmp((char const *)(password), "secret", 100U);
  _3_tigress_flatten_indirect_next = 22UL;
  goto *(_3_tigress_flatten_indirect_jumpTab[_3_tigress_flatten_indirect_next - 1]);

_3_tigress_flatten_indirect_lab32:
  local_state = ((local_state ^ ~(((unsigned int)password[i] & ref_input_value) * ((unsigned int)password[i] | ref_input_value) + ((unsigned int)password[i] & ~ref_input_value) * (~((unsigned int)password[i]) & ref_input_value))) + ((local_state | (((unsigned int)password[i] & ref_input_value) * ((unsigned int)password[i] | ref_input_value) + ((unsigned int)password[i] & ~ref_input_value) * (~((unsigned int)password[i]) & ref_input_value))) + (local_state | (((unsigned int)password[i] & ref_input_value) * ((unsigned int)password[i] | ref_input_value) + ((unsigned int)password[i] & ~ref_input_value) * (~((unsigned int)password[i]) & ref_input_value))))) + 1U;
  _3_tigress_flatten_indirect_next = 21UL;
  goto *(_3_tigress_flatten_indirect_jumpTab[_3_tigress_flatten_indirect_next - 1]);

_3_tigress_flatten_indirect_lab33:
  if (failed) {
    _3_tigress_flatten_indirect_next = 2UL;
  } else {
    _3_tigress_flatten_indirect_next = 5UL;
  }
  goto *(_3_tigress_flatten_indirect_jumpTab[_3_tigress_flatten_indirect_next - 1]);

_3_tigress_flatten_indirect_lab3:
  nb_seconds = (unsigned int)(((~time_info.tv_sec | 4294967295L) + time_info.tv_sec) + 1L);
  _3_tigress_flatten_indirect_next = 18UL;
  goto *(_3_tigress_flatten_indirect_jumpTab[_3_tigress_flatten_indirect_next - 1]);

_3_tigress_flatten_indirect_lab8:
  local_state = ((local_state ^ ~66U) + ((local_state | 66U) << 1U)) + 1U;
  _3_tigress_flatten_indirect_next = 11UL;
  goto *(_3_tigress_flatten_indirect_jumpTab[_3_tigress_flatten_indirect_next - 1]);

_3_tigress_flatten_indirect_lab34:
  password[0] = (char)'\000';
  _3_tigress_flatten_indirect_next = 20UL;
  goto *(_3_tigress_flatten_indirect_jumpTab[_3_tigress_flatten_indirect_next - 1]);

_3_tigress_flatten_indirect_lab27:
  failed = (failed & ~((unsigned int)((unsigned long)stringCompareResult != 0UL))) + (unsigned int)((unsigned long)stringCompareResult != 0UL);
  _3_tigress_flatten_indirect_next = 19UL;
  goto *(_3_tigress_flatten_indirect_jumpTab[_3_tigress_flatten_indirect_next - 1]);

_3_tigress_flatten_indirect_lab28:
  if ((int)((((~((unsigned long)i) & 100UL) | ((~((unsigned long)i) | 100UL) & ((unsigned long)i - 100UL))) >> 63UL) & 1UL)) {
    _3_tigress_flatten_indirect_next = 32UL;
  } else {
    _3_tigress_flatten_indirect_next = 11UL;
  }
  goto *(_3_tigress_flatten_indirect_jumpTab[_3_tigress_flatten_indirect_next - 1]);

_3_tigress_flatten_indirect_lab26:
  activationCode = *(input + 0UL);
  _3_tigress_flatten_indirect_next = 9UL;
  goto *(_3_tigress_flatten_indirect_jumpTab[_3_tigress_flatten_indirect_next - 1]);

_3_tigress_flatten_indirect_lab13:
  local_state = (local_state | 66U) - (local_state & 66U);
  _3_tigress_flatten_indirect_next = 11UL;
  goto *(_3_tigress_flatten_indirect_jumpTab[_3_tigress_flatten_indirect_next - 1]);

_3_tigress_flatten_indirect_lab11:
  *(output + 0UL) = (unsigned int)((((unsigned long)local_state - 389047233UL) - (((unsigned long)local_state | ~389047233UL) + ((unsigned long)local_state | ~389047233UL))) - 2UL);
  _3_tigress_flatten_indirect_next = 23UL;
  goto *(_3_tigress_flatten_indirect_jumpTab[_3_tigress_flatten_indirect_next - 1]);

_3_tigress_flatten_indirect_lab37:
  local_state = (unsigned int)(((unsigned long)*(input + 0UL) | 650604291UL) + ((unsigned long)*(input + 0UL) & 650604291UL));
  _3_tigress_flatten_indirect_next = 7UL;
  goto *(_3_tigress_flatten_indirect_jumpTab[_3_tigress_flatten_indirect_next - 1]);

_3_tigress_flatten_indirect_lab18:
  ref_input_value = ((((((((~nb_seconds | 1344344352U) + nb_seconds) + 1U) + 2197946369U) + 1U) + ((-(((~nb_seconds | 1344344352U) + nb_seconds) + 1U) - 1U) | (-2197946369U - 1U))) | (((((~nb_seconds | 1344344352U) - ~nb_seconds) - 1344887088U) - ((((~nb_seconds | 1344344352U) - ~nb_seconds) | ~1344887088U) + (((~nb_seconds | 1344344352U) - ~nb_seconds) | ~1344887088U))) - 2U)) + (((((((~nb_seconds | 1344344352U) + nb_seconds) + 1U) + 2197946369U) + 1U) + ((-(((~nb_seconds | 1344344352U) + nb_seconds) + 1U) - 1U) | (-2197946369U - 1U))) | (((((~nb_seconds | 1344344352U) - ~nb_seconds) - 1344887088U) - ((((~nb_seconds | 1344344352U) - ~nb_seconds) | ~1344887088U) + (((~nb_seconds | 1344344352U) - ~nb_seconds) | ~1344887088U))) - 2U))) - (((((((~nb_seconds | 1344344352U) + nb_seconds) + 1U) + 2197946369U) + 1U) + ((-(((~nb_seconds | 1344344352U) + nb_seconds) + 1U) - 1U) | (-2197946369U - 1U))) ^ (((((~nb_seconds | 1344344352U) - ~nb_seconds) - 1344887088U) - ((((~nb_seconds | 1344344352U) - ~nb_seconds) | ~1344887088U) + (((~nb_seconds | 1344344352U) - ~nb_seconds) | ~1344887088U))) - 2U));
  _3_tigress_flatten_indirect_next = 37UL;
  goto *(_3_tigress_flatten_indirect_jumpTab[_3_tigress_flatten_indirect_next - 1]);

_3_tigress_flatten_indirect_lab2:
  *(output + 0) = 0U;
  _3_tigress_flatten_indirect_next = 5UL;
  goto *(_3_tigress_flatten_indirect_jumpTab[_3_tigress_flatten_indirect_next - 1]);

_3_tigress_flatten_indirect_lab15:
  tmp = ((tmp ^ ~1U) + ((tmp | 1U) << 1U)) + 1U;
  _3_tigress_flatten_indirect_next = 29UL;
  goto *(_3_tigress_flatten_indirect_jumpTab[_3_tigress_flatten_indirect_next - 1]);

_3_tigress_flatten_indirect_lab21:
  i = (unsigned int)(((unsigned long)i - ~1UL) - 1UL);
  _3_tigress_flatten_indirect_next = 28UL;
  goto *(_3_tigress_flatten_indirect_jumpTab[_3_tigress_flatten_indirect_next - 1]);

_3_tigress_flatten_indirect_lab29:
  if ((int)((((~100U | tmp) & ((100U ^ tmp) | ~(tmp - 100U))) >> 31U) & 1U)) {
    _3_tigress_flatten_indirect_next = 4UL;
  } else {
    _3_tigress_flatten_indirect_next = 25UL;
  }
  goto *(_3_tigress_flatten_indirect_jumpTab[_3_tigress_flatten_indirect_next - 1]);

_3_tigress_flatten_indirect_lab5:
  if (((~local_state | 1U) + local_state) + 1U) {
    _3_tigress_flatten_indirect_next = 17UL;
  } else {
    _3_tigress_flatten_indirect_next = 12UL;
  }
  goto *(_3_tigress_flatten_indirect_jumpTab[_3_tigress_flatten_indirect_next - 1]);

_3_tigress_flatten_indirect_lab36:
  switch ((unsigned long)((int)local_state) % 4UL) {
  case 0UL:
    _3_tigress_flatten_indirect_next = 13UL;
    goto *(_3_tigress_flatten_indirect_jumpTab[_3_tigress_flatten_indirect_next - 1]);
  case 1UL:
    _3_tigress_flatten_indirect_next = 8UL;
    goto *(_3_tigress_flatten_indirect_jumpTab[_3_tigress_flatten_indirect_next - 1]);
  default:
    _3_tigress_flatten_indirect_next = 30UL;
    goto *(_3_tigress_flatten_indirect_jumpTab[_3_tigress_flatten_indirect_next - 1]);
  }

_3_tigress_flatten_indirect_lab30:
  local_state = (local_state + ~66U) + 1U;
  _3_tigress_flatten_indirect_next = 11UL;
  goto *(_3_tigress_flatten_indirect_jumpTab[_3_tigress_flatten_indirect_next - 1]);

_3_tigress_flatten_indirect_lab20:
  tmp = 1U;
  _3_tigress_flatten_indirect_next = 29UL;
  goto *(_3_tigress_flatten_indirect_jumpTab[_3_tigress_flatten_indirect_next - 1]);

_3_tigress_flatten_indirect_lab17:
  local_state = (((5U & local_state) * (5U | local_state) + (5U & ~local_state) * (~5U & local_state)) - ~activationCode) - 1U;
  _3_tigress_flatten_indirect_next = 36UL;
  goto *(_3_tigress_flatten_indirect_jumpTab[_3_tigress_flatten_indirect_next - 1]);
}
