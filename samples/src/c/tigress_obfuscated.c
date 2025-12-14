#include "export.h"

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