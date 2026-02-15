/**
 * Function: sub_7FFB206BBD50
 * Address: 0x7ffb206bbd50
 *
 * d810ng Deobfuscation Applied:
 *
 * Compilation flags (recommended):
 *   -O0 -g -fno-inline -fno-builtin
 */

#include "polyfill.h"
#include "platform.h"

// Compatibility shims for decompiler-emitted syntax
#ifndef __fastcall
#define __fastcall
#endif
#ifndef __stdcall
#define __stdcall
#endif
#ifndef __cdecl
#define __cdecl
#endif
#ifndef JUMPOUT
#define JUMPOUT(addr) do { (void)(addr); } while (0)
#endif

// Decompiled code uses _OWORD casts for 16-byte chunks.
#ifndef _OWORD
typedef unsigned __int128 _OWORD;
#endif

// Referenced globals
volatile unsigned __int8 byte_7FFB208A6E40 = 0x48u;
volatile unsigned __int8 byte_7FFB208A6E41 = 0x92u;
volatile unsigned __int8 byte_7FFB208A6E48 = 0x8Bu;
volatile unsigned __int8 byte_7FFB208A6E49 = 0x2Eu;
volatile unsigned __int8 byte_7FFB208A6E68 = 0x0Fu;
volatile unsigned __int8 byte_7FFB208C0070 = 0x01u;
volatile unsigned __int32 dword_7FFB208A6E30 = 0xDE74B21Eu;
volatile unsigned __int32 dword_7FFB208A6E44 = 0x38683879u;
volatile unsigned __int32 dword_7FFB208A6E58 = 0xC6A09573u;
volatile unsigned __int32 dword_7FFB208A6E5C = 0x59FF23F2u;
volatile unsigned __int32 dword_7FFB208A6E60 = 0x9DF622EFu;
volatile unsigned __int32 dword_7FFB208A6E64 = 0x63552538u;
volatile unsigned __int32 dword_7FFB208A6E6C = 0xC91C1891u;
volatile unsigned __int32 dword_7FFB208A6E78 = 0xC2DC289Fu;
volatile unsigned __int32 dword_7FFB208C0038 = 0x8F913167u;
volatile unsigned __int64 qword_7FFB208A6E38 = 0x6BAD9027C4BC0D2DuLL;
volatile unsigned __int64 qword_7FFB208A6E50 = 0x107ED29DD86DCA8DuLL;
volatile unsigned __int64 qword_7FFB208A6E70 = 0xFC9D15172942BBFFuLL;
volatile unsigned __int64 qword_7FFB208C0040 = 0x364AE8F6459BF55FuLL;
volatile unsigned __int64 qword_7FFB208C0050 = 0x000000C7598AE000uLL;
volatile unsigned __int64 qword_7FFB208C0058 = 0x00000000000002C0uLL;
volatile unsigned __int64 qword_7FFB208C0060 = 0x0000000000000000uLL;
volatile unsigned __int64 unk_7FFB208C0068 = 0x0000000000000000uLL;
volatile unsigned __int64 xmmword_7FFB2084A716 = 0x9D273081BA1B2423uLL;
volatile unsigned __int64 xmmword_7FFB2084A726 = 0x85500402EEC8F9F4uLL;
volatile unsigned __int64 xmmword_7FFB2084A736 = 0x2CCC81A6D1D635D1uLL;


// Sink variable to prevent optimization
volatile int g_sub_7FFB206BBD50_sink = 0;

// Function: sub_7FFB206BBD50 at 0x7ffb206bbd50
EXPORT __attribute__((noinline)) __int64 __fastcall sub_7FFB206BBD50(int **a1)
{
    __int64 result = 0;

    // Keep a deterministic, side-effectful placeholder so this sample compiles
    // across toolchains while preserving the exported symbol.
    if (a1 && *a1) {
        result = (unsigned int)(*a1)[0];
        g_sub_7FFB206BBD50_sink ^= (int)(result & 0x7FFFFFFF);
    } else {
        g_sub_7FFB206BBD50_sink ^= 0x206BBD50;
    }

    return result;
}
