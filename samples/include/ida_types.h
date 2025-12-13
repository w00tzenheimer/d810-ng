/*

   This file contains definitions used by the Hex-Rays decompiler output.
   It has type definitions and convenience macros to make the
   output more readable.

   Copyright (c) 2007-2018 Hex-Rays

*/

#ifndef HEXRAYS_DEFS_H
#define HEXRAYS_DEFS_H

#if defined(__GNUC__)
typedef long long ll;
typedef unsigned long long ull;
#define __int64 long long
#define __int32 int
#define __int16 short
#define __int8 char
#define MAKELL(num) num##LL
#define FMT_64 "ll"
#elif defined(_MSC_VER)
typedef __int64 ll;
typedef unsigned __int64 ull;
#define MAKELL(num) num##i64
#define FMT_64 "I64"
#elif defined(__BORLANDC__)
typedef __int64 ll;
typedef unsigned __int64 ull;
#define MAKELL(num) num##i64
#define FMT_64 "L"
#else
#error "unknown compiler"
#endif
typedef unsigned int uint;
typedef unsigned char uchar;
typedef unsigned short ushort;
typedef unsigned long ulong;

typedef signed char int8;
typedef signed char sint8;
typedef unsigned char uint8;
typedef short int16;
typedef signed short sint16;
typedef unsigned short uint16;
typedef int int32;
typedef signed int sint32;
typedef unsigned int uint32;
typedef ll int64;
typedef ll sint64;
typedef ull uint64;

#if !defined(__D810_STDINT_TYPES_DEFINED)
#define __D810_STDINT_TYPES_DEFINED 1

#if !defined(__int8_t_defined) && !defined(_INT8_T_DECLARED)
typedef int8 int8_t;
#endif
#ifndef __int8_t_defined
#define __int8_t_defined
#endif
#ifndef _INT8_T_DECLARED
#define _INT8_T_DECLARED
#endif

#if !defined(__uint8_t_defined) && !defined(_UINT8_T_DECLARED)
typedef uint8 uint8_t;
#endif
#ifndef __uint8_t_defined
#define __uint8_t_defined
#endif
#ifndef _UINT8_T_DECLARED
#define _UINT8_T_DECLARED
#endif

#if !defined(__int16_t_defined) && !defined(_INT16_T_DECLARED)
typedef int16 int16_t;
#endif
#ifndef __int16_t_defined
#define __int16_t_defined
#endif
#ifndef _INT16_T_DECLARED
#define _INT16_T_DECLARED
#endif

#if !defined(__uint16_t_defined) && !defined(_UINT16_T_DECLARED)
typedef uint16 uint16_t;
#endif
#ifndef __uint16_t_defined
#define __uint16_t_defined
#endif
#ifndef _UINT16_T_DECLARED
#define _UINT16_T_DECLARED
#endif

#if !defined(__int32_t_defined) && !defined(_INT32_T_DECLARED)
typedef int32 int32_t;
#endif
#ifndef __int32_t_defined
#define __int32_t_defined
#endif
#ifndef _INT32_T_DECLARED
#define _INT32_T_DECLARED
#endif

#if !defined(__uint32_t_defined) && !defined(_UINT32_T_DECLARED)
typedef uint32 uint32_t;
#endif
#ifndef __uint32_t_defined
#define __uint32_t_defined
#endif
#ifndef _UINT32_T_DECLARED
#define _UINT32_T_DECLARED
#endif

#if !defined(__int64_t_defined) && !defined(_INT64_T_DECLARED)
typedef int64 int64_t;
#endif
#ifndef __int64_t_defined
#define __int64_t_defined
#endif
#ifndef _INT64_T_DECLARED
#define _INT64_T_DECLARED
#endif

#if !defined(__uint64_t_defined) && !defined(_UINT64_T_DECLARED)
typedef uint64 uint64_t;
#endif
#ifndef __uint64_t_defined
#define __uint64_t_defined
#endif
#ifndef _UINT64_T_DECLARED
#define _UINT64_T_DECLARED
#endif

#endif // __D810_STDINT_TYPES_DEFINED

// Partially defined types. They are used when the decompiler does not know
// anything about the type except its size.
#define _BYTE uint8
#define _WORD uint16
#define _DWORD uint32
#define _QWORD uint64
#if !defined(_MSC_VER)
#define _LONGLONG __int128
#endif

// Non-standard boolean types. They are used when the decompiler can not use
// the standard "bool" type because of the size mistmatch but the possible
// values are only 0 and 1. See also 'BOOL' type below.
typedef int8 _BOOL1;
typedef int16 _BOOL2;
typedef int32 _BOOL4;
typedef int64 _BOOL8;

#if !defined(_WIN32) && !defined(_WINDOWS_)
typedef int8 BYTE;
typedef int16 WORD;
typedef int32 DWORD;
typedef int32 LONG;
typedef int BOOL; // uppercase BOOL is usually 4 bytes
#endif
typedef int64 QWORD;
#ifndef __cplusplus
typedef int bool; // we want to use bool in our C programs
#endif

#define __pure // pure function: always returns the same value, has no
// side effects

// Non-returning function
#if defined(__GNUC__)
#define __noreturn __attribute__((noreturn))
#else
#define __noreturn __declspec(noreturn)
#endif

// Used to annotate functions, methods and classes so they
// are not optimized by the compiler. Useful for tests
// where you expect loops to stay in place churning cycles
#if defined(_MSC_VER)
#define DONT_OPTIMIZE() __pragma(optimize("", off))
#define ENABLE_OPTIMIZE() __pragma(optimize("", on))
#elif defined(__clang__)
// [[clang::optnone]]
#define DONT_OPTIMIZE() _Pragma("clang optimize off")
#define ENABLE_OPTIMIZE() _Pragma("clang optimize on")
#elif defined(__GNUC__) || defined(__GNUG__)
#define DONT_OPTIMIZE()                  \
    _Pragma("GCC push_options")          \
        _Pragma("GCC optimize (\"O0\")") \
            _Pragma("GCC optimize (\"cold\")")
#define ENABLE_OPTIMIZE() _Pragma("GCC pop_options")
#else
#error new compiler
#endif

#ifndef NULL
#define NULL 0
#endif

// Some convenience macros to make partial accesses nicer
#define LAST_IND(x, part_type) (sizeof(x) / sizeof(part_type) - 1)
#if defined(__BYTE_ORDER) && __BYTE_ORDER == __BIG_ENDIAN
#define LOW_IND(x, part_type) LAST_IND(x, part_type)
#define HIGH_IND(x, part_type) 0
#else
#define HIGH_IND(x, part_type) LAST_IND(x, part_type)
#define LOW_IND(x, part_type) 0
#endif
// first unsigned macros:
#define BYTEn(x, n) (*((_BYTE *)&(x) + n))
#define WORDn(x, n) (*((_WORD *)&(x) + n))
#define DWORDn(x, n) (*((_DWORD *)&(x) + n))

#define LOBYTE(x) BYTEn(x, LOW_IND(x, _BYTE))
#define LOWORD(x) WORDn(x, LOW_IND(x, _WORD))
#define LODWORD(x) DWORDn(x, LOW_IND(x, _DWORD))
#define HIBYTE(x) BYTEn(x, HIGH_IND(x, _BYTE))
#define HIWORD(x) WORDn(x, HIGH_IND(x, _WORD))
#define HIDWORD(x) DWORDn(x, HIGH_IND(x, _DWORD))
#define BYTE1(x) BYTEn(x, 1) // byte 1 (counting from 0)
#define BYTE2(x) BYTEn(x, 2)
#define BYTE3(x) BYTEn(x, 3)
#define BYTE4(x) BYTEn(x, 4)
#define BYTE5(x) BYTEn(x, 5)
#define BYTE6(x) BYTEn(x, 6)
#define BYTE7(x) BYTEn(x, 7)
#define BYTE8(x) BYTEn(x, 8)
#define BYTE9(x) BYTEn(x, 9)
#define BYTE10(x) BYTEn(x, 10)
#define BYTE11(x) BYTEn(x, 11)
#define BYTE12(x) BYTEn(x, 12)
#define BYTE13(x) BYTEn(x, 13)
#define BYTE14(x) BYTEn(x, 14)
#define BYTE15(x) BYTEn(x, 15)
#define WORD1(x) WORDn(x, 1)
#define WORD2(x) WORDn(x, 2) // third word of the object, unsigned
#define WORD3(x) WORDn(x, 3)
#define WORD4(x) WORDn(x, 4)
#define WORD5(x) WORDn(x, 5)
#define WORD6(x) WORDn(x, 6)
#define WORD7(x) WORDn(x, 7)

// now signed macros (the same but with sign extension)
#define SBYTEn(x, n) (*((int8 *)&(x) + n))
#define SWORDn(x, n) (*((int16 *)&(x) + n))
#define SDWORDn(x, n) (*((int32 *)&(x) + n))

#define SLOBYTE(x) SBYTEn(x, LOW_IND(x, int8))
#define SLOWORD(x) SWORDn(x, LOW_IND(x, int16))
#define SLODWORD(x) SDWORDn(x, LOW_IND(x, int32))
#define SHIBYTE(x) SBYTEn(x, HIGH_IND(x, int8))
#define SHIWORD(x) SWORDn(x, HIGH_IND(x, int16))
#define SHIDWORD(x) SDWORDn(x, HIGH_IND(x, int32))
#define SBYTE1(x) SBYTEn(x, 1)
#define SBYTE2(x) SBYTEn(x, 2)
#define SBYTE3(x) SBYTEn(x, 3)
#define SBYTE4(x) SBYTEn(x, 4)
#define SBYTE5(x) SBYTEn(x, 5)
#define SBYTE6(x) SBYTEn(x, 6)
#define SBYTE7(x) SBYTEn(x, 7)
#define SBYTE8(x) SBYTEn(x, 8)
#define SBYTE9(x) SBYTEn(x, 9)
#define SBYTE10(x) SBYTEn(x, 10)
#define SBYTE11(x) SBYTEn(x, 11)
#define SBYTE12(x) SBYTEn(x, 12)
#define SBYTE13(x) SBYTEn(x, 13)
#define SBYTE14(x) SBYTEn(x, 14)
#define SBYTE15(x) SBYTEn(x, 15)
#define SWORD1(x) SWORDn(x, 1)
#define SWORD2(x) SWORDn(x, 2)
#define SWORD3(x) SWORDn(x, 3)
#define SWORD4(x) SWORDn(x, 4)
#define SWORD5(x) SWORDn(x, 5)
#define SWORD6(x) SWORDn(x, 6)
#define SWORD7(x) SWORDn(x, 7)

// Generate a pair of operands. S stands for 'signed'
#define __SPAIR16__(high, low) (((int16)(high) << 8) | (uint8)(low))
#define __SPAIR32__(high, low) (((int32)(high) << 16) | (uint16)(low))
#define __SPAIR64__(high, low) (((int64)(high) << 32) | (uint32)(low))
#define __SPAIR128__(high, low) (((int128)(high) << 64) | (uint64)(low))
#define __PAIR16__(high, low) (((uint16)(high) << 8) | (uint8)(low))
#define __PAIR32__(high, low) (((uint32)(high) << 16) | (uint16)(low))
#define __PAIR64__(high, low) (((uint64)(high) << 32) | (uint32)(low))
#define __PAIR128__(high, low) (((uint128)(high) << 64) | (uint64)(low))

// Helper functions to represent some assembly instructions.

#ifdef __cplusplus

// compile time assertion
#define __CASSERT_N0__(l) COMPILE_TIME_ASSERT_##l
#define __CASSERT_N1__(l) __CASSERT_N0__(l)
#define CASSERT(cnd) typedef char __CASSERT_N1__(__LINE__)[(cnd) ? 1 : -1]

// check that unsigned multiplication does not overflow
template <class T>
bool is_mul_ok(T count, T elsize)
{
    CASSERT((T)(-1) > 0); // make sure T is unsigned
    if (elsize == 0 || count == 0)
        return true;
    return count <= ((T)(-1)) / elsize;
}

// multiplication that saturates (yields the biggest value) instead of overflowing
// such a construct is useful in "operator new[]"
template <class T>
bool saturated_mul(T count, T elsize)
{
    return is_mul_ok(count, elsize) ? count * elsize : T(-1);
}

#include <stddef.h> // for size_t

// memcpy() with determined behavoir: it always copies
// from the start to the end of the buffer
// note: it copies byte by byte, so it is not equivalent to, for example, rep movsd
inline void *qmemcpy(void *dst, const void *src, size_t cnt)
{
    char *out = (char *)dst;
    const char *in = (const char *)src;
    while (cnt > 0)
    {
        *out++ = *in++;
        --cnt;
    }
    return dst;
}

// rotate left
template <class T>
T __ROL__(T value, int count)
{
    const uint nbits = sizeof(T) * 8;

    if (count > 0)
    {
        count %= nbits;
        T high = value >> (nbits - count);
        if (T(-1) < 0) // signed value
            high &= ~((T(-1) << count));
        value <<= count;
        value |= high;
    }
    else
    {
        count = -count % nbits;
        T low = value << (nbits - count);
        value >>= count;
        value |= low;
    }
    return value;
}

inline uint8 __ROL1__(uint8 value, int count) { return __ROL__((uint8)value, count); }
inline uint16 __ROL2__(uint16 value, int count) { return __ROL__((uint16)value, count); }
inline uint32 __ROL4__(uint32 value, int count) { return __ROL__((uint32)value, count); }
inline uint64 __ROL8__(uint64 value, int count) { return __ROL__((uint64)value, count); }
inline uint8 __ROR1__(uint8 value, int count) { return __ROL__((uint8)value, -count); }
inline uint16 __ROR2__(uint16 value, int count) { return __ROL__((uint16)value, -count); }
inline uint32 __ROR4__(uint32 value, int count) { return __ROL__((uint32)value, -count); }
inline uint64 __ROR8__(uint64 value, int count) { return __ROL__((uint64)value, -count); }

// carry flag of left shift
template <class T>
int8 __MKCSHL__(T value, uint count)
{
    const uint nbits = sizeof(T) * 8;
    count %= nbits;

    return (value >> (nbits - count)) & 1;
}

// carry flag of right shift
template <class T>
int8 __MKCSHR__(T value, uint count)
{
    return (value >> (count - 1)) & 1;
}

// sign flag
template <class T>
int8 __SETS__(T x)
{
    if (sizeof(T) == 1)
        return int8(x) < 0;
    if (sizeof(T) == 2)
        return int16(x) < 0;
    if (sizeof(T) == 4)
        return int32(x) < 0;
    return int64(x) < 0;
}

// overflow flag of subtraction (x-y)
template <class T, class U>
int8 __OFSUB__(T x, U y)
{
    if (sizeof(T) < sizeof(U))
    {
        U x2 = x;
        int8 sx = __SETS__(x2);
        return (sx ^ __SETS__(y)) & (sx ^ __SETS__(U(x2 - y)));
    }
    else
    {
        T y2 = y;
        int8 sx = __SETS__(x);
        return (sx ^ __SETS__(y2)) & (sx ^ __SETS__(T(x - y2)));
    }
}

// overflow flag of addition (x+y)
template <class T, class U>
int8 __OFADD__(T x, U y)
{
    if (sizeof(T) < sizeof(U))
    {
        U x2 = x;
        int8 sx = __SETS__(x2);
        return ((1 ^ sx) ^ __SETS__(y)) & (sx ^ __SETS__(U(x2 + y)));
    }
    else
    {
        T y2 = y;
        int8 sx = __SETS__(x);
        return ((1 ^ sx) ^ __SETS__(y2)) & (sx ^ __SETS__(T(x + y2)));
    }
}

// https://en.wikipedia.org/wiki/Carry_flag#Carry_flag_vs._borrow_flag
#if defined(__ARM__) || defined(__PPC__)
#define SUB_WITH_CARRY 1
#else
#define SUB_WITH_CARRY 0
#endif

// carry flag of subtraction (x-y)
template <class T, class U>
int8 __CFSUB__(T x, U y)
{
    int size = sizeof(T) > sizeof(U) ? sizeof(T) : sizeof(U);
    bool res;
    if (size == 1)
        res = uint8(x) < uint8(y);
    else if (size == 2)
        res = uint16(x) < uint16(y);
    else if (size == 4)
        res = uint32(x) < uint32(y);
    else
        res = uint64(x) < uint64(y);
#if SUB_WITH_CARRY
    res = !res;
#endif
    return res;
}

// carry flag of addition (x+y)
template <class T, class U>
int8 __CFADD__(T x, U y)
{
    int size = sizeof(T) > sizeof(U) ? sizeof(T) : sizeof(U);
    if (size == 1)
        return uint8(x) > uint8(x + y);
    if (size == 2)
        return uint16(x) > uint16(x + y);
    if (size == 4)
        return uint32(x) > uint32(x + y);
    return uint64(x) > uint64(x + y);
}

// carry flag of subtraction with carry
template <class T, class U>
int8 __CFSUB__(T x, U y, int8 cf)
{
#if SUB_WITH_CARRY
    cf = !cf;
#endif
    return __CFADD__(y, cf) ^ __CFSUB(x, y + cf);
}

// overflow flag of subtraction with carry
template <class T, class U>
int8 __OFSUB__(T x, U y, int8 cf)
{
#if SUB_WITH_CARRY
    cf = !cf;
#endif
    return __OFADD__(y, cf) ^ __OFSUB(x, y + cf);
}

inline int8 abs8(int8 x) { return x >= 0 ? x : -x; }
inline int16 abs16(int16 x) { return x >= 0 ? x : -x; }
inline int32 abs32(int32 x) { return x >= 0 ? x : -x; }
inline int64 abs64(int64 x) { return x >= 0 ? x : -x; }
// inline int128 abs128(int128 x) { return x >= 0 ? x : -x; }

#else // C++

#include <stddef.h> // for size_t

// #if defined(_MSC_VER)
// 	#include <intrin.h>
// #elif defined(__x86_64__)
// 	#include <x86intrin.h>
// #endif

// #if defined(__ARM_NEON)
// 	#include <arm_neon.h>
// #endif

#if defined(__clang__) || (defined(__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 5)))
#define __ROL1__(x, count) __builtin_rotateleft8((x), (count))
#define __ROR1__(x, count) __builtin_rotateright8((x), (count))
#define __ROL2__(x, count) __builtin_rotateleft16((x), (count))
#define __ROR2__(x, count) __builtin_rotateright16((x), (count))
#define __ROL4__(x, count) __builtin_rotateleft32((x), (count))
#define __ROR4__(x, count) __builtin_rotateright32((x), (count))
#define __ROL8__(x, count) __builtin_rotateleft64((x), (count))
#define __ROR8__(x, count) __builtin_rotateright64((x), (count))
#elif defined(_MSC_VER)
#include <intrin.h>
#define __ROL1__(x, count) _rotl8((x), (count))
#define __ROR1__(x, count) _rotr8((x), (count))
#define __ROL2__(x, count) _rotl16((x), (count))
#define __ROR2__(x, count) _rotr16((x), (count))
#define __ROL4__(x, count) _rotl((x), (count))
#define __ROR4__(x, count) _rotr((x), (count))
#define __ROL8__(x, count) _rotl64((x), (count))
#define __ROR8__(x, count) _rotr64((x), (count))
#else
#define __ROL1__(x, count) (((x) << ((count) % 8)) | ((x) >> (8 - ((count) % 8))))
#define __ROR1__(x, count) (((x) >> ((count) % 8)) | ((x) << (8 - ((count) % 8))))
#define __ROL2__(x, count) (((x) << ((count) % 16)) | ((x) >> (16 - ((count) % 16))))
#define __ROR2__(x, count) (((x) >> ((count) % 16)) | ((x) << (16 - ((count) % 16))))
#define __ROL4__(x, count) (((x) << ((count) % 32)) | ((x) >> (32 - ((count) % 32))))
#define __ROR4__(x, count) (((x) >> ((count) % 32)) | ((x) << (32 - ((count) % 32))))
#define __ROL8__(x, count) (((x) << ((count) % 64)) | ((x) >> (64 - ((count) % 64))))
#define __ROR8__(x, count) (((x) >> ((count) % 64)) | ((x) << (64 - ((count) % 64))))
#endif

#define __CFSHL__(x, y) invalid_operation // Generate carry flag for (x<<y)
#define __CFSHR__(x, y) invalid_operation // Generate carry flag for (x>>y)
#define __CFADD__(x, y) invalid_operation // Generate carry flag for (x+y)
#define __CFSUB__(x, y) invalid_operation // Generate carry flag for (x-y)
#define __OFADD__(x, y) invalid_operation // Generate overflow flag for (x+y)
#define __OFSUB__(x, y) invalid_operation // Generate overflow flag for (x-y)

#define abs8(x) (int8)((int8)(x) >= 0 ? (x) : -(x))
#define abs16(x) (int16)((int16)(x) >= 0 ? (x) : -(x))
#define abs32(x) (int32)((int32)(x) >= 0 ? (x) : -(x))
#define abs64(x) (int64)((int64)(x) >= 0 ? (x) : -(x))
#define abs128(x) (int128)((int128)(x) >= 0 ? (x) : -(x))

#endif // C++

// No definition for rcl/rcr because the carry flag is unknown
#define __RCL__(x, y) invalid_operation    // Rotate left thru carry
#define __RCR__(x, y) invalid_operation    // Rotate right thru carry
#define __MKCRCL__(x, y) invalid_operation // Generate carry flag for a RCL
#define __MKCRCR__(x, y) invalid_operation // Generate carry flag for a RCR
#define __SETP__(x, y) invalid_operation   // Generate parity flag for (x-y)

// In the decompilation listing there are some objects declared as _UNKNOWN
// because we could not determine their types. Since the C compiler does not
// accept void item declarations, we replace them by anything of our choice,
// for example a char:

#define _UNKNOWN char

#ifdef _MSC_VER
#define snprintf _snprintf
#define vsnprintf _vsnprintf
#endif

// The ADJ() macro is used for shifted pointers.
// While compilers do not understand it, it makes the code more readable.
// A shifted pointer is declared like this, for example:
//      char *__shifted(mystruct,8) p;
// It means: while 'p' points to 'char', it also points to the middle of 'mystruct'.
// More precisely, it is at the offset of 8 bytes from the beginning of 'mystruct'.
//
// The ADJ() macro performs the necessary adjustment.
// The __parentof() and __deltaof() functions are made up, they do not exist.
// __parentof() returns the parent structure type.
// __deltaof() returns the shift amount.

#define ADJ(p) (__parentof(p) *)(p - __deltaof(p))

#endif // HEXRAYS_DEFS_H