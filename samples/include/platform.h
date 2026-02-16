#ifndef PLATFORM_H
#define PLATFORM_H

/*^***************************************************************
*  Export parameters
*****************************************************************/
/*
*  D810_DLL_EXPORT :
*  Enable exporting of functions when building a Windows DLL.
*  D810_DLL_IMPORT :
*  Enable importing of symbols from a Windows DLL.
*  D810_LIB_VISIBILITY :
*  Control library symbol visibility on ELF/Mach-O.
*/
#ifndef D810_LIB_VISIBILITY
#  if defined(_WIN32) || defined(__CYGWIN__) || defined(_MSC_VER)
#    define D810_LIB_VISIBILITY
#  elif defined(__clang__)
#    if __has_attribute(visibility)
#      define D810_LIB_VISIBILITY __attribute__((visibility("default")))
#    else
#      define D810_LIB_VISIBILITY
#    endif
#  elif defined(__GNUC__) && (__GNUC__ >= 4)
#    define D810_LIB_VISIBILITY __attribute__((visibility("default")))
#  else
#    define D810_LIB_VISIBILITY
#  endif
#endif

#ifndef EXPORT
#  if defined(_WIN32) || defined(__CYGWIN__)
#    if defined(D810_DLL_EXPORT) && (D810_DLL_EXPORT == 1)
#      define EXPORT __declspec(dllexport) D810_LIB_VISIBILITY
#    elif defined(D810_DLL_IMPORT) && (D810_DLL_IMPORT == 1)
#      define EXPORT __declspec(dllimport) D810_LIB_VISIBILITY
#    else
#      define EXPORT D810_LIB_VISIBILITY
#    endif
#  else
#    define EXPORT D810_LIB_VISIBILITY
#  endif
#endif


// GCC version
#if defined(__GNUC__) && !defined (GCC_VERSION) && !defined (__clang__)
#define GCC_VERSION  ((__GNUC__) * 10000 + (__GNUC_MINOR__) * 100 + (__GNUC_PATCHLEVEL__))
#endif

// Clang version
#if defined (__clang__)
#define CLANG_VERSION  ((__clang_major__) * 10000 + (__clang_minor__) * 100 + (__clang_patchlevel__))
// Problem: The version number is not consistent across platforms
// http://llvm.org/bugs/show_bug.cgi?id=12643
// Apple bug 18746972
#endif

// Fix problem with macros named min and max in WinDef.h
// Prevent Windows min/max macros from interfering with templates
// Must be defined BEFORE any Windows headers are included
#if defined(_MSC_VER)
  #if defined (_WINDEF_) && defined(min) && defined(max)
  #undef min
  #undef max
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#endif

// Cross-platform force inline macro
#if defined(_MSC_VER)
#define D810_FORCEINLINE __forceinline
#elif defined(__clang__) || defined(__GNUC__)
#define D810_FORCEINLINE __attribute__((always_inline)) inline
#else
#define D810_FORCEINLINE inline
#endif

#if (defined(__GNUC__) && !defined(__clang__))
#define D810_NOINLINE __attribute__((noinline))
#elif defined(_MSC_VER)
#define D810_NOINLINE __declspec(noinline)
#else
#define D810_NOINLINE
#endif

// Alignment specifier
#if defined(_MSC_VER)
#define D810_ALIGNAS(x) __declspec(align(x))
#else
#define D810_ALIGNAS(x) __attribute__((aligned(x)))
#endif

// Unreachable hint
#if defined(_MSC_VER)
#define D810_UNREACHABLE() __assume(0)
#elif defined(__GNUC__) || defined(__clang__)
#define D810_UNREACHABLE() __builtin_unreachable()
#else
#define D810_UNREACHABLE() ((void)0)
#endif

// Optimization control macros
#if defined(_MSC_VER)
#define NO_OPTIMIZE_BEGIN __pragma(optimize("", off))
#define NO_OPTIMIZE_END   __pragma(optimize("", on))
#define NO_OPTIMIZE_ATTR
#elif defined(__clang__) || defined(__GNUC__)
#define NO_OPTIMIZE_BEGIN
#define NO_OPTIMIZE_END
#define NO_OPTIMIZE_ATTR __attribute__((optimize("O0")))
#else
#define NO_OPTIMIZE_BEGIN
#define NO_OPTIMIZE_END
#define NO_OPTIMIZE_ATTR
#endif

#if (defined(__GNUC__) && !defined(__clang__))
#define ATTR_UNUSED
#else
#define ATTR_UNUSED __attribute__((unused))
#endif

#endif /* PLATFORM_H */
