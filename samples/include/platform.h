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

#endif /* PLATFORM_H */
