@samples You are working inside the repo d810-ng, specifically the samples/ tree. This repo contains decompilation samples from Hex-Rays/IDA. The goal is to get everything in samples/ to compile cleanly with Clang, including cross-compiling to Windows (--target=x86_64-w64-mingw32), without depending on any real Windows SDK headers or libraries.

Instead, we want to use the project's own Hex-Rays-style headers (include/ida_types.h and include/polyfill.h) as a fake Windows shim so that everything compiles for demonstration / analysis purposes only. Correctness of the actual Windows API behavior is NOT important; the priority is "it compiles".

## Current Build System Status

The Makefile now supports cross-platform compilation for:

- **Windows** (x86_64): Creates `.dll` files via Docker cross-compilation
- **Linux** (x86_64): Creates `.so` files
- **macOS** (x86_64 and arm64): Creates `.dylib` files

### Build Commands

```bash
# Windows (via Docker)
docker build -t win-build -f Dockerfile.windows .
docker run --rm -v "$PWD":/work win-build

# Linux
make TARGET_OS=linux

# macOS (x86_64)
make TARGET_OS=darwin BUILD_ARCH=x86_64

# macOS (arm64)
make TARGET_OS=darwin BUILD_ARCH=arm64

# Test all platforms
make test-all-platforms
```

### Debug Symbol Generation

**Windows**: PDB files are **always generated** (required for Windows debugging)

- Generated automatically: `bins/libobfuscated.pdb`
- Uses `-gcodeview` and `-Wl,--pdb=` flags

**macOS & Linux**: Separate debug symbol files are **optional** (gated by `NIX_DEBUG_SYMBOLS=True`)

- **macOS**: `NIX_DEBUG_SYMBOLS=True make TARGET_OS=darwin` → generates `bins/libobfuscated.dylib.dSYM`
- **Linux**: `NIX_DEBUG_SYMBOLS=True make TARGET_OS=linux` → generates `bins/libobfuscated.so.debug` (if `objcopy`/`llvm-objcopy` available)

**Note**: Debug symbols are **always embedded** in binaries with `-g` on all platforms. The flag only controls generation of separate symbol files.

### Key Implementation Details

1. **Windows SDK Removal**: All Windows SDK headers have been removed from source files. The project uses only:
   - `include/ida_types.h` - Hex-Rays type definitions
   - `include/polyfill.h` - Fake Windows API stubs and structures
   - Standard C library headers (`<stdio.h>`, `<string.h>`, etc.)

2. **Stub Functions**: External functions that would normally come from Windows SDK are stubbed in `src/c/stubs.c`:
   - Windows API functions (LoadLibraryA, GetProcAddress, WinHTTP functions, etc.)
   - Interlocked functions (_InterlockedCompareExchange,_InterlockedExchangeW)
   - Other external symbols referenced by decompiled code

3. **Architecture Normalization**: The Makefile correctly handles architecture detection:
   - `arm64` is checked before generic `64` patterns to avoid misclassification
   - Supports `x86_64`, `x86`, `arm64`, and `aarch64` variants

4. **Cross-Platform Redirections**: Fixed `>nul` and `2>nul` to use `/dev/null` on Unix systems to prevent creation of unwanted `nul` files.

## High-level goals

1. No real Windows SDK headers anywhere in these samples:
   • No <windows.h>, <winnt.h>, <minwindef.h>, <winhttp.h>, <winsock2.h>, etc.
   • If any such includes exist in samples/include or samples/src, remove or comment them out and replace with project-local stubs where needed.

2. Rely only on include/ida_types.h and include/polyfill.h for Windows types & APIs:
   • All Windows-looking names (BYTE, WORD, DWORD, LONG, BOOL, CONTEXT,_EXCEPTION_POINTERS, _TEB, NtCurrentTeb, HINTERNET, WINHTTP_*, etc.) must come from these headers (or other project-local headers), not from the system SDK.
   • It is OK if these are only partial/inaccurate approximations. They just need to be type-correct enough for this project to compile.

3. Fix all current Windows-related compiler errors that appear when cross-compiling with:

```bash
cd samples
docker build -t win-build -f Dockerfile.windows .
docker run --rm -v "$PWD":/work win-build
```

You don't have to actually run Docker, but assume that the build inside the container uses: `clang --target=x86_64-w64-mingw32 -fuse-ld=lld ...` and make code changes so that this configuration compiles cleanly.

4. Keep things decompilation-friendly:
   • The C files under samples/src/c/*.c are decompiler outputs and demonstration samples.
   • We don't want to heavily rewrite or refactor them. Minimal, local, mechanical fixes are preferred (adding typedefs / stubs / small includes to our local headers).
   • It's OK if some functions (like WinHTTP calls) are effectively no-ops or stubbed.

## Concrete tasks and constraints

1. Remove all Windows SDK includes
Search the entire samples tree for any of these patterns:
   • #include <windows.h>
   • #include <winnt.h>
   • #include <minwindef.h>
   • #include <winhttp.h>
   • #include <winsock2.h>
   • #include <windowsx.h>
   • Any other <...> includes that are obviously Windows SDK headers

For each such include:
   • Remove the Windows header include.
   • If the file also needs a standard C library header (e.g., for printf, memcpy, etc.), add the appropriate C standard header instead, such as:
   • #include <stdio.h> for printf
   • #include <string.h> for memcpy, memmove, memset, etc.

Example: in samples/src/c/hodur_c2_flattened.c the top of the file should end up like this (conceptually):

```c
#include "polyfill.h"
#include <stdio.h>

// Global timeout variable
DWORD g_timeout_msec = 10000;
```

2. Make ida_types.h play nice with fake Windows types
Open samples/include/ida_types.h.

There is a block that defines Windows-like base types:

```c
#if !defined(_WIN32) && !defined(_WINDOWS_)
typedef int8 BYTE;
typedef int16 WORD;
typedef int32 DWORD;
typedef int32 LONG;
typedef int BOOL; // uppercase BOOL is usually 4 bytes
#endif
```

If that guard is not exactly this yet, change it to exactly:

```c
#if !defined(_WIN32) && !defined(_WINDOWS_)
typedef int8 BYTE;
typedef int16 WORD;
typedef int32 DWORD;
typedef int32 LONG;
typedef int BOOL; // uppercase BOOL is usually 4 bytes
#endif
```

This ensures:
   • When _WIN32 or _WINDOWS_ are ever defined, we don't redefine these types and clash with some external SDK.
   • In our current "no Windows SDK headers at all" scenario,_WIN32 should not be defined in these sample builds, so these typedefs will be active and used across the code.

Do not change all the other macros (BYTE1, WORD1, etc.) unless they are directly causing build errors after we remove Windows headers. They are part of Hex-Rays's usual helper macros.

3. Make polyfill.h provide fake Windows structs & functions unconditionally
Open samples/include/polyfill.h.

This file already contains a big amount of fake Windows/NT structures and enums (AccessMask, _M128A,_XSAVE_FORMAT,_CONTEXT, _EXCEPTION_RECORD, _EXCEPTION_POINTERS, _NT_TIB, _TEB, NtCurrentTeb, RTL_CRITICAL_SECTION, etc.). Right now, a lot of that content is wrapped in #ifndef_WIN32 guards or similar.

The goal:
   • All of this fake Windows stuff should be available even when targeting --target=x86_64-w64-mingw32.
   • Because we're no longer including real Windows headers anyway, there's no risk of conflict.
   • That means: remove or neutralize any #ifndef_WIN32 guarding that prevents these structs from being compiled when _WIN32 is defined.

## Known Issues and Solutions

### Type Redefinition Conflicts

- **Issue**: System headers (especially on macOS) may define `int8_t`, `uint8_t`, etc., causing conflicts with `ida_types.h`
- **Solution**: Added guards in `ida_types.h` using `!defined(__int8_t_defined)` and `!defined(_INT8_T_DECLARED)` to prevent redefinition

### Linker Errors for Undefined Symbols

- **Issue**: `lld` doesn't support flags like `--unresolved-symbols=ignore-all` or `--allow-shlib-undefined`
- **Solution**: Created `src/c/stubs.c` with concrete stub definitions for all external functions. The Makefile includes `stubs.o` in the build.

### Architecture Detection

- **Issue**: `arm64` was being misclassified as `x86_64` due to order of checks in architecture normalization
- **Solution**: Reordered checks in Makefile to check for `arm64`/`aarch64` before generic `64` patterns

### Cross-Platform File Redirections

- **Issue**: `>nul` and `2>nul` create actual files named `nul` on Unix systems
- **Solution**: Changed to `/dev/null` on Unix systems, kept `NUL` (uppercase) for Windows-specific code paths

## Files Modified

- `Makefile`: Added multi-platform support, debug symbol generation, test-all-platforms target
- `include/polyfill.h`: Removed `#ifndef _WIN32` guards, added explicit type definitions
- `include/ida_types.h`: Added guards to prevent type redefinition conflicts
- `src/c/stubs.c`: New file with stub definitions for external functions
- `src/c/unwrap_loops.c`: Removed conflicting extern declarations
- `src/c/constant_folding.c`: Removed conflicting extern declarations
- `src/c/hodur_c2_flattened.c`: Removed Windows SDK includes, added standard C headers
