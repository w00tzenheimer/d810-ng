# Building libobfuscated.dll

## Problem

The current `libobfuscated.dll` in this repository was built **without exporting function names**.

This causes all tests in `test_libdeobfuscated.py` to fail because IDA Pro cannot find functions by their expected names (`test_cst_simplification`, `test_chained_add`, etc.). Instead, IDA only sees generic names like `sub_180001000`.

## Solution

The source files have been updated with `EXPORT` macros to properly export function names. **The DLL must be rebuilt** for these changes to take effect.

---

## Building on Windows

### Quick Start (Any Compiler)

The Makefile auto-detects your compiler. Just run:

```cmd
cd samples
nmake clean    # If using Visual Studio Developer Command Prompt
make clean     # If using MinGW/Git Bash/WSL

nmake          # MSVC
make           # GCC/Clang/MinGW
```

Output: `bins/libobfuscated.dll`

---

### Option 1: Visual Studio (MSVC) - Recommended

**Prerequisites:**

- Visual Studio 2019 or later (Community Edition works)
- "Desktop development with C++" workload

**Steps:**

1. Open **Developer Command Prompt for VS** (or **x64 Native Tools Command Prompt**)

2. Build:

   ```cmd
   cd samples
   nmake clean
   nmake
   ```

3. Verify exports:

   ```cmd
   dumpbin /EXPORTS bins\libobfuscated.dll
   ```

You should see:

```
ordinal hint RVA      name
      1    0 00001000 test_and
      2    1 00001050 test_chained_add
      3    2 000010A0 test_cst_simplification
      ...
```

---

### Option 2: MinGW-w64 (GCC)

**Prerequisites:**

- MinGW-w64 ([download](https://winlibs.com/) or install via MSYS2/Cygwin)
- Make for Windows

**Steps:**

1. Add MinGW to PATH or use MSYS2 shell

2. Build:

   ```bash
   cd samples
   make clean
   make
   ```

3. Verify:

   ```bash
   objdump -p bins/libobfuscated.dll | grep "test_"
   ```

---

### Option 3: Clang (LLVM)

**Prerequisites:**

- LLVM for Windows ([download](https://releases.llvm.org/))
- Make for Windows

**Steps:**

1. Build:

   ```bash
   cd samples
   make clean
   CC=clang make
   ```

---

## Building on Linux/macOS (for comparison)

The Makefile defaults to building a Windows DLL, but you can build native shared libraries:

```bash
cd samples
make clean
TARGET_OS=native make
```

This creates:

- **Linux**: `bins/libobfuscated.so`
- **macOS**: `bins/libobfuscated.dylib`

Note: Tests expect the Windows DLL, so this is mainly for development/testing.

---

## Troubleshooting

### "nmake: command not found"

You're not in a Visual Studio Developer Command Prompt. Either:

- Use **Start Menu → Visual Studio → Developer Command Prompt**
- Or use `make` instead of `nmake` (requires MinGW/Git Bash)

### "cl: command not found" with nmake

Run from **Developer Command Prompt**, not regular CMD.

### "gcc: command not found"

Install MinGW-w64 or use MSVC instead.

### Build succeeds but tests still fail

1. Verify exports:

   ```cmd
   dumpbin /EXPORTS bins\libobfuscated.dll | findstr test_
   ```

2. You should see function names like `test_cst_simplification`, NOT just addresses

3. If exports are missing, ensure:
   - Source files have `#include "export.h"` at the top
   - Functions have `EXPORT` prefix (e.g., `EXPORT int test_xor(...)`)

### Linker errors about missing symbols

This is expected - the DLL references IDA Pro functions that don't exist at build time. The linker flags allow unresolved symbols.

---

## Makefile Features

The updated Makefile now:

✅ **Auto-detects Windows compiler** (MSVC → GCC → Clang)
✅ **Supports Visual Studio (MSVC)** with proper `/` flags
✅ **Supports MinGW/GCC** with `-` flags
✅ **Uses export.h macros** for cross-platform exports
✅ **Handles .obj (MSVC) and .o (GCC)** object files
✅ **Cleans all build artifacts** properly

---

## Next Steps After Building

1. **Verify the DLL** has proper exports (see commands above)

2. **Commit the rebuilt DLL:**

   ```bash
   git add samples/bins/libobfuscated.dll
   git commit -m "rebuild: add function name exports to libobfuscated.dll"
   git push
   ```

3. **GitHub Actions will test** the new DLL automatically

4. **Tests should pass** - functions will be found by name! ✅
