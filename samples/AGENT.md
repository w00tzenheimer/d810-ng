@samples

Agent guide for the `samples/` tree in `d810-ng`.

## Scope

- Build and maintain decompilation sample shared libraries in `samples/bins`.
- Keep sample C sources (`samples/src/c/*.c`) decompilation-friendly (minimal edits, no heavy refactors).
- Prefer compile reliability over runtime correctness for Windows API-like behavior in samples.

## Canonical Build Entry

```bash
cd samples
make ...
```

## Target Matrix

- `TARGET_OS=windows` -> `.dll`
- `TARGET_OS=darwin` -> `.dylib`
- `TARGET_OS=linux` -> `.so` (true ELF)

### Flag normalization rules (from Makefile)

- `TARGET_OS=native` always normalizes to the detected host OS.
- `BUILD_ARCH=x86` normalizes to `x86_64` (32-bit output is intentionally unsupported).
- `arm64` and `aarch64` normalize to `arm64`.

## Output Naming Rules

The Makefile intentionally has two naming modes:

- Default (`BINARY_NAME` untouched):
  - `bins/<BINARY_NAME>_<hostos>_<arch>.<suffix>`
- Explicit `BINARY_NAME` (CLI/env):
  - `bins/<BINARY_NAME>.<suffix>`

`<hostos>` is where make runs (not target OS).

## Linux ELF Behavior

On non-Linux hosts, `TARGET_OS=linux` automatically uses Docker for real ELF output:

- `x86_64` -> `--platform linux/amd64`
- `arm64` -> `--platform linux/arm64`

Generated image names:

- `linux-build-x86_64`
- `linux-build-arm64`

## Windows Build Workflow (authoritative)

Use native Windows build for checked-in PE artifacts:

- Windows repo path: `G:\idapro\plugins\d810-ng`
- Local SMB mirror on macOS: `/Volumes/re/idapro/plugins/d810-ng`

Run on Windows host (`reversepc.local`):

```powershell
cd G:\idapro\plugins\d810-ng\samples
.\build_windows.ps1
```

Expected outputs:

- `samples\bins\libobfuscated.dll`
- `samples\bins\libobfuscated.pdb`

## Symbol export policy

- Do not use a `.def` file for sample exports.
- Use the `EXPORT` macro from `samples/include/platform.h` for exported functions.
- Windows builds set `D810_DLL_EXPORT=1` in Makefile paths that produce DLLs.

## Header policy for sample sources

- Avoid real Windows SDK headers in sample code.
- Use project-local compatibility headers (`ida_types.h`, `polyfill.h`) for Windows-like types/stubs where needed.

## Stub policy (`samples/src/c/stubs.c`)

- `stubs.c` is the single link-time home for placeholder definitions of
  unresolved externs used by sample sources.
- Keep stubs in `stubs.c` (not header-inline bodies) so symbols are exported
  once and can satisfy references across all sample objects.
- Purpose is buildability of decompilation samples, not runtime correctness.

When to add new stubs:

- Only when link failures show unresolved symbols from a sample file.
- Add minimal no-op or deterministic placeholder behavior.
- Add a short comment near the stub naming the sample/reason.

## Quick verification commands

```bash
# Binary format
file bins/*

# Windows export table (when building a DLL)
objdump -p bins/*.dll | sed -n '/Export Table:/,/The Function Table/p'
```

## Common build commands

```bash
# Default Windows DLL
make

# Linux x86_64 ELF
make TARGET_OS=linux BUILD_ARCH=x86_64

# Linux arm64 ELF
make TARGET_OS=linux BUILD_ARCH=arm64

# macOS dylib
make TARGET_OS=darwin BUILD_ARCH=x86_64

# Native host target, x86 normalized to x86_64
make TARGET_OS=native BUILD_ARCH=x86

# Explicit binary name (drops host/arch suffix)
make BINARY_NAME=libobfuscatedv2
```
