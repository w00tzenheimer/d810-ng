# Building Sample Binaries

This directory builds shared-library samples used by runtime/system tests.

```bash
cd samples
make ...
```

## Output Naming

The Makefile has two output-name modes:

- default (`BINARY_NAME` not explicitly set):
  - `bins/<BINARY_NAME>_<hostos>_<arch>.<suffix>`
- explicit `BINARY_NAME` (CLI or environment):
  - `bins/<BINARY_NAME>.<suffix>`

Where:

- `<BINARY_NAME>` default is `libobfuscated`
- `<hostos>` is where `make` runs (`darwin`, `linux`, `windows`)
- `<arch>` is normalized (`x86_64` or `arm64`)
- suffix by `TARGET_OS`: `.dll` (windows), `.dylib` (darwin), `.so` (linux)

## Build Flags

- `TARGET_OS` (default: `windows`)
  - values: `windows`, `darwin`, `linux`, `native`
  - `native` is normalized to detected host OS
- `BUILD_ARCH` (default: `x86_64`)
  - values: `x86_64`, `x86`, `arm64`, `aarch64`
  - `x86` is normalized to `x86_64` (32-bit builds are not supported)
- `BINARY_NAME` (default: `libobfuscated`)

## Common Commands

```bash
# Default (Windows DLL)
make
# -> bins/libobfuscated_<hostos>_x86_64.dll

# Linux ELF x86_64
make TARGET_OS=linux BUILD_ARCH=x86_64
# -> bins/libobfuscated_<hostos>_x86_64.so

# Linux ELF arm64
make TARGET_OS=linux BUILD_ARCH=arm64
# -> bins/libobfuscated_<hostos>_arm64.so

# Native host target (x86 maps to x86_64)
make TARGET_OS=native BUILD_ARCH=x86

# Custom output basename (drops host/arch suffixes)
make BINARY_NAME=libobfuscatedv2
# -> bins/libobfuscatedv2.<suffix>

# Clean
make clean
```

## Linux ELF on macOS/Windows Hosts

When `TARGET_OS=linux` is requested on a non-Linux host, the Makefile uses Docker to produce true ELF binaries.

- `BUILD_ARCH=x86_64` -> Docker platform `linux/amd64`
- `BUILD_ARCH=arm64` -> Docker platform `linux/arm64`

Generated local Docker images:

- `linux-build-x86_64`
- `linux-build-arm64`

Verification:

```bash
file bins/*.so
```

Expected format examples:

- `ELF 64-bit ... x86-64`
- `ELF 64-bit ... ARM aarch64`

## Windows Native Build (reversepc.local)

Primary workflow for production Windows sample artifacts:

1. Ensure repo is synced to the Windows host path:
   - `G:\idapro\plugins\d810-ng`
2. From that repo on Windows, run:
   - `samples\\build_windows.ps1`
3. Artifact output:
   - `samples\\bins\\libobfuscated.dll`
   - `samples\\bins\\libobfuscated.pdb`

Your macOS SMB mount points to the same repo at:

- `/Volumes/re/idapro/plugins/d810-ng`

## Why `src/c/stubs.c` exists

`samples/src/c/stubs.c` is the central placeholder implementation file for
unresolved externals referenced by decompiler-derived sample sources.

- Keep it as a `.c` translation unit so symbols are provided once at link time.
- Do not convert these bodies to header-only inline definitions; that can create
  duplicate symbols or per-translation-unit copies.
- The goal is compile/link success for sample binaries, not runtime-accurate API
  behavior.

When to add entries:

- A new sample introduces unresolved externals during link
  (for example `LNK2019` or `undefined reference`).
- Add minimal no-op or deterministic constant-return placeholders.
- Include a short comment next to each new stub indicating which sample needed
  it.

## Troubleshooting

- Docker build fails with cache/space errors:
  - free Docker disk space and rebuild image
- Linux arm64 direct host build fails:
  - use Docker path (`TARGET_OS=linux BUILD_ARCH=arm64`) or set `LINUX_SYSROOT`
- Unexpected output format:
  - run `file bins/<name>.<ext>` and confirm `TARGET_OS`/`BUILD_ARCH`
