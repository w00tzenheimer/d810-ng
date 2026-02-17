# Samples Directory Guide

This document replaces the previous `BUILD.md` and `AGENT.md`, providing a consolidated how-to for building, understanding, and iterating on the shared-library samples that power runtime and system tests.

## Build entry point

```bash
cd samples
make ...
```

`make` defaults to building a Windows DLL (`TARGET_OS=windows`, `BUILD_ARCH=x86_64`) and outputs artifacts under `bins/`.

## Output naming modes

- default (`BINARY_NAME` not specified): `bins/<BINARY_NAME>_<hostos>_<arch>.<suffix>`
- explicit `BINARY_NAME`: `bins/<BINARY_NAME>.<suffix>` (drops automatic host/arch suffixes)

`BINARY_NAME` defaults to `libobfuscated`.
`<hostos>` is the machine invoking `make` (e.g., `darwin`, `linux`, `windows`).
`<arch>` is normalized to `x86_64` or `arm64`.
`suffix` is based on `TARGET_OS`: `.dll` (Windows), `.dylib` (macOS), `.so` (Linux).

## Target matrix and normalization

| Flag | Values | Notes |
| --- | --- | --- |
| `TARGET_OS` | `windows`, `darwin`, `linux`, `native` | `native` normalizes to the detected host OS. |
| `BUILD_ARCH` | `x86_64`, `x86`, `arm64`, `aarch64` | `x86` normalizes to `x86_64`; `arm64` and `aarch64` both map to `arm64`. |

32-bit builds are not supported; requesting `BUILD_ARCH=x86` still yields `x86_64` output.

## Linux ELF builds on other hosts

Setting `TARGET_OS=linux` on a non-Linux host uses Docker to produce authentic ELF binaries:

- `BUILD_ARCH=x86_64` → Docker platform `linux/amd64`
- `BUILD_ARCH=arm64` → Docker platform `linux/arm64`

Docker images produced by the Makefile are named `linux-build-x86_64` and `linux-build-arm64`.

Verify formats with `file bins/*.so` (look for `ELF 64-bit ... x86-64` or `ARM aarch64`).

## Authoritative Windows build workflow

Production PE artifacts come from the Windows host `reversepc.local`:

1. Work in the repo clone at `G:\idapro\plugins\d810-ng`.
2. Run from there:
   ```powershell
   cd G:\idapro\plugins\d810-ng\samples
   .\scripts\build_windows.ps1
   ```
3. Expect output under `samples\bins`: `libobfuscated.dll` and `libobfuscated.pdb`.

macOS developers can mirror the Windows repo via `/Volumes/re/idapro/plugins/d810-ng`.

## Export and header policy

- Avoid `.def` files; use the `EXPORT` macro defined in `samples/include/platform.h` for any symbols you need exported from DLL builds.
- Windows-friendly types should reference project-local headers such as `ida_types.h` and `polyfill.h` rather than pulling in the actual Windows SDK.
- Keep `stubs.c` as the central placeholder source for unresolved externals (`samples/src/c/stubs.c`). Add minimal no-op implementations there when a sample’s link step reports undefined symbols.

## Build commands reference

```bash
# Windows DLL (default)
make

# Linux x86_64 ELF
make TARGET_OS=linux BUILD_ARCH=x86_64

# Linux arm64 ELF
make TARGET_OS=linux BUILD_ARCH=arm64

# macOS dylib
make TARGET_OS=darwin BUILD_ARCH=x86_64

# Native host with x86 normalized to x86_64
make TARGET_OS=native BUILD_ARCH=x86

# Custom output basename
make BINARY_NAME=libobfuscatedv2
```

Use `make clean` to wipe previous `bins/` outputs.

## Quick checks

- `file bins/*` → confirms binary format (DLL, dylib, or ELF).
- `objdump -p bins/*.dll | sed -n '/Export Table:/,/The Function Table/p'` → inspects Windows exports.

## Troubleshooting hints

- Docker builds fail with cache/space errors: purge Docker storage and rebuild.
- Linux arm64 host builds fail: switch to Docker (`TARGET_OS=linux BUILD_ARCH=arm64`) or provide `LINUX_SYSROOT`.
- Output format doesn’t match expectations: rerun `file` and confirm `TARGET_OS`/`BUILD_ARCH` settings.
