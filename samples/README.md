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

### End-to-end mac → reversepc → local recipe

Use this when you've edited samples on macOS and need fresh PE artifacts back
in the local repo's `samples/bins/`.  Each step is annotated with the
specific failure mode it dodges.

```bash
# 0. (Optional) confirm the SMB share is mounted at /Volumes/re.
ls /Volumes/re/idapro/plugins/d810-ng/samples/bins >/dev/null

# 1. Sync local source over.  Skip IDA databases and macOS metadata droppings.
rsync -av --delete-excluded \
  --exclude='bins/*.i64' --exclude='bins/*.id*' \
  --exclude='bins/*.nam' --exclude='bins/*.til' \
  --exclude='.DS_Store' --exclude='._*' \
  samples/ /Volumes/re/idapro/plugins/d810-ng/samples/

# 2. Force a clean build by removing the old artifacts on the SMB side.
rm -f /Volumes/re/idapro/plugins/d810-ng/samples/bins/libobfuscated.dll \
      /Volumes/re/idapro/plugins/d810-ng/samples/bins/libobfuscated.pdb

# 3. Build on the Windows host.  Force IPv4; PowerShell profile noise is fine.
ssh -4 reversepc.local \
  'powershell -File G:\idapro\plugins\d810-ng\samples\scripts\build_windows.ps1'

# 4. Pull the fresh artifacts back.  tar-over-ssh sidesteps SMB cache + scp
#    banner issues (see "Gotchas" below).  Strip the 29-byte PowerShell
#    profile preamble before extracting.
rm -f samples/bins/libobfuscated.dll samples/bins/libobfuscated.pdb  # zsh `noclobber`
ssh -4 -o LogLevel=ERROR reversepc.local \
  'tar -cf - -C "G:\idapro\plugins\d810-ng\samples\bins" \
       libobfuscated.dll libobfuscated.pdb' \
  > /tmp/win_artifacts.tar
dd if=/tmp/win_artifacts.tar of=/tmp/win_artifacts.clean bs=1 skip=29 2>/dev/null
tar -xf /tmp/win_artifacts.clean -C samples/bins/

# 5. Validate.
file samples/bins/libobfuscated.dll          # → PE32+ executable (DLL) x86-64
head -c 4 samples/bins/libobfuscated.pdb     # → "Micr" (Microsoft PDB header)
```

### Gotchas you will hit if you stray from the recipe

- **SMB negative-lookup cache.**  After `rm -f /Volumes/re/.../libobfuscated.dll`,
  macOS pins "file does not exist" for several minutes.  Even when the
  Windows build *does* write a fresh DLL, `ls`, `find`, `du`, `stat`, and
  `sync` will all still report missing.  Sibling artifacts from the same
  build (`libobfuscated.exp`, `libobfuscated.lib`) often *are* visible —
  the cache is per-filename, not per-directory.  Fix: unmount/remount the
  share, or skip the SMB round-trip entirely and use the tar-over-ssh
  pull in step 4.

- **`scp` over reversepc fails on the SSH banner.**  Windows OpenSSH emits
  `** The server may need to be upgraded.  See https://openssh.com/pq.html`
  on every connection, which breaks `scp`'s framing
  (`Received message too long ...`).  Use `tar -cf -` over ssh instead,
  or stream raw bytes with `ssh ... 'powershell -NoProfile -Command "..."'`
  redirected through `base64 -d`.

- **PowerShell profile prefix in stdout.**  The reversepc profile prints
  `Found Psfzf. Configuring...\r\n` (29 bytes) on every non-interactive
  ssh invocation, even with `-NoProfile` on the inner command.  Anything
  that consumes ssh stdout as a binary stream must strip those 29 bytes
  (`dd skip=29` or `tail -c +30`) before parsing.

- **zsh `noclobber`.**  Output redirects like `> samples/bins/libobfuscated.dll`
  fail with `file exists` when the target is present.  Always `rm -f` the
  local target first, or use `>!` if you prefer the zsh-native escape.

- **`build_windows.ps1` produces artifacts even with unresolved externals.**
  The linker is configured to `FORCE` past missing symbols, so a "successful"
  exit code is not enough — always validate the artifact with `file` and a
  size check before claiming the build is good.

- **Stale local artifacts hide fresh exports.**  Because the local
  `samples/bins/libobfuscated.dll` is what `D810_TEST_BINARY` resolves
  against, an unsynced local copy will silently mask any new behavior from
  the Windows build.  Re-run step 4 after every reversepc build.

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
