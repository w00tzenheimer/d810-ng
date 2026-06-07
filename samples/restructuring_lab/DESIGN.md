# Restructuring Lab — Design

Status: approved design (2026-06-06). Spec lives here (not `docs/`) because this
repo gitignores `docs/`.

## 1. Purpose

A self-contained mini-project, `samples/restructuring_lab/`, that assembles and
links **MASM** and compiles **C** fixtures into an isolated DLL using the local
**Docker MinGW toolchain** (plus `llvm-ml64` for MASM) — with **no dependency on
the `reversepc.local` Windows host** and **no possibility of clobbering
`libobfuscated`**.

It is the *build half* of restructuring experiments. The *observe half* stays in
the existing `tools/hexrays_structuring_lab/` registry harness (validate-cfg →
dump → summarize), which consumes the DLL this lab produces.

### Why it exists
- The authoritative `libobfuscated.dll` is built on `reversepc.local`; iterating
  there is slow and remote. A local Docker build closes the loop.
- A full local `libobfuscated` rebuild is blocked by sibling samples that need
  MSVC intrinsics (`sub_7FFB206BBD50.c` `__security_cookie`, etc.), so new
  fixtures need an isolated DLL anyway.
- The main `samples/Makefile` now **auto-discovers `samples/src/masm/*.asm`** and its
  masm-assembly rule is **clang-cl-only**; reusing it for a MinGW/MASM lab would
  entangle the libobfuscated build. A separate project sidesteps both.

## 2. Layout (all new, all under `samples/restructuring_lab/`)

```
samples/restructuring_lab/
  Dockerfile.lab     # debian + clang + lld + mingw-w64 + llvm (provides llvm-ml64)
  Makefile           # compile c/*.c + assemble masm/*.asm -> link bins/restructuring_lab.dll
  build_lab.sh       # docker build + run (isolated mounts); copy dll -> samples/bins/
  README.md          # what/why/how + harness wiring
  DESIGN.md          # this file
  c/                 # C fixtures (*.c), one hypothesis each
  masm/              # MASM fixtures (*.asm), one hypothesis each
  bins/              # restructuring_lab.dll output (+ .pdb if produced)
```

- Each `c/*.c` and each `masm/*.asm` is an **independent fixture** exporting its
  own function. C and MASM are not two forms of one function here, so there is no
  "drop the .c when a matching .asm exists" rule (that was libobfuscated-only).
- Seed content: **one tiny C fixture + one tiny MASM fixture**, each a single
  clear CFG hypothesis, sufficient to prove the dual-path build end to end.

## 3. Build flow

`build_lab.sh` (run from repo root or the lab dir):

1. Ensure the image: `docker build -t restructuring-lab -f Dockerfile.lab .`
   (only when missing).
2. Build, mounting the **lab dir writable** and **`samples/include` read-only**:
   ```
   docker run --rm \
     -v "<repo>/samples/restructuring_lab":/work \
     -v "<repo>/samples/include":/include:ro \
     restructuring-lab make
   ```
   The container can write **only** inside `/work` (the lab dir). It physically
   cannot reach `samples/Makefile`, `samples/src/masm/`, or
   `samples/bins/libobfuscated.dll`. No throwaway-`/tmp` copy is needed.
3. Copy the uniquely-named `bins/restructuring_lab.dll` into `samples/bins/`
   (and `.pdb` if produced) so the existing harness / `D810_TEST_BINARY` resolve
   it. This never writes `libobfuscated.dll`.
4. Sanity-print: `file` + size of the produced DLL; warn (do not fail) if
   `samples/bins/libobfuscated.dll` somehow went missing.

### Makefile responsibilities (self-contained; only its own dir)
- **C:** `clang --target=x86_64-w64-mingw32 -fuse-ld=lld -O0 -g -ffreestanding -I/include -c c/<f>.c -o build/<f>.o` (flags mirror the samples debug profile; `-I/include` is the read-only `samples/include` mount).
- **MASM:** `MSYS2_ARG_CONV_EXCL='*' llvm-ml64 /nologo /c /Fo build/<f>.obj masm/<f>.asm` (the `-m64` and MSYS-path-mangling lessons from the libobfuscated work apply).
- **Link:** combine all objects into `bins/restructuring_lab.dll`, exporting each
  fixture symbol. Default linker = the MinGW clang driver
  (`clang --target=x86_64-w64-mingw32 -shared -fuse-ld=lld -Wl,--export-all-symbols`).
- `clean` removes only `build/` and `bins/` inside the lab dir.

## 4. The two validation risks (resolve during implementation)

1. **`llvm-ml64` availability in the image.** Debian's `llvm` package may not ship
   the `llvm-ml`/`llvm-ml64` driver. Resolution order: (a) `apt-get install -y
   llvm` and check for `llvm-ml64`; (b) if absent, add the `apt.llvm.org` repo and
   install a versioned `llvm-N` that includes it; (c) last resort, symlink
   `llvm-ml64 -> llvm-mc`-based wrapper. The Dockerfile is the single place this
   is pinned. **Confirmed by building the image and running `llvm-ml64 /?`.**
2. **C + MASM ABI mix.** MinGW C objects (GNU ABI) + `llvm-ml64` objects
   (MSVC-COFF) linked into one DLL. For freestanding, no-CRT, no-EH fixtures this
   is expected to link. **Fallback if it fights:** compile the C fixtures with
   `--target=x86_64-pc-windows-msvc -ffreestanding` (MSVC ABI) and link with
   `lld-link /DLL /NOENTRY /FORCE:UNRESOLVED` so both halves are uniform MSVC-COFF
   — a path already proven for `sub_7FFD3338C040` earlier. The Makefile keeps the
   linker/toolchain selection in one variable block so the fallback is a flag flip.

## 5. Harness integration (no duplicate harness)
- Add a `tools/hexrays_structuring_lab/registry.json` case (or document the
  pattern) pointing `binary` at `restructuring_lab.dll` so `validate-cfg`,
  `command`, and `summarize` work unchanged.
- The lab DLL must therefore land in `samples/bins/` (step 3) where the dump
  harness resolves binaries.

## 6. Success criteria
- `samples/restructuring_lab/build_lab.sh` (one command) rebuilds
  `restructuring_lab.dll` locally via Docker, with both a C and a MASM fixture
  linked + exported, and `libobfuscated.dll` provably untouched (hash unchanged).
- The produced DLL loads in IDA and both fixture functions are present/exported.
- A registry case can run the existing observe loop against it.

## 7. Out of scope (YAGNI)
- Re-exporting / regenerating `sub_7FFD3338C040` here (the small seed proves the
  pipeline; real functions can be dropped into `masm/` later).
- Changing the main `samples/Makefile` or the libobfuscated build at all.
- A second/parallel observe harness — reuse `tools/hexrays_structuring_lab/`.
- Mac-native (non-Docker) builds — Docker MinGW is the contract.

## 8. Decisions recorded
- Add `llvm-ml64` to Docker; keep the MASM dialect (do NOT add a GAS emitter).
- Self-contained mini-project (own Makefile/Dockerfile), not a shared-Makefile
  override.
- Seed = small purpose-built fixtures (C + MASM), not the real WoW function.
- Flat `c/` and `masm/` dirs (not `src/c/`).
