# Restructuring Lab

A self-contained mini-project that builds **C** and **MASM** CFG fixtures into an
isolated DLL using a **local Docker toolchain** (MinGW for C, `llvm-ml64` for
MASM) — no `reversepc.local`, and no way to clobber `libobfuscated`.

It is the *build half* of restructuring experiments. The *observe half* is the
existing registry harness in `tools/hexrays_structuring_lab/` (validate-cfg →
dump → summarize), which consumes the DLL this lab produces.

See `DESIGN.md` for the full design and rationale.

## Build

```bash
samples/restructuring_lab/build_lab.sh
```

This:
1. builds the `restructuring-lab` Docker image (`Dockerfile.lab`: debian + clang +
   lld + mingw-w64 + llvm; `llvm-ml64` is symlinked from `llvm-ml`) if missing,
2. runs `make` in the container with the **lab dir mounted writable** and
   **`samples/include` mounted read-only** (`/include`),
3. links `c/*.o` + `masm/*.obj` into `bins/restructuring_lab.dll`,
4. copies the uniquely-named DLL to `samples/bins/restructuring_lab.dll` for the
   dump harness / `D810_TEST_BINARY`, and prints `libobfuscated.dll`'s hash to
   prove it was untouched.

## Why it cannot clobber libobfuscated

- Own `Makefile` (never invokes `samples/Makefile`); writes only `build/` + `bins/`.
- Own `masm/` dir, so the main Makefile's `samples/src/masm/*.asm` auto-discovery
  never sees these fixtures.
- The container mounts only this dir (writable) + `samples/include` (read-only);
  it physically cannot reach `samples/Makefile`, `samples/src/masm/`, or
  `samples/bins/libobfuscated.dll`.

## Layout

```
Dockerfile.lab   toolchain image (mingw + llvm-ml64)
Makefile         compile c/*.c (mingw clang) + assemble masm/*.asm (llvm-ml64) -> link
build_lab.sh     docker build + run + copy-out + isolation check
c/               C fixtures   (one hypothesis each; -I/include for polyfill/platform)
masm/            MASM fixtures (compilable ml64; one hypothesis each)
bins/            DLL output (gitignored; the copy in samples/bins/ is the shared one)
```

## Adding a fixture

Drop a `c/<name>.c` (use `EXPORT D810_NOINLINE` from `platform.h`) or a
`masm/<name>.asm` (compilable ml64: `OPTION PROLOGUE/EPILOGUE:NONE`, a
`_TEXT SEGMENT ... END`, `PUBLIC <fn>`), then rebuild. Each file is an
independent exported function. Keep fixtures tiny — one CFG hypothesis each.

MASM fixtures should be compilable directly (the in-IDA "Export disassembly →
MASM" action emits this form, with materialized data in a `.rdata`/`_DATA`
segment). C and MASM here are separate experiments, not two forms of one
function.

## Seed fixtures

- `c/lab_if_diamond.c` — `lab_if_diamond`: a source if/else diamond (hypothesis:
  Hex-Rays preserves the join as if/else).
- `masm/lab_asm_branch.asm` — `lab_asm_branch`: a hand-written direct two-arm
  branch (hypothesis: forces clean if/else microcode edges the C compiler would
  normalize away).

## Observe (existing harness)

Point a `tools/hexrays_structuring_lab/registry.json` case's `binary` at
`restructuring_lab.dll` (resolved from `samples/bins/`), then:

```bash
python -m tools.hexrays_structuring_lab validate-cfg <case>
python -m tools.hexrays_structuring_lab command <case>
python -m tools.hexrays_structuring_lab summarize --db <diag.sqlite3>
```

## Validated facts (2026-06-06)

- `llvm-ml64` (symlink of debian `llvm`'s `llvm-ml`, LLVM 19) assembles ml64 MASM
  to x86-64 COFF; invoked as `llvm-ml64` it defaults to 64-bit.
- C (MinGW, GNU-ABI) + MASM (`llvm-ml64`, MSVC-COFF) link cleanly into one PE32+
  DLL via the MinGW clang driver for freestanding/no-CRT fixtures — no ABI
  fallback needed. (If a future fixture fights the mix: compile C with
  `--target=x86_64-pc-windows-msvc -ffreestanding` and link with `lld-link`.)
- Build leaves `samples/bins/libobfuscated.dll` byte-identical.
