# MASM fixtures (`src/masm/*.asm`)

Real obfuscated functions extracted from user binaries (e.g. `dac.dll`, issue
#48) and linked into `libobfuscated.dll` so d810 attacks the **genuine** obfuscated
machine code, and so those regressions live in the tracked corpus (CI catches
them without the un-committed source binary).

Each `src/masm/<name>.asm` is auto-discovered by the Makefile: assembled with
`ml64` (Windows) / `llvm-ml64` (local validation), linked into the DLL,
**exported** (`link.exe /EXPORT:<name>`), and its matching `src/c/<name>.c` (if
any) is dropped. MASM is Windows-x64 / MSVC-COFF only — the `.dylib`/`.so`
builds ignore this directory, so these functions exist **only in the PE `.dll`**.
DSL cases for them set `skip_if_function_absent=True` so they SKIP (not fail) on
non-Windows builds.

Authoritative build path (per `../../README.md`): `reversepc.local`,
`samples/scripts/build_windows.ps1`.

---

## How a fixture is created (the manual workflow)

Worked example: `sub_1815C8C30` (dac.dll `rand()%3` helper) and its `rand()`
retarget. This is the procedure the `d810cli.py fixture` command (ticket
d81-rtfh) automates — see **Automated** below; the manual steps follow it.

## Automated: `d810cli.py fixture`

The manual workflow below is automated by:

```bash
python tools/d810cli.py fixture add --idb <dac.dll.i64> --func <ea|name> \
    --project default_unflattening_ollvm.json
```

`add` runs extract → retarget (LEAF/IMPORT targets only — deeper obfuscated
`sub_*` stay `MEMORY[...]`) → local build (`scripts/build_masm.sh`, NO reversepc)
→ verify, then STOPS at a human gate: it emits a MINIMAL `DeobfuscationCase`
(`must_change` + `skip_if_function_absent` only — YOU write the semantic
assertions from the shown before/after dump) and never auto-commits binaries.
Re-run one stage with `fixture extract` / `retarget --dry-run` / `build` /
`register` / `verify`. Layering: pure `src/d810/testing/fixture_builder.py`
(detector/rewriter/case-emitter) + headless idalib worker
`scripts/fixture_idb_worker.py` (extract + VA→name resolve) +
`cmd_fixture` in `tools/d810cli.py`.

### 1. Extract the function to MASM

d810's structural exporter reads the function's real instructions from the IDB
and **materializes its referenced data closure** (the real opaque constants), so
the result is self-contained and compilable:

```python
# headless, via idalib
import idapro; idapro.open_database("dac.dll.i64", False)
from d810.ui.export_disasm_masm_emit import generate_masm_for_function
open("samples/src/masm/sub_1815C8C30.asm", "w").write(
    generate_masm_for_function(0x1815C8C30, materialize_data=True, const_data=True)
)
```

`const_data=True` puts materialized data in a read-only `CONST` segment (.rdata).
External `call sub_*` targets become `EXTERN … :PROC` and stay unresolved at link
(tolerated via `/FORCE:UNRESOLVED`). Validate locally: `llvm-ml64 /nologo /c
/Fo/tmp/x.obj <name>.asm`.

### 2. The export ordinal is automatic

The function label is emitted `PUBLIC <name>` and the Makefile links it with
`/EXPORT:<name>` (see `Makefile`: `$(MASM_FUNCS:%=/EXPORT:%)`). So after the
Windows build the function appears in the DLL's export table with an ordinal —
which is what makes IDA **name** it on fresh analysis (that's how the test
harness finds it by name). Verify:

```bash
llvm-objdump -p samples/bins/libobfuscated.dll | grep sub_1815C8C30
#      166  0x17220  sub_1815C8C30
```

No manual ordinal assignment is needed — `/EXPORT:<name>` on a `PUBLIC` symbol
gets an auto-assigned ordinal. To force a specific ordinal you would write
`/EXPORT:<name>,@<N>`, but the fixtures don't need fixed ordinals (tests look up
by name, not ordinal).

### 3. Retarget an obfuscated indirect call onto a NAMED symbol (the `rand()` trick)

Extraction alone reproduces the obfuscation faithfully, but an obfuscated
indirect call **devirtualizes to a dangling address**: the call target is a
computation over a materialized data slot (here `[off_18210A360] +
0x64E2C558D421136`) that, in the original binary, resolved to a real import
(`rand`). d810 correctly folds it to the *original* VA (`0x181803620` = dac.dll's
`rand`), but that address is **out of the sample DLL's image**, so it renders
`MEMORY[0x181803620]()` instead of `rand()`.

To make the devirt land on a real, named symbol, turn the data slot into a
**relocation** onto a stub named after the original target:

```asm
; sub_1815C8C30.asm
EXTERN rand:PROC                       ; defined + exported by rand.asm
...
; the call site computes: rax = [off_18210A360] + 0x64E2C558D421136 ; then `call rax`
; so set the slot to  &rand - const   =>  [slot] + const == &rand
off_18210A360 dq rand - 64E2C558D421136h
```

```asm
; rand.asm  -- a dependency-free leaf stub, auto-exported by the Makefile
OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE
_TEXT SEGMENT ALIGN(16) 'CODE'
PUBLIC rand
rand:
    xor eax, eax
    ret
_TEXT ENDS
END
```

Result after the Windows build: d810 folds `[slot]+const` to `&rand`, IDA names
`&rand` (it's exported), and the decompile renders the full golden
`return rand() % 3u;`.

**GOTCHA — do NOT use the CRT `rand`.** Referencing the C runtime `rand` drags
in `security-cookie` / `gs_report` code that needs kernel32 imports the sample
doesn't link; `/FORCE:UNRESOLVED` then points `rand` at `__ImageBase` (RVA 0),
collapsing the fold to `_ImageBase`. A dependency-free **local** stub avoids the
entire CRT dependency chain. (Verified both ways.)

The relocation assembles as an `IMAGE_REL_AMD64_ADDR64` against `rand` with the
`-const` baked into the addend (`llvm-objdump -r` confirms).

### 4. Build on reversepc + pull back

Follow `../../README.md` "End-to-end mac → reversepc → local recipe" (rsync
`samples/`, build via `samples/scripts/build_windows.ps1`, tar-over-ssh pull,
strip the 29-byte PowerShell preamble, validate `PE32+` / `Micr` PDB header).

### 5. Register a DSL case

Add a `DeobfuscationCase` (see `DAC_MASM_CASES` in
`tests/system/cases/libobfuscated_comprehensive.py`), with
`skip_if_function_absent=True`. **Pick assertions from an actual before/after
dump — never assert a golden you have not observed** (e.g. `rand()` was only
asserted AFTER the retarget made it real). Verify with:
`run_system_tests_docker.sh system -- -k TestDacMasmFixtures`.

---

## Current fixtures

- `sub_1815C8C30.asm` + `rand.asm` — dac.dll `rand()%3` helper. Golden
  `return rand() % 3u;`. Guards the d81-u3cg terminal-stack-alias-guard loop
  collapse AND the indirect-call devirtualization.
- `Java_dimension_DimensionAPI_getHuzpsbPY.asm` — dac.dll DimensionAPI (the
  function that crashed old d810-ng with INTERR 50860/51920). Standalone
  extraction loses the binary's extern/data context so it only PARTIALLY
  unflattens here; its case guards the no-INTERR + must-change property.
- `sub_7FFD3338C040.asm` — earlier Hodur extraction.
- `sub_7FF85A13D930.asm` — Hodur-like dispatcher with a cross-block constant
  return chain; guards forward propagation before subtree folding.
