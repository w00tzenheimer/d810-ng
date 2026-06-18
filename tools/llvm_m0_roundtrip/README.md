# LLVM M0a Middle Proof

This directory is a partial `llr-6q39` artifact: it proves the LLVM middle on
the `lab_flat_branchless` residue, but it is not the complete M0 lab
round-trip. `llr-6q39` remains open until the optimized LLVM result is
hand-lowered back through the lab microcode/pseudocode path and checked against
the reference by the parity oracle.

This is still a lab spike, not the M1 microcode-to-LLVM lifter.

The real-substrate anchor is the existing `restructuring_lab.dll`
`lab_flat_branchless` observation:

- `tools/hexrays_structuring_lab/observations/flat_branchless_synth.json`
- `samples/restructuring_lab/specs/L8-conditional-synthesis.md`
- `tests/system/runtime/hexrays/test_insert_unflatten_mini.py::TestInsertUnflattenBranchless`

That lab case proves d810 can recover the branchless next-state predicate from
Hex-Rays GLBOPT1 microcode and hand-lower it into a verifier-clean `if/else`.
The surviving branchless residue is:

```text
mask = -(token & 1)
state = (K1 & mask) | (K2 & ~mask)
```

`fixtures/lab_flat_branchless.before.ll` is a hand-authored LLVM translation of
that residue plus the nearby value computation. It is intentionally not generated
from `Instruction` or `InsnSnapshot`.

## What This Proves

Running:

```bash
PYTHONPATH=src python3 tools/llvm_m0_roundtrip/run_opt.py
```

finds an external `opt`, verifies the input IR, runs:

```text
instcombine,reassociate,sccp,simplifycfg,adce
```

and compares the normalized result with
`fixtures/lab_flat_branchless.after.ll`.

The optimized IR proves the LLVM middle can simplify part of the residue:

- `~mask` canonicalizes from `xor i32 %mask, -1` to `add nsw i32 %low, -1`.
- The else arm value fold mirrors the d810 lab finding:
  `(token + 0x11) - 0x33` becomes `token - 0x22`.
- LLVM verifies and preserves the all-ones mask dataflow cleanly.

It does not prove that stock LLVM recovers the high-level branch. With this
conservative pipeline, the mask/or select remains mask/or form. The `if/else`
recovery in the real lab case is still d810's job: predicate recovery plus
`LowerConditionalStateTransition`.

## IDAvator Reference

IDAvator is the existing local proof/reference for the literal LLVM lift/drop
shape:

- `/Users/mahmoud/src/idapro/compilers/idavator/README.md` documents the lane as
  Hex-Rays microcode `mba_t` to LLVM IR, external LLVM optimization, and
  optimized `.ll` dropped back into the open database.
- `/Users/mahmoud/src/idapro/compilers/idavator/src/idavator/round_trip.py`
  pre-filters LLVM modules to the supported drop subset, imports
  `LLVMDropConverter` only at the IDA boundary, drops the selected function, and
  compares dropped pseudocode against the original through its oracle.
- `/Users/mahmoud/src/idapro/compilers/idavator/src/idavator/llvm_drop.py`
  implements the concrete lower-back shape: `LLVMDropConverter.drop()` hooks
  `hxe_preoptimized`, rebuilds the target function's microcode from LLVM IR, and
  lets Hex-Rays decompile the rebuilt body.

This d810 M0a artifact does not call, vendor, or depend on IDAvator. It also
does not implement d810's drop/lower-back step yet. The remaining `llr-6q39`
work should borrow IDAvator's supported-subset discipline and lower-back
interface shape where possible, while preserving d810's native
`restructuring_lab.dll` decompile/parity-oracle gate.

## Remaining M0 Work

The full `llr-6q39` M0 gate still requires the lower-back half documented in
`docs/plans/llvm-deobfuscation-track.md`:

- hand-lower the optimized LLVM result back into Hex-Rays microcode or an
  equivalent decompilable lab path, analogous to IDAvator's `llvm_drop` lane,
- decompile the lowered form in `restructuring_lab.dll`,
- gate pseudocode equivalence through the parity oracle/reference source,
- document the fixture's collapse classes as:
  - `LLVM-free`: residue collapsed by stock LLVM middle-end passes,
  - `needs d810 predicate recovery`: branchless mask/or to recovered predicate
    and synthesized `if/else`,
  - `needs MBA/Z3`: stronger value/predicate residues LLVM cannot prove alone.

## Boundaries

- This is M0a / a partial M0 middle proof, not the complete M0 round-trip.
- There is no automated `Instruction -> LLVM` lifter in this slice.
- There is no general LLVM drop/backend in d810 in this slice.
- M1 must lift from canonical `Instruction` / `Varnode`; it must not target
  `InsnSnapshot` directly.
- IDAvator is the reference for literal LLVM lift/drop shape, not a dependency
  of this d810 M0 artifact.

The next LLVM milestone should use this as an evidence fixture only. It should
not treat the hand-authored `.ll` as a substitute for the remaining M0
lower-back/parity work, the real M1 lifter, or M3 Hex-Rays microcode
lower-back.
