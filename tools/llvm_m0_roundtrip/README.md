# LLVM M0 Lab Proof

This directory contains the checked-in `llr-6q39` M0 lab proof for
`lab_flat_branchless`.

It has two deliberately hand-authored pieces:

- **M0a:** `fixtures/lab_flat_branchless.before.ll` translates the observed
  branchless residue into LLVM IR and `run_opt.py` proves what the LLVM middle
  collapses.
- **M0b:** `lab_flat_branchless.lower_back.json` maps the optimized LLVM residue
  to d810's existing lab lower-back primitive and oracle test: recover the live
  `(token & 1)` predicate, synthesize an `if/else`, decompile
  `restructuring_lab.dll`, and compare against `lab_ref_cond`.

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

## M0a: LLVM Middle Proof

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

## M0b: Hand Lower-Back / Parity Proof

`lab_flat_branchless.lower_back.json` connects the optimized LLVM fixture to the
existing d810 lab lower-back proof:

- source fixture: `fixtures/lab_flat_branchless.after.ll`
- low predicate: `%low = and i32 %token, 1`
- surviving state mask form: `%state = or i32 %state_false, %state_true`
- true / odd arm: state `0xB92456DE`, value `(token + 0x11) ^ 0x22`
- false / even arm: state `0x3C8960A9`, value `token - 0x22`
- hand-lowered control: `if ((token & 1) != 0) ... else ...`
- d810 primitive: `ConditionalSynthesize`, via `recover_branchless` plus
  `lower_conditional_synthesize`
- oracle/reference: `lab_ref_cond`

The focused system proof is:

```text
tests/system/runtime/hexrays/test_llvm_m0_roundtrip.py::TestLLVMM0RoundTrip::test_hand_lowered_branchless_llvm_matches_cond_oracle
```

It reads the lower-back artifact, lowers `lab_flat_branchless` through the
catalog primitive, decompiles the lowered result, renders `lab_ref_cond`, and
asserts their `semantic_signature(...)` values match.

This is a hand lower-back proof. It does not implement a general LLVM dropper.

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

This d810 M0 proof does not call, vendor, or depend on IDAvator. M0b is a
hand-lowered lab proof that reaches d810's `restructuring_lab.dll`
decompile/parity-oracle gate; it is not a general automated LLVM drop/backend.
Future M3/general lower-back work should borrow IDAvator's supported-subset
discipline and interface shape where useful, while preserving d810's native
oracle/decompile gate.

## M0 Collapse Classes

This fixture classifies the M0 result as:

- `LLVM-free`: `~mask` canonicalization and false-arm fold to `token - 0x22`.
- `needs d810 predicate recovery`: mask/or state select to recovered
  `(token & 1)` predicate to synthesized `if/else`.
- `needs MBA/Z3`: none for this fixture. Stronger future residues may need it.

## Boundaries

- This is a completed M0 hand-lowered lab proof, not M1/M3 automation.
- There is no automated `Instruction -> LLVM` lifter in this slice.
- There is no general LLVM drop/backend in d810 in this slice.
- M1 must lift from canonical `Instruction` / `Varnode`; it must not target
  `InsnSnapshot` directly.
- IDAvator is the reference for literal LLVM lift/drop shape, not a dependency
  of this d810 M0 artifact.

The next LLVM milestone should use this as an evidence fixture only. It should
not treat the hand-authored `.ll` or hand lower-back map as a substitute for the
real M1 lifter or M3 Hex-Rays microcode lower-back.
