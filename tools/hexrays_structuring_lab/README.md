# Hex-Rays Structuring Lab

## Purpose

The Hex-Rays Structuring Lab is an experimental harness for learning which CFG
shapes Hex-Rays preserves, rewrites, merges, or destroys during decompilation.

This exists because d810's unflattening problem is not only "recover the right
state-transition graph." A recovered semantic graph still has to be lowered into
a concrete microcode CFG that Hex-Rays can structure without changing the shape
in ways that make the result semantically misleading.

The lab's goal is to turn Hex-Rays behavior from guesswork into measured,
repeatable evidence.

## Why This Matters

For flattened functions, d810 has to pass through several layers:

1. Recover a semantic state-transition program from dispatcher logic.
2. Convert that semantic program into concrete mblock/microcode edits.
3. Let Hex-Rays optimize and structure the mutated CFG.
4. Inspect pseudocode that may no longer resemble the CFG d810 emitted.

The difficult part is that each layer can be locally correct while the next
layer invalidates the intended structure. A DAG can cover every state, but
Hex-Rays may still merge handler boundaries, fold shared tails, erase alias
blocks, or convert a promising region into goto-heavy pseudocode.

The lab gives us a controlled way to answer questions like:

- Which block shapes are merged by `optimize_local` / GLBOPT?
- What prevents a handler boundary from being coalesced?
- Which two-child fork shapes become clean `if` / `else` pseudocode?
- Which cyclic CFG shapes become `while`, `do while`, or goto soup?
- What happens when state-write cleanup turns blocks into `m_und` shells?
- Which barriers survive Hex-Rays cleanup without leaking ugly pseudocode?

## Established Finding: Return Preservation (Terminal-Tail Construction)

The lab's first load-bearing result for d810's `returns=0` problem. Two C
fixtures, both `cfg_validation: passed`, form a controlled A/B on the **same**
7-byte terminal cascade — the only difference is how the terminals reach their
return:

| fixture | construction | GLBOPT1 pseudocode | verdict |
|-|-|-|
| `terminal_tail_ref_cascade` | nested early-return cascade, no state var | **returns=7, whiles=0, gotos=0** (22→16 blocks) | **good oracle** |
| `terminal_tail_shared_convergence` | `stage` state var + one `shared_guard` all terminals route through | **returns=2, whiles=5** (26→19 blocks) | **negative control — "the D810-like bad shape"** (its own source comment) |

`unique_continuation` and `split_guard` further show that **topology alone** and
**source-level splitting alone** do *not* recover the cascade, and
`side_effect_boundary_anchor` shows a `noinline volatile` call is **not** a
block-structure barrier.

**The recipe Hex-Rays rewards (measured, not guessed).** To preserve N returns,
the terminal lowering must emit the `ref_cascade` shape — three properties, all
of which d810's current `§1a #4` redirect-to-`common_return_corridor` path
violates:

1. **No shared convergence** — each terminal owns its return block; do not
   redirect terminals into a shared corridor/guard. (The fan-in is what becomes
   a loop nest.)
2. **Nested guard cascade** — `if (cond_i) return X_i;` chained, each guard
   either returns or falls to the next. Not a switch that re-converges.
3. **No residual state-staging writes** — leftover `stage = K` writes are what
   Hex-Rays reads as loop induction (the 5 whiles). They must be removed, not
   just left dead for DCE.

**The d810 invariant this implies:** terminal-tail lowering MUST produce the
cascade shape; the redirect-to-shared-corridor emission is the negative control
and cannot yield distinct returns. Verify with: `return_epilogue` has one
predecessor per terminal and the GLBOPT1 pseudocode has `whiles=0`.

**Open rung (the bridge to production) — and why C fixtures can't close it.**
Every case above is a C/compiled fixture proving the *target shape* Hex-Rays
rewards. They cannot, however, test d810's **detect → unflatten → emit** path,
and we proved this empirically (2026-06-01):

- Running `HodurUnflattener` (`-p hodur_flag2.json`) on `shared_convergence`:
  `DELTA=0` — no change.
- Running the §1a `StateMachineCffUnflattener`
  (`D810_USE_S1A_PIPELINE=1 -p hodur_flag2_s1a.json`): it **fires** but recovers
  nothing — `map_rows=0 transitions=0 regions=0`, `DELTA=0`, `returns=2`.

**Root cause (corrected by a LOCOPT microcode dump, 2026-06-01):** the dispatcher
is **fully intact at every maturity** — the microcode shows the equality chain
(`blk[4..9]: m_jz == 0,1,2,3,4,5 -> handlers`), and d810's recon classifies it
`type=ollvm_flat, confidence=1.00` at LOCOPT. d810 does **not** lose it to
structuring. The unflattener's `recover_dispatcher` returns `map_rows=0` for one
concrete reason: `MIN_STATE_CONSTANT = 0x01000000` and the fixture's state
constants are `stage = 0..6`, so `_split_const_state`'s `int(value) > min_const`
filter (`dispatcher_recovery.py:54`) rejects every comparison. That floor exists
to reject decoy/loop-bound compares because real OLLVM uses large random 32-bit
states; the clean fixture's tiny sequential states fall under it.

**Consequence:** the fixture *is* a valid minimal reproduction — the gap is a
detector threshold, not Hex-Rays structuring. Two fixes, both small: (a) a
large-constant variant (`stage = 0x1000_00xx`) so `recover_dispatcher` engages
and the full unflatten path runs on ~14 blocks; or (b) the `microcode_mutation`
case injects the de-flatten facts directly, bypassing detection, to test the
backend emission in isolation. (a) is the better first step — it exercises
detection + recovery + lowering end-to-end on a minimal case.

### Harness note (how to dump a lab function)

The pseudocode dump test is marked `pseudocode_dump`, which `pyproject.toml`
`addopts` deselects by default (`-m "not ... pseudocode_dump ..."`). A lab dump
that yields `0 selected` is this filter, **not** a missing function. Re-select
it explicitly:

```bash
D810_CAPTURE_POST_MATURITY=GLBOPT1 D810_TEST_BINARY=libobfuscated.dll \
  ./tools/scripts/run_system_tests_docker.sh dump \
  -f <lab_function> -p <project.json> -o hexrays_structuring_lab/<out>.txt \
  -l --enable-debug-logging -- -m pseudocode_dump
```

## Scope

This is not an attempt to fully reverse engineer Hex-Rays.

The scope is narrower: build a registry of CFG patterns that matter to d810's
unflattening pipeline, especially patterns involved in semantic region lowering,
bounded reconstruction, branch-local exits, handler-boundary preservation, and
post-d810 block collapse.

The lab should prioritize small fixtures with one hypothesis each.

## Fixture Levels

The lab should support three fixture levels because no single representation is
enough.

### C Fixtures With Compiled-CFG Validation

C fixtures are the default first attempt because they are fast to iterate on and
easy to maintain. They are useful for broad source-level behavior: ordinary
conditionals, loops, switches, gotos, shared returns, and compiler-generated
cleanup patterns.

They are acceptable only when the compiled binary CFG matches the intended
pattern. The contract is:

```text
C fixture is valid evidence only after compiled-CFG validation passes.
```

If the compiler erases or normalizes the intended shape, the fixture is invalid.
That is not negative Hex-Rays evidence.

### Assembly Fixtures

Assembly fixtures are the fallback when C cannot force the required block/edge
shape. These should be used for single-pred chains, multi-pred boundaries,
irreducible flow, dispatcher loops, and branch/fallthrough layout experiments
only after a reasonable C attempt fails validation.

### Microcode Mutation Fixtures

Microcode mutation fixtures are the last resort for d810-specific backend
behavior. They start from a known function, apply controlled
mblock/instruction/edge mutations, capture diagnostic snapshots, and then
observe what Hex-Rays does after optimization.

These are useful, but they should not be the default if manual microcode
fixtures are too brittle in practice.

## Pattern Registry

Every lab case should eventually have a registry entry describing:

- Pattern id.
- Fixture kind: `c`, `asm`, or `microcode_mutation`.
- Binary and function name.
- Compiler/toolchain flags, if applicable.
- d810 project/config used, if applicable.
- Mutation pass or env gate used, if applicable.
- Snapshot phases captured.
- Expected CFG behavior.
- Observed CFG behavior.
- Expected pseudocode shape.
- Observed pseudocode shape.
- Hex-Rays version / IDA version.
- Classification tags.
- Notes and links to diagnostic DBs or dumps.

The registry should distinguish what we know from what we suspect. If an entry
is based on one IDA version only, it should say that explicitly.

## Existing Infrastructure To Reuse

The lab should build on current d810 tooling instead of creating a separate
project:

- Docker system runner: `tools/scripts/run_system_tests_docker.sh`
- Pseudocode dump harness: `tests/system/e2e/test_dump_function_pseudocode.py`
- Diagnostic SQLite snapshots: `src/d810/core/diag/snapshot.py`
- Diagnostic query CLI: `python -m d810.diagnostics`
- Merge-causality query: `python -m d810.diagnostics merge-causality`
- Block trace / lineage queries: `block-trace`, `block-lineage`, `ea-trace`
- CFG provenance logging: `src/d810/core/diag/cfg_provenance.py`
- Existing C/ASM samples under `samples/src/c` and `samples/src/asm`

## Current CLI

The lab has a small registry-driven CLI:

```bash
python -m tools.hexrays_structuring_lab list
python -m tools.hexrays_structuring_lab show single_pred_chain_merge
python -m tools.hexrays_structuring_lab validate-cfg single_pred_chain_merge
python -m tools.hexrays_structuring_lab command single_pred_chain_merge
python -m tools.hexrays_structuring_lab summarize --db path/to/diag.sqlite3
```

The observed cases have complete vertical slices: fixture, compiled-CFG
validation, Docker dump, and checked-in observation artifacts under
`observations/`. Additional cases should follow the same gate: no structuring
conclusion unless compiled-CFG validation passes first. The registry should not
point at local `.tmp` dump or diagnostic DB paths, and it should only keep
compact observation summaries. Durable observed predicates and structuring
details belong in checked-in JSON artifacts; `show` hydrates those artifacts
when printing a case.

## Status Model

Registry case statuses are intentionally narrow:

- `planned`: the case is designed but not validated.
- `compiled_cfg_validated`: the compiled binary CFG matches the hypothesis.
- `observed`: the case has a Hex-Rays observation summary.
- `invalid_compiled_cfg`: the compiled C fixture did not match the hypothesis.

Compiled-CFG validation statuses are:

- `not_run`
- `passed`
- `failed`
- `not_provided`

Once validation is implemented, `validate-cfg` is a gate. A failed validation
means the fixture is invalid; it does not produce a Hex-Rays structuring
conclusion.

Run summaries should include the compiled-CFG validation result:

```bash
python -m tools.hexrays_structuring_lab summarize \
  --db path/to/diag.sqlite3 \
  --cfg-validation path/to/cfg_validation.json \
  --require-cfg-validation
```

With `--require-cfg-validation`, the summary hard-fails unless the validation
result has `status=passed`.

## Success Criteria

The lab is useful only if it produces decisions for d810.

A successful pattern entry should answer:

- What exact CFG shape was tested?
- What did Hex-Rays do to it?
- Which snapshot proves that behavior?
- Which d810 lowering rule should change because of this?
- What invariant should become a test or contract?

If a pattern does not feed back into a d810 invariant, it is documentation, not
engineering leverage.
