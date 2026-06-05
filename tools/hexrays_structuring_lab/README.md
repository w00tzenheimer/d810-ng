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
- Existing C/ASM samples under `samples/src/c` and `samples/masm`

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
