# L12: MBA / opaque-predicate simplification (structurability track)

Status: planned (2026-06-06). Roadmap: `ROADMAP.md` (L12). NOTE: this is the
*structurability* half (clean rendering of valid microcode), largely the existing
optimizer rule engine -- orthogonal to the insert primitives.

## Goal
Validate that obfuscated handler bodies (MBA-encoded constants, opaque predicates)
simplify to readable expressions in the render, so reconstructed functions are not
just structurally clean but semantically legible.

## What d810 already has
The optimizer rule engine: `InstructionOptimizerManager` (`optinsn_t`), MBA rules
(`optimizers/.../rules`, `mba/` DSL + Z3 verification), opaque-predicate handling
in the deobfuscation passes.

## Gap
Lab fixtures have clean arithmetic bodies. Real handlers carry MBA obfuscation +
opaque predicates; we have not exercised the rule engine in the restructuring-lab
harness alongside the insert reconstruction.

## Approach
A fixture whose handler body is an MBA-encoded constant + an opaque predicate;
let the rule engine simplify during decompilation; assert the render shows the
de-obfuscated value / the opaque predicate folded. This validates existing rules
in the lab context, not new lowering ops.

## Fixture
`c/lab_mba_handler.c`: a handler with an MBA-encoded constant (e.g.
`(x|y)+(x&y)` == `x+y`) and an always-true/false opaque predicate gating a branch.

## Success criteria
Render shows the simplified expression and the opaque branch resolved; verify
clean. Observation records which rules fired.

## Risks / IR-dump unknowns
This is the rule-engine track -- scope it separately from the insert primitives;
which rules fire at which maturity; Z3-backed rule selection.

## Dependencies
Independent of L1-L11 (rule engine). Improves any reconstructed function's
legibility.
