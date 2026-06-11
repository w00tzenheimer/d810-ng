# Lowering-primitive catalog

Status: in progress (2026-06-11). Ticket llr-jd2t.
Module: `tests/system/runtime/hexrays/lowering_catalog.py`.
Proof: `tests/system/runtime/hexrays/test_lowering_catalog.py`.
Oracles: `samples/restructuring_lab/c/lab_ref.c` (the non-flattened siblings).

## What this is

The restructuring lab's PRODUCT is a small set of **lowering primitives** -- reusable
operations that take a portable IR description of a recovered structure and emit the
microcode that Hex-Rays lowers to the **expected pseudocode**. "Expected" = the
original, non-flattened source (`lab_ref_*`), decompiled at baseline. Each primitive
is proven in the lab against that compiled-source oracle (the project's
oracle-equivalence gate).

The fixture is the forcing function; the **primitive** is the deliverable.

## Separation of concerns (mirrors the three-tier invariant)

- **ANALYSIS** (read-only): `recover_*` -> an IR plan (pure data, no mutation).
- **LOWERING** (the catalog): `lower_*` (IR plan -> `DeferredGraphModifier` emits).
- **MUTATION**: `DeferredGraphModifier.apply` (the vendor backend).

## The thesis: few primitives, many front-ends

There are only a FEW lowering primitives; every flattened shape is one of them with a
different *analysis front-end*. The shape is in the recovered routing graph, not in
the lowering.

|-|-|-|
| primitive | shapes | status |
| `DispatchDrain` -- redirect each routed state-writer to its handler | mini (linear), loop (back-edge emergent), cond (preserved handler branch), region (shared join); + jtbl via a separate `mcases_t` front-end | DONE -- 5 shapes, 2 front-ends, all == oracle |
| `ConditionalSynthesize` -- build a 2-way from a recovered predicate | branchless select (no jcc) | TODO (L8 logic; composes with DispatchDrain) |
| `RegionDeshare` -- clone conditional head + de-share tail | region duplicate (P3 = degenerate single-block case) | TODO (L7 phase-2 logic; oracle = duplicated sibling) |

`DispatchDrain` is ONE primitive whether the routing came from a `jz`-chain or a jump
table -- `recover_dispatch_jzchain` and `recover_dispatch_jtbl` are two front-ends
feeding the identical `lower_dispatch_drain`.

## The oracle: semantic-structural equivalence

Textual comparison to the ref decompile is infeasible: the flat-unflatten and the
ref-fresh-compile produce semantically-equal but structurally-different microcode, and
Hex-Rays renders each with different optimizations (DSE, store-forwarding, global
read-back, common-store hoisting). So the oracle is a **semantic signature**:

- the **control-flow skeleton** -- the `if/else/while/do/for/return` keyword + condition
  sequence (drop plain statements + braces, so store placement/hoisting is irrelevant);
- the **operation set** -- the `(operator, constant)` arithmetic ops (the handler work,
  independent of how many times / where Hex-Rays materializes it).

Two renders lower-equivalently iff their signatures are equal. This stays robust to
rendering choices while still failing on a wrong control structure or a wrong/missing
handler operation. (`semantic_signature` in the catalog module.)

## Done

- `DispatchDrain` primitive + `recover_dispatch_jzchain` + `recover_dispatch_jtbl`,
  proven == the `lab_ref_*` oracle for mini / loop / cond / region / jtbl (5 passed).
- Oracle harness: `apply_lowering_and_render` (optblock-stage recover+lower+render),
  `render_reference` (baseline sibling), `semantic_signature` (the comparator).

## Next

- `ConditionalSynthesize` (branchless) -- extract the L8 predicate-recovery + lower
  (`queue_lower_conditional_state_transition`); composes with `DispatchDrain` for the
  rest of the dispatcher. Oracle = `lab_ref_cond`.
- `RegionDeshare` (region duplicate) -- extract the L7 phase-2 two-pass; oracle = a new
  `lab_ref_region_deshare` sibling (the region duplicated per path).
- Then retire the shape-centric assertions in `test_insert_unflatten_mini.py` in favour
  of the primitive + oracle (the catalog subsumes them).
