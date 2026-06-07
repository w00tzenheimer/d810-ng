# L6: Jump-table / N-way dispatch

Status: planned (2026-06-06). Roadmap: `ROADMAP.md` (L6). Harness: Phases 1-3.

## Goal
Lab-validate reconstruction of a dispatcher compiled to a **jump table**
(`m_jtbl`) rather than an `if`-chain of `jz` compares.

## What d810 already has
`NormalizeNWayDispatcherExit`, `CanonicalizeJumpTableCaseOverlap`
(`graph_modification.py:585,605`), `hexrays/mutation/dispatcher_materialization.py`,
`m_jtbl` handling in `cfg_mutations.py` (jtbl case-target updates).

## Gap
Our fixtures are if-chain (`jz` on state consts). The routing extractor reads
`m_jz`/`m_jnz`; it does not read `m_jtbl` `mcases_t`. No jtbl fixture/proof.

## Approach
Add an `m_jtbl`-reading routing extractor (state-value -> handler from the jump
table's `mcases_t` case/target pairs). Reconstruct handlers off the jtbl with the
optblock-stage inserts (as in P1/P2a). Render should drop the jtbl/switch.

## Fixture
`c/lab_flat_jtbl.c`: a flattened dispatcher with state values dense/large enough
that clang emits `m_jtbl` (may require tuning -- a contiguous-ish key range or a
larger handler count). Validate the compiled CFG actually contains `m_jtbl`.

## Success criteria
`mba.verify()` clean; render contains no `switch`/jtbl dispatcher and no state
var; handlers reconstructed as a chain/branch. Observation records the jtbl shape.

## Risks / IR-dump unknowns
Forcing clang to emit `m_jtbl` (it may keep `jz` chains for sparse 32-bit states);
extracting routing from `mcases_t`; jtbl operand fixups when handlers are
redirected (`CanonicalizeJumpTableCaseOverlap`).

## Dependencies
P1/P2a; extends the routing extractor (`_dispatcher_routing`).
