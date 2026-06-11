# L6: Jump-table / N-way dispatch

Status: **DONE (2026-06-11)**. Roadmap: `ROADMAP.md` (L6). Harness: Phases 1-3.
Ticket llr-6aiq. Observation: `flat_jtbl_insert_unflatten.json`. Test:
`tests/system/runtime/hexrays/test_insert_unflatten_mini.py::TestInsertUnflattenJtbl`.

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

## Results (2026-06-11)
DONE. Fixture `lab_flat_jtbl.c` (5 dense keys 0..4) compiles to an `m_jtbl` at
GLBOPT1 (and CALLS); `test_dump_jtbl_structure` asserts the table + a readable
`mcases_t` (the L6 cfg-validation gate). `_jtbl_routing` reads `tail.r.c` ->
`{case_value: target}` straight from the table; `_build_jtbl_unflatten_plan`
redirects each state-writer to its routed handler and the switch DRAINS to a clean
linear chain (6 inserts, verify clean):

```c
g_hexrays_lab_sink = token + 0x11;
g_hexrays_lab_sink = (token + 0x11) ^ 0x22;
... ;
return (((token + 0x11) ^ 0x22) - 0x33 + 0x44) ^ 0x55;
```

Findings (in the observation JSON):
- **Density+count drive table lowering, not magnitude.** clang -O0 mingw emits
  `m_jtbl` for >=4 DENSE small keys (0..4); the large sparse 32-bit states the
  other lab fixtures use stay a `jz` if-chain. L6 deliberately uses small keys.
- **`old_target` is PER-WRITER, not a single dispatcher head.** The jtbl handlers
  goto a re-dispatch JOIN (blk9), while the entry gotos the jtbl block (blk2). So
  each writer's `old_target` = its own single successor (entry old=2, handlers
  old=9). The L1 mode-of-successors shortcut does NOT apply.
- **Deobfuscation DRAINS a switch, it never inserts one.** Reading `mcases_t`
  gives case->handler directly; d810's existing `m_jtbl` ops
  (`NormalizeNWayDispatcherExit` / `CanonicalizeJumpTableCaseOverlap`) only
  normalize an existing table -- none synthesize one.
