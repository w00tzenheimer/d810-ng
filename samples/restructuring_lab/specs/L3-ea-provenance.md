# L3: EA / provenance for inserted instructions

Status: planned (2026-06-06). Roadmap: `ROADMAP.md` (L3). Harness: Phases 1-3.

## Goal
Inserted/copied instructions carry meaningful source EAs (not the `mba.entry_ea`
hack), so the decompiler maps reconstructed code to the right source lines.

## What d810 already has
`hexrays/mutation/insn_snapshot_materializer.py` (sets EA + `IPROP_PERSIST`); the
`entry_ea` substitution in `cfg_mutations.insert_nop_blk`/synthesized gotos that
avoids INTERR 50863 (EA outside func).

## Gap
Inserts currently stamp `mba.entry_ea` on synthesized/copied insns, so every
reconstructed instruction maps to the function-entry line. The de-flatten ledger
notes `StateWriteAnchor` lacks `insn_ea`.

## Approach
When capturing a payload (P3), preserve each source instruction's original EA on
its copy (validated within `[func.start, func.end)` to avoid INTERR 50863). For
genuinely synthesized insns, anchor to the nearest meaningful source EA.

## Fixture
Reuse P1/P3 fixtures. Add an assertion that the inserted block's instruction EAs
are their SOURCE EAs (distinct from `entry_ea`), and that the `cfunc` line map is
non-degenerate.

## Success criteria
Inserted insns carry source EAs (not all `== entry_ea`); `mba.verify()` clean (no
50863); pseudocode line-mapping is reasonable. Observation records the EA scheme.

## Risks / IR-dump unknowns
Captured EAs may collide / be reused -> may need uniqueness handling. Confirm the
50863 range rule. Some materialization paths force `entry_ea` deliberately.

## Dependencies
P1/P3. Improves render quality for L1/L6/L7 on real functions.
