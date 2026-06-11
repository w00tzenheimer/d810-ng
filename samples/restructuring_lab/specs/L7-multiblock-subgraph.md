# L7: Multi-block subgraph insertion

Status: **DONE (2026-06-11)**. Roadmap: `ROADMAP.md` (L7). Harness: Phases 1-3.
Ticket llr-5866. Observation: `flat_region_multiblock.json`. Test:
`tests/system/runtime/hexrays/test_insert_unflatten_mini.py::TestInsertUnflattenRegion`.

## Goal
Insert a captured **region** (2+ blocks with internal edges) as a unit -- e.g.
de-share a shared multi-block continuation, not just a single block (P3).

## What d810 already has
`DuplicateReplayAndRedirect` (`graph_modification.py:545`), `PatchPlan.new_blocks`
(`tuple[PatchBlockSpec, ...]` -- multiple new blocks with inter-block edges),
`InsertBlock`, `create_standalone_block`.

## Gap
P3 de-shares a single block. A shared continuation that is itself 2+ blocks
(internal branch/sequence) has no lab proof; multiple `new_blocks` with internal
edges + serial assignment are untested.

## Approach
Capture the multi-block region state-free (each block's payload + the internal
edges), express as `new_blocks` (>=2 `PatchBlockSpec`) with the internal edges,
insert one private region copy per predecessor, redirect to the region exit.

## Fixture
`c/lab_flat_region.c`: a shared continuation of two blocks (e.g. a small
sequence or inner if) reached by two paths via the dispatcher.

## Success criteria
`mba.verify()` clean; render duplicates the 2-block region per path, state-free;
internal structure preserved. Observation recorded.

## Risks / IR-dump unknowns
Inter-new-block edge wiring + serial assignment for multiple inserts in one apply;
capturing a multi-block region (vs single-block); ordering for the internal edges.

## Dependencies
P3 (single-block de-share); the capture helper extended to multi-block regions.

## Results (2026-06-11)
DONE. Fixture `lab_flat_region.c`: a 2-block shared region (head `r-=0x22` + an
internal `if(token&2)` branch -> tail `r^=0x33`) reached from two paths A and B,
behind a clean entry handler (so L7 isolates the region, not L2). Delivered BOTH
reconstructions the user asked for:

**Phase 1 -- join-preserve (recommended, the correct deobfuscation).** The general
unflatten rule (region-aware const set incl KENTRY+RT) redirects every
dispatcher-returning state-writer to its routed handler. The region head becomes a
JOIN (its two writers A,B both route to it); the internal branch is preserved
(only its arms are redirected). Renders the region head `- 0x22` EXACTLY ONCE
(assert count==1) -- a shared join, no bloat. 8 inserts, verify clean.

**Phase 2 -- de-share / duplicate (per the spec).** TWO passes via optblock
re-entry: (0) drain the entry AND clone the region HEAD (conditional) per path via
`queue_create_conditional_redirect` (taken->tail, else->exit; jcc SENSE resolved by
which head arm writes RT); (1) de-share the now-multi-pred TAIL P3-style (re-found
across the pass-0 serial shift by instruction-EA overlap). Renders the whole region
(head + internal branch + tail) DUPLICATED into both arms. pass0=5 + pass1=3
inserts, verify clean.

Key findings (in the observation JSON):
- A multi-block region with an internal branch is NOT a single-block P3 de-share:
  the internal jcc must be cloned (`create_conditional_redirect`) and the tail
  de-shared separately.
- De-share = clone the conditional HEAD per path, THEN de-share the multi-pred
  TAIL. Two passes avoid cross-insert serial prediction; re-identify the tail by
  instruction-EA overlap after the serial shift.
- Join-preservation is the bloat-free correct reconstruction; duplication is the
  niche P3-extension capability. Both proven.
