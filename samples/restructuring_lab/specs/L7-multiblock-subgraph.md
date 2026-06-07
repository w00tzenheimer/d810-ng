# L7: Multi-block subgraph insertion

Status: planned (2026-06-06). Roadmap: `ROADMAP.md` (L7). Harness: Phases 1-3.

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
