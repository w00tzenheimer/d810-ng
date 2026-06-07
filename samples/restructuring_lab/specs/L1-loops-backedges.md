# L1: Loops / back-edges

Status: **DONE (2026-06-06)**. Roadmap: `ROADMAP.md` (L1). Harness: optblock-stage
insert + state-free capture (Phases 1-3); see `AGENTS.md`. Observation:
`tools/hexrays_structuring_lab/observations/flat_loop_insert_unflatten.json`.
Test: `tests/system/runtime/hexrays/test_insert_unflatten_mini.py::TestInsertUnflattenLoop`.

## Goal
Prove a reconstructed function whose TRUE CFG contains a loop renders as a clean
`while`/`do-while`/`for` (not goto-soup, not the dispatcher loop).

## What d810 already has
`analyses/control_flow/`: `backedge_classifier.py`, `loops.py`, `loop_prover.py`,
`local_select_loop.py`, `scc_analysis.py`, `dominator.py`/`postdominator.py`.
Lowering op: `PhaseCycleLowering` (`graph_modification.py:629`).

## Gap
Every lab fixture so far is acyclic. No proof that inserting a genuine back-edge
(handler -> earlier handler) at the optblock stage yields a clean loop render;
`PhaseCycleLowering` is unvalidated in the lab.

## Approach
Reconstruct the back-edge with the optblock-stage insert: redirect the
loop-body handler's transition to the loop-header handler (a back-edge to a
lower-serial block), and the exit transition to the post-loop handler. Reuse the
P2a conditional-routing extractor for the loop-exit predicate (loop continues vs
exits is a conditional state transition).

## Fixture
`c/lab_flat_loop.c`: a counter loop, large-const states. `H0` inits counter;
`Hbody` does work + `--counter`; if `counter != 0` -> `Hbody` (back-edge) else
-> `Hexit` -> return. True CFG: `entry -> Hbody (loop) -> Hexit -> return`.

## Success criteria
`mba.verify()` clean; render contains a real loop keyword (`while`/`do`/`for`)
over the body; no dispatcher state constants; counter/body present. Observation
artifact recorded.

## Risks / IR-dump unknowns
Does IDA accept an inserted back-edge to a lower-serial block + render a loop, or
require block reorder (L13)? Loop-exit may be a conditional transition (P2a). The
counter induction must survive (don't strip it as a "state write").

## Dependencies
P1 (insert), P2a (conditional routing for the exit). Possibly L13 (reorder).

## Results (2026-06-06)
DONE. `mba.verify()` clean (no INTERR), 5 inserts applied, renders a clean
`do { r ^= 0x22; sink = r; --counter } while (counter)` with `r += 0x11` hoisted
before and `r -= 0x33` after -- no dispatcher loop, no state constants, counter
induction intact. 10 passed / 1 xfailed across the lab file.

Key findings (all in the observation JSON):
- **The general unflatten rule gives loops for free.** `_build_unflatten_plan`
  redirects every *genuine dispatcher-returning* state-writer to the handler its
  state routes to (TERM-writers -> terminal). A handler that writes a state
  routing back to an earlier handler (the body's continue-arm, blk8 -> body blk7)
  becomes a real retreating edge. **No loop-specific lowering op was needed**
  (`PhaseCycleLowering` stayed unused); L1 generalizes the linear P1 plan.
- **Dispatcher head = MODE of writer successors, not their intersection.** The
  loop body (blk7) is BOTH a handler (routed-to by K1) AND a 2WAY that writes its
  own next-state, with successors = its counter arms {8,9}, not the dispatcher.
  An intersection over all writers therefore collapses to empty (`disp=-1`). The
  most-common-successor is robust (dispatcher head appears 5x; the arms 1x each).
- **Filter spurious writers by `succ == disp`.** blk7 writes K1 but branches into
  its own arms; redirecting `7 -> routing[K1]=7` would be a degenerate
  self-redirect. Only writers whose successor includes the dispatcher head are
  genuine dispatcher edges.
- The empty insert trampolines on the back-edge do NOT block loop structuring --
  Hex-Rays coalesces them and emits a structured `do/while`.
