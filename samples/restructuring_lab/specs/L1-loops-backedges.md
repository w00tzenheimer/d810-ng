# L1: Loops / back-edges

Status: planned (2026-06-06). Roadmap: `ROADMAP.md` (L1). Harness: optblock-stage
insert + state-free capture (Phases 1-3); see `AGENTS.md`.

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
