# L8: Conditional synthesis (branchless / recovered predicate)

Status: planned (2026-06-06). Roadmap: `ROADMAP.md` (L8). This is the deferred
Phase 2b. Harness: Phases 1-3.

## Goal
Synthesize an `if/else` when the next-state predicate is **branchless** (no `jcc`
to preserve) -- mask/cmov arithmetic or a predicate recovered from dataflow.

## What d810 already has
`LowerConditionalStateTransition` (`graph_modification.py:565`),
`CreateConditionalRedirect` / `queue_create_conditional_redirect` (clones a ref
conditional into a new 2-way block).

## Gap
P2a only handles the predicate-already-a-jcc case (preserve + redirect). When the
flattener encodes `state = cond ? K1 : K2` branchlessly there is no `jcc`, so the
branch must be **built**; and `queue_create_conditional_redirect` needs a ref
conditional to clone -- which may not exist.

## Approach
Recover the predicate from the branchless select (e.g. `mask = -(token&1)`,
`state = (K1 & mask) | (K2 & ~mask)`), synthesize a conditional via
`LowerConditionalStateTransition` (build the `jcnd` from the recovered predicate)
branching to the two handlers. May need MBA simplification (L12) to recover the
predicate.

## Fixture
`c/lab_flat_branchless.c`: next-state chosen via mask arithmetic, no `jcc` in the
handler. Validate the compiled CFG has no branch at the transition.

## Success criteria
`mba.verify()` clean; render is an `if/else` on the recovered predicate; no state
var. Observation records the recovered predicate.

## Risks / IR-dump unknowns
Predicate recovery from mask/MBA arithmetic (the hard part -- overlaps L12);
synthesizing a verifier-valid `jcnd`; whether `queue_create_conditional_redirect`
applies without a ref block (may need a synthesized-condition variant).

## Dependencies
P2a; likely L12 (MBA recovery of the predicate).
