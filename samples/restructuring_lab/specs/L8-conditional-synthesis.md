# L8: Conditional synthesis (branchless / recovered predicate)

Status: **DONE (2026-06-11)**. Roadmap: `ROADMAP.md` (L8). This was the deferred
Phase 2b. Harness: Phases 1-3. Ticket llr-se40. Observation:
`flat_branchless_synth.json`. Test:
`tests/system/runtime/hexrays/test_insert_unflatten_mini.py::TestInsertUnflattenBranchless`.

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

## Results (2026-06-11)
DONE. Fixture `lab_flat_branchless.c` selects the next state with mask arithmetic
(`state = (K1 & -(token&1)) | (K2 & ~-(token&1))`). At GLBOPT1 the select survives
as a SINGLE `m_or` in H0 (no jcc). `_find_low_bit_predicate` DFS-walks the m_or
tree for the `& #1` sub-instruction and clones it as the live `(token&1)` mop;
`queue_lower_conditional_state_transition` strips the m_or + goto and builds
`m_jnz (token&1), 0 -> H1` with a fall-through helper to H2. Plus entry->H0 and
H1/H2->terminal redirects to drain the dispatcher (4 mods, verify clean):

```c
g_hexrays_lab_sink = token + 0x11;
if ( (token & 1) != 0 ) { v2 = (token + 0x11) ^ 0x22; g_hexrays_lab_sink = v2; }
else                    { v2 = token - 0x22;          g_hexrays_lab_sink = ...; }
return v2;
```

Findings (in the observation JSON):
- **The predicate is recovered LIVE from the surviving MBA, not reconstructed.**
  ecx (token) is untouched by H0's stack-var arithmetic, so the cloned `cl&1`
  condition stays valid after the m_or is removed.
- **`_materialize_condition_mop` accepts a raw `mop_t` via `assign()`** -- not only
  the `SyntheticCounterBoundCondition` (counter/bound) descriptor -- so an
  arbitrary recovered predicate operand works as the synthesized jcnd condition.
- **L12 MBA machinery was NOT needed** for this select; a targeted `(x&1)`
  tree-walk sufficed. Richer branchless selects may need the abstract-domain
  predicate recovery.
- **Constant folding** collapses the else arm's `-0x33` with H0's `+0x11` into
  `token - 0x22` -- assert the if/else STRUCTURE + `& 1` + folded `- 0x22`, not a
  raw `0x33` (same lesson as the P2a cond test).
