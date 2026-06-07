# L2: Full state elimination (reg-sourced / computed / entry)

Status: planned (2026-06-06). Roadmap: `ROADMAP.md` (L2). Harness: Phases 1-3.

## Goal
Eliminate ALL state-machine variables from the render, including reg-sourced and
computed state writes and the entry selector -- not just constant stack writes.

## What d810 already has
`_state_slot` (KT-discriminated state-var detection, lab helper),
`ZeroStateWrite` (`graph_modification.py:400`),
`analyses/control_flow/state_transition_domain.py` (StateValue lattice).

## Gap
P3 left a residual: the entry selector `v1 = K0/K1` survives because it is
reg-sourced (computed in a register by the entry conditional), and our capture
only strips constant writes to the detected slot. Real functions set state via
registers / arithmetic / MBA.

## Approach
(1) Track reg-sourced state: follow `reg <- const` then `slot <- reg` chains so
the entry's K0/K1 are recognized as state writes. (2) Reconstruct the entry
conditional (redirect the entry arms directly to their handlers, P2a-style) so
the `state == K` compare disappears. (3) Strip/retarget the reg-sourced writes.

## Fixture
Reuse `lab_flat_shared` (the P3 residual) and `lab_flat_cond`. Tighten the
assertion to **no state constant anywhere** (K0/K1/KS/KT all absent).

## Success criteria
Render fully state-free: none of the state constants appear; the entry renders as
the original predicate (e.g. `if (token & 1)`), not `if (v1 == K1)`. Verify clean.

## Risks / IR-dump unknowns
Reg-sourced state tracking is a small def-use walk; confirm the entry's
`eax -> slot` copy form at the IR. Entry-predicate recovery may overlap L8.

## Dependencies
P2a (conditional reconstruction), P3 (de-share). Feeds L1/L6/L7 (all need a
clean state var).
