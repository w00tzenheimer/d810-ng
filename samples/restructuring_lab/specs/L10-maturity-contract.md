# L10: Maturity-timing contract

Status: planned (2026-06-06). Roadmap: `ROADMAP.md` (L10). Harness: Phases 1-3 +
L4 (gate).

## Goal
Formalize which lowering op is legal at which decompiler maturity, and reject
wrong-maturity application BEFORE it produces a runtime INTERR. We proved the
stage matters: glbopt-stage inserts trip INTERR 50346, optblock/GLBOPT1 inserts
do not.

## What d810 already has
`passes/transaction_policy.py` (phase ordering), the maturity gate inside the
optblock (`mba.maturity == MMAT_GLBOPT1`). De-flatten ledger: "no maturity-timing
contract".

## Gap
The legal-maturity window per op is implicit (hardcoded `MMAT_GLBOPT1` in the lab
optblock). No declarative contract; nothing rejects a CFG-shape op applied at a
post-optimization stage.

## Approach
A small contract mapping each `ModificationType`/op -> its legal maturity window,
checked before apply (a stage check folded into the projected gate, L4). Inserts
must run in the optblock pass during GLBOPT1; post-opt `glbopt` application is
rejected by the contract rather than surfacing as INTERR 50346.

## Fixture
Reuse the P1 glbopt-stage negative control: the maturity contract should REJECT
the glbopt-stage insert pre-apply (turning the current xfail/INTERR into a clean
contract rejection); the GLBOPT1 optblock insert is allowed.

## Success criteria
Contract allows GLBOPT1-optblock inserts, rejects glbopt-stage CFG-shape ops
pre-apply; the rejection message names the op + the required maturity. No reliance
on the runtime INTERR for stage errors.

## Risks / IR-dump unknowns
Defining each op's window precisely; integrating with L4's gate; distinguishing
"notification" hooks from the optblock optimizer.

## Dependencies
L4 (projected gate). Resolves the 50346 stage-class from L5.
