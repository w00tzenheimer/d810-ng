---
id: lrea-t5gy
status: in_progress
deps: []
links: [dsf-katd]
created: 2026-07-22T01:23:57Z
type: bug
priority: 0
assignee: w00tzenheimer
tags: [decompilation, rhad, preopt, identity, mutation, regression]
---
# Restore the exact four-function Rhad semantic matrix

Repair lifecycle-integration regressions that disconnected previously observed Rhad evidence. Treat sub_40D200 as semantically green pending oracle reconciliation; restore real semantic failures in sub_40A560, sub_40C8B0, and sub_40CDA0. This is required follow-up to dsf-katd, whose closeout did not execute its stated four-function acceptance matrix.

## Design

Represent each terminal return as one fragment-atomic mutation through MbaMutationGateway: route edge, return carrier, and terminal m_ret are planned, applied, verified, and receipted together. A disconnected synthetic m_ret is forbidden. Any identity ambiguity, non-state use-def severance, or ownership mismatch rejects the whole fragment. Diagnostic DB lifecycle events must correlate evidence generation, stable EA identities, mutation plan, and receipt. No compatibility layer and no production sample-EA guards.

## Acceptance Criteria

Fresh cache-disabled exact Docker matrix is semantically 4/4 in one run: sub_40A560 matches its established side-effect and terminal-return oracle; sub_40D200 matches native semantics after correcting only an oracle proven stale by raw native comparison; sub_40C8B0 and sub_40CDA0 recover their established full bodies without dispatcher stubs or JUMPOUT exits. The diagnostic DB records one atomic terminal fragment plan/receipt containing carrier, m_ret, and route edge, with full-fragment abstention tests. Hodur, Sub7ffd, Tigress, and Approov remain green. Focused runtime/unit suites, sg scan, all 14 import contracts, graphify update, and Docker operation pass. Work is committed logically and the worktree is clean.


## Notes

**2026-07-22T01:24:07Z**

2026-07-21 baseline audit: fresh preserved donor aa0438157 exact Docker four-function matrix was 4 failed in 475.08s. Semantic classification: sub_40D200 emitted a full structured body with zero while loops and is green; its exactly-one-while assertion is stale/overconstrained and must be reconciled against native output. Real failures: sub_40A560 recovered None; sub_40C8B0 ended JUMPOUT(0x40CD46); sub_40CDA0 ended JUMPOUT(0x40CEAB). Donor log: /Users/mahmoud/src/idapro/d810/.tmp/rhad_aa043_four_matrix_20260721.txt. Current branch at 4ace85587 has A560 nearly matching but ends JUMPOUT(0x40C898); capture-time disconnected m_ret WIP is rejected by design and will be replaced with an atomic carrier plus terminal plus route fragment.
