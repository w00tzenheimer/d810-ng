---
id: dsf-dnr9
status: open
deps: []
links: []
created: 2026-07-18T23:53:24Z
type: epic
priority: 1
assignee: w00tzenheimer
tags: [decompilation, preopt, identity, session, rhad]
---
# Decompilation session foundation closure

Close the portable session, identity, evidence, and mutation architecture around the already-green fresh cache-disabled `sub_40D200` A0 proof. Preserve `0x40D348 -> state 0x699BC698 -> handler 0x40EAA7`; do not add further Rhad semantics. Defer serialized snapshots, netnode persistence, cache reuse, and B2-B5. Preserve every protected family while architectural ownership changes.

## Design

Strict foundation-first order: specification correction; complete B0 inventory and terminology with no compatibility bridge; land an IDA-free `NativePreanalysisKey` in `d810.core` before `StableBlockIdentity`; complete portable identity and the live MBA index; make the coordinator-owned mutation gateway the only structural executor; implement `NativePreanalysisFacts` and the canonical coordinator session operations; fold the A0 route and resolver attachments into that aggregate; finally re-run A0 and all protected-family gates. `d810.ir` must never import upward from `d810.analyses` to obtain the key.

## Acceptance Criteria

Codemod dry-run has zero candidates and unknowns, including embedded lifecycle identifiers. Compatibility and temporary-port manifests remain empty. `NativePreanalysisKey`, `StableBlockIdentity`, `MbaBlockIdentityIndex`, mutation receipts, `NativePreanalysisFacts`, and coordinator session operations satisfy their final contracts. Every structural MBA mutation uses the coordinator-owned gateway; no resolver global, fallback gateway, adapter serial map, or persisted block serial remains. Static boundaries, Python/Cython ownership tests, graphify, complete focused/runtime suites, and Docker Rhad bootstrap/full semantic, Hodur, Sub7ffd, Tigress, and Approov gates pass. The ticket closes only with exact evidence, a clean foundation tree, and the donor tree untouched.


## Notes

**2026-07-19T00:00:08Z**

Design target locked: A0 is one vertical slice (session-owned evidence generation plus stable native-EA identity) before the first controlled redo. Detailed local plan: docs/superpowers/plans/2026-07-18-a0-session-identity-preopt-bootstrap.md. TODO.md records tracked scope and acceptance gate.

**2026-07-19T00:04:52Z**

2026-07-19 planning correction: pre-decompile native analysis is useful only through manager-owned session persistence. Updated TODO.md and the A0 execution plan so portable native evidence, evidence generation, and bound PREOPT generation are first-class DecompilationSessionContext state; no authoritative extensions/getattr/function-EA map. Eager preflight, hxe_flowchart fallback, and hxe_prolog defensive fallback all idempotently ensure one session; MERR_REDO reuses it. Live MBA/SWIG/block serial state remains callback-local. Netnode/serialized persistence stays deferred until the fresh no-cache path is green.

**2026-07-19T00:09:22Z**

Baseline: direct Docker Hodur/Sub7ffd gate passed (3 passed, 26.78s). A fresh cache-disabled sub_40D200 E2E now runs with the root donor fixture mounted read-only and fails as intended: 0 PreoptBootstrapRouteFact rows in its copied diagnostic DB (85.47s).

**2026-07-20**

Scope correction: A0 is now green on the foundation branch, but the portable contracts remain incomplete. The ticket is re-scoped to strict foundation closure before any A1/A2 work. The dependency contradiction is resolved by placing `NativePreanalysisKey` in `d810.core.native_preanalysis_key`, below both `d810.ir` and `d810.analyses`. Execution and commit boundaries are recorded in `docs/superpowers/plans/2026-07-20-decomp-session-foundation-closure.md`.
