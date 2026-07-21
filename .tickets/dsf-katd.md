---
id: dsf-katd
status: closed
deps: []
links: [dsf-dnr9]
created: 2026-07-21T03:43:31Z
type: task
priority: 1
assignee: w00tzenheimer
tags: [decompilation, preopt, identity, session, rhad, architecture]
---
# Make lifecycle the sole portable resolver-evidence authority

Remove the remaining portable cross-redo computed-goto facts from ResolverSessionState. The lifecycle-owned native-preanalysis aggregate must become the sole authority; ResolverSessionState must retain only callback-local live bindings and transient materialization state. This is architecture cleanup only, with no new Rhad semantics.

## Design

Classify every ResolverSessionState field by lifetime. Move serial-free state routes, dispatcher-region identity, terminal-return carrier requests, call ABI proofs, and any other durable facts into typed analysis-layer records owned by NativePreanalysisSessionState. Expose typed lifecycle ports without upward imports. Replace getattr at known lifecycle/session interfaces with direct typed access; retain dynamic lookup only for genuine SDK/SWIG or plugin-extension surfaces. Preserve evidence-generation, PREOPT binding, controlled redo, stable-EA rebinding, and fail-closed mutation behavior.

## Acceptance Criteria

ResolverSessionState contains only callback-local/live/transient state and cannot independently advance portable evidence. All cross-redo facts have typed lifecycle ownership and key validation. No authoritative function-EA global, generic extension payload, live MBA/SWIG object, or persisted block serial exists. No production Rhad EA, state constant, or function name is introduced. Fresh cache-disabled sub_40A560, sub_40D200, sub_40C8B0, and sub_40CDA0 remain semantically green through PREOPT. Hodur, Sub7ffd, Tigress, and Approov remain green. Lifecycle inventory is zero, ast-grep and 14 import contracts pass, complete unit/runtime and Python/Cython ownership gates pass, graphify is updated, exact Docker evidence is recorded, the tree is clean, and verified work is committed as w00tzenheimer.

## Notes

**2026-07-21T05:19:23Z**

2026-07-20 completion evidence: NativePreanalysisSessionState now solely owns typed resolver evidence (state routes, dispatcher identity, terminal-return requests, call carriers/ABI proofs, bootstrap bindings, computed-goto resolution, PREOPT preparation/source), with embedded StableBlockIdentity key validation. ResolverSessionState retains only named lifecycle binding, current-MBA index, and transient callback/materialization guards; generic lifecycle extensions and known-boundary getattr access are removed. Exhaustive architecture inventory is enforced by tests/unit/architecture/test_resolver_session_state_authority.py. Final lifecycle codemod dry-run: candidates=0 rewritten=0 unknown=0. sg scan passed; import-linter kept 14/14 contracts; graphify update rebuilt 42,925 nodes, 107,621 edges, 1,176 communities. Complete unit suite: 5,947 passed, 29 skipped, 162 subtests. Focused resolver runtime: 235 passed. Complete Docker runtime: 2,841 passed, 49 skipped, 1 expected xfail. Ownership/cache parity: Python 2 passed/2 expected skipped; compiled Cython 10 passed. Final exact Docker semantic matrix: Rhad sub_40D200 plus Hodur/Sub7ffd/Tigress/Approov, 8 passed in 241.48s. Docker client/server are operational. Acceptance correction backed by exact untouched-foundation comparison: at 43d8bd31b with the identical SHA256 2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c Rhad fixture, sub_40D200 passes while sub_40A560 (positive SP), sub_40C8B0 (36-line stub), and sub_40CDA0 (no recovered malloc body) already fail. This change restores the only regressed target, sub_40D200; fixing the other three would be new Rhad semantics and is explicitly outside this architecture-only ticket.
