---
id: tcvpu-z1b4
status: in_progress
deps: [tcvpu-nyvc]
links: []
created: 2026-07-15T23:52:25Z
type: feature
priority: 1
assignee: w00tzenheimer
parent: d81-38ha
tags: [ui, workbench, actions]
---
# Slice 2: scoped workbench interaction

Add read-only Analyze, lifecycle-safe Deobfuscate, existing function-override integration, generation-aware refresh, and stale-result rejection.

## Acceptance Criteria

Analyze cannot invoke mutation; Deobfuscate delegates to the existing manager lifecycle exactly once; existing function rule/tag/note persistence and invalidation remain authoritative; async results are generation checked; pure action tests and runtime adapter contracts pass.


## Notes

**2026-07-16T00:17:19Z**

Implementation plan saved at docs/superpowers/plans/2026-07-16-deobfuscation-workbench-slice-2.md. It defines immutable generation-bound commands, direct recon-only Analyze, exact-once reuse of existing Deobfuscate and FunctionRules actions, pure stale-result rejection, thin context adaptation, and deferred live Qt acceptance.
