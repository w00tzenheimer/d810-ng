---
id: tcvpu-guv6
status: in_progress
deps: [tcvpu-z1b4]
links: []
created: 2026-07-15T23:52:25Z
type: feature
priority: 1
assignee: w00tzenheimer
parent: d81-38ha
tags: [ui, workbench, oracle]
---
# Slice 3: native decompile comparison

Capture an isolated native-decompile baseline and compare it with the latest D810 output using fingerprint and generation freshness metadata.

## Acceptance Criteria

Native capture suppresses D810 hooks for one decompilation without changing persistent engine state; baseline and D810 references carry fingerprint, IDB, type, Hex-Rays, runtime, and generation identity; stale output is never labeled current; pure freshness tests pass.


## Notes

**2026-07-16T00:29:34Z**

Implementation plan saved at docs/superpowers/plans/2026-07-16-deobfuscation-workbench-slice-3.md. It defines identity-bearing native/D810 artifacts, an IDA-independent freshness/metrics service, exact one-shot hook-suppressed native capture, pure comparison projection, thin adapter wiring, and deferred live acceptance.
