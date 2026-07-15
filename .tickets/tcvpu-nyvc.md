---
id: tcvpu-nyvc
status: in_progress
deps: []
links: []
created: 2026-07-15T23:52:25Z
type: feature
priority: 1
assignee: w00tzenheimer
parent: d81-38ha
tags: [ui, workbench, config-v2]
---
# Slice 1: read-only deobfuscation workbench

Build the IDA-independent workbench snapshot service, pure projection logic, dock adapter, function following, pipeline/detail presentation, refresh, evidence export, and Stats compatibility entry point.

## Acceptance Criteria

Immutable function/runtime/attack/pipeline/outcome/rule-scope/artifact snapshots are produced without Qt or live Hex-Rays pointers; pure workbench logic distinguishes the approved outcome vocabulary and action states; the thin dock renders source/runtime truth and ordered stages; evidence export is deterministic; unit and source-level adapter tests pass.


## Notes

**2026-07-15T23:57:01Z**

Implementation plan saved at docs/superpowers/plans/2026-07-15-deobfuscation-workbench-slice-1.md. It defines immutable manager models, truthful pass/preflight/outcome/rule/stat/artifact collection, pure projection/export logic, a thin dock adapter, stable Stats redirect, automated gates, and an explicitly deferred live IDA/Qt acceptance gate.
