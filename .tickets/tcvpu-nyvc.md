---
id: tcvpu-nyvc
status: closed
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

**2026-07-16T00:14:16Z**

Terminal-only Slice 1 implementation completed through 3667b9245. Focused workbench/config/stats/action gate: 101 passed. Full unit gate: 5757 passed, 29 skipped, 9 pre-existing contract-vocabulary warnings, 162 subtests in 82.07s. ast-grep, import-linter, diff, prohibited-import, placeholder, and unanchored-block-serial scans are clean. Live dock/function-follow/theme/navigation/export acceptance remains deferred by user request, so this ticket stays in_progress.

**2026-07-16T22:02:00Z**

Live Docker/XQuartz acceptance completed against the copied `libobfuscated.dll.2026-06-03.i64` database through loopback MCP on port 13339. Named `--connect --open-workbench --function` runs opened `abc_f6_add_dispatch @ 0x180001000` and followed to `abc_f6_sub_dispatch @ 0x1800010D0`; the rendered source/runtime identities, six ordered config-v2 passes, rule scope, statistics, outcomes, and artifacts matched the immutable snapshot. Filtering reduced 18 rows to the one matching Rule scope row and restored all rows, row selection rendered structured detail, and the UI export matched the pure exporter byte-for-byte at SHA-256 `50f5b4b036249523b6f54d1b7e3c1587ba598f5a95c51a48708095c4db78a8c1`. Close/reopen created a new singleton without Qt warnings. A reload-specific stale persistent dock was found and fixed by giving the Stats action an explicit teardown that closes and releases its panel before module unload; after `D810.reload()`, both IDA and Qt reported no remaining workbench widget, and the named action recreated a live owned dock. Final automation audit: `.tmp/ida-gui/automation-410672afb9cf0ec636ca6dbb12c9c5c0.json`. Final X11 capture: `.tmp/ida-gui/live-workbench-final-0.png`.
