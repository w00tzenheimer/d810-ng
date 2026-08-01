---
id: tcvpu-f21a
status: in_progress
deps: []
links: []
created: 2026-07-17T19:48:13Z
type: feature
priority: 2
assignee: w00tzenheimer
tags: [ui, diagnostics, cleaner]
---
# Simplify Diagnostics Explorer cleaner controls

Replace the Cleaner button grid with an intent-based cleanup composer. Keep only selected-snapshot deletion and count-based retention as snapshot cleanup policies; remove time/timestamp cleanup. Separate database maintenance (quarantine, purge closed, reclaim storage), preserve plan-first execution and active-session safety.

## Acceptance Criteria

No Unix timestamp cleanup control or action remains; only action-relevant parameters are visible; plan-first confirmation remains explicit; focused unit/UI contract tests pass; live IDA/X11 presentation is checked before close.


## Notes

**2026-07-17T20:10:09Z**

Implemented intent-based Diagnostics cleaner: selected-snapshot deletion and retain-latest-N only; removed UI time/timestamp cleanup; maintenance actions remain explicit; plan-first confirmation stays hidden until preview; WAL checkpoint is forced; optional storage reclaim is snapshot-only. Verification: 6188 unit tests passed; ast-grep and import-linter passed. X11 native workbench launch succeeded against a copied sample IDB. Remaining: direct visual inspection of the Diagnostics Explorer dock is pending because XQuartz accessibility timed out; container is left available for manual inspection.
