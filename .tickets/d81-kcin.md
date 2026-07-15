---
id: d81-kcin
status: in_progress
deps: []
links: []
created: 2026-07-15T23:04:05Z
type: feature
priority: 1
assignee: w00tzenheimer
parent: d81-38ha
tags: [ui, config-v2]
---
# Slice 0: truthful config-v2 project UI

Expose source and effective runtime project identity, make configuration duplication lossless, refuse unsafe config-v2 edits, show effective pass and expanded-rule counts, and lock the OLLVM routing behavior with a regression test.

## Acceptance Criteria

The current configuration UI distinguishes legacy and config-v2 projects; routed bundled defaults show source and runtime identities; config-v2 editing is read-only; duplication materializes the effective runtime document without dropping unknown or additional fields; the UI shows effective configured pass IDs and expanded instruction/block rule counts; the OLLVM bundled-default witness is covered; pure UI decisions are unit-tested in tests/unit/ui/test_*_logic.py.


## Notes

**2026-07-15T23:21:51Z**

Implementation plan saved at docs/superpowers/plans/2026-07-15-truthful-config-v2-project-ui.md. It defines lossless atomic core persistence, a manager-owned immutable snapshot and guarded command facade, pure project_config_logic action tests, thin ida_ui wiring, and the exact OLLVM 11-pass/180-instruction-rule/6-block-rule regression.
