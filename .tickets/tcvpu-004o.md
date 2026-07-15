---
id: tcvpu-004o
status: open
deps: [tcvpu-nyvc, tcvpu-z1b4]
links: []
created: 2026-07-15T23:52:25Z
type: feature
priority: 1
assignee: w00tzenheimer
parent: d81-38ha
tags: [ui, recipes, config-v2]
---
# Slice 4: registered-pass Recipe Composer

Compose registered passes and explanatory owned transforms into ordered function recipes with pure draft operations, contract preflight, apply-once, and sibling function-recipe persistence.

## Acceptance Criteria

Catalog and draft use stable registered pass IDs; add/remove/enable/disable/reorder are deterministic; transforms are explanatory unless registered; unknown passes/options/contracts block execution; a full typed recipe is saved separately from existing function rule/tag/note records and reuses their identity/invalidation path; project-profile save remains disabled until Slice 5.

