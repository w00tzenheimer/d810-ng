---
id: tcvpu-v3qt
status: closed
deps: []
links: [d81-38ha]
created: 2026-07-17T00:00:00Z
type: feature
priority: 1
assignee: w00tzenheimer
---
# Guide the Workbench through a one-click deobfuscation attack

Superseded for new UI work by
`docs/superpowers/plans/2026-07-23-algorithm-driven-deobfuscation-workbench.md`.
The direct-run identity, freshness, and comparison safeguards remain active.

Replace the flat peer-action bar with an evidence-first, function-scoped
workflow: immediately run the recommended attack, automatically compare the
fresh output with a native oracle, and reveal diagnostics, recipe tuning, rule
overrides, and persistence as contextual next steps. Preserve the existing
manager actions and keep workflow projection independently unit-testable.
