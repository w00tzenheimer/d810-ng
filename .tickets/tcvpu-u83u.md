---
id: tcvpu-u83u
status: open
deps: [tcvpu-nyvc]
links: []
created: 2026-07-15T23:52:25Z
type: feature
priority: 1
assignee: w00tzenheimer
parent: d81-38ha
tags: [ui, diagnostics, sqlite]
---
# Diagnostics D0: read-only SQLite explorer

Discover generated diagnostic databases, sort newest-first deterministically, inventory snapshots, expose structured anchored views, and provide pure filtering/sorting/action logic behind a thin dock.

## Acceptance Criteria

Database and snapshot summaries are immutable and read through read-only connections; default/latest ordering uses timestamps plus deterministic ID/path tie breakers; filters and all requested sort keys are unit tested; structured views never expose arbitrary SQL and every block serial includes an EA anchor; Qt does not import sqlite3 or diagnostic models.

