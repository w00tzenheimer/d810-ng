---
id: tcvpu-oij1
status: open
deps: [tcvpu-u83u]
links: []
created: 2026-07-15T23:52:25Z
type: feature
priority: 1
assignee: w00tzenheimer
parent: d81-38ha
tags: [ui, diagnostics, sqlite, cleanup]
---
# Diagnostics D1: transactional SQLite cleaner

Plan and execute selected/bulk snapshot and database cleanup with active-session protection, schema-owned exact deletion, quarantine, WAL handling, integrity checks, and separate vacuum outcomes.

## Acceptance Criteria

Supports selected snapshots, delete all snapshots in one database, keep latest N, older-than, selected databases, all closed databases, and vacuum; active databases are skipped; unknown snapshot-owned tables fail closed; dependent rows delete by exact snapshot ID with parent last in one rollback-safe transaction; quarantine and vacuum outcomes are explicit; temporary SQLite fixture coverage passes.

