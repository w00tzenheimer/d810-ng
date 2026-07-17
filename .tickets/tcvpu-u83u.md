---
id: tcvpu-u83u
status: closed
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

## Completion evidence (2026-07-16)

Implementation commit `350a9a51b` adds the thin dock over the manager facade,
pure in-memory sorting/filtering/action logic, asynchronous exact inventory,
current-function selection, deterministic newest/oldest and explicit sort
controls, allowlisted structured views, and anchored navigation. Qt imports
neither sqlite3 nor diagnostic storage models, and no arbitrary SQL surface is
exposed.

Live Docker/XQuartz acceptance discovered 304 real generated databases without
blocking the dock, selected the current function's newest database, rendered 17
snapshots and 54 block records, and jumped to anchored EA `0x180012C9F`.
Immutable browsing preserved the database, WAL, and SHM hashes and metadata;
non-empty WAL input fails closed. A live post-quarantine refresh excluded the
manager-owned quarantine tree (`0 shown / 304 discovered`). Evidence:
`.tmp/ida-gui/live-diagnostics-explorer.png`.

Verification: 248 broad focused tests and an 87-test final focused rerun passed;
the full suite passed with 6166 tests, 29 skipped, 9 known warnings, and 162
subtests. The 931-module cycle scan, ast-grep, all 13 import-linter contracts,
graph update, and `git diff --check` passed.
