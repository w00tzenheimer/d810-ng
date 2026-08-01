---
id: tcvpu-oij1
status: closed
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

## Completion evidence (2026-07-16)

Implementation commit `350a9a51b` wires every approved cleaner scope into the
thin diagnostics dock while retaining the headless planner/executor boundary:
selected and all snapshots, keep latest N, older-than, selected databases, all
closed databases, delete all, and vacuum. Exact plans show paths, snapshot IDs,
counts, and owned-row estimates. Review acknowledgement is always required;
bulk deletion requires `DELETE ALL`, and reversible database quarantine requires
`QUARANTINE`.

Live Docker/XQuartz acceptance used only a copied real generated database. The
selected snapshot-17 plan named 187 rows; its transaction and integrity check
passed, WAL checkpoint succeeded, and refresh showed 16 snapshots with ID 16
newest. The non-executed all-snapshots plan named all 16 IDs and 12,968 rows and
proved the typed-confirmation gate. Selected-database quarantine moved the
disposable database and sidecars, displayed exact restore instructions, and
reported logical deletion, integrity, sidecars/quarantine, WAL, and vacuum
separately. The source database retained SHA-256
`0d6b700fbdb80b97a6dd1812045b737b21c84a24826a42b8e45059b32e242ec5`, and
the exact disposable quarantine artifact was removed afterward. Evidence:
`.tmp/ida-gui/live-diagnostics-cleaner-plan.png`,
`.tmp/ida-gui/live-diagnostics-cleaner-result.png`, and
`.tmp/ida-gui/live-diagnostics-cleaner-quarantine.png`.

Verification: 248 broad focused tests and an 87-test final focused rerun passed;
the full suite passed with 6166 tests, 29 skipped, 9 known warnings, and 162
subtests. Active-path/identity rechecks, fail-closed unknown-table handling,
rollback, sidecar quarantine, and vacuum outcomes have temporary-SQLite fixture
coverage. The 931-module cycle scan, ast-grep, all 13 import-linter contracts,
graph update, and `git diff --check` passed.
