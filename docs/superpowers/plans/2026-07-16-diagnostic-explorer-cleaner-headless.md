# Diagnostic Explorer and Cleaner - D0/D1 Headless Implementation Plan

> **For agentic workers:** Use `superpowers:executing-plans` and
> `superpowers:test-driven-development`.

**Goal:** Inventory, inspect, sort, filter, plan, and safely clean D810 diagnostic
SQLite databases without putting SQL, schema ownership, or destructive policy
inside Qt.

**Architecture:** `d810.core.diag` publishes the authoritative snapshot-owned
table registry derived from its peewee schema. IDA-independent manager services
open databases through SQLite read-only URI connections for inventory and
allowlisted structured views. Cleanup validates the live schema against the
registry, builds immutable plans, protects active paths, deletes exact snapshot
IDs in one transaction with `snapshots` last, and reports logical deletion,
WAL, quarantine, integrity, and vacuum outcomes separately. Pure UI logic owns
sorting, filtering, selection summaries, confirmation language, and button
enablement. Qt remains deferred.

## Constraints

- Default database and snapshot order is newest recorded timestamp first with
  deterministic path/ID tie breakers; filename order is never the latest oracle.
- Read-only inventory never runs schema creation, migration, or arbitrary SQL.
- Every displayed block serial is paired with an EA anchor. If no anchor exists,
  the serial value is omitted and the record explains that the anchor is missing.
- Cleanup fails closed when any unknown base table has a `snapshot_id` column.
- Dependent snapshot rows delete by exact snapshot IDs; `snapshots` deletes last.
- Active databases are skipped and reported for every destructive scope.
- Snapshot cleanup, WAL checkpoint, and vacuum are separate outcomes. A vacuum
  failure never relabels committed logical deletion as failed.
- Database deletion moves the database and sidecars to reversible quarantine.
- Qt code never imports `sqlite3`, diagnostic models, or cleanup implementation.

### Task 1: Publish schema ownership and immutable records

Derive current and supported-legacy snapshot-owned table names from `MODELS`.
Add immutable database, snapshot, record, cleanup target/plan/result, and
operation outcome records.

### Task 2: Build read-only inventory and structured inspection

Discover `*.diag.sqlite3`, query supported schema through read-only URI
connections, compute database/snapshot counts and recorded timestamps, and
return allowlisted structured records for blocks, instructions, recovered CFG,
modifications, facts/conflicts, provenance, and rendered programs. Add stable
anchor sanitization.

### Task 3: Add pure explorer logic

Implement every requested database/snapshot sort key, newest-first defaults,
case-insensitive filtering, current-function/latest selection, structured view
projection, and action enablement without IDA/Qt/SQLite imports.

### Task 4: Build cleanup plans

Support selected snapshots, all snapshots in one database, keep latest N,
older-than, selected databases, all closed databases, and vacuum. Plans include
exact IDs, row counts, active exclusions, and unambiguous confirmation text.

### Task 5: Execute rollback-safe cleanup

Validate table ownership, begin an immediate transaction, delete dependent rows
then parents, run orphan/foreign-key/integrity checks, and commit or roll back as
one unit. Checkpoint WAL after commit; vacuum separately. Quarantine database
files and `-wal`/`-shm` sidecars rather than unlinking them.

### Task 6: Add manager/state facades and verify

Manager owns inventory and cleanup services with an injected active-path
provider. State exposes immutable operations only. Run temporary-database
fixtures across every owned table, focused UI/action tests, the full unit suite,
architecture gates, `git diff --check`, and `graphify update .`. Keep Qt/live
acceptance open.

## Implementation evidence (2026-07-15)

The headless D0/D1 services are implemented. Inventory discovers diagnostic
databases read-only, orders databases and snapshots by recorded timestamps,
projects allowlisted anchored records, and exposes pure filter/sort/group/jump
logic. Cleanup supports selected/all snapshots, keep-latest, older-than,
selected/all closed databases, and vacuum with active-path protection,
schema-drift checks, exact-ID transactional deletion, integrity validation,
separate WAL/vacuum outcomes, and reversible sidecar-aware quarantine.

Fresh branch-wide verification completed with `5891 passed, 29 skipped, 9
warnings, 162 subtests passed`. `sg scan`, `lint-imports`, and `git diff --check`
were clean.

Open boundary: the thin Qt dock and live IDA navigation/confirmation acceptance
remain deferred. D0 and D1 stay open until that adapter work is performed.
