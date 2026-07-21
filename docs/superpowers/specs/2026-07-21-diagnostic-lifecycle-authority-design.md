# Diagnostic Lifecycle Authority Design

## Objective

Make the SQLite diagnostic database the primary authority for explaining a
decompilation session across PREOPT, CALLS, and structural MBA mutation. The
database must record evidence-generation changes, current-MBA generations,
ownership and rebinding decisions, planned structural changes, committed
mutation receipts, aborts, and optional MBA snapshots in one ordered timeline.

Text logs remain a focused rendering aid. They are not the only record of
causality and must not be required to reconstruct lifecycle order.

## Constraints

- Diagnostic capture remains opt-in through `D810_DIAG_SNAPSHOT=1`.
- Lifecycle events exist independently of MBA snapshots. `snapshot_id` is an
  optional correlation, never an inferred parent.
- Evidence generations and MBA generations are separate typed fields.
- Every cross-maturity block reference stores a portable stable identity and
  an EA anchor. A block serial is allowed only with its session, MBA generation,
  maturity, and EA anchor.
- The manager-owned lifecycle remains the authority for session identity and
  native-preanalysis evidence. The mutation gateway remains the sole authority
  for structural mutation receipts.
- Producers emit portable values on observability boundaries. The SQLite sink
  does not import Hex-Rays, planner, or resolver implementations.
- Diagnostic failures must not mutate or abort a live MBA. Capture errors are
  reported as diagnostic failures and leave optimizer behavior unchanged.
- The schema change is a hard cut. There are no migrations, compatibility
  views, legacy table aliases, reader overlays, silent upgrades, or fallbacks.

## Approaches Considered

### Snapshot children

Attach new rows to the nearest snapshot and extend the existing
`modifications` table. This is rejected because mutation commits and evidence
rebinding frequently occur between snapshots. Choosing a nearest snapshot
would invent ordering and loses events when no capture follows.

### Generic JSON event journal

Store every event in one table with an opaque JSON payload. This is compact and
easy to extend, but it makes the primary debugging questions depend on JSON
parsing and string conventions. Generation joins, plan/receipt reconciliation,
and identity queries would not be schema-enforced.

### Typed event envelope with typed detail tables

Use one ordered lifecycle-event envelope plus normalized detail tables for
evidence, rebinding/ownership, plans, and receipts. Expose a unified timeline
view and a CLI query. This is the selected design because it preserves exact
ordering while keeping the important fields directly queryable and
constraint-checked.

## Schema Hard Cut

The current diagnostic schema becomes version 2.

`diagnostic_schema` contains exactly one row with the current integer version.
Writer creation builds only version 2. Readers verify the version before
binding models and raise `DiagnosticSchemaMismatch` for a missing or different
version. The error includes the expected version, observed version, and DB
path.

The following compatibility machinery is deleted:

- `_LEGACY_DAG_TABLE_RENAMES` and its in-place rename path;
- `_overlay_legacy_schema` and temporary reader overlays;
- `dag_*` compatibility views over `state_cfg_*` tables;
- tests whose contract is reading or upgrading an older diagnostic schema.

Existing diagnostic databases are disposable and unsupported. A new probe must
be run to obtain a version-2 database.

## Event Envelope

`diagnostic_sessions` records one manager-owned top-level session:

- `session_id` primary key;
- function EA in hexadecimal and signed-64 forms;
- top-level epoch;
- canonical `NativePreanalysisKey` JSON;
- start and finish timestamps;
- terminal status: `active`, `finished`, or `failed`.

`lifecycle_events` records the total order within a session:

- `event_id` global integer primary key;
- `session_id` foreign key;
- monotonically increasing `event_seq`, unique within the session;
- event timestamp;
- event kind;
- optional snapshot foreign key;
- provider, maturity, and phase;
- optional evidence generation;
- optional MBA generation before and after;
- optional correlation ID;
- short summary and canonical JSON payload.

The sink assigns `event_seq` synchronously when it persists an event. Producers
do not maintain diagnostic counters. A snapshot correlation is written only
when the producer supplies the exact `SnapshotRef`; the sink never attaches an
event to the latest or nearest snapshot.

## Typed Detail Tables

`evidence_generation_events` has one row per evidence publication, merge,
conflict, PREOPT bind, redo request, or consumption. It records the event ID,
operation, previous and resulting evidence generations, evidence family,
accepted/rejected outcome, owner, and reason.

`identity_decisions` has one row per ownership or rebinding attempt. It records
the event ID, decision kind, consumer, identity role, canonical native key,
exact-EA JSON, native-range JSON, primary EA anchor, optional current serial,
MBA generation, outcome (`bound`, `missing`, `ambiguous`, `rejected`, or
`owned`), candidate identities, and reason. A serial without an EA anchor is
rejected by the observation model before persistence.

`mutation_plan_items` has one row per planned structural operation. It records
the event ID, mutation batch ID, item index, mutation kind, source/target/old
target identity roles and EA anchors, generation-local serials, disposition
(`planned`, `filtered`, or `rejected`), and reason. The batch ID is minted by
the mutation gateway and is not derived from a list index or block serial.

`mutation_receipts` has one row per committed or aborted gateway batch. It
records the event ID, mutation batch ID, structural mutation kind, pre/post MBA
generations, planned operation count, applied operation count, outcome, and
description. A committed receipt requires `post_generation = pre_generation +
1`; an aborted receipt does not advance the generation.

`mutation_receipt_identities` preserves every affected
`StableBlockIdentity`, keyed by receipt event and identity index, with its
canonical native key, exact EAs, native ranges, and primary EA anchor.

The existing `modifications` snapshot table remains only as a reconstruction
view tied to a particular captured graph. It is not used as the mutation audit
authority and is renamed to `snapshot_modifications` in version 2 so its scope
cannot be confused with gateway plans or receipts.

## Producer and Sink Flow

1. `DecompilationEvent.SESSION_STARTED` creates `diagnostic_sessions` and the
   first lifecycle event.
2. `NativePreanalysisSessionState` operations publish portable evidence events
   through a narrow injected observer owned by the lifecycle coordinator.
   Evidence state never imports the SQLite implementation.
3. Current-MBA identity-index construction and every rebind/ownership result
   publish portable identity-decision events. The observation includes both
   evidence and MBA generations.
4. Before applying a structural batch, the gateway supplies a stable mutation
   batch ID. The deferred modifier publishes the final post-filter plan under
   that ID before the first live SDK mutation.
5. `MbaMutationGateway.commit()` emits the authoritative receipt with the same
   batch ID only after the identity index advances synchronously. `abort()`
   emits an aborted receipt and records why the batch did not commit.
6. The manager bridges manager-bus mutation events into portable core
   observability events. The SQLite handler persists the envelope and typed
   details in one transaction.
7. MBA snapshots continue independently. When an exact `SnapshotRef` is
   available, the corresponding lifecycle event stores it; otherwise the event
   remains fully queryable with `snapshot_id = NULL`.
8. `SESSION_FINISHED` records the terminal status before the diagnostic
   connection is checkpointed and closed. Failure cleanup uses the same path,
   so WAL-backed evidence is durable even when Hex-Rays aborts early.

## Primary Query Surface

The schema exposes `lifecycle_timeline`, a read-only SQL view over
`lifecycle_events` and the typed detail tables. Each row contains session,
sequence, timestamp, maturity/phase, evidence generation, MBA generation,
correlation ID, event kind, outcome, EA anchor, and summary.

The CLI adds:

```text
python -m d810.diagnostics timeline --db FILE [--session ID] [--func EA]
python -m d810.diagnostics mutation-batch --db FILE BATCH_ID
python -m d810.diagnostics evidence-lineage --db FILE [--session ID]
```

`timeline` is the first debugging command for a Rhad regression. It renders the
ordered lifecycle without requiring a snapshot selector. `mutation-batch`
shows the final plan, filters/rejections, receipt, affected identities, and
generation transition. `evidence-lineage` shows publish/merge/bind/consume
transitions and identity decisions across PREOPT and CALLS.

Focused textual logging may include the same event ID and correlation ID, so a
specific DB row can lead to detailed live context. Logs do not invent a second
ordering authority.

## Failure Semantics

- Missing session identity, invalid generation transitions, a serial without
  an EA anchor, duplicate session sequence numbers, and a committed receipt
  without a plan are rejected by the observation model and logged as
  diagnostic errors.
- An unpersisted diagnostic event increments a session diagnostic-error count
  and is emitted to the focused logger. It never changes optimizer decisions.
- Session close records `failed` when diagnostic events were rejected, even if
  decompilation itself succeeded. This makes an incomplete DB visibly
  non-authoritative.
- Readers fail closed on any schema version other than 2. They do not create,
  rename, overlay, or backfill objects.

## Verification

Unit tests must prove:

- version-2 creation and exact schema-model equivalence;
- rejection of version-1, unversioned, and future-version databases without
  changing their bytes;
- total event ordering and explicit-only snapshot correlation;
- evidence and MBA generations remain distinct;
- plan and receipt correlation by mutation batch ID;
- committed and aborted receipt constraints;
- stable identities round-trip losslessly and serial-only rows fail;
- diagnostic sink failure cannot affect a gateway commit or live MBA result;
- CLI timeline, mutation-batch, and evidence-lineage output.

Runtime tests must prove one gateway batch records its post-filter plan and
receipt with matching generations. The exact C8B0 Docker probe then runs with
diagnostic capture and focused logging, and the resulting database must show:

- six distinct stack-carrier ownership/rebinding decisions;
- planned structural operations;
- at least one committed mutation receipt;
- PREOPT/CALLS evidence-generation transitions;
- a fully ordered session with no diagnostic errors;
- the existing four-return semantic oracle still green.

The complete four-function Rhad matrix and the protected Hodur, Sub7ffd, and
Tigress Docker gate run after the diagnostic runtime proof. Architecture gates
remain mandatory:

```bash
sg scan --config sgconfig.yml --report-style short
PYTHONPATH=src lint-imports --config .importlinter
```

After source changes, `graphify update .` refreshes the repository graph.

## Commit Boundaries

Implementation uses independently reviewable commits:

1. hard-cut schema versioning and remove legacy compatibility;
2. add the typed event envelope and SQLite sink;
3. publish evidence and identity-decision events;
4. correlate mutation plans with gateway receipts and aborts;
5. add primary timeline CLI queries;
6. prove the C8B0 diagnostic contract and protected regressions.
