# MBA residual discovery persistence

This document is the tracked source of truth for the D810-owned MBA residual
discovery store. It describes schema version 1 and its causal lifecycle. The
database is portable SQLite state; it does not import IDA objects and it is not
an authority for host observation sinks, miner adapters, materialized files,
CoBRA, or Egglog.

## Authority and transaction contract

`event_id`, assigned by SQLite, is the causal authority. Timestamps are
metadata only and may be equal. Every public write owns one `BEGIN IMMEDIATE`
transaction: validate current authority, mutate normalized owner rows, append
the event last, validate the resulting projection, and commit. Any owner CAS,
event insert, foreign-key check, or projection validation failure rolls back
the complete transaction. Callers never provide `event_id`.

Every global lifecycle/status read, write, and reopen validates the complete
event domain. It rejects orphan group/attempt/run/proposal references even if
another SQLite connection inserted them with `foreign_keys=OFF`, and then
consumes every event exactly once through its owning group projection. The
schema-version, table-column, connection-pragma, journal-mode, and row-count
helpers are diagnostic metadata/count queries and are non-authoritative; they
do not establish causal validity.

## Schema version 1

The owner tables are `schema_migrations`, `inputs`, `databases`, `functions`,
`terms`, `raw_terms`, `provider_attempts`, `residual_groups`,
`mining_runs`, and `proposals`. Terms, raw terms, outcomes, proposals, and
proof receipts use deterministic UTF-8 JSON BLOBs. The existing normalized
proposal receipt columns remain redundant authority and are checked against
the event stream.

The causal table is declared after all owner tables:

```sql
CREATE TABLE residual_group_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id INTEGER NOT NULL REFERENCES residual_groups,
    event_kind TEXT NOT NULL CHECK (event_kind IN (
        'observed', 'claimed', 'run_no_proposal', 'run_failed',
        'run_expired', 'run_superseded', 'proposal_published',
        'materialized', 'admitted', 'rejected'
    )),
    group_revision INTEGER NOT NULL,
    source_proposal_state TEXT,
    provider_attempt_id INTEGER REFERENCES provider_attempts,
    run_id TEXT REFERENCES mining_runs,
    proposal_id TEXT REFERENCES proposals,
    occurred_at TEXT NOT NULL,
    CHECK (group_revision >= 1),
    CHECK (
        (event_kind = 'observed'
            AND provider_attempt_id IS NOT NULL
            AND run_id IS NULL AND proposal_id IS NULL
            AND source_proposal_state IS NULL)
        OR
        (event_kind IN (
                'claimed', 'run_no_proposal', 'run_failed',
                'run_expired', 'run_superseded'
            )
            AND provider_attempt_id IS NULL
            AND run_id IS NOT NULL AND proposal_id IS NULL
            AND source_proposal_state IS NULL)
        OR
        (event_kind = 'proposal_published'
            AND provider_attempt_id IS NULL
            AND run_id IS NOT NULL AND proposal_id IS NOT NULL
            AND source_proposal_state IS NULL)
        OR
        (event_kind = 'materialized'
            AND provider_attempt_id IS NULL
            AND run_id IS NOT NULL AND proposal_id IS NOT NULL
            AND source_proposal_state IS NOT NULL
            AND source_proposal_state = 'proposed')
        OR
        (event_kind = 'admitted'
            AND provider_attempt_id IS NULL
            AND run_id IS NOT NULL AND proposal_id IS NOT NULL
            AND source_proposal_state IS NOT NULL
            AND source_proposal_state = 'materialized')
        OR
        (event_kind = 'rejected'
            AND provider_attempt_id IS NULL
            AND run_id IS NOT NULL AND proposal_id IS NOT NULL
            AND source_proposal_state IS NOT NULL
            AND source_proposal_state IN ('proposed', 'materialized'))
    )
);

CREATE UNIQUE INDEX idx_residual_group_events_revision
    ON residual_group_events(group_id, group_revision)
    WHERE event_kind IN ('observed', 'claimed');
CREATE UNIQUE INDEX idx_residual_group_events_attempt_owner
    ON residual_group_events(provider_attempt_id)
    WHERE provider_attempt_id IS NOT NULL;
CREATE UNIQUE INDEX idx_residual_group_events_run_kind
    ON residual_group_events(run_id, event_kind)
    WHERE run_id IS NOT NULL;
CREATE UNIQUE INDEX idx_residual_group_events_proposal_kind
    ON residual_group_events(proposal_id, event_kind)
    WHERE proposal_id IS NOT NULL;
CREATE UNIQUE INDEX idx_residual_group_events_run_terminal
    ON residual_group_events(run_id)
    WHERE event_kind IN (
        'run_no_proposal', 'run_failed', 'run_expired',
        'run_superseded', 'proposal_published'
    );
CREATE UNIQUE INDEX idx_residual_group_events_proposal_terminal
    ON residual_group_events(proposal_id)
    WHERE event_kind IN ('admitted', 'rejected');
CREATE INDEX idx_residual_group_events_group_order
    ON residual_group_events(group_id, event_id);
```

The seven named indexes above are validated for uniqueness, column order,
BINARY collation, and exact partial predicate. The table validates all four
foreign keys and all three CHECK expressions, including explicit application
checks for NULL and forbidden owner columns. The store enables and verifies
`foreign_keys=ON`, `journal_mode=WAL` for file databases, and
`busy_timeout=5000`.

An existing database with a pre-amendment schema-1 shape fails closed before
normal use. The store never drops, overwrites, adopts, or auto-migrates it;
deletion/recreation is an explicit operator or fixture action.

## Event and lifecycle matrix

`observed` owns one provider attempt and creates group revision `r`. `claimed`
owns one run and creates the next revision. All other events use the unchanged
current revision at their event position. Each attempt has exactly one
`observed`; each run has exactly one `claimed`.

| Normalized owner | Required ordered events |
| --- | --- |
| active run | `claimed` only |
| no-proposal run | `claimed -> run_no_proposal` |
| failed run | `claimed -> run_failed` |
| expired run | `claimed -> run_expired` |
| superseded run | `claimed -> run_superseded` |
| proposed run/proposal | `claimed -> proposal_published` |
| proposed proposal | `proposal_published` |
| materialized proposal | `proposal_published -> materialized` |
| admitted proposal | `proposal_published -> materialized -> admitted` |
| rejected from proposed | `proposal_published -> rejected` |
| rejected from materialized | `proposal_published -> materialized -> rejected` |

Run and proposal events are bidirectional with normalized state. A rejected
event's `source_proposal_state` must exactly equal the normalized
`terminal_source_state` as well as `terminal_source_revision`. Rejection has no
normalized owner timestamp in schema 1; its `occurred_at` is canonical display
metadata, while `event_id` remains causal authority.

Lease reclaim must be ordered in one transaction:

```text
... -> claimed(r) -> run_expired(r) -> claimed(r+1)
```

The old run is expired and its event appended at the current revision before
the replacement claim increments the group revision. Publication creates the
proposal and updates run/group before appending `proposal_published`.

## Validation and corruption contract

Validation orders events by `event_id` and proves revision creation is exactly
`1..revision`, event/owner group identity is consistent, timestamps agree for
observations/claims/run terminals/publication/materialization/admission, and
every non-revision event points to the latest preceding revision event.
Evidence with a larger `event_id` cannot be transferred backward into a
receipt, including when timestamps are equal.

It rejects missing, duplicate, orphaned, cross-group, wrong-kind, wrong-owner,
non-contiguous, reordered, contradictory, and mutually exclusive run/proposal
events. It rejects normalized/event receipt mismatches and validates both sides
of every run/proposal transition. Corrupt reads and stale writes fail closed
without mutating neighboring rows.

Exact retries compare the normalized receipt and matching causal event. Exact
attempt duplicates, exact publication retries, exact materialization/admission/
rejection retries, and all refused requests append no event. A duplicate or
refused call therefore cannot advance group revision or alter the event stream.

## Public API boundary

The store exposes typed operations for recording attempts, claiming/heartbeat,
`finish_no_proposal`, proposal publication, materialization, admission,
rejection, status counts, and close. It intentionally does not add public
finish APIs for failed or superseded runs; those event kinds remain part of the
closed vocabulary and bidirectional validator. The store records already-
written materialization receipts and never writes source artifacts or mutates a
catalogue.
