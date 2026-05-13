# Diagnostic Observability Boundary — Phase 0 Audit

Date: 2026-05-11

This document inventories every direct dependency on `d810.core.diag.*`
across `src/`, `tests/`, and `tools/`, classifies each call site, and
records the migration target for each.

The mandate (see `docs/plans/2026-05-11-diag-observability-boundary.md`):

```text
d810.core.diag           = SQLite/session/schema/snapshot sink only
d810.recon.observability = recon diagnostic capture facade
d810.cfg.observability   = CFG provenance / modification capture facade
d810.hexrays.observability = live Hex-Rays serialization / capture facade
d810.diagnostics         = post-hoc CLI/report/query layer
```

## Classes

- **A. runtime capture / write** — runtime code writes a diagnostic
  row, snapshot, or session event. Must route through a facade.
- **B. post-hoc query / report** — `d810.diagnostics` or a non-runtime
  consumer reads persisted data. May keep direct imports.
- **C. schema / test fixture** — tests call `create_tables`,
  `BlockSnapshot`, etc. to build synthetic DBs. May keep direct imports.
- **D. behavior bridge** — runtime code reads persisted diag rows to
  decide what to do next. Must be **documented explicitly** as a
  behavior bridge; the long-term plan is to lift the algorithm into
  `d810.recon.flow` (Phase 4).
- **E. stale / docs only** — historical references. Delete.

## Summary

```text
total direct imports of d810.core.diag*    123
  src/d810 runtime (class A)                51
  src/d810 behavior bridge (class D)         3
  src/d810/diagnostics (class B)             5
  src/d810/core/diag internal               (excluded from contract)
  tests/ (class C, mostly schema fixtures)  58
  tests/system/e2e capture (class A)         9
  tools/ (none after Track T)                0
```

## Migration Table

| file | import | class | target facade | migration |
|-|-|-|-|-|
| `src/d810/manager.py:540` | `get_diag_db` | A | `d810.recon.observability` (recon-facing snapshot kickoff) | Phase 2A |
| `src/d810/manager.py:629` | `get_diag_db`, `snapshot_rendered_program` | A | `d810.recon.observability.record_rendered_program` | Phase 2A |
| `src/d810/manager.py:697` | `get_diag_db` | A | `d810.recon.observability` (session-scoped session sentinel access) | Phase 2A |
| `src/d810/recon/runtime.py:349` | `get_diag_db`, `snapshot_fact_consumers` | A | `d810.recon.observability.record_fact_consumer` | Phase 2B |
| `src/d810/recon/runtime.py:412` | snapshot fact/observation/mapping/conflict writers | A | `d810.recon.observability.record_fact_*` | Phase 2B |
| `src/d810/recon/microcode_dump.py:1368` | `get_diag_db`, `mba_to_block_snapshots`, `snapshot_rendered_program`, `snapshot_mba` | A | `d810.recon.observability.record_rendered_program` + `d810.hexrays.observability.capture_mba_snapshot` | Phase 2B |
| `src/d810/recon/flow/selected_alternate_edge_override.py:77,81,85` | `alternate_correlation`, `alternate_selection`, `edge_diagnostics` | **D** | **Behavior bridge** — keep direct import but document. Phase 4 moves algorithm into `d810.recon.flow`. | Phase 4 |
| `src/d810/cfg/block_lineage.py:426` | `register_lineage_drainer` | A | `d810.cfg.observability` (inversion-of-control drainer registration) | Phase 2C |
| `src/d810/cfg/transform/byte_emit_tail_isolation_runtime.py:1919,1988,2311` | `get_diag_db` | A | `d810.cfg.observability` (corridor diagnostic capture) | Phase 2C |
| `src/d810/hexrays/hooks/hexrays_hooks.py:887,888,889` | `get_diag_db`, `mba_to_block_snapshots`, `snapshot_mba` | A | `d810.hexrays.observability.capture_mba_snapshot` | Phase 2D |
| `src/d810/hexrays/hooks/hexrays_hooks.py:935,936,937` | same | A | same | Phase 2D |
| `src/d810/hexrays/hooks/hexrays_hooks.py:1443,1595` | `open_diag_session`, `close_diag_session` | A | `d810.hexrays.observability` (session lifecycle) | Phase 2D |
| `src/d810/hexrays/mutation/deferred_modifier.py:2677,2678,2679` | `get_diag_db`, `snapshot_mba`, `mba_to_block_snapshots` | A | `d810.hexrays.observability.capture_mba_snapshot` | Phase 2D |
| `src/d810/hexrays/mutation/deferred_modifier.py:2743,2744` | `get_diag_db`, `snapshot_watch_transition` | A | `d810.cfg.observability.record_watch_block_transition` | Phase 2D |
| `src/d810/hexrays/mutation/cfg_mutations.py:191,322,401,526,1007,1365,1412` (7 sites) | `cfg_provenance.log_cfg_provenance` | A | `d810.cfg.observability.record_cfg_provenance` | Phase 2D |
| `src/d810/optimizers/microcode/flow/flattening/engine/executor.py:94` | `mba_to_block_snapshots` (module-top) | A | `d810.hexrays.observability` | Phase 2D |
| `src/d810/optimizers/microcode/flow/flattening/engine/executor.py:588,591` | `get_diag_db`, `snapshot_mba` | A | `d810.hexrays.observability.capture_mba_snapshot` | Phase 2D |
| `src/d810/optimizers/microcode/flow/flattening/engine/executor.py:729` | `cfg_provenance.log_cfg_provenance` | A | `d810.cfg.observability.record_cfg_provenance` | Phase 2D |
| `src/d810/optimizers/microcode/flow/flattening/hodur/_reconstruction_reporting.py:32,35,106,109` | `get_diag_db`, snapshot writers | A | `d810.recon.observability` (HCC reconstruction reporting) | Phase 2D |
| `src/d810/optimizers/microcode/flow/flattening/hodur/unflattener.py:808-810,1273-1275,1304-1306` | `get_diag_db`, `mba_to_block_snapshots`, `snapshot_mba`, `snapshot_reachability` | A | `d810.hexrays.observability` + `d810.cfg.observability` | Phase 2D |
| `src/d810/optimizers/microcode/flow/flattening/hodur/unflattener.py:1896,1931,2004,2272,2346` (5 sites) | `cfg_provenance.log_cfg_provenance` | A | `d810.cfg.observability.record_cfg_provenance` | Phase 2D |
| `src/d810/diagnostics/__main__.py:46,51,56,63,68` | `alternate_correlation`, `alternate_selection`, `bst_resolution`, `edge_diagnostics`, `formatting` | B | post-hoc reader — keep direct imports. Phase 4 moves the algorithm modules; the CLI then imports from `d810.recon.flow` and `d810.core.diag.formatting`. | Phase 4 |
| `src/d810/core/diag/__init__.py:18` | self-import (`schema.create_tables`) | internal | n/a | — |
| `src/d810/core/diag/snapshot.py:10,434,464` | self-imports (`formatting`, `cfg_provenance.drain_pending_provenance`, `__init__.drain_lineage_into_snapshot`) | internal | n/a | — |
| `src/d810/core/diag/mba_serializer.py:18` | self-import (`snapshot.BlockSnapshot`) | internal | n/a; Phase 5 moves serializer to `d810.hexrays` | Phase 5 |

### Tests (class C — schema / synthetic fixtures)

All test-side imports remain on `d810.core.diag.*` because tests
legitimately build synthetic DBs with `create_tables`, `BlockSnapshot`,
`InstructionSnapshot`, `_dual`, etc. The import-linter contract
introduced in Phase 3 will scope the forbidden contract to
`d810.optimizers`, `d810.recon`, `d810.cfg`, `d810.manager`, and
`d810.hexrays` source modules only.

Files in this class (no code changes expected):

```text
tests/unit/core/diag/*                       (8 files, schema + fixtures)
tests/unit/recon/test_runtime.py             (create_tables)
tests/unit/recon/flow/test_selected_alternate_edge_override.py
tests/unit/recon/facts/test_*.py             (7 files, BlockSnapshot/InstructionSnapshot)
tests/unit/diagnostics/test_*.py             (8 files, create_tables + _dual)
tests/unit/test_residual_dispatcher_worksheet.py
tests/system/runtime/test_manager_post_d810_validator.py
tests/system/e2e/test_hodur_baselines.py
tests/system/e2e/test_dump_function_pseudocode.py
```

Phase 4 module moves will update `tests/unit/core/diag/test_edge_diagnostics.py`,
`test_alternate_correlation.py`, `test_alternate_selection.py`, and
`test_bst_resolution.py` to import from `d810.recon.flow` instead.

## Behavior Bridges (class D)

The plan calls these out explicitly so they do NOT get disguised as
ordinary observability.

### `selected_alternate_edge_override` (recon.flow)

```text
src/d810/recon/flow/selected_alternate_edge_override.py
  imports: alternate_correlation, alternate_selection, edge_diagnostics
```

**Behavior bridge: reads selected alternate-edge diagnostics from DB.
Gated and intentional.**

This module runs at recon time and reads persisted diagnostic rows from
an earlier maturity to drive override decisions in the current maturity.
It is the only runtime read of diag DB state for behavior, not for
diagnostics.

Long-term target (Phase 4): lift the three algorithm modules
(`edge_diagnostics`, `alternate_correlation`, `alternate_selection`,
`bst_resolution`) into `d810.recon.flow.*`. After that, both runtime
and CLI consume the algorithm from `d810.recon.flow`, and the DB I/O
is mediated through `d810.recon.observability` (capture) and
`d810.diagnostics` (post-hoc report).

This phase (0) does NOT touch the behavior bridge. Phase 1 facades do
NOT cover it. Phase 4 supersedes it module-by-module.

## Phase Plan (recap)

```text
Phase 1   Add empty facades (no call-site changes)
Phase 2A  Manager  -> facades
Phase 2B  Recon    -> facades, document behavior bridge
Phase 2C  CFG      -> facades
Phase 2D  Optimizers / HCC -> facades
Phase 3   Import-linter contract forbids runtime → core.diag direct imports
Phase 4   Move semantic algorithms into d810.recon.flow (per commit)
Phase 5   Move mba_serializer into d810.hexrays
Phase 6   Split CFG provenance API from DB sink
```

Allowed remaining `d810.core.diag.*` consumers after Phase 6:

```text
src/d810/core/diag/**            self-imports + internal helpers
src/d810/diagnostics/**          post-hoc CLI/query
src/d810/recon/observability.py  capture facade implementation
src/d810/cfg/observability.py    capture facade implementation
src/d810/hexrays/observability.py capture facade implementation
src/d810/recon/flow/selected_alternate_edge_override.py
                                  documented behavior bridge (or migrated by Phase 4)
tests/**                          schema / synthetic fixtures
```

## Non-Goals

- No HCC behavior changes.
- No `sub_7FFD` byte-cascade output changes.
- No schema / output-shape changes unless strictly required and tested.
- No deletion of `d810.core.diag`.
- No mass test relocation.

---

# Event-Refactor Audit (Phase 0, 2026-05-11 follow-on)

The facade re-export pattern from Phases 1-6 keeps runtime call sites
on stable names but does not actually decouple the dependency graph:
every facade module ends up importing `d810.core.diag.*` for its
re-exports, so the `runtime-no-core-diag` import-linter contract has
to ignore the facade modules to pass. The exception list outnumbers
the enforcement.

This follow-on plan replaces the facade pattern with a real event /
observation architecture:

- Runtime publishes domain observation events; no `d810.core.diag`
  imports anywhere in `d810.{manager,optimizers,recon,cfg,hexrays}`.
- `d810.core.diag.event_handlers` installs SQLite subscribers that
  consume the events and write rows.
- Snapshot ids are mapped from a runtime `SnapshotRef` value by the
  subscriber, so runtime never holds a SQLite `snapshot_id`.

## Current Direct Imports (2026-05-11 follow-on)

```
$ rg "from d810\.core\.diag|import d810\.core\.diag" src/d810
src/d810/cfg/observability.py:from d810.core.diag import (...)
src/d810/cfg/observability.py:from d810.core.diag.snapshot import (...)
src/d810/cfg/provenance.py:    from d810.core.diag import register_provenance_drainer
src/d810/core/diag/__init__.py:from d810.core.diag.schema import create_tables
src/d810/core/diag/snapshot.py:    from d810.core.diag import drain_lineage_into_snapshot
src/d810/core/diag/snapshot.py:    from d810.core.diag import drain_pending_provenance
src/d810/core/diag/snapshot.py:from d810.core.diag.formatting import format_block_id
src/d810/diagnostics/__main__.py:from d810.core.diag.formatting import format_block_id
src/d810/hexrays/mba_serializer.py:from d810.core.diag.snapshot import (...)
src/d810/hexrays/observability.py:from d810.core.diag import (...)
src/d810/hexrays/observability.py:from d810.core.diag.snapshot import (...)
src/d810/recon/observability.py:from d810.core.diag import (...)
src/d810/recon/observability.py:from d810.core.diag.snapshot import (...)
```

## Event-Refactor Migration Table

| file | current import | new event/API target | status |
|-|-|-|-|
| `src/d810/cfg/observability.py` | re-exports from `core.diag` + `core.diag.snapshot` + `core.diag.cfg_provenance` (now `cfg.provenance`) | becomes a thin event-emit shim defined wholly in cfg domain; events go to bus | Phase 2 |
| `src/d810/cfg/provenance.py` | `register_provenance_drainer` at module load | emits `CfgProvenanceObserved` events on the bus instead of buffering for drain | Phase 5D |
| `src/d810/core/diag/__init__.py` | self-import (`schema.create_tables`) | unchanged | internal |
| `src/d810/core/diag/snapshot.py` | self-imports (`formatting`, IoC drains) | unchanged | internal |
| `src/d810/diagnostics/__main__.py` | `core.diag.formatting.format_block_id` | unchanged (post-hoc CLI) | allowed |
| `src/d810/hexrays/mba_serializer.py` | `BlockSnapshot`, `InstructionSnapshot` from `core.diag.snapshot` | dataclasses move to `d810.core.observability_models`; serializer imports from there | Phase 7 |
| `src/d810/hexrays/observability.py` | re-exports `capture_mba_snapshot`, `mba_to_block_snapshots`, session helpers | becomes event-emit module; `capture_mba_snapshot` returns `SnapshotRef`; event payloads carry neutral models | Phase 2 |
| `src/d810/recon/observability.py` | re-exports `record_*` from `core.diag.snapshot` plus dataclasses | becomes event-emit module; event payloads carry neutral models | Phase 2 |

## Target Architecture

```text
d810.core.observability         (NEW)
    SnapshotRef dataclass
    DiagnosticEventBus (subscribe / emit / reset)
    no d810.core.diag imports

d810.core.observability_models  (NEW, Phase 7)
    BlockSnapshot, InstructionSnapshot, DagNode, DagEdge,
    Modification, ProvenanceEntry, ...
    no d810.core.diag imports

d810.recon.observability        (REWRITTEN)
    DagObserved, FactObservationsObserved, RenderedProgramObserved, ...
    emit helpers
    no d810.core.diag imports

d810.cfg.observability          (REWRITTEN)
    CfgProvenanceObserved, WatchBlockTransitionObserved,
    BlockLineageObserved, ...
    emit helpers
    no d810.core.diag imports

d810.hexrays.observability      (REWRITTEN)
    capture_mba_snapshot(...) -> SnapshotRef | None
    no d810.core.diag imports
    delegates serialization to d810.hexrays.mba_serializer (own layer)

d810.core.diag.event_handlers   (NEW)
    install_diag_event_handlers() / uninstall_diag_event_handlers()
    SnapshotRef.key -> snapshots.id mapping
    handlers persist events through existing snapshot_* functions
    allowed to import core.diag + domain event types
    handler exceptions caught/logged, never propagated

manager / hexrays.hooks         (UPDATED in Phase 4)
    install_diag_event_handlers() on diag session open
    uninstall on close (idempotent)

d810.diagnostics                (UNCHANGED)
    post-hoc CLI / query / report
```

## Phase Plan (follow-on)

```text
Phase 0   Audit + this doc update
Phase 1   d810.core.observability (event bus + SnapshotRef)
Phase 2   recon/cfg/hexrays observability rewritten as event emitters
Phase 3   d810.core.diag.event_handlers (SQLite subscribers)
Phase 4   manager / hexrays hooks bootstrap subscribers
Phase 5   migrate call sites from facade re-exports to event APIs
            5A manager
            5B recon
            5C hexrays
            5D cfg / provenance
            5E optimizers / HCC
Phase 6   tighten import-linter: drop facade ignore_imports
Phase 7   move neutral dataclasses to d810.core.observability_models
```

## Hard Constraints (follow-on)

- No HCC behavior changes.
- No byte-cascade behavior changes.
- No diagnostic schema change unless unavoidable and tested.
- No parser/report logic in runtime packages.
- Runtime packages must not import `d810.core.diag`.
- Observability modules must not import `d810.core.diag`.
- Diagnostic subscriber failures must be logged/swallowed and must
  never change optimizer behavior.

## Phase 5 Migration Status (2026-05-11)

### Migrated (fire-and-forget events, no SnapshotRef threading)

- `src/d810/hexrays/mutation/cfg_mutations.py` (7 sites):
  `record_cfg_provenance(...)` -> `observe_cfg_provenance(...)`
- `src/d810/optimizers/microcode/flow/flattening/hodur/unflattener.py`
  (5 sites): `record_cfg_provenance as log_cfg_provenance` import
  retargeted to `observe_cfg_provenance as log_cfg_provenance`.
- `src/d810/optimizers/microcode/flow/flattening/engine/executor.py`
  (1 site): same import retarget.
- `src/d810/hexrays/mutation/deferred_modifier.py` (1 site):
  `record_watch_block_transition(diag_db, ...)` ->
  `observe_watch_block_transition(...)`. The `diag_db` positional was
  dropped; subscriber acquires the connection itself.

### Pending (SnapshotRef-threading sites)

The following call sites currently use the legacy
`record_*(conn, snap_id, ...)` pattern. Migrating them to events
requires a deeper redesign because the call site needs to thread a
:class:`SnapshotRef` from the originating
:func:`request_capture_mba_snapshot` through several intermediaries:

- `src/d810/manager.py` (3 sites):
  - `_post_d810_capture_handler` forwards a raw diag conn to
    `recon_runtime.capture_maturity_facts`. Migration requires
    `capture_maturity_facts` to drop the `diag_conn` parameter and
    emit `FactObservationsObserved` / `FactMappingsObserved` /
    `FactConflictsObserved` against a `SnapshotRef` -- which means
    the manager (or hexrays_hooks) must publish the ref on a path
    that recon can pick up.
  - `attach_post_d810_rendered_program` looks up an EXISTING
    snapshot_id via `SELECT MAX(id) FROM snapshots WHERE ...`. The
    event API has no equivalent "find me a prior SnapshotRef by
    func_ea+maturity+phase" lookup; we'd need a "snapshot remember"
    side-channel.
  - `validate_post_d810_handoff` is a pure read (calls
    `detect_post_d810_handoff_violations(diag_db, ...)`) -- a
    behavior-bridge classification, NOT a capture write.
- `src/d810/recon/runtime.py` (3 sites in `record_fact_consumers` and
  `_persist_maturity_facts`): same pattern as manager site 1.
- `src/d810/recon/microcode_dump.py`
  (`snapshot_linearized_program`): creates a new snap by calling
  `record_mba_snapshot` directly, then attaches a rendered program.
  Pure event flow would use
  `request_capture_mba_snapshot` + `observe_rendered_program`.
- `src/d810/hexrays/hooks/hexrays_hooks.py` (pre/post-D810 maturity
  snapshots): captures via `capture_mba_snapshot` (legacy). Migration
  to `request_capture_mba_snapshot` requires the manager-side
  consumers (`attach_post_d810_rendered_program`,
  `_post_d810_capture_handler`) to switch first, otherwise the
  returned `SnapshotRef` is lost.
- `src/d810/hexrays/mutation/deferred_modifier.py`
  (deferred-apply phase snapshot): captures via
  `capture_mba_snapshot`; no follow-on observe -- could migrate.
- `src/d810/optimizers/microcode/flow/flattening/engine/executor.py`
  (post-fragment snapshot): same as deferred_modifier.
- `src/d810/optimizers/microcode/flow/flattening/hodur/unflattener.py`
  (post-gut-and-wire, post-pipeline, intermediate snapshots): same
  pattern; some are followed by `observe_reachability`-style writes
  that DO need the `SnapshotRef`.
- `src/d810/optimizers/microcode/flow/flattening/hodur/_reconstruction_reporting.py`
  (DAG/modifications/local-facts persistence): full
  capture+observe flow.

### Behavior bridge

- `src/d810/recon/flow/selected_alternate_edge_override.py` reads
  alternate-edge diagnostics from the diag DB to drive
  override decisions. NOT a capture write; will not migrate.

### CFG runtime reads

- `src/d810/cfg/transform/byte_emit_tail_isolation_runtime.py`
  (`tail_distinct`, `tail_duplicate_convergence`,
  `tail_state_cascade`): env-gated dev/debug CFG transforms that
  READ persisted fact data from the diag DB to drive mutations.
  Behavior-bridge classification; not part of the capture event
  flow.
