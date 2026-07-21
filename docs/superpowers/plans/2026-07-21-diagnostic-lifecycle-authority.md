# Diagnostic Lifecycle Authority Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the version-2 diagnostic SQLite database the ordered authority for lifecycle evidence, identity decisions, mutation plans, and mutation receipts.

**Architecture:** Core observability owns portable event envelopes and the SQLite sink; the manager bridges lifecycle and gateway events without the sink importing runtime layers. Event rows are session-native and optionally reference an exact snapshot. The schema is a hard cut: readers reject every non-v2 database and no compatibility views or migrations remain.

**Tech Stack:** Python 3.11, peewee-backed SQLite, the existing core observability bus, pytest, idalib Docker runtime tests.

## Global Constraints

- No backward compatibility, migration, overlay, alias, or fallback reader.
- Diagnostic failures never change optimizer or live-MBA behavior.
- Evidence and MBA generations remain distinct.
- No serial may be persisted without its maturity, MBA generation, and EA anchor.
- Production layers do not import `d810.core.diag`.
- Use `PYTHONPATH=src:tests pyenv exec python -m pytest` for local tests.
- Run ast-grep, import-linter, graphify, the four Rhad oracles, and the protected Docker gate before completion.

---

### Task 1: Hard-cut diagnostic schema version 2

**Files:**
- Modify: `src/d810/core/diag/models.py`
- Modify: `src/d810/core/diag/schema.py`
- Modify: `src/d810/core/diag/__init__.py`
- Create: `tests/unit/core/diag/test_schema_version.py`
- Delete: `tests/unit/core/diag/test_state_cfg_migration.py`
- Modify: `tests/unit/core/diag/test_open_diag_database.py`

**Interfaces:**
- Produces: `DIAGNOSTIC_SCHEMA_VERSION = 2`, `DiagnosticSchemaMismatch`, and `require_current_schema(db, path)`.
- Consumers: every diagnostic reader and writer.

- [ ] **Step 1: Write failing hard-cut tests**

  Add tests that create unversioned, version-1, and version-3 files, call
  `open_diag_database`, assert `DiagnosticSchemaMismatch`, and compare file
  bytes before/after. Assert a fresh writer contains version 2 and contains no
  `dag_*` views.

- [ ] **Step 2: Verify red**

  Run:
  `PYTHONPATH=src:tests pyenv exec python -m pytest -q tests/unit/core/diag/test_schema_version.py`

  Expected: import/behavior failures because the version API does not exist.

- [ ] **Step 3: Implement the hard cut**

  Add a singleton `DiagnosticSchemaVersion` model, insert version 2 during
  creation, validate it before reader binding, remove `_LEGACY_DAG_TABLE_RENAMES`,
  `_overlay_legacy_schema`, legacy rename DDL, and `dag_*` views. Rename the
  peewee `Modification` table to `snapshot_modifications`.

- [ ] **Step 4: Verify green and schema equivalence**

  Run:
  `PYTHONPATH=src:tests pyenv exec python -m pytest -q tests/unit/core/diag/test_schema_version.py tests/unit/core/diag/test_schema.py tests/unit/core/diag/test_models_schema_equivalence.py tests/unit/core/diag/test_open_diag_database.py`

- [ ] **Step 5: Commit**

  Commit message: `refactor(diag): hard-cut diagnostic schema v2`

### Task 2: Persist the typed lifecycle envelope

**Files:**
- Modify: `src/d810/core/diag/models.py`
- Modify: `src/d810/core/observability_events.py`
- Modify: `src/d810/core/diag/event_handlers.py`
- Create: `src/d810/core/diag/lifecycle.py`
- Create: `tests/unit/core/diag/test_lifecycle_events.py`

**Interfaces:**
- Produces: `DiagnosticSessionObserved`, `LifecycleEventObserved`, and
  `persist_lifecycle_event(conn, event) -> int`.
- Consumers: manager bridges and typed detail handlers.

- [ ] **Step 1: Write failing ordering tests**

  Emit two lifecycle events without snapshots and one with an explicit
  `SnapshotRef`. Assert per-session sequences `1,2,3`, only the explicit event
  has `snapshot_id`, and evidence/MBA generation fields are not coalesced.

- [ ] **Step 2: Verify red**

  Run:
  `PYTHONPATH=src:tests pyenv exec python -m pytest -q tests/unit/core/diag/test_lifecycle_events.py`

- [ ] **Step 3: Implement models and sink**

  Add `DiagnosticSession` and `LifecycleEvent` peewee models plus portable core
  observation dataclasses. Persist an envelope and allocate `event_seq` in one
  SQLite transaction. Resolve `SnapshotRef` only when it is supplied and
  already bound; never use latest-snapshot lookup.

- [ ] **Step 4: Verify green**

  Run the new test and all `tests/unit/core/diag` tests.

- [ ] **Step 5: Commit**

  Commit message: `feat(diag): persist lifecycle event timeline`

### Task 3: Persist evidence and identity decisions

**Files:**
- Modify: `src/d810/core/diag/models.py`
- Modify: `src/d810/core/observability_events.py`
- Modify: `src/d810/core/diag/event_handlers.py`
- Modify: `src/d810/analyses/control_flow/native_preanalysis_session.py`
- Modify: `src/d810/hexrays/ir/mba_identity_index.py`
- Modify: `src/d810/manager/decompilation_lifecycle.py`
- Modify: `src/d810/manager/manager.py`
- Create: `tests/unit/core/diag/test_lifecycle_evidence.py`
- Modify: `tests/unit/analyses/control_flow/test_native_preanalysis_session.py`
- Modify: `tests/unit/hexrays/ir/test_mba_identity_index.py`

**Interfaces:**
- Produces: `EvidenceGenerationObserved` and `IdentityDecisionObserved`.
- Consumes: lifecycle session ID, `NativePreanalysisKey`,
  `StableBlockIdentity`, evidence generation, and MBA generation.

- [ ] **Step 1: Write failing evidence/identity tests**

  Test publish, merge, PREOPT bind, bound/missing/ambiguous rebind, and
  ownership outcomes. Assert stable identities round-trip and an observation
  containing a serial but no EA anchor raises before emission.

- [ ] **Step 2: Verify red**

  Run the three focused test modules and confirm missing observation behavior.

- [ ] **Step 3: Add narrow observer ports**

  Add optional portable callbacks to `NativePreanalysisSessionState` and
  `MbaBlockIdentityIndex`. Call them after authoritative state transitions.
  The lifecycle coordinator supplies adapters that emit core observation
  dataclasses; the state/index never imports the diagnostic backend.

- [ ] **Step 4: Persist typed details**

  Add `EvidenceGenerationEvent` and `IdentityDecision` models and handlers.
  Store canonical native-key JSON, exact-EA JSON, native-range JSON, primary
  EA anchor, current serial, outcome, consumer/owner, and reason.

- [ ] **Step 5: Verify green and commit**

  Run the focused modules plus all core diagnostic tests. Commit as
  `feat(diag): record evidence and identity lineage`.

### Task 4: Correlate mutation plans, receipts, and aborts

**Files:**
- Modify: `src/d810/core/diag/models.py`
- Modify: `src/d810/core/observability_events.py`
- Modify: `src/d810/core/diag/event_handlers.py`
- Modify: `src/d810/hexrays/mutation/mba_mutation_events.py`
- Modify: `src/d810/hexrays/mutation/deferred_modifier.py`
- Modify: `src/d810/manager/manager.py`
- Modify: `tests/unit/hexrays/mutation/test_mba_mutation_events.py`
- Create: `tests/unit/core/diag/test_mutation_timeline.py`

**Interfaces:**
- Produces: gateway-owned `mutation_batch_id`, `MutationPlanObserved`, and
  `MutationReceiptObserved`.
- Consumes: post-filter deferred plan and authoritative gateway receipt.

- [ ] **Step 1: Write failing correlation tests**

  Assert a gateway mints a stable batch ID, a committed receipt uses the same
  ID and advances exactly one MBA generation, an abort records no generation
  advance, and a receipt without a persisted plan marks the diagnostic session
  failed without raising through the gateway.

- [ ] **Step 2: Verify red**

  Run the gateway and new diagnostic modules; confirm missing batch/event APIs.

- [ ] **Step 3: Extend the gateway authority**

  Add batch ID and planned-operation count to gateway transactions and
  receipts. Emit abort events from `abort(reason=...)`. Preserve the invariant
  that subscriber failures are swallowed after the identity index commits.

- [ ] **Step 4: Publish the final plan before mutation**

  In `DeferredGraphModifier.apply`, emit the post-filter, post-coalesce plan
  immediately before `_begin_mutation_batch()` and before the first SDK write.
  Serialize each source/target with its EA anchor and generation-local serial.

- [ ] **Step 5: Persist typed plan and receipt tables**

  Add `MutationPlanItem`, `MutationReceipt`, and
  `MutationReceiptIdentity` models and sink handlers. Enforce plan/receipt and
  generation constraints in the sink while leaving runtime mutation unchanged.

- [ ] **Step 6: Verify green and commit**

  Run focused gateway, deferred-modifier, and diagnostic tests. Commit as
  `feat(diag): correlate mutation plans and receipts`.

### Task 5: Make timeline queries the primary CLI

**Files:**
- Create: `src/d810/diagnostics/lifecycle_timeline.py`
- Modify: `src/d810/diagnostics/__main__.py`
- Modify: `src/d810/core/diag/schema.py`
- Create: `tests/unit/diagnostics/test_lifecycle_timeline.py`

**Interfaces:**
- Produces: SQL view `lifecycle_timeline` and CLI commands `timeline`,
  `mutation-batch`, and `evidence-lineage`.

- [ ] **Step 1: Write failing CLI tests**

  Build a v2 fixture and assert deterministic text for ordered events, a
  correlated plan/receipt batch, and PREOPT-to-CALLS evidence lineage.

- [ ] **Step 2: Verify red**

  Run the new diagnostics module and confirm the commands are absent.

- [ ] **Step 3: Implement view, queries, and renderers**

  Add a read-only union view with common outcome/anchor columns. CLI commands
  do not resolve a latest snapshot and accept session/function filters.

- [ ] **Step 4: Verify green and commit**

  Run the new tests plus all unit diagnostic CLI tests. Commit as
  `feat(diag): add lifecycle timeline queries`.

### Task 6: Runtime authority proof and protected regression gates

**Files:**
- Modify: `tests/system/e2e/test_rhad_transfer_function_semantic_coverage.py`
- Modify only if needed: focused production files identified by failing tests.

**Interfaces:**
- Consumes: version-2 DB and timeline CLI.
- Produces: executable C8B0 proof that the DB contains the complete lifecycle.

- [ ] **Step 1: Strengthen the C8B0 oracle**

  Enable `D810_DEFERRED_DIAG_PHASES=1` and query the captured DB for six
  distinct stack-carrier identity decisions, evidence transitions, planned
  operations, matching committed receipts, and zero diagnostic errors.

- [ ] **Step 2: Verify the exact C8B0 Docker oracle**

  Run the exact test and confirm four returns with a complete diagnostic
  timeline.

- [ ] **Step 3: Run architecture gates**

  Run:
  `sg scan --config sgconfig.yml --report-style short`
  and
  `PYTHONPATH=src lint-imports --config .importlinter`.

- [ ] **Step 4: Run semantic and protected Docker gates**

  Run all four Rhad acceptance oracles and the established Hodur, Sub7ffd, and
  Tigress protected Docker tests. Record exact totals.

- [ ] **Step 5: Refresh graph and commit**

  Run `graphify update .`, confirm the worktree contains only intended changes,
  and commit as `test(diag): prove lifecycle authority on Rhad`.
