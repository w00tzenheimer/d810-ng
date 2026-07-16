# Deobfuscation Workbench - Slice 3 Implementation Plan

> **For agentic workers:** Use `superpowers:executing-plans` and `superpowers:test-driven-development`.

**Goal:** Capture a one-shot native Hex-Rays baseline with D810 mutation hooks suppressed, retain the latest normal D810 pseudocode, and compare them only when their complete identities are current.

**Architecture:** Expanded immutable baseline/output records carry pseudocode, metrics, function fingerprint, IDB identity, type generation, Hex-Rays version, capture time, and generation; the D810 side additionally carries runtime identity and pass IDs. `WorkbenchComparisonService` is IDA-independent, stores immutable per-function artifacts, computes exact freshness reasons and metrics, and supplies them to `WorkbenchService.collect`. `WorkbenchComparisonAdapter` owns the one live boundary: temporary `d810_hooks_suppressed`, decompile, tag removal, and metadata extraction through injected providers. Pure UI logic projects Native/D810 tabs and freshness; the panel delegates Compare and renders the returned comparison.

## Constraints

- Native capture enters `d810_hooks_suppressed(manager)` exactly once and decompiles exactly once inside it. Persistent `manager.started` state is never changed.
- Text equality is not semantic correctness. Report line/character metrics and freshness only; do not label a changed text correct.
- Current identity requires function EA/fingerprint, IDB identity, type generation, and Hex-Rays version. D810 additionally requires runtime path/pass IDs/generation.
- Never reuse a baseline after identity drift. Return explicit stale reasons.
- Live acceptance uses only the Docker/XQuartz copied-IDB lane.

### Task 1: Expand immutable comparison records

**Files:** `src/d810/manager/workbench_models.py`, `tests/unit/manager/test_workbench_models.py`

- Extend `BaselineRef` and `D810OutputRef` with defaulted identity/text/metric fields so existing four-argument callers remain compatible.
- Add frozen `ComparisonMetric`, `WorkbenchComparisonSnapshot`, and `ArtifactFreshness` records.
- RED/GREEN and commit `feat(workbench): define comparison evidence records`.

### Task 2: Build the IDA-independent comparison service

**Files:** create `src/d810/manager/workbench_comparison.py`, create `tests/unit/manager/test_workbench_comparison.py`, update manager/state/service wiring.

- `capture_baseline(...)` and `capture_d810_output(...)` normalize text, compute SHA-256 and line/character metrics, and store immutable records by function EA.
- `compare(current_identity)` returns both sides, exact stale reasons, text-changed flag, and metric deltas.
- `WorkbenchService.collect` obtains current refs from the comparison service when explicit refs are absent.
- Test every identity dimension independently and deterministic capture timestamps via injection.
- Commit `feat(workbench): add identity-safe comparison service`.

### Task 3: Add pure comparison projection

**Files:** update `src/d810/ui/workbench_logic.py`, update `tests/unit/ui/test_workbench_logic.py`.

- Add `ComparisonView`, `comparison_view(snapshot)`, and Compare action enablement.
- Current artifacts show Native/D810 labeled text and metrics; stale/missing artifacts show reasons and cannot be labeled current.
- Commit `feat(ui): project native and D810 comparison`.

### Task 4: Add thin native capture adapter and panel wiring

**Files:** create `src/d810/ui/workbench_comparison.py`, create `tests/unit/ui/test_workbench_comparison.py`, update panel/Stats adapter contracts.

- Adapter captures metadata from injected callables, suppresses hooks around exactly one native decompile, then captures the current normal D810 `cfunc` without a second mutation lifecycle.
- Panel Compare dispatches through the adapter and displays two read-only tabs plus metrics/freshness.
- Verify with fakes/source tests only and commit `feat(ui): wire native comparison capture`.

### Task 5: Verify

- Run focused comparison/workbench/action tests, full unit suite, architecture gates, prohibited-import scan, and graph update.
- Record evidence on `tcvpu-guv6` and close only after live comparison acceptance.

## Automated evidence (2026-07-16)

- Immutable comparison records and the IDA-independent service cover normalized
  pseudocode, stable SHA-256 values, deterministic capture times, per-function
  storage, every required identity dimension, missing artifacts, and exact
  stale reasons.
- Manager and state facades own capture and comparison. Normal workbench
  collection reuses the stored references unless an explicit reference was
  supplied.
- Pure projection labels Native and D810 evidence, exposes freshness reasons,
  and reports only text/line/character deltas. It makes no correctness claim.
- The injected capture adapter enters `d810_hooks_suppressed(manager)` once,
  decompiles once inside it, renders the existing D810 `cfunc` without another
  mutation lifecycle, and never assigns persistent `manager.started` state.
- The Qt panel owns a modeless, read-only Native/D810 tab dialog and closes it
  during panel teardown. Fresh `late_init()` starts D810 exactly once after a
  successful state load, so Compare is enabled without a bootstrap reload.
- Focused final comparison/lifecycle/action tests: `50 passed`.
- Full unit suite: `6094 passed, 29 skipped, 9 known contract-vocabulary
  warnings, 162 subtests passed`.
- `sg scan --config sgconfig.yml --report-style short`: clean.
- `PYTHONPATH=src lint-imports --config .importlinter`: 13 contracts kept,
  0 broken.
- `git diff --check`: clean. `graphify update .` completed.
- Live Docker/XQuartz acceptance used the copied IDB recorded by
  `.tmp/ida-gui/automation-0aebed31038fd1918ca1110e9c4cf813.json`.
  Both artifacts carried the concrete function fingerprint, IDB/type/Hex-Rays
  identities, runtime/pass identity, and generation; the visible result is in
  `.tmp/ida-gui/live-comparison-slice3-final.png`.
