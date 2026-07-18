# Guided Deobfuscation Workbench Attack Flow

**Ticket:** tcvpu-v3qt
**Status:** approved for implementation
**Date:** 2026-07-17

## Decision

The function-scoped Deobfuscation Workbench will make its normal path a
one-click attack:

`open current pseudocode -> run recommended attack -> refresh -> compare -> retain or investigate`

There is no confirmation dialog and no requirement to open Recipe Composer
before a first attempt. The existing manager-owned preconditions, identity
checks, and pass contracts remain the safety boundary. A blocked action does
not mutate the function and instead offers the relevant evidence.

This focused design extends the prior Workbench design in
`2026-07-15-deobfuscation-workbench-ui-design.md`. It changes how the existing
capabilities are presented and sequenced; it does not introduce a second
deobfuscation engine or a separate persistence mechanism.

## User journey

### 1. Ready to attack

When the current pseudocode function opens in the Workbench, its top card
shows:

- function name and EA;
- observed shape, selected profile, and confidence;
- effective runtime identity and pass count; and
- a single primary button: **Deobfuscate this function**.

For a recognized `ollvm_flat` function, the card says that D810 will run the
effective routed pipeline. For an unknown shape, it says that D810 will run the
effective project pipeline and retain the observed evidence. Both cases use the
same direct action; unknown is not silently presented as a vendor-specific
recommendation.

The control is disabled only when the snapshot is stale or D810 is not started.
Its disabled reason is visible in the usual tooltip. The previous standalone
Analyze action moves to advanced evidence controls: it remains available for
reconnaissance and diagnosis, but it is not a prerequisite for the normal run.

### 2. Run immediately

Clicking **Deobfuscate this function** invokes the existing Workbench
`deobfuscate` command. That command retains its current function EA,
fingerprint, and generation validation and executes the established
`DeobfuscateThisFunction` lifecycle. The Workbench does not directly edit
microcode or bypass the active runtime project.

While the lifecycle is running, the primary control is disabled and reports
`Running deobfuscation...`. A failure, stale result, or rejected result leaves
the evidence table visible and changes the card to a concise explanation plus
the appropriate next action.

### 3. Verify automatically

After an accepted deobfuscation result requests refresh, the panel refreshes
its snapshot and immediately captures a comparison using the existing
comparison adapter:

- native Hex-Rays pseudocode is freshly decompiled with D810 hooks suppressed;
- current D810 pseudocode is captured from the active function; and
- both artifacts are accepted only when their full comparison identity is
  current.

The Workbench then opens the existing read-only comparison dialog and changes
the top card to a compact result: `Pseudocode differs`, `Pseudocode matches`,
or `Comparison unavailable` with the exact freshness reason. A changed text
result is evidence of a changed rendering, not a correctness claim; the native
comparison remains the analyst's oracle.

If automatic comparison cannot be captured, the run remains recorded as
completed, but the card must not imply that the result was verified. It offers
**Retry comparison** and **Investigate diagnostics**.

### 4. Decide the next move

After a comparable result, the card exposes only the actions relevant to the
current outcome:

- **Investigate diagnostics** opens Diagnostics Explorer scoped to the current
  function and latest matching run.
- **Tune recipe** opens Recipe Composer seeded from the effective pipeline.
- **Adjust function rules** opens the established function rule override
  dialog.
- **Save recipe for this function** is available only through Recipe Composer
  after a current, valid recipe preflight.
- **Save as project profile** remains a Recipe Composer decision and is
  available only when config-v2 can be serialized losslessly.

The evidence chooser, filter, export, raw pipeline contracts, and explicit
comparison action remain available under Advanced controls. They support
inspection without competing with the primary workflow.

## UI structure

The Workbench remains one dockable PluginForm. Its vertical structure becomes:

1. **Function context**: existing function, runtime, and attack identity.
2. **Attack card**: current workflow state, one primary action, and contextual
   secondary actions.
3. **Evidence**: existing filterable structured table and detail pane.
4. **Advanced controls**: refresh, export, reconnaissance analysis, explicit
   comparison retry, recipe, function overrides, and diagnostics.

The card must use normal Qt widgets and existing portable status-icon helpers.
It must not depend on emoji, optional Unicode glyphs, or a custom font. It must
fit the PyQt5/IDA 9.1 and PyQt6/IDA 9.3 shims.

## State model and boundaries

Introduce a pure `workbench_workflow_logic.py` projection layer. It receives
the manager-owned Workbench snapshot plus, when available, the existing
comparison view and an explicit transient run state. It returns an immutable
view model containing:

- workflow phase;
- headline and explanatory detail;
- primary action state and disabled reason;
- contextual secondary actions; and
- whether the comparison should be offered, retried, or treated as current.

The model has these user-visible phases:

| Phase | Primary action | Meaning |
|-|-|-|
| ready | Deobfuscate this function | Current snapshot and started runtime permit a direct run. |
| unavailable | none | No current function, stale snapshot, or stopped engine prevents a run. |
| running | none | A direct run is in flight. |
| verify | View comparison | A run completed and a current comparison is available. |
| investigate | Investigate diagnostics | The run, gates, or comparison requires evidence review. |

The pure module does not call IDA, mutate state, open forms, or infer success
from a rule-firing count. `workbench_panel.py` only renders that model and
forwards actions to existing adapters. The manager and adapter seams continue
to own validation, lifecycle, capture, and persistence.

## Persistence semantics

Function rule overrides and function recipes remain intentionally distinct:

- **Adjust function rules** persists the existing enabled/disabled rule set,
  tags, and notes for the function.
- **Save recipe for this function** persists a validated ordered registered-pass
  recipe for that function; later normal deobfuscation runs activate it through
  the existing function-recipe runtime.

The direct recommended attack never creates either override implicitly. A
successful run is evidence for an explicit persistence decision, not a reason
to change future behavior silently.

## Error and freshness behavior

- A stale or mismatched command result is never rendered as the result for the
  currently selected function.
- A blocked pass contract, safety veto, or no-match result is an investigation
  state, not a generic `failed` state.
- Automatic comparison occurs only after the accepted run has refreshed the
  Workbench snapshot. It never compares the pre-run generation with a post-run
  cfunc.
- A comparison failure is localized to verification. It does not re-run the
  mutation lifecycle, alter persisted recipes, or discard run evidence.
- Diagnostics rows and graph records continue to identify microcode blocks with
  their EA anchor; serial-only identity is not introduced by this flow.

## Test plan

1. Unit-test the pure workflow projection for ready, stopped, stale, running,
   verified, comparison-unavailable, blocked, failed, abstained, and no-match
   inputs.
2. Unit-test panel orchestration: direct run uses the existing deobfuscate
   adapter, accepted refresh happens before automatic comparison, and an
   automatic comparison failure leaves a retryable investigation state.
3. Preserve adapter contract tests proving the existing command identity and
   lifecycle boundaries are used.
4. Run the focused UI and manager tests, project static architecture checks,
   and the full unit suite.
5. Reload D810 in the XQuartz-backed IDA 9.1 PyQt5 image, open the Workbench on
   a copied sample IDB, and visually verify the ready card, primary action, and
   post-run state. The IDB copy is disposable; no sample database is modified.

## Non-goals

- No Python pass authoring in IDA.
- No automatic persistence of recipes or rule overrides.
- No claim that a pseudocode diff proves semantic correctness.
- No replacement of the Diagnostics Explorer, comparison dialog, Recipe
  Composer, function override dialog, or their manager-owned actions.
- No graph-selection synchronization work; that remains the separately noted
  future exploration.
