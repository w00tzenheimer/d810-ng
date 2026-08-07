# Config-v2 Operator Pipeline Editor

Status: approved 2026-08-07

## Problem

The current config-v2 editor is a lossless serializer workbench presented as
the ordinary configuration interaction. It exposes implementation terms and
read-only JSON before it explains the decision a user is making.

This leads to several false affordances:

- `Stage` is a pass-owned execution descriptor, not independently selectable
  configuration. Showing it as a tree child makes it look enabled or disabled.
- `owned` transforms are registry availability, not project selection. For
  example, a pipeline can display every MBA transform while its
  `options.transforms` list is empty.
- protection-family routing is editable only as raw JSON, so users cannot tell
  how a family is activated, preferred, required, or excluded.
- `Unsupported fields`, the serializer manifest, and the complete document are
  implementation safeguards, but dominate the default page.
- `draft` and `reset` do not explain that edits are an unsaved local copy and
  that reset discards those changes.

The earlier density redesign remains valid for the D-810 Configuration dock.
This design changes the interaction reached from an active config-v2 pass: it
replaces the default serializer workbench with a pass-focused operator flow.

## Goals

1. Make selected passes, selected transforms, pass options, and routing choices
   understandable without reading JSON.
2. Keep strict config-v2 validation, manager-owned policy, atomic save/reload,
   and lossless preservation intact.
3. Use progressive disclosure: routine work is compact; raw document work is
   explicit and clearly marked advanced.
4. Reuse the Workbench structured-details/raw-tree interaction instead of
   another permanent `QPlainTextEdit` JSON surface.
5. Keep Qt presentation thin and put projections, selections, and action
   availability in IDA-free logic.

## Terminology shown to users

| Product term | Meaning | Directly editable? |
|---|---|---|
| Pass | One ordered operation in the project pipeline. | Yes |
| Transform | An optional, pass-owned technique. It is enabled only when selected for that pass. | Yes, when the pass exposes transforms |
| Runs during | The pass's declared workflow/execution stage. It explains scheduling; it is not a switch. | No |
| Protection family | A compatible recovery strategy considered by routing. | Yes, through routing policy |
| Unsaved changes | The current local config-v2 draft differs from its saved source. | N/A |
| Preserved fields | Configuration fields the structured editor leaves unchanged. | Via explicit raw edit only |

The UI never displays `owned` as a standalone state. A transform is either
`selected`, `available`, or unavailable for the selected pass.

## Information architecture

### D-810 Configuration: Pipeline Overview

The existing configuration dock remains the starting point. Its pipeline tree
shows active passes by default. Each active pass row has:

```
<ordinal>. <display name>              <selected transform / option summary>
         <one-line purpose>            <state>
```

Examples:

```
2. MBA simplify                 0 transforms selected
   Front-end normalization       active

5. Recover state transitions    min state constant: 0x1000000
   Recover dispatcher transitions active
```

The default list does not expand into stages or every registered transform.
`Add pass` remains a deliberate searchable catalog action. It lists only public
registered passes and labels them `Available`, rather than making the default
pipeline list a catalog.

Double-clicking an active config-v2 pass opens the Pass Inspector. A new
explicit `Edit pipeline` action opens the project-wide Pipeline Builder.

### Pass Inspector

The inspector is a focused dock or detachable panel for one pass in one draft.
It contains, from top to bottom:

1. Identity: display name, stable pass ID in subdued text, and ordered pipeline
   position.
2. Purpose: a concise catalog-derived description.
3. `Runs during`: a read-only workflow stage label with a tooltip explaining
   that it is scheduling metadata, not a separately enabled item.
4. Transforms: a searchable grouped checklist when the selected pass declares
   transform IDs. Checked rows are serialized in `options.transforms`; unchecked
   rows are available but inactive. No transform-capable pass shows `No
   selectable transforms` rather than an empty JSON object.
5. Pass settings: typed controls when a registered schema exists. Otherwise an
   explicitly labelled `Advanced pass options` control opens JSON for the
   selected pass only.
6. Contract summary: compact chips for required inputs, outputs, backend route,
   and safety policy. Detailed contract data remains available through `View raw
   contract` and does not consume the default layout.

Changing the checked transform set preserves `transform_options`, orders the
selection by the registered transform catalog, and uses the existing typed
pass-options mutation/validation path. It never activates transforms owned by a
different pass.

### Pipeline Builder

`Edit pipeline` opens the explicit project-level editor. It is not the target of
a normal pass double-click. Its primary region is a compact numbered sequence
of active passes, with:

- searchable `Add pass` picker;
- remove and move controls acting on the selected pipeline row;
- a small selected-pass summary and `Open inspector` action;
- project description in a one-line preview with `Edit description`, instead of
  a permanent multiline text area.

The builder has a separate collapsible `Protection-family routing` section:

- **Automatic**: no requirement, preferences, or exclusions; compatible
  evidence selects a family.
- **Require**: choose exactly one registered family.
- **Prefer**: choose compatible families and optional numeric preference
  weights; default selected weight is `1.0`.
- **Exclude**: choose families to forbid.

The controls enforce existing invariants before calling the manager: a required
family cannot be excluded, and a required family is the only allowed preferred
family. Existing routing validation remains authoritative.

## Structured details and raw JSON

The editor uses the same pattern as the Deobfuscation Workbench:

1. Structured cards/property rows are the default view.
2. `View raw configuration` opens an on-demand JSON tree with path, type, and
   provenance badges. It does not reserve default screen space.
3. The default raw tree is read-only. `Edit raw` is a distinct opt-in state with
   a clear warning that it can alter preserved fields.
4. `Preserved fields` is a filtered tree view showing fields without structured
   controls. Its explanation is: `D810 preserves these values unchanged unless
   you explicitly edit raw configuration.`
5. Saving raw edits parses JSON, reuses complete-document validation, and
   requires the same successful config-v2 validation as every other save.

The current serializer manifest is removed from the normal UI. It may be
available only from the raw tree's `About structured editing` disclosure for
developers diagnosing field support.

To avoid parallel tree implementations, extract or reuse the Workbench JSON
tree as a configuration-neutral UI component. Its view-model/projection logic
must remain Qt-free.

## Compact persistence strip

The editor has one thin bottom strip, not a multi-row footer:

```
<unsaved/clean indicator>  <validation state>   [ ... ]  [Save and reload]
```

The overflow menu contains, in order:

1. `Discard unsaved changes`
2. `Validate pipeline`
3. `Save as new config...`
4. `View raw configuration`

The current destination is visible in the header and tooltip, not repeated in
the footer. `Save and reload` is disabled until the exact current draft has a
successful validation result. Validation failures appear in a compact actionable
list beside the affected pass or routing control; they are never shown as an
anonymous large text box.

`Discard unsaved changes` reloads the saved complete runtime source and any
originating recipe seed. It replaces the ambiguous `Reset draft` label.

## State ownership and data flow

```
Configuration dock -> Config-v2 draft adapter -> manager editing service
       |                       |                         |
       |                       |                         +-> registry / family validation
       |                       +-> immutable draft + validation
       +-> Pipeline Builder / Pass Inspector / Raw tree
                                                |
                                       Save and reload atomically
```

The manager remains the authority for:

- templates and public pass catalog;
- registered transform IDs and family names;
- pass-option normalization;
- routing-policy validation;
- complete-document/source-drift validation; and
- atomic persistence and project reload.

The UI adapter may gain focused commands such as `set_pass_transforms` and
`replace_raw_document`, but it must delegate all actual document mutation and
validation to the manager. UI code must not modify `document_json` directly.

## Presentation models and testability

New or extended pure UI logic exposes at least:

- `ConfigV2PipelineOverview`: active rows, selected-transform counts, purpose,
  and action availability;
- `ConfigV2PassInspectorView`: pass identity, workflow-stage explanation,
  transform check-state, typed options, and compact contract summary;
- `ConfigV2RoutingView`: registered families and automatic/require/prefer/
  exclude state;
- `ConfigV2RawDocumentView`: structured versus preserved path metadata and raw
  edit state;
- `ConfigV2FooterView`: clean/dirty state, exact validation state, primary
  action availability, and overflow actions.

The Qt panels render these models and emit typed intents. They do not infer
transform selection from visual tree expansion or parse and mutate documents.

## Error handling

- Unknown pass, transform, or family choices are rejected by the manager and
  rendered at the relevant control.
- Invalid raw JSON leaves the current draft unchanged and highlights the parse
  error.
- Source drift, stale validation, or a failed atomic save leaves the draft open
  and shows a recovery message; it never silently overwrites a changed source.
- A pass with no selectable transforms or no typed options says so plainly.

## Verification

1. Pure unit tests cover active/available projection, transform selection and
   order preservation, no-transform passes, routing modes, footer state,
   preserved/raw path classification, invalid raw JSON, and stale validation.
2. Manager tests cover transform and complete-document mutation through the
   existing validation and atomic-save boundary.
3. Qt contract tests assert that the default overview has no serializer
   manifest, permanent raw document, or stage/transform catalog expansion; the
   inspector and builder own their focused controls; and the footer is one thin
   strip with overflow actions.
4. IDA 9.1 (PyQt5) and IDA 9.3 (PySide6) GUI smoke tests cover opening an active
   pass, selecting an individual transform, opening the pipeline builder,
   inspecting routing, viewing raw JSON, validating, and saving a disposable
   config.

## Out of scope

- Creating new Python pass or transform implementations inside IDA.
- Changing pass contracts, registry semantics, or pipeline execution order.
- Making the configuration project a function-specific recipe editor; that
  remains the Workbench's responsibility.
- Replacing the native Qt UI with the future HTTP/web workspace exploration.
