# Host-Owned Config-v2 Project Editor

Status: approved 2026-08-10

Amends:

- `2026-08-07-config-v2-operator-pipeline-editor-design.md`
- `2026-08-10-capability-driven-pass-inspector-design.md`

This design retains their typed, capability-driven editor model, but replaces
the Project Editor's duplicated configuration ownership and compressed identity
strip.

## Problem

The Configuration dock and Config-v2 Project Editor both present project
context and pipeline actions. The editor places pass name, purpose, Scope,
Backend, Safety, `View contract...`, and `Edit pipeline...` in one horizontal
strip. Under real IDA 9.4 dock geometry, that strip squeezes the name and
purpose into a narrow wrapping column. Rule selection and typed option controls
work, but the screen is difficult to scan.

The editor also reserves navigation and actions that belong to the
Configuration dock, so it is unclear which surface owns selection, project
context, and entry to project-wide editing.

## Goals

1. Make the Configuration dock the sole owner of selected configuration and
   the `Edit pipeline...` entry action.
2. Make the separate Project Editor a focused pipeline-builder or selected-pass
   detail dock, never a second configuration host.
3. Give the pass name and purpose a full-width readable header.
4. Keep pass contracts read-only and distinct from typed project-editable
   `PassEditorSpec` controls.
5. Make Rules/Transforms and their metadata usable at constrained dock widths
   through independent scrolling.
6. Preserve draft ownership, validation, rule selection, typed controls, and
   atomic save/reload.

## Information architecture

### D-810 Configuration dock: project host

The Configuration dock owns all project-level context:

1. configuration chooser;
2. compact project summary and collapsed `Details` disclosure;
3. ordered active-pass list and selected row; and
4. the sole visible `Edit pipeline...` command.

`Edit pipeline...` opens or activates the separate Project Editor on the
pipeline-builder screen. Double-clicking an active pass opens that same dock on
the selected-pass inspector. The host carries the exact pipeline row index to
the editor; it does not infer a unique selection from `pass_id`, because a
pipeline may validly include the same registered pass more than once.

The host does not show catalog availability as active pipeline state. Its
active-pass summaries remain compact and derive from the selected config-v2
draft.

### Config-v2 Project Editor: focused detail dock

The separate Project Editor has two screens:

- **Pipeline**: project-wide ordered pass sequence and editing controls.
- **Pass detail**: one explicitly selected active-pass editor.

It has no configuration chooser and no `Edit pipeline...` button. A compact
`Pipeline` navigation affordance returns from Pass detail to Pipeline. It does
not reselect or rewrite the host's configuration.

The editor header is a dense, stable project line:

```
<elided destination path>                              Ready | <N> passes
```

When Pass detail is active, it immediately follows with a full-width pass
header:

```
<Display name>  <stable pass ID>
<one- or two-line catalog purpose>
[Pipeline] [Details] [View contract...]
```

Pass identity and purpose are never in the same horizontal layout row as
contract metadata or action buttons. Purpose wraps across the available width.
`Pipeline` is navigation, not a duplicate project action.

### Details and contract boundary

`Details` is collapsed by default. It reveals a compact structured **Pass
contract (read-only)** section:

| Field | Meaning | Editable in this screen? |
|---|---|---|
| Scope | Legal scheduling granularity, for example `function`. | No |
| Backend | Registered application route, for example `mutation_backend`. | No |
| Safety | Registered safety policy, for example `default`. | No |

These fields originate in the registered `PassSpec`/contract. They must not
become project dropdowns: changing them would let a draft appear valid while
violating a pass's registered execution contract. A different backend,
granularity, or safety policy requires a separately registered pass or an
explicitly designed pass option.

`View contract...` remains an on-demand structured/raw read-only dialog. It is
not embedded in the normal screen and reserves no permanent area.

### Capability-driven body

`PassEditorSpec` is the sole authority for body sections:

- `RULE_CATALOG` renders Rules as primary workspace.
- `TRANSFORM_CATALOG` renders Transforms as primary workspace.
- Fields-only renders typed Options as primary workspace.
- No declared capability renders only a compact summary.
- No absent capability renders a label, empty group box, placeholder text, or
  vertical space.

The primary workspace is the only expandable body region. Secondary typed
options are compact and remain visible below it when declared. A fields-only
pass shows Options without empty Rules or Transforms sections.

#### Rules workspace

Rules has a fixed header for filter and bulk-selection controls. Below it, the
rule tree and rule metadata are separate scrollable panes in a horizontal
splitter:

- the tree scrolls independently while filter and `Select visible`/`Clear
  visible` remain fixed;
- metadata scrolls independently so a long purpose, proof, advisory, or
  constraint list does not change tree height;
- splitter sizes are presentation preferences and never config-v2 state;
- existing family/subfamily tri-state selection, filtering, experimental
  labels, and typed persistence remain intact.

Rule metadata may show verification state, expensive/skipped-proof advisories,
constraints, and experimental warnings. Experimental rules remain selectable;
the operator retains the final decision.

#### Typed Options

Only `FieldEditorSpec` declarations create editable controls:

- enum such as `memory_policy` -> dropdown;
- boolean such as `rva_guard` -> checkbox;
- integer -> bounded numeric control;
- advisory/danger text -> immediately beneath its relevant control.

No UI control is inferred from an arbitrary option key. Pass contract fields
are not typed options.

## State ownership and data flow

```
Configuration dock (config + selected row)
        | exact row index / explicit action
        v
Config-v2 Project Editor (Pipeline or Pass detail)
        | typed intents only
        v
draft adapter -> manager editing service -> validation / atomic save and reload
```

The Configuration dock owns configuration selection and entry actions. The
Project Editor owns only its current screen, detail disclosure state, splitter
geometry, and rendering. The shared draft adapter owns mutation intent; the
manager is authoritative for normalization, pass registration, routing,
validation, and persistence.

Changing a typed option, rule selection, or transform selection leaves the
pass detail open and marks the shared draft dirty. Changing host selection does
not discard the draft. A stale or invalid save leaves the draft open and shows
the existing actionable validation result.

## Error handling and hot reload

- Unknown selected index/pass reports a compact unavailable state without
  constructing a misleading inspector.
- Contract-dialog error is contained to that on-demand action.
- Screen changes add the destination widget to `QStackedWidget` before making
  it current. An absent widget is a logged no-op, never a native warning or
  crash.
- Details/splitter UI state is presentation-only and survives normal rerender;
  it is never serialized into project configuration.

## Verification

1. Qt-free tests prove exact-index host-to-editor routing and capability
   projection with no inferred absent sections.
2. Qt adapter tests prove the host owns the only `Edit pipeline...`; editor
   lacks a config chooser and duplicate action; pass header is full width; and
   Details is read-only.
3. Rule-catalog tests prove fixed filter/bulk controls, independently scrollable
   tree/metadata panes, family selection, experimental labels, and metadata.
4. Typed-control tests retain enum, boolean, integer, advisory, and
   manager-backed save behavior.
5. IDA 9.4 smoke opens a disposable config, Pipeline, and a rule-catalog pass,
   then captures full-width header, scrollable Rules, and compact options. It
   must not produce `QStackedWidget::setCurrentWidget`, crash, or timeout.
6. Existing IDA 9.1/PyQt5 and IDA 9.3/PySide6 compatibility coverage remains
   green.

## Non-goals

- Changing `PassSpec` contract policy at runtime.
- Making Scope, Backend, or Safety project dropdowns.
- Arbitrary user-authored Qt dialogs or editor schemas.
- Replacing the Project Editor dock with browser/WebEngine.
- Changing pipeline execution, routing, or config-v2 serialization.
