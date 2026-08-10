# Capability-Driven Config-v2 Pass Inspector

## Goal

Replace the generic, vertically stacked config-v2 pass inspector with a compact
editor whose visible sections are declared by the selected pass's
`PassEditorSpec`. The inspector must emphasize the control surface that exists
for that pass, rather than reserving space for generic sections that are empty.

## Operator model

The selected pass supplies the UI structure:

- Every pass has a compact identity header.
- `RULE_CATALOG` passes expose a Rules primary workspace.
- `TRANSFORM_CATALOG` passes expose a Transforms primary workspace.
- Typed fields expose an Options form only when fields exist.
- A summary-only pass exposes neither catalog nor Options body.

The inspector does not infer a capability from option names or runtime class
attributes. `PassEditorSpec` is the sole authority for the editor surface.

## Layout

The inspector is a flat adaptive shell, not a nested collection of permanent
`QGroupBox` sections.

1. **Identity strip** - pass label, stable ID, and compact Scope, Backend, and
   Safety badges. It replaces the current nested “Pass inspector -> Pass”
   framing and does not scroll.
2. **Primary capability** - exactly one expandable, full-height workspace:
   Rules for a rule catalog or Transforms for a transform catalog. It contains
   search, explicit family/subfamily selection, per-item metadata, warnings,
   and filter-scoped bulk actions.
3. **Secondary typed options** - a compact fixed-height two-column form. It is
   shown only when the pass declares field controls. Advisory text is rendered
   directly beneath the relevant control; it is never a detached blank row.
4. **Actions** - `Edit pipeline...` is a compact action in the identity/action
   strip. `View contract...` opens the existing structured/raw contract dialog
   on demand.
5. **Footer** - dirty/validation state, menu, and Save remain compact and
   stable.

No empty-state labels, blank catalog panes, fixed Contract tree, or empty
Transforms/Rules group is rendered. A missing section occupies zero layout
space.

### Examples

**Constant simplification**

Identity strip -> compact Options form (memory policy, RVA guard, executable
read-only toggle and advisory) -> View contract action -> footer.

**Jump fixer**

Identity strip -> expandable Rules catalog (dominant height) -> compact Options
form -> View contract action -> footer. There is no Transform section.

## Component boundaries

- The Qt-free projection gains explicit presentation flags and ordered section
  metadata derived only from `PassEditorSpec`.
- The Qt panel maps those flags to visibility and stretch factors. It owns no
  pass-policy decisions.
- Existing rule and transform catalog widgets remain responsible for their own
  filtering, family/subfamily bulk operations, selection state, and metadata.
- Typed option controls continue to be generated from `FieldEditorSpec`.
- Contract data remains read-only and is constructed only when the operator
  invokes `View contract...`.

The primary capability is the only expandable region. Secondary typed controls
are fixed and compact; their controls remain fully accessible without requiring
an extra disclosure action.

## State and error behavior

- Switching selected passes recomputes the projection and replaces only the
  declared visual sections; draft edits remain in the shared project draft.
- A summary-only pass displays its compact identity strip plus a short,
  non-panel sentence that it has no editable controls.
- Contract rendering errors are contained by the existing dialog error path and
  do not prevent the pass editor from opening.
- Selection and typed-field validation remain in the existing Qt-free config-v2
  editing logic; the layout change does not relax the typed editor contract.

## Tests and acceptance criteria

Qt-free tests must prove projection results for:

- fields-only, rule-catalog, transform-catalog, and summary-only passes;
- no placeholders for absent capabilities;
- Rules as the primary workspace for Jump Fixer;
- Options as the primary workspace for constant simplification;
- correct visibility/action routing for the on-demand contract dialog.

Qt adapter tests must prove that hidden sections are not merely disabled or
empty: they are absent from the visible layout and receive no stretch. Existing
family/subfamily selection and typed option tests must stay green.

Native smoke acceptance covers IDA 9.4 (the current operator image), with the
existing PyQt5/PySide6 compatibility coverage retained for IDA 9.1 and 9.3.
The native capture must demonstrate one fields-only pass and one rule-catalog
pass without empty catalog/contract panels.

## Non-goals

- No user-authored Qt layouts.
- No raw JSON editing inside the default inspector.
- No change to pass execution, validation, persistence, or default selection.
- No browser/WebEngine dependency.
