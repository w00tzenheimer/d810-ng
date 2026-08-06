# Left-Aligned Workbench Metadata Design

## Goal

Make the D-810 Configuration project summary and Deobfuscation Workbench
metadata read naturally from left to right on every supported Qt platform.
Remove the centered compact-form appearance observed under IDA on Windows
without changing project selection, workflow, or persistence behavior.

## Root cause

The configuration selector is a `QPushButton`, whose caption is centered by
default. The project identity, function context, and workflow summary use
`QFormLayout` without explicit form alignment, label alignment, or field-growth
policy. Qt therefore applies platform-style defaults; the affected Windows
style centers each compact form within the dock.

## Design

- Give the configuration selector a local left-aligned text style with modest
  leading padding. Do not apply an application-wide Qt stylesheet.
- Explicitly anchor the project identity, Workbench function context, and
  Workbench workflow-summary forms to the left and top.
- Explicitly left-align form labels.
- Let non-fixed value fields grow across the available width so long runtime
  names and effective-pass summaries use the dock rather than wrapping inside
  a centered island.
- Keep the workflow stage strip, description editor, action buttons, evidence
  table, and detail panel unchanged.

## Compatibility

Use Qt APIs exposed by `d810.qt_shim` and handle the `QFormLayout` field-growth
enum shape used by both PyQt5 and PySide6. The change is presentation-only and
must not introduce new state, settings, or dependencies.

## Verification

- Add regression coverage that identifies the explicit alignment and growth
  policy on both affected panels.
- Run the focused UI tests and the broader unit UI suite.
- Run ast-grep and import-linter from the target worktree.
- Refresh the graphify code graph after implementation.

