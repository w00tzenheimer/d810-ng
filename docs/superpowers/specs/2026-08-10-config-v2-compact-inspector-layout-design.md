# Config-v2 Compact Inspector Layout

## Purpose

Make the config-v2 Project Editor visually consistent with the D-810
Configuration host while preserving the inspector's capability-driven layout.
The editor must prioritize the declared controls that let an operator change a
pass, rather than leaving blank space or showing generic chrome.

## Scope

This change is limited to the Project Editor inspector and the shared footer
overflow-button geometry used by the Project Editor and Configuration host.
It does not change config-v2 document semantics, pass contracts, typed option
values, rule selection, routing, or execution behavior.

## Layout contract

### Shared density

The Project Editor will use the same compact grammar as the Configuration host:

- four-pixel outer gutters and local spacing;
- compact, left-aligned form rows;
- no centered metadata or empty vertical padding;
- a single shared overflow-button policy so both `...` controls have matching
  target size.

### Inspector header and Details

The header remains title, purpose, then the Pipeline / Details / View contract
actions. When Details is expanded, Scope, Backend, and Safety render as the
same compact, left-aligned three-row form used by the Configuration host.
Those values remain read-only registered-pass contract metadata.

### Primary capability workspace

The inspector continues to derive visibility and elastic height from the pass
layout projection:

- Rules is the elastic workspace for rule-catalog passes.
- Transforms is the elastic workspace for transform-catalog passes.
- Options is elastic only for fields-only passes.
- Absent capabilities render no group, placeholder, label, or reserved height.

Rules and rule metadata remain separately scrollable at all window sizes.

### Typed options

Options render as a compact two-column typed form:

- labels align in a stable left column;
- widgets grow across the value column;
- an experimental or advisory message belongs underneath its own value widget,
  wraps inside that column, and never overlaps an adjacent field;
- option groups have no surplus container padding.

The renderer remains constrained by `FieldEditorSpec`; it does not interpret
arbitrary project JSON into ad hoc widgets.

### Footer

The footer remains status, overflow, and Save. The Project Editor overflow
button and the Configuration host engine overflow button use the same shared
minimum geometry and popup behavior. The actions themselves remain unchanged.

## Failure handling

If an inspector layout or typed option projection is unavailable, the existing
compact status message remains the only fallback. The renderer must not add
empty Rules, Transforms, or Options sections to compensate.

## Verification

- Extend panel and host layout-contract tests before changing production code.
- Exercise Details, Rules-primary, Transforms-primary, Options-primary, and no
  selectable capability projections with fake Qt widgets.
- Verify advisory controls reserve their own wrapped value-column row.
- Run the focused UI tests, the full UI suite, Ruff, ast-grep, import-linter,
  and `graphify update .` from this worktree.
- Native acceptance is an IDA 9.4/XQuartz smoke of Configuration -> Edit
  pipeline -> a rule-heavy pass and a fields-only pass; it must confirm scroll
  regions, form alignment, wrapped advisory text, and matching overflow
  controls without modifying the original IDB.
