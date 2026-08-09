# Config-v2 Typed Pass Editors Design

## Goal

Replace the generic config-v2 pass inspector with a small, closed set of
pass-owned typed editors. The result must let an operator understand and edit
a pass without treating JSON or private rule implementation details as the
primary UI.

The first target is `mba-simplify`, whose many transforms require explicit
family selection, individual explanation, and clear verification advisories.
The model applies to config-v2 public passes only. Legacy-only paths remain
outside this cutover and are migrated by dedicated scripts before entering the
public config-v2 catalog.

## Non-goals

- Do not let pass authors supply arbitrary Qt widgets, callbacks, or UI Python.
- Do not infer transform families from identifier spelling in the UI.
- Do not silently change an existing project's transform selection.
- Do not claim a rule is slow at IDA runtime merely because its offline SMT
  proof is costly.
- Do not provide generic in-IDA raw option editing in this version.

## Registration contract

Every public config-v2 pass registration owns an immutable,
IDA-independent `PassEditorSpec`. It is catalog metadata, not persisted project
data. The persisted project remains the pass's ordinary typed
`PipelineConfig.options` mapping.

`PassEditorSpec` is deliberately closed in the initial release:

1. `summary`: display compact pass explanation and status only.
2. `fields`: render a fixed form from approved scalar controls only: boolean,
   integer/range, enum, text, and bounded string-list.
3. `transform_catalog`: render an explicitly catalogued tree of selectable
   transforms plus a structured focused-transform inspector.

The registry must reject a public config-v2 pass that has no editor spec. A
`transform_catalog` must reject every selectable transform with incomplete
metadata. There is no implicit or "miscellaneous" family fallback.

## Transform metadata

Each transform in a `transform_catalog` declares, at minimum:

- stable transform ID and display label;
- explicit family and optional subfamily identifiers and labels;
- concise purpose and reference;
- supported maturity information;
- `default_selected` for newly-added content only;
- verification status and explanatory reason;
- advisory tone (`none`, `info`, `warning`, `danger`) and explanation; and
- cost classification: `unknown`, `proof_expensive`, or a measured runtime
  tier.

The metadata is pass-owned. It can express policy without taking agency away
from the operator. For example, a pass may describe an intentionally
selectable rule as `danger`, default it to disabled, and explain that it is
known incorrect. A pre-existing explicit project selection remains selected.

`Mul_MBA_1` is presented as a warning: its offline SMT verification is skipped
because its four multiplications exceed the practical proof budget. This does
not imply that executing the transform in IDA is slow. Runtime-cost language is
reserved for measured runtime metadata.

## Operator interaction

The `transform_catalog` uses a family tree as its action surface and a
separate inspector as its explanation surface.

- Family and subfamily items are tri-state: clear, partial, or all selected.
- Selecting a family selects or clears all of its visible descendants. With no
  filter, that is the entire family; with a filter, it is the matching subset.
- Each group displays an exact `selected / total` count.
- Individual transform rows remain independently checkable.
- Filtering narrows the visible tree. `Select all` and `Clear` apply only to
  the filtered result set. A distinct overflow action, `Select every
  transform`, operates on the entire pass.
- The focused transform inspector shows purpose, advisory, verification
  explanation, maturity, reference, and any measured cost. Pattern and
  constraints are optional expanded details, not the default display.

This keeps the selection space scannable even for hundreds of transforms and
makes a warning actionable before an operator changes a profile.

## Data flow and mutation boundary

The pass registration supplies `PassEditorSpec`; the manager/adapter exposes
it through the existing public catalog; the pure config-v2 projection builds a
screen-specific view; and Qt selects one fixed renderer from the closed editor
kind.

Every change goes through an existing typed manager mutation exactly once. A
family bulk action resolves to the registered stable transform IDs and invokes
the same ordered transform-selection mutation used for individual checkboxes.
The manager keeps canonical registry ordering and prunes options belonging to
deselected transforms. Qt never parses or rewrites project JSON to implement a
selection action.

## Raw data boundary

The normal config-v2 UI does not expose generic raw option editing. Contracts
remain viewable, read-only, and structured for auditability. A future explicit
`Open config in editor...` action may hand the project JSON to the user's
external editor; it is intentionally outside this version.

## Compatibility and defaults

Existing config-v2 documents retain their exact selected transform IDs.
`default_selected` applies only when an operator adds a pass or when migration
creates new content without a prior explicit choice. The editor validates
against the registry and never invents selection state.

## Verification

Unit tests cover the pure metadata projection, rejection of missing
config-v2 metadata, family/subfamily selection semantics, filtered bulk
actions, advisory rendering data, and preservation of existing choices.
Manager/adapter tests prove one canonical mutation per action and canonical
transform ordering. Qt contract tests prove the fixed renderer routing and
tri-state behavior. Native smoke tests on both IDA 9.1/PyQt5 and
IDA 9.3/PyQt6 verify the family tree, inspector, selection persistence, and
compact layout.
