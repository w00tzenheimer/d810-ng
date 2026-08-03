# Rule Context Actions and User-Override Save Design

## Goal

Make the D-810 Configuration rule tree faster to use without weakening the
config-v2 source-of-truth boundary. A user should be able to discover the
opposite state of a rule from its context menu, enter the correct editing
workflow immediately, and save ordinary edits back to the effective writable
user override. Choosing a different configuration remains an explicit action.

## Existing boundaries

`RuleTreeWidget` currently renders both legacy rule policy and config-v2
runtime expansion. Its leaf items carry the registered rule object, while
category and optimizer headers are aggregate presentation items. The widget
already emits selection and toggle signals, but its context menu is limited to
category Select All/Deselect All actions.

Legacy projects persist a flat set of activated `RuleConfiguration` entries.
Their rule tree can therefore apply a requested state to the in-memory draft
and enter the existing edit state machine.

Config-v2 projects persist an ordered pipeline and typed pass rule selections.
The rule tree is only a runtime projection: an individual displayed rule may
come from an explicit MBA rule selection, a pass-level adapter, or a native
state-machine/cleanup pass. A generic flat-rule mutation would be lossy and is
not permitted. Config-v2 context actions therefore open the structured editor
and focus a safely identifiable pass/rule, leaving the draft unchanged until
the user edits it explicitly.

## User behavior

### Leaf rules

- Right-clicking an enabled rule presents `Disable`.
- Right-clicking a disabled rule presents `Enable`.
- Choosing either action first enters the applicable editing workflow.
- In a legacy project, the requested checkbox state is applied to the draft
  and the normal Save/Cancel controls become visible.
- In a config-v2 project, the structured editor opens. If the runtime rule can
  be mapped unambiguously to one pipeline pass, that pass is selected and the
  rule is identified in the editor status; no flat rule state is silently
  written.

### Category and optimizer headers

- A partially or fully disabled aggregate presents `Enable All`.
- A fully enabled aggregate presents `Disable All`.
- In legacy editing, the action applies recursively to all visible rules in
  that aggregate and enters the existing edit state machine before mutation is
  committed.
- In config-v2 mode, the action opens the structured editor for the aggregate's
  owning pass set. If the aggregate spans more than one editable representation,
  the editor opens without a mutation and explains that the selections must be
  edited explicitly.

The labels describe the requested operation; they never imply that a
config-v2 runtime projection has already been persisted.

## Architecture

### Pure context-action policy

Add a small UI-logic module that accepts an item kind and its enabled/total
counts and returns a typed context action (`enable`, `disable`, `enable_all`,
or `disable_all`). It also provides the recursive legacy draft operation for a
set of rule names. This module has no Qt, IDA, or persistence imports.

### Rule tree adapter

Extend `RuleTreeWidget` with a context-intent signal carrying the selected
rule/category target and requested operation. Menu construction remains in the
widget, but labels and operation selection come from the pure policy. Existing
category behavior is preserved for callers that do not opt into the global
configuration context actions (notably the function-rules dialog); those
callers continue to use their current Enable All control and checkbox editing.

### Configuration form orchestration

`D810ConfigForm_t` opts into the new context intents and owns the mode split:

- legacy: enter `_enter_edit_mode`, apply the pure operation to the tree draft,
  and let `_save_rules` persist the result;
- config-v2: resolve the current effective runtime snapshot, derive an optional
  pass focus target, and open `ConfigV2EditingPanel` with that focus metadata.

The form must not build or write config-v2 documents itself. The existing thin
adapter and manager service remain the only structured-edit path.

### Focused structured editor

`ConfigV2EditingPanel` accepts an optional pass/rule focus target. On initial
render it selects the matching pipeline row when present and reports the rule
target in the status/detail area. A missing or ambiguous mapping is shown as a
non-error explanation rather than guessed.

### Override destination and Save As

For ordinary config-v2 edit actions, destination resolution is deterministic:

1. use the current runtime path when it is already inside the writable
   `cfg/d810` directory;
2. otherwise use the writable user path with the same basename as the runtime
   project.

The edit action opens directly on that destination; it does not force a Save
dialog. The manager's existing atomic writer continues to overwrite an
existing user file safely and reload the project through the state facade.

The structured editor gets an explicit `Save as another config...` action. It
opens a file chooser, retargets the current draft without discarding edits,
and updates the displayed destination. The ordinary `Save atomically and
reload` button always saves to the current destination and never silently
creates a sibling rule configuration.

Duplicate actions retain their current explicit destination chooser and remain
the deliberate way to create a separate configuration from the current one.

## Error handling and safety

- Read-only or unavailable forms do not expose mutation actions.
- A context action that cannot resolve a current snapshot reports a concise
  warning and leaves the tree unchanged.
- Config-v2 focus resolution is conservative: zero or multiple owners produce
  an explanatory status, not a guessed pass edit.
- The manager continues to reject writes to bundled source files and validates
  the complete document before atomic replacement.
- Existing user overrides are overwritten only by the explicit ordinary save
  operation after validation; `Save as another config...` is the opt-in path
  for a new destination.

## Test strategy

1. Pure unit tests cover leaf/category/optimizer action labels, aggregate
   state, recursive legacy draft operations, and ambiguous config-v2 focus.
2. Rule-tree contract tests verify context-intent wiring, opt-in behavior, and
   that function-level dialogs retain their existing controls.
3. Configuration-form contract tests verify legacy auto-entry, config-v2
   focused-editor routing, and deterministic same-basename user destinations.
4. Adapter/panel tests verify focus selection, Save As retargeting, and that
   ordinary save delegates to the existing atomic manager command.
5. Existing manager tests continue to prove bundled-source refusal,
   lossless unknown-field preservation, stale-validation rejection, and
   atomic overwrite of an existing writable destination.
6. Run the targeted UI/manager tests with `PYTHONPATH=src pyenv exec python`,
   then the repository architecture gates (`sg scan` and `lint-imports`) from
   this worktree. Refresh `graphify-out` after source changes.

## Non-goals

- No new pass or transform implementations are generated by the UI.
- No flat legacy downgrade of config-v2 projects.
- No automatic guessing of which pipeline pass should own an ambiguous rule.
- No change to function-scoped override persistence beyond preserving the
  existing dialog behavior.
