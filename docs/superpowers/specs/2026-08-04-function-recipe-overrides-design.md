# Function Recipe Overrides Design

## Goal

Make saved, typed config-v2 function recipes the only user-facing per-function
override mechanism. Preserve private rule scoping as an internal runtime
facility, and expose a safe per-function `min_state_constant` override for the
state-machine CFF unflattener.

## Public model

The public unit is a registered pass recipe, never a private optimizer rule.
The workbench Recipe Composer remains the authoring surface and "Save for this
function" remains the persistence action. The old Function Rules dialog and
the statistics panel actions that save or infer private fired-rule sets are
removed from user-facing registration.

`min_state_constant` means the minimum numeric state value accepted by the
state-CFF dispatcher recovery path. It is an integer threshold, not a minimum
number of distinct constants. A typed `StateMachineCffOptions` record validates
that the value is an integer (excluding booleans) in the unsigned 64-bit range.

## State-CFF recipe editing

The state-CFF operation remains implemented by the canonical ordered five-pass
spine. One function-level edit applies `min_state_constant` atomically to every
spine entry so the live hook bridge, family detection, and recovery cannot see
different thresholds. The recipe service rejects missing, partial, duplicate,
or out-of-order spines rather than making a partial edit.

Current config-v2 canary files encode the live-rule options under
`legacy_rule_options` on every spine stage. Those persisted projects remain
readable. New function-recipe edits use the typed parser and update the
compatible serialized shape without exposing independent private-rule
selection.

## Persistence

Function recipes and internal rule-scope state share the optimization storage
port, but the default live-IDA backend changes from a SQLite file inside the
erasable log directory to an IDB-local netnode. Explicit `sqlite` configuration
continues to work for offline tests and users who deliberately select it. This
makes the default architecture portable across IDA on macOS, Linux, and Windows
and prevents `erase_logs_on_reload` from deleting saved function recipes.

## Compatibility boundary

The internal `RuleScopeService`, inference records, tags, and manager APIs stay
available for runtime policy and compatibility. They are no longer advertised
as operator controls. Existing saved function recipes continue to be checked
against function fingerprint, source project path, runtime project path, and
registered pass validation before activation.

## Verification

Unit tests cover typed threshold validation, atomic five-stage replacement,
legacy config-v2 compatibility, hook activation, IDB-local default storage, and
removal of private-rule actions from public UI registration. System validation
uses `tools/scripts/run_system_tests_docker.sh` for the state-CFF runtime path.
Architecture validation runs ast-grep and import-linter from this worktree.
