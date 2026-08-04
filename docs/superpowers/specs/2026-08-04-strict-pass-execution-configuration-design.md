# Strict Pass and Execution Configuration Design

**Status:** Implemented on `diff/lrea-portable-cfg-case-producer`.

## Goal

Finish the configuration consolidation so D810 has one public execution model:
ordered registered passes with typed options. Function recipes persist that
model for one function. Optimizer rule classes remain private backend code and
are not configuration, persistence, selector, or top-level diagnostic IDs.

This change also makes recipe persistence an application-level setting with a
strict, portable SQLite contract instead of a hidden project-config convention.

## Scope boundary

This design removes compatibility behavior from the config-v2 and function
recipe path. It does not delete the separate legacy project loader in this
change. A legacy project may still use its existing loader, but a config-v2
document or saved function recipe must use only the canonical schema defined
here. There is no mixed mode and no runtime migration from old config-v2
spellings.

## Public configuration model

### Passes are the durable execution unit

Every pipeline entry contains a canonical `pass_id`, pass contract fields, and
typed `options`. Pass ordering, enablement, and options are the only data saved
in a function recipe.

`PipelineConfig` no longer contains a generic `rules` member. It also no longer
accepts `pass` as an alias for `pass_id`, top-level contract aliases, or unknown
fields. Malformed or former config-v2 documents fail validation with the exact
field path.

### Transforms are pass-owned public choices

Some passes, notably `mba-simplify`, legitimately need fine-grained selection
without turning hundreds of algebraic rewrites into scheduler-level passes.
Those passes expose a typed `options.transforms` list of stable transform IDs
and optional `options.transform_options` keyed by those IDs.

Stable transform IDs are registered metadata. They are not Python class names
and do not contain `Rule` implementation terminology. The pass registry owns
the mapping from public transform ID to private backend implementation.

Passes such as `constant-simplification` intentionally expose no transform
selection. Their private stages always execute as one semantic operation and
only semantic options such as memory policy are configurable.

### Families compose passes

A family is an editor and validation concept that expands to a canonical pass
sequence. It is not another runtime selection layer. State-CFF remains a
five-pass spine; `min_state_constant` is one typed family option projected onto
the complete spine. Partial family configuration is rejected.

## Internal execution model

The pass registry publishes stable execution-stage descriptors:

- owning `pass_id`;
- stable `stage_id`;
- pipeline kind;
- allowed maturities;
- private implementation binding.

The implementation binding may point to an existing `*Rule` object because the
Hex-Rays hooks still execute optimizer rules. That name never crosses into a
project document, recipe, selector, hint, or top-level Workbench model.

`RuleScopeService` becomes `ExecutionScopeService`. It evaluates pass-level
function targeting, tags, maturity, and ephemeral inferred suppressions against
expanded stage descriptors. The same evaluator supplies the hook adapters and
the Workbench report.

Automated analysis may suppress a stable pass or stage ID and may provide typed
option overrides. It cannot activate an absent pass or name a private rule.

Deferred optimizer work follows the same boundary. `run_later` records the
owning `(pass_id, stage_id)` and the target maturity; the hook resolves that
identity through the current `ExecutionScopeService` expansion only when the
request becomes eligible. This costs one identity lookup when scheduling and
one when draining, but prevents a private class rename from changing durable or
cross-maturity behavior and prevents deferred work from activating an absent
pass.

`pipeline_v2_mode: "shadow-check"` is the sole project spelling for shadow
comparison. The former `require_pipeline_v2_shadow_match` boolean is rejected,
including when an explicit mode is also present. The tradeoff is deliberate:
older config-v2 documents must be edited instead of loading silently, while
configuration meaning stays singular and diagnostics never need to explain
which of two precedence paths won.

## Diagnostics

The Workbench reports a hierarchy instead of a flat rule list:

```text
constant-simplification
  fold-readonly-data       active at MMAT_PREOPTIMIZED
  fold-constant-subtree    active at MMAT_PREOPTIMIZED
  forward-constants        excluded at MMAT_GLBOPT1: inference-suppressed
```

Each stage decision contains `pass_id`, `stage_id`, pipeline, maturities,
active/excluded state, reason, and detail. Unknown targets are reported as
stable pass/stage IDs and indicate a programming or stale-analysis error.

User-visible statistics use pass and stage IDs. Low-level debug logs may still
include the implementation class name after the stable identity.

## Recipe persistence configuration

Recipe storage is application configuration, not project configuration. The
canonical setting is:

```json
"function_recipe_storage": {
  "backend": "netnode"
}
```

or:

```json
"function_recipe_storage": {
  "backend": "sqlite",
  "path": "/absolute/path/to/d810-recipes.sqlite3"
}
```

The shipped default is netnode. SQLite requires an absolute path. The resolved
path must not be the log directory or a descendant of it. Validation uses host
`pathlib` semantics, so Windows, macOS, and Linux use their native absolute-path
rules.

The former flat `function_recipe_backend` key and a string-valued
`function_recipe_storage` are errors. There is no path-implies-SQLite behavior.

Storage is opened when the manager starts and atomically reopened when the
application setting changes. An invalid SQLite configuration disables recipe
persistence and surfaces a configuration error; it never silently falls back
to netnode and does not prevent ordinary deobfuscation.

The Plugin Configuration dialog exposes the backend selector and SQLite file
picker. A project change cannot change the storage backend.

## Bundled configuration conversion

All bundled config-v2 canaries are rewritten in place to canonical `pass_id`
entries and typed options. Runtime compatibility parsing is not added.

- MBA rule lists become stable `options.transforms` IDs.
- `options.legacy_rule` is removed from simple flow passes.
- State-CFF `legacy_rule`, `legacy_rule_options`, and `native_pipeline` payloads
  become the canonical typed family options.
- Migration-only top-level aliases and ignored metadata are removed.

Saved recipes using the former schema fail validation as stale/unsupported.
They are not rewritten when loaded because guessing implementation-name
ownership would recreate the ambiguity this consolidation removes.

## Alternatives considered

### Promote every optimizer rule to a pass

This gives one identifier namespace but creates hundreds of scheduler nodes,
misrepresents local algebraic rewrites as function passes, and makes contracts
and maturity scheduling unmanageable. Rejected.

### Keep `rules.*` and only rename the UI

This is the smallest patch but preserves private implementation names in saved
recipes and leaves two selection models. Rejected.

### Public passes plus pass-owned stable transforms

This is the selected design. It preserves legitimate fine-grained MBA control
while keeping scheduling, persistence, and diagnostics centered on passes.

## Implementation decisions and consequences

### Keep optimizer rule classes private

`*Rule` classes still exist as Hex-Rays implementation objects. They are not
user configuration. Public project files, function recipes, deferred work, UI
selection, and effective-scope diagnostics use pass IDs and pass-owned stage or
transform IDs.

The benefit is one durable model that survives Python class renames. The cost
is a registry bridge from each public stage to its private implementation and a
small amount of low-level logging that still names the implementation when
debugging the backend.

### Make inferred adjustments strictly typed

Inferred execution adjustments use `ExecutionTargetKind` and
`ExecutionAdjustmentAction` enums. Raw strings are rejected instead of being
coerced. This makes invalid internal producers fail close to their source, at
the cost of requiring every producer to import and use the canonical types.

### Carry stable identities through deferred execution

Optimizer `run_later` requests carry `(pass_id, stage_id)` and are resolved
against the current expansion when drained. This prevents a private rule rename
or stale object reference from changing behavior. It adds one lookup at enqueue
and drain time, and intentionally drops requests whose public stage is absent
from the current configuration.

### Keep shadow comparison as an internal mechanism

The internal pass runner still has a boolean gate used to enforce comparison;
that is an implementation parameter, not a config compatibility alias. The
only accepted project spelling is `pipeline_v2_mode: "shadow-check"`. Former
project booleans are rejected. This preserves a simple internal API while
ensuring users never face two spellings or precedence rules.

### Make SQLite opt-in and fail closed

Netnode is the portable default. SQLite opens only from the typed,
application-level storage setting with an absolute path outside the log tree.
This prevents project changes and log cleanup from selecting or deleting shared
recipe state. The downside is that users who want a shared SQLite database must
configure an explicit host-native path, and invalid settings disable recipe
persistence instead of silently falling back.

## Verification contract

Completion requires:

- strict schema tests proving former spellings fail;
- storage tests proving only the typed application setting can select SQLite;
- cross-platform path-validation tests;
- execution/report parity at every maturity;
- config and recipe searches proving no serialized private rule IDs remain;
- conversion and semantic activation tests for every bundled config-v2 canary;
- native IDA tests through `tools/scripts/run_system_tests_docker.sh`;
- architecture checks from the target worktree;
- a current Graphify update.
