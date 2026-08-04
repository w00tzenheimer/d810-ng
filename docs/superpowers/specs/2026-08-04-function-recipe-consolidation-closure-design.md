# Strict pass and function-recipe configuration design

Status: implemented and superseding the earlier private-implementation design.

## Decision

Config-v2 passes and typed pass options are the only public configuration
model. Function recipes persist that same model. Stable transforms provide
legitimate fine-grained MBA selection; stable stages provide execution and
diagnostic identity without becoming independent configuration switches.

`ExecutionScopeService` evaluates expanded pass-owned stages for function EA,
tags, maturity, and ephemeral analysis adjustments. The optimizer and the
Workbench call the same evaluator. Private implementation objects exist only
at the hook adapter boundary.

## Storage

`function_recipe_storage` is one typed application setting. Missing settings
select IDB-local netnode storage. SQLite requires `{backend: sqlite, path:
<absolute external path>}`. Saving plugin settings immediately reconfigures the
manager. Invalid settings fail before the current backend is replaced.

Records use database identity, project name, and function EA; recipes also
carry a function fingerprint. No former unscoped table or selector shape is
translated.

## Diagnostics

The public hierarchy is pass -> stage. Decisions include pipeline, maturity,
active state, reason, and detail. Unknown pass/stage targets are visible and
fail closed. Public statistics are projected to stable stage IDs; private class
names may appear only in debug implementation detail.

## Deliberate tradeoffs

- Saved recipes run explicitly through `Deobfuscate This`, avoiding unsafe
  callback-time global runtime swaps.
- Atomic stages remove unsupported combinations at the cost of fewer expert
  toggles.
- SQLite remains available for inspectability and sharing, but the explicit
  path requirement makes ownership and cleanup the caller's responsibility.
- `allow_executable_readonly` remains as a confirmed, very dangerous expert
  override because some targets intentionally place immutable data in an
  executable segment; normal constness classification is architecture-neutral
  and does not depend on platform-specific section names.
