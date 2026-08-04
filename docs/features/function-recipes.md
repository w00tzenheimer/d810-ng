# Function recipes and execution configuration

Function recipes are the sole durable per-function execution configuration.
They store strict config-v2 pass entries: stable pass IDs, typed options, and
function targeting. Private Python optimizer class names are never recipe
selectors.

## Public vocabulary

- A **pass** is an ordered public operation, such as
  `constant-simplification` or `mba-simplify`.
- A **family** selects an obfuscation strategy behind a pass.
- A **transform** is a stable, user-selectable operation owned by a pass. MBA
  recipes use `options.transforms` and `options.transform_options`.
- A **stage** is a stable execution/diagnostic child owned atomically by a
  pass. Stages are visible but are not independent configuration switches.

`constant-simplification` owns `fold-readonly-data`,
`fold-constant-subtree`, and `forward-constants`. Its memory policy and the
dangerous `allow_executable_readonly` override apply to the operation as a
whole. The override remains available for explicit expert use and is rejected
unless the user confirms it in the editor.

## Create and run a recipe

1. Decompile the target and open the **d810-ng Deobfuscation Workbench**.
2. Open **Recipe** and add, remove, order, or configure registered passes.
3. Run **Analyze recipe** and resolve validation diagnostics.
4. Use **Apply once** to test the draft.
5. Use **Save for Deobfuscate This** to retain it for this function.
6. Invoke **Deobfuscate This** whenever the saved recipe should execute.

Ordinary F5 uses the active project pipeline. `Deobfuscate This` temporarily
installs the saved recipe for one synchronous decompile and restores the
project pipeline afterward.

The state-CFF spine exposes one family option, `min_state_constant`. The typed
integer is applied to the complete canonical spine; individual stages cannot
diverge. Validation rejects booleans, negative values, and integers wider than
64 bits.

## Effective execution diagnostics

The Workbench groups decisions by pass ID and stage ID. Each stage reports its
pipeline, maturities, active/excluded state, reason, and detail. Execution and
the report use the same evaluator, so the report cannot claim that a stage ran
when the optimizer excluded it. Unknown targets are reported without creating
or activating an implementation.

## Persistence and identity

The application setting is `function_recipe_storage`:

```json
{"backend": "netnode"}
```

Netnode is the portable default and travels with the IDB. SQLite is opt-in and
requires an explicit absolute path outside the erasable log directory:

```json
{
  "backend": "sqlite",
  "path": "/absolute/path/to/d810-function-recipes.sqlite3"
}
```

In the plugin settings, choosing SQLite, selecting the file, and saving calls
the manager's live reconfiguration path immediately; no restart or project
reload is required. An invalid backend, missing/relative path, or path beneath
the log directory fails closed and leaves the previous storage active. The
path rules are `pathlib`-based and therefore apply on macOS, Linux, and Windows.

Both backends key recipes and tags by database identity, project name, and
function address. The recipe also stores a function fingerprint; code drift
produces a visible stale-recipe result rather than silently applying uncertain
configuration.

Former unscoped records and private implementation selectors are intentionally
ignored. Translating them would recreate competing configuration semantics and
could assign data to the wrong database.

## Tradeoffs

- Explicit `Deobfuscate This` activation is less automatic than applying a
  recipe on every F5, but avoids re-entrant global runtime swaps from Hex-Rays
  callbacks.
- Netnode is portable and zero-configuration; SQLite is easier to inspect and
  share, but requires the operator to own a safe path and its lifecycle.
- Atomic pass-owned stages reduce fine-grained switches, but prevent invalid
  combinations such as folding memory without the propagation stages that
  define the public constant-simplification contract.
