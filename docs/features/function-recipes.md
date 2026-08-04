# Function Recipes

Function recipes are the sole durable per-function execution configuration.
They contain config-v2 public pass IDs and typed options. They do not expose
expanded instruction or flow rule classes as operator controls.

## Create and run a recipe

1. Decompile the target and open the **d810-ng Deobfuscation Workbench**.
2. Open **Recipe** and add, remove, order, or configure registered passes.
3. Run **Analyze recipe** and resolve validation diagnostics.
4. Use **Apply once** to test the draft.
5. Use **Save for Deobfuscate This** to retain it for this function.
6. Invoke **Deobfuscate This** whenever you want that saved recipe to execute.

Ordinary F5 and generic pseudocode refresh use the active project runtime. A
saved recipe does not silently alter those refreshes. `Deobfuscate This`
temporarily installs the recipe for one synchronous decompile and restores the
project runtime afterward.

## Typed state-CFF threshold

The state-machine CFF pass exposes `min_state_constant` as a typed integer
option. Set it in the recipe editor when a function's dispatcher state values
fall below the project default. Validation rejects booleans, negative values,
and integers wider than 64 bits before execution or persistence.

## What the Workbench reports

The runtime row distinguishes these cases:

- `project-runtime`: ordinary refresh and execution use the project pipeline;
- `saved-recipe-explicit`: ordinary refresh uses the project pipeline and
  `Deobfuscate This` has a current saved recipe;
- `saved-recipe-blocked`: the project remains active and the saved recipe is
  stale or invalid.

The Rule scope row lists the public operations and each expanded implementation
rule by pipeline and maturity. Every excluded rule has a stable reason such as
an EA selector, missing tag, inference suppression, or direct hint suppression.
Unknown/stale rule names referenced by ephemeral analysis are reported and do
not instantiate absent rules.

## Persistence and identity

Recipes and tags use a compound identity: database identity, project name, and
function address. The function fingerprint is stored in the recipe payload and
checked when loading. Keeping it outside the primary key makes code drift a
visible stale-recipe error instead of making the record disappear.

The default IDB-local netnode backend travels with the IDB and is not erased by
log cleanup. The optional SQLite backend uses the same compound identity, so
multiple databases and projects can share a file safely on macOS, Linux, or
Windows. Configure that advanced backend with `function_recipe_backend` and
`function_recipe_storage`.

Legacy unnamespaced recipes, private-rule overrides, notes, and persisted
active inference are intentionally not adopted: their database ownership is
not provable and retaining them would recreate a competing configuration
model.

## Decision tradeoff

Applying saved recipes automatically on every F5 would currently require
stopping and restarting global D810 state from Hex-Rays callbacks. That is
re-entrant and could leak one function's configuration into another. Explicit
`Deobfuscate This` activation is less magical, but it preserves an atomic,
testable install/decompile/restore boundary.
