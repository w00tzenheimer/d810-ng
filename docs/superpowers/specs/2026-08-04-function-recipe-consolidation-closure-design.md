# Function Recipe Consolidation Closure Design

## Goal

Finish the per-function configuration consolidation so that saved config-v2
recipes are the only durable operator-authored function override, internal rule
scope has one explainable precedence model, persistence cannot collide across
binaries that share an explicit SQLite file, and the UI and documentation say
exactly when a recipe executes.

## Decisions

### Saved recipes execute through `Deobfuscate This`

A saved recipe is the authoritative execution policy for `Deobfuscate This` on
its function. Ordinary F5 and generic pseudocode refresh continue to use the
active project runtime. The Workbench, Recipe Composer, action results, and
documentation must state both sides of that boundary.

This is selected over transparent ordinary-refresh activation because the live
implementation materializes a recipe by stopping the global D810 runtime,
installing a temporary project, performing one synchronous decompile, and then
restoring the project. Performing that swap from arbitrary Hex-Rays callbacks
would add re-entrant global-state mutation and could leak one function's recipe
into another decompilation.

The alternative with the best future semantics is a cache of immutable
per-function hook instances selected at decompilation entry. That requires a
larger runtime ownership redesign and is deliberately not hidden inside this
closure change.

Pros:

- Preserves the existing atomic activation and restoration boundary.
- Makes execution deterministic and testable.
- Prevents recipe state from leaking into unrelated functions.

Cons:

- Pressing F5 alone does not execute the saved recipe.
- Users must use the named D810 action for function-specific behavior.

### Remove durable private-rule operator state

Persisted function rule allowlists, denylists, notes, the manager mutation APIs,
and the persisted active-inference selector are removed. Function tags are
migrated into a dedicated scoped metadata store. Existing private-rule and
active-inference values are intentionally not migrated because retaining them
would preserve the competing configuration model this change removes.

`RuleScopeService` remains internal and owns:

- project rule selectors, including EA and tag selectors;
- function tags;
- ephemeral preanalysis inference selection and suppression;
- active-rule caching and effective-scope explanation.

Recipes own durable public pass selection and typed pass options.

Pros:

- There is one durable public function configuration model.
- The precedence contradiction between persisted overlays and inference
  filtering disappears.
- Stale private rule names cannot silently affect execution.

Cons:

- Existing private-rule overrides and persisted active inference are discarded.
- Low-level scripts using the removed manager/storage APIs must move to recipes
  or project selectors.

### One evaluator produces execution and explanations

Rule eligibility is evaluated by one pure decision function shared by
`get_active_rules()` and the Workbench report. Each decision includes pipeline,
rule name, maturity, active/excluded state, a stable reason code, and a human
explanation.

The precedence is:

1. The project or explicit recipe determines which rules are instantiated.
2. A project selector may require or reject a function EA or tags.
3. An ephemeral inference allowlist may narrow the instantiated set.
4. Ephemeral inference or direct hint suppressions may exclude a rule.
5. Rules surviving every gate are active.

`apply_hints()` resolves selector conflicts before it installs an inference, so
an explicit project whitelist/blacklist remains authoritative. The effective
report also lists inference or suppression rule names absent from the expanded
runtime as unknown; it never implies that inference can instantiate a globally
absent rule.

Pros:

- Reported and executed decisions cannot drift independently.
- Every exclusion has a machine-testable reason.
- Active rules are visible by maturity for both the project runtime and a saved
  recipe projection.

Cons:

- The decision model becomes a first-class internal API that must remain stable.
- Recipe projections must supply their expanded rule objects to the evaluator.

### Namespace durable function data

Function recipe and function tag records use a compound locator:

- database identity (`idb_key`);
- project name;
- function EA.

The function fingerprint remains in the recipe payload and is revalidated when
the record is projected. It is intentionally not part of the primary key: this
preserves a visible "stale fingerprint" diagnostic after bytes change instead
of making the recipe silently disappear.

The IDB-local netnode backend uses the same locator for uniform behavior. The
explicit SQLite backend receives a v2 recipe table with a compound primary key.
Unnamespaced recipe rows are not adopted because their binary ownership cannot
be proven safely.

Pros:

- Multiple binaries and projects can share one explicit SQLite file without
  overwriting same-EA recipes.
- Fingerprint drift remains observable.
- Netnode and SQLite implement the same storage contract.

Cons:

- Existing unnamespaced SQLite recipes are intentionally ignored.
- Database identity changes make prior records unreachable, which is safer than
  applying them to an uncertain database.

## User-visible model

The Recipe Composer exposes public registered pass IDs and typed options. Its
durable action is labelled `Save for Deobfuscate This`. The Workbench runtime
row reports both:

- `Ordinary F5: project runtime`;
- `Deobfuscate This: saved function recipe` when a current recipe exists.

The effective-scope row reports active and excluded expanded rules by pipeline
and maturity, with reason codes. It never offers private-rule mutation.

## Migration and safety

- Netnode state preserves recipes only after they are saved under the scoped
  locator. Legacy `function_rules` and `active_inference` payloads are removed;
  tags are copied into scoped metadata when their current database/project
  ownership is known.
- SQLite creates scoped function-tag and function-recipe tables. Legacy private
  rule and active-inference tables are dropped after tag migration.
- No migration guesses a database identity for an unnamespaced recipe.
- The explicit SQLite backend remains an advanced compatibility choice; the
  IDB-local netnode remains the safe default on macOS, Linux, and Windows.

## Verification

Tests must prove:

- ordinary refresh and explicit recipe execution are labelled distinctly;
- private-rule and persisted-inference mutation APIs are absent;
- selector, inference, hint suppression, unknown-rule, and active decisions use
  the expected reason codes;
- execution and explanation return the same active rules per maturity;
- same-EA recipes and tags coexist for two database/project locators in one
  SQLite file;
- fingerprint and project-path validation still blocks stale recipes;
- focused and full unit suites pass;
- architecture checks pass from this worktree;
- the relevant native IDA Docker system test passes through
  `tools/scripts/run_system_tests_docker.sh`;
- Graphify is updated after source changes.

## Rejected alternatives

1. **Keep the old APIs but hide their buttons.** Rejected because scripts,
   documentation, persisted rows, and the Workbench would continue to expose a
   second configuration model.
2. **Auto-apply recipes during every F5 via global runtime swapping.** Rejected
   because callback-time stop/start is re-entrant global mutation.
3. **Delete `RuleScopeService`.** Rejected because maturity-aware selectors,
   tags, and analysis-derived suppressions are valid internal execution policy.
4. **Key recipes by fingerprint.** Rejected because byte drift should surface as
   a stale saved recipe rather than look like no recipe was ever saved.
