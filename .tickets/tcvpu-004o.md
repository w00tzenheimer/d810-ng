---
id: tcvpu-004o
status: closed
deps: [tcvpu-nyvc, tcvpu-z1b4]
links: []
created: 2026-07-15T23:52:25Z
type: feature
priority: 1
assignee: w00tzenheimer
parent: d81-38ha
tags: [ui, recipes, config-v2]
---
# Slice 4: registered-pass Recipe Composer

Compose registered passes and explanatory owned transforms into ordered function recipes with pure draft operations, contract preflight, apply-once, and sibling function-recipe persistence.

## Acceptance Criteria

Catalog and draft use stable registered pass IDs; add/remove/enable/disable/reorder are deterministic; transforms are explanatory unless registered; unknown passes/options/contracts block execution; a full typed recipe is saved separately from existing function rule/tag/note records and reuses their identity/invalidation path; project-profile save remains disabled until Slice 5.

## Completion evidence (2026-07-16)

Implemented the thin dockable Recipe Composer over IDA-independent services and
pure presentation logic. The catalog exposes registered stable pass IDs and
explains owned transforms without making transforms independently runnable.
Immutable draft operations cover add/remove/enable/disable/reorder/reset and
structured options. Mutation-free live fact collection feeds chained contract
preflight; unknown passes, invalid options, missing contracts, invalid order,
and stale generations fail closed.

Function recipes persist as sibling records and leave the existing function
rule/tag/note override unchanged. Apply-once and ordinary Deobfuscate both reuse
the saved recipe, temporarily activate an in-memory config-v2 runtime, refresh
exactly once, and restore the original manager runtime. The main Workbench now
projects a valid saved recipe as the effective `function-recipe` pipeline and
shows blocked persistence/provenance errors explicitly. Project-profile save is
visible but disabled until Slice 5.

Live Docker/XQuartz acceptance used the copied DLL database
`.tmp/ida-gui/libobfuscated.dll.2026-06-03.docker.vGm8D6.i64` through the
loopback MCP endpoint. The named-command audit is
`.tmp/ida-gui/automation-0a26502ee9d75ad062bcee3a90757fa1.json`; the final
post-review Qt widget capture is
`.tmp/ida-gui/live-recipe-slice4-post-review.png`. The live checks proved:

- D810 started normally before the named action, with no bootstrap reload;
- the Recipe action was enabled on the current Workbench generation;
- the six-pass effective project recipe analyzed successfully with no
  diagnostics and enabled Apply/Save Function;
- a one-pass `jump-fixer` recipe saved successfully and immediately changed the
  main Workbench scope/pass list to `function-recipe` / `jump-fixer`;
- invalid `jump-fixer` options were rejected without changing revision 5;
- Apply invoked the recipe lifecycle exactly once and stale-generation Apply
  invoked it zero times;
- saved-recipe ordinary Deobfuscate activated `jump-fixer`, then restored the
  original runtime with the manager still started;
- rule/tag/note override values were byte-for-byte unchanged after saving the
  sibling function recipe; and
- clearing the recipe restored the six-pass project pipeline and left no saved
  test recipe.

The final review also added regression coverage proving body/setup failures
restore the original runtime, a failed restoration propagates instead of being
logged as success, and a registry-valid but cross-pass-invalid saved recipe is
rendered `function-recipe-blocked` instead of breaking Workbench refresh. A
fresh post-review Apply-once smoke restored the exact original runtime path and
left the manager started with no saved test recipe.

Verification: `157 passed` focused; full unit suite `6130 passed, 29 skipped, 9
warnings, 162 subtests passed`; ast-grep clean; import-linter `13 kept, 0
broken`; `git diff --check` clean; graphify updated. The canonical and copied
database SHA-256 remained
`61678430e3fe08f6bb23f41752faa22b57c805e8261277660933d01e3c046dab`.
