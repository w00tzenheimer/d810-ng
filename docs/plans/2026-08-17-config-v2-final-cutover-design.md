# Config-v2 Final Cutover Design

## Status

Approved direction, written for final review before implementation.

## Problem

The repository completed a runtime-authority cutover in 2026: bundled legacy
project names are routed to `*_config_v2_canary.json` files and those v2
pipelines are compiled back into live Hex-Rays hook rules. That made config v2
authoritative, but left two project identities, three runtime modes, a routing
table, canary names, and public legacy `ins_rules`/`blk_rules` configuration
surfaces.

The result is operationally v2 but architecturally transitional. Tests and
fixtures can still name legacy presets, user projects can still run through a
legacy path, and the module called a "bridge" remains a required runtime
compiler.

## Goal

Make config v2 the only project configuration and unflattening execution path:

- every bundled canonical preset contains its own v2 pipeline;
- every unflattening fixture and test selects a canonical v2 configuration;
- legacy user projects have an explicit, fail-closed offline migration tool;
- runtime project loading rejects legacy rule-array projects;
- legacy/default routing, canary aliases, shadow/legacy modes, and their tests
  are deleted;
- Hex-Rays hook scheduling is compiled from typed v2 pass declarations only;
- the production state-machine implementation is no longer a public legacy
  block-rule registration.

This is a configuration and runtime-boundary cutover. It does not redesign the
state-machine recovery algorithms or the portable pass contracts.

## Non-goals

- Do not rewrite the unflattening algorithms.
- Do not require Egglog, Z3, Triton, or another solver for migration.
- Do not preserve automatic runtime fallback for unmigrated projects.
- Do not maintain parallel legacy and v2 execution paths.
- Do not delete a working Hex-Rays callback host until a v2-only host owns the
  same lifecycle, convergence, journal, and restart behavior.
- Do not migrate unrelated spike configurations unless they contain legacy
  rule arrays or are referenced by production tests or documentation.

## Repository Inventory and Terms

The cutover distinguishes four categories:

1. **Mapped bundled presets.** The source/runtime pairs currently listed in
   `CONFIG_V2_SUPPORTED_DEFAULT_MAPPINGS`. Their canonical source names remain
   stable, but their contents become the current canary contents.
2. **Standalone v2 presets.** Existing v2 files that are not aliases, such as
   `eidolon_v3_const_solve.json`, remain canonical.
3. **Fixture-only v2 presets.** Files used only by system fixtures keep a
   descriptive fixture name but lose `_config_v2_canary`.
4. **Legacy user projects.** External files containing active `ins_rules` or
   `blk_rules`. These are accepted only by the offline migration command, never
   by the plugin runtime after cutover.

The phrase **legacy unflattening code** means the public legacy configuration
and selection path: rule-array activation, legacy/shadow mode branches,
canary routing, and string lookup of `StateMachineCffUnflattener`. It does not
mean deleting the state-machine recovery implementation that the v2 native
spine currently invokes.

## Considered Approaches

### A. Keep routing and rename the canaries

This is low risk but does not meet the policy. Source/runtime dual identity and
the legacy execution branch remain.

### B. Canonicalize files but keep the legacy hook bridge unchanged

This removes duplicate JSON files but leaves `PipelineV2Mode.LEGACY`, runtime
fallback to rule arrays, and public legacy rule names. It is only a cosmetic
cutover.

### C. Canonicalize projects and replace the bridge with a v2-only runtime compiler

This is the selected approach. It removes dual identity and dual selection
while respecting the unavoidable Hex-Rays hook boundary. Typed pass configs
compile into private runtime hook bindings; project JSON never names optimizer
classes.

Deleting the state-machine host outright in the same step is rejected because
it currently owns optblock lifecycle, bounded reruns, generated-MBA restart
coordination, execution journals, and native pass-manager invocation. Those
responsibilities must survive the cutover.

## Canonical Project Schema

A loadable project must contain a non-empty `additional_configuration.pipeline_v2`
sequence. `pipeline_v2_mode` may be accepted only with the value `config-v2`
during the migration release; the runtime normalizes it away and neither
`legacy` nor `shadow-check` exists as a mode.

Canonical bundled JSON contains:

- `description`;
- no active legacy rule arrays;
- `additional_configuration.pipeline_v2` with current typed `pass_id` entries;
- existing non-rule project metadata that is still consumed by a typed pass or
  project service.

The serializer omits `ins_rules` and `blk_rules` for v2 projects. The loader may
parse empty arrays for one migration release, but any non-empty legacy array is
an actionable error that names the migration command.

## Offline Migration Tool

Add `tools/migrations/migrate_project_config_v2.py` with a reusable library
entry point and CLI:

```text
python tools/migrations/migrate_project_config_v2.py INPUT [--output OUTPUT]
python tools/migrations/migrate_project_config_v2.py INPUT --in-place
python tools/migrations/migrate_project_config_v2.py DIRECTORY --check
```

Properties:

- deterministic, JSON-only, and safe to run outside IDA;
- defaults to stdout unless `--output` or `--in-place` is explicit;
- refuses to overwrite without `--in-place` or an explicit output path;
- converts only known legacy rule portfolios using current typed pass
  factories and transform catalogues;
- expands `StateMachineCffUnflattener` into the complete ordered native spine;
- preserves recognized typed options and rejects unknown or lossy options;
- emits canonical v2 JSON, not a shadow or canary;
- `--check` exits nonzero and lists every legacy or malformed project without
  writing files;
- running it twice is byte-stable after normalized JSON formatting.

Unknown rule names, conflicting duplicate ownership, mixed v2/active-legacy
input, or options with no typed equivalent fail closed. The tool never silently
drops a rule.

## V2-only Runtime Compiler

Replace `pipeline_v2_hook_bridge.py` with a module named for its actual role,
`config_v2_hook_runtime.py`. It consumes parsed `PipelineConfig` values and
produces a `ConfigV2HookSchedule` of private instruction and block bindings.

The schedule compiler preserves declared pass order and typed option
validation. It contains adapters only where Hex-Rays requires an
`optinsn_t`/`optblock_t` callback. It has no `enabled` flag and no legacy-mode
return value: a valid project always compiles a v2 schedule or raises before
mutating manager state.

`D810State` therefore has one activation path:

```text
canonical project -> parse pipeline_v2 -> compile hook schedule
                  -> install private runtime bindings -> decompile
```

The following path is deleted:

```text
legacy source name -> default routing table -> canary runtime project
                   -> bridge enabled/disabled branch -> legacy rule arrays
```

The operational `FunctionPassManager` continues to execute portable native
passes. The Hex-Rays state-machine callback becomes a private v2 runtime host
selected by native-spine pass IDs, not a project-visible block rule named
`StateMachineCffUnflattener`. Its algorithm can initially remain in the current
module; registration and configuration identity are the boundary being
removed.

## Bundled Configuration Canonicalization

For every current default mapping:

1. Replace the source file contents with the runtime canary's v2 contents.
2. Rewrite descriptions and metadata so they no longer describe a canary,
   shadow, legacy source, or alternate runtime.
3. Update all tests, fixtures, documentation, scripts, and CLI defaults to the
   canonical source name.
4. Delete the paired `_config_v2_canary.json` file.

Fixture-only canaries are renamed to stable fixture names and all references
move atomically. No alias file or basename routing remains.

## Legacy Deletion

After canonical projects and the v2-only runtime compiler are green, delete:

- `src/d810/core/config_v2_defaults.py`;
- `CONFIG_V2_SUPPORTED_DEFAULT_MAPPINGS` and source/runtime selection state;
- `PipelineV2Mode.LEGACY` and `PipelineV2Mode.SHADOW_CHECK`;
- shadow comparison branches in the module pass manager and state-machine host;
- `pipeline_v2_hook_bridge.py` after consumers use the v2 runtime compiler;
- bundled `*_config_v2_canary.json` aliases;
- tests whose only purpose is routing, canary self-consistency, legacy fallback,
  or shadow parity;
- legacy unflattening JSON rule registrations and user-facing references to
  selecting `StateMachineCffUnflattener` directly.

Tests of the underlying state-machine algorithm remain, but are expressed as
native-spine/runtime-host tests rather than legacy-rule compatibility tests.

## Safety and Failure Behavior

- Project activation validates and compiles the entire v2 schedule before
  replacing the current project.
- An unmigrated project is skipped with a message containing the exact migration
  command; the previous valid project remains active.
- A missing pass registration, malformed option, incomplete native spine, or
  unsupported legacy migration is fatal for that project and never degrades to
  legacy execution.
- Migration writes use a temporary sibling plus atomic replace for `--in-place`.
- No runtime process automatically rewrites a user's project.

## Verification

### Unit gates

- migration acceptance for every supported legacy rule portfolio;
- rejection tests for unknown rules, lossy options, mixed schemas, and overwrite
  attempts;
- migration idempotence and deterministic output;
- every canonical bundled project parses and compiles through the v2 registry;
- schedule order and typed options match the pre-cutover runtime canaries;
- manager activation is transactional and has no legacy fallback;
- a repository inventory test rejects canary filenames, default-routing imports,
  legacy/shadow modes, and active legacy arrays in bundled configurations.

### Architecture gates

Run from the isolated worktree:

```bash
sg scan --config sgconfig.yml --report-style short
PYTHONPATH=src lint-imports --config .importlinter
```

No new ignores are permitted.

### System gates

Run from the main repository root through
`tools/scripts/run_system_tests_docker.sh`:

1. focused project loading and operational config-v2 tests;
2. all unflattening fixture tests whose configuration names changed;
3. OLLVM, Tigress indirect, Approov, Hodur, and constant-solver semantic/golden oracles;
4. the complete system suite.

The same fixture binary, function, configuration, and output oracle must be
used when comparing pre-cutover and post-cutover behavior. A passing unit suite
alone is insufficient.

## Completion Criteria

The cutover is complete only when all of the following are true:

- no shipped project routes to another project;
- no bundled canary alias remains;
- no runtime legacy or shadow mode remains;
- no active bundled `ins_rules` or `blk_rules` remain;
- every unflattening fixture selects a canonical v2 project;
- the offline migrator handles all formerly supported bundled legacy
  portfolios and fails closed for unsupported input;
- Hex-Rays hooks are scheduled solely from typed v2 passes;
- the repository inventory, unit, architecture, focused system, and full system
  gates pass;
- before/after unflattening outputs remain semantically equivalent for the
  representative OLLVM, Tigress, Approov, Hodur, and constant-solver fixtures.
