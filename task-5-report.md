# Task 5 report: one canonical config-v2 project runtime

## Scope

This worktree implements Task 5 of the config-v2 final cutover. Runtime
activation now has one project identity and one compiled `ConfigV2HookSchedule`.
The legacy source-project/runtime-project selection path is gone from manager,
workbench, recipe, comparison, picker, and configuration-panel projections.

## Exact removals

- Removed `src/d810/core/config_v2_defaults.py` and
  `tests/unit/core/test_config_v2_defaults.py`.
- Removed the 21 transitional donor files from `src/d810/conf`:
  `bogus_loops_config_v2_canary.json`, `default_config_v2_canary.json`,
  `default_indirect_resolution_config_v2_canary.json`,
  `default_instruction_only_config_v2_canary.json`,
  `default_unflattening_approov_config_v2_canary.json`,
  `default_unflattening_approov_s1a_config_v2_canary.json`,
  `default_unflattening_ollvm_config_v2_canary.json`,
  `default_unflattening_tigress_engine_config_v2_canary.json`,
  `default_unflattening_tigress_engine_transition_facts_config_v2_canary.json`,
  `default_unflattening_tigress_indirect_config_v2_canary.json`,
  `eidolon_config_v2_canary.json`, `example_hodur_config_v2_canary.json`,
  `example_libobfuscated_abc_config_v2_canary.json`,
  `example_libobfuscated_config_v2_canary.json`,
  `example_libobfuscated_no_fixprecedessor_config_v2_canary.json`,
  `flatfold_config_v2_canary.json`, `hodur_flag2_config_v2_canary.json`,
  `hodur_flag2_s1a_config_v2_canary.json`,
  `hodur_flag2_with_fcp_config_v2_canary.json`,
  `hodur_glbopt2_only_config_v2_canary.json`, and
  `identity_call_config_v2_canary.json`.
- Repointed `rewrite_config_v2_transforms.py` at canonical `*.json` projects;
  it no longer depends on donor-file naming.

The historical donor payloads remain only in
`tools/migrations/data/known_config_v2_templates.json`, with the corresponding
identity/provenance catalogue in `tools/migrations/legacy_project_config.py`.
Those are offline migration evidence, not runtime presets or execution inputs.

## Canonical runtime behavior

- `D810State.current_project` is the sole active project identity.
- Removed `current_runtime_project`,
  `last_config_v2_default_selection`, and
  `last_pipeline_v2_hook_mode`.
- Renamed `last_pipeline_v2_hook_pass_ids` to `last_config_v2_pass_ids`.
- `ProjectRuntimeSnapshot` contains only `project` and
  `effective_pass_ids`.
- `ProjectConfigRef`, recipe drafts/overrides, comparison identities, output
  references, workbench snapshots, and UI rows carry one `project` identity.
- Every project activation compiles the complete typed schedule and snapshot
  before emitting the reload event, replacing state, or configuring rules.
  A malformed/legacy project therefore leaves the prior project, pass lists,
  schedule snapshot, and pass IDs active. The invalid-project diagnostic
  includes a copyable command such as:

  ```text
  python tools/migrations/migrate_project_config_v2.py --in-place /path/project.json
  ```

- Instruction and block bindings are installed in schedule-declared order;
  the legacy registry-order activation branch was removed.
- The configuration-panel disclosure is user-controlled; it no longer locks
  itself around a source/runtime identity divergence.

## Inventory audit

The retired runtime/default symbol scan is empty outside `tools/migrations`:

```text
config_v2_defaults
select_config_v2_default_project
ConfigV2DefaultSelection
current_runtime_project
last_config_v2_default_selection
last_pipeline_v2_hook_mode
last_pipeline_v2_hook_pass_ids
ProjectConfigMode
RuntimeConfigRef
```

No `*_config_v2_canary.json` files remain in `src/d810/conf`. The only literal
donor names are the classified migration catalogue/module noted above; tests
that must prove migration stripping construct the marker spelling dynamically
and do not create a runtime route.

## TDD evidence

- RED: `.tmp/task5_red_project_runtime.txt` records the pre-implementation
  failures for the canonical snapshot/clone contract.
- GREEN: `.tmp/task5_green_project_runtime_1.txt` records the focused manager
  contract after implementation.
- Focused Docker gate: `.tmp/task5_focused_docker.txt`, 73 passed.
- Final touched Docker gate from the main repository root:
  `.tmp/task5_touched_docker_final.txt`, 1112 passed, 118 warnings.
- Local manager/UI gate: 966 passed.
- Local migration/inventory/parser/pass gate: 268 passed, 5 expected contract
  vocabulary warnings.

The separately requested `tests/system/runtime/test_manager_native_preanalysis.py`
was also attempted in Docker. Its 18 failures are pre-existing failures in
tests that instantiate `D810Manager.__new__` without the `_started` state after
the earlier `fix(manager): detach stopped runtime owners` change; the failures
are unrelated to Task 5 and do not involve the changed project identity path.
The exact Task 5 state-loading system test is green in the final Docker gate.

Additional gates:

- Changed Python files: Ruff clean.
- `git diff --check`: clean.
- `sg scan --config sgconfig.yml --report-style short`: 14 kept, 0 broken.
- `PYTHONPATH=src lint-imports --config .importlinter`: passed.
- All 34 remaining bundled JSON projects parse successfully.
- `graphify update .`: completed; known graphify warnings are the existing
  zero-node JSON and two syntax-error sample warnings.

## Commit

Full commit hash: `98a54e288051c6ebddac74c532facb5648ca535e`
