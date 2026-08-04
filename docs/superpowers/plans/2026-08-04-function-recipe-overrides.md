# Function Recipe Overrides Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace public private-rule overrides with saved typed function recipes and add an atomic per-function state-CFF `min_state_constant` override.

**Architecture:** The Recipe Composer owns public per-function configuration. A typed state-CFF option model validates the threshold and a recipe-service operation updates the canonical five-pass spine atomically. Internal rule scoping remains available to runtime code, while default live persistence moves to an IDB-local netnode.

**Tech Stack:** Python 3, immutable dataclasses, config-v2 `PipelineConfig`, Qt/IDA adapters, pytest, IDA Docker system tests.

## Global Constraints

- Work only in `/Users/mahmoud/src/idapro/d810/.worktrees/lrea-portable-cfg-case-producer` on `diff/lrea-portable-cfg-case-producer`.
- Preserve compatibility with existing config-v2 state-machine spine payloads.
- Use saved function recipes as the sole user-facing function override.
- Keep private rule scope available only as an internal runtime facility.
- Validate `min_state_constant` as a non-boolean integer from 0 through `2**64 - 1`.
- Apply the threshold to the complete canonical five-pass state-CFF spine or reject the edit.
- Use `tools/scripts/run_system_tests_docker.sh` for system tests.

---

### Task 1: Typed state-CFF option and atomic recipe edit

**Files:**
- Create: `src/d810/passes/state_machine_options.py`
- Modify: `src/d810/manager/workbench_recipe_service.py`
- Modify: `src/d810/manager/workbench_recipe_models.py`
- Test: `tests/unit/passes/test_state_machine_options.py`
- Test: `tests/unit/manager/test_workbench_recipe_service.py`

**Interfaces:**
- Produces: `StateMachineCffOptions(min_state_constant: int)` and `RecipeService.replace_state_cff_options(draft, options)`.
- Consumes: `STATE_MACHINE_NATIVE_PASS_IDS` and existing `PipelineConfig.options` compatibility payloads.

- [ ] **Step 1: Write failing tests for integer validation and compatibility extraction**

Cover default extraction, direct options, legacy nested options, boolean/type
rejection, negative values, and values greater than `2**64 - 1`.

- [ ] **Step 2: Run the focused option tests and confirm they fail because the typed API is absent**

Run: `PYTHONPATH=src pyenv exec python -m pytest -q tests/unit/passes/test_state_machine_options.py`

- [ ] **Step 3: Implement the minimal typed option parser and compatible serializer**

The parser must preserve unrelated legacy rule options when replacing only the
threshold and must never silently coerce strings or booleans.

- [ ] **Step 4: Write failing recipe-service tests for whole-spine atomic replacement**

Assert that all five canonical stages receive the same threshold and that a
partial, duplicate, or reordered spine raises `RecipeEditError` without
returning a modified draft.

- [ ] **Step 5: Run the focused recipe tests and confirm the expected failures**

Run: `PYTHONPATH=src pyenv exec python -m pytest -q tests/unit/manager/test_workbench_recipe_service.py`

- [ ] **Step 6: Implement the minimal immutable recipe replacement operation**

Return one new draft revision only after all five replacement configs have
validated through the operational registry.

- [ ] **Step 7: Run both focused suites and confirm they pass**

Run: `PYTHONPATH=src pyenv exec python -m pytest -q tests/unit/passes/test_state_machine_options.py tests/unit/manager/test_workbench_recipe_service.py`

### Task 2: Function-recipe UI and private-rule control removal

**Files:**
- Modify: `src/d810/ui/workbench_recipe_commands.py`
- Modify: `src/d810/ui/workbench_recipe_panel.py`
- Modify: `src/d810/ui/workbench_workflow_logic.py`
- Modify: `src/d810/ui/workbench_commands.py`
- Modify: `src/d810/ui/workbench_panel.py`
- Modify: `src/d810/ui/actions/__init__.py`
- Modify: `src/d810/ui/pseudocode_actions.py`
- Modify: `src/d810/ui/stats_dialog.py`
- Modify: `src/d810/ui/stats_logic.py`
- Modify: `src/d810/manager/workbench_service.py`
- Modify: `src/d810/manager/state.py`
- Test: `tests/unit/ui/test_workbench_recipe_commands.py`
- Test: `tests/unit/ui/test_workbench_recipe_panel_contract.py`
- Test: `tests/unit/ui/test_workbench_workflow_logic.py`
- Test: `tests/unit/ui/test_actions_migration.py`
- Test: `tests/unit/ui/test_stats_logic.py`

**Interfaces:**
- Consumes: `RecipeService.replace_state_cff_options` through the manager/state adapter chain.
- Produces: a Recipe Composer state-CFF threshold edit and no public Function Rules/fired-rule override controls.

- [ ] **Step 1: Write failing adapter and UI-contract tests**

Assert that a typed state-CFF edit reaches the state adapter once, workflow
secondary actions contain Recipe but no private-rule override, builtin actions
do not register Function Rules, and stats logic exposes no fired-rule persistence
builder.

- [ ] **Step 2: Run the focused UI tests and confirm behavior-specific failures**

Run: `PYTHONPATH=src pyenv exec python -m pytest -q tests/unit/ui/test_workbench_recipe_commands.py tests/unit/ui/test_workbench_recipe_panel_contract.py tests/unit/ui/test_workbench_workflow_logic.py tests/unit/ui/test_actions_migration.py tests/unit/ui/test_stats_logic.py`

- [ ] **Step 3: Implement the typed Recipe Composer edit and remove public private-rule controls**

Keep internal manager rule-scope methods intact. Remove only action registration,
workbench commands/buttons, stats controls, and compatibility re-exports that
make private rule overrides user-facing.

- [ ] **Step 4: Re-run the focused UI tests**

Use the command from Step 2 and require zero failures.

### Task 3: IDB-local default persistence

**Files:**
- Modify: `src/d810/manager/rule_scope_runtime.py`
- Test: `tests/unit/manager/test_rule_scope_runtime.py`

**Interfaces:**
- Produces: default `backend="netnode"`, target `"$ d810.optimization_storage"`.
- Preserves: explicit SQLite configuration and injectable test storage factories.

- [ ] **Step 1: Write a failing test for the default storage backend and target**

Use an injected storage factory and assert it receives the netnode backend and
IDB-local node name when no function-storage config is supplied.

- [ ] **Step 2: Run the focused test and confirm the old SQLite/log-path behavior fails it**

Run: `PYTHONPATH=src pyenv exec python -m pytest -q tests/unit/manager/test_rule_scope_runtime.py`

- [ ] **Step 3: Change the default while preserving explicit SQLite behavior**

- [ ] **Step 4: Re-run the focused test suite**

Run the command from Step 2 and require zero failures.

### Task 4: Runtime and architecture verification

**Files:**
- Modify: `graphify-out/*` via `graphify update .`

**Interfaces:**
- Consumes: all changes from Tasks 1-3.
- Produces: fresh regression, system, architecture, and graph evidence.

- [ ] **Step 1: Run the consolidated unit regression set**

Run the recipe, hook bridge, function activation, rule scope, workbench, action,
and stats unit suites together.

- [ ] **Step 2: Run the state-CFF system tests through the repository Docker wrapper**

Run the narrow applicable state-CFF cases selected from the wrapper's supported
pytest arguments; do not invoke raw Docker or a shim.

- [ ] **Step 3: Run architecture checks from the target worktree**

Run: `sg scan --config sgconfig.yml --report-style short`

Run: `PYTHONPATH=src lint-imports --config .importlinter`

- [ ] **Step 4: Update Graphify and inspect the final diff/status**

Run: `graphify update .`

Run: `git diff --check`

Run: `git status --short --branch`

- [ ] **Step 5: Commit only the scoped implementation and tests**

Use an explicit path list so unrelated shared-worktree changes cannot enter the
commit. Do not push unless the user asks.
