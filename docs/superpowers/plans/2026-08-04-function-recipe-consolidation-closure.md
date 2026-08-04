# Function Recipe Consolidation Closure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make saved recipes the only durable public function override, make their explicit execution semantics unambiguous, produce effective rule decisions from the execution evaluator, and scope durable function data by database and project identity.

**Architecture:** A compound `FunctionStorageLocator` keys recipes and tags in both persistence backends. `RuleScopeService` keeps only tags, project selectors, and ephemeral hint policy; a shared decision function powers both active-rule selection and Workbench explanation. Saved recipes continue to run atomically through `Deobfuscate This`, while UI copy explicitly distinguishes that action from ordinary F5.

**Tech Stack:** Python 3.13, immutable dataclasses/enums, SQLite, IDA netnodes, config-v2 runtime projection, Qt/IDA adapters, pytest, Docker-based IDA system tests.

## Global Constraints

- Work only in `/Users/mahmoud/src/idapro/d810/.worktrees/lrea-portable-cfg-case-producer` on `diff/lrea-portable-cfg-case-producer`.
- Write each behavior test first and observe the expected failure before production edits.
- Preserve project EA/tag selectors and ephemeral analysis-derived rule suppressions.
- Remove persisted private-rule overrides and persisted active-inference operator state.
- Keep the IDB-local netnode as the default backend on macOS, Linux, and Windows.
- Use `tools/scripts/run_system_tests_docker.sh` for native IDA system tests.
- Do not add architecture-rule or import-linter ignores.
- Record migration decisions and user-facing semantics in repository documentation.

---

### Task 1: Scoped function persistence and legacy state removal

**Files:**
- Modify: `src/d810/core/persistence.py`
- Modify: `src/d810/core/__init__.py`
- Modify: `src/d810/backends/hexrays/evidence/caching.py`
- Modify: `src/d810/manager/function_recipe_runtime.py`
- Modify: `src/d810/manager/rule_scope_runtime.py`
- Modify: `src/d810/manager/manager.py`
- Modify: `tests/unit/core/test_persistence.py`
- Modify: `tests/unit/core/test_function_recipe_persistence.py`
- Modify: `tests/unit/manager/test_function_recipe_runtime.py`
- Modify: `tests/unit/manager/test_rule_scope_runtime.py`

**Interfaces:**
- Produces: `FunctionStorageLocator(database_identity: str, project_name: str, function_addr: int)`.
- Produces: locator-based `set/get/clear_function_recipe` and `set/get_function_tags` storage methods.
- Consumes: `D810Manager._database_identity` and the current project name.
- Removes: `FunctionRuleConfig`, `set/get/clear_function_rules`, `should_run_rule`, and persisted active-inference storage methods.

- [x] **Step 1: Add failing storage tests for compound identity**

  Add tests that save two recipes and two tag sets at the same EA under distinct
  locators and assert both are independently readable and clearable. Add contract
  assertions that the legacy function-rule and active-inference methods are absent.

- [x] **Step 2: Run the persistence tests and verify RED**

  Run:

  ```bash
  PYTHONPATH=src:tests pyenv exec python -m pytest -q \
    tests/unit/core/test_persistence.py \
    tests/unit/core/test_function_recipe_persistence.py \
    tests/unit/manager/test_function_recipe_runtime.py \
    tests/unit/manager/test_rule_scope_runtime.py
  ```

  Expected: failures for the missing locator API and surviving legacy methods.

- [x] **Step 3: Implement locator-based netnode and SQLite storage**

  Add the frozen locator dataclass and use a canonical JSON or tuple-derived key
  in netnode state. Create SQLite v2 tables with:

  ```sql
  PRIMARY KEY (database_identity, project_name, function_addr)
  ```

  Keep `function_fingerprint` in the recipe row. Do not adopt unnamespaced
  recipes or tags because their database/project ownership is unknown.

- [x] **Step 4: Remove legacy storage and adapter methods**

  Remove private-rule and persisted-inference methods from the storage protocol,
  both backends, and the Hex-Rays caching adapter. Remove their exports and
  statistics labels.

- [x] **Step 5: Thread locators through the runtimes**

  Give `FunctionRecipeRuntime` and `RuleScopeRuntime` database-identity
  providers. Build locators internally for recipe and tag calls so operator
  APIs never assemble storage keys.

- [x] **Step 6: Run the persistence tests and verify GREEN**

  Re-run Step 2 and require zero failures.

### Task 2: One explainable internal rule-scope evaluator

**Files:**
- Modify: `src/d810/core/rule_scope.py`
- Modify: `src/d810/manager/rule_scope_runtime.py`
- Modify: `src/d810/manager/manager.py`
- Modify: `src/d810/passes/inferences.py`
- Modify: `tests/unit/core/test_rule_scope.py`
- Modify: `tests/unit/core/test_rule_scope_apply_hints.py`

**Interfaces:**
- Produces: `EffectiveRuleDecision` and `EffectiveRuleScopeReport`.
- Produces: `RuleScopeService.explain_effective_scope(...) -> EffectiveRuleScopeReport`.
- Consumes: configured rule objects, function EA/tags, and ephemeral hint state.
- Removes: persisted overlay precedence and `ApplyHintsResult.user_overrides` naming.

- [x] **Step 1: Write failing decision tests**

  Cover active, selector allowlist, selector denylist, tag-any, tag-all,
  inference suppression, direct hint suppression, and
  unknown policy rule names. Assert stable reason values and maturity anchors.

- [x] **Step 2: Write a failing parity test**

  For each declared maturity, assert that active decisions from
  `explain_rules()` have exactly the same rule names as `get_active_rules()`.

- [x] **Step 3: Run the rule-scope tests and verify RED**

  Run:

  ```bash
  PYTHONPATH=src:tests pyenv exec python -m pytest -q \
    tests/unit/core/test_rule_scope.py \
    tests/unit/core/test_rule_scope_apply_hints.py
  ```

- [x] **Step 4: Implement the pure evaluator**

  Implement one function returning a `RuleScopeDecision` for a rule, maturity,
  function, tags, and policy. Use it from both reporting and active selection.
  Unknown rule names are the policy names absent from all expanded rule sets.

- [x] **Step 5: Remove persisted overlay behavior**

  Make the runtime overlay provider supply tags only. Remove function-rule
  mutation methods/events and global persisted inference. Keep ephemeral
  `apply_hints()` inference and suppression, renaming conflict output to
  `selector_conflicts`.

- [x] **Step 6: Run the rule-scope tests and verify GREEN**

  Re-run Step 3 and require zero failures.

### Task 3: Workbench effective-scope report

**Files:**
- Modify: `src/d810/manager/workbench_models.py`
- Modify: `src/d810/manager/workbench_service.py`
- Modify: `src/d810/manager/manager.py`
- Modify: `src/d810/ui/workbench_logic.py`
- Modify: `tests/unit/manager/test_workbench_models.py`
- Modify: `tests/unit/manager/test_workbench_service.py`
- Modify: `tests/unit/ui/test_workbench_logic.py`
- Modify: `tests/unit/ui/test_workbench_comparison.py`
- Modify: `tests/unit/ui/test_workbench_workflow_logic.py`
- Modify: `tests/unit/manager/test_deobfuscation_case_workflow.py`

**Interfaces:**
- Consumes: `EffectiveRuleScopeReport` for the projected project or saved-recipe rule objects.
- Produces: immutable Workbench decision summaries without private mutation fields.

- [x] **Step 1: Write failing Workbench model and rendering tests**

  Assert that the snapshot exposes active/excluded counts, decisions by
  pipeline/maturity, reason codes, and unknown names. Assert that old
  `function_enabled_rules`, `function_disabled_rules`, notes, and persisted
  inference fields are absent.

- [x] **Step 2: Run the Workbench tests and verify RED**

  Run:

  ```bash
  PYTHONPATH=src:tests pyenv exec python -m pytest -q \
    tests/unit/manager/test_workbench_models.py \
    tests/unit/manager/test_workbench_service.py \
    tests/unit/ui/test_workbench_logic.py \
    tests/unit/ui/test_workbench_comparison.py \
    tests/unit/ui/test_workbench_workflow_logic.py
  ```

- [x] **Step 3: Project the exact rule set being described**

  For config-v2 runtimes, expand the selected runtime project through the hook
  bridge and pass those instruction/block rules to `RuleScopeService`. For
  non-config-v2 projects, use the manager's live configured rule objects.

- [x] **Step 4: Replace the stored-state summary**

  Replace `RuleScopeSummary` fields with function tags, inference names,
  decisions, and unknown names. Render one line per decision with pipeline,
  maturity, active/excluded state, reason code, and detail.

- [x] **Step 5: Run the Workbench tests and verify GREEN**

  Re-run Step 2 and require zero failures.

### Task 4: Explicit saved-recipe execution semantics

**Files:**
- Modify: `src/d810/manager/function_recipe_activation.py`
- Modify: `src/d810/manager/workbench_models.py`
- Modify: `src/d810/manager/deobfuscation_case_service.py`
- Modify: `src/d810/manager/deobfuscation_case_workflow.py`
- Modify: `src/d810/ui/workbench_logic.py`
- Modify: `src/d810/ui/workbench_recipe_panel.py`
- Modify: `src/d810/ui/workbench_recipe_commands.py`
- Modify: `tests/unit/manager/test_function_recipe_activation.py`
- Modify: `tests/unit/manager/test_deobfuscation_case_service.py`
- Modify: `tests/unit/manager/test_deobfuscation_case_workflow.py`
- Modify: `tests/unit/ui/test_workbench_logic.py`
- Modify: `tests/unit/ui/test_workbench_recipe_panel_contract.py`
- Modify: `tests/unit/ui/test_workbench_recipe_commands.py`

**Interfaces:**
- Produces: stable execution-scope values `project-runtime`, `saved-recipe-explicit`, and `saved-recipe-blocked`.
- Produces: UI copy `Ordinary F5: project runtime` and `Deobfuscate This: saved function recipe`.

- [x] **Step 1: Write failing semantics tests**

  Assert the new scope values, runtime detail copy, Recipe Composer button label
  `Save for Deobfuscate This`, and save result text explaining that ordinary F5
  remains project-scoped.

- [x] **Step 2: Run the activation/UI tests and verify RED**

  Run:

  ```bash
  PYTHONPATH=src:tests pyenv exec python -m pytest -q \
    tests/unit/manager/test_function_recipe_activation.py \
    tests/unit/manager/test_deobfuscation_case_service.py \
    tests/unit/manager/test_deobfuscation_case_workflow.py \
    tests/unit/ui/test_workbench_logic.py \
    tests/unit/ui/test_workbench_recipe_panel_contract.py \
    tests/unit/ui/test_workbench_recipe_commands.py
  ```

- [x] **Step 3: Implement explicit execution naming and copy**

  Rename scope values without changing the atomic context-manager execution.
  Update every user-visible summary and action result to distinguish ordinary
  project refresh from explicit recipe execution.

- [x] **Step 4: Run the activation/UI tests and verify GREEN**

  Re-run Step 2 and require zero failures.

### Task 5: User documentation and legacy surface contract

**Files:**
- Modify: `README.md`
- Delete: `docs/features/function-rules.md`
- Create: `docs/features/function-recipes.md`
- Modify: `docs/superpowers/specs/2026-08-04-function-recipe-overrides-design.md`
- Modify: `tests/unit/ui/test_actions_migration.py`

**Interfaces:**
- Produces: one documented public function configuration workflow.
- Consumes: the execution-scope and persistence decisions from Tasks 1-4.

- [x] **Step 1: Replace the legacy documentation**

  Rewrite README around Recipe Composer and `Deobfuscate This`. Add the recipe
  guide with persistence identity, stale validation, `min_state_constant`,
  ordinary-F5 semantics, and effective-scope diagnostics. Remove the legacy
  guide and correct the earlier design document's compatibility wording.

- [x] **Step 2: Verify documentation and the public action contract**

  Review the rendered Markdown, search production documentation for stale
  `Function rules...` instructions and false precedence claims, and run:

  ```bash
  PYTHONPATH=src:tests pyenv exec python -m pytest -q \
    tests/unit/ui/test_actions_migration.py
  ```

### Task 6: Full verification, graph update, commit, and push

**Files:**
- Modify: `graphify-out/*` through `graphify update .`

**Interfaces:**
- Consumes: all completed tasks.
- Produces: current regression, architecture, runtime, graph, and delivery evidence.

- [x] **Step 1: Run the consolidated focused suites**

  Run every test file touched in Tasks 1-5 together with `PYTHONPATH=src:tests
  pyenv exec python -m pytest -q`.

- [x] **Step 2: Run the full unit suite**

  ```bash
  PYTHONPATH=src:tests pyenv exec python -m pytest tests/unit/ -q
  ```

- [x] **Step 3: Run formatting, compilation, and architecture checks**

  ```bash
  ruff check src tests
  PYTHONPATH=src:tests pyenv exec python -m compileall -q src tests
  sg scan --config sgconfig.yml --report-style short
  PYTHONPATH=src lint-imports --config .importlinter
  git diff --check
  ```

  Changed-file Ruff and format checks, compilation, ast-grep, import-linter,
  and `git diff --check` are green. The repository-wide unconfigured
  `ruff check src tests` remains a known baseline with 937 unrelated/vendor
  findings; it is recorded rather than expanded into this feature branch.

- [x] **Step 4: Run the native IDA Docker regression**

  ```bash
  tools/scripts/run_system_tests_docker.sh test \
    -w lrea-portable-cfg-case-producer -- \
    tests/system/runtime/test_rule_scope_manager_events.py \
    tests/system/runtime/hexrays/test_pass_pipeline_integration.py -q
  ```

- [x] **Step 5: Update Graphify and inspect repository state**

  ```bash
  graphify update .
  git status --short --branch
  git diff --stat
  ```

- [x] **Step 6: Commit and push**

  Stage only scoped files, commit with a closure-focused message, push
  `diff/lrea-portable-cfg-case-producer`, and verify the remote branch contains
  the new commit.
