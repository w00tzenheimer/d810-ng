# Strict Pass and Execution Configuration Implementation Plan

**Execution status (2026-08-04):** Implemented and committed on
`diff/lrea-portable-cfg-case-producer`. Plan-scoped unit, architecture, schema,
and native IDA tests pass. The branch-wide native suite retains 24
unflattening/mutation failures outside those plan-scoped slices; see the
completion record below. The branch was
not pushed because final delivery remains approval-gated.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace public rule configuration and hidden SQLite selection with one strict model: registered passes plus typed options, pass-owned stable transform IDs, private execution stages, and an explicit application-level recipe-storage setting.

**Architecture:** `PipelineConfig` becomes a strict pass schema with no generic `rules` member or compatibility aliases. `PassRegistry` expands each pass into stable execution-stage descriptors that bind privately to existing Hex-Rays optimizer objects; `ExecutionScopeService` evaluates those descriptors for both execution and diagnostics. Recipe storage is parsed from one typed application setting and atomically opened or reopened independently of project configuration.

**Tech Stack:** Python 3.13, immutable dataclasses and enums, JSON config-v2, SQLite, IDA 9 netnodes, Qt/IDA adapters, pytest, Docker-based IDA system tests, ast-grep, import-linter, Graphify.

## Global Constraints

- Work only in `/Users/mahmoud/src/idapro/d810/.worktrees/lrea-portable-cfg-case-producer` on `diff/lrea-portable-cfg-case-producer`.
- Do not add runtime migration, compatibility aliases, silent field adoption, or fallback from invalid SQLite configuration to netnode.
- The shipped default recipe backend is IDB-local netnode on macOS, Linux, and Windows.
- SQLite configuration is application-global and must never be read from `ProjectConfiguration.additional_configuration`.
- Public durable execution identity consists of `pass_id` plus pass-owned stable `transform_id` or `stage_id`; Python `*Rule` names remain private.
- A family expands to a canonical pass sequence and is not a second runtime selection namespace.
- Existing non-config-v2 project loading is outside this change; config-v2 and saved recipes are strict and may not mix former spellings.
- Write each behavior test first and observe the expected failure before production edits.
- Run native IDA verification only through `tools/scripts/run_system_tests_docker.sh`.
- Do not add ast-grep or import-linter ignores.
- Update Graphify after source changes.

---

### Task 1: Strict application-level recipe storage configuration

**Files:**
- Create: `src/d810/manager/function_storage_config.py`
- Modify: `src/d810/conf/options.json`
- Modify: `src/d810/core/config.py`
- Modify: `src/d810/manager/rule_scope_runtime.py`
- Modify: `src/d810/manager/manager.py`
- Modify: `src/d810/manager/state.py`
- Modify: `src/d810/ui/ida_ui.py`
- Create: `tests/unit/manager/test_function_storage_config.py`
- Modify: `tests/unit/manager/test_rule_scope_runtime.py`
- Modify: `tests/unit/manager/test_function_recipe_runtime.py`
- Modify: `tests/unit/ui/test_ida_ui_layout_contract.py`

**Interfaces:**
- Produces: `FunctionRecipeStorageBackend(str, Enum)` with `NETNODE` and `SQLITE`.
- Produces: `FunctionRecipeStorageConfig(backend: FunctionRecipeStorageBackend, path: pathlib.Path | None)`.
- Produces: `parse_function_recipe_storage(payload: object, *, log_dir: pathlib.Path) -> FunctionRecipeStorageConfig`.
- Produces: `D810Manager.reconfigure_function_storage(config: FunctionRecipeStorageConfig) -> None`.
- Removes: `function_recipe_backend` and string-valued `function_recipe_storage` from the project-runtime configuration path.

- [ ] **Step 1: Write strict parser tests**

  Add tests with these exact cases:

  ```python
  def test_missing_storage_setting_uses_netnode():
      parsed = parse_function_recipe_storage(None, log_dir=Path("/tmp/d810-logs"))
      assert parsed == FunctionRecipeStorageConfig(
          FunctionRecipeStorageBackend.NETNODE,
          None,
      )

  def test_sqlite_requires_absolute_non_log_path(tmp_path):
      log_dir = tmp_path / "logs"
      valid = tmp_path / "state" / "recipes.sqlite3"
      assert parse_function_recipe_storage(
          {"backend": "sqlite", "path": str(valid)},
          log_dir=log_dir,
      ).path == valid.resolve()

      with pytest.raises(FunctionStorageConfigurationError, match="absolute"):
          parse_function_recipe_storage(
              {"backend": "sqlite", "path": "recipes.sqlite3"},
              log_dir=log_dir,
          )
      with pytest.raises(FunctionStorageConfigurationError, match="log directory"):
          parse_function_recipe_storage(
              {"backend": "sqlite", "path": str(log_dir / "recipes.sqlite3")},
              log_dir=log_dir,
          )

  @pytest.mark.parametrize(
      "payload",
      ["/tmp/recipes.sqlite3", {"backend": "sqlite"}, {"backend": "netnode", "path": "/tmp/x"}],
  )
  def test_partial_or_former_storage_shapes_are_rejected(payload, tmp_path):
      with pytest.raises(FunctionStorageConfigurationError):
          parse_function_recipe_storage(payload, log_dir=tmp_path / "logs")
  ```

- [ ] **Step 2: Run the parser tests and verify RED**

  ```bash
  PYTHONPATH=src:tests pyenv exec python -m pytest -q \
    tests/unit/manager/test_function_storage_config.py
  ```

  Expected: import failure because the strict parser does not exist.

- [ ] **Step 3: Implement the parser and shipped default**

  Add this public shape to `src/d810/conf/options.json`:

  ```json
  "function_recipe_storage": {
    "backend": "netnode"
  }
  ```

  Validate exact keys. Resolve SQLite paths with `Path.expanduser().resolve(strict=False)` and reject `candidate == log_dir` or `candidate.is_relative_to(log_dir)` after resolving both paths. Do not inspect or infer a backend from a path string.

- [ ] **Step 4: Write runtime lifecycle tests**

  Assert that manager startup opens the parsed backend, applying a changed application setting closes the prior backend and opens the new backend exactly once, project selection does not reopen or select storage, and invalid SQLite configuration leaves `storage is None` without opening netnode.

- [ ] **Step 5: Remove project-driven storage selection and implement atomic reconfiguration**

  Pass the parsed application setting from `D810State` to `D810Manager`. Change `RuleScopeRuntime.initialize_storage()` to consume `FunctionRecipeStorageConfig`, not raw manager kwargs. Close the prior store only after the replacement store has opened successfully; on validation/open failure close no healthy existing store during a settings preview, and surface the error in the configuration UI.

- [ ] **Step 6: Add the Plugin Configuration controls**

  Add a backend combo with `IDB-local netnode` and `SQLite file`, a file picker enabled only for SQLite, and validation before `D810Configuration.save()`. After a successful save, call `D810Manager.reconfigure_function_storage(...)` so restart is unnecessary.

- [ ] **Step 7: Run storage and UI tests and verify GREEN**

  ```bash
  PYTHONPATH=src:tests pyenv exec python -m pytest -q \
    tests/unit/manager/test_function_storage_config.py \
    tests/unit/manager/test_rule_scope_runtime.py \
    tests/unit/manager/test_function_recipe_runtime.py \
    tests/unit/ui/test_ida_ui_layout_contract.py
  ```

- [ ] **Step 8: Commit the storage contract**

  ```bash
  git add src/d810/conf/options.json src/d810/core/config.py \
    src/d810/manager/function_storage_config.py \
    src/d810/manager/rule_scope_runtime.py src/d810/manager/manager.py \
    src/d810/manager/state.py src/d810/ui/ida_ui.py \
    tests/unit/manager/test_function_storage_config.py \
    tests/unit/manager/test_rule_scope_runtime.py \
    tests/unit/manager/test_function_recipe_runtime.py \
    tests/unit/ui/test_ida_ui_layout_contract.py
  git commit -m "refactor: make function storage configuration explicit"
  ```

### Task 2: Stable pass-owned execution-stage descriptors

**Files:**
- Create: `src/d810/passes/execution_stages.py`
- Modify: `src/d810/passes/registry.py`
- Modify: `src/d810/passes/operational_config_v2.py`
- Modify: `src/d810/passes/constant_simplification.py`
- Modify: `src/d810/passes/legacy_flow_rules.py`
- Modify: `src/d810/passes/cleanup_family_adapter.py`
- Modify: `src/d810/passes/state_machine_spine.py`
- Modify: `src/d810/manager/workbench_recipe_models.py`
- Modify: `src/d810/manager/workbench_recipe_service.py`
- Create: `tests/unit/passes/test_execution_stages.py`
- Modify: `tests/unit/passes/test_pass_registry.py`
- Modify: `tests/unit/passes/test_operational_config_v2.py`
- Modify: `tests/unit/manager/test_workbench_recipe_service.py`

**Interfaces:**
- Produces: `ExecutionPipeline` enum with `INSTRUCTION`, `FLOW`, and `CTREE`.
- Produces: `ExecutionStageDescriptor(pass_id: str, stage_id: str, pipeline: ExecutionPipeline, implementation_name: str)`.
- Produces: `canonical_transform_id(implementation_name: str) -> str`.
- Produces: `PassRegistry.stages_for(pass_id: str) -> tuple[ExecutionStageDescriptor, ...]`.
- Replaces: string-only `PassRegistry.transforms_for()` metadata.

- [ ] **Step 1: Write stage-identity tests**

  Require these identities:

  ```python
  assert canonical_transform_id("AddXor_Rule_1") == "add-xor-1"
  assert canonical_transform_id("FoldReadonlyDataRule") == "fold-readonly-data"

  stages = registry.stages_for("constant-simplification")
  assert tuple(stage.stage_id for stage in stages) == (
      "fold-readonly-data",
      "fold-constant-subtree",
      "forward-constants",
  )
  assert {stage.pass_id for stage in stages} == {"constant-simplification"}
  ```

  Add collision tests proving registration fails when two implementation names normalize to the same public ID within one pass.

- [ ] **Step 2: Run descriptor tests and verify RED**

  ```bash
  PYTHONPATH=src:tests pyenv exec python -m pytest -q \
    tests/unit/passes/test_execution_stages.py \
    tests/unit/passes/test_pass_registry.py
  ```

- [ ] **Step 3: Implement descriptor registration**

  Change `register()` and `register_configured()` to accept `stages: tuple[ExecutionStageDescriptor, ...]`. Validate non-empty IDs, owning pass equality, and uniqueness. Keep `implementation_name` private to the registry and hook bridge; catalog models expose `stage_id` and display labels only.

- [ ] **Step 4: Register canonical stages for every operational pass**

  Use pass ID as stage ID for one-stage flow passes. Register the three constant-simplification stages explicitly. Register each state-CFF native pass as its own stage. Rename `legacy_flow_rules.py` in a later task only after all imports use descriptors; at this point remove `legacy_rule` from catalog metadata but preserve execution behavior.

- [ ] **Step 5: Run registry and catalog tests and verify GREEN**

  ```bash
  PYTHONPATH=src:tests pyenv exec python -m pytest -q \
    tests/unit/passes/test_execution_stages.py \
    tests/unit/passes/test_pass_registry.py \
    tests/unit/passes/test_operational_config_v2.py \
    tests/unit/manager/test_workbench_recipe_service.py
  ```

- [ ] **Step 6: Commit stable execution identities**

  ```bash
  git add src/d810/passes src/d810/manager/workbench_recipe_models.py \
    src/d810/manager/workbench_recipe_service.py \
    tests/unit/passes/test_execution_stages.py \
    tests/unit/passes/test_pass_registry.py \
    tests/unit/passes/test_operational_config_v2.py \
    tests/unit/manager/test_workbench_recipe_service.py
  git commit -m "refactor: register stable pass execution stages"
  ```

### Task 3: Port MBA selection to typed transform options

**Files:**
- Create: `src/d810/passes/mba_transform_options.py`
- Modify: `src/d810/passes/mba_simplify.py`
- Modify: `src/d810/passes/pipeline_v2_hook_bridge.py`
- Modify: `src/d810/manager/workbench_recipe_models.py`
- Modify: `src/d810/manager/workbench_recipe_service.py`
- Modify: `src/d810/ui/workbench_recipe_logic.py`
- Create: `tools/migrations/rewrite_config_v2_transforms.py`
- Modify: every `src/d810/conf/*config_v2_canary.json` containing `mba-simplify`
- Create: `tests/unit/passes/test_mba_transform_options.py`
- Modify: `tests/unit/passes/test_mba_simplify.py`
- Modify: `tests/unit/passes/test_pipeline_v2_hook_bridge.py`
- Modify: `tests/unit/ui/test_workbench_recipe_logic.py`

**Interfaces:**
- Produces: `MbaSimplifyOptions(transform_ids: tuple[str, ...], transform_options: Mapping[str, Mapping[str, object]])`.
- Produces: `mba_transform_id(implementation_name: str) -> str` using the canonical stage normalizer.
- Produces: `parse_mba_simplify_options(config: PipelineConfig, registry: PassRegistry) -> MbaSimplifyOptions`.
- Removes: MBA dependence on `PipelineConfig.rules`.

- [ ] **Step 1: Write typed-option tests**

  Cover ordered selection, unknown transform IDs, duplicate IDs, options targeting an unselected transform, and implementation mapping:

  ```python
  config = PipelineConfig(
      pass_id="mba-simplify",
      options={
          "transforms": ["add-xor-1", "add-ollvm-1"],
          "transform_options": {"add-ollvm-1": {"max_depth": 6}},
      },
  )
  adapter = build_mba_simplify_pass(config)
  assert adapter.transform_ids == ("add-xor-1", "add-ollvm-1")
  assert adapter.implementation_names == ("AddXor_Rule_1", "Add_OllvmRule_1")
  ```

- [ ] **Step 2: Run MBA tests and verify RED**

  ```bash
  PYTHONPATH=src:tests pyenv exec python -m pytest -q \
    tests/unit/passes/test_mba_transform_options.py \
    tests/unit/passes/test_mba_simplify.py
  ```

- [ ] **Step 3: Implement typed MBA options and private binding**

  Preserve order exactly. Resolve public IDs through the pass registry and pass only private implementation names into the existing Hex-Rays capability request. Do not accept an implementation name in `options.transforms`.

- [ ] **Step 4: Add and dry-run the repository-only rewrite tool**

  The tool must accept `--check` and `--write`. It rewrites bundled JSON only; it is not imported by D810 and does not migrate user files at runtime. Verify first:

  ```bash
  PYTHONPATH=src pyenv exec python tools/migrations/rewrite_config_v2_transforms.py \
    --check src/d810/conf
  ```

  Expected before conversion: non-zero with a list of bundled files containing `rules`.

- [ ] **Step 5: Rewrite bundled MBA configs and inspect semantic parity**

  ```bash
  PYTHONPATH=src pyenv exec python tools/migrations/rewrite_config_v2_transforms.py \
    --write src/d810/conf
  git diff -- src/d810/conf
  ```

  For every rewritten pass, assert that resolving the new transform IDs yields the exact ordered private implementation list from the parent commit.

- [ ] **Step 6: Update Recipe Composer language**

  Replace catalog and detail fields named `owned_rules` with `transform_ids`. Display `transforms:` and stable IDs; never display the private implementation name in the public catalog.

- [ ] **Step 7: Run MBA, hook bridge, recipe, and rewrite tests and verify GREEN**

  ```bash
  PYTHONPATH=src:tests pyenv exec python -m pytest -q \
    tests/unit/passes/test_mba_transform_options.py \
    tests/unit/passes/test_mba_simplify.py \
    tests/unit/passes/test_pipeline_v2_hook_bridge.py \
    tests/unit/manager/test_workbench_recipe_service.py \
    tests/unit/ui/test_workbench_recipe_logic.py
  PYTHONPATH=src pyenv exec python tools/migrations/rewrite_config_v2_transforms.py \
    --check src/d810/conf
  ```

- [ ] **Step 8: Commit the transform model and bundled conversion**

  ```bash
  git add src/d810/passes src/d810/manager src/d810/ui/workbench_recipe_logic.py \
    src/d810/conf tools/migrations/rewrite_config_v2_transforms.py \
    tests/unit/passes tests/unit/manager/test_workbench_recipe_service.py \
    tests/unit/ui/test_workbench_recipe_logic.py
  git commit -m "refactor: replace MBA rule selection with transforms"
  ```

### Task 4: Delete config-v2 compatibility fields and legacy adapter options

**Files:**
- Modify: `src/d810/passes/pass_pipeline.py`
- Modify: `src/d810/passes/registry.py`
- Rename: `src/d810/passes/legacy_flow_rules.py` to `src/d810/passes/hook_transform_passes.py`
- Modify: `src/d810/passes/operational_config_v2.py`
- Modify: `src/d810/passes/pipeline_config_parser.py`
- Modify: `src/d810/passes/pipeline_v2_hook_bridge.py`
- Modify: `src/d810/passes/state_machine_options.py`
- Modify: `src/d810/passes/state_machine_spine.py`
- Modify: `src/d810/manager/config_v2_edit_models.py`
- Modify: `src/d810/manager/config_v2_editing.py`
- Modify: all bundled `src/d810/conf/*config_v2_canary.json`
- Modify: `tests/unit/passes/test_pass_pipeline.py`
- Modify: `tests/unit/passes/test_pipeline_config_parser.py`
- Modify: `tests/unit/passes/test_pipeline_v2_hook_bridge.py`
- Modify: `tests/unit/passes/test_state_machine_options.py`
- Modify: `tests/unit/manager/test_config_v2_editing.py`
- Modify: `tests/unit/ui/test_project_config_ollvm_regression.py`

**Interfaces:**
- Removes: `RuleSelection`, `PipelineConfig.rules`, `PassSpec.rules`, `ConfigV2EditableField.PASS_RULES`.
- Removes: aliases `pass`, top-level contract aliases, ignored `migration`, and unknown config fields.
- Removes: `legacy_rule`, `legacy_rule_options`, and `native_pipeline` options from config-v2.
- Produces: strict `PipelineConfig.from_dict()` accepting only canonical `to_dict()` fields.

- [ ] **Step 1: Replace compatibility-success tests with rejection tests**

  Add exact cases:

  ```python
  @pytest.mark.parametrize(
      ("payload", "message"),
      [
          ({"pass": "jump-fixer"}, "unknown field: pass"),
          ({"pass_id": "mba-simplify", "rules": {}}, "unknown field: rules"),
          ({"pass_id": "jump-fixer", "migration": {}}, "unknown field: migration"),
          ({"pass_id": "jump-fixer", "scope": "block"}, "unknown field: scope"),
      ],
  )
  def test_config_v2_rejects_former_or_unknown_fields(payload, message):
      with pytest.raises(PipelineConfigError, match=message):
          PipelineConfig.from_dict(payload)
  ```

  Add state-CFF tests proving `legacy_rule_options` is rejected and direct `min_state_constant` remains valid across the complete spine.

- [ ] **Step 2: Run strict schema tests and verify RED**

  ```bash
  PYTHONPATH=src:tests pyenv exec python -m pytest -q \
    tests/unit/passes/test_pass_pipeline.py \
    tests/unit/passes/test_pipeline_config_parser.py \
    tests/unit/passes/test_state_machine_options.py
  ```

- [ ] **Step 3: Remove `RuleSelection` and make parsing exact**

  Define one `_PIPELINE_CONFIG_FIELDS` set matching `PipelineConfig.to_dict()`. Reject `set(payload) - _PIPELINE_CONFIG_FIELDS` before parsing. Require `pass_id`. Remove compatibility construction of contract data from top-level aliases.

- [ ] **Step 4: Remove adapter-owned legacy options**

  Let registry metadata determine the private implementation for one-stage hook passes. Rename adapter types from `LegacyFlowRule*` to `HookTransform*`. `build_hook_transform_pass()` accepts the pass config and registry descriptor; public options contain only semantic pass options.

- [ ] **Step 5: Collapse state-CFF to the typed option shape**

  Remove the migrated-option branch from `state_machine_cff_options_from_config()` and `replace_state_machine_cff_options()`. Ensure all five spine entries agree on `min_state_constant`; reject disagreement and partial spines.

- [ ] **Step 6: Canonicalize every bundled config-v2 document**

  Serialize parsed configs through `PipelineConfig.to_dict()` after Task 3's transform conversion. Remove ignored migration metadata. Keep source legacy project JSON files untouched because they use the separate loader.

- [ ] **Step 7: Remove project-editor rule serialization**

  Delete `PASS_RULES` and its serializer. Project config editing operates on ordered passes and typed pass/family options only.

- [ ] **Step 8: Run strict schema, bundled config, and editing tests and verify GREEN**

  ```bash
  PYTHONPATH=src:tests pyenv exec python -m pytest -q \
    tests/unit/passes/test_pass_pipeline.py \
    tests/unit/passes/test_pipeline_config_parser.py \
    tests/unit/passes/test_pipeline_v2_hook_bridge.py \
    tests/unit/passes/test_state_machine_options.py \
    tests/unit/manager/test_config_v2_editing.py \
    tests/unit/ui/test_project_config_ollvm_regression.py
  ```

  Then require zero matches:

  ```bash
  ! rg -n '"pass"\s*:|"rules"\s*:|legacy_rule|legacy_rule_options|native_pipeline|"migration"\s*:' \
    src/d810/conf/*config_v2_canary.json
  ```

- [ ] **Step 9: Commit strict config-v2**

  ```bash
  git add src/d810/passes src/d810/manager/config_v2_edit_models.py \
    src/d810/manager/config_v2_editing.py src/d810/conf \
    tests/unit/passes tests/unit/manager/test_config_v2_editing.py \
    tests/unit/ui/test_project_config_ollvm_regression.py
  git commit -m "refactor: remove rule compatibility from config v2"
  ```

### Task 5: Replace rule scope with pass and stage execution scope

**Files:**
- Create: `src/d810/core/execution_scope.py`
- Delete: `src/d810/core/rule_scope.py`
- Rename: `src/d810/manager/rule_scope_runtime.py` to `src/d810/manager/function_storage_runtime.py`
- Modify: `src/d810/core/__init__.py`
- Modify: `src/d810/passes/inferences.py`
- Modify: `src/d810/passes/pass_pipeline.py`
- Modify: `src/d810/passes/analysis.py`
- Modify: `src/d810/passes/flow_hints.py`
- Modify: `src/d810/passes/runtime.py`
- Modify: `src/d810/passes/store.py`
- Modify: `src/d810/analyses/control_flow/models.py`
- Modify: `src/d810/manager/manager.py`
- Modify: `src/d810/manager/decompilation_lifecycle.py`
- Modify: `src/d810/hexrays/hooks/optinsn_adapter.py`
- Modify: `src/d810/hexrays/hooks/optblock_adapter.py`
- Rename: `tests/unit/core/test_rule_scope.py` to `tests/unit/core/test_execution_scope.py`
- Rename: `tests/unit/core/test_rule_scope_apply_hints.py` to `tests/unit/core/test_execution_scope_apply_hints.py`
- Rename: `tests/system/runtime/test_rule_scope_manager_events.py` to `tests/system/runtime/test_execution_scope_manager_events.py`
- Rename: `tests/system/runtime/test_instruction_rule_scope_consumption.py` to `tests/system/runtime/test_instruction_execution_scope_consumption.py`
- Modify: related preanalysis and lifecycle tests importing rule-scope types.

**Interfaces:**
- Produces: `FunctionTarget(include_eas, exclude_eas, tags_any, tags_all)` on `PipelineConfig`.
- Produces: `ExpandedExecutionStage(descriptor: ExecutionStageDescriptor, implementation: object, target: FunctionTarget, maturities: frozenset[int])`.
- Produces: `ExecutionAdjustment(target_kind: Literal["pass", "stage"], target_id: str, action: Literal["suppress", "override"], overrides: Mapping[str, object])`.
- Produces: `ExecutionScopeService.active_stages(...) -> tuple[ExpandedExecutionStage, ...]`.
- Produces: `ExecutionScopeService.explain(...) -> EffectiveExecutionReport`.
- Removes: `RuleDelta`, `RuleInferenceOverlay.enabled_rules`, `activate`, `suppress_rules`, and private rule-name selectors.

- [ ] **Step 1: Write execution-scope evaluator tests**

  Cover pass target include/exclude EAs, `tags_any`, `tags_all`, maturity, pass suppression, stage suppression, typed override, and unknown stable target. For every maturity assert:

  ```python
  active = service.active_stages(
      project_name="proj",
      idb_key="idb",
      func_ea=0x401000,
      pipeline=ExecutionPipeline.FLOW,
      maturity=maturity,
  )
  report = service.explain(
      project_name="proj",
      idb_key="idb",
      func_ea=0x401000,
      maturity=maturity,
  )
  assert {stage.descriptor.stage_id for stage in active} == {
      decision.stage_id
      for decision in report.decisions
      if decision.pipeline is ExecutionPipeline.FLOW and decision.active
  }
  ```

- [ ] **Step 2: Run execution-scope tests and verify RED**

  ```bash
  PYTHONPATH=src:tests pyenv exec python -m pytest -q \
    tests/unit/core/test_execution_scope.py \
    tests/unit/core/test_execution_scope_apply_hints.py
  ```

- [ ] **Step 3: Implement pass/stage evaluation and parity reporting**

  Compile `PipelineConfig.target` and expanded descriptors, not attributes read from private optimizer objects. Use one pure evaluator for execution and explanation. Reason values are `active`, `pass-not-targeted`, `ea-excluded`, `missing-tag-any`, `missing-tag-all`, `wrong-maturity`, `inference-suppressed`, and `hint-suppressed`.

- [ ] **Step 4: Port analysis hints to stable targets**

  Rename `DeobfuscationHints.suppress_rules` to `suppress_stages`. Change `unflattening_inference()` to suppress a registered stable stage ID. Remove `activate`; an inference cannot instantiate work absent from the recipe/project. Bump the analysis-hints table/schema key and ignore former persisted hint rows rather than translating private names.

- [ ] **Step 5: Bind hook adapters through expanded stages**

  Keep optimizer objects private. Hook adapters ask `ExecutionScopeService` for active expanded stages, then execute their `implementation` objects. Run-later scheduling carries `(pass_id, stage_id)` and resolves it through the current expansion instead of carrying a rule name.

- [ ] **Step 6: Separate storage metadata from execution scope**

  Rename the runtime that owns recipes/tags and storage invalidation to `FunctionStorageRuntime`. The execution-scope service receives tags through a narrow provider and does not own persistence.

- [ ] **Step 7: Run core, preanalysis, hook, and lifecycle tests and verify GREEN**

  ```bash
  PYTHONPATH=src:tests pyenv exec python -m pytest -q \
    tests/unit/core/test_execution_scope.py \
    tests/unit/core/test_execution_scope_apply_hints.py \
    tests/unit/preanalysis/test_runtime.py \
    tests/unit/preanalysis/test_runtime_integration.py \
    tests/unit/manager/test_decompilation_lifecycle.py \
    tests/system/runtime/test_execution_scope_manager_events.py \
    tests/system/runtime/test_instruction_execution_scope_consumption.py
  ```

- [ ] **Step 8: Commit execution scope**

  ```bash
  git add src/d810/core src/d810/passes src/d810/analyses \
    src/d810/manager src/d810/hexrays/hooks tests/unit/core \
    tests/unit/preanalysis tests/unit/manager \
    tests/system/runtime/test_execution_scope_manager_events.py \
    tests/system/runtime/test_instruction_execution_scope_consumption.py
  git commit -m "refactor: scope execution by passes and stages"
  ```

### Task 6: Replace rule-centric project and Workbench UI

**Files:**
- Rename: `src/d810/ui/rule_tree.py` to `src/d810/ui/pass_tree.py`
- Rename: `src/d810/ui/rule_tree_logic.py` to `src/d810/ui/pass_tree_logic.py`
- Modify: `src/d810/ui/ida_ui.py`
- Modify: `src/d810/ui/project_config_logic.py`
- Modify: `src/d810/ui/workbench_logic.py`
- Modify: `src/d810/ui/workbench_recipe_logic.py`
- Modify: `src/d810/ui/workbench_recipe_panel.py`
- Modify: `src/d810/manager/project_runtime.py`
- Modify: `src/d810/manager/workbench_models.py`
- Modify: `src/d810/manager/workbench_service.py`
- Modify: `src/d810/core/stats.py`
- Rename: `tests/unit/ui/test_rule_tree_logic.py` to `tests/unit/ui/test_pass_tree_logic.py`
- Rename: `tests/unit/ui/test_rule_tree_contract.py` to `tests/unit/ui/test_pass_tree_contract.py`
- Modify: project-config, Workbench, statistics, and canvas UI tests.

**Interfaces:**
- Produces: `EffectiveStageDecisionSummary(pass_id, stage_id, pipeline, maturities, active, reason, detail)`.
- Produces: `ExecutionScopeSummary(public_passes, function_tags, inference_names, decisions, unknown_targets)`.
- Removes: `EffectiveRuleDecisionSummary`, `RuleScopeSummary`, `owned_rules`, `enabled_rule_names`, and editable private rule widgets.

- [ ] **Step 1: Write public-model and rendering tests**

  Assert that the project tree contains pass nodes and pass-owned transform/stage children; only pass and supported transform selections are editable. Assert Workbench copy uses `Effective execution`, `pass`, `stage`, and `transform`, with no `Rule scope`, `rule firings`, or private `*Rule` names.

- [ ] **Step 2: Run UI tests and verify RED**

  ```bash
  PYTHONPATH=src:tests pyenv exec python -m pytest -q \
    tests/unit/ui/test_pass_tree_logic.py \
    tests/unit/ui/test_pass_tree_contract.py \
    tests/unit/ui/test_project_config_logic.py \
    tests/unit/ui/test_workbench_logic.py \
    tests/unit/ui/test_workbench_recipe_logic.py \
    tests/unit/manager/test_workbench_models.py \
    tests/unit/manager/test_workbench_service.py
  ```

- [ ] **Step 3: Replace the project rule tree**

  Build the tree from `PassCatalogEntry`, `transform_ids`, and execution-stage descriptors. Pass toggles edit the ordered pipeline. MBA child toggles edit `options.transforms`. Constant-simplification stages are visible diagnostics but read-only because the pass owns them atomically.

- [ ] **Step 4: Replace Workbench scope models and copy**

  Render decisions grouped by `pass_id`, then `stage_id`. Show active/excluded counts and exact maturity/reason details. Rename unknown rule names to unknown execution targets.

- [ ] **Step 5: Project statistics through stable identities**

  Keep low-level internal optimizer counters if required, but map them through the active stage registry before Workbench serialization. Public JSON and labels use `stage_matches` and `stage firings`; debug details may append `implementation=<private class>`.

- [ ] **Step 6: Run UI and Workbench tests and verify GREEN**

  Re-run Step 2 plus:

  ```bash
  PYTHONPATH=src:tests pyenv exec python -m pytest -q \
    tests/unit/ui/test_workbench_canvas_logic.py \
    tests/unit/ui/test_workbench_canvas_panel_contract.py \
    tests/unit/ui/test_workbench_recipe_panel_contract.py \
    tests/unit/manager/test_project_runtime.py
  ```

- [ ] **Step 7: Commit the public terminology and UI**

  ```bash
  git add src/d810/ui src/d810/manager src/d810/core/stats.py tests/unit/ui \
    tests/unit/manager
  git commit -m "refactor: expose passes and stages instead of rules"
  ```

### Task 7: Documentation and strict-surface audit

**Files:**
- Modify: `README.md`
- Modify: `docs/features/function-recipes.md`
- Modify: `docs/superpowers/specs/2026-08-04-function-recipe-consolidation-closure-design.md`
- Modify: `docs/superpowers/plans/2026-08-04-function-recipe-consolidation-closure.md`
- Modify: `tests/unit/ui/test_actions_migration.py`
- Create: `tests/unit/passes/test_no_public_rule_configuration.py`

**Interfaces:**
- Produces: one documented public model and an automated source/config audit.
- Records: the intentional rejection of former storage/config/recipe shapes.

- [ ] **Step 1: Write the public-surface audit test**

  Scan config-v2 fixtures, recipe serialization models, and user-facing UI strings. Fail on:

  ```python
  FORBIDDEN_CONFIG_KEYS = {"rules", "legacy_rule", "legacy_rule_options", "native_pipeline"}
  FORBIDDEN_PUBLIC_COPY = {"Rule scope", "Pass rule selection", "unknown/stale rule names"}
  ```

  The test must deliberately exclude internal optimizer modules where `Rule` is a valid implementation term.

- [ ] **Step 2: Run the audit test and verify RED**

  ```bash
  PYTHONPATH=src:tests pyenv exec python -m pytest -q \
    tests/unit/passes/test_no_public_rule_configuration.py
  ```

- [ ] **Step 3: Rewrite documentation**

  Document the pass/family/transform/stage taxonomy, typed SQLite application setting, immediate backend reconfiguration, failure behavior, stable diagnostics hierarchy, state-CFF family option, and `constant-simplification` atomic stages. Correct the old design and completed plan so they no longer claim SQLite compatibility or a public effective-rule report.

- [ ] **Step 4: Run documentation and surface audits and verify GREEN**

  ```bash
  PYTHONPATH=src:tests pyenv exec python -m pytest -q \
    tests/unit/passes/test_no_public_rule_configuration.py \
    tests/unit/ui/test_actions_migration.py
  ! rg -n 'function_recipe_backend|Rule scope|Pass rule selection|unknown/stale rule names' \
    README.md docs/features src/d810/ui src/d810/manager
  ```

- [ ] **Step 5: Commit documentation and audit gates**

  ```bash
  git add README.md docs src/d810 tests/unit/passes/test_no_public_rule_configuration.py \
    tests/unit/ui/test_actions_migration.py
  git commit -m "docs: define strict pass and recipe configuration"
  ```

### Task 8: Full verification and delivery evidence

**Files:**
- Modify: `graphify-out/*` through `graphify update .`

**Interfaces:**
- Consumes: Tasks 1-7.
- Produces: unit, architecture, native IDA, constant-simplification, graph, and Git evidence.

- [ ] **Step 1: Run all focused suites together**

  ```bash
  PYTHONPATH=src:tests pyenv exec python -m pytest -q \
    tests/unit/manager/test_function_storage_config.py \
    tests/unit/core/test_execution_scope.py \
    tests/unit/core/test_execution_scope_apply_hints.py \
    tests/unit/passes/test_execution_stages.py \
    tests/unit/passes/test_mba_transform_options.py \
    tests/unit/passes/test_mba_simplify.py \
    tests/unit/passes/test_pass_pipeline.py \
    tests/unit/passes/test_pipeline_config_parser.py \
    tests/unit/passes/test_pipeline_v2_hook_bridge.py \
    tests/unit/passes/test_state_machine_options.py \
    tests/unit/manager/test_config_v2_editing.py \
    tests/unit/manager/test_function_recipe_runtime.py \
    tests/unit/manager/test_workbench_service.py \
    tests/unit/ui/test_pass_tree_logic.py \
    tests/unit/ui/test_project_config_logic.py \
    tests/unit/ui/test_workbench_logic.py \
    tests/unit/ui/test_workbench_recipe_logic.py
  ```

- [ ] **Step 2: Run the full unit suite**

  ```bash
  PYTHONPATH=src:tests pyenv exec python -m pytest tests/unit/ -q
  ```

- [ ] **Step 3: Run source, schema, and architecture gates**

  ```bash
  ruff check src tests tools/migrations/rewrite_config_v2_transforms.py
  PYTHONPATH=src:tests pyenv exec python -m compileall -q src tests tools/migrations
  sg scan --config sgconfig.yml --report-style short
  PYTHONPATH=src lint-imports --config .importlinter
  git diff --check
  PYTHONPATH=src pyenv exec python tools/migrations/rewrite_config_v2_transforms.py \
    --check src/d810/conf
  ```

- [ ] **Step 4: Run native IDA execution-scope and pipeline tests**

  ```bash
  tools/scripts/run_system_tests_docker.sh test \
    -w lrea-portable-cfg-case-producer -- \
    tests/system/runtime/test_execution_scope_manager_events.py \
    tests/system/runtime/test_instruction_execution_scope_consumption.py \
    tests/system/runtime/hexrays/test_pass_pipeline_integration.py -q
  ```

- [ ] **Step 5: Re-run the constant-global semantic regression**

  ```bash
  tools/scripts/run_system_tests_docker.sh test \
    -w lrea-portable-cfg-case-producer -- \
    tests/system/runtime/test_constant_simplification_global_reads.py \
    tests/system/runtime/backends/hexrays/test_global_const_annotation.py -q
  ```

  Record the before/after pseudocode artifact already used for `const_globals.py` and require semantic output parity with the current branch while the configuration identity changes from private rule names to the `constant-simplification` pass and stable stages.

- [ ] **Step 6: Update Graphify and inspect the final diff**

  ```bash
  graphify update .
  git status --short --branch
  git diff --stat origin/diff/lrea-portable-cfg-case-producer...HEAD
  git log --oneline origin/diff/lrea-portable-cfg-case-producer..HEAD
  ```

- [ ] **Step 7: Final strictness audit**

  Require no public compatibility surface:

  ```bash
  ! rg -n 'function_recipe_backend|"rules"\s*:|legacy_rule|legacy_rule_options|native_pipeline' \
    src/d810/conf/*config_v2_canary.json docs/features/function-recipes.md
  ! rg -n 'Rule scope|Pass rule selection|unknown/stale rule names|owned_rules' \
    src/d810/ui src/d810/manager docs/features/function-recipes.md
  ```

- [ ] **Step 8: Commit Graphify output and push only after review approval**

  ```bash
  git add graphify-out
  git commit -m "chore: update graph for strict execution config"
  git push origin diff/lrea-portable-cfg-case-producer
  ```

## Completion record

- Focused strict-config suite: 208 passed.
- Full unit suite: 7,635 passed, 29 skipped, 162 subtests passed.
- Native execution-scope and pass-pipeline slice: 27 passed.
- Native constant-global and annotation slice: 12 passed.
- Full native system suite: 3,489 passed, 59 skipped, 9 deselected, 1 xfailed,
  24 failed. The two config/deferred-execution failures present before the final
  fixes are gone. Remaining failures are in existing computed-goto, DSL,
  Tigress, opaque-table/unflattening, cleanup-family, and semantic-fragment
  mutation coverage.
- Changed files are Ruff-clean. Full-tree Ruff remains red with 919 existing
  findings, primarily vendored code and unrelated legacy tests.
- `compileall`, ast-grep, import-linter, config-v2 migration check, strictness
  searches, and `git diff --check` pass.
- `graphify update .` completed successfully; it produced no tracked graph diff.
