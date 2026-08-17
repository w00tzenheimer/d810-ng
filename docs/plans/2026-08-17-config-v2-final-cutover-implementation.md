# Config-v2 Final Cutover Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make config v2 the sole bundled project schema and sole unflattening activation path, with deterministic offline migration for legacy user projects and no canary routing, legacy fallback, or shadow mode left in the runtime.

**Architecture:** First preserve legacy conversion knowledge in an offline, fail-closed migration tool. Then turn the current hook bridge into an unconditional typed v2 schedule compiler, canonicalize every routed preset in place, collapse manager state to one project identity, and delete routing plus legacy/shadow branches. The production state-machine algorithm remains behind a private v2 runtime host because Hex-Rays still requires an `optblock_t` callback, but project JSON can no longer activate it by legacy class name.

**Tech Stack:** Python 3.13, dataclasses, argparse, JSON, D810 typed `PipelineConfig`/`PassRegistry`, Hex-Rays hook adapters, pytest, ast-grep, import-linter, IDA 9.4 Docker system tests.

**Spec:** `docs/plans/2026-08-17-config-v2-final-cutover-design.md`

## Global Constraints

- Config v2 is the only runtime project schema; do not add a compatibility fallback.
- Migration is offline, deterministic, JSON-only, and fail-closed.
- Unknown rules or options must never be silently dropped.
- Preserve declared v2 pass order and typed option validation.
- Preserve state-machine convergence, journal, restart, mutation-safety, and semantic behavior.
- No new ast-grep ignores or import-linter exceptions.
- Run local/worktree commands with `PYTHONPATH=src`.
- Run Docker tests from `/Users/mahmoud/src/idapro/d810`, never from the worktree.
- Do not claim completion from unit tests alone; representative unflattening system oracles and the full system suite are required.

---

## File Structure

### New files

- `tools/migrations/legacy_project_config.py` - IDA-free legacy document parser and deterministic current-v2 converter.
- `tools/migrations/migrate_project_config_v2.py` - CLI for stdout, explicit output, atomic in-place conversion, and directory checks.
- `tests/unit/tools/test_migrate_project_config_v2.py` - migration library and CLI regression tests.
- `src/d810/passes/config_v2_hook_runtime.py` - unconditional compiler from typed v2 configs to private Hex-Rays hook bindings.
- `tests/unit/passes/test_config_v2_hook_runtime.py` - schedule compiler contract tests.
- `tests/unit/architecture/test_config_v2_only_inventory.py` - repository-wide no-legacy/no-canary ratchet.

### Removed files

- `src/d810/core/config_v2_defaults.py`
- `src/d810/passes/pipeline_v2_hook_bridge.py`
- `tests/unit/core/test_config_v2_defaults.py`
- `tests/unit/passes/test_pipeline_v2_hook_bridge.py`
- all mapped `src/d810/conf/*_config_v2_canary.json` files after their contents replace canonical source files;
- fixture-only canary files after renaming to stable fixture names.

### Major modified areas

- `src/d810/core/config.py` - canonical v2 load/save validation and omission of legacy arrays.
- `src/d810/passes/pipeline_config_parser.py` - v2-only parser; no legacy/shadow enum.
- `src/d810/passes/module_pass_manager.py` - remove shadow/fallback scheduling.
- `src/d810/manager/state.py` - one project identity and unconditional schedule compilation.
- `src/d810/manager/project_runtime.py` - one v2 runtime snapshot shape.
- `src/d810/manager/function_recipe_activation.py`
- `src/d810/manager/config_v2_editing.py`
- `src/d810/manager/manager.py`
- `src/d810/manager/post_d810_runtime.py`
- `src/d810/ui/project_config_logic.py`
- `src/d810/ui/workbench_*.py`
- `src/d810/optimizers/microcode/flow/flattening/state_machine_cff_unflattener.py`
- bundled configuration JSON, tests, fixtures, documentation, and scripts returned by the final inventory query.

---

### Task 1: Build the fail-closed legacy migration library

**Files:**
- Create: `tools/migrations/legacy_project_config.py`
- Create: `tests/unit/tools/test_migrate_project_config_v2.py`
- Read as fixtures: `src/d810/conf/*.json`

**Interfaces:**
- Produces: `LegacyMigrationError`
- Produces: `migrate_legacy_document(document: Mapping[str, object], *, source_name: str) -> dict[str, object]`
- Produces: `is_canonical_v2_document(document: Mapping[str, object]) -> bool`
- Consumes later: Task 2 CLI and Task 7 bundled canonicalization check.

- [ ] **Step 1: Write failing migration characterization tests**

Create tests that load every source/runtime pair from the current
`CONFIG_V2_SUPPORTED_DEFAULT_MAPPINGS`, migrate the source, and compare the
ordered `pass_id` sequence plus typed options with the existing canary. Keep the
pair list in the test as explicit historical fixture data so Task 8 can delete
the runtime mapping module without weakening coverage.

```python
@pytest.mark.parametrize("source_name,canary_name", LEGACY_CANARY_PAIRS)
def test_mapped_bundled_portfolio_migrates_to_current_canary_semantics(
    source_name: str, canary_name: str
) -> None:
    migrated = migrate_legacy_document(
        _load(source_name), source_name=source_name
    )
    expected = _load(canary_name)
    assert _pipeline(migrated) == _pipeline(expected)
    assert migrated.get("ins_rules", []) == []
    assert migrated.get("blk_rules", []) == []
```

Add rejection tests for an unknown instruction rule, unknown block rule,
unsupported option, mixed active legacy/v2 document, conflicting duplicate
ownership, malformed rule entries, and empty output pipeline. Assert the error
contains the exact rule/field path.

- [ ] **Step 2: Run the focused test and verify RED**

From the main repository root:

```bash
./tools/scripts/run_system_tests_docker.sh test -w config-v2-final-cutover \
  -o config_v2_migrator_red.txt -- \
  tests/unit/tools/test_migrate_project_config_v2.py -q
```

Expected: collection/import failure because `legacy_project_config.py` does not
exist.

- [ ] **Step 3: Implement a table-driven converter**

Keep legacy vocabulary under `tools/migrations`, never under runtime `src`.
Use ordered rule projections:

```python
@dataclass(frozen=True, slots=True)
class LegacyRuleProjection:
    rule_name: str
    pass_ids: tuple[str, ...]
    project: Callable[[Mapping[str, object]], tuple[dict[str, object], ...]]


def migrate_legacy_document(
    document: Mapping[str, object], *, source_name: str
) -> dict[str, object]:
    legacy = _parse_legacy_document(document, source_name=source_name)
    if legacy.pipeline_v2 and (legacy.active_ins_rules or legacy.active_blk_rules):
        raise LegacyMigrationError("mixed v2 and active legacy configuration")
    entries = _project_instruction_portfolio(legacy.active_ins_rules)
    entries += _project_block_rules(legacy.active_blk_rules)
    if not entries:
        raise LegacyMigrationError("migration produced an empty pipeline_v2")
    return _canonical_document(legacy, entries)
```

The state-machine rule projection emits exactly
`STATE_MACHINE_NATIVE_PASS_IDS`; MBA instruction portfolios must use current
typed `mba-simplify` transforms and reject any rule without a current transform
or bundle owner. Preserve non-rule `additional_configuration` keys only when a
current pass/editor owns them.

- [ ] **Step 4: Verify GREEN and deterministic/idempotent output**

Run the same Docker test. Add assertions that canonical JSON serialization is
byte-stable and that migrating an already canonical document returns its
normalized equivalent without introducing legacy arrays.

- [ ] **Step 5: Commit**

```bash
git add tools/migrations/legacy_project_config.py \
  tests/unit/tools/test_migrate_project_config_v2.py
git commit -m "feat(config-v2): add fail-closed legacy project migrator"
```

---

### Task 2: Add the offline migration CLI and atomic writes

**Files:**
- Create: `tools/migrations/migrate_project_config_v2.py`
- Modify: `tests/unit/tools/test_migrate_project_config_v2.py`
- Reuse: `src/d810/core/project_config_persistence.py`

**Interfaces:**
- Consumes: `migrate_legacy_document(...)` from Task 1.
- Produces: `main(argv: Sequence[str] | None = None) -> int`
- Produces CLI modes: stdout, `--output`, `--in-place`, and directory `--check`.

- [ ] **Step 1: Add failing CLI tests**

Use `subprocess.run` against the real script. Cover stdout without writes,
explicit output, refusal to overwrite an existing destination, atomic in-place
replacement, directory check exit codes, and an error message that users can
copy from runtime diagnostics.

```python
def test_cli_defaults_to_stdout_without_writing(tmp_path: Path) -> None:
    source = _write_legacy(tmp_path / "project.json")
    result = _run_cli(str(source))
    assert result.returncode == 0
    assert json.loads(result.stdout)["additional_configuration"]["pipeline_v2"]
    assert json.loads(source.read_text())["blk_rules"]


def test_cli_check_reports_every_legacy_file(tmp_path: Path) -> None:
    _write_legacy(tmp_path / "a.json")
    _write_legacy(tmp_path / "b.json")
    result = _run_cli(str(tmp_path), "--check")
    assert result.returncode == 1
    assert "a.json" in result.stderr
    assert "b.json" in result.stderr
```

- [ ] **Step 2: Verify RED in Docker**

Run only `tests/unit/tools/test_migrate_project_config_v2.py`; expected failure
is the missing CLI.

- [ ] **Step 3: Implement argparse and atomic output**

Use `tempfile.mkstemp(dir=destination.parent)` plus `os.replace`. Reject
`--output` with directory input and reject `--output` combined with
`--in-place`/`--check`. Never rewrite from the plugin runtime.

```python
def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.check:
        return _check_directory(args.input)
    migrated = migrate_path(args.input)
    if args.in_place:
        _write_atomically(args.input, migrated)
    elif args.output is not None:
        _write_new(args.output, migrated)
    else:
        sys.stdout.write(_canonical_json(migrated))
    return 0
```

- [ ] **Step 4: Verify GREEN**

Run the focused Docker test and inspect that no `.tmp` sibling remains after
either success or forced validation failure.

- [ ] **Step 5: Commit**

```bash
git add tools/migrations/migrate_project_config_v2.py \
  tests/unit/tools/test_migrate_project_config_v2.py
git commit -m "feat(config-v2): add offline project migration CLI"
```

---

### Task 3: Replace the optional bridge with an unconditional v2 hook runtime compiler

**Files:**
- Create: `src/d810/passes/config_v2_hook_runtime.py`
- Create: `tests/unit/passes/test_config_v2_hook_runtime.py`
- Modify temporarily: `src/d810/passes/pipeline_v2_hook_bridge.py`
- Modify imports in: `src/d810/manager/config_v2_editing.py`
- Modify imports in: `src/d810/manager/function_recipe_activation.py`
- Modify imports in unit tests that inspect effective hook schedules.

**Interfaces:**
- Produces: `ConfigV2HookSchedule`
- Produces: `compile_config_v2_hook_schedule(project_config) -> ConfigV2HookSchedule`
- Produces: `config_v2_native_state_machine_configs(project_config) -> tuple[PipelineConfig, ...]`
- Produces: `requires_native_preanalysis_handlers(schedule: ConfigV2HookSchedule) -> bool`
- Replaces: `PipelineV2HookActivation.enabled` and `pipeline_v2_hook_activation(...)`.

- [ ] **Step 1: Write failing schedule compiler tests**

Port behavioral assertions from `test_pipeline_v2_hook_bridge.py`, but remove
all legacy-mode inertness tests. Assert a missing/empty v2 pipeline raises and
that compilation returns no `enabled` field.

```python
def test_compile_schedule_requires_nonempty_v2_pipeline() -> None:
    project = ProjectConfiguration(path=Path("legacy.json"))
    with pytest.raises(PipelineConfigError, match="migrate_project_config_v2"):
        compile_config_v2_hook_schedule(project)


def test_native_spine_compiles_private_runtime_host() -> None:
    schedule = compile_config_v2_hook_schedule(_v2_project(NATIVE_SPINE))
    assert schedule.configured_pass_ids == STATE_MACHINE_NATIVE_PASS_IDS
    assert schedule.native_state_machine_pass_ids == STATE_MACHINE_NATIVE_PASS_IDS
    assert [binding.implementation_name for binding in schedule.block_bindings] == [
        STATE_MACHINE_RUNTIME_HOST
    ]
```

- [ ] **Step 2: Verify RED**

Run `tests/unit/passes/test_config_v2_hook_runtime.py` in Docker; expect import
failure.

- [ ] **Step 3: Move and tighten the compiler**

Move the existing typed projection logic without changing pass behavior. Rename
rule-shaped fields to runtime bindings and remove optional mode handling:

```python
@dataclass(frozen=True, slots=True)
class ConfigV2HookSchedule:
    configured_pass_ids: tuple[str, ...]
    instruction_bindings: tuple[RuleConfiguration, ...] = ()
    block_bindings: tuple[RuleConfiguration, ...] = ()
    native_state_machine_pass_ids: tuple[str, ...] = ()


def compile_config_v2_hook_schedule(project_config) -> ConfigV2HookSchedule:
    configs = pipeline_configs_from_project_config(project_config)
    if not configs:
        raise PipelineConfigError(_migration_message(project_config.path))
    return _compile_configs(configs)
```

For this task, leave `pipeline_v2_hook_bridge.py` as a deprecated import-only
shim so intermediate commits remain green. It must contain no behavior and is
deleted in Task 8.

- [ ] **Step 4: Verify the compiler and affected portfolio tests**

Run:

```text
tests/unit/passes/test_config_v2_hook_runtime.py
tests/unit/passes/test_mba_portfolio_order.py
tests/unit/passes/test_rotate_idiom_recovery_pass.py
tests/unit/passes/test_finite_zero_set_predicate_pass.py
tests/unit/passes/test_modular_product_nonzero_pass.py
tests/unit/passes/test_mba_egglog.py
```

- [ ] **Step 5: Commit**

```bash
git add src/d810/passes/config_v2_hook_runtime.py \
  src/d810/passes/pipeline_v2_hook_bridge.py \
  src/d810/manager/config_v2_editing.py \
  src/d810/manager/function_recipe_activation.py tests/unit
git commit -m "refactor(config-v2): compile unconditional hook schedules"
```

---

### Task 4: Make project parsing and persistence v2-only

**Files:**
- Modify: `src/d810/core/config.py`
- Modify: `src/d810/passes/pipeline_config_parser.py`
- Modify: `src/d810/manager/config_v2_editing.py`
- Modify: `src/d810/core/project_config_persistence.py`
- Modify: `tests/unit/passes/test_pipeline_config_parser.py`
- Modify/Create: `tests/unit/core/test_project_configuration_v2.py`
- Modify: `tests/unit/manager/test_config_v2_editing.py`

**Interfaces:**
- Produces: `require_config_v2_project(project_config) -> tuple[PipelineConfig, ...]`
- Removes: `PipelineV2Mode`, `pipeline_v2_mode_from_project_config`, and shadow fields.
- Changes: `ProjectConfiguration.save()` omits `ins_rules` and `blk_rules` for canonical v2 projects.

- [ ] **Step 1: Add failing v2-only schema tests**

```python
def test_runtime_rejects_active_legacy_rules_with_migration_command(tmp_path: Path):
    project = ProjectConfiguration.from_file(_legacy_file(tmp_path))
    with pytest.raises(PipelineConfigError) as exc:
        require_config_v2_project(project)
    assert "migrate_project_config_v2.py" in str(exc.value)


def test_canonical_save_omits_legacy_arrays(tmp_path: Path):
    project = _v2_project(tmp_path / "project.json")
    project.save()
    document = json.loads(project.path.read_text())
    assert "ins_rules" not in document
    assert "blk_rules" not in document
```

Also test that empty legacy arrays remain readable for the migration release,
`pipeline_v2_mode="config-v2"` is tolerated and normalized away on save, and
`legacy`/`shadow-check` values are rejected.

- [ ] **Step 2: Verify RED**

Run the parser, project configuration, and editor tests in Docker.

- [ ] **Step 3: Implement one parser path**

Delete the enum and return typed configs directly:

```python
def require_config_v2_project(project_config) -> tuple[PipelineConfig, ...]:
    if _active_legacy_rules(project_config):
        raise PipelineConfigError(_migration_message(project_config.path))
    configs = pipeline_configs_from_project_config(project_config)
    if not configs:
        raise PipelineConfigError(_migration_message(project_config.path))
    return configs
```

Make the config-v2 editor validate `pipeline_v2` presence rather than an
execution mode. Preserve unknown non-rule fields losslessly.

- [ ] **Step 4: Verify GREEN and serialization round trips**

Run affected core/parser/editor tests twice: once on a canonical file without
legacy keys and once on an existing v2 file that still has empty legacy arrays.

- [ ] **Step 5: Commit**

```bash
git add src/d810/core/config.py src/d810/core/project_config_persistence.py \
  src/d810/passes/pipeline_config_parser.py \
  src/d810/manager/config_v2_editing.py tests/unit
git commit -m "refactor(config-v2): require canonical v2 project schema"
```

---

### Task 5: Collapse manager activation to one project and one schedule

**Files:**
- Modify: `src/d810/manager/state.py`
- Modify: `src/d810/manager/project_runtime.py`
- Modify: `src/d810/manager/function_recipe_activation.py`
- Modify: `src/d810/manager/workbench_service.py`
- Modify: `src/d810/manager/manager.py`
- Modify: `src/d810/manager/__init__.py`
- Modify: `src/d810/ui/ida_ui.py`
- Modify: `src/d810/ui/project_config_logic.py`
- Modify: `src/d810/ui/workbench_comparison.py`
- Modify: `src/d810/ui/workbench_logic.py`
- Modify: `src/d810/ui/workbench_panel.py`
- Modify: `src/d810/ui/workbench_workflow_logic.py`
- Modify: corresponding `tests/unit/manager/**` and `tests/unit/ui/**` files.

**Interfaces:**
- Changes: `ProjectRuntimeSnapshot` contains `project`, `effective_pass_ids`, and no source/runtime/routed/mode split.
- Changes: `D810State.current_project` is the sole active project identity.
- Removes: `current_runtime_project`, `last_config_v2_default_selection`, `last_pipeline_v2_hook_mode`.
- Renames: `last_pipeline_v2_hook_pass_ids` to `last_config_v2_pass_ids`.

- [ ] **Step 1: Write failing transactional activation tests**

Replace routing assertions with one-project assertions. Add a malformed legacy
project test proving the old project remains active and the diagnostic contains
the migration command.

```python
def test_activation_compiles_v2_before_replacing_current_project(state):
    previous = state.load_project(_index("default.json"))
    result = state.load_project(_index("legacy-user.json"))
    assert result is None
    assert state.current_project is previous
    assert "migrate_project_config_v2.py" in state.invalid_projects["legacy-user.json"]
```

- [ ] **Step 2: Verify RED**

Run manager project-runtime, function-recipe, workbench, and project-config UI
tests.

- [ ] **Step 3: Implement unconditional schedule activation**

Compile before state mutation:

```python
def _activate_project(self, *, project_index: int, project: ProjectConfiguration):
    schedule = compile_config_v2_hook_schedule(project)
    snapshot = build_project_runtime_snapshot(
        project=project,
        effective_pass_ids=schedule.configured_pass_ids,
    )
    self._install_schedule(schedule)
    self.current_project_index = project_index
    self.current_project = project
    self.current_project_runtime_snapshot = snapshot
    return project
```

Delete the legacy registry-order branch; schedule binding order is always
pipeline order. Update workbench projections to use one identity and remove UI
copy implying a source/runtime route.

- [ ] **Step 4: Verify GREEN**

Run all touched unit tests plus `tests/system/runtime/test_state_project_loading.py`
through Docker.

- [ ] **Step 5: Commit**

```bash
git add src/d810/manager src/d810/ui tests/unit/manager tests/unit/ui \
  tests/system/runtime/test_state_project_loading.py
git commit -m "refactor(config-v2): activate one canonical project runtime"
```

---

### Task 6: Remove shadow and legacy modes from pass execution and the state-machine host

**Files:**
- Modify: `src/d810/passes/module_pass_manager.py`
- Modify: `src/d810/optimizers/microcode/flow/flattening/state_machine_cff_unflattener.py`
- Modify: `src/d810/manager/post_d810_runtime.py`
- Modify: `src/d810/manager/manager.py`
- Modify: `src/d810/optimizers/microcode/flow/__init__.py`
- Modify: `tests/unit/passes/test_pass_pipeline.py`
- Modify: `tests/system/runtime/optimizers/microcode/flow/flattening/test_unflatten_bounded_rerun.py`
- Modify: `tests/system/runtime/optimizers/microcode/flow/flattening/test_canonical_semantic_evidence_capability.py`

**Interfaces:**
- Removes: `pipeline_v2_shadow_registry`, `require_pipeline_v2_shadow_match`, `_log_pipeline_v2_shadow`.
- Produces private constant: `STATE_MACHINE_RUNTIME_HOST` used only by the schedule compiler and hook registry.
- Keeps: native-spine `pipeline_v2_specs` execution through `FunctionPassManager`.

- [ ] **Step 1: Add failing private-host tests**

Assert canonical native-spine execution reaches the host through compiled pass
IDs and that no project-visible block rule name is needed. Replace tests that
construct shadow modes with direct native specs.

- [ ] **Step 2: Verify RED**

Run the two state-machine runtime test modules and relevant pass-manager tests
in Docker.

- [ ] **Step 3: Delete shadow branches and privatize host selection**

The host always consumes v2 specs:

```python
configured_specs = pass_specs_from_project_config(
    project_config, operational_config_v2_pass_registry()
)
native_specs = _effective_native_specs(configured_specs, family)
if not native_specs:
    raise PipelineConfigError("native state-machine spine is required")
self._pass_manager.run(..., pipeline_v2_specs=native_specs)
```

Remove `_last_pipeline_v2_mode`, shadow comparison logging, and all
`PipelineV2Mode` imports. Keep bounded rerun and generated-restart logic
unchanged.

- [ ] **Step 4: Verify GREEN and no mode references**

Run tests, then:

```bash
rg -n 'SHADOW_CHECK|PipelineV2Mode|require_pipeline_v2_shadow_match' src tests
```

Expected: no runtime/test matches except historical documentation being
deleted or revised in Task 8.

- [ ] **Step 5: Commit**

```bash
git add src/d810/passes/module_pass_manager.py \
  src/d810/optimizers/microcode/flow \
  src/d810/manager/manager.py src/d810/manager/post_d810_runtime.py \
  tests/unit tests/system/runtime/optimizers
git commit -m "refactor(unflatten): remove legacy and shadow execution modes"
```

---

### Task 7: Canonicalize bundled configurations and fixture names

**Files:**
- Modify: every `source_config` in the historical pair list from Task 1.
- Delete: every paired `runtime_config` ending `_config_v2_canary.json`.
- Rename: fixture-only canaries such as `dead_store_elimination_fixture_config_v2_canary.json` to stable `*_fixture.json` names.
- Modify: all references returned by `rg -n 'config_v2_canary.json|_config_v2_canary'`.
- Modify: README, HEADLESS docs, MASM fixture docs, CLI defaults, and test parameter tables.

**Interfaces:**
- Consumes: current canary contents as canonical source contents.
- Produces: stable canonical basenames with `pipeline_v2` as their runtime source.

- [ ] **Step 1: Write a failing canonical bundled-config test**

Create a test that iterates every bundled JSON except `options.json` and
explicit spike/catalogue data. For project files, require a nonempty typed
pipeline and prohibit active legacy arrays or canary metadata.

```python
def test_bundled_runtime_projects_are_canonical_v2():
    for path in bundled_runtime_projects():
        document = json.loads(path.read_text())
        assert document["additional_configuration"]["pipeline_v2"]
        assert not document.get("ins_rules")
        assert not document.get("blk_rules")
        assert "canary" not in path.name
        compile_config_v2_hook_schedule(ProjectConfiguration.from_file(path))
```

- [ ] **Step 2: Verify RED**

Run the new inventory test and confirm it reports the expected legacy/canary
set, not unrelated data files.

- [ ] **Step 3: Replace each mapped source atomically**

For each historical pair, copy semantic content from canary to canonical source,
remove empty legacy arrays and obsolete routing/canary metadata, preserve the
canonical description where accurate, and validate through the operational
registry before deleting the canary.

Use the Task 2 `--check` command on `src/d810/conf` and an explicit allowlist for
non-project JSON datasets. Do not edit JSON with ad-hoc regex replacement.

- [ ] **Step 4: Update all fixture and documentation references**

Replace names in unit/system tests, test case tables, scripts, README, and MASM
fixture flow docs. Run:

```bash
rg -n 'config_v2_canary.json|_config_v2_canary' \
  src tests tools samples README.md HEADLESS.md
```

Expected: zero matches.

- [ ] **Step 5: Verify all canonical projects compile**

Run operational config-v2, parser, project picker, CLI, fixture builder, and
project loading tests in Docker. The test must instantiate every canonical
project through `compile_config_v2_hook_schedule`.

- [ ] **Step 6: Commit**

```bash
git add src/d810/conf tests tools samples README.md HEADLESS.md
git commit -m "refactor(config-v2): canonicalize bundled project presets"
```

---

### Task 8: Delete routing, bridge shims, legacy registrations, and compatibility tests

**Files:**
- Delete: `src/d810/core/config_v2_defaults.py`
- Delete: `src/d810/passes/pipeline_v2_hook_bridge.py`
- Delete: `tests/unit/core/test_config_v2_defaults.py`
- Delete: `tests/unit/passes/test_pipeline_v2_hook_bridge.py`
- Modify: all remaining imports and status/UI text.
- Create: `tests/unit/architecture/test_config_v2_only_inventory.py`
- Modify: `README.md`, `HEADLESS.md`, `samples/src/masm/README.md`, `tests/README.md`.

**Interfaces:**
- Removes source/runtime routing and compatibility names completely.
- Produces repository-level ratchet against reintroduction.

- [ ] **Step 1: Write the failing no-legacy inventory gate**

The test scans tracked production/config/test sources, with a narrow allowlist
for the offline migration tool and its tests:

```python
FORBIDDEN_RUNTIME_TOKENS = (
    "CONFIG_V2_SUPPORTED_DEFAULT_MAPPINGS",
    "select_config_v2_default_project",
    "PipelineV2Mode.LEGACY",
    "PipelineV2Mode.SHADOW_CHECK",
    "pipeline_v2_hook_bridge",
)


def test_runtime_has_no_legacy_config_v2_path():
    violations = scan_runtime_tokens(FORBIDDEN_RUNTIME_TOKENS)
    assert violations == []


def test_bundled_projects_do_not_register_optimizer_class_names():
    violations = scan_project_rule_arrays(CONF_DIR)
    assert violations == []
```

Do not forbid legacy vocabulary inside `tools/migrations` or its tests; that is
the deliberately retained conversion boundary.

- [ ] **Step 2: Verify RED**

Run the architecture test and confirm it names the routing module and shim.

- [ ] **Step 3: Delete compatibility files and remaining branches**

Remove default-selection status, source/runtime routing fields, compatibility
imports, direct JSON registration of `StateMachineCffUnflattener`, and tests
whose only assertion was legacy parity/routing. Preserve algorithmic and
semantic tests under v2-native terminology.

- [ ] **Step 4: Verify GREEN and repository inventory**

Run the architecture test, then manually inspect:

```bash
rg -n 'config_v2_defaults|pipeline_v2_hook_bridge|CONFIG_V2_SUPPORTED_DEFAULT|\
PipelineV2Mode|_config_v2_canary|"name"\s*:\s*"StateMachineCffUnflattener"' \
  src tests tools samples README.md HEADLESS.md
```

Expected: only deliberate offline migration references to the legacy class name.

- [ ] **Step 5: Run architecture boundaries**

From the worktree:

```bash
sg scan --config sgconfig.yml --report-style short
PYTHONPATH=src lint-imports --config .importlinter
```

Expected: zero ast-grep findings and 14 kept import contracts.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "refactor(config-v2): delete legacy project execution path"
```

---

### Task 9: Run focused unit and runtime acceptance gates

**Files:**
- Generated evidence only: `.tmp/config_v2_final_cutover_*.txt`
- No production edits unless a test exposes a scoped regression.

**Interfaces:**
- Proves migration, parser, manager, compiler, UI, and state-machine behavior before expensive system oracles.

- [ ] **Step 1: Run the focused unit matrix**

From the main repository root:

```bash
./tools/scripts/run_system_tests_docker.sh test -w config-v2-final-cutover \
  -o config_v2_final_cutover_units.txt -- \
  tests/unit/core tests/unit/manager tests/unit/passes tests/unit/tools \
  tests/unit/ui tests/unit/architecture -q
```

Expected: exit 0. Retain the output under the worktree `.tmp`.

- [ ] **Step 2: Run project-loading and state-machine runtime tests**

```bash
./tools/scripts/run_system_tests_docker.sh test -w config-v2-final-cutover \
  -l -o config_v2_final_cutover_runtime.txt -- \
  tests/system/runtime/test_state_project_loading.py \
  tests/system/runtime/optimizers/microcode/flow/flattening/\
test_unflatten_bounded_rerun.py \
  tests/system/runtime/optimizers/microcode/flow/flattening/\
test_canonical_semantic_evidence_capability.py -q
```

Expected: exit 0, no legacy fallback warnings, and no unknown pass IDs.

- [ ] **Step 3: Re-run architecture boundaries**

Run `sg scan`, `lint-imports`, `git diff --check`, and the inventory `rg` from
Task 8. Record exact outputs.

- [ ] **Step 4: Commit any test-only corrections**

Only if needed:

```bash
git add <scoped-files>
git commit -m "test(config-v2): close final cutover regressions"
```

---

### Task 10: Run representative unflattening and full-system semantic gates

**Files:**
- Evidence: `.tmp/config_v2_final_cutover_system_*.txt`
- Logs: `.tmp/logs/**`

**Interfaces:**
- Proves the final cutover preserves live IDA/Hex-Rays behavior, not just project parsing.

- [ ] **Step 1: Run representative profile oracles**

Run the exact OLLVM, Tigress indirect, Approov/Hodur, and Eidolon fixture tests
already referenced by the canonical configurations. Include at minimum:

```text
tests/system/e2e/test_ollvm_fla_bcf_dimension_api.py
tests/system/e2e/test_ollvm_fla_bcf_sub_oracle.py
tests/system/e2e/test_tigress_indirect_semantic_oracle.py
tests/system/e2e/test_hodur_baselines.py
tests/system/e2e/test_unflattening_characterization.py
tests/system/e2e/test_unflattening_effect_safety_fixtures.py
```

Use:

```bash
./tools/scripts/run_system_tests_docker.sh test -w config-v2-final-cutover \
  -l -o config_v2_final_cutover_profiles.txt -- <paths-above> -q
```

Expected: exit 0 with the same semantic/golden assertions as the baseline.

- [ ] **Step 2: Run the complete system suite**

```bash
./tools/scripts/run_system_tests_docker.sh system -w config-v2-final-cutover \
  -l -o config_v2_final_cutover_system_full.txt
```

Expected: exit 0. If it becomes minutes-long and CPU-bound in an uninstrumented
interval, stop, retain the partial log, and follow the repository profiling
instructions before retrying.

- [ ] **Step 3: Refresh the code graph**

From the worktree:

```bash
graphify update .
```

Inspect the graph diff for lingering edges to routing, canaries, shadow mode, or
legacy rule activation.

- [ ] **Step 4: Final verification and handoff**

Run:

```bash
git status --short
git log --oneline --decorate -10
git diff cfg-recon-mainline...HEAD --check
```

Report exact commit IDs, test counts, Docker output artifact paths, any skipped
test with reason, and whether the worktree is clean. Do not merge until the user
requests integration after reviewing this evidence.
