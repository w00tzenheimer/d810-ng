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
- The implementation worktree name is exactly `config-v2-final-cutover-impl`;
  every Docker invocation must pass `-w config-v2-final-cutover-impl`.
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

## Fixed Implementation Decisions

These are rulings, not choices left to the implementer:

1. **Known bundled legacy documents use fingerprinted projections.** The prior
   cutover intentionally changed some option shapes, so blindly translating
   every legacy key would either reject shipped presets or silently lose
   behavior. The migrator computes SHA-256 over canonical JSON
   (`sort_keys=True`, separators `(',', ':')`, UTF-8, `ensure_ascii=False`). An
   exact known fingerprint selects a named current-v2 projection. A custom file
   that differs by one semantic field does not inherit that projection.
2. **Custom user documents use only lossless rule projections.** Instruction
   implementation names are reverse-mapped through `mba_transform_stages()`;
   block rules are mapped through current registered hook-transform and cleanup
   adapters. Any active rule, option, or ordering constraint without an exact
   typed representation raises `LegacyMigrationError`.
3. **The migration tool remains after runtime legacy deletion.** It is the only
   allowed production location for legacy rule names and fingerprints. It must
   not be imported by `src/d810/**`.
4. **Canonicalization copies semantic documents, not raw prose.** The donor
   canary's `pipeline_v2` and owned non-rule metadata are authoritative. Remove
   `pipeline_v2_mode`, `config_v2_canary`, `ins_rules`, and `blk_rules`; rewrite
   the description to describe the canonical preset. Preserve keys such as
   `function_analysis_priors` exactly.
5. **Do not rename the algorithm module in this cutover.** Remove public JSON
   and manager registration by `StateMachineCffUnflattener`, but leave the class
   and module in place as the private Hex-Rays host. A later native callback
   extraction can rename it without mixing algorithm movement into this
   configuration migration.
6. **No automatic runtime rewrite.** Loading an unmigrated project produces an
   error containing this exact command shape:
   `python tools/migrations/migrate_project_config_v2.py INPUT --in-place`.
7. **No compatibility aliases.** Deleted canary basenames are not recreated as
   forwarding JSON, symlinks, lookup aliases, or deprecated constants.
8. **No test command improvisation.** Docker commands run from the main root
   and use `-w config-v2-final-cutover-impl`; local commands run inside the
   implementation worktree with `PYTHONPATH=src`.

## Normative Execution Order and Atomic Boundaries

Execute tasks in this order, which intentionally differs from numeric document
order: **1, 2, 3, 4, 7, 5, 6, 8, 9, 10**.

- Task 4 introduces v2-only validation but retains the deprecated mode enum and
  parser functions until Task 6 removes their remaining consumers. It must not
  create an import-time break in the state-machine host.
- Task 7 copies donor semantics into canonical source files and moves every
  consumer to canonical names, but temporarily retains the 21 routed donor
  canaries and `config_v2_defaults.py`. This makes canonical files ready while
  the old manager can still start.
- Task 5 is the atomic runtime cutover: it activates canonical files directly,
  collapses source/runtime state, deletes `config_v2_defaults.py`, and deletes
  the 21 now-unreferenced mapped donor canaries in the same commit. There must
  never be a commit where routing points at deleted donors.
- Task 6 removes legacy/shadow mode APIs after manager consumers are gone.
- Task 8 deletes the temporary bridge import shim, compatibility-only tests,
  remaining legacy vocabulary, and installs the final inventory ratchet.

These atomic boundaries override any older wording in an individual task that
suggests deleting mapped canaries in Task 7 or deleting mode APIs in Task 4.

## Exact Historical Canonicalization Matrix

The following table is copied from the current routing policy and donor files.
Task 1 freezes it as test fixture data before Task 8 deletes the routing module.
The pass sequence is ordered and must compare exactly.

| Canonical destination | Current donor to delete | Ordered pass IDs after canonicalization |
|---|---|---|
| `default_instruction_only.json` | `default_instruction_only_config_v2_canary.json` | `constant-simplification`, `mba-simplify`, `jump-fixer` |
| `default_unflattening_tigress_engine.json` | `default_unflattening_tigress_engine_config_v2_canary.json` | native spine |
| `hodur_flag2.json` | `hodur_flag2_config_v2_canary.json` | native spine, `jump-fixer` |
| `hodur_glbopt2_only.json` | `hodur_glbopt2_only_config_v2_canary.json` | native spine |
| `eidolon.json` | `eidolon_config_v2_canary.json` | `mba-simplify` |
| `default_unflattening_approov.json` | `default_unflattening_approov_config_v2_canary.json` | `mba-simplify`, `mba-state-preconditioner`, native spine, `jump-fixer` |
| `default_unflattening_approov_s1a.json` | `default_unflattening_approov_s1a_config_v2_canary.json` | `mba-simplify`, `mba-state-preconditioner`, native spine, `jump-fixer` |
| `hodur_flag2_s1a.json` | `hodur_flag2_s1a_config_v2_canary.json` | native spine, `jump-fixer` |
| `hodur_flag2_with_fcp.json` | `hodur_flag2_with_fcp_config_v2_canary.json` | `mba-simplify`, native spine, `jump-fixer`, `constant-simplification` |
| `identity_call.json` | `identity_call_config_v2_canary.json` | `identity-call-resolver` |
| `default_unflattening_tigress_engine_transition_facts.json` | `default_unflattening_tigress_engine_transition_facts_config_v2_canary.json` | `constant-simplification`, `mba-simplify`, native spine |
| `example_libobfuscated_abc.json` | `example_libobfuscated_abc_config_v2_canary.json` | `constant-simplification`, `mba-simplify`, native spine, `jump-fixer` |
| `flatfold.json` | `flatfold_config_v2_canary.json` | `constant-simplification`, `mba-simplify`, `mba-state-preconditioner`, `jump-fixer`, native spine |
| `example_hodur.json` | `example_hodur_config_v2_canary.json` | `constant-simplification`, `mba-simplify`, native spine, `jump-fixer` |
| `default_unflattening_ollvm.json` | `default_unflattening_ollvm_config_v2_canary.json` | `constant-simplification`, `mba-simplify`, `indirect-call-resolver`, `mba-state-preconditioner`, native spine, `simple-flattening-cleanup-unflattener`, `jump-fixer` |
| `default_indirect_resolution.json` | `default_indirect_resolution_config_v2_canary.json` | `indirect-branch-resolver`, `indirect-call-resolver` |
| `default_unflattening_tigress_indirect.json` | `default_unflattening_tigress_indirect_config_v2_canary.json` | `mba-simplify`, native spine, `jump-fixer` |
| `default.json` | `default_config_v2_canary.json` | `indirect-branch-resolver`, `indirect-call-resolver` |
| `example_libobfuscated_no_fixprecedessor.json` | `example_libobfuscated_no_fixprecedessor_config_v2_canary.json` | `constant-simplification`, `mba-simplify`, `simple-flattening-cleanup-unflattener`, `jump-fixer` |
| `bogus_loops.json` | `bogus_loops_config_v2_canary.json` | `single-trip-loop-peel`, `mba-state-preconditioner`, `jump-fixer` |
| `example_libobfuscated.json` | `example_libobfuscated_config_v2_canary.json` | `constant-simplification`, `mba-simplify`, `mba-state-preconditioner`, native spine, `jump-fixer` |

`native spine` always expands, in this exact order, to:

```python
(
    "recover_dispatcher",
    "recover_state_transitions",
    "plan_semantic_regions",
    "lower_state_machine",
    "cleanup_residual_dispatcher",
)
```

Two non-routed canaries are fixture variants rather than source/runtime pairs:

| Current file | Stable destination |
|---|---|
| `dead_store_elimination_fixture_config_v2_canary.json` | `dead_store_elimination_fixture.json` |
| `hodur_flag2_s1a_config_v2_canary_constant_simplification.json` | `hodur_flag2_s1a_constant_simplification.json` |

## Exact Known Legacy Fingerprints

Task 1 must hard-code these canonical-document fingerprints in the offline
migration catalogue and assert them in tests. They deliberately remain outside
runtime code.

```text
default_instruction_only.json b3f0944b2119e880d2976821953ebf2c50f2646a18a1898ee7ffc0d636c02ab2
default_unflattening_tigress_engine.json 1d343499a5cb0dec68b2a7efedf3237703dce6fc39b2aae61186feb1a0471db2
hodur_flag2.json 2c57256b924f15329eb0166edbfc693f19f56d57a4e317b2c1d03d5458fbc9eb
hodur_glbopt2_only.json c6a288756aed1880a54981c5cf596bbb5abddc09e74cefd2c6af60406445c986
eidolon.json bc241830174e4e5433a0b7d3aaac3f042d56978e9e77c6ed46d000c76cbbcd6c
default_unflattening_approov.json 83f454590e43ae04800cff57670a33e06185cd66ff7daf2141e1f84f62d1c9ac
default_unflattening_approov_s1a.json 1ca9be3289dd1ef4ec4893434612dbafaed5058bc12b2422ca86218ed51eda05
hodur_flag2_s1a.json 11d0f3aa77a291c12715550156585afe577010e865faaf55bdf04b4f2aef2e63
hodur_flag2_with_fcp.json 8bbdc05360b7d3f5fe9c345c19a70d8d5269fc0f6d64c5b49bef42ac8e52ae10
identity_call.json cd035f21e1ba345d0a6108616344375f1e93866a8cfdee23c6f6770224525339
default_unflattening_tigress_engine_transition_facts.json 33a35478e5adcf6b952ec30f30727524a31f721c1d502c89f80165c9b01c4750
example_libobfuscated_abc.json dcf343cfb6ce6f701e5954c64607d8cd8a3512345d1f3057f2be7cf7a006fa5e
flatfold.json fb2f480fcc9088f637a83c9ed5fc9354ed9c40ae61f0fe134ae7f237160d56dd
example_hodur.json 859f94847f7796fb4166b2a7feb70d927a0c54fb50c3f750c7209cddb8c8e6c0
default_unflattening_ollvm.json 176a9441b7c866ca37d174c9bf3bcd494521acd94c4ec29c55d115cd951451cb
default_indirect_resolution.json 3ad2011d8a652b62a1d7c33a4c42f43a9c66f95d8bd4ce42a48f0514baa2a3ee
default_unflattening_tigress_indirect.json 2101314f6b7a8213922818e88b4c8aa54d57048aa83dc2c414e6640b74ea9ec9
default.json 3ad2011d8a652b62a1d7c33a4c42f43a9c66f95d8bd4ce42a48f0514baa2a3ee
example_libobfuscated_no_fixprecedessor.json 9bf4606216bfe471d526b1f12d19cb6da17fdd7a542c51f8283ab350da98c457
bogus_loops.json a1c7a9b5ce95589848c0444413af458e33c599093f722dc89617bbf081a16945
example_libobfuscated.json 0e24934ca11872a24d65384967a9830fb567caf2d9b64ae4e15b88ec2d49f546
```

`default.json` and `default_indirect_resolution.json` intentionally share a
fingerprint. Lookup therefore keys on `(source basename, fingerprint)`, never
fingerprint alone.

## Migration Data Model and Projection Rules

Use these exact internal shapes so parsing, projection, and serialization stay
separate and testable:

```python
@dataclass(frozen=True, slots=True)
class LegacyRule:
    section: Literal["ins_rules", "blk_rules"]
    index: int
    name: str
    options: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class LegacyProject:
    source_name: str
    description: str
    active_rules: tuple[LegacyRule, ...]
    additional_configuration: Mapping[str, object]
    canonical_fingerprint: str


@dataclass(frozen=True, slots=True)
class KnownPortfolio:
    source_name: str
    fingerprint: str
    donor_name: str
```

Projection is ordered as follows:

1. Parse and validate the whole JSON object. `is_activated=False` rules are
   ignored; malformed inactive entries are still rejected because they are not
   valid project data.
2. If `pipeline_v2` is present and there are active legacy rules, reject mixed
   ownership. If it is present without active legacy rules, validate and return
   canonical v2.
3. Match `(source_name, canonical_fingerprint)` against `KnownPortfolio`. Load
   the donor document from the repository only while building/testing; the
   installed migration tool must instead use checked-in compact
   `PipelineConfig.to_dict()` templates plus owned metadata, so it continues to
   work after canaries are deleted.
4. Otherwise perform generic exact projection:
   - `FoldReadonlyDataRule`, `ConstantSubtreeFoldRule`, and
     `ForwardConstantPropagationRule` are one owner bundle. Partial selection is
     rejected rather than silently adding missing behavior. The complete bundle
     maps to `constant-simplification`; `fold_writable_constants=True` maps to
     `memory_policy="aggressive_no_direct_writes"`, false/missing maps to
     `"strict"`; only `allow_executable_readonly` and `rva_guard` map directly.
   - Every other instruction rule must match exactly one
     `ExecutionStageDescriptor.implementation_name` from
     `mba_transform_stages()`. Preserve source order as `options.transforms`.
     Rule configs become `options.transform_options[transform_id]` only if the
     transform declares those fields in `MBA_TRANSFORM_OPTION_FIELDS`; otherwise
     non-empty config is rejected.
   - `StateMachineCffUnflattener` maps to the complete native spine only when
     its options reduce exactly to public fields `min_state_constant`, `family`,
     `recovery_strategy`, and `native_cfg_persistence`. Former validator/limit
     flags are not guessed for custom input.
   - `JumpFixer` maps to `jump-fixer`; every `enabled_rules` value must be in
     `JUMP_FIXER_RULE_NAMES`, order is preserved, and all other fields reject.
   - The direct block-rule map is:
     `ForwardConstantPropagationRule -> forward-constant-propagation`,
     `IdentityCallResolver -> identity-call-resolver`,
     `IndirectBranchResolver -> indirect-branch-resolver`,
     `IndirectCallResolver -> indirect-call-resolver`,
     `MbaStatePreconditioner -> mba-state-preconditioner`,
     `SingleTripLoopPeel -> single-trip-loop-peel`, and
     `SimpleFlatteningCleanupUnflattener -> simple-flattening-cleanup-unflattener`.
     Validate every projected option by building the result with
     `operational_config_v2_pass_registry()`.
5. Validate the final ordered pipeline through the operational registry before
   returning a document. The first validation error is wrapped with source
   rule section/index/name so users can fix the input.

## Per-task Review Contract

Every implementation task report must contain:

- status: `DONE`, `DONE_WITH_CONCERNS`, `NEEDS_CONTEXT`, or `BLOCKED`;
- commit SHA(s);
- files changed and why;
- the exact RED command and expected failing assertion/error;
- the exact GREEN command, exit code, and pass/fail count;
- `git diff --check` result;
- deviations from the task brief, even if judged harmless;
- generated `.tmp` evidence filenames;
- no claim based on a test that was not run.

Reviewers must separately issue `SPEC: PASS|FAIL` and `QUALITY: PASS|FAIL`.
Any missing verdict is a failed review. Critical and important findings block
the next task; minor findings receive an explicit coordinator ruling.

## Exact Docker Command Matrix

Workers must copy these commands verbatim and run them from
`/Users/mahmoud/src/idapro/d810`. A worker whose shell is inside the worktree
must first `cd /Users/mahmoud/src/idapro/d810`; running the script from the
worktree breaks `D810_REPO_ROOT` and is not accepted evidence. Each `-o` value is
a bare filename and is written to
`.worktrees/config-v2-final-cutover-impl/.tmp/`.

```bash
# Task 1 RED/GREEN
./tools/scripts/run_system_tests_docker.sh test \
  -w config-v2-final-cutover-impl \
  -o task1_legacy_migrator.txt -- \
  tests/unit/tools/test_migrate_project_config_v2.py -q

# Task 2 RED/GREEN (same file, CLI cases included)
./tools/scripts/run_system_tests_docker.sh test \
  -w config-v2-final-cutover-impl \
  -o task2_migration_cli.txt -- \
  tests/unit/tools/test_migrate_project_config_v2.py -q

# Task 3 RED/GREEN
./tools/scripts/run_system_tests_docker.sh test \
  -w config-v2-final-cutover-impl \
  -o task3_hook_runtime.txt -- \
  tests/unit/passes/test_config_v2_hook_runtime.py \
  tests/unit/passes/test_mba_portfolio_order.py \
  tests/unit/passes/test_rotate_idiom_recovery_pass.py \
  tests/unit/passes/test_finite_zero_set_predicate_pass.py \
  tests/unit/passes/test_modular_product_nonzero_pass.py \
  tests/unit/passes/test_mba_egglog.py -q

# Task 4 RED/GREEN
./tools/scripts/run_system_tests_docker.sh test \
  -w config-v2-final-cutover-impl \
  -o task4_v2_schema.txt -- \
  tests/unit/core/test_project_configuration_v2.py \
  tests/unit/passes/test_pipeline_config_parser.py \
  tests/unit/manager/test_config_v2_editing.py \
  tests/unit/manager/test_config_v2_editing_facade.py \
  tests/unit/ui/test_config_v2_editing_commands.py -q

# Task 5 RED/GREEN
./tools/scripts/run_system_tests_docker.sh test \
  -w config-v2-final-cutover-impl \
  -o task5_single_project_runtime.txt -- \
  tests/unit/manager/test_project_runtime.py \
  tests/unit/manager/test_function_recipe_activation.py \
  tests/unit/manager/test_workbench_models.py \
  tests/unit/manager/test_workbench_service.py \
  tests/unit/ui/test_project_config_logic.py \
  tests/unit/ui/test_project_config_ollvm_regression.py \
  tests/unit/ui/test_workbench_logic.py \
  tests/system/runtime/test_state_project_loading.py -q

# Task 6 RED/GREEN
./tools/scripts/run_system_tests_docker.sh test \
  -w config-v2-final-cutover-impl -l \
  -o task6_private_state_machine_host.txt -- \
  tests/unit/passes/test_pass_pipeline.py \
  tests/system/runtime/optimizers/microcode/flow/flattening/test_unflatten_bounded_rerun.py \
  tests/system/runtime/optimizers/microcode/flow/flattening/test_canonical_semantic_evidence_capability.py -q

# Task 7 RED/GREEN
./tools/scripts/run_system_tests_docker.sh test \
  -w config-v2-final-cutover-impl \
  -o task7_canonical_presets.txt -- \
  tests/unit/passes/test_operational_config_v2.py \
  tests/unit/passes/test_pipeline_config_parser.py \
  tests/unit/ui/test_project_picker_logic.py \
  tests/unit/tools/test_d810cli.py \
  tests/unit/test_fixture_builder.py \
  tests/unit/test_fixture_cli.py \
  tests/system/runtime/test_state_project_loading.py -q

# Task 8 RED/GREEN
./tools/scripts/run_system_tests_docker.sh test \
  -w config-v2-final-cutover-impl \
  -o task8_no_legacy_inventory.txt -- \
  tests/unit/architecture/test_config_v2_only_inventory.py \
  tests/unit/architecture tests/unit/core tests/unit/manager tests/unit/passes \
  tests/unit/tools tests/unit/ui -q
```

The worker records the initial RED output before implementation. A RED run is
valid only when it fails for the missing behavior named by the task; collection
failure from a typo, wrong test path, wrong worktree, missing dependency, or
runner misuse must be corrected and rerun.

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
./tools/scripts/run_system_tests_docker.sh test -w config-v2-final-cutover-impl \
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
- Adds the v2-only validation API while retaining `PipelineV2Mode` and
  `pipeline_v2_mode_from_project_config` as deprecated compatibility symbols
  until Task 6 removes their remaining runtime consumers.
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

Add the required parser and make all new call sites use it. Do not delete the
enum in this task because the state-machine host and module pass manager still
import it until Task 6:

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

### Task 5: Atomically collapse manager activation and remove mapped routing

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
- Delete: `src/d810/core/config_v2_defaults.py`
- Delete: `tests/unit/core/test_config_v2_defaults.py`
- Delete: the 21 mapped donor `src/d810/conf/*_config_v2_canary.json` files
  listed in the canonicalization matrix.
- Modify: every remaining import of `config_v2_defaults` and every test that
  asserted source/runtime routing.
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
copy implying a source/runtime route. In this same implementation, remove
`select_config_v2_default_project`, delete `config_v2_defaults.py`, and delete
the 21 mapped donors retained by Task 7. The project manager now loads the
canonical source document and compiles it directly. Do not leave a temporary
basename alias or compatibility routing map.

- [ ] **Step 4: Verify GREEN**

Run all touched unit tests plus `tests/system/runtime/test_state_project_loading.py`
through Docker.

- [ ] **Step 5: Commit**

```bash
git add -A src/d810/core/config_v2_defaults.py src/d810/conf \
  src/d810/manager src/d810/ui tests/unit/core tests/unit/manager tests/unit/ui \
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

### Task 7: Stage canonical bundled configurations and fixture names

**Files:**
- Modify: every `source_config` in the historical pair list from Task 1.
- Retain temporarily: the 21 paired routed donor canaries; Task 5 deletes them
  atomically with routing.
- Rename: fixture-only canaries such as `dead_store_elimination_fixture_config_v2_canary.json` to stable `*_fixture.json` names.
- Modify: all references returned by `rg -n 'config_v2_canary.json|_config_v2_canary'`.
- Modify: README, HEADLESS docs, MASM fixture docs, CLI defaults, and test parameter tables.

**Interfaces:**
- Consumes: current canary contents as canonical source contents.
- Produces: stable canonical basenames with `pipeline_v2` as their runtime source.

- [ ] **Step 1: Write a failing canonical bundled-config test**

Create a test that iterates canonical bundled project names except
`options.json` and explicit spike/catalogue data. Require a nonempty typed
pipeline and prohibit active legacy arrays or canary metadata in canonical
files. The temporary donor files are not canonical projects and remain covered
by exact source/donor equivalence tests until Task 5 deletes them.

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
remove empty legacy arrays and obsolete routing/canary metadata from the
canonical copy, preserve the canonical description where accurate, and validate
through the operational registry. Retain the mapped donor file unchanged until
Task 5. Rename/delete the two non-routed fixture variants in this task because
the routing table never points at them.

Use the Task 2 `--check` command on `src/d810/conf` and an explicit allowlist for
non-project JSON datasets. Do not edit JSON with ad-hoc regex replacement.

- [ ] **Step 4: Update all fixture and documentation references**

Replace names in unit/system tests, test case tables, scripts, README, and MASM
fixture flow docs. Run:

```bash
rg -n 'config_v2_canary.json|_config_v2_canary' \
  src tests tools samples README.md HEADLESS.md
```

Expected after Task 7: matches are limited to the 21 temporary donor files,
`config_v2_defaults.py`, and tests explicitly proving source/donor equivalence.
All runtime fixtures, scripts, docs, and CLI defaults must already use canonical
source names. Task 5 makes this query reach zero.

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

### Task 8: Delete bridge shims, legacy registrations, and compatibility tests

**Files:**
- Delete: `src/d810/passes/pipeline_v2_hook_bridge.py`
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

Remove remaining compatibility imports, direct JSON registration of
`StateMachineCffUnflattener`, and tests whose only assertion was legacy
parity/routing. Source/runtime routing itself was deleted atomically in Task 5.
Preserve algorithmic and semantic tests under v2-native terminology.

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
./tools/scripts/run_system_tests_docker.sh test -w config-v2-final-cutover-impl \
  -o config_v2_final_cutover_units.txt -- \
  tests/unit/core tests/unit/manager tests/unit/passes tests/unit/tools \
  tests/unit/ui tests/unit/architecture -q
```

Expected: exit 0. Retain the output under the worktree `.tmp`.

- [ ] **Step 2: Run project-loading and state-machine runtime tests**

```bash
./tools/scripts/run_system_tests_docker.sh test -w config-v2-final-cutover-impl \
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
./tools/scripts/run_system_tests_docker.sh test -w config-v2-final-cutover-impl \
  -l -o config_v2_final_cutover_profiles.txt -- <paths-above> -q
```

Expected: exit 0 with the same semantic/golden assertions as the baseline.

- [ ] **Step 2: Run the complete system suite**

```bash
./tools/scripts/run_system_tests_docker.sh system -w config-v2-final-cutover-impl \
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
