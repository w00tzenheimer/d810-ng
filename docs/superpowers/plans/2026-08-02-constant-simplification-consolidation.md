# Constant Simplification Consolidation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace D810's overlapping constant-memory decisions and public rule choices with one architecture-neutral constness oracle and one public **Simplify constants** config-v2 bundle.

**Architecture:** Portable code decides whether a specific memory read may be inlined and whether the whole item may persistently become `const`. A Hex-Rays evidence adapter supplies item, permission, xref, bounds, and value facts. Existing live rules retain their valid maturity callbacks, but share one decision authority and one materialization helper module; config-v2 exposes one logical bundle which the hook bridge expands into private instruction and flow stages.

**Tech Stack:** Python 3.11+, pytest, IDA 9.x/Hex-Rays microcode, D810 PipelineConfig v2, ast-grep, import-linter, graphify.

## Global Constraints

- Work only in `/Users/mahmoud/src/idapro/d810/.worktrees/lrea-portable-cfg-case-producer` on branch `diff/lrea-portable-cfg-case-producer`.
- Portable packages under `d810.analyses` and `d810.passes` must not import IDA or live Hex-Rays modules.
- Default classification must depend on observed facts, not Mach-O, ELF, PE/COFF, raw format, operating system, or segment names.
- `allow_executable_readonly` remains accepted, defaults to `false`, is explicitly dangerous, bypasses only the executable item-kind guard, and never authorizes persistent `const`.
- `aggressive_no_direct_writes` remains opt-in and is never represented as proof of immutability.
- A modeled reaching write vetoes the read. An initializer-stable proof may authorize only that read despite unrelated writes.
- Existing legacy pass IDs remain readable at the serialization boundary during migration, but the public catalog exposes only `constant-simplification` for this capability.
- Do not add ast-grep ignores or import-linter exceptions.
- Every production behavior change follows red-green-refactor TDD.

---

### Task 1: Portable global constness oracle

**Files:**
- Create: `src/d810/analyses/value_flow/global_constness.py`
- Modify: `src/d810/analyses/value_flow/__init__.py`
- Create: `tests/unit/analyses/value_flow/test_global_constness.py`

**Interfaces:**
- Produces: `GlobalItemKind`, `GlobalConstPolicy`, `GlobalConstReason`, `GlobalConstEvidence`, `GlobalConstDecision`, and `decide_global_const_read(evidence, policy, allow_executable_readonly=False)`.
- Consumes: only immutable Python values; no live backend objects.

- [ ] **Step 1: Write the failing decision-table tests**

  Define literal evidence fixtures covering readable R-only data, readable R+X data, R+X code and unresolved items, writable/no-direct-write memory, direct writes, reaching writes, initializer-stable reads, invalid bounds, unsupported widths, and failed reads. Assert both `can_inline_read` and `can_persist_const`, plus the stable reason.

- [ ] **Step 2: Run the oracle test and verify RED**

  Run: `pyenv exec python -m pytest -q tests/unit/analyses/value_flow/test_global_constness.py`

  Expected: collection fails because `d810.analyses.value_flow.global_constness` does not exist.

- [ ] **Step 3: Implement the immutable oracle model**

  Implement this public shape:

  ```python
  class GlobalItemKind(str, Enum):
      DATA = "data"
      CODE = "code"
      TAIL = "tail"
      UNKNOWN = "unknown"

  class GlobalConstPolicy(str, Enum):
      STRICT = "strict"
      AGGRESSIVE_NO_DIRECT_WRITES = "aggressive_no_direct_writes"

  @dataclass(frozen=True, slots=True)
  class GlobalConstEvidence:
      address: int
      item_head: int
      item_end: int
      read_size: int
      readable: bool
      writable: bool
      executable: bool
      item_kind: GlobalItemKind
      has_direct_write: bool
      reaching_write: bool
      initializer_stable_at_read: bool
      value: int | None

  @dataclass(frozen=True, slots=True)
  class GlobalConstDecision:
      can_inline_read: bool
      can_persist_const: bool
      value: int | None
      reason: GlobalConstReason
      used_dangerous_override: bool = False
  ```

  Validate the read range with `item_head <= address` and `address + read_size <= item_end`; support only widths `1, 2, 4, 8`. Apply precedence: invalid evidence -> reaching-write veto -> initializer-stable read -> normal non-writable data -> dangerous R+X override -> aggressive writable/no-direct-write -> abstain.

- [ ] **Step 4: Run the oracle test and verify GREEN**

  Run the Task 1 pytest command and require zero failures.

- [ ] **Step 5: Commit Task 1**

  Commit message: `feat: add portable global constness oracle`

---

### Task 2: Hex-Rays evidence adapter and canonical materialization helpers

**Files:**
- Create: `src/d810/backends/hexrays/evidence/global_constness.py`
- Create: `src/d810/optimizers/microcode/constant_materialization.py`
- Create: `tests/system/runtime/backends/hexrays/test_global_constness.py`
- Modify: `tests/system/runtime/expr/test_opaque_table_folding.py`

**Interfaces:**
- Consumes: `GlobalConstPolicy` and portable oracle types from Task 1.
- Produces: `decide_hexrays_global_read(address, size, *, policy, allow_executable_readonly)` and canonical `replace_operand_with_immediate(...)` / `replace_load_with_immediate(...)` helpers.

- [ ] **Step 1: Write failing real-IDA evidence tests**

  Add runtime tests that locate representative data items in the loaded sample and assert the adapter reports canonical item bounds, supported value reads, and identical decisions from the same fact shape. Add R+X data/code tests when the fixture exposes those shapes; otherwise construct the portable fact row in Task 1 and keep the live test focused on adapter capture.

- [ ] **Step 2: Run the focused runtime selector and verify RED**

  Run the repository's IDA system-test wrapper for `tests/system/runtime/backends/hexrays/test_global_constness.py` and confirm failure is the missing adapter, not fixture setup.

- [ ] **Step 3: Implement backend fact capture**

  Canonicalize with `ida_bytes.get_item_head()` and `ida_bytes.get_item_size()`. Classify flags with `ida_bytes.is_code()`, `is_data()`, `is_tail()`, and unknown fallback. Query direct `dr_W` xrefs across every byte in the half-open item range. Capture segment R/W/X permissions and read widths `1, 2, 4, 8`, treating `BADADDR` and exceptions as unavailable values. Feed the result to `decide_global_const_read()`.

- [ ] **Step 4: Implement canonical mutation helpers**

  Move immediate operand construction and whole-load replacement into one optimizer module. Preserve destination legality, unsigned width masking, empty `r` operands, and shift-amount size rules. These helpers own memory-read-to-immediate mutation; rules only identify shapes and submit oracle decisions.

- [ ] **Step 5: Run focused runtime tests and verify GREEN**

  Run the new adapter test plus the existing opaque-table folding selector.

- [ ] **Step 6: Commit Task 2**

  Commit message: `feat: add Hex-Rays global const evidence adapter`

---

### Task 3: Route legacy materializers through one authority and remove FCP memory resolution

**Files:**
- Modify: `src/d810/optimizers/microcode/instructions/peephole/fold_readonlydata.py`
- Modify: `src/d810/optimizers/microcode/flow/constant_prop/global_const_inline.py`
- Modify: `src/d810/optimizers/microcode/flow/constant_prop/forward_const_prop.py`
- Modify: `tests/system/runtime/expr/test_opaque_table_folding.py`
- Modify: `tests/system/runtime/test_global_const_inline.py`
- Create: `tests/system/runtime/optimizers/microcode/flow/constant_prop/test_forward_const_memory_boundary.py`

**Interfaces:**
- Consumes: `decide_hexrays_global_read()` and Task 2 mutation helpers.
- Produces: no new public API; legacy classes remain compatibility entry points.

- [ ] **Step 1: Write failing rule-boundary tests**

  Assert strict, aggressive, R+X-data, and dangerous-R+X decisions are reflected by `FoldReadonlyDataRule`. Assert `GlobalConstantInliner` uses the same policy result and pointer filter after the decision. Assert FCP treats unresolved `ldx` as a KILL and has no memory-generated constant.

- [ ] **Step 2: Run the focused selectors and verify RED**

  Run the three test files and confirm failures identify the old duplicated classifiers and FCP resolver.

- [ ] **Step 3: Migrate `FoldReadonlyDataRule`**

  Replace `_segment_is_read_only`, `_is_foldable_address`, and `_fetch_constant` policy with a single `_decision_for(address, size)` call. Map `fold_writable_constants` to `GlobalConstPolicy.AGGRESSIVE_NO_DIRECT_WRITES`. Keep `allow_executable_readonly` with a `DANGEROUS` config description and emit a warning when enabled. Route direct, nested, xdu/xds, and mop_v paths through the same decision and Task 2 materializers.

- [ ] **Step 4: Migrate `GlobalConstantInliner`**

  Remove section-name and private xref classifiers. Add the same two compatibility options, call the shared adapter, retain `_looks_like_pointer()` as a post-decision value filter, and call Task 2 materializers. Keep old helper names only as thin deprecated wrappers where runtime tests or external imports require them.

- [ ] **Step 5: Remove memory resolution from FCP**

  Delete `_ro_segment_is_read_only`, `_ro_fetch_constant`, `_try_resolve_readonly_ldx`, their IDA segment imports, and the dynamic import of the peephole evaluator. In `_slow_transfer_single`, every `ldx` kills its written variable unless a constant was already materialized by the earlier memory stage.

- [ ] **Step 6: Run focused tests and verify GREEN**

  Re-run the Task 3 selectors and the existing global-constant runtime cases.

- [ ] **Step 7: Commit Task 3**

  Commit message: `refactor: consolidate constant memory materialization`

---

### Task 4: Add the public config-v2 constant-simplification bundle

**Files:**
- Create: `src/d810/passes/constant_simplification.py`
- Modify: `src/d810/passes/operational_config_v2.py`
- Modify: `src/d810/passes/pipeline_v2_hook_bridge.py`
- Modify: `src/d810/passes/registry.py`
- Modify: `src/d810/passes/legacy_flow_rules.py`
- Modify: `src/d810/manager/workbench_recipe_service.py`
- Create: `tests/unit/passes/test_constant_simplification.py`
- Modify: `tests/unit/passes/test_pipeline_v2_hook_bridge.py`
- Modify: `tests/unit/passes/test_operational_config_v2.py`
- Modify: `tests/unit/passes/test_pass_registry.py`
- Modify: `tests/unit/manager/test_workbench_recipe_service.py`

**Interfaces:**
- Produces: `CONSTANT_SIMPLIFICATION_PASS_ID`, `ConstantSimplificationOptions`, `build_constant_simplification_pass()`, `constant_simplification_hook_rules()`, and `PassRegistry.public_pass_ids()`.
- Consumes: PipelineConfig v2 and existing RuleConfiguration hook bridge.

- [ ] **Step 1: Write failing bundle and catalog tests**

  Assert default bundle expansion produces instruction rules `FoldReadonlyDataRule`, then `ConstantSubtreeFoldRule`, and block rule `ForwardConstantPropagationRule`, with no `GlobalConstantInliner`. Assert aggressive and dangerous options map only to `FoldReadonlyDataRule`. Assert unknown/wrongly typed options fail. Assert bundle plus legacy constant entries or managed rules is rejected. Assert legacy IDs remain buildable but disappear from `public_pass_ids()` and Recipe Composer catalog rows.

- [ ] **Step 2: Run unit selectors and verify RED**

  Run the five Task 4 unit test files and confirm missing bundle/public metadata failures.

- [ ] **Step 3: Implement bundle validation and expansion**

  Accept exactly:

  ```python
  {
      "memory_policy": "strict" | "aggressive_no_direct_writes",
      "allow_executable_readonly": bool,
  }
  ```

  The configured pass object is a descriptor returning an empty `PassResult`; live Hex-Rays execution remains owned by the hook bridge. `constant_simplification_hook_rules()` returns typed instruction/block rule configs in stage order.

- [ ] **Step 4: Add public/compatibility registry metadata**

  Extend `register()` and `register_configured()` with `public: bool = True`, retain all IDs in `registered_pass_ids()`, expose only public IDs through `public_pass_ids()`, and have Recipe Composer use the public list. Register `global-constant-inliner` and `forward-constant-propagation` as non-public compatibility aliases; register `constant-simplification` publicly.

- [ ] **Step 5: Expand the bundle in the hook bridge**

  Special-case `constant-simplification` before generic legacy-flow handling. Reject coexistence with `global-constant-inliner`, `forward-constant-propagation`, or an `mba-simplify` entry that includes `FoldReadonlyDataRule` or `ConstantSubtreeFoldRule`. Preserve configured pass identity as one logical pass while returning the three live rule activations.

- [ ] **Step 6: Run Task 4 unit tests and verify GREEN**

  Require all focused unit selectors to pass.

- [ ] **Step 7: Commit Task 4**

  Commit message: `feat: add constant simplification config bundle`

---

### Task 5: Migrate shipped configurations, defaults, and user-facing descriptions

**Files:**
- Modify: `src/d810/conf/*_config_v2_canary.json` entries that currently select any managed constant stage.
- Modify: `src/d810/core/config_v2_defaults.py`
- Modify: `README.md`
- Modify: `tests/unit/core/test_config_v2_defaults.py`
- Modify: `tests/unit/passes/test_pipeline_config_parser.py`
- Modify: `tests/unit/passes/test_mba_simplify.py`
- Modify: `tests/unit/ui/test_actions_logic.py`

**Interfaces:**
- Consumes: `constant-simplification` bundle from Task 4.
- Produces: shipped configs with one logical constant capability and no duplicate live materializer.

- [ ] **Step 1: Write failing migration assertions**

  Assert each bundled canary that previously contained at least one managed stage now contains exactly one `constant-simplification` entry, contains no legacy constant pass IDs, and excludes `FoldReadonlyDataRule` / `ConstantSubtreeFoldRule` from `mba-simplify`. Assert policy mapping preserves `fold_writable_constants`; shipped Mach-O-only `allow_executable_readonly` is removed because normal R+X data classification is architecture-neutral.

- [ ] **Step 2: Run migration/default tests and verify RED**

  Run the Task 5 unit selectors and confirm they fail on the legacy canary contents.

- [ ] **Step 3: Mechanically migrate JSON canaries**

  For each pipeline, insert one bundle at the earliest removed constant stage. Use `memory_policy=aggressive_no_direct_writes` if any removed `FoldReadonlyDataRule` config enabled `fold_writable_constants`; otherwise use `strict`. Do not carry shipped platform-specific `allow_executable_readonly`. Preserve unrelated pass ordering and metadata.

- [ ] **Step 4: Update routing expectations and documentation**

  Replace legacy expected pass IDs in `CONFIG_V2_SUPPORTED_DEFAULT_MAPPINGS`. Document **Simplify constants** as the public operation and label `allow_executable_readonly` as a dangerous expert override, not a macOS mode.

- [ ] **Step 5: Run Task 5 tests and verify GREEN**

  Re-run all migration/default/UI selectors and require zero failures.

- [ ] **Step 6: Commit Task 5**

  Commit message: `config: migrate constant simplification bundle`

---

### Task 6: Full verification, runtime parity, and graph update

**Files:**
- Modify only files required by failures attributable to this feature.
- Update generated graph: `graphify-out/**` via `graphify update .`.

**Interfaces:**
- Consumes: all prior tasks.
- Produces: verified consolidated behavior and current repository graph.

- [ ] **Step 1: Run the focused portable and config suite**

  ```bash
  pyenv exec python -m pytest -q \
    tests/unit/analyses/value_flow/test_global_constness.py \
    tests/unit/passes/test_constant_simplification.py \
    tests/unit/passes/test_pipeline_v2_hook_bridge.py \
    tests/unit/passes/test_operational_config_v2.py \
    tests/unit/passes/test_pass_registry.py \
    tests/unit/manager/test_workbench_recipe_service.py \
    tests/unit/core/test_config_v2_defaults.py \
    tests/unit/passes/test_pipeline_config_parser.py \
    tests/unit/passes/test_mba_simplify.py
  ```

- [ ] **Step 2: Run the existing pass/config regression directory**

  Run: `pyenv exec python -m pytest -q tests/unit/passes tests/unit/manager/test_config_v2_editing.py tests/unit/ui/test_workbench_recipe_logic.py`

- [ ] **Step 3: Run real-IDA constant-folding parity cases**

  Run the repository IDA wrapper for the adapter test, opaque-table folding tests, global-constant inlining cases, and representative config-v2 canaries. Record any environmental skips separately from failures.

- [ ] **Step 4: Run architecture gates**

  ```bash
  sg scan --config sgconfig.yml --report-style short
  PYTHONPATH=src lint-imports --config .importlinter
  ```

- [ ] **Step 5: Update and inspect graphify output**

  Run `graphify update .`, then `git status --short` and verify only feature-related graph changes are included.

- [ ] **Step 6: Final review against acceptance criteria**

  Confirm one public catalog entry, one oracle, canonical mutation helpers, no FCP memory resolver, architecture-neutral defaults, dangerous override containment, explicit legacy migration, and no persistent-IDB mutation.

- [ ] **Step 7: Commit verification fixes and graph update**

  Commit message: `test: verify constant simplification consolidation`
