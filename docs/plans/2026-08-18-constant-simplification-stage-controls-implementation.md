# Constant Simplification Stage Controls Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Compile `constant-simplification` into one immutable, operator-visible schedule with independently enabled and maturity-gated mutation stages, separate reversible global-const preparation, and independently bounded generic Z3 predicate transforms.

**Architecture:** Keep portable configuration, validation, and schedule compilation in `d810.passes`; pass the resulting immutable schedule into both live hook activation and Workbench projection. Keep IDA mutation and observation at backend/manager boundaries: the pre-Hex controller owns reversible type preparation, while a post-D810 `MMAT_CALLS` subscriber observes bounded tables without rewriting microcode. Give each generic predicate transform an immutable proof policy and use a fresh, policy-scoped solver so node limits, timeouts, caches, and receipts cannot leak between transforms.

**Tech Stack:** Python 3.11+, dataclasses, Hex-Rays microcode callbacks, Qt Workbench controls, Z3 bit-vectors, pytest, MASM fixture builder, IDA 9.4 Docker system-test runtime.

**Spec:** `docs/plans/2026-08-18-constant-simplification-stage-controls-design.md`

## Global Constraints

- Preserve the exact approved canonical JSON shape from the design specification. Do not rename public pass IDs, stage IDs, preparation keys, or Z3 transform option keys.
- Configuration may narrow a stage's implementation-declared maturity set but may never expand it. Unsupported maturities and enabled stages with an empty effective set are configuration errors, not silent omissions.
- Compile the effective schedule once. Runtime hook activation and Workbench projection must consume the same immutable value; neither may rediscover stage maturities from live rule instances.
- `global-const-types` is a pre-Hex preparation domain, not a microcode maturity. Never insert a fake maturity to make the UI easier.
- Reversible const preparation must continue through the existing proposal, journal, conflict, restore, and database-identity machinery. No direct `ida_typeinf` write outside that gateway is allowed.
- Dynamic bounded-table discovery is observation-only, runs on the existing post-D810 capture at `MMAT_CALLS`, queues proposals for the next natural preparation round, and never requests or forces a restart.
- Readonly folding and const preparation are independent. Aggressive folding must not weaken the strict const-persistence policy.
- The three generic Z3 transforms own independent immutable `max_expression_nodes` and `proof_timeout_ms` values. Do not mutate the cached shared solver or any process-global timeout.
- A node limit is enforced during recursive AST expansion, before the oversized tree is fully constructed. Timeout, `unknown`, unsupported translation, and node exhaustion are abstentions. Only an actual proof permits mutation.
- Keep Egglog unchanged.
- Use TDD. For every task, first add the focused failing assertion, run it and retain the expected failure, implement the narrow behavior, then rerun it green before broader verification.
- Do not weaken architecture checks, add ast-grep ignores, add import-linter ignores, quarantine a new test, or delete an existing system assertion to obtain green results.
- Other people may be editing the repository. Preserve unrelated changes and never revert work outside the assigned task.
- Local worktree commands must use `PYTHONPATH=src`.
- Run IDA-dependent tests only from the main repository root, never from inside the worktree. For this plan the exact command shape is:

  ```bash
  cd /Users/mahmoud/src/idapro/d810
  ./tools/scripts/run_system_tests_docker.sh test -w constant-simplification-stage-controls -o <bare-output-name>.txt -- <pytest-paths-and-args>
  ./tools/scripts/run_system_tests_docker.sh system -w constant-simplification-stage-controls -l -o <bare-output-name>.txt -- <pytest-args>
  ```

- Store Docker output in the worktree's `.tmp` by passing only a bare filename to `-o`.
- Before completion, run from the worktree:

  ```bash
  sg scan --config sgconfig.yml --report-style short
  PYTHONPATH=src lint-imports --config .importlinter
  ```

---

## Task 1: Define the portable stage contracts and compile canonical options

**Purpose:** Establish one pure, IDA-free source of truth for stage support, canonical/legacy parsing, pass-gate intersection, errors, and deterministic ordering. No live hook or UI code should guess these values later.

**Files:**

- Create: `src/d810/passes/constant_simplification_options.py`
- Modify: `src/d810/passes/execution_stages.py`
- Modify: `src/d810/passes/constant_simplification.py`
- Modify: `tests/unit/passes/test_constant_simplification.py`
- Modify: `tests/unit/passes/test_execution_stages.py`
- Create: `tests/unit/passes/test_constant_simplification_options.py`

### Required model

Implement these IDA-free frozen dataclasses and enums:

```python
class StageLifecycleDomain(str, Enum):
    PRE_HEXRAYS = "pre_hexrays"
    MICROCODE = "microcode"

@dataclass(frozen=True, slots=True)
class ConstantPreparationOptions:
    enabled: bool = False
    discover_bounded_tables: bool = True

@dataclass(frozen=True, slots=True)
class ConstantMutationStageOptions:
    enabled: bool
    requested_maturities: tuple[IRMaturity, ...]
    stage_options: Mapping[str, object]

@dataclass(frozen=True, slots=True)
class CompiledConstantStage:
    pass_id: str
    stage_id: str
    lifecycle_domain: StageLifecycleDomain
    pipeline: ExecutionPipeline | None
    implementation_name: str | None
    enabled: bool
    supported_maturities: tuple[IRMaturity, ...]
    requested_maturities: tuple[IRMaturity, ...]
    pass_maturity_gates: tuple[IRMaturity, ...]
    effective_maturities: tuple[IRMaturity, ...]
    runtime_order: int | None
    inactive_reason: str | None
    options: Mapping[str, object]

@dataclass(frozen=True, slots=True)
class CompiledConstantSimplificationSchedule:
    preparation: ConstantPreparationOptions
    stages: tuple[CompiledConstantStage, ...]
```

Use `MappingProxyType` or defensive frozen copies so callers cannot mutate nested stage options after compilation.

The portable registration owns the support sets, in `IR_MATURITY_ORDER` order:

```python
fold-readonly-data = (
    IRMaturity.CANONICAL,
    IRMaturity.LOCAL_OPTIMIZED,
    IRMaturity.CALL_MODELED,
    IRMaturity.GLOBAL_ANALYZED,
    IRMaturity.STRUCTURED,
)
fold-constant-subtree = (
    IRMaturity.LOCAL_OPTIMIZED,
    IRMaturity.CALL_MODELED,
    IRMaturity.GLOBAL_ANALYZED,
    IRMaturity.GLOBAL_OPTIMIZED,
    IRMaturity.STRUCTURED,
)
forward-constants = (
    IRMaturity.CALL_MODELED,
    IRMaturity.GLOBAL_ANALYZED,
    IRMaturity.GLOBAL_OPTIMIZED,
    IRMaturity.STRUCTURED,
)
```

Extend `ExecutionStageDescriptor` with `lifecycle_domain` and `supported_maturities`. Preserve construction compatibility for every other pass by giving both fields defaults, add equality/validation tests, and keep the descriptor free of `ida_hexrays` imports. `constant_simplification.py` populates these fields in its three registrations; the compiler reads those registrations rather than maintaining a duplicate support table.

### Parsing and compilation rules

- Canonical top-level option keys are exactly `preparation` and `stages`.
- Canonical preparation contains only `global_const_types`; it contains only `enabled` and `discover_bounded_tables`.
- Canonical stages contain exactly the three public stage IDs. Missing stage objects use their full current defaults. Unknown stage IDs or stage keys error.
- Each stage accepts `enabled` and `maturities`. `fold-readonly-data` additionally accepts `memory_policy`, `rva_guard`, and `allow_executable_readonly`.
- Normalize both portable names (`GLOBAL_ANALYZED`) and provider names (`MMAT_GLBOPT1`) through the existing maturity vocabulary. Reject unknown values, booleans, empty strings, and non-list maturity containers.
- Deduplicate repeated maturities and reorder deterministically by `IR_MATURITY_ORDER`; do not preserve arbitrary user duplicate/order artifacts.
- The legacy flat keys remain accepted only when neither canonical key is present. Map `persist_global_const_annotations` to `preparation.global_const_types.enabled`, preserve `discover_bounded_tables=True`, and put the other legacy values under `fold-readonly-data`. Supply all three full support sets.
- Any mix of one or more legacy keys with `preparation` or `stages` is an error.
- A requested maturity outside the stage support set is an error whose message contains pass ID, stage ID, offending maturity, and supported names.
- `effective_maturities = requested_maturities ∩ config.maturity_gates`. When `maturity_gates` is empty, treat it as no additional restriction and use all requested maturities.
- A disabled stage has no effective maturities and a stable inactive reason such as `disabled by configuration`.
- An enabled stage whose effective set is empty errors with pass ID, stage ID, requested set, and pass gate set.
- Runtime order is the declaration order within each backend pipeline: readonly folding before subtree folding in the instruction pipeline; forward constants is first in this pass's flow pipeline.

### TDD steps

- [ ] Add parameterized tests for the canonical defaults and every explicit field. Assert all frozen compiled values, not just parser acceptance.
- [ ] Add tests proving legacy flat options compile to the exact canonical schedule and that the current default mutation coverage is unchanged.
- [ ] Add rejection tests for mixed legacy/canonical input, unknown nested keys, malformed types, unsupported maturities, and enabled-empty intersections. Assert diagnostic substrings specified above.
- [ ] Add normalization tests using duplicate portable/provider spellings and assert one deterministic tuple.
- [ ] Add immutability tests that attempt to mutate nested compiled options.
- [ ] Run the focused tests and retain the expected RED result:

  ```bash
  PYTHONPATH=src pytest -q \
    tests/unit/passes/test_constant_simplification_options.py \
    tests/unit/passes/test_constant_simplification.py \
    tests/unit/passes/test_execution_stages.py
  ```

- [ ] Implement the portable models, contracts, parser, and compiler with no IDA imports.
- [ ] Replace the old flat `_parse_options` result with the compiled canonical schedule while preserving `build_constant_simplification_pass` as the public registry builder.
- [ ] Rerun the focused tests GREEN.
- [ ] Run `PYTHONPATH=src pytest -q tests/unit/passes/test_operational_config_v2.py tests/unit/core/test_config_v2_defaults.py`.
- [ ] Commit only Task 1 files with message `feat(config): compile constant simplification stages`.

---

## Task 2: Activate live rules only from the compiled schedule

**Purpose:** Make the hook bridge consume Task 1's immutable schedule, pass exact effective maturities to each enabled private implementation, and fail if live implementation defaults drift from the portable contract.

**Files:**

- Modify: `src/d810/passes/constant_simplification.py`
- Modify: `src/d810/passes/pipeline_v2_hook_bridge.py`
- Modify: `src/d810/manager/project_runtime.py`
- Modify: `src/d810/manager/state.py`
- Modify: `src/d810/manager/manager.py`
- Modify: `src/d810/optimizers/microcode/handler.py`
- Modify: `tests/unit/passes/test_pipeline_v2_hook_bridge.py`
- Modify: `tests/unit/manager/test_project_runtime.py`
- Create or modify: `tests/system/runtime/test_constant_simplification_stage_activation.py`

### Activation contract

Extend `PipelineV2HookActivation` to carry the compiled constant schedule (or a tuple of all compiled stage schedules when generalized) in addition to the ordered rule configurations. Do not reduce it back to a boolean before it reaches manager state.

For each enabled compiled stage, construct exactly one private rule configuration:

```python
RuleConfiguration(
    name="FoldReadonlyDataRule",
    is_activated=True,
    config={
        "maturities": [maturity.name for maturity in effective],
        "memory_policy": ...,
        "rva_guard": ...,
        "allow_executable_readonly": ...,
    },
)
```

Use the actual existing private option spelling for aggressive folding (`fold_writable_constants`) at the final backend boundary, but keep the public compiled schedule in public terminology.

Do not pass `persist_global_const_annotations` into `FoldReadonlyDataRule`; Task 3 removes that coupled authority.

Disabled stages must be absent from `instruction_rules`/`block_rules`, not present with `is_activated=False`. Preserve instruction rule declaration order.

### Live contract validation

After a configured rule instance has applied its `maturities` option, compare its native integer maturity set with the compiled effective provider set. Also instantiate or expose the implementation's declared defaults and compare them to the portable supported set. Fail configuration/startup with a precise contract-drift error if:

- the implementation cannot accept the compiled exact set;
- the portable supported set no longer equals the implementation default support set; or
- the instantiated enabled rule reports a different effective set.

Do not use this live check as the schedule source. It is an assertion against the portable authority.

### TDD steps

- [ ] Add bridge tests proving each of the eight enable/disable combinations emits the correct ordered instruction and block rule names.
- [ ] Add tests proving pass gates and stage maturities produce the exact `maturities` private config and no other stage is altered.
- [ ] Add a test proving the bridge carries the identical compiled schedule object/value into the project-runtime snapshot.
- [ ] Add a test that simulates a live default-support drift and asserts fail-closed startup with the implementation and stage named.
- [ ] Add a system test inside IDA that instantiates all three rules from a narrowed schedule and asserts their native `maturities` equal the selected provider constants.
- [ ] Run the focused unit tests RED:

  ```bash
  PYTHONPATH=src pytest -q \
    tests/unit/passes/test_pipeline_v2_hook_bridge.py \
    tests/unit/manager/test_project_runtime.py
  ```

- [ ] Implement activation and project-runtime propagation.
- [ ] Rerun the unit tests GREEN.
- [ ] From the main repo root, run the IDA test:

  ```bash
  ./tools/scripts/run_system_tests_docker.sh test \
    -w constant-simplification-stage-controls \
    -o constant_stage_activation.txt -- \
    tests/system/runtime/test_constant_simplification_stage_activation.py -q
  ```

- [ ] Commit Task 2 with message `feat(runtime): activate compiled constant stages`.

---

## Task 3: Separate reversible const preparation and dynamic observation

**Purpose:** Make const type preparation independently useful when readonly folding is disabled, and make bounded-table discovery an observation subscriber rather than a mutation-rule side effect.

**Files:**

- Modify: `src/d810/optimizers/microcode/instructions/peephole/fold_readonlydata.py`
- Modify: `src/d810/manager/pre_hexrays_preparation.py`
- Modify: `src/d810/manager/post_d810_runtime.py`
- Modify: `src/d810/manager/manager.py`
- Modify: `src/d810/manager/state.py`
- Modify: `src/d810/backends/hexrays/global_const_annotation.py`
- Create: `src/d810/backends/hexrays/global_const_observer.py`
- Modify: `tests/unit/manager/test_pre_hexrays_preparation.py`
- Create: `tests/unit/manager/test_global_const_observer.py`
- Modify: `tests/system/runtime/backends/hexrays/test_global_const_annotation.py`
- Modify: `tests/system/e2e/test_pre_hexrays_idb_preparation.py`

### Preparation behavior

The pre-Hex controller receives the compiled preparation options. When `enabled=False`, it performs no discovery or annotation for this pass. When `enabled=True`, it invokes the existing whole-item discovery for the selected function and applies proposals only through the reversible journal/gateway.

The constness policy remains the strict policy in `analyses/value_flow/global_constness.py` regardless of `fold-readonly-data.memory_policy`.

Expose a portable preparation status snapshot containing at least counts/identities for `pending`, `applied`, `conflicting`, and `restored` proposals plus a stable pending reason. Reuse existing journal/proposal identities; do not invent an address-only shadow ledger.

### Observation behavior

Create a small observer that accepts a live MBA and:

1. exits unless preparation is enabled and `discover_bounded_tables=True`;
2. exits unless the provider maturity is exactly `MMAT_CALLS` / `IRMaturity.CALL_MODELED`;
3. traverses each instruction once in deterministic block/instruction order;
4. calls the existing `discover_dynamic_global_table_access(instruction)`;
5. queues exact proposals through the existing annotation proposal API;
6. deduplicates using existing proposal identity, scoped to the current database/function generation rather than a process-global address set;
7. records `next preparation round` for new queued dynamic proposals; and
8. never mutates an instruction, returns an optimization count, marks lists dirty, or requests decompilation restart.

Wire it to the existing `DecompilationEvent.POST_D810_CAPTURE` subscriber path in `HexRaysPostD810Runtime`, filtering to the CALLS maturity. This event already provides the live MBA and is the correct manager-owned observation seam.

Remove `_persist_proven_global_consts`, dynamic-table discovery state, and the `persist_global_const_annotations` config branch from `FoldReadonlyDataRule`. Keep only direct folding decisions in that rule.

### TDD steps

- [ ] Add a unit test proving whole-item const preparation is called when preparation is enabled while `fold-readonly-data` is disabled.
- [ ] Add a unit test proving readonly folding may be enabled while preparation is disabled and no type proposal is queued.
- [ ] Add a policy test proving aggressive readonly folding still cannot persist a writable object as const.
- [ ] Add observer tests for disabled preparation, disabled dynamic discovery, wrong maturity, exact CALLS traversal, duplicate events, and queue failures. Queue failures must abstain/fail closed without mutation.
- [ ] Add a test asserting no restart request/event is emitted and the pending reason is exactly `next preparation round`.
- [ ] Run focused tests RED:

  ```bash
  PYTHONPATH=src pytest -q \
    tests/unit/manager/test_pre_hexrays_preparation.py \
    tests/unit/manager/test_global_const_observer.py
  ```

- [ ] Implement the separation and observer.
- [ ] Rerun focused tests GREEN.
- [ ] Run the global const system tests from the main root:

  ```bash
  ./tools/scripts/run_system_tests_docker.sh test \
    -w constant-simplification-stage-controls \
    -o global_const_preparation_observer.txt -- \
    tests/system/runtime/backends/hexrays/test_global_const_annotation.py \
    tests/system/e2e/test_pre_hexrays_idb_preparation.py -q
  ```

- [ ] Commit Task 3 with message `refactor(constants): separate preparation from folding`.

---

## Task 4: Render and edit the shared effective schedule in Workbench

**Purpose:** Give operators typed controls and display runtime truth from the same compiled schedule, including the separate preparation lifecycle and pending dynamic proposals.

**Files:**

- Modify: `src/d810/core/pass_editor_spec.py`
- Modify: `src/d810/passes/constant_simplification.py`
- Modify: `src/d810/manager/effective_pipeline_schedule.py`
- Modify: `src/d810/manager/workbench_models.py`
- Modify: `src/d810/manager/workbench_service.py`
- Modify: `src/d810/ui/config_v2_editing_logic.py`
- Modify: `src/d810/ui/config_v2_editing_panel.py`
- Modify: `src/d810/ui/workbench_logic.py`
- Modify: `tests/unit/core/test_pass_editor_spec.py`
- Modify: `tests/unit/passes/test_config_v2_editor_contracts.py`
- Modify: `tests/unit/manager/test_effective_pipeline_schedule.py`
- Modify: `tests/unit/ui/test_config_v2_editing_logic.py`
- Modify: `tests/unit/ui/test_workbench_logic.py`
- Modify: `tests/unit/ui/test_config_v2_project_editor_host_contract.py`
- Modify: `tests/unit/ui/test_project_config_adapter_contract.py`

### Editor controls

Use the generic field editor. The current `FieldControlKind.STRING_LIST` with `choices` already expresses a typed subset. Render a choice-backed string list as a `QListWidget` whose items use `Qt.ItemIsUserCheckable`; initialize each check state from the current value and emit the checked choices in declared-choice order. Preserve the current comma-separated `QLineEdit` only when `choices` is empty.

Register nested fields at these exact paths:

```text
preparation.global_const_types.enabled
preparation.global_const_types.discover_bounded_tables
stages.fold-readonly-data.enabled
stages.fold-readonly-data.maturities
stages.fold-readonly-data.memory_policy
stages.fold-readonly-data.rva_guard
stages.fold-readonly-data.allow_executable_readonly
stages.fold-constant-subtree.enabled
stages.fold-constant-subtree.maturities
stages.forward-constants.enabled
stages.forward-constants.maturities
```

Each maturity field's choices are only that stage's supported portable maturity names. Keep the danger advisory on executable readonly memory. The preparation description must say dynamic discoveries apply on the next natural preparation round.

### Workbench schedule model

Project the compiled schedule directly. Extend the model so every mutation row contains:

- enabled/disabled;
- supported maturities;
- requested maturities;
- pass-level gates;
- effective maturities;
- lifecycle domain;
- backend pipeline;
- runtime order within that pipeline;
- schedule source exactly `compiled stage contract`; and
- inactive/rejected reason.

Add a separate preparation row for `global-const-types` with lifecycle `PRE_HEXRAYS`, no provider maturity, and applied/pending/conflicting/restored state. A pending dynamic proposal renders `next preparation round`.

Do not call `build_effective_maturity_schedule` with live manager rule objects for the constant bundle. Other passes may keep their current projection until separately migrated. For constant simplification, the compiled schedule value carried by project runtime is authoritative.

Group instruction and flow stages independently at a maturity. Do not fabricate a single total callback order across pipelines.

### TDD steps

- [ ] Add pure editor-spec tests for all nested paths, defaults, choice vocabularies, and validation.
- [ ] Add logic tests proving a choice-backed string list rejects unknown values and round-trips a subset without changing its order/value semantics.
- [ ] Add Qt host-contract tests proving the control is editable and emits the selected list. Keep GUI mechanics minimal and test pure normalization separately.
- [ ] Add schedule tests proving Workbench output equals the compiled schedule even when fake live rule objects advertise conflicting maturities.
- [ ] Add preparation-row tests for pending/applied/conflicting/restored and the next-round reason.
- [ ] Add rendering tests proving supported/requested/gates/effective/source/pipeline order are visible and disabled stages remain visible rather than disappearing.
- [ ] Run focused tests RED:

  ```bash
  PYTHONPATH=src pytest -q \
    tests/unit/core/test_pass_editor_spec.py \
    tests/unit/passes/test_config_v2_editor_contracts.py \
    tests/unit/manager/test_effective_pipeline_schedule.py \
    tests/unit/ui/test_config_v2_editing_logic.py \
    tests/unit/ui/test_workbench_logic.py \
    tests/unit/ui/test_config_v2_project_editor_host_contract.py \
    tests/unit/ui/test_project_config_adapter_contract.py
  ```

- [ ] Implement generic editor and Workbench projection changes.
- [ ] Rerun focused tests GREEN.
- [ ] Commit Task 4 with message `feat(workbench): expose constant stage schedule`.

---

## Task 5: Add policy-scoped bounded Z3 proof outcomes

**Purpose:** Give the generic predicates a sound resource boundary and structured abstention reasons without changing existing callers that only need boolean proof APIs.

**Files:**

- Create: `src/d810/backends/ast/z3_proof_policy.py`
- Modify: `src/d810/backends/ast/z3.py`
- Create: `tests/unit/backends/ast/test_z3_proof_policy.py`
- Modify: `tests/system/runtime/backends/ast/test_z3_prover.py`
- Modify: `tests/system/runtime/backends/ast/test_z3_set_comparisons.py`

### Required API

Add immutable portable outcome types, with naming equivalent to:

```python
class Z3ProofStatus(str, Enum):
    PROVED = "proved"
    DISPROVED = "disproved"
    ABSTAINED = "abstained"

class Z3ProofAbstentionReason(str, Enum):
    NODE_LIMIT = "node_limit"
    TIMEOUT = "timeout"
    UNSUPPORTED_EXPRESSION = "unsupported_expression"
    SOLVER_UNKNOWN = "solver_unknown"

@dataclass(frozen=True, slots=True)
class Z3ProofPolicy:
    max_expression_nodes: int = 256
    proof_timeout_ms: int = 50

@dataclass(frozen=True, slots=True)
class Z3ProofResult:
    status: Z3ProofStatus
    reason: Z3ProofAbstentionReason | None
    observed_expression_nodes: int | None
    elapsed_ms: float
```

Validate `max_expression_nodes` in `1..4096` and `proof_timeout_ms` in `1..5000` at construction.

### Node accounting

Thread a budget object through recursive mop-to-AST expansion. Count every expanded occurrence: operator, constant, and leaf. Count repeated occurrences repeatedly; this is a work/resource bound, not DAG cardinality. Consume before descending/constructing that occurrence. On exhaustion, raise/carry an internal typed node-limit signal and return an abstention without completing the oversized AST.

Do not merely call an existing post-construction node counter.

### Solver isolation and results

- A prover with a policy creates a fresh solver (or a cache keyed by the complete immutable policy) and sets only that solver's timeout.
- Existing `get_solver()` compatibility may remain for callers without policy, but bounded predicate calls must not mutate or reuse the global cached solver.
- Distinguish `z3.unsat`, `z3.sat`, and `z3.unknown` explicitly. Use `solver.reason_unknown()` plus elapsed/budget context to classify timeout versus generic unknown.
- Translation failures map to `unsupported_expression`.
- A cache key includes the complete proof policy and query identity. Prefer caching only conclusive proofs. Never turn or reuse an abstention as a proof under another policy.
- Add result-returning APIs (`prove_equal`, `prove_unequal`, `prove_always_zero`, `prove_always_nonzero`, or one internal query primitive). Keep current `are_equal`, `are_unequal`, `is_always_zero`, and `is_always_nonzero` behavior as compatibility wrappers returning `True` only for `PROVED`.
- Do not weaken the existing fail-closed behavior for unsupported loads or mixed widths.

### TDD steps

- [ ] Add pure policy validation and immutability tests.
- [ ] Add unit tests around a portable/fake expansion walker proving exact occurrence counts and pre-construction cutoff.
- [ ] Add IDA system tests for an in-budget proof, one-node-too-small abstention, timeout/unknown, unsupported expression, and cache isolation between different policies.
- [ ] Add a test proving the process-global solver timeout is unchanged after a bounded proof.
- [ ] Run pure tests RED, implement the policy types and budget primitive, then rerun GREEN.
- [ ] Run IDA tests from the main root:

  ```bash
  ./tools/scripts/run_system_tests_docker.sh test \
    -w constant-simplification-stage-controls \
    -o bounded_z3_prover.txt -- \
    tests/system/runtime/backends/ast/test_z3_prover.py \
    tests/system/runtime/backends/ast/test_z3_set_comparisons.py -q
  ```

- [ ] Commit Task 5 with message `feat(z3): bound predicate proof resources`.

---

## Task 6: Wire independent bounds and receipts into all three generic predicates

**Purpose:** Expose the approved per-transform fields and ensure `setz`, `setnz`, and `lnot` independently use and report their own proof policies.

**Files:**

- Modify: `src/d810/passes/mba_transform_options.py`
- Modify: `src/d810/passes/mba_simplify.py`
- Modify: `src/d810/passes/pipeline_v2_hook_bridge.py`
- Modify: `src/d810/optimizers/microcode/instructions/z3/predicates.py`
- Modify: `src/d810/core/observability_events.py`
- Modify: `src/d810/core/diag/event_handlers.py`
- Modify: `src/d810/core/diag/models.py`
- Modify: `tests/unit/passes/test_mba_transform_options.py`
- Modify: `tests/unit/passes/test_mba_transform_catalog.py`
- Modify: `tests/unit/passes/test_mba_simplify.py`
- Create: `tests/unit/optimizers/test_z3_predicate_options.py`
- Create or modify: `tests/system/runtime/test_z3_predicate_bounds.py`

### Public transform options

Add the same two `FieldEditorSpec` values independently under each of:

```text
z-3-setz-generic
z-3-setnz-generic
z-3-lnot-generic
```

Fields:

```text
max_expression_nodes: integer, default 256, min 1, max 4096
proof_timeout_ms: integer, default 50, min 1, max 5000
```

The options parser must reject unknown keys, booleans-as-integers, and out-of-range values using the existing transform-specific error path. Omitting an option produces the default only for that transform.

### Predicate behavior

Each rule stores one immutable `Z3ProofPolicy` during `configure()`. Reuse that policy for every prover created in every branch of that rule. Replace the current repeated bare `Z3MopProver()` construction in `predicates.py`; no branch may accidentally use default bounds after the rule was configured.

For `setz`, `setnz`, and `lnot`:

- mutate only for the conclusive proof outcome expected by that branch;
- treat every abstention as no match;
- do not log routine abstentions at ERROR;
- emit a structured proof diagnostic with transform ID, both configured bounds, observed nodes if known, elapsed time, status, and reason;
- ensure a later rule callback can still attempt its own policy after another transform abstains.

### TDD steps

- [ ] Add parser/editor tests for defaults, explicit values, range/type rejection, and unknown keys for all three transform IDs.
- [ ] Add construction tests that configure three rules with distinct values and assert three distinct immutable policies.
- [ ] Add tests covering every prover creation branch in each predicate, using a fake result API to prove the configured policy is preserved.
- [ ] Add a cross-rule isolation test: force `setz` to hit a low node limit, then prove `setnz` succeeds under a larger limit, and verify `lnot` retains its unrelated timeout.
- [ ] Add receipt tests for proved and each abstention reason. Assert routine abstentions do not emit ERROR logs.
- [ ] Run focused unit tests RED:

  ```bash
  PYTHONPATH=src pytest -q \
    tests/unit/passes/test_mba_transform_options.py \
    tests/unit/passes/test_mba_transform_catalog.py \
    tests/unit/passes/test_mba_simplify.py \
    tests/unit/optimizers/test_z3_predicate_options.py
  ```

- [ ] Implement transform schema, rule configuration, proof use, and diagnostics.
- [ ] Rerun focused tests GREEN.
- [ ] Run IDA test from the main root:

  ```bash
  ./tools/scripts/run_system_tests_docker.sh test \
    -w constant-simplification-stage-controls \
    -o z3_predicate_bounds.txt -- \
    tests/system/runtime/test_z3_predicate_bounds.py -q
  ```

- [ ] Commit Task 6 with message `feat(mba): configure bounded z3 predicates`.

---

## Task 7: Migrate bundled profiles and guarantee canonical round trips

**Purpose:** Make repository-supplied projects use the canonical structure while retaining explicit read compatibility for external legacy projects.

**Files:**

- Modify all JSON files under `src/d810/conf/` containing `"pass_id": "constant-simplification"`
- Modify: `src/d810/core/config_v2_defaults.py`
- Modify: `src/d810/manager/config_v2_editing.py`
- Modify: `src/d810/ui/config_v2_editing_logic.py`
- Modify: `tests/unit/core/test_config_v2_defaults.py`
- Modify: `tests/unit/passes/test_operational_config_v2.py`
- Modify: `tests/unit/ui/test_config_v2_editing_logic.py`
- Create: `tests/unit/passes/test_constant_simplification_profile_migration.py`

### Migration requirements

- Rewrite every bundled profile to `preparation` + `stages`; do not leave legacy flat keys in repository-owned JSON.
- Preserve each profile's current effective behavior. In particular, a profile that had `persist_global_const_annotations=true` gets preparation enabled; all others stay false. Preserve memory policy/RVA/executable settings under readonly folding.
- Set each stage's default enabled state and full support list unless the profile intentionally needs a narrower selection established by a test.
- Preserve existing pass-level `maturity_gates`; compilation performs the intersection.
- The editor/load-save path canonicalizes an accepted legacy external config on the next write.
- Mixed canonical/legacy input remains a hard error; migration is not a precedence mechanism.

### TDD steps

- [ ] Add a repository-profile test that enumerates all bundled config files, locates constant simplification entries, rejects legacy keys, compiles every entry, and snapshots/asserts expected effective behavior for the Eid-prefixed v3/v4 profiles plus the default profiles.
- [ ] Add an external legacy load/save test proving output is canonical and equivalent.
- [ ] Run focused tests RED:

  ```bash
  PYTHONPATH=src pytest -q \
    tests/unit/passes/test_constant_simplification_profile_migration.py \
    tests/unit/core/test_config_v2_defaults.py \
    tests/unit/passes/test_operational_config_v2.py \
    tests/unit/ui/test_config_v2_editing_logic.py
  ```

- [ ] Migrate configurations and serialization.
- [ ] Rerun focused tests GREEN.
- [ ] Validate every JSON file with Python's JSON parser and the project's config parser.
- [ ] Commit Task 7 with message `chore(config): migrate constant stage controls`.

---

## Task 8: Add committed MASM acceptance fixtures and verify behavior, not eligibility

**Purpose:** Prove the complete operator contract inside IDA: preparation without folding, folding without preparation, schedule gating, callback order, dynamic next-round discovery, and three independently bounded predicates.

**Files:**

- Create: `samples/src/masm/constant_stage_controls.asm`
- Modify the actual MASM export/build manifest discovered via `rg "samples/src/masm" tests src tools`
- Create: `src/d810/conf/constant_stage_controls_config_v2_canary.json`
- Create: `tests/system/e2e/test_constant_stage_controls.py`
- Modify: `tests/system/cases/libobfuscated_comprehensive.py`
- Modify: `docs/plans/2026-08-18-constant-simplification-stage-controls-implementation.md` only to check completed boxes/evidence if the workflow records completion in-plan

### Fixture shapes

Export named functions with stable, neutral names for:

1. `const_prepare_without_fold`: reads a strictly eligible global so const metadata can be applied/restored while pseudocode/mutation receipts prove no direct readonly fold ran.
2. `readonly_fold_without_prepare`: folds a global value but leaves the original IDB type unchanged and creates no preparation journal entry.
3. `readonly_then_subtree`: requires the readonly value to become immediate before a surrounding arithmetic subtree can fold. Assert receipt order, not only final pseudocode.
4. `forward_selected_maturity`: exposes a constant def/use chain suitable for forward propagation; run once with an included maturity and once with it gated out.
5. `bounded_table_next_round`: exposes a bounded indexed table only after CALLS microcode. First run queues a proposal with `next preparation round` and no restart; second natural invocation applies it.
6. `bounded_setz`, `bounded_setnz`, and `bounded_lnot`: contain nontrivial but small symbolic predicates. Run each with a sufficient node budget and then one below the observed requirement.

Keep MASM deterministic and minimal. Do not rely on implementation addresses or block serials without EA anchors. If one object file cannot isolate persistent IDB state between cases, restore through the journal between assertions.

### System assertions

For every case, assert:

- the compiled schedule receipt contains supported/requested/gates/effective values;
- enabled stages have the expected provider callback and exact private rule order;
- disabled or gated stages produce no mutation receipt;
- final pseudocode contains the expected semantic form;
- preparation journal before/after types are exact and restoration succeeds;
- dynamic discovery produces no forced restart and applies only on the next natural round;
- Z3 proof receipts contain transform ID, effective bounds, observed nodes when available, elapsed time, and outcome/reason; and
- node-limit/timeout cases leave the original predicate intact.

An eligible rule, a log line saying it started, or a nonzero generic mutation count is not acceptance evidence.

### TDD and verification steps

- [ ] Add the system test assertions against the unimplemented fixture/receipts and run them to retain the expected RED result.
- [ ] Add and register the MASM fixture through the existing export fixture flow; do not create a parallel build mechanism.
- [ ] Implement only fixture/receipt glue required by the test; production behavior should already exist from Tasks 1-7.
- [ ] Run the dedicated fixture from the main root:

  ```bash
  ./tools/scripts/run_system_tests_docker.sh system \
    -w constant-simplification-stage-controls \
    -l \
    -o constant_stage_controls_e2e.txt -- \
    -k constant_stage_controls -vv -s
  ```

- [ ] Run the complete focused unit set:

  ```bash
  PYTHONPATH=src pytest -q \
    tests/unit/passes/test_constant_simplification_options.py \
    tests/unit/passes/test_constant_simplification.py \
    tests/unit/passes/test_pipeline_v2_hook_bridge.py \
    tests/unit/manager/test_project_runtime.py \
    tests/unit/manager/test_pre_hexrays_preparation.py \
    tests/unit/manager/test_global_const_observer.py \
    tests/unit/manager/test_effective_pipeline_schedule.py \
    tests/unit/ui/test_config_v2_editing_logic.py \
    tests/unit/ui/test_workbench_logic.py \
    tests/unit/backends/ast/test_z3_proof_policy.py \
    tests/unit/passes/test_mba_transform_options.py \
    tests/unit/passes/test_mba_simplify.py \
    tests/unit/optimizers/test_z3_predicate_options.py \
    tests/unit/passes/test_constant_simplification_profile_migration.py
  ```

- [ ] Run architecture gates from the worktree:

  ```bash
  sg scan --config sgconfig.yml --report-style short
  PYTHONPATH=src lint-imports --config .importlinter
  ```

- [ ] Run broader local units:

  ```bash
  PYTHONPATH=src pytest -q tests/unit
  ```

- [ ] Run the full Docker system suite from the main root and retain the output:

  ```bash
  ./tools/scripts/run_system_tests_docker.sh system \
    -w constant-simplification-stage-controls \
    -l \
    -o constant_stage_controls_full_system.txt -- \
    -vv
  ```

- [ ] Classify every failure as introduced, pre-existing, or environmental with exact test names and logs. Fix every introduced failure before completion; do not hide it with a skip/quarantine.
- [ ] Run `graphify update .` from the worktree and inspect the resulting diff. Commit graph changes only if they are the repository's normal tracked output; preserve unrelated pre-existing graph dirt.
- [ ] Commit Task 8 with message `test(system): cover constant stage controls`.

---

## Final Review and Handoff Checklist

- [ ] Verify `git diff <plan-base>...HEAD` contains only the planned feature, tests, configs, fixture, documentation, and any expected graph update.
- [ ] Verify no legacy `persist_global_const_annotations` behavior remains inside `FoldReadonlyDataRule`.
- [ ] Verify runtime activation and Workbench use the same compiled constant schedule value.
- [ ] Verify disabled stages are absent from live worklists but visible as disabled in Workbench.
- [ ] Verify no configuration can add an unsupported maturity or silently collapse an enabled stage to an empty schedule.
- [ ] Verify const preparation works with readonly folding disabled and readonly folding works with const preparation disabled.
- [ ] Verify dynamic discovery works with readonly folding disabled, observes only CALLS, queues next-round proposals, and never forces restart.
- [ ] Verify all three generic predicates have independent defaults/overrides and no solver, timeout, node budget, or cache state leaks between them.
- [ ] Verify bounded abstentions cannot mutate and do not log as routine errors.
- [ ] Verify all dedicated fixture cases show before/after pseudocode plus schedule/mutation/preparation/proof receipts.
- [ ] Run a final independent code-review agent against this plan and the full diff. Resolve every spec or quality finding, then rerun affected tests.
- [ ] Run the verification-before-completion checklist and record exact commands, exit codes, and output artifact paths.
- [ ] Do not merge, push, or remove the worktree unless the user explicitly requests integration after reviewing the completed result.
