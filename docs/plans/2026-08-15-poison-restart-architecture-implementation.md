# Poison Restart Provenance and Early-Quarantine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prevent D810 from repeating mutation work after an MBA is poisoned, preserve the real restart provenance, and reject the observed unsafe `fake_jump` rewrite before it touches live Hex-Rays microcode.

**Architecture:** Make native preanalysis state the typed restart and quarantine authority. Flowchart code may consume only evidence-rebind receipts; the manager may consume only poison-recovery receipts and start one fresh, mutation-abstaining decompile. Enforce quarantine at optimizer callback entry, mutation-gateway creation/publication, and LOCOPT mutation dispatch. Add the existing portable effectful-reachability proof to `fake_jump` preflight so the concrete regression is rejected before backend apply.

**Tech Stack:** Python 3.11+, pytest, Hex-Rays/IDA 9.4 system runtime, D810 portable `FlowGraph`, MASM fixture pipeline, ast-grep, import-linter, graphify.

**Spec:** [docs/plans/2026-08-15-poison-restart-architecture-design.md](./2026-08-15-poison-restart-architecture-design.md)

## Global Constraints

- Work only in `/Users/mahmoud/src/idapro/d810/.worktrees/poison-restart-architecture` until the branch is reviewed and merged.
- Use test-first commits. Run local tests with `PYTHONPATH=src` from the worktree.
- Run IDA-dependent tests from `/Users/mahmoud/src/idapro/d810` with `tools/scripts/run_system_tests_docker.sh -w poison-restart-architecture`.
- Do not throw through `optinsn_t` or `optblock_t`, invent a callback error code, weaken post-publication verification, or make computed-goto own poison recovery.
- Keep restart kind, consumer, evidence family, reason, and evidence generation typed. Do not introduce stringly typed owner checks.
- Log block identity with an EA anchor; a block serial alone is not acceptable evidence.
- Preserve read-only diagnostics and lifecycle completion after quarantine. Only mutation-producing work abstains.
- Commit source MASM and semantic assertions, never generated DLL/IDB binaries.

---

## Task 1: Replace lossy restart fields with typed receipts

**Files:**

- Modify: `src/d810/analyses/control_flow/native_preanalysis_session.py`
- Modify: `src/d810/optimizers/microcode/flow/jumps/computed_goto_resolver.py`
- Test: `tests/unit/analyses/control_flow/test_native_preanalysis_session.py`
- Test: `tests/unit/manager/test_decompilation_lifecycle.py`
- Test: `tests/unit/hexrays/mutation/test_fragment_publication_gateway.py`
- Test: `tests/system/runtime/hexrays/test_decompilation_lifecycle.py`
- Test: `tests/system/runtime/optimizers/microcode/flow/flattening/engine/test_cleanup_family.py`
- Test: `tests/system/runtime/test_manager_native_preanalysis.py`

### Interfaces

Add these public types next to the existing native-preanalysis lifecycle types:

```python
class GeneratedRestartKind(Enum):
    EVIDENCE_REBIND = "evidence_rebind"
    POISON_RECOVERY = "poison_recovery"


class GeneratedRestartConsumer(Enum):
    FLOWCHART = "flowchart"
    MANAGER = "manager"


@dataclass(frozen=True, slots=True)
class GeneratedRestartReceipt:
    kind: GeneratedRestartKind
    evidence_family: str
    reason: str
    evidence_generation: int
```

Expose these state APIs:

```python
@property
def pending_generated_restart(self) -> GeneratedRestartReceipt | None: ...

def consume_generated_restart(
    self,
    *,
    consumer: GeneratedRestartConsumer,
) -> GeneratedRestartReceipt | None: ...

@property
def native_mutation_quarantined(self) -> bool: ...
```

`native_mutation_quarantined` is true while poison recovery is pending, active, or exhausted for the current evidence generation. Preserve `pending_generated_restart_generation` and `pending_generated_restart_family` only as read-only compatibility properties if current callers still require them; the receipt is the sole stored authority.

- [ ] Add failing unit tests that request `EVIDENCE_REBIND`, assert the complete receipt, reject manager consumption without clearing it, and allow flowchart consumption.

- [ ] Add failing unit tests that request `POISON_RECOVERY`, assert unchanged evidence generation, reject flowchart consumption without clearing it, allow manager consumption, and keep quarantine active after consumption.

- [ ] Add a failing test for a second poison in the same evidence epoch: it marks exhaustion, returns no new receipt, and keeps quarantine active.

- [ ] Add a failing test for evidence discovered after an evidence-rebind request: advancing the evidence generation updates the pending receipt generation while retaining its family and reason.

- [ ] Run the focused test and confirm the new imports/API fail before implementation:

```bash
cd /Users/mahmoud/src/idapro/d810/.worktrees/poison-restart-architecture
PYTHONPATH=src python3 -m pytest tests/unit/analyses/control_flow/test_native_preanalysis_session.py -q
```

Expected: failures for missing `GeneratedRestartKind`, `GeneratedRestartConsumer`, receipt projection, and typed consumption.

- [ ] Implement the enum, receipt validation, typed request construction, owner-to-kind admission table, typed consumption, compatibility projections, and quarantine predicate.

The admission table must be explicit:

```python
_RESTART_KIND_BY_CONSUMER = {
    GeneratedRestartConsumer.FLOWCHART: GeneratedRestartKind.EVIDENCE_REBIND,
    GeneratedRestartConsumer.MANAGER: GeneratedRestartKind.POISON_RECOVERY,
}
```

Wrong-owner consumption returns `None` and records an abstention transition; it must not clear the receipt or increment `generated_restart_consumed_count`.

- [ ] Migrate every existing `consume_generated_restart()` caller to an explicit `GeneratedRestartConsumer`. Use `FLOWCHART` only in the computed-goto flowchart handler and `MANAGER` only in tests that model controller-owned poison recovery. Update the old hook test so it proves a poison receipt cannot produce `MERR_REDO`; do not preserve the incorrect behavior behind a compatibility default.

- [ ] Re-run the focused unit test plus the migrated system-runtime consumers and require all tests to pass:

```bash
cd /Users/mahmoud/src/idapro/d810
./tools/scripts/run_system_tests_docker.sh test -w poison-restart-architecture -o typed_restart_consumers.txt -- tests/system/runtime/hexrays/test_decompilation_lifecycle.py tests/system/runtime/optimizers/microcode/flow/flattening/engine/test_cleanup_family.py tests/system/runtime/test_manager_native_preanalysis.py -q
```

- [ ] Commit:

```bash
git add src/d810/analyses/control_flow/native_preanalysis_session.py src/d810/optimizers/microcode/flow/jumps/computed_goto_resolver.py tests/unit/analyses/control_flow/test_native_preanalysis_session.py tests/unit/manager/test_decompilation_lifecycle.py tests/unit/hexrays/mutation/test_fragment_publication_gateway.py tests/system/runtime/hexrays/test_decompilation_lifecycle.py tests/system/runtime/optimizers/microcode/flow/flattening/engine/test_cleanup_family.py tests/system/runtime/test_manager_native_preanalysis.py
git commit -m "refactor(lifecycle): type generated restart provenance"
```

---

## Task 2: Route evidence rebinding and poison recovery to different owners

**Files:**

- Modify: `src/d810/optimizers/microcode/flow/jumps/computed_goto_resolver.py`
- Modify: `src/d810/manager/decompilation_lifecycle.py`
- Modify: `src/d810/analyses/control_flow/native_preanalysis_session.py`
- Modify: `src/d810/manager/manager.py`
- Test: `tests/system/runtime/optimizers/microcode/flow/jumps/test_resolver_session_state.py`
- Test: `tests/system/runtime/test_manager_native_preanalysis.py`
- Test: `tests/system/runtime/hexrays/test_decompilation_lifecycle.py`

### Interfaces

Project the state authority through the coordinator:

```python
def pending_generated_restart(
    self,
    function_ea: int,
) -> GeneratedRestartReceipt | None: ...

def consume_generated_restart(
    self,
    function_ea: int,
    *,
    consumer: GeneratedRestartConsumer,
) -> GeneratedRestartReceipt | None: ...

def native_mutation_quarantined(self, function_ea: int) -> bool: ...
```

The flowchart handler derives its redo reason from the consumed receipt rather than a hard-coded computed-goto label:

```python
receipt = state.native_preanalysis.consume_generated_restart(
    consumer=GeneratedRestartConsumer.FLOWCHART,
)
if receipt is not None:
    request_hexrays_redo(
        decision,
        f"{receipt.evidence_family}_evidence_rebind",
        function_ea=function_ea,
        evidence_generation=receipt.evidence_generation,
    )
```

The manager consumes only `POISON_RECOVERY` after the poisoned `decompile()` returns, closes the discarded collector, invalidates the cached cfunc on the next loop iteration, and performs exactly one fresh recovery decompile. It must not route poison through `MERR_REDO`.

- [ ] Change the resolver system test first so it asserts exact evidence-family provenance and proves a poison receipt remains pending after flowchart processing.

- [ ] Add manager tests with a fake `decompile()` sequence that prove:

  - an evidence receipt is consumed by the flowchart path;
  - a poison receipt is consumed by the manager after round one;
  - the recovery round calls `decompile()` once more without invoking `request_hexrays_redo`;
  - the discarded stage-C collector closes before retry;
  - a second poison raises the existing refusal error and never returns poisoned output.

- [ ] Run the focused system-runtime tests and confirm they fail against the old generic consumer:

```bash
cd /Users/mahmoud/src/idapro/d810
./tools/scripts/run_system_tests_docker.sh test -w poison-restart-architecture -o poison_restart_routing_red.txt -- tests/system/runtime/optimizers/microcode/flow/jumps/test_resolver_session_state.py tests/system/runtime/test_manager_native_preanalysis.py -q
```

Expected: poison is still consumed by flowchart and the hard-coded `computed_goto_calls_evidence_rebind` assertion exposes the defect.

- [ ] Implement coordinator projections, owner-specific flowchart consumption, and manager-owned poison recovery.

- [ ] Split the manager's retry accounting into evidence-rebind and poison-recovery budgets. Do not let the existing aggregate five-round loop silently become the safety contract; assert one poison recovery explicitly.

- [ ] Include restart observability fields on request and consumption: `restart_kind`, `evidence_family`, `requester`, `consumer`, `evidence_generation_before`, `evidence_generation_after`, `native_inputs_changed`, and `recovery_mode` (`merr_redo` or `fresh_decompile`). For poison recovery, `native_inputs_changed` is false.

- [ ] Re-run the focused tests and require them to pass.

- [ ] Commit:

```bash
git add src/d810/optimizers/microcode/flow/jumps/computed_goto_resolver.py src/d810/manager/decompilation_lifecycle.py src/d810/manager/manager.py tests/system/runtime/optimizers/microcode/flow/jumps/test_resolver_session_state.py tests/system/runtime/test_manager_native_preanalysis.py tests/system/runtime/hexrays/test_decompilation_lifecycle.py
git commit -m "fix(lifecycle): route poison recovery through manager"
```

---

## Task 3: Stop optimizer and LOCOPT mutation work after poison

**Files:**

- Modify: `src/d810/manager/decompilation_lifecycle.py`
- Modify: `src/d810/hexrays/hooks/optinsn_adapter.py`
- Modify: `src/d810/hexrays/hooks/optblock_adapter.py`
- Modify: `src/d810/hexrays/hooks/hexrays_hooks.py`
- Modify: `src/d810/hexrays/hooks/ctree_hooks.py`
- Add: `tests/system/runtime/hexrays/test_poison_mutation_quarantine.py`
- Modify: `tests/system/runtime/hexrays/test_call_result_carrier_restore.py`
- Modify: `tests/system/runtime/test_ctree_hooks.py`

### Interfaces

Add a coordinator helper that both answers the predicate and emits one event per current-MBA generation/maturity boundary:

```python
def observe_native_mutation_quarantine(
    self,
    *,
    function_ea: int,
    maturity: int,
    boundary: NativeMutationBoundary,
) -> bool: ...
```

Define `NativeMutationBoundary` in `native_preanalysis_session.py` with `OPTINSN`, `OPTBLOCK`, `LOCOPT`, and `CTREE` members rather than using arbitrary strings. Deduplicate logs by `(current_mba_generation, maturity, boundary)` in the active session.

At the very start of `InstructionOptimizerManager.func`, before `log_info_on_input`, nested visitors, or optimizer invocation:

```python
if lifecycle is not None and lifecycle.observe_native_mutation_quarantine(
    function_ea=function_ea,
    maturity=journal_maturity,
    boundary=NativeMutationBoundary.OPTINSN,
):
    return False
```

At the very start of `BlockOptimizerManager.func`, before `_func()` and therefore before `synchronize_explicit_goto_flag`:

```python
if lifecycle is not None and lifecycle.observe_native_mutation_quarantine(
    function_ea=function_ea,
    maturity=maturity,
    boundary=NativeMutationBoundary.OPTBLOCK,
):
    return 0
```

In `HexraysDecompilationHook.locopt`, retain read-only lifecycle/session setup but omit live identity binding, mutation gateway creation, and `HEXRAYS_LOCOPT_READY` mutation dispatch when quarantined. In `CtreeOptimizerManager.on_maturity`, keep `capture_ctree()` and `analyze_current_function()` but return before iterating any ctree rule when `CTREE` is quarantined.

- [ ] Add adapter tests using object-constructed managers and counting fakes. Stage poison, call each callback repeatedly, and assert:

  - instruction optimizer count is zero;
  - nested visitor count is zero;
  - block optimizer count is zero;
  - pass-pipeline count is zero;
  - explicit-goto synchronization count is zero;
  - ctree optimizer count is zero;
  - callback returns the documented no-change value;
  - one quarantine event is emitted per MBA generation/maturity/boundary, not per instruction or block.

- [ ] Add a LOCOPT test that proves read-only lifecycle callback completion still occurs but no mutation gateway is created or passed to a mutation provider while quarantined.

- [ ] Run the focused Docker tests and confirm the counting fakes are invoked before implementation:

```bash
cd /Users/mahmoud/src/idapro/d810
./tools/scripts/run_system_tests_docker.sh test -w poison-restart-architecture -o poison_adapter_quarantine_red.txt -- tests/system/runtime/hexrays/test_poison_mutation_quarantine.py tests/system/runtime/hexrays/test_call_result_carrier_restore.py tests/system/runtime/test_ctree_hooks.py -q
```

- [ ] Implement the coordinator deduplication and the three early gates. Do not wrap the whole callback in a new exception path.

- [ ] Re-run the focused tests and require them to pass.

- [ ] Commit:

```bash
git add src/d810/analyses/control_flow/native_preanalysis_session.py src/d810/manager/decompilation_lifecycle.py src/d810/hexrays/hooks/optinsn_adapter.py src/d810/hexrays/hooks/optblock_adapter.py src/d810/hexrays/hooks/hexrays_hooks.py src/d810/hexrays/hooks/ctree_hooks.py tests/system/runtime/hexrays/test_poison_mutation_quarantine.py tests/system/runtime/hexrays/test_call_result_carrier_restore.py tests/system/runtime/test_ctree_hooks.py
git commit -m "fix(hexrays): quarantine mutation callbacks after poison"
```

---

## Task 4: Make the shared mutation gateway a quarantine backstop

**Files:**

- Modify: `src/d810/hexrays/mutation/fragment_publication_lifecycle.py`
- Modify: `src/d810/manager/fragment_publication_lifecycle.py`
- Modify: `src/d810/hexrays/mutation/mba_mutation_events.py`
- Modify: `src/d810/hexrays/mutation/semantic_fragment_publication.py`
- Test: `tests/unit/hexrays/mutation/test_fragment_publication_gateway.py`

### Interfaces

Extend the lifecycle protocol and manager implementation:

```python
@property
def native_mutation_quarantined(self) -> bool: ...
```

Add a typed rejection owned by the publication layer:

```python
class NativeMutationQuarantined(RuntimeError):
    pass
```

Add `MbaMutationGateway._require_mutation_permitted()` and call it from `new_transaction()`, `begin_batch()`, and `begin_patch_realization()` before any active-batch fields or live backend state change. `execute_patch_transaction()` also checks the lifecycle authority before recording a planned attempt so a gateway created just before poison cannot publish afterward.

- [ ] Add a failing unit test that creates a gateway while mutation is permitted, stages poison afterward, then proves `new_transaction`, `begin_batch`, `begin_patch_realization`, and `execute_patch_transaction` all raise `NativeMutationQuarantined` with no planned, staged, committed, or backend-apply events.

- [ ] Add a control test proving a non-quarantined gateway still enters and commits an ordinary transaction.

- [ ] Run the focused unit test and confirm the backstop test fails:

```bash
cd /Users/mahmoud/src/idapro/d810/.worktrees/poison-restart-architecture
PYTHONPATH=src python3 -m pytest tests/unit/hexrays/mutation/test_fragment_publication_gateway.py -q
```

- [ ] Implement the protocol property, manager projection, typed rejection, and gateway checks. Keep the adapter gates from Task 3; this is defense in depth for a race between planning and publication.

- [ ] Re-run the focused test and require it to pass.

- [ ] Commit:

```bash
git add src/d810/hexrays/mutation/fragment_publication_lifecycle.py src/d810/manager/fragment_publication_lifecycle.py src/d810/hexrays/mutation/mba_mutation_events.py src/d810/hexrays/mutation/semantic_fragment_publication.py tests/unit/hexrays/mutation/test_fragment_publication_gateway.py
git commit -m "fix(mutation): reject publications during poison quarantine"
```

---

## Task 5: Reject effect-losing `fake_jump` plans before live apply

**Files:**

- Modify: `src/d810/optimizers/microcode/flow/flattening/engine/executor.py`
- Modify: `tests/system/runtime/optimizers/microcode/flow/flattening/engine/test_runtime.py`

### Interfaces

Reuse the existing portable proof:

```python
from d810.analyses.control_flow.graph_checks import (
    check_effectful_reachability_preserved,
)
```

In `_run_preflight`, immediately after terminal reachability and before fake-jump entry-ratio heuristics or patch-plan compilation:

```python
effectful = check_effectful_reachability_preserved(pre_cfg, post_adj=sim_adj)
if not effectful.passed:
    result = StageResult(
        strategy_name=fragment.strategy_name,
        success=False,
        error=f"semantic preflight: {effectful.reason}",
        failure_phase="preflight",
    )
    result.metadata["effectful_reachability"] = effectful
    result.metadata["lost_effectful_ea_anchors"] = tuple(
        pre_cfg.get_block(serial).start_ea
        for serial in sorted(effectful.lost_block_serials)
    )
    return modifications, None, result, 0
```

Apply this proof inside the existing `fake_jump` preflight branch. Do not broaden other strategy contracts in this change; their projection semantics need separate evidence and tests.

- [ ] Add a failing executor test with a portable graph where a fake-jump redirect leaves terminal reachability intact but strands a reachable `InsnKind.CALL` block at EA `0x7FF85662A96E`.

- [ ] Make the test assert:

  - `failure_phase == "preflight"`;
  - metadata contains the lost serial and EA anchor;
  - patch-plan compilation returns `None`;
  - backend construction/apply count is zero;
  - mutation gateway begin count is zero;
  - no poison restart is requested.

- [ ] Add safe CALL-preserving and effect-free-dead-block controls so the gate does not become generic reachability preservation.

- [ ] Run the focused Docker test and confirm the unsafe plan reaches the backend before implementation:

```bash
cd /Users/mahmoud/src/idapro/d810
./tools/scripts/run_system_tests_docker.sh test -w poison-restart-architecture -o fake_jump_effectful_preflight_red.txt -- tests/system/runtime/optimizers/microcode/flow/flattening/engine/test_runtime.py -q
```

- [ ] Implement the proof call, EA-anchored diagnostics, and clean `StageResult` rejection.

- [ ] Re-run the focused test and require it to pass.

- [ ] Commit:

```bash
git add src/d810/optimizers/microcode/flow/flattening/engine/executor.py tests/system/runtime/optimizers/microcode/flow/flattening/engine/test_runtime.py
git commit -m "fix(unflat): preflight effectful reachability"
```

---

## Task 6: Commit the exact MASM regression and semantic system assertion

**Files:**

- Add: `samples/src/masm/sub_7FF856629E30.asm` (or the IDB's resolved exported name)
- Modify: `tests/system/cases/libobfuscated_comprehensive.py`
- Add: `tests/system/e2e/test_poison_restart_regression.py`
- Preserve generated evidence under: `.tmp/poison-restart-architecture/` (uncommitted)

### Fixture flow

Use the live IDB named by MCP instance `13337`:

```text
/Volumes/code/re/eid/115.9.6910.9/MMORPG_loader-115.9.6910.9-devirt.dll.i64
```

Run the existing structural exporter in the live IDA process through its MCP Python tool, then continue through the existing build/register flow:

```python
# Execute with mcp__ida_1337_local__py_eval.
from pathlib import Path
from d810.ui.export_disasm_masm_emit import generate_masm_for_function

out = Path(
    "/Users/mahmoud/src/idapro/d810/.worktrees/"
    "poison-restart-architecture/samples/src/masm/sub_7FF856629E30.asm"
)
out.write_text(
    generate_masm_for_function(
        0x7FF856629E30,
        materialize_data=True,
        const_data=True,
    ),
    encoding="utf-8",
)
str(out)
```

Then run the non-IDB stages locally:

```bash
cd /Users/mahmoud/src/idapro/d810/.worktrees/poison-restart-architecture
PYTHONPATH=src python3 tools/d810cli.py fixture build --idb /Volumes/code/re/eid/115.9.6910.9/MMORPG_loader-115.9.6910.9-devirt.dll.i64 --func sub_7FF856629E30
PYTHONPATH=src python3 tools/d810cli.py fixture register --idb /Volumes/code/re/eid/115.9.6910.9/MMORPG_loader-115.9.6910.9-devirt.dll.i64 --func sub_7FF856629E30 --project eidolon_v3_const_solve.json
PYTHONPATH=src python3 tools/d810cli.py fixture verify --idb /Volumes/code/re/eid/115.9.6910.9/MMORPG_loader-115.9.6910.9-devirt.dll.i64 --func sub_7FF856629E30
```

- [ ] Export the whole function with `materialize_data=True` and `const_data=True`; inspect the generated call/data closure. If the generated body contains an indirect call whose original target must be named for the semantic assertion, use `d810.testing.fixture_builder.detect_indirect_call_folds`, resolve that exact VA through MCP, and apply only the leaf/import retarget accepted by `plan_retargets`. Otherwise leave the faithful exported call intact.

- [ ] Build the fixture DLL and inspect before/after pseudocode. Hand-write the `DeobfuscationCase` assertions so they identify the effectful call/control-flow region and require the cleanup rule to abstain safely; do not accept the auto-emitted `must_change`-only case.

- [ ] Add an exact runtime test that captures structured mutation/restart events and asserts:

```python
assert unsafe_attempt.failure_phase == "preflight"
assert unsafe_attempt.lost_effectful_ea_anchors == (fixture_call_anchor,)
assert unsafe_attempt.mutation_started is False
assert unsafe_attempt.poisoned is False
assert restart_events == ()
```

Resolve `fixture_call_anchor` from the exported function's named call block. The linker may change the image base, so the assertion must derive the stable fixture anchor rather than compare an unrelated original VA.

- [ ] Run the exact fixture and e2e tests:

```bash
cd /Users/mahmoud/src/idapro/d810
./tools/scripts/run_system_tests_docker.sh system -w poison-restart-architecture -l -o poison_restart_fixture.txt -- -k 'sub_7FF856629E30 or poison_restart_regression'
./tools/scripts/run_system_tests_docker.sh test -w poison-restart-architecture -o poison_restart_e2e.txt -- tests/system/e2e/test_poison_restart_regression.py tests/system/e2e/test_libdeobfuscated_dsl.py -q
```

- [ ] Confirm the output contains no `poisoned_generation_restart`, no `computed_goto_calls_evidence_rebind` for this fixture, and no `native preanalysis poison restart exhausted`.

- [ ] Commit source and assertions only:

```bash
git add samples/src/masm/sub_7FF856629E30.asm tests/system/cases/libobfuscated_comprehensive.py tests/system/e2e/test_poison_restart_regression.py
git commit -m "test(unflat): cover poison restart regression fixture"
```

---

## Task 7: Verify architecture, regressions, and the live function

**Files:**

- Modify only if evidence reveals a defect in Tasks 1-6.
- Record uncommitted evidence under `.tmp/poison-restart-architecture/`.

- [ ] Run the complete focused local suite:

```bash
cd /Users/mahmoud/src/idapro/d810/.worktrees/poison-restart-architecture
PYTHONPATH=src python3 -m pytest tests/unit/analyses/control_flow/test_native_preanalysis_session.py tests/unit/hexrays/mutation/test_fragment_publication_gateway.py tests/unit/test_graph_checks.py -q
```

- [ ] Run the complete focused IDA suite:

```bash
cd /Users/mahmoud/src/idapro/d810
./tools/scripts/run_system_tests_docker.sh test -w poison-restart-architecture -l -o poison_restart_focused.txt -- tests/system/runtime/optimizers/microcode/flow/jumps/test_resolver_session_state.py tests/system/runtime/test_manager_native_preanalysis.py tests/system/runtime/hexrays/test_poison_mutation_quarantine.py tests/system/runtime/hexrays/test_call_result_carrier_restore.py tests/system/runtime/test_ctree_hooks.py tests/system/runtime/optimizers/microcode/flow/flattening/engine/test_runtime.py tests/system/e2e/test_poison_restart_regression.py -q
```

- [ ] Run architecture checks from the worktree:

```bash
cd /Users/mahmoud/src/idapro/d810/.worktrees/poison-restart-architecture
sg scan --config sgconfig.yml --report-style short
PYTHONPATH=src lint-imports --config .importlinter
```

- [ ] Update the knowledge graph after source changes:

```bash
cd /Users/mahmoud/src/idapro/d810/.worktrees/poison-restart-architecture
graphify update .
```

- [ ] Restart/reload the plugin from this worktree and live-decompile `0x7FF856629E30` through MCP instance `13337` using `eidolon_v3_const_solve.json`.

- [ ] Save before/after pseudocode, elapsed timing, restart events, and mutation receipts. The live acceptance evidence must show:

  - pseudocode returns successfully;
  - unsafe `fake_jump` is rejected in preflight with effectful EA anchor `0x7FF85662A96E`;
  - `mutation_started=0` and `poisoned=0` for that fragment;
  - no generated restart occurs;
  - the function is not processed twice;
  - subsequent unrelated decompilation still works.

- [ ] Run the broader relevant system regression suite:

```bash
cd /Users/mahmoud/src/idapro/d810
./tools/scripts/run_system_tests_docker.sh system -w poison-restart-architecture -l -o poison_restart_system.txt -- -k 'unflat or computed_goto or native_preanalysis or fragment_publication'
```

- [ ] Inspect every command's exit code and output. Report unrelated failures separately; do not collapse "suite started" into "suite passed".

- [ ] Confirm the worktree diff contains no generated binaries, IDBs, logs, or unrelated edits:

```bash
cd /Users/mahmoud/src/idapro/d810/.worktrees/poison-restart-architecture
git status --short
git diff --check cfg-recon-mainline...HEAD
git log --oneline cfg-recon-mainline..HEAD
```

- [ ] If all acceptance criteria are met, run the verification-before-completion and finishing-a-development-branch skills before proposing merge.
