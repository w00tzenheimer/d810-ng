# Deobfuscation Workbench - Slice 2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` and `superpowers:test-driven-development`; every command behavior starts with a focused RED.

**Goal:** Add generation-safe Analyze, Deobfuscate, and Function override commands to the workbench while preserving the existing recon, decompile, and function-rule persistence lifecycles.

**Architecture:** Immutable command request/result records join the existing manager model. `WorkbenchService` validates the latest function EA, fingerprint, and snapshot generation before and after each command. Analyze delegates to a new read-only `D810Manager.analyze_workbench_function` seam that invokes recon collection/classification directly and never reaches an optimizer, pass executor, or mutation backend. Deobfuscate and Function override accept injected zero-argument lifecycle callbacks and invoke each exactly once. `d810.ui.workbench_commands` adapts the current pseudocode context to those manager commands and reuses `DeobfuscateThisFunction` and `FunctionRules`. Pure workbench logic owns stale projection and completion acceptance; the panel only marks, dispatches, accepts/rejects, and refreshes.

## Constraints

- Implement `tcvpu-z1b4` in the existing isolated worktree. Keep `tcvpu-nyvc` open until live Slice 1 acceptance.
- Analyze may persist recon hints/session summaries, but it must not apply rule inferences, execute configured passes, invoke optimizer rules, refresh pseudocode, or call a mutation backend.
- Deobfuscate must call the existing `DeobfuscateThisFunction.execute(ctx)` once. Do not duplicate detached-snippet preparation or refresh/decompile policy.
- Function override must call the existing `FunctionRules.execute(ctx)` once. Existing `FunctionRuleConfig`, tags, notes, storage, invalidation, and one queued refresh remain authoritative.
- A request is current only when EA, fingerprint, and generation match the service's most recently collected snapshot. A stale-before request does not invoke its callback. A stale-after completion is returned but rejected by pure UI logic.
- The old snapshot is projected as `Stale` while a command is in flight. A completion cannot replace a different function or newer generation.
- No threads are introduced in this slice. The generation-aware request/result contract supports queued/async delivery without pretending the current adapters are asynchronous.
- No live IDA/Qt execution. Verify UI adapters with fakes and source contracts only.
- Add no architecture ignores.

---

### Task 1: Add immutable command and stale-result vocabulary

**Files:**

- Update: `src/d810/manager/workbench_models.py`
- Update: `src/d810/manager/__init__.py`
- Update: `tests/unit/manager/test_workbench_models.py`

**Records:**

```python
@dataclass(frozen=True, slots=True)
class WorkbenchCommandRequest:
    command: str
    function_ea: int
    expected_generation: int
    function_fingerprint: str | None

@dataclass(frozen=True, slots=True)
class WorkbenchCommandResult:
    command: str
    function_ea: int
    requested_generation: int
    function_fingerprint: str | None
    status: OutcomeStatus
    succeeded: bool
    accepted: bool
    refresh_requested: bool
    message: str
```

- [ ] Add failing frozen/slotted/tuple-safe model tests and public leaf exports.
- [ ] Implement the records and commit `feat(workbench): define generation-safe commands`.

---

### Task 2: Add manager-owned command validation and read-only Analyze

**Files:**

- Update: `src/d810/manager/workbench_service.py`
- Update: `src/d810/manager/manager.py`
- Update: `src/d810/manager/state.py`
- Update: `tests/unit/manager/test_workbench_service.py`

**Interfaces:**

```python
class D810Manager:
    def analyze_workbench_function(
        self, *, function_ea: int, target: object, provider_phase: object,
    ) -> object:
        """Call recon_runtime.collect_and_analyze with persist_hints=True."""

class WorkbenchService:
    def execute_analyze(
        self, request: WorkbenchCommandRequest, *, target: object,
        provider_phase: object,
    ) -> WorkbenchCommandResult:
        """Validate, invoke the read-only manager seam, and revalidate."""

    def execute_deobfuscate(
        self, request: WorkbenchCommandRequest, *, lifecycle: Callable[[], bool],
    ) -> WorkbenchCommandResult:
        """Validate and invoke the existing lifecycle exactly once."""

    def execute_function_override(
        self, request: WorkbenchCommandRequest, *, lifecycle: Callable[[], bool],
    ) -> WorkbenchCommandResult:
        """Validate and invoke the existing override action exactly once."""
```

- [ ] Test that `collect` records latest EA/fingerprint/generation.
- [ ] Test stale-before rejects all three commands without invoking recon or callbacks.
- [ ] Test Analyze calls `collect_and_analyze(function_ea, target, provider_phase, persist_hints=True)` once and has no optimizer/mutation imports or calls.
- [ ] Test Deobfuscate and Function override callbacks are called exactly once; false/exception results become `Failed` without a second attempt.
- [ ] Test revalidation catches a generation changed inside a callback and returns `Stale`/`accepted=False`.
- [ ] Add state facade methods that delegate to `manager.workbench_service`; state contains no command policy.
- [ ] Implement and commit `feat(workbench): add scoped manager commands`.

---

### Task 3: Add pure stale and action decisions

**Files:**

- Update: `src/d810/ui/workbench_logic.py`
- Update: `tests/unit/ui/test_workbench_logic.py`

**Interfaces:**

```python
def command_request(snapshot, command: str) -> WorkbenchCommandRequest:
    """Bind the command to current EA, fingerprint, and generation."""

def stale_snapshot(snapshot) -> DeobfuscationWorkbenchSnapshot:
    """Return a frozen copy with freshness and every pass/consumer status Stale."""

def should_accept_command_result(snapshot, result) -> bool:
    """Require accepted result plus exact EA, fingerprint, and generation identity."""
```

- [ ] Test action states now enable Analyze and Deobfuscate only for a current started engine, and enable Function override for a current function. Compare/Recipe/Diagnostics remain disabled.
- [ ] Test stale snapshots disable scoped commands, retain evidence payloads, and label pass/consumer outcomes `Stale`.
- [ ] Test completion acceptance across every EA/fingerprint/generation/accepted mismatch.
- [ ] Implement and commit `feat(ui): enforce workbench command freshness`.

---

### Task 4: Adapt current pseudocode context to existing lifecycles

**Files:**

- Create: `src/d810/ui/workbench_commands.py`
- Create: `tests/unit/ui/test_workbench_commands.py`

**Adapter:**

```python
class WorkbenchCommandAdapter:
    def __init__(self, state: object, idaapi_shim: object, ctx: object) -> None:
        """Retain the current action context and injected IDA shim."""

    def analyze(self, request: WorkbenchCommandRequest) -> WorkbenchCommandResult:
        """Read current cfunc.mba, build ProviderPhaseSnapshot, call state Analyze."""

    def deobfuscate(self, request: WorkbenchCommandRequest) -> WorkbenchCommandResult:
        """Wrap exactly one DeobfuscateThisFunction.execute(ctx) call."""

    def function_override(self, request: WorkbenchCommandRequest) -> WorkbenchCommandResult:
        """Wrap exactly one FunctionRules.execute(ctx) call."""
```

- [ ] Test Analyze passes the current MBA/provider phase and never calls refresh/decompile itself.
- [ ] Test Deobfuscate and Function override instantiate their established actions with the injected shim and execute once.
- [ ] Keep action imports lazy so the adapter remains importable outside IDA.
- [ ] Implement and commit `feat(ui): adapt workbench commands to existing actions`.

---

### Task 5: Wire panel dispatch and Stats context injection

**Files:**

- Update: `src/d810/ui/workbench_panel.py`
- Update: `src/d810/ui/actions/deobfuscation_stats.py`
- Update: `tests/unit/ui/test_workbench_adapter_contract.py`
- Update: `tests/unit/ui/test_actions_migration.py`

- [ ] Test the panel exposes `set_command_adapter`, adds Function override, binds enabled buttons, creates a pure request, renders a stale copy before dispatch, accepts only matching results, and refreshes once after accepted completions.
- [ ] Test the Stats compatibility action injects `WorkbenchCommandAdapter(state, idaapi, ctx)` while preserving action ID and evidence focus.
- [ ] Implement without lifecycle policy in widget callbacks and commit `feat(ui): wire scoped workbench interaction`.

---

### Task 6: Verify and record deferred runtime acceptance

- [ ] Run all workbench manager/UI tests plus existing deobfuscate/function-rules action tests.
- [ ] Run the full unit suite, ast-grep, import-linter, diff check, prohibited-import scan, and graph update.
- [ ] Confirm no Analyze path contains `refresh_view`, `decompile`, optimizer execution, configured-pass execution, or mutation-backend calls.
- [ ] Record evidence on `tcvpu-z1b4`; keep live command/dock behavior open for the later user-directed Qt session.
