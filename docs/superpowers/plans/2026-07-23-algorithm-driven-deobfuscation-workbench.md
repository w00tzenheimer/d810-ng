# Algorithm-Driven Deobfuscation Workbench Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Re-engineer the function-centric Workbench around the algorithmic workflow `observe -> characterize -> validate -> choose the smallest strategy -> execute -> verify`, with the two user-facing entry points **Build Deobfuscator** and **Deobfuscate Function**.

**Architecture:** The manager owns immutable case snapshots and command validation; a read-only diagnostics repository projects schema-versioned evidence into those snapshots; pure UI logic maps snapshots to workflow decisions; Qt renders the decisions and forwards commands. The Rhad lifecycle work remains the producer of portable evidence, normalization plans, fragment receipts, and typed rejection records. This feature must consume that data without importing its live mutation implementation or parsing log text.

**Tech Stack:** Python 3.13, IDA PluginForm, PyQt5/PyQt6 through `d810.qt_shim`, SQLite diagnostic snapshots, pytest, ast-grep, import-linter, XQuartz Docker IDA 9.1 and 9.3.

## Global Constraints

- Implement in `/Users/mahmoud/src/idapro/d810/.worktrees/truthful-config-v2-project-ui`; do not edit the active `/Users/mahmoud/src/idapro/d810/.worktrees/lifecycle-resolver-evidence-authority` worktree.
- The implementation consumes a versioned, read-only diagnostics contract. It must not read text logs, inspect a live `mba_t`, or infer receipt status from pseudocode text.
- Preserve the existing manager/action path for actual deobfuscation. The Workbench never mutates microcode directly.
- **Build Deobfuscator** means build and validate a strategy from registered capabilities; it never authors Python pass implementations inside IDA.
- **Deobfuscate Function** may run only a current saved recipe or a current recommended strategy. A user may still inspect or edit a recipe, but an unknown mechanism must not be presented as a recommended direct attack.
- C0-C5 are evidence/progress levels, not deobfuscation success. Only C6 may use `Semantic result verified`; a text difference, receipt, plan, or rule firing is not semantic verification.
- Every displayed microcode-block identity includes a native EA anchor. Case evidence must retain uncertainty, confidence, provenance, and typed abstention/rejection reasons.
- Function rules and saved function recipes remain separate persistence objects. Diagnostic case evidence is derived run data and is never silently saved as a rule override or recipe.
- Preserve PyQt5/IDA 9.1 and PyQt6/IDA 9.3 compatibility using ordinary widgets and `d810.qt_shim`; no emoji, font-dependent glyphs, or model-specific Qt APIs.
- New pure logic receives direct unit tests under `tests/unit/`; unit tests must not import `d810.ui` or `d810.hexrays`.
- Do not add ast-grep ignores or import-linter exceptions. Run `sg scan --config sgconfig.yml --report-style short` and `PYTHONPATH=src lint-imports --config .importlinter` from this worktree before each completion claim.

## Delivery Boundaries

The previous guided attack card is intentionally superseded, not deleted. Its safe command identity, stale-result handling, refresh-before-comparison ordering, and function-recipe behavior are retained. What changes is the entry decision: the old card assumed that the direct action was normally correct; the new case workflow chooses between non-mutating strategy construction and an established direct run.

The active Rhad work already defines the required evidence trajectory:

```text
observation
-> hypothesis
-> validation
-> portable evidence
-> normalization / canonical-pass decision
-> FragmentPlan
-> staged validation
-> publication receipt
-> semantic verification
```

The Workbench consumes that trajectory as a stable data contract. It must not display the Rhad implementation phases as an end-user wizard and must not block ordinary, non-Rhad attacks on a Rhad-specific milestone.

## File Structure

| File | Responsibility |
|-|-|
| `src/d810/core/deobfuscation_case.py` | Portable immutable vocabulary for observations, hypotheses, evidence, strategy recommendations, execution stages, verdicts, and diagnostic identities. |
| `src/d810/diagnostics/deobfuscation_case_repository.py` | Read-only projection from typed diagnostic SQLite records to `DeobfuscationCaseEvidence`; rejects incomplete schema and never reads logs. |
| `src/d810/manager/deobfuscation_case_service.py` | Combines current function/runtime identity, saved recipe state, and diagnostic evidence into a current `DeobfuscationCaseSnapshot`. |
| `src/d810/manager/workbench_models.py` | Adds the manager-owned `case` field and exact command vocabulary to the existing immutable Workbench snapshot. |
| `src/d810/manager/workbench_service.py` | Validates and executes the read-only `build_deobfuscator` command; retains the existing `deobfuscate` command identity. |
| `src/d810/manager/manager.py` and `src/d810/manager/state.py` | Own and expose the case service through thin state facades. |
| `src/d810/manager/deobfuscation_case_workflow.py` | Pure, Qt-free projection from a snapshot to labels, enabled actions, evidence rows, and next-step explanations. |
| `src/d810/ui/workbench_workflow_logic.py` | Compatibility facade that re-exports the direct-run freshness transition from the manager-owned case workflow. |
| `src/d810/ui/workbench_commands.py` | Adapts a current pseudocode context to the new non-mutating build command and existing direct command. |
| `src/d810/ui/workbench_panel.py` | Renders the two entry points, stage rail, case summary, and contextual actions using the pure view model. |
| `src/d810/manager/workbench_recipe_models.py`, `src/d810/manager/workbench_recipe_service.py`, `src/d810/ui/workbench_recipe_logic.py`, `src/d810/ui/workbench_recipe_panel.py` | Adds display-only workflow-stage metadata to registered passes and makes Recipe Composer a strategy-construction companion. |
| `src/d810/ui/workbench_diagnostics_logic.py`, `src/d810/ui/workbench_diagnostics_commands.py`, `src/d810/ui/workbench_diagnostics_panel.py`, `src/d810/ui/workbench_diagnostic_graph.py` | Adds case-timeline projection, canary comparison, and evidence-lineage graph projection without changing cleanup semantics. |
| `tests/unit/core/test_deobfuscation_case.py` | Tests portable records and validation invariants. |
| `tests/unit/diagnostics/test_deobfuscation_case_repository.py` | Tests schema/version, typed rejection, anchor, and chronological-trace projection. |
| `tests/unit/manager/test_deobfuscation_case_service.py` | Tests manager identity, recipe reuse, current/stale behavior, and command boundaries. |
| `tests/unit/manager/test_deobfuscation_case_workflow.py` | Tests all user-visible workflow decisions without importing Qt or `d810.ui`. |
| `tests/unit/ui/test_workbench_case_panel_contract.py` | AST-level contract tests for thin Qt orchestration. |
| `tests/unit/ui/test_workbench_recipe_logic.py` and `tests/unit/ui/test_workbench_diagnostics_logic.py` | Extends strategy-stage and case-timeline presentation coverage. |

---

### Task 1: Define the portable case and diagnostic-contract vocabulary

**Files:**
- Create: `src/d810/core/deobfuscation_case.py`
- Create: `tests/unit/core/test_deobfuscation_case.py`

**Interfaces:**
- Consumes: only stdlib dataclasses/enums and scalar native-EA identities.
- Produces: `CaseEvidenceLevel`, `CaseFindingKind`, `StrategyWorkflowStage`, `CaseFinding`, `CaseHypothesis`, `StrategyDeficiency`, `StrategyRecommendation`, `CaseExecution`, `CaseVerdict`, `DeobfuscationCaseEvidence`, and `DeobfuscationCaseSnapshot`.

- [ ] **Step 1: Write the failing portable-model tests**

```python
from d810.core.deobfuscation_case import (
    CaseEvidenceLevel,
    CaseFinding,
    CaseFindingKind,
    CaseVerdict,
)


def test_finding_requires_a_native_anchor_when_it_names_a_block() -> None:
    with pytest.raises(ValueError, match="native anchor"):
        CaseFinding(
            finding_id="route-1",
            kind=CaseFindingKind.PORTABLE_EVIDENCE,
            summary="state route",
            detail="",
            native_ea=None,
            confidence=1.0,
            provenance=(),
        )


def test_c5_receipt_is_progress_not_semantic_success() -> None:
    verdict = CaseVerdict(
        level=CaseEvidenceLevel.C5_PUBLICATION,
        summary="publication receipt committed",
        first_blocked_obligation=None,
    )

    assert verdict.semantic_verified is False
```

Add cases proving that C6 requires an explicit semantic witness, an unresolved question remains distinct from a rejected finding, and every `StrategyRecommendation` names a deficiency rather than a profile/vendor.

- [ ] **Step 2: Run the new tests and verify the missing module fails**

Run:

```bash
PYTHONPATH=src pytest tests/unit/core/test_deobfuscation_case.py -q
```

Expected: collection fails because `d810.core.deobfuscation_case` does not exist.

- [ ] **Step 3: Implement immutable, backend-neutral records**

```python
class CaseEvidenceLevel(str, enum.Enum):
    C0_ENVIRONMENT = "c0_environment"
    C1_DISCOVERY = "c1_discovery"
    C2_NORMALIZATION = "c2_normalization"
    C3_CANONICAL_PLAN = "c3_canonical_plan"
    C4_STAGED_PROOF = "c4_staged_proof"
    C5_PUBLICATION = "c5_publication"
    C6_SEMANTIC_OUTPUT = "c6_semantic_output"


@dataclasses.dataclass(frozen=True, slots=True)
class CaseFinding:
    finding_id: str
    kind: CaseFindingKind
    summary: str
    detail: str
    native_ea: int | None
    confidence: float | None
    provenance: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.kind in _ANCHOR_REQUIRED_KINDS and self.native_ea is None:
            raise ValueError("native anchor is required for this finding")
        if self.confidence is not None and not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")


@dataclasses.dataclass(frozen=True, slots=True)
class CaseVerdict:
    level: CaseEvidenceLevel
    summary: str
    first_blocked_obligation: str | None
    semantic_witness: str | None = None

    @property
    def semantic_verified(self) -> bool:
        return (
            self.level is CaseEvidenceLevel.C6_SEMANTIC_OUTPUT
            and self.semantic_witness is not None
        )


class StrategyWorkflowStage(str, enum.Enum):
    EVIDENCE_PROVIDER = "evidence_provider"
    FRONTEND_NORMALIZATION = "frontend_normalization"
    CANONICAL_ANALYSIS = "canonical_analysis"
    CANONICAL_TRANSFORM = "canonical_transform"
    BACKEND_PUBLICATION = "backend_publication"
    CANONICAL_PIPELINE = "canonical_pipeline"


@dataclasses.dataclass(frozen=True, slots=True)
class StrategyRecommendation:
    deficiency: StrategyDeficiency
    summary: str
    required_finding_ids: tuple[str, ...]
    stages: tuple[StrategyWorkflowStage, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class DeobfuscationCaseSnapshot:
    evidence: DeobfuscationCaseEvidence | None
    strategy: StrategyRecommendation | None
    direct_run_permitted: bool
    direct_run_reason: str
```

Use `CaseFindingKind` values for `observation`, `hypothesis`, `validation`, `portable_evidence`, `pass_decision`, `fragment_plan`, `receipt`, `semantic_result`, `unresolved_question`, and `rejection`. `DeobfuscationCaseEvidence` must carry a schema version, function fingerprint, runtime identity, run identity, ordered findings, and one verdict; reject empty IDs and duplicate finding IDs in `__post_init__`. The manager calculates `direct_run_permitted` only from a current saved recipe or a recommendation whose required finding IDs all remain present; the repository never grants execution permission.

- [ ] **Step 4: Verify the portable model**

Run:

```bash
PYTHONPATH=src pytest tests/unit/core/test_deobfuscation_case.py -q
```

Expected: PASS. No test imports `d810.ui`, `d810.manager`, `d810.diagnostics`, or `d810.hexrays`.

- [ ] **Step 5: Commit the portable contract**

```bash
git add src/d810/core/deobfuscation_case.py tests/unit/core/test_deobfuscation_case.py
git commit -m "feat(core): define deobfuscation case evidence"
```

### Task 2: Project typed diagnostic records into a case evidence report

**Files:**
- Create: `src/d810/diagnostics/deobfuscation_case_repository.py`
- Create: `tests/unit/diagnostics/test_deobfuscation_case_repository.py`
- Modify: `src/d810/diagnostics/workbench_models.py`

**Interfaces:**
- Consumes: the existing read-only diagnostic inventory/record reader and only typed lifecycle/plan/receipt records carrying a schema version, function identity, and native EA anchors.
- Produces: `DeobfuscationCaseRepository.load(function_ea, function_fingerprint) -> DeobfuscationCaseEvidence | None`.

- [ ] **Step 1: Freeze the diagnostic row contract in tests**

```python
def test_repository_builds_a_chronological_case_trace_from_typed_records() -> None:
    repository = DeobfuscationCaseRepository(_reader_with_records(
        _record("observation", 10, 0x1800020F0),
        _record("portable_evidence", 20, 0x1800020F0),
        _record("fragment_plan", 30, 0x1800020F0),
        _record("rejection", 40, 0x1800020F0,
                reason="unique realization failed"),
    ))

    evidence = repository.load(0x1800020F0, "sha256:fixture")

    assert [item.kind.value for item in evidence.findings] == [
        "observation", "portable_evidence", "fragment_plan", "rejection",
    ]
    assert evidence.verdict.first_blocked_obligation == "unique realization failed"
    assert evidence.verdict.level.value == "c1_discovery"
```

Add negative tests for an unsupported schema version, mismatched fingerprint, serial-only block identity, duplicate sequence numbers, and a receipt that lacks its correlated plan identity. The repository returns `None` for no matching records and raises `DeobfuscationCaseEvidenceError` for malformed matching records; it never substitutes log text.

- [ ] **Step 2: Run the repository tests and verify they fail**

Run:

```bash
PYTHONPATH=src pytest tests/unit/diagnostics/test_deobfuscation_case_repository.py -q
```

Expected: collection fails because `d810.diagnostics.deobfuscation_case_repository` does not exist.

- [ ] **Step 3: Add the repository and typed record view**

```python
class CaseDiagnosticReader(Protocol):
    def case_records(
        self,
        *,
        function_ea: int,
        function_fingerprint: str | None,
    ) -> tuple[CaseDiagnosticRow, ...]: ...


class DeobfuscationCaseRepository:
    def __init__(self, reader: CaseDiagnosticReader) -> None:
        self._reader = reader

    def load(
        self,
        function_ea: int,
        function_fingerprint: str | None,
    ) -> DeobfuscationCaseEvidence | None:
        rows = self._reader.case_records(
            function_ea=int(function_ea),
            function_fingerprint=function_fingerprint,
        )
        if not rows:
            return None
        return _project_case_evidence(rows, function_ea, function_fingerprint)
```

Add a `CaseDiagnosticRow` dataclass and `DiagnosticRecordKind.DEOBFUSCATION_CASE` plus `case_records(...)` on the diagnostics model/adapter. Require each row payload to include `case_schema_version`, `run_id`, `sequence`, `kind`, `summary`, and `function_fingerprint`; require `native_ea` for any block, route, predicate, fragment, or receipt row. Sort only by `(recorded_at, sequence, ordinal)`, so the timeline does not depend on SQLite insertion order.

- [ ] **Step 4: Verify the repository and its existing diagnostics neighbors**

Run:

```bash
PYTHONPATH=src pytest \
  tests/unit/diagnostics/test_deobfuscation_case_repository.py \
  tests/unit/diagnostics/test_workbench_models.py \
  tests/unit/diagnostics/test_workbench_inventory.py -q
```

Expected: PASS. The new repository reads diagnostic data only; no optimizer, pass, or Hex-Rays module imports diagnostic storage.

- [ ] **Step 5: Commit the read-only diagnostic projection**

```bash
git add src/d810/diagnostics/deobfuscation_case_repository.py \
  src/d810/diagnostics/workbench_models.py \
  tests/unit/diagnostics/test_deobfuscation_case_repository.py
git commit -m "feat(diagnostics): project deobfuscation case evidence"
```

### Task 3: Add a manager-owned case snapshot and non-mutating build command

**Files:**
- Create: `src/d810/manager/deobfuscation_case_service.py`
- Modify: `src/d810/manager/workbench_models.py`
- Modify: `src/d810/manager/workbench_service.py`
- Modify: `src/d810/manager/manager.py`
- Modify: `src/d810/manager/state.py`
- Create: `tests/unit/manager/test_deobfuscation_case_service.py`
- Modify: `tests/unit/manager/test_workbench_service.py`

**Interfaces:**
- Consumes: `DeobfuscationCaseRepository`, current `FunctionRef`, `RuntimeConfigRef`, current function recipe selection, and the existing manager-owned recon lifecycle.
- Produces: `DeobfuscationCaseSnapshot` on `DeobfuscationWorkbenchSnapshot.case`, `D810Manager.get_deobfuscation_case_snapshot(...)`, and the `build_deobfuscator` command result.

- [ ] **Step 1: Write manager-facing behavior tests**

```python
def test_unknown_function_offers_non_mutating_build_before_direct_run() -> None:
    snapshot = _snapshot(case=_case(level="c0_environment", strategy=None))

    result = service.execute_build_deobfuscator(
        _request("build_deobfuscator"),
        lifecycle=lambda: calls.append("analyze") or True,
    )

    assert result.accepted is True
    assert result.refresh_requested is True
    assert calls == ["analyze"]


def test_saved_current_recipe_permits_direct_run_without_overwriting_case_evidence() -> None:
    snapshot = _snapshot(case=_case(level="c1_discovery", strategy=None))
    snapshot = dataclasses.replace(snapshot, runtime=_runtime(recipe_scope="function-recipe"))

    assert snapshot.case.direct_run_permitted is True
```

Add tests that a stale function fingerprint makes the case unavailable, a malformed diagnostics report becomes a collection error rather than a guessed strategy, and `build_deobfuscator` invokes only `analyze_workbench_function` rather than the deobfuscation lifecycle.

- [ ] **Step 2: Run the focused manager tests and verify failure**

Run:

```bash
PYTHONPATH=src pytest \
  tests/unit/manager/test_deobfuscation_case_service.py \
  tests/unit/manager/test_workbench_service.py -q
```

Expected: collection fails because the case service and `build_deobfuscator` command do not exist.

- [ ] **Step 3: Implement the service and preserve existing command identity**

```python
class DeobfuscationCaseService:
    def collect(
        self,
        *,
        function: FunctionRef,
        runtime: RuntimeConfigRef,
        saved_recipe: FunctionPipelineOverride | None,
    ) -> DeobfuscationCaseSnapshot:
        evidence = self._repository.load(function.ea, function.fingerprint)
        return project_deobfuscation_case(
            function=function,
            runtime=runtime,
            saved_recipe=saved_recipe,
            evidence=evidence,
        )
```

Add `case: DeobfuscationCaseSnapshot` to `DeobfuscationWorkbenchSnapshot`. `WorkbenchService.collect(...)` calls the service after effective function-recipe selection, so the case reports the real effective runtime and saved recipe. Add `WorkbenchService.execute_build_deobfuscator(...)` using `_execute_lifecycle(..., expected_command="build_deobfuscator", label="Build Deobfuscator")`; its lifecycle callback calls only `analyze_workbench_function`.

Keep the existing internal direct command string `deobfuscate` for compatibility and persistence. The user-visible label changes in the UI task, not in manager command identity.

- [ ] **Step 4: Verify manager identity, freshness, and existing recipe behavior**

Run:

```bash
PYTHONPATH=src pytest \
  tests/unit/manager/test_deobfuscation_case_service.py \
  tests/unit/manager/test_workbench_service.py \
  tests/unit/manager/test_function_recipe_runtime.py \
  tests/unit/manager/test_workbench_recipe_service.py -q
```

Expected: PASS. A build result for a stale generation does not refresh or become a current case result.

- [ ] **Step 5: Commit the manager boundary**

```bash
git add src/d810/manager/deobfuscation_case_service.py \
  src/d810/manager/workbench_models.py \
  src/d810/manager/workbench_service.py \
  src/d810/manager/manager.py \
  src/d810/manager/state.py \
  tests/unit/manager/test_deobfuscation_case_service.py \
  tests/unit/manager/test_workbench_service.py
git commit -m "feat(manager): add deobfuscation case workflow"
```

### Task 4: Model the two-entry-point workflow in a manager-owned pure layer

**Files:**
- Create: `src/d810/manager/deobfuscation_case_workflow.py`
- Modify: `src/d810/ui/workbench_workflow_logic.py`
- Create: `tests/unit/manager/test_deobfuscation_case_workflow.py`
- Modify: `tests/unit/ui/test_workbench_workflow_logic.py`

**Interfaces:**
- Consumes: immutable manager snapshots and `WorkbenchCommandResult` values.
- Produces: `CaseWorkflowView`, `CaseActionView`, `CaseStageView`, and `project_case_workflow(...)`; it imports no IDA, Qt, or `d810.ui` module.

- [ ] **Step 1: Write all workflow-decision tests before implementation**

```python
def test_unknown_case_makes_build_deobfuscator_the_primary_action() -> None:
    view = project_case_workflow(_snapshot(level="c0_environment", strategy=None))

    assert view.primary.action_id == "build_deobfuscator"
    assert view.primary.label == "Build Deobfuscator"
    assert view.direct.action_id == "deobfuscate"
    assert view.direct.enabled is False
    assert "Build a strategy" in view.direct.reason


def test_validated_recommendation_makes_deobfuscate_function_available() -> None:
    view = project_case_workflow(_snapshot(
        level="c1_discovery",
        strategy=_strategy(deficiency="cfg_formation"),
    ))

    assert view.primary.action_id == "deobfuscate"
    assert view.primary.label == "Deobfuscate Function"
    assert view.build.label == "Build Deobfuscator"


def test_c5_receipt_names_publication_without_claiming_semantic_success() -> None:
    view = project_case_workflow(_snapshot(level="c5_publication"))

    assert view.verdict.label == "Publication receipt committed"
    assert "deobfuscated" not in view.verdict.detail.casefold()
```

Cover no selected function, stopped engine, stale snapshot, active build, active direct run, typed rejection with a first blocked obligation, C6 semantic witness, and a saved current recipe with no automatic recommendation.

- [ ] **Step 2: Verify the pure logic tests fail**

Run:

```bash
PYTHONPATH=src pytest \
  tests/unit/manager/test_deobfuscation_case_workflow.py \
  tests/unit/ui/test_workbench_workflow_logic.py -q
```

Expected: collection fails because `d810.manager.deobfuscation_case_workflow` does not exist and existing workflow labels still use the retired copy.

- [ ] **Step 3: Implement the projection and migrate the attack-card state machine**

```python
class CaseWorkflowPhase(str, enum.Enum):
    UNAVAILABLE = "unavailable"
    BUILD = "build"
    STRATEGY_READY = "strategy_ready"
    RUNNING = "running"
    INVESTIGATE = "investigate"
    VERDICT = "verdict"


def project_case_workflow(
    snapshot: DeobfuscationWorkbenchSnapshot | None,
    *,
    last_result: WorkbenchCommandResult | None = None,
    running_command: str | None = None,
) -> CaseWorkflowView:
    if snapshot is None:
        return _unavailable("Select a pseudocode function.")
    if snapshot.freshness is not SnapshotFreshness.CURRENT:
        return _unavailable("Refresh the stale workbench snapshot.")
    if not snapshot.engine_started:
        return _unavailable("Start D810 before building or running a deobfuscator.")
    return _current_case_view(snapshot.case, last_result, running_command)
```

Project the fixed stage rail in algorithm order: `Dossier`, `Hypotheses`, `Validated evidence`, `Strategy`, `Execution`, `Verdict`. Each stage has `not started`, `ready`, `blocked`, `complete`, or `unavailable` status based only on case records. Move `recommended_attack_transition(...)` into this manager-owned module as the sole pure decision for accepted direct-run refresh/comparison sequencing, and generalize it only to reject stale/mismatched build results as well. Keep `d810.ui.workbench_workflow_logic` as a compatibility facade that imports and re-exports the transition and its view types, so existing UI callers continue to work while no new unit test imports `d810.ui`.

- [ ] **Step 4: Verify pure logic and legacy safety coverage**

Run:

```bash
PYTHONPATH=src pytest \
  tests/unit/manager/test_deobfuscation_case_workflow.py \
  tests/unit/ui/test_workbench_workflow_logic.py \
  tests/unit/ui/test_workbench_logic.py -q
```

Expected: PASS. No test asserts that C1-C5 imply semantic correctness.

- [ ] **Step 5: Commit the pure workflow decision layer**

```bash
git add src/d810/manager/deobfuscation_case_workflow.py \
  src/d810/ui/workbench_workflow_logic.py \
  tests/unit/manager/test_deobfuscation_case_workflow.py \
  tests/unit/ui/test_workbench_workflow_logic.py
git commit -m "feat(ui): model build and deobfuscate workflow"
```

### Task 5: Render the case workflow and wire the two actions through existing adapters

**Files:**
- Modify: `src/d810/ui/workbench_commands.py`
- Modify: `src/d810/ui/workbench_panel.py`
- Create: `tests/unit/ui/test_workbench_case_panel_contract.py`
- Modify: `tests/unit/ui/test_workbench_commands.py`
- Modify: `tests/unit/ui/test_workbench_panel_contract.py`

**Interfaces:**
- Consumes: `CaseWorkflowView`, `D810State.execute_workbench_build_deobfuscator(...)`, existing `execute_workbench_deobfuscate(...)`, and the established comparison/recipe/diagnostics adapters.
- Produces: a thin PluginForm that renders the case workflow and performs no state inference in Qt callbacks.

- [ ] **Step 1: Write adapter and AST-level panel contracts**

```python
def test_build_deobfuscator_passes_current_mba_to_manager_without_deobfuscating() -> None:
    result = adapter.build_deobfuscator(_request("build_deobfuscator"))

    assert result.succeeded is True
    assert state_calls == [(request, mba, provider_phase)]
    assert deobfuscate_action_calls == []


def test_panel_renders_case_workflow_from_pure_logic() -> None:
    source = _method_source("_render_case_workflow")

    assert "project_case_workflow" in source
    assert "self.build_deobfuscator_button.setText(view.build.label)" in source
    assert "self.deobfuscate_function_button.setText(view.direct.label)" in source
    assert "snapshot.case" not in source
```

Add contracts proving `_run_build_deobfuscator()` calls `_run_command("build_deobfuscator", refresh_after=True)`, `_run_deobfuscate_function()` uses `_run_command("deobfuscate", refresh_after=False)`, and the latter retains refresh-before-comparison ordering.

- [ ] **Step 2: Run the UI contracts and verify failure**

Run:

```bash
PYTHONPATH=src pytest \
  tests/unit/ui/test_workbench_commands.py \
  tests/unit/ui/test_workbench_case_panel_contract.py \
  tests/unit/ui/test_workbench_panel_contract.py -q
```

Expected: FAIL because the build adapter and case renderer do not exist.

- [ ] **Step 3: Add the thin build adapter and replace the attack group**

```python
def build_deobfuscator(
    self,
    request: WorkbenchCommandRequest,
) -> WorkbenchCommandResult:
    return self._state.execute_workbench_build_deobfuscator(
        request,
        target=self._current_mba_for(request),
        provider_phase=self._current_provider_phase_for(request),
    )
```

Replace the old `Attack` group with `Deobfuscation workflow`. It contains a one-line case headline, the six-stage rail, compact evidence/blocked-obligation summary, **Build Deobfuscator**, and **Deobfuscate Function**. The former runs a non-mutating analysis and refreshes; the latter uses the current established action and preserves the existing baseline/comparison safety logic. Keep Recipe, Diagnostics, function rules, export, explicit refresh, and explicit comparison under `Advanced`.

Use ordinary `QLabel`, `QPushButton`, `QFormLayout`, and `QHBoxLayout` widgets. Set word wrapping and 4-pixel margins/spacing as in the existing configuration and diagnostics forms. Do not create a visual node editor or a new persistent dock for every stage.

- [ ] **Step 4: Verify adapters and static panel boundaries**

Run:

```bash
PYTHONPATH=src pytest \
  tests/unit/ui/test_workbench_commands.py \
  tests/unit/ui/test_workbench_case_panel_contract.py \
  tests/unit/ui/test_workbench_panel_contract.py \
  tests/unit/ui/test_deobfuscate_recipe_action.py -q
```

Expected: PASS. The UI action module continues to use injected IDA shims rather than direct IDA imports.

- [ ] **Step 5: Commit the Workbench re-rendering**

```bash
git add src/d810/ui/workbench_commands.py \
  src/d810/ui/workbench_panel.py \
  tests/unit/ui/test_workbench_case_panel_contract.py \
  tests/unit/ui/test_workbench_commands.py \
  tests/unit/ui/test_workbench_panel_contract.py
git commit -m "feat(ui): render algorithm-driven deobfuscation workflow"
```

### Task 6: Make Recipe Composer a strategy-construction companion

**Files:**
- Modify: `src/d810/passes/pass_pipeline.py`
- Modify: `src/d810/manager/workbench_recipe_models.py`
- Modify: `src/d810/manager/workbench_recipe_service.py`
- Modify: `src/d810/ui/workbench_recipe_logic.py`
- Modify: `src/d810/ui/workbench_recipe_panel.py`
- Modify: `tests/unit/passes/test_pipeline_config_parser.py`
- Modify: `tests/unit/manager/test_workbench_recipe_models.py`
- Modify: `tests/unit/manager/test_workbench_recipe_service.py`
- Modify: `tests/unit/ui/test_workbench_recipe_logic.py`
- Modify: `tests/unit/ui/test_workbench_recipe_panel_contract.py`

**Interfaces:**
- Consumes: registered `PipelineConfig` contract/maturity/backend metadata and the current case recommendation.
- Produces: display-only `StrategyWorkflowStage` metadata, stage-grouped catalog rows, and a strategy explanation. It does not change execution order or let a user compose raw transforms independently.

- [ ] **Step 1: Write catalog grouping and safety tests**

```python
def test_catalog_groups_registered_passes_without_reordering_the_draft() -> None:
    rows = project_catalog_rows(_catalog(), case=_case())

    assert [row.workflow_stage.value for row in rows] == [
        "frontend_normalization", "canonical_analysis", "canonical_transform",
    ]

    draft_rows = project_draft_rows(_draft_in_runtime_order(), _validation())
    assert [row.pass_id for row in draft_rows] == ["normalize", "recover", "lower"]


def test_recipe_explains_missing_evidence_without_enabling_raw_transform_editing() -> None:
    view = project_recipe_strategy(_case_with_unresolved_predicate(), _catalog())

    assert view.blocked_reason == "Validate predicate and both destinations first."
    assert view.can_add_transform is False
```

Add tests that an existing persisted function recipe round-trips unchanged, no stage label changes a `PipelineRecipeDraft.passes` order, and an unknown registry entry displays `canonical_pipeline` rather than being guessed as frontend normalization.

- [ ] **Step 2: Run the recipe tests and verify the new metadata is absent**

Run:

```bash
PYTHONPATH=src pytest \
  tests/unit/manager/test_workbench_recipe_models.py \
  tests/unit/manager/test_workbench_recipe_service.py \
  tests/unit/ui/test_workbench_recipe_logic.py \
  tests/unit/ui/test_workbench_recipe_panel_contract.py -q
```

Expected: FAIL because `StrategyWorkflowStage` metadata and strategy projection do not exist.

- [ ] **Step 3: Add explicit display metadata and render it**

```python
@dataclasses.dataclass(frozen=True, slots=True)
class PipelineConfig:
    # Existing fields remain unchanged.
    workflow_stage: StrategyWorkflowStage = (
        StrategyWorkflowStage.CANONICAL_PIPELINE
    )


@dataclasses.dataclass(frozen=True, slots=True)
class PassCatalogEntry:
    # Existing fields remain unchanged.
    workflow_stage: StrategyWorkflowStage
```

Add `PipelineConfig.workflow_stage` as explicit registration metadata. `to_dict()` emits its stable string; `from_dict()` uses `canonical_pipeline` when the field is absent and rejects an unknown value. It is not user input and not an execution scheduler. Project that field into `PassCatalogEntry`, then group the searchable catalog by stage, show `requires evidence`/`produces plan` contract summary, and display the case strategy recommendation above the catalog. Retain the existing ordered draft pane and Add/Remove/Enable/Move/Edit controls. Do not add a button to create a transform outside its registered owning pass.

- [ ] **Step 4: Verify recipe behavior and persistence compatibility**

Run:

```bash
PYTHONPATH=src pytest \
  tests/unit/manager/test_workbench_recipe_models.py \
  tests/unit/manager/test_workbench_recipe_service.py \
  tests/unit/passes/test_pipeline_config_parser.py \
  tests/unit/core/test_function_recipe_persistence.py \
  tests/unit/ui/test_workbench_recipe_logic.py \
  tests/unit/ui/test_workbench_recipe_panel_contract.py -q
```

Expected: PASS. Existing recipe JSON remains schema-compatible and execution order is unchanged.

- [ ] **Step 5: Commit the strategy-aware Recipe Composer**

```bash
git add src/d810/passes/pass_pipeline.py \
  src/d810/manager/workbench_recipe_models.py \
  src/d810/manager/workbench_recipe_service.py \
  src/d810/ui/workbench_recipe_logic.py \
  src/d810/ui/workbench_recipe_panel.py \
  tests/unit/passes/test_pipeline_config_parser.py \
  tests/unit/manager/test_workbench_recipe_models.py \
  tests/unit/manager/test_workbench_recipe_service.py \
  tests/unit/ui/test_workbench_recipe_logic.py \
  tests/unit/ui/test_workbench_recipe_panel_contract.py
git commit -m "feat(ui): relate recipe composition to case strategy"
```

### Task 7: Add evidence lineage and canary comparison to Diagnostics Explorer

**Files:**
- Modify: `src/d810/ui/workbench_diagnostics_logic.py`
- Modify: `src/d810/ui/workbench_diagnostics_commands.py`
- Modify: `src/d810/ui/workbench_diagnostics_panel.py`
- Modify: `src/d810/ui/workbench_diagnostic_graph.py`
- Modify: `tests/unit/diagnostics/test_workbench_graph_models.py`
- Modify: `tests/unit/diagnostics/test_workbench_graph_projection.py`
- Modify: `tests/unit/ui/test_workbench_diagnostics_logic.py`
- Modify: `tests/unit/ui/test_workbench_diagnostics_panel_contract.py`

**Interfaces:**
- Consumes: `DeobfuscationCaseEvidence` from Task 2 and existing selected database/snapshot inventory.
- Produces: case timeline rows, a current-versus-baseline canary comparison, and an anchored evidence-lineage graph. Cleaner commands remain unchanged.

- [ ] **Step 1: Write timeline, comparison, and graph projection tests**

```python
def test_case_timeline_reports_the_first_blocked_obligation() -> None:
    view = project_case_timeline(_case_evidence(
        level="c1_discovery",
        blocked="unique realization of native body failed",
    ))

    assert view.highest_level_label == "Discovery evidence recorded"
    assert view.first_blocked_obligation == "unique realization of native body failed"
    assert view.semantic_verified is False


def test_canary_comparison_reports_lost_facts_before_new_failures() -> None:
    comparison = compare_case_runs(_previous_case(), _current_case())

    assert comparison.lost_finding_ids == ("predicate:0x1800020F0",)
    assert comparison.first_regression == "predicate:0x1800020F0"


def test_case_graph_nodes_include_native_ea_in_every_block_label() -> None:
    graph = project_case_lineage_graph(_case_evidence())

    assert all("0x" in node.label for node in graph.nodes if node.requires_anchor)
```

Add tests that a C5 receipt remains distinct from C6, a selection never opens a graph when no case record exists, and case-cleanup candidates do not include a baseline run referenced by a selected canary comparison.

- [ ] **Step 2: Run the focused diagnostics tests and verify failure**

Run:

```bash
PYTHONPATH=src pytest \
  tests/unit/ui/test_workbench_diagnostics_logic.py \
  tests/unit/diagnostics/test_workbench_graph_models.py \
  tests/unit/diagnostics/test_workbench_graph_projection.py \
  tests/unit/ui/test_workbench_diagnostics_panel_contract.py -q
```

Expected: FAIL because the case timeline and comparison projections do not exist.

- [ ] **Step 3: Add the case view without weakening the existing two-pane layout**

```python
@dataclasses.dataclass(frozen=True, slots=True)
class CaseTimelineView:
    highest_level_label: str
    semantic_verified: bool
    first_blocked_obligation: str | None
    rows: tuple[DiagnosticRecordRow, ...]


def project_case_timeline(
    evidence: DeobfuscationCaseEvidence | None,
) -> CaseTimelineView:
    if evidence is None:
        return CaseTimelineView(
            "No case evidence recorded", False, None, ()
        )
    return _project_case_timeline(evidence)
```

Add `Deobfuscation case` to `_VIEW_LABELS` in the structured-record selector. Preserve the left `Databases` + `Snapshots` inventory and cleaner. The right pane gains a compact case summary above the structured timeline and a `Compare selected run` control that selects a prior matching run; it shows facts added/lost, plans staged, validation outcomes, receipts, first blocked obligation, and timing/maturity deltas. `Open graph` projects only the selected case lineage. Graph selection-to-record synchronization remains out of scope.

Never add direct delete buttons for evidence rows. Existing plan-first cleanup still targets snapshots/databases; when a selected run is a comparison baseline, the cleanup preview must name that dependency and require its existing confirmation path.

- [ ] **Step 4: Verify diagnostics behavior, graph contracts, and cleaner safety**

Run:

```bash
PYTHONPATH=src pytest \
  tests/unit/ui/test_workbench_diagnostics_logic.py \
  tests/unit/ui/test_workbench_diagnostics_commands.py \
  tests/unit/ui/test_workbench_diagnostics_panel_contract.py \
  tests/unit/diagnostics/test_workbench_graph_models.py \
  tests/unit/diagnostics/test_workbench_graph_projection.py \
  tests/unit/diagnostics/test_workbench_cleanup_plans.py \
  tests/unit/diagnostics/test_workbench_cleanup_execution.py -q
```

Expected: PASS. Existing database/snapshot filtering, sorting, and destructive-plan confirmation remain intact.

- [ ] **Step 5: Commit evidence-lineage diagnostics**

```bash
git add src/d810/ui/workbench_diagnostics_logic.py \
  src/d810/ui/workbench_diagnostics_commands.py \
  src/d810/ui/workbench_diagnostics_panel.py \
  src/d810/ui/workbench_diagnostic_graph.py \
  tests/unit/diagnostics/test_workbench_graph_models.py \
  tests/unit/diagnostics/test_workbench_graph_projection.py \
  tests/unit/ui/test_workbench_diagnostics_logic.py \
  tests/unit/ui/test_workbench_diagnostics_panel_contract.py
git commit -m "feat(diagnostics): show deobfuscation case lineage"
```

### Task 8: Validate migration, native UI behavior, and documentation

**Files:**
- Modify: `docs/superpowers/specs/2026-07-17-workbench-guided-attack-flow-design.md`
- Modify: `docs/superpowers/plans/2026-07-17-workbench-guided-attack-flow.md`
- Modify: `.tickets/tcvpu-v3qt.md`
- Modify: `docs/superpowers/plans/2026-07-23-algorithm-driven-deobfuscation-workbench.md`

**Interfaces:**
- Consumes: the completed Tasks 1-7 behavior and the diagnostic contract from the lifecycle work.
- Produces: explicit supersession/migration documentation, focused automated evidence, and native GUI screenshots on both supported Qt runtimes.

- [ ] **Step 1: Add migration assertions before marking the plan complete**

```python
def test_workbench_uses_algorithm_entry_point_labels() -> None:
    source = PANEL.read_text(encoding="utf-8")

    assert "Build Deobfuscator" in source
    assert "Deobfuscate Function" in source
    assert "Deobfuscate this function" not in source


def test_case_verdict_copy_never_claims_c1_through_c5_are_semantic_success() -> None:
    for level in range(1, 6):
        view = project_case_workflow(_snapshot(level=f"c{level}"))
        assert "semantic result verified" not in view.verdict.label.casefold()
```

- [ ] **Step 2: Run the complete focused UI/manager/diagnostics suite**

Run:

```bash
PYTHONPATH=src pytest \
  tests/unit/core/test_deobfuscation_case.py \
  tests/unit/diagnostics/test_deobfuscation_case_repository.py \
  tests/unit/manager/test_deobfuscation_case_service.py \
  tests/unit/manager/test_deobfuscation_case_workflow.py \
  tests/unit/ui/test_workbench_case_panel_contract.py \
  tests/unit/ui/test_workbench_workflow_logic.py \
  tests/unit/ui/test_workbench_recipe_logic.py \
  tests/unit/ui/test_workbench_diagnostics_logic.py -q
```

Expected: PASS.

- [ ] **Step 3: Run project architecture and full-unit gates**

Run:

```bash
sg scan --config sgconfig.yml --report-style short
PYTHONPATH=src lint-imports --config .importlinter
PYTHONPATH=src pytest tests/unit/ -q
graphify update .
```

Expected: ast-grep clean; all import contracts kept; unit suite passes; graph update completes.

- [ ] **Step 4: Validate both native IDA GUI paths on disposable databases**

Start each configured XQuartz image through `tools/scripts/run_ida_gui_docker.sh` from the repository root, mount the `truthful-config-v2-project-ui` worktree, and open a copied sample database. In IDA 9.1/PyQt5 and IDA 9.3/PyQt6:

1. Open a known, currently routable function and verify **Deobfuscate Function** is enabled with **Build Deobfuscator** available as the non-mutating alternative.
2. Open an unclassified function and verify **Build Deobfuscator** is primary while direct execution explains why it is unavailable.
3. Run Build and verify the dossier/hypothesis/strategy sections refresh without invoking the deobfuscation action.
4. Open Diagnostics Explorer, select the case view, verify the first blocked obligation and EA anchor, then open its lineage graph.
5. Verify the Recipe Composer stages catalog entries without changing the draft execution order.
6. Save neither the original sample nor the master IDB; record copied-file hashes and screenshots.

- [ ] **Step 5: Mark the old attack-card plan superseded, record evidence, and commit**

Update the older design and plan with this exact migration note:

```markdown
> Superseded for new UI work by
> `2026-07-23-algorithm-driven-deobfuscation-workbench.md`.
> Its direct-run identity/freshness/comparison rules remain in force.
```

Record test totals, IDA image tags, sample-copy hashes, and screenshot paths in the new plan's implementation-evidence section. Then commit:

```bash
git add -f docs/superpowers/specs/2026-07-17-workbench-guided-attack-flow-design.md \
  docs/superpowers/plans/2026-07-17-workbench-guided-attack-flow.md \
  docs/superpowers/plans/2026-07-23-algorithm-driven-deobfuscation-workbench.md
git add .tickets/tcvpu-v3qt.md \
  tests/unit/ui/test_workbench_case_panel_contract.py \
  tests/unit/manager/test_deobfuscation_case_workflow.py
git commit -m "docs(ui): record algorithm-driven workbench validation"
```

## Acceptance Criteria

- A current function has two unambiguous user-facing paths: **Build Deobfuscator** for non-mutating dossier/strategy construction and **Deobfuscate Function** for a current recommended or saved strategy.
- The Workbench identifies the first blocked obligation, evidence level, native anchors, and distinct uncertainty/rejection states without reading logs or relying on block serials.
- C1-C5 are never rendered as semantic success; C6 requires an explicit semantic witness.
- Recipe Composer explains each registered pass in the algorithmic stage it declares while preserving the effective draft's actual execution order and current function-recipe persistence behavior.
- Diagnostics Explorer reconstructs the evidence-to-receipt chain, compares compatible canary runs, and opens an anchored lineage graph without weakening snapshot/database cleaner safeguards.
- The pure case/workflow modules have unit coverage; the Qt panel only renders projections and dispatches existing validated manager actions.
- Focused tests, full unit tests, ast-grep, import-linter, Graphify update, and live IDA 9.1/9.3 validation pass with disposable sample copies.

## Implementation Evidence

This section is intentionally empty until Task 8. During execution, append only observed command outputs, test totals, Docker image tags, copied-IDB SHA-256 values, and screenshot paths. Do not replace a missing native validation result with an inference from a unit test.

### 2026-07-24: Task 1 completed; Task 2 contract gate reached

- Committed `ae952456a` (`feat(core): define deobfuscation case evidence`) in the `truthful-config-v2-project-ui` worktree.
- TDD evidence: `tests/unit/core/test_deobfuscation_case.py` failed at collection before the module existed, then passed 6/6 under `PYTHONPATH=src pyenv exec python -m pytest`; the complete core suite passed 506/506 under the same interpreter. Python 3.13.5 compilation passed with `pyenv exec python -m compileall`.
- The Task 2 consumer contract is not yet present. The active `lifecycle-resolver-evidence-authority` worktree has dirty diagnostic producer changes in `src/d810/core/diag/models.py` and `schema.py`, but does not declare a `case_schema_version`, `DeobfuscationCaseEvidence`, `first_blocked_obligation`, or `semantic_witness` field. Its existing lifecycle/evidence/plan/receipt tables must not be reverse-engineered by the UI branch into a guessed case verdict.
- The UI reader now treats diagnostic schema v7 as the explicit supported producer contract and rejects any other shape. Its first TDD slice reads only `diagnostic_sessions`, `lifecycle_events`, and the typed evidence/identity/plan/receipt detail tables; a disposable v7 fixture passed 3/3 focused tests under `pyenv exec python -m pytest`. This is not an aggregate event format and does not infer C6; later Task 2 slices must add the remaining strict correlation and malformed-row coverage before the repository is committed.

### 2026-07-24: Task 8 verification evidence

- Focused algorithm-workbench gate: `PYTHONPATH=src pyenv exec python -m pytest tests/unit/core/test_deobfuscation_case.py tests/unit/diagnostics/test_deobfuscation_case_repository.py tests/unit/manager/test_deobfuscation_case_service.py tests/unit/manager/test_deobfuscation_case_workflow.py tests/unit/ui/test_workbench_case_panel_contract.py tests/unit/ui/test_workbench_workflow_logic.py tests/unit/ui/test_workbench_recipe_logic.py tests/unit/ui/test_workbench_diagnostics_logic.py -q` passed `81` tests in `0.29s`. The complete unit gate previously passed `6278` tests with `29` skipped and `162` subtests in `35.99s` under the same interpreter.
- Architecture gates: `sg scan --config sgconfig.yml --report-style short` returned clean; `PYTHONPATH=src pyenv exec lint-imports --config .importlinter` reported `13 kept, 0 broken`.
- IDA 9.3 native XQuartz image: `idapro-9.3-speedups:x11-arm64` with `org.d810.gui-runtime=x11-dev-emulation-z3-v1`. It opened `D-810 Configuration` and `d810-ng Deobfuscation Workbench` for copied `/samples/bins/libobfuscated.dll.2026-06-03.i64`; source and copy SHA-256: `61678430e3fe08f6bb23f41752faa22b57c805e8261277660933d01e3c046dab`. MCP readback reported `PySide6`, both entry-point labels visible, and a successful `build_deobfuscator` whose 0x1000-byte function sample at `0x180001000` was unchanged.
- IDA 9.1 native XQuartz image: `idapro-9.1-speedups:x11-amd64` with `org.d810.gui-runtime=x11-dev-emulation-z3-v1`. It opened the same Configuration and Workbench docks using `PyQt5`; source and copy `/samples/bins/libobfuscated.dll.ida91.i64` SHA-256: `9d1073f6edec23f141dbb3cd6acf3584662777b54d6f0b459862780a3031e9bb`. `Build Deobfuscator` completed and the sampled function bytes at `0x180001000` remained unchanged.
- Native named-action audit records: `.tmp/ida-gui/automation-7e1f7762cf86b3298f45cda1702aa05c.json` (9.3 launch), `.tmp/ida-gui/automation-2bdaeed3f026a23fa9f30502a275a66f.json` (9.1 launch), and `.tmp/ida-gui/automation-72496cc607bdc6816bba120ab3defc0b.json` (9.3 reconnect).
- Native case/graph acceptance remains unverified: after Build, both native sessions reported `case_evidence: false`, `case_strategy: false`, and `direct_enabled: false`. The matching diagnostic inventory for `0x180001000` contained only closed schema-v1 files, while the Workbench reader intentionally accepts only schema-v7 case records. No native case timeline, blocked obligation, or lineage graph was fabricated from recon hints.

## Execution Handoff

Tasks 1 through 7 are implemented in the `truthful-config-v2-project-ui` worktree. Task 8 cannot close until the diagnostic producer emits a closed schema-v7 case session for the selected function. The current recon-store hints are not that contract and must not be projected into a case, strategy, blocked obligation, or lineage graph by the UI branch.

When the producer contract is available, rerun the Task 8 native checks from a fresh copied IDB: known routable direct-path enablement, Build dossier/strategy refresh, case timeline/anchor/lineage graph, and canary comparison. Preserve each task's isolated commit boundary, re-run its focused tests before advancing, and do not claim the UI is ready until that native gate passes.
