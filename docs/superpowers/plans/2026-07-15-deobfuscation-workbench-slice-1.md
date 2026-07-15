# Deobfuscation Workbench - Slice 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` and `superpowers:test-driven-development`. Execute every behavior test-first and record the RED result before production edits.

**Goal:** Replace the Stats-only entry point with a read-only, function-centric workbench whose immutable snapshot truthfully exposes the current function, source/runtime configuration, attack hints, ordered pass contracts and preflight, cross-consumer outcomes, rule scope, supporting statistics, and artifact references.

**Architecture:** `d810.manager.workbench_models` defines deeply immutable, IDA/Qt-free value objects and the approved outcome vocabulary. `d810.manager.workbench_service` collects those values from injected/current manager collaborators and returns deterministic snapshots with monotonically increasing generations. `D810Manager` owns the service; `D810State` supplies the current source/runtime project context through one facade. `d810.ui.workbench_logic` performs all row, status, filter, detail, action, and export projection. `d810.ui.workbench_panel` is a thin native adapter. The existing Stats action ID is retained and opens this workbench focused on evidence.

**Tech Stack:** Python 3.13, frozen dataclasses/enums, D810 pass registry/manifests/preflight, recon outcome adapters, rule-scope runtime, `OptimizationStatistics`, IDAPython's existing Qt shim, pytest, ast-grep, import-linter, graphify, and `tk`.

## Global constraints

- Implement ticket `tcvpu-nyvc`, child of `d81-38ha`, in the existing isolated `diff/truthful-config-v2-project-ui` worktree.
- Do not start or operate IDA, inspect live widgets, or perform manual Qt acceptance in this slice. Implement the adapter and verify it with pure/source-level tests; keep runtime acceptance explicitly open.
- Never return Qt objects, IDA objects, live Hex-Rays pointers, mutable dictionaries, or persistence records from the manager API.
- Preserve pass order exactly. Consumers are a separate phase-tagged collection and must never be inserted into that order.
- Do not infer a successful transform from aggregate firing counts. Statistics are supporting evidence only.
- Use the exact outcome vocabulary: `Not run`, `Ready`, `Not eligible`, `No match`, `Changed`, `Unchanged`, `Abstained`, `Blocked`, `Failed`, and `Stale`.
- A missing facts view produces `Not run`; a failed static contract produces `Blocked`. A consumer without source artifacts is `Not eligible`; one without a summary is `No match`; an applied verdict is `Changed`; a non-applied available verdict is `Abstained` unless explicit structured provenance supplies a more precise approved status.
- Diagnostic text must never render a microcode block serial without an EA anchor. Slice 1 does not invent block anchors from `CandidateFlag.block_serial`; it summarizes candidate kinds/counts instead.
- Evidence export is canonical UTF-8 JSON: sorted keys, stable tuple order, two-space indentation, and one trailing newline.
- UI code must not import pass registries, config parsers, SQLite, persistence implementations, diagnostic ORM models, or mutation backends.
- Add no ast-grep or import-linter ignores.

---

### Task 1: Define the immutable workbench contract

**Files:**

- Create: `src/d810/manager/workbench_models.py`
- Create: `tests/unit/manager/test_workbench_models.py`
- Update: `src/d810/manager/__init__.py`

**Interfaces:**

```python
class OutcomeStatus(str, Enum):
    NOT_RUN = "Not run"
    READY = "Ready"
    NOT_ELIGIBLE = "Not eligible"
    NO_MATCH = "No match"
    CHANGED = "Changed"
    UNCHANGED = "Unchanged"
    ABSTAINED = "Abstained"
    BLOCKED = "Blocked"
    FAILED = "Failed"
    STALE = "Stale"

class SnapshotFreshness(str, Enum):
    CURRENT = "current"
    STALE = "stale"
    UNAVAILABLE = "unavailable"

@dataclass(frozen=True, slots=True)
class FunctionRef:
    ea: int
    name: str
    fingerprint: str | None
    generation: int

@dataclass(frozen=True, slots=True)
class RuntimeConfigRef:
    source_name: str
    source_path: str
    runtime_name: str
    runtime_path: str
    mode: str
    routed: bool
    hook_mode: str | None
    pass_ids: tuple[str, ...]

@dataclass(frozen=True, slots=True)
class AttackSummary:
    observed_shape: str
    mechanism: str
    selected_profile: str | None
    selection_mode: str
    confidence: float | None
    recommended_inferences: tuple[str, ...]
    suppressed_rules: tuple[str, ...]
    candidate_kinds: tuple[str, ...]

@dataclass(frozen=True, slots=True)
class WorkbenchDiagnostic:
    code: str
    message: str
    pass_id: str | None
    namespace: str | None
    missing: tuple[str, ...]
    available: tuple[str, ...]

@dataclass(frozen=True, slots=True)
class PipelineStageSnapshot:
    ordinal: int
    pass_id: str
    phase: str
    scope: str
    maturity: str
    status: OutcomeStatus
    summary: str
    contract_json: str
    diagnostics: tuple[WorkbenchDiagnostic, ...]

@dataclass(frozen=True, slots=True)
class ConsumerOutcomeSnapshot:
    phase: str
    consumer_name: str
    status: OutcomeStatus
    detail: str
    provenance_json: str | None

@dataclass(frozen=True, slots=True)
class RuleScopeSummary:
    project_instruction_rules: tuple[str, ...]
    project_block_rules: tuple[str, ...]
    function_enabled_rules: tuple[str, ...]
    function_disabled_rules: tuple[str, ...]
    function_tags: tuple[str, ...]
    function_notes: str
    inference_name: str | None
    inference_enabled_rules: tuple[str, ...]
    inference_disabled_rules: tuple[str, ...]
    inference_applies: bool

@dataclass(frozen=True, slots=True)
class CountEntry:
    name: str
    count: int

@dataclass(frozen=True, slots=True)
class PatchCountEntry:
    name: str
    uses: int
    total_patches: int

@dataclass(frozen=True, slots=True)
class StatisticsSummary:
    optimizer_matches: tuple[CountEntry, ...]
    rule_matches: tuple[CountEntry, ...]
    cfg_patches: tuple[PatchCountEntry, ...]
    total_rule_firings: int
    cycles_detected: tuple[CountEntry, ...]
    total_cycles_detected: int

@dataclass(frozen=True, slots=True)
class ArtifactRef:
    kind: str
    label: str
    path: str | None
    available: bool

@dataclass(frozen=True, slots=True)
class BaselineRef:
    available: bool
    fingerprint: str | None
    path: str | None
    generation: int | None

@dataclass(frozen=True, slots=True)
class D810OutputRef:
    available: bool
    fingerprint: str | None
    path: str | None
    generation: int | None

@dataclass(frozen=True, slots=True)
class DeobfuscationWorkbenchSnapshot:
    generation: int
    function: FunctionRef
    runtime: RuntimeConfigRef
    attack: AttackSummary
    pipeline: tuple[PipelineStageSnapshot, ...]
    consumers: tuple[ConsumerOutcomeSnapshot, ...]
    rule_scope: RuleScopeSummary
    statistics: StatisticsSummary
    baseline: BaselineRef
    latest_output: D810OutputRef
    artifacts: tuple[ArtifactRef, ...]
    freshness: SnapshotFreshness
    engine_started: bool
    collection_errors: tuple[str, ...]
```

- [ ] Write tests proving every model is frozen/slotted, nested collections are tuples, enum values match the approved labels exactly, and a snapshot cannot be mutated.
- [ ] Run the model tests and record the expected import/collection RED.
- [ ] Implement only the immutable types and lazy manager exports.
- [ ] Run the model tests green and commit: `feat(workbench): define immutable snapshot contract`.

---

### Task 2: Collect truthful read-only snapshots in the manager layer

**Files:**

- Create: `src/d810/manager/workbench_service.py`
- Create: `tests/unit/manager/test_workbench_service.py`
- Update: `src/d810/manager/manager.py`
- Update: `src/d810/manager/state.py`

**Interfaces:**

```python
class WorkbenchService:
    def collect(
        self,
        *,
        function_ea: int,
        function_name: str,
        function_fingerprint: str | None,
        project_snapshot: ProjectRuntimeSnapshot,
        runtime_project: ProjectConfiguration,
        facts: object | None = None,
        baseline: BaselineRef | None = None,
        latest_output: D810OutputRef | None = None,
    ) -> DeobfuscationWorkbenchSnapshot:
        """Collect one immutable read-only snapshot."""

class D810Manager:
    workbench_service: WorkbenchService
    def get_workbench_snapshot(
        self,
        *,
        function_ea: int,
        function_name: str,
        function_fingerprint: str | None,
        project_snapshot: ProjectRuntimeSnapshot,
        runtime_project: ProjectConfiguration,
        facts: object | None = None,
        baseline: BaselineRef | None = None,
        latest_output: D810OutputRef | None = None,
    ) -> DeobfuscationWorkbenchSnapshot:
        """Delegate collection to the manager-owned service."""

class D810State:
    def get_workbench_snapshot(
        self,
        function_ea: int,
        function_name: str = "",
        function_fingerprint: str | None = None,
        *,
        facts: object | None = None,
    ) -> DeobfuscationWorkbenchSnapshot:
        """Supply current project context and request the snapshot."""
```

- [ ] Test source/runtime projection, exact configured pass ordering, static preflight (`Not run`/`Ready`/`Blocked`), structured diagnostics, monotonic generation, and non-fatal collection errors.
- [ ] Test attack projection from persisted recon hints without exposing candidate block serials.
- [ ] Test consumer projection stays outside the ordered pipeline and distinguishes `Not eligible`, `No match`, `Changed`, and `Abstained`.
- [ ] Test project/function/inference rule overlays, supporting statistics, recon/log/storage artifact availability, and absent artifacts.
- [ ] Test the state facade passes the current runtime project/snapshot to the manager and does not parse configuration itself.
- [ ] Run service tests and record the expected module/API RED.
- [ ] Implement the service using `operational_config_v2_pass_registry`, `pass_specs_from_project_config`, `preflight_pipeline_contract`, `pipeline_contract_preflight_manifest`, `ReconOutcomeLog`, `RuleScopeRuntime`, and `OptimizationStatistics` only inside the manager layer.
- [ ] Catch collaborator-specific collection failures into `collection_errors` while preserving the rest of the snapshot; do not catch programmer errors from model construction.
- [ ] Run manager tests green and commit: `feat(workbench): collect truthful function evidence`.

---

### Task 3: Add pure projection, filtering, action state, and canonical export

**Files:**

- Create: `src/d810/ui/workbench_logic.py`
- Create: `tests/unit/ui/test_workbench_logic.py`

**Interfaces:**

```python
class WorkbenchSection(str, Enum):
    CONTEXT = "context"
    ATTACK = "attack"
    PIPELINE = "pipeline"
    SUPPORTING = "supporting"
    EVIDENCE = "evidence"

@dataclass(frozen=True, slots=True)
class WorkbenchRow:
    key: str
    section: WorkbenchSection
    ordinal: int
    label: str
    summary: str
    detail: str
    status: OutcomeStatus
    color_role: str
    tooltip: str

@dataclass(frozen=True, slots=True)
class WorkbenchActionState:
    action_id: str
    label: str
    enabled: bool
    reason: str

def project_workbench_rows(
    snapshot: DeobfuscationWorkbenchSnapshot,
) -> tuple[WorkbenchRow, ...]:
    """Project the complete snapshot into ordered presentation rows."""

def filter_workbench_rows(
    rows: tuple[WorkbenchRow, ...], query: str,
) -> tuple[WorkbenchRow, ...]:
    """Filter rows without changing their relative order."""

def action_states(
    snapshot: DeobfuscationWorkbenchSnapshot,
) -> tuple[WorkbenchActionState, ...]:
    """Return explicit enablement and reasons for every visible action."""

def detail_text(row: WorkbenchRow) -> str:
    """Return the selected row's already-derived detail."""

def export_evidence_json(snapshot: DeobfuscationWorkbenchSnapshot) -> str:
    """Serialize canonical, deterministic, JSON-safe evidence."""
```

- [ ] Test pipeline rows preserve ordinal order; consumer rows are grouped under supporting decisions; source/runtime labels remain distinct; status labels/tooltips/colors are complete for all ten statuses.
- [ ] Test case-insensitive filtering across label, summary, detail, and status without reordering rows.
- [ ] Test Slice 1 action states: Refresh and Export enabled; Analyze, Deobfuscate, Compare, Recipe, and Diagnostics visible but disabled with explicit future-slice reasons.
- [ ] Test deterministic export twice and against an exact canonical JSON witness. Export enums as approved string values and paths as strings.
- [ ] Run logic tests and record the expected module RED.
- [ ] Implement pure logic with imports limited to `d810.manager.workbench_models` and the standard library.
- [ ] Run logic tests green and commit: `feat(ui): project read-only workbench evidence`.

---

### Task 4: Implement the thin dock adapter without runtime exploration

**Files:**

- Create: `src/d810/ui/workbench_panel.py`
- Create: `tests/unit/ui/test_workbench_adapter_contract.py`
- Reference: `src/d810/ui/stats_dialog.py`

**Adapter contract:**

- `DeobfuscationWorkbenchPanel(state)` owns only PluginForm lifecycle, Qt model/widget creation, selection/filter signal wiring, file-save prompt, and rendering.
- `set_function(func_ea, func_name, fingerprint=None)` changes the followed function, requests a fresh immutable state snapshot, and replaces rows atomically.
- `refresh()` re-requests the same function. `show(focus_section=None)` uses the established persistent dock pattern.
- Export obtains text from `export_evidence_json`; the adapter only chooses/writes the destination.
- The adapter renders `collection_errors`; it does not reinterpret them.

- [ ] Write AST/source tests proving the adapter calls `state.get_workbench_snapshot`, delegates projection/export to `workbench_logic`, and contains no prohibited imports or direct SQL/config/pass parsing.
- [ ] Test source-level presence of `set_function`, `refresh`, `show`, closed-panel recovery, function identity retention, filter wiring, and evidence focus.
- [ ] Run adapter tests and record the expected missing-module RED.
- [ ] Implement the adapter by adapting the existing `DeobfuscationStatsPanel` dock/tree/filter lifecycle, without starting IDA.
- [ ] Run adapter/source tests green and commit: `feat(ui): add native read-only workbench dock`.

---

### Task 5: Preserve the Stats action as a compatibility entry point

**Files:**

- Update: `src/d810/ui/actions/deobfuscation_stats.py`
- Update: `tests/unit/ui/test_actions_migration.py`

- [ ] Add a failing test that locks `ACTION_ID == "d810ng:deobfuscation_stats"`, proves the action opens `DeobfuscationWorkbenchPanel`, forwards current EA/name, calls `show(focus_section="evidence")`, and recreates a closed singleton.
- [ ] Run the focused test and record RED against the old stats panel.
- [ ] Redirect the action, retain the action ID/menu order, and update user-facing label/tooltip to describe the workbench while leaving any text fallback truthful.
- [ ] Run focused UI tests green and commit: `feat(ui): redirect Stats action to workbench`.

---

### Task 6: Verify architecture, regression safety, and deferred live gate

**Files:**

- Update: `.tickets/tcvpu-nyvc.md`
- Update: `.tickets/d81-38ha.md`

- [ ] Run focused Slice 1 tests:

```bash
PYTHONPATH=src:tests pyenv exec python -m pytest \
  tests/unit/manager/test_workbench_models.py \
  tests/unit/manager/test_workbench_service.py \
  tests/unit/ui/test_workbench_logic.py \
  tests/unit/ui/test_workbench_adapter_contract.py \
  tests/unit/ui/test_actions_migration.py -q --tb=short
```

- [ ] Run existing Slice 0 and stats/action regression tests.
- [ ] Run the full unit suite:

```bash
PYTHONPATH=src:tests pyenv exec python -m pytest tests/unit/ -q --tb=short
```

- [ ] Run architecture and diff gates from the worktree:

```bash
sg scan --config sgconfig.yml --report-style short
PYTHONPATH=src lint-imports --config .importlinter
git diff --check
```

- [ ] Scan new modules for `TODO`, `FIXME`, `NotImplementedError`, placeholder returns, prohibited imports, and unanchored `blk<serial>` rendering.
- [ ] Run `graphify update .` and confirm graph artifacts remain ignored.
- [ ] Add exact automated evidence to `tcvpu-nyvc`. Keep the ticket `in_progress` until dock/function-following/theme/navigation behavior is exercised in the user-selected IDA process later.
- [ ] Run `simba codex-finalize` before the terminal-only handoff.

## Deferred acceptance (explicitly not executed now)

- Construct/dock/close/reopen the panel in the intended IDA process.
- Verify theme rendering, live function-follow events, keyboard/filter behavior, evidence export dialog, and the compatibility action.
- These are acceptance gates, not permission to change the `~/.idapro/plugins/d810` symlink or operate any IDA process.
