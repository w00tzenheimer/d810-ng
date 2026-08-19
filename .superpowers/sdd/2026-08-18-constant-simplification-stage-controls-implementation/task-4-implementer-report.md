# Task 4 implementer report: expose the compiled constant stage schedule

## Result

Implemented Task 4 on `diff/constant-simplification-stage-controls`.
The config-v2 editor now exposes the canonical nested constant-stage controls,
choice-backed maturity lists use checkable Qt list items, and Workbench
projection consumes the immutable compiled schedule carried by project runtime.
The schedule projection includes disabled mutation stages and a separate
`PRE_HEXRAYS` global-const preparation row with durable proposal state.

## RED evidence

The exact focused command was run after adding the Task 4 assertions and before
the production changes:

```text
PYTHONPATH=src pytest -q tests/unit/core/test_pass_editor_spec.py tests/unit/passes/test_config_v2_editor_contracts.py tests/unit/manager/test_effective_pipeline_schedule.py tests/unit/ui/test_config_v2_editing_logic.py tests/unit/ui/test_workbench_logic.py tests/unit/ui/test_config_v2_project_editor_host_contract.py tests/unit/ui/test_project_config_adapter_contract.py
7 failed, 85 passed in 0.62s
```

The failures were the expected missing nested editor paths, choice-list
normalization/rejection, checkable-list host contract, compiled-schedule
projection hook, and Workbench contract/preparation rows.

## Files modified

- `src/d810/passes/constant_simplification.py`
  - registers the exact canonical preparation/stage field paths, defaults,
    portable maturity choices, dynamic-preparation description, and executable
    readonly danger advisory.
- `src/d810/manager/effective_pipeline_schedule.py`
  - projects constant stages from the compiled schedule rather than live rule
    maturities, preserves independent per-pipeline runtime order, and adds the
    global-const preparation row/status projection.
- `src/d810/manager/workbench_models.py`
  - extends schedule stage rows with enabled state, support/request/gate/
    effective maturities, lifecycle, source, and inactive/preparation details.
- `src/d810/manager/workbench_service.py`
  - passes the project-runtime compiled schedule and manager preparation status
    into schedule projection.
- `src/d810/ui/config_v2_editing_logic.py`
  - validates choice-backed string lists and normalizes selections in declared
    choice order; choice-less lists retain comma-separated behavior.
- `src/d810/ui/config_v2_editing_panel.py`
  - renders choice-backed string lists as editable checkable `QListWidget`
    controls while retaining `QLineEdit` for choice-less lists.
- `src/d810/ui/workbench_logic.py`
  - renders compiled contract fields, disabled stages, preparation state, and
    independent instruction/flow order details.
- `tests/unit/core/test_pass_editor_spec.py`
  - verifies nested default rendering and choice-backed list validation in the
    generic editor contract.
- `tests/unit/passes/test_config_v2_editor_contracts.py`
- `tests/unit/manager/test_effective_pipeline_schedule.py`
- `tests/unit/ui/test_config_v2_editing_logic.py`
- `tests/unit/ui/test_config_v2_project_editor_host_contract.py`
- `tests/unit/ui/test_workbench_logic.py`
  - cover the new editor, schedule, preparation, rendering, and host contracts.

## GREEN evidence

Exact focused command:

```text
PYTHONPATH=src pytest -q tests/unit/core/test_pass_editor_spec.py tests/unit/passes/test_config_v2_editor_contracts.py tests/unit/manager/test_effective_pipeline_schedule.py tests/unit/ui/test_config_v2_editing_logic.py tests/unit/ui/test_workbench_logic.py tests/unit/ui/test_config_v2_project_editor_host_contract.py tests/unit/ui/test_project_config_adapter_contract.py
94 passed in 0.53s
```

Adjacent affected subsystem tests:

```text
PYTHONPATH=src pytest -q tests/unit/passes/test_constant_simplification.py tests/unit/passes/test_constant_simplification_options.py tests/unit/passes/test_pipeline_v2_hook_bridge.py tests/unit/manager/test_project_runtime.py tests/unit/manager/test_workbench_service.py tests/unit/ui/test_workbench_pipeline_schedule.py tests/unit/manager/test_workbench_preparation_projection.py
87 passed in 0.64s
```

Required checks:

```text
ruff check src/d810/passes/constant_simplification.py src/d810/manager/effective_pipeline_schedule.py src/d810/manager/workbench_models.py src/d810/manager/workbench_service.py src/d810/ui/config_v2_editing_logic.py src/d810/ui/config_v2_editing_panel.py src/d810/ui/workbench_logic.py tests/unit/core/test_pass_editor_spec.py tests/unit/passes/test_config_v2_editor_contracts.py tests/unit/manager/test_effective_pipeline_schedule.py tests/unit/ui/test_config_v2_editing_logic.py tests/unit/ui/test_workbench_logic.py tests/unit/ui/test_config_v2_project_editor_host_contract.py
All checks passed!

sg scan --config sgconfig.yml --report-style short
exit 0

PYTHONPATH=src lint-imports --config .importlinter
Contracts: 14 kept, 0 broken.
```

## Deviations and risks

- A full `PYTHONPATH=src pytest -q tests/unit` run reached the existing
  `tests/unit/backends/ida/native_patch/test_encoder_unicorn_oracle.py` and
  terminated the Python process with `Fatal Python error: Illegal instruction`
  in `unicorn.mem_map`; the Task 4 focused and adjacent suites are green.
- `graphify query` was attempted first, but this worktree has no
  `graphify-out/graph.json`; the CLI reported `graph file not found`.
  The single required `graphify update .` attempt emitted the installed
  graphify package-version warning and produced no tracked graph output.
- No IDA Docker test was needed for this pure editor/Workbench projection
  task; the Qt host contract remains source-level because IDA Qt is unavailable
  in the local unit runtime.

## Commit

Feature commit SHA: pending immediate post-commit report update.

Required message:

```text
feat(workbench): expose constant stage schedule
```
