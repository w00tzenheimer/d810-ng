# Test Classification

This project uses four test lanes:

| Lane | Path | Requires live IDA runtime | Requires IDA database | Purpose |
|------|------|----------------------------|------------------------|---------|
| Unit | `tests/unit/` | No | No | Pure logic tests with no IDA imports or IDA mocks |
| Contracts | `tests/contracts/` | No (or mocked) | No | API/behavior contracts around IDA-facing code using mocks/stubs |
| Stateless | `tests/stateless/` | Yes | Yes | State-isolated IDA runtime tests (CFG/microcode/etc.) |
| System | `tests/system/` | Mixed | No | Cross-module/system-level checks and tooling glue that do not fit stateless workflow tests |

## Placement Rules

1. Put tests in `tests/unit/` when they do not import `ida_*` and do not mock IDA modules.
2. Put tests in `tests/contracts/` when they validate IDA-facing logic via mocks/stubs and do not need a live IDA database.
3. Put tests in `tests/stateless/` when they need real IDA/Hex-Rays objects and binary/database setup, while remaining state-isolated.
4. Keep tests in `tests/system/` for system-level glue/integration validation that is not binary/database workflow testing.

## Current `tests/system` Classification

| File | Classification | Reason |
|------|----------------|--------|
| `tests/system/optimizers/microcode/flow/flattening/test_heuristics.py` | System-level (IDA module import contract) | Imports optimizer modules with top-level IDA dependencies; no DB workflow |
| `tests/system/optimizers/microcode/flow/flattening/test_unflattener_services.py` | System-level (IDA module import contract) | Depends on modules importing IDA symbols at import time; composition contract tests |
| `tests/system/optimizers/test_context_aware_dsl.py` | System-level (IDA module import contract) | Explicitly validates extensions that import `ida_hexrays` at module level |
| `tests/system/optimizers/test_verifiable_rules.py` | System-level (registry/bootstrap integration) | Validates rule auto-discovery/registry + Z3 verification under project bootstrap |
| `tests/system/test_ast_comparison.py` | System-level (shared fixture integration) | Uses clang/code comparison fixture stack from system harness |
| `tests/system/test_capture.py` | System tooling | Contains capture plugin/database helpers used by system/stateless runs |
| `tests/system/test_cython_benchmark.py` | System-level performance check | Benchmarks Cython vs Python with IDA types available |
| `tests/system/test_optimization_rule.py` | System-level (IDA constants contract) | Validates rule behavior against real `ida_hexrays` constants |
| `tests/system/ui/test_export_actions.py` | System-level UI/API contract | Verifies mapping against live IDA loader constants |
