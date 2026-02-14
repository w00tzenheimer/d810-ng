# Test Classification

## Structure

```
tests/
  unit/
  system/
    runtime/
    e2e/
```

## Definitions

### unit/

- Pure Python
- No IDA runtime required
- Tests algorithms, transforms, helpers, internal logic
- Fast and deterministic

**Failure means:** "Our logic is wrong."

### system/runtime/

- Runs inside real IDA (Hex-Rays optional depending on test)
- Tests API usage and semantic correctness
- Asserts invariants, stability, shapes, no-crash behavior
- Does NOT assert full deobfuscation outcomes

**Failure means:** "Our interaction with IDA/Hex-Rays is wrong or unstable."

These are integration-level correctness tests.

### system/e2e/

- Runs full deobfuscation pipeline
- Uses real binaries
- Compares final results (golden output / normalized IR / pseudocode snapshots / etc.)

**Failure means:** "The deobfuscation pipeline is wrong."

These are product-level correctness tests.

## Classification Guide

|  | runtime | e2e |
|--|---------|-----|
| Are we checking invariants / API usage? | Yes | No |
| Are we validating final deobfuscation results? | No | Yes |
| Would this test survive refactoring the pipeline architecture? | Probably | No |
| Is this a golden-output test? | No | Yes |

## Guardrails

- If a test snapshots pseudocode → it goes in `e2e/`
- If a test only checks invariants / API usage → it stays in `runtime/`
- Do not let runtime tests assert full pipeline output. The moment they snapshot pseudocode or final deobfuscation artifacts, they belong in `e2e/`.

## Markers

- `@pytest.mark.runtime` — IDA runtime invariant/API tests
- `@pytest.mark.e2e` — end-to-end pipeline tests
- `@pytest.mark.hexrays` — requires Hex-Rays decompiler
- `@pytest.mark.ida_required` — requires IDA Pro
- `@pytest.mark.slow` — slow tests (>10s)
- `@pytest.mark.profile` — performance profiling tests
- `@pytest.mark.pure_python` — runs without IDA Pro

## Running Tests

```bash
# Unit tests (no IDA required)
PYTHONPATH=src pytest tests/unit/ -v --tb=short

# System tests (requires IDA Pro in Docker or locally)
pytest tests/system/ -v --tb=short --forked

# Runtime tests only
pytest tests/system/runtime/ -v --tb=short --forked

# E2E tests only
pytest tests/system/e2e/ -v --tb=short --forked
```

## Dump Before/After Pseudocode For Specific Functions

Use the manual dump harness when you need fast per-function debugging without
editing test files:

```bash
# Single function (loads example_libobfuscated.json by default)
pytest -s tests/system/e2e/test_dump_function_pseudocode.py \
  --dump-function-pseudocode mixed_dispatcher_pattern

# Multiple functions
pytest -s tests/system/e2e/test_dump_function_pseudocode.py \
  --dump-function-pseudocode "func_a,func_b,func_c"

# Choose project config explicitly
pytest -s tests/system/e2e/test_dump_function_pseudocode.py \
  --dump-function-pseudocode mixed_dispatcher_pattern \
  --dump-project example_libobfuscated.json

# Skip project loading
pytest -s tests/system/e2e/test_dump_function_pseudocode.py \
  --dump-function-pseudocode mixed_dispatcher_pattern \
  --dump-no-project

# Override binary when needed
D810_TEST_BINARY=libobfuscated.dll pytest -s \
  tests/system/e2e/test_dump_function_pseudocode.py \
  --dump-function-pseudocode mixed_dispatcher_pattern
```

## Backend-Aware Guard Note

- `tests/unit/test_mop_snapshot_guard.py` is intentionally backend-aware.
- `d810.hexrays.mop_snapshot.MopSnapshot` can resolve to either:
  - pure Python dataclass implementation, or
  - Cython extension implementation.
- Import order in a process can affect which implementation is loaded first.
- The guard test checks dataclass internals when the Python backend is active, and
  checks equivalent public field surface when the Cython backend is active.
- If you need deterministic pure-Python behavior for debugging this test:

```bash
D810_NO_CYTHON=1 PYTHONPATH=src pytest -q tests/unit/test_mop_snapshot_guard.py
```
