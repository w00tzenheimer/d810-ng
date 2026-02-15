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

## Unskip Tooling (Research Mode)

Use this when you are actively investigating tests that are intentionally skipped
by case metadata (golden mismatch, missing sample, known instability).

### When to use it

- You want to see the real current behavior instead of skip reasons.
- You are updating golden outputs or narrowing down regressions.
- You need to distinguish "expected stale skip" from "real breakage."

### When NOT to use it

- Normal CI gating.
- Quick smoke checks where known-hang/known-segfault cases are not relevant.

### Commands

```bash
# 1) Unskip normal research cases (safe default)
pytest tests/system/ -v -rs --unskip-research

# 2) Also unskip dangerous known-hang/known-segfault cases (local only)
pytest tests/system/ -v -rs --unskip-research --unskip-dangerous

# 3) Focus one case (zsh: quote parametrized ids)
pytest -q -rs --unskip-research \
  'tests/system/e2e/test_libdeobfuscated_dsl.py::TestCoreDeobfuscation::test_core_deobfuscation[test_xor]'

# 4) Environment-variable equivalent
D810_UNSKIP_CASES=1 pytest tests/system/ -v -rs
D810_UNSKIP_CASES=1 D810_UNSKIP_DANGEROUS=1 pytest tests/system/ -v -rs
```

### Result Triage

| Outcome | Meaning | Action |
|--|--|--|
| `SKIPPED` (without unskip flags) | Intentional case skip from metadata | Use `--unskip-research` if you want to investigate |
| `XFAIL` | Known unsupported runtime condition in current sample/runtime | Not blocking; capture as environment/sample gap |
| `FAIL` after unskip | Real mismatch now visible (often why the skip existed) | Fix rule behavior or update expectation/golden if behavior is now acceptable |
| `SKIPPED` with `--unskip-research` | Usually dangerous case still blocked | Add `--unskip-dangerous` for local deep investigation |

### Current Known Examples

- `test_xor` in `test_libdeobfuscated_dsl` now simplifies both MBA XOR forms
  (rule `Xor_HackersDelightRule_3` fires twice). If it fails, it is usually
  an expected-code drift (type/cast formatting), not a rule-miss.
- `test_services_integration::test_find_single_dispatcher` is `XFAIL` when no
  dispatcher is discovered in candidate functions at runtime. Treat this as
  sample/maturity coverage, not a hard regression in the services API.

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

# Research mode convenience: if no --dump-function-pseudocode is provided,
# the dump harness defaults to test_xor
pytest -s tests/system/e2e/test_dump_function_pseudocode.py --unskip-research
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
