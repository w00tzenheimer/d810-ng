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

All tests have access to IDA, but unit tests can import ida libraries but not actually run inside real IDA

### unit/

- No IDA database required, but idapro should be installed
- Tests algorithms, transforms, helpers, internal logic
- Fast and deterministic

**Failure means:** "Our logic is wrong."

### system/runtime/

- Runs *inside* of IDA with a database open
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

## D810 Testing & Diagnostics Instructions

### Primary Rule

Use `tools/d810cli.py` as the official interface for dumps, diagnostics, and analysis. Do not invoke `run_system_tests_docker.sh` directly unless you specifically need low-level control or unsupported flags.

---

### Environment Setup

Always run commands from the repository root checkout.

If you need Python CLI access to project modules, including environments that require `ida_hexrays` APIs, invoke Python using `pyenv` and pre-wire `PYTHONPATH` correctly:

```bash
WORKTREE_NAME=${YOUR_WORKTREE_DIR_NAME}
PYTHONPATH=.worktrees/${WORKTREE_NAME}/src pyenv exec python
```

Do not assume imports fail because `ida_hexrays` is unavailable. The environment fully supports it when invoked correctly.

---

### Official Workflow (Preferred)

#### 1. Create a deobfuscation dump
Use the `d810cli.py dump` subcommand. This wraps `run_system_tests_docker.sh dump` and automatically creates the dump text output, produces the diagnostic SQLite DB, and stores all artifacts under `.worktrees/<worktree>/.tmp/`:

```bash
PYTHONPATH=src python3 tools/d810cli.py dump \
  --worktree hodur-materialization-boundary \
  -f sub_7FFD3338C040 \
  -p hodur_flag2.json \
  --label my-check
```

**Defaults**: If omitted, parameters default to:
* `--worktree` — auto-detected from the script's location. When invoking
  `tools/d810cli.py` directly from a root checkout, this is `None` (root). When
  invoking `.worktrees/<name>/tools/d810cli.py`, the default is `<name>`. Pass
  `-w <name>` only to override the checkout and target a different worktree.
* `-f sub_7FFD3338C040`
* `-p hodur_flag2.json`
* `--capture-post-maturity 8` (MMAT_GLBOPT1)

**Shortest dump workflow**:
```bash
PYTHONPATH=src python3 tools/d810cli.py dump --label quick
```

#### 2. Inspect pseudocode and results
Inspect the latest generated dump's AFTER pseudocode and delta optimization metrics:

```bash
PYTHONPATH=src python3 tools/d810cli.py after -n --stats
```

Or inspect a specific dump path explicitly:
```bash
PYTHONPATH=src python3 tools/d810cli.py after \
  --dump /absolute/path/to/dump.txt \
  -n \
  --stats
```

---

### Useful d810cli.py Commands

* **Show latest dump / DB paths**: `PYTHONPATH=src python3 tools/d810cli.py paths --worktree <worktree>`
* **Delta Stats only**: `PYTHONPATH=src python3 tools/d810cli.py stats --worktree <worktree>`
* **Recompute Oracle**: `PYTHONPATH=src python3 tools/d810cli.py oracle --worktree <worktree>`
* **Frontier Diagnostics**: `PYTHONPATH=src python3 tools/d810cli.py frontier-diagnostics --worktree <worktree>`
* **Terminal Byte Audit**: `PYTHONPATH=src python3 tools/d810cli.py byte-audit --worktree <worktree>`

---

### Offline Diagnostic DB Queries

Locate the latest generated database and trace instruction EAs or list snapshots completely offline:

```bash
# Find latest DB in the worktree
WORKTREE_NAME=${YOUR_WORKTREE_DIR_NAME}
DB=$(ls -lhS .worktrees/${WORKTREE_NAME}/.tmp/logs/d810_logs/*.diag.sqlite3 | head -1 | awk '{print $NF}')

# List captured snapshots
sqlite3 $DB "SELECT id, label FROM snapshots"

# Trace specific EAs across snapshots
PYTHONPATH=.worktrees/${WORKTREE_NAME}/src python -m d810.core.diag ea-trace --db $DB 0x1800134A5 0x18001587E

# See all core diagnostics options
PYTHONPATH=.worktrees/${WORKTREE_NAME}/src python -m d810.core.diag --help
```

---

### Low-Level / Manual Workflow (Advanced)

Use only when `d810cli.py` does not expose the needed behavior. Review the available options first:
```bash
./tools/scripts/run_system_tests_docker.sh --help
```

#### Creating a worktree dump manually:
```bash
WORKTREE_NAME=${YOUR_WORKTREE_DIR_NAME}
truncate -s 0 .worktrees/${WORKTREE_NAME}/.tmp/logs/d810_logs/d810.log && \
D810_REPO_ROOT=/Users/mahmoud/src/idapro/d810 \
./tools/scripts/run_system_tests_docker.sh dump \
  -f sub_7FFD3338C040 \
  -p hodur_flag2.json \
  -w ${WORKTREE_NAME} \
  -o "sub_7ffd_$(date +'%Y%m%d_%H%M%S').txt" \
  -l \
  --enable-debug-logging \
  2>&1 | tail -3
```
*Manual artifacts appear under `.worktrees/${WORKTREE_NAME}/.tmp/`.*

#### Passing Additional Dump Arguments:
To forward extra arguments through the Docker runner, append `--` after `--enable-debug-logging`:

```bash
WORKTREE_NAME=${YOUR_WORKTREE_DIR_NAME}
truncate -s 0 .worktrees/${WORKTREE_NAME}/.tmp/logs/d810_logs/d810.log && \
D810_REPO_ROOT=/Users/mahmoud/src/idapro/d810 \
./tools/scripts/run_system_tests_docker.sh dump \
  -f sub_7FFD3338C040 \
  -p hodur_flag2.json \
  -o sub7FFD_diag_$(date +%Y%m%d-1).txt \
  -l \
  --enable-debug-logging -- \
  --dump-microcode-maturity CALLS,GLBOPT1 \
  --dump-microcode-d810 \
  --dump-terminal-return-valranges \
  --dump-bst-maturity GLBOPT1 \
  2>&1 | tail -3
```

---

### Key Guidance

1. **Prefer `d810cli.py`** for all standard deobfuscation workflows.
2. **Execute from the repository root**.
3. **Do not assume `ida_hexrays` is unavailable**; use the correct `PYTHONPATH` + `pyenv` invocation.
4. **Use low-level scripts only when necessary**.
5. **Dumps and DB artifacts** live under `.worktrees/<worktree>/.tmp/`.

---

### Alternative: In-Process pytest Dump Harness

`d810cli.py` wraps the Docker runner. For ad-hoc per-function dumps that load
the current project config inside a local headless IDA via `idalib` (no Docker,
no worktree), use `tests/system/e2e/test_dump_function_pseudocode.py`:

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

# Override binary
D810_TEST_BINARY=libobfuscated.dll pytest -s \
  tests/system/e2e/test_dump_function_pseudocode.py \
  --dump-function-pseudocode mixed_dispatcher_pattern
```

This is the workflow referenced from `.claude/rules/CORE_INSTRUCTIONS.md` and
project memory. Use `d810cli.py` when you need the Docker container + diag
SQLite artifacts under `.worktrees/<worktree>/.tmp/`; use the pytest harness
when you only need a quick before/after pseudocode snapshot from a local IDA.

---


## Backend-Aware Guard Note

- `tests/system/runtime/hexrays/test_mop_snapshot_guard.py` is intentionally backend-aware.
- `d810.hexrays.mop_snapshot.MopSnapshot` can resolve to either:
  - pure Python dataclass implementation, or
  - Cython extension implementation.
- Import order in a process can affect which implementation is loaded first.
- The guard test checks dataclass internals when the Python backend is active, and
  checks equivalent public field surface when the Cython backend is active.
- If you need deterministic pure-Python behavior for debugging this test:

```bash
D810_NO_CYTHON=1 PYTHONPATH=src pytest -q tests/system/runtime/hexrays/test_mop_snapshot_guard.py
```

## Operator Complexity Assertions

`assert_operator_complexity()` is a case-level guardrail for "did this
deobfuscation actually simplify expression shape?" checks.

Why it exists:

- Semantic equivalence alone is not enough for deobfuscation UX.
- Two outputs can be equivalent, but one can still be harder to read due to
  extra MBA noise.
- Operator-count trend checks catch readability regressions where transforms
  preserve meaning but increase surface complexity.

What it measures:

- It counts selected operator tokens in before/after pseudocode.
- Typical MBA set: `["+", "-", "*", "^", "&", "|"]`.
- It supports:
  - `decrease` (strictly fewer)
  - `non_increase` (same or fewer)

When to use:

- Add per-case via `DeobfuscationCase` fields:
  - `operator_complexity_mode`
  - `operator_complexity_ops`
- Use only for functions where simplification trend is part of expected product
  behavior.

When not to use:

- As a global test invariant across all functions.
- As a replacement for semantic/code-equivalence checks.

Limitations:

- This is lexical counting, not symbolic math complexity.
- Decompiler formatting/version changes can move tokens around.
- Equivalent rewrites can shift complexity across operator families.

Practical guidance:

- Default to `non_increase` for stability.
- Use `decrease` only when you have repeatedly validated that strict reduction
  is stable across target binaries/platforms/profiles.
