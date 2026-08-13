# Task 5 report: complete verification and performance accounting

## Status

Complete. Task 5 adds a non-flaky, profile-marked performance receipt that
separates cold whole-catalogue certification from per-candidate root-bucket
work. It records elapsed time with `time.perf_counter()` but gates only stable
structural facts: 188 receipts, 108 compiled rules, 14 rules in the selected
XOR-root bucket, and exactly 14 real `specialize()` calls in catalogue order.

No production defect emerged, so no production file changed. The two deferred
test-isolation concerns were both cheap and correct to repair:

- The central-statistics test no longer seeds `last_rule_family` or
  `last_rule_provenance`. It builds a real XOR-family candidate, invokes the
  real `EgglogOptimizer.check_and_replace()` / `_select_specialization()` path,
  stubs only native AST conversion, candidate admission, and final instruction
  materialization, and then checks the metadata transported into central
  statistics.
- The native config-v2 receipt now asserts `state.current_blk_rules == []` and
  exact `state.last_pipeline_v2_hook_pass_ids == ("mba-egglog",)` in addition
  to exact instruction-rule isolation.

The native family fixture now also prints its own `perf_counter()` runtime,
without imposing a timing threshold.

## Performance receipt

The structural accounting is the correctness contract:

| Metric | Asserted value |
| --- | ---: |
| Whole-corpus receipts | 188 |
| Closed-family compiled rules | 108 |
| Selected root | `xor` |
| Selected root-bucket candidates | 14 |
| Actual specialization attempts | 14 |

The elapsed values are diagnostic evidence only:

| Context | Cold catalogue | Selected XOR bucket | Native family fixture |
| --- | ---: | ---: | ---: |
| Host inventory probe | 23.903509 s | not run | not run |
| Isolated Docker performance test | 27.474665 s | 0.004968 s | measured separately |
| Combined Docker runtime suite | 47.392400 s | 0.003091 s | measured separately |
| Focused Docker e2e | configuration-owned | configuration-owned | 24.852611 s |

The focused retained-ADD plus family e2e command completed in 55.36 seconds.
The explicit 24.852611-second native-family receipt includes project loading,
cold selected-catalogue construction, decompilation, three live rewrites, and
receipt checks. It is intentionally not presented as pure rewrite time.

The cold value varies substantially with process/test ordering and machine
load, while the selected XOR-bucket work remained a few milliseconds. This is
the key performance conclusion: the current future performance question is
cold catalogue startup (approximately 24 seconds in the clean host/isolated
measurements, and 47 seconds under combined-suite load), not an unbounded
per-candidate scan. No elapsed number is a pass/fail criterion.

## Verification commands and results

Lifecycle entry:

```bash
simba codex-recall "Task 5 complete verification and performance accounting Egglog MBA wide catalogue cold compile specialization attempts native Docker e2e"
simba codex-status
```

Result: recall returned no task-specific memories; the Simba daemon, memory,
and readiness checks were healthy. Status reported no latest Codex transcript
metadata and therefore no pending extraction to run.

Independent host inventory and cold timing:

```bash
PYTHONPATH=src pyenv exec python -u - <<'PY'
# compile_mba_rule_catalogue(), time with perf_counter(), and count pattern roots
PY
```

Result: 23.903509 seconds, 108 compiled rules. Root counts were `add=24`,
`and=10`, `bnot=2`, `or=20`, `sub=38`, and `xor=14`.

An initial plain Docker `exec` probe was deliberately rejected as an authority
for handler accounting because it failed to import `_ida_hexrays` outside the
IDA harness. The subsequent runtime measurements all used the worktree's
authoritative `test` command.

Focused performance receipt:

```bash
D810_REPO_ROOT=/Users/mahmoud/src/idapro/d810 \
  tools/scripts/run_system_tests_docker.sh test -w egglog-mba-spike -- \
  tests/system/runtime/backends/test_egglog_mba_performance.py \
  -m profile -s -q
```

Result: `1 passed, 118 warnings in 28.53s`; receipt: cold 27.474665 seconds,
14 XOR-root candidates, 14 specialization attempts, selected work 0.004968
seconds.

Focused real-handler statistics transport:

```bash
D810_REPO_ROOT=/Users/mahmoud/src/idapro/d810 \
  tools/scripts/run_system_tests_docker.sh test -w egglog-mba-spike -- \
  tests/system/runtime/backends/test_egglog_mba_family_specialization.py::test_central_statistics_records_selected_family_provenance \
  -q
```

Result: `1 passed, 118 warnings in 29.88s`.

Focused pure catalogue/config/bridge suite:

```bash
PYTHONPATH=src:tests pyenv exec python -m pytest -q \
  tests/unit/mba/test_egglog_add_rule_catalogue.py \
  tests/unit/mba/test_egglog_mba_catalogue.py \
  tests/unit/passes/test_mba_egglog.py \
  tests/unit/passes/test_pipeline_v2_hook_bridge.py \
  tests/unit/passes/test_pipeline_config_parser.py
```

Result: `100 passed, 12 subtests passed in 138.27s`.

Combined Docker runtime/compiler/specialization/performance suite:

```bash
D810_REPO_ROOT=/Users/mahmoud/src/idapro/d810 \
  tools/scripts/run_system_tests_docker.sh test -w egglog-mba-spike -- \
  tests/system/runtime/backends/test_egglog_add_rule_compiler.py \
  tests/system/runtime/backends/test_egglog_mba_family_specialization.py \
  tests/system/runtime/backends/test_egglog_mba_performance.py \
  -m 'profile or not profile' -s -q
```

Result: `44 passed, 118 warnings in 94.62s`; receipt: cold 47.392400
seconds, 14 XOR-root candidates, 14 specialization attempts, selected work
0.003091 seconds.

Retained ADD plus native family e2e:

```bash
D810_REPO_ROOT=/Users/mahmoud/src/idapro/d810 \
  tools/scripts/run_system_tests_docker.sh test -w egglog-mba-spike -- \
  tests/system/e2e/test_egglog_add_spike.py \
  tests/system/e2e/test_egglog_mba_families_spike.py -s -q
```

Result: `4 passed, 122 warnings in 55.36s`; explicit native family fixture
receipt: `EGGLOG_MBA_NATIVE_FIXTURE_SECONDS=24.852611`. The three exact live
receipts remained ADD / XOR / SUB in order.

Relevant Ruff and diff gates:

```bash
pyenv exec ruff check \
  tests/system/runtime/backends/test_egglog_mba_performance.py \
  tests/system/runtime/backends/test_egglog_mba_family_specialization.py \
  tests/system/e2e/test_egglog_mba_families_spike.py
pyenv exec ruff format --check \
  tests/system/runtime/backends/test_egglog_mba_performance.py \
  tests/system/runtime/backends/test_egglog_mba_family_specialization.py \
  tests/system/e2e/test_egglog_mba_families_spike.py
git diff --check
```

Result: Ruff passed, all three files were already formatted, and diff check
passed.

A broader `pyenv exec ruff check src tests` was also attempted and reported
865 existing errors across vendored and legacy files outside this task. The
owned-file gate above is clean; Task 5 did not opportunistically rewrite that
unrelated repository baseline.

Architecture gates:

```bash
sg scan --config sgconfig.yml --report-style short
PYTHONPATH=src lint-imports --config .importlinter
```

Result: ast-grep passed. Import-linter analyzed 1,892 files / 10,916
dependencies and kept all 14 contracts with 0 broken.

Graph refresh:

```bash
graphify update .
```

Result: graph rebuilt successfully at 52,658 nodes / 159,486 edges / 1,042
communities. It repeated the existing two C syntax warnings and 103 zero-node
JSON/config/source warnings. Graph outputs are ignored working artifacts and
did not enter the task diff.

Lifecycle completion:

```bash
simba codex-finalize
```

Result: exited 0. Signal checking was skipped because no response file was
provided, and reflection capture was skipped because no transcript was found.

## Files changed

- `tests/system/runtime/backends/test_egglog_mba_performance.py`
- `tests/system/runtime/backends/test_egglog_mba_family_specialization.py`
- `tests/system/e2e/test_egglog_mba_families_spike.py`
- `.superpowers/sdd/2026-08-12-mba-wide-egglog-catalogue/task-5-report.md`

No production source, catalogue policy, proof contract, candidate guard,
configuration, sample binary, or native fixture changed.

## Concerns

- `compile_mba_rule_catalogue()` still certifies the whole corpus on each call;
  this task measures that cost but deliberately does not add a cache.
- The new performance test is marked `profile`, matching repository policy for
  slow diagnostic tests. It must be selected explicitly with `-m profile` (or
  the combined expression shown above); normal pytest runs exclude it.
- The worktree Docker runner still refreshes stale baked test dependencies on
  every container invocation. That setup cost is outside the explicit
  `perf_counter()` receipts but increases command wall time.
- Timings are machine-, load-, and test-order-dependent. The structural counts
  are the only regression gates.
