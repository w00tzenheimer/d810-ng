# Task 4 report: document and verify the complete feature

## Result

`DONE_WITH_CONCERNS`: the operator documentation is complete and the focused
compiled and Python-dispatcher verification passed. The worktree graph refresh
could not run because `graphify update .` failed with `Operation not
permitted`; no graph from the main checkout was touched. The known historical
default-runner assertion is recorded below and was directly exercised with
compiled extensions installed.

## Documentation

Updated `docs/native-performance-instrumentation.md` with:

- Settings > Developer activation and the exact control labels.
- The persistent `native_perf` and `nomut_matching` keys, their
  `options.json` boundary, and `D810_NATIVE_PERF` / `D810_NOMUT_MATCHING`
  precedence.
- The session-only Cython policy, `D810_NO_CYTHON` startup boundary, and the
  fact that the Cython checkbox is never persisted.
- Automatic post-dialog scheduling of the supported `D810:reload_plugin`
  action so import-time AST and pattern dispatchers rebind.
- The exact unavailable copy `Speedups not installed` and the three title
  states.
- The build-time-only `D810_CYTHON_PROFILE=1` boundary, separate from runtime
  `D810_NATIVE_PERF` receipts.

No production or test files were changed by Task 4.

## Focused compiled verification

The first required invocation was run from the main repository root without
host Docker permission:

```text
D810_NO_CYTHON=0 ./tools/scripts/run_system_tests_docker.sh test -w developer-speedup-controls -o developer_speedup_controls_full.txt -- tests/unit/core/test_cymode.py tests/unit/core/test_speedup_session.py tests/unit/core/test_settings.py tests/unit/manager/test_developer_settings_preferences.py tests/unit/ui/test_ida_ui_layout_contract.py tests/system/runtime/test_native_perf_instrumentation.py tests/system/runtime/test_nomut_matching.py tests/system/runtime/test_speedup_session_reload.py -q
```

Exit code: `1` before pytest. Docker reported:
`permission denied while trying to connect to the Docker API at
unix:///Users/mahmoud/.docker/run/docker.sock`.

The exact command was retried with the required host Docker permission and
completed with exit code `0`. Output:

```text
113 collected
111 passed, 2 skipped, 120 warnings in 14.87s
```

The two skips were the expected runtime skips in
`test_native_perf_instrumentation.py`; there were no failures. Warnings were
IDA/Hex-Rays SWIG deprecations plus the existing `get_func()` and
`gen_microcode(mba_ranges_t)` deprecations.

## Python-fallback verification

The required fallback invocation was run from the main repository root:

```text
D810_NO_CYTHON=1 ./tools/scripts/run_system_tests_docker.sh test -w developer-speedup-controls -o developer_speedup_controls_python.txt -- tests/unit/core/test_speedup_session.py tests/unit/core/test_settings.py tests/unit/ui/test_ida_ui_layout_contract.py tests/system/runtime/test_native_perf_instrumentation.py tests/system/runtime/test_nomut_matching.py -q
```

Exit code: `0`. The runner explicitly skipped the native build:
`[speedups] native build disabled by D810_NO_CYTHON=1`.

```text
80 collected
74 passed, 6 skipped, 118 warnings in 0.49s
```

The six skips were all compiled-mode cases in
`tests/system/runtime/test_native_perf_instrumentation.py`, at lines 73, 143,
236, 283, 316, and 361, each with reason `compiled mode is disabled`. The
same slice was rerun with `-rs`; no failure was hidden by a skip.

The prior Task 2 default-runner attempt exposed this pre-existing assertion:

```text
tests/system/runtime/test_native_perf_instrumentation.py::TestNativePerfInstrumentation::test_python_mode_selects_python_providers_with_extensions_present
```

That test requires the compiled `.so` modules even though it selects Python
dispatchers. The current `idapro-9.4-speedups:latest` image already exposed
those modules, so the exact fallback command did not reproduce the old
failure. It is retained here rather than treating the six compiled-mode skips
as proof of compiled-extension coverage.

The runner has no separate `build extensions / run Python dispatchers` option.
Its documented `exec` setup path can express the mixed case, so it was used
with host `D810_NO_CYTHON=0` for setup/build and a child
`D810_NO_CYTHON=1` for pytest:

```text
D810_NO_CYTHON=0 ./tools/scripts/run_system_tests_docker.sh exec -w developer-speedup-controls -- bash -lc 'D810_NO_CYTHON=1 "$PYTHON" -m pytest tests/unit/core/test_speedup_session.py tests/unit/core/test_settings.py tests/unit/ui/test_ida_ui_layout_contract.py tests/system/runtime/test_native_perf_instrumentation.py tests/system/runtime/test_nomut_matching.py -q > /work/.tmp/developer_speedup_controls_python_with_extensions.txt 2>&1; status=$?; cat /work/.tmp/developer_speedup_controls_python_with_extensions.txt; exit $status'
```

Exit code: `0`; the mixed slice reported `74 passed, 6 skipped, 118
warnings in 0.36s`. The six compiled-mode skips remain intentional because
the child process selected Python mode.

The compiled-extension/Python-dispatcher assertion was then run directly:

```text
D810_NO_CYTHON=0 ./tools/scripts/run_system_tests_docker.sh exec -w developer-speedup-controls -- bash -lc 'D810_NO_CYTHON=1 "$PYTHON" -m pytest tests/system/runtime/test_native_perf_instrumentation.py -k test_python_mode_selects_python_providers_with_extensions_present -q -s'
```

Exit code: `0`; `1 passed, 10 deselected, 118 warnings in 0.02s`. The test
printed compiled extension paths for both `c_ast` and `c_pattern_match` under
`/work/src/d810/.../*.so` while asserting the AST, pattern engine, and native
performance providers selected Python implementations.

## Architecture and hygiene gates

All commands below ran inside
`/Users/mahmoud/src/idapro/d810/.worktrees/developer-speedup-controls`:

```text
sg scan --config sgconfig.yml --report-style short
```

Exit code: `0` (no violations printed).

```text
PYTHONPATH=src lint-imports --config .importlinter
```

Exit code: `0`; `Analyzed 2067 files, 12363 dependencies` and `Contracts: 14
kept, 0 broken.`

```text
git diff --check
```

Exit code: `0`; no whitespace errors.

Before the Task 4 commit, `git status --short` showed only:

```text
 M docs/native-performance-instrumentation.md
```

The worktree diff was one documentation file with 48 added lines. The
`git diff --stat cfg-recon-mainline...HEAD` baseline inspection showed the 15
files from Tasks 1-3 (`761 insertions, 63 deletions`); those existing feature
commits were not changed by Task 4.

## Graph refresh concern

`graphify-out/` existed in the worktree only as an empty graph directory with
cache state; it had no `graph.json` or report. After reading the graphify
instructions, the required command was attempted from the worktree:

```text
graphify update .
```

Exit code: `1`. The command reported:

```text
Nothing to update or rebuild failed — check output above.
Re-extracting code files in . (no LLM needed)...
[graphify watch] Rebuild failed: [Errno 1] Operation not permitted
```

No tracked graph artifacts were created, and the main checkout's graph was not
updated with this worktree as a substitute.

## Self-review

- The docs distinguish persisted runtime settings from the session-only Cython
  policy and do not claim that changing `CythonMode` alone rebinds imports.
- The exact unavailable copy is present verbatim, with no partial/degraded
  state introduced.
- `D810_CYTHON_PROFILE=1` is documented as build-time instrumentation and not
  as a dialog-toggleable runtime feature.
- No placeholder text was added to the operator documentation or this report.
