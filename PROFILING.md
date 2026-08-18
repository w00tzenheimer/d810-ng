# Profiling D810

This document is the durable index and runbook for profiling D810 in the IDA
9.4 Linux runtime. It records the methodology and conclusions from the August
2026 SCCP/cache investigation, explains the available profiling layers, and
points to the raw captures while they remain available locally.

The central lesson from that investigation is methodological: do not infer a
hotspot from a long quiet interval or a repeated log message. Bound the exact
workload, capture the active maturity, sample the real IDA process, and change
one runtime dimension at a time.

## Profiling layers

D810 has four complementary profiling layers. They answer different
questions and should not be treated as interchangeable.

| Layer | Best use | Main output | Important limitation |
| --- | --- | --- | --- |
| `ProfilingController` | Attribute Python time by Hex-Rays maturity | `d810_cprofile.prof`, `d810_cprofile_MMAT_*.prof`, pyinstrument HTML/text | Deterministic instrumentation can heavily perturb callback-intensive workloads |
| `py-spy` | Low-overhead Python call-stack sampling inside the IDA container | SVG flamegraph and textual stack dump | Does not explain time spent entirely in opaque native frames |
| Linux `perf` | Sample Python, Cython, IDA/Hex-Rays, libc, and kernel-visible native work | `perf.data`, hierarchical and flat reports | Symbol quality depends on binaries, frame pointers, and unwind information |
| Native performance receipts | Count selected hot-path operations with profiling disabled by default | `D810_NATIVE_PERF_RECEIPT={...}` | Inclusive timing fields overlap and must not be added together |

`D810_CYTHON_PROFILE=1` is a fifth, specialized mode. It rebuilds the Cython
extensions with trace support for attribution. It perturbs execution and must
not be used for the first timing comparison or as optimized production timing.

## Repository support

The relevant maintained surfaces are:

- `src/d810/manager/profiling.py`: owns pyinstrument, cProfile, and per-maturity
  snapshots.
- `src/d810/core/native_perf.py`: process-local native performance provider
  lifecycle and receipt aggregation.
- `docs/native-performance-instrumentation.md`: settings, receipt schema,
  counter domains, and interpretation guidance.
- `tests/system/runtime/evaluator/test_sccp_cache_performance.py`: the attested
  SCCP/cache workload, bounded post-PREOPT profile, parity receipt, and
  verification logic.
- `tools/scripts/run_system_tests_docker.sh`: installs `perf` and `py-spy` only
  when `D810_NATIVE_PROFILE=1`, and grants `PERFMON`, `SYS_PTRACE`, and the
  narrow seccomp relaxation needed to attach profilers.

Run IDA-dependent profiling from the main repository root. A worktree name is
passed with `-w`; the runner mounts that worktree at `/work`.

## Exact SCCP workload

The August 2026 investigation used this immutable workload:

| Property | Value |
| --- | --- |
| Worktree | `sccp-cython-performance` |
| Function EA | `0x7ff8560d8ae0` |
| Binary | `MMORPG_loader-115.9.6910.9-devirt.dll.i64` |
| Fixture SHA-256 | `4eeda74c08f668c55dd0810174055d3da2446c0a85563c29f4c9387738b31cb5` |
| SCCP program | 226 blocks, 3,642 instructions |
| Constant MOP cache | 4,096 entries |
| AST MOP cache | 40,960 entries |
| Runtime image | `idapro-9.4-speedups:latest` |
| Runtime Python | CPython 3.13.15 |

The bounded profile target is:

```text
tests/system/runtime/evaluator/test_sccp_cache_performance.py::TestSccpCachePerformance::test_bounded_post_preopt_profile
```

It forces a no-cache decompilation, applies the stated cache capacities, and
terminates the profiling window after `D810_PROFILE_SECONDS` rather than
waiting blindly for the whole exact receipt sequence.

## Reproducing the bounded controller profile

The compiled production configuration with the SCCP overlay enabled is the
normal attribution baseline:

```bash
cd /path/to/d810

D810_NO_CYTHON=0 \
D810_NATIVE_PROFILE=1 \
D810_PERF_GATE=1 \
D810_PROFILE_CONTROLLER=on \
D810_PROFILE_SCCP_OVERLAY=on \
D810_PROFILE_SECONDS=180 \
D810_PROFILE_LABEL=compiled-overlay-on \
D810_SCCP_FUNCTION_EA=0x7ff8560d8ae0 \
D810_EXPECTED_FIXTURE_SHA256=4eeda74c08f668c55dd0810174055d3da2446c0a85563c29f4c9387738b31cb5 \
D810_FIXTURE_ATTESTATION=.tmp/sccp_exact_fixture_attestation.json \
D810_TEST_BINARY=MMORPG_loader-115.9.6910.9-devirt.dll.i64 \
./tools/scripts/run_system_tests_docker.sh test \
  -w WORKTREE \
  -o bounded-profile.txt \
  -- -m profile \
  tests/system/runtime/evaluator/test_sccp_cache_performance.py::TestSccpCachePerformance::test_bounded_post_preopt_profile \
  -q -s
```

The output directory inside the worktree is:

```text
.tmp/profiles/compiled-overlay-on/
```

It contains the combined cProfile, maturity snapshots, pyinstrument HTML/text,
and metadata when the bounded window completes normally or is stopped by its
watchdog.

### Controlled comparisons

Change exactly one dimension per run:

1. Compiled production configuration with `D810_PROFILE_SCCP_OVERLAY=on`.
2. The same compiled configuration with `D810_PROFILE_SCCP_OVERLAY=off`.
3. If a rule is implicated, the same configuration with only that rule or
   admission path toggled.

Do not use global `D810_NO_CYTHON=1` as the SCCP overlay baseline. That changes
the entire optimizer portfolio rather than isolating SCCP/FCP. A pure-Python
run remains useful for solver parity and implementation comparison, but it is
not an attribution control for a single overlay.

## Attaching py-spy

Set `D810_NATIVE_PROFILE=1` on the runner so the container has `py-spy`,
`SYS_PTRACE`, and the required seccomp policy. For the lowest perturbation,
turn the built-in controller off:

```bash
D810_PROFILE_CONTROLLER=off
```

Wait until the test enters the maturity window being investigated, identify
the pytest/IDA Python PID inside the container, then capture a bounded sample:

```bash
/app/ida/.venv/bin/py-spy record \
  --rate 50 \
  --duration 60 \
  --nonblocking \
  --pid PYTEST_PID \
  --output /work/.tmp/profiles/LABEL/py-spy.svg

/app/ida/.venv/bin/py-spy dump \
  --pid PYTEST_PID \
  > /work/.tmp/profiles/LABEL/py-spy-dump.txt
```

Store `command.txt` and `environment.txt` beside every capture. At minimum,
record the fixture hash, function EA, runtime image and image ID, Python
version, Cython mode, overlay mode, cache capacities, profile duration, and
the exact source revision.

The useful comparison window in the SCCP investigation began only after the
`MMAT_PREOPTIMIZED` analysis marker. Sampling the whole process would have
diluted the silent post-PREOPT interval with container startup and earlier
maturities.

## Attaching Linux perf

The runner provisions Linux `perf` and grants `PERFMON` when
`D810_NATIVE_PROFILE=1`. The historical native capture used:

```bash
perf record \
  -F 99 \
  -g \
  --call-graph dwarf \
  -p PYTEST_PID \
  -- sleep 210

perf report -i perf.data > perf-report.txt
perf report -i perf.data --stdio --no-children > perf-report-flat.txt
```

Prefer a build with debug symbols and usable frame pointers when native or
Cython attribution is important. Preserve the raw `perf.data`; textual reports
are convenient but cannot be reprocessed with different grouping, call-graph,
or symbolization settings.

The retained `exact-perf-overlay-on` artifact was a historical Python-only
native capture (`D810_NO_CYTHON=1`). It helped establish that SCCP itself was
not the dominant native stack, but it is not the controlled compiled
overlay-on versus overlay-off comparison described above.

## Reading cProfile by maturity

`ProfilingController.dump_segment()` writes a snapshot each time the maturity
changes:

```text
d810_cprofile_MMAT_ZERO.prof
d810_cprofile_MMAT_GENERATED.prof
d810_cprofile_MMAT_PREOPTIMIZED.prof
...
```

Convert a binary profile into a stable cumulative report with:

```bash
python -m pstats PROFILE.prof
```

Then use `sort cumulative`, `stats`, and `callers`, or generate a report
programmatically:

```bash
python -c 'import pstats; pstats.Stats("PROFILE.prof").strip_dirs().sort_stats("cumulative").print_stats(100)'
```

cProfile is deterministic but invasive. In this callback-heavy workload it
recorded almost 195 million calls during PREOPT and materially changed the
runtime. Use it to identify call relationships and maturity ownership, then
confirm the suspected improvement with low-overhead sampling.

## Findings from the SCCP/cache investigation

### SCCP was not the multi-minute bottleneck

The immutable SCCP solver results were:

- Python median: approximately 232.8 microseconds.
- Cython median: approximately 7.0 microseconds.
- Solver speedup: approximately 33.5x.
- Python/Cython parity and fingerprints matched.

The solver therefore could not explain the multi-minute silent interval.
Repeated `sccp: hit iteration limit` log messages were conspicuous, but they
were not evidence that the solver owned the wall time.

### Maturity attribution

The initial deterministic split was:

| Maturity | Profiled time |
| --- | ---: |
| `MMAT_ZERO` | 1.402 s |
| `MMAT_GENERATED` | 3.894 s |
| `MMAT_PREOPTIMIZED` | 64.599 s |

A later controller run spent 42.972 of 73.667 profiled seconds repeatedly
lifting the flowgraph. The original PREOPT profile included approximately:

- 36.17 s under `ir_translator.lift()`.
- 35.69 s under `capture_insn_snapshot()`.
- 21.29 s under the instruction callback wrapper.
- 16.01 s under opcode lookup.
- 12.97 s under opcode classification.
- 10.83 s under optimizer dispatch.
- 9.56 s under repeated `inspect.getfullargspec()` calls.

These numbers are diagnostic rather than additive: cumulative times overlap.

### Low-overhead sampling

The first useful post-PREOPT py-spy sample placed:

- 23.57% of sampled CPU in `PatternOptimizer._resolve_ast_with_tracker`.
- 4.49% in the actual MopTracker fallback.

The rest was primarily AST construction, recursive definition resolution,
native predecessor search, and per-instruction optimizer dispatch. The cost
was the repeated preparation and matching around each callback, not the SCCP
fixed-point solver.

### Rejected def-list caching

Callback-local `build_def_list` reuse was tested and removed. Matching
60-second windows produced 2,455 samples and 544 errors each:

- Reuse off: whole resolver appeared in 13.33% of samples.
- Reuse on: whole resolver appeared in 15.03% of samples.
- The small `find_def_in_block` leaf fell from 1.63% to 0.98%.

That local improvement did not reduce the enclosing resolver and did not earn
the additional production complexity.

### Retained admission cache

Fast-tier residual admission was being recomputed on every instruction
callback. It occupied 182 of 2,455 baseline samples, or 7.42%.

The retained optimization caches the result by maturity, allowed rule names,
and scheduled rule names. It invalidates on optimizer/rule registration,
execution-scope changes, and run-later lifecycle changes. In the matching
post-fix capture, `_has_active_fast_mba_provider` fell below the profiler's
sample threshold.

The resolver cache was also corrected to use callback-local exact
microinstruction identity: block serial plus live SWIG pointer/object identity.
EA-only identity is insufficient for microcode provenance. The experimental
`src/d810/core/tracker.py` was not adopted as production infrastructure.

### Native perf result

The native profile did not identify SCCP as dominant. The largest visible
stacks were IDAPython/Hex-Rays wrapper lifecycle and clock sampling, including
`hexrays_deregister_python_clearable_instance` and `clock_gettime`. Missing or
opaque native symbols limit how strongly that particular profile can divide
Hex-Rays work from wrapper work.

## Historical artifact index

These raw artifacts currently exist beneath the ignored performance worktree.
They are evidence, not tracked repository content, and may disappear if that
worktree is removed.

Base directory:

```text
.worktrees/sccp-cython-performance/.tmp/profiles/
```

| Artifact | Purpose |
| --- | --- |
| `2026-08-17-sccp-hotspot-report.md` | Original written hotspot report |
| `exact-perf-overlay-on/perf.data` | 179 MB raw Linux perf capture |
| `exact-perf-overlay-on/perf-report.txt` | Hierarchical native report |
| `exact-perf-overlay-on/perf-report-flat.txt` | Flat native-symbol report |
| `exact-compiled-overlay-on/d810_cprofile_MMAT_*.prof` | Per-maturity deterministic profiles |
| `exact-compiled-overlay-on/d810_cprofile_MMAT_*-report.txt` | Rendered maturity reports |
| `exact-pyspy-postpreopt-defcache-off-window/py-spy.svg` | Baseline post-PREOPT flamegraph |
| `exact-pyspy-postpreopt-admission-cache-window/py-spy.svg` | Retained admission-cache flamegraph |
| `exact-pyspy-postpreopt-defcache-window/py-spy.svg` | Rejected def-list-cache flamegraph |
| `exact-pyspy-postpreopt-optimized2/py-spy.svg` | Later optimized-path flamegraph |
| `exact-pyspy-compiled-overlay-on/` | Compiled overlay-on sampling |
| `exact-pyspy-compiled-overlay-off/` | Compiled overlay-off sampling |
| `exact-pyspy-compiled-ast-gateway/` | AST gateway experiment |
| `exact-pyspy-compiled-ast-tracker-off/` | Tracker-disabled comparison |
| `exact-pyspy-postpreopt-cdef/` | Cython definition-resolution experiment |
| `exact-pyspy-postpreopt-native-def/` | Native definition-resolution experiment |

Additional runner logs and exact receipt fragments are in:

```text
.worktrees/sccp-cython-performance/.tmp/
```

Notable files include `profile_exact_compiled_on.txt`,
`premerge-perf-python.txt`, `premerge-perf-cython.txt`,
`postrebase-perf-cython-clean.txt`, `postrebase-perf-final-green.txt`, and
`sccp_perf_green.txt`.

The main checkout also currently contains a separate antidebug capture:

```text
.tmp/profiles/antidebug-exception-filter/
```

It includes `d810_profile.html`, `d810_profile.txt`, a combined cProfile, and
per-maturity cProfile snapshots. Earlier Eid exact-A pyinstrument and
cProfile experiments remain under:

```text
.worktrees/eid-v2-unflattening-completeness/.tmp/
```

## Preservation policy

Do not rely on `.tmp` as the only record of a profiling conclusion. For every
completed investigation:

1. Add the workload identity, exact controls, profiler commands, environment,
   attribution, rejected hypotheses, retained change, and verification here.
2. Keep generated flamegraphs, reports, and receipts under the worktree's
   `.tmp/profiles/LABEL/` directory while active.
3. Keep large binary captures such as `perf.data` out of Git unless the
   repository deliberately adopts artifact storage.
4. Before removing a worktree, preserve any raw capture still needed for
   reproducibility in external artifact storage and update this index with its
   durable location and checksum.
5. Never claim a performance improvement from cProfile alone. Confirm it with
   an identical low-overhead sampling window or an exact end-to-end timing run,
   while preserving semantic, parity, and fail-closed checks.

## Checklist for the next investigation

- Attest the binary, copied IDB, function EA, source revision, runtime image,
  Python ABI, and configuration.
- Establish a bounded marker-gated window before launching a long run.
- Capture maturity ownership with the built-in controller.
- Capture low-overhead Python stacks with py-spy.
- Capture native stacks with perf when Python samples leave time unexplained.
- Compare one changed dimension at a time.
- Treat Cython trace builds as attribution-only.
- Write a failing behavior or performance regression before optimizing.
- Re-run the bounded capture after the change.
- Run exact end-to-end timing only after the hotspot has been attributed.
- Preserve semantic/parity receipts along with timing evidence.
