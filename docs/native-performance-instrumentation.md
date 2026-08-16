# Opt-in native performance instrumentation

The bounded instrumentation phase is enabled only when
`D810_NATIVE_PERF=1`. With the flag unset (or set to any value other than
`1`), the hot path checks a provider-local boolean and does not read a clock,
increment a counter, allocate an instrumentation snapshot object, or call
into the registry. Optional modules may still import and register providers at
module load; this guarantee is limited to the instrumented hot path and does
not prohibit unrelated Python allocations. The `clock_reads` counter is
exposed so the disabled-path contract can be tested directly.

## Lifecycle and receipt

At `SESSION_STARTED`, the manager begins the outer lifecycle session and
resets providers first, then applies the environment configuration and
discovers/validates providers. The outer `SESSION_FINISHED` emits one line
when the flag is enabled:

```
D810_NATIVE_PERF_RECEIPT={...}
```

The core-owned registry keeps this boundary below the optional Cython modules.
Providers register snapshot/configure/reset callbacks under stable names. A
new provider with the same name first disables the previous callback, then is
configured to the current enabled state. This makes fallback-to-Cython import
order and reloads safe without retaining a native object. Provider callback
exceptions are isolated and reported in `provider_errors`; `complete` is false
when an error has been observed. Provider, discovery, and lifecycle errors are
sticky for the current session even if a later configure/reset succeeds; the
next outermost session begins a new error epoch.

Receipts use schema version 1 and deterministic sorted JSON. They include the
enabled flag, aggregate backend, provider names and identities, reset/session
generation, safe session metadata, clock provenance, the
`D810_CYTHON_PROFILE=1` trace-request flag, provider completeness, and provider
errors. Values are copied through a JSON-safe boundary; unknown IDA/SWIG
objects become a type marker and are never retained in the receipt.

Sessions are process-local lifecycle events. The outermost `begin_session`
resets providers and captures function EA, database identity, top-level epoch,
and session id. Nested owners share that generation and counters, and their
work is included in the single outer receipt. `end_session` validates the
optional primitive session token; a mismatch or underflow records a lifecycle
error without emitting a receipt. Only the matching outermost end emits the
receipt; lifecycle errors are cleared when the next outermost session begins.
The receipt is not a cross-process aggregation format.

## Counter domains and actual paths

The `pattern_match` provider is a C struct in `c_pattern_match.pyx` when the
Cython backend is selected, and a matching Python dictionary provider in
`pattern_speedups.py` otherwise. The production matcher remains the legacy
mutating path by default; `D810_NOMUT_MATCHING=1` is required to opt into the
indexed `COpcodeIndexedStorage` and `match_pattern_nomut` path covered here.
That path records fingerprint calls/time, indexed bucket lookups/hits/misses,
entries scanned/accepted, non-mutating matcher calls/time/nodes, binding
additions, repeated-binding equality checks/time, and result-list and
`to_dict` materialization counts. The legacy `PatternStorage` path is not
instrumented.

The production AST path is not the standalone Cython `mop_to_ast` helper. It
is `minsn_utils.minsn_to_ast` -> Python `mop_utils.mop_to_ast` and its recursive
`mop_to_ast_internal` builder. `mop_utils` counts owner-scope key creation,
global `MOP_TO_AST_CACHE` lookups/hits/misses, local builder-cache lookups and
hits/misses, AST constructions, and proxy-return boundaries. The selected AST
backend (`c_ast.pyx` or `p_ast.py`) counts structural `get_mop_key` work and
`AstProxy` construction. The global key includes `mop_mba_owner_scope`; the
owner-scope counter is separate from structural-key calls so these boundaries
are not conflated.

## Timing interpretation

Cython providers use a portable native `std::chrono::steady_clock` helper;
Python providers use `time.perf_counter_ns`. Fingerprint and matcher timings
are inclusive spans. Matcher spans include recursive node walks and repeated
binding equality work; fingerprint spans include recursive Python object
accesses. Therefore timing fields overlap and must not be added together.
Clock-read overhead is not calibrated in this phase. The counters are for
attribution and comparative diagnosis, not microsecond-level acceptance
thresholds. `D810_CYTHON_PROFILE=1` remains a separate trace-enabled build and
cProfile attribution mode; its traced timings must not be used for optimized
benchmark comparisons.

## Known limits

This phase does not rewrite native containers or instrument the legacy matcher.
It also does not repair the existing `CMatchBindings`/`minsn` destination
borrowed-object seam. Counters and receipts avoid adding new retained SWIG
objects, but that pre-existing ownership boundary remains a limitation for
future work. The provider registry and lifecycle callbacks are intentionally
IDA-main-thread-only for this bounded phase. Concurrent registration,
configuration, and snapshot calls are unsupported; the registry lock is not a
promise of thread-safe semantics.
