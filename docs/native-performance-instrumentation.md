# Opt-in native performance instrumentation

The bounded instrumentation phase follows the resolved `native_perf` runtime
setting. **Emit native performance receipts** in Settings > Developer can
select it, and saving the control persists `native_perf` in `options.json`.
An explicit `D810_NATIVE_PERF` environment variable overrides that saved value.
When the resolved setting is disabled, the hot path checks a provider-local
boolean and does not read a clock, increment a counter, allocate an
instrumentation snapshot object, or call into the registry. Optional modules
may still import and register providers at module load; this guarantee is
limited to the instrumented hot path and does not prohibit unrelated Python
allocations. The `clock_reads` counter is exposed so the disabled-path contract
can be tested directly.

## Operator controls

Open the D-810 configuration dialog and choose **Settings > Developer**. The
developer tab contains the performance controls:

- **Emit native performance receipts** selects the `D810_NATIVE_PERF` behavior.
- **Use non-mutating pattern matcher** selects the `D810_NOMUT_MATCHING`
  behavior.
- **Do not use Cython speedups** selects the current IDA session's Python
  dispatchers when compatible compiled speedups are installed.

The first two controls are runtime settings. Saving them writes
`native_perf` and `nomut_matching` to D810's `options.json`; they are restored
on the next D810 load. An explicitly set environment variable remains
authoritative over its saved value:

| Setting | Saved key | Environment override |
| --- | --- | --- |
| Native performance receipts | `native_perf` | `D810_NATIVE_PERF` |
| Non-mutating pattern matcher | `nomut_matching` | `D810_NOMUT_MATCHING` |

When an override is present, the dialog may still save the checkbox value, but
that saved value is not effective until the environment variable is unset.

The Cython checkbox has a different boundary. Its value is session-only and is
never written to `options.json`. `D810_NO_CYTHON` determines the initial policy
when IDA starts; when it explicitly disables Cython (`1`, `true`, or `yes`),
the checkbox is disabled and the dialog reports `Disabled by D810_NO_CYTHON`.
On the next IDA launch, the session choice again comes from the environment.

Changing the Cython checkbox and saving schedules D810's supported
`D810:reload_plugin` action after the dialog closes. The full plugin reload is
required because the AST and pattern-engine dispatchers select their Python or
Cython implementations at import time. The main D-810 configuration title
reports the implementations from the last completed load as exactly
`SPEEDUPS ENABLED`, `SPEEDUPS DISABLED`, or `SPEEDUPS UNAVAILABLE`.

If compatible compiled speedups cannot be imported, the Cython checkbox is
disabled and the exact availability copy is **`Speedups not installed`**. A
missing optional extension is retained as diagnostic detail; it does not add a
partial or degraded title state.

`D810_CYTHON_PROFILE=1` is build-time instrumentation. The Cython extensions
must be rebuilt with that flag so they contain tracing support; the Developer
settings dialog cannot retrofit line tracing into an extension that was already
built. This is separate from `D810_NATIVE_PERF`, which controls runtime
receipts in the loaded plugin.

## Lifecycle and receipt

At `SESSION_STARTED`, the manager begins the outer lifecycle session and
resets providers first, then applies the resolved runtime configuration and
discovers/validates providers. The outer `SESSION_FINISHED` emits one line when
`native_perf` is enabled:

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
mutating path by default, but indexed storage and its fingerprint/bucket
lookup counters are also on by default. `D810_LEGACY_STORAGE=1` selects the
legacy `PatternStorage` lookup and bypasses those indexed lookup counters.
When the resolved `nomut_matching` setting is enabled, the non-mutating
`match_pattern_nomut` final matcher and its match/node/binding counters are
used. The **Use non-mutating pattern matcher** control in Settings > Developer
persists `nomut_matching` in `options.json`; an explicit `D810_NOMUT_MATCHING`
environment variable overrides that saved value. The indexed path records
fingerprint calls/time, bucket lookups/hits/misses,
entries scanned/accepted, repeated-binding equality checks/time, and
result-list and `to_dict` materialization counts. The legacy `PatternStorage`
path is not instrumented.

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
