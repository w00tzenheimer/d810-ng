# Egglog MBA Semantic Simplification

This document summarizes the domain-lifted Egglog/MBA work integrated into
`cfg-recon-mainline` at `202f42294`. The merge added a proof-carrying,
opt-in semantic MBA pipeline. It did not add a destructive global Hex-Rays AST
canonicalizer.

## Execution model

The runtime portfolio is ordered as follows:

```text
chain and direct fast paths
  -> residual-candidate gate
  -> portable fixed-width semantic canonicalization
  -> IDB learned-replay lookup
  -> bounded Egglog degree-1/degree-2 saturation
  -> native reconstruction
  -> mandatory semantic proof
  -> outer mutation acceptance
```

The fast chain and direct catalogue matchers remain first. Egglog receives only
the supported residual expressions that survive those providers and the
configured structural budgets.

The outer mutation owner remains authoritative. Constructing a cheaper
candidate records an `IMPROVED` provider outcome, but it becomes `APPLIED` only
after operand-size, expression-bloat, swap, and cycle guards accept the native
mutation.

## What was added

### Portable semantic canonicalization

The canonicalizer operates on a typed, fixed-width bit-vector term rather than
rewriting the live Hex-Rays AST. The lowering keeps the raw term and exact
native source paths alongside the canonical term.

It normalizes supported forms including:

- homogeneous associative-commutative trees;
- subtraction and negation;
- modular negative coefficients;
- same-width constant expressions;
- exact literal fixed-count shifts and complementary rotate trees.

This avoids the old representation gap where synthetic AST nodes lost the
native `mop_t` provenance needed for reconstruction. The raw native expression
also remains the cost baseline, so canonicalization alone cannot be credited as
an optimization.

Relevant implementation:

- [`src/d810/mba/semantic_canonicalization.py`](src/d810/mba/semantic_canonicalization.py)
- [`src/d810/mba/canonical_pattern.py`](src/d810/mba/canonical_pattern.py)
- [`src/d810/mba/typed_term.py`](src/d810/mba/typed_term.py)
- [`src/d810/backends/mba/hexrays_island.py`](src/d810/backends/mba/hexrays_island.py)

### Certified catalogue compilation

Certified `VerifiableRule` patterns and replacements pass through the same
canonical representation as runtime candidates. Their semantic fingerprints
include the pattern, replacement, constraints, supported widths, rule
implementation inputs, and the matcher/emitter runtime semantics.

This creates a bounded alternative to generating large commutative and
associative pattern-permutation inventories. The shipped Egglog profiles set
`generate_commutative_permutations` to `false`.

Structural matching remains certificate-gated and legacy-default. An
environment variable alone cannot authorize it. A valid certificate is bound
to all of the following:

- catalogue snapshot;
- corpus and toolchain digests;
- Python or Cython runtime mode;
- observation coverage and zero parity mismatches;
- active matcher, binding, materialization, and proof-emitter semantics.

Relevant implementation:

- [`src/d810/backends/mba/compiled_pattern_catalogue.py`](src/d810/backends/mba/compiled_pattern_catalogue.py)
- [`src/d810/mba/certified_catalogue.py`](src/d810/mba/certified_catalogue.py)
- [`src/d810/mba/ac_matching.py`](src/d810/mba/ac_matching.py)
- [`src/d810/backends/mba/runtime_semantics.py`](src/d810/backends/mba/runtime_semantics.py)
- [`src/d810/backends/mba/ida.py`](src/d810/backends/mba/ida.py)

### Bounded multi-rule Egglog composition

The certified catalogue is compiled into a bounded Egglog saturation model.
Degree 1 permits one certified rewrite step; degree 2 permits two sequential
steps. Degree 2 can cross a non-improving intermediate that a strict one-rule
optimizer cannot use. One proven example is:

```text
(~x) ^ (~y)
  -- BnotXor_FactorRule_1, equal cost -->
~((~x) ^ y)
  -- Bnot_FactorRule_5, cheaper -->
x ^ y
```

The result carries the ordered derivation trace. Saturation is bounded by:

- leaf and operator counts;
- degree and saturation rounds;
- e-classes and e-nodes;
- rule firings;
- per-candidate time;
- aggregate per-function time.

An equal-cost canonical reshaping is telemetry only. A native mutation requires
a strictly cheaper result and successful proof.

Relevant implementation:

- [`src/d810/backends/mba/egglog_saturation.py`](src/d810/backends/mba/egglog_saturation.py)
- [`src/d810/backends/mba/egglog_structural_rules.py`](src/d810/backends/mba/egglog_structural_rules.py)
- [`src/d810/optimizers/microcode/instructions/egraph/egglog_handler.py`](src/d810/optimizers/microcode/instructions/egraph/egglog_handler.py)

### Fixed shifts and rotates

The typed/native/proof model now supports exact literal `shl`, logical `lshr`,
`rol`, and `ror` terms. It rejects variable shift counts, arithmetic right
shifts, mixed-width or cast-contaminated expressions, and non-complementary
rotate trees.

Nested fixed shifts survive native POD matching because the operation key
includes the literal shift count. The `fixed_rotate` family cannot be combined
with cross-block preparation, avoiding an incompatible prepared-catalogue path.

Relevant implementation:

- [`src/d810/backends/mba/native_mba_term_view.py`](src/d810/backends/mba/native_mba_term_view.py)
- [`src/d810/backends/mba/native_rotate_helper.py`](src/d810/backends/mba/native_rotate_helper.py)
- [`src/d810/backends/mba/native_z3_proof_template.py`](src/d810/backends/mba/native_z3_proof_template.py)
- [`src/d810/backends/mba/native_pod_matcher.py`](src/d810/backends/mba/native_pod_matcher.py)

### Cross-block preparation

The interactive and deep profiles can prepare residual candidates using
bounded cross-block constant resolution. The deep profile additionally enables
bounded def-use preparation. This lets Egglog see small semantic islands whose
constants or definitions are separated by predecessor boundaries while keeping
the search path and predecessor count configurable and bounded.

### IDB-local learned replay

After a fresh Egglog derivation is rebuilt, proved, and accepted by the outer
mutation owner, the alpha-normalized composite template can be stored in the
IDB netnode:

```text
$ d810.egglog_composites.v1
```

The shipped profiles bound this cache to 256 entries and 2 MiB. Entries are
bound to the canonicalizer, catalogue, profile, proof contract, and Egglog
semantics. They never retain a live `cfunc_t`, `mop_t`, native leaf, or a
historical proof verdict.

A later equivalent candidate still binds live leaves, rebuilds the native
result, and proves it, but it can avoid another Egglog saturation run.

## Shipped profiles

### Interactive spike

[`src/d810/conf/mba_portfolio_spike.json`](src/d810/conf/mba_portfolio_spike.json)

- fast chain/direct providers before Egglog;
- ADD family;
- at most 2 leaves and 10 operators;
- degree 1 and 2 saturation rounds;
- 64 e-classes, 128 e-nodes, and 32 firings;
- cross-block constant preparation;
- learned replay enabled;
- 250 ms candidate admission budget;
- 1 second aggregate function admission budget.

This is the appropriate starting point for interactive use.

### Deep diagnostic profile

[`src/d810/conf/mba_portfolio_deep.json`](src/d810/conf/mba_portfolio_deep.json)

- all eight certified MBA families: `add`, `and`, `bnot`, `mul`, `neg`, `or`,
  `sub`, and `xor`;
- at most 4 leaves and 16 operators;
- degree 2 and 4 saturation rounds;
- 128 e-classes, 256 e-nodes, and 64 firings;
- cross-block constant and def-use preparation;
- learned replay enabled;
- 500 ms candidate admission budget;
- 5 second aggregate function admission budget.

This profile is intended for batch investigation and diagnostics, not as the
default everyday profile.

### 3 ms telemetry lane

[`src/d810/conf/mba_portfolio_telemetry_3ms.json`](src/d810/conf/mba_portfolio_telemetry_3ms.json)

The 3 ms configuration is an explicit no-engine measurement lane. It is useful
for measuring admission behavior, but it should not be used to expect Egglog
deobfuscation yield.

## Observing live behavior

### IDA log receipts

Every Egglog attempt emits an information-level extraction receipt:

```bash
rg "egglog MBA extraction receipt" ~/.idapro/logs/d810_logs/d810.log
```

A fresh successful extraction should have:

- `extracted_cost` strictly below `input_cost`;
- `degree=1` or `degree=2`;
- nonzero `rule_firings`;
- concrete `family` and `source` values;
- bounded `eclasses` and `enodes`;
- `skip=None`.

A fail-closed attempt records a stable `skip` reason and any lowering/profile
blockers rather than silently disappearing.

### Accepted central statistics

Only mutations accepted by the outer owner are recorded as applied in central
statistics. In the IDA Python console:

```python
from d810.manager.state import D810State

rows = [
    row
    for row in D810State().stats.to_dict()["rule_execution_log"]
    if row["rule_name"].lower() == "egglogoptimizer"
]

latest = rows[-1]["metadata"] if rows else None
```

Important metadata fields include:

- `input_cost`, `canonical_input_cost`, and `extracted_cost`;
- `normalization_steps`;
- `execution_path`;
- `degree` and `derivation_trace`;
- `eclass_count`, `enode_count`, and `rule_firings`;
- selected family, source rule, and aliases;
- native matcher comparisons, lazy swaps, and backend;
- proof mode, verdict, and timing;
- cache status and replay timing;
- `egglog_run_count` and `replay_saved_egglog_runs`;
- portable `mba_provider_outcome`.

Set `collect_stage_timings` to `true` in the `mba-egraph` options to add a
per-stage timing breakdown.

### Recognizing learned replay

A replayed result should report values equivalent to:

```text
execution_path = learned_replay
cache_status = hit
egglog_run_count = 0
replay_saved_egglog_runs > 0
```

The rebuilt result is still checked against the live candidate and proof gate.

### Offline corpus reporting

The IDA-free differential reporter consumes native provider capture rows and an
optional rollout-evidence sidecar:

```bash
python tools/scripts/mba_differential_report.py \
  --manifest tests/fixtures/mba_portfolio/compiler_shapes.json \
  --rollout-evidence rollout-evidence.json \
  --out report.json \
  --markdown report.md \
  capture.json
```

The report distinguishes measured zeroes from unmeasured lanes and aggregates:

- provider wins and unique/shared wins;
- degree-1 versus degree-2 Egglog wins;
- stable refusal reasons;
- proof, reconstruction, budget, and unavailable outcomes;
- candidate and whole-function latency;
- matcher bucket, attempted-rule, cap, and reassociation metrics;
- lifecycle/compiler/proof/cache measurements;
- fresh-saturation versus learned-replay work;
- 3 ms telemetry versus interactive execution;
- root-only misses containing strict useful sub-islands.

Whole-function latency is sourced once from the native capture; the telemetry
sidecar does not duplicate those samples.

### Structural parity certificates

Persisted parity evidence can be converted into a runtime-bound certificate:

```bash
python tools/scripts/mba_structural_matcher_certificate.py \
  --ledger parity.json \
  --capture capture.json \
  --runtime cython \
  --output certificate.json
```

Certificate generation fails unless legacy rule parity, native binding parity,
unknown bindings, and pending safe-coverage counters satisfy the rollout
contract. A stale catalogue, corpus, toolchain, runtime, or matcher/emitter
digest fails closed and leaves structural matching disabled.

## What benefit has actually been demonstrated

The implementation has established the following capabilities:

- a targeted degree-2 derivation can cross an equal-cost intermediate and
  produce a strictly cheaper native expression;
- certified fixed rotate trees can be extracted as native rotates;
- Python and Cython native lowering/matching paths preserve the same semantics;
- a previously accepted composite can be replayed without a second Egglog run;
- a real complement-mask probe produced an Egglog reduction, while forward
  constant propagation exposed the context in which the larger expression
  collapsed to zero;
- unsafe, unsupported, over-budget, or unproved results remain no-ops.

The final compiler-shaped native rollout corpus did not contain an eligible
fresh Egglog win. Its Egglog degree lanes were therefore correctly reported as
unmeasured rather than as measured zero wins.

That distinction matters. The merge demonstrates a bounded, observable, and
proof-gated capability, but it does not yet establish broad real-world yield on
the compiler-shaped corpus. The next useful evaluation target is a residual
corpus drawn from real supported-obfuscator and production-binary residuals,
with native capture enabled.

## Acceptance evidence

Retained acceptance evidence for the integrated implementation includes:

- full Cython system suite: `4435 passed, 43 skipped, 11 deselected, 1 xfailed`;
- focused Python and Cython native-capture coverage;
- certificate activation and stale-certificate fail-closed coverage;
- Ruff diff gate, ast-grep, import-linter, and diff checks;
- final report-only correction ensuring native whole-function latency samples
  are not double-counted.

The final merge-tip change affected report/native-capture measurement tests,
not the production optimizer runtime.
