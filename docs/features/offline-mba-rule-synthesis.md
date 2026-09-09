# Offline MBA rule synthesis

D810 can distill unresolved MBA expressions captured during decompilation into
proof-certified rewrite proposals. The workflow is:

**Capture residuals -> mine offline -> certify -> materialize -> review and admit.**

This feature is present in `cfg-recon-mainline`. Mining generates rewrite rules;
it does not automatically change the semantic canonicalizer or install rules in
the running plugin.

## Prerequisites

- Use a Python environment with D810's mining and proof dependencies installed,
  including Z3. The offline miner does not require IDA.
- Run the commands below from the D810 repository root, using `PYTHONPATH=src`
  so the selected checkout supplies the implementation.
- Obtain the discovery database from the decompilation run you want to mine.
  Use its actual log directory; different runs can have different databases.

The existing [discovery persistence reference](mba-residual-discovery.md)
documents the database's schema, causal events, and lifecycle validation.

## 1. Capture unresolved provider observations

In the plugin settings, enable **Record MBA provider residual observations**.
Recording is enabled by default; `D810_MBA_RESIDUAL_RECORDING=0` disables the
database writes. Keep the relevant MBA provider enabled in the selected project
and decompile the functions of interest.

The manager writes observations to:

```text
<D810 log directory>/d810_mba_discovery.sqlite3
```

The observation path records terms, source anchors, provider outcomes, costs,
and refusal information. It does not perform synthesis, SMT proofs, or source
generation in the capture callback. Recorded observations are evidence for
discovery; not every observation is eligible for mining.

For a separate offline copy of a live database, use SQLite's backup mechanism
rather than copying only the `.sqlite3` file while WAL writes are active.
Mining updates lifecycle state in whichever database you select.

## 2. Inspect and mine the database

Replace the database path before running:

```bash
export PYTHONPATH=src
DB="/actual/log/directory/d810_mba_discovery.sqlite3"
test -f "$DB" || { echo "Discovery database does not exist" >&2; exit 1; }

python tools/scripts/mba_residual_rule_miner.py status --db "$DB"
python tools/scripts/mba_residual_rule_miner.py mine --db "$DB" --limit 10
python tools/scripts/mba_residual_rule_miner.py status --db "$DB"
```

`status` reports group, run, and proposal counts plus outstanding and expired
leases. `mine --limit 10` processes at most ten claims; it does not promise ten
new rules. Omitting `--limit` processes eligible claims until none remain or an
error/refusal stops the invocation.

The miner groups observations by canonical term while retaining raw expression
evidence. It selects evidence deterministically, abstracts repeated subterms,
and searches for a cheaper replacement. Concrete witness signatures nominate
candidates. They do not prove equivalence: publication requires certification
of the source/replacement identity at **8, 16, 32, and 64 bits**.

The default search budget is:

| Option | Default |
|-|-|
| `--max-atoms` | 4 |
| `--max-variables` | 3 |
| `--max-candidate-operator-nodes` | 4 |
| `--max-generated-terms` | 50000 |
| `--max-candidate-attempts` | 100000 |
| `--witness-count` | 96 |

Use `mine --help` to inspect supported flags. A bounded search can legitimately
produce no proposal. An exhausted budget is not proof that no identity exists.
The JSON result distinguishes `published`, `no_proposal`, `refused`, and
`errors`; refusals or errors return exit status 2.

## 3. Select and materialize a proposal

The CLI currently reports aggregate status rather than listing proposal IDs.
Use a read-only query to list them:

```bash
sqlite3 -readonly "$DB" \
  'SELECT proposal_id, state FROM proposals ORDER BY created_at DESC;'

python tools/scripts/mba_residual_rule_miner.py materialize \
  --db "$DB" \
  --proposal "<proposal_id>" \
  --output-dir "/path/to/new-review-directory"
```

Use a dedicated output directory for the selected proposal. Materialization
atomically writes these two artifacts and records their receipt in the database:

```text
<proposal-fingerprint>.rule.py
<proposal-fingerprint>.fixture.json
```

The Python file defines a generated `VerifiableRule`. The fixture records the
original and atomized expressions, replacement, atomization bindings, proof
widths, and source fingerprint. The command prints the materialized path and
digest. Materialization is not catalogue admission or runtime activation.

## 4. Review, validate, and admit the rule

1. Review the generated pattern, replacement, constants, width assumptions,
   atom bindings, and proof evidence against the captured expression.
2. Add the reviewed rule to the appropriate family under `src/d810/mba/rules/`
   and register it in `src/d810/mba/rules/catalogue.py`.
3. Add regression coverage from the generated fixture, including relevant
   width and negative-match cases. Validate through the existing certification
   and matcher paths, then test actual native emission on a copied input.
4. Enable the rule through the intended project's pipeline/rule selection.
5. Record admission only after that work is accepted. The store exposes
   `mark_admitted(proposal_id, rule_id, ...)` and `mark_rejected(...)`; the CLI
   currently has no admission or rejection subcommand. These store operations
   record lifecycle state; they do not edit the catalogue or load rules.

Local validation commands, from the checkout being changed:

```bash
PYTHONPATH=src pytest -q tests/unit/mba
sg scan --config sgconfig.yml --report-style short
PYTHONPATH=src lint-imports --config .importlinter
```

Check marker selection when running certification tests: the default test
configuration can exclude slow tests. Invoke the relevant proof tests explicitly
with their required marker selection before claiming certification acceptance.

Run IDA-dependent tests through `tools/scripts/run_system_tests_docker.sh` from
the main repository root, using `-w <worktree>` for an isolated checkout and
passing the exact regression node to the runner's `test` command.

## Existing admitted example

[`MbaResidualRule_2aa7de9f2ef4`](../../src/d810/mba/rules/or_.py) is an already
admitted, generalized repeated-term OR identity:

```text
((y ^ x) - ((y & x) + 2 * (x & ~y))) + 2 * x  ->  x | y
```

The repeated subtree can bind as one matcher variable. Its registration is in
[`catalogue.py`](../../src/d810/mba/rules/catalogue.py). Use this as an example
of the final integration shape, not as a substitute for a new rule's proof.

## Implementation and history

| Component | Source |
|-|-|
| Offline CLI | [mba_residual_rule_miner.py](../../tools/scripts/mba_residual_rule_miner.py) |
| Claims, mining, materialization | [discovery_miner.py](../../src/d810/mba/discovery_miner.py) |
| Bounded search and certification | [bounded_synthesis.py](../../src/d810/mba/bounded_synthesis.py) |
| Proposal and rule rendering | [rule_proposal.py](../../src/d810/mba/rule_proposal.py) |
| SQLite lifecycle | [discovery_store.py](../../src/d810/mba/discovery_store.py) |
| Typed-term normalization | [semantic_canonicalization.py](../../src/d810/mba/semantic_canonicalization.py) |

The semantic canonicalizer normalizes typed terms for grouping and search. The
offline synthesizer discovers candidate identities. Runtime providers perform
their own solve/rewrite work. These are distinct responsibilities.

Verified ancestors of `cfg-recon-mainline`:

| Commit | Change |
|-|-|
| `a980acbbe` | Synthesize and certify residual identities |
| `df2cc8761` | Mine residual rules from SQLite |
| `5177dfd54` | Persist plugin residual discovery |
| `78a3d8a99` | Admit the repeated-term OR identity |

Older instructions showing `--input residual-corpus.json --output-dir ...`
describe the retired CLI. The current interface is `status`, `mine`, and
`materialize`, each taking `--db`.
