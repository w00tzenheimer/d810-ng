# Task 3 Implementation Report

## Scope and result

Worktree: `/Users/mahmoud/src/idapro/d810/.worktrees/domain-lifted-semantic-simplification`

Task 3 adds portable, width-specific canonical templates for already-admitted
`CompiledEgglogRule` objects. The native POD catalogue remains intact and
declaration ordered. Canonical compilation uses the Task 1
`canonicalize_mba_term()` implementation, preserves `Var` versus constrained
`Const` terminal semantics, and leaves unsupported operations on the legacy
path. Candidate matching consumes immutable precompiled templates and does not
compile proofs or build a second inventory at callback time. Certified snapshot
fingerprints now include canonicalizer version, canonical pattern/replacement
payloads, and all existing rule semantic inputs; parity certificates use schema
3 and reject older schemas.

## RED evidence

Initial required RED command, after adding the canonical-template tests and
before production implementation:

```text
PYTHONPATH=src pyenv exec python -m pytest -q tests/unit/mba/test_canonical_pattern.py tests/unit/mba/test_compiled_pattern_catalogue.py tests/unit/mba/test_certified_catalogue.py
17 failed, 16 passed in 36.44s
```

The failures were expected missing-module/catalogue API failures. The explicit
certificate/tool RED probe then failed against the old certificate/snapshot
schema as expected:

```text
PYTHONPATH=src pyenv exec python -m pytest -q tests/unit/mba/test_certified_catalogue.py tests/unit/mba/test_structural_matcher_certificate_tool.py
4 failed, 10 passed in 39.34s
```

A later RED regression exposed constraint-derived bindings without native
paths:

```text
PYTHONPATH=src pyenv exec python -m pytest -q tests/unit/mba/test_compiled_pattern_catalogue.py::test_canonical_catalogue_keeps_constraint_derived_bindings_without_paths
1 failed
ValueError: terms and candidate_paths must have the same names
```

The invariant was corrected to require only `candidate_paths` be a subset of
portable terms, preserving derived constraint bindings without inventing a
native path.

## GREEN evidence

The narrow canonical module gate requested by the controller:

```text
PYTHONPATH=src pyenv exec python -m pytest -q -x tests/unit/mba/test_canonical_pattern.py
19 passed in 49.05s
```

Post-fix focused Task 3 suite:

```text
PYTHONPATH=src pyenv exec python -m pytest -q tests/unit/mba/test_canonical_pattern.py tests/unit/mba/test_compiled_pattern_catalogue.py tests/unit/mba/test_certified_catalogue.py tests/unit/mba/test_structural_matcher_certificate_tool.py
42 passed in 39.87s
```

The admitted-rule projection test proves canonical projection does not invoke
proof verification again:

```text
PYTHONPATH=src pyenv exec python -m pytest -q tests/unit/mba/test_egglog_mba_catalogue.py -k canonical_template_projection_consumes_existing_admitted_rules_only
1 passed, 18 deselected in 1.34s
```

The exact five-file command required by the brief completed with all 59 Task 3
tests passing and two unrelated pre-existing catalogue-manifest failures:

```text
PYTHONPATH=src pyenv exec python -m pytest -q tests/unit/mba/test_canonical_pattern.py tests/unit/mba/test_compiled_pattern_catalogue.py tests/unit/mba/test_certified_catalogue.py tests/unit/mba/test_structural_matcher_certificate_tool.py tests/unit/mba/test_egglog_mba_catalogue.py
59 passed, 2 failed in 285.48s (0:04:45)
```

The unrelated failures are:

- `test_family_manifest_covers_every_module_owned_rule_in_source_order`: the
  existing manifest differs from discovered order at Eidolon/Xor and omits
  two discovered Xor rules.
- `test_whole_corpus_has_one_family_qualified_receipt_per_declaration`: the
  existing assertion expects 189 receipts while the current catalogue has 191.

No Task 3 implementation or canonical test failed in this command.

## Static and repository gates

- Ruff over all ten changed Python source/test files: `All checks passed!`
- `git diff --check`: exit 0, no diagnostics.
- `sg scan --config sgconfig.yml --report-style short`: `14 kept, 0 broken`.
- `PYTHONPATH=src lint-imports --config .importlinter`: `14 kept, 0 broken`.
- `graphify update .` was attempted after edits; rebuild failed with
  `[Errno 1] Operation not permitted`. It produced no tracked or untracked
  graph artifacts.
- No Docker/IDA run was necessary; Task 3's specified gate is portable unit
  coverage.

## Files modified

- `src/d810/mba/canonical_pattern.py`: portable lowering, canonical template
  records, semantic fingerprints, bounded canonical matching, fixed bindings,
  and JSON-safe template payloads.
- `src/d810/backends/mba/compiled_pattern_catalogue.py`: immutable canonical
  width records and canonical root buckets alongside the unchanged POD path.
- `src/d810/backends/mba/egglog_add_rule_compiler.py`: admitted-rule identity
  freeze helper and no-proof-recompilation boundary documentation.
- `src/d810/mba/certified_catalogue.py`: canonical snapshot payload/versioning,
  stronger semantic identity coverage, and parity schema 3.
- `tools/scripts/mba_structural_matcher_certificate.py`: canonicalizer-version
  evidence validation and schema-3 output.
- `tests/unit/mba/test_canonical_pattern.py`: symmetry, terminal, masking,
  unsupported-op, declaration-order, and semantic-fingerprint contracts.
- `tests/unit/mba/test_compiled_pattern_catalogue.py`: canonical catalogue,
  budget, and constraint-derived binding coverage.
- `tests/unit/mba/test_certified_catalogue.py`: snapshot/template and stale
  certificate contracts.
- `tests/unit/mba/test_structural_matcher_certificate_tool.py`: schema/version
  output contract.
- `tests/unit/mba/test_egglog_mba_catalogue.py`: admitted-object projection
  guard.

## Concerns

The required five-file command is not numerically all-green because of the two
unrelated current catalogue-manifest assertions described above. Graphify is
blocked by the local operation-permission failure. No Task 3-scoped concern
remains.
