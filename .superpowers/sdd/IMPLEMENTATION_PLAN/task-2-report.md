# Task 2 implementation report

## Scope

Implemented the closed immutable semantic-authority model for Blueprint
Sections 2.1-2.4 and 15.1-15.2. The implementation is limited to the model
package, its focused unit tests, and test helpers. It does not add hashing,
graph traversal, obligation indexes, Section 2.5 records, evaluator logic,
codec logic, results, or transaction integration.

## RED evidence

Before the production package existed:

```text
PYTHONPATH=src pytest tests/unit/transforms/unflatten_authority/test_model.py::test_authority_model_package_exists_and_is_closed -vv
...
FAILED ... ModuleNotFoundError: No module named 'd810.transforms.unflatten_authority'
```

After adding the Task 2 matrix and validation tests, the focused model node
remained RED for the same missing package (`10 failed`); the failures were
the expected absent-model import failures, not fixture or collection errors.

The review correction added focused counterexamples before the implementation
changes. The correction RED run showed three targeted failures: canonical
route-proof mismatches were rejected by Task 2 even though replay belongs to
later owners, route locator atomic-group disagreement was accepted, and a
PARTIAL retirement claim could retire a catalog block outside the dispatcher
inventory. Earlier RED coverage also caught retirement/route cross-field
mismatches, source/catalog duplicate EA and handler-row duplicates, malformed
host SHA-1, subclass-smuggled refs, wrong anchors, and foreign native keys.

## GREEN evidence

```text
PYTHONPATH=src pytest tests/unit/transforms/unflatten_authority/test_model.py -vv
21 passed in 0.10s

PYTHONPATH=src pytest tests/unit/transforms/unflatten_authority -q
21 passed in 0.10s
```

The focused tests cover all closed evidence kind/payload pairs, the complete
15.1 subject construction matrix, every 15.1 claim-field row, tuple
normalization and paired locator ordering, phase binding status invariants,
source catalog uniqueness (including native-EA reuse), closed plan shape and
handler inputs, the mandatory `ProposedUnflattenContract.plan_inputs` field,
a valid complete proposal, proposal native-key/generation/state/catalog
coherence, exact-type closure and subclass-smuggling rejection, local-alias
union rejection, host SHA-1 validation, reversed-input equality, exact
catalog ref/anchor ownership, native-key ownership for native witnesses, and
route-claim atomic-group coherence. Canonical route evidence is only
exact-typed and aligned to the source catalog's key/generation here; this
model does not replay proof IDs, route anchors, or proof destinations.

The valid proposal fixture uses distinct canonical source/target stable
identities (`0x1000 -> 0x1100`) and uses a third catalog block (`b2@0x1100`)
for the authoritative handler. Full dispatcher retirement covers only
`b0`/`b1`; handler refs remain locally disjoint from retired infrastructure,
while handler state/route coverage is deferred to later owners. Plan-shape
validation requires retirement refs to be a subset of the complete dispatcher
inventory, PARTIAL to retain at least one dispatcher member, and FULL to
retire the complete inventory.

The proposal constructor performs only local catalog membership and exact
ref/anchor checks for claim subjects and plan inputs. It does not compare
exact-effect instruction EAs to native origins; that authoritative matching is
deferred to T9.

Additional static checks:

```text
ruff check src/d810/transforms/unflatten_authority \
  tests/unit/transforms/unflatten_authority
All checks passed!

sg scan --config sgconfig.yml --report-style short
... Contracts: 14 kept, 0 broken.

PYTHONPATH=src lint-imports --config .importlinter
... Contracts: 14 kept, 0 broken.
```

## Files

- `src/d810/transforms/unflatten_authority/__init__.py`: package boundary and
  model re-exports.
- `src/d810/transforms/unflatten_authority/model.py`: all Task 2 enums,
  locators, phase bindings, closed evidence payloads, claims, use-def/source
  witnesses, plan inputs, and closed unions.
- `tests/unit/transforms/unflatten_authority/test_model.py`: focused RED/GREEN
  matrix and validation coverage.
- `tests/unit/transforms/unflatten_authority/helpers.py`: deterministic valid
  ID and portable fixture helpers.

## Commit

Commit message required by the task: `feat(unflatten): add closed semantic authority model`.
The original implementation commit is amended in this correction pass; the
new HEAD hash is reported by the implementation handoff after amendment.

## Concerns and boundaries

- Supplied IDs are checked structurally as `sha256:<64 lowercase hex>` only;
  they are not recomputed in Task 2.
- Unordered tuples use durable structural keys; semantic paths retain order,
  and parallel ref/EA tuples are sorted jointly to preserve associations.
- FULL plan shape treats `dispatcher_member_refs` as the complete inventory;
  retired refs must equal that inventory, local handler/retirement disjointness
  is checked, and normalized-state/route coverage is deferred to T6/later
  owners.
- `CanonicalSemanticEvidence` is referenced as the existing typed route
  evidence input; no route evidence is built or traversed here.
- No Docker, producer-owner, transaction-owner, full unit, or system suite was
  run, per task scope.
