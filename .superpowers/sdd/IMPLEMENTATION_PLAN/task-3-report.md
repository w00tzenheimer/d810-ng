# Task 3 implementation report

## Scope

Implemented the closed canonical wire codec, exact subject/claim/evidence
content IDs and module-private factories, explicit model/external adapters,
and semantic FlowGraph fingerprint projection. Model constructors now reject
forged well-formed IDs while factories compute IDs before construction. The
inverse is fail-closed: it restores exact registered enum/record types,
validates tag/field/key shape, and rejects any non-byte-identical re-encoding.
The graph projection validates block-key/serial identity, reciprocal topology,
typed operand correspondence manifests, and preserves the exact
Graph/Block/Insn/Mop field orders while excluding transitional
`operands`/`operand_slots`. The five pinned internal records have explicit
runtime validators for exact field types, nested shapes, digest strings, and
graph topology before direct encoding and inverse reconstruction.

## RED evidence

The required first RED node was run before `ids.py` existed:

```text
PYTHONPATH=src pytest tests/unit/transforms/unflatten_authority/test_ids.py::test_canonical_digest_fixture_is_pinned -vv
...
ModuleNotFoundError: No module named 'd810.transforms.unflatten_authority.ids'
```

After the module was introduced, the pinned vector intentionally remained RED
until object-tag wire format, encoded enum values, declaration-order record
fields, encoded/sorted mapping keys, and the exact content-ID preimage were
aligned. The revision review also recorded RED for forged model IDs and the
original fail-open inverse/graph probes; those probes are now committed as
regressions. The final vector is pinned to:

```text
sha256:07fd10c22a620eaab0a3639ae738586023c380b1027b2b84684be9fd4a5a9165
```

The re-review supplied the P1 RED evidence for partial typed-operand
correspondence collisions and malformed pinned-record runtime values. Those
probes are now committed as focused regressions; this report does not claim a
separate pre-implementation run for the reviewer-supplied probes.

The final review also supplied a RED probe showing `canonical_bytes()` raised
an uncontrolled `RecursionError` for root self-referential mappings/lists.
Public canonicalization now prevalidates once with the existing recursive
validator, including cycle guards for mappings and generic registered records;
the focused probe expects controlled `ValueError` instead.

## GREEN evidence

```text
PYTHONPATH=src pytest tests/unit/transforms/unflatten_authority/test_ids.py -vv
24 passed in 0.09s

PYTHONPATH=src pytest tests/unit/transforms/unflatten_authority/test_model.py tests/unit/transforms/unflatten_authority/test_ids.py -q
45 passed in 0.12s
```

The focused ID tests cover the pinned canonical bytes/digest vector, sequence
tag and inverse-type preservation, representative model/external round trips,
unknown/malformed/noncanonical inverse input, exact subject and
claim/evidence recomputation, forged-ID rejection for every current claim
class and AuthorityEvidence, omitted optionals, unknown values, float
rejection, mapping order/object-identity independence, exact graph field
sequences, malformed graph/operand-manifest rejection, malformed runtime
types for every pinned internal record, recursive-cycle rejection, and semantic fingerprint changes for
opcode/raw opcode, instruction/effect kind, predicate and branch predicate,
width, register/value operands, native origin, display text, reciprocal
topology, and entry. Complete transitional manifests are validated while
their object values remain excluded from successful fingerprints.

## Architecture gates

```text
ruff check src/d810/transforms/unflatten_authority/ids.py \
  src/d810/transforms/unflatten_authority/model.py \
  tests/unit/transforms/unflatten_authority/test_ids.py \
  tests/unit/transforms/unflatten_authority/test_model.py
All checks passed!

sg scan --config sgconfig.yml --report-style short
Contracts: 14 kept, 0 broken.

PYTHONPATH=src lint-imports --config .importlinter
Contracts: 14 kept, 0 broken.
```

## Scope boundary / concerns

- No Docker, producer-owner, transaction-owner, full unit, or system suite was
  run, per the focused Task 3 contract. The 45 passing tests are focused only.
- Graph fingerprinting accepts only the registered portable `FlowGraph`,
  `BlockSnapshot`, `InsnSnapshot`, and `MopSnapshot` types; live SDK objects
  are not accepted.
- No safety decision, obligation graph traversal, evaluator, persistence cache,
  persistence codec layer, or transaction integration was added; the only
  traversal is the deterministic FlowGraph projection validation described
  above.

## Commit

Amended required commit:

```text
feat(unflatten): pin authority content IDs
```

Amended commit status: complete; the final amended hash is reported in the
handoff after this commit.
