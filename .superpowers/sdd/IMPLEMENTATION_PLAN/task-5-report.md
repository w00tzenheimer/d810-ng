# Task 5 implementation report

## Scope

Implemented the typed `PatchPlan` unflatten channel, temporary non-authoritative
legacy shadow records, and total transaction route selection.

- Ordinary plans return `UnflattenAuthorityNotApplicable(ORDINARY)`.
- Closed typed proposals route as `TYPED_PROPOSAL`.
- Typed plans with top-level reserved legacy metadata reject with
  `DUAL_AUTHORITY_CHANNEL`.
- Legacy-only metadata rejects as requiring explicit codec adaptation; it never
  silently becomes ordinary authority.
- The exact shadow envelope is accepted only when its plan, snapshot, and
  generation correlate; mapping lookalikes and malformed transport reject.
- Reserved-key validation is assembled from the current producer owners.
- Metadata is snapshotted once at construction as raw immutable pairs, retaining
  duplicate/order information for reserved detection while preserving dict
  collapse semantics for lookup.
- Hostile metadata iteration, hashing, and equality failures fail closed as a
  typed malformed route; ordinary plans still avoid importing the authority
  model.
- Construction snapshots one-shot generators exactly once; reserved detection
  runs over raw entries before duplicate collapse and recognizes all canonical
  reserved keys only from exact built-in strings; arbitrary objects and `str`
  subclasses are rejected before any custom hash/equality can run.

## TDD evidence

The required RED node initially failed because `PatchPlan` had neither
`unflatten_proposal` nor `legacy_unflatten_shadow` in its constructor.

After the implementation, the same node passed and the focused route/record
tests passed.

The R4 RED tests initially observed `DUAL_AUTHORITY_CHANNEL` for both an
arbitrary equality alias and a custom `str` subclass.  After the correction,
both return `RejectedPlanRoute(MALFORMED_PROPOSAL, "metadata_key_type_invalid")`
without probing the key's hash or equality.

Sol/high reviewer approval was received for the combined Task 5 patch before
commit.

## Verification

```text
PYTHONPATH=src pytest tests/unit/transforms/unflatten_authority/test_proposal.py tests/unit/transforms/unflatten_authority/test_transaction_api.py tests/unit/transforms/test_cfg_transaction.py -vv
42 passed

PYTHONPATH=src pytest tests/unit/transforms/unflatten_authority/test_model.py tests/unit/transforms/unflatten_authority/test_proposal.py tests/unit/transforms/unflatten_authority/test_transaction_api.py -q
40 passed

PYTHONPATH=src pytest tests/unit/transforms/unflatten_authority -q
117 passed

ruff check <all Task 5 changed source and test files>
All checks passed!

sg scan --config sgconfig.yml --report-style short
clean (no findings)

PYTHONPATH=src lint-imports --config .importlinter
Contracts: 14 kept, 0 broken.

git diff --check
clean (no findings)

python3 tools/scripts/portable_shape_lint_gate.py
passes. The earlier failed invocation was `python tools/scripts/portable_shape_lint_gate.py`
under Python 2.7, producing:
`File "tools/scripts/portable_shape_lint_gate.py", line 69` at
`raise RuntimeError(f"cannot load detector at {_CODEMOD_PATH}")`.
The shape-gate file was not modified.
```

Docker, full unit suites, producer/transaction owner groups, Hodur, and A/B/C
were intentionally not run per the focused Task 5 execution correction.
