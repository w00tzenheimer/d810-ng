"""The coalescing tally must never outlive the apply cycle that produced it.

Conflict resolution legitimately collapses several queued modifications that
describe the same edge into one, so ``observe_patch_realization`` can only
reconcile ``applied + superseded == planned``. That makes a *stale* superseded
count dangerous in a way a missing one is not: it can silently balance an
inventory belonging to a later transaction and mask real corruption.

The contract is therefore one-shot reads plus a reset at the start of every
apply cycle, so an unexpected reader sees 0 and the reconciliation fails loudly.

System-runtime tier because ``deferred_modifier`` imports ``ida_hexrays``. The
tests bypass ``__init__`` deliberately: the tally's scoping is independent of
any live MBA, and constructing one would test Hex-Rays rather than this rule.
"""

from __future__ import annotations

from d810.hexrays.mutation.deferred_modifier import DeferredGraphModifier


def _bare_modifier() -> DeferredGraphModifier:
    """A modifier with no live MBA - only the tally contract is under test."""
    return object.__new__(DeferredGraphModifier)


def test_a_modifier_that_never_applied_reports_no_supersessions() -> None:
    assert _bare_modifier().take_superseded_count() == 0


def test_reading_the_tally_consumes_it() -> None:
    modifier = _bare_modifier()
    modifier._superseded_count = 3

    assert modifier.take_superseded_count() == 3
    assert modifier.take_superseded_count() == 0, "a second read must not re-balance"


def test_apply_zeroes_a_tally_left_by_an_earlier_transaction() -> None:
    """The reuse case: same modifier, new transaction, nothing coalesced."""
    modifier = _bare_modifier()
    modifier._superseded_count = 7
    observed = []

    def fake_apply(**kwargs):
        # Whatever the cycle coalesces, it starts from a clean tally.
        observed.append(modifier._superseded_count)
        return 0

    modifier._apply = fake_apply
    modifier.apply()

    assert observed == [0], "apply must reset the tally before doing any work"
    assert modifier.take_superseded_count() == 0


def test_a_raising_apply_still_leaves_no_stale_tally() -> None:
    modifier = _bare_modifier()
    modifier._superseded_count = 5

    def exploding_apply(**kwargs):
        raise RuntimeError("boom")

    def noop_abort(reason: str) -> None:
        return None

    modifier._apply = exploding_apply
    modifier._abort_open_mutation_batch = noop_abort

    try:
        modifier.apply()
    except RuntimeError:
        pass

    assert modifier.take_superseded_count() == 0, (
        "a failed cycle must not leave a count that reconciles the next one"
    )


def test_the_reconciliation_identity_is_what_callers_check() -> None:
    """Document the invariant the tally exists to serve.

    79 planned steps, two of which described the same edge to block 184: the
    coalescer removed one, the modifier applied 78, and 78 + 1 == 79.
    """
    modifier = _bare_modifier()
    modifier._superseded_count = 1
    planned, applied = 79, 78

    assert applied + modifier.take_superseded_count() == planned
