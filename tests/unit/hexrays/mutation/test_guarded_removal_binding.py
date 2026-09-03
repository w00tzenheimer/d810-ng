"""Guarded instruction removals bind to block identity, never to a serial.

A serial is only meaningful for the MBA generation that produced it.  A stage
that creates blocks (a redirect that clones a fall-through, for example)
shifts every later serial, so a removal planned against serial 10 can address
a different block by the time the deferred batch applies.  The removal's own
fingerprint is a stable identity and must be what the binding resolves
through.

These tests exercise the pure binding logic; no IDA state is involved.
"""

from __future__ import annotations

from d810.hexrays.mutation.guarded_removal_binding import (
    GuardedRemovalBindingOutcome,
    GuardedRemovalCandidateBlock,
    GuardedRemovalCandidateInstruction,
    GuardedRemovalFingerprint,
    GuardedRemovalPlanDisposition,
    bind_guarded_removal,
    decide_guarded_removal_preflight,
    decide_post_write_guard_rejection,
)


def _insn(
    ea: int,
    opcode: int = 0x11,
    *,
    kind: str | None = "stack",
    ident: int | None = 0x3C,
    size: int | None = 4,
) -> GuardedRemovalCandidateInstruction:
    return GuardedRemovalCandidateInstruction(
        ea=ea,
        opcode=opcode,
        destination_kind=kind,
        destination_id=ident,
        destination_size=size,
    )


def _block(serial: int, start_ea: int, *insns) -> GuardedRemovalCandidateBlock:
    return GuardedRemovalCandidateBlock(
        serial=serial,
        start_ea=start_ea,
        instructions=tuple(insns),
    )


FINGERPRINT = GuardedRemovalFingerprint(
    block_start_ea=0x7FFB0E398A42,
    insn_ea=0x7FFB0E399724,
    ordinal=1,
    opcode=0x11,
    destination_kind="stack",
    destination_id=0x3C,
    destination_size=4,
)


def _victim_block(serial: int) -> GuardedRemovalCandidateBlock:
    return _block(
        serial,
        0x7FFB0E398A42,
        _insn(0x7FFB0E399700),
        _insn(0x7FFB0E399724),
    )


def test_unshifted_plan_keeps_its_planned_serial() -> None:
    binding = bind_guarded_removal(
        FINGERPRINT,
        planned_serial=10,
        blocks=(_victim_block(10),),
    )

    assert binding.outcome is GuardedRemovalBindingOutcome.ALREADY_BOUND
    assert binding.serial == 10
    assert binding.bound is True


def test_clone_shifted_serial_rebinds_to_the_live_block() -> None:
    """The exact d81-d9m5 shape: a clone took serial 10, the victim is now 12."""
    clone = _block(10, 0x7FFB0E398A2C, _insn(0x7FFB0E398A2C, 0x0F))
    binding = bind_guarded_removal(
        FINGERPRINT,
        planned_serial=10,
        blocks=(clone, _victim_block(12)),
    )

    assert binding.outcome is GuardedRemovalBindingOutcome.REBOUND
    assert binding.serial == 12
    assert binding.bound is True
    assert "10" in binding.reason and "12" in binding.reason


def test_start_ea_alone_is_not_identity() -> None:
    """A clone sharing the start EA must not satisfy the fingerprint."""
    twin = _block(
        11,
        0x7FFB0E398A42,
        _insn(0x7FFB0E399700),
        _insn(0x7FFB0E399999),
    )
    binding = bind_guarded_removal(
        FINGERPRINT,
        planned_serial=10,
        blocks=(twin, _victim_block(12)),
    )

    assert binding.outcome is GuardedRemovalBindingOutcome.REBOUND
    assert binding.serial == 12


def test_vanished_identity_is_dropped_not_bound() -> None:
    binding = bind_guarded_removal(
        FINGERPRINT,
        planned_serial=10,
        blocks=(_block(10, 0x7FFB0E398A2C, _insn(0x7FFB0E398A2C, 0x0F)),),
    )

    assert binding.outcome is GuardedRemovalBindingOutcome.IDENTITY_GONE
    assert binding.serial is None
    assert binding.bound is False
    assert binding.reason


def test_ambiguous_identity_is_dropped_rather_than_guessed() -> None:
    binding = bind_guarded_removal(
        FINGERPRINT,
        planned_serial=10,
        blocks=(_victim_block(12), _victim_block(13)),
    )

    assert binding.outcome is GuardedRemovalBindingOutcome.AMBIGUOUS_IDENTITY
    assert binding.serial is None
    assert binding.bound is False


def test_destination_mismatch_is_not_the_same_instruction() -> None:
    moved = _block(
        12,
        0x7FFB0E398A42,
        _insn(0x7FFB0E399700),
        _insn(0x7FFB0E399724, ident=0x40),
    )
    binding = bind_guarded_removal(
        FINGERPRINT,
        planned_serial=10,
        blocks=(moved,),
    )

    assert binding.outcome is GuardedRemovalBindingOutcome.IDENTITY_GONE


def test_ordinal_beyond_block_body_is_not_a_match() -> None:
    truncated = _block(12, 0x7FFB0E398A42, _insn(0x7FFB0E399700))
    binding = bind_guarded_removal(
        FINGERPRINT,
        planned_serial=10,
        blocks=(truncated,),
    )

    assert binding.outcome is GuardedRemovalBindingOutcome.IDENTITY_GONE


def test_missing_planned_block_still_rebinds_by_identity() -> None:
    binding = bind_guarded_removal(
        FINGERPRINT,
        planned_serial=99,
        blocks=(_victim_block(12),),
    )

    assert binding.outcome is GuardedRemovalBindingOutcome.REBOUND
    assert binding.serial == 12


def test_unbindable_removal_refuses_the_whole_plan() -> None:
    """One unbindable guarded removal refuses the complete operation set.

    The authority proposed a complete set of operations. Silently omitting one
    of them and applying the rest declares a completion the authority never
    authorized - the plan has to be refused as a whole, before any write.
    """
    verdict = decide_guarded_removal_preflight(
        unbindable=("no live block carries 0x401000+0x401004 at ordinal 2",),
    )

    assert verdict.disposition is GuardedRemovalPlanDisposition.REJECT_PLAN_CLEAN
    assert verdict.refuses_plan
    assert "1" in verdict.reason
    assert "no live block carries" in verdict.reason


def test_fully_bindable_removals_let_the_plan_apply() -> None:
    """Nothing to refuse means the batch proceeds untouched."""
    verdict = decide_guarded_removal_preflight(unbindable=())

    assert verdict.disposition is GuardedRemovalPlanDisposition.APPLY_PLAN
    assert not verdict.refuses_plan


def test_guard_rejection_before_any_write_is_a_clean_plan_rejection() -> None:
    """A rejection that precedes every write costs nothing to refuse."""
    verdict = decide_post_write_guard_rejection(
        description="guarded removal blk 12 ord 2",
        live_mutation_started=False,
        rollback_available=False,
    )

    assert verdict.disposition is GuardedRemovalPlanDisposition.REJECT_PLAN_CLEAN


def test_guard_rejection_after_a_write_rolls_back_when_it_can() -> None:
    """A guard that rejects once siblings have written must undo them."""
    verdict = decide_post_write_guard_rejection(
        description="guarded removal blk 12 ord 2",
        live_mutation_started=True,
        rollback_available=True,
    )

    assert verdict.disposition is GuardedRemovalPlanDisposition.ROLL_BACK_PLAN
    assert "guarded removal blk 12 ord 2" in verdict.reason


def test_guard_rejection_after_a_write_poisons_when_it_cannot_roll_back() -> None:
    """Without recovery the transaction is poisoned, never counted complete."""
    verdict = decide_post_write_guard_rejection(
        description="guarded removal blk 12 ord 2",
        live_mutation_started=True,
        rollback_available=False,
    )

    assert verdict.disposition is GuardedRemovalPlanDisposition.POISON_GENERATION
    assert verdict.refuses_plan
