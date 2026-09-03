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
    bind_guarded_removal,
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
