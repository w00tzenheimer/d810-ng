"""Bind guarded instruction removals to live block identity, not to a serial.

A guarded removal is planned against a block *serial*, but a serial is only
valid for the MBA generation that produced it.  Any stage that creates blocks -
a redirect that clones a fall-through, for example - shifts every later serial,
so a removal planned against serial 10 can address a completely different block
by the time the deferred batch applies.

The removal already carries a stable identity: the block's start EA plus the
ordinal-th instruction's EA, opcode and destination.  That fingerprint survives
serial renumbering, so it is what the binding resolves through.  A start EA
alone is *not* an identity - a clone can share it - which is why the whole
fingerprint has to validate before a candidate is accepted.

This module holds no IDA imports on purpose: callers project live
``mblock_t``/``minsn_t`` state into the records below and receive a verdict
they can act on before any mutation happens.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

__all__ = [
    "GuardedRemovalBinding",
    "GuardedRemovalBindingOutcome",
    "GuardedRemovalCandidateBlock",
    "GuardedRemovalCandidateInstruction",
    "GuardedRemovalFingerprint",
    "bind_guarded_removal",
]


@dataclass(frozen=True)
class GuardedRemovalFingerprint:
    """The stable identity a guarded removal was proven against."""

    block_start_ea: int
    insn_ea: int
    ordinal: int
    opcode: int
    destination_kind: str
    destination_id: int
    destination_size: int


@dataclass(frozen=True)
class GuardedRemovalCandidateInstruction:
    """One live instruction projected out of the current MBA."""

    ea: int
    opcode: int
    destination_kind: str | None
    destination_id: int | None
    destination_size: int | None


@dataclass(frozen=True)
class GuardedRemovalCandidateBlock:
    """One live block projected out of the current MBA."""

    serial: int
    start_ea: int
    instructions: tuple[GuardedRemovalCandidateInstruction, ...]


class GuardedRemovalBindingOutcome(Enum):
    """Why a guarded removal did or did not resolve to a live serial."""

    ALREADY_BOUND = "already_bound"
    REBOUND = "rebound"
    IDENTITY_GONE = "identity_gone"
    AMBIGUOUS_IDENTITY = "ambiguous_identity"


@dataclass(frozen=True)
class GuardedRemovalBinding:
    """The verdict for one guarded removal against one live MBA."""

    outcome: GuardedRemovalBindingOutcome
    serial: int | None
    reason: str

    @property
    def bound(self) -> bool:
        """Return whether this removal may be applied at ``serial``."""
        return self.outcome in (
            GuardedRemovalBindingOutcome.ALREADY_BOUND,
            GuardedRemovalBindingOutcome.REBOUND,
        )


def _block_carries_identity(
    block: GuardedRemovalCandidateBlock,
    fingerprint: GuardedRemovalFingerprint,
) -> bool:
    """Return whether ``block`` still carries the fingerprinted instruction."""
    if int(block.start_ea) != int(fingerprint.block_start_ea):
        return False
    ordinal = int(fingerprint.ordinal)
    if ordinal < 0 or ordinal >= len(block.instructions):
        return False
    insn = block.instructions[ordinal]
    if int(insn.ea) != int(fingerprint.insn_ea):
        return False
    if int(insn.opcode) != int(fingerprint.opcode):
        return False
    if insn.destination_kind != fingerprint.destination_kind:
        return False
    if insn.destination_id is None or insn.destination_size is None:
        return False
    return int(insn.destination_id) == int(fingerprint.destination_id) and int(
        insn.destination_size
    ) == int(fingerprint.destination_size)


def bind_guarded_removal(
    fingerprint: GuardedRemovalFingerprint,
    *,
    planned_serial: int,
    blocks: tuple[GuardedRemovalCandidateBlock, ...],
) -> GuardedRemovalBinding:
    """Resolve one guarded removal against the blocks of the current MBA.

    Args:
        fingerprint: Stable identity captured when the removal was proven.
        planned_serial: Serial the removal was queued against.
        blocks: Every live block of the MBA the removal will be applied to.

    Returns:
        A verdict naming the live serial to use, or why the removal must be
        dropped before any mutation happens.
    """
    planned_serial = int(planned_serial)
    for block in blocks:
        if int(block.serial) == planned_serial and _block_carries_identity(
            block, fingerprint
        ):
            return GuardedRemovalBinding(
                outcome=GuardedRemovalBindingOutcome.ALREADY_BOUND,
                serial=planned_serial,
                reason=(
                    f"planned serial {planned_serial} still carries "
                    f"0x{int(fingerprint.insn_ea):x} at ordinal "
                    f"{int(fingerprint.ordinal)}"
                ),
            )

    matches = sorted(
        {
            int(block.serial)
            for block in blocks
            if _block_carries_identity(block, fingerprint)
        }
    )
    if len(matches) == 1:
        return GuardedRemovalBinding(
            outcome=GuardedRemovalBindingOutcome.REBOUND,
            serial=matches[0],
            reason=(
                f"planned serial {planned_serial} shifted; identity "
                f"0x{int(fingerprint.block_start_ea):x}"
                f"+0x{int(fingerprint.insn_ea):x} is now serial {matches[0]}"
            ),
        )
    if not matches:
        return GuardedRemovalBinding(
            outcome=GuardedRemovalBindingOutcome.IDENTITY_GONE,
            serial=None,
            reason=(
                f"no live block carries 0x{int(fingerprint.block_start_ea):x}"
                f"+0x{int(fingerprint.insn_ea):x} at ordinal "
                f"{int(fingerprint.ordinal)}"
            ),
        )
    return GuardedRemovalBinding(
        outcome=GuardedRemovalBindingOutcome.AMBIGUOUS_IDENTITY,
        serial=None,
        reason=(
            f"{len(matches)} live blocks carry "
            f"0x{int(fingerprint.block_start_ea):x}"
            f"+0x{int(fingerprint.insn_ea):x}: {matches}"
        ),
    )
