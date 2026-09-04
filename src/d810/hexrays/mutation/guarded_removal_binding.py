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

from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum

__all__ = [
    "GuardedRemovalBinding",
    "GuardedRemovalBindingOutcome",
    "GuardedRemovalCandidateBlock",
    "GuardedRemovalCandidateInstruction",
    "GuardedRemovalFingerprint",
    "GuardedRemovalPlanDisposition",
    "GuardedRemovalPlanVerdict",
    "bind_guarded_removal",
    "decide_guarded_removal_preflight",
    "decide_post_write_guard_rejection",
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


class GuardedRemovalPlanDisposition(Enum):
    """What the enclosing batch must do about a guarded removal it cannot honour.

    The names are the transaction outcomes the mutation gateway already
    speaks - a clean rejection, a completed rollback, a poisoned generation -
    so a verdict here maps onto one recorded phase and never onto a private
    "skipped" state that reads as success.
    """

    APPLY_PLAN = "apply_plan"
    REJECT_PLAN_CLEAN = "reject_plan_clean"
    ROLL_BACK_PLAN = "roll_back_plan"
    POISON_GENERATION = "poison_generation"


@dataclass(frozen=True)
class GuardedRemovalPlanVerdict:
    """The disposition of one plan that contains an unhonourable removal."""

    disposition: GuardedRemovalPlanDisposition
    reason: str

    @property
    def refuses_plan(self) -> bool:
        """Return whether this verdict forbids reporting the plan as applied."""
        return self.disposition is not GuardedRemovalPlanDisposition.APPLY_PLAN


def decide_guarded_removal_preflight(
    *,
    unbindable: Sequence[str],
) -> GuardedRemovalPlanVerdict:
    """Decide a batch's fate when preflight cannot bind every guarded removal.

    A plan is one authority's complete proposal.  "Instruction-only" describes
    what a single operation writes; it does not prove that operation is
    independent of the sibling CFG edits queued beside it in the same
    transaction.  Dropping the unbindable one and applying the rest therefore
    declares a completion nobody authorized, so the whole plan is refused - and
    because the preflight runs before any write, refusing costs nothing.

    Args:
        unbindable: One reason per guarded removal that would not bind.

    Returns:
        ``APPLY_PLAN`` when every removal bound, otherwise a clean refusal of
        the complete operation set.
    """
    reasons = tuple(str(reason) for reason in unbindable)
    if not reasons:
        return GuardedRemovalPlanVerdict(
            disposition=GuardedRemovalPlanDisposition.APPLY_PLAN,
            reason="every guarded removal bound to live block identity",
        )
    return GuardedRemovalPlanVerdict(
        disposition=GuardedRemovalPlanDisposition.REJECT_PLAN_CLEAN,
        reason=(
            f"{len(reasons)} guarded removal(s) cannot bind to live block "
            f"identity; refusing the complete plan before any write: "
            + "; ".join(reasons)
        ),
    )


def decide_post_write_guard_rejection(
    *,
    description: str,
    live_mutation_started: bool,
    rollback_available: bool,
) -> GuardedRemovalPlanVerdict:
    """Decide a batch's fate when a guard rejects after the preflight passed.

    The removal itself changed nothing - that is what its fingerprint
    revalidation guarantees - but the operations that already wrote in this
    transaction did.  Reporting the batch as complete after omitting a planned
    operation is the failure this exists to prevent, so the only outcomes are
    undoing those writes or poisoning the generation that carries them.

    Args:
        description: The rejected modification, for the recorded reason.
        live_mutation_started: Whether this transaction has crossed the
            irreversible write boundary.
        rollback_available: Whether a pre-apply snapshot can restore the MBA.

    Returns:
        A refusal naming the recovery the batch must perform.
    """
    detail = str(description)
    if not live_mutation_started:
        return GuardedRemovalPlanVerdict(
            disposition=GuardedRemovalPlanDisposition.REJECT_PLAN_CLEAN,
            reason=(
                f"guarded removal rejected before any write, refusing the "
                f"complete plan: {detail}"
            ),
        )
    if rollback_available:
        return GuardedRemovalPlanVerdict(
            disposition=GuardedRemovalPlanDisposition.ROLL_BACK_PLAN,
            reason=(
                f"guarded removal rejected after sibling operations wrote; "
                f"rolling the transaction back: {detail}"
            ),
        )
    return GuardedRemovalPlanVerdict(
        disposition=GuardedRemovalPlanDisposition.POISON_GENERATION,
        reason=(
            f"guarded removal rejected after sibling operations wrote and no "
            f"rollback is available; poisoning the generation: {detail}"
        ),
    )
