"""Proof that a folded-constant write to the return register is a *carrier
corruption* safe to drop (ticket llr-ytow).

Background
----------
When d810's MBA simplifier folds an obfuscation intermediate to a constant, the
fold can leave a now-dead ``mov #C, <return-reg>`` whose SSA def has no explicit
use, yet which still reaches a ``BLT_STOP`` as the physical return register.
By strict liveness such a def is *live* (it reaches the return), so textbook DCE
will not remove it -- and must not, because the same shape (``mov #C, rax`` with
no use) is *also* how a legitimate constant return is emitted. Dropping the
former restores the oracle's return value; dropping the latter would corrupt it.

The discriminator is a *severance gate* (the primary trigger) followed by a
two-pillar proof, all decidable from analyses we already have (a pre-fold
consumer snapshot + ``reaching_defs`` / DU-chains + a dominator tree):

* **Severance gate.** The value had a real operand consumer at the pre-fold
  snapshot (GLBOPT1 entry) and has none now -- i.e. IDA's fold actually orphaned
  it. A genuine constant return never had a consumer, so it fails the gate and is
  kept; this closes the legit-partial-return false-drop (ticket d81-fzlo).

* **Pillar 1 -- no computational use.** The def's SSA version has an *empty*
  use-def chain: no instruction operand reads it. Proves the constant feeds no
  computation; it can only affect the returned register's bits.

* **Pillar 2 -- a real carrier strictly dominates it.** A full-width return-reg
  definition sourced from a genuine return *carrier* (a stack slot / arg-derived
  pointer such as the counter ``*v17+1`` or ``a5+0xD0``) strictly dominates the
  candidate's block. Proves that on *every* path reaching the candidate the
  true return value was already established, so the candidate is overwriting it
  -- and removing the candidate re-delivers the dominating carrier.

``DROP`` iff Pillar 1 ∧ Pillar 2; otherwise ``KEEP`` (fail-closed). A genuine
constant return is kept by one of two fail-closed paths, both observed in the
real sub_7FFD microcode: IDA leaves the final-return write *untagged* (the
``0x5644...`` sentinel at blk9 -- no SSA version, kept at Pillar 1 before any
carrier check), or the constant is SSA-tagged but has *no* dominating carrier
(the ``0xc5fb...`` return at blk13 -- kept by Pillar 2).

This module is backend-neutral: the live ``ida_hexrays`` facts (DU-chain use
count, the carrier-block set, and the dominator relation) are *injected* by the
Hex-Rays evidence adapter, exactly like :mod:`d810.analyses.value_flow.liveness`
and :mod:`d810.analyses.value_flow.reaching_defs`. The proof itself is pure data
so it is unit-testable without IDA.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass

from d810.core.typing import Collection, Optional

__all__ = [
    "ReturnRegDef",
    "KeepReason",
    "CarrierCorruptionProof",
    "prove_return_const_droppable",
]


@dataclass(frozen=True, slots=True)
class ReturnRegDef:
    """A candidate definition of the return register (``rax`` family).

    Attributes:
        block: Serial of the block containing the definition.
        ea: Effective address of the defining instruction.
        ssa: SSA version of the defined register, or ``None`` when the
            destination carries no SSA tag (the untagged final-return write
            that IDA leaves on a genuine return value -- never droppable).
        is_const: ``True`` when the def is ``mov #imm, <reg>`` (a literal).
        is_partial: ``True`` when the write targets a sub-register (``al`` /
            ``ax`` / ``eax``) rather than the full ``rax``. Partial writes do
            not kill a dominating full-width carrier; full writes do.
        const_value: The literal value when :attr:`is_const`, else ``None``.
    """

    block: int
    ea: int
    ssa: Optional[int]
    is_const: bool
    is_partial: bool
    const_value: Optional[int] = None


class KeepReason(str, enum.Enum):
    """Why a candidate was *not* proven droppable (fail-closed audit trail)."""

    NOT_CONST = "not_const"
    """Destination is not a literal ``mov #imm`` -- out of scope."""

    UNTAGGED_DEF = "untagged_def"
    """No SSA version -- cannot establish an empty use-def chain."""

    NOT_SEVERED = "not_severed"
    """Severance gate failed: the value had no real consumer at the pre-fold
    snapshot, so the fold did not orphan it. A genuine constant return (never
    consumed) lands here and is kept -- closing the legit-partial-return
    false-drop (ticket d81-fzlo)."""

    HAS_USES = "has_uses"
    """Pillar 1 failed: the SSA def still has explicit operand use(s)."""

    NO_DOMINATING_CARRIER = "no_dominating_carrier"
    """Pillar 2 failed: no real carrier strictly dominates the def's block.

    This is exactly the case of a *genuine* constant return (the constant is
    the intended return value, with no carrier behind it)."""


@dataclass(frozen=True, slots=True)
class CarrierCorruptionProof:
    """Witness that a return-register constant write is a droppable corruption.

    Returned only when both pillars hold. Carries the evidence so call sites
    and logs can audit *why* the drop is sound.

    Attributes:
        target: The proven-droppable definition.
        du_chain_uses: Explicit operand uses of ``target.ssa`` (zero).
        dominating_carrier_blocks: Carrier-def blocks that strictly dominate
            ``target.block`` -- the carriers re-delivered once ``target`` is
            removed.
    """

    target: ReturnRegDef
    du_chain_uses: int
    dominating_carrier_blocks: tuple[int, ...]

    @property
    def reason(self) -> str:
        carriers = ",".join(str(b) for b in self.dominating_carrier_blocks)
        val = (
            "" if self.target.const_value is None else f"#{self.target.const_value:#x} "
        )
        return (
            f"drop {val}@blk{self.target.block} ea={self.target.ea:#x}: "
            f"ssa{{{self.target.ssa}}} has 0 uses; "
            f"carrier blk[{carriers}] strictly dominates"
        )


def prove_return_const_droppable(
    target: ReturnRegDef,
    *,
    was_consumed_prefold: bool,
    du_chain_uses: int,
    carrier_blocks: Collection[int],
    strict_dominators: Collection[int],
) -> CarrierCorruptionProof | tuple[None, KeepReason]:
    """Decide whether ``target`` is a droppable carrier corruption.

    All inputs are pre-computed facts the backend supplies from the live MBA:

    Args:
        target: The candidate return-register definition.
        was_consumed_prefold: Whether ``target.ssa`` had at least one real
            operand consumer at the pre-fold snapshot (GLBOPT1 entry). The
            severance gate (primary trigger) requires ``True``: only a value the
            fold actually orphaned is a corruption victim; ``False`` keeps a
            genuine constant return that never had a consumer.
        du_chain_uses: Number of explicit operand uses of ``target.ssa``
            (the empty-DU-chain query result). Pillar 1 requires ``0``.
        carrier_blocks: Blocks that contain a full-width return-carrier
            definition (stack-slot / arg-derived return value).
        strict_dominators: The *strict* dominators of ``target.block``
            (excluding the block itself).

    Returns:
        A :class:`CarrierCorruptionProof` when both pillars hold, else a
        ``(None, KeepReason)`` pair naming the failed pillar. The asymmetric
        return type forces call sites to handle the keep case explicitly and
        makes the gate fail-closed.

    Examples:
        Corruptor -- const, no uses, carrier dominates -> droppable:

        Corruptor -- severed (had a consumer pre-fold), no uses now, carrier
        dominates -> droppable:

        >>> d = ReturnRegDef(block=61, ea=0x180018f75, ssa=151, is_const=True,
        ...                  is_partial=True, const_value=0xB5)
        >>> p = prove_return_const_droppable(
        ...     d, was_consumed_prefold=True, du_chain_uses=0,
        ...     carrier_blocks={4, 16, 21, 49, 56, 62},
        ...     strict_dominators={0, 1, 4, 5, 49})
        >>> isinstance(p, CarrierCorruptionProof), p.dominating_carrier_blocks
        (True, (4, 49))

        A genuine partial return that was NEVER consumed (the fold did not sever
        it) is kept even though both pillars would otherwise pass -- this is the
        false-drop the severance gate closes (ticket d81-fzlo):

        >>> prove_return_const_droppable(
        ...     ReturnRegDef(block=70, ea=0x1800a0, ssa=300, is_const=True,
        ...                  is_partial=True, const_value=0x5),
        ...     was_consumed_prefold=False, du_chain_uses=0,
        ...     carrier_blocks={4, 49}, strict_dominators={0, 1, 4, 49})[1]
        <KeepReason.NOT_SEVERED: 'not_severed'>

        The genuine ``0x5644...`` sentinel return is *untagged* in the real
        sub_7FFD microcode (blk9 -- no SSA version), kept before any other check:

        >>> prove_return_const_droppable(
        ...     ReturnRegDef(block=9, ea=0x180015569, ssa=None, is_const=True,
        ...                  is_partial=False, const_value=0x5644FD01B1049C4B),
        ...     was_consumed_prefold=True, du_chain_uses=0,
        ...     carrier_blocks={4, 49}, strict_dominators={0, 1})[1]
        <KeepReason.UNTAGGED_DEF: 'untagged_def'>

        A *tagged* severed constant with no dominating carrier is the
        genuine-return case Pillar 2 guards (blk13, ``0xc5fb...``):

        >>> prove_return_const_droppable(
        ...     ReturnRegDef(block=13, ea=0x180015896, ssa=36, is_const=True,
        ...                  is_partial=False, const_value=0xC5FB34A1D9A6E315),
        ...     was_consumed_prefold=True, du_chain_uses=0,
        ...     carrier_blocks={4, 49}, strict_dominators={0, 1})[1]
        <KeepReason.NO_DOMINATING_CARRIER: 'no_dominating_carrier'>

        A def with a surviving use is never dropped:

        >>> prove_return_const_droppable(
        ...     ReturnRegDef(7, 0x7, 5, True, False, 0x1),
        ...     was_consumed_prefold=True, du_chain_uses=2,
        ...     carrier_blocks={4}, strict_dominators={4})[1]
        <KeepReason.HAS_USES: 'has_uses'>
    """
    if not target.is_const:
        return (None, KeepReason.NOT_CONST)
    if target.ssa is None:
        return (None, KeepReason.UNTAGGED_DEF)
    if not was_consumed_prefold:
        return (None, KeepReason.NOT_SEVERED)
    if du_chain_uses != 0:
        return (None, KeepReason.HAS_USES)
    dominating = tuple(sorted(set(carrier_blocks) & set(strict_dominators)))
    if not dominating:
        return (None, KeepReason.NO_DOMINATING_CARRIER)
    return CarrierCorruptionProof(
        target=target,
        du_chain_uses=du_chain_uses,
        dominating_carrier_blocks=dominating,
    )
