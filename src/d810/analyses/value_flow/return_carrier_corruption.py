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
    "CarrierDefinition",
    "ReturnRegDef",
    "KeepReason",
    "CarrierCorruptionProof",
    "prove_return_const_droppable",
]


def _coordinate(value: int, name: str, *, native_ea: bool = False) -> None:
    if type(value) is not int:
        raise TypeError(f"{name} must be an integer")
    if value < (1 if native_ea else 0) or (native_ea and value >= 0xFFFFFFFFFFFFFFFF):
        raise ValueError(f"invalid {name}")


@dataclass(frozen=True, slots=True, order=True)
class CarrierDefinition:
    """Snapshot-local block coordinate paired with its exact definition EA."""

    block: int
    ea: int

    def __post_init__(self) -> None:
        _coordinate(self.block, "carrier block")
        _coordinate(self.ea, "carrier EA", native_ea=True)


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

    def __post_init__(self) -> None:
        _coordinate(self.block, "target block")
        _coordinate(self.ea, "target EA", native_ea=True)
        if self.ssa is not None:
            _coordinate(self.ssa, "SSA version")
        if type(self.is_const) is not bool or type(self.is_partial) is not bool:
            raise TypeError("definition flags must be bools")
        if self.const_value is not None and type(self.const_value) is not int:
            raise TypeError("constant value must be an integer")


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
    dominating_carriers: tuple[CarrierDefinition, ...]
    was_consumed_prefold: bool

    def __post_init__(self) -> None:
        if type(self.target) is not ReturnRegDef:
            raise TypeError("proof target must be a ReturnRegDef")
        self.target.__post_init__()
        if self.target.is_const is not True or self.target.ssa is None:
            raise ValueError("corruption proof requires a tagged constant definition")
        if self.was_consumed_prefold is not True:
            raise ValueError("corruption proof requires observed pre-fold consumption")
        if type(self.du_chain_uses) is not int or self.du_chain_uses != 0:
            raise ValueError("corruption proof requires exactly zero uses")
        if type(self.dominating_carriers) is not tuple or not self.dominating_carriers:
            raise ValueError("corruption proof requires anchored carrier definitions")
        for carrier in self.dominating_carriers:
            if type(carrier) is not CarrierDefinition:
                raise TypeError("carrier must be a CarrierDefinition")
            carrier.__post_init__()
            if carrier.block == self.target.block:
                raise ValueError("carrier must strictly dominate the target block")
        if tuple(sorted(set(self.dominating_carriers))) != self.dominating_carriers:
            raise ValueError("carrier definitions must be unique and ordered")

    @property
    def dominating_carrier_blocks(self) -> tuple[int, ...]:
        """Diagnostic projection; block numbers alone are not proof evidence."""
        return tuple(sorted({carrier.block for carrier in self.dominating_carriers}))

    @property
    def reason(self) -> str:
        carriers = ",".join(f"blk{c.block}@{c.ea:#x}" for c in self.dominating_carriers)
        val = (
            "" if self.target.const_value is None else f"#{self.target.const_value:#x} "
        )
        return (
            f"drop {val}@blk{self.target.block} ea={self.target.ea:#x}: "
            f"ssa{{{self.target.ssa}}} has 0 uses; "
            f"carrier [{carriers}] strictly dominates"
        )


def prove_return_const_droppable(
    target: ReturnRegDef,
    *,
    was_consumed_prefold: bool,
    du_chain_uses: int,
    carrier_definitions: Collection[CarrierDefinition],
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
        carrier_definitions: Exact full-width carrier definitions, including
            both snapshot-local block and native instruction EA.
        strict_dominators: The *strict* dominators of ``target.block``
            (excluding the block itself).

    Returns:
        A :class:`CarrierCorruptionProof` when both pillars hold, else a
        ``(None, KeepReason)`` pair naming the failed pillar. The asymmetric
        return type forces call sites to handle the keep case explicitly and
        makes the gate fail-closed.

    """
    if type(target) is not ReturnRegDef:
        raise TypeError("target must be a ReturnRegDef")
    if type(was_consumed_prefold) is not bool:
        raise TypeError("was_consumed_prefold must be a bool")
    if type(du_chain_uses) is not int:
        raise TypeError("du_chain_uses must be an integer")
    if du_chain_uses < 0:
        raise ValueError("du_chain_uses must be non-negative")
    if not target.is_const:
        return (None, KeepReason.NOT_CONST)
    if target.ssa is None:
        return (None, KeepReason.UNTAGGED_DEF)
    if not was_consumed_prefold:
        return (None, KeepReason.NOT_SEVERED)
    if du_chain_uses != 0:
        return (None, KeepReason.HAS_USES)
    for serial in strict_dominators:
        _coordinate(serial, "strict dominator")
    for carrier in carrier_definitions:
        if type(carrier) is not CarrierDefinition:
            raise TypeError("carrier definitions must be anchored records")
        carrier.__post_init__()
    dominating = tuple(
        sorted(
            {
                carrier
                for carrier in carrier_definitions
                if carrier.block in strict_dominators and carrier.block != target.block
            }
        )
    )
    if not dominating:
        return (None, KeepReason.NO_DOMINATING_CARRIER)
    return CarrierCorruptionProof(
        target=target,
        du_chain_uses=du_chain_uses,
        dominating_carriers=dominating,
        was_consumed_prefold=was_consumed_prefold,
    )
